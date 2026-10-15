//! Modo **fusión** (`CONTRATO-ESTADO-DAG-v0` §3, `ORDEN-W03` §3.11; corregido en `ORDEN-W06a`
//! según `REVISION-RI-1a`).
//!
//! A diferencia de [`crate::transicion::aplicar`], aquí una transacción que no valida **se
//! descarta** con su motivo (`ED-4`…`ED-6`) en vez de invalidar el bloque; solo invalidan el bloque
//! las comprobaciones que la tabla de §3 marca como tales (forma, coinbase estructural, garantía del
//! productor). La coinbase PoST se acredita por `mín(declarado, subsidio_post(slot(B)) + tarifas
//! aceptadas)`.
//!
//! # Correcciones de `ORDEN-W06a` (decisiones 3 y 4, `REVISION-RI-1a`)
//!
//! - **RI-1a #1:** `fusion_post` fija `Estado.slot = punto` para **todo** bloque fusionado, como
//!   `aplicar_bloque_fusion!` (`P-ZRX/P-DAG/T04/src/EstadoDAG.jl:303`). `peso_sufijo` **no** lo suma
//!   el modo fusión: lo suma quien aplica, y solo por los bloques de **cadena** (`EstadoDAG.jl:395,
//!   607`), reparto que implementa `zx-cadena`.
//! - **RI-1a #2:** `aplicar_fusion` **rechaza** un bloque PoW: la fase PoW se aplica en modo
//!   estricto con [`crate::transicion::aplicar`] (`ED-1`). Se elimina `fusion_pow`, que no exigía
//!   `altura = altura_previa + 1`.
//! - **RD-2:** la coinbase PoST es **opcional** (el productor puede renunciar a ella); si existe,
//!   debe ser única, la primera y de tipo v3.
//! - **RD-7:** se aplican primero las transacciones no-coinbase y después se materializa el crédito
//!   recortado de la coinbase.
//! - **RD-10:** la garantía del productor es una comprobación de **admisión** en `Estado(past(B))`;
//!   **no** se vuelve a comprobar al fusionar el bloque como bloque de lado.
//!
//! La orquestación completa del DAG (ED-1…ED-3, orden del mergeset, `rojo_U3`) es de `zx-cadena`;
//! aquí se implementan las primitivas.

use zx_core::{Amount, ExtensionTx};

use crate::transicion::ErrorTransicion;
use crate::transicion::aplicar::{
    Efecto, aplicar_con_undo, aplicar_tx, es_coinbase, validar_bloque,
};
use crate::transicion::estado::{Aplicador, acreditar_credito, podar_incidentes};
use crate::transicion::tipos::{
    BloqueTransicion, Estado, Fase, HechosCabecera, ParametrosEvidencia, ParametrosTransicion,
    Pendiente, Punto, TxDescartada, Undo,
};

/// Aplica un bloque **PoST** en **modo fusión** desde `punto_aplicacion`.
///
/// Devuelve el estado nuevo, el undo por delta y las transacciones descartadas con su motivo.
///
/// # Errores
/// Solo los que invalidan el bloque según la tabla de §3 del contrato de estado DAG; un bloque PoW
/// es un uso incorrecto del modo fusión (`ED-1`).
pub fn aplicar_fusion(
    estado: &Estado,
    bloque: &BloqueTransicion,
    punto_aplicacion: Punto,
    params: &ParametrosTransicion,
    cbid: u32,
    evp: &ParametrosEvidencia,
) -> Result<(Estado, Undo, Vec<TxDescartada>), ErrorTransicion> {
    validar_bloque(bloque, params, evp)?;
    if matches!(bloque.hechos, HechosCabecera::Genesis { .. }) {
        let (nuevo, undo) = aplicar_con_undo(estado, bloque, params, cbid, evp)?;
        return Ok((nuevo, undo, Vec::new()));
    }
    if matches!(bloque.hechos, HechosCabecera::PoW { .. }) {
        // ED-1: la fase PoW se aplica con `aplicar` (estricto); no hay bloques PoW fusionados.
        return Err(ErrorTransicion::ErrOperacionFase);
    }
    let mut ap = Aplicador::nuevo(estado.clone());
    let mut descartadas: Vec<TxDescartada> = Vec::new();
    fusion_post(
        &mut ap,
        bloque,
        punto_aplicacion,
        params,
        cbid,
        evp,
        &mut descartadas,
    )?;
    Ok((ap.estado, ap.undo, descartadas))
}

/// Cuenta coinbases y comprueba posición (tabla de §3: invalida el bloque).
///
/// Devuelve `Some(índice)` si hay exactamente una coinbase (siempre en la posición 0), `None` si no
/// hay ninguna (RD-2: opcional en PoST).
fn coinbase_unica(bloque: &BloqueTransicion) -> Result<Option<usize>, ErrorTransicion> {
    let mut ncb = 0usize;
    let mut idx = 0usize;
    for (i, (tx, _)) in bloque.txs.iter().enumerate() {
        if es_coinbase(tx) {
            ncb += 1;
            idx = i;
        }
    }
    if ncb > 1 {
        return Err(ErrorTransicion::ErrEmision);
    }
    if ncb == 1 && idx != 0 {
        return Err(ErrorTransicion::ErrEmision);
    }
    Ok((ncb == 1).then_some(idx))
}

/// Aplica una coinbase PoST v3 acreditando `importe` (ya recortado).
fn acreditar_coinbase_post(
    ap: &mut Aplicador,
    productor: zx_core::ClavePublica,
    importe: Amount,
    punto: Punto,
    params: &ParametrosTransicion,
) -> Result<(), ErrorTransicion> {
    let slot = punto.como_slot().ok_or(ErrorTransicion::ErrOperacionFase)?;
    let madura = slot
        .checked_add(params.m_rec_slots)
        .ok_or(ErrorTransicion::ErrDesbordamiento)?;
    let g = ap.garantia_mut(productor);
    acreditar_credito(
        g,
        Pendiente {
            importe,
            madura_en_altura: None,
            madura_en_slot: Some(madura),
        },
        punto,
    )
}

/// Extrae el importe declarado de una coinbase PoST, comprobando F-09/F-17.
fn declarado_de_coinbase(
    tx: &zx_core::Tx,
    productor: &zx_core::ClavePublica,
    slot: u64,
) -> Result<Amount, ErrorTransicion> {
    match &tx.extension {
        ExtensionTx::CoinbasePost {
            clave,
            importe,
            slot: slot_tx,
        } => {
            if *clave != *productor {
                return Err(ErrorTransicion::ErrAutorizacion);
            }
            // F-17: el `slot` de la v3 MUST ser el slot del bloque que la contiene.
            if *slot_tx != slot {
                return Err(ErrorTransicion::ErrEmision);
            }
            Ok(*importe)
        }
        _ => Err(ErrorTransicion::ErrForma(
            zx_core::ErrorFormaTx::ExtensionIncoherente {
                version: tx.version,
                esperada: "CoinbasePost",
            },
        )),
    }
}

/// Fusiona un bloque PoST: coinbase v3 recortada y opcional, resto descartable.
fn fusion_post(
    ap: &mut Aplicador,
    bloque: &BloqueTransicion,
    punto: Punto,
    params: &ParametrosTransicion,
    cbid: u32,
    evp: &ParametrosEvidencia,
    descartadas: &mut Vec<TxDescartada>,
) -> Result<(), ErrorTransicion> {
    let HechosCabecera::PoST {
        padre,
        slot,
        productor,
        peso,
        prueba_valida,
        ..
    } = &bloque.hechos
    else {
        return Err(ErrorTransicion::ErrGenesis);
    };
    match ap.estado.fase {
        Fase::PoW => {
            let terminal = ap.estado.terminal.ok_or(ErrorTransicion::ErrSinTerminal)?;
            if *padre != terminal {
                return Err(ErrorTransicion::ErrSinTerminal);
            }
            if *slot < 1 {
                return Err(ErrorTransicion::ErrSlot);
            }
            ap.estado.fase = Fase::PoST;
            ap.estado.s0 = 0;
        }
        Fase::PoST => {}
        Fase::Genesis => return Err(ErrorTransicion::ErrGenesis),
    }
    if !prueba_valida {
        return Err(ErrorTransicion::ErrPow);
    }
    if *peso < 1 {
        return Err(ErrorTransicion::ErrSlot);
    }
    // (b) promoción de pendientes y créditos en el punto de aplicación.
    ap.promover(punto, true, params)?;
    // EV-11: la poda usa el **punto de aplicación**, no el slot propio del bloque fusionado.
    let punto_slot = punto.como_slot().ok_or(ErrorTransicion::ErrOperacionFase)?;
    podar_incidentes(&mut ap.estado, evp, punto_slot);
    // SR-1-2: materializa el ciclo de vida de los sectores en el punto de aplicación.
    crate::transicion::sector::materializar_sectores(
        ap,
        i64::try_from(punto_slot).unwrap_or(i64::MAX),
    )?;
    // RK-2 · V6 · borra las claves de voto anteriores vencidas en el punto de aplicación.
    crate::transicion::estado::podar_claves_voto_vencidas(ap, punto_slot);
    // SUS-1 · S2: en fusión manda el punto de aplicación (el slot efectivo del estado), antes de
    // aplicar las transacciones del bloque.
    crate::transicion::estado::liquidar_ventanas_voto(ap, punto_slot);
    // RD-10: la garantía del productor **no** se recompueba al fusionar; es admisión (RD-9).
    let coinbase = coinbase_unica(bloque)?;
    if let Some(idx) = coinbase {
        let Some((tx_coinbase, _)) = bloque.txs.get(idx) else {
            return Err(ErrorTransicion::ErrEmision);
        };
        // R-8: importe 0 en la coinbase PoST invalida el bloque.
        if declarado_de_coinbase(tx_coinbase, productor, *slot)?.brek() == 0 {
            return Err(ErrorTransicion::ErrSaldo);
        }
    }
    // Pre-pasada sobre una copia: conjunto aceptado y tarifas (RD-7 calcula el crédito con las
    // tarifas de las transacciones que sí se aplican).
    let mut temporal = Aplicador::nuevo(ap.estado.clone());
    let mut tarifas = Amount::CERO;
    let mut aceptadas: Vec<usize> = Vec::new();
    for (i, (tx, testigos)) in bloque.txs.iter().enumerate() {
        if Some(i) == coinbase {
            continue;
        }
        let marca = temporal.marcar();
        match aplicar_tx(
            &mut temporal,
            bloque,
            params,
            cbid,
            evp,
            punto,
            tx,
            testigos,
            bloque.hechos_votos.get(i).copied(),
        ) {
            Ok(Efecto::Fee(fee)) => {
                tarifas = tarifas
                    .suma_comprobada(fee)
                    .ok_or(ErrorTransicion::ErrDesbordamiento)?;
                aceptadas.push(i);
            }
            Ok(Efecto::Coinbase(_)) => {}
            Err(motivo) => {
                temporal.revertir_a(marca);
                descartadas.push(TxDescartada {
                    indice: i,
                    txid: zx_core::txid(tx, cbid),
                    motivo,
                });
            }
        }
    }
    // RD-7: primero las transacciones no-coinbase, después el crédito recortado de la coinbase.
    for i in aceptadas {
        let Some((tx, testigos)) = bloque.txs.get(i) else {
            continue;
        };
        let marca = ap.marcar();
        if let Err(motivo) = aplicar_tx(
            ap,
            bloque,
            params,
            cbid,
            evp,
            punto,
            tx,
            testigos,
            bloque.hechos_votos.get(i).copied(),
        ) {
            ap.revertir_a(marca);
            descartadas.push(TxDescartada {
                indice: i,
                txid: zx_core::txid(tx, cbid),
                motivo,
            });
        }
    }
    let sub = (params.subsidio_post)(*slot);
    let tope = sub
        .suma_comprobada(tarifas)
        .ok_or(ErrorTransicion::ErrDesbordamiento)?;
    let mut efectiva = Amount::CERO;
    if let Some(idx) = coinbase {
        let Some((tx_coinbase, _)) = bloque.txs.get(idx) else {
            return Err(ErrorTransicion::ErrEmision);
        };
        let declarado = declarado_de_coinbase(tx_coinbase, productor, *slot)?;
        efectiva = if declarado <= tope { declarado } else { tope };
        acreditar_coinbase_post(ap, *productor, efectiva, punto, params)?;
    }
    ap.estado.emitido += i128::from(efectiva.brek()) - i128::from(tarifas.brek());
    ap.estado.subsidio_acum += i128::from(sub.brek());
    // RI-1a #1: el slot del estado es el punto de aplicación (EstadoDAG.jl:303).
    ap.estado.slot = punto.como_slot().ok_or(ErrorTransicion::ErrOperacionFase)?;
    // EV-24(ii): se registra el slot **propio** del bloque, no el punto de aplicación.
    let prev = ap.estado.ultimo_slot_producido.get(productor).copied();
    if prev.is_none_or(|p| *slot > p) {
        ap.estado.ultimo_slot_producido.insert(*productor, *slot);
    }
    Ok(())
}
