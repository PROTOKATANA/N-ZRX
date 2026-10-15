//! B26-1 · reserva de mempool para operaciones de sector.
//!
//! Pruebas sobre la **API pública** del crate, equivalentes al plan de verificación de la orden:
//! 1. con la mempool llena de transacciones normales válidas, una operación de sector se admite
//!    desalojando la normal de menor tarifa;
//! 2. bajo «inundación» de normales de tarifa alta, la fase de reserva de `seleccionar` incluye la
//!    operación de sector y no pasa de `w_reserva`;
//! 3. una segunda operación de sector de la misma clave sigue rechazada por la cuota;
//! 4. la reserva combinada (depósitos + operaciones de sector) nunca pasa de `w_reserva`.
//!
//! Los puntos 1 y 2 fallan con el código anterior a B26-1.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño y trocean vectores ya comprobados"
)]

use std::collections::BTreeSet;
use std::time::Instant;

use zx_consensus::sectores::{Etapa, RegistroSector, SectorId};
use zx_consensus::transicion::{
    EntradaUtxo, Estado, Fase, Garantia, Origen, ParametrosEvidencia, ParametrosTransicion, Punto,
};
use zx_core::digest::Digest;
use zx_core::{
    Amount, CBID_RED_DEV, ClavePublica, ExtensionTx, HashType, Lock, OperacionSector, OutPoint,
    SpentOutput, TipoGarantia, Tx, TxId, TxIn, TxOut,
};
use zx_node::claves::ClaveDev;
use zx_node::mempool::{Admision, Mempool, Politica, Rechazo};

const CBID: u32 = CBID_RED_DEV;

fn params() -> ParametrosTransicion {
    zx_node::perfil::parametros_transicion_dev().expect("perfil dev")
}

fn evp() -> ParametrosEvidencia {
    zx_node::perfil::parametros_evidencia_dev()
}

fn ahora() -> Instant {
    Instant::now()
}

fn op_id(n: u8) -> OutPoint {
    OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
        prev_index: 0,
    }
}

/// Estado base en fase PoW con los UTXO indicados (origen `Tx`, sin inmadurez).
fn base_pow(utxos: &[(OutPoint, i64, ClavePublica)]) -> Estado {
    let mut e = Estado::inicial();
    e.fase = Fase::PoW;
    e.altura = 1;
    for (op, v, pk) in utxos {
        e.utxo.insert(
            *op,
            EntradaUtxo {
                valor: Amount::nuevo(*v).unwrap(),
                lock: Lock::PubKey { pubkey: *pk },
                origen: Origen::Tx,
                creada: Punto::Altura(0),
            },
        );
    }
    e
}

/// Añade una garantía activa (500) para `clave`, como los tests de `mempool.rs`.
fn con_garantia(mut e: Estado, clave: &ClaveDev) -> Estado {
    e.garantias.insert(
        clave.pk,
        Garantia {
            activo: Amount::nuevo(500).unwrap(),
            ..Garantia::nueva()
        },
    );
    e
}

fn peso_de(tx: &Tx, testigos: &[Vec<u8>]) -> u64 {
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
    buf.len() as u64
}

fn transferencia(
    clave: &ClaveDev,
    op: OutPoint,
    valor_in: i64,
    valor_out: i64,
    destino: ClavePublica,
) -> (Tx, Vec<Vec<u8>>) {
    let tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: op,
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::nuevo(valor_out).unwrap(),
            lock: Lock::PubKey { pubkey: destino },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let gastadas = [SpentOutput {
        value: Amount::nuevo(valor_in).unwrap(),
        lock: Lock::PubKey { pubkey: clave.pk },
    }];
    let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).unwrap();
    let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
    (tx, vec![firma.to_vec()])
}

/// Depósito v2 de `clave` que gasta por completo la salida `op` (tarifa 0).
fn deposito(clave: &ClaveDev, op: OutPoint, valor: i64, nonce: u64) -> (Tx, Vec<Vec<u8>>) {
    zx_node::pow::construir_deposito(
        op.prev_txid,
        Amount::nuevo(valor).unwrap(),
        clave,
        nonce,
        CBID,
    )
    .expect("depósito")
}

/// Alta de sector v5 firmada por `clave`.
fn alta_sector(clave: &ClaveDev, si: u16) -> (Tx, Vec<Vec<u8>>) {
    let op = OperacionSector::Alta {
        clave: clave.pk,
        sector_index: si,
        version: 0,
        r2: [7u8; 32],
        history_size: 1 << 20,
    };
    let tx = Tx {
        version: 5,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Sector { operacion: op },
    };
    let firma: [u8; 64] = clave.sk.sign(&zx_core::mensaje_sector(&tx, CBID)).into();
    (tx, vec![firma.to_vec()])
}

/// **†** Mempool llena de normales válidas: la operación de sector se admite y sale la normal de
/// menor feerate; las demás se quedan.
#[test]
fn mempool_llena_sector_desaloja_la_normal_de_menor_tarifa() {
    let a = ClaveDev::derivar(1, 0);
    let b = ClaveDev::derivar(1, 1);
    let base = con_garantia(
        base_pow(&[
            (op_id(1), 1_000, a.pk),
            (op_id(2), 1_000, a.pk),
            (op_id(3), 1_000, a.pk),
        ]),
        &a,
    );
    // Tres transferencias del mismo tamaño con tarifas distintas.
    let (baja, wb) = transferencia(&a, op_id(1), 1_000, 900, b.pk); // fee 100
    let (media, wm) = transferencia(&a, op_id(2), 1_000, 700, b.pk); // fee 300
    let (alta, wa) = transferencia(&a, op_id(3), 1_000, 500, b.pk); // fee 500
    let (sector, ws) = alta_sector(&a, 0);
    let p = peso_de(&baja, &wb);
    assert_eq!(p, peso_de(&media, &wm), "las normales miden lo mismo");
    assert_eq!(p, peso_de(&alta, &wa), "las normales miden lo mismo");
    let mut pol = Politica::dev();
    pol.s = (3 * p) as usize; // las tres normales llenan S exactamente
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let t_baja = zx_core::txid(&baja, CBID);
    let t_media = zx_core::txid(&media, CBID);
    let t_alta = zx_core::txid(&alta, CBID);
    let t_sector = zx_core::txid(&sector, CBID);
    for (tx, tst) in [(baja, wb), (media, wm), (alta, wa)] {
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    assert_eq!(m.estadisticas().n, 3);
    assert_eq!(m.estadisticas().bytes, (3 * p) as usize);
    // Llega el alta de sector: entra y desaloja la normal de menor tarifa.
    assert_eq!(
        m.admitir(None, sector, ws, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert!(m.contiene(&t_sector), "la operación de sector entra");
    assert!(!m.contiene(&t_baja), "sale la normal de menor tarifa");
    assert!(m.contiene(&t_media), "la normal media se queda");
    assert!(m.contiene(&t_alta), "la normal alta se queda");
    assert!(m.estadisticas().bytes <= m.politica().s);
}

/// **†** Bajo inundación de normales de tarifa muy alta, la reserva de `seleccionar` incluye la
/// operación de sector (tarifa 0) y el bloque no pasa de `w_reserva` por la reserva.
#[test]
fn bajo_inundacion_la_reserva_incluye_la_operacion_de_sector() {
    // Tarifa enorme: el muestreo ponderado la ordena siempre antes que la operación de sector
    // (feerate 0), que es lo que reproduce la inundación del humo.
    const FEE_ALTA: i64 = 1_000_000_000_000;
    let a = ClaveDev::derivar(2, 0);
    let d = ClaveDev::derivar(2, 1);
    let b = ClaveDev::derivar(2, 2);
    let mut utxos: Vec<(OutPoint, i64, ClavePublica)> = vec![(op_id(9), 1_000, d.pk)];
    for i in 0..8u8 {
        utxos.push((op_id(100 + i), 2 * FEE_ALTA, a.pk));
    }
    let base = con_garantia(base_pow(&utxos), &a);
    let (dep, wd) = deposito(&d, op_id(9), 1_000, 0);
    let (sector, ws) = alta_sector(&a, 0);
    let p_dep = peso_de(&dep, &wd);
    let p_sector = peso_de(&sector, &ws);
    let mut m = Mempool::nueva(params(), evp(), CBID, base, Politica::dev());
    assert_eq!(
        m.admitir(None, dep.clone(), wd.clone(), ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, sector.clone(), ws.clone(), ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    let mut p_normal = 0u64;
    for i in 0..8u8 {
        let (tx, tst) = transferencia(&a, op_id(100 + i), 2 * FEE_ALTA, FEE_ALTA, b.pk);
        p_normal = peso_de(&tx, &tst);
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    // Bloque con sitio para el depósito + tres normales. El código viejo llena ese hueco con las
    // normales de tarifa alta y deja fuera la operación de sector.
    let max_bytes = p_dep + 3 * p_normal;
    assert!(p_dep + p_sector <= max_bytes, "la reserva debe caber");
    let sel = m.seleccionar(max_bytes, 0x5a5a);
    let ids: BTreeSet<TxId> = sel.iter().map(|(t, _)| zx_core::txid(t, CBID)).collect();
    let t_dep = zx_core::txid(&dep, CBID);
    let t_sector = zx_core::txid(&sector, CBID);
    assert!(ids.contains(&t_dep), "la reserva incluye el depósito");
    assert!(
        ids.contains(&t_sector),
        "la reserva incluye la operación de sector"
    );
    let bytes_reserva: u64 = sel
        .iter()
        .filter(|(t, _)| {
            let id = zx_core::txid(t, CBID);
            id == t_dep || id == t_sector
        })
        .map(|(t, w)| peso_de(t, w))
        .sum();
    assert!(bytes_reserva <= m.politica().w_reserva);
    assert!(bytes_reserva >= p_dep + p_sector);
}

/// Una segunda operación de sector de la misma clave sigue rechazada por la cuota por clave.
#[test]
fn segunda_operacion_de_sector_de_la_misma_clave_sigue_rechazada() {
    let a = ClaveDev::derivar(3, 0);
    let base = con_garantia(base_pow(&[]), &a);
    let mut m = Mempool::nueva(params(), evp(), CBID, base, Politica::dev());
    let (s1, w1) = alta_sector(&a, 0);
    assert_eq!(
        m.admitir(None, s1, w1, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    let (s2, w2) = alta_sector(&a, 1);
    assert_eq!(
        m.admitir(None, s2, w2, ahora(), Punto::Altura(1)),
        Err(Rechazo::Limite("cuota_por_clave"))
    );
    assert_eq!(m.estadisticas().n, 1);
}

/// La reserva combinada (depósitos + operaciones de sector) nunca pasa de `w_reserva`; la fase de
/// reserva incluye al menos una operación de sector.
#[test]
fn la_reserva_combinada_no_pasa_de_w_reserva() {
    let mut utxos: Vec<(OutPoint, i64, ClavePublica)> = Vec::new();
    let depositantes: Vec<ClaveDev> = (0..4).map(|i| ClaveDev::derivar(4, i)).collect();
    for (i, d) in depositantes.iter().enumerate() {
        utxos.push((op_id(50 + u8::try_from(i).unwrap()), 1_000, d.pk));
    }
    let sectoristas: Vec<ClaveDev> = (0..4).map(|i| ClaveDev::derivar(5, i)).collect();
    // Una normal de tarifa enorme (clave de muestreo 1.0) separa la fase de reserva del resto: en
    // el paso 2 va antes que cualquier reserva sobrante (tarifa 0) y cierra el prefijo de reserva.
    const FEE_ALTA: i64 = 1_000_000_000_000;
    let n = ClaveDev::derivar(7, 0);
    let dest = ClaveDev::derivar(7, 1);
    utxos.push((op_id(80), 2 * FEE_ALTA, n.pk));
    let mut base = base_pow(&utxos);
    for a in &sectoristas {
        base = con_garantia(base, a);
    }
    // Construye primero todas las transacciones para conocer sus pesos.
    let depositos: Vec<(Tx, Vec<Vec<u8>>)> = depositantes
        .iter()
        .enumerate()
        .map(|(i, d)| deposito(d, op_id(50 + u8::try_from(i).unwrap()), 1_000, 0))
        .collect();
    let sectores: Vec<(Tx, Vec<Vec<u8>>)> = sectoristas.iter().map(|a| alta_sector(a, 0)).collect();
    let p_dep = peso_de(&depositos[0].0, &depositos[0].1);
    let p_sector = peso_de(&sectores[0].0, &sectores[0].1);
    // Tope que deja sitio a los 4 depósitos y a exactamente una operación de sector.
    let mut pol = Politica::dev();
    pol.w_reserva = 4 * p_dep + p_sector;
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let mut t_deps = BTreeSet::new();
    for (tx, w) in depositos {
        t_deps.insert(zx_core::txid(&tx, CBID));
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    let mut t_sectores = BTreeSet::new();
    for (tx, w) in sectores {
        t_sectores.insert(zx_core::txid(&tx, CBID));
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    let (normal, wn) = transferencia(&n, op_id(80), 2 * FEE_ALTA, FEE_ALTA, dest.pk);
    assert_eq!(
        m.admitir(None, normal, wn, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    let sel = m.seleccionar(1_000_000, 0x1234);
    // La fase de reserva es el prefijo contiguo de entradas de reserva.
    let mut bytes_reserva = 0u64;
    let mut sectores_en_reserva = 0usize;
    for (tx, w) in &sel {
        let id = zx_core::txid(tx, CBID);
        let es_reserva = t_deps.contains(&id) || t_sectores.contains(&id);
        if !es_reserva {
            break;
        }
        bytes_reserva += peso_de(tx, w);
        if t_sectores.contains(&id) {
            sectores_en_reserva += 1;
        }
    }
    assert!(
        bytes_reserva <= m.politica().w_reserva,
        "la reserva no puede pasar de w_reserva"
    );
    assert!(
        sectores_en_reserva >= 1,
        "la reserva incluye al menos una operación de sector"
    );
}

/// La operación de sector desaloja una normal, **nunca** un depósito reservado.
#[test]
fn sector_no_desaloja_deposito_reservado() {
    let a = ClaveDev::derivar(6, 0);
    let d = ClaveDev::derivar(6, 1);
    let b = ClaveDev::derivar(6, 2);
    let base = con_garantia(
        base_pow(&[
            (op_id(1), 1_000, d.pk),
            (op_id(2), 1_000, a.pk),
            (op_id(3), 1_000, a.pk),
        ]),
        &a,
    );
    let (dep, wd) = deposito(&d, op_id(1), 1_000, 0);
    let (n1, w1) = transferencia(&a, op_id(2), 1_000, 900, b.pk); // fee 100
    let (n2, w2) = transferencia(&a, op_id(3), 1_000, 500, b.pk); // fee 500
    let (sector, ws) = alta_sector(&a, 0);
    let p_dep = peso_de(&dep, &wd) as usize;
    let p1 = peso_de(&n1, &w1) as usize;
    let p2 = peso_de(&n2, &w2) as usize;
    assert_eq!(p1, p2);
    let mut pol = Politica::dev();
    pol.s = p_dep + p1 + p2; // depósito + dos normales llenan S exactamente
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let t_dep = zx_core::txid(&dep, CBID);
    let t_n1 = zx_core::txid(&n1, CBID);
    let t_sector = zx_core::txid(&sector, CBID);
    assert_eq!(
        m.admitir(None, dep, wd, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, n1, w1, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, n2, w2, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, sector, ws, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert!(m.contiene(&t_dep), "el depósito reservado se queda");
    assert!(!m.contiene(&t_n1), "sale una normal, no el depósito");
    assert!(m.contiene(&t_sector), "la operación de sector entra");
    assert!(m.estadisticas().bytes <= m.politica().s);
}

// ── B26-2 · regresiones de la doble resta de bytes ──────────────────────────────────────────
//
// La versión rechazada de B26-1 restaba el peso evadido **dos veces** (`eliminar` ya lo descontaba
// de `bytes_totales` y el bucle lo volvía a restar vía `liberado`). Consecuencia: el bucle creía
// que ya cabía la candidata antes de tiempo y la comprobación final la rechazaba **después** de
// haber borrado normales (y, en el camino normal, después de haber subido el mínimo rodante). Las
// cuatro regresiones de abajo fallan con el parche congelado y pasan con el arreglo.

/// Retiro de garantía v2 (tarifa 0): transacción **normal** (no reserva) y la más pequeña que el
/// códec y la validación admiten (sin entradas ni salidas y un testigo de aceptación de 64 B).
fn retiro(clave: &ClaveDev, importe: i64, nonce: u64) -> (Tx, Vec<Vec<u8>>) {
    let tx = Tx {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo: TipoGarantia::Retiro,
            clave: clave.pk,
            importe: Amount::nuevo(importe).unwrap(),
            nonce,
        },
    };
    let mensaje = zx_core::mensaje_aceptacion(&tx, CBID);
    let firma: [u8; 64] = clave.sk.sign(&mensaje).into();
    (tx, vec![firma.to_vec()])
}

/// Operación v5 `ContestarAuditoria` con prueba opaca de `prueba_len` B (máximo 64): es la
/// operación de sector de tamaño variable que permite construir candidatas grandes.
fn contestar(
    clave: &ClaveDev,
    si: u16,
    auditoria_id: u64,
    prueba_len: usize,
) -> (Tx, Vec<Vec<u8>>) {
    let op = OperacionSector::ContestarAuditoria {
        clave: clave.pk,
        sector_index: si,
        auditoria_id,
        prueba: vec![0xABu8; prueba_len],
    };
    let tx = Tx {
        version: 5,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Sector { operacion: op },
    };
    let firma: [u8; 64] = clave.sk.sign(&zx_core::mensaje_sector(&tx, CBID)).into();
    (tx, vec![firma.to_vec()])
}

/// Añade al estado base un sector `Activo` de `clave` con auditoría abierta y contestable en el
/// slot 1 (estado construido a mano, sin saltarse el autómata: `op_contestar` lo valida).
fn con_auditoria_abierta(mut e: Estado, clave: &ClaveDev) -> Estado {
    let id = SectorId {
        clave: clave.pk,
        sector_index: 0,
        version: 0,
    };
    let q_sec = e.parametros_sector.q_sec;
    e.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0u64; 4],
            history_size: 1 << 20,
            etapa: Etapa::Activo,
            alta_slot: 0,
            renovacion_slot: 0,
            retiro_slot: -1,
            fianza: q_sec,
            aud_apertura: 0,
            aud_contestada: -1,
        },
    );
    e
}

/// Transferencia v1 con varias entradas (todas de `clave`), una firma por índice.
fn transferencia_multi(
    clave: &ClaveDev,
    entradas: &[(OutPoint, i64)],
    salidas: &[(i64, ClavePublica)],
) -> (Tx, Vec<Vec<u8>>) {
    let tx = Tx {
        version: 1,
        inputs: entradas
            .iter()
            .map(|(op, _)| TxIn {
                outpoint: *op,
                sequence: 0,
            })
            .collect(),
        outputs: salidas
            .iter()
            .map(|(v, pk)| TxOut {
                value: Amount::nuevo(*v).unwrap(),
                lock: Lock::PubKey { pubkey: *pk },
            })
            .collect(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let gastadas: Vec<SpentOutput> = entradas
        .iter()
        .map(|(_, v)| SpentOutput {
            value: Amount::nuevo(*v).unwrap(),
            lock: Lock::PubKey { pubkey: clave.pk },
        })
        .collect();
    let mut testigos = Vec::with_capacity(entradas.len());
    for i in 0..entradas.len() {
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, i, CBID).unwrap();
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        testigos.push(firma.to_vec());
    }
    (tx, testigos)
}

/// **† B26-2 · regresión 1 (sector).** Con la mempool llena de normales mínimos, el alta de sector
/// válida (`ContestarAuditoria`, prueba máxima) se admite desalojando **tantas normales como exija
/// su peso** (dos con el códec real). La versión con la doble resta desaloja una y rechaza.
#[test]
fn b26_2_sector_expulsa_las_normales_que_hacen_falta() {
    let s_key = ClaveDev::derivar(11, 0);
    let normales_keys: Vec<ClaveDev> = (0..4u32).map(|i| ClaveDev::derivar(11, 1 + i)).collect();
    let mut utxos = Vec::new();
    for (i, k) in normales_keys.iter().enumerate() {
        utxos.push((op_id(u8::try_from(10 + i).unwrap()), 1_000, k.pk));
    }
    let mut base = base_pow(&utxos);
    base = con_garantia(base, &s_key);
    for k in &normales_keys {
        base = con_garantia(base, k);
    }
    let base = con_auditoria_abierta(base, &s_key);

    let normales: Vec<(Tx, Vec<Vec<u8>>)> = normales_keys.iter().map(|k| retiro(k, 1, 0)).collect();
    let (sector, ws) = contestar(&s_key, 0, 7, 64);
    let p_n = peso_de(&normales[0].0, &normales[0].1);
    let p_s = peso_de(&sector, &ws);
    // Pesos reales del códec: el sector más ancho son 108 B de operación + cabecera + firma; la
    // normal más pequeña es el retiro v2. Con ellos el máximo de expulsiones es 2 (188/129).
    assert!(
        p_s > p_n,
        "el sector ({p_s} B) debe pesar más que una normal ({p_n} B)"
    );
    let expulsiones = usize::try_from(p_s.div_ceil(p_n)).unwrap();
    assert_eq!(
        expulsiones, 2,
        "pesos reales: {p_s} B de sector / {p_n} B de normal"
    );
    println!("[B26-2] codigo: p_sector={p_s} p_normal_min(retiro)={p_n} expulsiones={expulsiones}");

    let mut pol = Politica::dev();
    pol.s = (4 * p_n) as usize;
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let ids_normales: Vec<TxId> = normales
        .iter()
        .map(|(tx, _)| zx_core::txid(tx, CBID))
        .collect();
    for (tx, w) in normales {
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    assert_eq!(m.estadisticas().n, 4);
    assert_eq!(m.estadisticas().bytes as u64, 4 * p_n);

    let t_sector = zx_core::txid(&sector, CBID);
    assert_eq!(
        m.admitir(None, sector, ws, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert!(m.contiene(&t_sector), "la operación de sector entra");
    let restantes = ids_normales.iter().filter(|id| m.contiene(id)).count();
    assert_eq!(
        restantes,
        4 - expulsiones,
        "salen exactamente las normales necesarias, ni una más"
    );
    assert_eq!(m.estadisticas().n, 4 - expulsiones + 1);
    assert!(m.estadisticas().bytes <= m.politica().s);
}

/// **† B26-2 · regresión 2 (camino normal).** Una candidata v1 grande (3 entradas, 2 salidas)
/// exige **tres** expulsiones: se comprueba admisión, orden por feerate ascendente, bytes finales
/// y mínimo rodante (el mayor feerate expulsado).
#[test]
fn b26_2_normal_expulsa_tres_y_actualiza_minimo_rodante() {
    let a = ClaveDev::derivar(12, 0);
    let b = ClaveDev::derivar(12, 1);
    let mut utxos = Vec::new();
    for i in 0..7u8 {
        utxos.push((op_id(20 + i), 1_000, a.pk));
    }
    let base = base_pow(&utxos);
    let (n1, w1) = transferencia(&a, op_id(20), 1_000, 900, b.pk); // fee 100
    let (n2, w2) = transferencia(&a, op_id(21), 1_000, 800, b.pk); // fee 200
    let (n3, w3) = transferencia(&a, op_id(22), 1_000, 700, b.pk); // fee 300
    let (n4, w4) = transferencia(&a, op_id(23), 1_000, 600, b.pk); // fee 400
    let (cand, wc) = transferencia_multi(
        &a,
        &[(op_id(24), 1_000), (op_id(25), 1_000), (op_id(26), 1_000)],
        &[(1_000, b.pk), (1_000, b.pk)],
    ); // fee 1000
    let p_n = peso_de(&n1, &w1);
    assert_eq!(p_n, peso_de(&n2, &w2));
    assert_eq!(p_n, peso_de(&n3, &w3));
    assert_eq!(p_n, peso_de(&n4, &w4));
    let p_c = peso_de(&cand, &wc);
    let expulsiones = p_c.div_ceil(p_n);
    assert_eq!(expulsiones, 3, "candidata {p_c} B / normal {p_n} B");
    println!("[B26-2] codigo: p_candidata_normal={p_c} p_normal={p_n} expulsiones={expulsiones}");

    let mut pol = Politica::dev();
    pol.s = (4 * p_n) as usize;
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let t1 = zx_core::txid(&n1, CBID);
    let t2 = zx_core::txid(&n2, CBID);
    let t3 = zx_core::txid(&n3, CBID);
    let t4 = zx_core::txid(&n4, CBID);
    for (tx, w) in [(n1, w1), (n2, w2), (n3, w3), (n4, w4)] {
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    assert_eq!(m.estadisticas().n, 4);
    assert_eq!(m.estadisticas().bytes as u64, 4 * p_n);
    assert_eq!(m.estadisticas().minimo_rodante, (0, 1));

    assert_eq!(
        m.admitir(None, cand, wc, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    // Salen las tres de menor feerate (n1, n2, n3); la cuarta se queda.
    assert!(!m.contiene(&t1), "sale la de menor feerate");
    assert!(!m.contiene(&t2));
    assert!(!m.contiene(&t3));
    assert!(m.contiene(&t4), "la de mayor feerate se queda");
    assert_eq!(
        m.estadisticas().bytes as u64,
        4 * p_n - 3 * p_n + p_c,
        "bytes finales = cuatro normales − tres expulsadas + la candidata"
    );
    assert!(m.estadisticas().bytes <= m.politica().s);
    assert_eq!(
        m.estadisticas().minimo_rodante,
        (300, u128::from(p_n)),
        "el mínimo rodante es el mayor feerate expulsado (n3)"
    );
}

/// **† B26-2 · regresión 3 (rechazo sin mutar, camino de sector).** Si las normales elegibles no
/// bastan, el rechazo conserva **todo**: conteo, txids, bytes y mínimo rodante; las reservas
/// (depósitos) siguen presentes.
#[test]
fn b26_2_rechazo_sin_normales_suficientes_no_muta_sector() {
    let s_key = ClaveDev::derivar(13, 0);
    let d0 = ClaveDev::derivar(13, 1);
    let d1 = ClaveDev::derivar(13, 2);
    let n = ClaveDev::derivar(13, 3);
    let b = ClaveDev::derivar(13, 4);
    let mut base = base_pow(&[
        (op_id(30), 1_000, d0.pk),
        (op_id(31), 1_000, d1.pk),
        (op_id(32), 1_000, n.pk),
    ]);
    base = con_garantia(base, &s_key);
    let base = con_auditoria_abierta(base, &s_key);

    let (dep0, wd0) = deposito(&d0, op_id(30), 1_000, 0);
    let (dep1, wd1) = deposito(&d1, op_id(31), 1_000, 0);
    let (normal, wn) = transferencia(&n, op_id(32), 1_000, 900, b.pk);
    let (sector, ws) = contestar(&s_key, 0, 7, 64);
    let p_dep = peso_de(&dep0, &wd0);
    let p_normal = peso_de(&normal, &wn);
    let p_sector = peso_de(&sector, &ws);
    assert!(
        p_sector > p_normal,
        "el sector ({p_sector} B) necesita más de una normal ({p_normal} B)"
    );

    let mut pol = Politica::dev();
    pol.s = (2 * p_dep + p_normal) as usize;
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let t_dep0 = zx_core::txid(&dep0, CBID);
    let t_dep1 = zx_core::txid(&dep1, CBID);
    let t_normal = zx_core::txid(&normal, CBID);
    assert_eq!(
        m.admitir(None, dep0, wd0, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, dep1, wd1, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, normal, wn, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    let antes = (
        m.estadisticas().n,
        m.estadisticas().bytes,
        m.estadisticas().minimo_rodante,
    );

    assert_eq!(
        m.admitir(None, sector, ws, ahora(), Punto::Altura(1)),
        Err(Rechazo::Limite("global"))
    );
    let despues = (
        m.estadisticas().n,
        m.estadisticas().bytes,
        m.estadisticas().minimo_rodante,
    );
    assert_eq!(antes, despues, "la mempool no cambia tras el rechazo");
    assert!(
        m.contiene(&t_dep0) && m.contiene(&t_dep1),
        "las reservas siguen"
    );
    assert!(m.contiene(&t_normal), "la normal no se borra a medias");
    assert_eq!(m.rechazos_limite().global, 1);
}

/// **† B26-2 · regresión 4 (rechazo sin mutar, camino normal).** Candidata grande con tarifa alta
/// y una sola normal desalojable: rechazo sin borrarla y **sin** subir el mínimo rodante.
#[test]
fn b26_2_rechazo_sin_normales_suficientes_no_muta_normal() {
    let a = ClaveDev::derivar(14, 0);
    let b = ClaveDev::derivar(14, 1);
    let d = ClaveDev::derivar(14, 2);
    let base = base_pow(&[
        (op_id(40), 1_000, a.pk),
        (op_id(41), 1_000, a.pk),
        (op_id(42), 1_000, a.pk),
        (op_id(43), 1_000, a.pk),
        (op_id(44), 1_000, d.pk),
    ]);
    let (normal, wn) = transferencia(&a, op_id(40), 1_000, 900, b.pk); // fee 100
    let (cand, wc) = transferencia_multi(
        &a,
        &[(op_id(41), 1_000), (op_id(42), 1_000), (op_id(43), 1_000)],
        &[(1_000, b.pk)],
    ); // fee 2000, grande
    let (dep, wd) = deposito(&d, op_id(44), 1_000, 0);
    let p_n = peso_de(&normal, &wn);
    let p_c = peso_de(&cand, &wc);
    let p_dep = peso_de(&dep, &wd);
    assert!(
        p_c > 2 * p_n,
        "la candidata ({p_c} B) necesita más de dos normales"
    );

    let mut pol = Politica::dev();
    pol.s = (p_n + p_dep) as usize;
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let t_normal = zx_core::txid(&normal, CBID);
    assert_eq!(
        m.admitir(None, normal, wn, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, dep, wd, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(m.estadisticas().minimo_rodante, (0, 1));
    let antes = (
        m.estadisticas().n,
        m.estadisticas().bytes,
        m.estadisticas().minimo_rodante,
    );

    assert_eq!(
        m.admitir(None, cand, wc, ahora(), Punto::Altura(1)),
        Err(Rechazo::Limite("global"))
    );
    let despues = (
        m.estadisticas().n,
        m.estadisticas().bytes,
        m.estadisticas().minimo_rodante,
    );
    assert_eq!(antes, despues, "rechazo sin mutar la mempool");
    assert_eq!(
        m.estadisticas().minimo_rodante,
        (0, 1),
        "el mínimo rodante no sube con una candidata rechazada"
    );
    assert!(m.contiene(&t_normal));
    assert_eq!(m.rechazos_limite().global, 1);
}

// ── B26-3 · atomicidad de todos los rechazos ────────────────────────────────────────────────
//
// Con B26-2 el desalojo se ejecutaba **antes** de comprobar `tarifa_minima`, `tarifa_rodante` y
// del contexto. Una candidata que superaba el plan de expulsión pero luego era rechazada por
// cualquiera de esas comprobaciones ya había borrado normales (y, en el camino normal, había subido
// el mínimo rodante). Las regresiones de abajo fallan con B26-2 y pasan con la corrección.

/// **† B26-3 · regresión 1 (tarifa mínima).** Candidata v1 firmada con feerate **mayor** que las
/// normales elegibles (B26-2 la habría admitido desalojándolas) pero por debajo de `phi_min`
/// configurado: el rechazo por `tarifa_minima` conserva entradas, txids, bytes y mínimo rodante.
#[test]
fn b26_3_tarifa_minima_no_desaloja() {
    let a = ClaveDev::derivar(21, 0);
    let b = ClaveDev::derivar(21, 1);
    let normales_keys: Vec<ClaveDev> = (0..4u32).map(|i| ClaveDev::derivar(21, 2 + i)).collect();
    let mut base = base_pow(&[(op_id(90), 1_000, a.pk)]);
    for k in &normales_keys {
        base = con_garantia(base, k);
    }
    // Normales exentas de tarifa mínima (retiros v2, tarifa 0): el peso mínimo real del códec.
    let normales: Vec<(Tx, Vec<Vec<u8>>)> = normales_keys.iter().map(|k| retiro(k, 1, 0)).collect();
    let (cand, wc) = transferencia(&a, op_id(90), 1_000, 999, b.pk); // fee 1 > 0
    let p_n = peso_de(&normales[0].0, &normales[0].1);
    let p_c = peso_de(&cand, &wc);
    assert!(
        p_c > p_n,
        "la candidata ({p_c} B) pide desalojo de normales ({p_n} B)"
    );
    let mut pol = Politica::dev();
    pol.phi_min = 1; // fee 1 < 1 brek/B · p_c ⇒ tarifa_minima
    pol.s = (4 * p_n) as usize; // las cuatro normales llenan S exactamente
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let ids: Vec<TxId> = normales
        .iter()
        .map(|(tx, _)| zx_core::txid(tx, CBID))
        .collect();
    for (tx, w) in normales {
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    assert_eq!(m.estadisticas().n, 4);
    let antes = (
        m.estadisticas().n,
        m.estadisticas().bytes,
        m.estadisticas().minimo_rodante,
    );
    assert_eq!(
        m.admitir(None, cand, wc, ahora(), Punto::Altura(1)),
        Err(Rechazo::Limite("tarifa_minima"))
    );
    assert_eq!(
        (
            m.estadisticas().n,
            m.estadisticas().bytes,
            m.estadisticas().minimo_rodante,
        ),
        antes,
        "el rechazo por tarifa mínima no toca la mempool"
    );
    for id in &ids {
        assert!(m.contiene(id), "la normal {id:?} sigue en la mempool");
    }
    assert_eq!(m.rechazos_limite().tarifa_minima, 1);
}

/// **† B26-3 · regresión 3 (contexto inválido).** En mempool llena, una operación de sector v5
/// firmada que no valida contra el estado (no hay auditoría abierta) se rechaza **sin** desalojar:
/// conserva entradas, txids, bytes, mínimo rodante y la vista virtual (una hija que gasta una
/// salida preservada no queda huérfana).
#[test]
fn b26_3_contexto_invalido_no_desaloja() {
    let s_key = ClaveDev::derivar(23, 0);
    let b = ClaveDev::derivar(23, 1);
    let normales_keys: Vec<ClaveDev> = (0..4u32).map(|i| ClaveDev::derivar(23, 2 + i)).collect();
    let mut utxos = Vec::new();
    for (i, k) in normales_keys.iter().enumerate() {
        utxos.push((op_id(u8::try_from(20 + i).unwrap()), 1_000, k.pk));
    }
    let mut base = base_pow(&utxos);
    base = con_garantia(base, &s_key); // la clave existe, pero no hay sector/auditoría abierta
    // `analizar` acepta forma y firma; el motor de transición la rechaza por contexto (sector
    // inexistente): sin bypass de validación.
    let (sector, ws) = contestar(&s_key, 0, 7, 64);
    let normales: Vec<(Tx, Vec<Vec<u8>>)> = normales_keys
        .iter()
        .enumerate()
        .map(|(i, k)| transferencia(k, op_id(u8::try_from(20 + i).unwrap()), 1_000, 900, b.pk))
        .collect();
    let p_n = peso_de(&normales[0].0, &normales[0].1);
    let p_s = peso_de(&sector, &ws);
    assert!(
        p_s > p_n,
        "el sector ({p_s} B) exige desalojar más de una normal ({p_n} B)"
    );
    let mut pol = Politica::dev();
    pol.s = (4 * p_n) as usize;
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    let ids: Vec<TxId> = normales
        .iter()
        .map(|(tx, _)| zx_core::txid(tx, CBID))
        .collect();
    for (tx, w) in normales {
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    let antes = (
        m.estadisticas().n,
        m.estadisticas().bytes,
        m.estadisticas().minimo_rodante,
    );
    let rechazo = m.admitir(None, sector, ws, ahora(), Punto::Altura(1));
    assert!(
        matches!(
            rechazo,
            Err(Rechazo::VistaLocal(_)) | Err(Rechazo::Demostrable(_))
        ),
        "el sector inválido se rechaza por contexto: {rechazo:?}"
    );
    assert_eq!(
        (
            m.estadisticas().n,
            m.estadisticas().bytes,
            m.estadisticas().minimo_rodante,
        ),
        antes,
        "el rechazo por contexto no toca la mempool"
    );
    for id in &ids {
        assert!(m.contiene(id), "la normal {id:?} sigue en la mempool");
    }
    // Vista virtual: una hija que gasta la salida de una normal preservada no puede quedar
    // huérfana (si se hubiera desalojado y recomputado la vista, su entrada faltaría).
    let op_hija = OutPoint {
        prev_txid: ids[0],
        prev_index: 0,
    };
    let destino = ClaveDev::derivar(23, 9);
    let (hija, wh) = transferencia(&b, op_hija, 900, 800, destino.pk);
    let r = m.admitir(None, hija, wh, ahora(), Punto::Altura(1));
    assert!(
        !matches!(r, Ok(Admision::Huerfana)),
        "la vista conserva la salida de la normal preservada: {r:?}"
    );
}

// ── B26-4 · desalojo indirecto de reservas ─────────────────────────────────────────────────
//
// Con B26-3, `desalojables_por_feerate` excluía solo las reservas directas. Una normal **padre**
// de un depósito reservado seguía siendo expulsable y `eliminar` → `recomputar_vista` borraba
// después el depósito (y, con él, la validez contextual de las reservas que dependían de su
// estado). Las regresiones de abajo fijan el invariante: una candidata solo desaloja entradas si
// la reserva vigente sobrevive; si no hay normales independientes suficientes, el rechazo es
// atómico. Fallan con B26-3 y pasan con el arreglo.

/// **† B26-4 · regresión 1 (ancestro inmediato).** El padre normal que sostiene un depósito
/// reservado no es expulsable: sin otras normales, la candidata de mejor tarifa se rechaza sin
/// borrar ni el padre ni la reserva, y el rechazo conserva conteo, bytes y mínimo rodante.
#[test]
fn b26_4_padre_normal_sostiene_deposito_reservado() {
    let a = ClaveDev::derivar(31, 0);
    let d = ClaveDev::derivar(31, 1);
    let b = ClaveDev::derivar(31, 2);
    let base = base_pow(&[(op_id(1), 1_000, a.pk), (op_id(2), 1_000, a.pk)]);
    let (padre, wp) = transferencia(&a, op_id(1), 1_000, 900, d.pk); // fee 100
    let t_padre = zx_core::txid(&padre, CBID);
    let (dep, wd) = deposito(
        &d,
        OutPoint {
            prev_txid: t_padre,
            prev_index: 0,
        },
        900,
        0,
    ); // reserva: d no tiene garantía en la base
    let t_dep = zx_core::txid(&dep, CBID);
    let (cand, wc) = transferencia(&a, op_id(2), 1_000, 500, b.pk); // fee 500
    let t_cand = zx_core::txid(&cand, CBID);
    let p_p = peso_de(&padre, &wp);
    let p_d = peso_de(&dep, &wd);
    let p_c = peso_de(&cand, &wc);
    assert_eq!(p_p, p_c, "misma transferencia v1, mismo peso");
    assert!(p_d > p_p, "el depósito v2 pesa más");

    let mut pol = Politica::dev();
    pol.s = (p_p + p_d) as usize; // el padre y el depósito llenan S
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    assert_eq!(
        m.admitir(None, padre, wp, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, dep, wd, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert!(m.contiene(&t_dep), "el depósito reservado entra");
    let antes = (
        m.estadisticas().n,
        m.estadisticas().bytes,
        m.estadisticas().minimo_rodante,
    );
    // La candidata supera en tarifa al padre: con B26-3 el plan la expulsaba y `recomputar_vista`
    // borraba después el depósito. Con la protección, no hay normales elegibles y se rechaza.
    assert_eq!(
        m.admitir(None, cand, wc, ahora(), Punto::Altura(1)),
        Err(Rechazo::Limite("global")),
        "sin normales independientes el rechazo es atómico"
    );
    assert!(m.contiene(&t_dep), "la reserva sobrevive");
    assert!(m.contiene(&t_padre), "el padre que la sostiene sobrevive");
    assert!(!m.contiene(&t_cand), "la candidata no entra");
    assert_eq!(
        (
            m.estadisticas().n,
            m.estadisticas().bytes,
            m.estadisticas().minimo_rodante,
        ),
        antes,
        "el rechazo conserva entradas, bytes y mínimo rodante"
    );
}

/// **† B26-4 · regresión 2 (alternativa independiente).** Con una normal independiente elegible,
/// la candidata se admite desalojándola **a ella** y conserva el padre protegido y la reserva.
#[test]
fn b26_4_hay_normales_independientes_y_admite() {
    let a = ClaveDev::derivar(32, 0);
    let d = ClaveDev::derivar(32, 1);
    let b = ClaveDev::derivar(32, 2);
    let base = base_pow(&[
        (op_id(1), 1_000, a.pk), // padre del depósito
        (op_id(2), 1_000, a.pk), // normal independiente
        (op_id(3), 1_000, a.pk), // candidata
    ]);
    let (padre, wp) = transferencia(&a, op_id(1), 1_000, 900, d.pk); // fee 100
    let t_padre = zx_core::txid(&padre, CBID);
    let (dep, wd) = deposito(
        &d,
        OutPoint {
            prev_txid: t_padre,
            prev_index: 0,
        },
        900,
        0,
    );
    let t_dep = zx_core::txid(&dep, CBID);
    let (normal, wn) = transferencia(&a, op_id(2), 1_000, 800, b.pk); // fee 200, independiente
    let t_normal = zx_core::txid(&normal, CBID);
    let (cand, wc) = transferencia(&a, op_id(3), 1_000, 500, b.pk); // fee 500
    let t_cand = zx_core::txid(&cand, CBID);
    let p_p = peso_de(&padre, &wp);
    let p_d = peso_de(&dep, &wd);
    let p_n = peso_de(&normal, &wn);
    let p_c = peso_de(&cand, &wc);
    assert_eq!(p_p, p_n);
    assert_eq!(p_p, p_c);

    let mut pol = Politica::dev();
    pol.s = (p_p + p_d + p_n) as usize; // las tres llenan S
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    for (tx, w) in [(padre, wp), (dep, wd), (normal, wn)] {
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    assert_eq!(m.estadisticas().n, 3);
    assert_eq!(
        m.admitir(None, cand, wc, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert!(m.contiene(&t_cand), "la candidata entra");
    assert!(
        !m.contiene(&t_normal),
        "sale la normal independiente, no el padre"
    );
    assert!(
        m.contiene(&t_padre),
        "el padre que sostiene la reserva se queda"
    );
    assert!(m.contiene(&t_dep), "la reserva se queda");
    assert!(m.estadisticas().bytes <= m.politica().s);
}

/// **† B26-4 · regresión 3 (ancestro transitivo).** La cadena `P1 → P2 → depósito reservado`: ni
/// P1 ni P2 son expulsables porque cualquiera de ellos deja al depósito sin su entrada. La
/// candidata se rechaza y los tres siguen presentes.
#[test]
fn b26_4_ancestro_transitivo_protege_reserva() {
    let a = ClaveDev::derivar(33, 0);
    let d = ClaveDev::derivar(33, 1);
    let b = ClaveDev::derivar(33, 2);
    let base = base_pow(&[(op_id(1), 1_000, a.pk), (op_id(2), 1_000, a.pk)]);
    let (p1, w1) = transferencia(&a, op_id(1), 1_000, 950, a.pk); // fee 50
    let t_p1 = zx_core::txid(&p1, CBID);
    let (p2, w2) = transferencia(
        &a,
        OutPoint {
            prev_txid: t_p1,
            prev_index: 0,
        },
        950,
        850,
        d.pk,
    ); // fee 100
    let t_p2 = zx_core::txid(&p2, CBID);
    let (dep, wd) = deposito(
        &d,
        OutPoint {
            prev_txid: t_p2,
            prev_index: 0,
        },
        850,
        0,
    );
    let t_dep = zx_core::txid(&dep, CBID);
    let (cand, wc) = transferencia(&a, op_id(2), 1_000, 500, b.pk); // fee 500
    let p1w = peso_de(&p1, &w1);
    let p2w = peso_de(&p2, &w2);
    let p_d = peso_de(&dep, &wd);
    let p_c = peso_de(&cand, &wc);
    assert_eq!(p1w, p2w);
    assert_eq!(p1w, p_c);

    let mut pol = Politica::dev();
    pol.s = (p1w + p2w + p_d) as usize;
    let mut m = Mempool::nueva(params(), evp(), CBID, base, pol);
    for (tx, w) in [(p1, w1), (p2, w2), (dep, wd)] {
        assert_eq!(
            m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }
    assert_eq!(m.estadisticas().n, 3);
    assert_eq!(
        m.admitir(None, cand, wc, ahora(), Punto::Altura(1)),
        Err(Rechazo::Limite("global"))
    );
    assert!(m.contiene(&t_dep), "la reserva sigue");
    assert!(m.contiene(&t_p1), "el ancestro raíz sigue");
    assert!(m.contiene(&t_p2), "el ancestro intermedio sigue");
    assert_eq!(m.estadisticas().n, 3);
}

/// **B26-4 · límite de la API (no reproducido): dependencia de estado sector→garantía.** Un alta
/// de sector depende del estado de garantía, pero la variante «un depósito pendiente de la misma
/// clave sostiene al sector» **no es construible**: `cuota_por_clave` admite a lo sumo una
/// operación pendiente por clave y el depósito ya ocupa la cuota. El caso indirecto reproducible
/// es el de ancestro UTXO (regresiones 1-3); además, el planificador de B26-4 reaplica la vista y
/// protege cualquier reserva que dependiera de estado, no solo de UTXO.
#[test]
fn b26_4_dependencia_sector_deposito_misma_clave_bloqueada_por_cuota() {
    let a = ClaveDev::derivar(34, 0);
    let d = ClaveDev::derivar(34, 1);
    let base = base_pow(&[(op_id(1), 1_000, a.pk)]);
    let (padre, wp) = transferencia(&a, op_id(1), 1_000, 900, d.pk);
    let t_padre = zx_core::txid(&padre, CBID);
    let (dep, wd) = deposito(
        &d,
        OutPoint {
            prev_txid: t_padre,
            prev_index: 0,
        },
        900,
        0,
    );
    let (sector, ws) = alta_sector(&d, 0);
    let mut m = Mempool::nueva(params(), evp(), CBID, base, Politica::dev());
    assert_eq!(
        m.admitir(None, padre, wp, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, dep, wd, ahora(), Punto::Altura(1)),
        Ok(Admision::Admitida)
    );
    assert_eq!(
        m.admitir(None, sector, ws, ahora(), Punto::Altura(1)),
        Err(Rechazo::Limite("cuota_por_clave")),
        "el depósito pendiente ocupa la cuota de la clave"
    );
}
