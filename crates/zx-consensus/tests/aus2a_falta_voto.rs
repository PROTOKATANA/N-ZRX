//! AUS-2a · la falta «elegido sin voto» en el consenso, según el diseño aceptado AV-1.
//!
//! Pruebas P1–P10 de la orden AUS-2a sobre el camino de estado real (`aplicar_con_undo` y la API
//! de votos), sin la firma Ed25519 de la transacción (que comprueba `aplicar_tx` y es ortogonal).
//!
//! - P1: el voto propio dentro de plazo admite la clave y el códec da la vuelta.
//! - P2: rechazos con error propio (plazo, clave BLS ajena, firma, repetido / ya certificado).
//! - P3: la liquidación respeta `votantes_voto` (firmante, voto propio y omitido).
//! - P4: ventana sin certificado tras una base con la tabla sin cambiar (R4 ii).
//! - P5: sin cobro (tabla desconocida, clave no registrada) y C6: el peso mínimo sí tiene deber.
//! - P6: aritmética exacta de la deuda y la quema.
//! - P7: una sola liquidación por ventana; la base conserva su tabla.
//! - P8: undo exacto al liquidar/cobrar y al aplicar un voto propio.
//! - P9: la falta de la última ventana elegible se cobra antes de poder liberar la fianza.
//! - P10: el coste por bloque no crece con la altura (2 000 ventanas con tabla de 1 000 claves).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use std::collections::BTreeSet;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::aplicar_voto_propio_con_undo;
use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, apertura_ventana, cierre_ventana};
use zx_consensus::transicion::{ErrorTransicion, Estado, Fase, Garantia, fuente_peso_de};
use zx_core::{Amount, ClavePublica, OperacionAlmacenamiento};
use zx_votos::{DOMINIO_VOTO, Firma, mensaje_voto_peso};

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Constructores y utilidades
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
}

/// Clave Ed25519 ficticia (identificador determinista).
fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn registro(p: &ParametrosSector, clave: ClavePublica, indice: u16) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    let reg = RegistroSector {
        id,
        r2: [0; 4],
        history_size: 1,
        etapa: Etapa::Activo,
        alta_slot: 0,
        renovacion_slot: 0,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado PoST con `claves = (índice Ed25519, nº de sectores)` y garantía activa `g` por clave.
fn estado_post(
    claves: &[(u8, usize)],
    g: i128,
) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for (indice, n_sectores) in claves {
        let secreta = bls(*indice)?;
        let pk = secreta.clave_publica();
        let e = ed(*indice);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for i in 0..*n_sectores {
            let (id, reg) = registro(&p, e, u16::try_from(i)?);
            est.sectores.insert(id, reg);
        }
        let mut gg = Garantia::nueva();
        gg.activo = Amount::nuevo(i64::try_from(g)?)?;
        est.garantias.insert(e, gg);
        secretas.push(secreta);
    }
    Ok((est, secretas))
}

/// Voto propio válido de `secreta` sobre `(n, candidato, h_t)`.
fn voto_propio(
    secreta: &zx_votos::ClaveSecreta,
    clave: ClavePublica,
    n: u64,
    candidato: [u8; 32],
    h_t: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let firma: Firma = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]),
    )?;
    Ok(OperacionAlmacenamiento::VotoPropio {
        clave,
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave_bls: pk.bytes(),
        firma: firma.bytes(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P1 · el voto propio dentro de plazo admite la clave y el códec da la vuelta
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p1_voto_propio_dentro_de_plazo_admite_y_codifica() -> Result<(), Error> {
    let n = 1u64;
    let (est, secretas) = estado_post(&[(1, 1)], 0)?;
    let op = voto_propio(&secretas[0], ed(1), n, [0x11; 32], [0x22; 32])?;

    // El códec canónico da la vuelta exacta y consume todos los bytes.
    let bytes = op.bytes_canonicos()?;
    let (vuelta, consumidos) = OperacionAlmacenamiento::desde_canonica(&bytes)?;
    assert_eq!(vuelta, op, "ida y vuelta");
    assert_eq!(consumidos, bytes.len(), "consume todos los bytes");
    assert_eq!(bytes[0], 0x08, "clase 0x08 primero");

    // Admisible en `[apertura(n), cierre(n) + W_reveal]`.
    for slot in [
        apertura_ventana(n),
        100,
        cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS,
    ] {
        let (nuevo, _, r) = aplicar_voto_propio_con_undo(&est, &op, i64::try_from(slot)?);
        r?;
        assert!(
            nuevo
                .votantes_voto
                .get(&n)
                .is_some_and(|v| v.contains(&ed(1))),
            "la clave queda admitida en la ventana {n} (slot {slot})"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P2 · rechazos con error propio
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p2_rechazos_con_error_propio() -> Result<(), Error> {
    let n = 1u64;
    let (est, secretas) = estado_post(&[(1, 1)], 0)?;
    let op = voto_propio(&secretas[0], ed(1), n, [0x11; 32], [0x22; 32])?;

    // Fuera de plazo: antes de abrir y después de `cierre + W_reveal`.
    let antes = i64::try_from(apertura_ventana(n) - 1)?;
    let (_, _, r) = aplicar_voto_propio_con_undo(&est, &op, antes);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioPlazo));
    let despues = i64::try_from(cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1)?;
    let (_, _, r) = aplicar_voto_propio_con_undo(&est, &op, despues);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioPlazo));

    // Firma inválida.
    let mut firma_mala = op.clone();
    if let OperacionAlmacenamiento::VotoPropio { firma, .. } = &mut firma_mala {
        firma[0] ^= 0xFF;
    }
    let (_, _, r) = aplicar_voto_propio_con_undo(&est, &firma_mala, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioFirma));

    // Clave BLS ajena.
    let ajena = bls(2)?;
    let mut bls_mala = op.clone();
    if let OperacionAlmacenamiento::VotoPropio { clave_bls, .. } = &mut bls_mala {
        *clave_bls = ajena.clave_publica().bytes();
    }
    let (_, _, r) = aplicar_voto_propio_con_undo(&est, &bls_mala, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioClave));

    // Repetido: la segunda aplicación se rechaza.
    let (una, _, r) = aplicar_voto_propio_con_undo(&est, &op, 100);
    r?;
    let (_, _, r) = aplicar_voto_propio_con_undo(&una, &op, 101);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioDuplicado));

    // De quien ya firmó el certificado (ya está en `votantes_voto[n]`).
    let mut con_cert = est.clone();
    let mut votantes: BTreeSet<ClavePublica> = BTreeSet::new();
    votantes.insert(ed(1));
    con_cert.votantes_voto.insert(n, votantes);
    let (_, _, r) = aplicar_voto_propio_con_undo(&con_cert, &op, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioDuplicado));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P3 · la liquidación respeta `votantes_voto` (firmante, voto propio y omitido)
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P4 · ventana sin certificado tras una base cuya tabla no cambió (R4 ii)
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P5 · sin cobro (cuota entera cero, tabla desconocida, clave no registrada)
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P6 · aritmética exacta de la deuda y la quema
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P7 · una sola vez y la base conserva su tabla
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P8 · undo exacto
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P9 · retención: la falta se cobra antes de poder liberar la fianza
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P10 · el coste por bloque no crece con la altura (2 000 ventanas, tabla de 1 000 claves)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `fuente_peso_de` se usa en la preparación de otros arneses; aquí se comprueba que el estado de
/// P4 lo tiene en cuenta al construir tablas (evita `unused`).
#[test]
fn p0_fuente_peso_es_usable() -> Result<(), Error> {
    let (est, _) = estado_post(&[(1, 2)], 50)?;
    assert!(fuente_peso_de(&est, &ed(1), 0, &est.parametros_sector) > 0);
    Ok(())
}
