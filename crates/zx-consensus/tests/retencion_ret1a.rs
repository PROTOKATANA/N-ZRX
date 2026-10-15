//! RET-1a · retención de votos en el consenso (RV-1, RV-3, RV-4).
//!
//! P1–P6 de `ORDEN-RET1A.md` §5. Se usan los valores del perfil dev por **literales**
//! (`96`, `600`, `1 023`, `1 024`, `330`) y la API existente para que este archivo compile también
//! contra `ws.orig`; P7 (consistencia de la fórmula) vive en `retencion_formula_rv.rs` porque
//! referencia los símbolos nuevos.
//!
//! Ejecutar con salida cruda:
//! `cargo test -p zx-consensus --test retencion_ret1a -- --nocapture`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use zx_consensus::sectores::{
    AplicadorSector, CuentaGarantia, EstadoSector, Etapa, MotivoSector, NO_HAY, Operacion,
    ParametrosSector, RegistroSector, Retiro, SectorId, TipoOp, clave_de,
};
use zx_core::ClavePublica;

/// Fianza por sector del perfil dev.
const Q_SEC: i64 = 140;

// ─────────────────────────────────────────────────────────────────────────────
// P1 · sector en retirada: la puerta RV-3 lo retiene hasta `retiro + 1 024`.
// ─────────────────────────────────────────────────────────────────────────────

/// Estado del oráculo con un sector en `EnRetirada` desde `s`, sin incidente ni producción.
fn estado_sector_en_retirada(
    p: &ParametrosSector,
    clave: ClavePublica,
    s: i64,
) -> (EstadoSector, SectorId) {
    let id = SectorId {
        clave,
        sector_index: 0,
        version: 0,
    };
    let mut est = EstadoSector {
        slot_actual: s,
        ..EstadoSector::default()
    };
    est.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0; 4],
            history_size: 1,
            etapa: Etapa::EnRetirada,
            alta_slot: 0,
            renovacion_slot: 0,
            retiro_slot: s,
            fianza: p.q_sec,
            aud_apertura: NO_HAY,
            aud_contestada: NO_HAY,
        },
    );
    (est, id)
}

#[test]
fn p1_el_sector_en_retirada_no_se_libera_antes_de_rv() {
    let p = ParametrosSector::dev();
    let s = 2i64;
    let clave = clave_de(1);
    let (mut est, id) = estado_sector_en_retirada(&p, clave, s);
    let mut ap = AplicadorSector::nuevo(&mut est);

    ap.materializar(s + 96, &p);
    assert_eq!(
        ap.estado.sectores[&id].etapa,
        Etapa::EnRetirada,
        "a retiro + R_sec (96) el sector no se libera"
    );
    ap.materializar(s + 1_023, &p);
    assert_eq!(
        ap.estado.sectores[&id].etapa,
        Etapa::EnRetirada,
        "a retiro + R_V - 1 (1 023) el sector no se libera"
    );
    ap.materializar(s + 1_024, &p);
    assert_eq!(
        ap.estado.sectores[&id].etapa,
        Etapa::Retirado,
        "a retiro + R_V (1 024) el sector se libera"
    );
    assert_eq!(ap.estado.sectores[&id].fianza, 0);
    assert_eq!(ap.estado.garantias[&clave].activo, p.q_sec);
}

// ─────────────────────────────────────────────────────────────────────────────
// P2 · garantía: un retiro iniciado en `s` no vence antes de `s + 1 024`.
// ─────────────────────────────────────────────────────────────────────────────

fn op_liberacion(clave: ClavePublica, importe: i64) -> Operacion {
    Operacion {
        tipo: TipoOp::Liberacion,
        clave,
        importe,
        firma: true,
        ..Operacion::base(TipoOp::Liberacion)
    }
}

#[test]
fn p2_la_garantia_no_se_libera_antes_de_rv() {
    let p = ParametrosSector::dev();
    let s = 2i64;
    let clave = clave_de(2);
    let importe = Q_SEC;
    let mut est = EstadoSector {
        slot_actual: s,
        ..EstadoSector::default()
    };
    let mut c = CuentaGarantia::nueva(clave);
    c.activo = 0;
    c.en_retirada.push(Retiro {
        importe,
        inicio_slot: s,
    });
    est.garantias.insert(clave, c);
    let mut ap = AplicadorSector::nuevo(&mut est);
    let op = op_liberacion(clave, importe);

    assert_eq!(
        ap.op_liberacion(&op, s + 600, &p),
        MotivoSector::ErrFianza,
        "a retiro + R_slots (600) no vence: manda R_V"
    );
    assert_eq!(
        ap.op_liberacion(&op, s + 1_023, &p),
        MotivoSector::ErrFianza,
        "a retiro + R_V - 1 (1 023) no vence"
    );
    assert_eq!(
        ap.op_liberacion(&op, s + 1_024, &p),
        MotivoSector::Ok,
        "a retiro + R_V (1 024) vence"
    );
    assert!(ap.estado.garantias[&clave].en_retirada.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures de voto (mismos orígenes que FV-4b-N2/N3 y REAN-1).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p6_con_r_votos_cero_el_modelo_no_cambia() {
    let p = ParametrosSector::fixture();
    let s = 10i64;
    let clave = clave_de(3);
    let (mut est, id) = estado_sector_en_retirada(&p, clave, s);
    let mut ap = AplicadorSector::nuevo(&mut est);
    ap.materializar(s + p.r_sec - 1, &p);
    assert_eq!(
        ap.estado.sectores[&id].etapa,
        Etapa::EnRetirada,
        "a R_sec - 1 no libera"
    );
    ap.materializar(s + p.r_sec, &p);
    assert_eq!(
        ap.estado.sectores[&id].etapa,
        Etapa::Retirado,
        "a R_sec libera como antes"
    );

    let mut est2 = EstadoSector {
        slot_actual: s,
        ..EstadoSector::default()
    };
    let importe = 50i64;
    let mut c = CuentaGarantia::nueva(clave);
    c.en_retirada.push(Retiro {
        importe,
        inicio_slot: s,
    });
    est2.garantias.insert(clave, c);
    let mut ap2 = AplicadorSector::nuevo(&mut est2);
    let op = op_liberacion(clave, importe);
    assert_eq!(
        ap2.op_liberacion(&op, s + p.r_slots - 1, &p),
        MotivoSector::ErrFianza
    );
    assert_eq!(ap2.op_liberacion(&op, s + p.r_slots, &p), MotivoSector::Ok);
}
