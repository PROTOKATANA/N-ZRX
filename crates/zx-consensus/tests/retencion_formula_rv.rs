//! RET-1a · P7: consistencia de la fórmula de `r_votos_slots` en el perfil dev.
//!
//! Referencia los símbolos nuevos (`r_votos_slots`, `CADUCIDAD_TABLA_VENTANAS`), así que **no**
//! compila contra `ws.orig`; el resto de pruebas (P1–P6) sí. Ejecutar:
//! `cargo test -p zx-consensus --test retencion_formula_rv -- --nocapture`

#![allow(
    clippy::expect_used,
    reason = "prueba de consistencia; falla con panic por diseño"
)]

use zx_consensus::sectores::ParametrosSector;
use zx_consensus::transicion::votos::{CADUCIDAD_TABLA_VENTANAS, T_INST_VOTOS};

#[test]
fn p7_formula_de_r_votos_en_dev() {
    let p = ParametrosSector::dev();
    let plazo = u64::try_from(p.plazo_slots).expect("plazo_slots ≥ 0");
    let margen = u64::try_from(p.m_margen_slots).expect("m_margen_slots ≥ 0");
    // `(L + G)·T_inst + plazo_slots + m_margen_slots`, con `L = 2`.
    let esperado = (2 + CADUCIDAD_TABLA_VENTANAS) * T_INST_VOTOS + plazo + margen;
    println!(
        "P7 (2 + {CADUCIDAD_TABLA_VENTANAS})·{T_INST_VOTOS} + {plazo} + {margen} = {esperado}; \
         r_votos_slots = {}",
        p.r_votos_slots
    );
    assert_eq!(
        u64::try_from(p.r_votos_slots).expect("r_votos_slots ≥ 0"),
        esperado
    );
    assert_eq!(p.r_votos_slots, 1_024);
    // El perfil del modelo (fixture, `r_sec = 30`) no altera su diferencial.
    assert_eq!(ParametrosSector::fixture().r_votos_slots, 0);
}
