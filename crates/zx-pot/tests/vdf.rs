//! Pruebas de la segmentación del segundo VDF (`C-RLJ-VDF-02`) de `zx-pot`.
//!
//! Van en `tests/` (crate de test con `std`) porque `zx-pot` es `#![no_std]`: los tests unitarios
//! internos no tienen `Vec` ni `vec!`.

#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]

use zx_pot::vdf::{ErrorVdf, MAX_SEG, segmentos};

fn longitudes(total: u64, max_seg: u64) -> Vec<u64> {
    segmentos(total, max_seg)
        .expect("segmentación válida")
        .collect()
}

#[test]
fn reparto_greedy_con_resto() {
    assert_eq!(longitudes(160, 64), vec![64, 64, 32]);
    assert_eq!(longitudes(48, 64), vec![48]);
    assert_eq!(longitudes(128, 64), vec![64, 64]);
}

#[test]
fn total_cero_no_produce_segmentos() {
    assert!(longitudes(0, 64).is_empty());
}

#[test]
fn tope_de_u32_redondeado_a_multiplo_de_16() {
    assert_eq!(MAX_SEG, 4_294_967_280);
    assert!(MAX_SEG.is_multiple_of(16));
    assert_eq!(
        longitudes(2 * MAX_SEG + 32, MAX_SEG),
        vec![MAX_SEG, MAX_SEG, 32]
    );
    assert_eq!(longitudes(MAX_SEG, MAX_SEG), vec![MAX_SEG]);
}

#[test]
fn entradas_fuera_de_dominio_se_rechazan() {
    assert_eq!(
        segmentos(15, 64),
        Err(ErrorVdf::TotalNoMultiploDe16 { total: 15 })
    );
    assert_eq!(
        segmentos(64, 15),
        Err(ErrorVdf::MaxSegNoMultiploDe16 { max_seg: 15 })
    );
    assert_eq!(segmentos(64, 0), Err(ErrorVdf::MaxSegCero));
}

#[test]
fn la_suma_de_segmentos_es_el_total() {
    let suma: u64 = segmentos(8_589_934_592, MAX_SEG).expect("válido").sum();
    assert_eq!(suma, 8_589_934_592);
}
