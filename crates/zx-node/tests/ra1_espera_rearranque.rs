//! RA-1 · la espera del rearranque atada al perfil del nodo (Z11) y la sensibilidad de
//! `estado_resumen` al campo nuevo del ciclo (Z10, parte `zx-node`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "prueba de magnitudes fijas; falla con panic por diseño"
)]

use zx_consensus::transicion::Estado;
use zx_consensus::transicion::votos::ESPERA_REARRANQUE_SLOTS;
use zx_node::estado_resumen::resumen_estado;
use zx_node::perfil::F_SLOTS;

/// Z11 · Y0 · la constante de consenso es la profundidad de finalidad del perfil del nodo.
#[test]
fn z11_espera_rearranque_igual_a_f_slots() {
    assert_eq!(
        ESPERA_REARRANQUE_SLOTS, F_SLOTS,
        "ESPERA_REARRANQUE_SLOTS debe ser igual a perfil::F_SLOTS"
    );
}

/// Z10 · `estado_resumen` cambia con el campo nuevo `tabla_ciclo_rearranque`.
#[test]
fn z10_resumen_sensible_al_ciclo_de_rearranque() {
    let base = Estado::inicial();
    let mut con_ciclo = base.clone();
    con_ciclo.tabla_ciclo_rearranque.insert(0, [7u8; 32]);
    assert_ne!(
        resumen_estado(&base),
        resumen_estado(&con_ciclo),
        "tabla_ciclo_rearranque debe verse en el resumen"
    );
}
