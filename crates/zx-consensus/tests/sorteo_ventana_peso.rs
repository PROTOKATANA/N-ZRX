//! M9-b1 · gemelas por el flujo por peso de `sorteo_ventana.rs` (lista P).
//!
//! `los_momentos_de_la_ventana_son_los_declarados` no usa ninguna operación ni campo del sorteo:
//! se copia al archivo nuevo porque el suyo desaparecerá con la retirada.

/// `apertura`/`cierre` de la ventana son coherentes con `T_inst`.
#[test]
fn los_momentos_de_la_ventana_son_los_declarados_peso() {
    const W_REVEAL_SLOTS_VOTOS: u64 = zx_consensus::transicion::votos::W_REVEAL_SLOTS_VOTOS;
    const G_SLOTS_VOTOS: u64 = zx_consensus::transicion::votos::G_SLOTS_VOTOS;
    assert_eq!(zx_consensus::transicion::votos::apertura_ventana(3), 6);
    assert_eq!(zx_consensus::transicion::votos::cierre_ventana(3), 8);
    const { assert!(W_REVEAL_SLOTS_VOTOS >= G_SLOTS_VOTOS) };
}
