//! Pruebas de la historia génesis dev (D-P12) y de su compromiso congelado (V7).
//!
//! Construye la historia **dos veces** por caminos distintos —[`HistoriaGenesis::construir`], que
//! coteja el compromiso congelado, y [`HistoriaGenesis::construir_bruto`], que no— y exige que las
//! dos coincidan con [`COMPROMISO_HISTORIA_GENESIS_DEV`]. Es la comprobación de determinismo V7 de
//! la orden y, a la vez, el test que recongela el compromiso si alguien toca la receta.

#![expect(
    clippy::expect_used,
    reason = "instrumento de test: un fallo al construir la historia debe producir panic"
)]

use zx_poas::{
    COMPROMISO_HISTORIA_GENESIS_DEV, HistoriaGenesis, TAMANO_HISTORIA_DEV, a_segment_commitment,
    comprobar_compromiso,
};

/// V7: la receta D-P12 es determinista y su compromiso es el congelado.
///
/// La primera construcción pasa por `construir` (con cotejo) y la segunda por `construir_bruto`
/// (sin cotejo). Comparar las dos demuestra que el valor congelado no se deriva del observado: si
/// divergieran, este test falla antes de tocar la constante.
#[test]
fn el_compromiso_de_la_historia_genesis_es_determinista_y_congelado() {
    let primera = HistoriaGenesis::construir()
        .expect("la historia génesis dev debe construirse y cotejar el compromiso congelado");
    let segunda = HistoriaGenesis::construir_bruto()
        .expect("la historia génesis dev debe construirse sin cotejo");

    assert_eq!(
        primera.segment_commitment(),
        segunda.segment_commitment(),
        "D-P12: la receta de la historia génesis dev debe ser determinista"
    );
    assert_eq!(
        primera.segment_commitment(),
        COMPROMISO_HISTORIA_GENESIS_DEV,
        "el compromiso observado debe ser el congelado; si la receta cambia a propósito, \
         actualiza COMPROMISO_HISTORIA_GENESIS_DEV"
    );

    // El protocolo es el dev y el contexto de pieza es coherente con el segmento.
    assert_eq!(primera.history_size().get(), TAMANO_HISTORIA_DEV);
    assert_eq!(primera.history_size().get(), 1);
    let params = primera.params_pieza();
    assert_eq!(
        params.segment_commitment,
        a_segment_commitment(primera.segment_commitment())
    );
    assert_eq!(params.current_history_size, primera.history_size());
    assert_eq!(
        params.max_pieces_in_sector,
        primera.protocolo().max_pieces_in_sector
    );
}

/// Un byte cambiado del compromiso congelado devuelve el error tipado, sin `panic` y sin aceptar el
/// valor nuevo.
#[test]
fn un_compromiso_mutado_devuelve_el_error_tipado() {
    let mut mutado = COMPROMISO_HISTORIA_GENESIS_DEV;
    if let Some(byte) = mutado.first_mut() {
        *byte ^= 0x01;
    }
    let error =
        comprobar_compromiso(mutado).expect_err("un compromiso mutado no puede pasar el cotejo");
    let texto = format!("{error}");
    assert!(
        texto.contains("compromiso de segmento inesperado"),
        "el error debe nombrar la divergencia: {texto}"
    );
}
