//! Pruebas de ZRX-C: ida y vuelta, diccionarios, corrupción y bombas.
//!
//! Es la cobertura de integración de la crate; los casos de unidad del marco
//! (xxHash64, cabecera, versiones) viven en `src/marco.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use zx_compresion::{
    CABECERA, Diccionario, ErrorCompresion, Limites, comprimir, descomprimir, esta_comprimido,
    leer_cabecera,
};

fn datos_repetitivos(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 17) as u8).collect()
}

#[test]
fn ida_y_vuelta_conserva_los_bytes() {
    let datos = datos_repetitivos(8_192);
    let marco = comprimir(&datos, 3, None).expect("comprime");
    assert!(esta_comprimido(&marco));
    let cabecera = leer_cabecera(&marco).expect("cabecera");
    assert_eq!(cabecera.version, zx_compresion::VERSION);
    assert_eq!(cabecera.algoritmo, zx_compresion::ALGORITMO_ZSTD);
    assert_eq!(cabecera.len_original, datos.len() as u64);
    assert_eq!(
        cabecera.len_comprimido as usize,
        marco.len() - CABECERA,
        "el tamaño del payload cuadra con la cabecera"
    );
    let salida = descomprimir(&marco, None, &Limites::VALOR_ALMACEN).expect("descomprime");
    assert_eq!(salida, datos);
}

#[test]
fn funciona_con_diccionario_y_rechaza_el_que_no_es() {
    let muestras: Vec<Vec<u8>> = (0..40u8)
        .map(|s| {
            (0..512)
                .map(|i| (i as u8).wrapping_add(s).wrapping_mul(3))
                .collect()
        })
        .collect();
    let dict = Diccionario::entrenar(7, &muestras, 1_024).expect("entrena");
    let datos = datos_repetitivos(2_048);
    let marco = comprimir(&datos, 3, Some(&dict)).expect("comprime con diccionario");
    assert_eq!(leer_cabecera(&marco).expect("cabecera").dict_id, 7);
    let salida = descomprimir(&marco, Some(&dict), &Limites::VALOR_ALMACEN).expect("descomprime");
    assert_eq!(salida, datos);
    assert!(matches!(
        descomprimir(&marco, None, &Limites::VALOR_ALMACEN),
        Err(ErrorCompresion::DiccionarioDesconocido { esperado: 7, .. })
    ));
}

#[test]
fn un_payload_corrupto_se_rechaza() {
    let datos = datos_repetitivos(4_096);
    let mut marco = comprimir(&datos, 3, None).expect("comprime");
    let ultimo = marco.last_mut().expect("no vacío");
    *ultimo ^= 0x01;
    assert!(descomprimir(&marco, None, &Limites::VALOR_ALMACEN).is_err());
}

#[test]
fn una_bomba_por_encima_del_tope_se_rechaza() {
    let bomb = vec![0u8; 1024 * 1024];
    let marco = comprimir(&bomb, 1, None).expect("comprime");
    assert!(
        marco.len() < 64 * 1024,
        "el ejemplo debe comprimir muchísimo"
    );
    let limites = Limites::nuevo(64 * 1024);
    assert!(matches!(
        descomprimir(&marco, None, &limites),
        Err(ErrorCompresion::DemasiadoGrande { .. })
    ));
}

#[test]
fn una_bomba_por_ratio_se_rechaza() {
    let bomb = vec![0u8; 2 * 1024 * 1024];
    let marco = comprimir(&bomb, 1, None).expect("comprime");
    // El tope de bytes es holgado; el ratio (declarado) es el que salta.
    let limites = Limites::nuevo(4 * 1024 * 1024).con_ratio(2);
    assert!(matches!(
        descomprimir(&marco, None, &limites),
        Err(ErrorCompresion::RatioExcesivo { .. })
    ));
}

#[test]
fn una_longitud_mentida_se_rechaza() {
    let datos = datos_repetitivos(32);
    let mut marco = comprimir(&datos, 3, None).expect("comprime");
    // `len_original` vive en los bytes 11..19.
    marco[11..19].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        descomprimir(&marco, None, &Limites::VALOR_ALMACEN),
        Err(ErrorCompresion::DemasiadoGrande { .. })
    ));
}

#[test]
fn marcos_invalidos_se_rechazan() {
    assert!(matches!(
        descomprimir(b"ZX", None, &Limites::VALOR_ALMACEN),
        Err(ErrorCompresion::MarcoCorto { .. })
    ));
    let mut malo = comprimir(&datos_repetitivos(16), 3, None).expect("comprime");
    malo[0] = b'Y';
    assert!(matches!(
        descomprimir(&malo, None, &Limites::VALOR_ALMACEN),
        Err(ErrorCompresion::MagiaInvalida)
    ));
    let mut raro = comprimir(&datos_repetitivos(16), 3, None).expect("comprime");
    raro[4] = 99;
    assert!(matches!(
        descomprimir(&raro, None, &Limites::VALOR_ALMACEN),
        Err(ErrorCompresion::VersionDesconocida { encontrada: 99 })
    ));
    assert!(matches!(
        comprimir(&datos_repetitivos(16), 0, None),
        Err(ErrorCompresion::NivelInvalido { nivel: 0 })
    ));
}

#[test]
fn un_original_vacio_va_y_vuelve() {
    let marco = comprimir(&[], 3, None).expect("comprime vacío");
    let salida = descomprimir(&marco, None, &Limites::VALOR_ALMACEN).expect("descomprime");
    assert!(salida.is_empty());
}
