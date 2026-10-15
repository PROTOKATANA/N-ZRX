//! CP-T-04, CP-T-05 y CP-T-06: topes, bombas y transporte en el marco ZRX-C.
//!
//! Escrito **antes** del código del crate (CP-C1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use zx_compresion::{ErrorCompresion, esta_comprimido};
use zx_pruebas::ErrorPrueba;
use zx_pruebas::limites::{MAX_PRUEBA_CANONICA_BYTES, MAX_PRUEBA_COMPRIMIDA_BYTES, NIVEL_PRUEBA};
use zx_pruebas::marco::{comprimir, descomprimir};
use zx_pruebas::objeto::{ClasePrueba, PruebaRecursiva};

/// Cuerpo pseudoaleatorio de 4 bits por byte: entropía ~4 bits ⇒ zstd comprime ~2:1,
/// suficiente para que el marco sea más pequeño que la forma canónica sin disparar el ratio
/// anti-bomba de 8:1 (que sí saltaría con datos periódicos).
fn cuerpo(n: usize, semilla: u8) -> Vec<u8> {
    let mut estado = 0x9e37_79b9u32 ^ u32::from(semilla);
    (0..n)
        .map(|_| {
            estado ^= estado << 13;
            estado ^= estado >> 17;
            estado ^= estado << 5;
            (estado & 0x0f) as u8
        })
        .collect()
}

#[test]
fn cp_t_04_el_tope_comprimido_se_rechaza_antes_de_descomprimir() {
    let datos = cuerpo(1024, 5);
    let mut marco = zx_compresion::comprimir(&datos, 1, None).expect("comprime");
    // `len_comprimido` vive en los bytes 19..27 (big-endian).
    marco[19..27].copy_from_slice(&(MAX_PRUEBA_COMPRIMIDA_BYTES + 1).to_be_bytes());
    assert!(matches!(
        descomprimir(&marco),
        Err(ErrorPrueba::ComprimidaDemasiadoLarga(_))
    ));
}

#[test]
fn cp_t_04_un_transporte_crudo_mayor_que_el_tope_se_rechaza() {
    let mut crudo = vec![zx_pruebas::objeto::VERSION_OBJETO, 0x01];
    crudo.resize((MAX_PRUEBA_COMPRIMIDA_BYTES + 1) as usize, 0);
    assert!(matches!(
        descomprimir(&crudo),
        Err(ErrorPrueba::ComprimidaDemasiadoLarga(_))
    ));
}

#[test]
fn cp_t_05_una_bomba_no_reserva_la_memoria_declarada() {
    // 8 TiB declarados con un payload mínimo. Si el receptor reservara la
    // memoria declarada, el proceso abortaría por OOM; que esto devuelva un
    // error prueba que la comprobación de tope precede a toda reserva.
    let datos = cuerpo(64, 9);
    let mut marco = zx_compresion::comprimir(&datos, 1, None).expect("comprime");
    marco[11..19].copy_from_slice(&(8u64 * 1024 * 1024 * 1024 * 1024).to_be_bytes());
    assert!(matches!(
        descomprimir(&marco),
        Err(ErrorPrueba::Compresion(
            ErrorCompresion::DemasiadoGrande { .. }
        ))
    ));
}

#[test]
fn cp_t_05_una_prueba_mayor_que_el_tope_se_rechaza() {
    let grande = vec![0u8; (MAX_PRUEBA_CANONICA_BYTES + 1) as usize];
    let marco = zx_compresion::comprimir(&grande, 1, None).expect("comprime");
    assert!(matches!(
        descomprimir(&marco),
        Err(ErrorPrueba::Compresion(
            ErrorCompresion::DemasiadoGrande { .. }
        ))
    ));
}

#[test]
fn cp_t_05_una_bomba_por_ratio_se_rechaza() {
    let grande = vec![0u8; MAX_PRUEBA_CANONICA_BYTES as usize];
    let marco = zx_compresion::comprimir(&grande, 1, None).expect("comprime");
    assert!(matches!(
        descomprimir(&marco),
        Err(ErrorPrueba::Compresion(
            ErrorCompresion::RatioExcesivo { .. }
        ))
    ));
}

#[test]
fn cp_t_06_ida_y_vuelta_y_fallback_sin_comprimir() {
    let p = PruebaRecursiva::nueva(ClasePrueba::PoRep, &cuerpo(4096, 1)).expect("nueva");
    let marco = comprimir(&p, NIVEL_PRUEBA).expect("comprime");
    assert!(
        esta_comprimido(&marco),
        "un objeto compresible debe ir en marco"
    );
    assert_eq!(descomprimir(&marco).expect("descomprime"), p);

    let pequeno = PruebaRecursiva::nueva(ClasePrueba::TurnoS4, &cuerpo(8, 2)).expect("nueva");
    let crudo = comprimir(&pequeno, NIVEL_PRUEBA).expect("comprime pequeño");
    assert!(
        !esta_comprimido(&crudo),
        "el fallback R-5 debe evitar el marco"
    );
    assert_eq!(descomprimir(&crudo).expect("descomprime crudo"), pequeno);
}

#[test]
fn la_huella_no_depende_del_nivel_de_compresion() {
    let p = PruebaRecursiva::nueva(ClasePrueba::PoSt, &cuerpo(4096, 4)).expect("nueva");
    let m1 = comprimir(&p, 1).expect("nivel 1");
    let m19 = comprimir(&p, NIVEL_PRUEBA).expect("nivel 19");
    let p1 = descomprimir(&m1).expect("descomprime 1");
    let p19 = descomprimir(&m19).expect("descomprime 19");
    assert_eq!(p1.huella(), p19.huella());
    assert_eq!(p1.huella(), p.huella());
    assert_eq!(p1, p);
    assert_eq!(p19, p);
}
