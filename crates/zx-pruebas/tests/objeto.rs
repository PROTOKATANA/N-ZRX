//! CP-T-01 y CP-T-02 (objeto y huella): formato versionado, conjunto de clases
//! cerrado, huella sobre el cuerpo canónico y su independencia de la compresión.
//!
//! Escrito **antes** del código del crate (CP-C1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sha3::{Digest as _, Sha3_256};
use zx_pruebas::ErrorPrueba;
use zx_pruebas::huella::{TAG_HUELLA, h_d, huella};
use zx_pruebas::limites::MAX_PRUEBA_CANONICA_BYTES;
use zx_pruebas::objeto::{ClasePrueba, PruebaRecursiva, VERSION_OBJETO};

fn cuerpo(n: usize, semilla: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(semilla))
        .collect()
}

#[test]
fn cp_t_01_rechaza_version_y_clase_desconocidas() {
    let mut version_mala = vec![VERSION_OBJETO.wrapping_add(1), 0x01];
    version_mala.extend_from_slice(&cuerpo(16, 0));
    assert!(matches!(
        PruebaRecursiva::desde_canonico(&version_mala),
        Err(ErrorPrueba::VersionDesconocida { .. })
    ));

    for mala in [0x00u8, 0x03, 0x04, 0x05, 0x07, 0xff] {
        let mut b = vec![VERSION_OBJETO, mala];
        b.extend_from_slice(&cuerpo(16, 0));
        assert!(matches!(
            PruebaRecursiva::desde_canonico(&b),
            Err(ErrorPrueba::ClaseDesconocida(_))
        ));
    }

    assert!(matches!(
        PruebaRecursiva::desde_canonico(&[]),
        Err(ErrorPrueba::BytesInsuficientes)
    ));
    assert!(matches!(
        PruebaRecursiva::desde_canonico(&[VERSION_OBJETO]),
        Err(ErrorPrueba::BytesInsuficientes)
    ));
}

#[test]
fn cp_t_01_acepta_las_tres_clases_y_conserva_el_cuerpo() {
    for (byte, clase) in [
        (0x01u8, ClasePrueba::PoRep),
        (0x02, ClasePrueba::PoSt),
        (0x06, ClasePrueba::TurnoS4),
    ] {
        let c = cuerpo(64, byte);
        let p = PruebaRecursiva::nueva(clase, &c).expect("nueva");
        assert_eq!(p.clase(), clase);
        assert_eq!(p.cuerpo_canonico(), c.as_slice());
        let bytes = p.a_bytes();
        assert_eq!(bytes[0], VERSION_OBJETO);
        assert_eq!(bytes[1], byte);
        assert_eq!(&bytes[2..], c.as_slice());
        let vuelta = PruebaRecursiva::desde_canonico(&bytes).expect("desde_canonico");
        assert_eq!(vuelta, p);
    }
}

#[test]
fn cp_t_01_el_conjunto_de_clases_es_cerrado() {
    assert_eq!(ClasePrueba::PoRep.byte(), 0x01);
    assert_eq!(ClasePrueba::PoSt.byte(), 0x02);
    assert_eq!(ClasePrueba::TurnoS4.byte(), 0x06);
    assert_eq!(ClasePrueba::desde_byte(0x01), Some(ClasePrueba::PoRep));
    assert_eq!(ClasePrueba::desde_byte(0x06), Some(ClasePrueba::TurnoS4));
    assert_eq!(ClasePrueba::desde_byte(0x03), None);
    assert_eq!(ClasePrueba::desde_byte(0x05), None);
}

#[test]
fn cp_t_02_la_huella_va_sobre_el_cuerpo_y_cambia_con_un_byte() {
    let c = cuerpo(256, 7);
    let p = PruebaRecursiva::nueva(ClasePrueba::PoRep, &c).expect("nueva");
    assert_eq!(p.huella(), huella(&c));

    let mut c2 = c.clone();
    c2[10] ^= 0x01;
    assert_ne!(huella(&c), huella(&c2));
}

#[test]
fn cp_t_02_el_dominio_separa_y_ancla_sha3_256() {
    let c = cuerpo(64, 3);
    let desnudo: [u8; 32] = Sha3_256::digest(&c).into();
    assert_ne!(huella(&c), desnudo, "la huella no es el SHA3-256 desnudo");

    let esperado: [u8; 32] = Sha3_256::digest(TAG_HUELLA).into();
    assert_eq!(h_d(TAG_HUELLA, b""), esperado);

    let vacio: [u8; 32] = Sha3_256::digest(b"").into();
    assert_eq!(
        hex::encode(vacio),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[test]
fn cp_t_02_el_tope_canonico_se_aplica_al_objeto_serializado() {
    let justo = vec![0u8; (MAX_PRUEBA_CANONICA_BYTES - 2) as usize];
    assert!(PruebaRecursiva::nueva(ClasePrueba::PoRep, &justo).is_ok());

    let pasado = vec![0u8; (MAX_PRUEBA_CANONICA_BYTES - 1) as usize];
    assert!(matches!(
        PruebaRecursiva::nueva(ClasePrueba::PoRep, &pasado),
        Err(ErrorPrueba::CanonicaDemasiadoLarga(_))
    ));
}
