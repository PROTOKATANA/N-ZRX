//! V2 — casos negativos, con un test por caso (ORDEN-BLS1 §3).
//!
//! Se prueban a nivel de la **API de ZEROX** (con `dominio`) los rechazos que exige la decisión 3,
//! más el ataque de la clave rebelde que ya demuestra `crudo::pruebas`. Los vectores oficiales
//! (`tests/vectores.rs`) cubren además la deserialización genérica; aquí cada caso tiene su test.
#![allow(
    clippy::indexing_slicing,
    reason = "los bytes de infinito y malformados se construyen por concatenacion explicita; no hay indices"
)]

use zx_bls::{
    ClavePublica, ClaveSecreta, ErrorBLS, Firma, LONGITUD_CLAVE_PUBLICA, LONGITUD_FIRMA, firmar,
    verificar, verificar_posesion,
};

/// Bytes del punto del infinito en G1: `0xc0` y 47 ceros.
fn infinito_g1() -> Vec<u8> {
    let mut bytes = vec![0u8; LONGITUD_CLAVE_PUBLICA];
    if let Some(primero) = bytes.first_mut() {
        *primero = 0xc0;
    }
    bytes
}

/// Bytes del punto del infinito en G2: `0xc0` y 95 ceros.
fn infinito_g2() -> Vec<u8> {
    let mut bytes = vec![0u8; LONGITUD_FIRMA];
    if let Some(primero) = bytes.first_mut() {
        *primero = 0xc0;
    }
    bytes
}

/// Busca en un fichero de vectores `bool\thex` el primer caso cuyo rechazo menciona `aguja`.
fn primer_motivo(vectores: &str, aguja: &str, g1: bool) -> Option<String> {
    for linea in vectores.lines() {
        let campos: Vec<&str> = linea.split('\t').collect();
        if campos.len() != 2 {
            continue;
        }
        let bytes = match campos[1].strip_prefix("0x") {
            Some(sin) => hex::decode(sin),
            None => hex::decode(campos[1]),
        };
        let Ok(bytes) = bytes else { continue };
        let motivo = if g1 {
            ClavePublica::desde_bytes(&bytes)
                .err()
                .map(|e| e.to_string())
        } else {
            Firma::desde_bytes(&bytes).err().map(|e| e.to_string())
        };
        if let Some(motivo) = motivo
            && motivo.contains(aguja)
        {
            return Some(motivo);
        }
    }
    None
}

#[test]
fn clave_fuera_de_subgrupo_se_rechaza() {
    let vectores = include_str!("vectores/deserialization_g1.txt");
    assert!(
        primer_motivo(vectores, "subgrupo", true).is_some(),
        "ningun vector de G1 fuera del subgrupo se rechazo por subgrupo"
    );
    // Un punto de G1 valido (el generador) si se acepta: el test no es vacuamente cierto.
    let generador = "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    assert!(ClavePublica::desde_bytes(&hex::decode(&generador[2..]).unwrap_or_default()).is_ok());
}

#[test]
fn firma_fuera_de_subgrupo_se_rechaza() {
    let vectores = include_str!("vectores/deserialization_g2.txt");
    assert!(
        primer_motivo(vectores, "subgrupo", false).is_some(),
        "ningun vector de G2 fuera del subgrupo se rechazo por subgrupo"
    );
}

#[test]
fn punto_del_infinito_se_rechaza() {
    assert!(ClavePublica::desde_bytes(&infinito_g1()).is_err());
    assert!(Firma::desde_bytes(&infinito_g2()).is_err());
}

#[test]
fn firma_malformada_se_rechaza() {
    let corta = vec![0u8; LONGITUD_FIRMA - 1];
    let larga = vec![0u8; LONGITUD_FIRMA + 1];
    let no_punto = vec![0u8; LONGITUD_FIRMA];
    assert!(Firma::desde_bytes(&corta).is_err());
    assert!(Firma::desde_bytes(&larga).is_err());
    assert!(Firma::desde_bytes(&no_punto).is_err());
    assert!(ClavePublica::desde_bytes(&[0u8; LONGITUD_CLAVE_PUBLICA]).is_err());
}

#[test]
fn firma_de_otro_dominio_no_verifica() -> Result<(), ErrorBLS> {
    let clave = ClaveSecreta::generar(&[0x51; 32])?;
    let publica = clave.clave_publica();
    let firma = firmar(&clave, b"dominio-A", b"voto")?;

    // Con el dominio correcto verifica...
    verificar(&publica, &firma, b"dominio-A", b"voto")?;
    // ...y con otro dominio se rechaza.
    assert_eq!(
        verificar(&publica, &firma, b"dominio-B", b"voto"),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}

#[test]
fn mensaje_alterado_no_verifica() -> Result<(), ErrorBLS> {
    let clave = ClaveSecreta::generar(&[0x52; 32])?;
    let publica = clave.clave_publica();
    let firma = firmar(&clave, b"ZX-FINALIDAD-VOTO", b"voto")?;

    assert_eq!(
        verificar(&publica, &firma, b"ZX-FINALIDAD-VOTO", b"voto alterado"),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}

#[test]
fn dominio_vacio_se_rechaza() -> Result<(), ErrorBLS> {
    let clave = ClaveSecreta::generar(&[0x53; 32])?;
    assert_eq!(firmar(&clave, b"", b"voto"), Err(ErrorBLS::DominioVacio));
    Ok(())
}

#[test]
fn la_prueba_de_posesion_de_una_clave_no_sirve_para_otra() -> Result<(), ErrorBLS> {
    let propietaria = ClaveSecreta::generar(&[0x54; 32])?;
    let impostora = ClaveSecreta::generar(&[0x55; 32])?;
    let prueba = zx_bls::probar_posesion(&propietaria);

    verificar_posesion(&propietaria.clave_publica(), &prueba)?;
    assert_eq!(
        verificar_posesion(&impostora.clave_publica(), &prueba),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}
