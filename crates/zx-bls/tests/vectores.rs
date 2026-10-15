//! V1 — vectores oficiales.
//!
//! Los ficheros de `vectores/` son la proyección a texto de los vectores de
//! `ethereum/bls12-381-tests` v0.1.0 (que a su vez usa los de RFC 9380 para `hash_to_G2`); su
//! procedencia, commit y fecha están en `PROCEDENCIA.md`. El parseo indexa campos de una línea de
//! longitud fija salida de `jq`, de ahí el `allow` acotado a este fichero de test.
#![allow(
    clippy::indexing_slicing,
    reason = "los ficheros de vectores son TSV de columnas fijas generados por jq; el indice esta acotado por el split"
)]

use zx_bls::crudo;
use zx_bls::{ClavePublica, ClaveSecreta, Firma, FirmaAgregada};

/// DST de los vectores de hash a curva de RFC 9380 (suite `BLS12381G2_XMD:SHA-256_SSWU_RO_`).
const DST_HASH_TO_G2: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// Quita el prefijo `0x` si está presente.
fn sin_prefijo(texto: &str) -> &str {
    texto.strip_prefix("0x").unwrap_or(texto)
}

/// Decodifica hex con o sin `0x`.
fn hex_bytes(texto: &str) -> Result<Vec<u8>, String> {
    hex::decode(sin_prefijo(texto)).map_err(|e| e.to_string())
}

/// `true` si los 48 bytes son la codificación del infinito en G1 (`0xc0` y ceros).
fn es_infinito_g1(bytes: &[u8]) -> bool {
    match bytes.split_first() {
        Some((primero, resto)) => {
            bytes.len() == zx_bls::LONGITUD_CLAVE_PUBLICA
                && *primero == 0xc0
                && resto.iter().all(|b| *b == 0)
        }
        None => false,
    }
}

/// `true` si los 96 bytes son la codificación del infinito en G2 (`0xc0` y ceros).
fn es_infinito_g2(bytes: &[u8]) -> bool {
    match bytes.split_first() {
        Some((primero, resto)) => {
            bytes.len() == zx_bls::LONGITUD_FIRMA
                && *primero == 0xc0
                && resto.iter().all(|b| *b == 0)
        }
        None => false,
    }
}

/// Ejecuta un comprobador sobre cada línea y falla con el listado completo.
fn comprobar(nombre: &str, contenido: &str, caso: fn(&str) -> Result<(), String>) {
    let mut fallos: Vec<String> = Vec::new();
    let mut total = 0usize;
    for linea in contenido.lines() {
        if linea.trim().is_empty() {
            continue;
        }
        total += 1;
        if let Err(e) = caso(linea) {
            fallos.push(format!("  - {e}"));
        }
    }
    assert!(
        fallos.is_empty(),
        "{nombre}: {} de {total} vectores fallaron:\n{}",
        fallos.len(),
        fallos.join("\n")
    );
    println!("{nombre}: {total} vectores OK");
}

/// Devuelve `(campo_real, campo_imaginario)` de un `x_r,x_i` de jq.
fn par_fq2(texto: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (real, imaginario) = texto
        .split_once(',')
        .ok_or_else(|| format!("se esperaba x_r,x_i y hay {texto}"))?;
    Ok((hex_bytes(real)?, hex_bytes(imaginario)?))
}

#[test]
fn vectores_hash_a_curva_rfc_9380() {
    comprobar(
        "hash_to_G2 (RFC 9380)",
        include_str!("vectores/hash_to_g2.txt"),
        un_hash_to_g2,
    );
}

fn un_hash_to_g2(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 3 {
        return Err(format!("se esperaban 3 campos y hay {}", campos.len()));
    }
    let mensaje = campos[0].as_bytes();
    // jq emite `x_r,x_i` / `y_r,y_i`; blst deserializa `x_i || x_r || y_i || y_r`.
    let (x_real, x_imag) = par_fq2(campos[1])?;
    let (y_real, y_imag) = par_fq2(campos[2])?;

    let mut punto = Vec::with_capacity(192);
    punto.extend_from_slice(&x_imag);
    punto.extend_from_slice(&x_real);
    punto.extend_from_slice(&y_imag);
    punto.extend_from_slice(&y_real);

    let esperado = crudo::firma_desde_uncomprimida(&punto).map_err(|e| e.to_string())?;
    let obtenido = crudo::hash_a_g2(mensaje, DST_HASH_TO_G2).map_err(|e| e.to_string())?;
    if obtenido.as_slice() != esperado.bytes().as_slice() {
        return Err(format!("el hash a curva de {:?} no coincide", campos[0]));
    }
    Ok(())
}

#[test]
fn vectores_de_firma_pop() {
    comprobar("sign (POP)", include_str!("vectores/sign.txt"), un_sign);
    comprobar(
        "verify (POP)",
        include_str!("vectores/verify.txt"),
        un_verify,
    );
}

fn un_sign(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 3 {
        return Err(format!("se esperaban 3 campos y hay {}", campos.len()));
    }
    let clave = ClaveSecreta::desde_bytes(&hex_bytes(campos[0])?);
    let mensaje = hex_bytes(campos[1])?;
    let salida = campos[2];

    match (clave, salida) {
        (Ok(_), "null") => Err("se esperaba rechazo de la clave secreta".to_string()),
        (Err(_), "null") => Ok(()),
        (Err(e), _) => Err(format!("clave valida rechazada: {e}")),
        (Ok(clave), esperado) => {
            let firma = crudo::firmar(&clave, &mensaje);
            let esperado = hex_bytes(esperado)?;
            if firma.bytes().as_slice() != esperado.as_slice() {
                return Err("la firma no coincide con el vector".to_string());
            }
            Ok(())
        }
    }
}

fn un_verify(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 4 {
        return Err(format!("se esperaban 4 campos y hay {}", campos.len()));
    }
    let esperado = campos[0] == "true";
    let clave = ClavePublica::desde_bytes(&hex_bytes(campos[1])?);
    let mensaje = hex_bytes(campos[2])?;
    let firma = Firma::desde_bytes(&hex_bytes(campos[3])?);

    match (clave, firma) {
        (Ok(clave), Ok(firma)) => {
            let obtenido = crudo::verificar(&clave, &firma, &mensaje).is_ok();
            if obtenido != esperado {
                return Err(format!("se esperaba {esperado} y se obtuvo {obtenido}"));
            }
            Ok(())
        }
        _ => {
            if esperado {
                Err("clave o firma invalidas en un vector valido".to_string())
            } else {
                Ok(())
            }
        }
    }
}

#[test]
fn vectores_de_agregacion() {
    comprobar(
        "aggregate",
        include_str!("vectores/aggregate.txt"),
        un_aggregate,
    );
}

fn un_aggregate(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 2 {
        return Err(format!("se esperaban 2 campos y hay {}", campos.len()));
    }
    let salida = campos[0];
    let entradas: Vec<&str> = campos[1].split(';').filter(|s| !s.is_empty()).collect();

    let mut firmas: Vec<Firma> = Vec::new();
    let mut invalida = false;
    for entrada in &entradas {
        match Firma::desde_bytes(&hex_bytes(entrada)?) {
            Ok(firma) => firmas.push(firma),
            Err(_) => invalida = true,
        }
    }

    if salida == "null" {
        if entradas.is_empty() {
            let vacio: Vec<&Firma> = Vec::new();
            if crudo::agregar_firmas(&vacio).is_ok() {
                return Err("la agregacion de la lista vacia no se rechazo".to_string());
            }
            return Ok(());
        }
        if invalida {
            return Ok(());
        }
        return Err("se esperaba rechazo".to_string());
    }

    if invalida {
        // Divergencia deliberada (decisión 3): el único caso es el agregado del infinito, que
        // ZEROX rechaza al deserializar.
        if entradas.len() == 1 && es_infinito_g2(&hex_bytes(entradas[0])?) {
            return Ok(());
        }
        return Err("entrada valida rechazada al deserializar".to_string());
    }

    let referencias: Vec<&Firma> = firmas.iter().collect();
    let agregada = crudo::agregar_firmas(&referencias).map_err(|e| e.to_string())?;
    let esperado = hex_bytes(salida)?;
    if agregada.bytes().as_slice() != esperado.as_slice() {
        return Err("el agregado no coincide con el vector".to_string());
    }
    Ok(())
}

#[test]
fn vectores_de_verificacion_agregada() {
    comprobar(
        "fast_aggregate_verify",
        include_str!("vectores/fast_aggregate_verify.txt"),
        un_fast_aggregate_verify,
    );
    comprobar(
        "aggregate_verify",
        include_str!("vectores/aggregate_verify.txt"),
        un_aggregate_verify,
    );
}

/// Deserializa `claves` separadas por `;`.
fn claves_de(texto: &str) -> Result<Vec<ClavePublica>, String> {
    let mut claves = Vec::new();
    for clave in texto.split(';').filter(|s| !s.is_empty()) {
        claves.push(ClavePublica::desde_bytes(&hex_bytes(clave)?).map_err(|e| e.to_string())?);
    }
    Ok(claves)
}

fn un_fast_aggregate_verify(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 4 {
        return Err(format!("se esperaban 4 campos y hay {}", campos.len()));
    }
    let esperado = campos[0] == "true";
    let mensaje = hex_bytes(campos[2])?;
    let firma = Firma::desde_bytes(&hex_bytes(campos[3])?);

    match (claves_de(campos[1]), firma) {
        (Ok(claves), Ok(firma)) => {
            let referencias: Vec<&ClavePublica> = claves.iter().collect();
            let agregada = FirmaAgregada::desde_firma(&firma);
            let obtenido = crudo::fast_aggregate_verify(&referencias, &agregada, &mensaje).is_ok();
            if obtenido != esperado {
                return Err(format!("se esperaba {esperado} y se obtuvo {obtenido}"));
            }
            Ok(())
        }
        _ => {
            if esperado {
                Err("clave o firma invalidas en un vector valido".to_string())
            } else {
                Ok(())
            }
        }
    }
}

fn un_aggregate_verify(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 4 {
        return Err(format!("se esperaban 4 campos y hay {}", campos.len()));
    }
    let esperado = campos[0] == "true";
    let mensajes: Vec<Vec<u8>> = campos[2]
        .split(';')
        .filter(|s| !s.is_empty())
        .map(hex_bytes)
        .collect::<Result<_, _>>()?;
    let firma = Firma::desde_bytes(&hex_bytes(campos[3])?);

    match (claves_de(campos[1]), firma) {
        (Ok(claves), Ok(firma)) => {
            let referencias: Vec<&ClavePublica> = claves.iter().collect();
            let msgs: Vec<&[u8]> = mensajes.iter().map(Vec::as_slice).collect();
            let agregada = FirmaAgregada::desde_firma(&firma);
            let obtenido = crudo::aggregate_verify(&referencias, &msgs, &agregada).is_ok();
            if obtenido != esperado {
                return Err(format!("se esperaba {esperado} y se obtuvo {obtenido}"));
            }
            Ok(())
        }
        _ => {
            if esperado {
                Err("clave o firma invalidas en un vector valido".to_string())
            } else {
                Ok(())
            }
        }
    }
}

#[test]
fn vectores_de_deserializacion() {
    comprobar(
        "deserialization_G1",
        include_str!("vectores/deserialization_g1.txt"),
        un_deserialization_g1,
    );
    comprobar(
        "deserialization_G2",
        include_str!("vectores/deserialization_g2.txt"),
        un_deserialization_g2,
    );
}

fn un_deserialization_g1(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 2 {
        return Err(format!("se esperaban 2 campos y hay {}", campos.len()));
    }
    let esperado = campos[0] == "true";
    let bytes = hex_bytes(campos[1])?;
    let resultado = ClavePublica::desde_bytes(&bytes);
    if esperado && !es_infinito_g1(&bytes) {
        resultado
            .map(|_| ())
            .map_err(|e| format!("vector valido rechazado: {e}"))
    } else if resultado.is_ok() {
        Err("se esperaba rechazo".to_string())
    } else {
        Ok(())
    }
}

fn un_deserialization_g2(linea: &str) -> Result<(), String> {
    let campos: Vec<&str> = linea.split('\t').collect();
    if campos.len() != 2 {
        return Err(format!("se esperaban 2 campos y hay {}", campos.len()));
    }
    let esperado = campos[0] == "true";
    let bytes = hex_bytes(campos[1])?;
    let resultado = Firma::desde_bytes(&bytes);
    if esperado && !es_infinito_g2(&bytes) {
        resultado
            .map(|_| ())
            .map_err(|e| format!("vector valido rechazado: {e}"))
    } else if resultado.is_ok() {
        Err("se esperaba rechazo".to_string())
    } else {
        Ok(())
    }
}
