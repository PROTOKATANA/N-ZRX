//! Serialización canónica `serial(T_n)` y hash `h_T(n)` (C-FV-02, C-FV-11).
//!
//! `serial(T_n)` = concatenación, sobre las claves ordenadas **ascendente por bytes de `pk`**, de
//! `pk ‖ peso_u64_be ‖ activo_u8 ‖ prueba_u8` (la garantía no entra en `h_T` en v1) y
//! `h_T(n) = SHA-256(serial(T_n))`. Reproduce bit a bit el oráculo Julia de FV-3.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::tipos::{Hash, LONGITUD_HASH, Tabla};

/// `SHA-256` del mensaje (C-FV-11).
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> Hash {
    let resumen = Sha256::digest(bytes);
    let mut salida = [0u8; LONGITUD_HASH];
    salida.copy_from_slice(resumen.as_slice());
    salida
}

/// `serial(T_n)`: serialización canónica de la tabla de poder (C-FV-11).
///
/// Las claves se ordenan por bytes de `pk` **antes** de escribir; el orden de entrada no importa.
#[must_use]
pub fn serial_tabla(tabla: &Tabla) -> Vec<u8> {
    let mut claves: Vec<&crate::tipos::Clave> = tabla.claves.iter().collect();
    claves.sort_by(|a, b| a.clave.cmp(&b.clave));

    let mut salida = Vec::with_capacity(claves.len() * 42);
    for clave in claves {
        salida.extend_from_slice(&clave.clave);
        salida.extend_from_slice(&clave.peso.to_be_bytes());
        salida.push(u8::from(clave.activo));
        salida.push(u8::from(clave.prueba));
    }
    salida
}

/// `h_T(n) = SHA-256(serial(T_n))` (C-FV-02, C-FV-11).
#[must_use]
pub fn hash_tabla(tabla: &Tabla) -> Hash {
    hash_bytes(&serial_tabla(tabla))
}

/// Entero big-endian de exactamente 32 bytes, o `None` si la longitud no es 32 (C-FV-03.2).
#[must_use]
pub fn bytes_a_entero(bytes: &[u8]) -> Option<BigUint> {
    if bytes.len() != LONGITUD_HASH {
        return None;
    }
    Some(BigUint::from_bytes_be(bytes))
}

/// Devuelve el hash como texto hexadecimal en minúsculas (ayuda de evidencia).
#[must_use]
pub fn hash_a_hex(hash: &Hash) -> String {
    let mut texto = String::with_capacity(LONGITUD_HASH * 2);
    for byte in hash {
        texto.push_str(&format!("{byte:02x}"));
    }
    texto
}
