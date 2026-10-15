//! Transporte de una prueba dentro del marco ZRX-C (`CP-R-06`).
//!
//! El objeto viaja y se guarda **solo** dentro del marco versionado de `zx-compresion`
//! (`magic ZXC1`, versión, algoritmo, nivel, `dict_id`, `len_original`, `len_comprimido` y
//! checksum zstd). Si el marco no es más pequeño que la forma canónica, se envía esta **sin
//! comprimir** (fallback R-5); el receptor distingue ambos casos con
//! [`zx_compresion::esta_comprimido`].
//!
//! El receptor comprueba el tope del payload **antes** de descomprimir (`CP-R-04`) y los topes
//! canónico y de ratio dentro de `zx-compresion` (`CP-R-05`), de modo que una bomba se rechaza
//! sin reservar la memoria declarada.

use zx_compresion::{
    CABECERA, comprimir as comprimir_zrxc, descomprimir as descomprimir_zrxc, esta_comprimido,
    leer_cabecera,
};

use crate::ErrorPrueba;
use crate::limites::{MAX_PRUEBA_COMPRIMIDA_BYTES, limites_prueba};
use crate::objeto::PruebaRecursiva;

/// Comprime una prueba para su transporte en el marco ZRX-C.
///
/// Devuelve el marco ZXC1 cuando es más pequeño que la forma canónica y su payload no supera
/// [`MAX_PRUEBA_COMPRIMIDA_BYTES`]; en otro caso devuelve la forma canónica sin comprimir
/// (fallback R-5), también acotada por el tope de transporte.
///
/// # Errores
/// [`ErrorPrueba::Compresion`] si `zx-compresion` falla;
/// [`ErrorPrueba::ComprimidaDemasiadoLarga`] si el transporte resultante supera el tope.
pub fn comprimir(prueba: &PruebaRecursiva, nivel: i32) -> Result<Vec<u8>, ErrorPrueba> {
    let canonico = prueba.a_bytes();
    let marco = comprimir_zrxc(&canonico, nivel, None)?;
    let payload = marco.len().saturating_sub(CABECERA) as u64;
    if payload <= MAX_PRUEBA_COMPRIMIDA_BYTES && marco.len() < canonico.len() {
        return Ok(marco);
    }
    let transportado = canonico.len() as u64;
    if transportado > MAX_PRUEBA_COMPRIMIDA_BYTES {
        return Err(ErrorPrueba::ComprimidaDemasiadoLarga(transportado));
    }
    Ok(canonico)
}

/// Reconstruye una prueba desde el transporte del carril (marco ZXC1 o forma canónica).
///
/// # Errores
/// [`ErrorPrueba::ComprimidaDemasiadoLarga`] si el payload o el transporte crudo superan el
/// tope; [`ErrorPrueba::Compresion`] si el marco no es válido, declara más canónico del tope o
/// una bomba; [`ErrorPrueba::VersionDesconocida`]/[`ErrorPrueba::ClaseDesconocida`]/
/// [`ErrorPrueba::BytesInsuficientes`] si el objeto no es válido.
pub fn descomprimir(bytes: &[u8]) -> Result<PruebaRecursiva, ErrorPrueba> {
    if esta_comprimido(bytes) {
        let cabecera = leer_cabecera(bytes)?;
        if cabecera.len_comprimido > MAX_PRUEBA_COMPRIMIDA_BYTES {
            return Err(ErrorPrueba::ComprimidaDemasiadoLarga(
                cabecera.len_comprimido,
            ));
        }
        let canonico = descomprimir_zrxc(bytes, None, &limites_prueba())?;
        PruebaRecursiva::desde_canonico(&canonico)
    } else {
        let transportado = bytes.len() as u64;
        if transportado > MAX_PRUEBA_COMPRIMIDA_BYTES {
            return Err(ErrorPrueba::ComprimidaDemasiadoLarga(transportado));
        }
        PruebaRecursiva::desde_canonico(bytes)
    }
}
