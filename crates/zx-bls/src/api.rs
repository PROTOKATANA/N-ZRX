//! API de ZEROX: la firma BLS con separación de dominios (decisión 2).
//!
//! Toda firma/verificación que vaya a consenso **MUST** pasar por aquí: `dominio` es obligatorio y
//! no vacío, y el mensaje firmado es `len_u16_be || dominio || mensaje`. La capa
//! [`crate::crudo`] no lleva prefijo y **solo** se usa para los vectores oficiales y como
//! implementación interna.

use crate::agregada::ClaveAgregada;
use crate::clave::{ClavePublica, ClaveSecreta};
use crate::crudo;
use crate::dominio::mensaje_con_dominio;
use crate::error::ErrorBLS;
use crate::firma::{Firma, FirmaAgregada};

/// Firma `mensaje` en el `dominio` de ZEROX.
///
/// # Errores
/// [`ErrorBLS::DominioVacio`] / [`ErrorBLS::DominioLargo`] si el dominio no es utilizable.
pub fn firmar(clave: &ClaveSecreta, dominio: &[u8], mensaje: &[u8]) -> Result<Firma, ErrorBLS> {
    let con_dominio = mensaje_con_dominio(dominio, mensaje)?;
    Ok(crudo::firmar(clave, &con_dominio))
}

/// Verifica una firma individual en el `dominio` de ZEROX.
///
/// # Errores
/// [`ErrorBLS::DominioVacio`] / [`ErrorBLS::DominioLargo`] si el dominio no es utilizable;
/// [`ErrorBLS::VerificacionFallida`] si no verifica.
pub fn verificar(
    clave: &ClavePublica,
    firma: &Firma,
    dominio: &[u8],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    let con_dominio = mensaje_con_dominio(dominio, mensaje)?;
    crudo::verificar(clave, firma, &con_dominio)
}

/// `fast_aggregate_verify`: un mismo mensaje y `N` claves en el `dominio` de ZEROX.
///
/// # Errores
/// Dominio inválido, lista vacía o certificado que no verifica.
pub fn fast_aggregate_verify(
    claves: &[&ClavePublica],
    firma: &FirmaAgregada,
    dominio: &[u8],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    let con_dominio = mensaje_con_dominio(dominio, mensaje)?;
    crudo::fast_aggregate_verify(claves, firma, &con_dominio)
}

/// `verificar_lote_con_escalares`: mismo mensaje y `N` claves, cada firma pesada por un escalar de
/// 128 bits, en el `dominio` de ZEROX.
///
/// Comprueba `e(Σ r_i·σ_i, g₁) == e(H(m), Σ r_i·pk_i)`. Las claves **deben** tener prueba de
/// posesión verificada (esquema POP, PT-3bc); ver `crudo::verificar_lote_con_escalares`.
///
/// # Errores
/// Dominio inválido, longitudes incompatibles, lote vacío, punto fuera de subgrupo o combinación
/// lineal que no cuadra.
pub fn verificar_lote_con_escalares(
    claves: &[&ClavePublica],
    firmas: &[&Firma],
    escalares: &[[u8; crudo::LONGITUD_ESCALAR_LOTE]],
    dominio: &[u8],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    let con_dominio = mensaje_con_dominio(dominio, mensaje)?;
    crudo::verificar_lote_con_escalares(claves, firmas, escalares, &con_dominio)
}

/// `verificar_lote_de_agregados_con_escalares`: varios agregados del mismo mensaje, cada uno contra
/// su mapa de claves, con escalares de 128 bits, en el `dominio` de ZEROX.
///
/// Ver [`crudo::verificar_lote_de_agregados_con_escalares`]: la clave de cada agregado es la suma de
/// las claves de su mapa y la aleatorización impide el desplazamiento compensado entre agregados.
///
/// # Errores
/// Dominio inválido, longitudes incompatibles, lote o mapa vacío, o combinación que no cuadra.
pub fn verificar_lote_de_agregados_con_escalares(
    agregados: &[crudo::AgregadoLote<'_>],
    escalares: &[[u8; crudo::LONGITUD_ESCALAR_LOTE]],
    dominio: &[u8],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    let con_dominio = mensaje_con_dominio(dominio, mensaje)?;
    crudo::verificar_lote_de_agregados_con_escalares(agregados, escalares, &con_dominio)
}

/// `aggregate_verify`: mensajes distintos, todos bajo el mismo `dominio` de ZEROX.
///
/// # Errores
/// [`ErrorBLS::LongitudesIncompatibles`] si el número de claves y de mensajes no coincide; dominio
/// inválido, lista vacía o certificado que no verifica.
pub fn aggregate_verify(
    claves: &[&ClavePublica],
    mensajes: &[&[u8]],
    dominio: &[u8],
    firma: &FirmaAgregada,
) -> Result<(), ErrorBLS> {
    if claves.len() != mensajes.len() {
        return Err(ErrorBLS::LongitudesIncompatibles {
            claves: claves.len(),
            mensajes: mensajes.len(),
        });
    }
    let mut con_dominio: Vec<Vec<u8>> = Vec::with_capacity(mensajes.len());
    for mensaje in mensajes {
        con_dominio.push(mensaje_con_dominio(dominio, mensaje)?);
    }
    let referencias: Vec<&[u8]> = con_dominio.iter().map(Vec::as_slice).collect();
    crudo::aggregate_verify(claves, &referencias, firma)
}

/// `PopProve`: prueba de posesión de la clave secreta.
///
/// El mensaje es la propia clave pública y el DST es el de posesión; no lleva prefijo de dominio
/// porque el borrador lo define así (ver `PROGRESO.md`).
#[must_use]
pub fn probar_posesion(clave: &ClaveSecreta) -> Firma {
    crudo::firmar_posesion(clave)
}

/// `PopVerify`: comprueba la prueba de posesión de una clave pública.
///
/// # Errores
/// [`ErrorBLS::VerificacionFallida`] si la prueba no es válida.
pub fn verificar_posesion(clave: &ClavePublica, prueba: &Firma) -> Result<(), ErrorBLS> {
    crudo::verificar_posesion(clave, prueba)
}

/// Agrega firmas (con comprobación de subgrupo de cada una).
///
/// # Errores
/// [`ErrorBLS::AgregacionVacia`] si la lista está vacía.
pub fn agregar_firmas(firmas: &[&Firma]) -> Result<FirmaAgregada, ErrorBLS> {
    crudo::agregar_firmas(firmas)
}

/// Verifica una firma agregada contra una **clave agregada ya calculada**, en el `dominio` de
/// ZEROX.
///
/// Equivale a [`fast_aggregate_verify`] con las claves del mapa, pero recibe su suma
/// ([`ClaveAgregada`]) en vez de la lista; no vuelve a sumar.
///
/// # Errores
/// Dominio inválido o certificado que no verifica (incluida la clave del punto del infinito).
pub fn verificar_agregado_con_clave(
    clave: &ClaveAgregada,
    firma: &FirmaAgregada,
    dominio: &[u8],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    let con_dominio = mensaje_con_dominio(dominio, mensaje)?;
    crate::agregada::verificar_agregado_con_clave(clave, firma, &con_dominio)
}

/// `verificar_lote_de_agregados_con_clave`: varios agregados del mismo mensaje, cada uno contra su
/// **clave agregada ya calculada**, con escalares de 128 bits, en el `dominio` de ZEROX.
///
/// Equivale a [`verificar_lote_de_agregados_con_escalares`] pero recibe la suma de las claves de
/// cada mapa ([`ClaveAgregada`]) en vez del mapa.
///
/// # Errores
/// Dominio inválido, longitudes incompatibles, lote vacío o combinación que no cuadra.
pub fn verificar_lote_de_agregados_con_clave(
    claves: &[&ClaveAgregada],
    firmas: &[&FirmaAgregada],
    escalares: &[[u8; crudo::LONGITUD_ESCALAR_LOTE]],
    dominio: &[u8],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    let con_dominio = mensaje_con_dominio(dominio, mensaje)?;
    crate::agregada::verificar_lote_de_agregados_con_clave(claves, firmas, escalares, &con_dominio)
}
