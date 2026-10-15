//! Errores tipados de `zx-bls`.
//!
//! Ninguna entrada externa provoca un `panic`: todo rechazo viaja como valor. Los códigos de
//! `blst` se traducen a un motivo `&'static str` para que el tipo de la biblioteca C **no** forme
//! parte de la API pública (PK-04: `blst` queda confinado en este crate).

use blst::BLST_ERROR;

/// Error de `zx-bls`.
///
/// Es `Clone + PartialEq + Eq` para que los tests puedan comparar rechazos sin `unwrap`/`expect`
/// (prohibidos por los lints del workspace).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ErrorBLS {
    /// La semilla de `KeyGen` mide menos de 32 bytes.
    #[error("semilla de {0} bytes; el KeyGen del borrador exige >= 32")]
    SemillaCorta(usize),

    /// El dominio de separación de ZEROX está vacío.
    #[error("el dominio de separacion MUST NOT estar vacio")]
    DominioVacio,

    /// El dominio no cabe en el prefijo `len_u16_be`.
    #[error("dominio de {0} bytes; el prefijo len_u16_be admite <= 65535")]
    DominioLargo(usize),

    /// La clave secreta no es un escalar válido (cero, fuera de rango o longitud distinta de 32).
    #[error("clave secreta invalida: {motivo}")]
    ClaveSecretaInvalida {
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// La clave pública no es un punto válido de G1 del subgrupo (o es el infinito).
    #[error("clave publica invalida: {motivo}")]
    ClaveInvalida {
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// La firma no es un punto válido de G2 del subgrupo (o es el infinito).
    #[error("firma invalida: {motivo}")]
    FirmaInvalida {
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// La verificación —individual o agregada— falló.
    #[error("la firma no verifica")]
    VerificacionFallida,

    /// Se pidió agregar o verificar una lista vacía de firmas/claves.
    #[error("la lista de firmas o claves esta vacia")]
    AgregacionVacia,

    /// El número de claves no coincide con el número de mensajes.
    #[error("{claves} claves y {mensajes} mensajes; MUST coincidir")]
    LongitudesIncompatibles {
        /// Número de claves.
        claves: usize,
        /// Número de mensajes.
        mensajes: usize,
    },

    /// El número de claves, firmas y escalares de un lote no coincide.
    #[error("lote con {claves} claves, {firmas} firmas y {escalares} escalares; MUST coincidir")]
    LongitudesLoteIncompatibles {
        /// Número de claves del lote.
        claves: usize,
        /// Número de firmas del lote.
        firmas: usize,
        /// Número de escalares del lote.
        escalares: usize,
    },
}

/// Traduce un código de `blst` a un motivo estable para la API pública.
#[must_use]
pub(crate) fn motivo_blst(error: BLST_ERROR) -> &'static str {
    match error {
        BLST_ERROR::BLST_SUCCESS => "exito (no es un error)",
        BLST_ERROR::BLST_BAD_ENCODING => "codificacion no valida",
        BLST_ERROR::BLST_POINT_NOT_ON_CURVE => "el punto no esta en la curva",
        BLST_ERROR::BLST_POINT_NOT_IN_GROUP => "el punto no esta en el subgrupo",
        BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => "tipo de agregado incompatible",
        BLST_ERROR::BLST_VERIFY_FAIL => "la verificacion fallo",
        BLST_ERROR::BLST_PK_IS_INFINITY => "el punto es el infinito",
        BLST_ERROR::BLST_BAD_SCALAR => "escalar fuera de rango",
    }
}
