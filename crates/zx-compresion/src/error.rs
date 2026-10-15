//! Errores de ZRX-C.
//!
//! Todo fallo es **visible**: un marco corto, con otra magia, con una versión o
//! un algoritmo que este binario no entiende, con longitudes que no cuadran, con
//! un checksum que no cuadra o con un tamaño declarado por encima del tope del
//! tipo se rechaza con un error explícito. Nunca se repara en silencio ni se
//! devuelve una salida parcial.

use thiserror::Error;

/// Fallo al comprimir o descomprimir un marco ZRX-C.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorCompresion {
    /// Los primeros cuatro bytes no son `ZXC1`.
    #[error("la magia del marco no es ZXC1")]
    MagiaInvalida,

    /// El búfer no llega a cubrir la cabecera completa del marco.
    #[error("el marco ZRX-C no llega a su cabecera: {bytes} B")]
    MarcoCorto {
        /// Bytes recibidos.
        bytes: usize,
    },

    /// El byte de versión no es el que entiende este binario.
    #[error("versión de marco ZRX-C desconocida: {encontrada}")]
    VersionDesconocida {
        /// Versión leída del marco.
        encontrada: u8,
    },

    /// El byte de algoritmo no es ninguno conocido (`0` almacenado, `1` zstd).
    #[error("algoritmo de marco ZRX-C desconocido: {encontrada:#04x}")]
    AlgoritmoDesconocido {
        /// Algoritmo leído del marco.
        encontrada: u8,
    },

    /// El nivel de compresión no está en el rango admitido (1…22).
    #[error("nivel de compresión zstd fuera de rango: {nivel}")]
    NivelInvalido {
        /// Nivel pedido.
        nivel: i32,
    },

    /// Las longitudes declaradas no cuadran con el tamaño real del marco.
    #[error("las longitudes del marco ZRX-C no cuadran")]
    LongitudIncoherente,

    /// La salida declarada supera el tope de descompresión del camino.
    #[error("el marco declara {declarado} B y el tope es {max} B (bomba)")]
    DemasiadoGrande {
        /// Longitud original declarada.
        declarado: u64,
        /// Tope del camino.
        max: u64,
    },

    /// El ratio declarado supera el máximo admitido (bomba).
    #[error("ratio {original}:{comprimido} excede el máximo (bomba)")]
    RatioExcesivo {
        /// Longitud original declarada.
        original: u64,
        /// Longitud comprimida.
        comprimido: u64,
    },

    /// El payload no se pudo descomprimir o el tamaño real no cuadró.
    #[error("payload ZRX-C corrupto o truncado")]
    Corrupto,

    /// El checksum de transporte no cuadra (R-11).
    #[error("checksum inválido (esperado {esperado:#018x}, calculado {calculado:#018x})")]
    ChecksumInvalido {
        /// El checksum del marco.
        esperado: u64,
        /// El calculado sobre los bytes originales.
        calculado: u64,
    },

    /// El marco exige un diccionario distinto del que se pasó.
    #[error("diccionario desconocido: el marco pide id {esperado} y se pasó {recibido}")]
    DiccionarioDesconocido {
        /// Id que declara el marco (`0` si no hay).
        esperado: u32,
        /// Id del diccionario disponible (`0` si no se pasó ninguno).
        recibido: u32,
    },

    /// Un diccionario con id `0` no es válido: `0` significa «sin diccionario».
    #[error("un diccionario ZRX-C no puede tener id 0")]
    DiccionarioIdCero,

    /// El entrenamiento de un diccionario falló.
    #[error("no se pudo entrenar el diccionario: {0}")]
    Entrenamiento(String),

    /// La librería zstd devolvió un error.
    #[error("zstd falló: {0}")]
    Zstd(String),
}

impl ErrorCompresion {
    /// Envuelve un error de E/S de zstd en un error visible de ZRX-C.
    pub(crate) fn zstd<E: core::fmt::Display>(e: E) -> Self {
        Self::Zstd(e.to_string())
    }
}
