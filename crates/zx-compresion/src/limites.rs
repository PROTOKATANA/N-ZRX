//! Límites de descompresión.
//!
//! Un marco ZRX-C no es digno de confianza solo porque lo haya escrito un nodo:
//! un byte cambiado o un emisor malicioso pueden declarar una longitud original
//! enorme o un ratio imposible. Estos límites se comprueban **antes** de
//! descomprimir y acotan la memoria que puede pedir zstd.

/// Tope de descompresión para un tipo de dato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limites {
    /// Máximo de bytes originales que el marco puede declarar y producir.
    pub max_original: u64,
    /// Ratio máximo admitido entre bytes originales y comprimidos.
    pub ratio_max: u32,
    /// `log2` máximo de la ventana de zstd que se acepta al descomprimir.
    pub window_log_max: u32,
}

impl Limites {
    /// Límites con el ratio y la ventana por omisión (1000:1 y 2²³ = 8 MiB).
    #[must_use]
    pub const fn nuevo(max_original: u64) -> Self {
        Self {
            max_original,
            ratio_max: 1000,
            window_log_max: 23,
        }
    }

    /// El mismo tope con otro ratio máximo.
    #[must_use]
    pub const fn con_ratio(self, ratio_max: u32) -> Self {
        Self { ratio_max, ..self }
    }

    /// El mismo tope con otra ventana máxima.
    #[must_use]
    pub const fn con_ventana(self, window_log_max: u32) -> Self {
        Self {
            window_log_max,
            ..self
        }
    }

    /// Tope para el valor de una entrada de `bloques` de `zx-storage`.
    ///
    /// Un bloque de red no supera `MAX_BLOQUE_RED_BYTES`, así que su valor
    /// guardado tampoco; el tope queda por encima para no rechazar bloques
    /// legítimos del tamaño máximo.
    pub const VALOR_ALMACEN: Self = Self::nuevo(2 * 1024 * 1024);

    /// Tope para un bloque de red (cabecera PoST y justificación PoT máximas).
    pub const BLOQUE_RED: Self = Self::nuevo(2_118_062);

    /// Tope para la metadata de una parcela (`zx-farmer`).
    pub const METADATA_PARCELA: Self = Self::nuevo(2 * 1024 * 1024);

    /// Tope para un voto o certificado pequeño.
    pub const VOTO: Self = Self::nuevo(4 * 1024);
}
