//! Errores tipados de `zx-votos`.
//!
//! Ninguna entrada externa provoca un `panic`: los rechazos viajan como [`ErrorVotos`] (la regla
//! del proyecto prohíbe `panic!`/`unwrap`/`expect` también en los tests, vía los lints del
//! workspace). El error de `zx-bls` se conserva como fuente (`#[from]`) para no perder el motivo.

use thiserror::Error;
use zx_bls::ErrorBLS;

/// Error de `zx-votos`.
///
/// Es `Clone + PartialEq + Eq` para poder comparar rechazos en los tests sin `unwrap`/`expect`.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorVotos {
    /// Un campo de longitud fija (clave, hash, salida VRF) no mide lo que se esperaba.
    #[error("longitud inesperada: se esperaban {esperado} bytes y hay {obtenido}")]
    LongitudInesperada {
        /// Longitud exigida por el esquema.
        esperado: usize,
        /// Longitud realmente recibida.
        obtenido: usize,
    },

    /// Un cómputo entero desbordó el ancho de `u64`.
    #[error("desbordamiento aritmetico al sumar o multiplicar enteros")]
    Desbordamiento,

    /// El denominador de una fracción de perfil (multa o cuantil) es cero.
    #[error("denominador cero en una fraccion del perfil")]
    DenominadorCero,

    /// La instancia que el certificado afirma no es la instancia pedida.
    #[error(
        "ventana incoherente: el certificado afirma n={afirmada} y la instancia es n={esperada}"
    )]
    VentanaIncoherente {
        /// Instancia afirmada por el certificado.
        afirmada: u64,
        /// Instancia realmente evaluada.
        esperada: u64,
    },

    /// El número de claves no coincide con el número de plazas declaradas.
    #[error("{claves} claves y {plazas} plazas; MUST coincidir")]
    LongitudesIncompatibles {
        /// Número de claves.
        claves: usize,
        /// Número de plazas.
        plazas: usize,
    },

    /// El número de claves no coincide con el número de firmas de un lote VRF.
    #[error("{claves} claves y {firmas} firmas; MUST coincidir")]
    FirmasIncompatibles {
        /// Número de claves.
        claves: usize,
        /// Número de firmas.
        firmas: usize,
    },

    /// La serialización de un certificado no empieza por la cabecera esperada.
    #[error("cabecera de certificado invalida")]
    CabeceraInvalida,

    /// La serialización de un certificado tiene bytes sobrantes al final.
    #[error("serializacion de certificado con {sobran} bytes sobrantes")]
    BytesSobrantes {
        /// Bytes que sobran después del último campo.
        sobran: usize,
    },

    /// Un entero de la serialización no cabe en `usize` en esta plataforma.
    #[error("entero de la serializacion fuera de la plataforma")]
    EnteroFueraDePlataforma,

    /// Una clave citada por el certificado no está registrada en la tabla de poder.
    #[error("clave no registrada en la tabla de poder")]
    ClaveNoRegistrada,

    /// Una clave citada por el certificado está registrada pero retirada (`activo = 0`).
    #[error("clave retirada en la tabla de poder")]
    ClaveRetirada,

    /// El certificado repite una misma clave entre sus firmantes.
    #[error("firmante repetido en el certificado")]
    FirmanteDuplicado,

    /// La suma de plazas de los votos válidos no alcanza el umbral `U = ceil(2K/3)`.
    #[error("quorum insuficiente: {plazas} plazas < {umbral}")]
    QuorumInsuficiente {
        /// Plazas que suman los votos contados.
        plazas: u64,
        /// Umbral exigido.
        umbral: u64,
    },

    /// La fuente de peso no tenía peso para una clave registrada.
    #[error("la fuente de peso no suministro peso para la clave")]
    PesoNoDisponible,

    /// La carga inicial (punto de control externo) del motor de votos es inválida.
    ///
    /// La raíz la confía quien llama; este error señala una guarda de **forma** (índice, `K` local,
    /// correspondencia claves↔tabla, `T_{n+1}` verificable) o una carga sobre un motor ya abierto.
    /// `motivo` es un literal estático y estable; el rechazo es atómico y no consume la carga.
    #[error("carga inicial de votos invalida: {motivo}")]
    CargaInicialInvalida {
        /// Guarda concreta que rechazó la carga.
        motivo: &'static str,
    },

    /// La primitiva BLS rechazó la operación (firma, agregado o verificación).
    #[error("error de BLS: {0}")]
    Bls(#[from] ErrorBLS),

    /// El JSON de un vector de FV-3 no tiene el esquema esperado.
    #[error("JSON de vector invalido: {0}")]
    Json(String),

    /// El JSON de un vector excede la profundidad de anidamiento admitida.
    #[error("JSON de vector demasiado anidado")]
    JsonProfundo,

    /// Un campo hexadecimal de un vector no es hexadecimal válido.
    #[error("hexadecimal invalido en un vector: {0}")]
    Hex(String),

    /// Una definición que el esquema exige no estaba presente en el vector.
    #[error("falta el campo obligatorio del vector: {0}")]
    CampoAusente(&'static str),
}

#[cfg(test)]
impl From<hex::FromHexError> for ErrorVotos {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error.to_string())
    }
}
