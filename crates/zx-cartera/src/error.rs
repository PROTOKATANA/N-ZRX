//! Errores de `zx-cartera`.
//!
//! La cartera no inventa errores de consenso: envuelve los de `zx-core` ([`EncodingError`] y
//! [`ErrorFormaTx`]) y añade solo los que son suyos (una entrada no construible, saldo negativo al
//! armar la transacción, etcétera).

use zx_core::error::{EncodingError, ErrorFormaTx};

/// Error de construcción o de firma de una transacción de la cartera.
#[derive(Debug, thiserror::Error)]
pub enum ErrorCartera {
    /// La cartera solo firma entradas `PubKey` (P2K). MultiSig y HTLC exigirían reunir varias
    /// firmas o una preimagen, y no son el caso de la cartera dev.
    #[error("la cartera solo firma entradas PubKey (P2K); este lock no lo soporta")]
    LockNoSoportado,
    /// Una transferencia v1 sin entradas no es una transferencia: es una coinbase, y la cartera no
    /// produce bloques.
    #[error("una transferencia v1 necesita al menos una entrada")]
    SinEntradas,
    /// F-05: una v1 con entradas exige al menos una salida (`forma::TransferenciaSinSalidas`).
    #[error("una transferencia v1 necesita al menos una salida")]
    SinSalidas,
    /// El valor de las entradas no cubre lo que la transacción promete (salidas + importe).
    #[error(
        "saldo insuficiente: entradas {entradas} brek < salidas {salidas} brek + importe {importe} brek"
    )]
    SaldoInsuficiente {
        /// Suma de las entradas, en brek.
        entradas: i64,
        /// Suma de las salidas, en brek.
        salidas: i64,
        /// Importe de la extensión de garantía, en brek.
        importe: i64,
    },
    /// F-07: el importe de una operación de garantía MUST ser `> 0`.
    #[error("el importe de la operación de garantía debe ser mayor que cero")]
    ImporteInvalido,
    /// La firma del testigo `indice` no verifica contra la clave y el mensaje esperados.
    #[error("la firma del testigo {indice} no verifica")]
    FirmaNoVerifica {
        /// Posición del testigo en la lista.
        indice: usize,
    },
    /// Error de codificación canónica de `zx-core`.
    #[error("codificación: {0}")]
    Codificacion(#[from] EncodingError),
    /// Error de forma de `zx-core`.
    #[error("forma: {0}")]
    Forma(#[from] ErrorFormaTx),
    /// El texto de entrada (CLI, fichero de claves) no tiene el formato esperado.
    #[error("entrada mal formada: {0}")]
    Parseo(String),
    /// Un byte serializado no es una transacción con sus testigos, o le sobran bytes.
    #[error("bytes de transacción inválidos: {0}")]
    Bytes(String),
}
