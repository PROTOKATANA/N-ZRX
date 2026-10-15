//! Objeto, huella y topes del carril de pruebas recursivas (orden CP-C1).
//!
//! Implementa la parte de primitivo del contrato `CONTRATO-CARRIL-PRUEBAS.md`:
//!
//! - [`objeto::PruebaRecursiva`]: `version u8 ‖ clase u8 ‖ cuerpo_canónico` (`CP-R-01`), con
//!   conjunto de clases cerrado `{0x01, 0x02, 0x06}`.
//! - [`huella::huella`]: `H_d("ZZKPruebaCarril_", cuerpo_canónico)`, 32 B (`CP-R-02`).
//! - [`limites`]: topes comprimido y descomprimido y ratio anti-bomba (`CP-R-04`/`CP-R-05`).
//! - [`marco`]: transporte dentro del marco ZRX-C de `zx-compresion` (`CP-R-06`).
//!
//! La huella se calcula sobre la **forma canónica descomprimida**: la compresión es transporte,
//! nunca identidad (`REVISION-PT3j-4.md:11-12`). Dos compresiones distintas del mismo objeto dan
//! la misma huella porque el hash se recomputa tras descomprimir.

pub mod huella;
pub mod limites;
pub mod marco;
pub mod objeto;

pub use huella::{TAG_HUELLA, h_d, huella};
pub use limites::{
    MAX_PRUEBA_CANONICA_BYTES, MAX_PRUEBA_COMPRIMIDA_BYTES, MAX_RATIO_DESCOMPRESION, NIVEL_PRUEBA,
    limites_prueba,
};
pub use marco::{comprimir, descomprimir};
pub use objeto::{CABECERA_OBJETO, ClasePrueba, PruebaRecursiva, VERSION_OBJETO};

use thiserror::Error;

/// Error del carril de pruebas recursivas.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ErrorPrueba {
    /// La versión del objeto no es la que entiende este binario.
    #[error("versión de prueba recursiva desconocida: {encontrada}")]
    VersionDesconocida {
        /// Versión leída del objeto.
        encontrada: u8,
    },

    /// La clase del objeto no pertenece al conjunto cerrado.
    #[error("clase de prueba recursiva desconocida: {0:#04x}")]
    ClaseDesconocida(u8),

    /// El búfer no alcanza para la versión y la clase.
    #[error("bytes insuficientes para el objeto prueba")]
    BytesInsuficientes,

    /// La forma canónica supera el tope descomprimido.
    #[error("la prueba canónica de {0} B excede el tope descomprimido")]
    CanonicaDemasiadoLarga(u64),

    /// El transporte supera el tope comprimido.
    #[error("la prueba de transporte de {0} B excede el tope comprimido")]
    ComprimidaDemasiadoLarga(u64),

    /// El marco ZRX-C no es válido.
    #[error("marco ZRX-C inválido: {0}")]
    Compresion(#[from] zx_compresion::ErrorCompresion),
}
