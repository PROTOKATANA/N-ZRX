//! Crate `zx-cadena`: estado del DAG en memoria de la red dev (`ORDEN-W06a`, `D-N02`).
//!
//! El documento del crate está en `README.md`; la API pública son [`BloqueCadena`],
//! [`BloquePost`], [`Cadena`], [`Descarte`], [`MotivoBloque`] y [`ViolacionFinalidad`].

#![doc = include_str!("../README.md")]

pub mod bloque;
pub mod cadena;
pub mod error;

pub use bloque::{BloqueCadena, BloquePost};
pub use cadena::{
    Cadena, Descarte, Eclipse, MAX_TERMINALES_CON_DAG, MotivoAncla, ResultadoAncla,
    ViolacionFinalidad,
};
pub use error::MotivoBloque;
