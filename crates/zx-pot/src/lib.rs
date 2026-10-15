#![doc = include_str!("../README.md")]
// Port literal de `subspace-proof-of-time` @ f8842d0 (0BSD). El crate implementa SOLO la primitiva
// de `C-POT-02` —prueba y verificación de un slot— y no declara válido ningún bloque.
//
// Los lints de estilo del workspace se apartan aquí módulo a módulo, nunca apagándolos en
// `Cargo.toml`: el AES copiado se conserva byte a byte y no se reformula para contentar a `clippy`.
#![no_std]

#[allow(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::wildcard_imports,
    reason = "AES copiado literalmente: intrínsecos, índices fijos y divisiones exactas del original"
)]
mod aes;

#[allow(
    unsafe_code,
    clippy::unwrap_used,
    missing_docs,
    reason = "newtypes y `repr(C)` copiados del prototipo; el `unwrap` es de un `NonZeroU8` constante"
)]
pub mod tipos;

#[allow(
    missing_docs,
    reason = "`vdf` documenta su propia API; el lint se aparta junto al port para no reformularlo"
)]
pub mod vdf;

use core::num::NonZeroU32;

use crate::tipos::{PotCheckpoints, PotSeed};

/// Error de la primitiva Proof of Time.
#[derive(Debug, thiserror::Error)]
pub enum PotError {
    /// Las iteraciones no son múltiplo del número de checkpoints por dos.
    #[error(
        "Iterations {iterations} are not multiple of number of checkpoints {num_checkpoints} \
        times two"
    )]
    NotMultipleOfCheckpoints {
        /// Iteraciones del slot.
        iterations: NonZeroU32,
        /// Número de checkpoints.
        num_checkpoints: u32,
    },
}

/// Ejecuta la prueba PoT y produce los checkpoints de un slot (`C-POT-02`).
///
/// # Errores
/// [`PotError::NotMultipleOfCheckpoints`] si `iterations` no es múltiplo de los checkpoints por
/// dos (16 con ocho checkpoints).
#[allow(
    clippy::integer_division,
    reason = "la división es exacta: el guardo `is_multiple_of` de arriba la precede"
)]
pub fn prove(seed: PotSeed, iterations: NonZeroU32) -> Result<PotCheckpoints, PotError> {
    if !iterations
        .get()
        .is_multiple_of(u32::from(PotCheckpoints::NUM_CHECKPOINTS.get() * 2))
    {
        return Err(PotError::NotMultipleOfCheckpoints {
            iterations,
            num_checkpoints: u32::from(PotCheckpoints::NUM_CHECKPOINTS.get()),
        });
    }

    Ok(aes::create(
        seed,
        seed.key(),
        iterations.get() / u32::from(PotCheckpoints::NUM_CHECKPOINTS.get()),
    ))
}

/// Verifica los checkpoints de un slot (`C-POT-02`).
///
/// El número de iteraciones se reparte uniformemente entre los checkpoints. La verificación es
/// una función **determinista** de `(semilla, N, PotCheckpoints)`: misma terna, mismo resultado,
/// en cualquier nodo y en cualquier orden de llegada.
///
/// # Errores
/// [`PotError::NotMultipleOfCheckpoints`] si `iterations` no es múltiplo de los checkpoints por
/// dos (16 con ocho checkpoints). Es un defecto de la terna, no una prueba inválida.
#[allow(
    clippy::integer_division,
    reason = "la división es exacta: el guardo `is_multiple_of` de arriba la precede"
)]
pub fn verify(
    seed: PotSeed,
    iterations: NonZeroU32,
    checkpoints: &PotCheckpoints,
) -> Result<bool, PotError> {
    let num_checkpoints = checkpoints.len() as u32;
    if !iterations.get().is_multiple_of(num_checkpoints * 2) {
        return Err(PotError::NotMultipleOfCheckpoints {
            iterations,
            num_checkpoints,
        });
    }

    Ok(aes::verify_sequential(
        seed,
        seed.key(),
        checkpoints,
        iterations.get() / num_checkpoints,
    ))
}
