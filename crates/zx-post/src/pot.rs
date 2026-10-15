//! Operaciones **puras** del PoT de ZEROX: el adaptador entre el wire y la primitiva AES de
//! `zx-pot` (`C-POT-02`, `C-POT-04`) y las derivaciones de semilla y aleatoriedad (`C-POT-01`,
//! `C-POT-03`), más la semilla del génesis de `C-FLU-06`.
//!
//! # Qué hay aquí
//!
//! 1. **Un slot AES** (`C-POT-02`): dadas `(semilla, N, checkpoints)`, decide si la cadena AES128
//!    secuencial reproduce esos checkpoints ([`verificar_slot_aes`]), con la conversión
//!    wire↔primitiva ([`checkpoints_a_primitiva`], [`checkpoints_a_wire`]) y la proyección de
//!    `N(s)` ([`proyectar_iteraciones`], `C-POT-04`).
//! 2. **Semilla y aleatoriedad** (`C-POT-01`, `C-POT-03`): [`semilla_siguiente`] encadena la salida
//!    anterior con cero o una inyección. El **reto** y su aleatoriedad **no** se duplican aquí:
//!    viven en [`zx_poas::reto`] y se reexportan ([`reto_desde_salida`], [`aleatoriedad_de_salida`]).
//! 3. **Semilla del génesis** (`C-FLU-06`): [`semilla_genesis`] deriva `semilla(f_0, 0)` con
//!    `blake3`, recibiendo la `entropía_externa` como argumento **explícito** del llamante.
//!
//! # Qué NO es
//!
//! **No** es `validar_bloque`: no conoce flujo, procedencia de la semilla, `N(s)` del contexto,
//! inyección acreditada, sello, caché, anclaje de `pot_output` ni el orden de validación de
//! §7.1.2. La clasificación contextual y la puerta conjunta viven en [`crate::pot_rango`] y
//! [`crate::cabecera_conjunta`].
//!
//! # Origen de las entradas: no acreditado aquí
//!
//! La semilla, la entropía, la salida y `N(s)` llegan como **argumentos libres**, y ninguna de
//! estas funciones **acredita su origen causal**. En particular, [`reto_desde_salida`] deriva un
//! reto de *cualquier* salida que el llamante entregue: **estas funciones, por sí solas, no impiden
//! saltarse slots**.

use core::num::NonZeroU32;

use thiserror::Error;
use zx_core::BlockHash;
use zx_core::wire_dag::{
    CHECKPOINTS_POR_BUNDLE, POT_OUTPUT_BYTES, PotCheckpoints as PotCheckpointsWire,
};
use zx_pot::tipos::{PotCheckpoints, PotOutput, PotSeed};

// El reto y su aleatoriedad **no** se duplican: son la misma función que `zx-poas` necesita para
// el auditor y que la revisión W05b1 ordena reutilizar (no reimplementar en el módulo PoT).
pub use zx_poas::reto::{ALEATORIEDAD_BYTES, aleatoriedad_de_salida, reto_desde_salida};

/// Motivo por el que un slot **no se pudo verificar por el contexto**, no por el candidato.
///
/// Ninguno de estos casos es una prueba inválida: el adaptador acepta `N(s)` como argumento libre
/// y no acredita su origen causal, así que un valor fuera de dominio no es un defecto del
/// candidato. El verificador de bloque los trata como `Pendiente` con diagnóstico de contexto,
/// como exige `C-POT-04`.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorContextoPot {
    /// `N(s) == 0`: el trabajo secuencial de un slot debe ser positivo.
    #[error("N(s) = 0: el trabajo de un slot PoT debe ser positivo")]
    IteracionesCero,
    /// `N(s) > u32::MAX`: no cabe en el dominio de la primitiva.
    #[error("N(s) = {valor} excede u32::MAX")]
    IteracionesExcedenU32 {
        /// Valor recibido como argumento.
        valor: u64,
    },
    /// `N(s) % 16 != 0`: la primitiva trabaja en múltiplos de checkpoints por dos.
    #[error("N(s) = {valor} no es múltiplo de 16")]
    IteracionesNoMultiploDe16 {
        /// Valor recibido como argumento.
        valor: u64,
    },
    /// La primitiva rechazó la terna **después** de comprobar el dominio. No debería ocurrir con
    /// `N(s)` ya proyectado; se mantiene como error de contexto para no confundirlo con una prueba
    /// inválida.
    #[error("la primitiva PoT rechazó la terna tras proyectar N(s)")]
    PrimitivaRechazada,
}

/// Proyecta `N(s): u64` al dominio de la primitiva (`C-POT-04`).
///
/// Comprueba cero, rango y múltiplo de 16 **sin `panic` y sin envolver en silencio**.
///
/// # Errores
/// [`ErrorContextoPot`] si `n` está fuera del dominio: cero, mayor que `u32::MAX`, o no múltiplo
/// de 16.
pub fn proyectar_iteraciones(n: u64) -> Result<NonZeroU32, ErrorContextoPot> {
    let acotado =
        u32::try_from(n).map_err(|_| ErrorContextoPot::IteracionesExcedenU32 { valor: n })?;
    if acotado == 0 {
        return Err(ErrorContextoPot::IteracionesCero);
    }
    if !acotado.is_multiple_of(16) {
        return Err(ErrorContextoPot::IteracionesNoMultiploDe16 { valor: n });
    }
    NonZeroU32::new(acotado).ok_or(ErrorContextoPot::IteracionesCero)
}

/// Convierte los ocho valores de 16 B del wire a los checkpoints de la primitiva.
///
/// Es una conversión **explícita, valor a valor y comprobable**: el wire es un `[u8; 128]` opaco
/// y la primitiva un `[PotOutput; 8]`. **No** usa `transmute` ni reinterpreta el contenido.
#[must_use]
pub fn checkpoints_a_primitiva(wire: &PotCheckpointsWire) -> PotCheckpoints {
    let mut checkpoints = PotCheckpoints::default();
    for (destino, fuente) in checkpoints.iter_mut().zip(wire.outputs().iter()) {
        *destino = PotOutput::from(*fuente);
    }
    checkpoints
}

/// Convierte los checkpoints de la primitiva a los 128 B del wire, en el mismo orden.
///
/// Es la vuelta exacta de [`checkpoints_a_primitiva`], también sin `transmute`.
#[must_use]
pub fn checkpoints_a_wire(checkpoints: &PotCheckpoints) -> PotCheckpointsWire {
    let mut outputs = [[0u8; POT_OUTPUT_BYTES]; CHECKPOINTS_POR_BUNDLE];
    for (destino, fuente) in outputs.iter_mut().zip(checkpoints.iter()) {
        *destino = **fuente;
    }
    PotCheckpointsWire::desde_outputs(outputs)
}

/// **Verifica un slot AES** de la primitiva PoT (`C-POT-02`).
///
/// `semilla` y `n` —el `N(s)`— no viajan en los checkpoints del wire, pero llegan como
/// **argumentos libres**: este adaptador no acredita su origen causal. `checkpoints` es lo único
/// que aporta el candidato. Devuelve `Ok(true)` si la cadena AES128 reproduce los ocho
/// checkpoints, `Ok(false)` si no, y `Err` si el contexto está fuera de dominio. **No valida un
/// bloque.**
///
/// # Errores
/// [`ErrorContextoPot`] si `n` está fuera del dominio de [`proyectar_iteraciones`].
pub fn verificar_slot_aes(
    semilla: [u8; POT_OUTPUT_BYTES],
    n: u64,
    checkpoints: &PotCheckpointsWire,
) -> Result<bool, ErrorContextoPot> {
    let iteraciones = proyectar_iteraciones(n)?;
    let primitiva = checkpoints_a_primitiva(checkpoints);
    zx_pot::verify(PotSeed::from(semilla), iteraciones, &primitiva)
        .map_err(|_| ErrorContextoPot::PrimitivaRechazada)
}

// ─────────────────────────────────────────────────────────────────────────────
// Derivaciones puras de semilla (C-POT-01)
// ─────────────────────────────────────────────────────────────────────────────

/// Bytes de la entropía de una inyección (`C-POT-01`).
///
/// Es la entrada de 32 B que el contexto aporta en un slot con inyección. El módulo la recibe como
/// argumento libre: **no acredita** de dónde sale ni que el slot sea el declarado.
pub const ENTROPIA_BYTES: usize = 32;

/// Longitud de la concatenación `entropía ‖ salida_anterior`: 32 + 16 = 48 B (`C-POT-01`).
const ENTRADA_SEMILLA_BYTES: usize = ENTROPIA_BYTES + POT_OUTPUT_BYTES;

/// Deriva la **semilla del slot siguiente** a partir de la salida anterior (`C-POT-01`).
///
/// ```text
/// semilla(f, s) = salida(f, s−1)                                  (sin inyección)
/// semilla(f, s) = blake3(entropía(f, s) ‖ salida(f, s−1))[0..16)  (con inyección)
/// ```
///
/// `entropia = None` representa **cero inyecciones** y devuelve la salida anterior **tal cual**:
/// los mismos 16 bytes, sin pasar por blake3. `entropia = Some(..)` representa **una inyección**
/// (a lo sumo una por llamada): concatena los 32 B de entropía **primero** y los 16 B de la salida
/// después —un buffer explícito de 48 B— y trunca `blake3` a 16 B.
///
/// # Lo que esta función NO acredita
///
/// Es una fórmula **pura de sus argumentos**. No sabe quién decidió inyectar ni en qué slot, y no
/// recibe el slot: `None` o `Some(..)` los elige el llamante con entradas libres.
#[must_use]
pub fn semilla_siguiente(
    salida_anterior: [u8; POT_OUTPUT_BYTES],
    entropia: Option<[u8; ENTROPIA_BYTES]>,
) -> [u8; POT_OUTPUT_BYTES] {
    let Some(entropia) = entropia else {
        return salida_anterior;
    };

    // Concatenación explícita de 48 B: entropía primero, salida después. Sin `unsafe`.
    let mut buffer = [0u8; ENTRADA_SEMILLA_BYTES];
    let (primera, segunda) = buffer.split_at_mut(ENTROPIA_BYTES);
    primera.copy_from_slice(&entropia);
    segunda.copy_from_slice(&salida_anterior);

    let digest = blake3::hash(&buffer);
    let (cabeza, _) = digest.as_bytes().split_at(POT_OUTPUT_BYTES);
    let mut semilla = [0u8; POT_OUTPUT_BYTES];
    semilla.copy_from_slice(cabeza);
    semilla
}

// ─────────────────────────────────────────────────────────────────────────────
// Semilla del génesis (C-FLU-06)
// ─────────────────────────────────────────────────────────────────────────────

/// `semilla(f_0, 0) = blake3( block_hash(T) ‖ entropía_externa )[0..16)` (`C-FLU-06`, D-P09).
///
/// Es el punto de arranque del PoT en el terminal `T`, **distinto** de `f_0`: `f_0` usa `H_flujo`
/// (`C-FLU-10`) y esta semilla usa `blake3`, y las dos rutas **no se uniforman**. El resultado son
/// 16 B, el tamaño de semilla de [`semilla_siguiente`].
///
/// # `entropía_externa` la aporta el llamante
///
/// D-P09 fija `entropía_externa` **vacía en la red dev**. Esta función es **pura**: no escoge bytes
/// de entropía, no ofrece un valor por defecto implícito y **no** acredita que la entropía se
/// hubiera comprometido antes del hash. Tampoco valida `T`. El marcador S1 (A-07) sigue abierto.
#[must_use]
pub fn semilla_genesis(
    block_hash_terminal: &BlockHash,
    entropia_externa: &[u8],
) -> [u8; POT_OUTPUT_BYTES] {
    // `blake3` incremental: `update(block_hash)` y después `update(entropía)` reproducen bit a bit
    // la preimagen `block_hash(génesis) ‖ entropía_externa`, sin buffer proporcional a la entrada.
    let mut hasher = blake3::Hasher::new();
    hasher.update(block_hash_terminal.as_bytes());
    hasher.update(entropia_externa);

    let digest = hasher.finalize();
    let (cabeza, _) = digest.as_bytes().split_at(POT_OUTPUT_BYTES);
    let mut semilla = [0u8; POT_OUTPUT_BYTES];
    semilla.copy_from_slice(cabeza);
    semilla
}
