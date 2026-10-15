//! Verificación de una `SolucionPoas` de ZEROX con las primitivas públicas de Autonomys y con el
//! árbol de Merkle transparente de `zx-merkle` (B-21, PT-2a-2).
//!
//! # Qué cubre
//!
//! Cubre el **paso 5 de `C-POT-08`**: cuando el PoT del **slot auditado** (`C-POT-03`), el slot, el
//! rango y el contexto de pieza ya vienen **validados por el pasado**, comprueba la prueba de
//! espacio, la distancia de solución y las **dos aperturas de pertenencia Merkle**
//! (chunk↔registro y registro↔segmento).
//!
//! Sustituye a `subspace_verification::verify_solution` (que es `#[cfg(feature = "kzg")]`): la
//! lógica no-KZG de upstream se reproduce aquí —PoS con `ChiaTable`, distancia con
//! `bidirectional_distance`, `history_size`/`piece_offset`/expiración y `derive_piece_index`— y los
//! dos `kzg.verify` se sustituyen por [`zx_merkle::verificar_solucion`]. **No se cambia ninguna otra
//! regla.**
//!
//! # Qué NO es
//!
//! **No valida un bloque completo.** Los pasos 1–4 de `C-POT-08` (estructura, flujo, caché y AES
//! secuencial), el sello, la cabecera y la validez absoluta siguen pendientes y corresponden a
//! otras piezas. En particular, esta función no deriva el flujo ni comprueba el pasado: recibe el
//! resultado ya acreditado como argumento.
//!
//! # El contexto de pieza no es opcional
//!
//! La firma recibe `&PieceCheckParams`, **no** `Option<...>`. El `None` de upstream **omite** la
//! comprobación de inclusión de la pieza en la historia; esta adaptación comprueba siempre el
//! contexto. La raíz Merkle de segmento viaja en los **primeros 32 B** de su
//! `segment_commitment` (los 16 restantes a cero); ver [`crate::raiz_de_segment_commitment`].
//!
//! # Frontera de confianza
//!
//! `slot`, `salida_pot_verificada`, `rango_validado` y `contexto_pieza` son argumentos del
//! **contexto ya validado**, nunca valores elegidos a partir de `solucion`. El llamante es
//! responsable de su procedencia; esta función no la acredita.
//!
//! `salida_pot_verificada` es la salida del **slot auditado** que `C-POT-03` usa para derivar el
//! reto, **no** el `pot_output` de la cabecera: ése es la salida **futura**
//! `salida(f, slot(B) + D)` de `C-POT-05`, anclada en otro slot, y no sirve para auditar la PoS de
//! éste.
//!
//! # Procedencia
//!
//! Dependencias enlazadas por `path` al clon fijado `terceros/autonomys` @ `f8842d0`. No se
//! copia ni se reimplementa PoS, la máscara del chunk ni la distancia; **sí** se reimplementa la
//! comprobación de pertenencia, que pasa de KZG a Merkle (`zx-merkle`).

use std::num::NonZeroU64;

use subspace_core_primitives::PublicKey;
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash_with_key};
use subspace_core_primitives::pieces::PieceOffset;
use subspace_core_primitives::pos::PosProof;
use subspace_core_primitives::pot::PotOutput;
use subspace_core_primitives::sectors::{SectorId, SectorSlotChallenge};
use subspace_core_primitives::segments::{ArchivedHistorySegment, HistorySize};
use subspace_core_primitives::solutions::{
    SolutionPotVerifier, SolutionRange, bidirectional_distance,
};
use subspace_proof_of_space::chia::ChiaTable;
use subspace_verification::PieceCheckParams;
use zx_core::SolucionPoas;
use zx_merkle::{
    CompromisoRegistro, CompromisoSegmento, ErrorMerkle, TestigoChunk, TestigoRegistro,
    TestigoSolucion,
};

use crate::historia::raiz_de_segment_commitment;

/// Piezas de un segmento de historia archivada.
///
/// Es `ArchivedHistorySegment::NUM_PIECES` del clon fijado (`128 × 2 / 1 = 256`). Se toma la
/// constante del crate, no se escribe a mano.
const PIEZAS_POR_SEGMENTO: u64 = ArchivedHistorySegment::NUM_PIECES as u64;

/// Motivo por el que el contexto de pieza no es aritméticamente representable en upstream.
///
/// Son precondiciones que `PieceCheckParams` **no** garantiza por tipo. No son topes de consenso:
/// solo verifican que las operaciones `+ 1`, `*` y `-` de `subspace-verification/src/lib.rs` y
/// `subspace-core-primitives/src/sectors.rs` no desborden ni resten en negativo con el contexto y
/// la solución recibidos.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContextoInvalido {
    /// `current_history_size + 1` (upstream, `verify_solution`) desbordaría `u64`.
    #[error("current_history_size = u64::MAX: la suma `+ 1` de upstream desborda")]
    CurrentHistorySizeSinMargen,
    /// `recent_segments.in_pieces()` (upstream) saturaría al multiplicar por
    /// `ArchivedHistorySegment::NUM_PIECES`.
    #[error("recent_segments = {0} no cabe en piezas sin saturar u64")]
    RecentSegmentsEnPiezas(u64),
    /// Un miembro de `recent_history_fraction` no cabe en piezas sin saturar.
    #[error("recent_history_fraction.{miembro} = {segmentos} no cabe en piezas sin saturar u64")]
    FraccionEnPiezas {
        /// `"0"` (divisor) o `"1"` (multiplicador) del par de la fracción.
        miembro: &'static str,
        /// Talla recibida, en segmentos.
        segmentos: u64,
    },
    /// `recent_segments_in_pieces * recent_history_fraction.1.in_pieces()` desborda `u64`.
    #[error(
        "recent_segments ({reciente_piezas} piezas) × fracción ({multiplicador} piezas) desborda u64"
    )]
    UmbralRecienteDesborda {
        /// `recent_segments` ya en piezas.
        reciente_piezas: u64,
        /// `recent_history_fraction.1` ya en piezas.
        multiplicador: u64,
    },
    /// `max_pieces_in_sector * recent_history_fraction.0.in_pieces() ... * 2` desborda `u64`.
    #[error("las piezas intercaladas del sector desbordan u64")]
    PiezasIntercaladasDesbordan {
        /// `max_pieces_in_sector` del contexto.
        max_pieces_in_sector: u16,
        /// `recent_history_fraction.0` ya en piezas.
        divisor_piezas: u64,
    },
    /// La rama reciente de upstream restaría en negativo: solo se informa cuando la condición
    /// exacta de upstream ejecuta la resta `history_size_in_pieces - recent_segments_in_pieces`.
    #[error("la rama reciente restaría {historia_piezas} − {reciente_piezas} piezas de historia")]
    RestaRecienteNegativa {
        /// `history_size` del candidato ya en piezas.
        historia_piezas: u64,
        /// `recent_segments` del contexto ya en piezas.
        reciente_piezas: u64,
    },
}

/// Error al verificar una `SolucionPoas` con la primitiva de Autonomys y `zx-merkle`.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ErrorPoas {
    /// La solución no se puede convertir a la representación de upstream, o una magnitud del
    /// candidato no es representable en la aritmética de upstream.
    ///
    /// Cubre `history_size = 0` (upstream usa `NonZeroU64`) y una `history_size` cuyo paso a piezas
    /// desborda `u64` (`HistorySize::in_pieces` satura y la saturación no se acepta como dato). No
    /// se redondea ni se sustituye por 1: la entrada es inválida y se informa como tal, sin
    /// `panic`.
    #[error("entrada no canónica: la solución no es representable por la primitiva upstream")]
    EntradaNoCanonica,
    /// El contexto de pieza no cumple las precondiciones aritméticas de upstream.
    ///
    /// Es un fallo **del contexto**, distinto de una prueba inválida del candidato.
    #[error("contexto de pieza inválido: {0}")]
    ContextoInvalido(ContextoInvalido),
    /// La primitiva de Autonomys rechazó la prueba de espacio, la distancia o del contexto.
    ///
    /// Conserva el error concreto de `subspace_verification` como fuente, sin transformarlo en
    /// `Ok` ni en un booleano.
    #[error("la solución PoAS no verifica: {0}")]
    Prueba(#[source] subspace_verification::Error),
    /// El árbol de Merkle rechazó una apertura: la prueba de pertenencia no cierra contra su
    /// compromiso (o la primitiva rechazó la longitud/índice).
    #[error("la pertenencia Merkle de la solución no verifica: {0}")]
    Merkle(#[source] ErrorMerkle),
}

/// Convierte segmentos a piezas **sin** aceptar la saturación de `HistorySize::in_pieces`.
///
/// `in_pieces` multiplica con `saturating_mul`, así que un valor saturado no distingue «cabe» de
/// «no cabe». Se reproduce aquí la multiplicación original con [`u64::checked_mul`]: `None`
/// significa que el dato no es representable como piezas.
fn a_piezas(size: HistorySize) -> Option<u64> {
    size.get().checked_mul(PIEZAS_POR_SEGMENTO)
}

/// Comprueba que la aritmética de upstream no desborda ni resta en negativo con este contexto y
/// esta solución (ver la cabecera del módulo).
///
/// Reproduce los operandos de `subspace-verification/src/lib.rs` y de
/// `SectorId::derive_piece_index`; **no** calcula el índice de pieza. Las divisiones usan
/// [`u64::div_euclid`] para dejar explícito que son la división entera exacta de upstream.
fn comprobar_aritmetica_contexto(
    solucion: &SolucionPoas,
    contexto: &PieceCheckParams,
) -> Result<(), ErrorPoas> {
    // `subspace-verification/src/lib.rs`: `current_history_size + 1`, sin comprobar.
    if contexto.current_history_size.get().checked_add(1).is_none() {
        return Err(ErrorPoas::ContextoInvalido(
            ContextoInvalido::CurrentHistorySizeSinMargen,
        ));
    }

    // `HistorySize::in_pieces` satura: comprobar la multiplicación original de cada talla.
    let reciente = a_piezas(contexto.recent_segments).ok_or(ErrorPoas::ContextoInvalido(
        ContextoInvalido::RecentSegmentsEnPiezas(contexto.recent_segments.get()),
    ))?;
    let (fraccion_divisor, fraccion_multiplicador) = contexto.recent_history_fraction;
    let divisor = a_piezas(fraccion_divisor).ok_or(ErrorPoas::ContextoInvalido(
        ContextoInvalido::FraccionEnPiezas {
            miembro: "0",
            segmentos: fraccion_divisor.get(),
        },
    ))?;
    let multiplicador = a_piezas(fraccion_multiplicador).ok_or(ErrorPoas::ContextoInvalido(
        ContextoInvalido::FraccionEnPiezas {
            miembro: "1",
            segmentos: fraccion_multiplicador.get(),
        },
    ))?;

    // `derive_piece_index`: `recent_segments_in_pieces * frac.1 / frac.0`.
    let umbral_reciente =
        reciente
            .checked_mul(multiplicador)
            .ok_or(ErrorPoas::ContextoInvalido(
                ContextoInvalido::UmbralRecienteDesborda {
                    reciente_piezas: reciente,
                    multiplicador,
                },
            ))?;
    // `divisor` procede de un `HistorySize` no nulo y no saturado: es `>= 256`, nunca cero.
    let min_historia = umbral_reciente.div_euclid(divisor);

    // `derive_piece_index`: `max_pieces_in_sector * frac.0 / frac.1 * 2`, de izquierda a derecha.
    let intercaladas_brutas = u64::from(contexto.max_pieces_in_sector)
        .checked_mul(divisor)
        .ok_or(ErrorPoas::ContextoInvalido(
            ContextoInvalido::PiezasIntercaladasDesbordan {
                max_pieces_in_sector: contexto.max_pieces_in_sector,
                divisor_piezas: divisor,
            },
        ))?;
    let num_intercaladas = intercaladas_brutas
        .div_euclid(multiplicador)
        .checked_mul(2)
        .ok_or(ErrorPoas::ContextoInvalido(
            ContextoInvalido::PiezasIntercaladasDesbordan {
                max_pieces_in_sector: contexto.max_pieces_in_sector,
                divisor_piezas: divisor,
            },
        ))?
        .max(1);

    // La talla de historia del candidato también pasa por `in_pieces` en upstream; si su
    // multiplicación original no cabe, la entrada no es canónica.
    let historia = solucion
        .history_size
        .checked_mul(PIEZAS_POR_SEGMENTO)
        .ok_or(ErrorPoas::EntradaNoCanonica)?;

    // Resta exacta de la rama reciente de upstream, y **solo** bajo sus tres condiciones. El
    // fixture válido (`recent_segments = 5 > history_size = 3`) no entra y sigue aceptándose.
    let offset = u64::from(solucion.piece_offset);
    if historia > min_historia
        && offset < num_intercaladas
        && solucion.piece_offset % 2 == 1
        && historia < reciente
    {
        return Err(ErrorPoas::ContextoInvalido(
            ContextoInvalido::RestaRecienteNegativa {
                historia_piezas: historia,
                reciente_piezas: reciente,
            },
        ));
    }

    Ok(())
}

/// Extrae la distancia de solución de un hash de 32 B: los primeros 8 B little-endian.
///
/// Se copian byte a byte para no usar indexación con rangos (prohibida por los lints del
/// workspace) ni `expect`/`unwrap`.
fn primeros_ocho(bytes: &[u8; 32]) -> SolutionRange {
    let mut arr = [0u8; 8];
    for (destino, origen) in arr.iter_mut().zip(bytes.iter()) {
        *destino = *origen;
    }
    SolutionRange::from_le_bytes(arr)
}

/// `calculate_solution_distance` de `subspace-verification`: hash con clave del chunk auditado y
/// distancia bidireccional contra el reto global.
fn calcular_distancia(
    global_challenge: &Blake3Hash,
    chunk: &[u8; 32],
    sector_slot_challenge: &SectorSlotChallenge,
) -> SolutionRange {
    let audit_chunk = blake3_hash_with_key(sector_slot_challenge, chunk);
    let audit = primeros_ocho(&audit_chunk);
    let global = primeros_ocho(global_challenge);
    bidirectional_distance(&global, &audit)
}

/// Verifica una `SolucionPoas` contra el contexto ya validado (paso 5 de `C-POT-08`).
///
/// Reproduce la lógica no-KZG de `subspace_verification::verify_solution` y cierra con las dos
/// aperturas Merkle de `zx-merkle`. Devuelve la **distancia de solución** (`<= rango_validado / 2`)
/// que upstream calcula. No es la entrada de peso de `C-GD-01`/`C-GD-08`: ésas usan el
/// `rango_validado`. `solution_distance` es el criterio de desempate de `C-GD-03` —y por tanto la
/// segunda clave del orden de `C-GD-05`— cuando dos bloques empatan en `blue_work`.
///
/// # Argumentos
///
/// - `solucion`: solución PoAS del bloque candidato.
/// - `slot`: índice de PoT del bloque, **del contexto**.
/// - `salida_pot_verificada`: salida de 16 B del **slot auditado** (`C-POT-03`), **del contexto**;
///   no es el `pot_output` futuro de la cabecera (`C-POT-05`).
/// - `rango_validado`: rango de solución **del contexto**, nunca el declarado por el candidato.
/// - `contexto_pieza`: parámetros de pieza **del contexto**; obligatorio. Su raíz Merkle de
///   segmento viaja en los 32 primeros bytes de `segment_commitment`.
///
/// # Errores
///
/// [`ErrorPoas::EntradaNoCanonica`] si la conversión falla o una talla del candidato no es
/// representable, [`ErrorPoas::ContextoInvalido`] si el contexto desborda la aritmética de
/// upstream, [`ErrorPoas::Prueba`] con el error concreto de la primitiva y [`ErrorPoas::Merkle`]
/// si una apertura de pertenencia no cierra.
pub fn verificar_solucion_poas(
    solucion: &SolucionPoas,
    slot: u64,
    salida_pot_verificada: [u8; 16],
    rango_validado: u64,
    contexto_pieza: &PieceCheckParams,
) -> Result<u64, ErrorPoas> {
    comprobar_aritmetica_contexto(solucion, contexto_pieza)?;

    let history_size = HistorySize::new(
        NonZeroU64::new(solucion.history_size).ok_or(ErrorPoas::EntradaNoCanonica)?,
    );
    let public_key = PublicKey::from(*solucion.public_key.bytes());
    let sector_id = SectorId::new(public_key.hash(), solucion.sector_index, history_size);

    let proof_of_time = PotOutput::from(salida_pot_verificada);
    let global_randomness = proof_of_time.derive_global_randomness();
    let global_challenge = global_randomness.derive_global_challenge(slot);
    let sector_slot_challenge = sector_id.derive_sector_slot_challenge(&global_challenge);
    let s_bucket_audit_index = sector_slot_challenge.s_bucket_audit_index();

    let proof_of_space = PosProof::from(solucion.proof_of_space);
    if !<ChiaTable as SolutionPotVerifier>::is_proof_valid(
        &sector_id.derive_evaluation_seed(PieceOffset::from(solucion.piece_offset)),
        u32::from(s_bucket_audit_index),
        &proof_of_space,
    ) {
        return Err(ErrorPoas::Prueba(
            subspace_verification::Error::InvalidProofOfSpace,
        ));
    }

    // Máscara `chunk ⊕ hash(proof_of_space)`, la misma de upstream.
    let mut masked_chunk = solucion.chunk;
    let chunk_hash: [u8; 32] = *proof_of_space.hash();
    for (byte, hash) in masked_chunk.iter_mut().zip(chunk_hash.iter()) {
        *byte ^= *hash;
    }

    let solution_distance =
        calcular_distancia(&global_challenge, &masked_chunk, &sector_slot_challenge);
    let mitad_rango = rango_validado.div_euclid(2);
    if solution_distance > mitad_rango {
        return Err(ErrorPoas::Prueba(
            subspace_verification::Error::OutsideSolutionRange {
                half_solution_range: mitad_rango,
                solution_distance,
            },
        ));
    }

    // Mismas comprobaciones de contexto que upstream (`piece_check_params` obligatorio).
    let PieceCheckParams {
        max_pieces_in_sector,
        segment_commitment,
        recent_segments,
        recent_history_fraction,
        min_sector_lifetime,
        current_history_size,
        sector_expiration_check_segment_commitment,
    } = contexto_pieza;

    if solucion.history_size > current_history_size.get() + 1 {
        return Err(ErrorPoas::Prueba(
            subspace_verification::Error::FutureHistorySize {
                current: *current_history_size,
                solution: history_size,
            },
        ));
    }

    if solucion.piece_offset >= *max_pieces_in_sector {
        return Err(ErrorPoas::Prueba(
            subspace_verification::Error::InvalidPieceOffset {
                piece_offset: solucion.piece_offset,
                max_pieces_in_sector: *max_pieces_in_sector,
            },
        ));
    }

    if let Some(compromiso_expiracion) = sector_expiration_check_segment_commitment {
        match sector_id.derive_expiration_history_size(
            history_size,
            compromiso_expiracion,
            *min_sector_lifetime,
        ) {
            Some(expiration_history_size) if expiration_history_size <= *current_history_size => {
                return Err(ErrorPoas::Prueba(
                    subspace_verification::Error::SectorExpired {
                        expiration_history_size,
                        current_history_size: *current_history_size,
                    },
                ));
            }
            Some(_) => {}
            None => {
                return Err(ErrorPoas::Prueba(
                    subspace_verification::Error::InvalidHistorySize,
                ));
            }
        }
    }

    let position = sector_id
        .derive_piece_index(
            PieceOffset::from(solucion.piece_offset),
            history_size,
            *max_pieces_in_sector,
            *recent_segments,
            *recent_history_fraction,
        )
        .position();

    let testigo = TestigoSolucion {
        chunk: TestigoChunk(solucion.chunk_witness),
        registro: TestigoRegistro(solucion.record_witness),
    };
    let compromiso_registro = CompromisoRegistro(solucion.record_commitment);
    let compromiso_segmento = CompromisoSegmento(raiz_de_segment_commitment(segment_commitment));

    zx_merkle::verificar_solucion(
        &testigo,
        &solucion.chunk,
        &solucion.record_commitment,
        u32::from(s_bucket_audit_index),
        position,
        &compromiso_registro,
        &compromiso_segmento,
    )
    .map_err(ErrorPoas::Merkle)?;

    Ok(solution_distance)
}
