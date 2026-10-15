//! Conversión local de candidatos de disco a soluciones PoAS verificadas (D2, tramo parcial).
//!
//! # Alcance: conversión local, no productor activo
//!
//! Este módulo es **solo** la conversión `candidato de D1 → solución de Autonomys → verificación
//! de A1`. **No** es el productor de bloques del destino y no debe llamarse «productor activo»:
//!
//! - no elige padres del DAG ni baraja su cola de candidatos (SPEC §11, política de producción);
//! - no aplica el filtro de profundidad de fusión ni la kosherización (SPEC §11, *bounded merge
//!   depth*, con sus cinco valores `<<PENDIENTE>>`);
//! - no arranca desde génesis (SPEC §15.1, bootstrap pendiente);
//! - no ensambla cuerpo, cabecera, prefirma ni sello (`C-HDR-03`/`C-HDR-09`);
//! - no deriva el `pot_output` futuro de la cabecera (`C-POT-05`), que es la salida de otro slot;
//! - no firma, no admite en red y no publica.
//!
//! El contrato completo de D2 exige congelar el **snapshot causal** del pasado DAG validado
//! *antes* de derivar la salida de slot, el rango y el contexto de pieza. Esta función recibe ese
//! lote ya construido y **no acredita su procedencia**: igual que
//! [`zx_poas::verificar_solucion_poas`], confía en quien la llama. En particular, no
//! acepta datos de una cabecera candidata como contexto validado.
//!
//! # Qué significa «comprobada»
//!
//! [`SolucionComprobadaLocal`] afirma solo que la solución verificó **contra las entradas
//! proporcionadas** —el mismo `slot`, la misma `salida_slot`, el mismo `rango_validado` y el mismo
//! `contexto_pieza`— con la primitiva pública de Autonomys. No es validez global del bloque, no es
//! validez absoluta (`C-POT-08` paso 5 es una parte) y no autoriza publicación.
//!
//! # Reglas citadas
//!
//! - `C-POT-03`: el reto del slot auditado se deriva de la salida de ese slot; D1 ya lo aplica y
//!   esta función no lo rederiva.
//! - `C-POT-05`: la salida auditada **no** es el `pot_output` futuro de la cabecera.
//! - `C-POT-08` paso 5: con el PoT, el slot, el rango y el contexto de pieza ya validados, se
//!   comprueba la prueba de espacio, la distancia y los dos compromisos KZG.
//! - `C-HDR-03`/`C-HDR-09`: layout, prefirma, sello y hash de cabecera; fuera de este tramo. La
//!   selección de padres, el filtro de profundidad de fusión (SPEC §11) y el bootstrap del génesis
//!   (SPEC §15.1) quedan igualmente fuera y siguen pendientes.
//!
//! # Contadores
//!
//! Los contadores de [`DiagnosticoLocal`] son de diagnóstico **local** de esta conversión. **No**
//! son las métricas F1–F3 de la 0.0.1 ni métricas de red, y no deben presentarse como tales. No se
//! deriva de la distancia ningún peso GHOSTDAG: el peso es otra magnitud (`C-GD-01`/`C-GD-08`).

use std::num::NonZeroU64;

use subspace_core_primitives::pot::PotOutput;
use subspace_core_primitives::sectors::SectorId;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::proving::ProvingError;
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_verification::PieceCheckParams;
use thiserror::Error;
use zx_core::{ClavePublica, SolucionPoas};
use zx_merkle::ErrorMerkle;
use zx_poas::{ErrorPoas, HistoriaGenesis, verificar_solucion_poas};

use crate::farmer::{ErrorFarmer, ParcelaDisco, TablaCacheada};

/// Error de la conversión local de candidatos a soluciones verificadas.
///
/// Distingue el fallo de la auditoría/parcela, el fallo de la conversión de candidatos
/// (`into_solutions` y sus lecturas) y el fallo del contexto de pieza. Un **rechazo de A1**
/// (`ErrorPoas::Prueba` distinto de `InvalidHistorySize`) **no** es un error de esta API: se
/// descarta y se cuenta en [`DiagnosticoLocal::rechazos_a1`], sin atribuir causa. Un candidato que
/// no produce solución no es error.
#[derive(Debug, Error)]
pub enum ErrorProductorPoas {
    /// Fallo al auditar la parcela o al leer sus archivos.
    #[error("auditoría de parcela: {0}")]
    Farmer(#[from] ErrorFarmer),
    /// Fallo al convertir los candidatos en soluciones: E/S, decodificación del mapa de sector,
    /// polinomio o testigo. Se propaga; no se confunde con «sin solución».
    #[error("conversión de candidatos a soluciones: {0}")]
    Proving(#[from] ProvingError),
    /// Fallo al construir o consultar el árbol Merkle de la historia (`zx-merkle`).
    #[error("árbol Merkle de la historia: {0}")]
    Merkl(#[from] ErrorMerkle),
    /// El contexto de pieza no es representable o la solución generada no lo es, incluido
    /// `ErrorPoas::Prueba(InvalidHistorySize)`, que nace de la expiración de sector y depende del
    /// contexto de pieza. Es un fallo **del contexto o de la conversión**, no del candidato. El
    /// resto de `ErrorPoas::Prueba` se descarta y se cuenta como rechazo de A1, sin atribución de
    /// causa.
    #[error("contexto de pieza no representable: {0}")]
    Contexto(#[from] ErrorPoas),
}

/// Diagnóstico local de una conversión de candidatos.
///
/// Son contadores de esta llamada, no métricas F1–F3 ni de red. Cada campo es el recuento
/// acumulado sobre todas las auditorías de sector devueltas por D1 para ese slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiagnosticoLocal {
    /// Candidatos de chunk vistos por la auditoría (`SolutionCandidates::len()`), antes de
    /// descartar los que no están codificados.
    pub candidatos: usize,
    /// Soluciones que `into_solutions` produjo (iterador recorrido con `Ok(Solution<()>)`).
    pub soluciones_generadas: usize,
    /// Soluciones generadas que A1 rechazó con `ErrorPoas::Prueba`, **sin** que este contador
    /// acredite la causa.
    ///
    /// Un rechazo **no** prueba un falso positivo del auditor A1: `ErrorPoas::Prueba` también
    /// procede de un `PieceCheckParams` inyectado incompatible (`FutureHistorySize`,
    /// `InvalidPieceOffset`, `SectorExpired`, `InvalidPiece`, …). Todos los rechazos con contexto
    /// ajeno pueden ocultar un fallo de integración causal, y esta función **no acredita la
    /// procedencia del contexto**. `InvalidHistorySize` no se cuenta aquí: se propaga por
    /// [`ErrorProductorPoas::Contexto`].
    pub rechazos_a1: usize,
    /// Soluciones que pasaron A1 y se devolvieron, con su distancia.
    pub soluciones_verificadas: usize,
    /// W08e (solo diagnóstico): tiempo de `ParcelaDisco::auditar_candidatos` en nanosegundos.
    ///
    /// Es el coste de derivar el reto y auditar el plot (lectura de la parcela), **antes** de la
    /// conversión. No forma parte de ninguna decisión.
    pub ns_auditoria: u64,
    /// W08e (solo diagnóstico): tiempo del bucle `into_solutions` + verificación A1, en
    /// nanosegundos. Es el coste de la conversión (tabla PoSpace + testigo KZG) y de A1.
    pub ns_conversion: u64,
}

/// Solución PoAS verificada **contra las entradas proporcionadas**.
///
/// Los campos son privados a propósito: no se puede construir una instancia sin pasar por la
/// verificación de esta API. [`Self::solucion`] y [`Self::distancia`] exponen lo comprobado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolucionComprobadaLocal {
    solucion: SolucionPoas,
    distancia: u64,
}

impl SolucionComprobadaLocal {
    /// La solución PoAS verificada.
    #[must_use]
    pub fn solucion(&self) -> &SolucionPoas {
        &self.solucion
    }

    /// Distancia de solución que devolvió A1 (`<= rango_validado / 2`).
    ///
    /// No es peso GHOSTDAG: es el criterio de desempate de `C-GD-03`/`C-GD-05`.
    #[must_use]
    pub fn distancia(&self) -> u64 {
        self.distancia
    }
}

/// Resultado de convertir los candidatos de un slot en soluciones verificadas.
#[derive(Debug, Default)]
pub struct ResultadoConversionLocal {
    soluciones: Vec<SolucionComprobadaLocal>,
    diagnostico: DiagnosticoLocal,
}

impl ResultadoConversionLocal {
    /// Las soluciones que pasaron A1, en el orden en que se generaron.
    #[must_use]
    pub fn soluciones(&self) -> &[SolucionComprobadaLocal] {
        &self.soluciones
    }

    /// El diagnóstico local de la conversión.
    #[must_use]
    pub fn diagnostico(&self) -> DiagnosticoLocal {
        self.diagnostico
    }
}

/// Convierte los candidatos de disco de `slot` en soluciones verificadas por A1.
///
/// # Procedimiento
///
/// 1. Llama a [`ParcelaDisco::auditar_candidatos`] con `salida_slot`, `slot` y `rango_validado`, y
///    **conserva los préstamos de la parcela y de su descriptor** durante toda la conversión.
/// 2. Por cada `AuditResult`, consume sus `solution_candidates` con
///    `SolutionCandidates::into_solutions::<(), ChiaTable, _>` en modo
///    [`ReadSectorRecordChunksMode::ConcurrentChunks`], con el `ErasureCoding` recibido y un
///    generador **paralelo** de tablas (`ChiaTable::generator()` + `generate_parallel`). No se usa
///    la ruta no paralela de `ab-proof-of-space`.
/// 3. Convierte cada `Solution<()>` a [`SolucionPoas`] sustituyendo el testigo del clon fijado por
///    el testigo **Merkle** (`zx-merkle`) construido desde `historia`, y llama a
///    [`verificar_solucion_poas`] con **el mismo** `slot`, `salida_slot`, `rango_validado` y
///    `contexto_pieza`. Solo se devuelven los pares que pasaron A1.
///
/// W08e: la función **corta en la primera solución verificada** (`break` del bucle de auditorías).
/// Para producir un bloque basta una solución por `(clave, slot)`, y los candidatos vienen
/// ordenados por distancia, de modo que la conservada es la de **menor** distancia. Esto evita
/// generar la tabla PoSpace y el testigo KZG de los candidatos restantes; no cambia la verificación
/// de la solución devuelta (se verifica A1 en el mismo punto).
///
/// Un candidato que no produce solución no es error. Un rechazo de A1 (`ErrorPoas::Prueba`
/// distinto de `InvalidHistorySize`) se descarta y se cuenta en
/// [`DiagnosticoLocal::rechazos_a1`], sin atribuir causa. Un fallo de E/S, de `into_solutions`,
/// de un elemento del iterador, de aritmética del contexto o de conversión no representable
/// **se propaga como error**, nunca se convierte en «sin solución». `InvalidHistorySize` se
/// propaga por [`ErrorProductorPoas::Contexto`].
///
/// # Límites
///
/// `salida_slot`, `slot`, `rango_validado` y `contexto_pieza` son el lote coherente que debe
/// inyectar un futuro snapshot causal del pasado DAG validado. Esta función **no acredita esa
/// procedencia** y no acepta datos de una cabecera candidata como contexto. No elige padres, no
/// firma y no publica.
///
/// # Errores
///
/// [`ErrorProductorPoas::Farmer`] si falla la auditoría, [`ErrorProductorPoas::Proving`] si falla
/// la conversión de candidatos y [`ErrorProductorPoas::Contexto`] si el contexto, una solución
/// generada o la expiración de sector (`InvalidHistorySize`) no son representables.
// `Se permite el número de argumentos`: la firma mantiene separadas las piezas del contexto
// inyectado (salida, slot, rango, parámetros de pieza) de las instancias de la red (historia y
// erasure coding); agruparlas ocultaría que ninguna se fabrica aquí.
#[allow(clippy::too_many_arguments)]
pub fn convertir_candidatos_locales(
    parcela: &ParcelaDisco,
    salida_slot: [u8; 16],
    slot: u64,
    rango_validado: u64,
    contexto_pieza: &PieceCheckParams,
    historia: &HistoriaGenesis,
    erasure_coding: &ErasureCoding,
) -> Result<ResultadoConversionLocal, ErrorProductorPoas> {
    // `auditorias` retiene los préstamos de `&ParcelaDisco` y del descriptor `File` de la parcela
    // durante toda la conversión: `into_solutions` lee de ese mismo descriptor.
    // W08e (solo diagnóstico): separar auditoría (deriva el reto y lee el plot) de conversión
    // (tabla PoSpace + testigo Merkle + A1).
    let inicio_auditoria = std::time::Instant::now();
    let auditorias = parcela.auditar_candidatos(salida_slot, slot, rango_validado)?;
    let ns_auditoria = inicio_auditoria.elapsed().as_nanos() as u64;

    // Vive fuera del bucle para que su préstamo cubra la conversión de cada auditoría.
    let recompensa = ();

    let mut diagnostico = DiagnosticoLocal::default();
    let mut verificadas = Vec::new();

    let inicio_conversion = std::time::Instant::now();
    'auditorias: for auditoria in auditorias {
        let candidatos = auditoria.solution_candidates;
        diagnostico.candidatos += candidatos.len();

        // W08e: la tabla PoSpace no depende del reto, así que se toma del caché de la parcela
        // (`tabla_pos_cacheada`) en vez de regenerarla en cada candidato. `into_solutions` se
        // conserva solo para obtener `proof_of_space` y `piece_offset` del candidato: la ruta de
        // ploteo es del clon fijado y exige un KZG por firma, pero el **testigo de pertenencia no
        // es el suyo**: se construye con `zx-merkle` a partir de la historia canónica (PT-2a-2).
        let generadas = candidatos.into_solutions::<(), TablaCacheada, _>(
            &recompensa,
            crate::farmer::kzg_de_ploteo(),
            erasure_coding,
            ReadSectorRecordChunksMode::ConcurrentChunks,
            move |seed| parcela.tabla_pos_cacheada(seed),
        )?;

        for generada in generadas {
            let solucion_upstream = generada?;
            diagnostico.soluciones_generadas += 1;

            // s-bucket y posición del reto: exactamente los que comprobará A1.
            let proof_of_time = PotOutput::from(salida_slot);
            let global_randomness = proof_of_time.derive_global_randomness();
            let global_challenge = global_randomness.derive_global_challenge(slot);
            let sector_id = SectorId::new(
                solucion_upstream.public_key.hash(),
                solucion_upstream.sector_index,
                solucion_upstream.history_size,
            );
            let sector_slot_challenge = sector_id.derive_sector_slot_challenge(&global_challenge);
            let s_bucket = u32::from(sector_slot_challenge.s_bucket_audit_index());
            let position = sector_id
                .derive_piece_index(
                    solucion_upstream.piece_offset,
                    solucion_upstream.history_size,
                    contexto_pieza.max_pieces_in_sector,
                    contexto_pieza.recent_segments,
                    contexto_pieza.recent_history_fraction,
                )
                .position();

            // Chunk canónico, raíz de registro y camino chunk→registro desde la historia; camino
            // registro→segmento desde su árbol cacheado.
            let (chunk, raiz, camino_chunk) = historia.chunk_raiz_y_camino(position, s_bucket)?;
            let camino_registro = historia.camino_registro(position)?;
            let solucion = SolucionPoas {
                public_key: ClavePublica::desde_bytes(*solucion_upstream.public_key),
                sector_index: solucion_upstream.sector_index,
                history_size: NonZeroU64::from(solucion_upstream.history_size).get(),
                piece_offset: solucion_upstream.piece_offset.into(),
                record_commitment: raiz.0,
                record_witness: camino_registro.0,
                chunk,
                chunk_witness: camino_chunk.0,
                proof_of_space: *solucion_upstream.proof_of_space,
            };

            match verificar_solucion_poas(
                &solucion,
                slot,
                salida_slot,
                rango_validado,
                contexto_pieza,
            ) {
                Ok(distancia) => {
                    diagnostico.soluciones_verificadas += 1;
                    verificadas.push(SolucionComprobadaLocal {
                        solucion,
                        distancia,
                    });
                    // W08e (reducción del lado productor): con **una** solución verificada por
                    // `(clave, slot)` basta para producir el bloque. `into_solutions` es perezoso y
                    // genera la tabla PoSpace y el testigo KZG en cada `next()`; cortar aquí evita
                    // el trabajo de los candidatos restantes. Los `WinningChunk` vienen ordenados
                    // por `solution_distance` (`auditing.rs:268`), así que el primero es el de
                    // **menor** distancia, el mismo criterio que prioriza el farmer de Autonomys.
                    // No cambia qué se verifica: la solución devuelta se acaba de verificar con A1
                    // aquí mismo.
                    break 'auditorias;
                }
                // `InvalidHistorySize` nace de `derive_expiration_history_size`, que depende de
                // `min_sector_lifetime` y del compromiso de expiración que aporta
                // `PieceCheckParams`. Es un fallo del contexto de pieza (misma clasificación que
                // `zx_poas`), no un rechazo ordinario del candidato: se
                // propaga conservando el motivo upstream, sin contarlo ni convertirlo en conjunto
                // vacío.
                Err(
                    error @ ErrorPoas::Prueba(subspace_verification::Error::InvalidHistorySize),
                ) => {
                    return Err(ErrorProductorPoas::Contexto(error));
                }
                // Rechazo de A1 con el contexto recibido. Se descarta y se cuenta, sin atribuir
                // causa: no prueba un falso positivo del auditor y, con contexto ajeno, puede
                // ocultar un fallo de integración causal. Una apertura Merkle que no cierra es un
                // rechazo del candidato, no un fallo del contexto.
                Err(ErrorPoas::Prueba(_) | ErrorPoas::Merkle(_)) => {
                    diagnostico.rechazos_a1 += 1;
                }
                // Contexto o representación: es un error, no un «sin solución».
                Err(error) => return Err(ErrorProductorPoas::Contexto(error)),
            }
        }
    }

    // W08e (solo diagnóstico): la conversión cubre `into_solutions` (tabla PoSpace y testigo KZG
    // del clon fijado), la construcción del testigo Merkle y la verificación A1 de cada solución.
    diagnostico.ns_auditoria = ns_auditoria;
    diagnostico.ns_conversion = inicio_conversion.elapsed().as_nanos() as u64;

    Ok(ResultadoConversionLocal {
        soluciones: verificadas,
        diagnostico,
    })
}
