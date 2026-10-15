//! Puerta **conjunta** de comprobación de una cabecera DAG ya decodificada (SPEC §6.1–§6.2 y
//! §7.1.5, `C-HDR-01`/`C-HDR-03`/`C-HDR-04`/`C-HDR-05`/`C-HDR-06`/`C-HDR-07`/`C-HDR-09` y
//! `C-POT-08`).
//!
//! # Qué es y qué no es
//!
//! [`verificar_cabecera_conjunta`] recorre, en el orden de `C-POT-08`, los pasos que existen por
//! separado: padres contextuales, estructura y flujo del rango PoT, sello ZIP-215, caché y cadena
//! AES con anclaje en `pot_output`, rango contextual y solución PoAS. El **mismo** bloque wire
//! —cabecera y justificación— alimenta todos los pasos.
//!
//! **La respuesta exitosa NO es admisión del nodo.** [`EstadoCabeceraConjunta::Comprobada`] solo
//! significa que las pruebas **locales** se han satisfecho contra los contextos que aporta el
//! llamante. No inserta en GHOSTDAG, no aplica UTXO, no comprueba compromisos del cuerpo, coinbase
//! ni orden DAG, y **no** se llama `validar_bloque`. Los rasgos `InstantaneaPot`, `ContextoDag` y
//! `ContextoRangoDag` siguen admitiendo implementaciones de prueba: no acreditan un `past(B)`
//! causal ni que el controlador de rango exista. Tampoco afirma altura derivada (`C-HDR-02`) ni
//! rama contextual activa (`C-HDR-02b`).
//!
//! # Orden obligatorio
//!
//! 1. Padres y condiciones estructurales (`C-HDR-05`, `C-FLU-02`, `C-GD-03`) por
//!    [`comprobar_padres_contextual`] de `zx-dag` (con D-P08). **Sin** caché ni AES.
//! 2. [`verificar_rango_pot_fase_previa`] (estructura y flujo, `C-POT-08` pasos 1 y 1b).
//! 3. [`zx_core::DagBlockHeader::verificar_sello`] sobre el `pre_hash` canónico (`C-HDR-03`,
//!    `C-HDR-04`). Un sello inválido no consulta la caché ni gasta AES.
//! 4. [`verificar_rango_pot_fase_aes`] con **el mismo** token de la fase previa (`C-POT-07`,
//!    `C-POT-08`): caché contextual, cadena AES y anclaje en `pot_output`.
//! 5. [`RangoSolucionValidado::validar`] (`C-HDR-06`). El `SR` de PoAS es **exclusivamente**
//!    [`RangoSolucionValidado::valor`], atado por construcción a esta cabecera. La **misma**
//!    instancia validada se conserva para pesarla (`w(SR)`, `C-GD-01`/`C-GD-08`).
//! 6. [`zx_poas::verificar_solucion_poas`] (`C-POT-03`, `C-POT-08` paso 5). El contexto de pieza es
//!    obligatorio: `None` es [`MotivoCabeceraPendiente::ContextoPiezaAusente`], nunca un `None`
//!    aguas arriba.
//!
//! # Clasificación de fallos
//!
//! Los motivos conservan el **tipo original** (no se esconden en cadenas). Un fallo del candidato
//! es [`MotivoCabeceraInvalida`]; una falta de contexto o un origen ambiguo es
//! [`MotivoCabeceraPendiente`]. En particular, `PadreNoValidado` y `SlotDePadreAusente` son
//! contexto incompleto; `CabeceraPostSinPadres`, `TerminalConPadresExtra`, `TerminalComoPadreExtra`,
//! `SlotDePadrePosterior`, `PadresNoAnticadena` y `PadreSeleccionadoIncorrecto` son `Invalida`.
//! `ErrorPoas::ContextoInvalido` y `ErrorPoas::Prueba(InvalidHistorySize)` son fallos del
//! **contexto** de pieza: `Pendiente`.

use primitive_types::U256;
use subspace_verification::PieceCheckParams;

use zx_core::wire_dag::BloqueDag;
use zx_core::{
    BlockHash, ClavePublica, DagBlockHeader, EncodingError, POT_OUTPUT_BYTES, PreHash, SolucionPoas,
};
use zx_dag::ErrorDag;
use zx_dag::bloque_dag::{
    ContextoDag, ContextoRangoDag, RangoSolucionValidado, comprobar_padres_contextual,
};
use zx_poas::{ContextoInvalido, ErrorPoas, verificar_solucion_poas};

use crate::pot_rango::{
    CachePotVerificada, EstadoPot, InstantaneaPot, MotivoPotInvalido, MotivoPotPendiente,
    PresupuestoPot, PruebaPotValidada, verificar_rango_pot_fase_aes,
    verificar_rango_pot_fase_previa,
};

/// Resultado de la comprobación conjunta de una cabecera DAG.
///
/// Son **tres** estados distinguibles, en la línea de `C-POT-06`: o se satisfizo todo lo local, o
/// hay un defecto verificable del candidato, o falta contexto. Ninguno convierte un pendiente en
/// válido por defecto.
#[derive(Debug, PartialEq, Eq)]
pub enum EstadoCabeceraConjunta {
    /// Todos los pasos locales terminaron y se conservan los hechos calculados.
    ///
    /// **No es admisión del nodo:** ver [`HechosPost`].
    Comprobada(HechosPost),
    /// Defecto **del candidato**, final y verificable.
    Invalida(MotivoCabeceraInvalida),
    /// Falta de contexto o fracaso de origen ambiguo. Nunca pasa a válido por defecto.
    Pendiente(MotivoCabeceraPendiente),
}

/// Hechos que la puerta conjunta entrega al motor de estado cuando **todos** los pasos locales
/// terminaron (D-P14, §3.3).
///
/// No es un certificado de admisión: acredita que una cabecera concreta superó las comprobaciones
/// contra los contextos recibidos, que pueden ser mocks o tener procedencia falsa. Falta el
/// derivador causal del pasado, la altura/rama derivadas (`C-HDR-02`, `C-HDR-02b`) y la integración
/// con GHOSTDAG, UTXO y cuerpo. Los campos son públicos y de solo lectura por valor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechosPost {
    /// `block_hash` de la cabecera comprobada.
    pub hash: BlockHash,
    /// Padre seleccionado declarado (`prev_hash`), ya validado por la comprobación contextual.
    pub padre_seleccionado: BlockHash,
    /// `slot(B)`, el slot cuyo reto consumió el PoAS (`C-POT-03`).
    pub slot: u64,
    /// Clave que firmó el sello y a la que la coinbase v3 debe pagar (`sol.public_key`).
    pub productor: ClavePublica,
    /// `w(SR)` del rango **validado** (`C-GD-01`/`C-GD-08`), para el `blue_work` de GHOSTDAG.
    pub peso: U256,
    /// Siempre `true` cuando el estado es [`EstadoCabeceraConjunta::Comprobada`]: la prueba existe.
    pub prueba_valida: bool,
    /// `requisito(B)` declarado. En dev es `0` (sin controlador, D-P11/TRN-07); se conserva para
    /// que el motor de estado pueda compararlo con el que derive el pasado.
    pub requisito_declarado: u64,
}

/// Fallo **del candidato** que hace inválida la cabecera.
///
/// Cada variante envuelve el error tipado original. No se codifican motivos en cadenas.
#[derive(Debug, PartialEq, Eq)]
pub enum MotivoCabeceraInvalida {
    /// Fallo estructural de padres (`C-HDR-05`, `C-FLU-02`, `C-GD-03`, D-P08).
    Padres(ErrorDag),
    /// `rango_solucion` distinto del esperado (`C-HDR-06`).
    Rango(ErrorDag),
    /// Sello Ed25519 inválido (`C-HDR-04`).
    Sello(EncodingError),
    /// Defecto verificado del rango PoT (`C-POT-06`).
    Pot(MotivoPotInvalido),
    /// Defecto verificado de la solución PoAS (`C-POT-03`, `C-POT-08` paso 5).
    Poas(ErrorPoas),
    /// **TRN-08 · CONTRATO §1:** un bloque PoST tiene `slot > s_0`. El bloque de transición declara
    /// un `slot` que no progresa respecto del terminal (su `s_0`).
    TransicionSinProgresoDeSlot {
        /// `slot` declarado por el bloque.
        slot: u64,
        /// `s_0`: slot del terminal `T`.
        s0: u64,
    },
}

/// Falta de contexto, o fracaso cuyo origen no puede atribuirse con seguridad al candidato.
///
/// Ninguno de estos casos es una prueba de invalidez: no deben cachearse como rechazo permanente.
#[derive(Debug, PartialEq, Eq)]
pub enum MotivoCabeceraPendiente {
    /// Falta de contexto DAG para comprobar los padres, o error ambiguo de esa comprobación.
    Padres(ErrorDag),
    /// Falta de contexto de rango, o error ambiguo al derivar el rango esperado.
    Rango(ErrorDag),
    /// Falta de contexto PoT (`C-POT-06`).
    Pot(MotivoPotPendiente),
    /// No se aportó contexto de pieza; `C-POT-08` paso 5 no puede ejecutarse.
    ContextoPiezaAusente,
    /// El contexto de pieza no cumple las precondiciones aritméticas de upstream.
    ContextoPieza(ContextoInvalido),
    /// La primitiva upstream devolvió `InvalidHistorySize`: la talla de historia de expiración
    /// depende de `min_sector_lifetime` y del compromiso de expiración que aporta el contexto de
    /// pieza (no acreditado), no de un defecto probado del candidato. Conserva el `ErrorPoas`
    /// original.
    PoasContexto(ErrorPoas),
    /// La prueba PoT devuelta no corresponde a esta cabecera. Por construcción de
    /// [`PruebaPotValidada`] no debería ocurrir; se deja `Pendiente` en vez de declarar invalidez.
    PruebaPotIncoherente,
    /// El rango validado no quedó atado a esta cabecera. Por construcción de
    /// [`RangoSolucionValidado::validar`] no debería ocurrir; se deja `Pendiente`.
    RangoSinAtadura,
}

/// Resultado **privado** del núcleo: la distancia PoAS que [`HechosPost`] no lleva (D3).
///
/// [`verificar_cabecera_conjunta`] la descarta al convertir a [`EstadoCabeceraConjunta`];
/// [`verificar_candidata_para_firma`] la conserva en [`CandidataComprobada`]. No es público.
enum ResultadoNucleo {
    /// Todos los pasos terminaron; `distancia` es la del verificador PoAS real.
    Comprobada {
        /// Mismos hechos que entrega la puerta de bloques recibidos.
        hechos: HechosPost,
        /// Distancia de solución PoAS (`u64` de `verificar_solucion_poas`).
        distancia: u64,
    },
    /// Defecto verificable del candidato.
    Invalida(MotivoCabeceraInvalida),
    /// Falta de contexto u origen ambiguo.
    Pendiente(MotivoCabeceraPendiente),
}

impl ResultadoNucleo {
    /// Proyecta al resultado público de la puerta de bloques recibidos, sin la distancia.
    fn a_estado(self) -> EstadoCabeceraConjunta {
        match self {
            Self::Comprobada { hechos, .. } => EstadoCabeceraConjunta::Comprobada(hechos),
            Self::Invalida(motivo) => EstadoCabeceraConjunta::Invalida(motivo),
            Self::Pendiente(motivo) => EstadoCabeceraConjunta::Pendiente(motivo),
        }
    }
}

/// Clasifica el error de [`comprobar_padres_contextual`] (`C-HDR-05`, `C-FLU-02`, `C-GD-03`,
/// D-P08).
fn clasificar_padres(error: ErrorDag) -> ResultadoNucleo {
    match error {
        e @ (ErrorDag::PadreNoValidado { .. } | ErrorDag::SlotDePadreAusente { .. }) => {
            ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::Padres(e))
        }
        e @ (ErrorDag::CabeceraPostSinPadres
        | ErrorDag::TerminalConPadresExtra { .. }
        | ErrorDag::TerminalComoPadreExtra { .. }
        | ErrorDag::SlotDePadrePosterior { .. }
        | ErrorDag::PadresNoAnticadena { .. }
        | ErrorDag::PadreSeleccionadoIncorrecto { .. }) => {
            ResultadoNucleo::Invalida(MotivoCabeceraInvalida::Padres(e))
        }
        e => ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::Padres(e)),
    }
}

/// Núcleo de la puerta, con costuras de test **privadas** para el sello y el PoAS.
///
/// La función pública [`verificar_cabecera_conjunta`] llama a esta con `cabecera.verificar_sello()`
/// y `zx_poas::verificar_solucion_poas` reales, sin exponer ningún argumento que permita
/// sustituirlos. Los parámetros `sello` y `poas_step` existen solo para que las pruebas internas
/// puedan observar el **orden** con efectos (que un paso no llegue a ejecutarse), no para admitir
/// bloques.
#[expect(
    clippy::too_many_arguments,
    reason = "la puerta encadena contextos y presupuestos explícitos; agruparlos ocultaría la procedencia"
)]
fn comprobar_cabecera_con<C, G, R, P, S, A>(
    bloque: &BloqueDag,
    pot: &C,
    dag: &G,
    rango: &R,
    reloj_pot: u64,
    cache: &mut CachePotVerificada,
    presupuesto: &mut P,
    contexto_pieza: Option<&PieceCheckParams>,
    sello: S,
    poas_step: A,
) -> ResultadoNucleo
where
    C: InstantaneaPot,
    G: ContextoDag,
    R: ContextoRangoDag,
    P: PresupuestoPot,
    S: Fn(&DagBlockHeader) -> Result<(), EncodingError>,
    A: Fn(
        &SolucionPoas,
        u64,
        [u8; POT_OUTPUT_BYTES],
        u64,
        &PieceCheckParams,
    ) -> Result<u64, ErrorPoas>,
{
    let cabecera = &bloque.cabecera;
    let justificacion = &bloque.justificacion;

    // 1 · Padres y estructura (C-HDR-05, C-FLU-02, C-GD-03, D-P08). Sin caché ni AES.
    if let Err(error) = comprobar_padres_contextual(cabecera, dag) {
        return clasificar_padres(error);
    }

    // 1b · TRN-08 · CONTRATO §1: `s_0` es el slot del terminal y todo bloque PoST tiene
    //      `slot > s_0`. Si el padre seleccionado es el terminal, el slot del bloque MUST
    //      progresar respecto de `s_0`; si no, `comprobar_padres_contextual` lo deja pasar con el
    //      mismo slot y `pot_rango` aceptaría una justificación vacía anclada en S1.
    let seleccionado = cabecera.padres.seleccionado();
    if dag.es_terminal(&seleccionado) {
        match dag.slot_de_padre(&seleccionado) {
            Ok(s0) if cabecera.slot <= s0 => {
                return ResultadoNucleo::Invalida(
                    MotivoCabeceraInvalida::TransicionSinProgresoDeSlot {
                        slot: cabecera.slot,
                        s0,
                    },
                );
            }
            Ok(_) => {}
            Err(error) => {
                return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::Padres(error));
            }
        }
    }

    // 2 · Fase previa del rango PoT: estructura y flujo (C-POT-08 pasos 1 y 1b).
    let token = match verificar_rango_pot_fase_previa(cabecera, justificacion, pot) {
        Ok(token) => token,
        Err(EstadoPot::PotInvalido(motivo)) => {
            return ResultadoNucleo::Invalida(MotivoCabeceraInvalida::Pot(motivo));
        }
        Err(EstadoPot::PotPendiente(motivo)) => {
            return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::Pot(motivo));
        }
        // `verificar_rango_pot_fase_previa` documenta que no puede devolver una prueba; si una
        // implementación futura lo hiciera, no se aceptaría aquí.
        Err(EstadoPot::PotValido(_)) => {
            return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::PruebaPotIncoherente);
        }
    };

    // 3 · Sello ZIP-215 sobre `pre_hash` (C-HDR-03, C-HDR-04). No consulta caché ni gasta AES.
    if let Err(error) = sello(cabecera) {
        return ResultadoNucleo::Invalida(MotivoCabeceraInvalida::Sello(error));
    }

    // 4 · Caché contextual, cadena AES y anclaje en `pot_output` (C-POT-07, C-POT-05).
    let prueba: PruebaPotValidada =
        match verificar_rango_pot_fase_aes(token, reloj_pot, cache, presupuesto) {
            EstadoPot::PotValido(prueba) => prueba,
            EstadoPot::PotInvalido(motivo) => {
                return ResultadoNucleo::Invalida(MotivoCabeceraInvalida::Pot(motivo));
            }
            EstadoPot::PotPendiente(motivo) => {
                return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::Pot(motivo));
            }
        };

    // 4b · La prueba tiene que ser de esta cabecera. Por construcción de `PruebaPotValidada` el
    //      `bloque` es el `block_hash` del candidato y el slot auditado es `cabecera.slot`, así que
    //      la discrepancia es imposible; se comprueba igualmente y se declara `Pendiente`.
    if prueba.bloque() != cabecera.block_hash() || prueba.slot_auditado() != cabecera.slot {
        return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::PruebaPotIncoherente);
    }

    // 5 · Rango contextual (C-HDR-06). El esperado sale del contexto; el candidato entra por la
    //     vista opaca `CandidatoSinRango`. La procedencia causal del método sigue pendiente.
    let sr = match RangoSolucionValidado::validar(cabecera, rango) {
        Ok(sr) => sr,
        Err(error @ ErrorDag::RangoIncorrecto { .. }) => {
            return ResultadoNucleo::Invalida(MotivoCabeceraInvalida::Rango(error));
        }
        Err(error) => {
            return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::Rango(error));
        }
    };
    // `validar` ata el rango a esta cabecera; `para_oraculos` no pasa por aquí.
    if sr.bloque() != Some(cabecera.block_hash()) {
        return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::RangoSinAtadura);
    }

    // 6 · Solución PoAS (C-POT-03, C-POT-08 paso 5). Sin contexto de pieza no hay paso 5.
    let Some(pieza) = contexto_pieza else {
        return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::ContextoPiezaAusente);
    };
    // La distancia sale ya en el valor de retorno privado (D3): `HechosPost` no la lleva.
    let distancia = match poas_step(
        &cabecera.sol,
        prueba.slot_auditado(),
        prueba.salida_auditada(),
        sr.valor(),
        pieza,
    ) {
        Ok(distancia) => distancia,
        // Fallo del contexto, no del candidato.
        Err(ErrorPoas::ContextoInvalido(error)) => {
            return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::ContextoPieza(error));
        }
        // `InvalidHistorySize` lo produce `derive_expiration_history_size` al desbordar
        // `min_sector_lifetime + history_size (× 4)`: depende del contexto de pieza que la puerta
        // **no** acredita. Se mapea antes de la rama general `Prueba(_)`.
        Err(error @ ErrorPoas::Prueba(subspace_verification::Error::InvalidHistorySize)) => {
            return ResultadoNucleo::Pendiente(MotivoCabeceraPendiente::PoasContexto(error));
        }
        // Clasificación **condicionada al contexto**, con el `ErrorPoas` original intacto. Una
        // apertura Merkle que no cierra es un defecto verificable del candidato.
        Err(
            error @ (ErrorPoas::EntradaNoCanonica | ErrorPoas::Prueba(_) | ErrorPoas::Merkle(_)),
        ) => {
            return ResultadoNucleo::Invalida(MotivoCabeceraInvalida::Poas(error));
        }
    };

    ResultadoNucleo::Comprobada {
        hechos: HechosPost {
            hash: prueba.bloque(),
            padre_seleccionado: cabecera.padres.seleccionado(),
            slot: prueba.slot_auditado(),
            productor: cabecera.sol.public_key,
            peso: sr.peso(),
            prueba_valida: true,
            requisito_declarado: 0,
        },
        distancia,
    }
}

/// Comprueba conjuntamente una cabecera DAG ya decodificada contra contextos del llamante.
///
/// Recorre el orden de `C-POT-08` descrito en la cabecera del módulo. La cabecera y la
/// justificación se extraen del **mismo** bloque wire.
///
/// # Argumentos
///
/// - `bloque`: bloque DAG completo. Solo se leen `cabecera` y `justificacion`; **no** se comprueban
///   cuerpo, testigos, coinbase ni UTXO.
/// - `pot`: instantánea contextual del pasado para el PoT ([`InstantaneaPot`]).
/// - `dag`: contexto de padres y slots ([`ContextoDag`]).
/// - `rango`: contexto del rango esperado ([`ContextoRangoDag`]). **Precondición no comprobada:** el
///   controlador que deriva `rango_esperado` de `past(B)` y del flujo **no existe** todavía.
/// - `reloj_pot`: reloj PoT del nodo (`C-NET-32`), estado local.
/// - `cache`: caché contextual verificada (`C-POT-07`).
/// - `presupuesto`: presupuesto de CPU inyectado (`C-NET-33`).
/// - `contexto_pieza`: parámetros de pieza del contexto. El `Option` modela **solo** falta de
///   contexto: `None` produce [`MotivoCabeceraPendiente::ContextoPiezaAusente`].
///
/// # Errores clasificados
///
/// Devuelve [`EstadoCabeceraConjunta`]. Los fallos contextuales quedan `Pendiente`; los defectos
/// verificables del candidato quedan `Invalida`.
///
/// # Límites
///
/// El `Ok` **no** es admisión del nodo ni validez global: ver [`HechosPost`]. No se derivan altura
/// ni rama (`C-HDR-02`, `C-HDR-02b`), no se ejecuta GHOSTDAG y no se comprueba el cuerpo.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "la firma declarada encadena los contextos y el presupuesto; agruparlos ocultaría su procedencia"
)]
pub fn verificar_cabecera_conjunta<C, G, R, P>(
    bloque: &BloqueDag,
    pot: &C,
    dag: &G,
    rango: &R,
    reloj_pot: u64,
    cache: &mut CachePotVerificada,
    presupuesto: &mut P,
    contexto_pieza: Option<&PieceCheckParams>,
) -> EstadoCabeceraConjunta
where
    C: InstantaneaPot,
    G: ContextoDag,
    R: ContextoRangoDag,
    P: PresupuestoPot,
{
    comprobar_cabecera_con(
        bloque,
        pot,
        dag,
        rango,
        reloj_pot,
        cache,
        presupuesto,
        contexto_pieza,
        |cabecera| cabecera.verificar_sello(),
        |solucion, slot, salida, sr, pieza| {
            verificar_solucion_poas(solucion, slot, salida, sr, pieza)
        },
    )
    .a_estado()
}

/// Resultado de [`verificar_candidata_para_firma`].
///
/// Reutiliza los dos tipos de motivo de la puerta de bloques recibidos y añade el rechazo
/// [`EstadoCandidata::YaSellada`]. **No son hechos de admisión** y no hay conversión a
/// [`HechosPost`].
#[derive(Debug, PartialEq, Eq)]
pub enum EstadoCandidata {
    /// La candidata sin sello superó **exactamente** las mismas comprobaciones que un bloque
    /// recibido, salvo la del sello.
    Comprobada(CandidataComprobada),
    /// Defecto **del candidato**, final y verificable (misma clasificación que la puerta recibida).
    Invalida(MotivoCabeceraInvalida),
    /// Falta de contexto u origen ambiguo (misma clasificación que la puerta recibida).
    Pendiente(MotivoCabeceraPendiente),
    /// La candidata ya tenía sello distinto de cero: **no** se verifica ni se acepta ninguna
    /// firma.
    YaSellada,
}

/// Comprobación de una candidata **sin sello** para que el nodo valide lo que va a firmar.
///
/// Campos **privados**, sin constructor público: los lectores son [`CandidataComprobada::slot`],
/// [`CandidataComprobada::productor`], [`CandidataComprobada::padre_seleccionado`],
/// [`CandidataComprobada::peso`], [`CandidataComprobada::distancia`] y
/// [`CandidataComprobada::pre_hash`]. **No** lleva `hash` (cambia al sellar, `C-HDR-09`), **no** es
/// [`HechosPost`] y **no** existe conversión a [`HechosPost`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidataComprobada {
    /// `slot(B)` auditado por el PoAS.
    slot: u64,
    /// Clave de la solución PoAS (`sol.public_key`), la que debe firmar.
    productor: ClavePublica,
    /// Padre seleccionado declarado, ya validado.
    padre_seleccionado: BlockHash,
    /// `w(SR)` del rango validado.
    peso: U256,
    /// Distancia del verificador PoAS real (`verificar_solucion_poas`).
    distancia: u64,
    /// Prefirma de la cabecera comprobada: quien firme debe exigir que firma **estos** bytes.
    pre_hash: PreHash,
}

impl CandidataComprobada {
    /// `slot(B)` de la candidata.
    #[must_use]
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Clave que debe firmar (`sol.public_key`).
    #[must_use]
    pub fn productor(&self) -> &ClavePublica {
        &self.productor
    }

    /// Padre seleccionado ya validado.
    #[must_use]
    pub fn padre_seleccionado(&self) -> BlockHash {
        self.padre_seleccionado
    }

    /// Peso del rango validado, `w(SR)`.
    #[must_use]
    pub fn peso(&self) -> U256 {
        self.peso
    }

    /// Distancia que devolvió el verificador PoAS real.
    #[must_use]
    pub fn distancia(&self) -> u64 {
        self.distancia
    }

    /// Prefirma de la cabecera comprobada (C-HDR-03): el mensaje que ha de firmarse.
    #[must_use]
    pub fn pre_hash(&self) -> PreHash {
        self.pre_hash
    }
}

/// Comprueba una **candidata sin sello** con las mismas comprobaciones que un bloque recibido.
///
/// Misma ruta y mismo núcleo privado que [`verificar_cabecera_conjunta`], con el PoAS real. En el
/// paso del sello **exige sello todo ceros**: si no lo es, devuelve
/// [`EstadoCandidata::YaSellada`] **sin verificar ni aceptar ninguna firma**. La puerta de los
/// bloques recibidos no cambia: sigue exigiendo el sello real.
///
/// # Argumentos
///
/// Idénticos a [`verificar_cabecera_conjunta`].
///
/// # Límites
///
/// [`EstadoCandidata::Comprobada`] **no** es admisión ni hechos de admisión: ver
/// [`CandidataComprobada`]. No existe conversión a [`HechosPost`].
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "misma cadena de contextos que la puerta de bloques recibidos; agruparlos ocultaría su procedencia"
)]
pub fn verificar_candidata_para_firma<C, G, R, P>(
    bloque: &BloqueDag,
    pot: &C,
    dag: &G,
    rango: &R,
    reloj_pot: u64,
    cache: &mut CachePotVerificada,
    presupuesto: &mut P,
    contexto_pieza: Option<&PieceCheckParams>,
) -> EstadoCandidata
where
    C: InstantaneaPot,
    G: ContextoDag,
    R: ContextoRangoDag,
    P: PresupuestoPot,
{
    match comprobar_cabecera_con(
        bloque,
        pot,
        dag,
        rango,
        reloj_pot,
        cache,
        presupuesto,
        contexto_pieza,
        |cabecera| {
            // Paso del sello de una candidata: todo ceros o «ya sellada». **Nunca** se llama a
            // `verificar_sello` ni a ninguna verificación de firma.
            if cabecera.sello.iter().all(|&b| b == 0) {
                Ok(())
            } else {
                Err(EncodingError::FirmaInvalida {
                    motivo: "la candidata ya está sellada",
                })
            }
        },
        |solucion, slot, salida, sr, pieza| {
            verificar_solucion_poas(solucion, slot, salida, sr, pieza)
        },
    ) {
        ResultadoNucleo::Comprobada { hechos, distancia } => {
            EstadoCandidata::Comprobada(CandidataComprobada {
                slot: hechos.slot,
                productor: hechos.productor,
                padre_seleccionado: hechos.padre_seleccionado,
                peso: hechos.peso,
                distancia,
                pre_hash: bloque.cabecera.pre_hash(),
            })
        }
        // Único error del paso de sello de esta función: la candidata ya estaba sellada.
        ResultadoNucleo::Invalida(MotivoCabeceraInvalida::Sello(_)) => EstadoCandidata::YaSellada,
        ResultadoNucleo::Invalida(motivo) => EstadoCandidata::Invalida(motivo),
        ResultadoNucleo::Pendiente(motivo) => EstadoCandidata::Pendiente(motivo),
    }
}

#[cfg(test)]
mod pruebas {
    #![expect(
        clippy::expect_used,
        clippy::panic,
        reason = "los tests fallan con panic por diseño"
    )]

    use core::num::NonZeroU32;
    use core::num::NonZeroU64;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    use ed25519_zebra::{SigningKey, VerificationKey};
    use subspace_core_primitives::segments::{HistorySize, SegmentCommitment};
    use subspace_verification::{Error, PieceCheckParams};

    use zx_core::digest::{BodyCommitment, Digest, MerkleRoot};
    use zx_core::wire_dag::{CHECKPOINTS_POR_BUNDLE, JustificacionPot, PotCheckpoints};
    use zx_core::{
        BlockHash, ClavePublica, DagBlockHeader, POT_OUTPUT_BYTES, PadresDag, SolucionPoas,
    };
    use zx_dag::ErrorDag;
    use zx_dag::bloque_dag::{
        CandidatoSinRango, ContextoDag, ContextoRangoDag, RangoSolucionValidado,
    };
    use zx_poas::ErrorPoas;
    use zx_pot::tipos::{PotCheckpoints as PotCheckpointsPrimitiva, PotSeed};

    use super::{
        EstadoCabeceraConjunta, EstadoCandidata, HechosPost, MotivoCabeceraInvalida,
        MotivoCabeceraPendiente, comprobar_cabecera_con, verificar_cabecera_conjunta,
        verificar_candidata_para_firma,
    };
    use crate::pot::semilla_siguiente;
    use crate::pot_rango::{
        BloqueDelPasado, CachePotVerificada, FLUJO_BYTES, InstantaneaPot, InyeccionesPot,
        MotivoPotInvalido, MotivoPotPendiente, PresupuestoPot,
    };

    const FLUJO: [u8; FLUJO_BYTES] = [0x11; FLUJO_BYTES];
    const BASE: [u8; POT_OUTPUT_BYTES] = [0xAB; POT_OUTPUT_BYTES];
    const AUDITADA: [u8; POT_OUTPUT_BYTES] = [0x5A; POT_OUTPUT_BYTES];
    const N: u64 = 16;
    const SLOT_SP: u64 = 100;
    const RETARDO: u64 = 2;
    /// `d = slot(B) − slot(sp) = 1 ≤ D = 2`: la salida auditada la aporta el pasado.
    const SLOT_B: u64 = SLOT_SP + 1;
    /// `slot(sp) + D`: ancla del rango, también en el pasado.
    const SLOT_BASE: u64 = SLOT_SP + RETARDO;
    const RELOJ: u64 = 1_000;

    fn hash_de(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    /// Contexto de prueba que implementa los tres rasgos. **Datos libres, sin procedencia.**
    struct Mundo {
        flujo: [u8; FLUJO_BYTES],
        pasado: Vec<BloqueDelPasado>,
        iteraciones: BTreeMap<u64, u64>,
        retardo: u64,
        salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
        validados: Vec<BlockHash>,
        slots_padre: Vec<(BlockHash, u64)>,
        terminal: BlockHash,
        sp: BlockHash,
        rango_esperado: u64,
    }

    impl InstantaneaPot for Mundo {
        fn flujo_candidato_en(&self, _slot: u64) -> Result<[u8; FLUJO_BYTES], MotivoPotPendiente> {
            Ok(self.flujo)
        }

        fn pasado(&self) -> Result<&[BloqueDelPasado], MotivoPotPendiente> {
            Ok(&self.pasado)
        }

        fn inyecciones_en(&self, _slot: u64) -> Result<InyeccionesPot, MotivoPotPendiente> {
            Ok(InyeccionesPot::Ninguna)
        }

        fn iteraciones(&self, slot: u64) -> Result<u64, MotivoPotPendiente> {
            self.iteraciones
                .get(&slot)
                .copied()
                .ok_or(MotivoPotPendiente::ContextoAusente { que: "N(s)" })
        }

        fn retardo_autoria(&self) -> Result<u64, MotivoPotPendiente> {
            Ok(self.retardo)
        }

        fn salida_validada(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], MotivoPotPendiente> {
            self.salidas
                .get(&slot)
                .copied()
                .ok_or(MotivoPotPendiente::ContextoAusente {
                    que: "salida ancla",
                })
        }
    }

    impl ContextoDag for Mundo {
        fn es_bloque_validado(&self, h: &BlockHash) -> bool {
            self.validados.contains(h)
        }

        fn esta_en_el_pasado_de(
            &self,
            _antepasado: &BlockHash,
            _descendiente: &BlockHash,
        ) -> Result<bool, ErrorDag> {
            Ok(false)
        }

        fn slot_de_padre(&self, h: &BlockHash) -> Result<u64, ErrorDag> {
            if !self.validados.contains(h) {
                return Err(ErrorDag::PadreNoValidado { padre: *h });
            }
            self.slots_padre
                .iter()
                .find_map(|(id, slot)| (id == h).then_some(*slot))
                .ok_or(ErrorDag::SlotDePadreAusente { padre: *h })
        }

        fn padre_seleccionado(&self, _padres: &PadresDag) -> Result<BlockHash, ErrorDag> {
            Ok(self.sp)
        }

        fn es_terminal(&self, h: &BlockHash) -> bool {
            *h == self.terminal
        }
    }

    impl ContextoRangoDag for Mundo {
        fn rango_esperado(&self, _candidato: &CandidatoSinRango<'_>) -> Result<u64, ErrorDag> {
            Ok(self.rango_esperado)
        }
    }

    struct PresupuestoUnit {
        restantes: usize,
        intentos: usize,
    }

    impl PresupuestoUnit {
        fn nuevo(restantes: usize) -> Self {
            Self {
                restantes,
                intentos: 0,
            }
        }
    }

    impl PresupuestoPot for PresupuestoUnit {
        fn consumir_slot(&mut self, _slot: u64) -> bool {
            self.intentos += 1;
            if self.restantes == 0 {
                false
            } else {
                self.restantes -= 1;
                true
            }
        }
    }

    /// Contexto de pieza con aritmética válida. Solo lo usan las espías de PoAS; el verificador
    /// real no se llama en las pruebas internas.
    fn pieza_dummy() -> PieceCheckParams {
        let h = |n: u64| HistorySize::from(NonZeroU64::new(n).expect("n > 0"));
        PieceCheckParams {
            max_pieces_in_sector: 1,
            segment_commitment: SegmentCommitment::default(),
            recent_segments: h(1),
            recent_history_fraction: (h(1), h(1)),
            min_sector_lifetime: h(1),
            current_history_size: h(1),
            sector_expiration_check_segment_commitment: None,
        }
    }

    /// Reproduce la conversión wire↔primitiva **sin** llamar a `pot::checkpoints_a_wire`, para no
    /// dar por alcanzado ese punto público como uso de producción.
    fn a_wire(carrier: &PotCheckpointsPrimitiva) -> PotCheckpoints {
        let mut outputs = [[0u8; POT_OUTPUT_BYTES]; CHECKPOINTS_POR_BUNDLE];
        for (destino, fuente) in outputs.iter_mut().zip(carrier.iter()) {
            *destino = **fuente;
        }
        PotCheckpoints::desde_outputs(outputs)
    }

    fn cabecera(
        slot: u64,
        pot_output: [u8; POT_OUTPUT_BYTES],
        sp: BlockHash,
        extras: &[BlockHash],
    ) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xc478_80ea,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
            timestamp: 1_788_480_000,
            height: 0,
            slot,
            pot_output,
            rango_solucion: 5,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
            padres: PadresDag::nuevo(sp, extras).expect("padres canónicos"),
            sello: [0u8; 64],
        }
    }

    /// Escenario PoT/AES válido: `d = 1 ≤ D = 2`, un portador real en `SLOT_BASE + 1`.
    fn escenario() -> (DagBlockHeader, JustificacionPot, Mundo) {
        let semilla = semilla_siguiente(BASE, None);
        let carrier = zx_pot::prove(
            PotSeed::from(semilla),
            NonZeroU32::new(u32::try_from(N).expect("N cabe en u32")).expect("N > 0"),
        )
        .expect("N múltiplo de 16");
        let portador = a_wire(&carrier);
        let pot_output = *carrier.output();

        let sp = hash_de(0x01);
        let extra = hash_de(0x02);
        let cabecera = cabecera(SLOT_B, pot_output, sp, &[extra]);
        let justificacion = JustificacionPot::nueva(vec![portador]).expect("un portador");

        let mut salidas = BTreeMap::new();
        salidas.insert(SLOT_BASE, BASE);
        salidas.insert(SLOT_B, AUDITADA);
        let mut iteraciones = BTreeMap::new();
        iteraciones.insert(SLOT_BASE + 1, N);

        let mundo = Mundo {
            flujo: FLUJO,
            pasado: vec![
                BloqueDelPasado {
                    hash: sp,
                    slot: SLOT_SP,
                    timestamp: 0,
                    flujo: FLUJO,
                },
                BloqueDelPasado {
                    hash: extra,
                    slot: SLOT_SP,
                    timestamp: 0,
                    flujo: FLUJO,
                },
            ],
            iteraciones,
            retardo: RETARDO,
            salidas,
            validados: vec![sp, extra],
            slots_padre: vec![(sp, SLOT_SP), (extra, SLOT_SP)],
            terminal: hash_de(0xEE),
            sp,
            rango_esperado: 5,
        };
        (cabecera, justificacion, mundo)
    }

    fn bloque(cabecera: DagBlockHeader, justificacion: JustificacionPot) -> zx_core::BloqueDag {
        zx_core::BloqueDag::nuevo(cabecera, justificacion, Vec::new(), Vec::new())
            .expect("bloque sin cuerpo")
    }

    fn firmar(cabecera: &mut DagBlockHeader, sk: &SigningKey) {
        let vk = VerificationKey::from(sk);
        cabecera.sol.public_key = ClavePublica::desde_bytes(vk.into());
        let pre = cabecera.pre_hash();
        cabecera.sello = sk.sign(pre.as_bytes()).into();
    }

    /// Sello espía que acierta; solo observa el orden.
    fn sello_ok(_cabecera: &DagBlockHeader) -> Result<(), zx_core::EncodingError> {
        Ok(())
    }

    #[test]
    fn padres_invalidos_no_llaman_sello_ni_tocan_presupuesto() {
        let (_cabecera_valida, justificacion, mundo) = escenario();
        // Cabecera con cero padres: D-P08 la rechaza siempre, aunque el contexto declare terminal.
        let mut impostora = cabecera(1, [0u8; POT_OUTPUT_BYTES], hash_de(0xEE), &[]);
        impostora.padres = PadresDag::genesis();
        let impostora = bloque(impostora, justificacion);

        let sello_llamado = Cell::new(false);
        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &impostora,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            |_c| {
                sello_llamado.set(true);
                Ok(())
            },
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();

        assert_eq!(
            estado,
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Padres(
                ErrorDag::CabeceraPostSinPadres
            ))
        );
        assert!(!sello_llamado.get(), "el sello no debe alcanzarse");
        assert!(!poas_llamado.get(), "el PoAS no debe alcanzarse");
        assert_eq!(presupuesto.intentos, 0, "no se gasta AES");
    }

    #[test]
    fn flujo_discrepante_no_llama_sello_ni_toca_presupuesto() {
        let (cabecera, justificacion, mut mundo) = escenario();
        if let Some(primero) = mundo.pasado.first_mut() {
            primero.flujo = [0x22; FLUJO_BYTES];
        }
        let bloque = bloque(cabecera, justificacion);

        let sello_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            |_c| {
                sello_llamado.set(true);
                Ok(())
            },
            |_sol, _slot, _salida, _sr, _pieza| Ok(0),
        )
        .a_estado();

        match estado {
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
                MotivoPotInvalido::FlujoDePasadoDiscrepa { .. },
            )) => {}
            otro => panic!("se esperaba flujo discrepante, llegó {otro:?}"),
        }
        assert!(!sello_llamado.get(), "el sello no debe alcanzarse");
        assert_eq!(presupuesto.intentos, 0, "la fase previa no gasta AES");
    }

    #[test]
    fn sello_invalido_tras_la_fase_previa_no_toca_cache_ni_presupuesto() {
        let (cabecera, justificacion, mundo) = escenario();
        let bloque = bloque(cabecera, justificacion);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            |_c| {
                Err(zx_core::EncodingError::FirmaInvalida {
                    motivo: "sello inválido de prueba",
                })
            },
            |_sol, _slot, _salida, _sr, _pieza| Ok(0),
        )
        .a_estado();

        match estado {
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_)) => {}
            otro => panic!("se esperaba sello inválido, llegó {otro:?}"),
        }
        assert_eq!(presupuesto.intentos, 0, "el sello no gasta AES");

        // Si la caché estuviera tocada, un intento posterior con presupuesto cero acertaría.
        let mut presupuesto_cero = PresupuestoUnit::nuevo(0);
        let segundo = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto_cero,
            Some(&pieza_dummy()),
            sello_ok,
            |_sol, _slot, _salida, _sr, _pieza| Ok(0),
        )
        .a_estado();
        assert_eq!(
            segundo,
            EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::Pot(
                MotivoPotPendiente::PresupuestoAgotado {
                    slot: SLOT_BASE + 1
                }
            )),
            "la caché no debe haberse llenado con el sello inválido"
        );
        assert_eq!(presupuesto_cero.intentos, 1);
    }

    #[test]
    fn pot_invalido_no_invoca_poas() {
        let (mut cabecera, justificacion, mundo) = escenario();
        cabecera.pot_output = [0u8; POT_OUTPUT_BYTES];
        let bloque = bloque(cabecera, justificacion);

        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_ok,
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();

        match estado {
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
                MotivoPotInvalido::PotOutputNoCoincide { .. },
            )) => {}
            otro => panic!("se esperaba anclaje incorrecto, llegó {otro:?}"),
        }
        assert!(!poas_llamado.get(), "el PoAS no debe ejecutarse");
    }

    #[test]
    fn pot_pendiente_no_invoca_poas() {
        let (cabecera, justificacion, mundo) = escenario();
        let bloque = bloque(cabecera, justificacion);

        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        // Reloj por detrás del último slot del rango: se retiene.
        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            SLOT_B,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_ok,
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();

        match estado {
            EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::Pot(
                MotivoPotPendiente::RelojFuturo { .. },
            )) => {}
            otro => panic!("se esperaba reloj futuro, llegó {otro:?}"),
        }
        assert!(!poas_llamado.get(), "el PoAS no debe ejecutarse");
        assert_eq!(presupuesto.intentos, 0, "el reloj no gasta AES");
    }

    #[test]
    fn contexto_de_pieza_ausente_es_pendiente_y_no_invoca_poas() {
        let (cabecera, justificacion, mundo) = escenario();
        let bloque = bloque(cabecera, justificacion);

        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            None,
            sello_ok,
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();

        assert_eq!(
            estado,
            EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::ContextoPiezaAusente)
        );
        assert!(!poas_llamado.get(), "sin contexto de pieza no hay paso 5");
        assert_eq!(
            presupuesto.intentos, 1,
            "el rango AES real sí se ejecuta antes"
        );
    }

    /// Ruta **instrumentada**: la espía de PoAS devuelve una distancia. No es la función pública.
    #[test]
    fn la_espia_de_poas_ok_registra_los_hechos_solo_al_final() {
        let (cabecera, justificacion, mundo) = escenario();
        let esperado = cabecera.block_hash();
        let productor = cabecera.sol.public_key;
        let padre = cabecera.padres.seleccionado();
        let bloque = bloque(cabecera, justificacion);
        // El `SR` esperado sale del mismo contexto: reproduce la precondición de C-HDR-06.
        let sr_esperado = RangoSolucionValidado::validar(&bloque.cabecera, &mundo)
            .expect("el contexto coincide con lo declarado");
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_ok,
            |_sol, slot, salida, sr, _pieza| {
                assert_eq!(slot, SLOT_B);
                assert_eq!(salida, AUDITADA);
                assert_eq!(sr, sr_esperado.valor());
                Ok(42)
            },
        )
        .a_estado();

        match estado {
            EstadoCabeceraConjunta::Comprobada(c) => {
                let esperado_hechos = HechosPost {
                    hash: esperado,
                    padre_seleccionado: padre,
                    slot: SLOT_B,
                    productor,
                    peso: sr_esperado.peso(),
                    prueba_valida: true,
                    requisito_declarado: 0,
                };
                assert_eq!(c, esperado_hechos);
                assert_eq!(c.hash, esperado);
                assert_eq!(c.slot, SLOT_B);
                assert_eq!(c.peso, sr_esperado.peso());
                assert!(c.prueba_valida);
                assert_eq!(c.requisito_declarado, 0);
            }
            otro => panic!("se esperaba comprobación, llegó {otro:?}"),
        }
    }

    /// Fallo 1 · `InvalidHistorySize` de upstream depende del contexto de pieza.
    #[test]
    fn invalid_history_size_de_upstream_es_pendiente_y_conserva_la_causa() {
        let (cabecera, justificacion, mundo) = escenario();
        let bloque = bloque(cabecera, justificacion);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_ok,
            |_sol, _slot, _salida, _sr, _pieza| Err(ErrorPoas::Prueba(Error::InvalidHistorySize)),
        )
        .a_estado();

        assert_eq!(
            estado,
            EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::PoasContexto(
                ErrorPoas::Prueba(Error::InvalidHistorySize)
            ))
        );
    }

    /// La función **pública** llama al sello real y al PoAS real: con un sello auténtico se llega
    /// hasta el paso 6 y, sin contexto de pieza, el estado es `Pendiente`.
    #[test]
    fn la_funcion_publica_usa_el_sello_real_y_termina_pendiente_sin_pieza() {
        let (mut cabecera, justificacion, mundo) = escenario();
        let sk = SigningKey::from([7u8; 32]);
        firmar(&mut cabecera, &sk);
        assert!(
            cabecera.verificar_sello().is_ok(),
            "la cabecera está firmada"
        );
        let bloque = bloque(cabecera, justificacion);

        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);
        let estado = verificar_cabecera_conjunta(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            None,
        );

        assert_eq!(
            estado,
            EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::ContextoPiezaAusente)
        );
        assert_eq!(presupuesto.intentos, 1, "se ejecutó un AES real");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIRC-1 · pruebas de orden de la candidata para firma (D1–D4, P3–P4)
    // ─────────────────────────────────────────────────────────────────────────

    /// Paso del sello de la candidata: todo ceros o error, **sin** verificar firma (D1).
    fn sello_candidata(cabecera: &DagBlockHeader) -> Result<(), zx_core::EncodingError> {
        if cabecera.sello.iter().all(|&b| b == 0) {
            Ok(())
        } else {
            Err(zx_core::EncodingError::FirmaInvalida {
                motivo: "la candidata ya está sellada",
            })
        }
    }

    #[test]
    fn candidata_ya_sellada_no_llama_verificacion_de_firma() {
        let (mut cabecera, justificacion, mundo) = escenario();
        let sk = SigningKey::from([9u8; 32]);
        firmar(&mut cabecera, &sk);
        assert!(cabecera.sello.iter().any(|&b| b != 0), "sello real");
        let bloque = bloque(cabecera, justificacion);

        // Espía de verificación de firma: **nadie** debe llamarla. El paso de sello de la
        // candidata es `sello_candidata` (solo comprueba ceros); si llegara a invocar
        // `verificar_sello`, la espía lo registraría.
        let firma_verificada = Cell::new(false);
        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);

        let estado = comprobar_cabecera_con(
            &bloque,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            |c| {
                // Ruta de producción de la candidata: solo ceros, sin verificar firmas.
                if c.sello.iter().all(|&b| b == 0) {
                    Ok(())
                } else {
                    Err(zx_core::EncodingError::FirmaInvalida {
                        motivo: "la candidata ya está sellada",
                    })
                }
            },
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();

        match estado {
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_)) => {}
            otro => panic!("se esperaba rechazo de sello, llegó {otro:?}"),
        }
        assert!(
            !firma_verificada.get(),
            "la candidata ya sellada no verifica ninguna firma"
        );
        assert!(!poas_llamado.get(), "tampoco alcanza el PoAS");
        assert_eq!(presupuesto.intentos, 0, "no gasta AES");

        // La espía de la función pública: un sello **válido** también se rechaza como
        // «ya sellada». Si la función verificara la firma, el sello válido pasaría el paso 3.
        let mut sellada_valida = bloque;
        // (el bloque ya llevaba sello real del `firmar` de arriba)
        sellada_valida.cabecera.sello = sk
            .sign(sellada_valida.cabecera.pre_hash().as_bytes())
            .into();
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);
        let estado = verificar_candidata_para_firma(
            &sellada_valida,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
        );
        assert_eq!(
            estado,
            EstadoCandidata::YaSellada,
            "un sello válido no se verifica: se rechaza como ya sellada"
        );
    }

    #[test]
    fn la_funcion_de_candidata_rechaza_sello_valido_y_de_basura_como_ya_sellada() {
        let (mut cabecera, justificacion, mundo) = escenario();
        let sk = SigningKey::from([3u8; 32]);
        firmar(&mut cabecera, &sk);
        let sellada_valida = bloque(cabecera, justificacion.clone());

        let mut basura = cabecera;
        basura.sello = [0xAA; 64];
        let sellada_basura = bloque(basura, justificacion);

        for (etiqueta, b) in [
            ("sello válido", &sellada_valida),
            ("sello de basura", &sellada_basura),
        ] {
            let mut cache = CachePotVerificada::nueva();
            let mut presupuesto = PresupuestoUnit::nuevo(1_000);
            let estado = verificar_candidata_para_firma(
                b,
                &mundo,
                &mundo,
                &mundo,
                RELOJ,
                &mut cache,
                &mut presupuesto,
                Some(&pieza_dummy()),
            );
            assert_eq!(
                estado,
                EstadoCandidata::YaSellada,
                "{etiqueta}: la función nueva la rechaza como ya sellada"
            );
            assert_eq!(
                presupuesto.intentos, 0,
                "{etiqueta}: no debe alcanzar la fase AES"
            );
        }
    }

    #[test]
    fn candidata_sin_sello_sigue_el_mismo_orden_que_el_bloque_recibido() {
        // Padres inválidos: no alcanzan la fase previa del PoT ni el presupuesto.
        let (_cabecera_valida, justificacion, mundo) = escenario();
        let mut impostora_h = cabecera(1, [0u8; POT_OUTPUT_BYTES], hash_de(0xEE), &[]);
        impostora_h.padres = PadresDag::genesis();
        let impostora = bloque(impostora_h, justificacion);
        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);
        let estado = comprobar_cabecera_con(
            &impostora,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_candidata,
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();
        assert_eq!(
            estado,
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Padres(
                ErrorDag::CabeceraPostSinPadres
            ))
        );
        assert!(!poas_llamado.get());
        assert_eq!(presupuesto.intentos, 0, "padres inválidos no gasta AES");

        // Flujo discrepante: no toca caché ni presupuesto.
        let (cabecera_h, justificacion, mut mundo) = escenario();
        if let Some(primero) = mundo.pasado.first_mut() {
            primero.flujo = [0x22; FLUJO_BYTES];
        }
        let b = bloque(cabecera_h, justificacion);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);
        let estado = comprobar_cabecera_con(
            &b,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_candidata,
            |_sol, _slot, _salida, _sr, _pieza| Ok(0),
        )
        .a_estado();
        match estado {
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
                MotivoPotInvalido::FlujoDePasadoDiscrepa { .. },
            )) => {}
            otro => panic!("se esperaba flujo discrepante, llegó {otro:?}"),
        }
        assert_eq!(presupuesto.intentos, 0, "flujo discrepante no gasta AES");

        // PoT inválido: no invoca el PoAS.
        let (mut cabecera_h, justificacion, mundo) = escenario();
        cabecera_h.pot_output = [0u8; POT_OUTPUT_BYTES];
        let b = bloque(cabecera_h, justificacion);
        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);
        let estado = comprobar_cabecera_con(
            &b,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_candidata,
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();
        match estado {
            EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
                MotivoPotInvalido::PotOutputNoCoincide { .. },
            )) => {}
            otro => panic!("se esperaba anclaje incorrecto, llegó {otro:?}"),
        }
        assert!(!poas_llamado.get(), "PoT inválido no invoca el PoAS");

        // PoT pendiente: no invoca el PoAS.
        let (cabecera_h, justificacion, mundo) = escenario();
        let b = bloque(cabecera_h, justificacion);
        let poas_llamado = Cell::new(false);
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);
        let estado = comprobar_cabecera_con(
            &b,
            &mundo,
            &mundo,
            &mundo,
            SLOT_B,
            &mut cache,
            &mut presupuesto,
            Some(&pieza_dummy()),
            sello_candidata,
            |_sol, _slot, _salida, _sr, _pieza| {
                poas_llamado.set(true);
                Ok(0)
            },
        )
        .a_estado();
        match estado {
            EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::Pot(
                MotivoPotPendiente::RelojFuturo { .. },
            )) => {}
            otro => panic!("se esperaba reloj futuro, llegó {otro:?}"),
        }
        assert!(!poas_llamado.get(), "PoT pendiente no invoca el PoAS");
    }

    #[test]
    fn la_funcion_de_candidata_con_sello_cero_y_sin_pieza_es_pendiente() {
        let (mut cabecera_h, justificacion, mundo) = escenario();
        let sk = SigningKey::from([7u8; 32]);
        firmar(&mut cabecera_h, &sk);
        // La candidata que se firmó: la misma prefirma con el sello a cero.
        cabecera_h.sello = [0u8; 64];
        let b = bloque(cabecera_h, justificacion);

        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit::nuevo(1_000);
        let estado = verificar_candidata_para_firma(
            &b,
            &mundo,
            &mundo,
            &mundo,
            RELOJ,
            &mut cache,
            &mut presupuesto,
            None,
        );
        assert_eq!(
            estado,
            EstadoCandidata::Pendiente(MotivoCabeceraPendiente::ContextoPiezaAusente)
        );
    }
}
