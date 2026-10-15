//! Fase PoST en régimen: hilo productor (decisión 3, 5 y 6; «Relanzamiento» punto 3).
//!
//! **W08g (arquitectura vigente):** la PoT vive en un hilo propio
//! ([`zx_post::publicador_pot::Timelord`]) que avanza el `ServicioPot` **sin esperar nunca a la
//! producción** y publica cada salida por un canal. Este hilo productor consume esas salidas, las
//! inserta en su **propio** `ServicioPot` con `insertar_calculado` (sin recalcular el AES) y audita,
//! convierte y produce en paralelo por clave. Si una solución no llega a tiempo para su slot, se
//! descarta; el reloj del nodo no se frena (decisiones 1 y 2 de `ORDEN-W08g`). Hasta W08e ambos iban
//! en el mismo hilo y cada producción alargaba el slot de pared del propio nodo (la causa medida en
//! `REVISION-W08e.md`).
//!
//! El bucle de consenso sigue siendo el único dueño de `zx-cadena`/`zx-storage`: este hilo solo
//! **pide** los padres canónicos (los calcula `zx-cadena` con el GHOSTDAG real) y **entrega**
//! bloques ya producidos para que el bucle los verifique y admita. Mantiene su **propia** copia
//! independiente de `ServicioPot`, arrancada del mismo terminal y el mismo `N_dev`: como el PoT es
//! una función determinista de `(terminal, N_dev)`, esta copia y la que usa el bucle para verificar
//! calculan exactamente las mismas salidas, sin compartir memoria ni bloquearse mutuamente.
//!
//! # Protocolo numerado (`ORDEN-W06d8`)
//!
//! Bajo cambio de terminal en caliente (`ORDEN-SL4b2` decisión 0) el bucle puede haber contestado ya
//! una petición que el hilo **abandonó** al recibir [`MsgBucle::CambiarTerminal`]; esa respuesta
//! atrasada llegaba después, donde el hilo esperaba otra cosa, y lo tiraba con un `panic!`
//! (`regimen.rs:438`, hallazgo de W07b). El protocolo ahora **numera** cada mensaje del hilo
//! (`PeticionPadres`, `Candidata`) con un `id: u64` creciente y el bucle devuelve ese `id`
//! en su respuesta (`Padres`, `Continuar`). Al esperar la respuesta `n`, el hilo:
//!
//! - **descarta** toda respuesta con `id < n` (es de una petición que ya abandonó) y escribe el
//!   evento de diagnóstico `productor_respuesta_descartada` con ambos `id`;
//! - atiende `Parar` **siempre**, sea cual sea el `id` pendiente;
//! - trata `id > n` (respuesta de una petición futura, imposible si el bucle responde en orden) como
//!   violación de invariante: envía [`MsgProductor::Fallo`] y termina **sin pánico**.
//!
//! [`MsgBucle::CambiarTerminal`] se sigue absorbiendo en el punto de espera, como antes.
//!
//! # Sin pánicos alcanzables
//!
//! Este módulo no usa `panic!`/`unreachable!`/`unwrap`/`expect`: cualquier fallo que el hilo no pueda
//! resolver (PoT que no avanza, padre ajeno sin información, producción que devuelve un error que no
//! es `SlotNoProgreso`, …) se convierte en [`MsgProductor::Fallo`], y el bucle lo traduce en el
//! evento crítico `fallo_productor` más una salida ≠ 0 (decisión 3 de `ORDEN-W06d8`). Nunca queda un
//! nodo que valida pero ha dejado de producir sin decirlo.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::time::{Duration, Instant};

use zx_core::wire_dag::{BloqueDag, POT_OUTPUT_BYTES};
use zx_core::{BlockHash, ClavePublica, PadresDag, Tx};
use zx_farmer::farmer::ParcelaDisco;
use zx_farmer::productor_poas::convertir_candidatos_locales;
use zx_poas::HistoriaGenesis;
use zx_post::productor::{FuenteSoluciones, ParametrosProductor, SolucionCandidata};
use zx_post::productor_regimen::{
    CuerpoProductor, ErrorRegimen, preparar_regimen_con_clave_publica,
};
use zx_post::publicador_pot::{ReceptorSalidas, SalidaPublicada, Timelord};
use zx_post::servicio_pot::{ErrorServicioPot, ServicioPot};

use crate::registro::Registro;

/// Mensajes que el hilo productor envía al bucle.
pub enum MsgProductor {
    /// Pide los padres canónicos actuales de un bloque de régimen, para el `slot` dado (decisión 4
    /// de `ORDEN-SL4b2`: el bucle necesita el slot objetivo para filtrar qué evidencias pendientes
    /// tienen la ventana abierta en el bloque que se va a construir). `id` numera la petición: la
    /// respuesta debe traerlo de vuelta.
    PeticionPadres {
        /// Identificador creciente de la petición.
        id: u64,
        /// Slot objetivo del bloque que se va a construir.
        slot: u64,
    },
    /// PROD-3b: una candidata PoST **sin sello** para que el bucle la compruebe, depure, ensaye,
    /// firme y admita. El hilo ya no firma. `id` numera el envío: la respuesta
    /// (`Continuar`/`Parar`) debe traerlo de vuelta. El `hash` del bloque sellado nace en el
    /// bucle; el hilo lo aprende después por el camino de «padre ajeno» al pedir padres.
    Candidata {
        /// Identificador creciente del envío.
        id: u64,
        /// Candidata sin sello (sello a cero).
        candidata: Box<BloqueDag>,
        /// Instante en que se obtuvo la salida PoT del slot (`retraso_slot_ns`).
        instante_salida: Instant,
        /// W08c (solo diagnóstico): índice de la clave dev que armó la candidata.
        clave_indice: u32,
    },
    /// VNT-R1 · el hilo PoT verificó en local la salida del `slot`, aunque no hubiera ninguna
    /// candidata ganadora. No es un bloque ni exige respuesta: el bucle solo lo usa para avanzar el
    /// cursor de votos y atender las fronteras de ventana. `flujo` identifica el terminal PoT del
    /// servicio del hilo (una salida de otro flujo se descarta). VNT-1b · D3: `n` es el `N` del
    /// calendario que el hilo tenía por vigente **para ese slot**; el bucle lo contrasta con su
    /// propio `ServicioPot` antes de mover el cursor.
    FronteraPot {
        /// Terminal/identidad del flujo PoT del hilo.
        flujo: BlockHash,
        /// Slot cuya salida ya se verificó en local.
        slot: u64,
        /// `N(slot)` del calendario del hilo, para que el bucle compruebe la generación por slot.
        n: u64,
    },
    /// `ORDEN-W06d8` decisión 3: el hilo productor detectó una violación de invariante (o un fallo
    /// interno irrecuperable) y termina. El bucle escribe el evento crítico `fallo_productor` con el
    /// motivo y devuelve error: el proceso sale con código ≠ 0, nunca en silencio ni a medias.
    Fallo {
        /// Motivo legible de la parada.
        motivo: String,
    },
}

/// Respuestas del bucle al hilo productor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarcaReloj {
    /// Perfil sin reloj: conservar la captura de SystemTime en el hilo.
    Inactivo,
    /// Marca ya admisible para los padres efectivos, elegida antes de sellar.
    Elegida {
        /// Marca entera en la intersección de PMT, banda y futuro.
        timestamp: u64,
        /// Longitud del segundo VDF del perfil de red.
        i_iter: u64,
    },
    /// Contexto incompleto o intersección sin enteros: omitir sin firmar.
    Abstenerse,
}

/// Respuestas numeradas del bucle al hilo productor.
#[expect(
    clippy::large_enum_variant,
    reason = "un mensaje por producción intentada (~1/s); boxear `PadresDag` (Copy, 481 B) solo movería el coste a una asignación de montón sin beneficio medible"
)]
pub enum MsgBucle {
    /// Padres canónicos (`padres::padres_de_regimen`), con `(hash, slot)` de **cada** padre
    /// (seleccionado y extras). `id` es el de la `PeticionPadres` a la que responde.
    ///
    /// `ORDEN-W06d3`, hallazgo en vivo (`PROGRESO.md`): con red, un padre puede ser un bloque
    /// **ajeno** que este proceso nunca produjo — el bucle lo admitió y lo conoce (`Cadena`,
    /// `self.servicio_verificacion`), pero el `ServicioPot` **propio** del hilo productor (una
    /// copia independiente, ver el docstring del módulo) nunca lo vio, porque solo se actualiza
    /// cuando el propio hilo produce un bloque (`registrar_validado`, más abajo). Sin esta
    /// información, `producir_en_regimen` fallaba con «el padre seleccionado no está registrado en
    /// el `ServicioPot`» en cuanto GHOSTDAG elegía un padre de otro nodo.
    ///
    /// `ORDEN-W06d5` decisión 1: además, las claves (entre las que gestiona el hilo) con garantía
    /// activa `>= q` en `Estado(padre_seleccionado)` — RD-9. El bucle las calcula porque solo él
    /// tiene `Cadena`/`params.q`; el hilo nunca intenta `producir_en_regimen` para una clave que no
    /// esté en este conjunto (causa de `ErrGarantia` fatal en V5 de `REVISION-W06d4.md`).
    Padres {
        /// `id` de la `PeticionPadres` a la que responde.
        id: u64,
        /// T3: decisión de reloj para los padres efectivos de este slot.
        marca_reloj: MarcaReloj,
        /// Padres canónicos del bloque.
        padres: PadresDag,
        /// `(hash, slot)` de cada padre (seleccionado y extras).
        info_padres: Vec<(BlockHash, u64)>,
        /// Claves con garantía activa `>= q` en el estado del padre seleccionado.
        con_garantia: BTreeSet<ClavePublica>,
        /// `ORDEN-TX3-2`: cuerpo ya seleccionado por el bucle para este bloque PoST con el mismo
        /// muestreo y reserva que la plantilla PoW (`Mempool::seleccionar`): transacciones de la
        /// mempool (incluido el depósito del granjero sin garantía, reserva TX-R-46) más las
        /// `EvidenceTx` elegibles del detector (`ORDEN-SL4b2` decisión 4). El hilo las mete en el
        /// cuerpo tal cual, sin volver a decidir nada sobre ellas.
        txs: Vec<Tx>,
        /// Testigos paralelos a `txs` (una lista por transacción, un testigo por entrada). Las
        /// `EvidenceTx` llevan lista vacía (EV-01: sin entradas, salidas ni testigos).
        testigos: Vec<Vec<Vec<u8>>>,
    },
    /// `Candidata` procesada: sigue produciendo. `id` es el del mensaje al que responde.
    Continuar {
        /// `id` del `Candidata` al que responde.
        id: u64,
    },
    /// Condición de parada alcanzada (`--parada-tras-slots`): el hilo debe terminar. No lleva `id`:
    /// se atiende siempre, sea cual sea la respuesta que el hilo esperaba.
    Parar,
    /// `ORDEN-SL4b2` decisión 0: el terminal **seleccionado** cambió mientras el hilo producía
    /// (FC-3, `ORDEN-W06d7`). El bucle manda el `ServicioPot` de verificación del nuevo terminal
    /// (ya avanzado con toda su historia admitida): el hilo lo adopta como su propio `ServicioPot`
    /// de régimen y abandona cualquier candidata/petición en vuelo del terminal anterior (esas
    /// candidatas pertenecían a un flujo PoT que ya no es el seleccionado; perder esa única
    /// oportunidad de slot es preferible a mezclar dos terminales en un mismo bloque, `ErrTerminalAmbiguo`/I-4).
    /// Puede llegar en cualquier punto de espera del hilo, incluso en medio de un intercambio
    /// `PeticionPadres`/`Post`.
    CambiarTerminal(ServicioPot),
}

/// Payload de una respuesta `Padres`, boxeado dentro de [`Recepcion`]: el `PadresDag` (481 B) más
/// los vectores harían que todas las variantes del enum cargasen ~560 B aunque la respuesta sea un
/// `Continuar`/`Parar` de 8 B (mismo criterio que el `Box` del mensaje del bucle).
struct PadresRecibidos {
    /// Decisión de reloj anterior a la firma.
    marca_reloj: MarcaReloj,
    /// Padres canónicos.
    padres: PadresDag,
    /// `(hash, slot)` de cada padre.
    info_padres: Vec<(BlockHash, u64)>,
    /// Claves con garantía activa `>= q`.
    con_garantia: BTreeSet<ClavePublica>,
    /// Cuerpo ya seleccionado por el bucle (transacciones + testigos paralelos).
    txs: Vec<Tx>,
    /// Testigos paralelos a `txs`.
    testigos: Vec<Vec<Vec<u8>>>,
}

/// Resultado de esperar una respuesta del bucle con el `id` esperado (o de absorber un cambio de
/// terminal). Ver el docstring del módulo para la regla de descarte.
enum Recepcion {
    /// Respuesta `Padres` con el `id` esperado.
    Padres(Box<PadresRecibidos>),
    /// Respuesta `Continuar` con el `id` esperado.
    Continuar,
    /// El bucle pidió parar; se atiende siempre.
    Parar,
    /// Se aplicó un cambio de terminal: el hilo debe abandonar el intercambio en curso y volver al
    /// principio de su bucle principal (el próximo `avanzar()` ya usa el `ServicioPot` nuevo).
    Interrumpido,
    /// El bucle cerró el canal: apagado normal del proceso.
    Cerrado,
    /// Violación de invariante del protocolo: el hilo debe terminar con [`MsgProductor::Fallo`].
    Violacion(String),
}

/// Escribe el evento de diagnóstico de una respuesta atrasada descartada, con ambos `id`.
fn registrar_descarte(registro: &Registro, id_esperado: u64, id_recibido: u64) {
    let _ = registro.escribir(
        registro
            .evento("productor_respuesta_descartada")
            .u64("id_esperado", id_esperado)
            .u64("id_recibido", id_recibido),
        false,
    );
}

/// `ORDEN-W06d9` decisión 2(b): escribe el evento de diagnóstico `produccion_omitida` con el slot y
/// el motivo. No es un evento crítico: el nodo sigue validando y produciendo en los slots
/// siguientes; solo deja de producir este bloque, que no puede justificar con esos padres.
fn registrar_produccion_omitida(registro: &Registro, slot: u64, motivo: &str) {
    let _ = registro.escribir(
        registro
            .evento("produccion_omitida")
            .u64("slot", slot)
            .str("motivo", motivo),
        false,
    );
}

/// W08c (solo diagnóstico): un evento por slot auditado con cuántas claves se auditaron y cuáles
/// dieron solución. Cierra el primer eslabón del embudo («¿hubo solución ganadora?») sin cambiar
/// ninguna decisión del productor.
///
/// W08e: añade el perfil por fases del slot — `t_pot_ns` (avance del PoT), `t_conv_ns` (auditoría +
/// conversión KZG de todas las claves en paralelo) y los máximos por clave `t_auditoria_max_ns` y
/// `t_conversion_max_ns`. Solo registro; ninguna decisión depende de ellos.
#[expect(
    clippy::too_many_arguments,
    reason = "evento de diagnóstico por fases; agrupar los tiempos en un struct no aporta"
)]
fn registrar_auditoria(
    registro: &Registro,
    slot: u64,
    n_claves: usize,
    ganadoras: &[(usize, SolucionCandidata)],
    n_candidatos: u64,
    t_pot_ns: u64,
    t_conv_ns: u64,
    t_auditoria_max_ns: u64,
    t_conversion_max_ns: u64,
) {
    let indices: Vec<String> = ganadoras.iter().map(|(i, _)| i.to_string()).collect();
    let _ = registro.escribir(
        registro
            .evento("produccion_auditoria")
            .u64("slot", slot)
            .u64("n_claves", n_claves as u64)
            .u64("n_candidatos", n_candidatos)
            .u64("n_ganadoras", ganadoras.len() as u64)
            .u64("t_pot_ns", t_pot_ns)
            .u64("t_conv_ns", t_conv_ns)
            .u64("t_auditoria_max_ns", t_auditoria_max_ns)
            .u64("t_conversion_max_ns", t_conversion_max_ns)
            .str("claves_ganadoras", &indices.join(",")),
        false,
    );
}

/// W08e (solo diagnóstico): coste de armar + firmar un bloque ganador (`t_armado_ns`) y tiempo total
/// desde que el hilo tuvo la salida PoT del slot hasta que el bucle confirmó la admisión
/// (`t_total_ns`). Permite separar el armado/firma de la conversión KZG y de la admisión.
fn registrar_armado(
    registro: &Registro,
    slot: u64,
    clave_indice: usize,
    t_armado_ns: u64,
    t_total_ns: u64,
) {
    let _ = registro.escribir(
        registro
            .evento("produccion_armado")
            .u64("slot", slot)
            .u64("clave_indice", clave_indice as u64)
            .u64("t_armado_ns", t_armado_ns)
            .u64("t_total_ns", t_total_ns),
        false,
    );
}

/// W08c (solo diagnóstico): la candidata se descartó por no alcanzar la garantía activa `>= q`
/// (RD-9). Antes solo se emitía un `tracing::info` que no llegaba al registro.
fn registrar_sin_garantia(registro: &Registro, slot: u64, indice: usize) {
    let _ = registro.escribir(
        registro
            .evento("produccion_sin_garantia")
            .u64("slot", slot)
            .u64("clave_indice", indice as u64),
        false,
    );
}

/// W08c (solo diagnóstico): la candidata se descartó tras pedir padres (p. ej. `SlotNoProgreso`);
/// antes solo se emitía un `tracing::info`.
fn registrar_descartada(registro: &Registro, slot: u64, indice: usize, motivo: &str) {
    let _ = registro.escribir(
        registro
            .evento("produccion_descartada")
            .u64("slot", slot)
            .u64("clave_indice", indice as u64)
            .str("motivo", motivo),
        false,
    );
}

/// W08c (solo diagnóstico): qué contestó el bucle a una `PeticionPadres` y con qué slot, para ver
/// si el productor va por detrás de la red (`slot_seleccionado >= slot_objetivo`).
fn registrar_padres(
    registro: &Registro,
    slot_objetivo: u64,
    slot_seleccionado: Option<u64>,
    n_extras: usize,
    n_con_garantia: usize,
    n_evidencias: usize,
) {
    let mut evento = registro
        .evento("produccion_padres")
        .u64("slot_objetivo", slot_objetivo)
        .u64("n_extras", n_extras as u64)
        .u64("n_con_garantia", n_con_garantia as u64)
        // W08d (solo diagnóstico, embudo B-20): cuántas transacciones (evidencias + mempool)
        // lleva el cuerpo de este bloque. Se conserva el nombre del campo por compatibilidad con
        // el analizador de W07c; desde TX-3-2 ya no son solo `EvidenceTx`.
        .u64("n_evidencias", n_evidencias as u64);
    if let Some(s) = slot_seleccionado {
        evento = evento.u64("slot_seleccionado", s);
    }
    let _ = registro.escribir(evento, false);
}

/// W08c (solo diagnóstico): el `ServicioPot` propio salta de `desde` a `hasta` para alcanzar un
/// padre ajeno. El salto ya existía; esto solo lo hace medible.
fn registrar_avanzar_hasta(registro: &Registro, desde: u64, hasta: u64) {
    let _ = registro.escribir(
        registro
            .evento("productor_avanzar_hasta")
            .u64("desde", desde)
            .u64("hasta", hasta),
        false,
    );
}

/// `ORDEN-W06d9` decisión 2: clasifica un fallo de `producir_en_regimen_con_firmante` como una
/// **producción omitible** (no se pudo justificar el bloque con esos padres: hueco de portadores no
/// recomputable o rango fuera del formato) o como un fallo interno que sí debe tumbar al productor.
///
/// Un portador ausente **no** es una violación de invariante del productor (decisión 2): se omite la
/// producción de ese slot y se sigue. Cualquier otro error sigue siendo `fallo_productor`.
fn motivo_produccion_omitida<E>(error: &ErrorRegimen<E>) -> Option<String>
where
    E: std::error::Error + 'static,
{
    match error {
        ErrorRegimen::Servicio(ErrorServicioPot::PortadorAusente { slot }) => {
            Some(format!("portador ausente para el slot {slot}"))
        }
        ErrorRegimen::Servicio(ErrorServicioPot::RecompletarExcedeMaximo {
            base_slot,
            d,
            max,
            ..
        }) => Some(format!(
            "no se pudo recompletar el rango de portadores: la salida conocida más cercana está en \
             el slot {base_slot} (distancia {d} > MAX_BUNDLES_POT={max})"
        )),
        ErrorRegimen::RangoExcedeMaximo { d, max } => {
            Some(format!("el rango {d} excede MAX_BUNDLES_POT={max}"))
        }
        _ => None,
    }
}

/// Espera el próximo mensaje del bucle aplicando la regla del protocolo numerado: descarta
/// respuestas atrasadas (`id <` el esperado, con evento de diagnóstico), atiende `Parar` siempre,
/// absorbe [`MsgBucle::CambiarTerminal`] en el sitio (decisión 0) y declara violación de invariante
/// una respuesta con `id` del futuro (`>`). Nunca entra en pánico.
///
/// `publicado` es el último slot publicado por el timelord cuando el hilo empezó a esperar (lectura
/// de `Timelord::slot_publicado`); el hilo del timelord vuelve a comprobar la dirección al adoptar,
/// así que una frontera que se quede atrás entre tanto no retrocede el reloj.
fn esperar(
    rx: &Receiver<MsgBucle>,
    servicio: &mut ServicioPot,
    publicado: u64,
    registro: &Registro,
    id_esperado: u64,
) -> Recepcion {
    loop {
        match rx.recv() {
            Err(_) => return Recepcion::Cerrado,
            Ok(MsgBucle::CambiarTerminal(nuevo)) => {
                // Terminal distinto: otro flujo PoT, se adopta siempre. Mismo terminal: la frontera
                // verificada va por delante del reloj, o trae un **ajuste del reloj** (`C-RLJ-06`)
                // que invalida las salidas calculadas con el `N(s)` viejo.
                let reloj_cambia = nuevo.reloj() != servicio.reloj();
                if nuevo.terminal() != servicio.terminal()
                    || nuevo.slot_actual() > publicado
                    || reloj_cambia
                {
                    *servicio = nuevo;
                    return Recepcion::Interrumpido;
                }
            }
            Ok(MsgBucle::Parar) => return Recepcion::Parar,
            Ok(MsgBucle::Padres {
                id,
                marca_reloj,
                padres,
                info_padres,
                con_garantia,
                txs,
                testigos,
            }) => match id.cmp(&id_esperado) {
                Ordering::Less => {
                    registrar_descarte(registro, id_esperado, id);
                    continue;
                }
                Ordering::Greater => {
                    return Recepcion::Violacion(format!(
                        "el bucle respondió `Padres` con id {id} > esperado {id_esperado}: \
                         respuestas fuera de orden"
                    ));
                }
                Ordering::Equal => {
                    return Recepcion::Padres(Box::new(PadresRecibidos {
                        marca_reloj,
                        padres,
                        info_padres,
                        con_garantia,
                        txs,
                        testigos,
                    }));
                }
            },
            Ok(MsgBucle::Continuar { id }) => match id.cmp(&id_esperado) {
                Ordering::Less => {
                    registrar_descarte(registro, id_esperado, id);
                    continue;
                }
                Ordering::Greater => {
                    return Recepcion::Violacion(format!(
                        "el bucle respondió `Continuar` con id {id} > esperado {id_esperado}: \
                         respuestas fuera de orden"
                    ));
                }
                Ordering::Equal => return Recepcion::Continuar,
            },
        }
    }
}

/// Envía al bucle una parada ordenada por violación de invariante (decisión 3). Si el canal ya
/// está cerrado, el bucle ya terminó: no hay nada más que hacer.
fn reportar_fallo(tx: &Sender<MsgProductor>, motivo: String) {
    let _ = tx.send(MsgProductor::Fallo { motivo });
}

/// Resultado de pedir al timelord la próxima salida PoT o de esperar a que alcance un slot.
enum RecepcionPot {
    /// Salida ya insertada en el `ServicioPot` propio, lista para auditar.
    Salida {
        /// Slot de la salida.
        slot: u64,
        /// Salida PoT de ese slot.
        salida: [u8; POT_OUTPUT_BYTES],
    },
    /// El bucle pidió parar; se atiende siempre.
    Parar,
    /// Se adoptó un cambio de terminal: se abandona la vuelta en curso.
    Interrumpido,
    /// El timelord falló o cerró el canal; el llamante lo convierte en `fallo_productor`.
    Fallo(String),
}

/// Inserta en `servicio` una salida publicada por el timelord sin recalcular el AES. Descarta las
/// publicaciones del terminal anterior (el timelord aún no adoptó el nuevo). Un fallo real se
/// devuelve como texto (el llamante lo convierte en `fallo_productor`).
fn insertar_publicacion(
    servicio: &mut ServicioPot,
    publicada: &SalidaPublicada,
) -> Result<(), String> {
    if publicada.terminal != servicio.terminal() {
        return Ok(());
    }
    servicio
        .declarar_salida_pasada(publicada.slot, publicada.salida, publicada.portador)
        .map_err(|e| {
            format!(
                "insertar la salida publicada del slot {}: {e}",
                publicada.slot
            )
        })
}

/// Atiende, **sin bloquear**, las órdenes del bucle que llegan mientras se espera al timelord.
/// Devuelve `Some` si hay que abandonar la vuelta (`Parar`/`CambiarTerminal`) y `None` si no había
/// nada. Las respuestas atrasadas a peticiones ya abandonadas se descartan (no hay petición viva).
fn atender_bucle_sin_bloquear(
    rx: &Receiver<MsgBucle>,
    servicio: &mut ServicioPot,
    timelord: &Timelord,
) -> Option<RecepcionPot> {
    loop {
        match rx.try_recv() {
            Ok(MsgBucle::CambiarTerminal(nuevo)) => {
                // Terminal distinto: se adopta siempre. Mismo terminal: frontera verificada, solo si
                // va por delante del reloj (`saltar_a_frontera` ya pide el salto al timelord), o un
                // **ajuste del reloj** (`C-RLJ-06`), que también invalida lo calculado con el `N(s)`
                // viejo y por eso se adopta aunque la frontera no vaya por delante.
                if nuevo.terminal() != servicio.terminal() || nuevo.reloj() != servicio.reloj() {
                    timelord.cambiar_servicio(nuevo.clone());
                    *servicio = nuevo;
                    return Some(RecepcionPot::Interrumpido);
                }
                if timelord.saltar_a_frontera(nuevo.clone()) {
                    *servicio = nuevo;
                    return Some(RecepcionPot::Interrumpido);
                }
            }
            Ok(MsgBucle::Parar) => return Some(RecepcionPot::Parar),
            Ok(_) => continue,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => return Some(RecepcionPot::Parar),
        }
    }
}

/// Espera la próxima salida publicada por el timelord (o una orden del bucle) y la inserta en el
/// `ServicioPot` propio, **en orden y sin saltarse slots**: así el `pasado` del servicio conserva los
/// padres recientes (que el bucle puede elegir) y el reloj no se toca. Si la producción va más
/// despacio que el reloj, los slots atrasados se auditan y se descartan igual, pero el reloj nunca
/// espera.
///
/// `ORDEN-W08h` (decisión 4): si el productor ya adoptó una frontera verificada por delante, las
/// salidas publicadas que quedan **por detrás** de ella ya no pueden ganar y se descartan sin
/// auditarlas (el `ServicioPot` adoptado ya trae sus datos).
fn recibir_salida_pot(
    rx_publicaciones: &ReceptorSalidas,
    rx: &Receiver<MsgBucle>,
    servicio: &mut ServicioPot,
    timelord: &Timelord,
) -> RecepcionPot {
    loop {
        match rx_publicaciones.recv_timeout(Duration::from_millis(20)) {
            Ok(publicada) => {
                // Con `N_dev` de tests las publicaciones llegan en ráfaga; se atiende el bucle en
                // cada vuelta para no diferir `Parar`/`CambiarTerminal`.
                if let Some(efecto) = atender_bucle_sin_bloquear(rx, servicio, timelord) {
                    return efecto;
                }
                if publicada.terminal != servicio.terminal() {
                    // Publicación del terminal anterior: descartar y seguir esperando al nuevo.
                    continue;
                }
                if publicada.slot <= servicio.slot_actual() {
                    // Salida anterior a la frontera ya adoptada: descartar sin auditarla.
                    continue;
                }
                if let Err(e) = insertar_publicacion(servicio, &publicada) {
                    return RecepcionPot::Fallo(e);
                }
                return RecepcionPot::Salida {
                    slot: publicada.slot,
                    salida: publicada.salida,
                };
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Some(efecto) = atender_bucle_sin_bloquear(rx, servicio, timelord) {
                    return efecto;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return RecepcionPot::Fallo("el timelord PoT terminó sin publicar".to_string());
            }
        }
    }
}

/// Espera a que el `ServicioPot` propio alcance `hasta`, insertando las salidas publicadas que
/// falten. Lo usa el catch-up de un padre ajeno más adelantado que el reloj insertado; el timelord
/// sigue avanzando por su cuenta (este hilo es el único que espera).
fn sincronizar_hasta(
    rx_publicaciones: &ReceptorSalidas,
    rx: &Receiver<MsgBucle>,
    servicio: &mut ServicioPot,
    timelord: &Timelord,
    hasta: u64,
) -> RecepcionPot {
    while servicio.slot_actual() < hasta {
        match rx_publicaciones.recv_timeout(Duration::from_millis(20)) {
            Ok(publicada) => {
                if let Some(efecto) = atender_bucle_sin_bloquear(rx, servicio, timelord) {
                    return efecto;
                }
                if publicada.terminal != servicio.terminal() {
                    continue;
                }
                if let Err(e) = insertar_publicacion(servicio, &publicada) {
                    return RecepcionPot::Fallo(e);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Some(efecto) = atender_bucle_sin_bloquear(rx, servicio, timelord) {
                    return efecto;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return RecepcionPot::Fallo(
                    "el timelord PoT terminó antes de alcanzar el slot del padre".to_string(),
                );
            }
        }
    }
    RecepcionPot::Salida {
        slot: servicio.slot_actual(),
        salida: servicio
            .salida_de(servicio.slot_actual())
            .unwrap_or([0u8; POT_OUTPUT_BYTES]),
    }
}

/// Material **público** de una clave productora con su parcela ya abierta (PROD-3c).
///
/// El hilo productor no recibe ninguna clave privada: solo el índice, la clave pública (la de
/// la solución y la coinbase) y la parcela. El bucle conserva las `ClaveDev` para firmar.
pub struct ClavePublicaConParcela {
    /// Índice de la clave (el de `MsgProductor::Candidata::clave_indice`).
    pub indice: u32,
    /// Clave pública de la solución y de la coinbase.
    pub pk: ClavePublica,
    /// Su parcela.
    pub parcela: ParcelaDisco,
}

/// Cuerpo del hilo productor en régimen.
///
/// Cada slot: avanza el PoT, audita las parcelas locales, y si hay solución para alguna clave, pide
/// los padres **una sola vez** para todo el slot (los hermanos del mismo slot comparten padres; una
/// segunda petición tras admitir el primero heredaría un `sp` del mismo slot — válido desde W08c,
/// pero innecesario — y añadiría un viaje de ida y vuelta por candidata) y produce un bloque por
/// clave ganadora.
///
/// Termina cuando `parada_tras_slots` se alcanza, cuando el bucle contesta [`MsgBucle::Parar`],
/// cuando el canal con el bucle se cierra (fin del proceso) o cuando detecta una violación de
/// invariante (envía [`MsgProductor::Fallo`] y devuelve).
#[expect(
    clippy::too_many_arguments,
    reason = "el estado de arranque de régimen ya viene mínimo; agruparlo ocultaría su procedencia"
)]
pub fn hilo_productor_regimen(
    mut servicio: ServicioPot,
    sr_dev: u64,
    cbid: u32,
    importe_coinbase: zx_core::Amount,
    claves: Vec<ClavePublicaConParcela>,
    historia: &HistoriaGenesis,
    parada_tras_slots: Option<u64>,
    rx: &Receiver<MsgBucle>,
    tx: &Sender<MsgProductor>,
    registro: &Registro,
) {
    // PROD-3b/PROD-3c: el hilo **no** firma ni construye el firmante, y **no** recibe ninguna
    // clave privada. Arma la candidata sin sello con `preparar_regimen_con_clave_publica` y la
    // manda al bucle, que es el dueño de la cadena y el único que puede comprobar, ensayar y firmar.
    // `servicio` es un **clon** del `ServicioPot` de verificación del bucle (`Nodo::
    // servicio_verificacion`), no uno construido desde cero: ya trae registrado el terminal y
    // *todo* bloque PoST admitido hasta ahora (el de transición si acaba de producirse, o toda la
    // historia de régimen si `fase_regimen` arranca tras un reinicio). Construir uno nuevo con
    // `ServicioPot::nuevo(terminal, ...)` aquí fue el bug real de la primera ejecución de V4
    // (`PROGRESO.md`): el hilo no conocía el bloque de transición, `slot_de(padre)` fallaba siempre
    // y `producir_en_regimen` fallaba en silencio para cada intento.
    let parametros = ParametrosProductor {
        // RL-2b: el productor hereda el `N_dev` **inicial** del servicio (con el reloj activo,
        // `T0·n_iter`), no el de la CLI: es el que `producir_en_regimen` compara.
        n_dev: servicio.n_dev(),
        sr_dev,
        max_slots: 150,
        consensus_branch_id: cbid,
        timestamp: 0,
        i_iter: zx_post::reloj_post::I_ITER_DEV,
        importe_coinbase,
    };

    // `ORDEN-W06d8` decisión 1: contador creciente de mensajes enviados al bucle. `wrapping_add` es
    // deliberado: llegar a 2^64 mensajes (~5.8·10^11 años a un mensaje por segundo) es inalcanzable,
    // y así ni el modo debug (comprobación de desbordamiento) puede entrar en pánico por el `id`.
    let mut proximo_id: u64 = 0;

    // `ORDEN-W08g` decisión 1: el reloj PoT arranca en su propio hilo con un clon del servicio. El
    // hilo productor conserva el suyo y lo alimenta con las salidas publicadas (sin recalcular AES).
    let (timelord, rx_publicaciones) = Timelord::arrancar(servicio.clone());

    'outer: loop {
        if let Some(limite) = parada_tras_slots
            && servicio.slot_actual() >= limite
        {
            return;
        }
        // `ORDEN-W08g` decisión 1: la PoT la avanza el timelord. Aquí solo se espera la próxima
        // salida publicada (o una orden del bucle) y se inserta en el `ServicioPot` propio. El
        // objetivo de slot ya no se fija aquí: lo marca el reloj publicado, e ir por detrás no lo
        // retrasa. `avanzar_hasta` solo se conserva para el catch-up de un padre ajeno (más abajo).
        let inicio_pot = Instant::now();
        let (slot, salida) =
            match recibir_salida_pot(&rx_publicaciones, rx, &mut servicio, &timelord) {
                RecepcionPot::Salida { slot, salida } => (slot, salida),
                RecepcionPot::Parar => return,
                RecepcionPot::Interrumpido => continue 'outer,
                RecepcionPot::Fallo(motivo) => {
                    reportar_fallo(tx, motivo);
                    return;
                }
            };
        let t_pot_ns = inicio_pot.elapsed().as_nanos() as u64;
        // `ORDEN-W07a`: instante en que este hilo tuvo la salida PoT del slot, para `retraso_slot_ns`.
        let instante_salida = Instant::now();

        // W08c: la auditoría y la conversión KZG de cada clave son independientes entre sí y son el
        // coste dominante del slot (≈ 1 s por clave con la parcela dev). Se paralelizan **por clave**
        // para que el coste por slot no crezca linealmente con el número de claves: con el bucle
        // secuencial, un proceso de 6 claves tardaba 5-7 s por vuelta y quedaba un slot por detrás de
        // la red en cada una, descartando todas sus candidatas (medido en A2/W08c: 0 bloques públicos
        // para las claves 0-5 frente a 74 aisladas). Cada tarea escribe solo en su propio resultado;
        // la recogida es por índice, en orden, sin carreras ni estado compartido.
        let mut ganadoras: Vec<(usize, SolucionCandidata)> = Vec::new();
        // W08e (solo diagnóstico): `t_conv_ns` mide la conversión (auditoría + tabla PoSpace + KZG)
        // de **todas** las claves en paralelo; `t_aud_max_ns` y `t_conv_max_ns` el máximo por clave.
        let mut t_aud_max_ns: u64 = 0;
        let mut t_conv_max_ns: u64 = 0;
        let mut n_candidatos: u64 = 0;
        let inicio_conversion = Instant::now();
        let resultados = std::thread::scope(|scope| {
            let mut tareas = Vec::with_capacity(claves.len());
            for cp in &claves {
                tareas.push(scope.spawn(move || {
                    // W08e: se llama directo a la conversión (sin el puente `FuenteParcela`) para
                    // conservar su diagnóstico por clave; el contrato es el mismo.
                    let params = historia.params_pieza();
                    convertir_candidatos_locales(
                        &cp.parcela,
                        salida,
                        slot,
                        sr_dev,
                        &params,
                        historia,
                        historia.erasure_coding(),
                    )
                }));
            }
            tareas
                .into_iter()
                .map(|tarea| tarea.join())
                .collect::<Vec<_>>()
        });
        let t_conv_ns = inicio_conversion.elapsed().as_nanos() as u64;
        for (i, resultado) in resultados.into_iter().enumerate() {
            let Ok(conversion) = resultado else {
                reportar_fallo(tx, format!("la auditoría de la clave {i} entró en pánico"));
                return;
            };
            let conversion = match conversion {
                Ok(conversion) => conversion,
                Err(e) => {
                    reportar_fallo(tx, format!("auditoría de la clave {i}: {e}"));
                    return;
                }
            };
            let diagnostico = conversion.diagnostico();
            t_aud_max_ns = t_aud_max_ns.max(diagnostico.ns_auditoria);
            t_conv_max_ns = t_conv_max_ns.max(diagnostico.ns_conversion);
            n_candidatos += diagnostico.candidatos as u64;
            if let Some(c) = conversion.soluciones().last().copied() {
                ganadoras.push((
                    i,
                    SolucionCandidata {
                        solucion: *c.solucion(),
                        distancia: c.distancia(),
                    },
                ));
            }
        }
        // Primer eslabón del embudo (W08c): ¿hubo solución ganadora en este slot?
        registrar_auditoria(
            registro,
            slot,
            claves.len(),
            &ganadoras,
            n_candidatos,
            t_pot_ns,
            t_conv_ns,
            t_aud_max_ns,
            t_conv_max_ns,
        );
        if ganadoras.is_empty() {
            // VNT-R1 · frontera de PoT verificada sin ganadora: el nodo la usa para avanzar el
            // cursor de votos. No bloquea la producción del slot; si el canal está cerrado, el
            // hilo se apaga de forma normal.
            if tx
                .send(MsgProductor::FronteraPot {
                    flujo: servicio.terminal(),
                    slot,
                    n: servicio.n_vigente(slot),
                })
                .is_err()
            {
                return;
            }
            continue;
        }

        let id_peticion = proximo_id;
        proximo_id = proximo_id.wrapping_add(1);
        if tx
            .send(MsgProductor::PeticionPadres {
                id: id_peticion,
                slot,
            })
            .is_err()
        {
            return; // el bucle cerró el canal: apagado normal del proceso.
        }
        let (padres, info_padres, con_garantia, txs, testigos, marca_reloj) = match esperar(
            rx,
            &mut servicio,
            timelord.slot_publicado(),
            registro,
            id_peticion,
        ) {
            Recepcion::Padres(p) => {
                let PadresRecibidos {
                    marca_reloj,
                    padres,
                    info_padres,
                    con_garantia,
                    txs,
                    testigos,
                } = *p;
                (
                    padres,
                    info_padres,
                    con_garantia,
                    txs,
                    testigos,
                    marca_reloj,
                )
            }
            Recepcion::Continuar => {
                reportar_fallo(
                    tx,
                    format!("se esperaba `Padres` para el id {id_peticion} y llegó `Continuar`"),
                );
                return;
            }
            // Decisión 0: el terminal cambió antes de que el bucle contestara esta petición
            // (era del terminal anterior). Se abandona esta candidata/slot sin fingir una
            // respuesta: el próximo `avanzar()` ya corre sobre el `ServicioPot` del terminal
            // nuevo.
            Recepcion::Interrumpido => {
                // `ORDEN-W08g`: el timelord debe adoptar el terminal nuevo; si no, seguiría
                // publicando el flujo viejo y el productor nunca vería una publicación del
                // terminal actual.
                timelord.cambiar_servicio(servicio.clone());
                continue 'outer;
            }
            Recepcion::Parar => return,
            Recepcion::Cerrado => return, // el bucle cerró el canal: apagado normal del proceso.
            Recepcion::Violacion(motivo) => {
                reportar_fallo(tx, motivo);
                return;
            }
        };
        if marca_reloj == MarcaReloj::Abstenerse {
            registrar_produccion_omitida(registro, slot, "sin_timestamp_admisible_o_contexto");
            continue 'outer;
        }
        // `ORDEN-W06d5` decisión 2 (`REVISION-W06d4.md`, V5-2): el padre seleccionado que incumple
        // `slot(padre) < slot_objetivo` ya lo descarta con gracia `producir_en_regimen` más abajo
        // (`ErrorRegimen::SlotNoProgreso`), pero ese cheque **no** cubre los padres extra del
        // mergeset GHOSTDAG (`C-HDR-05`/`C-FLU-02`: la regla alcanza a **todos** los padres). Se
        // excluyen aquí, antes de construir ningún bloque, en vez de descubrirlo en la verificación
        // completa (donde, al ser un bloque propio, era fatal).
        // W08c (solo diagnóstico): antes de filtrar, anotar qué padres contestó el bucle. El primer
        // `info_padres` es el seleccionado (el bucle lo inserta primero).
        let slot_sel = info_padres.first().map(|(_, s)| *s);
        registrar_padres(
            registro,
            slot,
            slot_sel,
            info_padres.len().saturating_sub(1),
            con_garantia.len(),
            txs.len(),
        );
        let padres = match filtrar_padres_extra_por_slot(padres, &info_padres, slot) {
            Ok(padres) => padres,
            Err(motivo) => {
                reportar_fallo(tx, motivo);
                return;
            }
        };
        // Registra en el `ServicioPot` propio cualquier padre que este hilo no haya producido él
        // mismo (ver el docstring de `MsgBucle::Padres`). `BloqueDuplicado` es el caso normal (un
        // padre que sí produjo este mismo hilo, o que ya se registró en una vuelta anterior porque
        // dos candidatas del mismo slot comparten padres): no es un error, es la confirmación de que
        // ya estaba. Cualquier otro fallo (`SlotFuturo`, `NDevInvalido`) sí es una incoherencia real.
        for (hash, slot_padre) in info_padres {
            // `ORDEN-W08g`: el flujo PoT lo avanza el timelord. Si un padre ajeno viene de un slot
            // **más adelantado** que el que este hilo lleva insertado, se esperan (y se insertan) las
            // salidas publicadas que falten; el productor ya **no** vuelve a correr el AES. El reloj
            // sigue avanzando por su cuenta; solo este hilo espera.
            if slot_padre > servicio.slot_actual() {
                let desde = servicio.slot_actual();
                match sincronizar_hasta(&rx_publicaciones, rx, &mut servicio, &timelord, slot_padre)
                {
                    RecepcionPot::Salida { .. } => {}
                    RecepcionPot::Parar => return,
                    RecepcionPot::Interrumpido => continue 'outer,
                    RecepcionPot::Fallo(motivo) => {
                        reportar_fallo(
                            tx,
                            format!(
                                "no se pudo alcanzar el slot {slot_padre} del padre ajeno {hash}: \
                                 {motivo}"
                            ),
                        );
                        return;
                    }
                }
                // W08c (solo diagnóstico): medir el salto de PoT que provoca ir por detrás.
                registrar_avanzar_hasta(registro, desde, servicio.slot_actual());
            }
            match servicio.registrar_validado(hash, slot_padre) {
                Ok(()) | Err(zx_post::servicio_pot::ErrorServicioPot::BloqueDuplicado { .. }) => {}
                Err(e) => {
                    reportar_fallo(
                        tx,
                        format!(
                            "no se pudo registrar el padre ajeno {hash} (slot {slot_padre}): {e}"
                        ),
                    );
                    return;
                }
            }
        }

        for (i, candidata) in ganadoras {
            let Some(cp) = claves.get(i) else {
                // Invariante del propio código (`i` sale de `claves.iter().enumerate()`): se
                // defiende sin pánico por si un cambio futuro rompe esa garantía.
                tracing::error!(indice = i, "candidata con índice de clave fuera de rango");
                continue;
            };
            // `ORDEN-W06d5` decisión 1 (`REVISION-W06d4.md`, V5-1): «producir solo con garantía».
            // No se **intenta** `producir_en_regimen` para una clave sin garantía activa `>= q` en
            // el estado de la punta elegida: intentarlo de todos modos solo para que el motor lo
            // rechace con `ErrGarantia` (fatal, decisión 4 de `ORDEN-W06d1`) es exactamente el
            // hallazgo V5-1 (un nodo que sincroniza tarde, con una clave nueva que nunca depositó).
            if !con_garantia.contains(&cp.pk) {
                // W08c (solo diagnóstico): dejar constancia en el registro de la clave descartada.
                registrar_sin_garantia(registro, slot, i);
                tracing::info!(
                    indice = i,
                    clave = ?cp.pk,
                    slot,
                    "candidata descartada: la clave no tiene garantía activa >= q en el estado \
                     de la punta elegida (RD-9); no se intenta producir"
                );
                continue;
            }
            let mut parametros_bloque = parametros;
            match marca_reloj {
                MarcaReloj::Elegida { timestamp, i_iter } => {
                    parametros_bloque.timestamp = timestamp;
                    parametros_bloque.i_iter = i_iter;
                }
                MarcaReloj::Inactivo => {
                    parametros_bloque.timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                }
                MarcaReloj::Abstenerse => continue,
            }
            let fuente_fija = SolucionFija(candidata);
            // `ORDEN-TX3-2`: el bucle ya seleccionó el cuerpo con `Mempool::seleccionar` (mismo
            // muestreo y reserva que la plantilla PoW) más las `EvidenceTx` elegibles del detector.
            // El hilo no vuelve a decidir nada: solo valida el cuerpo y lo sella.
            let cuerpo = match CuerpoProductor::nuevo(txs.clone(), testigos.clone()) {
                Ok(cuerpo) => cuerpo,
                Err(e) => {
                    reportar_fallo(tx, format!("cuerpo del bucle inválido: {e}"));
                    return;
                }
            };
            // W08e (solo diagnóstico): coste de armar (ensamblar cabecera/cuerpo sin sello).
            let inicio_armado = Instant::now();
            // PROD-3b/PROD-3c: el hilo arma la candidata **sin sello** y **sin clave privada**.
            // No llama al firmante; el bucle comprueba, depura, ensaya, firma y admite
            // (`firma_contextual`).
            let candidata = match preparar_regimen_con_clave_publica(
                padres,
                slot,
                &mut servicio,
                &fuente_fija,
                &cp.pk,
                &parametros_bloque,
                cuerpo,
            ) {
                Ok(c) => c,
                // `ORDEN-W06d3`, hallazgo en vivo (`PROGRESO.md`): con red, el padre elegido por
                // GHOSTDAG puede ser un bloque **más nuevo** que `slot` (otro nodo ya produjo, para
                // el mismo slot o uno posterior, con el padre que este hilo eligió cuando pidió
                // `PeticionPadres` — el propio catch-up de arriba, que adelanta `servicio` hasta el
                // slot del padre, es la prueba de que esto es normal, no un error). No es un bug de
                // este nodo: el candidato ya no puede ser un bloque de cadena válido (`slot(B)` MUST
                // ser mayor que `slot(sp)`), así que se descarta esta candidata concreta y se sigue
                // con la siguiente (o con el siguiente slot si no hay más). Cualquier otro error de
                // `preparar_regimen_con_clave_publica` sigue siendo una incoherencia interna real y
                // se reporta al bucle.
                Err(zx_post::productor_regimen::ErrorRegimen::SlotNoProgreso {
                    slot: slot_bloque,
                    slot_sp,
                }) => {
                    // W08c (solo diagnóstico): antes solo se emitía un `tracing::info`.
                    registrar_descartada(
                        registro,
                        slot,
                        i,
                        &format!("SlotNoProgreso: padre slot {slot_sp} >= objetivo {slot_bloque}"),
                    );
                    tracing::info!(
                        slot_bloque,
                        slot_sp,
                        "candidata descartada: el padre elegido ya es de este slot o uno \
                         posterior (otro nodo se adelantó)"
                    );
                    continue;
                }
                Err(e) => {
                    // `ORDEN-W06d9` decisión 2: un hueco de portadores que no se pudo recompletar
                    // (o un rango fuera de formato) no es una violación de invariante del productor:
                    // el bloque no se puede justificar con esos padres, así que se omite la
                    // producción de este slot con diagnóstico y se sigue con el siguiente. Cualquier
                    // otro error sigue siendo un fallo interno del productor.
                    if let Some(motivo) = motivo_produccion_omitida(&e) {
                        registrar_produccion_omitida(registro, slot, &motivo);
                        continue 'outer;
                    }
                    reportar_fallo(tx, format!("preparar_regimen_con_clave_publica falló: {e}"));
                    return;
                }
            };
            let t_armado_ns = inicio_armado.elapsed().as_nanos() as u64;
            // PROD-3b: el `hash` del bloque sellado nace en el bucle. El hilo no lo registra en su
            // `ServicioPot`; lo aprenderá por el camino de «padre ajeno» al pedir padres
            // (`registrar_validado` de `info_padres`).
            let id_candidata = proximo_id;
            proximo_id = proximo_id.wrapping_add(1);
            if tx
                .send(MsgProductor::Candidata {
                    id: id_candidata,
                    candidata: Box::new(candidata),
                    instante_salida,
                    clave_indice: cp.indice,
                })
                .is_err()
            {
                return; // el bucle cerró el canal: apagado normal del proceso.
            }
            match esperar(
                rx,
                &mut servicio,
                timelord.slot_publicado(),
                registro,
                id_candidata,
            ) {
                Recepcion::Continuar => {
                    // W08e (solo diagnóstico): el bucle procesó esta candidata (firmó y admitió,
                    // o la descartó con constancia). El hilo sigue.
                    registrar_armado(
                        registro,
                        slot,
                        cp.indice as usize,
                        t_armado_ns,
                        instante_salida.elapsed().as_nanos() as u64,
                    );
                }
                Recepcion::Parar => return,
                // Decisión 0: el bloque ya se mandó y el bucle puede haberlo admitido igualmente
                // (es válido en su propio terminal, aunque ya no sea el seleccionado); se abandona
                // el resto de candidatas de este slot (sus `padres` pertenecen al terminal
                // anterior) y el siguiente `avanzar()` ya corre sobre el `ServicioPot` nuevo. Si
                // `parada_tras_slots` se hubiera alcanzado, el chequeo de cabecera de bucle lo
                // detiene.
                Recepcion::Interrumpido => {
                    // `ORDEN-W08g`: el timelord debe adoptar el terminal nuevo; si no, seguiría
                    // publicando el flujo viejo y el productor nunca vería una publicación del
                    // terminal actual.
                    timelord.cambiar_servicio(servicio.clone());
                    continue 'outer;
                }
                Recepcion::Cerrado => return,
                Recepcion::Padres(..) => {
                    reportar_fallo(
                        tx,
                        format!(
                            "se esperaba `Continuar`/`Parar` tras `Candidata` (id \
                             {id_candidata}) y llegó `Padres`"
                        ),
                    );
                    return;
                }
                Recepcion::Violacion(motivo) => {
                    reportar_fallo(tx, motivo);
                    return;
                }
            }
        }
    }
}

/// `ORDEN-W06d5` decisión 2: reconstruye `padres` excluyendo cualquier padre **extra** cuyo `slot`
/// no sea anterior a `slot_objetivo` (`C-HDR-05`/`C-FLU-02`: la cota alcanza a todos los padres, no
/// solo al seleccionado). El padre seleccionado no se toca aquí — si él mismo incumple la cota, lo
/// descarta con gracia `producir_en_regimen` (`ErrorRegimen::SlotNoProgreso`), más abajo.
///
/// `info_padres` **MUST** traer el slot de cada padre (seleccionado y extras): lo construye el
/// bucle a partir de `Cadena::bloque`, que siempre lo conoce para un padre de régimen ya admitido
/// (docstring de [`MsgBucle::Padres`]). Su ausencia se devuelve como error explícito (el llamante lo
/// convierte en `fallo_productor`), nunca como pánico.
pub(crate) fn filtrar_padres_extra_por_slot(
    padres: PadresDag,
    info_padres: &[(BlockHash, u64)],
    slot_objetivo: u64,
) -> Result<PadresDag, String> {
    let seleccionado = padres.seleccionado();
    let mut extras_validos: Vec<BlockHash> = Vec::with_capacity(padres.extras().len());
    for h in padres.extras() {
        let Some(&(_, slot_padre)) = info_padres.iter().find(|(hp, _)| hp == h) else {
            return Err(format!("padre extra {h} sin información de slot del bucle"));
        };
        if slot_padre >= slot_objetivo {
            tracing::info!(
                padre = ?h,
                slot_padre,
                slot_objetivo,
                "padre extra descartado: su slot no es anterior al del bloque objetivo"
            );
        } else {
            extras_validos.push(*h);
        }
    }
    PadresDag::nuevo(seleccionado, &extras_validos)
        .map_err(|e| format!("reconstruir PadresDag tras filtrar padres extra: {e}"))
}

/// Fuente de soluciones que siempre devuelve la misma candidata ya auditada (evita volver a auditar
/// la parcela al construir el bloque: la auditoría ya se hizo una vez por slot, arriba).
struct SolucionFija(SolucionCandidata);

impl FuenteSoluciones for SolucionFija {
    type Error = std::convert::Infallible;

    fn soluciones(
        &self,
        _salida: [u8; 16],
        _slot: u64,
        _rango: u64,
    ) -> Result<Vec<SolucionCandidata>, Self::Error> {
        Ok(vec![self.0])
    }
}

/// `ORDEN-W06d6` decisión 5: test pendiente de `ORDEN-W06d5` decisión 2 (padres extra) —
/// `filtrar_padres_extra_por_slot` es la función que la implementa; se probaba solo con ejecuciones
/// reales (V6(b)), sin test unitario.
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
mod tests_filtrar_padres_extra {
    use zx_core::digest::Digest;
    use zx_core::{BlockHash, PadresDag};

    use super::filtrar_padres_extra_por_slot;

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    /// Un padre extra cuyo slot **no** es anterior al objetivo (`>=`) se descarta; uno anterior se
    /// conserva. El seleccionado nunca se toca aquí (lo descarta `producir_en_regimen` con gracia,
    /// no este filtro).
    #[test]
    fn descarta_solo_los_extras_cuyo_slot_no_es_anterior_al_objetivo() {
        let seleccionado = h(1);
        let extra_valido = h(2); // slot 5 < 10: se conserva.
        let extra_igual = h(3); // slot 10 == 10: se descarta (no es "anterior").
        let extra_posterior = h(4); // slot 11 > 10: se descarta.

        let padres =
            PadresDag::nuevo(seleccionado, &[extra_valido, extra_igual, extra_posterior]).unwrap();
        let info_padres = vec![
            (seleccionado, 3), // el slot del seleccionado no importa a este filtro.
            (extra_valido, 5),
            (extra_igual, 10),
            (extra_posterior, 11),
        ];

        let filtrados = filtrar_padres_extra_por_slot(padres, &info_padres, 10).unwrap();

        assert_eq!(
            filtrados.seleccionado(),
            seleccionado,
            "el seleccionado no se toca"
        );
        assert_eq!(
            filtrados.extras(),
            &[extra_valido],
            "solo sobrevive el extra con slot estrictamente anterior al objetivo"
        );
    }

    /// Sin ningún extra que filtrar, la reconstrucción es un no-op.
    #[test]
    fn sin_extras_no_cambia_nada() {
        let seleccionado = h(9);
        let padres = PadresDag::nuevo(seleccionado, &[]).unwrap();
        let filtrados = filtrar_padres_extra_por_slot(padres, &[(seleccionado, 1)], 100).unwrap();
        assert_eq!(filtrados.seleccionado(), seleccionado);
        assert!(filtrados.extras().is_empty());
    }

    /// Todos los extras por debajo del objetivo: ninguno se descarta.
    #[test]
    fn todos_los_extras_anteriores_sobreviven() {
        let seleccionado = h(1);
        let e1 = h(2);
        let e2 = h(3);
        let padres = PadresDag::nuevo(seleccionado, &[e1, e2]).unwrap();
        let info = vec![(seleccionado, 0), (e1, 1), (e2, 2)];
        let filtrados = filtrar_padres_extra_por_slot(padres, &info, 100).unwrap();
        let mut extras = filtrados.extras().to_vec();
        extras.sort();
        let mut esperado = vec![e1, e2];
        esperado.sort();
        assert_eq!(extras, esperado);
    }

    /// Un extra sin información de slot no es un pánico: se devuelve el motivo (el llamante lo
    /// convierte en `fallo_productor`, decisión 3).
    #[test]
    fn extra_sin_informacion_es_error_explicito() {
        let seleccionado = h(1);
        let extra = h(2);
        let padres = PadresDag::nuevo(seleccionado, &[extra]).unwrap();
        let err = filtrar_padres_extra_por_slot(padres, &[(seleccionado, 0)], 10).unwrap_err();
        assert!(err.contains("sin información de slot"), "{err}");
    }
}

/// `ORDEN-W06d8` V1: protocolo productor↔bucle con un bucle simulado. Se inyectan respuestas
/// atrasadas (`Padres`/`Continuar` tras `Interrumpido`), duplicadas, `Parar` en el punto de espera e
/// `id` del futuro, y se comprueba que el hilo (la función [`esperar`]) descarta, para o reporta
/// violación **sin pánico**, según la decisión 1 (y la 3 para el `id` del futuro).
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]
mod tests_protocolo {
    use std::sync::mpsc;

    use zx_core::digest::Digest;
    use zx_core::{BlockHash, PadresDag};

    use super::{MarcaReloj, MsgBucle, Recepcion, esperar};
    use crate::registro::Registro;
    use zx_post::servicio_pot::ServicioPot;

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn servicio() -> ServicioPot {
        // `N_dev` debe ser múltiplo de 16 (`proyectar_iteraciones`); 16 es el mínimo válido.
        ServicioPot::nuevo(h(1), 16, 4096).unwrap()
    }

    fn registro() -> (tempfile::TempDir, Registro) {
        let dir = tempfile::tempdir().unwrap();
        let registro = Registro::abrir(&dir.path().join("registro.jsonl")).unwrap();
        (dir, registro)
    }

    fn leer_registro(dir: &tempfile::TempDir) -> String {
        std::fs::read_to_string(dir.path().join("registro.jsonl")).unwrap()
    }

    fn padres(id: u64, selector: u8) -> MsgBucle {
        MsgBucle::Padres {
            id,
            marca_reloj: MarcaReloj::Inactivo,
            padres: PadresDag::nuevo(h(selector), &[]).unwrap(),
            info_padres: vec![(h(selector), u64::from(selector))],
            con_garantia: Default::default(),
            txs: Vec::new(),
            testigos: Vec::new(),
        }
    }

    /// `Padres` con un `id` atrasado llega tras un `Interrumpido`: se descarta (con evento de
    /// diagnóstico) y se entrega la respuesta correcta, sin pánico. Es el caso que tumbaba a W07b
    /// (`regimen.rs:438`).
    #[test]
    fn padres_atrasado_tras_interrumpido_se_descarta() {
        let (dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        // El terminal cambia mientras el hilo esperaba la respuesta a la petición id 0: la espera
        // se declara **interrumpida** y el hilo abandona esa petición. El bucle, que ya la había
        // contestado, deja la respuesta id 0 atrasada en el canal; el hilo ya espera la petición
        // viva id 1. El hash seleccionado distingue cuál se entregó.
        let mut nuevo = servicio();
        nuevo.avanzar().unwrap();
        tx.send(MsgBucle::CambiarTerminal(nuevo)).unwrap();
        tx.send(padres(0, 10)).unwrap();
        tx.send(padres(1, 11)).unwrap();

        let mut serv = servicio();
        assert!(matches!(
            esperar(&rx, &mut serv, 0, &registro, 0),
            Recepcion::Interrumpido
        ));
        match esperar(&rx, &mut serv, 0, &registro, 1) {
            Recepcion::Padres(p) => {
                assert_eq!(p.padres.seleccionado(), h(11), "se descarta el atrasado");
                assert_eq!(p.info_padres, vec![(h(11), 11)]);
            }
            _ => panic!("se esperaba la respuesta Padres viva"),
        }
        let texto = leer_registro(&dir);
        assert!(
            texto.contains("productor_respuesta_descartada"),
            "falta el evento de descarte: {texto}"
        );
        assert!(texto.contains("\"id_esperado\":1"), "{texto}");
        assert!(texto.contains("\"id_recibido\":0"), "{texto}");
    }

    /// `Continuar` duplicado (respuesta repetida de un `Post` ya abandonado): se descarta y se
    /// atiende la respuesta con el `id` esperado.
    #[test]
    fn continuar_duplicado_se_descarta() {
        let (dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        tx.send(MsgBucle::Continuar { id: 3 }).unwrap();
        tx.send(MsgBucle::Continuar { id: 4 }).unwrap();

        let mut serv = servicio();
        assert!(matches!(
            esperar(&rx, &mut serv, 0, &registro, 4),
            Recepcion::Continuar
        ));
        let texto = leer_registro(&dir);
        assert!(texto.contains("productor_respuesta_descartada"), "{texto}");
        assert!(texto.contains("\"id_esperado\":4"), "{texto}");
        assert!(texto.contains("\"id_recibido\":3"), "{texto}");
    }

    /// `Parar` se atiende siempre, incluso tras descartar una respuesta atrasada y aunque el `id`
    /// que el hilo esperaba no haya llegado.
    #[test]
    fn parar_se_atiende_siempre() {
        let (_dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        tx.send(padres(0, 1)).unwrap();
        tx.send(MsgBucle::Parar).unwrap();

        let mut serv = servicio();
        assert!(matches!(
            esperar(&rx, &mut serv, 0, &registro, 9),
            Recepcion::Parar
        ));
    }

    /// Un `id` del futuro es una violación de invariante: el hilo la reporta (el llamante envía
    /// `Fallo` y termina ordenadamente), no entra en pánico.
    #[test]
    fn id_del_futuro_es_violacion() {
        let (_dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        tx.send(padres(7, 1)).unwrap();
        let mut serv = servicio();
        match esperar(&rx, &mut serv, 0, &registro, 2) {
            Recepcion::Violacion(motivo) => assert!(motivo.contains("id 7"), "{motivo}"),
            _ => panic!("se esperaba violación de invariante Padres"),
        }

        let (tx2, rx2) = mpsc::channel::<MsgBucle>();
        tx2.send(MsgBucle::Continuar { id: 7 }).unwrap();
        match esperar(&rx2, &mut serv, 0, &registro, 2) {
            Recepcion::Violacion(motivo) => assert!(motivo.contains("id 7"), "{motivo}"),
            _ => panic!("se esperaba violación de invariante Continuar"),
        }
    }

    /// `CambiarTerminal` se absorbe en el sitio: la espera se declara interrumpida y el servicio se
    /// sustituye por el nuevo.
    #[test]
    fn cambiar_terminal_se_absorbe_y_sustituye_el_servicio() {
        let (_dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        let mut nuevo = servicio();
        nuevo.avanzar().unwrap();
        tx.send(MsgBucle::CambiarTerminal(nuevo)).unwrap();

        let mut serv = servicio();
        assert_eq!(serv.slot_actual(), 0);
        assert!(matches!(
            esperar(&rx, &mut serv, 0, &registro, 0),
            Recepcion::Interrumpido
        ));
        assert_eq!(
            serv.slot_actual(),
            1,
            "el servicio se sustituyó por el nuevo"
        );
    }

    /// El canal cerrado no es un pánico: es el apagado normal.
    #[test]
    fn canal_cerrado_es_apagado_normal() {
        let (_dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        drop(tx);
        let mut serv = servicio();
        assert!(matches!(
            esperar(&rx, &mut serv, 0, &registro, 0),
            Recepcion::Cerrado
        ));
    }

    /// V2 (W08h): una frontera verificada del **mismo** terminal que va por delante del reloj se
    /// adopta (el productor salta a ella). Falla con el código de W08g, que no la enviaba nunca; el
    /// test ejerce el camino que el bucle usa al mandarla.
    #[test]
    fn una_frontera_adelantada_del_mismo_terminal_se_adopta() {
        let (_dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        let mut frontera = servicio();
        frontera.avanzar_hasta(7).unwrap();
        tx.send(MsgBucle::CambiarTerminal(frontera)).unwrap();

        let mut serv = servicio();
        // El timelord solo publicó hasta el slot 2: la frontera (7) va por delante.
        assert!(matches!(
            esperar(&rx, &mut serv, 2, &registro, 0),
            Recepcion::Interrumpido
        ));
        assert_eq!(serv.slot_actual(), 7, "el productor salta a la frontera");
    }

    /// Decisión 2 (W08h): una frontera del mismo terminal que **no** supera el último slot publicado
    /// se ignora y la espera sigue por la respuesta viva. Con el código de W08g se habría adoptado
    /// (retrocediendo el reloj) e interrumpido el intercambio.
    #[test]
    fn una_frontera_retrasada_del_mismo_terminal_se_ignora() {
        let (_dir, registro) = registro();
        let (tx, rx) = mpsc::channel::<MsgBucle>();
        let mut atras = servicio();
        atras.avanzar().unwrap(); // slot 1
        tx.send(MsgBucle::CambiarTerminal(atras)).unwrap();
        tx.send(padres(0, 11)).unwrap();

        let mut serv = servicio();
        // El timelord ya publicó hasta el slot 5: la frontera (1) no va por delante.
        match esperar(&rx, &mut serv, 5, &registro, 0) {
            Recepcion::Padres(p) => assert_eq!(p.padres.seleccionado(), h(11)),
            _ => panic!("una frontera atrasada no debe interrumpir la espera"),
        }
        assert_eq!(serv.slot_actual(), 0, "el servicio no se tocó");
    }
}

/// `ORDEN-W06d9` V2: un portador ausente (o un rango no recompletable) es una **producción
/// omitida**, no un `fallo_productor`; el evento de diagnóstico lleva slot y motivo.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "el test falla con panic por diseño"
)]
mod tests_produccion_omitida {
    use std::convert::Infallible;

    use zx_post::productor_regimen::ErrorRegimen;
    use zx_post::servicio_pot::ErrorServicioPot;

    use super::{motivo_produccion_omitida, registrar_produccion_omitida};
    use crate::registro::Registro;

    /// Un portador ausente que no se pudo recompletar es omitible (nunca `fallo_productor`).
    #[test]
    fn un_portador_ausente_es_omisible() {
        let error: ErrorRegimen<Infallible> =
            ErrorRegimen::Servicio(ErrorServicioPot::PortadorAusente { slot: 6 });
        let motivo = motivo_produccion_omitida(&error).expect("omisible");
        assert!(motivo.contains("slot 6"), "{motivo}");
    }

    /// Un rango que excede la cota de recálculo o la del formato también es omitible.
    #[test]
    fn un_rango_no_recompletable_es_omisible() {
        let rango: ErrorRegimen<Infallible> =
            ErrorRegimen::Servicio(ErrorServicioPot::RecompletarExcedeMaximo {
                sp_slot: 100,
                b_slot: 200,
                base_slot: 0,
                d: 200,
                max: 150,
            });
        assert!(motivo_produccion_omitida(&rango).is_some());

        let formato: ErrorRegimen<Infallible> =
            ErrorRegimen::RangoExcedeMaximo { d: 160, max: 150 };
        let motivo = motivo_produccion_omitida(&formato).expect("omisible");
        assert!(motivo.contains("MAX_BUNDLES_POT"), "{motivo}");
    }

    /// Un error interno real sigue siendo `fallo_productor` (no se enmascara como omisión).
    #[test]
    fn un_error_interno_no_es_omisible() {
        let error: ErrorRegimen<Infallible> = ErrorRegimen::SinPadres;
        assert!(motivo_produccion_omitida(&error).is_none());
    }

    /// El evento `produccion_omitida` se escribe con `slot` y `motivo`.
    #[test]
    fn produccion_omitida_escribe_el_evento_con_slot_y_motivo() {
        let dir = tempfile::tempdir().unwrap();
        let registro = Registro::abrir(&dir.path().join("registro.jsonl")).unwrap();
        registrar_produccion_omitida(&registro, 7, "portador ausente para el slot 6");
        let texto = std::fs::read_to_string(dir.path().join("registro.jsonl")).unwrap();
        assert!(texto.contains("\"tipo\":\"produccion_omitida\""), "{texto}");
        assert!(texto.contains("\"slot\":7"), "{texto}");
        assert!(texto.contains("portador ausente para el slot 6"), "{texto}");
    }
}
