//! Red del nodo (`ORDEN-W06d2`): puente entre el bucle asíncrono de `zx-p2p` y el hilo de consenso
//! síncrono que posee `zx-cadena`/`zx-storage` (D-N07).
//!
//! Ver los submódulos para cada pieza: [`huerfanos`] (depósito acotado, decisión 3),
//! [`vista`] (instantánea de solo lectura que sirve el saludo y las peticiones de sincronización),
//! [`manejador`] ([`zx_p2p::entrante::ManejadorEntrante`] real, decisión 1) y [`sync`] (localizador
//! PoW + recorrido hacia atrás del DAG, decisión 4).

pub mod huerfanos;
pub mod manejador;
pub mod registro_direcciones;
pub mod sync;
pub mod vista;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use zx_core::BlockHash;
use zx_core::firma::ClavePublica;
use zx_p2p::entrante::IdDiferido;
use zx_p2p::mensaje::BloqueRed;
use zx_p2p::registro::EntradaRegistro;

use crate::claves::ClaveDev;
use crate::cli::OpcionesRegistro;
use crate::red::registro_direcciones::{
    ConfigRegistro, PublicacionPropia, ReenvioAlDirector, RegistroRed,
};
use crate::registro::Registro;

/// Lo que el manejador (lado asíncrono) encola para que el hilo de consenso lo procese.
///
/// El manejador **nunca** valida nada: solo mete esto en la cola y devuelve
/// [`zx_p2p::entrante::Veredicto::Diferir`] de inmediato (decisión 1). El hilo de consenso decide,
/// a su ritmo, y responde con [`zx_p2p::servicio::ManejoRed::informar_validacion_bloqueante`].
///
/// `llegada` (`ORDEN-W07a` decisión 3): instante en que el bloque llegó al nodo, capturado en el
/// lado asíncrono y transportado con el bloque para que `t_total_ns` mida desde la llegada, cola
/// incluida.
#[derive(Debug)]
pub enum TrabajoRed {
    /// Un bloque llegó por difusión (gossipsub) y su veredicto está diferido con `id`.
    BloqueDifundido {
        /// El identificador opaco a devolver.
        id: IdDiferido,
        /// El bloque, ya deserializado.
        bloque: BloqueRed,
        /// Instante de llegada al nodo.
        llegada: Instant,
    },
    /// Un bloque llegó como respuesta a una petición de sincronización (no lleva `IdDiferido`: no
    /// pasó por gossipsub, así que no hay nada que informarle a `report_message_validation_result`).
    /// Penalizar a quien lo mandó, si hace falta, es cosa de quien conduce la sincronización
    /// ([`sync`]), no de esta cola.
    BloqueDeSincronizacion {
        /// Quién lo mandó (para que la sincronización pueda desconectar si es basura).
        de: libp2p::PeerId,
        /// El bloque.
        bloque: BloqueRed,
        /// Instante de llegada al nodo.
        llegada: Instant,
    },
    /// FV-4b-N1 · un sobre de voto/certificado de finalidad llegó por el tema de votos.
    ///
    /// Los bytes son **opacos** para `zx-p2p`: los valida `zx-node` con `zx-votos` en el hilo de
    /// consenso (el manejador solo comprueba la estructura mínima).
    ///
    /// A5-c-2b · X3b: el tema global de votos queda **muerto**; el manejador honesto ya no encola
    /// esta variante (el tipo la conserva y las pruebas del manejador la construyen).
    VotoDifundido {
        /// Quién lo propagó.
        de: libp2p::PeerId,
        /// El sobre `ZXV1` sin decodificar.
        bytes: Vec<u8>,
    },
    /// A5-c-2b · X4: un **voto de red** de la subred `subred` llegó por `/<red>/votos-sub/<s>/1`.
    ///
    /// El manejador difiere el veredicto: encola el `IdDiferido` con los bytes opacos y el hilo de
    /// consenso entrega el voto al motor (`recibir_voto_subred`) y contesta a la red.
    VotoSubredDifundido {
        /// El identificador opaco a devolver tras el veredicto.
        id: IdDiferido,
        /// Subred 0-based que declara el tema.
        subred: u8,
        /// Los 248 B del `VotoRed` sin decodificar.
        bytes: Vec<u8>,
    },
    /// A5-c-2b · X5: un **agregado de subred** llegó por `/<red>/votos-agr/1`.
    ///
    /// El hilo de consenso junta todos los agregados de la vuelta en un lote y llama **una vez** a
    /// `recibir_agregados`; después contesta a la red uno a uno.
    AgregadoDifundido {
        /// El identificador opaco a devolver tras el veredicto.
        id: IdDiferido,
        /// Los bytes del agregado A3 sin decodificar.
        bytes: Vec<u8>,
    },
}

impl TrabajoRed {
    /// Tamaño estimado en bytes de este trabajo, para el tope agregado
    /// [`MAX_TRABAJO_RED_BYTES`]. No es el tamaño exacto en memoria (eso incluiría la asignación de
    /// `Vec`s internos con su capacidad, no solo su longitud), pero es el mismo orden de magnitud
    /// que ya usa `zx-p2p` para acotar el presupuesto de red (`zx_p2p::codec::bloque_a_bytes`), y
    /// **nunca** subestima: el códec serializa exactamente lo que ocuparía en el wire.
    fn tamano_estimado(&self) -> usize {
        match self {
            Self::BloqueDifundido { bloque, .. } | Self::BloqueDeSincronizacion { bloque, .. } => {
                zx_p2p::codec::bloque_a_bytes(bloque).len()
            }
            Self::VotoDifundido { bytes, .. }
            | Self::VotoSubredDifundido { bytes, .. }
            | Self::AgregadoDifundido { bytes, .. } => bytes.len(),
        }
    }
}

/// Cuántos elementos puede tener [`TrabajoRed`] en cola hacia el hilo de consenso (RI-3a #3,
/// `REVISION-RI-3a.md` hallazgo 3).
///
/// Antes era un `unbounded_channel`: 40 960 bloques de gossipsub —cada uno solo pasado por el
/// parseo del códec, sin PoW/PoAS/PoT válidos exigidos todavía— se encolaban en 16,7 ms sin que
/// nada los rechazara, mientras nadie leyera del otro extremo (confirmado,
/// `resultados-RI-3a/ri3a_cola_trabajo_sin_tope.rs`). Con tope, lo nuevo se descarta sin bloquear
/// la red: un bloque honesto descartado se recupera por la petición de padres o por la
/// sincronización por registro (decisión 1 de esta orden), nunca se pierde en silencio para
/// siempre.
pub const MAX_TRABAJO_RED: usize = 1_024;

/// Cuántos bytes (estimados, ver [`TrabajoRed::tamano_estimado`]) puede tener [`TrabajoRed`] en
/// cola a la vez, adicional al tope de elementos: un atacante podría intentar llenar la cola con
/// pocos elementos pero enormes (hasta `MAX_BLOQUE_RED_BYTES` cada uno) para agotar memoria sin
/// llegar al tope de 1 024.
pub const MAX_TRABAJO_RED_BYTES: usize = 256 * 1024 * 1024;

/// El lado que **encola** [`TrabajoRed`] hacia el hilo de consenso, acotado en elementos y en
/// bytes. Clonable: lo comparten [`manejador::ManejadorRed`] (bloques difundidos) y
/// [`sync::tarea_sincronizacion`] (bloques de sincronización).
#[derive(Clone)]
pub struct EmisorTrabajoRed {
    tx: tokio::sync::mpsc::Sender<TrabajoRed>,
    bytes_en_cola: Arc<AtomicUsize>,
}

/// Lo que puede pasar al intentar encolar un [`TrabajoRed`] (RI-3a #3).
#[derive(Debug)]
pub enum ResultadoEnvioTrabajo {
    /// Se encoló con normalidad.
    Encolado,
    /// El tope (de elementos o de bytes) está lleno: se descartó **sin bloquear**. No es que el
    /// hilo de consenso haya muerto — solo va más lento que la llegada; quien llama decide si
    /// registrarlo, nunca se tira en silencio.
    Lleno(TrabajoRed),
    /// El receptor ya no existe (el hilo de consenso terminó): no hay a quién entregarle nada más.
    Cerrado(TrabajoRed),
}

impl EmisorTrabajoRed {
    /// Intenta encolar `trabajo`. **Nunca bloquea** (`try_send`, no `send().await`).
    pub fn intentar_enviar(&self, trabajo: TrabajoRed) -> ResultadoEnvioTrabajo {
        let tamano = trabajo.tamano_estimado();
        // `fetch_update` compara-e-intercambia: dos productores concurrentes no pueden pasarse los
        // dos del tope agregado (mismo patrón que `zx_p2p::presupuesto::Presupuesto`).
        let admitido = self
            .bytes_en_cola
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |actual| {
                let nuevo = actual.checked_add(tamano)?;
                (nuevo <= MAX_TRABAJO_RED_BYTES).then_some(nuevo)
            })
            .is_ok();
        if !admitido {
            return ResultadoEnvioTrabajo::Lleno(trabajo);
        }
        match self.tx.try_send(trabajo) {
            Ok(()) => ResultadoEnvioTrabajo::Encolado,
            Err(tokio::sync::mpsc::error::TrySendError::Full(t)) => {
                // No cupo por elementos: deshacer la reserva de bytes que sí se concedió.
                self.bytes_en_cola.fetch_sub(tamano, Ordering::AcqRel);
                ResultadoEnvioTrabajo::Lleno(t)
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(t)) => {
                self.bytes_en_cola.fetch_sub(tamano, Ordering::AcqRel);
                ResultadoEnvioTrabajo::Cerrado(t)
            }
        }
    }
}

/// El lado que **drena** [`TrabajoRed`] en el hilo de consenso (síncrono, D-N07): envuelve el
/// receptor bloqueante y libera de `bytes_en_cola` lo que cada elemento reservó al encolarse.
pub struct ReceptorTrabajoRed {
    rx: tokio::sync::mpsc::Receiver<TrabajoRed>,
    bytes_en_cola: Arc<AtomicUsize>,
}

impl ReceptorTrabajoRed {
    /// Igual que `Receiver::try_recv`: no bloquea. Libera el tamaño estimado del elemento devuelto.
    pub fn try_recv(&mut self) -> Result<TrabajoRed, tokio::sync::mpsc::error::TryRecvError> {
        let trabajo = self.rx.try_recv()?;
        self.bytes_en_cola
            .fetch_sub(trabajo.tamano_estimado(), Ordering::AcqRel);
        Ok(trabajo)
    }
}

/// Construye el par (emisor, receptor) acotado de [`TrabajoRed`] (RI-3a #3).
#[must_use]
pub fn nueva_cola_trabajo_red() -> (EmisorTrabajoRed, ReceptorTrabajoRed) {
    let (tx, rx) = tokio::sync::mpsc::channel(MAX_TRABAJO_RED);
    let bytes_en_cola = Arc::new(AtomicUsize::new(0));
    (
        EmisorTrabajoRed {
            tx,
            bytes_en_cola: Arc::clone(&bytes_en_cola),
        },
        ReceptorTrabajoRed { rx, bytes_en_cola },
    )
}

/// Un límite de recursión declarado para el recorrido hacia atrás del DAG (decisión 3 y 4): cuántos
/// saltos de "pide al padre que falta" se permiten antes de darse por vencido con esa rama. Evita
/// una cascada sin fin si un par miente sobre una cadena de padres arbitrariamente larga.
pub const LIMITE_SALTOS_RECORRIDO_ATRAS: u32 = 4096;

/// Cuántos huérfanos puede tener el depósito en total (decisión 3).
///
/// Valor dev: generoso para no penalizar una ráfaga honesta durante IBD, acotado para no crecer sin
/// límite. 🔶 Revisable con medición real (W07).
pub const MAX_HUERFANOS_TOTAL: usize = 4_096;

/// Cuántos huérfanos puede tener el depósito esperando al **mismo** padre.
pub const MAX_HUERFANOS_POR_PADRE: usize = 64;

/// `ORDEN-W06d6` decisión 1: mientras el cursor de sincronización esté a más de esto (en bloques)
/// de la `longitud_registro` de algún par, un bloque PoST de **gossip** cuyo padre falte se
/// descarta en vez de depositarse como huérfano (llegará por el registro). Es la vía **principal**
/// de puesta al día; la resolución por padres se queda para los huecos pequeños, por debajo de este
/// umbral.
pub const UMBRAL_SINCRONIZANDO: u64 = 64;

/// Construye el depósito de huérfanos con los topes de producción declarados arriba.
#[must_use]
pub fn nuevo_deposito_huerfanos() -> huerfanos::DepositoHuerfanos {
    huerfanos::DepositoHuerfanos::nuevo(MAX_HUERFANOS_TOTAL, MAX_HUERFANOS_POR_PADRE)
}

/// Los tres hashes de un bloque que hacen falta para decidir si es huérfano, ya extraídos de
/// [`BloqueRed`] sin tocar consenso (`zx-p2p` no expone `padres()`, así que se replica aquí lo
/// mínimo: el padre PoW o los padres PoST declarados).
#[must_use]
pub fn padres_declarados(bloque: &BloqueRed) -> Vec<BlockHash> {
    match bloque {
        BloqueRed::Pow { cabecera, .. } => {
            if cabecera.height == 0 {
                Vec::new()
            } else {
                vec![cabecera.prev_hash]
            }
        }
        BloqueRed::Post { cabecera, .. } => {
            let p = &cabecera.padres;
            if p.es_genesis() {
                Vec::new()
            } else {
                let mut v = vec![p.seleccionado()];
                v.extend_from_slice(p.extras());
                v
            }
        }
    }
}

/// Hash del bloque, sin depender de a qué familia pertenece.
#[must_use]
pub fn hash_de(bloque: &BloqueRed) -> BlockHash {
    match bloque {
        BloqueRed::Pow { cabecera, .. } => cabecera.block_hash(),
        BloqueRed::Post { cabecera, .. } => cabecera.block_hash(),
    }
}

/// Handle compartido hacia la red, más los canales por los que el hilo de consenso recibe trabajo y
/// eventos de sincronización. Construido por [`crate::nodo::Nodo`] al arrancar con red.
pub struct ManijaRed {
    /// Para hablarle a `zx-p2p` desde el hilo de consenso (métodos bloqueantes o vía `runtime`).
    pub manejo: zx_p2p::servicio::ManejoRed,
    /// El `Handle` del runtime `tokio` que corre el bucle de `zx-p2p`, para los métodos de
    /// `ManejoRed` que sólo existen en versión `async` (`pedir`, `desconectar`, `difundir_bloque`).
    pub runtime: tokio::runtime::Handle,
    /// Instantánea compartida que sirve el saludo y las respuestas de sincronización.
    pub vista: Arc<vista::VistaRed>,
    /// RD-4b · P1: el registro firmado de direcciones está encendido. Sin él no hay sorteo ni tabla
    /// de pesos que entregar, así que el nodo no consulta la cadena.
    registro_activo: bool,
    /// RD-4b · P3: tablas de pesos descartadas por canal de comandos lleno (diagnóstico).
    tablas_descartadas: Arc<AtomicU64>,
}

impl ManijaRed {
    /// Difunde un bloque propio. Bloqueante: se llama desde el hilo de consenso.
    pub fn difundir_bloque(&self, bloque: &BloqueRed) -> Result<(), zx_p2p::error::P2pError> {
        self.runtime.block_on(self.manejo.difundir_bloque(bloque))
    }

    /// Difunde una transacción propia ya serializada (`tx_a_bytes`) por el tema de tx
    /// (`ORDEN-TX3`). Bloqueante: se llama desde el hilo de consenso.
    pub fn difundir_tx(&self, bytes: &[u8]) -> Result<(), zx_p2p::error::P2pError> {
        self.runtime.block_on(self.manejo.difundir_tx(bytes))
    }

    /// FV-4b-N1 · Difunde un sobre de voto/certificado por el tema de votos. Bloqueante: se llama
    /// desde el hilo de consenso.
    pub fn difundir_voto(&self, bytes: &[u8]) -> Result<(), zx_p2p::error::P2pError> {
        self.runtime.block_on(self.manejo.difundir_voto(bytes))
    }

    /// A5-c-2b · X3 · Difunde un **voto de red** por el tema de su subred `s` (0-based). Bloqueante:
    /// se llama desde el hilo de consenso.
    pub fn difundir_voto_subred(&self, s: u8, bytes: &[u8]) -> Result<(), zx_p2p::error::P2pError> {
        self.runtime
            .block_on(self.manejo.difundir_voto_subred(s, bytes))
    }

    /// A5-c-2b · X6 · Difunde un **agregado** por el tema común de agregados. Bloqueante.
    pub fn difundir_agregado(&self, bytes: &[u8]) -> Result<(), zx_p2p::error::P2pError> {
        self.runtime.block_on(self.manejo.difundir_agregado(bytes))
    }

    /// A5-c-2b · X2 · Suscribe este nodo a las subredes de voto `subredes` (0-based). Sin llamadas,
    /// el nodo no recibe votos sueltos de ninguna subred.
    pub fn suscribir_subredes(&self, subredes: &[u8]) {
        for &s in subredes {
            if let Err(e) = self.runtime.block_on(self.manejo.suscribir_subred(s)) {
                tracing::warn!(%e, subred = s, "no se pudo suscribir a una subred de voto");
            }
        }
    }

    /// A5-c-2b · X7 · Fija el cupo de diferidos de los dos temas nuevos. Bloqueante.
    ///
    /// # Errores
    /// Los de [`zx_p2p::servicio::ManejoRed::fijar_cupo_diferidos_agregacion`].
    pub fn fijar_cupo_diferidos_agregacion(
        &self,
        cupo: usize,
    ) -> Result<(), zx_p2p::error::P2pError> {
        self.runtime
            .block_on(self.manejo.fijar_cupo_diferidos_agregacion(cupo))
    }

    /// Pide algo a un par. Bloqueante.
    pub fn pedir(&self, peer: libp2p::PeerId, peticion: zx_p2p::mensaje::Peticion) {
        if let Err(e) = self.runtime.block_on(self.manejo.pedir(peer, peticion)) {
            tracing::debug!(%e, "no se pudo encolar una petición de sincronización");
        }
    }

    /// Corta con un par por un motivo dado. Bloqueante.
    pub fn desconectar(&self, peer: libp2p::PeerId, motivo: zx_p2p::error::MotivoDesconexion) {
        let _ = self.runtime.block_on(self.manejo.desconectar(peer, motivo));
    }

    /// Informa el veredicto final de una validación diferida. Ya es bloqueante de por sí (no hace
    /// falta `runtime.block_on`, ver `informar_validacion_bloqueante`).
    pub fn informar_validacion(&self, id: IdDiferido, veredicto: zx_p2p::entrante::VeredictoFinal) {
        if let Err(e) = self.manejo.informar_validacion_bloqueante(id, veredicto) {
            tracing::debug!(%e, "no se pudo informar el veredicto diferido");
        }
    }

    /// RD-4b · P1/P3: fija la tabla de pesos del director (`productor → bloques certificados`)
    /// **sin esperar**. Si el canal de comandos del bucle de red está lleno, la tabla se descarta,
    /// se cuenta, y el siguiente cambio de ancla la vuelve a mandar. Devuelve `true` si se encoló.
    ///
    /// Ya no es bloqueante: un consenso parado esperando a que la red drene su canal era el defecto
    /// que corrige P3.
    pub fn fijar_tabla_pesos(&self, pesos: Vec<(ClavePublica, u64)>) -> bool {
        if self.manejo.intentar_fijar_tabla_pesos(pesos) {
            true
        } else {
            self.tablas_descartadas.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// RD-4b · P1: ¿está encendido el registro firmado de direcciones? Sin él no hay sorteo.
    #[must_use]
    pub const fn registro_activo(&self) -> bool {
        self.registro_activo
    }

    /// RD-4b · P3: cuántas tablas de pesos se descartaron por canal lleno.
    #[must_use]
    pub fn tablas_descartadas(&self) -> u64 {
        self.tablas_descartadas.load(Ordering::Relaxed)
    }

    /// RD-4a · H2/H3: entrega una entrada del registro firmado al director, que la revalida (forma,
    /// época y firma). Bloqueante: se llama desde el hilo de consenso. El reloj es el de pared local.
    ///
    /// # Errores
    /// Los de [`zx_p2p::servicio::ManejoRed::insertar_registro`].
    pub fn insertar_registro(
        &self,
        entrada: EntradaRegistro,
    ) -> Result<(), zx_p2p::error::P2pError> {
        let ahora = registro_direcciones::unix_ahora();
        self.runtime
            .block_on(self.manejo.insertar_registro(entrada, ahora))
    }

    /// RD-4a · H2/H3: marca (`Some`) o quita (`None`) la saliente protegida del director.
    /// Bloqueante: se llama desde el hilo de consenso.
    ///
    /// # Errores
    /// Los de [`zx_p2p::servicio::ManejoRed::proteger_saliente`].
    pub fn proteger_saliente(
        &self,
        peer: Option<libp2p::PeerId>,
    ) -> Result<(), zx_p2p::error::P2pError> {
        self.runtime.block_on(self.manejo.proteger_saliente(peer))
    }
}

/// RD-4a · H3 · puente de producción: encola cada entrada aceptada por el [`RegistroRed`] para que
/// el bucle de red la entregue al director con la orden `InsertarRegistro` (H2).
///
/// RD-4b · P4: el canal es **acotado** (`max_pendientes` de [`ConfigRegistro`]). Lleno no bloquea:
/// se cuenta el descarte y se marca `resincronizar`; la tarea de vaciado, cuando ha vaciado,
/// vuelve a entregar al director **todas** las entradas vigentes del registro del nodo.
struct ReenvioManejoRed {
    tx: tokio::sync::mpsc::Sender<EntradaRegistro>,
    /// Marcado por el productor cuando el canal está lleno; lo consume la tarea de vaciado.
    resincronizar: Arc<AtomicBool>,
    /// Entradas descartadas por canal lleno (diagnóstico).
    descartadas: Arc<AtomicU64>,
}

impl ReenvioAlDirector for ReenvioManejoRed {
    fn insertar_registro(&self, entrada: &EntradaRegistro) {
        match self.tx.try_send(entrada.clone()) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // No bloquea y no pierde: la entrada ya está en el `RegistroRed`; la
                // resincronización la volverá a entregar. Se cuenta y se marca.
                self.resincronizar.store(true, Ordering::Release);
                self.descartadas.fetch_add(1, Ordering::Relaxed);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // La tarea de vaciado ya no existe: nada que hacer.
            }
        }
    }
}

/// RD-4b · P4: reenvía al director todas las entradas vigentes del registro del nodo. Es lo que la
/// tarea de vaciado ejecuta (con `await`) cuando ha vaciado el canal y había un descarte pendiente.
#[cfg(test)]
fn entradas_a_resincronizar(registro: &RegistroRed) -> Vec<EntradaRegistro> {
    registro.entradas_vigentes()
}

/// Todo lo que arranca la red de un nodo (`ORDEN-W06d2`): el runtime `tokio` (que hay que
/// mantener vivo mientras el nodo corra: soltarlo para el bucle y la sincronización), la
/// [`ManijaRed`] a entregarle a [`crate::nodo::Nodo::conectar_red`] y el receptor de trabajo.
pub struct RedArrancada {
    /// **No soltar** mientras el nodo esté vivo: al soltarse, `tokio` cancela sus tareas.
    pub runtime: tokio::runtime::Runtime,
    /// Para `Nodo::conectar_red`.
    pub manija: ManijaRed,
    /// Para `Nodo::conectar_red`.
    pub trabajo: ReceptorTrabajoRed,
    /// `PeerId` de libp2p de este nodo (texto), para el `arranque` del registro.
    pub peer_id: String,
}

/// `ORDEN-RD3c` N5: la publicación propia (clave de productor, dirección de escucha e intervalo de
/// republicación) a partir de las opciones de arranque. `None` si el registro o la publicación
/// están apagados, o si no hay dirección de escucha que anunciar.
fn publicacion_propia(
    opciones: &crate::cli::OpcionesRegistro,
    escuchar: Option<&libp2p::Multiaddr>,
    config: ConfigRegistro,
) -> Option<PublicacionPropia> {
    if !config.activo || !config.publicar {
        return None;
    }
    let direccion = escuchar?.clone();
    let indice = *opciones.indices_claves.first()?;
    Some(PublicacionPropia {
        productor: ClaveDev::derivar(opciones.semilla, indice),
        direcciones: vec![direccion],
        intervalo: std::time::Duration::from_secs(crate::perfil::REGISTRO_REPUBLICACION_S),
    })
}

/// Construye el transporte TCP real (decisión 8 de la orden: `127.0.0.1` en pruebas, cualquier
/// dirección en un despliegue), el behaviour de la red dev, y arranca el bucle y la tarea de
/// sincronización en un runtime `tokio` nuevo. Escucha en `escuchar` (si se da) y marca cada
/// dirección de `marcar`. `registro` es el registro estructurado compartido (`ORDEN-W07a`): la
/// tarea de sincronización escribe allí los eventos de par y el manejador, los límites de cola.
///
/// # Errores
/// [`zx_p2p::error::P2pError`] si el behaviour o el transporte no se pueden construir; un error
/// libre si el runtime `tokio` no arranca (out-of-resources, no un caso de test).
pub fn arrancar(
    escuchar: Option<libp2p::Multiaddr>,
    marcar: Vec<libp2p::Multiaddr>,
    vista: Arc<vista::VistaRed>,
    registro: Arc<Registro>,
    mempool: Arc<std::sync::Mutex<crate::mempool::Mempool>>,
) -> Result<RedArrancada, String> {
    // El directorio de datos del nodo no llega hasta esta firma (la fija `main.rs`, fuera del
    // alcance de RED-2). Se lee de `ZX_RED_DATOS` si el lanzador lo fija; si no, el gestor vive
    // solo en memoria. Ver `PROGRESO.md`.
    let dir_datos = std::env::var_os("ZX_RED_DATOS").map(std::path::PathBuf::from);
    // RD-4b · P5: la vía de `arrancar` (solo un test la usa) no recibe opciones; arranca con el
    // registro apagado, que es el valor por defecto.
    arrancar_con_datos(
        escuchar,
        marcar,
        vista,
        registro,
        dir_datos,
        mempool,
        OpcionesRegistro::apagado(),
    )
}

/// Igual que [`arrancar`], con el directorio de datos del gestor explícito (para pruebas y para un
/// arranque con persistencia de anclas y de `probados`).
///
/// Es la llamada a [`arrancar_con_manejador`] con la **identidad** como envoltorio: el manejador
/// que atiende la red es el [`manejador::ManejadorRed`] real, sin envolver. El cuerpo de arranque
/// (runtime `tokio`, `Swarm`, registro de direcciones, publicación propia y tarea de
/// sincronización) vive **una sola vez**, en [`arrancar_con_manejador`].
///
/// # Errores
/// Los de [`arrancar_con_manejador`].
pub fn arrancar_con_datos(
    escuchar: Option<libp2p::Multiaddr>,
    marcar: Vec<libp2p::Multiaddr>,
    vista: Arc<vista::VistaRed>,
    registro: Arc<Registro>,
    dir_datos: Option<std::path::PathBuf>,
    mempool: Arc<std::sync::Mutex<crate::mempool::Mempool>>,
    opciones: OpcionesRegistro,
) -> Result<RedArrancada, String> {
    arrancar_con_manejador(
        escuchar,
        marcar,
        vista,
        registro,
        dir_datos,
        mempool,
        opciones,
        |real| real,
    )
}

/// Igual que [`arrancar_con_datos`], pero el [`zx_p2p::entrante::ManejadorEntrante`] que atiende la
/// red no es directamente el [`manejador::ManejadorRed`] real: `envolver` recibe el manejador real
/// recién construido y devuelve el manejador que usará `zx-p2p`.
///
/// Es el *seam* que permite que un binario aparte (p. ej. `zx-censor`, `ORDEN-AD2-2`) altere el
/// veredicto de un mensaje concreto **sin tocar el camino honesto**: el [`manejador::ManejadorRed`]
/// que se construye aquí es exactamente el mismo que el de [`arrancar_con_datos`] (misma cola,
/// misma vista, mismo registro, misma mempool y mismo registro de direcciones), y el envoltorio
/// solo decide qué hacer con los métodos que le interesan; el resto los delega en el real.
/// `zx-node` (el binario real) no llama a esta función: su arranque sigue siendo
/// [`arrancar_con_datos`], que la llama con la identidad.
///
/// # Errores
/// [`zx_p2p::error::P2pError`] si el behaviour o el transporte no se pueden construir; un error
/// libre si el runtime `tokio` no arranca (out-of-resources, no un caso de test).
#[expect(
    clippy::too_many_arguments,
    reason = "cuerpo único de arranque de la red; el parámetro del registro (RD-4b) añade uno más"
)]
pub fn arrancar_con_manejador<M, F>(
    escuchar: Option<libp2p::Multiaddr>,
    marcar: Vec<libp2p::Multiaddr>,
    vista: Arc<vista::VistaRed>,
    registro: Arc<Registro>,
    dir_datos: Option<std::path::PathBuf>,
    mempool: Arc<std::sync::Mutex<crate::mempool::Mempool>>,
    opciones: OpcionesRegistro,
    envolver: F,
) -> Result<RedArrancada, String>
where
    M: zx_p2p::entrante::ManejadorEntrante,
    F: FnOnce(Arc<manejador::ManejadorRed>) -> Arc<M>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime tokio: {e}"))?;

    let clave = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = clave.public().to_peer_id().to_string();
    let behaviour = zx_p2p::behaviour::ZxBehaviour::nueva(
        &clave,
        zx_p2p::config::ParametrosRed::dag_dev(),
        zx_p2p::limites::LIMITE_BLOQUE_DEV,
    )
    .map_err(|e| format!("behaviour de red: {e}"))?;

    // Construcción síncrona (ninguno de estos métodos de `SwarmBuilder` es `async`): un cierre sin
    // argumentos con el tipo de retorno anotado, para que el `?` de `with_tcp` no confunda al
    // compilador con el `Result<_, Infallible>` de `with_behaviour` (`TryIntoBehaviour<B> for B`
    // tiene `Error = Infallible`: no hay nada que manejar salvo el `match` exhaustivo de abajo).
    let construir_swarm = || -> Result<libp2p::Swarm<zx_p2p::behaviour::ZxBehaviour>, String> {
        let builder = libp2p::SwarmBuilder::with_existing_identity(clave)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| format!("transporte TCP: {e}"))?;
        let builder = match builder.with_behaviour(|_| behaviour) {
            Ok(b) => b,
            Err(nunca) => match nunca {},
        };
        Ok(builder
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(std::time::Duration::from_secs(30))
            })
            .build())
    };
    let swarm = construir_swarm()?;

    let (tx_trabajo, rx_trabajo) = nueva_cola_trabajo_red();
    // `ORDEN-RD3c` (N1): el registro de direcciones queda apagado por defecto; solo una opción de
    // arranque lo enciende. El estado compartido lo lee el manejador para servir la página (N2) y
    // lo escriben la tarea de sincronización (N4) y la publicación propia (N5).
    // RD-4b · P5: las opciones llegan **ya parseadas** desde `main.rs` (o `zx-censor`), no se
    // releen los argumentos del proceso.
    let config_registro = if opciones.activo {
        ConfigRegistro::encendido(opciones.publicar)
    } else {
        ConfigRegistro::APAGADO
    };
    let registro_direcciones = Arc::new(RegistroRed::nuevo(vista.estado().red, config_registro));

    // `ORDEN-AD2-2` E1: **único** cuerpo. El manejador real se construye aquí una vez; `envolver`
    // decide qué manejador (el mismo, o uno que lo envuelve) atiende la red. `zx-node` pasa la
    // identidad y obtiene exactamente el arranque de siempre.
    let real = Arc::new(manejador::ManejadorRed::nuevo(
        tx_trabajo.clone(),
        Arc::clone(&vista),
        Arc::clone(&registro),
        mempool,
        Arc::clone(&registro_direcciones),
    ));
    let manejador = envolver(real);
    // RD-4b · P6: el registro del director se enciende con la misma opción que el del nodo; así el
    // director sortea por producción certificada (si no, `sortear_candidata` sale sin más).
    let piezas = zx_p2p::servicio::arrancar_con_registro(swarm, manejador, config_registro.activo);
    let manejo = piezas.manejo;

    // RD-4a · H3 / RD-4b · P4: puente del `RegistroRed` del nodo al registro del director de
    // `zx-p2p`. Cada entrada que el registro acepta se encola en un canal **acotado** por
    // `max_pendientes` y esta tarea la entrega con la orden `InsertarRegistro` (H2). Con el canal
    // lleno no se bloquea ni se pierde: se marca `resincronizar` y, cuando la tarea ha vaciado,
    // vuelve a entregar al director **todas** las entradas vigentes (el director descarta las
    // repetidas: `RegistroDirecciones::insertar` devuelve `Err(EpocaNoCreciente)`,
    // `crates/zx-p2p/src/registro.rs:565`). Con el registro apagado no se acepta ninguna.
    let (tx_reenvio, mut rx_reenvio) =
        tokio::sync::mpsc::channel::<EntradaRegistro>(config_registro.max_pendientes);
    let resincronizar = Arc::new(AtomicBool::new(false));
    let descartadas = Arc::new(AtomicU64::new(0));
    registro_direcciones.conectar_reenvio(Arc::new(ReenvioManejoRed {
        tx: tx_reenvio,
        resincronizar: Arc::clone(&resincronizar),
        descartadas: Arc::clone(&descartadas),
    }));
    let manejo_para_director = manejo.clone();
    let registro_para_resync = Arc::clone(&registro_direcciones);
    runtime.spawn(async move {
        while let Some(entrada) = rx_reenvio.recv().await {
            let ahora = registro_direcciones::unix_ahora();
            if let Err(e) = manejo_para_director.insertar_registro(entrada, ahora).await {
                tracing::debug!(%e, "no se pudo reenviar una entrada al director");
            }
            // P4: el canal está vacío y hubo un descarte: se vuelven a entregar todas las entradas
            // vigentes al director (no por el canal, para no realimentar el descarte).
            if rx_reenvio.is_empty() && resincronizar.swap(false, Ordering::AcqRel) {
                for e in registro_para_resync.entradas_vigentes() {
                    let ahora = registro_direcciones::unix_ahora();
                    if let Err(err) = manejo_para_director.insertar_registro(e, ahora).await {
                        tracing::debug!(%err, "no se pudo reenviar una entrada de la resincronización");
                    }
                }
            }
        }
    });

    // `ORDEN-RD3c` N5: firma y retiene la entrada propia al arrancar (si toca publicar). Se
    // republica cada `REGISTRO_REPUBLICACION_S` desde la tarea de sincronización.
    let publicacion = publicacion_propia(&opciones, escuchar.as_ref(), config_registro);
    if let Some(p) = &publicacion {
        let ahora = registro_direcciones::unix_ahora();
        match registro_direcciones.publicar_propia(&p.productor, &p.direcciones, ahora) {
            Ok(true) => {
                let evento = registro
                    .evento("registro_direccion_publicada")
                    .u64("epoch", ahora);
                let _ = registro.escribir(evento, false);
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(%e, "no se pudo publicar la entrada propia del registro de direcciones");
            }
        }
    }

    runtime.spawn(piezas.bucle.correr());
    runtime.spawn(sync::tarea_sincronizacion(
        piezas.eventos,
        manejo.clone(),
        Arc::clone(&vista),
        tx_trabajo,
        registro,
        Arc::clone(&registro_direcciones),
        publicacion,
    ));

    if let Some(addr) = escuchar {
        runtime
            .block_on(manejo.escuchar(addr))
            .map_err(|e| format!("escuchar: {e}"))?;
    }
    // C-NET-34: `--red-marcar` es **solo el arranque**. El gestor de direcciones y el director
    // toman el relevo (descubrimiento, sondeo, renovación); ya no hay redial sin fin de la lista.
    if let Err(e) = runtime.block_on(manejo.sembrar(dir_datos, marcar)) {
        tracing::warn!(%e, "no se pudo sembrar el gestor de direcciones");
    }

    Ok(RedArrancada {
        manija: ManijaRed {
            manejo,
            runtime: runtime.handle().clone(),
            vista,
            registro_activo: config_registro.activo,
            tablas_descartadas: descartadas,
        },
        runtime,
        trabajo: rx_trabajo,
        peer_id,
    })
}

/// RD-4b · seam de prueba (P3): un `ManijaRed` real construido con un `ManejoRed` cuyo canal de
/// comandos no tiene bucle (lo provee `zx_p2p::servicio::manejo_sin_bucle`). Permite ejercitar
/// `fijar_tabla_pesos` sin red real.
#[cfg(test)]
pub(crate) fn manija_de_prueba(
    manejo: zx_p2p::servicio::ManejoRed,
    runtime: tokio::runtime::Handle,
    vista: Arc<vista::VistaRed>,
    registro_activo: bool,
) -> ManijaRed {
    ManijaRed {
        manejo,
        runtime,
        vista,
        registro_activo,
        tablas_descartadas: Arc::new(AtomicU64::new(0)),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::*;
    use crate::red::registro_direcciones::construir_entrada_propia;
    use zx_core::red::Red;

    fn dir_prueba(ip: &str) -> libp2p::Multiaddr {
        format!("/ip4/{ip}/tcp/9833").parse().unwrap()
    }

    /// **RD-4b · P4.** Con el canal del puente lleno, `insertar` **no bloquea**, cuenta el descarte
    /// y marca `resincronizar`; la resincronización vuelve a entregar **todas** las entradas
    /// vigentes (incluida la descartada), sin perder ninguna.
    #[test]
    fn rd4b_puente_lleno_no_bloquea_y_resincroniza() {
        let capacidad = 2usize;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<EntradaRegistro>(capacidad);
        let resincronizar = Arc::new(AtomicBool::new(false));
        let descartadas = Arc::new(AtomicU64::new(0));
        let puente = Arc::new(ReenvioManejoRed {
            tx,
            resincronizar: Arc::clone(&resincronizar),
            descartadas: Arc::clone(&descartadas),
        });
        let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(true));
        reg.conectar_reenvio(puente);

        let ahora = 1_000u64;
        for i in 0..(capacidad + 1) {
            let clave = ClaveDev::derivar(1, u32::try_from(i).unwrap());
            let e = construir_entrada_propia(&clave, &[dir_prueba("10.0.0.1")], ahora, Red::Dev);
            let inicio = std::time::Instant::now();
            let _ = reg.insertar(e, ahora);
            assert!(
                inicio.elapsed() < std::time::Duration::from_secs(1),
                "el puente lleno no debe bloquear"
            );
        }
        assert!(
            resincronizar.load(Ordering::Acquire),
            "el descarte marca resincronizar"
        );
        assert_eq!(
            descartadas.load(Ordering::Relaxed),
            1,
            "se cuenta el descarte"
        );

        let mut encoladas = 0usize;
        while rx.try_recv().is_ok() {
            encoladas += 1;
        }
        assert_eq!(encoladas, capacidad, "las primeras sí entraron");

        let mut entregadas = 0usize;
        for _ in entradas_a_resincronizar(&reg) {
            entregadas += 1;
        }
        assert_eq!(
            entregadas,
            capacidad + 1,
            "la resincronización entrega todas las vigentes, incluida la descartada"
        );
    }
}
