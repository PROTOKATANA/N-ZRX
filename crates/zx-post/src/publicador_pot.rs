//! Timelord PoT del nodo (lado productor): un hilo propio que avanza un [`ServicioPot`] **sin
//! esperar nunca a la producción** y publica cada salida ya calculada por un canal
//! (`ORDEN-W08g` decisión 1).
//!
//! # Por qué
//!
//! Hasta W08e el hilo productor del nodo calculaba la PoT y producía **en secuencia**: cada
//! conversión (auditoría + tabla PoSpace + testigo KZG + armado) alargaba el slot de pared del
//! propio nodo (`crates/zx-node/src/regimen.rs`). Con la PoT en su propio hilo, el reloj del nodo
//! avanza a su ritmo intrínseco aunque la producción sea lenta; la producción consume las salidas
//! publicadas y descarta lo que no llegue a tiempo, pero nunca frena el reloj (decisión 2).
//!
//! # Qué publica
//!
//! Por cada slot avanzado, la salida de 16 B y el portador de 128 B ya calculados. El productor los
//! inserta en su propio [`ServicioPot`] con [`ServicioPot::insertar_calculado`] (sin volver a correr
//! el AES) y produce sobre esa salida.
//!
//! # Terminal y frontera verificada
//!
//! El timelord arranca con un `ServicioPot` anclado en un terminal. Si el nodo cambia de terminal
//! seleccionado, [`Timelord::cambiar_servicio`] le entrega el nuevo servicio; el timelord lo adopta
//! en el siguiente punto de control (tras terminar el slot en curso) y sigue publicando desde ahí.
//! Cada publicación lleva su terminal para que el productor descarte las del terminal anterior.
//!
//! `ORDEN-W08h` (IPA B-22): el productor también puede entregarle la **frontera PoT verificada** del
//! **mismo** terminal (las salidas de los bloques ya admitidos, [`Timelord::saltar_a_frontera`]). El
//! timelord salta a ella solo si va **por delante** de su último slot publicado; si su propio cálculo
//! ya la alcanzó, no hace nada. Así un nodo reiniciado con retraso, o una CPU más lenta que la red,
//! sigue produciendo siguiendo la PoT verificada en vez de tener que calcularla al mismo ritmo que la
//! red (decisión 2).
//!
//! # Sin pánicos
//!
//! Un fallo del servicio (aritmética de slots o primitiva PoT) termina el hilo; el productor lo
//! detecta al cerrarse la cola y lo convierte en `fallo_productor`, nunca en un nodo que finge
//! producir sin reloj.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zx_core::BlockHash;
use zx_core::wire_dag::{POT_OUTPUT_BYTES, PotCheckpoints};

use crate::servicio_pot::ServicioPot;

/// Tope de la cola de salidas publicadas (`ORDEN-W08h`, decisión 4). El timelord **nunca** se
/// bloquea: si el productor se atrasa y la cola está llena, se descarta la salida **nueva** y el
/// reloj sigue. `64` slots ≈ 9 KiB de salidas y portadores: cubre de sobra el atraso normal (≤ 1
/// slot) y acota la memoria si el productor se queda atrás.
///
/// Se descarta la nueva, no la más antigua, para que el productor consuma **en orden**: saltarse
/// slots hacia delante podaría su `pasado` (ventana de 4096) y perdería los padres recientes de la
/// cadena. Las salidas anteriores a una frontera adoptada las descarta el propio productor sin
/// auditarlas (decisión 4).
pub const TOPE_COLA_SALIDAS: usize = 64;

/// Estado interno de la cola acotada.
#[derive(Default)]
struct EstadoCola {
    /// Salidas en espera, de la más antigua a la más reciente.
    entradas: VecDeque<SalidaPublicada>,
    /// El lado receptor se soltó (o el emisor terminó): no habrá más salidas.
    cerrada: bool,
}

/// Cola acotada de salidas publicadas por el timelord, que descarta la **nueva** cuando se llena.
///
/// Sustituye al `mpsc` ilimitado de W08g: aquel no tenía tope (observación de `REVISION-W08g.md`) y
/// una producción atascada podía hacer crecer la cola sin límite. Aquí el productor nunca frena al
/// timelord (`publicar` no bloquea nunca), que es la condición que V1 de W08g exige.
struct ColaSalidas {
    estado: Mutex<EstadoCola>,
    hay: Condvar,
}

impl ColaSalidas {
    fn nueva() -> Self {
        Self {
            estado: Mutex::new(EstadoCola::default()),
            hay: Condvar::new(),
        }
    }

    /// Bloquea el estado tolerando un `Mutex` envenenado (el timelord no entra en pánico, pero la
    /// cola no debe tumbar al productor si un test lo hiciera).
    fn bloquear(&self) -> MutexGuard<'_, EstadoCola> {
        match self.estado.lock() {
            Ok(guard) => guard,
            Err(envenenado) => envenenado.into_inner(),
        }
    }

    /// Publica una salida. Si la cola está llena descarta la **nueva** (el productor sigue leyendo en
    /// orden); si está cerrada, no hace nada. Devuelve `true` salvo si la cola está cerrada (para que
    /// el timelord deje de publicar). Nunca bloquea.
    fn publicar(&self, salida: SalidaPublicada) -> bool {
        let mut estado = self.bloquear();
        if estado.cerrada {
            return false;
        }
        if estado.entradas.len() >= TOPE_COLA_SALIDAS {
            return true;
        }
        estado.entradas.push_back(salida);
        self.hay.notify_one();
        true
    }

    /// Cierra la cola: los receptores ven `Disconnected` y el emisor deja de publicar.
    fn cerrar(&self) {
        let mut estado = self.bloquear();
        estado.cerrada = true;
        self.hay.notify_all();
    }

    /// Vacía las salidas en espera. La usa el timelord cuando adopta un **cambio de reloj**
    /// (`C-RLJ-06`) del mismo terminal: las salidas ya calculadas con el `N(s)` viejo dejan de
    /// valer y se recalculan desde la frontera verificada. No cierra la cola.
    fn vaciar(&self) {
        let mut estado = self.bloquear();
        estado.entradas.clear();
    }

    /// Espera una salida hasta `espera`. Mismos `Err` que `mpsc::Receiver::recv_timeout`.
    fn recv_timeout(&self, espera: Duration) -> Result<SalidaPublicada, RecvTimeoutError> {
        let inicio = Instant::now();
        let mut estado = self.bloquear();
        loop {
            if let Some(salida) = estado.entradas.pop_front() {
                return Ok(salida);
            }
            if estado.cerrada {
                return Err(RecvTimeoutError::Disconnected);
            }
            let restante = espera.saturating_sub(inicio.elapsed());
            if restante.is_zero() {
                return Err(RecvTimeoutError::Timeout);
            }
            let (nuevo, _) = match self.hay.wait_timeout(estado, restante) {
                Ok(par) => par,
                Err(envenenado) => envenenado.into_inner(),
            };
            estado = nuevo;
        }
    }

    /// Intenta tomar una salida sin bloquear. Mismos `Err` que `mpsc::Receiver::try_recv`.
    fn try_recv(&self) -> Result<SalidaPublicada, TryRecvError> {
        let mut estado = self.bloquear();
        if let Some(salida) = estado.entradas.pop_front() {
            return Ok(salida);
        }
        if estado.cerrada {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }
}

/// Extremo receptor de la cola acotada de salidas publicadas.
pub struct ReceptorSalidas(Arc<ColaSalidas>);

impl ReceptorSalidas {
    /// Espera la próxima salida publicada (o el fin de la cola) hasta `espera`.
    ///
    /// # Errores
    /// Los mismos que `mpsc::Receiver::recv_timeout`.
    pub fn recv_timeout(&self, espera: Duration) -> Result<SalidaPublicada, RecvTimeoutError> {
        self.0.recv_timeout(espera)
    }

    /// Toma una salida sin bloquear.
    ///
    /// # Errores
    /// Los mismos que `mpsc::Receiver::try_recv`.
    pub fn try_recv(&self) -> Result<SalidaPublicada, TryRecvError> {
        self.0.try_recv()
    }
}

impl Drop for ReceptorSalidas {
    fn drop(&mut self) {
        // Sin consumidor, el timelord deja de publicar (`publicar` devuelve `false`).
        self.0.cerrar();
    }
}

/// Cierra la cola cuando el hilo del timelord termina, sea cual sea el motivo.
struct CierreCola(Arc<ColaSalidas>);

impl Drop for CierreCola {
    fn drop(&mut self) {
        self.0.cerrar();
    }
}

/// Salida PoT ya calculada y publicada por el timelord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SalidaPublicada {
    /// Terminal del flujo PoT al que pertenece la salida.
    pub terminal: BlockHash,
    /// Slot calculado.
    pub slot: u64,
    /// Salida de 16 B del slot.
    pub salida: [u8; POT_OUTPUT_BYTES],
    /// Portador PoT de 128 B del slot.
    pub portador: PotCheckpoints,
}

/// Mandato del productor al timelord.
enum Mandato {
    /// Sustituye el servicio: cambio de terminal seleccionado o salto a la frontera verificada.
    CambiarServicio(Box<ServicioPot>),
    /// Termina en el siguiente punto de control.
    Parar,
}

/// Hilo del reloj PoT del nodo.
///
/// Se arranca con [`Timelord::arrancar`], publica por el [`ReceptorSalidas`] que devuelve y se
/// detiene al caer (su `Drop`). No hay pánicos alcanzables: un fallo del servicio cierra la cola.
pub struct Timelord {
    mandato: Sender<Mandato>,
    parar: Arc<AtomicBool>,
    slot_publicado: Arc<AtomicU64>,
    hilo: Option<JoinHandle<()>>,
}

impl Timelord {
    /// Arranca el timelord con el `servicio` dado (ya anclado en su terminal) y devuelve el
    /// manejador y el receptor de salidas publicadas, en orden creciente de `slot`.
    pub fn arrancar(servicio: ServicioPot) -> (Self, ReceptorSalidas) {
        // Soporte exclusivo de `cfg(test)`: el hilo de la prueba —y solo el suyo— puede dejar
        // preparada una puerta que se entrega al hilo del timelord para sincronizar su arranque.
        // En producción esta línea desaparece y el cuerpo es el original.
        #[cfg(test)]
        let puerta = soporte_prueba::tomar_puerta_pendiente();
        let cola = Arc::new(ColaSalidas::nueva());
        let (tx_mandato, rx_mandato) = mpsc::channel();
        let parar = Arc::new(AtomicBool::new(false));
        let slot_publicado = Arc::new(AtomicU64::new(servicio.slot_actual()));
        let hilo = {
            let parar = Arc::clone(&parar);
            let slot_publicado = Arc::clone(&slot_publicado);
            let cola_hilo = Arc::clone(&cola);
            thread::Builder::new()
                .name("zx-timelord-pot".to_string())
                .spawn(move || {
                    let _cierre = CierreCola(Arc::clone(&cola_hilo));
                    #[cfg(test)]
                    soporte_prueba::instalar_puerta(puerta);
                    bucle(servicio, &rx_mandato, &cola_hilo, &parar, &slot_publicado);
                })
        };
        let manejador = Self {
            mandato: tx_mandato,
            parar,
            slot_publicado,
            hilo: hilo.ok(),
        };
        (manejador, ReceptorSalidas(cola))
    }

    /// Último slot publicado. Se lee sin bloquear (diagnóstico y tests); el valor inicial es el
    /// `slot_actual()` del servicio con el que se arrancó.
    #[must_use]
    pub fn slot_publicado(&self) -> u64 {
        self.slot_publicado.load(Ordering::Relaxed)
    }

    /// Pide al timelord que adopte el servicio del nuevo terminal seleccionado. Si el hilo ya
    /// terminó, el envío falla en silencio: el productor lo detectará por la cola de salidas.
    pub fn cambiar_servicio(&self, servicio: ServicioPot) {
        let _ = self
            .mandato
            .send(Mandato::CambiarServicio(Box::new(servicio)));
    }

    /// Salta a la **frontera PoT verificada** `frontera` **solo si va por delante** del último slot
    /// publicado; si el cálculo propio ya la alcanzó, no hace nada (decisión 2 de `ORDEN-W08h`).
    /// Devuelve `true` si pidió el salto.
    ///
    /// El hilo del timelord vuelve a comprobar la dirección al adoptar (nunca retrocede el reloj
    /// para el mismo terminal), así que una frontera que se quede atrás entre esta comprobación y la
    /// adopción no reescribe la cola.
    pub fn saltar_a_frontera(&self, frontera: ServicioPot) -> bool {
        if frontera.slot_actual() > self.slot_publicado() {
            self.cambiar_servicio(frontera);
            true
        } else {
            false
        }
    }

    /// Pide la parada ordenada y espera al hilo.
    pub fn detener(mut self) {
        self.parar_interno();
    }

    fn parar_interno(&mut self) {
        self.parar.store(true, Ordering::Relaxed);
        let _ = self.mandato.send(Mandato::Parar);
        if let Some(hilo) = self.hilo.take() {
            let _ = hilo.join();
        }
    }
}

impl Drop for Timelord {
    fn drop(&mut self) {
        self.parar_interno();
    }
}

/// Bucle del timelord: atiende los mandatos pendientes y avanza **un** slot por vuelta.
///
/// El avance no espera a ningún consumidor: la [`ColaSalidas`] es acotada y **nunca bloquea** (si se
/// llena, descarta la salida nueva), así que la producción nunca frena el reloj (condición de
/// `ORDEN-W08g`, decisión 4 de `ORDEN-W08h`). Un fallo del servicio cierra la cola.
///
/// Al adoptar un servicio nuevo, un **terminal distinto** siempre se adopta (es otro flujo); el
/// **mismo** terminal solo si la frontera va por delante, para no retroceder el reloj.
fn bucle(
    mut servicio: ServicioPot,
    rx_mandato: &Receiver<Mandato>,
    cola: &ColaSalidas,
    parar: &AtomicBool,
    slot_publicado: &AtomicU64,
) {
    loop {
        // Soporte exclusivo de `cfg(test)`: punto de control observable una vez por vuelta para
        // que una prueba pueda pausar el cálculo. En producción la línea desaparece y el bucle es
        // el original.
        #[cfg(test)]
        soporte_prueba::punto_de_control();
        if parar.load(Ordering::Relaxed) {
            return;
        }
        match rx_mandato.try_recv() {
            Ok(Mandato::Parar) | Err(TryRecvError::Disconnected) => return,
            Ok(Mandato::CambiarServicio(nuevo)) => {
                let mut candidato = *nuevo;
                // Drenar los cambios acumulados: solo el último servicio importa.
                loop {
                    match rx_mandato.try_recv() {
                        Ok(Mandato::CambiarServicio(s)) => candidato = *s,
                        Ok(Mandato::Parar) | Err(TryRecvError::Disconnected) => return,
                        Err(TryRecvError::Empty) => break,
                    }
                }
                let mismo_terminal = candidato.terminal() == servicio.terminal();
                let reloj_cambia = candidato.reloj() != servicio.reloj();
                if !mismo_terminal
                    || candidato.slot_actual() > servicio.slot_actual()
                    || reloj_cambia
                {
                    servicio = candidato;
                    // La frontera adoptada ya está verificada por el bucle: se anota como publicada
                    // para que las decisiones de salto posteriores no la vean por delante.
                    slot_publicado.store(servicio.slot_actual(), Ordering::Relaxed);
                    // RL-2b (`C-RLJ-06`): un cambio de reloj en el **mismo** terminal invalida las
                    // salidas ya calculadas con el `N(s)` viejo; se descartan y se recalculan desde
                    // la frontera verificada con el calendario nuevo.
                    if mismo_terminal && reloj_cambia {
                        cola.vaciar();
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
        }
        let slot = match servicio.avanzar() {
            Ok(slot) => slot,
            Err(_) => return,
        };
        let (salida, portador) = match (servicio.salida_de(slot), servicio.portador_de(slot)) {
            (Ok(salida), Ok(portador)) => (salida, *portador),
            _ => return,
        };
        slot_publicado.store(slot, Ordering::Relaxed);
        let publicado = SalidaPublicada {
            terminal: servicio.terminal(),
            slot,
            salida,
            portador,
        };
        if !cola.publicar(publicado) {
            return;
        }
    }
}

/// Soporte de sincronización **exclusivo de `cfg(test)`**; desaparece por completo en producción.
///
/// No hay estado global que mezcle pruebas paralelas: la `PuertaPrueba` pendiente vive en el hilo
/// de la prueba que va a arrancar el timelord (`PUERTA_PENDIENTE`) y la activa en el hilo del
/// propio timelord (`PUERTA_ACTIVA`). Cada ejecución configura la suya. Todas las esperas tienen
/// fecha límite finita y se liberan también si el lado de la prueba cae (canal desconectado): un
/// pánico o una aserción fallida no dejan el hilo del timelord colgado ni bloquean su `Drop`.
#[cfg(test)]
mod soporte_prueba {
    use std::cell::RefCell;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::Duration;

    /// Fecha límite de la puerta: si la prueba no libera (p. ej. por pánico antes de tiempo), el
    /// hilo continúa solo y `Drop`/`join` cierran en tiempo acotado. No se renueva por mensaje.
    pub(super) const LIMITE_PUERTA: Duration = Duration::from_secs(5);

    /// Puerta de sincronización por ejecución: en el punto de control `parada` (0-based) avisa y
    /// espera permiso; el resto de puntos de control pasa sin bloquear.
    pub(super) struct PuertaPrueba {
        parada: u64,
        vistos: u64,
        aviso: Sender<()>,
        permiso: Receiver<()>,
    }

    impl PuertaPrueba {
        /// Construye la puerta y devuelve el lado de la prueba: recibe el aviso de llegada al punto
        /// de parada y envía el permiso para que el hilo continúe.
        pub(super) fn nueva(parada: u64) -> (Self, Receiver<()>, Sender<()>) {
            let (aviso, aviso_rx) = mpsc::channel();
            let (permiso_tx, permiso) = mpsc::channel();
            (
                Self {
                    parada,
                    vistos: 0,
                    aviso,
                    permiso,
                },
                aviso_rx,
                permiso_tx,
            )
        }

        /// Punto de control del hilo del timelord. En `parada` avisa y espera permiso con fecha
        /// límite finita; si el lado de la prueba ya cayó, el canal se desconecta y continúa.
        fn punto_de_control(&mut self) {
            let visto = self.vistos;
            self.vistos = self.vistos.saturating_add(1);
            if visto != self.parada {
                return;
            }
            let _ = self.aviso.send(());
            // `Ok` si la prueba libera; `Timeout`/`Disconnected` si la prueba cayó: ambos siguen.
            let _ = self.permiso.recv_timeout(LIMITE_PUERTA);
        }
    }

    thread_local! {
        /// Puerta pendiente del hilo de la prueba; `arrancar` la recoge y la entrega al timelord.
        static PUERTA_PENDIENTE: RefCell<Option<PuertaPrueba>> = const { RefCell::new(None) };
        /// Puerta activa del hilo del timelord. `None` en pruebas que no la usan.
        static PUERTA_ACTIVA: RefCell<Option<PuertaPrueba>> = const { RefCell::new(None) };
    }

    /// Deja `puerta` para la siguiente llamada a `Timelord::arrancar` **de este hilo de prueba**.
    pub(super) fn dejar_puerta_pendiente(puerta: PuertaPrueba) {
        PUERTA_PENDIENTE.with(|celda| *celda.borrow_mut() = Some(puerta));
    }

    /// `arrancar` recoge la puerta pendiente del hilo llamante (si la hay).
    pub(super) fn tomar_puerta_pendiente() -> Option<PuertaPrueba> {
        PUERTA_PENDIENTE.with(|celda| celda.borrow_mut().take())
    }

    /// El hilo del timelord instala su puerta (o `None` si la prueba no la usa).
    pub(super) fn instalar_puerta(puerta: Option<PuertaPrueba>) {
        PUERTA_ACTIVA.with(|celda| *celda.borrow_mut() = puerta);
    }

    /// Punto de control de `bucle`, llamado una vez por vuelta. Sin puerta no hace nada.
    pub(super) fn punto_de_control() {
        PUERTA_ACTIVA.with(|celda| {
            if let Some(puerta) = celda.borrow_mut().as_mut() {
                puerta.punto_de_control();
            }
        });
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
mod pruebas {
    use std::time::{Duration, Instant};

    use zx_core::BlockHash;
    use zx_core::digest::Digest;

    use super::{ReceptorSalidas, ServicioPot, Timelord, soporte_prueba};

    /// Cota global de las esperas de las pruebas: finita y no renovada por mensaje.
    const PRUEBA_LIMITE: Duration = Duration::from_secs(5);

    /// Montaje de una prueba con puerta: el timelord retenido en el punto de control `parada`, el
    /// receptor de salidas, el aviso de llegada a la parada y el permiso de continuación.
    struct Montaje {
        timelord: Timelord,
        rx: ReceptorSalidas,
        aviso: std::sync::mpsc::Receiver<()>,
        permiso: std::sync::mpsc::Sender<()>,
    }

    /// Prepara la puerta y arranca el timelord con ella; solo el hilo de esta prueba la recoge.
    fn montar(servicio: ServicioPot, parada: u64) -> Montaje {
        let (puerta, aviso, permiso) = soporte_prueba::PuertaPrueba::nueva(parada);
        soporte_prueba::dejar_puerta_pendiente(puerta);
        let (timelord, rx) = Timelord::arrancar(servicio);
        Montaje {
            timelord,
            rx,
            aviso,
            permiso,
        }
    }

    fn hash(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    /// `N = 16` (mínimo válido de `proyectar_iteraciones`): cada slot cuesta microsegundos, así que
    /// el timelord publica decenas de salidas en pocos milisegundos.
    fn servicio() -> ServicioPot {
        servicio_con(16)
    }

    /// Servicio del terminal `0x01` con `N_dev` arbitrario (múltiplo de 16, como exige la primitiva).
    fn servicio_con(n_dev: u64) -> ServicioPot {
        ServicioPot::nuevo(hash(0x01), n_dev, 4096).expect("servicio dev válido")
    }

    /// V1 (W08g): un consumidor lento (producción con muchas claves y conversión artificialmente
    /// lenta) **no** retrasa las salidas PoT publicadas. Falla con la arquitectura anterior, en la
    /// que la PoT solo avanzaba dentro del bucle de producción: allí, mientras la conversión no
    /// terminaba, no había salida nueva que publicar.
    #[test]
    fn un_consumidor_lento_no_retrasa_el_reloj() {
        let (timelord, rx) = Timelord::arrancar(servicio());
        // El consumidor solo toma una salida y después se queda «produciendo».
        let primera = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("la primera salida llega pronto");
        // Con la arquitectura de hoy, aquí no habría ningún avance más hasta consumir. El timelord
        // debe seguir publicando mientras el consumidor está bloqueado.
        std::thread::sleep(Duration::from_millis(200));
        let despues = timelord.slot_publicado();
        assert!(
            despues >= primera.slot + 3,
            "el reloj debe avanzar sin el consumidor: primera={}, despues={despues}",
            primera.slot
        );
        // El canal encoló esas salidas: se pueden drenar y son crecientes y coherentes.
        let mut anterior = primera.slot;
        let mut leidas = 1u64;
        loop {
            match rx.try_recv() {
                Ok(s) => {
                    assert!(s.slot > anterior, "slots publicados en orden creciente");
                    anterior = s.slot;
                    leidas += 1;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
        assert!(
            leidas >= 3,
            "debe haber varias salidas encoladas aunque nadie las consuma: {leidas}"
        );
    }

    /// Las salidas publicadas coinciden **byte a byte** con las de un `ServicioPot` de referencia
    /// avanzado a mano, y van en orden.
    #[test]
    fn lo_publicado_coincide_con_la_referencia() {
        let mut referencia = servicio();
        let (timelord, rx) = Timelord::arrancar(servicio());
        for esperado in 1..=5u64 {
            referencia.avanzar().expect("referencia");
            let publicada = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("salida publicada");
            assert_eq!(publicada.slot, esperado);
            assert_eq!(publicada.terminal, referencia.terminal());
            assert_eq!(
                publicada.salida,
                referencia.salida_de(esperado).expect("salida")
            );
            assert_eq!(
                publicada.portador,
                *referencia.portador_de(esperado).expect("portador")
            );
        }
        assert!(
            timelord.slot_publicado() >= 5,
            "el timelord sigue a su ritmo, sin esperar al consumidor"
        );
    }

    /// `cambiar_servicio` hace que el timelord continúe desde el nuevo terminal sin publicar más
    /// slots del anterior.
    #[test]
    fn cambiar_servicio_continua_en_el_terminal_nuevo() {
        let (timelord, rx) = Timelord::arrancar(servicio());
        let _ = rx.recv_timeout(Duration::from_secs(5)).expect("primera");
        let mut nuevo = ServicioPot::nuevo(hash(0x07), 16, 4096).expect("servicio");
        nuevo.avanzar().expect("adelanto del nuevo terminal");
        let nuevo_terminal = nuevo.terminal();
        timelord.cambiar_servicio(nuevo);
        // Tras adoptar, la primera salida nueva es del terminal nuevo y del slot siguiente.
        let mut visto = None;
        for _ in 0..1000 {
            let p = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("publicación");
            if p.terminal == nuevo_terminal {
                visto = Some(p);
                break;
            }
        }
        let p = visto.expect("el timelord adopta el terminal nuevo");
        assert_eq!(p.slot, 2, "el nuevo servicio estaba en el slot 1");
    }

    /// V1 (W08h), determinista: un timelord con 20 slots de **retraso inicial** salta a la frontera
    /// PoT **verificada** del mismo terminal (la que avanza al ritmo de la red) y publica el slot de
    /// la red en ≤ 2 slots.
    ///
    /// La puerta retiene el hilo del timelord **antes** de su primer punto de control: la solicitud
    /// de salto queda encolada cuando el hilo la atiende, así que no compite con ninguna publicación
    /// ordinaria y la **primera** salida publicada es la de la frontera. Sin la puerta, el hilo
    /// podía calcular y encolar slots ordinarios antes de atender la solicitud y el criterio viejo
    /// —leer el primer mensaje— confundía ese mensaje anterior con un fallo de salto.
    #[test]
    fn un_timelord_retrasado_alcanza_la_frontera_verificada() {
        // La red ya verificó hasta el slot 20 cuando el timelord arranca en el 0.
        let mut red = servicio();
        red.avanzar_hasta(20).expect("red");
        // Punto de control 0: el hilo queda retenido antes de calcular ningún slot.
        let Montaje {
            timelord,
            rx,
            aviso,
            permiso,
        } = montar(servicio(), 0);
        aviso
            .recv_timeout(PRUEBA_LIMITE)
            .expect("el timelord llega a la puerta");
        // El hilo está retenido: no ha avanzado su reloj ni ha publicado nada.
        assert_eq!(
            timelord.slot_publicado(),
            0,
            "arranca con 20 slots de retraso"
        );
        assert!(
            timelord.saltar_a_frontera(red.clone()),
            "la frontera verificada va por delante: debe saltar"
        );
        // Se libera después de encolar la solicitud: el hilo la atiende antes de calcular.
        permiso.send(()).expect("liberar el timelord");
        let p = rx
            .recv_timeout(PRUEBA_LIMITE)
            .expect("publicación tras el salto");
        // Frontera autenticada: mismo terminal y avance ≤ 2 slots de la red (20 → 21).
        assert_eq!(p.terminal, red.terminal(), "terminal de la frontera");
        assert!(
            (20..=22).contains(&p.slot),
            "debe alcanzar la frontera en <= 2 slots de la red: publicó {}",
            p.slot
        );
        // Publicación genuina: coincide byte a byte con el flujo de la frontera verificada.
        let mut esperado = red.clone();
        let slot = esperado.avanzar().expect("referencia de la frontera");
        assert_eq!(slot, p.slot, "la frontera avanza un slot");
        assert_eq!(
            p.salida,
            esperado.salida_de(p.slot).expect("salida genuina")
        );
        assert_eq!(
            p.portador,
            *esperado.portador_de(p.slot).expect("portador genuino")
        );
    }

    /// Control negativo de la regresión anterior: con el **mismo** montaje y la puerta en el mismo
    /// punto, pero **sin** solicitar el salto, la primera publicación es el slot ordinario 1, nunca
    /// la frontera. Si el salto se deshabilita, la regresión positiva falla en su primera aserción
    /// de frontera: no se satisface esperando a que el cálculo ordinario recorra 20 slots.
    #[test]
    fn sin_salto_el_timelord_no_alcanza_la_frontera() {
        let mut red = servicio();
        red.avanzar_hasta(20).expect("red");
        let Montaje {
            timelord: _timelord,
            rx,
            aviso,
            permiso,
        } = montar(servicio(), 0);
        aviso
            .recv_timeout(PRUEBA_LIMITE)
            .expect("el timelord llega a la puerta");
        // No se encola ninguna solicitud de salto.
        permiso.send(()).expect("liberar el timelord");
        let p = rx
            .recv_timeout(PRUEBA_LIMITE)
            .expect("publicación ordinaria");
        assert_eq!(
            p.slot, 1,
            "sin salto la primera publicación es el slot ordinario"
        );
        assert!(
            !(20..=22).contains(&p.slot),
            "sin salto no se alcanza la frontera en el primer punto de control"
        );
    }

    /// El criterio viejo leía la **primera** publicación y exigía `20..=22`. Aquí el hilo publica de
    /// forma **auténtica** un mensaje ordinario (slot 1) y queda pausado en el punto de control
    /// siguiente hasta que la prueba encola la solicitud de salto; después la atiende y alcanza la
    /// frontera **sin ocultar** los mensajes anteriores.
    ///
    /// `N` es el de desarrollo (`16`): la sincronización es por puerta, no por lentitud de cálculo,
    /// velocidad relativa de la CPU ni un `N` grande.
    #[test]
    fn el_criterio_viejo_confundia_un_mensaje_anterior_con_fallo_de_salto() {
        let mut red = servicio();
        red.avanzar_hasta(20).expect("red");
        // Punto de control 1: el hilo publica el slot ordinario 1 y se pausa antes del 2.
        let Montaje {
            timelord,
            rx,
            aviso,
            permiso,
        } = montar(servicio(), 1);
        aviso
            .recv_timeout(PRUEBA_LIMITE)
            .expect("el timelord publica el mensaje anterior y se detiene");
        // El mensaje anterior ya está encolado; el criterio viejo lo habría leído primero.
        let anterior = rx
            .recv_timeout(PRUEBA_LIMITE)
            .expect("mensaje anterior a la frontera");
        assert_eq!(
            anterior.slot, 1,
            "publicación ordinaria auténtica antes del salto"
        );
        assert!(
            anterior.slot < 20,
            "mensaje anterior al salto: {}",
            anterior.slot
        );
        assert!(
            !(20..=22).contains(&anterior.slot),
            "el criterio viejo habría rechazado un mensaje legítimo anterior"
        );
        // La solicitud se encola mientras el hilo está pausado; solo después se libera.
        assert!(
            timelord.saltar_a_frontera(red.clone()),
            "la frontera va por delante del slot ordinario"
        );
        permiso.send(()).expect("liberar el timelord");
        // Una sola cota global para alcanzar la frontera: no se renueva por mensaje.
        let limite = Instant::now() + PRUEBA_LIMITE;
        let mut frontera = None;
        while let Some(restante) = limite.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(restante) {
                Ok(p) if (20..=22).contains(&p.slot) => {
                    frontera = Some(p);
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let p = frontera.expect("la regresión alcanza la frontera tras el salto");
        let mut esperado = red.clone();
        let slot = esperado.avanzar().expect("referencia de la frontera");
        assert_eq!(p.slot, slot, "salta a la frontera en <= 1 slot siguiente");
        assert_eq!(p.terminal, esperado.terminal());
        assert_eq!(
            p.salida,
            esperado.salida_de(p.slot).expect("salida genuina")
        );
    }

    /// V2 (W08h): un timelord **más lento que la red** sigue produciendo siguiendo la frontera
    /// verificada: por cada slot nuevo de la frontera, el timelord salta y el productor puede
    /// auditarlo. El retardo se inyecta **solo en el test** (un `N_dev` mayor para el timelord,
    /// mientras la frontera se alimenta con salidas ya verificadas, que es O(1) por slot); no hay
    /// ninguna perilla de lentitud en producción.
    #[test]
    fn un_timelord_mas_lento_que_la_red_sigue_la_frontera_verificada() {
        // `N_dev` grande: el cálculo propio del timelord es lento.
        const LENTO: u64 = 262_144;
        const SLOTS: u64 = 20;
        // Salidas ya verificadas del mismo terminal (precalculadas una vez por el test).
        let mut referencia = servicio_con(LENTO);
        let mut verificadas = Vec::with_capacity(SLOTS as usize);
        for _ in 0..SLOTS {
            let slot = referencia.avanzar().expect("referencia lenta");
            let salida = referencia.salida_de(slot).expect("salida");
            let portador = *referencia.portador_de(slot).expect("portador");
            verificadas.push((slot, salida, portador));
        }
        // La red declara esas salidas ya verificadas: avanza mucho más rápido que el cálculo propio.
        let mut frontera = servicio_con(LENTO);
        let (timelord, rx) = Timelord::arrancar(servicio_con(LENTO));
        let mut saltos = 0u64;
        for (slot, salida, portador) in &verificadas {
            frontera
                .insertar_calculado(*slot, *salida, *portador)
                .expect("frontera");
            if timelord.saltar_a_frontera(frontera.clone()) {
                saltos += 1;
            }
        }
        // El timelord no pudo calcular 20 slots a `N=262144` mientras la red los declaraba, así que
        // cada slot nuevo de la frontera le pilló por detrás y pidió el salto.
        assert_eq!(
            saltos, SLOTS,
            "cada slot nuevo de la frontera provoca un salto"
        );
        // El productor puede auditar el último slot de la frontera.
        let mut visto = None;
        for _ in 0..10_000 {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(p) => {
                    if p.slot >= SLOTS {
                        visto = Some(p.slot);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let visto = visto.expect("el productor audita la frontera");
        assert!(
            visto <= SLOTS + 2,
            "sigue la frontera en <= 2 slots: publicó {visto}"
        );
    }

    /// Decisión 2 (W08h): una frontera del **mismo** terminal que no va por delante **no** retrocede
    /// el reloj. Con el código de W08g, `cambiar_servicio` la adoptaba igualmente y el timelord
    /// volvía a un slot ya publicado.
    #[test]
    fn una_frontera_retrasada_no_retrocede_el_reloj() {
        let mut red = servicio();
        red.avanzar_hasta(5).expect("red");
        let (timelord, rx) = Timelord::arrancar(red.clone());
        let mut atras = servicio();
        atras.avanzar().expect("slot 1");
        assert!(
            !timelord.saltar_a_frontera(atras),
            "no debe saltar hacia atrás en el mismo terminal"
        );
        // Aunque se entregue a mano, el hilo del timelord tampoco retrocede.
        let mut atras2 = servicio();
        atras2.avanzar().expect("slot 1");
        timelord.cambiar_servicio(atras2);
        let p = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("publicación");
        assert_eq!(
            p.slot, 6,
            "el reloj sigue desde el slot 5, no desde el 1 (W08h: no retrocede)"
        );
    }
}
