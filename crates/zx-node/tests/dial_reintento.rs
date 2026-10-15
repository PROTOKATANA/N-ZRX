//! `ORDEN-W06d6` decisión 2: el dial de arranque reintenta con espera creciente mientras el par
//! todavía no escucha, en vez de rendirse tras un único intento.
//!
//! **Regresión**: sin el reintento (un solo `manejo.marcar` al arrancar, como en `ORDEN-W06d5` y
//! antes), este test falla — el intento único ocurre antes de que el "servidor" empiece a escuchar,
//! y nadie vuelve a intentarlo. Con el reintento (1, 2, 4… s), el dial que fallaba al principio
//! acaba conectando cuando el servidor por fin escucha.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "el test falla con panic por diseño"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use libp2p::core::transport::Transport as _;
use libp2p::{Swarm, identity, noise, tcp, yamux};
use zx_core::digest::{BlockHash, Digest};
use zx_core::red::Red;
use zx_node::red::manejador::ManejadorRed;
use zx_node::red::vista::VistaRed;
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::mensaje::{Estado, Fase, PuntaPow};
use zx_p2p::servicio::EventoRed;

/// Registro estructurado de test (`ORDEN-W07a`).
fn registro() -> (tempfile::TempDir, Arc<zx_node::registro::Registro>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = Arc::new(
        zx_node::registro::Registro::abrir(&dir.path().join("registro.jsonl")).expect("registro"),
    );
    (dir, r)
}

/// Mempool vacía sobre el estado inicial: estos tests de red no admiten transacciones.
fn mempool_prueba() -> Arc<std::sync::Mutex<zx_node::mempool::Mempool>> {
    Arc::new(std::sync::Mutex::new(zx_node::mempool::Mempool::nueva(
        zx_node::perfil::parametros_transicion_dev().expect("perfil dev"),
        zx_node::perfil::parametros_evidencia_dev(),
        zx_core::CBID_RED_DEV,
        zx_consensus::transicion::Estado::inicial(),
        zx_node::mempool::Politica::dev(),
    )))
}

fn estado_vacio(n: u8) -> Estado {
    Estado {
        hash_genesis: BlockHash::from_digest(Digest::from_bytes([n; 32])),
        red: Red::Dev,
        fase: Fase::Pow,
        punta_pow: PuntaPow {
            hash: BlockHash::from_digest(Digest::from_bytes([n; 32])),
            altura: 0,
            trabajo_acumulado: [0; 32],
        },
        terminal: None,
        puntas_post: Vec::new(),
        blue_work_virtual: [0; 32],
        longitud_registro: 0,
    }
}

/// Rango de puertos propio (distinto del de `red_tcp.rs`) para no chocar si los binarios de test
/// corren en paralelo.
fn puerto() -> u16 {
    static SIGUIENTE: AtomicU16 = AtomicU16::new(41_301);
    SIGUIENTE.fetch_add(1, Ordering::Relaxed)
}

fn swarm_tcp() -> Swarm<ZxBehaviour> {
    let clave = identity::Keypair::generate_ed25519();
    let peer_id = clave.public().to_peer_id();
    let transporte = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&clave).expect("noise"))
        .multiplex(yamux::Config::default())
        .boxed();
    let behaviour = ZxBehaviour::nueva(
        &clave,
        ParametrosRed::dag_dev(),
        zx_p2p::limites::LIMITE_BLOQUE_DEV,
    )
    .expect("behaviour");
    Swarm::new(
        transporte,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(30)),
    )
}

async fn esperar_conexion(
    ev: &mut tokio::sync::mpsc::Receiver<EventoRed>,
    plazo: Duration,
) -> bool {
    let limite = tokio::time::Instant::now() + plazo;
    loop {
        let resto = limite.saturating_duration_since(tokio::time::Instant::now());
        if resto.is_zero() {
            return false;
        }
        match tokio::time::timeout(resto, ev.recv()).await {
            Ok(Some(EventoRed::PeerConectado(_))) => return true,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Arranca un `Swarm` de juguete que **no** escucha todavía: el test decide cuándo llamar a
/// `.escuchar(...)`, simulando el par que "todavía no escucha" de la decisión 2.
fn arrancar_servidor_de_juguete() -> (
    zx_p2p::servicio::ManejoRed,
    tokio::sync::mpsc::Receiver<EventoRed>,
    tokio::task::JoinHandle<()>,
) {
    let vista = Arc::new(VistaRed::nueva(estado_vacio(9)));
    let (tx_trabajo, _rx_trabajo) = zx_node::red::nueva_cola_trabajo_red();
    let (_dir, reg) = registro();
    let manejador = Arc::new(ManejadorRed::nuevo(
        tx_trabajo,
        vista,
        reg,
        mempool_prueba(),
        // `ORDEN-RD3c`: estos tests de red no ejercen el registro de direcciones.
        Arc::new(zx_node::red::registro_direcciones::RegistroRed::nuevo(
            Red::Dev,
            zx_node::red::registro_direcciones::ConfigRegistro::APAGADO,
        )),
    ));
    let piezas = zx_p2p::servicio::arrancar(swarm_tcp(), manejador);
    let manejo = piezas.manejo;
    let eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());
    (manejo, eventos, tarea)
}

/// **Regresión de la decisión 2.** `zx_node::red::arrancar` (la ruta real de producción, con
/// reintento) marca una dirección que todavía no escucha; el servidor empieza a escuchar 2,5 s
/// después (más tarde que el intento único inicial, pero dentro de la ventana de los reintentos con
/// espera creciente 1, 2, 4…). El servidor debe ver `PeerConectado` bastante antes de que se agoten
/// los reintentos.
#[tokio::test]
async fn el_dial_reintenta_hasta_que_el_par_escucha() {
    let addr: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", puerto()).parse().unwrap();

    let (manejo_servidor, mut eventos_servidor, tarea_servidor) = arrancar_servidor_de_juguete();

    // El nodo que marca: la ruta real de `zx_node::red::arrancar`, con el reintento de la decisión
    // 2. Se arranca en un hilo aparte porque construye su propio runtime `tokio` multihilo
    // (`Builder::new_multi_thread`) y lo bloquea brevemente al marcar por primera vez.
    let vista_dial = Arc::new(VistaRed::nueva(estado_vacio(1)));
    let addr_dial = addr.clone();
    let hilo_dial = std::thread::spawn(move || {
        let (_dir, reg) = registro();
        zx_node::red::arrancar(None, vec![addr_dial], vista_dial, reg, mempool_prueba())
            .expect("arrancar (dial)")
    });

    // El servidor empieza a escuchar bastante después del intento único inicial (t=0), pero dentro
    // de la ventana de reintentos (1, 2, 4 s...): sin reintento, este dial ya se dio por vencido.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    manejo_servidor
        .escuchar(addr)
        .await
        .expect("el servidor escucha");

    let conectado = esperar_conexion(&mut eventos_servidor, Duration::from_secs(15)).await;
    assert!(
        conectado,
        "el servidor MUST ver una conexión: el dial de arranque MUST reintentar con espera \
         creciente en vez de rendirse tras el primer intento (ORDEN-W06d6 decisión 2)"
    );

    tarea_servidor.abort();
    // Unir el hilo y soltar el `RedArrancada` explícitamente: al soltarlo, su runtime `tokio` se
    // apaga y cancela sus tareas (el reintento de dial incluido). Sin esto, el hilo seguiría vivo
    // hasta que el binario de test entero terminara. Soltar un `Runtime` bloquea brevemente para
    // apagarlo, y eso no está permitido dentro de un contexto async (este test lo es): se hace en
    // un hilo bloqueante aparte.
    tokio::task::spawn_blocking(move || {
        let red_dial = hilo_dial
            .join()
            .expect("el hilo del dial no debe entrar en pánico");
        drop(red_dial);
    })
    .await
    .expect("cerrar el runtime del dial no debe entrar en pánico");
}
