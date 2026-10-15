//! `ORDEN-W06d2` decisión 8: prueba en proceso con transporte TCP real en `127.0.0.1`.
//!
//! Dos nodos de red reales (mismo behaviour/transporte que construye `zx_node::red::arrancar`, pero
//! con acceso directo a [`EventoRed`] en el test, en vez de dejar que
//! `zx_node::red::sync::tarea_sincronizacion` se los coma) deben conectarse de verdad sobre TCP.

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
use zx_p2p::servicio::{EventoRed, ManejoRed, arrancar};

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

fn puerto() -> u16 {
    static SIGUIENTE: AtomicU16 = AtomicU16::new(41_101);
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

/// Nodo de red de juguete: arranca el bucle, deja el receptor de eventos accesible al test (no lo
/// consume `sync`, a propósito, para poder comprobar `EventoRed::PeerConectado` directamente).
struct NodoDeJuguete {
    manejo: ManejoRed,
    eventos: tokio::sync::mpsc::Receiver<EventoRed>,
}

fn arrancar_de_juguete() -> (NodoDeJuguete, tokio::task::JoinHandle<()>) {
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
    let piezas = arrancar(swarm_tcp(), manejador);
    let manejo = piezas.manejo;
    let eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());
    (NodoDeJuguete { manejo, eventos }, tarea)
}

async fn esperar(
    ev: &mut tokio::sync::mpsc::Receiver<EventoRed>,
    f: impl Fn(&EventoRed) -> bool,
    plazo: Duration,
) -> Option<EventoRed> {
    let limite = tokio::time::Instant::now() + plazo;
    loop {
        let resto = limite.saturating_duration_since(tokio::time::Instant::now());
        if resto.is_zero() {
            return None;
        }
        match tokio::time::timeout(resto, ev.recv()).await {
            Ok(Some(e)) if f(&e) => return Some(e),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

#[tokio::test]
async fn dos_nodos_reales_sobre_tcp_se_conectan() {
    let (mut a, tarea_a) = arrancar_de_juguete();
    let (mut b, tarea_b) = arrancar_de_juguete();

    let addr: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", puerto()).parse().unwrap();
    a.manejo.escuchar(addr.clone()).await.expect("A escucha");
    assert!(
        esperar(
            &mut a.eventos,
            |e| matches!(e, EventoRed::Escuchando(_)),
            Duration::from_secs(5)
        )
        .await
        .is_some(),
        "A debe anunciar que escucha"
    );

    b.manejo.marcar(addr).await.expect("B marca a A");

    let vio_a = esperar(
        &mut a.eventos,
        |e| matches!(e, EventoRed::PeerConectado(_)),
        Duration::from_secs(10),
    )
    .await;
    let vio_b = esperar(
        &mut b.eventos,
        |e| matches!(e, EventoRed::PeerConectado(_)),
        Duration::from_secs(10),
    )
    .await;

    assert!(vio_a.is_some(), "A debe ver conectarse a B por TCP real");
    assert!(vio_b.is_some(), "B debe ver conectarse a A por TCP real");

    tarea_a.abort();
    tarea_b.abort();
}
