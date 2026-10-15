//! `ORDEN-W06d10`: un bloque difundido **demostrablemente inválido** (`Rechazar`) desconecta y
//! penaliza al propagador, y `Ignorar` nunca penaliza.
//!
//! # Por qué TCP real y no el transporte en memoria
//!
//! La excepción de la red local (`127.0.0.0/8` → penalización por `PeerId`, no por prefijo) **solo
//! existe con direcciones IP**: el transporte en memoria no lleva IP y `LimitesPorIp` no limita ahí.
//! Por eso estas pruebas escuchan en `127.0.0.1:0` y comprueban el comportamiento observable: el
//! adversario se cae, los demás pares del **mismo** `/24` siguen conectados y uno nuevo puede
//! reconectar (señal de que el prefijo `127.0.0.0/24` **no** quedó vetado).

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::core::transport::Transport as _;
use libp2p::core::upgrade;
use libp2p::{Multiaddr, PeerId, Swarm, identity, noise, yamux};
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest, MerkleRoot, TxId};
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::limites;
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};
use zx_p2p::servicio::{EventoRed, ManejoRed};

/// `nonce` que marca el bloque que el objetivo debe rechazar (el resto se aceptan).
const NONCE_MALO: u64 = 0xDEAD_BEEF;

/// Manejador de prueba: rechaza/ignora **solo** el bloque marcado con [`NONCE_MALO`] y acepta el
/// resto; además registra cada aviso `par_penalizado`.
struct Objetivo {
    /// Qué veredicto devuelve para el bloque marcado.
    veredicto: Veredicto,
    /// Pares avisados como penalizados (`(peer, motivo, accion)`).
    penalizados: Mutex<Vec<(PeerId, String, String)>>,
    /// Bloques juzgados (para comprobar que el bloque bueno llegó al manejador).
    juzgados: Mutex<usize>,
}

impl Objetivo {
    fn nuevo(veredicto: Veredicto) -> Self {
        Self {
            veredicto,
            penalizados: Mutex::new(Vec::new()),
            juzgados: Mutex::new(0),
        }
    }

    fn penalizados(&self) -> Vec<(PeerId, String, String)> {
        self.penalizados.lock().expect("mutex").clone()
    }

    fn juzgados(&self) -> usize {
        *self.juzgados.lock().expect("mutex")
    }
}

impl ManejadorEntrante for Objetivo {
    fn estado(&self) -> Estado {
        Estado {
            hash_genesis: BlockHash::from_digest(Digest::from_bytes([0; 32])),
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: BlockHash::from_digest(Digest::from_bytes([1; 32])),
                altura: 0,
                trabajo_acumulado: [0; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [0; 32],
            longitud_registro: 0,
        }
    }

    fn bloque_difundido(&self, _id: IdDiferido, bloque: &BloqueRed) -> Veredicto {
        *self.juzgados.lock().expect("mutex") += 1;
        match bloque {
            BloqueRed::Pow { cabecera, .. } if cabecera.nonce == NONCE_MALO => self.veredicto,
            _ => Veredicto::Aceptar,
        }
    }

    fn tx_difundida(&self, _peer: libp2p::PeerId, _: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }

    fn par_penalizado(&self, peer: PeerId, motivo: &str, accion: &str) {
        self.penalizados.lock().expect("mutex").push((
            peer,
            motivo.to_string(),
            accion.to_string(),
        ));
    }
}

/// Un nodo TCP real sobre `127.0.0.1:0`, ya escuchando. Devuelve además la dirección de escucha.
struct Nodo {
    manejo: ManejoRed,
    eventos: tokio::sync::mpsc::Receiver<EventoRed>,
    peer_id: PeerId,
    direccion: Multiaddr,
    _tarea: tokio::task::JoinHandle<()>,
}

async fn nodo<M: ManejadorEntrante>(manejador: Arc<M>) -> Nodo {
    let clave = identity::Keypair::generate_ed25519();
    let peer_id = clave.public().to_peer_id();
    let transporte = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&clave).expect("noise"))
        .multiplex(yamux::Config::default())
        .boxed();
    let behaviour =
        ZxBehaviour::nueva(&clave, ParametrosRed::dag_dev(), limites::LIMITE_BLOQUE_DEV)
            .expect("behaviour dev");
    let swarm = Swarm::new(
        transporte,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(30)),
    );

    let piezas = zx_p2p::servicio::arrancar(swarm, manejador);
    let manejo = piezas.manejo;
    let mut eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());

    manejo
        .escuchar("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .await
        .expect("escuchar");
    let direccion = match esperar(&mut eventos, |e| matches!(e, EventoRed::Escuchando(_))).await {
        Some(EventoRed::Escuchando(d)) => d,
        otro => panic!("se esperaba Escuchando, llegó {otro:?}"),
    };

    Nodo {
        manejo,
        eventos,
        peer_id,
        direccion,
        _tarea: tarea,
    }
}

/// Espera al primer evento que cumpla el predicado, con tope de tiempo.
async fn esperar<F>(rx: &mut tokio::sync::mpsc::Receiver<EventoRed>, f: F) -> Option<EventoRed>
where
    F: Fn(&EventoRed) -> bool,
{
    let plazo = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let resto = plazo.saturating_duration_since(tokio::time::Instant::now());
        if resto.is_zero() {
            return None;
        }
        match tokio::time::timeout(resto, rx.recv()).await {
            Ok(Some(e)) if f(&e) => return Some(e),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

/// ¿No llega el evento buscado en `ventana`? Se usa para afirmar "no pasó".
async fn no_llega<F>(
    rx: &mut tokio::sync::mpsc::Receiver<EventoRed>,
    ventana: Duration,
    f: F,
) -> bool
where
    F: Fn(&EventoRed) -> bool,
{
    let plazo = tokio::time::Instant::now() + ventana;
    loop {
        let resto = plazo.saturating_duration_since(tokio::time::Instant::now());
        if resto.is_zero() {
            return true;
        }
        match tokio::time::timeout(resto, rx.recv()).await {
            Ok(Some(e)) if f(&e) => return false,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return true,
        }
    }
}

/// Espera a que `observador` vea las **dos** suscripciones de `peer`, para no publicar antes de que
/// la malla de gossipsub esté formada (mismo motivo que `dos_nodos.rs`).
async fn esperar_suscripciones(rx: &mut tokio::sync::mpsc::Receiver<EventoRed>, peer: PeerId) {
    let mut pow = false;
    let mut post = false;
    while !(pow && post) {
        let Some(e) = esperar(rx, |e| matches!(e, EventoRed::Suscripcion { .. })).await else {
            panic!("no llegaron las dos suscripciones de {peer}");
        };
        if let EventoRed::Suscripcion {
            peer: p,
            topico,
            suscrito: true,
        } = e
            && p == peer
        {
            pow |= topico.ends_with("/bloques/pow/2");
            post |= topico.ends_with("/bloques/post/2");
        }
    }
}

fn tx_llave(n: u8) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: OutPoint {
                prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                prev_index: 0,
            },
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::nuevo(1_000).unwrap(),
            lock: Lock::PubKey {
                pubkey: zx_core::firma::ClavePublica::desde_bytes([n; 32]),
            },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

/// Bloque PoW de fixture, con `nonce` elegible para marcar el que debe rechazarse.
fn bloque(nonce: u64) -> BloqueRed {
    BloqueRed::Pow {
        cabecera: BlockHeader {
            consensus_branch_id: 0xa8b4_66a7,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([1; 32])),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x33; 32])),
            timestamp: 1_788_480_000,
            bits: 0x1c07_fff8,
            nonce,
            height: 1,
        },
        txs: vec![tx_llave(0x11)],
        testigos: vec![vec![vec![0x66; 64]]],
    }
}

/// **Decisión 1.** Un `Rechazar` por gossip desconecta al propagador, lo puntúa y avisa al nodo
/// (`par_penalizado`); el mismo `/24` no queda vetado: un par honesto sigue conectado y uno nuevo
/// puede reconectar.
#[tokio::test]
async fn rechazar_en_gossip_desconecta_penaliza_y_no_veta_el_prefijo() {
    let objetivo = Arc::new(Objetivo::nuevo(Veredicto::Rechazar));
    let mut a = nodo(Arc::clone(&objetivo)).await;
    let direccion = a.direccion.clone();

    // Adversario y dos honestos, todos desde 127.0.0.1 (el mismo /24).
    let mut adversario = nodo(Arc::new(Objetivo::nuevo(Veredicto::Aceptar))).await;
    let mut honesto1 = nodo(Arc::new(Objetivo::nuevo(Veredicto::Aceptar))).await;
    let mut honesto2 = nodo(Arc::new(Objetivo::nuevo(Veredicto::Aceptar))).await;

    for (n, etiqueta) in [
        (&mut adversario, "adversario"),
        (&mut honesto1, "honesto1"),
        (&mut honesto2, "honesto2"),
    ] {
        n.manejo.marcar(direccion.clone()).await.expect("marcar");
        let Some(EventoRed::PeerConectado(p)) =
            esperar(&mut a.eventos, |e| matches!(e, EventoRed::PeerConectado(_))).await
        else {
            panic!("A no vio conectar a {etiqueta}");
        };
        assert_eq!(p, n.peer_id, "el conectado debe ser {etiqueta}");
        esperar_suscripciones(&mut a.eventos, p).await;
        // Y el cliente ve las suscripciones de A: así `publish` no falla localmente.
        esperar_suscripciones(&mut n.eventos, a.peer_id).await;
    }
    assert_eq!(
        objetivo.penalizados().len(),
        0,
        "aún no hay nada que penalizar"
    );

    // El adversario difunde el bloque marcado: A lo rechaza.
    adversario
        .manejo
        .difundir_bloque(&bloque(NONCE_MALO))
        .await
        .expect("difundir el bloque malo");

    let Some(EventoRed::PeerDesconectado(caido)) = esperar(&mut a.eventos, |e| {
        matches!(e, EventoRed::PeerDesconectado(_))
    })
    .await
    else {
        panic!("A debería haber desconectado al adversario");
    };
    assert_eq!(caido, adversario.peer_id);

    let penalizados = objetivo.penalizados();
    assert_eq!(penalizados.len(), 1, "un `par_penalizado` por el rechazo");
    let (par, motivo, accion) = penalizados.first().expect("un par_penalizado");
    assert_eq!(*par, adversario.peer_id);
    assert_eq!(
        motivo.as_str(),
        zx_p2p::servicio::MOTIVO_PAR_PENALIZADO_GOSSIP
    );
    assert_eq!(
        accion.as_str(),
        zx_p2p::servicio::ACCION_PAR_PENALIZADO_EXPULSION
    );

    // Los dos honestos siguen conectados: no llega su `PeerDesconectado`.
    for (n, etiqueta) in [(&honesto1, "honesto1"), (&honesto2, "honesto2")] {
        assert!(
            no_llega(&mut a.eventos, Duration::from_millis(500), |e| matches!(
                e,
                EventoRed::PeerDesconectado(p) if *p == n.peer_id
            ))
            .await,
            "{etiqueta} NO debe caer por la penalización de otro par del mismo /24"
        );
    }

    // Y un par **nuevo** en 127.0.0.1 puede reconectar: el prefijo no está vetado.
    let nuevo = nodo(Arc::new(Objetivo::nuevo(Veredicto::Aceptar))).await;
    nuevo.manejo.marcar(direccion).await.expect("marcar");
    let Some(EventoRed::PeerConectado(p)) =
        esperar(&mut a.eventos, |e| matches!(e, EventoRed::PeerConectado(_))).await
    else {
        panic!("un par nuevo de 127.0.0.1 debe poder conectar (prefijo no vetado)");
    };
    assert_eq!(p, nuevo.peer_id);
}

/// **Decisión 1, la otra mitad.** `Ignorar` (pendiente, huérfano, duplicado,
/// `ImposibleSinPenalizar`…) **nunca** desconecta ni penaliza.
#[tokio::test]
async fn ignorar_no_desconecta_ni_penaliza() {
    let objetivo = Arc::new(Objetivo::nuevo(Veredicto::Ignorar));
    let mut a = nodo(Arc::clone(&objetivo)).await;
    let direccion = a.direccion.clone();

    let mut par = nodo(Arc::new(Objetivo::nuevo(Veredicto::Aceptar))).await;
    par.manejo.marcar(direccion).await.expect("marcar");
    let Some(EventoRed::PeerConectado(p)) =
        esperar(&mut a.eventos, |e| matches!(e, EventoRed::PeerConectado(_))).await
    else {
        panic!("A no vio conectar al par");
    };
    assert_eq!(p, par.peer_id);
    esperar_suscripciones(&mut a.eventos, p).await;
    esperar_suscripciones(&mut par.eventos, a.peer_id).await;

    par.manejo
        .difundir_bloque(&bloque(NONCE_MALO))
        .await
        .expect("difundir el bloque ignorado");

    assert!(
        no_llega(&mut a.eventos, Duration::from_millis(500), |e| matches!(
            e,
            EventoRed::PeerDesconectado(_)
        ))
        .await,
        "`Ignorar` no puede desconectar a nadie"
    );
    assert!(
        objetivo.penalizados().is_empty(),
        "`Ignorar` no puede generar `par_penalizado`"
    );
    assert_eq!(objetivo.juzgados(), 1, "el bloque sí se juzgó (Ignorar)");
}
