//! Humo ZRX-C de **4 nodos** sobre transporte en memoria (`MemoryTransport`).
//!
//! Mide los bytes que el nodo A **envía** por gossip con y sin ZRX-C (contadores
//! [`zx_p2p::zrxc::Metricas`], que el nodo lleva de verdad en el camino de publicación) y
//! comprueba que los 4 nodos acaban con el **mismo estado** (mismos bloques y transacciones).
//!
//! El transporte es en memoria, así que la cifra es de **capa de aplicación** (payload de gossip),
//! no del framing TCP; el arnés real de 4 nodos hace la comprobación con `zx-node` en `MEDIDA.log`.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use libp2p::core::transport::{MemoryTransport, Transport};
use libp2p::core::upgrade;
use libp2p::{Multiaddr, Swarm, identity, noise, yamux};
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot, TxId};
use zx_core::preimage::block::BlockHeader;
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_core::red::Red;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_core::wire_dag::{JustificacionPot, PotCheckpoints};
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::limites;
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};
use zx_p2p::presupuesto::Presupuesto;
use zx_p2p::servicio::{EventoRed, Piezas, arrancar_con};

/// Manejador de juguete: cuenta lo que llega y **no juzga**.
#[derive(Default)]
struct Contador {
    bloques: AtomicUsize,
    txs: AtomicUsize,
}

impl ManejadorEntrante for Contador {
    fn estado(&self) -> Estado {
        Estado {
            hash_genesis: BlockHash::from_digest(Digest::from_bytes([0; 32])),
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: BlockHash::from_digest(Digest::from_bytes([0; 32])),
                altura: 0,
                trabajo_acumulado: [0; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [0; 32],
            longitud_registro: 0,
        }
    }

    fn bloque_difundido(&self, _id: IdDiferido, _: &BloqueRed) -> Veredicto {
        self.bloques.fetch_add(1, Ordering::Relaxed);
        Veredicto::Aceptar
    }

    fn tx_difundida(&self, _peer: libp2p::PeerId, _: &[u8]) -> Veredicto {
        self.txs.fetch_add(1, Ordering::Relaxed);
        Veredicto::Aceptar
    }

    fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }
}

/// Un nodo listo para correr.
fn nodo() -> (Piezas<Contador>, Arc<Contador>) {
    let contador = Arc::new(Contador::default());
    let presupuesto = Presupuesto::default();
    let clave = identity::Keypair::generate_ed25519();
    let peer_id = clave.public().to_peer_id();
    let transporte = MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&clave).expect("noise"))
        .multiplex(yamux::Config::default())
        .boxed();
    let behaviour = ZxBehaviour::con_presupuesto(
        &clave,
        ParametrosRed::dag_dev(),
        limites::LIMITE_BLOQUE_DEV,
        presupuesto.clone(),
    )
    .expect("behaviour");
    let swarm = Swarm::new(
        transporte,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(30)),
    );
    (
        arrancar_con(swarm, Arc::clone(&contador), presupuesto),
        contador,
    )
}

/// Una dirección de memoria distinta por test, para no colisionar en paralelo.
fn addr_memoria() -> Multiaddr {
    static SIGUIENTE: AtomicU64 = AtomicU64::new(60_001);
    let puerto = SIGUIENTE.fetch_add(1, Ordering::Relaxed);
    format!("/memory/{puerto}").parse().expect("multiaddr")
}

/// Espera a que `n` pares distintos aparezcan suscritos a **cada uno** de los cuatro temas.
///
/// Se espera a todos en la misma pasada: descartar los eventos de otros temas al esperar uno
/// perdería las suscripciones que llegan intercaladas.
async fn esperar_malla(rx: &mut tokio::sync::mpsc::Receiver<EventoRed>, n: usize) {
    const TEMAS: [&str; 4] = [
        "/zx-dev/bloques/pow/2",
        "/zx-dev/bloques/post/2",
        "/zx-dev/tx/2",
        "/zx-dev/votos/2",
    ];
    let mut visto: [Vec<libp2p::PeerId>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let plazo = tokio::time::Instant::now() + Duration::from_secs(20);
    while visto.iter().any(|v| v.len() < n) {
        let resto = plazo.saturating_duration_since(tokio::time::Instant::now());
        assert!(!resto.is_zero(), "no se formó la malla a tiempo: {visto:?}");
        match tokio::time::timeout(resto, rx.recv()).await {
            Ok(Some(EventoRed::Suscripcion {
                peer,
                topico,
                suscrito: true,
            })) => {
                if let Some(i) = TEMAS.iter().position(|t| *t == topico.as_str())
                    && let Some(v) = visto.get_mut(i)
                    && !v.contains(&peer)
                {
                    v.push(peer);
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => panic!("el canal de eventos se cerró esperando suscripciones"),
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

fn tx_a_wire(tx: &Tx, testigos: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
    buf
}

/// Un cuerpo con varias transacciones, para que el bloque tenga redundancia comprimible.
fn cuerpo_gordo(base: u8) -> (Vec<Tx>, Vec<Vec<Vec<u8>>>) {
    let txs: Vec<Tx> = (0..8u8).map(|i| tx_llave(base.wrapping_add(i))).collect();
    let testigos: Vec<Vec<Vec<u8>>> = (0..8u8).map(|_| vec![vec![base; 64]]).collect();
    (txs, testigos)
}

fn bloque_pow(n: u8) -> BloqueRed {
    let (txs, testigos) = cuerpo_gordo(n);
    BloqueRed::Pow {
        cabecera: BlockHeader {
            consensus_branch_id: 0xa8b4_66a7,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([n; 32])),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x33; 32])),
            timestamp: 1_788_480_000,
            bits: 0x1c07_fff8,
            nonce: u64::from(n),
            height: u32::from(n),
        },
        txs,
        testigos,
    }
}

fn bloque_post(n: u8) -> BloqueRed {
    let (txs, testigos) = cuerpo_gordo(n.wrapping_add(0x40));
    let portador = PotCheckpoints::desde_outputs([[n; 16]; 8]);
    BloqueRed::Post {
        cabecera: DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xa8b4_66a7,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x33; 32])),
            timestamp: 1_788_480_000,
            height: 0,
            slot: u64::from(n),
            pot_output: [n; 16],
            rango_solucion: 1,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x44; 32])),
            padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([0x55; 32])), &[])
                .unwrap(),
            sello: [n; 64],
        },
        justificacion: JustificacionPot::nueva(vec![portador]).expect("1 <= MAX_BUNDLES_POT"),
        txs,
        testigos,
    }
}

/// **ORDEN-ZC3 (c), humo de 4 nodos.** A difunde bloques y transacciones; B, C y D convergen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn humo_cuatro_nodos_zrxc_baja_los_bytes_y_conserva_el_estado() {
    let (pa, _ca) = nodo();
    let (pb, cb) = nodo();
    let (pc, cc) = nodo();
    let (pd, cd) = nodo();

    let mut ev_a = pa.eventos;
    let ma = pa.manejo.clone();
    let mb = pb.manejo.clone();
    let mc = pc.manejo.clone();
    let md = pd.manejo.clone();
    let _ta = tokio::spawn(pa.bucle.correr());
    let _tb = tokio::spawn(pb.bucle.correr());
    let _tc = tokio::spawn(pc.bucle.correr());
    let _td = tokio::spawn(pd.bucle.correr());

    let addr = addr_memoria();
    ma.escuchar(addr.clone()).await.unwrap();
    for m in [&mb, &mc, &md] {
        m.marcar(addr.clone()).await.unwrap();
    }

    esperar_malla(&mut ev_a, 3).await;
    // Deja que gossipsub forme la malla tras las suscripciones.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let n_bloques = 6usize;
    let n_txs = 20usize;
    for i in 0..n_bloques {
        if i % 2 == 0 {
            ma.difundir_bloque(&bloque_pow(i as u8)).await.unwrap();
        } else {
            ma.difundir_bloque(&bloque_post(i as u8)).await.unwrap();
        }
    }
    for i in 0..n_txs {
        let bytes = tx_a_wire(&tx_llave(i as u8), &[]);
        ma.difundir_tx(&bytes).await.unwrap();
    }

    // Convergencia: los 3 receptores tienen que ver lo mismo.
    let plazo = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let bloques = [
            cb.bloques.load(Ordering::Relaxed),
            cc.bloques.load(Ordering::Relaxed),
            cd.bloques.load(Ordering::Relaxed),
        ];
        let txs = [
            cb.txs.load(Ordering::Relaxed),
            cc.txs.load(Ordering::Relaxed),
            cd.txs.load(Ordering::Relaxed),
        ];
        if bloques.iter().all(|b| *b >= n_bloques) && txs.iter().all(|t| *t >= n_txs) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < plazo,
            "no convergió: bloques={bloques:?} txs={txs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Mismo estado final: los cuatro nodos tienen los mismos bloques y txs (A produjo, B/C/D
    // recibieron; A no cuenta los suyos por gossip pero su fuente es la misma).
    let esperado_bloques = n_bloques;
    let esperado_txs = n_txs;
    assert_eq!(cb.bloques.load(Ordering::Relaxed), esperado_bloques);
    assert_eq!(cc.bloques.load(Ordering::Relaxed), esperado_bloques);
    assert_eq!(cd.bloques.load(Ordering::Relaxed), esperado_bloques);
    assert_eq!(cb.txs.load(Ordering::Relaxed), esperado_txs);
    assert_eq!(cc.txs.load(Ordering::Relaxed), esperado_txs);
    assert_eq!(cd.txs.load(Ordering::Relaxed), esperado_txs);

    // Y el ahorro de bytes que A envió.
    let m = ma.metricas();
    let factor = m.factor();
    eprintln!(
        "ZRX-C humo-4-nodos: bytes_originales={} bytes_enviados={} factor={factor:.4} ahorro={:.2}%",
        m.bytes_originales(),
        m.bytes_enviados(),
        100.0 * (1.0 - factor)
    );
    assert!(
        m.bytes_originales() > 0,
        "el humo tiene que haber enviado algo"
    );
    assert!(
        factor < 0.80,
        "ORDEN-ZC3 (c): los bytes enviados MUST bajar >= 20%; factor={factor}"
    );
}
