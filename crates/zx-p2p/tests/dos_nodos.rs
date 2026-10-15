//! Arnés de dos nodos sobre transporte **en memoria** (SPEC §16).
//!
//! # Por qué se construye a mano y no con `libp2p-swarm-test`
//!
//! `swarm-test` escucha **siempre en TCP real** además de en memoria, y con mDNS activo un nodo
//! empieza a descubrir vecinos de la LAN. Así que el transporte es `MemoryTransport` **puro**,
//! siguiendo el patrón de `protocols/kad/src/behaviour/test.rs`.
//!
//! # Lo que este arnés NO cubre
//!
//! - **Latencia, pérdida y reordenamiento reales.** `MemoryTransport` son canales `mpsc`.
//! - **NAT y hole punching.**
//! - **Caída de proceso.** Aquí "caer" un nodo es soltar su `Swarm`.
//! - **Determinismo estricto.** Es hermético y rápido, no reproducible byte a byte.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use libp2p::core::transport::{MemoryTransport, Transport};
use libp2p::core::upgrade;
use libp2p::{Multiaddr, PeerId, Swarm, identity, noise, yamux};
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot, TxId};
use zx_core::preimage::block::BlockHeader;
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_core::red::Red;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_core::wire_dag::{JustificacionPot, PotCheckpoints};
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::desalojo::DesalojoEntrantes;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto, VeredictoFinal};
use zx_p2p::limites;
use zx_p2p::mensaje::{BloqueRed, Estado, FamiliaBloque, Fase, Peticion, PuntaPow, Respuesta};
use zx_p2p::presupuesto::Presupuesto;
use zx_p2p::servicio::{
    EventoRed, arrancar_con, arrancar_con_plazo, arrancar_con_plazo_y_desalojo,
};

/// Manejador de juguete: cuenta llamadas y sirve un estado y unos bloques reconocibles.
struct Contador {
    /// Bloques que llegaron por difusión.
    bloques: AtomicUsize,
    /// Transacciones que llegaron por difusión (canal retirado en 0.0.1).
    txs: AtomicUsize,
    /// Para distinguir de quién es la respuesta en un test con dos nodos.
    marca: u8,
    /// Génesis que este nodo dice tener.
    genesis: BlockHash,
    /// Cabeceras PoW que este nodo dice tener.
    cabeceras: Vec<BlockHeader>,
    /// Bloques que este nodo sirve por `Bloques`.
    cuerpos: Vec<BloqueRed>,
    /// El mismo contador de C-NET-21 que se pasa al códec y al bucle de este nodo.
    presupuesto: Presupuesto,
}

impl Contador {
    fn nuevo(marca: u8) -> Self {
        Self {
            bloques: AtomicUsize::new(0),
            txs: AtomicUsize::new(0),
            marca,
            genesis: BlockHash::from_digest(Digest::from_bytes([0; 32])),
            cabeceras: Vec::new(),
            cuerpos: Vec::new(),
            presupuesto: Presupuesto::default(),
        }
    }

    fn con_genesis(marca: u8, genesis: u8) -> Self {
        let mut c = Self::nuevo(marca);
        c.genesis = BlockHash::from_digest(Digest::from_bytes([genesis; 32]));
        c
    }

    fn con_cabeceras(marca: u8, n: usize) -> Self {
        let cabeceras = (0..n)
            .map(|i| BlockHeader {
                consensus_branch_id: 0xa8b4_66a7,
                prev_hash: BlockHash::from_digest(Digest::from_bytes([i as u8; 32])),
                merkle_root: MerkleRoot::from_digest(Digest::from_bytes([9; 32])),
                timestamp: 1_788_480_000 + i as u64,
                bits: 0x1c07_fff8,
                nonce: i as u64,
                height: i as u32,
            })
            .collect();
        let mut c = Self::nuevo(marca);
        c.cabeceras = cabeceras;
        c
    }
}

impl Default for Contador {
    fn default() -> Self {
        Self::nuevo(0)
    }
}

impl ManejadorEntrante for Contador {
    fn estado(&self) -> Estado {
        Estado {
            hash_genesis: self.genesis,
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: BlockHash::from_digest(Digest::from_bytes([self.marca; 32])),
                altura: u32::from(self.marca) * 100,
                trabajo_acumulado: [self.marca; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [self.marca; 32],
            longitud_registro: u64::from(self.marca),
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
        self.cabeceras.clone()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        self.cuerpos.clone()
    }
}

/// Conecta dos nodos y devuelve sus piezas ya corriendo.
type Conectados = (
    zx_p2p::servicio::ManejoRed,
    tokio::sync::mpsc::Receiver<EventoRed>,
    PeerId,
    Vec<tokio::task::JoinHandle<()>>,
    // El handle de B, que hay que mantener vivo o su bucle termina.
    zx_p2p::servicio::ManejoRed,
    tokio::sync::mpsc::Receiver<EventoRed>,
);

async fn dos_conectados(a: Arc<Contador>, b: Arc<Contador>) -> Conectados {
    let swarm_a = nodo_en_memoria(&a.presupuesto);
    let swarm_b = nodo_en_memoria(&b.presupuesto);
    let id_b = *swarm_b.local_peer_id();
    let tema_pow = swarm_a.behaviour().parametros_de_red().topic_bloques_pow();
    let tema_post = swarm_a.behaviour().parametros_de_red().topic_bloques_post();

    let pa = arrancar_con(swarm_a, a.clone(), a.presupuesto.clone());
    let pb = arrancar_con(swarm_b, b.clone(), b.presupuesto.clone());

    let manejo_a = pa.manejo.clone();
    let mut ev_a = pa.eventos;
    let mut ev_b = pb.eventos;
    let tareas = vec![
        tokio::spawn(pa.bucle.correr()),
        tokio::spawn(pb.bucle.correr()),
    ];

    // B escucha, A marca: así A conoce la dirección de B y puede pedirle cosas.
    let addr = addr_memoria();
    pb.manejo.escuchar(addr.clone()).await.expect("B escucha");
    manejo_a.marcar(addr).await.expect("A marca");
    assert!(
        esperar(&mut ev_a, |e| matches!(e, EventoRed::PeerConectado(_)))
            .await
            .is_some(),
        "A debería conectarse con B"
    );

    // Se esperan **los dos temas**, en el orden en que lleguen: A los envía al establecerse la
    // conexión y el orden dentro del RPC no está garantizado. La comparación es por igualdad
    // exacta con el tema configurado.
    let mut vio_pow = false;
    let mut vio_post = false;
    while !(vio_pow && vio_post) {
        let Some(e) = esperar(&mut ev_b, |e| matches!(e, EventoRed::Suscripcion { .. })).await
        else {
            panic!("B no vio las dos suscripciones de A (pow={vio_pow}, post={vio_post})");
        };
        if let EventoRed::Suscripcion {
            topico,
            suscrito: true,
            ..
        } = &e
        {
            vio_pow |= topico.as_str() == tema_pow;
            vio_post |= topico.as_str() == tema_post;
        }
    }

    // ⚠️ El handle de B se DEVUELVE, no se suelta: soltar el último `ManejoRed` cierra el canal de
    // comandos y el bucle de B terminaría.
    (manejo_a, ev_a, id_b, tareas, pb.manejo, ev_b)
}

/// Arranca un nodo pasando **el mismo** `Presupuesto` de su manejador al bucle y al códec.
fn arrancar_de(c: &Arc<Contador>) -> zx_p2p::servicio::Piezas<Contador> {
    arrancar_con(
        nodo_en_memoria(&c.presupuesto),
        Arc::clone(c),
        c.presupuesto.clone(),
    )
}

/// Un `Swarm` sobre transporte en memoria. **Sin TCP**.
fn nodo_en_memoria(presupuesto: &Presupuesto) -> Swarm<ZxBehaviour> {
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

    Swarm::new(
        transporte,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(30)),
    )
}

/// Una dirección de memoria distinta por test, para que no colisionen en paralelo.
fn addr_memoria() -> Multiaddr {
    static SIGUIENTE: AtomicU64 = AtomicU64::new(50_001);
    let puerto = SIGUIENTE.fetch_add(1, Ordering::Relaxed);
    format!("/memory/{puerto}").parse().expect("multiaddr")
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

/// Una transacción mínima con una entrada.
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

/// Un bloque PoW de fixture.
fn bloque_pow(n: u8) -> BloqueRed {
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
        txs: vec![tx_llave(0x11)],
        testigos: vec![vec![vec![0x66; 64]]],
    }
}

/// Un bloque PoST de fixture.
fn justificacion_simple(n: u8) -> JustificacionPot {
    let portador = PotCheckpoints::desde_outputs([[n; 16]; 8]);
    JustificacionPot::nueva(vec![portador]).unwrap_or_else(|_| unreachable!("1 <= MAX_BUNDLES_POT"))
}

fn bloque_post(n: u8) -> BloqueRed {
    BloqueRed::Post {
        justificacion: justificacion_simple(n),
        cabecera: DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xa8b4_66a7,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x33; 32])),
            timestamp: 1_788_480_000,
            height: 0,
            slot: u64::from(n),
            pot_output: [0; 16],
            rango_solucion: 1,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x44; 32])),
            padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([0x55; 32])), &[])
                .unwrap(),
            sello: [0; 64],
        },
        txs: vec![tx_llave(0x22)],
        testigos: vec![vec![vec![0x77; 64]]],
    }
}

/// **Dos nodos se encuentran y se ven.**
#[tokio::test]
async fn dos_nodos_se_conectan_y_se_ven() {
    let piezas_a = arrancar_de(&Arc::new(Contador::default()));
    let piezas_b = arrancar_de(&Arc::new(Contador::default()));

    let manejo_a = piezas_a.manejo.clone();
    let manejo_b = piezas_b.manejo.clone();
    let mut ev_a = piezas_a.eventos;
    let mut ev_b = piezas_b.eventos;

    let tarea_a = tokio::spawn(piezas_a.bucle.correr());
    let tarea_b = tokio::spawn(piezas_b.bucle.correr());

    let addr = addr_memoria();
    manejo_a.escuchar(addr.clone()).await.expect("A escucha");

    assert!(
        esperar(&mut ev_a, |e| matches!(e, EventoRed::Escuchando(_)))
            .await
            .is_some(),
        "A debería anunciar que escucha"
    );

    manejo_b.marcar(addr).await.expect("B marca");

    let a_vio = esperar(&mut ev_a, |e| matches!(e, EventoRed::PeerConectado(_))).await;
    let b_vio = esperar(&mut ev_b, |e| matches!(e, EventoRed::PeerConectado(_))).await;

    assert!(a_vio.is_some(), "A debería ver conectarse a B");
    assert!(b_vio.is_some(), "B debería ver conectarse a A");

    tarea_a.abort();
    tarea_b.abort();
}

/// **El bucle termina solo cuando se sueltan todos los handles.**
#[tokio::test]
async fn el_bucle_termina_al_soltar_los_handles() {
    let piezas = arrancar_de(&Arc::new(Contador::default()));
    let manejo = piezas.manejo;
    let eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());

    drop(manejo);
    drop(eventos);

    let fin = tokio::time::timeout(Duration::from_secs(5), tarea).await;
    assert!(
        fin.is_ok(),
        "el bucle MUST terminar al soltarse el último handle"
    );
}

/// **Un handle huérfano devuelve error, no entra en pánico.**
#[tokio::test]
async fn un_handle_sin_bucle_devuelve_error_y_no_panic() {
    let piezas = arrancar_de(&Arc::new(Contador::default()));
    let manejo = piezas.manejo.clone();

    drop(piezas.bucle);
    drop(piezas.eventos);

    assert!(
        manejo.escuchar(addr_memoria()).await.is_err(),
        "sin bucle, el comando MUST fallar limpiamente"
    );
}

/// **El saludo, de extremo a extremo.**
#[tokio::test]
async fn el_saludo_recorre_el_camino_completo() {
    let (manejo_a, mut ev_a, id_b, tareas, _vivo_b, _ev_b) =
        dos_conectados(Arc::new(Contador::nuevo(1)), Arc::new(Contador::nuevo(7))).await;

    manejo_a
        .pedir(id_b, Peticion::Estado)
        .await
        .expect("A pregunta");

    let e = esperar(&mut ev_a, |e| matches!(e, EventoRed::Respuesta { .. }))
        .await
        .expect("A debería recibir el estado de B");

    let EventoRed::Respuesta { respuesta, .. } = e else {
        panic!("se esperaba una respuesta");
    };
    match *respuesta {
        Respuesta::Estado(s) => {
            assert_eq!(
                s.punta_pow.altura, 700,
                "debe ser el estado de B, no el de A"
            );
            assert_eq!(s.punta_pow.trabajo_acumulado, [7; 32]);
        }
        otra => panic!("se esperaba Estado, llegó {otra:?}"),
    }

    for t in tareas {
        t.abort();
    }
}

/// **Pedir cabeceras PoW y que el manejador de B las sirva.**
#[tokio::test]
async fn pedir_cabeceras_llega_al_manejador_del_otro_lado() {
    let (manejo_a, mut ev_a, id_b, tareas, _vivo_b, _ev_b) = dos_conectados(
        Arc::new(Contador::nuevo(1)),
        Arc::new(Contador::con_cabeceras(2, 5)),
    )
    .await;

    manejo_a
        .pedir(
            id_b,
            Peticion::CabecerasPow {
                locator: vec![BlockHash::from_digest(Digest::from_bytes([0; 32]))],
                parada: None,
            },
        )
        .await
        .expect("A pide");

    let e = esperar(&mut ev_a, |e| matches!(e, EventoRed::Respuesta { .. }))
        .await
        .expect("A debería recibir cabeceras");

    let EventoRed::Respuesta { respuesta, .. } = e else {
        panic!("se esperaba una respuesta");
    };
    match *respuesta {
        Respuesta::CabecerasPow(cs) => assert_eq!(cs.len(), 5, "las cinco que B dice tener"),
        otra => panic!("se esperaba CabecerasPow, llegó {otra:?}"),
    }

    for t in tareas {
        t.abort();
    }
}

/// **"No tengo eso" es una respuesta, no un error.**
#[tokio::test]
async fn no_tener_un_bloque_es_una_respuesta_legitima() {
    let (manejo_a, mut ev_a, id_b, tareas, _vivo_b, _ev_b) =
        dos_conectados(Arc::new(Contador::nuevo(1)), Arc::new(Contador::nuevo(2))).await;

    manejo_a
        .pedir(
            id_b,
            Peticion::Bloques {
                hashes: vec![BlockHash::from_digest(Digest::from_bytes([42; 32]))],
            },
        )
        .await
        .expect("A pide");

    let e = esperar(&mut ev_a, |e| matches!(e, EventoRed::Respuesta { .. }))
        .await
        .expect("A debería recibir algo");

    let EventoRed::Respuesta { respuesta, .. } = e else {
        panic!("se esperaba una respuesta");
    };
    assert_eq!(
        *respuesta,
        Respuesta::NoDisponible,
        "no tener el bloque MUST decirse, no callarse"
    );

    for t in tareas {
        t.abort();
    }
}

/// **Pedir bloques por hash devuelve el bloque, con su familia.**
#[tokio::test]
async fn pedir_bloques_por_hash_devuelve_el_bloque() {
    let mut sirve = Contador::nuevo(2);
    sirve.cuerpos = vec![bloque_pow(3), bloque_post(4)];
    let (manejo_a, mut ev_a, id_b, tareas, _vivo_b, _ev_b) =
        dos_conectados(Arc::new(Contador::nuevo(1)), Arc::new(sirve)).await;

    manejo_a
        .pedir(
            id_b,
            Peticion::Bloques {
                hashes: vec![
                    BlockHash::from_digest(Digest::from_bytes([1; 32])),
                    BlockHash::from_digest(Digest::from_bytes([2; 32])),
                ],
            },
        )
        .await
        .expect("A pide");

    let e = esperar(&mut ev_a, |e| matches!(e, EventoRed::Respuesta { .. }))
        .await
        .expect("A debería recibir bloques");
    let EventoRed::Respuesta { respuesta, .. } = e else {
        panic!("se esperaba una respuesta");
    };
    match *respuesta {
        Respuesta::Bloques(bs) => {
            assert_eq!(bs.len(), 2);
            assert_eq!(bs.first().map(BloqueRed::familia), Some(FamiliaBloque::Pow));
            assert_eq!(bs.get(1).map(BloqueRed::familia), Some(FamiliaBloque::Post));
        }
        otra => panic!("se esperaba Bloques, llegó {otra:?}"),
    }

    for t in tareas {
        t.abort();
    }
}

/// **Un bloque PoW real viaja por su tema y llega al callback.**
#[tokio::test]
async fn un_bloque_pow_viaja_y_llega_al_callback() {
    let a = Arc::new(Contador::nuevo(1));
    let b = Arc::new(Contador::nuevo(2));
    let (_manejo_a, mut ev_a, _id_b, tareas, manejo_b, _vivo_b) =
        dos_conectados(Arc::clone(&a), Arc::clone(&b)).await;

    manejo_b
        .difundir_bloque(&bloque_pow(7))
        .await
        .expect("B publica el bloque PoW por su tema");

    esperar_contador(&a.bloques, 1, &mut ev_a).await;
    assert_eq!(a.txs.load(Ordering::Relaxed), 0, "no es una transacción");

    for t in tareas {
        t.abort();
    }
}

/// **Un bloque PoST real viaja por su tema y llega al callback.**
#[tokio::test]
async fn un_bloque_post_viaja_y_llega_al_callback() {
    let a = Arc::new(Contador::nuevo(1));
    let b = Arc::new(Contador::nuevo(2));
    let (_manejo_a, mut ev_a, _id_b, tareas, manejo_b, _vivo_b) =
        dos_conectados(Arc::clone(&a), Arc::clone(&b)).await;

    manejo_b
        .difundir_bloque(&bloque_post(9))
        .await
        .expect("B publica el bloque PoST por su tema");

    esperar_contador(&a.bloques, 1, &mut ev_a).await;

    for t in tareas {
        t.abort();
    }
}

/// Espera acotada a que un contador llegue a `objetivo`, bombeando el canal de eventos.
async fn esperar_contador(
    contador: &AtomicUsize,
    objetivo: usize,
    ev: &mut tokio::sync::mpsc::Receiver<EventoRed>,
) {
    let plazo = tokio::time::Instant::now() + Duration::from_secs(10);
    while contador.load(Ordering::Relaxed) < objetivo {
        assert!(
            tokio::time::Instant::now() < plazo,
            "el bloque no llegó al callback"
        );
        let _ = tokio::time::timeout(Duration::from_millis(20), ev.recv()).await;
    }
}

/// Manejador que **siempre difiere** un bloque, avisando el `IdDiferido` por un canal, para que el
/// test controle cuándo (y con qué veredicto final) se resuelve (`ORDEN-W06d2`, decisión 1).
struct Diferidor {
    aviso: tokio::sync::mpsc::UnboundedSender<IdDiferido>,
}

impl ManejadorEntrante for Diferidor {
    fn estado(&self) -> Estado {
        Estado {
            hash_genesis: BlockHash::from_digest(Digest::from_bytes([0; 32])),
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: BlockHash::from_digest(Digest::from_bytes([9; 32])),
                altura: 0,
                trabajo_acumulado: [0; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [0; 32],
            longitud_registro: 0,
        }
    }

    fn bloque_difundido(&self, id: IdDiferido, _: &BloqueRed) -> Veredicto {
        // Si el test ya no escucha (canal cerrado), no hay nada que informar: se difiere igual y
        // expirará por plazo, que es exactamente lo que debe pasar.
        let _ = self.aviso.send(id);
        Veredicto::Diferir
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
}

/// **Un veredicto diferido no se retransmite hasta que se informa `Aceptar`.**
///
/// A → B (`Diferidor`) → C. B recibe el bloque de A y lo difiere: mientras tanto no debe llegar a
/// C. Solo tras `informar_validacion(id, Aceptar)` gossipsub reenvía el mensaje y C lo ve.
#[tokio::test]
async fn un_diferido_no_se_retransmite_hasta_informar_aceptar() {
    let (tx_aviso, mut rx_aviso) = tokio::sync::mpsc::unbounded_channel();
    let b = Arc::new(Diferidor { aviso: tx_aviso });
    let c = Arc::new(Contador::nuevo(3));

    let (manejo_a, _ev_a, manejo_b, ev_b, manejo_c, mut ev_c, mut tareas) =
        cadena_de_tres(Arc::new(Contador::nuevo(1)), Arc::clone(&b), Arc::clone(&c)).await;

    manejo_a
        .difundir_bloque(&bloque_pow(11))
        .await
        .expect("A publica");

    let id = tokio::time::timeout(Duration::from_secs(10), rx_aviso.recv())
        .await
        .expect("el aviso de diferido debe llegar")
        .expect("canal abierto");

    // Ventana corta: mientras no se informe, C no debe ver nada.
    let _ = tokio::time::timeout(Duration::from_millis(300), ev_c.recv()).await;
    assert_eq!(
        c.bloques.load(Ordering::Relaxed),
        0,
        "C no debe recibir el bloque antes de que B informe el veredicto"
    );

    manejo_b
        .informar_validacion(id, VeredictoFinal::Aceptar)
        .await
        .expect("B informa Aceptar");

    esperar_contador(&c.bloques, 1, &mut ev_c).await;

    for t in tareas.drain(..) {
        t.abort();
    }
    drop((manejo_a, manejo_b, manejo_c, ev_b));
}

/// **Un diferido sin informe a tiempo se trata como `Ignorar`: nunca se retransmite.**
///
/// Con un plazo corto (para no alargar el test), B difiere y **no** informa nada. Pasado el plazo,
/// C sigue sin ver el bloque.
#[tokio::test]
async fn un_diferido_sin_informe_a_tiempo_no_se_retransmite() {
    let (tx_aviso, mut rx_aviso) = tokio::sync::mpsc::unbounded_channel();
    let b = Arc::new(Diferidor { aviso: tx_aviso });
    let c = Arc::new(Contador::nuevo(3));

    let plazo_corto = Duration::from_millis(200);
    let (manejo_a, _ev_a, _manejo_b, _ev_b, _manejo_c, mut ev_c, mut tareas) =
        cadena_de_tres_con_plazo(
            Arc::new(Contador::nuevo(1)),
            Arc::clone(&b),
            Arc::clone(&c),
            plazo_corto,
        )
        .await;

    manejo_a
        .difundir_bloque(&bloque_pow(12))
        .await
        .expect("A publica");

    let _id = tokio::time::timeout(Duration::from_secs(10), rx_aviso.recv())
        .await
        .expect("el aviso de diferido debe llegar")
        .expect("canal abierto");

    // Se espera bastante más que el plazo de expiración, sin informar nunca: C no debe ver nada.
    let _ = tokio::time::timeout(plazo_corto * 6, ev_c.recv()).await;
    assert_eq!(
        c.bloques.load(Ordering::Relaxed),
        0,
        "un diferido que expira MUST tratarse como Ignorar: nunca se retransmite"
    );

    for t in tareas.drain(..) {
        t.abort();
    }
}

/// Encadena A → B → C (cada uno marca al siguiente) con el plazo de diferido por defecto.
async fn cadena_de_tres(
    a: Arc<impl ManejadorEntrante>,
    b: Arc<impl ManejadorEntrante>,
    c: Arc<impl ManejadorEntrante>,
) -> Cadena3 {
    cadena_de_tres_con_plazo(
        a,
        b,
        c,
        Duration::from_secs(zx_p2p::limites::PLAZO_VALIDACION_DIFERIDA_S),
    )
    .await
}

type Cadena3 = (
    zx_p2p::servicio::ManejoRed,
    tokio::sync::mpsc::Receiver<EventoRed>,
    zx_p2p::servicio::ManejoRed,
    tokio::sync::mpsc::Receiver<EventoRed>,
    zx_p2p::servicio::ManejoRed,
    tokio::sync::mpsc::Receiver<EventoRed>,
    Vec<tokio::task::JoinHandle<()>>,
);

/// Igual que [`cadena_de_tres`], con el plazo de validación diferida explícito para B (el único que
/// difiere en los tests de este módulo).
async fn cadena_de_tres_con_plazo(
    a: Arc<impl ManejadorEntrante>,
    b: Arc<impl ManejadorEntrante>,
    c: Arc<impl ManejadorEntrante>,
    plazo_b: Duration,
) -> Cadena3 {
    let presupuesto_a = Presupuesto::default();
    let presupuesto_b = Presupuesto::default();
    let presupuesto_c = Presupuesto::default();

    let swarm_a = nodo_en_memoria(&presupuesto_a);
    let swarm_b = nodo_en_memoria(&presupuesto_b);
    let swarm_c = nodo_en_memoria(&presupuesto_c);

    let pa = arrancar_con(swarm_a, a, presupuesto_a);
    let pb = arrancar_con_plazo(swarm_b, b, presupuesto_b, plazo_b);
    let pc = arrancar_con(swarm_c, c, presupuesto_c);

    let manejo_a = pa.manejo;
    let manejo_b = pb.manejo;
    let manejo_c = pc.manejo;
    let mut ev_a = pa.eventos;
    let mut ev_b = pb.eventos;
    let ev_c = pc.eventos;

    let tareas = vec![
        tokio::spawn(pa.bucle.correr()),
        tokio::spawn(pb.bucle.correr()),
        tokio::spawn(pc.bucle.correr()),
    ];

    let addr_b = addr_memoria();
    manejo_b.escuchar(addr_b.clone()).await.expect("B escucha");
    manejo_a.marcar(addr_b.clone()).await.expect("A marca B");
    assert!(
        esperar(&mut ev_a, |e| matches!(e, EventoRed::PeerConectado(_)))
            .await
            .is_some(),
        "A debería conectarse con B"
    );
    esperar_ambas_suscripciones(&mut ev_b).await;

    let addr_c = addr_memoria();
    manejo_c.escuchar(addr_c.clone()).await.expect("C escucha");
    manejo_b.marcar(addr_c.clone()).await.expect("B marca C");
    assert!(
        esperar(&mut ev_b, |e| matches!(e, EventoRed::PeerConectado(_)))
            .await
            .is_some(),
        "B debería conectarse con C"
    );
    // B debe ver la suscripción de C, y viceversa, antes de publicar nada.
    let mut ev_c = ev_c;
    esperar_ambas_suscripciones(&mut ev_c).await;
    esperar_ambas_suscripciones(&mut ev_b).await;

    (manejo_a, ev_a, manejo_b, ev_b, manejo_c, ev_c, tareas)
}

/// Espera a ver las suscripciones a los dos temas de bloques en el canal de eventos dado.
async fn esperar_ambas_suscripciones(ev: &mut tokio::sync::mpsc::Receiver<EventoRed>) {
    let tema_pow = ParametrosRed::dag_dev().topic_bloques_pow().to_owned();
    let tema_post = ParametrosRed::dag_dev().topic_bloques_post().to_owned();
    let mut vio_pow = false;
    let mut vio_post = false;
    while !(vio_pow && vio_post) {
        let Some(e) = esperar(ev, |e| matches!(e, EventoRed::Suscripcion { .. })).await else {
            panic!("no se vieron las dos suscripciones (pow={vio_pow}, post={vio_post})");
        };
        if let EventoRed::Suscripcion {
            topico,
            suscrito: true,
            ..
        } = &e
        {
            vio_pow |= *topico == tema_pow;
            vio_post |= *topico == tema_post;
        }
    }
}

/// **Un génesis ajeno se corta.** El nodo compara el `Estado` recibido con el suyo y desconecta.
#[tokio::test]
async fn un_genesis_ajeno_desconecta() {
    // B tiene un génesis distinto del de A.
    let a = Arc::new(Contador::con_genesis(1, 0x00));
    let b = Arc::new(Contador::con_genesis(2, 0xAA));
    let (manejo_a, mut ev_a, id_b, tareas, _vivo_b, mut ev_b) =
        dos_conectados(Arc::clone(&a), Arc::clone(&b)).await;

    manejo_a
        .pedir(id_b, Peticion::Estado)
        .await
        .expect("A pregunta");

    let e = esperar(&mut ev_a, |e| matches!(e, EventoRed::Respuesta { .. }))
        .await
        .expect("A debería recibir el estado de B");
    let EventoRed::Respuesta { respuesta, .. } = e else {
        panic!("se esperaba una respuesta");
    };
    let Respuesta::Estado(ajeno) = *respuesta else {
        panic!("se esperaba Estado");
    };
    assert_ne!(
        ajeno.hash_genesis,
        a.estado().hash_genesis,
        "el génesis de B MUST ser ajeno al de A"
    );

    // La decisión es del nodo, no de `zx-p2p` (este crate no valida): el nodo corta.
    manejo_a
        .desconectar(id_b, zx_p2p::error::MotivoDesconexion::ViolacionDeConsenso)
        .await
        .expect("A desconecta");

    assert!(
        esperar(&mut ev_b, |e| matches!(e, EventoRed::PeerDesconectado(_)))
            .await
            .is_some(),
        "B debe ver la desconexión por génesis ajeno"
    );

    for t in tareas {
        t.abort();
    }
}

/// `ORDEN-W06d6` decisión 1 (V1): `Peticion::Registro`/`Respuesta::Registro` viajan de punta a
/// punta como cualquier otro par petición/respuesta del protocolo.
#[tokio::test]
async fn pedir_registro_llega_al_manejador_del_otro_lado() {
    let (manejo_a, mut ev_a, id_b, tareas, _vivo_b, _ev_b) =
        dos_conectados(Arc::new(Contador::nuevo(1)), Arc::new(Contador::nuevo(2))).await;

    manejo_a
        .pedir(id_b, Peticion::Registro { desde: 0 })
        .await
        .expect("A pide el registro de B");

    let e = esperar(&mut ev_a, |e| matches!(e, EventoRed::Respuesta { .. }))
        .await
        .expect("A debería recibir la página del registro");
    let EventoRed::Respuesta { respuesta, .. } = e else {
        panic!("se esperaba una respuesta");
    };
    match *respuesta {
        // `Contador` no implementa `pagina_registro` (usa el valor por defecto del trait): página
        // vacía y longitud 0, pero el mensaje SÍ viajó de punta a punta con su forma correcta.
        Respuesta::Registro {
            desde,
            bloques,
            longitud,
        } => {
            assert_eq!(desde, 0);
            assert!(bloques.is_empty());
            assert_eq!(longitud, 0);
        }
        otra => panic!("se esperaba Registro, llegó {otra:?}"),
    }

    for t in tareas {
        t.abort();
    }
}

/// `ORDEN-W06d6` decisión 1 (V1): un par que "cae" (aquí, se sueltan sus tareas) a mitad de una
/// petición de registro no cuelga al que pregunta — la petición falla con
/// `EventoRed::PeticionFallida`, igual que cualquier otra petición de sincronización (documentado
/// como límite del arnés: "caer" un nodo es soltar su `Swarm`, no matar un proceso real).
#[tokio::test]
async fn par_caido_a_mitad_de_una_peticion_de_registro_no_cuelga() {
    let (manejo_a, mut ev_a, id_b, tareas, vivo_b, ev_b) =
        dos_conectados(Arc::new(Contador::nuevo(1)), Arc::new(Contador::nuevo(2))).await;

    manejo_a
        .pedir(id_b, Peticion::Registro { desde: 0 })
        .await
        .expect("A pide el registro de B");

    // "B cae" a mitad: se suelta su último `ManejoRed` (cierra el canal de comandos de su bucle,
    // que entonces termina solo) y su receptor de eventos. **Solo** la tarea de B (índice 1: `dos_
    // conectados` las devuelve en orden `[A, B]`) se aborta — abortar también la de A le impediría
    // enterarse de nada.
    drop(vivo_b);
    drop(ev_b);
    if let Some(tarea_b) = tareas.get(1) {
        tarea_b.abort();
    }

    // `TIMEOUT_SYNC` (`behaviour.rs`) son 30 s: el `esperar` genérico de este arnés (10 s) es
    // demasiado corto para este caso concreto, así que aquí se espera explícitamente más que eso.
    let plazo = tokio::time::Instant::now() + Duration::from_secs(35);
    let mut visto = None;
    while tokio::time::Instant::now() < plazo {
        let resto = plazo.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(resto, ev_a.recv()).await {
            Ok(Some(e @ (EventoRed::PeticionFallida { .. } | EventoRed::PeerDesconectado(_)))) => {
                visto = Some(e);
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    assert!(
        visto.is_some(),
        "A MUST enterarse (fallo de petición o desconexión) dentro de TIMEOUT_SYNC, nunca \
         quedarse esperando para siempre"
    );

    if let Some(tarea_a) = tareas.first() {
        tarea_a.abort();
    }
}

/// **V1 (RED-3).** Ocho nodos en proceso, **una sola** dirección de arranque (la del nodo 0).
///
/// El descubrimiento (Kademlia `Mode::Server` + paseo aleatorio) sustituye la estrella del humo de
/// RED-2 por la **malla completa**: los 8 nodos acaban conectados con los otros 7 (28 pares) a
/// partir de una sola dirección. La distribución de qué lado marca cada par es una carrera; el
/// criterio literal de «≥4 salientes por nodo» es imposible con 8 nodos (28 pares ⇒ la suma de
/// salientes ≤ 28 < 32 = 8×4), como se razona en `PROGRESO.md`. Se reporta la distribución medida.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ocho_nodos_forman_malla_completa_con_una_sola_direccion_de_arranque() {
    use std::collections::HashSet;
    use std::sync::Mutex;

    const N: usize = 8;
    let mut manejos = Vec::with_capacity(N);
    let mut direcciones = Vec::with_capacity(N);
    let mut conectados: Vec<Arc<Mutex<HashSet<PeerId>>>> = Vec::with_capacity(N);
    let mut salientes: Vec<Arc<Mutex<HashSet<PeerId>>>> = Vec::with_capacity(N);
    let mut tareas = Vec::new();

    for i in 0..N {
        let c = Arc::new(Contador::nuevo(i as u8));
        let swarm = nodo_en_memoria(&c.presupuesto);
        let zx_p2p::servicio::Piezas {
            manejo,
            eventos,
            bucle,
        } = arrancar_con(swarm, c.clone(), c.presupuesto.clone());
        let con: Arc<Mutex<HashSet<PeerId>>> = Arc::new(Mutex::new(HashSet::new()));
        let sal: Arc<Mutex<HashSet<PeerId>>> = Arc::new(Mutex::new(HashSet::new()));
        let mut ev = eventos;
        let con_tarea = Arc::clone(&con);
        let sal_tarea = Arc::clone(&sal);
        tareas.push(tokio::spawn(async move {
            while let Some(e) = ev.recv().await {
                match e {
                    EventoRed::PeerConectado(p) => {
                        con_tarea.lock().expect("lock").insert(p);
                    }
                    EventoRed::PeerDesconectado(p) => {
                        con_tarea.lock().expect("lock").remove(&p);
                    }
                    EventoRed::ConexionSaliente(p) => {
                        sal_tarea.lock().expect("lock").insert(p);
                    }
                    _ => {}
                }
            }
        }));
        tareas.push(tokio::spawn(bucle.correr()));
        manejos.push(manejo);
        conectados.push(con);
        salientes.push(sal);
        direcciones.push(addr_memoria());
    }

    // Todos escuchan: sin dirección de escucha propia, Kademlia no puede marcar a los descubiertos.
    for (m, a) in manejos.iter().zip(direcciones.iter()) {
        m.escuchar(a.clone()).await.expect("escucha");
    }
    let dir_arranque = direcciones.first().expect("nodo 0").clone();
    manejos
        .first()
        .expect("nodo 0")
        .sembrar(None, Vec::new())
        .await
        .expect("el arranque siembra el director");
    // Arranque del operador: cada nodo conoce **solo** la dirección del nodo 0.
    for m in manejos.iter().skip(1) {
        m.sembrar(None, vec![dir_arranque.clone()])
            .await
            .expect("siembra");
        m.marcar(dir_arranque.clone())
            .await
            .expect("marca arranque");
    }

    let plazo = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        let completos = conectados
            .iter()
            .filter(|c| c.lock().expect("lock").len() >= N - 1)
            .count();
        if completos == N || tokio::time::Instant::now() >= plazo {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let grados: Vec<usize> = conectados
        .iter()
        .map(|c| c.lock().expect("lock").len())
        .collect();
    let salidas: Vec<usize> = salientes
        .iter()
        .map(|s| s.lock().expect("lock").len())
        .collect();
    let total: usize = salidas.iter().sum();
    eprintln!("V1 malla: vecinos={grados:?} salientes={salidas:?} suma_salientes={total}");
    for t in tareas {
        t.abort();
    }

    assert!(
        grados.iter().all(|g| *g >= N - 1),
        "no se formó la malla completa (se esperaban 7 vecinos por nodo): vecinos={grados:?}"
    );
    assert!(
        salidas.iter().filter(|s| **s >= 4).count() >= 1,
        "ningún nodo marcó a 4 pares: el descubrimiento no creció fuera de la estrella \
         (salientes={salidas:?})"
    );
}

/// **V4 (RED-3).** Punto de aceptación de C-NET-42: con el tope de entrantes lleno, una entrante
/// nueva desaloja a una de las ya establecidas y **no** a la que se está aceptando. Se baja el tope
/// a 3 para no montar 72 conexiones reales; la política con 72 y la protección del que entregó un
/// bloque válido están cubiertas por los tests de `desalojo.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn con_el_tope_de_entrantes_lleno_la_siguiente_desaloja() {
    let c = Arc::new(Contador::nuevo(0));
    let swarm_c = nodo_en_memoria(&c.presupuesto);
    let id_c = *swarm_c.local_peer_id();
    let zx_p2p::servicio::Piezas {
        manejo: manejo_c,
        eventos: mut ev_c,
        bucle: bucle_c,
    } = arrancar_con_plazo_y_desalojo(
        swarm_c,
        c.clone(),
        c.presupuesto.clone(),
        Duration::from_secs(5),
        DesalojoEntrantes::nuevo(3),
    );
    let mut tareas = vec![tokio::spawn(bucle_c.correr())];
    let addr_c = addr_memoria();
    manejo_c.escuchar(addr_c.clone()).await.expect("C escucha");

    let mut manejos = Vec::new();
    let mut eventos = Vec::new();
    let mut ids = Vec::new();
    for i in 1..=4u8 {
        let p = Arc::new(Contador::nuevo(i));
        let swarm = nodo_en_memoria(&p.presupuesto);
        ids.push(*swarm.local_peer_id());
        let zx_p2p::servicio::Piezas {
            manejo,
            eventos: ev,
            bucle,
        } = arrancar_con(swarm, p.clone(), p.presupuesto.clone());
        tareas.push(tokio::spawn(bucle.correr()));
        manejos.push(manejo);
        eventos.push(ev);
    }

    // Las tres primeras llenan el tope.
    for m in manejos.iter().take(3) {
        m.marcar(addr_c.clone()).await.expect("marca");
    }
    // Se cuentan los tres pares **distintos** ya establecidos, no tres eventos: una
    // reconexión del *bootstrap* de Kademlia podría anunciar a uno de ellos dos veces.
    let mut conectados: Vec<PeerId> = Vec::new();
    while conectados.len() < 3 {
        let Some(EventoRed::PeerConectado(p)) =
            esperar(&mut ev_c, |e| matches!(e, EventoRed::PeerConectado(_))).await
        else {
            panic!("C no vio las 3 primeras conexiones");
        };
        if ids.iter().take(3).any(|q| *q == p) && !conectados.contains(&p) {
            conectados.push(p);
        }
    }

    // La cuarta desborda el tope: C elige víctima entre las tres anteriores y la desconecta.
    let p4 = ids.get(3).copied().expect("P4");
    manejos
        .get(3)
        .expect("P4")
        .marcar(addr_c.clone())
        .await
        .expect("marca 4");
    // P4 fue aceptada: el punto de aceptación anuncia a la entrante como conectada.
    assert!(
        matches!(
            esperar(
                &mut ev_c,
                |e| matches!(e, EventoRed::PeerConectado(p) if *p == p4)
            )
            .await,
            Some(EventoRed::PeerConectado(_))
        ),
        "C debe aceptar a P4"
    );
    let evento = esperar(&mut ev_c, |e| matches!(e, EventoRed::PeerDesconectado(_)))
        .await
        .expect("con el tope lleno, la 4.ª entrante debe provocar un desalojo");
    let EventoRed::PeerDesconectado(victima) = evento else {
        unreachable!()
    };
    eprintln!("V4 desalojo: víctima={victima}, P4={p4}, C={id_c} (ids={ids:?})");
    assert_ne!(victima, p4, "la víctima no puede ser la que se acepta");
    let indice = ids
        .iter()
        .take(3)
        .position(|p| *p == victima)
        .expect("la víctima debe salir de las tres ya establecidas");

    // El servicio solo desconecta a la víctima que elige: su propio canal lo ve, y eso
    // cierra la comprobación de que **P4 no es la víctima de esta admisión**. NO se exige
    // que P4 no vuelva a desconectarse más tarde: mientras el tope siga lleno, el
    // reingreso de la desalojada —el *bootstrap* automático de Kademlia redescubre a C y
    // vuelve a marcarla— provoca un nuevo desalojo, y entonces P4, la más joven de las no
    // probadas, es la víctima legítima (C-NET-42). Aquella espera negativa de 10 s
    // dependía del orden de eventos y del reloj: era la fuente de la inestabilidad
    // (FIX-06). El caso determinista equivalente está en `desalojo.rs`.
    let ev_victima = eventos.get_mut(indice).expect("canal de la víctima");
    assert!(
        matches!(
            esperar(ev_victima, |e| matches!(e, EventoRed::PeerDesconectado(_))).await,
            Some(EventoRed::PeerDesconectado(_))
        ),
        "la víctima elegida por C debe ver su desconexión"
    );

    for t in tareas {
        t.abort();
    }
}
