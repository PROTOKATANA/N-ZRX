//! A5-c-2a · el veredicto **diferido** de los dos temas nuevos de AG-2c (voto de red por subred y
//! agregado), con la misma mecánica que los bloques (`ORDEN-W06d2`, decisión 1).
//!
//! Cubre las siete pruebas que fija `P-ZRX/P-004/ORDEN-A5C2A.md` §3 y la octava de
//! `P-ZRX/P-004/ORDEN-A5C2A-2.md` §3 (`dif_08_el_nodo_fija_el_cupo`). Usa el transporte **en
//! memoria** (mismo patrón que `dos_nodos.rs`), que es hermético y rápido: A publica, B difiere, C
//! observa. Como la malla de gossipsub solo se forma con las suscripciones, cada conexión espera a
//! verlas.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::core::transport::{MemoryTransport, Transport};
use libp2p::core::upgrade;
use libp2p::{Multiaddr, PeerId, Swarm, identity, noise, yamux};
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest, MerkleRoot, TxId};
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto, VeredictoFinal};
use zx_p2p::limites::{
    CUPO_DIFERIDOS_VOTOS_ARRANQUE, LIMITE_BLOQUE_DEV, PLAZO_VALIDACION_DIFERIDA_S,
};
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};
use zx_p2p::presupuesto::Presupuesto;
use zx_p2p::servicio::{EventoRed, ManejoRed, arrancar_con_plazo};

/// Tema de agregados de la red dev.
const TEMA_AGREGADO: &str = "/zx-dev/votos-agr/1";

/// Subred que usan las pruebas de voto de red.
const SUBRED: u8 = 5;

/// Un bloque PoW de fixture, serializable con el códec de bloques.
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

fn estado_dev() -> Estado {
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

/// Manejador que **siempre difiere** los bloques y los dos ganchos nuevos, guarda los `IdDiferido`
/// y anota los `par_penalizado`. El test decide cuándo y con qué veredicto final se resuelven.
#[derive(Default)]
struct Diferidor {
    penalizados: Mutex<Vec<PeerId>>,
    ids_bloque: Mutex<Vec<IdDiferido>>,
    ids_subred: Mutex<Vec<IdDiferido>>,
    ids_agregado: Mutex<Vec<IdDiferido>>,
}

impl Diferidor {
    fn primero(ids: &Mutex<Vec<IdDiferido>>) -> Option<IdDiferido> {
        ids.lock().expect("mutex").first().copied()
    }

    fn penalizados(&self) -> Vec<PeerId> {
        self.penalizados.lock().expect("mutex").clone()
    }

    fn n_agregados(&self) -> usize {
        self.ids_agregado.lock().expect("mutex").len()
    }
}

impl ManejadorEntrante for Diferidor {
    fn estado(&self) -> Estado {
        estado_dev()
    }

    fn bloque_difundido(&self, id: IdDiferido, _: &BloqueRed) -> Veredicto {
        self.ids_bloque.lock().expect("mutex").push(id);
        Veredicto::Diferir
    }

    fn tx_difundida(&self, _peer: PeerId, _: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn voto_subred_difundida(
        &self,
        id: IdDiferido,
        _subred: u8,
        _bytes: &[u8],
        _peer: PeerId,
    ) -> Veredicto {
        self.ids_subred.lock().expect("mutex").push(id);
        Veredicto::Diferir
    }

    fn agregado_difundido(&self, id: IdDiferido, _bytes: &[u8], _peer: PeerId) -> Veredicto {
        self.ids_agregado.lock().expect("mutex").push(id);
        Veredicto::Diferir
    }

    fn par_penalizado(&self, peer: PeerId, _motivo: &str, _accion: &str) {
        self.penalizados.lock().expect("mutex").push(peer);
    }

    fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }
}

/// Manejador observador: acepta todo y cuenta lo que le llega.
#[derive(Default)]
struct Observador {
    bloques: AtomicUsize,
    subredes: AtomicUsize,
    agregados: AtomicUsize,
}

impl ManejadorEntrante for Observador {
    fn estado(&self) -> Estado {
        estado_dev()
    }

    fn bloque_difundido(&self, _id: IdDiferido, _: &BloqueRed) -> Veredicto {
        self.bloques.fetch_add(1, Ordering::Relaxed);
        Veredicto::Aceptar
    }

    fn tx_difundida(&self, _peer: PeerId, _: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn voto_subred_difundida(
        &self,
        _id: IdDiferido,
        _subred: u8,
        _bytes: &[u8],
        _peer: PeerId,
    ) -> Veredicto {
        self.subredes.fetch_add(1, Ordering::Relaxed);
        Veredicto::Aceptar
    }

    fn agregado_difundido(&self, _id: IdDiferido, _bytes: &[u8], _peer: PeerId) -> Veredicto {
        self.agregados.fetch_add(1, Ordering::Relaxed);
        Veredicto::Aceptar
    }

    fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }
}

/// Manejador que **no** implementa los dos ganchos: usa los defaults del trait (prueba 7).
#[derive(Default)]
struct SoloDefecto {
    penalizados: Mutex<Vec<PeerId>>,
}

impl SoloDefecto {
    fn penalizados(&self) -> Vec<PeerId> {
        self.penalizados.lock().expect("mutex").clone()
    }
}

impl ManejadorEntrante for SoloDefecto {
    fn estado(&self) -> Estado {
        estado_dev()
    }

    fn bloque_difundido(&self, _id: IdDiferido, _: &BloqueRed) -> Veredicto {
        Veredicto::Aceptar
    }

    fn tx_difundida(&self, _peer: PeerId, _: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn par_penalizado(&self, peer: PeerId, _motivo: &str, _accion: &str) {
        self.penalizados.lock().expect("mutex").push(peer);
    }

    fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }
}

/// Un nodo sobre transporte en memoria, ya escuchando.
struct Nodo {
    manejo: ManejoRed,
    eventos: tokio::sync::mpsc::Receiver<EventoRed>,
    peer_id: PeerId,
    direccion: Multiaddr,
    tarea: tokio::task::JoinHandle<()>,
}

impl Drop for Nodo {
    fn drop(&mut self) {
        self.tarea.abort();
    }
}

async fn nodo<M: ManejadorEntrante>(manejador: Arc<M>, plazo: Duration) -> Nodo {
    let presupuesto = Presupuesto::default();
    let swarm = nodo_en_memoria(&presupuesto);
    let peer_id = *swarm.local_peer_id();
    let piezas = arrancar_con_plazo(swarm, manejador, presupuesto, plazo);
    let manejo = piezas.manejo;
    let mut eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());

    let direccion = addr_memoria();
    manejo.escuchar(direccion.clone()).await.expect("escuchar");
    let Some(EventoRed::Escuchando(_)) =
        esperar(&mut eventos, |e| matches!(e, EventoRed::Escuchando(_))).await
    else {
        panic!("se esperaba `Escuchando`");
    };

    Nodo {
        manejo,
        eventos,
        peer_id,
        direccion,
        tarea,
    }
}

/// Un `Swarm` sobre transporte en memoria, con el **mismo** presupuesto que el bucle.
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
        LIMITE_BLOQUE_DEV,
        presupuesto.clone(),
    )
    .expect("behaviour dev");

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
    static SIGUIENTE: AtomicU64 = AtomicU64::new(60_001);
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

/// Espera acotada a que se cumpla una condición observada en memoria (callbacks del manejador).
async fn esperar_hasta<F: Fn() -> bool>(f: F, plazo: Duration) -> bool {
    let fin = tokio::time::Instant::now() + plazo;
    loop {
        if f() {
            return true;
        }
        if tokio::time::Instant::now() >= fin {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Espera a que `rx` vea conectarse a `peer`.
async fn esperar_conectado(rx: &mut tokio::sync::mpsc::Receiver<EventoRed>, peer: PeerId) {
    let Some(_) = esperar(
        rx,
        |e| matches!(e, EventoRed::PeerConectado(p) if *p == peer),
    )
    .await
    else {
        panic!("no llegó `PeerConectado` de {peer}");
    };
}

/// Espera a que `rx` vea que `peer` se suscribió a **todos** los `temas`, en cualquier orden.
async fn esperar_suscripciones(
    rx: &mut tokio::sync::mpsc::Receiver<EventoRed>,
    peer: PeerId,
    temas: &[String],
) {
    let mut vistos = vec![false; temas.len()];
    while vistos.iter().any(|v| !v) {
        let Some(e) = esperar(rx, |e| matches!(e, EventoRed::Suscripcion { .. })).await else {
            let faltan: Vec<&str> = temas
                .iter()
                .zip(&vistos)
                .filter(|(_, v)| !**v)
                .map(|(t, _)| t.as_str())
                .collect();
            panic!("no llegaron las suscripciones de {peer} a {faltan:?}");
        };
        if let EventoRed::Suscripcion {
            peer: p,
            topico,
            suscrito: true,
        } = e
            && p == peer
        {
            for (i, t) in temas.iter().enumerate() {
                if &topico == t
                    && let Some(v) = vistos.get_mut(i)
                {
                    *v = true;
                }
            }
        }
    }
}

/// Conecta `cliente` a `servidor` y espera a que el servidor vea su conexión y **todas** sus
/// suscripciones: los dos temas de bloque, el de agregado y, si se indica, el de la subred.
async fn conectar_y_esperar(servidor: &mut Nodo, cliente: &mut Nodo, subred: Option<u8>) {
    cliente
        .manejo
        .marcar(servidor.direccion.clone())
        .await
        .expect("marcar");
    esperar_conectado(&mut servidor.eventos, cliente.peer_id).await;

    let p = ParametrosRed::dag_dev();
    let mut temas = vec![
        p.topic_bloques_pow().to_owned(),
        p.topic_bloques_post().to_owned(),
        TEMA_AGREGADO.to_owned(),
    ];
    if let Some(s) = subred {
        temas.push(p.topic_voto_subred(s));
    }
    esperar_suscripciones(&mut servidor.eventos, cliente.peer_id, &temas).await;
}

/// Plazo largo para el nodo que difiere: el test decide el veredicto antes de que venza.
const PLAZO_LARGO: Duration = Duration::from_secs(30);

// ── Prueba 1 ────────────────────────────────────────────────────────────────

/// **Prueba 1.** Un voto de subred que B difiere no llega a C; tras `informar_validacion(Aceptar)`,
/// B lo reenvía y C lo ve.
#[tokio::test]
async fn dif_01_voto_de_subred_diferido_se_reenvia_al_aceptar() {
    let a = Arc::new(Observador::default());
    let b = Arc::new(Diferidor::default());
    let c = Arc::new(Observador::default());
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), PLAZO_LARGO).await;
    let mut nc = nodo(Arc::clone(&c), PLAZO_LARGO).await;

    nb.manejo.suscribir_subred(SUBRED).await.expect("B a la 5");
    nc.manejo.suscribir_subred(SUBRED).await.expect("C a la 5");
    conectar_y_esperar(&mut na, &mut nb, Some(SUBRED)).await;
    conectar_y_esperar(&mut nb, &mut nc, Some(SUBRED)).await;

    na.manejo
        .difundir_voto_subred(SUBRED, &[0x11; 248])
        .await
        .expect("A publica el voto");

    assert!(
        esperar_hasta(
            || Diferidor::primero(&b.ids_subred).is_some(),
            Duration::from_secs(5)
        )
        .await,
        "B debe diferir el voto"
    );
    let id = Diferidor::primero(&b.ids_subred).expect("id diferido");

    // Mientras no se informe, C no debe verlo.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        c.subredes.load(Ordering::Relaxed),
        0,
        "C no debe recibir el voto antes del veredicto"
    );

    nb.manejo
        .informar_validacion(id, VeredictoFinal::Aceptar)
        .await
        .expect("B informa Aceptar");

    assert!(
        esperar_hasta(
            || c.subredes.load(Ordering::Relaxed) >= 1,
            Duration::from_secs(5)
        )
        .await,
        "tras Aceptar, B debe reenviar el voto y C verlo"
    );
}

// ── Prueba 2 ────────────────────────────────────────────────────────────────

/// **Prueba 2.** Un agregado que B difiere no se reenvía antes del veredicto; tras `Aceptar`, sí.
#[tokio::test]
async fn dif_02_agregado_diferido_no_se_reenvia_antes_del_veredicto() {
    let a = Arc::new(Observador::default());
    let b = Arc::new(Diferidor::default());
    let c = Arc::new(Observador::default());
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), PLAZO_LARGO).await;
    let mut nc = nodo(Arc::clone(&c), PLAZO_LARGO).await;

    conectar_y_esperar(&mut na, &mut nb, None).await;
    conectar_y_esperar(&mut nb, &mut nc, None).await;

    na.manejo
        .difundir_agregado(&[0x22; 300])
        .await
        .expect("A publica el agregado");

    assert!(
        esperar_hasta(
            || Diferidor::primero(&b.ids_agregado).is_some(),
            Duration::from_secs(5)
        )
        .await,
        "B debe diferir el agregado"
    );
    let id = Diferidor::primero(&b.ids_agregado).expect("id diferido");

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        c.agregados.load(Ordering::Relaxed),
        0,
        "C no debe recibir el agregado antes del veredicto"
    );

    nb.manejo
        .informar_validacion(id, VeredictoFinal::Aceptar)
        .await
        .expect("B informa Aceptar");

    assert!(
        esperar_hasta(
            || c.agregados.load(Ordering::Relaxed) >= 1,
            Duration::from_secs(5)
        )
        .await,
        "tras Aceptar, B debe reenviar el agregado y C verlo"
    );
}

// ── Prueba 3 ────────────────────────────────────────────────────────────────

/// **Prueba 3.** `Rechazar` al resolver un diferido penaliza al par que lo propagó, igual que un
/// bloque rechazado.
#[tokio::test]
async fn dif_03_rechazar_penaliza_al_propagador() {
    let a = Arc::new(Observador::default());
    let b = Arc::new(Diferidor::default());
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), PLAZO_LARGO).await;

    nb.manejo.suscribir_subred(SUBRED).await.expect("B a la 5");
    conectar_y_esperar(&mut na, &mut nb, Some(SUBRED)).await;

    na.manejo
        .difundir_voto_subred(SUBRED, &[0x33; 248])
        .await
        .expect("A publica el voto");

    assert!(
        esperar_hasta(
            || Diferidor::primero(&b.ids_subred).is_some(),
            Duration::from_secs(5)
        )
        .await,
        "B debe diferir el voto"
    );
    let id = Diferidor::primero(&b.ids_subred).expect("id diferido");

    nb.manejo
        .informar_validacion(id, VeredictoFinal::Rechazar)
        .await
        .expect("B informa Rechazar");

    assert!(
        esperar_hasta(|| !b.penalizados().is_empty(), Duration::from_secs(5)).await,
        "Rechazar un diferido debe penalizar al propagador"
    );
    assert!(
        b.penalizados().contains(&na.peer_id),
        "el penalizado debe ser A, que propagó el voto"
    );
}

// ── Prueba 4 ────────────────────────────────────────────────────────────────

/// **Prueba 4.** `Ignorar` al resolver un diferido **no** penaliza a nadie.
#[tokio::test]
async fn dif_04_ignorar_no_penaliza() {
    let a = Arc::new(Observador::default());
    let b = Arc::new(Diferidor::default());
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), PLAZO_LARGO).await;

    conectar_y_esperar(&mut na, &mut nb, None).await;

    na.manejo
        .difundir_agregado(&[0x44; 300])
        .await
        .expect("A publica el agregado");

    assert!(
        esperar_hasta(
            || Diferidor::primero(&b.ids_agregado).is_some(),
            Duration::from_secs(5)
        )
        .await,
        "B debe diferir el agregado"
    );
    let id = Diferidor::primero(&b.ids_agregado).expect("id diferido");

    nb.manejo
        .informar_validacion(id, VeredictoFinal::Ignorar)
        .await
        .expect("B informa Ignorar");

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        b.penalizados().is_empty(),
        "Ignorar un diferido no puede penalizar"
    );
}

// ── Prueba 5 ────────────────────────────────────────────────────────────────

/// **Prueba 5.** Un diferido que nadie resuelve vence y se trata como `Ignorar`: no se reenvía y no
/// penaliza. Usa un plazo corto para no alargar el test.
#[tokio::test]
async fn dif_05_el_que_vence_se_ignora() {
    let a = Arc::new(Observador::default());
    let b = Arc::new(Diferidor::default());
    let c = Arc::new(Observador::default());
    let plazo_corto = Duration::from_millis(200);
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), plazo_corto).await;
    let mut nc = nodo(Arc::clone(&c), PLAZO_LARGO).await;

    conectar_y_esperar(&mut na, &mut nb, None).await;
    conectar_y_esperar(&mut nb, &mut nc, None).await;

    na.manejo
        .difundir_agregado(&[0x55; 300])
        .await
        .expect("A publica el agregado");

    assert!(
        esperar_hasta(
            || Diferidor::primero(&b.ids_agregado).is_some(),
            Duration::from_secs(5)
        )
        .await,
        "B debe diferir el agregado"
    );

    // Muy por encima del plazo, sin informar nunca: no se reenvía y no se penaliza.
    tokio::time::sleep(plazo_corto * 6).await;
    assert_eq!(
        c.agregados.load(Ordering::Relaxed),
        0,
        "un diferido que vence se ignora: nunca se retransmite"
    );
    assert!(
        b.penalizados().is_empty(),
        "un vencimiento no penaliza: el manejador lento no es culpa del peer"
    );
}

// ── Prueba 6 ────────────────────────────────────────────────────────────────

/// **Prueba 6.** Un aluvión de agregados no desaloja un bloque pendiente: las cotas de diferidos de
/// los dos temas nuevos y de los bloques son **independientes** (D4).
#[tokio::test]
async fn dif_06_un_aluvion_de_agregados_no_desaloja_un_bloque_pendiente() {
    let a = Arc::new(Observador::default());
    let b = Arc::new(Diferidor::default());
    let c = Arc::new(Observador::default());
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), PLAZO_LARGO).await;
    let mut nc = nodo(Arc::clone(&c), PLAZO_LARGO).await;

    conectar_y_esperar(&mut na, &mut nb, None).await;
    conectar_y_esperar(&mut nb, &mut nc, None).await;

    // Primero el bloque: B lo difiere y queda pendiente.
    na.manejo
        .difundir_bloque(&bloque_pow(7))
        .await
        .expect("A publica el bloque");
    assert!(
        esperar_hasta(
            || Diferidor::primero(&b.ids_bloque).is_some(),
            Duration::from_secs(5)
        )
        .await,
        "B debe diferir el bloque"
    );
    let id_bloque = Diferidor::primero(&b.ids_bloque).expect("id del bloque");

    // Ahora el aluvión: más agregados que el cupo de su clase. Cada uno debe ser **distinto**:
    // gossipsub descarta como `Duplicate` un mensaje idéntico al ya visto.
    let aluvion = CUPO_DIFERIDOS_VOTOS_ARRANQUE + 2;
    for i in 0..aluvion {
        let cuerpo = [i as u8; 300];
        na.manejo
            .difundir_agregado(&cuerpo)
            .await
            .unwrap_or_else(|e| panic!("agregado {i}: {e}"));
    }
    assert!(
        esperar_hasta(|| b.n_agregados() >= aluvion, Duration::from_secs(15)).await,
        "B debe haber visto los {aluvion} agregados"
    );

    // El bloque sigue pendiente: al informarlo, B lo reenvía y C lo ve.
    nb.manejo
        .informar_validacion(id_bloque, VeredictoFinal::Aceptar)
        .await
        .expect("B informa Aceptar del bloque");
    assert!(
        esperar_hasta(
            || c.bloques.load(Ordering::Relaxed) >= 1,
            Duration::from_secs(5)
        )
        .await,
        "el aluvión de agregados no debe haber desalojado el bloque pendiente"
    );
}

// ── Prueba 7 ────────────────────────────────────────────────────────────────

/// **Prueba 7.** Un manejador que **no** implementa los dos ganchos los ignora por defecto: no se
/// reenvían y no se penaliza.
#[tokio::test]
async fn dif_07_por_defecto_se_ignora() {
    let a = Arc::new(Observador::default());
    let b = Arc::new(SoloDefecto::default());
    let c = Arc::new(Observador::default());
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), PLAZO_LARGO).await;
    let mut nc = nodo(Arc::clone(&c), PLAZO_LARGO).await;

    nb.manejo.suscribir_subred(SUBRED).await.expect("B a la 5");
    nc.manejo.suscribir_subred(SUBRED).await.expect("C a la 5");
    conectar_y_esperar(&mut na, &mut nb, Some(SUBRED)).await;
    conectar_y_esperar(&mut nb, &mut nc, Some(SUBRED)).await;

    // El default `Ignorar` ni difiere ni reenvía; tampoco penaliza.
    na.manejo
        .difundir_voto_subred(SUBRED, &[0x77; 248])
        .await
        .expect("voto");
    na.manejo
        .difundir_agregado(&[0x88; 300])
        .await
        .expect("agregado");

    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        b.penalizados().is_empty(),
        "el default `Ignorar` no puede penalizar"
    );
    assert_eq!(
        c.subredes.load(Ordering::Relaxed),
        0,
        "el default `Ignorar` no reenvía el voto de subred"
    );
    assert_eq!(
        c.agregados.load(Ordering::Relaxed),
        0,
        "el default `Ignorar` no reenvía el agregado"
    );
}

/// **Prueba 8** (`ORDEN-A5C2A-2` §3). El cupo lo fija el nodo en marcha:
///
/// - con el cupo en `K`, se retienen `K` y el siguiente **se ignora sin penalizar**;
/// - al subirlo en marcha, entran más;
/// - los bloques pendientes no cuentan ni se ven afectados.
#[tokio::test]
async fn dif_08_el_nodo_fija_el_cupo() {
    /// Cupo pequeño para que la prueba sea rápida.
    const K: usize = 2;
    /// Lo que sube el nodo en marcha.
    const NUEVO_CUPO: usize = K + 2;

    let a = Arc::new(Observador::default());
    let b = Arc::new(Diferidor::default());
    let c = Arc::new(Observador::default());
    let mut na = nodo(Arc::clone(&a), PLAZO_LARGO).await;
    let mut nb = nodo(Arc::clone(&b), PLAZO_LARGO).await;
    let mut nc = nodo(Arc::clone(&c), PLAZO_LARGO).await;

    conectar_y_esperar(&mut na, &mut nb, None).await;
    conectar_y_esperar(&mut nb, &mut nc, None).await;

    // Un bloque pendiente que **no** debe contar en el cupo de los dos temas nuevos.
    na.manejo
        .difundir_bloque(&bloque_pow(9))
        .await
        .expect("A publica el bloque");
    assert!(
        esperar_hasta(
            || Diferidor::primero(&b.ids_bloque).is_some(),
            Duration::from_secs(5)
        )
        .await,
        "B debe diferir el bloque"
    );

    // El nodo fija el cupo en K.
    nb.manejo
        .fijar_cupo_diferidos_agregacion(K)
        .await
        .expect("B fija el cupo");

    // K agregados distintos caben.
    for i in 0..K {
        na.manejo
            .difundir_agregado(&[0x40 + i as u8; 300])
            .await
            .expect("A publica un agregado");
    }
    assert!(
        esperar_hasta(|| b.n_agregados() >= K, Duration::from_secs(5)).await,
        "B debe haber visto los {K} agregados"
    );
    // El callback cuenta antes de retener; se deja asentar la retención.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // El siguiente (K+1-ésimo) llega con la tabla llena: se ignora sin penalizar.
    na.manejo
        .difundir_agregado(&[0x4F; 300])
        .await
        .expect("A publica el agregado de más");
    assert!(
        esperar_hasta(|| b.n_agregados() > K, Duration::from_secs(5)).await,
        "B debe haber visto el agregado de más"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;

    let ids: Vec<IdDiferido> = b.ids_agregado.lock().expect("mutex").clone();
    assert_eq!(ids.len(), K + 1, "el manejador ve los {K}+1");
    let id_de_mas = *ids.get(K).expect("el K+1-ésimo id");

    // El que no cabe se ignora: su informe es un no-op (no está pendiente) y no penaliza.
    nb.manejo
        .informar_validacion(id_de_mas, VeredictoFinal::Aceptar)
        .await
        .expect("B informa el de más");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        c.agregados.load(Ordering::Relaxed),
        0,
        "el mensaje que no cabe no puede reenviarse"
    );
    assert!(
        b.penalizados().is_empty(),
        "ignorar por cupo lleno no penaliza"
    );

    // Los K que caben sí entran.
    for id in ids.get(..K).expect("los K primeros ids") {
        nb.manejo
            .informar_validacion(*id, VeredictoFinal::Aceptar)
            .await
            .expect("B informa uno de los que caben");
    }
    assert!(
        esperar_hasta(
            || c.agregados.load(Ordering::Relaxed) >= K,
            Duration::from_secs(5)
        )
        .await,
        "los K que caben deben reenviarse"
    );

    // El bloque sigue pendiente: el aluvión de agregados no lo tocó.
    let id_bloque = Diferidor::primero(&b.ids_bloque).expect("id del bloque");
    nb.manejo
        .informar_validacion(id_bloque, VeredictoFinal::Aceptar)
        .await
        .expect("B informa Aceptar del bloque");
    assert!(
        esperar_hasta(
            || c.bloques.load(Ordering::Relaxed) >= 1,
            Duration::from_secs(5)
        )
        .await,
        "el cupo de los temas nuevos no toca a los bloques"
    );

    // Al subirlo en marcha entran más: NUEVO_CUPO agregados nuevos, todos retenidos.
    nb.manejo
        .fijar_cupo_diferidos_agregacion(NUEVO_CUPO)
        .await
        .expect("B sube el cupo");
    let base = b.n_agregados();
    for i in 0..NUEVO_CUPO {
        na.manejo
            .difundir_agregado(&[0x80 + i as u8; 300])
            .await
            .expect("A publica un agregado nuevo");
    }
    assert!(
        esperar_hasta(
            || b.n_agregados() >= base + NUEVO_CUPO,
            Duration::from_secs(5)
        )
        .await,
        "B debe haber visto los {NUEVO_CUPO} agregados nuevos"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ids2: Vec<IdDiferido> = {
        let todos = b.ids_agregado.lock().expect("mutex");
        todos.get(base..).expect("los ids nuevos").to_vec()
    };
    assert_eq!(ids2.len(), NUEVO_CUPO);
    for id in &ids2 {
        nb.manejo
            .informar_validacion(*id, VeredictoFinal::Aceptar)
            .await
            .expect("B informa uno nuevo");
    }
    assert!(
        esperar_hasta(
            || c.agregados.load(Ordering::Relaxed) >= K + NUEVO_CUPO,
            Duration::from_secs(5)
        )
        .await,
        "con el cupo subido a {NUEVO_CUPO} deben entrar más"
    );
    assert!(
        b.penalizados().is_empty(),
        "subir el cupo no penaliza a nadie"
    );
}

/// El plazo de producción sigue siendo el documentado: el test no lo cambia.
#[test]
fn dif_plazo_de_produccion_intacto() {
    assert_eq!(PLAZO_VALIDACION_DIFERIDA_S, 5);
}
