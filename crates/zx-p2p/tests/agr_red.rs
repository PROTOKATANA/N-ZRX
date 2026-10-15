//! AG-2c · los temas nuevos de `zx-p2p`: voto de red por subred y agregado por tema común.
//!
//! Cubre las ocho pruebas que fija `P-ZRX/P-004/ORDEN-AG2C.md` §3. Las de red montan nodos TCP
//! reales sobre `127.0.0.1:0` (mismo patrón que `penalizacion_gossip.rs`) porque la malla de
//! gossipsub solo se forma cuando llegan los `SUBSCRIBE`, y hay que esperarlos.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use libp2p::core::transport::Transport as _;
use libp2p::core::upgrade;
use libp2p::{Multiaddr, PeerId, Swarm, identity, noise, yamux};
use zx_core::digest::{BlockHash, Digest};
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::limites::{
    MAX_DESCOMPRIMIDO_AGREGADO, MAX_DESCOMPRIMIDO_TX, MAX_DESCOMPRIMIDO_VOTO_RED, MAX_GOSSIP_BYTES,
};
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};
use zx_p2p::servicio::{EventoRed, ManejoRed, TemaDifusion, clasificar_tema};

/// Tema de agregados de la red dev.
const TEMA_AGREGADO: &str = "/zx-dev/votos-agr/1";

/// Manejador espía: cuenta los callbacks nuevos, devuelve el veredicto configurado y registra los
/// `par_penalizado`.
struct Espia {
    subredes: Mutex<Vec<u8>>,
    agregados: Mutex<u32>,
    veredicto_subred: Veredicto,
    veredicto_agregado: Veredicto,
    penalizados: Mutex<Vec<PeerId>>,
}

impl Espia {
    fn nuevo(veredicto_subred: Veredicto, veredicto_agregado: Veredicto) -> Self {
        Self {
            subredes: Mutex::new(Vec::new()),
            agregados: Mutex::new(0),
            veredicto_subred,
            veredicto_agregado,
            penalizados: Mutex::new(Vec::new()),
        }
    }

    fn subredes(&self) -> Vec<u8> {
        self.subredes.lock().expect("mutex").clone()
    }

    fn agregados(&self) -> u32 {
        *self.agregados.lock().expect("mutex")
    }

    fn penalizados(&self) -> Vec<PeerId> {
        self.penalizados.lock().expect("mutex").clone()
    }
}

impl ManejadorEntrante for Espia {
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

    fn bloque_difundido(&self, _id: IdDiferido, _bloque: &BloqueRed) -> Veredicto {
        Veredicto::Aceptar
    }

    fn tx_difundida(&self, _peer: PeerId, _bytes: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn voto_subred_difundida(
        &self,
        _id: IdDiferido,
        subred: u8,
        _bytes: &[u8],
        _peer: PeerId,
    ) -> Veredicto {
        self.subredes.lock().expect("mutex").push(subred);
        self.veredicto_subred
    }

    fn agregado_difundido(&self, _id: IdDiferido, _bytes: &[u8], _peer: PeerId) -> Veredicto {
        *self.agregados.lock().expect("mutex") += 1;
        self.veredicto_agregado
    }

    fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }

    fn par_penalizado(&self, peer: PeerId, _motivo: &str, _accion: &str) {
        self.penalizados.lock().expect("mutex").push(peer);
    }
}

/// Manejador que **no** implementa los callbacks nuevos: usa los defaults del trait. Para la
/// prueba 7.
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

    fn bloque_difundido(&self, _id: IdDiferido, _bloque: &BloqueRed) -> Veredicto {
        Veredicto::Aceptar
    }

    fn tx_difundida(&self, _peer: PeerId, _bytes: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }

    fn par_penalizado(&self, peer: PeerId, _motivo: &str, _accion: &str) {
        self.penalizados.lock().expect("mutex").push(peer);
    }
}

/// Un nodo TCP real sobre `127.0.0.1:0`, ya escuchando.
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
    let behaviour = ZxBehaviour::nueva(
        &clave,
        ParametrosRed::dag_dev(),
        zx_p2p::limites::LIMITE_BLOQUE_DEV,
    )
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
///
/// Los eventos `Subscribed` de un mismo mensaje llegan en orden no garantizado: esperar un tema y
/// descartar el resto perdería el otro. Por eso se acumulan todos en un solo bucle.
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
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// ¿NO llega el evento buscado en `ventana`? Para afirmar "no pasó".
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

/// Conecta `cliente` a `servidor` y espera a que el servidor lo vea y a que lleguen **todas** sus
/// suscripciones: la del agregado (siempre) y la de una subred concreta si se indica.
async fn conectar_y_esperar(servidor: &mut Nodo, cliente: &mut Nodo, subred_cliente: Option<u8>) {
    cliente
        .manejo
        .marcar(servidor.direccion.clone())
        .await
        .expect("marcar");
    esperar_conectado(&mut servidor.eventos, cliente.peer_id).await;
    let mut temas = vec![TEMA_AGREGADO.to_string()];
    if let Some(s) = subred_cliente {
        temas.push(ParametrosRed::dag_dev().topic_voto_subred(s));
    }
    esperar_suscripciones(&mut servidor.eventos, cliente.peer_id, &temas).await;
}

// ── Prueba 1 ────────────────────────────────────────────────────────────────

/// **Prueba 1.** Los 65 temas de cada red se clasifican bien; las tres formas no canónicas de G2 y
/// un tema de otra red con el mismo sufijo, no.
#[test]
fn agr_red_temas_exactos_por_red_y_subred() {
    for p in [
        ParametrosRed::de(Red::Mainnet),
        ParametrosRed::de(Red::Testnet),
        ParametrosRed::dag_dev(),
    ] {
        assert_eq!(
            p.subredes_voto(),
            64,
            "{:?}: S es constante de la red",
            p.red()
        );
        assert_eq!(
            clasificar_tema(p.topic_agregado()),
            TemaDifusion::Agregado,
            "{:?}: el agregado",
            p.red()
        );
        for s in 0..p.subredes_voto() {
            let tema = p.topic_voto_subred(s);
            assert_eq!(
                clasificar_tema(&tema),
                TemaDifusion::VotoSubred(s),
                "{tema} ({:?})",
                p.red()
            );
            assert_eq!(p.subred_del_tema(&tema), Some(s), "{tema}");
        }
    }

    // Las tres formas de G2 que NO son temas: fuera de rango, cero a la izquierda y sufijo distinto.
    for malo in [
        "/zx-dev/votos-sub/64/1",
        "/zx-dev/votos-sub/07/1",
        "/zx-dev/votos-sub/7/1x",
    ] {
        assert_eq!(
            clasificar_tema(malo),
            TemaDifusion::Desconocido,
            "{malo} no es un tema de subred"
        );
    }

    // Un tema de **otra** red con el mismo sufijo no es de esta red, aunque la clasificación
    // genérica sí reconozca la red que lo declara.
    let ajeno = "/zerox/votos-sub/5/1";
    assert_eq!(clasificar_tema(ajeno), TemaDifusion::VotoSubred(5));
    assert_eq!(
        ParametrosRed::dag_dev().subred_del_tema(ajeno),
        None,
        "el tema de mainnet no es una subred de la red dev"
    );
}

// ── Prueba 2 ────────────────────────────────────────────────────────────────

/// **Prueba 2.** A publica en la subred 5; B, suscrito a la 5, lo recibe; C, suscrito a la 6, no.
#[tokio::test]
async fn agr_red_voto_de_subred_llega_solo_a_los_suscritos() {
    let a = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let b = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let c = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    let mut nc = nodo(Arc::clone(&c)).await;

    nb.manejo.suscribir_subred(5).await.expect("B a la 5");
    nc.manejo.suscribir_subred(6).await.expect("C a la 6");

    conectar_y_esperar(&mut na, &mut nb, Some(5)).await;
    conectar_y_esperar(&mut na, &mut nc, Some(6)).await;

    na.manejo
        .difundir_voto_subred(5, &[0x11; 248])
        .await
        .expect("publicar en la 5");

    assert!(
        esperar_hasta(|| b.subredes().contains(&5), Duration::from_secs(5)).await,
        "B, suscrito a la 5, debe recibirlo"
    );
    // Margen para que, si algo se reenviara mal, C ya lo habría registrado.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !c.subredes().contains(&5),
        "C, suscrito a la 6, NO debe recibir el voto de la 5"
    );
}

// ── Prueba 3 ────────────────────────────────────────────────────────────────

/// **Prueba 3.** El agregado llega a todos (todos están suscritos al tema común).
#[tokio::test]
async fn agr_red_agregado_llega_a_todos() {
    let a = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let b = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let c = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    let mut nc = nodo(Arc::clone(&c)).await;

    conectar_y_esperar(&mut na, &mut nb, None).await;
    conectar_y_esperar(&mut na, &mut nc, None).await;

    na.manejo
        .difundir_agregado(&[0x22; 300])
        .await
        .expect("publicar el agregado");

    assert!(
        esperar_hasta(|| b.agregados() >= 1, Duration::from_secs(5)).await,
        "B debe recibir el agregado"
    );
    assert!(
        esperar_hasta(|| c.agregados() >= 1, Duration::from_secs(5)).await,
        "C debe recibir el agregado"
    );
}

// ── Prueba 4 ────────────────────────────────────────────────────────────────

/// **Prueba 4.** Un voto de red de 249 B y un agregado de 8 525 B **no llegan** al manejador.
#[tokio::test]
async fn agr_red_mensaje_mayor_que_su_tope_no_llega_al_nodo() {
    // (a) voto de red de 249 B (uno más que su tope de 248).
    let a1 = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let b1 = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let mut na1 = nodo(Arc::clone(&a1)).await;
    let mut nb1 = nodo(Arc::clone(&b1)).await;
    nb1.manejo.suscribir_subred(5).await.expect("B a la 5");
    conectar_y_esperar(&mut na1, &mut nb1, Some(5)).await;
    na1.manejo
        .difundir_voto_subred(5, &[0u8; 249])
        .await
        .expect("el emisor local no aplica el tope del receptor");
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        b1.subredes().len(),
        0,
        "249 B superan el tope de 248 y NO deben llegar al manejador"
    );

    // (b) agregado de 8 525 B (uno más que su tope de 8 524), con conexión fresca: el rechazo de
    // (a) desconecta al emisor, así que no vale reutilizar la pareja.
    let a2 = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let b2 = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let mut na2 = nodo(Arc::clone(&a2)).await;
    let mut nb2 = nodo(Arc::clone(&b2)).await;
    conectar_y_esperar(&mut na2, &mut nb2, None).await;
    na2.manejo
        .difundir_agregado(&[0u8; 8525])
        .await
        .expect("el emisor local no aplica el tope del receptor");
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        b2.agregados(),
        0,
        "8 525 B superan el tope de 8 524 y NO deben llegar al manejador"
    );
}

// ── Prueba 5 ────────────────────────────────────────────────────────────────

/// **Prueba 5.** Suscribir, desuscribir y publicar con `s = 64` es un **error**, no un pánico.
#[tokio::test]
async fn agr_red_subred_fuera_de_rango_es_error() {
    let espia = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
    let n = nodo(espia).await;

    assert!(
        n.manejo.suscribir_subred(64).await.is_err(),
        "suscribir la 64 debe ser error"
    );
    assert!(
        n.manejo.desuscribir_subred(64).await.is_err(),
        "desuscribir la 64 debe ser error"
    );
    assert!(
        n.manejo.difundir_voto_subred(64, b"x").await.is_err(),
        "publicar en la 64 debe ser error"
    );

    // El borde de dentro sí se acepta.
    assert!(n.manejo.suscribir_subred(63).await.is_ok());
    assert!(n.manejo.desuscribir_subred(63).await.is_ok());
}

// ── Prueba 6 ────────────────────────────────────────────────────────────────

/// **Prueba 6.** Con cada uno de los tres veredictos, para las dos clases: el nodo decide (se le
/// consulta) y la reacción observable coincide (`Rechazar` penaliza; `Aceptar`/`Ignorar`, no).
#[tokio::test]
async fn agr_red_veredicto_del_nodo_decide_el_reenvio() {
    for veredicto in [Veredicto::Aceptar, Veredicto::Ignorar, Veredicto::Rechazar] {
        // Voto de red.
        {
            let a = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
            let b = Arc::new(Espia::nuevo(veredicto, Veredicto::Aceptar));
            let mut na = nodo(Arc::clone(&a)).await;
            let mut nb = nodo(Arc::clone(&b)).await;
            nb.manejo.suscribir_subred(5).await.expect("B a la 5");
            conectar_y_esperar(&mut na, &mut nb, Some(5)).await;
            na.manejo
                .difundir_voto_subred(5, &[0x33; 248])
                .await
                .expect("publicar");
            assert!(
                esperar_hasta(|| !b.subredes().is_empty(), Duration::from_secs(5)).await,
                "el manejador de B debe ser consultado (voto de red, {veredicto:?})"
            );
            comprobar_reaccion(&b, veredicto).await;
        }

        // Agregado.
        {
            let a = Arc::new(Espia::nuevo(Veredicto::Aceptar, Veredicto::Aceptar));
            let b = Arc::new(Espia::nuevo(Veredicto::Aceptar, veredicto));
            let mut na = nodo(Arc::clone(&a)).await;
            let mut nb = nodo(Arc::clone(&b)).await;
            conectar_y_esperar(&mut na, &mut nb, None).await;
            na.manejo
                .difundir_agregado(&[0x44; 300])
                .await
                .expect("publicar");
            assert!(
                esperar_hasta(|| b.agregados() >= 1, Duration::from_secs(5)).await,
                "el manejador de B debe ser consultado (agregado, {veredicto:?})"
            );
            comprobar_reaccion(&b, veredicto).await;
        }
    }
}

/// `Rechazar` debe generar un `par_penalizado`; `Aceptar` e `Ignorar`, nunca.
async fn comprobar_reaccion(espia: &Espia, veredicto: Veredicto) {
    if veredicto == Veredicto::Rechazar {
        assert!(
            esperar_hasta(|| !espia.penalizados().is_empty(), Duration::from_secs(5)).await,
            "Rechazar debe penalizar al propagador"
        );
    } else {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            espia.penalizados().is_empty(),
            "{veredicto:?} no debe penalizar"
        );
    }
}

// ── Prueba 7 ────────────────────────────────────────────────────────────────

/// **Prueba 7.** Con la implementación por defecto del trait, los dos mensajes se ignoran **sin
/// penalizar**: el par sigue conectado y no hay `par_penalizado`.
#[tokio::test]
async fn agr_red_por_defecto_se_ignora_sin_penalizar() {
    let a = Arc::new(SoloDefecto::default());
    let b = Arc::new(SoloDefecto::default());
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;

    nb.manejo.suscribir_subred(5).await.expect("B a la 5");
    conectar_y_esperar(&mut na, &mut nb, Some(5)).await;

    let _ = na.manejo.difundir_voto_subred(5, &[0x55; 248]).await;
    let _ = na.manejo.difundir_agregado(&[0x66; 300]).await;

    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        b.penalizados().is_empty(),
        "el default `Ignorar` no puede penalizar"
    );
    assert!(
        !b.penalizados().contains(&na.peer_id),
        "A no debe quedar penalizado por el default"
    );
    // El par sigue conectado: no llega su `PeerDesconectado` a B (que es quien penalizaría a A).
    assert!(
        no_llega(&mut nb.eventos, Duration::from_millis(500), |e| matches!(
            e,
            EventoRed::PeerDesconectado(p) if *p == na.peer_id
        ))
        .await,
        "el default `Ignorar` no puede desconectar al par"
    );
}

// ── Prueba 8 ────────────────────────────────────────────────────────────────

/// **Prueba 8.** Un certificado de 65 536 firmantes (8 509 B) cabe en el tema de transacciones de
/// hoy. No se toca ese tope.
#[test]
fn agr_red_certificado_65536_cabe_en_el_tema_de_tx() {
    // 8 509 B es la talla del certificado con 65 536 firmantes (firma de agregación + mapa).
    let certificado: u64 = 8_509;

    assert_eq!(MAX_DESCOMPRIMIDO_VOTO_RED, 248, "tope del voto de red");
    assert_eq!(MAX_DESCOMPRIMIDO_AGREGADO, 8_524, "tope del agregado");
    assert!(
        certificado <= MAX_DESCOMPRIMIDO_TX,
        "8 509 <= {} (tope del tema de tx)",
        MAX_DESCOMPRIMIDO_TX
    );
    assert!(
        certificado <= MAX_GOSSIP_BYTES as u64,
        "8 509 <= {} (techo de transporte)",
        MAX_GOSSIP_BYTES
    );
    // Y el tope del tema de tx es el de un bloque de red completo, no uno nuevo de AG-2c.
    assert_eq!(
        ParametrosRed::dag_dev().topic_txs(),
        "/zx-dev/tx/2",
        "el tema de transacciones de hoy no cambia"
    );
}
