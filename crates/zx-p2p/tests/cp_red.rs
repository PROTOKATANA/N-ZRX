//! A6-02 (CP-C3) · el carril de pruebas en la red: anuncio por huella y petición bajo demanda.
//!
//! Cubre las nueve pruebas de `P-ZRX/P-004/ORDEN-A602.md` §3. Las de red montan nodos TCP reales
//! sobre `127.0.0.1:0` (mismo patrón que `agr_red.rs`): la malla de gossipsub solo se forma cuando
//! llegan los `SUBSCRIBE`, y hay que esperarlos.

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
use zx_core::firma::{ClavePublica, Firma};
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::limites::{MAX_PRUEBA_COMPRIMIDA_BYTES, MAX_RESPUESTA_PRUEBA_BYTES};
use zx_p2p::mensaje::{
    AnuncioPrueba, BloqueRed, ErrorAnuncio, Estado, LONGITUD_ANUNCIO_PRUEBA, Peticion, Respuesta,
};
use zx_p2p::presupuesto::{MAX_PRUEBAS_EN_VUELO_NODO, MAX_PRUEBAS_EN_VUELO_POR_PAR, cabe_prueba};
use zx_p2p::servicio::{
    EventoRed, ManejoRed, TemaDifusion, clasificar_tema, prueba_respuesta_aceptable,
};

/// Tema de pruebas de la red dev.
const TEMA_PRUEBAS: &str = "/zx-dev/pruebas/2";

// ─────────────────────────────────────────────────────────────────────────────
// Utilidades de firma y anuncios
// ─────────────────────────────────────────────────────────────────────────────

fn par(semilla: u8) -> (identity::ed25519::Keypair, ClavePublica) {
    let sk = identity::ed25519::SecretKey::try_from_bytes([semilla; 32]).expect("semilla");
    let kp = identity::ed25519::Keypair::from(sk);
    let pk = ClavePublica::desde_bytes(kp.public().to_bytes());
    (kp, pk)
}

fn firmar(kp: &identity::ed25519::Keypair, msg: &[u8]) -> Firma {
    let sig: [u8; 64] = kp.sign(msg).try_into().expect("firma de 64 B");
    Firma::desde_bytes(sig)
}

/// Un anuncio **bien firmado** con los campos dados (dominio incluido).
fn anuncio(
    semilla: u8,
    huella: [u8; 32],
    clase: u8,
    len_comprimido: u32,
    epoch: u64,
) -> AnuncioPrueba {
    let (kp, pk) = par(semilla);
    let mut a = AnuncioPrueba {
        version: AnuncioPrueba::VERSION,
        clase,
        huella,
        clave_productor: pk,
        epoch,
        n_sectores: 128,
        len_comprimido,
        firma: Firma::desde_bytes([0; 64]),
    };
    a.firma = firmar(&kp, &a.preimagen_firma());
    a
}

// ─────────────────────────────────────────────────────────────────────────────
// Manejador espía
// ─────────────────────────────────────────────────────────────────────────────

struct Espia {
    anuncios: Mutex<Vec<AnuncioPrueba>>,
    servir_llamado: Mutex<Vec<[u8; 32]>>,
    prueba: Mutex<Option<([u8; 32], Vec<u8>)>>,
    veredicto_anuncio: Veredicto,
    penalizados: Mutex<Vec<PeerId>>,
}

impl Espia {
    fn nuevo(veredicto_anuncio: Veredicto) -> Self {
        Self {
            anuncios: Mutex::new(Vec::new()),
            servir_llamado: Mutex::new(Vec::new()),
            prueba: Mutex::new(None),
            veredicto_anuncio,
            penalizados: Mutex::new(Vec::new()),
        }
    }

    /// Este nodo tiene el cuerpo de `huella`: lo servirá.
    fn con_prueba(self, huella: [u8; 32], bytes: Vec<u8>) -> Self {
        *self.prueba.lock().expect("mutex") = Some((huella, bytes));
        self
    }

    fn anuncios(&self) -> Vec<AnuncioPrueba> {
        self.anuncios.lock().expect("mutex").clone()
    }

    fn servir_llamado(&self) -> Vec<[u8; 32]> {
        self.servir_llamado.lock().expect("mutex").clone()
    }

    fn penalizados(&self) -> Vec<PeerId> {
        self.penalizados.lock().expect("mutex").clone()
    }
}

impl ManejadorEntrante for Espia {
    fn estado(&self) -> Estado {
        estado_dev()
    }

    fn bloque_difundido(&self, _id: IdDiferido, _bloque: &BloqueRed) -> Veredicto {
        Veredicto::Aceptar
    }

    fn tx_difundida(&self, _peer: PeerId, _bytes: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn anuncio_prueba(&self, _peer: PeerId, anuncio: &AnuncioPrueba) -> Veredicto {
        self.anuncios.lock().expect("mutex").push(*anuncio);
        self.veredicto_anuncio
    }

    fn servir_prueba(&self, huella: &[u8; 32]) -> Option<Vec<u8>> {
        self.servir_llamado.lock().expect("mutex").push(*huella);
        let guard = self.prueba.lock().expect("mutex");
        match guard.as_ref() {
            Some((h, bytes)) if h == huella => Some(bytes.clone()),
            _ => None,
        }
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

/// Manejador que **no** implementa los callbacks nuevos: usa los defaults del trait (prueba 9).
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

fn estado_dev() -> Estado {
    Estado {
        hash_genesis: BlockHash::from_digest(Digest::from_bytes([0; 32])),
        red: Red::Dev,
        fase: zx_p2p::mensaje::Fase::Pow,
        punta_pow: zx_p2p::mensaje::PuntaPow {
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

// ─────────────────────────────────────────────────────────────────────────────
// Nodos reales
// ─────────────────────────────────────────────────────────────────────────────

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

async fn esperar_suscripcion(
    rx: &mut tokio::sync::mpsc::Receiver<EventoRed>,
    peer: PeerId,
    tema: &str,
) {
    let Some(_) = esperar(rx, |e| {
        matches!(e, EventoRed::Suscripcion { peer: p, topico, suscrito: true }
            if *p == peer && topico == tema)
    })
    .await
    else {
        panic!("no llegó la suscripción de {peer} a {tema}");
    };
}

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

/// Conecta `cliente` a `servidor` y espera a que el servidor lo vea conectado.
async fn conectar(servidor: &mut Nodo, cliente: &mut Nodo) {
    cliente
        .manejo
        .marcar(servidor.direccion.clone())
        .await
        .expect("marcar");
    esperar_conectado(&mut servidor.eventos, cliente.peer_id).await;
}

/// Conecta y espera además la suscripción al tema de pruebas (la malla de gossipsub).
async fn conectar_y_esperar(servidor: &mut Nodo, cliente: &mut Nodo) {
    conectar(servidor, cliente).await;
    esperar_suscripcion(&mut servidor.eventos, cliente.peer_id, TEMA_PRUEBAS).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 1
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 1.** El tema de pruebas se reconoce por igualdad exacta en las tres redes, y ninguna
/// forma parecida cuela.
#[test]
fn cp_red_tema_exacto_por_red() {
    for (p, esperado) in [
        (ParametrosRed::de(Red::Mainnet), "/zerox/pruebas/2"),
        (ParametrosRed::de(Red::Testnet), "/zerox-testnet/pruebas/2"),
        (ParametrosRed::dag_dev(), "/zx-dev/pruebas/2"),
    ] {
        assert_eq!(p.topic_pruebas(), esperado, "{:?}", p.red());
        assert_eq!(
            clasificar_tema(p.topic_pruebas()),
            TemaDifusion::Prueba,
            "{:?}",
            p.red()
        );
        assert!(
            !p.es_tema_de_votos_nuevo(p.topic_pruebas()),
            "{:?}: el tema de pruebas no es de la agregación",
            p.red()
        );
    }

    for malo in [
        "/zx-dev/pruebas/1",
        "/zx-dev/pruebas/2x",
        "/zx-dev/pruebas",
        "/zx-dev/pruebas/",
        "/zx-dev/prueba/2",
        "/zerox/pruebas/2", // es de mainnet, pero clasificar_tema no conoce el nodo: SÍ lo clasifica
    ] {
        let esperado = if malo == "/zerox/pruebas/2" {
            TemaDifusion::Prueba
        } else {
            TemaDifusion::Desconocido
        };
        assert_eq!(clasificar_tema(malo), esperado, "{malo}");
    }

    // La red dev no comparte el tema con las públicas.
    assert_ne!(
        ParametrosRed::dag_dev().topic_pruebas(),
        ParametrosRed::de(Red::Mainnet).topic_pruebas()
    );
    assert_ne!(
        ParametrosRed::de(Red::Testnet).topic_pruebas(),
        ParametrosRed::de(Red::Mainnet).topic_pruebas()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 2
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 2a.** Un anuncio de 146 B viaja entero y llega al nodo con los mismos campos.
#[tokio::test]
async fn cp_red_anuncio_ida_y_vuelta_146() {
    let a = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let b = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    conectar_y_esperar(&mut na, &mut nb).await;

    let enviado = anuncio(1, [0x42; 32], AnuncioPrueba::CLASE_POREP, 318_563, 9);
    assert_eq!(enviado.a_bytes().len(), LONGITUD_ANUNCIO_PRUEBA);
    assert_eq!(LONGITUD_ANUNCIO_PRUEBA, 146);

    na.manejo
        .difundir_anuncio_prueba(&enviado.a_bytes())
        .await
        .expect("publicar el anuncio");

    assert!(
        esperar_hasta(|| b.anuncios().contains(&enviado), Duration::from_secs(5)).await,
        "B debe recibir el anuncio y con los mismos campos"
    );
    assert_eq!(b.anuncios(), vec![enviado]);
    assert!(b.penalizados().is_empty(), "un anuncio válido no penaliza");
}

/// **Prueba 2b.** Las formas inválidas de Q2 se rechazan (longitud, versión, clase y
/// `len_comprimido`), sin llegar siquiera a mirar la firma.
#[test]
fn cp_red_anuncio_forma_invalida_se_rechaza() {
    let bueno = anuncio(2, [0x11; 32], AnuncioPrueba::CLASE_POST, 1, 3);

    // Longitud: 145 y 147.
    let mut corto = bueno.a_bytes();
    corto.pop();
    assert_eq!(
        AnuncioPrueba::desde_bytes(&corto),
        Err(ErrorAnuncio::Longitud(145))
    );
    let mut largo = bueno.a_bytes();
    largo.push(0);
    assert_eq!(
        AnuncioPrueba::desde_bytes(&largo),
        Err(ErrorAnuncio::Longitud(147))
    );

    // Versión 2.
    let mut version = bueno;
    version.version = 2;
    assert_eq!(
        AnuncioPrueba::desde_bytes(&version.a_bytes()),
        Err(ErrorAnuncio::VersionDesconocida(2))
    );

    // Clases fuera del conjunto cerrado.
    for clase in [0x00u8, 0x03, 0x06, 0x0D] {
        let mut malo = bueno;
        malo.clase = clase;
        assert_eq!(
            AnuncioPrueba::desde_bytes(&malo.a_bytes()),
            Err(ErrorAnuncio::ClaseDesconocida(clase)),
            "clase {clase:#04x}"
        );
    }

    // len_comprimido 0 y 352 001 (el tope es 352 000, el gemelo de zx-pruebas).
    assert_eq!(MAX_PRUEBA_COMPRIMIDA_BYTES, 352_000);
    for len in [0u32, 352_001] {
        let mut malo = bueno;
        malo.len_comprimido = len;
        assert_eq!(
            AnuncioPrueba::desde_bytes(&malo.a_bytes()),
            Err(ErrorAnuncio::LenComprimido(len)),
            "len {len}"
        );
    }

    // El borde exacto del tope sí entra.
    let mut borde = bueno;
    borde.len_comprimido = 352_000;
    assert!(AnuncioPrueba::desde_bytes(&borde.a_bytes()).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 3
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 3.** Una firma inválida (incluida una firma **válida** sobre `huella ‖ clase ‖ epoch`
/// **sin** el dominio) se rechaza; y en red, el par que la manda es penalizado y el nodo no la ve.
#[tokio::test]
async fn cp_t_38_anuncio_con_firma_invalida_se_rechaza_y_penaliza() {
    let huella = [0x77; 32];
    let valido = anuncio(3, huella, AnuncioPrueba::CLASE_TURNO, 1_000, 5);

    // (a) Firma de ceros.
    let mut sin_firma = valido;
    sin_firma.firma = Firma::desde_bytes([0; 64]);
    assert_eq!(
        AnuncioPrueba::desde_bytes_validado(&sin_firma.a_bytes()),
        Err(ErrorAnuncio::FirmaInvalida)
    );

    // (b) Firma válida sobre `huella ‖ clase ‖ epoch` SIN el dominio: se rechaza.
    let (kp, pk) = par(3);
    let mut sin_dominio = AnuncioPrueba {
        version: AnuncioPrueba::VERSION,
        clase: AnuncioPrueba::CLASE_TURNO,
        huella,
        clave_productor: pk,
        epoch: 5,
        n_sectores: 128,
        len_comprimido: 1_000,
        firma: Firma::desde_bytes([0; 64]),
    };
    let mut mensaje = Vec::new();
    mensaje.extend_from_slice(&sin_dominio.huella);
    mensaje.push(sin_dominio.clase);
    mensaje.extend_from_slice(&sin_dominio.epoch.to_be_bytes());
    sin_dominio.firma = firmar(&kp, &mensaje);
    // La firma es criptográficamente válida sobre ese mensaje...
    assert!(
        zx_core::firma::verificar(&pk, &sin_dominio.firma, &mensaje).is_ok(),
        "control: la firma sin dominio es válida sobre su mensaje"
    );
    // ...pero NO sobre la preimagen con dominio, así que el anuncio se rechaza.
    assert_eq!(
        AnuncioPrueba::desde_bytes_validado(&sin_dominio.a_bytes()),
        Err(ErrorAnuncio::FirmaInvalida)
    );

    // (c) En red: el nodo no lo ve y el emisor queda penalizado.
    let a = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let b = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    conectar_y_esperar(&mut na, &mut nb).await;

    na.manejo
        .difundir_anuncio_prueba(&sin_firma.a_bytes())
        .await
        .expect("publicar el anuncio inválido");

    assert!(
        esperar_hasta(
            || b.penalizados().contains(&na.peer_id),
            Duration::from_secs(5)
        )
        .await,
        "B debe penalizar al que manda una firma inválida"
    );
    assert!(
        b.anuncios().is_empty(),
        "un anuncio con firma inválida NO debe llegar al nodo"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 4
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 4.** Por el tema de pruebas solo pasa el anuncio de 146 B: un cuerpo mayor no llega al
/// nodo y penaliza a quien lo mandó.
#[tokio::test]
async fn cp_t_11_el_cuerpo_no_va_por_difusion() {
    let a = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let b = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    conectar_y_esperar(&mut na, &mut nb).await;

    // 300 B: el tamaño de un cuerpo, no el de un anuncio.
    na.manejo
        .difundir_anuncio_prueba(&[0u8; 300])
        .await
        .expect("el emisor local no aplica el tope del receptor");

    assert!(
        esperar_hasta(
            || b.penalizados().contains(&na.peer_id),
            Duration::from_secs(5)
        )
        .await,
        "un mensaje mayor que 146 B en el tema de pruebas penaliza"
    );
    assert!(
        b.anuncios().is_empty(),
        "el cuerpo NO debe llegar al manejador por difusión"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 5
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 5.** Tres nodos: quien tiene la prueba la sirve entera; quien no, responde
/// `NoDisponible` sin penalización.
#[tokio::test]
async fn cp_t_12_peticion_respuesta_y_no_disponible() {
    let huella = [0x5a; 32];
    let cuerpo: Vec<u8> = (0..200u8).collect();

    let a = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let b = Arc::new(Espia::nuevo(Veredicto::Aceptar).con_prueba(huella, cuerpo.clone()));
    let c = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    let mut nc = nodo(Arc::clone(&c)).await;

    conectar(&mut na, &mut nb).await;
    conectar(&mut na, &mut nc).await;

    na.manejo
        .pedir_prueba(nb.peer_id, huella)
        .await
        .expect("A pide a B");
    na.manejo
        .pedir_prueba(nc.peer_id, huella)
        .await
        .expect("A pide a C");

    let mut de_b = None;
    let mut de_c = None;
    for _ in 0..2 {
        let Some(EventoRed::Respuesta {
            peer, respuesta, ..
        }) = esperar(&mut na.eventos, |e| {
            matches!(e, EventoRed::Respuesta { .. })
        })
        .await
        else {
            panic!("A debería recibir dos respuestas");
        };
        if peer == nb.peer_id {
            de_b = Some(*respuesta);
        } else if peer == nc.peer_id {
            de_c = Some(*respuesta);
        }
    }

    assert_eq!(
        de_b,
        Some(Respuesta::Prueba {
            huella,
            bytes: cuerpo
        }),
        "B tiene la prueba y la sirve entera"
    );
    assert_eq!(
        de_c,
        Some(Respuesta::NoDisponible),
        "C no la tiene y lo dice sin penalizar"
    );
    assert!(b.servir_llamado().contains(&huella));
    assert!(c.servir_llamado().contains(&huella));
    assert!(
        a.penalizados().is_empty() && b.penalizados().is_empty() && c.penalizados().is_empty(),
        "ni `NoDisponible` ni una respuesta válida penalizan"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 6
// ─────────────────────────────────────────────────────────────────────────────

/// Bytes que no se comprimen a más de 1000:1 (xorshift64), para que la defensa de ratio del códec
/// no intercepte la respuesta antes de que el servicio aplique el tope del carril.
fn incompresible(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x & 0xff) as u8);
    }
    v
}

/// **Prueba 6.** Una respuesta por encima del tope o con otra huella se rechaza. La parte pura fija
/// la regla; la de red comprueba que además penaliza.
#[tokio::test]
async fn cp_t_12_respuesta_mayor_que_el_tope_o_de_otra_huella_se_rechaza() {
    let h = [0x33; 32];
    assert_eq!(MAX_RESPUESTA_PRUEBA_BYTES, 352_035);

    // La regla pura, con el borde exacto.
    assert!(prueba_respuesta_aceptable(&h, &Respuesta::NoDisponible));
    assert!(prueba_respuesta_aceptable(
        &h,
        &Respuesta::Prueba {
            huella: h,
            bytes: vec![0u8; MAX_RESPUESTA_PRUEBA_BYTES as usize],
        }
    ));
    assert!(!prueba_respuesta_aceptable(
        &h,
        &Respuesta::Prueba {
            huella: h,
            bytes: vec![0u8; MAX_RESPUESTA_PRUEBA_BYTES as usize + 1],
        }
    ));
    assert!(!prueba_respuesta_aceptable(
        &h,
        &Respuesta::Prueba {
            huella: [0x44; 32],
            bytes: vec![0u8; 16],
        }
    ));
    assert!(!prueba_respuesta_aceptable(
        &h,
        &Respuesta::Bloques(Vec::new())
    ));

    // Y en red: un manejador que miente con el tamaño hace que A penalice a B.
    let a = Arc::new(Espia::nuevo(Veredicto::Aceptar));
    let b = Arc::new(
        Espia::nuevo(Veredicto::Aceptar)
            .con_prueba(h, incompresible(MAX_RESPUESTA_PRUEBA_BYTES as usize + 1)),
    );
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    conectar(&mut na, &mut nb).await;

    na.manejo
        .pedir_prueba(nb.peer_id, h)
        .await
        .expect("A pide a B");

    assert!(
        esperar_hasta(|| b.servir_llamado().contains(&h), Duration::from_secs(5)).await,
        "B debe haber sido consultado"
    );
    assert!(
        esperar_hasta(
            || a.penalizados().contains(&nb.peer_id),
            Duration::from_secs(5)
        )
        .await,
        "una respuesta por encima del tope debe penalizar al que la manda"
    );
    assert!(
        no_llega(&mut na.eventos, Duration::from_millis(500), |e| matches!(
            e,
            EventoRed::Respuesta { .. }
        ))
        .await,
        "la respuesta inválida NO debe llegar al nodo"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 7
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 7a.** Un par no puede tener dos peticiones de prueba en vuelo a la vez.
#[test]
fn cp_t_13_un_par_no_tiene_dos_peticiones_de_prueba_a_la_vez() {
    assert_eq!(MAX_PRUEBAS_EN_VUELO_POR_PAR, 1);
    assert!(cabe_prueba(0, 0), "sin nada en vuelo, cabe");
    assert!(
        cabe_prueba(0, MAX_PRUEBAS_EN_VUELO_NODO - 1),
        "con sitio global y el par a cero, cabe"
    );
    assert!(
        !cabe_prueba(MAX_PRUEBAS_EN_VUELO_POR_PAR, 1),
        "el mismo par con una en vuelo no admite otra"
    );
    assert!(
        !cabe_prueba(MAX_PRUEBAS_EN_VUELO_POR_PAR, MAX_PRUEBAS_EN_VUELO_NODO - 1),
        "aunque quede sitio global, la cuota por par corta"
    );
}

/// **Prueba 7b.** La quinta petición del nodo no entra (la cuarta sí).
#[test]
fn cp_t_13_la_quinta_del_nodo_no_entra() {
    assert_eq!(MAX_PRUEBAS_EN_VUELO_NODO, 4);
    for total in 0..MAX_PRUEBAS_EN_VUELO_NODO {
        assert!(
            cabe_prueba(0, total),
            "con {total} en vuelo, la siguiente cabe"
        );
    }
    assert!(
        !cabe_prueba(0, MAX_PRUEBAS_EN_VUELO_NODO),
        "la quinta del nodo no entra"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 8
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 8.** Las variantes nuevas no chocan con el registro de direcciones: ida y vuelta de
/// **todas** las variantes de `Peticion` y `Respuesta`, con sus identificadores escritos.
#[test]
fn cp_red_identificadores_no_chocan_con_el_registro_de_direcciones() {
    // Los identificadores del registro de direcciones no se tocan, y los nuevos son los siguientes.
    assert_eq!(Peticion::DISC_REGISTRO_DIRECCIONES, 0x04);
    assert_eq!(Peticion::DISC_PRUEBA, 0x05);
    assert_eq!(Respuesta::DISC_REGISTRO_DIRECCIONES, 0x05);
    assert_eq!(Respuesta::DISC_PRUEBA, 0x06);
    assert_ne!(Peticion::DISC_PRUEBA, Peticion::DISC_REGISTRO_DIRECCIONES);
    assert_ne!(Respuesta::DISC_PRUEBA, Respuesta::DISC_REGISTRO_DIRECCIONES);

    let huella = [0x21; 32];
    let peticiones = vec![
        Peticion::Estado,
        Peticion::CabecerasPow {
            locator: vec![BlockHash::from_digest(Digest::from_bytes([1; 32]))],
            parada: None,
        },
        Peticion::Bloques {
            hashes: vec![BlockHash::from_digest(Digest::from_bytes([2; 32]))],
        },
        Peticion::Registro { desde: 7 },
        Peticion::RegistroDirecciones { desde: 9 },
        Peticion::Prueba { huella },
    ];
    let mut vistos = Vec::new();
    for p in &peticiones {
        assert!(!vistos.contains(&p.discriminante()), "{p:?} colisiona");
        vistos.push(p.discriminante());
        let bytes = zx_p2p::codec::peticion_a_bytes(p);
        let leida = zx_p2p::codec::peticion_desde_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{p:?} no da la vuelta: {e:?}"));
        assert_eq!(&leida, p, "{p:?} vuelve distinta");
    }

    let respuestas = vec![
        Respuesta::NoDisponible,
        Respuesta::Bloques(Vec::new()),
        Respuesta::Registro {
            desde: 0,
            bloques: Vec::new(),
            longitud: 0,
        },
        Respuesta::RegistroDirecciones {
            desde: 1,
            entradas: Vec::new(),
            total: 0,
        },
        Respuesta::Prueba {
            huella,
            bytes: vec![0xAA; 200],
        },
    ];
    let mut vistos = Vec::new();
    for r in &respuestas {
        assert!(!vistos.contains(&r.discriminante()), "{r:?} colisiona");
        vistos.push(r.discriminante());
        let bytes = zx_p2p::codec::respuesta_a_bytes(r);
        let leida = zx_p2p::codec::respuesta_desde_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{r:?} no da la vuelta: {e:?}"));
        assert_eq!(&leida, r, "{r:?} vuelve distinta");
    }

    // Una respuesta de prueba responde a una petición de prueba y a ninguna otra.
    assert!(
        Respuesta::Prueba {
            huella,
            bytes: Vec::new()
        }
        .responde_a(&Peticion::Prueba { huella })
    );
    assert!(
        !Respuesta::Prueba {
            huella,
            bytes: Vec::new()
        }
        .responde_a(&Peticion::RegistroDirecciones { desde: 0 })
    );
    assert!(
        Respuesta::NoDisponible.responde_a(&Peticion::Prueba { huella }),
        "NoDisponible vale para una petición de prueba"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Prueba 9
// ─────────────────────────────────────────────────────────────────────────────

/// **Prueba 9.** Con la implementación por defecto del trait: el anuncio se ignora y una petición
/// recibe `NoDisponible`, todo **sin penalizar**.
#[tokio::test]
async fn cp_red_por_defecto_anuncio_ignorado_y_no_disponible() {
    let a = Arc::new(SoloDefecto::default());
    let b = Arc::new(SoloDefecto::default());
    let mut na = nodo(Arc::clone(&a)).await;
    let mut nb = nodo(Arc::clone(&b)).await;
    conectar_y_esperar(&mut na, &mut nb).await;

    let enviado = anuncio(4, [0x66; 32], AnuncioPrueba::CLASE_POREP, 2_000, 1);
    na.manejo
        .difundir_anuncio_prueba(&enviado.a_bytes())
        .await
        .expect("publicar");

    // El default ignora el anuncio: ni lo reenvía ni penaliza.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        b.penalizados().is_empty(),
        "el default `Ignorar` del anuncio no penaliza"
    );

    // El default de servir responde "no la tengo".
    na.manejo
        .pedir_prueba(nb.peer_id, enviado.huella)
        .await
        .expect("pedir");
    let Some(EventoRed::Respuesta { respuesta, .. }) = esperar(&mut na.eventos, |e| {
        matches!(e, EventoRed::Respuesta { .. })
    })
    .await
    else {
        panic!("A debería recibir la respuesta por defecto");
    };
    assert_eq!(*respuesta, Respuesta::NoDisponible);
    assert!(
        a.penalizados().is_empty() && b.penalizados().is_empty(),
        "`NoDisponible` no penaliza"
    );
}
