//! `zx-txcliente`: cliente de prueba de transacciones para V5/V6 de `ORDEN-TX3-2`.
//!
//! **No es un nodo** (igual que `zx-adversario`): habla el protocolo real de `zx-p2p` (mismo
//! transporte, behaviour y red dev) para inyectar transacciones en la mempool de un nodo objetivo a
//! través del tema de gossip `/zx-dev/tx/1`, y observa por los temas de bloques lo que la red hace
//! con ellas. Es el «cliente de prueba» que pide V5 mientras TX-4 construye la cartera de verdad.
//!
//! # Por qué existe el modo `transferir` con clave cruzada
//!
//! La economía dev hace **imposible** una transferencia v1 admisible: la coinbase PoW vale
//! `Amount::nuevo(50)` = 50 brek (`perfil.rs`, `SUBSIDIO_POW_BREK`), mientras que la política de
//! mempool de TX-3 exige `fee ≥ φ_min·peso` con `φ_min = 1 brek/B` ⇒ una v1 de una entrada necesita
//! ~150 brek. Por eso el modo `transferir` construye el camino económicamente equivalente a
//! «transferencia + depósito»: un **depósito v2 de clave cruzada** que gasta una coinbase PoW no
//! depositada del emisor (firma de entrada del emisor) y acredita la garantía de la clave nueva
//! (firma de aceptación de la clave nueva). Es el único camino válido bajo el perfil dev para dar
//! garantía a un nodo que cruzó el corte sin ella. Ver `PROGRESO.md` §2-bis.
//!
//! # Modos
//!
//! - `transferir`: espera al corte, elige la coinbase PoW no depositada más reciente del emisor,
//!   publica el depósito de clave cruzada hacia la clave destino y espera a verlo incluido en un
//!   bloque.
//! - `inundar`: tras el corte, hace un **abanico** de salidas de valor 0 desde una coinbase PoW
//!   conocida (v1 válida: en el perfil dev `phi_min = 0`, así que una tarifa de 0 entra) y **gasta**
//!   cada salida en cadena a la tasa pedida (`--tasa` B/s), creando una salida nueva por gasto. Las
//!   firmas usan el valor **real** gastado, de modo que la mempool las admite y nunca las clasifica
//!   `Demostrable` (TX-6-2: el `v1_ruido` de TX-6 firmaba con un valor falso y expulsaba al cliente).
//! - `--solo-tx`: modo solo-transacciones. El cliente nunca difunde ni reenvía bloques (su
//!   `bloque_difundido` ya devuelve `Ignorar` y no hay ninguna llamada a `difundir_bloque`); la
//!   recepción de bloques sigue activa para detectar el corte y las coinbases PoW. El contador final
//!   `bloques vistos N, reenviados 0` lo deja por escrito.
//!
//! Uso:
//! ```text
//! zx-txcliente --objetivo /ip4/127.0.0.1/tcp/PUERTO transferir  --indice-destino 3
//! zx-txcliente --objetivo /ip4/127.0.0.1/tcp/PUERTO --solo-tx inundar --segundos 600 \
//!   --tasa 1048576 --salidas 64
//! ```

#![allow(
    clippy::all,
    reason = "herramienta de prueba de un solo uso (V5/V6); se silencian los lints de estilo/perf \
              por defecto, pero NO los `deny` del workspace (unwrap/expect/panic/wildcard), que este \
              fichero respeta"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use libp2p::core::transport::Transport as _;
use libp2p::{Multiaddr, PeerId, Swarm, identity, noise, yamux};
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest};
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_core::tx::{
    ExtensionTx, Lock, OperacionAlmacenamiento, OperacionSector, OutPoint, SpentOutput,
    TipoGarantia, Tx, TxIn, TxOut,
};
use zx_core::{
    CBID_RED_DEV, HashType, LONGITUD_CLAVE_BLS, LONGITUD_PRUEBA_POSESION_BLS, mensaje_aceptacion,
    mensaje_almacenamiento, mensaje_sector, sighash, txid,
};
use zx_node::claves::ClaveDev;
use zx_node::cli::RedCli;
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};
use zx_p2p::servicio::{EventoRed, arrancar};

/// CLI del cliente de prueba.
#[derive(Parser, Debug)]
#[command(
    name = "zx-txcliente",
    about = "Cliente de transacciones de TX-3-2 (V5/V6)"
)]
struct Cli {
    /// Dirección del nodo objetivo (el que escucha).
    #[arg(long, value_name = "MULTIADDR")]
    objetivo: Multiaddr,

    /// Red configurada, igual que en `zx-node`.
    #[arg(long, value_enum, default_value_t = RedCli::Dev)]
    red: RedCli,

    /// Semilla de derivación de claves dev (debe coincidir con la de los nodos).
    #[arg(long, default_value_t = 1)]
    semilla: u64,

    /// Índices de claves que el cliente conoce y con las que puede firmar.
    #[arg(long, value_delimiter = ',', default_value = "0,1,2,3")]
    indices: Vec<u32>,

    /// Índice de la clave destino (la que cruzó sin garantía).
    #[arg(long, default_value_t = 3)]
    indice_destino: u32,

    /// Slots que se esperan tras el primer bloque PoST antes de publicar (madurez `M_res_slots`).
    #[arg(long, default_value_t = 30)]
    espera_slot: u64,

    /// Cuántas coinbases PoW hacia atrás se elige la del emisor (0 = la más reciente).
    #[arg(long, default_value_t = 0)]
    retroceso: usize,

    /// Plazo global del modo `transferir`, en segundos.
    #[arg(long, default_value_t = 600)]
    plazo_s: u64,

    /// TX-6-2 · modo solo-transacciones: el cliente no difunde ni reenvía bloques. Sigue recibiendo
    /// bloques para detectar el corte y recolectar las coinbases PoW. La inundación del arnés lo usa.
    #[arg(long, default_value_t = false)]
    solo_tx: bool,

    /// Subcomando.
    #[command(subcommand)]
    modo: Modo,
}

/// Modo de operación.
#[derive(Subcommand, Debug)]
enum Modo {
    /// Publica un depósito de clave cruzada hacia `--indice-destino` y espera su inclusión.
    Transferir,
    /// Inunda la mempool del objetivo durante `--segundos`.
    Inundar {
        /// Duración de la inundación, en segundos.
        #[arg(long, default_value_t = 600)]
        segundos: u64,
        /// TX-6: tasa de oferta objetivo en **bytes por segundo** (0 = sin límite). El arnés usa
        /// `--tasa 1048576` (1 MiB/s, el máximo por par de DR-07).
        #[arg(long, default_value_t = 0)]
        tasa: u64,
        /// TX-6-2: salidas del abanico inicial de valor 0 (una cadena de gasto por salida).
        #[arg(long, default_value_t = 64)]
        salidas: usize,
        /// TX-6-2: además de inundar, publica el depósito de clave cruzada a `--indice-destino`
        /// gastando la primera salida del abanico. Permite que la inundación y el depósito del
        /// granjero compartan la **misma** coinbase (la única viva tras el corte, porque el nodo
        /// auto-deposita en cada bloque PoW toda coinbase propia madura).
        #[arg(long, default_value_t = false)]
        depositar: bool,
    },
    /// SR-1-2 · publica un **alta de sector** v5 (`C-SEC-02`) firmada por `--indice-destino`.
    SectorAlta {
        /// Índice de sector dentro de la clave.
        #[arg(long, default_value_t = 0)]
        sector_index: u16,
        /// `history_size` declarado.
        #[arg(long, default_value_t = 1 << 20)]
        history_size: u64,
        /// SR-G2b · número de altas consecutivas (misma clave) para llenar una caja; la `k+1` se
        /// publica solo cuando la `k` aparece incluida, de modo que se respeta la regla de madurez.
        #[arg(long, default_value_t = 1)]
        sector_n: u16,
    },
    /// FV-4b-N1-2 · publica un **registro v6 de la clave BLS de voto** (`clase 0x03`) firmado por
    /// `--indice-destino`, con la prueba de posesión derivada de `--semilla` e `--indice-voto`.
    ///
    /// La clave BLS que se registra es la **misma** que el nodo deriva en dev para ese índice
    /// (`zx_node::votos::derivar_ikm_voto`), de modo que, tras incluirse la transacción, el nodo ya
    /// puede firmar votos con ella. Reintenta cada 5 s hasta el plazo.
    ClaveVoto {
        /// Índice con el que se deriva la clave BLS de voto; si falta, el de `--indice-destino`.
        #[arg(long)]
        indice_voto: Option<u32>,
    },
}

/// Manejador espía: guarda cada bloque difundido para que el bucle principal lo inspeccione.
struct Espia {
    hash_genesis: BlockHash,
    red: Red,
    bloques: Mutex<Option<tokio::sync::mpsc::UnboundedSender<BloqueRed>>>,
}

impl Espia {
    fn nuevo(
        red_cli: RedCli,
        bloques: Option<tokio::sync::mpsc::UnboundedSender<BloqueRed>>,
    ) -> Result<Self, String> {
        let red = Red::from(red_cli);
        if red != Red::Dev {
            return Err(zx_node::error::ErrorNodo::RedNoEsDev { encontrada: red }.to_string());
        }
        let perfil = red_cli.perfil_red().map_err(|e| e.to_string())?;
        Ok(Self {
            hash_genesis: zx_node::perfil::identidad_red(&perfil),
            red,
            bloques: Mutex::new(bloques),
        })
    }
}

impl ManejadorEntrante for Espia {
    fn estado(&self) -> Estado {
        // La misma identidad que el nodo del perfil elegido; dev conserva el saludo anterior.
        Estado {
            hash_genesis: self.hash_genesis,
            red: self.red,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: BlockHash::from_digest(Digest::from_bytes([0xEE; 32])),
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
        if let Ok(guard) = self.bloques.lock()
            && let Some(tx) = guard.as_ref()
        {
            let _ = tx.send(bloque.clone());
        }
        Veredicto::Ignorar
    }

    fn tx_difundida(&self, _peer: PeerId, _tx: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    fn cabeceras_desde(
        &self,
        _locator: &[BlockHash],
        _hasta: Option<BlockHash>,
    ) -> Vec<BlockHeader> {
        Vec::new()
    }

    fn bloques_por_hash(&self, _hashes: &[BlockHash]) -> Vec<BloqueRed> {
        Vec::new()
    }
}

fn swarm_tcp() -> Result<Swarm<ZxBehaviour>, String> {
    let clave = identity::Keypair::generate_ed25519();
    let peer_id = clave.public().to_peer_id();
    let ruido = noise::Config::new(&clave).map_err(|e| format!("noise: {e}"))?;
    let transporte = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
        .authenticate(ruido)
        .multiplex(yamux::Config::default())
        .boxed();
    let behaviour = ZxBehaviour::nueva(
        &clave,
        ParametrosRed::dag_dev(),
        zx_p2p::limites::LIMITE_BLOQUE_DEV,
    )
    .map_err(|e| format!("behaviour de la red dev: {e}"))?;
    Ok(Swarm::new(
        transporte,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(30)),
    ))
}

/// Búsqueda de la clave que controla una salida `PubKey`.
fn clave_de_salida(tx: &Tx, claves: &[ClaveDev]) -> Option<(ClaveDev, Amount)> {
    let out = tx.outputs.first()?;
    let Lock::PubKey { pubkey } = &out.lock else {
        return None;
    };
    claves
        .iter()
        .find(|c| c.pk == *pubkey)
        .map(|c| (c.clone(), out.value))
}

/// Publica una transacción serializada, con reintentos cortos (la suscripción de gossipsub puede
/// no haber cuajado en el primer intento).
async fn publicar(manejo: &zx_p2p::servicio::ManejoRed, bytes: &[u8]) -> Result<(), String> {
    let mut ultimo = String::new();
    for _ in 0..20 {
        match manejo.difundir_tx(bytes).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                ultimo = format!("{e}");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    Err(ultimo)
}

/// Construye un depósito v2 de clave cruzada: el input pertenece a `dueno` y la garantía se acredita
/// a `destino`. Firmas: entrada por `dueno`, aceptación por `destino`.
fn deposito_clave_cruzada(
    outpoint: OutPoint,
    valor: Amount,
    dueno: &ClaveDev,
    destino: &ClaveDev,
) -> Result<(Tx, Vec<Vec<u8>>), String> {
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            outpoint,
            sequence: 0,
        }],
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo: TipoGarantia::Deposito,
            clave: destino.pk,
            importe: valor,
            nonce: 0,
        },
    };
    let gastadas = [SpentOutput {
        value: valor,
        lock: Lock::PubKey { pubkey: dueno.pk },
    }];
    let digest = sighash(&tx, &gastadas, HashType::All, 0, CBID_RED_DEV)
        .map_err(|e| format!("sighash: {e}"))?;
    let firma_entrada: [u8; 64] = dueno.sk.sign(digest.as_bytes()).into();
    let firma_aceptacion: [u8; 64] = destino
        .sk
        .sign(&mensaje_aceptacion(&tx, CBID_RED_DEV))
        .into();
    Ok((tx, vec![firma_entrada.to_vec(), firma_aceptacion.to_vec()]))
}

/// TX-6-2 · transferencia v1 **válida**: gasta `outpoint` (con valor `valor` y lock del `dueno`) y
/// crea `n_salidas` salidas al `dueno`: la primera vale `salida_0` y el resto [`Amount::CERO`]. El
/// valor restante es la tarifa; en el perfil dev `phi_min = 0`, así que una tarifa de 0 entra igual.
/// Firma la entrada con el valor **real** gastado: es lo que evita el `ErrFirma`/`Demostrable` que
/// expulsaba al cliente en TX-6 (allí el ruido firmaba con `value = 1` aunque gastara una coinbase
/// de 50 brek). Con `salida_0 = valor` el abanico deja una salida que puede financiar el depósito de
/// clave cruzada del granjero dentro del **mismo** árbol de transacciones.
fn transferencia_v1(
    outpoint: OutPoint,
    valor: Amount,
    dueno: &ClaveDev,
    n_salidas: usize,
    salida_0: Amount,
) -> Result<(Tx, Vec<Vec<u8>>), String> {
    let tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint,
            sequence: 0,
        }],
        outputs: (0..n_salidas)
            .map(|j| TxOut {
                value: if j == 0 { salida_0 } else { Amount::CERO },
                lock: Lock::PubKey { pubkey: dueno.pk },
            })
            .collect(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let gastadas = [SpentOutput {
        value: valor,
        lock: Lock::PubKey { pubkey: dueno.pk },
    }];
    let digest = sighash(&tx, &gastadas, HashType::All, 0, CBID_RED_DEV)
        .map_err(|e| format!("sighash: {e}"))?;
    let firma: [u8; 64] = dueno.sk.sign(digest.as_bytes()).into();
    Ok((tx, vec![firma.to_vec()]))
}

fn bytes_tx(tx: &Tx, testigos: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
    buf
}

/// FV-4b-N1-2 · Deriva la clave BLS de voto dev `(semilla, indice)` y su prueba de posesión, lista
/// para el registro v6 `0x03`. Es la **misma** derivación que hace el nodo al arrancar su motor.
fn derivar_clave_voto(
    semilla: u64,
    indice: u32,
) -> Result<([u8; LONGITUD_CLAVE_BLS], [u8; LONGITUD_PRUEBA_POSESION_BLS]), String> {
    let sk = zx_node::votos::clave_voto_dev(semilla, indice)
        .map_err(|e| format!("clave BLS de voto: {e}"))?;
    let pk = sk.clave_publica();
    let prueba = zx_votos::probar_posesion(&sk);
    Ok((pk.bytes(), prueba.bytes()))
}

/// TX-6: espera lo necesario para que, desde `inicio`, no se hayan ofrecido más de `tasa` bytes por
/// segundo. `tasa == 0` no limita (comportamiento anterior). El objetivo se calcula en nanosegundos
/// con enteros: no usa coma flotante.
#[allow(
    clippy::integer_division,
    reason = "el objetivo es una división entera determinista; la coma flotante no es admisible aquí"
)]
async fn esperar_tasa(inicio: tokio::time::Instant, bytes: u64, tasa: u64) {
    if tasa == 0 {
        return;
    }
    let objetivo_ns = u128::from(bytes).saturating_mul(1_000_000_000) / u128::from(tasa);
    let transcurrido = inicio.elapsed().as_nanos();
    if transcurrido < objetivo_ns {
        // TX-6: no dormir por deudas de sub-milisegundo (el temporizador redondea a ~1 ms y
        // estrangularía la tasa); la deuda se acumula y se paga cuando llega a 2 ms.
        let falta = objetivo_ns - transcurrido;
        if falta >= 2_000_000 {
            let nanos = falta.min(u128::from(u64::MAX));
            tokio::time::sleep(Duration::from_nanos(nanos as u64)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let (tx_bloques, mut rx_bloques) = tokio::sync::mpsc::unbounded_channel::<BloqueRed>();
    let espia = match Espia::nuevo(cli.red, Some(tx_bloques)) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("zx-txcliente: {e}");
            std::process::exit(2);
        }
    };
    let claves: Vec<ClaveDev> = cli
        .indices
        .iter()
        .map(|i| ClaveDev::derivar(cli.semilla, *i))
        .collect();
    let destino = ClaveDev::derivar(cli.semilla, cli.indice_destino);

    let swarm = match swarm_tcp() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zx-txcliente: no se pudo construir la red: {e}");
            std::process::exit(1);
        }
    };
    let piezas = arrancar(swarm, Arc::clone(&espia));
    let manejo = piezas.manejo;
    let mut eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());

    println!(
        "zx-txcliente: marcando {} (semilla {}, índices {:?}, destino {}) ...",
        cli.objetivo, cli.semilla, cli.indices, cli.indice_destino
    );
    if let Err(e) = manejo.marcar(cli.objetivo.clone()).await {
        eprintln!("zx-txcliente: no se pudo marcar: {e}");
        std::process::exit(1);
    }

    // Espera conexión y suscripción al tema de tx del objetivo.
    let topico_tx = ParametrosRed::dag_dev().topic_txs().to_owned();
    let mut conectado = false;
    let mut suscrito = false;
    let limite = tokio::time::Instant::now() + Duration::from_secs(30);
    while (!conectado || !suscrito) && tokio::time::Instant::now() < limite {
        match tokio::time::timeout(Duration::from_millis(500), eventos.recv()).await {
            Ok(Some(EventoRed::PeerConectado(_))) => conectado = true,
            Ok(Some(EventoRed::Suscripcion {
                topico,
                suscrito: s,
                ..
            })) if topico == topico_tx && s => suscrito = true,
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    println!("zx-txcliente: conectado={conectado} suscrito_tx={suscrito}");

    // Acumula las coinbases PoW vistas y detecta el corte (primer bloque PoST) y su slot.
    let mut pow_coinbases: Vec<(u32, Tx)> = Vec::new();
    let mut slot_corte: Option<u64> = None;
    let mut slot_actual: u64 = 0;
    let mut corte_anunciado = false;

    // Estado del modo transferir.
    let mut deposito_publicado = false;
    let mut deposito_txid: Option<zx_core::TxId> = None;
    let mut incluido = false;

    // Estado del modo inundar.
    let (inundar, segundos, tasa) = match &cli.modo {
        Modo::Transferir | Modo::SectorAlta { .. } | Modo::ClaveVoto { .. } => (false, 0u64, 0u64),
        Modo::Inundar { segundos, tasa, .. } => (true, *segundos, *tasa),
    };
    let es_sector = matches!(cli.modo, Modo::SectorAlta { .. });
    let es_clave_voto = matches!(cli.modo, Modo::ClaveVoto { .. });
    // TX-6: `base_programa` mide el plazo global; `base_inundacion` se fija con el primer envío
    // real, de modo que `--segundos` cuenta el tiempo **inundando**, no la espera del corte.
    let base_programa = tokio::time::Instant::now();
    let mut base_inundacion_opt: Option<tokio::time::Instant> = None;
    // TX-6: limitador de tasa. `inicio_tasa` se fija con el primer envío válido (no antes de
    // madurar el corte), para no acumular un crédito de bytes que produciría una ráfaga inicial.
    let mut inicio_tasa: Option<tokio::time::Instant> = None;
    let mut bytes_tasa: u64 = 0;
    // TX-6-2 · generador de txs válidas: cola de UTXO de valor 0 que se gastan en cadena. El abanico
    // inicial la llena desde una coinbase PoW; cada gasto repone una salida nueva.
    let mut utxos: VecDeque<(OutPoint, Amount, ClaveDev)> = VecDeque::new();
    let mut abanico_hecho = false;
    let salidas_fanout = match &cli.modo {
        Modo::Inundar { salidas, .. } => (*salidas).max(1),
        _ => 1,
    };
    let inundar_deposita = matches!(
        cli.modo,
        Modo::Inundar {
            depositar: true,
            ..
        }
    );
    let mut enviados_validos: u64 = 0;
    let mut bloques_vistos: u64 = 0;
    // TX-6-2 · instante del último aviso de progreso de la inundación (cada 60 s).
    let mut ultimo_aviso = tokio::time::Instant::now();

    // SR-1-2 · estado del modo `sector-alta`.
    let mut sector_publicado = false;
    let mut sector_txid: Option<zx_core::TxId> = None;
    let mut sector_incluido = false;
    let mut sector_anunciado = false;
    let mut ultimo_sector = tokio::time::Instant::now();
    // SR-G2b · altas consecutivas de la misma clave (caja de varios sectores).
    let (sector_base, sector_n) = match &cli.modo {
        Modo::SectorAlta {
            sector_index,
            sector_n,
            ..
        } => (*sector_index, (*sector_n).max(1)),
        _ => (0, 1),
    };
    let mut sector_actual = sector_base;

    // FV-4b-N1-2 · estado del modo `clave-voto` (registro v6 `0x03` de la clave BLS de voto).
    let mut voto_publicado = false;
    let mut voto_txid: Option<zx_core::TxId> = None;
    let mut voto_incluido = false;
    let mut voto_anunciado = false;
    let mut ultimo_voto = tokio::time::Instant::now();

    loop {
        // Procesa bloques con un pequeño plazo para no bloquear la inundación. TX-6: al inundar se
        // reduce a 1 ms; si no, la espera de 50 ms limitaría la tasa ofrecida muy por debajo de
        // 1 MiB/s y el limitador `--tasa` sería irrelevante.
        let plazo_bloque = if inundar {
            Duration::from_millis(1)
        } else {
            Duration::from_millis(50)
        };
        match tokio::time::timeout(plazo_bloque, rx_bloques.recv()).await {
            Ok(Some(bloque)) => match &bloque {
                BloqueRed::Pow { cabecera, txs, .. } => {
                    bloques_vistos += 1;
                    if let Some(cb) = txs.first() {
                        pow_coinbases.push((cabecera.height, cb.clone()));
                        if pow_coinbases.len() > 64 {
                            pow_coinbases.remove(0);
                        }
                    }
                }
                BloqueRed::Post { cabecera, txs, .. } => {
                    bloques_vistos += 1;
                    if slot_corte.is_none() {
                        slot_corte = Some(cabecera.slot);
                    }
                    slot_actual = slot_actual.max(cabecera.slot);
                    if !corte_anunciado {
                        corte_anunciado = true;
                        println!(
                            "zx-txcliente: corte detectado (primer PoST slot {}); esperando {} slots",
                            cabecera.slot, cli.espera_slot
                        );
                    }
                    for t in txs {
                        let tid = txid(t, CBID_RED_DEV);
                        if Some(tid) == deposito_txid && !incluido {
                            incluido = true;
                            if inundar_deposita {
                                println!("zx-txcliente: depósito incluido en un bloque.");
                            }
                        }
                        if Some(tid) == sector_txid {
                            sector_incluido = true;
                        }
                        if Some(tid) == voto_txid {
                            voto_incluido = true;
                        }
                    }
                }
            },
            _ => {}
        }

        // El corte debe estar detectado y haber madurado `M_res_slots` para gastar la coinbase.
        // SR-1-2/FV-4b-N1-2: los modos `sector-alta` y `clave-voto` no dependen de recibir bloques
        // (publican y reintentan), así que no se les aplica la puerta de madurez.
        let maduro = slot_corte.is_some_and(|s| slot_actual >= s + cli.espera_slot);
        if !maduro && !es_sector && !es_clave_voto {
            continue;
        }

        if inundar {
            // TX-6-2: el primer envío real arranca el reloj de `--segundos`.
            let base_inundacion = *base_inundacion_opt.get_or_insert_with(|| {
                println!(
                    "zx-txcliente: inundación arrancada (primer envío, solo-tx={})",
                    cli.solo_tx
                );
                tokio::time::Instant::now()
            });
            // TX-6: base del limitador; se fija con el primer envío de esta corrida.
            let base_tasa = *inicio_tasa.get_or_insert_with(tokio::time::Instant::now);
            // 1) Abanico inicial: una v1 válida gasta una coinbase PoW madura y reparte su valor
            //    entre `salidas_fanout` salidas del mismo dueño. Si `--depositar`, la salida 0
            //    conserva **todo** el valor (financia el depósito de clave cruzada) y el resto son
            //    salidas de valor 0 para las cadenas. Se hace una sola vez.
            if !abanico_hecho {
                let mut lista: Vec<(u32, Tx)> = pow_coinbases.clone();
                lista.sort_by_key(|(h, _)| *h);
                if let Some((altura, cb)) = lista.iter().rev().nth(cli.retroceso)
                    && let Some((dueno, valor)) = clave_de_salida(cb, &claves)
                {
                    let op = OutPoint {
                        prev_txid: txid(cb, CBID_RED_DEV),
                        prev_index: 0,
                    };
                    let salida_0 = if inundar_deposita {
                        valor
                    } else {
                        Amount::CERO
                    };
                    if let Ok((tx, testigos)) =
                        transferencia_v1(op, valor, &dueno, salidas_fanout, salida_0)
                    {
                        let bytes = bytes_tx(&tx, &testigos);
                        if publicar(&manejo, &bytes).await.is_ok() {
                            let tid = txid(&tx, CBID_RED_DEV);
                            let desde = usize::from(inundar_deposita);
                            for j in desde..salidas_fanout {
                                utxos.push_back((
                                    OutPoint {
                                        prev_txid: tid,
                                        prev_index: u32::try_from(j).unwrap_or(u32::MAX),
                                    },
                                    Amount::CERO,
                                    dueno.clone(),
                                ));
                            }
                            bytes_tasa = bytes_tasa.saturating_add(bytes.len() as u64);
                            esperar_tasa(base_tasa, bytes_tasa, tasa).await;
                            enviados_validos += 1;
                            abanico_hecho = true;
                            println!(
                                "zx-txcliente: abanico publicado desde coinbase altura {} valor {} \
                                 brek -> salida0={} brek + {} salidas de valor 0",
                                altura,
                                valor.brek(),
                                salida_0.brek(),
                                salidas_fanout.saturating_sub(desde)
                            );
                            // 1-bis) Depósito de clave cruzada del granjero sin garantía, gastando
                            //     la salida 0 del abanico: así comparte con la inundación la única
                            //     coinbase viva tras el corte.
                            if inundar_deposita {
                                let op0 = OutPoint {
                                    prev_txid: tid,
                                    prev_index: 0,
                                };
                                if let Ok((txd, twd)) =
                                    deposito_clave_cruzada(op0, valor, &dueno, &destino)
                                {
                                    let bd = bytes_tx(&txd, &twd);
                                    match publicar(&manejo, &bd).await {
                                        Ok(()) => {
                                            let tidd = txid(&txd, CBID_RED_DEV);
                                            deposito_txid = Some(tidd);
                                            deposito_publicado = true;
                                            bytes_tasa = bytes_tasa.saturating_add(bd.len() as u64);
                                            esperar_tasa(base_tasa, bytes_tasa, tasa).await;
                                            enviados_validos += 1;
                                            println!(
                                                "zx-txcliente: depósito de clave cruzada publicado \
                                                 desde abanico (valor {} brek, emisor {} -> destino \
                                                 {}); txid {}",
                                                valor.brek(),
                                                dueno.indice,
                                                destino.indice,
                                                hex(tidd.as_bytes())
                                            );
                                        }
                                        Err(e) => eprintln!(
                                            "zx-txcliente: no se pudo publicar el depósito: {e}"
                                        ),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // 2) Gasto en cadena a la tasa pedida: cada tx gasta una salida de valor 0 y crea otra
            //    igual; la cola de UTXO se mantiene constante. Todas son válidas (firma con el valor
            //    real, `phi_min = 0`) y la mempool las admite; al llenar `S_par` aparecen los
            //    rechazos por tope (`par_memoria`) que pide la pregunta falsable.
            let mut hechos: u64 = 0;
            while let Some((op, valor, dueno)) = utxos.pop_front() {
                let Ok((tx, testigos)) = transferencia_v1(op, valor, &dueno, 1, Amount::CERO)
                else {
                    continue;
                };
                let bytes = bytes_tx(&tx, &testigos);
                if publicar(&manejo, &bytes).await.is_err() {
                    // No se pierde la cadena: se devuelve el UTXO a la cola y se reintenta luego.
                    utxos.push_front((op, valor, dueno));
                    break;
                }
                let tid = txid(&tx, CBID_RED_DEV);
                utxos.push_back((
                    OutPoint {
                        prev_txid: tid,
                        prev_index: 0,
                    },
                    Amount::CERO,
                    dueno,
                ));
                bytes_tasa = bytes_tasa.saturating_add(bytes.len() as u64);
                esperar_tasa(base_tasa, bytes_tasa, tasa).await;
                enviados_validos += 1;
                hechos += 1;
                if hechos >= 512 {
                    break; // deja respirar al bucle de red
                }
            }
            // TX-6-2 · progreso para poder calcular la tasa **ofrecida** real (bytes/segundos).
            if ultimo_aviso.elapsed() >= Duration::from_secs(60) {
                ultimo_aviso = tokio::time::Instant::now();
                println!(
                    "zx-txcliente: progreso: {} txs, {} bytes ofrecidos en {} s (objetivo {} B/s, \
                     abanico={})",
                    enviados_validos,
                    bytes_tasa,
                    base_inundacion.elapsed().as_secs(),
                    tasa,
                    abanico_hecho
                );
            }
            if base_inundacion.elapsed() >= Duration::from_secs(segundos) {
                println!(
                    "zx-txcliente: inundación terminada: {} txs v1 válidas (abanico={}), {} bytes \
                     ofrecidos en {} s (tasa objetivo {} B/s), bloques vistos {} reenviados 0 \
                     (solo-tx={})",
                    enviados_validos,
                    abanico_hecho,
                    bytes_tasa,
                    base_inundacion.elapsed().as_secs(),
                    tasa,
                    bloques_vistos,
                    cli.solo_tx
                );
                break;
            }
        } else if es_clave_voto {
            // FV-4b-N1-2 · modo `clave-voto`: publica el registro v6 `0x03` de la clave BLS de voto
            // del nodo, firmado por `destino` (Ed25519). La clave BLS se deriva de la semilla y el
            // índice (el **mismo** que usa el nodo en dev), y su prueba de posesión permite al
            // consenso aceptarla. Se reintenta cada 5 s hasta que el productor la incluya; es
            // idempotente (`guardar_clave_voto` reescribe la misma entrada).
            if ultimo_voto.elapsed() >= Duration::from_secs(5) {
                ultimo_voto = tokio::time::Instant::now();
                let indice_voto = match &cli.modo {
                    Modo::ClaveVoto { indice_voto } => indice_voto.unwrap_or(cli.indice_destino),
                    _ => cli.indice_destino,
                };
                match derivar_clave_voto(cli.semilla, indice_voto) {
                    Ok((clave_bls, prueba_posesion)) => {
                        let op = OperacionAlmacenamiento::ClaveVoto {
                            clave: destino.pk,
                            clave_bls,
                            prueba_posesion,
                        };
                        let tx = Tx {
                            version: 6,
                            inputs: Vec::new(),
                            outputs: Vec::new(),
                            lock_time: 0,
                            expiry_height: 0,
                            extension: ExtensionTx::PruebaAlmacenamiento { operacion: op },
                        };
                        let firma: [u8; 64] = destino
                            .sk
                            .sign(&mensaje_almacenamiento(&tx, CBID_RED_DEV))
                            .into();
                        let testigos = vec![firma.to_vec()];
                        let bytes = bytes_tx(&tx, &testigos);
                        match publicar(&manejo, &bytes).await {
                            Ok(()) => {
                                let tid = txid(&tx, CBID_RED_DEV);
                                voto_txid = Some(tid);
                                if !voto_publicado {
                                    voto_publicado = true;
                                    println!(
                                        "zx-txcliente: registro de clave BLS de voto publicado \
                                         (clave Ed {} índice BLS {}); txid {}",
                                        destino.indice,
                                        indice_voto,
                                        hex(tid.as_bytes())
                                    );
                                }
                            }
                            Err(e) => {
                                if !voto_publicado {
                                    eprintln!(
                                        "zx-txcliente: no se pudo publicar la clave de voto: {e}"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("zx-txcliente: clave BLS de voto inválida: {e}"),
                }
            }
            // No se corta al verla incluida: una reorganización puede deshacerla y el reintento la
            // vuelve a publicar. Solo se avisa una vez.
            if voto_incluido && !voto_anunciado {
                voto_anunciado = true;
                println!(
                    "zx-txcliente: registro de clave de voto visto en un bloque; se sigue \
                     republicando hasta el plazo."
                );
            }
        } else if es_sector {
            // SR-1-2 · modo `sector-alta`: reintenta cada 5 s. El mempool valida contra su vista y
            // retiene la `Tx` hasta que la fianza de la clave madura; el productor la incluye
            // entonces. No depende de recibir bloques (el cliente puede quedarse sordo al gossip).
            if ultimo_sector.elapsed() >= Duration::from_secs(5) {
                ultimo_sector = tokio::time::Instant::now();
                let (sector_index, history_size) = match &cli.modo {
                    Modo::SectorAlta { history_size, .. } => (sector_actual, *history_size),
                    _ => (0, 1 << 20),
                };
                let op = OperacionSector::Alta {
                    clave: destino.pk,
                    sector_index,
                    version: 0,
                    r2: [0u8; 32],
                    history_size,
                };
                let tx = Tx {
                    version: 5,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    lock_time: 0,
                    expiry_height: 0,
                    extension: ExtensionTx::Sector { operacion: op },
                };
                let firma: [u8; 64] = destino.sk.sign(&mensaje_sector(&tx, CBID_RED_DEV)).into();
                let testigos = vec![firma.to_vec()];
                let bytes = bytes_tx(&tx, &testigos);
                match publicar(&manejo, &bytes).await {
                    Ok(()) => {
                        let tid = txid(&tx, CBID_RED_DEV);
                        sector_txid = Some(tid);
                        if !sector_publicado {
                            sector_publicado = true;
                            println!(
                                "zx-txcliente: alta de sector publicada (clave {} índice {} ver 0 h {}); txid {}",
                                destino.indice,
                                sector_index,
                                history_size,
                                hex(tid.as_bytes())
                            );
                        }
                    }
                    Err(e) => {
                        if !sector_publicado {
                            eprintln!("zx-txcliente: no se pudo publicar el alta de sector: {e}");
                        }
                    }
                }
            }
            // No se corta al verla incluida: una reorganización puede deshacerla y hay que seguir
            // republicando hasta que el plazo cierre (el mempool la re-admite).
            if sector_incluido && !sector_anunciado {
                sector_anunciado = true;
                println!(
                    "zx-txcliente: alta de sector vista en un bloque; se sigue republicando hasta el plazo."
                );
            }
            // SR-G2b · avanza a la siguiente alta de la caja cuando la actual se ha incluido. El
            // hueco nuevo solo madura `M_sec` slots después, así que el mempool puede rechazarla
            // temporalmente; el reintento de 5 s la acaba metiendo y la cuota por clave garantiza
            // que nunca haya dos altas de la misma clave pendientes a la vez.
            if sector_incluido && sector_actual < sector_base.saturating_add(sector_n - 1) {
                println!(
                    "zx-txcliente: alta del sector {} incluida; paso al sector {} de {}.",
                    sector_actual,
                    sector_actual.saturating_add(1),
                    sector_n
                );
                sector_actual = sector_actual.saturating_add(1);
                sector_incluido = false;
                sector_publicado = false;
                sector_anunciado = false;
                sector_txid = None;
            }
        } else {
            // Modo transferir.
            if !deposito_publicado {
                let mut lista: Vec<(u32, Tx)> = pow_coinbases.clone();
                lista.sort_by_key(|(h, _)| *h);
                let Some((altura, cb)) = lista.iter().rev().nth(cli.retroceso) else {
                    continue;
                };
                let Some((dueno, valor)) = clave_de_salida(cb, &claves) else {
                    continue;
                };
                let op = OutPoint {
                    prev_txid: txid(cb, CBID_RED_DEV),
                    prev_index: 0,
                };
                let Ok((tx, testigos)) = deposito_clave_cruzada(op, valor, &dueno, &destino) else {
                    continue;
                };
                let bytes = bytes_tx(&tx, &testigos);
                match publicar(&manejo, &bytes).await {
                    Ok(()) => {
                        let tid = txid(&tx, CBID_RED_DEV);
                        deposito_txid = Some(tid);
                        deposito_publicado = true;
                        println!(
                            "zx-txcliente: depósito de clave cruzada publicado (coinbase altura {altura}, \
                             valor {} brek, emisor {} -> destino {}); txid {}",
                            valor.brek(),
                            dueno.indice,
                            destino.indice,
                            hex(tid.as_bytes())
                        );
                    }
                    Err(e) => eprintln!("zx-txcliente: no se pudo publicar el depósito: {e}"),
                }
            } else if incluido {
                println!("zx-txcliente: depósito incluido en un bloque. Fin.");
                break;
            }
        }

        if tokio::time::Instant::now().duration_since(base_programa)
            > Duration::from_secs(cli.plazo_s)
        {
            println!("zx-txcliente: plazo agotado (incluido={incluido}).");
            break;
        }
    }

    tarea.abort();
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{Cli, Espia};
    use clap::{Parser, ValueEnum};
    use zx_core::{BlockHash, Red};
    use zx_p2p::entrante::ManejadorEntrante;

    #[test]
    fn red1_el_cliente_declara_la_identidad_del_nodo_en_cada_red() {
        for red in zx_node::cli::RedCli::value_variants() {
            let valor = red.to_possible_value().expect("valor de CLI");
            let cli = Cli::try_parse_from([
                "zx-txcliente",
                "--objetivo",
                "/ip4/127.0.0.1/tcp/1",
                "--red",
                valor.get_name(),
                "sector-alta",
            ])
            .expect("la opción del nodo debe ser reconocida");
            let nodo = zx_node::cli::Cli::try_parse_from([
                "zx-node",
                "--datos",
                "datos",
                "--registro",
                "registro",
                "--red",
                valor.get_name(),
            ])
            .expect("CLI del nodo");
            assert_eq!(cli.red, nodo.red);
            let espia = Espia::nuevo(cli.red, None);
            if Red::from(nodo.red) == Red::Dev {
                let estado = espia.expect("cliente de red dev").estado();
                assert_eq!(estado.red, Red::from(nodo.red));
                assert_eq!(
                    estado.hash_genesis,
                    zx_node::perfil::identidad_red(
                        &nodo.red.perfil_red().expect("perfil del nodo")
                    )
                );
            } else {
                assert_eq!(
                    espia.err().expect("red no operativa rechazada"),
                    zx_node::error::ErrorNodo::RedNoEsDev {
                        encontrada: Red::from(nodo.red),
                    }
                    .to_string()
                );
            }
        }
    }

    #[test]
    fn red1_sin_opcion_declara_la_de_hoy() {
        let cli = Cli::try_parse_from([
            "zx-txcliente",
            "--objetivo",
            "/ip4/127.0.0.1/tcp/1",
            "sector-alta",
        ])
        .expect("CLI sin opción");
        assert_eq!(cli.red, zx_node::cli::RedCli::Dev);
        let estado = Espia::nuevo(cli.red, None)
            .expect("red por defecto")
            .estado();
        let anterior = zx_p2p::mensaje::Estado {
            hash_genesis: BlockHash::from_digest(zx_core::Digest::from_bytes(
                zx_consensus::genesis::HASH_GENESIS_DEV,
            )),
            red: Red::Dev,
            fase: zx_p2p::mensaje::Fase::Pow,
            punta_pow: zx_p2p::mensaje::PuntaPow {
                hash: BlockHash::from_digest(zx_core::Digest::from_bytes([0xEE; 32])),
                altura: 0,
                trabajo_acumulado: [0; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [0; 32],
            longitud_registro: 0,
        };
        assert_eq!(estado, anterior, "todo el saludo anterior se conserva");
    }
}
