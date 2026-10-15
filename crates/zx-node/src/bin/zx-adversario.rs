//! `zx-adversario`: herramienta adversarial separada (`ORDEN-W06d2` decisión 6).
//!
//! Un binario aparte —**nunca** un modo de `zx-node`— que habla el protocolo real de `zx-p2p`
//! (mismo transporte, mismo behaviour, misma red dev) para enviarle a un nodo objetivo las
//! entradas inválidas de `P-ZRX/P-MEDICION/ESCENARIOS-0.0.1.md` §3 E-7 y E-8, y observar si las
//! rechaza sin cambiar de estado.
//!
//! # Qué cubre esta versión, y qué no (ver `PROGRESO.md` del encargo)
//!
//! `BloqueRed::Post` ya lleva `JustificacionPot` (`ORDEN-W06d3` decisión 1): el objetivo puede
//! verificar de verdad la cabecera conjunta de un PoST ajeno. Los escenarios de E-7 con PoAS/PoT/
//! sello **PoST** malos declaran como único padre el **terminal real** del objetivo (pedido con
//! `Peticion::Estado`, igual que ya hacían los de PoW): así el bloque llega a la verificación de
//! contenido en vez de quedarse en «huérfano, padre desconocido». Si el objetivo todavía no tiene
//! terminal (sigue en fase PoW), esos escenarios se omiten: enviarlos sin un padre real solo
//! probaría el camino de huérfanos, ya cubierto por la ráfaga de E-7. El escenario **E-8**
//! (equivocación) sigue limitado: esta herramienta no tiene la clave privada de ningún productor
//! real, así que no puede construir dos bloques **válidos** del mismo slot y observar cómo los
//! colorea GHOSTDAG (eso se demuestra en un test dedicado con claves propias, no por red); lo que
//! sí demuestra es que dos bloques distintos con contenido inválido para el mismo slot se rechazan
//! cada uno por su motivo, sin que el segundo cambie el estado. Los escenarios de la familia
//! **PoW** se validan de extremo a extremo: esta herramienta primero pregunta el estado real del
//! objetivo (`Peticion::Estado`) y construye los bloques adversariales **extendiendo su punta
//! real**, para que lleguen al validador de verdad en vez de quedarse en «huérfano, no juzgable».
//!
//! # Cómo se usa
//!
//! ```text
//! zx-adversario --objetivo /ip4/127.0.0.1/tcp/PUERTO
//! ```
//!
//! Corre cada escenario una vez, en orden, con una pausa entre cada uno para poder leer el
//! registro estructurado del objetivo. Imprime a stdout qué mandó y qué observó (conexión viva o
//! cortada) en cada paso; el veredicto de fondo (aceptado/ignorado/rechazado, y por qué) se lee en
//! el registro del nodo objetivo, no aquí — esta herramienta no tiene acceso a su estado interno,
//! solo al protocolo de red, que es exactamente el punto.

use std::collections::BTreeSet;
use std::time::Duration;

use clap::{Parser, Subcommand};
use libp2p::core::transport::Transport as _;
use libp2p::{Multiaddr, PeerId, Swarm, identity, noise, yamux};
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest, MerkleRoot, TxId};
use zx_core::firma::ClavePublica;
use zx_core::preimage::block::{BlockHeader, merkle_root};
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_core::red::Red;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_core::wire_dag::{JustificacionPot, PotCheckpoints};
use zx_node::cli::RedCli;
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::mensaje::{BloqueRed, Estado, FamiliaBloque, Fase, Peticion, Respuesta};
use zx_p2p::servicio::{EventoRed, arrancar};

/// CLI de la herramienta adversarial.
#[derive(Parser, Debug)]
#[command(
    name = "zx-adversario",
    about = "Herramienta adversarial de ORDEN-W06d2 (E-7/E-8) y ORDEN-SL4b2 (doble-firma)"
)]
struct Cli {
    /// Dirección del nodo objetivo.
    #[arg(long, value_name = "MULTIADDR")]
    objetivo: Multiaddr,

    /// Red configurada, igual que en `zx-node`.
    #[arg(long, value_enum, default_value_t = RedCli::Dev)]
    red: RedCli,

    /// Pausa tras difundir cada vector, en milisegundos, para dar tiempo a que el objetivo valide
    /// y (si procede) corte la conexión, y para poder leer su registro. `ORDEN-W06d10`: con la
    /// penalización activa, el corte puede tardar lo que tarde la verificación (hasta decenas de ms)
    /// más el turno del hilo de consenso; 1 s deja margen de sobra.
    #[arg(long, default_value_t = 1000)]
    pausa_ms: u64,

    /// Sin subcomando: la ráfaga E-7/E-8 de siempre (`ORDEN-W06d2`). Con `doble-firma`: `ORDEN-SL4b2`
    /// decisión 5.
    #[command(subcommand)]
    modo: Option<Modo>,
}

/// `ORDEN-SL4b2` decisión 5: subcomandos nuevos del binario existente (nunca un modo del nodo).
#[derive(Subcommand, Debug)]
enum Modo {
    /// Se conecta al objetivo, espera un bloque PoST producido por la clave dev
    /// `--clave-indice` (derivada con `zx_node::claves::ClaveDev`, la misma función que usa el
    /// nodo), construye una segunda cabecera **idéntica salvo `timestamp + 1`**, la sella con esa
    /// misma clave, comprueba localmente que la identidad RAT-1 coincide y el `pre_hash` no, y la
    /// publica. Con `--repetir`, publica además una tercera (`timestamp + 2`) del mismo billete,
    /// para probar la deduplicación (EV-12).
    DobleFirma {
        /// Índice de la clave dev cuyo bloque se espera y se duplica.
        #[arg(long)]
        clave_indice: u32,
        /// Semilla de derivación (debe coincidir con la del objetivo, `--semilla` de `zx-node`).
        #[arg(long, default_value_t = 1)]
        semilla: u64,
        /// Plazo máximo de espera del primer bloque de la clave, en segundos.
        #[arg(long, default_value_t = 120)]
        plazo_espera_s: u64,
        /// Publica también una tercera cabecera (`timestamp + 2`) del mismo billete (EV-12).
        #[arg(long)]
        repetir: bool,
    },
}

/// Manejador espía: no se necesita servir nada de verdad (la herramienta no es un nodo, no tiene
/// cadena que ofrecer); cuenta lo que le llega para el resumen final.
///
/// `ORDEN-SL4b2` decisión 5: además reenvía cada `BloqueRed::Post` difundido por el objetivo a
/// `posts` (si hay un receptor puesto), para que `doble-firma` pueda esperar el primero de una
/// clave concreta sin bloquear el bucle de red (`bloque_difundido` corre en ese bucle).
struct Espia {
    hash_genesis: BlockHash,
    red: Red,
    respuestas: std::sync::atomic::AtomicUsize,
    posts: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<BloqueRed>>>,
}

impl Espia {
    fn nuevo(red_cli: RedCli) -> Result<Self, String> {
        let red = Red::from(red_cli);
        if red != Red::Dev {
            return Err(zx_node::error::ErrorNodo::RedNoEsDev { encontrada: red }.to_string());
        }
        let perfil = red_cli.perfil_red().map_err(|e| e.to_string())?;
        Ok(Self {
            hash_genesis: zx_node::perfil::identidad_red(&perfil),
            red,
            respuestas: std::sync::atomic::AtomicUsize::new(0),
            posts: std::sync::Mutex::new(None),
        })
    }
}

impl ManejadorEntrante for Espia {
    fn estado(&self) -> Estado {
        // `ORDEN-W06d6` decisión 3 (V7), hallazgo en vivo: la herramienta declaraba un
        // `hash_genesis` vacío (`[0xEE; 32]`) a propósito ("si el objetivo comprueba esto y
        // desconecta, no rompe nada del lado de la herramienta"). Eso era cierto con un objetivo
        // recién arrancado, pero deja de serlo con un objetivo real en marcha (500+ bloques): el
        // saludo recíproco del propio objetivo (`sync.rs::atender_respuesta`, `Respuesta::Estado`)
        // ve el génesis ajeno y llama a `desconectar(ViolacionDeConsenso)` **de inmediato** — y como
        // la respuesta de esta herramienta (trivial) siempre llega antes que la del objetivo
        // (construir la suya es más caro cuantos más bloques tenga), el objetivo gana la carrera
        // sistemáticamente y corta la conexión antes de que la herramienta reciba nada, dejando
        // "el objetivo no respondió el saludo" — la ráfaga de escenarios nunca llegaba a mandarse.
        // Reproducido en vivo contra un objetivo con 500+ bloques PoST (`PROGRESO.md`). El génesis
        // del perfil se declara con la misma función que el nodo; no debilita ningún escenario
        // adversarial (la identidad no es parte de ningún ataque de E-7/E-8).
        Estado {
            hash_genesis: self.hash_genesis,
            red: self.red,
            fase: Fase::Pow,
            punta_pow: zx_p2p::mensaje::PuntaPow {
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
        if matches!(bloque, BloqueRed::Post { .. })
            && let Ok(guard) = self.posts.lock()
            && let Some(tx) = guard.as_ref()
        {
            let _ = tx.send(bloque.clone());
        }
        Veredicto::Ignorar
    }

    fn tx_difundida(&self, _peer: libp2p::PeerId, _tx: &[u8]) -> Veredicto {
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
            value: Amount::nuevo(1_000).unwrap_or(Amount::CERO),
            lock: Lock::PubKey {
                pubkey: ClavePublica::desde_bytes([n; 32]),
            },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

/// E-7 «PoW con nonce malo»: extiende la punta real del objetivo con una cabecera cuyo `nonce` no
/// cumple el PoW real (probabilidad astronómicamente en contra de que cumpla por azar con la
/// dificultad dev). El motor de transición la rechazaría igual por su coinbase (no está firmada por
/// nadie que el objetivo conozca como productor válido de esa altura salvo que coincida una clave
/// real), pero la comprobación de PoW real es la primera de la tubería (`validar_cabecera_pow`) y
/// MUST fallar antes de llegar a mirar la coinbase.
fn escenario_pow_nonce_malo(estado_objetivo: &Estado) -> BloqueRed {
    let altura = estado_objetivo.punta_pow.altura + 1;
    let clave = ClavePublica::desde_bytes([0x41; 32]);
    let coinbase = zx_node::pow::construir_coinbase_pow(clave, altura);
    let txid_coinbase = zx_core::txid(&coinbase, zx_core::CBID_RED_DEV);
    BloqueRed::Pow {
        cabecera: BlockHeader {
            consensus_branch_id: zx_core::CBID_RED_DEV,
            prev_hash: estado_objetivo.punta_pow.hash,
            merkle_root: merkle_root(&[txid_coinbase]),
            timestamp: 1_800_000_000,
            bits: 0x1c07_fff8,
            nonce: 0, // no minado: no cumple `hash_pow < target` con la dificultad dev real.
            height: altura,
        },
        txs: vec![coinbase],
        testigos: vec![Vec::new()],
    }
}

/// E-7 «coinbase mayor que el subsidio»: mismo bloque que el anterior pero con PoW real (minado de
/// verdad, presupuesto acotado) y una coinbase que paga de más. Si la dificultad dev real tarda más
/// que el presupuesto de esta herramienta en encontrar un nonce válido, se declara `None` y el
/// escenario se omite (no se falsea un PoW).
fn escenario_coinbase_excesiva(estado_objetivo: &Estado) -> Option<BloqueRed> {
    let altura = estado_objetivo.punta_pow.altura + 1;
    let clave = ClavePublica::desde_bytes([0x42; 32]);
    let mut coinbase = zx_node::pow::construir_coinbase_pow(clave, altura);
    // El doble del subsidio dev declarado: demostrablemente por encima de lo que F-16 permite.
    let salida = coinbase.outputs.first_mut()?;
    let doble = salida.value.brek().checked_mul(2)?;
    salida.value = Amount::nuevo(doble).ok()?;
    let txid_coinbase = zx_core::txid(&coinbase, zx_core::CBID_RED_DEV);
    let objetivo_pow =
        zx_core::decodificar_con(0x1c07_fff8, &zx_consensus::PARAMETROS_POW_DEV.limites).ok()?;
    let cabecera_base = BlockHeader {
        consensus_branch_id: zx_core::CBID_RED_DEV,
        prev_hash: estado_objetivo.punta_pow.hash,
        merkle_root: merkle_root(&[txid_coinbase]),
        timestamp: 1_800_000_000,
        bits: 0x1c07_fff8,
        nonce: 0,
        height: altura,
    };
    // Presupuesto acotado y declarado, reusando el minero real (`zx_consensus::minar`): hasta
    // 2_000_000 intentos. Con la dificultad inicial dev real esto puede no bastar (se ha medido en
    // otras órdenes ~4-5 s/bloque en `debug`); si no se encuentra, se omite el escenario en vez de
    // mandar un PoW falso.
    let cancelar = core::sync::atomic::AtomicBool::new(false);
    let minada = zx_consensus::minar(
        &cabecera_base,
        objetivo_pow,
        &zx_consensus::Sha3Dev,
        2_000_000,
        &cancelar,
    )?;
    Some(BloqueRed::Pow {
        cabecera: minada,
        txs: vec![coinbase],
        testigos: vec![Vec::new()],
    })
}

/// E-7 «ráfaga de huérfanos»: muchos bloques PoW con padres inexistentes (aleatorios), para
/// comprobar que el objetivo los deposita acotado y no se cae ni penaliza al remitente (son
/// indistinguibles de "llegó antes que su padre").
fn escenario_rafaga_huerfanos(n: usize) -> Vec<BloqueRed> {
    (0..n)
        .map(|i| {
            // Un hash "aleatorio" distinto por índice basta: no necesita ser impredecible, solo no
            // coincidir con ningún padre real. `sha3_256_publico` de los bytes de `i` (`u64`
            // big-endian) da 32 bytes bien repartidos sin aritmética manual por byte.
            let semilla = u64::try_from(i).unwrap_or(0).to_be_bytes();
            let padre_inexistente = BlockHash::from_digest(zx_core::sha3_256_publico(&semilla));
            BloqueRed::Pow {
                cabecera: BlockHeader {
                    consensus_branch_id: zx_core::CBID_RED_DEV,
                    prev_hash: padre_inexistente,
                    merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x33; 32])),
                    timestamp: 1_800_000_000,
                    bits: 0x1c07_fff8,
                    nonce: u64::try_from(i).unwrap_or(0),
                    height: 1,
                },
                txs: vec![tx_llave(u8::try_from(i % 256).unwrap_or(0))],
                testigos: vec![vec![vec![0xAA; 64]]],
            }
        })
        .collect()
}

/// Justificación PoT que no corresponde a ningún flujo real: basta un portador de relleno para que
/// `verificar_cabecera_conjunta` la lea y la rechace en la comprobación de PoT, en vez de fallar
/// antes por tener la lista vacía (que también sería un rechazo, pero uno de forma, no de PoT).
fn justificacion_mala(variante: u8) -> JustificacionPot {
    let portador = PotCheckpoints::desde_outputs([[0xEE ^ variante; 16]; 8]);
    JustificacionPot::nueva(vec![portador]).unwrap_or_else(|_| unreachable!("1 <= MAX_BUNDLES_POT"))
}

/// E-7 «PoST con PoAS/PoT/sello malos» y E-8 «equivocación» (ver el docstring del módulo: E-8
/// sigue limitado por no tener claves reales). `variante` distingue el hash de dos bloques del
/// mismo `slot` sin cambiar nada más. Declara como único padre el **terminal real** del objetivo:
/// sin eso, el objetivo lo trataría como huérfano (`Ignorar`) en vez de verificar su contenido.
/// `None` si el objetivo todavía no tiene terminal (nada útil que demostrar por esta vía todavía).
fn escenario_post_malo(slot: u8, variante: u8, estado_objetivo: &Estado) -> Option<BloqueRed> {
    let terminal = estado_objetivo.terminal?;
    Some(BloqueRed::Post {
        cabecera: DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: zx_core::CBID_RED_DEV,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x99 ^ variante; 32])),
            timestamp: 1_800_000_000,
            height: 0,
            slot: u64::from(slot),
            pot_output: [0xFF; 16], // PoT que no corresponde a ningún flujo real.
            rango_solucion: 1,
            sol: SolucionPoas::default(), // PoAS vacía/inválida.
            body_commitment: zx_core::digest::BodyCommitment::from_digest(Digest::from_bytes(
                [0x11 ^ variante; 32],
            )),
            padres: PadresDag::nuevo(terminal, &[])
                .unwrap_or_else(|_| unreachable!("un solo padre siempre construye")),
            sello: [0xFF; 64], // sello arbitrario, no una firma real.
        },
        justificacion: justificacion_mala(variante),
        txs: vec![tx_llave(slot)],
        testigos: vec![vec![vec![0xBB; 64]]],
    })
}

#[tokio::main]
async fn main() {
    // `ORDEN-W06d6` decisión 3 (V7): sin esto, ningún `tracing::debug!`/`tracing::warn!` de esta
    // herramienta ni de `zx-p2p` (el motivo real de un rechazo local de gossipsub, penalizaciones
    // de par, etc.) se imprime en ningún sitio — la mitad de por qué V7 quedó "parcial" en
    // `REVISION-W06d5.md`: el motivo existía en el código pero nada lo mostraba. `DEBUG` fijo (no
    // `RUST_LOG`): esta es una herramienta de diagnóstico de un solo uso, no un servicio con
    // configuración propia.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .init();

    let cli = Cli::parse();
    let espia = match Espia::nuevo(cli.red) {
        Ok(e) => std::sync::Arc::new(e),
        Err(e) => {
            eprintln!("zx-adversario: {e}");
            std::process::exit(2);
        }
    };
    let swarm = match swarm_tcp() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zx-adversario: no se pudo construir la red: {e}");
            std::process::exit(1);
        }
    };
    // `ORDEN-SL4b2` decisión 5: el canal se registra **antes** de conectar, para no perder ningún
    // `BloqueRed::Post` que llegue entre la conexión y que `doble-firma` empiece a esperar
    // (inocuo para la ráfaga E-7/E-8: nadie lee `rx_posts` en ese camino).
    let (tx_posts, rx_posts) = tokio::sync::mpsc::unbounded_channel::<BloqueRed>();
    #[expect(
        clippy::unwrap_used,
        reason = "recién creado, sin panic previo posible: un Mutex envenenado aquí sería un bug de este mismo binario"
    )]
    {
        *espia.posts.lock().unwrap() = Some(tx_posts);
    }
    let piezas = arrancar(swarm, std::sync::Arc::clone(&espia));
    let manejo = piezas.manejo;
    let mut eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());

    println!("zx-adversario: marcando {} ...", cli.objetivo);
    if let Err(e) = manejo.marcar(cli.objetivo.clone()).await {
        eprintln!("zx-adversario: no se pudo marcar: {e}");
        std::process::exit(1);
    }

    let Some(peer) = esperar_conexion(&mut eventos).await else {
        eprintln!("zx-adversario: el objetivo no conectó en el plazo esperado");
        std::process::exit(1);
    };
    println!("zx-adversario: conectado a {peer}");

    // `ORDEN-W06d5` decisión 5 (`REVISION-W06d4.md`, V7): la conexión TCP no es la malla de
    // gossipsub; publicar antes de que el objetivo confirme sus dos suscripciones (bloques
    // pow/post) falla localmente con `NoPeersSubscribedToTopic`. Se pide el saludo y se esperan las
    // suscripciones **en el mismo bucle** (`pedir_estado_y_suscripciones`): hacerlo en dos bucles
    // consecutivos sobre el mismo canal perdía los eventos de suscripción que llegaran mientras se
    // esperaba el saludo (ver el docstring de la función — encontrado en vivo, no hipotético).
    let (estado_objetivo, pendientes) =
        pedir_estado_y_suscripciones(&manejo, &mut eventos, peer, Duration::from_secs(10)).await;
    let Some(estado_objetivo) = estado_objetivo else {
        eprintln!("zx-adversario: el objetivo no respondió el saludo");
        std::process::exit(1);
    };
    println!(
        "zx-adversario: objetivo declara altura PoW {} fase {:?}",
        estado_objetivo.punta_pow.altura, estado_objetivo.fase
    );

    let pausa = Duration::from_millis(cli.pausa_ms);

    if pendientes.is_empty() {
        println!("zx-adversario: el objetivo confirmó su suscripción a los dos temas de gossipsub");
    } else {
        println!(
            "zx-adversario: el objetivo no confirmó suscripción a {pendientes:?} en el plazo \
             esperado; prosigo igualmente (la ráfaga puede perder mensajes por esto)"
        );
    }

    // `ORDEN-SL4b2` decisión 5: con el subcomando `doble-firma`, esta herramienta hace **solo**
    // eso (no encadena con la ráfaga E-7/E-8 de abajo).
    if let Some(Modo::DobleFirma {
        clave_indice,
        semilla,
        plazo_espera_s,
        repetir,
    }) = cli.modo
    {
        ejecutar_doble_firma(
            &manejo,
            rx_posts,
            clave_indice,
            semilla,
            Duration::from_secs(plazo_espera_s),
            repetir,
        )
        .await;
        tarea.abort();
        return;
    }

    // La conexión persistente ya cumplió su única función aquí: leer el saludo del objetivo (fase y
    // terminal) con el que se construyen los bloques. Se cierra **antes** de los vectores: si
    // siguiera viva, ocuparía el tercer cupo de `MAX_POR_PREFIJO` en `127.0.0.0/24` (B y C ya
    // ocupan dos) y las identidades nuevas no podrían conectar. El cierre se deja asentar un
    // instante para que el objetivo descuente la conexión.
    tarea.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // `ORDEN-W06d10` decisión 4: con la penalización activa, el primer bloque inválido de un
    // vector ya cuesta la conexión (el objetivo desconecta y veta al propagador). Para que **todos**
    // los vectores lleguen a juzgarse, cada uno se envía desde una **identidad nueva** (`PeerId`
    // nuevo y conexión nueva); el `PeerId` de cada vector queda impreso en la salida.
    let mut vectores: Vec<(String, Vec<BloqueRed>)> = Vec::new();
    vectores.push((
        "E-7 ráfaga de huérfanos (256 padres inexistentes)".to_string(),
        escenario_rafaga_huerfanos(256),
    ));

    if let Some(b) = escenario_post_malo(1, 0, &estado_objetivo) {
        vectores.push((
            "E-7 PoST con PoAS/PoT/sello malos (padre = terminal real del objetivo)".to_string(),
            vec![b],
        ));
    } else {
        println!(
            "zx-adversario: E-7 PoST malo OMITIDO (el objetivo todavía no fijó terminal, sigue en \
             fase PoW)"
        );
    }

    // E-8 «equivocación»: dos bloques distintos del mismo slot. Cada uno desde su propia identidad
    // (con una sola conexión, el primero —ya rechazado— se llevaría por delante al segundo).
    match (
        escenario_post_malo(2, 1, &estado_objetivo),
        escenario_post_malo(2, 2, &estado_objetivo),
    ) {
        (Some(b1), Some(b2)) => {
            vectores.push((
                "E-8 equivocación: bloque del mismo slot (variante 1)".to_string(),
                vec![b1],
            ));
            vectores.push((
                "E-8 equivocación: bloque del mismo slot (variante 2)".to_string(),
                vec![b2],
            ));
        }
        _ => println!(
            "zx-adversario: E-8 OMITIDO (el objetivo todavía no fijó terminal, sigue en fase PoW)"
        ),
    }

    vectores.push((
        "E-7 PoW nonce malo".to_string(),
        vec![escenario_pow_nonce_malo(&estado_objetivo)],
    ));

    if let Some(b) = escenario_coinbase_excesiva(&estado_objetivo) {
        vectores.push(("E-7 coinbase mayor que el subsidio".to_string(), vec![b]));
    } else {
        println!(
            "zx-adversario: E-7 coinbase excesiva OMITIDO (no se encontró nonce PoW real en el \
             presupuesto de esta herramienta; no se manda un PoW falso)"
        );
    }

    for (nombre, bloques) in vectores {
        enviar_vector_con_identidad_nueva(&cli.objetivo, cli.red, &nombre, bloques, pausa).await;
    }

    println!(
        "zx-adversario: fin. Respuestas de sincronización recibidas: {}. \
         El veredicto de fondo de cada envío se lee en el registro del objetivo.",
        espia.respuestas.load(std::sync::atomic::Ordering::Relaxed)
    );
    tarea.abort();
}

async fn esperar_conexion(eventos: &mut tokio::sync::mpsc::Receiver<EventoRed>) -> Option<PeerId> {
    let plazo = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let resto = plazo.saturating_duration_since(tokio::time::Instant::now());
        if resto.is_zero() {
            return None;
        }
        match tokio::time::timeout(resto, eventos.recv()).await {
            Ok(Some(EventoRed::PeerConectado(p))) => return Some(p),
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

/// Pide el saludo **y**, en el mismo bucle de consumo del canal de eventos, acumula las
/// suscripciones de gossipsub del objetivo que lleguen mientras tanto.
///
/// `ORDEN-W06d5` decisión 5, corrección tras el primer intento de V7 con esta misma orden: separar
/// esto en dos funciones consecutivas —cada una con su propio bucle sobre el **mismo** canal— hacía
/// que la que corría primero (`pedir_estado`) descartara en silencio (`Ok(Some(_)) => {}`) los
/// eventos `Suscripcion` que llegaran mientras esperaba el saludo, exactamente los que la segunda
/// (`esperar_suscripcion`) necesitaba después: con las dos suscripciones anunciándose casi siempre
/// junto con la respuesta al saludo (ambas llegan justo tras la conexión), la carrera se perdía casi
/// siempre y el plazo de la segunda función expiraba sin ver nada — reproducido en vivo, no una
/// hipótesis: el registro del intento anterior mostraba exactamente `"el objetivo no confirmó
/// suscripción"` seguido de `NoPeersSubscribedToTopic` en la ráfaga.
async fn pedir_estado_y_suscripciones(
    manejo: &zx_p2p::servicio::ManejoRed,
    eventos: &mut tokio::sync::mpsc::Receiver<EventoRed>,
    peer: PeerId,
    plazo_suscripcion: Duration,
) -> (Option<Estado>, BTreeSet<&'static str>) {
    manejo.pedir(peer, Peticion::Estado).await.ok();
    let mut pendientes: BTreeSet<&'static str> = [
        ParametrosRed::dag_dev().topic_bloques_pow(),
        ParametrosRed::dag_dev().topic_bloques_post(),
    ]
    .into_iter()
    .collect();
    let mut estado = None;
    // El plazo total es el mayor de los dos: seguimos escuchando suscripciones después de tener ya
    // el saludo, hasta `plazo_suscripcion`, pero no más allá de 10s si el saludo mismo no llega.
    let fin_saludo = tokio::time::Instant::now() + Duration::from_secs(10);
    let fin_suscripcion = tokio::time::Instant::now() + plazo_suscripcion;
    loop {
        if estado.is_some() && pendientes.is_empty() {
            break;
        }
        let limite = if estado.is_some() {
            fin_suscripcion
        } else {
            fin_saludo.min(fin_suscripcion)
        };
        let resto = limite.saturating_duration_since(tokio::time::Instant::now());
        if resto.is_zero() {
            break;
        }
        match tokio::time::timeout(resto, eventos.recv()).await {
            Ok(Some(EventoRed::Respuesta { respuesta, .. })) => {
                if let Respuesta::Estado(e) = *respuesta {
                    estado = Some(e);
                }
            }
            Ok(Some(EventoRed::Suscripcion {
                peer: p,
                topico,
                suscrito: true,
            })) if p == peer => {
                pendientes.retain(|t| topico != *t);
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    (estado, pendientes)
}

/// Envía **un** vector adversarial desde una **identidad nueva** (`ORDEN-W06d10` decisión 4).
///
/// Construye un `Swarm` (y por tanto un `PeerId` nuevo), conecta, espera las suscripciones de
/// gossipsub del objetivo, difunde los bloques y observa si el objetivo corta la conexión. Imprime
/// el `PeerId` usado en cada vector para dejar constancia en la salida de la herramienta.
async fn enviar_vector_con_identidad_nueva(
    objetivo: &Multiaddr,
    red: RedCli,
    nombre: &str,
    bloques: Vec<BloqueRed>,
    pausa: Duration,
) {
    let swarm = match swarm_tcp() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zx-adversario: vector «{nombre}»: no se pudo construir la red: {e}");
            return;
        }
    };
    let propio = *swarm.local_peer_id();
    let espia = match Espia::nuevo(red) {
        Ok(e) => std::sync::Arc::new(e),
        Err(e) => {
            eprintln!("zx-adversario: vector «{nombre}»: {e}");
            return;
        }
    };
    let piezas = arrancar(swarm, espia);
    let manejo = piezas.manejo;
    let mut eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());

    println!(
        "--- {nombre} ({} mensaje(s)) desde identidad NUEVA (PeerId {propio}) ---",
        bloques.len()
    );
    if let Err(e) = manejo.marcar(objetivo.clone()).await {
        eprintln!("zx-adversario: vector «{nombre}»: no se pudo marcar: {e}");
        tarea.abort();
        return;
    }
    let Some(remoto) = esperar_conexion(&mut eventos).await else {
        eprintln!("zx-adversario: vector «{nombre}»: el objetivo no conectó en el plazo esperado");
        tarea.abort();
        return;
    };

    // Publicar exige esperar las suscripciones de gossipsub del objetivo (si no, `publish` falla
    // localmente con `NoPeersSubscribedToTopic`). El saludo que devuelve aquí se ignora.
    let (_estado, pendientes) =
        pedir_estado_y_suscripciones(&manejo, &mut eventos, remoto, Duration::from_secs(10)).await;
    if !pendientes.is_empty() {
        println!("  (el objetivo no confirmó suscripción a {pendientes:?}; se difunde igualmente)");
    }

    for b in &bloques {
        let familia = match b.familia() {
            FamiliaBloque::Pow => "pow",
            FamiliaBloque::Post => "post",
        };
        match manejo.difundir_bloque(b).await {
            Ok(()) => println!("  difundido ({familia}): aceptado localmente por gossipsub"),
            Err(e) => println!("  difundido ({familia}): RECHAZADO localmente: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Ventana corta para ver si el objetivo nos corta la conexión (penalización).
    let vivo = tokio::time::timeout(pausa, esperar_desconexion(&mut eventos)).await;
    match vivo {
        Ok(Some(_)) => println!("  el objetivo CORTÓ la conexión tras este vector"),
        _ => println!("  la conexión sigue viva tras este vector"),
    }
    tarea.abort();
    // Deja que el objetivo procese el cierre antes de la siguiente identidad: `MAX_POR_PREFIJO`
    // cuenta conexiones establecidas del mismo /24 (B y C ya ocupan dos), y el vector anterior aún
    // podría contarse como la tercera.
    tokio::time::sleep(Duration::from_millis(1500)).await;
}

async fn esperar_desconexion(eventos: &mut tokio::sync::mpsc::Receiver<EventoRed>) -> Option<()> {
    loop {
        match eventos.recv().await {
            Some(EventoRed::PeerDesconectado(_)) => return Some(()),
            Some(_) => {}
            None => return None,
        }
    }
}

/// `ORDEN-SL4b2` decisión 5: `zx-adversario doble-firma`.
///
/// Espera el primer `BloqueRed::Post` de `clave_indice` (derivada con la misma función que
/// `zx_node::claves::ClaveDev`), construye una segunda cabecera idéntica salvo `timestamp + 1`, la
/// sella con la misma clave, comprueba localmente RAT-1 y publica. Con `repetir`, publica también
/// una tercera (`timestamp + 2`) del mismo billete.
async fn ejecutar_doble_firma(
    manejo: &zx_p2p::servicio::ManejoRed,
    mut posts: tokio::sync::mpsc::UnboundedReceiver<BloqueRed>,
    clave_indice: u32,
    semilla: u64,
    plazo_espera: Duration,
    repetir: bool,
) {
    let clave = zx_node::claves::ClaveDev::derivar(semilla, clave_indice);
    println!(
        "zx-adversario doble-firma: esperando un bloque PoST de la clave {clave_indice} \
         (semilla {semilla}, clave pública {:?}), plazo {plazo_espera:?} ...",
        clave.pk
    );

    let encontrado = tokio::time::timeout(plazo_espera, async {
        loop {
            match posts.recv().await {
                Some(BloqueRed::Post {
                    cabecera,
                    justificacion,
                    txs,
                    testigos,
                }) if cabecera.sol.public_key == clave.pk => {
                    return Some((cabecera, justificacion, txs, testigos));
                }
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await;

    let Ok(Some((original, justificacion, txs, testigos))) = encontrado else {
        eprintln!(
            "zx-adversario doble-firma: no llegó ningún bloque PoST de la clave {clave_indice} \
             en el plazo; nada que duplicar"
        );
        std::process::exit(1);
    };
    println!(
        "zx-adversario doble-firma: bloque original recibido — slot {} hash {}",
        original.slot,
        original.block_hash()
    );

    let segunda = resellar_con_otro_timestamp(&original, &clave, 1);
    verificar_misma_identidad_otro_pre_hash(&original, &segunda);
    println!(
        "zx-adversario doble-firma: segunda cabecera sellada — slot {} hash {} (pre_hash \
         distinto del original, identidad RAT-1 igual, comprobado localmente)",
        segunda.slot,
        segunda.block_hash()
    );
    let bloque_2 = BloqueRed::Post {
        cabecera: segunda,
        justificacion: justificacion.clone(),
        txs: txs.clone(),
        testigos: testigos.clone(),
    };
    match manejo.difundir_bloque(&bloque_2).await {
        Ok(()) => println!("zx-adversario doble-firma: segunda cabecera publicada"),
        Err(e) => eprintln!("zx-adversario doble-firma: fallo al publicar la segunda: {e}"),
    }

    if repetir {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tercera = resellar_con_otro_timestamp(&original, &clave, 2);
        verificar_misma_identidad_otro_pre_hash(&original, &tercera);
        println!(
            "zx-adversario doble-firma: tercera cabecera sellada — slot {} hash {} (--repetir, \
             prueba de deduplicación EV-12)",
            tercera.slot,
            tercera.block_hash()
        );
        let bloque_3 = BloqueRed::Post {
            cabecera: tercera,
            justificacion,
            txs,
            testigos,
        };
        match manejo.difundir_bloque(&bloque_3).await {
            Ok(()) => println!("zx-adversario doble-firma: tercera cabecera publicada"),
            Err(e) => eprintln!("zx-adversario doble-firma: fallo al publicar la tercera: {e}"),
        }
    }

    println!(
        "zx-adversario doble-firma: fin. El veredicto (evidencia_detectada/evidencia_incluida/\
         confiscación) se lee en el registro estructurado de los nodos objetivo, no aquí."
    );
}

/// Cabecera idéntica a `original` salvo `timestamp + delta` (cambia el `pre_hash`, no la identidad
/// RAT-1), sellada de nuevo con `clave` (decisión 5: «idéntica salvo timestamp + 1»).
fn resellar_con_otro_timestamp(
    original: &DagBlockHeader,
    clave: &zx_node::claves::ClaveDev,
    delta: u64,
) -> DagBlockHeader {
    let mut nueva = *original;
    nueva.timestamp = nueva.timestamp.wrapping_add(delta);
    nueva.sello = [0u8; 64];
    let pre_hash = nueva.pre_hash();
    nueva.sello = clave.sk.sign(pre_hash.as_bytes()).into();
    nueva
}

/// Decisión 5: «verifica localmente que la identidad RAT-1 coincide y el `pre_hash` no». Un
/// `panic!` aquí sería un bug de esta misma herramienta (nunca de un objetivo remoto): la
/// construcción de arriba solo cambia `timestamp` y vuelve a firmar, así que ambas condiciones
/// deben cumplirse siempre.
fn verificar_misma_identidad_otro_pre_hash(a: &DagBlockHeader, b: &DagBlockHeader) {
    let id_a = zx_post::firmante::Firmante::identidad(a).huella();
    let id_b = zx_post::firmante::Firmante::identidad(b).huella();
    assert_eq!(
        id_a, id_b,
        "zx-adversario doble-firma: bug interno, la identidad RAT-1 debía coincidir"
    );
    assert_ne!(
        a.pre_hash(),
        b.pre_hash(),
        "zx-adversario doble-firma: bug interno, el pre_hash debía cambiar con el timestamp"
    );
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
                "zx-adversario",
                "--objetivo",
                "/ip4/127.0.0.1/tcp/1",
                "--red",
                valor.get_name(),
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
            let espia = Espia::nuevo(cli.red);
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
        let cli = Cli::try_parse_from(["zx-adversario", "--objetivo", "/ip4/127.0.0.1/tcp/1"])
            .expect("CLI sin opción");
        assert_eq!(cli.red, zx_node::cli::RedCli::Dev);
        let estado = Espia::nuevo(cli.red).expect("red por defecto").estado();
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
