//! `zx-cartera` (binario) — cartera dev de TX-4.
//!
//! Genera claves dev, construye y firma transacciones y las **difunde** por el tema `/zx-<red>/tx/1`
//! del protocolo real de `zx-p2p`, sin RPC. Observa los bloques difundidos para informar si una
//! transacción llegó a incluirse.
//!
//! Subcomandos:
//! - `claves`: deriva `--semilla`/`--indices` y las escribe en `--archivo` (nunca en el repositorio).
//! - `transferencia`, `deposito`, `retiro`, `liberacion`: construyen, firman y auto-comprueban.
//! - `enviar`: publica una o varias txs y espera su inclusión.
//!
//! Los negativos de V3 se piden con `--corromper-firma` (firma mala) y `--doble-gasto` (duplica una
//! entrada, doble gasto interno demostrable); el caso de tarifa baja se construye con salidas que
//! dejan una tarifa `< φ_min·peso`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use libp2p::core::transport::Transport as _;
use libp2p::{Multiaddr, PeerId, Swarm, identity, noise, yamux};
use zx_cartera::{
    ClaveCartera, Entrada, TxFirmada, deposito_v2, liberacion_v2, retiro_v2, transferencia_v1,
};
use zx_consensus::genesis::HASH_GENESIS_DEV;
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest, TxId};
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_core::tx::{Lock, OutPoint, TxOut};
use zx_core::{CBID_RED_DEV, txid};
use zx_p2p::behaviour::ZxBehaviour;
use zx_p2p::config::ParametrosRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};
use zx_p2p::servicio::{EventoRed, arrancar};

zx_core::definir_red_cli! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
    enum RedCli
}

/// Línea de órdenes de la cartera.

#[derive(Parser, Debug)]
#[command(
    name = "zx-cartera",
    about = "Cartera dev de ZEROX (TX-4): construye, firma y difunde transacciones sin RPC"
)]
struct Cli {
    /// Red del nodo objetivo: nombres y valor por defecto compartidos con `zx-node`.
    #[arg(long, global = true, value_enum, default_value_t = RedCli::POR_DEFECTO)]
    red: RedCli,

    /// Subcomando.
    #[command(subcommand)]
    modo: Modo,
}

/// Subcomandos de la cartera.
#[derive(Subcommand, Debug)]
enum Modo {
    /// Deriva claves dev y las muestra; con `--archivo`, las guarda.
    Claves {
        /// Semilla de la derivación (debe coincidir con la de los nodos).
        #[arg(long, default_value_t = 1)]
        semilla: u64,
        /// Índices que se derivan.
        #[arg(long, value_delimiter = ',', default_value = "0,1,2,3")]
        indices: Vec<u32>,
        /// Fichero de salida (semilla + claves secretas). Fuera del repositorio.
        #[arg(long, value_name = "RUTA")]
        archivo: Option<PathBuf>,
    },
    /// Construye y firma una transferencia v1.
    Transferencia {
        /// Entrada `TXID:INDICE:VALOR_BREK:INDICE_CLAVE` (repetible).
        #[arg(long, value_name = "SPEC")]
        entrada: Vec<String>,
        /// Salida `VALOR_BREK:INDICE_CLAVE` (repetible).
        #[arg(long, value_name = "SPEC")]
        salida: Vec<String>,
        /// Semilla de las claves dev.
        #[arg(long, default_value_t = 1)]
        semilla: u64,
        /// Fichero de claves (subcomando `claves`); si se da, manda sobre `--semilla`.
        #[arg(long, value_name = "RUTA")]
        claves: Option<PathBuf>,
        /// Corrompe un bit de la primera firma (negativo de V3: firma mala).
        #[arg(long, default_value_t = false)]
        corromper_firma: bool,
        /// Duplica la primera entrada (negativo de V3: doble gasto interno).
        #[arg(long, default_value_t = false)]
        doble_gasto: bool,
        /// Fichero donde dejar el hexadecimal de la tx (si no, se imprime).
        #[arg(long, value_name = "RUTA")]
        archivo_tx: Option<PathBuf>,
    },
    /// Construye y firma un depósito v2 (con firma de aceptación de la clave destino).
    Deposito {
        /// Entrada `TXID:INDICE:VALOR_BREK:INDICE_CLAVE` (repetible).
        #[arg(long, value_name = "SPEC")]
        entrada: Vec<String>,
        /// Salida `VALOR_BREK:INDICE_CLAVE` (repetible).
        #[arg(long, value_name = "SPEC")]
        salida: Vec<String>,
        /// Índice de la clave que recibe la garantía.
        #[arg(long)]
        indice_destino: u32,
        /// Importe del depósito, en brek.
        #[arg(long)]
        importe: i64,
        /// `nonce_siguiente` de la clave destino (F-15).
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        /// Semilla de las claves dev.
        #[arg(long, default_value_t = 1)]
        semilla: u64,
        /// Fichero de claves (subcomando `claves`).
        #[arg(long, value_name = "RUTA")]
        claves: Option<PathBuf>,
        /// Corrompe un bit de la primera firma (negativo de V3: firma mala).
        #[arg(long, default_value_t = false)]
        corromper_firma: bool,
        /// Duplica la primera entrada (negativo de V3: doble gasto interno).
        #[arg(long, default_value_t = false)]
        doble_gasto: bool,
        /// Fichero donde dejar el hexadecimal de la tx.
        #[arg(long, value_name = "RUTA")]
        archivo_tx: Option<PathBuf>,
    },
    /// Construye y firma un retiro de garantía v2.
    Retiro {
        /// Índice de la clave que retira.
        #[arg(long)]
        indice: u32,
        /// Importe a retirar, en brek.
        #[arg(long)]
        importe: i64,
        /// `nonce_siguiente` de la clave (F-15).
        #[arg(long)]
        nonce: u64,
        /// Semilla de las claves dev.
        #[arg(long, default_value_t = 1)]
        semilla: u64,
        /// Fichero de claves (subcomando `claves`).
        #[arg(long, value_name = "RUTA")]
        claves: Option<PathBuf>,
        /// Corrompe un bit de la firma de aceptación (negativo de V3: firma mala).
        #[arg(long, default_value_t = false)]
        corromper_firma: bool,
        /// Fichero donde dejar el hexadecimal de la tx.
        #[arg(long, value_name = "RUTA")]
        archivo_tx: Option<PathBuf>,
    },
    /// Construye y firma una liberación de garantía v2.
    Liberacion {
        /// Índice de la clave que libera.
        #[arg(long)]
        indice: u32,
        /// Importe a liberar, en brek.
        #[arg(long)]
        importe: i64,
        /// `nonce_siguiente` de la clave (F-15).
        #[arg(long)]
        nonce: u64,
        /// Semilla de las claves dev.
        #[arg(long, default_value_t = 1)]
        semilla: u64,
        /// Fichero de claves (subcomando `claves`).
        #[arg(long, value_name = "RUTA")]
        claves: Option<PathBuf>,
        /// Fichero donde dejar el hexadecimal de la tx.
        #[arg(long, value_name = "RUTA")]
        archivo_tx: Option<PathBuf>,
    },
    /// Publica una o varias transacciones por el tema de gossip y espera su inclusión.
    Enviar {
        /// Nodo objetivo (multiaddr).
        #[arg(long, value_name = "MULTIADDR")]
        objetivo: Multiaddr,
        /// Fichero hexadecimal de una tx (repetible).
        #[arg(long, value_name = "RUTA")]
        archivo: Vec<PathBuf>,
        /// Hexadecimal de una tx (repetible).
        #[arg(long, value_name = "HEX")]
        hex: Vec<String>,
        /// Segundos a esperar la inclusión tras publicar (0 = no esperar).
        #[arg(long, default_value_t = 120)]
        plazo_s: u64,
    },
    /// Observa los bloques difundidos y lista las coinbases PoW (para elegir una salida madura).
    Observar {
        /// Nodo objetivo (multiaddr).
        #[arg(long, value_name = "MULTIADDR")]
        objetivo: Multiaddr,
        /// Segundos que dura la observación.
        #[arg(long, default_value_t = 120)]
        segundos: u64,
    },
}

/// Fichero de claves dev.
struct Llavero {
    semilla: u64,
    explicitas: BTreeMap<u32, ClaveCartera>,
}

impl Llavero {
    /// Crea un llavero que deriva todo de `semilla`.
    fn de_semilla(semilla: u64) -> Self {
        Self {
            semilla,
            explicitas: BTreeMap::new(),
        }
    }

    /// Lee un fichero del subcomando `claves` (`semilla N` y `clave I HEX`).
    ///
    /// # Errores
    /// Texto de diagnóstico si el fichero no se puede leer o una línea no cuadra.
    fn de_archivo(ruta: &std::path::Path) -> Result<Self, String> {
        let texto = std::fs::read_to_string(ruta)
            .map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()))?;
        let mut llavero = Self::de_semilla(1);
        for (n, linea) in texto.lines().enumerate() {
            let linea = linea.trim();
            if linea.is_empty() || linea.starts_with('#') {
                continue;
            }
            let campos: Vec<&str> = linea.split_whitespace().collect();
            match campos.first().copied() {
                Some("semilla") => {
                    let v = campos
                        .get(1)
                        .ok_or_else(|| format!("línea {}: falta el valor de semilla", n + 1))?;
                    llavero.semilla = v
                        .parse()
                        .map_err(|e| format!("línea {}: semilla: {e}", n + 1))?;
                }
                Some("clave") => {
                    let i: u32 = campos
                        .get(1)
                        .ok_or_else(|| format!("línea {}: falta el índice", n + 1))?
                        .parse()
                        .map_err(|e| format!("línea {}: índice: {e}", n + 1))?;
                    let hexs = campos
                        .get(2)
                        .ok_or_else(|| format!("línea {}: falta la clave", n + 1))?;
                    let bytes =
                        hex::decode(hexs).map_err(|e| format!("línea {}: hex: {e}", n + 1))?;
                    let clave = ClaveCartera::desde_secreto(i, &bytes)
                        .map_err(|e| format!("línea {}: {e}", n + 1))?;
                    llavero.explicitas.insert(i, clave);
                }
                otro => {
                    return Err(format!("línea {}: campo desconocido {otro:?}", n + 1));
                }
            }
        }
        Ok(llavero)
    }

    /// La clave `indice`: la explícita del fichero o la derivada de la semilla.
    fn clave(&self, indice: u32) -> ClaveCartera {
        self.explicitas
            .get(&indice)
            .cloned()
            .unwrap_or_else(|| ClaveCartera::derivar(self.semilla, indice))
    }
}

/// Parsea una entrada `TXID:INDICE:VALOR:INDICE_CLAVE`.
fn parse_entrada(spec: &str, llavero: &Llavero) -> Result<Entrada, String> {
    let campos: Vec<&str> = spec.split(':').collect();
    if campos.len() != 4 {
        return Err(format!(
            "--entrada espera TXID:INDICE:VALOR:INDICE_CLAVE, recibido {spec:?}"
        ));
    }
    let txid_hex = campos
        .first()
        .copied()
        .ok_or_else(|| "falta el txid".to_string())?;
    let bytes = hex::decode(txid_hex).map_err(|e| format!("txid {txid_hex:?}: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("el txid {txid_hex:?} no mide 32 B"))?;
    let prev_index: u32 = campo(campos.get(1), "prev_index")?
        .parse()
        .map_err(|e| format!("prev_index: {e}"))?;
    let valor_i: i64 = campo(campos.get(2), "valor")?
        .parse()
        .map_err(|e| format!("valor: {e}"))?;
    let clave_i: u32 = campo(campos.get(3), "índice de clave")?
        .parse()
        .map_err(|e| format!("índice de clave: {e}"))?;
    let valor = Amount::nuevo(valor_i).map_err(|e| format!("valor: {e}"))?;
    let outpoint = OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes(arr)),
        prev_index,
    };
    Ok(Entrada::p2k(outpoint, valor, llavero.clave(clave_i)))
}

/// Parsea una salida `VALOR:INDICE_CLAVE`.
fn parse_salida(spec: &str, llavero: &Llavero) -> Result<TxOut, String> {
    let campos: Vec<&str> = spec.split(':').collect();
    if campos.len() != 2 {
        return Err(format!(
            "--salida espera VALOR:INDICE_CLAVE, recibido {spec:?}"
        ));
    }
    let valor_i: i64 = campo(campos.first(), "valor")?
        .parse()
        .map_err(|e| format!("valor: {e}"))?;
    let clave_i: u32 = campo(campos.get(1), "índice de clave")?
        .parse()
        .map_err(|e| format!("índice de clave: {e}"))?;
    let valor = Amount::nuevo(valor_i).map_err(|e| format!("valor: {e}"))?;
    let clave = llavero.clave(clave_i);
    Ok(TxOut {
        value: valor,
        lock: Lock::PubKey { pubkey: clave.pk },
    })
}

/// Extrae un campo obligatorio de una lista de trozos.
fn campo<'a>(valor: Option<&&'a str>, nombre: &str) -> Result<&'a str, String> {
    valor.copied().ok_or_else(|| format!("falta {nombre}"))
}

/// Corrompe un bit del testigo `indice` (negativo de firma mala).
fn corromper_firma(tx: &mut TxFirmada, indice: usize) {
    if let Some(testigo) = tx.testigos.get_mut(indice)
        && let Some(b) = testigo.first_mut()
    {
        *b ^= 0x01;
    }
}

/// Duplica la primera entrada **antes de firmar** (negativo de doble gasto interno): la tx queda
/// con la misma salida gastada dos veces y `n_wit = n_in + 1` sigue cuadrando, así que el nodo la
/// clasifica como `doble_gasto_interno` (demostrable) y no como un fallo de forma.
fn duplicar_primera_entrada(entradas: &mut Vec<Entrada>) {
    if let Some(primera) = entradas.first().cloned() {
        entradas.push(primera);
    }
}

/// Escribe la tx en `--archivo-tx` (hex) o la imprime, e imprime siempre el `txid`.
fn emitir(tx: &TxFirmada, archivo: Option<&std::path::Path>) -> Result<(), String> {
    println!("txid={}", hex::encode(tx.txid().as_bytes()));
    match archivo {
        Some(ruta) => {
            std::fs::write(ruta, tx.a_hex())
                .map_err(|e| format!("no se pudo escribir {}: {e}", ruta.display()))?;
            eprintln!("zx-cartera: tx escrita en {}", ruta.display());
        }
        None => println!("tx={}", tx.a_hex()),
    }
    Ok(())
}

/// Ejecuta el subcomando `claves`.
fn cmd_claves(
    semilla: u64,
    indices: &[u32],
    archivo: Option<&std::path::Path>,
) -> Result<(), String> {
    let indices: Vec<u32> = if indices.is_empty() {
        vec![0]
    } else {
        indices.to_vec()
    };
    let mut texto = String::from("# zx-cartera claves dev v1\n");
    texto.push_str(&format!("semilla {semilla}\n"));
    for indice in indices {
        let clave = ClaveCartera::derivar(semilla, indice);
        let sk: [u8; 32] = clave.sk.into();
        // La clave secreta solo va al fichero (nunca a la salida estándar, que acaba en registros).
        println!(
            "indice={} pk={}",
            clave.indice,
            hex::encode(clave.pk.bytes())
        );
        texto.push_str(&format!("clave {} {}\n", clave.indice, hex::encode(sk)));
    }
    if let Some(ruta) = archivo {
        std::fs::write(ruta, texto)
            .map_err(|e| format!("no se pudo escribir {}: {e}", ruta.display()))?;
        eprintln!("zx-cartera: claves escritas en {}", ruta.display());
    }
    Ok(())
}

/// Construye (y opcionalmente corrompe) una transferencia v1.
fn cmd_transferencia(
    entrada: &[String],
    salida: &[String],
    semilla: u64,
    claves: Option<&std::path::Path>,
    corromper: bool,
    doble_gasto: bool,
    archivo_tx: Option<&std::path::Path>,
) -> Result<(), String> {
    let llavero = cargar_llavero(semilla, claves)?;
    let mut entradas = parse_entradas(entrada, &llavero)?;
    let salidas = parse_salidas(salida, &llavero)?;
    if doble_gasto {
        duplicar_primera_entrada(&mut entradas);
    }
    let mut tx = transferencia_v1(&entradas, salidas).map_err(|e| e.to_string())?;
    if corromper {
        corromper_firma(&mut tx, 0);
    } else {
        tx.verificar_entradas(&entradas)
            .map_err(|e| e.to_string())?;
    }
    emitir(&tx, archivo_tx)
}

/// Construye (y opcionalmente corrompe) un depósito v2.
#[allow(clippy::too_many_arguments, reason = "espejo de los argumentos de CLI")]
fn cmd_deposito(
    entrada: &[String],
    salida: &[String],
    indice_destino: u32,
    importe: i64,
    nonce: u64,
    semilla: u64,
    claves: Option<&std::path::Path>,
    corromper: bool,
    doble_gasto: bool,
    archivo_tx: Option<&std::path::Path>,
) -> Result<(), String> {
    let llavero = cargar_llavero(semilla, claves)?;
    let mut entradas = parse_entradas(entrada, &llavero)?;
    let salidas = parse_salidas(salida, &llavero)?;
    let destino = llavero.clave(indice_destino);
    let importe = Amount::nuevo(importe).map_err(|e| format!("importe: {e}"))?;
    if doble_gasto {
        duplicar_primera_entrada(&mut entradas);
    }
    let mut tx =
        deposito_v2(&entradas, salidas, &destino, importe, nonce).map_err(|e| e.to_string())?;
    if corromper {
        corromper_firma(&mut tx, 0);
    } else {
        tx.verificar_entradas(&entradas)
            .map_err(|e| e.to_string())?;
    }
    emitir(&tx, archivo_tx)
}

/// Construye un retiro v2.
fn cmd_retiro(
    indice: u32,
    importe: i64,
    nonce: u64,
    semilla: u64,
    claves: Option<&std::path::Path>,
    corromper: bool,
    archivo_tx: Option<&std::path::Path>,
) -> Result<(), String> {
    let llavero = cargar_llavero(semilla, claves)?;
    let clave = llavero.clave(indice);
    let importe = Amount::nuevo(importe).map_err(|e| format!("importe: {e}"))?;
    let mut tx = retiro_v2(&clave, importe, nonce).map_err(|e| e.to_string())?;
    if corromper {
        corromper_firma(&mut tx, 0);
    } else {
        tx.verificar().map_err(|e| e.to_string())?;
    }
    emitir(&tx, archivo_tx)
}

/// Construye una liberación v2.
fn cmd_liberacion(
    indice: u32,
    importe: i64,
    nonce: u64,
    semilla: u64,
    claves: Option<&std::path::Path>,
    archivo_tx: Option<&std::path::Path>,
) -> Result<(), String> {
    let llavero = cargar_llavero(semilla, claves)?;
    let clave = llavero.clave(indice);
    let importe = Amount::nuevo(importe).map_err(|e| format!("importe: {e}"))?;
    let tx = liberacion_v2(&clave, importe, nonce).map_err(|e| e.to_string())?;
    tx.verificar().map_err(|e| e.to_string())?;
    emitir(&tx, archivo_tx)
}

/// Carga el llavero del fichero o lo deriva de la semilla.
fn cargar_llavero(semilla: u64, claves: Option<&std::path::Path>) -> Result<Llavero, String> {
    match claves {
        Some(ruta) => Llavero::de_archivo(ruta),
        None => Ok(Llavero::de_semilla(semilla)),
    }
}

/// Parsea todas las entradas de la CLI.
fn parse_entradas(specs: &[String], llavero: &Llavero) -> Result<Vec<Entrada>, String> {
    specs.iter().map(|s| parse_entrada(s, llavero)).collect()
}

/// Parsea todas las salidas de la CLI.
fn parse_salidas(specs: &[String], llavero: &Llavero) -> Result<Vec<TxOut>, String> {
    specs.iter().map(|s| parse_salida(s, llavero)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Red
// ─────────────────────────────────────────────────────────────────────────────

/// Manejador espía: guarda cada bloque difundido para que el bucle principal lo inspeccione.
struct Espia {
    hash_genesis: BlockHash,
    red: Red,
    bloques: Mutex<Option<tokio::sync::mpsc::UnboundedSender<BloqueRed>>>,
}

impl Espia {
    fn nuevo(
        seleccion: RedCli,
        bloques: Option<tokio::sync::mpsc::UnboundedSender<BloqueRed>>,
    ) -> Result<Self, String> {
        let red = Red::from(seleccion);
        if red != Red::Dev {
            return Err(format!(
                "red configurada {red:?}: este binario solo arranca en Red::Dev"
            ));
        }
        let hash_genesis = zx_core::red::identidad_red(
            HASH_GENESIS_DEV,
            seleccion.etiqueta_consenso(),
            seleccion.reloj_activo(),
        );
        Ok(Self {
            hash_genesis,
            red,
            bloques: Mutex::new(bloques),
        })
    }
}

impl ManejadorEntrante for Espia {
    fn estado(&self) -> Estado {
        // Identidad del perfil elegido: la misma función pura que usa el nodo.
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

/// Construye un `Swarm` sobre TCP con el behaviour de la red dev.
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

/// Tarea del bucle de red.
type TareaRed = tokio::task::JoinHandle<()>;

/// Arranca la red, marca `objetivo` y espera conexión y suscripción al tema de transacciones.
///
/// # Errores
/// Texto de diagnóstico si el `Swarm` no se construye, el `marcar` falla o no se llega a conectar y
/// suscribir en 30 s.
async fn conectar(
    objetivo: Multiaddr,
    seleccion: RedCli,
) -> Result<
    (
        zx_p2p::servicio::ManejoRed,
        tokio::sync::mpsc::UnboundedReceiver<BloqueRed>,
        TareaRed,
    ),
    String,
> {
    let (tx_bloques, rx_bloques) = tokio::sync::mpsc::unbounded_channel::<BloqueRed>();
    let espia = Arc::new(Espia::nuevo(seleccion, Some(tx_bloques))?);
    let swarm = swarm_tcp()?;
    let piezas = arrancar(swarm, Arc::clone(&espia));
    let manejo = piezas.manejo;
    let mut eventos = piezas.eventos;
    let tarea = tokio::spawn(piezas.bucle.correr());

    manejo.marcar(objetivo).await.map_err(|e| e.to_string())?;

    let topico_tx = ParametrosRed::dag_dev().topic_txs().to_owned();
    let mut conectado = false;
    let mut suscrito = false;
    // Espera a la conexión. La suscripción al tema de tx se **intenta observar**, pero no se exige:
    // el evento `Suscripcion` de gossipsub puede perderse si el anuncio llega antes de que este
    // bucle empiece a consumir eventos, y `publicar` ya reintenta mientras la malla se forma.
    let limite = tokio::time::Instant::now() + Duration::from_secs(30);
    while !conectado && tokio::time::Instant::now() < limite {
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
    // Margen corto para capturar la suscripción si aún no llegó (informativo).
    let limite_sub = tokio::time::Instant::now() + Duration::from_secs(10);
    while !suscrito && conectado && tokio::time::Instant::now() < limite_sub {
        match tokio::time::timeout(Duration::from_millis(500), eventos.recv()).await {
            Ok(Some(EventoRed::Suscripcion {
                topico,
                suscrito: s,
                ..
            })) if topico == topico_tx && s => suscrito = true,
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    println!("conectado={conectado} suscrito_tx={suscrito}");
    if !conectado {
        tarea.abort();
        return Err("no se pudo conectar con el nodo objetivo".to_string());
    }
    Ok((manejo, rx_bloques, tarea))
}

/// Publica una transacción con reintentos (la suscripción de gossipsub puede tardar en cuajar).
async fn publicar(manejo: &zx_p2p::servicio::ManejoRed, bytes: &[u8]) -> Result<(), String> {
    let mut ultimo = String::new();
    for _ in 0..40 {
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

/// Carga los bytes de todas las txs pedidas (`--archivo` y `--hex`).
fn cargar_txs(archivos: &[PathBuf], hexes: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut salida = Vec::new();
    for ruta in archivos {
        let texto = std::fs::read_to_string(ruta)
            .map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()))?;
        let bytes =
            hex::decode(texto.trim()).map_err(|e| format!("{}: hex: {e}", ruta.display()))?;
        salida.push(bytes);
    }
    for texto in hexes {
        let bytes = hex::decode(texto.trim()).map_err(|e| format!("--hex: {e}"))?;
        salida.push(bytes);
    }
    if salida.is_empty() {
        return Err("hay que dar al menos una tx con --archivo o --hex".to_string());
    }
    Ok(salida)
}

/// Publica las txs y espera su inclusión.
async fn cmd_enviar(
    objetivo: Multiaddr,
    seleccion: RedCli,
    archivos: &[PathBuf],
    hexes: &[String],
    plazo_s: u64,
) -> Result<(), String> {
    let txs = cargar_txs(archivos, hexes)?;
    // Comprueba que son decodificables y obtiene sus txid.
    let mut pendientes: Vec<(TxId, Vec<u8>)> = Vec::with_capacity(txs.len());
    for bytes in &txs {
        let firmada = TxFirmada::desde_bytes(bytes).map_err(|e| e.to_string())?;
        pendientes.push((firmada.txid(), bytes.clone()));
    }
    for (id, _) in &pendientes {
        println!("txid={}", hex::encode(id.as_bytes()));
    }

    let (manejo, mut rx_bloques, tarea) = conectar(objetivo, seleccion).await?;

    // Publica todas (incluidos los conflictos, que la mempool resolverá).
    for (id, bytes) in &pendientes {
        match publicar(&manejo, bytes).await {
            Ok(()) => println!("publicado={}", hex::encode(id.as_bytes())),
            Err(e) => println!("error_publicando={} {e}", hex::encode(id.as_bytes())),
        }
    }

    let mut incluidos: Vec<bool> = vec![false; pendientes.len()];
    let fin = tokio::time::Instant::now() + Duration::from_secs(plazo_s);
    while plazo_s > 0 && tokio::time::Instant::now() < fin && incluidos.iter().any(|x| !x) {
        match tokio::time::timeout(Duration::from_millis(500), rx_bloques.recv()).await {
            Ok(Some(bloque)) => {
                // Productor del bloque (clave pública), para saber qué nodo incluyó la tx.
                let productor = match &bloque {
                    BloqueRed::Post { cabecera, .. } => {
                        hex::encode(cabecera.sol.public_key.bytes())
                    }
                    BloqueRed::Pow { .. } => "-".to_string(),
                };
                for (i, (id, _)) in pendientes.iter().enumerate() {
                    if !incluidos.get(i).copied().unwrap_or(true) {
                        let encontrado = bloque.txs().iter().any(|t| txid(t, CBID_RED_DEV) == *id);
                        if encontrado {
                            if let Some(slot) = incluidos.get_mut(i) {
                                *slot = true;
                            }
                            println!(
                                "incluido={} productor={productor}",
                                hex::encode(id.as_bytes())
                            );
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }

    for (i, (id, _)) in pendientes.iter().enumerate() {
        let flag = i32::from(incluidos.get(i).copied().unwrap_or(false));
        println!("resultado={} incluido={flag}", hex::encode(id.as_bytes()));
    }
    tarea.abort();
    Ok(())
}

/// Observa los bloques difundidos y lista las coinbases PoW, para elegir una salida madura.
async fn cmd_observar(objetivo: Multiaddr, seleccion: RedCli, segundos: u64) -> Result<(), String> {
    let (_manejo, mut rx_bloques, tarea) = conectar(objetivo, seleccion).await?;
    let fin = tokio::time::Instant::now() + Duration::from_secs(segundos);
    let mut observados: u64 = 0;
    while tokio::time::Instant::now() < fin {
        match tokio::time::timeout(Duration::from_millis(500), rx_bloques.recv()).await {
            Ok(Some(BloqueRed::Pow { cabecera, txs, .. })) => {
                if let Some(cb) = txs.first() {
                    let (valor, pubkey) = match cb.outputs.first() {
                        Some(o) => match &o.lock {
                            Lock::PubKey { pubkey } => {
                                (o.value.brek(), hex::encode(pubkey.bytes()))
                            }
                            _ => (o.value.brek(), "-".to_string()),
                        },
                        None => (0, "-".to_string()),
                    };
                    println!(
                        "coinbase altura={} txid={} valor={} pubkey={}",
                        cabecera.height,
                        hex::encode(txid(cb, CBID_RED_DEV).as_bytes()),
                        valor,
                        pubkey
                    );
                    observados += 1;
                }
            }
            Ok(Some(BloqueRed::Post { cabecera, .. })) => {
                println!("corte slot={}", cabecera.slot);
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    println!("observados={observados}");
    tarea.abort();
    Ok(())
}

/// Punto de entrada.
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let resultado = match cli.modo {
        Modo::Claves {
            semilla,
            indices,
            archivo,
        } => cmd_claves(semilla, &indices, archivo.as_deref()),
        Modo::Transferencia {
            entrada,
            salida,
            semilla,
            claves,
            corromper_firma,
            doble_gasto,
            archivo_tx,
        } => cmd_transferencia(
            &entrada,
            &salida,
            semilla,
            claves.as_deref(),
            corromper_firma,
            doble_gasto,
            archivo_tx.as_deref(),
        ),
        Modo::Deposito {
            entrada,
            salida,
            indice_destino,
            importe,
            nonce,
            semilla,
            claves,
            corromper_firma,
            doble_gasto,
            archivo_tx,
        } => cmd_deposito(
            &entrada,
            &salida,
            indice_destino,
            importe,
            nonce,
            semilla,
            claves.as_deref(),
            corromper_firma,
            doble_gasto,
            archivo_tx.as_deref(),
        ),
        Modo::Retiro {
            indice,
            importe,
            nonce,
            semilla,
            claves,
            corromper_firma,
            archivo_tx,
        } => cmd_retiro(
            indice,
            importe,
            nonce,
            semilla,
            claves.as_deref(),
            corromper_firma,
            archivo_tx.as_deref(),
        ),
        Modo::Liberacion {
            indice,
            importe,
            nonce,
            semilla,
            claves,
            archivo_tx,
        } => cmd_liberacion(
            indice,
            importe,
            nonce,
            semilla,
            claves.as_deref(),
            archivo_tx.as_deref(),
        ),
        Modo::Enviar {
            objetivo,
            archivo,
            hex,
            plazo_s,
        } => cmd_enviar(objetivo, cli.red, &archivo, &hex, plazo_s).await,
        Modo::Observar { objetivo, segundos } => cmd_observar(objetivo, cli.red, segundos).await,
    };
    if let Err(e) = resultado {
        eprintln!("zx-cartera: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
mod red1b_tests {
    use super::{Cli, Espia, HASH_GENESIS_DEV, RedCli};
    use clap::{Parser, ValueEnum};
    use zx_core::{BlockHash, Digest, Red};
    use zx_p2p::entrante::ManejadorEntrante;
    use zx_p2p::mensaje::{Estado, Fase, PuntaPow};

    #[test]
    fn red1b_la_cartera_declara_la_identidad_del_nodo_en_cada_red() {
        for seleccion in RedCli::value_variants() {
            let valor = seleccion.to_possible_value().expect("valor de CLI");
            assert_eq!(valor.get_name(), seleccion.nombre());
            for modo in ["enviar", "observar"] {
                for global_antes in [true, false] {
                    let mut args = vec!["zx-cartera"];
                    if global_antes {
                        args.extend(["--red", valor.get_name()]);
                    }
                    args.extend([modo, "--objetivo", "/ip4/127.0.0.1/tcp/1"]);
                    if !global_antes {
                        args.extend(["--red", valor.get_name()]);
                    }
                    let cli = Cli::try_parse_from(args).expect("red canónica reconocida");
                    assert_eq!(cli.red, *seleccion);
                    let espia = Espia::nuevo(cli.red, None);
                    let red = Red::from(*seleccion);
                    if red == Red::Dev {
                        let estado = espia.expect("red dev operativa").estado();
                        assert_eq!(estado.red, red);
                        assert_eq!(
                            estado.hash_genesis,
                            zx_core::red::identidad_red(
                                HASH_GENESIS_DEV,
                                seleccion.etiqueta_consenso(),
                                seleccion.reloj_activo(),
                            ),
                            "el saludo usa la identidad compartida para {modo} en {seleccion:?}"
                        );
                    } else {
                        assert_eq!(
                            espia.err().expect("red no operativa rechazada"),
                            format!(
                                "red configurada {red:?}: este binario solo arranca en Red::Dev"
                            )
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn red1b_sin_opcion_la_cartera_declara_la_de_hoy() {
        for modo in ["enviar", "observar"] {
            let cli =
                Cli::try_parse_from(["zx-cartera", modo, "--objetivo", "/ip4/127.0.0.1/tcp/1"])
                    .expect("CLI anterior sin --red");
            assert_eq!(cli.red, RedCli::Dev);
            let estado = Espia::nuevo(cli.red, None)
                .expect("red por defecto")
                .estado();
            let anterior = Estado {
                hash_genesis: BlockHash::from_digest(Digest::from_bytes([
                    0xc7, 0x2f, 0xdb, 0x3b, 0x37, 0xe7, 0x57, 0x1a, 0x82, 0xec, 0x1e, 0x0e, 0x97,
                    0x3e, 0x90, 0xd5, 0xe9, 0x5e, 0x7a, 0xd9, 0xfc, 0x87, 0x17, 0x72, 0x26, 0x5b,
                    0x19, 0x94, 0x05, 0x0c, 0x2d, 0x59,
                ])),
                red: Red::Dev,
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
            };
            assert_eq!(estado, anterior, "se conserva el saludo completo anterior");
        }
    }
}
