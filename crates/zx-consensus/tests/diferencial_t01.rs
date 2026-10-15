//! Arnés **diferencial** contra el oráculo Julia T01 (`ORDEN-SL4a` §2.3, V4; vectores v0.6.1 con
//! `EvidenceTx`, TX-2b y TX-2c).
//!
//! Lee `testdata/transicion-v0.6.1/vectores-transicion-v0.6.1.txt` (y su cobertura), deriva claves
//! Ed25519 deterministas por clave abstracta (`semilla = SHA3-256("zx-t01-clave" ‖ k u64 LE)` con
//! `ed25519-zebra`), construye transacciones **reales** v1/v2/v3/v4 firmadas por el `firmante`
//! abstracto, traduce la salida implícita de una `Liberacion` a su `OutPoint` real `(txid, 0)`,
//! ejecuta el motor en el orden de entrega del fichero y compara `RES`, `SEL`, la cobertura y el
//! estado canónico traducido de vuelta a claves abstractas.
//!
//! # TX-2b · límites de tamaño
//!
//! - **TXL-01/TXL-02.** El oráculo v0.6 modela `tx_a_bytes` con un campo abstracto `bytes=`.
//!   Conforme a `ACLARACION-TX2b.md` §1, aquí **no** se fabrican transacciones de ese tamaño: se
//!   construye la transacción/cuerpo que el vector describe, se mide su `tx_a_bytes` **real** y se
//!   fija el límite del **bloque descrito** al tamaño real (`ok`) o a ese tamaño menos 1 (`mas1`).
//!   Los bloques anteriores de la historia se aplican con el límite del vector (`100 000` /
//!   `320 000`): un `max_tx_bytes` global al caso rechazaría coinbases previas de dos salidas más
//!   grandes que la tx descrita, lo que el vector no espera.
//!
//! # TX-2c · modo fusión del oráculo v0.6.1
//!
//! - **Fusión por bloque objeto (`FD-TX2a-R-1`).** `PARAM fusion=1` se aplica **solo a la hoja del
//!   caso** (el último `BLOQUE`); el resto de la historia es contexto en modo estricto. El arnés
//!   computa el prefijo con `seleccionar` (estricto, igual que el oráculo) y aplica la hoja con
//!   `aplicar_fusion` sobre el estado de su padre (`FD-TX2c-3`).
//! - **PoW en fusión (`ED-1`).** Un bloque PoW por la vía de fusión devuelve
//!   `ErrorTransicion::ErrOperacionFase`, que es lo que esperan los 6 `dep-fee-fusion-*` de v0.6.1.
//!   Se **retira** el canal de excepción de TX-2b: ahora cuentan como cualquier otro `RES`.
//! - **PoST en fusión.** Los 6 `dep-fee-fusion-post-*` se traducen a `aplicar_fusion` (tarifa
//!   acreditada si la transacción se aplica; no acreditada si se descarta) y se comparan también
//!   `SEL`, `UTXO`, `GAR` y `EST`.
//!
//! Requisito de V4: **0 discrepancias** en los 3 230 casos y cobertura idéntica a
//! `cobertura-v0.6.1.txt`.

#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio test"
)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::fs;

use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use zx_consensus::transicion::seleccion::seleccionar_con_inicial;
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, HechosCabecera, Origen, ParametrosEvidencia,
    ParametrosTransicion, Punto, aplicar_con_undo, aplicar_fusion, deshacer,
};
use zx_core::preimage::tx::txid as calcular_txid;
use zx_core::wire::tx_a_bytes;
use zx_core::{
    Amount, BlockHash, BodyCommitment, CBID_RED_DEV, ClavePublica, DagBlockHeader, Digest,
    ErrorFormaTx, ExtensionTx, HashType, Lock, MerkleRoot, OutPoint, PadresDag, SigHash,
    SolucionPoas, SpentOutput, TipoGarantia, Tx, TxId, TxIn, TxOut,
};

/// Rutas a los ficheros de vectores v0.6.1 dentro del workspace (`ws/testdata/...`).
const RUTA_VECTORES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/transicion-v0.6.1/vectores-transicion-v0.6.1.txt"
);
const RUTA_COBERTURA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/transicion-v0.6.1/cobertura-v0.6.1.txt"
);
const RUTA_NEGATIVOS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/transicion-v0.2/vectores-transicion-negativos-v0.2.txt"
);

// ─────────────────────────────────────────────────────────────────────────────
// Claves y salidas abstractas
// ─────────────────────────────────────────────────────────────────────────────

/// Deriva el par determinista de la clave abstracta `k`.
fn firmante_de(k: u64) -> SigningKey {
    let mut mensaje = b"zx-t01-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    SigningKey::from(*digest.as_bytes())
}

/// Clave pública determinista de la clave abstracta `k`.
fn clave_de(k: u64) -> ClavePublica {
    let sk = firmante_de(k);
    let vk = VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

/// Hash de bloque sintético: el id abstracto en big-endian, para que el orden de bytes coincida con
/// el orden entero que usa el oráculo en los desempates.
fn hash_de(id: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&id.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

/// `OutPoint` sintético para una entrada abstracta sin salida registrada: el motor no lo encontrará
/// y devolverá `ErrDobleGasto`, como el oráculo.
fn outpoint_inexistente(id: u64) -> OutPoint {
    let mut mensaje = b"zx-t01-inexistente".to_vec();
    mensaje.extend_from_slice(&id.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    OutPoint {
        prev_txid: TxId::from_digest(digest),
        prev_index: 0,
    }
}

/// Base del rango reservado a las salidas de liberación (T01-E / F-18).
const ID_LIB_BASE: u64 = 1 << 62;
/// Máscara de 20 bits: `clave`, `nonce` e `importe` viven en `[0, 2²⁰)`.
const MASCARA_20: u64 = (1 << 20) - 1;

/// Deshace `ID_LIB(clave, nonce, importe) = 2⁶² + clave·2⁴⁰ + nonce·2²⁰ + importe`.
///
/// Devuelve `None` para un id explícito (`< 2⁶²`) o fuera del rango de 60 bits de la codificación.
fn decodificar_id_lib(id: u64) -> Option<(u64, u64, u64)> {
    let resto = id.checked_sub(ID_LIB_BASE)?;
    if (resto >> 60) != 0 {
        return None;
    }
    let importe = resto & MASCARA_20;
    let nonce = (resto >> 20) & MASCARA_20;
    let clave = (resto >> 40) & MASCARA_20;
    Some((clave, nonce, importe))
}

/// Registro de una salida abstracta: su `OutPoint` real, valor y dueño.
#[derive(Clone, Copy)]
struct SalidaRef {
    op: OutPoint,
    valor: Amount,
    dueno: u64,
}

/// Correspondencia entre claves abstractas y claves reales.
#[derive(Default)]
struct Claves {
    id_a_clave: BTreeMap<u64, ClavePublica>,
    clave_a_id: BTreeMap<[u8; 32], u64>,
}

impl Claves {
    fn id(&mut self, k: u64) -> ClavePublica {
        if let Some(pk) = self.id_a_clave.get(&k) {
            return *pk;
        }
        let pk = clave_de(k);
        self.id_a_clave.insert(k, pk);
        self.clave_a_id.insert(*pk.bytes(), k);
        pk
    }

    fn abstracta(&self, pk: &ClavePublica) -> Option<u64> {
        self.clave_a_id.get(pk.bytes()).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser del fichero de vectores
// ─────────────────────────────────────────────────────────────────────────────

/// Campos `clave=valor` de una línea (el primer token es el nombre de la línea).
fn campos(linea: &str) -> BTreeMap<String, String> {
    let mut mapa = BTreeMap::new();
    for token in linea.split_whitespace().skip(1) {
        if let Some((k, v)) = token.split_once('=') {
            mapa.insert(k.to_string(), v.to_string());
        }
    }
    mapa
}

fn parse_salidas(texto: &str) -> Vec<(u64, u64, u64)> {
    let dentro = texto
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");
    if dentro.is_empty() {
        return Vec::new();
    }
    dentro
        .split(',')
        .map(|item| {
            let p: Vec<&str> = item.split(':').collect();
            (
                p[0].parse().expect("id de salida"),
                p[1].parse().expect("valor de salida"),
                p[2].parse().expect("dueño de salida"),
            )
        })
        .collect()
}

fn parse_entradas(texto: &str) -> Vec<u64> {
    let dentro = texto
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");
    if dentro.is_empty() {
        return Vec::new();
    }
    dentro
        .split(',')
        .map(|x| x.parse().expect("id de entrada"))
        .collect()
}

/// Una transacción abstracta leída del fichero.
#[derive(Clone, Debug)]
struct TxCrudo {
    tipo: String,
    firmante: u64,
    clave: u64,
    importe: u64,
    ent: Vec<u64>,
    sal: Vec<(u64, u64, u64)>,
    /// F-15: nonce de una operación de garantía (0 en el resto).
    nonce: u64,
    /// SL-4a: evidencia abstracta de una `EvidenceTx` v4, si el vector la trae.
    ev: Option<EvCrudo>,
    /// TX-2b: tamaño abstracto `|tx_a_bytes(tx)|` del vector v0.6 (`bytes=`; 0 si falta).
    bytes: u64,
}

/// Una cabecera abstracta de evidencia (`ev=` de T01).
#[derive(Clone, Copy, Debug)]
struct EvCab {
    cbid: u32,
    clave: u64,
    sector: u16,
    historia: u64,
    chunk: u64,
    slot: u64,
    ph: u64,
    sello_ok: bool,
}

/// La evidencia abstracta de una `EvidenceTx` v4.
#[derive(Clone, Copy, Debug)]
struct EvCrudo {
    id1: EvCab,
    id2: EvCab,
}

fn parsear_evidencia(texto: &str) -> EvCrudo {
    let partes: Vec<&str> = texto.split('|').collect();
    assert_eq!(partes.len(), 2, "evidencia malformada: {texto}");
    let mut cab = [EvCab {
        cbid: 0,
        clave: 0,
        sector: 0,
        historia: 0,
        chunk: 0,
        slot: 0,
        ph: 0,
        sello_ok: true,
    }; 2];
    for (j, p) in partes.iter().enumerate() {
        let f: Vec<&str> = p.split(':').collect();
        assert_eq!(f.len(), 8, "cabecera de evidencia malformada: {p}");
        cab[j] = EvCab {
            cbid: f[0].parse().expect("cbid"),
            clave: f[1].parse().expect("clave"),
            sector: f[2].parse().expect("sector"),
            historia: f[3].parse().expect("historia"),
            chunk: f[4].parse().expect("chunk"),
            slot: f[5].parse().expect("slot"),
            ph: f[6].parse().expect("pre_hash"),
            sello_ok: f[7] == "1",
        };
    }
    EvCrudo {
        id1: cab[0],
        id2: cab[1],
    }
}

/// Un bloque abstracto leído del fichero.
#[derive(Clone, Debug)]
struct BloqueCrudo {
    id: u64,
    fam: String,
    padre: u64,
    altura: u32,
    trabajo: u64,
    pow_ok: bool,
    slot: u64,
    prod: u64,
    peso: u64,
    reqdecl: u64,
    txs: Vec<TxCrudo>,
}

/// Parámetros de prueba de un caso.
#[derive(Clone, Debug)]
struct ParamCrudo {
    h_dep: u32,
    m_cb: u32,
    m_dep: u32,
    h_corte_min: u32,
    w_min: u64,
    s_min: u64,
    k_min: u32,
    q: u64,
    m_res_slots: u64,
    m_dep_slots: u64,
    m_rec_slots: u64,
    r_slots: u64,
    f_slots: Option<u64>,
    f_num: u64,
    f_den: u64,
    plazo_slots: u64,
    m_margen_slots: u64,
    cbid: u32,
    evp: bool,
    /// TX-2b: `max_tx_bytes` del vector (`100 000` por defecto).
    max_tx_bytes: u64,
    /// TX-2b: `max_cuerpo_bloque_bytes` del vector (`320 000` por defecto).
    max_cuerpo_bloque_bytes: u64,
    /// TX-2b: `fusion=` del vector (por defecto `false`).
    fusion: bool,
}

impl ParamCrudo {
    fn vacio() -> Self {
        Self {
            h_dep: 0,
            m_cb: 0,
            m_dep: 0,
            h_corte_min: 0,
            w_min: 0,
            s_min: 0,
            k_min: 0,
            q: 0,
            m_res_slots: 0,
            m_dep_slots: 0,
            m_rec_slots: 0,
            r_slots: 0,
            f_slots: None,
            f_num: 1,
            f_den: 1,
            plazo_slots: 0,
            m_margen_slots: 0,
            cbid: 0,
            evp: false,
            max_tx_bytes: 100_000,
            max_cuerpo_bloque_bytes: 320_000,
            fusion: false,
        }
    }
}

/// Un caso completo del fichero.
#[derive(Debug)]
struct Caso {
    n: u64,
    nombre: String,
    param: ParamCrudo,
    bloques: Vec<BloqueCrudo>,
    res: BTreeMap<u64, String>,
    sel: i64,
    utxo: Vec<String>,
    gar: Vec<String>,
    est: String,
}

fn parsear_parametros(c: &BTreeMap<String, String>) -> ParamCrudo {
    let f = c.get("F_slots").expect("F_slots");
    ParamCrudo {
        h_dep: c.get("H_dep").expect("H_dep").parse().expect("H_dep"),
        m_cb: c.get("M_cb").expect("M_cb").parse().expect("M_cb"),
        m_dep: c.get("M_dep").expect("M_dep").parse().expect("M_dep"),
        h_corte_min: c
            .get("H_corte_min")
            .expect("H_corte_min")
            .parse()
            .expect("H_corte_min"),
        w_min: c.get("W_min").expect("W_min").parse().expect("W_min"),
        s_min: c.get("S_min").expect("S_min").parse().expect("S_min"),
        k_min: c.get("K_min").expect("K_min").parse().expect("K_min"),
        q: c.get("q").expect("q").parse().expect("q"),
        m_res_slots: c
            .get("M_res_slots")
            .expect("M_res_slots")
            .parse()
            .expect("M_res_slots"),
        m_dep_slots: c
            .get("M_dep_slots")
            .expect("M_dep_slots")
            .parse()
            .expect("M_dep_slots"),
        m_rec_slots: c
            .get("M_rec_slots")
            .expect("M_rec_slots")
            .parse()
            .expect("M_rec_slots"),
        r_slots: c.get("R_slots").expect("R_slots").parse().expect("R_slots"),
        f_slots: if f == "inf" {
            None
        } else {
            Some(f.parse().expect("F_slots"))
        },
        f_num: c.get("f_num").map_or(1, |v| v.parse().expect("f_num")),
        f_den: c.get("f_den").map_or(1, |v| v.parse().expect("f_den")),
        plazo_slots: c
            .get("Plazo_slots")
            .map_or(0, |v| v.parse().expect("Plazo_slots")),
        m_margen_slots: c
            .get("M_margen_slots")
            .map_or(0, |v| v.parse().expect("M_margen_slots")),
        cbid: c.get("cbid").map_or(0, |v| v.parse().expect("cbid")),
        evp: c.get("evp").is_some_and(|v| v == "1"),
        max_tx_bytes: c
            .get("max_tx_bytes")
            .map_or(100_000, |v| v.parse().expect("max_tx_bytes")),
        max_cuerpo_bloque_bytes: c
            .get("max_cuerpo_bloque_bytes")
            .map_or(320_000, |v| v.parse().expect("max_cuerpo_bloque_bytes")),
        fusion: c.get("fusion").is_some_and(|v| v == "1"),
    }
}

fn parsear_fichero(ruta: &str) -> Vec<Caso> {
    let contenido = fs::read_to_string(ruta).expect("leer vectores");
    let mut casos = Vec::new();
    let mut caso: Option<Caso> = None;
    let mut bloque: Option<BloqueCrudo> = None;
    for linea in contenido.lines() {
        if linea.starts_with('#') || linea.trim().is_empty() {
            continue;
        }
        let primera = linea.split_whitespace().next().unwrap_or("");
        match primera {
            "CASO" => {
                let c = campos(linea);
                caso = Some(Caso {
                    n: c.get("n").expect("n").parse().expect("n"),
                    nombre: c.get("nombre").expect("nombre").clone(),
                    param: ParamCrudo::vacio(),
                    bloques: Vec::new(),
                    res: BTreeMap::new(),
                    sel: -1,
                    utxo: Vec::new(),
                    gar: Vec::new(),
                    est: String::new(),
                });
            }
            "PARAM" => {
                if let Some(c) = caso.as_mut() {
                    c.param = parsear_parametros(&campos(linea));
                }
            }
            "BLOQUE" => {
                let c = campos(linea);
                bloque = Some(BloqueCrudo {
                    id: c.get("id").expect("id").parse().expect("id"),
                    fam: c.get("fam").expect("fam").clone(),
                    padre: c.get("padre").expect("padre").parse().expect("padre"),
                    altura: c.get("altura").expect("altura").parse().expect("altura"),
                    trabajo: c.get("trabajo").expect("trabajo").parse().expect("trabajo"),
                    pow_ok: c.get("pow_ok").expect("pow_ok") == "1",
                    slot: c.get("slot").expect("slot").parse().expect("slot"),
                    prod: c.get("prod").expect("prod").parse().expect("prod"),
                    peso: c.get("peso").expect("peso").parse().expect("peso"),
                    reqdecl: c.get("reqdecl").expect("reqdecl").parse().expect("reqdecl"),
                    txs: Vec::new(),
                });
            }
            "TX" => {
                let c = campos(linea);
                if let Some(b) = bloque.as_mut() {
                    b.txs.push(TxCrudo {
                        tipo: c.get("tipo").expect("tipo").clone(),
                        firmante: c
                            .get("firmante")
                            .expect("firmante")
                            .parse()
                            .expect("firmante"),
                        clave: c.get("clave").expect("clave").parse().expect("clave"),
                        importe: c.get("importe").expect("importe").parse().expect("importe"),
                        ent: parse_entradas(c.get("ent").expect("ent")),
                        sal: parse_salidas(c.get("sal").expect("sal")),
                        // F-15: solo los vectores v0.1 traen `nonce=`; ausente = 0.
                        nonce: c.get("nonce").map_or(0, |v| v.parse().expect("nonce")),
                        // SL-4a: `ev=` solo en las `EvidenceTx` v4 con cabeceras.
                        ev: c.get("ev").map(|v| parsear_evidencia(v)),
                        // TX-2b: tamaño abstracto del vector (0 si el campo falta).
                        bytes: c.get("bytes").map_or(0, |v| v.parse().expect("bytes")),
                    });
                }
            }
            "RES" => {
                let c = campos(linea);
                let res = c.get("res").expect("res").clone();
                if let Some(b) = bloque.take()
                    && let Some(caso) = caso.as_mut()
                {
                    caso.res.insert(b.id, res);
                    caso.bloques.push(b);
                }
            }
            "SEL" => {
                let c = campos(linea);
                if let Some(caso) = caso.as_mut() {
                    caso.sel = c.get("punta").expect("punta").parse().expect("punta");
                }
            }
            "UTXO" => {
                if let Some(caso) = caso.as_mut() {
                    caso.utxo.push(linea.to_string());
                }
            }
            "GAR" => {
                if let Some(caso) = caso.as_mut() {
                    caso.gar.push(linea.to_string());
                }
            }
            "EST" => {
                if let Some(caso) = caso.as_mut() {
                    caso.est = linea.to_string();
                }
            }
            "FIN" => {
                if let Some(c) = caso.take() {
                    casos.push(c);
                }
            }
            _ => {}
        }
    }
    casos
}

// ─────────────────────────────────────────────────────────────────────────────
// Parámetros y construcción de bloques reales
// ─────────────────────────────────────────────────────────────────────────────

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).expect("subsidio pow")
}

fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).expect("subsidio post")
}

fn parametros(
    p: &ParamCrudo,
    max_tx_bytes: u64,
    max_cuerpo_bloque_bytes: u64,
) -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: p.h_dep,
        m_cb: p.m_cb,
        m_dep: p.m_dep,
        h_corte_min: p.h_corte_min,
        w_min: U256::from(p.w_min),
        s_min: Amount::nuevo(p.s_min as i64).expect("S_min"),
        q: Amount::nuevo(p.q as i64).expect("q"),
        k_min: p.k_min,
        max_tx_bytes,
        max_cuerpo_bloque_bytes,
        m_res_slots: p.m_res_slots,
        m_dep_slots: p.m_dep_slots,
        m_rec_slots: p.m_rec_slots,
        r_slots: p.r_slots,
        f_slots: p.f_slots,
        subsidio_pow,
        subsidio_post,
    }
}

/// SL-4a: parámetros de evidencia del caso.
fn parametros_evidencia(p: &ParamCrudo) -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: p.f_num,
        f_den: p.f_den,
        plazo_slots: p.plazo_slots,
        m_margen_slots: p.m_margen_slots,
        cbid: p.cbid,
        evp: p.evp,
    }
}

/// Constructor de transacciones reales con la correspondencia de salidas abstractas.
struct Constructor {
    cbid: u32,
    claves: Claves,
    /// Salidas explícitas (`id < 2⁶²`): coinbases, transferencias y cambios.
    salidas: BTreeMap<u64, SalidaRef>,
    /// Salidas de liberaciones, indexadas por el `(clave, nonce, importe)` que decodifica su
    /// `ID_LIB`. Su `OutPoint` real es `(txid, 0)`; no hay contador de ids implícitos.
    liberaciones: BTreeMap<(u64, u64, u64), SalidaRef>,
}

impl Constructor {
    fn nuevo(cbid: u32) -> Self {
        Self {
            cbid,
            claves: Claves::default(),
            salidas: BTreeMap::new(),
            liberaciones: BTreeMap::new(),
        }
    }

    /// Resuelve una entrada abstracta a su salida real: los ids explícitos por su mapa; los ids de
    /// liberación (`≥ 2⁶²`) decodificando `(clave, nonce, importe)` y buscando el `(txid, 0)`
    /// registrado al construirla. Una entrada sin salida creada queda ausente.
    fn salida(&self, id: u64) -> Option<&SalidaRef> {
        if let Some(triple) = decodificar_id_lib(id) {
            self.liberaciones.get(&triple)
        } else {
            self.salidas.get(&id)
        }
    }

    fn txin(&self, id: u64) -> TxIn {
        let op = self
            .salida(id)
            .map_or_else(|| outpoint_inexistente(id), |s| s.op);
        TxIn {
            outpoint: op,
            sequence: 0,
        }
    }

    fn salidas_reales(&mut self, sal: &[(u64, u64, u64)]) -> Vec<TxOut> {
        sal.iter()
            .map(|(_id, valor, dueno)| {
                // Decisión 4 de ORDEN-W02b: sin claves de salida artificiales. Con F-15/F-16 los
                // `txid` de operaciones repetidas ya son únicos, así que cada salida se bloquea con
                // la clave real de su dueño abstracto.
                let pk = self.claves.id(*dueno);
                TxOut {
                    value: Amount::nuevo(*valor as i64).expect("valor"),
                    lock: Lock::PubKey { pubkey: pk },
                }
            })
            .collect()
    }

    fn gastadas(&self, ids: &[u64]) -> Vec<SpentOutput> {
        ids.iter()
            .map(|id| match self.salida(*id) {
                Some(s) => SpentOutput {
                    value: s.valor,
                    lock: Lock::PubKey {
                        pubkey: clave_de(s.dueno),
                    },
                },
                None => SpentOutput {
                    value: Amount::CERO,
                    lock: Lock::PubKey {
                        pubkey: clave_de(0),
                    },
                },
            })
            .collect()
    }

    fn registrar(&mut self, tx: &Tx, sal: &[(u64, u64, u64)]) -> Result<(), String> {
        let txid = calcular_txid(tx, self.cbid);
        for (j, (id, valor, dueno)) in sal.iter().enumerate() {
            let op = OutPoint {
                prev_txid: txid,
                prev_index: u32::try_from(j).map_err(|_| "índice de salida".to_string())?,
            };
            let valor = Amount::nuevo(*valor as i64).expect("valor");
            self.salidas.insert(
                *id,
                SalidaRef {
                    op,
                    valor,
                    dueno: *dueno,
                },
            );
        }
        Ok(())
    }

    /// Registra la salida implícita de una `Liberacion` (F-18): su id abstracto es
    /// `ID_LIB(clave, nonce, importe)` y su `OutPoint` real `(txid, 0)`. Se indexa por el triple
    /// que decodifica ese id, sin contador.
    fn registrar_liberacion(
        &mut self,
        tx: &Tx,
        importe: u64,
        clave_abstracta: u64,
        nonce: u64,
    ) -> Result<(), String> {
        let valor = i64::try_from(importe)
            .map_err(|_| "importe de liberación fuera de rango".to_string())?;
        let txid = calcular_txid(tx, self.cbid);
        self.liberaciones.insert(
            (clave_abstracta, nonce, importe),
            SalidaRef {
                op: OutPoint {
                    prev_txid: txid,
                    prev_index: 0,
                },
                valor: Amount::nuevo(valor).expect("importe de liberación"),
                dueno: clave_abstracta,
            },
        );
        Ok(())
    }

    fn firmar_entradas(&self, tx: &Tx, ids: &[u64], firmante: u64) -> Vec<Vec<u8>> {
        let gastadas = self.gastadas(ids);
        let mut testigos = Vec::with_capacity(ids.len());
        for (i, _id) in ids.iter().enumerate() {
            let digest: SigHash =
                zx_core::sighash(tx, &gastadas, HashType::All, i, self.cbid).expect("sighash");
            // La firma siempre es del `firmante` abstracto: si no es el dueño de la salida, la
            // verificación falla y el motor devuelve `ErrFirma` (que §4 lee como `ErrAutorizacion`),
            // exactamente como el oráculo.
            let sk = firmante_de(firmante);
            let firma: [u8; 64] = sk.sign(digest.as_bytes()).into();
            testigos.push(firma.to_vec());
        }
        testigos
    }

    fn aceptacion(&self, tx: &Tx, firmante: u64) -> Vec<u8> {
        let mensaje = zx_core::mensaje_aceptacion(tx, self.cbid);
        let sk = firmante_de(firmante);
        let firma: [u8; 64] = sk.sign(&mensaje).into();
        firma.to_vec()
    }

    /// Construye una transacción abstracta como transacción real con sus testigos.
    ///
    /// `altura` es la altura del bloque que la contiene (F-16: `expiry_height` de la coinbase PoW) y
    /// `slot` su slot (F-17: `slot` de la coinbase PoST); para el resto de transacciones no aplican.
    fn construir_tx(
        &mut self,
        tx: &TxCrudo,
        productor: u64,
        altura: u32,
        slot: u64,
    ) -> Result<(Tx, Vec<Vec<u8>>), String> {
        let (real, testigos) = match tx.tipo.as_str() {
            "Coinbase" => {
                let salidas = self.salidas_reales(&tx.sal);
                let real = Tx {
                    version: 1,
                    inputs: Vec::new(),
                    outputs: salidas,
                    lock_time: 0,
                    // F-16: `expiry_height` de la coinbase PoW = altura del bloque (el génesis, 0).
                    expiry_height: altura,
                    extension: ExtensionTx::Ninguna,
                };
                (real, Vec::new())
            }
            "Transferencia" => {
                let mut inputs = Vec::with_capacity(tx.ent.len());
                for id in &tx.ent {
                    inputs.push(self.txin(*id));
                }
                let salidas = self.salidas_reales(&tx.sal);
                let real = Tx {
                    version: 1,
                    inputs,
                    outputs: salidas,
                    lock_time: 0,
                    expiry_height: 0,
                    extension: ExtensionTx::Ninguna,
                };
                let testigos = self.firmar_entradas(&real, &tx.ent, tx.firmante);
                (real, testigos)
            }
            "Deposito" | "Retiro" | "Liberacion" => {
                let tipo = match tx.tipo.as_str() {
                    "Deposito" => TipoGarantia::Deposito,
                    "Retiro" => TipoGarantia::Retiro,
                    _ => TipoGarantia::Liberacion,
                };
                let mut inputs = Vec::with_capacity(tx.ent.len());
                for id in &tx.ent {
                    inputs.push(self.txin(*id));
                }
                let salidas = self.salidas_reales(&tx.sal);
                let clave = self.claves.id(tx.clave);
                let real = Tx {
                    version: 2,
                    inputs,
                    outputs: salidas,
                    lock_time: 0,
                    expiry_height: 0,
                    extension: ExtensionTx::Garantia {
                        tipo,
                        clave,
                        importe: Amount::nuevo(tx.importe as i64).expect("importe"),
                        nonce: tx.nonce,
                    },
                };
                let mut testigos = self.firmar_entradas(&real, &tx.ent, tx.firmante);
                testigos.push(self.aceptacion(&real, tx.firmante));
                (real, testigos)
            }
            "CoinbasePost" => {
                let clave = self.claves.id(productor);
                let real = Tx {
                    version: 3,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    lock_time: 0,
                    expiry_height: 0,
                    extension: ExtensionTx::CoinbasePost {
                        clave,
                        importe: Amount::nuevo(tx.importe as i64).expect("importe"),
                        // F-17: `slot` de la coinbase PoST = slot del bloque que la contiene.
                        slot,
                    },
                };
                (real, Vec::new())
            }
            "Evidencia" => {
                let Some(ev) = tx.ev else {
                    // Evidencia malformada heredada (sin cabeceras): v4 inactiva.
                    let real = Tx {
                        version: 4,
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                        lock_time: 0,
                        expiry_height: 0,
                        extension: ExtensionTx::Ninguna,
                    };
                    return Ok((real, Vec::new()));
                };
                // Registra las claves abstractas de la identidad para que `render_gar` pueda
                // traducir de vuelta la garantía que el motor cree (p. ej. la clave 99).
                let _ = self.claves.id(ev.id1.clave);
                let _ = self.claves.id(ev.id2.clave);
                let (h1, h2) = cabeceras_de_evidencia(&ev);
                let salidas = self.salidas_reales(&tx.sal);
                let real = Tx {
                    version: 4,
                    inputs: Vec::new(),
                    outputs: salidas,
                    lock_time: 0,
                    expiry_height: 0,
                    extension: ExtensionTx::Evidencia { h1, h2 },
                };
                (real, Vec::new())
            }
            otro => return Err(format!("tipo de transacción no soportado: {otro}")),
        };
        self.registrar(&real, &tx.sal)?;
        if tx.tipo == "Liberacion" {
            self.registrar_liberacion(&real, tx.importe, tx.clave, tx.nonce)?;
        }
        Ok((real, testigos))
    }
}

/// Cabecera PoST sintética con `height = 0` (solo se usa para `validar_forma_cabecera_post`).
fn cabecera_post(padre: BlockHash) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: CBID_RED_DEV,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0u8; 32])),
        timestamp: 0,
        height: 0,
        slot: 0,
        pot_output: [0u8; 16],
        rango_solucion: 0,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0u8; 32])),
        padres: PadresDag::nuevo(padre, &[]).expect("padres"),
        sello: [0u8; 64],
    }
}

/// Construye una cabecera `PoAS_PoT_DAG` real con la identidad abstracta `cab` y una sal.
fn cabecera_evidencia(cab: &EvCab, sal: u64) -> DagBlockHeader {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&cab.chunk.to_le_bytes());
    let sol = SolucionPoas {
        public_key: clave_de(cab.clave),
        sector_index: cab.sector,
        history_size: cab.historia,
        chunk,
        ..Default::default()
    };
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: cab.cbid,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0u8; 32])),
        timestamp: sal,
        height: 0,
        slot: cab.slot,
        pot_output: [0u8; 16],
        rango_solucion: cab.ph,
        sol,
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0u8; 32])),
        padres: PadresDag::genesis(),
        sello: [0u8; 64],
    }
}

/// Traduce una evidencia abstracta a dos cabeceras reales con sellos Ed25519 reales.
///
/// El orden canónico real por `pre_hash` reproduce la relación `ph1 < ph2` del vector: se busca una
/// sal en `H2` hasta que la comparación real coincide con la abstracta. Si la identidad y la
/// `pre_hash` abstractas son iguales, las prefirmas son idénticas y el `pre_hash` real también lo
/// es (`ErrOrdenCanonico`). La identidad/cbid/sellos del motor se comprueban sobre las cabeceras.
fn cabeceras_de_evidencia(ev: &EvCrudo) -> (DagBlockHeader, DagBlockHeader) {
    let mut h1 = cabecera_evidencia(&ev.id1, 0);
    let mut h2;
    let quiere_menor = ev.id1.ph < ev.id2.ph;
    let mut sal = 0u64;
    loop {
        h2 = cabecera_evidencia(&ev.id2, sal);
        let menor = h1.pre_hash().as_bytes() < h2.pre_hash().as_bytes();
        if menor == quiere_menor {
            break;
        }
        sal += 1;
    }
    for (cab, h) in [(&ev.id1, &mut h1), (&ev.id2, &mut h2)] {
        if cab.sello_ok {
            let sk = firmante_de(cab.clave);
            let firma: [u8; 64] = sk.sign(h.pre_hash().as_bytes()).into();
            h.sello = firma;
        } else {
            h.sello = [0u8; 64];
        }
    }
    (h1, h2)
}

/// Bloques reales de un caso, con la correspondencia hash ↔ id abstracto.
struct Reales {
    bloques: Vec<BloqueTransicion>,
    hash_a_id: BTreeMap<BlockHash, u64>,
    id_a_idx: BTreeMap<u64, usize>,
    claves: Claves,
}

fn construir_caso(caso: &Caso) -> Result<Reales, String> {
    let mut constructor = Constructor::nuevo(CBID_RED_DEV);
    let mut bloques = Vec::with_capacity(caso.bloques.len());
    let mut hash_a_id = BTreeMap::new();
    let mut id_a_idx = BTreeMap::new();
    for (idx, b) in caso.bloques.iter().enumerate() {
        let productor = b.prod;
        let mut txs = Vec::with_capacity(b.txs.len());
        for tx in &b.txs {
            txs.push(constructor.construir_tx(tx, productor, b.altura, b.slot)?);
        }
        let hash = hash_de(b.id);
        let hechos = match b.fam.as_str() {
            "Genesis" => HechosCabecera::Genesis { hash },
            "PoW" => HechosCabecera::PoW {
                hash,
                padre: hash_de(b.padre),
                altura: b.altura,
                trabajo: U256::from(b.trabajo),
                pow_valido: b.pow_ok,
            },
            "PoST" => HechosCabecera::PoST {
                hash,
                padre: hash_de(b.padre),
                slot: b.slot,
                productor: constructor.claves.id(productor),
                peso: u128::from(b.peso),
                prueba_valida: b.pow_ok,
                requisito_declarado: b.reqdecl,
            },
            otra => return Err(format!("familia desconocida: {otra}")),
        };
        let bloque = match b.fam.as_str() {
            "PoST" => {
                BloqueTransicion::con_cabecera_post(hechos, txs, cabecera_post(hash_de(b.padre)))
            }
            _ => BloqueTransicion::nuevo(hechos, txs),
        };
        hash_a_id.insert(hash, b.id);
        id_a_idx.insert(b.id, idx);
        bloques.push(bloque);
    }
    let claves = constructor.claves;
    Ok(Reales {
        bloques,
        hash_a_id,
        id_a_idx,
        claves,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Render canónico traducido a claves abstractas
// ─────────────────────────────────────────────────────────────────────────────

fn orden_origen(origen: Origen) -> u8 {
    match origen {
        Origen::CoinbasePow => 0,
        Origen::Tx => 1,
        Origen::Liberacion => 2,
    }
}

fn nombre_fase(fase: Fase) -> &'static str {
    match fase {
        Fase::Genesis => "FaseGenesis",
        Fase::PoW => "FasePoW",
        Fase::PoST => "FasePoST",
    }
}

/// Clave `(dueño, valor, origen, altura, slot)` del render de UTXO del oráculo.
type ClaveUtxo = (u64, u64, u8, i64, i64);

fn utxo_engine(estado: &Estado, claves: &Claves) -> Result<Vec<ClaveUtxo>, String> {
    let mut v = Vec::with_capacity(estado.utxo.len());
    for (op, e) in &estado.utxo {
        let dueno = match &e.lock {
            Lock::PubKey { pubkey } => claves
                .abstracta(pubkey)
                .ok_or_else(|| format!("clave desconocida en salida {op:?}"))?,
            otro => return Err(format!("lock inesperado en UTXO: {otro:?}")),
        };
        let (altura, slot) = match e.creada {
            Punto::Altura(h) => (i64::from(h), -1),
            Punto::Slot(s) => (-1, s as i64),
        };
        v.push((
            dueno,
            u64::try_from(e.valor.brek()).unwrap_or(0),
            orden_origen(e.origen),
            altura,
            slot,
        ));
    }
    v.sort_unstable();
    Ok(v)
}

fn parse_utxo_linea(linea: &str) -> ClaveUtxo {
    let c = campos(linea);
    let altura = c.get("altura").expect("altura");
    let slot = c.get("slot").expect("slot");
    let origen = match c.get("origen").expect("origen").as_str() {
        "CoinbasePow" => 0,
        "Tx" => 1,
        _ => 2,
    };
    (
        c.get("dueño").expect("dueño").parse().expect("dueño"),
        c.get("valor").expect("valor").parse().expect("valor"),
        origen,
        if altura == "-" {
            -1
        } else {
            altura.parse().expect("altura")
        },
        if slot == "-" {
            -1
        } else {
            slot.parse().expect("slot")
        },
    )
}

fn render_gar(claves: &Claves, estado: &Estado) -> Result<Vec<(u64, String)>, String> {
    let mut lineas = Vec::new();
    for (pk, g) in &estado.garantias {
        let clave = claves
            .abstracta(pk)
            .ok_or_else(|| format!("clave desconocida en garantía {pk:?}"))?;
        let mut pendientes = g.pendientes.clone();
        pendientes.sort_by_key(|p| (p.importe, p.madura_en_altura, p.madura_en_slot));
        let ps = pendientes
            .iter()
            .map(|p| match p.madura_en_altura {
                Some(h) => format!("{}@h{}", p.importe.brek(), h),
                None => format!("{}@s{}", p.importe.brek(), p.madura_en_slot.unwrap_or(0)),
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut retiradas = g.en_retirada.clone();
        retiradas.sort_by_key(|r| (r.inicio_slot, r.importe));
        let rs = retiradas
            .iter()
            .map(|r| format!("{}@s{}", r.importe.brek(), r.inicio_slot))
            .collect::<Vec<_>>()
            .join(",");
        let mut creditos = g.creditos.clone();
        creditos.sort_by_key(|p| (p.importe, p.madura_en_slot));
        let cs = creditos
            .iter()
            .map(|p| format!("{}@s{}", p.importe.brek(), p.madura_en_slot.unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(",");
        let inc = if g.incidentes.is_empty() {
            String::new()
        } else {
            let lista = g
                .incidentes
                .iter()
                .map(|i| {
                    let mut hex = String::with_capacity(64);
                    for b in &i.id {
                        let _ = write!(hex, "{b:02x}");
                    }
                    format!("{hex}@{}", i.slot_falta)
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(" inc={lista}")
        };
        lineas.push((
            clave,
            format!(
                "GAR clave={clave} activo={} pend=[{ps}] ret=[{rs}] cred=[{cs}] congelado={} nonce={}{inc}",
                g.activo.brek(),
                g.congelado.brek(),
                g.nonce_siguiente
            ),
        ));
    }
    lineas.sort_by_key(|(k, _)| *k);
    Ok(lineas)
}

// ─────────────────────────────────────────────────────────────────────────────
// Ejecución diferencial
// ─────────────────────────────────────────────────────────────────────────────

/// Normaliza el `incident_id` de una línea `GAR`: el id es **opaco**, así que se compara su número
/// y su `@slot_falta`, no el hex (ver `DEFINICIONES-FALTANTES.md` FD-1). Se ordenan los slots para
/// que la comparación no dependa del orden del id del motor.
fn normalizar_gar(linea: &str) -> String {
    let Some(pos) = linea.find(" inc=") else {
        return linea.to_string();
    };
    let (pref, inc) = linea.split_at(pos + 5);
    let mut slots: Vec<&str> = inc
        .split(',')
        .map(|item| item.split('@').nth(1).unwrap_or(""))
        .collect();
    slots.sort_unstable();
    format!("{pref}{}", slots.join(","))
}

/// Nombre aceptado para un error del motor frente al esperado del fichero (§4).
fn coincide(esperado: &str, error: &ErrorTransicion) -> bool {
    if let ErrorTransicion::ErrForma(ErrorFormaTx::VersionInactiva { .. }) = error {
        return esperado == "ErrOperacionFase" || esperado == "ErrFueraDeAlcanceV0";
    }
    error.nombre_t01() == esperado
}

fn inc_cov(cov: &mut BTreeMap<String, usize>, k: &str) {
    *cov.entry(k.to_string()).or_insert(0) += 1;
}

/// Reproduce `contar_cobertura` del oráculo T01 (`exportar.jl:298-358`) sobre el `memo` del BFS.
///
/// SL-4c: además de los contadores de v0.4, reproduce los subtipos de la forma v4:
/// `ambos` (cbid ajeno + orden no canónico en la primera evidencia, gana el cbid) y
/// `orden_igual`/`orden_descendente` (solo cuando el error es `OrdenCanonicoInvalido`).
fn contar_cobertura(
    caso: &Caso,
    reales: &Reales,
    params: &ParametrosTransicion,
    evp: &ParametrosEvidencia,
    memo: &BTreeMap<u64, Estado>,
    cov: &mut BTreeMap<String, usize>,
) {
    if !caso.param.evp {
        return;
    }
    for (i, b) in caso.bloques.iter().enumerate() {
        let Some((idx, txev)) = b
            .txs
            .iter()
            .enumerate()
            .find(|(_, t)| t.tipo == "Evidencia")
        else {
            continue;
        };
        let ep = memo.get(&b.padre);
        if memo.contains_key(&b.id) {
            let Some(ev) = txev.ev else {
                inc_cov(cov, "malformada");
                continue;
            };
            let v = ep
                .and_then(|e| e.garantias.get(&clave_de(ev.id1.clave)))
                .map_or(0, zx_consensus::transicion::total_garantia);
            inc_cov(cov, if v == 0 { "sin_saldo" } else { "aplicada" });
            if let Some(ep) = ep
                && let Ok((e2, undo)) =
                    aplicar_con_undo(ep, &reales.bloques[i], params, CBID_RED_DEV, evp)
                && deshacer(&e2, &undo) == *ep
            {
                inc_cov(cov, "deshecha");
            }
        } else if ep.is_none() {
            inc_cov(cov, "sin_padre");
        } else if let Some(ep) = ep {
            // Forma v4 de la **primera** evidencia del bloque (la que el oráculo mira): sus dos
            // defectos de forma, calculados sobre las cabeceras reales.
            let (cbid_ajeno, orden_malo, orden_igual) = if txev.ev.is_some() {
                match reales
                    .bloques
                    .get(i)
                    .and_then(|bl| bl.txs.get(idx))
                    .map(|(t, _)| t)
                {
                    Some(Tx {
                        extension: ExtensionTx::Evidencia { h1, h2 },
                        ..
                    }) => {
                        let ph1 = h1.pre_hash();
                        let ph2 = h2.pre_hash();
                        let o1 = ph1.as_bytes();
                        let o2 = ph2.as_bytes();
                        (
                            h1.consensus_branch_id != evp.cbid
                                || h2.consensus_branch_id != evp.cbid,
                            !(o1 < o2),
                            o1 == o2,
                        )
                    }
                    _ => (false, false, false),
                }
            } else {
                (false, false, false)
            };
            if cbid_ajeno && orden_malo {
                inc_cov(cov, "ambos");
            }
            let nombre = match aplicar_con_undo(ep, &reales.bloques[i], params, CBID_RED_DEV, evp) {
                Ok(_) => "otro_error",
                Err(e) => match e.nombre_t01() {
                    "ErrEvidenciaDuplicada" => "duplicada",
                    "ErrEvidenciaTardia" => "tardia",
                    "ErrForma(EvidenciaCbidAjeno)" => "cbid_ajeno",
                    "ErrForma(OrdenCanonicoInvalido)" => "orden_canonico",
                    "ErrSinEvidencia" => "sin_evidencia",
                    "ErrForma(EvidenciaConEntradasOSalidas)" => "con_entradas",
                    "ErrPuertaRAT3" => "puerta_rat3",
                    _ => "otro_error",
                },
            };
            inc_cov(cov, nombre);
            if nombre == "orden_canonico" && txev.ev.is_some() {
                inc_cov(
                    cov,
                    if orden_igual {
                        "orden_igual"
                    } else {
                        "orden_descendente"
                    },
                );
            }
        }
    }
}

/// TX-2b: ¿el caso pertenece a las familias nuevas (TXL-01/TXL-02/DEP-FEE)?
fn es_caso_tx2a(nombre: &str) -> bool {
    nombre.starts_with("tx-limite")
        || nombre.starts_with("cuerpo-limite")
        || nombre.starts_with("dep-fee")
        || nombre == "coinbase-excede"
}

/// Cobertura de las familias TX-2a/TX-2b/TX-2c, contada como `contar_cobertura_tx2a` de
/// `exportar.jl`: por nombre, `estricto`/`fusion`, `aplicado`/`rechazado`, la clase de error y
/// `I1_true` en los aceptados. Se cuenta desde el **vector** (el resultado esperado es el del
/// propio caso), lo que mantiene los contadores independientes de la traducción al motor
/// (`FD-TX2c-4`).
fn contar_cobertura_tx2a(caso: &Caso, cov: &mut BTreeMap<String, usize>) {
    if !es_caso_tx2a(&caso.nombre) {
        return;
    }
    inc_cov(cov, &caso.nombre);
    inc_cov(
        cov,
        if caso.param.fusion {
            "fusion"
        } else {
            "estricto"
        },
    );
    let ultimo = caso.bloques.last().map_or(0, |b| b.id);
    let esperado = caso.res.get(&ultimo).cloned().unwrap_or_default();
    if esperado == "OK" {
        inc_cov(cov, "aplicado");
        inc_cov(cov, "I1_true");
    } else {
        inc_cov(cov, "rechazado");
        let saneado: String = esperado
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        inc_cov(cov, &format!("err_{saneado}"));
    }
}

/// Bloque cuyo límite TXL se sustituye por el tamaño **real** medido (`ACLARACION-TX2b.md` §1).
struct LimiteBorde {
    /// Índice del bloque descrito dentro de `reales.bloques`.
    bloque: usize,
    /// `max_tx_bytes` del vector.
    max_tx_bytes: u64,
    /// `max_cuerpo_bloque_bytes` del vector.
    max_cuerpo_bloque_bytes: u64,
}

/// Localiza el bloque que describe un vector TXL-01/TXL-02 y mide el tamaño real de su
/// transacción o de su cuerpo. `None` para las demás familias.
fn limite_borde(caso: &Caso, reales: &Reales) -> Option<LimiteBorde> {
    let nombre = caso.nombre.as_str();
    let es_mas1 = nombre.contains("mas1");
    if nombre.starts_with("tx-limite") {
        let objetivo = if es_mas1 {
            caso.param.max_tx_bytes + 1
        } else {
            caso.param.max_tx_bytes
        };
        for (bi, b) in caso.bloques.iter().enumerate() {
            for (ti, t) in b.txs.iter().enumerate() {
                if t.bytes != objetivo {
                    continue;
                }
                let (tx, testigos) = reales.bloques.get(bi)?.txs.get(ti)?;
                let mut buf = Vec::new();
                tx_a_bytes(&mut buf, tx, testigos);
                let real = buf.len() as u64;
                let max_tx_bytes = if es_mas1 {
                    real.saturating_sub(1)
                } else {
                    real
                };
                return Some(LimiteBorde {
                    bloque: bi,
                    max_tx_bytes,
                    max_cuerpo_bloque_bytes: caso.param.max_cuerpo_bloque_bytes,
                });
            }
        }
        return None;
    }
    if nombre.starts_with("cuerpo-limite") {
        let mut mejor: Option<(usize, u64)> = None;
        for (bi, b) in caso.bloques.iter().enumerate() {
            let suma: u64 = b.txs.iter().map(|t| t.bytes).sum();
            if mejor.is_none_or(|(_, s)| suma > s) {
                mejor = Some((bi, suma));
            }
        }
        let (bi, _) = mejor?;
        let bloque = reales.bloques.get(bi)?;
        let mut buf = Vec::new();
        let mut total: u64 = 0;
        for (tx, testigos) in &bloque.txs {
            buf.clear();
            tx_a_bytes(&mut buf, tx, testigos);
            total = total.checked_add(buf.len() as u64)?;
        }
        let max_cuerpo_bloque_bytes = if es_mas1 {
            total.saturating_sub(1)
        } else {
            total
        };
        return Some(LimiteBorde {
            bloque: bi,
            max_tx_bytes: caso.param.max_tx_bytes,
            max_cuerpo_bloque_bytes,
        });
    }
    None
}

/// `ParametrosTransicion` del caso; el bloque descrito usa el límite real medido.
fn parametros_del_bloque(
    p: &ParamCrudo,
    limite: &Option<LimiteBorde>,
    indice: usize,
) -> ParametrosTransicion {
    match limite {
        Some(l) if l.bloque == indice => parametros(p, l.max_tx_bytes, l.max_cuerpo_bloque_bytes),
        _ => parametros(p, p.max_tx_bytes, p.max_cuerpo_bloque_bytes),
    }
}

/// TX-2c · punto propio de un bloque abstracto para `aplicar_fusion`: `Slot` en PoST y `Altura`
/// en el resto (el PoW se rechaza antes de usarlo, ED-1).
fn punto_de(b: &BloqueCrudo) -> Punto {
    if b.fam == "PoST" {
        Punto::Slot(b.slot)
    } else {
        Punto::Altura(b.altura)
    }
}

/// RET-1a · Estado inicial del diferencial T01. Los vectores T01 no conocen `R_V`: se neutraliza
/// `r_votos_slots` (0) para que el diferencial siga comparando solo las reglas del oráculo.
fn estado_inicial_t01() -> Estado {
    let mut e = Estado::inicial();
    e.parametros_sector.r_votos_slots = 0;
    e
}

fn ejecutar_caso(caso: &Caso, discrepancias: &mut Vec<String>, cov: &mut BTreeMap<String, usize>) {
    let params_base = parametros(
        &caso.param,
        caso.param.max_tx_bytes,
        caso.param.max_cuerpo_bloque_bytes,
    );
    let evp = parametros_evidencia(&caso.param);
    let reales = match construir_caso(caso) {
        Ok(r) => r,
        Err(e) => {
            discrepancias.push(format!("CASO {}: construcción: {e}", caso.n));
            return;
        }
    };
    // TX-2b: el bloque descrito por un vector TXL-01/TXL-02 lleva el límite medido de verdad.
    let limite = limite_borde(caso, &reales);

    // TX-2c · modo fusión: la hoja del caso se traduce con `aplicar_fusion`; el resto de la
    // historia es contexto estricto (FD-TX2a-R-1). Se retira el canal de excepción de TX-2b.
    if caso.param.fusion {
        ejecutar_caso_fusion(caso, &reales, &limite, discrepancias, cov);
        return;
    }

    let inicial = estado_inicial_t01();
    // BFS sobre los padres abstractos (el génesis no lleva padre en los hechos reales).
    let mut memo: BTreeMap<u64, Estado> = BTreeMap::new();
    if let Some(gi) = caso.bloques.iter().position(|b| b.fam == "Genesis")
        && let Some(bloque) = reales.bloques.get(gi)
    {
        let params_gi = parametros_del_bloque(&caso.param, &limite, gi);
        if let Ok((e, _)) = aplicar_con_undo(&inicial, bloque, &params_gi, CBID_RED_DEV, &evp) {
            memo.insert(caso.bloques[gi].id, e);
        }
    }
    let mut cola: VecDeque<u64> = memo.keys().copied().collect();
    while let Some(pid) = cola.pop_front() {
        let Some(estado_padre) = memo.get(&pid).cloned() else {
            continue;
        };
        for (i, b) in caso.bloques.iter().enumerate() {
            if b.padre != pid || memo.contains_key(&b.id) {
                continue;
            }
            let Some(bloque) = reales.bloques.get(i) else {
                continue;
            };
            let params_i = parametros_del_bloque(&caso.param, &limite, i);
            if let Ok((nuevo, undo)) =
                aplicar_con_undo(&estado_padre, bloque, &params_i, CBID_RED_DEV, &evp)
            {
                if deshacer(&nuevo, &undo) != estado_padre {
                    discrepancias.push(format!("CASO {} undo bloque {}", caso.n, b.id));
                }
                memo.insert(b.id, nuevo);
                cola.push_back(b.id);
            }
        }
    }
    // RES por bloque.
    for (i, b) in caso.bloques.iter().enumerate() {
        let esperado = caso.res.get(&b.id).cloned().unwrap_or_default();
        let padre_conocido = reales.id_a_idx.contains_key(&b.padre);
        let Some(bloque) = reales.bloques.get(i) else {
            continue;
        };
        let params_i = parametros_del_bloque(&caso.param, &limite, i);
        let fallo = if memo.contains_key(&b.id) {
            esperado != "OK"
        } else if !padre_conocido || !memo.contains_key(&b.padre) {
            esperado != "ErrSinPadre"
        } else {
            let estado_padre = memo
                .get(&b.padre)
                .cloned()
                .unwrap_or_else(estado_inicial_t01);
            match aplicar_con_undo(&estado_padre, bloque, &params_i, CBID_RED_DEV, &evp) {
                Ok(_) => esperado != "OK",
                Err(e) => !coincide(&esperado, &e),
            }
        };
        if fallo {
            let obtenido = if memo.contains_key(&b.id) {
                "OK".to_string()
            } else if !padre_conocido || !memo.contains_key(&b.padre) {
                "ErrSinPadre".to_string()
            } else {
                let estado_padre = memo
                    .get(&b.padre)
                    .cloned()
                    .unwrap_or_else(estado_inicial_t01);
                match aplicar_con_undo(&estado_padre, bloque, &params_i, CBID_RED_DEV, &evp) {
                    Ok(_) => "OK".to_string(),
                    Err(e) => e.nombre_t01().to_string(),
                }
            };
            discrepancias.push(format!(
                "CASO {} ({}) bloque {} RES esperado={esperado} obtenido={obtenido}",
                caso.n, caso.nombre, b.id
            ));
        }
    }
    contar_cobertura(caso, &reales, &params_base, &evp, &memo, cov);
    contar_cobertura_tx2a(caso, cov);
    // SEL. Para los vectores TXL, el bloque descrito se aplica con el límite medido; si el motor lo
    // rechaza (`mas1`), se excluye de la selección, como hace el oráculo.
    let mut bloques_sel = reales.bloques.clone();
    if let Some(l) = &limite
        && let Some(b) = caso.bloques.get(l.bloque)
        && !memo.contains_key(&b.id)
    {
        bloques_sel.remove(l.bloque);
    }
    let seleccion = match seleccionar_con_inicial(
        &estado_inicial_t01(),
        &bloques_sel,
        &params_base,
        CBID_RED_DEV,
        &evp,
    ) {
        Ok(s) => s,
        Err(e) => {
            discrepancias.push(format!("CASO {}: seleccionar: {e:?}", caso.n));
            return;
        }
    };
    let punta_id = seleccion
        .punta
        .and_then(|h| reales.hash_a_id.get(&h).copied())
        .map_or(-1, |id| id as i64);
    if punta_id != caso.sel {
        discrepancias.push(format!(
            "CASO {} ({}) SEL esperado={} obtenido={punta_id}",
            caso.n, caso.nombre, caso.sel
        ));
    }
    // UTXO.
    let mut esperado_utxo: Vec<ClaveUtxo> = caso.utxo.iter().map(|l| parse_utxo_linea(l)).collect();
    esperado_utxo.sort_unstable();
    match utxo_engine(&seleccion.estado, &reales.claves) {
        Ok(obtenido) => {
            if obtenido != esperado_utxo {
                discrepancias.push(format!(
                    "CASO {} ({}) UTXO esperado={:?} obtenido={:?}",
                    caso.n, caso.nombre, esperado_utxo, obtenido
                ));
            }
        }
        Err(e) => discrepancias.push(format!("CASO {} UTXO: {e}", caso.n)),
    }
    // GAR.
    match render_gar(&reales.claves, &seleccion.estado) {
        Ok(obtenido) => {
            let obtenido: Vec<String> = obtenido.into_iter().map(|(_, l)| l).collect();
            let esperado_n: Vec<String> = caso.gar.iter().map(|l| normalizar_gar(l)).collect();
            let obtenido_n: Vec<String> = obtenido.iter().map(|l| normalizar_gar(l)).collect();
            if obtenido_n != esperado_n {
                discrepancias.push(format!(
                    "CASO {} ({}) GAR esperado={:?} obtenido={:?}",
                    caso.n, caso.nombre, caso.gar, obtenido
                ));
            }
        }
        Err(e) => discrepancias.push(format!("CASO {} GAR: {e}", caso.n)),
    }
    // EST.
    let terminal = seleccion
        .estado
        .terminal
        .and_then(|h| reales.hash_a_id.get(&h).copied())
        .map_or(-1, |id| id as i64);
    let est = format!(
        "EST emitido={} quemado={} fase={} terminal={terminal} altura={} slot={} peso_sufijo={}",
        seleccion.estado.emitido,
        seleccion.estado.quemado,
        nombre_fase(seleccion.estado.fase),
        seleccion.estado.altura,
        seleccion.estado.slot,
        seleccion.estado.peso_sufijo
    );
    if est != caso.est {
        discrepancias.push(format!(
            "CASO {} ({}) EST esperado={} obtenido={est}",
            caso.n, caso.nombre, caso.est
        ));
    }
    // X-16: independencia del orden de entrega.
    if caso.nombre == "X-16" && reales.bloques.len() > 1 {
        let mut invertidos = reales.bloques.clone();
        invertidos.reverse();
        if let Ok(inv) = seleccionar_con_inicial(
            &estado_inicial_t01(),
            &invertidos,
            &params_base,
            CBID_RED_DEV,
            &evp,
        ) && (inv.punta != seleccion.punta || inv.estado != seleccion.estado)
        {
            discrepancias.push(format!("CASO {} X-16 orden inverso difiere", caso.n));
        }
    }
}

/// TX-2c · caso en modo fusión (v0.6.1).
///
/// El bloque **objeto** es la hoja del caso (`FD-TX2c-1`); el resto de la historia es contexto
/// estricto. Se computa el prefijo con `seleccionar` y la hoja con `aplicar_fusion` sobre el
/// estado de su padre (`FD-TX2c-3`): un PoW da `ErrOperacionFase` (`ED-1`) y un PoST se fusiona. Se
/// comparan `RES` por bloque, `SEL`, `UTXO`, `GAR` y `EST` como en el camino estricto, y se cuentan
/// los contadores TX-2a desde el vector (`FD-TX2c-4`).
fn ejecutar_caso_fusion(
    caso: &Caso,
    reales: &Reales,
    limite: &Option<LimiteBorde>,
    discrepancias: &mut Vec<String>,
    cov: &mut BTreeMap<String, usize>,
) {
    contar_cobertura_tx2a(caso, cov);
    let Some(hoja_idx) = caso.bloques.len().checked_sub(1) else {
        discrepancias.push(format!(
            "CASO {} ({}): caso en fusión sin bloques",
            caso.n, caso.nombre
        ));
        return;
    };
    let params_base = parametros(
        &caso.param,
        caso.param.max_tx_bytes,
        caso.param.max_cuerpo_bloque_bytes,
    );
    let params_hoja = parametros_del_bloque(&caso.param, limite, hoja_idx);
    let evp = parametros_evidencia(&caso.param);
    // Prefijo estricto: todos los bloques menos la hoja (`FD-TX2a-R-1`).
    let prefijo: Vec<BloqueTransicion> = reales.bloques[..hoja_idx].to_vec();
    let seleccion_prefijo = match seleccionar_con_inicial(
        &estado_inicial_t01(),
        &prefijo,
        &params_base,
        CBID_RED_DEV,
        &evp,
    ) {
        Ok(s) => s,
        Err(e) => {
            discrepancias.push(format!(
                "CASO {} ({}): seleccionar prefijo: {e:?}",
                caso.n, caso.nombre
            ));
            return;
        }
    };
    // Estados de los bloques válidos del prefijo, por id abstracto.
    let mut memo: BTreeMap<u64, Estado> = BTreeMap::new();
    for (hash, estado) in &seleccion_prefijo.validos {
        if let Some(id) = reales.hash_a_id.get(hash) {
            memo.insert(*id, estado.clone());
        }
    }
    let hoja = &caso.bloques[hoja_idx];
    // La hoja se aplica en fusión sobre el estado de su padre (si es válido). RI-1a #1:
    // `aplicar_fusion` no suma `peso_sufijo`; lo suma quien aplica, como `zx-cadena`
    // (`cadena.rs:813-827`). La hoja es el bloque de cadena del caso, así que el arnés lo suma.
    let resultado_hoja: Option<Result<Estado, ErrorTransicion>> =
        memo.get(&hoja.padre).map(|estado_padre| {
            let (mut estado, _undo, _descartadas) = aplicar_fusion(
                estado_padre,
                &reales.bloques[hoja_idx],
                punto_de(hoja),
                &params_hoja,
                CBID_RED_DEV,
                &evp,
            )?;
            estado.peso_sufijo = estado
                .peso_sufijo
                .checked_add(u128::from(hoja.peso))
                .ok_or(ErrorTransicion::ErrDesbordamiento)?;
            Ok(estado)
        });
    // RES por bloque: prefijo estricto + hoja en fusión.
    for (i, b) in caso.bloques.iter().enumerate() {
        let esperado = caso.res.get(&b.id).cloned().unwrap_or_default();
        let (fallo, obtenido) = if i == hoja_idx {
            match resultado_hoja.as_ref() {
                None => (esperado != "ErrSinPadre", "ErrSinPadre".to_string()),
                Some(Ok(_)) => (esperado != "OK", "OK".to_string()),
                Some(Err(e)) => (!coincide(&esperado, e), e.nombre_t01().to_string()),
            }
        } else if memo.contains_key(&b.id) {
            (esperado != "OK", "OK".to_string())
        } else if let Some(estado_padre) = memo.get(&b.padre) {
            match aplicar_con_undo(
                estado_padre,
                &reales.bloques[i],
                &params_base,
                CBID_RED_DEV,
                &evp,
            ) {
                Ok(_) => (esperado != "OK", "OK".to_string()),
                Err(e) => (!coincide(&esperado, &e), e.nombre_t01().to_string()),
            }
        } else {
            (esperado != "ErrSinPadre", "ErrSinPadre".to_string())
        };
        if fallo {
            discrepancias.push(format!(
                "CASO {} ({}) bloque {} RES esperado={esperado} obtenido={obtenido}",
                caso.n, caso.nombre, b.id
            ));
        }
    }
    // Estado final y punta FC-3: la hoja si se fusiona; si no, la punta del prefijo.
    let (estado_final, punta_id) = match resultado_hoja.as_ref() {
        Some(Ok(estado)) => (estado.clone(), hoja.id as i64),
        _ => {
            let punta = seleccion_prefijo
                .punta
                .and_then(|h| reales.hash_a_id.get(&h).copied())
                .map_or(-1, |id| id as i64);
            (seleccion_prefijo.estado.clone(), punta)
        }
    };
    if punta_id != caso.sel {
        discrepancias.push(format!(
            "CASO {} ({}) SEL esperado={} obtenido={punta_id}",
            caso.n, caso.nombre, caso.sel
        ));
    }
    // UTXO.
    let mut esperado_utxo: Vec<ClaveUtxo> = caso.utxo.iter().map(|l| parse_utxo_linea(l)).collect();
    esperado_utxo.sort_unstable();
    match utxo_engine(&estado_final, &reales.claves) {
        Ok(obtenido) => {
            if obtenido != esperado_utxo {
                discrepancias.push(format!(
                    "CASO {} ({}) UTXO esperado={:?} obtenido={:?}",
                    caso.n, caso.nombre, esperado_utxo, obtenido
                ));
            }
        }
        Err(e) => discrepancias.push(format!("CASO {} UTXO: {e}", caso.n)),
    }
    // GAR.
    match render_gar(&reales.claves, &estado_final) {
        Ok(obtenido) => {
            let obtenido: Vec<String> = obtenido.into_iter().map(|(_, l)| l).collect();
            let esperado_n: Vec<String> = caso.gar.iter().map(|l| normalizar_gar(l)).collect();
            let obtenido_n: Vec<String> = obtenido.iter().map(|l| normalizar_gar(l)).collect();
            if obtenido_n != esperado_n {
                discrepancias.push(format!(
                    "CASO {} ({}) GAR esperado={:?} obtenido={:?}",
                    caso.n, caso.nombre, caso.gar, obtenido
                ));
            }
        }
        Err(e) => discrepancias.push(format!("CASO {} GAR: {e}", caso.n)),
    }
    // EST.
    let terminal = estado_final
        .terminal
        .and_then(|h| reales.hash_a_id.get(&h).copied())
        .map_or(-1, |id| id as i64);
    let est = format!(
        "EST emitido={} quemado={} fase={} terminal={terminal} altura={} slot={} peso_sufijo={}",
        estado_final.emitido,
        estado_final.quemado,
        nombre_fase(estado_final.fase),
        estado_final.altura,
        estado_final.slot,
        estado_final.peso_sufijo
    );
    if est != caso.est {
        discrepancias.push(format!(
            "CASO {} ({}) EST esperado={} obtenido={est}",
            caso.n, caso.nombre, caso.est
        ));
    }
}

fn cargar_casos(ruta: &str) -> Vec<Caso> {
    let casos = parsear_fichero(ruta);
    assert!(!casos.is_empty(), "no se leyeron casos de {ruta}");
    casos
}

/// Corre el diferencial sobre `casos` y devuelve `(informe, nº de discrepancias, cobertura)`.
fn correr_diferencial(casos: &[Caso]) -> (String, usize, BTreeMap<String, usize>) {
    let mut discrepancias: Vec<String> = Vec::new();
    let mut por_nombre: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut con_post = 0usize;
    let mut por_error: BTreeMap<String, usize> = BTreeMap::new();
    let mut cov: BTreeMap<String, usize> = BTreeMap::new();
    for caso in casos {
        let antes = discrepancias.len();
        ejecutar_caso(caso, &mut discrepancias, &mut cov);
        let fallo = discrepancias.len() > antes;
        let entrada = por_nombre.entry(caso.nombre.clone()).or_insert((0, 0));
        entrada.0 += 1;
        if fallo {
            entrada.1 += 1;
        }
        if caso.est.contains("fase=FasePoST") {
            con_post += 1;
        }
        for res in caso.res.values() {
            *por_error.entry(res.clone()).or_insert(0) += 1;
        }
    }
    let mut informe = String::new();
    let _ = writeln!(informe, "casos leidos      = {}", casos.len());
    let _ = writeln!(informe, "con sufijo PoST   = {con_post}");
    let _ = writeln!(informe, "discrepancias     = {}", discrepancias.len());
    let _ = writeln!(informe, "RES por error esperado:");
    for (error, n) in &por_error {
        let _ = writeln!(informe, "  {error}: {n}");
    }
    let _ = writeln!(informe, "por nombre de caso:");
    for (nombre, (n, fallos)) in &por_nombre {
        let _ = writeln!(informe, "  {nombre}: {n} casos, {fallos} con discrepancia");
    }
    for d in discrepancias.iter().take(40) {
        let _ = writeln!(informe, "  {d}");
    }
    (informe, discrepancias.len(), cov)
}

/// Lee los contadores de `cobertura-v0.6.1.txt` (líneas `clave = valor`).
fn cargar_cobertura() -> BTreeMap<String, usize> {
    let contenido = fs::read_to_string(RUTA_COBERTURA).expect("leer cobertura");
    let mut mapa = BTreeMap::new();
    for linea in contenido.lines() {
        if linea.starts_with('#') || linea.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = linea.split_once('=') {
            mapa.insert(k.trim().to_string(), v.trim().parse().expect("contador"));
        }
    }
    mapa
}

/// V4: diferencial completo contra el oráculo T01 (`vectores-transicion-v0.6.1.txt`, 3 230 casos)
/// y tabla de cobertura **idéntica** a `cobertura-v0.6.1.txt`. Los casos de fusión se traducen al
/// motor (`aplicar_fusion` para la hoja, estricto para el prefijo) y deben dar **0 discrepancias**.
#[test]
fn diferencial_t01() {
    let casos = cargar_casos(RUTA_VECTORES);
    let (informe, n, cov) = correr_diferencial(&casos);
    println!("{informe}");
    let esperada = cargar_cobertura();
    let mut cob_informe = String::new();
    for (k, v) in &cov {
        let _ = writeln!(
            cob_informe,
            "  {k} = {v} (esperado {})",
            esperada.get(k).copied().unwrap_or(0)
        );
    }
    assert!(
        n == 0,
        "diferencial T01 v0.6.1 con {n} discrepancias:\n{informe}"
    );
    assert_eq!(
        cov, esperada,
        "cobertura T01 distinta de cobertura-v0.6.1.txt:\n{cob_informe}"
    );
}

/// V4: diferencial contra los negativos de T01-E (`…-negativos-v0.2.txt`, 3 914 casos), incluidos
/// los de repetición (`ErrNonce`).
#[test]
fn diferencial_t01_negativos() {
    let casos = cargar_casos(RUTA_NEGATIVOS);
    let (informe, n, _) = correr_diferencial(&casos);
    println!("{informe}");
    assert!(
        n == 0,
        "diferencial T01 (negativos) con {n} discrepancias:\n{informe}"
    );
}
