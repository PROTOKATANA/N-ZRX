//! Arnés **diferencial** contra el oráculo T04 (`ORDEN-SL4a`, V4 y V5).
//!
//! Lee `testdata/estado-dag-v0.6/vectores-estado-dag-v0.6.txt`, deriva claves Ed25519 deterministas
//! por clave abstracta (`semilla = SHA3-256("zx-t01-clave" ‖ k u64 LE)`, igual que W03), construye
//! transacciones **reales** v1/v2/v3/v4 firmadas por el `firmante` abstracto, traduce cada bloque a
//! [`BloqueCadena`] con `padres`, `sr`, `sd`, `ident` y `k` y ejecuta [`Cadena`] en el orden de
//! entrega del fichero.
//!
//! La `EvidenceTx` v4 se traduce a **dos cabeceras `PoAS_PoT_DAG` reales** con sellos Ed25519
//! reales; el `incident_id` es opaco (se compara número y `@slot_falta`, FD-1).
//!
//! Compara, por caso: `RES` de cada bloque, `DESC` (transacción descartada y motivo), `SEL`, `UTXO`,
//! `GAR` y `EST`. V4 exige **0 discrepancias** en los 2 108 casos; V5 exige que la tabla de
//! cobertura (vectores aleatorios, evidencia y forma v4) sea idéntica a
//! `cobertura-v0.6.txt` (la sección `run.jl` no se reproduce desde el fichero de vectores).

#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio test"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;

use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena, Descarte, MotivoBloque};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, HechosCabecera, ParametrosEvidencia, ParametrosTransicion,
    total_garantia,
};
use zx_consensus::transicion::{ErrorTransicion, Origen, Punto};
use zx_core::preimage::tx::txid as calcular_txid;
use zx_core::{
    Amount, BlockHash, BodyCommitment, CBID_RED_DEV, ClavePublica, DagBlockHeader, Digest,
    ErrorFormaTx, ExtensionTx, HashType, Lock, MerkleRoot, OutPoint, PadresDag, SolucionPoas,
    SpentOutput, TipoGarantia, Tx, TxId, TxIn, TxOut,
};
use zx_dag::IdentidadGhostdag;

/// Vectores v0.6 dentro del workspace (`ws/testdata/...`).
const RUTA_VECTORES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/estado-dag-v0.6/vectores-estado-dag-v0.6.txt"
);
/// Tabla de cobertura esperada de T04.
const RUTA_COBERTURA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/estado-dag-v0.6/cobertura-v0.6.txt"
);
/// Máximo de padres del generador de T04, declarado (`ORDEN-W06a-C` decisión 1): sus vectores no
/// admiten más de 3 y la identidad viaja como `u64` de fixture (`IdentidadGhostdag::de_fixture`).
/// Es el **único** consumidor de ese dominio: la ruta de producción usa la tupla real.
const MAX_PADRES_ARNES: u8 = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Claves y salidas abstractas
// ─────────────────────────────────────────────────────────────────────────────

fn firmante_de(k: u64) -> SigningKey {
    let mut mensaje = b"zx-t01-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    SigningKey::from(*digest.as_bytes())
}

fn clave_de(k: u64) -> ClavePublica {
    let sk = firmante_de(k);
    let vk = VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

/// Hash de bloque sintético con el **mismo** mapeo que GDR-v0.2/T04: el terminal es `"T"` y cada
/// bloque es `"B<id>"`, en ASCII rellenado a 32 bytes por la derecha (`hash_de_id` de `modelo.jl`).
/// El orden de bytes de esos hashes es el que decide los empates de GHOSTDAG (`C-GD-03`/`C-GD-05`).
fn hash_abstracto(id: u64, terminal_id: Option<u64>) -> BlockHash {
    if Some(id) == terminal_id {
        zx_dag::hash_de_id_textual("T")
    } else {
        zx_dag::hash_de_id_textual(&format!("B{id}"))
    }
}

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

#[derive(Clone, Copy)]
struct SalidaRef {
    op: OutPoint,
    valor: Amount,
    dueno: u64,
}

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

fn campos(linea: &str) -> BTreeMap<String, String> {
    let mut mapa = BTreeMap::new();
    for token in linea.split_whitespace().skip(1) {
        if let Some((k, v)) = token.split_once('=') {
            mapa.insert(k.to_string(), v.to_string());
        }
    }
    mapa
}

fn desnudar(texto: &str) -> &str {
    texto
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("")
}

fn parse_lista_u64(texto: &str) -> Vec<u64> {
    let dentro = desnudar(texto);
    if dentro.is_empty() {
        return Vec::new();
    }
    dentro
        .split(',')
        .map(|x| x.parse().expect("entero"))
        .collect()
}

fn parse_salidas(texto: &str) -> Vec<(u64, u64, u64)> {
    let dentro = desnudar(texto);
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

#[derive(Clone, Debug)]
struct TxCrudo {
    tipo: String,
    firmante: u64,
    clave: u64,
    importe: u64,
    ent: Vec<u64>,
    sal: Vec<(u64, u64, u64)>,
    nonce: u64,
    /// SL-4a: evidencia abstracta de una `EvidenceTx` v4.
    ev: Option<EvCrudo>,
}

/// Una cabecera abstracta de evidencia (`ev=` de T04).
///
/// `slot` es `i64`: el generador de evidencia tardía de T04 produce slots negativos.
#[derive(Clone, Copy, Debug)]
struct EvCab {
    cbid: u32,
    clave: u64,
    sector: u16,
    historia: u64,
    chunk: u64,
    slot: i64,
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
    let mut ids = [EvCab {
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
        ids[j] = EvCab {
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
        id1: ids[0],
        id2: ids[1],
    }
}

#[derive(Clone, Debug)]
struct BloqueCrudo {
    id: u64,
    fam: String,
    padres: Vec<u64>,
    altura: u32,
    trabajo: u64,
    pow_ok: bool,
    slot: u64,
    prod: u64,
    peso: u64,
    sr: u64,
    sd: u64,
    ident: u64,
    reqdecl: u64,
    txs: Vec<TxCrudo>,
}

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
    k: u32,
    f_num: u64,
    f_den: u64,
    plazo_slots: u64,
    m_margen_slots: u64,
    cbid: u32,
    evp: bool,
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
            k: 0,
            f_num: 1,
            f_den: 1,
            plazo_slots: 0,
            m_margen_slots: 0,
            cbid: 0,
            evp: false,
        }
    }
}

#[derive(Debug)]
struct Caso {
    n: u64,
    nombre: String,
    param: ParamCrudo,
    bloques: Vec<BloqueCrudo>,
    res: BTreeMap<u64, String>,
    desc: Vec<(u64, u64, String)>,
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
        k: c.get("k").expect("k").parse().expect("k"),
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
                    desc: Vec::new(),
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
                    padres: parse_lista_u64(c.get("padres").expect("padres")),
                    altura: c.get("altura").expect("altura").parse().expect("altura"),
                    trabajo: c.get("trabajo").expect("trabajo").parse().expect("trabajo"),
                    pow_ok: c.get("pow_ok").expect("pow_ok") == "1",
                    slot: c.get("slot").expect("slot").parse().expect("slot"),
                    prod: c.get("prod").expect("prod").parse().expect("prod"),
                    peso: c.get("peso").expect("peso").parse().expect("peso"),
                    sr: c.get("sr").expect("sr").parse().expect("sr"),
                    sd: c.get("sd").expect("sd").parse().expect("sd"),
                    ident: c.get("ident").expect("ident").parse().expect("ident"),
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
                        ent: parse_lista_u64(c.get("ent").expect("ent")),
                        sal: parse_salidas(c.get("sal").expect("sal")),
                        nonce: c.get("nonce").map_or(0, |v| v.parse().expect("nonce")),
                        ev: c.get("ev").map(|v| parsear_evidencia(v)),
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
            "DESC" => {
                let c = campos(linea);
                if let Some(caso) = caso.as_mut() {
                    caso.desc.push((
                        c.get("bloque").expect("bloque").parse().expect("bloque"),
                        c.get("tx").expect("tx").parse().expect("tx"),
                        c.get("motivo").expect("motivo").clone(),
                    ));
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

fn parametros(p: &ParamCrudo) -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: p.h_dep,
        m_cb: p.m_cb,
        m_dep: p.m_dep,
        h_corte_min: p.h_corte_min,
        w_min: U256::from(p.w_min),
        s_min: Amount::nuevo(p.s_min as i64).expect("S_min"),
        q: Amount::nuevo(p.q as i64).expect("q"),
        k_min: p.k_min,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
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

/// Cabecera `PoAS_PoT_DAG` real con la identidad abstracta `cab` y una sal.
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
        slot: cab.slot as u64,
        pot_output: [0u8; 16],
        rango_solucion: cab.ph,
        sol,
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0u8; 32])),
        padres: PadresDag::genesis(),
        sello: [0u8; 64],
    }
}

/// Traduce la evidencia abstracta a dos cabeceras reales con sellos Ed25519 reales.
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
            let digest: zx_core::SigHash =
                zx_core::sighash(tx, &gastadas, HashType::All, i, self.cbid).expect("sighash");
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
                // El formato real `OutPoint = (txid, índice)` no distingue dos transferencias
                // abstractas con el mismo contenido (mismos prevouts y mismas salidas en
                // valor/dueño) pero distinto id de salida, y el oráculo sí (sus ids son únicos).
                // Se fija `sequence` (campo que el motor no interpreta) con el id abstracto de la
                // primera salida para que el `txid` real sea inyectivo en el contenido abstracto.
                let secuencia = tx.sal.first().map_or(0, |(id, _, _)| *id);
                let secuencia = u32::try_from(secuencia)
                    .map_err(|_| "id abstracto fuera de u32 para sequence".to_string())?;
                for input in &mut inputs {
                    input.sequence = secuencia;
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
                        slot,
                    },
                };
                (real, Vec::new())
            }
            "Evidencia" => {
                let Some(ev) = tx.ev else {
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
                let _ = self.claves.id(ev.id1.clave);
                let _ = self.claves.id(ev.id2.clave);
                let (h1, h2) = cabeceras_de_evidencia(&ev);
                // SL-4c-O-C: el modelo abstracto lleva `ent`/`sal` también en la evidencia; la
                // forma v4 (`EV-04`) los rechaza, así que la `Tx` real debe conservarlos.
                let mut inputs = Vec::with_capacity(tx.ent.len());
                for id in &tx.ent {
                    inputs.push(self.txin(*id));
                }
                let salidas = self.salidas_reales(&tx.sal);
                let real = Tx {
                    version: 4,
                    inputs,
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

struct Reales {
    bloques: Vec<BloqueCadena>,
    hash_a_id: BTreeMap<BlockHash, u64>,
    hash_a_idx: BTreeMap<BlockHash, usize>,
    claves: Claves,
}

fn construir_reales(caso: &Caso) -> Result<Reales, String> {
    // El terminal es el padre del primer bloque PoST; su id abstracto se mapea a `"T"`.
    let terminal_id = caso
        .bloques
        .iter()
        .find(|b| b.fam == "PoST")
        .and_then(|b| b.padres.first().copied());
    let h = |id: u64| hash_abstracto(id, terminal_id);
    let mut constructor = Constructor::nuevo(CBID_RED_DEV);
    let mut bloques = Vec::with_capacity(caso.bloques.len());
    let mut hash_a_id = BTreeMap::new();
    let mut hash_a_idx = BTreeMap::new();
    for (idx, b) in caso.bloques.iter().enumerate() {
        let productor = b.prod;
        let mut txs = Vec::with_capacity(b.txs.len());
        for tx in &b.txs {
            txs.push(constructor.construir_tx(tx, productor, b.altura, b.slot)?);
        }
        let hash = h(b.id);
        let bloque = match b.fam.as_str() {
            "Genesis" => BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::Genesis { hash },
                txs,
            )),
            "PoW" => {
                let padre = h(*b.padres.first().ok_or("PoW sin padre")?);
                BloqueCadena::Pow(BloqueTransicion::nuevo(
                    HechosCabecera::PoW {
                        hash,
                        padre,
                        altura: b.altura,
                        trabajo: U256::from(b.trabajo),
                        pow_valido: b.pow_ok,
                    },
                    txs,
                ))
            }
            "PoST" => BloqueCadena::Post(BloquePost {
                hash,
                padres: b.padres.iter().map(|p| h(*p)).collect(),
                slot: b.slot,
                timestamp: 0,
                productor: constructor.claves.id(productor),
                peso: u128::from(b.peso),
                prueba_valida: b.pow_ok,
                requisito_declarado: b.reqdecl,
                sr: b.sr,
                distancia: b.sd,
                identidad: IdentidadGhostdag::de_fixture(b.ident),
                txs,
            }),
            otra => return Err(format!("familia desconocida: {otra}")),
        };
        hash_a_id.insert(hash, b.id);
        hash_a_idx.insert(hash, idx);
        bloques.push(bloque);
    }
    let claves = constructor.claves;
    Ok(Reales {
        bloques,
        hash_a_id,
        hash_a_idx,
        claves,
    })
}

/// RET-1a/RET-1b · Estado inicial del diferencial T04. Los vectores T04 no conocen el plazo de
/// retención por votos (`R_V`): se neutraliza `r_votos_slots` (0) para comparar solo las reglas del
/// oráculo, igual que `estado_inicial_t01` del diferencial T01
/// (`zx-consensus/tests/diferencial_t01.rs`).
fn estado_inicial_t04() -> Estado {
    let mut e = Estado::inicial();
    e.parametros_sector.r_votos_slots = 0;
    e
}

/// Caso resuelto: bloques reales, cadena admitida, estado de la historia, orden y descartes.
type Resuelto = (Reales, Cadena, Estado, Vec<BlockHash>, Vec<Descarte>);

/// Construye los bloques reales una sola vez y aplica la historia. Con F-18 no hay colisión de ids
/// que exija un punto fijo: la salida de cada liberación se traduce a su `(txid, 0)` real por
/// contenido.
///
/// `FIN-1`: el oráculo T04 **no** modela la cota de finalidad `R1` (decisión 3 de `ORDEN-FIN1`:
/// «solo en la selección del nodo»), así que el diferencial corre el motor de DAG puro con
/// [`Cadena::sin_finalidad_dag`]. Con la cota activa, los casos cuya reorganización supera `F`
/// divergen del oráculo por diseño; eso lo cubren `finalidad_fin1.rs` y V4.
fn construir_y_resolver(caso: &Caso) -> Result<Resuelto, String> {
    let params = parametros(&caso.param);
    let reales = construir_reales(caso)?;
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params,
        caso.param.k,
        CBID_RED_DEV,
        MAX_PADRES_ARNES,
        parametros_evidencia(&caso.param),
        estado_inicial_t04(),
    )
    .sin_finalidad_dag();
    for bloque in &reales.bloques {
        let _ = cadena.admitir(bloque.clone());
    }
    let (estado, orden, desc) = cadena
        .aplicar_historia()
        .map_err(|motivo| motivo.nombre().to_string())?;
    Ok((reales, cadena, estado, orden, desc))
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

fn render_gar(claves: &Claves, estado: &Estado) -> Result<Vec<String>, String> {
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
        lineas.push(format!(
            "GAR clave={clave} activo={} pend=[{ps}] ret=[{rs}] cred=[{cs}] congelado={} nonce={}{inc}",
            g.activo.brek(),
            g.congelado.brek(),
            g.nonce_siguiente
        ));
    }
    lineas.sort();
    Ok(lineas)
}

/// Normaliza el `incident_id` de una línea `GAR` (id opaco; ver FD-1). El orden de los incidentes
/// es el del id del motor, que no coincide con el del oráculo, así que se compara el **multiconjunto**
/// de `@slot_falta`.
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

// ─────────────────────────────────────────────────────────────────────────────
// Tabla de cobertura (V4b)
// ─────────────────────────────────────────────────────────────────────────────

const TIPOS_COBERTURA: [&str; 4] = ["Transferencia", "Deposito", "Retiro", "Liberacion"];
const TIPOS_GARANTIA: [&str; 3] = ["Deposito", "Retiro", "Liberacion"];
const MOTIVOS_COBERTURA: [&str; 8] = [
    "ErrNonce",
    "ErrDobleGasto",
    "ErrSaldo",
    "ErrRetiroPendiente",
    "ErrAutorizacion",
    "ErrInmaduro",
    "ErrOperacionFase",
    "ErrEmision",
];

#[derive(Default)]
struct Cobertura {
    construidas: BTreeMap<String, u64>,
    aplicadas: BTreeMap<String, u64>,
    descartes: BTreeMap<String, BTreeMap<String, u64>>,
    reorgs: u64,
    casos: u64,
    /// SL-4a · contadores `EV ...` de la sección de evidencia.
    ev: BTreeMap<String, u64>,
    /// SL-4c · contadores `FORMA ...` de la sección de forma v4.
    forma: BTreeMap<String, u64>,
}

fn tipo_cobertura(tx: &Tx) -> Option<&'static str> {
    match &tx.extension {
        ExtensionTx::Garantia {
            tipo: TipoGarantia::Deposito,
            ..
        } => Some("Deposito"),
        ExtensionTx::Garantia {
            tipo: TipoGarantia::Retiro,
            ..
        } => Some("Retiro"),
        ExtensionTx::Garantia {
            tipo: TipoGarantia::Liberacion,
            ..
        } => Some("Liberacion"),
        _ if tx.version == 1 && !tx.inputs.is_empty() => Some("Transferencia"),
        _ => None,
    }
}

fn es_garantia(tx: &Tx) -> bool {
    matches!(tx.extension, ExtensionTx::Garantia { .. })
}

fn operaciones_garantia_aplicadas(cadena: &Cadena) -> BTreeSet<(BlockHash, usize)> {
    let Ok((_estado, orden, desc)) = cadena.aplicar_historia() else {
        return BTreeSet::new();
    };
    let descartadas: BTreeSet<(BlockHash, usize)> =
        desc.iter().map(|d| (d.bloque, d.indice)).collect();
    let mut ops = BTreeSet::new();
    for hash in orden {
        if let Some(bloque) = cadena.bloque(&hash) {
            for (i, (tx, _)) in bloque.txs().iter().enumerate() {
                if es_garantia(tx) && !descartadas.contains(&(hash, i)) {
                    ops.insert((hash, i));
                }
            }
        }
    }
    ops
}

fn reorgs_que_deshacen_garantia(
    reales: &Reales,
    params: ParametrosTransicion,
    k: u32,
    evp: ParametrosEvidencia,
) -> u64 {
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params,
        k,
        CBID_RED_DEV,
        MAX_PADRES_ARNES,
        evp,
        estado_inicial_t04(),
    )
    .sin_finalidad_dag();
    let mut prev_tip: Option<BlockHash> = None;
    let mut prev_ops: BTreeSet<(BlockHash, usize)> = BTreeSet::new();
    let mut reorgs = 0u64;
    for bloque in &reales.bloques {
        let _ = cadena.admitir(bloque.clone());
        if !matches!(bloque, BloqueCadena::Post(_)) {
            continue;
        }
        let tip = cadena.mejor_punta();
        if tip == prev_tip {
            continue;
        }
        let ops = operaciones_garantia_aplicadas(&cadena);
        if !prev_ops.is_subset(&ops) {
            reorgs += 1;
        }
        prev_tip = tip;
        prev_ops = ops;
    }
    reorgs
}

/// ¿La transacción es una `EvidenceTx` v4 (bien formada o no)?
fn es_evidencia(tx: &Tx) -> bool {
    tx.version == 4
}

/// Pares `(bloque, índice)` de evidencia aplicada en la historia seleccionada (ED-*).
fn evidencias_aplicadas(cadena: &Cadena) -> BTreeSet<(BlockHash, usize)> {
    let Ok((_estado, orden, desc)) = cadena.aplicar_historia() else {
        return BTreeSet::new();
    };
    let descartadas: BTreeSet<(BlockHash, usize)> =
        desc.iter().map(|d| (d.bloque, d.indice)).collect();
    let mut set = BTreeSet::new();
    for hash in orden {
        let Some(bloque) = cadena.bloque(&hash) else {
            continue;
        };
        for (i, (tx, _)) in bloque.txs().iter().enumerate() {
            if es_evidencia(tx) && !descartadas.contains(&(hash, i)) {
                set.insert((hash, i));
            }
        }
    }
    set
}

/// Evidencias aplicadas en alguna historia seleccionada y luego retiradas por una reorganización
/// (`EV-27`/`EV-28`), contadas como conjunto (igual que `evidencias_deshechas_por_reorg`).
fn evidencias_deshechas_por_reorg(
    reales: &Reales,
    params: ParametrosTransicion,
    k: u32,
    evp: ParametrosEvidencia,
) -> u64 {
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params,
        k,
        CBID_RED_DEV,
        MAX_PADRES_ARNES,
        evp,
        estado_inicial_t04(),
    )
    .sin_finalidad_dag();
    let mut prev_tip: Option<BlockHash> = None;
    let mut prev_ev: BTreeSet<(BlockHash, usize)> = BTreeSet::new();
    let mut perdidas: BTreeSet<(BlockHash, usize)> = BTreeSet::new();
    for bloque in &reales.bloques {
        let _ = cadena.admitir(bloque.clone());
        if !matches!(bloque, BloqueCadena::Post(_)) {
            continue;
        }
        let Some(tip) = cadena.mejor_punta() else {
            continue;
        };
        // El oráculo recalcula el conjunto **tras cada bloque**; solo compara al cambiar la punta.
        let ev = evidencias_aplicadas(&cadena);
        if Some(tip) != prev_tip {
            for p in prev_ev.difference(&ev) {
                perdidas.insert(*p);
            }
        }
        prev_tip = Some(tip);
        prev_ev = ev;
    }
    perdidas.len() as u64
}

/// Reproduce `contar_evidencia` del oráculo T04 (`exportar.jl:234-269`).
#[expect(
    clippy::too_many_arguments,
    reason = "el contexto del caso ya viene partido por el arnés"
)]
fn contar_evidencia(
    reales: &Reales,
    cadena: &Cadena,
    orden: &[BlockHash],
    desc: &[Descarte],
    cobertura: &mut Cobertura,
    params: ParametrosTransicion,
    k: u32,
    evp: ParametrosEvidencia,
) {
    let hay_evidencia = reales
        .bloques
        .iter()
        .any(|b| b.txs().iter().any(|(tx, _)| es_evidencia(tx)));
    if !hay_evidencia {
        return;
    }
    let descartadas: BTreeMap<(BlockHash, usize), &ErrorTransicion> = desc
        .iter()
        .map(|d| ((d.bloque, d.indice), &d.motivo))
        .collect();
    for hash in orden {
        let Some(bloque) = cadena.bloque(hash) else {
            continue;
        };
        for (i, (tx, _)) in bloque.txs().iter().enumerate() {
            if !es_evidencia(tx) {
                continue;
            }
            *cobertura.ev.entry("construida".to_string()).or_insert(0) += 1;
            if let Some(motivo) = descartadas.get(&(*hash, i)) {
                // SL-4c: la forma v4 (entradas/salidas, cbid, orden) ya no es descarte semántico;
                // estos nombres completos solo aparecerían si el motor dejara de validar la forma
                // antes, y la cobertura los separa de la sección `FORMA`.
                let nombre = match motivo.nombre_t01() {
                    "ErrEvidenciaDuplicada" => "duplicada",
                    "ErrEvidenciaTardia" => "tardia",
                    "ErrForma(EvidenciaCbidAjeno)" => "cbid_ajeno",
                    "ErrForma(EvidenciaConEntradasOSalidas)" => "con_entradas",
                    "ErrForma(OrdenCanonicoInvalido)" => "orden_canonico",
                    "ErrSinEvidencia" => "sin_evidencia",
                    _ => "otro",
                };
                *cobertura.ev.entry(nombre.to_string()).or_insert(0) += 1;
            } else {
                let ExtensionTx::Evidencia { h1, .. } = &tx.extension else {
                    *cobertura.ev.entry("malformada".to_string()).or_insert(0) += 1;
                    continue;
                };
                let v = cadena
                    .estado_past(hash)
                    .and_then(|e| e.garantias.get(&h1.sol.public_key))
                    .map_or(0, total_garantia);
                let nombre = if v == 0 { "sin_saldo" } else { "aplicada" };
                *cobertura.ev.entry(nombre.to_string()).or_insert(0) += 1;
            }
        }
    }
    let d = evidencias_deshechas_por_reorg(reales, params, k, evp);
    if d > 0 {
        *cobertura.ev.entry("deshecha".to_string()).or_insert(0) += d;
    }
}

/// Primer sub-defecto de **forma v4** de un bloque, en el orden de sus transacciones
/// (`primer_defecto_forma` del oráculo T04, `EstadoDAG.jl:217-232`): estructura →
/// `cbid` → orden canónico. Devuelve `None` si ninguna `EvidenceTx` con cabeceras tiene defecto.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DefectoForma {
    Entradas,
    Salidas,
    EntradasSalidas,
    Cbid,
    OrdenIgual,
    OrdenDesc,
}

fn primer_defecto_forma(bloque: &BloquePost, cbid_local: u32) -> Option<DefectoForma> {
    for (tx, _) in &bloque.txs {
        if tx.version != 4 {
            continue;
        }
        let ExtensionTx::Evidencia { h1, h2 } = &tx.extension else {
            continue;
        };
        let ent = !tx.inputs.is_empty();
        let sal = !tx.outputs.is_empty();
        if ent && sal {
            return Some(DefectoForma::EntradasSalidas);
        }
        if ent {
            return Some(DefectoForma::Entradas);
        }
        if sal {
            return Some(DefectoForma::Salidas);
        }
        if h1.consensus_branch_id != cbid_local || h2.consensus_branch_id != cbid_local {
            return Some(DefectoForma::Cbid);
        }
        let ph1 = h1.pre_hash();
        let ph2 = h2.pre_hash();
        let o1 = ph1.as_bytes();
        let o2 = ph2.as_bytes();
        if !(o1 < o2) {
            return Some(if o1 == o2 {
                DefectoForma::OrdenIgual
            } else {
                DefectoForma::OrdenDesc
            });
        }
    }
    None
}

/// Incrementa un contador solo si `d > 0` (semántica de `max(n, 1)` del oráculo).
fn inc_mapa(mapa: &mut BTreeMap<String, u64>, k: &str, d: u64) {
    if d > 0 {
        *mapa.entry(k.to_string()).or_insert(0) += d;
    }
}

/// Reproduce `contar_forma_evidencia` del oráculo T04 (`exportar.jl:313-377`): recorre **todos**
/// los bloques construidos (válidos o no) y clasifica los que la forma v4 invalida.
fn contar_forma_evidencia(
    reales: &Reales,
    cadena: &Cadena,
    cobertura: &mut Cobertura,
    cbid_local: u32,
) {
    for bloque in &reales.bloques {
        let BloqueCadena::Post(p) = bloque else {
            continue;
        };
        let hash = bloque.hash();
        let Some(motivo) = cadena.motivo(&hash) else {
            continue;
        };
        let es_forma = |f: &ErrorFormaTx| {
            matches!(
                motivo,
                MotivoBloque::ErrTransicion(ErrorTransicion::ErrForma(x)) if x == f
            )
        };
        let hay_tx = p.txs.iter().any(|(tx, _)| tipo_cobertura(tx).is_some());
        let mut n_cbid = 0u64;
        let mut n_orden = 0u64;
        let mut n_ig = 0u64;
        let mut n_de = 0u64;
        let mut n_ent = 0u64;
        let mut n_sal = 0u64;
        let mut n_amb = 0u64;
        let mut n_tres = 0u64;
        for (tx, _) in &p.txs {
            if tx.version != 4 {
                continue;
            }
            let ExtensionTx::Evidencia { h1, h2 } = &tx.extension else {
                continue;
            };
            let c_ent = !tx.inputs.is_empty();
            let c_sal = !tx.outputs.is_empty();
            let c_cbid =
                h1.consensus_branch_id != cbid_local || h2.consensus_branch_id != cbid_local;
            let ph1 = h1.pre_hash();
            let ph2 = h2.pre_hash();
            let o1 = ph1.as_bytes();
            let o2 = ph2.as_bytes();
            let c_orden = !(o1 < o2);
            if c_ent {
                n_ent += 1;
            }
            if c_sal {
                n_sal += 1;
            }
            if c_ent && c_sal {
                n_amb += 1;
            }
            if c_ent && c_cbid && c_orden {
                n_tres += 1;
            }
            if c_cbid {
                n_cbid += 1;
            }
            if c_orden {
                n_orden += 1;
                if o1 == o2 {
                    n_ig += 1;
                } else {
                    n_de += 1;
                }
            }
        }
        if es_forma(&ErrorFormaTx::EvidenciaConEntradasOSalidas) {
            inc_mapa(&mut cobertura.forma, "bloque_estructura", 1);
            if hay_tx {
                inc_mapa(&mut cobertura.forma, "con_tx_estructura", 1);
            }
            match primer_defecto_forma(p, cbid_local) {
                Some(DefectoForma::Entradas) => {
                    inc_mapa(&mut cobertura.forma, "bloque_estructura_entradas", 1);
                }
                Some(DefectoForma::Salidas) => {
                    inc_mapa(&mut cobertura.forma, "bloque_estructura_salidas", 1);
                }
                _ => {
                    inc_mapa(&mut cobertura.forma, "bloque_estructura_ambos", 1);
                }
            }
            if n_tres > 0 {
                inc_mapa(&mut cobertura.forma, "bloque_estructura_cbid_orden", 1);
            }
            inc_mapa(
                &mut cobertura.forma,
                "ev_estructura",
                (n_ent + n_sal).saturating_sub(n_amb).max(1),
            );
        } else if es_forma(&ErrorFormaTx::EvidenciaCbidAjeno) {
            inc_mapa(&mut cobertura.forma, "bloque_cbid", 1);
            inc_mapa(&mut cobertura.forma, "ev_cbid", n_cbid.max(1));
            if hay_tx {
                inc_mapa(&mut cobertura.forma, "con_tx_cbid", 1);
            }
            if n_orden > 0 {
                inc_mapa(&mut cobertura.forma, "ambos_cbid", 1);
            }
        } else if es_forma(&ErrorFormaTx::OrdenCanonicoInvalido) {
            inc_mapa(&mut cobertura.forma, "bloque_orden", 1);
            if hay_tx {
                inc_mapa(&mut cobertura.forma, "con_tx_orden", 1);
            }
            match primer_defecto_forma(p, cbid_local) {
                Some(DefectoForma::OrdenIgual) => {
                    inc_mapa(&mut cobertura.forma, "bloque_orden_igual", 1);
                }
                _ => {
                    inc_mapa(&mut cobertura.forma, "bloque_orden_desc", 1);
                }
            }
            inc_mapa(&mut cobertura.forma, "ev_orden", n_orden.max(1));
            inc_mapa(&mut cobertura.forma, "ev_orden_igual", n_ig);
            inc_mapa(&mut cobertura.forma, "ev_orden_desc", n_de);
        }
    }
}

fn acumular_caso(
    cobertura: &mut Cobertura,
    reales: &Reales,
    orden: &[BlockHash],
    desc: &[Descarte],
    params: ParametrosTransicion,
    k: u32,
    evp: ParametrosEvidencia,
) {
    for bloque in &reales.bloques {
        if let BloqueCadena::Post(p) = bloque {
            for (tx, _) in &p.txs {
                if let Some(t) = tipo_cobertura(tx) {
                    *cobertura.construidas.entry(t.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    let descartadas: BTreeMap<(BlockHash, usize), &ErrorTransicion> = desc
        .iter()
        .map(|d| ((d.bloque, d.indice), &d.motivo))
        .collect();
    for hash in orden {
        let Some(idx) = reales.hash_a_idx.get(hash).copied() else {
            continue;
        };
        let Some(bloque) = reales.bloques.get(idx) else {
            continue;
        };
        for (i, (tx, _)) in bloque.txs().iter().enumerate() {
            let Some(t) = tipo_cobertura(tx) else {
                continue;
            };
            if let Some(motivo) = descartadas.get(&(*hash, i)) {
                *cobertura
                    .descartes
                    .entry(t.to_string())
                    .or_default()
                    .entry(motivo.nombre_t01().to_string())
                    .or_insert(0) += 1;
            } else {
                *cobertura.aplicadas.entry(t.to_string()).or_insert(0) += 1;
            }
        }
    }
    cobertura.reorgs += reorgs_que_deshacen_garantia(reales, params, k, evp);
    cobertura.casos += 1;
}

fn valor(mapa: &BTreeMap<String, u64>, clave: &str) -> u64 {
    mapa.get(clave).copied().unwrap_or(0)
}

fn generar_lineas(c: &Cobertura) -> Vec<String> {
    let mut out = Vec::new();
    out.push("SECCION vectores-v0.6 (casos aleatorios)".to_string());
    out.push(format!("casos = {}", c.casos));
    for t in TIPOS_COBERTURA {
        let desc_t = c.descartes.get(t);
        let dtot: u64 = desc_t.map(|m| m.values().sum()).unwrap_or(0);
        let motivos = MOTIVOS_COBERTURA
            .iter()
            .map(|m| {
                format!(
                    "{m}={}",
                    desc_t.and_then(|d| d.get(*m)).copied().unwrap_or(0)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let conocidos: u64 = MOTIVOS_COBERTURA
            .iter()
            .map(|m| desc_t.and_then(|d| d.get(*m)).copied().unwrap_or(0))
            .sum();
        let aplicadas = valor(&c.aplicadas, t);
        let construidas = valor(&c.construidas, t);
        let evaluadas = aplicadas + dtot;
        out.push(format!(
            "TIPO {t} construidas={construidas} aplicadas={aplicadas} descartadas={dtot} evaluadas={evaluadas} en_ramas_no_seleccionadas={} {motivos} otros={}",
            construidas - evaluadas,
            dtot - conocidos
        ));
    }
    let cons_gar: u64 = TIPOS_GARANTIA
        .iter()
        .map(|t| valor(&c.construidas, t))
        .sum();
    let eval_gar: u64 = TIPOS_GARANTIA
        .iter()
        .map(|t| {
            valor(&c.aplicadas, t)
                + c.descartes
                    .get(*t)
                    .map(|m| m.values().sum::<u64>())
                    .unwrap_or(0)
        })
        .sum();
    let errnonce: u64 = TIPOS_GARANTIA
        .iter()
        .map(|t| {
            c.descartes
                .get(*t)
                .and_then(|m| m.get("ErrNonce"))
                .copied()
                .unwrap_or(0)
        })
        .sum();
    let doble: u64 = TIPOS_COBERTURA
        .iter()
        .map(|t| {
            c.descartes
                .get(*t)
                .and_then(|m| m.get("ErrDobleGasto"))
                .copied()
                .unwrap_or(0)
        })
        .sum();
    out.push(format!("garantia_construidas = {cons_gar}"));
    out.push(format!("garantia_evaluadas = {eval_gar}"));
    out.push(format!("garantia_errnonce = {errnonce}"));
    out.push(format!(
        "garantia_errnonce_pct_construidas = {:.2}",
        if cons_gar == 0 {
            0.0
        } else {
            100.0 * errnonce as f64 / cons_gar as f64
        }
    ));
    out.push(format!(
        "garantia_errnonce_pct_evaluadas = {:.2}",
        if eval_gar == 0 {
            0.0
        } else {
            100.0 * errnonce as f64 / eval_gar as f64
        }
    ));
    out.push(format!("err_doble_gasto_total = {doble}"));
    out.push(format!(
        "reorganizaciones_que_deshacen_garantia = {}",
        c.reorgs
    ));
    out.extend(generar_lineas_evidencia(c));
    out.extend(generar_lineas_forma(c));
    out
}

/// Sección `EV ...` de la cobertura de evidencia (orden alfabético como el oráculo).
fn generar_lineas_evidencia(c: &Cobertura) -> Vec<String> {
    let mut out =
        vec!["SECCION evidencia SL-3b/SL-4c-O (dirigidos + aleatorios C-EVP)".to_string()];
    let mut claves: Vec<&String> = c.ev.keys().collect();
    claves.sort();
    for k in claves {
        out.push(format!("EV {k} = {}", c.ev[k]));
    }
    out
}

/// Sección `FORMA ...` de la forma v4, en el orden exacto del oráculo (`exportar.jl:507-513`) y
/// con la línea final `minimos_SL4cO`.
fn generar_lineas_forma(c: &Cobertura) -> Vec<String> {
    const CLAVES: [&str; 18] = [
        "bloque_estructura",
        "bloque_estructura_entradas",
        "bloque_estructura_salidas",
        "bloque_estructura_ambos",
        "bloque_estructura_cbid_orden",
        "ev_estructura",
        "con_tx_estructura",
        "bloque_cbid",
        "bloque_orden",
        "bloque_orden_igual",
        "bloque_orden_desc",
        "ev_cbid",
        "ev_orden",
        "ev_orden_igual",
        "ev_orden_desc",
        "ambos_cbid",
        "con_tx_cbid",
        "con_tx_orden",
    ];
    let v = |k: &str| c.forma.get(k).copied().unwrap_or(0);
    let mut out = vec!["SECCION forma v4 SL-4c-O/SL-4c-O-B/SL-4c-O-C".to_string()];
    for k in CLAVES {
        out.push(format!("FORMA {k} = {}", v(k)));
    }
    let minimos = v("bloque_cbid") >= 30
        && v("bloque_orden") >= 30
        && v("con_tx_cbid") >= 10
        && v("con_tx_orden") >= 10
        && v("ambos_cbid") >= 5
        && v("bloque_orden_desc") >= 10
        && v("bloque_orden_igual") >= 10
        && v("bloque_estructura") >= 30
        && v("con_tx_estructura") >= 10
        && v("bloque_estructura_ambos") >= 5
        && v("bloque_estructura_cbid_orden") >= 5;
    out.push(format!(
        "FORMA minimos_SL4cO = {}",
        if minimos { "OK" } else { "NO" }
    ));
    out
}

fn cobertura_esperada() -> Vec<String> {
    let texto = fs::read_to_string(RUTA_COBERTURA).expect("leer cobertura");
    let mut lineas = Vec::new();
    let mut dentro = false;
    for linea in texto.lines() {
        if linea.starts_with("SECCION vectores-v0.6") {
            dentro = true;
            lineas.push(linea.to_string());
            continue;
        }
        if dentro {
            if linea.starts_with("SECCION run.jl") {
                break;
            }
            lineas.push(linea.to_string());
        }
    }
    lineas
}

// ─────────────────────────────────────────────────────────────────────────────
// Ejecución diferencial
// ─────────────────────────────────────────────────────────────────────────────

fn ejecutar_caso(caso: &Caso, discrepancias: &mut Vec<String>, cobertura: &mut Cobertura) {
    let params = parametros(&caso.param);
    let (reales, cadena, estado, orden, desc) = match construir_y_resolver(caso) {
        Ok(x) => x,
        Err(e) => {
            discrepancias.push(format!("CASO {}: construcción: {e}", caso.n));
            return;
        }
    };
    for bloque in &reales.bloques {
        let hash = bloque.hash();
        let id = reales.hash_a_id.get(&hash).copied().unwrap_or(0);
        let esperado = caso.res.get(&id).cloned().unwrap_or_default();
        let obtenido = if cadena.es_valido(&hash) {
            "OK".to_string()
        } else {
            cadena
                .motivo(&hash)
                .map_or_else(|| "ErrSinPadre".to_string(), |m| m.nombre().to_string())
        };
        if obtenido != esperado {
            discrepancias.push(format!(
                "CASO {} ({}) bloque {} RES esperado={esperado} obtenido={obtenido}",
                caso.n, caso.nombre, id
            ));
        }
    }
    // DESC.
    let obtenido_desc: Vec<(u64, u64, String)> = desc
        .iter()
        .map(|d| {
            (
                reales.hash_a_id.get(&d.bloque).copied().unwrap_or(0),
                d.indice as u64 + 1,
                d.motivo.nombre_t01().to_string(),
            )
        })
        .collect();
    if obtenido_desc != caso.desc {
        discrepancias.push(format!(
            "CASO {} ({}) DESC esperado={:?} obtenido={:?}",
            caso.n, caso.nombre, caso.desc, obtenido_desc
        ));
    }
    // SEL.
    let punta = cadena
        .mejor_punta()
        .and_then(|h| reales.hash_a_id.get(&h).copied())
        .map_or(-1, |id| id as i64);
    if punta != caso.sel {
        discrepancias.push(format!(
            "CASO {} ({}) SEL esperado={} obtenido={punta}",
            caso.n, caso.nombre, caso.sel
        ));
    }
    // UTXO.
    let mut esperado_utxo: Vec<ClaveUtxo> = caso.utxo.iter().map(|l| parse_utxo_linea(l)).collect();
    esperado_utxo.sort_unstable();
    match utxo_engine(&estado, &reales.claves) {
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
    match render_gar(&reales.claves, &estado) {
        Ok(obtenido) => {
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
    let terminal = estado
        .terminal
        .and_then(|h| reales.hash_a_id.get(&h).copied())
        .map_or(-1, |id| id as i64);
    let est = format!(
        "EST emitido={} quemado={} fase={} terminal={terminal} altura={} slot={} peso_sufijo={}",
        estado.emitido,
        estado.quemado,
        nombre_fase(estado.fase),
        estado.altura,
        estado.slot,
        estado.peso_sufijo
    );
    if est != caso.est {
        discrepancias.push(format!(
            "CASO {} ({}) EST esperado={} obtenido={est}",
            caso.n, caso.nombre, caso.est
        ));
    }
    let evp = parametros_evidencia(&caso.param);
    // El oráculo solo alimenta `contar_evidencia` con los dirigidos `D-1*`, los `ev-aleatorio` y
    // los `forma-*` (`exportar.jl:407,436,451`); el resto de dirigidos (p. ej. `D-20`/`D-21`) no
    // cuentan en la sección de evidencia.
    let cuenta_evidencia = caso.nombre.starts_with("D-1")
        || caso.nombre == "ev-aleatorio"
        || caso.nombre.starts_with("forma-");
    if cuenta_evidencia {
        contar_evidencia(
            &reales,
            &cadena,
            &orden,
            &desc,
            cobertura,
            params,
            caso.param.k,
            evp,
        );
    }
    // SL-4c: la forma v4 (los tres errores) se cuenta sobre **todos** los bloques construidos,
    // válidos o no, con el `cbid` local del perfil (`evp.cbid`).
    contar_forma_evidencia(&reales, &cadena, cobertura, evp.cbid);
    if caso.nombre == "aleatorio" {
        acumular_caso(cobertura, &reales, &orden, &desc, params, caso.param.k, evp);
    }
}

fn cargar_casos(ruta: &str) -> Vec<Caso> {
    let casos = parsear_fichero(ruta);
    assert!(!casos.is_empty(), "no se leyeron casos de {ruta}");
    casos
}

fn correr() -> (String, Vec<String>, Vec<String>, Vec<String>) {
    let casos = cargar_casos(RUTA_VECTORES);
    let mut discrepancias: Vec<String> = Vec::new();
    let mut cobertura = Cobertura::default();
    let mut por_nombre: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for caso in &casos {
        let antes = discrepancias.len();
        ejecutar_caso(caso, &mut discrepancias, &mut cobertura);
        let fallo = discrepancias.len() > antes;
        let entrada = por_nombre.entry(caso.nombre.clone()).or_insert((0, 0));
        entrada.0 += 1;
        if fallo {
            entrada.1 += 1;
        }
    }
    let esperado_cob = cobertura_esperada();
    let obtenido_cob = generar_lineas(&cobertura);
    let mut diferencias_cob = Vec::new();
    if esperado_cob.len() != obtenido_cob.len() {
        diferencias_cob.push(format!(
            "longitud de cobertura esperada={} obtenida={}",
            esperado_cob.len(),
            obtenido_cob.len()
        ));
    }
    for (e, o) in esperado_cob.iter().zip(obtenido_cob.iter()) {
        if e != o {
            diferencias_cob.push(format!("esperado={e} obtenido={o}"));
        }
    }
    let mut informe = String::new();
    let _ = writeln!(informe, "casos leidos      = {}", casos.len());
    let _ = writeln!(informe, "discrepancias     = {}", discrepancias.len());
    let _ = writeln!(informe, "por nombre de caso:");
    for (nombre, (n, fallos)) in &por_nombre {
        let _ = writeln!(informe, "  {nombre}: {n} casos, {fallos} con discrepancia");
    }
    for d in discrepancias.iter().take(40) {
        let _ = writeln!(informe, "  {d}");
    }
    let _ = writeln!(informe, "cobertura (tabla del arnés):");
    for l in &obtenido_cob {
        let _ = writeln!(informe, "  {l}");
    }
    (informe, discrepancias, diferencias_cob, obtenido_cob)
}

/// V4 · diferencial completo contra T04 (`vectores-estado-dag-v0.6.txt`, 2 108 casos).
#[test]
fn diferencial_t04() {
    let (informe, discrepancias, diferencias_cob, _cob) = correr();
    println!("{informe}");
    assert!(
        discrepancias.is_empty(),
        "diferencial T04 con {} discrepancias:\n{informe}",
        discrepancias.len()
    );
    assert!(
        diferencias_cob.is_empty(),
        "cobertura V4b con {} diferencias:\n{}",
        diferencias_cob.len(),
        diferencias_cob.join("\n")
    );
}
