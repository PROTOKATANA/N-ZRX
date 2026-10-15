//! PROD-3a · pruebas de equivalencia y coste del ensayo sin copia (`E1`, `E2`, `E4`, `E6a`).
//!
//! Módulo hijo de `cadena` para ver `O1` (el cuerpo original de `ensayar_post`, conservado al pie de
//! la letra como referencia), los campos privados y los generadores copiados de `tests/` (cada
//! archivo de `tests/` es un crate aparte). No toca `nodo.rs`, `regimen.rs` ni `mempool.rs`.

#![expect(clippy::unwrap_used, reason = "pruebas: fallan con panic por diseño")]

use std::time::Instant;

use primitive_types::U256;
use zx_consensus::transicion::{
    BloqueTransicion, EntradaUtxo, Estado, HechoVoto, HechosCabecera, Origen, ParametrosEvidencia,
    ParametrosTransicion, Punto, TxDescartada,
};
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, HashType, Lock,
    OperacionAlmacenamiento, OutPoint, SpentOutput, Tx, TxId, TxIn, TxOut, VotoPesoEvidencia,
};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::{Color, IdentidadGhostdag};

use super::Cadena;
use crate::bloque::{BloqueCadena, BloquePost};
use crate::error::MotivoBloque;

/// Máximo de padres del perfil dev (`PERFIL-DEV-v0.md` §4).
const MAX_PADRES: u8 = 15;

type ResultadoEnsayo = Result<(Estado, Vec<TxDescartada>), MotivoBloque>;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// Parámetros triviales para la puerta de garantía y el corte (`q = S_min = 0`).
fn params() -> ParametrosTransicion {
    params_con(None, Amount::CERO)
}

/// Igual que [`params`] con `f_slots` y `q` explícitos (casos dirigidos).
fn params_con(f_slots: Option<u64>, q: Amount) -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 1,
        w_min: U256::one(),
        s_min: Amount::CERO,
        q,
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 1,
        f_slots,
        subsidio_pow,
        subsidio_post,
    }
}

/// Hash con 2 bytes de variedad (orden lexicográfico == numérico).
fn hash16(n: u16) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[30] = (n >> 8) as u8;
    bytes[31] = (n & 0xff) as u8;
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

/// Hash del generador de propiedades (`[n; 32]`), distinto de [`hash16`].
fn hash8(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn clave(semilla: u8) -> ClavePublica {
    let mensaje = [b"zx-prod3a", &[semilla][..]].concat();
    let digest = zx_core::sha3_256_publico(&mensaje);
    let sk = ed25519_zebra::SigningKey::from(*digest.as_bytes());
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

fn tx_coinbase_post(clave: ClavePublica, importe: i64, slot: u64) -> Tx {
    Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave,
            importe: Amount::nuevo(importe).unwrap(),
            slot,
        },
    }
}

fn genesis() -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash16(0) },
        Vec::new(),
    ))
}

fn pow_terminal(id: u16, trabajo: u64) -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash16(id),
            padre: hash16(0),
            altura: 1,
            trabajo: U256::from(trabajo),
            pow_valido: true,
        },
        Vec::new(),
    ))
}

fn post(
    id: u16,
    padres: Vec<BlockHash>,
    slot: u64,
    sr: u64,
    productor_semilla: u8,
    chunk: u8,
    txs: Vec<(Tx, Vec<Vec<u8>>)>,
) -> BloqueCadena {
    let productor = clave(productor_semilla);
    let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor,
        0,
        u64::from(chunk) + 1,
        [chunk; 32],
        slot,
    ));
    BloqueCadena::Post(BloquePost {
        hash: hash16(id),
        padres,
        slot,
        timestamp: 0,
        productor,
        peso: 1,
        prueba_valida: true,
        requisito_declarado: 0,
        sr,
        distancia: 0,
        identidad,
        txs,
    })
}

fn post_coinbase(
    id: u16,
    padres: Vec<BlockHash>,
    slot: u64,
    sr: u64,
    productor_semilla: u8,
    chunk: u8,
) -> BloqueCadena {
    let productor = clave(productor_semilla);
    let tx = tx_coinbase_post(productor, 1, slot);
    post(
        id,
        padres,
        slot,
        sr,
        productor_semilla,
        chunk,
        vec![(tx, Vec::new())],
    )
}

/// Tx que gasta una salida inexistente: debe salir como descarte (o error de transición).
fn tx_inexistente(id: u8) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: OutPoint {
                prev_txid: TxId::from_digest(Digest::from_bytes([id; 32])),
                prev_index: 0,
            },
            sequence: 0,
        }],
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

/// `n` bloques PoST encadenados desde `terminal`, con pesos iguales (`sr`).
fn suceso_suffix(
    terminal: BlockHash,
    n: usize,
    sr: u64,
    id_base: u16,
    productor_semilla: u8,
) -> (Vec<BloqueCadena>, BlockHash) {
    let mut bloques = Vec::new();
    let mut padre = terminal;
    let mut punta = terminal;
    for i in 0..n {
        let id = id_base + u16::try_from(i).unwrap();
        let slot = i as u64 + 1;
        let b = post_coinbase(id, vec![padre], slot, sr, productor_semilla, i as u8);
        punta = b.hash();
        bloques.push(b);
        padre = punta;
    }
    (bloques, punta)
}

/// Cadena con `n` terminales (trabajo `i*10`), cada uno con un bloque PoST que le da DAG propio.
fn cadena_con_terminales(n: u16) -> (Cadena, Vec<BlockHash>) {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    let mut terminales = Vec::new();
    for i in 1..=n {
        cadena.admitir(pow_terminal(i, u64::from(i) * 10)).unwrap();
        cadena
            .admitir(post_coinbase(
                100 + i,
                vec![hash16(i)],
                1,
                10,
                i as u8,
                i as u8,
            ))
            .unwrap();
        terminales.push(hash16(i));
    }
    (cadena, terminales)
}

// ─────────────────────────── generadores copiados de `tests/` ───────────────────────────────

struct Cursor<'a> {
    datos: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn siguiente(&mut self, n: u32) -> u32 {
        let b = u32::from(self.datos.get(self.pos).copied().unwrap_or(0));
        self.pos = self.pos.wrapping_add(1);
        if n == 0 { 0 } else { b % n }
    }
}

struct Historia {
    bloques: Vec<BloqueCadena>,
}

/// Copia del generador de `tests/propiedades.rs` (`generar`, `:112`), autoconsistente en `hash8`.
fn generar(entropia: &[u8]) -> Historia {
    let mut cursor = Cursor {
        datos: entropia,
        pos: 0,
    };
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    let mut bloques = Vec::new();
    let gen_bloque = BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash8(0) },
        Vec::new(),
    ));
    cadena.admitir(gen_bloque.clone()).unwrap();
    bloques.push(gen_bloque);
    let pow = BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash8(1),
            padre: hash8(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        Vec::new(),
    ));
    cadena.admitir(pow.clone()).unwrap();
    bloques.push(pow);

    let productor = clave(1);
    let n_post = cursor.siguiente(8);
    let mut posts: Vec<BlockHash> = Vec::new();
    for i in 0..n_post {
        let id = 10 + i as u8;
        let bhash = hash8(id);
        let mut padres: Vec<BlockHash> = if posts.is_empty() {
            vec![hash8(1)]
        } else {
            let max_cuantos = posts.len().min(3) as u32;
            let cuantos = 1 + cursor.siguiente(max_cuantos);
            let mut elegidos = std::collections::BTreeSet::new();
            for _ in 0..cuantos {
                let j = cursor.siguiente(posts.len() as u32) as usize;
                if let Some(h) = posts.get(j) {
                    elegidos.insert(*h);
                }
            }
            if elegidos.is_empty()
                && let Some(h) = posts.last()
            {
                elegidos.insert(*h);
            }
            elegidos.into_iter().collect()
        };
        if padres.is_empty() {
            padres.push(hash8(1));
        }
        let slot_padre = padres
            .iter()
            .filter_map(|h| match cadena.bloque(h) {
                Some(BloqueCadena::Post(p)) => Some(p.slot),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let slot = slot_padre + 1 + u64::from(cursor.siguiente(3));
        let peso = 1 + u128::from(cursor.siguiente(3));
        let importe = 1 + i64::from(cursor.siguiente(3));
        let sr = u64::from(cursor.siguiente(255)) + 1;
        let sd = u64::from(cursor.siguiente(255));
        let tx = tx_coinbase_post(productor, importe, slot);
        let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
            productor,
            0,
            u64::from(i) + 1,
            [i as u8; 32],
            slot,
        ));
        let bloque = BloqueCadena::Post(BloquePost {
            hash: bhash,
            padres,
            slot,
            timestamp: 0,
            productor,
            peso,
            prueba_valida: true,
            requisito_declarado: 0,
            sr,
            distancia: sd,
            identidad,
            txs: vec![(tx, Vec::new())],
        });
        if cadena.admitir(bloque.clone()).is_ok() {
            posts.push(bhash);
            bloques.push(bloque);
        } else {
            break;
        }
    }
    Historia { bloques }
}

// ─────────────────────────── oráculos O1 y O2 ───────────────────────────────

/// **O1** · cuerpo original de `ensayar_post` (`cadena.rs:354` a `:366`), conservado al pie de la
/// letra; es la referencia de «no he cambiado nada».
fn o1_ensayar(cadena: &Cadena, candidata: &BloquePost) -> ResultadoEnsayo {
    if cadena.por_hash.contains_key(&candidata.hash) {
        return Err(MotivoBloque::ErrSinPadre);
    }
    let mut copia = cadena.clone();
    let bloque = BloqueCadena::Post(candidata.clone());
    copia.por_hash.insert(candidata.hash, bloque.clone());
    copia.admitir_post(&bloque)?;
    let estado = copia
        .post
        .remove(&candidata.hash)
        .ok_or(MotivoBloque::ErrSinPadre)?;
    let descartes = copia.descartes.remove(&candidata.hash).unwrap_or_default();
    Ok((estado, descartes))
}

/// **O2** · admisión pública en una copia (`cadena.clone()` + `admitir`).
fn o2_admitir(cadena: &Cadena, candidata: &BloquePost) -> ResultadoEnsayo {
    let mut copia = cadena.clone();
    let bloque = BloqueCadena::Post(candidata.clone());
    let hash = bloque.hash();
    match copia.admitir(bloque) {
        Ok(()) => {
            let estado = copia
                .estado_post(&hash)
                .cloned()
                .ok_or(MotivoBloque::ErrSinPadre)?;
            let descartes = copia
                .descartes(&hash)
                .map(<[TxDescartada]>::to_vec)
                .unwrap_or_default();
            Ok((estado, descartes))
        }
        Err(m) => Err(m),
    }
}

// ─────────────────────────── recuento y comparación ───────────────────────────────

#[derive(Default)]
struct Stats {
    total: usize,
    validos_sin_descartes: usize,
    validos_con_descartes: usize,
    err_garantia: usize,
    err_merge_depth: usize,
    err_limite: usize,
    err_sin_padre: usize,
    err_slot: usize,
    err_emision: usize,
    err_transicion: usize,
    otras: usize,
    rojo_u3: usize,
    rojo_k: usize,
    evid_falta: usize,
    evid_sinfalta: usize,
    evid_mergeset: usize,
    diferencias: Vec<String>,
}

impl Stats {
    fn contar(&mut self, r: &ResultadoEnsayo) {
        self.total += 1;
        match r {
            Ok((_, d)) if d.is_empty() => self.validos_sin_descartes += 1,
            Ok(_) => self.validos_con_descartes += 1,
            Err(MotivoBloque::ErrGarantia) => self.err_garantia += 1,
            Err(MotivoBloque::ErrMergeDepth) => self.err_merge_depth += 1,
            Err(MotivoBloque::ErrLimiteTerminales) => self.err_limite += 1,
            Err(MotivoBloque::ErrSinPadre) => self.err_sin_padre += 1,
            Err(MotivoBloque::ErrSlot) => self.err_slot += 1,
            Err(MotivoBloque::ErrEmision) => self.err_emision += 1,
            Err(MotivoBloque::ErrTransicion(_)) => self.err_transicion += 1,
            Err(_) => self.otras += 1,
        }
    }

    fn imprimir_tabla(&self) {
        println!(
            "E2 total={} sin_descartes={} con_descartes={} err_garantia={} err_merge_depth={} err_limite={} err_sin_padre={} err_slot={} err_emision={} err_transicion={} rojo_u3={} rojo_k={} evid_falta={} evid_sinfalta={} evid_mergeset={} otras={}",
            self.total,
            self.validos_sin_descartes,
            self.validos_con_descartes,
            self.err_garantia,
            self.err_merge_depth,
            self.err_limite,
            self.err_sin_padre,
            self.err_slot,
            self.err_emision,
            self.err_transicion,
            self.rojo_u3,
            self.rojo_k,
            self.evid_falta,
            self.evid_sinfalta,
            self.evid_mergeset,
            self.otras
        );
        for d in &self.diferencias {
            println!("DIFERENCIA_ADMISION {d}");
        }
    }
}

/// Comprueba `nuevo == O1` (debe cumplirse siempre) y anota las diferencias con `O2`.
fn equivalencia(cadena: &Cadena, candidata: &BloquePost, etiqueta: &str, stats: &mut Stats) {
    let nuevo = cadena.ensayar_post(candidata);
    let o1 = o1_ensayar(cadena, candidata);
    assert_eq!(nuevo, o1, "PROD-3a: ensayo nuevo != O1 [{etiqueta}]");
    let o2 = o2_admitir(cadena, candidata);
    if o2 != o1 {
        stats
            .diferencias
            .push(format!("{etiqueta}: O1={o1:?} O2={o2:?}"));
    }
    stats.contar(&o1);
}

// ─────────────────────────── observables de E4 ───────────────────────────────

#[derive(PartialEq, Eq, Debug)]
struct Observables {
    terminal: Option<BlockHash>,
    punta: Option<BlockHash>,
    virtual_estado: Estado,
    terminales_con_dag: Vec<BlockHash>,
    limite: bool,
    finalidad: Option<BlockHash>,
}

fn observables(cadena: &Cadena) -> Observables {
    Observables {
        terminal: cadena.terminal(),
        punta: cadena.mejor_punta(),
        virtual_estado: cadena.estado_virtual().unwrap(),
        terminales_con_dag: cadena.terminales_con_dag(),
        limite: cadena.limite_terminales_alcanzado(),
        finalidad: cadena.punto_finalidad(),
    }
}

// ─────────────────────────── E1 · equivalencia ───────────────────────────────

const ENTROPIAS: &[&[u8]] = &[
    &[
        60, 71, 209, 170, 98, 159, 87, 163, 129, 148, 203, 188, 157, 226, 1, 131, 181, 79, 98, 165,
        134, 138, 102, 63,
    ],
    &[
        66, 47, 197, 20, 128, 26, 35, 242, 206, 70, 114, 179, 182, 95, 26, 207, 189, 222, 118, 234,
        17, 80, 84, 60,
    ],
    &[
        71, 23, 184, 126, 159, 150, 238, 65, 27, 248, 25, 171, 208, 220, 51, 27, 197, 109, 138, 47,
        157, 22, 66, 58,
    ],
    &[
        77, 255, 172, 232, 189, 17, 186, 144, 104, 169, 191, 162, 234, 89, 75, 102, 205, 253, 158,
        116, 40, 220, 47, 55,
    ],
    &[
        82, 231, 159, 82, 219, 141, 133, 223, 181, 91, 102, 153, 4, 214, 100, 178, 213, 140, 178,
        185, 180, 162, 29, 53,
    ],
    &[
        88, 207, 147, 188, 250, 8, 81, 46, 2, 12, 13, 144, 30, 83, 125, 254, 221, 27, 198, 254, 64,
        104, 11, 50,
    ],
    &[
        93, 183, 134, 38, 24, 132, 28, 125, 78, 190, 179, 135, 56, 208, 149, 73, 229, 170, 218, 68,
        203, 46, 249, 48,
    ],
    &[
        99, 159, 122, 144, 54, 255, 232, 203, 155, 111, 90, 126, 82, 78, 174, 149, 237, 57, 238,
        137, 87, 244, 230, 45,
    ],
    &[
        105, 135, 109, 250, 85, 123, 179, 26, 232, 33, 1, 117, 107, 203, 199, 225, 246, 200, 2,
        206, 226, 186, 212, 43,
    ],
    &[
        110, 111, 97, 99, 115, 246, 127, 105, 53, 211, 167, 108, 133, 72, 224, 44, 254, 87, 22, 19,
        110, 128, 194, 40,
    ],
    &[
        116, 88, 84, 205, 145, 114, 74, 184, 130, 132, 78, 100, 159, 197, 248, 120, 6, 230, 42, 88,
        249, 70, 176, 38,
    ],
    &[
        121, 64, 72, 55, 176, 237, 21, 7, 207, 54, 245, 91, 185, 66, 17, 196, 14, 117, 62, 158,
        133, 12, 157, 35,
    ],
    &[
        127, 40, 59, 161, 206, 105, 225, 86, 27, 231, 155, 82, 211, 191, 42, 15, 22, 4, 82, 227,
        16, 211, 139, 33,
    ],
    &[
        133, 16, 47, 11, 236, 229, 172, 165, 104, 153, 66, 73, 237, 60, 66, 91, 30, 148, 102, 40,
        156, 153, 121, 30,
    ],
    &[
        138, 248, 35, 117, 11, 96, 120, 244, 181, 74, 233, 64, 6, 185, 91, 167, 38, 35, 122, 109,
        39, 95, 103, 28,
    ],
    &[
        144, 224, 22, 223, 41, 220, 67, 66, 2, 252, 143, 55, 32, 54, 116, 243, 46, 178, 142, 178,
        179, 37, 84, 25,
    ],
    &[
        149, 200, 10, 73, 71, 87, 15, 145, 79, 174, 54, 46, 58, 179, 140, 62, 55, 65, 162, 248, 62,
        235, 66, 23,
    ],
    &[
        155, 176, 253, 179, 102, 211, 218, 224, 155, 95, 221, 38, 84, 48, 165, 138, 63, 208, 182,
        61, 202, 177, 48, 20,
    ],
    &[
        161, 152, 241, 28, 132, 78, 166, 47, 232, 17, 131, 29, 110, 173, 190, 214, 71, 95, 202,
        130, 85, 119, 30, 18,
    ],
    &[
        166, 128, 228, 134, 163, 202, 113, 126, 53, 194, 42, 20, 136, 42, 215, 33, 79, 238, 222,
        199, 225, 61, 12, 15,
    ],
    &[
        172, 104, 216, 240, 193, 69, 60, 205, 130, 116, 209, 11, 161, 167, 239, 109, 87, 125, 242,
        12, 109, 3, 249, 13,
    ],
    &[
        177, 80, 203, 90, 223, 193, 8, 28, 207, 37, 119, 2, 187, 36, 8, 185, 95, 12, 6, 81, 248,
        201, 231, 10,
    ],
    &[
        183, 56, 191, 196, 254, 60, 211, 107, 28, 215, 30, 249, 213, 162, 33, 4, 103, 155, 26, 151,
        132, 143, 213, 8,
    ],
    &[
        188, 33, 178, 46, 28, 184, 159, 185, 104, 137, 197, 240, 239, 31, 57, 80, 111, 43, 46, 220,
        15, 85, 195, 5,
    ],
    &[
        194, 9, 166, 152, 58, 51, 106, 8, 181, 58, 107, 231, 9, 156, 82, 156, 119, 186, 66, 33,
        155, 27, 176, 2,
    ],
    &[
        200, 241, 153, 2, 89, 175, 54, 87, 2, 236, 18, 223, 35, 25, 107, 231, 128, 73, 86, 102, 38,
        225, 158, 0,
    ],
    &[
        205, 217, 141, 108, 119, 42, 1, 166, 79, 157, 185, 214, 60, 150, 131, 51, 136, 216, 106,
        171, 178, 167, 140, 253,
    ],
    &[
        211, 193, 128, 213, 149, 166, 205, 245, 156, 79, 95, 205, 86, 19, 156, 127, 144, 103, 126,
        241, 61, 109, 122, 251,
    ],
    &[
        216, 169, 116, 63, 180, 33, 152, 68, 232, 0, 6, 196, 112, 144, 181, 202, 152, 246, 146, 54,
        201, 51, 103, 248,
    ],
    &[
        222, 145, 103, 169, 210, 157, 99, 147, 53, 178, 173, 187, 138, 13, 206, 22, 160, 133, 166,
        123, 84, 249, 85, 246,
    ],
    &[
        228, 121, 91, 19, 240, 24, 47, 226, 130, 100, 83, 178, 164, 138, 230, 98, 168, 20, 186,
        192, 224, 191, 67, 243,
    ],
    &[
        233, 97, 78, 125, 15, 148, 250, 48, 207, 21, 250, 169, 190, 7, 255, 173, 176, 163, 206, 5,
        107, 133, 49, 241,
    ],
    &[
        239, 73, 66, 231, 45, 16, 198, 127, 28, 199, 161, 160, 216, 132, 24, 249, 184, 50, 226, 75,
        247, 75, 31, 238,
    ],
    &[
        244, 49, 53, 81, 75, 139, 145, 206, 105, 120, 71, 152, 241, 1, 48, 69, 193, 193, 246, 144,
        130, 17, 12, 236,
    ],
    &[
        250, 25, 41, 187, 106, 7, 93, 29, 181, 42, 238, 143, 11, 126, 73, 144, 201, 81, 11, 213,
        14, 215, 250, 233,
    ],
    &[
        0, 1, 28, 37, 136, 130, 40, 108, 2, 219, 148, 134, 37, 251, 98, 220, 209, 224, 31, 26, 154,
        157, 232, 231,
    ],
    &[
        5, 233, 16, 142, 167, 254, 244, 187, 79, 141, 59, 125, 63, 121, 122, 40, 217, 111, 51, 95,
        37, 99, 214, 228,
    ],
    &[
        11, 210, 3, 248, 197, 121, 191, 10, 156, 63, 226, 116, 89, 246, 147, 116, 225, 254, 71,
        164, 177, 41, 195, 226,
    ],
    &[
        16, 186, 247, 98, 227, 245, 138, 89, 233, 240, 136, 107, 115, 115, 172, 191, 233, 141, 91,
        234, 60, 239, 177, 223,
    ],
    &[
        22, 162, 234, 204, 2, 112, 86, 167, 54, 162, 47, 98, 140, 240, 197, 11, 241, 28, 111, 47,
        200, 181, 159, 221,
    ],
    &[
        27, 138, 222, 54, 32, 236, 33, 246, 130, 83, 214, 90, 166, 109, 221, 87, 249, 171, 131,
        116, 83, 123, 141, 218,
    ],
    &[
        33, 114, 209, 160, 62, 103, 237, 69, 207, 5, 124, 81, 192, 234, 246, 162, 1, 58, 151, 185,
        223, 65, 122, 216,
    ],
    &[
        39, 90, 197, 10, 93, 227, 184, 148, 28, 182, 35, 72, 218, 103, 15, 238, 10, 201, 171, 254,
        106, 7, 104, 213,
    ],
    &[
        44, 66, 184, 116, 123, 94, 132, 227, 105, 104, 202, 63, 244, 228, 39, 58, 18, 88, 191, 68,
        246, 205, 86, 211,
    ],
    &[
        50, 42, 172, 222, 153, 218, 79, 50, 182, 26, 112, 54, 14, 97, 64, 133, 26, 232, 211, 137,
        129, 147, 68, 208,
    ],
    &[
        55, 18, 159, 71, 184, 85, 27, 129, 2, 203, 23, 45, 39, 222, 89, 209, 34, 119, 231, 206, 13,
        89, 50, 206,
    ],
    &[
        61, 250, 147, 177, 214, 209, 230, 208, 79, 125, 190, 36, 65, 91, 114, 29, 42, 6, 251, 19,
        152, 31, 31, 203,
    ],
    &[
        67, 226, 134, 27, 244, 76, 177, 30, 156, 46, 100, 27, 91, 216, 138, 104, 50, 149, 15, 88,
        36, 229, 13, 201,
    ],
    &[
        72, 202, 122, 133, 19, 200, 125, 109, 233, 224, 11, 19, 117, 85, 163, 180, 58, 36, 35, 157,
        176, 172, 251, 198,
    ],
    &[
        78, 178, 110, 239, 49, 67, 72, 188, 54, 145, 178, 10, 143, 210, 188, 0, 66, 179, 55, 227,
        59, 114, 233, 196,
    ],
    &[
        83, 155, 97, 89, 79, 191, 20, 11, 131, 67, 88, 1, 169, 79, 212, 75, 74, 66, 75, 40, 199,
        56, 214, 193,
    ],
    &[
        89, 131, 85, 195, 110, 59, 223, 90, 207, 245, 255, 248, 194, 205, 237, 151, 83, 209, 95,
        109, 82, 254, 196, 191,
    ],
    &[
        95, 107, 72, 45, 140, 182, 171, 169, 28, 166, 166, 239, 220, 74, 6, 227, 91, 96, 115, 178,
        222, 196, 178, 188,
    ],
    &[
        100, 83, 60, 151, 171, 50, 118, 248, 105, 88, 76, 230, 246, 199, 30, 46, 99, 239, 135, 247,
        105, 138, 160, 186,
    ],
    &[
        106, 59, 47, 0, 201, 173, 66, 71, 182, 9, 243, 221, 16, 68, 55, 122, 107, 127, 155, 61,
        245, 80, 141, 183,
    ],
    &[
        111, 35, 35, 106, 231, 41, 13, 149, 3, 187, 154, 212, 42, 193, 80, 198, 115, 14, 175, 130,
        128, 22, 123, 181,
    ],
    &[
        117, 11, 22, 212, 6, 164, 216, 228, 79, 108, 64, 204, 68, 62, 105, 17, 123, 157, 195, 199,
        12, 220, 105, 178,
    ],
    &[
        122, 243, 10, 62, 36, 32, 164, 51, 156, 30, 231, 195, 93, 187, 129, 93, 131, 44, 215, 12,
        151, 162, 87, 176,
    ],
    &[
        128, 219, 253, 168, 66, 155, 111, 130, 233, 208, 142, 186, 119, 56, 154, 169, 139, 187,
        235, 81, 35, 104, 68, 173,
    ],
    &[
        134, 195, 241, 18, 97, 23, 59, 209, 54, 129, 52, 177, 145, 181, 179, 245, 148, 74, 255,
        151, 174, 46, 50, 171,
    ],
    &[
        139, 171, 228, 124, 127, 146, 6, 32, 131, 51, 219, 168, 171, 50, 203, 64, 156, 217, 19,
        220, 58, 244, 32, 168,
    ],
    &[
        145, 147, 216, 230, 157, 14, 210, 111, 208, 228, 130, 159, 197, 175, 228, 140, 164, 104,
        39, 33, 197, 186, 14, 166,
    ],
    &[
        150, 123, 203, 80, 188, 137, 157, 190, 28, 150, 40, 150, 223, 44, 253, 216, 172, 247, 59,
        102, 81, 128, 252, 163,
    ],
    &[
        156, 99, 191, 185, 218, 5, 105, 12, 105, 71, 207, 141, 249, 169, 21, 35, 180, 134, 79, 171,
        221, 70, 233, 161,
    ],
];

#[test]
fn e1_equivalencia_sin_copia() {
    let mut stats = Stats::default();
    for (i, entropia) in ENTROPIAS.iter().enumerate() {
        let h = generar(entropia);
        let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
        for b in &h.bloques {
            if let BloqueCadena::Post(p) = b {
                equivalencia(&cadena, p, &format!("prop-{i}"), &mut stats);
            }
            cadena.admitir(b.clone()).unwrap();
        }
    }
    multiterminal(&mut stats);
    dirigidos(&mut stats);
    validos_con_descartes(&mut stats);
    rojos_en_mergeset(&mut stats);
    evidencia_en_plazo(&mut stats);
    stats.imprimir_tabla();
    println!(
        "E1 total={} o1_o2_diferencias={}",
        stats.total,
        stats.diferencias.len()
    );
    for (nombre, casos) in [
        ("sin_descartes", stats.validos_sin_descartes),
        ("con_descartes", stats.validos_con_descartes),
        ("garantia", stats.err_garantia),
        ("merge_depth", stats.err_merge_depth),
        ("limite", stats.err_limite),
        ("sin_padre", stats.err_sin_padre),
        ("slot", stats.err_slot),
        ("emision", stats.err_emision),
        ("rojo_u3", stats.rojo_u3),
        ("rojo_k", stats.rojo_k),
        ("evid_falta", stats.evid_falta),
        ("evid_sinfalta", stats.evid_sinfalta),
        ("evid_mergeset", stats.evid_mergeset),
    ] {
        assert!(casos > 0, "clase de E2 con cero casos: {nombre}");
    }
}

/// Dos terminales con sufijos y candidatas sobre nodos de ambos.
fn multiterminal(stats: &mut Stats) {
    let ta = hash16(1);
    let tb = hash16(2);
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 10)).unwrap();
    cadena.admitir(pow_terminal(2, 10)).unwrap();
    let (suf_a, punta_a) = suceso_suffix(ta, 6, 5_000, 200, 1);
    let (suf_b, punta_b) = suceso_suffix(tb, 3, 10, 300, 2);
    for b in suf_a.iter().chain(suf_b.iter()) {
        cadena.admitir(b.clone()).unwrap();
    }
    let candidata = match post_coinbase(500, vec![punta_a], 8, 7, 5, 9) {
        BloqueCadena::Post(p) => p,
        BloqueCadena::Pow(_) => return,
    };
    equivalencia(&cadena, &candidata, "multi-a", stats);
    let candidata_b = match post_coinbase(501, vec![punta_b], 4, 7, 5, 10) {
        BloqueCadena::Post(p) => p,
        BloqueCadena::Pow(_) => return,
    };
    equivalencia(&cadena, &candidata_b, "multi-b", stats);
}

/// Extrae la `BloquePost` de una `BloqueCadena::Post`, o `None`.
fn como_post(b: BloqueCadena) -> Option<BloquePost> {
    match b {
        BloqueCadena::Post(p) => Some(p),
        BloqueCadena::Pow(_) => None,
    }
}

/// Casos dirigidos que cubren las clases que el generador no alcanza.
fn dirigidos(stats: &mut Stats) {
    let t1 = hash16(1);
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 10)).unwrap();

    // Forma: ErrSlot.
    if let Some(malo_slot) = como_post(post_coinbase(50, vec![t1], 0, 10, 1, 0)) {
        equivalencia(&cadena, &malo_slot, "dir-slot", stats);
        // Mismo hash ya cacheado como inválido: `por_hash` lo tiene pero el DAG no. Sin la guarda
        // g1 el ensayo volvería a calcular (ErrSlot) en vez de rechazar por `hash` existente.
        assert_eq!(
            cadena.admitir(BloqueCadena::Post(malo_slot.clone())),
            Err(MotivoBloque::ErrSlot)
        );
        equivalencia(&cadena, &malo_slot, "dir-hash-invalido", stats);
    }

    // Forma: ErrEmision (dos coinbases).
    let productor = clave(1);
    let cb1 = (tx_coinbase_post(productor, 1, 1), Vec::new());
    let cb2 = (tx_coinbase_post(productor, 1, 1), Vec::new());
    if let Some(malo_emision) = como_post(post(51, vec![t1], 1, 10, 1, 0, vec![cb1, cb2])) {
        equivalencia(&cadena, &malo_emision, "dir-emision", stats);
    }

    // ErrSinPadre por padre desconocido.
    if let Some(huerfano) = como_post(post_coinbase(52, vec![hash16(9999)], 2, 10, 1, 0)) {
        equivalencia(&cadena, &huerfano, "dir-huerfano", stats);
    }

    // Descartes: una tx que gasta una salida inexistente.
    if let Some(con_descarte) = como_post(post(
        53,
        vec![t1],
        3,
        10,
        1,
        0,
        vec![
            (tx_coinbase_post(productor, 1, 3), Vec::new()),
            (tx_inexistente(0x9A), Vec::new()),
        ],
    )) {
        equivalencia(&cadena, &con_descarte, "dir-descartes", stats);
    }

    // g1: hash ya existente (se admite antes un bloque con ese hash; luego se repite con otro cuerpo).
    if let Some(valido101) = como_post(post_coinbase(101, vec![t1], 1, 10, 1, 1)) {
        cadena.admitir(BloqueCadena::Post(valido101)).unwrap();
    }
    if let Some(existente) = como_post(post_coinbase(101, vec![t1], 2, 11, 1, 2)) {
        equivalencia(&cadena, &existente, "dir-hash-existente", stats);
    }

    // ErrGarantia: q > 0 y productor sin actividad.
    let mut cadena_q = Cadena::nueva(
        params_con(None, Amount::nuevo(1_000_000).unwrap()),
        1,
        CBID_RED_DEV,
        MAX_PADRES,
    );
    cadena_q.admitir(genesis()).unwrap();
    cadena_q.admitir(pow_terminal(1, 10)).unwrap();
    if let Some(sin_garantia) = como_post(post_coinbase(60, vec![t1], 1, 10, 77, 2)) {
        equivalencia(&cadena_q, &sin_garantia, "dir-garantia", stats);
    }

    // ErrMergeDepth: `f_slots = 2`, un bloque fusionado muy antiguo.
    let mut cadena_f = Cadena::nueva(
        params_con(Some(2), Amount::CERO),
        1,
        CBID_RED_DEV,
        MAX_PADRES,
    );
    cadena_f.admitir(genesis()).unwrap();
    cadena_f.admitir(pow_terminal(1, 10)).unwrap();
    let ah = hash16(70);
    if let Some(a) = como_post(post_coinbase(70, vec![t1], 1, 1_000, 1, 0)) {
        cadena_f.admitir(BloqueCadena::Post(a)).unwrap();
    }
    let mut bh = t1;
    if let Some(b) = como_post(post_coinbase(71, vec![t1], 5, 1, 2, 1)) {
        bh = b.hash;
        cadena_f.admitir(BloqueCadena::Post(b)).unwrap();
    }
    // C selecciona a `B` (más pesado) y fusiona a `A`, de slot muy anterior a `f = 2`.
    if let Some(c) = como_post(post_coinbase(72, vec![bh, ah], 20, 10, 3, 2)) {
        equivalencia(&cadena_f, &c, "dir-merge-depth", stats);
    }

    // Terminal sin DAG con 7 terminales: se crea el DAG (válido).
    let (mut cadena7, _) = cadena_con_terminales(7);
    cadena7.admitir(pow_terminal(8, 80)).unwrap();
    if let Some(nuevo7) = como_post(post_coinbase(208, vec![hash16(8)], 1, 10, 8, 3)) {
        equivalencia(&cadena7, &nuevo7, "dir-dag-7", stats);
    }

    // Terminal sin DAG con 8 terminales y trabajo insuficiente: ErrLimiteTerminales.
    let (mut cadena8, _) = cadena_con_terminales(8);
    cadena8.admitir(pow_terminal(9, 1)).unwrap();
    if let Some(nuevo9) = como_post(post_coinbase(209, vec![hash16(9)], 1, 10, 9, 4)) {
        equivalencia(&cadena8, &nuevo9, "dir-limite-8", stats);
    }

    // Terminal sin DAG con 8 terminales y trabajo superior: se crea el DAG sin tocar el original.
    let (mut cadena8b, _) = cadena_con_terminales(8);
    cadena8b.admitir(pow_terminal(10, 10_000)).unwrap();
    if let Some(nuevo10) = como_post(post_coinbase(210, vec![hash16(10)], 1, 10, 10, 5)) {
        equivalencia(&cadena8b, &nuevo10, "dir-desaloja-8", stats);
    }
}

// ─────────────── E1 · descartes, rojos y evidencia (segunda ronda PROD-3a-2) ───────────────

/// (a) · candidata válida con descartes: la transacción que ya aplicó su padre se descarta.
fn validos_con_descartes(stats: &mut Stats) {
    let semilla = [b"zx-prod3a-descarte".as_slice(), &[0x5A][..]].concat();
    let digest = zx_core::sha3_256_publico(&semilla);
    let sk = ed25519_zebra::SigningKey::from(*digest.as_bytes());
    let pk = ClavePublica::desde_bytes(ed25519_zebra::VerificationKey::from(&sk).into());
    let op = OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([0x5A; 32])),
        prev_index: 0,
    };
    let mut inicial = Estado::inicial();
    inicial.utxo.insert(
        op,
        EntradaUtxo {
            valor: Amount::nuevo(100).unwrap(),
            lock: Lock::PubKey { pubkey: pk },
            origen: Origen::Tx,
            creada: Punto::Altura(0),
        },
    );
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params(),
        1,
        CBID_RED_DEV,
        MAX_PADRES,
        ParametrosEvidencia::inactiva(),
        inicial,
    );
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 10)).unwrap();
    let t1 = hash16(1);
    let gasto = |salida: i64| -> (Tx, Vec<Vec<u8>>) {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(salida).unwrap(),
                lock: Lock::PubKey { pubkey: pk },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let soportes = [SpentOutput {
            value: Amount::nuevo(100).unwrap(),
            lock: Lock::PubKey { pubkey: pk },
        }];
        let digest = zx_core::sighash(&tx, &soportes, HashType::All, 0, CBID_RED_DEV).unwrap();
        let firma: [u8; 64] = sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    };
    let (tx, testigos) = gasto(90);
    if let Some(a) = como_post(post(
        400,
        vec![t1],
        1,
        10,
        1,
        0,
        vec![(tx.clone(), testigos.clone())],
    )) {
        cadena.admitir(BloqueCadena::Post(a)).unwrap();
    }
    if let Some(c) = como_post(post(
        401,
        vec![hash16(400)],
        2,
        10,
        2,
        1,
        vec![(tx, testigos)],
    )) {
        let (_, descartes) = cadena.ensayar_post(&c).unwrap();
        assert!(
            !descartes.is_empty(),
            "(a) la candidata válida no descartó ninguna transacción"
        );
        equivalencia(&cadena, &c, "dir-descartes-valido", stats);
        println!("E1_DESCARTES descartes={}", descartes.len());
    }
}

/// (b) · conjunto de fusión con un `RojoU3` (el cálculo lo salta) y un `RojoK` (se aplica).
fn rojos_en_mergeset(stats: &mut Stats) {
    let t1 = hash16(1);
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 10)).unwrap();
    for (i, chunk) in [0_u8, 0, 1, 1, 2, 2, 3].into_iter().enumerate() {
        let id = 500 + u16::try_from(i).unwrap();
        cadena
            .admitir(post(id, vec![t1], 1, 10, 1, chunk, Vec::new()))
            .unwrap();
    }
    let padres: Vec<BlockHash> = (0..7_u16).map(|i| hash16(500 + i)).collect();
    let Some(candidata) = como_post(post(600, padres, 2, 10, 1, 7, Vec::new())) else {
        return;
    };
    let terminal = cadena.chequear_forma(&candidata).unwrap();
    let mut dag = super::admision_post::dag_para_ensayo(&cadena, terminal).unwrap();
    super::admision_post::anadir_al_dag(&mut dag, &candidata).unwrap();
    let Some(&idx) = dag.dag_idx.get(&candidata.hash) else {
        return;
    };
    let gd = dag.dag.datos(idx).unwrap();
    let mut u3 = 0_usize;
    let mut k = 0_usize;
    for &m in &gd.orden_mergeset {
        match dag.dag.color_en(idx, m) {
            Some(Color::RojoU3) => u3 += 1,
            Some(Color::RojoK) => k += 1,
            _ => {}
        }
    }
    assert!(u3 > 0, "(b) ningún RojoU3 en el conjunto de fusión");
    assert!(k > 0, "(b) ningún RojoK en el conjunto de fusión");
    stats.rojo_u3 += u3;
    stats.rojo_k += k;
    equivalencia(&cadena, &candidata, "dir-rojos", stats);
    println!("E1_ROJOS rojo_u3={u3} rojo_k={k}");
}

/// Evidencia `0x0B` del montaje de `pruebas_fv4b` (firmas vacías: solo se lee el hecho).
fn tx_evidencia(n1: u64, c1: BlockHash, n2: u64, c2: BlockHash) -> Tx {
    let voto = |n: u64, c: BlockHash| VotoPesoEvidencia {
        n,
        candidato: *c.as_bytes(),
        h_t_siguiente: [0u8; 32],
        raiz_estado: [0u8; 32],
        firma: [0u8; 96],
    };
    Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: OperacionAlmacenamiento::EvidenciaVotosPeso {
                clave: ClavePublica::desde_bytes([200; 32]),
                clave_bls: [9u8; 48],
                voto1: voto(n1, c1),
                voto2: voto(n2, c2),
            },
        },
    }
}

/// Hecho de la evidencia para un bloque ya en el DAG de `terminal`.
fn hecho_en(cadena: &Cadena, terminal: BlockHash, x: BlockHash, op: &Tx) -> HechoVoto {
    let idx = cadena
        .dags
        .get(&terminal)
        .unwrap()
        .dag_idx
        .get(&x)
        .copied()
        .unwrap();
    let ctx = cadena.contexto_real(terminal, idx).unwrap();
    let plazo = u64::try_from(cadena.estado_t.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
    cadena.hecho_de_tx(&ctx, plazo, x, op)
}

/// Hecho de la evidencia para la **candidata** por la misma vista que usa el ensayo.
fn hecho_candidato(cadena: &Cadena, p: &BloquePost, op: &Tx) -> Option<HechoVoto> {
    let terminal = cadena.chequear_forma(p).ok()?;
    let mut dag = super::admision_post::dag_para_ensayo(cadena, terminal).ok()?;
    super::admision_post::anadir_al_dag(&mut dag, p).ok()?;
    let idx = *dag.dag_idx.get(&p.hash)?;
    let vista = super::admision_post::VistaPost::nueva(
        cadena,
        terminal,
        dag,
        BloqueCadena::Post(p.clone()),
    );
    let ctx = super::admision_post::contexto_real(&vista, terminal, idx)?;
    let plazo = u64::try_from(cadena.estado_t.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
    Some(super::admision_post::hecho_de_tx(
        &vista, &ctx, plazo, p.hash, op,
    ))
}

/// (c) · evidencia de doble voto en plazo, en el cuerpo de la candidata y en su conjunto de fusión.
fn evidencia_en_plazo(stats: &mut Stats) {
    let t1 = hash16(1);
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 10)).unwrap();
    // t1 → (A, B1, B2); X reúne los tres.
    cadena
        .admitir(post(700, vec![t1], 1, 10, 1, 0, Vec::new()))
        .unwrap();
    cadena
        .admitir(post(701, vec![t1], 1, 10, 1, 1, Vec::new()))
        .unwrap();
    cadena
        .admitir(post(702, vec![t1], 1, 10, 2, 2, Vec::new()))
        .unwrap();
    let (a, b1, b2) = (hash16(700), hash16(701), hash16(702));
    cadena
        .admitir(post(710, vec![a, b1, b2], 2, 10, 3, 3, Vec::new()))
        .unwrap();
    let x = hash16(710);
    let ev = tx_evidencia(1, b1, 4, b2);

    // (c1) en el cuerpo de la candidata: el hecho recorre el grafo y da `Falta`.
    let Some(c_falta) = como_post(post(
        720,
        vec![x],
        3,
        10,
        4,
        4,
        vec![(ev.clone(), vec![vec![0u8; 64]])],
    )) else {
        return;
    };
    assert_eq!(
        hecho_candidato(&cadena, &c_falta, &ev),
        Some(HechoVoto::Falta),
        "(c) la evidencia del cuerpo no dio Falta"
    );
    stats.evid_falta += 1;
    equivalencia(&cadena, &c_falta, "dir-evid-falta", stats);

    // (c2) en un bloque del conjunto de fusión: `y` es el padre seleccionado (más peso) y `y2`, con
    // la evidencia y menos peso, entra en el conjunto de fusión: el ensayo del hijo lo recorre.
    let Some(y) = como_post(post(711, vec![x], 3, 10, 5, 5, Vec::new())) else {
        return;
    };
    let Some(y2) = como_post(post(
        712,
        vec![x],
        3,
        1_000,
        6,
        6,
        vec![(ev.clone(), vec![vec![0u8; 64]])],
    )) else {
        return;
    };
    cadena.admitir(BloqueCadena::Post(y.clone())).unwrap();
    assert_eq!(
        cadena.admitir(BloqueCadena::Post(y2.clone())),
        Ok(()),
        "(c) el bloque con evidencia no se admitió"
    );
    assert_eq!(
        hecho_en(&cadena, t1, y2.hash, &ev),
        HechoVoto::Falta,
        "(c) la evidencia del conjunto de fusión no dio Falta"
    );
    stats.evid_mergeset += 1;
    if let Some(c_hijo) = como_post(post(721, vec![y.hash, y2.hash], 4, 10, 7, 7, Vec::new())) {
        equivalencia(&cadena, &c_hijo, "dir-evid-mergeset", stats);
    }

    // (c3) `SinFalta`: la finalidad del pasado de B2 sella un bloque en conflicto con B1 (paso 10).
    // El castigo monetario de una falta aplicada se prueba en `zx-consensus`; aquí se afirma el
    // hecho que lo decide, que es lo que la vista debe recorrer.
    cadena.finalidad_pasado.insert(b2, (1, Some(b2)));
    let Some(c_sin) = como_post(post(
        722,
        vec![x],
        3,
        10,
        8,
        8,
        vec![(ev.clone(), vec![vec![0u8; 64]])],
    )) else {
        return;
    };
    assert_eq!(
        hecho_candidato(&cadena, &c_sin, &ev),
        Some(HechoVoto::SinFalta),
        "(c) la evidencia justificada no dio SinFalta"
    );
    stats.evid_sinfalta += 1;
    equivalencia(&cadena, &c_sin, "dir-evid-sinfalta", stats);
    println!(
        "E1_EVIDENCIA falta={} sinfalta={} mergeset={}",
        stats.evid_falta, stats.evid_sinfalta, stats.evid_mergeset
    );
}

/// (c) sola: los casos de evidencia dentro de plazo por la vista (es la prueba que caza R7).
#[test]
fn e1_evidencia_dentro_de_plazo() {
    let mut stats = Stats::default();
    evidencia_en_plazo(&mut stats);
    assert_eq!(stats.evid_falta, 1, "(c) falta");
    assert_eq!(stats.evid_sinfalta, 1, "(c) sinfalta");
    assert_eq!(stats.evid_mergeset, 1, "(c) mergeset");
}

// ─────────────────────────── E4 · el ensayo no altera el original ───────────────────────────
#[test]
fn e4_ensayo_no_altera_el_original() {
    for (i, entropia) in ENTROPIAS.iter().enumerate() {
        let h = generar(entropia);
        let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
        for b in &h.bloques {
            if let BloqueCadena::Post(p) = b {
                let antes = observables(&cadena);
                let _ = cadena.ensayar_post(p);
                let despues = observables(&cadena);
                assert_eq!(
                    antes, despues,
                    "E4: el ensayo alteró el original [prop-{i}]"
                );
                let o2 = o2_admitir(&cadena, p);
                cadena.admitir(b.clone()).unwrap();
                if let Ok((estado_esperado, desc_esperados)) = o2 {
                    let hash = p.hash;
                    assert_eq!(cadena.estado_post(&hash), Some(&estado_esperado));
                    assert_eq!(
                        cadena
                            .descartes(&hash)
                            .map(<[TxDescartada]>::to_vec)
                            .unwrap_or_default(),
                        desc_esperados
                    );
                }
            } else {
                cadena.admitir(b.clone()).unwrap();
            }
        }
    }

    // g4 con 8 terminales: el ensayo del noveno no toca límite ni desalojo.
    let (mut cadena8, _) = cadena_con_terminales(8);
    cadena8.admitir(pow_terminal(9, 1)).unwrap();
    let antes = observables(&cadena8);
    if let Some(candidata) = como_post(post_coinbase(209, vec![hash16(9)], 1, 10, 9, 4)) {
        assert_eq!(
            cadena8.ensayar_post(&candidata),
            Err(MotivoBloque::ErrLimiteTerminales)
        );
    }
    let despues = observables(&cadena8);
    assert_eq!(
        antes, despues,
        "E4: el ensayo del noveno terminal alteró el original"
    );
    assert!(!cadena8.limite_terminales_alcanzado());
}

// ─────────────────────────── E6a · coste (release) ───────────────────────────────

fn cadena_lineal(n: usize) -> (Cadena, BlockHash) {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 10)).unwrap();
    let (bloques, punta) = suceso_suffix(hash16(1), n, 100, 1_000, 1);
    for b in &bloques {
        cadena.admitir(b.clone()).unwrap();
    }
    (cadena, punta)
}

#[test]
#[ignore = "medida release de E6a; se corre aparte"]
fn prod3a_coste_historia_retenida() {
    if cfg!(debug_assertions) {
        return;
    }
    for (n, id) in [(16_usize, 2_000_u16), (64, 3_000), (256, 4_000)] {
        let (cadena, punta) = cadena_lineal(n);
        let slot = u64::try_from(n).unwrap() + 2;
        let Some(candidata) = como_post(post_coinbase(id, vec![punta], slot, 100, 9, 9)) else {
            continue;
        };
        let _ = cadena.ensayar_post(&candidata);
        let _ = o1_ensayar(&cadena, &candidata);
        let mut t_o1: Vec<u128> = Vec::new();
        let mut t_new: Vec<u128> = Vec::new();
        for _ in 0..5 {
            let i = Instant::now();
            let _ = std::hint::black_box(o1_ensayar(&cadena, &candidata));
            t_o1.push(i.elapsed().as_nanos());
            let i = Instant::now();
            let _ = std::hint::black_box(cadena.ensayar_post(&candidata));
            t_new.push(i.elapsed().as_nanos());
        }
        t_o1.sort_unstable();
        t_new.sort_unstable();
        let min_o1 = t_o1.first().copied().unwrap_or(0);
        let med_o1 = t_o1.get(2).copied().unwrap_or(0);
        let max_o1 = t_o1.last().copied().unwrap_or(0);
        let min_new = t_new.first().copied().unwrap_or(0);
        let med_new = t_new.get(2).copied().unwrap_or(0);
        let max_new = t_new.last().copied().unwrap_or(0);
        println!(
            "PROD3A_COSTE bloques={n} estados={n} o1_ns={min_o1}/{med_o1}/{max_o1} nuevo_ns={min_new}/{med_new}/{max_new} perfil=release"
        );
    }
}
