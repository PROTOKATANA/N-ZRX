//! `FIN-1-2` · Cláusula (3): con `F = 600` y DAG honestos aleatorios (anchura 1–15, 10⁴ bloques,
//! retrasos de red de hasta 10 slots), el filtro de finalidad **no excluye nunca** un bloque
//! honesto.
//!
//! Modelo honesto determinista (semilla fija, PRNG propio sin dependencias nuevas):
//!
//! - `10⁴` bloques repartidos en slots; en cada slot se producen `w ∈ [1, 15]` bloques (la
//!   **anchura** que admite el motor: `zx_dag::ghostdag::MAX_PADRES_POR_DEFECTO = 15`).
//! - Todos los bloques de un slot referencian como padres **todas** las puntas del slot anterior
//!   (así la anchura se mantiene `≤ 15`), y además hasta `RETRASO_MAX = 10` slots atrás se añaden
//!   padres antiguos que modelan el **retraso de red** (un bloque puede no haber visto aún lo más
//!   reciente y fusionar bloques de hasta 10 slots de antigüedad).
//! - Ningún bloque bifurca en privado ni deja de descender de la cadena: es un DAG honesto.
//!
//! Al cerrar **cada slot** se comprueba si el filtro descarta alguna punta válida del terminal:
//! `tips_validas_de` (todas) frente a `tips_validas` (ya filtradas). El punto de finalidad solo
//! avanza, así que una punta excluida lo sigue estando: comprobar al final del slot con el punto
//! más avanzado es la comprobación más estricta. Una diferencia es un bloque honesto excluido: un
//! contraejemplo a la cláusula (3).

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio test"
)]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;

const MAX_PADRES: u8 = 15;
const K: u32 = 1;
/// Punto de finalidad de la cláusula (3).
const F: u64 = 600;
/// Bloques del DAG honesto.
const N_BLOQUES: usize = 10_000;
/// Anchura máxima (bloques por slot), igual que `MAX_PADRES_POR_DEFECTO`.
const ANCHO_MAX: u64 = 15;
/// Retraso de red máximo, en slots.
const RETRASO_MAX: usize = 10;
/// Semilla fija del generador.
const SEMILLA: u64 = 0x5eed_1234_abcd_0001;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// `q = S_min = 0`, `H_corte_min = 1`: sin garantía, para aislar la selección. `f_slots = Some(F)`.
fn params(f_slots: Option<u64>) -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 1,
        w_min: U256::one(),
        s_min: Amount::CERO,
        q: Amount::CERO,
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

fn hash_u32(n: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn productor() -> ClavePublica {
    let digest = zx_core::sha3_256_publico(b"zx-fin1-finalidad");
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
        HechosCabecera::Genesis { hash: hash_u32(0) },
        Vec::new(),
    ))
}

fn pow_terminal(id: u32, trabajo: u64) -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash_u32(id),
            padre: hash_u32(0),
            altura: 1,
            trabajo: U256::from(trabajo),
            pow_valido: true,
        },
        Vec::new(),
    ))
}

/// Bloque PoST honesto con identidad única (`id`), `slot` y `sr`.
fn post(id: u32, padres: Vec<BlockHash>, slot: u64, sr: u64) -> BloqueCadena {
    let productor = productor();
    let tx = tx_coinbase_post(productor, 1, slot);
    let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor,
        0,
        u64::from(id) + 1,
        [(id & 0xff) as u8; 32],
        slot,
    ));
    BloqueCadena::Post(BloquePost {
        hash: hash_u32(id),
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
        txs: vec![(tx, Vec::new())],
    })
}

/// PRNG determinista `splitmix64` (sin dependencias nuevas).
struct Rng(u64);

impl Rng {
    fn siguiente(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Entero uniforme en `[0, n)` (sesgo despreciable para los tamaños del test).
    fn abajo(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.siguiente() % n
    }
}

/// Una punta honesta descartada por el filtro en un momento dado.
struct Exclusion {
    slot_pf: u64,
    slot_tip: u64,
    pf: BlockHash,
    tip: BlockHash,
}

#[test]
fn fin12_filtro_no_excluye_bloques_honestos() {
    // Por defecto la cláusula (3): 10⁴ bloques y `F = 600`. `FIN12_N`/`FIN12_F` permiten un
    // diagnóstico reducido sin recompilar; el informe usa los valores por defecto.
    let n_bloques: usize = std::env::var("FIN12_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(N_BLOQUES);
    let f: u64 = std::env::var("FIN12_F")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(F);
    let debug = std::env::var("FIN12_DEBUG").is_ok();

    let mut cadena = Cadena::nueva(params(Some(f)), K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    let terminal_inicial = hash_u32(1);

    let mut rng = Rng(SEMILLA);
    // `por_slot[s - 1]`: hashes de los bloques producidos en el slot `s`.
    let mut por_slot: Vec<Vec<BlockHash>> = Vec::new();
    // Puntas del DAG al empezar el slot actual (bloques del slot anterior).
    let mut tips: Vec<BlockHash> = vec![terminal_inicial];
    let mut id: u32 = 100;
    let mut total = 0usize;
    let mut fallos_admision = 0usize;
    let mut fallos_ejemplo: Vec<String> = Vec::new();
    let mut exclusiones: Vec<Exclusion> = Vec::new();
    let mut max_slot_pf = 0u64;

    let mut slot = 1u64;
    while total < n_bloques {
        let ancho = 1 + rng.abajo(ANCHO_MAX); // 1..=ANCHO_MAX
        let mut hashes_slot: Vec<BlockHash> = Vec::new();
        for _ in 0..ancho {
            // Padres honestos: todas las puntas del slot anterior.
            let mut padres: Vec<BlockHash> = tips.clone();
            // Retraso de red: hasta 2 padres extra de hasta `RETRASO_MAX` slots atrás, sin pasar
            // del tope de padres que admite el motor (`MAX_PADRES`).
            let mut intentos = 0;
            while padres.len() < usize::from(MAX_PADRES) && intentos < 2 {
                intentos += 1;
                let ventana = por_slot.len().min(RETRASO_MAX);
                if ventana == 0 {
                    break;
                }
                let s2 = por_slot.len() - 1 - (rng.abajo(ventana as u64) as usize);
                let opciones = &por_slot[s2];
                if opciones.is_empty() {
                    continue;
                }
                let cand = opciones[rng.abajo(opciones.len() as u64) as usize];
                if !padres.contains(&cand) {
                    padres.push(cand);
                }
            }
            let b = post(id, padres, slot, 10);
            let h = b.hash();
            if let Err(e) = cadena.admitir(b) {
                fallos_admision += 1;
                if fallos_ejemplo.len() < 20 {
                    fallos_ejemplo.push(format!("id={id} slot={slot}: {e:?}"));
                }
            }
            id += 1;
            hashes_slot.push(h);
            total += 1;
        }

        // Cláusula (3): al cerrar el slot, ninguna punta honesta puede quedar fuera del filtro.
        if let (Some(terminal), Some(pf)) = (cadena.terminal(), cadena.punto_finalidad()) {
            let slot_pf = cadena.bloque(&pf).and_then(|b| b.slot()).unwrap_or(0);
            max_slot_pf = max_slot_pf.max(slot_pf);
            let validas = cadena.tips_validas_de(terminal);
            let seleccionables: std::collections::BTreeSet<BlockHash> =
                cadena.tips_validas().into_iter().collect();
            if debug && slot.is_multiple_of(50) {
                let punta = cadena.mejor_punta();
                let slot_punta = punta
                    .and_then(|h| cadena.bloque(&h).and_then(|b| b.slot()))
                    .unwrap_or(0);
                println!(
                    "[dbg] total={total} slot={slot} punta_slot={slot_punta} limite={} pf_slot={slot_pf} n_tips={} n_sel={}",
                    slot_punta.saturating_sub(f),
                    validas.len(),
                    seleccionables.len()
                );
            }
            for tip in validas {
                if !seleccionables.contains(&tip) {
                    let slot_tip = cadena.bloque(&tip).and_then(|b| b.slot()).unwrap_or(0);
                    exclusiones.push(Exclusion {
                        slot_pf,
                        slot_tip,
                        pf,
                        tip,
                    });
                }
            }
        }

        assert!(
            !hashes_slot.is_empty(),
            "slot {slot} no produjo ningún bloque"
        );
        tips = hashes_slot.clone();
        por_slot.push(hashes_slot);
        slot += 1;
    }

    // Invariantes del montaje: el DAG es honesto y la cota estuvo activa.
    assert!(
        fallos_admision == 0,
        "el DAG honesto tuvo {fallos_admision} admisiones fallidas: {fallos_ejemplo:?}"
    );
    assert!(
        cadena.punto_finalidad().is_some(),
        "no se fijó punto de finalidad"
    );
    assert!(
        max_slot_pf.saturating_mul(2) > f,
        "el punto de finalidad no avanzó lo suficiente (slot {max_slot_pf}, F={f}); la cota fue vacua"
    );
    assert!(
        exclusiones.is_empty(),
        "el filtro excluyó {} bloques honestos (primeros 20): {:?}",
        exclusiones.len(),
        exclusiones
            .iter()
            .take(20)
            .map(|e| format!("pf_slot={} tip_slot={}", e.slot_pf, e.slot_tip))
            .collect::<Vec<_>>()
    );

    println!("=== FIN-1-2 cláusula (3): DAG honesto, F={f} ===");
    println!("bloques admitidos            = {total}");
    println!(
        "anchura media                = {:.2}",
        (total as f64) / (slot as f64)
    );
    println!("slots generados              = {slot}");
    println!("admisiones fallidas          = {fallos_admision}");
    println!("slot máximo del punto final  = {max_slot_pf}");
    println!("puntas honestas excluidas    = {}", exclusiones.len());
    if let Some(ex) = exclusiones.first() {
        println!(
            "primera exclusión: pf={:?} (slot {}), punta={:?} (slot {})",
            ex.pf, ex.slot_pf, ex.tip, ex.slot_tip
        );
    }
    println!(
        "violaciones de finalidad     = {}",
        cadena.violaciones_finalidad().len()
    );
}
