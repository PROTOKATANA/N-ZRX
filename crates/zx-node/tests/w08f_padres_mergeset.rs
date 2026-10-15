//! `ORDEN-W08f` (IPA B-18/B-20): el productor elige padres respetando el tope de mergeset.
//!
//! - **V1**: un DAG con dos ramas de 300 bloques. El conjunto de padres de hoy (`sp` + la otra
//!   punta) se rechaza con `ErrMergeset`; `padres_de_regimen` elige un subconjunto que sí cabe y el
//!   bloque resultante se admite.
//! - **V2**: 200 historias aleatorias **sin** reorganización profunda (anchura ≤ 15 y ramas cortas,
//!   de modo que el mergeset completo cabe holgado en el tope): la selección es exactamente la de
//!   hoy (todas las puntas), 0 diferencias.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño"
)]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena, MotivoBloque};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, PadresDag, Tx};
use zx_dag::bloque_dag::ContextoDag;
use zx_dag::{IdentidadGhostdag, IdentidadTicket};
use zx_node::padres::padres_de_regimen;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// `q = S_min = 0`: la garantía del productor nunca bloquea.
fn params() -> ParametrosTransicion {
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
        f_slots: None,
        subsidio_pow,
        subsidio_post,
    }
}

/// Hash determinista a partir de un entero (los tests antiguos usan `[n; 32]` con `n: u8`, que no
/// llega para cientos de bloques).
fn hash_de(n: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn bytes_de(n: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    bytes
}

fn productor(byte: u8) -> ClavePublica {
    ClavePublica::desde_bytes([byte; 32])
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

/// Construye bloques PoST con hash, `slot` e identidad únicos y crecientes.
struct Constructor {
    siguiente: u64,
}

impl Constructor {
    fn nuevo() -> Self {
        Self { siguiente: 0 }
    }

    fn post(&mut self, padres: Vec<BlockHash>) -> BloqueCadena {
        let id = self.siguiente;
        self.siguiente += 1;
        let slot = 2 + id;
        let byte = u8::try_from(id % 250 + 1).unwrap_or(1);
        let prod = productor(byte);
        BloqueCadena::Post(BloquePost {
            hash: hash_de(1_000_000 + id + 1),
            padres,
            slot,
            timestamp: 0,
            productor: prod,
            peso: 5,
            prueba_valida: true,
            requisito_declarado: 0,
            sr: 1,
            distancia: 0,
            identidad: IdentidadGhostdag::Billete(IdentidadTicket::vigente(
                prod,
                3,
                1 << 20,
                bytes_de(id + 1),
                slot,
            )),
            txs: vec![(tx_coinbase_post(prod, 3, slot), Vec::new())],
        })
    }
}

fn cadena_con_terminal() -> Cadena {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, 15);
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis { hash: hash_de(0) },
            Vec::new(),
        )))
        .unwrap();
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::PoW {
                hash: hash_de(1),
                padre: hash_de(0),
                altura: 1,
                trabajo: U256::one(),
                pow_valido: true,
            },
            Vec::new(),
        )))
        .unwrap();
    assert_eq!(cadena.terminal(), Some(hash_de(1)));
    cadena
}

/// Los padres declarados en `PadresDag`, como vector (`sp` primero).
fn padres_como_vec(padres: &PadresDag) -> Vec<BlockHash> {
    std::iter::once(padres.seleccionado())
        .chain(padres.extras().iter().copied())
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// V1 · dos ramas de 300 bloques
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v1_dos_ramas_de_300_se_reunen_dentro_del_tope() {
    let mut cadena = cadena_con_terminal();
    let terminal = hash_de(1);
    let mut constructor = Constructor::nuevo();

    // Dos ramas de 300 bloques colgando del terminal.
    let mut punta_a = terminal;
    for _ in 0..300 {
        let b = constructor.post(vec![punta_a]);
        punta_a = b.hash();
        cadena.admitir(b).unwrap();
    }
    let mut punta_b = terminal;
    for _ in 0..300 {
        let b = constructor.post(vec![punta_b]);
        punta_b = b.hash();
        cadena.admitir(b).unwrap();
    }
    assert_eq!(cadena.tips_validas().len(), 2);

    // El conjunto de padres de hoy (las dos puntas) no cabe: `|mergeset| + 1 > 180`.
    let tips = cadena.tips_validas();
    let bloque_de_hoy = constructor.post(tips.clone());
    assert_eq!(
        cadena.admitir(bloque_de_hoy),
        Err(MotivoBloque::ErrMergeset),
        "con las dos puntas el bloque de reunión debe rechazarse por tope de mergeset"
    );

    // La selección nueva omite la punta que no cabe y el bloque se admite.
    let elegidos = padres_de_regimen(&cadena).unwrap();
    assert_eq!(
        elegidos.count(),
        1,
        "la rama de 300 no cabe como padre extra: solo queda el seleccionado"
    );
    let bloque = constructor.post(padres_como_vec(&elegidos));
    assert!(
        cadena.admitir(bloque).is_ok(),
        "el bloque con los padres elegidos debe admitirse sin `ErrMergeset`"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// V2 · propiedad sin reorganización profunda
// ─────────────────────────────────────────────────────────────────────────────

/// xorshift64* determinista: la propiedad debe ser reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn rango(&mut self, n: u64) -> u64 {
        assert!(n > 0, "rango sobre un conjunto vacío");
        self.next() % n
    }
}

/// Genera una historia aleatoria con anchura ≤ 15 y pocos bloques (≤ ~50), de forma que el
/// mergeset completo quepa siempre holgado en el tope de 180.
fn historia_aleatoria(rng: &mut Rng) -> Cadena {
    let mut cadena = cadena_con_terminal();
    let terminal = hash_de(1);
    let mut constructor = Constructor::nuevo();
    let mut tips: Vec<BlockHash> = vec![terminal];
    let objetivo = 20 + rng.rango(31) as usize;
    let mut puestos = 0usize;

    while puestos < objetivo {
        let accion = rng.rango(10);
        if tips.len() < 15 && accion < 4 {
            // Bifurcación: dos hijos del mismo tip.
            let i = rng.rango(tips.len() as u64) as usize;
            let padre = tips.swap_remove(i);
            let b1 = constructor.post(vec![padre]);
            let b2 = constructor.post(vec![padre]);
            let (h1, h2) = (b1.hash(), b2.hash());
            cadena.admitir(b1).unwrap();
            cadena.admitir(b2).unwrap();
            tips.push(h1);
            tips.push(h2);
            puestos += 2;
        } else if tips.len() >= 2 && accion < 7 {
            // Reunión de 2 o 3 puntas.
            let max = tips.len().min(3);
            let k = 2 + rng.rango((max - 1) as u64) as usize;
            let mut idx: Vec<usize> = (0..tips.len()).collect();
            for j in 0..k {
                let r = j + rng.rango((tips.len() - j) as u64) as usize;
                idx.swap(j, r);
            }
            let padres: Vec<BlockHash> = idx[..k].iter().map(|&j| tips[j]).collect();
            let b = constructor.post(padres);
            let h = b.hash();
            cadena.admitir(b).unwrap();
            let mut sel: Vec<usize> = idx[..k].to_vec();
            sel.sort_unstable_by(|a, b| b.cmp(a));
            for j in sel {
                tips.swap_remove(j);
            }
            tips.push(h);
            puestos += 1;
        } else {
            // Extensión de una punta.
            let i = rng.rango(tips.len() as u64) as usize;
            let b = constructor.post(vec![tips[i]]);
            let h = b.hash();
            cadena.admitir(b).unwrap();
            tips[i] = h;
            puestos += 1;
        }
    }

    let mut esperadas = cadena.tips_validas();
    esperadas.sort_unstable();
    let mut generadas = tips.clone();
    generadas.sort_unstable();
    assert_eq!(esperadas, generadas, "el generador debe conocer las puntas");
    cadena
}

#[test]
fn v2_sin_reorganizacion_profunda_los_padres_son_los_de_hoy() {
    let mut rng = Rng(0x5a5a_5a5a_5a5a_5a5a);
    for historia in 0..200 {
        let cadena = historia_aleatoria(&mut rng);
        let tips = cadena.tips_validas();
        assert!(!tips.is_empty());

        // El conjunto completo cabe: es una historia sin reorganización profunda.
        let (tamano, tope) = cadena.mergeset_de_padres(&tips).unwrap();
        assert!(
            tamano < u64::from(tope),
            "historia {historia}: el mergeset completo no cabe ({tamano}+1 > {tope})"
        );

        // Selección de hoy, implementada aquí: `sp` por GHOSTDAG + todas las puntas restantes.
        let dag = cadena.contexto_dag().unwrap();
        let (primero, resto) = tips.split_first().unwrap();
        let provisional = PadresDag::nuevo(*primero, resto).unwrap();
        let sp = ContextoDag::padre_seleccionado(dag, &provisional).unwrap();
        let extras: Vec<BlockHash> = tips.iter().copied().filter(|h| *h != sp).collect();
        let esperado = PadresDag::nuevo(sp, &extras).unwrap();

        let elegido = padres_de_regimen(&cadena).unwrap();
        assert_eq!(
            elegido, esperado,
            "historia {historia}: la selección nueva difiere de la de hoy"
        );
    }
}
