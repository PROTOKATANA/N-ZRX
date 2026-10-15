//! Propiedades con `proptest` (`ORDEN-W06a` V5, IE-1…IE-4).
//!
//! Genera DAGs PoST **válidos** (sin `rojo_U3`) sobre un prefijo PoW mínimo con `q = S_min = 0`,
//! de modo que la garantía del productor nunca bloquea y la entropía decide padres, slots, pesos,
//! `sr`, `sd` e identidad. Semilla fija (`RngSeed::Fixed(0x5a5a)`), como el resto del workspace.
//!
//! - **IE-1** conservación (`invariante_i1`) en `past`, `post` y virtual;
//! - **IE-2** cada bloque se aplica una sola vez en la historia seleccionada;
//! - **IE-3** el resultado no depende del orden de llegada (permutación topológica);
//! - **IE-4** undo exacto al recomputar una rama y una reorganización.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, HechosCabecera, ParametrosTransicion, invariante_i1,
};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::{IdentidadGhostdag, IdentidadTicket};

/// Máximo de padres del perfil dev (`PERFIL-DEV-v0.md` §4). El generador produce como mucho 3
/// padres por bloque, así que este valor no cambia ninguna propiedad; se declara explícitamente
/// porque `Cadena::nueva` no tiene valor por defecto oculto (`ORDEN-W06a-C` decisión 1).
const MAX_PADRES_PRODUCCION: u8 = 15;

fn subsidio_pow_prop(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post_prop(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// Parámetros que hacen trivial la puerta de garantía y el corte (`q = S_min = 0`).
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
        subsidio_pow: subsidio_pow_prop,
        subsidio_post: subsidio_post_prop,
    }
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn par(k: u64) -> ClavePublica {
    let mut mensaje = b"zx-w06a-prop-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    let sk = SigningKey::from(*digest.as_bytes());
    let vk = VerificationKey::from(&sk);
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

/// Cursor determinista sobre el vector de entropía.
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

/// Historia generada: cadena ya resuelta, bloques en orden de generación y hashes PoST.
struct Historia {
    cadena: Cadena,
    bloques: Vec<BloqueCadena>,
    posts: Vec<BlockHash>,
}

fn generar(entropia: &[u8]) -> Historia {
    let mut cursor = Cursor {
        datos: entropia,
        pos: 0,
    };
    let params = params();
    let mut cadena = Cadena::nueva(params, 1, CBID_RED_DEV, MAX_PADRES_PRODUCCION);
    let mut bloques = Vec::new();

    let genesis = BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash(0) },
        Vec::new(),
    ));
    cadena.admitir(genesis.clone()).unwrap();
    bloques.push(genesis);

    // PoW h = 1, sin transacciones: cumple H_corte_min = 1, W_min = 1 y Φ.
    let pow = BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(1),
            padre: hash(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        Vec::new(),
    ));
    cadena.admitir(pow.clone()).unwrap();
    bloques.push(pow);

    let productor = par(1);
    let n_post = cursor.siguiente(8);
    let mut posts: Vec<BlockHash> = Vec::new();
    for i in 0..n_post {
        let id = 10 + i as u8;
        let bhash = hash(id);
        let mut padres: Vec<BlockHash> = if posts.is_empty() {
            vec![hash(1)]
        } else {
            let max_cuantos = posts.len().min(3) as u32;
            let cuantos = 1 + cursor.siguiente(max_cuantos);
            let mut elegidos = BTreeSet::new();
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
            padres.push(hash(1));
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
        // Identidad real de `C-GD-07`, distinta por bloque (`de_fixture` es sólo del arnés T04).
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
    Historia {
        cadena,
        bloques,
        posts,
    }
}

/// Orden topológico aleatorio de los índices de `bloques` (Kahn con elección aleatoria).
fn orden_topologico(bloques: &[BloqueCadena], entropia: &[u8]) -> Vec<usize> {
    let n = bloques.len();
    let mut pos_de: BTreeMap<BlockHash, usize> = BTreeMap::new();
    for (i, b) in bloques.iter().enumerate() {
        pos_de.insert(b.hash(), i);
    }
    let mut padres: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut hijos: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, b) in bloques.iter().enumerate() {
        let ps: Vec<usize> = b
            .padres()
            .iter()
            .filter_map(|p| pos_de.get(p).copied())
            .collect();
        for p in &ps {
            if let Some(h) = hijos.get_mut(*p) {
                h.push(i);
            }
        }
        padres.push(ps);
    }
    let mut listos: Vec<usize> = (0..n)
        .filter(|i| padres.get(*i).is_some_and(Vec::is_empty))
        .collect();
    let mut orden = Vec::with_capacity(n);
    let mut cursor = 0usize;
    while !listos.is_empty() {
        let b = u32::from(entropia.get(cursor).copied().unwrap_or(0));
        cursor = cursor.wrapping_add(1);
        let j = b as usize % listos.len();
        let i = listos.swap_remove(j);
        orden.push(i);
        let mut nuevos = Vec::new();
        if let Some(hs) = hijos.get(i) {
            for h in hs {
                if let Some(ps) = padres.get(*h)
                    && ps.iter().all(|p| orden.contains(p))
                {
                    nuevos.push(*h);
                }
            }
        }
        listos.extend(nuevos);
    }
    orden
}

proptest! {
    #![proptest_config(ProptestConfig {
        rng_seed: RngSeed::Fixed(0x5a5a),
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// IE-1: conservación en `past(B)`, `post(B)` y virtual.
    #[test]
    fn ie1_conservacion(entropia in prop::collection::vec(any::<u8>(), 8..80)) {
        let h = generar(&entropia);
        for hash_post in &h.posts {
            let past = h.cadena.estado_past(hash_post).unwrap();
            let post = h.cadena.estado_post(hash_post).unwrap();
            prop_assert!(invariante_i1(past));
            prop_assert!(invariante_i1(post));
        }
        let virtual_estado = h.cadena.estado_virtual().unwrap();
        prop_assert!(invariante_i1(&virtual_estado));
        let (historia, _, _) = h.cadena.aplicar_historia().unwrap();
        prop_assert!(invariante_i1(&historia));
        prop_assert_eq!(historia, virtual_estado);
    }

    /// IE-2: cada bloque válido se aplica exactamente una vez en la historia seleccionada.
    #[test]
    fn ie2_aplicacion_unica(entropia in prop::collection::vec(any::<u8>(), 8..80)) {
        let h = generar(&entropia);
        let orden = h.cadena.orden_aplicacion().unwrap();
        let unicos: BTreeSet<BlockHash> = orden.iter().copied().collect();
        prop_assert_eq!(unicos.len(), orden.len(), "bloque aplicado dos veces");
        let esperados: BTreeSet<BlockHash> = h.posts.iter().copied().collect();
        prop_assert_eq!(unicos, esperados);
    }

    /// IE-3: el estado por bloque no depende del orden de llegada.
    #[test]
    fn ie3_orden_de_llegada(entropia in prop::collection::vec(any::<u8>(), 8..80)) {
        let h = generar(&entropia);
        let orden = orden_topologico(&h.bloques, &entropia);
        prop_assert_eq!(orden.len(), h.bloques.len());
        let mut cadena2 = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES_PRODUCCION);
        cadena2.resolver(&h.bloques, &orden).unwrap();
        for hash_post in &h.posts {
            prop_assert_eq!(cadena2.estado_past(hash_post), h.cadena.estado_past(hash_post));
            prop_assert_eq!(cadena2.estado_post(hash_post), h.cadena.estado_post(hash_post));
        }
        prop_assert_eq!(cadena2.mejor_punta(), h.cadena.mejor_punta());
    }

    /// IE-4: undo exacto de una rama y de una reorganización entre dos puntas.
    #[test]
    fn ie4_undo_y_reorg(entropia in prop::collection::vec(any::<u8>(), 8..80)) {
        let h = generar(&entropia);
        let estado_t: Estado = h.cadena.estado_terminal().clone();
        let Some(tip) = h.cadena.mejor_punta() else {
            prop_assert!(h.posts.is_empty());
            return Ok(());
        };
        let (estado_a, undos_a) = h.cadena.aplicar_rama(&tip).unwrap();
        prop_assert_eq!(h.cadena.deshacer_historia(&estado_a, &undos_a), estado_t.clone());
        // La historia seleccionada es independiente de la rama elegida para deshacer.
        let (historia, _, _) = h.cadena.aplicar_historia().unwrap();
        prop_assert!(invariante_i1(&historia));
        let tips = h.cadena.tips_validas();
        if let Some(otra) = tips.iter().find(|t| **t != tip) {
            let (estado_b, undos_b) = h.cadena.aplicar_rama(otra).unwrap();
            prop_assert_eq!(h.cadena.deshacer_historia(&estado_b, &undos_b), estado_t.clone());
            // Volver a la primera rama reproduce exactamente el estado previo.
            let (estado_vuelta, _) = h.cadena.aplicar_rama(&tip).unwrap();
            prop_assert_eq!(estado_vuelta, estado_a);
        }
    }
}
