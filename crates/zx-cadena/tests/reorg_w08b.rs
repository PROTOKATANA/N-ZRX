//! V6 · W08b — reorganización profunda: una rama rival de `D` slots que gana.
//!
//! Recrea en memoria el caso A5 de DF-1a (rama privada profunda que acaba imponiéndose): se
//! admiten `D` bloques PoST de una rama principal con poco trabajo por bloque (`SR = 10`) y
//! después `D` bloques de una rama rival con más trabajo (`SR = 1`) que acaba ganando. Se mide el
//! coste total de la admisión de la rival y se comprueba que la cadena virtual seleccionada es la
//! rival, sin ningún fallo.
//!
//! `D` se fija con `W08B_REORG_D` (por defecto 2000). Es lento: se lanza con `--ignored`.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
#![expect(clippy::panic, reason = "un fallo de admisión es un panic del test")]

use std::time::Instant;

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;

const MAX_PADRES: u8 = 15;
const K: u32 = 30;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// `q = S_min = 0` y sin `C-FIN-01` ni profundidad de fusión (`f_slots = None`).
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

fn hash_u32(n: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn productor() -> ClavePublica {
    let digest = zx_core::sha3_256_publico(b"zx-w08b-v6-reorg");
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

/// Bloque PoST con identidad única (`history_size` = `id`), `slot` y `sr` dados.
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

/// Construye una rama de `d` bloques desde el terminal `hash_u32(1)` y devuelve (punta, ids).
fn rama(cadena: &mut Cadena, d: u32, base_id: u32, sr: u64) -> (BlockHash, Vec<u32>) {
    let mut padre = hash_u32(1);
    let mut ids = Vec::with_capacity(d as usize);
    for i in 0..d {
        let id = base_id + i;
        let b = post(id, vec![padre], u64::from(i) + 1, sr);
        cadena
            .admitir(b.clone())
            .unwrap_or_else(|e| panic!("rama base_id={base_id} i={i}: {e:?}"));
        padre = b.hash();
        ids.push(id);
    }
    (padre, ids)
}

#[test]
#[ignore = "V6; lento, se lanza con --ignored"]
fn reorg_profunda_rival_gana() {
    let d: u32 = std::env::var("W08B_REORG_D")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let mut cadena = Cadena::nueva(params(), K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();

    let t_main = Instant::now();
    let (_punta_main, ids_main) = rama(&mut cadena, d, 10, 10);
    let t_main = t_main.elapsed();

    let t_rival = Instant::now();
    let (punta_rival, ids_rival) = rama(&mut cadena, d, 100_000, 1);
    let t_rival = t_rival.elapsed();

    let cadena_virtual = cadena.cadena_virtual();
    let gano_rival = cadena_virtual.contains(&punta_rival);
    let contiene_main = ids_main
        .iter()
        .any(|id| cadena_virtual.contains(&hash_u32(*id)));
    let contiene_rival = ids_rival
        .iter()
        .any(|id| cadena_virtual.contains(&hash_u32(*id)));

    println!(
        "RES d={d} main_ms={:.1} rival_ms={:.1} admisiones={} valida_rival={gano_rival} \
         cadena_len={} main_en_cadena={contiene_main} rival_en_cadena={contiene_rival} \
         admitidos={}",
        t_main.as_secs_f64() * 1e3,
        t_rival.as_secs_f64() * 1e3,
        2 * d,
        cadena_virtual.len(),
        cadena.bloques_admitidos(),
    );
    assert!(gano_rival, "la rama rival debe ganar la selección");
    assert!(
        !contiene_main,
        "la cadena seleccionada no debe contener la rama perdedora"
    );
    assert!(
        contiene_rival,
        "la cadena seleccionada debe contener la rama rival"
    );
}
