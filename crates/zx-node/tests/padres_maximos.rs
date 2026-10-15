//! `ORDEN-W06a-C` decisión 3: `zx-node` elige **hasta 15 padres** (perfil dev §4), no 3.
//!
//! `Cadena::nueva` recibe `max_padres` como parámetro de construcción sin valor por defecto oculto;
//! el nodo le pasa el del perfil dev (`15`). Se construyen 16 puntas válidas y se comprueba que
//! `padres_de_regimen` usa las 15 primeras (orden de hash) y que el `PadresDag` resultante tiene 15
//! padres, con el seleccionado calculado por el GHOSTDAG real.
//!
//! El caso de admisión de un bloque de 15 padres y rechazo de 16 se cubre en
//! `zx-cadena/tests/padres_e_identidad.rs`; aquí se ejercita la **selección del nodo**.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::{IdentidadGhostdag, IdentidadTicket};
use zx_node::padres::{MAX_PADRES_CADENA, padres_de_regimen};
use zx_node::perfil;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

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

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
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

fn ticket(byte: u8, slot: u64) -> IdentidadGhostdag {
    IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor(byte),
        3,
        1 << 20,
        [byte; 32],
        slot,
    ))
}

fn post(hash_n: u8, padres: Vec<BlockHash>, slot: u64, prod: ClavePublica) -> BloqueCadena {
    BloqueCadena::Post(BloquePost {
        hash: hash(hash_n),
        padres,
        slot,
        timestamp: 0,
        productor: prod,
        peso: 5,
        prueba_valida: true,
        requisito_declarado: 0,
        sr: 1,
        distancia: 0,
        identidad: ticket(hash_n, slot),
        txs: vec![(tx_coinbase_post(prod, 3, slot), Vec::new())],
    })
}

#[test]
fn padres_de_regimen_usa_hasta_quince_puntas() {
    assert_eq!(MAX_PADRES_CADENA, 15);
    assert_eq!(MAX_PADRES_CADENA, usize::from(perfil::MAX_PADRES));

    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, perfil::ghostdag_max_padres());
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis { hash: hash(0) },
            Vec::new(),
        )))
        .unwrap();
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::PoW {
                hash: hash(1),
                padre: hash(0),
                altura: 1,
                trabajo: U256::one(),
                pow_valido: true,
            },
            Vec::new(),
        )))
        .unwrap();
    let terminal = cadena.terminal().unwrap();

    // 16 puntas válidas (un solo padre: el terminal), cada una con su billete real.
    for i in 0..16u8 {
        let slot = u64::from(i) + 1;
        cadena
            .admitir(post(10 + i, vec![terminal], slot, productor(i + 1)))
            .unwrap();
    }
    assert_eq!(cadena.tips_validas().len(), 16);

    let padres = padres_de_regimen(&cadena).unwrap();
    assert_eq!(
        usize::from(padres.count()),
        MAX_PADRES_CADENA,
        "el nodo debe seleccionar el tope del perfil dev"
    );
    assert_eq!(padres.extras().len(), MAX_PADRES_CADENA - 1);

    // Todas las elegidas pertenecen al conjunto de 15 puntas que `padres_de_regimen` usa.
    let mut usadas = cadena.tips_validas();
    usadas.truncate(MAX_PADRES_CADENA);
    assert!(usadas.contains(&padres.seleccionado()));
    for extra in padres.extras() {
        assert!(usadas.contains(extra));
    }
}
