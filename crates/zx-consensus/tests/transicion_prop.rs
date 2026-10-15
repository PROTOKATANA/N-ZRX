//! Propiedades con `proptest` (`ORDEN-W03` V6): undo exacto e `I-1`/`I-1b` sobre secuencias
//! aleatorias de bloques **válidos**.
//!
//! La secuencia se construye con una cadena PoW mínima (coinbase, y un depósito que habilita la
//! garantía) seguida de 0–3 bloques PoST; la entropía decide el número de bloques y los slots. Cada
//! bloque se aplica en orden; si el motor lo acepta, se comprueba el undo y los invariantes. Semilla
//! fija en el código, como el resto del workspace.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use zx_consensus::transicion::{
    BloqueTransicion, Estado, HechosCabecera, ParametrosEvidencia, ParametrosTransicion, aplicar,
    aplicar_con_undo, deshacer, invariante_i1, invariante_i1b,
};
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, HashType, Lock, OutPoint,
    SpentOutput, TipoGarantia, Tx, TxIn, TxOut,
};

fn subsidio_pow_prop(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post_prop(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 2,
        w_min: U256::one(),
        s_min: Amount::nuevo(1).unwrap(),
        q: Amount::nuevo(1).unwrap(),
        k_min: 1,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 2,
        f_slots: None,
        subsidio_pow: subsidio_pow_prop,
        subsidio_post: subsidio_post_prop,
    }
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn par(k: u64) -> (SigningKey, ClavePublica) {
    let mut mensaje = b"zx-w03-prop-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    let sk = SigningKey::from(*digest.as_bytes());
    let vk = VerificationKey::from(&sk);
    (sk, ClavePublica::desde_bytes(vk.into()))
}

fn tx_out(valor: i64, pk: ClavePublica) -> TxOut {
    TxOut {
        value: Amount::nuevo(valor).unwrap(),
        lock: Lock::PubKey { pubkey: pk },
    }
}

fn tx_coinbase_pow(salidas: Vec<TxOut>, expiry_height: u32) -> Tx {
    Tx {
        version: 1,
        inputs: Vec::new(),
        outputs: salidas,
        lock_time: 0,
        expiry_height,
        extension: ExtensionTx::Ninguna,
    }
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

fn tx_deposito(op: OutPoint, clave: ClavePublica, importe: i64) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            outpoint: op,
            sequence: 0,
        }],
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo: TipoGarantia::Deposito,
            clave,
            importe: Amount::nuevo(importe).unwrap(),
            nonce: 0,
        },
    }
}

fn firma(sk: &SigningKey, tx: &Tx, gastadas: &[SpentOutput], i: usize) -> Vec<u8> {
    let digest = zx_core::sighash(tx, gastadas, HashType::All, i, CBID_RED_DEV).unwrap();
    let firma: [u8; 64] = sk.sign(digest.as_bytes()).into();
    firma.to_vec()
}

fn aceptacion(sk: &SigningKey, tx: &Tx) -> Vec<u8> {
    let mensaje = zx_core::mensaje_aceptacion(tx, CBID_RED_DEV);
    let firma: [u8; 64] = sk.sign(&mensaje).into();
    firma.to_vec()
}

/// Genera una historia **válida** a partir de la entropía.
fn generar(entropia: &[u8]) -> Vec<BloqueTransicion> {
    let mut cursor = 0usize;
    let mut siguiente = |n: u32| -> u32 {
        let b = u32::from(entropia.get(cursor).copied().unwrap_or(0));
        cursor = cursor.wrapping_add(1);
        if n == 0 { 0 } else { b % n }
    };
    let params = params();
    let mut estado = Estado::inicial();
    let mut bloques = Vec::new();

    let genesis = BloqueTransicion::nuevo(HechosCabecera::Genesis { hash: hash(0) }, Vec::new());
    estado = aplicar(
        &estado,
        &genesis,
        &params,
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    bloques.push(genesis);

    // PoW h = 1: coinbase a `k1`.
    let (sk1, pk1) = par(1);
    let cb1 = tx_coinbase_pow(vec![tx_out(10, pk1)], 1);
    let op1 = OutPoint {
        prev_txid: zx_core::txid(&cb1, CBID_RED_DEV),
        prev_index: 0,
    };
    let b1 = BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(1),
            padre: hash(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        vec![(cb1, Vec::new())],
    );
    estado = aplicar(
        &estado,
        &b1,
        &params,
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    bloques.push(b1);

    // PoW h = 2: coinbase a `k2` y depósito del coinbase anterior (habilita la garantía).
    let (_sk2, pk2) = par(2);
    let cb2 = tx_coinbase_pow(vec![tx_out(10, pk2)], 2);
    let dep = tx_deposito(op1, pk1, 10);
    let gastadas = vec![SpentOutput {
        value: Amount::nuevo(10).unwrap(),
        lock: Lock::PubKey { pubkey: pk1 },
    }];
    let testigos = vec![firma(&sk1, &dep, &gastadas, 0), aceptacion(&sk1, &dep)];
    let b2 = BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(2),
            padre: hash(1),
            altura: 2,
            trabajo: U256::one(),
            pow_valido: true,
        },
        vec![(cb2, Vec::new()), (dep, testigos)],
    );
    estado = aplicar(
        &estado,
        &b2,
        &params,
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    bloques.push(b2);

    // 0–3 bloques PoST acreditando al productor con garantía (`k1`).
    let n_post = siguiente(4);
    let mut slot = 0u64;
    let mut padre = hash(2);
    for i in 0..n_post {
        slot = slot
            .saturating_add(1)
            .saturating_add(u64::from(siguiente(2)));
        let cb = tx_coinbase_post(pk1, 3, slot);
        let post = BloqueTransicion::nuevo(
            HechosCabecera::PoST {
                hash: hash(10 + i as u8),
                padre,
                slot,
                productor: pk1,
                peso: 1,
                prueba_valida: true,
                requisito_declarado: 0,
            },
            vec![(cb, Vec::new())],
        );
        let Ok(nuevo) = aplicar(
            &estado,
            &post,
            &params,
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva(),
        ) else {
            break;
        };
        padre = hash(10 + i as u8);
        estado = nuevo;
        bloques.push(post);
    }
    bloques
}

proptest! {
    #![proptest_config(ProptestConfig {
        rng_seed: RngSeed::Fixed(0x5a5a),
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// `deshacer(aplicar_con_undo(E, B)) == E` e `I-1`/`I-1b` en cada paso.
    #[test]
    fn undo_exacto_e_i1_en_secuencias_validas(
        entropia in prop::collection::vec(any::<u8>(), 4..40),
    ) {
        let bloques = generar(&entropia);
        let mut estado = Estado::inicial();
        for bloque in &bloques {
            let (nuevo, undo) =
                aplicar_con_undo(&estado, bloque, &params(), CBID_RED_DEV, &ParametrosEvidencia::inactiva()).unwrap();
            prop_assert_eq!(&deshacer(&nuevo, &undo), &estado);
            prop_assert!(invariante_i1(&nuevo));
            prop_assert!(invariante_i1b(&nuevo));
            estado = nuevo;
        }
        // La secuencia siempre incluye génesis + 2 PoW.
        prop_assert!(bloques.len() >= 3);
    }

    /// Aplicar dos veces el mismo bloque desde el mismo estado es determinista.
    #[test]
    fn la_aplicacion_es_determinista(
        entropia in prop::collection::vec(any::<u8>(), 4..40),
    ) {
        let bloques = generar(&entropia);
        let mut estado = Estado::inicial();
        for bloque in &bloques {
            let a = aplicar(&estado, bloque, &params(), CBID_RED_DEV, &ParametrosEvidencia::inactiva()).unwrap();
            let b = aplicar(&estado, bloque, &params(), CBID_RED_DEV, &ParametrosEvidencia::inactiva()).unwrap();
            prop_assert_eq!(a, b);
            estado = aplicar(&estado, bloque, &params(), CBID_RED_DEV, &ParametrosEvidencia::inactiva()).unwrap();
        }
    }
}
