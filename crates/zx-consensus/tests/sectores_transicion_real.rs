//! SR-1-2 · la **transición real** (`transicion::aplicar_con_undo`) aplica un alta de sector v5 y
//! su `deshacer` restituye el estado bit a bit.
//!
//! A diferencia del diferencial V2 (que replega bloques del oráculo), aquí se construye un
//! [`BloqueTransicion`] PoW real con una `Tx` v5 **firmada** por la clave del sector y se ejerce el
//! mismo motor que aplica los bloques de la cadena.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "el test falla con panic por diseño"
)]

use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo, deshacer,
};
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, OperacionSector, Tx,
    mensaje_sector,
};

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
        // Alto para que el primer bloque PoW no fije terminal y el segundo pueda aplicarse.
        h_corte_min: 1000,
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
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn clave_y_firma(n: u8) -> (SigningKey, ClavePublica) {
    let sk = SigningKey::from([n; 32]);
    let vk = VerificationKey::from(&sk);
    (sk, ClavePublica::desde_bytes(vk.into()))
}

#[test]
fn la_transicion_real_aplica_y_deshace_un_alta_de_sector() {
    let (sk, clave) = clave_y_firma(7);
    let mut est = Estado::inicial();
    est.fase = Fase::PoW;
    // Fondea la clave por encima de `q_sec` del perfil dev (140).
    est.garantias.insert(
        clave,
        Garantia {
            activo: Amount::nuevo(500).unwrap(),
            ..Garantia::nueva()
        },
    );

    let op = OperacionSector::Alta {
        clave,
        sector_index: 0,
        version: 0,
        r2: [3u8; 32],
        history_size: 1 << 20,
    };
    let tx = Tx {
        version: 5,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Sector {
            operacion: op.clone(),
        },
    };
    let firma: [u8; 64] = sk.sign(&mensaje_sector(&tx, CBID_RED_DEV)).into();
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(1),
            padre: hash(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        vec![(tx.clone(), vec![firma.to_vec()])],
    );

    let (nuevo, undo) = aplicar_con_undo(
        &est,
        &bloque,
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .expect("el alta de sector v5 debe ser válida");

    assert_eq!(
        nuevo.sectores.len(),
        1,
        "la transición real debe poblar Estado::sectores"
    );
    let (id, reg) = nuevo.sectores.iter().next().unwrap();
    assert_eq!(id.clave, clave);
    assert_eq!(id.sector_index, 0);
    assert_eq!(id.version, 0);
    assert_eq!(reg.fianza, nuevo.parametros_sector.q_sec);
    // La fianza se debitó del activo.
    assert_eq!(
        nuevo.garantias.get(&clave).unwrap().activo.brek(),
        500 - nuevo.parametros_sector.q_sec
    );

    let restaurado = deshacer(&nuevo, &undo);
    assert_eq!(restaurado, est, "el undo debe ser bit a bit");

    // Una operación de sector inválida (segunda alta v0) invalida el bloque.
    let bloque2 = BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(2),
            padre: hash(1),
            altura: 2,
            trabajo: U256::one(),
            pow_valido: true,
        },
        vec![(tx.clone(), vec![firma.to_vec()])],
    );
    let err = aplicar_con_undo(
        &nuevo,
        &bloque2,
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .expect_err("la doble alta debe rechazarse");
    assert!(
        matches!(
            err,
            zx_consensus::transicion::ErrorTransicion::ErrSector(
                zx_consensus::sectores::MotivoSector::ErrDobleAlta
            )
        ),
        "se esperaba ErrSector(ErrDobleAlta), salió {err:?}"
    );
}
