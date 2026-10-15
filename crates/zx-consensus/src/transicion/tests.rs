//! Tests unitarios del motor de transición (`ORDEN-W03` V5).
//!
//! Cubren lo que el arnés diferencial contra T01 **no** cubre: el testigo real, el cambio de un
//! depósito (F-07), `MultiSig`, y los rechazos de coinbase/Posición/productor. Los tests del
//! diferencial viven en `tests/diferencial_t01.rs`.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre arrays de tamaño fijo en el test"
)]

use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, HashType, Lock, OutPoint,
    SpentOutput, TipoGarantia, Tx, TxId, TxIn, TxOut,
};

use crate::transicion::estado::{invariante_i1, invariante_i1b};
use crate::transicion::{
    BloqueTransicion, EnRetirada, EntradaUtxo, ErrorTransicion, Estado, Fase, Garantia,
    HechosCabecera, Origen, ParametrosEvidencia, ParametrosTransicion, Punto, aplicar,
    aplicar_con_undo, aplicar_fusion, deshacer,
};

fn subsidio_pow_test(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post_test(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 100,
        w_min: U256::one(),
        s_min: Amount::nuevo(1).unwrap(),
        q: Amount::nuevo(1).unwrap(),
        k_min: 1,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 3,
        f_slots: None,
        subsidio_pow: subsidio_pow_test,
        subsidio_post: subsidio_post_test,
    }
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn par(semilla: u8) -> (SigningKey, ClavePublica) {
    let sk = SigningKey::from([semilla; 32]);
    let vk = VerificationKey::from(&sk);
    (sk, ClavePublica::desde_bytes(vk.into()))
}

fn outpoint(n: u8, idx: u32) -> OutPoint {
    OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
        prev_index: idx,
    }
}

fn txin(op: OutPoint) -> TxIn {
    TxIn {
        outpoint: op,
        sequence: 0,
    }
}

fn tx_out(valor: i64, pk: ClavePublica) -> TxOut {
    TxOut {
        value: Amount::nuevo(valor).unwrap(),
        lock: Lock::PubKey { pubkey: pk },
    }
}

fn entrada(valor: i64, lock: Lock, origen: Origen, creada: Punto) -> EntradaUtxo {
    EntradaUtxo {
        valor: Amount::nuevo(valor).unwrap(),
        lock,
        origen,
        creada,
    }
}

fn tx_coinbase_pow(salidas: Vec<TxOut>) -> Tx {
    Tx {
        version: 1,
        inputs: Vec::new(),
        outputs: salidas,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

/// Coinbase PoW con `expiry_height` explícito (F-16).
fn tx_coinbase_pow_exp(salidas: Vec<TxOut>, expiry_height: u32) -> Tx {
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

fn tx_transferencia(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Tx {
    Tx {
        version: 1,
        inputs,
        outputs,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

fn tx_garantia(tipo: TipoGarantia, clave: ClavePublica, importe: i64, nonce: u64) -> Tx {
    Tx {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo,
            clave,
            importe: Amount::nuevo(importe).unwrap(),
            nonce,
        },
    }
}

fn tx_deposito(inputs: Vec<TxIn>, outputs: Vec<TxOut>, clave: ClavePublica, importe: i64) -> Tx {
    Tx {
        version: 2,
        inputs,
        outputs,
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

fn firma_entrada(sk: &SigningKey, tx: &Tx, gastadas: &[SpentOutput], i: usize) -> Vec<u8> {
    let digest = zx_core::sighash(tx, gastadas, HashType::All, i, CBID_RED_DEV).unwrap();
    let firma: [u8; 64] = sk.sign(digest.as_bytes()).into();
    firma.to_vec()
}

fn aceptacion(sk: &SigningKey, tx: &Tx) -> Vec<u8> {
    let mensaje = zx_core::mensaje_aceptacion(tx, CBID_RED_DEV);
    let firma: [u8; 64] = sk.sign(&mensaje).into();
    firma.to_vec()
}

fn estado_pow() -> Estado {
    let mut estado = Estado::inicial();
    estado.fase = Fase::PoW;
    estado
}

fn estado_post() -> Estado {
    let mut estado = Estado::inicial();
    estado.fase = Fase::PoST;
    estado
}

fn con_garantia(estado: &mut Estado, pk: ClavePublica, activo: i64) {
    estado.garantias.insert(
        pk,
        Garantia {
            activo: Amount::nuevo(activo).unwrap(),
            pendientes: Vec::new(),
            en_retirada: Vec::new(),
            congelado: Amount::CERO,
            creditos: Vec::new(),
            nonce_siguiente: 0,
            incidentes: Vec::new(),
        },
    );
}

fn bloque_pow(altura: u32, txs: Vec<(Tx, Vec<Vec<u8>>)>) -> BloqueTransicion {
    BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(1),
            padre: hash(0),
            altura,
            trabajo: U256::one(),
            pow_valido: true,
        },
        txs,
    )
}

fn bloque_post(
    slot: u64,
    productor: ClavePublica,
    txs: Vec<(Tx, Vec<Vec<u8>>)>,
) -> BloqueTransicion {
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash(2),
            padre: hash(1),
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        txs,
    )
}

// ── V5 · testigo real ──────────────────────────────────────────────────────

/// Regresión `compromiso != autorización`: un testigo criptográficamente inválido puede coincidir
/// con el `body_commitment` calculado sobre él, y el motor lo rechaza igualmente.
#[test]
fn un_testigo_invalido_puede_coincidir_con_el_compromiso() {
    let (_, pk) = par(42);
    let op = outpoint(7, 0);
    let tx = tx_transferencia(vec![txin(op)], vec![tx_out(9, pk)]);
    let testigos: Vec<Vec<u8>> = vec![vec![0x00u8; 64]];

    let compromiso = zx_core::body_commitment(
        std::slice::from_ref(&tx),
        std::slice::from_ref(&testigos),
        CBID_RED_DEV,
    )
    .unwrap();
    let recomputado = zx_core::body_commitment(
        std::slice::from_ref(&tx),
        std::slice::from_ref(&testigos),
        CBID_RED_DEV,
    )
    .unwrap();
    assert_eq!(
        compromiso, recomputado,
        "el compromiso es fiel a los testigos inválidos"
    );

    let mut estado = estado_pow();
    estado.utxo.insert(
        op,
        entrada(
            10,
            Lock::PubKey { pubkey: pk },
            Origen::Tx,
            Punto::Altura(0),
        ),
    );
    let bloque = bloque_pow(1, vec![(tx, testigos)]);
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrFirma),
        "la verificación criptográfica MUST rechazarlos"
    );
}

// ── V5 · depósito con cambio (F-07) ────────────────────────────────────────

#[test]
fn deposito_con_cambio_crea_el_cambio_y_acredita_la_garantia() {
    let (sk, pk) = par(1);
    let op = outpoint(7, 0);
    let tx = tx_deposito(vec![txin(op)], vec![tx_out(4, pk)], pk, 6);
    let gastadas = vec![SpentOutput {
        value: Amount::nuevo(10).unwrap(),
        lock: Lock::PubKey { pubkey: pk },
    }];
    let mut testigos = vec![firma_entrada(&sk, &tx, &gastadas, 0)];
    testigos.push(aceptacion(&sk, &tx));

    let mut estado = estado_pow();
    estado.utxo.insert(
        op,
        entrada(
            10,
            Lock::PubKey { pubkey: pk },
            Origen::Tx,
            Punto::Altura(0),
        ),
    );
    // Estado de partida consistente con I-1 (UTXO 10).
    estado.emitido = 10;
    estado.subsidio_acum = 10;
    let bloque = bloque_pow(1, vec![(tx, testigos)]);
    let nuevo = aplicar(
        &estado,
        &bloque,
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();

    assert!(invariante_i1(&nuevo));
    assert!(invariante_i1b(&nuevo));
    assert_eq!(nuevo.activo_de(&pk), Amount::nuevo(6).unwrap());
    assert!(
        nuevo
            .utxo
            .values()
            .any(|e| e.valor == Amount::nuevo(4).unwrap() && e.origen == Origen::Tx),
        "el cambio MUST existir en el UTXO"
    );
}

// ── V5 · MultiSig ──────────────────────────────────────────────────────────

#[test]
fn multisig_2_de_3_autoriza_y_el_orden_importa() {
    let (sk0, pk0) = par(10);
    let (_, pk1) = par(11);
    let (sk2, pk2) = par(12);
    let lock = Lock::multisig(2, vec![pk0, pk1, pk2]).unwrap();
    let op = outpoint(9, 0);
    let tx = tx_transferencia(vec![txin(op)], vec![tx_out(9, pk0)]);
    let gastadas = vec![SpentOutput {
        value: Amount::nuevo(10).unwrap(),
        lock: lock.clone(),
    }];
    let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID_RED_DEV).unwrap();
    let f0: [u8; 64] = sk0.sign(digest.as_bytes()).into();
    let f2: [u8; 64] = sk2.sign(digest.as_bytes()).into();

    let mut ordenado = vec![0u8];
    ordenado.extend_from_slice(&f0);
    ordenado.push(2u8);
    ordenado.extend_from_slice(&f2);

    let mut desordenado = vec![2u8];
    desordenado.extend_from_slice(&f2);
    desordenado.push(0u8);
    desordenado.extend_from_slice(&f0);

    let mut estado = estado_pow();
    estado
        .utxo
        .insert(op, entrada(10, lock, Origen::Tx, Punto::Altura(0)));
    let valido = bloque_pow(1, vec![(tx.clone(), vec![ordenado])]);
    assert!(
        aplicar(
            &estado,
            &valido,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        )
        .is_ok()
    );

    let invalido = bloque_pow(1, vec![(tx, vec![desordenado])]);
    assert_eq!(
        aplicar(
            &estado,
            &invalido,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrFirma),
        "los índices de MultiSig MUST ser estrictamente crecientes"
    );
}

// ── V5 · rechazos de coinbase ──────────────────────────────────────────────

#[test]
fn coinbase_pow_sin_salidas_se_rechaza() {
    let (_, _pk) = par(3);
    let estado = estado_pow();
    let bloque = bloque_pow(1, vec![(tx_coinbase_pow(Vec::new()), Vec::new())]);
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrEmision)
    );
}

#[test]
fn dos_coinbases_se_rechazan() {
    let (_, pk) = par(4);
    let estado = estado_pow();
    let cb = tx_coinbase_pow(vec![tx_out(1, pk)]);
    let bloque = bloque_pow(1, vec![(cb.clone(), Vec::new()), (cb, Vec::new())]);
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrEmision)
    );
}

#[test]
fn coinbase_post_en_posicion_dos_se_rechaza() {
    let (sk, pk) = par(5);
    let estado = {
        let mut e = estado_post();
        con_garantia(&mut e, pk, 10);
        e
    };
    let retiro = tx_garantia(TipoGarantia::Retiro, pk, 1, 0);
    let testigo = aceptacion(&sk, &retiro);
    let cb = tx_coinbase_post(pk, 3, 1);
    let bloque = bloque_post(1, pk, vec![(retiro, vec![testigo]), (cb, Vec::new())]);
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrEmision)
    );
}

#[test]
fn coinbase_post_a_otra_clave_se_rechaza() {
    let (_, pk) = par(6);
    let (_, otra) = par(7);
    let estado = {
        let mut e = estado_post();
        con_garantia(&mut e, pk, 10);
        e
    };
    let cb = tx_coinbase_post(otra, 3, 1);
    let bloque = bloque_post(1, pk, vec![(cb, Vec::new())]);
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrAutorizacion)
    );
}

// ── V5 · modo fusión ───────────────────────────────────────────────────────

#[test]
fn fusion_descarta_doble_gasto() {
    let (sk, pk) = par(20);
    let op = outpoint(5, 0);
    let t1 = tx_transferencia(vec![txin(op)], vec![tx_out(9, pk)]);
    let t2 = tx_transferencia(vec![txin(op)], vec![tx_out(8, pk)]);
    let gastadas = vec![SpentOutput {
        value: Amount::nuevo(10).unwrap(),
        lock: Lock::PubKey { pubkey: pk },
    }];
    let w1 = vec![firma_entrada(&sk, &t1, &gastadas, 0)];
    let w2 = vec![firma_entrada(&sk, &t2, &gastadas, 0)];
    let cb = tx_coinbase_post(pk, 3, 1);

    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.utxo.insert(
        op,
        entrada(
            10,
            Lock::PubKey { pubkey: pk },
            Origen::Tx,
            Punto::Altura(0),
        ),
    );
    // Estado de partida consistente con I-1 (UTXO 10 + garantía 10).
    estado.emitido = 20;
    estado.subsidio_acum = 20;
    let bloque = bloque_post(1, pk, vec![(cb, Vec::new()), (t1, w1), (t2, w2)]);
    let (nuevo, _undo, descartadas) = aplicar_fusion(
        &estado,
        &bloque,
        Punto::Slot(1),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert_eq!(descartadas.len(), 1);
    assert_eq!(descartadas[0].motivo, ErrorTransicion::ErrDobleGasto);
    assert!(invariante_i1(&nuevo));
}

#[test]
fn fusion_descarta_retiro_duplicado() {
    let (sk, pk) = par(21);
    let t1 = tx_garantia(TipoGarantia::Retiro, pk, 3, 0);
    let t2 = tx_garantia(TipoGarantia::Retiro, pk, 2, 1);
    let w1 = vec![aceptacion(&sk, &t1)];
    let w2 = vec![aceptacion(&sk, &t2)];
    let cb = tx_coinbase_post(pk, 3, 1);

    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.emitido = 10;
    estado.subsidio_acum = 10;
    let bloque = bloque_post(1, pk, vec![(cb, Vec::new()), (t1, w1), (t2, w2)]);
    let (nuevo, _undo, descartadas) = aplicar_fusion(
        &estado,
        &bloque,
        Punto::Slot(1),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert_eq!(descartadas.len(), 1);
    assert_eq!(descartadas[0].motivo, ErrorTransicion::ErrRetiroPendiente);
    let g = nuevo.garantias.get(&pk).unwrap();
    assert_eq!(g.activo, Amount::nuevo(7).unwrap());
    assert_eq!(g.en_retirada.len(), 1);
}

#[test]
fn fusion_descarta_liberacion_prematura() {
    let (sk, pk) = par(22);
    let t1 = tx_garantia(TipoGarantia::Liberacion, pk, 5, 0);
    let w1 = vec![aceptacion(&sk, &t1)];
    let cb = tx_coinbase_post(pk, 3, 1);

    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 1);
    if let Some(g) = estado.garantias.get_mut(&pk) {
        g.en_retirada.push(EnRetirada {
            importe: Amount::nuevo(5).unwrap(),
            inicio_slot: 0,
        });
    }
    estado.emitido = 6;
    estado.subsidio_acum = 6;
    let bloque = bloque_post(1, pk, vec![(cb, Vec::new()), (t1, w1)]);
    let (nuevo, _undo, descartadas) = aplicar_fusion(
        &estado,
        &bloque,
        Punto::Slot(1),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert_eq!(descartadas.len(), 1);
    assert_eq!(descartadas[0].motivo, ErrorTransicion::ErrSaldo);
    let _ = nuevo;
}

#[test]
fn fusion_recorta_la_coinbase_post() {
    let (_, pk) = par(23);
    let cb = tx_coinbase_post(pk, 100, 1);
    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.emitido = 10;
    estado.subsidio_acum = 10;
    let bloque = bloque_post(1, pk, vec![(cb, Vec::new())]);
    let (nuevo, _undo, descartadas) = aplicar_fusion(
        &estado,
        &bloque,
        Punto::Slot(1),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert!(descartadas.is_empty());
    let g = nuevo.garantias.get(&pk).unwrap();
    assert_eq!(
        g.activo,
        Amount::nuevo(10).unwrap(),
        "no se emite el exceso"
    );
    assert_eq!(g.creditos.len(), 1);
    assert_eq!(g.creditos[0].importe, Amount::nuevo(3).unwrap());
    assert_eq!(g.creditos[0].madura_en_slot, Some(2));
    assert!(invariante_i1(&nuevo));
    assert!(invariante_i1b(&nuevo));
}

/// **TX-2b · DEP-FEE en fusión (C-BON-03/TX-R-40).** Un depósito que paga tarifa la aporta al
/// bloque; un depósito descartado **no** acredita la suya y la coinbase se recorta a
/// `subsidio_post(slot) + Σ tarifas aceptadas`.
#[test]
fn fusion_dep_fee_acredita_solo_las_tarifas_aceptadas() {
    let (sk, pk) = par(30);
    let op = outpoint(30, 0);
    let valor = 10;
    // Depósito A: importe 8 sobre una entrada de 10 ⇒ tarifa 2 (DEP-FEE, `Σ entradas ≥ importe`).
    let d_a = tx_deposito(vec![txin(op)], Vec::new(), pk, 8);
    let gastadas = vec![SpentOutput {
        value: Amount::nuevo(valor).unwrap(),
        lock: Lock::PubKey { pubkey: pk },
    }];
    let mut w_a = vec![firma_entrada(&sk, &d_a, &gastadas, 0)];
    w_a.push(aceptacion(&sk, &d_a));
    // Depósito B: el mismo `OutPoint` (doble gasto) ⇒ se descarta y no aporta tarifa.
    let d_b = tx_deposito_nonce(vec![txin(op)], Vec::new(), pk, 7, 1);
    let mut w_b = vec![firma_entrada(&sk, &d_b, &gastadas, 0)];
    w_b.push(aceptacion(&sk, &d_b));
    // La coinbase declara `subsidio_post(1) + 2·2 = 3 + 4 = 7`; en fusión se recorta a `3 + 2 = 5`.
    let cb = tx_coinbase_post(pk, 7, 1);

    let mut estado = estado_post();
    estado.utxo.insert(
        op,
        entrada(
            valor,
            Lock::PubKey { pubkey: pk },
            Origen::Tx,
            Punto::Altura(0),
        ),
    );
    estado.emitido = 10;
    estado.subsidio_acum = 10;

    let bloque = bloque_post(1, pk, vec![(cb, Vec::new()), (d_a, w_a), (d_b, w_b)]);
    let (nuevo, _undo, descartadas) = aplicar_fusion(
        &estado,
        &bloque,
        Punto::Slot(1),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();

    assert_eq!(descartadas.len(), 1, "el segundo depósito se descarta");
    assert_eq!(descartadas[0].motivo, ErrorTransicion::ErrDobleGasto);
    let g = nuevo.garantias.get(&pk).unwrap();
    // El depósito A acredita su importe (8) como pendiente (madura en el slot 2 = 1 + M_dep_slots);
    // la tarifa aceptada es 2 y la coinbase recortada 5.
    assert_eq!(g.activo, Amount::CERO);
    assert_eq!(g.pendientes.len(), 1);
    assert_eq!(g.pendientes[0].importe, Amount::nuevo(8).unwrap());
    assert_eq!(g.creditos.len(), 1);
    assert_eq!(
        g.creditos[0].importe,
        Amount::nuevo(5).unwrap(),
        "la coinbase se recorta a subsidio + tarifas aceptadas (3 + 2)"
    );
    assert!(invariante_i1(&nuevo));
}

// ── V5 · F-15 (nonce por clave) ────────────────────────────────────────────

fn tx_deposito_nonce(
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    clave: ClavePublica,
    importe: i64,
    nonce: u64,
) -> Tx {
    Tx {
        version: 2,
        inputs,
        outputs,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo: TipoGarantia::Deposito,
            clave,
            importe: Amount::nuevo(importe).unwrap(),
            nonce,
        },
    }
}

/// F-15 · dos operaciones de la misma clave con nonces `n, n+1` son válidas y dejan
/// `nonce_siguiente = n+2`; con el mismo nonce `n, n` la segunda invalida el bloque estricto.
#[test]
fn dos_depositos_con_nonces_consecutivos_valen_y_la_repeticion_no() {
    let (sk, pk) = par(40);
    let op1 = outpoint(11, 0);
    let op2 = outpoint(12, 0);
    let d1 = tx_deposito_nonce(vec![txin(op1)], Vec::new(), pk, 10, 0);
    let d2 = tx_deposito_nonce(vec![txin(op2)], Vec::new(), pk, 10, 1);
    let g1 = vec![SpentOutput {
        value: Amount::nuevo(10).unwrap(),
        lock: Lock::PubKey { pubkey: pk },
    }];
    let g2 = g1.clone();
    let w1 = vec![firma_entrada(&sk, &d1, &g1, 0), aceptacion(&sk, &d1)];
    let w2 = vec![firma_entrada(&sk, &d2, &g2, 0), aceptacion(&sk, &d2)];

    let mut estado = estado_pow();
    for op in [op1, op2] {
        estado.utxo.insert(
            op,
            entrada(
                10,
                Lock::PubKey { pubkey: pk },
                Origen::Tx,
                Punto::Altura(0),
            ),
        );
    }
    estado.emitido = 20;
    estado.subsidio_acum = 20;

    let bloque_ok = bloque_pow(1, vec![(d1.clone(), w1.clone()), (d2.clone(), w2.clone())]);
    let nuevo = aplicar(
        &estado,
        &bloque_ok,
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    let g = nuevo.garantias.get(&pk).unwrap();
    assert_eq!(g.activo, Amount::nuevo(20).unwrap());
    assert_eq!(g.nonce_siguiente, 2, "cada operación incrementa el nonce");

    let d2_repetido = tx_deposito_nonce(vec![txin(op2)], Vec::new(), pk, 10, 0);
    let g2r = vec![SpentOutput {
        value: Amount::nuevo(10).unwrap(),
        lock: Lock::PubKey { pubkey: pk },
    }];
    let w2r = vec![
        firma_entrada(&sk, &d2_repetido, &g2r, 0),
        aceptacion(&sk, &d2_repetido),
    ];
    let bloque_mal = bloque_pow(1, vec![(d1.clone(), w1), (d2_repetido, w2r)]);
    assert_eq!(
        aplicar(
            &estado,
            &bloque_mal,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrNonce)
    );
    let _ = d2;
}

/// F-15 · repetición exacta de un retiro ya aplicado: el bloque estricto es inválido.
#[test]
fn repeticion_de_retiro_invalida_el_bloque_estricto() {
    let (sk, pk) = par(41);
    let retiro = tx_garantia(TipoGarantia::Retiro, pk, 3, 0);
    let w = vec![aceptacion(&sk, &retiro)];
    let cb = tx_coinbase_post(pk, 3, 1);

    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.emitido = 10;
    estado.subsidio_acum = 10;

    let bloque = bloque_post(
        1,
        pk,
        vec![(cb, Vec::new()), (retiro.clone(), w.clone()), (retiro, w)],
    );
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrNonce)
    );
}

/// F-15 · repetición exacta de una liberación ya aplicada: el bloque estricto es inválido.
#[test]
fn repeticion_de_liberacion_invalida_el_bloque_estricto() {
    let (sk, pk) = par(42);
    let lib = tx_garantia(TipoGarantia::Liberacion, pk, 5, 0);
    let w = vec![aceptacion(&sk, &lib)];
    let cb = tx_coinbase_post(pk, 3, 3);

    let mut estado = estado_post();
    // RET-1a · RV-3 se neutraliza en esta prueba de repetición de nonce: con `r_votos_slots = 0`
    // la primera liberación vence a `r_slots` como antes y la segunda cae por `ErrNonce`.
    estado.parametros_sector.r_votos_slots = 0;
    estado.garantias.insert(
        pk,
        Garantia {
            activo: Amount::nuevo(6).unwrap(),
            pendientes: Vec::new(),
            en_retirada: vec![EnRetirada {
                importe: Amount::nuevo(5).unwrap(),
                inicio_slot: 0,
            }],
            congelado: Amount::CERO,
            creditos: Vec::new(),
            nonce_siguiente: 0,
            incidentes: Vec::new(),
        },
    );
    estado.emitido = 11;
    estado.subsidio_acum = 11;

    let bloque = bloque_post(
        3,
        pk,
        vec![(cb, Vec::new()), (lib.clone(), w.clone()), (lib, w)],
    );
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrNonce)
    );
}

/// F-15 · en modo fusión la repetición se **descarta** con motivo `ErrNonce`, no invalida el bloque.
#[test]
fn fusion_descarta_repeticion_con_err_nonce() {
    let (sk, pk) = par(43);
    let retiro = tx_garantia(TipoGarantia::Retiro, pk, 3, 0);
    let w = vec![aceptacion(&sk, &retiro)];
    let cb = tx_coinbase_post(pk, 3, 1);

    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.emitido = 10;
    estado.subsidio_acum = 10;

    let bloque = bloque_post(
        1,
        pk,
        vec![(cb, Vec::new()), (retiro.clone(), w.clone()), (retiro, w)],
    );
    let (nuevo, _undo, descartadas) = aplicar_fusion(
        &estado,
        &bloque,
        Punto::Slot(1),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert_eq!(descartadas.len(), 1);
    assert_eq!(descartadas[0].motivo, ErrorTransicion::ErrNonce);
    let g = nuevo.garantias.get(&pk).unwrap();
    assert_eq!(g.nonce_siguiente, 1, "solo la primera operación se aplica");
}

/// F-15 · el nonce se comprueba **antes** que el resto de reglas: un retiro con nonce equivocado
/// y saldo insuficiente da `ErrNonce`, no `ErrSaldo`.
#[test]
fn el_nonce_se_comprueba_antes_que_el_saldo() {
    let (sk, pk) = par(44);
    let retiro = tx_garantia(TipoGarantia::Retiro, pk, 9_999, 7);
    let w = vec![aceptacion(&sk, &retiro)];
    let cb = tx_coinbase_post(pk, 3, 1);

    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.emitido = 10;
    estado.subsidio_acum = 10;

    let bloque = bloque_post(1, pk, vec![(cb, Vec::new()), (retiro, w)]);
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrNonce)
    );
}

/// F-15 · el undo por delta restituye `nonce_siguiente`.
#[test]
fn el_undo_restituye_el_nonce() {
    let (sk, pk) = par(45);
    let retiro = tx_garantia(TipoGarantia::Retiro, pk, 3, 0);
    let w = vec![aceptacion(&sk, &retiro)];
    let cb = tx_coinbase_post(pk, 3, 1);

    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.emitido = 10;
    estado.subsidio_acum = 10;

    let bloque = bloque_post(1, pk, vec![(cb, Vec::new()), (retiro, w)]);
    let (nuevo, undo) = aplicar_con_undo(
        &estado,
        &bloque,
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert_eq!(nuevo.garantias.get(&pk).unwrap().nonce_siguiente, 1);
    assert_eq!(deshacer(&nuevo, &undo), estado);
    assert_eq!(
        deshacer(&nuevo, &undo)
            .garantias
            .get(&pk)
            .unwrap()
            .nonce_siguiente,
        0
    );
}

// ── V5 · F-16 (coinbase PoW única por altura) ──────────────────────────────

/// F-16 · la coinbase PoW exige `expiry_height == altura`; cualquier otro valor ⇒ `ErrEmision`.
#[test]
fn la_coinbase_pow_exige_expiry_igual_a_la_altura() {
    let (_, pk) = par(46);
    let estado = estado_pow();

    for expiry in [0u32, 2, 99] {
        let cb = tx_coinbase_pow_exp(vec![tx_out(1, pk)], expiry);
        let bloque = bloque_pow(1, vec![(cb, Vec::new())]);
        assert_eq!(
            aplicar(
                &estado,
                &bloque,
                &params(),
                CBID_RED_DEV,
                &ParametrosEvidencia::inactiva()
            ),
            Err(ErrorTransicion::ErrEmision),
            "expiry {expiry} ≠ altura 1"
        );
    }

    let cb = tx_coinbase_pow_exp(vec![tx_out(1, pk)], 1);
    let bloque = bloque_pow(1, vec![(cb, Vec::new())]);
    assert!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        )
        .is_ok()
    );
}

/// F-16 · dos coinbases PoW idénticas salvo la altura (y por tanto el `expiry_height`) tienen
/// `txid` distintos y no colisionan en el UTXO.
#[test]
fn dos_coinbases_pow_iguales_salvo_altura_no_colisionan() {
    let (_, pk) = par(47);
    let cb1 = tx_coinbase_pow_exp(vec![tx_out(5, pk)], 1);
    let cb2 = tx_coinbase_pow_exp(vec![tx_out(5, pk)], 2);
    assert_ne!(
        zx_core::txid(&cb1, CBID_RED_DEV),
        zx_core::txid(&cb2, CBID_RED_DEV),
        "el expiry (altura) entra en el txid"
    );

    let estado = estado_pow();
    let s1 = aplicar(
        &estado,
        &bloque_pow(1, vec![(cb1, Vec::new())]),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    let s2 = aplicar(
        &s1,
        &bloque_pow(2, vec![(cb2, Vec::new())]),
        &params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert_eq!(s2.utxo.len(), 2, "las dos coinbases coexisten");
}

// ── V5 · F-17 (coinbase PoST única por bloque y slot) ──────────────────────

/// F-17 · el `slot` de la v3 MUST ser el del bloque; otro valor ⇒ `ErrEmision`.
#[test]
fn la_coinbase_post_exige_el_slot_del_bloque() {
    let (_, pk) = par(48);
    let mut estado = estado_post();
    con_garantia(&mut estado, pk, 10);
    estado.emitido = 10;
    estado.subsidio_acum = 10;

    for slot in [0u64, 2, 99] {
        let cb = tx_coinbase_post(pk, 3, slot);
        let bloque = bloque_post(1, pk, vec![(cb, Vec::new())]);
        assert_eq!(
            aplicar(
                &estado,
                &bloque,
                &params(),
                CBID_RED_DEV,
                &ParametrosEvidencia::inactiva()
            ),
            Err(ErrorTransicion::ErrEmision),
            "slot {slot} ≠ slot del bloque 1"
        );
    }

    let cb = tx_coinbase_post(pk, 3, 1);
    let bloque = bloque_post(1, pk, vec![(cb, Vec::new())]);
    assert!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        )
        .is_ok()
    );
}

// ── PT-3bc · dos pruebas de almacenamiento en un bloque ────────────────────

/// Una tx v6 de prueba de almacenamiento (clase `0x02`).
fn tx_v6_prueba(clave: ClavePublica) -> Tx {
    Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: zx_core::OperacionAlmacenamiento::PoSt {
                clave,
                epoch: 1,
                n_sectores: 1,
                raiz_conjunto: [0; 32],
                prueba: vec![1],
            },
        },
    }
}

/// `REVISION-PT3a` decisión 3: dos tx v6 de clase `0x01`/`0x02` en un bloque lo invalidan.
#[test]
fn un_bloque_con_dos_pruebas_de_almacenamiento_es_invalido() {
    let (_, pk) = par(7);
    let t = vec![vec![0u8; 64]];
    let bloque = bloque_post(
        1,
        pk,
        vec![(tx_v6_prueba(pk), t.clone()), (tx_v6_prueba(pk), t.clone())],
    );
    let estado = estado_post();
    assert_eq!(
        aplicar(
            &estado,
            &bloque,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrDosPruebasAlmacenamiento)
    );

    // La misma tx repetida **una** vez no dispara la regla de forma (fallará más tarde por firma,
    // pero no con `ErrDosPruebasAlmacenamiento`).
    let bloque_uno = bloque_post(1, pk, vec![(tx_v6_prueba(pk), t)]);
    assert_ne!(
        aplicar(
            &estado,
            &bloque_uno,
            &params(),
            CBID_RED_DEV,
            &ParametrosEvidencia::inactiva()
        ),
        Err(ErrorTransicion::ErrDosPruebasAlmacenamiento)
    );
}
