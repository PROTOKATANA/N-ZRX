//! Tests propios de evidencia (`ORDEN-SL4a` §3 V5): RAT-3, autodenuncia, `cbid` ajeno,
//! evidencia duplicada en hermanos y undo/reaparición (`EV-27`/`EV-28`).
//!
//! Construyen cabeceras `PoAS_PoT_DAG` reales con sellos Ed25519 reales y aplican el motor con
//! `ParametrosEvidencia` activos. La carrera completa de RAT-3 y los casos dirigidos de reorg están
//! además en los diferenciales `diferencial_t01` (`EV-RAT3-carrera`, `EV-autodenuncia`) y
//! `diferencial_t04` (D-15…D-18).

#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio test"
)]

use ed25519_zebra::SigningKey;
use primitive_types::U256;
use zx_consensus::transicion::{
    BloqueTransicion, EnRetirada, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera,
    ParametrosEvidencia, ParametrosTransicion, Punto, aplicar_con_undo, aplicar_fusion, deshacer,
};
use zx_core::{
    Amount, BlockHash, BodyCommitment, CBID_RED_DEV, ClavePublica, DagBlockHeader, Digest,
    ErrorFormaTx, ExtensionTx, Lock, MerkleRoot, PadresDag, SolucionPoas, TipoGarantia, Tx, TxOut,
};

fn firmante_de(k: u64) -> SigningKey {
    let mut mensaje = b"zx-t01-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    SigningKey::from(*digest.as_bytes())
}

fn clave_de(k: u64) -> ClavePublica {
    let sk = firmante_de(k);
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

fn hash_de(id: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&id.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).expect("subsidio pow")
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).expect("subsidio post")
}

fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 1,
        w_min: U256::from(1u32),
        s_min: Amount::nuevo(1).expect("s_min"),
        q: Amount::nuevo(1).expect("q"),
        k_min: 1,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 3,
        f_slots: Some(2),
        subsidio_pow,
        subsidio_post,
    }
}

fn evp(cbid: u32) -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid,
        evp: true,
    }
}

/// Cabecera real con identidad `(cbid, clave, slot)` y `pre_hash` controlado por `(ph, sal)`.
fn cabecera(cbid: u32, clave: ClavePublica, slot: i64, ph: u64, sal: u64) -> DagBlockHeader {
    let sol = SolucionPoas {
        public_key: clave,
        ..Default::default()
    };
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: cbid,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0u8; 32])),
        timestamp: sal,
        height: 0,
        slot: slot as u64,
        pot_output: [0u8; 16],
        rango_solucion: ph,
        sol,
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0u8; 32])),
        padres: PadresDag::genesis(),
        sello: [0u8; 64],
    }
}

/// `EvidenceTx` v4 con dos cabeceras reales de la misma identidad y sellos reales.
#[expect(
    clippy::too_many_arguments,
    reason = "el test construye el caso campo a campo"
)]
fn evidencia_tx(
    cbid: u32,
    clave_idx: u64,
    slot: i64,
    ph1: u64,
    ph2: u64,
    sello1: bool,
    sello2: bool,
    salidas: Vec<TxOut>,
) -> Tx {
    let clave = clave_de(clave_idx);
    let mut h1 = cabecera(cbid, clave, slot, ph1, 0);
    let mut h2;
    let quiere_menor = ph1 < ph2;
    let mut sal = 0u64;
    loop {
        h2 = cabecera(cbid, clave, slot, ph2, sal);
        if (h1.pre_hash().as_bytes() < h2.pre_hash().as_bytes()) == quiere_menor {
            break;
        }
        sal += 1;
    }
    let sk = firmante_de(clave_idx);
    for (ok, h) in [(sello1, &mut h1), (sello2, &mut h2)] {
        if ok {
            let firma: [u8; 64] = sk.sign(h.pre_hash().as_bytes()).into();
            h.sello = firma;
        } else {
            h.sello = [0u8; 64];
        }
    }
    Tx {
        version: 4,
        inputs: Vec::new(),
        outputs: salidas,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Evidencia { h1, h2 },
    }
}

fn bloque_post(
    slot: u64,
    productor: ClavePublica,
    txs: Vec<(Tx, Vec<Vec<u8>>)>,
) -> BloqueTransicion {
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash_de(slot + 100),
            padre: hash_de(1),
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        txs,
    )
}

/// Estado PoST con una garantía de 8 brek en la clave 1 y terminal `hash_de(1)`.
fn estado_post() -> Estado {
    let mut estado = Estado::inicial();
    estado.fase = Fase::PoST;
    estado.terminal = Some(hash_de(1));
    estado.slot = 0;
    estado.garantias.insert(
        clave_de(1),
        Garantia {
            activo: Amount::nuevo(8).expect("activo"),
            pendientes: Vec::new(),
            en_retirada: Vec::new(),
            congelado: Amount::CERO,
            creditos: Vec::new(),
            nonce_siguiente: 0,
            incidentes: Vec::new(),
        },
    );
    // Clave 2, productora de bloques en los tests que no deben fallar por `ErrGarantia`.
    estado.garantias.insert(
        clave_de(2),
        Garantia {
            activo: Amount::nuevo(1).expect("activo"),
            pendientes: Vec::new(),
            en_retirada: Vec::new(),
            congelado: Amount::CERO,
            creditos: Vec::new(),
            nonce_siguiente: 0,
            incidentes: Vec::new(),
        },
    );
    estado
}

fn ev_valida(cbid: u32, clave_idx: u64, slot: i64) -> Tx {
    evidencia_tx(cbid, clave_idx, slot, 11, 22, true, true, Vec::new())
}

/// `cbid` ajeno ⇒ `ErrForma(EvidenciaCbidAjeno)` (RAT-1, forma de la v4).
#[test]
fn cbid_ajeno() {
    let estado = estado_post();
    let bloque = bloque_post(1, clave_de(1), vec![(ev_valida(99, 1, 1), Vec::new())]);
    let r = aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7));
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrForma(ErrorFormaTx::EvidenciaCbidAjeno))
    );
}

/// Orden canónico inválido (`pre_hash` iguales) ⇒ `ErrForma(OrdenCanonicoInvalido)` (EV-01).
#[test]
fn orden_canonico_invalido() {
    let estado = estado_post();
    // ph1 == ph2 e identidad igual ⇒ prefirmas iguales ⇒ pre_hash real igual.
    let tx = evidencia_tx(7, 1, 1, 5, 5, true, true, Vec::new());
    let bloque = bloque_post(1, clave_de(1), vec![(tx, Vec::new())]);
    let r = aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7));
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrForma(
            ErrorFormaTx::OrdenCanonicoInvalido
        ))
    );
}

/// Sellos inválidos ⇒ `ErrSinEvidencia` (EV-07).
#[test]
fn sello_invalido() {
    let estado = estado_post();
    let tx = evidencia_tx(7, 1, 1, 11, 22, false, true, Vec::new());
    let bloque = bloque_post(1, clave_de(1), vec![(tx, Vec::new())]);
    let r = aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7));
    assert_eq!(r, Err(ErrorTransicion::ErrSinEvidencia));
}

/// Autodenuncia (RAT-2′): el infractor pierde al menos `6/8·C`; con `V = C = 8`, pierde 6 y el
/// productor recibe `suelo(8·2/8) = 2`.
#[test]
fn autodenuncia() {
    let estado = estado_post();
    // El productor es la propia clave infractora.
    let bloque = bloque_post(1, clave_de(1), vec![(ev_valida(7, 1, 1), Vec::new())]);
    let (nuevo, _) = aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7))
        .expect("evidencia admitida");
    assert_eq!(nuevo.quemado, 6, "quemado = C - suelo(C/4) = 8 - 2");
    let g = nuevo.garantias.get(&clave_de(1)).expect("garantía");
    assert_eq!(g.activo.brek(), 0);
    // La recompensa queda como crédito pendiente; `congelado` es el total remanente (EV-20).
    assert_eq!(g.congelado.brek(), 2);
    let credito: i64 = g.creditos.iter().map(|p| p.importe.brek()).sum();
    assert_eq!(credito, 2, "recompensa al productor = suelo(C·2/8)");
    assert_eq!(nuevo.emitido, 0);
}

/// Evidencia duplicada en **hermanos** (modo fusión): la segunda se descarta (`ErrEvidenciaDuplicada`).
#[test]
fn duplicada_en_hermanos() {
    let estado = estado_post();
    let tx = ev_valida(7, 1, 1);
    let a = bloque_post(1, clave_de(1), vec![(tx.clone(), Vec::new())]);
    let b = bloque_post(2, clave_de(1), vec![(tx, Vec::new())]);
    let (e1, _u1, d1) = aplicar_fusion(
        &estado,
        &a,
        Punto::Slot(1),
        &params(),
        CBID_RED_DEV,
        &evp(7),
    )
    .expect("primer hermano");
    assert!(d1.is_empty());
    let (e2, _u2, d2) = aplicar_fusion(&e1, &b, Punto::Slot(2), &params(), CBID_RED_DEV, &evp(7))
        .expect("bloque válido con descarte");
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0].motivo, ErrorTransicion::ErrEvidenciaDuplicada);
    // La segunda no vuelve a congelar ni confiscar: mismo `quemado` y un solo incidente.
    assert_eq!(e2.quemado, e1.quemado);
    let g = e2.garantias.get(&clave_de(1)).expect("garantía");
    assert_eq!(g.incidentes.len(), 1, "un único incidente registrado");
    assert_eq!(g.congelado.brek(), 2, "sin segundo gravamen");
}

/// `EV-27`/`EV-28`: el undo exacto devuelve el estado; la misma evidencia vuelve a aplicarse como
/// primera (no como duplicada) si la aplicación se deshizo.
#[test]
fn undo_y_reaparicion() {
    let estado = estado_post();
    let bloque = bloque_post(1, clave_de(1), vec![(ev_valida(7, 1, 1), Vec::new())]);
    let (nuevo, undo) =
        aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7)).expect("aplicada");
    assert_eq!(deshacer(&nuevo, &undo), estado, "undo exacto EV-27");
    let (nuevo2, _undo2) = aplicar_con_undo(
        &deshacer(&nuevo, &undo),
        &bloque,
        &params(),
        CBID_RED_DEV,
        &evp(7),
    )
    .expect("se reaplica como primera EV-28");
    assert_eq!(nuevo2, nuevo);
}

/// `EV-24(ii)`/RAT-3: una liberación con producción reciente (`último_slot_producido`) se rechaza
/// aunque el retiro esté vencido; pasada la ventana `Plazo + M_margen`, se admite.
#[test]
fn ventana_de_liberacion_rat3() {
    let mut estado = estado_post();
    // RET-1a · RV-3 se neutraliza en esta prueba de la ventana RAT-3: el estado usa
    // `r_votos_slots = 0` para aislar la puerta `ultimo_slot_producido` (`EV-24(ii)`).
    estado.parametros_sector.r_votos_slots = 0;
    // Retirada vencida de 8 brek y último bloque producido en el slot 5.
    let g = estado.garantias.get_mut(&clave_de(1)).expect("garantía");
    g.activo = Amount::CERO;
    g.en_retirada.push(EnRetirada {
        importe: Amount::nuevo(8).expect("importe"),
        inicio_slot: 0,
    });
    estado.ultimo_slot_producido.insert(clave_de(1), 5);

    let liberacion = |nonce: u64| {
        let tx = Tx {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Garantia {
                tipo: TipoGarantia::Liberacion,
                clave: clave_de(1),
                importe: Amount::nuevo(8).expect("importe"),
                nonce,
            },
        };
        let sk = firmante_de(1);
        let firma: [u8; 64] = sk
            .sign(&zx_core::mensaje_aceptacion(&tx, CBID_RED_DEV))
            .into();
        (tx, vec![firma.to_vec()])
    };

    // slot 5 < 5 + Plazo(2) + M_margen(0) = 7 ⇒ ErrVentanaAbierta.
    let bloque = bloque_post(5, clave_de(2), vec![liberacion(0)]);
    let r = aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7));
    assert_eq!(r, Err(ErrorTransicion::ErrVentanaAbierta));
    // slot 7 ≥ 7 y retirada vencida (0 + R_slots(3) <= 7) ⇒ se admite.
    let bloque = bloque_post(7, clave_de(2), vec![liberacion(0)]);
    let r = aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7));
    assert!(
        r.is_ok(),
        "la liberación tras la ventana debe admitirse: {r:?}"
    );
}

/// `EV-04`: evidencia con salidas monetarias ⇒ `ErrEvidenciaConEntradas`.
#[test]
fn evidencia_con_salidas() {
    let estado = estado_post();
    let salida = TxOut {
        value: Amount::nuevo(1).expect("valor"),
        lock: Lock::PubKey {
            pubkey: clave_de(2),
        },
    };
    let tx = evidencia_tx(7, 1, 1, 11, 22, true, true, vec![salida]);
    let bloque = bloque_post(1, clave_de(1), vec![(tx, Vec::new())]);
    let r = aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(7));
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrForma(
            ErrorFormaTx::EvidenciaConEntradasOSalidas
        ))
    );
}
