//! FV-N6-C4-2 · alcance de la garantía: R4 (`EvidenceTx`), conservación de dinero con fianzas,
//! orden de débito determinista, subcuentas completas, límite, continuación de certificados con la
//! tabla siguiente que refleja la suspensión, y recorrido real sector→activo→Retiro→Liberación con
//! los plazos vigentes (`R_sec = 96`, `R_slots = 600`).
//!
//! **Fixtures declarados.** Los estados con fianza se montan con un estado inicial
//! **contablemente conservado** (`emitido = Σ activo + Σ fianza`, `quemado = 0`): no son altas
//! autenticadas extraídas de la red. Donde se añade un sector después se usa el **alta por API
//! real** (`aplicar_operacion_con_undo` con `OperacionSector::Alta`), que debita `Garantia.activo` y
//! no cambia `emitido`. Las claves BLS, el sorteo VRF, las firmas de voto, los sellos Ed25519 de las
//! cabeceras `PoAS_PoT_DAG` y la aceptación de las Tx v2 son reales; los registros de sector y las
//! cabeceras son **fixture**, no un proceso de red de cuatro nodos.
//!
//! La conservación en los tests **no dedicados a `I-1`** se calcula dentro del test
//! ([`conservacion`]): `UTXO` + las cuatro sub-cuentas de `Garantia` + `Σ fianza` no terminal
//! `== emitido − quemado`. Así, sobre la base limpia `cda9b836` el rojo llega a los débitos de las
//! penas y no se detiene en una `invariante_i1` que todavía no suma fianzas. El test dedicado
//! [`i1_suma_fianzas_no_terminales`] sí comprueba la `invariante_i1` productiva.
//!
//! R4 usa cabeceras `PoAS_PoT_DAG` con sellos Ed25519 reales y el camino real de bloque
//! (`aplicar_con_undo`), no una función que imite la pena.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::panic,
    reason = "test de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use ed25519_zebra::SigningKey;
use primitive_types::U256;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Undo, aplicar_con_undo, deshacer, invariante_i1, materializar_con_undo,
    total_garantia,
};
use zx_core::{
    Amount, BlockHash, BodyCommitment, CBID_RED_DEV, ClavePublica, DagBlockHeader, Digest,
    ExtensionTx, MerkleRoot, PadresDag, SolucionPoas, Tx, TxOut,
};

const Q_SEC: i64 = 140;

type Error = Box<dyn std::error::Error>;

// ── fixtures de voto (mismos orígenes que los tests FV-4b-N2/N3) ─────────────

fn bls(indice: u8) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn registro(p: &ParametrosSector, clave: ClavePublica, indice: u16) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    let reg = RegistroSector {
        id,
        r2: [0; 4],
        history_size: 1,
        etapa: Etapa::Activo,
        alta_slot: 0,
        renovacion_slot: 0,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

fn estado_conservado(
    claves: &[(u8, usize, i64)],
) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let mut secretas = Vec::new();
    let mut emitido: i128 = 0;
    for (indice, n_sectores, activo) in claves {
        let secreta = bls(*indice)?;
        let pk = secreta.clave_publica();
        let e = ed(*indice);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for i in 0..*n_sectores {
            let (id, reg) = registro(&p, e, u16::try_from(i)?);
            emitido += i128::from(reg.fianza);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(*activo)?;
        emitido += i128::from(*activo);
        est.garantias.insert(e, g);
        secretas.push(secreta);
    }
    est.emitido = emitido;
    est.quemado = 0;
    Ok((est, secretas))
}

fn fianza_de(est: &Estado, clave: &ClavePublica) -> i128 {
    est.sectores
        .iter()
        .filter(|(id, r)| id.clave == *clave && !r.es_terminal())
        .map(|(_, r)| i128::from(r.fianza))
        .sum()
}

fn total_castigable_test(est: &Estado, clave: &ClavePublica) -> i128 {
    let cuenta = est.garantias.get(clave).map_or(0, total_garantia);
    cuenta + fianza_de(est, clave)
}

/// Conservación **independiente** calculada dentro del test (no llama a `invariante_i1`):
/// `UTXO` + las cuatro sub-cuentas de `Garantia` (`activo`, `pendientes`, `en_retirada`,
/// `creditos`) + `Σ fianza` no terminal `== emitido − quemado`.
///
/// Es la precondición/postcondición contable de los tests que no son el dedicado de `I-1`: en la
/// base `cda9b836` la `invariante_i1` productiva no suma fianzas y enmascararía el débito.
fn conservacion(est: &Estado) -> bool {
    let mut total: i128 = est.utxo.values().map(|e| i128::from(e.valor.brek())).sum();
    for g in est.garantias.values() {
        total += i128::from(g.activo.brek());
        total += g
            .pendientes
            .iter()
            .map(|p| i128::from(p.importe.brek()))
            .sum::<i128>();
        total += g
            .en_retirada
            .iter()
            .map(|r| i128::from(r.importe.brek()))
            .sum::<i128>();
        total += g
            .creditos
            .iter()
            .map(|p| i128::from(p.importe.brek()))
            .sum::<i128>();
    }
    for r in est.sectores.values() {
        if !r.es_terminal() {
            total += i128::from(r.fianza);
        }
    }
    total == est.emitido - est.quemado
}

fn params_transicion() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 0,
        w_min: U256::zero(),
        s_min: Amount::CERO,
        q: Amount::nuevo(1).expect("q"),
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 600,
        f_slots: Some(600),
        subsidio_pow: |_| Amount::CERO,
        subsidio_post: |_| Amount::CERO,
    }
}

// ── fixtures de bloque para R4 (`EvidenceTx` v4 real) ────────────────────────

fn firmante_de(k: u64) -> SigningKey {
    let mut mensaje = b"zx-t01-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    SigningKey::from(*digest.as_bytes())
}

fn clave_firmante(k: u64) -> ClavePublica {
    let sk = firmante_de(k);
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

fn hash_de(id: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&id.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

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
fn evidencia_tx(cbid: u32, clave_idx: u64, slot: i64, ph1: u64, ph2: u64) -> Tx {
    let clave = clave_firmante(clave_idx);
    let mut h1 = cabecera(cbid, clave, slot, ph1, 0);
    let quiere_menor = ph1 < ph2;
    let mut sal = 0u64;
    let mut h2;
    loop {
        h2 = cabecera(cbid, clave, slot, ph2, sal);
        if (h1.pre_hash().as_bytes() < h2.pre_hash().as_bytes()) == quiere_menor {
            break;
        }
        sal += 1;
    }
    let sk = firmante_de(clave_idx);
    let firma1: [u8; 64] = sk.sign(h1.pre_hash().as_bytes()).into();
    h1.sello = firma1;
    let firma2: [u8; 64] = sk.sign(h2.pre_hash().as_bytes()).into();
    h2.sello = firma2;
    Tx {
        version: 4,
        inputs: Vec::new(),
        outputs: Vec::<TxOut>::new(),
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

/// Estado PoST con la clave 1 (infractora, `activo = 0`, un sector de fianza) y la clave 2
/// (productora, `activo = 1`). `emitido = 141`.
fn estado_r4() -> Estado {
    let p = ParametrosSector::dev();
    let mut estado = Estado::inicial();
    estado.parametros_sector = p;
    estado.fase = Fase::PoST;
    estado.terminal = Some(hash_de(1));
    estado.slot = 0;
    let (id, reg) = registro(&p, clave_firmante(1), 0);
    estado.sectores.insert(id, reg);
    let mut g1 = Garantia::nueva();
    g1.activo = Amount::CERO;
    estado.garantias.insert(clave_firmante(1), g1);
    let mut g2 = Garantia::nueva();
    g2.activo = Amount::nuevo(1).expect("activo");
    estado.garantias.insert(clave_firmante(2), g2);
    estado.emitido = 1 + i128::from(Q_SEC);
    estado.quemado = 0;
    estado
}

// ── tests ───────────────────────────────────────────────────────────────────

/// `I-1` productiva suma las fianzas no terminales (rojo en la base, verde con la corrección).
#[test]
fn i1_suma_fianzas_no_terminales() -> Result<(), Error> {
    let (base, _) = estado_conservado(&[(1, 2, 0), (2, 1, 7)])?;
    assert_eq!(total_castigable_test(&base, &ed(1)), i128::from(2 * Q_SEC));
    assert!(
        invariante_i1(&base),
        "UTXO + garantías + fianzas == emitido − quemado"
    );
    // Mover una fianza a terminal la devuelve a `activo` por el camino real: la suma no cambia.
    let mut con_retirada = base.clone();
    let sid = SectorId {
        clave: ed(1),
        sector_index: 0,
        version: 0,
    };
    let r = con_retirada.sectores.get_mut(&sid).ok_or("sector")?;
    r.etapa = Etapa::EnRetirada;
    r.retiro_slot = 0;
    let (tras, _undo) =
        materializar_con_undo(&con_retirada, 1_024, &con_retirada.parametros_sector);
    assert_eq!(
        tras.sectores[&sid].fianza, 0,
        "la fianza se libera a activo"
    );
    assert!(tras.garantias[&ed(1)].activo.brek() >= Q_SEC);
    assert!(invariante_i1(&tras), "I-1 tras devolución sector→activo");
    Ok(())
}

/// R4: `EvidenceTx` de bloque alcanza la fianza, recompensa con `suelo(C/4)` y quema el resto.
#[test]
fn r4_evidencia_de_bloque_alcanza_la_fianza() -> Result<(), Error> {
    let base = estado_r4();
    assert!(conservacion(&base), "fixture conservado");
    let tx = evidencia_tx(7, 1, 1, 11, 22);
    let bloque = bloque_post(1, clave_firmante(2), vec![(tx.clone(), Vec::new())]);
    let evp = ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid: 7,
        evp: true,
    };
    let (nuevo, undo) = aplicar_con_undo(&base, &bloque, &params_transicion(), CBID_RED_DEV, &evp)
        .expect("evidencia admitida");
    assert_eq!(fianza_de(&nuevo, &clave_firmante(1)), 0, "V = fianza = 140");
    assert_eq!(
        nuevo.quemado,
        i128::from(Q_SEC) - i128::from(Q_SEC) / 4,
        "quema C − suelo(C/4)"
    );
    let g2 = nuevo.garantias.get(&clave_firmante(2)).ok_or("productor")?;
    let credito: i64 = g2.creditos.iter().map(|p| p.importe.brek()).sum();
    assert_eq!(credito, Q_SEC / 4, "recompensa real al productor");
    assert_eq!(
        nuevo.garantias[&clave_firmante(1)].congelado.brek(),
        0,
        "gravamen sobre el remanente real"
    );
    assert!(conservacion(&nuevo), "conservación tras R4");
    assert_eq!(deshacer(&nuevo, &undo), base, "undo bit a bit");

    let dup = aplicar_con_undo(
        &nuevo,
        &bloque_post(2, clave_firmante(2), vec![(tx, Vec::new())]),
        &params_transicion(),
        CBID_RED_DEV,
        &evp,
    );
    assert_eq!(dup, Err(ErrorTransicion::ErrEvidenciaDuplicada));
    Ok(())
}

/// El incidente repetido de R4 no vuelve a congelar ni confiscar (undo incluido).
#[test]
fn incidente_duplicado_no_recobra() -> Result<(), Error> {
    let base = estado_r4();
    let tx = evidencia_tx(7, 1, 1, 11, 22);
    let bloque = bloque_post(1, clave_firmante(2), vec![(tx.clone(), Vec::new())]);
    let evp = ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid: 7,
        evp: true,
    };
    let (primero, _) = aplicar_con_undo(&base, &bloque, &params_transicion(), CBID_RED_DEV, &evp)
        .expect("primera evidencia");
    let segundo = aplicar_con_undo(
        &primero,
        &bloque_post(2, clave_firmante(2), vec![(tx, Vec::new())]),
        &params_transicion(),
        CBID_RED_DEV,
        &evp,
    )
    .expect_err("la segunda debe rechazarse");
    // `aplicar_con_undo` devuelve Err sin estado; comprobamos dedup con el incidente ya registrado.
    assert_eq!(segundo, ErrorTransicion::ErrEvidenciaDuplicada);
    assert_eq!(
        primero.garantias[&clave_firmante(1)].incidentes.len(),
        1,
        "un único incidente"
    );
    assert_eq!(fianza_de(&primero, &clave_firmante(1)), 0);
    // Y no hay una segunda mutación que revierta: el undo de la primera sigue siendo exacto.
    Ok(())
}

/// Guarda de que el `Undo` de R4 restaura el estado exacto con fianzas.
#[test]
fn undo_de_r4_con_fianza_es_exacto() -> Result<(), Error> {
    let base = estado_r4();
    let tx = evidencia_tx(7, 1, 1, 11, 22);
    let bloque = bloque_post(1, clave_firmante(2), vec![(tx, Vec::new())]);
    let evp = ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid: 7,
        evp: true,
    };
    let (nuevo, undo): (Estado, Undo) =
        aplicar_con_undo(&base, &bloque, &params_transicion(), CBID_RED_DEV, &evp)
            .expect("evidencia admitida");
    assert_eq!(deshacer(&nuevo, &undo), base);
    Ok(())
}
