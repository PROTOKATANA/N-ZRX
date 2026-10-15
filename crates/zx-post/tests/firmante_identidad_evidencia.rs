//! V5 de `ORDEN-SL4b1`: la identidad del firmante es la identidad de la evidencia (`RAT-1`).
//!
//! - (a) para cabeceras reales firmadas, «misma identidad del firmante» ⟺ «mismo
//!   `zx_core::incident_id_evidencia`» calculado de cada cabecera;
//! - (b) con dos cabeceras de la misma identidad y distinto `pre_hash`, la `EvidenceTx` v4 pasa
//!   `zx_core::validar_forma_tx_v4` y **se aplica** en el motor (`zx-consensus`, dev-dependency);
//! - (c) cambiando **uno** de los seis campos de la identidad (uno por test, incluido
//!   `consensus_branch_id`), el firmante las trata como oportunidades distintas **y** el motor
//!   rechaza la evidencia (`ErrSinEvidencia`; el `cbid` ajeno lo rechaza antes la forma v4 con
//!   `ErrorFormaTx::EvidenciaCbidAjeno`, `RAT-1`);
//! - (d) cambiar un campo que no es de la identidad (padres, cuerpo, `timestamp`) no cambia la
//!   identidad del firmante.
//!
//! El modelo del motor está portado de `crates/zx-consensus/tests/evidencia.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use ed25519_zebra::SigningKey;
use primitive_types::U256;
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_core::{
    Amount, BlockHash, BodyCommitment, CBID_RED_DEV, ClavePublica, Digest, ErrorFormaTx,
    ExtensionTx, MerkleRoot, Tx, incident_id_evidencia, validar_forma_tx_v4,
};
use zx_post::firmante::{Firmante, Registro, Resultado};

use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo,
};

/// `cbid` de la red de prueba de la evidencia.
const CBID_EVP: u32 = 7;

fn firmante_de(k: u64) -> SigningKey {
    let mut mensaje = b"zx-sl4b1-clave".to_vec();
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

/// Cabecera con la identidad `RAT-1` fijada por los campos de `sol` + `slot` + `cbid`, y `pre_hash`
/// controlado por `(ph, sal)` y por `padre`/cuerpo.
fn cabecera(cbid: u32, clave_idx: u64, slot: u64, ph: u64, sal: u64) -> DagBlockHeader {
    let sol = SolucionPoas {
        public_key: clave_de(clave_idx),
        sector_index: 3,
        history_size: 1 << 20,
        chunk: [0x11; 32],
        ..Default::default()
    };
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: cbid,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
        timestamp: sal,
        height: 0,
        slot,
        pot_output: [0x33; 16],
        rango_solucion: ph,
        sol,
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x44; 32])),
        padres: PadresDag::genesis(),
        sello: [0u8; 64],
    }
}

/// Firma la cabecera con la clave de su `sol.public_key` si `clave_idx` la identifica.
fn firmar(c: &mut DagBlockHeader, clave_idx: u64) {
    let sk = firmante_de(clave_idx);
    let pre = c.pre_hash();
    c.sello = sk.sign(pre.as_bytes()).into();
}

/// La identidad de la evidencia calculada desde la cabecera (RAT-1).
fn incident_id_de(c: &DagBlockHeader) -> Digest {
    incident_id_evidencia(
        c.consensus_branch_id,
        c.sol.public_key.bytes(),
        c.sol.sector_index,
        c.sol.history_size,
        &c.sol.chunk,
        c.slot,
    )
}

/// ¿Tienen la **misma** identidad de firmante?
fn misma_identidad_firmante(a: &DagBlockHeader, b: &DagBlockHeader) -> bool {
    Firmante::identidad(a).huella() == Firmante::identidad(b).huella()
}

/// ¿Tienen el **mismo** `incident_id` de la evidencia?
fn mismo_incident_id(a: &DagBlockHeader, b: &DagBlockHeader) -> bool {
    incident_id_de(a) == incident_id_de(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Modelo del motor (portado de zx-consensus/tests/evidencia.rs)
// ─────────────────────────────────────────────────────────────────────────────

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

/// Estado PoST con una garantía de 8 brek en la clave 1 y otra en la 2 (productor).
fn estado_post() -> Estado {
    let mut estado = Estado::inicial();
    estado.fase = Fase::PoST;
    estado.terminal = Some(hash_de(1));
    estado.slot = 0;
    let garantia = |activo: i64| Garantia {
        activo: Amount::nuevo(activo).expect("activo"),
        pendientes: Vec::new(),
        en_retirada: Vec::new(),
        congelado: Amount::CERO,
        creditos: Vec::new(),
        nonce_siguiente: 0,
        incidentes: Vec::new(),
    };
    estado.garantias.insert(clave_de(1), garantia(8));
    estado.garantias.insert(clave_de(2), garantia(1));
    estado
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

/// Aplica una `EvidenceTx` v4 al motor con el perfil de evidencia activo.
fn aplicar(tx: Tx) -> Result<(), ErrorTransicion> {
    let estado = estado_post();
    let bloque = bloque_post(1, clave_de(2), vec![(tx, Vec::new())]);
    aplicar_con_undo(&estado, &bloque, &params(), CBID_RED_DEV, &evp(CBID_EVP)).map(|_| ())
}

fn tx_evidencia(h1: DagBlockHeader, h2: DagBlockHeader) -> Tx {
    Tx {
        version: 4,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Evidencia { h1, h2 },
    }
}

/// Construye dos cabeceras de la misma identidad, distinto `pre_hash` y orden canónico
/// (`pre_hash(h1) < pre_hash(h2)`), ambas firmadas.
fn par_canonico(clave_idx: u64, slot: u64) -> (DagBlockHeader, DagBlockHeader) {
    let mut h1 = cabecera(CBID_EVP, clave_idx, slot, 11, 0);
    let mut sal = 0u64;
    let mut h2 = cabecera(CBID_EVP, clave_idx, slot, 22, sal);
    while h1.pre_hash().as_bytes() >= h2.pre_hash().as_bytes() {
        sal += 1;
        h2 = cabecera(CBID_EVP, clave_idx, slot, 22, sal);
    }
    firmar(&mut h1, clave_idx);
    firmar(&mut h2, clave_idx);
    (h1, h2)
}

/// Registro limpio para el firmante en un directorio temporal propio.
struct DirTemporal {
    ruta: std::path::PathBuf,
}

impl DirTemporal {
    fn nuevo(etiqueta: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CONTADOR: AtomicU64 = AtomicU64::new(0);
        let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "zx-firmante-v5-{}-{}-{etiqueta}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("directorio temporal");
        Self { ruta: base }
    }
}

impl Drop for DirTemporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ruta);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// V5(a) · Identidad del firmante ⟺ incident_id de la evidencia
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v5a_misma_identidad_firmante_si_y_solo_si_mismo_incident_id() {
    // Cabeceras reales firmadas: un par de la misma identidad con distinto `pre_hash`, otro con
    // otra clave, otro con otro slot y otro con otro cbid.
    let (mut a1, mut a2) = par_canonico(1, 1);
    let mut b = cabecera(CBID_EVP, 2, 1, 11, 0);
    let mut c = cabecera(CBID_EVP, 1, 2, 11, 0);
    let mut d = cabecera(CBID_EVP + 1, 1, 1, 11, 0);
    firmar(&mut b, 2);
    firmar(&mut c, 1);
    firmar(&mut d, 1);
    for h in [&mut a1, &mut a2, &mut b, &mut c, &mut d] {
        h.verificar_sello().expect("sello real");
    }

    let cabeceras = [&a1, &a2, &b, &c, &d];
    for (i, x) in cabeceras.iter().enumerate() {
        for (j, y) in cabeceras.iter().enumerate() {
            assert_eq!(
                misma_identidad_firmante(x, y),
                mismo_incident_id(x, y),
                "par ({i},{j}): la igualdad de identidad del firmante y la del incident_id difieren"
            );
        }
    }
    // Controles positivos: (0,1) misma identidad; (0,2) distinta clave; (0,3) distinto slot;
    // (0,4) distinto cbid.
    assert!(misma_identidad_firmante(&a1, &a2));
    assert!(!misma_identidad_firmante(&a1, &b));
    assert!(!misma_identidad_firmante(&a1, &c));
    assert!(!misma_identidad_firmante(&a1, &d));
}

// ─────────────────────────────────────────────────────────────────────────────
// V5(b) · La evidencia de dos cabeceras reales pasa forma y se aplica
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v5b_evidencia_v4_valida_pasa_forma_y_se_aplica() {
    let (h1, h2) = par_canonico(1, 1);
    let tx = tx_evidencia(h1, h2);
    validar_forma_tx_v4(&tx, &[], CBID_EVP).expect("forma v4 válida");
    assert!(
        aplicar(tx).is_ok(),
        "la evidencia de dos firmas reales debe aplicarse"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// V5(c) · Un campo de la identidad cambiado ⇒ oportunidad distinta y motor rechaza
// ─────────────────────────────────────────────────────────────────────────────

/// Cambia **un** campo de identidad en `h2` y comprueba: el firmante la ve como oportunidad
/// distinta (Sellado) y el motor rechaza la evidencia con `esperado`.
fn caso_campo_identidad(
    etiqueta: &str,
    variar: impl FnOnce(&mut DagBlockHeader, &mut u64),
    esperado: ErrorTransicion,
) {
    let dir = DirTemporal::nuevo(etiqueta);
    let mut h1 = cabecera(CBID_EVP, 1, 1, 11, 0);
    firmar(&mut h1, 1);

    // h2 parte de la misma identidad y se le cambia un campo.
    let mut h2 = cabecera(CBID_EVP, 1, 1, 22, 0);
    let mut clave_h2 = 1u64;
    variar(&mut h2, &mut clave_h2);
    // El orden canónico (`EV-01`/`EV-04`) también es forma y se comprueba antes que la semántica:
    // se ajusta el `timestamp` (campo ajeno a la identidad) hasta `pre_hash(h1) < pre_hash(h2)`
    // para que el motor llegue a la comprobación semántica en los cinco campos no-`cbid`.
    let mut sal = h2.timestamp;
    while h1.pre_hash().as_bytes() >= h2.pre_hash().as_bytes() {
        sal += 1;
        h2.timestamp = sal;
    }
    firmar(&mut h2, clave_h2);

    // (1) El firmante las trata como oportunidades distintas.
    let registro = Registro::nueva(dir.ruta.join("r.log")).expect("registro limpio");
    let firmante = Firmante::nuevo(&registro);
    let mut c1 = h1;
    assert_eq!(
        firmante.firmar(&mut c1, &firmante_de(1)).unwrap(),
        Resultado::Sellado
    );
    let mut c2 = h2;
    assert_eq!(
        firmante.firmar(&mut c2, &firmante_de(clave_h2)).unwrap(),
        Resultado::Sellado,
        "{etiqueta}: el firmante debe ver otra oportunidad"
    );
    assert!(!misma_identidad_firmante(&h1, &h2), "{etiqueta}");

    // (2) El motor rechaza la evidencia.
    let tx = tx_evidencia(h1, h2);
    assert_eq!(aplicar(tx), Err(esperado), "{etiqueta}");
}

#[test]
fn v5c_cbid_cambiado_oportunidad_distinta_y_err_cbid_ajeno() {
    caso_campo_identidad(
        "cbid",
        |h2, _| h2.consensus_branch_id = CBID_EVP + 1,
        ErrorTransicion::ErrForma(ErrorFormaTx::EvidenciaCbidAjeno),
    );
}

#[test]
fn v5c_clave_cambiada_oportunidad_distinta_y_err_sin_evidencia() {
    caso_campo_identidad(
        "clave",
        |h2, clave| {
            *clave = 3;
            h2.sol.public_key = clave_de(3);
        },
        ErrorTransicion::ErrSinEvidencia,
    );
}

#[test]
fn v5c_sector_cambiado_oportunidad_distinta_y_err_sin_evidencia() {
    caso_campo_identidad(
        "sector",
        |h2, _| h2.sol.sector_index += 1,
        ErrorTransicion::ErrSinEvidencia,
    );
}

#[test]
fn v5c_historia_cambiada_oportunidad_distinta_y_err_sin_evidencia() {
    caso_campo_identidad(
        "historia",
        |h2, _| h2.sol.history_size += 1,
        ErrorTransicion::ErrSinEvidencia,
    );
}

#[test]
fn v5c_chunk_cambiado_oportunidad_distinta_y_err_sin_evidencia() {
    caso_campo_identidad(
        "chunk",
        |h2, _| h2.sol.chunk[0] ^= 0x01,
        ErrorTransicion::ErrSinEvidencia,
    );
}

#[test]
fn v5c_slot_cambiado_oportunidad_distinta_y_err_sin_evidencia() {
    caso_campo_identidad(
        "slot",
        |h2, _| h2.slot += 1,
        ErrorTransicion::ErrSinEvidencia,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// V5(d) · Campos ajenos a la identidad del firmante y forma v4 (`cbid` de red)
// ─────────────────────────────────────────────────────────────────────────────

/// Cambia un campo que **no** es de la identidad y comprueba que la huella del firmante no cambia
/// y que, con otro `pre_hash`, el firmante se abstiene por conflicto (misma oportunidad).
fn caso_campo_ajeno(etiqueta: &str, variar: impl FnOnce(&mut DagBlockHeader)) {
    let dir = DirTemporal::nuevo(etiqueta);
    let mut h1 = cabecera(CBID_EVP, 1, 1, 11, 0);
    firmar(&mut h1, 1);
    let mut h2 = cabecera(CBID_EVP, 1, 1, 11, 0);
    variar(&mut h2);
    firmar(&mut h2, 1);

    assert_eq!(
        Firmante::identidad(&h1).huella(),
        Firmante::identidad(&h2).huella()
    );
    assert_ne!(
        h1.pre_hash(),
        h2.pre_hash(),
        "{etiqueta}: cambia el pre_hash"
    );

    let registro = Registro::nueva(dir.ruta.join("r.log")).expect("registro limpio");
    let firmante = Firmante::nuevo(&registro);
    let mut c1 = h1;
    assert_eq!(
        firmante.firmar(&mut c1, &firmante_de(1)).unwrap(),
        Resultado::Sellado
    );
    let mut c2 = h2;
    assert!(
        matches!(
            firmante.firmar(&mut c2, &firmante_de(1)).unwrap(),
            Resultado::AbstenidoPorConflicto { .. }
        ),
        "{etiqueta}: misma identidad, otro pre_hash ⇒ abstención"
    );
}

#[test]
fn v5d_padres_distintos_no_cambian_la_identidad() {
    caso_campo_ajeno("ajeno-padres", |h| {
        h.padres = PadresDag::nuevo(hash_de(0xAA), &[hash_de(0xBB)]).expect("dos padres");
    });
}

#[test]
fn v5d_cuerpo_distinto_no_cambia_la_identidad() {
    caso_campo_ajeno("ajeno-cuerpo", |h| {
        h.merkle_root = MerkleRoot::from_digest(Digest::from_bytes([0x55; 32]));
        h.body_commitment = BodyCommitment::from_digest(Digest::from_bytes([0x66; 32]));
    });
}

#[test]
fn v5d_timestamp_distinto_no_cambia_la_identidad() {
    caso_campo_ajeno("ajeno-timestamp", |h| {
        h.timestamp += 1;
    });
}

/// La forma v4 **sí** mira el `cbid` de red (`RAT-1`) y **no** el resto de la identidad: un par con
/// el mismo `cbid` y otro campo de identidad cambiado (clave, sector, historial, chunk o slot) pasa
/// `validar_forma_tx_v4`; el rechazo por identidad es semántico y vive en el motor (`v5c_*`).
#[test]
fn v5d_la_forma_v4_rechaza_cbid_ajeno_y_acepta_el_resto_de_la_identidad() {
    // (1) `cbid` ajeno en la segunda cabecera ⇒ forma v4 inválida (RAT-1), antes del orden.
    let mut h1 = cabecera(CBID_EVP, 1, 1, 11, 0);
    let mut h2 = cabecera(CBID_EVP + 1, 1, 1, 22, 0);
    firmar(&mut h1, 1);
    firmar(&mut h2, 1);
    let tx = tx_evidencia(h1, h2);
    assert_eq!(
        validar_forma_tx_v4(&tx, &[], CBID_EVP),
        Err(ErrorFormaTx::EvidenciaCbidAjeno),
        "la forma v4 debe rechazar un cbid ajeno a la red local"
    );

    // (2) Mismo `cbid` y otro campo de la identidad cambiado ⇒ la forma v4 lo acepta (el rechazo
    //     por identidad es semántico y lo cubren los `v5c_*`).
    forma_acepta_identidad_distinta("clave", |h| h.sol.public_key = clave_de(3));
    forma_acepta_identidad_distinta("sector", |h| h.sol.sector_index += 1);
    forma_acepta_identidad_distinta("historia", |h| h.sol.history_size += 1);
    forma_acepta_identidad_distinta("chunk", |h| h.sol.chunk[0] ^= 0x01);
    forma_acepta_identidad_distinta("slot", |h| h.slot += 1);
}

/// Con el mismo `cbid` local, cambia la identidad de `H2` y ajusta su `timestamp` hasta que
/// `pre_hash(H1) < pre_hash(H2)`; la forma v4 debe aceptarlo (no mira el resto de la identidad ni
/// los sellos, que aquí no se comprueban).
fn forma_acepta_identidad_distinta(etiqueta: &str, variar: impl FnOnce(&mut DagBlockHeader)) {
    let h1 = cabecera(CBID_EVP, 1, 1, 11, 0);
    let mut h2 = cabecera(CBID_EVP, 1, 1, 22, 0);
    variar(&mut h2);
    let mut sal = 0u64;
    while h1.pre_hash().as_bytes() >= h2.pre_hash().as_bytes() {
        sal += 1;
        h2.timestamp = sal;
    }
    let tx = tx_evidencia(h1, h2);
    assert!(
        validar_forma_tx_v4(&tx, &[], CBID_EVP).is_ok(),
        "la forma v4 no debe mirar la identidad salvo el cbid ({etiqueta})"
    );
}
