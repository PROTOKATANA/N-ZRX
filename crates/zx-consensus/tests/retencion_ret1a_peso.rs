//! RET-1a · retención de votos en el consenso (RV-1, RV-3, RV-4).
//!
//! P1–P6 de `ORDEN-RET1A.md` §5. Se usan los valores del perfil dev por **literales**
//! (`96`, `600`, `1 023`, `1 024`, `330`) y la API existente para que este archivo compile también
//! contra `ws.orig`; P7 (consistencia de la fórmula) vive en `retencion_formula_rv.rs` porque
//! referencia los símbolos nuevos.
//!
//! Ejecutar con salida cruda:
//! `cargo test -p zx-consensus --test retencion_ret1a -- --nocapture`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    dead_code,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use ed25519_zebra::SigningKey;
use primitive_types::U256;
use zx_consensus::sectores::{
    ClaveVoto, Etapa, MotivoSector, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_undo;
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo, aplicar_operacion_con_undo, materializar_con_undo,
};
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, OperacionAlmacenamiento,
    OperacionSector, TipoGarantia, Tx, VotoPesoEvidencia,
};
use zx_votos::DOMINIO_VOTO;

/// `K` local vigente (M9-b2 retiró la constante de plazas del consenso; se usa su literal `65 536`
/// para poder compilar contra `ws.orig`). El literal `1 024` quedó obsoleto y hacía fallar el
/// compromiso (`k != K`) en `p4`/`p5`.
const K: u64 = 65_536;
/// Prima de disponibilidad (FV-D05).
const B: u64 = 2;
/// Fianza por sector del perfil dev.
const Q_SEC: i64 = 140;

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures de voto (mismos orígenes que FV-4b-N2/N3 y REAN-1).
// ─────────────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

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

/// Estado con `claves = [(índice, nº de sectores)]` y garantía activa `garantia`.
fn estado(
    claves: &[(u8, usize)],
    garantia: i64,
) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    est.terminal = Some(hash_de(1));
    let mut secretas = Vec::new();
    for (indice, n_sectores) in claves {
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
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(garantia)?;
        est.garantias.insert(e, g);
        secretas.push(secreta);
    }
    Ok((est, secretas))
}

/// M9-b1 · evidencia de dos votos por peso (`0x0B`) con las dos firmas A3 reales.
fn op_doble_voto_peso(
    secreta: &zx_votos::ClaveSecreta,
    n: u64,
    h_t: [u8; 32],
    h1: [u8; 32],
    h2: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let f1 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &h1, &h_t, &h1),
    )?;
    let f2 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &h2, &h_t, &h2),
    )?;
    Ok(OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: pk.bytes(),
        voto1: VotoPesoEvidencia {
            n,
            candidato: h1,
            h_t_siguiente: h_t,
            raiz_estado: h1,
            firma: f1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n,
            candidato: h2,
            h_t_siguiente: h_t,
            raiz_estado: h2,
            firma: f2.bytes(),
        },
    })
}

fn param_evidencia() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid: 0,
        evp: true,
    }
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

#[test]
fn p3_la_evidencia_de_doble_voto_tiene_edad_maxima_peso() -> Result<(), Error> {
    let (base, secretas) = estado(&[(1, 20)], 50)?;
    let n = 10u64;
    let secreta = secretas.first().ok_or("sin clave")?;
    let op = op_doble_voto_peso(secreta, n, [0x5A; 32], [0x01; 32], [0x02; 32])?;
    let params = params_transicion();
    let evp = param_evidencia();
    // `cierre(n) + plazo_slots` con el `plazo_slots = 300` del perfil dev.
    let limite = (n + 1) * 2 + 300;

    let (aceptado, _, r) =
        aplicar_evidencia_votos_peso_con_undo(&base, &op, ed(200), &params, &evp, limite);
    println!("P3 evidencia en {limite} -> {r:?}");
    r?;
    assert!(aceptado.quemado > base.quemado, "la evidencia confisca");

    let (sin_mutar, _, r) =
        aplicar_evidencia_votos_peso_con_undo(&base, &op, ed(200), &params, &evp, limite + 1);
    println!("P3 evidencia en {} -> {r:?}", limite + 1);
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));
    assert_eq!(sin_mutar, base, "un rechazo no muta");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// P5 · extremo a extremo en el consenso: la fianza del sector retirado sigue
//      confiscable cuando la prueba entra dentro de su plazo, porque la
//      liberación a UTXO no ha vencido (RV-3).
// ─────────────────────────────────────────────────────────────────────────────

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
            importe: Amount::nuevo(importe).expect("importe"),
            nonce,
        },
    }
}

fn firma_aceptacion(tx: &Tx, k: u64) -> Vec<u8> {
    let sk = firmante_de(k);
    let firma: [u8; 64] = sk
        .sign(&zx_core::mensaje_aceptacion(tx, CBID_RED_DEV))
        .into();
    firma.to_vec()
}

/// Estado PoST con el dueño (un sector, garantía `activo = 0`) y el productor (`activo = 1`).
fn estado_p5() -> Result<(Estado, zx_votos::ClaveSecreta), Error> {
    // Capacidad 1: el retiro de un sector suelto es admisible (como en `alcance_garantia.rs`).
    let p = ParametrosSector {
        capacidad_caja: 1,
        ..ParametrosSector::dev()
    };
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    est.terminal = Some(hash_de(1));
    let dueno = clave_firmante(1);
    let secreta = bls(1)?;
    est.claves_voto.insert(
        dueno,
        ClaveVoto {
            clave_bls: secreta.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let (id, reg) = registro(&p, dueno, 0);
    est.sectores.insert(id, reg);
    let mut g1 = Garantia::nueva();
    g1.activo = Amount::CERO;
    est.garantias.insert(dueno, g1);
    let mut g2 = Garantia::nueva();
    g2.activo = Amount::nuevo(1)?;
    est.garantias.insert(clave_firmante(2), g2);
    est.emitido = 1 + i128::from(Q_SEC);
    est.quemado = 0;
    Ok((est, secreta))
}

#[test]
fn p5_extremo_a_extremo_la_fianza_no_escapa_peso() -> Result<(), Error> {
    let p = ParametrosSector {
        capacidad_caja: 1,
        ..ParametrosSector::dev()
    };
    let (base, secreta) = estado_p5()?;
    let dueno = clave_firmante(1);
    let productor = clave_firmante(2);
    let s = 1i64;
    let params = params_transicion();
    let evp = param_evidencia();

    // (1) La clave pide la retirada de su sector.
    let op_retirar = OperacionSector::Retirar {
        clave: dueno,
        sector_index: 0,
    };
    let (en_retirada, res) = aplicar_operacion_con_undo(&base, &op_retirar, s, &p);
    assert_eq!(res.motivo, MotivoSector::Ok, "retiro admitido");

    // (2) El sector se materializa; RET-1b E6 hace que la fianza vuelva a `Garantia.activo` a los
    //     `R_V = r_votos_slots = 1 024` slots, no a los `R_sec = 96`.
    let (con_fianza, _u) = materializar_con_undo(&en_retirada, s + p.r_votos_slots, &p);

    // (3) `Retiro` autenticado de la garantía.
    let slot_retiro = s + p.r_votos_slots;
    let tx_retiro = tx_garantia(TipoGarantia::Retiro, dueno, Q_SEC, 0);
    let testigo = firma_aceptacion(&tx_retiro, 1);
    let bloque_retiro = bloque_post(
        u64::try_from(slot_retiro)?,
        productor,
        vec![(tx_retiro, vec![testigo])],
    );
    let (tras_retiro, _u) =
        aplicar_con_undo(&con_fianza, &bloque_retiro, &params, CBID_RED_DEV, &evp)?;
    assert_eq!(tras_retiro.garantias[&dueno].en_retirada.len(), 1);

    // (4) El ataque intenta liberar a `retiro_garantia + 600`, todavía dentro de `R_V = 1 024`: la
    //     liberación falla (`ErrSaldo`). La prueba, de la ventana `n = 662`, vence en
    //     `cierre(662) + 300 = 1 626`, y se aplica en `slot_retiro + 600 = 1 625`.
    let n = 662u64;
    let slot_liberacion = slot_retiro + 600;
    assert!(slot_liberacion <= i64::try_from((n + 1) * 2 + 300)?);
    let tx_liberacion = tx_garantia(TipoGarantia::Liberacion, dueno, Q_SEC, 1);
    let testigo = firma_aceptacion(&tx_liberacion, 1);
    let bloque_liberacion = bloque_post(
        u64::try_from(slot_liberacion)?,
        productor,
        vec![(tx_liberacion, vec![testigo])],
    );
    let intento = aplicar_con_undo(
        &tras_retiro,
        &bloque_liberacion,
        &params,
        CBID_RED_DEV,
        &evp,
    );
    println!("P5 liberación en {slot_liberacion} -> {intento:?}");
    let base_evidencia = match &intento {
        Ok((liberado, _)) => {
            // Sin RV-3 la liberación escapa: la fianza ya no es confiscable.
            liberado.clone()
        }
        Err(e) => {
            assert_eq!(*e, ErrorTransicion::ErrSaldo, "no vence: manda R_V = 1 024");
            tras_retiro.clone()
        }
    };

    // (5) La prueba de doble voto se aplica dentro de su plazo y encuentra la fianza.
    let op_ev = op_doble_voto_peso(&secreta, n, [0x6B; 32], [0x01; 32], [0x02; 32])?;
    let (penado, _u, r) = aplicar_evidencia_votos_peso_con_undo(
        &base_evidencia,
        &op_ev,
        productor,
        &params,
        &evp,
        u64::try_from(slot_liberacion)?,
    );
    println!("P5 evidencia en {slot_liberacion} -> {r:?}");
    r?;
    assert!(
        penado.garantias[&dueno].en_retirada.is_empty(),
        "la evidencia confisca la fianza en retirada"
    );
    assert!(
        penado.quemado > base_evidencia.quemado,
        "la evidencia encuentra fianza: la liberación no ocurrió"
    );
    Ok(())
}
