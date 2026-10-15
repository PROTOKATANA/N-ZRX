//! RAK-1 · diagnóstico con la transición real: ¿puede admitirse la evidencia de un doble voto un
//! slot después de que la clave de voto anterior (o la garantía en retirada) haya dejado de
//! responder, en el borde del rearranque?
//!
//! Caracteriza lo que hace **HOY** `crates/zx-consensus` (no cambia producto). Casos `rak_01`–`rak_07`
//! de `ORDEN-RAK1.md` §2, siguiendo el molde de `ra1_rearranque.rs`, `rk2_rotacion.rs` y
//! `ret1b_evidencia_peso.rs`. Toda la evidencia va por el camino real
//! (`aplicar_evidencia_votos_peso_con_hecho_con_undo`); la rotación, por el `0x03` real; la retirada y
//! la liberación de garantía, por el bloque `aplicar_con_undo` real.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    missing_docs,
    dead_code,
    reason = "pruebas de caracterización con estados construidos a mano; fallan con panic por diseño"
)]

use ed25519_zebra::SigningKey;
use primitive_types::U256;
use zx_consensus::sectores::{
    ClaveVoto, Etapa, MotivoSector, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::tipos::K_TABLAS_VOTO;
use zx_consensus::transicion::votos::{
    CADUCIDAD_TABLA_VENTANAS, CalendarioRearranque, ESPERA_REARRANQUE_SLOTS, T_INST_VOTOS,
    aplicar_certificado_peso_con_undo, aplicar_evidencia_votos_peso_con_hecho_con_undo,
    calendario_rearranque, cierre_ventana, derivar_tabla_sin_base_con_undo, retencion_clave_voto,
    retencion_clave_voto_por_tabla, tabla_derivada, tomar_instantaneas_rearranque_con_undo,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Undo, aplicar_almacenamiento_con_undo, aplicar_con_undo,
};
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, ClaveTablaVoto, Digest, ExtensionTx,
    OperacionAlmacenamiento, TipoGarantia, Tx, VotoPesoEvidencia,
};
use zx_votos::{ClaveSecreta, DOMINIO_VOTO, MotivoPeso};

const PLAZO_DEV: u64 = 300;

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Constructores y utilidades (mismos orígenes que `rk2_rotacion.rs` / `retencion_ret1a_peso.rs`)
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

/// Clave **nueva** para rotar la de `indice` (distinta de [`bls`] y determinista).
fn bls_rot(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[1] = 0x5A;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 0,
        w_min: U256::zero(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 300_000,
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

/// `f = 1/2`, `plazo_slots = 300`, como en `at1b.rs`: el castigo real es `C = min(V, techo(f·V))`.
fn param_evidencia() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 2,
        plazo_slots: PLAZO_DEV,
        m_margen_slots: 0,
        cbid: 0,
        evp: true,
    }
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
        renovacion_slot: 1_000_000,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado PoST con `(clave, nº de sectores, activo de la garantía)` por clave. La clave BLS se
/// registra directamente (primera alta); la rotación va por el `0x03`.
fn estado_base(claves: &[(u8, u16, i64)]) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for (i, n_sectores, activo) in claves {
        let s = bls(*i)?;
        est.claves_voto.insert(
            ed(*i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for k in 0..*n_sectores {
            let (id, reg) = registro(&p, ed(*i), k);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(*activo)?;
        est.garantias.insert(ed(*i), g);
        secretas.push((*i, s));
    }
    Ok((est, secretas))
}

/// Igual que [`estado_base`] pero con base de finalidad por votos en la ventana `m = 0`, para que el
/// gancho de instantáneas del rearranque esté activo.
fn estado_rearranque(
    claves: &[(u8, u16, i64)],
) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let (mut est, secretas) = estado_base(claves)?;
    est.finalidad_votos_n = 0;
    est.finalidad_votos = Some(hash(7));
    Ok((est, secretas))
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

fn op_clave_voto(clave: ClavePublica, sk: &ClaveSecreta) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::ClaveVoto {
        clave,
        clave_bls: sk.clave_publica().bytes(),
        prueba_posesion: zx_votos::probar_posesion(sk).bytes(),
    }
}

/// Aplica la rotación real `0x03` (prueba de posesión incluida) en `slot`.
fn rotar_en(estado: &Estado, indice: u8, nueva: &ClaveSecreta, slot: i64) -> Result<Estado, Error> {
    let p = ParametrosSector::dev();
    let op = op_clave_voto(ed(indice), nueva);
    let (rotado, _undo, motivo) = aplicar_almacenamiento_con_undo(estado, &op, slot, &p);
    assert_eq!(motivo, MotivoSector::Ok, "la rotación 0x03 debe aceptarse");
    Ok(rotado)
}

/// Evidencia de dos votos por peso (`0x0B`) con las dos firmas A3 reales.
#[allow(clippy::too_many_arguments)]
fn evidencia_peso(
    secreta: &ClaveSecreta,
    n1: u64,
    c1: [u8; 32],
    t1: [u8; 32],
    r1: [u8; 32],
    n2: u64,
    c2: [u8; 32],
    t2: [u8; 32],
    r2: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let f1 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n1, &c1, &t1, &r1),
    )?;
    let f2 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n2, &c2, &t2, &r2),
    )?;
    Ok(OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: pk.bytes(),
        voto1: VotoPesoEvidencia {
            n: n1,
            candidato: c1,
            h_t_siguiente: t1,
            raiz_estado: r1,
            firma: f1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n: n2,
            candidato: c2,
            h_t_siguiente: t2,
            raiz_estado: r2,
            firma: f2.bytes(),
        },
    })
}

/// Dos votos en conflicto de la **misma** ventana.
fn evidencia_misma_ventana(
    secreta: &ClaveSecreta,
    n: u64,
) -> Result<OperacionAlmacenamiento, Error> {
    evidencia_peso(
        secreta, n, [0x01; 32], [0xAA; 32], [0x10; 32], n, [0x02; 32], [0xBB; 32], [0x20; 32],
    )
}

/// Aplica la evidencia por el camino real con el incluidor `ed(9)` y devuelve `(estado, undo, rc)`.
fn aplica_evidencia_en(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    slot: u64,
) -> (Estado, Undo, Result<(), ErrorTransicion>) {
    aplicar_evidencia_votos_peso_con_hecho_con_undo(
        estado,
        op,
        ed(9),
        &params(),
        &param_evidencia(),
        slot,
        None,
    )
}

/// `C = quemado + recompensa` realmente cobrada por el castigo.
fn cobrado(antes: &Estado, despues: &Estado, productor: u8) -> i128 {
    let premio = |e: &Estado| -> i128 {
        e.garantias.get(&ed(productor)).map_or(0, |g| {
            g.creditos
                .iter()
                .map(|p| i128::from(p.importe.brek()))
                .sum()
        })
    };
    (despues.quemado - antes.quemado) + (premio(despues) - premio(antes))
}

/// `(n, cierre, e_max)` de la última ventana que **abre** dentro de la fase activa del ciclo 0.
fn borde(cal: &CalendarioRearranque) -> (u64, u64, u64) {
    let ultima_apertura = (cal.inicio(0) + cal.a - 1) / T_INST_VOTOS * T_INST_VOTOS;
    let n = ultima_apertura / T_INST_VOTOS;
    let cierre = cierre_ventana(n);
    (n, cierre, cierre + PLAZO_DEV)
}

/// TB4-R5 · `(n, cierre, e_max)` de la última ventana que **abre y cierra** dentro de la fase activa
/// del ciclo 0 (`cierre(n) < inicio(0) + A`). Sustituye a [`borde`] en las pruebas que ejercitan la
/// regla nueva; [`borde`] se conserva para la que fija la frontera de retención (`rak_05`).
fn borde_v14(cal: &CalendarioRearranque) -> (u64, u64, u64) {
    let (mut n, _, _) = borde(cal);
    if cierre_ventana(n) >= cal.inicio(0).saturating_add(cal.a) {
        n -= 1;
    }
    let cierre = cierre_ventana(n);
    (n, cierre, cierre + PLAZO_DEV)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// rak_01 · el calendario del borde
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn rak_01_calendario_del_borde() {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).expect("dev tiene A > 0");

    assert_eq!(cal.a, 65, "A");
    assert_eq!(cal.sil, 661, "SIL");
    assert_eq!(cal.periodo, 726, "P");
    assert_eq!(cal.s0, 1_262, "s0 con m = 0");
    assert_eq!(cal.inicio(0), 1_262);
    assert_eq!(
        cal.referencia(0),
        602,
        "ref = inicio - ESPERA - margen = inicio - 660"
    );
    assert_eq!(
        cal.s0,
        cierre_ventana(CADUCIDAD_TABLA_VENTANAS) + ESPERA_REARRANQUE_SLOTS,
        "s0 = cierre(m + CADUCIDAD) + ESPERA"
    );

    // La última ventana que **abre** dentro de `[inicio, inicio + A)` y su cierre.
    let (n, cierre, e_max) = borde(&cal);
    assert_eq!(n, 663, "n de la última ventana");
    assert_eq!(cierre, 1_328, "cierre(n) = (n+1)·2");
    assert_eq!(e_max, 1_628, "último slot admisible = cierre + plazo");
    assert_eq!(e_max, cal.referencia(0) + 1_026, "ref + 1 026");
    assert!(
        cierre > cal.inicio(0) + cal.a,
        "la última ventana cierra 1 slot después de la fase activa"
    );

    // Paridad: `s0` y `P` son pares, luego todo `inicio(j)` es par; un `inicio` impar **no** es
    // alcanzable con el calendario del código (la pista lo marca como borde sintético).
    assert_eq!(cal.s0 % 2, 0, "s0 par");
    assert_eq!(cal.periodo % 2, 0, "P par");
    for j in 0..4u64 {
        assert_eq!(cal.inicio(j) % 2, 0, "inicio({j}) par");
    }

    // Vencimientos de la clave anterior según el slot de rotación: el déficit de 1 slot es exacto.
    let ret = retencion_clave_voto(&p);
    assert_eq!(ret, 1_024);
    assert_eq!(retencion_clave_voto_por_tabla(&p), 961);
    assert_eq!(
        cal.referencia(0) + 1 + ret,
        1_627,
        "rotar en ref+1 responde hasta ref+1 025"
    );
    assert_eq!(
        cal.referencia(0) + 2 + ret,
        1_628,
        "rotar en ref+2 responde hasta el último slot"
    );
    assert_eq!(
        cal.referencia(0) + ret,
        1_626,
        "rotar en ref responde hasta ref+1 024"
    );
    println!(
        "rak_01: A={} ref={} inicio={} ultima_ventana={} cierre={} e_max={} (ref+1026)",
        cal.a,
        cal.referencia(0),
        cal.inicio(0),
        n,
        cierre,
        e_max
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// rak_02 · rotación en ref+1, evidencia en el último slot admisible
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn rak_02_clave_rotada_en_ref_mas_1_evidencia_en_el_ultimo_slot() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).ok_or("sin calendario de rearranque")?;
    let (base, secretas) = estado_rearranque(&[(1, 1, 50)])?;
    // v1.4 · TB4-R5: la última ventana de rearranque es la 662 (cierra 1 326 < 1 327), no la 663.
    let (n, _, e_max) = borde_v14(&cal);
    assert_eq!(n, 662, "última ventana que cierra en la fase activa");
    assert_eq!(e_max, 1_626, "último slot admisible");

    // Instantánea real del ciclo 0 justo después de `ref(0)` (el estado de entrada trae la clave
    // vieja). Después, la rotación real `0x03` en `ref+1`.
    let s_r = cal.referencia(0) + 1;
    let (con_instantanea, _u) = tomar_instantaneas_rearranque_con_undo(&base, s_r);
    let k2 = bls_rot(1)?;
    let rotado = rotar_en(&con_instantanea, 1, &k2, i64::try_from(s_r)?)?;
    assert_eq!(
        rotado.claves_voto_previas[&ed(1)].vencimiento,
        s_r + retencion_clave_voto(&p),
        "vencimiento = ref+1 + retención"
    );
    assert_eq!(rotado.claves_voto_previas[&ed(1)].vencimiento, 1_627);

    // v1.4 · antes el borde 663 ponía la evidencia en 1 628, un slot después del vencimiento: se
    // rechazaba. Con la ventana 662 el último slot admisible es 1 626, dentro de la retención: se
    // admite y castiga.
    assert!(e_max <= rotado.claves_voto_previas[&ed(1)].vencimiento);
    let op = evidencia_misma_ventana(secreta(&secretas, 1)?, n)?;
    let (post, _undo, r) = aplica_evidencia_en(&rotado, &op, e_max);
    println!("rak_02: evidencia en {e_max} (rotada en {s_r}) -> {r:?}");
    r?;
    assert_eq!(post.garantias[&ed(1)].incidentes.len(), 1);
    assert_eq!(post.quemado - rotado.quemado, 72, "quema 72");
    assert_eq!(cobrado(&rotado, &post, 9), 95, "cobrado = 95");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// rak_03 · la misma evidencia un slot antes
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn rak_03_la_misma_evidencia_un_slot_antes() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).ok_or("sin calendario de rearranque")?;
    let (base, secretas) = estado_rearranque(&[(1, 1, 50)])?;
    // v1.4 · TB4-R5 · borde de la ventana 662: último slot 1 626.
    let (n, _, e_max) = borde_v14(&cal);

    let s_r = cal.referencia(0) + 1;
    let (con_instantanea, _u) = tomar_instantaneas_rearranque_con_undo(&base, s_r);
    let k2 = bls_rot(1)?;
    let rotado = rotar_en(&con_instantanea, 1, &k2, i64::try_from(s_r)?)?;

    // En `e_max - 1 = 1 625`, la clave anterior responde y la evidencia se admite y castiga.
    let e = e_max - 1;
    assert_eq!(e, 1_625);
    assert_eq!(rotado.claves_voto_previas[&ed(1)].vencimiento, 1_627);
    assert!(e <= rotado.claves_voto_previas[&ed(1)].vencimiento);
    let op = evidencia_misma_ventana(secreta(&secretas, 1)?, n)?;
    let (post, _undo, r) = aplica_evidencia_en(&rotado, &op, e);
    println!("rak_03: evidencia en {e} (rotada en {s_r}) -> {r:?}");
    r?;
    assert_eq!(
        post.garantias[&ed(1)].incidentes.len(),
        1,
        "incidente registrado"
    );
    assert_eq!(
        post.quemado - rotado.quemado,
        72,
        "quema 72 (C = min(V, techo(V/2)))"
    );
    assert_eq!(cobrado(&rotado, &post, 9), 95, "cobrado = 95");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// rak_04 · rotación en ref+2 (el vecino que sí cubre)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn rak_04_clave_rotada_en_ref_mas_2() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).ok_or("sin calendario de rearranque")?;
    let (base, secretas) = estado_rearranque(&[(1, 1, 50)])?;
    // v1.4 · TB4-R5 · borde de la ventana 662: último slot 1 626.
    let (n, _, e_max) = borde_v14(&cal);
    assert_eq!(n, 662);
    assert_eq!(e_max, 1_626);

    let s_c = cal.referencia(0) + 1;
    let (con_instantanea, _u) = tomar_instantaneas_rearranque_con_undo(&base, s_c);
    let s_r = s_c + 1;
    let k2 = bls_rot(1)?;
    let rotado = rotar_en(&con_instantanea, 1, &k2, i64::try_from(s_r)?)?;

    // Rotar en `ref+2 = 604` da vencimiento 1 628: la evidencia en 1 626 se admite y castiga.
    assert_eq!(rotado.claves_voto_previas[&ed(1)].vencimiento, 1_628);
    assert!(e_max <= rotado.claves_voto_previas[&ed(1)].vencimiento);
    let op = evidencia_misma_ventana(secreta(&secretas, 1)?, n)?;
    let (post, _undo, r) = aplica_evidencia_en(&rotado, &op, e_max);
    println!("rak_04: evidencia en {e_max} (rotada en {s_r}) -> {r:?}");
    r?;
    assert_eq!(post.garantias[&ed(1)].incidentes.len(), 1);
    assert_eq!(post.quemado - rotado.quemado, 72);
    assert_eq!(cobrado(&rotado, &post, 9), 95);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// rak_05 · rotación en ref (el otro vecino, con déficit de 2)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn rak_05_clave_rotada_en_ref() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).ok_or("sin calendario de rearranque")?;
    let (base, secretas) = estado_rearranque(&[(1, 1, 50)])?;
    let (n, _, e_max) = borde(&cal);

    // La rotación se hace en `ref = 602`; la instantánea del ciclo se toma después, en `ref+1`,
    // sobre el estado ya rotado (el de entrada al bloque de 603).
    let s_r = cal.referencia(0);
    let k2 = bls_rot(1)?;
    let ya_rotado = rotar_en(&base, 1, &k2, i64::try_from(s_r)?)?;
    let (rotado, _u) = tomar_instantaneas_rearranque_con_undo(&ya_rotado, s_r + 1);
    assert_eq!(rotado.claves_voto_previas[&ed(1)].vencimiento, 1_626);

    // En `e_max` (1628) falta por 2 slots: rechazo.
    let op = evidencia_misma_ventana(secreta(&secretas, 1)?, n)?;
    let (post, _undo, r) = aplica_evidencia_en(&rotado, &op, e_max);
    println!("rak_05: evidencia en {e_max} (rotada en {s_r}) -> {r:?}");
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));
    assert_eq!(post, rotado, "sin mutar");

    // En su vencimiento (1626) sí se admite y castiga.
    let (post2, _u2, r2) = aplica_evidencia_en(&rotado, &op, 1_626);
    r2?;
    assert_eq!(post2.quemado - rotado.quemado, 72);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// rak_06 · garantía en retirada desde ref+1, evidencia en el último slot
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn firmante_de(k: u64) -> SigningKey {
    let mut mensaje = b"zx-rak1-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    SigningKey::from(*digest.as_bytes())
}

fn clave_firmante(k: u64) -> ClavePublica {
    let sk = firmante_de(k);
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

fn firmar_aceptacion(tx: &Tx, k: u64) -> Vec<u8> {
    let sk = firmante_de(k);
    let firma: [u8; 64] = sk
        .sign(&zx_core::mensaje_aceptacion(tx, CBID_RED_DEV))
        .into();
    firma.to_vec()
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

fn bloque_post(
    slot: u64,
    productor: ClavePublica,
    txs: Vec<(Tx, Vec<Vec<u8>>)>,
) -> BloqueTransicion {
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash(1),
            padre: hash(2),
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        txs,
    )
}

/// Estado PoST con un dueño Ed25519 real (clave BLS registrada, garantía `activo = importe`) y sin
/// sectores: `total_castigable = importe`. El productor de los bloques no es el dueño.
fn estado_garantia(importe: i64) -> Result<(Estado, ClaveSecreta, ClavePublica), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    est.terminal = Some(hash(1));
    let dueno = clave_firmante(1);
    let s = bls(1)?;
    est.claves_voto.insert(
        dueno,
        ClaveVoto {
            clave_bls: s.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(importe)?;
    est.garantias.insert(dueno, g);
    est.emitido = i128::from(importe);
    est.quemado = 0;
    Ok((est, s, dueno))
}

/// Aplica un bloque PoST con una operación de garantía firmada por el dueño `k`.
fn aplicar_garantia_en(
    estado: &Estado,
    tipo: TipoGarantia,
    clave: ClavePublica,
    importe: i64,
    nonce: u64,
    slot: u64,
    k: u64,
) -> Result<Estado, Error> {
    let tx = tx_garantia(tipo, clave, importe, nonce);
    let testigo = firmar_aceptacion(&tx, k);
    let bloque = bloque_post(slot, clave_firmante(2), vec![(tx, vec![testigo])]);
    let (nuevo, _undo) =
        aplicar_con_undo(estado, &bloque, &params(), CBID_RED_DEV, &param_evidencia())?;
    Ok(nuevo)
}

#[test]
fn rak_06_garantia_en_retirada_desde_ref_mas_1_evidencia_en_el_ultimo_slot() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).ok_or("sin calendario de rearranque")?;
    // v1.4 · TB4-R5 · borde de la ventana 662: último slot 1 626.
    let (n, _, e_max) = borde_v14(&cal);
    assert_eq!(n, 662);
    assert_eq!(e_max, 1_626);
    let (base, s, dueno) = estado_garantia(50)?;

    // Retirada real de garantía en `ref+1 = 603`: `activo (50) -> en_retirada`.
    let s_r = cal.referencia(0) + 1;
    let tras_retiro = aplicar_garantia_en(&base, TipoGarantia::Retiro, dueno, 50, 0, s_r, 1)?;
    assert_eq!(tras_retiro.garantias[&dueno].en_retirada.len(), 1);
    assert_eq!(tras_retiro.garantias[&dueno].activo, Amount::CERO);

    // La liberación real vence en `ref+1 + R_V = 1 627`, **después** del borde 1 626 de la ventana
    // 662: en el último slot admisible la garantía sigue en retirada.
    let s_lib = s_r + u64::try_from(p.r_votos_slots).expect("R_V >= 0");
    assert_eq!(s_lib, 1_627);
    assert_eq!(s_lib, e_max + 1);

    // v1.4 · antes (ventana 663, evidencia en 1 628) la garantía ya estaba liberada y el cobro era
    // 0; con el borde corregido la evidencia cae dentro y castiga la garantía en retirada:
    // C = min(50, techo(50/2)) = 25.
    let op = evidencia_misma_ventana(&s, n)?;
    let (penado, _u, r) = aplica_evidencia_en(&tras_retiro, &op, e_max);
    println!("rak_06: evidencia en {e_max} -> {r:?}");
    r?;
    assert_eq!(penado.garantias[&dueno].incidentes.len(), 1);
    assert_eq!(cobrado(&tras_retiro, &penado, 9), 25, "cobrado = 25");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// rak_07 · control fuera del rearranque (régimen normal, tabla caducada como mucho)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn rak_07_fuera_del_rearranque() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    assert_eq!(
        retencion_clave_voto(&p),
        1_024,
        "retención = max(1 024, 961)"
    );
    assert_eq!(
        retencion_clave_voto_por_tabla(&p),
        961,
        "cota por vida de tabla"
    );

    // Sin rearranque no hay instantánea: la clave se rota en `s_r` y la tabla vigente en ese
    // momento puede seguir asociándose hasta `k + CADUCIDAD` ventanas. La última evidencia de esa
    // tabla (la más tardía del diseño) cae en `cierre(k+CADUCIDAD) + plazo`.
    let (base, secretas) = estado_base(&[(1, 1, 50)])?;
    let s_r = 10_000u64; // par, para que k = s_r / T_inst sea exacto
    let k = s_r / T_INST_VOTOS;
    let k2 = bls_rot(1)?;
    let rotado = rotar_en(&base, 1, &k2, i64::try_from(s_r)?)?;
    let ret = retencion_clave_voto(&p);

    let n_tarde = k + CADUCIDAD_TABLA_VENTANAS;
    let e_tarde = cierre_ventana(n_tarde) + PLAZO_DEV;
    let edad_max = e_tarde - s_r;
    assert_eq!(edad_max, 962, "(CADUCIDAD+1)·T_inst + plazo");
    assert!(
        e_tarde <= s_r + ret,
        "la retención cubre la última evidencia de la tabla más vieja ({e_tarde} <= {})",
        s_r + ret
    );

    // La evidencia firmada con la clave anterior se admite y castiga en `e_tarde` (control: el
    // diseño dice que sí).
    let op = evidencia_misma_ventana(secreta(&secretas, 1)?, n_tarde)?;
    let (post, _u, r) = aplica_evidencia_en(&rotado, &op, e_tarde);
    println!("rak_07: evidencia en {e_tarde} (rotada en {s_r}) -> {r:?}");
    r?;
    assert_eq!(
        post.quemado - rotado.quemado,
        72,
        "castigo dentro del régimen normal"
    );

    // Borde exacto del vencimiento: en `s_r + ret` la clave anterior aún responde; un slot después
    // ya no.
    let e_venc = s_r + ret;
    let n_venc = (e_venc - PLAZO_DEV) / T_INST_VOTOS - 1;
    assert_eq!(cierre_ventana(n_venc) + PLAZO_DEV, e_venc);
    let op_venc = evidencia_misma_ventana(secreta(&secretas, 1)?, n_venc)?;
    let (post_venc, _u2, r_venc) = aplica_evidencia_en(&rotado, &op_venc, e_venc);
    r_venc?;
    assert_eq!(post_venc.garantias[&ed(1)].incidentes.len(), 1);
    let (_, _, r_fuera) = aplica_evidencia_en(&rotado, &op_venc, e_venc + 1);
    assert_eq!(r_fuera, Err(ErrorTransicion::ErrEvidenciaVoto));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// RAK-2 · rak_08–rak_11 · ¿la tabla de la instantánea sigue rigiendo tras el certificado de
// rearranque y admite certificados posteriores (hasta la caducidad) con la clave que rotó?
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn clave_contrato_voto(c: &ClaveTablaVoto) -> zx_votos::Clave {
    zx_votos::Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    }
}

fn tabla_contrato_voto(n: u64, claves: &[ClaveTablaVoto]) -> zx_votos::Tabla {
    zx_votos::Tabla {
        n,
        claves: claves.iter().map(clave_contrato_voto).collect(),
    }
}

/// `hash_tabla` del payload (no depende de `n`, como usa la transición).
fn hash_tabla_voto(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_contrato_voto(0, claves))
}

/// Certificado `0x09` con firmas BLS reales de las claves secretas dadas; cada firmante se localiza
/// en `tabla` por su clave pública (así puede armarse con la instantánea vieja aunque el estado ya
/// tenga la clave rotada).
fn op_certificado(
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    raiz: [u8; 32],
    tabla: &[ClaveTablaVoto],
    firmantes: &[&ClaveSecreta],
) -> Result<OperacionAlmacenamiento, Error> {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz);
    let mut votos: Vec<(usize, zx_votos::Firma)> = Vec::with_capacity(firmantes.len());
    for sk in firmantes {
        let publica = sk.clave_publica().bytes();
        let posicion = tabla
            .iter()
            .position(|c| c.clave_bls == publica)
            .ok_or("firmante fuera de la tabla")?;
        votos.push((posicion + 1, zx_votos::firmar(sk, DOMINIO_VOTO, &mensaje)?));
    }
    let cert = zx_votos::construir_certificado(
        n,
        candidato,
        h_t_siguiente,
        raiz,
        &tabla_contrato_voto(n, tabla),
        &votos,
    )?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

fn ed_real(k: u64) -> ClavePublica {
    clave_firmante(k)
}

/// Tres identidades reales (Ed25519 firmante + BLS de voto), un sector activo y garantía
/// `activo = 50` cada una; base de finalidad `m = 0` para que el gancho de instantáneas actúe.
fn estado_escenario() -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    est.terminal = Some(hash(1));
    let mut secretas = Vec::new();
    for i in 1u8..=3 {
        let s = bls(i)?;
        let k = ed_real(u64::from(i));
        est.claves_voto.insert(
            k,
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, k, 0);
        est.sectores.insert(id, reg);
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(50)?;
        est.garantias.insert(k, g);
        secretas.push((i, s));
    }
    est.emitido = 150;
    est.quemado = 0;
    est.finalidad_votos_n = 0;
    est.finalidad_votos = Some(hash(7));
    Ok((est, secretas))
}

/// Fija la tabla vigente de la base `m` (contenido conocido, sin sembrar Q) y devuelve su huella.
fn poner_tabla_base(est: &mut Estado, m: u64, t: &[ClaveTablaVoto]) -> [u8; 32] {
    let h = hash_tabla_voto(t);
    est.finalidad_votos_n = m;
    est.finalidad_votos = Some(hash(7));
    est.finalidad_votos_h_t = Some(h);
    est.tablas_voto_contenido.insert(h, t.to_vec());
    est.tablas_voto.insert(m, t.to_vec());
    est.liquidacion_voto_hasta = Some(m);
    h
}

/// Rota la clave de voto `clave` a `nueva` por el camino real `0x03`.
fn rotar_en_clave(
    estado: &Estado,
    clave: ClavePublica,
    nueva: &ClaveSecreta,
    slot: i64,
) -> Result<Estado, Error> {
    let p = ParametrosSector::dev();
    let op = op_clave_voto(clave, nueva);
    let (rotado, _undo, motivo) = aplicar_almacenamiento_con_undo(estado, &op, slot, &p);
    assert_eq!(motivo, MotivoSector::Ok, "la rotación 0x03 debe aceptarse");
    Ok(rotado)
}

struct Escenario {
    est: Estado,
    secretas: Vec<(u8, ClaveSecreta)>,
    t_snap: Vec<ClaveTablaVoto>,
    h_snap: [u8; 32],
    /// TB4-R4 · tabla fresca de `Q` que el certificado de rearranque compromete (la instantánea ya
    /// no es admisible como siguiente).
    t_fresca: Vec<ClaveTablaVoto>,
    h_fresca: [u8; 32],
    k1_vieja: ClaveSecreta,
    k1_nueva: ClaveSecreta,
}

/// Escenario con la transición real: instantánea del ciclo 0 en `ref(0)+1 = 603`, rotación de la
/// clave 1 en `ref(0)+2 = 604` (vence en 1 628) y retirada real de la garantía de la clave 3 en 604.
/// El gancho por ventana (TB4-R1) deposita en `Q` la tabla fresca de la ventana del rearranque.
fn escenario_rearranque() -> Result<Escenario, Error> {
    let (base, secretas) = estado_escenario()?;
    let (mut est, _u) = tomar_instantaneas_rearranque_con_undo(&base, 603);
    let h_snap = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("sin instantánea del ciclo 0")?;
    let t_snap = est
        .tablas_voto_contenido
        .get(&h_snap)
        .ok_or("sin contenido de la instantánea")?
        .clone();
    assert_eq!(t_snap.len(), 3, "la instantánea tiene las tres claves");
    let _ = poner_tabla_base(&mut est, 0, &t_snap);
    let (est, _u) = derivar_tabla_sin_base_con_undo(&est, 603);
    let est = rotar_en_clave(&est, ed_real(1), &bls_rot(1)?, 604)?;
    let est = aplicar_garantia_en(&est, TipoGarantia::Retiro, ed_real(3), 50, 0, 604, 3)?;
    // TB4-R1/R4 · la cadena deriva D(E, k) al cruzar cada ventana: se deriva la del borde 662 para
    // que el certificado de rearranque tenga una tabla fresca admisible que comprometer.
    let (est, _u) = derivar_tabla_sin_base_con_undo(&est, 2 * 662);
    let h_fresca = est
        .cola_tablas_voto
        .last()
        .ok_or("sin tabla fresca en la cola")?
        .1;
    let t_fresca = est
        .tablas_voto_contenido
        .get(&h_fresca)
        .ok_or("sin contenido de la tabla fresca")?
        .clone();
    Ok(Escenario {
        est,
        secretas,
        t_snap,
        h_snap,
        t_fresca,
        h_fresca,
        k1_vieja: bls(1)?,
        k1_nueva: bls_rot(1)?,
    })
}

/// TB4-R4/R5 · aplica el certificado de rearranque de la última ventana que cierra en la fase
/// activa (662): verifica con la instantánea y compromete la tabla fresca de `Q`.
fn aplicar_rearranque_662(esc: &Escenario) -> Result<Estado, Error> {
    let cal = calendario_rearranque(&ParametrosSector::dev(), 0).ok_or("sin calendario")?;
    let (n, _, _) = borde_v14(&cal);
    assert_eq!(n, 662);
    let s2 = secreta(&esc.secretas, 2)?;
    let cert = op_certificado(
        n,
        [0x22; 32],
        esc.h_fresca,
        [0x33; 32],
        &esc.t_snap,
        &[&esc.k1_vieja, s2],
    )?;
    let (nuevo, _undo, r) = aplicar_certificado_peso_con_undo(&esc.est, &cert, 1_324);
    r?;
    Ok(nuevo)
}

#[test]
fn rak_08_que_tabla_queda_vigente_tras_el_certificado_de_rearranque() -> Result<(), Error> {
    let esc = escenario_rearranque()?;
    let nuevo = aplicar_rearranque_662(&esc)?;

    // v1.4 · antes la tabla vigente seguía siendo la instantánea (h_snap); ahora se compromete la
    // tabla fresca de `Q` y la instantánea deja de certificar.
    assert_eq!(
        nuevo.finalidad_votos_n, 662,
        "la base pasa a la ventana 662"
    );
    assert_eq!(
        nuevo.finalidad_votos_h_t,
        Some(esc.h_fresca),
        "la tabla vigente es la fresca de la cola, no la instantánea"
    );
    assert_ne!(esc.h_fresca, esc.h_snap);
    assert!(
        nuevo.tabla_ciclo_rearranque.is_empty(),
        "Y2 borra las instantáneas al avanzar la base"
    );
    assert_eq!(
        nuevo.cola_tablas_voto,
        vec![(301, esc.h_snap), (662, esc.h_fresca)],
        "la cola conserva la instantánea y la fresca (sin empujes de la aplicación)"
    );
    assert!(
        !nuevo.finalidad_votos_h_t.is_some_and(|h| h == esc.h_snap),
        "la instantánea ya no es la vigente"
    );

    let vigente = nuevo
        .tablas_voto_contenido
        .get(&esc.h_fresca)
        .ok_or("sin contenido de la vigente")?;
    let bls_vieja = esc.k1_vieja.clave_publica().bytes();
    let bls_nueva = esc.k1_nueva.clave_publica().bytes();
    assert!(
        !vigente.iter().any(|c| c.clave_bls == bls_vieja),
        "la tabla fresca ya no contiene la clave rotada en ref+1"
    );
    assert!(
        vigente.iter().any(|c| c.clave_bls == bls_nueva),
        "la tabla que aceptará el siguiente certificado es la que trae la clave nueva"
    );
    assert_eq!(
        nuevo.claves_voto[&ed_real(1)].clave_bls,
        bls_nueva,
        "el estado tiene la clave nueva"
    );
    println!(
        "rak_08: base=662; vigente=h_fresca (vieja={} nueva={}); cola=2",
        vigente.iter().any(|c| c.clave_bls == bls_vieja),
        vigente.iter().any(|c| c.clave_bls == bls_nueva)
    );
    Ok(())
}

#[test]
fn rak_09_siguiente_certificado_con_la_tabla_antigua() -> Result<(), Error> {
    let esc = escenario_rearranque()?;
    let nuevo = aplicar_rearranque_662(&esc)?;
    let s2 = secreta(&esc.secretas, 2)?;

    // v1.4 · antes la instantánea seguía vigente y admitía los certificados siguientes; ahora la
    // vigente es la tabla fresca y la instantánea ya no está fresca en `Q`.

    // (a) ventana siguiente (663), armada con la instantánea: rechazada (huella no fresca en Q y
    // firma contra la tabla fresca).
    let cert = op_certificado(
        663,
        [0x40; 32],
        esc.h_snap,
        [0x41; 32],
        &esc.t_snap,
        &[&esc.k1_vieja, s2],
    )?;
    let (_p, _u, r) = aplicar_certificado_peso_con_undo(&nuevo, &cert, 1_326);
    println!("rak_09: 663 con instantánea -> {r:?}");
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );

    // (b) ventana lejana pero dentro de la caducidad (992 = 662 + 330), armada con la instantánea:
    // rechazada igual.
    let cert = op_certificado(
        992,
        [0x42; 32],
        esc.h_snap,
        [0x43; 32],
        &esc.t_snap,
        &[&esc.k1_vieja, s2],
    )?;
    let (_p, _u, r) = aplicar_certificado_peso_con_undo(&nuevo, &cert, 1_984);
    println!("rak_09: 992 con instantánea -> {r:?}");
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );

    // (c) la tabla fresca (vigente) sí puede certificar la ventana siguiente dentro del tope de edad,
    // firmando con sus claves (la nueva de la identidad 1 y la 2).
    let cert = op_certificado(
        663,
        [0x44; 32],
        esc.h_fresca,
        [0x45; 32],
        &esc.t_fresca,
        &[&esc.k1_nueva, s2],
    )?;
    let (post663, _u, r) = aplicar_certificado_peso_con_undo(&nuevo, &cert, 1_326);
    println!("rak_09: 663 con la fresca -> {r:?}");
    r?;
    assert_eq!(post663.finalidad_votos_n, 663);
    assert_eq!(post663.finalidad_votos_h_t, Some(esc.h_fresca));
    Ok(())
}

#[test]
fn rak_10_evidencia_en_esas_ventanas() -> Result<(), Error> {
    let esc = escenario_rearranque()?;
    let nuevo = aplicar_rearranque_662(&esc)?;
    let s2 = secreta(&esc.secretas, 2)?;
    // v1.4 · la ventana 992 (aún dentro de la caducidad) armada con la instantánea ya no se admite.
    let cert = op_certificado(
        992,
        [0x42; 32],
        esc.h_snap,
        [0x43; 32],
        &esc.t_snap,
        &[&esc.k1_vieja, s2],
    )?;
    let (_p, _u, r) = aplicar_certificado_peso_con_undo(&nuevo, &cert, 1_984);
    println!("rak_10: 992 con instantánea -> {r:?}");
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );

    let n = 992u64;
    let e_max = cierre_ventana(n) + PLAZO_DEV;
    assert_eq!(e_max, 2_286, "último slot admisible de la ventana 992");

    // (a) doble voto de la clave que rotó en ref+1: la evidencia se rechaza (ya no está en el índice
    // de retención en 2 288).
    let op = evidencia_misma_ventana(&esc.k1_vieja, n)?;
    let (post, _u, r) = aplica_evidencia_en(&nuevo, &op, e_max);
    println!("rak_10: evidencia de la clave rotada en {e_max} -> {r:?}");
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));
    assert_eq!(post, nuevo, "el rechazo no muta el estado");
    assert_eq!(cobrado(&nuevo, &post, 9), 0, "no cobra nada");

    // (b) doble voto de la garantía retirada en ref+1 (clave 3, sin rotar): se ADMITE (la clave
    // sigue registrada), pero la garantía ya se liberó. El bono de sector, en cambio, sigue vivo:
    // `V = fianza_no_terminal = q_sec` y `C = techo(q_sec/2)`.
    let con_lib = aplicar_garantia_en(
        &nuevo,
        TipoGarantia::Liberacion,
        ed_real(3),
        50,
        1,
        2_000,
        3,
    )?;
    assert!(
        con_lib.garantias[&ed_real(3)].en_retirada.is_empty(),
        "la garantía en retirada ya salió"
    );
    assert_eq!(con_lib.garantias[&ed_real(3)].activo, Amount::CERO);
    let op = evidencia_misma_ventana(secreta(&esc.secretas, 3)?, n)?;
    let (post3, _u, r3) = aplica_evidencia_en(&con_lib, &op, e_max);
    println!("rak_10: evidencia de la garantía retirada en {e_max} -> {r3:?}");
    r3?;
    assert_eq!(post3.garantias[&ed_real(3)].incidentes.len(), 1);
    let q = ParametrosSector::dev().q_sec;
    assert_eq!(
        cobrado(&con_lib, &post3, 9),
        i128::from((q + 1) / 2),
        "cobra el bono de sector: C = techo(q_sec/2)"
    );
    Ok(())
}

#[test]
fn rak_11_segundo_ciclo_sin_certificado() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).ok_or("sin calendario")?;
    assert_eq!(cal.referencia(1), 1_328, "ref(1) = inicio(1) - 660");
    assert_eq!(cal.inicio(1), 1_988);

    let (base, _secretas) = estado_escenario()?;
    let (mut est, _u) = tomar_instantaneas_rearranque_con_undo(&base, 603);
    let h_snap = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("sin instantánea del ciclo 0")?;
    let t_snap = est
        .tablas_voto_contenido
        .get(&h_snap)
        .ok_or("sin contenido de la instantánea")?
        .clone();
    let _ = poner_tabla_base(&mut est, 0, &t_snap);
    let (est, _u) = derivar_tabla_sin_base_con_undo(&est, 603);
    let est = rotar_en_clave(&est, ed_real(1), &bls_rot(1)?, 604)?;

    // En `ref(1) = 1 328` todavía no se toma (la condición es estricta); en 1 329 sí.
    let (en_ref, _u) = tomar_instantaneas_rearranque_con_undo(&est, 1_328);
    assert!(
        en_ref.tabla_ciclo_rearranque.is_empty(),
        "en ref(1) no hay instantánea nueva"
    );
    let (ciclo1, _u) = tomar_instantaneas_rearranque_con_undo(&est, 1_329);
    assert_eq!(
        ciclo1.tabla_ciclo_rearranque.len(),
        1,
        "una sola instantánea, la del ciclo 1"
    );
    let h1 = *ciclo1
        .tabla_ciclo_rearranque
        .get(&1)
        .ok_or("sin instantánea del ciclo 1")?;
    let t1 = ciclo1
        .tablas_voto_contenido
        .get(&h1)
        .ok_or("sin contenido del ciclo 1")?;
    let bls_vieja = bls(1)?.clave_publica().bytes();
    let bls_nueva = bls_rot(1)?.clave_publica().bytes();
    assert!(
        t1.iter().any(|c| c.clave_bls == bls_nueva),
        "contiene la clave nueva"
    );
    assert!(
        !t1.iter().any(|c| c.clave_bls == bls_vieja),
        "ya no contiene la clave que rotó en ref(0)+1"
    );
    println!(
        "rak_11: instantánea del ciclo 1 en el primer slot > ref(1)=1328 (1329); vieja={} nueva={}",
        t1.iter().any(|c| c.clave_bls == bls_vieja),
        t1.iter().any(|c| c.clave_bls == bls_nueva)
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// RAK-3 · rak_12–rak_16 · fuera del rearranque, ¿puede una tabla vieja seguir certificando
// cuando quienes salieron de ella ya no responden? (con la transición real)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Estado **sin base** de finalidad por votos (rama X2/T5′: `finalidad_votos` y
/// `finalidad_votos_h_t` ausentes). El gancho `derivar_tabla_sin_base` (T1′) llena la cola.
fn estado_sin_base() -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let (mut est, secretas) = estado_escenario()?;
    est.finalidad_votos = None;
    est.finalidad_votos_h_t = None;
    est.finalidad_votos_n = 0;
    Ok((est, secretas))
}

/// Estado con base `m = 0` y tabla vigente `T0` = derivada de la ventana 0 (las tres claves del
/// escenario), cola `Q` arrancada con su huella.
struct BaseT0 {
    est: Estado,
    secretas: Vec<(u8, ClaveSecreta)>,
    t0: Vec<ClaveTablaVoto>,
    h0: [u8; 32],
}

fn base_con_t0() -> Result<BaseT0, Error> {
    let (mut est, secretas) = estado_escenario()?;
    let t0 = tabla_derivada(&est, 0);
    let h0 = hash_tabla_voto(&t0);
    poner_tabla_base(&mut est, 0, &t0);
    let (est, _u) = derivar_tabla_sin_base_con_undo(&est, 0);
    Ok(BaseT0 {
        est,
        secretas,
        t0,
        h0,
    })
}

#[test]
fn rak_12_la_cola_tras_certificados_espaciados() -> Result<(), Error> {
    let BaseT0 {
        est,
        secretas,
        t0,
        h0,
    } = base_con_t0()?;
    // La clave 3 sale de la tabla en cuanto se deriva `T0`: rotación real `0x03` en el slot 1.
    let est = rotar_en_clave(&est, ed_real(3), &bls_rot(3)?, 1)?;
    let d_rot = tabla_derivada(&est, 2);
    let h_rot = hash_tabla_voto(&d_rot);
    assert_ne!(h_rot, h0, "la derivada cambia con la rotación");

    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    // v1.4 · TB4-R1/R6: la aplicación ya no empuja a `Q`; solo el gancho por ventana la mantiene, de
    // modo que `T0` conserva su ventana 0 y deja de ser admisible pasadas `X` ventanas.
    let mut actual = est;
    let cert1 = op_certificado(1, [0x50; 32], h0, [0x60; 32], &t0, &[k1, k2])?;
    let (nuevo1, _u, r) = aplicar_certificado_peso_con_undo(&actual, &cert1, 2);
    r?;
    assert_eq!(
        nuevo1.finalidad_votos_h_t,
        Some(h0),
        "T0 sigue vigente en la ventana 1"
    );
    assert_eq!(
        nuevo1.cola_tablas_voto, actual.cola_tablas_voto,
        "la aplicación no toca la cola (un solo dueño: el gancho)"
    );
    actual = nuevo1;

    // Ventanas espaciadas pero aún dentro de la caducidad de la base (`m = 1`, tope `1 + 330`); la
    // 601 y la 901 caerían en la rama de rearranque y no es lo que se prueba aquí.
    for (i, n) in [301u64, 331].iter().enumerate() {
        let cert = op_certificado(
            *n,
            [0x51 + i as u8; 32],
            h0,
            [0x61 + i as u8; 32],
            &t0,
            &[k1, k2],
        )?;
        let (_e, _u, r) = aplicar_certificado_peso_con_undo(&actual, &cert, i64::try_from(2 * n)?);
        println!("rak_12: ventana {n} recometiendo T0 -> {r:?}");
        assert_eq!(
            r,
            Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::TablaNoDerivada
            )),
            "T0 ya no está fresca en Q"
        );
    }
    assert_eq!(actual.finalidad_votos_n, 1, "la base no avanzó");

    // El gancho sí refresca: la derivada fresca entra en la cola y sustituye a T0 como siguiente.
    let (con_q, _u) = derivar_tabla_sin_base_con_undo(&actual, 2 * 301);
    assert!(
        con_q.cola_tablas_voto.iter().any(|(_, h)| *h == h_rot),
        "la derivada fresca está en la cola"
    );
    let cert = op_certificado(301, [0x52; 32], h_rot, [0x62; 32], &t0, &[k1, k2])?;
    let (post, _u, r) = aplicar_certificado_peso_con_undo(&con_q, &cert, 2 * 301);
    r?;
    assert_eq!(post.finalidad_votos_n, 301);
    assert_eq!(post.finalidad_votos_h_t, Some(h_rot));
    Ok(())
}

#[test]
fn rak_13_volver_a_comprometer_la_tabla_vigente() -> Result<(), Error> {
    let BaseT0 {
        est,
        secretas,
        t0,
        h0,
    } = base_con_t0()?;
    let est = rotar_en_clave(&est, ed_real(3), &bls_rot(3)?, 1)?;
    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;

    // v1.4 · antes `T0` se podía recometer 16 veces (una cada 330 ventanas). Con el tope de edad
    // solo se admite mientras está fresca: la ventana 331 (edad 331 > X = 31), aún dentro de la
    // caducidad, ya no.
    let mut actual = est;
    let mut exitos = 0u32;
    let mut primer_rechazo: Option<u64> = None;
    for i in 0..2u64 {
        let n = 1 + 330 * i;
        let cert = op_certificado(n, [0x70 + i as u8; 32], h0, [0x80; 32], &t0, &[k1, k2])?;
        let (nuevo, _u, r) =
            aplicar_certificado_peso_con_undo(&actual, &cert, i64::try_from(2 * n)?);
        match r {
            Ok(()) => {
                exitos += 1;
                actual = nuevo;
            }
            Err(e) => {
                assert_eq!(
                    e,
                    ErrorTransicion::ErrCertificadoPesoMotivo(MotivoPeso::TablaNoDerivada)
                );
                if primer_rechazo.is_none() {
                    primer_rechazo = Some(n);
                }
            }
        }
    }
    assert_eq!(exitos, 1, "T0 solo se admite mientras está fresca");
    assert_eq!(
        primer_rechazo,
        Some(331),
        "la ventana 331 ya supera el tope X = 31"
    );
    assert_eq!(actual.finalidad_votos_n, 1);

    // La tabla fresca de la cola sí permite avanzar la base.
    let (con_q, _u) = derivar_tabla_sin_base_con_undo(&actual, 2 * 331);
    let d_rot = tabla_derivada(&con_q, 331);
    let h_rot = hash_tabla_voto(&d_rot);
    let cert = op_certificado(331, [0x90; 32], h_rot, [0x91; 32], &t0, &[k1, k2])?;
    let (post, _u, r) = aplicar_certificado_peso_con_undo(&con_q, &cert, i64::from(2 * 331));
    r?;
    assert_eq!(post.finalidad_votos_n, 331);
    assert_eq!(post.finalidad_votos_h_t, Some(h_rot));
    println!("rak_13: T0 deja de recometerse; la fresca avanza la base a 331");
    Ok(())
}

#[test]
fn rak_14_evidencia_cuando_la_clave_ya_no_responde() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let BaseT0 { est, secretas, .. } = base_con_t0()?;
    // Una clave de T0 (la 3) rota justo después de derivarse T0 (slot 1); otra (la 2) retira su
    // garantía (slot 1) y la libera en `1 + R_V = 1 025`.
    let est = rotar_en_clave(&est, ed_real(3), &bls_rot(3)?, 1)?;
    let est = aplicar_garantia_en(&est, TipoGarantia::Retiro, ed_real(2), 50, 0, 1, 2)?;
    assert_eq!(est.garantias[&ed_real(2)].en_retirada.len(), 1);
    assert_eq!(est.garantias[&ed_real(2)].activo, Amount::CERO);
    let s_lib = 1 + u64::try_from(p.r_votos_slots)?;
    let est = aplicar_garantia_en(&est, TipoGarantia::Liberacion, ed_real(2), 50, 1, s_lib, 2)?;
    assert!(
        est.garantias[&ed_real(2)].en_retirada.is_empty(),
        "garantía fuera"
    );

    // v1.4 · ya no hacen falta «16 recompromisos espaciados» (que hoy se rechazan tras el primero):
    // basta la ventana 4 951 y su último slot admisible para el caso de evidencia.
    let n = 4_951u64;
    let e_max = cierre_ventana(n) + PLAZO_DEV;
    assert_eq!(e_max, 10_204, "último slot admisible de la ventana 4 951");

    // (a) doble voto de la clave que rotó en el slot 1: la evidencia se rechaza (ya no responde).
    let op3 = evidencia_misma_ventana(secreta(&secretas, 3)?, n)?;
    let (post, _u, r) = aplica_evidencia_en(&est, &op3, e_max);
    println!("rak_14: evidencia de la clave rotada en {e_max} -> {r:?}");
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));
    assert_eq!(post, est, "el rechazo no muta el estado");
    assert_eq!(cobrado(&est, &post, 9), 0, "cobrado = 0");

    // (b) doble voto de la garantía retirada y liberada (clave 2, sin rotar): se admite, pero la
    // garantía ya no está; solo queda el bono de sector `C = techo(q_sec/2)`.
    let op2 = evidencia_misma_ventana(secreta(&secretas, 2)?, n)?;
    let (post2, _u, r2) = aplica_evidencia_en(&est, &op2, e_max);
    println!("rak_14: evidencia de la garantía retirada en {e_max} -> {r2:?}");
    r2?;
    assert_eq!(post2.garantias[&ed_real(2)].incidentes.len(), 1);
    let q = p.q_sec;
    assert_eq!(
        cobrado(&est, &post2, 9),
        i128::from((q + 1) / 2),
        "solo el bono de sector"
    );
    Ok(())
}

#[test]
fn rak_15_primer_certificado_sin_base_con_tabla_antigua() -> Result<(), Error> {
    // Sin base, el gancho T1′ deriva al cruzar cada ventana. v1.4 · al actualizar la ventana en el
    // sitio, la huella de la ventana 0 conserva su ventana y pasadas `X` ventanas queda fuera del
    // tope: el primer certificado no puede declararla.
    let (est, secretas) = estado_sin_base()?;
    let (est, _u) = derivar_tabla_sin_base_con_undo(&est, 0);
    assert_eq!(est.cola_tablas_voto.len(), 1, "primera derivación sin base");
    let h0 = est.cola_tablas_voto[0].1;
    assert_eq!(est.cola_tablas_voto[0].0, 0, "T0 se deriva en la ventana 0");
    // La clave 3 sale de T0 justo después (rotación real en el slot 1).
    let est = rotar_en_clave(&est, ed_real(3), &bls_rot(3)?, 1)?;
    let mut est = est;
    for k in 1..=400u64 {
        let (nuevo, _u) = derivar_tabla_sin_base_con_undo(&est, 2 * k);
        est = nuevo;
    }
    assert_eq!(est.ultima_ventana_derivada_sin_base, Some(400));
    assert_eq!(
        est.cola_tablas_voto.len(),
        2,
        "solo T0 y la derivada con la clave nueva"
    );
    assert_eq!(est.cola_tablas_voto[0], (0, h0), "T0 conserva su ventana 0");
    let h_rot = est.cola_tablas_voto[1].1;
    assert_eq!(
        est.cola_tablas_voto[1].0, 400,
        "la fresca se actualiza en el sitio"
    );
    assert_ne!(h_rot, h0);

    let n = 400u64;
    let t0 = est
        .tablas_voto_contenido
        .get(&h0)
        .cloned()
        .ok_or("sin contenido de T0")?;
    let t_rot = est
        .tablas_voto_contenido
        .get(&h_rot)
        .cloned()
        .ok_or("sin contenido de la fresca")?;
    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    // (a) la tabla vieja (edad 400 > X = 31) se rechaza.
    let cert = op_certificado(n, [0xA0; 32], h0, [0xA1; 32], &t0, &[k1, k2])?;
    let (_e, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * n)?);
    println!("rak_15: primer certificado sin base con T0 -> {r:?}");
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    // (b) la tabla fresca de la cola se admite.
    let cert = op_certificado(n, [0xA2; 32], h_rot, [0xA3; 32], &t_rot, &[k1, k2])?;
    let (primero, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * n)?);
    r?;
    assert_eq!(primero.finalidad_votos_n, n);
    assert_eq!(
        primero.finalidad_votos_h_t,
        Some(h_rot),
        "la tabla fresca queda vigente"
    );

    // (paso 3) evidencia de la clave 3 rotada en la ventana 400, en su último slot admisible.
    let e_max = cierre_ventana(n) + PLAZO_DEV;
    assert_eq!(e_max, 1_102);
    let op3 = evidencia_misma_ventana(secreta(&secretas, 3)?, n)?;
    let (post, _u, r) = aplica_evidencia_en(&primero, &op3, e_max);
    println!("rak_15: evidencia de la clave rotada en {e_max} -> {r:?}");
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));
    assert_eq!(cobrado(&primero, &post, 9), 0);
    Ok(())
}

#[test]
fn rak_16_regimen_denso() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let BaseT0 {
        est,
        secretas,
        t0,
        h0,
    } = base_con_t0()?;
    // La clave 3 rota tras derivarse T0; desde la ventana 2 la tabla vigente es la derivada fresca
    // (que ya lleva la clave nueva).
    let est = rotar_en_clave(&est, ed_real(3), &bls_rot(3)?, 1)?;
    let d_rot = tabla_derivada(&est, 2);
    let h_rot = hash_tabla_voto(&d_rot);
    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    let mut actual = est;
    for i in 1..=20u64 {
        // v1.4 · TB4-R1: el gancho por ventana mantiene la cola (la aplicación ya no empuja). Se
        // deriva con el estado de entrada, como el bloque real antes de las operaciones.
        let (con_q, _u) = derivar_tabla_sin_base_con_undo(&actual, 2 * i);
        actual = con_q;
        let h_next = if i == 1 { h0 } else { h_rot };
        let tabla_vig = if i <= 2 { &t0 } else { &d_rot };
        let cert = op_certificado(
            i,
            [0xB0u8.wrapping_add(i as u8); 32],
            h_next,
            [0xB1; 32],
            tabla_vig,
            &[k1, k2],
        )?;
        let (nuevo, _u, r) =
            aplicar_certificado_peso_con_undo(&actual, &cert, i64::try_from(2 * i)?);
        r?;
        actual = nuevo;
        assert_eq!(actual.finalidad_votos_n, i);
        assert!(
            actual.cola_tablas_voto.len() <= K_TABLAS_VOTO,
            "cola acotada en {i}"
        );
        if i == 1 {
            assert_eq!(actual.finalidad_votos_h_t, Some(h0));
        } else {
            assert_eq!(
                actual.finalidad_votos_h_t,
                Some(h_rot),
                "tabla fresca en {i}"
            );
        }
    }
    // La tabla vigente es la derivada de su propia ventana: edad 0 ≤ K_TABLAS_VOTO.
    let vigente = tabla_derivada(&actual, actual.finalidad_votos_n);
    assert_eq!(
        hash_tabla_voto(&vigente),
        h_rot,
        "vigente = derivada de la ventana actual"
    );

    // Control: una clave que rota justo después de la tabla fresca responde cuando llega la evidencia
    // de su ventana (cierre + plazo = 342 ≪ vencimiento 1 065).
    let s_r: i64 = 2 * 20 + 1;
    let actual = rotar_en_clave(&actual, ed_real(1), &bls_rot(1)?, s_r)?;
    assert_eq!(
        actual.claves_voto_previas[&ed_real(1)].vencimiento,
        u64::try_from(s_r)? + retencion_clave_voto(&p)
    );
    let e_max = cierre_ventana(20) + PLAZO_DEV;
    assert_eq!(e_max, 342);
    let op = evidencia_misma_ventana(secreta(&secretas, 1)?, 20)?;
    let (post, _u, r) = aplica_evidencia_en(&actual, &op, e_max);
    println!("rak_16: evidencia de la clave rotada tras tabla fresca en {e_max} -> {r:?}");
    r?;
    assert_eq!(post.garantias[&ed_real(1)].incidentes.len(), 1);
    assert!(cobrado(&actual, &post, 9) > 0, "castiga");
    Ok(())
}
