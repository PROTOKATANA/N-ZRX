//! PD-1b2 · Q1/Q2 · con base `m`, las ventanas `n > m + CADUCIDAD_TABLA_VENTANAS` no tienen tabla
//! vigente: se liquidan **sin cobro** y un acta de una ventana caducada se rechaza con
//! `ErrActaTablaDesconocida`.
//!
//! Pruebas V1–V4 de la orden PD-1b2 sobre el camino de estado real. V5 es la suite de
//! `pd1b_compacto.rs`, `pd1c_huecos.rs` y `aus2a_falta_voto.rs` en verde (se ejecuta con
//! `cargo test -p zx-consensus`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use zx_consensus::sectores::{ClaveVoto, ParametrosSector};
use zx_consensus::transicion::votos::{
    W_REVEAL_SLOTS_VOTOS, aplicar_acta_presencia_con_undo, aplicar_voto_propio_con_undo,
    cierre_ventana,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

const CBID: u32 = 0;
const DEN: i128 = 1_401_600_000;
const CADUCIDAD: u64 = 330;

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Utilidades (mismas que `pd1b_compacto.rs`, autocontenidas)
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
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
        w_min: primitive_types::U256::zero(),
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

/// Estado con `indices` registrados (clave BLS determinista) y garantía activa `g` por clave.
fn estado_con(indices: &[u8], g: i128) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let mut est = Estado::inicial();
    est.parametros_sector = ParametrosSector::dev();
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for i in indices {
        let s = bls(*i)?;
        est.claves_voto.insert(
            ed(*i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let mut gg = Garantia::nueva();
        gg.activo = Amount::nuevo(i64::try_from(g)?)?;
        est.garantias.insert(ed(*i), gg);
        secretas.push((*i, s));
    }
    Ok((est, secretas))
}

fn clave_contrato(c: &ClaveTablaVoto) -> Clave {
    Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    }
}

fn tabla_contrato(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves.iter().map(clave_contrato).collect(),
    }
}

fn hash_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_contrato(0, claves))
}

/// Tabla canónica (ascendente por bytes de clave) con los pesos dados.
fn tabla_canonica(est: &Estado, pesos: &[(u8, u64)]) -> Vec<ClaveTablaVoto> {
    let mut t: Vec<ClaveTablaVoto> = pesos
        .iter()
        .map(|(i, w)| ClaveTablaVoto {
            clave_bls: est.claves_voto[&ed(*i)].clave_bls,
            peso: *w,
            activo: true,
            prueba: false,
            garantia: *w,
        })
        .collect();
    t.sort_by_key(|a| a.clave_bls);
    t
}

/// Fija la base `m` con la tabla `t` como vigente (C2) y la asocia a `m`.
fn poner_base(est: &mut Estado, m: u64, t: &[ClaveTablaVoto]) {
    let h = hash_payload(t);
    est.finalidad_votos_n = m;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some(h);
    est.tablas_voto_contenido.insert(h, t.to_vec());
    est.tablas_voto.insert(m, t.to_vec());
    est.cola_tablas_voto.push((m, h));
    est.liquidacion_voto_hasta = Some(m);
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

/// Acta de presencia (`0x0A`) o certificado compacto (`0x09`) con firmas BLS reales sobre A3.
#[allow(clippy::too_many_arguments)]
fn op_compacto(
    est: &Estado,
    secretas: &[(u8, ClaveSecreta)],
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    raiz_declarada: [u8; 32],
    raiz_firmada: [u8; 32],
    tabla: &[ClaveTablaVoto],
    firmantes: &[u8],
    _tabla_siguiente: Option<&[ClaveTablaVoto]>,
    acta: bool,
) -> Result<OperacionAlmacenamiento, Error> {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz_firmada);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for i in firmantes {
        let bls_i = est.claves_voto[&ed(*i)].clave_bls;
        let Some(pos) = tabla.iter().position(|c| c.clave_bls == bls_i) else {
            continue;
        };
        let f = zx_votos::firmar(secreta(secretas, *i)?, DOMINIO_VOTO, &mensaje)?;
        votos.push((pos + 1, f));
    }
    let cert = zx_votos::construir_certificado(
        n,
        candidato,
        h_t_siguiente,
        raiz_declarada,
        &tabla_contrato(n, tabla),
        &votos,
    )?;
    let bytes = zx_votos::serial_certificado_peso(&cert);
    if acta {
        Ok(OperacionAlmacenamiento::ActaPresencia {
            clave: ed(200),
            bytes,
        })
    } else {
        Ok(OperacionAlmacenamiento::CertificadoPeso {
            clave: ed(200),
            bytes,
        })
    }
}

fn voto_propio(
    secreta: &ClaveSecreta,
    clave: u8,
    n: u64,
    candidato: [u8; 32],
    h_t: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let firma: Firma = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]),
    )?;
    Ok(OperacionAlmacenamiento::VotoPropio {
        clave: ed(clave),
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave_bls: pk.bytes(),
        firma: firma.bytes(),
    })
}

/// Aplica un bloque PoST vacío (dispara la liquidación) y devuelve estado y undo.
fn aplica_post(est: &Estado, slot: u64) -> Result<(Estado, zx_consensus::transicion::Undo), Error> {
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash(1),
            padre: hash(2),
            slot,
            productor: ed(1),
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        Vec::new(),
    );
    Ok(aplicar_con_undo(
        est,
        &bloque,
        &params(),
        CBID,
        &ParametrosEvidencia::inactiva(),
    )?)
}

fn slot_liquidacion(n: u64) -> u64 {
    cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1
}

fn deuda(est: &Estado, i: u8) -> i128 {
    est.deuda_ausencia.get(&ed(i)).copied().unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// V1 · V2 · V4 — ninguna ventana posterior a la caducidad cobra; las que votan no acumulan
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn v1_v2_v4_frontera_sin_cobro() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    let m = 0u64;
    poner_base(&mut est, m, &tabla);
    let h_t = hash_payload(&tabla);
    let candidato = [0x22u8; 32];

    // Las claves 1 y 2 publican su voto propio en cada ventana `m+1 … m+332`; la 3 nunca vota.
    for n in (m + 1)..=(m + CADUCIDAD + 2) {
        for i in [1u8, 2] {
            let vp = voto_propio(secreta(&secretas, i)?, i, n, candidato, h_t)?;
            let slot = i64::try_from(cierre_ventana(n))?;
            let (nuevo, _, r) = aplicar_voto_propio_con_undo(&est, &vp, slot);
            r?;
            est = nuevo;
        }
    }

    // Liquidación escalonada en la frontera: hasta m+329, m+330, m+331 y m+332.
    let (est, _) = aplica_post(&est, slot_liquidacion(m + CADUCIDAD - 1))?;
    let q_antes = est.quemado;
    let (est, _) = aplica_post(&est, slot_liquidacion(m + CADUCIDAD))?;
    let d_330 = deuda(&est, 3);
    let q_330 = est.quemado;
    let (est, _) = aplica_post(&est, slot_liquidacion(m + CADUCIDAD + 1))?;
    let d_331 = deuda(&est, 3);
    let q_331 = est.quemado;
    let (est, _) = aplica_post(&est, slot_liquidacion(m + CADUCIDAD + 2))?;
    let d_332 = deuda(&est, 3);
    let q_332 = est.quemado;

    // V4 · la ventana m+330, dentro de la caducidad, sí cobra.
    assert!(
        q_330 > q_antes,
        "m+330 debe cobrar: quemado {q_antes} -> {q_330}"
    );
    // V1 · m+331 y m+332 no añaden deuda ni quema a la ausente.
    assert_eq!(d_331, d_330, "m+331 no añade deuda (base {d_330})");
    assert_eq!(d_332, d_330, "m+332 no añade deuda (base {d_330})");
    assert_eq!(q_331, q_330, "m+331 no quema (base {q_330})");
    assert_eq!(q_332, q_330, "m+332 no quema (base {q_330})");
    // V2 · las dos claves que votan no acumulan deuda en ninguna ventana.
    assert_eq!(deuda(&est, 1), 0, "la clave 1 votó en todas las ventanas");
    assert_eq!(deuda(&est, 2), 0, "la clave 2 votó en todas las ventanas");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// V3 — Q2 · el acta de una ventana caducada se rechaza; la de m+330 se acepta
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn v3_acta_caducada_rechazada() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    let m = 0u64;
    poner_base(&mut est, m, &tabla);
    let h_t = hash_payload(&tabla);
    let candidato = [0x33u8; 32];

    // Acta de la ventana m+330 (dentro de la caducidad): aceptada.
    let acta_330 = op_compacto(
        &est,
        &secretas,
        m + CADUCIDAD,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1],
        None,
        true,
    )?;
    let slot_330 = i64::try_from(cierre_ventana(m + CADUCIDAD))?;
    let (est, _, r) = aplicar_acta_presencia_con_undo(&est, &acta_330, slot_330);
    r?;

    // Acta de la ventana m+331 (caducada): tabla desconocida.
    let acta_331 = op_compacto(
        &est,
        &secretas,
        m + CADUCIDAD + 1,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1],
        None,
        true,
    )?;
    let slot_331 = i64::try_from(cierre_ventana(m + CADUCIDAD + 1))?;
    let (_, _, r) = aplicar_acta_presencia_con_undo(&est, &acta_331, slot_331);
    assert!(
        matches!(r, Err(ErrorTransicion::ErrActaTablaDesconocida)),
        "acta caducada: se esperaba ErrActaTablaDesconocida, llegó {r:?}"
    );
    Ok(())
}
