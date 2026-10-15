//! M9-b1 · gemelas por el flujo por peso de `ret1b_evidencia.rs` (lista J, 4 pruebas).
//!
//! La evidencia antigua `0x05` se sustituye por `0x0B` (`EvidenciaVotosPeso`); las afirmaciones
//! (confiscación, orden canónico, firma por `h_t`, `undo` exacto) son las de la original.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test de escenarios; falla con panic por diseño"
)]

use primitive_types::U256;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_undo;
use zx_consensus::transicion::{
    ErrorTransicion, Estado, Garantia, ParametrosEvidencia, ParametrosTransicion, deshacer,
};
use zx_core::{Amount, ClavePublica, OperacionAlmacenamiento, VotoPesoEvidencia};
use zx_votos::DOMINIO_VOTO;

type Error = Box<dyn std::error::Error>;

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

fn estado(garantia: i64) -> Result<(Estado, zx_votos::ClaveSecreta), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let secreta = bls(1)?;
    let pk = secreta.clave_publica();
    let e = ed(1);
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: pk.bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let (id, reg) = registro(&p, e, 0);
    est.sectores.insert(id, reg);
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(garantia)?;
    est.garantias.insert(e, g);
    Ok((est, secreta))
}

fn param_evidencia() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 0,
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
        q: Amount::CERO,
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

fn firmar_voto_peso(
    secreta: &zx_votos::ClaveSecreta,
    n: u64,
    cand: [u8; 32],
    h_t: [u8; 32],
) -> zx_votos::Firma {
    zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &cand, &h_t, &cand),
    )
    .expect("firma")
}

fn evidencia_peso(
    secreta: &zx_votos::ClaveSecreta,
    n: u64,
    h1: [u8; 32],
    h_t1: [u8; 32],
    h2: [u8; 32],
    h_t2: [u8; 32],
) -> OperacionAlmacenamiento {
    let f1 = firmar_voto_peso(secreta, n, h1, h_t1);
    let f2 = firmar_voto_peso(secreta, n, h2, h_t2);
    OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: secreta.clave_publica().bytes(),
        voto1: VotoPesoEvidencia {
            n,
            candidato: h1,
            h_t_siguiente: h_t1,
            raiz_estado: h1,
            firma: f1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n,
            candidato: h2,
            h_t_siguiente: h_t2,
            raiz_estado: h2,
            firma: f2.bytes(),
        },
    }
}

/// Q3 · la prueba con **dos tablas** se aplica y confisca; el undo revierte bit a bit.
#[test]
fn q3_evidencia_dos_tablas_se_aplica_peso() -> Result<(), Error> {
    let (est, secreta) = estado(50)?;
    let n = 3;
    let op = evidencia_peso(&secreta, n, [0x01; 32], [0xAA; 32], [0x02; 32], [0xBB; 32]);
    let (nuevo, undo, resultado) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    resultado.expect("evidencia con dos tablas admitida");
    assert!(nuevo.quemado > est.quemado, "confisca");
    assert_eq!(deshacer(&nuevo, &undo), est, "undo bit a bit");
    Ok(())
}

/// Q3 · una firma que no corresponde a **su** `h_t` se rechaza sin mutar.
#[test]
fn q3_firma_que_no_corresponde_a_su_h_t_se_rechaza_peso() -> Result<(), Error> {
    let (est, secreta) = estado(50)?;
    let n = 3;
    let h1 = [0x01; 32];
    let h2 = [0x02; 32];
    let h_t1 = [0xAA; 32];
    let h_t2 = [0xBB; 32];
    // firma1 se calcula sobre `h_t2` (no sobre su `h_t1`).
    let firma1 = firmar_voto_peso(&secreta, n, h1, h_t2);
    let firma2 = firmar_voto_peso(&secreta, n, h2, h_t2);
    let op = OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: secreta.clave_publica().bytes(),
        voto1: VotoPesoEvidencia {
            n,
            candidato: h1,
            h_t_siguiente: h_t1,
            raiz_estado: h1,
            firma: firma1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n,
            candidato: h2,
            h_t_siguiente: h_t2,
            raiz_estado: h2,
            firma: firma2.bytes(),
        },
    };
    let (nuevo, _, resultado) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    assert_eq!(resultado, Err(ErrorTransicion::ErrEvidenciaVoto));
    assert_eq!(nuevo.quemado, est.quemado, "sin mutar");
    Ok(())
}

/// Q3 · pares iguales o en orden no canónico se rechazan sin verificar firmas.
#[test]
fn q3_pares_iguales_o_orden_no_canonico_se_rechazan_peso() -> Result<(), Error> {
    let (est, secreta) = estado(50)?;
    let n = 3;
    let cand = [0x01; 32];
    let h_t = [0xAA; 32];

    // Par repetido `(h1,h_t1) == (h2,h_t2)` con firmas válidas.
    let repetido = evidencia_peso(&secreta, n, cand, h_t, cand, h_t);
    let (_, _, r) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &repetido,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    // Orden no canónico: `(h1,h_t1) > (h2,h_t2)`.
    let desordenado = evidencia_peso(&secreta, n, [0x02; 32], h_t, [0x01; 32], h_t);
    let (_, _, r2) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &desordenado,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    assert_eq!(r2, Err(ErrorTransicion::ErrEvidenciaVoto));
    Ok(())
}

/// Q8 · el caso con el mismo `h_T` (que ya funcionaba) sigue aplicándose.
#[test]
fn q8_mismo_h_t_sigue_aplicando_peso() -> Result<(), Error> {
    let (est, secreta) = estado(50)?;
    let n = 3;
    let op = evidencia_peso(&secreta, n, [0x01; 32], [0xCC; 32], [0x02; 32], [0xCC; 32]);
    let (nuevo, undo, resultado) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    resultado.expect("mismo h_T admitido");
    assert!(nuevo.quemado > est.quemado);
    assert_eq!(deshacer(&nuevo, &undo), est);
    Ok(())
}
