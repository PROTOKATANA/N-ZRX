//! TB-1c-2/3 · pruebas de X3′ (N1′: el votante sin base firma con la última huella de la cola del
//! candidato y la declara; con la cola vacía abre la ventana con la tabla vacía y no vota), de X4
//! (N6: el motor abandona una base provisional que la cadena no confirmó) y la regresión del humo
//! (un sector que madura en el hueco entre el candidato y el bloque que aplica el primer `0x09`).
//!
//! Módulo hijo de `votos`, así que usa el mismo camino que el motor real (`MotorVotos::avanzar`) y
//! puede observar sus campos privados. Las firmas BLS son reales.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use super::*;
use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::tipos::K_TABLAS_VOTO;
use zx_consensus::transicion::votos::{derivar_tabla_sin_base_con_undo, tabla_derivada};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo,
};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, ClaveTablaVoto, Digest, Tx};

/// Slot de reloj de las pruebas (solo afecta al candado; las tablas usan `n·t_inst`).
const SLOT: i64 = 100;

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

fn bh(byte: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([byte; 32]))
}

fn registro(p: &ParametrosSector, clave: ClaveEd, indice: u16) -> (SectorId, RegistroSector) {
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

/// Estado con una clave registrada y `n_sectores` activos (toda la tabla para esa clave).
fn estado_con(n_sectores: usize) -> (Estado, ClaveSecreta) {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let sk = bls(1);
    let pk = sk.clave_publica();
    let e = ed(1);
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: pk.bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    for i in 0..n_sectores {
        let (id, reg) = registro(&p, e, u16::try_from(i).expect("indice"));
        est.sectores.insert(id, reg);
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);
    (est, sk)
}

fn motor_con(sk: ClaveSecreta) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: true,
    })
}

/// Tabla canónica de `est` en la apertura de `n` y su huella, con el contenido guardado en `est`.
fn tabla_y_huella(est: &mut Estado, n: u64) -> [u8; 32] {
    let slot = i64::try_from(n.saturating_mul(2)).unwrap_or(i64::MAX);
    let contenido = zx_consensus::transicion::votos::tabla_canonica(est, slot);
    let tabla = tabla_de_contenido(n, &contenido);
    let h = hash_tabla(&tabla);
    est.tablas_voto_contenido.insert(h, contenido);
    h
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// X3 · el votante sin base
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb1c2_votante_sin_base_firma_con_la_ultima_de_la_cola_del_candidato() {
    // La cola se llena en el slot 90 (k=45), cuando el sector extra aún está precomprometido
    // (madura en el 95); la ventana se abre en el slot 100, cuando ya pesa. Así la última tabla de
    // la cola (peso 2) difiere de `construir_tabla` en la apertura (peso 3): es lo que hace fallar
    // el control rojo R8.
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let sk = bls(1);
    let e = ed(1);
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: sk.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    for s in 0..2u16 {
        let (id, reg) = registro(&p, e, s);
        est.sectores.insert(id, reg);
    }
    let id_extra = SectorId {
        clave: e,
        sector_index: 2,
        version: 0,
    };
    est.sectores.insert(
        id_extra,
        RegistroSector {
            id: id_extra,
            r2: [0u64; 4],
            history_size: 1,
            etapa: Etapa::Precomprometido,
            alta_slot: 95 - p.m_sec,
            renovacion_slot: 95,
            retiro_slot: -1,
            fianza: p.q_sec,
            aud_apertura: -1,
            aud_contestada: -1,
        },
    );
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);

    let (con_cola, _u) = derivar_tabla_sin_base_con_undo(&est, 90);
    let (k_ultima, h_ultima) = *con_cola
        .cola_tablas_voto
        .last()
        .expect("el gancho llenó la cola");
    assert_eq!(k_ultima, 45, "la cola se llenó en la ventana 45");
    assert_eq!(
        pesos_de(&tabla_derivada(&con_cola, 45)),
        vec![2],
        "en el slot 90 el sector extra no pesa"
    );
    assert_eq!(
        pesos_de(&tabla_derivada(&con_cola, 50)),
        vec![3],
        "en el slot 100 (apertura) el sector extra ya pesa"
    );

    let mut m = motor_con(sk);
    let paso = m.avanzar(50, bh(0x77), &con_cola, SLOT).expect("abrir");
    assert_eq!(paso.votos.len(), 1, "el votante sin base vota");
    let tabla = m.tabla_actual().expect("instancia abierta");
    assert_eq!(
        hash_tabla(tabla),
        h_ultima,
        "firma con el contenido de la última huella de la cola, no con `construir_tabla`"
    );
    let declarada = paso
        .eventos
        .iter()
        .find_map(|e| match e {
            EventoMotor::VentanaAbierta { h_t_siguiente, .. } => Some(h_t_siguiente.clone()),
            _ => None,
        })
        .expect("evento ventana_abierta");
    assert_eq!(declarada, hex(&h_ultima), "y declara esa misma huella");
}

#[test]
fn tb1c2_votante_con_cola_vacia_no_vota() {
    let (est, sk) = estado_con(100);
    let mut m = motor_con(sk);
    // TB-1c-3 · X3′ · sin cola, la ventana se abre con la **tabla vacía** (como cuando ninguna
    // identidad tiene peso): la instancia se abre, nadie vota (cada clave sale por `fuera_de_tabla`)
    // y no hay ningún motivo nuevo.
    let p1 = m.avanzar(50, bh(0x77), &est, SLOT).expect("abrir");
    assert!(p1.votos.is_empty(), "sin cola no vota");
    let tabla = m
        .tabla_actual()
        .expect("la instancia se abre con la tabla vacía");
    assert!(tabla.claves.is_empty(), "la tabla vigente es la vacía");
    assert!(
        p1.eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::VentanaAbierta { .. })),
        "ventana_abierta con la tabla vacía"
    );
    let motivos: Vec<&'static str> = p1
        .eventos
        .iter()
        .filter_map(|e| match e {
            EventoMotor::VotoPesoPropio {
                motivo, emitido, ..
            } if !*emitido => Some(*motivo),
            _ => None,
        })
        .collect();
    assert_eq!(
        motivos,
        vec!["fuera_de_tabla"],
        "el motivo es el de una clave sin plaza en la tabla"
    );
    assert!(
        !p1.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VotoPesoPropio { motivo, .. } if *motivo == "sin_tabla_derivada"
        )),
        "X3′ retira el motivo literal `sin_tabla_derivada`"
    );
    // Al cruzar a la ventana siguiente, la 50 se cierra sin certificado.
    let p2 = m.avanzar(51, bh(0x78), &est, SLOT).expect("abrir 51");
    let cerrada = p2.eventos.iter().find_map(|e| match e {
        EventoMotor::VentanaCerrada { n, certificado, .. } => Some((*n, *certificado)),
        _ => None,
    });
    assert_eq!(
        cerrada,
        Some((50, false)),
        "ventana_cerrada sin certificado con la tabla vacía"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// X4 · la base provisional
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn evento_abandono(paso: &PasoVotos) -> Option<(u64, u64, String)> {
    paso.eventos.iter().find_map(|e| match e {
        EventoMotor::BaseProvisionalAbandonada { n, m_base, huella } => {
            Some((*n, *m_base, huella.clone()))
        }
        _ => None,
    })
}

#[test]
fn tb1c2_motor_abandona_base_provisional_pasado_k() {
    let (est, sk) = estado_con(100);
    let mut m = motor_con(sk);
    let m_base = 5u64;
    let h = [0xAB; 32];
    m.base = Some((m_base, h));
    m.base_provisional = true;
    let n = m_base + u64::try_from(K_TABLAS_VOTO).unwrap_or(u64::MAX) + 1;
    let paso = m.avanzar(n, bh(0x60), &est, SLOT).expect("abrir");
    assert!(m.base.is_none(), "la base provisional se abandona");
    assert_eq!(
        evento_abandono(&paso),
        Some((n, m_base, hex(&h))),
        "evento base_provisional_abandonada"
    );
}

#[test]
fn tb1c2_motor_no_abandona_antes_de_k() {
    let (mut est, sk) = estado_con(100);
    let mut m = motor_con(sk);
    let m_base = 5u64;
    let h = tabla_y_huella(&mut est, m_base);
    m.base = Some((m_base, h));
    m.base_provisional = true;
    let n = m_base + u64::try_from(K_TABLAS_VOTO).unwrap_or(u64::MAX); // justo en el límite: no se pasa de K
    let paso = m.avanzar(n, bh(0x61), &est, SLOT).expect("abrir");
    assert_eq!(m.base, Some((m_base, h)), "no abandona antes de pasarse");
    assert!(evento_abandono(&paso).is_none());
}

#[test]
fn tb1c2_motor_no_abandona_base_confirmada() {
    let (mut est, sk) = estado_con(100);
    let mut m = motor_con(sk);
    let m_base = 5u64;
    let h = tabla_y_huella(&mut est, m_base);
    est.finalidad_votos_n = m_base;
    est.finalidad_votos = Some(bh(0x40));
    est.finalidad_votos_h_t = Some(h);
    m.base = Some((m_base, h));
    m.base_provisional = true;
    // El motor ya observó una base (evita el guard de bootstrap); la base sigue siendo provisional.
    m.base_de_estado = true;
    let paso = m.avanzar(m_base + 2, bh(0x62), &est, SLOT).expect("abrir");
    assert_eq!(m.base, Some((m_base, h)), "la base confirmada se conserva");
    assert!(!m.base_provisional, "deja de ser provisional");
    assert!(evento_abandono(&paso).is_none());
}

#[test]
fn tb1c2_motor_abandona_en_el_acto_si_la_cadena_confirma_otra() {
    let (mut est, sk) = estado_con(100);
    let mut m = motor_con(sk);
    let m_base = 5u64;
    let h_vieja = [0xAB; 32];
    let h_nueva = tabla_y_huella(&mut est, m_base + 3);
    assert_ne!(h_nueva, h_vieja);
    est.finalidad_votos_n = m_base + 3;
    est.finalidad_votos = Some(bh(0x50));
    est.finalidad_votos_h_t = Some(h_nueva);
    m.base = Some((m_base, h_vieja));
    m.base_provisional = true;
    // El motor ya observó una base (evita el guard de bootstrap); la base sigue siendo provisional.
    m.base_de_estado = true;
    let paso = m.avanzar(m_base + 4, bh(0x63), &est, SLOT).expect("abrir");
    assert!(
        evento_abandono(&paso).is_some(),
        "abandona en el acto otra huella"
    );
    assert_eq!(
        m.base,
        Some((m_base + 3, h_nueva)),
        "toma la finalidad del estado del candidato"
    );
    assert!(!m.base_provisional);
}

#[test]
fn tb1c2_motor_no_firma_dos_veces_la_misma_ventana_tras_abandonar() {
    let (est, sk) = estado_con(100);
    let (con_cola, _u) = derivar_tabla_sin_base_con_undo(&est, SLOT as u64);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut m = motor_con(sk);
    m.vincular_diario(DiarioVotos::nueva(dir.path().join("tb1c2.registro"), 0).expect("diario"));
    let n = 50u64;
    let p1 = m.avanzar(n, bh(0x70), &con_cola, SLOT).expect("abrir");
    assert_eq!(p1.votos.len(), 1, "la primera vez sí firma");
    // Tras abandonar la base se fuerza la reapertura de la MISMA ventana con otro candidato.
    m.base = None;
    m.base_provisional = false;
    m.instancia = None;
    let p2 = m.avanzar(n, bh(0x71), &con_cola, SLOT).expect("reapertura");
    assert!(
        p2.votos.is_empty(),
        "no vuelve a firmar una ventana ya firmada"
    );
    let motivo = p2.eventos.iter().find_map(|e| match e {
        EventoMotor::VotoPesoPropio {
            motivo, emitido, ..
        } if !*emitido => Some(*motivo),
        _ => None,
    });
    assert_eq!(
        motivo,
        Some("conflicto_diario"),
        "lo impide la reserva durable del diario (votos.rs, `diario.resolver`)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Regresión del humo (REVISION-DGT5-2): un sector madura en el hueco entre el candidato y el
// bloque que aplica el primer certificado; con T5′ la cola que la cadena guardó lo evita.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Parámetros de transición de la regresión (los mismos que `pd1e_peso`).
fn params_regresion() -> ParametrosTransicion {
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

fn hash_slot(slot: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&slot.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn bloque_post(slot: u64, productor: ClaveEd, txs: Vec<(Tx, Vec<Vec<u8>>)>) -> BloqueTransicion {
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash_slot(slot),
            padre: hash_slot(slot.saturating_sub(1)),
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        txs,
    )
}

fn aplicar_bloque(estado: &Estado, bloque: &BloqueTransicion) -> Estado {
    aplicar_con_undo(
        estado,
        bloque,
        &params_regresion(),
        CBID_REGRESION,
        &ParametrosEvidencia::inactiva(),
    )
    .expect("la transición real aplica el bloque")
    .0
}

fn par_ed(seed: u8) -> (SigningKey, ClaveEd) {
    let sk = SigningKey::from([seed; 32]);
    let vk = VerificationKey::from(&sk);
    (sk, ClaveEd::desde_bytes(vk.into()))
}

fn pesos_de(contenido: &[ClaveTablaVoto]) -> Vec<u64> {
    let mut pesos: Vec<u64> = contenido.iter().map(|c| c.peso).collect();
    pesos.sort_unstable();
    pesos
}

/// Estado de la regresión: tres identidades con pesos 2, 2 y 1; la segunda con un sector extra
/// `Precomprometido` de `alta_slot = 368` (madura en el 380 con `m_sec = 12`).
fn estado_regresion(claves: &[ClaveSecreta]) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let pesos = [2u16, 2, 1];
    for (i, sk) in claves.iter().enumerate() {
        let e = ed(u8::try_from(i).unwrap_or(0) + 1);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: sk.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for s in 0..pesos[i] {
            let (id, reg) = registro(&p, e, s);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(1_401_600_000).expect("garantía");
        est.garantias.insert(e, g);
    }
    // Sector extra de la segunda identidad (índice 1): precomprometido en el 368, madura en el 380.
    let e1 = ed(2);
    let id = SectorId {
        clave: e1,
        sector_index: 2,
        version: 0,
    };
    est.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0u64; 4],
            history_size: 1,
            etapa: Etapa::Precomprometido,
            alta_slot: 368,
            renovacion_slot: 368 + p.m_sec,
            retiro_slot: -1,
            fianza: p.q_sec,
            aud_apertura: -1,
            aud_contestada: -1,
        },
    );
    est
}

const CBID_REGRESION: u32 = 0;

/// La regresión del humo: el primer certificado de la ventana 189 se firma sobre la tabla que el
/// candidato (bloque del 374) guardó en su cola —pesos 2-2-1— y la cadena lo acepta aunque el
/// estado en que se aplica (bloque del 381) derive 2-3-1 porque el sector maduró en el hueco.
#[test]
fn tb1c2_sector_que_madura_en_el_hueco_no_impide_el_primer_certificado() {
    let est0 = estado_regresion(&(1..=3u8).map(bls).collect::<Vec<_>>());

    // Bloques reales en los slots del humo: 372, 373, 374, 376, 377, 378, 379 y 380.
    let mut estados: std::collections::BTreeMap<u64, Estado> = std::collections::BTreeMap::new();
    let mut est = est0;
    for slot in [372u64, 373, 374, 376, 377, 378, 379, 380] {
        est = aplicar_bloque(&est, &bloque_post(slot, ed(1), Vec::new()));
        estados.insert(slot, est.clone());
    }
    let estado_candidato = estados
        .get(&374)
        .expect("estado del candidato (374)")
        .clone();
    let estado_aplicador = estados
        .get(&380)
        .expect("estado en que se aplica (380)")
        .clone();

    // El candidato deriva 2-2-1 en la apertura de la 189 (378); el aplicador, 2-3-1: el sector
    // extra maduró en el 380 y `estado_efectivo` lo da por activo en cualquier slot.
    let tabla_candidato = tabla_derivada(&estado_candidato, 189);
    let tabla_aplicador = tabla_derivada(&estado_aplicador, 189);
    assert_eq!(pesos_de(&tabla_candidato), vec![1, 2, 2], "candidato 2-2-1");
    assert_eq!(pesos_de(&tabla_aplicador), vec![1, 2, 3], "aplicador 2-3-1");

    // Tres votantes reales (uno por identidad) abren la 189 sobre el estado del candidato y cierran
    // con quórum al abrir la 190.
    let mut ms: Vec<MotorVotos> = (1..=3u8).map(|i| motor_con(bls(i))).collect();
    let mut cert189 = None;
    for n in [189u64, 190] {
        let mut sobres: Vec<Vec<u8>> = Vec::new();
        for m in &mut ms {
            let paso = m
                .avanzar(n, hash_slot(n), &estado_candidato, SLOT)
                .expect("abrir");
            sobres.extend(paso.votos);
            if let Some(c) = paso.certificado_peso
                && c.n == 189
            {
                cert189 = Some(c);
            }
        }
        for m in &mut ms {
            for s in &sobres {
                let _ = m.recibir_voto(s);
            }
        }
    }
    let cert = cert189.expect("los tres votantes cierran la 189 con quórum");

    // El bloque del 381 incluye el `0x09` y la transición real lo aplica.
    let (firmante_sk, firmante_pk) = par_ed(0x5A);
    let (tx, firmas) = tx_certificado_peso(&cert, firmante_pk, &firmante_sk, CBID_REGRESION);
    let bloque381 = bloque_post(381, ed(1), vec![(tx, firmas)]);
    let (aplicado, _undo) = aplicar_con_undo(
        &estado_aplicador,
        &bloque381,
        &params_regresion(),
        CBID_REGRESION,
        &ParametrosEvidencia::inactiva(),
    )
    .expect("el bloque del 381 con el 0x09 se aplica");

    // Afirma: aplicado, base en la ventana 189 y tabla vigente de pesos 2-2-1 (la del candidato),
    // no la 2-3-1 que el estado aplicador calcula en el mismo slot.
    assert_eq!(
        aplicado.finalidad_votos_n, 189,
        "el primer certificado fija la base en la ventana 189"
    );
    let h_vig = aplicado.finalidad_votos_h_t.expect("huella vigente");
    let contenido = aplicado
        .tablas_voto_contenido
        .get(&h_vig)
        .expect("contenido de la huella vigente");
    assert_eq!(pesos_de(contenido), vec![1, 2, 2], "tabla vigente 2-2-1");
    let canonica_aplicador = tabla_derivada(&aplicado, 189);
    assert_eq!(
        pesos_de(&canonica_aplicador),
        vec![1, 2, 3],
        "el estado aplicador ya calcula 2-3-1"
    );
}

/// Peso de la clave de la identidad `indice` en un contenido de tabla (0 si no está).
fn peso_de_identidad(contenido: &[ClaveTablaVoto], indice: u8) -> u64 {
    let clave = bls(indice).clave_publica().bytes();
    contenido
        .iter()
        .find(|c| c.clave_bls == clave)
        .map(|c| c.peso)
        .unwrap_or(0)
}

/// Inserta en `est` un sector `Precomprometido` de `clave` que madura en `slot`
/// (`alta_slot = slot − m_sec`).
fn programar_alta(est: &mut Estado, clave: ClaveEd, indice: u16, slot: u64) {
    let p = est.parametros_sector;
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    let slot_i = i64::try_from(slot).unwrap_or(i64::MAX);
    est.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0u64; 4],
            history_size: 1,
            etapa: Etapa::Precomprometido,
            alta_slot: slot_i - p.m_sec,
            renovacion_slot: slot_i,
            retiro_slot: -1,
            fianza: p.q_sec,
            aud_apertura: -1,
            aud_contestada: -1,
        },
    );
}

/// Renueva (extiende `renovacion_slot`) el sector `indice` de `clave` en `slot`.
fn programar_renovacion(est: &mut Estado, clave: ClaveEd, indice: u16, slot: u64) {
    let p = est.parametros_sector;
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    if let Some(r) = est.sectores.get_mut(&id) {
        r.renovacion_slot = i64::try_from(slot)
            .unwrap_or(i64::MAX)
            .saturating_add(p.m_sec);
    }
}

/// 60 ventanas seguidas con un alta que madura —y una renovación— cada 5 ventanas, siempre en el
/// hueco entre el candidato (`2n−4`) y la apertura (`2n`): la finalidad arranca en la primera
/// ventana con quórum y sigue, y la tabla vigente llega a reflejar los cambios.
#[test]
fn tb1c2_finalidad_arranca_y_sigue_con_pesos_que_cambian() {
    const N0: u64 = 189;
    const N1: u64 = 248;
    const LAG: u64 = 4;

    let mut est = estado_regresion(&(1..=3u8).map(bls).collect::<Vec<_>>());
    let mut motores: Vec<MotorVotos> = (1..=3u8).map(|i| motor_con(bls(i))).collect();

    // Altas/renovaciones programadas: cada 5 ventanas, madura un alta de la identidad 1 en `2n−1`.
    let mut altas: std::collections::BTreeMap<u64, u16> = std::collections::BTreeMap::new();
    let mut renovaciones: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    // La identidad 1 (ed(1)) usa los índices 0 y 1; el contador arranca en 2.
    for (indice_alta, k) in (2_u16..).zip(1..=12u64) {
        let nc = N0 + 5 * k - 1;
        if nc > N1 {
            break;
        }
        let ms = 2 * nc - 1;
        altas.insert(ms, indice_alta);
        renovaciones.insert(ms);
    }

    let primer_slot = 2 * N0 - LAG;
    let ultimo_slot = 2 * N1 + 3;
    let mut estados: std::collections::BTreeMap<u64, Estado> = std::collections::BTreeMap::new();
    let mut certs: std::collections::BTreeMap<u64, CertificadoPeso> =
        std::collections::BTreeMap::new();
    let mut huellas_base: Vec<[u8; 32]> = Vec::new();
    let mut pesos_base: Vec<u64> = Vec::new();

    for slot in primer_slot..=ultimo_slot {
        if let Some(idx) = altas.get(&slot) {
            programar_alta(&mut est, ed(1), *idx, slot);
        }
        if renovaciones.contains(&slot) {
            programar_renovacion(&mut est, ed(2), 0, slot);
        }

        // Apertura `n = slot/2`: el motor real usa el estado del candidato (`slot − LAG`). Se abre
        // también la `N1+1` para que la última ventana (`N1`) cierre y emita su certificado.
        if slot % 2 == 0 && (N0..=N1 + 1).contains(&slot.div_euclid(2)) {
            let n = slot.div_euclid(2);
            let candidato_est = estados
                .get(&(slot - LAG))
                .cloned()
                .expect("estado del candidato disponible");
            let mut sobres: Vec<Vec<u8>> = Vec::new();
            for m in &mut motores {
                let paso = m
                    .avanzar(n, hash_slot(n), &candidato_est, SLOT)
                    .expect("abrir la ventana");
                sobres.extend(paso.votos);
                if let Some(c) = paso.certificado_peso {
                    certs.insert(c.n, c);
                }
            }
            for m in &mut motores {
                for s in &sobres {
                    let _ = m.recibir_voto(s);
                }
            }
        }

        // El bloque del slot incluye el certificado si es el slot de aplicación `2m+3`.
        let mut txs: Vec<(Tx, Vec<Vec<u8>>)> = Vec::new();
        if slot >= 3 && (slot - 3) % 2 == 0 {
            let m = (slot - 3).div_euclid(2);
            if slot == 2 * m + 3
                && let Some(c) = certs.get(&m)
            {
                let (fsk, fpk) = par_ed(0x5A);
                let (tx, firmas) = tx_certificado_peso(c, fpk, &fsk, CBID_REGRESION);
                txs.push((tx, firmas));
            }
        }
        est = aplicar_bloque(&est, &bloque_post(slot, ed(1), txs));
        estados.insert(slot, est.clone());

        // Tras aplicar la ventana `n` (`2n+3`), recoge la tabla vigente.
        if slot >= 3 && (slot - 3) % 2 == 0 {
            let n = (slot - 3).div_euclid(2);
            if slot == 2 * n + 3 && (N0..=N1).contains(&n) && est.finalidad_votos_n == n {
                let h = est.finalidad_votos_h_t.expect("huella vigente");
                huellas_base.push(h);
                let contenido = est
                    .tablas_voto_contenido
                    .get(&h)
                    .expect("contenido vigente");
                pesos_base.push(peso_de_identidad(contenido, 1));
            }
        }
    }

    // Un certificado aplicado por cada ventana desde la primera con quórum.
    assert_eq!(
        est.finalidad_votos_n, N1,
        "la finalidad avanza una ventana por certificado hasta la última"
    );
    assert_eq!(
        huellas_base.len() as u64,
        N1 - N0 + 1,
        "hay una tabla vigente registrada por cada ventana"
    );
    // La tabla vigente llega a reflejar los cambios (el alta que madura en el hueco sube el peso).
    assert!(
        pesos_base.iter().any(|p| *p > 2),
        "alguna tabla vigente refleja el alta que maduró en el hueco: {pesos_base:?}"
    );
    assert!(
        huellas_base.windows(2).any(|w| w[0] != w[1]),
        "la tabla vigente cambia a lo largo de las 60 ventanas"
    );
}
