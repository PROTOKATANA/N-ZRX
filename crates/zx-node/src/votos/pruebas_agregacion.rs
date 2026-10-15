//! A5-c-1b · la agregación de votos en el motor (pieza A5, paso (c)).
//!
//! Pruebas de que el motor lleva **una sola contabilidad por raíces** con `VentanaPorRaices`,
//! emite además el voto de red compacto por subred, recibe votos de subred y agregados y publica su
//! agregado propio una vez por ventana. Con solo votos sueltos, el certificado y el acta salen como
//! en la base.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseno"
)]

use std::collections::HashMap;

use primitive_types::U256;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{
    aplicar_certificado_peso_con_undo, derivar_tabla_sin_base_con_undo,
};
use zx_consensus::transicion::{Estado, Fase, Garantia, ParametrosEvidencia, ParametrosTransicion};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, Digest, OperacionAlmacenamiento};
use zx_votos::agregacion::{
    Agregado, DOMINIO_SORTEO, ErrorAgregacion, MensajeVoto, VotoRed, subred,
};
use zx_votos::{
    ClaveSecreta, DOMINIO_VOTO, Firma, Hash, Tabla, agregar_firmas, construir_certificado, firmar,
    hash_tabla, mensaje_voto_peso, serial_certificado_peso, verificar_firma_peso,
};

use super::{
    ConfigMotorVotos, MotorVotos, RAIZ_ESTADO_CERO, RecepcionAgregado, RecepcionVoto,
    RecepcionVotoSubred, VistaPermisiva, VotoPeso, claves_publicas_de_tabla,
    deserializar_voto_peso, serializar_voto_peso,
};

const DEN: i64 = 1_401_600_000;
const SLOT: i64 = 100;

type Error = Box<dyn std::error::Error>;

// ── utilidades de estado ─────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
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

fn param_evidencia() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 2,
        plazo_slots: 300,
        m_margen_slots: 0,
        cbid: 0,
        evp: true,
    }
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

/// Estado PoST con `(clave, nº de sectores, activo de la garantía)` por clave.
fn estado_sectores(claves: &[(u8, u16, i64)]) -> Result<(Estado, Vec<u8>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut indices = Vec::new();
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
        indices.push(*i);
    }
    let (con_cola, _u) = derivar_tabla_sin_base_con_undo(&est, u64::try_from(SLOT)?);
    let _ = params();
    let _ = param_evidencia();
    Ok((con_cola, indices))
}

fn motor_de(indices: &[u8], emitir: bool, subredes: u16) -> Result<MotorVotos, Error> {
    let claves = indices
        .iter()
        .map(|i| bls(*i))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: crate::perfil::parametros_votos_dev(),
            claves,
            emitir_votos: emitir,
        },
        subredes,
    ))
}

fn inst_h_t(m: &MotorVotos) -> Hash {
    m.instancia.as_ref().expect("instancia").h_t_siguiente
}

fn inst_cand(m: &MotorVotos) -> Hash {
    m.instancia.as_ref().expect("instancia").candidato
}

// ── votos ────────────────────────────────────────────────────────────────────────────────────

fn voto_con(sk: &ClaveSecreta, n: u64, c: Hash, h_t: Hash, raiz: Hash) -> Result<VotoPeso, Error> {
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje_voto_peso(n, &c, &h_t, &raiz))?;
    Ok(VotoPeso {
        n,
        candidato: c,
        h_t_siguiente: h_t,
        raiz_estado: raiz,
        clave: sk.clave_publica().bytes(),
        firma,
    })
}

fn voto_red_con(
    sk: &ClaveSecreta,
    n: u64,
    c: Hash,
    h_t: Hash,
    raiz: Hash,
) -> Result<VotoRed, Error> {
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje_voto_peso(n, &c, &h_t, &raiz))?;
    Ok(VotoRed {
        n,
        candidato: c,
        h_t_siguiente: h_t,
        raiz_estado: raiz,
        clave: sk.clave_publica(),
        firma,
    })
}

// ── agregados ────────────────────────────────────────────────────────────────────────────────

/// Voto suelto de la clave que ocupa el índice global `global` de la tabla.
fn voto_en_global(
    tabla: &Tabla,
    secretas: &HashMap<Vec<u8>, ClaveSecreta>,
    global: usize,
    n: u64,
    c: Hash,
    h_t: Hash,
    raiz: Hash,
) -> Result<VotoPeso, Error> {
    let pk = tabla
        .claves
        .get(global)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
        .clave
        .clone();
    let sk = secretas
        .get(&pk)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    voto_con(sk, n, c, h_t, raiz)
}

/// Reparto local: por subred, los índices globales en orden ascendente de clave (como `Reparto`).
fn reparto_de(tabla: &Tabla, s: u16) -> Result<Vec<Vec<usize>>, ErrorAgregacion> {
    let mut subredes: Vec<Vec<usize>> = vec![Vec::new(); usize::from(s)];
    for (i, clave) in tabla.claves.iter().enumerate() {
        let sub = subred(clave.clave.as_slice(), s)?;
        if let Some(lista) = subredes.get_mut(usize::from(sub)) {
            lista.push(i);
        }
    }
    for lista in &mut subredes {
        lista.sort_by(|a, b| {
            let ca = tabla.claves.get(*a).map(|c| c.clave.as_slice());
            let cb = tabla.claves.get(*b).map(|c| c.clave.as_slice());
            ca.cmp(&cb).then_with(|| a.cmp(b))
        });
    }
    Ok(subredes)
}

fn secretas_por_pk(indices: &[u8]) -> Result<HashMap<Vec<u8>, ClaveSecreta>, Error> {
    let mut mapa = HashMap::new();
    for i in indices {
        let sk = bls(*i)?;
        mapa.insert(sk.clave_publica().bytes().to_vec(), sk);
    }
    Ok(mapa)
}

/// Agregado válido de la subred `sub` que cubre los índices globales `cubiertos`.
#[allow(clippy::too_many_arguments, reason = "montaje de una prueba")]
fn agregado_con(
    tabla: &Tabla,
    s: u16,
    secretas: &HashMap<Vec<u8>, ClaveSecreta>,
    sub: u16,
    cubiertos: &[usize],
    indice_agregadora: usize,
    msg: MensajeVoto,
) -> Result<Agregado, Error> {
    let reparto = reparto_de(tabla, s)?;
    let indices = reparto
        .get(usize::from(sub))
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let n_s = indices.len();
    let mut mapa_local = vec![0u8; n_s.div_ceil(8)];
    let mut firmas: Vec<Firma> = Vec::new();
    for &global in cubiertos {
        let pos = indices
            .iter()
            .position(|g| *g == global)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        if let Some(byte) = mapa_local.get_mut(pos >> 3) {
            *byte |= 1 << (pos & 7);
        }
        let pk = tabla
            .claves
            .get(global)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
            .clave
            .clone();
        let sk = secretas
            .get(&pk)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        firmas.push(firmar(sk, DOMINIO_VOTO, &msg.mensaje())?);
    }
    let referencias: Vec<&Firma> = firmas.iter().collect();
    let firma_agregada = agregar_firmas(&referencias)?;
    let global_agregadora = *indices
        .get(indice_agregadora)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let pk_ag = tabla
        .claves
        .get(global_agregadora)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
        .clave
        .clone();
    let sk_ag = secretas
        .get(&pk_ag)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let firma_sorteo = firmar(sk_ag, DOMINIO_SORTEO, &msg.n.to_be_bytes())?;
    Ok(Agregado {
        n: msg.n,
        candidato: msg.candidato,
        h_t_siguiente: msg.h_t_siguiente,
        raiz_estado: msg.raiz_estado,
        firma_agregada,
        huella_tabla: hash_tabla(tabla),
        subred: sub,
        indice_agregadora: u16::try_from(indice_agregadora)?,
        mapa_local,
        firma_sorteo,
    })
}

fn msg_de(m: &MotorVotos, raiz: Hash) -> MensajeVoto {
    MensajeVoto {
        n: m.instancia.as_ref().expect("instancia").n,
        candidato: inst_cand(m),
        h_t_siguiente: inst_h_t(m),
        raiz_estado: raiz,
    }
}

// ── agm_01 · solo sueltos: certificado y acta byte a byte ───────────────────────────────────

#[test]
fn agm_01_solo_sueltos_certificado_y_acta_identicos() -> Result<(), Error> {
    // Certificado: W = 3, quorum = 2. Voto propio (raíz cero) + voto de la clave 2.
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], true, 1)?;
    let paso = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let propio = deserializar_voto_peso(&paso.votos[0])?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    let sk2 = bls(2)?;
    let v2 = voto_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v2)),
        RecepcionVoto::Aceptado { .. }
    ));
    let cierre = motor.cerrar()?;
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let cert = cierre.certificado_peso.clone().expect("certificado");
    let pos1 = tabla
        .claves
        .iter()
        .position(|k| k.clave == propio.clave)
        .expect("clave 1");
    let pos2 = tabla
        .claves
        .iter()
        .position(|k| k.clave == v2.clave)
        .expect("clave 2");
    let esperado = construir_certificado(
        1,
        c,
        h_t,
        RAIZ_ESTADO_CERO,
        &tabla,
        &[(pos1 + 1, propio.firma), (pos2 + 1, v2.firma)],
    )?;
    assert_eq!(
        cert, esperado,
        "certificado byte a byte con los mismos votos"
    );

    // Acta: W = 4 (quorum = 3) pero solo dos votos sueltos de la misma raíz.
    let (estado4, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let mut motor4 = motor_de(&[1], true, 1)?;
    let paso4 = motor4.avanzar(1, hash(0x11), &estado4, SLOT)?;
    let propio4 = deserializar_voto_peso(&paso4.votos[0])?;
    let h_t4 = inst_h_t(&motor4);
    let c4 = inst_cand(&motor4);
    let v4 = voto_con(&sk2, 1, c4, h_t4, RAIZ_ESTADO_CERO)?;
    assert!(matches!(
        motor4.recibir_voto(&serializar_voto_peso(&v4)),
        RecepcionVoto::Aceptado { .. }
    ));
    let cierre4 = motor4.cerrar()?;
    assert!(
        cierre4.certificado_peso.is_none(),
        "sin quorum no hay certificado"
    );
    let acta = cierre4.acta_peso.clone().expect("acta");
    let tabla4 = motor4.tabla_actual().expect("tabla").clone();
    let pos_a = tabla4
        .claves
        .iter()
        .position(|k| k.clave == propio4.clave)
        .expect("clave 1");
    let pos_b = tabla4
        .claves
        .iter()
        .position(|k| k.clave == v4.clave)
        .expect("clave 2");
    let acta_esperada = construir_certificado(
        1,
        c4,
        h_t4,
        RAIZ_ESTADO_CERO,
        &tabla4,
        &[(pos_a + 1, propio4.firma), (pos_b + 1, v4.firma)],
    )?;
    assert_eq!(acta, acta_esperada, "acta byte a byte con los mismos votos");
    Ok(())
}

// ── agm_02 · el voto propio sale también como voto de red ───────────────────────────────────

#[test]
fn agm_02_el_voto_propio_sale_tambien_como_voto_de_subred() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], true, 4)?;
    let paso = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    assert_eq!(paso.votos.len(), 1, "un sobre ZXV3");
    assert_eq!(paso.votos_red.len(), 1, "además, un voto de red");
    let (bytes, sub) = &paso.votos_red[0];
    assert_eq!(bytes.len(), 248, "el voto de red mide 248 B");
    let vr = VotoRed::deserializar(bytes)?;
    assert_eq!(*sub, subred(&vr.clave.bytes(), 4)?);
    let so = deserializar_voto_peso(&paso.votos[0])?;
    assert_eq!(vr.n, so.n);
    assert_eq!(vr.candidato, so.candidato);
    assert_eq!(vr.h_t_siguiente, so.h_t_siguiente);
    assert_eq!(vr.raiz_estado, so.raiz_estado);
    assert_eq!(vr.clave.bytes(), so.clave);
    assert_eq!(vr.firma.bytes(), so.firma.bytes());
    Ok(())
}

// ── agm_03/04/05 · recibir votos de subred ──────────────────────────────────────────────────

#[test]
fn agm_03_voto_de_subred_valido_cuenta_y_entra_en_el_detector() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 4)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    let sk2 = bls(2)?;
    let vr = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    let sub = subred(&vr.clave.bytes(), 4)?;
    let antes = motor.detector.votos_guardados();
    let r = motor.recibir_voto_subred(sub, &vr.serializar(), &VistaPermisiva);
    assert!(matches!(r, RecepcionVotoSubred::Aceptado { .. }));
    let inst = motor.instancia.as_ref().expect("instancia");
    assert!(inst.votos_peso.iter().any(|v| v.clave == vr.clave.bytes()));
    assert_eq!(
        motor.detector.votos_guardados(),
        antes + 1,
        "el voto de subred entra en el detector"
    );
    Ok(())
}

#[test]
fn agm_04_voto_por_la_subred_que_no_es_la_de_su_clave_se_rechaza() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 4)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    let sk2 = bls(2)?;
    let vr = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    let sub = subred(&vr.clave.bytes(), 4)?;
    let mala = (sub + 1) % 4;
    let r = motor.recibir_voto_subred(mala, &vr.serializar(), &VistaPermisiva);
    assert!(
        matches!(r, RecepcionVotoSubred::Penalizar { motivo: "subred" }),
        "subred equivocada: penalizable"
    );
    Ok(())
}

#[test]
fn agm_05_firma_falsa_penalizable_y_clave_fuera_de_tabla_ignorada() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 4)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    let sk2 = bls(2)?;
    let mut vr = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    vr.firma = firmar(&sk2, DOMINIO_VOTO, b"mensaje que no es el voto")?;
    let sub = subred(&vr.clave.bytes(), 4)?;
    assert!(matches!(
        motor.recibir_voto_subred(sub, &vr.serializar(), &VistaPermisiva),
        RecepcionVotoSubred::Penalizar {
            motivo: "firma_falsa"
        }
    ));
    let sk9 = bls(9)?;
    let vr9 = voto_red_con(&sk9, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    let sub9 = subred(&vr9.clave.bytes(), 4)?;
    assert!(matches!(
        motor.recibir_voto_subred(sub9, &vr9.serializar(), &VistaPermisiva),
        RecepcionVotoSubred::Ignorar {
            motivo: "no_registrada"
        }
    ));
    Ok(())
}

// ── agm_06 · un agregado válido suma al quórum ──────────────────────────────────────────────

#[test]
fn agm_06_un_agregado_valido_suma_al_quorum() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3])?;
    let msg = msg_de(&motor, RAIZ_ESTADO_CERO);
    let ag = agregado_con(&tabla, 1, &secretas, 0, &[0, 1, 2], 0, msg)?;
    let respuestas = motor.recibir_agregados(&[ag])?;
    assert!(matches!(respuestas[0], RecepcionAgregado::Reenviar));
    let cierre = motor.cerrar()?;
    let cert = cierre
        .certificado_peso
        .clone()
        .expect("el agregado suma al quorum");
    let pubs = claves_publicas_de_tabla(&tabla)?;
    verificar_firma_peso(&tabla, &pubs, &cert)?;
    // zx-consensus lo aplica con la transición real.
    let op = OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: serial_certificado_peso(&cert),
    };
    let (_nuevo, _undo, r) = aplicar_certificado_peso_con_undo(&estado, &op, SLOT);
    assert!(r.is_ok(), "zx-consensus aplica el certificado: {r:?}");
    Ok(())
}

// ── agm_07 · inválido, otra tabla y repetido ────────────────────────────────────────────────

#[test]
fn agm_07_agregado_invalido_penalizable_otra_tabla_y_repetido_ignorados() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3])?;
    let msg = msg_de(&motor, RAIZ_ESTADO_CERO);
    let ag = agregado_con(&tabla, 1, &secretas, 0, &[0, 1], 0, msg)?;

    let sk1 = bls(1)?;
    let mut invalido = ag.clone();
    invalido.firma_agregada = agregar_firmas(&[&firmar(&sk1, DOMINIO_VOTO, b"no vale")?])?;
    assert!(matches!(
        motor.recibir_agregados(&[invalido])?[0],
        RecepcionAgregado::Penalizar(_)
    ));

    let mut otra_tabla = ag.clone();
    otra_tabla.huella_tabla = [0xAB; 32];
    assert!(matches!(
        motor.recibir_agregados(&[otra_tabla])?[0],
        RecepcionAgregado::Ignorar
    ));

    assert!(matches!(
        motor.recibir_agregados(std::slice::from_ref(&ag))?[0],
        RecepcionAgregado::Reenviar
    ));
    assert!(matches!(
        motor.recibir_agregados(&[ag])?[0],
        RecepcionAgregado::Ignorar
    ));
    Ok(())
}

// ── agm_08 · publicar el agregado propio (sin cobertura: desde el último slot) ──────────────

#[test]
fn agm_08_agregado_propio_solo_desde_el_ultimo_slot_y_una_vez() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    // A5-c-2c: con S = 1 y ninguna otra clave votada, la subred propia no está cubierta, así que
    // rige la regla antigua de esperar al último slot. La publicación temprana la cubren agm_13/14.
    // n = 1: apertura 2, cierre 4, último slot 3.
    assert!(
        motor.publicar_agregado(0)?.is_empty(),
        "antes de la ventana"
    );
    assert!(
        motor.publicar_agregado(2)?.is_empty(),
        "slot+1 = 3 < 4 y subred sin cubrir: todavía no"
    );
    let primera = motor.publicar_agregado(3)?;
    assert_eq!(primera.len(), 1, "publica en el último slot");
    assert_eq!(primera[0].len(), Agregado::longitud(3));
    assert!(
        motor.publicar_agregado(3)?.is_empty(),
        "una sola vez por ventana"
    );
    assert!(motor.publicar_agregado(4)?.is_empty(), "tampoco después");
    Ok(())
}

// ── agm_09 · quien no vota no publica y sí certifica ────────────────────────────────────────

#[test]
fn agm_09_quien_no_emite_votos_no_publica_y_si_certifica() -> Result<(), Error> {
    // El motor no emite (observación) pero recibe de la red, incluso un voto de su propia clave.
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], false, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    let sk1 = bls(1)?;
    let vr1 = voto_red_con(&sk1, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    let sub1 = subred(&vr1.clave.bytes(), 1)?;
    assert!(matches!(
        motor.recibir_voto_subred(sub1, &vr1.serializar(), &VistaPermisiva),
        RecepcionVotoSubred::Aceptado { .. }
    ));
    assert!(
        motor.publicar_agregado(3)?.is_empty(),
        "quien no emite votos no publica aunque tenga un suelto"
    );
    for i in [2u8, 3] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        assert!(matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ));
    }
    let cierre = motor.cerrar()?;
    assert!(
        cierre.certificado_peso.is_some(),
        "recibe y certifica aunque no vote"
    );
    Ok(())
}

// ── agm_10 · dos raíces con agregados ───────────────────────────────────────────────────────

#[test]
fn agm_10_dos_raices_con_agregados_gana_la_del_quorum() -> Result<(), Error> {
    // W = 6, quorum = 4. Raíz A: agregado {0,1} + sueltos {2,3} = 4 (quorum).
    // Raíz B: agregado {4} + suelto {5} = 2. Si los sueltos de dos raíces cayeran en un mismo
    // grupo, ningún grupo llegaría al quórum y la prueba caería.
    let (estado, _) = estado_sectores(&[
        (1, 1, DEN),
        (2, 1, DEN),
        (3, 1, DEN),
        (4, 1, DEN),
        (5, 1, DEN),
        (6, 1, DEN),
    ])?;
    let mut motor = motor_de(&[], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3, 4, 5, 6])?;
    let ra = [0xAA; 32];
    let rb = [0xBB; 32];
    let ag_a = agregado_con(&tabla, 1, &secretas, 0, &[0, 1], 0, msg_de(&motor, ra))?;
    let ag_b = agregado_con(&tabla, 1, &secretas, 0, &[4], 4, msg_de(&motor, rb))?;
    let respuestas = motor.recibir_agregados(&[ag_a, ag_b])?;
    assert!(
        respuestas
            .iter()
            .all(|r| matches!(r, RecepcionAgregado::Reenviar))
    );
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    for (global, raiz) in [(2usize, ra), (3, ra), (5, rb)] {
        let v = voto_en_global(&tabla, &secretas, global, 1, c, h_t, raiz)?;
        assert!(matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ));
    }
    let cierre = motor.cerrar()?;
    let cert = cierre
        .certificado_peso
        .clone()
        .expect("quorum de la raíz A");
    assert_eq!(cert.raiz_estado, ra, "gana la raíz con quórum");
    Ok(())
}

// ── agm_11 · no se remonta un certificado con agregados ─────────────────────────────────────

#[test]
fn agm_11_no_se_remonta_un_certificado_con_agregados() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3])?;
    let ag = agregado_con(
        &tabla,
        1,
        &secretas,
        0,
        &[0, 1],
        0,
        msg_de(&motor, RAIZ_ESTADO_CERO),
    )?;
    motor.recibir_agregados(&[ag])?;
    let cierre = motor.cerrar()?;
    assert!(cierre.certificado_peso.is_some());
    assert!(
        motor.certificado_para_tabla(&tabla)?.is_none(),
        "con agregados no se remonta"
    );

    // Con solo sueltos, como hoy: sí se remonta.
    let mut motor2 = motor_de(&[1], true, 1)?;
    let _ = motor2.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor2);
    let c = inst_cand(&motor2);
    let sk2 = bls(2)?;
    let v2 = voto_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    assert!(matches!(
        motor2.recibir_voto(&serializar_voto_peso(&v2)),
        RecepcionVoto::Aceptado { .. }
    ));
    let cierre2 = motor2.cerrar()?;
    assert!(cierre2.certificado_peso.is_some());
    let tabla2 = motor2.tabla_actual().expect("tabla").clone();
    assert!(
        motor2.certificado_para_tabla(&tabla2)?.is_some(),
        "con solo sueltos sí se remonta"
    );
    Ok(())
}

// ── agm_12 · un agregado de otra ventana se ignora ──────────────────────────────────────────

#[test]
fn agm_12_agregado_de_otra_ventana_se_ignora() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3])?;
    let mut msg = msg_de(&motor, RAIZ_ESTADO_CERO);
    msg.n = 2;
    let ag = agregado_con(&tabla, 1, &secretas, 0, &[0, 1], 0, msg)?;
    let respuestas = motor.recibir_agregados(&[ag])?;
    assert!(matches!(respuestas[0], RecepcionAgregado::Ignorar));
    Ok(())
}

// ── agm_13/14/15 · N3 · B-87 · publicar en cuanto se cubre la subred ────────────────────────

#[test]
fn agm_13_publica_en_cuanto_cubre_toda_su_subred() -> Result<(), Error> {
    // S = 1: las tres claves de la tabla caen en la subred 0, la única propia de la clave 1.
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    // Solo el voto propio: faltan dos claves (2 y 3).
    assert!(
        motor.publicar_agregado(2)?.is_empty(),
        "con dos claves sin voto no se publica antes del último slot"
    );
    let v2 = voto_con(&bls(2)?, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v2)),
        RecepcionVoto::Aceptado { .. }
    ));
    assert!(
        motor.publicar_agregado(2)?.is_empty(),
        "con una clave sin voto tampoco"
    );
    let v3 = voto_con(&bls(3)?, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v3)),
        RecepcionVoto::Aceptado { .. }
    ));
    // Subred cubierta: publica en el slot 2, antes del último (3).
    let publicados = motor.publicar_agregado(2)?;
    assert_eq!(
        publicados.len(),
        1,
        "en cuanto cubre toda su subred, publica"
    );
    Ok(())
}

#[test]
fn agm_14_si_falta_una_clave_espera_al_ultimo_slot() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    let v2 = voto_con(&bls(2)?, 1, c, h_t, RAIZ_ESTADO_CERO)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v2)),
        RecepcionVoto::Aceptado { .. }
    ));
    // Falta la clave 3: la subred no está cubierta y no publica antes del último slot.
    assert!(
        motor.publicar_agregado(2)?.is_empty(),
        "si falta una clave, espera al último slot"
    );
    let publicados = motor.publicar_agregado(3)?;
    assert_eq!(
        publicados.len(),
        1,
        "al empezar el último slot publica aunque falte la clave"
    );
    Ok(())
}

#[test]
fn agm_15_sigue_publicando_una_sola_vez() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], true, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let c = inst_cand(&motor);
    let h_t = inst_h_t(&motor);
    for i in [2u8, 3] {
        let v = voto_con(&bls(i)?, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        assert!(matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ));
    }
    assert_eq!(
        motor.publicar_agregado(2)?.len(),
        1,
        "publica en cuanto cubre la subred"
    );
    // La bandera de publicación única queda armada: es la que impide repetir en la misma ventana.
    assert!(
        motor
            .instancia
            .as_ref()
            .expect("instancia")
            .agregado_publicado,
        "la bandera de publicación única queda armada"
    );
    assert!(
        motor.publicar_agregado(2)?.is_empty(),
        "no se repite en el mismo slot"
    );
    assert!(
        motor.publicar_agregado(3)?.is_empty(),
        "ni al llegar el último slot"
    );
    assert!(motor.publicar_agregado(4)?.is_empty(), "ni después");
    Ok(())
}
