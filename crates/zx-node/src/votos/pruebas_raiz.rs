//! A1-D1-2 · M1–M9 · la raíz de estado en el motor de votos (pieza A1, paso (d), primera mitad).
//!
//! Pruebas de que el motor firma la raíz **que le da la vista**, acepta votos con cualquier raíz,
//! los agrupa por raíz, certifica la que alcanza el quórum y avisa de la discrepancia. Con la vista
//! por defecto todo sale como la base (raíz cero, byte a byte).

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
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use primitive_types::U256;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_undo;
use zx_consensus::transicion::{Estado, Fase, Garantia, ParametrosEvidencia, ParametrosTransicion};
use zx_core::{Amount, BlockHash, ClavePublica, Digest, OperacionAlmacenamiento};
use zx_votos::{ClaveSecreta, DOMINIO_VOTO};

use super::{
    ConfigMotorVotos, DiarioVotos, EventoMotor, MotorVotos, RAIZ_ESTADO_CERO, RecepcionVoto,
    VistaCadena, deserializar_voto_peso, serializar_voto_peso,
};

const DEN: i64 = 1_401_600_000;
const SLOT: i64 = 100;

type Error = Box<dyn std::error::Error>;
type Hash = zx_votos::Hash;

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

fn cand(n: u8) -> Hash {
    [n; 32]
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
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de `cola_tablas_voto`.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT)?,
    );
    Ok((con_cola, indices))
}

fn motor_peso(indices: &[u8], emitir: bool) -> Result<MotorVotos, Error> {
    let claves = indices
        .iter()
        .map(|i| bls(*i))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves,
        emitir_votos: emitir,
    }))
}

/// Vista de cadena que niega el candado (permisiva) y **entrega** una raíz fija (M1).
struct VistaRaiz(Hash);

impl VistaCadena for VistaRaiz {
    fn desciende(&self, _candidato: &Hash, _ancestro: &Hash) -> bool {
        true
    }
    fn en_cadena_seleccionada(&self, _hash: &Hash) -> bool {
        true
    }
    fn slot_de(&self, _hash: &Hash) -> Option<u64> {
        None
    }
    fn raiz_estado_de_voto(&self, _n: u64, _candidato: &Hash) -> Hash {
        self.0
    }
}

/// Voto por peso firmado (A3) con la raíz dada.
fn voto_con(
    sk: &ClaveSecreta,
    n: u64,
    candidato: Hash,
    h_t_siguiente: Hash,
    raiz_estado: Hash,
) -> Result<super::VotoPeso, Error> {
    let firma = zx_votos::firmar(
        sk,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz_estado),
    )?;
    Ok(super::VotoPeso {
        n,
        candidato,
        h_t_siguiente,
        raiz_estado,
        clave: sk.clave_publica().bytes(),
        firma,
    })
}

fn inst_h_t(motor: &MotorVotos) -> Hash {
    motor
        .instancia
        .as_ref()
        .expect("instancia abierta")
        .h_t_siguiente
}

fn inst_cand(motor: &MotorVotos) -> Hash {
    motor
        .instancia
        .as_ref()
        .expect("instancia abierta")
        .candidato
}

fn inst_raiz(motor: &MotorVotos) -> Hash {
    motor
        .instancia
        .as_ref()
        .expect("instancia abierta")
        .raiz_estado
}

/// Extrae el único aviso M8 de una lista de eventos, si lo hay.
fn aviso_m8(eventos: &[EventoMotor]) -> Option<EventoMotor> {
    let avisos: Vec<EventoMotor> = eventos
        .iter()
        .filter(|e| matches!(e, EventoMotor::RaizEstadoDiscrepante { .. }))
        .cloned()
        .collect();
    assert!(
        avisos.len() <= 1,
        "M8: a lo sumo un aviso por ventana, llegaron {}",
        avisos.len()
    );
    avisos.into_iter().next()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// M1 · el voto lleva la raíz que da la vista
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t_raiz_m1_el_voto_lleva_la_raiz_de_la_vista() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let r = [0xAB; 32];
    let mut motor = motor_peso(&[1], true)?;
    let paso = motor.avanzar_con_vista(1, hash(0x11), &estado, SLOT, &VistaRaiz(r))?;
    let voto = deserializar_voto_peso(&paso.votos[0])?;
    assert_eq!(
        voto.raiz_estado, r,
        "M1: el voto propio lleva la raíz de la vista"
    );
    assert_eq!(
        inst_raiz(&motor),
        r,
        "M1: la instancia guarda la raíz propia"
    );
    Ok(())
}

#[test]
fn t_raiz_m1_el_voto_tardio_lleva_la_raiz_de_la_vista() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 2, DEN)])?;
    let sk = bls(1)?;
    let r = [0xCD; 32];
    let dir = tempfile::tempdir()?;
    let mut motor = motor_peso(&[1], true)?;
    motor.vincular_diario(DiarioVotos::nueva(dir.path().join("v.registro"), 7)?);
    let c = cand(0x20);
    let paso = motor.votar_tardio(3, c, &estado, &VistaRaiz(r))?;
    assert_eq!(paso.votos.len(), 1, "firma el tardío");
    assert_eq!(
        paso.votos[0].raiz_estado, r,
        "M1: el tardío lleva la raíz de la vista"
    );
    let mensaje = zx_votos::mensaje_voto_peso(3, &c, &paso.votos[0].h_t_siguiente, &r);
    zx_votos::verificar(
        &sk.clave_publica(),
        &paso.votos[0].firma,
        DOMINIO_VOTO,
        &mensaje,
    )?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// M3/M4 · recibir con cualquier raíz y agrupar
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t_raiz_m3_voto_con_otra_raiz_se_acepta_y_va_a_su_grupo() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&[1], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    let sk2 = bls(2)?;
    let r = [0x55; 32];
    let v = voto_con(&sk2, 1, c, h_t, r)?;
    assert!(
        matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ),
        "M3: un voto válido con otra raíz se acepta"
    );
    let inst = motor.instancia.as_ref().expect("instancia");
    let guardado = inst
        .votos_peso
        .iter()
        .find(|a| a.clave == v.clave)
        .expect("voto guardado");
    assert_eq!(
        guardado.raiz_estado, r,
        "M3: el voto se guarda en el grupo de su raíz"
    );
    Ok(())
}

#[test]
fn t_raiz_m3_una_clave_cuenta_en_un_solo_grupo() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&[1], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    let sk2 = bls(2)?;
    let r1 = [0x01; 32];
    let r2 = [0x02; 32];
    let v1 = voto_con(&sk2, 1, c, h_t, r1)?;
    let v2 = voto_con(&sk2, 1, c, h_t, r2)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v1)),
        RecepcionVoto::Aceptado { .. }
    ));
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v2)),
        RecepcionVoto::Aceptado { .. }
    ));
    let inst = motor.instancia.as_ref().expect("instancia");
    let del_grupo: Vec<_> = inst
        .votos_peso
        .iter()
        .filter(|a| a.clave == v1.clave)
        .collect();
    assert_eq!(del_grupo.len(), 1, "M3: la clave cuenta en un solo grupo");
    assert_eq!(
        del_grupo[0].raiz_estado, r1,
        "M3: se queda en el primer grupo"
    );
    Ok(())
}

#[test]
fn t_raiz_m4_voto_pasado_con_raiz_entra_en_el_detector() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&[1], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let _ = motor.avanzar(2, hash(0x22), &estado, SLOT)?;
    let antes = motor.detector.votos_guardados();
    let sk2 = bls(2)?;
    let r = [0x42; 32];
    let v = voto_con(&sk2, 1, cand(0x33), cand(0x44), r)?;
    assert!(
        matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Rechazado { motivo: "ventana" }
        ),
        "la respuesta al llamante sigue siendo `ventana`"
    );
    assert_eq!(
        motor.detector.votos_guardados(),
        antes + 1,
        "M4: el voto pasado con raíz entró en el detector"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// M5 · agrupar por raíz y certificar la que alcanza el quórum
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t_raiz_m5_se_certifica_la_raiz_con_quorum_aunque_no_sea_la_propia() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let r = [0x77; 32];
    let mut motor = motor_peso(&[1], true)?;
    let paso1 = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    assert_eq!(paso1.votos.len(), 1, "voto propio");
    let propio = deserializar_voto_peso(&paso1.votos[0])?;
    assert_eq!(
        propio.raiz_estado, RAIZ_ESTADO_CERO,
        "la vista por defecto firma cero"
    );
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    for i in [2u8, 3u8] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c, h_t, r)?;
        assert!(matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ));
    }
    let cierre = motor.cerrar()?;
    let cert = cierre
        .certificado_peso
        .clone()
        .expect("M5: certifica la raíz del grupo con quórum");
    assert_eq!(
        cert.raiz_estado, r,
        "M5: se certifica la raíz del grupo, no la propia"
    );
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let pubs = super::claves_publicas_de_tabla(&tabla)?;
    zx_votos::verificar_firma_peso(&tabla, &pubs, &cert)?;
    assert_eq!(
        zx_votos::peso::firmantes_de_mapa(&cert.mapa).len(),
        2,
        "M5: el certificado lleva solo las firmas de su grupo"
    );
    let aviso = aviso_m8(&cierre.eventos).expect("M8: aviso al certificar otra raíz");
    if let EventoMotor::RaizEstadoDiscrepante {
        n,
        propia,
        certificada,
        raiz_mayor,
        raices_distintas,
        sin_quorum_por_division,
        ..
    } = aviso
    {
        assert_eq!(n, 1);
        assert_eq!(propia, super::hex(&RAIZ_ESTADO_CERO));
        assert_eq!(certificada, Some(super::hex(&r)));
        assert_eq!(raiz_mayor, super::hex(&r));
        assert_eq!(raices_distintas, 2);
        assert!(!sin_quorum_por_division);
    } else {
        unreachable!("aviso_m8 devuelve la variante");
    }
    Ok(())
}

#[test]
fn t_raiz_m5_dos_grupos_sin_quorum_no_certifican() -> Result<(), Error> {
    // W = 4 (cuatro claves de peso 1); quórum = 3. Dos grupos de peso 2: ninguno llega, la suma sí.
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let r_a = [0x10; 32];
    let r_b = [0x20; 32];
    let mut motor = motor_peso(&[], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    for (i, r) in [(1u8, r_a), (2, r_a), (3, r_b), (4, r_b)] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c, h_t, r)?;
        assert!(matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ));
    }
    let cierre = motor.cerrar()?;
    assert!(
        cierre.certificado_peso.is_none(),
        "M5: ningún grupo alcanza el quórum"
    );
    let acta = cierre
        .acta_peso
        .clone()
        .expect("M5: acta del grupo de más peso");
    assert_eq!(acta.raiz_estado, r_a, "M5: a igualdad, la raíz menor");
    let aviso = aviso_m8(&cierre.eventos).expect("M8: aviso por división");
    if let EventoMotor::RaizEstadoDiscrepante {
        certificada,
        peso_mayor,
        peso_segunda,
        raices_distintas,
        sin_quorum_por_division,
        ..
    } = aviso
    {
        assert!(certificada.is_none(), "M8: no hubo certificado");
        assert_eq!(peso_mayor, 2);
        assert_eq!(peso_segunda, 2);
        assert_eq!(raices_distintas, 2);
        assert!(
            sin_quorum_por_division,
            "M8: sin quórum por división aunque la suma lo alcanza"
        );
    } else {
        unreachable!("aviso_m8 devuelve la variante");
    }
    Ok(())
}

#[test]
fn t_raiz_m5_no_se_mezclan_firmas_de_dos_raices() -> Result<(), Error> {
    // W = 3; quórum = 2. R_A con dos claves (quórum) y R_B con una.
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let r_a = [0x30; 32];
    let r_b = [0x40; 32];
    let mut motor = motor_peso(&[], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    for (i, r) in [(1u8, r_a), (2, r_a), (3, r_b)] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c, h_t, r)?;
        assert!(matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ));
    }
    let cierre = motor.cerrar()?;
    let cert = cierre.certificado_peso.clone().expect("certificado de R_A");
    assert_eq!(cert.raiz_estado, r_a);
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let pos = |i: u8| -> usize {
        tabla
            .claves
            .iter()
            .position(|cl| cl.clave == bls(i).expect("clave").clave_publica().bytes())
            .map(|p| p + 1)
            .expect("clave en la tabla")
    };
    let mut esperados = [pos(1), pos(2)];
    esperados.sort_unstable();
    assert_eq!(
        zx_votos::peso::firmantes_de_mapa(&cert.mapa),
        esperados.to_vec(),
        "M5: el mapa del certificado solo marca al grupo certificado"
    );
    Ok(())
}

#[test]
fn t_raiz_m5_certificado_remontado_conserva_la_raiz() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let r = [0x66; 32];
    let mut motor = motor_peso(&[1], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    for i in [2u8, 3u8] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c, h_t, r)?;
        assert!(matches!(
            motor.recibir_voto(&serializar_voto_peso(&v)),
            RecepcionVoto::Aceptado { .. }
        ));
    }
    assert_eq!(
        motor
            .cerrar()?
            .certificado_peso
            .expect("certificado")
            .raiz_estado,
        r
    );
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let remontado = motor
        .certificado_para_tabla(&tabla)?
        .expect("hay quórum con la misma tabla");
    assert_eq!(
        remontado.raiz_estado, r,
        "M5: el certificado remontado conserva la raíz de su grupo"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// M6 · dos raíces de una clave son doble voto
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t_raiz_m6_dos_raices_de_una_clave_son_doble_voto() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, 50)])?;
    let sk1 = bls(1)?;
    let mut motor = motor_peso(&[], false)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    let r1 = [0x01; 32];
    let r2 = [0x02; 32];
    let v1 = voto_con(&sk1, 1, c, h_t, r1)?;
    let v2 = voto_con(&sk1, 1, c, h_t, r2)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v1)),
        RecepcionVoto::Aceptado { .. }
    ));
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v2)),
        RecepcionVoto::Aceptado { .. }
    ));
    let evidencias = motor.drenar_evidencias_peso();
    assert_eq!(
        evidencias.len(),
        1,
        "M6: dos raíces de una clave forman una pareja"
    );
    let ev = evidencias[0].clone();
    assert_ne!(ev.raiz1, ev.raiz2, "M6: la pareja es por raíces distintas");
    // El consenso aplica la evidencia `0x0B` y castiga el doble voto.
    let op = OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: ev.clave_bls,
        voto1: zx_core::VotoPesoEvidencia {
            n: ev.n,
            candidato: ev.h1,
            h_t_siguiente: ev.h_t1,
            raiz_estado: ev.raiz1,
            firma: ev.firma1.bytes(),
        },
        voto2: zx_core::VotoPesoEvidencia {
            n: ev.n2,
            candidato: ev.h2,
            h_t_siguiente: ev.h_t2,
            raiz_estado: ev.raiz2,
            firma: ev.firma2.bytes(),
        },
    };
    let (castigado, _, r) = aplicar_evidencia_votos_peso_con_undo(
        &estado,
        &op,
        ed(9),
        &params(),
        &param_evidencia(),
        5,
    );
    r?;
    assert_eq!(
        castigado.garantias[&ed(1)].incidentes.len(),
        1,
        "el consenso castiga el doble voto por raíz"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// M7 · una sola raíz propia por ventana, también tras reabrir el diario
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t_raiz_m7_tras_reabrir_el_diario_no_se_firma_otra_raiz() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 2, DEN)])?;
    let dir = tempfile::tempdir()?;
    let ruta = dir.path().join("votos.registro");
    let c = cand(0x20);
    let r1 = [0x11; 32];
    let r2 = [0x22; 32];
    let clave_bls = bls(1)?.clave_publica().bytes();
    let h_t;
    let mensaje_r1;
    {
        let mut motor = motor_peso(&[1], true)?;
        motor.vincular_diario(DiarioVotos::nueva(ruta.as_path(), 7)?);
        let paso = motor.votar_tardio(3, c, &estado, &VistaRaiz(r1))?;
        assert_eq!(paso.votos.len(), 1);
        assert_eq!(paso.votos[0].raiz_estado, r1);
        h_t = paso.votos[0].h_t_siguiente;
        mensaje_r1 = zx_votos::mensaje_voto_peso(3, &c, &h_t, &r1);
    }
    // M7 · la reserva cubre la raíz: el mensaje reservado con `r1` y el que se pediría con `r2` son
    // distintos, así que el diario los ve como conflicto aunque el motor corte antes por
    // `ya_reservada`.
    let mensaje_r2 = zx_votos::mensaje_voto_peso(3, &c, &h_t, &r2);
    assert_ne!(
        mensaje_r1, mensaje_r2,
        "la raíz entra en el mensaje que se reserva"
    );
    let diario = DiarioVotos::abrir(ruta.as_path(), 7)?;
    assert_eq!(
        diario.resolver(&clave_bls, 3, &mensaje_r2)?,
        super::ResolucionDiario::Conflicto {
            registrado: mensaje_r1
        },
        "M7: el diario ve el conflicto porque la reserva incluye la raíz"
    );
    drop(diario);
    // El motor, con otra raíz, tampoco firma la misma ventana tras reabrir.
    let mut motor2 = motor_peso(&[1], true)?;
    motor2.vincular_diario(DiarioVotos::abrir(ruta.as_path(), 7)?);
    let paso2 = motor2.votar_tardio(3, c, &estado, &VistaRaiz(r2))?;
    assert!(
        paso2.votos.is_empty(),
        "M7: no se firma otra raíz tras reabrir el diario"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// M8 · un aviso por ventana con sus campos; sin discrepancia, no hay aviso
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t_raiz_m8_un_aviso_por_ventana_con_sus_campos() -> Result<(), Error> {
    // Caso con certificado: la propia firma cero y las claves 2 y 3 firman R (quórum).
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let r = [0x99; 32];
    let mut motor = motor_peso(&[1], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    for i in [2u8, 3u8] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c, h_t, r)?;
        let _ = motor.recibir_voto(&serializar_voto_peso(&v));
    }
    let cierre = motor.cerrar()?;
    let aviso = aviso_m8(&cierre.eventos).expect("M8: un aviso por ventana");
    if let EventoMotor::RaizEstadoDiscrepante {
        n,
        propia,
        certificada,
        raiz_mayor,
        peso_mayor,
        raiz_segunda,
        peso_segunda,
        raices_distintas,
        sin_quorum_por_division,
    } = aviso
    {
        assert_eq!(n, 1);
        assert_eq!(propia, super::hex(&RAIZ_ESTADO_CERO));
        assert_eq!(certificada, Some(super::hex(&r)));
        assert_eq!(raiz_mayor, super::hex(&r));
        assert_eq!(peso_mayor, 2);
        assert_eq!(raiz_segunda, super::hex(&RAIZ_ESTADO_CERO));
        assert_eq!(peso_segunda, 1);
        assert_eq!(raices_distintas, 2);
        assert!(!sin_quorum_por_division);
    } else {
        unreachable!("aviso_m8 devuelve la variante");
    }

    // Caso sin certificado por división: dos grupos de peso 2 y la suma 4 (quórum 3).
    let (estado4, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let ra = [0x10; 32];
    let rb = [0x20; 32];
    let mut motor4 = motor_peso(&[], true)?;
    let _ = motor4.avanzar(1, hash(0x11), &estado4, SLOT)?;
    let h_t4 = inst_h_t(&motor4);
    let c4 = inst_cand(&motor4);
    for (i, r) in [(1u8, ra), (2, ra), (3, rb), (4, rb)] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c4, h_t4, r)?;
        let _ = motor4.recibir_voto(&serializar_voto_peso(&v));
    }
    let cierre4 = motor4.cerrar()?;
    let aviso4 = aviso_m8(&cierre4.eventos).expect("M8: aviso sin certificado");
    if let EventoMotor::RaizEstadoDiscrepante {
        certificada,
        peso_mayor,
        peso_segunda,
        raices_distintas,
        sin_quorum_por_division,
        ..
    } = aviso4
    {
        assert!(certificada.is_none(), "M8: no hubo certificado");
        assert_eq!(peso_mayor, 2);
        assert_eq!(peso_segunda, 2);
        assert_eq!(raices_distintas, 2);
        assert!(sin_quorum_por_division, "M8: sin quórum por división");
    } else {
        unreachable!("aviso_m8 devuelve la variante");
    }
    Ok(())
}

#[test]
fn t_raiz_m8_sin_discrepancia_no_hay_aviso() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&[1], true)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let h_t = inst_h_t(&motor);
    let c = inst_cand(&motor);
    for i in [2u8, 3u8] {
        let sk = bls(i)?;
        let v = voto_con(&sk, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let _ = motor.recibir_voto(&serializar_voto_peso(&v));
    }
    let cierre = motor.cerrar()?;
    assert!(
        !cierre
            .eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::RaizEstadoDiscrepante { .. })),
        "M8: sin discrepancia no hay aviso"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// M9 · con la vista por defecto, todo sale cero
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t_raiz_m9_con_la_vista_por_defecto_sale_cero() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&[1, 2], true)?;
    let paso1 = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    assert_eq!(paso1.votos.len(), 2, "dos claves propias");
    for sobre in &paso1.votos {
        let v = deserializar_voto_peso(sobre)?;
        assert_eq!(
            v.raiz_estado, RAIZ_ESTADO_CERO,
            "M9: el voto con la vista por defecto sale cero"
        );
    }
    let paso2 = motor.avanzar(2, hash(0x22), &estado, SLOT)?;
    let cert = paso2.certificado_peso.expect("certificado");
    assert_eq!(
        cert.raiz_estado, RAIZ_ESTADO_CERO,
        "M9: el certificado con la vista por defecto sale cero"
    );
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let pubs = super::claves_publicas_de_tabla(&tabla)?;
    zx_votos::verificar_firma_peso(&tabla, &pubs, &cert)?;
    assert!(
        !paso2
            .eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::RaizEstadoDiscrepante { .. })),
        "M9: sin discrepancia no hay aviso"
    );
    Ok(())
}
