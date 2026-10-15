//! RET-1b · pruebas del sobre `ZXV2`, de los pares contradictorios por tabla siguiente y de la
//! caducidad del motor (E1, E3, E4, E7).
//!
//! Módulo hijo de `votos`, de modo que puede observar la memoria privada de parejas
//! (`drenar_evidencias`) y el candado (`candidato_permitido`) sin abrir API nueva.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use super::*;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{Estado, Garantia};
use zx_core::{Amount, ClavePublica as ClaveEd, Digest};

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

fn bh(x: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([x; 32]))
}

fn h(x: u8) -> Hash {
    [x; 32]
}

/// Estado dev con la clave `ed(1)` registrada y `n_sectores` activos (fixture de peso real).
fn estado_con(n_sectores: usize) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
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
        let id = SectorId {
            clave: e,
            sector_index: u16::try_from(i).expect("indice"),
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
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
            },
        );
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    con_cola
}

/// Igual que [`estado_con`] más un sector **activo** extra (`sector_index` 100): la tabla de la
/// ventana 0 (`T_0`) ya difiere de la de `estado_con(100)`. Con N1, sin base ni cola, el votante
/// declara la huella de la tabla con la que firma, así que dos estados con `T_0` distinta declaran
/// huellas siguientes distintas sin depender de la `T_1` que antes construía el nodo.
fn estado_con_extra() -> Estado {
    let mut est = estado_con(100);
    let p = ParametrosSector::dev();
    let id = SectorId {
        clave: ed(1),
        sector_index: 100,
        version: 0,
    };
    est.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0; 4],
            history_size: 1,
            etapa: Etapa::Activo,
            alta_slot: -10,
            renovacion_slot: 0,
            retiro_slot: -1,
            fianza: p.q_sec,
            aud_apertura: -1,
            aud_contestada: -1,
        },
    );
    // TB-1c-2 · X3 · el sector extra cambia la tabla; vuelve a derivar la cola con el estado nuevo.
    est.cola_tablas_voto.clear();
    est.ultima_ventana_derivada_sin_base = None;
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    con_cola
}

fn motor(emitir: bool) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![bls(1)],
        emitir_votos: emitir,
    })
}

/// Abre la instancia 0 con `candidato` y devuelve sus sobres propios.
fn abrir_cero(m: &mut MotorVotos, candidato: u8, est: &Estado) -> Vec<Vec<u8>> {
    m.avanzar(0, bh(candidato), est, SLOT)
        .expect("abrir 0")
        .votos
}

/// Comprueba que cada firma verifica con **su** `h_T(n+1)` y que el par es canónico.
fn firmas_alineadas(ev: &EvidenciaVotosPesoCompleta) {
    let pk = ClavePublica::desde_bytes(&ev.clave_bls).expect("clave BLS");
    let m1 = mensaje_voto_peso(ev.n, &ev.h1, &ev.h_t1, &ev.raiz1);
    let m2 = mensaje_voto_peso(ev.n, &ev.h2, &ev.h_t2, &ev.raiz2);
    assert!(
        verificar(&pk, &ev.firma1, DOMINIO_VOTO, &m1).is_ok(),
        "firma1 con h_t1"
    );
    assert!(
        verificar(&pk, &ev.firma2, DOMINIO_VOTO, &m2).is_ok(),
        "firma2 con h_t2"
    );
    assert!(
        (ev.h1, ev.h_t1) < (ev.h2, ev.h_t2),
        "par canónico (h1,h_t1) < (h2,h_t2)"
    );
}

fn una_evidencia(r: &mut MotorVotos) -> EvidenciaVotosPesoCompleta {
    let mut evs = r.drenar_evidencias_peso();
    assert_eq!(evs.len(), 1, "una evidencia pendiente");
    evs.remove(0)
}

/// Q1 · dos votos de la misma clave y ventana con candidatos **y** tablas siguientes distintas
/// forman una prueba (la pregunta falsable de RET-1b).
#[test]
fn q1_distinto_candidato_y_distinta_tabla_forman_prueba() {
    let est_a = estado_con(100);
    let est_b = estado_con_extra();
    let mut r = motor(true);
    let _ = abrir_cero(&mut r, 0x20, &est_a);
    let h_t_r = r.instancia.as_ref().expect("instancia").h_t_siguiente;

    let mut s = motor(true);
    let sobres = abrir_cero(&mut s, 0x21, &est_b);
    let sobre = sobres.first().expect("sobre ajeno");
    let v = deserializar_voto_peso(sobre).expect("ZXV2");
    assert_ne!(
        v.h_t_siguiente, h_t_r,
        "la tabla siguiente del ajeno difiere"
    );

    assert_eq!(
        r.recibir_voto(sobre),
        RecepcionVoto::Rechazado {
            motivo: "otro_candidato"
        }
    );
    let ev = una_evidencia(&mut r);
    assert_eq!(ev.n, 0);
    assert_ne!(ev.h_t1, ev.h_t2, "las dos tablas siguientes constan");
    firmas_alineadas(&ev);
    assert!(r.drenar_evidencias_peso().is_empty(), "no se repite");
}

/// Q2 · mismo candidato y tablas siguientes distintas: también forman prueba.
#[test]
fn q2_mismo_candidato_y_distinta_tabla_forman_prueba() {
    let est_a = estado_con(100);
    let est_b = estado_con_extra();
    let mut r = motor(true);
    let _ = abrir_cero(&mut r, 0x30, &est_a);
    let h_t_r = r.instancia.as_ref().expect("instancia").h_t_siguiente;

    let mut s = motor(true);
    let sobres = abrir_cero(&mut s, 0x30, &est_b);
    let sobre = sobres.first().expect("sobre ajeno");
    let v = deserializar_voto_peso(sobre).expect("ZXV2");
    assert_ne!(v.h_t_siguiente, h_t_r, "misma candidato, distinta tabla");

    assert_eq!(
        r.recibir_voto(sobre),
        RecepcionVoto::Rechazado {
            motivo: "otra_tabla"
        }
    );
    let ev = una_evidencia(&mut r);
    assert_eq!(ev.n, 0);
    assert_eq!(ev.h1, ev.h2, "mismo candidato");
    assert_ne!(ev.h_t1, ev.h_t2, "distinta tabla siguiente");
    firmas_alineadas(&ev);
}

/// Q4 · un sobre `ZXV1` se rechaza; un `ZXV2` con otra tabla siguiente y firma válida no cuenta.
#[test]
fn q4_zxv1_se_rechaza_y_otra_tabla_no_cuenta() {
    // Cabecera vieja: no deserializa y no es plausible.
    assert!(!voto_es_plausible(b"ZXV1\x00\x00\x00\x00"));
    let mut viejo = vec![0u8; 400];
    viejo[..4].copy_from_slice(b"ZXV1");
    assert!(matches!(
        deserializar_voto_peso(&viejo),
        Err(ErrorVotos::CabeceraInvalida)
    ));

    let est_a = estado_con(100);
    let est_b = estado_con_extra();
    let mut r = motor(false);
    let _ = abrir_cero(&mut r, 0x40, &est_a);

    let mut s = motor(true);
    let sobres = abrir_cero(&mut s, 0x40, &est_b);
    let sobre = sobres.first().expect("sobre ajeno");
    let v = deserializar_voto_peso(sobre).expect("ZXV2");
    // Firma válida con el `h_T(n+1)` del sobre; no coincide con el de la instancia.
    assert_eq!(
        r.recibir_voto(sobre),
        RecepcionVoto::Rechazado {
            motivo: "otra_tabla"
        }
    );
    let inst = r.instancia.as_ref().expect("instancia");
    // M9-a2 · en modo por peso la memoria de aceptación es `votos_peso` (no hay `firmas` del
    // sorteo): el voto de otra tabla queda en la evidencia y no cuenta para el quórum.
    assert!(
        !inst.votos_peso.iter().any(|a| a.clave == v.clave),
        "no cuenta para el quórum"
    );
}

/// E4 · la caducidad del perfil dev coincide con `F_SLOTS + m_margen_slots` (en slots).
#[test]
fn e4_formula_caducidad_del_perfil_dev() {
    assert_eq!(
        CADUCIDAD_TABLA_VENTANAS.saturating_mul(T_INST_VOTOS),
        crate::perfil::F_SLOTS.saturating_add(crate::perfil::M_MARGEN_SLOTS),
        "CADUCIDAD·T_inst == F_SLOTS + m_margen"
    );
}

/// Q5 · con la base caducada el motor no abre ni firma y emite `base_caducada` una sola vez.
#[test]
fn q5_base_caducada_no_abre_y_avisa_una_vez() {
    let est = estado_con(100);
    let mut m = motor(true);
    let m_base: u64 = 10;
    let mut est_cad = est.clone();
    est_cad.finalidad_votos_n = m_base;
    est_cad.finalidad_votos_h_t = Some(h(0xAB));
    let n = m_base + CADUCIDAD_TABLA_VENTANAS + 1;
    let paso = m
        .avanzar(n, bh(0x50), &est_cad, SLOT)
        .expect("avanzar caducado");
    assert_eq!(m.instancia_actual(), None, "no abre");
    assert!(
        paso.votos.is_empty(),
        "no firma ni emite sobres con base caducada"
    );
    assert_eq!(
        paso.eventos
            .iter()
            .filter(|e| matches!(e, EventoMotor::BaseCaducada { .. }))
            .count(),
        1,
        "un solo aviso"
    );
    // Segunda vuelta: la marca impide repetir el aviso.
    let paso2 = m
        .avanzar(n + 1, bh(0x51), &est_cad, SLOT)
        .expect("avanzar caducado 2");
    assert_eq!(
        paso2
            .eventos
            .iter()
            .filter(|e| matches!(e, EventoMotor::BaseCaducada { .. }))
            .count(),
        0,
        "el aviso es único"
    );
}

/// Vista sin cadena: el bloque votado no está en la selección y su slot es desconocido.
struct VistaSinBloque;

impl VistaCadena for VistaSinBloque {
    fn desciende(&self, _candidato: &Hash, _ancestro: &Hash) -> bool {
        false
    }
    fn en_cadena_seleccionada(&self, _hash: &Hash) -> bool {
        false
    }
    fn slot_de(&self, _hash: &Hash) -> Option<u64> {
        None
    }
}

/// Q10 · candado cuyo bloque no está en la vista: bloqueado antes de `n_v·T_inst + F_SLOTS` y
/// liberado a partir de esa cota (E7).
#[test]
fn q10_candado_sin_bloque_en_vista() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    let diario = DiarioVotos::nueva(&ruta, 7).expect("diario");
    let clave_bls = bls(1).clave_publica().bytes();
    let n_v: u64 = 4;
    let candidato_v = h(0x60);
    diario
        .fijar_candado(&clave_bls, n_v, &candidato_v)
        .expect("candado");
    assert_eq!(diario.candado(&clave_bls), Some((n_v, candidato_v)));

    let vista = VistaSinBloque;
    let cota = n_v
        .saturating_mul(T_INST_VOTOS)
        .saturating_add(crate::perfil::F_SLOTS);
    let antes = i64::try_from(cota - 1).expect("slot");
    assert!(matches!(
        candidato_permitido(&diario, &clave_bls, &h(0x61), None, antes, &vista).expect("permiso"),
        PermisoCandado::Bloqueado
    ));
    let en_cota = i64::try_from(cota).expect("slot");
    assert!(matches!(
        candidato_permitido(
            &diario,
            &clave_bls,
            &h(0x61),
            None,
            en_cota,
            &vista
        )
        .expect("permiso"),
        PermisoCandado::Liberado(c) if c == candidato_v
    ));
}
