//! `A5-c-2b` · la agregación de votos en el nodo: suscripción, voto por subred, lotes de agregados,
//! publicación del agregado propio y registro (`agn_01`…`agn_10`).
//!
//! Las pruebas del censor y del tema global (`censor_ignora_votos_de_subred_y_agregados`,
//! `agn_12_un_voto_por_el_tema_global_se_ignora_y_no_llega_al_motor`) viven junto a sus tipos:
//! `bin/zx-censor.rs` y `red/manejador.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use super::*;
use crate::votos::{ConfigMotorVotos, RecepcionAgregado};
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{Estado, Garantia};
use zx_core::{Amount, ClavePublica as ClaveEd};
use zx_votos::ClaveSecreta;
use zx_votos::agregacion::{Agregado, Reparto, subred};

/// Slot fijo de la fixture (independiente del reloj simulado del Nodo).
const SLOT_FIXTURE: i64 = 100;

fn h32(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

/// Estado dev con la clave `1` registrada y `n_sectores` activos (peso real de la fixture).
fn estado_con(n_sectores: usize) -> (Estado, ClaveSecreta) {
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
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT_FIXTURE).expect("slot"),
    );
    (con_cola, sk)
}

fn motor_con(sk: ClaveSecreta) -> MotorVotos {
    MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: perfil::parametros_votos_dev(),
            claves: vec![sk],
            emitir_votos: true,
        },
        64,
    )
}

fn config_base(dir: &std::path::Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: vec![0],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

fn nodo_de_prueba(dir: &std::path::Path) -> Nodo {
    Nodo::arrancar(&config_base(dir)).expect("arranque limpio")
}

fn t_inst() -> u64 {
    perfil::parametros_votos_dev().t_inst.max(1)
}

/// Deja un motor con `C_0` adoptado y la ventana 1 **abierta con quórum real**. Devuelve también la
/// clave BLS pública de ese motor, para que el nodo de prueba pueda declararla como propia.
fn motor_con_ventana_uno_abierta() -> (MotorVotos, Estado, Vec<u8>) {
    let (est, sk) = estado_con(100);
    let pk = sk.clave_publica().bytes().to_vec();
    let c0 = h32(0x10);
    let c1 = h32(0x11);
    let mut motor = motor_con(sk);
    motor.avanzar(0, c0, &est, SLOT_FIXTURE).expect("abrir 0");
    let p1 = motor.avanzar(1, c1, &est, SLOT_FIXTURE).expect("abrir 1");
    assert!(
        p1.certificado_peso.is_some(),
        "C_0 real adoptado al cerrar 0"
    );
    (motor, est, pk)
}

/// A5-c-2c · estado dev con las claves 1 y 2 registradas y `n_sectores` sectores por clave.
fn estado_con_dos_claves(n_sectores: usize) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    for indice in [1u8, 2] {
        let sk = bls(indice);
        let e = ed(indice);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: sk.clave_publica().bytes(),
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
    }
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT_FIXTURE).expect("slot"),
    );
    con_cola
}

/// A5-c-2c · motor con la ventana 1 abierta y la subred propia **sin cubrir**: la tabla tiene dos
/// claves (1 y 2) en la única subred (`S = 1`) y solo la 1 vota. Sirve para probar el respaldo
/// «al empezar el último slot».
fn motor_ventana_uno_sin_cubrir() -> (MotorVotos, Estado) {
    let estado = estado_con_dos_claves(100);
    let sk = bls(1);
    let mut motor = MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: perfil::parametros_votos_dev(),
            claves: vec![sk],
            emitir_votos: true,
        },
        1,
    );
    let c0 = h32(0x10);
    let c1 = h32(0x11);
    motor
        .avanzar(0, c0, &estado, SLOT_FIXTURE)
        .expect("abrir 0");
    motor
        .avanzar(1, c1, &estado, SLOT_FIXTURE)
        .expect("abrir 1");
    (motor, estado)
}

/// Encola un trabajo en la cola acotada y exige que quepa.
fn encolar(tx: &crate::red::EmisorTrabajoRed, trabajo: TrabajoRed) {
    assert!(
        matches!(
            tx.intentar_enviar(trabajo),
            crate::red::ResultadoEnvioTrabajo::Encolado
        ),
        "la cola debe admitir el trabajo"
    );
}

fn registro_de(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("registro.jsonl")).unwrap_or_default()
}

// ── agn_01 · el votante se suscribe a las subredes de sus claves ───────────────────────────

#[test]
fn agn_01_el_votante_se_suscribe_a_las_subredes_de_sus_claves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nodo = nodo_de_prueba(dir.path());
    assert!(nodo.vota, "el nodo de prueba emite votos");
    let s = u16::from(zx_p2p::config::SUBREDES_VOTO);
    let mut esperadas: Vec<u8> = nodo
        .claves_bls_propias
        .iter()
        .filter_map(|clave| subred(clave, s).ok().and_then(|x| u8::try_from(x).ok()))
        .collect();
    esperadas.sort_unstable();
    esperadas.dedup();
    assert!(!esperadas.is_empty(), "el votante tiene subredes propias");
    assert_eq!(
        nodo.subredes_propias(),
        esperadas,
        "el votante se suscribe a las subredes de sus claves de voto"
    );
}

// ── agn_02 · quien no vota no se suscribe ni publica ───────────────────────────────────────

#[test]
fn agn_02_quien_no_vota_no_se_suscribe_ni_publica() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = config_base(dir.path());
    cfg.sin_voto = true;
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque");
    assert!(!nodo.vota);
    assert!(
        nodo.subredes_propias().is_empty(),
        "el que no vota no se suscribe a ninguna subred"
    );
    DIFUSIONES_AGREGADO.with(|c| c.set(0));
    nodo.publicar_agregado_propio(i64::MAX)
        .expect("publicar sin error");
    assert_eq!(
        DIFUSIONES_AGREGADO.with(|c| c.get()),
        0,
        "el que no vota no publica agregados"
    );
    assert!(!registro_de(dir.path()).contains("\"tipo\":\"agregado_publicado\""));
}

// ── agn_03 · el voto sale por su subred ────────────────────────────────────────────────────

#[test]
fn agn_03_el_voto_sale_por_su_subred_y_no_por_el_tema_global() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (motor, _est, _pk) = motor_con_ventana_uno_abierta();
    nodo.motor_votos = Some(motor);
    nodo.candidato_votos_simulado = Some(h32(0xAA));
    DIFUSIONES_VOTO_SUBRED.with(|c| c.set(0));
    let t = t_inst();
    nodo.slot_votos_simulado = Some(2 * t);
    nodo.procesar_votos().expect("procesar");
    assert!(
        DIFUSIONES_VOTO_SUBRED.with(|c| c.get()) > 0,
        "el voto propio de la apertura sale por su subred"
    );
    assert!(
        nodo.red.is_none(),
        "sin red no hay difusión real; el encaminamiento se prueba por el contador"
    );
}

// ── agn_04 · voto de subred válido se reenvía y el de firma falsa penaliza ─────────────────

#[test]
fn agn_04_voto_de_subred_valido_se_reenvia_y_el_de_firma_falsa_penaliza() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (est, sk) = estado_con(100);
    let mut motor = motor_con(sk);
    let paso = motor
        .avanzar(0, h32(0x20), &est, SLOT_FIXTURE)
        .expect("abrir 0");
    let (bytes, subred_voto_u16) = paso
        .votos_red
        .first()
        .cloned()
        .expect("el motor emite un voto de red");
    let subred_voto = u8::try_from(subred_voto_u16).expect("subred < 64");
    assert_eq!(bytes.len(), 248);
    nodo.motor_votos = Some(motor);
    let (tx, rx) = crate::red::nueva_cola_trabajo_red();
    nodo.trabajo_red = Some(rx);

    encolar(
        &tx,
        TrabajoRed::VotoSubredDifundido {
            id: IdDiferido::default(),
            subred: subred_voto,
            bytes: bytes.clone(),
        },
    );
    nodo.procesar_trabajo_red_pendiente();
    assert_eq!(
        nodo.agn.votos_reenviados, 1,
        "un voto de subred válido se reenvía"
    );

    // Firma falsa: se corrompe el último byte de la firma BLS.
    let mut falso = bytes;
    let ultimo = falso.len() - 1;
    falso[ultimo] ^= 0xFF;
    encolar(
        &tx,
        TrabajoRed::VotoSubredDifundido {
            id: IdDiferido::default(),
            subred: subred_voto,
            bytes: falso,
        },
    );
    nodo.procesar_trabajo_red_pendiente();
    assert_eq!(
        nodo.agn.votos_penalizados, 1,
        "un voto con firma falsa se penaliza"
    );
}

// ── agn_05 · los agregados de una vuelta van en un solo lote ───────────────────────────────

#[test]
fn agn_05_los_agregados_de_una_vuelta_van_en_un_solo_lote() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (tx, rx) = crate::red::nueva_cola_trabajo_red();
    nodo.trabajo_red = Some(rx);
    for _ in 0..3 {
        encolar(
            &tx,
            TrabajoRed::AgregadoDifundido {
                id: IdDiferido::default(),
                bytes: vec![0u8; 334],
            },
        );
    }
    LOTES_AGREGADOS.with(|c| c.set(0));
    nodo.procesar_trabajo_red_pendiente();
    assert_eq!(
        LOTES_AGREGADOS.with(|c| c.get()),
        1,
        "los tres agregados de la vuelta van en un solo lote"
    );
    assert_eq!(nodo.agn.agregados_recibidos, 3);
}

// ── agn_06 · cada agregado recibe su veredicto ─────────────────────────────────────────────

#[test]
fn agn_06_cada_agregado_recibe_su_veredicto() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (tx, rx) = crate::red::nueva_cola_trabajo_red();
    nodo.trabajo_red = Some(rx);
    for _ in 0..2 {
        encolar(
            &tx,
            TrabajoRed::AgregadoDifundido {
                id: IdDiferido::default(),
                bytes: vec![1u8; 334],
            },
        );
    }
    nodo.procesar_trabajo_red_pendiente();
    assert_eq!(
        nodo.agn.agregados_ignorados, 2,
        "cada agregado sin tabla abierta recibe su veredicto (ignorar)"
    );
}

// ── agn_07 · el agregado propio se difunde desde el último slot ────────────────────────────

#[test]
fn agn_07_el_agregado_propio_se_difunde_desde_el_ultimo_slot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (motor, _estado) = motor_ventana_uno_sin_cubrir();
    nodo.motor_votos = Some(motor);
    DIFUSIONES_AGREGADO.with(|c| c.set(0));
    // Ventana 1: cierra en el slot 4; el slot 3 es el último. La subred propia tiene dos claves y
    // solo vota una, así que no está cubierta y rige el respaldo al último slot (N3/B-87).
    nodo.publicar_agregado_propio(0).expect("antes del cierre");
    assert_eq!(
        DIFUSIONES_AGREGADO.with(|c| c.get()),
        0,
        "sin subred cubierta, antes del último slot no se publica"
    );
    nodo.publicar_agregado_propio(3).expect("último slot");
    assert!(
        DIFUSIONES_AGREGADO.with(|c| c.get()) > 0,
        "en el último slot se difunde el agregado propio"
    );
    assert!(
        registro_de(dir.path()).contains("\"tipo\":\"agregado_publicado\""),
        "queda el evento del agregado publicado"
    );
}

// ── agn_08 · el cupo se fija con la tabla abierta ──────────────────────────────────────────

#[test]
fn agn_08_el_cupo_se_fija_con_la_tabla_abierta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let s = u16::from(zx_p2p::config::SUBREDES_VOTO);
    let base = (AGREGADORES_POR_SUBRED as usize) * usize::from(s);
    assert_eq!(
        nodo.cupo_diferidos_agregacion(),
        base,
        "sin tabla abierta el cupo es A·S"
    );
    let (motor, _est, pk) = motor_con_ventana_uno_abierta();
    nodo.motor_votos = Some(motor);
    nodo.claves_bls_propias = vec![pk];
    let reparto = {
        let motor = nodo.motor_votos.as_ref().expect("motor");
        let tabla = motor.tabla_actual().expect("tabla abierta");
        Reparto::construir(tabla, motor.subredes()).expect("reparto")
    };
    let extra: usize = nodo
        .subredes_propias()
        .iter()
        .map(|&sub| reparto.claves_de(u16::from(sub)).len())
        .sum();
    assert!(extra > 0, "la tabla abierta tiene claves propias");
    assert_eq!(
        nodo.cupo_diferidos_agregacion(),
        base + extra,
        "el cupo usa la tabla abierta"
    );
}

// ── agn_09 · un evento agregacion_ventana por ventana ──────────────────────────────────────

#[test]
fn agn_09_un_evento_agregacion_ventana_por_ventana() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (motor, _est, _pk) = motor_con_ventana_uno_abierta();
    nodo.motor_votos = Some(motor);
    nodo.candidato_votos_simulado = Some(h32(0xAA));
    let t = t_inst();
    nodo.slot_votos_simulado = Some(2 * t);
    nodo.procesar_votos().expect("cerrar 1 y abrir 2");
    nodo.slot_votos_simulado = Some(3 * t);
    nodo.procesar_votos().expect("cerrar 2 y abrir 3");
    let registro = registro_de(dir.path());
    let lineas: Vec<&str> = registro
        .lines()
        .filter(|l| l.contains("\"tipo\":\"agregacion_ventana\""))
        .collect();
    assert_eq!(lineas.len(), 2, "un evento por ventana cerrada");
    assert!(
        lineas
            .iter()
            .any(|l| l.contains("\"n\":1") && l.contains("\"votos_recibidos\""))
    );
    assert!(lineas.iter().any(|l| l.contains("\"n\":2")));
}

// ── agn_10 · el nodo que no vota certifica solo con agregados ──────────────────────────────

#[test]
fn agn_10_el_nodo_que_no_vota_certifica_solo_con_agregados() {
    let (estado, sk) = estado_con(100);
    // Agregador: emite su voto y publica el agregado de la ventana 1.
    let mut agregador = motor_con(sk);
    agregador
        .avanzar(1, h32(0x30), &estado, SLOT_FIXTURE)
        .expect("abrir 1");
    let publicados = agregador.publicar_agregado(3).expect("publicar");
    assert_eq!(publicados.len(), 1, "la clave es agregadora");
    let (tabla, s) = {
        let t = agregador.tabla_actual().expect("tabla").clone();
        (t, agregador.subredes())
    };
    let reparto = Reparto::construir(&tabla, s).expect("reparto");
    let sub = subred_de_agregado(&publicados[0]).expect("subred");
    let agregado = Agregado::deserializar(&publicados[0], reparto.claves_de(sub).len())
        .expect("agregado válido");

    // Receptor que **no** vota: abre la misma ventana y no publica nada.
    let mut receptor = MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: perfil::parametros_votos_dev(),
            claves: vec![bls(1)],
            emitir_votos: false,
        },
        s,
    );
    receptor
        .avanzar(1, h32(0x30), &estado, SLOT_FIXTURE)
        .expect("abrir 1");
    assert!(
        receptor.publicar_agregado(3).expect("publicar").is_empty(),
        "el que no vota no publica"
    );
    let respuestas = receptor
        .recibir_agregados(std::slice::from_ref(&agregado))
        .expect("recibir agregado");
    assert_eq!(respuestas, vec![RecepcionAgregado::Reenviar]);
    let cierre = receptor.cerrar().expect("cerrar");
    assert!(
        cierre.certificado_peso.is_some(),
        "el nodo que no vota certifica solo con agregados"
    );
}

// ── agn_13 · N1/B-71 · el detector vigila las subredes suscritas ────────────────────────────

#[test]
fn agn_13_el_detector_vigila_las_subredes_suscritas() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nodo = nodo_de_prueba(dir.path());
    assert!(nodo.vota, "el nodo de prueba emite votos");
    let s = u16::from(zx_p2p::config::SUBREDES_VOTO);
    let propias = nodo.subredes_propias();
    assert!(!propias.is_empty(), "el votante tiene subredes propias");
    let motor = nodo.motor_votos.as_ref().expect("motor");
    for clave in &nodo.claves_bls_propias {
        let c: [u8; 48] = clave.as_slice().try_into().expect("clave BLS de 48 B");
        assert!(motor.clave_vigilada(&c), "la clave propia está vigilada");
    }
    let mut ajena = None;
    for indice in 2u8..64 {
        let sk = bls(indice);
        let sub = subred(sk.clave_publica().bytes().as_slice(), s).expect("subred");
        if !propias.contains(&u8::try_from(sub).expect("subred < 64")) {
            ajena = Some(sk.clave_publica().bytes());
            break;
        }
    }
    let ajena = ajena.expect("hay claves fuera de las subredes propias");
    assert!(
        !motor.clave_vigilada(&ajena),
        "una clave de otra subred no está vigilada"
    );
}

// ── agn_14 · N1/B-71 · el que no vota no vigila ninguna ─────────────────────────────────────

#[test]
fn agn_14_quien_no_vota_no_vigila_ninguna() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = config_base(dir.path());
    cfg.sin_voto = true;
    let nodo = Nodo::arrancar(&cfg).expect("arranque");
    assert!(!nodo.vota);
    assert!(
        nodo.subredes_propias().is_empty(),
        "el que no vota no se suscribe a ninguna subred"
    );
    let motor = nodo.motor_votos.as_ref().expect("motor");
    for indice in 1u8..8 {
        assert!(
            !motor.clave_vigilada(&bls(indice).clave_publica().bytes()),
            "el que no vota no vigila ninguna clave"
        );
    }
}

// ── agn_15 · N2/B-83 · el aviso de «sin azar del sistema» queda en el registro ──────────────

#[test]
fn agn_15_sin_azar_del_sistema_queda_en_el_registro() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let motor = MotorVotos::nuevo_sin_azar_para_test(
        ConfigMotorVotos {
            perfil: perfil::parametros_votos_dev(),
            claves: vec![bls(1)],
            emitir_votos: true,
        },
        64,
    );
    assert!(motor.azar_del_sistema_no_disponible());
    nodo.motor_votos = Some(motor);
    nodo.avisar_sin_azar_del_sistema();
    nodo.avisar_sin_azar_del_sistema();
    let registro = registro_de(dir.path());
    let veces = registro
        .lines()
        .filter(|l| l.contains("\"tipo\":\"azar_del_sistema_no_disponible\""))
        .count();
    assert_eq!(veces, 1, "el aviso queda una sola vez en el registro");
}
