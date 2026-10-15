#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
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

fn motor_con_emitir(sk: ClaveSecreta, emitir: bool) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: emitir,
    })
}

/// Abre la instancia 0 con `candidato` en un motor nuevo de la clave registrada. Devuelve el
/// motor y el estado compartido (misma `T_0`/`h_T(1)` para todos los motores de esta fixture).
fn abrir_cero(candidato: u8, emitir: bool) -> (MotorVotos, Estado, Vec<u8>) {
    let est = estado_con(100);
    let mut m = motor_con_emitir(bls(1), emitir);
    let paso = m.avanzar(0, bh(candidato), &est, SLOT).expect("abrir 0");
    (m, est, paso.votos.into_iter().next().unwrap_or_default())
}

/// Abre 0 y 1; devuelve el motor y el sobre propio de la instancia 1.
fn abrir_uno(candidato0: u8, candidato1: u8, emitir: bool) -> (MotorVotos, Estado, Vec<u8>) {
    let est = estado_con(100);
    let mut m = motor_con_emitir(bls(1), emitir);
    m.avanzar(0, bh(candidato0), &est, SLOT).expect("abrir 0");
    let paso = m.avanzar(1, bh(candidato1), &est, SLOT).expect("abrir 1");
    (m, est, paso.votos.into_iter().next().expect("voto n=1"))
}

fn evidencia_de(receptor: &mut MotorVotos) -> EvidenciaVotosPesoCompleta {
    let mut evs = receptor.drenar_evidencias_peso();
    assert_eq!(evs.len(), 1, "una evidencia pendiente");
    evs.remove(0)
}

/// Comprueba que cada firma verifica exactamente sobre su candidato, su propio `h_t` y su raíz
/// (RET-1b E2/E3) y que el par está en orden canónico.
fn firmas_alineadas(ev: &EvidenciaVotosPesoCompleta) {
    let pk = ClavePublica::desde_bytes(&ev.clave_bls).expect("clave BLS");
    let m1 = mensaje_voto_peso(ev.n, &ev.h1, &ev.h_t1, &ev.raiz1);
    let m2 = mensaje_voto_peso(ev.n, &ev.h2, &ev.h_t2, &ev.raiz2);
    assert!(
        verificar(&pk, &ev.firma1, DOMINIO_VOTO, &m1).is_ok(),
        "firma1 alineada con h1/h_t1"
    );
    assert!(
        verificar(&pk, &ev.firma2, DOMINIO_VOTO, &m2).is_ok(),
        "firma2 alineada con h2/h_t2"
    );
    assert!(
        (ev.h1, ev.h_t1) < (ev.h2, ev.h_t2),
        "(h1, h_t1) < (h2, h_t2) canónico"
    );
}

/// Un voto ajeno válido se reconoce (rechazo `otro_candidato`) y **cierra** la pareja con el
/// voto local, generando una única evidencia con las firmas alineadas.
#[test]
fn voto_ajeno_valido_genera_evidencia_con_el_local() {
    let (mut receptor, _est, _local) = abrir_cero(0x20, true);
    let (_ajeno, _est2, sobre) = abrir_cero(0x21, true);
    match receptor.recibir_voto(&sobre) {
        RecepcionVoto::Rechazado { motivo } => assert_eq!(motivo, "otro_candidato"),
        otro => panic!("se esperaba otro_candidato, llegó {otro:?}"),
    }
    let ev = evidencia_de(&mut receptor);
    assert_eq!(ev.n, 0);
    assert_eq!((ev.h1, ev.h2), (h(0x20), h(0x21)));
    firmas_alineadas(&ev);
    // Drenar de nuevo no repite la evidencia.
    assert!(receptor.drenar_evidencias_peso().is_empty());
}

/// Mismo caso con el orden inverso: primero se registra el voto ajeno (motor en observación) y
/// después llega el local; la evidencia es idéntica.
#[test]
fn evidencia_identica_con_ambos_ordenes() {
    let (_local, _est, sobre_local) = abrir_cero(0x30, true);
    let (_ajeno, _est2, sobre_ajeno) = abrir_cero(0x31, true);

    // Orden ajeno -> local.
    let (mut r1, _e1, _s1) = abrir_cero(0x30, false);
    let _ = r1.recibir_voto(&sobre_ajeno);
    assert!(matches!(
        r1.recibir_voto(&sobre_local),
        RecepcionVoto::Aceptado { .. }
    ));
    let ev1 = evidencia_de(&mut r1);

    // Orden local (automático) -> ajeno.
    let (mut r2, _e2, _s2) = abrir_cero(0x30, true);
    let _ = r2.recibir_voto(&sobre_ajeno);
    let ev2 = evidencia_de(&mut r2);

    assert_eq!(ev1.n, ev2.n);
    assert_eq!((ev1.h1, ev1.h2), (ev2.h1, ev2.h2));
    assert_eq!(ev1.clave_bls, ev2.clave_bls);
    firmas_alineadas(&ev1);
    firmas_alineadas(&ev2);
}

/// Dos candidatos **ajenos** al local forman pareja aunque el motor no emita voto propio (par de
/// candidatos ajenos), en ambos órdenes, y solo una evidencia por `(clave, n)`.
#[test]
fn par_de_candidatos_ajenos_forma_una_evidencia() {
    let (_f1, _est1, s1) = abrir_cero(0x41, true);
    let (_f2, _est2, s2) = abrir_cero(0x42, true);
    let (_f3, _est3, s3) = abrir_cero(0x43, true);
    let (h1, s_h1, h2, s_h2) = if h(0x41) < h(0x42) {
        (h(0x41), s1, h(0x42), s2)
    } else {
        (h(0x42), s2, h(0x41), s1)
    };

    let (mut r, _e, _s) = abrir_cero(0x40, false);
    let _ = r.recibir_voto(&s_h1);
    assert!(
        r.drenar_evidencias_peso().is_empty(),
        "un solo ajeno no basta"
    );
    let _ = r.recibir_voto(&s_h2);
    let ev = evidencia_de(&mut r);
    assert_eq!((ev.h1, ev.h2), (h1, h2));
    firmas_alineadas(&ev);
    // Un tercer candidato distinto no produce una segunda evidencia.
    let _ = r.recibir_voto(&s3);
    assert!(r.drenar_evidencias_peso().is_empty());
    // Un duplicado exacto tampoco.
    let _ = r.recibir_voto(&s_h1);
    assert!(r.drenar_evidencias_peso().is_empty());
}

/// Una firma falsa (o firmada sobre otro `h_T`) no genera evidencia: la verificación real usa el
/// `h_T(n+1)` de la instancia.
#[test]
fn firma_falsa_u_otro_h_t_no_genera_evidencia() {
    let (mut r, _e, _s) = abrir_cero(0x50, false);
    let (_a, _ea, s) = abrir_cero(0x51, true);
    // Firma de otro mensaje con `h_T` distinto (mismo tamaño, punto válido).
    let sk = bls(1);
    let firma_otra = firmar(
        &sk,
        DOMINIO_VOTO,
        &mensaje_voto_peso(0, &h(0x51), &h(0x77), &RAIZ_ESTADO_CERO),
    )
    .expect("firma");
    let mut alterado = s.clone();
    // M9-a2 · el voto por peso ZXV3 mide 252 B: firma BLS en `156..252`.
    alterado[156..252].copy_from_slice(&firma_otra.bytes());
    match r.recibir_voto(&alterado) {
        RecepcionVoto::Rechazado { motivo } => assert_eq!(motivo, "firma_falsa"),
        otro => panic!("se esperaba firma_falsa, llegó {otro:?}"),
    }
    assert!(
        r.drenar_evidencias_peso().is_empty(),
        "sin evidencia por firma falsa"
    );
}

// `ancla_vrf_y_plazas_ajenas_no_generan_evidencia` se **retira** (M9-a2 · lista J, salida (c)):
// el voto por peso ZXV3 no tiene ancla, ni VRF, ni plazas (el formato de 252 B no lleva esos
// campos), así que los motivos `ancla`/`vrf_falso`/`plazas_discrepantes` ya no existen. Su hueco
// negativo lo cubren `firma_falsa_u_otro_h_t_no_genera_evidencia` y
// `clave_no_registrada_no_genera_evidencia`, y el motivo `raiz` de `pd1d_peso`.

/// Una clave no registrada se rechaza por `no_registrada` y no genera evidencia.
#[test]
fn clave_no_registrada_no_genera_evidencia() {
    let (mut r, _e, _s) = abrir_cero(0x70, false);
    let (_a, _ea, sobre_valido) = abrir_cero(0x71, true);
    // Mismo sobre, pero con la clave pública de otra BLS no registrada en la tabla: el índice de
    // la instancia no la conoce y se rechaza **antes** de tocar VRF/firma.
    let mut sobre = sobre_valido.clone();
    // M9-a2 · el voto por peso ZXV3 mide 252 B: clave BLS en `108..156`.
    sobre[108..156].copy_from_slice(&bls(9).clave_publica().bytes());
    assert_eq!(
        r.recibir_voto(&sobre),
        RecepcionVoto::Rechazado {
            motivo: "no_registrada"
        }
    );
    assert!(r.drenar_evidencias_peso().is_empty());
}

/// Un voto de una instancia futura se encola (`ventana`); al abrir esa instancia,
/// `reproducir_pendientes` lo revalida y la evidencia se drena sin que llegue otro voto.
#[test]
fn bufer_futuro_produce_evidencia_al_abrir() {
    let (_a, est, sobre_uno) = abrir_uno(0x80, 0x82, true);
    let (mut r, _e, _s) = abrir_cero(0x80, true);
    assert_eq!(
        r.recibir_voto(&sobre_uno),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
    assert!(r.drenar_evidencias_peso().is_empty());
    // Abrir 1 (con candidato local distinto) reproduce el pendiente y drena la evidencia.
    r.avanzar(1, bh(0x81), &est, SLOT).expect("abrir 1");
    let evs = r.drenar_evidencias_peso();
    assert_eq!(evs.len(), 1, "evidencia tras abrir con el voto adelantado");
    assert_eq!(evs[0].n, 1);
    assert_eq!((evs[0].h1, evs[0].h2), (h(0x81), h(0x82)));
    firmas_alineadas(&evs[0]);
}
