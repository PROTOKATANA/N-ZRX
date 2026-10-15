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

/// Estado con una clave registrada y `n_sectores` activos (fixture de peso real).
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
        let (id, reg) = registro(&p, e, u16::try_from(i).expect("indice"));
        est.sectores.insert(id, reg);
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    (con_cola, sk)
}

fn motor_con(sk: ClaveSecreta) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: true,
    })
}

#[test]
fn diario_reserva_antes_de_firmar_reemite_y_suprime_conflicto() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    let candidato = BlockHash::from_digest(Digest::from_bytes([0x22u8; 32]));
    let (est, sk) = estado_con(100);

    // Primer arranque: reserva y firma.
    let mut motor = motor_con(sk);
    motor.vincular_diario(DiarioVotos::nueva(&ruta, 7).expect("diario"));
    let paso = motor.avanzar(0, candidato, &est, SLOT).expect("abrir");
    assert_eq!(paso.votos.len(), 1, "una firma propia");
    assert!(
        !paso
            .eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::VotoPesoPropio { emitido: false, .. })),
        "sin supresión en la primera reserva"
    );
    // Se cierra el primer motor (y su cerrojo de fichero) antes de reabrir el diario.
    drop(motor);

    // Segundo arranque, mismo directorio y misma clave/n pero `T_{n+1}` distinta: conflicto.
    let (est2, sk2) = estado_con(101);
    let mut motor2 = motor_con(sk2);
    motor2.vincular_diario(DiarioVotos::abrir(&ruta, 7).expect("reabrir"));
    let paso2 = motor2.avanzar(0, candidato, &est2, SLOT).expect("abrir 2");
    assert!(
        paso2.votos.is_empty(),
        "mensaje distinto para la misma (clave, n) no se firma"
    );
    assert!(
        paso2.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VotoPesoPropio {
                emitido: false,
                motivo: "conflicto_diario",
                ..
            }
        )),
        "se observa la supresión"
    );
    drop(motor2);

    // Tercer arranque con el mensaje **idéntico** al primero: reemisión exacta.
    let mut motor3 = motor_con(bls(1));
    motor3.vincular_diario(DiarioVotos::abrir(&ruta, 7).expect("reabrir 2"));
    let paso3 = motor3.avanzar(0, candidato, &est, SLOT).expect("abrir 3");
    assert_eq!(paso3.votos.len(), 1, "la reemisión exacta se permite");
    assert!(
        !paso3
            .eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::VotoPesoPropio { emitido: false, .. })),
        "la reemisión exacta no se suprime"
    );
}

#[test]
fn observacion_no_firma_ni_reserva() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    let (est, sk) = estado_con(100);
    let candidato = BlockHash::from_digest(Digest::from_bytes([0x22u8; 32]));
    let mut motor = motor_con(sk);
    motor.poner_en_observacion();
    let paso = motor.avanzar(0, candidato, &est, SLOT).expect("abrir");
    assert!(paso.votos.is_empty(), "en observación no hay voto propio");
    // No se creó diario: el nodo observador no abre uno limpio.
    assert!(!ruta.exists(), "el motor sin diario no crea fichero");
}

/// FV-N6-C7-2 · fallo de `sync` por el **camino real** motor→diario→firma: cero voto, sin
/// rehabilitación hasta una reapertura validada; entonces la reemisión exacta se permite.
#[test]
fn fallo_sync_motor_diario_firma_cero_voto_hasta_reabrir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    let candidato = BlockHash::from_digest(Digest::from_bytes([0x22u8; 32]));
    let (est, sk) = estado_con(100);
    let mut motor = motor_con(sk);
    let diario = DiarioVotos::nueva(&ruta, 7).expect("diario");
    diario.fallar_proximo_sync_para_test();
    motor.vincular_diario(diario);
    let paso = motor.avanzar(0, candidato, &est, SLOT).expect("abrir");
    assert!(paso.votos.is_empty(), "diario en duda ⇒ cero voto");
    assert!(
        paso.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VotoPesoPropio {
                emitido: false,
                motivo: "diario_en_duda",
                ..
            }
        )),
        "se observa la supresión por duda"
    );
    // Sin reabrir, la ventana siguiente tampoco firma: el diario sigue envenenado.
    let paso1 = motor.avanzar(1, candidato, &est, SLOT).expect("abrir 1");
    assert!(paso1.votos.is_empty(), "envenenado ⇒ sigue sin firma");
    drop(motor);
    // Reapertura validada: la reserva original se acredita y la reemisión exacta se permite.
    let mut motor2 = motor_con(bls(1));
    motor2.vincular_diario(DiarioVotos::abrir(&ruta, 7).expect("reabrir"));
    let paso2 = motor2.avanzar(0, candidato, &est, SLOT).expect("abrir 2");
    assert_eq!(
        paso2.votos.len(),
        1,
        "la reapertura validada rehabilita la reemisión exacta"
    );
}

/// FV-N6-C7-2 · tres ventanas sucesivas por el motor: al avanzar a `n+1` se cierra `n`
/// (adoptando su certificado con quórum real de una clave con todo el peso) y **después** se
/// abre `n+1`; el cierre no se pierde. Es la conducta que el guard de arranque de Nodo no debe
/// bloquear en vivo.
#[test]
fn tres_ventanas_cierran_antes_de_abrir_la_siguiente() {
    let (est, sk) = estado_con(100);
    let mut motor = motor_con(sk);
    let c0 = BlockHash::from_digest(Digest::from_bytes([0x10u8; 32]));
    let c1 = BlockHash::from_digest(Digest::from_bytes([0x11u8; 32]));
    let c2 = BlockHash::from_digest(Digest::from_bytes([0x12u8; 32]));

    let p0 = motor.avanzar(0, c0, &est, SLOT).expect("abrir 0");
    assert_eq!(motor.instancia_actual(), Some(0));
    assert_eq!(p0.votos.len(), 1, "voto propio de la ventana 0");

    let p1 = motor.avanzar(1, c1, &est, SLOT).expect("abrir 1");
    assert_eq!(motor.instancia_actual(), Some(1));
    assert!(
        p1.certificado_peso.is_some(),
        "C_0 se adopta al cerrar la ventana 0"
    );
    assert!(
        p1.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VentanaCerrada {
                n: 0,
                certificado: true,
                ..
            }
        )),
        "cierre observado con certificado"
    );
    assert!(
        p1.eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::VentanaAbierta { n: 1, .. })),
        "apertura observada de la ventana 1"
    );

    let p2 = motor.avanzar(2, c2, &est, SLOT).expect("abrir 2");
    assert_eq!(motor.instancia_actual(), Some(2));
    assert!(
        p2.certificado_peso.is_some(),
        "C_1 se adopta al cerrar la ventana 1"
    );
    assert!(
        p2.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VentanaCerrada {
                n: 1,
                certificado: true,
                ..
            }
        )),
        "cierre observado de la ventana 1"
    );
}

// FV-N6-C7-3 · las tres pruebas del **sorteo** (`sorteo_independiente_de_emision_misma_tirada_y_plazas`,
// `plazas_cero_se_observan_sin_emitir`, `cero_de_sorteo_k_local_peso_positivo_con_q_estricta`) y sus
// ayudantes `motor_con_opciones`/`sorteo_de` se **retiran** (lista B): el sorteo ya no existe en el
// modo por peso. En su lugar, `pd1d_peso` cubre la emisión/observación por peso.

/// FV-N6-C7-3 · corrección 1: una clave propia fuera de la tabla se declara explícitamente; no
/// se construye un voto sintético ni se silencia.
#[test]
fn clave_fuera_de_tabla_se_declara_no_elegible() {
    let (est, _sk) = estado_con(100);
    let candidato = BlockHash::from_digest(Digest::from_bytes([0x44u8; 32]));
    let mut motor = motor_con(bls(9));
    let paso = motor.avanzar(0, candidato, &est, SLOT).expect("abrir");
    assert!(paso.votos.is_empty());
    assert!(
        paso.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VotoPesoPropio {
                peso: 0,
                emitido: false,
                motivo: "fuera_de_tabla",
                ..
            }
        )),
        "la clave fuera de tabla se declara: {:?}",
        paso.eventos
    );
}

/// FV-N6-C7-3 · corrección 1 (M9-a2 · lista J): la supresión por conflicto de diario observa el
/// motivo **sin** perder el peso real de la clave en la tabla.
#[test]
fn supresion_por_diario_conserva_plazas_reales() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    let (est, _sk) = estado_con(100);
    let candidato = BlockHash::from_digest(Digest::from_bytes([0x55u8; 32]));
    let n = 0u64;
    let clave_bls = bls(1).clave_publica().bytes();
    let diario = DiarioVotos::nueva(&ruta, 7).expect("diario");
    assert_eq!(
        diario
            .resolver(&clave_bls, n, &[0u8; 32])
            .expect("reserva previa"),
        ResolucionDiario::Nueva
    );
    let mut motor = motor_con(bls(1));
    motor.vincular_diario(diario);
    let paso = motor
        .avanzar(n, candidato, &est, SLOT)
        .expect("abrir con conflicto");
    assert!(paso.votos.is_empty());
    let mut visto = None;
    for e in &paso.eventos {
        if let EventoMotor::VotoPesoPropio {
            peso,
            emitido,
            motivo,
            ..
        } = e
            && *motivo == "conflicto_diario"
        {
            visto = Some((*peso, *emitido));
        }
    }
    assert_eq!(
        visto,
        Some((visto.expect("evento de conflicto").0, false)),
        "el conflicto conserva el peso real y no firma"
    );
    assert!(
        visto.expect("evento de conflicto").0 > 0,
        "las plazas/peso reales no se pierden por el conflicto"
    );
}

/// FV-N6-C7-3 · corrección 7: un salto de reloj no puede reutilizar la tabla comprometida de la
/// ventana cerrada renumerándola. El cierre ya obtenido (`C_{m+1}`) no se pierde; la apertura se
/// difiere y el sucesor exacto sí abre después.
#[test]
fn salto_de_reloj_no_reutiliza_tabla_renombrada() {
    let (est, sk) = estado_con(100);
    let c0 = BlockHash::from_digest(Digest::from_bytes([0x10u8; 32]));
    let c1 = BlockHash::from_digest(Digest::from_bytes([0x11u8; 32]));
    let c3 = BlockHash::from_digest(Digest::from_bytes([0x13u8; 32]));
    let mut motor = motor_con(sk);
    motor.avanzar(0, c0, &est, SLOT).expect("abrir 0");
    let p1 = motor.avanzar(1, c1, &est, SLOT).expect("abrir 1");
    assert!(p1.certificado_peso.is_some(), "C_0 adoptado al cerrar 0");
    let p3 = motor.avanzar(3, c3, &est, SLOT).expect("salto observado");
    assert!(
        p3.certificado_peso.is_some(),
        "el cierre de la ventana 1 no se pierde"
    );
    assert!(p3.eventos.iter().any(|e| matches!(
        e,
        EventoMotor::AperturaDiferida {
            n: 3,
            motivo: "salto_tabla_no_sucesora"
        }
    )));
    assert!(
        !p3.eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::VentanaAbierta { n: 3, .. }))
    );
    assert!(!p3.eventos.iter().any(|e| matches!(
        e,
        EventoMotor::VotoPesoPropio {
            n: 3,
            emitido: true,
            ..
        }
    )));
    assert_eq!(motor.instancia_actual(), None);
    assert_eq!(motor.ultimo_certificado_peso().map(|c| c.n), Some(1));
    // El sucesor exacto (n = 2) sí abre con la tabla que dejó el cierre.
    motor.avanzar(2, c1, &est, SLOT).expect("abrir 2");
    assert_eq!(motor.instancia_actual(), Some(2));
}

/// FV-N6-C7-4 · el control de reserva usa el **mensaje productivo**: mismo `n`, misma clave y
/// mismo candidato, distinto `h_T(n+1)` ⇒ digests distintos ⇒ conflicto durable y ninguna
/// firma contradictoria. No son digests arbitrarios del análogo SIGKILL.
#[test]
fn reserva_conflicto_por_mismo_n_y_candidato_distinto_h_t() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    let clave_bls = bls(1).clave_publica().bytes();
    let candidato = *BlockHash::from_digest(Digest::from_bytes([0x77u8; 32])).as_bytes();
    let h_t_a = [0xAAu8; 32];
    let h_t_b = [0xBBu8; 32];
    let mensaje_a = mensaje_voto_peso(3, &candidato, &h_t_a, &RAIZ_ESTADO_CERO);
    let mensaje_b = mensaje_voto_peso(3, &candidato, &h_t_b, &RAIZ_ESTADO_CERO);
    assert_ne!(
        mensaje_a, mensaje_b,
        "el h_T(n+1) entra en el digest productivo"
    );

    let diario = DiarioVotos::nueva(&ruta, 7).expect("diario");
    assert_eq!(
        diario.resolver(&clave_bls, 3, &mensaje_a).expect("reserva"),
        ResolucionDiario::Nueva
    );
    assert_eq!(
        diario
            .resolver(&clave_bls, 3, &mensaje_b)
            .expect("conflicto"),
        ResolucionDiario::Conflicto {
            registrado: mensaje_a
        },
        "otro digest para el mismo (CBID, clave, n) es conflicto durable"
    );
}

/// Estado con dos claves: la propia pesa 1 y una ajena pesa 1000, de modo que la propia no
/// alcanza el quórum `U = ceil(2K/3)` por sí sola (probabilidad de lograrlo ínfima).
fn estado_desigual() -> (Estado, ClaveSecreta) {
    let (mut est, sk) = estado_con(1);
    let p = ParametrosSector::dev();
    let sk2 = bls(2);
    let pk2 = sk2.clave_publica();
    let e2 = ed(2);
    est.claves_voto.insert(
        e2,
        ClaveVoto {
            clave_bls: pk2.bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    for i in 0..1000u16 {
        let (id, reg) = registro(&p, e2, i);
        est.sectores.insert(id, reg);
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e2, g);
    (est, sk)
}

/// FV-N6-C7-4 / REAN-2 · la memoria de primera apertura efectiva es **monotónica**. Tras abrir
/// una ventana y diferir la apertura siguiente (base aplicada cuyo hash no casa con ninguna
/// tabla, dejando `instancia = None` y `certificados` vacío), ni la resiembra ni una carga nueva
/// se aceptan. Antes de abrir, la misma llamada falla validando la carga, no por motor abierto.
#[test]
fn apertura_efectiva_monotonica_bloquea_resiembra_tras_cerrar_sin_quorum() {
    let (mut est, sk) = estado_desigual();
    let c0 = BlockHash::from_digest(Digest::from_bytes([0x10u8; 32]));
    let c1 = BlockHash::from_digest(Digest::from_bytes([0x11u8; 32]));
    let firma_relleno = firmar(&bls(9), DOMINIO_VOTO, &[0u8; 32]).expect("firma de relleno");
    // M9-a2 · el certificado del modo por peso es compacto (mapa + firma agregada).
    let dummy = CertificadoPeso {
        n: 0,
        candidato: [0u8; 32],
        h_t_siguiente: [0u8; 32],
        raiz_estado: [0u8; 32],
        firma: zx_votos::FirmaAgregada::desde_firma(&firma_relleno),
        mapa: Vec::new(),
    };
    let tabla_vacia = Tabla {
        n: 0,
        claves: Vec::new(),
    };

    let mut motor = motor_con(sk);
    // Antes de abrir: no hay memoria de apertura; el rechazo es de validación de la carga.
    let err_antes = motor
        .sembrar_punto_control_peso(tabla_vacia.clone(), Vec::new(), dummy.clone(), &[])
        .expect_err("una carga vacía no re-siembra");
    assert!(
        !matches!(&err_antes, ErrorVotos::CargaInicialInvalida { motivo } if *motivo == "motor_ya_abierto"),
        "antes de abrir no hay memoria de apertura: el rechazo es de validación: {err_antes:?}"
    );

    // Abre 0 con un estado limpio; después la finalidad aplicada trae un hash que ninguna
    // tabla casa, de modo que la apertura de 1 se difiere sin firmar.
    motor.avanzar(0, c0, &est, SLOT).expect("abrir 0");
    est.finalidad_votos_n = 0;
    est.finalidad_votos = Some(c0);
    est.finalidad_votos_h_t = Some([0xEEu8; 32]);
    let p1 = motor.avanzar(1, c1, &est, SLOT).expect("apertura diferida");
    assert!(p1.eventos.iter().any(|e| matches!(
        e,
        EventoMotor::AperturaDiferida {
            n: 1,
            motivo: "tabla_base_no_hallada"
        }
    )));
    assert_eq!(motor.instancia_actual(), None);
    assert!(
        motor.certificados_peso().is_empty(),
        "sin certificado local"
    );
    assert!(
        motor.apertura_efectiva_para_test(),
        "la apertura dejó memoria"
    );

    // Con la memoria fijada, la resiembra se rechaza por motor abierto, no por la carga.
    let err = motor
        .sembrar_punto_control_peso(tabla_vacia, Vec::new(), dummy, &[])
        .expect_err("un motor que ya abrió no se re-siembra");
    assert!(
        matches!(
            err,
            ErrorVotos::CargaInicialInvalida {
                motivo: "motor_ya_abierto"
            }
        ),
        "el rechazo es por memoria de apertura: {err:?}"
    );
}
