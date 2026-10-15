//! PD-1d · pruebas del **modo por peso** del motor de votos (M1–M14, T1–T12).
//!
//! Cada prueba construye el estado y las claves con sectores reales (para que `construir_tabla`
//! derive pesos) y aplica las salidas del motor con las funciones `*_con_undo` de `zx-consensus`.
//! Las firmas BLS son reales.
//!
//! T11 (modo sorteo intacto) es el conjunto de pruebas de hoy del motor, que se ejecuta sin cambios;
//! aquí no se duplica.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use primitive_types::U256;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{
    W_REVEAL_SLOTS_VOTOS, aplicar_acta_presencia_con_undo, aplicar_certificado_peso_con_undo,
    aplicar_evidencia_votos_peso_con_undo, aplicar_voto_propio_con_undo, cierre_ventana,
};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, ErrorVotos, Firma, Tabla, hash_tabla};

use super::{
    ConfigMotorVotos, DiarioVotos, EventoMotor, MotorVotos, RAIZ_ESTADO_CERO, RecepcionVoto,
    deserializar_punto_control_peso, deserializar_voto_peso, serial_certificado_peso,
    serializar_punto_control_peso, serializar_voto_peso, tx_evidencia_votos_peso,
    voto_propio_de_peso,
};

const CBID: u32 = 0;
const DEN: i64 = 1_401_600_000;
const SLOT: i64 = 100;

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Utilidades
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

fn cand(n: u8) -> BlockHash {
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
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de `cola_tablas_voto`: el
    // montaje deja una derivada de producto para que el motor real pueda votar.
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

fn core_tabla(tabla: &Tabla) -> Vec<ClaveTablaVoto> {
    tabla
        .claves
        .iter()
        .map(|c| {
            let mut clave_bls = [0u8; 48];
            clave_bls.copy_from_slice(&c.clave);
            ClaveTablaVoto {
                clave_bls,
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            }
        })
        .collect()
}

fn op_cert(cert: &super::CertificadoPeso) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: serial_certificado_peso(cert),
    }
}

/// Voto por peso firmado por `sk` (A3) con candidato `c` y `h_t` dados.
fn voto_manual(
    sk: &ClaveSecreta,
    n: u64,
    c: [u8; 32],
    h_t: [u8; 32],
) -> Result<super::VotoPeso, Error> {
    let firma: Firma = zx_votos::firmar(
        sk,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &c, &h_t, &RAIZ_ESTADO_CERO),
    )?;
    Ok(super::VotoPeso {
        n,
        candidato: c,
        h_t_siguiente: h_t,
        raiz_estado: RAIZ_ESTADO_CERO,
        clave: sk.clave_publica().bytes(),
        firma,
    })
}

/// Aplica un bloque PoST vacío (dispara la liquidación).
fn aplica_post(est: &Estado, slot: u64) -> Result<Estado, Error> {
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
    let (nuevo, _) = aplicar_con_undo(
        est,
        &bloque,
        &params(),
        CBID,
        &ParametrosEvidencia::inactiva(),
    )?;
    Ok(nuevo)
}

fn deuda(est: &Estado, i: u8) -> i128 {
    est.deuda_ausencia.get(&ed(i)).copied().unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T1 · la pregunta (1): primera ventana y siguiente, sin 0x04/0x05/0x06/0x07
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t1_pregunta_1_sella_y_encadena() -> Result<(), Error> {
    let (estado, secretas) =
        estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    assert!(estado.finalidad_votos_n == 0 && estado.finalidad_votos_h_t.is_none());
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let paso2 = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert1 = paso2
        .certificado_peso
        .clone()
        .expect("certificado ventana 1");
    assert_eq!(cert1.n, 1);
    let (est1, _, r) = aplicar_certificado_peso_con_undo(&estado, &op_cert(&cert1), SLOT);
    r?;
    assert_eq!(est1.finalidad_votos_n, 1, "(1) la primera ventana sella");

    let paso3 = motor.avanzar(3, cand(0x33), &estado, SLOT)?;
    let cert2 = paso3
        .certificado_peso
        .clone()
        .expect("certificado ventana 2");
    assert_eq!(cert2.n, 2);
    let (est2, _, r) = aplicar_certificado_peso_con_undo(&est1, &op_cert(&cert2), SLOT);
    r?;
    assert_eq!(
        est2.finalidad_votos_n, 2,
        "(1) la ventana siguiente encadena"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T2 · la pregunta (2): quórum exacto, acta y cobro solo al ausente
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t2_quorum_exacto_y_acta() -> Result<(), Error> {
    // W = 3 (una unidad por clave). Quórum = 2.
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    // Solo votan las claves 1 y 2: quórum exacto.
    let votantes: Vec<u8> = secretas.iter().copied().filter(|i| *i != 3).collect();
    let mut motor = motor_peso(&votantes, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let paso2 = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert = paso2
        .certificado_peso
        .clone()
        .expect("quórum exacto da certificado");
    let (est1, _, r) = aplicar_certificado_peso_con_undo(&estado, &op_cert(&cert), SLOT);
    r?;
    assert_eq!(est1.finalidad_votos_n, 1);

    // Con una unidad de peso menos (solo la clave 1) en la **ventana 2** (con base ya fijada) no hay
    // certificado, pero sí acta. El motor nuevo se siembra con el certificado de la ventana 1.
    let tabla1 = Tabla {
        n: cert.n,
        claves: motor.tabla_actual().expect("tabla").claves.clone(),
    };
    let pubs1 = super::claves_publicas_de_tabla(&tabla1)?;
    let mut motor2 = motor_peso(&[1], true)?;
    motor2.sembrar_punto_control_peso(tabla1, pubs1, cert.clone(), &[])?;
    let _ = motor2.avanzar(2, cand(0x22), &est1, SLOT)?;
    let paso3 = motor2.avanzar(3, cand(0x33), &est1, SLOT)?;
    assert!(
        paso3.certificado_peso.is_none(),
        "una unidad menos no da certificado"
    );
    let acta = paso3.acta_peso.clone().expect("una unidad menos da acta");
    let op_acta = OperacionAlmacenamiento::ActaPresencia {
        clave: ed(200),
        bytes: serial_certificado_peso(&acta),
    };
    let (con_acta, _, r) = aplicar_acta_presencia_con_undo(&est1, &op_acta, SLOT);
    r?;
    assert!(
        con_acta.votantes_voto[&2].contains(&ed(1)),
        "el acta acredita a su firmante"
    );

    // Liquidación: solo la clave 3 (ausente) paga en la ventana 1.
    let fin = aplica_post(&est1, cierre_ventana(1) + W_REVEAL_SLOTS_VOTOS + 1)?;
    assert_eq!(deuda(&fin, 1), 0, "la clave 1 votó");
    assert_eq!(deuda(&fin, 2), 0, "la clave 2 votó");
    assert!(
        deuda(&fin, 3) > 0 || fin.activo_de(&ed(3)) < est1.activo_de(&ed(3)),
        "la clave 3 no votó: paga o acumula deuda"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T3 · M2: orden por BLS distinto del de Ed25519; el consenso acepta
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t3_tabla_en_orden_canonico() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[
        (1, 1, DEN),
        (2, 1, DEN),
        (3, 1, DEN),
        (4, 1, DEN),
        (5, 1, DEN),
        (6, 1, DEN),
    ])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let tabla = motor.tabla_actual().expect("tabla abierta").clone();
    assert!(
        tabla.claves.windows(2).all(|w| w[0].clave <= w[1].clave),
        "la tabla va en orden canónico por bytes de BLS"
    );
    // El orden por Ed25519 (índices 1..6 ascendentes) difiere del orden por BLS en este conjunto.
    let indice_ed: Vec<u8> = tabla
        .claves
        .iter()
        .map(|c| {
            (1u8..=6)
                .find(|i| {
                    bls(*i)
                        .map(|s| s.clave_publica().bytes().to_vec())
                        .expect("clave")
                        == c.clave
                })
                .expect("clave conocida")
        })
        .collect();
    assert!(
        !indice_ed.windows(2).all(|w| w[0] < w[1]),
        "los órdenes por Ed25519 y por BLS difieren: {indice_ed:?}"
    );

    let paso2 = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert = paso2.certificado_peso.clone().expect("certificado");
    let (est1, _, r) = aplicar_certificado_peso_con_undo(&estado, &op_cert(&cert), SLOT);
    r?;
    assert_eq!(
        est1.finalidad_votos_n, 1,
        "el consenso acepta el mapa canónico"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T4 · M8: certificado remontado contra otra tabla
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t4_certificado_para_otra_tabla() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[
        (1, 1, DEN),
        (2, 1, DEN),
        (3, 1, DEN),
        (4, 1, DEN),
        (5, 1, DEN),
        (6, 1, DEN),
    ])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let paso2 = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert1 = paso2.certificado_peso.clone().expect("certificado 1");
    let (est1, _, r) = aplicar_certificado_peso_con_undo(&estado, &op_cert(&cert1), SLOT);
    r?;
    let paso3 = motor.avanzar(3, cand(0x33), &estado, SLOT)?;
    assert!(paso3.certificado_peso.is_some(), "la ventana 2 certifica");

    // Tabla del bloque: la vigente de la ventana 2 con la clave 7 añadida y la 6 (firmante) fuera.
    let mut t_prima = motor.tabla_actual().expect("tabla abierta").clone();
    let clave6 = bls(6)?.clave_publica().bytes().to_vec();
    t_prima.claves.retain(|c| c.clave != clave6);
    t_prima.claves.push(Clave {
        clave: bls(7)?.clave_publica().bytes().to_vec(),
        peso: 1,
        activo: true,
        prueba: false,
        garantia: 1,
    });
    t_prima.claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    let remontado = motor
        .certificado_para_tabla(&t_prima)?
        .expect("hay quórum con la tabla del bloque");

    // El consenso lo acepta con esa tabla como vigente.
    let h_prima = hash_tabla(&t_prima);
    let mut est_rem = est1.clone();
    est_rem.finalidad_votos_h_t = Some(h_prima);
    est_rem
        .tablas_voto_contenido
        .insert(h_prima, core_tabla(&t_prima));
    let op = op_cert(&remontado);
    let (sellado, _, r) = aplicar_certificado_peso_con_undo(&est_rem, &op, SLOT);
    r?;
    assert_eq!(
        sellado.finalidad_votos_n, 2,
        "el consenso acepta el remontado"
    );

    // Sin quórum no se devuelve nada: la tabla del bloque añade diez claves nuevas.
    let mut t_sin = t_prima.clone();
    for i in 20..30 {
        t_sin.claves.push(Clave {
            clave: bls(i)?.clave_publica().bytes().to_vec(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        });
    }
    t_sin.claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    assert!(
        motor.certificado_para_tabla(&t_sin)?.is_none(),
        "sin quórum no se devuelve nada"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T5 · M5: motivos de rechazo en su orden; formatos cruzados
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t5_motivos_de_rechazo() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let h_t = motor.tabla_actual().map(hash_tabla).unwrap_or([0u8; 32]);
    let sk1 = bls(secretas[0])?;

    // `formato`: un sobre de hoy (ZXV2) no es un voto por peso.
    let viejo = [b"ZXV2".as_slice(), &[0u8; 64]].concat();
    assert_eq!(
        motor.recibir_voto(&viejo),
        RecepcionVoto::Rechazado { motivo: "formato" }
    );

    // `no_registrada`: voto válido de una clave que no está en la tabla.
    let ajena = bls(9)?;
    let v_ajeno = voto_manual(&ajena, 1, [0x11u8; 32], h_t)?;
    assert_eq!(
        motor.recibir_voto(&serializar_voto_peso(&v_ajeno)),
        RecepcionVoto::Rechazado {
            motivo: "no_registrada"
        }
    );

    // `retirada`: la clave está en la tabla pero inactiva.
    if let Some(inst) = motor.instancia.as_mut()
        && let Some(registro) = inst
            .tabla
            .claves
            .iter_mut()
            .find(|c| c.clave == sk1.clave_publica().bytes().to_vec())
    {
        registro.activo = false;
    }
    let v_ok = voto_manual(&sk1, 1, [0x11u8; 32], h_t)?;
    assert_eq!(
        motor.recibir_voto(&serializar_voto_peso(&v_ok)),
        RecepcionVoto::Rechazado { motivo: "retirada" }
    );
    // `sin_peso`: activa pero peso 0.
    if let Some(inst) = motor.instancia.as_mut()
        && let Some(registro) = inst
            .tabla
            .claves
            .iter_mut()
            .find(|c| c.clave == sk1.clave_publica().bytes().to_vec())
    {
        registro.activo = true;
        registro.peso = 0;
    }
    assert_eq!(
        motor.recibir_voto(&serializar_voto_peso(&v_ok)),
        RecepcionVoto::Rechazado { motivo: "sin_peso" }
    );
    // Restaura el peso.
    if let Some(inst) = motor.instancia.as_mut()
        && let Some(registro) = inst
            .tabla
            .claves
            .iter_mut()
            .find(|c| c.clave == sk1.clave_publica().bytes().to_vec())
    {
        registro.peso = 1;
    }

    // M3 · raíz distinta de 32 ceros: ya **no** es un rechazo. El voto es válido y se acepta; la
    // clave 1 no había votado todavía (los intentos anteriores se rechazaron antes de agrupar), así
    // que entra en el grupo de su raíz.
    let firma = zx_votos::firmar(
        &sk1,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(1, &[0x11; 32], &h_t, &[0x77; 32]),
    )?;
    let v_raiz = super::VotoPeso {
        n: 1,
        candidato: [0x11; 32],
        h_t_siguiente: h_t,
        raiz_estado: [0x77; 32],
        clave: sk1.clave_publica().bytes(),
        firma,
    };
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v_raiz)),
        RecepcionVoto::Aceptado { .. }
    ));

    // `firma_falsa`: firma válida sobre otro mensaje.
    let mut v_falsa = v_ok;
    v_falsa.candidato = [0x55; 32];
    assert_eq!(
        motor.recibir_voto(&serializar_voto_peso(&v_falsa)),
        RecepcionVoto::Rechazado {
            motivo: "firma_falsa"
        }
    );

    // `otro_candidato`: firma A3 válida con otro candidato; se guarda para evidencia.
    let v_otro = voto_manual(&sk1, 1, [0x99u8; 32], h_t)?;
    assert_eq!(
        motor.recibir_voto(&serializar_voto_peso(&v_otro)),
        RecepcionVoto::Rechazado {
            motivo: "otro_candidato"
        }
    );

    // Voto propio correcto: aceptado; repetido: idempotente.
    let v_ok = voto_manual(&sk1, 1, [0x11u8; 32], h_t)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v_ok)),
        RecepcionVoto::Aceptado { .. }
    ));
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v_ok)),
        RecepcionVoto::Aceptado { .. }
    ));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T6 · M3: reserva antes de firmar, reemisión idempotente y claves fuera de tabla
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t6_reserva_y_reemision() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let dir = tempfile::tempdir()?;
    let ruta = dir.path().join("votos.registro");
    let mut motor = motor_peso(&[1], true)?;
    motor.vincular_diario(DiarioVotos::nueva(&ruta, 7)?);
    let paso = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    assert_eq!(paso.votos.len(), 1, "reserva y firma");
    drop(motor);

    // Reemisión exacta permitida.
    let mut motor2 = motor_peso(&[1], true)?;
    motor2.vincular_diario(DiarioVotos::abrir(&ruta, 7)?);
    let paso2 = motor2.avanzar(1, cand(0x11), &estado, SLOT)?;
    assert_eq!(paso2.votos.len(), 1, "la reemisión exacta se permite");
    assert!(
        !paso2
            .eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::VotoSuprimido { .. })),
        "la reemisión exacta no se suprime"
    );
    drop(motor2);

    // Conflicto: mismo `(clave, n)` con otro mensaje (otra tabla) → suprimido.
    let (estado_b, _) = estado_sectores(&[(1, 1, DEN), (2, 2, DEN), (3, 1, DEN)])?;
    let mut motor3 = motor_peso(&[1], true)?;
    motor3.vincular_diario(DiarioVotos::abrir(&ruta, 7)?);
    let paso3 = motor3.avanzar(1, cand(0x11), &estado_b, SLOT)?;
    assert!(paso3.votos.is_empty(), "el conflicto de diario no firma");
    assert!(
        paso3
            .eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::VotoSuprimido { .. })),
        "se observa la supresión"
    );
    drop(motor3);

    // Clave fuera de tabla: no vota ni se suprime.
    let mut motor4 = motor_peso(&[1, 9], true)?;
    let paso4 = motor4.avanzar(1, cand(0x11), &estado, SLOT)?;
    assert_eq!(paso4.votos.len(), 1, "solo vota la clave en tabla");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T7 · la pregunta (3) y M10: dos votos contradictorios → evidencia → el consenso castiga
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t7_evidencia_doble_voto_peso() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, 50)])?;
    let sk1 = bls(secretas[0])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let h_t = motor.tabla_actual().map(hash_tabla).unwrap_or([0u8; 32]);
    let v_ok = voto_manual(&sk1, 1, [0x11u8; 32], h_t)?;
    let v_otro = voto_manual(&sk1, 1, [0x22u8; 32], h_t)?;
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v_ok)),
        RecepcionVoto::Aceptado { .. }
    ));
    assert!(matches!(
        motor.recibir_voto(&serializar_voto_peso(&v_otro)),
        RecepcionVoto::Rechazado { .. }
    ));
    let evidencias = motor.drenar_evidencias_peso();
    assert_eq!(evidencias.len(), 1, "se forma la evidencia");
    let ev = evidencias[0].clone();
    // Ejercita el constructor de la tx `0x0B` (M11).
    let (_tx, _tst) = tx_evidencia_votos_peso(
        &ev,
        ed(200),
        &ed25519_zebra::SigningKey::from([7u8; 32]),
        CBID,
    );
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
            n: ev.n,
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
    assert!(
        castigado.garantias[&ed(1)].incidentes.len() == 1,
        "el consenso castiga el doble voto"
    );
    assert!(castigado.quemado > estado.quemado, "confisca y quema");

    // Votos idénticos no generan evidencia.
    let mut motor2 = motor_peso(&secretas, true)?;
    let _ = motor2.avanzar(1, cand(0x11), &estado, SLOT)?;
    let h_t2 = motor2.tabla_actual().map(hash_tabla).unwrap_or([0u8; 32]);
    let a = voto_manual(&sk1, 1, [0x11u8; 32], h_t2)?;
    let _ = motor2.recibir_voto(&serializar_voto_peso(&a));
    let _ = motor2.recibir_voto(&serializar_voto_peso(&a));
    assert!(
        motor2.drenar_evidencias_peso().is_empty(),
        "votos idénticos no generan evidencia"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T8 · M9: el 0x08 del modo peso (A3) lo acepta el consenso
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t8_voto_propio_a3() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    let paso = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let sobre = paso.votos.first().expect("voto propio").clone();
    let voto = deserializar_voto_peso(&sobre)?;
    let payload = voto_propio_de_peso(&voto);
    let op = OperacionAlmacenamiento::VotoPropio {
        clave: ed(1),
        n: payload.n,
        candidato: payload.candidato,
        h_t_siguiente: payload.h_t_siguiente,
        raiz_estado: payload.raiz_estado,
        clave_bls: payload.clave_bls,
        firma: payload.firma,
    };
    let (con_voto, _, r) = aplicar_voto_propio_con_undo(&estado, &op, SLOT);
    r?;
    assert!(
        con_voto.votantes_voto[&1].contains(&ed(1)),
        "el consenso acepta el 0x08 sobre A3"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T9 · cambio de tabla: el certificado lleva la siguiente y la ventana siguiente la usa
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t9_cambio_de_tabla() -> Result<(), Error> {
    let (estado1, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    // Estado con una clave más: la tabla de la ventana 2 cambia.
    let (mut estado2, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    // TB-1b · N1: la huella siguiente ya no la construye el nodo; el estado la trae derivada en su
    // cola `Q`. Aquí se prepara a mano como la dejaría el consenso tras aplicar el certificado de la
    // base (contenido canónico en `tablas_voto_contenido`).
    let (mut t_base, _) = super::construir_tabla(1, &estado1, SLOT)?;
    let (mut t_der, _) = super::construir_tabla(2, &estado2, SLOT)?;
    t_base.claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    t_der.claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    let h_base = hash_tabla(&t_base);
    let h_der = hash_tabla(&t_der);
    assert_ne!(h_base, h_der, "el cambio de peso cambia la huella");
    estado2.finalidad_votos = Some(cand(0x01));
    estado2.finalidad_votos_n = 1;
    estado2.finalidad_votos_h_t = Some(h_base);
    estado2
        .tablas_voto_contenido
        .insert(h_base, core_tabla(&t_base));
    estado2
        .tablas_voto_contenido
        .insert(h_der, core_tabla(&t_der));
    estado2.cola_tablas_voto.push((1, h_base));
    estado2.cola_tablas_voto.push((1, h_der));

    let mut motor = motor_peso(&secretas, true)?;
    motor.sembrar_base_de_estado(1, h_base, *cand(0x01).as_bytes())?;
    // La ventana 2 se abre con el estado que ya derivó el cambio de tabla.
    let _ = motor.avanzar(2, cand(0x22), &estado2, SLOT)?;
    let paso3 = motor.avanzar(3, cand(0x33), &estado2, SLOT)?;
    let cert2 = paso3.certificado_peso.clone().expect("ventana 2 certifica");
    // TB-1c · T2/T3: el certificado no lleva tabla; declara la huella derivada que el consenso
    // exige que esté en la cola.
    assert_eq!(
        cert2.h_t_siguiente, h_der,
        "la huella declarada es la derivada de la ventana"
    );
    let (est2, _, r) = aplicar_certificado_peso_con_undo(&estado2, &op_cert(&cert2), SLOT);
    r?;
    assert_eq!(est2.finalidad_votos_n, 2);
    let h3 = cert2.h_t_siguiente;
    assert!(
        est2.tablas_voto_contenido.contains_key(&h3),
        "el consenso adopta la tabla siguiente"
    );

    // La ventana 3 se certifica con la tabla siguiente adoptada.
    let paso4 = motor.avanzar(4, cand(0x44), &estado2, SLOT)?;
    let cert3 = paso4.certificado_peso.clone().expect("ventana 3 certifica");
    let (est3, _, r) = aplicar_certificado_peso_con_undo(&est2, &op_cert(&cert3), SLOT);
    r?;
    assert_eq!(est3.finalidad_votos_n, 3);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T10 · M12: ida y vuelta del punto de control; fija base y punto; uno manipulado se rechaza
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t10_punto_de_control_peso() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let paso2 = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert = paso2.certificado_peso.clone().expect("certificado");
    // La tabla de la ventana 1 (el certificado no cambia de tabla, así que la abierta vale) con su
    // índice `n`.
    let tabla_vigente = Tabla {
        n: cert.n,
        claves: motor.tabla_actual().expect("tabla").claves.clone(),
    };
    let bytes = serializar_punto_control_peso(&tabla_vigente, &cert, &[], &[]);
    let punto = deserializar_punto_control_peso(&bytes)?;
    assert_eq!(punto.certificado, cert);
    let (tabla2, pubs2, cert2) = (punto.tabla, punto.claves, punto.certificado);

    let mut nuevo = motor_peso(&[], false)?;
    nuevo.sembrar_punto_control_peso(tabla2.clone(), pubs2.clone(), cert2.clone(), &[])?;
    assert_eq!(nuevo.base_n(), Some(cert.n));
    assert_eq!(nuevo.punto(), Some(cert.candidato));

    // Punto de control manipulado: se rechaza.
    let mut falso = cert2.clone();
    falso.candidato = [0xEE; 32];
    assert!(
        nuevo
            .sembrar_punto_control_peso(tabla2, pubs2, falso, &[])
            .is_err(),
        "un punto de control manipulado se rechaza"
    );
    Ok(())
}

/// B-57 · `n = u64::MAX` no tiene ventana siguiente que abrir: el punto de control se rechaza con
/// motivo `n_max` **antes** de cualquier otra comprobación o efecto; el motor queda intacto.
#[test]
fn sembrar_punto_control_n_max_se_rechaza() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let paso2 = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert = paso2.certificado_peso.clone().expect("certificado");
    let tabla_vigente = Tabla {
        n: cert.n,
        claves: motor.tabla_actual().expect("tabla").claves.clone(),
    };
    let bytes = serializar_punto_control_peso(&tabla_vigente, &cert, &[], &[]);
    let punto = deserializar_punto_control_peso(&bytes)?;
    let (tabla2, pubs2, cert2) = (punto.tabla, punto.claves, punto.certificado);

    let mut nuevo = motor_peso(&[], false)?;
    let mut cert_max = cert2.clone();
    cert_max.n = u64::MAX;
    let tabla_max = Tabla {
        n: u64::MAX,
        claves: tabla2.claves.clone(),
    };
    let err = nuevo
        .sembrar_punto_control_peso(tabla_max, pubs2.clone(), cert_max, &[])
        .expect_err("n = u64::MAX se rechaza");
    assert_eq!(
        err,
        ErrorVotos::CargaInicialInvalida { motivo: "n_max" },
        "motivo n_max"
    );
    assert_eq!(nuevo.base_n(), None, "el motor no cambia: base");
    assert_eq!(nuevo.punto(), None, "el motor no cambia: punto");
    assert!(
        nuevo.ultimo_certificado_peso().is_none(),
        "el motor no cambia: último certificado"
    );
    assert!(
        nuevo.tabla_control_peso().is_none(),
        "el motor no cambia: tabla de control"
    );
    Ok(())
}

/// B-57 · `n = u64::MAX − 1` no entra en la guarda `n_max`: se comporta como hoy (con el código
/// base, sin guarda), es decir, el certificado se rechaza por la verificación ordinaria, no por la
/// guarda. Se deja constancia del error observado y de que el motor queda intacto.
#[test]
fn sembrar_punto_control_n_max_menos_uno_no_cambia() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let paso2 = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert = paso2.certificado_peso.clone().expect("certificado");
    let tabla_vigente = Tabla {
        n: cert.n,
        claves: motor.tabla_actual().expect("tabla").claves.clone(),
    };
    let bytes = serializar_punto_control_peso(&tabla_vigente, &cert, &[], &[]);
    let punto = deserializar_punto_control_peso(&bytes)?;
    let (tabla2, pubs2, cert2) = (punto.tabla, punto.claves, punto.certificado);

    let mut nuevo = motor_peso(&[], false)?;
    let mut cert_menos = cert2.clone();
    cert_menos.n = u64::MAX - 1;
    let tabla_menos = Tabla {
        n: u64::MAX - 1,
        claves: tabla2.claves.clone(),
    };
    let err = nuevo
        .sembrar_punto_control_peso(tabla_menos, pubs2, cert_menos, &[])
        .expect_err("el certificado no verifica al cambiar n");
    assert_ne!(
        err,
        ErrorVotos::CargaInicialInvalida { motivo: "n_max" },
        "u64::MAX - 1 no cae en la guarda n_max"
    );
    assert_eq!(nuevo.base_n(), None, "el motor no cambia: base");
    assert_eq!(nuevo.punto(), None, "el motor no cambia: punto");
    assert!(
        nuevo.ultimo_certificado_peso().is_none(),
        "el motor no cambia: último certificado"
    );
    assert!(
        nuevo.tabla_control_peso().is_none(),
        "el motor no cambia: tabla de control"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// T12 · tamaños: voto v2 y certificado de 200 + ceil(N/8) sin cambio de tabla
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn t12_tamanos() -> Result<(), Error> {
    let sk = bls(1)?;
    let voto = voto_manual(&sk, 1, [0x11; 32], [0x22; 32])?;
    assert_eq!(serializar_voto_peso(&voto).len(), 252, "voto v2");

    for n in [3usize, 1000, 4096] {
        let tabla = Tabla {
            n: 1,
            claves: (0..n)
                .map(|i| Clave {
                    clave: vec![(i & 0xff) as u8; 48],
                    peso: 1,
                    activo: true,
                    prueba: false,
                    garantia: 1,
                })
                .collect(),
        };
        let firma = zx_votos::firmar(&sk, DOMINIO_VOTO, &[0u8; 32])?;
        let cert = zx_votos::construir_certificado(
            1,
            [0u8; 32],
            [0u8; 32],
            RAIZ_ESTADO_CERO,
            &tabla,
            &[(1, firma)],
        )?;
        assert_eq!(
            serial_certificado_peso(&cert).len(),
            zx_votos::LONGITUD_FIJA_CERTIFICADO_PESO + n.div_ceil(8),
            "tamaño con {n} claves"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// PD-1e · U1/E1+E2 y U2/E3
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// U1 · E1+E2: con la base en la propia ventana (o más allá) el cierre **no** es un error; devuelve
/// sin certificado y deja abrir la siguiente. Con un hash de base que no encadena de verdad, el
/// certificado no se adopta (E2).
#[test]
fn u1_base_en_la_ventana_cierra_sin_certificado_y_abre_la_siguiente() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let tabla1 = motor.tabla_actual().expect("tabla 1").clone();
    let h1 = hash_tabla(&tabla1);

    // La finalidad aplicada ya está en la ventana 1 que se va a cerrar.
    let mut estado_base_n = estado.clone();
    estado_base_n.finalidad_votos_n = 1;
    estado_base_n.finalidad_votos_h_t = Some(h1);
    let paso = motor
        .avanzar(2, cand(0x22), &estado_base_n, SLOT)
        .expect("E1: cerrar con la base en la ventana no es error");
    assert!(paso.certificado_peso.is_none(), "no hay certificado");
    assert!(
        paso.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VentanaCerrada {
                n: 1,
                certificado: false,
                ..
            }
        )),
        "la ventana 1 se cierra sin certificado: {:?}",
        paso.eventos
    );
    assert_eq!(
        motor.instancia_actual(),
        Some(2),
        "E1: abre la ventana siguiente"
    );

    // E2 · base `m < n` pero con un hash que no es el que comprometió la base: sin la comprobación
    // real el certificado se adoptaría; con ella, el cierre queda sin certificado.
    let (estado2, secretas2) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor2 = motor_peso(&secretas2, true)?;
    let _ = motor2.avanzar(1, cand(0x11), &estado2, SLOT)?;
    let mut estado2_malo = estado2.clone();
    estado2_malo.finalidad_votos_n = 0;
    estado2_malo.finalidad_votos_h_t = Some([0xAB; 32]);
    let paso2 = motor2
        .avanzar(2, cand(0x22), &estado2_malo, SLOT)
        .expect("sin error");
    assert!(
        paso2.certificado_peso.is_none(),
        "E2: un hash de base que no casa no certifica"
    );
    Ok(())
}

/// U2 · E3: cada clave propia deja un evento con su peso, si emitió y el motivo cuando no.
#[test]
fn u2_evento_por_clave_con_peso_y_motivo() -> Result<(), Error> {
    let (estado, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let sk1 = bls(1)?;
    let sk2 = bls(2)?;
    let sk3 = bls(3)?;
    let tabla = Tabla {
        n: 1,
        claves: vec![
            Clave {
                clave: sk1.clave_publica().bytes().to_vec(),
                peso: 2,
                activo: true,
                prueba: false,
                garantia: 0,
            },
            Clave {
                clave: sk2.clave_publica().bytes().to_vec(),
                peso: 0,
                activo: true,
                prueba: false,
                garantia: 0,
            },
            Clave {
                clave: sk3.clave_publica().bytes().to_vec(),
                peso: 1,
                activo: false,
                prueba: false,
                garantia: 0,
            },
        ],
    };
    let pubs = vec![
        sk1.clave_publica(),
        sk2.clave_publica(),
        sk3.clave_publica(),
    ];
    let claves = vec![bls(1)?, bls(2)?, bls(3)?, bls(9)?];
    let mut motor = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves,
        emitir_votos: true,
    });
    let (_p, _s, _red, _sup, eventos) = motor.abrir(
        1,
        *cand(0x11).as_bytes(),
        &estado,
        SLOT,
        Some((tabla.clone(), pubs.clone())),
        None,
        &super::VistaPermisiva,
    )?;
    let motivos: Vec<(&str, u64, bool)> = eventos
        .iter()
        .filter_map(|e| match e {
            EventoMotor::VotoPesoPropio {
                peso,
                emitido,
                motivo,
                ..
            } => Some((*motivo, *peso, *emitido)),
            _ => None,
        })
        .collect();
    assert_eq!(motivos.len(), 4, "una por clave propia: {motivos:?}");
    assert!(motivos.contains(&("emitido", 2, true)), "{motivos:?}");
    assert!(motivos.contains(&("sin_peso", 0, false)), "{motivos:?}");
    assert!(motivos.contains(&("inactiva", 0, false)), "{motivos:?}");
    assert!(
        motivos.contains(&("fuera_de_tabla", 0, false)),
        "{motivos:?}"
    );

    // Observación: con `emitir_votos = false` la clave elegible no firma y deja `observacion`.
    let mut motor_obs = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![bls(1)?, bls(2)?, bls(3)?, bls(9)?],
        emitir_votos: false,
    });
    let (_p, _s, _red, _sup, eventos_obs) = motor_obs.abrir(
        1,
        *cand(0x11).as_bytes(),
        &estado,
        SLOT,
        Some((tabla, pubs)),
        None,
        &super::VistaPermisiva,
    )?;
    let motivos_obs: Vec<(&str, u64, bool)> = eventos_obs
        .iter()
        .filter_map(|e| match e {
            EventoMotor::VotoPesoPropio {
                peso,
                emitido,
                motivo,
                ..
            } => Some((*motivo, *peso, *emitido)),
            _ => None,
        })
        .collect();
    assert!(
        motivos_obs.contains(&("observacion", 2, false)),
        "{motivos_obs:?}"
    );
    Ok(())
}

/// TB-1c · N2/T2: el certificado que arma el nodo (`cerrar_peso`) no lleva tabla; su cuerpo mide
/// `LONGITUD_FIJA + ⌈N/8⌉`.
#[test]
fn certificado_del_nodo_no_lleva_tabla() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    let _ = motor.avanzar(1, cand(0x11), &estado, SLOT)?;
    let paso = motor.avanzar(2, cand(0x22), &estado, SLOT)?;
    let cert = paso.certificado_peso.expect("certificado");
    let bytes = serial_certificado_peso(&cert);
    assert_eq!(
        bytes.len(),
        zx_votos::LONGITUD_FIJA_CERTIFICADO_PESO + cert.mapa.len(),
        "N2 · el cuerpo es fijo más mapa, nada detrás"
    );
    assert_eq!(bytes.len(), 200 + cert.mapa.len());
    Ok(())
}

/// TB-1c · P4/B-61: un `0x09` con 65 536 firmantes mide 8 509 B de transacción y entra en un bloque
/// con el perfil real.
#[test]
fn certificado_65536_claves_mide_8509() -> Result<(), Error> {
    let sk = ClaveSecreta::generar(&[7u8; 32])?;
    let pk = sk.clave_publica();
    let tabla = Tabla {
        n: 2,
        claves: vec![Clave {
            clave: pk.bytes().to_vec(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        }],
    };
    let mensaje = zx_votos::mensaje_voto_peso(2, &[0u8; 32], &[0u8; 32], &[0u8; 32]);
    let firma = zx_votos::firmar(&sk, DOMINIO_VOTO, &mensaje)?;
    let base =
        zx_votos::construir_certificado(2, [0u8; 32], [0u8; 32], [0u8; 32], &tabla, &[(1, firma)])?;
    let cert = zx_votos::CertificadoPeso {
        mapa: vec![0xFFu8; 65_536 / 8],
        ..base
    };
    let (tx, tst) = super::tx_certificado_peso(
        &cert,
        ed(200),
        &ed25519_zebra::SigningKey::from([7u8; 32]),
        CBID,
    );
    let mut bytes = Vec::new();
    zx_core::wire::tx_a_bytes(&mut bytes, &tx, &tst);
    assert_eq!(
        bytes.len(),
        8_509,
        "el 0x09 con 65 536 firmantes mide 8 509 B"
    );
    assert!(
        bytes.len() <= 320_000,
        "cabe en el cuerpo de bloque del perfil real"
    );
    Ok(())
}
