//! RA-2 · pruebas del motor en modo peso en el rearranque tras una pausa larga (mejora 8).
//!
//! T1–T5, T7: banco de cuatro motores reales sobre un `Estado` real, aplicando los certificados
//! `0x09` con la función de consenso (`aplicar_certificado_peso_con_undo`), como `pd1e_peso.rs` y
//! `ra1_rearranque.rs`. Las pruebas de nodo (T6, T9, T10) viven en `crate::nodo::pruebas_ra2`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use std::collections::BTreeMap;

use zx_consensus::sectores::{
    ClaveVoto, Etapa, NO_HAY, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::{
    T_INST_VOTOS, aplicar_certificado_peso_con_undo, calendario_rearranque,
    derivar_tabla_sin_base_con_undo, tomar_instantaneas_rearranque_con_undo,
};
use zx_consensus::transicion::{Estado, Fase, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, ClaveTablaVoto, Digest};
use zx_votos::peso::{CertificadoPeso, serial_certificado_peso};
use zx_votos::{Clave, ClavePublica, ClaveSecreta, Tabla};

use super::{ConfigMotorVotos, MotorVotos};

const SLOT: i64 = 100;
const NODOS: usize = 4;
const DEN: i64 = 1_401_600_000;

fn semilla(i: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    ikm[0] = 0x42;
    ikm[8..16].copy_from_slice(&(i as u64).to_le_bytes());
    ikm
}

fn clave_ed(i: usize) -> ClaveEd {
    let mut bytes = [0u8; 32];
    bytes[0] = u8::try_from(i).unwrap_or(0) + 1;
    ClaveEd::desde_bytes(bytes)
}

fn clave_bls(i: usize) -> ClaveSecreta {
    ClaveSecreta::generar(&semilla(i)).expect("clave BLS")
}

fn cand(n: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xcc;
    bytes[1..9].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

/// `Estado` con los sectores indicados por clave, registrando la clave BLS de voto del nodo `i`.
fn estado_con_pesos(bls: &[ClavePublica], sectores: &[u16]) -> Estado {
    let p = ParametrosSector::dev();
    let mut estado = Estado::inicial();
    estado.parametros_sector = p;
    estado.fase = Fase::PoST;
    for (i, pk) in bls.iter().enumerate() {
        let ed = clave_ed(i);
        estado.claves_voto.insert(
            ed,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for s in 0..sectores[i] {
            let id = SectorId {
                clave: ed,
                sector_index: s,
                version: 0,
            };
            estado.sectores.insert(
                id,
                RegistroSector {
                    id,
                    r2: [0u64; 4],
                    history_size: 1,
                    etapa: Etapa::Activo,
                    alta_slot: 0,
                    renovacion_slot: 1_000_000,
                    retiro_slot: NO_HAY,
                    fianza: p.q_sec,
                    aud_apertura: NO_HAY,
                    aud_contestada: NO_HAY,
                },
            );
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(DEN).expect("garantia activa");
        estado.garantias.insert(ed, g);
    }
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &estado,
        u64::try_from(SLOT).expect("slot"),
    );
    con_cola
}

/// Tres motores votantes y un observador, todos en modo peso.
fn motores_peso(votantes: usize) -> Vec<MotorVotos> {
    let mut ms = Vec::with_capacity(NODOS);
    for i in 0..votantes {
        ms.push(motor_de_clave(i));
    }
    for _ in votantes..NODOS {
        ms.push(MotorVotos::nuevo(ConfigMotorVotos {
            perfil: crate::perfil::parametros_votos_dev(),
            claves: Vec::new(),
            emitir_votos: false,
        }));
    }
    ms
}

fn motor_de_clave(i: usize) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![clave_bls(i)],
        emitir_votos: true,
    })
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

fn hash_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&Tabla {
        n: 0,
        claves: claves.iter().map(clave_contrato).collect(),
    })
}

/// Aplica un `0x09` al estado con la transición real.
fn aplicar(estado: &Estado, cert: &CertificadoPeso, slot: i64) -> Estado {
    let op = zx_core::OperacionAlmacenamiento::CertificadoPeso {
        clave: clave_ed(200),
        bytes: serial_certificado_peso(cert),
    };
    let (nuevo, _undo, r) = aplicar_certificado_peso_con_undo(estado, &op, slot);
    r.expect("el certificado por peso se aplica");
    nuevo
}

/// Difunde los sobres a todos los motores.
fn difundir(ms: &mut [MotorVotos], sobres: &[Vec<u8>]) {
    for m in ms.iter_mut() {
        for s in sobres {
            let _ = m.recibir_voto(s);
        }
    }
}

/// T1 · la parte 1: base en `m`; el estado avanza hasta la fase activa del primer ciclo con la
/// instantánea tomada; los motores abren, votan y uno cierra con certificado; aplicado, la base del
/// estado pasa a esa ventana. **Sin R1 falla** (nadie abre: `BaseCaducada`).
#[test]
fn t1_abre_vota_y_certifica_en_la_fase_activa() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let base = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let mut ms = motores_peso(3);

    // Fase A · camino normal hasta la base m = 2.
    let mut estado = base.clone();
    let mut certs: BTreeMap<u64, CertificadoPeso> = BTreeMap::new();
    for n in 1..=3u64 {
        let mut sobres = Vec::new();
        for m in &mut ms {
            let paso = m
                .avanzar(n, cand(n), &estado, SLOT)
                .expect("avanzar normal");
            sobres.extend(paso.votos);
            if let Some(c) = paso.certificado_peso {
                certs.entry(c.n).or_insert(c);
            }
        }
        difundir(&mut ms, &sobres);
    }
    for n in 1..=2u64 {
        let c = certs.get(&n).expect("certificado normal").clone();
        estado = aplicar(&estado, &c, SLOT + i64::try_from(n).unwrap_or(0));
    }
    assert_eq!(estado.finalidad_votos_n, 2, "base m = 2");

    // Instantánea del primer ciclo con el hook real del consenso.
    let cal = calendario_rearranque(&estado.parametros_sector, 2).expect("dev tiene A > 0");
    let (estado, _) = tomar_instantaneas_rearranque_con_undo(&estado, cal.referencia(0) + 1);
    assert!(
        estado.tabla_ciclo_rearranque.contains_key(&0),
        "instantánea del ciclo 0"
    );

    // Ventana que abre en la fase activa del ciclo 0.
    let n_re = cal.inicio(0) / T_INST_VOTOS;
    assert_eq!(cal.ciclo_de_apertura(n_re * T_INST_VOTOS), Some(0));
    let slot_re = i64::try_from(cal.inicio(0)).unwrap_or(i64::MAX);
    // TB4-R1 · el gancho por ventana del bloque que aplica el rearranque deposita la tabla fresca en
    // `Q`; sin él la aplicación ya no la mantiene (TB4-R6).
    let (estado, _) = derivar_tabla_sin_base_con_undo(&estado, u64::try_from(slot_re).unwrap_or(0));

    let mut sobres = Vec::new();
    for m in &mut ms {
        let paso = m
            .avanzar(n_re, cand(n_re), &estado, slot_re)
            .expect("avanzar en rearranque");
        assert_eq!(
            m.instancia_actual(),
            Some(n_re),
            "el motor abre en la fase activa (R1)"
        );
        sobres.extend(paso.votos);
    }
    difundir(&mut ms, &sobres);

    let mut cert_re: Option<CertificadoPeso> = None;
    for m in &mut ms {
        let paso = m
            .avanzar(n_re + 1, cand(n_re + 1), &estado, slot_re + 2)
            .expect("cerrar el rearranque");
        if let Some(c) = paso.certificado_peso {
            cert_re = Some(c);
        }
    }
    let cert = cert_re.expect("el rearranque produce certificado (R2)");
    assert_eq!(cert.n, n_re);

    let fin = aplicar(&estado, &cert, slot_re);
    assert_eq!(
        fin.finalidad_votos_n, n_re,
        "la base del estado pasa a la ventana del rearranque"
    );
    assert!(
        fin.tabla_ciclo_rearranque.is_empty(),
        "Y2 borra las instantáneas al avanzar la base"
    );
}

/// T2 · la parte 2: en la espera (`< s₀`) y en la fase de silencio nadie abre ni firma; un evento
/// `rearranque_en_espera` por ciclo.
#[test]
fn t2_en_espera_y_en_silencio_no_abre() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let base = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let cal = calendario_rearranque(&base.parametros_sector, 2).expect("calendario");
    let mut estado = base;
    estado.finalidad_votos_n = 2;
    estado.finalidad_votos = Some(cand(2));
    let t = {
        use zx_consensus::transicion::votos::tabla_canonica;
        tabla_canonica(&estado, 0)
    };
    let h = hash_payload(&t);
    estado.finalidad_votos_h_t = Some(h);
    estado.tablas_voto_contenido.insert(h, t.clone());
    // Instantánea del ciclo 0 (la espera es `< s0`; la instantánea existe ya en el estado).
    estado.tabla_ciclo_rearranque.insert(0, h);
    let mut m = motor_de_clave(0);
    m.sembrar_base_de_estado(2, h, *cand(2).as_bytes())
        .expect("base de estado");

    // Antes de s0: dos ventanas en el mismo ciclo de espera → un solo evento.
    let antes1 = m
        .avanzar(400, cand(400), &estado, SLOT)
        .expect("avanzar en espera");
    assert!(m.instancia_actual().is_none(), "no abre antes de s0");
    let esperas1 = antes1
        .eventos
        .iter()
        .filter(|e| matches!(e, super::EventoMotor::RearranqueEnEspera { .. }))
        .count();
    assert_eq!(esperas1, 1, "un evento de espera");
    let antes2 = m
        .avanzar(401, cand(401), &estado, SLOT)
        .expect("avanzar en espera");
    let esperas2 = antes2
        .eventos
        .iter()
        .filter(|e| matches!(e, super::EventoMotor::RearranqueEnEspera { .. }))
        .count();
    assert_eq!(esperas2, 0, "el evento de espera es una vez por ciclo");
    assert!(m.instancia_actual().is_none());

    // Fase de silencio: apertura en `[inicio(0)+a, inicio(1))`.
    let apertura_silencio = cal.inicio(0) + cal.a + 1;
    let n_sil = apertura_silencio.div_euclid(T_INST_VOTOS);
    let sil = m
        .avanzar(
            n_sil,
            cand(n_sil),
            &estado,
            i64::try_from(apertura_silencio).unwrap_or(0),
        )
        .expect("avanzar en silencio");
    assert!(m.instancia_actual().is_none(), "no abre en silencio");
    assert!(
        sil.eventos
            .iter()
            .any(|e| matches!(e, super::EventoMotor::RearranqueEnEspera { .. })),
        "evento de espera en el silencio"
    );
}

/// T3 · la parte 2: sin instantánea del ciclo (cadena sin bloques tras la referencia) nadie abre;
/// evento `rearranque_sin_tabla`.
#[test]
fn t3_sin_instantanea_no_abre() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let mut estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let cal = calendario_rearranque(&estado.parametros_sector, 2).expect("calendario");
    estado.finalidad_votos_n = 2;
    estado.finalidad_votos = Some(cand(2));
    let t = zx_consensus::transicion::votos::tabla_canonica(&estado, 0);
    let h = hash_payload(&t);
    estado.finalidad_votos_h_t = Some(h);
    estado.tablas_voto_contenido.insert(h, t);
    // Sin instantánea del ciclo.
    let mut m = motor_de_clave(0);
    m.sembrar_base_de_estado(2, h, *cand(2).as_bytes())
        .expect("base de estado");
    let n_re = cal.inicio(0) / T_INST_VOTOS;
    let paso = m
        .avanzar(
            n_re,
            cand(n_re),
            &estado,
            i64::try_from(cal.inicio(0)).unwrap_or(0),
        )
        .expect("avanzar sin instantánea");
    assert!(m.instancia_actual().is_none(), "no abre sin instantánea");
    assert!(
        paso.eventos
            .iter()
            .any(|e| matches!(e, super::EventoMotor::RearranqueSinTabla { .. })),
        "evento rearranque_sin_tabla"
    );
}

/// T5 · R0: un motor que **no** tenía abierta la ventana anterior abre la siguiente a un cambio de
/// tabla con el contenido guardado en el estado. **Sin R0 difiere la apertura**.
#[test]
fn t5_tabla_de_base_desde_el_contenido_guardado() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let mut estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    // Tabla del contenido distinta de la canónica (pesos cambiados) y ausente de `tablas_voto`.
    let t_cambio: Vec<ClaveTablaVoto> = vec![
        ClaveTablaVoto {
            clave_bls: bls[0].bytes(),
            peso: 5,
            activo: true,
            prueba: false,
            garantia: 5,
        },
        ClaveTablaVoto {
            clave_bls: bls[1].bytes(),
            peso: 7,
            activo: true,
            prueba: false,
            garantia: 7,
        },
    ];
    let h = hash_payload(&t_cambio);
    estado.finalidad_votos_n = 2;
    estado.finalidad_votos = Some(cand(2));
    estado.finalidad_votos_h_t = Some(h);
    estado.tablas_voto_contenido.insert(h, t_cambio.clone());

    let mut m = motor_de_clave(0);
    m.sembrar_base_de_estado(2, h, *cand(2).as_bytes())
        .expect("base de estado");
    let paso = m
        .avanzar(3, cand(3), &estado, SLOT)
        .expect("avanzar con contenido guardado");
    assert_eq!(
        m.instancia_actual(),
        Some(3),
        "abre con la tabla del contenido guardado (R0)"
    );
    assert!(
        paso.eventos
            .iter()
            .any(|e| matches!(e, super::EventoMotor::VentanaAbierta { n: 3, .. })),
        "ventana abierta"
    );
    assert!(
        !paso
            .eventos
            .iter()
            .any(|e| matches!(e, super::EventoMotor::AperturaDiferida { .. })),
        "sin R0 la apertura se diferiría"
    );
}

/// T7 · R2: dos tercios del peso de la **tabla del ciclo** certifican; con menos, acta y no
/// certificado. La tabla de la base es distinta de la del ciclo (si R2 no encadenara con la tabla
/// vigente, el motor no produciría certificado).
#[test]
fn t7_dos_tercios_de_la_tabla_del_ciclo() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let mut estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let cal = calendario_rearranque(&estado.parametros_sector, 2).expect("calendario");
    let mut t_base: Vec<ClaveTablaVoto> = vec![
        ClaveTablaVoto {
            clave_bls: bls[0].bytes(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        },
        ClaveTablaVoto {
            clave_bls: bls[1].bytes(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        },
    ];
    let mut t_ciclo: Vec<ClaveTablaVoto> = (0..NODOS)
        .map(|i| ClaveTablaVoto {
            clave_bls: bls[i].bytes(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        })
        .collect();
    // Orden canónico (por bytes de clave BLS): el que indexa el mapa de bits del certificado.
    t_base.sort_by_key(|c| c.clave_bls);
    t_ciclo.sort_by_key(|c| c.clave_bls);
    let h_base = hash_payload(&t_base);
    let h_ciclo = hash_payload(&t_ciclo);
    assert_ne!(h_base, h_ciclo, "las dos tablas difieren");
    estado.finalidad_votos_n = 2;
    estado.finalidad_votos = Some(cand(2));
    estado.finalidad_votos_h_t = Some(h_base);
    estado.tablas_voto_contenido.insert(h_base, t_base);
    estado.tablas_voto_contenido.insert(h_ciclo, t_ciclo);
    estado.tabla_ciclo_rearranque.insert(0, h_ciclo);
    let n_re = cal.inicio(0) / T_INST_VOTOS;
    let slot_re = i64::try_from(cal.inicio(0)).unwrap_or(i64::MAX);
    // TB4-R1 · el gancho por ventana deposita la tabla fresca en `Q` antes de aplicar.
    let (estado, _) = derivar_tabla_sin_base_con_undo(&estado, u64::try_from(slot_re).unwrap_or(0));

    // Tres votantes de cuatro: 3/4 ≥ 2/3 de la tabla del ciclo → certificado.
    let mut ms: Vec<MotorVotos> = (0..3).map(motor_de_clave).collect();
    for m in &mut ms {
        m.sembrar_base_de_estado(2, h_base, *cand(2).as_bytes())
            .expect("base de estado");
    }
    let mut sobres = Vec::new();
    for m in &mut ms {
        let paso = m
            .avanzar(n_re, cand(n_re), &estado, slot_re)
            .expect("abrir");
        sobres.extend(paso.votos);
    }
    difundir(&mut ms, &sobres);
    let mut cert = None;
    for m in &mut ms {
        let paso = m
            .avanzar(n_re + 1, cand(n_re + 1), &estado, slot_re + 2)
            .expect("cerrar");
        if let Some(c) = paso.certificado_peso {
            cert = Some(c);
        }
    }
    let cert = cert.expect("dos tercios de la tabla del ciclo certifican (R2)");
    let fin = aplicar(&estado, &cert, slot_re);
    assert_eq!(fin.finalidad_votos_n, n_re);

    // Un solo votante: sin quórum, acta y **no** certificado.
    let mut solo = motor_de_clave(0);
    solo.sembrar_base_de_estado(2, h_base, *cand(2).as_bytes())
        .expect("base de estado");
    let _ = solo
        .avanzar(n_re, cand(n_re), &estado, slot_re)
        .expect("abrir");
    let paso = solo
        .avanzar(n_re + 1, cand(n_re + 1), &estado, slot_re + 2)
        .expect("cerrar");
    assert!(
        paso.certificado_peso.is_none(),
        "sin dos tercios del ciclo no hay certificado"
    );
    assert!(paso.acta_peso.is_some(), "con votos y sin quórum hay acta");
}

/// T4 · la parte 3: tras el rearranque, las dos ventanas siguientes se certifican por el camino
/// normal y la atadura rige (la base del estado avanza con cada certificado).
#[test]
fn t4_ventanas_siguientes_por_camino_normal() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let base = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let mut ms = motores_peso(3);
    let mut estado = base;
    let mut certs: BTreeMap<u64, CertificadoPeso> = BTreeMap::new();
    for n in 1..=3u64 {
        let mut sobres = Vec::new();
        for m in &mut ms {
            let paso = m
                .avanzar(n, cand(n), &estado, SLOT)
                .expect("avanzar normal");
            sobres.extend(paso.votos);
            if let Some(c) = paso.certificado_peso {
                certs.entry(c.n).or_insert(c);
            }
        }
        difundir(&mut ms, &sobres);
    }
    for n in 1..=2u64 {
        let c = certs.get(&n).expect("certificado normal").clone();
        estado = aplicar(&estado, &c, SLOT + i64::try_from(n).unwrap_or(0));
    }
    let cal = calendario_rearranque(&estado.parametros_sector, 2).expect("calendario");
    let (estado, _) = tomar_instantaneas_rearranque_con_undo(&estado, cal.referencia(0) + 1);
    let n_re = cal.inicio(0) / T_INST_VOTOS;
    let slot_re = i64::try_from(cal.inicio(0)).unwrap_or(i64::MAX);
    // TB4-R1 · el gancho por ventana deposita la tabla fresca en `Q` antes de aplicar.
    let (mut estado, _) =
        derivar_tabla_sin_base_con_undo(&estado, u64::try_from(slot_re).unwrap_or(0));

    let mut sobres = Vec::new();
    for m in &mut ms {
        let paso = m
            .avanzar(n_re, cand(n_re), &estado, slot_re)
            .expect("abrir");
        sobres.extend(paso.votos);
    }
    difundir(&mut ms, &sobres);
    // Cierra el rearranque (el motor abre ya `n_re + 1`) y difunde los votos de esa ventana.
    let mut cert = None;
    let mut sobres_siguiente = Vec::new();
    for m in &mut ms {
        let paso = m
            .avanzar(n_re + 1, cand(n_re + 1), &estado, slot_re + 2)
            .expect("cerrar rearranque");
        if let Some(c) = paso.certificado_peso {
            cert = Some(c);
        }
        sobres_siguiente.extend(paso.votos);
    }
    difundir(&mut ms, &sobres_siguiente);
    estado = aplicar(&estado, &cert.expect("certificado de rearranque"), slot_re);
    assert_eq!(estado.finalidad_votos_n, n_re);

    // Las dos ventanas siguientes, por el camino normal (encadenadas con la base nueva).
    for paso_n in [n_re + 1, n_re + 2] {
        let mut sb = Vec::new();
        let mut c = None;
        for m in &mut ms {
            let paso = m
                .avanzar(paso_n + 1, cand(paso_n + 1), &estado, slot_re + 4)
                .expect("cerrar normal");
            if let Some(x) = paso.certificado_peso {
                c = Some(x);
            }
            sb.extend(paso.votos);
        }
        difundir(&mut ms, &sb);
        let c = c.unwrap_or_else(|| panic!("certificado normal de la ventana {paso_n}"));
        estado = aplicar(&estado, &c, slot_re + 4);
        assert_eq!(estado.finalidad_votos_n, paso_n, "la atadura rige");
    }
}

/// T8 · R5 y «se conserva»: sin voto tardío más allá de la caducidad de la base.
#[test]
fn t8_caducidad_y_sin_voto_tardio() {
    use super::{DiarioVotos, EventoMotor, VistaPermisiva};

    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let mut estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let t = zx_consensus::transicion::votos::tabla_canonica(&estado, 0);
    let h = hash_payload(&t);
    estado.finalidad_votos_n = 2;
    estado.finalidad_votos = Some(cand(2));
    estado.finalidad_votos_h_t = Some(h);
    estado.tablas_voto_contenido.insert(h, t);

    // Base caducada: `BaseCaducada` y no abre (el comportamiento de hoy no cambia). M9-a2 · este
    // motor es el único que queda, el **modo por peso**; antes se llamaba «sorteo».
    let mut motor_caducado = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![clave_bls(0)],
        emitir_votos: true,
    });
    motor_caducado
        .sembrar_base_de_estado(2, h, *cand(2).as_bytes())
        .expect("base de estado");
    let paso = motor_caducado
        .avanzar(400, cand(400), &estado, SLOT)
        .expect("avanzar en modo por peso");
    assert!(
        motor_caducado.instancia_actual().is_none(),
        "no abre tras la caducidad"
    );
    assert!(
        paso.eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::BaseCaducada { .. })),
        "emite BaseCaducada"
    );

    // Modo peso: sin voto tardío más allá de la caducidad (con diario vinculado).
    let dir = tempfile::tempdir().expect("tempdir");
    let diario = DiarioVotos::nueva(dir.path().join("votos.registro"), 0).expect("diario");
    let mut peso = motor_de_clave(0);
    peso.vincular_diario(diario);
    peso.sembrar_base_de_estado(2, h, *cand(2).as_bytes())
        .expect("base de estado");
    let tardo = peso
        .votar_tardio(400, *cand(400).as_bytes(), &estado, &VistaPermisiva)
        .expect("voto tardío");
    assert!(
        tardo.votos.is_empty(),
        "no hay voto tardío más allá de la caducidad (R5)"
    );
}
