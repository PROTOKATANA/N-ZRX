//! TB4 · TB4-R7 en el motor de votos: el votante declara la **última huella de `Q`** del estado de
//! su candidato en las tres ramas (con base, sin base y rearranque) y firma con la misma tabla que
//! antes; el certificado de rearranque que arma el motor lo admite la cadena (TB4-R4).
//!
//! Módulo hijo de `votos`: usa el camino real (`MotorVotos::avanzar`) y la transición real
//! (`aplicar_certificado_peso_con_undo`). Firmas BLS reales.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "pruebas de escenario con estados construidos a mano; fallan con panic por diseño"
)]

use std::collections::BTreeMap;

use zx_consensus::sectores::{
    ClaveVoto, Etapa, NO_HAY, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::{
    aplicar_certificado_peso_con_undo, calendario_rearranque, derivar_tabla_sin_base_con_undo,
    tomar_instantaneas_rearranque_con_undo,
};
use zx_consensus::transicion::{Estado, Fase, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, Digest};
use zx_votos::peso::{CertificadoPeso, serial_certificado_peso};
use zx_votos::{ClavePublica, ClaveSecreta};

use super::*;

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

/// `Estado` con los sectores indicados por clave y la cola `Q` sembrada por el gancho.
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
    let (con_cola, _u) =
        derivar_tabla_sin_base_con_undo(&estado, u64::try_from(SLOT).expect("slot"));
    con_cola
}

fn motor_de_clave(i: usize) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![clave_bls(i)],
        emitir_votos: true,
    })
}

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

fn difundir(ms: &mut [MotorVotos], sobres: &[Vec<u8>]) {
    for m in ms.iter_mut() {
        for s in sobres {
            let _ = m.recibir_voto(s);
        }
    }
}

fn aplicar(estado: &Estado, cert: &CertificadoPeso, slot: i64) -> Estado {
    let op = zx_core::OperacionAlmacenamiento::CertificadoPeso {
        clave: clave_ed(200),
        bytes: serial_certificado_peso(cert),
    };
    let (nuevo, _undo, r) = aplicar_certificado_peso_con_undo(estado, &op, slot);
    r.expect("el certificado por peso se aplica");
    nuevo
}

/// La huella declarada por el motor en la apertura de la última ventana observada.
fn declarada(paso: &PasoVotos) -> Option<String> {
    paso.eventos.iter().find_map(|e| match e {
        EventoMotor::VentanaAbierta { h_t_siguiente, .. } => Some(h_t_siguiente.clone()),
        _ => None,
    })
}

/// Huella de la última entrada de `Q`.
fn ultima_cola(estado: &Estado) -> [u8; 32] {
    estado
        .cola_tablas_voto
        .last()
        .map(|(_, h)| *h)
        .expect("cola no vacía")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R7 · el votante declara la última de la cola en el rearranque
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_r7_el_votante_declara_la_ultima_de_la_cola_en_rearranque() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let mut estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    // Base m = 0 con la tabla canónica como vigente y su instantánea del ciclo 0.
    estado.finalidad_votos_n = 0;
    estado.finalidad_votos = Some(cand(0));
    let (mut estado, _u) = tomar_instantaneas_rearranque_con_undo(&estado, 603);
    let h_snap = *estado
        .tabla_ciclo_rearranque
        .get(&0)
        .expect("instantánea del ciclo 0");
    estado.finalidad_votos_h_t = Some(h_snap);
    // Alta real posterior a la instantánea: la tabla actual cambia de peso y el gancho del
    // bloque de rearranque deposita esa tabla; no se siembra Q con contenido inventado.
    let alta = zx_core::OperacionSector::Alta {
        clave: clave_ed(0),
        sector_index: 1,
        version: 0,
        r2: [0; 32],
        history_size: 1,
    };
    let (estado, r) = zx_consensus::transicion::sector::aplicar_operacion_con_undo(
        &estado,
        &alta,
        604,
        &estado.parametros_sector,
    );
    assert_eq!(r.motivo, zx_consensus::sectores::MotivoSector::Ok);
    let (estado, _) = derivar_tabla_sin_base_con_undo(&estado, 1_262);
    let h_otra = ultima_cola(&estado);
    assert_ne!(h_otra, h_snap);

    let mut m = motor_de_clave(0);
    m.sembrar_base_de_estado(0, h_snap, *cand(0).as_bytes())
        .expect("base de estado");
    let paso = m.avanzar(631, cand(631), &estado, 1_262).expect("abrir");
    let declarada = declarada(&paso).expect("evento ventana_abierta");
    assert_eq!(
        declarada,
        hex(&h_otra),
        "en el rearranque declara la última de la cola, no la instantánea"
    );
    assert_eq!(
        hash_tabla(m.tabla_actual().expect("instancia abierta")),
        h_snap,
        "firma con la instantánea, como antes"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R7 · con base y sin base declara la última de la cola en régimen denso
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_r7_con_base_y_sin_base_declara_lo_mismo_que_antes_en_regimen_denso() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);

    // Con base: `Q` con la última ventana fresca.
    let mut con_base = estado.clone();
    con_base.finalidad_votos_n = 40;
    con_base.finalidad_votos = Some(cand(40));
    let h_base = ultima_cola(&con_base);
    con_base.finalidad_votos_h_t = Some(h_base);
    let (con_base, _u) = derivar_tabla_sin_base_con_undo(&con_base, 2 * 50);
    let ultima_base = ultima_cola(&con_base);
    let mut m = motor_de_clave(0);
    m.sembrar_base_de_estado(40, h_base, *cand(40).as_bytes())
        .expect("base de estado");
    let paso = m
        .avanzar(51, cand(51), &con_base, 102)
        .expect("abrir con base");
    assert_eq!(
        declarada(&paso).expect("evento"),
        hex(&ultima_base),
        "con base declara la última de Q"
    );

    // Sin base: misma regla.
    let mut sin_base = estado.clone();
    sin_base.finalidad_votos = None;
    sin_base.finalidad_votos_h_t = None;
    sin_base.finalidad_votos_n = 0;
    let (sin_base, _u) = derivar_tabla_sin_base_con_undo(&sin_base, 2 * 50);
    let ultima_sin = ultima_cola(&sin_base);
    let mut m = motor_de_clave(0);
    let paso = m
        .avanzar(51, cand(51), &sin_base, 102)
        .expect("abrir sin base");
    assert_eq!(
        declarada(&paso).expect("evento"),
        hex(&ultima_sin),
        "sin base declara la última de Q"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R7 + TB4-R4 · el certificado de rearranque que arma el motor lo admite la cadena
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_el_motor_arma_un_certificado_de_rearranque_que_la_cadena_admite() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let base = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let mut ms = motores_peso(3);

    // Camino normal hasta la base m = 2.
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
    assert_eq!(estado.finalidad_votos_n, 2);

    // Instantánea del primer ciclo.
    let cal = calendario_rearranque(&estado.parametros_sector, 2).expect("calendario");
    let (estado, _) = tomar_instantaneas_rearranque_con_undo(&estado, cal.referencia(0) + 1);
    let n_re = cal.inicio(0) / 2;
    let slot_re = i64::try_from(cal.inicio(0)).unwrap_or(i64::MAX);
    // Un sector nuevo en la identidad 3 cambia la tabla fresca respecto de la instantánea: así un
    // votante que declarase la instantánea (control rojo) no sería admitido por la cadena.
    let mut estado = estado;
    let p = estado.parametros_sector;
    let id3 = SectorId {
        clave: clave_ed(3),
        sector_index: 1,
        version: 0,
    };
    estado.sectores.insert(
        id3,
        RegistroSector {
            id: id3,
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
    // TB4-R1: el gancho por ventana del bloque que aplica el rearranque refresca `Q`.
    let (estado, _) = derivar_tabla_sin_base_con_undo(&estado, u64::try_from(slot_re).unwrap_or(0));
    assert_ne!(
        estado.cola_tablas_voto.last().expect("fresca").1,
        *estado.tabla_ciclo_rearranque.get(&0).expect("instantánea"),
        "la fresca difiere de la instantánea (base del control rojo)"
    );

    let mut sobres = Vec::new();
    for m in &mut ms {
        let paso = m
            .avanzar(n_re, cand(n_re), &estado, slot_re)
            .expect("abrir rearranque");
        assert_eq!(m.instancia_actual(), Some(n_re));
        sobres.extend(paso.votos);
    }
    difundir(&mut ms, &sobres);
    let mut cert_re: Option<CertificadoPeso> = None;
    for m in &mut ms {
        let paso = m
            .avanzar(n_re + 1, cand(n_re + 1), &estado, slot_re + 2)
            .expect("cerrar rearranque");
        if let Some(c) = paso.certificado_peso {
            cert_re = Some(c);
        }
    }
    let cert = cert_re.expect("el motor arma el certificado de rearranque");
    assert_eq!(cert.n, n_re);
    // La huella declarada es la fresca de `Q`, no la instantánea.
    assert_eq!(cert.h_t_siguiente, ultima_cola(&estado));
    let fin = aplicar(&estado, &cert, slot_re);
    assert_eq!(fin.finalidad_votos_n, n_re);
    assert_eq!(
        fin.finalidad_votos_h_t,
        Some(ultima_cola(&estado)),
        "la cadena admite el certificado y la fresca queda vigente"
    );
}

/// A→B→A con alta, maduración, cierre y retirada reales de un sector adicional.
/// La ventana A inicial es 50, B llega en 57 y A vuelve en 58; Q nunca se edita.
fn estado_vuelta(con_base: bool) -> (Estado, [u8; 32], [u8; 32]) {
    use zx_consensus::sectores::MotivoSector;
    use zx_consensus::transicion::sector::aplicar_operacion_con_undo;
    use zx_consensus::transicion::votos::tabla_derivada;
    use zx_core::OperacionSector;

    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let mut estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let h_a = ultima_cola(&estado);
    if con_base {
        estado.finalidad_votos_n = 50;
        estado.finalidad_votos = Some(cand(50));
        estado.finalidad_votos_h_t = Some(h_a);
    }
    let p = estado.parametros_sector;
    let alta = OperacionSector::Alta {
        clave: clave_ed(0),
        sector_index: 1,
        version: 0,
        r2: [0; 32],
        history_size: 1,
    };
    let (nuevo, r) = aplicar_operacion_con_undo(&estado, &alta, 101, &p);
    assert_eq!(r.motivo, MotivoSector::Ok, "alta real");
    estado = nuevo;
    for k in 51..=57 {
        (estado, _) = derivar_tabla_sin_base_con_undo(&estado, 2 * k);
    }
    let h_b = ultima_cola(&estado);
    assert_ne!(h_a, h_b, "la alta madura cambia el peso derivado");
    for op in [
        OperacionSector::CerrarCaja {
            clave: clave_ed(0),
            seq: 1,
        },
        OperacionSector::RetirarCaja {
            clave: clave_ed(0),
            seq: 1,
        },
    ] {
        let (nuevo, r) = aplicar_operacion_con_undo(&estado, &op, 115, &p);
        assert_eq!(r.motivo, MotivoSector::Ok, "cierre/retirada reales");
        estado = nuevo;
    }
    (estado, _) = derivar_tabla_sin_base_con_undo(&estado, 116);
    assert_eq!(
        hash_tabla(&tabla_de_contenido(58, &tabla_derivada(&estado, 58))),
        h_a
    );
    assert_eq!(estado.cola_tablas_voto.len(), 2, "solo A y B");
    (estado, h_a, h_b)
}

#[test]
fn tb4_vuelta_el_votante_declara_la_fresca() {
    let mut observadas = Vec::new();
    for con_base in [true, false] {
        let (estado, h_a, _) = estado_vuelta(con_base);
        let mut motor = motor_de_clave(0);
        if con_base {
            motor
                .sembrar_base_de_estado(50, h_a, *cand(50).as_bytes())
                .expect("base sellada");
        }
        let paso = motor.avanzar(60, cand(60), &estado, 120).expect("abrir");
        let declarada = declarada(&paso).expect("ventana abierta");
        let firmante = hash_tabla(motor.tabla_actual().expect("tabla firmante"));
        println!(
            "declaración: con_base={con_base}, declara A={}, firma con A={}",
            declarada == hex(&h_a),
            firmante == h_a
        );
        observadas.push((con_base, declarada, firmante, h_a));
    }
    for (con_base, declarada, firmante, h_a) in observadas {
        assert_eq!(declarada, hex(&h_a), "con_base={con_base}");
        assert_eq!(firmante, h_a, "con_base={con_base}");
    }
}

/// Certificado de la ventana 94 con el candidato de la 92 (lag de cuatro slots),
/// tras A estable durante X+3 ventanas. Usa apertura, votos y cierre reales del motor.
fn certificado_tras_vuelta(con_base: bool) {
    use zx_consensus::transicion::votos::tope_edad_tabla_ventanas;

    let (mut estado, h_a, h_b) = estado_vuelta(con_base);
    let x = tope_edad_tabla_ventanas(&estado.parametros_sector);
    assert_eq!(x, 31);
    let k_fin = 58 + x + 3;
    for k in 59..=k_fin {
        (estado, _) = derivar_tabla_sin_base_con_undo(&estado, 2 * k);
    }
    let n = k_fin + 2;
    assert!(n - 57 > x, "B envejeció más allá de X");
    let mut motores = motores_peso(3);
    let mut sobres = Vec::new();
    for motor in &mut motores {
        if con_base {
            motor
                .sembrar_base_de_estado(50, h_a, *cand(50).as_bytes())
                .expect("base sellada");
        }
        let paso = motor
            .avanzar(n, cand(n), &estado, (2 * n) as i64)
            .expect("abrir");
        sobres.extend(paso.votos);
    }
    difundir(&mut motores, &sobres);
    let mut certificado = None;
    for motor in &mut motores {
        let paso = motor
            .avanzar(n + 1, cand(n + 1), &estado, (2 * n + 2) as i64)
            .expect("cerrar");
        if let Some(cert) = paso.certificado_peso {
            certificado = Some(cert);
        }
    }
    let certificado = certificado.expect("tres de cuatro motores forman cuórum");
    assert_eq!(certificado.n, n);
    assert_eq!(
        certificado.h_t_siguiente,
        ultima_cola(&estado),
        "declara lo que declaró el motor"
    );
    println!(
        "vuelta: con_base={con_base}, X={x}, A estable={} ventanas, n={n}, edad B={}, declara A={}, declara B={}",
        x + 3,
        n - 57,
        certificado.h_t_siguiente == h_a,
        certificado.h_t_siguiente == h_b
    );
    // El candidato va cuatro slots por detrás. La cadena ejecuta también el gancho en las
    // ventanas posteriores hasta el bloque que incluye el certificado ya cerrado.
    let mut estado_aplicacion = estado.clone();
    for k in k_fin + 1..=n + 1 {
        (estado_aplicacion, _) = derivar_tabla_sin_base_con_undo(&estado_aplicacion, 2 * k);
    }
    let post = aplicar(&estado_aplicacion, &certificado, (2 * n + 2) as i64);
    assert_eq!(post.finalidad_votos_n, n);
    assert_eq!(
        post.finalidad_votos_h_t,
        Some(h_a),
        "se compromete la derivada actual"
    );
}

#[test]
fn tb4_vuelta_la_finalidad_no_se_para() {
    certificado_tras_vuelta(true);
}

#[test]
fn tb4_vuelta_sin_base_el_primer_certificado_se_admite() {
    certificado_tras_vuelta(false);
}
