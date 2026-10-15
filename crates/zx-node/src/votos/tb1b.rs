//! TB-1b · pruebas de N1 (el votante declara la última huella de la cola del candidato), N5 (el
//! nodo valida las claves de una tabla con memoria) y banco de `construir_tabla`.
//!
//! Orden `P-ZRX/P-004/ORDEN-TB1B.md` §3 y §4. Las siete pruebas de N1 usan el motor por peso con
//! estados construidos a mano (sectores reales, firmas BLS reales) y la prueba 7 usa el consenso
//! real (`aplicar_certificado_peso_con_undo`). Los nombres son los fijos de la orden.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::needless_range_loop,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::items_after_statements,
    dead_code,
    reason = "pruebas de escenario y banco de medida con estados a mano; fallan con panic por diseño"
)]

use std::time::Instant;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::sector::pesos_por_clave;
use zx_consensus::transicion::votos::{
    CADUCIDAD_TABLA_VENTANAS, PRIMA_DISPONIBILIDAD_ACTIVA, aplicar_certificado_peso_con_undo,
};
use zx_consensus::transicion::{Estado, Fase, Garantia};
use zx_core::{
    Amount, BlockHash, ClavePublica as ClaveEd, ClaveTablaVoto, Digest, OperacionAlmacenamiento,
};
use zx_votos::{
    Clave, ClavePublica, ClaveSecreta, ErrorVotos, FuenteSectores, Hash, Tabla, clave_desde_fuente,
    hash_tabla,
};

use super::{ConfigMotorVotos, MotorVotos, deserializar_voto_peso, serial_certificado_peso};

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

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

fn cand(byte: u8) -> BlockHash {
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
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT)?,
    );
    Ok((con_cola, indices))
}

/// Añade un sector activo más a `clave` (cambio de peso que el consenso derivará).
fn agregar_sector(est: &mut Estado, indice: u8, k: u16) {
    let p = est.parametros_sector;
    let (id, reg) = registro(&p, ed(indice), k);
    est.sectores.insert(id, reg);
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

fn payload_de(tabla: &Tabla) -> Vec<ClaveTablaVoto> {
    tabla
        .claves
        .iter()
        .map(|c| {
            let clave_bls = <[u8; 48]>::try_from(c.clave.as_slice()).expect("clave BLS de 48 B");
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

/// Huella siguiente declarada por la instancia abierta del motor.
fn h_declarada(m: &MotorVotos) -> Hash {
    m.instancia
        .as_ref()
        .expect("instancia abierta")
        .h_t_siguiente
}

/// Tabla que acompaña a la huella declarada (la que el motor adjuntaría al certificado).
fn tabla_adjunta(m: &MotorVotos) -> Tabla {
    m.instancia
        .as_ref()
        .expect("instancia abierta")
        .tabla_siguiente
        .clone()
}

/// Copia del `construir_tabla` histórico: valida las claves **sin** memoria. Referencia de N5.
fn construir_tabla_sin_memoria(
    n: u64,
    estado: &Estado,
    slot: i64,
) -> Result<(Tabla, Vec<ClavePublica>), ErrorVotos> {
    let pesos = pesos_por_clave(estado, slot, &estado.parametros_sector);
    let mut claves: Vec<Clave> = Vec::new();
    let mut pubs: Vec<ClavePublica> = Vec::new();
    for (clave_ed, clave_voto) in &estado.claves_voto {
        let peso = pesos.get(clave_ed).copied().unwrap_or(0);
        if peso <= 0 {
            continue;
        }
        let Ok(pk) = ClavePublica::desde_bytes(&clave_voto.clave_bls) else {
            continue;
        };
        let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && estado.pruebas.contains_key(clave_ed);
        let peso = u64::try_from(peso).map_err(|_| ErrorVotos::Desbordamiento)?;
        let clave_tabla =
            clave_desde_fuente(&clave_voto.clave_bls, true, prueba, peso, &FuenteSectores)?;
        claves.push(clave_tabla);
        pubs.push(pk);
    }
    Ok((Tabla { n, claves }, pubs))
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 1 · N1 declara la última huella de la cola del candidato (con un cambio de peso ya derivado)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n1_declara_la_ultima_huella_de_la_cola_del_candidato() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    // Cambio de peso que el estado ya derivó: una cuarta identidad entra en la tabla.
    let (estado4, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let (t_base, _) = super::construir_tabla(1, &estado, SLOT)?;
    let (t_der, _) = super::construir_tabla(2, &estado4, SLOT)?;
    let h_base = hash_tabla(&t_base);
    let h_der = hash_tabla(&t_der);
    assert_ne!(h_base, h_der, "el cambio de peso cambia la huella");

    let mut est = estado.clone();
    est.finalidad_votos = Some(cand(0x01));
    est.finalidad_votos_n = 1;
    est.finalidad_votos_h_t = Some(h_base);
    est.tablas_voto_contenido
        .insert(h_base, payload_de(&t_base));
    est.tablas_voto_contenido.insert(h_der, payload_de(&t_der));
    est.cola_tablas_voto.push((1, h_base));
    est.cola_tablas_voto.push((1, h_der));

    let mut m = motor_peso(&secretas, true)?;
    m.sembrar_base_de_estado(1, h_base, *cand(0x01).as_bytes())?;
    let paso = m.avanzar(2, cand(0x22), &est, SLOT)?;
    assert_eq!(
        h_declarada(&m),
        h_der,
        "N1: declara la última huella de Q del estado del candidato"
    );
    let voto = deserializar_voto_peso(&paso.votos[0])?;
    assert_eq!(
        voto.h_t_siguiente, h_der,
        "el voto firmado lleva la huella declarada"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 2 · P2: dos nodos con el mismo candidato y distinta punta declaran la misma huella
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n1_dos_nodos_mismo_candidato_distinta_punta_misma_huella() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let (t_base, _) = super::construir_tabla(1, &estado, SLOT)?;
    let h_base = hash_tabla(&t_base);
    // Dos tablas distintas (distinta punta): se reetiquetan pesos para cambiar la huella.
    let mut t_a = t_base.clone();
    t_a.claves[0].peso += 1;
    let mut t_b = t_base.clone();
    t_b.claves[1].peso += 2;
    let h_a = hash_tabla(&t_a);
    let h_b = hash_tabla(&t_b);
    assert_ne!(h_a, h_b);

    let (estado4, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let (t_q, _) = super::construir_tabla(2, &estado4, SLOT)?;
    let h_q = hash_tabla(&t_q);

    let mut est = estado.clone();
    est.finalidad_votos = Some(cand(0x01));
    est.finalidad_votos_n = 3;
    est.finalidad_votos_h_t = Some(h_base);
    est.tablas_voto_contenido
        .insert(h_base, payload_de(&t_base));
    est.tablas_voto_contenido.insert(h_a, payload_de(&t_a));
    est.tablas_voto_contenido.insert(h_b, payload_de(&t_b));
    est.tablas_voto_contenido.insert(h_q, payload_de(&t_q));
    est.cola_tablas_voto.push((3, h_base));
    est.cola_tablas_voto.push((3, h_q));

    // Puntas distintas (bases distintas), mismo estado del pasado del candidato.
    let mut m1 = motor_peso(&secretas, true)?;
    let mut m2 = motor_peso(&secretas, true)?;
    m1.sembrar_base_de_estado(5, h_a, *cand(0x01).as_bytes())?;
    m2.sembrar_base_de_estado(5, h_b, *cand(0x01).as_bytes())?;
    m1.avanzar(6, cand(0x66), &est, SLOT)?;
    m2.avanzar(6, cand(0x66), &est, SLOT)?;
    assert_eq!(
        h_declarada(&m1),
        h_declarada(&m2),
        "P2: mismo candidato ⇒ misma huella declarada aunque la punta difiera"
    );
    assert_eq!(h_declarada(&m1), h_q, "y es la última de Q");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 3 · sin base declara la tabla con la que firma
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n1_sin_base_declara_la_tabla_con_la_que_firma() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    assert!(estado.finalidad_votos_h_t.is_none());
    let mut m = motor_peso(&secretas, true)?;
    m.avanzar(2, cand(0x22), &estado, SLOT)?;
    let ancla = hash_tabla(m.tabla_actual().expect("tabla abierta"));
    assert_eq!(
        h_declarada(&m),
        ancla,
        "sin base: declara la huella de la tabla con la que firma"
    );
    assert_eq!(
        hash_tabla(&tabla_adjunta(&m)),
        ancla,
        "y la tabla adjunta es esa misma"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 4 · base caducada declara la tabla con la que firma
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n1_base_caducada_declara_la_tabla_con_la_que_firma() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let (t_base, _) = super::construir_tabla(1, &estado, SLOT)?;
    let (estado4, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let (t_q, _) = super::construir_tabla(2, &estado4, SLOT)?;
    let h_base = hash_tabla(&t_base);
    let h_q = hash_tabla(&t_q);
    assert_ne!(h_base, h_q);

    let m0 = 1u64;
    let n = m0 + CADUCIDAD_TABLA_VENTANAS + 1; // la base del estado ya está caducada
    let mut est = estado.clone();
    est.finalidad_votos = Some(cand(0x01));
    est.finalidad_votos_n = m0;
    est.finalidad_votos_h_t = Some(h_base);
    est.tablas_voto_contenido
        .insert(h_base, payload_de(&t_base));
    est.tablas_voto_contenido.insert(h_q, payload_de(&t_q));
    est.cola_tablas_voto.push((m0, h_base));
    est.cola_tablas_voto.push((m0, h_q)); // cola no vacía: solo la caducidad fuerza el repliegue

    // La base del motor no está caducada (como cuando el nodo ya certificó por delante del estado):
    // el reloj abre la ventana y N1 decide con el estado del candidato.
    let mut m = motor_peso(&secretas, true)?;
    m.sembrar_base_de_estado(n - 1, h_base, *cand(0x01).as_bytes())?;
    m.avanzar(n, cand(0x44), &est, SLOT)?;
    // TB4-R7 · con la base caducada el votante declara la **última de `Q`** (antes declaraba el
    // ancla); sigue firmando con la tabla de su base.
    assert_eq!(
        h_declarada(&m),
        h_q,
        "base caducada: declara la última de la cola (TB4-R7)"
    );
    assert_eq!(
        hash_tabla(m.tabla_actual().expect("tabla abierta")),
        h_base,
        "y firma con la tabla de la base"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 5 · cola vacía declara la tabla con la que firma
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n1_cola_vacia_declara_la_tabla_con_la_que_firma() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let (t_base, _) = super::construir_tabla(1, &estado, SLOT)?;
    let h_base = hash_tabla(&t_base);
    let mut est = estado.clone();
    // TB-1c-2 · el montaje compartido siembra la cola; esta prueba fija el caso de **cola vacía**.
    est.cola_tablas_voto.clear();
    est.ultima_ventana_derivada_sin_base = None;
    est.finalidad_votos = Some(cand(0x01));
    est.finalidad_votos_n = 1;
    est.finalidad_votos_h_t = Some(h_base);
    est.tablas_voto_contenido
        .insert(h_base, payload_de(&t_base));
    assert!(est.cola_tablas_voto.is_empty());

    let mut m = motor_peso(&secretas, true)?;
    m.sembrar_base_de_estado(1, h_base, *cand(0x01).as_bytes())?;
    m.avanzar(2, cand(0x22), &est, SLOT)?;
    assert_eq!(
        h_declarada(&m),
        h_base,
        "cola vacía: declara la huella de la tabla con la que firma"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 6 · adjunta el contenido de la huella declarada
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n1_adjunta_el_contenido_de_la_huella_declarada() -> Result<(), Error> {
    let (estado, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let (t_base, _) = super::construir_tabla(1, &estado, SLOT)?;
    let (estado4, _) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let (mut t_q, _) = super::construir_tabla(2, &estado4, SLOT)?;
    // El consenso guarda el contenido en orden canónico por bytes de clave BLS.
    t_q.claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    let h_base = hash_tabla(&t_base);
    let h_q = hash_tabla(&t_q);
    assert_ne!(h_base, h_q);

    let mut est = estado.clone();
    est.finalidad_votos = Some(cand(0x01));
    est.finalidad_votos_n = 1;
    est.finalidad_votos_h_t = Some(h_base);
    est.tablas_voto_contenido
        .insert(h_base, payload_de(&t_base));
    est.tablas_voto_contenido.insert(h_q, payload_de(&t_q));
    est.cola_tablas_voto.push((1, h_base));
    est.cola_tablas_voto.push((1, h_q));

    let mut m = motor_peso(&secretas, true)?;
    m.sembrar_base_de_estado(1, h_base, *cand(0x01).as_bytes())?;
    m.avanzar(2, cand(0x22), &est, SLOT)?;
    assert_eq!(h_declarada(&m), h_q);
    let adjunta = tabla_adjunta(&m);
    assert_eq!(
        hash_tabla(&adjunta),
        h_q,
        "la tabla adjunta es el contenido de la huella declarada"
    );
    assert_eq!(
        payload_de(&adjunta),
        payload_de(&t_q),
        "el contenido es el del estado, no una tabla construida por el nodo"
    );

    // Al cerrar, el certificado declara esa huella; la tabla ya **no** viaja (T2).
    let paso = m.avanzar(3, cand(0x33), &est, SLOT)?;
    let cert = paso.certificado_peso.expect("la ventana 2 certifica");
    assert_eq!(cert.h_t_siguiente, h_q);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 7 · veinte ventanas con cambios de peso y el consenso real las acepta
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n1_veinte_ventanas_con_cambios_de_peso_el_consenso_las_acepta() -> Result<(), Error> {
    let (mut est, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_peso(&secretas, true)?;
    // Abre la ventana 1 con el estado génesis.
    motor.avanzar(1, cand(0x01), &est, SLOT)?;

    let mut aplicados = 0usize;
    let mut extra: u16 = 0;
    for n in 2u64..=60 {
        let paso = motor.avanzar(n, cand(n as u8), &est, SLOT)?;
        let Some(cert) = paso.certificado_peso.clone() else {
            continue;
        };
        // El slot de aplicación es la apertura de la ventana certificada (T9 no la rechaza).
        let slot_app = i64::try_from(cert.n.saturating_mul(2)).unwrap_or(i64::MAX);
        let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&est, &op_cert(&cert), slot_app);
        r?; // ningún certificado se rechaza por su tabla
        assert_eq!(nuevo.finalidad_votos_n, cert.n);
        est = nuevo;
        aplicados += 1;
        // Cambio de peso real: entran sectores nuevos a las tres identidades.
        if aplicados.is_multiple_of(2) {
            extra += 1;
            for i in [1u8, 2, 3] {
                agregar_sector(&mut est, i, extra);
            }
        }
        if aplicados >= 22 {
            break;
        }
    }
    assert!(
        aplicados >= 20,
        "se aplicaron {aplicados} certificados y ninguno se rechazó por su tabla"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 8 · la tabla del nodo es igual con y sin memoria
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn n5_tabla_del_nodo_igual_con_y_sin_memoria() -> Result<(), Error> {
    let pool: Vec<u8> = (1..=12u8).collect();
    let mut claves: Vec<(u8, u16, i64)> = Vec::new();
    for i in &pool {
        claves.push((*i, 1 + u16::from(*i % 3), DEN));
    }
    let (estado, _) = estado_sectores(&claves)?;
    let (con_memoria, pubs_memoria) = super::construir_tabla(1, &estado, SLOT)?;
    let (sin_memoria, pubs_sin_memoria) = construir_tabla_sin_memoria(1, &estado, SLOT)?;
    assert_eq!(
        con_memoria, sin_memoria,
        "N5: la tabla no cambia al validar las claves con memoria"
    );
    assert_eq!(
        pubs_memoria, pubs_sin_memoria,
        "N5: las claves públicas tampoco cambian"
    );
    // Una segunda pasada (ya en memoria) da lo mismo que la primera.
    let (repetida, pubs_repetida) = super::construir_tabla(1, &estado, SLOT)?;
    assert_eq!(con_memoria, repetida);
    assert_eq!(pubs_memoria, pubs_repetida);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Banco · construir_tabla con 4 096 y 65 536 claves, primera vez y siguientes
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Clave Ed25519 sintética y distinta por índice (banco).
fn ed_i(i: usize) -> ClaveEd {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
    ClaveEd::desde_bytes(b)
}

/// Par BLS real y distinto por índice (semilla determinista; banco).
fn par_bls_i(i: usize) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
    ikm[30] = 0xB1;
    ikm[31] = 0x7A;
    Ok(ClaveSecreta::generar(&ikm)?)
}

/// Estado con las claves `[base, base + n)` de voto activas (peso 1 cada una). El offset hace que
/// dos tamaños distintos usen claves **disjuntas**, de modo que la primera pasada de cada uno
/// encuentre la memoria de claves fría.
fn estado_n(n: usize, base: usize) -> Result<Estado, Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    for i in 0..n {
        let indice = base.saturating_add(i);
        let s = par_bls_i(indice)?;
        let pk = s.clave_publica();
        let e = ed_i(indice);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, e, 0);
        est.sectores.insert(id, reg);
    }
    Ok(est)
}

#[test]
#[ignore = "TB-1b · banco de construir_tabla; se ejecuta a mano en el bloque 0 (--release)"]
fn banco_tb1b() -> Result<(), Error> {
    let ns: Vec<usize> = std::env::var("TB1B_NS")
        .unwrap_or_else(|_| "4096,65536".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let reps: usize = std::env::var("TB1B_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    println!("TB1B HDR reps {reps} ns {ns:?}");
    let mut base = 0usize;
    for &n in &ns {
        let t_prep = Instant::now();
        let estado = estado_n(n, base)?;
        base = base.saturating_add(n);
        println!("TB1B PREP N {n} ns {}", t_prep.elapsed().as_nanos());
        // Primera vez: la validación de claves llena la memoria del proceso.
        let t0 = Instant::now();
        let (tabla, pubs) = super::construir_tabla(1, &estado, SLOT)?;
        println!(
            "TB1B SAMPLE N {n} OP construir_tabla REP primera ns {} claves {}",
            t0.elapsed().as_nanos(),
            tabla.claves.len()
        );
        std::hint::black_box(&(tabla, pubs));
        // Siguientes: claves ya en memoria.
        for rep in 0..reps {
            let t = Instant::now();
            let (tabla, pubs) = super::construir_tabla(1, &estado, SLOT)?;
            println!(
                "TB1B SAMPLE N {n} OP construir_tabla REP {rep} ns {} claves {}",
                t.elapsed().as_nanos(),
                tabla.claves.len()
            );
            std::hint::black_box(&(tabla, pubs));
        }
    }
    println!("TB1B FIN");
    Ok(())
}
