//! TB-1c-2 · reglas X1 (T1′) y X2 (T5′) del paso 3, contrato v1.3: sin base, la cadena deriva una
//! tabla al cruzar cada ventana y el primer certificado vale si su huella declarada está en la cola,
//! usando el contenido de esa huella como tabla vigente.
//!
//! Estados montados a mano con sectores reales y firmas BLS reales (mismo estilo que `tb1a_cola.rs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::similar_names,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::tipos::K_TABLAS_VOTO;
use zx_consensus::transicion::votos::{
    T_INST_VOTOS, aplicar_certificado_peso_con_undo, derivar_tabla_sin_base_con_undo,
    tabla_canonica, tabla_derivada,
};
use zx_consensus::transicion::{ErrorTransicion, Estado, Fase, deshacer};
use zx_core::{BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

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

fn registro(
    p: &ParametrosSector,
    clave: ClavePublica,
    indice: u16,
    etapa: Etapa,
    alta_slot: i64,
    renovacion_slot: i64,
) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    let reg = RegistroSector {
        id,
        r2: [0; 4],
        history_size: 1,
        etapa,
        alta_slot,
        renovacion_slot,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado PoST con las claves 1..=3 (sector activo). Con `con_diferida`, añade la clave 4 con un
/// sector `Precomprometido` que se activa en el slot `50 + m_sec = 62`.
fn estado_cola(con_diferida: bool) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for i in 1u8..=3 {
        let s = bls(i)?;
        est.claves_voto.insert(
            ed(i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, ed(i), 0, Etapa::Activo, 0, 10_000);
        est.sectores.insert(id, reg);
        secretas.push((i, s));
    }
    if con_diferida {
        let s = bls(4)?;
        est.claves_voto.insert(
            ed(4),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, ed(4), 0, Etapa::Precomprometido, 50, 0);
        est.sectores.insert(id, reg);
        secretas.push((4, s));
    }
    Ok((est, secretas))
}

/// Añade a `est` la clave `i` con un sector activo (para que su tabla derivada cambie).
fn añadir_clave_activa(est: &mut Estado, i: u8) -> Result<(), Error> {
    let s = bls(i)?;
    est.claves_voto.insert(
        ed(i),
        ClaveVoto {
            clave_bls: s.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let (id, reg) = registro(&est.parametros_sector, ed(i), 0, Etapa::Activo, 0, 10_000);
    est.sectores.insert(id, reg);
    Ok(())
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

fn tabla_contrato(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves.iter().map(clave_contrato).collect(),
    }
}

fn hash_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_contrato(0, claves))
}

fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

/// Certificado compacto `0x09` con firmas BLS reales sobre A3 (raíz cero).
///
/// Firma con `tabla` (el mapa indexa esa tabla) y declara `h_t_siguiente`.
fn op_cert(
    est: &Estado,
    secretas: &[(u8, ClaveSecreta)],
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    tabla: &[ClaveTablaVoto],
    firmantes: &[u8],
) -> Result<OperacionAlmacenamiento, Error> {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &[0u8; 32]);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for i in firmantes {
        let bls_i = est.claves_voto[&ed(*i)].clave_bls;
        let Some(pos) = tabla.iter().position(|c| c.clave_bls == bls_i) else {
            continue;
        };
        let f = zx_votos::firmar(secreta(secretas, *i)?, DOMINIO_VOTO, &mensaje)?;
        votos.push((pos + 1, f));
    }
    let cert = zx_votos::construir_certificado(
        n,
        candidato,
        h_t_siguiente,
        [0u8; 32],
        &tabla_contrato(n, tabla),
        &votos,
    )?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

/// Corrompe la firma BLS (96 B finales) del `0x09`, para probar el orden de las comprobaciones.
fn con_firma_corrupta(op: OperacionAlmacenamiento) -> OperacionAlmacenamiento {
    let OperacionAlmacenamiento::CertificadoPeso { clave, mut bytes } = op else {
        return op;
    };
    let n = bytes.len();
    if n >= 96 {
        for b in &mut bytes[n - 96..] {
            *b = 0;
        }
    }
    OperacionAlmacenamiento::CertificadoPeso { clave, bytes }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// X1 · el gancho de derivación sin base
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb1c2_cola_sin_base_crece_al_cruzar_ventana() -> Result<(), Error> {
    let (est, _s) = estado_cola(true)?;
    // Ventana 0 (slot 0): la diferida aún no está activa -> 3 claves.
    let (e1, _u1) = derivar_tabla_sin_base_con_undo(&est, 0);
    assert_eq!(e1.cola_tablas_voto.len(), 1, "la primera derivación encola");
    let (k0, h0) = e1.cola_tablas_voto[0];
    assert_eq!(k0, 0);
    assert_eq!(e1.ultima_ventana_derivada_sin_base, Some(0));
    // Ventana 31 (slot 62): la diferida ya está activa -> 4 claves (tabla distinta).
    let (e2, _u2) = derivar_tabla_sin_base_con_undo(&e1, 62);
    assert_eq!(
        e2.cola_tablas_voto.len(),
        2,
        "al cruzar a otra ventana crece"
    );
    let (k1, h1) = e2.cola_tablas_voto[1];
    assert_eq!(k1, 31);
    assert_ne!(h0, h1, "las tablas de las dos ventanas difieren");
    assert_eq!(e2.ultima_ventana_derivada_sin_base, Some(31));
    assert!(e2.tablas_voto_contenido.contains_key(&h0));
    assert!(e2.tablas_voto_contenido.contains_key(&h1));
    Ok(())
}

#[test]
fn tb1c2_cola_sin_base_no_anade_vacia_ni_repetida() -> Result<(), Error> {
    // (i) sin claves la tabla derivada es vacía: no añade nada.
    let mut vacio = Estado::inicial();
    vacio.fase = Fase::PoST;
    let (v1, _u) = derivar_tabla_sin_base_con_undo(&vacio, 100);
    assert!(
        v1.cola_tablas_voto.is_empty(),
        "una tabla vacía no encola entrada"
    );
    // (ii) la misma tabla en dos ventanas consecutivas no repite la huella.
    let (est, _s) = estado_cola(false)?;
    let (e1, _u1) = derivar_tabla_sin_base_con_undo(&est, 100); // k = 50
    let (e2, _u2) = derivar_tabla_sin_base_con_undo(&e1, 102); // k = 51, misma tabla
    assert_eq!(
        e2.cola_tablas_voto.len(),
        1,
        "la huella repetida no se reencola"
    );
    Ok(())
}

#[test]
fn tb1c2_cola_sin_base_una_derivacion_por_ventana() -> Result<(), Error> {
    let (est, _s) = estado_cola(false)?;
    let (e1, _u1) = derivar_tabla_sin_base_con_undo(&est, 100); // k = 50, tabla A (3 claves)
    assert_eq!(e1.cola_tablas_voto.len(), 1);
    let h_a = e1.cola_tablas_voto[0].1;
    // Entre los dos bloques de la MISMA ventana añado a propósito un sector que cambiaría la tabla:
    // si el gancho volviera a derivar, la huella sería otra y encolaría una segunda entrada.
    let mut e1_mut = e1.clone();
    añadir_clave_activa(&mut e1_mut, 4)?;
    let tabla_si_derivara = tabla_derivada(&e1_mut, 50);
    assert_ne!(
        hash_payload(&tabla_si_derivara),
        h_a,
        "el montaje hace que una segunda derivación daría otra huella"
    );
    let (e2, _u2) = derivar_tabla_sin_base_con_undo(&e1_mut, 101); // mismo k = 50
    assert_eq!(
        e2.cola_tablas_voto,
        vec![(50, h_a)],
        "el segundo bloque de la ventana no deriva (marca ultima_ventana_derivada_sin_base)"
    );
    Ok(())
}

#[test]
fn tb1c2_cola_sin_base_tope_k_y_poda() -> Result<(), Error> {
    let mut estado = Estado::inicial();
    estado.parametros_sector = ParametrosSector::dev();
    estado.fase = Fase::PoST;
    let total = K_TABLAS_VOTO + 2;
    let mut primera_huella: Option<[u8; 32]> = None;
    for j in 0..total {
        let i = u8::try_from(j + 1)?;
        añadir_clave_activa(&mut estado, i)?;
        let slot = u64::try_from(j)?.saturating_mul(T_INST_VOTOS);
        let (nuevo, _u) = derivar_tabla_sin_base_con_undo(&estado, slot);
        estado = nuevo;
        if j == 0 {
            primera_huella = Some(estado.cola_tablas_voto[0].1);
        }
    }
    assert_eq!(
        estado.cola_tablas_voto.len(),
        K_TABLAS_VOTO,
        "la cola se recorta a K"
    );
    let ventanas: Vec<u64> = estado.cola_tablas_voto.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        ventanas,
        (2..=(u64::try_from(K_TABLAS_VOTO).unwrap_or(0) + 1)).collect::<Vec<u64>>(),
        "quedan las últimas ventanas, en orden"
    );
    for (_, h) in &estado.cola_tablas_voto {
        assert!(estado.tablas_voto_contenido.contains_key(h));
    }
    if let Some(h0) = primera_huella {
        assert!(
            !estado.tablas_voto_contenido.contains_key(&h0),
            "el contenido de la entrada desalojada se podó"
        );
    }
    Ok(())
}

#[test]
fn tb1c2_cola_sin_base_deshacer_exacto() -> Result<(), Error> {
    let (est, _s) = estado_cola(true)?;
    let (nuevo, undo) = derivar_tabla_sin_base_con_undo(&est, 62);
    assert_ne!(nuevo, est, "el gancho cambió el estado");
    assert_eq!(deshacer(&nuevo, &undo), est, "el undo es exacto");
    Ok(())
}

#[test]
fn tb1c2_con_base_el_gancho_no_hace_nada() -> Result<(), Error> {
    // TB4-R1: el gancho **sí** actúa con base (el nombre histórico se conserva para no perder la
    // prueba de la referencia; lo que cambia es lo que afirma). El estado sin cola, con base, deriva
    // la tabla de la ventana y la deposita.
    let (mut est, _s) = estado_cola(true)?;
    est.finalidad_votos_n = 5;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some([0x55; 32]);
    let antes = est.clone();
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(&est, 62);
    assert_ne!(nuevo, antes, "con base el gancho también deriva");
    assert_eq!(nuevo.ultima_ventana_derivada_sin_base, Some(31));
    assert_eq!(
        nuevo.cola_tablas_voto.len(),
        1,
        "la derivada entra en la cola"
    );
    assert_eq!(nuevo.cola_tablas_voto[0].0, 31, "con su ventana fresca");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// X2 · el primer certificado contra la cola
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Coloca en la cola la derivada de la ventana del slot `slot` y devuelve `(estado, tabla, huella)`.
fn preparar_primer_certificado(
    est: &Estado,
    slot: u64,
) -> Result<(Estado, Vec<ClaveTablaVoto>, [u8; 32]), Error> {
    let (con_cola, _u) = derivar_tabla_sin_base_con_undo(est, slot);
    let k = slot / T_INST_VOTOS;
    let tabla = tabla_derivada(&con_cola, k);
    let h = hash_payload(&tabla);
    assert!(
        con_cola.cola_tablas_voto.iter().any(|(_, x)| *x == h),
        "la derivada está en la cola"
    );
    Ok((con_cola, tabla, h))
}

#[test]
fn tb1c2_primer_certificado_de_la_cola_se_acepta() -> Result<(), Error> {
    let (est, secretas) = estado_cola(true)?;
    let slot = 100u64;
    let (con_cola, tabla, h) = preparar_primer_certificado(&est, slot)?;
    let k = slot / T_INST_VOTOS;
    let op = op_cert(&con_cola, &secretas, k, [0x11; 32], h, &tabla, &[1, 2, 3])?;
    let (nuevo, _u, r) = aplicar_certificado_peso_con_undo(&con_cola, &op, i64::try_from(slot)?);
    r?;
    assert_eq!(nuevo.finalidad_votos_n, k, "la base queda en la ventana");
    assert_eq!(nuevo.finalidad_votos_h_t, Some(h));
    Ok(())
}

#[test]
fn tb1c2_primer_certificado_huella_fuera_de_la_cola_se_rechaza() -> Result<(), Error> {
    let (mut est, secretas) = estado_cola(true)?;
    let slot = 100u64;
    let k = slot / T_INST_VOTOS;
    let tabla = canoniza(tabla_canonica(&est, i64::try_from(slot)?));
    let h = hash_payload(&tabla);
    // La huella tiene contenido guardado, pero NO está en la cola (vacía).
    est.tablas_voto_contenido.insert(h, tabla.clone());
    let op = con_firma_corrupta(op_cert(
        &est,
        &secretas,
        k,
        [0x11; 32],
        h,
        &tabla,
        &[1, 2, 3],
    )?);
    let (_nuevo, _u, r) = aplicar_certificado_peso_con_undo(&est, &op, i64::try_from(slot)?);
    // La firma está corrupta: si se validara antes, el motivo sería `firma_falsa`. Se rechaza por la
    // cola, así que la pertenencia se decide antes de validar la firma.
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            zx_votos::peso::MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}

#[test]
fn tb1c2_primer_certificado_firmado_con_otra_tabla_se_rechaza() -> Result<(), Error> {
    let (est, _s) = estado_cola(false)?;
    let slot = 100u64;
    let (con_cola, tabla_a, h_a) = preparar_primer_certificado(&est, slot)?;
    let k = slot / T_INST_VOTOS;
    // Se declara una huella de la cola (A) pero se firma con otra tabla (B) de **las mismas
    // dimensiones** (3 claves distintas, para que el mapa sea válido y el rechazo sea de firma).
    let p = ParametrosSector::dev();
    let mut est_b = Estado::inicial();
    est_b.parametros_sector = p;
    est_b.fase = Fase::PoST;
    let mut secretas_b = Vec::new();
    for i in 5u8..=7 {
        let s = bls(i)?;
        est_b.claves_voto.insert(
            ed(i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, ed(i), 0, Etapa::Activo, 0, 10_000);
        est_b.sectores.insert(id, reg);
        secretas_b.push((i, s));
    }
    let tabla_b = canoniza(tabla_canonica(&est_b, i64::try_from(slot)?));
    assert_eq!(tabla_a.len(), tabla_b.len());
    let op = op_cert(
        &est_b,
        &secretas_b,
        k,
        [0x11; 32],
        h_a,
        &tabla_b,
        &[5, 6, 7],
    )?;
    let (_n, _u, r) = aplicar_certificado_peso_con_undo(&con_cola, &op, i64::try_from(slot)?);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            zx_votos::peso::MotivoPeso::FirmaFalsa
        )),
        "el motivo es de firma, no de tabla"
    );
    Ok(())
}

#[test]
fn tb1c2_primer_certificado_no_usa_la_ultima_sino_cualquiera_de_la_cola() -> Result<(), Error> {
    let (est, secretas) = estado_cola(false)?;
    // Ventana 50 (slot 100): tabla A de 3 claves.
    let (e1, _u1) = derivar_tabla_sin_base_con_undo(&est, 100);
    // Ventana 51 (slot 102): madura otro sector -> tabla B (4 claves), que queda como última.
    let mut con_sector = e1.clone();
    añadir_clave_activa(&mut con_sector, 4)?;
    let (e2, _u2) = derivar_tabla_sin_base_con_undo(&con_sector, 102);
    assert_eq!(e2.cola_tablas_voto.len(), 2);
    let (ka, h_a) = e2.cola_tablas_voto[0];
    let (kb, h_b) = e2.cola_tablas_voto[1];
    assert_ne!(h_a, h_b);
    let tabla_a = e2
        .tablas_voto_contenido
        .get(&h_a)
        .cloned()
        .ok_or("contenido de A")?;
    // Se declara la MÁS ANTIGUA (A) y se firma con su contenido: se acepta aunque B sea la última.
    let op = op_cert(&e2, &secretas, ka, [0x11; 32], h_a, &tabla_a, &[1, 2])?;
    let (nuevo, _u3, r) = aplicar_certificado_peso_con_undo(&e2, &op, 100);
    r?;
    assert_eq!(nuevo.finalidad_votos_n, ka);
    assert_eq!(nuevo.finalidad_votos_h_t, Some(h_a));
    let _ = kb;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Coste de X1 (medida `#[ignore]`, sin candado exclusivo; ORDEN-TB1C-2 §4, TB-1C-3 §2)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Coste del gancho X1 con 65 536 identidades (una clave de voto y un sector activo cada una),
/// cuando **deriva** (ventana nueva) y cuando **no** (misma ventana ya derivada).
#[test]
#[ignore = "medida manual del coste de X1; se corre con --ignored"]
fn medida_x1_65536_identidades() {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    for i in 0..65_536u32 {
        let mut kb = [0u8; 32];
        kb[0..4].copy_from_slice(&i.to_le_bytes());
        let e = ClavePublica::desde_bytes(kb);
        let mut clave_bls = [0u8; 48];
        clave_bls[0..4].copy_from_slice(&i.to_le_bytes());
        // `tabla_derivada` no valida la clave BLS: basta un valor determinista de 48 B.
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls,
                prueba_posesion: [0u8; 96],
            },
        );
        let id = SectorId {
            clave: e,
            sector_index: 0,
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
                id,
                r2: [0u64; 4],
                history_size: 1,
                etapa: Etapa::Activo,
                alta_slot: 0,
                renovacion_slot: 1_000_000,
                retiro_slot: -1,
                fianza: p.q_sec,
                aud_apertura: -1,
                aud_contestada: -1,
            },
        );
    }
    let t0 = std::time::Instant::now();
    let (con, _u) = derivar_tabla_sin_base_con_undo(&est, 0);
    let t_deriva = t0.elapsed();
    assert_eq!(
        con.cola_tablas_voto.len(),
        1,
        "la primera derivación encola"
    );
    let t1 = std::time::Instant::now();
    let (sin, _u2) = derivar_tabla_sin_base_con_undo(&con, 0);
    let t_no = t1.elapsed();
    assert_eq!(sin.cola_tablas_voto.len(), 1, "la segunda no añade");
    println!("X1 65536: deriva={t_deriva:?} no_deriva={t_no:?}");
}
