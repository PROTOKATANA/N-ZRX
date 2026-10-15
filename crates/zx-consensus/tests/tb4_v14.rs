//! TB4 · tabla v1.4 en la cadena: TB4-R1 (derivación por ventana también con base), TB4-R2 (qué
//! guarda la cola `Q`), TB4-R3/P2 (tope de edad `X` derivado), TB4-R4 (el rearranque verifica con la
//! instantánea y compromete la fresca), TB4-R5 (la ventana de rearranque cierra en la fase activa),
//! TB4-R6 (un solo dueño de `Q`) y P5 (la repetición cumple el tope).
//!
//! Estados y firmas reales (BLS), con la transición real (`aplicar_certificado_peso_con_undo`,
//! `derivar_tabla_sin_base_con_undo`, `tomar_instantaneas_rearranque_con_undo`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::similar_names,
    missing_docs,
    reason = "pruebas de escenario con estados construidos a mano; fallan con panic por diseño"
)]

use zx_consensus::sectores::{
    ClaveVoto, Etapa, MotivoSector, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::tipos::K_TABLAS_VOTO;
use zx_consensus::transicion::votos::{
    T_INST_VOTOS, apertura_ventana, aplicar_certificado_peso_con_undo, calendario_rearranque,
    cierre_ventana, derivar_tabla_sin_base_con_undo, tabla_derivada,
    tomar_instantaneas_rearranque_con_undo, tope_edad_tabla_ventanas,
};
use zx_consensus::transicion::{
    ErrorTransicion, Estado, Fase, Garantia, aplicar_almacenamiento_con_undo,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, MotivoPeso, Tabla};

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

/// Clave BLS nueva para rotar la de `indice` (distinta de [`bls`] y determinista).
fn bls_rot(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[1] = 0x5A;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
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
        renovacion_slot: 1_000_000,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Tres identidades reales (Ed25519 + clave BLS) con un sector activo y garantía `activo = 50`.
fn estado_base() -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    est.terminal = Some(hash(1));
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
        let (id, reg) = registro(&p, ed(i), 0);
        est.sectores.insert(id, reg);
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(50)?;
        est.garantias.insert(ed(i), g);
        secretas.push((i, s));
    }
    est.emitido = 150;
    Ok((est, secretas))
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

/// `hash_tabla` del payload (no depende de `n`).
fn hash_tabla_voto(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_contrato(0, claves))
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

/// Fija la base `m` con la tabla `t` como vigente y deja su contenido guardado.
fn poner_tabla_base(est: &mut Estado, m: u64, t: &[ClaveTablaVoto]) {
    let h = hash_tabla_voto(t);
    est.finalidad_votos_n = m;
    est.finalidad_votos = Some(hash(7));
    est.finalidad_votos_h_t = Some(h);
    est.tablas_voto_contenido.insert(h, t.to_vec());
    est.tablas_voto.insert(m, t.to_vec());
    est.cola_tablas_voto.clear();
    est.cola_tablas_voto.push((m, h));
    est.liquidacion_voto_hasta = Some(m);
}

/// Certificado `0x09` con firmas BLS reales; cada firmante se localiza en `tabla` por su clave.
fn op_certificado(
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    raiz: [u8; 32],
    tabla: &[ClaveTablaVoto],
    firmantes: &[&ClaveSecreta],
) -> Result<OperacionAlmacenamiento, Error> {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz);
    let mut votos: Vec<(usize, Firma)> = Vec::with_capacity(firmantes.len());
    for sk in firmantes {
        let publica = sk.clave_publica().bytes();
        let posicion = tabla
            .iter()
            .position(|c| c.clave_bls == publica)
            .ok_or("firmante fuera de la tabla")?;
        votos.push((posicion + 1, zx_votos::firmar(sk, DOMINIO_VOTO, &mensaje)?));
    }
    let cert = zx_votos::construir_certificado(
        n,
        candidato,
        h_t_siguiente,
        raiz,
        &tabla_contrato(n, tabla),
        &votos,
    )?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

fn op_clave_voto(clave: ClavePublica, sk: &ClaveSecreta) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::ClaveVoto {
        clave,
        clave_bls: sk.clave_publica().bytes(),
        prueba_posesion: zx_votos::probar_posesion(sk).bytes(),
    }
}

/// Aplica la rotación real `0x03` (prueba de posesión incluida) en `slot`.
fn rotar_en_clave(
    estado: &Estado,
    clave: ClavePublica,
    nueva: &ClaveSecreta,
    slot: i64,
) -> Result<Estado, Error> {
    let p = ParametrosSector::dev();
    let op = op_clave_voto(clave, nueva);
    let (rotado, _undo, motivo) = aplicar_almacenamiento_con_undo(estado, &op, slot, &p);
    assert_eq!(motivo, MotivoSector::Ok, "la rotación 0x03 debe aceptarse");
    Ok(rotado)
}

/// Tabla distinta de `t` (mismo número de claves, un peso cambiado).
fn tabla_alterada(t: &[ClaveTablaVoto]) -> Vec<ClaveTablaVoto> {
    let mut otra = t.to_vec();
    if let Some(c) = otra.first_mut() {
        c.peso = c.peso.saturating_add(1);
        c.garantia = c.garantia.saturating_add(1);
    }
    otra
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R1 · derivación por ventana también con base
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_r1_deriva_con_base_cada_ventana() -> Result<(), Error> {
    let (mut est, _s) = estado_base()?;
    let t0 = tabla_derivada(&est, 0);
    let h0 = hash_tabla_voto(&t0);
    poner_tabla_base(&mut est, 0, &t0);

    let (e1, _u) = derivar_tabla_sin_base_con_undo(&est, 2 * 10);
    assert_eq!(
        e1.ultima_ventana_derivada_sin_base,
        Some(10),
        "con base el gancho actúa"
    );
    assert!(
        e1.cola_tablas_voto
            .iter()
            .any(|(k, h)| *k == 10 && *h == h0)
    );

    let (e2, _u) = derivar_tabla_sin_base_con_undo(&e1, 2 * 11);
    assert_eq!(e2.ultima_ventana_derivada_sin_base, Some(11));
    assert_eq!(e2.cola_tablas_voto.len(), 1, "la misma tabla no se duplica");
    assert_eq!(e2.cola_tablas_voto[0], (11, h0));

    // Estado distinto (la clave 3 rota): tabla distinta, la cola crece.
    let e3 = rotar_en_clave(&e2, ed(3), &bls_rot(3)?, 1)?;
    let (e4, _u) = derivar_tabla_sin_base_con_undo(&e3, 2 * 12);
    assert_eq!(e4.cola_tablas_voto.len(), 2);
    assert_ne!(e4.cola_tablas_voto[1].1, h0);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R2 · qué guarda la cola
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_r2_cola_actualiza_ultima_ventana() -> Result<(), Error> {
    let (est, _s) = estado_base()?;
    let (e1, _u) = derivar_tabla_sin_base_con_undo(&est, 0);
    assert_eq!(e1.cola_tablas_voto.len(), 1);
    let h = e1.cola_tablas_voto[0].1;
    assert_eq!(e1.cola_tablas_voto[0].0, 0);

    let (e2, _u) = derivar_tabla_sin_base_con_undo(&e1, 2 * 5);
    assert_eq!(
        e2.cola_tablas_voto.len(),
        1,
        "un par por contenido distinto"
    );
    assert_eq!(
        e2.cola_tablas_voto[0],
        (5, h),
        "refresca su ventana sin duplicar el contenido"
    );
    assert_eq!(e2.ultima_ventana_derivada_sin_base, Some(5));
    Ok(())
}

#[test]
fn tb4_r2_sale_la_de_menor_ventana() -> Result<(), Error> {
    let (mut est, _s) = estado_base()?;
    let contenido = tabla_derivada(&est, 0);
    est.cola_tablas_voto.clear();
    // K entradas con ventanas 100..; la de menor última ventana fresca (5) va en medio.
    for j in 0..K_TABLAS_VOTO {
        let mut h = [0u8; 32];
        h[0] = 0x40u8.saturating_add(u8::try_from(j)?);
        est.tablas_voto_contenido.insert(h, contenido.clone());
        est.cola_tablas_voto.push((100 + u64::try_from(j)?, h));
    }
    let h_min = [0xEE; 32];
    est.tablas_voto_contenido.insert(h_min, contenido.clone());
    let medio = K_TABLAS_VOTO / 2;
    est.cola_tablas_voto[medio] = (5, h_min);

    // El gancho deriva una tabla nueva (la canónica) y desborda la cola.
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(&est, 2 * 200);
    assert_eq!(nuevo.cola_tablas_voto.len(), K_TABLAS_VOTO);
    assert!(
        !nuevo.cola_tablas_voto.iter().any(|(_, h)| *h == h_min),
        "sale la de menor última ventana fresca, no la primera"
    );
    let mut h100 = [0u8; 32];
    h100[0] = 0x40;
    assert!(
        nuevo.cola_tablas_voto.iter().any(|(_, h)| *h == h100),
        "la primera entrada (ventana 100) sigue: no se desaloja por posición"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R3 · tope de edad
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_r3_edad_en_el_tope_admite_y_una_mas_rechaza() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let x = tope_edad_tabla_ventanas(&p);
    assert_eq!(x, 31, "tope derivado del perfil dev");
    let (mut est, secretas) = estado_base()?;
    let t_prev = tabla_derivada(&est, 0);
    let h_prev = hash_tabla_voto(&t_prev);
    poner_tabla_base(&mut est, 100, &t_prev);
    let n = 200u64;
    let t_vieja = tabla_alterada(&t_prev);
    let h_vieja = hash_tabla_voto(&t_vieja);
    assert_ne!(h_vieja, h_prev);
    est.tablas_voto_contenido.insert(h_vieja, t_vieja.clone());
    est.cola_tablas_voto.clear();
    est.cola_tablas_voto.push((n - x, h_prev));
    est.cola_tablas_voto.push((n - x - 1, h_vieja));

    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    // Edad exactamente X: se admite.
    let cert = op_certificado(n, [0x01; 32], h_prev, [0x02; 32], &t_prev, &[k1, k2])?;
    let (post, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * n)?);
    r?;
    assert_eq!(post.finalidad_votos_h_t, Some(h_prev));

    // Edad X + 1: se rechaza sin validar firmas.
    let cert = op_certificado(n, [0x03; 32], h_vieja, [0x04; 32], &t_prev, &[k1, k2])?;
    let (_e, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * n)?);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}

#[test]
fn tb4_r3_sin_base_tambien() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let x = tope_edad_tabla_ventanas(&p);
    let (mut est, secretas) = estado_base()?;
    est.finalidad_votos = None;
    est.finalidad_votos_h_t = None;
    est.finalidad_votos_n = 0;
    let t_a = tabla_derivada(&est, 0);
    let h_a = hash_tabla_voto(&t_a);
    let t_b = tabla_alterada(&t_a);
    let h_b = hash_tabla_voto(&t_b);
    est.tablas_voto_contenido.insert(h_a, t_a.clone());
    est.tablas_voto_contenido.insert(h_b, t_b.clone());
    let n = 400u64;
    est.cola_tablas_voto.clear();
    est.cola_tablas_voto.push((n - x, h_a));
    est.cola_tablas_voto.push((n - x - 1, h_b));

    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    // Edad X: la declarada es la vigente y se firma con ella.
    let cert = op_certificado(n, [0x11; 32], h_a, [0x12; 32], &t_a, &[k1, k2])?;
    let (post, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * n)?);
    r?;
    assert_eq!(post.finalidad_votos_h_t, Some(h_a));

    // Edad X + 1: rechazada.
    let cert = op_certificado(n, [0x13; 32], h_b, [0x14; 32], &t_b, &[k1, k2])?;
    let (_e, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * n)?);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R4 · el rearranque verifica con la instantánea y compromete la fresca
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_r4_rearranque_verifica_con_la_instantanea_y_compromete_la_fresca() -> Result<(), Error> {
    let (mut base, secretas) = estado_base()?;
    base.finalidad_votos_n = 0;
    base.finalidad_votos = Some(hash(7));
    let (mut est, _u) = tomar_instantaneas_rearranque_con_undo(&base, 603);
    let h_snap = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("sin instantánea del ciclo 0")?;
    let t_snap = est
        .tablas_voto_contenido
        .get(&h_snap)
        .ok_or("sin contenido de la instantánea")?
        .clone();
    est.finalidad_votos_h_t = Some(h_snap);
    est.tablas_voto.insert(0, t_snap.clone());
    est.liquidacion_voto_hasta = Some(0);
    let (est, _u) = derivar_tabla_sin_base_con_undo(&est, 603);
    let est = rotar_en_clave(&est, ed(3), &bls_rot(3)?, 604)?;
    let (est, _u) = derivar_tabla_sin_base_con_undo(&est, 2 * 662);
    let h_fresca = est.cola_tablas_voto.last().ok_or("sin fresca")?.1;
    let t_fresca = est
        .tablas_voto_contenido
        .get(&h_fresca)
        .ok_or("sin contenido de la fresca")?
        .clone();
    assert_ne!(h_fresca, h_snap, "la fresca trae la clave nueva");

    let k1_vieja = bls(1)?;
    let k2 = secreta(&secretas, 2)?;
    // Verifica con la instantánea (las claves viejas) y compromete la fresca.
    let cert = op_certificado(
        662,
        [0x21; 32],
        h_fresca,
        [0x22; 32],
        &t_snap,
        &[&k1_vieja, k2],
    )?;
    let (post, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, 1_324);
    r?;
    assert_eq!(post.finalidad_votos_n, 662);
    assert_eq!(
        post.finalidad_votos_h_t,
        Some(h_fresca),
        "la vigente es la fresca, no la instantánea"
    );
    assert!(
        post.tabla_ciclo_rearranque.is_empty(),
        "Y2 borra la instantánea al avanzar la base"
    );

    // La instantánea ya no es admisible como siguiente en la ventana normal siguiente.
    let cert = op_certificado(
        663,
        [0x23; 32],
        h_snap,
        [0x24; 32],
        &t_fresca,
        &[&bls_rot(3)?, secreta(&secretas, 1)?],
    )?;
    let (_e, _u, r) = aplicar_certificado_peso_con_undo(&post, &cert, 1_326);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R5 · la ventana de rearranque cierra en la fase activa
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_r5_cierra_en_la_fase_activa_662_si_663_no() {
    let cal = calendario_rearranque(&ParametrosSector::dev(), 0).expect("calendario dev");
    assert_eq!(cal.a, 65);
    assert_eq!(apertura_ventana(662), 1_324);
    assert_eq!(cierre_ventana(662), 1_326);
    assert_eq!(cal.ciclo_de_apertura(apertura_ventana(662)), Some(0));
    assert_eq!(cal.ciclo_de_apertura(apertura_ventana(663)), None);
    assert!(
        cierre_ventana(662) < cal.inicio(0) + cal.a,
        "la 662 cierra dentro"
    );
    assert!(
        cierre_ventana(663) >= cal.inicio(0) + cal.a,
        "la 663 cierra fuera"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P5 · la repetición cumple el tope
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_p5_repeticion_cumple_el_tope() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let x = tope_edad_tabla_ventanas(&p);
    let (mut est, secretas) = estado_base()?;
    let t_prev = tabla_derivada(&est, 0);
    let h_prev = hash_tabla_voto(&t_prev);
    let m = 199u64;
    poner_tabla_base(&mut est, m, &t_prev);
    let n = 200u64;
    let t_fuera = tabla_alterada(&t_prev);
    let h_fuera = hash_tabla_voto(&t_fuera);
    est.tablas_voto_contenido.insert(h_fuera, t_fuera.clone());
    est.cola_tablas_voto.clear();
    est.cola_tablas_voto.push((n, h_prev));
    est.cola_tablas_voto.push((n - x - 1, h_fuera));

    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    let cert = op_certificado(n, [0x31; 32], h_prev, [0x32; 32], &t_prev, &[k1, k2])?;
    let (aplicado, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * n)?);
    r?;
    assert_eq!(aplicado.finalidad_votos_n, n);
    assert_eq!(aplicado.finalidad_votos_h_t, Some(h_prev));

    // La repetición del mismo certificado es idempotente.
    let (_rep, _u, r) = aplicar_certificado_peso_con_undo(&aplicado, &cert, i64::try_from(2 * n)?);
    r?;

    // Una repetición de la misma ventana con una tabla fuera del tope se rechaza igual.
    let cert_fuera = op_certificado(n, [0x33; 32], h_fuera, [0x34; 32], &t_prev, &[k1, k2])?;
    let (_e, _u, r) =
        aplicar_certificado_peso_con_undo(&aplicado, &cert_fuera, i64::try_from(2 * n)?);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB4-R6 · la aplicación no refresca la edad de la tabla comprometida
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_salir_y_volver_no_refresca_la_edad() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let x = tope_edad_tabla_ventanas(&p);
    let (mut est, secretas) = estado_base()?;
    let t_prev = tabla_derivada(&est, 0);
    let h_prev = hash_tabla_voto(&t_prev);
    poner_tabla_base(&mut est, 0, &t_prev);
    est.cola_tablas_voto.clear();
    est.cola_tablas_voto.push((0, h_prev));

    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    // A la edad exacta X se admite que la vuelva a comprometer.
    let cert = op_certificado(x, [0x41; 32], h_prev, [0x42; 32], &t_prev, &[k1, k2])?;
    let (post, _u, r) = aplicar_certificado_peso_con_undo(&est, &cert, i64::try_from(2 * x)?);
    r?;
    assert_eq!(post.finalidad_votos_h_t, Some(h_prev));
    assert_eq!(
        post.cola_tablas_voto,
        vec![(0, h_prev)],
        "la aplicación no refresca la ventana de `Q`"
    );

    // A la edad X + 1 ya no: ser la vigente no rejuvenece la tabla.
    let cert2 = op_certificado(x + 1, [0x43; 32], h_prev, [0x44; 32], &t_prev, &[k1, k2])?;
    let (_e, _u, r) = aplicar_certificado_peso_con_undo(&post, &cert2, i64::try_from(2 * (x + 1))?);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Régimen denso · sin cambios de resultado
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tb4_regimen_denso_sin_cambios_de_resultado() -> Result<(), Error> {
    let (mut est, secretas) = estado_base()?;
    let t0 = tabla_derivada(&est, 0);
    let h0 = hash_tabla_voto(&t0);
    poner_tabla_base(&mut est, 0, &t0);
    let mut actual = est;
    let k1 = secreta(&secretas, 1)?;
    let k2 = secreta(&secretas, 2)?;
    for i in 1..=20u64 {
        // El gancho por ventana mantiene `Q` fresca, como el bloque real.
        let (con_q, _u) = derivar_tabla_sin_base_con_undo(&actual, i * T_INST_VOTOS);
        actual = con_q;
        let cert = op_certificado(
            i,
            [0xB0u8.wrapping_add(u8::try_from(i)?); 32],
            h0,
            [0xB1; 32],
            &t0,
            &[k1, k2],
        )?;
        let (nuevo, _u, r) =
            aplicar_certificado_peso_con_undo(&actual, &cert, i64::try_from(i * T_INST_VOTOS)?);
        r?;
        actual = nuevo;
        assert_eq!(actual.finalidad_votos_n, i);
        assert_eq!(
            actual.finalidad_votos_h_t,
            Some(h0),
            "una tabla estable sigue certificando en régimen denso"
        );
        assert!(actual.cola_tablas_voto.len() <= K_TABLAS_VOTO);
    }
    Ok(())
}

/// A→B→A por alta y retirada reales del peso de un sector; Q solo la escribe el gancho.
fn estado_vuelta() -> Result<(Estado, [u8; 32], [u8; 32]), Error> {
    use zx_consensus::transicion::sector::aplicar_operacion_con_undo;
    use zx_core::OperacionSector;

    let (mut est, _) = estado_base()?;
    est.garantias.get_mut(&ed(3)).ok_or("sin garantía")?.activo = Amount::nuevo(1_000)?;
    est.emitido = 1_100;
    let (mut est, _) = derivar_tabla_sin_base_con_undo(&est, 0);
    let h_a = est.cola_tablas_voto.last().ok_or("sin A")?.1;
    let p = est.parametros_sector;
    let alta = OperacionSector::Alta {
        clave: ed(3),
        sector_index: 1,
        version: 0,
        r2: [0; 32],
        history_size: 1,
    };
    let (nuevo, r) = aplicar_operacion_con_undo(&est, &alta, 1, &p);
    assert_eq!(r.motivo, MotivoSector::Ok, "alta real");
    est = nuevo;
    for k in 1..=7 {
        (est, _) = derivar_tabla_sin_base_con_undo(&est, k * T_INST_VOTOS);
    }
    let h_b = est.cola_tablas_voto.last().ok_or("sin B")?.1;
    assert_ne!(h_a, h_b, "el sector maduro cambia el peso derivado");
    for op in [
        OperacionSector::CerrarCaja {
            clave: ed(3),
            seq: 1,
        },
        OperacionSector::RetirarCaja {
            clave: ed(3),
            seq: 1,
        },
    ] {
        let (nuevo, r) = aplicar_operacion_con_undo(&est, &op, 15, &p);
        assert_eq!(r.motivo, MotivoSector::Ok, "cierre/retirada reales");
        est = nuevo;
    }
    (est, _) = derivar_tabla_sin_base_con_undo(&est, 8 * T_INST_VOTOS);
    assert_eq!(
        hash_tabla_voto(&tabla_derivada(&est, 8)),
        h_a,
        "la derivada vuelve a A"
    );
    Ok((est, h_a, h_b))
}

#[test]
fn tb4_vuelta_la_refrescada_es_la_ultima_de_la_cola() -> Result<(), Error> {
    let (est, h_a, h_b) = estado_vuelta()?;
    assert_eq!(est.cola_tablas_voto.len(), 2, "una entrada por contenido");
    for h in [h_a, h_b] {
        assert_eq!(
            est.cola_tablas_voto
                .iter()
                .filter(|(_, entrada)| *entrada == h)
                .count(),
            1
        );
    }
    assert_eq!(
        est.cola_tablas_voto.last(),
        Some(&(8, h_a)),
        "la última es A fresca"
    );
    Ok(())
}

#[test]
fn tb4_r2_la_refrescada_pasa_al_final() -> Result<(), Error> {
    use zx_consensus::transicion::deshacer;

    let (est, h_a, h_b) = estado_vuelta()?;
    assert_eq!(est.cola_tablas_voto, vec![(7, h_b), (8, h_a)]);
    let antes = est.clone();
    let (fresca, undo) = derivar_tabla_sin_base_con_undo(&antes, 18);
    assert_eq!(fresca.cola_tablas_voto, vec![(7, h_b), (9, h_a)]);
    assert_eq!(
        deshacer(&fresca, &undo),
        antes,
        "deshacer conserva exactamente el orden de Q"
    );
    let (repetida, _) = derivar_tabla_sin_base_con_undo(&fresca, 19);
    assert_eq!(repetida, fresca, "una sola derivación por ventana");
    Ok(())
}
