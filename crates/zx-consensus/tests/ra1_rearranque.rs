//! RA-1 · rearranque por ciclos tras una pausa larga (contrato v2, parte D; mejora 8).
//!
//! Pruebas Z1–Z10 de `ORDEN-RA1.md` §5 sobre la transición real. Z11 (la constante de consenso
//! atada a `zx_node::perfil::F_SLOTS`) y la sensibilidad de `estado_resumen` al campo nuevo viven en
//! `crates/zx-node/tests/ra1_espera_rearranque.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use zx_consensus::sectores::{
    ClaveVoto, Etapa, NO_HAY, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::{
    aplicar_certificado_peso_con_undo, calendario_rearranque, derivar_tabla_sin_base_con_undo,
    tomar_instantaneas_rearranque_con_undo,
};
use zx_consensus::transicion::{ErrorTransicion, Estado, Fase, Garantia, deshacer};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::peso::MotivoPeso;
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Utilidades (mismas que `pd1b2_caducidad.rs`, autocontenidas)
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

/// Estado con las claves `indices` registradas (clave BLS determinista) y garantía activa.
fn estado_base(indices: &[u8]) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let mut est = Estado::inicial();
    est.parametros_sector = ParametrosSector::dev();
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for i in indices {
        let s = bls(*i)?;
        est.claves_voto.insert(
            ed(*i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(1_000_000)?;
        est.garantias.insert(ed(*i), g);
        secretas.push((*i, s));
    }
    Ok((est, secretas))
}

/// Inserta un sector con la fianza de perfil (`q_sec`) para que cuente en `tabla_canonica`.
fn add_sector(
    est: &mut Estado,
    i: u8,
    si: u16,
    etapa: Etapa,
    alta_slot: i64,
    renovacion_slot: i64,
    retiro_slot: i64,
) {
    let q = est.parametros_sector.q_sec;
    let id = SectorId {
        clave: ed(i),
        sector_index: si,
        version: 0,
    };
    est.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0u64; 4],
            history_size: 1,
            etapa,
            alta_slot,
            renovacion_slot,
            retiro_slot,
            fianza: q,
            aud_apertura: NO_HAY,
            aud_contestada: NO_HAY,
        },
    );
}

/// Estado con las claves activas (un sector activo cada una, maduro antes de `ref(0)`) y base `m = 0`.
fn estado_hook(indices: &[u8]) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let (mut est, secretas) = estado_base(indices)?;
    for i in indices {
        add_sector(&mut est, *i, 0, Etapa::Activo, 1, 1_000, NO_HAY);
    }
    est.finalidad_votos_n = 0;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some([9u8; 32]);
    est.liquidacion_voto_hasta = Some(0);
    Ok((est, secretas))
}

/// Tabla canónica (ascendente por bytes de clave) con los pesos dados.
fn tabla_con_pesos(est: &Estado, pesos: &[(u8, u64)]) -> Vec<ClaveTablaVoto> {
    let mut t: Vec<ClaveTablaVoto> = pesos
        .iter()
        .map(|(i, w)| ClaveTablaVoto {
            clave_bls: est.claves_voto[&ed(*i)].clave_bls,
            peso: *w,
            activo: true,
            prueba: false,
            garantia: *w,
        })
        .collect();
    t.sort_by_key(|a| a.clave_bls);
    t
}

/// Fija la base `m` con la tabla `t` como vigente (C2) y la asocia a `m`.
fn poner_base(est: &mut Estado, m: u64, t: &[ClaveTablaVoto]) {
    poner_base_sin_cola(est, m, t);
    est.cola_tablas_voto.push((m, hash_payload(t)));
}

/// Base de la prueba, sin sembrar Q: el gancho del bloque es quien la llena.
fn poner_base_sin_cola(est: &mut Estado, m: u64, t: &[ClaveTablaVoto]) {
    let h = hash_payload(t);
    est.finalidad_votos_n = m;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some(h);
    est.tablas_voto_contenido.insert(h, t.to_vec());
    est.tablas_voto.insert(m, t.to_vec());
    est.liquidacion_voto_hasta = Some(m);
}

/// Instala a mano la instantánea del ciclo `j` con la tabla `t`.
fn poner_instantanea(est: &mut Estado, j: u64, t: &[ClaveTablaVoto]) {
    let h = hash_payload(t);
    est.tablas_voto_contenido.insert(h, t.to_vec());
    est.tabla_ciclo_rearranque.insert(j, h);
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

/// Certificado compacto (`0x09`) con firmas BLS reales sobre A3.
#[allow(clippy::too_many_arguments)]
fn op_compacto(
    est: &Estado,
    secretas: &[(u8, ClaveSecreta)],
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    raiz_declarada: [u8; 32],
    raiz_firmada: [u8; 32],
    tabla: &[ClaveTablaVoto],
    firmantes: &[u8],
    acta: bool,
) -> Result<OperacionAlmacenamiento, Error> {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz_firmada);
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
        raiz_declarada,
        &tabla_contrato(n, tabla),
        &votos,
    )?;
    let bytes = zx_votos::serial_certificado_peso(&cert);
    if acta {
        Ok(OperacionAlmacenamiento::ActaPresencia {
            clave: ed(200),
            bytes,
        })
    } else {
        Ok(OperacionAlmacenamiento::CertificadoPeso {
            clave: ed(200),
            bytes,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z1 · Y0 · constantes y calendario
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z1_constantes_y_calendario() {
    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).expect("dev tiene A > 0");
    assert_eq!(cal.a, 65, "A");
    assert_eq!(cal.sil, 661, "SIL");
    assert_eq!(cal.periodo, 726, "P");
    assert_eq!(cal.s0, 1_262, "s0 con m = 0");
    assert_eq!(cal.inicio(0), 1_262);
    assert_eq!(cal.referencia(0), 602);
    assert_eq!(cal.inicio(1), 1_988);
    assert_eq!(cal.referencia(1), 1_328);
    assert_eq!(cal.inicio(3), 1_262 + 3 * 726);
    assert_eq!(cal.referencia(3), 1_262 + 3 * 726 - 660);

    let cal1000 = calendario_rearranque(&p, 1_000).expect("dev tiene A > 0");
    assert_eq!(cal1000.s0, 3_262, "s0 con m = 1 000");
    assert_eq!(cal1000.inicio(0), 3_262);
    assert_eq!(cal1000.referencia(0), 2_602);
    assert_eq!(cal1000.inicio(2), 3_262 + 2 * 726);
    assert_eq!(cal1000.referencia(2), 3_262 + 2 * 726 - 660);

    // Z1 · con los parámetros de fixture `A ≤ 0`: no hay rearranque.
    assert!(calendario_rearranque(&ParametrosSector::fixture(), 0).is_none());

    // TB4-R5 · la frontera de la fase activa: la ventana debe **cerrar** dentro, así que la última
    // apertura admitida es `inicio+A-3` (cierra en `inicio+A-1`); `inicio+A-1` ya no.
    assert_eq!(cal.ciclo_de_apertura(cal.inicio(0) + cal.a - 3), Some(0));
    assert_eq!(cal.ciclo_de_apertura(cal.inicio(0) + cal.a - 1), None);
    assert_eq!(cal.ciclo_de_apertura(cal.s0 - 1), None);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z2 · Y1 · la instantánea se toma en el primer bloque con slot > ref(0) con el estado de entrada
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z2_instantanea_primer_bloque_y_clave_posterior() -> Result<(), Error> {
    let (mut est, _) = estado_hook(&[1, 2, 3])?;
    // Antes de `ref(0)` no hay instantánea (la condición es estricta).
    let (antes, _) = tomar_instantaneas_rearranque_con_undo(&est, 602);
    assert!(antes.tabla_ciclo_rearranque.is_empty());

    // Una clave registrada en el mismo bloque o después no está en la instantánea: su sector no
    // madura hasta después de `ref(0)`.
    let s4 = bls(4)?;
    est.claves_voto.insert(
        ed(4),
        ClaveVoto {
            clave_bls: s4.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    add_sector(&mut est, 4, 0, Etapa::Precomprometido, 604, 604, NO_HAY);

    let (con, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = *con
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("falta la instantánea del ciclo 0")?;
    let tabla = con
        .tablas_voto_contenido
        .get(&h)
        .ok_or("falta el contenido de la instantánea")?;
    assert_eq!(tabla.len(), 3, "solo las tres claves maduras en ref(0)");
    let bls4 = est.claves_voto[&ed(4)].clave_bls;
    assert!(
        !tabla.iter().any(|c| c.clave_bls == bls4),
        "la clave registrada después de ref(0) no entra"
    );

    // Hay una sola instantánea por ciclo y sobrevive dentro de la fase activa.
    let (otra, _) = tomar_instantaneas_rearranque_con_undo(&con, 1_263);
    assert_eq!(otra.tabla_ciclo_rearranque.len(), 1);
    assert_eq!(otra.tabla_ciclo_rearranque.get(&0), Some(&h));
    // Terminada la fase activa, se borra (Y2).
    let (fin, _) = tomar_instantaneas_rearranque_con_undo(&con, 1_327);
    assert!(fin.tabla_ciclo_rearranque.is_empty());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z3 · la pregunta, parte afirmativa: el certificado de rearranque se acepta, la base pasa a n, no
// quedan instantáneas y el siguiente certificado normal encadena
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z3_certificado_de_rearranque_aceptado() -> Result<(), Error> {
    let (est, secretas) = estado_hook(&[1, 2, 3])?;
    let (mut est, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("falta la instantánea")?;
    let t = est
        .tablas_voto_contenido
        .get(&h)
        .ok_or("falta el contenido")?
        .clone();
    poner_base_sin_cola(&mut est, 0, &t);
    let (est, _) = derivar_tabla_sin_base_con_undo(&est, 603);
    let (est, _) = derivar_tabla_sin_base_con_undo(&est, 1_262);
    let h_siguiente = est
        .cola_tablas_voto
        .last()
        .ok_or("gancho sin tabla fresca")?
        .1;

    let candidato = [0x22u8; 32];
    let cert = op_compacto(
        &est,
        &secretas,
        631,
        candidato,
        h_siguiente,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (nuevo, _undo, r) = aplicar_certificado_peso_con_undo(&est, &cert, 1_262);
    r?;
    assert_eq!(nuevo.finalidad_votos_n, 631, "la base pasa a n");
    assert!(
        nuevo.tabla_ciclo_rearranque.is_empty(),
        "Y2 borra las instantáneas al avanzar la base"
    );

    // El siguiente certificado normal encadena con la tabla fresca comprometida.
    let (nuevo, _) = derivar_tabla_sin_base_con_undo(&nuevo, 1_264);
    let h_siguiente = nuevo
        .cola_tablas_voto
        .last()
        .ok_or("gancho sin tabla fresca")?
        .1;
    let cert2 = op_compacto(
        &nuevo,
        &secretas,
        632,
        candidato,
        h_siguiente,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (nuevo2, _undo2, r2) = aplicar_certificado_peso_con_undo(&nuevo, &cert2, 1_264);
    r2?;
    assert_eq!(nuevo2.finalidad_votos_n, 632);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z4 · rechazos, uno por motivo
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z4_rechazos_por_motivo() -> Result<(), Error> {
    let (est, secretas) = estado_hook(&[1, 2, 3])?;
    let (mut est, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("falta la instantánea")?;
    let t = est
        .tablas_voto_contenido
        .get(&h)
        .ok_or("falta el contenido")?
        .clone();
    poner_base(&mut est, 0, &t);
    let candidato = [0x44u8; 32];

    // (a) ventana que abre antes de `s0`.
    let cert = op_compacto(
        &est,
        &secretas,
        331,
        candidato,
        h,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &cert, 662);
    assert!(
        matches!(r, Err(ErrorTransicion::ErrRearranqueFueraDeFase)),
        "antes de s0: {r:?}"
    );

    // (b) ventana que abre en la fase de silencio (apertura = s0 + 66).
    let cert = op_compacto(
        &est,
        &secretas,
        664,
        candidato,
        h,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &cert, 1_328);
    assert!(
        matches!(r, Err(ErrorTransicion::ErrRearranqueFueraDeFase)),
        "en silencio: {r:?}"
    );

    // (d) sin instantánea del ciclo.
    let mut sin = est.clone();
    sin.tabla_ciclo_rearranque.clear();
    let cert = op_compacto(
        &est,
        &secretas,
        631,
        candidato,
        h,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&sin, &cert, 1_262);
    assert!(
        matches!(r, Err(ErrorTransicion::ErrRearranqueSinTabla)),
        "sin instantánea: {r:?}"
    );

    // (e) `A ≤ 0` (parámetros de fixture): rige la guarda 4 de hoy y la ventana se rechaza.
    let mut fixture = est.clone();
    fixture.parametros_sector = ParametrosSector::fixture();
    let (_, _, r) = aplicar_certificado_peso_con_undo(&fixture, &cert, 1_262);
    assert!(
        matches!(r, Err(ErrorTransicion::ErrCertificadoInstancia)),
        "A <= 0: {r:?}"
    );

    // (c) frontera exacta: la última ventana que **cierra** dentro de la fase activa es la 662.
    let cal = calendario_rearranque(&ParametrosSector::dev(), 0).ok_or("sin calendario")?;
    let ultima = (cal.inicio(0) + cal.a - 1) / 2 - 1;
    let siguiente = ultima + 1;
    assert_eq!(ultima, 662);
    assert_eq!(cal.ciclo_de_apertura(2 * ultima), Some(0));
    assert_eq!(cal.ciclo_de_apertura(2 * siguiente), None);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z5 · la pregunta, parte (b): dos tercios de la tabla actual que no lo son de la del ciclo
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z5_dos_tercios_de_la_tabla_actual_no_del_ciclo() -> Result<(), Error> {
    let (mut est, secretas) = estado_hook(&[1, 2, 3])?;
    for si in 1..10 {
        add_sector(&mut est, 3, si, Etapa::Activo, 1, 1_000, NO_HAY);
    }
    let t_actual = tabla_con_pesos(&est, &[(1, 1), (2, 1)]);
    let t_ciclo = tabla_con_pesos(&est, &[(1, 1), (2, 1), (3, 10)]);
    poner_base_sin_cola(&mut est, 0, &t_actual);
    let (est, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = hash_payload(&t_ciclo);
    assert_eq!(est.tabla_ciclo_rearranque.get(&0), Some(&h));
    assert_eq!(est.tablas_voto_contenido.get(&h), Some(&t_ciclo));
    let (mut est, _) = derivar_tabla_sin_base_con_undo(&est, 603);
    // La tercera identidad retira sus diez sectores después de ref(0); la instantánea conserva
    // su peso 10, mientras que la tabla actual derivada tiene solo las claves 1 y 2 (peso 2).
    for r in est.sectores.values_mut().filter(|r| r.id.clave == ed(3)) {
        r.etapa = Etapa::EnRetirada;
        r.retiro_slot = 700;
    }
    let (est, _) = derivar_tabla_sin_base_con_undo(&est, 1_262);
    let h_siguiente = est
        .cola_tablas_voto
        .last()
        .ok_or("gancho sin tabla fresca")?
        .1;
    assert_eq!(h_siguiente, hash_payload(&t_actual));
    assert_eq!(est.tablas_voto_contenido.get(&h_siguiente), Some(&t_actual));
    assert_ne!(h_siguiente, h);

    // Las claves 1 y 2 alcanzan el cuórum con 2/2 de `t_actual`, pero solo 2/12 de `t_ciclo`.
    let cert = op_compacto(
        &est,
        &secretas,
        631,
        [0x55u8; 32],
        h_siguiente,
        [0u8; 32],
        [0u8; 32],
        &t_ciclo,
        &[1, 2],
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &cert, 1_262);
    assert!(
        matches!(
            r,
            Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::Quorum
            ))
        ),
        "se evalúa con la tabla del ciclo: {r:?}"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z6 · una clave que pidió la retirada después de ref(j) sigue en la instantánea y su firma cuenta
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z6_clave_en_retirada_posterior_a_ref() -> Result<(), Error> {
    let (est, secretas) = estado_hook(&[1, 2, 3])?;
    let (mut est, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("falta la instantánea")?;
    let t = est
        .tablas_voto_contenido
        .get(&h)
        .ok_or("falta el contenido")?
        .clone();
    poner_base_sin_cola(&mut est, 0, &t);
    let (mut est, _) = derivar_tabla_sin_base_con_undo(&est, 603);

    // La clave 3 pide la retirada **después** de `ref(0) = 602` (se simula el estado del retiro).
    let id3 = est
        .sectores
        .keys()
        .find(|id| id.clave == ed(3))
        .copied()
        .ok_or("sin sector de la clave 3")?;
    if let Some(r) = est.sectores.get_mut(&id3) {
        r.etapa = Etapa::EnRetirada;
        r.retiro_slot = 700;
    }
    let bls3 = est.claves_voto[&ed(3)].clave_bls;
    let tabla = est
        .tablas_voto_contenido
        .get(&h)
        .ok_or("falta el contenido")?;
    assert!(
        tabla.iter().any(|c| c.clave_bls == bls3),
        "la clave en retirada posterior a ref(0) sigue en la instantánea"
    );

    // Su firma cuenta en la instantánea: bastan las claves 2 y 3 (2 de 3), aunque la fresca
    // derivada después de la retirada ya no incluya la clave 3.
    let (est, _) = derivar_tabla_sin_base_con_undo(&est, 1_262);
    let h_siguiente = est
        .cola_tablas_voto
        .last()
        .ok_or("gancho sin tabla fresca")?
        .1;
    assert_ne!(
        h_siguiente, h,
        "la retirada cambia la tabla derivada actual"
    );
    let cert = op_compacto(
        &est,
        &secretas,
        631,
        [0x66u8; 32],
        h_siguiente,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[2, 3],
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &cert, 1_262);
    r?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z7 · Y4 · tras el rearranque, las ventanas m+331 … n−1 no se asocian a ninguna tabla (sin cobro)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z7_ventanas_intermedias_sin_asociacion() -> Result<(), Error> {
    let (est, secretas) = estado_hook(&[1, 2, 3])?;
    let (mut est, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("sin instantánea")?;
    let t = est
        .tablas_voto_contenido
        .get(&h)
        .ok_or("sin contenido de la instantánea")?
        .clone();
    poner_base_sin_cola(&mut est, 0, &t);
    let (est, _) = derivar_tabla_sin_base_con_undo(&est, 603);
    let (est, _) = derivar_tabla_sin_base_con_undo(&est, 1_262);
    let h_siguiente = est
        .cola_tablas_voto
        .last()
        .ok_or("gancho sin tabla fresca")?
        .1;

    let cert = op_compacto(
        &est,
        &secretas,
        631,
        [0x77u8; 32],
        h_siguiente,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&est, &cert, 1_262);
    r?;
    // AT-1b · W6.2 (J12) · tras un rearranque **ninguna** ventana `m < k ≤ m + CADUCIDAD` se
    // asocia (ya están liquidadas); solo `n` queda asociada.
    assert_eq!(
        nuevo.tabla_ventana_voto.keys().copied().collect::<Vec<_>>(),
        vec![631],
        "W6.2: solo la ventana n se asocia"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z8 · Y2 y Y5 · un certificado normal tardío borra las instantáneas; pasada la fase activa también
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z8_borrado_de_instantaneas() -> Result<(), Error> {
    // Y5 · un certificado normal de una ventana <= m + CADUCIDAD se admite y borra las instantáneas.
    let (mut est, secretas) = estado_base(&[1, 2, 3])?;
    let t = tabla_con_pesos(&est, &[(1, 1), (2, 1), (3, 1)]);
    poner_base(&mut est, 0, &t);
    poner_instantanea(&mut est, 0, &t);
    assert!(!est.tabla_ciclo_rearranque.is_empty());
    let h = hash_payload(&t);
    let cert = op_compacto(
        &est,
        &secretas,
        1,
        [0x88u8; 32],
        h,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&est, &cert, 4);
    r?;
    assert_eq!(nuevo.finalidad_votos_n, 1);
    assert!(
        nuevo.tabla_ciclo_rearranque.is_empty(),
        "el avance de la base borra todas las instantáneas"
    );

    // Y2 · pasada la fase activa, la instantánea de ese ciclo se borra (cubierto también en Z2).
    let (est, _) = estado_hook(&[1, 2, 3])?;
    let (con, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    assert_eq!(con.tabla_ciclo_rearranque.len(), 1);
    let (fin, _) = tomar_instantaneas_rearranque_con_undo(&con, 1_327);
    assert!(fin.tabla_ciclo_rearranque.is_empty());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z9 · dos estados que difieren solo en operaciones posteriores a ref(j) dan la misma instantánea
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z9_operaciones_posteriores_no_cambian_la_instantanea() -> Result<(), Error> {
    let (a, _) = estado_hook(&[1, 2, 3])?;
    let (mut b, _) = estado_hook(&[1, 2, 3])?;
    // Alta posterior a `ref(0) = 602`.
    let s4 = bls(4)?;
    b.claves_voto.insert(
        ed(4),
        ClaveVoto {
            clave_bls: s4.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    add_sector(&mut b, 4, 0, Etapa::Precomprometido, 700, 700, NO_HAY);

    let (sa, _) = tomar_instantaneas_rearranque_con_undo(&a, 603);
    let (sb, _) = tomar_instantaneas_rearranque_con_undo(&b, 603);
    assert_eq!(sa.tabla_ciclo_rearranque, sb.tabla_ciclo_rearranque);
    let ha = *sa
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("sin instantánea a")?;
    let hb = *sb
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("sin instantánea b")?;
    assert_eq!(
        sa.tablas_voto_contenido.get(&ha),
        sb.tablas_voto_contenido.get(&hb)
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Z10 · deshacer exacto de la instantánea y del certificado de rearranque
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn z10_deshacer_exacto() -> Result<(), Error> {
    // Bloque que toma una instantánea.
    let (est, secretas) = estado_hook(&[1, 2, 3])?;
    let (nuevo, undo) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    assert_ne!(nuevo, est, "la instantánea muta el estado");
    assert_eq!(
        deshacer(&nuevo, &undo),
        est,
        "deshacer exacto de la instantánea"
    );

    // Bloque con el certificado de rearranque.
    let (mut con, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = *con
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("falta la instantánea")?;
    let t = con
        .tablas_voto_contenido
        .get(&h)
        .ok_or("falta el contenido")?
        .clone();
    poner_base_sin_cola(&mut con, 0, &t);
    let (con, _) = derivar_tabla_sin_base_con_undo(&con, 603);
    let (con, _) = derivar_tabla_sin_base_con_undo(&con, 1_262);
    let h_siguiente = con
        .cola_tablas_voto
        .last()
        .ok_or("gancho sin tabla fresca")?
        .1;
    let cert = op_compacto(
        &con,
        &secretas,
        631,
        [0x99u8; 32],
        h_siguiente,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (despues, undo2, r) = aplicar_certificado_peso_con_undo(&con, &cert, 1_262);
    r?;
    assert_eq!(
        deshacer(&despues, &undo2),
        con,
        "deshacer exacto del certificado de rearranque"
    );
    Ok(())
}

/// TB-1c · T6/P6: tras la caducidad, el certificado de rearranque solo vale si su huella es la de la
/// instantánea del ciclo; que esté en la cola `Q` no basta.
#[test]
fn rearranque_huella_distinta_de_la_instantanea_se_rechaza() -> Result<(), Error> {
    let (est, secretas) = estado_hook(&[1, 2, 3])?;
    let (mut est, _) = tomar_instantaneas_rearranque_con_undo(&est, 603);
    let h = *est
        .tabla_ciclo_rearranque
        .get(&0)
        .ok_or("falta la instantánea")?;
    let t = est
        .tablas_voto_contenido
        .get(&h)
        .ok_or("falta el contenido")?
        .clone();
    poner_base(&mut est, 0, &t);

    // Otra tabla con contenido presente y en la cola, pero que no es la instantánea.
    let mut t_otra = t.clone();
    if let Some(c) = t_otra.first_mut() {
        c.peso = c.peso.saturating_add(1);
        c.garantia = c.garantia.saturating_add(1);
    }
    let h_otra = hash_payload(&t_otra);
    assert_ne!(h_otra, h);
    est.tablas_voto_contenido.insert(h_otra, t_otra.clone());
    est.cola_tablas_voto.push((0, h_otra));

    let cert = op_compacto(
        &est,
        &secretas,
        631,
        [0x22u8; 32],
        h_otra,
        [0u8; 32],
        [0u8; 32],
        &t,
        &[1, 2],
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &cert, 1_262);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}
