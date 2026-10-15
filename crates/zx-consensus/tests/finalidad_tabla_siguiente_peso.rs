//! M9-b1 · gemelas por el flujo por peso de `finalidad_tabla_siguiente.rs` (lista P, 9 pruebas).
//!
//! La operación antigua `0x04` (+ compromiso `0x06`) se sustituye por el certificado compacto
//! `0x09` (`aplicar_certificado_peso_con_undo`). El estado se monta como lo deja el flujo por peso
//! (tabla vigente + contenido), no con `tablas_voto`. Las afirmaciones son las de la original.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::type_complexity,
    dead_code,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{
    PRIMA_DISPONIBILIDAD_ACTIVA, aplicar_certificado_peso_con_undo, derivar_tabla_sin_base_con_undo,
};
use zx_consensus::transicion::{ErrorTransicion, Estado, Garantia, deshacer, fuente_peso_de};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

const B: u64 = 2;
const SLOT: i64 = 13;

type Error = Box<dyn std::error::Error>;

/// TB-1c-2 · X2 · montaje autorizado: llama al gancho de producto `derivar_tabla_sin_base` con el
/// slot del bloque (no una copia) para que la derivada que el primer certificado declara esté en `Q`.
fn preparar_cola_sin_base(est: &mut Estado, slot: u64) {
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(est, slot);
    *est = nuevo;
}

fn bls(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
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

/// Estado con `claves` = `(índice de clave, nº de sectores activos)` y garantía activa `G`.
fn estado(claves: &[(u8, usize)], garantia: i64) -> Result<(Estado, Vec<ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let mut secretas = Vec::new();
    for (indice, n_sectores) in claves {
        let secreta = bls(*indice)?;
        let pk = secreta.clave_publica();
        let e = ed(*indice);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for i in 0..*n_sectores {
            let (id, reg) = registro(&p, e, u16::try_from(i)?);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(garantia)?;
        est.garantias.insert(e, g);
        secretas.push(secreta);
    }
    Ok((est, secretas))
}

/// Tabla `T_n` (payload y tipo del contrato) derivada del estado vivo en `SLOT`.
fn tabla_de(est: &Estado, n: u64) -> Result<(Vec<ClaveTablaVoto>, Tabla), Error> {
    let p = est.parametros_sector;
    let mut claves_payload = Vec::new();
    let mut tabla_claves = Vec::new();
    for (e, cv) in &est.claves_voto {
        let peso = fuente_peso_de(est, e, SLOT, &p);
        if peso <= 0 {
            continue;
        }
        let peso = u64::try_from(peso)?;
        let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && est.pruebas.contains_key(e);
        claves_payload.push(ClaveTablaVoto {
            clave_bls: cv.clave_bls,
            peso,
            activo: true,
            prueba,
            garantia: peso,
        });
        tabla_claves.push(Clave {
            clave: cv.clave_bls.to_vec(),
            peso,
            activo: true,
            prueba,
            garantia: peso,
        });
    }
    Ok((
        claves_payload,
        Tabla {
            n,
            claves: tabla_claves,
        },
    ))
}

fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

fn tabla_desde_payload(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves
            .iter()
            .map(|c| Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    }
}

fn hash_tabla(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_desde_payload(0, claves))
}

/// Estado con base `m` fijada como la deja el flujo por peso: tabla vigente (`h_t`), contenido y
/// asociación de la ventana de la base.
fn poner_base(est: &mut Estado, m: u64, t: &[ClaveTablaVoto]) {
    let h = hash_tabla(t);
    est.finalidad_votos_n = m;
    est.finalidad_votos = Some(BlockHash::from_digest(Digest::from_bytes([9u8; 32])));
    est.finalidad_votos_h_t = Some(h);
    est.tablas_voto_contenido.insert(h, t.to_vec());
    est.tabla_ventana_voto.insert(m, h);
    est.cola_tablas_voto.push((m, h));
    est.liquidacion_voto_hasta = Some(m);
}

/// Certificado compacto `0x09` con firmas BLS reales sobre el mensaje A3 (raíz cero).
fn certificado_peso(
    secretas: &[ClaveSecreta],
    n: u64,
    claves_payload: &[ClaveTablaVoto],
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    firmantes: &[usize],
    _tabla_siguiente: Option<&[ClaveTablaVoto]>,
) -> Result<OperacionAlmacenamiento, Error> {
    let vigente = canoniza(claves_payload.to_vec());
    let tabla = tabla_desde_payload(n, &vigente);
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &[0u8; 32]);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for (orden, secreta) in secretas.iter().enumerate() {
        if !firmantes.contains(&orden) {
            continue;
        }
        let pk = secreta.clave_publica();
        let Some(pos) = tabla
            .claves
            .iter()
            .position(|c| c.clave == pk.bytes().to_vec())
        else {
            continue;
        };
        let firma = zx_votos::firmar(secreta, DOMINIO_VOTO, &mensaje)?;
        votos.push((pos + 1, firma));
    }
    let cert =
        zx_votos::construir_certificado(n, candidato, h_t_siguiente, [0u8; 32], &tabla, &votos)?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

/// Tres tablas auténticas consecutivas del mismo estado (más sectores de la clave 1).
type TresTablas = (
    Estado,
    Vec<ClaveSecreta>,
    Vec<ClaveTablaVoto>,
    [u8; 32],
    Vec<ClaveTablaVoto>,
    [u8; 32],
    Vec<ClaveTablaVoto>,
    [u8; 32],
);

fn escenario_tres_tablas() -> Result<TresTablas, Error> {
    let (mut base0, secretas) = estado(&[(1, 100), (2, 1)], 50)?;
    // TB-1c-2 · X2 · T5′: sin base, el gancho X1 ya derivó y guardó la tabla de la ventana.
    preparar_cola_sin_base(&mut base0, u64::try_from(SLOT)?);
    let (t1, tab1) = tabla_de(&base0, 1)?;
    let h1 = zx_votos::hash_tabla(&tab1);
    let mut b2 = base0.clone();
    let (id, reg) = registro(&b2.parametros_sector, ed(1), 100);
    b2.sectores.insert(id, reg);
    let (t2, tab2) = tabla_de(&b2, 2)?;
    let h2 = zx_votos::hash_tabla(&tab2);
    let mut b3 = b2.clone();
    let (id, reg) = registro(&b3.parametros_sector, ed(1), 101);
    b3.sectores.insert(id, reg);
    let (t3, tab3) = tabla_de(&b3, 3)?;
    let h3 = zx_votos::hash_tabla(&tab3);
    Ok((
        base0,
        secretas,
        canoniza(t1),
        h1,
        canoniza(t2),
        h2,
        canoniza(t3),
        h3,
    ))
}

/// (P1) Dos certificados consecutivos sobre tablas distintas se adoptan, el segundo encadena el
/// compromiso de la tabla vigente y el undo es exacto.
#[test]
fn cadena_de_tablas_cambiantes_conserva_el_compromiso_siguiente_peso() -> Result<(), Error> {
    let (base0, secretas, t1, h1, t2, h2, _t3, _h3) = escenario_tres_tablas()?;
    assert_ne!(h1, h2, "las tablas deben ser distintas");
    let cand_n = [0x11u8; 32];
    let cand_n1 = [0x12u8; 32];
    // Génesis (T5): la tabla vigente es `D(E, 1)`; el certificado declara su huella.
    let op_n = certificado_peso(&secretas, 1, &t1, cand_n, h1, &[0, 1], None)?;
    let (tras_n, undo_n, r_n) = aplicar_certificado_peso_con_undo(&base0, &op_n, SLOT);
    r_n?;
    assert_eq!(tras_n.finalidad_votos_n, 1);
    assert_eq!(
        tras_n.finalidad_votos_h_t,
        Some(h1),
        "el estado guarda la huella de la tabla vigente"
    );
    assert_eq!(deshacer(&tras_n, &undo_n), base0, "undo de C_1 bit a bit");

    // TB-1c · T3: el certificado de la ventana 2 declara `h2`, que el estado tiene que haber
    // derivado. Se inyecta en la cola `Q` con su contenido (T1 lo haría al aplicar C_1 en un estado
    // con el sector extra).
    let mut tras_n2 = tras_n.clone();
    let (id, reg) = registro(&tras_n2.parametros_sector, ed(1), 100);
    tras_n2.sectores.insert(id, reg);
    tras_n2.tablas_voto_contenido.insert(h2, t2.clone());
    tras_n2.cola_tablas_voto.push((1, h2));
    let op_n1 = certificado_peso(&secretas, 2, &t2, cand_n1, h2, &[0, 1], None)?;
    let (tras_n1, undo_n1, r_n1) = aplicar_certificado_peso_con_undo(&tras_n2, &op_n1, SLOT);
    r_n1?;
    assert_eq!(tras_n1.finalidad_votos_n, 2);
    assert_eq!(
        tras_n1.finalidad_votos,
        Some(BlockHash::from_digest(Digest::from_bytes(cand_n1)))
    );
    assert_eq!(
        tras_n1.finalidad_votos_h_t,
        Some(h2),
        "el estado conserva el compromiso siguiente"
    );
    assert_eq!(
        deshacer(&tras_n1, &undo_n1),
        tras_n2,
        "undo de C_2 bit a bit"
    );
    Ok(())
}

/// (P2) Repetir el certificado es idempotente: éxito, estado idéntico, sin doble débito.
#[test]
fn repeticion_idempotente_no_debita_ni_muta_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, _h3) = escenario_tres_tablas()?;
    let cand = [0x11u8; 32];
    // Solo firma la clave 1; R7: la clave 2 no se debita en el certificado.
    let op = certificado_peso(&secretas, 1, &t1, cand, h1, &[0], None)?;
    let (tras, _, r1) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r1?;
    assert_eq!(
        tras.activo_de(&ed(2)),
        base.activo_de(&ed(2)),
        "R7: no debita"
    );
    let (repetido, _, r2) = aplicar_certificado_peso_con_undo(&tras, &op, SLOT);
    r2?;
    assert_eq!(repetido, tras, "la repetición no muta el estado");
    assert_eq!(
        repetido.activo_de(&ed(2)),
        tras.activo_de(&ed(2)),
        "la repetición no debe debitar otra vez"
    );
    Ok(())
}

/// (P3) La variante con el mismo `n` y candidato pero `h_t_siguiente` distinto se rechaza.
#[test]
fn repeticion_con_h_t_distinto_se_rechaza_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, h3) = escenario_tres_tablas()?;
    let cand = [0x11u8; 32];
    let op = certificado_peso(&secretas, 1, &t1, cand, h1, &[0], None)?;
    let (tras, _, r1) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r1?;
    let variante = certificado_peso(&secretas, 1, &t1, cand, h3, &[0], None)?;
    let (nuevo, _, resultado) = aplicar_certificado_peso_con_undo(&tras, &variante, SLOT);
    assert_eq!(
        resultado,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            zx_votos::peso::MotivoPeso::TablaNoDerivada
        ))
    );
    assert_eq!(nuevo, tras, "un conflicto no muta el estado");
    Ok(())
}

/// (P4) La variante con el mismo `n` y `h_t_siguiente` pero candidato distinto se rechaza.
#[test]
fn repeticion_con_candidato_distinto_se_rechaza_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, _h3) = escenario_tres_tablas()?;
    let op = certificado_peso(&secretas, 1, &t1, [0x11u8; 32], h1, &[0], None)?;
    let (tras, _, r1) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r1?;
    let variante = certificado_peso(&secretas, 1, &t1, [0x77u8; 32], h1, &[0], None)?;
    let (nuevo, _, resultado) = aplicar_certificado_peso_con_undo(&tras, &variante, SLOT);
    assert_eq!(resultado, Err(ErrorTransicion::ErrCertificadoConflictivo));
    assert_eq!(nuevo, tras, "un conflicto no muta el estado");
    Ok(())
}

/// (P5) La primera adopción de `n = 0` se adopta, fija punto y compromiso, no debita y su undo es
/// exacto.
#[test]
fn primera_adopcion_n0_se_adopta_y_undo_exacto_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, _h3) = escenario_tres_tablas()?;
    let cand = [0x11u8; 32];
    let op = certificado_peso(&secretas, 0, &t1, cand, h1, &[0], None)?;
    let (tras, undo, r) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r?;
    assert_eq!(tras.finalidad_votos_n, 0);
    assert_eq!(
        tras.finalidad_votos,
        Some(BlockHash::from_digest(Digest::from_bytes(cand))),
        "primer punto de finalidad n=0 adoptado"
    );
    assert_eq!(
        tras.finalidad_votos_h_t,
        Some(h1),
        "el estado guarda la huella de la tabla vigente"
    );
    assert_eq!(
        tras.activo_de(&ed(2)),
        base.activo_de(&ed(2)),
        "R7: la primera adopción no debita"
    );
    assert_eq!(
        deshacer(&tras, &undo),
        base,
        "undo de la primera adopción n=0 bit a bit"
    );
    Ok(())
}

/// (P6) Repetir el certificado `n = 0` ya adoptado es idempotente y no debita dos veces.
#[test]
fn repeticion_n0_idempotente_sin_doble_multa_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, _h3) = escenario_tres_tablas()?;
    let op = certificado_peso(&secretas, 0, &t1, [0x11u8; 32], h1, &[0], None)?;
    let (tras, _, r1) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r1?;
    let activo_ausente = tras.activo_de(&ed(2));
    assert_eq!(
        activo_ausente,
        base.activo_de(&ed(2)),
        "R7: el certificado no debita"
    );
    let (repetido, _, r2) = aplicar_certificado_peso_con_undo(&tras, &op, SLOT);
    r2?;
    assert_eq!(repetido, tras, "la repetición n=0 no muta el estado");
    assert_eq!(
        repetido.activo_de(&ed(2)),
        activo_ausente,
        "la repetición n=0 no debe debitar otra vez"
    );
    Ok(())
}

/// (P7) La variante `n = 0` con el mismo candidato pero `h_t_siguiente` distinto se rechaza.
#[test]
fn repeticion_n0_con_h_t_distinto_se_rechaza_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, h3) = escenario_tres_tablas()?;
    let cand = [0x11u8; 32];
    let op = certificado_peso(&secretas, 0, &t1, cand, h1, &[0], None)?;
    let (tras, _, r1) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r1?;
    let variante = certificado_peso(&secretas, 0, &t1, cand, h3, &[0], None)?;
    let (nuevo, _, resultado) = aplicar_certificado_peso_con_undo(&tras, &variante, SLOT);
    assert_eq!(
        resultado,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            zx_votos::peso::MotivoPeso::TablaNoDerivada
        ))
    );
    assert_eq!(nuevo, tras, "un conflicto n=0 no muta el estado");
    Ok(())
}

/// (P8) La variante `n = 0` con el mismo `h_t_siguiente` pero candidato distinto se rechaza.
#[test]
fn repeticion_n0_con_candidato_distinto_se_rechaza_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, _h3) = escenario_tres_tablas()?;
    let op = certificado_peso(&secretas, 0, &t1, [0x11u8; 32], h1, &[0], None)?;
    let (tras, _, r1) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r1?;
    let variante = certificado_peso(&secretas, 0, &t1, [0x77u8; 32], h1, &[0], None)?;
    let (nuevo, _, resultado) = aplicar_certificado_peso_con_undo(&tras, &variante, SLOT);
    assert_eq!(resultado, Err(ErrorTransicion::ErrCertificadoConflictivo));
    assert_eq!(nuevo, tras, "un conflicto n=0 no muta el estado");
    Ok(())
}

/// (P9) Un estado de finalidad parcial/incoherente (punto sin compromiso, o compromiso sin punto)
/// no habilita génesis nueva.
#[test]
fn estado_de_finalidad_incoherente_no_se_acepta_peso() -> Result<(), Error> {
    let (base, secretas, t1, h1, _t2, _h2, _t3, _h3) = escenario_tres_tablas()?;
    let mut est = base;
    poner_base(&mut est, 1, &t1);
    let op = certificado_peso(&secretas, 1, &t1, [0x11u8; 32], h1, &[0], None)?;

    // Punto de finalidad presente pero sin el compromiso.
    let mut punto_sin_compromiso = est.clone();
    punto_sin_compromiso.finalidad_votos_h_t = None;
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&punto_sin_compromiso, &op, SLOT);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoConflictivo));
    assert_eq!(nuevo, punto_sin_compromiso, "no habilita génesis nueva");

    // Compromiso presente pero sin punto de finalidad.
    let mut compromiso_sin_punto = est.clone();
    compromiso_sin_punto.finalidad_votos = None;
    let (nuevo2, _, r2) = aplicar_certificado_peso_con_undo(&compromiso_sin_punto, &op, SLOT);
    assert_eq!(r2, Err(ErrorTransicion::ErrCertificadoConflictivo));
    assert_eq!(nuevo2, compromiso_sin_punto, "no habilita génesis nueva");
    Ok(())
}
