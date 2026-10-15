//! AT-1b · J9 (W4, la transición de la falta entre ventanas) y J11 (W6.1, el acta no encadena con
//! la base).
//!
//! Toda firma BLS es real y los estados se construyen con sectores reales, como `pd1c_huecos.rs`.
//! El hecho que decide el caso de ventanas distintas lo calcula `zx-cadena` (W2); aquí se le pasa
//! explícito a `aplicar_evidencia_votos_peso_con_hecho_con_undo` para fijar W4.
//!
//! Las pruebas de J1–J6 sobre una `Cadena` real necesitan firmar votos BLS desde `zx-cadena`, que
//! no declara `zx-votos` como dependencia de test; añadirla cambiaría `Cargo.lock` (archivo caliente
//! fuera de los que posee esta orden). La lógica de W1/W2 sí se prueba dentro de `zx-cadena`
//! (`crates/zx-cadena/src/cadena.rs`, módulo de pruebas) con datos del DAG y votos sintéticos.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use primitive_types::U256;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{
    W_REVEAL_SLOTS_VOTOS, aplicar_acta_presencia_con_undo,
    aplicar_evidencia_votos_peso_con_hecho_con_undo, cierre_ventana, tabla_canonica,
};
use zx_consensus::transicion::{
    ErrorTransicion, Estado, Fase, Garantia, HechoVoto, ParametrosEvidencia, ParametrosTransicion,
    deshacer,
};
use zx_core::{
    Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento,
    VotoPesoEvidencia,
};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

const DEN: i64 = 1_401_600_000;

type Error = Box<dyn std::error::Error>;

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
fn estado_sectores(claves: &[(u8, u16, i64)]) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
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
        secretas.push((*i, s));
    }
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

/// Acta de presencia (`0x0A`) con firmas BLS reales sobre A3.
#[allow(clippy::too_many_arguments)]
fn acta(
    est: &Estado,
    secretas: &[(u8, ClaveSecreta)],
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    raiz: [u8; 32],
    tabla: &[ClaveTablaVoto],
    firmantes: &[u8],
) -> Result<OperacionAlmacenamiento, Error> {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz);
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
        raiz,
        &tabla_contrato(n, tabla),
        &votos,
    )?;
    let bytes = zx_votos::serial_certificado_peso(&cert);
    Ok(OperacionAlmacenamiento::ActaPresencia {
        clave: ed(200),
        bytes,
    })
}

/// Evidencia de dos votos por peso (`0x0B`) con las dos firmas A3 reales.
#[allow(clippy::too_many_arguments)]
fn evidencia_peso(
    secreta: &ClaveSecreta,
    n1: u64,
    c1: [u8; 32],
    t1: [u8; 32],
    r1: [u8; 32],
    n2: u64,
    c2: [u8; 32],
    t2: [u8; 32],
    r2: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let f1 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n1, &c1, &t1, &r1),
    )?;
    let f2 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n2, &c2, &t2, &r2),
    )?;
    Ok(OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: pk.bytes(),
        voto1: VotoPesoEvidencia {
            n: n1,
            candidato: c1,
            h_t_siguiente: t1,
            raiz_estado: r1,
            firma: f1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n: n2,
            candidato: c2,
            h_t_siguiente: t2,
            raiz_estado: r2,
            firma: f2.bytes(),
        },
    })
}

fn evidencia_entre_ventanas(
    secretas: &[(u8, ClaveSecreta)],
) -> Result<OperacionAlmacenamiento, Error> {
    evidencia_peso(
        secreta(secretas, 1)?,
        3,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        4,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// J9 · W4 · la transición de la falta
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `Falta` castiga como el doble voto de la misma ventana; `SinFalta` e `Inadmisible`/ausente se
/// descartan sin tocar el estado.
#[test]
fn j9_falta_castiga_sin_falta_e_inadmisible_descartan() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, 50)])?;
    let p = params();
    let evp = param_evidencia();
    let op = evidencia_entre_ventanas(&secretas)?;
    let slot = 10;

    // Falta: mismo castigo que la misma ventana.
    let (castigado, undo, r) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &base,
        &op,
        ed(9),
        &p,
        &evp,
        slot,
        Some(HechoVoto::Falta),
    );
    r?;
    assert_eq!(
        castigado.garantias[&ed(1)].incidentes.len(),
        1,
        "Falta registra el incidente"
    );
    assert!(castigado.quemado > base.quemado, "Falta confisca y quema");
    assert_eq!(deshacer(&castigado, &undo), base, "undo exacto");

    // Sin falta: descarte con error propio, sin tocar el estado.
    let (_, _, r) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &base,
        &op,
        ed(9),
        &p,
        &evp,
        slot,
        Some(HechoVoto::SinFalta),
    );
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaSinFalta));

    // Inadmisible y sin hecho: descarte sin invalidar el bloque.
    for hecho in [Some(HechoVoto::Inadmisible), None] {
        let (_, _, r) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
            &base,
            &op,
            ed(9),
            &p,
            &evp,
            slot,
            hecho,
        );
        assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaInadmisible));
    }
    Ok(())
}

/// Los rechazos de W4: firma falsa, clave no registrada, fuera de plazo e incidente repetido.
#[test]
fn j9_rechazos_de_w4() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, 50)])?;
    let p = params();
    let evp = param_evidencia();
    let slot = 10;
    let op = evidencia_entre_ventanas(&secretas)?;
    let falta = Some(HechoVoto::Falta);

    // Incidente repetido: el segundo intento con el mismo par de votos.
    let (primero, _, r) =
        aplicar_evidencia_votos_peso_con_hecho_con_undo(&base, &op, ed(9), &p, &evp, slot, falta);
    r?;
    let (_, _, r) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &primero,
        &op,
        ed(9),
        &p,
        &evp,
        slot,
        falta,
    );
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaDuplicada));

    // Firma falsa: se corrompe un byte de la segunda firma.
    let mut falso = op.clone();
    if let OperacionAlmacenamiento::EvidenciaVotosPeso { voto2, .. } = &mut falso {
        voto2.firma[0] ^= 0xFF;
    }
    let (_, _, r) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &base,
        &falso,
        ed(9),
        &p,
        &evp,
        slot,
        falta,
    );
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    // Clave BLS no registrada.
    let ajena = bls(7)?;
    let no_reg = evidencia_peso(
        &ajena, 3, [0x01; 32], [0xAA; 32], [0x10; 32], 4, [0x02; 32], [0xBB; 32], [0x20; 32],
    )?;
    let (_, _, r) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &base,
        &no_reg,
        ed(9),
        &p,
        &evp,
        slot,
        falta,
    );
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    // Fuera de plazo: `cierre(n₂) + plazo_slots` con `n₂ = 4`.
    let tarde = cierre_ventana(4) + 300 + 1;
    let (_, _, r) =
        aplicar_evidencia_votos_peso_con_hecho_con_undo(&base, &op, ed(9), &p, &evp, tarde, falta);
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    // La misma ventana no cambia: sin hecho, dos votos de la ventana 3 se castigan.
    let misma = evidencia_peso(
        secreta(&secretas, 1)?,
        3,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        3,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )?;
    let (nw, _, r) =
        aplicar_evidencia_votos_peso_con_hecho_con_undo(&base, &misma, ed(9), &p, &evp, slot, None);
    r?;
    assert_eq!(nw.garantias[&ed(1)].incidentes.len(), 1);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// J11 · W6.1 · el acta no encadena con la base
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Acta de una ventana `n` con la base ya en `n + 1` (y la ventana sin liquidar): aceptada. Sin
/// tabla o fuera de plazo: rechazada.
#[test]
fn j11_acta_no_encadena_con_la_base() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let t = canoniza(tabla_canonica(&base, 100));
    let h = hash_payload(&t);
    let n = 2;
    let mut est = base;
    // Base en `m = n + 1 = 3`; la ventana 2 queda asociada a la tabla `T` y **no** liquidada.
    est.finalidad_votos_n = 3;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some(h);
    est.tablas_voto_contenido.insert(h, t.clone());
    est.tablas_voto.insert(3, t.clone());
    est.tabla_ventana_voto.insert(n, h);
    assert_eq!(est.liquidacion_voto_hasta, None);

    let raiz = [0xABu8; 32];
    let a = acta(
        &est,
        &secretas,
        n,
        [0x33u8; 32],
        [0x77u8; 32],
        raiz,
        &t,
        &[1, 2],
    )?;
    let (con_acta, undo, r) = aplicar_acta_presencia_con_undo(&est, &a, 100);
    r?;
    let votantes = con_acta.votantes_voto.get(&n).cloned().unwrap_or_default();
    assert!(
        votantes.contains(&ed(1)) && votantes.contains(&ed(2)),
        "acredita a sus firmantes aunque la base esté en n+1"
    );
    assert_eq!(con_acta.finalidad_votos_n, 3, "no mueve la finalidad");
    assert_eq!(deshacer(&con_acta, &undo), est, "undo exacto");

    // Sin tabla conocida (ventana más allá de la caducidad): rechazada.
    let lejos = 3 + 331;
    let a_lejos = acta(
        &est,
        &secretas,
        lejos,
        [0x33u8; 32],
        [0x77u8; 32],
        raiz,
        &t,
        &[1],
    )?;
    let (_, _, r) = aplicar_acta_presencia_con_undo(&est, &a_lejos, 800);
    assert_eq!(r, Err(ErrorTransicion::ErrActaTablaDesconocida));

    // Fuera de plazo: `cierre(2) + W_reveal = 6 + 160`.
    let tarde = i64::try_from(cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1).unwrap();
    let (_, _, r) = aplicar_acta_presencia_con_undo(&est, &a, tarde);
    assert_eq!(r, Err(ErrorTransicion::ErrActaPlazo));
    Ok(())
}
