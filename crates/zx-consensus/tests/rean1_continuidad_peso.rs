//! REAN-1 · continuidad: gemela por el flujo por peso de
//! `rean1_continuidad.rs::t9_rotacion_de_clave_de_voto_no_impide_el_certificado` (M9-b1b,
//! corrección C6).
//!
//! Tras fijar la base `m` con una tabla, se rota la clave BLS de voto de la clave 2 y se aplica un
//! `0x09` de la ventana `m+1` que trae la tabla comprometida con la clave vieja. La clave 1 sola
//! alcanza el quórum y el certificado se acepta (la rotación no invalida la tabla comprometida).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    dead_code,
    reason = "test de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use zx_consensus::sectores::{ClaveVoto, ParametrosSector};
use zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo;
use zx_consensus::transicion::{Estado, Fase, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

const K: u64 = 65_536;

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

/// Estado con `indices` registrados (clave BLS determinista) y garantía activa `g` por clave.
fn estado_con(indices: &[u8], g: i128) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
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
        let mut gg = Garantia::nueva();
        gg.activo = Amount::nuevo(i64::try_from(g)?)?;
        est.garantias.insert(ed(*i), gg);
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

/// Tabla canónica (ascendente por bytes de clave) con los pesos dados.
fn tabla_canonica(est: &Estado, pesos: &[(u8, u64)]) -> Vec<ClaveTablaVoto> {
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

/// Fija la base `m` con la tabla `t` como vigente y la asocia a `m`.
fn poner_base(est: &mut Estado, m: u64, t: &[ClaveTablaVoto]) {
    let h = hash_payload(t);
    est.finalidad_votos_n = m;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some(h);
    est.tablas_voto_contenido.insert(h, t.to_vec());
    est.tablas_voto.insert(m, t.to_vec());
    est.cola_tablas_voto.push((m, h));
    est.liquidacion_voto_hasta = Some(m);
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

/// Certificado compacto (`0x09`) con firmas BLS reales sobre el mensaje A3.
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
    _tabla_siguiente: Option<&[ClaveTablaVoto]>,
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
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes,
    })
}

/// T9 · la rotación de la clave de voto de la clave 2 no impide el certificado de la ventana
/// siguiente: la clave 1 sola alcanza el quórum con la **tabla comprometida** (clave vieja).
#[test]
fn t9_rotacion_de_clave_de_voto_no_impide_el_certificado_peso() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2], 50)?;
    let m = 4u64;
    let tabla = tabla_canonica(&base, &[(1, 20), (2, 8)]);
    let mut est = base;
    poner_base(&mut est, m, &tabla);

    // Rotación: la clave BLS de voto de la clave 2 cambia.
    let nueva = bls(9)?;
    let bls_vieja = tabla.iter().find(|c| c.peso == 8).map(|c| c.clave_bls);
    if let Some(cv) = est.claves_voto.get_mut(&ed(2)) {
        cv.clave_bls = nueva.clave_publica().bytes();
    }
    assert!(
        !est.claves_voto
            .values()
            .any(|cv| Some(cv.clave_bls) == bls_vieja),
        "la clave vieja ya no está registrada"
    );

    let n = m + 1;
    let h_t = hash_payload(&tabla);
    let op = op_compacto(
        &est,
        &secretas,
        n,
        [0xBCu8; 32],
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1],
        None,
    )?;
    let (fin, _undo, r) = aplicar_certificado_peso_con_undo(&est, &op, 100);
    println!("T9-PESO n={} r={r:?}", fin.finalidad_votos_n);
    r?;
    assert_eq!(fin.finalidad_votos_n, n);
    Ok(())
}
