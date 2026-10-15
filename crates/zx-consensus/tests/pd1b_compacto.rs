//! PD-1b · certificado compacto por peso (`0x09`), acta de presencia (`0x0A`), tabla vigente por
//! ventana (C5, corrige B-47) y deber de voto sin cuota entera (C6).
//!
//! Pruebas E1–E10 de la orden PD-1b. Construyen el estado con tablas explícitas y firman BLS real
//! sobre el mensaje A3; los bytes del certificado son los de `serial_certificado_peso`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use zx_consensus::sectores::{ClaveVoto, ParametrosSector};
use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, apertura_ventana, cierre_ventana};
use zx_consensus::transicion::votos::{
    aplicar_acta_presencia_con_undo, aplicar_certificado_peso_con_undo,
    aplicar_voto_propio_con_undo,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo, deshacer,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{
    Clave, ClaveSecreta, DOMINIO_VOTO, Firma, LONGITUD_FIJA_CERTIFICADO_PESO, MotivoPeso, Tabla,
};

const K: u64 = 65_536;
const B: u64 = 2;
const CBID: u32 = 0;
const DEN: i128 = 1_401_600_000;

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

fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 0,
        w_min: primitive_types::U256::zero(),
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

/// Serializa una tabla **sin ordenar** (para forzar una cola no canónica).
fn serial_tabla_cruda(claves: &[ClaveTablaVoto]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in claves {
        out.extend_from_slice(&c.clave_bls);
        out.extend_from_slice(&c.peso.to_be_bytes());
        out.push(u8::from(c.activo));
        out.push(u8::from(c.prueba));
    }
    out
}

/// Fija la base `m` con la tabla `t` como vigente (C2) y la asocia a `m`.
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

/// Certificado compacto (`0x09`) o acta (`0x0A`) con firmas BLS reales sobre el mensaje A3.
///
/// `firmantes` son índices Ed25519. `raiz_firmada` permite firmar sobre una raíz distinta de la
/// declarada (para el caso de firma falsa con punto válido).
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

fn voto_propio(
    secreta: &ClaveSecreta,
    clave: u8,
    n: u64,
    candidato: [u8; 32],
    h_t: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let firma: Firma = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]),
    )?;
    Ok(OperacionAlmacenamiento::VotoPropio {
        clave: ed(clave),
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave_bls: pk.bytes(),
        firma: firma.bytes(),
    })
}

/// Aplica un bloque PoST vacío (dispara la liquidación) y devuelve estado y undo.
fn aplica_post(est: &Estado, slot: u64) -> Result<(Estado, zx_consensus::transicion::Undo), Error> {
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
    Ok(aplicar_con_undo(
        est,
        &bloque,
        &params(),
        CBID,
        &ParametrosEvidencia::inactiva(),
    )?)
}

fn slot_liquidacion(n: u64) -> u64 {
    cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1
}

fn deuda(est: &Estado, i: u8) -> i128 {
    est.deuda_ausencia.get(&ed(i)).copied().unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E1 · mismo efecto que el `0x04` equivalente; una unidad menos de peso ⇒ quorum
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E2 · tres ventanas sin certificado, reanudación antes de liquidar: paga solo quien no votó
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e2_b47_reanudacion_antes_de_liquidar() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    poner_base(&mut est, 0, &tabla);
    let h_t = hash_payload(&tabla);
    let candidato = [0x22u8; 32];

    // Ventanas 1 y 2: acta de la clave 1 y voto propio de la clave 2; la 3 no vota.
    for n in [1u64, 2] {
        let acta = op_compacto(
            &est,
            &secretas,
            n,
            candidato,
            h_t,
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1],
            None,
            true,
        )?;
        let (nuevo, _, r) = aplicar_acta_presencia_con_undo(&est, &acta, 100);
        r?;
        est = nuevo;
        let vp = voto_propio(secreta(&secretas, 2)?, 2, n, candidato, h_t)?;
        let (nuevo, _, r) = aplicar_voto_propio_con_undo(&est, &vp, 100);
        r?;
        est = nuevo;
    }
    // La votación se reanuda: un 0x09 para la ventana 3 avanza la base 0 → 3 antes de liquidar.
    let op09 = op_compacto(
        &est,
        &secretas,
        3,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        false,
    )?;
    let (est, _, r) = aplicar_certificado_peso_con_undo(&est, &op09, 100);
    r?;
    assert_eq!(est.finalidad_votos_n, 3);
    for k in 1..=3u64 {
        assert_eq!(
            est.tabla_ventana_voto.get(&k).copied(),
            Some(h_t),
            "la ventana {k} queda asociada a la tabla vigente en ella"
        );
    }

    // Liquidar las tres ventanas de una vez.
    let (fin, _) = aplica_post(&est, slot_liquidacion(3))?;
    assert_eq!(
        deuda(&fin, 1),
        0,
        "la clave 1 votó por acta en las tres ventanas"
    );
    assert_eq!(
        deuda(&fin, 2),
        0,
        "la clave 2 publicó su voto propio en las tres ventanas"
    );
    assert!(
        deuda(&fin, 3) > 0 || fin.activo_de(&ed(3)) < Amount::nuevo(i64::try_from(DEN)?)?,
        "la clave 3 no votó: paga o acumula deuda"
    );
    // Se cobran las **tres** ventanas (1 y 2 sin certificado): 7 + 6 + 7 = 20 brek, con `G` cayendo
    // al ritmo del cobro. Sin C5 solo se cobraría la ventana de la base (7), no las anteriores.
    assert_eq!(
        fin.quemado, 20,
        "las tres ventanas sin certificado cobran a la ausente"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E3 · rechazos, uno por motivo
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e3_rechazos_uno_por_motivo() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    poner_base(&mut est, 1, &tabla);
    let h_t = hash_payload(&tabla);
    let candidato = [0x33u8; 32];
    let slot = 100;

    // (a) ventana: la instancia evaluada no es la del certificado (nivel contrato).
    {
        let op = op_compacto(
            &est,
            &secretas,
            2,
            candidato,
            h_t,
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        let OperacionAlmacenamiento::CertificadoPeso { bytes, .. } = &op else {
            unreachable!()
        };
        let cert = zx_votos::deserializar_certificado_peso(bytes, tabla.len())?;
        let tabla_ref = tabla_contrato(2, &tabla);
        let entrada = zx_votos::EntradaPeso {
            b: B,
            genesis: false,
            n_certificado: 2,
            ventana: 3,
            tabla_vigente: &tabla_ref,
            cert_previo: Some(zx_votos::CertPrevioPeso {
                n: 1,
                h_t_siguiente: h_t,
            }),
            tabla_comprometida: &h_t,
            raiz_estado: &[0u8; 32],
            raiz_firmada: &[0u8; 32],
            firma_ok: true,
            h_t_siguiente_declarada: &h_t,
            h_t_siguiente_aceptadas: std::slice::from_ref(&h_t),
            acta: false,
            mapa_bits: &cert.mapa,
        };
        let res = zx_votos::evaluar_certificado(&entrada)?;
        assert!(res.motivos.contains(&MotivoPeso::Ventana));
    }

    // (b) mapa fuera de tabla: un bit por encima de N.
    {
        let mut op = op_compacto(
            &est,
            &secretas,
            2,
            candidato,
            h_t,
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        if let OperacionAlmacenamiento::CertificadoPeso { bytes, .. } = &mut op {
            bytes[LONGITUD_FIJA_CERTIFICADO_PESO] |= 0x80;
        }
        let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
        assert_eq!(
            r,
            Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::MapaFueraTabla
            ))
        );
    }

    // (c) mapa mal formado (longitud): nivel contrato.
    {
        let tabla_ref = tabla_contrato(2, &tabla);
        let entrada = zx_votos::EntradaPeso {
            b: B,
            genesis: false,
            n_certificado: 2,
            ventana: 2,
            tabla_vigente: &tabla_ref,
            cert_previo: Some(zx_votos::CertPrevioPeso {
                n: 1,
                h_t_siguiente: h_t,
            }),
            tabla_comprometida: &h_t,
            raiz_estado: &[0u8; 32],
            raiz_firmada: &[0u8; 32],
            firma_ok: true,
            h_t_siguiente_declarada: &h_t,
            h_t_siguiente_aceptadas: std::slice::from_ref(&h_t),
            acta: false,
            mapa_bits: &[0u8; 5],
        };
        let res = zx_votos::evaluar_certificado(&entrada)?;
        assert_eq!(res.motivos, vec![MotivoPeso::MapaLongitud]);
    }

    // (d) firmante inactivo.
    {
        let mut tabla_inact = tabla.clone();
        if let Some(c) = tabla_inact
            .iter_mut()
            .find(|c| c.clave_bls == est.claves_voto[&ed(1)].clave_bls)
        {
            c.activo = false;
        }
        let mut est_i = est.clone();
        let h_i = hash_payload(&tabla_inact);
        est_i.finalidad_votos_h_t = Some(h_i);
        est_i.tablas_voto_contenido.insert(h_i, tabla_inact.clone());
        est_i.cola_tablas_voto.push((1, h_i));
        let op = op_compacto(
            &est_i,
            &secretas,
            2,
            candidato,
            h_i,
            [0u8; 32],
            [0u8; 32],
            &tabla_inact,
            &[1, 2],
            None,
            false,
        )?;
        let (_, _, r) = aplicar_certificado_peso_con_undo(&est_i, &op, slot);
        assert_eq!(
            r,
            Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::FirmanteInactivo
            ))
        );
    }

    // (e) firma falsa (punto BLS válido, mensaje distinto).
    {
        let op = op_compacto(
            &est,
            &secretas,
            2,
            candidato,
            h_t,
            [0u8; 32],
            [0xABu8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
        assert_eq!(
            r,
            Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::FirmaFalsa
            ))
        );
    }

    // (f) tabla siguiente ausente cuando cambia.
    {
        let h_otra = [0x77u8; 32];
        let op = op_compacto(
            &est,
            &secretas,
            2,
            candidato,
            h_otra,
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
        assert_eq!(
            r,
            Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::TablaNoDerivada
            ))
        );
    }

    // (g) bytes detrás del mapa: T2 lo rechaza **por forma**, aunque sean una tabla.
    {
        let tabla2 = tabla_canonica(&est, &[(1, 1), (2, 1)]);
        let mut op = op_compacto(
            &est,
            &secretas,
            2,
            candidato,
            hash_payload(&tabla2),
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        if let OperacionAlmacenamiento::CertificadoPeso { bytes, .. } = &mut op {
            let mut invertida = tabla2.clone();
            invertida.reverse();
            bytes.extend_from_slice(&serial_tabla_cruda(&invertida));
        }
        let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
        assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPesoBytes));
    }

    // (h) tabla vigente desconocida.
    {
        let mut est_d = est.clone();
        est_d.finalidad_votos_h_t = Some([0x55u8; 32]);
        let op = op_compacto(
            &est,
            &secretas,
            2,
            candidato,
            [0x55u8; 32],
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        let (_, _, r) = aplicar_certificado_peso_con_undo(&est_d, &op, slot);
        assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPesoTablaDesconocida));
    }

    // (i) ventana anterior a la base.
    {
        let op = op_compacto(
            &est,
            &secretas,
            0,
            candidato,
            h_t,
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
        assert_eq!(r, Err(ErrorTransicion::ErrFinalidadRetrocede));
    }

    // (j) más allá de la caducidad. RA-1 · Y3: con `A > 0` (perfil dev) la guarda 4 se sustituye por
    // la de rearranque y esta ventana abre antes de `s0` (no hay fase activa que la admita). TB-1a ·
    // T9: el slot de aplicación sube a la apertura de la ventana para que no la rechace antes la
    // guarda de ventana futura.
    {
        let n = 1 + 330 + 1;
        let op = op_compacto(
            &est,
            &secretas,
            n,
            candidato,
            h_t,
            [0u8; 32],
            [0u8; 32],
            &tabla,
            &[1, 2],
            None,
            false,
        )?;
        let (_, _, r) =
            aplicar_certificado_peso_con_undo(&est, &op, i64::try_from(apertura_ventana(n))?);
        assert_eq!(r, Err(ErrorTransicion::ErrRearranqueFueraDeFase));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E4 · cambio de tabla: el certificado trae la siguiente; el próximo se valida con ella
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e4_cambio_de_tabla() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3, 4], DEN)?;
    let t1 = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let t2 = tabla_canonica(&base, &[(1, 2), (4, 3)]);
    assert_ne!(hash_payload(&t1), hash_payload(&t2));
    let mut est = base;
    poner_base(&mut est, 1, &t1);
    let h1 = hash_payload(&t1);
    let h2 = hash_payload(&t2);
    // TB-1c · T3: el certificado que cambia a T2 declara `h2`, que tiene que estar en la cola `Q`
    // del estado en que se aplica (la derivó el certificado anterior) y con su contenido guardado.
    est.cola_tablas_voto.push((1, h2));
    est.tablas_voto_contenido.insert(h2, t2.clone());
    let candidato = [0x44u8; 32];

    // 0x09 de la ventana 2 que cambia la tabla a T2. Firma [1,3] (Σ=2, W=3 ⇒ quórum).
    let op = op_compacto(
        &est,
        &secretas,
        2,
        candidato,
        h2,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1, 3],
        Some(&t2),
        false,
    )?;
    let (est2, _, r) = aplicar_certificado_peso_con_undo(&est, &op, 100);
    r?;
    assert_eq!(est2.finalidad_votos_h_t, Some(h2), "la tabla vigente es T2");
    assert!(est2.tablas_voto_contenido.contains_key(&h2));
    assert_eq!(
        est2.tabla_ventana_voto.get(&2),
        Some(&h1),
        "la ventana 2 usó T1"
    );

    // El próximo certificado se valida con T2.
    let op3 = op_compacto(
        &est2,
        &secretas,
        3,
        candidato,
        h2,
        [0u8; 32],
        [0u8; 32],
        &t2,
        &[1, 4],
        None,
        false,
    )?;
    let (est3, _, r) = aplicar_certificado_peso_con_undo(&est2, &op3, 100);
    r?;
    assert_eq!(est3.finalidad_votos_n, 3);

    // La ventana 2 se cobra con la tabla vieja T1: la clave 2 (ausente de T2 y sin voto en la 2)
    // paga. Con T2 no tendría deber.
    let (fin, _) = aplica_post(&est3, slot_liquidacion(3))?;
    assert_eq!(
        fin.activo_de(&ed(2)),
        Amount::nuevo(i64::try_from(DEN - 7)?)?,
        "la ventana 2 se cobra con T1 (clave 2)"
    );
    assert_eq!(fin.quemado, 7, "solo la clave 2, con la tabla vieja");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E5 · acta de presencia
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e5_acta() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    poner_base(&mut est, 1, &tabla);
    let h_t = hash_payload(&tabla);
    let candidato = [0x55u8; 32];
    let n = 2;

    let acta = op_compacto(
        &est,
        &secretas,
        n,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        true,
    )?;
    let (con_acta, _, r) = aplicar_acta_presencia_con_undo(&est, &acta, 100);
    r?;
    let votantes = con_acta.votantes_voto.get(&n).cloned().unwrap_or_default();
    assert!(votantes.contains(&ed(1)) && votantes.contains(&ed(2)));
    assert_eq!(
        con_acta.finalidad_votos_n, est.finalidad_votos_n,
        "no mueve la finalidad"
    );
    assert_eq!(con_acta.finalidad_votos, est.finalidad_votos);

    // Repetida: todos sus firmantes ya constan.
    let (_, _, r) = aplicar_acta_presencia_con_undo(&con_acta, &acta, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrActaRepetida));

    // Fuera de plazo.
    let (_, _, r) = aplicar_acta_presencia_con_undo(&est, &acta, 0);
    assert_eq!(r, Err(ErrorTransicion::ErrActaPlazo));
    let tarde = i64::try_from(cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1)?;
    let (_, _, r) = aplicar_acta_presencia_con_undo(&est, &acta, tarde);
    assert_eq!(r, Err(ErrorTransicion::ErrActaPlazo));

    // Ventana liquidada.
    let mut liquidada = est.clone();
    liquidada.liquidacion_voto_hasta = Some(n);
    let (_, _, r) = aplicar_acta_presencia_con_undo(&liquidada, &acta, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrActaLiquidada));

    // Tabla desconocida.
    let mut sin_tabla = est.clone();
    sin_tabla.finalidad_votos_h_t = Some([0x99u8; 32]);
    let (_, _, r) = aplicar_acta_presencia_con_undo(&sin_tabla, &acta, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrActaTablaDesconocida));

    // Un acta no puede llevar tabla siguiente (códec del cuerpo).
    let mut con_cola = acta.clone();
    if let OperacionAlmacenamiento::ActaPresencia { bytes, .. } = &mut con_cola {
        bytes.extend_from_slice(&[0u8; 58]);
    }
    let (_, _, r) = aplicar_acta_presencia_con_undo(&est, &con_cola, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPesoBytes));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E6 · convivencia 0x04 y 0x09
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E7 · deber sin cuota entera; una inactiva no tiene deber
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e7_deber_sin_cuota_entera() -> Result<(), Error> {
    let (base, _) = estado_con(&[1, 2, 3], 1)?;
    // La clave 1 tiene peso 1 y la 2 peso K, ambas **activas**: `W = 1 + K` y la cuota entera de la
    // clave 1 es `⌊K·1/W⌋ = 0`, así que con la regla anterior no tendría deber. La 3 va inactiva.
    let mut tabla = tabla_canonica(&base, &[(1, 1), (2, K), (3, 1)]);
    for c in &mut tabla {
        if c.clave_bls == base.claves_voto[&ed(3)].clave_bls {
            c.activo = false;
        }
    }
    let mut est = base;
    est.tablas_voto.insert(1, tabla.clone());
    est.liquidacion_voto_hasta = Some(0);

    let (fin, _) = aplica_post(&est, slot_liquidacion(1))?;
    assert!(
        deuda(&fin, 1) > 0,
        "peso mínimo sin voto acumula deuda (C6)"
    );
    assert_eq!(deuda(&fin, 3), 0, "una clave inactiva no tiene deber");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E8 · deshacer exacto
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e8_deshacer_exacto() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    poner_base(&mut est, 1, &tabla);
    let h_t = hash_payload(&tabla);
    let candidato = [0x88u8; 32];

    let op09 = op_compacto(
        &est,
        &secretas,
        2,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        false,
    )?;
    let (con09, undo09, r) = aplicar_certificado_peso_con_undo(&est, &op09, 100);
    r?;
    assert_eq!(deshacer(&con09, &undo09), est, "undo exacto del 0x09");

    let acta = op_compacto(
        &est,
        &secretas,
        2,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[3],
        None,
        true,
    )?;
    let (con_acta, undo_acta, r) = aplicar_acta_presencia_con_undo(&est, &acta, 100);
    r?;
    assert_eq!(deshacer(&con_acta, &undo_acta), est, "undo exacto del 0x0A");

    // Liquidación que cobra.
    let mut est_c = est.clone();
    est_c.liquidacion_voto_hasta = Some(1);
    poner_base(&mut est_c, 1, &tabla);
    let (fin, undo_fin) = aplica_post(&est_c, slot_liquidacion(2))?;
    assert!(fin.quemado > est_c.quemado, "la liquidación cobra");
    assert_eq!(
        deshacer(&fin, &undo_fin),
        est_c,
        "undo exacto de la liquidación que cobra"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E9 · códec de las dos operaciones
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e9_codec_ida_y_vuelta_y_tamanos() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let siguiente = tabla_canonica(&base, &[(1, 5), (2, 4), (3, 6)]);
    let mut est = base;
    poner_base(&mut est, 1, &tabla);

    // 0x09 con tabla siguiente: ida y vuelta y tamaño.
    let op = op_compacto(
        &est,
        &secretas,
        2,
        [0x11u8; 32],
        hash_payload(&siguiente),
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        Some(&siguiente),
        false,
    )?;
    let bytes = op.bytes_canonicos()?;
    let (vuelta, consumidos) = OperacionAlmacenamiento::desde_canonica(&bytes)?;
    assert_eq!(vuelta, op);
    assert_eq!(consumidos, bytes.len());
    assert_eq!(bytes[0], 0x09);
    let n = tabla.len();
    let mapa = n.div_ceil(8);
    // TB-1c · T2: el certificado ya no lleva tabla; mide `1 + 32 + 4 + LONGITUD_FIJA + mapa`.
    let esperado = 1 + 32 + 4 + LONGITUD_FIJA_CERTIFICADO_PESO + mapa;
    assert_eq!(bytes.len(), esperado, "tamaño canónico del 0x09");
    assert_eq!(
        LONGITUD_FIJA_CERTIFICADO_PESO + mapa,
        200 + 1,
        "el certificado mide 200 + ⌈N/8⌉ sin la tabla siguiente"
    );

    // 0x0A sin tabla siguiente.
    let acta = op_compacto(
        &est,
        &secretas,
        2,
        [0x11u8; 32],
        hash_payload(&tabla),
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1],
        None,
        true,
    )?;
    let bytes_a = acta.bytes_canonicos()?;
    let (vuelta_a, consumidos_a) = OperacionAlmacenamiento::desde_canonica(&bytes_a)?;
    assert_eq!(vuelta_a, acta);
    assert_eq!(consumidos_a, bytes_a.len());
    assert_eq!(bytes_a[0], 0x0A);
    assert_eq!(
        bytes_a.len(),
        1 + 32 + 4 + LONGITUD_FIJA_CERTIFICADO_PESO + mapa
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// E10 · coste
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn e10_coste_1024() -> Result<(), Error> {
    const CLAVES: u32 = 1024;
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut secretas: Vec<(u32, ClaveSecreta)> = Vec::new();
    let mut tabla = Vec::with_capacity(CLAVES as usize);
    for i in 0..CLAVES {
        let mut ikm = [0u8; 32];
        ikm[..4].copy_from_slice(&i.to_le_bytes());
        ikm[31] = 0xA5;
        let s = ClaveSecreta::generar(&ikm)?;
        let e = ClavePublica::desde_bytes({
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b
        });
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        est.garantias.insert(e, Garantia::nueva());
        tabla.push(ClaveTablaVoto {
            clave_bls: s.clave_publica().bytes(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        });
        secretas.push((i, s));
    }
    tabla.sort_by_key(|a| a.clave_bls);
    est.tablas_voto.insert(1, tabla.clone());
    est.finalidad_votos_n = 1;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some(hash_payload(&tabla));
    est.tablas_voto_contenido
        .insert(hash_payload(&tabla), tabla.clone());
    est.cola_tablas_voto.push((1, hash_payload(&tabla)));
    est.liquidacion_voto_hasta = Some(1);

    let candidato = [0x99u8; 32];
    let h_t = hash_payload(&tabla);
    let mensaje = zx_votos::mensaje_voto_peso(2, &candidato, &h_t, &[0u8; 32]);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for (i, s) in &secretas {
        let _ = i;
        let pos = tabla
            .iter()
            .position(|c| c.clave_bls == s.clave_publica().bytes())
            .ok_or("clave fuera de la tabla")?;
        votos.push((pos + 1, zx_votos::firmar(s, DOMINIO_VOTO, &mensaje)?));
    }
    let cert = zx_votos::construir_certificado(
        2,
        candidato,
        h_t,
        [0u8; 32],
        &tabla_contrato(2, &tabla),
        &votos,
    )?;
    let op = OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    };

    let t0 = Instant::now();
    let (est2, _, r) = aplicar_certificado_peso_con_undo(&est, &op, 100);
    r?;
    let t_aplicar = t0.elapsed();

    let t1 = Instant::now();
    let (fin, _) = aplica_post(&est2, slot_liquidacion(2))?;
    let t_liquidar = t1.elapsed();
    println!(
        "PD1B-E10 claves={CLAVES} aplicar_0x09={t_aplicar:?} liquidar_ventana={t_liquidar:?} quemado={}",
        fin.quemado
    );
    assert!(
        t_aplicar < Duration::from_secs(10) && t_liquidar < Duration::from_secs(10),
        "coste acotado (espacio del agente, no medida de clase M)"
    );
    assert_eq!(fin.finalidad_votos_n, 2);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Cobertura del acta que solo aporta claves nuevas parcialmente
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn acta_parcial_aporta_claves_nuevas() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    poner_base(&mut est, 1, &tabla);
    let h_t = hash_payload(&tabla);
    let n = 2;
    let acta1 = op_compacto(
        &est,
        &secretas,
        n,
        [0x11u8; 32],
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1],
        None,
        true,
    )?;
    let (uno, _, r) = aplicar_acta_presencia_con_undo(&est, &acta1, 100);
    r?;
    let acta2 = op_compacto(
        &est,
        &secretas,
        n,
        [0x11u8; 32],
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        true,
    )?;
    let (dos, _, r) = aplicar_acta_presencia_con_undo(&uno, &acta2, 100);
    r?;
    let v = dos.votantes_voto.get(&n).cloned().unwrap_or_default();
    assert!(v.contains(&ed(1)) && v.contains(&ed(2)));
    let _ = BTreeSet::<u8>::new();
    Ok(())
}
// F3 · M9-b1 · gemela de `e1_equivalencia_con_04_y_quorum` con los **valores fijos** que daba la
// comparación con el `0x04`: `h_T` se leyó de una ejecución de la prueba original el 2026-10-06
// (tabla canónica de las claves 1,2,3 con peso 1; `TMP_E1_H_T`).
#[test]
fn e1_quorum_valores_fijos() -> Result<(), Error> {
    let (base, secretas) = estado_con(&[1, 2, 3], DEN)?;
    let tabla = tabla_canonica(&base, &[(1, 1), (2, 1), (3, 1)]);
    let mut est = base;
    poner_base(&mut est, 1, &tabla);
    let h_t: [u8; 32] = [
        179, 71, 37, 203, 183, 105, 123, 227, 120, 27, 174, 43, 166, 38, 110, 207, 205, 81, 248,
        71, 64, 93, 150, 122, 116, 112, 17, 86, 52, 109, 13, 220,
    ];
    assert_eq!(
        hash_payload(&tabla),
        h_t,
        "la tabla montada es la del hash fijo"
    );
    let candidato = [0x11u8; 32];
    let n = 2;

    let op09 = op_compacto(
        &est,
        &secretas,
        n,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2, 3],
        None,
        false,
    )?;
    let (con09, _, r) = aplicar_certificado_peso_con_undo(&est, &op09, 100);
    r?;
    assert_eq!(con09.finalidad_votos_n, 2, "la finalidad avanza a n");
    assert_eq!(
        con09.finalidad_votos,
        Some(BlockHash::from_digest(Digest::from_bytes(candidato)))
    );
    assert_eq!(con09.finalidad_votos_h_t, Some(h_t));

    // Una unidad menos: solo la clave 1 (Σ = 1) ⇒ 3·1 < 2·3 ⇒ quorum.
    let op_menos = op_compacto(
        &est,
        &secretas,
        n,
        candidato,
        h_t,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1],
        None,
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &op_menos, 100);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::Quorum
        ))
    );
    Ok(())
}
