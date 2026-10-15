//! PD-1c · los cuatro huecos de PD-1b (G1, G3, G4, G5) — pruebas H1–H9.
//!
//! H1/H2 fijan G1 (primer `0x09` sin base y encadenado); H3 fija G3 (acta en ventana con cambio
//! de tabla); H4 fija G4 (voto propio sobre A3); H5/H6 fijan G5 (evidencia de dos votos por peso
//! `0x0B`); H7 el códec; H8 el deshacer exacto; H9 el recorrido completo de la pregunta falsable.
//!
//! Toda firma BLS es real; los estados se construyen con sectores reales (para que
//! `tabla_canonica` derive pesos) salvo donde la prueba fija otra cosa.

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
    T_INST_VOTOS, W_REVEAL_SLOTS_VOTOS, aplicar_acta_presencia_con_undo,
    aplicar_certificado_peso_con_undo, aplicar_evidencia_votos_peso_con_undo,
    aplicar_voto_propio_con_undo, cierre_ventana, derivar_tabla_sin_base_con_undo, tabla_canonica,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Undo, aplicar_con_undo, deshacer,
};
use zx_core::{
    Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, LONGITUD_CLAVE_BLS,
    OperacionAlmacenamiento, VotoPesoEvidencia,
};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, LONGITUD_HASH, MotivoPeso, Tabla};

const CBID: u32 = 0;
const DEN: i64 = 1_401_600_000;

type Error = Box<dyn std::error::Error>;

/// TB-1c-2 · X2 · montaje autorizado para las pruebas que aplican un **primer** certificado sobre un
/// estado montado a mano: llama al gancho de producto `derivar_tabla_sin_base` con el slot del bloque
/// (no una copia), de modo que la derivada que el certificado declara esté en `Q`.
fn preparar_cola_sin_base(est: &mut Estado, slot: u64) {
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(est, slot);
    *est = nuevo;
}

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

/// Orden canónico (ascendente por bytes de clave BLS), como el que indexa el mapa de bits.
fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
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

/// Certificado compacto (`0x09`) o acta (`0x0A`) con firmas BLS reales sobre A3.
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

/// Voto propio sobre el **mensaje antiguo** (raíz = candidato).
fn voto_propio_antiguo(
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
        &zx_votos::mensaje_voto(n, &candidato, &h_t, &candidato),
    )?;
    Ok(OperacionAlmacenamiento::VotoPropio {
        clave: ed(clave),
        n,
        candidato,
        h_t_siguiente: h_t,
        // RE-2c · el mensaje antiguo (raíz = candidato) ya no se acepta: el `0x08` lleva la raíz
        // cero y la firma sobre `candidato` no verifica con ella → rechazo por firma.
        raiz_estado: [0u8; 32],
        clave_bls: pk.bytes(),
        firma: firma.bytes(),
    })
}

/// Voto propio sobre A3 (`peso::mensaje_voto_peso`) con la raíz dada.
fn voto_propio_a3(
    secreta: &ClaveSecreta,
    clave: u8,
    n: u64,
    candidato: [u8; 32],
    h_t: [u8; 32],
    raiz: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let firma: Firma = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_t, &raiz),
    )?;
    Ok(OperacionAlmacenamiento::VotoPropio {
        clave: ed(clave),
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: raiz,
        clave_bls: pk.bytes(),
        firma: firma.bytes(),
    })
}

/// Evidencia de dos votos por peso (`0x0B`) con las dos firmas A3 reales.
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

/// Aplica un bloque PoST vacío (dispara la liquidación) y devuelve estado y undo.
fn aplica_post(est: &Estado, slot: u64) -> Result<(Estado, Undo), Error> {
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
// H1 · G1: primer `0x09` sin base sella con la tabla canónica; una unidad menos ⇒ quorum
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h1_primer_certificado_sin_base() -> Result<(), Error> {
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    // TB-1c · sector diferido (activo a partir del slot 62): no pesa en la tabla del slot de
    // apertura (`n·T_INST = 2`) pero sí en la del slot del bloque (100). Distingue T5 del slot del
    // bloque (control rojo R5).
    let s4 = bls(4)?;
    base.claves_voto.insert(
        ed(4),
        ClaveVoto {
            clave_bls: s4.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let (id4, mut reg4) = registro(&base.parametros_sector, ed(4), 0);
    reg4.etapa = Etapa::Precomprometido;
    reg4.alta_slot = 50;
    base.sectores.insert(id4, reg4);
    assert!(
        base.finalidad_votos.is_none() && base.finalidad_votos_h_t.is_none(),
        "sin finalidad por votos"
    );
    // TB-1c-2 · X2 · T5′: sin base, el gancho X1 ya derivó y guardó la tabla de la ventana 1.
    preparar_cola_sin_base(&mut base, T_INST_VOTOS);
    let slot = 100i64;
    let slot_apertura = i64::try_from(T_INST_VOTOS)?;
    let tabla = canoniza(tabla_canonica(&base, slot_apertura));
    assert_eq!(tabla.len(), 3, "tres claves con peso en la apertura");
    assert_eq!(
        canoniza(tabla_canonica(&base, slot)).len(),
        4,
        "el sector diferido sí pesa en el slot del bloque"
    );
    let h = hash_payload(&tabla);
    let candidato = [0x11u8; 32];

    // Dos tercios (claves 1 y 2 de W = 3): 3·2 ≥ 2·3.
    let op = op_compacto(
        &base,
        &secretas,
        1,
        candidato,
        h,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        false,
    )?;
    let (sellado, undo, r) = aplicar_certificado_peso_con_undo(&base, &op, slot);
    r?;
    assert_eq!(
        sellado.finalidad_votos_n, 1,
        "la primera ventana queda sellada"
    );
    assert_eq!(sellado.finalidad_votos_h_t, Some(h));
    assert!(
        sellado.tablas_voto_contenido.contains_key(&h),
        "la tabla vigente queda conocida"
    );
    assert_eq!(deshacer(&sellado, &undo), base, "undo exacto");

    // Una unidad menos (solo la clave 1): 3·1 < 2·3 ⇒ quorum.
    let op_menos = op_compacto(
        &base,
        &secretas,
        1,
        candidato,
        h,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1],
        None,
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&base, &op_menos, slot);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::Quorum
        ))
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H2 · G1: el segundo `0x09` encadena; un mapa montado contra otra tabla se rechaza
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h2_encadenado_y_mapa_de_otra_tabla() -> Result<(), Error> {
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let slot = 100i64;
    preparar_cola_sin_base(&mut base, u64::try_from(slot)?);
    let tabla = canoniza(tabla_canonica(&base, slot));
    let h = hash_payload(&tabla);
    let candidato = [0x22u8; 32];

    let op1 = op_compacto(
        &base,
        &secretas,
        1,
        candidato,
        h,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        false,
    )?;
    let (est1, _, r) = aplicar_certificado_peso_con_undo(&base, &op1, slot);
    r?;

    // Segundo `0x09`: encadena con el primero (tabla sin cambio) y avanza a 2.
    let op2 = op_compacto(
        &est1,
        &secretas,
        2,
        candidato,
        h,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        false,
    )?;
    let (est2, _, r) = aplicar_certificado_peso_con_undo(&est1, &op2, slot);
    r?;
    assert_eq!(est2.finalidad_votos_n, 2, "el segundo encadena");

    // Una clave registrada después: la tabla canónica del estado pasa a tener 4 claves. Un `0x09`
    // cuyo mapa/firma se montó contra esa tabla nueva (pero que dice que la tabla no cambia) se
    // rechaza: el consenso lo verifica contra la tabla vigente (3 claves).
    let (mut est3, secretas3) =
        estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    // El estado est3 arranca sin base; le ponemos la base ya fijada por est2.
    est3.tablas_voto_contenido = est2.tablas_voto_contenido.clone();
    est3.tablas_voto = est2.tablas_voto.clone();
    est3.finalidad_votos_n = est2.finalidad_votos_n;
    est3.finalidad_votos = est2.finalidad_votos;
    est3.finalidad_votos_h_t = est2.finalidad_votos_h_t;
    // TB-1c · T3: sin la cola `Q` copiada, la huella declarada no estaría derivada.
    est3.cola_tablas_voto = est2.cola_tablas_voto.clone();
    let tabla_nueva = canoniza(tabla_canonica(&est3, slot));
    assert_eq!(tabla_nueva.len(), 4, "la clave 4 ya pesa");
    let op_malo = op_compacto(
        &est3,
        &secretas3,
        3,
        candidato,
        h, // declara que la tabla no cambia
        [0u8; 32],
        [0u8; 32],
        &tabla_nueva, // pero el mapa y las firmas se montaron contra 4 claves
        &[1, 2, 4],
        None,
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est3, &op_malo, slot);
    assert!(
        matches!(
            r,
            Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::FirmaFalsa | MotivoPeso::MapaFueraTabla
            ))
        ),
        "mapa montado contra otra tabla: {r:?}"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H3 · G3: acta que declara una tabla siguiente distinta acredita y no mueve nada
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h3_acta_con_cambio_de_tabla() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let t1 = canoniza(tabla_canonica(&base, 100));
    let mut est = base;
    poner_base(&mut est, 1, &t1);
    let h1 = hash_payload(&t1);
    // La tabla siguiente declarada por el acta es arbitraria (el acta no la transporta).
    let h2 = [0x77u8; 32];
    assert_ne!(h1, h2);
    let n = 2;
    let raiz = [0xABu8; 32];

    let acta = op_compacto(
        &est,
        &secretas,
        n,
        [0x33u8; 32],
        h2,
        raiz,
        raiz,
        &t1,
        &[1, 2],
        None,
        true,
    )?;
    let n_antes = est.finalidad_votos_n;
    let tabla_antes = est.finalidad_votos_h_t;
    let (con_acta, undo, r) = aplicar_acta_presencia_con_undo(&est, &acta, 100);
    r?;
    let votantes = con_acta.votantes_voto.get(&n).cloned().unwrap_or_default();
    assert!(
        votantes.contains(&ed(1)) && votantes.contains(&ed(2)),
        "acredita a sus firmantes"
    );
    assert_eq!(con_acta.finalidad_votos_n, n_antes, "no mueve la finalidad");
    assert_eq!(
        con_acta.finalidad_votos_h_t, tabla_antes,
        "no cambia la tabla vigente"
    );
    assert_eq!(deshacer(&con_acta, &undo), est, "undo exacto");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H4 · G4: voto propio sobre A3 con raíz cero; antiguo; A3 con otra raíz rechazado
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h4_voto_propio_sobre_a3() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let tabla = canoniza(tabla_canonica(&base, 100));
    let mut est = base;
    poner_base(&mut est, 1, &tabla);
    let cand = [0x44u8; 32];
    let h_t = [0x55u8; 32];

    // (a) mensaje antiguo: **rechazado con `ErrVotoPropioFirma`** y el estado no cambia.
    let vp_antiguo = voto_propio_antiguo(secreta(&secretas, 1)?, 1, 2, cand, h_t)?;
    let (e1, _, r) = aplicar_voto_propio_con_undo(&est, &vp_antiguo, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioFirma));
    assert_eq!(e1, est, "el estado no cambia");

    // (b) A3 con raíz cero: aceptado (parte del estado inicial).
    let vp_a3 = voto_propio_a3(secreta(&secretas, 2)?, 2, 3, cand, h_t, [0u8; 32])?;
    let (e2, _, r) = aplicar_voto_propio_con_undo(&est, &vp_a3, 100);
    r?;
    assert!(e2.votantes_voto[&3].contains(&ed(2)));

    // (c) A3 con otra raíz: **aceptado** si la firma es sobre la raíz que el `0x08` trae (C2′ no
    //     compara la raíz con la del certificado ni con el estado).
    let vp_otra = voto_propio_a3(secreta(&secretas, 3)?, 3, 4, cand, h_t, [0x99u8; 32])?;
    let (e3, _, r) = aplicar_voto_propio_con_undo(&e2, &vp_otra, 100);
    r?;
    assert!(e3.votantes_voto[&4].contains(&ed(3)));

    // (d) firma hecha sobre `[0x99;32]` pero el campo `raiz_estado` trae otra (`[0xAA;32]`):
    //     **rechazado** con `ErrVotoPropioFirma` (la firma no vale con la raíz que trae).
    let mut vp_firma_otra = voto_propio_a3(secreta(&secretas, 3)?, 3, 5, cand, h_t, [0x99u8; 32])?;
    if let OperacionAlmacenamiento::VotoPropio { raiz_estado, .. } = &mut vp_firma_otra {
        *raiz_estado = [0xAAu8; 32];
    }
    let (e4, _, r) = aplicar_voto_propio_con_undo(&e3, &vp_firma_otra, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioFirma));
    assert_eq!(e4, e3, "el estado no cambia");
    Ok(())
}

/// TB-1a · T9 · un `0x09` de una ventana futura (`n = u64::MAX`) se rechaza con
/// [`ErrorTransicion::ErrCertificadoVentanaFutura`] y el estado no cambia. Sustituye la
/// caracterización anterior («se acepta sellando la ventana máxima») porque la guarda de ventana no
/// futura entró en el consenso.
#[test]
fn certificado_peso_indice_maximo_no_desborda() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let slot = 100i64;
    let tabla = canoniza(tabla_canonica(&base, slot));
    let h = hash_payload(&tabla);
    let op = op_compacto(
        &base,
        &secretas,
        u64::MAX,
        [0x77u8; 32],
        h,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        false,
    )?;
    let (estado, _undo, r) = aplicar_certificado_peso_con_undo(&base, &op, slot);
    // `apertura_ventana(u64::MAX)` satura a `u64::MAX`, muy por encima del slot 100.
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoVentanaFutura),
        "un 0x09 de ventana futura se rechaza"
    );
    assert_eq!(estado, base, "el estado no cambia");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H5 · G5: la evidencia `0x0B` castiga como el `0x05`; repetida y fuera de plazo se rechazan
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H6 · G5 rechazos: idénticos, orden no canónico, firma falsa, BLS no registrada, ventanas
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h6_rechazos_evidencia_peso() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, 50)])?;
    let n = 3;
    let slot = 10;
    let evp = param_evidencia();
    let p = params();
    let s1 = secreta(&secretas, 1)?;

    // Votos idénticos.
    let ident = evidencia_peso(
        s1, n, [0x01; 32], [0xAA; 32], [0x10; 32], n, [0x01; 32], [0xAA; 32], [0x10; 32],
    )?;
    let (_, _, r) = aplicar_evidencia_votos_peso_con_undo(&base, &ident, ed(9), &p, &evp, slot);
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    // Orden no canónico.
    let desorden = evidencia_peso(
        s1, n, [0x02; 32], [0xAA; 32], [0x10; 32], n, [0x01; 32], [0xAA; 32], [0x10; 32],
    )?;
    let (_, _, r) = aplicar_evidencia_votos_peso_con_undo(&base, &desorden, ed(9), &p, &evp, slot);
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    // Firma de voto1 sobre un mensaje distinto (raíz cambiada).
    {
        let f1 = zx_votos::firmar(
            s1,
            DOMINIO_VOTO,
            &zx_votos::mensaje_voto_peso(n, &[0x01; 32], &[0xAA; 32], &[0xFF; 32]),
        )?;
        let f2 = zx_votos::firmar(
            s1,
            DOMINIO_VOTO,
            &zx_votos::mensaje_voto_peso(n, &[0x02; 32], &[0xBB; 32], &[0x20; 32]),
        )?;
        let mala = OperacionAlmacenamiento::EvidenciaVotosPeso {
            clave: ed(200),
            clave_bls: s1.clave_publica().bytes(),
            voto1: VotoPesoEvidencia {
                n,
                candidato: [0x01; 32],
                h_t_siguiente: [0xAA; 32],
                raiz_estado: [0x10; 32],
                firma: f1.bytes(),
            },
            voto2: VotoPesoEvidencia {
                n,
                candidato: [0x02; 32],
                h_t_siguiente: [0xBB; 32],
                raiz_estado: [0x20; 32],
                firma: f2.bytes(),
            },
        };
        let (_, _, r) = aplicar_evidencia_votos_peso_con_undo(&base, &mala, ed(9), &p, &evp, slot);
        assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));
    }

    // Clave BLS no registrada.
    let ajena = bls(7)?;
    let no_reg = evidencia_peso(
        &ajena, n, [0x01; 32], [0xAA; 32], [0x10; 32], n, [0x02; 32], [0xBB; 32], [0x20; 32],
    )?;
    let (_, _, r) = aplicar_evidencia_votos_peso_con_undo(&base, &no_reg, ed(9), &p, &evp, slot);
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    // Ventanas distintas sin hecho de la cadena: inadmisible (AT-1b · W4).
    let dos_ventanas = evidencia_peso(
        s1,
        n,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        n + 1,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )?;
    let (_, _, r) =
        aplicar_evidencia_votos_peso_con_undo(&base, &dos_ventanas, ed(9), &p, &evp, slot);
    // AT-1b · sin hecho de la cadena, la evidencia de ventanas distintas es inadmisible.
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaInadmisible));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H7 · códec del `0x0B`: ida y vuelta, tamaño y orden canónico
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h7_codec_evidencia_peso() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, 50)])?;
    let op = evidencia_peso(
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
    let bytes = op.bytes_canonicos()?;
    let (vuelta, consumidos) = OperacionAlmacenamiento::desde_canonica(&bytes)?;
    assert_eq!(vuelta, op, "ida y vuelta");
    assert_eq!(consumidos, bytes.len(), "consume todos los bytes");
    assert_eq!(bytes[0], 0x0B, "la clase va primero");
    let esperado = 1 + 32 + LONGITUD_CLAVE_BLS + 2 * (8 + 3 * LONGITUD_HASH + 96);
    assert_eq!(bytes.len(), esperado, "tamaño canónico del 0x0B");
    assert_eq!(esperado, 481, "1 + 32 + 48 + 2·200");

    // El códec rechaza el orden no canónico.
    let OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave,
        clave_bls,
        voto1,
        voto2,
    } = op
    else {
        unreachable!()
    };
    let invertida = OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave,
        clave_bls,
        voto1: voto2,
        voto2: voto1,
    };
    assert!(
        invertida.bytes_canonicos().is_err(),
        "orden no canónico rechazado"
    );
    let _ = base;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H8 · deshacer exacto con `0x09` de primera ventana, `0x0B` y `0x08` sobre A3
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h8_deshacer_exacto() -> Result<(), Error> {
    // `0x09` de primera ventana (sin base).
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    preparar_cola_sin_base(&mut base, 100);
    let tabla = canoniza(tabla_canonica(&base, 100));
    let h = hash_payload(&tabla);
    let op09 = op_compacto(
        &base,
        &secretas,
        1,
        [0x11u8; 32],
        h,
        [0u8; 32],
        [0u8; 32],
        &tabla,
        &[1, 2],
        None,
        false,
    )?;
    let (con09, undo09, r) = aplicar_certificado_peso_con_undo(&base, &op09, 100);
    r?;
    assert_eq!(deshacer(&con09, &undo09), base, "undo del 0x09 sin base");

    // `0x0B`.
    let (base2, secretas2) = estado_sectores(&[(1, 1, 50)])?;
    let opb = evidencia_peso(
        secreta(&secretas2, 1)?,
        3,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        3,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )?;
    let (conb, undob, r) = aplicar_evidencia_votos_peso_con_undo(
        &base2,
        &opb,
        ed(9),
        &params(),
        &param_evidencia(),
        10,
    );
    r?;
    assert_eq!(deshacer(&conb, &undob), base2, "undo del 0x0B");

    // `0x08` sobre A3.
    let (base3, secretas3) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let tabla3 = canoniza(tabla_canonica(&base3, 100));
    let mut est3 = base3;
    poner_base(&mut est3, 1, &tabla3);
    let vp = voto_propio_a3(
        secreta(&secretas3, 1)?,
        1,
        2,
        [0x44u8; 32],
        [0x55u8; 32],
        [0u8; 32],
    )?;
    let (conv, undov, r) = aplicar_voto_propio_con_undo(&est3, &vp, 100);
    r?;
    assert_eq!(deshacer(&conv, &undov), est3, "undo del 0x08 A3");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// H9 · recorrido completo de la pregunta falsable en un solo estado
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn h9_recorrido_pregunta_falsable() -> Result<(), Error> {
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    assert!(
        base.finalidad_votos.is_none() && base.finalidad_votos_h_t.is_none(),
        "sin finalidad por votos ni 0x04/0x05/0x06/0x07"
    );
    let slot_cert = 2i64;
    preparar_cola_sin_base(&mut base, u64::try_from(slot_cert)?);
    let t1 = canoniza(tabla_canonica(&base, slot_cert));
    let h1 = hash_payload(&t1);
    let cand1 = [0x01u8; 32];

    // (1) primera ventana por `0x09` sin base, unánime.
    let op1 = op_compacto(
        &base,
        &secretas,
        1,
        cand1,
        h1,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1, 2, 3],
        None,
        false,
    )?;
    let (est1, _, r) = aplicar_certificado_peso_con_undo(&base, &op1, slot_cert);
    r?;
    assert_eq!(est1.finalidad_votos_n, 1, "(1) primera ventana sellada");
    // TB-1c · T3: la huella que el certificado de reanudación puede declarar es la última derivada
    // de la cola (T2 ya no viaja en el certificado).
    let h_der = est1
        .cola_tablas_voto
        .last()
        .map(|(_, h)| *h)
        .ok_or("cola vacía tras (1)")?;

    // Tabla siguiente hipotética T2 (la ventana 2 cambia de tabla). No la deriva el estado: el
    // acta solo declara su hash.
    let mut t2 = t1.clone();
    if let Some(c) = t2
        .iter_mut()
        .find(|c| c.clave_bls == est1.claves_voto[&ed(3)].clave_bls)
    {
        c.peso = 2;
        c.garantia = 2;
    }
    let t2 = canoniza(t2);
    let h2 = hash_payload(&t2);
    assert_ne!(h1, h2);

    // (2) acta en la ventana 2 declarando T2, con la clave 1.
    let acta = op_compacto(
        &est1,
        &secretas,
        2,
        [0x02u8; 32],
        h2,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1],
        None,
        true,
    )?;
    let (est2, _, r) = aplicar_acta_presencia_con_undo(&est1, &acta, 20);
    r?;
    assert!(
        est2.votantes_voto[&2].contains(&ed(1)),
        "(2) el acta acredita a la clave 1 en la ventana con cambio de tabla"
    );

    // (3) voto propio A3 de la clave 3 en la ventana 2.
    let vp = voto_propio_a3(secreta(&secretas, 3)?, 3, 2, [0x02u8; 32], h2, [0u8; 32])?;
    let (est3, _, r) = aplicar_voto_propio_con_undo(&est2, &vp, 20);
    r?;
    assert!(
        est3.votantes_voto[&2].contains(&ed(3)),
        "(3) voto propio firmado sobre A3"
    );

    // Reanudación: `0x09` de la ventana 3 que cambia la tabla a T2 (firmantes 1 y 3 de T1).
    let op3 = op_compacto(
        &est3,
        &secretas,
        3,
        [0x03u8; 32],
        h_der,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1, 3],
        None,
        false,
    )?;
    let (est4, _, r) = aplicar_certificado_peso_con_undo(&est3, &op3, 20);
    r?;
    assert_eq!(est4.finalidad_votos_n, 3, "reanudación hasta la ventana 3");
    assert_eq!(
        est4.finalidad_votos_h_t,
        Some(h_der),
        "tabla vigente derivada"
    );
    assert_eq!(est4.tabla_ventana_voto.get(&2).copied(), Some(h1));
    assert_eq!(est4.tabla_ventana_voto.get(&3).copied(), Some(h1));

    // (4) doble voto por peso de la clave 1 en la ventana 2: dos votos A3 distintos.
    let opb = evidencia_peso(
        secreta(&secretas, 1)?,
        2,
        [0x10u8; 32],
        h2,
        [0u8; 32],
        2,
        [0x20u8; 32],
        h2,
        [0u8; 32],
    )?;
    let (est5, _, r) = aplicar_evidencia_votos_peso_con_undo(
        &est4,
        &opb,
        ed(9),
        &params(),
        &param_evidencia(),
        20,
    );
    r?;
    assert!(
        est5.garantias[&ed(1)].incidentes.len() == 1,
        "(4) doble voto castigado"
    );
    assert!(est5.quemado > est4.quemado, "el doble voto quema");
    let quemado_antes_liq = est5.quemado;

    // Liquidación: la ventana 2 y la 3 se cobran con T1; solo la clave 2 no votó en ellas.
    let (fin, _) = aplica_post(&est5, slot_liquidacion(3))?;
    assert_eq!(deuda(&fin, 1), 0, "la clave 1 votó (acta) en la ventana 2");
    assert_eq!(deuda(&fin, 3), 0, "la clave 3 votó (A3) en la ventana 2");
    assert!(
        deuda(&fin, 2) > 0 || fin.activo_de(&ed(2)) < est5.activo_de(&ed(2)),
        "la clave 2 no votó en la ventana 2: paga o acumula deuda"
    );
    assert!(
        fin.quemado > quemado_antes_liq,
        "la liquidación cobra la ausencia"
    );
    Ok(())
}
// F3 · M9-b1 · gemela de `h5_evidencia_peso_como_05` con los **valores fijos** que daba la
// comparación con el `0x05`, leídos de una ejecución de la prueba original el 2026-10-06
// (`TMP_H5_QUEMADO=72 CONGELADO=Amount(95) INCIDENTES=1 ACTIVO9=Amount(0)`).
#[test]
fn h5_evidencia_peso_valores_fijos() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, 50)])?;
    let n = 3;
    let slot = 10;
    let evp = param_evidencia();
    let p = params();

    let opb = evidencia_peso(
        secreta(&secretas, 1)?,
        n,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        n,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )?;
    let (nb, ub, rb) = aplicar_evidencia_votos_peso_con_undo(&base, &opb, ed(9), &p, &evp, slot);
    rb?;
    assert_eq!(nb.quemado, 72, "confisca y quema");
    assert_eq!(nb.garantias[&ed(1)].congelado, Amount::nuevo(95)?);
    assert_eq!(nb.garantias[&ed(1)].incidentes.len(), 1, "un incidente");
    assert_eq!(nb.garantias[&ed(9)].activo, Amount::CERO);

    // Repetida: el incidente ya está.
    let (_, _, r) = aplicar_evidencia_votos_peso_con_undo(&nb, &opb, ed(9), &p, &evp, slot);
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaDuplicada));

    // Fuera de plazo (`cierre(n) + plazo_slots`).
    let tarde = cierre_ventana(n) + 300 + 1;
    let (_, _, r) = aplicar_evidencia_votos_peso_con_undo(&base, &opb, ed(9), &p, &evp, tarde);
    assert_eq!(r, Err(ErrorTransicion::ErrEvidenciaVoto));

    assert_eq!(deshacer(&nb, &ub), base, "undo exacto");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TB-1c · T3/T5/T6: la huella declarada tiene que ser una derivada del estado
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// P1/B-58 · T3: dos tercios del peso firman un `h_t_siguiente` cuyo contenido existe en el estado
/// pero que no está en la cola `Q`; el certificado se rechaza con `TablaNoDerivada`.
#[test]
fn tabla_no_derivada_se_rechaza() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let t1 = canoniza(tabla_canonica(&base, 100));
    let mut est = base;
    poner_base(&mut est, 1, &t1);
    let h1 = hash_payload(&t1);
    // Una tabla distinta, con su contenido presente pero **fuera** de la cola.
    let mut t2 = t1.clone();
    if let Some(c) = t2
        .iter_mut()
        .find(|c| c.clave_bls == est.claves_voto[&ed(3)].clave_bls)
    {
        c.peso = 2;
        c.garantia = 2;
    }
    let t2 = canoniza(t2);
    let h2 = hash_payload(&t2);
    assert_ne!(h1, h2);
    est.tablas_voto_contenido.insert(h2, t2.clone());
    assert!(!est.cola_tablas_voto.iter().any(|(_, h)| *h == h2));

    let op = op_compacto(
        &est,
        &secretas,
        2,
        [0x44u8; 32],
        h2,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &op, 100);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}

/// P6 · T3: un certificado de la ventana siguiente con la huella vigente (que sí está en `Q`) se
/// acepta.
#[test]
fn sin_cambio_de_tabla_se_acepta() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let t1 = canoniza(tabla_canonica(&base, 100));
    let mut est = base;
    poner_base(&mut est, 1, &t1);
    let h1 = hash_payload(&t1);
    let op = op_compacto(
        &est,
        &secretas,
        2,
        [0x44u8; 32],
        h1,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&est, &op, 100);
    r?;
    assert_eq!(nuevo.finalidad_votos_n, 2);
    assert_eq!(nuevo.finalidad_votos_h_t, Some(h1));
    Ok(())
}

/// P6 · T5: sin base, un certificado cuya `h_t_siguiente` no es la huella de `D(E, n)` se rechaza;
/// con la huella correcta se acepta.
#[test]
fn primer_certificado_huella_distinta_se_rechaza() -> Result<(), Error> {
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    // TB-1c-2 · X2 · T5′: sin base, el gancho X1 ya derivó y guardó la tabla de la ventana 1.
    preparar_cola_sin_base(&mut base, T_INST_VOTOS);
    let slot = i64::try_from(T_INST_VOTOS)?;
    let t1 = canoniza(tabla_canonica(&base, slot));
    let h1 = hash_payload(&t1);
    let mut t2 = t1.clone();
    if let Some(c) = t2
        .iter_mut()
        .find(|c| c.clave_bls == base.claves_voto[&ed(3)].clave_bls)
    {
        c.peso = 2;
        c.garantia = 2;
    }
    let t2 = canoniza(t2);
    let h2 = hash_payload(&t2);
    let mut est = base;
    est.tablas_voto_contenido.insert(h2, t2.clone());

    let malo = op_compacto(
        &est,
        &secretas,
        1,
        [0x44u8; 32],
        h2,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &malo, slot);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );

    // Control positivo: la huella de `D(E, 1)` sí entra.
    let bueno = op_compacto(
        &est,
        &secretas,
        1,
        [0x44u8; 32],
        h1,
        [0u8; 32],
        [0u8; 32],
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&est, &bueno, slot);
    r?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// RE-2c · la raíz de estado en el consenso (C1′/C2′/C6) — pruebas nuevas
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `t_raiz_01` · al aplicar un `0x09` con raíz `R`, el estado la guarda en su campo único; el
/// certificado siguiente la **sustituye**.
#[test]
fn t_raiz_01_estado_guarda_la_raiz_del_certificado() -> Result<(), Error> {
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    preparar_cola_sin_base(&mut base, 100);
    let t1 = canoniza(tabla_canonica(&base, 100));
    let h1 = hash_payload(&t1);
    assert_eq!(base.raiz_estado, None, "sin certificado no hay raíz");

    let r1 = [0x11u8; 32];
    let op1 = op_compacto(
        &base,
        &secretas,
        1,
        [0x01u8; 32],
        h1,
        r1,
        r1,
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (e1, _, r) = aplicar_certificado_peso_con_undo(&base, &op1, 100);
    r?;
    assert_eq!(
        e1.raiz_estado,
        Some(r1),
        "el estado guarda la raíz del 0x09"
    );

    let h_der = e1
        .cola_tablas_voto
        .last()
        .map(|(_, h)| *h)
        .ok_or("cola vacía tras el primer certificado")?;
    let r2 = [0x22u8; 32];
    let op2 = op_compacto(
        &e1,
        &secretas,
        2,
        [0x02u8; 32],
        h_der,
        r2,
        r2,
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (e2, _, r) = aplicar_certificado_peso_con_undo(&e1, &op2, 100);
    r?;
    assert_eq!(
        e2.raiz_estado,
        Some(r2),
        "el certificado siguiente sustituye la raíz (campo único)"
    );
    Ok(())
}

/// `t_raiz_02` · `deshacer` de un bloque con `0x09` restaura la raíz previa; con dos certificados,
/// el undo del segundo vuelve a la raíz del primero.
#[test]
fn t_raiz_02_deshacer_restaura_la_raiz() -> Result<(), Error> {
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    preparar_cola_sin_base(&mut base, 100);
    let t1 = canoniza(tabla_canonica(&base, 100));
    let h1 = hash_payload(&t1);
    let r1 = [0x33u8; 32];
    let op1 = op_compacto(
        &base,
        &secretas,
        1,
        [0x01u8; 32],
        h1,
        r1,
        r1,
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (e1, undo1, r) = aplicar_certificado_peso_con_undo(&base, &op1, 100);
    r?;
    assert_eq!(
        deshacer(&e1, &undo1),
        base,
        "deshacer restaura la raíz previa"
    );

    let h_der = e1
        .cola_tablas_voto
        .last()
        .map(|(_, h)| *h)
        .ok_or("cola vacía")?;
    let r2 = [0x44u8; 32];
    let op2 = op_compacto(
        &e1,
        &secretas,
        2,
        [0x02u8; 32],
        h_der,
        r2,
        r2,
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (e2, undo2, r) = aplicar_certificado_peso_con_undo(&e1, &op2, 100);
    r?;
    let restaurado = deshacer(&e2, &undo2);
    assert_eq!(
        restaurado.raiz_estado,
        Some(r1),
        "el undo del segundo certificado vuelve a la raíz del primero"
    );
    assert_eq!(restaurado, e1, "undo exacto del segundo 0x09");
    Ok(())
}

/// `t_raiz_05` · un `0x08` firmado sobre A3 con la **misma** raíz que porta se admite (control
/// positivo de C2′).
#[test]
fn t_raiz_05_08_firma_con_la_raiz_que_lleva_se_acepta() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let raiz = [0x77u8; 32];
    let op = voto_propio_a3(
        secreta(&secretas, 1)?,
        1,
        2,
        [0x44u8; 32],
        [0x55u8; 32],
        raiz,
    )?;
    let (nuevo, _, r) = aplicar_voto_propio_con_undo(&base, &op, 100);
    r?;
    assert!(
        nuevo.votantes_voto[&2].contains(&ed(1)),
        "el 0x08 con su propia raíz se acepta"
    );
    Ok(())
}

/// `t_raiz_07` · A3 firmada con `R` pero el campo `raiz_estado` con `R'`: se rechaza por firma.
#[test]
fn t_raiz_07_08_firma_con_otra_raiz_se_rechaza() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut op = voto_propio_a3(
        secreta(&secretas, 1)?,
        1,
        2,
        [0x44u8; 32],
        [0x55u8; 32],
        [0x99u8; 32],
    )?;
    if let OperacionAlmacenamiento::VotoPropio { raiz_estado, .. } = &mut op {
        *raiz_estado = [0xAAu8; 32];
    }
    let (_, _, r) = aplicar_voto_propio_con_undo(&base, &op, 100);
    assert_eq!(r, Err(ErrorTransicion::ErrVotoPropioFirma));
    Ok(())
}

/// `t_raiz_08` · con la ventana certificada con raíz `R`, un `0x08` bien firmado con `R'` **no** se
/// rechaza (C2′ no compara) y **no** cambia la raíz del estado.
#[test]
fn t_raiz_08_08_raiz_no_se_compara_con_el_certificado() -> Result<(), Error> {
    let (mut base, secretas) = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    preparar_cola_sin_base(&mut base, 100);
    let t1 = canoniza(tabla_canonica(&base, 100));
    let h1 = hash_payload(&t1);
    let r_cert = [0x11u8; 32];
    let op09 = op_compacto(
        &base,
        &secretas,
        1,
        [0x01u8; 32],
        h1,
        r_cert,
        r_cert,
        &t1,
        &[1, 2],
        None,
        false,
    )?;
    let (e1, _, r) = aplicar_certificado_peso_con_undo(&base, &op09, 100);
    r?;
    assert_eq!(e1.raiz_estado, Some(r_cert));

    // La clave 3 no firmó el certificado; su 0x08 trae otra raíz, bien firmada.
    let r_voto = [0x99u8; 32];
    let vp = voto_propio_a3(secreta(&secretas, 3)?, 3, 1, [0x01u8; 32], h1, r_voto)?;
    let (e2, _, r) = aplicar_voto_propio_con_undo(&e1, &vp, 100);
    r?;
    assert!(
        e2.votantes_voto[&1].contains(&ed(3)),
        "el 0x08 con otra raíz se acepta (C2′ no compara)"
    );
    assert_eq!(
        e2.raiz_estado,
        Some(r_cert),
        "el 0x08 no cambia la raíz del estado"
    );
    Ok(())
}

/// `t_raiz_09` · dos votos de la misma clave y ventana con `(candidato, h_t)` iguales y **raíces
/// distintas** son doble voto `0x0B` y se castigan (C5, ya existente).
#[test]
fn t_raiz_09_raices_distintas_misma_ventana_es_doble_voto() -> Result<(), Error> {
    let (base, secretas) = estado_sectores(&[(1, 1, 50)])?;
    let n = 3u64;
    let opb = evidencia_peso(
        secreta(&secretas, 1)?,
        n,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        n,
        [0x01; 32],
        [0xAA; 32],
        [0x20; 32],
    )?;
    let (nb, ub, r) = aplicar_evidencia_votos_peso_con_undo(
        &base,
        &opb,
        ed(9),
        &params(),
        &param_evidencia(),
        10,
    );
    r?;
    assert_eq!(
        nb.garantias[&ed(1)].incidentes.len(),
        1,
        "dos raíces distintas con el mismo (n, candidato, h_t) son doble voto"
    );
    assert_eq!(deshacer(&nb, &ub), base, "undo exacto");
    Ok(())
}
