//! AUS-2a · la falta «elegido sin voto» en el consenso, según el diseño aceptado AV-1.
//!
//! Pruebas P1–P10 de la orden AUS-2a sobre el camino de estado real (`aplicar_con_undo` y la API
//! de votos), sin la firma Ed25519 de la transacción (que comprueba `aplicar_tx` y es ortogonal).
//!
//! - P1: el voto propio dentro de plazo admite la clave y el códec da la vuelta.
//! - P2: rechazos con error propio (plazo, clave BLS ajena, firma, repetido / ya certificado).
//! - P3: la liquidación respeta `votantes_voto` (firmante, voto propio y omitido).
//! - P4: ventana sin certificado tras una base con la tabla sin cambiar (R4 ii).
//! - P5: sin cobro (tabla desconocida, clave no registrada) y C6: el peso mínimo sí tiene deber.
//! - P6: aritmética exacta de la deuda y la quema.
//! - P7: una sola liquidación por ventana; la base conserva su tabla.
//! - P8: undo exacto al liquidar/cobrar y al aplicar un voto propio.
//! - P9: la falta de la última ventana elegible se cobra antes de poder liberar la fianza.
//! - P10: el coste por bloque no crece con la altura (2 000 ventanas con tabla de 1 000 claves).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use std::collections::BTreeSet;
use std::time::Duration;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::aplicar_voto_propio_con_undo;
use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, apertura_ventana, cierre_ventana};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo, deshacer,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{DOMINIO_VOTO, Firma, mensaje_voto_peso};

const K: u64 = 65_536;
const CBID: u32 = 0;
const DEN: i128 = 1_401_600_000;
const DEN_I64: i64 = 1_401_600_000;
const NUM: i128 = 7;

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Constructores y utilidades
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
}

/// Clave Ed25519 ficticia (identificador determinista).
fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

/// Clave Ed25519 determinista para índices ≥ 256 (P10).
fn ed_idx(indice: u32) -> ClavePublica {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&indice.to_le_bytes());
    ClavePublica::desde_bytes(b)
}

/// Clave BLS determinista para índices ≥ 256 (P10).
fn bls_idx(indice: u32) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[..4].copy_from_slice(&indice.to_le_bytes());
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
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
        max_tx_bytes: 100_000,
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

/// Estado PoST con `claves = (índice Ed25519, nº de sectores)` y garantía activa `g` por clave.
fn estado_post(
    claves: &[(u8, usize)],
    g: i128,
) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
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
        let mut gg = Garantia::nueva();
        gg.activo = Amount::nuevo(i64::try_from(g)?)?;
        est.garantias.insert(e, gg);
        secretas.push(secreta);
    }
    Ok((est, secretas))
}

/// Tabla manual `(índice Ed25519, peso)` tomando la clave BLS registrada en el estado.
fn tabla(est: &Estado, pesos: &[(u8, u64)]) -> Vec<ClaveTablaVoto> {
    pesos
        .iter()
        .map(|(i, w)| ClaveTablaVoto {
            clave_bls: est.claves_voto[&ed(*i)].clave_bls,
            peso: *w,
            activo: true,
            prueba: false,
            garantia: *w,
        })
        .collect()
}

/// Tabla de peso 1 por clave a partir de los índices dados.
fn tabla_unos(est: &Estado, indices: &[u8]) -> Vec<ClaveTablaVoto> {
    tabla(est, &indices.iter().map(|i| (*i, 1u64)).collect::<Vec<_>>())
}

/// `hash_tabla` del payload (no depende de `n`, como el contrato de `zx-votos`).
fn hash_tabla_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&zx_votos::Tabla {
        n: 0,
        claves: claves
            .iter()
            .map(|c| zx_votos::Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    })
}

/// M9-b1 · deja la tabla de la ventana `n` como el flujo por peso: el contenido en
/// `tablas_voto_contenido` y la asociación ventana → hash en `tabla_ventana_voto`.
fn poner_tabla(est: &mut Estado, n: u64, claves: Vec<ClaveTablaVoto>) -> [u8; 32] {
    let h = hash_tabla_payload(&claves);
    est.tablas_voto_contenido.insert(h, claves);
    est.tabla_ventana_voto.insert(n, h);
    h
}

/// Voto propio válido de `secreta` sobre `(n, candidato, h_t)`.
fn voto_propio(
    secreta: &zx_votos::ClaveSecreta,
    clave: ClavePublica,
    n: u64,
    candidato: [u8; 32],
    h_t: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let firma: Firma = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]),
    )?;
    Ok(OperacionAlmacenamiento::VotoPropio {
        clave,
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

/// Slot del primer bloque que liquida la ventana `n`.
fn slot_liquidacion(n: u64) -> u64 {
    cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1
}

fn deuda(est: &Estado, i: u8) -> i128 {
    est.deuda_ausencia.get(&ed(i)).copied().unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P3 · la liquidación respeta `votantes_voto` (firmante, voto propio y omitido)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p3_liquidacion_respeta_votantes_peso() -> Result<(), Error> {
    let n = 3u64;
    let (base, secretas) = estado_post(&[(1, 0), (2, 0), (3, 0)], DEN)?;
    let mut est = base;
    let t = tabla_unos(&est, &[1, 2, 3]);
    poner_tabla(&mut est, n, t);
    // La clave 1 firmó el certificado (ya admitida); la 2 mete su voto propio.
    let mut votantes: BTreeSet<ClavePublica> = BTreeSet::new();
    votantes.insert(ed(1));
    est.votantes_voto.insert(n, votantes);
    let op = voto_propio(&secretas[1], ed(2), n, [0x11; 32], [0x22; 32])?;
    let (con_voto, _, r) =
        aplicar_voto_propio_con_undo(&est, &op, i64::try_from(apertura_ventana(n))?);
    r?;
    let (nuevo, _) = aplica_post(&con_voto, slot_liquidacion(n))?;

    assert_eq!(
        deuda(&nuevo, 1),
        0,
        "el firmante del certificado no acumula"
    );
    assert_eq!(deuda(&nuevo, 2), 0, "el voto propio no acumula");
    assert_eq!(nuevo.quemado, 7, "solo el omitido cobra (7 brek)");
    assert_eq!(
        nuevo.activo_de(&ed(1)),
        Amount::nuevo(DEN_I64)?,
        "firmante intacto"
    );
    assert_eq!(
        nuevo.activo_de(&ed(2)),
        Amount::nuevo(DEN_I64)?,
        "voto propio intacto"
    );
    assert_eq!(
        nuevo.activo_de(&ed(3)),
        Amount::nuevo(DEN_I64 - 7)?,
        "el omitido paga 7 brek"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P4 · ventana sin certificado tras una base cuya tabla no cambió (R4 ii)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p4_tabla_de_la_base_sin_cambiar_peso() -> Result<(), Error> {
    let m = 1u64;
    let n = 2u64;
    let (base, secretas) = estado_post(&[(1, 0), (2, 0)], DEN)?;
    let mut est = base;
    let tabla_base = tabla_unos(&est, &[1, 2]);
    poner_tabla(&mut est, m, tabla_base.clone());
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_n = m;
    est.finalidad_votos_h_t = Some(hash_tabla_payload(&tabla_base));
    est.liquidacion_voto_hasta = Some(m);
    // La clave 1 publica su voto propio; la 2 no.
    let op = voto_propio(&secretas[0], ed(1), n, [0x11; 32], [0x22; 32])?;
    let (con_voto, _, r) =
        aplicar_voto_propio_con_undo(&est, &op, i64::try_from(apertura_ventana(n))?);
    r?;
    assert!(
        !con_voto.tabla_ventana_voto.contains_key(&n),
        "sin tabla propia de n"
    );
    assert!(
        con_voto
            .tablas_voto_contenido
            .contains_key(&hash_tabla_payload(&tabla_base)),
        "la tabla de la base queda como contenido (flujo por peso)"
    );
    let (nuevo, _) = aplica_post(&con_voto, slot_liquidacion(n))?;
    assert_eq!(deuda(&nuevo, 1), 0, "quien publicó su voto no acumula");
    assert_eq!(nuevo.quemado, 7, "solo el omitido cobra");
    assert_eq!(
        nuevo.activo_de(&ed(1)),
        Amount::nuevo(DEN_I64)?,
        "votante intacto"
    );
    assert_eq!(
        nuevo.activo_de(&ed(2)),
        Amount::nuevo(DEN_I64 - 7)?,
        "quien no publicó paga"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P5 · sin cobro (cuota entera cero, tabla desconocida, clave no registrada)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p5_sin_cobro_peso() -> Result<(), Error> {
    // (a) PD-1b · C6: la cuota entera ya no exime del deber. La clave de peso 1 (que con
    // `⌊K·1/(1+65 536)⌋ = 0` no cobraba) ahora tiene deber y paga como la de cuota alta.
    let n = 2u64;
    let (base, _) = estado_post(&[(1, 0), (2, 0)], DEN)?;
    let mut est = base;
    let claves = est.claves_voto[&ed(1)].clave_bls;
    let claves2 = est.claves_voto[&ed(2)].clave_bls;
    let t = vec![
        ClaveTablaVoto {
            clave_bls: claves,
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        },
        ClaveTablaVoto {
            clave_bls: claves2,
            peso: K,
            activo: true,
            prueba: false,
            garantia: K,
        },
    ];
    poner_tabla(&mut est, n, t);
    est.liquidacion_voto_hasta = Some(n - 1);
    let (cuota, _) = aplica_post(&est, slot_liquidacion(n))?;
    assert_eq!(
        deuda(&cuota, 1),
        0,
        "la deuda del peso mínimo se cobra entera"
    );
    assert_eq!(cuota.quemado, 14, "C6: las dos claves con peso > 0 cobran");
    assert_eq!(
        cuota.activo_de(&ed(1)),
        Amount::nuevo(DEN_I64 - 7)?,
        "C6: el peso mínimo paga"
    );
    assert_eq!(
        cuota.activo_de(&ed(2)),
        Amount::nuevo(DEN_I64 - 7)?,
        "cuota alta paga"
    );

    // (b) tabla desconocida: base que cambió la tabla (`h_T(m) != finalidad_votos_h_t`). En el
    // flujo por peso no hay contenido para el `h_t` de la base, así que se liquida sin cobro.
    let (base_b, _) = estado_post(&[(1, 0)], DEN)?;
    let mut est_b = base_b;
    est_b.finalidad_votos = Some(hash(9));
    est_b.finalidad_votos_n = 1;
    est_b.finalidad_votos_h_t = Some([0xAB; 32]); // no casa con la tabla guardada
    est_b.liquidacion_voto_hasta = Some(1);
    let (sin_tabla, _) = aplica_post(&est_b, slot_liquidacion(2))?;
    assert_eq!(deuda(&sin_tabla, 1), 0, "tabla desconocida: sin cobro");

    // (c) clave ya no registrada: la tabla cita una BLS ajena.
    let (base_c, _) = estado_post(&[(1, 0)], DEN)?;
    let mut est_c = base_c;
    let t = vec![ClaveTablaVoto {
        clave_bls: [0xEE; 48],
        peso: 1,
        activo: true,
        prueba: false,
        garantia: 1,
    }];
    poner_tabla(&mut est_c, 2, t);
    est_c.liquidacion_voto_hasta = Some(1);
    let (no_reg, _) = aplica_post(&est_c, slot_liquidacion(2))?;
    assert!(
        no_reg.deuda_ausencia.is_empty(),
        "clave no registrada: se omite"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P6 · aritmética exacta de la deuda y la quema
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p6_aritmetica_exacta_peso() -> Result<(), Error> {
    // G = 10^8, N = 3: la deuda llega a 2,1·10^9 y cobra 1, guardando 7·10^8.
    let (base, _secretas) = estado_post(&[(1, 0)], 100_000_000)?;
    let mut est = base;
    for w in 0..3u64 {
        let t = tabla_unos(&est, &[1]);
        poner_tabla(&mut est, w, t);
    }
    let quemado0 = est.quemado;
    let mut actual = est;
    for w in 0..3u64 {
        let (nuevo, _) = aplica_post(&actual, slot_liquidacion(w))?;
        actual = nuevo;
    }
    let esperado = 3 * 100_000_000 * NUM / DEN;
    assert_eq!(
        actual.quemado - quemado0,
        esperado,
        "lo quemado es ⌊N·G·7/den⌋"
    );
    assert_eq!(actual.quemado - quemado0, 1, "cobra 1 brek");
    assert_eq!(
        deuda(&actual, 1),
        3 * 100_000_000 * NUM - DEN,
        "resto exacto"
    );

    // G = 1 401 600 000, N = 1: cobra 7 y la deuda queda a cero.
    let (b2, _) = estado_post(&[(2, 0)], DEN)?;
    let mut e2 = b2;
    let t2 = tabla_unos(&e2, &[2]);
    poner_tabla(&mut e2, 0, t2);
    let q0 = e2.quemado;
    let (f2, _) = aplica_post(&e2, slot_liquidacion(0))?;
    assert_eq!(f2.quemado - q0, 7);
    assert_eq!(deuda(&f2, 2), 0);

    // G = 100 con la deuda a un paso del umbral: cobra 1 al cruzarlo.
    let (b3, _) = estado_post(&[(3, 0)], 100)?;
    let mut e3 = b3;
    e3.deuda_ausencia.insert(ed(3), DEN - NUM);
    let t3 = tabla_unos(&e3, &[3]);
    poner_tabla(&mut e3, 0, t3);
    let q3 = e3.quemado;
    let (f3, _) = aplica_post(&e3, slot_liquidacion(0))?;
    assert_eq!(f3.quemado - q3, 1, "cobra 1 al cruzar el umbral");
    assert_eq!(deuda(&f3, 3), 693, "resto exacto tras el cobro");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P7 · una sola vez y la base conserva su tabla
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p7_una_sola_vez_y_base_conserva_peso() -> Result<(), Error> {
    let n = 2u64;
    let (base, _) = estado_post(&[(1, 0)], DEN)?;
    let mut est = base;
    let t = tabla_unos(&est, &[1]);
    let h = poner_tabla(&mut est, n, t);
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_n = n;
    est.finalidad_votos_h_t = Some(h);
    est.liquidacion_voto_hasta = Some(n - 1);
    let (uno, _) = aplica_post(&est, slot_liquidacion(n))?;
    assert_eq!(uno.quemado, 7, "la ventana se cobra a su hora");
    assert!(
        uno.tablas_voto_contenido.contains_key(&h),
        "la base conserva su tabla vigente"
    );
    // Slot más tardío en el que todavía **no vence ninguna otra ventana**: con
    // `cierre(k) = (k+1)·T_INST` (`T_INST = 2`) y `W_reveal = 160`, la mayor ventana vencida es
    // `n` exactamente hasta `slot = cierre(n+1) + W_reveal` (para `n = 2`, `168`). Así
    // `liquidacion_voto_hasta = n` y `desde = n+1 > n_max = n`: no se reliquida la base.
    let slot_sin_otra_ventana = cierre_ventana(n + 1) + W_REVEAL_SLOTS_VOTOS;
    let (dos, _) = aplica_post(&uno, slot_sin_otra_ventana)?;
    assert_eq!(dos.quemado, uno.quemado, "no se repite el cobro");
    assert_eq!(dos.deuda_ausencia, uno.deuda_ausencia);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P8 · undo exacto
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p8_undo_exacto_peso() -> Result<(), Error> {
    // Bloque que liquida y cobra.
    let n = 2u64;
    let (base, _) = estado_post(&[(1, 0)], DEN)?;
    let mut est = base;
    let t = tabla_unos(&est, &[1]);
    poner_tabla(&mut est, n, t);
    est.liquidacion_voto_hasta = Some(n - 1);
    let (nuevo, undo) = aplica_post(&est, slot_liquidacion(n))?;
    assert_ne!(nuevo, est);
    assert_eq!(
        deshacer(&nuevo, &undo),
        est,
        "undo exacto al liquidar y cobrar"
    );

    // Bloque que aplica un voto propio.
    let (base_v, secretas) = estado_post(&[(1, 1)], 0)?;
    let op = voto_propio(&secretas[0], ed(1), 1, [0x11; 32], [0x22; 32])?;
    let (con_voto, undo_v, r) = aplicar_voto_propio_con_undo(&base_v, &op, 100);
    r?;
    assert_eq!(
        deshacer(&con_voto, &undo_v),
        base_v,
        "undo exacto del voto propio"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P9 · retención: la falta se cobra antes de poder liberar la fianza
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p9_cobra_antes_de_liberar_la_fianza_peso() -> Result<(), Error> {
    let n = 4u64;
    let retiro_slot = i64::try_from(cierre_ventana(n))?;
    let p = ParametrosSector::dev();
    let r_votos = p.r_votos_slots;
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let secreta = bls(1)?;
    let e = ed(1);
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: secreta.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let (id, mut reg) = registro(&p, e, 0);
    reg.etapa = Etapa::EnRetirada;
    reg.retiro_slot = retiro_slot;
    reg.fianza = DEN_I64;
    est.sectores.insert(id, reg);
    est.garantias.insert(e, Garantia::nueva()); // activo 0: el cobro va a la fianza
    let t = tabla_unos(&est, &[1]);
    poner_tabla(&mut est, n, t);
    est.liquidacion_voto_hasta = Some(n - 1);

    let slot = slot_liquidacion(n);
    assert!(
        i64::try_from(slot)? < retiro_slot + r_votos,
        "la liquidación precede a la liberación"
    );
    let (nuevo, _) = aplica_post(&est, slot)?;
    assert_eq!(
        nuevo.sectores[&id].fianza,
        DEN_I64 - 7,
        "la falta se cobra de la fianza antes de poder liberarla"
    );
    assert_eq!(nuevo.quemado, 7);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// P10 · el coste por bloque no crece con la altura (2 000 ventanas, tabla de 1 000 claves)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn p10_coste_no_crece_con_la_altura_peso() -> Result<(), Error> {
    const N_CLAVES: u32 = 1_000;
    const N_VENTANAS: u64 = 2_000;
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut tabla_base = Vec::with_capacity(N_CLAVES as usize);
    for i in 0..N_CLAVES {
        let secreta = bls_idx(i)?;
        let e = ed_idx(i);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: secreta.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        est.garantias.insert(e, Garantia::nueva()); // G = 0: sin cobro, solo coste
        tabla_base.push(ClaveTablaVoto {
            clave_bls: secreta.clave_publica().bytes(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        });
    }
    // Cada una de las 2 000 ventanas tiene su tabla completa de 1 000 claves.
    for w in 0..N_VENTANAS {
        poner_tabla(&mut est, w, tabla_base.clone());
    }

    let mut actual = est;
    let mut t_primero = Duration::ZERO;
    let mut t_ultimo = Duration::ZERO;
    for w in 0..N_VENTANAS {
        let t0 = std::time::Instant::now();
        let (nuevo, _) = aplica_post(&actual, slot_liquidacion(w))?;
        let dt = t0.elapsed();
        actual = nuevo;
        if w == 0 {
            t_primero = dt;
        }
        if w == N_VENTANAS - 1 {
            t_ultimo = dt;
        }
    }
    let limite = t_primero
        .saturating_mul(20)
        .saturating_add(Duration::from_millis(20));
    println!(
        "AUS2A-P10 ventanas={N_VENTANAS} claves={N_CLAVES} primero={t_primero:?} ultimo={t_ultimo:?} limite={limite:?}"
    );
    assert!(
        t_ultimo <= limite,
        "el tiempo por bloque no crece con la altura: primero {t_primero:?}, último {t_ultimo:?}"
    );
    // Ninguna deuda se acumuló (G = 0) y las tablas vencidas se podaron.
    assert!(actual.deuda_ausencia.values().all(|d| *d == 0));
    assert!(
        actual.tabla_ventana_voto.is_empty(),
        "todas las ventanas vencidas se podan"
    );
    Ok(())
}
