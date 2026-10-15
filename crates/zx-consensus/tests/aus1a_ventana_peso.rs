//! AUS-1a · V1–V2: la liquidación de ventanas poda y **no** suspende (DEC-003-A2).
//!
//! - **V1** una clave de la tabla que ni compromete ni revela en la ventana `n` sigue en la tabla
//!   canónica y fuera del conjunto de suspendidas después de vencer el plazo de revelación; la
//!   ventana vencida se poda igual y el undo es exacto. Debe fallar contra `ws.orig`.
//! - **V2** la poda no cambia: tras 2 000 ventanas solo quedan en el estado la de la base y las de
//!   plazo no vencido.
//!
//! Compila contra `ws.orig` y contra `ws`: usa solo símbolos ya presentes en la base.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    dead_code,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use std::collections::BTreeSet;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, cierre_ventana, tabla_canonica};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo, deshacer,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest};

const CBID: u32 = 0;
const K: u64 = 65_536;

type Error = Box<dyn std::error::Error>;

fn ed(i: u8) -> ClavePublica {
    ClavePublica::desde_bytes([i; 32])
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

fn estado_post() -> Estado {
    let mut est = Estado::inicial();
    est.fase = Fase::PoST;
    est
}

fn plazo(n: u64) -> u64 {
    cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS
}

/// Aplica un bloque PoST vacío (que dispara la liquidación) y devuelve estado y undo.
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

/// Tabla de ventana con las claves `keys` (clave BLS `[i; 48]`, peso positivo).
fn tabla_de(keys: &[u8]) -> Vec<ClaveTablaVoto> {
    keys.iter()
        .map(|i| ClaveTablaVoto {
            clave_bls: [*i; 48],
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        })
        .collect()
}

/// M9-b1 · asocia la ventana `n` a la tabla de `keys` como lo deja el flujo por peso: el contenido
/// va a `tablas_voto_contenido` y la asociación ventana → hash a `tabla_ventana_voto`.
fn poner_ventana(est: &mut Estado, n: u64, keys: &[u8]) -> [u8; 32] {
    let t = tabla_de(keys);
    let h = zx_votos::hash_tabla(&zx_votos::Tabla {
        n: 0,
        claves: t
            .iter()
            .map(|c| zx_votos::Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    });
    est.tablas_voto_contenido.insert(h, t);
    est.tabla_ventana_voto.insert(n, h);
    h
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

/// Estado con tres claves registradas y con peso positivo (`fuente_peso_de > 0`).
fn estado_tres_claves() -> Result<Estado, Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    for i in 1..=3u8 {
        let e = ed(i);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: [i; 48],
                prueba_posesion: [0u8; 96],
            },
        );
        for j in 0..20u16 {
            let (id, reg) = registro(&p, e, j);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(50)?;
        est.garantias.insert(e, g);
    }
    Ok(est)
}

/// V1 · pregunta falsable: una clave que ni compromete ni revela en `n` sigue en la tabla canónica
/// y fuera de las suspendidas tras vencer el plazo. En `ws.orig` esta prueba falla (la clave queda
/// suspendida y `tabla_canonica` pierde una clave).
#[test]
fn v1_una_clave_silenciosa_sigue_en_la_tabla_canonica_peso() -> Result<(), Error> {
    let mut est = estado_tres_claves()?;
    let n = 1u64;
    poner_ventana(&mut est, n, &[1, 2, 3]);
    // Las claves 1 y 2 votan a tiempo; la 3 ni compromete ni revela en la ventana `n`.
    let slot = plazo(n) + 1;
    let slot_i = i64::try_from(slot)?;
    let (nuevo, undo) = aplica_post(&est, slot)?;
    let canonica = tabla_canonica(&nuevo, slot_i);
    println!("AUS1A-V1 slot={slot} claves_canonicas={}", canonica.len());
    assert_eq!(
        canonica.len(),
        3,
        "la tabla canónica conserva las tres claves, incluida la silenciosa"
    );
    assert!(
        !nuevo.tabla_ventana_voto.contains_key(&n),
        "la ventana vencida se poda igual (asociación)"
    );
    assert_eq!(deshacer(&nuevo, &undo), est, "undo exacto");
    Ok(())
}

/// V2 · la poda no cambia: tras 2 000 ventanas quedan la base y las de plazo no vencido.
#[test]
fn v2_la_poda_no_cambia_tras_dos_mil_ventanas_peso() -> Result<(), Error> {
    const N: u64 = 2_000;
    let mut est = estado_post();
    let mut h_base = [0u8; 32];
    for w in 1..=N {
        let h = poner_ventana(&mut est, w, &[1]);
        if w == 1 {
            h_base = h;
        }
    }
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_n = 1; // la ventana 1 es la base
    est.finalidad_votos_h_t = Some(h_base);
    let slot = plazo(N - 1) + 1;
    let (nuevo, undo) = aplica_post(&est, slot)?;
    let esperadas: BTreeSet<u64> = (1..=N).filter(|w| plazo(*w) >= slot).collect();
    let actuales: BTreeSet<u64> = nuevo.tabla_ventana_voto.keys().copied().collect();
    assert_eq!(
        actuales, esperadas,
        "solo quedan las ventanas de plazo no vencido (la base suelta su asociación)"
    );
    assert!(
        nuevo.tablas_voto_contenido.contains_key(&h_base),
        "la base conserva su tabla vigente (contenido por finalidad_votos_h_t)"
    );
    assert_eq!(deshacer(&nuevo, &undo), est, "undo exacto");
    Ok(())
}
