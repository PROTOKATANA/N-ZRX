//! SUS-1 · U1, U3, U6, U7: liquidación de ventanas de votos al vencer su plazo y poda del estado
//! por el flujo por peso (M9-b1; las afirmaciones sobre el conjunto de suspendidas no pasan a la
//! gemela: DEC-003-A2 lo deja siempre vacío y M9-b2 lo retira).
//!
//! - **U1** una clave que no vota no queda suspendida y la ventana de la base suelta su asociación;
//! - **U3** la ventana de la base conserva su contenido mientras sea la base; al avanzar la base,
//!   se poda;
//! - **U6** aplicar y deshacer un bloque que liquida devuelve un estado idéntico;
//! - **U7** cota de tamaño (y cifras de coste) tras 10 000 ventanas con 64 claves.

use zx_consensus::sectores::ClaveVoto;
use zx_consensus::transicion::Undo;
use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, cierre_ventana};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, HechosCabecera, ParametrosEvidencia, ParametrosTransicion,
    aplicar_con_undo, deshacer,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest};

const CBID: u32 = 0;

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

fn registra_clave(est: &mut Estado, i: u8, bls: [u8; 48]) {
    est.claves_voto.insert(
        ed(i),
        ClaveVoto {
            clave_bls: bls,
            prueba_posesion: [0u8; 96],
        },
    );
}

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

/// M9-b1 · asocia la ventana `n` a la tabla de `keys` como lo deja el flujo por peso (contenido +
/// asociación), sin `tablas_voto`.
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

fn estado_post() -> Estado {
    let mut est = Estado::inicial();
    est.fase = Fase::PoST;
    est
}

fn plazo(n: u64) -> u64 {
    cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS
}

/// Aplica un bloque PoST vacío (que dispara la liquidación) y devuelve estado y undo.
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

/// U1 · una clave de la tabla que no vota **no** queda suspendida al aplicarse el primer bloque
/// posterior al plazo (DEC-003-A2), y la asociación de la ventana de la base se suelta. La
/// asociación solo la suelta `liquidar_ventana_voto`: `podar_ventanas_vencidas` conserva la base.
#[test]
fn u1_el_silencio_no_suspende_y_la_ventana_desaparece_peso() -> Result<(), Error> {
    let mut est = estado_post();
    registra_clave(&mut est, 1, [1; 48]);
    registra_clave(&mut est, 2, [2; 48]);
    let n = 1;
    let h = poner_ventana(&mut est, n, &[1, 2]);
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_n = n;
    est.finalidad_votos_h_t = Some(h);
    let (nuevo, undo) = aplica_post(&est, plazo(n) + 1)?;
    assert!(
        !nuevo.tabla_ventana_voto.contains_key(&n),
        "la asociación de la ventana se poda"
    );
    assert_eq!(deshacer(&nuevo, &undo), est, "undo exacto");
    Ok(())
}

/// U3 · la ventana de la base conserva su **contenido** mientras sea la base (su asociación la
/// suelta `liquidar_ventana_voto`); al avanzar la base, el contenido se poda.
#[test]
fn u3_la_base_conserva_su_ventana_y_al_avanzar_se_poda_peso() -> Result<(), Error> {
    let mut est = estado_post();
    registra_clave(&mut est, 1, [1; 48]);
    registra_clave(&mut est, 2, [2; 48]);
    let n = 1;
    let h = poner_ventana(&mut est, n, &[1, 2]);
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_n = n;
    est.finalidad_votos_h_t = Some(h);
    let (con_base, undo) = aplica_post(&est, plazo(n) + 1)?;
    assert!(
        con_base.tablas_voto_contenido.contains_key(&h),
        "la tabla vigente de la base no se poda mientras sea la base"
    );
    assert!(
        !con_base.tabla_ventana_voto.contains_key(&n),
        "la asociación de la base se suelta al liquidarla"
    );
    assert_eq!(deshacer(&con_base, &undo), est);
    // La base avanza: la ventana `n` deja de ser la base y su contenido se poda en el siguiente
    // bloque (el flujo por peso referencia la tabla vigente por `finalidad_votos_h_t`).
    let mut avanzada = con_base.clone();
    avanzada.finalidad_votos_n = n + 1;
    avanzada.finalidad_votos = Some(hash(10));
    avanzada.finalidad_votos_h_t = Some([11u8; 32]);
    let (poda, _) = aplica_post(&avanzada, plazo(n) + 2)?;
    assert!(
        !poda.tablas_voto_contenido.contains_key(&h),
        "al avanzar la base se poda el contenido"
    );
    Ok(())
}

/// U6 · aplicar y deshacer un bloque que liquida devuelve un estado idéntico (con varias ventanas;
/// la liquidación poda, DEC-003-A2).
#[test]
fn u6_undo_exacto_de_un_bloque_que_liquida_peso() -> Result<(), Error> {
    let mut est = estado_post();
    for i in 1..=4u8 {
        registra_clave(&mut est, i, [i; 48]);
    }
    poner_ventana(&mut est, 1, &[1, 2, 3]);
    poner_ventana(&mut est, 2, &[2, 3, 4]);
    poner_ventana(&mut est, 3, &[1, 4]);
    let (nuevo, undo) = aplica_post(&est, plazo(3) + 1)?;
    assert!(nuevo.tabla_ventana_voto.is_empty());
    assert_eq!(deshacer(&nuevo, &undo), est, "undo bit a bit");
    Ok(())
}

/// Estado con `n` ventanas y 64 claves. La ventana `1` es la base: `podar_ventanas_vencidas` la
/// conserva, así que solo `liquidar_ventana_voto` suelta su asociación; su contenido se conserva
/// por `finalidad_votos_h_t`.
fn estado_con_ventanas(n: u64) -> (Estado, u64) {
    let mut est = estado_post();
    for i in 1..=64u8 {
        registra_clave(&mut est, i, [i; 48]);
    }
    let keys: Vec<u8> = (1..=64).collect();
    let mut slot_final = 0;
    let mut h_base = [0u8; 32];
    for w in 1..=n {
        let h = poner_ventana(&mut est, w, &keys);
        if w == 1 {
            h_base = h;
        }
        slot_final = plazo(w);
    }
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_n = 1;
    est.finalidad_votos_h_t = Some(h_base);
    (est, slot_final)
}

/// U7 · cota de tamaño y coste constante. Informa las cifras (no las afirma salvo la cota).
#[test]
fn u7_cota_de_tamano_y_coste_constante_peso() -> Result<(), Error> {
    let (cien, slot_cien) = estado_con_ventanas(100);
    let (cien, _undo) = aplica_post(&cien, slot_cien + 1)?;
    assert!(cien.tabla_ventana_voto.len() <= 1, "100 ventanas: poda");

    let (muchas, slot_muchas) = estado_con_ventanas(10_000);
    let (muchas, _undo) = aplica_post(&muchas, slot_muchas + 1)?;
    // M9-b2: la medición de `claves_suspendidas` (SUS-1) se retira con el conjunto de suspendidas;
    // quedan las cotas de tamaño, que son las que no dependen del sorteo.
    println!(
        "SUS1-U7 claves=64 ventanas=100 asociaciones={} contenidos={}",
        cien.tabla_ventana_voto.len(),
        cien.tablas_voto_contenido.len()
    );
    println!(
        "SUS1-U7 claves=64 ventanas=10000 asociaciones={} contenidos={}",
        muchas.tabla_ventana_voto.len(),
        muchas.tablas_voto_contenido.len()
    );
    // Cota de tamaño: ninguna ventana queda asociada (todas vencieron y la base suelta su
    // asociación); en `tablas_voto_contenido` sobreviven la tabla vigente de la base y, como
    // mucho, la instantánea del ciclo de rearranque (`tomar_instantaneas_rearranque`, votos.rs).
    assert!(
        muchas.tabla_ventana_voto.is_empty(),
        "10 000 ventanas: quedan {} asociaciones",
        muchas.tabla_ventana_voto.len()
    );
    assert!(
        muchas.tablas_voto_contenido.len() <= 1 + muchas.tabla_ciclo_rearranque.len(),
        "10 000 ventanas: quedan {} contenidos",
        muchas.tablas_voto_contenido.len()
    );
    Ok(())
}
