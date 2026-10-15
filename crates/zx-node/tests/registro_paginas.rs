//! `ORDEN-W06d6` decisión 1: cobertura de `VistaRed::pagina_registro` (servida por
//! `Peticion::Registro`/`Respuesta::Registro`) por tipo de resultado — tabla de cobertura de la
//! orden: página llena, página corta, `desde` más allá del final.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use std::sync::Arc;

use zx_core::digest::{BlockHash, Digest, MerkleRoot};
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_node::red::vista::VistaRed;
use zx_p2p::limites::MAX_BLOQUES_POR_RESPUESTA;
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};

fn h(n: u32) -> BlockHash {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_digest(Digest::from_bytes(b))
}

fn estado_vacio() -> Estado {
    Estado {
        hash_genesis: h(0),
        red: Red::Dev,
        fase: Fase::Pow,
        punta_pow: PuntaPow {
            hash: h(0),
            altura: 0,
            trabajo_acumulado: [0; 32],
        },
        terminal: None,
        puntas_post: Vec::new(),
        blue_work_virtual: [0; 32],
        longitud_registro: 0,
    }
}

fn bloque(n: u32) -> BloqueRed {
    BloqueRed::Pow {
        cabecera: BlockHeader {
            consensus_branch_id: 0xa8b4_66a7,
            prev_hash: h(n),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x44; 32])),
            timestamp: 1_000 + u64::from(n),
            bits: 0x1c07_fff8,
            nonce: u64::from(n),
            height: n,
        },
        txs: Vec::new(),
        testigos: Vec::new(),
    }
}

/// Un registro de admisión con `n` bloques (alturas `0..n`), como si el génesis y `n - 1` bloques
/// PoW más se hubieran admitido en orden.
fn vista_con_registro(n: u32) -> Arc<VistaRed> {
    let vista = Arc::new(VistaRed::nueva(estado_vacio()));
    for i in 0..n {
        vista.registrar_pow(i, bloque(i));
    }
    vista
}

/// **Página llena**: pedir desde el principio de un registro más largo que el tope devuelve
/// exactamente `MAX_BLOQUES_POR_RESPUESTA` bloques, en orden, y la longitud real (mayor que la
/// página).
#[test]
fn pagina_llena_se_recorta_a_max_bloques_por_respuesta() {
    let total = (MAX_BLOQUES_POR_RESPUESTA * 3) as u32;
    let vista = vista_con_registro(total);

    let (pagina, longitud) = vista.pagina_registro(0, MAX_BLOQUES_POR_RESPUESTA, u64::MAX);
    assert_eq!(
        pagina.len(),
        MAX_BLOQUES_POR_RESPUESTA,
        "página llena: el tope de bloques"
    );
    assert_eq!(longitud, u64::from(total));
    for (i, b) in pagina.iter().enumerate() {
        let esperado = zx_node::red::hash_de(&bloque(i as u32));
        assert_eq!(
            zx_node::red::hash_de(b),
            esperado,
            "orden de admisión, índice {i}"
        );
    }
}

/// **Página corta**: pedir cerca del final de un registro más corto que el tope devuelve solo lo
/// que queda, no rellena con nada.
#[test]
fn pagina_corta_devuelve_solo_lo_que_queda() {
    let total = 5u32;
    let vista = vista_con_registro(total);

    let (pagina, longitud) = vista.pagina_registro(2, MAX_BLOQUES_POR_RESPUESTA, u64::MAX);
    assert_eq!(
        pagina.len(),
        3,
        "quedan 3 (índices 2, 3, 4) de un registro de 5"
    );
    assert_eq!(longitud, u64::from(total));
    assert_eq!(
        zx_node::red::hash_de(pagina.first().unwrap()),
        zx_node::red::hash_de(&bloque(2))
    );
    assert_eq!(
        zx_node::red::hash_de(pagina.last().unwrap()),
        zx_node::red::hash_de(&bloque(4))
    );
}

/// **`desde` más allá del final**: una página vacía, pero con la longitud real (para que quien
/// sincroniza sepa que no hay nada nuevo todavía, no que el par no tenga registro).
#[test]
fn desde_mas_alla_del_final_da_pagina_vacia_con_la_longitud_real() {
    let total = 5u32;
    let vista = vista_con_registro(total);

    let (pagina, longitud) = vista.pagina_registro(5, MAX_BLOQUES_POR_RESPUESTA, u64::MAX);
    assert!(pagina.is_empty(), "nada más allá del final");
    assert_eq!(longitud, u64::from(total));

    let (pagina_lejos, longitud_lejos) =
        vista.pagina_registro(1_000_000, MAX_BLOQUES_POR_RESPUESTA, u64::MAX);
    assert!(pagina_lejos.is_empty());
    assert_eq!(longitud_lejos, u64::from(total));
}

/// Un registro vacío (solo estado inicial, sin nada admitido) da longitud 0 y página vacía desde
/// cualquier `desde`.
#[test]
fn registro_vacio_da_longitud_cero() {
    let vista = Arc::new(VistaRed::nueva(estado_vacio()));
    assert_eq!(vista.longitud_registro(), 0);
    let (pagina, longitud) = vista.pagina_registro(0, MAX_BLOQUES_POR_RESPUESTA, u64::MAX);
    assert!(pagina.is_empty());
    assert_eq!(longitud, 0);
}

/// El tope de **bytes** también acota, aunque el de bloques no se alcance: al menos un bloque
/// siempre entra (para no dejar al que sincroniza sin poder avanzar nunca).
#[test]
fn el_tope_de_bytes_acota_pero_deja_avanzar_al_menos_un_bloque() {
    let vista = vista_con_registro(20);
    let un_bloque_bytes = zx_p2p::codec::bloque_a_bytes(&bloque(0)).len() as u64;

    // Presupuesto de bytes que solo permite un poco más de un bloque: debe devolver justo 1 o 2,
    // nunca 0 y nunca el máximo de 16 (con 20 bloques disponibles).
    let (pagina, _longitud) = vista.pagina_registro(0, MAX_BLOQUES_POR_RESPUESTA, un_bloque_bytes);
    assert!(!pagina.is_empty(), "al menos un bloque siempre entra");
    assert!(
        pagina.len() < MAX_BLOQUES_POR_RESPUESTA,
        "el tope de bytes MUST cortar antes del tope de bloques aquí"
    );
}
