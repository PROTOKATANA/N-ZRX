//! Vectores congelados de la cabecera DAG y del compromiso del cuerpo.
//!
//! # Cómo se obtuvieron
//!
//! **No se copiaron a ojo.** Se generaron una sola vez con la propia implementación
//! (`DagBlockHeader::a_bytes`, `pre_hash`, `block_hash` y `body_commitment`) sobre un escenario
//! determinista, se revisaron y se congelaron como literales hex. La prueba **recalcula** y
//! compara, de modo que un cambio de bytes, orden o etiqueta de dominio la rompe de inmediato.
//!
//! El escenario: rama `0xc47880ea`, `P = 2` padres (`prev_hash` en `[4,36)` y un adicional en
//! `[525,557)`), dos transacciones (coinbase + gasto), sello de 64 ceros. La serialización
//! canónica completa también se congela para separar "cambió el wire" de "cambió el hash".

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "rangos constantes sobre el wire congelado de longitud conocida"
)]

use zx_core::digest::{BodyCommitment, Digest, TxId};
use zx_core::firma::ClavePublica;
use zx_core::preimage::block::merkle_root;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_core::{Amount, BlockHash, DagBlockHeader, PadresDag, SolucionPoas, body_commitment, txid};

const CBID: u32 = 0xc478_80ea;

fn tx(n: u8, valor: i64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: OutPoint {
                prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                prev_index: u32::from(n),
            },
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOut {
            value: Amount::nuevo(valor).unwrap(),
            lock: Lock::PubKey {
                pubkey: ClavePublica::desde_bytes([n; 32]),
            },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

fn escenario() -> (DagBlockHeader, Vec<Tx>, Vec<Vec<Vec<u8>>>) {
    let txs = vec![tx(1, 5_000), tx(2, 3_000)];
    let testigos = vec![vec![vec![0x11; 64]], vec![vec![0x22; 65]]];
    let txids: Vec<TxId> = txs.iter().map(|t| txid(t, CBID)).collect();

    let mut cabecera = DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: CBID,
        merkle_root: merkle_root(&txids),
        timestamp: 1_788_480_000,
        height: 7,
        slot: 1234,
        pot_output: [0xAB; 16],
        rango_solucion: 999,
        sol: SolucionPoas {
            public_key: ClavePublica::desde_bytes([0x7a; 32]),
            sector_index: 5,
            history_size: 1 << 40,
            piece_offset: 3,
            record_commitment: [0x01; 32],
            record_witness: [0x02; 256],
            chunk: [0x03; 32],
            chunk_witness: [0x04; 512],
            proof_of_space: [0x05; 160],
        },
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0; 32])),
        padres: PadresDag::nuevo(
            BlockHash::from_digest(Digest::from_bytes([0x10; 32])),
            &[BlockHash::from_digest(Digest::from_bytes([0x20; 32]))],
        )
        .unwrap(),
        sello: [0u8; 64],
    };
    cabecera.body_commitment = body_commitment(&txs, &testigos, CBID).unwrap();
    (cabecera, txs, testigos)
}

/// Generado una vez con la implementación; 621 bytes para `P = 2`.
const WIRE: &str = "ea8078c41010101010101010101010101010101010101010101010101010101010101010c6687fbde4a3699bb078f3e083bf284ee45851090f8d852cbbd53ac15bb7b105000a9a6a0000000007000000d204000000000000abababababababababababababababab00000000000000000000000000000000e7030000000000007a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a05000000000000010000030001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505057f25bbbd4438f345f6942bde4fd762888e6d9eb02ccb8cbb77372364d2173b2002202020202020202020202020202020202020202020202020202020202020202000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

const PRE_HASH: &str = "fa5c667cecb89139bdf32accc2a1a564120db87a3d7f5c83650d722c8f04030c";
const BLOCK_HASH: &str = "110f6eb2cf2b5094ed228124ac92c154d42924863853c4b73f626039e4c69114";
const BODY: &str = "7f25bbbd4438f345f6942bde4fd762888e6d9eb02ccb8cbb77372364d2173b20";

#[test]
fn el_wire_congelado_se_recalcula() {
    let (cabecera, _, _) = escenario();
    assert_eq!(cabecera.tamano(), 1293, "P = 2");
    assert_eq!(hex::encode(cabecera.a_bytes()), WIRE);
}

#[test]
fn los_hashes_congelados_se_recalculan() {
    let (cabecera, txs, testigos) = escenario();
    assert_eq!(cabecera.pre_hash().to_string(), PRE_HASH);
    assert_eq!(cabecera.block_hash().to_string(), BLOCK_HASH);
    assert_eq!(
        body_commitment(&txs, &testigos, CBID).unwrap().to_string(),
        BODY
    );
    assert_eq!(cabecera.body_commitment.to_string(), BODY);
}

/// Los offsets congelados: compromiso en `[1164,1196)`, `parent_count` en 1196 y sello al final.
#[test]
fn los_offsets_congelados_del_wire() {
    let (cabecera, _, _) = escenario();
    let bytes = cabecera.a_bytes();
    assert_eq!(hex::encode(&bytes[1164..1196]), BODY, "body_commitment");
    assert_eq!(bytes[1196], 2, "parent_count");
    assert_eq!(hex::encode(&bytes[1197..1229]), "20".repeat(32));
    assert_eq!(&bytes[bytes.len() - 64..], &[0u8; 64], "sello al final");
    assert_eq!(hex::encode(&bytes[4..36]), "10".repeat(32), "prev_hash");
}

/// Mutar un byte del wire cambia el hash: no hay bytes decorativos.
#[test]
fn un_byte_del_wire_cambia_el_hash() {
    let (cabecera, _, _) = escenario();
    let original = cabecera.block_hash();

    // Un byte del sello [1213, 1277): cambia `block_hash`, no `pre_hash`.
    let mut con_sello = cabecera.a_bytes();
    con_sello[1250] ^= 0x01;
    let (otra, resto) = zx_core::dag_header_desde_bytes(&con_sello).unwrap();
    assert!(resto.is_empty());
    assert_eq!(
        otra.pre_hash(),
        cabecera.pre_hash(),
        "el sello no entra en pre_hash"
    );
    assert_ne!(
        otra.block_hash(),
        original,
        "el sello sí entra en block_hash"
    );

    // Un byte de la prefirma: cambia también `pre_hash`.
    let mut con_prefirma = cabecera.a_bytes();
    con_prefirma[100] ^= 0x01;
    let (otra, _) = zx_core::dag_header_desde_bytes(&con_prefirma).unwrap();
    assert_ne!(otra.pre_hash(), cabecera.pre_hash(), "la prefirma sí entra");
}
