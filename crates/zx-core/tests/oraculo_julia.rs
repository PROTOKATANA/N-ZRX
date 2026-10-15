//! Comparación contra el **oráculo Julia independiente** (H-08a).
//!
//! Los vectores congelados de `vectores_dag.rs` los generó la propia implementación Rust: cazan
//! regresiones, pero no un error de base (si `escribir` pusiera dos campos en el orden equivocado,
//! el vector congelaría el orden equivocado). Este test compara contra
//! `lineo/vectores-cabecera-dag/resultados/vectores.txt`, que un programa Julia **recomputó desde
//! el SPEC** sin tocar el código Rust.
//!
//! Si el fichero del oráculo no existe, el test **falla**: no se degrada a "sin verificar". La
//! línea de ejecución del oráculo está en `lineo/vectores-cabecera-dag/INFORME.md` y en
//! `PRUEBAS.md`.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::panic,
    reason = "el test falla ruidosamente si el oráculo no existe"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "índices constantes sobre el escenario del test"
)]

use std::collections::HashMap;
use std::path::PathBuf;

use zx_core::digest::{BodyCommitment, Digest, TxId};
use zx_core::firma::ClavePublica;
use zx_core::preimage::block::merkle_root;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_core::{Amount, BlockHash, DagBlockHeader, PadresDag, SolucionPoas, auth_digest, txid};

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
    cabecera.body_commitment = zx_core::body_commitment(&txs, &testigos, CBID).unwrap();
    (cabecera, txs, testigos)
}

fn leer_oraculo() -> HashMap<String, String> {
    // Los vectores viven en `testdata/vectores-cabecera-dag/`, copiados sin cambios del oráculo
    // Julia del commit 9681061 (ver `PROCEDENCIA.md`). `CARGO_MANIFEST_DIR` es `crates/zx-core`,
    // así que la raíz del workspace está dos niveles arriba.
    let ruta: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "testdata",
        "vectores-cabecera-dag",
        "vectores.txt",
    ]
    .iter()
    .collect();
    let texto = std::fs::read_to_string(&ruta).unwrap_or_else(|e| {
        panic!(
            "no se pudo leer el oráculo Julia en {}: {e}. Ejecútalo (ver PRUEBAS.md); este test \
             MUST fallar, no degradarse a 'sin verificar'.",
            ruta.display()
        )
    });
    let mut map = HashMap::new();
    for linea in texto.lines() {
        if let Some((k, v)) = linea.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

#[test]
#[ignore = "PT-2a-2: el wire de SolucionPoas pasa a Merkle (32 B + 768 B); el oraculo Julia \
            congelado en testdata/ describe el layout KZG de 48 B y no se regenero (testdata/ no \
            es propiedad de esta orden). Lo regenera el orquestador."]
fn el_oraculo_julia_coincide_con_la_implementacion() {
    let o = leer_oraculo();
    let (cabecera, txs, testigos) = escenario();

    // Intermedios: txid y auth_digest, los árboles del SPEC §4.2 y §4.4.
    let txid1 = txid(&txs[0], CBID).to_string();
    let txid2 = txid(&txs[1], CBID).to_string();
    let auth1 = auth_digest(&testigos[0]).to_string();
    let auth2 = auth_digest(&testigos[1]).to_string();
    assert_eq!(o.get("txid1"), Some(&txid1));
    assert_eq!(o.get("txid2"), Some(&txid2));
    assert_eq!(o.get("auth1"), Some(&auth1));
    assert_eq!(o.get("auth2"), Some(&auth2));

    // Compromisos y hashes.
    assert_eq!(
        o.get("body_commitment"),
        Some(&cabecera.body_commitment.to_string())
    );
    assert_eq!(
        o.get("merkle_root"),
        Some(&cabecera.merkle_root.to_string())
    );
    assert_eq!(o.get("pre_hash"), Some(&cabecera.pre_hash().to_string()));
    assert_eq!(
        o.get("block_hash"),
        Some(&cabecera.block_hash().to_string())
    );

    // El wire completo, byte a byte.
    assert_eq!(o.get("wire"), Some(&hex::encode(cabecera.a_bytes())));

    // Y el propio oráculo se validó contra el vector NIST de SHA3-256 vacío.
    assert_eq!(
        o.get("sha3_vacio"),
        Some(&"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a".to_string())
    );
}
