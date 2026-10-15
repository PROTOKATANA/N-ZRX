//! Propiedades e invariantes del almacén.
//!
//! - **V6:** con semilla fija, una secuencia aleatoria de admisiones con duplicados produce una
//!   repetición igual a la secuencia **sin duplicados**, con los mismos bytes.
//! - **Diferencial:** el almacén en memoria y el de RocksDB responden igual a la misma secuencia.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use proptest::collection::vec as pvec;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, TestRng, TestRunner};

use zx_core::body_commitment;
use zx_core::digest::{BlockHash, Digest};
use zx_core::preimage::block::{BlockHeader, merkle_root};
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_core::red::Red;
use zx_core::wire_dag::{BUNDLE_BYTES, BloqueDag, JustificacionPot, PotCheckpoints};
use zx_storage::almacen::{Almacen, BloqueAdmitido};
use zx_storage::memoria::AlmacenEnMemoria;

/// Semilla fija de la propiedad (V6): 32 bytes exactos para `RngAlgorithm::ChaCha`.
const SEMILLA: [u8; 32] = [
    0x57, 0x30, 0x36, 0x62, 0x2d, 0x70, 0x72, 0x6f, 0x70, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x30,
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

fn genesis() -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([0x9a; 32]))
}

fn cabecera_pow(nonce: u64, altura: u32) -> BlockHeader {
    BlockHeader {
        consensus_branch_id: zx_core::CBID_RED_DEV,
        prev_hash: BlockHash::from_digest(Digest::from_bytes([(altura % 251) as u8; 32])),
        merkle_root: merkle_root(&[]),
        timestamp: 1_788_480_000 + nonce,
        bits: 0x1d00_ffff,
        nonce,
        height: altura,
    }
}

fn cabecera_post(marca: u8) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: zx_core::CBID_RED_DEV,
        merkle_root: merkle_root(&[]),
        timestamp: 1_788_480_000 + u64::from(marca),
        height: 0,
        slot: u64::from(marca),
        pot_output: [marca; 16],
        rango_solucion: u64::from(marca),
        sol: SolucionPoas::default(),
        body_commitment: body_commitment(&[], &[], zx_core::CBID_RED_DEV)
            .expect("sin tx no hay descuadre"),
        padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([0x07; 32])), &[])
            .expect("un padre seleccionado es canónico"),
        sello: [marca; 64],
    }
}

/// Un bloque determinista por etiqueta, alternando PoW y PoST.
fn bloque(etiqueta: u16) -> BloqueAdmitido<'static> {
    if etiqueta.is_multiple_of(2) {
        BloqueAdmitido::pow(
            &cabecera_pow(u64::from(etiqueta), u32::from(etiqueta)),
            &[],
            &[],
        )
    } else {
        let marca = (etiqueta % 251) as u8;
        let justificacion =
            JustificacionPot::nueva(vec![PotCheckpoints::desde_bytes([marca; BUNDLE_BYTES])])
                .expect("un portador está dentro del máximo");
        let dag = BloqueDag::nuevo(cabecera_post(marca), justificacion, vec![], vec![])
            .expect("sin txs no hay descuadre");
        BloqueAdmitido::post(&dag)
    }
}

/// La secuencia sin duplicados, conservando la primera aparición de cada etiqueta.
fn sin_duplicados(etiquetas: &[u16]) -> Vec<u16> {
    let mut unicas: Vec<u16> = Vec::new();
    for etiqueta in etiquetas {
        if !unicas.contains(etiqueta) {
            unicas.push(*etiqueta);
        }
    }
    unicas
}

fn repetir_todo(a: &impl Almacen) -> Vec<(BlockHash, Vec<u8>)> {
    let mut salida: Vec<(BlockHash, Vec<u8>)> = Vec::new();
    a.repetir(&mut |hash, valor| {
        salida.push((hash, valor.to_vec()));
        Ok::<(), ()>(())
    })
    .expect("la repetición no debe fallar en el almacén");
    salida
}

/// **V6.** Secuencia aleatoria de admisiones con duplicados ⇒ repetición sin duplicados y mismos
/// bytes.
#[test]
fn la_repeticion_es_la_secuencia_sin_duplicados() {
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &SEMILLA);
    let mut runner = TestRunner::new_with_rng(
        ProptestConfig {
            cases: 256,
            ..ProptestConfig::default()
        },
        rng,
    );
    let estrategia = pvec(0u16..64, 0..64);

    runner
        .run(&estrategia, |etiquetas| {
            let a = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
            for etiqueta in &etiquetas {
                let b = bloque(*etiqueta);
                let hash = a.admitir(&b, true).unwrap();
                prop_assert_eq!(hash, b.hash());
            }

            let esperadas = sin_duplicados(&etiquetas);
            prop_assert_eq!(a.longitud_registro().unwrap(), esperadas.len() as u64);

            let salida = repetir_todo(&a);
            prop_assert_eq!(salida.len(), esperadas.len());
            for (obtenido, etiqueta) in salida.iter().zip(&esperadas) {
                let esperado = bloque(*etiqueta);
                prop_assert_eq!(obtenido.0, esperado.hash());
                prop_assert_eq!(obtenido.1.clone(), esperado.a_bytes_almacen());
            }
            Ok(())
        })
        .expect("la propiedad no debe fallar");
}

/// La misma secuencia, contra los dos backends, da exactamente lo mismo (diferencial).
#[cfg(feature = "rocksdb")]
#[test]
fn memoria_y_disco_repiten_igual() {
    use zx_storage::disco::AlmacenEnDisco;

    let etiquetas: Vec<u16> = (0..200u16).map(|i| (i * 7 + i % 5) % 90).collect();
    let dir = tempfile::tempdir().expect("tempdir");

    let memoria = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
    let disco = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");

    for etiqueta in &etiquetas {
        let b = bloque(*etiqueta);
        memoria.admitir(&b, true).expect("memoria admite");
        disco.admitir(&b, true).expect("disco admite");
    }
    assert_eq!(
        memoria.longitud_registro().expect("memoria"),
        disco.longitud_registro().expect("disco")
    );

    let de_memoria = repetir_todo(&memoria);
    let de_disco = repetir_todo(&disco);
    assert_eq!(de_memoria, de_disco, "los dos backends deben coincidir");

    // Y la lectura por hash coincide byte a byte.
    for (hash, valor) in &de_memoria {
        assert_eq!(
            memoria.bloque(hash).expect("memoria lee"),
            Some(valor.clone())
        );
        assert_eq!(disco.bloque(hash).expect("disco lee"), Some(valor.clone()));
    }

    // Reabrir el de disco conserva la repetición.
    drop(disco);
    let disco = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("reabre");
    assert_eq!(repetir_todo(&disco), de_disco);
}
