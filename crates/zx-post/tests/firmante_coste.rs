//! V8 de `ORDEN-SL4b1`: coste de `Firmante::firmar` con `fsync` real.
//!
//! Se ejecuta explícitamente porque mide tiempos de disco y no es criterio de aceptación:
//!
//! ```text
//! FIRMANTE_COSTE_DIR=/ruta/a/un/directorio/en/disco \
//!   cargo test -p zx-post --test firmante_coste -- --ignored --nocapture
//! ```
//!
//! `FIRMANTE_COSTE_DIR` debe apuntar al **disco de la zona** (no a un `tmpfs`): el `fsync` que se
//! mide es el del registro real. Cada muestra usa una oportunidad `(identidad, slot)` distinta para
//! forzar escritura + `sync_all` en cada llamada.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_core::{BlockHash, BodyCommitment, ClavePublica, Digest, MerkleRoot};
use zx_post::firmante::{Firmante, Registro, Resultado};

fn sk() -> SigningKey {
    SigningKey::from([42u8; 32])
}

fn clave_publica() -> ClavePublica {
    ClavePublica::desde_bytes(VerificationKey::from(&sk()).into())
}

fn candidato(padre: u8, slot: u64) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: zx_core::CBID_RED_DEV,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
        timestamp: 1_700_000_000,
        height: 0,
        slot,
        pot_output: [0x11; 16],
        rango_solucion: 7,
        sol: SolucionPoas {
            public_key: clave_publica(),
            sector_index: 1,
            history_size: 1 << 20,
            chunk: [5u8; 32],
            ..SolucionPoas::default()
        },
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x33; 32])),
        padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([padre; 32])), &[])
            .unwrap(),
        sello: [0u8; 64],
    }
}

/// Mediana y p99 de una lista de duraciones.
fn percentil(ordenadas: &[Duration], p: f64) -> Duration {
    if ordenadas.is_empty() {
        return Duration::ZERO;
    }
    let indice = ((ordenadas.len() - 1) as f64 * p).round() as usize;
    ordenadas[indice.min(ordenadas.len() - 1)]
}

#[test]
#[ignore = "V8: mide fsync real; se ejecuta explícitamente con --ignored"]
fn coste_de_firmar_con_fsync() {
    let dir: PathBuf = std::env::var_os("FIRMANTE_COSTE_DIR")
        .map(PathBuf::from)
        .expect("define FIRMANTE_COSTE_DIR al disco de la zona");
    std::fs::create_dir_all(&dir).expect("crear el directorio de coste");
    let ruta = dir.join("coste-firmante.log");
    let _ = std::fs::remove_file(&ruta);

    let reg = Registro::nueva(&ruta).expect("registro limpio en la zona");
    let f = Firmante::nuevo(&reg);

    const MUESTRAS: u64 = 2_000;
    let mut tiempos = Vec::with_capacity(MUESTRAS as usize);
    for i in 0..MUESTRAS {
        let mut c = candidato(1, 100_000 + i);
        let inicio = Instant::now();
        let r = f.firmar(&mut c, &sk()).expect("firmar sella");
        tiempos.push(inicio.elapsed());
        assert_eq!(r, Resultado::Sellado);
    }
    tiempos.sort();
    let total: Duration = tiempos.iter().sum();
    let mediana = percentil(&tiempos, 0.50);
    let p99 = percentil(&tiempos, 0.99);
    let media = total / u32::try_from(MUESTRAS).expect("muestras caben en u32");
    eprintln!(
        "[V8] firmar+fsync: n={MUESTRAS} mediana={:.3} ms p99={:.3} ms media={:.3} ms total={:.3} s",
        mediana.as_secs_f64() * 1e3,
        p99.as_secs_f64() * 1e3,
        media.as_secs_f64() * 1e3,
        total.as_secs_f64()
    );
    assert_eq!(reg.entradas(), MUESTRAS);
}
