//! Medición de V7: admisiones/s y tiempo de apertura + repetición de 10 000 bloques dev.
//!
//! Ejecutar en release y con un solo hilo:
//!
//! ```text
//! cargo run --release -p zx-storage --features rocksdb --example medir_almacen -- <dir>
//! ```
//!
//! Sin umbral: aquí solo se mide. El informe recoge la cifra y el entorno.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "es un instrumento de medición: imprime su resultado y falla con panic"
)]

use std::path::PathBuf;
use std::time::Instant;

use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest};
use zx_core::firma::ClavePublica;
use zx_core::preimage::block::{BlockHeader, merkle_root};
use zx_core::red::Red;
use zx_core::tx::{ExtensionTx, Lock, Tx, TxOut};
use zx_core::txid;
use zx_storage::almacen::{Almacen, BloqueAdmitido};
use zx_storage::disco::AlmacenEnDisco;

const BLOQUES: u64 = 10_000;

fn genesis() -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([0x9a; 32]))
}

fn bloque(i: u64) -> BloqueAdmitido<'static> {
    let tx = Tx {
        version: 1,
        inputs: Vec::new(),
        outputs: vec![TxOut {
            value: Amount::nuevo(1_000 + i as i64).unwrap(),
            lock: Lock::PubKey {
                pubkey: ClavePublica::desde_bytes([9; 32]),
            },
        }],
        lock_time: 0,
        expiry_height: u32::try_from(i).unwrap_or(u32::MAX),
        extension: ExtensionTx::Ninguna,
    };
    // La cabecera MUST declarar el `merkle_root` de su cuerpo: el almacén lo recalcula al abrir y
    // al leer (Corrección A).
    let raiz = merkle_root(&[txid(&tx, zx_core::CBID_RED_DEV)]);
    let cabecera = BlockHeader {
        consensus_branch_id: zx_core::CBID_RED_DEV,
        prev_hash: BlockHash::from_digest(Digest::from_bytes([(i % 251) as u8; 32])),
        merkle_root: raiz,
        timestamp: 1_788_480_000 + i,
        bits: 0x1d00_ffff,
        nonce: i,
        height: u32::try_from(i).unwrap_or(u32::MAX),
    };
    BloqueAdmitido::pow(&cabecera, std::slice::from_ref(&tx), &[Vec::new()])
}

fn main() {
    let ruta: PathBuf = std::env::args().nth(1).map_or_else(
        || std::env::temp_dir().join(format!("zx-storage-medir-{}", std::process::id())),
        PathBuf::from,
    );
    println!("zona: {}", ruta.display());
    println!("bloques: {BLOQUES}");

    // Alta.
    let mut bytes_totales: u64 = 0;
    let t_alta = Instant::now();
    {
        let a = AlmacenEnDisco::abrir(&ruta, Red::Dev, genesis()).expect("abre");
        for i in 0..BLOQUES {
            let b = bloque(i);
            bytes_totales += b.a_bytes_almacen().len() as u64;
            a.admitir(&b, false).expect("admite");
        }
        a.sincronizar().expect("sincroniza");
    }
    let alta = t_alta.elapsed();

    // Apertura: incluye la verificación completa del registro y de cada hash.
    let t_apertura = Instant::now();
    let a = AlmacenEnDisco::abrir(&ruta, Red::Dev, genesis()).expect("reabre");
    let apertura = t_apertura.elapsed();
    let n = a.longitud_registro().expect("longitud");
    assert_eq!(n, BLOQUES, "el registro debe tener las admitidas");

    // Repetición.
    let t_repeticion = Instant::now();
    let mut contados: u64 = 0;
    let mut bytes_repetidos: u64 = 0;
    a.repetir(&mut |_hash, valor| {
        contados += 1;
        bytes_repetidos += valor.len() as u64;
        Ok::<(), ()>(())
    })
    .expect("repite");
    let repeticion = t_repeticion.elapsed();

    let segundos_alta = alta.as_secs_f64();
    let admisiones_por_s = if segundos_alta > 0.0 {
        BLOQUES as f64 / segundos_alta
    } else {
        f64::INFINITY
    };
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    println!(
        "alta: {:.3} s, {:.0} admisiones/s, {:.2} MiB/s ({} bytes, {:.2} MiB)",
        segundos_alta,
        admisiones_por_s,
        mib(bytes_totales) / segundos_alta.max(f64::MIN_POSITIVE),
        bytes_totales,
        mib(bytes_totales)
    );
    println!(
        "apertura (con verificación completa): {:.3} s, {:.0} bloques/s",
        apertura.as_secs_f64(),
        BLOQUES as f64 / apertura.as_secs_f64().max(f64::MIN_POSITIVE)
    );
    println!(
        "repeticion: {:.3} s, {:.0} bloques/s, {:.2} MiB/s ({} bloques, {} bytes)",
        repeticion.as_secs_f64(),
        BLOQUES as f64 / repeticion.as_secs_f64().max(f64::MIN_POSITIVE),
        mib(bytes_repetidos) / repeticion.as_secs_f64().max(f64::MIN_POSITIVE),
        contados,
        bytes_repetidos
    );
}
