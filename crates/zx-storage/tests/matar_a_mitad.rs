//! **Matar el proceso a mitad de una admisión y comprobar que el almacén queda coherente.**
//!
//! # Lo que este test NO pretende demostrar
//!
//! Que RocksDB sea atómico. Eso lo demuestra RocksDB con su `db_crashtest.py`. Aquí se prueba que
//! **nuestro** uso del `WriteBatch` (bloque + entrada del registro) deja tras un `SIGKILL` un
//! **prefijo exacto** del registro: sin huecos, sin entradas sin su bloque y con los mismos bytes.
//!
//! # Por qué la ruta es matar un proceso de verdad
//!
//! `rust-rocksdb` no expone `SyncPoint` ni `FaultInjectionTestEnv`; la ruta whitebox no está
//! disponible sin escribir C++ propio. Queda la blackbox: el binario de test se relanza a sí mismo
//! con una variable de entorno, y `Child::kill` manda `SIGKILL` en Unix.
//!
//! # Sincronización del golpe
//!
//! Se espera a la **primera** señal del trabajador (confirma que abrió y escribió) y a partir de
//! ahí se le deja correr una espera pseudoaleatoria distinta en cada ronda, con semilla fija, antes
//! de matarlo. Así el `kill` no está sincronizado con el final de una escritura y cae donde caiga.

#![cfg(feature = "rocksdb")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};

use zx_core::digest::{BlockHash, Digest};
use zx_core::preimage::block::{BlockHeader, merkle_root};
use zx_core::red::Red;
use zx_storage::almacen::{Almacen, BloqueAdmitido};
use zx_storage::disco::AlmacenEnDisco;

/// Con esta variable puesta, el binario de test se comporta como el trabajador al que se mata.
const VAR_RUTA: &str = "ZX_MATAR_A_MITAD_RUTA";
/// Semilla fija de las esperas (splitmix64).
const SEMILLA: u64 = 0x57_30_36_62_5f_6d_61_74;
/// Rondas: cada una mata en un punto distinto.
const RONDAS: u32 = 64;

fn genesis() -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([0x9a; 32]))
}

/// El bloque `i` de la secuencia, determinista y conocido por las dos partes.
fn bloque(i: u64) -> BloqueAdmitido<'static> {
    let cabecera = BlockHeader {
        consensus_branch_id: zx_core::CBID_RED_DEV,
        prev_hash: BlockHash::from_digest(Digest::from_bytes([(i % 251) as u8; 32])),
        merkle_root: merkle_root(&[]),
        timestamp: 1_788_480_000 + i,
        bits: 0x1d00_ffff,
        nonce: i,
        height: u32::try_from(i).unwrap_or(u32::MAX),
    };
    BloqueAdmitido::pow(&cabecera, &[], &[])
}

/// Genera una espera pseudoaleatoria a partir de una semilla fija (splitmix64).
fn espera_micros(ronda: u32) -> u64 {
    let mut z = SEMILLA ^ u64::from(ronda).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    z % 3_000
}

/// El trabajador: admite bloques en bucle y anuncia cada avance, hasta que lo maten.
fn trabajar(ruta: &Path) -> ! {
    let almacen = AlmacenEnDisco::abrir(ruta, Red::Dev, genesis()).expect("abre");
    // Se retoma donde estuviera, que es lo que haría un nodo tras reiniciar.
    let mut i = almacen.longitud_registro().expect("longitud");

    let salida = std::io::stdout();
    loop {
        let b = bloque(i);
        almacen.admitir(&b, true).expect("admite con sync");
        let mut s = salida.lock();
        writeln!(s, "AVANCE {i}").expect("anuncia");
        s.flush().expect("vacía");
        drop(s);
        i = i.checked_add(1).expect("la secuencia no desborda");
    }
}

/// Comprueba que lo reabierto es un prefijo exacto y devuelve su longitud.
fn comprobar(ruta: &Path, ronda: u32) -> u64 {
    let a = AlmacenEnDisco::abrir(ruta, Red::Dev, genesis()).expect("reabre tras el SIGKILL");
    let n = a.longitud_registro().expect("longitud");

    let mut vistos = 0u64;
    a.repetir(&mut |hash, valor| {
        let esperado = bloque(vistos);
        assert_eq!(
            hash,
            esperado.hash(),
            "ronda {ronda}: hash inesperado en {vistos}"
        );
        assert_eq!(
            valor,
            esperado.a_bytes_almacen().as_slice(),
            "ronda {ronda}: bytes inesperados en {vistos}"
        );
        vistos += 1;
        Ok::<(), ()>(())
    })
    .expect("la repetición de un almacén coherente no debe fallar");

    assert_eq!(
        vistos, n,
        "ronda {ronda}: el registro y la repetición descuadran"
    );
    n
}

#[test]
fn matar_a_mitad_de_escritura_no_deja_entrada_sin_bloque() {
    // ── ¿Somos el hijo? ──────────────────────────────────────────────────────
    if let Ok(ruta) = std::env::var(VAR_RUTA) {
        trabajar(Path::new(&ruta));
    }

    let exe = std::env::current_exe().expect("ruta del propio binario");
    let mut alcanzadas: Vec<u64> = Vec::new();

    for ronda in 1..=RONDAS {
        let dir = tempfile::tempdir().expect("tempdir");

        let mut hijo = Command::new(&exe)
            .args([
                "--exact",
                "matar_a_mitad_de_escritura_no_deja_entrada_sin_bloque",
                "--nocapture",
            ])
            .env(VAR_RUTA, dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("lanza al trabajador");

        // Se espera a la PRIMERA señal: confirma que el trabajador abrió y escribió algo.
        let mut arranco = false;
        let salida = hijo.stdout.take().expect("stdout");
        let mut lector = BufReader::new(salida);
        let mut linea = String::new();
        while lector.read_line(&mut linea).unwrap_or(0) > 0 {
            if linea.starts_with("AVANCE ") {
                arranco = true;
                break;
            }
            linea.clear();
        }
        assert!(
            arranco,
            "ronda {ronda}: el trabajador no llegó a escribir nada; el test no está probando nada"
        );

        // Espera pseudoaleatoria (semilla fija) y SIGKILL: ni destructores, ni cierre de la base.
        std::thread::sleep(std::time::Duration::from_micros(espera_micros(ronda)));
        hijo.kill().expect("mata al trabajador");
        hijo.wait().expect("lo entierra");

        alcanzadas.push(comprobar(dir.path(), ronda));
    }

    // Que el test no se vuelva vacío en silencio: hubo trabajo y los golpes cayeron en puntos
    // distintos.
    let maxima = alcanzadas.iter().copied().max().unwrap_or(0);
    assert!(
        maxima > 0,
        "ninguna ronda llegó a admitir un bloque: el test no prueba nada"
    );
    let distintas = {
        let mut v = alcanzadas.clone();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    assert!(
        distintas > 1,
        "todas las rondas murieron en el mismo punto ({alcanzadas:?}): el `kill` está sincronizado"
    );
}
