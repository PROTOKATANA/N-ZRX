//! Medición informativa de `zx-pot` (§6 de ORDEN-W05b2).
//!
//! Mide iteraciones AES por segundo de `prove` y `verify` en perfil `release`, 1 hilo, mediana de
//! ≥ 10 corridas, y calcula el `N` que daría ≈ 1 s por slot **en esta máquina**. Registra `uptime`
//! y `nproc` porque la máquina puede tener carga ajena. **No** es un parámetro de red: el valor de
//! red se calibra en W07 (D-P10).
//!
//! Ejecutar:
//! ```text
//! CARGO_HOME=… cargo run --release -p zx-pot --example medir_pot --offline
//! ```

#![expect(
    clippy::expect_used,
    clippy::integer_division,
    reason = "instrumento de medición local: la media por índice es entera, el fallo del fixture debe producir panic"
)]

use core::num::NonZeroU32;
use std::hint::black_box;
use std::process::Command;
use std::time::{Duration, Instant};

use zx_pot::tipos::PotSeed;

/// Iteraciones por corrida de medición (múltiplo de 16). No es un valor de red.
const N_MEDICION: u32 = 20_000_000;

/// Número de corridas por primitiva (≥ 10).
const CORRIDAS: usize = 11;

fn mediana(mut tiempos: Vec<Duration>) -> Duration {
    tiempos.sort_unstable();
    *tiempos
        .get(tiempos.len() / 2)
        .expect("la lista de tiempos no está vacía")
}

fn salida(comando: &str, args: &[&str]) -> String {
    Command::new(comando)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|e| format!("<{comando} no disponible: {e}>"))
}

fn main() {
    let seed = PotSeed::from([0x5Au8; 16]);
    let n = NonZeroU32::new(N_MEDICION).expect("N > 0");

    // Calentamiento: amortiza la primera lectura de CPU/caché.
    let carrier = zx_pot::prove(seed, n).expect("N múltiplo de 16");
    assert!(zx_pot::verify(seed, n, &carrier).expect("N múltiplo de 16"));

    let mut tiempos_prove = Vec::with_capacity(CORRIDAS);
    for _ in 0..CORRIDAS {
        let inicio = Instant::now();
        let c = zx_pot::prove(seed, n).expect("N múltiplo de 16");
        tiempos_prove.push(inicio.elapsed());
        black_box(c);
    }

    let mut tiempos_verify = Vec::with_capacity(CORRIDAS);
    for _ in 0..CORRIDAS {
        let inicio = Instant::now();
        let ok = zx_pot::verify(seed, n, &carrier).expect("N múltiplo de 16");
        tiempos_verify.push(inicio.elapsed());
        black_box(ok);
    }

    let t_prove = mediana(tiempos_prove);
    let t_verify = mediana(tiempos_verify);
    let iter_prove = f64::from(N_MEDICION) / t_prove.as_secs_f64();
    let iter_verify = f64::from(N_MEDICION) / t_verify.as_secs_f64();
    // `N` que daría ≈ 1 s por slot, redondeado al múltiplo de 16 más cercano.
    let n_1s_prove = ((iter_prove).round() as u64).next_multiple_of(16);
    let n_1s_verify = ((iter_verify).round() as u64).next_multiple_of(16);

    println!("== Medición informativa zx-pot (§6 W05b2) ==");
    println!("uptime: {}", salida("uptime", &[]));
    println!("nproc:  {}", salida("nproc", &[]));
    println!("N por corrida: {N_MEDICION} (múltiplo de 16), corridas: {CORRIDAS}");
    println!(
        "prove : mediana {:?} | {:.3e} iter/s | N(1 s/slot) ≈ {}",
        t_prove, iter_prove, n_1s_prove
    );
    println!(
        "verify: mediana {:?} | {:.3e} iter/s | N(1 s/slot) ≈ {}",
        t_verify, iter_verify, n_1s_verify
    );
    println!(
        "cociente verify/prove: {:.2}",
        t_verify.as_secs_f64() / t_prove.as_secs_f64()
    );
}
