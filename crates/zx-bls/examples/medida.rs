//! Banco de medida V4 de `zx-bls` (ORDEN-BLS1 §3 V4).
//!
//! Mide, con `REPETICIONES` repeticiones y `CALENTAMIENTO` de calentamiento:
//!
//! - verificar 1 firma individual;
//! - `fast_aggregate_verify` (mismo mensaje, incluye la agregación de las `K` claves) para
//!   `K` = 64, 256, 1 024 y 4 096;
//! - agregar `K` firmas;
//! - deserializar con comprobación de subgrupo una clave pública y una firma.
//!
//! Imprime una tabla TSV con mediana, p95, mínimo y máximo (ns), las muestras crudas de esa misma
//! corrida y la pendiente derivada del término lineal en `K` (ns por voto). No usa `Python`.
//!
//! Ejecución (clase M, candado exclusivo):
//! `cargo run --release -p zx-bls --example medida`
#![allow(
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "el banco indexa muestras acotadas por su longitud y usa aritmetica entera de percentiles"
)]

use std::hint::black_box;
use std::time::Instant;

use zx_bls::{
    ClavePublica, ClaveSecreta, ErrorBLS, Firma, agregar_firmas, fast_aggregate_verify, firmar,
    verificar,
};

/// Dominio de ZEROX usado en la medida (separación de dominios, decisión 2).
const DOMINIO: &[u8] = b"ZX-BLS1-MEDIDA";
/// Mensaje del certificado de la medida.
const MENSAJE: &[u8] = b"certificado-de-finalidad";
/// Repeticiones por escenario (la orden exige >= 30).
const REPETICIONES: usize = 31;
/// Calentamientos por escenario (amortiza el primer uso).
const CALENTAMIENTO: usize = 3;
/// Tamaños de certificado de `fast_aggregate_verify` y agregación.
const KS: [usize; 4] = [64, 256, 1024, 4096];

/// Material de clave determinista y distinto por índice.
fn semilla(indice: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    let bytes = (indice as u64).to_le_bytes();
    for (destino, origen) in ikm.iter_mut().zip(bytes.iter()) {
        *destino = *origen;
    }
    ikm[8] = 0xa5;
    ikm[31] = 0x5a;
    ikm
}

/// Una fila medida: escenario, K y las muestras crudas en ns.
struct Fila {
    escenario: &'static str,
    k: usize,
    muestras: Vec<u64>,
}

/// Un resumen estadístico en nanosegundos.
struct Resumen {
    mediana: u64,
    p95: u64,
    minimo: u64,
    maximo: u64,
}

/// Mide `f` con calentamiento y devuelve las muestras crudas en ns.
fn medir<R>(f: &mut impl FnMut() -> R, reps: usize) -> Vec<u64> {
    for _ in 0..CALENTAMIENTO {
        black_box(f());
    }
    let mut muestras = Vec::with_capacity(reps);
    for _ in 0..reps {
        let inicio = Instant::now();
        black_box(f());
        muestras.push(inicio.elapsed().as_nanos() as u64);
    }
    muestras
}

/// Registra una fila midiendo `f`.
fn registrar<R>(
    filas: &mut Vec<Fila>,
    escenario: &'static str,
    k: usize,
    f: &mut impl FnMut() -> R,
) {
    filas.push(Fila {
        escenario,
        k,
        muestras: medir(f, REPETICIONES),
    });
}

/// Mediana (elemento central) y p95 por rango más cercano sobre muestras ordenadas.
fn resumir(muestras: &mut [u64]) -> Resumen {
    muestras.sort_unstable();
    let n = muestras.len();
    let mediana = muestras[(n - 1) / 2];
    let indice_p95 = (95 * n).div_ceil(100).saturating_sub(1).min(n - 1);
    Resumen {
        mediana,
        p95: muestras[indice_p95],
        minimo: muestras[0],
        maximo: muestras[n - 1],
    }
}

fn main() -> Result<(), ErrorBLS> {
    let hilos = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!("# zx-bls V4 — banco de medida (mediana/p95 por rango mas cercano, ns)");
    println!(
        "# hilos_disponibles: {hilos} (el banco es monohilo; blst crea su ThreadPool interno)"
    );
    println!("# repeticiones: {REPETICIONES}, calentamiento: {CALENTAMIENTO}");

    let mut filas: Vec<Fila> = Vec::new();

    // --- verificar 1 firma individual y deserializaciones -----------------------------
    {
        let clave = ClaveSecreta::generar(&semilla(0))?;
        let publica = clave.clave_publica();
        let firma = firmar(&clave, DOMINIO, MENSAJE)?;
        let pk_bytes = publica.bytes();
        let firma_bytes = firma.bytes();

        registrar(&mut filas, "verificar_1", 1, &mut || {
            verificar(&publica, &firma, DOMINIO, MENSAJE)
        });
        registrar(&mut filas, "deserializar_clave_subgrupo", 1, &mut || {
            ClavePublica::desde_bytes(&pk_bytes)
        });
        registrar(&mut filas, "deserializar_firma_subgrupo", 1, &mut || {
            Firma::desde_bytes(&firma_bytes)
        });
    }

    // --- fast_aggregate_verify y agregar K firmas -------------------------------------
    let mut medianas_agregada: Vec<(usize, u64)> = Vec::new();
    for &k in &KS {
        let mut claves: Vec<ClaveSecreta> = Vec::with_capacity(k);
        for i in 0..k {
            claves.push(ClaveSecreta::generar(&semilla(i))?);
        }
        let publicas: Vec<ClavePublica> = claves.iter().map(ClaveSecreta::clave_publica).collect();
        let firmas: Vec<Firma> = claves
            .iter()
            .map(|clave| firmar(clave, DOMINIO, MENSAJE))
            .collect::<Result<_, _>>()?;
        let refs_firmas: Vec<&Firma> = firmas.iter().collect();
        let agregada = agregar_firmas(&refs_firmas)?;
        let refs_publicas: Vec<&ClavePublica> = publicas.iter().collect();

        registrar(&mut filas, "fast_aggregate_verify", k, &mut || {
            fast_aggregate_verify(&refs_publicas, &agregada, DOMINIO, MENSAJE)
        });
        registrar(&mut filas, "agregar_firmas", k, &mut || {
            agregar_firmas(&refs_firmas)
        });
    }

    // --- tabla resumen ----------------------------------------------------------------
    println!("# escenario\tK\tn\tmediana_ns\tp95_ns\tmin_ns\tmax_ns");
    for fila in &filas {
        let mut ordenadas = fila.muestras.clone();
        let r = resumir(&mut ordenadas);
        println!(
            "{}\t{}\t{REPETICIONES}\t{}\t{}\t{}\t{}",
            fila.escenario, fila.k, r.mediana, r.p95, r.minimo, r.maximo
        );
        if fila.escenario == "fast_aggregate_verify" {
            medianas_agregada.push((fila.k, r.mediana));
        }
    }

    // --- muestras crudas de esa misma corrida -----------------------------------------
    println!("# crudo: escenario\tK\tindice\tns");
    for fila in &filas {
        for (indice, ns) in fila.muestras.iter().enumerate() {
            println!("crudo\t{}\t{}\t{indice}\t{ns}", fila.escenario, fila.k);
        }
    }

    // --- pendiente derivada del término lineal en K -----------------------------------
    if let (Some(&(k0, m0)), Some(&(k1, m1))) =
        (medianas_agregada.first(), medianas_agregada.last())
        && k1 > k0
    {
        let pendiente = (m1.saturating_sub(m0)) as f64 / (k1 - k0) as f64;
        println!("# derivado: pendiente_ns_por_voto entre K={k0} y K={k1}: {pendiente:.1}");
    }
    Ok(())
}
