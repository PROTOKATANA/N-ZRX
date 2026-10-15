//! Banco del coloreo GHOSTDAG en el caso real (LINEO §6 y §10).
//!
//! No añade dependencias: `criterion` no está en el lock de este workspace y el encargo exige
//! `Cargo.lock` idéntico. Se ejecuta con:
//!
//! ```text
//! cargo test -p zx-dag --release --test ghostdag_bench --offline --locked -- \
//!     --ignored --nocapture
//! ```
//!
//! El caso real es el **mergeset máximo que de verdad se colorea**: R-FIN-12 rechaza
//! `|mergeset(B)| + 1 > 180`, así que el mayor mergeset coloreado es **179**, no 180. Se mide
//! sobre una construcción en la que el mergeset es exactamente 179 y `k = 30`.

#![expect(clippy::unwrap_used, reason = "el banco falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio banco"
)]

use std::time::Instant;

use zx_dag::RangoSolucionValidado;
use zx_dag::ghostdag::{
    Algoritmo, AlmacenGhostdag, BloqueGhostdag, IdentidadGhostdag, ModoMerge, ModoSp, Parametros,
    hash_de_id_textual,
};

fn params() -> Parametros {
    Parametros {
        sp: ModoSp::Zerox,
        merge: ModoMerge::Terna,
        ..Parametros::default()
    }
}

/// Dos cadenas desde la raíz; la unión tiene un mergeset del tamaño de la cadena corta.
fn construir_brazo(algoritmo: Algoritmo, largo_p: usize, largo_q: usize) -> AlmacenGhostdag {
    let mut almacen = AlmacenGhostdag::nuevo(
        params(),
        algoritmo,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    let mut anterior = hash_de_id_textual("G");
    for i in 1..=largo_p {
        let id = hash_de_id_textual(&format!("P{i}"));
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id,
                padres: vec![anterior],
                slot: i as u64,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(100),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        anterior = id;
    }
    let mut anterior = hash_de_id_textual("G");
    for i in 1..=largo_q {
        let id = hash_de_id_textual(&format!("Q{i}"));
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id,
                padres: vec![anterior],
                slot: i as u64,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(100),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        anterior = id;
    }
    almacen
}

fn mediana(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() >> 1]
}

fn medir(algoritmo: Algoritmo, repeticiones: usize) -> Vec<f64> {
    // Calentamiento.
    for _ in 0..2 {
        let mut a = construir_brazo(algoritmo, 180, 179);
        a.anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("U"),
            padres: vec![hash_de_id_textual("P180"), hash_de_id_textual("Q179")],
            slot: 180,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(100),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    }
    let mut tiempos = Vec::with_capacity(repeticiones);
    for _ in 0..repeticiones {
        let mut a = construir_brazo(algoritmo, 180, 179);
        let t0 = Instant::now();
        a.anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("U"),
            padres: vec![hash_de_id_textual("P180"), hash_de_id_textual("Q179")],
            slot: 180,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(100),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
        tiempos.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    tiempos
}

struct Azar(u64);

impl Azar {
    const fn nuevo(semilla: u64) -> Self {
        Self(semilla)
    }

    fn siguiente(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn rango(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.siguiente() % (hi - lo + 1)
    }
}

/// DAG aleatorio con ventana 30, como el generador del instrumento Julia (para comparar
/// peras con peras).
fn generar(n: usize, ventana: usize, semilla: u64) -> Vec<BloqueGhostdag> {
    let mut rng = Azar::nuevo(semilla);
    let mut nodos: Vec<BloqueGhostdag> = vec![BloqueGhostdag {
        id: hash_de_id_textual("G"),
        padres: Vec::new(),
        slot: 0,
        solution_distance: 0,
        rango_espacio: RangoSolucionValidado::para_oraculos(0),
        identidad: IdentidadGhostdag::SinBillete,
    }];
    for i in 1..n {
        let lo = i.saturating_sub(ventana);
        let npadres = (i - lo).min(1 + rng.rango(0, 3) as usize);
        let mut padres: Vec<zx_core::BlockHash> = Vec::new();
        while padres.len() < npadres {
            let p = lo + rng.rango(0, (i - lo - 1) as u64) as usize;
            if !padres.contains(&nodos[p].id) {
                padres.push(nodos[p].id);
            }
        }
        let max_slot = padres
            .iter()
            .map(|h| {
                nodos
                    .iter()
                    .find(|b| b.id == *h)
                    .map(|b| b.slot)
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0);
        let sr = match rng.rango(0, 4) {
            0 => 0,
            1 => 1,
            2 => u64::MAX - 1,
            3 => u64::MAX,
            _ => rng.rango(0, i64::MAX as u64),
        };
        nodos.push(BloqueGhostdag {
            id: hash_de_id_textual(&format!("B{i}")),
            padres,
            slot: max_slot + rng.rango(0, 2),
            solution_distance: rng.rango(0, 1 << 20),
            rango_espacio: RangoSolucionValidado::para_oraculos(sr),
            identidad: IdentidadGhostdag::SinBillete,
        });
    }
    nodos
}

fn bench_throughput(algoritmo: Algoritmo) {
    println!("\n-- coste por bloque frente al tamaño del DAG (k=30, ventana 30) --");
    println!("n        total (ms)     µs/bloque");
    for n in [100usize, 200, 400, 800, 1600] {
        let nodos = generar(n, 30, 0xB0E1 + n as u64);
        // Calentamiento.
        let _ = {
            let mut a = AlmacenGhostdag::nuevo(
                params(),
                algoritmo,
                nodos[0].id,
                nodos[0].slot,
                nodos[0].rango_espacio,
                0,
            );
            for b in nodos.iter().skip(1) {
                a.anadir_sintetico(b.clone()).unwrap();
            }
            a
        };
        let t0 = Instant::now();
        let mut a = AlmacenGhostdag::nuevo(
            params(),
            algoritmo,
            nodos[0].id,
            nodos[0].slot,
            nodos[0].rango_espacio,
            0,
        );
        for b in nodos.iter().skip(1) {
            a.anadir_sintetico(b.clone()).unwrap();
        }
        let dt = t0.elapsed().as_secs_f64() * 1e3;
        println!("{:<8} {:>12.3} {:>12.3}", n, dt, dt * 1e3 / n as f64);
    }
}

#[test]
#[ignore = "banco; ejecutar con --ignored --nocapture"]
fn bench_coloreo_mergeset_maximo() {
    for (nombre, algoritmo) in [
        ("kernel", Algoritmo::Kernel),
        ("referencia", Algoritmo::Referencia),
    ] {
        let t = medir(algoritmo, 21);
        let min = t.iter().copied().fold(f64::INFINITY, f64::min);
        let max = t.iter().copied().fold(0.0, f64::max);
        println!(
            "coloreo {nombre} (|mergeset|=179, k=30): mediana {:.3} µs, min {:.3} µs, max {:.3} µs, n={}",
            mediana(t.clone()),
            min,
            max,
            t.len()
        );
    }
    bench_throughput(Algoritmo::Kernel);
    bench_throughput(Algoritmo::Referencia);
}
