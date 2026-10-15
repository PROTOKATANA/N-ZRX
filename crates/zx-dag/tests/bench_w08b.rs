//! Banco W08b: coste por admisión y memoria residente (`VmHWM`) con `N` = 10³…10⁶, en cadena
//! lineal y DAG ancho (anchura media 3 y 10).
//!
//! Una sola configuración por proceso (env `W08B_N` y `W08B_MODO`) para que `VmHWM` corresponda a
//! esa `N`. El conductor `run/bench.sh` invoca el binario ya compilado.
//!
//! ```text
//! W08B_N=100000 W08B_MODO=lineal cargo test -p zx-dag --release --test bench_w08b --locked \
//!     -- --ignored --nocapture --exact bench_w08b_uno
//! ```

#![expect(clippy::unwrap_used, reason = "el banco falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio banco"
)]
#![expect(
    clippy::integer_division,
    reason = "el tramo marginal es n/10, una división entera deliberada"
)]
#![expect(clippy::panic, reason = "un modo desconocido es un fallo del banco")]

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

fn bloque(
    id: zx_core::BlockHash,
    padres: Vec<zx_core::BlockHash>,
    slot: u64,
    sr: u64,
) -> BloqueGhostdag {
    BloqueGhostdag {
        id,
        padres,
        slot,
        solution_distance: 0,
        rango_espacio: RangoSolucionValidado::para_oraculos(sr),
        identidad: IdentidadGhostdag::SinBillete,
    }
}

fn generar_lineal(n: usize) -> Vec<BloqueGhostdag> {
    let mut v = vec![bloque(hash_de_id_textual("G"), Vec::new(), 0, 0)];
    for i in 1..n {
        let padre = v[i - 1].id;
        v.push(bloque(
            hash_de_id_textual(&format!("L{i}")),
            vec![padre],
            i as u64,
            100,
        ));
    }
    v
}

fn generar_ancho(n: usize, ancho: usize, semilla: u64) -> Vec<BloqueGhostdag> {
    let mut rng = Azar::nuevo(semilla);
    let ventana = (ancho * 2).max(2);
    let mut v = vec![bloque(hash_de_id_textual("G"), Vec::new(), 0, 0)];
    for i in 1..n {
        let lo = i.saturating_sub(ventana);
        let disponibles = i - lo;
        let max_padres = disponibles.min(1 + rng.rango(0, (ancho - 1) as u64) as usize);
        let mut indices: Vec<usize> = Vec::new();
        while indices.len() < max_padres {
            let p = lo + rng.rango(0, (disponibles - 1) as u64) as usize;
            if !indices.contains(&p) {
                indices.push(p);
            }
        }
        let slot_base = indices.iter().map(|p| v[*p].slot).max().unwrap_or(0);
        let padres: Vec<zx_core::BlockHash> = indices.iter().map(|p| v[*p].id).collect();
        v.push(bloque(
            hash_de_id_textual(&format!("B{i}")),
            padres,
            slot_base + 1,
            100,
        ));
    }
    v
}

fn hwm_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for linea in s.lines() {
        if let Some(resto) = linea.strip_prefix("VmHWM:")
            && let Some(v) = resto.split_whitespace().next()
        {
            return v.parse().unwrap_or(0);
        }
    }
    0
}

#[test]
#[ignore = "banco; se lanza con --ignored y las variables W08B_N/W08B_MODO"]
fn bench_w08b_uno() {
    let n: usize = std::env::var("W08B_N")
        .unwrap_or_else(|_| "1000".to_string())
        .parse()
        .unwrap();
    let modo = std::env::var("W08B_MODO").unwrap_or_else(|_| "lineal".to_string());
    let nodos = match modo.as_str() {
        "lineal" => generar_lineal(n),
        "ancho3" => generar_ancho(n, 3, 0xA3),
        "ancho10" => generar_ancho(n, 10, 0xA10),
        otro => panic!("modo desconocido: {otro}"),
    };
    let base = hwm_kb();
    let mut almacen = AlmacenGhostdag::nuevo(
        params(),
        Algoritmo::Kernel,
        nodos[0].id,
        nodos[0].slot,
        nodos[0].rango_espacio,
        0,
    );
    // Se mide por separado el tramo final (coste marginal a tamaño N) y el total.
    let ventana = (n / 10).clamp(1, 2000);
    let prefijo = n - 1 - ventana;
    let t0 = Instant::now();
    for b in nodos.iter().skip(1).take(prefijo) {
        almacen.anadir_sintetico(b.clone()).unwrap();
    }
    let t_pre = t0.elapsed();
    let t1 = Instant::now();
    for b in nodos.iter().skip(1).skip(prefijo) {
        almacen.anadir_sintetico(b.clone()).unwrap();
    }
    let t_ult = t1.elapsed();
    let hwm = hwm_kb();
    let us_total = (t_pre + t_ult).as_secs_f64() * 1e6 / (n - 1) as f64;
    let us_ult = t_ult.as_secs_f64() * 1e6 / ventana as f64;
    let (cub_max, cub_total) = almacen.diagnostico_cubrientes();
    println!(
        "RES n={n} modo={modo} ventana={ventana} us_total={us_total:.3} us_ultimas={us_ult:.3} \
         hwm_kb={hwm} hwm_delta_kb={} cub_max={cub_max} cub_total={cub_total}",
        hwm.saturating_sub(base)
    );
    assert_eq!(almacen.len(), n);
}
