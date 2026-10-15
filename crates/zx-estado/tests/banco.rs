//! Banco de medida del lote del árbol de estado (prueba `#[ignore]`, `--release`).
//!
//! Se ejecuta **solo** en el bloque 0, con `flock -x deepseek/.bloque0.lock taskset -c 0-7,16-23`
//! y envuelto en `perf stat -e cycles:u,task-clock:u`. Cada celda es un proceso:
//!
//! ```text
//! BANCO_CELDA=construir BANCO_M=7 BANCO_DIR=<db> cargo test --release -p zx-estado \
//!     --all-features --test banco -- --ignored --exact banco
//! BANCO_M=6 BANCO_B=10000 BANCO_FRIO=1 BANCO_HILOS=1 BANCO_REPS=5 \
//!     BANCO_CSV=crudos/banco-m6-b1e4-frio-h1.csv ...
//! ```
//!
//! La base (árbol de `10^M` entradas) se construye una vez por `M` y se reutiliza.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "el banco falla con panic por diseño"
)]

use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use zx_estado::{
    Almacen, AlmacenRocks, Cambio, CaminoSha3, Error, Hash32, Nodos, SplitMix64, aplicar,
    hash_vacio, hash_valor, reconstruir,
};

/// Familia de la medida.
const FAM: u8 = 0x02;

/// Constructor del árbol base: agrupa escrituras de nodos en lotes y las confirma.
struct Constructor {
    alm: AlmacenRocks,
    nodos: Vec<(Hash32, Option<Vec<u8>>)>,
    umbral: usize,
}

impl Constructor {
    fn nuevo(alm: AlmacenRocks, umbral: usize) -> Self {
        Self {
            alm,
            nodos: Vec::new(),
            umbral: umbral.max(1),
        }
    }

    fn vaciar(&mut self) -> Result<(), Error> {
        if self.nodos.is_empty() {
            return Ok(());
        }
        let nodos = std::mem::take(&mut self.nodos);
        self.alm.commit(&nodos, &[], &[])
    }

    fn almacen_mut(&mut self) -> &mut AlmacenRocks {
        &mut self.alm
    }
}

impl Nodos for Constructor {
    fn leer(&self, h: &Hash32) -> Result<Option<Vec<u8>>, Error> {
        self.alm.leer(h)
    }

    fn poner(&mut self, h: Hash32, v: Vec<u8>) -> Result<(), Error> {
        self.nodos.push((h, Some(v)));
        if self.nodos.len() >= self.umbral {
            self.vaciar()?;
        }
        Ok(())
    }

    fn quitar(&mut self, h: Hash32) -> Result<(), Error> {
        self.nodos.push((h, None));
        if self.nodos.len() >= self.umbral {
            self.vaciar()?;
        }
        Ok(())
    }
}

fn env_usize(nombre: &str, defecto: usize) -> usize {
    std::env::var(nombre)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(defecto)
}

fn env_u64(nombre: &str, defecto: u64) -> u64 {
    std::env::var(nombre)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(defecto)
}

fn env_bool(nombre: &str, defecto: bool) -> bool {
    std::env::var(nombre)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(defecto)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Construye el árbol base de `10^m_exp` entradas si aún no existe.
fn construir_base(dir: &Path, m_exp: u32, semilla: u64) -> Result<(), Error> {
    let m = 10usize.pow(m_exp);
    let alm = AlmacenRocks::abrir(dir, false)?;
    if alm.raiz(FAM)? != hash_vacio() {
        println!("base ya construida: {dir:?}");
        return Ok(());
    }
    let t0 = Instant::now();
    let mut rng = SplitMix64::nuevo(semilla);
    let mut entradas: Vec<(Vec<u8>, Hash32)> = Vec::with_capacity(m);
    for _ in 0..m {
        let k = rng.bytes32();
        let _v = rng.bytes32();
        entradas.push((k.to_vec(), hash_valor(&_v)));
    }
    let gen_s = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let mut constructor = Constructor::nuevo(alm, 1_000_000);
    let raiz = reconstruir(&CaminoSha3, &mut constructor, FAM, &entradas)?;
    constructor.vaciar()?;
    constructor.almacen_mut().commit(&[], &[], &[(FAM, raiz)])?;
    constructor.almacen_mut().volcar()?;
    let arbol = t1.elapsed().as_secs_f64();
    println!(
        "construir m={m} gen_s={gen_s:.3} arbol_s={arbol:.3} raiz={}",
        hex(&raiz)
    );
    Ok(())
}

fn claves_de(m: usize, semilla: u64) -> Vec<[u8; 32]> {
    let mut rng = SplitMix64::nuevo(semilla);
    let mut claves = Vec::with_capacity(m);
    for _ in 0..m {
        let k = rng.bytes32();
        let _v = rng.bytes32();
        claves.push(k);
    }
    claves
}

fn indices_objetivo(m: usize, b: usize, semilla: u64) -> Vec<usize> {
    if b >= m {
        return (0..m).collect();
    }
    let mut vistos = std::collections::HashSet::with_capacity(b);
    let mut rng = SplitMix64::nuevo(semilla ^ 0x5EED);
    while vistos.len() < b {
        vistos.insert(usize::try_from(rng.hasta(m as u64)).unwrap_or(0));
    }
    let mut v: Vec<usize> = vistos.into_iter().collect();
    v.sort_unstable();
    v
}

#[allow(clippy::too_many_arguments)]
fn medir_celda(
    dir: &Path,
    m_exp: u32,
    b: usize,
    frio: bool,
    hilos: usize,
    reps: usize,
    semilla: u64,
    csv: &str,
) -> Result<(), Error> {
    let m = 10usize.pow(m_exp);
    let claves = claves_de(m, semilla);
    let indices = indices_objetivo(m, b, semilla);

    let mut salida = std::fs::File::create(csv).expect("crear csv");
    writeln!(salida, "m,b,temp,hilos,rep,segundos,raiz").expect("cabecera");

    let mut alm = AlmacenRocks::abrir(dir, frio)?;
    for rep in 0..reps {
        if frio {
            alm.volcar()?;
            drop(alm);
            alm = AlmacenRocks::abrir(dir, true)?;
        }
        let _raiz = alm.raiz(FAM)?;
        let mut rng = SplitMix64::nuevo(
            semilla
                .wrapping_mul(1_000_003)
                .wrapping_add(rep as u64)
                .wrapping_add(0x1234),
        );
        let cambios: Vec<Cambio> = indices
            .iter()
            .map(|&i| Cambio::poner(FAM, claves[i].to_vec(), rng.bytes32().to_vec()))
            .collect();

        let t0 = Instant::now();
        let raices = aplicar(&mut alm, &CaminoSha3, &cambios, hilos)?;
        let seg = t0.elapsed().as_secs_f64();
        let nueva = raices.first().map_or(hash_vacio(), |(_, r)| *r);
        let temp = if frio { "frio" } else { "caliente" };
        writeln!(
            salida,
            "{m},{b},{temp},{hilos},{rep},{seg:.6},{}",
            hex(&nueva)
        )
        .expect("fila csv");
        salida.flush().expect("volcar csv");
        println!(
            "celda m={m} b={b} {temp} hilos={hilos} rep={rep} segundos={seg:.6} raiz={}",
            hex(&nueva)
        );
    }
    Ok(())
}

#[test]
#[ignore = "banco del bloque 0; requiere --release, candado exclusivo y base construida"]
fn banco() {
    let semilla = env_u64("BANCO_SEMILLA", 0x5EED);
    let dir = std::env::var("BANCO_DIR").unwrap_or_else(|_| "/tmp/zx-estado-banco".to_string());
    let dir = Path::new(&dir);
    if env_bool("BANCO_CONSTRUIR", false) {
        let m_exp = u32::try_from(env_usize("BANCO_M", 6)).expect("m_exp");
        construir_base(dir, m_exp, semilla).expect("construir base");
        return;
    }
    let m_exp = u32::try_from(env_usize("BANCO_M", 6)).expect("m_exp");
    let b = env_usize("BANCO_B", 10_000);
    let frio = env_bool("BANCO_FRIO", true);
    let hilos = env_usize("BANCO_HILOS", 1);
    let reps = env_usize("BANCO_REPS", 5);
    let csv = std::env::var("BANCO_CSV").unwrap_or_else(|_| "crudos/banco.csv".to_string());
    if let Some(padre) = Path::new(&csv).parent() {
        let _ = std::fs::create_dir_all(padre);
    }
    medir_celda(dir, m_exp, b, frio, hilos, reps, semilla, &csv).expect("medir celda");
}
