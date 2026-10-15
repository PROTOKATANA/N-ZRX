//! Diferencial de la **parte B** de `timestamps.jsonl` (reglas de timestamp PoST, RL-2b).
//!
//! Reproduce las 8 filas `pmt`, `monotonia_frontera`, `ftl` y `banda_ts_slot` de
//! `P-ZRX/P-RELOJ/RL1/vectores/timestamps.jsonl` a través de las funciones **reales** de
//! `zx_consensus::timestamps` (`C-RLJ-TS-01`…`C-RLJ-TS-03`). Es el test que **falla hoy** (las
//! funciones no existían) y pasa tras RL-2b.
//!
//! No se reimplementa el parser JSON: los vectores son JSONL plano y se extraen los campos con el
//! mismo criterio que `zx-post/tests/vectores_rl1.rs`.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "instrumento de test: un fallo de fixture o de comparación debe producir panic"
)]

use std::fs;
use std::path::PathBuf;

use zx_consensus::timestamps::{
    ErrorTimestampPost, PERFIL_TIMESTAMP_POST_DEV, ParametrosTimestampPost,
    comprobar_banda_ts_slot, comprobar_ftl_post, comprobar_pmt, pmt,
};

/// Directorio de vectores de RL-1, relativo a la raíz del workspace.
const DIR_VECTORES: &str = "testdata/reloj-rl1-vectores";

fn ruta(fichero: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(DIR_VECTORES)
        .join(fichero)
}

fn leer(fichero: &str) -> Vec<String> {
    let ruta = ruta(fichero);
    let texto = fs::read_to_string(&ruta)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", ruta.display()));
    texto
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Valor crudo de `"clave":` en una línea JSONL simple (los vectores usan valores planos).
fn campo<'a>(linea: &'a str, clave: &str) -> &'a str {
    let patron = format!("\"{clave}\":");
    let Some(pos) = linea.find(&patron) else {
        return "";
    };
    let resto = &linea[pos + patron.len()..];
    if let Some(interior) = resto.strip_prefix('"') {
        match interior.find('"') {
            Some(fin) => &interior[..fin],
            None => "",
        }
    } else {
        match resto.find([',', '}']) {
            Some(fin) => resto[..fin].trim(),
            None => resto.trim(),
        }
    }
}

fn num(linea: &str, clave: &str) -> u64 {
    campo(linea, clave)
        .parse()
        .unwrap_or_else(|e| panic!("campo {clave} no numérico en {linea}: {e}"))
}

fn logico(linea: &str, clave: &str) -> bool {
    campo(linea, clave) == "true"
}

/// `"num/den"` → `(num, den)` como `i128` (el vector usa racionales exactos).
fn rac(linea: &str, clave: &str) -> (i128, i128) {
    let texto = campo(linea, clave);
    let (n, d) = texto
        .split_once('/')
        .unwrap_or_else(|| panic!("racional sin '/' : {texto}"));
    (
        n.parse()
            .unwrap_or_else(|e| panic!("num inválido {n}: {e}")),
        d.parse()
            .unwrap_or_else(|e| panic!("den inválido {d}: {e}")),
    )
}

fn rac_entero(linea: &str, clave: &str) -> i64 {
    let (n, d) = rac(linea, clave);
    if d != 1 {
        panic!("se esperaba un racional entero en {clave}: {n}/{d}");
    }
    i64::try_from(n).unwrap_or_else(|e| panic!("{n} no cabe en i64: {e}"))
}

fn perfil(linea: &str) -> ParametrosTimestampPost {
    let (num, den) = rac(linea, "tau_ref");
    ParametrosTimestampPost {
        t_ancla: i64::try_from(num_entero(linea, "t_ancla")).expect("t_ancla cabe en i64"),
        tau_ref_num: num,
        tau_ref_den: den,
        ..PERFIL_TIMESTAMP_POST_DEV
    }
}

fn num_entero(linea: &str, clave: &str) -> u64 {
    num(linea, clave)
}

fn acepta(salida: Result<(), ErrorTimestampPost>, esperado: bool, linea: &str, que: &str) {
    match (salida, esperado) {
        (Ok(()), true) | (Err(_), false) => {}
        (Ok(()), false) => panic!("{que}: se esperaba rechazo y se aceptó en {linea}"),
        (Err(e), true) => panic!("{que}: se esperaba aceptación y se rechazó con {e:?} en {linea}"),
    }
}

#[test]
fn diferencial_timestamps_parte_b() {
    let lineas = leer("timestamps.jsonl");
    let mut n_pmt = 0usize;
    let mut n_monotonia = 0usize;
    let mut n_ftl = 0usize;
    let mut n_banda = 0usize;
    let mut discrepancias: Vec<String> = Vec::new();

    for linea in &lineas {
        match campo(linea, "tipo") {
            "pmt" => {
                n_pmt += 1;
                let valores: Vec<i64> = campo(linea, "pasado")
                    .split(',')
                    .map(|v| v.trim().parse().expect("timestamp entero"))
                    .collect();
                let m = num(linea, "m") as usize;
                let obtenido = pmt(&valores, m).expect("ventana no vacía");
                let (esperado, den) = rac(linea, "salida");
                if den != 1 || i128::from(obtenido) != esperado {
                    discrepancias.push(format!(
                        "pmt: esperado {esperado}/{den}, obtenido {obtenido} en {linea}"
                    ));
                }
            }
            "monotonia_frontera" => {
                n_monotonia += 1;
                let ts = rac_entero(linea, "ts");
                let mediana = rac_entero(linea, "pmt");
                acepta(
                    comprobar_pmt(ts, mediana),
                    logico(linea, "acepta"),
                    linea,
                    "monotonia_frontera",
                );
            }
            "ftl" => {
                n_ftl += 1;
                let ts = i64::try_from(num(linea, "ts")).expect("ts cabe en i64");
                let reloj = i64::try_from(num(linea, "reloj")).expect("reloj cabe en i64");
                let ftl = i64::try_from(num(linea, "ftl")).expect("ftl cabe en i64");
                let salida = comprobar_ftl_post(ts, reloj, ftl);
                // C-RLJ-TS-02: el rechazo por futuro **no** es permanente.
                if let Err(e) = &salida
                    && e.es_permanente()
                {
                    discrepancias.push(format!("ftl: rechazo marcado permanente en {linea}"));
                }
                acepta(salida, logico(linea, "acepta"), linea, "ftl");
            }
            "banda_ts_slot" => {
                n_banda += 1;
                let ts = i64::try_from(num(linea, "ts")).expect("ts cabe en i64");
                let slot = num(linea, "slot");
                let p = perfil(linea);
                acepta(
                    comprobar_banda_ts_slot(ts, slot, &p),
                    logico(linea, "acepta"),
                    linea,
                    "banda_ts_slot",
                );
            }
            // Parte A: la cubre `zx-post/tests/vectores_rl1.rs` (mediana, cuantiles, sesgo).
            "mediana" | "cuantil_mediana_ataque" | "sesgo_por_mitades" => {}
            otro => discrepancias.push(format!("tipo desconocido en timestamps.jsonl: {otro}")),
        }
    }

    assert!(
        discrepancias.is_empty(),
        "discrepancias parte B ({}):\n{}",
        discrepancias.len(),
        discrepancias.join("\n")
    );
    assert!(
        n_pmt > 0 && n_monotonia > 0 && n_ftl > 0 && n_banda > 0,
        "faltan filas de la parte B"
    );
    eprintln!(
        "RL2b V2 parte B: {n_pmt} pmt + {n_monotonia} monotonia + {n_ftl} ftl + {n_banda} banda, \
         0 discrepancias"
    );
}
