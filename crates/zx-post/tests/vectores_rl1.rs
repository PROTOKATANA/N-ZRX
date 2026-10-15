//! Diferencial **RL-2** contra los vectores de RL-1 (`P-ZRX/P-RELOJ/RL1/vectores/*.jsonl`).
//!
//! Cubre las reglas de las **partes A y C** del contrato:
//!
//! - `ajuste.jsonl` → `C-RLJ-05` (ajuste), `C-RLJ-03` (duplicación) y `C-RLJ-07` (techo).
//! - `timestamps.jsonl` (sólo las filas de la parte A) → `C-RLJ-04`: mediana, cuantil de la mediana
//!   bajo ataque y sesgo por mitades. Las filas `pmt`, `monotonia_frontera`, `ftl` y `banda_ts_slot`
//!   son **parte B** (timestamps PoST) y pertenecen a RL-2b, que las cablea a `zx-consensus`.
//! - `manipulacion.jsonl` → ataque de timestamps sobre el estimador `C-RLJ-04` (mismo mecanismo).
//! - `vdf.jsonl` → `C-RLJ-VDF-02` (segmentos y encadenado) y `C-RLJ-VDF-03` (orden no circular).
//! - `adelanto.jsonl` → `C-RLJ-VDF-01`.
//!
//! # Lo que NO se compara
//!
//! - `cadena_segmentada`: la salida de RL-1 usa la primitiva de juguete (LCG) y declara que sólo es
//!   reproducible en **estructura**. Aquí se ejecuta la primitiva AES real y se comprueban las
//!   longitudes y el encadenado (`salida_final == última salida por segmento`), como manda
//!   `VECTORES.md`.
//! - `molienda*.jsonl`: son el **ataque 1 de §4** (modelo estadístico ND-1f y certificado racional
//!   con `BigInt`), no una regla de las partes A o C que RL-2 cablee; no se reimplementan aquí.

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::integer_division,
    reason = "instrumento de test: un fallo de fixture o de comparación debe producir panic"
)]

use std::fs;
use std::path::PathBuf;

use zx_post::reloj::{
    Accion, EstadoReloj, Racional, adelanto_con_vdf, adelanto_sin_vdf, ajustar,
    cuantil_mediana_bajo_ataque, mediana, recorte, rho_umbral, segundo_vdf_util, sesgo_por_mitades,
};
use zx_post::vdf::{
    EntradaVdf, EstadoOrdenVdf, cadena_segmentada, orden_vdf, segmentos as segmentos_vdf,
};

/// Directorio de vectores de RL-1, relativo a la raíz del workspace.
const DIR_VECTORES: &str = "testdata/reloj-rl1-vectores";

/// `N_max` del perfil de PK-08 que usa el ataque de manipulación (`C-RLJ-07`).
const N_MAX_PK08: u64 = 240_000_000;

/// `n_iter` de ejemplo de RL-1 (múltiplo de 16, RL1-A10) usado por `manipulacion.jsonl`.
const N_ITER_RL1: u64 = 2_603_792;

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

fn rac_de(texto: &str) -> Racional {
    let (n, d) = texto
        .split_once('/')
        .unwrap_or_else(|| panic!("racional sin '/' : {texto}"));
    Racional::nuevo(
        n.parse()
            .unwrap_or_else(|e| panic!("num inválido {n}: {e}")),
        d.parse()
            .unwrap_or_else(|e| panic!("den inválido {d}: {e}")),
    )
    .unwrap_or_else(|e| panic!("racional inválido {texto}: {e}"))
}

fn rac(linea: &str, clave: &str) -> Racional {
    rac_de(campo(linea, clave))
}

fn accion_nombre(accion: Accion) -> &'static str {
    match accion {
        Accion::Bajar => "bajar",
        Accion::Igual => "igual",
        Accion::Subir => "subir",
    }
}

fn longitudes_texto(valores: &[u64]) -> String {
    valores
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// `ajuste.jsonl`: fronteras exactas de `C-RLJ-05`, `C-RLJ-03` y `C-RLJ-07`.
#[test]
fn diferencial_ajuste() {
    let lineas = leer("ajuste.jsonl");
    let mut discrepancias = Vec::new();
    let mut n_ajuste = 0usize;
    let mut n_techo = 0usize;
    let mut salidas_ajuste: Vec<(u64, u64, u64, u64, u64, u64)> = Vec::new();

    for linea in &lineas {
        let tipo = campo(linea, "tipo");
        let t = num(linea, "T");
        let n_iter = num(linea, "n_iter");
        match tipo {
            "ajuste" => {
                n_ajuste += 1;
                let n_max = num(linea, "n_max");
                let salida = ajustar(
                    EstadoReloj::nuevo(t, n_iter, n_max),
                    rac(linea, "tau_est"),
                    rac(linea, "tau_ref"),
                    rac(linea, "U"),
                );
                if accion_nombre(salida.accion) != campo(linea, "accion") {
                    discrepancias.push(format!(
                        "accion: esperado {}, obtenido {} en {linea}",
                        campo(linea, "accion"),
                        accion_nombre(salida.accion)
                    ));
                }
                if salida.duplicado != logico(linea, "duplicado") {
                    discrepancias.push(format!("duplicado en {linea}"));
                }
                if salida.estado.t() != num(linea, "T2")
                    || salida.estado.n_iter() != num(linea, "n_iter2")
                    || salida.estado.iteraciones() != num(linea, "N2")
                {
                    discrepancias.push(format!(
                        "estado: esperado ({},{},{}), obtenido ({},{},{}) en {linea}",
                        num(linea, "T2"),
                        num(linea, "n_iter2"),
                        num(linea, "N2"),
                        salida.estado.t(),
                        salida.estado.n_iter(),
                        salida.estado.iteraciones()
                    ));
                }
                salidas_ajuste.push((
                    t,
                    n_iter,
                    n_max,
                    salida.estado.t(),
                    salida.estado.n_iter(),
                    salida.estado.iteraciones(),
                ));
            }
            "ajuste_techo" => {
                n_techo += 1;
                let n_max = num(linea, "N_max");
                // La fila de techo no trae `tau`; se comprueba que sea idéntica a una fila
                // `ajuste` ya calculada para el mismo estado de entrada.
                let esperado = (
                    t,
                    n_iter,
                    n_max,
                    num(linea, "T2"),
                    num(linea, "n_iter2"),
                    num(linea, "N2"),
                );
                if !salidas_ajuste.contains(&esperado) {
                    discrepancias.push(format!(
                        "ajuste_techo sin fila `ajuste` equivalente: {linea}"
                    ));
                }
            }
            otro => discrepancias.push(format!("tipo desconocido en ajuste.jsonl: {otro}")),
        }
    }

    assert!(
        discrepancias.is_empty(),
        "discrepancias ajuste ({}):\n{}",
        discrepancias.len(),
        discrepancias.join("\n")
    );
    assert!(n_ajuste > 0 && n_techo > 0, "faltan filas de ajuste");
    eprintln!(
        "RL2 V2 ajuste: {n_ajuste} filas `ajuste` + {n_techo} `ajuste_techo`, 0 discrepancias"
    );
}

/// `timestamps.jsonl` (parte A): mediana, cuantil de la mediana y sesgo por mitades de `C-RLJ-04`.
#[test]
fn diferencial_estimador_parte_a() {
    let lineas = leer("timestamps.jsonl");
    let mut discrepancias = Vec::new();
    let mut n_mediana = 0usize;
    let mut n_cuantil = 0usize;
    let mut n_sesgo = 0usize;
    let mut omitidas_parte_b = 0usize;

    for linea in &lineas {
        match campo(linea, "tipo") {
            "mediana" => {
                n_mediana += 1;
                let valores: Vec<u64> = campo(linea, "entrada")
                    .split(',')
                    .map(|v| v.trim().parse().expect("entrada numérica"))
                    .collect();
                let obtenido = mediana(&valores).expect("mediana");
                if obtenido.to_string() != campo(linea, "salida") {
                    discrepancias.push(format!(
                        "mediana: esperado {}, obtenido {obtenido} en {linea}",
                        campo(linea, "salida")
                    ));
                }
            }
            "cuantil_mediana_ataque" => {
                n_cuantil += 1;
                let obtenido =
                    cuantil_mediana_bajo_ataque(rac(linea, "alpha_mitad")).expect("cuantil válido");
                if obtenido.to_string() != campo(linea, "cuantil") {
                    discrepancias.push(format!(
                        "cuantil: esperado {}, obtenido {obtenido} en {linea}",
                        campo(linea, "cuantil")
                    ));
                }
            }
            "sesgo_por_mitades" => {
                n_sesgo += 1;
                let sesgo = sesgo_por_mitades(rac(linea, "alpha_total"), num(linea, "A"))
                    .expect("sesgo válido");
                if sesgo.alpha_mitad.to_string() != campo(linea, "alpha_mitad")
                    || sesgo.cuantil_mediana.to_string() != campo(linea, "cuantil_mitad_atacada")
                {
                    discrepancias.push(format!(
                        "sesgo: esperado ({},{}), obtenido ({},{}) en {linea}",
                        campo(linea, "alpha_mitad"),
                        campo(linea, "cuantil_mitad_atacada"),
                        sesgo.alpha_mitad,
                        sesgo.cuantil_mediana
                    ));
                }
            }
            // Parte B (timestamps PoST): los cablea RL-2b en `zx-consensus`.
            "pmt" | "monotonia_frontera" | "ftl" | "banda_ts_slot" => omitidas_parte_b += 1,
            otro => discrepancias.push(format!("tipo desconocido en timestamps.jsonl: {otro}")),
        }
    }

    assert!(
        discrepancias.is_empty(),
        "discrepancias estimador ({}):\n{}",
        discrepancias.len(),
        discrepancias.join("\n")
    );
    assert!(n_mediana > 0 && n_cuantil > 0 && n_sesgo > 0);
    eprintln!(
        "RL2 V2 C-RLJ-04: {n_mediana} medianas + {n_cuantil} cuantiles + {n_sesgo} sesgos; \
         {omitidas_parte_b} filas de parte B omitidas (RL-2b)"
    );
}

/// `manipulacion.jsonl`: ataque de timestamps sobre el estimador `C-RLJ-04`.
#[test]
fn diferencial_manipulacion() {
    let lineas = leer("manipulacion.jsonl");
    let mut discrepancias = Vec::new();
    let mut n = 0usize;

    for linea in &lineas {
        n += 1;
        let a = num(linea, "A");
        let alpha_total = rac(linea, "alpha_total");
        let sesgo = sesgo_por_mitades(alpha_total, a).expect("sesgo válido");
        let atacada = sesgo.cuantil_mediana;
        let opuesta = Racional::uno() - atacada;
        let salto = atacada - opuesta;
        let t_max = N_MAX_PK08 / N_ITER_RL1;
        let ventanas_50_a_1 = 50u64 - 1;
        let ventanas_50_a_t_max = t_max - 50;
        let comparaciones = [
            (
                "alpha_mitad",
                sesgo.alpha_mitad.to_string(),
                campo(linea, "alpha_mitad").to_owned(),
            ),
            (
                "cuantil_mediana_atacada",
                atacada.to_string(),
                campo(linea, "cuantil_mediana_atacada").to_owned(),
            ),
            (
                "cuantil_mediana_opuesta",
                opuesta.to_string(),
                campo(linea, "cuantil_mediana_opuesta").to_owned(),
            ),
            (
                "salto_cuantil",
                salto.to_string(),
                campo(linea, "salto_cuantil").to_owned(),
            ),
            (
                "deriva_ticks_por_ventana",
                "1".to_owned(),
                campo(linea, "deriva_ticks_por_ventana").to_owned(),
            ),
            (
                "ventanas_50_a_1",
                ventanas_50_a_1.to_string(),
                campo(linea, "ventanas_50_a_1").to_owned(),
            ),
            (
                "slots_50_a_1",
                (ventanas_50_a_1 * a).to_string(),
                campo(linea, "slots_50_a_1").to_owned(),
            ),
            (
                "segundos_nominales_50_a_1",
                (ventanas_50_a_1 * a).to_string(),
                campo(linea, "segundos_nominales_50_a_1").to_owned(),
            ),
            ("T_max", t_max.to_string(), campo(linea, "T_max").to_owned()),
            (
                "ventanas_50_a_T_max",
                ventanas_50_a_t_max.to_string(),
                campo(linea, "ventanas_50_a_T_max").to_owned(),
            ),
            (
                "slots_50_a_T_max",
                (ventanas_50_a_t_max * a).to_string(),
                campo(linea, "slots_50_a_T_max").to_owned(),
            ),
            (
                "segundos_nominales_50_a_T_max",
                (ventanas_50_a_t_max * a).to_string(),
                campo(linea, "segundos_nominales_50_a_T_max").to_owned(),
            ),
            (
                "hay_mayoria",
                (alpha_total >= Racional::nuevo(1, 2).expect("1/2")).to_string(),
                campo(linea, "hay_mayoria").to_owned(),
            ),
        ];
        for (clave, esperado, obtenido) in comparaciones {
            if esperado != obtenido {
                discrepancias.push(format!(
                    "manipulacion {clave}: esperado {esperado}, obtenido {obtenido} en {linea}"
                ));
            }
        }
    }

    assert!(
        discrepancias.is_empty(),
        "discrepancias manipulacion ({}):\n{}",
        discrepancias.len(),
        discrepancias.join("\n")
    );
    assert!(n > 0);
    eprintln!("RL2 V2 manipulacion: {n} filas, 0 discrepancias");
}

/// `vdf.jsonl`: segmentación exacta (`C-RLJ-VDF-02`), encadenado real y orden no circular
/// (`C-RLJ-VDF-03`).
#[test]
fn diferencial_vdf() {
    let lineas = leer("vdf.jsonl");
    let mut discrepancias = Vec::new();
    let mut n_segmentos = 0usize;
    let mut n_cadena = 0usize;
    let mut n_orden = 0usize;

    for linea in &lineas {
        match campo(linea, "tipo") {
            "segmentos" => {
                n_segmentos += 1;
                let total = num(linea, "total");
                let max_seg = num(linea, "max_seg");
                let obtenido = segmentos_vdf(total, max_seg).expect("segmentación válida");
                let esperado = campo(linea, "longitudes").to_owned();
                let suma: u64 = obtenido.iter().sum();
                if longitudes_texto(&obtenido) != esperado
                    || obtenido.len() != num(linea, "n_segmentos") as usize
                    || suma != num(linea, "suma")
                {
                    discrepancias.push(format!(
                        "segmentos: esperado {esperado}, obtenido {} en {linea}",
                        longitudes_texto(&obtenido)
                    ));
                }
            }
            "cadena_segmentada" => {
                n_cadena += 1;
                let total = num(linea, "total");
                let max_seg = num(linea, "max_seg");
                // Primitiva AES real; sólo se compara la estructura, como declara `VECTORES.md`.
                let cadena = cadena_segmentada([1u8; 16], total, max_seg).expect("cadena válida");
                if longitudes_texto(&cadena.longitudes) != campo(linea, "longitudes") {
                    discrepancias.push(format!(
                        "cadena longitudes: esperado {}, obtenido {} en {linea}",
                        campo(linea, "longitudes"),
                        longitudes_texto(&cadena.longitudes)
                    ));
                }
                match cadena.salidas_por_segmento.last() {
                    Some(ultima) if *ultima == cadena.salida_final => {}
                    _ => discrepancias.push(format!("cadena no encadena en {linea}")),
                }
            }
            "orden_vdf" => {
                n_orden += 1;
                let caso = campo(linea, "caso");
                let entrada = match caso {
                    "positivo_pasado" => EntradaVdf {
                        ancla_en_pasado: true,
                        chunk_en_pasado: true,
                        t_j: 10,
                        usa_pot_output_del_candidato: false,
                        hay_flujo_previo: true,
                    },
                    "negativo_circular" => EntradaVdf {
                        ancla_en_pasado: true,
                        chunk_en_pasado: true,
                        t_j: 10,
                        usa_pot_output_del_candidato: true,
                        hay_flujo_previo: true,
                    },
                    "negativo_contexto" => EntradaVdf {
                        ancla_en_pasado: false,
                        chunk_en_pasado: true,
                        t_j: 10,
                        usa_pot_output_del_candidato: false,
                        hay_flujo_previo: true,
                    },
                    otro => {
                        discrepancias.push(format!("caso de orden desconocido: {otro}"));
                        continue;
                    }
                };
                let (estado, pasos) = match orden_vdf(&entrada) {
                    EstadoOrdenVdf::Ok(pasos) => (
                        "ok",
                        pasos
                            .iter()
                            .map(|p| p.nombre())
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                    EstadoOrdenVdf::PendienteCircular => ("pendiente_circular", String::new()),
                    EstadoOrdenVdf::PendienteContexto => ("pendiente_contexto", String::new()),
                };
                if estado != campo(linea, "estado") || pasos != campo(linea, "pasos") {
                    discrepancias.push(format!(
                        "orden_vdf {caso}: esperado ({},{}), obtenido ({estado},{pasos})",
                        campo(linea, "estado"),
                        campo(linea, "pasos")
                    ));
                }
            }
            otro => discrepancias.push(format!("tipo desconocido en vdf.jsonl: {otro}")),
        }
    }

    assert!(
        discrepancias.is_empty(),
        "discrepancias vdf ({}):\n{}",
        discrepancias.len(),
        discrepancias.join("\n")
    );
    assert!(n_segmentos > 0 && n_cadena > 0 && n_orden > 0);
    eprintln!(
        "RL2 V2 VDF: {n_segmentos} segmentaciones + {n_cadena} cadenas (estructura AES) + \
         {n_orden} ordenes, 0 discrepancias"
    );
}

/// `adelanto.jsonl`: `C-RLJ-VDF-01` exacto.
#[test]
fn diferencial_adelanto() {
    let lineas = leer("adelanto.jsonl");
    let mut discrepancias = Vec::new();
    let mut n = 0usize;

    for linea in &lineas {
        n += 1;
        let l = num(linea, "L");
        let i = num(linea, "I");
        let rho = rac(linea, "rho");
        let sin = adelanto_sin_vdf(l);
        let con = adelanto_con_vdf(l, i, rho).expect("ρ > 1");
        let umbral = rho_umbral(l, i).expect("I > 0");
        let rec = recorte(l, i, rho).expect("L > 0");
        let util = segundo_vdf_util(l, i, rho).expect("I > 0");
        let flotante_esperado = campo(linea, "con_vdf_float").parse::<f64>().expect("float");
        let comparaciones = [
            (
                "sin_vdf",
                sin.to_string(),
                campo(linea, "sin_vdf").to_owned(),
            ),
            (
                "con_vdf",
                con.to_string(),
                campo(linea, "con_vdf").to_owned(),
            ),
            (
                "recorte",
                rec.to_string(),
                campo(linea, "recorte").to_owned(),
            ),
            (
                "rho_umbral",
                umbral.to_string(),
                campo(linea, "rho_umbral").to_owned(),
            ),
            (
                "vdf_util",
                util.to_string(),
                campo(linea, "vdf_util").to_owned(),
            ),
        ];
        for (clave, esperado, obtenido) in comparaciones {
            if esperado != obtenido {
                discrepancias.push(format!(
                    "adelanto {clave}: esperado {esperado}, obtenido {obtenido} en {linea}"
                ));
            }
        }
        if (con.a_f64() - flotante_esperado).abs() > 1e-9 {
            discrepancias.push(format!(
                "adelanto con_vdf_float: esperado {flotante_esperado}, obtenido {}",
                con.a_f64()
            ));
        }
    }

    assert!(
        discrepancias.is_empty(),
        "discrepancias adelanto ({}):\n{}",
        discrepancias.len(),
        discrepancias.join("\n")
    );
    assert!(n > 0);
    eprintln!("RL2 V2 adelanto: {n} filas, 0 discrepancias");
}
