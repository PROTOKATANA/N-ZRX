//! V2 · Diferencial contra `SR0/vectores/*.jsonl` (168/168) y tabla de cobertura por regla.
//!
//! Reescribe en la transición de Rust los 144 casos de S03 (12 tipos × 12 semillas) y los 24
//! vectores de rechazo del contrato `C-SEC-*`. Los ficheros se empotran con `include_str!`, así que
//! el test no depende del directorio de trabajo.

#![expect(
    clippy::indexing_slicing,
    reason = "parser JSONL de test con índices acotados por construcción"
)]

use std::collections::BTreeMap;

use soporte::ParametrosSector;
use soporte::generadores::{ResultadoCaso, TIPOS, VECTORES_RECHAZO, generar, validar_caso};

mod soporte;

const S03_144: &str = include_str!("../../../testdata/registro-sectores-sr0/s03-144.jsonl");
const RECHAZO: &str =
    include_str!("../../../testdata/registro-sectores-sr0/rechazo-contrato.jsonl");

/// Valor JSON mínimo.
#[derive(Clone, Debug)]
enum Valor {
    Texto(String),
    Entero(i64),
    Booleano(bool),
}

impl Valor {
    fn texto(&self) -> &str {
        match self {
            Self::Texto(s) => s,
            _ => "",
        }
    }
    fn entero(&self) -> i64 {
        match self {
            Self::Entero(n) => *n,
            _ => 0,
        }
    }
    fn booleano(&self) -> bool {
        matches!(self, Self::Booleano(true))
    }
}

/// Parser JSON de una línea con objetos planos `{"k": "v", "n": 1, "b": true}`.
fn parse_objeto(linea: &str) -> BTreeMap<String, Valor> {
    let b: Vec<char> = linea.chars().collect();
    let mut i = 0usize;
    let mut out = BTreeMap::new();
    let siguiente = |i: &mut usize| {
        while *i < b.len() && b[*i].is_whitespace() {
            *i += 1;
        }
    };
    siguiente(&mut i);
    if i < b.len() && b[i] == '{' {
        i += 1;
    }
    loop {
        siguiente(&mut i);
        if i >= b.len() || b[i] == '}' {
            break;
        }
        // clave
        if b[i] != '"' {
            break;
        }
        i += 1;
        let mut clave = String::new();
        while i < b.len() && b[i] != '"' {
            if b[i] == '\\' && i + 1 < b.len() {
                i += 1;
            }
            clave.push(b[i]);
            i += 1;
        }
        i += 1; // cierra comilla
        siguiente(&mut i);
        if i < b.len() && b[i] == ':' {
            i += 1;
        }
        siguiente(&mut i);
        // valor
        let valor = if i < b.len() && b[i] == '"' {
            i += 1;
            let mut s = String::new();
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' && i + 1 < b.len() {
                    i += 1;
                }
                s.push(b[i]);
                i += 1;
            }
            i += 1;
            Valor::Texto(s)
        } else if linea_restante_es_booleano(&b, i) {
            let s: String = b[i..].iter().collect();
            if s.starts_with("true") {
                i += 4;
                Valor::Booleano(true)
            } else {
                i += 5;
                Valor::Booleano(false)
            }
        } else {
            let inicio = i;
            while i < b.len() && (b[i] == '-' || b[i].is_ascii_digit()) {
                i += 1;
            }
            let s: String = b[inicio..i].iter().collect();
            Valor::Entero(s.parse::<i64>().unwrap_or(0))
        };
        out.insert(clave, valor);
        siguiente(&mut i);
        if i < b.len() && b[i] == ',' {
            i += 1;
        }
    }
    out
}

fn linea_restante_es_booleano(b: &[char], i: usize) -> bool {
    let s: String = b[i..].iter().take(5).collect();
    s.starts_with("true") || s.starts_with("false")
}

fn filas(texto: &str) -> Vec<BTreeMap<String, Valor>> {
    texto
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(parse_objeto)
        .collect()
}

fn comparar_caso(
    rec: &BTreeMap<String, Valor>,
    p: &ParametrosSector,
) -> (bool, ResultadoCaso, String) {
    let tipo = rec.get("tipo").map(Valor::texto).unwrap_or("");
    let r = validar_caso(&generar(tipo, p), p);
    let mut fallos = Vec::new();
    let mut comprobar = |campo: &str, esperado: i64, obtenido: i64| {
        if esperado != obtenido {
            fallos.push(format!("{campo}: {esperado}≠{obtenido}"));
        }
    };
    comprobar(
        "n_bloques",
        rec.get("n_bloques").map_or(0, Valor::entero),
        r.n_bloques as i64,
    );
    comprobar(
        "n_sectores",
        rec.get("n_sectores").map_or(0, Valor::entero),
        r.n_sectores as i64,
    );
    comprobar(
        "n_ops",
        rec.get("n_ops").map_or(0, Valor::entero),
        r.n_ops as i64,
    );
    comprobar(
        "n_descartes",
        rec.get("n_descartes").map_or(0, Valor::entero),
        r.n_descartes as i64,
    );
    let ok_esperado = rec.get("ok").is_some_and(Valor::booleano);
    if ok_esperado != r.ok {
        fallos.push(format!(
            "ok: {ok_esperado}≠{} ({:?})",
            r.ok,
            r.propiedades
                .iter()
                .filter(|(_, v)| !v)
                .map(|(k, _)| *k)
                .collect::<Vec<_>>()
        ));
    }
    (fallos.is_empty(), r, fallos.join("; "))
}

#[test]
fn diferencial_168_vectores() {
    let p = ParametrosSector::fixture();

    // ── 144 de S03 ──
    let s03 = filas(S03_144);
    assert_eq!(s03.len(), 144, "s03-144.jsonl debe tener 144 líneas");
    let mut s03_ok = 0usize;
    let mut fallos = Vec::new();
    for rec in &s03 {
        let (bien, _r, msg) = comparar_caso(rec, &p);
        if bien {
            s03_ok += 1;
        } else {
            let id = rec.get("id").map(Valor::texto).unwrap_or("");
            fallos.push(format!("{id}: {msg}"));
        }
    }

    // ── 24 de rechazo ──
    let rechazo = filas(RECHAZO);
    assert_eq!(
        rechazo.len(),
        24,
        "rechazo-contrato.jsonl debe tener 24 líneas"
    );
    let mut rec_ok = 0usize;
    let mut cobertura = Vec::new();
    for rec in &rechazo {
        let id = rec.get("id").map(Valor::texto).unwrap_or("");
        let esperado = rec.get("esperado").map(Valor::texto).unwrap_or("");
        let Some(v) = VECTORES_RECHAZO.iter().find(|v| v.id == id) else {
            fallos.push(format!("{id}: vector desconocido"));
            continue;
        };
        let observado = soporte::generadores::evaluar_vector(v, &p);
        let bien = observado == esperado;
        if bien {
            rec_ok += 1;
        } else {
            fallos.push(format!(
                "{id} ({}): esperado {esperado}, observado {observado}",
                v.regla
            ));
        }
        cobertura.push(format!(
            "| {} | {} | {} | {} | {} |",
            v.regla,
            v.id,
            esperado,
            observado,
            if bien { "sí" } else { "NO" }
        ));
    }

    // ── tabla por tipo ──
    let mut tabla = Vec::new();
    for tipo in TIPOS {
        let mut n = 0usize;
        let mut ok = 0usize;
        let mut bl = 0i64;
        let mut sec = 0i64;
        let mut ops = 0i64;
        for rec in &s03 {
            if rec.get("tipo").map(Valor::texto) != Some(tipo) {
                continue;
            }
            n += 1;
            let (bien, r, _) = comparar_caso(rec, &p);
            if bien {
                ok += 1;
            }
            bl = bl.max(rec.get("n_bloques").map_or(0, Valor::entero));
            sec = sec.max(rec.get("n_sectores").map_or(0, Valor::entero));
            ops = ops.max(rec.get("n_ops").map_or(0, Valor::entero));
            let _ = r;
        }
        tabla.push(format!("| {tipo} | {n} | {ok} | {bl} | {sec} | {ops} |"));
    }

    eprintln!("=== V2 · cobertura por regla (rechazos) ===");
    for l in &cobertura {
        eprintln!("{l}");
    }
    eprintln!("=== V2 · cobertura S03 por tipo ===");
    eprintln!("| tipo | casos | ok | bloques(máx) | sectores(máx) | ops(máx) |");
    for l in &tabla {
        eprintln!("{l}");
    }
    eprintln!(
        "V2 · S03 {s03_ok}/144; rechazo {rec_ok}/24; total {}/168",
        s03_ok + rec_ok
    );

    assert!(fallos.is_empty(), "V2 fallos:\n{}", fallos.join("\n"));
    assert_eq!(s03_ok, 144, "S03 no reproduce 144/144");
    assert_eq!(rec_ok, 24, "rechazo no reproduce 24/24");
}
