//! Comparación contra el **oráculo independiente GDR-v0.2 en Julia**.
//!
//! El fichero `testdata/ghostdag-rank-v1/corpus-rust.txt` es la copia sin cambios del
//! `veritas/consenso/ghostdag-rank-v1/resultados/corpus-rust.txt` del commit `9681061`, que lo
//! escribió `volcar_corpus.jl` ejecutando GDR-v0.2 (ver `PROCEDENCIA.md`). Ninguna línea la
//! produce Rust: si el fichero falta, el test **MUST fallar**, no degradarse a "sin verificar".
//!
//! Se comprueban las dos implementaciones —referencia y kernel— contra el mismo volcado, y
//! por separado los vectores oficiales de rusty-kaspa (`kaspa-rust.txt`, modo SP_KASPA /
//! MERGE_KASPA, U2/U3 off).

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::panic,
    reason = "el test falla ruidosamente si el oráculo no existe"
)]
#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio test"
)]

use std::collections::HashMap;
use std::path::PathBuf;

use primitive_types::U256;
use zx_dag::RangoSolucionValidado;
use zx_dag::ghostdag::{
    Algoritmo, AlmacenGhostdag, BloqueGhostdag, Color, IdentidadGhostdag, Idx, ModoMerge, ModoSp,
    Parametros, hash_de_id_textual,
};

#[derive(Debug)]
struct Spec {
    id: String,
    padres: Vec<String>,
    slot: u64,
    sd: u64,
    sr: u64,
    ident: u64,
}

#[derive(Debug, Default)]
struct Esperado {
    sp: Option<String>,
    score: u64,
    bw: U256,
    ms: Vec<String>,
    blues: Vec<String>,
    reds: Vec<String>,
    colores: Vec<(String, u8)>,
    rank: Option<(U256, u64, String)>,
}

#[derive(Debug)]
struct Dag {
    etiqueta: String,
    k: u32,
    u2: bool,
    u3: bool,
    specs: Vec<Spec>,
    esperados: Vec<Esperado>,
}

fn ruta(relativa: &[&str]) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    for r in relativa {
        p.push(r);
    }
    p
}

fn leer(relativa: &[&str]) -> String {
    let p = ruta(relativa);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "no se pudo leer el volcado del oráculo Julia en {}: {e}. Este test MUST fallar, no \
             degradarse (ver testdata/ghostdag-rank-v1/PROCEDENCIA.md).",
            p.display()
        )
    })
}

fn campos(linea: &str) -> (String, HashMap<String, String>) {
    let mut it = linea.split_whitespace();
    let _marca = it.next();
    let id = it.next().unwrap_or_default().to_string();
    let mut mapa = HashMap::new();
    for resto in it {
        if let Some((k, v)) = resto.split_once('=') {
            mapa.insert(k.to_string(), v.to_string());
        }
    }
    (id, mapa)
}

fn lista(csv: &str) -> Vec<String> {
    if csv.is_empty() {
        Vec::new()
    } else {
        csv.split(',').map(str::to_string).collect()
    }
}

fn parsear_corpus(texto: &str) -> Vec<Dag> {
    let mut dags: Vec<Dag> = Vec::new();
    let mut actual: Option<Dag> = None;
    for linea in texto.lines() {
        if linea.starts_with('#') || linea.trim().is_empty() {
            continue;
        }
        if linea.starts_with("DAG ") || linea.starts_with("DAGK ") {
            if let Some(d) = actual.take() {
                dags.push(d);
            }
            let partes: Vec<&str> = linea.split_whitespace().skip(1).collect();
            let etiqueta = partes.first().copied().unwrap_or("").to_string();
            let k = partes
                .iter()
                .find_map(|p| p.strip_prefix("k="))
                .and_then(|v| v.parse().ok())
                .unwrap_or(30);
            let u2 = partes.contains(&"u2=1");
            let u3 = partes.contains(&"u3=2");
            actual = Some(Dag {
                etiqueta,
                k,
                u2,
                u3,
                specs: Vec::new(),
                esperados: Vec::new(),
            });
        } else if linea.starts_with("B ") {
            let (id, m) = campos(linea);
            let d = actual.as_mut().unwrap();
            d.specs.push(Spec {
                id,
                padres: lista(m.get("padres").map(String::as_str).unwrap_or("")),
                slot: m.get("slot").map(|v| v.parse().unwrap()).unwrap_or(0),
                sd: m.get("sd").map(|v| v.parse().unwrap()).unwrap_or(0),
                sr: m.get("sr").map(|v| v.parse().unwrap()).unwrap_or(0),
                ident: m.get("ident").map(|v| v.parse().unwrap()).unwrap_or(0),
            });
        } else if linea.starts_with("E ") {
            let (_id, m) = campos(linea);
            let rank = m.get("rank").map(|v| {
                let partes: Vec<&str> = v.split(':').collect();
                (
                    U256::from_dec_str(partes[0]).unwrap(),
                    partes[1].parse().unwrap(),
                    partes[2].to_string(),
                )
            });
            let colores = m
                .get("colores")
                .map(|v| {
                    lista(v)
                        .into_iter()
                        .filter_map(|c| {
                            c.split_once('=')
                                .map(|(id, t)| (id.to_string(), t.parse().unwrap()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let sp = m.get("sp").and_then(|v| (v != "-").then(|| v.to_string()));
            let d = actual.as_mut().unwrap();
            d.esperados.push(Esperado {
                sp,
                score: m.get("score").map(|v| v.parse().unwrap()).unwrap_or(0),
                bw: U256::from_dec_str(m.get("bw").map(String::as_str).unwrap_or("0")).unwrap(),
                ms: lista(m.get("ms").map(String::as_str).unwrap_or("")),
                blues: lista(m.get("blues").map(String::as_str).unwrap_or("")),
                reds: lista(m.get("reds").map(String::as_str).unwrap_or("")),
                colores,
                rank,
            });
        } else if linea == "END"
            && let Some(d) = actual.take()
        {
            dags.push(d);
        }
    }
    if let Some(d) = actual.take() {
        dags.push(d);
    }
    dags
}

fn construir_dag(dag: &Dag, params: Parametros, algoritmo: Algoritmo) -> AlmacenGhostdag {
    let g = dag.specs.first().expect("toda DAG tiene raíz");
    let raiz = hash_de_id_textual(&g.id);
    let mut almacen = AlmacenGhostdag::nuevo(
        params,
        algoritmo,
        raiz,
        g.slot,
        RangoSolucionValidado::para_oraculos(g.sr),
        g.ident,
    );
    for spec in dag.specs.iter().skip(1) {
        let bloque = BloqueGhostdag {
            id: hash_de_id_textual(&spec.id),
            padres: spec.padres.iter().map(|p| hash_de_id_textual(p)).collect(),
            slot: spec.slot,
            solution_distance: spec.sd,
            rango_espacio: RangoSolucionValidado::para_oraculos(spec.sr),
            identidad: IdentidadGhostdag::de_fixture(spec.ident),
        };
        almacen
            .anadir_sintetico(bloque)
            .unwrap_or_else(|e| panic!("DAG {} rechaza {}: {e}", dag.etiqueta, spec.id));
    }
    almacen
}

fn ids_a_indices(_almacen: &AlmacenGhostdag, ids: &[String], dag: &Dag) -> Vec<Idx> {
    let mut mapa: HashMap<String, Idx> = HashMap::new();
    for (i, spec) in dag.specs.iter().enumerate() {
        mapa.insert(spec.id.clone(), i as Idx);
    }
    ids.iter()
        .map(|id| {
            *mapa
                .get(id)
                .unwrap_or_else(|| panic!("id desconocido {id}"))
        })
        .collect()
}

fn comprobar_dag(dag: &Dag, algoritmo: Algoritmo) {
    let params = Parametros {
        k: dag.k,
        u2: dag.u2,
        u3_dinamica: dag.u3,
        sp: ModoSp::Zerox,
        merge: ModoMerge::Terna,
        ..Parametros::default()
    };
    let almacen = construir_dag(dag, params, algoritmo);
    for (i, exp) in dag.esperados.iter().enumerate() {
        let idx = i as Idx;
        let gd = almacen.datos(idx).expect("dato GHOSTDAG");
        let sp_esp = exp
            .sp
            .as_ref()
            .map(|s| ids_a_indices(&almacen, std::slice::from_ref(s), dag)[0]);
        assert_eq!(
            gd.sp, sp_esp,
            "DAG {} bloque {} ({:?}): sp",
            dag.etiqueta, i, dag.specs[i].id
        );
        assert_eq!(
            gd.blue_score, exp.score,
            "DAG {} bloque {}: blue_score",
            dag.etiqueta, i
        );
        assert_eq!(
            gd.blue_work, exp.bw,
            "DAG {} bloque {}: blue_work",
            dag.etiqueta, i
        );
        assert_eq!(
            gd.orden_mergeset,
            ids_a_indices(&almacen, &exp.ms, dag),
            "DAG {} bloque {}: mergeset ordenado",
            dag.etiqueta,
            i
        );
        assert_eq!(
            gd.blues,
            ids_a_indices(&almacen, &exp.blues, dag),
            "DAG {} bloque {}: blues",
            dag.etiqueta,
            i
        );
        assert_eq!(
            gd.rojos,
            ids_a_indices(&almacen, &exp.reds, dag),
            "DAG {} bloque {}: reds",
            dag.etiqueta,
            i
        );
        // Colores de los rojos.
        for (id, tipo) in &exp.colores {
            let cand = ids_a_indices(&almacen, std::slice::from_ref(id), dag)[0];
            let color = almacen.color_en(idx, cand).expect("color del rojo");
            let esperado = if *tipo == 2 {
                Color::RojoU3
            } else {
                Color::RojoK
            };
            assert_eq!(
                color, esperado,
                "DAG {} bloque {}: color de {id}",
                dag.etiqueta, i
            );
        }
        // rank.
        if let Some((bw, sd, id)) = &exp.rank {
            let r = almacen.rank(idx).expect("rank");
            assert_eq!(r.blue_work, *bw, "DAG {} bloque {i}: rank.bw", dag.etiqueta);
            assert_eq!(
                r.solution_distance, *sd,
                "DAG {} bloque {i}: rank.sd",
                dag.etiqueta
            );
            assert_eq!(
                r.id,
                hash_de_id_textual(id),
                "DAG {} bloque {i}: rank.id",
                dag.etiqueta
            );
        }
    }
}

#[test]
fn la_referencia_rust_coincide_con_gdr_v0_2() {
    let texto = leer(&["testdata", "ghostdag-rank-v1", "corpus-rust.txt"]);
    let dags = parsear_corpus(&texto);
    assert!(!dags.is_empty(), "el corpus del oráculo está vacío");
    for dag in &dags {
        comprobar_dag(dag, Algoritmo::Referencia);
    }
    eprintln!("referencia Rust = GDR-v0.2 en {} DAGs", dags.len());
}

#[test]
fn el_kernel_rust_coincide_con_gdr_v0_2() {
    let texto = leer(&["testdata", "ghostdag-rank-v1", "corpus-rust.txt"]);
    let dags = parsear_corpus(&texto);
    assert!(!dags.is_empty(), "el corpus del oráculo está vacío");
    for dag in &dags {
        comprobar_dag(dag, Algoritmo::Kernel);
    }
    eprintln!("kernel Rust = GDR-v0.2 en {} DAGs", dags.len());
}

#[test]
fn los_vectores_de_rusty_kaspa_pasan() {
    let texto = leer(&["testdata", "ghostdag-rank-v1", "kaspa-rust.txt"]);
    let dags = parsear_corpus(&texto);
    assert!(!dags.is_empty(), "el volcado de Kaspa está vacío");
    let mut bloques = 0usize;
    for dag in &dags {
        let params = Parametros {
            k: dag.k,
            u2: false,
            u3_dinamica: false,
            sp: ModoSp::Kaspa,
            merge: ModoMerge::Kaspa,
            ..Parametros::default()
        };
        for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
            let almacen = construir_dag(dag, params, algoritmo);
            for (i, exp) in dag.esperados.iter().enumerate() {
                let idx = i as Idx;
                let gd = almacen.datos(idx).unwrap();
                let sp_esp = exp
                    .sp
                    .as_ref()
                    .map(|s| ids_a_indices(&almacen, std::slice::from_ref(s), dag)[0]);
                assert_eq!(gd.sp, sp_esp, "kaspa {} sp", dag.etiqueta);
                assert_eq!(gd.blue_score, exp.score, "kaspa {} score", dag.etiqueta);
                assert_eq!(
                    gd.blues,
                    ids_a_indices(&almacen, &exp.blues, dag),
                    "kaspa {} blues",
                    dag.etiqueta
                );
                assert_eq!(
                    gd.rojos,
                    ids_a_indices(&almacen, &exp.reds, dag),
                    "kaspa {} reds",
                    dag.etiqueta
                );
                bloques += 1;
            }
        }
    }
    eprintln!("vectores Kaspa: {bloques} comprobaciones");
}
