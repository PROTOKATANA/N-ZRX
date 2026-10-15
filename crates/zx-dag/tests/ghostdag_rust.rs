//! Pruebas Rust de GHOSTDAG y `rank`.
//!
//! Cubren: referencia vs kernel sobre DAGs generados, determinismo con ≥ 1000 órdenes de
//! llegada, desbordamiento de `blue_work`, límites de R-FIN-12, ancestría, totalidad de
//! `rank`, la decisión C (hermanos y copias) y `ContextoDag` real contra
//! `comprobar_padres_contextual` con la raíz en el terminal (D-P07/D-P08).

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
#![expect(clippy::panic, reason = "el test falla ruidosamente")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio test"
)]

use std::collections::HashMap;

use primitive_types::U256;
use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
use zx_core::{ClavePublica, DagBlockHeader, PadresDag, SolucionPoas};
use zx_dag::ContextoDag;
use zx_dag::ErrorDag;
use zx_dag::RangoSolucionValidado;
use zx_dag::bloque_dag::{CandidatoSinRango, ContextoRangoDag, comprobar_padres_contextual};
use zx_dag::ghostdag::{
    Algoritmo, AlmacenGhostdag, BloqueGhostdag, Color, DatosGhostdag, IdentidadGhostdag, Idx,
    ModoMerge, ModoSp, Parametros, Rank, hash_de_id_textual, peso, sumar_blue_work,
};
use zx_dag::{IdentidadTicket, identidad_de_cabecera};

// ─────────────────────────────────────────────────────────────────────────────
// Generador determinista de DAGs (semilla fija en el código).
// ─────────────────────────────────────────────────────────────────────────────

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

#[derive(Clone)]
struct Nodo {
    id: BlockHash,
    padres: Vec<usize>,
    slot: u64,
    sd: u64,
    sr: u64,
    ident: u64,
}

fn generar(n: usize, ventana: usize, semilla: u64) -> Vec<Nodo> {
    let mut rng = Azar::nuevo(semilla);
    let mut nodos = vec![Nodo {
        id: hash_de_id_textual("G"),
        padres: Vec::new(),
        slot: 0,
        sd: 0,
        sr: 0,
        ident: 0,
    }];
    for i in 1..n {
        let mut ident = 0u64;
        let mut padres_fijados: Option<Vec<usize>> = None;
        if i % 8 == 0 {
            ident = i as u64;
        } else if i % 8 == 1 && nodos[i - 1].ident != 0 {
            ident = nodos[i - 1].ident;
            padres_fijados = Some(nodos[i - 1].padres.clone());
        }
        let tiene_fijados = padres_fijados.is_some();
        let padres = if let Some(p) = padres_fijados.clone() {
            p
        } else {
            // 0-based: los candidatos van de `lo` a `i-1` (la raíz es 0).
            let lo = i.saturating_sub(ventana);
            let npadres = (i - lo).min(1 + rng.rango(0, 3) as usize);
            let mut elegidos: Vec<usize> = Vec::new();
            while elegidos.len() < npadres {
                let p = lo + rng.rango(0, (i - lo - 1) as u64) as usize;
                if !elegidos.contains(&p) {
                    elegidos.push(p);
                }
            }
            elegidos
        };
        let max_slot = padres.iter().map(|p| nodos[*p].slot).max().unwrap_or(0);
        let slot = max_slot + rng.rango(0, 2);
        let sr = match rng.rango(0, 4) {
            0 => 0,
            1 => 1,
            2 => u64::MAX - 1,
            3 => u64::MAX,
            _ => rng.rango(0, i64::MAX as u64),
        };
        let sd = if tiene_fijados && i >= 1 {
            nodos[i - 1].sd
        } else {
            rng.rango(0, 1 << 20)
        };
        nodos.push(Nodo {
            id: hash_de_id_textual(&format!("B{i}")),
            padres,
            slot,
            sd,
            sr,
            ident,
        });
    }
    nodos
}

fn orden_topologico(rng: &mut Azar, nodos: &[Nodo]) -> Vec<usize> {
    let n = nodos.len();
    let mut entregados = vec![false; n];
    let mut orden = Vec::with_capacity(n);
    entregados[0] = true;
    orden.push(0);
    while orden.len() < n {
        let disponibles: Vec<usize> = (1..n)
            .filter(|i| !entregados[*i] && nodos[*i].padres.iter().all(|p| entregados[*p]))
            .collect();
        if disponibles.is_empty() {
            panic!("el DAG no es acíclico");
        }
        let e = disponibles[rng.rango(0, (disponibles.len() - 1) as u64) as usize];
        entregados[e] = true;
        orden.push(e);
    }
    orden
}

fn entregar(
    nodos: &[Nodo],
    orden: &[usize],
    params: Parametros,
    algoritmo: Algoritmo,
) -> AlmacenGhostdag {
    let mut almacen = AlmacenGhostdag::nuevo(
        params,
        algoritmo,
        nodos[0].id,
        nodos[0].slot,
        RangoSolucionValidado::para_oraculos(nodos[0].sr),
        nodos[0].ident,
    );
    let mut mapa: HashMap<usize, Idx> = HashMap::new();
    mapa.insert(0, 0);
    for spec_idx in orden.iter().skip(1) {
        let nodo = &nodos[*spec_idx];
        let padres = nodo.padres.iter().map(|p| nodos[*p].id).collect();
        let idx = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: nodo.id,
                padres,
                slot: nodo.slot,
                solution_distance: nodo.sd,
                rango_espacio: RangoSolucionValidado::para_oraculos(nodo.sr),
                identidad: IdentidadGhostdag::de_fixture(nodo.ident),
            })
            .unwrap_or_else(|e| panic!("DAG válido rechazado: {e}"));
        mapa.insert(*spec_idx, idx);
    }
    almacen
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Proy {
    sp: Option<usize>,
    ms: Vec<usize>,
    blues: Vec<usize>,
    rojos: Vec<usize>,
    colores: Vec<(usize, u8)>,
    score: u64,
    bw: U256,
}

fn proyeccion(almacen: &AlmacenGhostdag, nodos: &[Nodo]) -> Vec<Proy> {
    let mut hash_a_spec: HashMap<BlockHash, usize> = HashMap::new();
    for (i, n) in nodos.iter().enumerate() {
        hash_a_spec.insert(n.id, i);
    }
    let mut idx_a_spec: HashMap<Idx, usize> = HashMap::new();
    for idx in 0..almacen.len() as Idx {
        let h = almacen.id(idx).unwrap();
        idx_a_spec.insert(idx, hash_a_spec[&h]);
    }
    // Indexado por índice de nodo (spec), no por índice del almacén: dos órdenes de llegada
    // distintos dan índices de almacén distintos para el mismo bloque.
    let mut salida: Vec<Option<Proy>> = vec![None; nodos.len()];
    for idx in 0..almacen.len() as Idx {
        let gd = almacen.datos(idx).unwrap();
        let conv = |v: &[Idx]| v.iter().map(|x| idx_a_spec[x]).collect::<Vec<_>>();
        let proy = Proy {
            sp: gd.sp.map(|s| idx_a_spec[&s]),
            ms: conv(&gd.orden_mergeset),
            blues: conv(&gd.blues),
            rojos: conv(&gd.rojos),
            colores: gd
                .colores
                .iter()
                .map(|(c, color)| (idx_a_spec[c], if *color == Color::RojoU3 { 2 } else { 1 }))
                .collect(),
            score: gd.blue_score,
            bw: gd.blue_work,
        };
        salida[idx_a_spec[&idx]] = Some(proy);
    }
    salida
        .into_iter()
        .map(|x| x.expect("todo nodo fue entregado"))
        .collect()
}

fn params_regla_c() -> Parametros {
    Parametros {
        sp: ModoSp::Zerox,
        merge: ModoMerge::Terna,
        ..Parametros::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1 · Referencia vs kernel
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn referencia_y_kernel_coinciden_en_dags_generados() {
    let mut choques = 0usize;
    for semilla in 0..60u64 {
        let n = 4 + (semilla as usize * 7) % 80;
        let ventana = 1 + (semilla as usize % 8) * 4;
        let nodos = generar(n, ventana, 0xD1F_F000 + semilla);
        let a = entregar(
            &nodos,
            &(0..n).collect::<Vec<_>>(),
            params_regla_c(),
            Algoritmo::Referencia,
        );
        let b = entregar(
            &nodos,
            &(0..n).collect::<Vec<_>>(),
            params_regla_c(),
            Algoritmo::Kernel,
        );
        if proyeccion(&a, &nodos) != proyeccion(&b, &nodos) {
            choques += 1;
        }
    }
    assert_eq!(choques, 0, "referencia y kernel divergen en {choques} DAGs");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2 · Determinismo (C-GD-09): ≥ 1000 órdenes de llegada
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn determinismo_con_mil_ordenes_de_llegada() {
    for familia in 0..3u64 {
        let n = 120;
        let ventana = if familia == 0 { 6 } else { 30 };
        let nodos = generar(n, ventana, 0x6D60 + familia);
        let mut rng = Azar::nuevo(0xA11CE + familia);
        let base = proyeccion(
            &entregar(
                &nodos,
                &(0..n).collect::<Vec<_>>(),
                params_regla_c(),
                Algoritmo::Kernel,
            ),
            &nodos,
        );
        for ronda in 0..1000 {
            let orden = orden_topologico(&mut rng, &nodos);
            let est = entregar(&nodos, &orden, params_regla_c(), Algoritmo::Kernel);
            assert_eq!(
                proyeccion(&est, &nodos),
                base,
                "determinismo roto en familia {familia}, ronda {ronda}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3 · Desbordamiento de blue_work (C-GD-02)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn desbordamiento_de_blue_work_es_error_explicito() {
    assert_eq!(
        sumar_blue_work(U256::MAX, U256::one()),
        Err(ErrorDag::BlueWorkDesbordado)
    );
    assert_eq!(sumar_blue_work(U256::MAX, U256::zero()), Ok(U256::MAX));
}

#[test]
fn peso_fronteras() {
    // SR=0 → 2^128; SR=2^64−1 → 2^64.
    assert_eq!(peso(0), U256::one() << 128usize);
    assert_eq!(peso(u64::MAX), U256::one() << 64usize);
    for sr in [0u64, 1, 2, 1 << 32, u64::MAX - 1, u64::MAX] {
        assert!(peso(sr) >= (U256::one() << 64usize));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4 · Límites de R-FIN-12 (C-GD-04)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quince_padres_se_aceptan_y_dieciseis_se_rechazan() {
    let mut almacen = AlmacenGhostdag::nuevo(
        params_regla_c(),
        Algoritmo::Kernel,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    for i in 1..=16 {
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual(&format!("P{i}")),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 1,
                rango_espacio: RangoSolucionValidado::para_oraculos(i),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
    }
    let quince: Vec<BlockHash> = (1..=15)
        .map(|i| hash_de_id_textual(&format!("P{i}")))
        .collect();
    let dieciseis: Vec<BlockHash> = (1..=16)
        .map(|i| hash_de_id_textual(&format!("P{i}")))
        .collect();
    assert!(
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("A"),
                padres: quince,
                slot: 1,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(0),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .is_ok()
    );
    assert_eq!(
        almacen.anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("B"),
            padres: dieciseis,
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(0),
            identidad: IdentidadGhostdag::SinBillete,
        }),
        Err(ErrorDag::DemasiadosPadresDag {
            declarados: 16,
            maximo: 15,
        })
    );
}

/// Brazo con dos cadenas desde la raíz: la segunda aporta el mergeset del bloque de unión.
fn construir_brazo(largo_p: usize, largo_q: usize) -> AlmacenGhostdag {
    let mut almacen = AlmacenGhostdag::nuevo(
        params_regla_c(),
        Algoritmo::Kernel,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    let mut anterior_p = hash_de_id_textual("G");
    for i in 1..=largo_p {
        let id = hash_de_id_textual(&format!("P{i}"));
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id,
                padres: vec![anterior_p],
                slot: i as u64,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(100),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        anterior_p = id;
    }
    let mut anterior_q = hash_de_id_textual("G");
    for i in 1..=largo_q {
        let id = hash_de_id_textual(&format!("Q{i}"));
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id,
                padres: vec![anterior_q],
                slot: i as u64,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(100),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        anterior_q = id;
    }
    almacen
}

#[test]
fn bordes_exactos_de_mergeset_180_y_181() {
    // 179 bloques en la cadena Q ⇒ |mergeset| = 179 ⇒ +1 = 180: se acepta.
    let mut acepta = construir_brazo(180, 179);
    let ok = acepta.anadir_sintetico(BloqueGhostdag {
        id: hash_de_id_textual("U"),
        padres: vec![hash_de_id_textual("P180"), hash_de_id_textual("Q179")],
        slot: 180,
        solution_distance: 0,
        rango_espacio: RangoSolucionValidado::para_oraculos(100),
        identidad: IdentidadGhostdag::SinBillete,
    });
    assert!(ok.is_ok(), "180 debe aceptarse: {ok:?}");

    // 180 bloques en Q ⇒ |mergeset| = 180 ⇒ +1 = 181: se rechaza.
    let mut rechaza = construir_brazo(180, 180);
    assert_eq!(
        rechaza.anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("V"),
            padres: vec![hash_de_id_textual("P180"), hash_de_id_textual("Q180")],
            slot: 180,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(100),
            identidad: IdentidadGhostdag::SinBillete,
        }),
        Err(ErrorDag::MergesetExcedeLimite {
            tamano: 181,
            maximo: 180,
        })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5 · Ancestralidad y totalidad de rank (C-ORD-01)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn todo_padre_tiene_menor_rank_que_su_hijo() {
    for semilla in 0..40u64 {
        let n = 20 + (semilla as usize * 3) % 60;
        let nodos = generar(n, 6, 0xA5CE + semilla);
        let almacen = entregar(
            &nodos,
            &(0..n).collect::<Vec<_>>(),
            params_regla_c(),
            Algoritmo::Kernel,
        );
        for idx in 0..almacen.len() as Idx {
            let r = almacen.rank(idx).unwrap();
            for p in almacen.padres_de(idx).unwrap() {
                assert!(almacen.rank(*p).unwrap() < r, "padre con rank >= hijo");
            }
        }
    }
}

#[test]
fn rank_es_total_sobre_el_corpus() {
    for semilla in 0..20u64 {
        let n = 40 + (semilla as usize * 5) % 80;
        let nodos = generar(n, 30, 0x70A1 + semilla);
        let almacen = entregar(
            &nodos,
            &(0..n).collect::<Vec<_>>(),
            params_regla_c(),
            Algoritmo::Kernel,
        );
        let mut ranques: Vec<Rank> = (0..almacen.len() as Idx)
            .map(|idx| almacen.rank(idx).unwrap())
            .collect();
        ranques.sort();
        ranques.dedup();
        assert_eq!(
            ranques.len(),
            almacen.len(),
            "rank no es total en el DAG de semilla {semilla}: hay tuplas repetidas"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6 · Decisión C: hermanos y copias de billete (C-GD-03, C-ORD-02)
// ─────────────────────────────────────────────────────────────────────────────

fn almacen_hermanos() -> (AlmacenGhostdag, BlockHash) {
    let mut almacen = AlmacenGhostdag::nuevo(
        params_regla_c(),
        Algoritmo::Kernel,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    // Hermana 1: menor id, mismo bw y sd.
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("A1"),
            padres: vec![hash_de_id_textual("G")],
            slot: 1,
            solution_distance: 7,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    // Hermana 2: mismo bw y sd, id mayor.
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("A2"),
            padres: vec![hash_de_id_textual("G")],
            slot: 1,
            solution_distance: 7,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    (almacen, hash_de_id_textual("G"))
}

#[test]
fn sp_empatado_en_bw_y_sd_elige_el_menor_id() {
    let (mut almacen, g) = almacen_hermanos();
    let c = almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("C"),
            padres: vec![hash_de_id_textual("A2"), hash_de_id_textual("A1")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    let sp = almacen.datos(c).unwrap().sp.unwrap();
    assert_eq!(almacen.id(sp).unwrap(), hash_de_id_textual("A1"));
    let _ = g;
}

#[test]
fn sp_empatado_en_bw_elige_el_menor_sd() {
    let mut almacen = AlmacenGhostdag::nuevo(
        params_regla_c(),
        Algoritmo::Kernel,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    for (id, sd) in [("A1", 9u64), ("A2", 3u64)] {
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual(id),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: sd,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
    }
    let c = almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("C"),
            padres: vec![hash_de_id_textual("A1"), hash_de_id_textual("A2")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    let sp = almacen.datos(c).unwrap().sp.unwrap();
    assert_eq!(almacen.id(sp).unwrap(), hash_de_id_textual("A2"));
}

#[test]
fn sp_elige_el_mayor_blue_work() {
    let mut almacen = AlmacenGhostdag::nuevo(
        params_regla_c(),
        Algoritmo::Kernel,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("A"),
            padres: vec![hash_de_id_textual("G")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("B"),
            padres: vec![hash_de_id_textual("A")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    let c = almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("C"),
            padres: vec![hash_de_id_textual("A"), hash_de_id_textual("B")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    let sp = almacen.datos(c).unwrap().sp.unwrap();
    assert_eq!(almacen.id(sp).unwrap(), hash_de_id_textual("B"));
}

#[test]
fn copia_de_billete_direccion_coherente_entre_padres_y_mergeset() {
    let params = Parametros {
        k: 30,
        ..params_regla_c()
    };
    let mut almacen = AlmacenGhostdag::nuevo(
        params,
        Algoritmo::Kernel,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    // A (sin billete) y dos copias s1,s2 del billete 7. A es el sp por tener menor sd.
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("A"),
            padres: vec![hash_de_id_textual("G")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    for id in ["S1", "S2"] {
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual(id),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 5,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Sintetica(7),
            })
            .unwrap();
    }
    // C con A como sp (menor sd) y S1,S2 en el mergeset.
    let c = almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("C"),
            padres: vec![
                hash_de_id_textual("A"),
                hash_de_id_textual("S1"),
                hash_de_id_textual("S2"),
            ],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    // Los dos hermanos van en orden de rank (S1 antes que S2) y el primero queda azul, el
    // segundo rojo_U3; la copia seleccionada es S1, la misma dirección que elegiría el sp.
    let ms: Vec<BlockHash> = almacen
        .datos(c)
        .unwrap()
        .orden_mergeset
        .iter()
        .map(|i| almacen.id(*i).unwrap())
        .collect();
    assert_eq!(ms, vec![hash_de_id_textual("S1"), hash_de_id_textual("S2")]);
    let idx_s1 = almacen
        .datos(c)
        .unwrap()
        .orden_mergeset
        .first()
        .copied()
        .unwrap();
    let idx_s2 = *almacen.datos(c).unwrap().orden_mergeset.get(1).unwrap();
    assert_eq!(almacen.color_en(c, idx_s1), Some(Color::Azul));
    assert_eq!(almacen.color_en(c, idx_s2), Some(Color::RojoU3));
    let ganadora = almacen
        .seleccionar_copia(&[(idx_s1, Color::Azul), (idx_s2, Color::RojoU3)])
        .unwrap();
    assert_eq!(ganadora, idx_s1);
    // Y si las dos fuesen rojo_k (sin copia azul), gana la de menor rank: S1.
    let ganadora_sin_azul = almacen
        .seleccionar_copia(&[(idx_s2, Color::RojoK), (idx_s1, Color::RojoK)])
        .unwrap();
    assert_eq!(ganadora_sin_azul, idx_s1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7 · U2 frente a U3″ (C-GD-07)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn u2_invalida_y_u3_colorea() {
    let mut almacen = AlmacenGhostdag::nuevo(
        params_regla_c(),
        Algoritmo::Kernel,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    // A lleva el billete 7.
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("A"),
            padres: vec![hash_de_id_textual("G")],
            slot: 1,
            solution_distance: 5,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::Sintetica(7),
        })
        .unwrap();
    // S es copia (mismo billete) pero hermana, no descendiente de A: U2 NO la invalida.
    let s = almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("S"),
            padres: vec![hash_de_id_textual("G")],
            slot: 1,
            solution_distance: 5,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::Sintetica(7),
        })
        .unwrap();
    // U2 NO la rechaza: es hermana de A, no descendiente. El bloque existe.
    assert!(almacen.datos(s).is_some());

    // D es descendiente de A: el billete 7 ya está en el pasado estricto de su padre ⇒ U2.
    assert_eq!(
        almacen.anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("D"),
            padres: vec![hash_de_id_textual("A")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::Sintetica(7),
        }),
        Err(ErrorDag::BilleteDuplicadoU2 {
            identidad: IdentidadGhostdag::Sintetica(7),
        })
    );

    // C fusiona A (sp) y S: S no se evalúa contra el k-cluster, queda rojo_U3.
    let c = almacen
        .anadir_sintetico(BloqueGhostdag {
            id: hash_de_id_textual("C"),
            padres: vec![hash_de_id_textual("A"), hash_de_id_textual("S")],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    let idx_s = almacen.datos(c).unwrap().rojos.first().copied().unwrap();
    assert_eq!(almacen.color_en(c, idx_s), Some(Color::RojoU3));
}

// ─────────────────────────────────────────────────────────────────────────────
// 8 · ContextoDag real contra comprobar_padres_contextual (H-04 / D-P08)
// ─────────────────────────────────────────────────────────────────────────────

const CBID: u32 = 0xc478_80ea;

fn cabecera(padres: PadresDag, n: u8) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: CBID,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([n; 32])),
        timestamp: 1_788_480_000 + u64::from(n),
        height: u32::from(n),
        slot: u64::from(n),
        pot_output: [n; 16],
        rango_solucion: 42,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0; 32])),
        padres,
        sello: [0u8; 64],
    }
}

struct Escenario {
    almacen: AlmacenGhostdag,
    h_terminal: DagBlockHeader,
    h_a: DagBlockHeader,
    h_b: DagBlockHeader,
    h_c: DagBlockHeader,
}

fn escenario_dag() -> Escenario {
    escenario_dag_con(Algoritmo::Kernel)
}

/// La raíz del almacén es el terminal `T` (D-P07); `A` es su primer hijo (transición) y `B`
/// desciende de `A`. `C` es hermana de `A` (anticadena con `A`).
fn escenario_dag_con(algoritmo: Algoritmo) -> Escenario {
    let h_terminal = cabecera(PadresDag::genesis(), 0);
    let mut almacen = AlmacenGhostdag::con_raiz_terminal(
        params_regla_c(),
        algoritmo,
        h_terminal.block_hash(),
        RangoSolucionValidado::para_oraculos(0),
    );
    let h_a = cabecera(PadresDag::nuevo(h_terminal.block_hash(), &[]).unwrap(), 1);
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: h_a.block_hash(),
            padres: vec![h_terminal.block_hash()],
            slot: 1,
            solution_distance: 1,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    let h_b = cabecera(PadresDag::nuevo(h_a.block_hash(), &[]).unwrap(), 2);
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: h_b.block_hash(),
            padres: vec![h_a.block_hash()],
            slot: 2,
            solution_distance: 1,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    let h_c = cabecera(PadresDag::nuevo(h_terminal.block_hash(), &[]).unwrap(), 3);
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: h_c.block_hash(),
            padres: vec![h_terminal.block_hash()],
            slot: 1,
            solution_distance: 2,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    Escenario {
        almacen,
        h_terminal,
        h_a,
        h_b,
        h_c,
    }
}

/// **D-P08 · sustituye a `el_genesis_sin_padres_pasa_contra_el_almacen_real`.** Una cabecera PoST
/// con cero padres se rechaza **siempre**, incluso contra el almacén real cuya raíz es el terminal.
#[test]
fn la_cabecera_sin_padres_se_rechaza_contra_el_almacen_real() {
    let esc = escenario_dag();
    assert_eq!(
        comprobar_padres_contextual(&esc.h_terminal, &esc.almacen),
        Err(ErrorDag::CabeceraPostSinPadres)
    );
}

/// **D-P08 · caso nuevo.** La transición válida: `A` es hijo único del terminal `T`.
#[test]
fn la_transicion_valida_con_el_terminal_como_unico_padre_pasa() {
    let esc = escenario_dag();
    assert!(comprobar_padres_contextual(&esc.h_a, &esc.almacen).is_ok());
}

/// **D-P08 · caso nuevo.** `T` como padre adicional junto a un PoST validado se rechaza.
#[test]
fn el_terminal_como_padre_extra_se_rechaza_contra_el_almacen_real() {
    let esc = escenario_dag();
    // Padres A (seleccionado) y T (extra).
    let h = cabecera(
        PadresDag::nuevo(esc.h_a.block_hash(), &[esc.h_terminal.block_hash()]).unwrap(),
        9,
    );
    assert_eq!(
        comprobar_padres_contextual(&h, &esc.almacen),
        Err(ErrorDag::TerminalComoPadreExtra {
            terminal: esc.h_terminal.block_hash(),
        })
    );
}

/// **D-P08 · caso nuevo.** Un padre PoW ajeno (no `T`) se rechaza contra el almacén real.
#[test]
fn un_padre_pow_ajeno_se_rechaza_contra_el_almacen_real() {
    let esc = escenario_dag();
    let ajeno = cabecera(PadresDag::genesis(), 0xEE).block_hash();
    let h = cabecera(PadresDag::nuevo(esc.h_a.block_hash(), &[ajeno]).unwrap(), 9);
    assert_eq!(
        comprobar_padres_contextual(&h, &esc.almacen),
        Err(ErrorDag::PadreNoValidado { padre: ajeno })
    );
}

#[test]
fn un_padre_no_validado_se_rechaza_contra_el_almacen_real() {
    let esc = escenario_dag();
    let impostor: BlockHash = cabecera(PadresDag::genesis(), 0xEE).block_hash();
    let h = cabecera(
        PadresDag::nuevo(esc.h_a.block_hash(), &[impostor]).unwrap(),
        9,
    );
    assert!(matches!(
        comprobar_padres_contextual(&h, &esc.almacen),
        Err(ErrorDag::PadreNoValidado { .. })
    ));
}

#[test]
fn la_anticadena_se_comprueba_contra_el_almacen_real() {
    let esc = escenario_dag();
    // Padres B (seleccionado) y A (extra): A está en el pasado de B.
    let h = cabecera(
        PadresDag::nuevo(esc.h_b.block_hash(), &[esc.h_a.block_hash()]).unwrap(),
        9,
    );
    assert_eq!(
        comprobar_padres_contextual(&h, &esc.almacen),
        Err(ErrorDag::PadresNoAnticadena {
            antepasado: esc.h_a.block_hash(),
            descendiente: esc.h_b.block_hash(),
        })
    );
}

#[test]
fn el_prev_hash_que_no_es_sp_se_rechaza_contra_el_almacen_real() {
    let esc = escenario_dag();
    // Padres anticadena A y C; pero se declara C como seleccionado. El sp real (mayor bw)
    // es A, porque A y C tienen el mismo bw y A tiene menor sd.
    let h = cabecera(
        PadresDag::nuevo(esc.h_c.block_hash(), &[esc.h_a.block_hash()]).unwrap(),
        9,
    );
    assert_eq!(
        comprobar_padres_contextual(&h, &esc.almacen),
        Err(ErrorDag::PadreSeleccionadoIncorrecto {
            esperado: esc.h_a.block_hash(),
            encontrado: esc.h_c.block_hash(),
        })
    );
}

#[test]
fn padres_validados_y_anticadena_pasan_contra_el_almacen_real() {
    let esc = escenario_dag();
    // A y C son hermanas (anticadena), y A es el sp (menor sd).
    let h = cabecera(
        PadresDag::nuevo(esc.h_a.block_hash(), &[esc.h_c.block_hash()]).unwrap(),
        9,
    );
    assert!(comprobar_padres_contextual(&h, &esc.almacen).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// 9 · C-HDR-05 · C-FLU-02 — cota de slot para TODOS los padres, en el almacén
// ─────────────────────────────────────────────────────────────────────────────

/// Estado observable completo del almacén: lo que un rechazo **MUST NOT** haber tocado.
type EstadoObservable = (BlockHash, Vec<Idx>, Option<Rank>, Option<DatosGhostdag>);

fn huella(a: &AlmacenGhostdag) -> Vec<EstadoObservable> {
    (0..a.len() as Idx)
        .map(|i| {
            (
                a.id(i).unwrap(),
                a.padres_de(i).map(|p| p.to_vec()).unwrap_or_default(),
                a.rank(i),
                a.datos(i).cloned(),
            )
        })
        .collect()
}

/// Dos hermanas con el mismo `blue_work` y distinto `sd`: `A` es el `sp` (menor `sd`) y `C` es el
/// padre adicional. `slot_c` fija el slot **contextual** de `C`, que es el único que cuenta.
fn escenario_hermanas(
    algoritmo: Algoritmo,
    slot_c: u64,
) -> (AlmacenGhostdag, BlockHash, BlockHash) {
    let g = cabecera(PadresDag::genesis(), 0);
    let mut almacen = AlmacenGhostdag::con_raiz_terminal(
        params_regla_c(),
        algoritmo,
        g.block_hash(),
        RangoSolucionValidado::para_oraculos(0),
    );
    let a = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 1);
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: a.block_hash(),
            padres: vec![g.block_hash()],
            slot: 1,
            solution_distance: 1,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    // La cabecera de `C` declara el MISMO slot que se almacena: `slot_c` se fija antes de calcular
    // `block_hash`, para que el fixture sea coherente y no un slot declarado distinto del contextual.
    let mut c = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 9);
    c.slot = slot_c;
    let id_c = c.block_hash();
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: id_c,
            padres: vec![g.block_hash()],
            slot: slot_c,
            solution_distance: 2,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    (almacen, a.block_hash(), id_c)
}

#[test]
fn el_padre_seleccionado_con_slot_posterior_se_rechaza_en_los_dos_algoritmos() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let mut esc = escenario_dag_con(algoritmo);
        let h_b = esc.h_b.block_hash(); // slot 2 en el almacén, slot 2 en la cabecera
        let err = esc
            .almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("FUT-SEL"),
                padres: vec![h_b],
                slot: 1,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap_err();
        assert_eq!(
            err,
            ErrorDag::SlotDePadrePosterior {
                padre: h_b,
                slot_padre: 2,
                slot_b: 1,
            },
            "{algoritmo:?}"
        );
    }
}

/// **Caso de aceptación focalizado.** El seleccionado cumple la cota y el adicional no: el rechazo
/// debe nombrar al adicional. Sin la comprobación de todos los padres, este bloque se aceptaría.
#[test]
fn el_padre_adicional_con_slot_posterior_se_rechaza_aunque_el_seleccionado_cumpla() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let (mut almacen, a, c) = escenario_hermanas(algoritmo, 5);
        let err = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("FUT-EXTRA"),
                // `sp` = A (menor sd) con slot 1; C es el adicional con slot 5.
                padres: vec![a, c],
                slot: 3,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap_err();
        assert_eq!(
            err,
            ErrorDag::SlotDePadrePosterior {
                padre: c,
                slot_padre: 5,
                slot_b: 3,
            },
            "{algoritmo:?}"
        );
    }
}

#[test]
fn todos_los_padres_con_el_mismo_slot_que_b_se_aceptan() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let (mut almacen, a, c) = escenario_hermanas(algoritmo, 1);
        let idx = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("MISMO"),
                padres: vec![a, c],
                slot: 1,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap_or_else(|e| panic!("{algoritmo:?}: la igualdad está permitida: {e}"));
        assert_eq!(almacen.padres_de(idx).unwrap(), &[1, 2]);
    }
}

#[test]
fn padres_con_slots_anteriores_se_aceptan() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let (mut almacen, a, c) = escenario_hermanas(algoritmo, 1);
        let idx = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("TARDE"),
                padres: vec![a, c],
                slot: 40,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap_or_else(|e| panic!("{algoritmo:?}: los slots anteriores son válidos: {e}"));
        assert_eq!(almacen.padres_de(idx).unwrap(), &[1, 2]);
    }
}

#[test]
fn un_padre_desconocido_se_rechaza_sin_tocar_el_almacen() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let mut esc = escenario_dag_con(algoritmo);
        let antes = huella(&esc.almacen);
        let impostor = cabecera(PadresDag::genesis(), 0xEE).block_hash();
        let err = esc
            .almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("HUERFANO"),
                padres: vec![impostor],
                slot: 9,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap_err();
        assert_eq!(
            err,
            ErrorDag::BloqueDesconocido { hash: impostor },
            "{algoritmo:?}"
        );
        assert_eq!(huella(&esc.almacen), antes, "{algoritmo:?}");
    }
}

/// Un rechazo por la cota de slot deja el almacén **exactamente** como estaba: índices, padres,
/// slots, colores y acumuladores.
#[test]
fn el_rechazo_por_slot_deja_el_almacen_intacto() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        // Caso 1: padre seleccionado con slot posterior.
        let mut esc = escenario_dag_con(algoritmo);
        let antes = (
            esc.almacen.len(),
            esc.almacen.puntas(),
            huella(&esc.almacen),
        );
        assert!(
            esc.almacen
                .anadir_sintetico(BloqueGhostdag {
                    id: hash_de_id_textual("R-SEL"),
                    padres: vec![esc.h_b.block_hash()],
                    slot: 1,
                    solution_distance: 0,
                    rango_espacio: RangoSolucionValidado::para_oraculos(5),
                    identidad: IdentidadGhostdag::SinBillete,
                })
                .is_err(),
            "{algoritmo:?}"
        );
        assert_eq!(
            (
                esc.almacen.len(),
                esc.almacen.puntas(),
                huella(&esc.almacen)
            ),
            antes,
            "{algoritmo:?}: un rechazo no puede modificar el almacén"
        );

        // Caso 2: padre adicional con slot posterior y seleccionado válido.
        let (mut almacen, a, c) = escenario_hermanas(algoritmo, 5);
        let antes = (almacen.len(), almacen.puntas(), huella(&almacen));
        assert!(
            almacen
                .anadir_sintetico(BloqueGhostdag {
                    id: hash_de_id_textual("R-EXTRA"),
                    padres: vec![a, c],
                    slot: 3,
                    solution_distance: 0,
                    rango_espacio: RangoSolucionValidado::para_oraculos(5),
                    identidad: IdentidadGhostdag::SinBillete,
                })
                .is_err(),
            "{algoritmo:?}"
        );
        assert_eq!(
            (almacen.len(), almacen.puntas(), huella(&almacen)),
            antes,
            "{algoritmo:?}: un rechazo no puede modificar el almacén"
        );
    }
}

/// La consulta `slot_de_padre` del almacén real devuelve el slot **contextual** del padre y falla
/// explícitamente ante un hash que no conoce; nunca devuelve cero por defecto.
#[test]
fn el_slot_contextual_del_almacen_real_es_explicito() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let esc = escenario_dag_con(algoritmo);
        assert_eq!(
            esc.almacen.slot_de_padre(&esc.h_b.block_hash()).unwrap(),
            2,
            "{algoritmo:?}: el slot sale del contexto, no del candidato"
        );

        let impostor = cabecera(PadresDag::genesis(), 0xEE).block_hash();
        assert_eq!(
            esc.almacen.slot_de_padre(&impostor),
            Err(ErrorDag::PadreNoValidado { padre: impostor }),
            "{algoritmo:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10 · C-HDR-06 → C-GD-01/C-GD-08 — frontera del SR contextual validado
// ─────────────────────────────────────────────────────────────────────────────

/// Contexto de rango de los tests: un valor fijo. No hay controlador.
struct CtxRangoFijo(u64);

impl ContextoRangoDag for CtxRangoFijo {
    fn rango_esperado(&self, _c: &CandidatoSinRango<'_>) -> Result<u64, ErrorDag> {
        Ok(self.0)
    }
}

#[test]
fn el_rango_contextual_correcto_e_incorrecto() {
    // El helper `cabecera` declara `rango_solucion = 42`.
    let h = cabecera(PadresDag::genesis(), 3);

    let validado = RangoSolucionValidado::validar(&h, &CtxRangoFijo(42)).unwrap();
    assert_eq!(validado.valor(), 42);

    // El esperado es el del contexto; el declarado no puede usarse como tal.
    assert_eq!(
        RangoSolucionValidado::validar(&h, &CtxRangoFijo(7)),
        Err(ErrorDag::RangoIncorrecto {
            esperado: 7,
            encontrado: 42,
        })
    );
}

/// El SR que pesa sale de `validar` (C-HDR-06), no de un `u64` libre del candidato.
#[test]
fn el_peso_usa_el_sr_validado_en_los_dos_algoritmos() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let g = cabecera(PadresDag::genesis(), 0);
        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params_regla_c(),
            algoritmo,
            g.block_hash(),
            RangoSolucionValidado::para_oraculos(0),
        );

        let h_a = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 1);
        let sr_a = RangoSolucionValidado::validar(&h_a, &CtxRangoFijo(42)).unwrap();
        let idx_a = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h_a.block_hash(),
                padres: vec![g.block_hash()],
                slot: 1,
                solution_distance: 1,
                rango_espacio: sr_a,
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();

        // B desciende de A: hereda `blue_work(A)` y suma `w(A)` con el SR validado.
        let h_b = cabecera(PadresDag::nuevo(h_a.block_hash(), &[]).unwrap(), 2);
        let idx_b = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h_b.block_hash(),
                padres: vec![h_a.block_hash()],
                slot: 2,
                solution_distance: 2,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();

        let esperado_a = peso(0); // la raíz es azul de A y su SR es 0
        let esperado_b = sumar_blue_work(esperado_a, peso(sr_a.valor())).unwrap();
        assert_eq!(
            almacen.rank(idx_a).unwrap().blue_work,
            esperado_a,
            "{algoritmo:?}"
        );
        assert_eq!(
            almacen.rank(idx_b).unwrap().blue_work,
            esperado_b,
            "{algoritmo:?}"
        );
        assert_eq!(sr_a.valor(), 42);
    }
}

/// `SR = 0` (peso máximo) y `SR = u64::MAX` (peso mínimo) se acumulan sin desbordar ni
/// confundirse con una ausencia. Referencia y Kernel coinciden.
#[test]
fn los_extremos_del_sr_se_acumulan_en_blue_work() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let g = cabecera(PadresDag::genesis(), 0);
        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params_regla_c(),
            algoritmo,
            g.block_hash(),
            RangoSolucionValidado::para_oraculos(0),
        );
        let h_a = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 1);
        let idx_a = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h_a.block_hash(),
                padres: vec![g.block_hash()],
                slot: 1,
                solution_distance: 1,
                rango_espacio: RangoSolucionValidado::para_oraculos(0),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        // B usa el extremo máximo; su peso cuenta al incluirse en C, no en sí mismo (C-GD-08).
        let h_b = cabecera(PadresDag::nuevo(h_a.block_hash(), &[]).unwrap(), 2);
        let idx_b = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h_b.block_hash(),
                padres: vec![h_a.block_hash()],
                slot: 2,
                solution_distance: 2,
                rango_espacio: RangoSolucionValidado::para_oraculos(u64::MAX),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        let h_c = cabecera(PadresDag::nuevo(h_b.block_hash(), &[]).unwrap(), 3);
        let idx_c = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h_c.block_hash(),
                padres: vec![h_b.block_hash()],
                slot: 3,
                solution_distance: 3,
                rango_espacio: RangoSolucionValidado::para_oraculos(1),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();

        // A hereda el peso de la raíz (SR=0) = 2^128.
        assert_eq!(
            almacen.rank(idx_a).unwrap().blue_work,
            U256::one() << 128usize,
            "{algoritmo:?}"
        );
        // B añade el peso de A (SR=0): 2^129.
        assert_eq!(
            almacen.rank(idx_b).unwrap().blue_work,
            U256::one() << 129usize,
            "{algoritmo:?}"
        );
        // C añade el peso de B (SR=u64::MAX) = 2^64, sin desbordar.
        let esperado_c = sumar_blue_work(U256::one() << 129usize, U256::one() << 64usize).unwrap();
        assert_eq!(
            almacen.rank(idx_c).unwrap().blue_work,
            esperado_c,
            "{algoritmo:?}"
        );
    }
}

/// **Adversarial (hueco conocido, no cerrado).**
///
/// Un cliente normal puede construir `RangoSolucionValidado::para_oraculos(cabecera.rango_solucion)`
/// y llamar a `anadir_sintetico` sin pasar por ningún contexto: se acepta. La frontera de
/// producción no impide esta llamada; solo la separa por nombre y por API. Este test existe para
/// que la limitación quede exhibida y no se presente como resuelta.
#[test]
fn el_sr_sintetico_libre_sigue_siendo_una_puerta_trasera() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let g = cabecera(PadresDag::genesis(), 0);
        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params_regla_c(),
            algoritmo,
            g.block_hash(),
            RangoSolucionValidado::para_oraculos(0),
        );
        // La cabecera declara `rango_solucion = 42`; el llamante lo copia sin contexto.
        let h = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 7);
        let idx = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h.block_hash(),
                padres: vec![g.block_hash()],
                slot: h.slot,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(h.rango_solucion),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .expect("se conserva como hueco: la entrada sintética no valida C-HDR-06");
        assert_eq!(almacen.id(idx), Some(h.block_hash()));
    }
}

/// La entrada **de producción** rechaza lo que la sintética acepta.
#[test]
fn admitir_rechaza_el_rango_declarado_que_no_es_el_esperado() {
    let g = cabecera(PadresDag::genesis(), 0);
    let h = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 7); // declara 42
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params_regla_c(),
            algoritmo,
            g.block_hash(),
            RangoSolucionValidado::para_oraculos(0),
        );
        let antes = (almacen.len(), huella(&almacen));
        assert_eq!(
            almacen.admitir(&h, 0, &CtxRangoFijo(7)),
            Err(ErrorDag::RangoIncorrecto {
                esperado: 7,
                encontrado: 42,
            }),
            "{algoritmo:?}"
        );
        assert_eq!(
            (almacen.len(), huella(&almacen)),
            antes,
            "{algoritmo:?}: el rechazo no muta el almacén"
        );

        // Con el contexto correcto inserta el id de la MISMA cabecera que valida.
        let idx = almacen
            .admitir(&h, 0, &CtxRangoFijo(42))
            .unwrap_or_else(|e| panic!("{algoritmo:?}: {e}"));
        assert_eq!(almacen.id(idx), Some(h.block_hash()), "{algoritmo:?}");
    }
}

/// **Adversarial.** Un `SR` validado para `A` no se puede colocar en un bloque con el id de `B`:
/// la atadura `(bloque, rango)` lo rechaza.
#[test]
fn un_sr_validado_no_se_puede_colocar_en_otro_bloque() {
    let g = cabecera(PadresDag::genesis(), 0);
    let h_a = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 1);
    let h_b = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 2);
    assert_ne!(h_a.block_hash(), h_b.block_hash());

    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let sr_a = RangoSolucionValidado::validar(&h_a, &CtxRangoFijo(42)).unwrap();
        assert_eq!(sr_a.bloque(), Some(h_a.block_hash()));

        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params_regla_c(),
            algoritmo,
            g.block_hash(),
            RangoSolucionValidado::para_oraculos(0),
        );
        let err = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h_b.block_hash(),
                padres: vec![g.block_hash()],
                slot: h_b.slot,
                solution_distance: 0,
                rango_espacio: sr_a,
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap_err();
        assert_eq!(
            err,
            ErrorDag::RangoDeOtroBloque {
                bloque: h_b.block_hash(),
                validado_para: h_a.block_hash(),
            },
            "{algoritmo:?}"
        );
        assert_eq!(
            almacen.len(),
            1,
            "{algoritmo:?}: el rechazo no muta el almacén"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11 · Unicidad del almacén y alcance real de `ContextoRangoDag`
// ─────────────────────────────────────────────────────────────────────────────

/// **Antes**, insertar dos veces el mismo `block_hash` hacía que `indice.insert` sustituyera la
/// entrada (el mapa pasaba a apuntar al índice nuevo) mientras `ids` crecía: `len()` llegaba a 3 y
/// `id(1) == id(2) == duplicado`. **Ahora** se rechaza como duplicado de almacenamiento antes de
/// mutar, y la huella completa no cambia.
#[test]
fn el_duplicado_por_anadir_sintetico_se_rechaza_sin_mutar() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let g = cabecera(PadresDag::genesis(), 0);
        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params_regla_c(),
            algoritmo,
            g.block_hash(),
            RangoSolucionValidado::para_oraculos(0),
        );
        let h = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 1);
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h.block_hash(),
                padres: vec![g.block_hash()],
                slot: h.slot,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();

        let antes = (almacen.len(), almacen.puntas(), huella(&almacen));
        // Mismo id con otros metadatos: un duplicado de almacenamiento, no una prueba PoST nueva.
        let h_dup = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 2);
        let err = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: h.block_hash(),
                padres: vec![g.block_hash()],
                slot: h_dup.slot,
                solution_distance: 1,
                rango_espacio: RangoSolucionValidado::para_oraculos(9),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap_err();
        assert_eq!(
            err,
            ErrorDag::BloqueDuplicado {
                hash: h.block_hash()
            },
            "{algoritmo:?}"
        );
        assert_eq!(
            (almacen.len(), almacen.puntas(), huella(&almacen)),
            antes,
            "{algoritmo:?}: el duplicado no puede mutar el almacén"
        );
    }
}

/// El duplicado se rechaza **antes** de consultar el contexto: no se revalida un bloque que ya
/// está, y no depende de que el controlador responda.
#[test]
fn el_duplicado_por_admitir_se_rechaza_sin_consultar_el_contexto() {
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let g = cabecera(PadresDag::genesis(), 0);
        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params_regla_c(),
            algoritmo,
            g.block_hash(),
            RangoSolucionValidado::para_oraculos(0),
        );
        let h = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 1); // declara 42
        almacen.admitir(&h, 0, &CtxRangoFijo(42)).unwrap();

        let antes = (almacen.len(), almacen.puntas(), huella(&almacen));
        // Este contexto haría fallar la validación si se consultara; el duplicado va primero.
        let err = almacen.admitir(&h, 0, &CtxRangoFijo(999)).unwrap_err();
        assert_eq!(
            err,
            ErrorDag::BloqueDuplicado {
                hash: h.block_hash()
            },
            "{algoritmo:?}"
        );
        assert_eq!(
            (almacen.len(), almacen.puntas(), huella(&almacen)),
            antes,
            "{algoritmo:?}: el duplicado no puede mutar el almacén"
        );
    }
}

/// Contexto **adversarial**: conserva la cabecera y devuelve su `rango_solucion` declarado como
/// «esperado». `CandidatoSinRango` solo bloquea el acceso directo *dentro de la vista*; no impide
/// esta vía, así que la vista **no** es una garantía de ausencia de circularidad.
struct CtxQueReenviaElDeclarado(DagBlockHeader);

impl ContextoRangoDag for CtxQueReenviaElDeclarado {
    fn rango_esperado(&self, _c: &CandidatoSinRango<'_>) -> Result<u64, ErrorDag> {
        Ok(self.0.rango_solucion)
    }
}

#[test]
fn un_contexto_puede_devolver_el_sr_declarado_como_esperado() {
    // No hace falta un DAG: `validar` solo compara el declarado con lo que dé el contexto.
    let h = cabecera(PadresDag::genesis(), 7); // declara 42
    let v = RangoSolucionValidado::validar(&h, &CtxQueReenviaElDeclarado(h)).unwrap();
    assert_eq!(v.valor(), 42);

    // Y con cualquier otro valor declarado también pasa: el contexto lo copia, no lo deriva.
    let mut otro = cabecera(PadresDag::genesis(), 8);
    otro.rango_solucion = 999;
    let v2 = RangoSolucionValidado::validar(&otro, &CtxQueReenviaElDeclarado(otro)).unwrap();
    assert_eq!(v2.valor(), 999);
}

// ─────────────────────────────────────────────────────────────────────────────
// 12 · Identidad exacta de C-GD-07: U2/U3 con la tupla literal, no con una proyección
// ─────────────────────────────────────────────────────────────────────────────

/// Contraejemplo de **cualquier** proyección artificial de ocho bytes elegida para el test: dos
/// billetes que solo difieren en un byte del `chunk` comparten los primeros ocho bytes de la
/// codificación canónica (que son la clave pública), así que una proyección de `[..8]` los
/// confundiría. La tupla literal los distingue: **ni U2 ni U3** deben dispararse.
#[test]
fn identidades_distintas_con_misma_proyeccion_no_disparan_u2_ni_u3() {
    let t1 = IdentidadTicket::vigente(
        ClavePublica::desde_bytes([9u8; 32]),
        3,
        1 << 20,
        [1u8; 32],
        1,
    );
    let t2 = IdentidadTicket::vigente(
        ClavePublica::desde_bytes([9u8; 32]),
        3,
        1 << 20,
        [2u8; 32],
        1,
    );
    assert_ne!(t1, t2, "la tupla literal los distingue");
    assert_eq!(
        t1.bytes_canonicos()[..8],
        t2.bytes_canonicos()[..8],
        "una proyección artificial de los primeros ocho bytes los confundiría"
    );

    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let mut almacen = AlmacenGhostdag::nuevo(
            params_regla_c(),
            algoritmo,
            hash_de_id_textual("G"),
            0,
            RangoSolucionValidado::para_oraculos(0),
            0,
        );
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("A"),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 5,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(t1),
            })
            .unwrap();
        // Descendiente de A con t2: identidades distintas ⇒ U2 NO lo invalida.
        let a2 = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("A2"),
                padres: vec![hash_de_id_textual("A")],
                slot: 2,
                solution_distance: 6,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(t2),
            })
            .unwrap_or_else(|e| panic!("{algoritmo:?}: A2 no debe ser U2: {e}"));
        assert!(almacen.datos(a2).is_some(), "{algoritmo:?}");

        // Hermana S con t2; C fusiona A (sp) y S. Como t2 ≠ t1, S no puede ser U3: se comprueba
        // su color de forma directa, no solo que una lista de colores no contenga `RojoU3`.
        let s = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("S"),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 7,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(t2),
            })
            .unwrap();
        let c = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("C"),
                padres: vec![hash_de_id_textual("A"), hash_de_id_textual("S")],
                slot: 2,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        assert_eq!(
            almacen.color_en(c, s),
            Some(Color::Azul),
            "{algoritmo:?}: dos identidades literales distintas no pueden hacer U3 a S"
        );
    }
}

/// La **misma** identidad literal: U2 en un descendiente y U3 en un mergeset, en Referencia y
/// Kernel. El billete es real (`Billete`), no un `u64` de fixture.
#[test]
fn la_misma_identidad_literal_dispara_u2_y_u3() {
    let t = IdentidadTicket::vigente(
        ClavePublica::desde_bytes([4u8; 32]),
        7,
        1 << 20,
        [3u8; 32],
        1,
    );
    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let mut almacen = AlmacenGhostdag::nuevo(
            params_regla_c(),
            algoritmo,
            hash_de_id_textual("G"),
            0,
            RangoSolucionValidado::para_oraculos(0),
            0,
        );
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("A"),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 5,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(t),
            })
            .unwrap();
        // Misma tupla en un descendiente ⇒ U2, sin mutar el almacén.
        let antes = (almacen.len(), huella(&almacen));
        assert_eq!(
            almacen.anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("D"),
                padres: vec![hash_de_id_textual("A")],
                slot: 1,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(t),
            }),
            Err(ErrorDag::BilleteDuplicadoU2 {
                identidad: IdentidadGhostdag::Billete(t),
            }),
            "{algoritmo:?}"
        );
        assert_eq!((almacen.len(), huella(&almacen)), antes, "{algoritmo:?}");

        // Misma tupla en una hermana ⇒ el candidato del mergeset es rojo_U3.
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("S"),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 5,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(t),
            })
            .unwrap();
        let c = almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("C"),
                padres: vec![hash_de_id_textual("A"), hash_de_id_textual("S")],
                slot: 2,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        let s_idx = almacen
            .datos(c)
            .unwrap()
            .rojos
            .first()
            .copied()
            .unwrap_or_else(|| panic!("{algoritmo:?}: S debe quedar fuera del blue set"));
        assert_eq!(
            almacen.color_en(c, s_idx),
            Some(Color::RojoU3),
            "{algoritmo:?}: la repetición de la misma tupla es U3"
        );
    }
}

/// Un billete real cuyos bytes canónicos son **todos cero** no es ausencia: se registra y su
/// repetición se detecta como U2. El `SinBillete` de la raíz/fixture no produce U2 falso.
#[test]
fn un_billete_real_de_bytes_cero_no_es_ausencia() {
    let cero = IdentidadTicket::vigente(ClavePublica::desde_bytes([0u8; 32]), 0, 0, [0u8; 32], 0);
    assert!(cero.bytes_canonicos().iter().all(|b| *b == 0));
    assert_ne!(
        IdentidadGhostdag::Billete(cero),
        IdentidadGhostdag::SinBillete,
        "un billete de bytes cero no es ausencia"
    );

    for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
        let mut almacen = AlmacenGhostdag::nuevo(
            params_regla_c(),
            algoritmo,
            hash_de_id_textual("G"),
            0,
            RangoSolucionValidado::para_oraculos(0),
            0,
        );
        // Sin billete sobre la raíz: aceptado, sin U2 falso por la ausencia.
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("N"),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 1,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::SinBillete,
            })
            .unwrap();
        // Billete real de bytes cero: aceptado una vez…
        almacen
            .anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("Z1"),
                padres: vec![hash_de_id_textual("G")],
                slot: 1,
                solution_distance: 2,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(cero),
            })
            .unwrap();
        // …y detectado cuando reaparece en su descendiente.
        assert_eq!(
            almacen.anadir_sintetico(BloqueGhostdag {
                id: hash_de_id_textual("Z2"),
                padres: vec![hash_de_id_textual("Z1")],
                slot: 2,
                solution_distance: 0,
                rango_espacio: RangoSolucionValidado::para_oraculos(5),
                identidad: IdentidadGhostdag::Billete(cero),
            }),
            Err(ErrorDag::BilleteDuplicadoU2 {
                identidad: IdentidadGhostdag::Billete(cero),
            }),
            "{algoritmo:?}"
        );
    }
}

/// `admitir` no acepta identidad: la deriva de la misma cabecera que aporta hash y slot. Un error
/// de SR deja el almacén intacto y el mismo header se reintenta correctamente; un hijo con la
/// misma tupla dispara U2, que es la prueba de que la identidad salió de la cabecera.
#[test]
fn admitir_deriva_la_identidad_de_la_cabecera() {
    let g = cabecera(PadresDag::genesis(), 0);
    let mut almacen = AlmacenGhostdag::con_raiz_terminal(
        params_regla_c(),
        Algoritmo::Kernel,
        g.block_hash(),
        RangoSolucionValidado::para_oraculos(0),
    );
    let h = cabecera(PadresDag::nuevo(g.block_hash(), &[]).unwrap(), 1); // declara 42
    let antes = (almacen.len(), huella(&almacen));
    assert_eq!(
        almacen.admitir(&h, 0, &CtxRangoFijo(7)),
        Err(ErrorDag::RangoIncorrecto {
            esperado: 7,
            encontrado: 42,
        })
    );
    assert_eq!(
        (almacen.len(), huella(&almacen)),
        antes,
        "un rechazo de SR no muta índices ni identidades"
    );

    // El MISMO header se reintenta con el contexto correcto.
    let idx = almacen
        .admitir(&h, 0, &CtxRangoFijo(42))
        .unwrap_or_else(|e| panic!("el reintento correcto debe aceptar: {e}"));
    assert_eq!(almacen.id(idx), Some(h.block_hash()));

    // Un hijo con la MISMA tupla de identidad (misma cabecera salvo padres) dispara U2.
    let h2 = cabecera(PadresDag::nuevo(h.block_hash(), &[]).unwrap(), 1);
    assert_ne!(h.block_hash(), h2.block_hash());
    assert_eq!(identidad_de_cabecera(&h), identidad_de_cabecera(&h2));
    let antes = (almacen.len(), huella(&almacen));
    assert_eq!(
        almacen.admitir(&h2, 0, &CtxRangoFijo(42)),
        Err(ErrorDag::BilleteDuplicadoU2 {
            identidad: IdentidadGhostdag::Billete(identidad_de_cabecera(&h)),
        })
    );
    assert_eq!(
        (almacen.len(), huella(&almacen)),
        antes,
        "U2 no muta el almacén"
    );
}
