//! Property tests de GHOSTDAG con **semilla fija en el código** (`RngSeed::Fixed`). No se usa
//! `PROPTEST_SEED` (no existe) ni `PROPTEST_RNG_SEED` (se parsea como u64 decimal): la semilla vive
//! aquí, como exige LINEO y como rectificó la revisión de 02.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio test"
)]

use std::cell::RefCell;

use primitive_types::U256;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use zx_core::digest::BlockHash;
use zx_dag::RangoSolucionValidado;
use zx_dag::ghostdag::{
    Algoritmo, AlmacenGhostdag, BloqueGhostdag, Color, IdentidadGhostdag, Idx, ModoMerge, ModoSp,
    Parametros, hash_de_id_textual,
};

const NODOS: usize = 14;

fn params() -> Parametros {
    Parametros {
        sp: ModoSp::Zerox,
        merge: ModoMerge::Terna,
        ..Parametros::default()
    }
}

fn construir(
    mascaras: &[u16],
    sds: &[u16],
    srs: &[u8],
    idents: &[u8],
    algoritmo: Algoritmo,
) -> Result<Vec<(Option<usize>, u64, U256)>, zx_dag::ErrorDag> {
    let mut almacen = AlmacenGhostdag::nuevo(
        params(),
        algoritmo,
        hash_de_id_textual("G"),
        0,
        RangoSolucionValidado::para_oraculos(0),
        0,
    );
    let mut ids: Vec<BlockHash> = vec![hash_de_id_textual("G")];
    for i in 1..NODOS {
        let id = hash_de_id_textual(&format!("B{i}"));
        let mut padres: Vec<BlockHash> = Vec::new();
        for (j, id_j) in ids.iter().enumerate().take(i) {
            if mascaras[i] & (1u16 << j) != 0 {
                padres.push(*id_j);
            }
        }
        let idx = almacen.anadir_sintetico(BloqueGhostdag {
            id,
            padres,
            slot: i as u64,
            solution_distance: u64::from(sds[i % sds.len()]),
            rango_espacio: RangoSolucionValidado::para_oraculos(u64::from(srs[i % srs.len()])),
            identidad: IdentidadGhostdag::de_fixture(u64::from(idents[i % idents.len()])),
        })?;
        debug_assert_eq!(idx as usize, i);
        ids.push(id);
    }
    // Proyección por índice de nodo: sp, blue_score y blue_work.
    let mut salida: Vec<(Option<usize>, u64, U256)> = Vec::new();
    for idx in 0..almacen.len() as Idx {
        let gd = almacen.datos(idx).unwrap();
        salida.push((gd.sp.map(|s| s as usize), gd.blue_score, gd.blue_work));
    }
    Ok(salida)
}

proptest! {
    #![proptest_config(ProptestConfig {
        rng_seed: RngSeed::Fixed(0x5a5a),
        cases: 512,
        ..ProptestConfig::default()
    })]

    /// Referencia y kernel deben coincidir (o rechazar el mismo bloque) en cualquier DAG.
    #[test]
    fn referencia_y_kernel_coinciden(
        mascaras in prop::collection::vec(0u16..=(1u16 << 14) - 1, NODOS),
        sds in prop::collection::vec(0u16..64, 8),
        srs in prop::collection::vec(0u8..8, 8),
        idents in prop::collection::vec(0u8..3, 8),
    ) {
        let a = construir(&mascaras, &sds, &srs, &idents, Algoritmo::Referencia);
        let b = construir(&mascaras, &sds, &srs, &idents, Algoritmo::Kernel);
        match (a, b) {
            (Ok(pa), Ok(pb)) => prop_assert_eq!(pa, pb),
            (Err(ea), Err(eb)) => prop_assert_eq!(ea, eb),
            (Ok(_), Err(e)) => prop_assert!(false, "la referencia acepta y el kernel rechaza: {e:?}"),
            (Err(e), Ok(_)) => prop_assert!(false, "el kernel acepta y la referencia rechaza: {e:?}"),
        }
    }

    /// Todo padre tiene menor `rank` que su hijo.
    #[test]
    fn ancestria_estricta(
        mascaras in prop::collection::vec(0u16..=(1u16 << 14) - 1, NODOS),
        sds in prop::collection::vec(0u16..64, 8),
        srs in prop::collection::vec(0u8..8, 8),
    ) {
        let idents = vec![0u8; 8];
        if construir(&mascaras, &sds, &srs, &idents, Algoritmo::Kernel).is_ok() {
            let mut almacen = AlmacenGhostdag::nuevo(
                params(), Algoritmo::Kernel, hash_de_id_textual("G"), 0, RangoSolucionValidado::para_oraculos(0), 0);
            let mut ids: Vec<BlockHash> = vec![hash_de_id_textual("G")];
            for i in 1..NODOS {
                let id = hash_de_id_textual(&format!("B{i}"));
                let mut padres: Vec<BlockHash> = Vec::new();
                for (j, id_j) in ids.iter().enumerate().take(i) {
                    if mascaras[i] & (1u16 << j) != 0 { padres.push(*id_j); }
                }
                if almacen.anadir_sintetico(BloqueGhostdag {
                    id, padres, slot: i as u64,
                    solution_distance: u64::from(sds[i % sds.len()]),
                    rango_espacio: RangoSolucionValidado::para_oraculos(u64::from(srs[i % srs.len()])),
                    identidad: IdentidadGhostdag::SinBillete,
                }).is_err() { return Ok(()); }
                ids.push(id);
            }
            for idx in 0..almacen.len() as Idx {
                let r = almacen.rank(idx).unwrap();
                for p in almacen.padres_de(idx).unwrap() {
                    prop_assert!(almacen.rank(*p).unwrap() < r);
                }
            }
        }
    }
}

/// Control negativo de la semilla: dos corridas con `RngSeed::Fixed` son idénticas.
#[test]
fn la_semilla_fija_es_reproducible() {
    fn muestra(seed: RngSeed) -> Vec<u32> {
        let cfg = ProptestConfig {
            rng_seed: seed,
            cases: 8,
            ..ProptestConfig::default()
        };
        let mut runner = proptest::test_runner::TestRunner::new(cfg);
        let estrategia = prop::collection::vec(prop::num::u32::ANY, 4);
        let salida = RefCell::new(Vec::new());
        runner
            .run(&estrategia, |v| {
                salida.borrow_mut().push(v.iter().fold(0u32, |a, b| a ^ b));
                Ok(())
            })
            .unwrap();
        salida.into_inner()
    }
    assert_eq!(
        muestra(RngSeed::Fixed(0x5a5a)),
        muestra(RngSeed::Fixed(0x5a5a))
    );
}

// `Color` se importa para que el tipo esté disponible si se amplía la proyección.
#[allow(dead_code)]
fn _usa_color(c: Color) -> u8 {
    match c {
        Color::Azul => 0,
        Color::RojoK => 1,
        Color::RojoU3 => 2,
    }
}
