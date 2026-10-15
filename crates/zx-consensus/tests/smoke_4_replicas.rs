//! V5 (sustituto consensus-level) · Humo de 4 réplicas con alta de sector.
//!
//! El humo que pide `ORDEN-SR1` §3-V5 es de **4 nodos reales** con un cliente de prueba que haga un
//! alta de sector. `zx-node` no posee la extensión `ExtensionTx::Sector` (incidencia B-1), así que
//! ese humo exigiría tocar `zx-node` (archivo ajeno). Este test cubre la parte verificable en el
//! carril: **cuatro réplicas independientes** de la transición reciben el mismo DAG con punteras
//! distintas (incluidas reorganizaciones), convergen al **mismo estado bit a bit**, conservan el
//! alta y no producen ningún bloque de productor inválido (`fallo_productor = 0`). Ver `INFORME.md`
//! §Límites.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test: falla con panic por diseño y usa índices acotados"
)]

use soporte::generadores::{Constr, k1, op_alta, op_fond, op_renovar};
use soporte::{
    CadenaSector, EstadoEfectivo, MotivoSector, ParametrosSector, avanzar, estado_efectivo,
    fold_referencia, sector_vivo,
};

mod soporte;

#[test]
fn humo_cuatro_replicas_mismo_estado_con_alta() {
    let p = ParametrosSector::fixture();
    let k1 = k1();
    let c = &mut Constr::new();
    // Bloque 0: fondos. Bloque 1: alta del sector 0. Bloques 2..4: PoST del productor.
    let b0 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 100)]);
    let b1 = c.pow(vec![b0], 1, k1, 1, vec![op_alta(k1, 0, 0, p.q_sec, 1)]);
    let s0 = 1 + p.m_sec;
    let b2 = c.post(vec![b1], s0, k1, 0, 1, 0, 1, vec![]);
    let b3 = c.post(vec![b2], s0 + 1, k1, 0, 1, 0, 1, vec![op_renovar(k1, 0)]);
    let b4 = c.post(vec![b3], s0 + 2, k1, 0, 1, 0, 1, vec![]);

    let (referencia, descartes) = fold_referencia(&c.dag, b4, &p);
    assert_eq!(
        referencia.sectores.len(),
        1,
        "el alta de sector debe estar en el estado final"
    );
    let vivo = sector_vivo(&referencia, &k1, 0).expect("sector vivo tras la alta");
    assert_eq!(
        estado_efectivo(&vivo, referencia.slot_actual, &p),
        EstadoEfectivo::Activo
    );

    // Punteras distintas: cuatro caminos de llegada al mismo DAG.
    let caminos: [&[u64]; 4] = [&[b4], &[b2, b3, b4], &[b1, b4], &[b3, b1, b4]];
    let mut estados = Vec::new();
    for (i, camino) in caminos.iter().enumerate() {
        let mut cadena = CadenaSector::default();
        for tip in *camino {
            avanzar(&mut cadena, &c.dag, *tip, &p);
        }
        assert_eq!(
            cadena.estado, referencia,
            "réplica {i}: estado distinto del oráculo"
        );
        estados.push(cadena.estado);
    }
    for (i, e) in estados.iter().enumerate().skip(1) {
        assert_eq!(
            e, &estados[0],
            "réplica {i}: estado distinto de la réplica 0 (se exige el mismo estado)"
        );
    }

    // `fallo_productor`: ningún bloque PoST del productor resultó inválido.
    let fallo_productor = c
        .dag
        .bloques
        .values()
        .filter(|b| b.sol.is_some())
        .filter(|b| {
            descartes
                .get(&b.id)
                .is_some_and(|d| d == &vec![MotivoSector::ErrEstado])
        })
        .count();
    assert_eq!(fallo_productor, 0, "un productor falló");

    eprintln!(
        "V5(sustituto) · 4 réplicas, mismo estado, alta presente, fallo_productor={fallo_productor}"
    );
}
