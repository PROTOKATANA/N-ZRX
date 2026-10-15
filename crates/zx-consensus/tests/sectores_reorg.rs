//! V3 · Reorganización y undo exacto: 200 casos aleatorios con semilla fija.
//!
//! Cada caso construye un DAG con un prefijo controlado que **fuerza** un alta, una suspensión
//! derivada (auditoría no contestada a plazo) y una retirada, más ramas y bloques aleatorios. La
//! propiedad: `avanzar` (que deshace el prefijo que sobra con undo por delta) coincide **bit a bit**
//! con `fold_referencia`, y `undo_exacto` devuelve el estado previo en cada bloque.

#![expect(
    clippy::indexing_slicing,
    reason = "generador aleatorio de test con índices acotados por construcción"
)]

use soporte::generadores::{
    Constr, k1, k2, op_abrir, op_alta, op_contestar, op_dep, op_evid, op_fond, op_renovar,
    op_retirar, undo_exacto,
};
use soporte::{
    CadenaSector, EstadoEfectivo, EstadoSector, Operacion, ParametrosSector, TipoOp, avanzar,
    estado_efectivo, fold_referencia, sector_vivo,
};

mod soporte;

/// splitmix64 determinista.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn abajo(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

fn op_aleatoria(
    rng: &mut Rng,
    k1: &zx_core::ClavePublica,
    k2: &zx_core::ClavePublica,
    p: &ParametrosSector,
    si: u16,
) -> Operacion {
    let importe = 5 + i64::try_from(rng.abajo(46)).unwrap_or(0);
    let clave = if rng.abajo(2) == 0 { *k1 } else { *k2 };
    match rng.abajo(9) {
        0 => op_fond(clave, importe),
        1 => op_dep(clave, importe),
        2 => op_alta(clave, si, 0, p.q_sec, 1),
        3 => op_renovar(*k1, 0),
        4 => op_abrir(*k1, 1, 7),
        5 => op_contestar(*k1, 1, 7, true),
        6 => op_retirar(*k1, 0),
        7 => op_evid(*k1, 0, 9),
        _ => op_alta(*k2, si, 0, p.q_sec, 1),
    }
}

#[test]
fn reorg_200_casos() {
    let p = ParametrosSector::fixture();
    let (k1, k2) = (k1(), k2());
    let mut casos_con_alta = 0usize;
    let mut casos_con_suspension = 0usize;
    let mut casos_con_retiro = 0usize;

    for caso in 0..200u64 {
        let mut rng = Rng(0x5A5A_0001_0001_0001 ^ caso.wrapping_mul(0x9E37_79B9));
        let c = &mut Constr::new();

        // ── prefijo controlado: alta + suspensión + retiro ──
        let b0 = c.pow(
            vec![],
            0,
            k1,
            1,
            vec![
                op_fond(k1, 100 * p.q_sec + 500),
                op_fond(k2, 100 * p.q_sec + 500),
            ],
        );
        let b1 = c.pow(
            vec![b0],
            1,
            k1,
            1,
            vec![
                op_alta(k1, 0, 0, p.q_sec, 1),
                op_alta(k1, 1, 0, p.q_sec, 1),
                op_alta(k2, 0, 0, p.q_sec, 1),
            ],
        );
        let s0 = 1 + p.m_sec;
        let b2 = c.post(vec![b1], s0, k1, 0, 1, 0, 1, vec![]);
        let aud = 7 + rng.abajo(100);
        let b3 = c.post(vec![b2], s0 + 1, k1, 0, 1, 0, 1, vec![op_abrir(k1, 1, aud)]);
        // En `s0 + 1 + p_aud` el sector 1 está suspendido; se retira el 0 en el mismo bloque.
        let b4 = c.post(
            vec![b3],
            s0 + 1 + p.p_aud,
            k1,
            0,
            1,
            0,
            1,
            vec![op_retirar(k1, 0)],
        );
        // K2 produce con su sector 0 (maduro) y se recupera el 1 de K1.
        let b5 = c.post(vec![b4], s0 + 2 + p.p_aud, k2, 0, 1, 0, 1, vec![]);
        let b6 = c.pow(
            vec![b5],
            s0 + 3 + p.p_aud,
            k2,
            1,
            vec![op_contestar(k1, 1, aud, true)],
        );
        // Bloque tardío que materializa la liberación de la fianza de K1/si0 (terminal).
        let b7 = c.post(vec![b6], s0 + 1 + p.p_aud + 40, k1, 1, 1, 0, 1, vec![]);

        // ── rama aleatoria ──
        let mut ids = vec![b0, b1, b2, b3, b4, b5, b6, b7];
        let extra = 4 + rng.abajo(20);
        let mut ultimo = b7;
        let mut si_libre: u16 = 10;
        for _ in 0..extra {
            let padre = ids[rng.abajo(ids.len() as u64) as usize % ids.len()];
            let slot = c.dag.bloques.get(&padre).map_or(s0 + 4, |b| {
                b.slot + 1 + i64::try_from(rng.abajo(3)).unwrap_or(0)
            });
            let productor = if rng.abajo(2) == 0 { k1 } else { k2 };
            let n_ops = rng.abajo(3);
            let mut ops = Vec::new();
            for _ in 0..n_ops {
                ops.push(op_aleatoria(&mut rng, &k1, &k2, &p, si_libre));
                si_libre = si_libre.saturating_add(1);
            }
            let id = if rng.abajo(3) == 0 {
                c.pow(vec![padre], slot, productor, 1, ops)
            } else {
                let si = rng.abajo(3) as u16;
                c.post(vec![padre], slot, productor, si, 1, 0, 1, ops)
            };
            ids.push(id);
            ultimo = id;
        }
        let _ = ultimo;

        // Dos puntas distintas.
        let a = ids[rng.abajo(ids.len() as u64) as usize % ids.len()];
        let b = b7;
        let (ea, _) = fold_referencia(&c.dag, a, &p);
        let (eb, _) = fold_referencia(&c.dag, b, &p);

        let mut cadena = CadenaSector::default();
        avanzar(&mut cadena, &c.dag, b, &p);
        assert_eq!(
            cadena.estado, eb,
            "caso {caso}: avanzar(B) difiere del oráculo"
        );
        avanzar(&mut cadena, &c.dag, a, &p);
        assert_eq!(
            cadena.estado, ea,
            "caso {caso}: avanzar(A) difiere del oráculo (reorg)"
        );
        avanzar(&mut cadena, &c.dag, b, &p);
        assert_eq!(
            cadena.estado, eb,
            "caso {caso}: volver a B difiere del oráculo (reorg)"
        );

        assert!(
            undo_exacto(&c.dag, a, &p),
            "caso {caso}: undo_exacto(A) falla"
        );
        assert!(
            undo_exacto(&c.dag, b, &p),
            "caso {caso}: undo_exacto(B) falla"
        );

        // Cobertura: alta, suspensión (en b4) y retiro terminal (en b7).
        if c.dag
            .bloques
            .values()
            .any(|bl| bl.ops.iter().any(|o| o.tipo == TipoOp::Alta))
        {
            casos_con_alta += 1;
        }
        let (e4, _) = fold_referencia(&c.dag, b4, &p);
        if estado_de_vivo(&e4, &k1, 1, e4.slot_actual, &p) == Some(EstadoEfectivo::Suspendido) {
            casos_con_suspension += 1;
        }
        if eb.sectores.values().any(|r| r.es_terminal()) {
            casos_con_retiro += 1;
        }
    }

    eprintln!(
        "V3 · 200 casos: alta={casos_con_alta}, suspensión={casos_con_suspension}, retiro={casos_con_retiro}"
    );
    assert!(casos_con_alta > 0, "ningún caso con alta");
    assert!(
        casos_con_suspension > 0,
        "ningún caso con suspensión derivada"
    );
    assert!(casos_con_retiro > 0, "ningún caso con retirada terminal");
}

fn estado_de_vivo(
    est: &EstadoSector,
    clave: &zx_core::ClavePublica,
    si: u16,
    slot: i64,
    p: &ParametrosSector,
) -> Option<EstadoEfectivo> {
    sector_vivo(est, clave, si).map(|r| estado_efectivo(&r, slot, p))
}
