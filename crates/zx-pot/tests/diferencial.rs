//! Diferencial de la **primitiva** `zx-pot` (no del verificador contextual).
//!
//! `vectores-nightly.txt` son 32 vectores byte a byte generados ejecutando
//! `subspace-proof-of-time` @ `f8842d0` **sin modificar** bajo `nightly-2026-05-03`. Este test
//! comprueba que el port reproduce la primitiva original y que su propia verificación acepta lo
//! que la prueba produjo. Cualquier divergencia de un byte falla.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices fijos sobre los vectores de 16 B y sobre las líneas del fichero"
)]

use std::num::NonZeroU32;

use zx_pot::tipos::PotSeed;

const REF: &str = include_str!("vectores-nightly.txt");

#[test]
fn el_port_a_estable_es_byte_a_byte_identico_al_original() {
    let mut n = 0;
    for linea in REF.lines().filter(|l| l.starts_with("VEC ")) {
        let p: Vec<&str> = linea.split_whitespace().collect();
        let (s, it, esperado) = (
            p[1].parse::<u8>().unwrap(),
            p[2].parse::<u32>().unwrap(),
            p[3],
        );
        let mut b = [0u8; 16];
        b[0] = s;
        b[15] = s.wrapping_mul(37).wrapping_add(11);
        let cp = zx_pot::prove(PotSeed::from(b), NonZeroU32::new(it).unwrap()).unwrap();
        let obtenido: String = cp
            .iter()
            .flat_map(|o| o.iter())
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            obtenido, esperado,
            "divergencia en semilla {s}, {it} iteraciones"
        );
        assert!(zx_pot::verify(PotSeed::from(b), NonZeroU32::new(it).unwrap(), &cp).unwrap());
        n += 1;
    }
    assert_eq!(n, 32, "faltan vectores");
}
