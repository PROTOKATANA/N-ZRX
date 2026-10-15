//! Property tests de los parsers DAG: bytes arbitrarios no deben entrar en pánico (C-WIRE-05).
//!
//! # Semilla y reproducibilidad (H-08b)
//!
//! Por defecto `proptest` siembra con entropía del sistema, y un fallo encontrado hoy no se
//! reproduce mañana. Aquí la semilla **se fija en el código**, no en el entorno:
//!
//! - `rng_seed: RngSeed::Fixed(SEMILLA)` con la semilla maestra del proyecto, `0x5a5a` — la misma
//!   de `veritas/LINEO.md` y de `veritas/finalidad/delta-medido-v1/`;
//! - `cases = 256`;
//! - un fichero de regresiones **en el árbol del proyecto** (`parsers_dag_prop-regresiones`, junto
//!   a este fuente), de modo que todo caso que falle se persista y se reejecute después.
//!
//! Basta con:
//!
//! ```text
//! cargo test --offline --locked -j 2 -p zx-core --test parsers_dag_prop
//! ```
//!
//! **Sin variables de entorno.** Medido: dos corridas seguidas generan la misma secuencia de 256
//! casos; con `RngSeed::Random` en su lugar, difieren.
//!
//! **Pero el entorno sigue mandando si alguien lo usa.** El macro `proptest!` vuelve a aplicar las
//! variables sobre la configuración que recibe (`contextualize_config`, `sugar.rs:226`), así que
//! `PROPTEST_RNG_SEED=<n>` **sí** sobrescribe esta semilla. Comprobado. No se puede cerrar desde
//! aquí: una corrida con esa variable puesta no es la corrida documentada, y quien la ponga debe
//! decirlo.
//!
//! Nota sobre el nombre de la variable, que costó una ronda de revisión: `proptest` no conoce
//! ninguna `PROPTEST_SEED` —la ignora con un aviso que `cargo test` se traga salvo con
//! `--nocapture`—. La suya es `PROPTEST_RNG_SEED`, y se parsea como `u64` **decimal**: un `0x5a5a`
//! tampoco vale (`0x5a5a` = `23130`).
//!
//! El objetivo no es cubrir la semántica —eso lo hacen los tests dirigidos— sino que ninguna
//! entrada arbitraria provoque un `panic`, que en un parser de red es un DoS remoto de una línea.

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

/// Semilla maestra del proyecto (`veritas/LINEO.md`). `0x5a5a` = `23130`.
const SEMILLA: u64 = 0x5a5a;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        rng_seed: RngSeed::Fixed(SEMILLA),
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regresiones"))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn dag_header_desde_bytes_no_entra_en_panico(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = zx_core::dag_header_desde_bytes(&bytes);
    }

    #[test]
    fn bloque_dag_desde_bytes_no_entra_en_panico(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = zx_core::bloque_dag_desde_bytes(&bytes);
    }
}
