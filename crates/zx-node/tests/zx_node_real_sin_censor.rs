//! `ORDEN-AD2` §3 prueba 2 (vigente en `ORDEN-AD2-2`): el binario real `zx-node` no ofrece ninguna
//! opción de censura y el manejador que arranca es el real, no el envoltorio.
//!
//! **Cómo se demuestra.**
//!
//! 1. **Dinámico:** se ejecuta el binario real recién construido (`CARGO_BIN_EXE_zx-node`) con
//!    `--help` y se comprueba que termina con éxito y que su salida **no** nombra la censura (ni
//!    `censor`, ni `censura`, ni `censurar`). El binario real no gana ninguna opción: su CLI es la de
//!    siempre.
//! 2. **Estático sobre el camino de arranque:** se incluye `src/main.rs` en tiempo de compilación y
//!    se comprueba que el único arranque de red que usa es `red::arrancar_con_datos` (el que
//!    construye el [`zx_node::red::manejador::ManejadorRed`] real) y que no menciona ni el *seam*
//!    `arrancar_con_manejador` ni el envoltorio `ManejadorCensor`. El envoltorio sólo puede entrar
//!    por `arrancar_con_manejador`, que `zx-node` no llama.
//! 3. Se comprueba además que existe el binario aparte `zx-censor`: la capacidad vive en un binario
//!    distinto, no en el real.

#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]

use std::process::Command;

/// El manejador real de `zx-node` y su CLI quedan fuera del censor (`ORDEN-AD2` C1).
#[test]
fn zx_node_real_sin_censor() {
    let salida = Command::new(env!("CARGO_BIN_EXE_zx-node"))
        .arg("--help")
        .output()
        .expect("ejecutar `zx-node --help`");
    assert!(
        salida.status.success(),
        "`zx-node --help` falló: {:?}",
        salida.status
    );
    let texto = format!(
        "{}{}",
        String::from_utf8_lossy(&salida.stdout),
        String::from_utf8_lossy(&salida.stderr)
    );
    let minusculas = texto.to_lowercase();
    for palabra in ["censor", "censura", "censurar"] {
        assert!(
            !minusculas.contains(palabra),
            "el --help de zx-node nombra {palabra:?}: {texto}"
        );
    }

    // El arranque del binario real usa el constructor del manejador real, no el seam del censor.
    let main = include_str!("../src/main.rs");
    assert!(
        main.contains("arrancar_con_datos"),
        "main.rs no arranca la red con el manejador real"
    );
    for prohibido in ["arrancar_con_manejador", "ManejadorCensor", "zx-censor"] {
        assert!(
            !main.contains(prohibido),
            "el camino honesto de main.rs menciona {prohibido:?}"
        );
    }

    // La capacidad de censura vive en un binario aparte.
    let censor = env!("CARGO_BIN_EXE_zx-censor");
    assert!(
        std::path::Path::new(censor).exists(),
        "no existe el binario aparte zx-censor: {censor}"
    );
}
