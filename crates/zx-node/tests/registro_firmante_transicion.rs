//! `ORDEN-SL4b3` verificación real (decisión 1): el registro del firmante de cada nodo contiene la
//! entrada del slot de su bloque de transición.
//!
//! Se ejecuta **explícitamente** después de la ejecución real corta (tres nodos cruzan el corte con
//! `--parada-tras-slots 1`, de modo que el único bloque PoST que firma cada nodo es su bloque de
//! transición):
//!
//! ```text
//! ZX_FIRMANTE_A=<run>/A/datos/firmante.registro \
//! ZX_FIRMANTE_B=<run>/B/datos/firmante.registro \
//! ZX_FIRMANTE_C=<run>/C/datos/firmante.registro \
//!   cargo test -p zx-node --test registro_firmante_transicion -- --ignored --nocapture
//! ```
//!
//! No se inventa un formato de lectura: se abre cada fichero con `zx_post::firmante::Registro::abrir`
//! (la API pública de lectura/validación del registro) y se consulta por la API: `entradas()` y
//! `max_slot()`. Con el arranque limpio de cada nodo (registro `nueva`, sin abstención) y la parada
//! en el slot 1, la única entrada posible es la del bloque de transición; su slot es `max_slot()`.
//!
//! Si el defecto 1 de `REVISION-SL4b2.md` reapareciera (transición sin firmante), `entradas()` sería
//! 0 y la aserción falla.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test de verificación con panic por diseño"
)]

use std::path::PathBuf;

use zx_post::firmante::Registro;

fn registro_de(variable: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("define {variable} con la ruta de firmante.registro"))
}

#[test]
#[ignore = "verificación de la ejecución real; se lanza con --ignored y las rutas en el entorno"]
fn el_registro_de_cada_nodo_contiene_la_entrada_de_su_transicion() {
    for variable in ["ZX_FIRMANTE_A", "ZX_FIRMANTE_B", "ZX_FIRMANTE_C"] {
        let ruta = registro_de(variable);
        let reg = Registro::abrir(&ruta, 0, 1).expect("el registro del firmante es válido");
        assert_eq!(
            reg.entradas(),
            1,
            "{variable}: con `--parada-tras-slots 1` el único bloque firmado debe ser la transición"
        );
        let slot = reg.max_slot();
        println!("{variable}: entrada del firmante en el slot de transición {slot}");
        assert!(
            slot > 0,
            "{variable}: el slot de la transición debe ser mayor que 0"
        );
    }
}
