//! FV-N6-C7 · reinicio local de votos: diario durable y observación sin firma.
//!
//! Integración real con el producto: arranca `Nodo` de verdad sobre un directorio temporal, con su
//! almacén, su semilla y su registro estructurado. Comprueba el contrato de arranque del diario:
//!
//! - directorio **nuevo**: se aprovisiona `votos.registro` antes de cualquier voto;
//! - directorio **previo** (almacén no vacío) sin diario: **no** se considera identidad nueva ni se
//!   crea un diario limpio; el nodo entra en observación sin firmar;
//! - diario **corrupto**: misma observación, sin excepción fatal ni recreación;
//! - reapertura con diario sano: vuelve a vincularlo.
//!
//! Límite declarado: no ejecuta aún la minería ni la segunda vuelta de certificado; eso queda para
//! el humo de cuatro procesos. Aquí se acredita el cableado durable observable por arranque real.

#![expect(clippy::expect_used, reason = "el test falla con expect por diseño")]

use std::path::{Path, PathBuf};

use zx_core::Red;
use zx_node::nodo::{Config, Nodo};

const N_DEV_TEST: &str = "32";
const SR_DEV_TEST: &str = "18446744073709551615";

fn config_de_test(dir: &Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 0x1234,
        indices_claves: vec![0, 1, 2],
        n_dev: N_DEV_TEST.parse().expect("N_dev"),
        sr_dev: SR_DEV_TEST.parse().expect("SR_dev"),
        perfil_red: zx_node::perfil::perfil_red_dev(),
        parada_tras_slots: None,
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

fn ruta_diario(cfg: &Config) -> PathBuf {
    cfg.dir_datos.join("votos.registro")
}

fn registro_texto(cfg: &Config) -> String {
    std::fs::read_to_string(&cfg.ruta_registro).unwrap_or_default()
}

#[test]
fn arranque_limpio_aprovisiona_diario_y_reabre_vinculado() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_test(dir.path());

    {
        let _nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
        let bytes = std::fs::read(ruta_diario(&cfg)).expect("diario aprovisionado");
        assert_eq!(
            bytes.get(..8),
            Some(b"ZXVOTOD1".as_slice()),
            "el diario tiene la magia esperada"
        );
    }

    // Reapertura con diario sano: se vuelve a vincular (mismo directorio conservado).
    let registro_previo = registro_texto(&cfg);
    let _nodo = Nodo::arrancar(&cfg).expect("reanudar con diario sano");
    let registro = registro_texto(&cfg);
    let nuevos = registro.get(registro_previo.len()..).unwrap_or("");
    assert!(
        nuevos.contains("\"tipo\":\"votos_arranque\""),
        "hay evento de arranque de votos: {nuevos}"
    );
    assert!(
        nuevos.contains("\"diario\":true") && nuevos.contains("\"observacion\":false"),
        "con diario sano no se observa: {nuevos}"
    );
}

#[test]
fn directorio_previo_sin_diario_entra_en_observacion_sin_firma() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_test(dir.path());

    {
        let _nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
    }
    // Se destruye el diario de un directorio que ya tiene almacén: no es una identidad nueva.
    std::fs::remove_file(ruta_diario(&cfg)).expect("quitar diario");
    let registro_previo = registro_texto(&cfg);

    let _nodo = Nodo::arrancar(&cfg).expect("reanudar sin diario");
    let registro = registro_texto(&cfg);
    let nuevos = registro.get(registro_previo.len()..).unwrap_or("");
    assert!(
        nuevos.contains("\"tipo\":\"votos_arranque\""),
        "hay evento de arranque de votos: {nuevos}"
    );
    assert!(
        nuevos.contains("\"observacion\":true"),
        "sin diario en directorio previo se observa sin firmar: {nuevos}"
    );
    assert!(
        !ruta_diario(&cfg).exists(),
        "no se creó un diario limpio para habilitar la firma"
    );
}

#[test]
fn diario_corrupto_entra_en_observacion_sin_recrear() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_test(dir.path());

    {
        let _nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
    }
    // Cola parcial: un diario que no reabre debe observarse, no recrearse.
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(ruta_diario(&cfg))
            .expect("abrir diario");
        f.write_all(&[0u8; 5]).expect("corromper");
        f.sync_all().expect("sync");
    }
    let registro_previo = registro_texto(&cfg);

    let _nodo = Nodo::arrancar(&cfg).expect("reanudar con diario corrupto");
    let registro = registro_texto(&cfg);
    let nuevos = registro.get(registro_previo.len()..).unwrap_or("");
    assert!(
        nuevos.contains("\"observacion\":true"),
        "diario corrupto entra en observación: {nuevos}"
    );
    assert!(
        !nuevos.contains("\"diario\":true"),
        "no se declara diario sano: {nuevos}"
    );
}
