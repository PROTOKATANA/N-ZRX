//! `ORDEN-W06d1` V6 y decisión 2: la red configurada distinta de `Red::Dev` se rechaza **antes**
//! de abrir disco o parcelas, con código de error explícito y sin crear ningún fichero.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]

use zx_core::Red;
use zx_node::error::ErrorNodo;
use zx_node::nodo::{Config, Nodo};

fn config_con_red(dir: &std::path::Path, red: Red) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red,
        semilla: 1,
        indices_claves: vec![0, 1, 2],
        n_dev: 32,
        sr_dev: u64::MAX,
        perfil_red: zx_node::perfil::perfil_red_dev(),
        parada_tras_slots: Some(1),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

#[test]
fn mainnet_se_rechaza_sin_crear_nada() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_con_red(dir.path(), Red::Mainnet);
    let resultado = Nodo::arrancar(&cfg);
    match resultado {
        Err(ErrorNodo::RedNoEsDev {
            encontrada: Red::Mainnet,
        }) => {}
        Err(otro) => panic!("se esperaba RedNoEsDev, se obtuvo otro error: {otro}"),
        Ok(_) => panic!("se esperaba RedNoEsDev, arrancó"),
    }
    assert!(
        !cfg.dir_datos.exists(),
        "no debe crearse el directorio de datos si la red no es dev"
    );
    assert!(
        !cfg.ruta_registro.exists(),
        "no debe crearse el registro si la red no es dev"
    );
}

#[test]
fn testnet_se_rechaza_sin_crear_nada() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_con_red(dir.path(), Red::Testnet);
    let resultado = Nodo::arrancar(&cfg);
    match resultado {
        Err(ErrorNodo::RedNoEsDev {
            encontrada: Red::Testnet,
        }) => {}
        Err(otro) => panic!("se esperaba RedNoEsDev, se obtuvo otro error: {otro}"),
        Ok(_) => panic!("se esperaba RedNoEsDev, arrancó"),
    }
    assert!(!cfg.dir_datos.exists());
}
