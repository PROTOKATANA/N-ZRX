//! Tests de la familia de cuerpos de pruebas (`CP-R-27`…`CP-R-31`).
//!
//! No dependen de los tipos de `zx-core`: trabajan con huellas de 32 B y bytes opacos. El backend
//! de disco, la reapertura y la migración de esquema se prueban en `src/disco.rs` (que ya usa los
//! *fixtures* de bloque de `zx-core` para comprobar que podar no toca las otras familias).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use zx_storage::{
    AlmacenPruebas, AlmacenPruebasEnMemoria, EstadoPrueba, Huella, MAX_CUERPO_PRUEBA_BYTES,
};

fn huella(n: u8) -> Huella {
    [n; 32]
}

fn almacen() -> AlmacenPruebasEnMemoria {
    AlmacenPruebasEnMemoria::nuevo()
}

#[test]
fn guardar_y_obtener_por_huella() {
    let a = almacen();
    a.guardar(huella(0x11), 12, b"cuerpo-de-prueba")
        .expect("guarda");

    let estado = a.obtener(&huella(0x11)).expect("obtiene").expect("existe");
    assert_eq!(
        estado,
        EstadoPrueba::Presente {
            huella: huella(0x11),
            referencia: 12,
            cuerpo: b"cuerpo-de-prueba".to_vec(),
        }
    );
    assert_eq!(a.obtener(&huella(0x99)).expect("obtiene"), None);
}

#[test]
fn tras_podar_obtener_devuelve_podado_con_la_huella() {
    let a = almacen();
    a.guardar(huella(0x21), 7, b"cuerpo").expect("guarda");
    a.guardar(huella(0x22), 40, b"posterior").expect("guarda");

    assert_eq!(a.podar_hasta(7).expect("poda"), 1);

    let estado = a.obtener(&huella(0x21)).expect("obtiene").expect("existe");
    assert!(estado.esta_podado(), "el cuerpo se podó");
    assert_eq!(estado.huella(), huella(0x21), "devuelve la huella");
    assert_eq!(estado.referencia(), 7, "conserva el metadato");
    assert_eq!(estado.cuerpo(), None);

    // La entrada posterior al punto no se toca: podar no arrastra a las demás.
    let posterior = a.obtener(&huella(0x22)).expect("obtiene").expect("existe");
    assert!(!posterior.esta_podado());
    assert_eq!(posterior.cuerpo(), Some(b"posterior".as_slice()));

    // Idempotente.
    assert_eq!(a.podar_hasta(7).expect("poda otra vez"), 0);
}

#[test]
fn un_cuerpo_mayor_que_el_tope_se_rechaza() {
    let a = almacen();
    let grande = vec![0xEE; MAX_CUERPO_PRUEBA_BYTES + 1];
    let err = a
        .guardar(huella(0x31), 1, &grande)
        .expect_err("más que el tope MUST rechazarse");
    assert!(matches!(
        err,
        zx_storage::StorageError::CuerpoDemasiadoGrande { bytes, tope }
            if bytes == MAX_CUERPO_PRUEBA_BYTES + 1 && tope == MAX_CUERPO_PRUEBA_BYTES
    ));
    assert_eq!(a.obtener(&huella(0x31)).expect("obtiene"), None);
}

#[test]
fn la_misma_huella_con_otro_cuerpo_es_corrupcion() {
    let a = almacen();
    a.guardar(huella(0x41), 1, b"uno").expect("guarda");
    a.guardar(huella(0x41), 2, b"uno")
        .expect("el mismo cuerpo sube el punto");
    let estado = a.obtener(&huella(0x41)).expect("obtiene").expect("existe");
    assert_eq!(estado.referencia(), 2);

    let err = a
        .guardar(huella(0x41), 2, b"dos")
        .expect_err("otro cuerpo bajo la misma huella MUST fallar");
    assert!(matches!(err, zx_storage::StorageError::Corrupto { .. }));
}
