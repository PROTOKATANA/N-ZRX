//! Compresión ZSTD de ZEROX (ZRX-C).
//!
//! Este crate es la **única** implementación de ZRX-C desde ZC-4: el marco, los
//! topes, el diccionario y la verificación viven aquí, y `zx-p2p` lo consume. Ver
//! el `README.md` del crate para el formato del marco y las reglas.

#![doc = include_str!("../README.md")]

pub mod dict;
pub mod error;
pub mod limites;
pub mod marco;

pub use dict::{DICT_ID_TX, Diccionario, diccionario, diccionario_tx};
pub use error::ErrorCompresion;
pub use limites::Limites;
pub use marco::{
    ALG_ALMACENADO, ALG_ZSTD, ALGORITMO_ZSTD, CABECERA, Cabecera, MAGIA, MAGIC, MARCA_ZRXC,
    MAX_RATIO, Metricas, NIVEL, NIVEL_DISCO, TAMANO_CABECERA, UMBRAL_MINIMO_BYTES, VERSION,
    anuncia_zrxc, cabecera, comprimir, comprimir_red, descomprimir, descomprimir_por_id, es_marco,
    esta_comprimido, leer_cabecera, xxh64,
};
