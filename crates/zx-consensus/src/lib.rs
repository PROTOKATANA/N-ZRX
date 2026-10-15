//! Motor PoW de la fase de arranque para la red dev (D-P05, D-T01).
//!
//! Todo lo de aquí es **consensus-critical**: una divergencia de un bit entre dos nodos es un split
//! de cadena. Cada elemento cita la regla `C-XXX` del SPEC que implementa.
//!
//! El retarget, la selección por trabajo, los timestamps, el génesis y el verificador están
//! **parametrizados por red** ([`ParametrosPow`]) en vez de con constantes globales. El `hash_pow`
//! vive detrás de [`AlgoritmoPow`]; su implementación dev es [`Sha3Dev`].

#![doc = include_str!("../README.md")]

pub mod activacion;
pub mod algoritmo;
pub mod cajas;
pub mod dificultad;
pub mod error;
pub mod evidencia_agregados;
pub mod fork_choice;
pub mod genesis;
pub mod minero_dev;
pub mod parametros;
pub mod prueba_almacenamiento;
pub mod sectores;
pub mod timestamps;
pub mod transicion;
pub mod verificador;

pub use activacion::{
    RAMA_DEV, RAMA_V1_MAINNET, RAMAS_DEV, RAMAS_MAINNET, RAMAS_TESTNET, Rama, Red,
    comprobar_branch_id, comprobar_tabla, rama_activa, ramas,
};
pub use algoritmo::{AlgoritmoPow, Sha3Dev};
pub use dificultad::{BIAS_DEN, BIAS_NUM, VentanaRetarget, median_time_past, siguiente_target};
pub use error::ErrorPow;
pub use fork_choice::{Preferencia, Tip, preferir, trabajo_acumulado};
pub use genesis::{
    GENESIS_DEV, GENESIS_MAINNET, GENESIS_TESTNET, HASH_GENESIS_DEV, HASH_GENESIS_TESTNET,
    ParametrosGenesis, TIMESTAMP_MINIMO_GENESIS, VERSION_TX, coinbase_genesis, comprobar,
    comprobar_al_arrancar, construir, hash, hash_congelado, target_inicial_bits, txid_coinbase,
};
pub use minero_dev::minar;
pub use parametros::{PARAMETROS_POW_ANTIGUOS, PARAMETROS_POW_DEV, ParametrosPow, limites_de};
pub use timestamps::{
    BANDA_SLOT_DEV, ErrorTimestampPost, FTL_POST_DEV, M_TS_DEV, PERFIL_TIMESTAMP_POST_DEV,
    ParametrosTimestampPost, comprobar_banda_ts_slot, comprobar_ftl, comprobar_ftl_post,
    comprobar_monotonia, comprobar_pmt, comprobar_timestamp_post, pmt, timestamp_del_minero,
};
pub use verificador::{ContextoPow, validar_cabecera_pow};
