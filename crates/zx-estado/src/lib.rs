//! `zx-estado` — el árbol de la raíz de estado (pieza A1, paso a).
//!
//! Crate **genérico**: familia, clave y valor son bytes; no conoce el `Estado` de consenso ni
//! depende de `zx-consensus` ni de `zx-node`. Implementa el diseño de
//! `P-ZRX/P-CARRILES/ER1/RAIZ-ESTADO.md` §3 y §5:
//!
//! - un **trie binario compacto de Patricia** por familia, con compromiso de Merkle por nodo, claves
//!   en un camino de 56 bits y lista de colisión en la hoja;
//! - la **actualización en lote** (orden por familia y clave, la última gana, borrar es un cambio,
//!   **una** escritura atómica) y lecturas en paralelo;
//! - la **raíz de 32 B** a partir de las raíces de las familias y un resumen de escalares que se le
//!   pasa hecho;
//! - las **pruebas de pertenencia y de no pertenencia** y su verificador;
//! - dos almacenes tras la misma interfaz: [`AlmacenEnMemoria`] y (con la feature `rocksdb`)
//!   [`AlmacenRocks`].
//!
//! ## Ejemplo
//!
//! ```
//! use zx_estado::{AlmacenEnMemoria, Cambio, CaminoSha3, Estado};
//!
//! let mut estado = Estado::nuevo(AlmacenEnMemoria::nuevo(), CaminoSha3);
//! let cambios = [Cambio::poner(0x01, b"clave".to_vec(), b"valor".to_vec())];
//! let raices = estado.aplicar(&cambios, 1).expect("lote");
//! let raiz = raices.first().expect("familia tocada").1;
//! let prueba = estado.prueba(0x01, b"clave").expect("prueba");
//! assert!(estado.verificar(&raiz, 0x01, b"clave", Some(b"valor"), &prueba));
//! ```

#![forbid(unsafe_code)]

pub mod almacen;
pub mod arbol;
pub mod camino;
pub mod canon;
pub mod error;
pub mod estado;
pub mod hash;
pub mod lote;
pub mod nodo;
pub mod prueba;
pub mod rng;
#[cfg(feature = "rocksdb")]
pub mod rocks;

pub use almacen::{Almacen, AlmacenEnMemoria, Nodos, Overlay, reconstruir_familia};
pub use arbol::{borrar, insertar, reconstruir};
pub use camino::{Camino, CaminoSha3};
pub use canon::{
    VERSION_CANON, cambios_de_undo, h_escalares, h_escalares_con_version, h_libro, hoja_caja,
    hoja_clave_voto, hoja_garantia, hoja_porep, hoja_prueba, hoja_sector, hoja_ultimo_slot,
    hoja_utxo, hojas_de_estado, raiz_de_estado,
};
pub use error::Error;
pub use estado::Estado;
pub use hash::{FAMILIAS, Hash32, VERSION_ESTRUCTURA, hash_vacio, hash_valor, raiz_estado};
pub use lote::{Cambio, aplicar, aplicar_normalizado, normalizar};
pub use prueba::{MAX_NIVELES, Prueba, TAMANO_MAXIMO_PRUEBA, Terminal, prueba, verificar};
pub use rng::SplitMix64;
#[cfg(feature = "rocksdb")]
pub use rocks::AlmacenRocks;
