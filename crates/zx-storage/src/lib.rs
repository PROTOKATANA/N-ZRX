//! Almacén de bloques admitidos y registro de admisión (decisión D-N03′).
//!
//! La pregunta falsable de W06b: tras cualquier secuencia de admisiones interrumpida por la muerte
//! del proceso en un punto arbitrario, el almacén reabre con un **prefijo exacto** de lo confirmado
//! —ni bloques a medias ni entradas del registro sin su bloque—, **rechaza con error explícito**
//! cualquier corrupción de bytes, y la repetición entrega los bloques **en el mismo orden y con los
//! mismos bytes**.
//!
//! # Piezas
//!
//! - [`almacen`]: el rasgo [`Almacen`] —admitir, leer, repetir— y [`BloqueAdmitido`], el bloque con
//!   su familia y sus bytes canónicos.
//! - [`formato`]: el sobre de disco `familia(1) ‖ bloque canónico`, el recálculo del hash con el
//!   código de `zx-core` y la exigencia de forma canónica.
//! - [`memoria`]: la implementación de referencia, para los tests rápidos.
//! - [`disco`]: la implementación sobre RocksDB, tras la feature `rocksdb`.
//! - [`pruebas`]: la familia de cuerpos de pruebas por huella de 32 B, con retención y poda
//!   (`CP-R-27`…`CP-R-31`).
//! - [`error`]: [`StorageError`], que traduce toda anomalía en un error visible.

#![doc = include_str!("../README.md")]

pub mod almacen;
#[cfg(feature = "rocksdb")]
pub mod disco;
pub mod error;
pub mod formato;
pub mod memoria;
pub mod pruebas;

pub use almacen::{Almacen, BloqueAdmitido, ErrorRepeticion};
#[cfg(feature = "rocksdb")]
pub use disco::AlmacenEnDisco;
pub use error::StorageError;
pub use formato::{Familia, VERSION_ESQUEMA, VERSION_ESQUEMA_ZSTD};
pub use memoria::AlmacenEnMemoria;
pub use pruebas::{
    AlmacenPruebas, AlmacenPruebasEnMemoria, EstadoPrueba, Huella, LONGITUD_HUELLA,
    MAX_CUERPO_PRUEBA_BYTES, Referencia,
};
