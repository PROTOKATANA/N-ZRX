//! Crate `zx-poas`: verificador PoAS, historia génesis dev, protocolo dev y reto de auditoría.
//!
//! Tres piezas, todas ancladas al mismo objetivo (D-P12):
//!
//! - [`verificador`]: adapta `subspace_verification::verify_solution` a
//!   [`zx_core::SolucionPoas`] (paso 5 de `C-POT-08`). Portado **sin cambio de lógica** de
//!   `crates/zx-consensus/src/poas.rs` de `9681061`.
//! - [`historia`]: archiva el cuerpo del génesis dev de W04 con el `Archiver` real del clon
//!   fijado, rellenado hasta `RecordedHistorySegment::SIZE` con `ChaCha8Rng` sembrado con
//!   `block_hash(génesis)` (D-P12), y expone el segmento 0, el KZG, el erasure coding, el
//!   `FarmerProtocolInfo` dev y el `PieceCheckParams` coherente.
//! - [`protocolo_dev`]: los valores de desarrollo (`history_size = 1`, `max_pieces_in_sector = 2`,
//!   `recent_segments = 5`, `recent_history_fraction = (1, 10)`, `min_sector_lifetime = 4`),
//!   etiquetados `dev`.
//!
//! [`reto`] mantiene además el reto de auditoría puro (`reto_desde_salida`), que `zx-farmer`
//! necesita y no puede tomar de `zx-consensus`: es un hash de sus argumentos, no una verificación
//! PoT.
//!
//! # Lo que este crate NO hace
//!
//! No valida PoT, ni cabecera, ni cuerpo, ni DAG, ni orden, ni admisión. `verificar_solucion_poas`
//! recibe el slot, la salida y el rango **ya validados por el pasado** como argumentos y no
//! acredita su procedencia. No hay ninguna función que declare válido un bloque.

#![doc = include_str!("../README.md")]

pub mod historia;
pub mod protocolo_dev;
pub mod reto;
pub mod verificador;

pub use historia::{
    COMPROMISO_HISTORIA_GENESIS_DEV, ErrorHistoriaGenesis, HistoriaGenesis, a_segment_commitment,
    comprobar_compromiso, raiz_de_segment_commitment,
};
pub use protocolo_dev::{
    FRACCION_RECIENTE_DIVISOR_DEV, FRACCION_RECIENTE_MULTIPLICADOR_DEV, PIEZAS_POR_SECTOR_DEV,
    SEGMENTOS_RECIENTES_DEV, TAMANO_HISTORIA_DEV, VIDA_MINIMA_SECTOR_DEV, a_tamano_historia,
    parametros,
};
pub use reto::{ALEATORIEDAD_BYTES, aleatoriedad_de_salida, reto_desde_salida};
pub use verificador::{ContextoInvalido, ErrorPoas, verificar_solucion_poas};
