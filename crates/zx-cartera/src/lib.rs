//! `zx-cartera` — cartera dev de ZEROX (TX-4).
//!
//! Genera claves dev, **construye y firma** transacciones (transferencias v1, depósitos v2 y
//! retiros/liberaciones de garantía) a partir de las salidas que se le indican, y su binario las
//! envía por el tema de transacciones de `zx-p2p`. **No** habla RPC: es una cartera offline que
//! recibe sus `OutPoint` por argumento o archivo, y solo usa la red para difundir.
//!
//! # Frontera
//!
//! Reutiliza `zx-core` (preimagen, sighash, txid, forma, verificación y wire) y `zx-p2p`
//! (transporte). **No** reimplementa firmas ni formatos, y **no** depende de `zx-node` (la frontera
//! de `ci/frontera-crates.sh` lo prohíbe). La única pieza que repite es la **derivación dev de
//! claves**, para que nodo y cartera coincidan byte a byte (ver [`claves`]).
//!
//! # Ejemplo
//!
//! ```no_run
//! use zx_cartera::{ClaveCartera, retiro_v2};
//! use zx_core::amount::Amount;
//!
//! let clave = ClaveCartera::derivar(101, 3);
//! let importe = Amount::nuevo(1).expect("1 brek");
//! let retiro = retiro_v2(&clave, importe, 1).expect("retiro firmado");
//! assert!(retiro.verificar().is_ok());
//! ```

#![forbid(unsafe_code)]

pub mod claves;
pub mod error;
pub mod tx;

pub use claves::{ClaveCartera, DOMINIO_CLAVE_DEV};
pub use error::ErrorCartera;
pub use tx::{
    Entrada, TxFirmada, deposito_v2, firma_de_entrada, firma_desde_bytes, firmar, firmar_crudo,
    liberacion_v2, retiro_v2, transferencia_v1,
};

/// Rama de consenso de la red dev: la cartera solo firma para dev en TX-4.
pub const CBID: u32 = zx_core::CBID_RED_DEV;
