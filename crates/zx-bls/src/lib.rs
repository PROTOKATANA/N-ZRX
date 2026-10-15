//! # `zx-bls` — firma BLS12-381 de ZEROX sobre `blst`
//!
//! Crate de la firma de la finalidad por votos (PK-04, `ORDEN-BLS1`). Envuelve el crate oficial
//! [`blst`] (Supranational, versión exacta `=0.3.17`) con el esquema de **prueba de posesión**
//! del borrador IRTF de firmas BLS, en su variante *minimal-pubkey-size*:
//!
//! - **claves** en G1, 48 bytes comprimidos;
//! - **firmas** en G2, 96 bytes comprimidos;
//! - DST de firma `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` y de prueba de posesión
//!   `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
//!
//! ## Garantías
//!
//! - `#![forbid(unsafe_code)]`: el `unsafe` de `blst` queda detrás de su API segura y confinado en
//!   este crate (`ci/frontera-crates.sh` impide que otro crate dependa de `blst`).
//! - Toda clave pública y toda firma se **deserializan con comprobación de subgrupo** y con rechazo
//!   del punto del infinito ([`ClavePublica::desde_bytes`], [`Firma::desde_bytes`]).
//! - Ninguna entrada externa provoca un `panic`: los rechazos viajan como [`ErrorBLS`].
//! - Las operaciones de consenso llevan **separación de dominios de ZEROX**: exigen un `dominio`
//!   no vacío y firman `len_u16_be || dominio || mensaje` (ver [`firmar`], [`verificar`]).
//!
//! ## Capas
//!
//! - la **API de ZEROX** ([`firmar`], [`verificar`], [`agregar_firmas`],
//!   [`fast_aggregate_verify`], [`aggregate_verify`], [`verificar_lote_con_escalares`],
//!   [`probar_posesion`], [`verificar_posesion`]) aplica el prefijo de dominio;
//! - la capa [`crudo`] es la primitiva sin prefijo, que existe para reproducir los vectores
//!   oficiales del borrador (`ethereum/bls12-381-tests`) y como implementación interna. **No debe
//!   usarse desde el consenso.**
//!
//! ## Ejemplo
//!
//! ```
//! use zx_bls::{agregar_firmas, fast_aggregate_verify, firmar, verificar, ClaveSecreta};
//!
//! # fn main() -> Result<(), zx_bls::ErrorBLS> {
//! let sk = ClaveSecreta::generar(&[0x42; 32])?;
//! let pk = sk.clave_publica();
//! let dominio = b"ZX-FINALIDAD-VOTO";
//! let mensaje = b"certificado";
//!
//! let firma = firmar(&sk, dominio, mensaje)?;
//! verificar(&pk, &firma, dominio, mensaje)?;
//!
//! let agregada = agregar_firmas(&[&firma])?;
//! fast_aggregate_verify(&[&pk], &agregada, dominio, mensaje)?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod agregada;
mod api;
mod clave;
mod dominio;
mod error;
mod firma;

/// Primitiva sin separación de dominio de ZEROX (vectores oficiales y uso interno).
pub mod crudo;

pub use agregada::ClaveAgregada;
pub use api::{
    aggregate_verify, agregar_firmas, fast_aggregate_verify, firmar, probar_posesion, verificar,
    verificar_agregado_con_clave, verificar_lote_con_escalares,
    verificar_lote_de_agregados_con_clave, verificar_lote_de_agregados_con_escalares,
    verificar_posesion,
};
pub use clave::{
    ClavePublica, ClaveSecreta, LONGITUD_CLAVE_PUBLICA, LONGITUD_CLAVE_SECRETA, MEMORIA_CLAVES_MAX,
};
pub use crudo::{AgregadoLote, LONGITUD_ESCALAR_LOTE};
pub use dominio::mensaje_con_dominio;
pub use error::ErrorBLS;
pub use firma::{Firma, FirmaAgregada, LONGITUD_FIRMA};

pub use clave::ClavesPreparadas;
