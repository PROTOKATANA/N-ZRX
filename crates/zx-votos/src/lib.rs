//! # `zx-votos` — finalidad por votos de ZEROX (FV-4a)
//!
//! Biblioteca pura que implementa el contrato `C-FV-01…C-FV-12` de
//! `P-ZRX/P-FINALIDAD-VOTOS/FV3/CONTRATO-FV-v1.md` con las decisiones `FV-D01…FV-D08` y la firma
//! BLS de `zx-bls` (`REVISION-BLS1.md`). **No** cablea `zx-node` ni `zx-consensus` (eso es FV-4b).
//!
//! ## Qué hace
//!
//! - **Peso efectivo y total** (`CONTRATO-VOTOS-v2` A1): `w_i = peso_i·(1+(b−1)·prueba_i)` y `W`,
//!   reutilizando `binomial`.
//! - **Tabla de poder** A4: `serial(T_n)` y `h_T(n)` con SHA-256 ([`serial_tabla`], [`hash_tabla`]).
//! - **Certificado compacto y acta** (A5/A6): [`peso::evaluar_certificado`] comprueba el mapa de
//!   bits, la firma agregada, el encadenado y el quórum `3·Σ ≥ 2·W` con el vocabulario cerrado de
//!   [`MotivoPeso`].
//! - **Falta por ausencia** (`CONTRATO-VOTOS-v2` A7): el deber lo decide el consenso con el peso
//!   efectivo; [`ParametrosPerfil::multa_ausencia`] conserva el parámetro de perfil.
//!
//! ## Qué no hace
//!
//! No decide arquitectura ni parámetros de consenso, y no toca el nodo. La fuente de peso
//! definitiva (sectores registrados con garantía de la identidad de la clave, FV-D01) está detrás
//! del trait [`FuentePeso`]; la implementación [`FuenteSectores`] la materializa.
//!
//! ## M9-b2
//!
//! Se retiraron la evaluación por plazas, el sorteo y su VRF (`ancla`, `modelo`, `vrf`, `vectores`
//! y el reparto R-prop de `binomial`). Solo queda el flujo por peso. El lector JSONL `json` es
//! **privado y solo de test**: lo usa el diferencial de `peso` contra los 21 vectores de
//! `tests/datos/pdm1/`.

#![forbid(unsafe_code)]

pub mod agregacion;
pub mod agregador;
pub mod binomial;
pub mod bls;
pub mod error;
pub mod perfil;
pub mod peso;
pub mod serial;
pub mod tipos;
pub mod ventana_raices;

#[cfg(test)]
mod json;

pub use bls::{DOMINIO_VOTO, mensaje_voto};
pub use error::ErrorVotos;
pub use perfil::{
    EstadoFinalidad, FuentePeso, FuenteSectores, ParametrosPerfil, clave_desde_fuente,
    estado_finalidad,
};
pub use peso::{
    CertPrevioPeso, CertificadoPeso, EntradaPeso, LONGITUD_FIJA_CERTIFICADO_PESO, MotivoPeso,
    ResultadoPeso, construir_certificado, deserializar_certificado_peso, evaluar_certificado,
    firmantes_de_mapa, mensaje_voto_peso, peso_de_clave, peso_total_u128, quorum_peso,
    serial_certificado_peso, umbral_peso, verificar_firma_peso,
};
pub use serial::{hash_tabla, serial_tabla};
pub use tipos::{Clave, Hash, LONGITUD_HASH, Tabla};

/// Re-export mínimo de `zx-bls` que exige el cableado de `zx-node` (FV-4b-N1): firmar el voto,
/// agregar firmas y verificar el certificado. `zx-node` depende de `zx-votos` y **no** de `zx-bls`
/// (frontera `ci/frontera-crates.sh`), así que los tipos de firma entran por aquí.
pub use zx_bls::{
    ClavePublica, ClaveSecreta, ErrorBLS, Firma, FirmaAgregada, LONGITUD_CLAVE_PUBLICA,
    LONGITUD_FIRMA, agregar_firmas, fast_aggregate_verify, firmar, probar_posesion, verificar,
    verificar_posesion,
};
