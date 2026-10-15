//! Huella del carril de pruebas recursivas (`CP-R-02`).
//!
//! `huella = H_d("ZZKPruebaCarril_", cuerpo_canónico)`: 32 B que identifican el objeto y
//! **no** dependen del nivel de compresión, del diccionario ni de la versión de ZRX-C. La
//! compresión es transporte, nunca identidad (`REVISION-PT3j-4.md:11-12`).
//!
//! La etiqueta mide exactamente 16 B y sigue la convención `DomainTag::fija` de
//! `zx-core::hash` (C-HASH-04). `h_d` es `pub(crate)` en `zx-core` a propósito, así que esta
//! etiqueta nueva se implementa aquí con el mismo `SHA3-256(tag ‖ msg)`, igual que `zx-merkle`.

use sha3::{Digest as _, Sha3_256};

/// Etiqueta de dominio de la huella del carril (16 B, C-HASH-04).
pub const TAG_HUELLA: [u8; 16] = *b"ZZKPruebaCarril_";

/// Hash con dominio `H_d(tag ‖ msg) = SHA3-256(tag ‖ msg)` (C-HASH-04).
///
/// La etiqueta es de longitud fija (16 B), así que ninguna puede ser prefijo propio de otra
/// y la construcción es inyectiva. SHA-3 no sufre extensión de longitud.
#[must_use]
pub fn h_d(tag: [u8; 16], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(tag);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Huella de una prueba recursiva sobre su **cuerpo canónico descomprimido** (`CP-R-02`).
#[must_use]
pub fn huella(cuerpo_canonico: &[u8]) -> [u8; 32] {
    h_d(TAG_HUELLA, cuerpo_canonico)
}
