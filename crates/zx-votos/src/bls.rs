//! Dominio y mensaje de la firma del voto (contrato v2 A3).
//!
//! **M9-b2:** aquí vivía la verificación BLS del certificado de plazas (`CertificadoBls`,
//! `verificar_certificado_bls`), retirada con el sorteo. La verificación real del certificado
//! compacto por peso vive en [`crate::peso::verificar_firma_peso`]. Se conservan el dominio de
//! firma y el constructor del mensaje porque los usan el `0x08` (voto propio) y el `0x0B`
//! (evidencia de dos votos) del consenso, y `peso.rs`.

use crate::serial::hash_bytes;
use crate::tipos::{Hash, LONGITUD_HASH};

/// Dominio de separación de ZEROX para la firma del voto.
///
/// El contrato `C-FV-*` no lo fija; se usa el dominio de ejemplo de la documentación de `zx-bls`
/// (ver `PROGRESO.md` §2, definición 3).
pub const DOMINIO_VOTO: &[u8] = b"ZX-FINALIDAD-VOTO";

/// Mensaje que firma un voto: `SHA256(n_u64_be ‖ h_B ‖ h_T(n+1) ‖ h_cand)` (C-FV-04).
#[must_use]
pub fn mensaje_voto(n: u64, h_b: &Hash, h_t_siguiente: &Hash, h_cand: &Hash) -> Hash {
    let mut bytes = Vec::with_capacity(8 + 3 * LONGITUD_HASH);
    bytes.extend_from_slice(&n.to_be_bytes());
    bytes.extend_from_slice(h_b);
    bytes.extend_from_slice(h_t_siguiente);
    bytes.extend_from_slice(h_cand);
    hash_bytes(&bytes)
}
