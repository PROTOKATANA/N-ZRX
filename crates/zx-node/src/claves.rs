//! Claves dev del nodo: derivación determinista desde una semilla y un índice (CLI, decisión 10).
//!
//! **Solo dev.** La derivación es `blake3("zx-node/clave-dev/v1" || semilla_le(8) ||
//! indice_le(4))[0..32)` como bytes de la `SigningKey` Ed25519. No es una ruta de seguridad de red:
//! es la manera reproducible de que `--semilla 1 --claves 0,1,2` dé siempre las mismas tres claves
//! en cualquier máquina, para poder repetir un escenario exactamente.

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::ClavePublica;

/// Dominio de la derivación de claves dev (no es una etiqueta de consenso: nunca entra en un hash de
/// bloque, solo decide qué bytes locales usa el binario para firmar).
const DOMINIO_CLAVE_DEV: &[u8] = b"zx-node/clave-dev/v1";

/// Una clave dev del nodo: su índice, su clave de firma y su clave pública.
#[derive(Clone)]
pub struct ClaveDev {
    /// Índice con el que se derivó (para el registro y los nombres de fichero de la parcela).
    pub indice: u32,
    /// Clave de firma Ed25519.
    pub sk: SigningKey,
    /// Clave pública correspondiente.
    pub pk: ClavePublica,
}

impl ClaveDev {
    /// Deriva la clave dev `indice` de la `semilla` dada.
    #[must_use]
    pub fn derivar(semilla: u64, indice: u32) -> Self {
        let mut mensaje = Vec::with_capacity(DOMINIO_CLAVE_DEV.len() + 8 + 4);
        mensaje.extend_from_slice(DOMINIO_CLAVE_DEV);
        mensaje.extend_from_slice(&semilla.to_le_bytes());
        mensaje.extend_from_slice(&indice.to_le_bytes());
        let digest = zx_core::sha3_256_publico(&mensaje);
        let sk = SigningKey::from(*digest.as_bytes());
        let vk = VerificationKey::from(&sk);
        let pk = ClavePublica::desde_bytes(vk.into());
        Self { indice, sk, pk }
    }

    /// Deriva varias claves dev de la misma semilla, en el orden de `indices`.
    #[must_use]
    pub fn derivar_varias(semilla: u64, indices: &[u32]) -> Vec<Self> {
        indices.iter().map(|i| Self::derivar(semilla, *i)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::ClaveDev;

    #[test]
    fn es_determinista_y_distinta_por_indice() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 0);
        let c = ClaveDev::derivar(1, 1);
        let d = ClaveDev::derivar(2, 0);
        assert_eq!(a.pk, b.pk, "misma semilla e índice ⇒ misma clave");
        assert_ne!(a.pk, c.pk, "distinto índice ⇒ distinta clave");
        assert_ne!(a.pk, d.pk, "distinta semilla ⇒ distinta clave");
    }
}
