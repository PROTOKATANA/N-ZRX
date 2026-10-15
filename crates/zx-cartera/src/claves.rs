//! Claves dev de la cartera.
//!
//! # Por qué la derivación es la del nodo, y no una nueva
//!
//! Una transacción de la cartera solo es válida si la clave pública que firma coincide con la que
//! el nodo puso en la salida. Los nodos dev construyen sus claves con
//! `zx-node::claves::ClaveDev::derivar`: `SHA3-256("zx-node/clave-dev/v1" ‖ semilla_le(8) ‖
//! indice_le(4))` como bytes de la `SigningKey` Ed25519. La cartera **repite esa derivación** con la
//! misma etiqueta y el mismo orden de bytes para que `--semilla 101 --indice 0` dé exactamente la
//! misma clave en el nodo y en la cartera. No es una firma ni un formato nuevos: es la misma
//! derivación dev, y V3 la comprueba de extremo a extremo (si divergiera, el nodo rechazaría la
//! firma).
//!
//! El binario **no** guarda claves en el repositorio: el subcomando `claves` las escribe en un
//! fichero de la zona de trabajo del ejecutor, y el subcomando opuesto las puede leer de ahí.

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::ClavePublica;

/// Etiqueta de la derivación dev (idéntica a `crates/zx-node/src/claves.rs`). No es una etiqueta de
/// consenso: nunca entra en un hash de bloque, solo decide qué bytes locales usa el binario para
/// firmar.
pub const DOMINIO_CLAVE_DEV: &[u8] = b"zx-node/clave-dev/v1";

/// Una clave dev de la cartera: índice, clave de firma y clave pública.
#[derive(Clone)]
pub struct ClaveCartera {
    /// Índice con el que se derivó.
    pub indice: u32,
    /// Clave de firma Ed25519.
    pub sk: SigningKey,
    /// Clave pública correspondiente.
    pub pk: ClavePublica,
}

impl core::fmt::Debug for ClaveCartera {
    /// No imprime la clave secreta: un `Debug` que la volcara la dejaría en cualquier log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClaveCartera")
            .field("indice", &self.indice)
            .field("pk", &hex::encode(self.pk.bytes()))
            .finish_non_exhaustive()
    }
}

impl ClaveCartera {
    /// Deriva la clave dev `indice` de `semilla` con la derivación de `zx-node`.
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

    /// Deriva varias claves dev en el orden de `indices`.
    #[must_use]
    pub fn derivar_varias(semilla: u64, indices: &[u32]) -> Vec<Self> {
        indices.iter().map(|i| Self::derivar(semilla, *i)).collect()
    }

    /// Reconstruye una clave a partir de sus 32 bytes secretos, con un índice informativo.
    ///
    /// # Errores
    /// [`zx_core::error::EncodingError`] si `secreto` no mide 32 bytes.
    pub fn desde_secreto(indice: u32, secreto: &[u8]) -> Result<Self, crate::ErrorCartera> {
        let bytes: [u8; 32] = secreto.try_into().map_err(|_| {
            crate::ErrorCartera::Parseo(format!("clave secreta de {} B", secreto.len()))
        })?;
        let sk = SigningKey::from(bytes);
        let vk = VerificationKey::from(&sk);
        let pk = ClavePublica::desde_bytes(vk.into());
        Ok(Self { indice, sk, pk })
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::ClaveCartera;

    #[test]
    fn es_determinista_y_distinta_por_indice() {
        let a = ClaveCartera::derivar(1, 0);
        let b = ClaveCartera::derivar(1, 0);
        let c = ClaveCartera::derivar(1, 1);
        let d = ClaveCartera::derivar(2, 0);
        assert_eq!(a.pk, b.pk, "misma semilla e índice ⇒ misma clave");
        assert_ne!(a.pk, c.pk, "distinto índice ⇒ distinta clave");
        assert_ne!(a.pk, d.pk, "distinta semilla ⇒ distinta clave");
    }

    #[test]
    fn el_debug_no_imprime_la_clave_secreta() {
        let c = ClaveCartera::derivar(7, 3);
        let texto = format!("{c:?}");
        assert!(!texto.contains(&hex::encode(c.sk.as_ref())), "{texto}");
    }

    #[test]
    fn se_reconstruye_desde_el_secreto() {
        let c = ClaveCartera::derivar(9, 4);
        let secreto: [u8; 32] = c.sk.into();
        let r = ClaveCartera::desde_secreto(4, &secreto).expect("32 B");
        assert_eq!(r.pk, c.pk);
    }
}
