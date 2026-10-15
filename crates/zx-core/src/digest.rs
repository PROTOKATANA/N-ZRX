//! Salidas de hash de 32 bytes, y los tipos con nombre que las envuelven.
//!
//! [`Digest`] es deliberadamente **ciego**: no sabe de qué dominio salió. Los tipos con nombre
//! ([`TxId`], [`BlockHash`]…) son newtypes distintos, no alias, para que el compilador impida
//! pasar un `BlockHash` donde se espera un `TxId` — por ejemplo al construir las hojas del árbol de
//! Merkle (C-BLK-01), donde el error sería silencioso y cambiaría la raíz.

use core::fmt;

/// Salida cruda de SHA3-256: 32 bytes, sin semántica de dominio.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Construye un digest a partir de sus 32 bytes.
    ///
    /// Público a propósito: hace falta para leer un `prev_hash` de la red o del disco. No abre
    /// ningún agujero — construir un digest arbitrario no es lo mismo que **calcularlo** sobre
    /// bytes arbitrarios, que es lo que la separación wire/preimagen impide (ver [`crate::hash`]).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Los 32 bytes, en el orden en que salieron de la esponja.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Genera un newtype con nombre sobre [`Digest`].
macro_rules! digest_newtype {
    ($(#[$meta:meta])* $nombre:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $nombre(Digest);

        impl $nombre {
            /// Envuelve un digest ya calculado.
            #[must_use]
            pub const fn from_digest(d: Digest) -> Self {
                Self(d)
            }

            /// El digest subyacente.
            #[must_use]
            pub const fn digest(&self) -> &Digest {
                &self.0
            }

            /// Los 32 bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl core::fmt::Display for $nombre {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

digest_newtype!(
    /// Identificador de transacción — solo datos de efecto, sin firmas (C-TX-01).
    ///
    /// Que excluya las firmas es lo que lo hace **no maleable**, y por tanto lo que permite
    /// construir una transacción B que gasta salidas de A antes de que A esté minada.
    TxId
);

digest_newtype!(
    /// Digest que firma una entrada concreta (C-SIG-01).
    SigHash
);

digest_newtype!(
    /// Compromiso sobre los datos de autorización (C-TX-02).
    AuthDigest
);

digest_newtype!(
    /// Hash de la cabecera de bloque, sello incluido (C-HDR-09).
    ///
    /// En el formato DAG ya **no** es la preimagen del PoW: el PoW de hash único pertenece a la
    /// base lineal heredada y no se hereda aquí. Es un identificador de cabecera, nada más.
    BlockHash
);

digest_newtype!(
    /// `pre_hash = H_d("ZZKBlkPreHash___", prefirma)` (C-HDR-03).
    ///
    /// Es el mensaje que firma el sello Ed25519 de la cabecera DAG. Se distingue de [`BlockHash`]
    /// a propósito: uno es lo que se firma (todo menos el sello) y el otro lo que identifica al
    /// bloque (prefirma ‖ sello). Confundirlos produciría una firma sobre el valor equivocado, y
    /// el compilador lo impide.
    PreHash
);

digest_newtype!(
    /// Compromiso completo del cuerpo: `H_d("ZZKBlkBodyHash__", CompactSize(n) ‖ txid ‖ auth_digest)`
    /// (SPEC §6.1, nota de cuerpo).
    ///
    /// A diferencia de [`MerkleRoot`], que solo cubre los datos de efecto vía `txid`, este
    /// compromiso liga **también** la autorización (`auth_digest`). Que la raíz de Merkle coincida
    /// **no** sustituye comprobar las firmas: son dos controles distintos.
    BodyCommitment
);

digest_newtype!(
    /// Raíz del árbol de Merkle de transacciones (C-BLK-01).
    MerkleRoot
);

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{BlockHash, Digest, TxId};

    #[test]
    fn digest_se_muestra_en_hex_big_endian() {
        let mut bytes = [0u8; 32];
        *bytes.first_mut().unwrap() = 0xab;
        *bytes.last_mut().unwrap() = 0xcd;
        let d = Digest::from_bytes(bytes);
        let s = format!("{d}");
        assert!(s.starts_with("ab"), "{s}");
        assert!(s.ends_with("cd"), "{s}");
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn los_newtypes_no_son_intercambiables() {
        // Esta prueba es de compilación, no de ejecución: si `TxId` y `BlockHash` fueran alias de
        // `Digest`, lo de abajo compilaría con los tipos cruzados. Al ser newtypes distintos, el
        // compilador lo impide — y eso es exactamente lo que queremos verificar.
        let d = Digest::from_bytes([7u8; 32]);
        let t = TxId::from_digest(d);
        let b = BlockHash::from_digest(d);
        assert_eq!(t.as_bytes(), b.as_bytes());
    }
}
