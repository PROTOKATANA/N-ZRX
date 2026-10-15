//! Firmas Ed25519 con las reglas de verificación de ZIP-215 (SPEC §5, C-SIG).
//!
//! # Por qué ZIP-215 y no "Ed25519 a secas"
//!
//! No existe *un* Ed25519 para consenso. RFC 8032 admite dos ecuaciones de verificación —cofactored
//! y no cofactored— y deja libertad sobre las codificaciones no canónicas. El resultado es que dos
//! bibliotecas conformes pueden **discrepar sobre si una firma concreta es válida**, lo que en una
//! blockchain es un split.
//!
//! ZIP-215 fija los criterios sin ambigüedad, y `ed25519-zebra` los documenta verbatim:
//!
//! > - `A_bytes` y `R_bytes` **MUST** ser codificaciones de puntos de la curva, y las **no
//! >   canónicas MUST aceptarse**;
//! > - `s_bytes` **MUST** representar un entero `s < l`;
//! > - la ecuación `[8][s]B = [8]R + [8][k]A` **MUST** satisfacerse;
//! > - la alternativa `[s]B = R + [k]A`, permitida por RFC 8032, **MUST NOT** usarse.
//!
//! ⚠️ **No mezclar con `ed25519-dalek::verify_strict`.** Elige distinto en el cofactor: hay firmas
//! que una acepta y la otra rechaza. Usar las dos en la misma red es un split garantizado. Este
//! módulo es el **único** punto de verificación de firmas de ZEROX, y por eso `zx-core` no depende
//! de `ed25519-dalek`.

use ed25519_zebra::{Signature, VerificationKey};

use crate::error::EncodingError;

/// Longitud de una clave pública Ed25519.
pub const LONGITUD_CLAVE: usize = 32;

/// Longitud de una firma Ed25519.
pub const LONGITUD_FIRMA: usize = 64;

/// Clave pública Ed25519, en su codificación de 32 bytes.
///
/// **No se valida al construir.** ZIP-215 exige aceptar codificaciones no canónicas, así que
/// rechazar aquí sería una divergencia. La validez del punto se decide en [`verificar`].
///
/// Desde P-020 este tipo es también lo que guarda una salida `PubKey`: ZEROX usa **P2K, no P2KH**,
/// así que no existe ningún `HashClave`. Ver [`crate::tx::Lock`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClavePublica([u8; LONGITUD_CLAVE]);

impl ClavePublica {
    /// Envuelve los 32 bytes de una clave.
    #[must_use]
    pub const fn desde_bytes(b: [u8; LONGITUD_CLAVE]) -> Self {
        Self(b)
    }

    /// Los 32 bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; LONGITUD_CLAVE] {
        &self.0
    }
}

/// Firma Ed25519, en su codificación de 64 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Firma([u8; LONGITUD_FIRMA]);

impl Firma {
    /// Envuelve los 64 bytes de una firma.
    #[must_use]
    pub const fn desde_bytes(b: [u8; LONGITUD_FIRMA]) -> Self {
        Self(b)
    }

    /// Los 64 bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; LONGITUD_FIRMA] {
        &self.0
    }
}

/// Verifica una firma sobre `mensaje` con las reglas de ZIP-215.
///
/// `mensaje` es siempre un `signature_digest` de §4.3 — nunca bytes arbitrarios.
///
/// # Errores
/// [`EncodingError::FirmaInvalida`] si la clave no decodifica a un punto, si `s ≥ l`, o si la
/// ecuación cofactored no se satisface.
pub fn verificar(clave: &ClavePublica, firma: &Firma, mensaje: &[u8]) -> Result<(), EncodingError> {
    let vk =
        VerificationKey::try_from(*clave.bytes()).map_err(|_| EncodingError::FirmaInvalida {
            motivo: "clave pública no decodificable",
        })?;
    let sig = Signature::from_bytes(firma.bytes());
    vk.verify(&sig, mensaje)
        .map_err(|_| EncodingError::FirmaInvalida {
            motivo: "la firma no verifica (ZIP-215)",
        })
}

#[cfg(test)]
mod tests {
    use super::{ClavePublica, Firma, LONGITUD_CLAVE, LONGITUD_FIRMA, verificar};
    use ed25519_zebra::{SigningKey, VerificationKey};

    /// Genera un par determinista a partir de una semilla, para que los tests sean reproducibles.
    fn par(semilla: u8) -> (SigningKey, ClavePublica) {
        let sk = SigningKey::from([semilla; 32]);
        let vk = VerificationKey::from(&sk);
        (sk, ClavePublica::desde_bytes(vk.into()))
    }

    fn firmar(sk: &SigningKey, msg: &[u8]) -> Firma {
        Firma::desde_bytes(sk.sign(msg).into())
    }

    #[test]
    fn una_firma_valida_verifica() {
        let (sk, pk) = par(1);
        let msg = b"signature_digest de la entrada 0";
        assert!(verificar(&pk, &firmar(&sk, msg), msg).is_ok());
    }

    /// Cambiar **un solo bit** del mensaje invalida la firma. Es lo que ata la firma al sighash.
    #[test]
    fn cambiar_el_mensaje_invalida() {
        let (sk, pk) = par(2);
        let msg = [0x11u8; 32];
        let f = firmar(&sk, &msg);

        let mut otro = msg;
        if let Some(b) = otro.first_mut() {
            *b ^= 0x01;
        }
        assert!(
            verificar(&pk, &f, &otro).is_err(),
            "un bit distinto MUST invalidar"
        );
    }

    #[test]
    fn otra_clave_no_verifica() {
        let (sk, _) = par(3);
        let (_, pk_ajena) = par(4);
        let msg = b"mismo mensaje";
        assert!(verificar(&pk_ajena, &firmar(&sk, msg), msg).is_err());
    }

    #[test]
    fn una_firma_manipulada_no_verifica() {
        let (sk, pk) = par(5);
        let msg = b"mensaje";
        let mut bytes = *firmar(&sk, msg).bytes();
        if let Some(b) = bytes.last_mut() {
            *b ^= 0x80;
        }
        assert!(verificar(&pk, &Firma::desde_bytes(bytes), msg).is_err());
    }

    #[test]
    fn una_clave_que_no_es_un_punto_se_rechaza() {
        // Todo unos no es una codificación válida de un punto de la curva.
        let pk = ClavePublica::desde_bytes([0xFF; LONGITUD_CLAVE]);
        let f = Firma::desde_bytes([0u8; LONGITUD_FIRMA]);
        assert!(verificar(&pk, &f, b"x").is_err());
    }

    /// **P-020, P2K.** El enlace clave→salida es la **igualdad de la clave**, no un hash.
    ///
    /// Este test existe para que el cambio a P2K quede fijado: si alguien reintroduce un
    /// `SHA3-256(pubkey)` en el camino de gasto, la comparación deja de ser esta y hay que volver a
    /// pasar por P-020.
    #[test]
    fn la_clave_enlaza_con_la_salida_por_igualdad() {
        let (_, pk) = par(6);
        assert_eq!(pk, ClavePublica::desde_bytes(*pk.bytes()));

        let (_, otra) = par(7);
        assert_ne!(otra, pk, "otra clave MUST NOT coincidir");
    }

    /// Firmas de mensajes distintos con la misma clave son distintas — descarta un stub que
    /// devolviera siempre lo mismo.
    #[test]
    fn firmas_de_mensajes_distintos_difieren() {
        let (sk, _) = par(8);
        assert_ne!(firmar(&sk, b"a").bytes(), firmar(&sk, b"b").bytes());
    }

    /// La firma es determinista (Ed25519 lo es por diseño): dos firmas del mismo mensaje con la
    /// misma clave son idénticas. Si no lo fueran, habría una fuente de no-determinismo en el
    /// wallet y las transacciones no serían reproducibles.
    #[test]
    fn la_firma_es_determinista() {
        let (sk, _) = par(9);
        let msg = b"determinista";
        assert_eq!(firmar(&sk, msg).bytes(), firmar(&sk, msg).bytes());
    }
}
