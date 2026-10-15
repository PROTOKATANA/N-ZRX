//! Firmas BLS: la firma vive en G2 (96 B comprimidos) y su agregado es otro punto de G2.

use blst::min_pk::{AggregateSignature, Signature};

use crate::error::{ErrorBLS, motivo_blst};

/// Longitud de una firma comprimida (punto de G2).
pub const LONGITUD_FIRMA: usize = 96;

/// Firma BLS (punto de G2).
///
/// **Siempre** se construye con comprobación de subgrupo y rechazo del infinito (decisión 3).
#[derive(Clone, Copy, Debug)]
pub struct Firma(Signature);

impl PartialEq for Firma {
    fn eq(&self, otra: &Self) -> bool {
        self.0.to_bytes() == otra.0.to_bytes()
    }
}

impl Eq for Firma {}

impl Firma {
    /// Deserializa 96 bytes comprimidos y **valida** el punto: en la curva, no infinito y en el
    /// subgrupo de orden primo.
    ///
    /// # Errores
    /// [`ErrorBLS::FirmaInvalida`] si la longitud no es 96 o el punto no es válido.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, ErrorBLS> {
        if bytes.len() != LONGITUD_FIRMA {
            return Err(ErrorBLS::FirmaInvalida {
                motivo: "longitud distinta de 96",
            });
        }
        let firma = Signature::sig_validate(bytes, true).map_err(|e| ErrorBLS::FirmaInvalida {
            motivo: motivo_blst(e),
        })?;
        Ok(Self(firma))
    }

    /// Los 96 bytes comprimidos.
    #[must_use]
    pub fn bytes(&self) -> [u8; LONGITUD_FIRMA] {
        self.0.to_bytes()
    }

    /// Vista interna para la capa `crudo`. No sale de este crate.
    pub(crate) fn interna(&self) -> &Signature {
        &self.0
    }

    /// Construye desde el tipo de `blst` (firma ya validada por la capa que la produjo).
    pub(crate) fn desde_interna(firma: Signature) -> Self {
        Self(firma)
    }
}

/// Firma agregada: la suma de varias firmas en G2.
#[derive(Clone, Copy, Debug)]
pub struct FirmaAgregada(AggregateSignature);

impl FirmaAgregada {
    /// Envuelve una firma individual como agregado de tamaño uno.
    #[must_use]
    pub fn desde_firma(firma: &Firma) -> Self {
        Self(AggregateSignature::from_signature(firma.interna()))
    }

    /// Los 96 bytes comprimidos del punto agregado.
    #[must_use]
    pub fn bytes(&self) -> [u8; LONGITUD_FIRMA] {
        self.0.to_signature().to_bytes()
    }

    /// Vista interna para la capa `crudo`. No sale de este crate.
    pub(crate) fn interna(&self) -> &AggregateSignature {
        &self.0
    }

    /// Construye desde el tipo de `blst` (agregado ya validado por la capa que lo produjo).
    pub(crate) fn desde_interna(agregada: AggregateSignature) -> Self {
        Self(agregada)
    }
}
