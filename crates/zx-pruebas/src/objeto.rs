//! Objeto `PruebaRecursiva` (`CP-R-01`): versión, clase cerrada y cuerpo canónico.
//!
//! `PruebaRecursiva = version u8 ‖ clase u8 ‖ cuerpo_canónico`, con `version = 1` y
//! `clase ∈ {0x01 PoRep, 0x02 PoSt, 0x06 TurnoS4}`. Para `0x01`/`0x02` el cuerpo canónico es
//! `bytes_canonicos(OperacionAlmacenamiento)` de `zx-core`; este crate lo trata como **opaco**
//! (la semántica de `zx-core` es del carril `CP-C2`) y solo garantiza su conservación byte a byte.

use crate::ErrorPrueba;
use crate::huella::huella;
use crate::limites::MAX_PRUEBA_CANONICA_BYTES;

/// Versión del objeto que entiende este binario.
pub const VERSION_OBJETO: u8 = 1;

/// Bytes de la cabecera del objeto: `version u8 ‖ clase u8`.
pub const CABECERA_OBJETO: usize = 2;

/// Clases cerradas del carril de pruebas recursivas (`CP-R-01`).
///
/// `0x03`/`0x04`/`0x05` ya están ocupadas por `ClaveVoto`/`CertificadoFinalidad`/
/// `EvidenciaDobleVoto` (`crates/zx-core/src/tx.rs:319-350`); el carril añade `0x06` para la
/// prueba de turno S4 por identidad.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ClasePrueba {
    /// `0x01` · prueba PoRep agregada por lote del granjero.
    PoRep = 0x01,
    /// `0x02` · prueba PoSt agregada por granjero.
    PoSt = 0x02,
    /// `0x06` · prueba de turno S4 por identidad (`π_g(h)`).
    TurnoS4 = 0x06,
}

impl ClasePrueba {
    /// El byte canónico.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Decodifica el byte; el conjunto es **cerrado** y cualquier otro valor se rechaza.
    #[must_use]
    pub const fn desde_byte(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::PoRep),
            0x02 => Some(Self::PoSt),
            0x06 => Some(Self::TurnoS4),
            _ => None,
        }
    }
}

/// La forma canónica descomprimida de una prueba recursiva.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PruebaRecursiva {
    clase: ClasePrueba,
    cuerpo_canonico: Vec<u8>,
}

impl PruebaRecursiva {
    /// Construye el objeto a partir de su clase y su cuerpo canónico.
    ///
    /// # Errores
    /// [`ErrorPrueba::CanonicaDemasiadoLarga`] si `version ‖ clase ‖ cuerpo` supera
    /// [`MAX_PRUEBA_CANONICA_BYTES`].
    pub fn nueva(clase: ClasePrueba, cuerpo_canonico: &[u8]) -> Result<Self, ErrorPrueba> {
        let total = CABECERA_OBJETO.saturating_add(cuerpo_canonico.len()) as u64;
        if total > MAX_PRUEBA_CANONICA_BYTES {
            return Err(ErrorPrueba::CanonicaDemasiadoLarga(total));
        }
        Ok(Self {
            clase,
            cuerpo_canonico: cuerpo_canonico.to_vec(),
        })
    }

    /// Decodifica la forma canónica `version u8 ‖ clase u8 ‖ cuerpo`.
    ///
    /// # Errores
    /// [`ErrorPrueba::BytesInsuficientes`] si faltan la versión o la clase;
    /// [`ErrorPrueba::VersionDesconocida`] si la versión no es [`VERSION_OBJETO`];
    /// [`ErrorPrueba::ClaseDesconocida`] si la clase no está en el conjunto cerrado;
    /// [`ErrorPrueba::CanonicaDemasiadoLarga`] si el objeto supera
    /// [`MAX_PRUEBA_CANONICA_BYTES`].
    pub fn desde_canonico(bytes: &[u8]) -> Result<Self, ErrorPrueba> {
        if bytes.len() as u64 > MAX_PRUEBA_CANONICA_BYTES {
            return Err(ErrorPrueba::CanonicaDemasiadoLarga(bytes.len() as u64));
        }
        let version = *bytes.first().ok_or(ErrorPrueba::BytesInsuficientes)?;
        if version != VERSION_OBJETO {
            return Err(ErrorPrueba::VersionDesconocida {
                encontrada: version,
            });
        }
        let clase_byte = *bytes.get(1).ok_or(ErrorPrueba::BytesInsuficientes)?;
        let clase =
            ClasePrueba::desde_byte(clase_byte).ok_or(ErrorPrueba::ClaseDesconocida(clase_byte))?;
        let cuerpo_canonico = bytes.get(CABECERA_OBJETO..).unwrap_or_default().to_vec();
        Ok(Self {
            clase,
            cuerpo_canonico,
        })
    }

    /// La clase del objeto.
    #[must_use]
    pub const fn clase(&self) -> ClasePrueba {
        self.clase
    }

    /// El cuerpo canónico opaco.
    #[must_use]
    pub fn cuerpo_canonico(&self) -> &[u8] {
        &self.cuerpo_canonico
    }

    /// Serializa la forma canónica `version u8 ‖ clase u8 ‖ cuerpo_canonico`.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(CABECERA_OBJETO.saturating_add(self.cuerpo_canonico.len()));
        out.push(VERSION_OBJETO);
        out.push(self.clase.byte());
        out.extend_from_slice(&self.cuerpo_canonico);
        out
    }

    /// La huella del objeto: `H_d("ZZKPruebaCarril_", cuerpo_canónico)` (`CP-R-02`).
    #[must_use]
    pub fn huella(&self) -> [u8; 32] {
        huella(&self.cuerpo_canonico)
    }
}
