//! Segundo VDF: **segmentación de una cadena larga** en tramos de clave fija
//! (`C-RLJ-VDF-02` de `P-ZRX/P-RELOJ/RL1/CONTRATO-RELOJ-v0.md`).
//!
//! # Por qué existe
//!
//! La primitiva [`crate::prove`] recibe un `NonZeroU32` de iteraciones (`C-POT-04`), pero la
//! longitud `I` del segundo VDF puede exceder `u32::MAX`. La cadena larga se define por
//! **segmentos**: cada segmento es una llamada a la primitiva con la **clave fija** derivada de su
//! semilla; la salida del segmento `k` es la semilla del segmento `k+1` (encadenado). La
//! descomposición es aritmética entera exacta y no decide nada del consenso: sólo reparte el
//! trabajo.
//!
//! # Qué NO hace
//!
//! No ejecuta AES (eso lo hace quien encadene, `zx-post`), no acredita la semilla y no decide
//! `L`, `I` ni `N(s)`. Tampoco es un reloj de pared (`C-RLJ-VDF-05`).

/// Iteraciones máximas de un segmento: `u32::MAX` redondeado **hacia abajo** a múltiplo de 16
/// (`MAX_SEG = 4 294 967 280`), que es el dominio de [`crate::prove`] (`C-RLJ-VDF-02`).
pub const MAX_SEG: u64 = 4_294_967_280;

/// Defecto de una segmentación pedida.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorVdf {
    /// `total` no es múltiplo de 16: la primitiva no admite esa longitud.
    #[error("la longitud total {total} no es múltiplo de 16")]
    TotalNoMultiploDe16 {
        /// Longitud pedida.
        total: u64,
    },
    /// `max_seg` no es múltiplo de 16: los segmentos deben caer en el dominio de la primitiva.
    #[error("la longitud máxima de segmento {max_seg} no es múltiplo de 16")]
    MaxSegNoMultiploDe16 {
        /// Longitud máxima pedida.
        max_seg: u64,
    },
    /// `max_seg = 0` no reparte nada.
    #[error("la longitud máxima de segmento no puede ser cero")]
    MaxSegCero,
}

/// Iterador de longitudes de segmento de una cadena de `total` iteraciones repartida en tramos de
/// a lo sumo `max_seg`, **todos múltiplos de 16** (`C-RLJ-VDF-02`).
///
/// El reparto es *greedy*: segmentos llenos de `max_seg` y un último resto. `total` y `max_seg`
/// deben ser múltiplos de 16 (lo garantiza [`segmentos`]), de modo que el resto también lo es.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segmentos {
    resto: u64,
    max_seg: u64,
}

impl Segmentos {
    /// Iteraciones que quedan por repartir.
    #[must_use]
    pub const fn resto(&self) -> u64 {
        self.resto
    }

    /// Longitud máxima de cada segmento.
    #[must_use]
    pub const fn max_seg(&self) -> u64 {
        self.max_seg
    }
}

impl Iterator for Segmentos {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.resto == 0 {
            return None;
        }
        let n = self.resto.min(self.max_seg);
        self.resto -= n;
        Some(n)
    }
}

/// Construye el reparto en segmentos de `total` iteraciones con tope `max_seg`.
///
/// # Errores
/// [`ErrorVdf::TotalNoMultiploDe16`] si `total % 16 != 0`;
/// [`ErrorVdf::MaxSegNoMultiploDe16`] si `max_seg % 16 != 0`;
/// [`ErrorVdf::MaxSegCero`] si `max_seg == 0`.
pub fn segmentos(total: u64, max_seg: u64) -> Result<Segmentos, ErrorVdf> {
    if max_seg == 0 {
        return Err(ErrorVdf::MaxSegCero);
    }
    if !total.is_multiple_of(16) {
        return Err(ErrorVdf::TotalNoMultiploDe16 { total });
    }
    if !max_seg.is_multiple_of(16) {
        return Err(ErrorVdf::MaxSegNoMultiploDe16 { max_seg });
    }
    Ok(Segmentos {
        resto: total,
        max_seg,
    })
}
