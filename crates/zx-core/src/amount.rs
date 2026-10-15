//! Importes en brek (C-ENC-01, C-TX-12).
//!
//! Todo importe del protocolo se expresa y codifica en **brek**, nunca en ZZK. Las conversiones a
//! ZZK son exclusivamente de presentación y no viven en el consenso.

use crate::error::EncodingError;

/// Brek por ZZK: `1 ZZK = 100 000 000 brek` (8 decimales).
pub const BREK_POR_ZZK: i64 = 100_000_000;

/// Cota de cordura de cualquier importe individual (C-TX-12).
///
/// ZEROX **no tiene** un `MAX_MONEY`: la cola de emisión hace el suministro no acotado, así que no
/// puede copiarse la regla de Zcash. `2^62` está deliberadamente desacoplado de la emisión real —
/// partiendo de 1000 M ZZK y creciendo 8 409 600 ZZK/año, el suministro tardaría ~5 365 años en
/// acercarse. Su función es acotar la aritmética, no la economía.
pub const ZX_VALUE_SANITY_LIMIT: i64 = 1 << 62;

/// Un importe válido, en brek.
///
/// El constructor es la **única** forma de obtener uno, así que un `Amount` que exista está dentro
/// de `[0, ZX_VALUE_SANITY_LIMIT]` por construcción. Ningún punto posterior necesita volver a
/// comprobarlo, y ninguno puede olvidarse de hacerlo.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Amount(i64);

impl Amount {
    /// Cero brek.
    pub const CERO: Self = Self(0);

    /// Construye un importe, validando C-TX-12.
    ///
    /// # Errores
    /// [`EncodingError::ImporteFueraDeRango`] si es negativo o excede la cota de cordura.
    pub const fn nuevo(brek: i64) -> Result<Self, EncodingError> {
        if brek < 0 || brek > ZX_VALUE_SANITY_LIMIT {
            return Err(EncodingError::ImporteFueraDeRango { brek });
        }
        Ok(Self(brek))
    }

    /// El valor en brek.
    #[must_use]
    pub const fn brek(self) -> i64 {
        self.0
    }

    /// Suma comprobada (C-ENC-03).
    ///
    /// Devuelve `None` si desborda **o** si el resultado excede la cota de cordura. No satura: un
    /// valor fuera de rango convertido en silencio al máximo disfrazaría un intento de ataque de
    /// valor legítimo, que es justo lo que C-ENC-03 prohíbe.
    #[must_use]
    pub fn suma_comprobada(self, otro: Self) -> Option<Self> {
        let s = self.0.checked_add(otro.0)?;
        Self::nuevo(s).ok()
    }

    /// Resta comprobada. `None` si el resultado sería negativo.
    #[must_use]
    pub fn resta_comprobada(self, otro: Self) -> Option<Self> {
        let d = self.0.checked_sub(otro.0)?;
        Self::nuevo(d).ok()
    }

    /// Suma una secuencia de importes, rechazando cualquier desbordamiento.
    ///
    /// # Errores
    /// [`EncodingError::ImporteFueraDeRango`] si la suma parcial se sale de rango en algún punto.
    pub fn suma<I: IntoIterator<Item = Self>>(importes: I) -> Result<Self, EncodingError> {
        let mut acc = Self::CERO;
        for a in importes {
            acc = acc
                .suma_comprobada(a)
                .ok_or(EncodingError::ImporteFueraDeRango { brek: i64::MAX })?;
        }
        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, BREK_POR_ZZK, ZX_VALUE_SANITY_LIMIT};

    #[test]
    fn se_rechazan_los_importes_fuera_de_rango() {
        assert!(Amount::nuevo(-1).is_err());
        assert!(Amount::nuevo(ZX_VALUE_SANITY_LIMIT + 1).is_err());
        assert!(Amount::nuevo(i64::MIN).is_err());
        assert!(Amount::nuevo(i64::MAX).is_err());
    }

    #[test]
    fn las_fronteras_exactas_son_validas() {
        assert!(Amount::nuevo(0).is_ok());
        assert!(Amount::nuevo(ZX_VALUE_SANITY_LIMIT).is_ok());
    }

    #[test]
    fn la_suma_no_desborda_en_silencio() {
        let casi = Amount::nuevo(ZX_VALUE_SANITY_LIMIT).ok();
        let uno = Amount::nuevo(1).ok();
        match (casi, uno) {
            (Some(a), Some(b)) => assert!(a.suma_comprobada(b).is_none(), "debería rechazar"),
            _ => unreachable!("los constructores acaban de validarse arriba"),
        }
    }

    #[test]
    fn una_zzk_son_cien_millones_de_brek() {
        assert_eq!(BREK_POR_ZZK, 100_000_000);
    }
}
