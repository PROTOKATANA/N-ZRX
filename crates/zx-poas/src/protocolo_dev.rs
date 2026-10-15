//! Protocolo de agricultura **dev** (valores de desarrollo, no de red).
//!
//! Reproduce los valores que usaba el fixture `tests/farmer_disco.rs` de `9681061` y cuya fuente es
//! el test upstream `subspace-farmer-components/tests/plot_read_roundtrip.rs`. Son los que la orden
//! §3.1 fija: `history_size = 1`, `max_pieces_in_sector = 2`, `recent_segments = 5`,
//! `recent_history_fraction = (1, 10)` y `min_sector_lifetime = 4`.
//!
//! **No son parámetros de red.** La red dev 0.0.1 fija `history_size = 1` durante toda su vida
//! (D-P12), pero el resto son valores de fixture local, etiquetados `dev` en cada constante. El
//! compromiso de segmento de [`crate::HistoriaGenesis`] se congeló sobre la receta que usa este
//! protocolo, no sobre un compromiso de mainnet/testnet.

use std::num::NonZeroU64;

use subspace_core_primitives::segments::HistorySize;
use subspace_farmer_components::FarmerProtocolInfo;

use crate::historia::ErrorHistoriaGenesis;

/// `history_size` del fixture local, en segmentos. Valor de **desarrollo**, no de red.
pub const TAMANO_HISTORIA_DEV: u64 = 1;

/// Piezas por sector del fixture local. Valor de **desarrollo**, no de red.
pub const PIEZAS_POR_SECTOR_DEV: u16 = 2;

/// `recent_segments` del fixture local, en segmentos. Valor de **desarrollo**, no de red.
pub const SEGMENTOS_RECIENTES_DEV: u64 = 5;

/// Divisor de `recent_history_fraction` del fixture local. Valor de **desarrollo**, no de red.
pub const FRACCION_RECIENTE_DIVISOR_DEV: u64 = 1;

/// Multiplicador de `recent_history_fraction` del fixture local. Valor de **desarrollo**, no de red.
pub const FRACCION_RECIENTE_MULTIPLICADOR_DEV: u64 = 10;

/// `min_sector_lifetime` del fixture local, en segmentos. Valor de **desarrollo**, no de red.
pub const VIDA_MINIMA_SECTOR_DEV: u64 = 4;

/// Convierte un número de segmentos a [`HistorySize`] sin aceptar el cero.
///
/// # Errores
/// [`ErrorHistoriaGenesis::TamanoHistoriaCero`] si `segmentos` es cero.
pub fn a_tamano_historia(segmentos: u64) -> Result<HistorySize, ErrorHistoriaGenesis> {
    NonZeroU64::new(segmentos)
        .map(HistorySize::new)
        .ok_or(ErrorHistoriaGenesis::TamanoHistoriaCero { segmentos })
}

/// El [`FarmerProtocolInfo`] dev completo, construido desde las constantes de este módulo.
///
/// # Errores
/// [`ErrorHistoriaGenesis::TamanoHistoriaCero`] si alguna constante fuera cero (hoy no lo es).
pub fn parametros() -> Result<FarmerProtocolInfo, ErrorHistoriaGenesis> {
    Ok(FarmerProtocolInfo {
        history_size: a_tamano_historia(TAMANO_HISTORIA_DEV)?,
        max_pieces_in_sector: PIEZAS_POR_SECTOR_DEV,
        recent_segments: a_tamano_historia(SEGMENTOS_RECIENTES_DEV)?,
        recent_history_fraction: (
            a_tamano_historia(FRACCION_RECIENTE_DIVISOR_DEV)?,
            a_tamano_historia(FRACCION_RECIENTE_MULTIPLICADOR_DEV)?,
        ),
        min_sector_lifetime: a_tamano_historia(VIDA_MINIMA_SECTOR_DEV)?,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{
        FRACCION_RECIENTE_DIVISOR_DEV, FRACCION_RECIENTE_MULTIPLICADOR_DEV, PIEZAS_POR_SECTOR_DEV,
        SEGMENTOS_RECIENTES_DEV, TAMANO_HISTORIA_DEV, VIDA_MINIMA_SECTOR_DEV, parametros,
    };

    #[test]
    fn los_valores_dev_son_los_de_la_orden() {
        let p = parametros().unwrap();
        assert_eq!(p.history_size.get(), TAMANO_HISTORIA_DEV);
        assert_eq!(p.max_pieces_in_sector, PIEZAS_POR_SECTOR_DEV);
        assert_eq!(p.recent_segments.get(), SEGMENTOS_RECIENTES_DEV);
        assert_eq!(
            p.recent_history_fraction.0.get(),
            FRACCION_RECIENTE_DIVISOR_DEV
        );
        assert_eq!(
            p.recent_history_fraction.1.get(),
            FRACCION_RECIENTE_MULTIPLICADOR_DEV
        );
        assert_eq!(p.min_sector_lifetime.get(), VIDA_MINIMA_SECTOR_DEV);
        assert_eq!(p.history_size.get(), 1);
        assert_eq!(p.max_pieces_in_sector, 2);
        assert_eq!(p.recent_segments.get(), 5);
        assert_eq!(
            (
                p.recent_history_fraction.0.get(),
                p.recent_history_fraction.1.get()
            ),
            (1, 10)
        );
    }
}
