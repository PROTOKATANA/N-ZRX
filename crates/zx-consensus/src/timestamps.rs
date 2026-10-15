//! Reglas de timestamp (`C-TS-01`, `C-TS-03`, `C-TS-05`).
//!
//! # Aquí no existe la hora de red
//!
//! `C-TS-04` prohíbe usar mediana de pares, NTP o cualquier hora ajustada. Solo el reloj local.
//!
//! No es purismo: con un `FTL` de minutos, la regla «revert to node time» de Bitcoin y Zcash abriría
//! un ataque Sybil al 33 %. Al eliminar la hora de pares del consenso, la vulnerabilidad deja de
//! existir en lugar de mitigarse.

use crate::error::ErrorPow;

/// `C-TS-01` · Monotonía: `ts(H) > ts(H−1)`. Rechazo **permanente**.
///
/// # Errores
/// [`ErrorPow::TimestampNoMonotono`].
pub fn comprobar_monotonia(altura: u32, ts: i64, ts_padre: i64) -> Result<(), ErrorPow> {
    if ts > ts_padre {
        Ok(())
    } else {
        Err(ErrorPow::TimestampNoMonotono {
            altura,
            ts,
            ts_padre,
        })
    }
}

/// `C-TS-03` · Future Time Limit: `ts(H) ≤ reloj_local + ftl`.
///
/// Rechazo **NO permanente**. Quien reciba este error **MUST** diferir el bloque y reintentarlo, y
/// **MUST NOT** cachearlo como inválido ni banear al par: cachearlo produce un split garantizado
/// ante una partición temporal.
///
/// `ftl` sale del perfil de red (`N·T/20`); `reloj_local` es el reloj del propio nodo, nunca una
/// hora de red (`C-TS-04`).
///
/// # Errores
/// [`ErrorPow::TimestampDemasiadoFuturo`].
pub fn comprobar_ftl(ts: i64, reloj_local: i64, ftl: i64) -> Result<(), ErrorPow> {
    let limite = reloj_local
        .checked_add(ftl)
        .ok_or(ErrorPow::DesbordamientoAritmetico)?;
    if ts <= limite {
        Ok(())
    } else {
        Err(ErrorPow::TimestampDemasiadoFuturo { ts, limite })
    }
}

/// `C-TS-05` · Timestamp que debe poner un minero. **No es regla de consenso.**
///
/// `ts = max(reloj_local, ts(padre) + 1)`. El minero además **no debe publicar** hasta que
/// `ts ≤ reloj_local + ftl`, cosa que esta función no puede imponer.
#[must_use]
pub fn timestamp_del_minero(reloj_local: i64, ts_padre: i64) -> i64 {
    reloj_local.max(ts_padre.saturating_add(1))
}

// ─────────────────────────────────────────────────────────────────────────────
// Parte B del contrato del reloj (`C-RLJ-TS-01`…`C-RLJ-TS-05`, RL-2b)
// ─────────────────────────────────────────────────────────────────────────────
//
// Reglas de timestamp del PoST. A-3 de `REVISION-RL2b-a.md`: solo son de **consenso** las que son
// función determinista de la cabecera y de `past(B)` (PMT y banda); el límite de futuro (FTL)
// depende del reloj **local** y por eso **solo retrasa** la admisión, nunca invalida ni penaliza
// (RFT-27). Este módulo no conoce el DAG: recibe la ventana ya extraída del pasado validado.

/// Ventana de la mediana del pasado (`M_ts`) de ejemplo para la red dev.
///
/// `[no verificado]` en `CONTRATO-RELOJ-v0.md` §0.1; valor de **dev** rotulado (A-5), no de
/// producción.
pub const M_TS_DEV: usize = 264;

/// `Banda_slot` de ejemplo para dev, en segundos (`<<PENDIENTE>>` en el contrato).
pub const BANDA_SLOT_DEV: u64 = 30;

/// `FTL` de ejemplo para el PoST dev, en segundos (el del PoW vigente, `N·T/20`).
pub const FTL_POST_DEV: i64 = 540;

/// `tau_ref` de ejemplo para dev, en segundos por slot (`1/1`).
pub const TAU_REF_DEV_NUM: i128 = 1;

/// Denominador de `tau_ref` de ejemplo para dev.
pub const TAU_REF_DEV_DEN: i128 = 1;

/// Parámetros de las reglas de timestamp PoST (tipo **nuevo**: `ParametrosTransicion` no se toca,
/// A-4 de `REVISION-RL2b-a.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParametrosTimestampPost {
    /// `M_ts`: tamaño de la ventana de la mediana del pasado.
    pub m_ts: usize,
    /// `Banda_slot`: semiancho de la relación timestamp–slot, en segundos.
    pub banda_slot: u64,
    /// `FTL`: límite de futuro, en segundos (depende del reloj local; **diferible**).
    pub ftl: i64,
    /// `T_ancla`: timestamp del bloque de slot 0 del terminal.
    pub t_ancla: i64,
    /// Numerador de `tau_ref` (segundos por slot).
    pub tau_ref_num: i128,
    /// Denominador de `tau_ref` (positivo).
    pub tau_ref_den: i128,
}

/// Perfil de timestamps PoST **de dev**, rotulado (A-5). No es de producción.
pub const PERFIL_TIMESTAMP_POST_DEV: ParametrosTimestampPost = ParametrosTimestampPost {
    m_ts: M_TS_DEV,
    banda_slot: BANDA_SLOT_DEV,
    ftl: FTL_POST_DEV,
    t_ancla: 0,
    tau_ref_num: TAU_REF_DEV_NUM,
    tau_ref_den: TAU_REF_DEV_DEN,
};

/// Fallo de una regla de timestamp PoST.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorTimestampPost {
    /// `C-RLJ-TS-01`: `timestamp(B) < PMT(B)`. **Permanente** (depende solo de `past(B)`).
    #[error("timestamp {ts} por debajo de la mediana del pasado {pmt} (C-RLJ-TS-01)")]
    PorDebajoDePmt {
        /// Timestamp del candidato.
        ts: i64,
        /// Mediana del pasado.
        pmt: i64,
    },
    /// `C-RLJ-TS-03`: fuera de la banda timestamp–slot. **Permanente**.
    #[error("timestamp {ts} fuera de la banda ±{banda} alrededor de {esperado} (C-RLJ-TS-03)")]
    FueraDeBanda {
        /// Timestamp del candidato.
        ts: i64,
        /// `T_ancla + slot·tau_ref` redondeado hacia abajo (solo para el mensaje).
        esperado: i64,
        /// `Banda_slot`.
        banda: u64,
    },
    /// `C-RLJ-TS-02`: `timestamp(B) > reloj_local + FTL`. **NO permanente** (depende del reloj
    /// local): se difiere y se reintenta, nunca se cachea ni se penaliza al par (RFT-27).
    #[error("timestamp {ts} por encima del límite de futuro {limite} (C-RLJ-TS-02, diferible)")]
    DemasiadoFuturo {
        /// Timestamp del candidato.
        ts: i64,
        /// `reloj_local + FTL`.
        limite: i64,
    },
    /// La ventana del PMT llegó vacía o con más elementos que `M_ts`.
    #[error("ventana de PMT inválida: {recibidos} timestamps para M_ts = {m_ts}")]
    VentanaDePmtInvalida {
        /// Timestamps recibidos.
        recibidos: usize,
        /// Tamaño declarado de la ventana.
        m_ts: usize,
    },
    /// `tau_ref` con denominador no positivo.
    #[error("tau_ref con denominador {den} no positivo")]
    TauRefInvalida {
        /// Denominador recibido.
        den: i128,
    },
}

impl ErrorTimestampPost {
    /// ¿El rechazo es **permanente** (función determinista de la cabecera y de `past(B)`)?
    ///
    /// `C-RLJ-TS-02` (FTL) devuelve `false`: se difiere y se reintenta.
    #[must_use]
    pub const fn es_permanente(&self) -> bool {
        !matches!(self, Self::DemasiadoFuturo { .. })
    }
}

/// `C-RLJ-TS-01` · Mediana del pasado: la de la ventana de `m` timestamps de **mayor slot**.
///
/// `ventana` llega ordenada por slot ascendente (la extrae el llamante de `past(B)`); se toman los
/// `m` últimos. Si `m` supera el número de elementos (cadena temprana), se usa la ventana entera:
/// con menos de `M_ts` bloques el pasado es todo lo que hay, y dos nodos ven el mismo conjunto.
///
/// # Errores
/// [`ErrorTimestampPost::VentanaDePmtInvalida`] si `ventana` está vacía.
pub fn pmt(ventana: &[i64], m_ts: usize) -> Result<i64, ErrorTimestampPost> {
    if ventana.is_empty() {
        return Err(ErrorTimestampPost::VentanaDePmtInvalida { recibidos: 0, m_ts });
    }
    let inicio = ventana.len().saturating_sub(m_ts);
    let mut valores: Vec<i64> = ventana.get(inicio..).unwrap_or(ventana).to_vec();
    valores.sort_unstable();
    // Mediana **superior**: `floor(n/2)` con índices desde cero (la que exige C-RLJ-TS-01).
    let mitad = valores.len() >> 1;
    valores
        .get(mitad)
        .copied()
        .ok_or(ErrorTimestampPost::VentanaDePmtInvalida {
            recibidos: ventana.len(),
            m_ts,
        })
}

/// `C-RLJ-TS-01` · Monotonía respecto del pasado: `ts ≥ PMT`. **Consenso, permanente.**
///
/// # Errores
/// [`ErrorTimestampPost::PorDebajoDePmt`].
pub fn comprobar_pmt(ts: i64, pmt: i64) -> Result<(), ErrorTimestampPost> {
    if ts >= pmt {
        Ok(())
    } else {
        Err(ErrorTimestampPost::PorDebajoDePmt { ts, pmt })
    }
}

/// `C-RLJ-TS-03` · Relación timestamp–slot:
/// `|ts − (T_ancla + slot·tau_ref)| ≤ Banda_slot`. **Consenso, permanente.**
///
/// Comparación **exacta** con enteros (sin coma flotante): `ts`, `slot`, `t_ancla` y `banda` son
/// enteros y `tau_ref` un racional exacto.
///
/// # Errores
/// [`ErrorTimestampPost::FueraDeBanda`] o [`ErrorTimestampPost::TauRefInvalida`].
pub fn comprobar_banda_ts_slot(
    ts: i64,
    slot: u64,
    p: &ParametrosTimestampPost,
) -> Result<(), ErrorTimestampPost> {
    if p.tau_ref_den <= 0 {
        return Err(ErrorTimestampPost::TauRefInvalida { den: p.tau_ref_den });
    }
    // esperado = t_ancla + slot·(num/den) = (t_ancla·den + slot·num) / den.
    let num =
        i128::from(p.t_ancla) * p.tau_ref_den + i128::from(slot).saturating_mul(p.tau_ref_num);
    // |ts − esperado| ≤ banda  <=>  |ts·den − num| ≤ banda·den.
    let desviacion = (i128::from(ts) * p.tau_ref_den - num).abs();
    let margen = i128::from(p.banda_slot) * p.tau_ref_den;
    if desviacion <= margen {
        Ok(())
    } else {
        Err(ErrorTimestampPost::FueraDeBanda {
            ts,
            esperado: i64::try_from(num.div_euclid(p.tau_ref_den)).unwrap_or(ts),
            banda: p.banda_slot,
        })
    }
}

/// `C-RLJ-TS-02` · Límite de futuro del PoST (`ts ≤ reloj_local + FTL`). **Diferible.**
///
/// # Errores
/// [`ErrorTimestampPost::DemasiadoFuturo`], que **no** es permanente.
pub fn comprobar_ftl_post(ts: i64, reloj_local: i64, ftl: i64) -> Result<(), ErrorTimestampPost> {
    let limite = reloj_local.saturating_add(ftl);
    if ts <= limite {
        Ok(())
    } else {
        Err(ErrorTimestampPost::DemasiadoFuturo { ts, limite })
    }
}

/// Orden de `C-RLJ-TS-04`: PMT (consenso) y banda (consenso) en la ruta de validación; el FTL se
/// consulta **después** y solo retrasa. Los dos primeros son deterministas del pasado.
///
/// # Errores
/// Las permanentes de [`comprobar_pmt`]/[`comprobar_banda_ts_slot`] y, por último, la diferible de
/// [`comprobar_ftl_post`].
pub fn comprobar_timestamp_post(
    ts: i64,
    slot: u64,
    ventana_pasado: &[i64],
    reloj_local: i64,
    p: &ParametrosTimestampPost,
) -> Result<(), ErrorTimestampPost> {
    let mediana = pmt(ventana_pasado, p.m_ts)?;
    comprobar_pmt(ts, mediana)?;
    comprobar_banda_ts_slot(ts, slot, p)?;
    comprobar_ftl_post(ts, reloj_local, p.ftl)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{comprobar_ftl, comprobar_monotonia, timestamp_del_minero};
    use crate::error::ErrorPow;

    #[test]
    fn la_monotonia_es_estricta_y_permanente() {
        assert!(comprobar_monotonia(7, 101, 100).is_ok());
        let e = comprobar_monotonia(7, 100, 100).unwrap_err();
        assert!(matches!(e, ErrorPow::TimestampNoMonotono { .. }), "{e:?}");
        assert!(e.es_permanente());
    }

    #[test]
    fn el_ftl_es_no_permanente_y_depende_del_perfil() {
        assert!(
            comprobar_ftl(1_540, 1_000, 540).is_ok(),
            "justo en el límite"
        );
        let e = comprobar_ftl(1_541, 1_000, 540).unwrap_err();
        assert!(
            matches!(e, ErrorPow::TimestampDemasiadoFuturo { limite: 1_540, .. }),
            "{e:?}"
        );
        assert!(
            !e.es_permanente(),
            "C-TS-03: se difiere y se reintenta, nunca se cachea"
        );
    }

    #[test]
    fn el_minero_avanza_respecto_al_padre() {
        assert_eq!(timestamp_del_minero(1_000, 999), 1_000);
        assert_eq!(timestamp_del_minero(1_000, 1_000), 1_001);
        assert_eq!(timestamp_del_minero(1_000, i64::MAX), i64::MAX);
    }
}
