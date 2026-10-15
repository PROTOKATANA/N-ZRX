//! Parámetros PoW por red (D-P05).
//!
//! Las constantes del retarget de `9681061` (`T`, `N`, `K`, `NK`, `ST_CAP`, `T_FLOOR`, `FTL`,
//! `MTP_W`) eran globales. Aquí son campos de [`ParametrosPow`] y las **funciones derivadas**
//! reproducen las fórmulas de los comentarios antiguos con aritmética comprobada:
//!
//! ```text
//! k       = N(N+1)T/2
//! nk      = N·k
//! st_cap  = 6T
//! t_floor = N(N+1)T/20
//! ftl     = N·T/20
//! ```
//!
//! Un test obligatorio comprueba que, con `T = 120`, `N = 90`, `LIMITES_ANTIGUOS`,
//! `bits_iniciales = 0x1c07fff8` y `mtp_w = 11`, los derivados valen **exactamente** las constantes
//! de `9681061`: `K = 491_400`, `NK = 44_226_000`, `ST_CAP = 720`, `T_FLOOR = 49_140`, `FTL = 540`.

// Igual que en el `dificultad.rs` antiguo: `clippy::integer_division` sugiere floats, y
// `C-ENC-04` prohíbe la coma flotante en toda ruta de consenso. La división entera **truncada** es
// la especificación.
#![expect(
    clippy::integer_division,
    reason = "C-ENC-04 prohíbe floats; la división entera truncada es la especificación"
)]

use primitive_types::U256;
use zx_core::Red;
use zx_core::target::{LIMITES_ANTIGUOS, LimitesTarget};

use crate::error::ErrorPow;

/// Parámetros PoW de una red.
///
/// Todos los campos son consenso de esa red. `limites` sustituye a las constantes globales
/// `MIN_TARGET`/`POW_LIMIT`; `bits_iniciales` sustituye a `TARGET_INICIAL_BITS_*`; `mtp_w` sustituye
/// a `MTP_W`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParametrosPow {
    /// Tiempo objetivo entre bloques, en segundos (`T`).
    pub t: i64,
    /// Tamaño de la ventana del retarget, en bloques (`N`).
    pub n: usize,
    /// Límites de target de la red (`C-POW-05`).
    pub limites: LimitesTarget,
    /// `bits` de arranque (`C-DIFF-02`).
    pub bits_iniciales: u32,
    /// Ventana del median-time-past (`C-TS-02`).
    pub mtp_w: usize,
}

impl ParametrosPow {
    /// `n` como `i64`, o error de desbordamiento.
    fn n_i64(&self) -> Result<i64, ErrorPow> {
        i64::try_from(self.n).map_err(|_| ErrorPow::DesbordamientoAritmetico)
    }

    /// `k = N(N+1)T/2`.
    ///
    /// `N(N+1)` es par, así que la división intermedia es **exacta**.
    pub fn k(&self) -> Result<i64, ErrorPow> {
        let n = self.n_i64()?;
        let np1 = n.checked_add(1).ok_or(ErrorPow::DesbordamientoAritmetico)?;
        let par = n
            .checked_mul(np1)
            .ok_or(ErrorPow::DesbordamientoAritmetico)?;
        let mitad = par / 2;
        mitad
            .checked_mul(self.t)
            .ok_or(ErrorPow::DesbordamientoAritmetico)
    }

    /// `NK = N·k`, el denominador del retarget.
    pub fn nk(&self) -> Result<i64, ErrorPow> {
        let n = self.n_i64()?;
        n.checked_mul(self.k()?)
            .ok_or(ErrorPow::DesbordamientoAritmetico)
    }

    /// `ST_CAP = 6T`. Techo del solvetime de un bloque.
    pub fn st_cap(&self) -> Result<i64, ErrorPow> {
        self.t
            .checked_mul(6)
            .ok_or(ErrorPow::DesbordamientoAritmetico)
    }

    /// `T_FLOOR = N(N+1)T/20`. Suelo de la suma ponderada (P-003).
    pub fn t_floor(&self) -> Result<i64, ErrorPow> {
        let n = self.n_i64()?;
        let np1 = n.checked_add(1).ok_or(ErrorPow::DesbordamientoAritmetico)?;
        n.checked_mul(np1)
            .and_then(|x| x.checked_mul(self.t))
            .map(|x| x / 20)
            .ok_or(ErrorPow::DesbordamientoAritmetico)
    }

    /// `FTL = N·T/20`. Margen de futuro admitido en un timestamp (`C-TS-03`).
    pub fn ftl(&self) -> Result<i64, ErrorPow> {
        let n = self.n_i64()?;
        n.checked_mul(self.t)
            .map(|x| x / 20)
            .ok_or(ErrorPow::DesbordamientoAritmetico)
    }
}

/// Parámetros **antiguos** de `9681061`: las constantes del commit, ahora como perfil.
///
/// `MIN_TARGET`/`POW_LIMIT` no cambian; van en `LIMITES_ANTIGUOS`.
pub const PARAMETROS_POW_ANTIGUOS: ParametrosPow = ParametrosPow {
    t: 120,
    n: 90,
    limites: LIMITES_ANTIGUOS,
    bits_iniciales: 0x1c07_fff8,
    mtp_w: 11,
};

/// Perfil **dev** de la red de pruebas local de 0.0.1.
///
/// ⚠️ **No son parámetros de producción**: se eligieron para que una red local de pruebas mine en
/// segundos. En particular, `limites.max` y `bits_iniciales` son `0x1e7fffff`, un target **más
/// fácil que `POW_LIMIT`**, que solo existe porque `LimitesTarget` está parametrizado por red. El
/// algoritmo PoW de producción sigue abierto (IPA A-12).
///
/// `limites.max` es la expansión exacta de `0x1e7fffff`: `0x7fffff · 2^216` = `2^239 − 2^216`. Un
/// test lo recalcula con `decodificar_con` y comprueba que no se tecleó mal.
pub const PARAMETROS_POW_DEV: ParametrosPow = ParametrosPow {
    t: 2,
    n: 20,
    limites: LimitesTarget {
        min: U256([0, 1, 0, 0]),
        max: U256([0, 0, 0, 0x0000_7fff_ff00_0000]),
    },
    bits_iniciales: 0x1e7f_ffff,
    mtp_w: 11,
};

/// Límites de target de una red.
#[must_use]
pub const fn limites_de(red: Red) -> LimitesTarget {
    match red {
        Red::Mainnet | Red::Testnet => LIMITES_ANTIGUOS,
        Red::Dev => PARAMETROS_POW_DEV.limites,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{PARAMETROS_POW_ANTIGUOS, PARAMETROS_POW_DEV, limites_de};
    use zx_core::Red;
    use zx_core::target::{LIMITES_AMPLIOS, LIMITES_ANTIGUOS, decodificar_con};

    /// **Test obligatorio de ORDEN-W04 §3.4.** Con los parámetros antiguos, los derivados son
    /// exactamente las constantes de `9681061`.
    #[test]
    fn las_constantes_precomputadas_cuadran() {
        let p = PARAMETROS_POW_ANTIGUOS;
        assert_eq!(p.k().unwrap(), 491_400, "K = N(N+1)T/2");
        assert_eq!(p.nk().unwrap(), 44_226_000, "NK = N·k");
        assert_eq!(p.st_cap().unwrap(), 720, "ST_CAP = 6T");
        assert_eq!(p.t_floor().unwrap(), 49_140, "T_FLOOR = N(N+1)T/20");
        assert_eq!(p.ftl().unwrap(), 540, "FTL = N·T/20");
    }

    /// El perfil dev es dev: arranca más fácil que el mínimo antiguo y su máximo es exacto.
    #[test]
    fn el_maximo_dev_es_la_expansion_de_su_bits_iniciales() {
        let objetivo =
            decodificar_con(PARAMETROS_POW_DEV.bits_iniciales, &LIMITES_AMPLIOS).unwrap();
        assert_eq!(PARAMETROS_POW_DEV.limites.max, objetivo);
        assert_eq!(PARAMETROS_POW_DEV.limites.min, LIMITES_ANTIGUOS.min);
        assert_eq!(PARAMETROS_POW_DEV.bits_iniciales, 0x1e7f_ffff);
        assert!(
            decodificar_con(
                PARAMETROS_POW_DEV.bits_iniciales,
                &PARAMETROS_POW_DEV.limites
            )
            .is_ok(),
            "el propio perfil dev admite su bits de arranque"
        );
        assert!(
            decodificar_con(PARAMETROS_POW_DEV.bits_iniciales, &LIMITES_ANTIGUOS).is_err(),
            "mainnet/testnet MUST NOT admitirlo: es más fácil que POW_LIMIT"
        );
    }

    #[test]
    fn los_limites_por_red_son_los_esperados() {
        assert_eq!(limites_de(Red::Mainnet), LIMITES_ANTIGUOS);
        assert_eq!(limites_de(Red::Testnet), LIMITES_ANTIGUOS);
        assert_eq!(limites_de(Red::Dev), PARAMETROS_POW_DEV.limites);
    }
}
