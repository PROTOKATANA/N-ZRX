//! LWMA-1: ajuste de dificultad con retarget por bloque (SPEC §7.3).
//!
//! Portado de `crates/zx-consensus/src/dificultad.rs` de `9681061`, **sin cambiar la aritmética**:
//! misma variante de espacio-target en `U512`, mismos solvetimes monótonos, mismo `BIAS = 1/1` y
//! mismo clamp. Lo único que cambia es que `T`, `N`, `ST_CAP`, `T_FLOOR`, `NK` y los límites salen
//! del [`ParametrosPow`] de la red en vez de constantes globales.
//!
//! # El patrón prohibido
//!
//! `C-DIFF-03` reconstruye los solvetimes de forma **monótona**. La diferencia con saturar no es
//! estilística: `if st < 1 { st = 1 }` es exactamente el patrón que produjo un ataque real, en el que
//! una moneda perdió 4 800 bloques en 5 horas porque los timestamps retrasados se convertían en
//! solvetimes largos artificiales que hundían la dificultad.
//!
//! # Determinismo
//!
//! `C-DIFF-01` hace de esto una **función pura**: sus únicas entradas son los `N+1` timestamps y los
//! `N` targets de la ventana. No lee reloj, ni hora de red, ni mempool, ni configuración. Cualquier
//! fuente de no-determinismo aquí es un split de cadena.

// `clippy::integer_division` sugiere floats; `C-ENC-04` prohíbe la coma flotante en consenso y la
// división entera **truncada** es la especificación (`C-DIFF-07`).
#![expect(
    clippy::integer_division,
    reason = "C-ENC-04 prohíbe floats; la división entera truncada es la especificación (C-DIFF-07)"
)]

use primitive_types::{U256, U512};

use crate::error::ErrorPow;
use crate::parametros::ParametrosPow;

/// Numerador de la corrección del sesgo del clamp (`C-DIFF-07`).
///
/// ✅ **P-005 cerrado: no se corrige.** Vale 1, y así se queda. Los dos factores se conservan en la
/// fórmula en vez de colapsarla a `S·t/NK` para que la **ausencia** de corrección sea visible.
pub const BIAS_NUM: u64 = 1;

/// Denominador de la corrección del sesgo. Ver [`BIAS_NUM`].
pub const BIAS_DEN: u64 = 1;

// Si la corrección se reabre, MUST **aflojar** (`BIAS_NUM ≥ BIAS_DEN`) porque el clamp recorta por
// arriba y sesga el target a la baja. Esta aserción estaba al revés y protegía la dirección
// equivocada.
const _: () = assert!(
    BIAS_NUM >= BIAS_DEN,
    "C-DIFF-07: si la corrección del sesgo se reabre, debe aflojar (>= 1), no apretar — ver P-005"
);

/// La ventana que consume el retarget (`C-DIFF-01`).
///
/// Es todo lo que la función pura puede mirar.
#[derive(Clone, Copy, Debug)]
pub struct VentanaRetarget<'a> {
    /// Los `N+1` timestamps, de `ts(H−N−1)` a `ts(H−1)`, en orden ascendente de altura.
    pub timestamps: &'a [i64],
    /// Los `N` targets, ya decodificados desde `bits` (`C-DIFF-09`), en el mismo orden.
    pub targets: &'a [U256],
}

/// Reconstruye los solvetimes de la ventana de forma monótona (`C-DIFF-03`).
///
/// Invariante garantizado por construcción: `1 ≤ st[j] ≤ st_cap`.
fn solvetimes(timestamps: &[i64], st_cap: i64) -> Result<Vec<i64>, ErrorPow> {
    let mut previo = *timestamps.first().ok_or(ErrorPow::VentanaVacia)?;
    let mut st = Vec::with_capacity(timestamps.len().saturating_sub(1));

    for actual in timestamps.iter().skip(1) {
        // Normalización: si el timestamp no avanza, se toma `previo + 1`. Nunca se satura después.
        let c = if *actual > previo {
            *actual
        } else {
            previo
                .checked_add(1)
                .ok_or(ErrorPow::DesbordamientoAritmetico)?
        };
        let bruto = c
            .checked_sub(previo)
            .ok_or(ErrorPow::DesbordamientoAritmetico)?;
        st.push(bruto.min(st_cap));
        previo = c;
    }
    Ok(st)
}

/// Calcula el target del bloque de altura `h` (`C-DIFF-01..08`).
///
/// Es una **función pura** de la ventana. Para `1 ≤ h ≤ N` no debe llamarse: rige
/// `bits_iniciales` (`C-DIFF-02`).
///
/// # Errores
/// - [`ErrorPow::VentanaDeTamanoIncorrecto`] si la ventana no trae exactamente `N+1` timestamps y
///   `N` targets. **MUST NOT** encogerse dinámicamente.
/// - [`ErrorPow::DesbordamientoAritmetico`] ante cualquier desbordamiento (`C-ENC-03`).
pub fn siguiente_target(v: VentanaRetarget<'_>, p: &ParametrosPow) -> Result<U256, ErrorPow> {
    if v.timestamps.len() != p.n + 1 || v.targets.len() != p.n {
        return Err(ErrorPow::VentanaDeTamanoIncorrecto {
            timestamps: v.timestamps.len(),
            targets: v.targets.len(),
            esperados: p.n,
        });
    }

    // C-DIFF-03 · solvetimes monótonos.
    let st = solvetimes(v.timestamps, p.st_cap()?)?;

    // C-DIFF-04 · suma ponderada `t = Σ j·st[j]`, con j desde 1.
    let mut t: i64 = 0;
    for (idx, s) in st.iter().enumerate() {
        let j = i64::try_from(idx).map_err(|_| ErrorPow::DesbordamientoAritmetico)? + 1;
        let termino = j
            .checked_mul(*s)
            .ok_or(ErrorPow::DesbordamientoAritmetico)?;
        t = t
            .checked_add(termino)
            .ok_or(ErrorPow::DesbordamientoAritmetico)?;
    }

    // C-DIFF-05 · suelo.
    let t_floor = p.t_floor()?;
    if t < t_floor {
        t = t_floor;
    }

    // C-DIFF-06 · suma de targets en U512, sin divisiones intermedias.
    let mut s = U512::zero();
    for target in v.targets {
        let ancho = U512::from(*target);
        s = s
            .checked_add(ancho)
            .ok_or(ErrorPow::DesbordamientoAritmetico)?;
    }

    // C-DIFF-07 · `next = (S · t · BIAS_NUM) / (NK · BIAS_DEN)`, división entera truncada.
    let t_u = u64::try_from(t).map_err(|_| ErrorPow::DesbordamientoAritmetico)?;
    let numerador = s
        .checked_mul(U512::from(t_u))
        .and_then(|x| x.checked_mul(U512::from(BIAS_NUM)))
        .ok_or(ErrorPow::DesbordamientoAritmetico)?;
    let nk = u64::try_from(p.nk()?).map_err(|_| ErrorPow::DesbordamientoAritmetico)?;
    let denominador = U512::from(nk)
        .checked_mul(U512::from(BIAS_DEN))
        .ok_or(ErrorPow::DesbordamientoAritmetico)?;
    if denominador.is_zero() {
        return Err(ErrorPow::DesbordamientoAritmetico);
    }
    let next = numerador / denominador;

    // C-DIFF-08 · acotado. El clamp se aplica en U512 y solo después se estrecha, para que un
    // resultado por encima del máximo no se trunque en silencio al convertir.
    let techo = U512::from(p.limites.max);
    let suelo = U512::from(p.limites.min);
    let acotado = next.max(suelo).min(techo);

    // Tras el clamp, `acotado ≤ max < 2^256`, así que entra en U256 sin pérdida. Se convierte por
    // bytes en vez de con `low_u256()` para que la conversión sea explícita y auditable.
    let bytes = acotado.to_big_endian();
    let bajos = bytes.get(32..).ok_or(ErrorPow::DesbordamientoAritmetico)?;
    Ok(U256::from_big_endian(bajos))
}

/// Median-time-past sobre los `mtp_w` bloques anteriores (`C-TS-02`).
///
/// **Solo** sirve de reloj para `lock_time` y HTLC. **MUST NOT** entrar en el retarget.
///
/// # Errores
/// [`ErrorPow::MtpDeTamanoIncorrecto`] si no se dan exactamente `mtp_w` timestamps.
pub fn median_time_past(ultimos: &[i64], p: &ParametrosPow) -> Result<i64, ErrorPow> {
    if ultimos.len() != p.mtp_w {
        return Err(ErrorPow::MtpDeTamanoIncorrecto {
            recibidos: ultimos.len(),
            esperados: p.mtp_w,
        });
    }
    let mut v = ultimos.to_vec();
    v.sort_unstable();
    v.get(p.mtp_w / 2).copied().ok_or(ErrorPow::VentanaVacia)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{BIAS_DEN, BIAS_NUM, VentanaRetarget, median_time_past, siguiente_target};
    use crate::error::ErrorPow;
    use crate::parametros::{PARAMETROS_POW_ANTIGUOS, ParametrosPow};
    use primitive_types::{U256, U512};

    fn p() -> ParametrosPow {
        PARAMETROS_POW_ANTIGUOS
    }

    /// Ventana en la que todos los bloques salieron exactamente a tiempo y con el mismo target.
    fn ventana_estable(target: U256) -> (Vec<i64>, Vec<U256>) {
        let pp = p();
        let ts: Vec<i64> = (0..=pp.n)
            .map(|i| i64::try_from(i).unwrap() * pp.t)
            .collect();
        let tg: Vec<U256> = vec![target; pp.n];
        (ts, tg)
    }

    fn calcular(ts: &[i64], tg: &[U256]) -> U256 {
        siguiente_target(
            VentanaRetarget {
                timestamps: ts,
                targets: tg,
            },
            &p(),
        )
        .unwrap()
    }

    /// Con la red exactamente en su ritmo, el target no se mueve (BIAS = 1).
    #[test]
    fn en_regimen_estable_el_target_apenas_se_mueve() {
        let base = U256::one() << 200_usize;
        let (ts, tg) = ventana_estable(base);
        let next = calcular(&ts, &tg);

        let ratio_num = U512::from(next) * U512::from(1_000_000_u32);
        let ratio = (ratio_num / U512::from(base)).low_u64();
        assert!(
            (990_000..=1_000_000).contains(&ratio),
            "esperado ~1,0·base con BIAS = 1, salió ratio {ratio}/1e6"
        );
        assert!(
            next <= base,
            "la corrección del sesgo MUST hacer el target igual o menor"
        );
    }

    /// Bloques al doble de rápido ⇒ el target **baja** (más difícil).
    #[test]
    fn bloques_rapidos_endurecen() {
        let base = U256::one() << 200_usize;
        let (_, tg) = ventana_estable(base);
        let pp = p();
        let rapidos: Vec<i64> = (0..=pp.n)
            .map(|i| i64::try_from(i).unwrap() * (pp.t / 2))
            .collect();
        let next = calcular(&rapidos, &tg);
        assert!(
            next < base,
            "el doble de rápido debe endurecer: {next} < {base}"
        );
    }

    /// Bloques al doble de lentos ⇒ el target **sube** (más fácil).
    #[test]
    fn bloques_lentos_ablandan() {
        let base = U256::one() << 200_usize;
        let (_, tg) = ventana_estable(base);
        let pp = p();
        let lentos: Vec<i64> = (0..=pp.n)
            .map(|i| i64::try_from(i).unwrap() * (pp.t * 2))
            .collect();
        let next = calcular(&lentos, &tg);
        assert!(
            next > base,
            "el doble de lentos debe ablandar: {next} > {base}"
        );
    }

    /// **C-DIFF-05, y el motivo de P-003.** El suelo acota el endurecimiento a ×10.
    #[test]
    fn el_suelo_acota_el_endurecimiento_a_diez_veces() {
        let base = U256::one() << 200_usize;
        let (_, tg) = ventana_estable(base);
        let pp = p();
        let hostiles: Vec<i64> = (0..=pp.n).map(|i| i64::try_from(i).unwrap()).collect();
        let next = calcular(&hostiles, &tg);

        let diez_veces_mas_dificil = base / U256::from(10_u32);
        let cien_veces = base / U256::from(100_u32);
        assert!(
            next > cien_veces,
            "sin suelo caería a ~base/120; con suelo no: {next}"
        );
        assert!(
            next <= diez_veces_mas_dificil * U256::from(11_u32) / U256::from(10_u32),
            "el suelo debe acotar el endurecimiento cerca de ×10: {next}"
        );
    }

    /// **C-DIFF-03: el invariante es por construcción, no por saturación.**
    #[test]
    fn los_timestamps_que_retroceden_no_hunden_la_dificultad() {
        let base = U256::one() << 200_usize;
        let (_, tg) = ventana_estable(base);
        let pp = p();

        let mut caos: Vec<i64> = Vec::with_capacity(pp.n + 1);
        for i in 0..=pp.n {
            let i = i64::try_from(i).unwrap();
            caos.push(if i % 3 == 0 {
                i * pp.t
            } else {
                i * pp.t - 10_000
            });
        }
        let next = calcular(&caos, &tg);

        assert!(next >= pp.limites.min && next <= pp.limites.max);
        assert!(
            next <= base * U256::from(11_u32) / U256::from(10_u32),
            "un retroceso de timestamps NO debe poder ablandar la dificultad: {next}"
        );
    }

    /// C-DIFF-08: el resultado siempre queda dentro de `[min, max]` de la red.
    #[test]
    fn el_resultado_siempre_esta_acotado() {
        let pp = p();
        let (_, tg) = ventana_estable(pp.limites.max);
        let lentisimos: Vec<i64> = (0..=pp.n)
            .map(|i| i64::try_from(i).unwrap() * 100_000)
            .collect();
        assert!(
            calcular(&lentisimos, &tg) <= pp.limites.max,
            "C-DIFF-08: techo"
        );

        let (_, tg) = ventana_estable(pp.limites.min);
        let instantaneos: Vec<i64> = (0..=pp.n).map(|i| i64::try_from(i).unwrap()).collect();
        assert!(
            calcular(&instantaneos, &tg) >= pp.limites.min,
            "C-DIFF-08: suelo"
        );
    }

    /// C-DIFF-01: función pura. La misma ventana da siempre el mismo resultado.
    #[test]
    fn es_determinista() {
        let base = U256::one() << 190_usize;
        let (ts, tg) = ventana_estable(base);
        let a = calcular(&ts, &tg);
        for _ in 0..8 {
            assert_eq!(calcular(&ts, &tg), a);
        }
    }

    /// C-DIFF-02: la ventana es **siempre** de tamaño `N`. No se encoge ni crece.
    #[test]
    fn se_rechaza_una_ventana_de_tamano_incorrecto() {
        let pp = p();
        let base = U256::one() << 200_usize;
        let ts_largo: Vec<i64> = (0..=(pp.n + 5))
            .map(|i| i64::try_from(i).unwrap() * pp.t)
            .collect();
        let tg_largo: Vec<U256> = vec![base; pp.n + 5];

        let casos = [
            (pp.n, pp.n),
            (pp.n + 1, pp.n - 1),
            (pp.n + 2, pp.n),
            (pp.n + 1, pp.n + 1),
            (0, 0),
            (pp.n + 3, pp.n + 2),
        ];
        for (t_len, g_len) in casos {
            let r = siguiente_target(
                VentanaRetarget {
                    timestamps: ts_largo.get(..t_len).unwrap(),
                    targets: tg_largo.get(..g_len).unwrap(),
                },
                &pp,
            );
            assert!(
                matches!(r, Err(ErrorPow::VentanaDeTamanoIncorrecto { .. })),
                "({t_len}, {g_len}) debería rechazarse, devolvió {r:?}"
            );
        }

        assert!(
            siguiente_target(
                VentanaRetarget {
                    timestamps: ts_largo.get(..=pp.n).unwrap(),
                    targets: tg_largo.get(..pp.n).unwrap(),
                },
                &pp,
            )
            .is_ok(),
            "(N+1, N) es la única forma válida"
        );
    }

    /// ✅ **P-005 cerrado: no se corrige.** `BIAS = 1/1`, y este test lo fija.
    #[test]
    fn la_correccion_del_sesgo_sigue_en_la_identidad() {
        assert_eq!(
            (BIAS_NUM, BIAS_DEN),
            (1, 1),
            "P-005 se cerró en NO corregir"
        );
    }

    /// La derivación que refutó la dirección anterior, ejecutada de verdad para que no se repita.
    #[test]
    fn el_clamp_sesga_el_solvetime_a_la_baja() {
        const ESCALA: i128 = 1_000_000_000_000;
        let mut termino: i128 = ESCALA;
        let mut suma: i128 = 0;
        for n in 0..64_i128 {
            suma += termino;
            termino = termino * -6 / (n + 1);
        }
        let e_menos_6 = suma;
        let factor = ESCALA - e_menos_6;

        assert!(
            (997_500_000_000..=997_530_000_000).contains(&factor),
            "1 − e⁻⁶ debería ser ≈0,99752; salió {factor}/{ESCALA}"
        );

        let t_ms: i128 = 120_000;
        let media_truncada = t_ms * factor / ESCALA;
        assert!(
            media_truncada < t_ms,
            "el clamp recorta por arriba: la media observada ({media_truncada} ms) MUST ser menor \
             que T ({t_ms} ms)"
        );

        let corrector = t_ms * ESCALA / media_truncada;
        assert!(
            corrector > ESCALA,
            "el factor corrector es {corrector}/{ESCALA} > 1 — ponerlo < 1 empeora el sesgo"
        );
    }

    /// Cota de overflow de C-DIFF-07 con los valores máximos reales del perfil antiguo.
    #[test]
    fn el_numerador_de_c_diff_07_cabe_en_u512() {
        let pp = p();
        let s_max = U512::from(pp.limites.max) * U512::from(u32::try_from(pp.n).unwrap());
        let t_max = U512::from(u64::try_from(pp.st_cap().unwrap()).unwrap())
            * U512::from(u64::try_from(pp.n * (pp.n + 1) / 2).unwrap());
        let prod = s_max
            .checked_mul(t_max)
            .and_then(|x| x.checked_mul(U512::from(BIAS_NUM)));
        assert!(prod.is_some(), "el numerador MUST caber en U512");
        let bits = 512 - prod.unwrap().leading_zeros();
        assert!(bits <= 280, "el numerador ocupa {bits} bits");
    }

    // ── MTP ──────────────────────────────────────────────────────────────────

    #[test]
    fn el_mtp_es_la_mediana_y_no_le_afecta_el_orden() {
        let pp = p();
        let v: Vec<i64> = (0..pp.mtp_w)
            .map(|i| i64::try_from(i).unwrap() * 10)
            .collect();
        let esperado = i64::try_from(pp.mtp_w / 2).unwrap() * 10;
        assert_eq!(median_time_past(&v, &pp).unwrap(), esperado);

        let mut desordenado = v;
        desordenado.reverse();
        assert_eq!(
            median_time_past(&desordenado, &pp).unwrap(),
            esperado,
            "la mediana no ve el orden"
        );
    }

    #[test]
    fn el_mtp_exige_exactamente_once_timestamps() {
        let pp = p();
        assert!(median_time_past(&[1, 2, 3], &pp).is_err());
        assert!(median_time_past(&[], &pp).is_err());
    }
}
