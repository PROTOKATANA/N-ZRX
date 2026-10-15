//! Reloj por ticks del PoT (`C-RLJ-02`…`C-RLJ-07` de `CONTRATO-RELOJ-v0.md`) y adelanto del
//! segundo VDF (`C-RLJ-VDF-01`).
//!
//! # Qué implementa
//!
//! - El estado del reloj `(T, n_iter)` con `N(s) = T(s)·n_iter` y techo `N_max` (`C-RLJ-02`,
//!   `C-RLJ-07`). `n_iter` debe ser múltiplo de 16 para que **todo** `T` entero dé un `N(s)` en el
//!   dominio de la primitiva (`REVISION-RL1.md`, RL1-A10); lo comprueba [`EstadoReloj::valida`].
//! - El ajuste determinista de `T` con la **medida de la ventana como entrada** (`C-RLJ-05`),
//!   la duplicación si `T > 100` (`C-RLJ-03`) y el recorte por el techo (`C-RLJ-07`). La medida la
//!   aporta el llamante: este módulo **no** lee timestamps ni reloj local; RL-2b la cablea a la
//!   ventana de `C-RLJ-04`.
//! - El estimador robusto por mitades `tau_est = (t2 − t1)/(s2 − s1)` (`C-RLJ-04`) y la mediana
//!   exacta que usa, más la cota de manipulación de la mediana (`cuantil_mediana_bajo_ataque`).
//! - El adelanto del adversario con y sin segundo VDF (`C-RLJ-VDF-01`):
//!   `sin_vdf = L`, `con_vdf = (L + I)(1 − 1/ρ)`, `ρ* = 1 + L/I`.
//!
//! # Aritmética
//!
//! [`Racional`] es una fracción exacta `i128/i128` normalizada; las fronteras del ajuste (`d = ±U`)
//! se deciden con comparación exacta, nunca en coma flotante. Las cifras de los `<<PENDIENTE>>`
//! (`n_iter`, `U`, `L`, `I`) llegan como argumentos.

use core::cmp::Ordering;
use core::fmt;
use core::ops::{Add, Div, Mul, Neg, Sub};

/// Umbral de la regla de duplicación de `C-RLJ-03`: si el `T` ajustado supera este valor,
/// `n_iter ← 2·n_iter` y `T ← ⌊T/2⌋`.
pub const T_UMBRAL_DUP: u64 = 100;

/// Defecto de una operación del reloj.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorReloj {
    /// Un denominador cero en una fracción exacta.
    #[error("denominador cero en una fracción exacta")]
    DenominadorCero,
    /// `n_iter` no es positivo.
    #[error("n_iter debe ser positivo, no {n_iter}")]
    NIterCero {
        /// Valor recibido.
        n_iter: u64,
    },
    /// `n_iter` no es múltiplo de 16 (`REVISION-RL1.md`, RL1-A10).
    #[error("n_iter = {n_iter} no es múltiplo de 16 (RL1-A10)")]
    NIterNoMultiploDe16 {
        /// Valor recibido.
        n_iter: u64,
    },
    /// La ventana del estimador tiene `s2 ≤ s1`.
    #[error("ventana inválida: s2 = {s2} no es mayor que s1 = {s1}")]
    VentanaInvalida {
        /// Mediana de los slots de la primera mitad.
        s1: u64,
        /// Mediana de los slots de la segunda mitad.
        s2: u64,
    },
    /// La mediana se pidió sobre una colección vacía.
    #[error("no hay mediana de una colección vacía")]
    ColeccionVacia,
    /// La fracción del atacante en una mitad no cae en `[0, 1/2)`.
    #[error("alpha_mitad = {alpha_mitad} fuera de [0, 1/2)")]
    AlphaFueraDeRango {
        /// Valor recibido, en forma `num/den`.
        alpha_mitad: Racional,
    },
    /// `ρ ≤ 1`: la fórmula del adelanto exige `ρ > 1`.
    #[error("ρ = {rho} debe ser mayor que 1")]
    RhoInvalido {
        /// Valor recibido, en forma `num/den`.
        rho: Racional,
    },
    /// `I = 0` no permite calcular `ρ* = 1 + L/I`.
    #[error("I no puede ser cero para ρ*")]
    ICero,
}

/// Fracción exacta `num/den` con `den > 0` y reducida a su forma canónica.
///
/// El contrato expresa las fronteras del ajuste, los cuantiles y el adelanto con racionales
/// exactos; usarlos evita que `d = ±U` se decida con redondeo. `Display` emite siempre
/// `num/den` (por ejemplo `20/1`), el formato de los vectores de RL-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Racional {
    num: i128,
    den: i128,
}

/// Máximo común divisor de dos enteros (Euclides, sin división truncada).
fn mcd(mut a: i128, mut b: i128) -> i128 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

impl Racional {
    /// Construye la fracción `num/den`, normalizada.
    ///
    /// # Errores
    /// [`ErrorReloj::DenominadorCero`] si `den == 0`.
    pub fn nuevo(num: i128, den: i128) -> Result<Self, ErrorReloj> {
        if den == 0 {
            return Err(ErrorReloj::DenominadorCero);
        }
        let (num, den) = if den < 0 { (-num, -den) } else { (num, den) };
        if num == 0 {
            return Ok(Self { num: 0, den: 1 });
        }
        let g = mcd(num, den);
        // `g` divide a `num` y a `den` por construcción; la división es exacta.
        let num = dividir_exacta(num, g);
        let den = dividir_exacta(den, g);
        Ok(Self { num, den })
    }

    /// Entero `n` como fracción `n/1`.
    #[must_use]
    pub const fn entero(n: i128) -> Self {
        Self { num: n, den: 1 }
    }

    /// Construye `num/den` **ya normalizada** (`den > 0`), sin calcular el `mcd`.
    ///
    /// Solo para constantes escritas a mano (por ejemplo `1/2`); usar [`Racional::nuevo`] para
    /// valores calculados.
    #[must_use]
    pub const fn nuevo_const(num: i128, den: i128) -> Self {
        Self { num, den }
    }

    /// Cero (`0/1`).
    #[must_use]
    pub const fn cero() -> Self {
        Self { num: 0, den: 1 }
    }

    /// Uno (`1/1`).
    #[must_use]
    pub const fn uno() -> Self {
        Self { num: 1, den: 1 }
    }

    /// Dos (`2/1`).
    #[must_use]
    pub const fn dos() -> Self {
        Self { num: 2, den: 1 }
    }

    /// Numerador (con el signo).
    #[must_use]
    pub const fn num(&self) -> i128 {
        self.num
    }

    /// Denominador (siempre positivo).
    #[must_use]
    pub const fn den(&self) -> i128 {
        self.den
    }

    /// ¿Es cero?
    #[must_use]
    pub const fn es_cero(&self) -> bool {
        self.num == 0
    }

    /// Valor absoluto.
    #[must_use]
    pub const fn abs(&self) -> Self {
        Self {
            num: self.num.abs(),
            den: self.den,
        }
    }

    /// Convierte a `f64` (sólo para diagnóstico y vectores que piden flotante).
    #[must_use]
    pub fn a_f64(&self) -> f64 {
        self.num as f64 / self.den as f64
    }
}

/// División exacta de enteros, con el lint de división entera apartado explícitamente.
#[expect(
    clippy::integer_division,
    reason = "la división es exacta: `g` divide a `a` por construcción (mcd o normalización)"
)]
fn dividir_exacta(a: i128, g: i128) -> i128 {
    a / g
}

impl fmt::Display for Racional {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.num, self.den)
    }
}

impl PartialOrd for Racional {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Racional {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.num * other.den).cmp(&(other.num * self.den))
    }
}

impl Neg for Racional {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            num: -self.num,
            den: self.den,
        }
    }
}

impl Add for Racional {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let num = self.num * other.den + other.num * self.den;
        let den = self.den * other.den;
        Self::nuevo(num, den).unwrap_or(Self::cero())
    }
}

impl Sub for Racional {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        self + (-other)
    }
}

impl Mul for Racional {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        Self::nuevo(self.num * other.num, self.den * other.den).unwrap_or(Self::cero())
    }
}

impl Div for Racional {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        Self::nuevo(self.num * other.den, self.den * other.num).unwrap_or(Self::cero())
    }
}

/// Estado del reloj: `T` ticks por slot, `n_iter` iteraciones por tick y techo `N_max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstadoReloj {
    t: u64,
    n_iter: u64,
    n_max: u64,
}

impl EstadoReloj {
    /// Construye un estado `(T, n_iter, N_max)`.
    #[must_use]
    pub const fn nuevo(t: u64, n_iter: u64, n_max: u64) -> Self {
        Self { t, n_iter, n_max }
    }

    /// `T` ticks por slot.
    #[must_use]
    pub const fn t(&self) -> u64 {
        self.t
    }

    /// `n_iter` iteraciones por tick.
    #[must_use]
    pub const fn n_iter(&self) -> u64 {
        self.n_iter
    }

    /// Techo `N_max` de iteraciones por slot.
    #[must_use]
    pub const fn n_max(&self) -> u64 {
        self.n_max
    }

    /// `N(s) = T·n_iter` del estado.
    #[must_use]
    pub const fn iteraciones(&self) -> u64 {
        self.t.saturating_mul(self.n_iter)
    }

    /// Comprueba el dominio de RL1-A10: `n_iter > 0` y `n_iter % 16 == 0`.
    ///
    /// # Errores
    /// [`ErrorReloj::NIterCero`] o [`ErrorReloj::NIterNoMultiploDe16`].
    pub fn valida(&self) -> Result<(), ErrorReloj> {
        if self.n_iter == 0 {
            return Err(ErrorReloj::NIterCero {
                n_iter: self.n_iter,
            });
        }
        if !self.n_iter.is_multiple_of(16) {
            return Err(ErrorReloj::NIterNoMultiploDe16 {
                n_iter: self.n_iter,
            });
        }
        Ok(())
    }
}

/// Acción que tomó el ajuste `C-RLJ-05`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accion {
    /// `T` bajó un tick (los slots medidos son más lentos que `τ*`).
    Bajar,
    /// `T` no cambió.
    Igual,
    /// `T` subió un tick (los slots medidos son más rápidos que `τ*`).
    Subir,
}

/// Resultado de un paso de ajuste: estado nuevo, acción y si se aplicó la duplicación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ajuste {
    /// Estado `(T, n_iter, N_max)` resultante.
    pub estado: EstadoReloj,
    /// Acción de `C-RLJ-05` antes de duplicar y recortar.
    pub accion: Accion,
    /// `true` si se aplicó `C-RLJ-03` (`T` superó 100).
    pub duplicado: bool,
}

/// Aplica un paso de `C-RLJ-05`, después `C-RLJ-03` y por último el techo `C-RLJ-07`.
///
/// `tau_est` es la medida de la ventana (la aporta el llamante; `C-RLJ-04`), `tau_ref` el objetivo
/// y `u` la banda muerta. Con `d = tau_est − tau_ref`:
///
/// ```text
/// d >  U  -> T − 1
/// d < −U  -> T + 1
/// si no   -> T
/// ```
///
/// Luego, si `T > 100`: `n_iter ← 2·n_iter`, `T ← ⌊T/2⌋` (RL1-A2, lectura (i)). Al final, si
/// `T·n_iter > N_max`, `T ← max(1, ⌊N_max/n_iter⌋)`.
#[must_use]
pub fn ajustar(estado: EstadoReloj, tau_est: Racional, tau_ref: Racional, u: Racional) -> Ajuste {
    let delta = tau_est - tau_ref;
    let (t_accion, accion) = if delta > u {
        (estado.t.saturating_sub(1), Accion::Bajar)
    } else if delta < -u {
        (estado.t.saturating_add(1), Accion::Subir)
    } else {
        (estado.t, Accion::Igual)
    };
    let mut t2 = t_accion.max(1);
    let mut n2 = estado.n_iter;
    let mut duplicado = false;
    if t2 > T_UMBRAL_DUP {
        n2 = n2.saturating_mul(2);
        t2 >>= 1;
        duplicado = true;
    }
    if u128::from(t2) * u128::from(n2) > u128::from(estado.n_max) {
        t2 = recorte_techo(estado.n_max, n2);
    }
    Ajuste {
        estado: EstadoReloj {
            t: t2,
            n_iter: n2,
            n_max: estado.n_max,
        },
        accion,
        duplicado,
    }
}

/// `T` recortado por el techo: `max(1, ⌊N_max / n_iter⌋)`.
fn recorte_techo(n_max: u64, n_iter: u64) -> u64 {
    if n_iter == 0 {
        return 1;
    }
    n_max.checked_div(n_iter).unwrap_or(1).max(1)
}

/// Mediana **exacta** de una colección de enteros (`C-RLJ-04`).
///
/// Con longitud impar es el valor central; con longitud par, la media de los dos centrales
/// (`Rational`, para no perder exactitud).
///
/// # Errores
/// [`ErrorReloj::ColeccionVacia`] si `valores` está vacía.
pub fn mediana(valores: &[u64]) -> Result<Racional, ErrorReloj> {
    if valores.is_empty() {
        return Err(ErrorReloj::ColeccionVacia);
    }
    let mut ordenados: Vec<u64> = valores.to_vec();
    ordenados.sort_unstable();
    let n = ordenados.len();
    let mitad = n >> 1;
    if n % 2 == 1 {
        let centro = *ordenados.get(mitad).ok_or(ErrorReloj::ColeccionVacia)?;
        Racional::nuevo(i128::from(centro), 1)
    } else {
        let baja = *ordenados.get(mitad - 1).ok_or(ErrorReloj::ColeccionVacia)?;
        let alta = *ordenados.get(mitad).ok_or(ErrorReloj::ColeccionVacia)?;
        Racional::nuevo(i128::from(baja) + i128::from(alta), 2)
    }
}

/// Estimador robusto por mitades de `C-RLJ-04`: `tau_est = (t2 − t1)/(s2 − s1)`.
///
/// Recibe la mediana de los timestamps (`t1`, `t2`) y de los slots (`s1`, `s2`) de las dos mitades
/// de la ventana y devuelve el tiempo de slot estimado, exacto.
///
/// # Errores
/// [`ErrorReloj::VentanaInvalida`] si `s2 ≤ s1`.
pub fn tau_estimado_ventana(t1: u64, s1: u64, t2: u64, s2: u64) -> Result<Racional, ErrorReloj> {
    let ds = s2
        .checked_sub(s1)
        .ok_or(ErrorReloj::VentanaInvalida { s1, s2 })?;
    if ds == 0 {
        return Err(ErrorReloj::VentanaInvalida { s1, s2 });
    }
    let dt = i128::from(t2) - i128::from(t1);
    Racional::nuevo(dt, i128::from(ds))
}

/// Cuantil de la mediana de una mitad atacada: `u = 1/(2(1 − alpha_mitad))`.
///
/// # Errores
/// [`ErrorReloj::AlphaFueraDeRango`] si `alpha_mitad` no cae en `[0, 1/2)`.
pub fn cuantil_mediana_bajo_ataque(alpha_mitad: Racional) -> Result<Racional, ErrorReloj> {
    let medio = Racional::nuevo(1, 2)?;
    if alpha_mitad < Racional::cero() || alpha_mitad >= medio {
        return Err(ErrorReloj::AlphaFueraDeRango { alpha_mitad });
    }
    let denominador = Racional::dos() * (Racional::uno() - alpha_mitad);
    Ok(Racional::uno() / denominador)
}

/// Cota de la manipulación por mitades del estimador `C-RLJ-04`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sesgo {
    /// Fracción del atacante dentro de la mitad atacada.
    pub alpha_mitad: Racional,
    /// Cuantil de la distribución honesta al que se mueve la mediana de esa mitad.
    pub cuantil_mediana: Racional,
}

/// Reparte la fracción `alpha_total` de la ventana en una sola mitad:
/// `alpha_mitad = min(2·alpha_total, A/(2(A+1)))` y devuelve el cuantil forzado.
///
/// # Errores
/// [`ErrorReloj::AlphaFueraDeRango`] o [`ErrorReloj::DenominadorCero`] en los casos límite.
pub fn sesgo_por_mitades(alpha_total: Racional, a: u64) -> Result<Sesgo, ErrorReloj> {
    if alpha_total < Racional::cero() {
        return Err(ErrorReloj::AlphaFueraDeRango {
            alpha_mitad: alpha_total,
        });
    }
    let a_i = i128::from(a);
    let limite = Racional::nuevo(a_i, 2 * (a_i + 1))?;
    let doble = Racional::dos() * alpha_total;
    let alpha_mitad = if doble < limite { doble } else { limite };
    let cuantil_mediana = cuantil_mediana_bajo_ataque(alpha_mitad)?;
    Ok(Sesgo {
        alpha_mitad,
        cuantil_mediana,
    })
}

/// Adelanto del adversario **sin** segundo VDF (en slots): `L` (`C-RLJ-VDF-01`).
#[must_use]
pub fn adelanto_sin_vdf(l: u64) -> Racional {
    Racional::entero(i128::from(l))
}

/// Adelanto del adversario **con** segundo VDF: `(L + I)(1 − 1/ρ)` (`C-RLJ-VDF-01`), exacto.
///
/// # Errores
/// [`ErrorReloj::RhoInvalido`] si `rho ≤ 1`.
pub fn adelanto_con_vdf(l: u64, i: u64, rho: Racional) -> Result<Racional, ErrorReloj> {
    if rho <= Racional::uno() {
        return Err(ErrorReloj::RhoInvalido { rho });
    }
    let li = Racional::entero(i128::from(l) + i128::from(i));
    Ok(li * (Racional::uno() - Racional::uno() / rho))
}

/// Umbral `ρ* = 1 + L/I` por encima del cual el segundo VDF no recorta.
///
/// # Errores
/// [`ErrorReloj::ICero`] si `i == 0`.
pub fn rho_umbral(l: u64, i: u64) -> Result<Racional, ErrorReloj> {
    if i == 0 {
        return Err(ErrorReloj::ICero);
    }
    Ok(Racional::uno() + Racional::entero(i128::from(l)) / Racional::entero(i128::from(i)))
}

/// ¿El segundo VDF recorta el adelanto? Ocurre sólo si `ρ < ρ*`.
///
/// # Errores
/// Las de [`rho_umbral`].
pub fn segundo_vdf_util(l: u64, i: u64, rho: Racional) -> Result<bool, ErrorReloj> {
    Ok(rho < rho_umbral(l, i)?)
}

/// Recorte relativo del adelanto frente a `L`: `1 − con_vdf/L`.
///
/// # Errores
/// [`ErrorReloj::RhoInvalido`] o [`ErrorReloj::DenominadorCero`] si `l == 0`.
pub fn recorte(l: u64, i: u64, rho: Racional) -> Result<Racional, ErrorReloj> {
    let con = adelanto_con_vdf(l, i, rho)?;
    let sin = adelanto_sin_vdf(l);
    if sin.es_cero() {
        return Err(ErrorReloj::DenominadorCero);
    }
    Ok(Racional::uno() - con / sin)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan por diseño")]
mod pruebas {
    use super::{
        Accion, ErrorReloj, EstadoReloj, Racional, ajustar, cuantil_mediana_bajo_ataque, mediana,
        sesgo_por_mitades, tau_estimado_ventana,
    };

    fn r(num: i128, den: i128) -> Racional {
        Racional::nuevo(num, den).expect("fracción válida")
    }

    #[test]
    fn racional_normaliza_y_ordena() {
        assert_eq!(r(4, 8).to_string(), "1/2");
        assert_eq!(r(-4, 8).to_string(), "-1/2");
        assert_eq!(r(3, 1).to_string(), "3/1");
        assert!(r(1, 3) < r(1, 2));
        assert_eq!(Racional::nuevo(1, 0), Err(ErrorReloj::DenominadorCero));
    }

    #[test]
    fn fronteras_exactas_del_ajuste() {
        let base = EstadoReloj::nuevo(50, 2_603_792, 240_000_000);
        let tau_ref = r(1000, 1);
        let u = r(5, 1);
        // d = +6 > U: baja.
        let bajo = ajustar(base, r(1006, 1), tau_ref, u);
        assert_eq!((bajo.accion, bajo.estado.t()), (Accion::Bajar, 49));
        // d = +5 = U: no cambia.
        let igual = ajustar(base, r(1005, 1), tau_ref, u);
        assert_eq!((igual.accion, igual.estado.t()), (Accion::Igual, 50));
        // d = −5 = −U: no cambia.
        let igual2 = ajustar(base, r(995, 1), tau_ref, u);
        assert_eq!((igual2.accion, igual2.estado.t()), (Accion::Igual, 50));
        // d = −6 < −U: sube.
        let alto = ajustar(base, r(994, 1), tau_ref, u);
        assert_eq!((alto.accion, alto.estado.t()), (Accion::Subir, 51));
    }

    #[test]
    fn duplicacion_y_techo() {
        let tau_ref = r(1000, 1);
        let u = r(5, 1);
        // T=100, +1 -> 101: duplica n_iter y T=50; N = 200 000 000 <= N_max.
        let dup = ajustar(
            EstadoReloj::nuevo(100, 2_000_000, 240_000_000),
            r(994, 1),
            tau_ref,
            u,
        );
        assert!(dup.duplicado);
        assert_eq!(
            (
                dup.estado.t(),
                dup.estado.n_iter(),
                dup.estado.iteraciones()
            ),
            (50, 4_000_000, 200_000_000)
        );
        // T=100, n_iter=2 603 792: la duplicación dispara el techo y recorta a 46.
        let techo = ajustar(
            EstadoReloj::nuevo(100, 2_603_792, 240_000_000),
            r(994, 1),
            tau_ref,
            u,
        );
        assert!(techo.duplicado);
        assert_eq!(techo.estado.t(), 46);
        assert_eq!(techo.estado.iteraciones(), 239_548_864);
        // T=92, +1 -> 93 excede el techo: se recorta a 92.
        let sat = ajustar(
            EstadoReloj::nuevo(92, 2_603_792, 240_000_000),
            r(994, 1),
            tau_ref,
            u,
        );
        assert!(!sat.duplicado);
        assert_eq!(sat.estado.t(), 92);
        assert_eq!(sat.estado.iteraciones(), 239_548_864);
    }

    #[test]
    fn mediana_y_estimador() {
        assert_eq!(mediana(&[10, 20, 30]).expect("mediana"), r(20, 1));
        assert_eq!(mediana(&[10, 20, 30, 40]).expect("mediana"), r(25, 1));
        assert_eq!(
            tau_estimado_ventana(1_000, 10, 1_004, 14).expect("tau"),
            r(1, 1)
        );
        assert!(matches!(
            tau_estimado_ventana(1, 10, 1, 10),
            Err(ErrorReloj::VentanaInvalida { .. })
        ));
    }

    #[test]
    fn cuantiles_y_sesgo() {
        assert_eq!(
            cuantil_mediana_bajo_ataque(r(0, 1)).expect("cuantil"),
            r(1, 2)
        );
        assert_eq!(
            cuantil_mediana_bajo_ataque(r(1, 10)).expect("cuantil"),
            r(5, 9)
        );
        assert_eq!(
            cuantil_mediana_bajo_ataque(r(1, 5)).expect("cuantil"),
            r(5, 8)
        );
        let s = sesgo_por_mitades(r(1, 4), 2048).expect("sesgo");
        assert_eq!(s.alpha_mitad, r(1024, 2049));
        assert_eq!(s.cuantil_mediana, r(2049, 2050));
    }

    #[test]
    fn estado_del_reloj_valida_el_dominio() {
        assert_eq!(
            EstadoReloj::nuevo(50, 0, u64::MAX).valida(),
            Err(ErrorReloj::NIterCero { n_iter: 0 })
        );
        assert_eq!(
            EstadoReloj::nuevo(50, 15, u64::MAX).valida(),
            Err(ErrorReloj::NIterNoMultiploDe16 { n_iter: 15 })
        );
        assert!(EstadoReloj::nuevo(50, 16, u64::MAX).valida().is_ok());
    }
}
