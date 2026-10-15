//! Perfil del reloj por ticks y **segundo VDF** en la red dev (RL-2b).
//!
//! # Qué hay aquí
//!
//! - [`ParametrosRelojPost`]: el tipo **nuevo** de parámetros del reloj y del segundo VDF. No se
//!   toca `ParametrosTransicion` (A-4 de `REVISION-RL2b-a.md`).
//! - [`PERFIL_RELOJ_DEV`]: valores de ejemplo **de dev**, rotulados (A-5). `n_iter` es múltiplo de
//!   16 (RL1-A10). No son parámetros de producción.
//! - [`semilla_vdf`], [`calcular_v_j`] y [`verificar_v_j`]: la parte C (`C-RLJ-VDF-02`,
//!   `C-RLJ-VDF-03`). La semilla se deriva **solo** de la salida del slot anterior de `past(B)` y
//!   del slot, nunca del `pot_output` del candidato: es lo que rompe la circularidad.
//!
//! # Límite declarado
//!
//! `calcular_v_j` ejecuta la primitiva AES real (`cadena_segmentada`). El orden acíclico es
//! condición **necesaria, no suficiente** sin la acreditación causal del pasado (lo advierte
//! `crate::pot_rango`).

use zx_core::wire_dag::POT_OUTPUT_BYTES;

use crate::reloj::{ErrorReloj, EstadoReloj, Racional, ajustar, tau_estimado_ventana};
use crate::vdf::{ErrorVdf, cadena_segmentada};

/// `T0` de ejemplo para dev: ticks por slot iniciales (`C-RLJ-02`).
pub const T0_DEV: u64 = 50;

/// `n_iter` de ejemplo para dev (múltiplo de 16, RL1-A10): con `T0 = 50` da `N(s) ≈ 1,3·10⁸`,
/// ≈1 s/slot con `t_iter ≈ 7,7 ns`, el ancla de RL-1. No es el de producción.
pub const N_ITER_DEV: u64 = 2_603_792;

/// `N_max` de ejemplo para dev (`2,4·10⁸` de PK-08).
pub const N_MAX_DEV: u64 = 240_000_000;

/// Margen de seguridad (`RL-2d-2`) entre `A_epoch` y `F_slots`: `A ≥ F + MARGEN_RELOJ`. El ajuste
/// de una frontera `f` solo está comprometido cuando el **punto de finalidad** alcanza `f`; con
/// `A = F + 1` un hueco de un solo slot sin bloque honesto retrasaba ese compromiso más allá de
/// `f + A` y el productor escribía con el `N` viejo (`Pot(AesFallido { slot: 1201 })`, hallazgo del
/// humo de RL-2d). La ventana de 64 slots hace despreciable que la finalidad no haya alcanzado `f`
/// al llegar `f + A` (≈ e⁻³² con la mitad honesta).
pub const MARGEN_RELOJ: u64 = 64;

/// `A_epoch` de ejemplo para dev (`RL-2d-2`): **`A = F_slots + MARGEN_RELOJ = 600 + 64 = 664`**.
/// La decisión 2 de `ORDEN-RL2d` exige el invariante `A ≥ F` (`a_epoch ≥ f_slots`) para que la
/// ventana de ajuste `(f − A, f]` quede por debajo del punto de finalidad de FIN-1 (`F = 600`);
/// `ORDEN-RL2d-2` lo endurece a `A ≥ F + MARGEN_RELOJ`, comprobado en
/// `zx_node::perfil::PerfilRedConsenso::validar`.
///
/// **Por qué no basta `F + 1`.** El humo de RL-2d con `A = F = 600` hizo caer a 1 de 4 nodos
/// (`Pot(AesFallido { slot: 1201 })`): el calendario se comprometía cuando el punto de finalidad
/// alcanzaba `f` (punta ≥ `f + F`), es decir **en el mismo slot `f + A`** que empezaba a regir, y el
/// productor de ese slot ya lo había calculado con el `N` anterior. La revisión de RL-2d mostró que
/// `F + 1` tampoco basta: si el slot `f` (o los siguientes) no tiene bloque, el punto de finalidad
/// no pasa de `f` hasta más tarde y el `N` llega después de empezar a regir. El valor de producción
/// es `A = 2048 ≥ F = 600`; este de dev va rotulado (A-5).
pub const A_EPOCH_DEV: u64 = 664;

/// `L` de ejemplo para dev (retardo de revelación, en slots).
pub const L_DEV: u64 = 600;

/// `I` de ejemplo para dev (separación entre inyecciones, en slots).
pub const I_DEV: u64 = 32;

/// Longitud del segundo VDF en iteraciones, de ejemplo para dev (`<<PENDIENTE>>` en el contrato).
/// Múltiplo de 16 para el dominio de la primitiva.
pub const I_ITER_DEV: u64 = 1_024;

/// Numerador de `U` de ejemplo para dev (banda muerta del ajuste). `0` es un valor de **dev**
/// rotulado: garantiza que el humo observe el ajuste cuando `tau_est ≠ tau_ref`.
pub const U_DEV_NUM: i128 = 0;

/// Denominador de `U` de ejemplo para dev.
pub const U_DEV_DEN: i128 = 1;

/// `tau_ref` de ejemplo para dev: `1` segundo por slot, el ancla de RL-1. La unidad del
/// `timestamp` de la cabecera es el segundo; el racional mantiene la relación exacta.
pub const TAU_REF_DEV_NUM: i128 = 1;

/// Denominador de `tau_ref` de ejemplo para dev.
pub const TAU_REF_DEV_DEN: i128 = 1;

/// Parámetros del reloj por ticks y del segundo VDF (tipo nuevo; `ParametrosTransicion` no se toca).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParametrosRelojPost {
    /// `T0`: ticks por slot iniciales.
    pub t0: u64,
    /// `n_iter`: iteraciones AES por tick (múltiplo de 16).
    pub n_iter: u64,
    /// `N_max`: techo de iteraciones por slot.
    pub n_max: u64,
    /// `U`: banda muerta del ajuste.
    pub u: Racional,
    /// `tau_ref`: duración objetivo del slot.
    pub tau_ref: Racional,
    /// `A_epoch`: ventana de ajuste, en slots.
    pub a_epoch: u64,
    /// `L`: retardo de revelación, en slots.
    pub l: u64,
    /// `I`: separación entre inyecciones, en slots.
    pub i: u64,
    /// Longitud del segundo VDF, en iteraciones (múltiplo de 16).
    pub i_iter: u64,
}

/// Perfil de reloj **de dev**, rotulado (A-5). No es de producción.
pub const PERFIL_RELOJ_DEV: ParametrosRelojPost = ParametrosRelojPost {
    t0: T0_DEV,
    n_iter: N_ITER_DEV,
    n_max: N_MAX_DEV,
    u: Racional::nuevo_const(U_DEV_NUM, U_DEV_DEN),
    tau_ref: Racional::nuevo_const(TAU_REF_DEV_NUM, TAU_REF_DEV_DEN),
    a_epoch: A_EPOCH_DEV,
    l: L_DEV,
    i: I_DEV,
    i_iter: I_ITER_DEV,
};

impl ParametrosRelojPost {
    /// Estado inicial `(T0, n_iter, N_max)` del reloj.
    #[must_use]
    pub const fn estado_inicial(&self) -> EstadoReloj {
        EstadoReloj::nuevo(self.t0, self.n_iter, self.n_max)
    }

    /// Primera frontera de epoch **estrictamente posterior** a `slot` (`s_e + A`, con `s_e` el
    /// último slot del epoch que contiene a `slot`).
    #[must_use]
    pub const fn siguiente_frontera(&self, slot: u64) -> u64 {
        if self.a_epoch == 0 {
            return slot.saturating_add(1);
        }
        let epoch = slot.div_euclid(self.a_epoch);
        epoch.saturating_add(1).saturating_mul(self.a_epoch)
    }
}

/// Mediana **superior** de una lista de enteros (la que usa el nodo para `C-RLJ-04`): con longitud
/// par devuelve el central alto (`v[len/2]`), no la media de los dos centrales.
fn mediana_superior(valores: &[u64]) -> Option<u64> {
    if valores.is_empty() {
        return None;
    }
    let mut v = valores.to_vec();
    v.sort_unstable();
    v.get(v.len() >> 1).copied()
}

/// `RL-2c` · calendario `N(s)` como función **determinista** de la cadena seleccionada en `past(B)`
/// (`C-RLJ-04`/`C-RLJ-06`).
///
/// `bloques` son los `(slot, timestamp)` de los bloques PoST de la cadena seleccionada, en orden de
/// cadena (antiguo → nuevo). El resultado depende **solo** del contenido de esa cadena: dos nodos
/// que validan el mismo bloque, aunque hayan visto los bloques en órdenes distintos, obtienen el
/// mismo calendario.
///
/// La regla replica `C-RLJ-04`/`C-RLJ-05`:
/// - para cada frontera `f = A, 2A, …` alcanzada por la cadena, la ventana `W_A` son los bloques
///   con `slot ∈ (f − A, f]`;
/// - `mitad1 = { slot ≤ f − A/2 }`, `mitad2 = W_A \ mitad1`;
/// - `tau_est = (mediana(ts2) − mediana(ts1)) / (mediana(slot2) − mediana(slot1))`;
/// - `T` se ajusta ±1 (con duplicación y techo) y el `N` nuevo rige desde `f + A`.
///
/// Devuelve el calendario `(desde_slot, N)` —incluye `(0, N0)`— y el estado final del reloj.
///
/// # Errores
/// [`ErrorReloj`] solo de la aritmética exacta del estimador; en la práctica no falla con una
/// ventana válida.
pub fn calendario_desde_cadena(
    params: &ParametrosRelojPost,
    bloques: &[(u64, u64)],
) -> Result<(Vec<(u64, u64)>, EstadoReloj), ErrorReloj> {
    let mut estado = params.estado_inicial();
    let mut calendario: Vec<(u64, u64)> = vec![(0, estado.iteraciones())];
    let a = params.a_epoch;
    if a == 0 {
        return Ok((calendario, estado));
    }
    let mitad = a.div_euclid(2);
    let max_slot = bloques.iter().map(|(s, _)| *s).max().unwrap_or(0);
    let mut f = a;
    while f <= max_slot {
        let desde = f.saturating_sub(a);
        let corte = f.saturating_sub(mitad);
        let mut ts1: Vec<u64> = Vec::new();
        let mut ss1: Vec<u64> = Vec::new();
        let mut ts2: Vec<u64> = Vec::new();
        let mut ss2: Vec<u64> = Vec::new();
        for (s, t) in bloques {
            if *s > desde && *s <= f {
                if *s <= corte {
                    ss1.push(*s);
                    ts1.push(*t);
                } else {
                    ss2.push(*s);
                    ts2.push(*t);
                }
            }
        }
        if let (Some(t1), Some(s1), Some(t2), Some(s2)) = (
            mediana_superior(&ts1),
            mediana_superior(&ss1),
            mediana_superior(&ts2),
            mediana_superior(&ss2),
        ) && let Ok(tau_est) = tau_estimado_ventana(t1, s1, t2, s2)
        {
            let ajuste = ajustar(estado, tau_est, params.tau_ref, params.u);
            estado = ajuste.estado;
            calendario.push((f.saturating_add(a), estado.iteraciones()));
        }
        f = f.saturating_add(a);
    }
    Ok((calendario, estado))
}

/// Fallo del segundo VDF.
#[derive(Debug, thiserror::Error)]
pub enum ErrorVdfPost {
    /// La primitiva rechazó la cadena larga.
    #[error("segundo VDF: {0}")]
    Vdf(#[from] ErrorVdf),
}

/// `semilla_vdf(j) = blake3(salida_anterior ‖ LE64(slot))[0..16)`.
///
/// `salida_anterior` es `salida(f, slot(B) − 1)`, que vive en `past(B)` ya validado; **no** es el
/// `pot_output` del candidato (`C-RLJ-VDF-03`).
#[must_use]
pub fn semilla_vdf(salida_anterior: [u8; POT_OUTPUT_BYTES], slot: u64) -> [u8; POT_OUTPUT_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&salida_anterior);
    hasher.update(&slot.to_le_bytes());
    let digest = hasher.finalize();
    let (cabeza, _) = digest.as_bytes().split_at(POT_OUTPUT_BYTES);
    let mut semilla = [0u8; POT_OUTPUT_BYTES];
    semilla.copy_from_slice(cabeza);
    semilla
}

/// `v_j = VDF(semilla_vdf(j), i_iter)` con la cadena larga segmentada real (`C-RLJ-VDF-02`).
///
/// # Errores
/// [`ErrorVdfPost::Vdf`] si la segmentación o la primitiva rechazan la longitud.
pub fn calcular_v_j(
    salida_anterior: [u8; POT_OUTPUT_BYTES],
    slot: u64,
    i_iter: u64,
) -> Result<[u8; POT_OUTPUT_BYTES], ErrorVdfPost> {
    let semilla = semilla_vdf(salida_anterior, slot);
    let cadena = cadena_segmentada(semilla, i_iter, crate::vdf::MAX_SEG)?;
    Ok(cadena.salida_final)
}

/// ¿El `v_j` declarado en la cabecera coincide con el recalculado desde `past(B)`?
///
/// Un `v_j` falso (incluido todo ceros) devuelve `Ok(false)`: es un defecto **del candidato**.
///
/// # Errores
/// [`ErrorVdfPost::Vdf`] si la longitud no es admisible por la primitiva (contexto, no candidato).
pub fn verificar_v_j(
    declarado: [u8; POT_OUTPUT_BYTES],
    salida_anterior: [u8; POT_OUTPUT_BYTES],
    slot: u64,
    i_iter: u64,
) -> Result<bool, ErrorVdfPost> {
    if declarado == [0u8; POT_OUTPUT_BYTES] {
        return Ok(false);
    }
    let esperado = calcular_v_j(salida_anterior, slot, i_iter)?;
    Ok(declarado == esperado)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
mod pruebas {
    use super::{
        A_EPOCH_DEV, I_ITER_DEV, N_ITER_DEV, PERFIL_RELOJ_DEV, ParametrosRelojPost, T0_DEV,
        calcular_v_j, calendario_desde_cadena, semilla_vdf, verificar_v_j,
    };

    #[test]
    fn v_j_correcto_verifica_y_falso_invalida() {
        let ancla = [0xAB; 16];
        let v = calcular_v_j(ancla, 7, I_ITER_DEV).expect("vdf");
        assert!(verificar_v_j(v, ancla, 7, I_ITER_DEV).expect("dominio"));
        let mut falso = v;
        falso[0] ^= 1;
        assert!(
            !verificar_v_j(falso, ancla, 7, I_ITER_DEV).expect("dominio"),
            "un v_j falso debe invalidar"
        );
        assert!(
            !verificar_v_j([0u8; 16], ancla, 7, I_ITER_DEV).expect("dominio"),
            "v_j ausente no verifica"
        );
        // La semilla depende del ancla y del slot.
        assert_ne!(semilla_vdf(ancla, 7), semilla_vdf(ancla, 8));
        assert_ne!(semilla_vdf(ancla, 7), semilla_vdf([0u8; 16], 7));
    }

    #[test]
    fn el_perfil_dev_es_multiplo_de_16_y_la_frontera_es_exacta() {
        let p = PERFIL_RELOJ_DEV;
        assert_eq!(p.estado_inicial().t(), T0_DEV);
        assert_eq!(p.estado_inicial().n_iter(), N_ITER_DEV);
        assert_eq!(N_ITER_DEV % 16, 0, "RL1-A10");
        assert_eq!(p.estado_inicial().iteraciones(), T0_DEV * N_ITER_DEV);
        assert_eq!(p.siguiente_frontera(0), A_EPOCH_DEV);
        assert_eq!(p.siguiente_frontera(A_EPOCH_DEV - 1), A_EPOCH_DEV);
        assert_eq!(p.siguiente_frontera(A_EPOCH_DEV), 2 * A_EPOCH_DEV);
    }

    /// `RL-2c`: el calendario es función del **conjunto** de bloques de la cadena seleccionada, no
    /// del orden de la lista ni del orden de llegada.
    ///
    /// `RL-2d`/`RL-2d-2`: usa un `A_epoch` pequeño local (el `A_EPOCH_DEV` de dev pasó a `664` para
    /// cumplir `A ≥ F + MARGEN_RELOJ`), porque la historia de prueba solo tiene 20 slots.
    #[test]
    fn el_calendario_no_depende_del_orden_de_la_lista() {
        let p = ParametrosRelojPost {
            a_epoch: 8,
            ..PERFIL_RELOJ_DEV
        };
        // Cadena de 20 slots: los 8 primeros lentos (tau≈4) y el resto a tau≈1.
        let mut bloques: Vec<(u64, u64)> = (1..=20u64)
            .map(|s| (s, 1_000 + if s <= 8 { 4 * s } else { s }))
            .collect();
        let (c1, e1) = calendario_desde_cadena(&p, &bloques).expect("calendario");
        bloques.reverse();
        let (c2, e2) = calendario_desde_cadena(&p, &bloques).expect("calendario");
        assert_eq!(
            c1, c2,
            "el calendario no puede depender del orden de la lista"
        );
        assert_eq!(e1, e2);
        assert!(c1.len() > 1, "debe haber al menos una frontera ajustada");
    }
}
