//! Perfil de la red dev, tal como lo fija `P-ZRX/P-RED-DEV/PERFIL-DEV-v0.md`.
//!
//! Ningún valor de aquí es parámetro de producción (el propio perfil lo dice en su cabecera). Los
//! que dependen del hardware (`N_dev`, `SR_dev`) son argumentos de la CLI, no constantes: la CLI
//! trae valores por defecto razonables para pruebas pequeñas, pero V8 exige poder fijar los reales.

use primitive_types::U256;
use zx_consensus::PARAMETROS_POW_DEV;
use zx_consensus::timestamps::{PERFIL_TIMESTAMP_POST_DEV, ParametrosTimestampPost};
use zx_core::{Amount, decodificar_con, trabajo_bloque};
use zx_dag::ghostdag::Algoritmo;
use zx_post::reloj_post::{MARGEN_RELOJ, PERFIL_RELOJ_DEV, ParametrosRelojPost};

use zx_consensus::transicion::{ParametrosEvidencia, ParametrosTransicion};

/// `H_dep` (§3).
pub const H_DEP: u32 = 1;
/// `M_cb` en bloques PoW (§3).
pub const M_CB: u32 = 5;
/// `M_dep` en bloques PoW (§3).
pub const M_DEP: u32 = 3;
/// `H_corte_min` (§3).
pub const H_CORTE_MIN: u32 = 30;
/// `q` por clave, en brek (§3).
pub const Q_BREK: i64 = 10;
/// `K_min`: una clave por nodo de la red de prueba (§3).
pub const K_MIN: u32 = 3;
/// TXL-01 (`ORDEN-TX2b`, DR-01): `max_tx_bytes` del perfil dev, `|tx_a_bytes(tx, testigos)|`.
pub const MAX_TX_BYTES: u64 = 100_000;
/// TXL-02 (`ORDEN-TX2b`, DR-01): `max_cuerpo_bloque_bytes` del perfil dev, con la coinbase
/// incluida. Rige para bloques PoW y PoST.
pub const MAX_CUERPO_BLOQUE_BYTES: u64 = 320_000;
/// `M_res_slots` (§3).
pub const M_RES_SLOTS: u64 = 20;
/// `M_dep_slots` (§3).
pub const M_DEP_SLOTS: u64 = 10;
/// `M_rec_slots` (§3).
pub const M_REC_SLOTS: u64 = 30;
/// `R_slots` (`ORDEN-SL4b2` decisión 1: `600`, antes `60`; `= F_SLOTS`, recomendación de SL-2b
/// «`R_slots ≥ F_slots`»; puerta RAT-3: `600 > PLAZO_SLOTS + M_MARGEN_SLOTS = 360`).
pub const R_SLOTS: u64 = 600;
/// `F_slots` (§3).
pub const F_SLOTS: u64 = 600;

// ─────────────────────────────────────────────────────────────────────────────
// ORDEN-RD3c · registro firmado de direcciones (N7)
// ─────────────────────────────────────────────────────────────────────────────

/// Margen de época `V` del registro de direcciones, en segundos.
///
/// **Provisional** (`REVISION-RDM2.md`, 2026-10-08): es la tolerancia de reloj de `dev` (`540 s`,
/// `FTL_POST_DEV`) más el periodo de republicación (`600 s`). No es un parámetro de consenso: se
/// vuelve a decidir con el modelo de la red real.
pub const REGISTRO_EPOCA_V_S: u64 = 1_140;
/// Periodo de republicación de la entrada propia del registro de direcciones, en segundos.
///
/// **Provisional** (`REVISION-RDM2.md`, 2026-10-08): `600 s`.
pub const REGISTRO_REPUBLICACION_S: u64 = 600;
/// Tope de entradas **pendientes** del registro de direcciones.
///
/// **Provisional, `<<PENDIENTE DE MODELO>>`** (se queda con el valor de las pruebas de RD-1c): sale
/// del tamaño de la ventana de pesos.
pub const REGISTRO_PENDIENTES_MAX: usize = 64;
/// Caducidad (`TTL`) de una entrada pendiente, en segundos.
///
/// **Provisional, `<<PENDIENTE DE MODELO>>`** (se queda con el valor de las pruebas de RD-1c).
pub const REGISTRO_TTL_S: u64 = 7_200;

/// RD-4b · P2 · Ventana `V` (en bloques) de la tabla de pesos certificados: cuántos bloques hacia
/// atrás desde el ancla de votos recorre `Cadena::productores_en_ventana`.
///
/// **Provisional** (`P-ZRX/P-004/REVISION-RDM2.md`): 236 250 bloques (unos 3,5 días) es el mejor
/// punto de una rejilla de cuatro; falta el barrido fino y la tasa real de abandono de productores.
pub const VENTANA_PESOS_BLOQUES: u64 = 236_250;

// ─────────────────────────────────────────────────────────────────────────────
// FV-4b-N1 · perfil dev del motor de finalidad por votos (REVISION-FV4bD decisión 7)
// ─────────────────────────────────────────────────────────────────────────────

/// FV-4b-N1 · `ParametrosPerfil` del motor de votos en `dev` (decisión 7 de `REVISION-FV4bD.md`):
/// `b = 2`, `f_aus = 1/420 000`, `m_min = 1 brek`, `t_inst = 2` slots y `n_pausa = t_inst`.
///
/// Es **mecánica, no seguridad** (FV-D08): en la escala dev `floor(f_aus·G) = 0` y manda `m_min`.
/// Ningún valor de aquí se publica como cifra de seguridad.
#[must_use]
pub const fn parametros_votos_dev() -> zx_votos::ParametrosPerfil {
    zx_votos::ParametrosPerfil {
        b: 2,
        f_aus_numerador: 1,
        f_aus_denominador: 420_000,
        m_min: 1,
        n_pausa: 2,
        t_inst: 2,
    }
}

/// `Plazo_slots` (`ORDEN-SL4b2` decisión 1, `CONTRATO-EVIDENCIA-v0.md` EV-13): ventana de admisión
/// de una `EvidenceTx` desde `slot_falta`. En `localhost` la segunda cabecera llega en menos de un
/// slot, pero un nodo que reinicia (E-4) o llega tarde (E-5) tiene que poder incluirla todavía: 300
/// slots son de 2,5 a 8 minutos según `N_dev`.
pub const PLAZO_SLOTS: u64 = 300;
/// `M_margen_slots` (`ORDEN-SL4b2` decisión 1, EV-15/EV-15b): margen de inclusión/propagación sobre
/// `Plazo_slots` que exige la puerta RAT-3.
pub const M_MARGEN_SLOTS: u64 = 60;
/// `f = F_NUM/F_DEN` (`ORDEN-SL4b2` decisión 1): fracción confiscada por incidente en la red dev,
/// `1/1` (se confisca la garantía **entera**, RAT-2′).
pub const EVP_F_NUM: u64 = 1;
/// Denominador de `f` (`ORDEN-SL4b2` decisión 1).
pub const EVP_F_DEN: u64 = 1;
/// `S_max_slots` del firmante seguro (`ORDEN-SL4b2` decisión 2, `CONTRATO-EVIDENCIA-v0.md` FIR-10):
/// horizonte de abstención tras perder el registro. Valor nominal de perfil (`SPEC.md` §7.3).
pub const S_MAX_SLOTS: u64 = 150;
/// Tope de evidencias que un bloque propio puede incluir (`ORDEN-SL4b2` decisión 4).
pub const MAX_EVIDENCIAS_POR_BLOQUE: usize = 4;
/// Tope de identidades que el detector de doble firma indexa a la vez (`ORDEN-SL4b2` decisión 3).
pub const MAX_IDENTIDADES_DETECTOR: usize = 65_536;
/// `subsidio_pow(h)`, constante (§3).
pub const SUBSIDIO_POW_BREK: i64 = 50;
/// `subsidio_post(s)`, constante (§3).
pub const SUBSIDIO_POST_BREK: i64 = 5;

/// `φ_min` de la mempool dev, en brek/B (TX-R-11; hallazgo E-08).
///
/// **Por qué 0 (E-08).** La coinbase PoW dev vale `SUBSIDIO_POW_BREK = 50` brek y el peso mínimo
/// de una v1 de una entrada es 161 B (`resultados-TX4/INFORME.md` §6). Con `φ_min` entero ≥ 1
/// brek/B la tarifa mínima sería ≥ 161 brek y **ninguna v1 cabría** en la escala dev; `0` es el
/// único valor entero de brek/B compatible con ella. En dev el abuso lo acotan `w_reserva`
/// (DR-10/TX-R-46), los topes por par/globales (DR-07) y la cuota por clave (TX-R-20); una tarifa
/// de relevo positiva es parámetro de **producción** y va al IPA, no al perfil dev.
pub const PHI_MIN_BREK_POR_BYTE: u64 = 0;

/// GHOSTDAG `k` (§4).
pub const GHOSTDAG_K: u32 = 10;
/// Máximo de padres reales de un bloque (§4, «formato de cabecera sin cambios»).
pub const MAX_PADRES: u8 = 15;

/// `subsidio_pow(altura)` constante del perfil dev (§3): 50 brek.
#[must_use]
pub fn subsidio_pow(_altura: u32) -> Amount {
    #[expect(
        clippy::unwrap_used,
        reason = "50 brek es una constante del perfil dev, siempre representable"
    )]
    Amount::nuevo(SUBSIDIO_POW_BREK).unwrap()
}

/// `subsidio_post(slot)` constante del perfil dev (§3): 5 brek.
#[must_use]
pub fn subsidio_post(_slot: u64) -> Amount {
    #[expect(
        clippy::unwrap_used,
        reason = "5 brek es una constante del perfil dev, siempre representable"
    )]
    Amount::nuevo(SUBSIDIO_POST_BREK).unwrap()
}

/// Fallo al construir el perfil de transición dev.
#[derive(Debug, thiserror::Error)]
pub enum ErrorPerfil {
    /// `PARAMETROS_POW_DEV.bits_iniciales` no decodifica (no debería: es una constante del propio
    /// perfil consensus-critical de W04).
    #[error("bits iniciales del perfil dev inválidos: {0}")]
    BitsIniciales(#[from] zx_core::EncodingError),
    /// `W_min = 30 · trabajo(máximo dev)` desborda `U256` (no debería con el target dev).
    #[error("W_min desborda U256")]
    WMinDesborda,
    /// `RL-2d-2`: el perfil de reloj incumple `A ≥ F + MARGEN_RELOJ` (`a_epoch ≥ f_slots + 64`).
    /// Sin ese margen la ventana `(f − A, f]` puede incluir bloques por encima del punto de
    /// finalidad y el calendario `N(s)` deja de ser común a todos los nodos honestos (riesgo de
    /// partición de `REVISION-RL2c`); además, si la finalidad no alcanza `f` al llegar `f + A`, el
    /// ajuste se compromete tarde y el nodo caía con `Pot(AesFallido)` (hallazgo del humo de RL-2d).
    #[error(
        "perfil de reloj inválido: A_epoch ({a_epoch}) debe ser >= F_slots ({f_slots}) + margen \
         ({margen})"
    )]
    RelojVentanaMenorQueFinalidad {
        /// `A_epoch` del perfil.
        a_epoch: u64,
        /// `F_slots` de la red.
        f_slots: u64,
        /// `MARGEN_RELOJ` exigido entre `A_epoch` y `F_slots` (`RL-2d-2`).
        margen: u64,
    },
}

/// `ParametrosTransicion` del perfil dev (§3 de `PERFIL-DEV-v0.md`).
///
/// `W_min = 30 · trabajo(bits_iniciales dev)`: el trabajo de un bloque a la dificultad **inicial**
/// (la más baja de la red dev, D-P05) es el mínimo trabajo por bloque; con margen para que 3 nodos
/// minen y depositen sin que la dificultad haya podido subir mucho.
///
/// # Errores
/// [`ErrorPerfil`] si los bits iniciales no decodifican o si `W_min` desborda.
pub fn parametros_transicion_dev() -> Result<ParametrosTransicion, ErrorPerfil> {
    #[expect(
        clippy::unwrap_used,
        reason = "30 brek es una constante del perfil dev, siempre representable"
    )]
    let s_min = Amount::nuevo(K_MIN as i64 * Q_BREK).unwrap();
    #[expect(
        clippy::unwrap_used,
        reason = "10 brek es una constante del perfil dev, siempre representable"
    )]
    let q = Amount::nuevo(Q_BREK).unwrap();

    let target_max = decodificar_con(
        PARAMETROS_POW_DEV.bits_iniciales,
        &PARAMETROS_POW_DEV.limites,
    )?;
    let trabajo_max = trabajo_bloque(target_max).ok_or(ErrorPerfil::WMinDesborda)?;
    let w_min = trabajo_max
        .checked_mul(U256::from(30u32))
        .ok_or(ErrorPerfil::WMinDesborda)?;

    Ok(ParametrosTransicion {
        h_dep: H_DEP,
        m_cb: M_CB,
        m_dep: M_DEP,
        h_corte_min: H_CORTE_MIN,
        w_min,
        s_min,
        q,
        k_min: K_MIN,
        max_tx_bytes: MAX_TX_BYTES,
        max_cuerpo_bloque_bytes: MAX_CUERPO_BLOQUE_BYTES,
        m_res_slots: M_RES_SLOTS,
        m_dep_slots: M_DEP_SLOTS,
        m_rec_slots: M_REC_SLOTS,
        r_slots: R_SLOTS,
        f_slots: Some(F_SLOTS),
        subsidio_pow,
        subsidio_post,
    })
}

/// Algoritmo GHOSTDAG de producción (no el `Referencia` de los oráculos de test).
#[must_use]
pub const fn algoritmo_ghostdag_dev() -> Algoritmo {
    Algoritmo::Kernel
}

/// Comprueba que `Cadena::nueva` recibe el mismo `k` que este perfil (defensa contra desajuste).
#[must_use]
pub const fn ghostdag_k() -> u32 {
    GHOSTDAG_K
}

/// Máximo de padres que `Cadena::nueva` recibe del perfil dev (§4, `ORDEN-W06a-C` decisión 1).
#[must_use]
pub const fn ghostdag_max_padres() -> u8 {
    MAX_PADRES
}

/// `ParametrosEvidencia` del perfil dev (`ORDEN-SL4b2` decisión 1): `f = 1/1`, `Plazo_slots = 300`,
/// `M_margen_slots = 60`, `cbid = CBID_RED_DEV`, evidencia **activa**.
#[must_use]
pub const fn parametros_evidencia_dev() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: EVP_F_NUM,
        f_den: EVP_F_DEN,
        plazo_slots: PLAZO_SLOTS,
        m_margen_slots: M_MARGEN_SLOTS,
        cbid: zx_core::CBID_RED_DEV,
        evp: true,
    }
}

/// Puerta RAT-3 (`CONTRATO-EVIDENCIA-v0.md`, «Ratificación v0»): `R_slots > Plazo_slots +
/// M_margen_slots`. El nodo (`ORDEN-SL4b2` decisión 1) **se niega a arrancar** si no se cumple: sin
/// esta desigualdad, un infractor podría completar una liberación de su garantía antes de que la
/// ventana de admisión de su propia falta cierre (EV-15).
///
/// Toma `r_slots` y `evidencia` explícitos (no las constantes del módulo) para que un test pueda
/// comprobar un perfil que la incumple sin construir un nodo entero.
#[must_use]
pub const fn puerta_rat3(r_slots: u64, evidencia: &ParametrosEvidencia) -> bool {
    r_slots > evidencia.plazo_slots + evidencia.m_margen_slots
}

/// FV-4b-N4 · R-ECL-05 · `LOOKBACK` dev: instancias hacia atrás en las que un voto (y su ancla)
/// sigue siendo admisible. El caso dev da `V_slots = LOOKBACK·T_inst <= R_slots − Plazo_slots −
/// M_margen_slots = 240`, con `T_inst = 2` ⇒ `LOOKBACK <= 120`; se fija el máximo derivado y la
/// puerta [`puerta_recl05`] lo comprueba.
pub const LOOKBACK_VOTOS_DEV: u64 = 120;

/// FV-4b-N4 · R-ECL-05 · ventana de voto `V_slots = LOOKBACK · T_inst`, en slots PoT.
#[must_use]
pub const fn ventana_voto_slots(lookback: u64, t_inst: u64) -> u64 {
    lookback.saturating_mul(t_inst)
}

/// FV-4b-N4 · R-ECL-05 · puerta `R_slots >= V_slots + Plazo_voto_slots + M_margen_voto_slots`.
///
/// La garantía de una clave debe seguir siendo confiscable mientras un voto de una instancia pasada
/// sea relevante; si no, un infractor podría liberar su fianza antes de que la capa de votos cierre.
/// Toma los cuatro términos explícitos para poder probar un perfil que la incumpla.
#[must_use]
pub const fn puerta_recl05(
    r_slots: u64,
    v_slots: u64,
    plazo_voto_slots: u64,
    m_margen_voto_slots: u64,
) -> bool {
    r_slots
        >= v_slots
            .saturating_add(plazo_voto_slots)
            .saturating_add(m_margen_voto_slots)
}

// ─────────────────────────────────────────────────────────────────────────────
// RL-2c · perfil de red: el reloj por ticks es un parámetro de la **red**, no del nodo
// ─────────────────────────────────────────────────────────────────────────────

/// `RL-2c` · perfil de red del reloj. El reloj por ticks y el segundo VDF son una propiedad de la
/// **red**, igual para todos sus nodos; no una bandera de arranque (`--reloj-dev` desaparece).
///
/// La identidad de red ([`identidad_red`]) es función del génesis dev y del perfil, de modo que dos
/// nodos con perfiles distintos no se aceptan como la misma red en el saludo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfilRedConsenso {
    /// Etiqueta humana/estable del perfil (entra en la identidad de red).
    pub etiqueta: &'static str,
    /// ¿El reloj por ticks y el segundo VDF están activos en esta red?
    pub reloj_activo: bool,
    /// Perfil del reloj por ticks (`C-RLJ-02`…`C-RLJ-07`).
    pub reloj: ParametrosRelojPost,
    /// Perfil de las reglas de timestamp PoST (`C-RLJ-TS-01`…`C-RLJ-TS-05`).
    pub timestamp: ParametrosTimestampPost,
}

/// `RL-2c` · perfil de la red **dev clásica**: reloj **inactivo** (`N` constante, sin `v_j`
/// obligatorio). Es el comportamiento de 0.0.1 previo a RL-2c.
#[must_use]
pub const fn perfil_red_dev() -> PerfilRedConsenso {
    PerfilRedConsenso {
        etiqueta: crate::cli::RedCli::Dev.nombre(),
        reloj_activo: false,
        reloj: PERFIL_RELOJ_DEV,
        timestamp: PERFIL_TIMESTAMP_POST_DEV,
    }
}

/// `RL-2c` · perfil de la **red dev con reloj**: mismo génesis dev, pero el reloj por ticks y el
/// segundo VDF son obligatorios para todos sus nodos. Es la red nueva que activa RL-2c.
///
/// `RL-2d-2`: **fallible**, porque exige el invariante `A ≥ F + MARGEN_RELOJ` al construir el
/// perfil (decisión 2).
///
/// # Errores
/// [`ErrorPerfil::RelojVentanaMenorQueFinalidad`] si el `A_epoch` del perfil de reloj es menor que
/// `F_SLOTS + MARGEN_RELOJ`.
pub fn perfil_red_dev_reloj() -> Result<PerfilRedConsenso, ErrorPerfil> {
    let perfil = PerfilRedConsenso {
        etiqueta: crate::cli::RedCli::DevReloj.etiqueta_consenso(),
        reloj_activo: true,
        reloj: PERFIL_RELOJ_DEV,
        timestamp: PERFIL_TIMESTAMP_POST_DEV,
    };
    perfil.validar()?;
    Ok(perfil)
}

impl PerfilRedConsenso {
    /// `RL-2d`/`RL-2d-2` · comprueba el invariante de perfil `A ≥ F + MARGEN_RELOJ`
    /// (`a_epoch ≥ f_slots + 64`), decisiones 2 de `ORDEN-RL2d` y de `ORDEN-RL2d-2`. Solo se exige
    /// con el reloj activo: un perfil sin reloj no usa la ventana de ajuste. Se llama al construir
    /// el perfil; un perfil que lo incumple no debe usarse.
    ///
    /// # Errores
    /// [`ErrorPerfil::RelojVentanaMenorQueFinalidad`] si `reloj_activo` y
    /// `a_epoch < F_SLOTS + MARGEN_RELOJ`.
    pub fn validar(&self) -> Result<(), ErrorPerfil> {
        if self.reloj_activo && self.reloj.a_epoch < F_SLOTS + MARGEN_RELOJ {
            return Err(ErrorPerfil::RelojVentanaMenorQueFinalidad {
                a_epoch: self.reloj.a_epoch,
                f_slots: F_SLOTS,
                margen: MARGEN_RELOJ,
            });
        }
        Ok(())
    }

    /// `RL-2d-2` · slot del último ajuste de reloj que debe estar **ya comprometido** al producir en
    /// `slot`, o `None` si aún no rige ningún ajuste (`slot < 2·A`).
    ///
    /// El calendario del reloj solo añade entradas `(f + A, N)` para cada frontera `f = A, 2A, …`
    /// cuando el punto de finalidad alcanza `f` (ver `RelojPost::calendario_desde_cadena` y
    /// `Nodo::recalcular_calendario_reloj`). Al llegar a `slot`, el ajuste que rige es el de la
    /// frontera `f = A·(⌊slot/A⌋ − 1)`, cuyo `desde` es `d = A·⌊slot/A⌋`; la primera frontera es
    /// `f = A`, de modo que `d = 2A` es el primer ajuste exigible. Con `d` ausente del calendario, el
    /// `N` de esa frontera **no está comprometido** y el nodo no debe producir con un `N` dudoso.
    #[must_use]
    pub const fn ajuste_exigido(&self, slot: u64) -> Option<u64> {
        if !self.reloj_activo {
            return None;
        }
        let a = self.reloj.a_epoch;
        if a == 0 {
            return None;
        }
        let epoca = slot.div_euclid(a);
        if epoca < 2 {
            return None;
        }
        Some(epoca.saturating_mul(a))
    }

    /// `RL-2d-2` · ¿el calendario `calendario` (pares `(desde, N)` del `ServicioPot`) contiene el
    /// ajuste que rige en `slot`? `true` también cuando aún no rige ningún ajuste.
    #[must_use]
    pub fn n_comprometido(&self, calendario: &[(u64, u64)], slot: u64) -> bool {
        match self.ajuste_exigido(slot) {
            None => true,
            Some(desde) => calendario.iter().any(|(d, _)| *d == desde),
        }
    }
}

/// `RL-2c` · identidad de red del perfil: `H(HASH_GENESIS_DEV ‖ etiqueta)` para los perfiles
/// nuevos, y el propio `HASH_GENESIS_DEV` para la dev clásica.
///
/// Se usa en el saludo (`Estado.hash_genesis` del nodo) para que un nodo de `dev` y uno de
/// `dev-reloj` se **desconecten** en vez de hablarse como si fueran la misma red. El génesis real
/// de la cadena sigue siendo `HASH_GENESIS_DEV` para el almacén y la validación.
#[must_use]
pub fn identidad_red(perfil: &PerfilRedConsenso) -> zx_core::BlockHash {
    zx_core::red::identidad_red(
        zx_consensus::genesis::HASH_GENESIS_DEV,
        perfil.etiqueta,
        perfil.reloj_activo,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ErrorPerfil, F_SLOTS, LOOKBACK_VOTOS_DEV, M_MARGEN_SLOTS, MARGEN_RELOJ, PERFIL_RELOJ_DEV,
        PERFIL_TIMESTAMP_POST_DEV, PLAZO_SLOTS, ParametrosRelojPost, PerfilRedConsenso,
        identidad_red, parametros_evidencia_dev, parametros_transicion_dev, perfil_red_dev,
        perfil_red_dev_reloj, puerta_rat3, puerta_recl05, ventana_voto_slots,
    };
    use zx_consensus::transicion::ParametrosEvidencia;

    #[test]
    #[expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
    fn el_perfil_dev_construye() {
        let p = parametros_transicion_dev().expect("perfil dev válido");
        assert_eq!(p.h_corte_min, super::H_CORTE_MIN);
        assert_eq!(p.k_min, super::K_MIN);
        assert!(!p.w_min.is_zero());
    }

    /// El perfil dev real cumple la puerta RAT-3: `600 > 300 + 60`.
    #[test]
    fn la_puerta_rat3_se_cumple_con_el_perfil_dev_real() {
        assert!(puerta_rat3(super::R_SLOTS, &parametros_evidencia_dev()));
    }

    /// Un perfil de prueba que la incumple (`R_slots` demasiado corto para su propia ventana):
    /// `puerta_rat3` debe devolver `false`, no un pánico ni un `true` optimista.
    #[test]
    fn la_puerta_rat3_detecta_un_perfil_que_la_incumple() {
        let evidencia_mala = ParametrosEvidencia {
            plazo_slots: 300,
            m_margen_slots: 60,
            ..parametros_evidencia_dev()
        };
        // 360 == 300 + 60: la desigualdad es estricta (`>`), así que el igual también incumple.
        assert!(!puerta_rat3(360, &evidencia_mala));
        // Y con margen aún más corto que la ventana, sigue incumpliendo.
        assert!(!puerta_rat3(100, &evidencia_mala));
    }

    /// FV-4b-N4 · R-ECL-05: el perfil dev cumple la igualdad exacta
    /// `600 >= 120·2 + 300 + 60 = 600`.
    #[test]
    fn la_puerta_recl05_se_cumple_con_el_perfil_dev_real() {
        let t_inst = super::parametros_votos_dev().t_inst;
        let v_slots = ventana_voto_slots(LOOKBACK_VOTOS_DEV, t_inst);
        assert_eq!(v_slots, 240, "V_slots = LOOKBACK·T_inst");
        assert!(puerta_recl05(
            super::R_SLOTS,
            v_slots,
            PLAZO_SLOTS,
            M_MARGEN_SLOTS
        ));
    }

    /// FV-4b-N4 · R-ECL-05: una instancia más de `LOOKBACK` (`121 ⇒ V_slots = 242`) o una
    /// retención menor incumplen la puerta; no hay `true` optimista.
    #[test]
    fn la_puerta_recl05_detecta_un_lookback_excesivo() {
        let t_inst = super::parametros_votos_dev().t_inst;
        let v_slots = ventana_voto_slots(LOOKBACK_VOTOS_DEV + 1, t_inst);
        assert_eq!(v_slots, 242);
        assert!(!puerta_recl05(
            super::R_SLOTS,
            v_slots,
            PLAZO_SLOTS,
            M_MARGEN_SLOTS
        ));
        assert!(!puerta_recl05(599, 240, PLAZO_SLOTS, M_MARGEN_SLOTS));
    }

    /// `RL-2c`: la red dev clásica y la red dev con reloj tienen identidad distinta (no se
    /// conectarían) y solo la segunda activa el reloj.
    #[test]
    #[expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
    fn los_perfiles_dev_y_dev_reloj_tienen_identidades_distintas() {
        let clasica = perfil_red_dev();
        let con_reloj = perfil_red_dev_reloj().expect("perfil dev-reloj válido");
        assert!(!clasica.reloj_activo);
        assert!(con_reloj.reloj_activo);
        assert_ne!(identidad_red(&clasica), identidad_red(&con_reloj));
        assert_ne!(clasica.etiqueta, con_reloj.etiqueta);
    }

    /// `RL-2d-2` · **V2**: el invariante de perfil `A ≥ F + MARGEN_RELOJ`
    /// (`a_epoch ≥ f_slots + 64`). El perfil `dev-reloj` real lo cumple con holgura
    /// (`A = F + 64 = 664`); un perfil con `A = F + 63 = 663` se **rechaza** al validarlo (el
    /// humo de RL-2d midió que `A = F + 1` no basta).
    #[test]
    #[expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
    fn el_perfil_con_a_menor_que_f_mas_margen_se_rechaza() {
        let valido = perfil_red_dev_reloj().expect("perfil dev-reloj válido");
        assert_eq!(
            valido.reloj.a_epoch,
            F_SLOTS + MARGEN_RELOJ,
            "A = F + 64 = 664"
        );
        assert!(valido.validar().is_ok());

        let invalido = PerfilRedConsenso {
            etiqueta: "dev-reloj-invalido",
            reloj_activo: true,
            reloj: ParametrosRelojPost {
                a_epoch: F_SLOTS + MARGEN_RELOJ - 1,
                ..PERFIL_RELOJ_DEV
            },
            timestamp: PERFIL_TIMESTAMP_POST_DEV,
        };
        let err = invalido.validar();
        assert!(
            matches!(
                err,
                Err(ErrorPerfil::RelojVentanaMenorQueFinalidad { a_epoch, f_slots, margen })
                    if a_epoch == F_SLOTS + MARGEN_RELOJ - 1
                        && f_slots == F_SLOTS
                        && margen == MARGEN_RELOJ
            ),
            "se esperaba el error del invariante A >= F + margen, llegó {err:?}"
        );
    }

    /// `RL-2d-2` · la guarda `ajuste_exigido` identifica el ajuste que rige en cada slot y
    /// `n_comprometido` exige su entrada en el calendario (la base del test (b) de nodo).
    #[test]
    #[expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
    fn el_ajuste_exigido_empieza_en_dos_a_y_n_comprometido_lo_comprueba() {
        let perfil = perfil_red_dev_reloj().expect("perfil dev-reloj válido");
        // `A = 664`: hasta `2A = 1328` no rige ningún ajuste.
        assert_eq!(perfil.ajuste_exigido(0), None);
        assert_eq!(perfil.ajuste_exigido(663), None);
        assert_eq!(perfil.ajuste_exigido(1327), None);
        assert_eq!(perfil.ajuste_exigido(1328), Some(1328));
        assert_eq!(perfil.ajuste_exigido(1991), Some(1328));
        assert_eq!(perfil.ajuste_exigido(1992), Some(1992));
        // Sin la entrada `(1328, N)` el `N` de la frontera 664 no está comprometido.
        let calendario = vec![(0u64, 1u64), (1328u64, 2u64)];
        assert!(perfil.n_comprometido(&calendario, 1328));
        assert!(!perfil.n_comprometido(&calendario, 1992));
        let incompleto = vec![(0u64, 1u64)];
        assert!(!perfil.n_comprometido(&incompleto, 1328));
        assert!(perfil.n_comprometido(&incompleto, 1327));
    }
}
