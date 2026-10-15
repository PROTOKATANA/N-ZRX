//! Segundo VDF: **cadena larga por segmentos de clave fija** y **orden de validación no circular**
//! (`C-RLJ-VDF-02` y `C-RLJ-VDF-03` de `CONTRATO-RELOJ-v0.md`).
//!
//! # Cadena larga
//!
//! [`cadena_segmentada`] recorre `total` iteraciones repartiéndolas con [`zx_pot::vdf::segmentos`]
//! y ejecutando cada segmento con la primitiva real [`zx_pot::prove`]: dentro del segmento la clave
//! AES es fija (deriva de su semilla) y **la salida del segmento `k` es la semilla del `k+1`**.
//! A diferencia de los vectores de RL-1 (primitiva de juguete), aquí la salida es AES real; el
//! diferencial comprueba la **estructura** (longitudes y encadenado), como declara `VECTORES.md`.
//!
//! # Orden no circular
//!
//! [`orden_vdf`] modela la máquina de estados de `C-RLJ-VDF-03`: la semilla del segundo VDF se
//! deriva **sólo de `past(B)`**, la cadena larga se verifica y **después** se deriva el flujo
//! `f(t_j) = H_flujo(f(t_j−1) ‖ v_j ‖ LE64(t_j))`; la comprobación de flujo y la caché AES van al
//! final. Un caso que usaría el `pot_output` del propio candidato nunca devuelve `Ok`: es
//! `PendienteCircular`, y la falta de ancla/chunk del pasado es `PendienteContexto`.
//!
//! # Límite declarado
//!
//! El orden acíclico es **condición necesaria, no suficiente**: la procedencia causal de
//! `salida(f, t_j−1)` y `chunk(I_j)` sigue siendo una precondición por acreditar (lo advierte el
//! propio [`crate::pot_rango`]). Este módulo no la fabrica.

use core::num::NonZeroU32;

use zx_core::wire_dag::POT_OUTPUT_BYTES;
use zx_pot::tipos::PotSeed;

pub use zx_pot::vdf::MAX_SEG;

/// Defecto de la cadena larga del segundo VDF.
#[derive(Debug, thiserror::Error)]
pub enum ErrorVdf {
    /// La segmentación no cumple el dominio de la primitiva.
    #[error("segmentación inválida: {0}")]
    Segmentacion(#[from] zx_pot::vdf::ErrorVdf),
    /// Una longitud de segmento no cabe en el `NonZeroU32` de la primitiva.
    #[error("la longitud de segmento {longitud} no cabe en u32")]
    LongitudFueraDeU32 {
        /// Longitud del segmento.
        longitud: u64,
    },
    /// La primitiva PoT rechazó la terna del segmento (no debería con múltiplos de 16).
    #[error("la primitiva PoT rechazó el segmento de {longitud} iteraciones")]
    Primitiva {
        /// Longitud del segmento.
        longitud: u64,
    },
}

/// Resultado de una cadena larga segmentada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadenaSegmentada {
    /// Longitud de cada segmento, en orden.
    pub longitudes: Vec<u64>,
    /// Salida de 16 B al terminar cada segmento.
    pub salidas_por_segmento: Vec<[u8; POT_OUTPUT_BYTES]>,
    /// Salida final: la del último segmento (o la semilla si no hubo segmentos).
    pub salida_final: [u8; POT_OUTPUT_BYTES],
}

/// Reparte `total` iteraciones en longitudes de segmento (envoltorio del iterador de `zx-pot`).
///
/// # Errores
/// Las de [`zx_pot::vdf::segmentos`].
pub fn segmentos(total: u64, max_seg: u64) -> Result<Vec<u64>, zx_pot::vdf::ErrorVdf> {
    Ok(zx_pot::vdf::segmentos(total, max_seg)?.collect())
}

/// Ejecuta la cadena larga del segundo VDF con la primitiva real.
///
/// `semilla` es la semilla del primer segmento; `total` la longitud total (múltiplo de 16) y
/// `max_seg` el tope por segmento (múltiplo de 16, típicamente [`MAX_SEG`]).
///
/// # Errores
/// [`ErrorVdf::Segmentacion`], [`ErrorVdf::LongitudFueraDeU32`] o [`ErrorVdf::Primitiva`].
pub fn cadena_segmentada(
    semilla: [u8; POT_OUTPUT_BYTES],
    total: u64,
    max_seg: u64,
) -> Result<CadenaSegmentada, ErrorVdf> {
    let mut actual = semilla;
    let mut longitudes = Vec::new();
    let mut salidas_por_segmento = Vec::new();
    for longitud in zx_pot::vdf::segmentos(total, max_seg)? {
        let acotada =
            u32::try_from(longitud).map_err(|_| ErrorVdf::LongitudFueraDeU32 { longitud })?;
        let iteraciones =
            NonZeroU32::new(acotada).ok_or(ErrorVdf::LongitudFueraDeU32 { longitud })?;
        let carrier = zx_pot::prove(PotSeed::from(actual), iteraciones)
            .map_err(|_| ErrorVdf::Primitiva { longitud })?;
        actual = *carrier.output();
        longitudes.push(longitud);
        salidas_por_segmento.push(actual);
    }
    Ok(CadenaSegmentada {
        longitudes,
        salidas_por_segmento,
        salida_final: actual,
    })
}

/// Un paso del orden de validación de `C-RLJ-VDF-03`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasoVdf {
    /// Paso 1: estructura y cota de slots, sin AES.
    Estructura,
    /// Paso 2: derivar `semilla_vdf(j)` **sólo** de `past(B)`.
    DerivarSemillaVdfDelPasado,
    /// Paso 3: verificar la cadena larga y obtener `v_j`.
    VerificarCadenaLarga,
    /// Paso 4: derivar `f(t_j) = H_flujo(f(t_j−1) ‖ v_j ‖ LE64(t_j))`.
    DerivarFlujoDesdeVdf,
    /// Paso 5: comprobar la consistencia de flujo del pasado (`C-FLU-14`).
    ComprobarFlujoDelPasado,
    /// Paso 6: caché `(f, s, semilla, N(s))` y cadena AES del rango.
    CacheYAesDelRango,
}

impl PasoVdf {
    /// Nombre estable del paso, el que usan los vectores de RL-1.
    #[must_use]
    pub const fn nombre(&self) -> &'static str {
        match self {
            Self::Estructura => "estructura",
            Self::DerivarSemillaVdfDelPasado => "derivar_semilla_vdf_del_pasado",
            Self::VerificarCadenaLarga => "verificar_cadena_larga",
            Self::DerivarFlujoDesdeVdf => "derivar_flujo_desde_vdf",
            Self::ComprobarFlujoDelPasado => "comprobar_flujo_del_pasado",
            Self::CacheYAesDelRango => "cache_y_aes_del_rango",
        }
    }
}

/// Los seis pasos del orden no circular, en orden.
pub const PASOS_VALIDOS: [PasoVdf; 6] = [
    PasoVdf::Estructura,
    PasoVdf::DerivarSemillaVdfDelPasado,
    PasoVdf::VerificarCadenaLarga,
    PasoVdf::DerivarFlujoDesdeVdf,
    PasoVdf::ComprobarFlujoDelPasado,
    PasoVdf::CacheYAesDelRango,
];

/// Datos del segundo VDF de una inyección.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntradaVdf {
    /// El ancla `salida(f, t_j−1)` está en `past(B)` ya validado.
    pub ancla_en_pasado: bool,
    /// El `chunk(I_j)` está en `past(B)` ya validado.
    pub chunk_en_pasado: bool,
    /// Slot de activación `t_j`.
    pub t_j: u64,
    /// La derivación usaría el `pot_output` del propio candidato (circular).
    pub usa_pot_output_del_candidato: bool,
    /// Hay flujo previo `f(t_j−1)` validado.
    pub hay_flujo_previo: bool,
}

/// Estado del orden de validación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstadoOrdenVdf {
    /// Orden acíclico posible, con la secuencia de pasos.
    Ok(Vec<PasoVdf>),
    /// La semilla usaría el `pot_output` del candidato: circular, nunca válido.
    PendienteCircular,
    /// Falta ancla, chunk o flujo previo del pasado: no se puede cerrar el orden.
    PendienteContexto,
}

/// Decide el orden de validación de `C-RLJ-VDF-03`.
///
/// Devuelve [`EstadoOrdenVdf::PendienteCircular`] si la derivación usaría el `pot_output` del
/// candidato, [`EstadoOrdenVdf::PendienteContexto`] si falta ancla, chunk, flujo previo o `t_j > 0`,
/// y [`EstadoOrdenVdf::Ok`] con [`PASOS_VALIDOS`] en caso contrario.
#[must_use]
pub fn orden_vdf(entrada: &EntradaVdf) -> EstadoOrdenVdf {
    if entrada.usa_pot_output_del_candidato {
        return EstadoOrdenVdf::PendienteCircular;
    }
    if !(entrada.ancla_en_pasado && entrada.chunk_en_pasado && entrada.hay_flujo_previo)
        || entrada.t_j == 0
    {
        return EstadoOrdenVdf::PendienteContexto;
    }
    EstadoOrdenVdf::Ok(PASOS_VALIDOS.to_vec())
}

/// `true` si la derivación sería circular (usa el `pot_output` del candidato).
#[must_use]
pub const fn contexto_circular(entrada: &EntradaVdf) -> bool {
    entrada.usa_pot_output_del_candidato
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan por diseño")]
mod pruebas {
    use super::{
        EntradaVdf, EstadoOrdenVdf, MAX_SEG, PASOS_VALIDOS, cadena_segmentada, orden_vdf, segmentos,
    };

    #[test]
    fn segmentacion_de_los_vectores() {
        assert_eq!(segmentos(160, 64).expect("válido"), vec![64, 64, 32]);
        assert_eq!(segmentos(48, 64).expect("válido"), vec![48]);
        assert_eq!(segmentos(128, 64).expect("válido"), vec![64, 64]);
        assert_eq!(
            segmentos(2 * MAX_SEG + 32, MAX_SEG).expect("válido"),
            vec![MAX_SEG, MAX_SEG, 32]
        );
    }

    #[test]
    fn cadena_con_aes_encadena_las_salidas() {
        let total = 160;
        let max_seg = 64;
        let cadena = cadena_segmentada([1u8; 16], total, max_seg).expect("cadena válida");
        assert_eq!(cadena.longitudes, vec![64, 64, 32]);
        assert_eq!(cadena.salidas_por_segmento.len(), 3);
        assert_eq!(
            cadena.salida_final,
            *cadena.salidas_por_segmento.last().expect("no vacía")
        );
        // La salida declarada de cada segmento no es la semilla del siguiente por accidente.
        assert_ne!(cadena.salidas_por_segmento.first(), Some(&[1u8; 16]));
    }

    #[test]
    fn cadena_vacia_devuelve_la_semilla() {
        let cadena = cadena_segmentada([7u8; 16], 0, 64).expect("válida");
        assert!(cadena.longitudes.is_empty());
        assert_eq!(cadena.salida_final, [7u8; 16]);
    }

    #[test]
    fn orden_no_circular() {
        let positivo = EntradaVdf {
            ancla_en_pasado: true,
            chunk_en_pasado: true,
            t_j: 10,
            usa_pot_output_del_candidato: false,
            hay_flujo_previo: true,
        };
        assert_eq!(
            orden_vdf(&positivo),
            EstadoOrdenVdf::Ok(PASOS_VALIDOS.to_vec())
        );
        let circular = EntradaVdf {
            usa_pot_output_del_candidato: true,
            ..positivo
        };
        assert_eq!(orden_vdf(&circular), EstadoOrdenVdf::PendienteCircular);
        let sin_ancla = EntradaVdf {
            ancla_en_pasado: false,
            ..positivo
        };
        assert_eq!(orden_vdf(&sin_ancla), EstadoOrdenVdf::PendienteContexto);
        let t_cero = EntradaVdf { t_j: 0, ..positivo };
        assert_eq!(orden_vdf(&t_cero), EstadoOrdenVdf::PendienteContexto);
    }
}
