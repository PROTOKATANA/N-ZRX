//! Verificación de la **justificación PoT del wire** de un bloque DAG (`C-HDR-07`, `C-POT-08`).
//!
//! # Qué sustituye
//!
//! En `9681061`, `zx_core::wire_dag::verificar_justificacion_pot` devolvía **siempre**
//! `IntegracionPotPendiente`: el wire y los portadores existían, pero no había verificador. Este
//! módulo **sustituye** ese `ok` ficticio por la verificación real sobre
//! [`crate::pot_rango::verificar_rango_pot`], reutilizando el **mismo** formato de portadores de
//! `zx_core::wire_dag` y la cota `MAX_BUNDLES_POT = 150`.
//!
//! # Por qué no vive en `zx-core`
//!
//! El rasgo antiguo `zx_core::wire_dag::ContextoVerificacionPot` expone `flujo`, `semilla`,
//! `retardo` e `iteraciones`, pero **no** aporta el `pasado(B)` que exige `C-FLU-14` ni la
//! `salida_validada` que ancla el rango en `C-POT-05`; por sí solo no puede alimentar el núcleo de
//! `pot_rango`. Además `zx-core` **no puede** depender de `zx-pot` (frontera). La orden sanciona la
//! ruta al nombrar `pot_rango` y `contexto_transicion.rs`: aquí la verificación se hace sobre
//! [`InstantaneaPot`], que es la interfaz que el núcleo exige. El stub de `zx-core` queda como
//! interfaz superada; **no** se toca para no romper su frontera ni sus tests.
//!
//! # Lo que NO acredita
//!
//! [`verificar_justificacion_pot`] verifica el **núcleo PoT** contra el contexto recibido: no
//! comprueba el sello (`C-HDR-04`), ni la solución PoAS (paso 5), ni la admisión del bloque. La
//! puerta completa es [`crate::cabecera_conjunta::verificar_cabecera_conjunta`]. Un contexto de
//! prueba no acredita procedencia causal.

use thiserror::Error;

use zx_core::wire_dag::{BUNDLE_BYTES, JustificacionPot, MAX_BUNDLES_POT, PotCheckpoints};
use zx_core::{DagBlockHeader, EncodingError};

use crate::pot_rango::{
    CachePotVerificada, EstadoPot, InstantaneaPot, MotivoPotInvalido, MotivoPotPendiente,
    PresupuestoPot, verificar_rango_pot,
};

/// Fallo al **decodificar** una justificación PoT del wire.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ErrorJustificacion {
    /// El buffer termina antes de completar el contador o los portadores.
    #[error("justificación PoT truncada")]
    Truncado,
    /// El contador declara más portadores que la cota del formato (`S_max_slots = 150`).
    #[error("justificación PoT: {declarados} portadores, máximo {maximo}")]
    DemasiadosPortadores {
        /// Portadores declarados por el byte de contador.
        declarados: usize,
        /// Cota del formato.
        maximo: usize,
    },
    /// `zx-core` rechazó la lista ya construida (no debería ocurrir tras acotar aquí).
    #[error("formato de la justificación PoT: {0}")]
    Formato(#[from] EncodingError),
}

/// Motivo de no-verificación de la justificación PoT del wire.
#[derive(Debug, PartialEq, Eq)]
pub enum MotivoJustificacion {
    /// Defecto verificado del candidato (tabla de `C-POT-06`).
    Invalida(MotivoPotInvalido),
    /// Falta de contexto o imposibilidad de verificarlo; **nunca** se convierte en válido.
    Pendiente(MotivoPotPendiente),
}

/// Decodifica una justificación PoT con el **mismo** formato de `zx_core::wire_dag`:
/// `pot_bundle_count:u8 ‖ count × 128 B`.
///
/// Acota el contador antes de reservar y **nunca entra en pánico**. Devuelve la justificación y el
/// resto de bytes.
///
/// # Errores
/// [`ErrorJustificacion::Truncado`] si el buffer no alcanza;
/// [`ErrorJustificacion::DemasiadosPortadores`] si supera [`MAX_BUNDLES_POT`].
pub fn leer_justificacion(bytes: &[u8]) -> Result<(JustificacionPot, &[u8]), ErrorJustificacion> {
    let Some((&contador, resto)) = bytes.split_first() else {
        return Err(ErrorJustificacion::Truncado);
    };
    let n = usize::from(contador);
    if n > MAX_BUNDLES_POT {
        return Err(ErrorJustificacion::DemasiadosPortadores {
            declarados: n,
            maximo: MAX_BUNDLES_POT,
        });
    }
    let Some((bloque, resto)) = resto.split_at_checked(n * BUNDLE_BYTES) else {
        return Err(ErrorJustificacion::Truncado);
    };

    let mut bundles = Vec::with_capacity(n);
    for trozo in bloque.chunks_exact(BUNDLE_BYTES) {
        let mut b = [0u8; BUNDLE_BYTES];
        b.copy_from_slice(trozo);
        bundles.push(PotCheckpoints::desde_bytes(b));
    }
    Ok((JustificacionPot::nueva(bundles)?, resto))
}

/// Verifica la justificación PoT de `cabecera` con el núcleo de [`crate::pot_rango`].
///
/// Encadena la fase previa (estructura y flujo) y la fase AES (caché, cadena y anclaje). El
/// contexto es un [`InstantaneaPot`] —el mismo que aporta [`crate::contexto_transicion::ContextoTransicion`]—
/// y `reloj_pot`, `cache` y `presupuesto` son estado local del nodo.
///
/// # Errores
/// [`MotivoJustificacion::Invalida`] si el candidato es defectuoso de forma verificable;
/// [`MotivoJustificacion::Pendiente`] si falta contexto o no se pudo verificar. **Nunca** un
/// `Ok(())` sin verificación (ese era el defecto que este módulo elimina).
pub fn verificar_justificacion_pot<C, P>(
    cabecera: &DagBlockHeader,
    justificacion: &JustificacionPot,
    contexto: &C,
    reloj_pot: u64,
    cache: &mut CachePotVerificada,
    presupuesto: &mut P,
) -> Result<(), MotivoJustificacion>
where
    C: InstantaneaPot,
    P: PresupuestoPot,
{
    match verificar_rango_pot(
        cabecera,
        justificacion,
        contexto,
        reloj_pot,
        cache,
        presupuesto,
    ) {
        EstadoPot::PotValido(_) => Ok(()),
        EstadoPot::PotInvalido(motivo) => Err(MotivoJustificacion::Invalida(motivo)),
        EstadoPot::PotPendiente(motivo) => Err(MotivoJustificacion::Pendiente(motivo)),
    }
}
