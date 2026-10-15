//! Elección de padres canónicos para un bloque en régimen (decisión 6; «Relanzamiento» punto 3).
//!
//! Usa el GHOSTDAG **real** de `zx-cadena` (`Cadena::mejor_punta`) para calcular el padre
//! seleccionado: nunca el atajo dev de `zx_post::ContextoTransicion`. Tope de **15** padres en total
//! (`PERFIL-DEV-v0.md` §4): `zx-cadena` lo recibe como parámetro de construcción y el nodo le pasa
//! el del perfil (`ORDEN-W06a-C` decisión 1).
//!
//! `ORDEN-W08f`: además del tope de 15 padres, la selección respeta el tope de **mergeset** del
//! consenso (`C-GD-04`). Antes se metían todas las puntas válidas y un bloque de reunión tras una
//! reorganización profunda se rechazaba con `ErrMergeset`; ahora las puntas se añaden solo si el
//! mergeset resultante cabría en la admisión (algoritmo de `pick_virtual_parents` de Kaspa,
//! `consensus/src/pipeline/virtual_processor/processor.rs:1053`, commit `c338d49`, licencia ISC).

use primitive_types::U256;
use zx_cadena::Cadena;
use zx_core::{BlockHash, PadresDag};
use zx_dag::ErrorDag;

/// Tope real de padres que `zx-cadena` admite por bloque: el máximo del perfil dev
/// (`PERFIL-DEV-v0.md` §4), que el nodo pasa a `Cadena::nueva`. Se mantiene en sincronía con
/// [`crate::perfil::MAX_PADRES`] mediante esta constante.
pub const MAX_PADRES_CADENA: usize = crate::perfil::MAX_PADRES as usize;

/// Fallo al elegir padres.
#[derive(Debug, thiserror::Error)]
pub enum ErrorPadres {
    /// Aún no hay terminal fijado: no hay DAG que consultar.
    #[error("no hay terminal fijado: no se pueden elegir padres de régimen")]
    SinTerminal,
    /// No hay ninguna punta válida todavía (se debe usar el bloque de transición, no régimen).
    #[error("no hay puntas válidas: el siguiente bloque es el de transición, no de régimen")]
    SinPuntas,
    /// Fallo de GHOSTDAG al calcular el padre seleccionado real.
    #[error("GHOSTDAG: {0}")]
    Dag(#[from] ErrorDag),
    /// El formato de padres rechazó la combinación (no debería, ya que se controla el tope).
    #[error("formato de padres: {0}")]
    Formato(#[from] zx_core::EncodingError),
}

/// `blue_work` de una punta del DAG del terminal seleccionado, o cero si no está (no debería: toda
/// punta de `tips_validas` pertenece a ese DAG).
fn blue_work_de(cadena: &Cadena, hash: &BlockHash) -> U256 {
    cadena
        .datos_ghostdag(hash)
        .map_or_else(U256::zero, |d| d.blue_work)
}

/// Elige los padres canónicos del próximo bloque en régimen respetando el tope de mergeset.
///
/// Pasos (`ORDEN-W08f`, decisión 2, tomado de `pick_virtual_parents` de Kaspa):
///
/// 1. el padre seleccionado es la punta de mayor `blue_work` (`C-GD-03`; el `sp` lo decide el
///    GHOSTDAG real sobre **todas** las puntas, no el orden declarado);
/// 2. las demás puntas se prueban en orden determinista (`blue_work` descendente, hash como
///    desempate) y se añaden solo si el mergeset resultante seguiría dentro del tope de consenso y
///    el total de padres no pasaría de [`MAX_PADRES_CADENA`];
/// 3. una punta que no cabe se omite en ese bloque. Si nunca cabe, queda sin fusionar: es el coste
///    de haber perdido.
///
/// El tope de mergeset lo aporta la propia `Cadena`
/// ([`Cadena::mergeset_de_padres`]), de modo que el nodo no duplica el valor del consenso.
///
/// # Errores
/// [`ErrorPadres::SinTerminal`], [`ErrorPadres::SinPuntas`] o los de GHOSTDAG/formato.
pub fn padres_de_regimen(cadena: &Cadena) -> Result<PadresDag, ErrorPadres> {
    if cadena.contexto_dag().is_none() {
        return Err(ErrorPadres::SinTerminal);
    }
    let tips = cadena.tips_validas();
    if tips.is_empty() {
        return Err(ErrorPadres::SinPuntas);
    }

    // El padre seleccionado es la punta de mayor `blue_work` (`C-GD-03`), sobre **todas** las
    // puntas: `mejor_punta` aplica la regla C con desempate por `solution_distance` y hash. (El
    // `PadresDag` provisional de antes no sirve aquí: su formato topa en 15 padres y no debe
    // recortar la elección del `sp`.)
    let sp: BlockHash = cadena.mejor_punta().ok_or(ErrorPadres::SinPuntas)?;

    // Orden determinista de las demás puntas: `blue_work` descendente, hash como desempate.
    let mut candidatas: Vec<BlockHash> = tips.iter().copied().filter(|h| *h != sp).collect();
    candidatas.sort_by(|a, b| {
        blue_work_de(cadena, b)
            .cmp(&blue_work_de(cadena, a))
            .then_with(|| a.cmp(b))
    });

    let mut extras: Vec<BlockHash> = Vec::new();
    for cand in candidatas {
        // `sp` + los extras ya aceptados + este candidato: si ya no cabe el tope de padres, se para
        // (añadir cualquiera de los restantes daría el mismo total).
        if extras.len() + 2 > MAX_PADRES_CADENA {
            break;
        }
        let mut prueba = Vec::with_capacity(extras.len() + 2);
        prueba.push(sp);
        prueba.extend_from_slice(&extras);
        prueba.push(cand);
        let Some((tamano, tope)) = cadena.mergeset_de_padres(&prueba) else {
            // Punta fuera del DAG del terminal: se omite, no se declara.
            continue;
        };
        // Misma condición que la admisión (`zx-dag`, `C-GD-04`): `|mergeset| + 1 <= tope`,
        // que rechaza si `|mergeset| + 1 > tope`. Equivalentemente, `|mergeset| < tope`.
        if tamano < u64::from(tope) {
            extras.push(cand);
        }
    }

    Ok(PadresDag::nuevo(sp, &extras)?)
}

#[cfg(test)]
mod tests {
    // Cubierto de extremo a extremo por `tests/integracion.rs` (padres reales sobre GHOSTDAG real),
    // `tests/padres_maximos.rs` (tope de 15) y `tests/w08f_padres_mergeset.rs` (tope de mergeset y
    // propiedad sin reorganización profunda).
}
