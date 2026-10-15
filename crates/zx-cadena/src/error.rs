//! Motivos de rechazo de bloque de `zx-cadena`.
//!
//! Los nombres coinciden con los que el oráculo T04 escribe en los vectores (`RES bloque=… res=…`):
//! `ErrSinPadre`, `ErrSlot`, `ErrEmision`, `ErrSaldo`, `ErrMergeset`, `ErrU2`, `ErrMergeDepth` y
//! `ErrGarantia`. `ErrMergeDepth` es la lectura de `RD-5` (`merge_depth` dev), que no existía en el
//! contrato de transición T01 y por eso no está en [`ErrorTransicion`].
//!
//! Los motivos de **transacción descartada** (`DESC`) no viven aquí: son
//! [`ErrorTransicion`](zx_consensus::transicion::ErrorTransicion) y el arnés los lee con
//! `nombre_t01()`, con las correspondencias ya fijadas por `ORDEN-W03` §4.

use thiserror::Error;
use zx_consensus::transicion::ErrorTransicion;

/// Por qué un bloque no se admite.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum MotivoBloque {
    /// Un padre no está admitido (o falta), el bloque no tiene padres, los repite o `T` no es el
    /// único padre (`D-P08`, `R-15`).
    #[error("ErrSinPadre")]
    ErrSinPadre,
    /// `slot` inválido, no monotónico o salto mayor que `S_max` (`R-10`, `C-HDG-04`).
    #[error("ErrSlot")]
    ErrSlot,
    /// Coinbase mal colocada, ausente donde se exige, repetida o con importe incoherente
    /// (`R-6`, `R-7`, `R-9`).
    #[error("ErrEmision")]
    ErrEmision,
    /// Importe 0 en la coinbase PoST (`R-8`) u otra regla de saldo del bloque.
    #[error("ErrSaldo")]
    ErrSaldo,
    /// El mergeset supera el tope (`C-GD-04`).
    #[error("ErrMergeset")]
    ErrMergeset,
    /// Billete repetido detectado por U2 (`C-GD-07`).
    #[error("ErrU2")]
    ErrU2,
    /// `slot(B) − slot(X) > F_slots` para un bloque fusionado no `rojo_U3` (`RD-5`).
    #[error("ErrMergeDepth")]
    ErrMergeDepth,
    /// El productor no alcanza `q` en `Estado(past(B))` promovido en `slot(B)` (`RD-9`, `TRN-07`).
    #[error("ErrGarantia")]
    ErrGarantia,
    /// Los padres declarados resuelven a más de un terminal distinto: una historia tiene como
    /// mucho un terminal (`I-4`, `ORDEN-W06d7` decisión 1).
    #[error("ErrTerminalAmbiguo")]
    ErrTerminalAmbiguo,
    /// El terminal candidato no cabe en `MAX_TERMINALES_CON_DAG`: su trabajo PoW no supera al peor
    /// de los ya admitidos con DAG propio (`ORDEN-W06d7` decisión 4).
    #[error("ErrLimiteTerminales")]
    ErrLimiteTerminales,
    /// Un fallo del motor de transición que invalida el bloque (forma, etc.).
    #[error("ErrTransicion: {0}")]
    ErrTransicion(#[from] ErrorTransicion),
}

impl MotivoBloque {
    /// Nombre canónico con el que el oráculo T04 lo escribe en el vector.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Self::ErrSinPadre => "ErrSinPadre",
            Self::ErrSlot => "ErrSlot",
            Self::ErrEmision => "ErrEmision",
            Self::ErrSaldo => "ErrSaldo",
            Self::ErrMergeset => "ErrMergeset",
            Self::ErrU2 => "ErrU2",
            Self::ErrMergeDepth => "ErrMergeDepth",
            Self::ErrGarantia => "ErrGarantia",
            Self::ErrTerminalAmbiguo => "ErrTerminalAmbiguo",
            Self::ErrLimiteTerminales => "ErrLimiteTerminales",
            Self::ErrTransicion(e) => e.nombre_t01(),
        }
    }
}
