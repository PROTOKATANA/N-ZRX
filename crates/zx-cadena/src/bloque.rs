//! Bloque de entrada de la cadena (`ORDEN-W06a` decisión 2).
//!
//! `BloqueCadena` une las dos familias de la transición con lo que GHOSTDAG necesita para colorear y
//! ordenar (`C-GD-05`, `C-GD-07`) más lo que el motor de transición necesita:
//!
//! - [`BloqueCadena::Pow`]: el bloque PoW ya traducido a [`BloqueTransicion`] (`ED-1`).
//! - [`BloqueCadena::Post`]: el bloque `PoAS_PoT_DAG` con sus padres, `slot`, productor, peso,
//!   `sr`/`distancia`/`identidad` de GHOSTDAG y sus transacciones reales.
//!
//! La verificación de cabeceras (PoW, PoT, PoAS, sello) **no** es de esta orden: llega hecha en
//! `pow_valido`/`prueba_valida`, como en W03.

use zx_consensus::transicion::{BloqueTransicion, HechosCabecera};
use zx_core::{BlockHash, ClavePublica, Tx};
use zx_dag::ghostdag::IdentidadGhostdag;

/// Bloque `PoAS_PoT_DAG` con los campos que consumen `zx-dag` y `zx-consensus`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BloquePost {
    /// `block_hash` del bloque.
    pub hash: BlockHash,
    /// Padres declarados (incluido el terminal en el bloque de transición). El orden es el del
    /// vector; `zx-dag` recalcula el `sp`.
    pub padres: Vec<BlockHash>,
    /// Índice de PoT del bloque (`≥ 1`).
    pub slot: u64,
    /// `timestamp` de la cabecera PoST.
    ///
    /// `RL-2c`: la cadena seleccionada necesita el timestamp para recalcular el calendario de `T`
    /// de forma determinista (`C-RLJ-04`/`C-RLJ-06`), sin depender del pasado admitido localmente.
    pub timestamp: u64,
    /// Clave del productor (`sol.public_key`).
    pub productor: ClavePublica,
    /// Peso PoST del bloque (`≥ 1`), que suma `peso_sufijo` solo si el bloque es de cadena.
    pub peso: u128,
    /// Resultado de la verificación de sello/prueba, ya decidida.
    pub prueba_valida: bool,
    /// `requisito` declarado en la cabecera; se ignora para decidir (`X-10`).
    pub requisito_declarado: u64,
    /// `rango_solucion` de GHOSTDAG (`C-GD-01`).
    pub sr: u64,
    /// `solution_distance` de GHOSTDAG (`C-GD-05`).
    pub distancia: u64,
    /// Identidad de billete de GHOSTDAG (`C-GD-07`) **real**: la tupla literal
    /// `(public_key, sector_index, history_size, chunk, slot)`.
    ///
    /// La ruta de producción la deriva de la misma cabecera que aporta `block_hash`, `slot` y `SR`
    /// con `zx_dag::identidad_de_cabecera` (`IdentidadGhostdag::Billete`). El arnés diferencial de
    /// T04 usa [`IdentidadGhostdag::de_fixture`] porque sus vectores sólo traen un `u64`; su uso
    /// queda limitado a ese arnés.
    pub identidad: IdentidadGhostdag,
    /// Transacciones del bloque con sus testigos.
    pub txs: Vec<(Tx, Vec<Vec<u8>>)>,
}

/// Bloque de la cadena: fase PoW o fase PoST.
///
/// La variante PoW guarda el bloque de transición completo (cabecera real opcional incluida); la
/// diferencia de tamaño no importa porque los bloques viven en mapas y no en vectores densos.
#[derive(Clone, PartialEq, Eq, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "los bloques viven en mapas, no en un vector denso; boxear oscurecería el tipo de la orden"
)]
pub enum BloqueCadena {
    /// Bloque de la fase PoW (incluido el génesis).
    Pow(BloqueTransicion),
    /// Bloque `PoAS_PoT_DAG` de la fase PoST.
    Post(BloquePost),
}

impl BloqueCadena {
    /// `block_hash` del bloque.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        match self {
            Self::Pow(b) => b.hash(),
            Self::Post(p) => p.hash,
        }
    }

    /// Padre seleccionado declarado, si lo hay.
    #[must_use]
    pub fn padre_seleccionado(&self) -> Option<BlockHash> {
        match self {
            Self::Pow(b) => b.padre(),
            Self::Post(p) => p.padres.first().copied(),
        }
    }

    /// `slot` de un bloque PoST.
    #[must_use]
    pub fn slot(&self) -> Option<u64> {
        match self {
            Self::Pow(_) => None,
            Self::Post(p) => Some(p.slot),
        }
    }

    /// Padres declarados (vacío en PoW, donde el padre es único).
    #[must_use]
    pub fn padres(&self) -> Vec<BlockHash> {
        match self {
            Self::Pow(b) => b.padre().map_or_else(Vec::new, |p| vec![p]),
            Self::Post(p) => p.padres.clone(),
        }
    }

    /// Peso PoST de un bloque (`None` en PoW).
    #[must_use]
    pub fn peso(&self) -> Option<u128> {
        match self {
            Self::Pow(_) => None,
            Self::Post(p) => Some(p.peso),
        }
    }

    /// Transacciones con testigos.
    #[must_use]
    pub fn txs(&self) -> &[(Tx, Vec<Vec<u8>>)] {
        match self {
            Self::Pow(b) => &b.txs,
            Self::Post(p) => &p.txs,
        }
    }

    /// Representación como [`BloqueTransicion`] para el motor de transición.
    ///
    /// Para PoST usa `padres[0]` como `padre` declarado; `aplicar_fusion` solo lo consulta en el
    /// bloque de transición (`padre == terminal`), donde la lista tiene exactamente un elemento.
    #[must_use]
    pub fn como_transicion(&self) -> BloqueTransicion {
        match self {
            Self::Pow(b) => b.clone(),
            Self::Post(p) => {
                let padre = p.padres.first().copied().unwrap_or(p.hash);
                BloqueTransicion::nuevo(
                    HechosCabecera::PoST {
                        hash: p.hash,
                        padre,
                        slot: p.slot,
                        productor: p.productor,
                        peso: p.peso,
                        prueba_valida: p.prueba_valida,
                        requisito_declarado: p.requisito_declarado,
                    },
                    p.txs.clone(),
                )
            }
        }
    }
}
