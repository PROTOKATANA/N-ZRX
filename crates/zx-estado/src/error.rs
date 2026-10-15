//! Error propio del crate. Sin `unsafe`, sin `unwrap` y sin `panic!` en el camino de producción.

use crate::hash::Hash32;

/// Error del árbol de estado, del lote o del almacén.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Los bytes de un nodo no son un nodo válido del formato.
    #[error("nodo mal formado")]
    NodoMalFormado,
    /// Falta el nodo referenciado por un padre.
    #[error("nodo ausente: {0:02x?}")]
    NodoAusente(Hash32),
    /// La familia no es una de las del diseño (`RAIZ-ESTADO.md` §3.2).
    #[error("familia desconocida: {0:#04x}")]
    FamiliaDesconocida(u8),
    /// Una prueba no tiene forma válida (profundidad, longitudes o terminal).
    #[error("prueba inválida")]
    PruebaInvalida,
    /// Un valor no cabe en el formato de longitud del formato de nodo.
    #[error("longitud fuera de rango en el formato")]
    LongitudFueraDeRango,
    /// Falta una familia de columnas del almacén en disco.
    #[error("familia de columnas ausente: {0}")]
    ColumnFamilyAusente(&'static str),
    /// Error del motor RocksDB.
    #[cfg(feature = "rocksdb")]
    #[error("rocksdb: {0}")]
    Rocks(#[from] rocksdb::Error),
}
