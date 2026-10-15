//! Errores del almacén de bloques admitidos.
//!
//! Todos son **visibles**: el almacén no repara en silencio. Un hueco en el registro, una entrada
//! sin bloque, un hash que no se reproduce o una `meta` ajena se denuncian; convertir cualquiera de
//! ellos en `None` o en «casi bien» es justo lo que la orden prohíbe.

use thiserror::Error;

use zx_core::digest::BlockHash;
use zx_core::red::Red;

/// Fallo al manipular el almacén.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum StorageError {
    /// Fallo del backend (RocksDB, E/S, lock envenenado).
    #[error("fallo del almacén: {0}")]
    Backend(String),

    /// Los bytes guardados no decodifican, no son canónicos o no son lo que dicen ser.
    ///
    /// Nunca se convierte en `None`: una entrada ilegible es corrupción, no ausencia.
    #[error("almacén corrupto: {que}")]
    Corrupto {
        /// Qué no decodificaba o no era canónico.
        que: &'static str,
    },

    /// El almacén pertenece a otra red.
    #[error("el almacén pertenece a otra red (se abrió como {pedida:?})")]
    RedDistinta {
        /// Red guardada en `meta`.
        encontrada: Red,
        /// Red con la que se intentó abrir.
        pedida: Red,
    },

    /// El almacén pertenece a otro génesis (C-GEN-04).
    #[error("el génesis del almacén ({encontrado}) no es el esperado ({pedido})")]
    GenesisDistinto {
        /// Génesis guardado en `meta`.
        encontrado: BlockHash,
        /// Génesis con el que se intentó abrir.
        pedido: BlockHash,
    },

    /// La versión del esquema de disco no es la esperada.
    #[error("versión de esquema {encontrada} distinta de la esperada {esperada}")]
    VersionEsquema {
        /// Versión guardada en `meta`.
        encontrada: u32,
        /// Versión que entiende este binario.
        esperada: u32,
    },

    /// Falta un índice del registro: el orden de admisión dejó de ser contiguo.
    #[error(
        "hueco en el registro de admisión: se esperaba el índice {esperado} y hay {encontrado}"
    )]
    HuecoEnRegistro {
        /// Índice que tocaba.
        esperado: u64,
        /// Índice que se encontró.
        encontrado: u64,
    },

    /// Una entrada del registro no tiene su bloque: la admisión quedó a medias.
    #[error("la entrada {indice} del registro no tiene bloque")]
    EntradaSinBloque {
        /// Índice huérfano.
        indice: u64,
    },

    /// El hash recalculado del bloque no coincide con la clave bajo la que está guardado.
    #[error("el bloque guardado bajo {clave} no reproduce su hash")]
    HashNoCoincide {
        /// Clave bajo la que estaba guardado.
        clave: BlockHash,
    },

    /// El cuerpo guardado no reproduce el compromiso del cuerpo que declara su cabecera.
    ///
    /// `block_hash` solo cubre la cabecera. El cuerpo se ata por el compromiso que la cabecera
    /// declara —`merkle_root(txids)` en PoW, `body_commitment` sobre `(txid, auth_digest)` en
    /// PoST— y ese compromiso se recalcula al abrir y al leer. Un bit cambiado dentro de una
    /// transacción deja el `block_hash` intacto, así que sin este recálculo pasaría inadvertido.
    #[error("el cuerpo del bloque no reproduce el compromiso declarado en su cabecera")]
    CuerpoNoCoincide,

    /// El cuerpo de una prueba supera el tope de tamaño del almacén (`CP-R-05`).
    ///
    /// No es corrupción: es un rechazo explícito de un cuerpo demasiado grande antes de gastar
    /// memoria en él.
    #[error("el cuerpo de la prueba mide {bytes} B y el tope es {tope} B")]
    CuerpoDemasiadoGrande {
        /// Tamaño del cuerpo recibido, en bytes.
        bytes: usize,
        /// Tope admitido, en bytes.
        tope: usize,
    },
}

impl StorageError {
    /// Envuelve un error del backend en [`StorageError::Backend`].
    pub fn backend<E: core::fmt::Display>(e: E) -> Self {
        Self::Backend(e.to_string())
    }
}
