//! El rasgo del almacén y el bloque que se admite.
//!
//! [`Almacen`] es lo único que el nodo necesita para persistir: admitir un bloque, leerlo por hash
//! y repetir el registro en orden. Lo implementan [`crate::memoria::AlmacenEnMemoria`] y
//! [`crate::disco::AlmacenEnDisco`], y los tests diferenciales exigen que respondan igual.

use core::fmt;
use std::borrow::Cow;

use zx_core::digest::BlockHash;
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_core::tx::Tx;
use zx_core::wire;
use zx_core::wire_dag::{BloqueDag, bloque_dag_a_bytes};

use crate::error::StorageError;
use crate::formato::{self, Familia};

/// Un bloque listo para admitir: su familia, sus bytes canónicos y su hash ya calculado.
///
/// Se construye de tres formas:
///
/// - [`BloqueAdmitido::pow`] y [`BloqueAdmitido::post`] codifican un bloque tipado con el códec
///   canónico de `zx-core` y calculan su hash.
/// - [`BloqueAdmitido::desde_canonicos`] toma bytes ya codificados y **exige** que decodifiquen y
///   que la re-codificación coincida (forma canónica).
/// - [`BloqueAdmitido::desde_almacen`] toma el valor guardado `familia(1) ‖ canónicos`, como el que
///   entrega [`Almacen::repetir`].
#[derive(Debug, Clone)]
pub struct BloqueAdmitido<'a> {
    familia: Familia,
    canonicos: Cow<'a, [u8]>,
    hash: BlockHash,
}

impl<'a> BloqueAdmitido<'a> {
    /// Codifica un bloque PoW con `cuerpo_a_bytes` y calcula su `block_hash`.
    #[must_use]
    pub fn pow(cabecera: &BlockHeader, txs: &[Tx], testigos: &[Vec<Vec<u8>>]) -> Self {
        let mut canonicos = Vec::new();
        wire::cuerpo_a_bytes(&mut canonicos, cabecera, txs, testigos);
        Self {
            familia: Familia::Pow,
            canonicos: Cow::Owned(canonicos),
            hash: cabecera.block_hash(),
        }
    }

    /// Codifica un bloque PoST con `bloque_dag_a_bytes` y calcula su `block_hash`.
    #[must_use]
    pub fn post(bloque: &BloqueDag) -> Self {
        let mut canonicos = Vec::new();
        bloque_dag_a_bytes(&mut canonicos, bloque);
        Self {
            familia: Familia::Post,
            canonicos: Cow::Owned(canonicos),
            hash: bloque.cabecera.block_hash(),
        }
    }

    /// Toma bytes canónicos ya codificados, comprueba que lo sean y calcula su hash.
    ///
    /// # Errores
    /// [`StorageError::Corrupto`] si no decodifican, sobran bytes o la forma no es canónica.
    pub fn desde_canonicos(familia: Familia, canonicos: &'a [u8]) -> Result<Self, StorageError> {
        let hash = formato::hash_canonico(familia, canonicos)?;
        Ok(Self {
            familia,
            canonicos: Cow::Borrowed(canonicos),
            hash,
        })
    }

    /// Toma el valor guardado `familia(1) ‖ canónicos`.
    ///
    /// # Errores
    /// [`StorageError::Corrupto`] si el sobre está vacío, la familia es desconocida o los canónicos
    /// no son válidos.
    pub fn desde_almacen(valor: &'a [u8]) -> Result<Self, StorageError> {
        let (familia, canonicos) = formato::separar(valor)?;
        Self::desde_canonicos(familia, canonicos)
    }

    /// El hash de la cabecera, ya calculado.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.hash
    }

    /// La familia del bloque.
    #[must_use]
    pub fn familia(&self) -> Familia {
        self.familia
    }

    /// Los bytes canónicos del bloque, sin el sobre de familia.
    #[must_use]
    pub fn canonicos(&self) -> &[u8] {
        &self.canonicos
    }

    /// El valor tal y como se guarda en la familia `bloques`.
    #[must_use]
    pub fn a_bytes_almacen(&self) -> Vec<u8> {
        formato::bloque_a_bytes(self.familia, &self.canonicos)
    }
}

/// El fallo de una repetición: o fue del almacén, o lo devolvió el destino.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorRepeticion<E> {
    /// El almacén no pudo entregar el siguiente bloque.
    Almacen(StorageError),
    /// El destino rechazó el bloque. La repetición se detuvo en él.
    Destino(E),
}

impl<E: fmt::Display> fmt::Display for ErrorRepeticion<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Almacen(e) => write!(f, "la repetición falló en el almacén: {e}"),
            Self::Destino(e) => write!(f, "la repetición falló en el destino: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for ErrorRepeticion<E> {}

/// Almacén de bloques admitidos y de su orden de admisión.
///
/// # Contrato
///
/// - **Atomicidad:** cada admisión es una sola operación lógica —el bloque y su entrada del
///   registro—. Un corte del proceso deja el registro en un prefijo contiguo, nunca a medias.
/// - **Idempotencia:** admitir otra vez el mismo `block_hash` no añade entrada al registro.
/// - **Integridad:** al abrir y al leer se recalcula el hash del bloque y se compara con la clave;
///   un hueco del registro, una entrada sin bloque o un hash que no coincide son error explícito,
///   sin reparación silenciosa.
/// - **Repetición:** los bloques salen en el orden del registro, con los mismos bytes.
pub trait Almacen: Send + Sync {
    /// La red con la que se abrió el almacén.
    fn red(&self) -> Red;

    /// El hash del génesis con el que se abrió el almacén.
    fn genesis(&self) -> BlockHash;

    /// Admite un bloque y devuelve su hash.
    ///
    /// `sync` decide si la escritura se fuerza a disco antes de volver (`true` en los tests de
    /// muerte). Admitir dos veces el mismo bloque es idempotente.
    ///
    /// # Errores
    /// [`StorageError`] si el backend falla o si ya había bytes distintos bajo el mismo hash.
    fn admitir(&self, bloque: &BloqueAdmitido<'_>, sync: bool) -> Result<BlockHash, StorageError>;

    /// Admite bytes canónicos ya codificados, sin construirlos antes a mano.
    ///
    /// # Errores
    /// Las de [`BloqueAdmitido::desde_canonicos`] y [`Almacen::admitir`].
    fn admitir_canonicos(
        &self,
        familia: Familia,
        canonicos: &[u8],
        sync: bool,
    ) -> Result<BlockHash, StorageError> {
        let bloque = BloqueAdmitido::desde_canonicos(familia, canonicos)?;
        self.admitir(&bloque, sync)
    }

    /// Lee el valor guardado de un bloque, `familia(1) ‖ canónicos`, verificando su hash.
    ///
    /// `Ok(None)` significa que el hash no está admitido; una entrada corrupta devuelve error.
    ///
    /// # Errores
    /// [`StorageError::Corrupto`] o [`StorageError::HashNoCoincide`] si lo guardado no cuadra.
    fn bloque(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StorageError>;

    /// Recorre el registro en orden y entrega cada bloque.
    ///
    /// El destino recibe `(block_hash, valor_guardado)`, donde el valor es
    /// `familia(1) ‖ canónicos` (reconstruible con [`BloqueAdmitido::desde_almacen`]). Se detiene en
    /// el primer error y lo devuelve en [`ErrorRepeticion`].
    ///
    /// # Errores
    /// [`ErrorRepeticion::Almacen`] si el almacén falla; [`ErrorRepeticion::Destino`] si el destino
    /// devuelve error.
    fn repetir<E>(
        &self,
        destino: &mut impl FnMut(BlockHash, &[u8]) -> Result<(), E>,
    ) -> Result<(), ErrorRepeticion<E>>;

    /// Cuántas entradas tiene el registro: el índice de la próxima admisión.
    ///
    /// # Errores
    /// [`StorageError`] si el backend falla.
    fn longitud_registro(&self) -> Result<u64, StorageError>;

    /// Fuerza el volcado a disco de lo pendiente.
    ///
    /// # Errores
    /// [`StorageError`] si el backend falla.
    fn sincronizar(&self) -> Result<(), StorageError>;
}
