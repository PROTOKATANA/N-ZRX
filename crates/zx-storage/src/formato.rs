//! Formato de disco de una entrada de la familia `bloques`.
//!
//! # El sobre de familia, y por qué existe
//!
//! Un bloque PoW (`zx_core::wire::cuerpo_a_bytes`) y uno PoST
//! (`zx_core::wire_dag::bloque_dag_a_bytes`) **empiezan los dos por el mismo
//! `consensus_branch_id`** de 4 bytes, así que sus bytes no dicen a qué familia pertenecen.
//! FORMATO‑v0 F‑04 prohíbe «adivinar» la familia de un buffer ambiguo, y aquí no hay llamante que
//! la declare al leer: la clave es solo el `block_hash`. Por eso cada valor guardado lleva delante
//! un discriminante de familia, igual que el sobre versionado del `zx-storage` antiguo
//! (`almacen_admitidos_dag.rs`, `VERSION_ADMITIDOS_DAG`), y el decodificador exige un
//! discriminante conocido en vez de reinterpretarlo.
//!
//! # La codificación es inyectiva y se comprueba
//!
//! Además de recalcular el hash con el código de `zx-core` y compararlo con la clave, se
//! **re-codifica** el objeto leído y se exige que coincida byte a byte con lo guardado. Así una
//! forma no canónica o unos bytes finales no se cuelan como una segunda codificación del mismo
//! bloque: el almacén no guarda dos representaciones de lo mismo.
//!
//! # El `block_hash` no basta: hay que recalcular el compromiso del cuerpo
//!
//! `block_hash` cubre **solo la cabecera**. El cuerpo se ata por el compromiso que la cabecera
//! declara, y ese compromiso hay que recalcularlo sobre los bytes guardados:
//!
//! - **PoW:** `merkle_root(txids)`, con `txid` calculado por `zx-core`, contra
//!   `cabecera.merkle_root`.
//! - **PoST:** `body_commitment` sobre `(txid, auth_digest)`, con el código de `zx-core`, contra
//!   `cabecera.body_commitment`. Cubre tanto los datos de efecto como la autorización (testigos).
//!
//! Sin este recálculo, un bit cambiado en el importe o el destino de una transacción decodifica,
//! deja el `block_hash` intacto y pasaría la integridad; como la repetición no re-verifica
//! cabeceras (D-N03′), el nodo reconstruiría en silencio un estado distinto.
//!
//! # Qué **no** cubre el compromiso PoW: los testigos
//!
//! En PoW no hay `body_commitment` en la cabecera: solo `merkle_root`, calculado sobre los `txid`,
//! y el `txid` **excluye los testigos** (C-TX-01). Por tanto, cambiar un testigo de un bloque PoW
//! no altera ni `block_hash` ni `merkle_root` y la integridad del almacén no puede verlo: lo
//! detecta la **verificación de firmas del motor al re-aplicar** la transacción en la repetición
//! (el testigo es lo que la firma debe satisfacer), no el almacén. En PoST sí queda cubierto,
//! porque `body_commitment` liga `(txid, auth_digest)`.

use zx_core::body_commitment;
use zx_core::digest::{BlockHash, TxId};
use zx_core::preimage::block::merkle_root;
use zx_core::txid;
use zx_core::wire;
use zx_core::wire_dag::{bloque_dag_a_bytes, bloque_dag_desde_bytes};

use crate::error::StorageError;

/// Versión del esquema de disco que entiende este binario.
///
/// La versión 1 dejaba las tablas en la compresión por omisión de RocksDB (LZ4
/// en las instalaciones observadas por ZC-1) y el registro de escritura sin
/// comprimir. La versión 2 usa **zstd** en las tres familias y en el registro de
/// escritura. La versión 3 añade la familia lógica `pruebas` (cuerpos de pruebas
/// por huella de 32 B, con retención y poda; ver [`crate::pruebas`]). Al abrir un
/// almacén de la versión 1 o 2 se migra solo (`disco::migrar_a_v3`), forzando la
/// compactación. El valor de `bloques` conserva su formato
/// `familia(1) ‖ canónicos`: la compresión es del motor de almacenamiento, no una
/// capa que cambie los bytes del bloque.
pub const VERSION_ESQUEMA: u32 = 3;

/// Versión que aún se sabe migrar al abrir: tablas con zstd y sin `pruebas`.
pub const VERSION_ESQUEMA_ZSTD: u32 = 2;

/// Versión que aún se sabe migrar al abrir: tablas con la compresión antigua.
pub const VERSION_ESQUEMA_LZ4: u32 = 1;

/// Familia de un bloque admitido.
///
/// Los valores son parte del formato de disco: no se reordenan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Familia {
    /// Bloque PoW: `cuerpo_a_bytes`, cabecera de 92 B y transacciones con testigos.
    Pow = 0x01,
    /// Bloque PoST: `bloque_dag_a_bytes`, cabecera DAG, justificación PoT y transacciones.
    Post = 0x02,
}

impl Familia {
    /// El byte con el que la familia viaja al disco.
    #[must_use]
    pub const fn discriminante(self) -> u8 {
        self as u8
    }

    /// Interpreta el discriminante de una entrada guardada.
    ///
    /// # Errores
    /// [`StorageError::Corrupto`] si el byte no es una familia conocida.
    pub fn desde_discriminante(byte: u8) -> Result<Self, StorageError> {
        match byte {
            0x01 => Ok(Self::Pow),
            0x02 => Ok(Self::Post),
            _ => Err(StorageError::Corrupto {
                que: "una entrada de `bloques` con una familia desconocida",
            }),
        }
    }
}

/// Compone el valor guardado: `familia(1) ‖ canónicos`.
#[must_use]
pub fn bloque_a_bytes(familia: Familia, canonicos: &[u8]) -> Vec<u8> {
    let mut valor = Vec::with_capacity(1 + canonicos.len());
    valor.push(familia.discriminante());
    valor.extend_from_slice(canonicos);
    valor
}

/// Separa el sobre de familia de los bytes canónicos del bloque.
///
/// # Errores
/// [`StorageError::Corrupto`] si el valor está vacío o la familia es desconocida.
pub fn separar(valor: &[u8]) -> Result<(Familia, &[u8]), StorageError> {
    let (discriminante, canonicos) = valor.split_first().ok_or(StorageError::Corrupto {
        que: "una entrada vacía de `bloques`",
    })?;
    let familia = Familia::desde_discriminante(*discriminante)?;
    Ok((familia, canonicos))
}

/// Recalcula el hash de un bloque a partir de sus bytes canónicos, exigiendo forma canónica y
/// compromiso del cuerpo.
///
/// Además de devolver el `block_hash` de la cabecera, comprueba que el cuerpo reproduce el
/// compromiso que la cabecera declara: `merkle_root(txids)` en PoW, `body_commitment` sobre
/// `(txid, auth_digest)` en PoST. Ver la nota del módulo sobre lo que el PoW **no** cubre.
///
/// # Errores
/// [`StorageError::Corrupto`] si los bytes no decodifican, sobran bytes, o la re-codificación del
/// objeto no coincide exactamente con los bytes de entrada; [`StorageError::CuerpoNoCoincide`] si
/// el cuerpo no reproduce el compromiso de la cabecera.
pub fn hash_canonico(familia: Familia, canonicos: &[u8]) -> Result<BlockHash, StorageError> {
    match familia {
        Familia::Pow => {
            let (cuerpo, sobra) =
                wire::cuerpo_desde_bytes(canonicos).map_err(|_| StorageError::Corrupto {
                    que: "un bloque PoW guardado que no decodifica",
                })?;
            if !sobra.is_empty() {
                return Err(StorageError::Corrupto {
                    que: "un bloque PoW guardado con bytes finales",
                });
            }
            let (cabecera, txs, testigos) = cuerpo;
            let mut re_codificado = Vec::with_capacity(canonicos.len());
            wire::cuerpo_a_bytes(&mut re_codificado, &cabecera, &txs, &testigos);
            if re_codificado != canonicos {
                return Err(StorageError::Corrupto {
                    que: "un bloque PoW guardado en forma no canónica",
                });
            }
            // El `block_hash` solo cubre la cabecera; el cuerpo (los `txid`) se ata por el
            // `merkle_root` que la cabecera declara. Los testigos quedan fuera del `txid` y, por
            // tanto, de este compromiso: ver la nota del módulo.
            let txids: Vec<TxId> = txs
                .iter()
                .map(|t| txid(t, cabecera.consensus_branch_id))
                .collect();
            if merkle_root(&txids) != cabecera.merkle_root {
                return Err(StorageError::CuerpoNoCoincide);
            }
            Ok(cabecera.block_hash())
        }
        Familia::Post => {
            let (bloque, sobra) =
                bloque_dag_desde_bytes(canonicos).map_err(|_| StorageError::Corrupto {
                    que: "un bloque PoST guardado que no decodifica",
                })?;
            if !sobra.is_empty() {
                return Err(StorageError::Corrupto {
                    que: "un bloque PoST guardado con bytes finales",
                });
            }
            let mut re_codificado = Vec::with_capacity(canonicos.len());
            bloque_dag_a_bytes(&mut re_codificado, &bloque);
            if re_codificado != canonicos {
                return Err(StorageError::Corrupto {
                    que: "un bloque PoST guardado en forma no canónica",
                });
            }
            // `body_commitment` liga `(txid, auth_digest)`: cubre los datos de efecto y los
            // testigos. `BloqueDag` garantiza que `txs` y `testigos` miden lo mismo, así que un
            // descuadre aquí solo puede venir de bytes que el decodificador ya aceptó.
            let recalculado = body_commitment(
                bloque.txs(),
                bloque.testigos(),
                bloque.cabecera.consensus_branch_id,
            )
            .map_err(|_| StorageError::Corrupto {
                que: "un bloque PoST con tx y testigos descuadrados",
            })?;
            if recalculado != bloque.cabecera.body_commitment {
                return Err(StorageError::CuerpoNoCoincide);
            }
            Ok(bloque.cabecera.block_hash())
        }
    }
}

/// Recalcula el hash de un valor guardado y exige que coincida con la clave.
///
/// # Errores
/// [`StorageError::Corrupto`] si el sobre no decodifica; [`StorageError::HashNoCoincide`] si el
/// hash recalculado no es la clave; [`StorageError::CuerpoNoCoincide`] si el cuerpo no reproduce
/// el compromiso declarado en su cabecera.
pub fn hash_de_valor(clave: &BlockHash, valor: &[u8]) -> Result<BlockHash, StorageError> {
    let (familia, canonicos) = separar(valor)?;
    let recalculado = hash_canonico(familia, canonicos)?;
    if recalculado != *clave {
        return Err(StorageError::HashNoCoincide { clave: *clave });
    }
    Ok(recalculado)
}
