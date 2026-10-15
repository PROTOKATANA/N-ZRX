//! Almacén sobre RocksDB (feature `rocksdb`).
//!
//! Ver [`crate::memoria`] para por qué existe una implementación de referencia en memoria contra la
//! que este backend se contrasta.
//!
//! # Familias de columnas
//!
//! | Familia | Clave → valor | Por qué separada |
//! |---|---|---|
//! | `bloques` | `block_hash`(32) → `familia`(1) ‖ canónicos | Los bloques admitidos, con su familia PoW/PoST |
//! | `registro` | índice(`u64` BE) → `block_hash`(32) | El orden de admisión; se recorre para repetir |
//! | `pruebas` | prefijo `prueba:` ‖ huella(32) → `referencia`(8) ‖ estado(1) ‖ [cuerpo] | Cuerpos de pruebas por huella, con retención y poda (`CP-R-27`…`CP-R-31`) |
//! | `meta` | clave corta → valor | red, génesis y versión del esquema |
//!
//! La familia `pruebas` es **lógica**: vive en el *column family* `default` bajo el prefijo
//! `prueba:`. No se añade un *column family* nuevo porque RocksDB exige abrir **todas** las
//! familias existentes y hay abridores que listan solo las tres documentadas (p. ej.
//! `crates/zx-node/tests/reinicio.rs`); `default` ya lo abren todos. Ver [`crate::pruebas`].
//!
//! El índice va en **big-endian a propósito**: RocksDB ordena las claves por bytes, así que
//! big-endian hace que el orden lexicográfico coincida con el numérico y el registro se recorra en
//! orden ascendente sin ordenar nada.
//!
//! # Escrituras atómicas
//!
//! Cada admisión toca **dos** familias —`bloques` y `registro`— y se hace con un solo `WriteBatch`:
//! RocksDB lo aplica de forma atómica porque las familias comparten el WAL. Sin el lote, un corte
//! entre las dos escrituras dejaría una entrada de registro sin su bloque o un bloque sin entrada.
//!
//! # Integridad al abrir y al leer
//!
//! Al abrir se recorre el registro exigiendo que sea contiguo desde `0` y que cada entrada tenga su
//! bloque con el hash correcto. Al leer un bloque se vuelve a recalcular su hash con el código de
//! `zx-core`. Cualquier anomalía es error explícito; no hay reparación silenciosa.

use std::path::Path;
use std::sync::Mutex;

use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, DBRecoveryMode, Direction,
    IteratorMode, Options, WriteBatch, WriteOptions,
};

use zx_core::digest::{BlockHash, Digest};
use zx_core::red::Red;

use crate::almacen::{Almacen, BloqueAdmitido, ErrorRepeticion};
use crate::error::StorageError;
use crate::formato::{self, VERSION_ESQUEMA, VERSION_ESQUEMA_LZ4, VERSION_ESQUEMA_ZSTD};
use crate::pruebas::{
    self, AlmacenPruebas, EstadoPrueba, Huella, MAX_CUERPO_PRUEBA_BYTES, Referencia,
};

/// Los bloques admitidos: `block_hash`(32) → `familia`(1) ‖ canónicos.
const CF_BLOQUES: &str = "bloques";
/// El orden de admisión: índice(`u64` BE) → `block_hash`(32).
const CF_REGISTRO: &str = "registro";
/// La identidad del almacén: red, génesis y versión del esquema.
const CF_META: &str = "meta";
/// El *column family* físico que aloja la familia lógica `pruebas`.
///
/// Es `default` a propósito: RocksDB obliga a abrir todas las familias existentes y hay abridores
/// (fuera de este crate) que listan solo `bloques`, `registro` y `meta`; `default` lo añade
/// rust-rocksdb solo en cualquier apertura.
const CF_PRUEBAS: &str = "default";

/// Prefijo de las claves de la familia `pruebas` dentro de `default`.
const PREFIJO_PRUEBA: &[u8] = b"prueba:";

/// Clave de la red dentro de `meta`.
const META_RED: &[u8] = b"red";
/// Clave del hash del génesis dentro de `meta`.
const META_GENESIS: &[u8] = b"genesis";
/// Clave de la versión del esquema dentro de `meta`.
const META_VERSION: &[u8] = b"version_esquema";

/// Almacén persistente sobre RocksDB.
#[derive(Debug)]
pub struct AlmacenEnDisco {
    db: DB,
    red: Red,
    genesis: BlockHash,
    /// Índice de la próxima admisión. Se inicializa con la longitud verificada del registro.
    siguiente: Mutex<u64>,
}

fn backend<E: core::fmt::Display>(e: E) -> StorageError {
    StorageError::backend(e)
}

/// El byte con el que la red viaja a `meta`.
fn codigo_red(red: Red) -> u8 {
    match red {
        Red::Mainnet => 0,
        Red::Testnet => 1,
        Red::Dev => 2,
    }
}

/// Interpreta el byte de red de `meta`.
///
/// # Errores
/// [`StorageError::Corrupto`] si no es una red conocida.
fn red_desde_codigo(codigo: u8) -> Result<Red, StorageError> {
    match codigo {
        0 => Ok(Red::Mainnet),
        1 => Ok(Red::Testnet),
        2 => Ok(Red::Dev),
        _ => Err(StorageError::Corrupto {
            que: "la red en `meta` no es conocida",
        }),
    }
}

/// Accede a una familia de columnas.
///
/// # Errores
/// [`StorageError::Backend`] si la familia no existe (no debería: se abren todas).
fn cf<'a>(db: &'a DB, nombre: &str) -> Result<&'a ColumnFamily, StorageError> {
    db.cf_handle(nombre)
        .ok_or_else(|| StorageError::Backend(format!("falta la familia {nombre}")))
}

/// ¿Está la familia vacía?
///
/// # Errores
/// [`StorageError`] si el iterador falla.
fn esta_vacio(db: &DB, nombre: &str) -> Result<bool, StorageError> {
    let cf = cf(db, nombre)?;
    match db.iterator_cf(cf, IteratorMode::Start).next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(e)) => Err(backend(e)),
    }
}

/// Lee el valor de un bloque verificando que su hash recalculado coincide con la clave.
///
/// # Errores
/// [`StorageError::Corrupto`] o [`StorageError::HashNoCoincide`] si lo guardado no cuadra.
fn leer_verificado(db: &DB, hash: &BlockHash) -> Result<Option<Vec<u8>>, StorageError> {
    let cf_bloques = cf(db, CF_BLOQUES)?;
    let Some(valor) = db.get_cf(cf_bloques, hash.as_bytes()).map_err(backend)? else {
        return Ok(None);
    };
    let _ = formato::hash_de_valor(hash, &valor)?;
    Ok(Some(valor))
}

/// Comprueba —o escribe por primera vez— la identidad del almacén.
///
/// Un almacén sin marca de esquema solo puede ser nuevo: si tuviera datos, es corrupción y no se
/// reescribe nada.
///
/// # Errores
/// [`StorageError::RedDistinta`], [`StorageError::GenesisDistinto`], [`StorageError::VersionEsquema`]
/// o [`StorageError::Corrupto`].
fn inicializar_o_verificar_meta(db: &DB, red: Red, genesis: BlockHash) -> Result<(), StorageError> {
    let cf_meta = cf(db, CF_META)?;
    let Some(bytes) = db.get_cf(cf_meta, META_VERSION).map_err(backend)? else {
        if !esta_vacio(db, CF_BLOQUES)?
            || !esta_vacio(db, CF_REGISTRO)?
            || !esta_vacio(db, CF_PRUEBAS)?
        {
            return Err(StorageError::Corrupto {
                que: "un almacén con datos y sin marca de esquema",
            });
        }
        let mut lote = WriteBatch::default();
        lote.put_cf(cf_meta, META_RED, [codigo_red(red)]);
        lote.put_cf(cf_meta, META_GENESIS, genesis.as_bytes());
        lote.put_cf(cf_meta, META_VERSION, VERSION_ESQUEMA.to_be_bytes());
        let mut opciones = WriteOptions::default();
        opciones.set_sync(true);
        return db.write_opt(lote, &opciones).map_err(backend);
    };

    let version: [u8; 4] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::Corrupto {
            que: "la versión del esquema en `meta`",
        })?;
    let encontrada = u32::from_be_bytes(version);

    let red_bytes =
        db.get_cf(cf_meta, META_RED)
            .map_err(backend)?
            .ok_or(StorageError::Corrupto {
                que: "falta la red en `meta`",
            })?;
    let encontrada_red = red_desde_codigo(*red_bytes.first().ok_or(StorageError::Corrupto {
        que: "la red en `meta` está vacía",
    })?)?;
    if encontrada_red != red {
        return Err(StorageError::RedDistinta {
            encontrada: encontrada_red,
            pedida: red,
        });
    }

    let genesis_bytes =
        db.get_cf(cf_meta, META_GENESIS)
            .map_err(backend)?
            .ok_or(StorageError::Corrupto {
                que: "falta el génesis en `meta`",
            })?;
    let genesis_arr: [u8; 32] =
        genesis_bytes
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Corrupto {
                que: "el génesis en `meta`",
            })?;
    let encontrado = BlockHash::from_digest(Digest::from_bytes(genesis_arr));
    if encontrado != genesis {
        return Err(StorageError::GenesisDistinto {
            encontrado,
            pedido: genesis,
        });
    }

    match encontrada {
        VERSION_ESQUEMA => Ok(()),
        VERSION_ESQUEMA_ZSTD | VERSION_ESQUEMA_LZ4 => migrar_a_v3(db),
        otra => Err(StorageError::VersionEsquema {
            encontrada: otra,
            esperada: VERSION_ESQUEMA,
        }),
    }
}

/// Migra del esquema 1 (compresión antigua) o 2 (zstd sin `pruebas`) al 3 (con la familia
/// `pruebas`).
///
/// No reescribe los valores —el formato de bloque no cambia y la familia nueva nace vacía—: fuerza
/// la compactación de las cuatro familias para que las SST viejas se reescriban con la compresión
/// zstd ya activa en las opciones y fija `version_esquema=3`. Es idempotente: si el proceso muere
/// antes de fijar la versión, el siguiente arranque repite la compactación sin tocar los datos.
///
/// # Errores
/// [`StorageError::Backend`].
fn migrar_a_v3(db: &DB) -> Result<(), StorageError> {
    // La compactación reescribe las SST antiguas con la compresión nueva: sin
    // esto, el ahorro en tablas no llega hasta que RocksDB compacte sola.
    for nombre in [CF_PRUEBAS, CF_BLOQUES, CF_REGISTRO, CF_META] {
        let cf = cf(db, nombre)?;
        db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
    }

    let cf_meta = cf(db, CF_META)?;
    let mut opciones = WriteOptions::default();
    opciones.set_sync(true);
    db.put_cf_opt(
        cf_meta,
        META_VERSION,
        VERSION_ESQUEMA.to_be_bytes(),
        &opciones,
    )
    .map_err(backend)
}

/// Recorre el registro exigiendo contigüidad y que cada entrada tenga su bloque verificado.
///
/// Devuelve cuántas entradas hay (el índice de la próxima admisión).
///
/// # Errores
/// [`StorageError::HuecoEnRegistro`], [`StorageError::EntradaSinBloque`] o las de
/// [`leer_verificado`].
fn verificar_estructura(db: &DB) -> Result<u64, StorageError> {
    let cf_registro = cf(db, CF_REGISTRO)?;
    let mut esperado: u64 = 0;
    for item in db.iterator_cf(cf_registro, IteratorMode::Start) {
        let (clave, valor) = item.map_err(backend)?;
        let clave_arr: [u8; 8] = clave
            .as_ref()
            .try_into()
            .map_err(|_| StorageError::Corrupto {
                que: "una clave del registro con tamaño distinto de 8",
            })?;
        let indice = u64::from_be_bytes(clave_arr);
        if indice != esperado {
            return Err(StorageError::HuecoEnRegistro {
                esperado,
                encontrado: indice,
            });
        }
        let hash_arr: [u8; 32] = valor
            .as_ref()
            .try_into()
            .map_err(|_| StorageError::Corrupto {
                que: "un hash del registro con tamaño distinto de 32",
            })?;
        let hash = BlockHash::from_digest(Digest::from_bytes(hash_arr));
        if leer_verificado(db, &hash)?.is_none() {
            return Err(StorageError::EntradaSinBloque { indice });
        }
        esperado = esperado.checked_add(1).ok_or_else(|| {
            StorageError::Backend("el registro desbordó el contador de u64".to_owned())
        })?;
    }
    Ok(esperado)
}

impl AlmacenEnDisco {
    /// Abre —o crea— el almacén en un directorio, para una red y un génesis.
    ///
    /// Si el almacén ya existía con otra red, otro génesis u otra versión de esquema, devuelve
    /// error y **no** reescribe nada.
    ///
    /// # Errores
    /// [`StorageError::Backend`] si RocksDB no puede abrir el directorio; [`StorageError::Corrupto`],
    /// [`StorageError::RedDistinta`], [`StorageError::GenesisDistinto`] o
    /// [`StorageError::VersionEsquema`] si lo guardado no cuadra.
    pub fn abrir(ruta: &Path, red: Red, genesis: BlockHash) -> Result<Self, StorageError> {
        let mut opciones = Options::default();
        opciones.create_if_missing(true);
        opciones.create_missing_column_families(true);

        // El modo de recuperación se fija explícitamente, aunque hoy coincida con el valor por
        // omisión: depender de un default es depender de que nadie lo mueva, y ya se movió una vez
        // (RocksDB 6.6). NO se usa `AbsoluteConsistency`: convierte la cola truncada normal de un
        // `kill -9` en una base de datos que no abre (facebook/rocksdb#2871), y un nodo que no
        // arranca es peor que uno que re-sincroniza los últimos bloques.
        opciones.set_wal_recovery_mode(DBRecoveryMode::PointInTime);

        // ZRX-C (ZC-2): el registro de escritura y las tablas van en zstd. El
        // valor de `bloques` conserva su formato `familia(1) ‖ canónicos`; la
        // compresión es del motor de almacenamiento (R-10 de ZRX-C).
        opciones.set_wal_compression_type(DBCompressionType::Zstd);

        fn opciones_de_familia() -> Options {
            let mut cf_opts = Options::default();
            cf_opts.set_compression_type(DBCompressionType::Zstd);
            cf_opts
        }

        let familias = [CF_PRUEBAS, CF_BLOQUES, CF_REGISTRO, CF_META]
            .into_iter()
            .map(|nombre| ColumnFamilyDescriptor::new(nombre, opciones_de_familia()))
            .collect::<Vec<_>>();

        let db = DB::open_cf_descriptors(&opciones, ruta, familias).map_err(backend)?;
        inicializar_o_verificar_meta(&db, red, genesis)?;
        let longitud = verificar_estructura(&db)?;

        Ok(Self {
            db,
            red,
            genesis,
            siguiente: Mutex::new(longitud),
        })
    }

    /// Los hashes del registro, en orden.
    fn hashes_del_registro(&self) -> Result<Vec<BlockHash>, StorageError> {
        let cf_registro = cf(&self.db, CF_REGISTRO)?;
        let mut hashes = Vec::new();
        for item in self.db.iterator_cf(cf_registro, IteratorMode::Start) {
            let (_clave, valor) = item.map_err(backend)?;
            let arr: [u8; 32] = valor
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Corrupto {
                    que: "un hash del registro con tamaño distinto de 32",
                })?;
            hashes.push(BlockHash::from_digest(Digest::from_bytes(arr)));
        }
        Ok(hashes)
    }
}

impl Almacen for AlmacenEnDisco {
    fn red(&self) -> Red {
        self.red
    }

    fn genesis(&self) -> BlockHash {
        self.genesis
    }

    fn admitir(&self, bloque: &BloqueAdmitido<'_>, sync: bool) -> Result<BlockHash, StorageError> {
        let hash = bloque.hash();
        let valor = bloque.a_bytes_almacen();

        // El lock serializa la comprobación de duplicado **y** la asignación del índice. Hacer la
        // comprobación fuera dejaría que dos hilos admitieran a la vez el mismo hash nuevo y
        // crearan dos entradas del registro. El lock se mantiene durante la escritura, de modo que
        // un fallo del backend tampoco consume un índice.
        let mut siguiente = self.siguiente.lock().map_err(|_| {
            StorageError::Backend("lock envenenado: otro hilo entró en pánico".to_owned())
        })?;

        // Idempotencia: el mismo hash no añade una segunda entrada al registro. Si los bytes
        // guardados difieren, es corrupción y se denuncia.
        let cf_bloques = cf(&self.db, CF_BLOQUES)?;
        if let Some(existente) = self
            .db
            .get_cf(cf_bloques, hash.as_bytes())
            .map_err(backend)?
        {
            if existente != valor {
                return Err(StorageError::Corrupto {
                    que: "dos admisiones del mismo hash con bytes distintos",
                });
            }
            return Ok(hash);
        }

        let indice = *siguiente;
        let siguiente_indice = indice.checked_add(1).ok_or_else(|| {
            StorageError::Backend("el registro desbordó el contador de u64".to_owned())
        })?;

        let cf_registro = cf(&self.db, CF_REGISTRO)?;
        let mut lote = WriteBatch::default();
        lote.put_cf(cf_bloques, hash.as_bytes(), valor);
        lote.put_cf(cf_registro, indice.to_be_bytes(), hash.as_bytes());
        let mut opciones = WriteOptions::default();
        opciones.set_sync(sync);
        self.db.write_opt(lote, &opciones).map_err(backend)?;

        *siguiente = siguiente_indice;
        Ok(hash)
    }

    fn bloque(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StorageError> {
        leer_verificado(&self.db, hash)
    }

    fn repetir<E>(
        &self,
        destino: &mut impl FnMut(BlockHash, &[u8]) -> Result<(), E>,
    ) -> Result<(), ErrorRepeticion<E>> {
        let hashes = self
            .hashes_del_registro()
            .map_err(ErrorRepeticion::Almacen)?;
        for (posicion, hash) in hashes.into_iter().enumerate() {
            let indice = u64::try_from(posicion).map_err(|_| {
                ErrorRepeticion::Almacen(StorageError::Backend(
                    "el registro no cabe en u64".to_owned(),
                ))
            })?;
            let valor = self
                .bloque(&hash)
                .map_err(ErrorRepeticion::Almacen)?
                .ok_or(ErrorRepeticion::Almacen(StorageError::EntradaSinBloque {
                    indice,
                }))?;
            destino(hash, &valor).map_err(ErrorRepeticion::Destino)?;
        }
        Ok(())
    }

    fn longitud_registro(&self) -> Result<u64, StorageError> {
        let guard = self.siguiente.lock().map_err(|_| {
            StorageError::Backend("lock envenenado: otro hilo entró en pánico".to_owned())
        })?;
        Ok(*guard)
    }

    fn sincronizar(&self) -> Result<(), StorageError> {
        self.db.flush().map_err(backend)
    }
}

/// Compone la clave de la familia `pruebas`: `prueba:` ‖ huella(32).
fn clave_prueba(huella: &Huella) -> Vec<u8> {
    let mut clave = Vec::with_capacity(PREFIJO_PRUEBA.len() + huella.len());
    clave.extend_from_slice(PREFIJO_PRUEBA);
    clave.extend_from_slice(huella);
    clave
}

impl AlmacenPruebas for AlmacenEnDisco {
    fn guardar(
        &self,
        huella: Huella,
        referencia: Referencia,
        cuerpo: &[u8],
    ) -> Result<(), StorageError> {
        if cuerpo.len() > MAX_CUERPO_PRUEBA_BYTES {
            return Err(StorageError::CuerpoDemasiadoGrande {
                bytes: cuerpo.len(),
                tope: MAX_CUERPO_PRUEBA_BYTES,
            });
        }
        let cf = cf(&self.db, CF_PRUEBAS)?;
        let clave = clave_prueba(&huella);
        let (retencion, conserva_cuerpo) = match self.db.get_cf(cf, &clave).map_err(backend)? {
            Some(valor) => {
                let (retencion, guardado) = pruebas::valor_desde_bytes(&valor)?;
                if guardado.is_some_and(|bytes| bytes != cuerpo) {
                    return Err(StorageError::Corrupto {
                        que: "la misma huella de `pruebas` con dos cuerpos distintos",
                    });
                }
                (retencion.max(referencia), guardado.is_some())
            }
            None => (referencia, true),
        };
        let valor = if conserva_cuerpo {
            pruebas::valor_a_bytes(retencion, Some(cuerpo))
        } else {
            pruebas::valor_a_bytes(retencion, None)
        };
        self.db.put_cf(cf, &clave, valor).map_err(backend)
    }

    fn obtener(&self, huella: &Huella) -> Result<Option<EstadoPrueba>, StorageError> {
        let cf = cf(&self.db, CF_PRUEBAS)?;
        let Some(valor) = self.db.get_cf(cf, clave_prueba(huella)).map_err(backend)? else {
            return Ok(None);
        };
        let (referencia, cuerpo) = pruebas::valor_desde_bytes(&valor)?;
        Ok(Some(match cuerpo {
            Some(bytes) => EstadoPrueba::Presente {
                huella: *huella,
                referencia,
                cuerpo: bytes.to_vec(),
            },
            None => EstadoPrueba::Podado {
                huella: *huella,
                referencia,
            },
        }))
    }

    fn podar_hasta(&self, punto: Referencia) -> Result<u64, StorageError> {
        let cf = cf(&self.db, CF_PRUEBAS)?;
        let mut lote = WriteBatch::default();
        let mut podados: u64 = 0;
        for item in self
            .db
            .iterator_cf(cf, IteratorMode::From(PREFIJO_PRUEBA, Direction::Forward))
        {
            let (clave, valor) = item.map_err(backend)?;
            if !clave.starts_with(PREFIJO_PRUEBA) {
                break;
            }
            let (referencia, cuerpo) = pruebas::valor_desde_bytes(&valor)?;
            if referencia <= punto && cuerpo.is_some() {
                lote.put_cf(cf, &clave, pruebas::valor_a_bytes(referencia, None));
                podados += 1;
            }
        }
        if podados > 0 {
            let mut opciones = WriteOptions::default();
            opciones.set_sync(true);
            self.db.write_opt(lote, &opciones).map_err(backend)?;
        }
        Ok(podados)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{
        AlmacenEnDisco, CF_BLOQUES, CF_META, CF_REGISTRO, META_VERSION, VERSION_ESQUEMA,
        VERSION_ESQUEMA_LZ4, VERSION_ESQUEMA_ZSTD, cf,
    };
    use crate::almacen::{Almacen, BloqueAdmitido};
    use crate::error::StorageError;
    use crate::formato::{self, Familia};
    use crate::pruebas::{AlmacenPruebas, MAX_CUERPO_PRUEBA_BYTES};
    use zx_core::amount::Amount;
    use zx_core::body_commitment;
    use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot, TxId};
    use zx_core::firma::ClavePublica;
    use zx_core::preimage::block::{BlockHeader, merkle_root};
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_core::red::Red;
    use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
    use zx_core::txid;
    use zx_core::wire_dag::{
        BUNDLE_BYTES, BloqueDag, JustificacionPot, PotCheckpoints, bloque_dag_a_bytes,
    };

    /// Rama de consenso de la red dev, la que usan los fixtures.
    const CBID: u32 = zx_core::CBID_RED_DEV;

    fn genesis() -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([0x9a; 32]))
    }

    fn clave(n: u8) -> ClavePublica {
        ClavePublica::desde_bytes([n; 32])
    }

    /// La raíz de Merkle de los `txid` del cuerpo: lo que la cabecera debe declarar.
    fn raiz_de(txs: &[Tx]) -> MerkleRoot {
        let txids: Vec<TxId> = txs.iter().map(|t| txid(t, CBID)).collect();
        merkle_root(&txids)
    }

    fn cabecera_pow(nonce: u64, altura: u32, raiz: MerkleRoot) -> BlockHeader {
        BlockHeader {
            consensus_branch_id: CBID,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([(altura % 251) as u8; 32])),
            merkle_root: raiz,
            timestamp: 1_788_480_000 + nonce,
            bits: 0x1d00_ffff,
            nonce,
            height: altura,
        }
    }

    /// Bloque PoW de cuerpo vacío: `merkle_root(&[])` es lo que compromete la cabecera.
    fn bloque_pow(nonce: u64, altura: u32) -> BloqueAdmitido<'static> {
        BloqueAdmitido::pow(&cabecera_pow(nonce, altura, merkle_root(&[])), &[], &[])
    }

    /// Transacción de coinbase PoW (v1 sin entradas) con una salida de `brek`.
    fn tx_pow_coinbase(brek: i64) -> Tx {
        Tx {
            version: 1,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::nuevo(brek).expect("importe dentro de rango"),
                lock: Lock::PubKey {
                    pubkey: clave(0x09),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        }
    }

    /// Bloque PoW con una coinbase de `brek`; la cabecera compromete sus `txid`.
    fn bloque_pow_coinbase(nonce: u64, altura: u32, brek: i64) -> BloqueAdmitido<'static> {
        let txs = vec![tx_pow_coinbase(brek)];
        let testigos = vec![Vec::new()];
        let cabecera = cabecera_pow(nonce, altura, raiz_de(&txs));
        BloqueAdmitido::pow(&cabecera, &txs, &testigos)
    }

    fn cabecera_post(marca: u8, raiz: MerkleRoot, compromiso: BodyCommitment) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: CBID,
            merkle_root: raiz,
            timestamp: 1_788_480_000 + u64::from(marca),
            height: 0,
            slot: u64::from(marca),
            pot_output: [marca; 16],
            rango_solucion: u64::from(marca),
            sol: SolucionPoas::default(),
            body_commitment: compromiso,
            padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([0x07; 32])), &[])
                .expect("un padre seleccionado es canónico"),
            sello: [marca; 64],
        }
    }

    /// Bloque PoST con el cuerpo y los testigos dados; la cabecera compromete ambos.
    fn bloque_post_con(
        marca: u8,
        txs: Vec<Tx>,
        testigos: Vec<Vec<Vec<u8>>>,
    ) -> BloqueAdmitido<'static> {
        let raiz = raiz_de(&txs);
        let compromiso = body_commitment(&txs, &testigos, CBID).expect("tx y testigos cuadran");
        let justificacion =
            JustificacionPot::nueva(vec![PotCheckpoints::desde_bytes([marca; BUNDLE_BYTES])])
                .expect("un portador está dentro del máximo");
        let bloque = BloqueDag::nuevo(
            cabecera_post(marca, raiz, compromiso),
            justificacion,
            txs,
            testigos,
        )
        .expect("tx y testigos cuadran");
        BloqueAdmitido::post(&bloque)
    }

    /// Bloque PoST de cuerpo vacío.
    fn bloque_post(marca: u8) -> BloqueAdmitido<'static> {
        bloque_post_con(marca, Vec::new(), Vec::new())
    }

    /// Coinbase PoST v3: sin entradas ni salidas; `importe` y `slot` van en la extensión.
    fn tx_post_coinbase(brek: i64, slot: u64) -> Tx {
        Tx {
            version: 3,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::CoinbasePost {
                clave: clave(0x33),
                importe: Amount::nuevo(brek).expect("importe dentro de rango"),
                slot,
            },
        }
    }

    /// Transacción no coinbase (v1) con una entrada y una salida.
    fn tx_post_transferencia(marca: u8, brek: i64) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: OutPoint {
                    prev_txid: TxId::from_digest(Digest::from_bytes([marca; 32])),
                    prev_index: 0,
                },
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(brek).expect("importe dentro de rango"),
                lock: Lock::PubKey {
                    pubkey: clave(marca),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        }
    }

    /// Escribe un valor bajo la clave que ya existía: inyecta la corrupción saltándose `admitir`.
    fn reescribir_valor(a: &AlmacenEnDisco, hash: &BlockHash, valor: Vec<u8>) {
        let cf_bloques = cf(&a.db, CF_BLOQUES).expect("familia");
        a.db.put_cf(cf_bloques, hash.as_bytes(), valor)
            .expect("corrompe el valor guardado");
    }

    /// Decodifica el valor guardado de un bloque PoW.
    fn decodificar_pow(valor: &[u8]) -> (BlockHeader, Vec<Tx>, Vec<Vec<Vec<u8>>>) {
        let (familia, canonicos) = formato::separar(valor).expect("sobre");
        assert_eq!(familia, Familia::Pow);
        let (cuerpo, sobra) = zx_core::wire::cuerpo_desde_bytes(canonicos).expect("decodifica");
        assert!(sobra.is_empty(), "no debe sobrar nada");
        cuerpo
    }

    /// Decodifica el valor guardado de un bloque PoST.
    fn decodificar_post(valor: &[u8]) -> BloqueDag {
        let (familia, canonicos) = formato::separar(valor).expect("sobre");
        assert_eq!(familia, Familia::Post);
        let (bloque, sobra) =
            zx_core::wire_dag::bloque_dag_desde_bytes(canonicos).expect("decodifica");
        assert!(sobra.is_empty(), "no debe sobrar nada");
        bloque
    }

    /// Recodifica el cuerpo PoW dado bajo la misma cabecera para el sobre de `bloques`.
    fn valor_pow_con_cuerpo(
        cabecera: &BlockHeader,
        txs: &[Tx],
        testigos: &[Vec<Vec<u8>>],
    ) -> Vec<u8> {
        let mut canonicos = Vec::new();
        zx_core::wire::cuerpo_a_bytes(&mut canonicos, cabecera, txs, testigos);
        formato::bloque_a_bytes(Familia::Pow, &canonicos)
    }

    /// Recodifica el cuerpo PoST dado bajo la misma cabecera para el sobre de `bloques`.
    fn valor_post_con_cuerpo(
        base: &BloqueDag,
        txs: Vec<Tx>,
        testigos: Vec<Vec<Vec<u8>>>,
    ) -> Vec<u8> {
        let nuevo = BloqueDag::nuevo(base.cabecera, base.justificacion.clone(), txs, testigos)
            .expect("tx y testigos cuadran");
        let mut canonicos = Vec::new();
        bloque_dag_a_bytes(&mut canonicos, &nuevo);
        formato::bloque_a_bytes(Familia::Post, &canonicos)
    }

    #[test]
    fn admite_lee_repite_y_reapertura_conserva() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pow = bloque_pow(1, 0);
        let post = bloque_post(0x33);
        let (h_pow, h_post) = (pow.hash(), post.hash());

        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            assert_eq!(a.longitud_registro().expect("longitud"), 0);
            a.admitir(&pow, true).expect("admite pow");
            a.admitir(&post, true).expect("admite post");
            assert_eq!(a.admitir(&pow, true).expect("idempotente"), h_pow);
            assert_eq!(a.longitud_registro().expect("longitud"), 2);
            a.sincronizar().expect("sincroniza");
        }

        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("reabre");
        assert_eq!(
            a.bloque(&h_pow).expect("lee pow"),
            Some(pow.a_bytes_almacen())
        );
        assert_eq!(
            a.bloque(&h_post).expect("lee post"),
            Some(post.a_bytes_almacen())
        );
        let mut vistos: Vec<BlockHash> = Vec::new();
        a.repetir(&mut |h, valor| {
            let b = BloqueAdmitido::desde_almacen(valor).expect("el valor decodifica");
            assert_eq!(b.hash(), h);
            vistos.push(h);
            Ok::<(), ()>(())
        })
        .expect("repite");
        assert_eq!(vistos, vec![h_pow, h_post], "el orden es el del registro");
    }

    #[test]
    fn abrir_con_otra_red_no_reescribe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pow = bloque_pow(2, 0);
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre dev");
            a.admitir(&pow, true).expect("admite");
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Mainnet, genesis())
            .expect_err("otra red MUST fallar");
        assert!(matches!(
            err,
            StorageError::RedDistinta {
                encontrada: Red::Dev,
                pedida: Red::Mainnet
            }
        ));
        // Y reabrir con la red correcta sigue viendo el bloque: no se tocó nada.
        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("reabre dev");
        assert_eq!(a.longitud_registro().expect("longitud"), 1);
        assert_eq!(
            a.bloque(&pow.hash()).expect("lee"),
            Some(pow.a_bytes_almacen())
        );
    }

    #[test]
    fn abrir_con_otro_genesis_falla() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let _a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
        }
        let otro = BlockHash::from_digest(Digest::from_bytes([0x01; 32]));
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, otro)
            .expect_err("otro génesis MUST fallar");
        assert!(matches!(err, StorageError::GenesisDistinto { .. }));
    }

    #[test]
    fn bit_cambiado_en_un_bloque_es_corrupcion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pow = bloque_pow(3, 0);
        let hash = pow.hash();
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&pow, true).expect("admite");
            let cf_bloques = cf(&a.db, CF_BLOQUES).expect("familia");
            let mut valor =
                a.db.get_cf(cf_bloques, hash.as_bytes())
                    .expect("lee crudo")
                    .expect("existe");
            let ultimo = valor.last_mut().expect("no está vacío");
            *ultimo ^= 0x01;
            a.db.put_cf(cf_bloques, hash.as_bytes(), valor)
                .expect("corrompe");

            assert!(
                a.bloque(&hash).is_err(),
                "leer un bloque corrupto MUST ser error, no `None`"
            );
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("reabrir MUST detectar la corrupción");
        assert!(matches!(
            err,
            StorageError::Corrupto { .. } | StorageError::HashNoCoincide { .. }
        ));
    }

    #[test]
    fn entrada_borrada_del_registro_es_un_hueco() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            for i in 0..3u64 {
                a.admitir(&bloque_pow(i, i as u32), true).expect("admite");
            }
            let cf_registro = cf(&a.db, CF_REGISTRO).expect("familia");
            a.db.delete_cf(cf_registro, 1u64.to_be_bytes())
                .expect("borra la entrada 1");
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("el hueco MUST detectarse");
        assert!(matches!(
            err,
            StorageError::HuecoEnRegistro {
                esperado: 1,
                encontrado: 2
            }
        ));
    }

    #[test]
    fn version_de_esquema_desconocida_falla() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            let cf_meta = cf(&a.db, CF_META).expect("familia");
            a.db.put_cf(
                cf_meta,
                META_VERSION,
                VERSION_ESQUEMA.wrapping_add(1).to_be_bytes(),
            )
            .expect("reescribe la versión");
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("otra versión MUST fallar");
        assert!(matches!(
            err,
            StorageError::VersionEsquema {
                esperada: VERSION_ESQUEMA,
                ..
            }
        ));
    }

    #[test]
    fn datos_sin_marca_de_esquema_es_corrupcion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pow = bloque_pow(4, 0);
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&pow, true).expect("admite");
            let cf_meta = cf(&a.db, CF_META).expect("familia");
            a.db.delete_cf(cf_meta, META_VERSION)
                .expect("borra la marca");
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("sin marca y con datos MUST fallar");
        assert!(matches!(err, StorageError::Corrupto { .. }));
    }

    /// **Idempotencia bajo concurrencia.** La comprobación de duplicado va dentro del lock: ocho
    /// hilos que admiten el mismo bloque dejan **una** entrada, no ocho.
    #[test]
    fn admisiones_concurrentes_del_mismo_bloque_no_duplican() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().expect("tempdir");
        let a = Arc::new(AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre"));
        let pow = bloque_pow(5, 5);
        let hash = pow.hash();

        let mut hilos = Vec::new();
        for _ in 0..8 {
            let a = Arc::clone(&a);
            let pow = pow.clone();
            hilos.push(std::thread::spawn(move || {
                a.admitir(&pow, false).expect("admite");
            }));
        }
        for hilo in hilos {
            hilo.join().expect("el hilo no debe entrar en pánico");
        }

        assert_eq!(a.longitud_registro().expect("longitud"), 1);
        assert_eq!(a.bloque(&hash).expect("lee"), Some(pow.a_bytes_almacen()));
    }

    /// Admisiones concurrentes de bloques **distintos**: el registro queda contiguo y con todos.
    #[test]
    fn admisiones_concurrentes_de_bloques_distintos_son_contiguas() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().expect("tempdir");
        let a = Arc::new(AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre"));

        let mut hilos = Vec::new();
        for i in 0..8u64 {
            let a = Arc::clone(&a);
            hilos.push(std::thread::spawn(move || {
                a.admitir(&bloque_pow(i, u32::try_from(i).unwrap_or(0)), false)
                    .expect("admite");
            }));
        }
        for hilo in hilos {
            hilo.join().expect("el hilo no debe entrar en pánico");
        }

        assert_eq!(a.longitud_registro().expect("longitud"), 8);
        let mut contados = 0u64;
        a.repetir(&mut |_hash, _valor| {
            contados += 1;
            Ok::<(), ()>(())
        })
        .expect("la repetición no debe fallar");
        assert_eq!(contados, 8);
    }

    // ── V5 (Corrección A) · El compromiso del cuerpo se recalcula al abrir y al leer ─────────────
    //
    // Un bit cambiado **dentro del cuerpo** deja el `block_hash` intacto. Estos tests inyectan el
    // cuerpo alterado bajo la misma clave y exigen error explícito en la lectura y en la reapertura.

    /// **(a)** Importe cambiado en la coinbase de un bloque **PoW** ⇒ el `merkle_root` recalculado
    /// sobre los `txid` deja de cuadrar.
    #[test]
    fn importe_cambiado_en_coinbase_pow_es_cuerpo_no_coincide() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = bloque_pow_coinbase(0x11, 1, 1_000);
        let hash = base.hash();
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&base, true).expect("admite");
            let (cabecera, mut txs, testigos) = decodificar_pow(&base.a_bytes_almacen());
            txs.first_mut()
                .expect("hay coinbase")
                .outputs
                .first_mut()
                .expect("hay salida")
                .value = Amount::nuevo(1_001).expect("importe dentro de rango");
            reescribir_valor(&a, &hash, valor_pow_con_cuerpo(&cabecera, &txs, &testigos));
            assert!(
                matches!(a.bloque(&hash), Err(StorageError::CuerpoNoCoincide)),
                "leer un cuerpo cambiado MUST ser CuerpoNoCoincide"
            );
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("reabrir MUST detectar el cuerpo cambiado");
        assert!(matches!(err, StorageError::CuerpoNoCoincide));
    }

    /// **(b)** Importe cambiado en la coinbase **v3** de un bloque **PoST** ⇒ cambia el `txid` y el
    /// `body_commitment` recalculado deja de cuadrar.
    #[test]
    fn importe_cambiado_en_coinbase_v3_post_es_cuerpo_no_coincide() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = bloque_post_con(0x22, vec![tx_post_coinbase(1_000, 7)], vec![Vec::new()]);
        let hash = base.hash();
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&base, true).expect("admite");
            let guardado = decodificar_post(&base.a_bytes_almacen());
            let testigos = guardado.testigos().to_vec();
            let txs = vec![tx_post_coinbase(1_001, 7)];
            reescribir_valor(&a, &hash, valor_post_con_cuerpo(&guardado, txs, testigos));
            assert!(
                matches!(a.bloque(&hash), Err(StorageError::CuerpoNoCoincide)),
                "leer un cuerpo cambiado MUST ser CuerpoNoCoincide"
            );
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("reabrir MUST detectar el cuerpo cambiado");
        assert!(matches!(err, StorageError::CuerpoNoCoincide));
    }

    /// **(c)** Un campo (importe de salida) cambiado en una transacción **no coinbase** de un
    /// bloque PoST ⇒ error explícito.
    #[test]
    fn campo_cambiado_en_tx_no_coinbase_post_es_cuerpo_no_coincide() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = bloque_post_con(
            0x33,
            vec![tx_post_coinbase(1_000, 7), tx_post_transferencia(0x40, 500)],
            vec![Vec::new(), Vec::new()],
        );
        let hash = base.hash();
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&base, true).expect("admite");
            let guardado = decodificar_post(&base.a_bytes_almacen());
            let testigos = guardado.testigos().to_vec();
            let txs = vec![tx_post_coinbase(1_000, 7), tx_post_transferencia(0x40, 501)];
            reescribir_valor(&a, &hash, valor_post_con_cuerpo(&guardado, txs, testigos));
            assert!(
                matches!(a.bloque(&hash), Err(StorageError::CuerpoNoCoincide)),
                "leer un cuerpo cambiado MUST ser CuerpoNoCoincide"
            );
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("reabrir MUST detectar el cuerpo cambiado");
        assert!(matches!(err, StorageError::CuerpoNoCoincide));
    }

    /// **(d)** Un testigo cambiado en un bloque **PoST** ⇒ error explícito: `body_commitment` liga
    /// `(txid, auth_digest)`.
    #[test]
    fn testigo_cambiado_en_post_es_cuerpo_no_coincide() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = bloque_post_con(
            0x44,
            vec![tx_post_coinbase(1_000, 7)],
            vec![vec![vec![0xAA; 64]]],
        );
        let hash = base.hash();
        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&base, true).expect("admite");
            let guardado = decodificar_post(&base.a_bytes_almacen());
            let txs = guardado.txs().to_vec();
            let testigos = vec![vec![vec![0xAB; 64]]];
            reescribir_valor(&a, &hash, valor_post_con_cuerpo(&guardado, txs, testigos));
            assert!(
                matches!(a.bloque(&hash), Err(StorageError::CuerpoNoCoincide)),
                "leer un testigo cambiado MUST ser CuerpoNoCoincide"
            );
        }
        let err = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect_err("reabrir MUST detectar el testigo cambiado");
        assert!(matches!(err, StorageError::CuerpoNoCoincide));
    }

    /// **(e)** Un testigo cambiado en un bloque **PoW** **no** está comprometido: `merkle_root` solo
    /// cubre los `txid`, y el `txid` excluye los testigos (C-TX-01). El almacén **no** puede
    /// detectarlo y lo acepta; quien lo detecta es la **verificación de firmas del motor al
    /// re-aplicar** la transacción en la repetición (D-N03′). Este test fija el comportamiento real
    /// en vez de fingir una detección inexistente.
    #[test]
    fn testigo_cambiado_en_pow_no_lo_detecta_el_almacen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let txs = vec![tx_pow_coinbase(1_000)];
        let testigos = vec![vec![vec![0xAA; 64]]];
        let cabecera = cabecera_pow(0x55, 1, raiz_de(&txs));
        let base = BloqueAdmitido::pow(&cabecera, &txs, &testigos);
        let hash = base.hash();

        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&base, true).expect("admite");

            let (cabecera_leida, txs_leidas, _testigos_leidos) =
                decodificar_pow(&base.a_bytes_almacen());
            let testigos_alterados = vec![vec![vec![0xAB; 64]]];

            // Contraste: un compromiso sobre `(txid, auth_digest)` —el que PoST sí lleva en su
            // cabecera y PoW no— **sí** distinguiría el testigo cambiado. No hay tal campo en la
            // cabecera PoW, así que el almacén no puede compararlo.
            assert_ne!(
                body_commitment(&txs_leidas, &testigos, CBID).expect("tx y testigos cuadran"),
                body_commitment(&txs_leidas, &testigos_alterados, CBID)
                    .expect("tx y testigos cuadran"),
                "el auth_digest del testigo cambiado es distinto"
            );

            reescribir_valor(
                &a,
                &hash,
                valor_pow_con_cuerpo(&cabecera_leida, &txs_leidas, &testigos_alterados),
            );

            // El almacén acepta: el `block_hash` y el `merkle_root` no cambian con el testigo.
            let leido = a
                .bloque(&hash)
                .expect("el almacén no detecta el testigo PoW; lo hará el motor al re-aplicar");
            assert!(leido.is_some(), "el bloque sigue guardado bajo su clave");
        }

        // Reabrir tampoco lo detecta: la integridad del almacén no cubre los testigos PoW.
        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis())
            .expect("reabrir no debe fallar por un testigo PoW");
        assert_eq!(
            a.longitud_registro().expect("longitud"),
            1,
            "la entrada del registro sigue siendo exacta"
        );
        let mut vistos = 0u64;
        a.repetir(&mut |_hash, _valor| {
            vistos += 1;
            Ok::<(), ()>(())
        })
        .expect("la repetición entrega el bloque; el motor lo rechazará al verificar la firma");
        assert_eq!(vistos, 1);
    }

    /// **(ZC-2)** Un almacén de la versión 1 se **migra solo** al abrirlo: la
    /// compactación reescribe las tablas con zstd y `meta` sube a la versión 3,
    /// sin intervención y sin perder el contenido.
    #[test]
    fn un_almacen_v1_se_migra_solo_al_abrirlo() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pow = bloque_pow(0x77, 0);
        let post = bloque_post(0x78);
        let (h_pow, h_post) = (pow.hash(), post.hash());

        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&pow, true).expect("admite pow");
            a.admitir(&post, true).expect("admite post");
            // Simula el almacén viejo: la marca de esquema en 1.
            let cf_meta = cf(&a.db, CF_META).expect("familia");
            a.db.put_cf(cf_meta, META_VERSION, VERSION_ESQUEMA_LZ4.to_be_bytes())
                .expect("versión 1");
        }

        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("migra y abre");
        assert_eq!(
            a.bloque(&h_pow).expect("lee pow"),
            Some(pow.a_bytes_almacen())
        );
        assert_eq!(
            a.bloque(&h_post).expect("lee post"),
            Some(post.a_bytes_almacen())
        );
        let cf_meta = cf(&a.db, CF_META).expect("familia");
        assert_eq!(
            a.db.get_cf(cf_meta, META_VERSION)
                .expect("lee versión")
                .expect("existe"),
            VERSION_ESQUEMA.to_be_bytes(),
            "la migración fija la versión 3"
        );

        // Reabrir otra vez es idempotente: ya no hay nada que migrar.
        drop(a);
        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("reabre");
        assert_eq!(
            a.bloque(&h_pow).expect("lee pow"),
            Some(pow.a_bytes_almacen())
        );
    }

    // ── CP-C5a · familia `pruebas` (retención y poda) ────────────────────────────────────────

    /// **(C5a)** Un almacén de la versión 2 (zstd sin `pruebas`) se migra solo al abrirlo,
    /// conserva los bloques y el contenido de la familia `pruebas`, y fija la versión 3.
    #[test]
    fn un_almacen_v2_se_migra_solo_al_abrirlo_y_conserva_la_familia_pruebas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pow = bloque_pow(0x7a, 0);
        let h_pow = pow.hash();
        let huella = [0x5A; 32];

        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.admitir(&pow, true).expect("admite pow");
            a.guardar(huella, 4, b"cuerpo").expect("guarda prueba");
            // Simula el almacén de la versión 2: zstd, pero sin la familia `pruebas`.
            let cf_meta = cf(&a.db, CF_META).expect("familia");
            a.db.put_cf(cf_meta, META_VERSION, VERSION_ESQUEMA_ZSTD.to_be_bytes())
                .expect("versión 2");
        }

        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("migra y abre");
        let cf_meta = cf(&a.db, CF_META).expect("familia");
        assert_eq!(
            a.db.get_cf(cf_meta, META_VERSION)
                .expect("lee versión")
                .expect("existe"),
            VERSION_ESQUEMA.to_be_bytes(),
            "la migración fija la versión 3"
        );
        assert_eq!(
            a.bloque(&h_pow).expect("lee pow"),
            Some(pow.a_bytes_almacen()),
            "los bloques sobreviven a la migración"
        );
        let estado = a.obtener(&huella).expect("obtiene").expect("existe");
        assert_eq!(
            estado.cuerpo(),
            Some(b"cuerpo".as_slice()),
            "la familia `pruebas` sobrevive a la migración"
        );
    }

    /// **(C5a)** Tras podar y reabrir, la huella y el metadato siguen ahí y el cuerpo no vuelve.
    #[test]
    fn reabrir_conserva_lo_podado_con_huella_y_metadato() {
        let dir = tempfile::tempdir().expect("tempdir");
        let huella = [0x6B; 32];

        {
            let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
            a.guardar(huella, 9, b"cuerpo").expect("guarda");
            assert_eq!(a.podar_hasta(9).expect("poda"), 1);
            a.sincronizar().expect("sincroniza");
        }

        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("reabre");
        let estado = a.obtener(&huella).expect("obtiene").expect("existe");
        assert!(estado.esta_podado(), "tras reabrir sigue podado");
        assert_eq!(estado.huella(), huella, "conserva la huella");
        assert_eq!(estado.referencia(), 9, "conserva el metadato");
        assert_eq!(estado.cuerpo(), None, "el cuerpo no vuelve");
    }

    /// **(C5a)** Podar la familia `pruebas` no toca `bloques` ni `registro`.
    #[test]
    fn podar_no_toca_las_otras_familias() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pow = bloque_pow(0x7b, 0);
        let h_pow = pow.hash();
        let huella = [0x7C; 32];

        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
        a.admitir(&pow, true).expect("admite pow");
        a.guardar(huella, 3, b"cuerpo").expect("guarda prueba");
        assert_eq!(a.longitud_registro().expect("longitud"), 1);

        assert_eq!(a.podar_hasta(3).expect("poda"), 1);

        assert_eq!(a.longitud_registro().expect("longitud"), 1);
        assert_eq!(
            a.bloque(&h_pow).expect("lee pow"),
            Some(pow.a_bytes_almacen()),
            "el bloque no cambia"
        );
        let mut vistos = 0u64;
        a.repetir(&mut |_hash, _valor| {
            vistos += 1;
            Ok::<(), ()>(())
        })
        .expect("repite");
        assert_eq!(vistos, 1, "el registro sigue con su única entrada");
        assert!(
            a.obtener(&huella)
                .expect("obtiene")
                .expect("existe")
                .esta_podado(),
            "y la prueba sí quedó podada"
        );
    }

    /// **(C5a)** El tope de tamaño también se aplica en disco y no deja entrada.
    #[test]
    fn un_cuerpo_mayor_que_el_tope_se_rechaza_en_disco() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
        let grande = vec![0xAB; MAX_CUERPO_PRUEBA_BYTES + 1];
        let err = a
            .guardar([0x8D; 32], 1, &grande)
            .expect_err("un cuerpo por encima del tope MUST rechazarse");
        assert!(matches!(err, StorageError::CuerpoDemasiadoGrande { .. }));
        assert_eq!(a.obtener(&[0x8D; 32]).expect("obtiene"), None);
    }

    /// **(C5a)** Diferencial: la memoria y el disco responden igual en la familia `pruebas`.
    #[test]
    fn memoria_y_disco_coinciden_en_pruebas() {
        use crate::memoria::AlmacenEnMemoria;

        let dir = tempfile::tempdir().expect("tempdir");
        let memoria = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
        let disco = AlmacenEnDisco::abrir(dir.path(), Red::Dev, genesis()).expect("abre");
        let datos: [([u8; 32], u64, &[u8]); 3] = [
            ([0x01; 32], 5, b"a"),
            ([0x02; 32], 9, b"bb"),
            ([0x03; 32], 1, b"ccc"),
        ];
        for (huella, referencia, cuerpo) in datos {
            memoria
                .guardar(huella, referencia, cuerpo)
                .expect("memoria guarda");
            disco
                .guardar(huella, referencia, cuerpo)
                .expect("disco guarda");
        }
        assert_eq!(memoria.podar_hasta(5).expect("memoria poda"), 2);
        assert_eq!(disco.podar_hasta(5).expect("disco poda"), 2);
        for (huella, _referencia, _cuerpo) in datos {
            assert_eq!(
                memoria.obtener(&huella).expect("memoria obtiene"),
                disco.obtener(&huella).expect("disco obtiene"),
                "los dos backends deben coincidir"
            );
        }
    }
}
