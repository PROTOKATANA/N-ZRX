//! Almacén en disco sobre RocksDB, tras la misma interfaz [`Almacen`] que el de memoria.
//!
//! Misma versión y opciones base que `crates/zx-storage` (`rocksdb = "=0.25.0"`, `create_if_missing`,
//! `create_missing_column_families`, `set_wal_recovery_mode(PointInTime)`, `set_wal_compression_type`
//! y compresión `Zstd` por familia). Tres familias de columnas:
//!
//! - `nodos`: `hash(32) → nodo`;
//! - `hojas`: `familia(1) ‖ clave → h_valor(32)` (índice para reconstruir y oráculo);
//! - `meta`: `familia(1) → raíz(32)`.
//!
//! El modo frío (para el banco del bloque 0) activa `set_use_direct_reads(true)` y una caché de
//! bloques mínima de 1 MiB; el caliente usa la caché por defecto.

use std::path::Path;

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompressionType, DBRecoveryMode,
    IteratorMode, Options, WriteBatch,
};

use crate::almacen::{Almacen, Nodos};
use crate::error::Error;
use crate::hash::{Hash32, hash_vacio};

/// Familia de columnas de los nodos del trie.
pub const CF_NODOS: &str = "nodos";
/// Familia de columnas del índice de hojas.
pub const CF_HOJAS: &str = "hojas";
/// Familia de columnas de las raíces por familia.
pub const CF_META: &str = "meta";

/// Almacén del árbol sobre RocksDB.
pub struct AlmacenRocks {
    db: DB,
}

impl AlmacenRocks {
    /// Abre o crea el almacén. `frio` activa lecturas directas y caché mínima.
    ///
    /// # Errors
    /// Si RocksDB no puede abrir o crear el directorio y sus familias.
    pub fn abrir(ruta: &Path, frio: bool) -> Result<Self, Error> {
        let mut opciones = Options::default();
        opciones.create_if_missing(true);
        opciones.create_missing_column_families(true);
        opciones.set_wal_recovery_mode(DBRecoveryMode::PointInTime);
        opciones.set_wal_compression_type(DBCompressionType::Zstd);

        let cache = if frio {
            Some(Cache::new_lru_cache(1024 * 1024))
        } else {
            None
        };
        if let Some(c) = &cache {
            let mut bbt = BlockBasedOptions::default();
            bbt.set_block_cache(c);
            opciones.set_block_based_table_factory(&bbt);
        }
        if frio {
            opciones.set_use_direct_reads(true);
        }

        let familias = [CF_NODOS, CF_HOJAS, CF_META]
            .into_iter()
            .map(|nombre| {
                let mut o = Options::default();
                o.set_compression_type(DBCompressionType::Zstd);
                if let Some(c) = &cache {
                    let mut bbt = BlockBasedOptions::default();
                    bbt.set_block_cache(c);
                    o.set_block_based_table_factory(&bbt);
                }
                ColumnFamilyDescriptor::new(nombre, o)
            })
            .collect::<Vec<_>>();

        let db = DB::open_cf_descriptors(&opciones, ruta, familias)?;
        Ok(Self { db })
    }

    /// Vuelca las memtables a SST.
    ///
    /// # Errors
    /// Si RocksDB no puede volcar.
    pub fn volcar(&self) -> Result<(), Error> {
        self.db.flush()?;
        Ok(())
    }

    /// Cierra el almacén.
    ///
    /// # Errors
    /// Si RocksDB no puede volcar al cerrar.
    pub fn cerrar(self) -> Result<(), Error> {
        self.db.flush()?;
        Ok(())
    }

    fn cf(&self, nombre: &'static str) -> Result<&rocksdb::ColumnFamily, Error> {
        self.db
            .cf_handle(nombre)
            .ok_or(Error::ColumnFamilyAusente(nombre))
    }

    /// `true` si el almacén no tiene ninguna hoja.
    ///
    /// # Errors
    /// Si RocksDB no puede leer.
    pub fn esta_vacio(&self) -> Result<bool, Error> {
        Ok(self.listar_hojas()?.is_empty())
    }
}

impl Nodos for AlmacenRocks {
    fn leer(&self, h: &Hash32) -> Result<Option<Vec<u8>>, Error> {
        let cf = self.cf(CF_NODOS)?;
        Ok(self.db.get_cf(cf, h)?)
    }

    fn poner(&mut self, h: Hash32, v: Vec<u8>) -> Result<(), Error> {
        let cf = self.cf(CF_NODOS)?;
        self.db.put_cf(cf, h, v)?;
        Ok(())
    }

    fn quitar(&mut self, h: Hash32) -> Result<(), Error> {
        let cf = self.cf(CF_NODOS)?;
        self.db.delete_cf(cf, h)?;
        Ok(())
    }
}

impl Almacen for AlmacenRocks {
    fn hoja(&self, familia: u8, clave: &[u8]) -> Result<Option<Hash32>, Error> {
        let cf = self.cf(CF_HOJAS)?;
        let mut k = Vec::with_capacity(1 + clave.len());
        k.push(familia);
        k.extend_from_slice(clave);
        match self.db.get_cf(cf, &k)? {
            Some(v) => Ok(v.get(..32).and_then(|s| s.try_into().ok())),
            None => Ok(None),
        }
    }

    fn raiz(&self, familia: u8) -> Result<Hash32, Error> {
        let cf = self.cf(CF_META)?;
        match self.db.get_cf(cf, [familia])? {
            Some(v) => v
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::NodoMalFormado),
            None => Ok(hash_vacio()),
        }
    }

    fn raices(&self) -> Result<Vec<(u8, Hash32)>, Error> {
        let cf = self.cf(CF_META)?;
        let mut salida = Vec::new();
        for item in self.db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item?;
            let Some((&familia, _)) = k.split_first() else {
                continue;
            };
            if let Some(h) = v.get(..32).and_then(|s| s.try_into().ok()) {
                salida.push((familia, h));
            }
        }
        Ok(salida)
    }

    fn listar_hojas(&self) -> Result<Vec<(u8, Vec<u8>, Hash32)>, Error> {
        let cf = self.cf(CF_HOJAS)?;
        let mut salida = Vec::new();
        for item in self.db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = item?;
            let Some((&familia, clave)) = k.split_first() else {
                continue;
            };
            if let Some(h) = v.get(..32).and_then(|s| s.try_into().ok()) {
                salida.push((familia, clave.to_vec(), h));
            }
        }
        Ok(salida)
    }

    fn commit(
        &mut self,
        nodos: &[(Hash32, Option<Vec<u8>>)],
        hojas: &[(u8, Vec<u8>, Option<Hash32>)],
        raices: &[(u8, Hash32)],
    ) -> Result<(), Error> {
        let cf_nodos = self.cf(CF_NODOS)?;
        let cf_hojas = self.cf(CF_HOJAS)?;
        let cf_meta = self.cf(CF_META)?;
        let mut lote = WriteBatch::default();
        for (h, v) in nodos {
            match v {
                Some(bytes) => lote.put_cf(cf_nodos, h, bytes),
                None => lote.delete_cf(cf_nodos, h),
            }
        }
        for (familia, clave, v) in hojas {
            let mut k = Vec::with_capacity(1 + clave.len());
            k.push(*familia);
            k.extend_from_slice(clave);
            match v {
                Some(h) => lote.put_cf(cf_hojas, k, h),
                None => lote.delete_cf(cf_hojas, k),
            }
        }
        for (familia, r) in raices {
            lote.put_cf(cf_meta, [*familia], r);
        }
        let mut wo = rocksdb::WriteOptions::default();
        wo.set_sync(true);
        self.db.write_opt(lote, &wo)?;
        Ok(())
    }

    fn sincronizar(&mut self) -> Result<(), Error> {
        self.db.flush()?;
        Ok(())
    }
}
