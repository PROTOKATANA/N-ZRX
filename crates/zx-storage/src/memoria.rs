//! Almacén en memoria: la implementación de referencia.
//!
//! No es un juguete. Es la referencia simple y evidentemente correcta contra la que se contrasta el
//! backend de RocksDB con un test diferencial. Es la misma idea que el verificador CPU frente al
//! kernel de GPU: sin una referencia, «RocksDB funciona» no tiene contra qué compararse.

use std::collections::HashMap;
use std::sync::RwLock;

use zx_core::digest::BlockHash;
use zx_core::red::Red;

use crate::almacen::{Almacen, BloqueAdmitido, ErrorRepeticion};
use crate::error::StorageError;
use crate::pruebas::{AlmacenPruebas, AlmacenPruebasEnMemoria, EstadoPrueba, Huella, Referencia};

/// Almacén en RAM.
#[derive(Debug)]
pub struct AlmacenEnMemoria {
    red: Red,
    genesis: BlockHash,
    interior: RwLock<Interior>,
    /// La familia de cuerpos de pruebas, con su propia referencia en RAM.
    pruebas: AlmacenPruebasEnMemoria,
}

#[derive(Debug, Default)]
struct Interior {
    /// Valor guardado por hash: `familia(1) ‖ canónicos`.
    bloques: HashMap<BlockHash, Vec<u8>>,
    /// Orden de admisión. Contiguo desde `0`.
    registro: Vec<BlockHash>,
}

/// Un lock envenenado significa que otro hilo entró en pánico mientras lo tenía.
///
/// Se traduce a error en vez de propagar el pánico: el workspace prohíbe `panic` en producción, y
/// un almacén que revienta porque otro hilo reventó convierte un fallo local en una caída total.
fn envenenado() -> StorageError {
    StorageError::Backend("lock envenenado: otro hilo entró en pánico".to_owned())
}

impl AlmacenEnMemoria {
    /// Uno vacío para la red y el génesis dados.
    #[must_use]
    pub fn nuevo(red: Red, genesis: BlockHash) -> Self {
        Self {
            red,
            genesis,
            interior: RwLock::new(Interior::default()),
            pruebas: AlmacenPruebasEnMemoria::nuevo(),
        }
    }
}

impl AlmacenPruebas for AlmacenEnMemoria {
    fn guardar(
        &self,
        huella: Huella,
        referencia: Referencia,
        cuerpo: &[u8],
    ) -> Result<(), StorageError> {
        self.pruebas.guardar(huella, referencia, cuerpo)
    }

    fn obtener(&self, huella: &Huella) -> Result<Option<EstadoPrueba>, StorageError> {
        self.pruebas.obtener(huella)
    }

    fn podar_hasta(&self, punto: Referencia) -> Result<u64, StorageError> {
        self.pruebas.podar_hasta(punto)
    }
}

impl Almacen for AlmacenEnMemoria {
    fn red(&self) -> Red {
        self.red
    }

    fn genesis(&self) -> BlockHash {
        self.genesis
    }

    fn admitir(&self, bloque: &BloqueAdmitido<'_>, _sync: bool) -> Result<BlockHash, StorageError> {
        let hash = bloque.hash();
        let valor = bloque.a_bytes_almacen();
        let mut i = self.interior.write().map_err(|_| envenenado())?;

        // Idempotencia: el mismo hash no añade una segunda entrada al registro. Pero si los bytes
        // guardados no son los mismos, algo se corrompió y se denuncia en vez de aceptarlo.
        if let Some(existente) = i.bloques.get(&hash) {
            if existente != &valor {
                return Err(StorageError::Corrupto {
                    que: "dos admisiones del mismo hash con bytes distintos",
                });
            }
            return Ok(hash);
        }

        i.bloques.insert(hash, valor);
        i.registro.push(hash);
        Ok(hash)
    }

    fn bloque(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StorageError> {
        let i = self.interior.read().map_err(|_| envenenado())?;
        Ok(i.bloques.get(hash).cloned())
    }

    fn repetir<E>(
        &self,
        destino: &mut impl FnMut(BlockHash, &[u8]) -> Result<(), E>,
    ) -> Result<(), ErrorRepeticion<E>> {
        // Se copia solo la lista de hashes (32 B cada uno) para no retener el lock durante la
        // llamada al destino: si el destino volviera a entrar al almacén, un lock retenido sería un
        // interbloqueo.
        let hashes: Vec<BlockHash> = {
            let i = self
                .interior
                .read()
                .map_err(|_| envenenado())
                .map_err(ErrorRepeticion::Almacen)?;
            i.registro.clone()
        };

        for (indice, hash) in hashes.into_iter().enumerate() {
            let valor = {
                let i = self
                    .interior
                    .read()
                    .map_err(|_| envenenado())
                    .map_err(ErrorRepeticion::Almacen)?;
                i.bloques.get(&hash).cloned()
            };
            let indice = u64::try_from(indice).map_err(|_| {
                ErrorRepeticion::Almacen(StorageError::Backend(
                    "el registro en memoria no cabe en u64".to_owned(),
                ))
            })?;
            let valor = valor.ok_or(ErrorRepeticion::Almacen(StorageError::EntradaSinBloque {
                indice,
            }))?;
            destino(hash, &valor).map_err(ErrorRepeticion::Destino)?;
        }
        Ok(())
    }

    fn longitud_registro(&self) -> Result<u64, StorageError> {
        let i = self.interior.read().map_err(|_| envenenado())?;
        u64::try_from(i.registro.len())
            .map_err(|_| StorageError::Backend("el registro en memoria no cabe en u64".to_owned()))
    }

    fn sincronizar(&self) -> Result<(), StorageError> {
        // En RAM no hay nada que sincronizar. No es un no-op vacío: documenta que el contrato se
        // cumple trivialmente en vez de dejar a quien lea preguntándose si falta algo.
        Ok(())
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
    use super::AlmacenEnMemoria;
    use crate::almacen::{Almacen, BloqueAdmitido};
    use zx_core::digest::{BlockHash, Digest};
    use zx_core::preimage::block::{BlockHeader, merkle_root};
    use zx_core::red::Red;

    fn genesis() -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([0; 32]))
    }

    fn cabecera(nonce: u64) -> BlockHeader {
        BlockHeader {
            consensus_branch_id: zx_core::CBID_RED_DEV,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([0x11; 32])),
            merkle_root: merkle_root(&[]),
            timestamp: 1_788_480_000 + nonce,
            bits: 0x1d00_ffff,
            nonce,
            height: 1,
        }
    }

    fn bloque(nonce: u64) -> BloqueAdmitido<'static> {
        BloqueAdmitido::pow(&cabecera(nonce), &[], &[])
    }

    #[test]
    fn admite_lee_y_repite_en_orden() {
        let a = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
        let b0 = bloque(0);
        let b1 = bloque(1);
        let (h0, h1) = (b0.hash(), b1.hash());
        a.admitir(&b0, true).unwrap();
        a.admitir(&b1, true).unwrap();

        assert_eq!(a.bloque(&h0).unwrap(), Some(b0.a_bytes_almacen()));
        assert_eq!(a.longitud_registro().unwrap(), 2);

        let mut vistos: Vec<(BlockHash, Vec<u8>)> = Vec::new();
        a.repetir(&mut |h, b| {
            vistos.push((h, b.to_vec()));
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(vistos.len(), 2);
        assert_eq!(vistos.first().map(|p| p.0), Some(h0));
        assert_eq!(vistos.get(1).map(|p| p.0), Some(h1));
        assert_eq!(
            vistos.first().map(|p| p.1.clone()),
            Some(b0.a_bytes_almacen())
        );
    }

    #[test]
    fn admitir_dos_veces_es_idempotente() {
        let a = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
        let b = bloque(7);
        assert_eq!(a.admitir(&b, true).unwrap(), b.hash());
        assert_eq!(a.admitir(&b, false).unwrap(), b.hash());
        assert_eq!(a.longitud_registro().unwrap(), 1);
    }

    #[test]
    fn el_destino_detiene_la_repeticion() {
        let a = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
        for i in 0..3 {
            a.admitir(&bloque(i), true).unwrap();
        }
        let mut contados = 0u32;
        let r = a.repetir(&mut |_h, _b| {
            contados += 1;
            if contados == 2 {
                return Err("alto");
            }
            Ok(())
        });
        assert_eq!(r, Err(crate::almacen::ErrorRepeticion::Destino("alto")));
        assert_eq!(contados, 2);
    }
}
