//! Compendio de bloques admitidos (`ORDEN-W07d` decisión 1).
//!
//! `compendio_bloques` es un identificador de conjunto: `SHA3-256` de la concatenación de los
//! hashes de **todos** los bloques admitidos (PoW y PoST), ordenados por bytes. Sirve para comparar
//! el conjunto de bloques de dos nodos (o de dos aperturas) sin depender del orden de admisión, que
//! en una red real no coincide entre nodos. No es un hash de consenso: es un instrumento de
//! diagnóstico del registro.
//!
//! La orden no fija la codificación exacta; la falta de definición 2 de `FALTAS-DE-DEFINICION.md`
//! adopta el hash en bruto (32 bytes, `BlockHash::as_bytes()`) y el resultado en hexadecimal
//! minúsculo de 64 caracteres, igual que el resto del registro.

use zx_core::digest::BlockHash;
use zx_core::sha3_256_publico;
use zx_storage::{Almacen, ErrorRepeticion, StorageError};

/// `SHA3-256` de la concatenación de `hashes` ordenados por bytes.
///
/// El orden lexicográfico de bytes (`BlockHash` deriva `Ord` sobre `[u8; 32]`) hace el compendio
/// independiente del orden de admisión: la propiedad que exige la orden.
#[must_use]
pub fn compendio_de_hashes(hashes: &[BlockHash]) -> String {
    let mut ordenados: Vec<BlockHash> = hashes.to_vec();
    ordenados.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut bytes = Vec::with_capacity(ordenados.len() * 32);
    for hash in &ordenados {
        bytes.extend_from_slice(hash.as_bytes());
    }
    sha3_256_publico(&bytes).to_string()
}

/// Reúne todos los hashes admitidos del almacén y devuelve su compendio.
///
/// # Errores
/// El error de E/S del almacén al recorrer su registro ([`StorageError`]).
pub fn compendio_de_almacen<A: Almacen>(almacen: &A) -> Result<String, StorageError> {
    let mut hashes: Vec<BlockHash> = Vec::new();
    let resultado: Result<(), ErrorRepeticion<std::convert::Infallible>> =
        almacen.repetir(&mut |hash, _valor| {
            hashes.push(hash);
            Ok(())
        });
    match resultado {
        Ok(()) => Ok(compendio_de_hashes(&hashes)),
        Err(ErrorRepeticion::Almacen(e)) => Err(e),
        // `Infallible` no tiene valores: el destino de esta repetición no puede fallar.
        Err(ErrorRepeticion::Destino(imposible)) => match imposible {},
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
    use super::{compendio_de_almacen, compendio_de_hashes};
    use zx_core::digest::{BlockHash, Digest};
    use zx_core::preimage::block::{BlockHeader, merkle_root};
    use zx_core::red::Red;
    use zx_storage::{Almacen, AlmacenEnMemoria, BloqueAdmitido};

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
    fn el_compendio_no_depende_del_orden_de_los_hashes() {
        let a = bloque(0).hash();
        let b = bloque(1).hash();
        let c = bloque(2).hash();
        let directo = compendio_de_hashes(&[a, b, c]);
        assert_eq!(directo, compendio_de_hashes(&[c, b, a]));
        assert_eq!(directo, compendio_de_hashes(&[b, c, a]));
    }

    #[test]
    fn el_compendio_cambia_si_cambia_el_conjunto() {
        let a = bloque(0).hash();
        let b = bloque(1).hash();
        assert_ne!(
            compendio_de_hashes(&[a, b]),
            compendio_de_hashes(&[a, b, bloque(2).hash()])
        );
    }

    #[test]
    fn dos_almacenes_con_el_mismo_conjunto_en_orden_distinto_coinciden() {
        let b0 = bloque(0);
        let b1 = bloque(1);
        let b2 = bloque(2);

        let en_orden = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
        en_orden.admitir(&b0, true).unwrap();
        en_orden.admitir(&b1, true).unwrap();
        en_orden.admitir(&b2, true).unwrap();

        let invertido = AlmacenEnMemoria::nuevo(Red::Dev, genesis());
        invertido.admitir(&b2, true).unwrap();
        invertido.admitir(&b0, true).unwrap();
        invertido.admitir(&b1, true).unwrap();

        assert_eq!(
            compendio_de_almacen(&en_orden).unwrap(),
            compendio_de_almacen(&invertido).unwrap()
        );
    }
}
