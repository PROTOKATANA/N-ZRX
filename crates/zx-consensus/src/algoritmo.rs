//! Interfaz del algoritmo de prueba de trabajo.
//!
//! `C-HDR-03` fija `block_hash = SHA3-256("ZZKBlkHeader____" ‖ cabecera)`; eso **no cambia**. Lo que
//! esta interfaz separa es el hash que se compara con el target (`hash_pow`), para que un algoritmo
//! de producción distinto pueda entrar sin tocar la cabecera ni su identificador.
//!
//! ⚠️ **Parámetro de desarrollo**: el algoritmo de producción está abierto (**IPA A-12**). SHA3-256
//! se usa aquí porque es el `block_hash` heredado y porque permite un minero local honesto; **no**
//! se afirma que sea el algoritmo final.

use zx_core::preimage::block::BlockHeader;

/// Algoritmo de prueba de trabajo.
///
/// El contrato es mínimo a propósito: dado un cabecera, devolver 32 bytes que se interpretan
/// **big-endian** y se comparan estrictamente con el target (`C-POW-01`).
pub trait AlgoritmoPow {
    /// Hash que se compara con el target. **MUST** ser determinista y no depender de estado externo.
    fn hash_pow(&self, cabecera: &BlockHeader) -> [u8; 32];
}

/// Implementación dev: `hash_pow` es exactamente el `block_hash` antiguo
/// (`SHA3-256("ZZKBlkHeader____" ‖ cabecera)`, F-01).
///
/// ⚠️ Parámetro de desarrollo; el algoritmo de producción está abierto (IPA A-12).
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha3Dev;

impl AlgoritmoPow for Sha3Dev {
    fn hash_pow(&self, cabecera: &BlockHeader) -> [u8; 32] {
        *cabecera.block_hash().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{AlgoritmoPow, Sha3Dev};
    use zx_core::preimage::block::BlockHeader;
    use zx_core::{BlockHash, Digest, MerkleRoot};

    fn cabecera() -> BlockHeader {
        BlockHeader {
            consensus_branch_id: zx_core::CBID_RED_DEV,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([1u8; 32])),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([2u8; 32])),
            timestamp: 1_790_380_800,
            bits: 0x1e7f_ffff,
            nonce: 0,
            height: 1,
        }
    }

    /// El `hash_pow` dev **es** el `block_hash` de la cabecera, byte a byte.
    #[test]
    fn sha3_dev_coincide_con_el_block_hash() {
        let c = cabecera();
        assert_eq!(Sha3Dev.hash_pow(&c), *c.block_hash().as_bytes());
    }

    /// `SHA3-256` no se sustituye por otra primitiva sin que el test lo note.
    #[test]
    fn el_hash_pow_dev_es_sha3_del_prefijo_y_la_cabecera() {
        let c = cabecera();
        let pre = c.preimagen_pow();
        let esperado = zx_core::sha3_256_publico(&pre);
        assert_eq!(Sha3Dev.hash_pow(&c), *esperado.as_bytes());
    }
}
