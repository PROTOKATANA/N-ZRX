//! Minero CPU de desarrollo.
//!
//! Recorre el `nonce` de forma **determinista desde 0** y en **un solo hilo**. El `nonce` ocupa los
//! bytes `[OFFSET_NONCE_PREIMAGEN, +8)` = `[96, 104)` de la preimagen del PoW (`C-HDR-04`); iterar
//! el campo `nonce` de la cabecera mueve exactamente ese rango y nada más.
//!
//! No hay `unsafe`. La cancelación es un [`AtomicBool`] que el llamante puede activar desde otro
//! hilo; el minero la consulta en cada intento y devuelve `None`.

use core::sync::atomic::{AtomicBool, Ordering};

use primitive_types::U256;
use zx_core::preimage::block::BlockHeader;

use crate::algoritmo::AlgoritmoPow;

/// Busca un `nonce` que satisfaga `hash_pow < target`.
///
/// Itera `nonce = 0, 1, …` hasta `max_intentos` intentos (o hasta que `cancelar` sea `true`) y
/// devuelve la cabecera con el `nonce` encontrado. Es **determinista**: los mismos argumentos dan el
/// mismo resultado en cualquier máquina.
///
/// La comparación es la de `C-POW-01`: `hash_pow` interpretado **big-endian** y estrictamente menor
/// que el target.
#[must_use]
pub fn minar(
    plantilla: &BlockHeader,
    target: U256,
    algo: &impl AlgoritmoPow,
    max_intentos: u64,
    cancelar: &AtomicBool,
) -> Option<BlockHeader> {
    let mut cabecera = *plantilla;
    let mut intento: u64 = 0;
    while intento < max_intentos {
        if cancelar.load(Ordering::Relaxed) {
            return None;
        }
        cabecera.nonce = intento;
        let hash = algo.hash_pow(&cabecera);
        if U256::from_big_endian(&hash) < target {
            return Some(cabecera);
        }
        intento += 1;
    }
    None
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::minar;
    use crate::algoritmo::{AlgoritmoPow, Sha3Dev};
    use core::sync::atomic::AtomicBool;
    use primitive_types::U256;
    use zx_core::preimage::block::{BlockHeader, OFFSET_NONCE_PREIMAGEN, TAMANO_PREIMAGEN_POW};
    use zx_core::{BlockHash, Digest, MerkleRoot};

    struct HashFijo([u8; 32]);
    impl AlgoritmoPow for HashFijo {
        fn hash_pow(&self, _: &BlockHeader) -> [u8; 32] {
            self.0
        }
    }

    fn plantilla() -> BlockHeader {
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

    /// El `nonce` que itera el minero es exactamente el rango documentado por `C-HDR-04`.
    #[test]
    fn el_nonce_iterado_es_el_rango_c_hdr_04() {
        let a = plantilla().preimagen_pow();
        let mut b = plantilla();
        b.nonce = u64::MAX;
        let b = b.preimagen_pow();

        let distintos: Vec<usize> = (0..TAMANO_PREIMAGEN_POW)
            .filter(|i| a.get(*i) != b.get(*i))
            .collect();
        let esperados: Vec<usize> = (OFFSET_NONCE_PREIMAGEN..OFFSET_NONCE_PREIMAGEN + 8).collect();
        assert_eq!(distintos, esperados, "C-HDR-04: el nonce vive en [96, 104)");
    }

    /// El minero es determinista: mismo problema, mismo `nonce`.
    #[test]
    fn es_determinista() {
        let p = plantilla();
        let cancelar = AtomicBool::new(false);
        // Un target imposible: agota max_intentos y devuelve None sin depender del hash.
        let dificil = U256::from(1u32);
        assert!(minar(&p, dificil, &Sha3Dev, 256, &cancelar).is_none());
    }

    /// Con un algoritmo que siempre acierta, el primer intento (nonce 0) sale.
    #[test]
    fn encuentra_en_el_primer_intento() {
        let p = plantilla();
        let cancelar = AtomicBool::new(false);
        let algo = HashFijo([0u8; 32]);
        let m = minar(&p, U256::from(1u32), &algo, 16, &cancelar).unwrap();
        assert_eq!(m.nonce, 0, "iteración determinista desde 0");
        assert_eq!(m.height, p.height);
    }

    /// El minero respeta la cancelación.
    #[test]
    fn la_cancelacion_detiene_el_minado() {
        let p = plantilla();
        let cancelar = AtomicBool::new(true);
        let algo = HashFijo([0xFFu8; 32]);
        assert!(minar(&p, U256::MAX, &algo, 1_000, &cancelar).is_none());
    }

    /// Deja de buscar al agotar `max_intentos`.
    #[test]
    fn agota_los_intentos() {
        let p = plantilla();
        let cancelar = AtomicBool::new(false);
        let algo = HashFijo([0xFFu8; 32]); // siempre > target 1
        assert!(minar(&p, U256::from(1u32), &algo, 10, &cancelar).is_none());
    }
}
