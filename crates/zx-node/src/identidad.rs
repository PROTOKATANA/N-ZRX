//! Identidad GHOSTDAG del bloque producido (`C-GD-07`, `ORDEN-W06a-C` decisión 2).
//!
//! `zx-cadena::BloquePost::identidad` es hoy una [`IdentidadGhostdag`] **real**, no un `u64` de
//! fixture. Este módulo es la puerta única del nodo: deriva la tupla literal
//! `(public_key, sector_index, history_size, chunk, slot)` de la **misma** cabecera que aporta
//! `block_hash`, `slot` y `SR` con `zx_dag::identidad_de_cabecera`, y **no la trunca** (antes se
//! proyectaba a los 8 primeros bytes de `huella()`, que no es inyectivo).

use zx_core::DagBlockHeader;
use zx_dag::ghostdag::IdentidadGhostdag;
use zx_dag::identidad_de_cabecera;

/// Deriva la identidad real de `C-GD-07` de una cabecera PoST ya construida.
#[must_use]
pub fn identidad_de_cabecera_post(cabecera: &DagBlockHeader) -> IdentidadGhostdag {
    IdentidadGhostdag::Billete(identidad_de_cabecera(cabecera))
}

#[cfg(test)]
mod tests {
    use super::identidad_de_cabecera_post;
    use zx_core::digest::{BodyCommitment, Digest, MerkleRoot};
    use zx_core::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_dag::ghostdag::IdentidadGhostdag;

    fn cabecera(slot: u64, chunk: u8) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: zx_core::CBID_RED_DEV,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
            timestamp: 1_788_480_000,
            height: 0,
            slot,
            pot_output: [0u8; 16],
            rango_solucion: 1,
            sol: SolucionPoas {
                chunk: [chunk; 32],
                ..SolucionPoas::default()
            },
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
            padres: PadresDag::genesis(),
            sello: [0u8; 64],
        }
    }

    #[test]
    fn es_determinista_y_nunca_cero() {
        let a = identidad_de_cabecera_post(&cabecera(1, 0xAA));
        let b = identidad_de_cabecera_post(&cabecera(1, 0xAA));
        let c = identidad_de_cabecera_post(&cabecera(1, 0xBB));
        assert_eq!(a, b);
        assert_ne!(a, c);
        // La identidad es un billete real: nunca el centinela `SinBillete` ni el dominio sintético
        // (el truncamiento a `u64` que este módulo hacía antes está eliminado).
        assert!(matches!(a, IdentidadGhostdag::Billete(_)));
        assert!(matches!(c, IdentidadGhostdag::Billete(_)));
    }
}
