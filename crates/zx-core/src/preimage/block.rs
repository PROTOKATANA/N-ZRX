//! Cabecera de bloque y árbol de Merkle (SPEC §6.1–§6.3).
//!
//! # Los offsets se derivan, no se transcriben
//!
//! `C-HDR-04` fija en qué bytes de la preimagen del PoW vive el `nonce`, y eso es **regla de
//! consenso**: el kernel GPU itera exactamente ese rango.
//!
//! Ese número es una suma de los anchos de los campos anteriores, así que aquí se **calcula** a
//! partir de ellos y un test lo compara contra el valor documentado en el SPEC. No se escribe a
//! mano.
//!
//! No es celo preventivo: el SPEC lo tuvo mal. Decía `[92, 100)` con offset 76, que era el valor
//! correcto cuando `timestamp` era `u32`; P-004 lo cambió a `u64` y el offset se quedó atrás. Un
//! minero que hubiera seguido la regla literalmente habría estado **mutando `bits` mientras
//! minaba**, y todos sus bloques habrían sido rechazados por C-BLK-05. Ver H-005.

use crate::digest::{BlockHash, Digest, MerkleRoot, TxId};
use crate::hash::{TAG_BLK_HEADER, TAG_BLK_MERKLE};
use crate::preimage::PreimageWriter;

/// Anchos de los campos de la cabecera, en el orden de C-HDR-01. **Es consenso.**
mod ancho {
    /// `consensus_branch_id: u32`.
    pub const BRANCH_ID: usize = 4;
    /// `prev_hash: u256`.
    pub const PREV_HASH: usize = 32;
    /// `merkle_root: u256`.
    pub const MERKLE_ROOT: usize = 32;
    /// `timestamp: u64`.
    pub const TIMESTAMP: usize = 8;
    /// `bits: u32`.
    pub const BITS: usize = 4;
    /// `nonce: u64`.
    pub const NONCE: usize = 8;
    /// `height: u32`.
    pub const HEIGHT: usize = 4;
}

/// Tamaño de la cabecera serializada: **92 bytes** (C-HDR-01).
pub const TAMANO_CABECERA: usize = ancho::BRANCH_ID
    + ancho::PREV_HASH
    + ancho::MERKLE_ROOT
    + ancho::TIMESTAMP
    + ancho::BITS
    + ancho::NONCE
    + ancho::HEIGHT;

/// Longitud de una etiqueta de dominio (C-HASH-04).
const TAMANO_ETIQUETA: usize = 16;

/// Tamaño de la preimagen del PoW: etiqueta + cabecera = **108 bytes**.
///
/// Cabe holgadamente en un solo bloque de *rate* de SHA3-256 (136 bytes), lo que permite mantener
/// un kernel GPU de absorción única. Es un contrato con la Fase 8, no una casualidad.
pub const TAMANO_PREIMAGEN_POW: usize = TAMANO_ETIQUETA + TAMANO_CABECERA;

/// Rate de SHA3-256: 136 bytes (C-HASH-01).
const RATE_SHA3_256: usize = 136;

// Contrato con el kernel GPU de la Fase 8: la preimagen del PoW MUST caber en un solo bloque de
// rate, para poder mantener una absorción única sin bucle multi-bloque. Es una aserción de
// **compilación**: si alguien engorda la cabecera por encima de 120 bytes, el crate no compila y se
// entera antes de escribir una línea de HIP.
const _: () = assert!(
    TAMANO_PREIMAGEN_POW <= RATE_SHA3_256,
    "la preimagen del PoW ya no cabe en un bloque de rate de SHA3-256"
);

/// Offset del `nonce` dentro de la cabecera: **80**. Derivado, no transcrito.
pub const OFFSET_NONCE_CABECERA: usize =
    ancho::BRANCH_ID + ancho::PREV_HASH + ancho::MERKLE_ROOT + ancho::TIMESTAMP + ancho::BITS;

/// Offset del `nonce` dentro de la preimagen del PoW: **96** (C-HDR-04).
///
/// El minero GPU **MUST** iterar exactamente `[OFFSET_NONCE_PREIMAGEN, +8)`.
pub const OFFSET_NONCE_PREIMAGEN: usize = TAMANO_ETIQUETA + OFFSET_NONCE_CABECERA;

/// Cabecera de bloque (§6.1). Tamaño fijo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockHeader {
    /// Rama de consenso activa a esta altura (C-HDR-02b).
    ///
    /// Va en la cabecera, y no solo en el sighash, para cerrar el ataque de *wipe-out* que ZIP-200
    /// describe y Zcash no llegó a implementar (C-UPG-05).
    pub consensus_branch_id: u32,
    /// Hash de la cabecera del padre.
    pub prev_hash: BlockHash,
    /// Raíz del árbol de Merkle de transacciones (§6.3).
    pub merkle_root: MerkleRoot,
    /// Segundos Unix.
    pub timestamp: u64,
    /// Target compacto (§7.2).
    pub bits: u32,
    /// El campo que el minero itera.
    pub nonce: u64,
    /// Altura. El génesis tiene `0` (C-HDR-02).
    pub height: u32,
}

impl BlockHeader {
    /// Codificación canónica de la cabecera: 92 bytes, campos en orden, little-endian (C-HDR-01).
    fn escribir(&self, w: &mut PreimageWriter) {
        w.u32(self.consensus_branch_id)
            .h32(self.prev_hash.as_bytes())
            .h32(self.merkle_root.as_bytes())
            .u64(self.timestamp)
            .u32(self.bits)
            .u64(self.nonce)
            .u32(self.height);
    }

    /// La preimagen del PoW: `etiqueta ‖ cabecera`, 108 bytes (C-HDR-03).
    ///
    /// Es lo que el minero GPU absorbe. Se expone porque el minero necesita el buffer para iterar
    /// el nonce in situ sin reconstruirlo en cada intento.
    #[must_use]
    pub fn preimagen_pow(&self) -> [u8; TAMANO_PREIMAGEN_POW] {
        let mut w = PreimageWriter::con_capacidad(TAMANO_CABECERA);
        self.escribir(&mut w);
        let cuerpo = w.into_bytes();

        let mut buf = [0u8; TAMANO_PREIMAGEN_POW];
        let (etiqueta, resto) = buf.split_at_mut(TAMANO_ETIQUETA);
        etiqueta.copy_from_slice(TAG_BLK_HEADER.as_bytes());
        resto.copy_from_slice(&cuerpo);
        buf
    }

    /// `block_hash = H_d("ZZKBlkHeader____", cabecera)` (C-HDR-03).
    ///
    /// Es también la preimagen del PoW: el mismo digest que se compara contra el target (C-POW-01).
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        let mut w = PreimageWriter::con_capacidad(TAMANO_CABECERA);
        self.escribir(&mut w);
        BlockHash::from_digest(w.finish(TAG_BLK_HEADER))
    }
}

/// Hoja nula con la que se empareja un nodo suelto (C-BLK-03).
const HOJA_NULA: [u8; 32] = [0u8; 32];

/// Raíz del árbol de Merkle sobre los txid del bloque, en orden de aparición.
///
/// Implementa C-BLK-01 (las hojas son los txid, en orden), C-BLK-02 (los nodos internos son
/// `H_d("ZZKBlkMerkle____", izq ‖ der)`) y C-BLK-03 (un nodo suelto se empareja con la hoja nula,
/// nunca se duplica).
///
/// Las tres se citan por su número entero y no como `C-BLK-01..03`: un rango no lo encuentra
/// ninguna búsqueda por número, y la trazabilidad de este proyecto se comprueba buscando.
///
/// # Relleno con nulo, no duplicación
///
/// Cuando un nivel tiene un número impar de nodos, el último se empareja con `0x00 × 32`. **No** se
/// duplica.
///
/// Duplicar es lo que hace Bitcoin, y arrastra **CVE-2012-2459**: dos listas de transacciones
/// distintas producen la misma raíz, lo que permite maleabilidad de bloque. El relleno con un valor
/// nulo distinguible elimina la ambigüedad y cuesta cero.
///
/// # Una hoja también se hashea
///
/// Con una sola transacción, la raíz es `H_d(tag, hoja ‖ nulo)`, **no la hoja desnuda**. Bitcoin
/// devuelve la hoja tal cual, con lo que `merkle_root == txid` para un bloque de una sola
/// transacción: una cabecera de bloque acaba comprometiendo un valor que es a la vez un
/// identificador de transacción válido. Hashear siempre garantiza que los dos espacios sean
/// disjuntos, y cuesta un hash por bloque.
///
/// Un bloque sin transacciones no existe —siempre lleva coinbase (C-BLK-07)—, pero por completitud
/// la raíz de la lista vacía es `H_d(tag, ⟨⟩)`, coherente con C-TX-04.
#[must_use]
pub fn merkle_root(txids: &[TxId]) -> MerkleRoot {
    if txids.is_empty() {
        return MerkleRoot::from_digest(PreimageWriter::new().finish(TAG_BLK_MERKLE));
    }

    let mut nivel: Vec<Digest> = txids.iter().map(|t| *t.digest()).collect();

    // Siempre se da al menos una vuelta, así que una hoja suelta también se hashea.
    loop {
        let mut siguiente: Vec<Digest> = Vec::with_capacity(nivel.len().div_ceil(2));
        for par in nivel.chunks(2) {
            let mut w = PreimageWriter::con_capacidad(64);
            match par {
                // C-BLK-02 · el nodo interno es el digest de la concatenación, con la etiqueta
                // de dominio del árbol de bloque.
                [izq, der] => {
                    w.digest(izq).digest(der);
                }
                // C-BLK-03: nodo suelto → hoja nula, nunca duplicación.
                [solo] => {
                    w.digest(solo).h32(&HOJA_NULA);
                }
                // `chunks(2)` sobre un slice no vacío solo produce trozos de 1 o 2.
                _ => return MerkleRoot::from_digest(PreimageWriter::new().finish(TAG_BLK_MERKLE)),
            }
            siguiente.push(w.finish(TAG_BLK_MERKLE));
        }
        match siguiente.as_slice() {
            [unico] => return MerkleRoot::from_digest(*unico),
            _ => nivel = siguiente,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#[expect(
    clippy::indexing_slicing,
    reason = "rangos constantes sobre arrays de tamaño fijo"
)]
mod tests {
    use super::{
        BlockHeader, OFFSET_NONCE_CABECERA, OFFSET_NONCE_PREIMAGEN, TAMANO_CABECERA,
        TAMANO_PREIMAGEN_POW, merkle_root,
    };
    use crate::digest::{BlockHash, Digest, MerkleRoot, TxId};

    fn cabecera() -> BlockHeader {
        BlockHeader {
            consensus_branch_id: 0xc478_80ea,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([0x11; 32])),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
            timestamp: 1_767_225_600,
            bits: 0x1d00_ffff,
            nonce: 0,
            height: 1,
        }
    }

    fn txid(n: u8) -> TxId {
        TxId::from_digest(Digest::from_bytes([n; 32]))
    }

    #[test]
    fn la_cabecera_mide_92_bytes_y_la_preimagen_108() {
        assert_eq!(TAMANO_CABECERA, 92, "C-HDR-01");
        assert_eq!(TAMANO_PREIMAGEN_POW, 108, "C-HDR-03");
        assert_eq!(cabecera().preimagen_pow().len(), 108);
    }

    /// **H-005.** Fija el offset del nonce contra el valor documentado en C-HDR-04.
    ///
    /// El SPEC lo tuvo mal: decía `[92, 100)` con offset 76, correcto solo cuando `timestamp` era
    /// `u32`. P-004 lo cambió a `u64` y el offset se quedó atrás. Un minero que hubiera seguido la
    /// regla habría estado mutando `bits` mientras minaba, y todos sus bloques habrían sido
    /// rechazados por C-BLK-05.
    ///
    /// Aquí los offsets se derivan de los anchos de los campos, así que este test es lo que impide
    /// que la deriva vuelva a ocurrir en silencio.
    #[test]
    fn el_nonce_esta_donde_dice_c_hdr_04() {
        assert_eq!(OFFSET_NONCE_CABECERA, 80, "offset del nonce en la cabecera");
        assert_eq!(
            OFFSET_NONCE_PREIMAGEN, 96,
            "C-HDR-04: el minero itera [96, 104)"
        );
    }

    /// Y la comprobación empírica: cambiar el nonce **solo** mueve esos 8 bytes.
    ///
    /// Si el offset estuviera mal, aquí se vería que también se mueven bytes de `bits`.
    #[test]
    fn cambiar_el_nonce_solo_toca_su_rango() {
        let a = cabecera().preimagen_pow();
        let mut h = cabecera();
        h.nonce = u64::MAX;
        let b = h.preimagen_pow();

        let distintos: Vec<usize> = (0..TAMANO_PREIMAGEN_POW)
            .filter(|i| a[*i] != b[*i])
            .collect();
        let esperados: Vec<usize> = (OFFSET_NONCE_PREIMAGEN..OFFSET_NONCE_PREIMAGEN + 8).collect();
        assert_eq!(
            distintos, esperados,
            "el nonce tiene que mover exactamente [96, 104) y nada más — si toca [92, 96) está \
             corrompiendo `bits` (H-005)"
        );
    }

    /// El campo `bits` queda justo antes del nonce: es el vecino que se corrompería.
    #[test]
    fn bits_esta_justo_antes_del_nonce() {
        let a = cabecera().preimagen_pow();
        let mut h = cabecera();
        h.bits = 0x1e00_ffff;
        let b = h.preimagen_pow();

        let distintos: Vec<usize> = (0..TAMANO_PREIMAGEN_POW)
            .filter(|i| a[*i] != b[*i])
            .collect();
        assert!(
            distintos.iter().all(|i| (92..96).contains(i)),
            "bits vive en [92, 96); cambió {distintos:?}"
        );
    }

    #[test]
    fn cada_campo_de_la_cabecera_entra_en_el_hash() {
        let base = cabecera();
        let original = base.block_hash();

        let mut v = base;
        v.consensus_branch_id ^= 1;
        assert_ne!(v.block_hash(), original, "consensus_branch_id");

        let mut v = base;
        v.prev_hash = BlockHash::from_digest(Digest::from_bytes([0x33; 32]));
        assert_ne!(v.block_hash(), original, "prev_hash");

        let mut v = base;
        v.merkle_root = MerkleRoot::from_digest(Digest::from_bytes([0x44; 32]));
        assert_ne!(v.block_hash(), original, "merkle_root");

        let mut v = base;
        v.timestamp += 1;
        assert_ne!(v.block_hash(), original, "timestamp");

        let mut v = base;
        v.bits ^= 1;
        assert_ne!(v.block_hash(), original, "bits");

        let mut v = base;
        v.nonce = 1;
        assert_ne!(v.block_hash(), original, "nonce");

        let mut v = base;
        v.height += 1;
        assert_ne!(v.block_hash(), original, "height");
    }

    // ── Merkle ───────────────────────────────────────────────────────────────

    /// Una sola hoja **también** se hashea: `merkle_root ≠ txid`, siempre.
    ///
    /// Bitcoin devuelve la hoja desnuda, con lo que en un bloque de una transacción la raíz de
    /// Merkle **es** un txid válido. Hashear siempre mantiene los dos espacios disjuntos.
    #[test]
    fn una_sola_hoja_no_es_su_propia_raiz() {
        let t = txid(1);
        let r = merkle_root(&[t]);
        assert_ne!(
            r.as_bytes(),
            t.as_bytes(),
            "merkle_root nunca debe ser un txid"
        );
    }

    /// **CVE-2012-2459.** La regresión que justifica el relleno con nulo.
    ///
    /// Con la construcción de Bitcoin —duplicar el último nodo— la lista `[a, b, c]` y la lista
    /// `[a, b, c, c]` producen **la misma raíz**, así que dos bloques con transacciones distintas
    /// comparten cabecera. Con relleno nulo, no.
    #[test]
    fn duplicar_la_ultima_hoja_no_da_la_misma_raiz() {
        let (a, b, c) = (txid(1), txid(2), txid(3));
        assert_ne!(
            merkle_root(&[a, b, c]),
            merkle_root(&[a, b, c, c]),
            "CVE-2012-2459: si estas dos raíces coinciden, el bloque es maleable"
        );
    }

    #[test]
    fn la_raiz_depende_del_orden() {
        let (a, b) = (txid(1), txid(2));
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }

    #[test]
    fn la_raiz_depende_del_numero_de_hojas() {
        let hojas: Vec<TxId> = (1u8..=8).map(txid).collect();
        let mut vistas: Vec<MerkleRoot> = Vec::new();
        for n in 1..=hojas.len() {
            let r = merkle_root(hojas.get(..n).unwrap());
            assert!(!vistas.contains(&r), "colisión con {n} hojas");
            vistas.push(r);
        }
    }

    #[test]
    fn la_raiz_es_determinista() {
        let hojas: Vec<TxId> = (1u8..=5).map(txid).collect();
        assert_eq!(merkle_root(&hojas), merkle_root(&hojas));
    }

    /// Un bloque sin transacciones no existe (C-BLK-07), pero la lista vacía tiene raíz definida y
    /// distinta de la de cualquier lista real — coherente con C-TX-04.
    #[test]
    fn la_lista_vacia_tiene_raiz_propia() {
        let vacia = merkle_root(&[]);
        assert_ne!(vacia.as_bytes(), &[0u8; 32], "nunca ceros");
        assert_ne!(vacia, merkle_root(&[txid(1)]));
    }
}
