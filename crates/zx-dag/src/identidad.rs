//! La **identidad de oportunidad** que indexa el registro local del firmante.
//!
//! # Qué es y qué no es
//!
//! Es la clave lógica con la que el productor apunta «esta oportunidad ya se usó para firmar este
//! `pre_hash`». La definición vigente es la de `C-GD-07`/R-FIN-11:
//! `(public_key, sector_index, history_size, chunk, slot)`. Se deriva de los campos de la solución
//! PoAS de la cabecera y del `slot` del bloque.
//!
//! **No es consenso.** La huella es un marcador **local**: no entra en ningún `pre_hash`, no viaja
//! por el wire y no altera `C-HASH-05` ni la tabla de etiquetas de `SPEC.md` §4.5. Un verificador
//! **MUST NOT** consultarla ni rechazar un bloque remoto por ella: es política de producción.
//!
//! # La huella, no la tupla
//!
//! El índice del registro guarda una **huella de 32 bytes** con dominio propio, no la tupla. Dos
//! codificaciones distintas —o una definición futura de la identidad— producen espacios de claves
//! disjuntos, y el registro no mezcla oportunidades.
//!
//! La huella es `SHA3-256(dominio ‖ versión ‖ campos)`, con todos los campos de anchura fija. Se
//! usa [`zx_core::sha3_256_publico`], la función sin dominio que `SPEC.md` reserva para lo que no
//! entra en consenso, en vez de añadir una dependencia de hash.
//!
//! # Límite que hay que decir
//!
//! La identidad vigente **no** lleva dominio de red: el mismo billete en mainnet y en testnet
//! colisiona (`P-ZRX/P-FIRMANTE/ESPECIFICACION.md` FP8). Este módulo no lo arregla por su cuenta;
//! lo deja escrito para que la decisión no se olvide.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use zx_core::{ClavePublica, DagBlockHeader, sha3_256_publico};

/// Longitud de la huella de identidad que indexa el registro, en bytes.
pub const LONGITUD_HUELLA: usize = 32;

/// Dominio de la huella de [`IdentidadTicket`].
///
/// Es un marcador **local del firmante**: no es una etiqueta de `SPEC.md` §4.5, no entra en ninguna
/// preimagen de consenso y **no** debe pasar por `C-HASH-05`.
pub const DOMINIO_TICKET_VIGENTE: &[u8] = b"ZXRFIRM/ticket-vigente/c-gd-07";

/// Marca de versión del esquema de codificación de la identidad dentro de la huella.
///
/// Cambiar el orden o el ancho de un campo **obliga** a subir esto: si no, dos codificaciones
/// distintas con los mismos bytes producirían la misma huella y el registro daría por iguales dos
/// oportunidades distintas.
pub const VERSION_ESQUEMA: u8 = 1;

/// La identidad de oportunidad de `C-GD-07`/R-FIN-11.
///
/// Los campos son privados: la única forma de construirla es [`IdentidadTicket::vigente`], que
/// recibe exactamente la tupla de la regla. [`identidad_de_cabecera`] la deriva de la cabecera y
/// **no** acepta una identidad declarada por el llamante.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdentidadTicket {
    /// Clave pública que firma el sello (`sol.public_key` de la cabecera).
    public_key: ClavePublica,
    /// Índice de sector (`sol.sector_index`).
    sector_index: u16,
    /// Tamaño de historia (`sol.history_size`).
    history_size: u64,
    /// Chunk de la solución (`sol.chunk`, 32 B).
    chunk: [u8; 32],
    /// Índice de PoT del bloque (`header.slot`).
    slot: u64,
}

impl IdentidadTicket {
    /// Construye la identidad vigente con la tupla literal de `C-GD-07`.
    #[must_use]
    pub const fn vigente(
        public_key: ClavePublica,
        sector_index: u16,
        history_size: u64,
        chunk: [u8; 32],
        slot: u64,
    ) -> Self {
        Self {
            public_key,
            sector_index,
            history_size,
            chunk,
            slot,
        }
    }

    /// La huella de 32 bytes que indexa el registro: `SHA3-256(dominio ‖ versión ‖ campos)`.
    #[must_use]
    pub fn huella(&self) -> [u8; LONGITUD_HUELLA] {
        let mut preimagen = Vec::with_capacity(DOMINIO_TICKET_VIGENTE.len() + 1 + 34 + 32 + 8);
        preimagen.extend_from_slice(DOMINIO_TICKET_VIGENTE);
        preimagen.push(VERSION_ESQUEMA);
        preimagen.extend_from_slice(&self.bytes_canonicos());
        *sha3_256_publico(&preimagen).as_bytes()
    }

    /// Los bytes canónicos de la identidad, para diagnóstico y para comprobar la inyectividad de
    /// la codificación.
    ///
    /// El orden es el de la tupla de `C-GD-07` y la anchura es fija por campo: `public_key` (32) ‖
    /// `sector_index` (2, LE) ‖ `history_size` (8, LE) ‖ `chunk` (32) ‖ `slot` (8, LE).
    #[must_use]
    pub fn bytes_canonicos(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 2 + 8 + 32 + 8);
        v.extend_from_slice(self.public_key.bytes());
        v.extend_from_slice(&self.sector_index.to_le_bytes());
        v.extend_from_slice(&self.history_size.to_le_bytes());
        v.extend_from_slice(&self.chunk);
        v.extend_from_slice(&self.slot.to_le_bytes());
        v
    }

    /// El slot de la oportunidad. Va **también** en la clave del registro, aparte de la huella.
    ///
    /// Redundante a propósito: la clave es `(TicketId(B), slot(B))` —`C-GD-07` para la identidad y
    /// el `slot` de la cabecera— y si una definición futura de la identidad dejara de incluir el
    /// slot, la clave seguiría siendo la misma. El coste son 8 bytes por entrada.
    #[must_use]
    pub const fn slot(&self) -> u64 {
        self.slot
    }
}

/// La identidad de oportunidad de `C-GD-07` de una cabecera DAG.
///
/// Es el cuerpo de `Firmante::identidad` del árbol antiguo, ahora libre de la dependencia del
/// firmante: la identidad sale de la **misma** cabecera que aporta `block_hash`, `slot` y `SR`, y
/// el llamante no puede pasar una identidad distinta. **No** acredita PoST, PoAS ni procedencia:
/// solo fija la tupla literal que GHOSTDAG compara en U2/U3.
#[must_use]
pub fn identidad_de_cabecera(header: &DagBlockHeader) -> IdentidadTicket {
    IdentidadTicket::vigente(
        header.sol.public_key,
        header.sol.sector_index,
        header.sol.history_size,
        header.sol.chunk,
        header.slot,
    )
}

impl Hash for IdentidadTicket {
    /// Hash **campo a campo**, sin `Vec` intermedio. Solo elige cubeta: la igualdad la decide el
    /// `Eq` derivado de `IdentidadTicket`, que compara los mismos campos. El orden y la anchura
    /// coinciden con el de `bytes_canonicos`, pero esta vía no asigna en el heap, que es lo que
    /// exige la ruta caliente de U2/U3 (`HashSet` de identidades en GHOSTDAG).
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key.bytes().hash(state);
        self.sector_index.hash(state);
        self.history_size.hash(state);
        self.chunk.hash(state);
        self.slot.hash(state);
    }
}

impl Ord for IdentidadTicket {
    /// Orden total determinista, **campo a campo** y en el orden de la tupla de `C-GD-07`.
    ///
    /// Es consistente con `Eq` (`cmp == Equal` si y solo si todos los campos son iguales) y no
    /// reserva memoria, a diferencia de comparar `bytes_canonicos()` (que devuelve un `Vec`).
    fn cmp(&self, other: &Self) -> Ordering {
        self.public_key
            .bytes()
            .cmp(other.public_key.bytes())
            .then_with(|| self.sector_index.cmp(&other.sector_index))
            .then_with(|| self.history_size.cmp(&other.history_size))
            .then_with(|| self.chunk.cmp(&other.chunk))
            .then_with(|| self.slot.cmp(&other.slot))
    }
}

impl PartialOrd for IdentidadTicket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño y usan índices constantes"
)]
mod tests {
    use super::{
        DOMINIO_TICKET_VIGENTE, IdentidadTicket, LONGITUD_HUELLA, VERSION_ESQUEMA,
        identidad_de_cabecera,
    };
    use zx_core::digest::{BodyCommitment, Digest, MerkleRoot};
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_core::{BlockHash, ClavePublica};

    fn vigente(chunk_byte: u8, slot: u64) -> IdentidadTicket {
        IdentidadTicket::vigente(
            ClavePublica::desde_bytes([7u8; 32]),
            3,
            1 << 20,
            [chunk_byte; 32],
            slot,
        )
    }

    #[test]
    fn la_huella_mide_32_bytes_y_es_determinista() {
        let a = vigente(1, 100);
        assert_eq!(a.huella().len(), LONGITUD_HUELLA);
        assert_eq!(a.huella(), vigente(1, 100).huella());
    }

    #[test]
    fn cambiar_cualquier_campo_cambia_la_huella() {
        let base = vigente(1, 100);
        // chunk y slot.
        assert_ne!(base.huella(), vigente(2, 100).huella());
        assert_ne!(base.huella(), vigente(1, 101).huella());
        // sector_index.
        let otro_sector = IdentidadTicket::vigente(
            ClavePublica::desde_bytes([7u8; 32]),
            4,
            1 << 20,
            [1u8; 32],
            100,
        );
        assert_ne!(base.huella(), otro_sector.huella());
        // history_size.
        let otra_historia = IdentidadTicket::vigente(
            ClavePublica::desde_bytes([7u8; 32]),
            3,
            (1 << 20) + 1,
            [1u8; 32],
            100,
        );
        assert_ne!(base.huella(), otra_historia.huella());
        // public_key.
        let otra_clave = IdentidadTicket::vigente(
            ClavePublica::desde_bytes([8u8; 32]),
            3,
            1 << 20,
            [1u8; 32],
            100,
        );
        assert_ne!(base.huella(), otra_clave.huella());
    }

    #[test]
    fn el_slot_se_lee_de_la_identidad() {
        assert_eq!(vigente(1, 4_242).slot(), 4_242);
    }

    #[test]
    fn el_dominio_y_la_version_forman_parte_de_la_preimagen() {
        // Si el dominio o la versión no entraran, la huella coincidiría con un SHA3 de los campos.
        let id = vigente(1, 100);
        let crudo = *zx_core::sha3_256_publico(&id.bytes_canonicos()).as_bytes();
        assert_ne!(id.huella(), crudo);
        assert!(!DOMINIO_TICKET_VIGENTE.is_empty());
        assert_eq!(VERSION_ESQUEMA, 1);
    }

    /// `identidad_de_cabecera` deriva la tupla literal de la cabecera y **solo** de ella: cambiar
    /// cualquier campo de `sol` o el `slot` cambia la huella.
    #[test]
    fn identidad_de_cabecera_deriva_la_tupla_literal() {
        let cabecera = DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
            timestamp: 1_700_000_000,
            height: 10,
            slot: 1234,
            pot_output: [0x11; 16],
            rango_solucion: 7,
            sol: SolucionPoas {
                public_key: ClavePublica::desde_bytes([9u8; 32]),
                sector_index: 3,
                history_size: 1 << 20,
                chunk: [4u8; 32],
                ..SolucionPoas::default()
            },
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x33; 32])),
            padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([0x01; 32])), &[])
                .unwrap(),
            sello: [0u8; 64],
        };

        let esperado = IdentidadTicket::vigente(
            ClavePublica::desde_bytes([9u8; 32]),
            3,
            1 << 20,
            [4u8; 32],
            1234,
        );
        assert_eq!(identidad_de_cabecera(&cabecera), esperado);

        let mut otro = cabecera;
        otro.slot = 1235;
        assert_ne!(
            identidad_de_cabecera(&cabecera),
            identidad_de_cabecera(&otro)
        );
    }
}
