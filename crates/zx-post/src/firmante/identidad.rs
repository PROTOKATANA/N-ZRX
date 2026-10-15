//! La **identidad de oportunidad** que indexa el registro local del firmante (`RAT-1`).
//!
//! # Qué es y qué no es
//!
//! Es la clave lógica con la que el productor apunta «esta oportunidad ya se usó para firmar este
//! `pre_hash`». La definición vigente es la de `RAT-1`/`EV-05`/`DS-L04`:
//! `(consensus_branch_id, public_key, sector_index, history_size, chunk, slot)`. Se deriva de la
//! cabecera: `consensus_branch_id` y `slot` del bloque, y el resto de los campos de la solución
//! PoAS. Es la **misma** identidad que usa la evidencia de consenso (`RAT-1` prevalece sobre EV-05):
//! `zx_core::preimage::tx::incident_id_evidencia`, así que dos cabeceras comparten identidad de
//! firmante si y solo si producen el mismo `incident_id` de la evidencia.
//!
//! **No es consenso.** La huella es un marcador **local**: no entra en ningún `pre_hash`, no viaja
//! por el wire y no altera `C-HASH-05`. Un verificador **MUST NOT** consultarla ni rechazar un
//! bloque remoto por ella: es política de producción (FIR-15).
//!
//! # La huella, no la tupla
//!
//! El índice del registro guarda una **huella de 32 bytes** con dominio propio, no la tupla. Dos
//! codificaciones distintas —o una definición futura de la identidad— producen espacios de claves
//! disjuntos, y el registro no mezcla oportunidades.
//!
//! La huella es `SHA3-256(dominio ‖ versión ‖ campos)`, con todos los campos de anchura fija. Se
//! usa [`zx_core::sha3_256_publico`], la función sin dominio que el repositorio reserva para lo que
//! no entra en consenso, en vez de añadir una dependencia de hash.
//!
//! # La versión 2 cierra `FP8`
//!
//! La v1 antigua no llevaba red: el mismo billete en mainnet y en testnet colisionaba. La v2
//! incluye `consensus_branch_id` en la identidad y sube [`VERSION_ESQUEMA`] a 2; cambiar el orden o
//! la anchura de un campo obliga a subir la versión.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use zx_core::{ClavePublica, sha3_256_publico};

/// Longitud de la huella de identidad que indexa el registro, en bytes.
pub const LONGITUD_HUELLA: usize = 32;

/// Dominio de la huella de [`IdentidadTicket`] (RAT-1, con `cbid`).
///
/// Es un marcador **local del firmante**: no es una etiqueta de `SPEC.md` §4.5, no entra en ninguna
/// preimagen de consenso y **no** debe pasar por `C-HASH-05`.
pub const DOMINIO_TICKET_RAT1: &[u8] = b"ZXRFIRM/ticket-rat1/cbid-c-gd-07";

/// Marca de versión del esquema de codificación de la identidad dentro de la huella.
///
/// La v1 (código antiguo) no llevaba `consensus_branch_id`; la v2 es la identidad de `RAT-1`.
/// Cambiar el orden o el ancho de un campo **obliga** a subir esto: si no, dos codificaciones
/// distintas con los mismos bytes producirían la misma huella y el registro daría por iguales dos
/// oportunidades distintas.
pub const VERSION_ESQUEMA: u8 = 2;

/// La identidad de oportunidad de `RAT-1`/`EV-05`.
///
/// Los campos son privados: la única forma de construirla es [`IdentidadTicket::rat1`], que recibe
/// exactamente la tupla de la regla. El firmante la deriva de la cabecera y **no** acepta una
/// identidad declarada por el llamante.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdentidadTicket {
    /// Rama de consenso de la red (`header.consensus_branch_id`, RAT-1).
    consensus_branch_id: u32,
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
    /// Construye la identidad de `RAT-1` con la tupla literal.
    #[must_use]
    pub const fn rat1(
        consensus_branch_id: u32,
        public_key: ClavePublica,
        sector_index: u16,
        history_size: u64,
        chunk: [u8; 32],
        slot: u64,
    ) -> Self {
        Self {
            consensus_branch_id,
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
        let mut preimagen =
            Vec::with_capacity(DOMINIO_TICKET_RAT1.len() + 1 + 4 + 32 + 2 + 8 + 32 + 8);
        preimagen.extend_from_slice(DOMINIO_TICKET_RAT1);
        preimagen.push(VERSION_ESQUEMA);
        preimagen.extend_from_slice(&self.bytes_canonicos());
        *sha3_256_publico(&preimagen).as_bytes()
    }

    /// Los bytes canónicos de la identidad, para diagnóstico y para comprobar la inyectividad de la
    /// codificación.
    ///
    /// El orden es el de la tupla de `RAT-1` y la anchura es fija por campo: `consensus_branch_id`
    /// (4, LE) ‖ `public_key` (32) ‖ `sector_index` (2, LE) ‖ `history_size` (8, LE) ‖ `chunk` (32)
    /// ‖ `slot` (8, LE). El ancho de `consensus_branch_id` coincide con el de
    /// [`zx_core::incident_id_evidencia`] para que la relación de igualdad de ambas sea la misma.
    #[must_use]
    pub fn bytes_canonicos(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 32 + 2 + 8 + 32 + 8);
        v.extend_from_slice(&self.consensus_branch_id.to_le_bytes());
        v.extend_from_slice(self.public_key.bytes());
        v.extend_from_slice(&self.sector_index.to_le_bytes());
        v.extend_from_slice(&self.history_size.to_le_bytes());
        v.extend_from_slice(&self.chunk);
        v.extend_from_slice(&self.slot.to_le_bytes());
        v
    }

    /// El slot de la oportunidad. Va **también** en la clave del registro, aparte de la huella.
    ///
    /// Redundante a propósito: la clave es `(TicketId(B), slot(B))` —`RAT-1` para la identidad y el
    /// `slot` de la cabecera— y si una definición futura de la identidad dejara de incluir el slot,
    /// la clave seguiría siendo la misma. El coste son 8 bytes por entrada.
    #[must_use]
    pub const fn slot(&self) -> u64 {
        self.slot
    }
}

impl Hash for IdentidadTicket {
    /// Hash **campo a campo**, sin `Vec` intermedio. Solo elige cubeta: la igualdad la decide el
    /// `Eq` derivado de `IdentidadTicket`, que compara los mismos campos. El orden y la anchura
    /// coinciden con el de `bytes_canonicos`, pero esta vía no asigna en el heap.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.consensus_branch_id.hash(state);
        self.public_key.bytes().hash(state);
        self.sector_index.hash(state);
        self.history_size.hash(state);
        self.chunk.hash(state);
        self.slot.hash(state);
    }
}

impl Ord for IdentidadTicket {
    /// Orden total determinista, **campo a campo** y en el orden de la tupla de `RAT-1`.
    ///
    /// Es consistente con `Eq` (`cmp == Equal` si y solo si todos los campos son iguales) y no
    /// reserva memoria, a diferencia de comparar `bytes_canonicos()` (que devuelve un `Vec`).
    fn cmp(&self, other: &Self) -> Ordering {
        self.consensus_branch_id
            .cmp(&other.consensus_branch_id)
            .then_with(|| self.public_key.bytes().cmp(other.public_key.bytes()))
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
    use super::{DOMINIO_TICKET_RAT1, IdentidadTicket, LONGITUD_HUELLA, VERSION_ESQUEMA};
    use zx_core::ClavePublica;

    fn rat1(chunk_byte: u8, slot: u64) -> IdentidadTicket {
        IdentidadTicket::rat1(
            7,
            ClavePublica::desde_bytes([7u8; 32]),
            3,
            1 << 20,
            [chunk_byte; 32],
            slot,
        )
    }

    #[test]
    fn la_huella_mide_32_bytes_y_es_determinista() {
        let a = rat1(1, 100);
        assert_eq!(a.huella().len(), LONGITUD_HUELLA);
        assert_eq!(a.huella(), rat1(1, 100).huella());
    }

    #[test]
    fn cambiar_cualquier_campo_cambia_la_huella() {
        let base = rat1(1, 100);
        // chunk y slot.
        assert_ne!(base.huella(), rat1(2, 100).huella());
        assert_ne!(base.huella(), rat1(1, 101).huella());
        // sector_index.
        let otro_sector = IdentidadTicket::rat1(
            7,
            ClavePublica::desde_bytes([7u8; 32]),
            4,
            1 << 20,
            [1u8; 32],
            100,
        );
        assert_ne!(base.huella(), otro_sector.huella());
        // history_size.
        let otra_historia = IdentidadTicket::rat1(
            7,
            ClavePublica::desde_bytes([7u8; 32]),
            3,
            (1 << 20) + 1,
            [1u8; 32],
            100,
        );
        assert_ne!(base.huella(), otra_historia.huella());
        // public_key.
        let otra_clave = IdentidadTicket::rat1(
            7,
            ClavePublica::desde_bytes([8u8; 32]),
            3,
            1 << 20,
            [1u8; 32],
            100,
        );
        assert_ne!(base.huella(), otra_clave.huella());
        // consensus_branch_id (RAT-1: cierra FP8).
        let otra_red = IdentidadTicket::rat1(
            8,
            ClavePublica::desde_bytes([7u8; 32]),
            3,
            1 << 20,
            [1u8; 32],
            100,
        );
        assert_ne!(base.huella(), otra_red.huella());
    }

    #[test]
    fn el_slot_se_lee_de_la_identidad() {
        assert_eq!(rat1(1, 4_242).slot(), 4_242);
    }

    #[test]
    fn el_dominio_y_la_version_forman_parte_de_la_preimagen() {
        // Si el dominio o la versión no entraran, la huella coincidiría con un SHA3 de los campos.
        let id = rat1(1, 100);
        let crudo = *zx_core::sha3_256_publico(&id.bytes_canonicos()).as_bytes();
        assert_ne!(id.huella(), crudo);
        assert!(!DOMINIO_TICKET_RAT1.is_empty());
        assert_eq!(VERSION_ESQUEMA, 2);
    }
}
