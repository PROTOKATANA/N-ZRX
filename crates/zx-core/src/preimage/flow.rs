//! Flujo del génesis y derivación del identificador de flujo (SPEC §7.1.3–§7.1.4).
//!
//! # Qué implementa
//!
//! Dos derivaciones **puras** de `C-FLU-06` y `C-FLU-10`, con entradas tipadas:
//!
//! ```text
//! f_0             = H_flujo( ETIQUETA_GENESIS ‖ block_hash(génesis) )       32 B
//! flujo_siguiente = H_flujo( flujo_anterior ‖ entropía_j ‖ LE64(t_j) )      32 B
//! H_flujo(m)      = H_d( ETIQUETA_FLUJO ‖ m ) = SHA3-256( ETIQUETA_FLUJO ‖ m )
//! ```
//!
//! `ETIQUETA_FLUJO` (`ZZKFlowId_______`) y `ETIQUETA_GENESIS` (`ZZKFlowGenesis__`) son **dos
//! etiquetas distintas** de la tabla C-HASH-06 y **no se uniforman**: la primera es la etiqueta de
//! dominio de `H_flujo`; la segunda va **dentro de su mensaje**, junto al `block_hash` del génesis.
//! Es la decisión D-F2 = A del SPEC.
//!
//! # Lo que NO acredita
//!
//! Estas funciones son fórmulas puras de sus argumentos y **no** sustituyen al derivador de
//! contexto de §7.1.2:
//!
//! - **No** seleccionan la inyección `I_j`, ni calculan `t_j`, ni comprueban el calendario de
//!   inyecciones ni la activación retrasada (`C-FLU-12`). El `t_j` llega **ya derivado**.
//! - **No** validan el génesis ni acreditan que el `block_hash` de entrada sea el del génesis.
//! - **No** dicen quién decidió inyectar ni en qué slot. `C-FLU-10` es función exclusiva de
//!   `past(B)`; acreditarlo es responsabilidad del futuro derivador contextual, que **no existe**.
//!
//! # Por qué ninguna API acepta bytes de wire
//!
//! [`h_d`] sigue siendo `pub(crate)`: solo se reexporta `sha3_256_publico`, que no acepta etiqueta
//! de dominio. Estas funciones reciben tipos de dominio (`BlockHash`, arrays de 32 B y `u64`) y
//! construyen la preimagen con **longitudes fijas**, así que no hay ningún camino por el que unos
//! bytes de wire acaben hasheados como si fueran una preimagen canónica.

use crate::digest::BlockHash;
use crate::hash::{TAG_FLOW_GENESIS, TAG_FLOW_ID, h_d};

/// Bytes de un identificador de flujo (SPEC §7.1.4).
pub const FLUJO_BYTES: usize = 32;

/// Bytes de la entropía de una inyección (`C-FLU-12` vía `C-POT-01`).
///
/// No se elige aquí: `C-FLU-12` define `entropía_j(B) := blake3(chunk(I_j(B)) ‖ pot_output(I_j(B)))`
/// y `blake3` entrega 32 B. Esta función recibe la entropía **ya calculada** por el llamante.
pub const ENTROPIA_INYECCION_BYTES: usize = 32;

/// Longitud de una etiqueta de dominio (C-HASH-04).
const TAMANO_ETIQUETA: usize = 16;

/// `f_0 = H_flujo( ETIQUETA_GENESIS ‖ block_hash(génesis) )` (`C-FLU-06` junto a `C-FLU-10`).
///
/// Calcula `SHA3-256( ZZKFlowId_______ ‖ ZZKFlowGenesis__ ‖ block_hash )`, 32 B. Las dos etiquetas
/// son **distintas y no se uniforman**.
///
/// `block_hash_genesis` es el `block_hash` del bloque génesis y llega ya calculado: esta función
/// **no** valida el génesis ni acredita que sea el correcto. El génesis **no** es ancla de nada:
/// las épocas se indexan desde `j = 1` y `flujo(B, s) = f_0` para todo `s < t_1` (`C-FLU-06`).
#[must_use]
pub fn flujo_genesis(block_hash_genesis: &BlockHash) -> [u8; FLUJO_BYTES] {
    let mut preimagen = [0u8; TAMANO_ETIQUETA + FLUJO_BYTES];
    let (etiqueta, resto) = preimagen.split_at_mut(TAMANO_ETIQUETA);
    etiqueta.copy_from_slice(TAG_FLOW_GENESIS.as_bytes());
    resto.copy_from_slice(block_hash_genesis.as_bytes());
    *h_d(TAG_FLOW_ID, &preimagen).as_bytes()
}

/// `H_flujo( flujo_anterior ‖ entropía_j ‖ LE64(t_j) )` (`C-FLU-10`).
///
/// `flujo_anterior` es **el valor vigente justo antes de la inyección** `j`, es decir
/// `flujo(B, t_j − 1)`. **No** se escribe ni se calcula como `flujo(B, t_{j−1})`: con una época
/// saltada, `t_{j−1}` puede no existir. Esta función recibe ese valor **ya derivado** y **no**
/// afirma seleccionar `I_j`.
///
/// `t_j = slot(I_j) + L_slots` es el slot de activación, ya calculado por el llamante; aquí solo
/// entra como `LE64(t_j)`, codificación fija. La preimagen tiene longitudes fijas —32 B de flujo +
/// 32 B de entropía + 8 B de slot—, sin ambigüedad de concatenación.
#[must_use]
pub fn flujo_siguiente(
    flujo_anterior: &[u8; FLUJO_BYTES],
    entropia_j: &[u8; ENTROPIA_INYECCION_BYTES],
    t_j: u64,
) -> [u8; FLUJO_BYTES] {
    let mut preimagen = [0u8; FLUJO_BYTES + ENTROPIA_INYECCION_BYTES + 8];
    let (flujo, resto) = preimagen.split_at_mut(FLUJO_BYTES);
    flujo.copy_from_slice(flujo_anterior);
    let (entropia, slot) = resto.split_at_mut(ENTROPIA_INYECCION_BYTES);
    entropia.copy_from_slice(entropia_j);
    slot.copy_from_slice(&t_j.to_le_bytes());
    *h_d(TAG_FLOW_ID, &preimagen).as_bytes()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño al parsear los vectores"
)]
mod tests {
    use super::{ENTROPIA_INYECCION_BYTES, FLUJO_BYTES, flujo_genesis, flujo_siguiente};
    use crate::digest::{BlockHash, Digest};

    /// `block_hash` del génesis del vector: byte `i` = `i` (`0x00..0x1F`).
    const HASH_GENESIS: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    /// Flujo anterior del vector: byte `i` = `0x40 + i` (`0x40..0x5F`).
    const FLUJO_ANTERIOR: [u8; FLUJO_BYTES] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];

    /// Entropía de inyección del vector: byte `i` = `0x80 + i` (`0x80..0x9F`).
    const ENTROPIA: [u8; ENTROPIA_INYECCION_BYTES] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];

    /// Slot de activación con bytes **asimétricos**: `LE64` y `BE64` difieren en todos sus bytes.
    const T_J: u64 = 0x0102_0304_0506_0708;

    fn genesis_fijo() -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes(HASH_GENESIS))
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).expect("hex de 64 dígitos");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    /// **Vector fijo de `f_0`.** La expectativa se calculó **fuera** de la función bajo prueba:
    ///
    /// ```text
    /// printf 'ZZKFlowId_______ZZKFlowGenesis__'        > f0.bin   # 16 + 16 B
    /// for i in $(seq 0 31); do printf "\\x$(printf '%02x' $i)"; done >> f0.bin   # 0x00..0x1F
    /// openssl dgst -sha3-256 f0.bin
    ///   -> d16f8fb47eeefa36d4295b007d14f3e215aacc99c20f356caad984208236094a
    /// ```
    ///
    /// Fuente: OpenSSL 3.5.3, `sha3-256`. Orden de bytes: preimagen tal cual, sin inversión; el
    /// digest se lee en el orden en que lo entrega la esponja (el mismo que `Digest`).
    #[test]
    fn f0_vector_fijo_openssl() {
        assert_eq!(
            flujo_genesis(&genesis_fijo()),
            hex32("d16f8fb47eeefa36d4295b007d14f3e215aacc99c20f356caad984208236094a"),
            "C-FLU-06: f_0 = SHA3-256(ZZKFlowId_______ ‖ ZZKFlowGenesis__ ‖ block_hash)"
        );
    }

    /// **Vector fijo de `flujo_siguiente`.** Calculado fuera de la función bajo prueba:
    ///
    /// ```text
    /// printf 'ZZKFlowId_______'                            > fs.bin   # 16 B
    /// for i in $(seq 64 95);   do printf "\\x$(printf '%02x' $i)"; done >> fs.bin  # 0x40..0x5F
    /// for i in $(seq 128 159); do printf "\\x$(printf '%02x' $i)"; done >> fs.bin  # 0x80..0x9F
    /// printf '\x08\x07\x06\x05\x04\x03\x02\x01'            >> fs.bin  # LE64(0x0102030405060708)
    /// openssl dgst -sha3-256 fs.bin
    ///   -> 47c4a9da7125f1b92fa292cce0ad6bc0e9ed2866a53870570b6c89f1c23c7b4c
    /// ```
    #[test]
    fn flujo_siguiente_vector_fijo_openssl() {
        assert_eq!(
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J),
            hex32("47c4a9da7125f1b92fa292cce0ad6bc0e9ed2866a53870570b6c89f1c23c7b4c"),
            "C-FLU-10: H_flujo(flujo_anterior ‖ entropía ‖ LE64(t_j))"
        );
    }

    /// Las salidas miden 32 B y son deterministas.
    #[test]
    fn las_salidas_miden_32_bytes_y_son_deterministas() {
        let f0 = flujo_genesis(&genesis_fijo());
        assert_eq!(f0.len(), FLUJO_BYTES);
        assert_eq!(f0, flujo_genesis(&genesis_fijo()));

        let f1 = flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J);
        assert_eq!(f1.len(), FLUJO_BYTES);
        assert_eq!(f1, flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J));
    }

    /// Cambiar el `block_hash` del génesis cambia `f_0`.
    #[test]
    fn cambiar_el_hash_del_genesis_cambia_f0() {
        let mut otro = HASH_GENESIS;
        otro[0] ^= 0x01;
        assert_ne!(
            flujo_genesis(&genesis_fijo()),
            flujo_genesis(&BlockHash::from_digest(Digest::from_bytes(otro)))
        );
    }

    /// Si la implementación **omitiera** `ETIQUETA_GENESIS`, daría este otro vector fijo de
    /// openssl: `SHA3-256(ZZKFlowId_______ ‖ 0x00..0x1F)`.
    ///
    /// Demuestra que la etiqueta del génesis entra de verdad en la preimagen, como exige `C-FLU-06`
    /// (las dos etiquetas son distintas y no se uniforman, D-F2 = A).
    #[test]
    fn omitir_la_etiqueta_del_genesis_cambia_f0() {
        assert_ne!(
            flujo_genesis(&genesis_fijo()),
            hex32("15342d0e46df7f705d03412861da06ccf726998ec91382c84d5fc4a85cea305a")
        );
    }

    /// Si `H_flujo` usara `ZZKFlowGenesis__` como etiqueta de **dominio** en lugar de
    /// `ZZKFlowId_______`, daría este otro vector fijo de openssl.
    #[test]
    fn cambiar_la_etiqueta_de_flujo_cambia_la_salida() {
        assert_ne!(
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J),
            hex32("b99338d3a1e3a9b24ea4a479a3ce2fb768f889c39800f2bf1c09ec26c16843ed")
        );
    }

    /// Cambiar la entropía de la inyección cambia el flujo.
    #[test]
    fn cambiar_la_entropia_cambia_el_flujo() {
        let mut otra = ENTROPIA;
        otra[0] ^= 0x01;
        assert_ne!(
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J),
            flujo_siguiente(&FLUJO_ANTERIOR, &otra, T_J)
        );
    }

    /// Cambiar `t_j` cambia el flujo: el slot entra en la preimagen.
    #[test]
    fn cambiar_t_j_cambia_el_flujo() {
        assert_ne!(
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J),
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J + 1)
        );
    }

    /// **LE64 con slot asimétrico.** Si `t_j` entrara en big-endian, la salida sería este otro
    /// vector fijo de openssl (`… ‖ 01 02 03 04 05 06 07 08`).
    #[test]
    fn control_detecta_big_endian_en_t_j() {
        assert_ne!(
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J),
            hex32("382d470adfc06640649e9a303678b5ebaa19548e10843c4fbc05448e15fb000f"),
            "C-FLU-10: la codificación es LE64(t_j), no BE64"
        );
    }

    /// Si se invirtiera el orden `flujo ‖ entropía`, la salida sería este otro vector fijo de
    /// openssl (`ZZKFlowId_______ ‖ entropía ‖ flujo ‖ LE64(t_j)`).
    #[test]
    fn control_detecta_invertir_flujo_y_entropia() {
        assert_ne!(
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J),
            hex32("e1561435b7ae58694c9e8f74c03dd806c84f15c1226e7b142f29e0d2ee73a660"),
            "el orden es flujo_anterior primero, entropía después"
        );
    }

    /// El flujo y la entropía no son intercambiables: usar uno como otro da salidas distintas.
    #[test]
    fn flujo_y_entropia_no_son_intercambiables() {
        assert_ne!(
            flujo_siguiente(&FLUJO_ANTERIOR, &ENTROPIA, T_J),
            flujo_siguiente(&ENTROPIA, &FLUJO_ANTERIOR, T_J)
        );
    }
}
