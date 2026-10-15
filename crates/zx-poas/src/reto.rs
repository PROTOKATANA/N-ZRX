//! Reto de auditoría derivado de la salida de un slot PoT (`C-POT-03`).
//!
//! # Qué es
//!
//! [`reto_desde_salida`] reproduce la ruta pura que usaba `zx-consensus::pot` en `9681061`:
//!
//! ```text
//! aleatoriedad(f, s) = blake3(salida(f, s))                       (32 B)
//! reto(f, s)         = blake3(aleatoriedad(f, s) ‖ LE64(s))       (32 B)
//! ```
//!
//! Es el valor de 32 B que consume `audit_plot_sync` y que `verify_solution` de Autonomys
//! reconstruye internamente (allí `PotOutput::derive_global_randomness().derive_global_challenge(slot)`,
//! que es el mismo cálculo). Vive en `zx-poas` porque `zx-farmer` (auditoría) solo puede depender
//! de `zx-poas` y `zx-core` (§3.2, §6 V8), y es un hash **puro** de sus argumentos, no una
//! verificación PoT: no hay AES, ni flujo, ni `N(s)`, ni cabecera.
//!
//! # Lo que NO acredita
//!
//! `salida` y `slot` llegan como argumentos libres. Esta función comprueba la forma del hash y la
//! codificación little-endian, pero **no** que la salida provenga de la cadena secuencial del PoT
//! hasta `s` ni que `s` sea el slot del candidato. Esa procedencia contextual es de W05b2; aquí
//! los valores son de prueba.

use zx_core::wire_dag::POT_OUTPUT_BYTES;

/// Longitud del reto y de la aleatoriedad, en bytes.
pub const ALEATORIEDAD_BYTES: usize = 32;

/// `aleatoriedad(f, s) = blake3(salida(f, s))` (`C-POT-03`), 32 B.
///
/// Es una fórmula pura: **no acredita** que la salida venga de la cadena secuencial hasta `s`.
#[must_use]
pub fn aleatoriedad_de_salida(salida: [u8; POT_OUTPUT_BYTES]) -> [u8; ALEATORIEDAD_BYTES] {
    blake3::hash(&salida).into()
}

/// `reto(f, s) = blake3(aleatoriedad(f, s) ‖ LE64(s))` (`C-POT-03`), 32 B.
///
/// Calcula la aleatoriedad **dentro de esta ruta**; no acepta una aleatoriedad precalculada ni
/// ofrece un atajo del tipo `blake3(salida ‖ slot)`. La concatenación es explícita (40 B) y sin
/// `unsafe`.
///
/// # Lo que NO acredita
///
/// `salida` y `slot` son argumentos libres: por sí sola **no impide saltarse slots**. Ver la
/// cabecera del módulo.
#[must_use]
pub fn reto_desde_salida(salida: [u8; POT_OUTPUT_BYTES], slot: u64) -> [u8; ALEATORIEDAD_BYTES] {
    let aleatoriedad = aleatoriedad_de_salida(salida);

    // Concatenación explícita de 40 B: aleatoriedad primero, `LE64(slot)` después.
    let mut buffer = [0u8; ALEATORIEDAD_BYTES + 8];
    let (primera, segunda) = buffer.split_at_mut(ALEATORIEDAD_BYTES);
    primera.copy_from_slice(&aleatoriedad);
    segunda.copy_from_slice(&slot.to_le_bytes());

    blake3::hash(&buffer).into()
}

#[cfg(test)]
mod tests {
    use super::{ALEATORIEDAD_BYTES, aleatoriedad_de_salida, reto_desde_salida};

    #[test]
    fn el_reto_es_blake3_de_aleatoriedad_mas_slot_le() {
        let salida = [0x5a; 16];
        let slot = 7_u64;
        let aleatoriedad = aleatoriedad_de_salida(salida);
        assert_eq!(aleatoriedad, *blake3::hash(&salida).as_bytes());

        let mut buffer = [0u8; ALEATORIEDAD_BYTES + 8];
        let (primera, segunda) = buffer.split_at_mut(ALEATORIEDAD_BYTES);
        primera.copy_from_slice(&aleatoriedad);
        segunda.copy_from_slice(&slot.to_le_bytes());
        assert_eq!(
            reto_desde_salida(salida, slot),
            *blake3::hash(&buffer).as_bytes()
        );
    }

    #[test]
    fn el_slot_cambia_el_reto_y_la_salida_tambien() {
        let a = reto_desde_salida([1u8; 16], 0);
        assert_ne!(a, reto_desde_salida([1u8; 16], 1));
        assert_ne!(a, reto_desde_salida([2u8; 16], 0));
    }
}
