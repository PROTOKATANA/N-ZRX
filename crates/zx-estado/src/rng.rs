//! Generador determinista SplitMix64 para pruebas y medidas.
//!
//! Semilla explícita, nunca aleatoriedad del sistema (`LINEO.md` §7): todo dato de prueba o banco se
//! deriva de `(semilla_maestra, índice)`. No es criptográfico.

use crate::hash::Hash32;

/// Generador SplitMix64.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    estado: u64,
}

impl SplitMix64 {
    /// Crea el generador con una semilla.
    #[must_use]
    pub fn nuevo(semilla: u64) -> Self {
        Self { estado: semilla }
    }

    /// Siguiente entero de 64 bits.
    pub fn siguiente(&mut self) -> u64 {
        self.estado = self.estado.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.estado;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Rellena 32 bytes reproducibles.
    pub fn bytes32(&mut self) -> Hash32 {
        let mut salida = [0u8; 32];
        for trozo in salida.chunks_exact_mut(8) {
            trozo.copy_from_slice(&self.siguiente().to_le_bytes());
        }
        salida
    }

    /// Entero en `0..n` (sin sesgo apreciable por rechazo simple).
    pub fn hasta(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.siguiente() % n
    }
}
