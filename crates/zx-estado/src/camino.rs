//! Función de camino (56 bits) de una clave dentro de una familia.
//!
//! El camino real es `primeros 7 bytes de clave_arbol` (SHA3-256 con dominio). El rasgo permite
//! inyectar otra función de camino en las pruebas: así se fuerzan colisiones de 56 bits y cadenas
//! de profundidad máxima sin depender de encontrar una colisión real de SHA3.

use crate::hash;

/// Camino de 56 bits de una clave.
pub trait Camino: Send + Sync {
    /// Devuelve los 7 bytes de camino de `clave` en `familia`.
    fn camino(&self, familia: u8, clave: &[u8]) -> [u8; 7];
}

/// Camino real del diseño: `primeros 7 bytes de h_d("ZXEstadoClave1", familia ‖ clave)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CaminoSha3;

impl Camino for CaminoSha3 {
    fn camino(&self, familia: u8, clave: &[u8]) -> [u8; 7] {
        hash::camino(familia, clave)
    }
}
