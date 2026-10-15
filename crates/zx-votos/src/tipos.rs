//! Tipos de la tabla de poder y del hash de `zx-votos` (contrato v2 A4).
//!
//! **M9-b2:** aquí vivían los tipos del oráculo de plazas (`Caso`, `Voto`, `Motivo`, `Resultado`,
//! `Evidencia`…), retirados con la evaluación por plazas.

/// Longitud de un hash y de una salida VRF: 32 bytes (C-FV-11).
pub const LONGITUD_HASH: usize = 32;

/// Hash de 32 bytes (`SHA-256`, C-FV-11).
pub type Hash = [u8; LONGITUD_HASH];

/// Una clave registrada de la tabla de poder `T_n` (C-FV-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clave {
    /// Clave pública de voto `pk_i` (bytes; el contrato no fija su longitud).
    pub clave: Vec<u8>,
    /// Peso registrado `peso_i` (entero ≥ 0).
    pub peso: u64,
    /// `activo_i`: 1 si la clave sigue registrada (FV-D04).
    pub activo: bool,
    /// `prueba_i`: 1 si tiene prueba de disponibilidad vigente.
    pub prueba: bool,
    /// Garantía confiscable `garantia_i` (entero ≥ 0).
    pub garantia: u64,
}

/// Tabla de poder `T_n` de la instancia `n` (C-FV-02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tabla {
    /// Instancia a la que pertenece la tabla.
    pub n: u64,
    /// Claves registradas.
    pub claves: Vec<Clave>,
}
