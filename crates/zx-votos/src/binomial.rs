//! Peso **efectivo** de una clave y peso total de una tabla (contrato v2 A1).
//!
//! `w_i = peso_i·(1 + (b−1)·prueba_i)` y `W = Σ_{activo} w_i`, con enteros de precisión arbitraria
//! (nada de `Float64` para umbrales, LINEO §5.3).
//!
//! **M9-b2:** aquí vivía el reparto R-prop de plazas (`plazas_rprop`, `plazas_de`, `CacheSorteo`,
//! `umbral_quorum`), retirado con la evaluación por plazas. Solo se conserva lo que usa `peso.rs`.

use num_bigint::BigUint;
use num_traits::Zero;

use crate::error::ErrorVotos;
use crate::tipos::{Clave, Tabla};

/// Peso efectivo `w_i = peso_i·(1 + (b−1)·prueba_i)` (C-FV-01.3).
///
/// # Errores
/// No desborda: el producto se hace con enteros de precisión arbitraria.
pub fn peso_efectivo(clave: &Clave, b: u64) -> Result<BigUint, ErrorVotos> {
    let factor = if clave.prueba { b } else { 1 };
    let mut peso = BigUint::from(clave.peso);
    if factor != 1 {
        peso *= BigUint::from(factor);
    }
    Ok(peso)
}

/// Peso efectivo total `W = Σ_{activo_i=1} w_i` (C-FV-01.4).
///
/// # Errores
/// No desborda (precisión arbitraria).
pub fn peso_total(tabla: &Tabla, b: u64) -> Result<BigUint, ErrorVotos> {
    let mut total = BigUint::zero();
    for clave in &tabla.claves {
        if clave.activo {
            total += peso_efectivo(clave, b)?;
        }
    }
    Ok(total)
}
