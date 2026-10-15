//! Cajas de sectores (`C-CAJA-01…14`) — tipos canónicos, árbol Merkle y utilidades puras.
//!
//! `SR-G2b` implementa las reglas de `SRG2a/CONTRATO-CAJAS-v0.md` con las decisiones del
//! orquestador (`REVISION-SRG2a.md`): (1) añadir un sector exige que el anterior de la caja haya
//! madurado (`slot ≥ ultima_alta_slot + M_sec`); (2) el hueco retirado no se rellena y el retiro es
//! de **caja entera** (`EV-24(i)+(ii)`).
//!
//! Este módulo es **puro** (no depende de [`crate::transicion::Estado`]): identidad y estados de la
//! caja ([`CajaId`], [`EtapaCaja`], [`RegistroCaja`]), el árbol Merkle de `capacidad_caja` hojas y
//! las rutas de prueba. La aplicación al estado de consenso vive en
//! [`crate::transicion::caja`].
//!
//! **Nota de alcance (D-2).** Como el estado conserva el registro por sector de SR-1-2, la caja
//! guarda un índice compacto `huecos[j] = (sector_index, version)` y **reconstruye** las hojas
//! `R2` desde [`crate::sectores::RegistroSector`]; la entrada canónica de 132 B de `C-CAJA-02` no
//! incluye ese índice (falta de definición declarada en `PROGRESO.md` §1).

#![expect(
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "árbol Merkle de tamaño fijo (potencia de dos): índices acotados por construcción"
)]

use zx_core::{ClavePublica, sha3_256_publico};

use crate::sectores::R2;

/// Capacidad máxima de una caja (`PK-14`): 16 sectores de 1 GiB.
pub const CAPACIDAD_MAX: usize = 16;

/// Marca de «no aplica» para slots (coincide con [`crate::sectores::NO_HAY`]).
pub const NO_HAY: i64 = -1;

/// Identidad de una caja (`C-CAJA-01`): `(clave, seq)`, con `seq` asignado por un contador por clave.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CajaId {
    /// Dueño de la caja.
    pub clave: ClavePublica,
    /// Contador por clave (`1,2,3,…`); el granjero no lo elige.
    pub seq: u32,
}

/// Cajas de una clave en orden de `CajaId`, incluidos `seq = 0` y `u32::MAX`.
/// El orden derivado compara primero la `ClavePublica` completa y luego `seq`.
pub(crate) fn cajas_de_clave<'a>(
    cajas: &'a std::collections::BTreeMap<CajaId, RegistroCaja>,
    clave: &ClavePublica,
) -> std::collections::btree_map::Range<'a, CajaId, RegistroCaja> {
    cajas.range(
        CajaId {
            clave: *clave,
            seq: 0,
        }..=CajaId {
            clave: *clave,
            seq: u32::MAX,
        },
    )
}

/// Etapa **almacenada** de la caja (`C-CAJA-01`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EtapaCaja {
    /// Admite añadidos.
    Abierta = 0,
    /// Raíz congelada; no admite añadidos.
    Cerrada = 1,
    /// Fianza retenida, a la espera de `EV-24(i)+(ii)`.
    EnRetirada = 2,
    /// Fianza liberada.
    Retirada = 3,
}

/// Código de 2 bits del estado de un hueco almacenado en `estado_hueco` (`C-CAJA-02`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EstadoHueco {
    /// Hueco libre.
    Libre = 0,
    /// Ocupado pero aún no maduro.
    Comprometido = 1,
    /// Ocupado y activo.
    Activo = 2,
    /// Ocupado y suspendido.
    Suspendido = 3,
}

impl EstadoHueco {
    /// Código de 2 bits.
    #[must_use]
    pub const fn codigo(self) -> u32 {
        self as u32
    }

    /// Lee el código de un hueco `j` (0-based) de la máscara `estado_hueco`.
    #[must_use]
    pub const fn de_mascara(mascara: u32, j: usize) -> u32 {
        (mascara >> (2 * j)) & 0b11
    }

    /// Escribe el código de un hueco `j` (0-based) en la máscara `estado_hueco`.
    #[must_use]
    pub const fn poner(mascara: u32, j: usize, v: u32) -> u32 {
        let limpio = mascara & !(0b11u32 << (2 * j));
        limpio | ((v & 0b11) << (2 * j))
    }
}

/// Ocupante de un hueco: solo `(sector_index, version)`; la clave es la de la caja (`D-2`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ocupante {
    /// Índice de sector del ocupante.
    pub sector_index: u16,
    /// Versión del ocupante.
    pub version: u32,
    /// `false` si el hueco está libre.
    pub ocupado: bool,
}

/// Hueco libre.
pub const HUECO_LIBRE: Ocupante = Ocupante {
    sector_index: u16::MAX,
    version: 0,
    ocupado: false,
};

/// Registro canónico de una caja (`C-CAJA-02`).
///
/// Los campos escalares son los de la entrada propuesta de 132 B; `huecos` es el índice compacto
/// que `D-2` exige para localizar un sector y reconstruir la raíz. `raiz`, `n` y `ocupacion` se
/// mantienen coherentes con `huecos` (invariante `I-CAJA-4`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistroCaja {
    /// Identidad.
    pub id: CajaId,
    /// Raíz Merkle de las hojas de la caja (32 B).
    pub raiz: R2,
    /// Huecos ocupados (`0..=capacidad_caja`).
    pub n: u8,
    /// Máscara de huecos ocupados (bit `j-1` = hueco `j`).
    pub ocupacion: u16,
    /// 2 bits por hueco ([`EstadoHueco`]).
    pub estado_hueco: u32,
    /// `history_size`, único para toda la caja (`C-CAJA-04.3`).
    pub history_size: u64,
    /// Etapa.
    pub etapa: EtapaCaja,
    /// Slot de apertura.
    pub alta_slot: i64,
    /// Slot del último añadido (regla de madurez del orquestador).
    pub ultima_alta_slot: i64,
    /// Slot de cierre (`NO_HAY` si sigue abierta).
    pub cierre_slot: i64,
    /// Slot desde el que cuenta `T_cad` (nivel de caja).
    pub renovacion_slot: i64,
    /// Slot de retirada (`NO_HAY` si no está en retirada).
    pub retiro_slot: i64,
    /// Fianza retenida por los huecos no terminales (caché de `fianza_caja`).
    pub fianza: i64,
    /// Índice compacto hueco → ocupante.
    pub huecos: [Ocupante; CAPACIDAD_MAX],
}

impl RegistroCaja {
    /// Caja recién abierta, sin huecos.
    #[must_use]
    pub fn nueva(id: CajaId, history_size: u64, slot: i64) -> Self {
        Self {
            id,
            raiz: raiz_vacia(1),
            n: 0,
            ocupacion: 0,
            estado_hueco: 0,
            history_size,
            etapa: EtapaCaja::Abierta,
            alta_slot: slot,
            ultima_alta_slot: slot,
            cierre_slot: NO_HAY,
            renovacion_slot: NO_HAY,
            retiro_slot: NO_HAY,
            fianza: 0,
            huecos: [HUECO_LIBRE; CAPACIDAD_MAX],
        }
    }

    /// ¿Es terminal (fianza liberada)?
    #[must_use]
    pub const fn es_terminal(&self) -> bool {
        matches!(self.etapa, EtapaCaja::Retirada)
    }
}

// ---------------------------------------------------------------------------
// Árbol Merkle (C-CAJA-02)
// ---------------------------------------------------------------------------

/// Mezcla `splitmix64` usada por el nodo interno (idéntica a la del oráculo SR-G2a).
#[inline]
#[must_use]
pub fn mezcla(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Nodo interno `H(a ‖ b)` de la caja.
#[must_use]
pub fn combinar(a: R2, b: R2) -> R2 {
    let mut s = 0u64;
    for v in a {
        s = mezcla(s ^ v);
    }
    for v in b {
        s = mezcla(s ^ v);
    }
    [s, mezcla(s ^ 1), mezcla(s ^ 2), mezcla(s ^ 3)]
}

/// `R2` a partir de los 32 B de un `Digest` (4 palabras little-endian).
#[must_use]
pub fn digest_a_r2(d: zx_core::Digest) -> R2 {
    let b = d.as_bytes();
    let mut out = [0u64; 4];
    for (i, w) in out.iter_mut().enumerate() {
        let mut ocho = [0u8; 8];
        ocho.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(ocho);
    }
    out
}

/// Bytes de un `R2` (32 B little-endian).
#[must_use]
pub fn r2_a_bytes(r2: R2) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in r2.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Hoja de un hueco **ocupado**: `H(0x00 ‖ R2_j)` (dominio separado, `C-CAJA-02`).
#[must_use]
pub fn hoja_ocupada(r2: R2) -> R2 {
    let mut msg = [0u8; 33];
    msg[0] = 0x00;
    msg[1..].copy_from_slice(&r2_a_bytes(r2));
    digest_a_r2(sha3_256_publico(&msg))
}

/// Hoja de un hueco **libre**: `H(0x01)`.
#[must_use]
pub fn hoja_libre() -> R2 {
    digest_a_r2(sha3_256_publico(&[0x01]))
}

/// Raíz Merkle de una lista de hojas de tamaño potencia de dos (`≥ 1`).
///
/// # Panics
/// No entra en pánico: si la lista estuviera vacía devuelve [`raiz_vacia`] de 1 hoja; el llamante
/// la construye siempre de tamaño `capacidad_caja ∈ {1,16}`.
#[must_use]
pub fn raiz_merkle(hojas: &[R2]) -> R2 {
    if hojas.is_empty() {
        return hoja_libre();
    }
    let mut nivel = hojas.to_vec();
    while nivel.len() > 1 {
        let mut siguiente = Vec::with_capacity(nivel.len() / 2);
        let mut k = 0usize;
        while k + 1 < nivel.len() {
            siguiente.push(combinar(nivel[k], nivel[k + 1]));
            k += 2;
        }
        // Longitud impar: se propaga la última (no ocurre con potencias de dos).
        if k < nivel.len() {
            siguiente.push(nivel[k]);
        }
        nivel = siguiente;
    }
    nivel[0]
}

/// Raíz de una caja vacía de `cap` hojas.
#[must_use]
pub fn raiz_vacia(cap: usize) -> R2 {
    let hojas = vec![hoja_libre(); cap.max(1)];
    raiz_merkle(&hojas)
}

/// Ruta Merkle (hermanos) de la hoja `j` (**1-based**) hasta la raíz.
#[must_use]
pub fn ruta_merkle(hojas: &[R2], j: usize) -> Vec<R2> {
    let mut idx = j;
    let mut nivel = hojas.to_vec();
    let mut ruta = Vec::new();
    while nivel.len() > 1 {
        let par = if idx % 2 == 1 { idx + 1 } else { idx - 1 };
        ruta.push(nivel[par - 1]);
        let mut siguiente = Vec::with_capacity(nivel.len() / 2);
        let mut k = 0usize;
        while k + 1 < nivel.len() {
            siguiente.push(combinar(nivel[k], nivel[k + 1]));
            k += 2;
        }
        if k < nivel.len() {
            siguiente.push(nivel[k]);
        }
        nivel = siguiente;
        idx = idx.div_ceil(2);
    }
    ruta
}

/// Verifica la ruta de la hoja `j` (**1-based**) contra `raiz`.
#[must_use]
pub fn verificar_prueba(raiz: R2, j: usize, hoja: R2, ruta: &[R2]) -> bool {
    let mut idx = j;
    let mut actual = hoja;
    for h in ruta {
        actual = if idx % 2 == 1 {
            combinar(actual, *h)
        } else {
            combinar(*h, actual)
        };
        idx = idx.div_ceil(2);
    }
    actual == raiz
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_16_rutas_verifican_y_tamper_no() {
        let cap = 16usize;
        let hojas: Vec<R2> = (1..=cap as u64)
            .map(|k| combinar([k, k + 1, 2 * k, 3 * k], hoja_libre()))
            .collect();
        let raiz = raiz_merkle(&hojas);
        for j in 1..=cap {
            let ruta = ruta_merkle(&hojas, j);
            assert_eq!(ruta.len(), 4);
            assert!(verificar_prueba(raiz, j, hojas[j - 1], &ruta));
        }
        let mut malas = hojas.clone();
        malas[0] = combinar(malas[0], hoja_libre());
        assert!(!verificar_prueba(
            raiz,
            1,
            malas[0],
            &ruta_merkle(&hojas, 1)
        ));
    }

    #[test]
    fn merkle_1_hoja() {
        let raiz = hoja_ocupada([7, 8, 9, 10]);
        assert!(verificar_prueba(raiz, 1, hoja_ocupada([7, 8, 9, 10]), &[]));
        assert!(!verificar_prueba(raiz, 1, hoja_ocupada([1, 2, 3, 4]), &[]));
    }
}
