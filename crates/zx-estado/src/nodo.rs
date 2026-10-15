//! Codificación de los nodos del trie: hoja (con lista de colisión) y nodo interno.
//!
//! Formato (`RAIZ-ESTADO.md` §3.2):
//!
//! ```text
//! interno = 0x00 ‖ split(2 BE) ‖ izq(32) ‖ der(32)                      # 67 B
//! hoja    = 0x01 ‖ familia(1) ‖ n(4 BE) ‖ n × (len(4 BE) ‖ clave ‖ h_valor(32))
//! ```
//!
//! La lista `n > 1` cubre la colisión de 56 bits del camino (`RAIZ-ESTADO.md` §3.1, §8.6): dos
//! claves distintas con el mismo camino comparten hoja y no pierden ni mezclan datos.

use crate::error::Error;
use crate::hash::{Hash32, hash_hoja, hash_hoja_lista};

/// Marca de byte del nodo interno.
pub const B_INTERNO: u8 = 0x00;
/// Marca de byte de la hoja.
pub const B_HOJA: u8 = 0x01;

/// Longitud fija de un nodo interno codificado.
pub const LONGITUD_INTERNO: usize = 67;

/// Hoja del trie: familia y lista ordenada de `(clave_canonica, h_valor)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hoja {
    /// Familia del estado.
    pub familia: u8,
    /// Entradas ordenadas por `clave_canonica`.
    pub entradas: Vec<(Vec<u8>, Hash32)>,
}

impl Hoja {
    /// Hoja de una sola entrada.
    #[must_use]
    pub fn nueva(familia: u8, clave: Vec<u8>, h_valor: Hash32) -> Self {
        Self {
            familia,
            entradas: vec![(clave, h_valor)],
        }
    }

    /// Hash de la hoja: una entrada usa `hash_hoja`; varias, `hash_hoja_lista`.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        if let [(clave, h_valor)] = self.entradas.as_slice() {
            hash_hoja(self.familia, clave, h_valor)
        } else {
            hash_hoja_lista(self.familia, &self.entradas)
        }
    }

    /// `h_valor` de `clave`, si la hoja la contiene.
    #[must_use]
    pub fn contiene(&self, clave: &[u8]) -> Option<Hash32> {
        self.entradas
            .iter()
            .find(|(k, _)| k.as_slice() == clave)
            .map(|(_, h)| *h)
    }

    /// Inserta o actualiza `(clave, h_valor)` manteniendo el orden por clave.
    pub fn insertar(&mut self, clave: Vec<u8>, h_valor: Hash32) {
        match self
            .entradas
            .binary_search_by(|(k, _)| k.as_slice().cmp(clave.as_slice()))
        {
            Ok(pos) => {
                if let Some(e) = self.entradas.get_mut(pos) {
                    e.1 = h_valor;
                }
            }
            Err(pos) => self.entradas.insert(pos, (clave, h_valor)),
        }
    }

    /// Borra `clave`; devuelve `true` si estaba.
    pub fn quitar(&mut self, clave: &[u8]) -> bool {
        match self
            .entradas
            .binary_search_by(|(k, _)| k.as_slice().cmp(clave))
        {
            Ok(pos) => {
                self.entradas.remove(pos);
                true
            }
            Err(_) => false,
        }
    }

    /// Codifica la hoja.
    ///
    /// # Errors
    /// Si una clave o el número de entradas no caben en `u32`.
    pub fn codificar(&self) -> Result<Vec<u8>, Error> {
        let n = u32::try_from(self.entradas.len()).map_err(|_| Error::LongitudFueraDeRango)?;
        let mut salida = Vec::with_capacity(6 + self.entradas.len() * 70);
        salida.push(B_HOJA);
        salida.push(self.familia);
        salida.extend_from_slice(&n.to_be_bytes());
        for (clave, h_valor) in &self.entradas {
            let len = u32::try_from(clave.len()).map_err(|_| Error::LongitudFueraDeRango)?;
            salida.extend_from_slice(&len.to_be_bytes());
            salida.extend_from_slice(clave);
            salida.extend_from_slice(h_valor);
        }
        Ok(salida)
    }
}

/// Nodo decodificado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nodo {
    /// Nodo interno: primer bit en que difieren las hojas del subárbol y sus dos hijos.
    Interno {
        /// Primer bit en que difieren las hojas del subárbol (`0..56`).
        split: u16,
        /// Hash del hijo izquierdo.
        izq: Hash32,
        /// Hash del hijo derecho.
        der: Hash32,
    },
    /// Hoja terminal.
    Hoja(Hoja),
}

/// Codifica un nodo interno.
#[must_use]
pub fn codificar_interno(split: u16, izq: &Hash32, der: &Hash32) -> Vec<u8> {
    let mut salida = Vec::with_capacity(LONGITUD_INTERNO);
    salida.push(B_INTERNO);
    salida.extend_from_slice(&split.to_be_bytes());
    salida.extend_from_slice(izq);
    salida.extend_from_slice(der);
    salida
}

/// Decodifica un nodo; bytes mal formados dan [`Error::NodoMalFormado`].
///
/// # Errors
/// Si los bytes no son un nodo interno de 67 B ni una hoja autodelimitada y exacta.
pub fn decodificar(bytes: &[u8]) -> Result<Nodo, Error> {
    match bytes.first().copied() {
        Some(B_INTERNO) => {
            if bytes.len() != LONGITUD_INTERNO {
                return Err(Error::NodoMalFormado);
            }
            let split = u16::from_be_bytes(
                bytes
                    .get(1..3)
                    .and_then(|s| s.try_into().ok())
                    .ok_or(Error::NodoMalFormado)?,
            );
            let izq: Hash32 = bytes
                .get(3..35)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::NodoMalFormado)?;
            let der: Hash32 = bytes
                .get(35..67)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::NodoMalFormado)?;
            Ok(Nodo::Interno { split, izq, der })
        }
        Some(B_HOJA) => {
            let familia = *bytes.get(1).ok_or(Error::NodoMalFormado)?;
            let n = u32::from_be_bytes(
                bytes
                    .get(2..6)
                    .and_then(|s| s.try_into().ok())
                    .ok_or(Error::NodoMalFormado)?,
            );
            let n = usize::try_from(n).map_err(|_| Error::NodoMalFormado)?;
            let mut entradas = Vec::with_capacity(n);
            let mut off = 6usize;
            for _ in 0..n {
                let len = u32::from_be_bytes(
                    bytes
                        .get(off..off.saturating_add(4))
                        .and_then(|s| s.try_into().ok())
                        .ok_or(Error::NodoMalFormado)?,
                );
                let len = usize::try_from(len).map_err(|_| Error::NodoMalFormado)?;
                off = off.saturating_add(4);
                let fin = off.checked_add(len).ok_or(Error::NodoMalFormado)?;
                let clave = bytes.get(off..fin).ok_or(Error::NodoMalFormado)?.to_vec();
                off = fin;
                let h_valor: Hash32 = bytes
                    .get(off..off.saturating_add(32))
                    .and_then(|s| s.try_into().ok())
                    .ok_or(Error::NodoMalFormado)?;
                off = off.saturating_add(32);
                entradas.push((clave, h_valor));
            }
            if off != bytes.len() {
                return Err(Error::NodoMalFormado);
            }
            Ok(Nodo::Hoja(Hoja { familia, entradas }))
        }
        _ => Err(Error::NodoMalFormado),
    }
}
