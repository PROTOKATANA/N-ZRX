//! Pruebas de pertenencia y de no pertenencia, y su verificador.
//!
//! Formato (`RAIZ-ESTADO.md` §5.1): familia, clave, camino de hermanos (de la raíz a la hoja),
//! profundidades de bifurcación y terminal (hoja con su lista de colisión, o subárbol vacío). El
//! verificador solo necesita la raíz de la familia, la familia, la clave, el valor (o su ausencia)
//! y la prueba.

use crate::almacen::Almacen;
use crate::camino::Camino;
use crate::error::Error;
use crate::hash::{Hash32, bit, hash_hoja, hash_hoja_lista, hash_nodo, hash_vacio, hash_valor};
use crate::nodo::{Nodo, decodificar};

/// Profundidad máxima del trie por la cota de 56 bits del camino.
pub const MAX_NIVELES: usize = 56;

/// Tamaño máximo de una prueba codificada, en bytes: el techo de 2 KB del diseño
/// (`RAIZ-ESTADO.md` §5.5, peor caso por la cota de 56 bits y claves de hasta 40 B).
pub const TAMANO_MAXIMO_PRUEBA: usize = 2048;

/// Terminal de una prueba.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminal {
    /// Hoja con su lista de colisión (una o más entradas `clave → h_valor`).
    Hoja(Vec<(Vec<u8>, Hash32)>),
    /// Subárbol vacío: la familia no tiene árbol o el camino termina en vacío.
    Vacio,
}

/// Prueba de pertenencia (la clave está en la hoja) o de no pertenencia (no está).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prueba {
    /// Familia del estado.
    pub familia: u8,
    /// Clave consultada.
    pub clave: Vec<u8>,
    /// Hermanos, de la raíz a la hoja.
    pub camino: Vec<Hash32>,
    /// Profundidad de bifurcación de cada hermano, paralela a `camino`.
    pub split_depths: Vec<u16>,
    /// Terminal alcanzado por el camino.
    pub terminal: Terminal,
}

impl Prueba {
    /// Codifica la prueba.
    ///
    /// # Errors
    /// Si una longitud no cabe en el formato.
    pub fn codificar(&self) -> Result<Vec<u8>, Error> {
        let mut salida = Vec::with_capacity(TAMANO_MAXIMO_PRUEBA);
        salida.push(self.familia);
        let len = u32::try_from(self.clave.len()).map_err(|_| Error::LongitudFueraDeRango)?;
        salida.extend_from_slice(&len.to_be_bytes());
        salida.extend_from_slice(&self.clave);
        let n = u16::try_from(self.camino.len()).map_err(|_| Error::LongitudFueraDeRango)?;
        salida.extend_from_slice(&n.to_be_bytes());
        for (sib, split) in self.camino.iter().zip(self.split_depths.iter()) {
            salida.extend_from_slice(&split.to_be_bytes());
            salida.extend_from_slice(sib);
        }
        match &self.terminal {
            Terminal::Vacio => salida.push(0x00),
            Terminal::Hoja(entradas) => {
                salida.push(0x01);
                let n = u32::try_from(entradas.len()).map_err(|_| Error::LongitudFueraDeRango)?;
                salida.extend_from_slice(&n.to_be_bytes());
                for (clave, h_valor) in entradas {
                    let len =
                        u32::try_from(clave.len()).map_err(|_| Error::LongitudFueraDeRango)?;
                    salida.extend_from_slice(&len.to_be_bytes());
                    salida.extend_from_slice(clave);
                    salida.extend_from_slice(h_valor);
                }
            }
        }
        Ok(salida)
    }

    /// Tamaño de la prueba codificada, en bytes.
    ///
    /// # Errors
    /// Si una longitud no cabe en el formato.
    pub fn tamano(&self) -> Result<usize, Error> {
        self.codificar().map(|v| v.len())
    }
}

/// Genera la prueba de `clave` en `familia` contra el árbol del almacén.
///
/// # Errors
/// Si falta un nodo del camino o hay bytes mal formados en el almacén.
pub fn prueba<A: Almacen + ?Sized, C: Camino + ?Sized>(
    a: &A,
    c: &C,
    familia: u8,
    clave: &[u8],
) -> Result<Prueba, Error> {
    let p = c.camino(familia, clave);
    let mut camino = Vec::new();
    let mut split_depths = Vec::new();
    let mut actual = a.raiz(familia)?;
    loop {
        if actual == hash_vacio() {
            return Ok(Prueba {
                familia,
                clave: clave.to_vec(),
                camino,
                split_depths,
                terminal: Terminal::Vacio,
            });
        }
        let bytes = a.leer(&actual)?.ok_or(Error::NodoAusente(actual))?;
        match decodificar(&bytes)? {
            Nodo::Interno { split, izq, der } => {
                if split_depths.len() >= MAX_NIVELES {
                    return Err(Error::PruebaInvalida);
                }
                let es_izq = bit(&p, split) == 0;
                let (hijo, sib) = if es_izq { (izq, der) } else { (der, izq) };
                camino.push(sib);
                split_depths.push(split);
                actual = hijo;
            }
            Nodo::Hoja(h) => {
                return Ok(Prueba {
                    familia,
                    clave: clave.to_vec(),
                    camino,
                    split_depths,
                    terminal: Terminal::Hoja(h.entradas),
                });
            }
        }
    }
}

fn h_valor_de_terminal(terminal: &Terminal, clave: &[u8]) -> Option<Hash32> {
    match terminal {
        Terminal::Hoja(entradas) => entradas
            .iter()
            .find(|(k, _)| k.as_slice() == clave)
            .map(|(_, h)| *h),
        Terminal::Vacio => None,
    }
}

/// Verifica una prueba contra `raiz`.
///
/// `valor = Some(v)` exige **pertenencia** con ese valor; `valor = None` exige **no pertenencia**.
/// Devuelve `false` ante cualquier prueba mal formada o que no cuadre con la raíz.
#[must_use]
pub fn verificar<C: Camino + ?Sized>(
    c: &C,
    raiz: &Hash32,
    familia: u8,
    clave: &[u8],
    valor: Option<&[u8]>,
    prueba: &Prueba,
) -> bool {
    // El verificador comprueba que la prueba es de la familia y la clave consultadas.
    if prueba.familia != familia {
        return false;
    }
    if prueba.clave.as_slice() != clave {
        return false;
    }
    if prueba.camino.len() != prueba.split_depths.len() {
        return false;
    }
    if prueba.camino.len() > MAX_NIVELES {
        return false;
    }
    let mut anterior: Option<u16> = None;
    for split in &prueba.split_depths {
        if *split >= 56 {
            return false;
        }
        if let Some(a) = anterior
            && *split <= a
        {
            return false;
        }
        anterior = Some(*split);
    }

    let (h_hoja, presente) = match &prueba.terminal {
        Terminal::Vacio => (hash_vacio(), false),
        Terminal::Hoja(entradas) => {
            if entradas.is_empty() {
                return false;
            }
            let h = if let [(k, hv)] = entradas.as_slice() {
                hash_hoja(familia, k, hv)
            } else {
                hash_hoja_lista(familia, entradas)
            };
            let presente = entradas.iter().any(|(k, _)| k.as_slice() == clave);
            (h, presente)
        }
    };

    match valor {
        Some(v) => {
            let Some(hv) = h_valor_de_terminal(&prueba.terminal, clave) else {
                return false;
            };
            if hash_valor(v) != hv {
                return false;
            }
        }
        None => {
            if presente {
                return false;
            }
        }
    }

    let p = c.camino(familia, clave);
    let mut h = h_hoja;
    for (sib, split) in prueba.camino.iter().zip(prueba.split_depths.iter()).rev() {
        h = if bit(&p, *split) == 0 {
            hash_nodo(*split, &h, sib)
        } else {
            hash_nodo(*split, sib, &h)
        };
    }
    h == *raiz
}
