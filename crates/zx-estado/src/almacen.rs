//! El rasgo de almacén y sus dos implementaciones de producción tras la misma interfaz.
//!
//! - [`Nodos`]: lectura y escritura de nodos del trie. Lo implementan el almacén en memoria, el de
//!   RocksDB y el [`Overlay`] que agrupa las escrituras de un lote.
//! - [`Almacen`]: la interfaz persistente (nodos, índice de hojas `(familia, clave) → h_valor` y
//!   raíz por familia) con **una** escritura atómica por lote ([`Almacen::commit`]).
//! - [`AlmacenEnMemoria`]: implementación de referencia, para pruebas y para el oráculo.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::camino::Camino;
use crate::error::Error;
use crate::hash::{Hash32, hash_vacio};

/// Lectura y escritura de nodos por su hash.
pub trait Nodos {
    /// Lee el nodo con ese hash; `None` si no existe.
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    fn leer(&self, h: &Hash32) -> Result<Option<Vec<u8>>, Error>;
    /// Escribe (o reemplaza) el nodo.
    ///
    /// # Errors
    /// Si el almacén no puede escribir.
    fn poner(&mut self, h: Hash32, v: Vec<u8>) -> Result<(), Error>;
    /// Borra el nodo de ese hash.
    ///
    /// # Errors
    /// Si el almacén no puede borrar.
    fn quitar(&mut self, h: Hash32) -> Result<(), Error>;
}

/// Almacén persistente del árbol de estado.
///
/// La actualización en lote vive en [`crate::lote`]: se calcula sobre un [`Overlay`] y se confirma
/// en **una** llamada a [`commit`](Almacen::commit), que es la escritura atómica por lote.
pub trait Almacen: Nodos + Send + Sync {
    /// `h_valor` guardado para `(familia, clave)`, si existe.
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    fn hoja(&self, familia: u8, clave: &[u8]) -> Result<Option<Hash32>, Error>;
    /// Raíz guardada de `familia` ([`hash_vacio`] si aún no hay árbol).
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    fn raiz(&self, familia: u8) -> Result<Hash32, Error>;
    /// Raíces guardadas de todas las familias con árbol.
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    fn raices(&self) -> Result<Vec<(u8, Hash32)>, Error>;
    /// Todas las hojas guardadas `(familia, clave, h_valor)`.
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    fn listar_hojas(&self) -> Result<Vec<(u8, Vec<u8>, Hash32)>, Error>;
    /// Confirma en **una** escritura atómica nodos, índice de hojas y raíces.
    ///
    /// # Errors
    /// Si el motor rechaza la escritura.
    fn commit(
        &mut self,
        nodos: &[(Hash32, Option<Vec<u8>>)],
        hojas: &[(u8, Vec<u8>, Option<Hash32>)],
        raices: &[(u8, Hash32)],
    ) -> Result<(), Error>;
    /// Vuelca lo pendiente a disco (no-op en memoria).
    ///
    /// # Errors
    /// Si el motor no puede volcar.
    fn sincronizar(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Overlay de escrituras pendientes sobre un almacén: las lecturas ven primero lo pendiente.
pub struct Overlay<'a, A: Almacen + ?Sized> {
    base: &'a A,
    ops: HashMap<Hash32, Option<Vec<u8>>>,
    creados: HashSet<Hash32>,
    lecturas_base: Cell<u64>,
    precarga: Option<&'a HashMap<Hash32, Vec<u8>>>,
    lecturas_precarga: Cell<u64>,
}

impl<'a, A: Almacen + ?Sized> Overlay<'a, A> {
    /// Crea el overlay sobre `base`.
    #[must_use]
    pub fn nuevo(base: &'a A) -> Self {
        Self {
            base,
            ops: HashMap::new(),
            creados: HashSet::new(),
            lecturas_base: Cell::new(0),
            precarga: None,
            lecturas_precarga: Cell::new(0),
        }
    }

    /// Crea el overlay sobre `base` con una caché de lectura precargada en paralelo.
    #[must_use]
    pub fn con_precarga(base: &'a A, precarga: &'a HashMap<Hash32, Vec<u8>>) -> Self {
        Self {
            base,
            ops: HashMap::new(),
            creados: HashSet::new(),
            lecturas_base: Cell::new(0),
            precarga: Some(precarga),
            lecturas_precarga: Cell::new(0),
        }
    }

    /// Escrituras pendientes: `None` es borrado.
    #[must_use]
    pub fn pendientes(&self) -> Vec<(Hash32, Option<Vec<u8>>)> {
        self.ops.iter().map(|(h, v)| (*h, v.clone())).collect()
    }

    /// Lecturas que fueron al almacén base, no al overlay ni a la precarga.
    #[must_use]
    pub fn lecturas_base(&self) -> u64 {
        self.lecturas_base.get()
    }

    /// Lecturas servidas por la caché precargada.
    #[must_use]
    pub fn lecturas_precarga(&self) -> u64 {
        self.lecturas_precarga.get()
    }
}

impl<A: Almacen + ?Sized> Nodos for Overlay<'_, A> {
    fn leer(&self, h: &Hash32) -> Result<Option<Vec<u8>>, Error> {
        if let Some(v) = self.ops.get(h) {
            return Ok(v.clone());
        }
        if let Some(precarga) = self.precarga
            && let Some(v) = precarga.get(h)
        {
            self.lecturas_precarga.set(self.lecturas_precarga.get() + 1);
            return Ok(Some(v.clone()));
        }
        self.lecturas_base.set(self.lecturas_base.get() + 1);
        self.base.leer(h)
    }

    fn poner(&mut self, h: Hash32, v: Vec<u8>) -> Result<(), Error> {
        self.ops.insert(h, Some(v));
        self.creados.insert(h);
        Ok(())
    }

    fn quitar(&mut self, h: Hash32) -> Result<(), Error> {
        // Si el nodo se creó dentro del mismo lote, nunca llegó al disco: no hay que borrarlo.
        if self.creados.remove(&h) {
            self.ops.remove(&h);
        } else {
            self.ops.insert(h, None);
        }
        Ok(())
    }
}

/// Almacén de referencia en memoria.
#[derive(Debug, Default)]
pub struct AlmacenEnMemoria {
    nodos: HashMap<Hash32, Vec<u8>>,
    hojas: BTreeMap<(u8, Vec<u8>), Hash32>,
    raices: BTreeMap<u8, Hash32>,
}

impl AlmacenEnMemoria {
    /// Almacén vacío.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Número de nodos guardados (hojas y nodos internos).
    #[must_use]
    pub fn contar_nodos(&self) -> usize {
        self.nodos.len()
    }
}

impl Nodos for AlmacenEnMemoria {
    fn leer(&self, h: &Hash32) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.nodos.get(h).cloned())
    }

    fn poner(&mut self, h: Hash32, v: Vec<u8>) -> Result<(), Error> {
        self.nodos.insert(h, v);
        Ok(())
    }

    fn quitar(&mut self, h: Hash32) -> Result<(), Error> {
        self.nodos.remove(&h);
        Ok(())
    }
}

impl Almacen for AlmacenEnMemoria {
    fn hoja(&self, familia: u8, clave: &[u8]) -> Result<Option<Hash32>, Error> {
        Ok(self.hojas.get(&(familia, clave.to_vec())).copied())
    }

    fn raiz(&self, familia: u8) -> Result<Hash32, Error> {
        Ok(self
            .raices
            .get(&familia)
            .copied()
            .unwrap_or_else(hash_vacio))
    }

    fn raices(&self) -> Result<Vec<(u8, Hash32)>, Error> {
        Ok(self.raices.iter().map(|(f, r)| (*f, *r)).collect())
    }

    fn listar_hojas(&self) -> Result<Vec<(u8, Vec<u8>, Hash32)>, Error> {
        Ok(self
            .hojas
            .iter()
            .map(|((f, k), h)| (*f, k.clone(), *h))
            .collect())
    }

    fn commit(
        &mut self,
        nodos: &[(Hash32, Option<Vec<u8>>)],
        hojas: &[(u8, Vec<u8>, Option<Hash32>)],
        raices: &[(u8, Hash32)],
    ) -> Result<(), Error> {
        for (h, v) in nodos {
            match v {
                Some(bytes) => {
                    self.nodos.insert(*h, bytes.clone());
                }
                None => {
                    self.nodos.remove(h);
                }
            }
        }
        for (f, k, v) in hojas {
            match v {
                Some(hv) => {
                    self.hojas.insert((*f, k.clone()), *hv);
                }
                None => {
                    self.hojas.remove(&(*f, k.clone()));
                }
            }
        }
        for (f, r) in raices {
            self.raices.insert(*f, *r);
        }
        Ok(())
    }
}

/// Reconstruye el árbol de una familia del almacén `a` y devuelve su raíz (oráculo desde cero).
///
/// # Errors
/// Si el almacén no puede leer o el árbol reconstruido no cabe en el formato.
pub fn reconstruir_familia<A: Almacen + ?Sized, C: Camino + ?Sized>(
    a: &A,
    c: &C,
    familia: u8,
) -> Result<Hash32, Error> {
    let entradas: Vec<(Vec<u8>, Hash32)> = a
        .listar_hojas()?
        .into_iter()
        .filter(|(f, _, _)| *f == familia)
        .map(|(_, k, h)| (k, h))
        .collect();
    let mut memoria = AlmacenEnMemoria::nuevo();
    crate::arbol::reconstruir(c, &mut memoria, familia, &entradas)
}
