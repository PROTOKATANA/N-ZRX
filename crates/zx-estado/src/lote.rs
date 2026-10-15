//! Lote de cambios: orden, deduplicación (la última gana), aplicación atómica y lecturas en
//! paralelo.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use crate::almacen::{Almacen, Nodos, Overlay};
use crate::arbol;
use crate::camino::Camino;
use crate::error::Error;
use crate::hash::{Hash32, bit, hash_vacio, hash_valor};
use crate::nodo::{Nodo, decodificar};
use crate::prueba::MAX_NIVELES;

/// Un cambio del lote. `valor = None` borra la clave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cambio {
    /// Familia del estado.
    pub familia: u8,
    /// Clave canónica.
    pub clave: Vec<u8>,
    /// Valor nuevo, o `None` para borrar.
    pub valor: Option<Vec<u8>>,
}

impl Cambio {
    /// Cambio que fija `valor` para `(familia, clave)`.
    #[must_use]
    pub fn poner(familia: u8, clave: Vec<u8>, valor: Vec<u8>) -> Self {
        Self {
            familia,
            clave,
            valor: Some(valor),
        }
    }

    /// Cambio que borra `(familia, clave)`.
    #[must_use]
    pub fn borrar(familia: u8, clave: Vec<u8>) -> Self {
        Self {
            familia,
            clave,
            valor: None,
        }
    }
}

/// Deja la última ocurrencia de cada `(familia, clave)` y ordena por `(familia, camino, clave)`.
#[must_use]
pub fn normalizar<C: Camino + ?Sized>(cambios: &[Cambio], c: &C) -> Vec<Cambio> {
    let mut vistos: HashSet<(u8, Vec<u8>)> = HashSet::with_capacity(cambios.len());
    let mut tmp: Vec<(u8, [u8; 7], Cambio)> = Vec::with_capacity(cambios.len());
    for cambio in cambios.iter().rev() {
        if vistos.insert((cambio.familia, cambio.clave.clone())) {
            let p = c.camino(cambio.familia, &cambio.clave);
            tmp.push((cambio.familia, p, cambio.clone()));
        }
    }
    tmp.reverse();
    tmp.sort_unstable_by(|a, b| (a.0, a.1, &a.2.clave).cmp(&(b.0, b.1, &b.2.clave)));
    tmp.into_iter().map(|(_, _, cambio)| cambio).collect()
}

/// Aplica un lote y devuelve las raíces de las familias tocadas.
///
/// Normaliza, opcionalmente **precarga con `hilos` hilos** los nodos que el lote necesitará
/// (lecturas independientes sobre el árbol actual, deduplicadas en una caché) y confirma **una**
/// escritura atómica. El resultado no depende de `hilos`.
///
/// # Errors
/// Si falta un nodo, hay bytes mal formados o el almacén rechaza la escritura.
pub fn aplicar<A: Almacen, C: Camino + ?Sized>(
    alm: &mut A,
    c: &C,
    cambios: &[Cambio],
    hilos: usize,
) -> Result<Vec<(u8, Hash32)>, Error> {
    let norm = normalizar(cambios, c);
    if hilos > 1 {
        let precarga = prefetch(alm, c, &norm, hilos);
        aplicar_interno(alm, c, &norm, Some(&precarga))
    } else {
        aplicar_interno(alm, c, &norm, None)
    }
}

/// Aplica un lote ya normalizado en una escritura atómica, sin precarga.
///
/// # Errors
/// Si falta un nodo, hay bytes mal formados o el almacén rechaza la escritura.
pub fn aplicar_normalizado<A: Almacen, C: Camino + ?Sized>(
    alm: &mut A,
    c: &C,
    cambios: &[Cambio],
) -> Result<Vec<(u8, Hash32)>, Error> {
    aplicar_interno(alm, c, cambios, None)
}

fn aplicar_interno<A: Almacen, C: Camino + ?Sized>(
    alm: &mut A,
    c: &C,
    cambios: &[Cambio],
    precarga: Option<&HashMap<Hash32, Vec<u8>>>,
) -> Result<Vec<(u8, Hash32)>, Error> {
    let mut raices: BTreeMap<u8, Hash32> = BTreeMap::new();
    let mut hojas: Vec<(u8, Vec<u8>, Option<Hash32>)> = Vec::with_capacity(cambios.len());
    let pendientes = {
        let mut ov = match precarga {
            Some(p) => Overlay::con_precarga(alm, p),
            None => Overlay::nuevo(alm),
        };
        for cambio in cambios {
            let raiz_actual = raices
                .get(&cambio.familia)
                .copied()
                .map_or_else(|| alm.raiz(cambio.familia), Ok)?;
            let nueva = match &cambio.valor {
                Some(valor) => {
                    let hv = hash_valor(valor);
                    hojas.push((cambio.familia, cambio.clave.clone(), Some(hv)));
                    arbol::insertar(c, &mut ov, &raiz_actual, cambio.familia, &cambio.clave, &hv)?
                }
                None => {
                    hojas.push((cambio.familia, cambio.clave.clone(), None));
                    arbol::borrar(c, &mut ov, &raiz_actual, cambio.familia, &cambio.clave)?
                }
            };
            raices.insert(cambio.familia, nueva);
        }
        ov.pendientes()
    };
    let raices_vec: Vec<(u8, Hash32)> = raices.iter().map(|(f, r)| (*f, *r)).collect();
    alm.commit(&pendientes, &hojas, &raices_vec)?;
    Ok(raices_vec)
}

/// Precarga en paralelo, deduplicada, los nodos que el lote leerá del almacén base.
///
/// Cada hilo recorre, sin escribir, el camino de un subconjunto de claves sobre el árbol actual y
/// guarda en una caché compartida los nodos que lee. La caché se pasa luego al overlay de
/// [`aplicar`], de modo que el lote **reutiliza** esas lecturas y no repite la E/S. Es solo
/// precarga: el resultado de [`aplicar`] es idéntico con cualquier `hilos`.
fn prefetch<A: Almacen, C: Camino + ?Sized>(
    alm: &A,
    c: &C,
    cambios: &[Cambio],
    hilos: usize,
) -> HashMap<Hash32, Vec<u8>> {
    let Ok(raices) = alm.raices() else {
        return HashMap::new();
    };
    let raiz_de = |familia: u8| {
        raices
            .iter()
            .find(|(f, _)| *f == familia)
            .map_or_else(hash_vacio, |(_, h)| *h)
    };
    let hilos = hilos.max(1);
    let cache: Mutex<HashMap<Hash32, Vec<u8>>> = Mutex::new(HashMap::new());
    std::thread::scope(|scope| {
        for t in 0..hilos {
            let sub: Vec<(Hash32, [u8; 7])> = cambios
                .iter()
                .enumerate()
                .filter(|(i, _)| i % hilos == t)
                .map(|(_, cambio)| {
                    (
                        raiz_de(cambio.familia),
                        c.camino(cambio.familia, &cambio.clave),
                    )
                })
                .collect();
            let cache_ref = &cache;
            scope.spawn(move || {
                for (raiz, camino) in sub {
                    let _ = prefetch_camino(alm, cache_ref, &raiz, &camino);
                }
            });
        }
    });
    cache.into_inner().unwrap_or_else(|e| e.into_inner())
}

fn prefetch_camino<A: Nodos + ?Sized>(
    a: &A,
    cache: &Mutex<HashMap<Hash32, Vec<u8>>>,
    raiz: &Hash32,
    camino: &[u8; 7],
) -> Result<(), Error> {
    let mut actual = *raiz;
    let mut profundidad = 0usize;
    while actual != hash_vacio() && profundidad <= MAX_NIVELES {
        let en_cache = cache.lock().ok().and_then(|g| g.get(&actual).cloned());
        let bytes = match en_cache {
            Some(b) => b,
            None => {
                let b = a.leer(&actual)?.ok_or(Error::NodoAusente(actual))?;
                if let Ok(mut g) = cache.lock() {
                    g.insert(actual, b.clone());
                }
                b
            }
        };
        match decodificar(&bytes)? {
            Nodo::Interno { split, izq, der } => {
                actual = if bit(camino, split) == 0 { izq } else { der };
                profundidad += 1;
            }
            Nodo::Hoja(_) => break,
        }
    }
    Ok(())
}
