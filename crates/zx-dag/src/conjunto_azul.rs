//! Conjunto **persistente** de identidades azules, sin copia por bloque.
//!
//! # Qué sustituye
//!
//! `DatosGhostdag::blue_idents: Vec<IdentidadGhostdag>` copiaba en cada bloque toda la colección
//! acumulada (coste `O(N)` por bloque, `O(N²)` por construcción). Aquí cada bloque guarda solo la
//! **raíz** (`u32`) de un árbol treap persistente compartido por un arena común; insertar un
//! elemento nuevo copia únicamente el camino (`O(log n)` nodos) y reutiliza el resto por
//! compartición estructural. La pertenencia sigue siendo exacta (`O(log n)`), que es todo lo que
//! necesita U3″ (`sp_bi.contains(cid)`).
//!
//! # Por qué un arena y no `Rc`
//!
//! Los nodos viven en un `Vec` propiedad del almacén y se referencian por índice `u32`; así el
//! almacén sigue siendo `Send + Sync` sin `Rc`/`Arc` y sin liberar memoria durante la construcción.
//! Las prioridades del treap son un hash determinista de la clave, de modo que el árbol se comporta
//! como un ABB aleatorizado independiente del orden de inserción.

#![expect(
    clippy::indexing_slicing,
    reason = "arena interna: los índices se construyen con `empujar` y nunca se invalidan"
)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::ghostdag::IdentidadGhostdag;

/// Índice nulo del arena.
pub(crate) const NULO: u32 = u32::MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Nodo {
    clave: IdentidadGhostdag,
    izq: u32,
    der: u32,
    prioridad: u64,
}

/// ¿Está `clave` en el conjunto con raíz `raiz`?
pub(crate) fn contiene(nodos: &[Nodo], raiz: u32, clave: &IdentidadGhostdag) -> bool {
    let mut actual = raiz;
    while actual != NULO {
        let Some(nodo) = nodos.get(actual as usize) else {
            return false;
        };
        match clave.cmp(&nodo.clave) {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => actual = nodo.izq,
            std::cmp::Ordering::Greater => actual = nodo.der,
        }
    }
    false
}

/// Inserta `clave` en el conjunto con raíz `raiz` y devuelve la raíz del nuevo conjunto.
///
/// Si la clave ya estaba, devuelve la misma raíz sin asignar nodos.
pub(crate) fn insertar(nodos: &mut Vec<Nodo>, raiz: u32, clave: IdentidadGhostdag) -> u32 {
    insertar_rec(nodos, raiz, clave)
}

fn prioridad(clave: &IdentidadGhostdag) -> u64 {
    let mut hasher = DefaultHasher::new();
    clave.hash(&mut hasher);
    hasher.finish()
}

fn empujar(nodos: &mut Vec<Nodo>, clave: IdentidadGhostdag, izq: u32, der: u32) -> u32 {
    let prioridad = prioridad(&clave);
    let indice = nodos.len() as u32;
    nodos.push(Nodo {
        clave,
        izq,
        der,
        prioridad,
    });
    indice
}

fn prioridad_de(nodos: &[Nodo], i: u32) -> u64 {
    if i == NULO {
        u64::MAX
    } else {
        nodos[i as usize].prioridad
    }
}

fn rotar_derecha(nodos: &mut Vec<Nodo>, raiz: u32) -> u32 {
    let Some(nodo) = nodos.get(raiz as usize).cloned() else {
        return raiz;
    };
    let izquierdo = nodo.izq;
    let Some(nodo_izq) = nodos.get(izquierdo as usize).cloned() else {
        return raiz;
    };
    // Nueva versión de `raiz` con su hijo izquierdo reemplazado por el derecho del izquierdo.
    let nueva_raiz = empujar(nodos, nodo.clave, nodo_izq.der, nodo.der);
    // Nueva versión del izquierdo apuntando a la nueva raíz.
    empujar(nodos, nodo_izq.clave, nodo_izq.izq, nueva_raiz)
}

fn rotar_izquierda(nodos: &mut Vec<Nodo>, raiz: u32) -> u32 {
    let Some(nodo) = nodos.get(raiz as usize).cloned() else {
        return raiz;
    };
    let derecho = nodo.der;
    let Some(nodo_der) = nodos.get(derecho as usize).cloned() else {
        return raiz;
    };
    let nueva_raiz = empujar(nodos, nodo.clave, nodo.izq, nodo_der.izq);
    empujar(nodos, nodo_der.clave, nueva_raiz, nodo_der.der)
}

fn insertar_rec(nodos: &mut Vec<Nodo>, raiz: u32, clave: IdentidadGhostdag) -> u32 {
    if raiz == NULO {
        return empujar(nodos, clave, NULO, NULO);
    }
    let Some(nodo) = nodos.get(raiz as usize).cloned() else {
        return raiz;
    };
    match clave.cmp(&nodo.clave) {
        std::cmp::Ordering::Equal => raiz,
        std::cmp::Ordering::Less => {
            let nuevo_izq = insertar_rec(nodos, nodo.izq, clave);
            let indice = empujar(nodos, nodo.clave, nuevo_izq, nodo.der);
            if prioridad_de(nodos, nuevo_izq) < prioridad_de(nodos, indice) {
                rotar_derecha(nodos, indice)
            } else {
                indice
            }
        }
        std::cmp::Ordering::Greater => {
            let nuevo_der = insertar_rec(nodos, nodo.der, clave);
            let indice = empujar(nodos, nodo.clave, nodo.izq, nuevo_der);
            if prioridad_de(nodos, nuevo_der) < prioridad_de(nodos, indice) {
                rotar_izquierda(nodos, indice)
            } else {
                indice
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u64) -> IdentidadGhostdag {
        IdentidadGhostdag::Sintetica(n)
    }

    #[test]
    fn insercion_y_pertenencia_persistentes() {
        let mut nodos = Vec::new();
        let mut raices = Vec::new();
        let mut raiz = NULO;
        for i in 0..500u64 {
            raiz = insertar(&mut nodos, raiz, s(i));
            raices.push(raiz);
        }
        // El conjunto final tiene todas.
        for i in 0..500u64 {
            assert!(contiene(&nodos, raiz, &s(i)), "falta {i}");
        }
        assert!(!contiene(&nodos, raiz, &s(501)));
        // Las versiones antiguas conservan exactamente lo que tenían.
        for (k, r) in raices.iter().enumerate() {
            for i in 0..500u64 {
                let esperado = i <= k as u64;
                assert_eq!(
                    contiene(&nodos, *r, &s(i)),
                    esperado,
                    "version {k} clave {i}"
                );
            }
        }
    }

    #[test]
    fn insertar_duplicado_no_crea_nodos() {
        let mut nodos = Vec::new();
        let raiz = insertar(&mut nodos, NULO, s(7));
        let n = nodos.len();
        let raiz2 = insertar(&mut nodos, raiz, s(7));
        assert_eq!(raiz, raiz2);
        assert_eq!(nodos.len(), n);
    }
}
