//! Trie binario compacto de Patricia con compromiso de Merkle por nodo.
//!
//! Estructura, claves y hashes: `P-ZRX/P-CARRILES/ER1/RAIZ-ESTADO.md` §3. La hoja guarda
//! `(familia, [(clave_canonica, h_valor)])`; la lista cubre la colisión del camino de 56 bits
//! (§3.1). Los nodos se leen y escriben a través del rasgo [`Nodos`], de modo que la misma lógica
//! sirve para el almacén en memoria, el de RocksDB y el oráculo de reconstrucción.

use crate::almacen::Nodos;
use crate::camino::Camino;
use crate::error::Error;
use crate::hash::{Hash32, bit, hash_nodo, hash_vacio, prefijo_comun};
use crate::nodo::{Hoja, Nodo, codificar_interno, decodificar};

/// Camino de la hoja a partir de su primera entrada.
fn camino_de_hoja<C: Camino + ?Sized>(c: &C, familia: u8, hoja: &Hoja) -> [u8; 7] {
    hoja.entradas
        .first()
        .map_or([0u8; 7], |(k, _)| c.camino(familia, k.as_slice()))
}

/// Inserta o actualiza `(clave, h_valor)` y devuelve la nueva raíz.
///
/// # Errors
/// Si falta un nodo del camino, hay bytes mal formados o el almacén rechaza una escritura.
pub fn insertar<S: Nodos + ?Sized, C: Camino + ?Sized>(
    c: &C,
    s: &mut S,
    raiz: &Hash32,
    familia: u8,
    clave: &[u8],
    h_valor: &Hash32,
) -> Result<Hash32, Error> {
    let p = c.camino(familia, clave);
    if raiz == &hash_vacio() {
        let hoja = Hoja::nueva(familia, clave.to_vec(), *h_valor);
        let h = hoja.hash();
        s.poner(h, hoja.codificar()?)?;
        return Ok(h);
    }

    // Primera bajada: hoja terminal del camino `p`.
    let mut actual = *raiz;
    let hoja_encontrada = loop {
        let bytes = s.leer(&actual)?.ok_or(Error::NodoAusente(actual))?;
        match decodificar(&bytes)? {
            Nodo::Interno { split, izq, der } => {
                actual = if bit(&p, split) == 0 { izq } else { der };
            }
            Nodo::Hoja(h) => break h,
        }
    };

    let p_exist = camino_de_hoja(c, familia, &hoja_encontrada);

    // Misma clave o misma ruta (colisión): la topología no cambia; se sustituye la hoja.
    if hoja_encontrada.contiene(clave).is_some() || p_exist == p {
        if hoja_encontrada.contiene(clave).as_ref() == Some(h_valor) {
            return Ok(*raiz);
        }
        let mut h2 = hoja_encontrada;
        h2.insertar(clave.to_vec(), *h_valor);
        return sustituir_hoja(s, raiz, &p, &h2);
    }

    // Clave nueva con ruta distinta: inserción Patricia.
    let split_nuevo = prefijo_comun(&p, &p_exist);
    let nueva = Hoja::nueva(familia, clave.to_vec(), *h_valor);
    let h_nueva = nueva.hash();
    s.poner(h_nueva, nueva.codificar()?)?;

    // Segunda bajada con pila de ancestros hasta el punto de inserción.
    let mut pila: Vec<(Hash32, u16, bool, Hash32)> = Vec::new();
    let mut n = *raiz;
    loop {
        let bytes = s.leer(&n)?.ok_or(Error::NodoAusente(n))?;
        match decodificar(&bytes)? {
            Nodo::Interno { split, izq, der } => {
                if split > split_nuevo {
                    break;
                }
                let es_izq = bit(&p, split) == 0;
                let (hijo, sib) = if es_izq { (izq, der) } else { (der, izq) };
                pila.push((n, split, es_izq, sib));
                n = hijo;
            }
            Nodo::Hoja(_) => break,
        }
    }

    let (hi, hd) = if bit(&p, split_nuevo) == 0 {
        (h_nueva, n)
    } else {
        (n, h_nueva)
    };
    let mut nh = hash_nodo(split_nuevo, &hi, &hd);
    s.poner(nh, codificar_interno(split_nuevo, &hi, &hd))?;
    while let Some((hp, sp, es_izq, sib)) = pila.pop() {
        let (i, d) = if es_izq { (nh, sib) } else { (sib, nh) };
        let nn = hash_nodo(sp, &i, &d);
        if nn != hp {
            s.poner(nn, codificar_interno(sp, &i, &d))?;
            s.quitar(hp)?;
        }
        nh = nn;
    }
    Ok(nh)
}

/// Sustituye la hoja terminal del camino `p` por `hoja` (misma topología).
fn sustituir_hoja<S: Nodos + ?Sized>(
    s: &mut S,
    raiz: &Hash32,
    p: &[u8; 7],
    hoja: &Hoja,
) -> Result<Hash32, Error> {
    let bytes = s.leer(raiz)?.ok_or(Error::NodoAusente(*raiz))?;
    match decodificar(&bytes)? {
        Nodo::Interno { split, izq, der } => {
            let (ni, nd) = if bit(p, split) == 0 {
                (sustituir_hoja(s, &izq, p, hoja)?, der)
            } else {
                (izq, sustituir_hoja(s, &der, p, hoja)?)
            };
            let nh = hash_nodo(split, &ni, &nd);
            if &nh != raiz {
                s.poner(nh, codificar_interno(split, &ni, &nd))?;
                s.quitar(*raiz)?;
            }
            Ok(nh)
        }
        Nodo::Hoja(_) => {
            let nh = hoja.hash();
            if &nh != raiz {
                s.poner(nh, hoja.codificar()?)?;
                s.quitar(*raiz)?;
            }
            Ok(nh)
        }
    }
}

/// Borra `clave` y devuelve la nueva raíz.
///
/// # Errors
/// Si falta un nodo del camino, hay bytes mal formados o el almacén rechaza una escritura.
pub fn borrar<S: Nodos + ?Sized, C: Camino + ?Sized>(
    c: &C,
    s: &mut S,
    raiz: &Hash32,
    familia: u8,
    clave: &[u8],
) -> Result<Hash32, Error> {
    let p = c.camino(familia, clave);
    borrar_rec(s, raiz, &p, clave)
}

fn borrar_rec<S: Nodos + ?Sized>(
    s: &mut S,
    raiz: &Hash32,
    p: &[u8; 7],
    clave: &[u8],
) -> Result<Hash32, Error> {
    if raiz == &hash_vacio() {
        return Ok(hash_vacio());
    }
    let bytes = s.leer(raiz)?.ok_or(Error::NodoAusente(*raiz))?;
    match decodificar(&bytes)? {
        Nodo::Interno { split, izq, der } => {
            if bit(p, split) == 0 {
                let ni = borrar_rec(s, &izq, p, clave)?;
                if ni == hash_vacio() {
                    s.quitar(*raiz)?;
                    return Ok(der);
                }
                let nh = hash_nodo(split, &ni, &der);
                if &nh != raiz {
                    s.poner(nh, codificar_interno(split, &ni, &der))?;
                    s.quitar(*raiz)?;
                }
                Ok(nh)
            } else {
                let nd = borrar_rec(s, &der, p, clave)?;
                if nd == hash_vacio() {
                    s.quitar(*raiz)?;
                    return Ok(izq);
                }
                let nh = hash_nodo(split, &izq, &nd);
                if &nh != raiz {
                    s.poner(nh, codificar_interno(split, &izq, &nd))?;
                    s.quitar(*raiz)?;
                }
                Ok(nh)
            }
        }
        Nodo::Hoja(mut hoja) => {
            if !hoja.quitar(clave) {
                return Ok(*raiz);
            }
            if hoja.entradas.is_empty() {
                s.quitar(*raiz)?;
                return Ok(hash_vacio());
            }
            let nh = hoja.hash();
            s.poner(nh, hoja.codificar()?)?;
            s.quitar(*raiz)?;
            Ok(nh)
        }
    }
}

/// Reconstruye el árbol desde las hojas `(clave_canonica, h_valor)` y devuelve la raíz.
///
/// Es el oráculo de reconstrucción desde cero (`RAIZ-ESTADO.md` §9.1, `T-RAIZ-03`): agrupa por
/// camino (lista de colisión), construye de abajo arriba y debe dar la misma raíz que la vía
/// incremental.
///
/// # Errors
/// Si el almacén rechaza una escritura o una longitud no cabe en el formato.
pub fn reconstruir<S: Nodos + ?Sized, C: Camino + ?Sized>(
    c: &C,
    s: &mut S,
    familia: u8,
    entradas: &[(Vec<u8>, Hash32)],
) -> Result<Hash32, Error> {
    if entradas.is_empty() {
        return Ok(hash_vacio());
    }
    let mut orden: Vec<(&[u8], &Hash32, [u8; 7])> = entradas
        .iter()
        .map(|(clave, h_valor)| (clave.as_slice(), h_valor, c.camino(familia, clave)))
        .collect();
    orden.sort_unstable_by(|a, b| (a.2, a.0).cmp(&(b.2, b.0)));

    // Agrupa por camino (lista de colisión) y materializa las hojas.
    let mut terminales: Vec<([u8; 7], Hash32)> = Vec::new();
    let mut i = 0usize;
    while i < orden.len() {
        let Some(primera) = orden.get(i) else {
            break;
        };
        let p = primera.2;
        let mut lista: Vec<(Vec<u8>, Hash32)> = Vec::new();
        let mut j = i;
        while let Some((clave, h_valor, pj)) = orden.get(j) {
            if *pj != p {
                break;
            }
            lista.push((clave.to_vec(), **h_valor));
            j += 1;
        }
        let hoja = Hoja {
            familia,
            entradas: lista,
        };
        let h = hoja.hash();
        s.poner(h, hoja.codificar()?)?;
        terminales.push((p, h));
        i = j;
    }
    construir(s, &terminales, 0)
}

fn construir<S: Nodos + ?Sized>(
    s: &mut S,
    nodos: &[([u8; 7], Hash32)],
    inicio: u16,
) -> Result<Hash32, Error> {
    if let [(_, h)] = nodos {
        return Ok(*h);
    }
    let Some(primera) = nodos.first() else {
        return Ok(hash_vacio());
    };
    let Some(ultima) = nodos.last() else {
        return Ok(hash_vacio());
    };
    let split = prefijo_comun(&primera.0, &ultima.0);
    if split < inicio {
        return Err(Error::NodoMalFormado);
    }
    let medio = nodos.partition_point(|(p, _)| bit(p, split) == 0);
    if medio == 0 || medio >= nodos.len() {
        return Err(Error::NodoMalFormado);
    }
    let izq = construir(s, nodos.get(..medio).unwrap_or_default(), split + 1)?;
    let der = construir(s, nodos.get(medio..).unwrap_or_default(), split + 1)?;
    let nh = hash_nodo(split, &izq, &der);
    s.poner(nh, codificar_interno(split, &izq, &der))?;
    Ok(nh)
}
