//! Primitivas de hash con separación de dominio del árbol de estado.
//!
//! Sigue `P-ZRX/P-CARRILES/ER1/RAIZ-ESTADO.md` §3.2–§3.3: `h_d(tag, msg) = SHA3-256(tag ‖ msg)`
//! con etiquetas de 16 B (literal ASCII rellenado con ceros a la derecha), y los dominios
//! `clave_arbol`, `hash_hoja`, `hash_nodo`, `hash_vacio`, `h_valor` y `raiz_estado`.
//!
//! `TAG_RAIZ` incorpora la etiqueta de versión de la estructura: el sufijo decimal de la etiqueta
//! es [`VERSION_ESTRUCTURA`]. Cambiar la estructura obliga a subir esa constante (y con ella el
//! dominio de la raíz), de modo que dos versiones no comparten preimagen.

use sha3::{Digest as _, Sha3_256};

/// Hash de 32 bytes.
pub type Hash32 = [u8; 32];

/// Etiqueta de versión de la estructura del árbol que viaja en el dominio de la raíz.
///
/// Corresponde a los dos dígitos decimales del sufijo de `TAG_RAIZ` (`ZXEstadoRaizVV`).
pub const VERSION_ESTRUCTURA: u8 = 1;

/// Familias del estado, en el orden exacto en que la raíz las concatena (`RAIZ-ESTADO.md` §3.3):
/// `utxo`, `garantias`, `cuentas`, `sectores`, `cajas`, `pruebas`, `poreps`, `claves_voto` y
/// `ultimo_slot`.
pub const FAMILIAS: [u8; 9] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

/// Etiqueta de `clave_arbol`.
const TAG_CLAVE: [u8; 16] = *b"ZXEstadoClave1\0\0";
/// Etiqueta de `hash_hoja`.
const TAG_HOJA: [u8; 16] = *b"ZXEstadoHoja01\0\0";
/// Etiqueta de `hash_nodo`.
const TAG_NODO: [u8; 16] = *b"ZXEstadoNodo01\0\0";
/// Etiqueta de `hash_vacio`.
const TAG_VACIO: [u8; 16] = *b"ZXEstadoVacio1\0\0";
/// Etiqueta de `h_valor`.
const TAG_VALOR: [u8; 16] = *b"ZXEstadoValor1\0\0";
/// Etiqueta de `raiz_estado`, con la versión de la estructura en el sufijo (`01`).
const TAG_RAIZ: [u8; 16] = *b"ZXEstadoRaiz01\0\0";

/// `h_d(tag, msg) = SHA3-256(tag ‖ msg)`.
#[must_use]
pub fn h_d(tag: [u8; 16], msg: &[u8]) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(tag);
    hasher.update(msg);
    hasher.finalize().into()
}

/// `hash_vacio = h_d("ZXEstadoVacio1", "")`.
#[must_use]
pub fn hash_vacio() -> Hash32 {
    h_d(TAG_VACIO, b"")
}

/// `h_valor = h_d("ZXEstadoValor1", valor_canonico)`.
#[must_use]
pub fn hash_valor(valor: &[u8]) -> Hash32 {
    h_d(TAG_VALOR, valor)
}

/// `clave_arbol(familia, clave) = h_d("ZXEstadoClave1", familia(1) ‖ clave)`.
#[must_use]
pub fn clave_arbol(familia: u8, clave: &[u8]) -> Hash32 {
    let mut msg = Vec::with_capacity(1 + clave.len());
    msg.push(familia);
    msg.extend_from_slice(clave);
    h_d(TAG_CLAVE, &msg)
}

/// `camino(familia, clave) = primeros 7 bytes de clave_arbol` (56 bits).
#[must_use]
pub fn camino(familia: u8, clave: &[u8]) -> [u8; 7] {
    let ca = clave_arbol(familia, clave);
    let mut p = [0u8; 7];
    if let Some(origen) = ca.get(..7) {
        p.copy_from_slice(origen);
    }
    p
}

/// Bit `i` (0 = más significativo) del camino de 56 bits.
///
/// Un índice fuera de `0..56` devuelve `0` en lugar de entrar en pánico: el camino es de 7 bytes
/// fijos y el diseño acota `split_depth < 56`.
#[must_use]
pub fn bit(p: &[u8; 7], i: u16) -> u8 {
    let byte = usize::from(i >> 3);
    let shift = 7 - (i & 7);
    p.get(byte).copied().unwrap_or(0) >> shift & 1
}

/// Primer bit en que difieren dos caminos (`56` si son iguales).
#[must_use]
pub fn prefijo_comun(a: &[u8; 7], b: &[u8; 7]) -> u16 {
    let mut i = 0u16;
    while i < 56 {
        if bit(a, i) != bit(b, i) {
            return i;
        }
        i += 1;
    }
    56
}

/// `hash_hoja` de una hoja de una sola entrada (`RAIZ-ESTADO.md` §3.2).
#[must_use]
pub fn hash_hoja(familia: u8, clave: &[u8], h_valor: &Hash32) -> Hash32 {
    let mut msg = Vec::with_capacity(1 + clave.len() + 32);
    msg.push(familia);
    msg.extend_from_slice(clave);
    msg.extend_from_slice(h_valor);
    h_d(TAG_HOJA, &msg)
}

/// Extensión documentada para la lista de colisión del diseño (`RAIZ-ESTADO.md` §3.1, §8.6): una
/// hoja con `n > 1` entradas hashea `familia(1) ‖ 0xFF ‖ concat(len(4 BE) ‖ clave ‖ h_valor)`.
#[must_use]
pub fn hash_hoja_lista(familia: u8, entradas: &[(Vec<u8>, Hash32)]) -> Hash32 {
    let mut msg = Vec::with_capacity(2 + entradas.len() * 70);
    msg.push(familia);
    msg.push(0xFF);
    for (clave, h_valor) in entradas {
        msg.extend_from_slice(&u32::try_from(clave.len()).unwrap_or(u32::MAX).to_be_bytes());
        msg.extend_from_slice(clave);
        msg.extend_from_slice(h_valor);
    }
    h_d(TAG_HOJA, &msg)
}

/// `hash_nodo = h_d("ZXEstadoNodo01", split_depth_be(2) ‖ izq(32) ‖ der(32))`.
#[must_use]
pub fn hash_nodo(split: u16, izq: &Hash32, der: &Hash32) -> Hash32 {
    let mut msg = [0u8; 66];
    if let Some(d) = msg.get_mut(0..2) {
        d.copy_from_slice(&split.to_be_bytes());
    }
    if let Some(d) = msg.get_mut(2..34) {
        d.copy_from_slice(izq);
    }
    if let Some(d) = msg.get_mut(34..66) {
        d.copy_from_slice(der);
    }
    h_d(TAG_NODO, &msg)
}

/// `raiz_estado = h_d(TAG_RAIZ, raiz_f1 ‖ … ‖ raiz_f9 ‖ h_escalares)`.
///
/// `raices` trae las raíces de familia que se conozcan; las familias de [`FAMILIAS`] ausentes
/// aportan [`hash_vacio`]. El resumen de escalares `h_escalares` se pasa **hecho**: este crate no
/// conoce la codificación de los escalares (es genérico sobre clave, familia y valor).
#[must_use]
pub fn raiz_estado(raices: &[(u8, Hash32)], h_escalares: &Hash32) -> Hash32 {
    let mut msg = Vec::with_capacity(FAMILIAS.len() * 32 + 32);
    for familia in FAMILIAS {
        let r = raices
            .iter()
            .find(|(f, _)| *f == familia)
            .map_or_else(hash_vacio, |(_, h)| *h);
        msg.extend_from_slice(&r);
    }
    msg.extend_from_slice(h_escalares);
    h_d(TAG_RAIZ, &msg)
}
