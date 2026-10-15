//! Enteros de longitud fija, little-endian (C-ENC-02).
//!
//! Sin excepciones y sin configuración: little-endian siempre. La única secuencia de bytes que se
//! interpreta como **big-endian** en todo ZEROX es el hash de bloque al compararlo con el target
//! (C-POW-01), y eso vive en `crate::target`, no aquí.

use crate::error::EncodingError;

/// Lee `N` bytes del principio de `bytes` y devuelve el resto.
///
/// Es la única primitiva de lectura del módulo: todo lo demás pasa por aquí, de modo que la
/// comprobación de longitud ocurre en un solo sitio y no puede olvidarse en uno de los casos.
fn tomar<const N: usize>(bytes: &[u8]) -> Result<([u8; N], &[u8]), EncodingError> {
    let (cabeza, resto) = bytes.split_at_checked(N).ok_or(EncodingError::Truncado {
        esperados: N,
        disponibles: bytes.len(),
    })?;
    let mut buf = [0u8; N];
    buf.copy_from_slice(cabeza);
    Ok((buf, resto))
}

/// Genera el par leer/escribir de un entero de ancho fijo.
macro_rules! entero_le {
    ($tipo:ty, $leer:ident, $escribir:ident, $n:literal, $doc:literal) => {
        #[doc = concat!("Lee un `", stringify!($tipo), "` little-endian (", $doc, ").")]
        ///
        /// Devuelve el valor y el resto del buffer.
        ///
        /// # Errores
        /// [`EncodingError::Truncado`] si no quedan bytes suficientes.
        pub fn $leer(bytes: &[u8]) -> Result<($tipo, &[u8]), EncodingError> {
            let (buf, resto) = tomar::<$n>(bytes)?;
            Ok((<$tipo>::from_le_bytes(buf), resto))
        }

        #[doc = concat!("Escribe un `", stringify!($tipo), "` little-endian al final de `salida`.")]
        pub fn $escribir(salida: &mut Vec<u8>, v: $tipo) {
            salida.extend_from_slice(&v.to_le_bytes());
        }
    };
}

entero_le!(
    u8,
    leer_u8,
    escribir_u8,
    1,
    "trivialmente, un byte no tiene orden"
);
entero_le!(u16, leer_u16, escribir_u16, 2, "C-ENC-02");
entero_le!(u32, leer_u32, escribir_u32, 4, "C-ENC-02");
entero_le!(u64, leer_u64, escribir_u64, 8, "C-ENC-02");
entero_le!(
    i64,
    leer_i64,
    escribir_i64,
    8,
    "C-ENC-02, complemento a dos"
);

/// Lee 32 bytes crudos (un `u256` o un digest) y devuelve el resto.
///
/// # Errores
/// [`EncodingError::Truncado`] si no quedan 32 bytes.
pub fn leer_32(bytes: &[u8]) -> Result<([u8; 32], &[u8]), EncodingError> {
    tomar::<32>(bytes)
}

/// Lee 16 bytes crudos (la salida PoT) y devuelve el resto.
///
/// # Errores
/// [`EncodingError::Truncado`] si no quedan 16 bytes.
pub fn leer_16(bytes: &[u8]) -> Result<([u8; 16], &[u8]), EncodingError> {
    tomar::<16>(bytes)
}

/// Lee 48 bytes crudos y devuelve el resto.
///
/// # Errores
/// [`EncodingError::Truncado`] si no quedan 48 bytes.
pub fn leer_48(bytes: &[u8]) -> Result<([u8; 48], &[u8]), EncodingError> {
    tomar::<48>(bytes)
}

/// Lee 256 bytes crudos (camino Merkle registro→segmento, B-21) y devuelve el resto.
///
/// # Errores
/// [`EncodingError::Truncado`] si no quedan 256 bytes.
pub fn leer_256(bytes: &[u8]) -> Result<([u8; 256], &[u8]), EncodingError> {
    tomar::<256>(bytes)
}

/// Lee 512 bytes crudos (camino Merkle chunk→registro, B-21) y devuelve el resto.
///
/// # Errores
/// [`EncodingError::Truncado`] si no quedan 512 bytes.
pub fn leer_512(bytes: &[u8]) -> Result<([u8; 512], &[u8]), EncodingError> {
    tomar::<512>(bytes)
}

/// Lee 160 bytes crudos (la prueba de espacio) y devuelve el resto.
///
/// # Errores
/// [`EncodingError::Truncado`] si no quedan 160 bytes.
pub fn leer_160(bytes: &[u8]) -> Result<([u8; 160], &[u8]), EncodingError> {
    tomar::<160>(bytes)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{escribir_i64, escribir_u32, leer_i64, leer_u32, leer_u64};
    use crate::error::EncodingError;

    #[test]
    fn u32_ida_y_vuelta_en_little_endian() {
        let mut buf = Vec::new();
        escribir_u32(&mut buf, 0x1234_5678);
        assert_eq!(buf, vec![0x78, 0x56, 0x34, 0x12], "C-ENC-02: little-endian");
        let (v, resto) = leer_u32(&buf).unwrap();
        assert_eq!(v, 0x1234_5678);
        assert!(resto.is_empty());
    }

    #[test]
    fn i64_negativo_en_complemento_a_dos() {
        let mut buf = Vec::new();
        escribir_i64(&mut buf, -1);
        assert_eq!(buf, vec![0xFF; 8]);
        assert_eq!(leer_i64(&buf).unwrap().0, -1);
    }

    #[test]
    fn un_buffer_corto_no_se_lee_a_medias() {
        let corto = [0u8; 3];
        let e = leer_u32(&corto).unwrap_err();
        assert_eq!(
            e,
            EncodingError::Truncado {
                esperados: 4,
                disponibles: 3
            }
        );
        assert!(leer_u64(&corto).is_err());
    }

    #[test]
    fn leer_deja_el_resto_intacto() {
        let buf = [1u8, 0, 0, 0, 0xAA, 0xBB];
        let (v, resto) = leer_u32(&buf).unwrap();
        assert_eq!(v, 1);
        assert_eq!(resto, &[0xAA, 0xBB]);
    }
}
