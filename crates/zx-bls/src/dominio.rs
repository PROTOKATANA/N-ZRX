//! Separación de dominios de ZEROX (ORDEN-BLS1, decisión 2).
//!
//! El mensaje que entra a la firma BLS es `len_u16_be || dominio || mensaje`, con `dominio` no
//! vacío. Los DST del borrador POP **no** cambian: la separación es de ZEROX y se suma al DST, no
//! lo sustituye.

use crate::error::ErrorBLS;

/// Prefija el dominio al mensaje con su longitud en big-endian de 16 bits.
///
/// # Errores
/// [`ErrorBLS::DominioVacio`] si `dominio` está vacío; [`ErrorBLS::DominioLargo`] si no cabe en
/// `u16`.
pub fn mensaje_con_dominio(dominio: &[u8], mensaje: &[u8]) -> Result<Vec<u8>, ErrorBLS> {
    if dominio.is_empty() {
        return Err(ErrorBLS::DominioVacio);
    }
    let longitud =
        u16::try_from(dominio.len()).map_err(|_| ErrorBLS::DominioLargo(dominio.len()))?;

    let mut salida = Vec::with_capacity(2 + dominio.len() + mensaje.len());
    salida.extend_from_slice(&longitud.to_be_bytes());
    salida.extend_from_slice(dominio);
    salida.extend_from_slice(mensaje);
    Ok(salida)
}

#[cfg(test)]
mod pruebas {
    use super::mensaje_con_dominio;
    use crate::error::ErrorBLS;

    #[test]
    fn el_prefijo_es_la_longitud_big_endian() -> Result<(), ErrorBLS> {
        let m = mensaje_con_dominio(b"zx", b"cuerpo")?;
        assert_eq!(m, b"\x00\x02zxcuerpo");
        Ok(())
    }

    #[test]
    fn un_dominio_vacio_se_rechaza() {
        assert_eq!(mensaje_con_dominio(b"", b"x"), Err(ErrorBLS::DominioVacio));
    }
}
