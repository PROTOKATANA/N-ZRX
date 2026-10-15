//! `CompactSize` — longitud variable para contadores y longitudes (SPEC §2.2).
//!
//! | Valor | Codificación |
//! |---|---|
//! | `< 0xFD` | 1 byte: el valor |
//! | `≤ 0xFFFF` | `0xFD` + `u16` LE |
//! | `≤ 0xFFFF_FFFF` | `0xFE` + `u32` LE |
//! | resto | `0xFF` + `u64` LE |
//!
//! # C-ENC-05: la minimalidad no es estética
//!
//! Un valor **MUST** usar la codificación más corta posible, y las no mínimas **MUST** rechazarse.
//! El motivo es concreto y está documentado: sin esta regla, un minero puede codificar el mismo
//! objeto de varias formas distintas y probar **cada una** contra el filtro de dificultad, en vez de
//! solo la intencionada. El decodificador de aquí rechaza; no normaliza en silencio.

use crate::encoding::int::{leer_u8, leer_u16, leer_u32, leer_u64};
use crate::error::EncodingError;

/// Prefijo de tres bytes: el valor cabe en `u16`.
const PREFIJO_U16: u8 = 0xFD;
/// Prefijo de cinco bytes: el valor cabe en `u32`.
const PREFIJO_U32: u8 = 0xFE;
/// Prefijo de nueve bytes: el valor necesita `u64`.
const PREFIJO_U64: u8 = 0xFF;

/// Escribe `v` en su forma **mínima** al final de `salida` (C-ENC-05).
pub fn escribir(salida: &mut Vec<u8>, v: u64) {
    if v < u64::from(PREFIJO_U16) {
        // Cabe en el propio byte de prefijo. El cast no puede perder datos: v < 0xFD.
        salida.push(u8::try_from(v).unwrap_or(0));
    } else if v <= u64::from(u16::MAX) {
        salida.push(PREFIJO_U16);
        salida.extend_from_slice(&u16::try_from(v).unwrap_or(0).to_le_bytes());
    } else if v <= u64::from(u32::MAX) {
        salida.push(PREFIJO_U32);
        salida.extend_from_slice(&u32::try_from(v).unwrap_or(0).to_le_bytes());
    } else {
        salida.push(PREFIJO_U64);
        salida.extend_from_slice(&v.to_le_bytes());
    }
}

/// Decodifica un `CompactSize`, **rechazando** toda codificación no mínima (C-ENC-05).
///
/// Devuelve el valor y el resto del buffer.
///
/// # Errores
/// - [`EncodingError::Truncado`] si el buffer se queda corto.
/// - [`EncodingError::CompactSizeNoMinimo`] si el valor cabía en una forma más corta.
pub fn leer(bytes: &[u8]) -> Result<(u64, &[u8]), EncodingError> {
    let (prefijo, resto) = leer_u8(bytes)?;

    match prefijo {
        PREFIJO_U16 => {
            let (v, resto) = leer_u16(resto)?;
            // Un valor < 0xFD tenía que ir en un solo byte.
            if v < u16::from(PREFIJO_U16) {
                return Err(EncodingError::CompactSizeNoMinimo {
                    valor: u64::from(v),
                    prefijo,
                });
            }
            Ok((u64::from(v), resto))
        }
        PREFIJO_U32 => {
            let (v, resto) = leer_u32(resto)?;
            // Un valor que cabía en u16 tenía que usar el prefijo de tres bytes.
            if v <= u32::from(u16::MAX) {
                return Err(EncodingError::CompactSizeNoMinimo {
                    valor: u64::from(v),
                    prefijo,
                });
            }
            Ok((u64::from(v), resto))
        }
        PREFIJO_U64 => {
            let (v, resto) = leer_u64(resto)?;
            // Un valor que cabía en u32 tenía que usar el prefijo de cinco bytes.
            if v <= u64::from(u32::MAX) {
                return Err(EncodingError::CompactSizeNoMinimo { valor: v, prefijo });
            }
            Ok((v, resto))
        }
        // Cualquier byte < 0xFD es el valor en sí, y por construcción es mínimo.
        n => Ok((u64::from(n), resto)),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{escribir, leer};
    use crate::error::EncodingError;

    fn ida_y_vuelta(v: u64) {
        let mut buf = Vec::new();
        escribir(&mut buf, v);
        let (leido, resto) = leer(&buf).unwrap();
        assert_eq!(leido, v, "ida y vuelta rota para {v}");
        assert!(resto.is_empty());
    }

    #[test]
    fn fronteras_exactas_de_cada_forma() {
        for v in [
            0,
            1,
            0xFC,
            0xFD,
            0xFE,
            0xFF,
            0x1_00,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX,
        ] {
            ida_y_vuelta(v);
        }
    }

    #[test]
    fn cada_forma_ocupa_lo_que_debe() {
        let casos: [(u64, usize); 4] = [(0xFC, 1), (0xFFFF, 3), (0xFFFF_FFFF, 5), (u64::MAX, 9)];
        for (v, esperado) in casos {
            let mut buf = Vec::new();
            escribir(&mut buf, v);
            assert_eq!(buf.len(), esperado, "longitud incorrecta para {v}");
        }
    }

    /// C-ENC-05. Cada uno de estos codifica un valor que cabía en una forma más corta.
    #[test]
    fn se_rechazan_las_codificaciones_no_minimas() {
        // 0x00 con prefijo de u16 — cabía en un byte.
        let e = leer(&[0xFD, 0x00, 0x00]).unwrap_err();
        assert!(matches!(
            e,
            EncodingError::CompactSizeNoMinimo {
                valor: 0,
                prefijo: 0xFD
            }
        ));

        // 0xFC con prefijo de u16 — el mayor que aún cabe en un byte.
        assert!(leer(&[0xFD, 0xFC, 0x00]).is_err());

        // 0xFFFF con prefijo de u32 — cabía en tres bytes.
        assert!(leer(&[0xFE, 0xFF, 0xFF, 0x00, 0x00]).is_err());

        // 0xFFFF_FFFF con prefijo de u64 — cabía en cinco bytes.
        assert!(leer(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    /// Los mínimos legítimos de cada forma sí pasan. Es el borde opuesto al test anterior:
    /// un decodificador demasiado estricto los rechazaría y partiría la cadena igual.
    #[test]
    fn el_valor_minimo_de_cada_forma_es_valido() {
        assert_eq!(leer(&[0xFD, 0xFD, 0x00]).unwrap().0, 0xFD);
        assert_eq!(leer(&[0xFE, 0x00, 0x00, 0x01, 0x00]).unwrap().0, 0x1_0000);
        assert_eq!(
            leer(&[0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
                .unwrap()
                .0,
            0x1_0000_0000
        );
    }

    #[test]
    fn un_buffer_truncado_no_se_lee_a_medias() {
        assert!(leer(&[]).is_err());
        assert!(leer(&[0xFD]).is_err());
        assert!(leer(&[0xFD, 0x00]).is_err());
        assert!(leer(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn se_devuelve_el_resto_sin_tocar() {
        let (v, resto) = leer(&[0x02, 0xAA, 0xBB]).unwrap();
        assert_eq!(v, 2);
        assert_eq!(resto, &[0xAA, 0xBB]);
    }
}
