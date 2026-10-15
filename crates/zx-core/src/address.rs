//! Direcciones transparentes en bech32 (SPEC §2.3, C-ENC-06, C-ENC-06b, C-ENC-07).
//!
//! # Dos decisiones que el SPEC no fijaba, y que importan
//!
//! **1 · Se usa bech32m (BIP-350), no bech32 (BIP-173).**
//!
//! BIP-350 existe precisamente porque bech32 tiene un defecto conocido de inserción: en una cadena
//! cuyo último carácter de datos es `p`, insertar o borrar caracteres `q` justo antes **no invalida
//! el checksum**. Bitcoin conserva bech32 para segwit v0 por compatibilidad hacia atrás; ZEROX
//! nace en 2026 sin ningún legado que respetar, así que usa la versión corregida. La diferencia es
//! una constante (`1` frente a `0x2bc830a3`) y cuesta cero.
//!
//! Hay un test que **demuestra el defecto** en bech32 y su ausencia en bech32m, en vez de dar la
//! afirmación por buena.
//!
//! **2 · Nunca se usa `bech32::decode()`** — es C-ENC-06b: el algoritmo de checksum se exige
//! explícitamente, y una dirección con checksum bech32 (BIP-173) se rechaza aunque el resto esté
//! bien formado.
//!
//! Esa función de conveniencia acepta **cualquiera de los dos checksums**:
//!
//! ```text
//! match unchecked.validate_checksum::<Bech32m>() {
//!     Ok(_) => {}
//!     Err(ChecksumError::InvalidResidue(ref e)) if e.matches_bech32_checksum() => {}
//!     ...
//! ```
//!
//! Para un parser de direcciones eso es **maleabilidad**: dos cadenas distintas —una con checksum
//! bech32 y otra con bech32m— decodificarían a la misma dirección, y un sistema de pagos que las
//! trate como identificadores distintos se descuadra. Aquí se exige el algoritmo explícitamente con
//! `CheckedHrpstring::new::<Bech32m>`.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

use crate::error::EncodingError;
use crate::firma::{ClavePublica, LONGITUD_CLAVE};

/// HRP de mainnet, pool transparente (C-ENC-06).
pub const HRP_MAINNET: &str = "zzk";
/// HRP de mainnet, pool blindado. **Reservado para v1.1.**
pub const HRP_MAINNET_BLINDADA: &str = "zzs";
/// HRP de testnet, pool transparente.
pub const HRP_TESTNET: &str = "tzzk";
/// HRP de la red dev, pool transparente (F-12, D-P05).
pub const HRP_DEV: &str = "dzzk";

pub use crate::red::Red;

/// El HRP de cada red. La red es parte de la dirección, no un ajuste del nodo: una dirección de
/// testnet **no puede** leerse como de mainnet, porque el HRP entra en el checksum.
trait HrpDeRed {
    fn hrp_transparente(self) -> &'static str;
    fn desde_hrp(h: &str) -> Option<Red>;
}

impl HrpDeRed for Red {
    fn hrp_transparente(self) -> &'static str {
        match self {
            Self::Mainnet => HRP_MAINNET,
            Self::Testnet => HRP_TESTNET,
            Self::Dev => HRP_DEV,
        }
    }

    fn desde_hrp(h: &str) -> Option<Self> {
        match h {
            HRP_MAINNET => Some(Self::Mainnet),
            HRP_TESTNET => Some(Self::Testnet),
            HRP_DEV => Some(Self::Dev),
            _ => None,
        }
    }
}

/// Dirección transparente: red + **la clave pública Ed25519** (C-ENC-07).
///
/// # P2K, no P2KH (P-020)
///
/// La dirección lleva la clave en claro, no `SHA3-256(pubkey)`. El hash de ZEROX mide 32 bytes y
/// una clave Ed25519 mide **exactamente** 32 bytes, así que hashear no acortaba la dirección ni un
/// carácter: solo obligaba a repetir la clave en el testigo al gastar, 32 bytes por entrada.
///
/// La contrapartida —la clave queda expuesta al **recibir**, no al gastar— está asumida y razonada
/// en P-020: la defensa post-cuántica de ZEROX es un network upgrade con una variante nueva de
/// `Lock`, no el formato de dirección.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
    /// Red a la que pertenece.
    pub red: Red,
    /// La clave pública, 32 bytes.
    pub pubkey: ClavePublica,
}

impl Address {
    /// Construye la dirección de una clave pública (C-ENC-07).
    #[must_use]
    pub const fn de_pubkey(red: Red, pubkey: ClavePublica) -> Self {
        Self { red, pubkey }
    }

    /// Codifica en bech32m, en minúsculas.
    ///
    /// # Errores
    /// [`EncodingError::DireccionInvalida`] si el HRP no es válido — imposible con los HRP fijos de
    /// C-ENC-06, pero se propaga en vez de darse por hecho.
    pub fn codificar(&self) -> Result<String, EncodingError> {
        let hrp = Hrp::parse(self.red.hrp_transparente()).map_err(|_| {
            EncodingError::DireccionInvalida {
                motivo: "HRP inválido",
            }
        })?;
        bech32::encode_lower::<Bech32m>(hrp, self.pubkey.bytes()).map_err(|_| {
            EncodingError::DireccionInvalida {
                motivo: "fallo al codificar bech32m",
            }
        })
    }

    /// Decodifica, exigiendo **bech32m** y longitud exacta.
    ///
    /// # Errores
    /// [`EncodingError::DireccionInvalida`] si el checksum no es bech32m válido, si el HRP no es de
    /// una red conocida, o si los datos no miden exactamente 32 bytes.
    pub fn decodificar(s: &str) -> Result<Self, EncodingError> {
        let malo = |motivo| EncodingError::DireccionInvalida { motivo };

        // Explícitamente Bech32m: `bech32::decode()` aceptaría también bech32 — ver el módulo.
        let checked =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|_| malo("checksum bech32m inválido"))?;

        let red = Red::desde_hrp(checked.hrp().as_str()).ok_or_else(|| malo("HRP desconocido"))?;

        let datos: Vec<u8> = checked.byte_iter().collect();
        let bytes: [u8; LONGITUD_CLAVE] = datos
            .try_into()
            .map_err(|_| malo("una dirección transparente MUST llevar 32 bytes exactos"))?;

        // No se valida que los bytes decodifiquen a un punto de la curva: ZIP-215 exige aceptar
        // codificaciones no canónicas, y rechazarlas aquí sería una divergencia con `verificar`.
        Ok(Self {
            red,
            pubkey: ClavePublica::desde_bytes(bytes),
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{Address, HRP_DEV, HRP_MAINNET, HRP_TESTNET, Red};
    use crate::firma::{ClavePublica, LONGITUD_CLAVE};
    use bech32::{Bech32, Bech32m, Hrp};

    fn dir(red: Red, n: u8) -> Address {
        Address::de_pubkey(red, ClavePublica::desde_bytes([n; LONGITUD_CLAVE]))
    }

    #[test]
    fn ida_y_vuelta() {
        for red in [Red::Mainnet, Red::Testnet, Red::Dev] {
            let a = dir(red, 0x42);
            let s = a.codificar().unwrap();
            assert_eq!(Address::decodificar(&s).unwrap(), a, "{s}");
        }
    }

    #[test]
    fn el_hrp_identifica_la_red() {
        assert!(
            dir(Red::Mainnet, 1)
                .codificar()
                .unwrap()
                .starts_with(HRP_MAINNET)
        );
        assert!(
            dir(Red::Dev, 1).codificar().unwrap().starts_with(HRP_DEV),
            "F-12: el HRP de dev es dzzk"
        );
        assert!(
            dir(Red::Testnet, 1)
                .codificar()
                .unwrap()
                .starts_with(HRP_TESTNET)
        );
    }

    /// Una dirección de testnet no puede leerse como de mainnet: el HRP entra en el checksum, así
    /// que cambiarlo a mano lo invalida. Es la defensa contra enviar fondos a la red equivocada.
    #[test]
    fn no_se_puede_cambiar_de_red_editando_el_hrp() {
        let s = dir(Red::Testnet, 7).codificar().unwrap();
        let falsa = s.replacen(HRP_TESTNET, HRP_MAINNET, 1);
        assert!(
            Address::decodificar(&falsa).is_err(),
            "el checksum debe cubrir el HRP"
        );
    }

    #[test]
    fn un_caracter_cambiado_invalida() {
        let s = dir(Red::Mainnet, 3).codificar().unwrap();
        let mut bytes: Vec<char> = s.chars().collect();
        let ultimo = bytes.len() - 1;
        // 'q' y 'p' son ambos del alfabeto bech32, así que el cambio es "legal" salvo por checksum.
        *bytes.get_mut(ultimo).unwrap() = if s.ends_with('q') { 'p' } else { 'q' };
        let roto: String = bytes.into_iter().collect();
        assert!(Address::decodificar(&roto).is_err());
    }

    /// C-ENC-07: exactamente 32 bytes. Ni más, ni menos.
    #[test]
    fn se_rechaza_una_longitud_distinta_de_32() {
        let hrp = Hrp::parse(HRP_MAINNET).unwrap();
        for n in [0usize, 20, 31, 33, 64] {
            let s = bech32::encode_lower::<Bech32m>(hrp, &vec![0u8; n]).unwrap();
            assert!(
                Address::decodificar(&s).is_err(),
                "{n} bytes debería rechazarse (C-ENC-07 exige 32)"
            );
        }
    }

    /// **La razón de usar bech32m.** Se exige el algoritmo, no se acepta cualquiera.
    ///
    /// Con la misma carga útil, el checksum bech32 y el bech32m difieren; `Address::decodificar`
    /// **MUST** rechazar el primero. Si usara `bech32::decode()`, aceptaría los dos y existirían dos
    /// cadenas distintas para la misma dirección: maleabilidad.
    #[test]
    fn se_rechaza_el_checksum_bech32_antiguo() {
        let hrp = Hrp::parse(HRP_MAINNET).unwrap();
        let datos = [0x5au8; LONGITUD_CLAVE];

        let con_m = bech32::encode_lower::<Bech32m>(hrp, &datos).unwrap();
        let sin_m = bech32::encode_lower::<Bech32>(hrp, &datos).unwrap();
        assert_ne!(con_m, sin_m, "los dos algoritmos dan checksums distintos");

        assert!(
            Address::decodificar(&con_m).is_ok(),
            "bech32m es el nuestro"
        );
        assert!(
            Address::decodificar(&sin_m).is_err(),
            "bech32 (BIP-173) MUST rechazarse: si se aceptara, la misma dirección tendría dos \
             representaciones válidas"
        );

        // Y la comprobación de que no es un falso positivo: la permisiva sí acepta las dos.
        assert!(bech32::decode(&con_m).is_ok());
        assert!(
            bech32::decode(&sin_m).is_ok(),
            "bech32::decode() acepta ambos — por eso no se usa"
        );
    }

    /// **Demostración empírica del defecto de BIP-173** que motiva BIP-350.
    ///
    /// En una cadena bech32 cuyo último carácter de datos es `p`, insertar `q` justo antes no
    /// invalida el checksum. Se busca un caso real por fuerza bruta y se comprueba que bech32 lo
    /// acepta y bech32m no.
    #[test]
    fn bech32_tiene_el_defecto_de_insercion_y_bech32m_no() {
        let hrp = Hrp::parse("zzk").unwrap();

        // Buscar una carga útil cuya codificación bech32 termine en 'p'.
        let mut encontrado = None;
        for n in 0u32..4096 {
            let mut datos = [0u8; LONGITUD_CLAVE];
            let n_bytes = n.to_le_bytes();
            if let Some(cabeza) = datos.get_mut(..n_bytes.len()) {
                cabeza.copy_from_slice(&n_bytes);
            }
            let s = bech32::encode_lower::<Bech32>(hrp, &datos).unwrap();
            if s.ends_with('p') {
                encontrado = Some(s);
                break;
            }
        }

        // ~1 de cada 32 cadenas termina en 'p', así que en 4096 intentos siempre aparece. Si no
        // apareciera, el test estaría pasando en vacío y eso sí sería un fallo.
        let s = encontrado.expect(
            "no se encontró ninguna cadena bech32 terminada en 'p' en 4096 \
                                   intentos — el test estaría pasando en vacío",
        );

        let insertada = format!("{}q{}", s.get(..s.len() - 1).unwrap_or(""), 'p');

        let bech32_lo_acepta =
            bech32::primitives::decode::CheckedHrpstring::new::<Bech32>(&insertada).is_ok();
        assert!(
            bech32_lo_acepta,
            "BIP-350 documenta este defecto de BIP-173; si aquí no se reproduce, revisar el caso: {s}"
        );

        // Y lo que importa: nuestra función lo rechaza, porque exige bech32m.
        assert!(
            Address::decodificar(&insertada).is_err(),
            "ZEROX MUST rechazar la inserción"
        );
    }
}
