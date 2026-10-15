//! Identidad de red.
//!
//! # Por qué vive en `zx-core` y no en `zx-consensus`
//!
//! Llegó a haber **dos** `Red` distintos en el workspace —uno en `zx-core::address`, otro en
//! `zx-consensus::activacion`— y eso es exactamente el error que hay que evitar: dos tipos con el
//! mismo nombre y el mismo significado que el compilador no puede relacionar. Nada impedía pasar el
//! de un módulo donde se esperaba el otro salvo que las firmas no cuadraran, y el día que
//! cuadraran por casualidad el fallo sería silencioso.
//!
//! Vive aquí porque es una etiqueta, no una regla: no decide nada de consenso. Y ponerla en el
//! crate base es lo que permite que `zx-p2p` la use **sin depender de `zx-consensus`** — ver el
//! diagrama de dependencias en `zx-p2p`.

/// Prefijo mágico de mainnet (C-NET-01). Primeros 4 bytes de `SHA3-256("ZEROX/mainnet/magic")`.
pub const MAGIC_MAINNET: [u8; 4] = [0x9e, 0x0f, 0x10, 0x44];

/// Prefijo mágico de testnet (C-NET-01). Primeros 4 bytes de `SHA3-256("ZEROX/testnet/magic")`.
pub const MAGIC_TESTNET: [u8; 4] = [0xbb, 0x79, 0x64, 0x3f];

/// Prefijo mágico de la red dev (C-NET-01). Primeros 4 bytes de `SHA3-256("ZEROX/dev/magic")`.
pub const MAGIC_DEV: [u8; 4] = [0xdb, 0x34, 0x78, 0x47];

/// `CONSENSUS_BRANCH_ID` de la red dev (F-12).
///
/// Los **4 primeros bytes, en little-endian**, de `SHA3-256("ZEROX hibrido red dev v0")`; si salen
/// `0`, se usa `1`. Vale `0xa8b466a7` y el test lo **recalcula** de su fórmula. Solo la red dev
/// puede usarlo (D-P05).
pub const CBID_RED_DEV: u32 = 0xa8b4_66a7;

/// Etiqueta de consenso de la red `dev-reloj` con las reglas R3 (`ORDEN-RLJ3A`): PMT por la cadena
/// seleccionada del bloque y banda como diagnóstico. Es **distinta** del nombre de la línea de
/// órdenes `dev-reloj` (`RedCli::nombre`), que no cambia.
pub const ETIQUETA_DEV_RELOJ_R3: &str = "dev-reloj-r3-pmt-sp-banda-diag-v1";

/// La cadena a la que pertenece algo.
///
/// Aparece en direcciones (el HRP entra en el checksum, así que una dirección de testnet **no
/// puede** leerse como de mainnet), en la tabla de ramas de consenso, en el génesis y en los
/// parámetros de red.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Red {
    /// Cadena principal.
    Mainnet,
    /// Cadena de pruebas.
    Testnet,
    /// Red de desarrollo de 0.0.1 (F-12, D-P05).
    Dev,
}

impl Red {
    /// Nombre corto, para logs y para componer identificadores.
    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Dev => "dev",
        }
    }

    /// Prefijo mágico de esta red (C-NET-01).
    ///
    /// **Este prefijo, y no el hash del génesis, es lo que impide que un nodo hable con un peer de
    /// otra red.** El génesis distinto (C-GEN-04) evita que las cadenas se confundan; el prefijo
    /// evita que los nodos siquiera se saluden.
    #[must_use]
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Self::Mainnet => MAGIC_MAINNET,
            Self::Testnet => MAGIC_TESTNET,
            Self::Dev => MAGIC_DEV,
        }
    }
}

/// Identidad del saludo de un perfil dev (RL-2c).
///
/// El génesis se aporta desde su fuente en `zx-consensus`: el crate base no depende de consenso.
/// Con reloj activo se compromete su etiqueta; sin reloj se conserva el génesis byte a byte.
#[must_use]
pub fn identidad_red(genesis: [u8; 32], etiqueta: &str, reloj_activo: bool) -> crate::BlockHash {
    if reloj_activo {
        let mut bytes = Vec::with_capacity(genesis.len() + etiqueta.len());
        bytes.extend_from_slice(&genesis);
        bytes.extend_from_slice(etiqueta.as_bytes());
        crate::BlockHash::from_digest(crate::sha3_256_publico(&bytes))
    } else {
        crate::BlockHash::from_digest(crate::Digest::from_bytes(genesis))
    }
}

/// Declara la lista canónica de redes de CLI en un consumidor.
///
/// Los atributos se aportan en el consumidor, que ya depende de clap: `zx-core` sigue siendo
/// independiente de la CLI. El nodo conserva su tipo y su método local `perfil_red`.
#[macro_export]
macro_rules! definir_red_cli {
    ($(#[$atributo:meta])* $vis:vis enum $nombre:ident) => {
        $(#[$atributo])*
        $vis enum $nombre {
            /// Red de desarrollo clásica, sin reloj activo.
            Dev,
            /// Red de desarrollo con reloj por ticks y segundo VDF activos.
            DevReloj,
            /// Red principal, reconocida pero no operativa en los binarios dev.
            Mainnet,
            /// Red de pruebas, reconocida pero no operativa en los binarios dev.
            Testnet,
        }

        impl $nombre {
            /// Selección por defecto compartida por nodo y cartera.
            pub const POR_DEFECTO: Self = Self::Dev;

            /// Etiqueta estable del perfil y nombre de la opción de CLI.
            #[must_use]
            pub const fn nombre(self) -> &'static str {
                match self {
                    Self::Dev => "dev",
                    Self::DevReloj => "dev-reloj",
                    Self::Mainnet => "mainnet",
                    Self::Testnet => "testnet",
                }
            }

            /// Activación del reloj de la selección dev.
            #[must_use]
            pub const fn reloj_activo(self) -> bool {
                matches!(self, Self::DevReloj)
            }

            /// Etiqueta que entra en la identidad de consenso del saludo.
            ///
            /// Coincide con [`Self::nombre`] salvo en `dev-reloj`, que usa la etiqueta R3
            /// (`ORDEN-RLJ3A`): al cambiar la regla de marcas cambia la identidad de red. La
            /// etiqueta de `dev` no cambia (y su identidad tampoco: sin reloj la función de
            /// identidad ignora la etiqueta).
            #[must_use]
            pub const fn etiqueta_consenso(self) -> &'static str {
                match self {
                    Self::Dev => "dev",
                    Self::DevReloj => $crate::red::ETIQUETA_DEV_RELOJ_R3,
                    Self::Mainnet => "mainnet",
                    Self::Testnet => "testnet",
                }
            }
        }

        impl From<$nombre> for $crate::Red {
            fn from(red: $nombre) -> Self {
                match red {
                    $nombre::Dev | $nombre::DevReloj => Self::Dev,
                    $nombre::Mainnet => Self::Mainnet,
                    $nombre::Testnet => Self::Testnet,
                }
            }
        }
    };
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{CBID_RED_DEV, MAGIC_DEV, MAGIC_MAINNET, MAGIC_TESTNET, Red};
    use crate::sha3_256_publico;

    #[test]
    fn las_dos_redes_tienen_nombres_distintos() {
        assert_ne!(Red::Mainnet.nombre(), Red::Testnet.nombre());
        assert_eq!(Red::Mainnet.nombre(), "mainnet");
        assert_eq!(Red::Dev.nombre(), "dev");
        assert_ne!(Red::Dev.nombre(), Red::Mainnet.nombre());
    }

    /// **C-NET-01.** Los prefijos son **derivados, no inventados**, y esto lo demuestra.
    ///
    /// El SPEC afirma que salen de `SHA3-256("ZEROX/<red>/magic")`. Una afirmación así o se
    /// comprueba o sobra: sin este test nadie sabría si los bytes del SPEC son los que da la
    /// fórmula o los que alguien tecleó una vez.
    #[test]
    fn los_prefijos_magicos_se_derivan_de_su_formula() {
        for red in [Red::Mainnet, Red::Testnet, Red::Dev] {
            let etiqueta = format!("ZEROX/{}/magic", red.nombre());
            let h = sha3_256_publico(etiqueta.as_bytes());
            let cuatro: [u8; 4] = h.as_bytes().get(..4).unwrap().try_into().unwrap();
            assert_eq!(
                cuatro,
                red.magic(),
                "primeros 4 bytes de SHA3-256({etiqueta:?})"
            );
        }
    }

    /// Bitcoin documenta que sus prefijos *"not valid as UTF-8"*. Comprobado, no citado.
    #[test]
    fn los_prefijos_magicos_no_son_utf8_valido() {
        for magic in [MAGIC_MAINNET, MAGIC_TESTNET, MAGIC_DEV] {
            assert!(core::str::from_utf8(&magic).is_err(), "{magic:02x?}");
        }
    }

    #[test]
    fn cada_red_tiene_su_propio_prefijo() {
        assert_ne!(Red::Mainnet.magic(), Red::Testnet.magic());
        assert_ne!(Red::Mainnet.magic(), Red::Dev.magic());
        assert_ne!(Red::Testnet.magic(), Red::Dev.magic());
    }

    /// **F-12.** El `CONSENSUS_BRANCH_ID` de dev es **derivado**, no tecleado: se recalcula aquí
    /// de su fórmula exacta (primeros 4 bytes LE de `SHA3-256("ZEROX hibrido red dev v0")`; `0` se
    /// sustituye por `1`).
    #[test]
    fn el_cbid_de_dev_se_deriva_de_su_formula() {
        let h = sha3_256_publico(b"ZEROX hibrido red dev v0");
        let bytes: [u8; 4] = h.as_bytes().get(..4).unwrap().try_into().unwrap();
        let mut cbid = u32::from_le_bytes(bytes);
        if cbid == 0 {
            cbid = 1;
        }
        assert_eq!(cbid, CBID_RED_DEV, "F-12");
        assert_ne!(CBID_RED_DEV, 0, "F-12: 0 se sustituye por 1");
    }
}
