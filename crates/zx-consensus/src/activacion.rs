//! Activación de ramas de consenso (`C-UPG-01…05`) y parámetros de red.
//!
//! Portado de `9681061` con **una** diferencia: la red dev tiene su propia rama,
//! `(CBID_RED_DEV, 0)`, y mainnet/testnet conservan la tabla antigua sin cambios (`ORDEN-W04 §3.9`).
//!
//! El `CONSENSUS_BRANCH_ID` va en la cabecera (ZIP-200) para cerrar el ataque de *wipe-out*: un
//! bloque de una rama vieja no puede competir a alturas donde rige otra.

use crate::error::ErrorPow;

/// La red, definida en `zx-core` y reexportada aquí por comodidad.
pub use zx_core::Red;

pub use zx_core::red::{MAGIC_MAINNET, MAGIC_TESTNET};

/// Una rama de consenso: su identificador y la altura desde la que rige (`C-UPG-02`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rama {
    /// `CONSENSUS_BRANCH_ID`. **MUST** ser no cero y globalmente único.
    pub id: u32,
    /// Altura desde la que se aplican sus reglas.
    pub desde_altura: u32,
}

/// Rama v1.0 de mainnet, activa desde el génesis (`C-UPG-02`).
///
/// `0xc47880ea` = primeros 4 bytes de `SHA3-256("ZEROX/consensus-branch/v1.0")` leídos como `u32`
/// little-endian. **Derivado, no inventado**: cualquiera puede reproducirlo.
pub const RAMA_V1_MAINNET: Rama = Rama {
    id: 0xc478_80ea,
    desde_altura: 0,
};

/// Tabla de ramas de mainnet, **ordenada por altura ascendente**.
pub const RAMAS_MAINNET: &[Rama] = &[RAMA_V1_MAINNET];

/// Tabla de ramas de testnet.
///
/// Comparte identificador con mainnet en v1.0 porque las dos redes ya están separadas por el génesis
/// (`C-GEN-04`) y por el prefijo mágico (`C-NET-01`).
pub const RAMAS_TESTNET: &[Rama] = &[RAMA_V1_MAINNET];

/// Rama única de la **red dev** (`F-12`, D-P05): `CBID_RED_DEV` desde la altura 0.
pub const RAMA_DEV: Rama = Rama {
    id: zx_core::CBID_RED_DEV,
    desde_altura: 0,
};

/// Tabla de ramas de la red dev: una sola rama (`ORDEN-W04 §3.9`).
pub const RAMAS_DEV: &[Rama] = &[RAMA_DEV];

/// Tabla de ramas de una red.
///
/// Función libre y no método porque [`Red`] vive en `zx-core`.
#[must_use]
pub const fn ramas(red: Red) -> &'static [Rama] {
    match red {
        Red::Mainnet => RAMAS_MAINNET,
        Red::Testnet => RAMAS_TESTNET,
        Red::Dev => RAMAS_DEV,
    }
}

/// Identificador de rama activo a una altura dada (`C-UPG-01`, `C-UPG-02`).
///
/// # Errores
/// [`ErrorPow::SinRamaActiva`] si ninguna rama cubre esa altura.
pub fn rama_activa(red: Red, altura: u32) -> Result<u32, ErrorPow> {
    ramas(red)
        .iter()
        .rev()
        .find(|r| altura >= r.desde_altura)
        .map(|r| r.id)
        .ok_or(ErrorPow::SinRamaActiva { altura })
}

/// `C-HDR-02b`: el `consensus_branch_id` de la cabecera **MUST** ser el activo a esa altura.
///
/// # Errores
/// [`ErrorPow::BranchIdIncorrecto`].
pub fn comprobar_branch_id(red: Red, altura: u32, branch_id: u32) -> Result<(), ErrorPow> {
    let esperado = rama_activa(red, altura)?;
    if branch_id == esperado {
        Ok(())
    } else {
        Err(ErrorPow::BranchIdIncorrecto {
            altura,
            esperado,
            encontrado: branch_id,
        })
    }
}

/// Comprueba que una tabla de ramas está bien formada (`C-UPG-02`, `C-UPG-03`).
///
/// Invariantes: arranca en la altura 0, las alturas crecen estrictamente, ningún identificador es
/// cero y no hay identificadores repetidos.
///
/// # Errores
/// [`ErrorPow::TablaDeRamasInvalida`] con el motivo.
pub fn comprobar_tabla(ramas: &[Rama]) -> Result<(), ErrorPow> {
    let malo = |motivo| ErrorPow::TablaDeRamasInvalida { motivo };

    let primera = ramas.first().ok_or_else(|| malo("la tabla está vacía"))?;
    if primera.desde_altura != 0 {
        return Err(malo("la primera rama MUST arrancar en la altura 0"));
    }

    let mut vistos: Vec<u32> = Vec::with_capacity(ramas.len());
    let mut altura_previa: Option<u32> = None;

    for r in ramas {
        if r.id == 0 {
            return Err(malo("un CONSENSUS_BRANCH_ID MUST ser distinto de cero"));
        }
        if vistos.contains(&r.id) {
            return Err(malo("dos ramas comparten CONSENSUS_BRANCH_ID"));
        }
        vistos.push(r.id);

        if let Some(prev) = altura_previa
            && r.desde_altura <= prev
        {
            return Err(malo("las alturas de activación MUST crecer estrictamente"));
        }
        altura_previa = Some(r.desde_altura);
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{
        MAGIC_MAINNET, MAGIC_TESTNET, RAMA_DEV, RAMA_V1_MAINNET, RAMAS_MAINNET, Rama, Red,
        comprobar_branch_id, comprobar_tabla, rama_activa, ramas,
    };
    use crate::error::ErrorPow;
    use zx_core::sha3_256_publico;

    /// Las constantes derivadas se recalculan aquí, no se confían.
    #[test]
    fn las_constantes_derivadas_se_reproducen() {
        let cbid = sha3_256_publico(b"ZEROX/consensus-branch/v1.0");
        let cuatro = cbid.as_bytes().get(..4).unwrap();
        let esperado = u32::from_le_bytes(cuatro.try_into().unwrap());
        assert_eq!(
            RAMA_V1_MAINNET.id, esperado,
            "el branch ID MUST ser los primeros 4 B de SHA3-256(\"ZEROX/consensus-branch/v1.0\") en LE"
        );

        let m = sha3_256_publico(b"ZEROX/mainnet/magic");
        assert_eq!(m.as_bytes().get(..4).unwrap(), MAGIC_MAINNET);
        let t = sha3_256_publico(b"ZEROX/testnet/magic");
        assert_eq!(t.as_bytes().get(..4).unwrap(), MAGIC_TESTNET);
    }

    /// **F-12.** El `CBID` de dev es derivado: se recalcula de su fórmula.
    #[test]
    fn el_cbid_de_dev_se_reproduce() {
        let h = sha3_256_publico(b"ZEROX hibrido red dev v0");
        let bytes: [u8; 4] = h.as_bytes().get(..4).unwrap().try_into().unwrap();
        let mut cbid = u32::from_le_bytes(bytes);
        if cbid == 0 {
            cbid = 1;
        }
        assert_eq!(RAMA_DEV.id, cbid, "F-12");
        assert_eq!(RAMA_DEV.id, zx_core::CBID_RED_DEV);
    }

    #[test]
    fn el_branch_id_no_es_cero() {
        assert_ne!(RAMA_V1_MAINNET.id, 0, "C-UPG-02: MUST ser no cero");
        assert_ne!(RAMA_DEV.id, 0);
    }

    #[test]
    fn la_rama_v1_rige_desde_el_genesis() {
        assert_eq!(rama_activa(Red::Mainnet, 0).unwrap(), RAMA_V1_MAINNET.id);
        assert_eq!(
            rama_activa(Red::Mainnet, u32::MAX).unwrap(),
            RAMA_V1_MAINNET.id
        );
        assert_eq!(rama_activa(Red::Dev, 0).unwrap(), RAMA_DEV.id);
        assert_eq!(rama_activa(Red::Dev, u32::MAX).unwrap(), RAMA_DEV.id);
    }

    #[test]
    fn la_tabla_real_esta_bien_formada() {
        assert!(comprobar_tabla(RAMAS_MAINNET).is_ok());
        assert!(comprobar_tabla(ramas(Red::Testnet)).is_ok());
        assert!(comprobar_tabla(ramas(Red::Dev)).is_ok());
        assert_eq!(ramas(Red::Dev).len(), 1, "§3.9: una sola rama dev");
    }

    /// La tabla se editará a mano en cada hard fork: estas son las formas de estropearla.
    #[test]
    fn se_detecta_una_tabla_mal_formada() {
        let casos: [(&str, Vec<Rama>); 5] = [
            ("vacía", vec![]),
            (
                "no arranca en 0",
                vec![Rama {
                    id: 1,
                    desde_altura: 5,
                }],
            ),
            (
                "alturas no crecientes",
                vec![
                    Rama {
                        id: 1,
                        desde_altura: 0,
                    },
                    Rama {
                        id: 2,
                        desde_altura: 0,
                    },
                ],
            ),
            (
                "altura que retrocede",
                vec![
                    Rama {
                        id: 1,
                        desde_altura: 0,
                    },
                    Rama {
                        id: 2,
                        desde_altura: 100,
                    },
                    Rama {
                        id: 3,
                        desde_altura: 50,
                    },
                ],
            ),
            (
                "id cero",
                vec![Rama {
                    id: 0,
                    desde_altura: 0,
                }],
            ),
        ];
        for (que, tabla) in casos {
            assert!(
                matches!(
                    comprobar_tabla(&tabla),
                    Err(ErrorPow::TablaDeRamasInvalida { .. })
                ),
                "debería detectarse: {que}"
            );
        }
    }

    /// **La protección contra wipe-out en funcionamiento.**
    #[test]
    fn un_bloque_de_la_rama_vieja_no_vale_en_la_nueva() {
        const VIEJA: u32 = 0x1111_1111;
        const NUEVA: u32 = 0x2222_2222;
        let tabla = vec![
            Rama {
                id: VIEJA,
                desde_altura: 0,
            },
            Rama {
                id: NUEVA,
                desde_altura: 1000,
            },
        ];
        assert!(comprobar_tabla(&tabla).is_ok());

        let activo_en = |h: u32| {
            tabla
                .iter()
                .rev()
                .find(|r| h >= r.desde_altura)
                .map(|r| r.id)
                .unwrap()
        };
        assert_eq!(activo_en(999), VIEJA, "antes de la activación");
        assert_eq!(activo_en(1000), NUEVA, "justo en la altura de activación");
    }

    #[test]
    fn se_rechaza_una_cabecera_con_el_branch_id_equivocado() {
        assert!(comprobar_branch_id(Red::Mainnet, 10, RAMA_V1_MAINNET.id).is_ok());
        assert!(comprobar_branch_id(Red::Dev, 10, RAMA_DEV.id).is_ok());
        let e = comprobar_branch_id(Red::Mainnet, 10, 0xDEAD_BEEF).unwrap_err();
        assert!(matches!(e, ErrorPow::BranchIdIncorrecto { .. }), "{e:?}");
        assert!(
            comprobar_branch_id(Red::Dev, 10, RAMA_V1_MAINNET.id).is_err(),
            "un branch_id de mainnet NO vale en dev"
        );
    }
}
