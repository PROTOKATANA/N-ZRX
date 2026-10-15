//! Familia `pruebas`: cuerpos de pruebas indexados por su **huella de 32 B**.
//!
//! # Qué guarda y por qué
//!
//! El carril de pruebas recursivas (contrato `CP-1`, reglas `CP-R-27`…`CP-R-31`) mantiene los
//! cuerpos de prueba **fuera** de la cadena: lo que viaja en la cadena es solo la huella de 32 B.
//! Este almacén es el que guarda esos cuerpos en el nodo, con **metadatos de retención** —un punto
//! (`slot` o `altura`) de referencia— para poder **podar** el cuerpo cuando ya no hace falta,
//! conservando la huella y el metadato.
//!
//! # Contrato
//!
//! - La clave es la huella de 32 B; el valor guarda `referencia u64 BE ‖ estado u8 ‖ [cuerpo]`. La
//!   huella **es** la clave, así que podar el cuerpo no la pierde.
//! - Guardar un cuerpo mayor que [`MAX_CUERPO_PRUEBA_BYTES`] se **rechaza** (defensa contra bombas
//!   de memoria; `CP-R-05`).
//! - Guardar la misma huella con **otro** cuerpo es corrupción: la huella identifica al cuerpo.
//! - [`AlmacenPruebas::podar_hasta`] borra el cuerpo de las entradas con `referencia <= punto` y
//!   deja `Podado` con la huella y la referencia. Es idempotente.
//! - Una entrada ya podada **no se rehidrata**: volver a guardar el cuerpo la deja podada (el
//!   cuerpo que se recibe de nuevo no se retiene más allá del punto de poda).
//!
//! El punto y la referencia son **opacos** para este módulo: PODA-1a (finalidad por votos) los
//! calcula fuera y aquí solo se comparan. Así el almacén no depende de los tipos de `zx-core` ni de
//! `zx-consensus`.
//!
//! # Familia física en disco
//!
//! En el backend RocksDB ([`crate::disco`]) la familia lógica `pruebas` vive en el *column family*
//! `default` bajo el prefijo `prueba:`. No se añade un *column family* nuevo a propósito: RocksDB
//! exige que un abridor liste **todas** las familias existentes y `crates/zx-node/tests/reinicio.rs`
//! abre el mismo almacén listando solo `bloques`, `registro` y `meta`; un cuarto *column family*
//! haría fallar ese test con `Column families not opened`. `default` ya lo abren todos los
//! abridores (rust-rocksdb lo añade solo), de modo que la familia nueva no rompe a nadie.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::StorageError;

/// Tope de tamaño de un cuerpo de prueba, en bytes (`CP-R-05` del contrato `CP-1`).
pub const MAX_CUERPO_PRUEBA_BYTES: usize = 400_000;

/// Longitud, en bytes, de la huella que indexa un cuerpo.
pub const LONGITUD_HUELLA: usize = 32;

/// Huella de 32 B que identifica un cuerpo de prueba.
pub type Huella = [u8; LONGITUD_HUELLA];

/// Punto de retención: el `slot` o la altura a la que se ata el cuerpo.
pub type Referencia = u64;

/// Estado de una prueba en el almacén.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstadoPrueba {
    /// El cuerpo sigue retenido.
    Presente {
        /// Huella que indexa el cuerpo.
        huella: Huella,
        /// Punto de retención.
        referencia: Referencia,
        /// Bytes del cuerpo.
        cuerpo: Vec<u8>,
    },
    /// El cuerpo se podó; quedan la huella y el metadato.
    Podado {
        /// Huella que indexa el cuerpo.
        huella: Huella,
        /// Punto de retención.
        referencia: Referencia,
    },
}

impl EstadoPrueba {
    /// La huella del objeto, en los dos estados.
    #[must_use]
    pub fn huella(&self) -> Huella {
        match self {
            Self::Presente { huella, .. } | Self::Podado { huella, .. } => *huella,
        }
    }

    /// El punto de retención.
    #[must_use]
    pub fn referencia(&self) -> Referencia {
        match self {
            Self::Presente { referencia, .. } | Self::Podado { referencia, .. } => *referencia,
        }
    }

    /// El cuerpo, o `None` si está podado.
    #[must_use]
    pub fn cuerpo(&self) -> Option<&[u8]> {
        match self {
            Self::Presente { cuerpo, .. } => Some(cuerpo),
            Self::Podado { .. } => None,
        }
    }

    /// ¿Se podó el cuerpo?
    #[must_use]
    pub fn esta_podado(&self) -> bool {
        matches!(self, Self::Podado { .. })
    }
}

/// Almacén de cuerpos de pruebas por huella.
pub trait AlmacenPruebas: Send + Sync {
    /// Guarda un cuerpo bajo su huella con su punto de retención.
    ///
    /// Si la huella ya estaba guardada con el mismo cuerpo, es idempotente y el punto de retención
    /// sube al mayor de los dos. Si ya estaba **podada**, sigue podada (no se rehidrata) y el punto
    /// también sube al mayor.
    ///
    /// # Errores
    /// [`StorageError::CuerpoDemasiadoGrande`] si `cuerpo` supera [`MAX_CUERPO_PRUEBA_BYTES`];
    /// [`StorageError::Corrupto`] si la misma huella ya estaba guardada con**otro** cuerpo.
    fn guardar(
        &self,
        huella: Huella,
        referencia: Referencia,
        cuerpo: &[u8],
    ) -> Result<(), StorageError>;

    /// Devuelve el estado de una huella.
    ///
    /// `Ok(None)` significa que esa huella no está en el almacén; una entrada corrupta devuelve
    /// error.
    ///
    /// # Errores
    /// [`StorageError::Corrupto`] si el valor guardado no decodifica.
    fn obtener(&self, huella: &Huella) -> Result<Option<EstadoPrueba>, StorageError>;

    /// Poda los cuerpos con `referencia <= punto` y conserva huella y metadato.
    ///
    /// Devuelve cuántos cuerpos se podaron. Es idempotente: repetir con el mismo punto no poda nada
    /// más.
    ///
    /// # Errores
    /// [`StorageError::Corrupto`] si algún valor guardado no decodifica; [`StorageError::Backend`]
    /// si el backend falla.
    fn podar_hasta(&self, punto: Referencia) -> Result<u64, StorageError>;
}

/// Discriminante de una entrada con el cuerpo presente.
pub(crate) const ESTADO_PRESENTE: u8 = 0x01;
/// Discriminante de una entrada sin cuerpo (podada).
pub(crate) const ESTADO_PODADO: u8 = 0x02;

/// Codifica el valor guardado: `referencia u64 BE ‖ estado u8 ‖ [cuerpo]`.
pub(crate) fn valor_a_bytes(referencia: Referencia, cuerpo: Option<&[u8]>) -> Vec<u8> {
    let capacidad = 9 + cuerpo.map_or(0, <[u8]>::len);
    let mut valor = Vec::with_capacity(capacidad);
    valor.extend_from_slice(&referencia.to_be_bytes());
    match cuerpo {
        Some(bytes) => {
            valor.push(ESTADO_PRESENTE);
            valor.extend_from_slice(bytes);
        }
        None => valor.push(ESTADO_PODADO),
    }
    valor
}

/// Decodifica el valor guardado `referencia u64 BE ‖ estado u8 ‖ [cuerpo]`.
///
/// # Errores
/// [`StorageError::Corrupto`] si el valor está truncado o el discriminante no es conocido.
pub(crate) fn valor_desde_bytes(valor: &[u8]) -> Result<(Referencia, Option<&[u8]>), StorageError> {
    let (referencia_bytes, resto) = valor.split_at_checked(8).ok_or(StorageError::Corrupto {
        que: "una entrada de `pruebas` sin sus 8 B de referencia",
    })?;
    let referencia: [u8; 8] = referencia_bytes
        .try_into()
        .map_err(|_| StorageError::Corrupto {
            que: "la referencia de una entrada de `pruebas`",
        })?;
    let (estado, cuerpo) = resto.split_first().ok_or(StorageError::Corrupto {
        que: "una entrada de `pruebas` sin su discriminante",
    })?;
    match *estado {
        ESTADO_PRESENTE => Ok((Referencia::from_be_bytes(referencia), Some(cuerpo))),
        ESTADO_PODADO => Ok((Referencia::from_be_bytes(referencia), None)),
        _ => Err(StorageError::Corrupto {
            que: "el discriminante de una entrada de `pruebas`",
        }),
    }
}

/// Un lock envenenado significa que otro hilo entró en pánico mientras lo tenía.
fn envenenado() -> StorageError {
    StorageError::Backend("lock envenenado: otro hilo entró en pánico".to_owned())
}

/// Estado de una entrada en memoria: punto de retención y cuerpo (`None` si está podado).
type EntradaEnMemoria = (Referencia, Option<Vec<u8>>);

/// Implementación de referencia en RAM, sin dependencia de `zx-core`.
///
/// Es el oráculo simple contra el que se contrasta el backend de RocksDB, igual que
/// [`crate::memoria::AlmacenEnMemoria`] lo es para los bloques.
#[derive(Debug, Default)]
pub struct AlmacenPruebasEnMemoria {
    /// Estado por huella: punto de retención y cuerpo (`None` si está podado).
    interior: RwLock<HashMap<Huella, EntradaEnMemoria>>,
}

impl AlmacenPruebasEnMemoria {
    /// Uno vacío.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }
}

impl AlmacenPruebas for AlmacenPruebasEnMemoria {
    fn guardar(
        &self,
        huella: Huella,
        referencia: Referencia,
        cuerpo: &[u8],
    ) -> Result<(), StorageError> {
        if cuerpo.len() > MAX_CUERPO_PRUEBA_BYTES {
            return Err(StorageError::CuerpoDemasiadoGrande {
                bytes: cuerpo.len(),
                tope: MAX_CUERPO_PRUEBA_BYTES,
            });
        }
        let mut i = self.interior.write().map_err(|_| envenenado())?;
        if let Some((retencion, guardado)) = i.get_mut(&huella) {
            if guardado
                .as_ref()
                .is_some_and(|bytes| bytes.as_slice() != cuerpo)
            {
                return Err(StorageError::Corrupto {
                    que: "la misma huella de `pruebas` con dos cuerpos distintos",
                });
            }
            if referencia > *retencion {
                *retencion = referencia;
            }
            return Ok(());
        }
        i.insert(huella, (referencia, Some(cuerpo.to_vec())));
        Ok(())
    }

    fn obtener(&self, huella: &Huella) -> Result<Option<EstadoPrueba>, StorageError> {
        let i = self.interior.read().map_err(|_| envenenado())?;
        Ok(i.get(huella).map(|(referencia, cuerpo)| match cuerpo {
            Some(bytes) => EstadoPrueba::Presente {
                huella: *huella,
                referencia: *referencia,
                cuerpo: bytes.clone(),
            },
            None => EstadoPrueba::Podado {
                huella: *huella,
                referencia: *referencia,
            },
        }))
    }

    fn podar_hasta(&self, punto: Referencia) -> Result<u64, StorageError> {
        let mut i = self.interior.write().map_err(|_| envenenado())?;
        let mut podados: u64 = 0;
        for (retencion, cuerpo) in i.values_mut() {
            if *retencion <= punto && cuerpo.is_some() {
                *cuerpo = None;
                podados += 1;
            }
        }
        Ok(podados)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{
        AlmacenPruebas, AlmacenPruebasEnMemoria, EstadoPrueba, Huella, MAX_CUERPO_PRUEBA_BYTES,
    };

    fn huella(n: u8) -> Huella {
        [n; 32]
    }

    #[test]
    fn guardar_y_obtener_devuelve_el_cuerpo_y_el_metadato() {
        let a = AlmacenPruebasEnMemoria::nuevo();
        a.guardar(huella(0x11), 7, b"cuerpo").expect("guarda");

        let estado = a.obtener(&huella(0x11)).expect("obtiene").expect("existe");
        assert_eq!(estado.huella(), huella(0x11));
        assert_eq!(estado.referencia(), 7);
        assert_eq!(estado.cuerpo(), Some(b"cuerpo".as_slice()));
        assert!(!estado.esta_podado());

        assert_eq!(a.obtener(&huella(0x22)).expect("obtiene"), None);
    }

    #[test]
    fn podar_conserva_la_huella_y_el_metadato_y_no_toca_lo_posterior() {
        let a = AlmacenPruebasEnMemoria::nuevo();
        a.guardar(huella(0x01), 10, b"viejo").expect("guarda viejo");
        a.guardar(huella(0x02), 20, b"nuevo").expect("guarda nuevo");

        assert_eq!(
            a.podar_hasta(10).expect("poda"),
            1,
            "solo poda el de ref <= 10"
        );

        let viejo = a.obtener(&huella(0x01)).expect("obtiene").expect("existe");
        assert!(viejo.esta_podado(), "el de ref 10 queda podado");
        assert_eq!(viejo.huella(), huella(0x01), "conserva la huella");
        assert_eq!(viejo.referencia(), 10, "conserva el metadato");
        assert_eq!(viejo.cuerpo(), None, "el cuerpo ya no está");

        let nuevo = a.obtener(&huella(0x02)).expect("obtiene").expect("existe");
        assert!(!nuevo.esta_podado(), "el de ref 20 no se toca");
        assert_eq!(nuevo.cuerpo(), Some(b"nuevo".as_slice()));

        // Idempotente.
        assert_eq!(a.podar_hasta(10).expect("poda otra vez"), 0);
    }

    #[test]
    fn un_cuerpo_mayor_que_el_tope_se_rechaza() {
        let a = AlmacenPruebasEnMemoria::nuevo();
        let grande = vec![0xAB; MAX_CUERPO_PRUEBA_BYTES + 1];
        let err = a
            .guardar(huella(0x03), 1, &grande)
            .expect_err("un cuerpo por encima del tope MUST rechazarse");
        assert!(matches!(
            err,
            crate::error::StorageError::CuerpoDemasiadoGrande { .. }
        ));
        assert_eq!(
            a.obtener(&huella(0x03)).expect("obtiene"),
            None,
            "el rechazo no deja entrada"
        );

        // El tope exacto sí cabe.
        let justo = vec![0xCD; MAX_CUERPO_PRUEBA_BYTES];
        a.guardar(huella(0x04), 1, &justo).expect("el tope cabe");
        let estado = a.obtener(&huella(0x04)).expect("obtiene").expect("existe");
        assert_eq!(
            estado.cuerpo().map(<[u8]>::len),
            Some(MAX_CUERPO_PRUEBA_BYTES)
        );
    }

    #[test]
    fn la_misma_huella_con_otro_cuerpo_es_corrupcion() {
        let a = AlmacenPruebasEnMemoria::nuevo();
        a.guardar(huella(0x05), 1, b"uno").expect("guarda");
        let err = a
            .guardar(huella(0x05), 1, b"dos")
            .expect_err("dos cuerpos bajo la misma huella MUST ser error");
        assert!(matches!(err, crate::error::StorageError::Corrupto { .. }));
    }

    #[test]
    fn una_entrada_podada_no_se_rehidrata_y_sube_su_punto() {
        let a = AlmacenPruebasEnMemoria::nuevo();
        a.guardar(huella(0x06), 5, b"cuerpo").expect("guarda");
        assert_eq!(a.podar_hasta(5).expect("poda"), 1);
        a.guardar(huella(0x06), 9, b"cuerpo").expect("reguarda");
        let estado = a.obtener(&huella(0x06)).expect("obtiene").expect("existe");
        assert!(estado.esta_podado(), "una entrada podada no revive");
        assert_eq!(estado.referencia(), 9, "el punto de retención sube");
    }

    #[test]
    fn el_valor_codifica_y_decodifica_ida_y_vuelta() {
        let con_cuerpo = super::valor_a_bytes(42, Some(b"xyz"));
        assert_eq!(
            super::valor_desde_bytes(&con_cuerpo).expect("decodifica"),
            (42, Some(b"xyz".as_slice()))
        );
        let podado = super::valor_a_bytes(42, None);
        assert_eq!(
            super::valor_desde_bytes(&podado).expect("decodifica"),
            (42, None)
        );
        assert!(super::valor_desde_bytes(&[0x00, 0x01]).is_err());
        assert!(super::valor_desde_bytes(&[0; 8]).is_err());
        let mut desconocido = 1u64.to_be_bytes().to_vec();
        desconocido.push(0xFF);
        assert!(super::valor_desde_bytes(&desconocido).is_err());
    }

    #[test]
    fn el_estado_documenta_sus_dos_formas() {
        let presente = EstadoPrueba::Presente {
            huella: [1; 32],
            referencia: 3,
            cuerpo: vec![9],
        };
        let podado = EstadoPrueba::Podado {
            huella: [1; 32],
            referencia: 3,
        };
        assert_eq!(presente.cuerpo(), Some([9].as_slice()));
        assert_eq!(podado.cuerpo(), None);
        assert_eq!(presente.huella(), podado.huella());
    }
}
