//! Historia archivada del **génesis dev** (D-P12) y contexto de pieza coherente con ella.
//!
//! # Qué es y qué no es
//!
//! [`HistoriaGenesis`] archiva **una vez** el cuerpo del génesis dev de W04
//! (`zx_consensus::GENESIS_DEV`) —codificado con la red de `zx_core::wire`— rellenado hasta
//! `RecordedHistorySegment::SIZE` con `ChaCha8Rng` sembrado con `block_hash(génesis)`, usando el
//! `Archiver` real del clon fijado (`terceros/autonomys` @ `f8842d0`). Expone, de forma
//! inmutable:
//!
//! - el segmento archivado [`NewArchivedSegment`] que produjo esa archivación (el **primero**, es
//!   decir el segmento 0) y las **2⁸ raíces Merkle de registro** + la raíz Merkle de segmento
//!   (B-21, PT-2a-2);
//! - el [`ErasureCoding`] con el que se archivó;
//! - el [`FarmerProtocolInfo`] de desarrollo ([`crate::protocolo_dev`]);
//! - el contexto de pieza [`PieceCheckParams`] coherente con el segmento y con ese protocolo.
//!
//! Es la **fuente única** que productor, auditor y verificador comparten para no reconstruir cada
//! uno su propia historia. Sustituye a `HistoriaDagDev` de `9681061`, que archivaba un
//! `RecordedHistorySegment` llenado por splitmix64 con semilla fija: ahora el contenido deriva del
//! génesis real de la red dev (D-P12).
//!
//! **No acredita validez.** No hay ninguna función que declare válida una cabecera ni un bloque.
//! `params_pieza` devuelve un contexto de pieza coherente con esta historia dev, pero el cableado a
//! la puerta conjunta (snapshot causal del pasado, flujo, rango, cabecera) es de W05b2; este objeto
//! no admite bloques.
//!
//! # La receta, byte a byte (D-P12)
//!
//! 1. `bytes = cuerpo_a_bytes(génesis dev)`: cabecera PoW de 92 B + `CompactSize(n_tx)` + la
//!    coinbase del génesis con sus testigos (ninguno).
//! 2. `bytes.resize(RecordedHistorySegment::SIZE, 0)`.
//! 3. `ChaCha8Rng::from_seed(block_hash(génesis))` y `rng.fill` sobre la cola `[cuerpo.len(), SIZE)`
//!    — el mismo patrón de Autonomys `sc-consensus-subspace/src/archiver.rs:524-541`, que siembra
//!    con el `state_root`.
//! 4. `Archiver::new(kzg, erasure_coding).add_block(bytes, BlockObjectMapping::default(), false)`.
//! 5. El **primer** `NewArchivedSegment` es el segmento 0.
//!
//! Nuestra semilla y nuestro RNG son una **definición propia** (D-P12): Autonomys siembra con el
//! `state_root` y usa `rand_chacha 0.3.1`; aquí se siembra con `block_hash(génesis)` y se usa
//! `rand_chacha =0.9.0`.
//!
//! # Inmutabilidad de la fuente
//!
//! Los getters exponen el segmento, el KZG, el erasure coding y el protocolo **tal como se
//! archivaron**, y `params_pieza` los deriva de ellos. No existe constructor alterno: no se acepta
//! un compromiso, una historia ni unos parámetros suministrados por un candidato o un usuario.

use std::num::NonZeroUsize;

use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::pieces::Record;
use subspace_core_primitives::segments::{HistorySize, RecordedHistorySegment, SegmentCommitment};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_kzg::Kzg;
use subspace_verification::PieceCheckParams;
use thiserror::Error;
use zx_consensus::{ErrorPow, GENESIS_DEV, construir as construir_genesis};
use zx_core::wire::cuerpo_a_bytes;
use zx_merkle::{
    CompromisoRegistro, ErrorMerkle, REGISTROS_POR_SEGMENTO, TAMANO_HOJA, TestigoChunk,
    TestigoRegistro, construir_registro, construir_segmento,
};

use crate::protocolo_dev;

/// Número de s-buckets de un registro: `Record::NUM_S_BUCKETS = 2¹⁶` (D2).
const S_BUCKETS_POR_REGISTRO: usize = zx_merkle::HOJAS_POR_REGISTRO;

/// Compromiso de segmento **congelado** de la historia génesis dev (D-P12), en bytes.
///
/// Es la **raíz Merkle** de segmento (32 B) de esta historia dev, calculada sobre las 2⁸ raíces
/// Merkle de registro de `construir_bruto`. Se congela para detectar divergencia local del archivo
/// determinista: **no** es un compromiso de mainnet/testnet ni un parámetro de red, y su cotejo no
/// acredita disponibilidad de historia en red ni valida cabeceras. El test
/// `el_compromiso_de_la_historia_genesis_esta_congelado` lo recalcula.
pub const COMPROMISO_HISTORIA_GENESIS_DEV: [u8; 32] = [
    0x20, 0x65, 0x0b, 0xfa, 0x73, 0x96, 0xa7, 0x01, 0x8b, 0x92, 0x4c, 0x90, 0x58, 0x63, 0xaa, 0xd8,
    0xd8, 0xca, 0x05, 0xa7, 0x9d, 0x97, 0x6f, 0x0d, 0xe6, 0xe3, 0xaa, 0xa8, 0x79, 0x6c, 0xec, 0x76,
];

/// Error tipado de la construcción de la historia archivada del génesis dev.
///
/// Separa el fallo del génesis de W04, el del erasure coding, un tamaño de historia no
/// representable como `NonZeroU64`, la ausencia de segmento archivado y la divergencia del
/// compromiso congelado. Ninguno se convierte en un objeto a medias: [`HistoriaGenesis::construir`]
/// solo devuelve `Ok` con el segmento ya archivado.
#[derive(Debug, Error)]
pub enum ErrorHistoriaGenesis {
    /// El génesis dev de W04 no se pudo construir o comprobar.
    #[error("génesis dev de W04: {0}")]
    Genesis(#[from] ErrorPow),
    /// La escala del erasure coding no cabe en `usize` o es cero.
    #[error("escala de erasure coding inválida para la historia génesis dev")]
    EscalaErasureCoding,
    /// `ErasureCoding::new` rechazó la escala calculada.
    ///
    /// El upstream devuelve `String`, de tipado pobre; se conserva textualmente sin fabricar éxito.
    #[error("el erasure coding de la historia génesis dev no se pudo construir: {0}")]
    ErasureCoding(String),
    /// El cuerpo del génesis quedó vacío o más largo que un segmento: no hay cola que rellenar.
    #[error(
        "el cuerpo del génesis ({cuerpo} B) no deja cola dentro de un segmento de {segmento} B"
    )]
    RellenoInvalido {
        /// Longitud del cuerpo codificado del génesis.
        cuerpo: usize,
        /// Tamaño del segmento.
        segmento: usize,
    },
    /// Un tamaño de historia del protocolo dev sería cero y no es representable como `HistorySize`.
    #[error("tamaño de historia dev cero para {segmentos} segmentos")]
    TamanoHistoriaCero {
        /// Tamaño de historia pedido, en segmentos.
        segmentos: u64,
    },
    /// El bloque determinista no produjo ningún segmento archivado.
    #[error("la historia génesis dev no produjo ningún segmento archivado")]
    SinSegmentoArchivado,
    /// El segmento archivado no tenía la forma fijada (2⁸ piezas, 2¹⁶ s-buckets por registro).
    #[error("segmento archivado inesperado: {detalle}")]
    SegmentoInesperado {
        /// Descripción del desajuste.
        detalle: &'static str,
    },
    /// El árbol Merkle de la historia dev no se pudo construir.
    #[error("árbol Merkle de la historia génesis dev: {0}")]
    Merkle(#[from] ErrorMerkle),
    /// El segmento archivado no reprodujo el compromiso congelado (raíz Merkle de segmento).
    ///
    /// Lleva ambos valores para que el fallo sea diagnosticable; el esperado no se deriva del
    /// observado y el observado no se acepta: [`HistoriaGenesis::construir`] no crea el objeto.
    #[error("compromiso de segmento inesperado: esperado {esperado:?}, observado {observado:?}")]
    CompromisoInesperado {
        /// Compromiso congelado de la historia génesis dev.
        esperado: [u8; 32],
        /// Compromiso que produjo esta ejecución.
        observado: [u8; 32],
    },
}

/// Historia archivada del génesis dev, inmutable una vez construida.
///
/// Se crea con [`HistoriaGenesis::construir`] y solo se lee por sus getters. Los campos son
/// privados a propósito: no se puede construir una instancia con un compromiso, una historia o un
/// protocolo traídos de fuera.
#[derive(Debug)]
pub struct HistoriaGenesis {
    historial: NewArchivedSegment,
    erasure_coding: ErasureCoding,
    protocolo: FarmerProtocolInfo,
    /// Las 2⁸ raíces Merkle de registro de la historia dev (dos por registro crudo: origen y
    /// paridad comparten extensión), en el orden de las piezas del segmento.
    raices_registro: Vec<[u8; 32]>,
    /// Raíz Merkle del segmento sobre `raices_registro`.
    compromiso_segmento: [u8; 32],
}

impl HistoriaGenesis {
    /// Construye la historia archivada del génesis dev.
    ///
    /// Aplica la receta de la cabecera del módulo (D-P12) y coteja que el compromiso del primer
    /// segmento coincida con [`COMPROMISO_HISTORIA_GENESIS_DEV`]. No usa `unwrap` ni `expect`: si el
    /// génesis, el erasure coding, el relleno, el archiver o el compromiso fallan, devuelve
    /// [`ErrorHistoriaGenesis`] sin construir el objeto.
    ///
    /// # Errores
    ///
    /// [`ErrorHistoriaGenesis::Genesis`] si el génesis dev no se construye,
    /// [`ErrorHistoriaGenesis::EscalaErasureCoding`] o [`ErrorHistoriaGenesis::ErasureCoding`] si
    /// el erasure coding no se puede instanciar, [`ErrorHistoriaGenesis::RellenoInvalido`] si el
    /// cuerpo no deja cola en el segmento, [`ErrorHistoriaGenesis::TamanoHistoriaCero`] si algún
    /// tamaño del protocolo dev fuera cero, [`ErrorHistoriaGenesis::SinSegmentoArchivado`] si el
    /// archiver no produjo ningún segmento y [`ErrorHistoriaGenesis::CompromisoInesperado`] si el
    /// compromiso observado no es el congelado.
    pub fn construir() -> Result<Self, ErrorHistoriaGenesis> {
        let historia = Self::construir_bruto()?;
        comprobar_compromiso(historia.segment_commitment())?;
        Ok(historia)
    }

    /// Construye la historia sin cotejar el compromiso congelado.
    ///
    /// Es la receta de D-P12 sin la comprobación final. Existe para que el test V7 pueda **recalcular**
    /// el compromiso desde cero dos veces y compararlo, y para que `construir` no derive el esperado
    /// del observado.
    ///
    /// # Errores
    /// Las mismas que [`HistoriaGenesis::construir`] salvo
    /// [`ErrorHistoriaGenesis::CompromisoInesperado`].
    pub fn construir_bruto() -> Result<Self, ErrorHistoriaGenesis> {
        let escala = NonZeroUsize::new(
            usize::try_from(Record::NUM_S_BUCKETS.next_power_of_two().ilog2())
                .map_err(|_| ErrorHistoriaGenesis::EscalaErasureCoding)?,
        )
        .ok_or(ErrorHistoriaGenesis::EscalaErasureCoding)?;
        let erasure_coding =
            ErasureCoding::new(escala).map_err(ErrorHistoriaGenesis::ErasureCoding)?;

        let (cabecera, coinbase) =
            construir_genesis(GENESIS_DEV).map_err(ErrorHistoriaGenesis::Genesis)?;
        let mut bytes = Vec::new();
        cuerpo_a_bytes(&mut bytes, &cabecera, core::slice::from_ref(&coinbase), &[]);

        // Cola de relleno determinista (D-P12): `ChaCha8Rng` sembrado con `block_hash(génesis)`.
        let cuerpo = bytes.len();
        let segmento = RecordedHistorySegment::SIZE;
        bytes.resize(segmento, 0);
        let cola = bytes
            .get_mut(cuerpo..)
            .ok_or(ErrorHistoriaGenesis::RellenoInvalido { cuerpo, segmento })?;
        let mut rng = ChaCha8Rng::from_seed(*cabecera.block_hash().as_bytes());
        rng.fill(cola);

        let mut archiver = Archiver::new(Kzg::new(), erasure_coding.clone());
        let salida = archiver.add_block(bytes, BlockObjectMapping::default(), false);
        let historial = salida
            .archived_segments
            .into_iter()
            .next()
            .ok_or(ErrorHistoriaGenesis::SinSegmentoArchivado)?;

        let protocolo = protocolo_dev::parametros()?;
        // El compromiso de segmento pasa a ser la **raíz Merkle** sobre las 2⁸ raíces de registro
        // (B-21); se calcula de la misma salida del `Archiver` que plotea el productor.
        let (raices_registro, compromiso_segmento) = raices_merkle_de(&historial)?;

        Ok(Self {
            historial,
            erasure_coding,
            protocolo,
            raices_registro,
            compromiso_segmento,
        })
    }

    /// Segmento archivado que produjo el `Archiver` real (el segmento 0).
    #[must_use]
    pub fn historial(&self) -> &NewArchivedSegment {
        &self.historial
    }

    /// Las 2⁸ raíces Merkle de registro del segmento dev, en el orden de sus piezas.
    #[must_use]
    pub fn raices_registro(&self) -> &[[u8; 32]] {
        &self.raices_registro
    }

    /// Camino Merkle de la raíz de registro en `position` dentro del segmento (2⁸ hojas).
    ///
    /// # Errores
    /// [`ErrorMerkle::LongitudIncorrecta`] si `position >= 2⁸`.
    pub fn camino_registro(&self, position: u32) -> Result<TestigoRegistro, ErrorMerkle> {
        zx_merkle::camino_registro(&self.raices_registro, position)
    }

    /// Chunk canónico, raíz de registro y camino del `chunk` en `s_bucket` para la pieza
    /// `position`.
    ///
    /// Construye el árbol Merkle del registro crudo `position / 2` a partir de la historia
    /// archivada (origen y paridad comparten extensión). El productor obtiene de aquí los datos
    /// Merkle sin depender del formato de parcela ni de KZG.
    ///
    /// # Errores
    /// [`ErrorMerkle`] si `position` o `s_bucket` están fuera de rango.
    pub fn chunk_raiz_y_camino(
        &self,
        position: u32,
        s_bucket: u32,
    ) -> Result<([u8; 32], CompromisoRegistro, TestigoChunk), ErrorMerkle> {
        let indice = position as usize;
        if indice >= REGISTROS_POR_SEGMENTO {
            return Err(ErrorMerkle::IndiceFueraDeRango {
                indice,
                n: REGISTROS_POR_SEGMENTO,
            });
        }
        let crudo = indice.div_euclid(2);
        let mut piezas = self.historial.pieces.pieces();
        let origen = piezas
            .nth(crudo * 2)
            .ok_or(ErrorMerkle::IndiceFueraDeRango {
                indice: crudo * 2,
                n: REGISTROS_POR_SEGMENTO,
            })?;
        let paridad = piezas.next().ok_or(ErrorMerkle::IndiceFueraDeRango {
            indice: crudo * 2 + 1,
            n: REGISTROS_POR_SEGMENTO,
        })?;
        let mut chunks = vec![[0u8; TAMANO_HOJA]; S_BUCKETS_POR_REGISTRO];
        for ((destino, a), b) in chunks
            .chunks_exact_mut(2)
            .zip(origen.record().iter())
            .zip(paridad.record().iter())
        {
            if let [x, y] = destino {
                *x = *a;
                *y = *b;
            }
        }
        let chunk =
            chunks
                .get(s_bucket as usize)
                .copied()
                .ok_or(ErrorMerkle::IndiceFueraDeRango {
                    indice: s_bucket as usize,
                    n: S_BUCKETS_POR_REGISTRO,
                })?;
        let (raiz, camino) = zx_merkle::raiz_y_camino_chunk(&chunks, s_bucket)?;
        Ok((chunk, raiz, camino))
    }

    /// Erasure coding, el mismo con el que se archivó el segmento.
    #[must_use]
    pub fn erasure_coding(&self) -> &ErasureCoding {
        &self.erasure_coding
    }

    /// Raíz Merkle de segmento de la historia génesis dev (32 B, B-21).
    ///
    /// Es una medición de la historia génesis dev, no un compromiso de génesis de red.
    #[must_use]
    pub fn segment_commitment(&self) -> [u8; 32] {
        self.compromiso_segmento
    }

    /// Protocolo dev, por copia.
    #[must_use]
    pub fn protocolo(&self) -> FarmerProtocolInfo {
        self.protocolo
    }

    /// Tamaño de historia del protocolo dev, por copia.
    #[must_use]
    pub fn history_size(&self) -> HistorySize {
        self.protocolo.history_size
    }

    /// Contexto de pieza coherente con el segmento archivado y el protocolo dev.
    ///
    /// Construye **todos** los campos a partir del segmento y del mismo [`FarmerProtocolInfo`], con
    /// `sector_expiration_check_segment_commitment: None`. Este contexto vale para el paso 5 de
    /// `C-POT-08` cuando el resto del lote (slot, salida y rango) ya viene validado; no valida una
    /// cabecera por sí mismo.
    #[must_use]
    pub fn params_pieza(&self) -> PieceCheckParams {
        PieceCheckParams {
            max_pieces_in_sector: self.protocolo.max_pieces_in_sector,
            segment_commitment: a_segment_commitment(self.compromiso_segmento),
            recent_segments: self.protocolo.recent_segments,
            recent_history_fraction: self.protocolo.recent_history_fraction,
            min_sector_lifetime: self.protocolo.min_sector_lifetime,
            current_history_size: self.protocolo.history_size,
            sector_expiration_check_segment_commitment: None,
        }
    }
}

/// Encaja una raíz Merkle de segmento (32 B) en el `SegmentCommitment` de 48 B: los 32 primeros
/// bytes son la raíz y los 16 restantes quedan a cero.
#[must_use]
pub fn a_segment_commitment(raiz: [u8; 32]) -> SegmentCommitment {
    let mut bytes = [0u8; 48];
    if let Some(destino) = bytes.get_mut(..32) {
        destino.copy_from_slice(&raiz);
    }
    SegmentCommitment::from(bytes)
}

/// Extrae la raíz Merkle de segmento (32 B) de un `SegmentCommitment` de 48 B.
///
/// Es la operación inversa de [`a_segment_commitment`]; los 16 bytes finales se ignoran.
#[must_use]
pub fn raiz_de_segment_commitment(compromiso: &SegmentCommitment) -> [u8; 32] {
    let mut raiz = [0u8; 32];
    let bytes: &[u8] = compromiso.as_ref();
    if let Some(origen) = bytes.get(..32) {
        raiz.copy_from_slice(origen);
    }
    raiz
}

/// Calcula las 2⁸ raíces Merkle de registro y la raíz Merkle de segmento del segmento archivado.
///
/// Cada registro crudo `i` ocupa las piezas `2i` (origen) y `2i+1` (paridad); su extensión
/// intercalada `[origen_0, paridad_0, …]` es el registro de `2¹⁶` s-buckets sobre el que se
/// construye el árbol. Origen y paridad comparten extensión, así que comparten raíz.
///
/// # Errores
/// [`ErrorHistoriaGenesis::SegmentoInesperado`] si el segmento no tiene `2⁸` piezas o un registro
/// no mide `2¹⁵` chunks, y [`ErrorHistoriaGenesis::Merkle`] si la primitiva rechaza longitudes.
fn raices_merkle_de(
    historial: &NewArchivedSegment,
) -> Result<(Vec<[u8; 32]>, [u8; 32]), ErrorHistoriaGenesis> {
    let piezas: Vec<_> = historial.pieces.pieces().collect();
    if piezas.len() != REGISTROS_POR_SEGMENTO {
        return Err(ErrorHistoriaGenesis::SegmentoInesperado {
            detalle: "el segmento archivado no tiene 2⁸ piezas",
        });
    }
    let chunks_origen = S_BUCKETS_POR_REGISTRO.div_euclid(2);
    let mut raices = Vec::with_capacity(REGISTROS_POR_SEGMENTO);
    for par in piezas.chunks_exact(2) {
        let (origen, paridad) = match par {
            [origen, paridad] => (origen.record(), paridad.record()),
            _ => {
                return Err(ErrorHistoriaGenesis::SegmentoInesperado {
                    detalle: "par origen/paridad incompleto",
                });
            }
        };
        if origen.as_ref().len() != chunks_origen * TAMANO_HOJA
            || paridad.as_ref().len() != chunks_origen * TAMANO_HOJA
        {
            return Err(ErrorHistoriaGenesis::SegmentoInesperado {
                detalle: "un registro no mide 2¹⁵ chunks de 32 B",
            });
        }
        let mut chunks = vec![[0u8; TAMANO_HOJA]; S_BUCKETS_POR_REGISTRO];
        for ((destino, a), b) in chunks
            .chunks_exact_mut(2)
            .zip(origen.iter())
            .zip(paridad.iter())
        {
            if let [x, y] = destino {
                *x = *a;
                *y = *b;
            }
        }
        let raiz = construir_registro(&chunks)?.0;
        raices.push(raiz);
        raices.push(raiz);
    }
    let compromiso = construir_segmento(&raices)?.0;
    Ok((raices, compromiso))
}

/// Coteja un compromiso observado contra el congelado de la historia génesis dev.
///
/// Se aísla para poder probar el rechazo con una raíz mutada sin volver a archivar. No deriva el
/// esperado del observado ni acepta el valor nuevo: ante divergencia devuelve
/// [`ErrorHistoriaGenesis::CompromisoInesperado`] con ambos valores.
///
/// # Errores
/// [`ErrorHistoriaGenesis::CompromisoInesperado`] si `observado` no es el congelado.
pub fn comprobar_compromiso(observado: [u8; 32]) -> Result<(), ErrorHistoriaGenesis> {
    let esperado = COMPROMISO_HISTORIA_GENESIS_DEV;
    if observado == esperado {
        Ok(())
    } else {
        Err(ErrorHistoriaGenesis::CompromisoInesperado {
            esperado,
            observado,
        })
    }
}
