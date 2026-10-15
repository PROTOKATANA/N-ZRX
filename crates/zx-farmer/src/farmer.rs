//! Parcela persistente y auditoría por slot (pieza D1).
//!
//! Este módulo es la única frontera de `zx-farmer` con el plotter/auditor del farmer auditado. Enlaza
//! por `path` la API pública del clon fijado (`terceros/autonomys` @ `f8842d0`) y **no** copia
//! ni reimplementa PoS, KZG ni erasure coding:
//!
//! - [`plotear_sector_en_disco`] usa `plot_sector` con `CpuRecordsEncoder::<ChiaTable>` y la ruta
//!   **paralela** de generación de tablas (`generate_parallel`). No se invoca la ruta no paralela
//!   de `ab-proof-of-space`, que tiene un SIGSEGV reproducible documentado en
//!   `P-ZRX/P-INTENTO/investigacion/mediciones/fallo-semilla.md`.
//! - [`ParcelaDisco::auditar_candidatos`] deriva el reto de `C-POT-03` con `reto_desde_salida` y
//!   llama a `audit_plot_sync` (`C-POT-08`, paso 5); [`ParcelaDisco::auditar_slot`] lo resume sin
//!   repetir la auditoría. El resultado son **candidatos**, nunca soluciones válidas: la conversión
//!   candidato→solución probada con A1 corresponde a D2.
//!
//! La parcela se guarda como un par de archivos (`<ruta>` y `<ruta>.meta`). El archivo de sector
//! coloca los bytes en el offset natural `sector_index * sector_size(pieces_in_sector)`, de modo
//! que `audit_plot_sync` pueda leerlo con un `&File` sin realinear offsets; el hueco previo es un
//! agujero disperso. La metadata lleva versión, clave pública, índice, longitud, huella BLAKE3 del
//! sector y el `PlottedSector` codificado con `parity-scale-codec`, más un checksum BLAKE3 del
//! propio cuerpo. Abrir comprueba ambos checksums, la longitud y la coherencia de clave, índice,
//! índices de pieza e historia; un par incompleto falla con error explícito y nunca ofrece
//! auditoría.
//!
//! # Descriptor verificado, no ruta
//!
//! `abrir` conserva el descriptor de sector sobre el que midió la longitud y calculó la huella, y
//! la auditoría lee de él: un `rename` de la ruta no redirige la lectura a otro inode. La ruta
//! queda solo para diagnóstico. Esto **no** protege contra una escritura en sitio sobre el inode
//! verificado (misma ruta, mismo descriptor, contenido cambiado después de `abrir`): el directorio
//! de parcelas se asume **exclusivo** y el archivo, inmutable durante la auditoría.
//!
//! # Cota de la metadata
//!
//! La metadata se mide y se lee desde el mismo descriptor y se rechaza con
//! [`ErrorFarmer::MetadataSobredimensionada`] si supera [`LIMITE_METADATA_BYTES`], una cota
//! **local de recursos** (2 MiB) justificada por el tamaño máximo de `u16::MAX` índices
//! `PieceIndex` de 8 B más la metadata fija. No es un parámetro de consenso.
//!
//! # Exclusión de escritores y ausencia de atomicidad de par
//!
//! Antes de plotear se crea `<ruta>.lock` con `create_new`: dos escritores del mismo destino no
//! pueden solaparse y el segundo falla con [`ErrorFarmer::ParcelaEnUso`]. El guard se retiene
//! durante el ploteo, la escritura de los temporales, los dos `rename` y el `sync_all` del
//! directorio; al soltarse elimina **solo** el lock propio. Si el proceso muere, el lock queda
//! huérfano y las llamadas posteriores fallan cerrado: la recuperación es **manual** (borrar el
//! lock una vez comprobado que no hay ningún escritor vivo), nunca automática.
//!
//! Publicar el par son **dos** `rename` consecutivos, no una transacción: un corte entre ambos
//! puede dejar un par incompleto y [`ParcelaDisco::abrir`] lo rechaza con un error explícito
//! ([`ErrorFarmer::FaltaSector`] o [`ErrorFarmer::FaltaMetadata`]). Los temporales se crean con
//! `create_new` para no pisar restos de una operación anterior. `fs::rename` no ofrece reemplazo
//! condicional portable: por eso se comprueba cada destino justo antes de publicar y el directorio
//! de datos se asume **exclusivo** (un solo escritor a la vez, serializado por el lock). No se
//! promete atomicidad de par.
//!
//! Ningún valor de consenso se fabrica aquí: `D`, `N(s)`, el rango y la historia son entradas del
//! llamante (contexto) o del fixture de test.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use parity_scale_codec::{Decode, DecodeAll, Encode};
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash};
use subspace_core_primitives::pos::{PosProof, PosSeed};
use subspace_core_primitives::sectors::{SectorId, SectorIndex};
use subspace_core_primitives::solutions::SolutionPotVerifier;
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_farmer_components::ReadAtOffset;
use subspace_farmer_components::auditing::{AuditResult, audit_plot_sync};
use subspace_farmer_components::plotting::{
    CpuRecordsEncoder, PlotSectorOptions, PlottedSector, plot_sector,
};
use subspace_farmer_components::sector::{SectorMetadataChecksummed, sector_size};
use subspace_kzg::Kzg;
use subspace_proof_of_space::chia::ChiaTable;
use subspace_proof_of_space::{PosTableType, Table, TableGenerator};
use thiserror::Error;
use zx_poas::reto_desde_salida;

/// Versión explícita del formato de persistencia de la parcela.
pub const VERSION_PARCELA: u32 = 1;

/// Sufijo del archivo de metadata que acompaña al archivo de sector.
const SUFIJO_METADATA: &str = ".meta";

/// Sufijo del lock que serializa a los escritores de un mismo destino.
const SUFIJO_LOCK: &str = ".lock";

/// Sufijo de los temporales que se publican con `rename`.
const SUFIJO_TEMPORAL: &str = ".tmp";

/// W08e: número máximo de tablas PoSpace cacheadas por parcela.
///
/// La tabla no depende del reto, así que reutilizarla es equivalente a regenerarla; esta cota acota
/// la memoria del proceso. En el banco dev cada parcela tiene `pieces_in_sector = 2`, de modo que 8
/// entradas cubren de sobra las dos piezas del sector. No es un parámetro de consenso.
pub const MAX_TABLAS_CACHEADAS: usize = 8;

/// W08e: tabla PoSpace cacheada para un seed de evaluación.
///
/// La tabla de proof-of-space depende solo de `(sector_id, piece_offset)`
/// (`SectorId::derive_evaluation_seed`) y **no** del reto del slot: reutilizarla devuelve las
/// mismas pruebas que regenerarla. Se envuelve en `Arc` para que el caché pueda prestarla sin
/// clonar la tabla.
pub struct TablaCacheada(Arc<ChiaTable>);

// `Debug` manual: derivarlo forzaría `ChiaTable: Debug` y el solver de rasgos desborda con
// `generic_const_exprs` (`Tables<20>: Debug`) al compilar los tests del crate.
impl std::fmt::Debug for TablaCacheada {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TablaCacheada")
    }
}

impl SolutionPotVerifier for TablaCacheada {
    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        <ChiaTable as Table>::is_proof_valid(seed, challenge_index, proof)
    }
}

impl Table for TablaCacheada {
    const TABLE_TYPE: PosTableType = PosTableType::Chia;
    type Generator = GeneradorTablaCacheada;

    fn find_proof(&self, challenge_index: u32) -> Option<PosProof> {
        self.0.find_proof(challenge_index)
    }

    fn is_proof_valid(seed: &PosSeed, challenge_index: u32, proof: &PosProof) -> bool {
        <ChiaTable as Table>::is_proof_valid(seed, challenge_index, proof)
    }
}

/// W08e: generador trivial de [`TablaCacheada`]. Solo satisface el tipo asociado `Table::Generator`;
/// la ruta real del productor usa el caché de [`ParcelaDisco::tabla_pos_cacheada`].
#[derive(Debug, Default, Clone)]
pub struct GeneradorTablaCacheada;

impl TableGenerator<TablaCacheada> for GeneradorTablaCacheada {
    fn generate(&self, seed: &PosSeed) -> TablaCacheada {
        // W08e: se usa la ruta **paralela** (la única que el proyecto considera segura; ver la nota
        // de `ab-proof-of-space` en el docstring del módulo). Este generador no se usa en la ruta
        // real, que pasa por el caché de `ParcelaDisco::tabla_pos_cacheada`.
        TablaCacheada(Arc::new(ChiaTable::generator().generate_parallel(seed)))
    }
}

/// Tamaño del fragmento de lectura de la huella, en bytes.
///
/// Es una decisión de implementación para acotar la memoria viva, **no** un parámetro de consenso:
/// cualquier tamaño produce la misma huella BLAKE3 del flujo completo.
const TAMANO_FRAGMENTO_HUELLA: usize = 64 * 1024;

/// Límite **local de recursos** del archivo de metadata, en bytes.
///
/// - **Definición:** cota superior de `len(<ruta>.meta)`, es decir, del par
///   `Encode(CuerpoParcela) ‖ BLAKE3(Encode(CuerpoParcela))`; no es un campo ni un parámetro de
///   consenso.
/// - **Unidad:** bytes.
/// - **Estado:** elegido (decisión de implementación de D1).
/// - **Justificación:** el cuerpo no puede superar la metadata fija más `u16::MAX` índices
///   `PieceIndex` de 8 B. La parte fija (80 B de cabecera + `PlottedSector` con `sector_id`,
///   `sector_index`, la metadata con `s_bucket_sizes` de `2^16` entradas `u16`, `history_size` y su
///   checksum) ronda los 128 KiB, y `u16::MAX · 8 B = 512 KiB`; con el checksum BLAKE3 de 32 B el
///   máximo real queda por debajo de 1 MiB. El valor elegido, **2 MiB = 2 · 1024 · 1024 B**, da
///   margen frente a cambios de layout de esos mismos tipos y detiene una metadata sparse o
///   corrupta antes de reservar memoria, sin depender del tamaño del archivo en disco.
const LIMITE_METADATA_BYTES: u64 = 2 * 1024 * 1024;

/// Errores tipados del plotter/auditor de parcela.
#[derive(Debug, Error)]
pub enum ErrorFarmer {
    /// Error de E/S al leer o escribir los archivos de la parcela.
    #[error("E/S de parcela: {0}")]
    Eio(#[from] std::io::Error),
    /// El plotter devolvió un error. Nunca se convierte en una parcela utilizable.
    #[error("ploteo falló: {0}")]
    Plot(#[from] subspace_farmer_components::plotting::PlottingError),
    /// La auditoría devolvió un error de lectura del sector.
    #[error("auditoría falló: {0}")]
    Auditoria(#[from] subspace_farmer_components::auditing::AuditingError),
    /// La metadata no decodifica con `parity-scale-codec`.
    #[error("metadata no decodifica: {0}")]
    Decodificacion(String),
    /// Ya existe un par de parcela en la ruta. D1 no sobrescribe: hace falta una operación de
    /// reemplazo segura que esta versión no expone.
    #[error("ya existe una parcela en {ruta:?}; D1 no la sobrescribe")]
    ParcelaExistente {
        /// Ruta del archivo de sector.
        ruta: PathBuf,
    },
    /// Otro escritor retiene el lock del destino. Falla cerrado sin tocar nada.
    #[error(
        "parcela en uso: el lock {ruta:?} ya existe; si ningún proceso la está ploteando, \
         retíralo a mano (recuperación manual)"
    )]
    ParcelaEnUso {
        /// Ruta del fichero de lock.
        ruta: PathBuf,
    },
    /// Ya existe un temporal de una publicación anterior interrumpida.
    #[error("temporal preexistente {ruta:?}; revísalo antes de reintentar")]
    TemporalPreexistente {
        /// Ruta del temporal.
        ruta: PathBuf,
    },
    /// Falta el archivo de sector del par.
    #[error("falta el archivo de sector {ruta:?}")]
    FaltaSector {
        /// Ruta esperada.
        ruta: PathBuf,
    },
    /// Falta el archivo de metadata del par.
    #[error("falta la metadata {ruta:?}")]
    FaltaMetadata {
        /// Ruta esperada.
        ruta: PathBuf,
    },
    /// La metadata tiene menos bytes que un checksum.
    #[error("metadata truncada")]
    MetadataTruncada,
    /// El checksum BLAKE3 del cuerpo de metadata no coincide.
    #[error("metadata corrupta: el checksum no coincide")]
    MetadataCorrupta,
    /// El archivo de metadata supera el límite local de recursos.
    #[error("metadata sobredimensionada: {encontrado} B supera el límite local de {limite} B")]
    MetadataSobredimensionada {
        /// Límite aplicado, en bytes.
        limite: u64,
        /// Longitud observada del descriptor, en bytes.
        encontrado: u64,
    },
    /// La versión de formato no es la soportada.
    #[error("versión de parcela desconocida: {encontrada}")]
    VersionDesconocida {
        /// Versión leída.
        encontrada: u32,
    },
    /// La clave pública del par no es la esperada.
    #[error("clave pública discordante")]
    ClaveDiscordante,
    /// El índice de sector de la cabecera no coincide con el de la metadata.
    #[error("índice de sector discordante")]
    IndiceDiscordante,
    /// El número de piezas de la cabecera no coincide con el de la metadata.
    #[error("número de piezas discordante")]
    PiezasDiscordantes,
    /// El índice de sector de `PlottedSector` no coincide con el de la cabecera.
    #[error("índice de sector de PlottedSector discordante")]
    IndicePlottedDiscordante,
    /// El número de índices de pieza no coincide con `pieces_in_sector`.
    #[error(
        "número de índices de pieza discordante: esperados {esperado}, encontrados {encontrado}"
    )]
    IndicesPiezasDiscordantes {
        /// Número de índices esperado (`pieces_in_sector`).
        esperado: usize,
        /// Número de índices encontrado en `piece_indexes`.
        encontrado: usize,
    },
    /// La longitud declarada o la del archivo no es la esperada.
    #[error("longitud de sector discordante: esperada {esperado}, encontrada {encontrado}")]
    LongitudDiscordante {
        /// Longitud esperada en bytes.
        esperado: u64,
        /// Longitud encontrada en bytes.
        encontrado: u64,
    },
    /// La huella BLAKE3 de los bytes de sector no coincide (truncado o corrupción en reposo).
    #[error("huella del sector no coincide")]
    SectorCorrupto,
    /// El `sector_id` no corresponde a (clave pública, índice, historia).
    #[error("sector_id no corresponde a (clave pública, índice, historia)")]
    SectorIdDiscordante,
    /// Un tamaño u offset de sector no es representable.
    #[error("tamaño u offset de sector no representable")]
    AritmeticaNoRepresentable,
}

/// Resumen de los candidatos encontrados en una auditoría por slot.
///
/// Un candidato **no** es una solución válida: todavía debe pasar la prueba PoAS de A1 y la
/// conversión de D2. `num_candidatos == 0` significa «sin candidato», no error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumenCandidatos {
    /// Índice del sector auditado.
    pub sector_index: SectorIndex,
    /// Número de candidatos del sector para ese reto de slot.
    pub num_candidatos: usize,
}

/// Cuerpo serializable de la metadata de parcela.
///
/// El archivo de metadata contiene `Encode(cuerpo) ‖ BLAKE3(Encode(cuerpo))`.
#[derive(Debug, Encode, Decode)]
struct CuerpoParcela {
    version: u32,
    public_key: PublicKey,
    sector_index: SectorIndex,
    pieces_in_sector: u16,
    longitud_sector: u64,
    huella_sector: Blake3Hash,
    plotted_sector: PlottedSector,
}

/// Parcela de un solo sector persistida en disco.
///
/// Se abre con [`ParcelaDisco::abrir`], que verifica los dos checksums y la coherencia del par, y
/// se audita por slot con [`ParcelaDisco::auditar_slot`]. El descriptor del archivo de sector
/// verificado en `abrir` se conserva y es el que usa la auditoría; `ruta` queda solo para
/// diagnóstico.
#[derive(Debug)]
pub struct ParcelaDisco {
    ruta: PathBuf,
    public_key: PublicKey,
    /// Descriptor abierto en `abrir` y verificado sobre él (longitud y huella). La auditoría lee
    /// de aquí y **no** vuelve a resolver `ruta`, de modo que un `rename` de la ruta no redirige
    /// la lectura a otro inode.
    archivo: File,
    cuerpo: CuerpoParcela,
    /// W08e: caché de tablas PoSpace por seed de evaluación, acotada a [`MAX_TABLAS_CACHEADAS`]. La
    /// tabla es función de `(sector_id, piece_offset)` y no del reto; reutilizarla solo ahorra CPU.
    cache_tablas: CacheTablas,
}

/// W08e: caché de tablas PoSpace con `Debug` manual.
///
/// El `Debug` manual evita forzar `ChiaTable: Debug`: el solver de rasgos desborda con
/// `generic_const_exprs` (`Tables<20>: Debug`) al compilar los tests del crate, y el contenido de
/// la caché no aporta nada al diagnóstico.
struct CacheTablas(Mutex<HashMap<[u8; 32], Arc<ChiaTable>>>);

impl std::fmt::Debug for CacheTablas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entradas = match self.0.lock() {
            Ok(guardia) => guardia.len(),
            Err(envenenado) => envenenado.into_inner().len(),
        };
        f.debug_struct("CacheTablas")
            .field("entradas", &entradas)
            .finish()
    }
}

impl ParcelaDisco {
    /// Abre y verifica la parcela de `ruta` para `public_key_esperada`.
    ///
    /// Falla con error explícito si falta cualquiera de los dos archivos, si la metadata está
    /// truncada, corrupta o supera el límite local [`LIMITE_METADATA_BYTES`], si la versión es
    /// desconocida, si la clave, el índice, las piezas, los índices de pieza o la longitud no
    /// cuadran, o si la huella del sector no coincide. No ofrece auditoría sobre un par incompleto.
    ///
    /// La metadata se mide y se lee desde el **mismo descriptor**: la cota se comprueba antes de
    /// reservar memoria y no se vuelve a resolver la ruta entre la medida y la lectura. El
    /// descriptor de sector que resulta se conserva en la parcela y lo usa la auditoría.
    ///
    /// # Límites
    ///
    /// Esto **no** protege contra una escritura en sitio sobre el inode ya verificado (misma ruta,
    /// mismo descriptor, contenido cambiado tras `abrir`): el directorio de parcelas se asume
    /// **exclusivo** y el archivo, inmutable durante la auditoría. Solo se protege frente a la
    /// sustitución de la **ruta** por otro inode.
    pub fn abrir(ruta: &Path, public_key_esperada: &PublicKey) -> Result<Self, ErrorFarmer> {
        let ruta_metadata = ruta_metadata(ruta);

        if !ruta.exists() {
            return Err(ErrorFarmer::FaltaSector {
                ruta: ruta.to_path_buf(),
            });
        }
        if !ruta_metadata.exists() {
            return Err(ErrorFarmer::FaltaMetadata {
                ruta: ruta_metadata,
            });
        }

        // Mismo descriptor para medir y leer: la cota se aplica antes de reservar y `take` impide
        // que una carrera que agrande el archivo tras la medida provoque una lectura sin cota.
        let archivo_metadata = File::open(&ruta_metadata).map_err(ErrorFarmer::Eio)?;
        let longitud_metadata = archivo_metadata.metadata().map_err(ErrorFarmer::Eio)?.len();
        if longitud_metadata > LIMITE_METADATA_BYTES {
            return Err(ErrorFarmer::MetadataSobredimensionada {
                limite: LIMITE_METADATA_BYTES,
                encontrado: longitud_metadata,
            });
        }
        let capacidad = usize::try_from(longitud_metadata)
            .map_err(|_| ErrorFarmer::AritmeticaNoRepresentable)?;
        let mut bytes_metadata = Vec::with_capacity(capacidad);
        archivo_metadata
            .take(LIMITE_METADATA_BYTES)
            .read_to_end(&mut bytes_metadata)
            .map_err(ErrorFarmer::Eio)?;
        let cuerpo = decodificar_cuerpo(&bytes_metadata)?;

        if cuerpo.version != VERSION_PARCELA {
            return Err(ErrorFarmer::VersionDesconocida {
                encontrada: cuerpo.version,
            });
        }
        if cuerpo.public_key != *public_key_esperada {
            return Err(ErrorFarmer::ClaveDiscordante);
        }

        let metadata = &cuerpo.plotted_sector.sector_metadata;
        if cuerpo.sector_index != metadata.sector_index {
            return Err(ErrorFarmer::IndiceDiscordante);
        }
        if cuerpo.sector_index != cuerpo.plotted_sector.sector_index {
            return Err(ErrorFarmer::IndicePlottedDiscordante);
        }
        if cuerpo.pieces_in_sector != metadata.pieces_in_sector {
            return Err(ErrorFarmer::PiezasDiscordantes);
        }
        let indices = cuerpo.plotted_sector.piece_indexes.len();
        if indices != usize::from(cuerpo.pieces_in_sector) {
            return Err(ErrorFarmer::IndicesPiezasDiscordantes {
                esperado: usize::from(cuerpo.pieces_in_sector),
                encontrado: indices,
            });
        }

        let longitud_esperada = longitud_de_sector(cuerpo.pieces_in_sector)?;
        if cuerpo.longitud_sector != longitud_esperada {
            return Err(ErrorFarmer::LongitudDiscordante {
                esperado: longitud_esperada,
                encontrado: cuerpo.longitud_sector,
            });
        }

        let base = base_de_sector(cuerpo.sector_index, cuerpo.longitud_sector)?;
        let mut archivo = File::open(ruta).map_err(ErrorFarmer::Eio)?;
        let longitud_archivo = archivo.metadata().map_err(ErrorFarmer::Eio)?.len();
        let longitud_total = base
            .checked_add(cuerpo.longitud_sector)
            .ok_or(ErrorFarmer::AritmeticaNoRepresentable)?;
        if longitud_archivo != longitud_total {
            return Err(ErrorFarmer::LongitudDiscordante {
                esperado: longitud_total,
                encontrado: longitud_archivo,
            });
        }

        let huella = huella_de_region(&mut archivo, base, cuerpo.longitud_sector)?;
        if huella != cuerpo.huella_sector {
            return Err(ErrorFarmer::SectorCorrupto);
        }

        let sector_id_esperado = SectorId::new(
            public_key_esperada.hash(),
            cuerpo.sector_index,
            metadata.history_size,
        );
        if cuerpo.plotted_sector.sector_id != sector_id_esperado {
            return Err(ErrorFarmer::SectorIdDiscordante);
        }

        Ok(Self {
            ruta: ruta.to_path_buf(),
            public_key: *public_key_esperada,
            archivo,
            cuerpo,
            cache_tablas: CacheTablas(Mutex::new(HashMap::new())),
        })
    }

    /// W08e: tabla PoSpace del `seed`, generándola y cacheándola si no estaba.
    ///
    /// La tabla es función de `(sector_id, piece_offset)` y no del reto; el valor devuelto es
    /// idéntico al de `ChiaTable::generator().generate_parallel(seed)`. La caché está acotada a
    /// [`MAX_TABLAS_CACHEADAS`]; al superarla se descarta una entrada cualquiera (no hay política de
    /// reemplazo garantizada, solo cota de memoria).
    pub fn tabla_pos_cacheada(&self, seed: &PosSeed) -> TablaCacheada {
        let clave: [u8; 32] = (*seed).into();
        // Un `Mutex` envenenado por un pánico previo no debe tumbar la producción: se recupera el
        // contenido interior (la caché es solo un acelerador; su contenido no es crítico).
        let mut cache = match self.cache_tablas.0.lock() {
            Ok(guardia) => guardia,
            Err(envenenado) => envenenado.into_inner(),
        };
        if let Some(tabla) = cache.get(&clave) {
            return TablaCacheada(Arc::clone(tabla));
        }
        let tabla = Arc::new(ChiaTable::generator().generate_parallel(seed));
        if cache.len() >= MAX_TABLAS_CACHEADAS
            && let Some(victima) = cache.keys().next().copied()
        {
            cache.remove(&victima);
        }
        cache.insert(clave, Arc::clone(&tabla));
        TablaCacheada(tabla)
    }

    /// Índice del sector persistido.
    #[must_use]
    pub fn sector_index(&self) -> SectorIndex {
        self.cuerpo.sector_index
    }

    /// Número de piezas del sector persistido.
    #[must_use]
    pub fn pieces_in_sector(&self) -> u16 {
        self.cuerpo.pieces_in_sector
    }

    /// Ruta del archivo de sector, **solo para diagnóstico**.
    ///
    /// La auditoría no la usa: lee del descriptor verificado en [`ParcelaDisco::abrir`].
    #[must_use]
    pub fn ruta(&self) -> &Path {
        &self.ruta
    }

    /// Metadata verificada del sector (`sector_id`, checksums, `s_bucket_sizes`, historia).
    #[must_use]
    pub fn metadata(&self) -> &SectorMetadataChecksummed {
        &self.cuerpo.plotted_sector.sector_metadata
    }

    /// Audita el sector y devuelve los candidatos completos, sin resumir.
    ///
    /// `salida_pot_verificada` es la salida de 16 B del **slot auditado** (`C-POT-03`) y
    /// `rango_validado` el rango de solución; ambos vienen del contexto de productor validado,
    /// nunca de una cabecera candidata. El reto de 32 B se deriva **una sola vez** con
    /// `reto_desde_salida` y la auditoría lee el sector con `audit_plot_sync` sobre el descriptor
    /// verificado en `abrir`. Como la parcela es inmutable durante la auditoría, el conjunto de
    /// sectores en modificación va vacío.
    ///
    /// Un vector vacío significa «sin candidato», no error. Un candidato **no** es una solución
    /// válida: D2 debe convertirlos con `SolutionCandidates::into_solutions` y verificar la prueba
    /// PoAS con A1 antes de autorizar nada. Esta función no autoriza bloques.
    pub fn auditar_candidatos(
        &self,
        salida_pot_verificada: [u8; 16],
        slot: u64,
        rango_validado: u64,
    ) -> Result<Vec<AuditResult<'_, ReadAtOffset<'_, File>>>, ErrorFarmer> {
        let reto = reto_desde_salida(salida_pot_verificada, slot);
        self.auditar_con_reto(reto, rango_validado)
    }

    /// Audita el sector con un **reto de 32 B explícito**, sin derivarlo.
    ///
    /// Es la primitiva de [`Self::auditar_candidatos`]: el reto es exactamente el valor que consume
    /// `audit_plot_sync`. En W05b1 los tests pueden fijarlo directamente (la derivación desde el
    /// PoT es de W05b2); el llamante es responsable de que, cuando además vaya a verificar con
    /// `verificar_solucion_poas`, el reto corresponda a la salida de 16 B y al slot que le pase.
    ///
    /// Un vector vacío significa «sin candidato», no error. Un candidato **no** es una solución
    /// válida: hay que convertirla y verificar la prueba PoAS antes de autorizar nada.
    pub fn auditar_con_reto(
        &self,
        reto: [u8; 32],
        rango_validado: u64,
    ) -> Result<Vec<AuditResult<'_, ReadAtOffset<'_, File>>>, ErrorFarmer> {
        let challenge = Blake3Hash::from(reto);

        let sectores = std::slice::from_ref(&self.cuerpo.plotted_sector.sector_metadata);
        let en_modificacion: HashSet<SectorIndex> = HashSet::new();

        audit_plot_sync(
            &self.public_key,
            &challenge,
            rango_validado,
            &self.archivo,
            sectores,
            &en_modificacion,
        )
        .map_err(ErrorFarmer::Auditoria)
    }

    /// Audita el sector para el reto del slot y devuelve solo el resumen por sector.
    ///
    /// Es un envoltorio de [`Self::auditar_candidatos`]: deriva el reto y ejecuta la auditoría una
    /// sola vez, y resume el número de candidatos de cada sector. Un vector vacío o
    /// `num_candidatos == 0` significa «sin candidato», no error. Los candidatos **no** son
    /// soluciones válidas.
    pub fn auditar_slot(
        &self,
        salida_pot_verificada: [u8; 16],
        slot: u64,
        rango_validado: u64,
    ) -> Result<Vec<ResumenCandidatos>, ErrorFarmer> {
        let resultados = self.auditar_candidatos(salida_pot_verificada, slot, rango_validado)?;

        Ok(resultados
            .iter()
            .map(|resultado| ResumenCandidatos {
                sector_index: resultado.sector_index,
                num_candidatos: resultado.solution_candidates.len(),
            })
            .collect())
    }
}

/// Plotea un sector con `ChiaTable` y lo persiste como par de archivos en `ruta`.
///
/// La ruta de generación de tablas es la **paralela** (`generate_parallel`). El
/// `FarmerProtocolInfo` es una entrada explícita: no se fabrica ningún valor de producción dentro
/// de la función.
///
/// El destino se serializa con un lock `<ruta>.lock`. Si ya existe una parcela (sector o metadata)
/// falla con [`ErrorFarmer::ParcelaExistente`]; si otro escritor retiene el lock, con
/// [`ErrorFarmer::ParcelaEnUso`] **sin tocar** los archivos ajenos. D1 no expone reemplazo.
///
/// La función es síncrona y ejecuta el `plot_sector` asíncrono con `futures::executor::block_on`,
/// de modo que debe llamarse fuera de un executor de red.
///
/// # Errores
///
/// Propaga el [`ErrorFarmer::Plot`] del plotter; un fallo **nunca** deja una parcela utilizable.
// Se permite el número de argumentos: D1 exige las entradas explícitas (ruta, clave, índice,
// piezas, getter, protocolo y erasure coding); agruparlas en una estructura ocultaría que el
// protocolo y las instancias vienen de fuera. El KZG que `plot_sector` heredado exige por firma se
// obtiene de [`kzg_de_ploteo`]: es residual del formato de parcela del clon fijado y no entra en la
// verificación (B-21, PT-2a-2).
#[allow(clippy::too_many_arguments)]
pub fn plotear_sector_en_disco<PG>(
    ruta: &Path,
    public_key: &PublicKey,
    sector_index: SectorIndex,
    pieces_in_sector: u16,
    piece_getter: &PG,
    farmer_protocol_info: FarmerProtocolInfo,
    erasure_coding: &ErasureCoding,
) -> Result<(), ErrorFarmer>
where
    PG: PieceGetter + Send + Sync,
{
    escribir_parcela(
        ruta,
        public_key,
        sector_index,
        pieces_in_sector,
        piece_getter,
        farmer_protocol_info,
        erasure_coding,
    )
}

/// Parámetros KZG heredados que `plot_sector` exige por firma.
///
/// **KZG residual:** el formato de parcela y el ploteo viven en el clon fijado
/// `terceros/autonomys` y no son propiedad de PT-2a-2. El productor **no** usa KZG para el
/// testigo (usa `zx-merkle`); aquí solo se satisface la firma. En dev el `PieceGetter` es el propio
/// segmento archivado, así que la ruta de reconstrucción de piezas (la única que usa KZG) no se
/// ejerce. Se carga una sola vez por proceso.
#[must_use]
pub fn kzg_de_ploteo() -> &'static Kzg {
    static KZG: OnceLock<Kzg> = OnceLock::new();
    KZG.get_or_init(Kzg::new)
}

/// Guard de exclusión mutua de un destino de parcela.
///
/// Retiene el fichero `<ruta>.lock` (creado con `create_new`) y, al soltarse, elimina **solo** el
/// lock propio. Si el proceso muere antes, el lock queda huérfano y las llamadas posteriores
/// fallan cerrado con [`ErrorFarmer::ParcelaEnUso`]; la recuperación es manual.
struct GuardiaLock {
    ruta: PathBuf,
    _archivo: File,
}

impl Drop for GuardiaLock {
    fn drop(&mut self) {
        // `create_new` prueba que este fichero lo creó esta llamada; no se toca el de nadie más.
        let _ = fs::remove_file(&self.ruta);
    }
}

fn adquirir_lock(ruta: &Path) -> Result<GuardiaLock, ErrorFarmer> {
    let ruta_lock = ruta_con_sufijo(ruta, SUFIJO_LOCK);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ruta_lock)
    {
        Ok(archivo) => Ok(GuardiaLock {
            ruta: ruta_lock,
            _archivo: archivo,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(ErrorFarmer::ParcelaEnUso { ruta: ruta_lock })
        }
        Err(error) => Err(ErrorFarmer::Eio(error)),
    }
}

#[allow(clippy::too_many_arguments)]
fn escribir_parcela<PG>(
    ruta: &Path,
    public_key: &PublicKey,
    sector_index: SectorIndex,
    pieces_in_sector: u16,
    piece_getter: &PG,
    farmer_protocol_info: FarmerProtocolInfo,
    erasure_coding: &ErasureCoding,
) -> Result<(), ErrorFarmer>
where
    PG: PieceGetter + Send + Sync,
{
    let ruta_metadata = ruta_metadata(ruta);
    if ruta.exists() || ruta_metadata.exists() {
        return Err(ErrorFarmer::ParcelaExistente {
            ruta: ruta.to_path_buf(),
        });
    }

    // El lock serializa a los escritores del mismo destino y se retiene hasta después del
    // `sync_all` del directorio. Volver a comprobar los destinos tras adquirirlo cierra la
    // ventana con otro escritor que hubiera publicado justo antes.
    let _guardia = adquirir_lock(ruta)?;
    if ruta.exists() || ruta_metadata.exists() {
        return Err(ErrorFarmer::ParcelaExistente {
            ruta: ruta.to_path_buf(),
        });
    }

    let mut generador = ChiaTable::generator();
    let mut salida: Vec<u8> = Vec::new();
    let abortar = AtomicBool::new(false);
    let mutex_global = async_lock::Mutex::new(());
    let mut encoder = CpuRecordsEncoder::<ChiaTable>::new(
        std::slice::from_mut(&mut generador),
        erasure_coding,
        &mutex_global,
    );

    let trazado = futures::executor::block_on(plot_sector(PlotSectorOptions {
        public_key,
        sector_index,
        piece_getter,
        farmer_protocol_info,
        kzg: kzg_de_ploteo(),
        erasure_coding,
        pieces_in_sector,
        sector_output: &mut salida,
        downloading_semaphore: None,
        encoding_semaphore: None,
        records_encoder: &mut encoder,
        abort_early: &abortar,
    }))?;

    if trazado.sector_index != sector_index {
        return Err(ErrorFarmer::IndiceDiscordante);
    }
    if trazado.sector_metadata.pieces_in_sector != pieces_in_sector {
        return Err(ErrorFarmer::PiezasDiscordantes);
    }
    if trazado.sector_metadata.history_size != farmer_protocol_info.history_size {
        return Err(ErrorFarmer::PiezasDiscordantes);
    }

    let sector_id_esperado = SectorId::new(
        public_key.hash(),
        sector_index,
        farmer_protocol_info.history_size,
    );
    if trazado.sector_id != sector_id_esperado {
        return Err(ErrorFarmer::SectorIdDiscordante);
    }

    let longitud_sector = longitud_de_sector(pieces_in_sector)?;
    let longitud_escrita =
        u64::try_from(salida.len()).map_err(|_| ErrorFarmer::AritmeticaNoRepresentable)?;
    if longitud_escrita != longitud_sector {
        return Err(ErrorFarmer::LongitudDiscordante {
            esperado: longitud_sector,
            encontrado: longitud_escrita,
        });
    }

    let base = base_de_sector(sector_index, longitud_sector)?;
    let huella_sector = blake3_hash(&salida);

    let cuerpo = CuerpoParcela {
        version: VERSION_PARCELA,
        public_key: *public_key,
        sector_index,
        pieces_in_sector,
        longitud_sector,
        huella_sector,
        plotted_sector: trazado,
    };
    let bytes_cuerpo = cuerpo.encode();
    let huella_metadata = blake3_hash(&bytes_cuerpo);
    let mut bytes_metadata = bytes_cuerpo;
    bytes_metadata.extend_from_slice(&*huella_metadata);

    publicar_par(ruta, &salida, base, &bytes_metadata)
}

fn publicar_par(
    ruta: &Path,
    bytes_sector: &[u8],
    base: u64,
    bytes_metadata: &[u8],
) -> Result<(), ErrorFarmer> {
    let ruta_metadata = ruta_metadata(ruta);
    let tmp_sector = ruta_con_sufijo(ruta, SUFIJO_TEMPORAL);
    let tmp_metadata = ruta_con_sufijo(&ruta_metadata, SUFIJO_TEMPORAL);

    // `create_new`: un temporal preexistente es un resto de una operación interrumpida y detiene
    // la publicación sin borrarlo. Un lock huérfano ya habría detenido la llamada antes de aquí.
    escribir_sector_temporal(&tmp_sector, bytes_sector, base)?;
    if let Err(error) = escribir_archivo_temporal(&tmp_metadata, bytes_metadata) {
        let _ = fs::remove_file(&tmp_sector);
        return Err(error);
    }

    // Precondición de directorio de datos exclusivo: nadie más escribe en `ruta` mientras se
    // retiene el lock. Se comprueba cada destino antes de publicar porque `fs::rename` no ofrece
    // reemplazo condicional portable y pisaría un destino creado por fuera.
    if ruta.exists() || ruta_metadata.exists() {
        let _ = fs::remove_file(&tmp_sector);
        let _ = fs::remove_file(&tmp_metadata);
        return Err(ErrorFarmer::ParcelaExistente {
            ruta: ruta.to_path_buf(),
        });
    }

    // Dos renombrados, no una transacción: un corte entre ambos deja un par incompleto que
    // [`ParcelaDisco::abrir`] rechaza explícitamente.
    if let Err(error) = fs::rename(&tmp_sector, ruta) {
        let _ = fs::remove_file(&tmp_sector);
        let _ = fs::remove_file(&tmp_metadata);
        return Err(ErrorFarmer::Eio(error));
    }
    if let Err(error) = fs::rename(&tmp_metadata, &ruta_metadata) {
        // El sector ya publicado es nuestro; se retira para no dejar un par a medias.
        let _ = fs::remove_file(ruta);
        let _ = fs::remove_file(&tmp_metadata);
        return Err(ErrorFarmer::Eio(error));
    }

    sincronizar_directorio(ruta)?;
    Ok(())
}

fn decodificar_cuerpo(bytes: &[u8]) -> Result<CuerpoParcela, ErrorFarmer> {
    let tamano_huella = Blake3Hash::SIZE;
    if bytes.len() < tamano_huella {
        return Err(ErrorFarmer::MetadataTruncada);
    }

    let (cuerpo_bytes, huella_bytes) = bytes.split_at(bytes.len() - tamano_huella);
    let esperada: [u8; Blake3Hash::SIZE] = huella_bytes
        .try_into()
        .map_err(|_| ErrorFarmer::MetadataCorrupta)?;
    let real = blake3_hash(cuerpo_bytes);
    if *real != esperada {
        return Err(ErrorFarmer::MetadataCorrupta);
    }

    let mut restante = cuerpo_bytes;
    CuerpoParcela::decode_all(&mut restante)
        .map_err(|error| ErrorFarmer::Decodificacion(error.to_string()))
}

fn huella_de_region(
    archivo: &mut File,
    base: u64,
    longitud: u64,
) -> Result<Blake3Hash, ErrorFarmer> {
    archivo
        .seek(SeekFrom::Start(base))
        .map_err(ErrorFarmer::Eio)?;

    // Lectura en fragmentos de tamaño fijo y `Hasher` incremental: la memoria viva no depende de
    // `longitud` (que sale de `sector_size(pieces_in_sector)` y puede ser enorme con metadata
    // sparse), y un EOF prematuro se propaga vía `read_exact` como `Eio`.
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; TAMANO_FRAGMENTO_HUELLA];
    let mut restante = longitud;
    while restante > 0 {
        let tamano = usize::try_from(restante.min(TAMANO_FRAGMENTO_HUELLA as u64))
            .map_err(|_| ErrorFarmer::AritmeticaNoRepresentable)?;
        let fragmento = buffer
            .get_mut(..tamano)
            .ok_or(ErrorFarmer::AritmeticaNoRepresentable)?;
        archivo.read_exact(fragmento).map_err(ErrorFarmer::Eio)?;
        hasher.update(fragmento);
        let leidos = u64::try_from(tamano).map_err(|_| ErrorFarmer::AritmeticaNoRepresentable)?;
        restante = restante
            .checked_sub(leidos)
            .ok_or(ErrorFarmer::AritmeticaNoRepresentable)?;
    }

    Ok(Blake3Hash::from(hasher.finalize().as_bytes()))
}

/// Abre un temporal nuevo. Un fichero preexistente detiene la operación en vez de borrarse.
fn crear_temporal(ruta: &Path) -> Result<File, ErrorFarmer> {
    match OpenOptions::new().write(true).create_new(true).open(ruta) {
        Ok(archivo) => Ok(archivo),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(ErrorFarmer::TemporalPreexistente {
                ruta: ruta.to_path_buf(),
            })
        }
        Err(error) => Err(ErrorFarmer::Eio(error)),
    }
}

fn escribir_sector_temporal(ruta: &Path, bytes: &[u8], base: u64) -> Result<(), ErrorFarmer> {
    let mut archivo = crear_temporal(ruta)?;
    archivo
        .seek(SeekFrom::Start(base))
        .map_err(ErrorFarmer::Eio)?;
    archivo.write_all(bytes).map_err(ErrorFarmer::Eio)?;
    archivo.sync_all().map_err(ErrorFarmer::Eio)?;
    Ok(())
}

fn escribir_archivo_temporal(ruta: &Path, bytes: &[u8]) -> Result<(), ErrorFarmer> {
    let mut archivo = crear_temporal(ruta)?;
    archivo.write_all(bytes).map_err(ErrorFarmer::Eio)?;
    archivo.sync_all().map_err(ErrorFarmer::Eio)?;
    Ok(())
}

fn sincronizar_directorio(ruta: &Path) -> Result<(), ErrorFarmer> {
    let padre = match ruta.parent() {
        Some(padre) if !padre.as_os_str().is_empty() => padre.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let directorio = File::open(&padre).map_err(ErrorFarmer::Eio)?;
    directorio.sync_all().map_err(ErrorFarmer::Eio)?;
    Ok(())
}

fn base_de_sector(sector_index: SectorIndex, longitud_sector: u64) -> Result<u64, ErrorFarmer> {
    u64::from(sector_index)
        .checked_mul(longitud_sector)
        .ok_or(ErrorFarmer::AritmeticaNoRepresentable)
}

fn longitud_de_sector(pieces_in_sector: u16) -> Result<u64, ErrorFarmer> {
    u64::try_from(sector_size(pieces_in_sector)).map_err(|_| ErrorFarmer::AritmeticaNoRepresentable)
}

fn ruta_metadata(ruta: &Path) -> PathBuf {
    ruta_con_sufijo(ruta, SUFIJO_METADATA)
}

fn ruta_con_sufijo(ruta: &Path, sufijo: &str) -> PathBuf {
    let mut os: OsString = ruta.as_os_str().to_os_string();
    os.push(sufijo);
    PathBuf::from(os)
}
