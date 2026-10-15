//! Tests de contrato de D1: parcela persistente y auditoría por slot.
//!
//! El fixture se construye una sola vez por proceso: toma la historia archivada del génesis dev de
//! [`zx_poas::HistoriaGenesis`] (que archiva el cuerpo del génesis dev con el `Archiver` real, no un
//! `PieceGetter` de bytes arbitrarios), plotea un sector con `ChiaTable` y guarda el par de
//! archivos. Los tests reutilizan esos bytes para no repetir el ploteo ni la archivación. Los
//! valores de `FarmerProtocolInfo` son de **desarrollo** y su fuente es el test upstream
//! `subspace-farmer-components/tests/plot_read_roundtrip.rs`; no son parámetros de red.
//!
//! La auditoría se comprueba contra un oráculo independiente que lee el sector desde disco y
//! recalcula los ganadores con `blake3_hash_with_key` + `bidirectional_distance`; así un
//! `auditar_slot` que no leyera nada no pasaría, y si el fixture no produce ganadores el test
//! demuestra la ejecución por el contador, sin afirmar una solución inexistente.

#![expect(
    clippy::expect_used,
    reason = "instrumento de test: un fallo al construir o comprobar el fixture debe producir panic"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "índices deliberados sobre fixtures de tamaño conocido y truncamientos bajo prueba"
)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Barrier, OnceLock};

use parity_scale_codec::{Decode, DecodeAll, Encode};
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash, blake3_hash_with_key};
use subspace_core_primitives::sectors::{SectorId, SectorIndex};
use subspace_core_primitives::segments::{HistorySize, SegmentCommitment};
use subspace_core_primitives::solutions::bidirectional_distance;
use subspace_core_primitives::{PublicKey, ScalarBytes};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting::PlottedSector;
use subspace_farmer_components::sector::{SectorContentsMap, sector_size};
use zx_farmer::farmer::{ErrorFarmer, ParcelaDisco, plotear_sector_en_disco};
use zx_farmer::productor_poas::{
    ErrorProductorPoas, ResultadoConversionLocal, convertir_candidatos_locales,
};
use zx_poas::{ErrorPoas, HistoriaGenesis, reto_desde_salida, verificar_solucion_poas};

/// Piezas del sector de fixture (valor de desarrollo).
const PIEZAS: u16 = 2;
/// Índice de sector de fixture, distinto de cero para ejercitar el offset natural en el archivo.
const INDICE_SECTOR: SectorIndex = 2;
/// Rango elegido **de test** para que los ganadores sean frecuentes. No es un parámetro de red.
const RANGO_PRUEBA: u64 = u64::MAX;

struct Fondo {
    public_key: PublicKey,
    /// Historia archivada común dev: única fuente de historial, protocolo, KZG, erasure coding y
    /// contexto de pieza. Sustituye a los campos que este test reconstruía por su cuenta.
    historia: HistoriaGenesis,
    bytes_sector: Vec<u8>,
    bytes_metadata: Vec<u8>,
}

static FONDO: OnceLock<Fondo> = OnceLock::new();

fn fondo() -> &'static Fondo {
    FONDO.get_or_init(construir_fondo)
}

fn construir_fondo() -> Fondo {
    let public_key = PublicKey::default();
    let historia =
        HistoriaGenesis::construir().expect("la historia archivada dev debe construirse");

    let dir = DirTemporal::nuevo("fondo");
    let ruta = dir.unir("sector.plot");
    let inicio = std::time::Instant::now();
    plotear_sector_en_disco(
        &ruta,
        &public_key,
        INDICE_SECTOR,
        PIEZAS,
        historia.historial(),
        historia.protocolo(),
        historia.erasure_coding(),
    )
    .expect("el fixture de ploteo debe funcionar");
    eprintln!(
        "[medición local, no consenso] ploteo de fixture D1: {:?}; hilos visibles: {}",
        inicio.elapsed(),
        std::thread::available_parallelism().map_or(1, |n| n.get())
    );

    let bytes_sector = fs::read(&ruta).expect("leer sector ploteado");
    let bytes_metadata = fs::read(ruta_metadata(&ruta)).expect("leer metadata ploteada");
    drop(dir);

    Fondo {
        public_key,
        historia,
        bytes_sector,
        bytes_metadata,
    }
}

struct DirTemporal {
    ruta: PathBuf,
}

impl DirTemporal {
    fn nuevo(nombre: &str) -> Self {
        static CONTADOR: AtomicU64 = AtomicU64::new(0);
        let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("zx-farmer-{}-{}-{}", std::process::id(), nombre, n));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("crear directorio temporal");
        Self { ruta: base }
    }

    fn unir(&self, hijo: &str) -> PathBuf {
        self.ruta.join(hijo)
    }
}

impl Drop for DirTemporal {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.ruta);
    }
}

fn con_sufijo(ruta: &Path, sufijo: &str) -> PathBuf {
    let mut os = OsString::from(ruta.as_os_str());
    os.push(sufijo);
    PathBuf::from(os)
}

fn ruta_metadata(ruta: &Path) -> PathBuf {
    con_sufijo(ruta, ".meta")
}

fn instalar_par(dir: &DirTemporal, fondo: &Fondo) -> PathBuf {
    let ruta = dir.unir("sector.plot");
    fs::write(&ruta, &fondo.bytes_sector).expect("escribir sector");
    fs::write(ruta_metadata(&ruta), &fondo.bytes_metadata).expect("escribir metadata");
    ruta
}

/// Espejo local del `CuerpoParcela` privado de `farmer.rs`, con el mismo orden y tipos, para
/// decodificar el cuerpo de una metadata real, alterarlo y recodificarlo con un checksum válido.
#[derive(Encode, Decode)]
struct CuerpoParcelaEspejo {
    version: u32,
    public_key: PublicKey,
    sector_index: SectorIndex,
    pieces_in_sector: u16,
    longitud_sector: u64,
    huella_sector: Blake3Hash,
    plotted_sector: PlottedSector,
}

/// Decodifica la metadata válida de `ruta`, aplica `alterar`, recalcula el checksum BLAKE3 del
/// cuerpo y reescribe el `.meta`. Reutiliza el fixture; no duplica bytes de sector ni metadata.
fn reescribir_metadata_con_checksum_valido(
    ruta: &Path,
    alterar: impl FnOnce(&mut CuerpoParcelaEspejo),
) {
    let bytes = fs::read(ruta_metadata(ruta)).expect("leer metadata válida");
    let (cuerpo_bytes, _) = bytes.split_at(bytes.len() - Blake3Hash::SIZE);
    let mut restante = cuerpo_bytes;
    let mut cuerpo = CuerpoParcelaEspejo::decode_all(&mut restante).expect("decodificar cuerpo");
    alterar(&mut cuerpo);
    let nuevo_cuerpo = cuerpo.encode();
    let mut nuevo = nuevo_cuerpo.clone();
    nuevo.extend_from_slice(&*blake3_hash(&nuevo_cuerpo));
    fs::write(ruta_metadata(ruta), nuevo).expect("reescribir metadata con checksum válido");
}

fn primera_u64(hash: &Blake3Hash) -> u64 {
    let bytes: &[u8; 32] = hash;
    let mut ocho = [0u8; 8];
    ocho.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(ocho)
}

/// Oráculo independiente: lee el s-bucket auditado desde disco y recalcula los ganadores.
fn candidatos_oraculo(ruta: &Path, parcela: &ParcelaDisco, salida: [u8; 16], slot: u64) -> usize {
    let challenge = Blake3Hash::from(reto_desde_salida(salida, slot));
    let metadata = parcela.metadata();
    let sector_id = SectorId::new(
        fondo().public_key.hash(),
        parcela.sector_index(),
        metadata.history_size,
    );
    let ssc = sector_id.derive_sector_slot_challenge(&challenge);
    let indice = usize::from(ssc.s_bucket_audit_index());

    let bytes = fs::read(ruta).expect("leer sector del oráculo");
    let base = usize::from(parcela.sector_index()) * sector_size(parcela.pieces_in_sector());
    let inicio_buckets = SectorContentsMap::encoded_size(parcela.pieces_in_sector());
    let antes: usize = metadata.s_bucket_sizes[..indice]
        .iter()
        .map(|n| usize::from(*n))
        .sum();
    let tam = usize::from(metadata.s_bucket_sizes[indice]);
    let inicio = base + inicio_buckets + antes * ScalarBytes::FULL_BYTES;
    let fin = inicio + tam * ScalarBytes::FULL_BYTES;
    let bucket = &bytes[inicio..fin];

    bucket
        .chunks_exact(ScalarBytes::FULL_BYTES)
        .filter(|chunk| {
            let auditado = blake3_hash_with_key(&ssc, chunk);
            let distancia =
                bidirectional_distance(&primera_u64(&challenge), &primera_u64(&auditado));
            distancia <= RANGO_PRUEBA >> 1
        })
        .count()
}

#[test]
fn plotea_reabre_y_audita_por_slot_con_reinicio() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("audita");
    let ruta = instalar_par(&dir, fondo);

    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir parcela válida");
    assert_eq!(parcela.sector_index(), INDICE_SECTOR);
    assert_eq!(parcela.pieces_in_sector(), PIEZAS);

    let casos = [([3u8; 16], 0u64), ([4u8; 16], 1u64)];
    let mut primera = Vec::new();
    for (salida, slot) in casos {
        let resumen = parcela
            .auditar_slot(salida, slot, RANGO_PRUEBA)
            .expect("auditar slot");
        let total: usize = resumen.iter().map(|r| r.num_candidatos).sum();
        for fila in &resumen {
            assert_eq!(fila.sector_index, INDICE_SECTOR);
        }
        let esperado = candidatos_oraculo(&ruta, &parcela, salida, slot);
        assert_eq!(
            total, esperado,
            "slot {slot}: los candidatos deben coincidir con el oráculo independiente"
        );
        primera.push((salida, slot, total));
    }
    drop(parcela);

    let reabierta = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("reabrir parcela");
    for (salida, slot, total) in &primera {
        let resumen = reabierta
            .auditar_slot(*salida, *slot, RANGO_PRUEBA)
            .expect("auditar tras reinicio");
        let repetido: usize = resumen.iter().map(|r| r.num_candidatos).sum();
        assert_eq!(
            repetido, *total,
            "slot {slot}: la auditoría debe repetir el mismo resultado tras reinicio"
        );
    }

    // Barrido de slots: cada uno se contrasta con el oráculo. Si ninguno produjera ganadores, la
    // igualdad con el oráculo (que lee y recalcula) ya demuestra que la auditoría se ejecutó.
    let mut con_candidatos = 0usize;
    for slot in 0u64..64 {
        let salida = [7u8; 16];
        let resumen = reabierta
            .auditar_slot(salida, slot, RANGO_PRUEBA)
            .expect("auditar barrido");
        let total: usize = resumen.iter().map(|r| r.num_candidatos).sum();
        let esperado = candidatos_oraculo(&ruta, &reabierta, salida, slot);
        assert_eq!(total, esperado, "barrido slot {slot}");
        if total > 0 {
            con_candidatos += 1;
        }
    }
    eprintln!(
        "[medición local, no consenso] slots 0..64 con candidatos: {con_candidatos}; rango de prueba {RANGO_PRUEBA}"
    );
}

#[test]
fn abrir_rechaza_sector_y_metadata_corruptos() {
    let fondo = fondo();

    let dir = DirTemporal::nuevo("corrupto-sector");
    let ruta = instalar_par(&dir, fondo);
    voltear_ultimo_byte(&ruta);
    let error = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("sector corrupto");
    assert!(
        matches!(error, ErrorFarmer::SectorCorrupto),
        "se esperaba SectorCorrupto, fue {error:?}"
    );

    let dir = DirTemporal::nuevo("corrupto-meta");
    let ruta = instalar_par(&dir, fondo);
    voltear_ultimo_byte(&ruta_metadata(&ruta));
    let error = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("metadata corrupta");
    assert!(
        matches!(error, ErrorFarmer::MetadataCorrupta),
        "se esperaba MetadataCorrupta, fue {error:?}"
    );
}

#[test]
fn abrir_rechaza_par_incompleto_clave_erronea_y_truncado() {
    let fondo = fondo();

    let dir = DirTemporal::nuevo("sin-meta");
    let ruta = dir.unir("sector.plot");
    fs::write(&ruta, &fondo.bytes_sector).expect("escribir solo sector");
    let error = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("falta metadata");
    assert!(
        matches!(error, ErrorFarmer::FaltaMetadata { .. }),
        "se esperaba FaltaMetadata, fue {error:?}"
    );

    let dir = DirTemporal::nuevo("sin-sector");
    let ruta = dir.unir("sector.plot");
    fs::write(ruta_metadata(&ruta), &fondo.bytes_metadata).expect("escribir solo metadata");
    let error = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("falta sector");
    assert!(
        matches!(error, ErrorFarmer::FaltaSector { .. }),
        "se esperaba FaltaSector, fue {error:?}"
    );

    let dir = DirTemporal::nuevo("clave");
    let ruta = instalar_par(&dir, fondo);
    let otra = PublicKey::from([9u8; 32]);
    let error = ParcelaDisco::abrir(&ruta, &otra).expect_err("clave distinta");
    assert!(
        matches!(error, ErrorFarmer::ClaveDiscordante),
        "se esperaba ClaveDiscordante, fue {error:?}"
    );

    let dir = DirTemporal::nuevo("truncado");
    let ruta = instalar_par(&dir, fondo);
    let archivo = OpenOptions::new()
        .write(true)
        .open(&ruta)
        .expect("abrir sector para truncar");
    let longitud = archivo.metadata().expect("metadata del archivo").len();
    archivo.set_len(longitud - 1).expect("truncar sector");
    let error = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("sector truncado");
    assert!(
        matches!(error, ErrorFarmer::LongitudDiscordante { .. }),
        "se esperaba LongitudDiscordante, fue {error:?}"
    );

    let dir = DirTemporal::nuevo("meta-truncada");
    let ruta = instalar_par(&dir, fondo);
    let meta = ruta_metadata(&ruta);
    let archivo = OpenOptions::new()
        .write(true)
        .open(&meta)
        .expect("abrir metadata para truncar");
    let longitud = archivo.metadata().expect("metadata del archivo").len();
    archivo.set_len(longitud - 1).expect("truncar metadata");
    let error = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("metadata truncada");
    assert!(
        matches!(error, ErrorFarmer::MetadataCorrupta),
        "se esperaba MetadataCorrupta, fue {error:?}"
    );
}

#[test]
fn ploteo_sobre_par_existente_rechaza_y_conserva_el_previo() {
    let fondo = fondo();

    let dir = DirTemporal::nuevo("existe");
    let ruta = instalar_par(&dir, fondo);

    let salida = [3u8; 16];
    let slot = 0u64;
    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir parcela previa");
    let antes: usize = parcela
        .auditar_slot(salida, slot, RANGO_PRUEBA)
        .expect("auditar el par previo")
        .iter()
        .map(|r| r.num_candidatos)
        .sum();
    drop(parcela);

    let error = plotear_sector_en_disco(
        &ruta,
        &fondo.public_key,
        INDICE_SECTOR,
        PIEZAS,
        fondo.historia.historial(),
        fondo.historia.protocolo(),
        fondo.historia.erasure_coding(),
    )
    .expect_err("no debe sobreescribir sin una operación segura");
    assert!(
        matches!(error, ErrorFarmer::ParcelaExistente { .. }),
        "se esperaba ParcelaExistente, fue {error:?}"
    );

    // El par previo queda byte a byte intacto: misma huella de sector y misma metadata.
    assert_eq!(
        fs::read(&ruta).expect("releer sector previo"),
        fondo.bytes_sector,
        "el rechazo no debe tocar el sector previo"
    );
    assert_eq!(
        fs::read(ruta_metadata(&ruta)).expect("releer metadata previa"),
        fondo.bytes_metadata,
        "el rechazo no debe tocar la metadata previa"
    );

    // Y sigue abriendo con exactamente la misma auditoría.
    let reabierta = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("reabrir parcela previa");
    let despues: usize = reabierta
        .auditar_slot(salida, slot, RANGO_PRUEBA)
        .expect("auditar el par previo tras el rechazo")
        .iter()
        .map(|r| r.num_candidatos)
        .sum();
    assert_eq!(
        despues, antes,
        "la auditoría del par previo debe ser idéntica tras el rechazo"
    );
}

#[test]
fn plotter_fallido_no_deja_par_ni_lock() {
    let fondo = fondo();

    // Error de plotter (erasure coding con muy pocos shards): no debe dejar par utilizable.
    let dir = DirTemporal::nuevo("plot-falla");
    let ruta = dir.unir("sector.plot");
    let poca = ErasureCoding::new(NonZeroUsize::new(4).expect("no es cero"))
        .expect("4 shards es una instancia válida");
    let error = plotear_sector_en_disco(
        &ruta,
        &fondo.public_key,
        INDICE_SECTOR,
        PIEZAS,
        fondo.historia.historial(),
        fondo.historia.protocolo(),
        &poca,
    )
    .expect_err("el plotter debe fallar");
    assert!(
        matches!(error, ErrorFarmer::Plot(_)),
        "se esperaba Plot, fue {error:?}"
    );
    assert!(!ruta.exists(), "un ploteo fallido no debe dejar sector");
    assert!(
        !ruta_metadata(&ruta).exists(),
        "un ploteo fallido no debe dejar metadata"
    );
    assert!(
        !con_sufijo(&ruta, ".lock").exists(),
        "el guard de lock propio debe retirarse al fallar"
    );
    assert!(
        !con_sufijo(&ruta, ".tmp").exists(),
        "un ploteo fallido no debe dejar temporal de sector"
    );
    assert!(
        !con_sufijo(&ruta_metadata(&ruta), ".tmp").exists(),
        "un ploteo fallido no debe dejar temporal de metadata"
    );
}

#[test]
fn lock_preexistente_falla_cerrado_sin_tocar_al_primero() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("lock-ajeno");
    let ruta = dir.unir("sector.plot");

    // Estado del primer escritor: retiene el lock y ha dejado su temporal a medias.
    let ruta_lock = con_sufijo(&ruta, ".lock");
    fs::write(&ruta_lock, b"primer-escritor").expect("escribir lock del primero");
    let tmp_primero = con_sufijo(&ruta, ".tmp");
    fs::write(&tmp_primero, b"temporal-del-primero").expect("escribir temporal del primero");

    let error = plotear_sector_en_disco(
        &ruta,
        &fondo.public_key,
        INDICE_SECTOR,
        PIEZAS,
        fondo.historia.historial(),
        fondo.historia.protocolo(),
        fondo.historia.erasure_coding(),
    )
    .expect_err("el lock ajeno debe detener el ploteo");
    assert!(
        matches!(error, ErrorFarmer::ParcelaEnUso { .. }),
        "se esperaba ParcelaEnUso, fue {error:?}"
    );

    // El segundo no publica nada ni toca el lock ni el temporal del primero.
    assert!(!ruta.exists(), "el segundo no debe publicar sector");
    assert!(
        !ruta_metadata(&ruta).exists(),
        "el segundo no debe publicar metadata"
    );
    assert_eq!(
        fs::read(&ruta_lock).expect("releer lock del primero"),
        b"primer-escritor",
        "el lock ajeno no se borra ni se modifica"
    );
    assert_eq!(
        fs::read(&tmp_primero).expect("releer temporal del primero"),
        b"temporal-del-primero",
        "un temporal preexistente no se borra a ciegas"
    );
}

#[test]
fn dos_escritores_concurrentes_publican_uno_solo() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("concurrente");
    let ruta = dir.unir("sector.plot");
    let barrera = Barrier::new(2);

    let ploteo = || {
        plotear_sector_en_disco(
            &ruta,
            &fondo.public_key,
            INDICE_SECTOR,
            PIEZAS,
            fondo.historia.historial(),
            fondo.historia.protocolo(),
            fondo.historia.erasure_coding(),
        )
    };

    let resultados: Vec<Result<(), ErrorFarmer>> = std::thread::scope(|alcance| {
        let primero = alcance.spawn(|| {
            barrera.wait();
            ploteo()
        });
        let segundo = alcance.spawn(|| {
            barrera.wait();
            ploteo()
        });
        vec![
            primero.join().expect("hilo 1"),
            segundo.join().expect("hilo 2"),
        ]
    });

    let exitos = resultados.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        exitos, 1,
        "exactamente un escritor debe publicar, resultados: {resultados:?}"
    );
    // El perdedor falla `ParcelaEnUso` mientras el ganador plotea. Si se retrasara más que todo el
    // ploteo, vería el par ya publicado y fallaría `ParcelaExistente`; el caso `ParcelaEnUso`
    // queda fijado de forma determinista en `lock_preexistente_falla_cerrado_sin_tocar_al_primero`.
    let rechazos = resultados
        .iter()
        .filter(|r| {
            matches!(
                r,
                Err(ErrorFarmer::ParcelaEnUso { .. } | ErrorFarmer::ParcelaExistente { .. })
            )
        })
        .count();
    assert_eq!(
        rechazos, 1,
        "el otro escritor debe ser rechazado sin publicar, resultados: {resultados:?}"
    );

    // El par publicado abre y audita contra el oráculo independiente.
    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir par publicado");
    let salida = [5u8; 16];
    let total: usize = parcela
        .auditar_slot(salida, 0, RANGO_PRUEBA)
        .expect("auditar par publicado")
        .iter()
        .map(|r| r.num_candidatos)
        .sum();
    let esperado = candidatos_oraculo(&ruta, &parcela, salida, 0);
    assert_eq!(
        total, esperado,
        "el par publicado debe auditar como el oráculo"
    );
}

#[cfg(unix)]
#[test]
fn auditoria_usa_el_descriptor_verificado_tras_sustituir_la_ruta() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("descriptor");
    let ruta = instalar_par(&dir, fondo);

    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir parcela válida");
    let salida = [7u8; 16];
    let slot = 0u64;
    let antes: usize = parcela
        .auditar_slot(salida, slot, RANGO_PRUEBA)
        .expect("auditar antes de sustituir la ruta")
        .iter()
        .map(|r| r.num_candidatos)
        .sum();

    // El par verificado se mueve fuera de la ruta y en su lugar aparece otro archivo. No se vuelve
    // a llamar a `abrir`: la auditoría debe seguir leyendo el inode original a través del
    // descriptor guardado, no resolver `ruta` de nuevo.
    let ruta_movida = dir.unir("sector-movido.plot");
    fs::rename(&ruta, &ruta_movida).expect("renombrar el sector verificado");
    fs::rename(ruta_metadata(&ruta), ruta_metadata(&ruta_movida))
        .expect("renombrar la metadata verificada");
    fs::write(&ruta, b"otro archivo en la misma ruta").expect("colocar sustituto en la ruta");

    let despues: usize = parcela
        .auditar_slot(salida, slot, RANGO_PRUEBA)
        .expect("auditar tras sustituir la ruta")
        .iter()
        .map(|r| r.num_candidatos)
        .sum();
    let esperado = candidatos_oraculo(&ruta_movida, &parcela, salida, slot);
    assert_eq!(
        despues, antes,
        "el descriptor verificado debe repetir el resultado aunque la ruta cambie"
    );
    assert_eq!(
        despues, esperado,
        "el descriptor verificado debe coincidir con el oráculo sobre el archivo movido"
    );

    // La ruta ya no contiene un par: quien la abra no recibe auditoría.
    let error =
        ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("la ruta sustituida no abre");
    assert!(
        matches!(error, ErrorFarmer::FaltaMetadata { .. }),
        "se esperaba FaltaMetadata en la ruta sustituida, fue {error:?}"
    );
}

#[test]
fn auditar_candidatos_coincide_con_oraculo_y_resumen() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("candidatos");
    let ruta = instalar_par(&dir, fondo);
    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir parcela válida");

    // El barrido 0..64 ya produce candidatos con otra salida; este límite solo acota la búsqueda
    // determinista por si el fixture cambia. No se fabrica ningún candidato: si no aparece, falla.
    const LIMITE_BUSQUEDA_SLOTS: u64 = 4096;
    let salida = [11u8; 16];
    let mut encontrado: Option<u64> = None;
    let mut comprobados = 0u64;
    for slot in 0..LIMITE_BUSQUEDA_SLOTS {
        let candidatos = parcela
            .auditar_candidatos(salida, slot, RANGO_PRUEBA)
            .expect("auditar candidatos");
        let total_candidatos: usize = candidatos.iter().map(|r| r.solution_candidates.len()).sum();
        for fila in &candidatos {
            assert_eq!(fila.sector_index, INDICE_SECTOR, "sector del candidato");
        }

        let resumen = parcela
            .auditar_slot(salida, slot, RANGO_PRUEBA)
            .expect("auditar resumen");
        let total_resumen: usize = resumen.iter().map(|r| r.num_candidatos).sum();
        let total_oraculo = candidatos_oraculo(&ruta, &parcela, salida, slot);

        assert_eq!(
            total_candidatos, total_oraculo,
            "slot {slot}: los candidatos reales deben coincidir con el oráculo"
        );
        assert_eq!(
            total_candidatos, total_resumen,
            "slot {slot}: el resumen debe contar los mismos candidatos que la API directa"
        );

        comprobados += 1;
        if total_candidatos > 0 {
            encontrado = Some(slot);
            break;
        }
    }

    assert!(
        encontrado.is_some(),
        "el fixture no produjo ningún candidato en {comprobados} slots con la salida {salida:?} y \
         rango {RANGO_PRUEBA}; no se fabrica un candidato: revisa el fixture o el límite de test"
    );
    eprintln!(
        "[medición local, no consenso] primer slot determinista con candidatos: {encontrado:?} \
         (salida {salida:?})"
    );
}

/// Salida de PoT de fixture para D2. Valor de test, no de red.
const SALIDA_D2: [u8; 16] = [13u8; 16];

/// Límite de test del barrido de slots de D2. Si no aparece solución, el test falla con mensaje.
const LIMITE_BUSQUEDA_SOLUCION: u64 = 64;

/// W08e: la conversión corta en la **primera** solución verificada (una por `(clave, slot)`), sin
/// dejar de verificar A1. Con el rango de test el fixture produce varios candidatos por slot; la
/// conversión devuelve uno y no genera tabla/testigo de los restantes.
#[test]
fn w08e_la_conversion_corta_en_la_primera_solucion() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("conversion-corta");
    let ruta = instalar_par(&dir, fondo);
    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir parcela válida");
    let params = fondo.historia.params_pieza();

    let mut hallado: Option<(u64, ResultadoConversionLocal)> = None;
    for slot in 0..LIMITE_BUSQUEDA_SOLUCION {
        let resultado = convertir_candidatos_locales(
            &parcela,
            SALIDA_D2,
            slot,
            RANGO_PRUEBA,
            &params,
            &fondo.historia,
            fondo.historia.erasure_coding(),
        )
        .expect("la conversión no debe fallar con el contexto del fixture");
        if resultado.diagnostico().candidatos > 1 && !resultado.soluciones().is_empty() {
            hallado = Some((slot, resultado));
            break;
        }
    }
    let (slot, resultado) = hallado.expect(
        "el fixture debe producir un slot con varios candidatos y al menos una solución verificada",
    );
    assert_eq!(
        resultado.soluciones().len(),
        1,
        "W08e: como mucho una solución por (clave, slot)"
    );
    let comprobada = &resultado.soluciones()[0];
    let distancia = verificar_solucion_poas(
        comprobada.solucion(),
        slot,
        SALIDA_D2,
        RANGO_PRUEBA,
        &params,
    )
    .expect("la solución devuelta debe verificar de forma independiente");
    assert_eq!(distancia, comprobada.distancia());
    eprintln!(
        "[W08e] slot {slot}: candidatos={} devueltas={}",
        resultado.diagnostico().candidatos,
        resultado.soluciones().len()
    );
}

/// W08e: la tabla PoSpace cacheada devuelve las **mismas** pruebas que la generada directamente y
/// se reutiliza entre llamadas. La tabla depende de `(sector_id, piece_offset)` y no del reto.
#[test]
fn w08e_la_tabla_cacheada_coincide_con_la_generada() {
    use subspace_core_primitives::pos::PosSeed;
    use subspace_proof_of_space::Table;
    use subspace_proof_of_space::TableGenerator;
    use subspace_proof_of_space::chia::ChiaTable;

    let fondo = fondo();
    let dir = DirTemporal::nuevo("cache-tabla");
    let ruta = instalar_par(&dir, fondo);
    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir parcela válida");
    let seed = PosSeed::from([7u8; 32]);

    let cacheada = parcela.tabla_pos_cacheada(&seed);
    let directa = ChiaTable::generator().generate(&seed);
    for i in [0u32, 1, 12_345, 999_999] {
        assert_eq!(
            cacheada.find_proof(i),
            directa.find_proof(i),
            "la tabla cacheada debe coincidir con la generada para el índice {i}"
        );
    }
    let cacheada2 = parcela.tabla_pos_cacheada(&seed);
    for i in [0u32, 12_345] {
        assert_eq!(cacheada.find_proof(i), cacheada2.find_proof(i));
    }
}

/// D2 (tramo local): convierte candidatos de D1 en soluciones, verifica con A1 y no acepta lo que
/// A1 rechaza. No elige padres, no firma y no publica.
#[test]
fn convierte_candidatos_y_verifica_a1() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("conversion-a1");
    let ruta = instalar_par(&dir, fondo);
    let parcela = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect("abrir parcela válida");
    let params = fondo.historia.params_pieza();

    // Barrido con límite de test explícito hasta la primera solución verificada por A1.
    let mut hallado: Option<(u64, ResultadoConversionLocal)> = None;
    let mut barridos = 0u64;
    for slot in 0..LIMITE_BUSQUEDA_SOLUCION {
        let resultado = convertir_candidatos_locales(
            &parcela,
            SALIDA_D2,
            slot,
            RANGO_PRUEBA,
            &params,
            &fondo.historia,
            fondo.historia.erasure_coding(),
        )
        .expect("la conversión no debe fallar con el contexto del fixture");
        barridos += 1;
        if !resultado.soluciones().is_empty() {
            hallado = Some((slot, resultado));
            break;
        }
    }
    let mensaje = format!(
        "el fixture no produjo ninguna solución verificada por A1 en {barridos} slots con la salida \
         {SALIDA_D2:?} y rango {RANGO_PRUEBA}; no se fabrica una solución: revisa el fixture o el \
         límite de test"
    );
    let (slot, resultado) = hallado.expect(&mensaje);

    // Cada solución devuelta vuelve a verificar de forma independiente y su distancia es la de A1.
    for comprobada in resultado.soluciones() {
        let distancia = verificar_solucion_poas(
            comprobada.solucion(),
            slot,
            SALIDA_D2,
            RANGO_PRUEBA,
            &params,
        )
        .expect("la solución devuelta debe verificar de forma independiente");
        assert_eq!(
            distancia,
            comprobada.distancia(),
            "la distancia devuelta debe ser la que calcula A1"
        );
    }
    assert_eq!(
        resultado.diagnostico().soluciones_verificadas,
        resultado.soluciones().len(),
        "el contador de verificadas debe coincidir con las devueltas"
    );
    assert!(
        resultado.diagnostico().soluciones_generadas >= resultado.soluciones().len(),
        "no puede haber más verificadas que generadas"
    );

    // Mutación de prueba: A1 la rechaza y la API no la devuelve como válida.
    let mut mutada = *resultado.soluciones()[0].solucion();
    mutada.proof_of_space = [0u8; 160];
    let rechazo = verificar_solucion_poas(&mutada, slot, SALIDA_D2, RANGO_PRUEBA, &params)
        .expect_err("A1 debe rechazar la mutación de prueba");
    assert!(
        matches!(rechazo, ErrorPoas::Prueba(_)),
        "la mutación debe rechazarse como prueba inválida, fue {rechazo:?}"
    );
    assert!(
        resultado
            .soluciones()
            .iter()
            .all(|comprobada| comprobada.solucion() != &mutada),
        "la API no debe devolver la mutación como válida"
    );

    // Contexto de pieza incompatible (compromiso de segmento ajeno): A1 rechaza las generadas y la
    // API no acepta ninguna. El rechazo se cuenta en `rechazos_a1` **sin atribuir causa**: no
    // prueba un falso positivo del auditor y, con contexto ajeno, puede ocultar un fallo de
    // integración causal; la función no acredita la procedencia del contexto. Sin A1, aquí
    // aparecerían soluciones.
    let mut contexto_ajeno = params.clone();
    contexto_ajeno.segment_commitment = SegmentCommitment::default();
    let con_ajeno = convertir_candidatos_locales(
        &parcela,
        SALIDA_D2,
        slot,
        RANGO_PRUEBA,
        &contexto_ajeno,
        &fondo.historia,
        fondo.historia.erasure_coding(),
    )
    .expect("un contexto aritméticamente válido no debe ser error");
    assert!(
        con_ajeno.soluciones().is_empty(),
        "un contexto de pieza incompatible no puede producir soluciones válidas"
    );
    assert!(
        con_ajeno.diagnostico().rechazos_a1 > 0,
        "el rechazo debe contarse como rechazo de A1 (sin atribución de causa), no como ausencia \
         de candidato"
    );

    // Contexto aritméticamente inválido: error explícito, nunca aceptación.
    let mut contexto_invalido = params.clone();
    contexto_invalido.current_history_size =
        HistorySize::from(NonZeroU64::new(u64::MAX).expect("no es cero"));
    let error = convertir_candidatos_locales(
        &parcela,
        SALIDA_D2,
        slot,
        RANGO_PRUEBA,
        &contexto_invalido,
        &fondo.historia,
        fondo.historia.erasure_coding(),
    )
    .expect_err("un contexto aritméticamente inválido debe propagarse como error");
    assert!(
        matches!(
            error,
            ErrorProductorPoas::Contexto(ErrorPoas::ContextoInvalido(_))
        ),
        "se esperaba contexto inválido explícito, fue {error:?}"
    );

    // `InvalidHistorySize` de upstream (rama `derive_expiration_history_size`) es un fallo del
    // contexto de pieza/expiración, no un rechazo ordinario: se propaga por
    // `ErrorProductorPoas::Contexto` conservando el motivo upstream, sin contarlo como
    // `rechazos_a1` ni convertirlo en conjunto vacío. Se induce con el mismo fixture de A1
    // (`min_sector_lifetime` desbordado + compromiso de expiración del segmento) y el slot ya
    // hallado, sin volver a plotear.
    let mut contexto_expiracion = params.clone();
    contexto_expiracion.min_sector_lifetime =
        HistorySize::from(NonZeroU64::new(u64::MAX).expect("no es cero"));
    contexto_expiracion.sector_expiration_check_segment_commitment =
        Some(params.segment_commitment);
    let error = convertir_candidatos_locales(
        &parcela,
        SALIDA_D2,
        slot,
        RANGO_PRUEBA,
        &contexto_expiracion,
        &fondo.historia,
        fondo.historia.erasure_coding(),
    )
    .expect_err("la expiración de sector no representable debe propagarse como error");
    assert!(
        matches!(
            error,
            ErrorProductorPoas::Contexto(ErrorPoas::Prueba(
                subspace_verification::Error::InvalidHistorySize
            ))
        ),
        "se esperaba propagar InvalidHistorySize conservando el motivo upstream, fue {error:?}"
    );

    eprintln!(
        "[medición local, no consenso] D2: primera solución verificada en slot {slot}; diagnóstico \
         {:?}; hilos visibles {}",
        resultado.diagnostico(),
        std::thread::available_parallelism().map_or(1, |n| n.get()),
    );
}

#[test]
fn abrir_rechaza_metadata_sparse_sobredimensionada_sin_leerla() {
    let fondo = fondo();
    let dir = DirTemporal::nuevo("meta-gigante");
    let ruta = instalar_par(&dir, fondo);

    // Archivo disperso de 8 GiB: `set_len` no reserva bloques de datos. Si `abrir` lo leyera,
    // agotaría memoria o tardaría; debe rechazarlo por longitud antes de leer y sin cargarlo.
    let meta = ruta_metadata(&ruta);
    let archivo = OpenOptions::new()
        .write(true)
        .open(&meta)
        .expect("abrir metadata para agrandar");
    archivo
        .set_len(8 * 1024 * 1024 * 1024)
        .expect("crecer metadata de forma dispersa");
    drop(archivo);

    let error =
        ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("metadata sobredimensionada");
    assert!(
        matches!(
            error,
            ErrorFarmer::MetadataSobredimensionada { limite, encontrado }
                if limite == 2 * 1024 * 1024 && encontrado == 8 * 1024 * 1024 * 1024
        ),
        "se esperaba MetadataSobredimensionada con el límite de 2 MiB, fue {error:?}"
    );
}

#[test]
fn abrir_rechaza_metadata_bien_checksummada_pero_incoherente() {
    let fondo = fondo();

    // `plotted_sector.sector_index` distinto del de la cabecera, con checksum recalculado.
    let dir = DirTemporal::nuevo("meta-indice");
    let ruta = instalar_par(&dir, fondo);
    reescribir_metadata_con_checksum_valido(&ruta, |cuerpo| {
        cuerpo.plotted_sector.sector_index = cuerpo.sector_index.wrapping_add(1);
    });
    let error = ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("índice incoherente");
    assert!(
        matches!(error, ErrorFarmer::IndicePlottedDiscordante),
        "se esperaba IndicePlottedDiscordante, fue {error:?}"
    );

    // `piece_indexes.len()` distinto de `pieces_in_sector`, con checksum recalculado.
    let dir = DirTemporal::nuevo("meta-indices-piezas");
    let ruta = instalar_par(&dir, fondo);
    reescribir_metadata_con_checksum_valido(&ruta, |cuerpo| {
        cuerpo.plotted_sector.piece_indexes.pop();
    });
    let error =
        ParcelaDisco::abrir(&ruta, &fondo.public_key).expect_err("índices de pieza incoherentes");
    assert!(
        matches!(error, ErrorFarmer::IndicesPiezasDiscordantes { .. }),
        "se esperaba IndicesPiezasDiscordantes, fue {error:?}"
    );
}

fn voltear_ultimo_byte(ruta: &Path) {
    let mut archivo = OpenOptions::new()
        .read(true)
        .write(true)
        .open(ruta)
        .expect("abrir archivo para corromper");
    let longitud = archivo.metadata().expect("metadata del archivo").len();
    archivo
        .seek(SeekFrom::Start(longitud - 1))
        .expect("posicionar en el último byte");
    let mut byte = [0u8; 1];
    archivo.read_exact(&mut byte).expect("leer último byte");
    archivo
        .seek(SeekFrom::Start(longitud - 1))
        .expect("reposicionar");
    archivo
        .write_all(&[byte[0] ^ 0xFF])
        .expect("escribir byte volteado");
}
