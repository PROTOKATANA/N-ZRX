//! Extremo a extremo PoAS sobre la historia génesis dev (V5) y negativos por mutación (V6).
//!
//! # Qué demuestra
//!
//! 1. **V5**: con la historia derivada del génesis dev (D-P12), un sector ploteado con una clave dev
//!    produce, para retos de prueba fijos, **al menos tres** soluciones que
//!    [`zx_poas::verificar_solucion_poas`] acepta, con la distancia que devuelve la primitiva.
//! 2. **V6**: alterar `chunk`, `proof_of_space`, `public_key`, `sector_index`, `history_size` o
//!    `piece_offset` de una solución honesta, o usar `PieceCheckParams` con otro compromiso / otros
//!    parámetros de historia, se rechaza con su error.
//!
//! # Qué NO demuestra
//!
//! Nada de PoT, cabecera, sello, admisión, DAG, orden ni publicación. `salida` y `slot` son valores
//! de **prueba** fijos: su derivación desde el flujo PoT es de W05b2. El rango `u64::MAX` es un
//! valor de test para que los ganadores sean frecuentes, no un parámetro de red.

#![expect(
    clippy::expect_used,
    reason = "instrumento de test: un fallo al construir o comprobar el fixture debe producir panic"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "índices deliberados sobre arrays de anchura fija bajo prueba"
)]

use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::OnceLock;

use subspace_core_primitives::PublicKey;
use subspace_core_primitives::segments::{HistorySize, SegmentCommitment};
use subspace_verification::{Error as ErrorVerificacion, PieceCheckParams};
use zx_core::{ClavePublica, SolucionPoas};
use zx_farmer::farmer::{ParcelaDisco, plotear_sector_en_disco};
use zx_farmer::productor_poas::{SolucionComprobadaLocal, convertir_candidatos_locales};
use zx_poas::{
    ContextoInvalido, ErrorPoas, HistoriaGenesis, reto_desde_salida, verificar_solucion_poas,
};

/// Clave dev del sector ploteado. Valor de **prueba**, no de red.
const CLAVE_DEV: [u8; 32] = [0x11; 32];

/// Índice de sector del fixture; distinto de cero para ejercitar el offset natural del archivo.
const INDICE_SECTOR: u16 = 3;

/// Piezas por sector del fixture (protocolo dev, §3.1).
const PIEZAS: u16 = 2;

/// Salida de 16 B del **slot de prueba**. Valor fijo de test; su derivación del PoT es W05b2.
const SALIDA_PRUEBA: [u8; 16] = [0xa5; 16];

/// Rango de solución de **prueba**: `u64::MAX` para que los ganadores sean frecuentes.
const RANGO_PRUEBA: u64 = u64::MAX;

/// Límite de test del barrido de slots. Si no aparecen tres soluciones, el test lo dice y falla.
const LIMITE_SLOTS: u64 = 4_096;

/// Sector ploteado una sola vez por proceso.
struct Fondo {
    public_key: PublicKey,
    historia: HistoriaGenesis,
    ruta: PathBuf,
    /// Se retiene para que el directorio temporal viva mientras el `static` exista.
    _dir: DirTemporal,
}

static FONDO: OnceLock<Fondo> = OnceLock::new();

fn fondo() -> &'static Fondo {
    FONDO.get_or_init(|| {
        let public_key = PublicKey::from(CLAVE_DEV);
        let historia =
            HistoriaGenesis::construir().expect("la historia génesis dev debe construirse");
        let dir = DirTemporal::nuevo("e2e");
        let ruta = dir.unir("sector.plot");
        plotear_sector_en_disco(
            &ruta,
            &public_key,
            INDICE_SECTOR,
            PIEZAS,
            historia.historial(),
            historia.protocolo(),
            historia.erasure_coding(),
        )
        .expect("el ploteo del fixture debe funcionar");
        Fondo {
            public_key,
            historia,
            ruta,
            _dir: dir,
        }
    })
}

fn params() -> PieceCheckParams {
    fondo().historia.params_pieza()
}

/// Soluciones verificadas del barrido, con el slot que las produjo. Se calculan una sola vez.
static SOLUCIONES: OnceLock<Vec<(u64, SolucionComprobadaLocal)>> = OnceLock::new();

fn soluciones() -> &'static Vec<(u64, SolucionComprobadaLocal)> {
    SOLUCIONES.get_or_init(|| {
        let f = fondo();
        let parcela =
            ParcelaDisco::abrir(&f.ruta, &f.public_key).expect("la parcela del fixture debe abrir");
        let params = f.historia.params_pieza();
        let mut encontradas: Vec<(u64, SolucionComprobadaLocal)> = Vec::new();
        for slot in 0..LIMITE_SLOTS {
            let resultado = convertir_candidatos_locales(
                &parcela,
                SALIDA_PRUEBA,
                slot,
                RANGO_PRUEBA,
                &params,
                &f.historia,
                f.historia.erasure_coding(),
            )
            .expect("la conversión no debe fallar con el contexto del fixture");
            for comprobada in resultado.soluciones() {
                encontradas.push((slot, *comprobada));
            }
            if encontradas.len() >= 3 {
                break;
            }
        }
        encontradas
    })
}

fn primera() -> (u64, SolucionPoas) {
    let (slot, comprobada) = soluciones()
        .first()
        .expect("el barrido debe producir al menos una solución");
    (*slot, *comprobada.solucion())
}

/// Comprueba una solución mutable contra el contexto del fixture.
fn verificar(
    solucion: &SolucionPoas,
    slot: u64,
    contexto: &PieceCheckParams,
) -> Result<u64, ErrorPoas> {
    verificar_solucion_poas(solucion, slot, SALIDA_PRUEBA, RANGO_PRUEBA, contexto)
}

/// **V5 · reto de 32 B explícito.** La primitiva de auditoría acepta el reto directamente y la
/// cuenta de candidatos coincide con la ruta que lo deriva de `(salida, slot)`.
#[test]
fn v5_auditoria_con_reto_explicito_coincide() {
    let f = fondo();
    let parcela =
        ParcelaDisco::abrir(&f.ruta, &f.public_key).expect("la parcela del fixture debe abrir");
    let slot = 0_u64;
    let reto = reto_desde_salida(SALIDA_PRUEBA, slot);

    let con_reto: usize = parcela
        .auditar_con_reto(reto, RANGO_PRUEBA)
        .expect("auditar con reto explícito")
        .iter()
        .map(|resultado| resultado.solution_candidates.len())
        .sum();
    let derivado: usize = parcela
        .auditar_candidatos(SALIDA_PRUEBA, slot, RANGO_PRUEBA)
        .expect("auditar derivando el reto")
        .iter()
        .map(|resultado| resultado.solution_candidates.len())
        .sum();
    assert_eq!(
        con_reto, derivado,
        "la ruta con reto explícito debe coincidir con la que lo deriva"
    );
}

/// **V5.** Al menos tres soluciones honestas son aceptadas por el verificador real.
#[test]
fn v5_tres_soluciones_honestas_son_aceptadas() {
    let encontradas = soluciones();
    assert!(
        encontradas.len() >= 3,
        "el fixture debe producir al menos 3 soluciones en {LIMITE_SLOTS} slots; produjo {}",
        encontradas.len()
    );

    let contexto = params();
    for (slot, comprobada) in encontradas.iter().take(3) {
        let distancia = verificar(comprobada.solucion(), *slot, &contexto)
            .expect("cada solución devuelta debe verificar de forma independiente");
        assert_eq!(
            distancia,
            comprobada.distancia(),
            "la distancia devuelta debe ser la que calcula la primitiva"
        );
    }

    // Las tres primeras son distintas entre sí (dos slots no repiten la misma prueba de espacio).
    let tres: Vec<&(u64, SolucionComprobadaLocal)> = encontradas.iter().take(3).collect();
    for i in 0..tres.len() {
        for j in (i + 1)..tres.len() {
            assert_ne!(
                tres[i].1.solucion().proof_of_space,
                tres[j].1.solucion().proof_of_space,
                "las soluciones contadas como distintas no deben repetir la prueba de espacio"
            );
        }
    }

    eprintln!(
        "[medición local de fixture, no consenso] V5: {} soluciones verificadas en los primeros \
         slots; primera en el slot {} con distancia {}",
        encontradas.len(),
        encontradas[0].0,
        encontradas[0].1.distancia()
    );
}

/// **V6 · `proof_of_space`.** Alterada, la primitiva responde `InvalidProofOfSpace`.
#[test]
fn v6_proof_of_space_alterada_se_rechaza() {
    let (slot, mut solucion) = primera();
    solucion.proof_of_space = [0u8; 160];
    assert_eq!(
        verificar(&solucion, slot, &params()),
        Err(ErrorPoas::Prueba(ErrorVerificacion::InvalidProofOfSpace))
    );
}

/// **V6 · `chunk`.** Alterado, deja de pertenecer al registro y la apertura Merkle falla.
#[test]
fn v6_chunk_alterado_se_rechaza() {
    let (slot, mut solucion) = primera();
    solucion.chunk[0] ^= 0xFF;
    let error =
        verificar(&solucion, slot, &params()).expect_err("el chunk alterado debe rechazarse");
    assert!(
        matches!(error, ErrorPoas::Merkle(_)),
        "se esperaba una falla Merkle, fue {error:?}"
    );
}

/// **V6 · `public_key`.** Alterada, cambia el `sector_id` y la prueba de espacio falla.
#[test]
fn v6_public_key_alterada_se_rechaza() {
    let (slot, mut solucion) = primera();
    solucion.public_key = ClavePublica::desde_bytes([0u8; 32]);
    assert_eq!(
        verificar(&solucion, slot, &params()),
        Err(ErrorPoas::Prueba(ErrorVerificacion::InvalidProofOfSpace))
    );
}

/// **V6 · `sector_index`.** Alterado, cambia el `sector_id` y la prueba de espacio falla.
#[test]
fn v6_sector_index_alterado_se_rechaza() {
    let (slot, mut solucion) = primera();
    solucion.sector_index = solucion.sector_index.wrapping_add(1);
    assert_eq!(
        verificar(&solucion, slot, &params()),
        Err(ErrorPoas::Prueba(ErrorVerificacion::InvalidProofOfSpace))
    );
}

/// **V6 · `history_size = 0`.** Entrada no canónica para upstream (`NonZeroU64`).
#[test]
fn v6_history_size_cero_se_rechaza() {
    let (slot, mut solucion) = primera();
    solucion.history_size = 0;
    assert_eq!(
        verificar(&solucion, slot, &params()),
        Err(ErrorPoas::EntradaNoCanonica)
    );
}

/// **V6 · `history_size` no nulo.** Alterado, cambia el `sector_id` y la prueba de espacio falla.
#[test]
fn v6_history_size_no_nulo_alterado_se_rechaza() {
    let (slot, mut solucion) = primera();
    solucion.history_size = solucion.history_size.saturating_add(1);
    assert_eq!(
        verificar(&solucion, slot, &params()),
        Err(ErrorPoas::Prueba(ErrorVerificacion::InvalidProofOfSpace))
    );
}

/// **V6 · `piece_offset`.** Alterado, cambia la semilla de evaluación y la prueba de espacio falla.
#[test]
fn v6_piece_offset_alterado_se_rechaza() {
    let (slot, mut solucion) = primera();
    solucion.piece_offset ^= 1;
    assert_eq!(
        verificar(&solucion, slot, &params()),
        Err(ErrorPoas::Prueba(ErrorVerificacion::InvalidProofOfSpace))
    );
}

/// **V6 · contexto con otro compromiso.** El contexto no pertenece a esta historia: la apertura
/// registro→segmento no cierra.
#[test]
fn v6_contexto_con_otro_compromiso_se_rechaza() {
    let (slot, solucion) = primera();
    let mut contexto = params();
    contexto.segment_commitment = SegmentCommitment::default();
    assert!(matches!(
        verificar(&solucion, slot, &contexto),
        Err(ErrorPoas::Merkle(_))
    ));
}

/// **V6 · contexto con otro `current_history_size`.** El contexto es aritméticamente inválido: la
/// comprobación previa devuelve su error de contexto, no un rechazo de la prueba.
#[test]
fn v6_contexto_con_otro_history_size_se_rechaza() {
    let (slot, solucion) = primera();
    let mut contexto = params();
    contexto.current_history_size =
        HistorySize::from(NonZeroU64::new(u64::MAX).expect("u64::MAX no es cero"));
    assert_eq!(
        verificar(&solucion, slot, &contexto),
        Err(ErrorPoas::ContextoInvalido(
            ContextoInvalido::CurrentHistorySizeSinMargen
        ))
    );
}

/// **V6 · contexto con `recent_segments` no representable.** Además de otro compromiso y otro
/// `history_size`, un contexto cuyos parámetros de historia desbordan el umbral de upstream se
/// rechaza antes de llamarlo, con su error de contexto.
#[test]
fn v6_contexto_con_recent_segments_desbordado_se_rechaza() {
    let (slot, solucion) = primera();
    let mut contexto = params();
    contexto.recent_segments =
        HistorySize::from(NonZeroU64::new(u64::MAX >> 8).expect("u64::MAX>>8 no es cero"));
    let error = verificar(&solucion, slot, &contexto).expect_err("el contexto debe rechazarse");
    assert!(
        matches!(
            error,
            ErrorPoas::ContextoInvalido(ContextoInvalido::UmbralRecienteDesborda { .. })
        ),
        "se esperaba UmbralRecienteDesborda, fue {error:?}"
    );
}

/// Directorio temporal con limpieza al soltar; se retiene dentro del `static`.
struct DirTemporal {
    ruta: PathBuf,
}

impl DirTemporal {
    fn nuevo(nombre: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CONTADOR: AtomicU64 = AtomicU64::new(0);
        let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("zx-farmer-{}-{}-{}", std::process::id(), nombre, n));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("crear directorio temporal");
        Self { ruta: base }
    }

    fn unir(&self, hijo: &str) -> PathBuf {
        self.ruta.join(hijo)
    }
}

impl Drop for DirTemporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ruta);
    }
}
