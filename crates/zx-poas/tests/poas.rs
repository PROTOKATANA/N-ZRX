//! Pruebas del verificador PoAS de `zx-poas::verificador` (A1; paso 5 de `C-POT-08`).
//!
//! Contexto **sintético**: el record es constante y el segmento se forma con compromisos
//! repetidos, ambos con KZG genuino. No se afirma que este segmento sea una historia alcanzable
//! por ZEROX/Archiver, ni se valida PoT, sello, cabecera, cuerpo, DAG ni orden.
//!
//! # Fixture
//!
//! Es la misma fixture fijada de `prototipos/poas-identidad` (mismo contexto, `slot = 4`,
//! `bucket = 22412` y las tres distancias conocidas). Se genera **una sola vez** con la ruta
//! **paralela** de ploteo (`Tables::create_parallel`). La ruta no paralela tiene un SIGSEGV
//! reproducible documentado en `P-ZRX/P-INTENTO/investigacion/mediciones/fallo-semilla.md` y no se
//! usa aquí.
//!
//! La distancia esperada es una **constante externa al wrapper**, no una segunda llamada idéntica
//! a `verify_solution`: comparar el wrapper consigo mismo no probaría nada.

#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño; índices sobre arrays de anchura fija"
)]

use std::num::NonZeroU64;
use std::sync::OnceLock;

use ab_proof_of_space::chiapos::{Tables, TablesCache};
use subspace_core_primitives::pieces::PieceOffset;
use subspace_core_primitives::pos::PosProof;
use subspace_core_primitives::pot::PotOutput;
use subspace_core_primitives::sectors::SectorId;
use subspace_core_primitives::segments::{ArchivedHistorySegment, HistorySize};
use subspace_core_primitives::{PublicKey, ScalarBytes};
use subspace_kzg::Scalar;
use subspace_verification::{Error, PieceCheckParams};
use zx_core::{ClavePublica, SolucionPoas};
use zx_poas::{ContextoInvalido, ErrorPoas, a_segment_commitment, verificar_solucion_poas};

/// Distancia de la primera PoS de offset 0. Constante registrada en `poas-identidad`.
const DISTANCIA_PRIMERA: u64 = 4_352_823_087_875_908_110;
/// Distancia de la segunda PoS de offset 0.
const DISTANCIA_ALTERNATIVA: u64 = 8_322_768_934_019_865_430;
/// Distancia de la PoS de offset 1 a igual slot/bucket.
const DISTANCIA_OTRA_PIEZA: u64 = 3_650_123_740_992_092_631;
/// Slot y bucket fijados de la fixture.
const SLOT: u64 = 4;
const BUCKET: u32 = 22_412;
/// `⌊u64::MAX / 256⌋`: el mayor `recent_segments` que aún cabe en piezas (`× 256`).
const RECIENTE_MAXIMO_EN_PIEZAS: u64 = 72_057_594_037_927_935;

/// Contexto completo de la fixture, ya construido una vez.
struct Fixture {
    primera: SolucionPoas,
    alternativa: SolucionPoas,
    otra_pieza: SolucionPoas,
    params: PieceCheckParams,
    pot: [u8; 16],
    slot: u64,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn fixture() -> &'static Fixture {
    // El ploteo Chia K=20 usa pilas profundas: el hilo de test por defecto (2 MiB) desborda.
    // Se construye en un hilo propio con holgura y se transfiere el resultado ya construido.
    FIXTURE.get_or_init(|| {
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(construir_fixture)
            .expect("hilo de fixture")
            .join()
            .expect("fixture sin panic")
    })
}

fn history(size: u64) -> HistorySize {
    HistorySize::from(NonZeroU64::new(size).expect("constante positiva de fixture"))
}

fn bucket(sector: &SectorId, pot: PotOutput, slot: u64) -> u32 {
    let global = pot.derive_global_randomness().derive_global_challenge(slot);
    u16::from(
        sector
            .derive_sector_slot_challenge(&global)
            .s_bucket_audit_index(),
    )
    .into()
}

fn prefix(s_bucket: u32) -> u32 {
    // Misma costura endian que `ChiaTable::is_proof_valid`, K = 20 del commit fijado.
    u32::from_be_bytes(s_bucket.to_le_bytes()) >> (32 - u32::from(PosProof::K))
}

fn construir_fixture() -> Fixture {
    // Clave Ed25519 de semilla pública [0x42; 32], la misma de `poas-identidad`.
    let public_key = PublicKey::from([
        0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab,
        0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06, 0x98, 0x81,
        0xdb, 0x12,
    ]);
    let history_size = history(3);
    let sector_index = 7;
    let sector = SectorId::new(public_key.hash(), sector_index, history_size);
    let pot = PotOutput::from([0x35; 16]);

    // Registro constante (B-21): todas las hojas iguales al chunk `value`, que es el mismo valor
    // que usaba el fixture KZG de `poas-identidad` (así las distancias congeladas se conservan).
    let value = Scalar::from([0x17; ScalarBytes::SAFE_BYTES]);
    let chunk: [u8; 32] = *ScalarBytes::from(value);
    let mut chunks = vec![[0u8; 32]; zx_merkle::HOJAS_POR_REGISTRO];
    for hoja in chunks.iter_mut() {
        *hoja = chunk;
    }
    let record_root = zx_merkle::construir_registro(&chunks)
        .expect("registro Merkle del fixture")
        .0;
    // Segmento constante: las 2⁸ raíces de registro son la misma.
    let raices = vec![record_root; ArchivedHistorySegment::NUM_PIECES];
    let segment_root = zx_merkle::construir_segmento(&raices)
        .expect("segmento Merkle del fixture")
        .0;

    let params = PieceCheckParams {
        max_pieces_in_sector: 2,
        segment_commitment: a_segment_commitment(segment_root),
        recent_segments: history(5),
        recent_history_fraction: (history(1), history(10)),
        min_sector_lifetime: history(4),
        current_history_size: history_size,
        sector_expiration_check_segment_commitment: None,
    };

    // Ruta PARALELA de ploteo: la no paralela tiene SIGSEGV reproducible.
    let cache = TablesCache::default();
    let table0 = Tables::<20>::create_parallel(
        sector.derive_evaluation_seed(PieceOffset::from(0)).into(),
        &cache,
    );
    let table1 = Tables::<20>::create_parallel(
        sector.derive_evaluation_seed(PieceOffset::from(1)).into(),
        &cache,
    );

    // Búsqueda acotada idéntica a `poas-identidad`: dos PoS de offset 0 y una de offset 1 bajo
    // el mismo slot/bucket. No se acepta regeneración silenciosa.
    let mut selected = None;
    for slot in 1..=4096_u64 {
        let audit_bucket = bucket(&sector, pot, slot);
        let proofs0: Vec<[u8; 160]> = table0
            .find_proof_raw(prefix(audit_bucket))
            .take(2)
            .collect();
        if let ([first, second], Some(other)) = (
            proofs0.as_slice(),
            table1.find_proof_raw(prefix(audit_bucket)).next(),
        ) && first != second
        {
            selected = Some((slot, audit_bucket, *first, *second, other));
            break;
        }
    }
    let (slot, audit_bucket, proof0a, proof0b, proof1) =
        selected.expect("sin fixture en los 4096 slots");
    assert_eq!((slot, audit_bucket), (SLOT, BUCKET), "fixture fijada");

    let make_solution = |offset: u16, proof: [u8; 160]| -> SolucionPoas {
        let piece_offset = PieceOffset::from(offset);
        let position = sector
            .derive_piece_index(
                piece_offset,
                history_size,
                params.max_pieces_in_sector,
                params.recent_segments,
                params.recent_history_fraction,
            )
            .position();
        let camino_chunk =
            zx_merkle::camino_chunk(&chunks, audit_bucket).expect("camino de chunk del fixture");
        let camino_registro =
            zx_merkle::camino_registro(&raices, position).expect("camino de registro del fixture");
        SolucionPoas {
            public_key: ClavePublica::desde_bytes(*public_key),
            sector_index,
            history_size: history_size.get(),
            piece_offset: offset,
            record_commitment: record_root,
            record_witness: camino_registro.0,
            chunk,
            chunk_witness: camino_chunk.0,
            proof_of_space: proof,
        }
    };

    Fixture {
        primera: make_solution(0, proof0a),
        alternativa: make_solution(0, proof0b),
        otra_pieza: make_solution(1, proof1),
        params,
        pot: *pot,
        slot,
    }
}

/// Verifica contra la fixture con el contexto de pieza fijado.
fn verificar(
    solucion: &SolucionPoas,
    slot: u64,
    salida_pot: [u8; 16],
    rango: u64,
) -> Result<u64, ErrorPoas> {
    verificar_solucion_poas(solucion, slot, salida_pot, rango, &fixture().params)
}

#[test]
fn positivo_devuelve_la_distancia_de_la_fixture() {
    let f = fixture();
    assert_eq!(
        verificar(&f.primera, f.slot, f.pot, u64::MAX),
        Ok(DISTANCIA_PRIMERA),
        "la distancia esperada es la constante externa de poas-identidad"
    );
    assert_eq!(
        verificar(&f.alternativa, f.slot, f.pot, u64::MAX),
        Ok(DISTANCIA_ALTERNATIVA)
    );
    assert_eq!(
        verificar(&f.otra_pieza, f.slot, f.pot, u64::MAX),
        Ok(DISTANCIA_OTRA_PIEZA)
    );
    // La construcción no depende de un `Option`: el contexto es obligatorio por firma.
    assert_eq!(f.primera.piece_offset, 0);
    assert_eq!(f.otra_pieza.piece_offset, 1);
    // El fixture válido tiene `recent_segments = 5 > history_size = 3`; se acepta porque su rama
    // reciente no se ejecuta. La comprobación aritmética no impone una cota global falsa.
    assert!(f.params.recent_segments.get() > f.primera.history_size);
}

#[test]
fn proof_of_space_mutada_falla() {
    let f = fixture();
    let mut s = f.primera;
    s.proof_of_space = [0u8; 160];
    assert_eq!(
        verificar(&s, f.slot, f.pot, u64::MAX),
        Err(ErrorPoas::Prueba(Error::InvalidProofOfSpace))
    );
}

#[test]
fn chunk_witness_mutada_falla() {
    let f = fixture();
    let mut s = f.primera;
    s.chunk_witness = [0u8; 512];
    assert!(matches!(
        verificar(&s, f.slot, f.pot, u64::MAX),
        Err(ErrorPoas::Merkle(_))
    ));
}

#[test]
fn record_witness_mutada_falla() {
    let f = fixture();
    let mut s = f.primera;
    s.record_witness = [0u8; 256];
    assert!(matches!(
        verificar(&s, f.slot, f.pot, u64::MAX),
        Err(ErrorPoas::Merkle(_))
    ));
}

#[test]
fn record_commitment_mutada_falla() {
    let f = fixture();
    let mut s = f.primera;
    s.record_commitment[0] ^= 0x01;
    // La primera apertura (chunk↔registro) deja de cerrar contra la raíz mutada.
    assert!(matches!(
        verificar(&s, f.slot, f.pot, u64::MAX),
        Err(ErrorPoas::Merkle(_))
    ));
}

#[test]
fn rango_por_debajo_de_la_distancia_falla() {
    let f = fixture();
    let borde = DISTANCIA_PRIMERA
        .checked_mul(2)
        .and_then(|x| x.checked_sub(1))
        .expect("borde representable");
    let error = verificar(&f.primera, f.slot, f.pot, borde).expect_err("debe rechazar");
    assert!(matches!(
        error,
        ErrorPoas::Prueba(Error::OutsideSolutionRange { solution_distance, .. })
            if solution_distance == DISTANCIA_PRIMERA
    ));
    // El mismo rango justo por encima sí acepta: la frontera es el rango, no el wrapper.
    assert_eq!(
        verificar(&f.primera, f.slot, f.pot, borde + 1),
        Ok(DISTANCIA_PRIMERA)
    );
}

#[test]
fn history_size_cero_es_error_sin_panic() {
    let f = fixture();
    let mut s = f.primera;
    s.history_size = 0;
    assert_eq!(
        verificar(&s, f.slot, f.pot, u64::MAX),
        Err(ErrorPoas::EntradaNoCanonica)
    );
}

#[test]
fn salida_pot_equivocada_falla() {
    let f = fixture();
    let error = verificar(&f.primera, f.slot, [0x36; 16], u64::MAX).expect_err("debe rechazar");
    assert!(matches!(
        error,
        ErrorPoas::Prueba(Error::InvalidProofOfSpace)
    ));
}

#[test]
fn slot_equivocado_falla() {
    let f = fixture();
    let sector = SectorId::new(
        PublicKey::from(*f.primera.public_key.bytes()).hash(),
        f.primera.sector_index,
        history(3),
    );
    let pot = PotOutput::from(f.pot);
    let otro_slot = (f.slot + 1..f.slot + 4097)
        .find(|&s| bucket(&sector, pot, s) != BUCKET)
        .expect("sin slot de control");
    assert!(matches!(
        verificar(&f.primera, otro_slot, f.pot, u64::MAX),
        Err(ErrorPoas::Prueba(Error::InvalidProofOfSpace))
    ));
}

// ── Precondiciones aritméticas del contexto (upstream usa aritmética ordinaria) ─────────────
//
// `PieceCheckParams` es público y su tipo no garantiza los rangos: antes de llamar a upstream se
// comprueban con `checked_*` las operaciones que desbordan. Estas pruebas demuestran error
// explícito sin `panic`: si la comprobación faltase, el desbordamiento/underflow de upstream
// haría fallar el test con `panic` en perfil de test (que es `debug`).

/// `current_history_size = u64::MAX` haría desbordar el `+ 1` de upstream.
#[test]
fn current_history_size_maximo_es_contexto_invalido_sin_panic() {
    let f = fixture();
    let mut contexto = f.params.clone();
    contexto.current_history_size = history(u64::MAX);
    assert_eq!(
        verificar_solucion_poas(&f.primera, f.slot, f.pot, u64::MAX, &contexto),
        Err(ErrorPoas::ContextoInvalido(
            ContextoInvalido::CurrentHistorySizeSinMargen
        ))
    );
}

/// Una fracción/segmentos que desborda el producto del umbral reciente
/// (`recent_segments_in_pieces × fracción.1`) da error explícito, no `panic`.
#[test]
fn producto_del_umbral_reciente_es_contexto_invalido_sin_panic() {
    let f = fixture();
    let mut contexto = f.params.clone();
    // `RECIENTE_MAXIMO_EN_PIEZAS` por sí solo cabe en piezas; el producto por la fracción (`1/10`
    // del fixture, es decir 2 560 piezas) desborda.
    contexto.recent_segments = history(RECIENTE_MAXIMO_EN_PIEZAS);
    contexto.recent_history_fraction = (history(1), history(10));
    let error = verificar_solucion_poas(&f.primera, f.slot, f.pot, u64::MAX, &contexto)
        .expect_err("el contexto debe rechazarse antes de upstream");
    assert!(matches!(
        error,
        ErrorPoas::ContextoInvalido(ContextoInvalido::UmbralRecienteDesborda { .. })
    ));
}

/// La saturación de `HistorySize::in_pieces` no se acepta como dato válido.
#[test]
fn recent_segments_saturado_es_contexto_invalido_sin_panic() {
    let f = fixture();
    let mut contexto = f.params.clone();
    contexto.recent_segments = history(u64::MAX);
    assert_eq!(
        verificar_solucion_poas(&f.primera, f.slot, f.pot, u64::MAX, &contexto),
        Err(ErrorPoas::ContextoInvalido(
            ContextoInvalido::RecentSegmentsEnPiezas(u64::MAX)
        ))
    );
}

/// Una talla de historia del candidato que no cabe en piezas es entrada no canónica.
#[test]
fn history_size_del_candidato_que_no_cabe_es_entrada_no_canonica() {
    let f = fixture();
    let mut s = f.primera;
    s.history_size = RECIENTE_MAXIMO_EN_PIEZAS + 1;
    assert_eq!(
        verificar_solucion_poas(&s, f.slot, f.pot, u64::MAX, &f.params),
        Err(ErrorPoas::EntradaNoCanonica)
    );
}

/// La resta de la rama reciente de upstream
/// (`history_size_in_pieces − recent_segments_in_pieces`) se comprueba **bajo su condición
/// exacta**. Con multiplicador menor que divisor (`1/10`), la rama se ejecuta y restaría en
/// negativo: error explícito, no `panic`.
#[test]
fn resta_reciente_negativa_es_contexto_invalido_sin_panic() {
    let f = fixture();
    let mut contexto = f.params.clone();
    contexto.recent_segments = history(100);
    contexto.recent_history_fraction = (history(10), history(1));
    contexto.current_history_size = history(20);
    let mut s = f.primera;
    s.history_size = 20;
    s.piece_offset = 1;
    assert_eq!(
        verificar_solucion_poas(&s, f.slot, f.pot, u64::MAX, &contexto),
        Err(ErrorPoas::ContextoInvalido(
            ContextoInvalido::RestaRecienteNegativa {
                historia_piezas: 5_120,
                reciente_piezas: 25_600,
            }
        ))
    );
}

/// **Fallo 1** · `min_sector_lifetime` desbordado es contexto, no candidato.
///
/// `min_sector_lifetime` lo aporta `PieceCheckParams` y la puerta no lo acredita. Con
/// `history_size = 3` y `min_sector_lifetime = u64::MAX`, `SectorId::sector_expiration_check`
/// devuelve `None`, `derive_expiration_history_size` propaga `None` y la primitiva real responde
/// `Error::InvalidHistorySize`. El adaptador debe conservar ese error tipado —no `panic`, no `Ok`—
/// para que la puerta pueda clasificarlo como `Pendiente`. Se reutiliza la fixture positiva y su
/// compromiso de segmento; no se duplica el ploteo ni se genera una solución nueva.
#[test]
fn min_sector_lifetime_desbordado_devuelve_invalid_history_size_sin_panic() {
    let f = fixture();
    let mut contexto = f.params.clone();
    contexto.min_sector_lifetime = history(u64::MAX);
    contexto.sector_expiration_check_segment_commitment = Some(f.params.segment_commitment);

    assert_eq!(
        verificar_solucion_poas(&f.primera, f.slot, f.pot, u64::MAX, &contexto),
        Err(ErrorPoas::Prueba(Error::InvalidHistorySize))
    );
}
