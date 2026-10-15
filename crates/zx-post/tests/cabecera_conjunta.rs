//! Pruebas de integración de la puerta conjunta de cabecera (`zx-consensus::cabecera_conjunta`,
//! A3 parcial; `C-HDR-03`/`C-HDR-04`/`C-HDR-05`/`C-HDR-06`/`C-HDR-07` y `C-POT-08`).
//!
//! # Qué ejercita de verdad
//!
//! - La **función pública**, con el **sello ZIP-215 real** (`verificar_sello` sin costuras) y la
//!   **cadena AES real** de `zx-pot` para construir el rango PoT.
//! - La clasificación tipada de fallos: padres contextuales `Pendiente`, sello inválido
//!   `Invalida`, PoT pendiente/inválido sin PoAS, falta de contexto de pieza `Pendiente`,
//!   `ErrorPoas::EntradaNoCanonica` `Invalida` y `ErrorPoas::ContextoInvalido` `Pendiente`.
//!
//! # Qué NO cubre, y por qué
//!
//! **No se alcanza [`EstadoCabeceraConjunta::Comprobada`] por la ruta pública.** El único fixture
//! PoAS positivo del crate (`tests/poas.rs`) está atado a una `public_key` de Chia cuyo secreto
//! Ed25519 no se conoce, y vive en otro binario de test, así que no puede firmar el sello real de
//! la misma cabecera que verifica la PoS. Construir aquí un ploteo Chia K=20 con una clave que sí
//! sepamos firmar duplicaría ese fixture pesado; el orden pide exactamente documentar la cobertura
//! que falta en vez de fingir un positivo. La ruta `Comprobada` sí se ejercita en las pruebas
//! **internas** del módulo con espías, que no son la función pública.
//!
//! Los `InstantaneaPot`, `ContextoDag` y `ContextoRangoDag` de este archivo son **mocks**: datos
//! libres, sin procedencia causal. Un `Pendiente`/`Invalida` observado aquí no acredita el
//! veredicto de un nodo; solo fija la clasificación de la puerta.

#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
#![expect(clippy::panic, reason = "los tests fallan con panic por diseño")]

use core::num::NonZeroU32;
use std::collections::BTreeMap;
use std::num::NonZeroU64;

use ed25519_zebra::SigningKey;
use subspace_core_primitives::segments::{HistorySize, SegmentCommitment};
use subspace_verification::PieceCheckParams;

use zx_core::digest::{BodyCommitment, Digest, MerkleRoot};
use zx_core::wire_dag::JustificacionPot;
use zx_core::{
    BlockHash, BloqueDag, ClavePublica, DagBlockHeader, POT_OUTPUT_BYTES, PadresDag, SolucionPoas,
};
use zx_dag::ErrorDag as ConsensusError;
use zx_dag::bloque_dag::{ContextoDag, ContextoRangoDag};
use zx_poas::{ContextoInvalido, ErrorPoas};
use zx_post::cabecera_conjunta::{
    EstadoCabeceraConjunta, MotivoCabeceraInvalida, MotivoCabeceraPendiente,
    verificar_cabecera_conjunta,
};
use zx_post::pot::checkpoints_a_wire;
use zx_post::pot_rango::{
    BloqueDelPasado, CachePotVerificada, EstadoPot, FLUJO_BYTES, InstantaneaPot, InyeccionesPot,
    MotivoPotInvalido, MotivoPotPendiente, PresupuestoPot, verificar_rango_pot,
};
use zx_post::verificar_cabecera_conjunta as puerta_reexportada;
use zx_pot::tipos::PotSeed;

const FLUJO: [u8; FLUJO_BYTES] = [0x11; FLUJO_BYTES];
const BASE: [u8; POT_OUTPUT_BYTES] = [0xAB; POT_OUTPUT_BYTES];
const AUDITADA: [u8; POT_OUTPUT_BYTES] = [0x5A; POT_OUTPUT_BYTES];
const N: u64 = 16;
const SLOT_SP: u64 = 100;
const RETARDO: u64 = 2;
/// `d = slot(B) − slot(sp) = 1 ≤ D = 2`: la salida auditada la aporta el pasado.
const SLOT_B: u64 = SLOT_SP + 1;
/// `slot(sp) + D`: ancla del rango, también en el pasado.
const SLOT_BASE: u64 = SLOT_SP + RETARDO;
const RELOJ: u64 = 1_000;

fn hash_de(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

/// Mocks de los tres contextos. **Datos libres, sin procedencia acreditada.**
struct Mundo {
    flujo: [u8; FLUJO_BYTES],
    pasado: Vec<BloqueDelPasado>,
    iteraciones: BTreeMap<u64, u64>,
    retardo: u64,
    salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
    validados: Vec<BlockHash>,
    slots_padre: Vec<(BlockHash, u64)>,
    genesis: BlockHash,
    sp: BlockHash,
    rango_esperado: u64,
}

impl Mundo {
    /// El mismo escenario con solo el padre seleccionado validado: contexto incompleto.
    fn sin_el_padre_adicional(mut self) -> Self {
        self.validados.retain(|h| *h == self.sp);
        self
    }
}

impl InstantaneaPot for Mundo {
    fn flujo_candidato_en(&self, _slot: u64) -> Result<[u8; FLUJO_BYTES], MotivoPotPendiente> {
        Ok(self.flujo)
    }

    fn pasado(&self) -> Result<&[BloqueDelPasado], MotivoPotPendiente> {
        Ok(&self.pasado)
    }

    fn inyecciones_en(&self, _slot: u64) -> Result<InyeccionesPot, MotivoPotPendiente> {
        Ok(InyeccionesPot::Ninguna)
    }

    fn iteraciones(&self, slot: u64) -> Result<u64, MotivoPotPendiente> {
        self.iteraciones
            .get(&slot)
            .copied()
            .ok_or(MotivoPotPendiente::ContextoAusente { que: "N(s)" })
    }

    fn retardo_autoria(&self) -> Result<u64, MotivoPotPendiente> {
        Ok(self.retardo)
    }

    fn salida_validada(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], MotivoPotPendiente> {
        self.salidas
            .get(&slot)
            .copied()
            .ok_or(MotivoPotPendiente::ContextoAusente {
                que: "salida ancla",
            })
    }
}

impl ContextoDag for Mundo {
    fn es_bloque_validado(&self, h: &BlockHash) -> bool {
        self.validados.contains(h)
    }

    fn esta_en_el_pasado_de(
        &self,
        _antepasado: &BlockHash,
        _descendiente: &BlockHash,
    ) -> Result<bool, ConsensusError> {
        Ok(false)
    }

    fn slot_de_padre(&self, h: &BlockHash) -> Result<u64, ConsensusError> {
        if !self.validados.contains(h) {
            return Err(ConsensusError::PadreNoValidado { padre: *h });
        }
        self.slots_padre
            .iter()
            .find_map(|(id, slot)| (id == h).then_some(*slot))
            .ok_or(ConsensusError::SlotDePadreAusente { padre: *h })
    }

    fn padre_seleccionado(&self, _padres: &PadresDag) -> Result<BlockHash, ConsensusError> {
        Ok(self.sp)
    }

    fn es_terminal(&self, h: &BlockHash) -> bool {
        *h == self.genesis
    }
}

impl ContextoRangoDag for Mundo {
    fn rango_esperado(
        &self,
        _candidato: &zx_dag::bloque_dag::CandidatoSinRango<'_>,
    ) -> Result<u64, ConsensusError> {
        Ok(self.rango_esperado)
    }
}

struct PresupuestoPrueba {
    restantes: usize,
    intentos: usize,
}

impl PresupuestoPrueba {
    fn nuevo(restantes: usize) -> Self {
        Self {
            restantes,
            intentos: 0,
        }
    }
}

impl PresupuestoPot for PresupuestoPrueba {
    fn consumir_slot(&mut self, _slot: u64) -> bool {
        self.intentos += 1;
        if self.restantes == 0 {
            false
        } else {
            self.restantes -= 1;
            true
        }
    }
}

/// Contexto de pieza con aritmética válida. Solo se usa cuando el PoAS real debe **rechazar** por
/// el candidato o por el propio contexto; nunca se espera un positivo de él.
fn pieza_dummy() -> PieceCheckParams {
    let h = |n: u64| HistorySize::from(NonZeroU64::new(n).expect("n > 0"));
    PieceCheckParams {
        max_pieces_in_sector: 1,
        segment_commitment: SegmentCommitment::default(),
        recent_segments: h(1),
        recent_history_fraction: (h(1), h(1)),
        min_sector_lifetime: h(1),
        current_history_size: h(1),
        sector_expiration_check_segment_commitment: None,
    }
}

/// Escenario PoT/AES válido: `d = 1 ≤ D = 2`, un portador real en `SLOT_BASE + 1`.
fn escenario() -> (DagBlockHeader, JustificacionPot, Mundo) {
    let semilla = zx_post::pot::semilla_siguiente(BASE, None);
    let carrier = zx_pot::prove(
        PotSeed::from(semilla),
        NonZeroU32::new(u32::try_from(N).expect("N cabe en u32")).expect("N > 0"),
    )
    .expect("N múltiplo de 16");
    let portador = checkpoints_a_wire(&carrier);
    let pot_output = *carrier.output();

    let sp = hash_de(0x01);
    let extra = hash_de(0x02);
    let cabecera = DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: 0xc478_80ea,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
        timestamp: 1_788_480_000,
        height: 1,
        slot: SLOT_B,
        pot_output,
        rango_solucion: 5,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
        padres: PadresDag::nuevo(sp, &[extra]).expect("padres canónicos"),
        sello: [0u8; 64],
    };
    let justificacion = JustificacionPot::nueva(vec![portador]).expect("un portador");

    let mut salidas = BTreeMap::new();
    salidas.insert(SLOT_BASE, BASE);
    salidas.insert(SLOT_B, AUDITADA);
    let mut iteraciones = BTreeMap::new();
    iteraciones.insert(SLOT_BASE + 1, N);

    let mundo = Mundo {
        flujo: FLUJO,
        pasado: vec![
            BloqueDelPasado {
                hash: sp,
                slot: SLOT_SP,
                timestamp: 0,
                flujo: FLUJO,
            },
            BloqueDelPasado {
                hash: extra,
                slot: SLOT_SP,
                timestamp: 0,
                flujo: FLUJO,
            },
        ],
        iteraciones,
        retardo: RETARDO,
        salidas,
        validados: vec![sp, extra],
        slots_padre: vec![(sp, SLOT_SP), (extra, SLOT_SP)],
        genesis: hash_de(0xEE),
        sp,
        rango_esperado: 5,
    };
    (cabecera, justificacion, mundo)
}

fn bloque(cabecera: DagBlockHeader, justificacion: JustificacionPot) -> BloqueDag {
    BloqueDag::nuevo(cabecera, justificacion, Vec::new(), Vec::new()).expect("bloque sin cuerpo")
}

fn firmar(cabecera: &mut DagBlockHeader, sk: &SigningKey) {
    let vk = ed25519_zebra::VerificationKey::from(sk);
    cabecera.sol.public_key = ClavePublica::desde_bytes(vk.into());
    let pre = cabecera.pre_hash();
    cabecera.sello = sk.sign(pre.as_bytes()).into();
}

/// Cabecera válida y firmada, con `history_size` a elección, sobre el escenario PoT/AES.
fn bloque_firmado(history_size: u64, rango_solucion: u64) -> (BloqueDag, Mundo) {
    let (mut cabecera, justificacion, mundo) = escenario();
    cabecera.sol.history_size = history_size;
    cabecera.rango_solucion = rango_solucion;
    let sk = SigningKey::from([7u8; 32]);
    firmar(&mut cabecera, &sk);
    (bloque(cabecera, justificacion), mundo)
}

// ─────────────────────────────────────────────────────────────────────────────
// Paso 6: falta de contexto de pieza y PoAS real
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sin_contexto_de_pieza_es_pendiente_tras_sello_y_aes() {
    let (bloque, mundo) = bloque_firmado(3, 5);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        None,
    );

    assert_eq!(
        estado,
        EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::ContextoPiezaAusente)
    );
    assert_eq!(presupuesto.intentos, 1, "el rango AES real sí se ejecuta");
}

#[test]
fn el_poas_real_rechaza_entrada_no_canonica() {
    // `history_size = 0` no es representable por la primitiva upstream: fallo del candidato.
    let (bloque, mundo) = bloque_firmado(0, 5);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );

    assert_eq!(
        estado,
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Poas(
            ErrorPoas::EntradaNoCanonica
        ))
    );
}

#[test]
fn un_contexto_de_pieza_aritmeticamente_invalido_es_pendiente() {
    let (bloque, mundo) = bloque_firmado(1, 5);
    let mut pieza = pieza_dummy();
    pieza.current_history_size =
        HistorySize::from(NonZeroU64::new(u64::MAX).expect("u64::MAX es no nulo"));
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza),
    );

    assert_eq!(
        estado,
        EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::ContextoPieza(
            ContextoInvalido::CurrentHistorySizeSinMargen
        ))
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Orden: sello, padres, reloj y rango
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sello_invalido_no_gasta_presupuesto() {
    // Cabecera firmada y después corrompida: la clave no es de orden pequeño, así que el sello
    // falla de verdad y el paso 3 rechaza antes de la caché/AES.
    let (mut bloque, mundo) = bloque_firmado(3, 5);
    bloque.cabecera.sello[0] ^= 0x01;
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );

    match estado {
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_)) => {}
        otro => panic!("se esperaba sello inválido, llegó {otro:?}"),
    }
    assert_eq!(presupuesto.intentos, 0, "el sello inválido no gasta AES");
}

#[test]
fn padres_invalidos_no_gastan_presupuesto() {
    let (mut cabecera, justificacion, mundo) = escenario();
    // Bloque no génesis con cero padres: fallo del candidato, antes de tocar PoT o AES.
    cabecera.padres = PadresDag::genesis();
    let bloque = bloque(cabecera, justificacion);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );

    assert_eq!(
        estado,
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Padres(
            ConsensusError::CabeceraPostSinPadres
        ))
    );
    assert_eq!(presupuesto.intentos, 0);
}

#[test]
fn un_padre_desconocido_es_pendiente() {
    let (bloque, mundo) = bloque_firmado(3, 5);
    let mundo = mundo.sin_el_padre_adicional();
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );

    match estado {
        EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::Padres(
            ConsensusError::PadreNoValidado { .. },
        )) => {}
        otro => panic!("se esperaba padre no validado, llegó {otro:?}"),
    }
    assert_eq!(presupuesto.intentos, 0);
}

#[test]
fn reloj_futuro_es_pendiente_y_no_invoca_poas() {
    let (bloque, mundo) = bloque_firmado(3, 5);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    // Reloj anterior al último slot del rango: `C-NET-32`, se retiene.
    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        SLOT_B,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );

    match estado {
        EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::Pot(
            MotivoPotPendiente::RelojFuturo { .. },
        )) => {}
        otro => panic!("se esperaba reloj futuro, llegó {otro:?}"),
    }
    assert_eq!(presupuesto.intentos, 0);
}

#[test]
fn rango_declarado_incorrecto_es_invalida() {
    // El contexto espera 5 y la cabecera declara 4; el sello se rehace para que falle el rango,
    // no el sello.
    let (bloque, mundo) = bloque_firmado(3, 4);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );

    assert_eq!(
        estado,
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Rango(
            ConsensusError::RangoIncorrecto {
                esperado: 5,
                encontrado: 4
            }
        ))
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Un PoT de mock no es admisión
// ─────────────────────────────────────────────────────────────────────────────

/// El núcleo PoT con un contexto inventado devuelve `PotValido`; la puerta conjunta **no** lo
/// admite: interpone el sello real y rechaza la misma cabecera. Es la prueba de que un mock de
/// `InstantaneaPot` no se presenta como admisión del nodo.
#[test]
fn un_pot_valido_de_mock_no_admite_la_cabecera() {
    // Cabecera firmada y luego invalidada en el sello: el núcleo PoT la acepta igual (no mira el
    // sello), pero la puerta conjunta no.
    let (mut bloque, mundo) = bloque_firmado(3, 5);
    bloque.cabecera.sello[0] ^= 0x01;

    let mut cache_nucleo = CachePotVerificada::nueva();
    let mut presupuesto_nucleo = PresupuestoPrueba::nuevo(1_000);
    let nucleo = verificar_rango_pot(
        &bloque.cabecera,
        &bloque.justificacion,
        &mundo,
        RELOJ,
        &mut cache_nucleo,
        &mut presupuesto_nucleo,
    );
    assert!(
        matches!(nucleo, EstadoPot::PotValido(_)),
        "el núcleo PoT con el mock sí produce prueba; llegó {nucleo:?}"
    );

    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);
    let puerta = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );
    match puerta {
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_)) => {}
        otro => panic!("la puerta no debe admitir un PoT de mock; llegó {otro:?}"),
    }
}

/// La reexportación del crate apunta a la misma puerta (no hay dos rutas divergentes).
#[test]
fn la_reexportacion_es_la_misma_funcion() {
    let (bloque, mundo) = bloque_firmado(3, 5);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);
    let estado = puerta_reexportada(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        None,
    );
    assert_eq!(
        estado,
        EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::ContextoPiezaAusente)
    );
}

// Mantiene el tipo de motivo inválido en la firma del módulo aunque alguna prueba no lo nombre.
#[test]
fn el_motivo_invalido_conserva_el_tipo_del_nucleo_pot() {
    let (mut cabecera, justificacion, mundo) = escenario();
    cabecera.pot_output = [0u8; POT_OUTPUT_BYTES];
    let sk = SigningKey::from([7u8; 32]);
    firmar(&mut cabecera, &sk);
    let bloque = bloque(cabecera, justificacion);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    let estado = verificar_cabecera_conjunta(
        &bloque,
        &mundo,
        &mundo,
        &mundo,
        RELOJ,
        &mut cache,
        &mut presupuesto,
        Some(&pieza_dummy()),
    );
    assert!(matches!(
        estado,
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
            MotivoPotInvalido::PotOutputNoCoincide { .. }
        ))
    ));
}
