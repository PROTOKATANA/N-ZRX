//! Decodificación y verificación de la justificación PoT del wire (`C-HDR-07`, `C-POT-08`).
//!
//! Sustituye el `IntegracionPotPendiente` perpetuo del código antiguo: con el contexto de
//! transición dev, un portador honesto verifica y un portador ajeno se rechaza.

#![expect(
    clippy::expect_used,
    reason = "instrumento de test: un fallo del fixture debe producir panic"
)]

use core::num::NonZeroU32;

use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
use zx_core::wire_dag::{BUNDLE_BYTES, JustificacionPot, PotCheckpoints};
use zx_core::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_post::contexto_transicion::ContextoTransicion;
use zx_post::justificacion::{
    ErrorJustificacion, MotivoJustificacion, leer_justificacion, verificar_justificacion_pot,
};
use zx_post::pot::{checkpoints_a_wire, semilla_genesis, semilla_siguiente};
use zx_post::pot_rango::{CachePotVerificada, MotivoPotInvalido, PresupuestoPot};
use zx_pot::tipos::PotSeed;

const N: u64 = 16;
const T: [u8; 32] = [0x42; 32];

fn terminal() -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes(T))
}

fn contexto() -> ContextoTransicion {
    ContextoTransicion::nuevo(terminal(), N, 7, Vec::new()).expect("contexto dev")
}

fn cabecera(slot: u64, pot_output: [u8; 16]) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: 0xc478_80ea,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
        timestamp: 1_788_480_000,
        height: 0,
        slot,
        pot_output,
        rango_solucion: 7,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
        padres: PadresDag::nuevo(terminal(), &[]).expect("un padre"),
        sello: [0u8; 64],
    }
}

/// Portador honesto del slot 1 y el `pot_output` que ancla el rango.
fn portador_slot_uno() -> (PotCheckpoints, [u8; 16]) {
    let s1 = semilla_genesis(&terminal(), &[]);
    let semilla = semilla_siguiente(s1, None);
    let carrier = zx_pot::prove(
        PotSeed::from(semilla),
        NonZeroU32::new(u32::try_from(N).expect("N cabe")).expect("N > 0"),
    )
    .expect("N múltiplo de 16");
    (checkpoints_a_wire(&carrier), *carrier.output())
}

struct PresupuestoIlimitado;

impl PresupuestoPot for PresupuestoIlimitado {
    fn consumir_slot(&mut self, _slot: u64) -> bool {
        true
    }
}

#[test]
fn el_portador_honesto_verifica_con_el_contexto_dev() {
    let (portador, salida) = portador_slot_uno();
    let justificacion = JustificacionPot::nueva(vec![portador]).expect("un portador");
    let cabecera = cabecera(1, salida);
    let ctx = contexto();
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoIlimitado;

    assert_eq!(
        verificar_justificacion_pot(
            &cabecera,
            &justificacion,
            &ctx,
            u64::MAX,
            &mut cache,
            &mut presupuesto,
        ),
        Ok(()),
        "un portador honesto no puede quedar en IntegracionPotPendiente"
    );
}

#[test]
fn un_portador_ajeno_es_invalido() {
    let (_, salida) = portador_slot_uno();
    let ajeno = zx_pot::prove(
        PotSeed::from([0x77u8; 16]),
        NonZeroU32::new(u32::try_from(N).expect("N cabe")).expect("N > 0"),
    )
    .expect("N múltiplo de 16");
    let justificacion =
        JustificacionPot::nueva(vec![checkpoints_a_wire(&ajeno)]).expect("un portador");
    let cabecera = cabecera(1, salida);
    let ctx = contexto();
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoIlimitado;

    assert_eq!(
        verificar_justificacion_pot(
            &cabecera,
            &justificacion,
            &ctx,
            u64::MAX,
            &mut cache,
            &mut presupuesto,
        ),
        Err(MotivoJustificacion::Invalida(
            MotivoPotInvalido::AesFallido { slot: 1 }
        ))
    );
}

#[test]
fn leer_justificacion_hace_ida_y_vuelta_y_acota() {
    let (portador, _) = portador_slot_uno();
    let justificacion = JustificacionPot::nueva(vec![portador]).expect("un portador");
    let mut bytes = Vec::new();
    justificacion.escribir(&mut bytes);
    bytes.extend_from_slice(b"cola");

    let (leida, resto) = leer_justificacion(&bytes).expect("decodifica");
    assert_eq!(leida, justificacion);
    assert_eq!(resto, b"cola");

    assert_eq!(leer_justificacion(&[]), Err(ErrorJustificacion::Truncado));
    assert_eq!(
        leer_justificacion(&[151]),
        Err(ErrorJustificacion::DemasiadosPortadores {
            declarados: 151,
            maximo: 150
        })
    );

    // Contador que declara un portador pero sin los 128 B: truncado, sin pánico.
    assert_eq!(
        leer_justificacion(&[1, 0, 0]),
        Err(ErrorJustificacion::Truncado)
    );
    assert_eq!(BUNDLE_BYTES, 128);
}
