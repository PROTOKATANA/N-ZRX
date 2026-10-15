//! **V6 · casos nuevos de D-P08** contra un almacén con raíz en el terminal `T`.
//!
//! Cada caso nombra su resultado: `0` padres; transición con dos padres; `T` como padre adicional;
//! padre PoW ajeno; y transición válida con `T` como único padre. Se usan el `AlmacenGhostdag` real
//! (raíz `T`, D-P07) y `comprobar_padres_contextual`, no un contexto de conveniencia.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]

use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_dag::bloque_dag::comprobar_padres_contextual;
use zx_dag::ghostdag::{Algoritmo, AlmacenGhostdag, BloqueGhostdag, IdentidadGhostdag, Parametros};
use zx_dag::{ErrorDag, RangoSolucionValidado};

fn h(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn cabecera(padres: PadresDag, slot: u64) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: 0xc478_80ea,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
        timestamp: 1_788_480_000 + slot,
        height: u32::try_from(slot).unwrap_or(0),
        slot,
        pot_output: [0x11; 16],
        rango_solucion: 42,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x33; 32])),
        padres,
        sello: [0u8; 64],
    }
}

/// Almacén con raíz en el terminal `T` y un PoST validado `P` hijo único de `T`.
fn almacen_con_terminal_y_post() -> (AlmacenGhostdag, BlockHash, BlockHash) {
    let terminal = h(0x01);
    let mut almacen = AlmacenGhostdag::con_raiz_terminal(
        Parametros::default(),
        Algoritmo::Kernel,
        terminal,
        RangoSolucionValidado::para_oraculos(0),
    );
    let post = h(0x02);
    almacen
        .anadir_sintetico(BloqueGhostdag {
            id: post,
            padres: vec![terminal],
            slot: 1,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(5),
            identidad: IdentidadGhostdag::SinBillete,
        })
        .unwrap();
    (almacen, terminal, post)
}

#[test]
fn v6_cero_padres_se_rechaza() {
    let (almacen, _terminal, _post) = almacen_con_terminal_y_post();
    let c = cabecera(PadresDag::genesis(), 2);
    assert_eq!(
        comprobar_padres_contextual(&c, &almacen),
        Err(ErrorDag::CabeceraPostSinPadres)
    );
}

#[test]
fn v6_transicion_con_dos_padres_se_rechaza() {
    let (almacen, terminal, post) = almacen_con_terminal_y_post();
    // Seleccionado = T (transición) pero con el PoST P como padre adicional.
    let c = cabecera(PadresDag::nuevo(terminal, &[post]).unwrap(), 2);
    assert_eq!(
        comprobar_padres_contextual(&c, &almacen),
        Err(ErrorDag::TerminalConPadresExtra { declarados: 2 })
    );
}

#[test]
fn v6_terminal_como_padre_extra_se_rechaza() {
    let (almacen, terminal, post) = almacen_con_terminal_y_post();
    // Seleccionado = P (PoST validado), T como adicional.
    let c = cabecera(PadresDag::nuevo(post, &[terminal]).unwrap(), 2);
    assert_eq!(
        comprobar_padres_contextual(&c, &almacen),
        Err(ErrorDag::TerminalComoPadreExtra { terminal })
    );
}

#[test]
fn v6_padre_pow_ajeno_se_rechaza() {
    let (almacen, _terminal, _post) = almacen_con_terminal_y_post();
    let ajeno = h(0xAA);
    let c = cabecera(PadresDag::nuevo(ajeno, &[]).unwrap(), 2);
    assert_eq!(
        comprobar_padres_contextual(&c, &almacen),
        Err(ErrorDag::PadreNoValidado { padre: ajeno })
    );
}

#[test]
fn v6_transicion_valida_con_el_terminal_como_unico_padre_pasa() {
    let (almacen, terminal, _post) = almacen_con_terminal_y_post();
    let c = cabecera(PadresDag::nuevo(terminal, &[]).unwrap(), 1);
    assert!(comprobar_padres_contextual(&c, &almacen).is_ok());
}

#[test]
fn v6_descendiente_post_valido_pasa() {
    let (almacen, _terminal, post) = almacen_con_terminal_y_post();
    let c = cabecera(PadresDag::nuevo(post, &[]).unwrap(), 2);
    assert!(comprobar_padres_contextual(&c, &almacen).is_ok());
}
