//! Regresión RI-3a #3 (`ORDEN-W06d6` decisión 4; `P-ZRX/P-REVISION-CODIGO/REVISION-RI-3a.md`
//! hallazgo 3).
//!
//! **Antes de corregir** (confirmado; el test original de reproducción, ejecutado tal cual contra
//! la base en `deepseek/W06d6/logs/RI-3a-antes.log`): `TrabajoRed` viajaba por un
//! `unbounded_channel`, así que 40 960 bloques (`MAX_DIFERIDOS_PENDIENTES × 10`) se encolaban sin
//! que nada los rechazara, aunque nadie leyera del otro extremo.
//!
//! **Después de corregir**: `red::nueva_cola_trabajo_red` da un emisor acotado en elementos
//! (`MAX_TRABAJO_RED = 1 024`) y en bytes (`MAX_TRABAJO_RED_BYTES = 256 MiB`). Pasado el tope, se
//! descarta lo nuevo **sin bloquear** (`intentar_enviar` nunca espera) y se informa con
//! `ResultadoEnvioTrabajo::Lleno`, nunca en silencio.

#![expect(clippy::panic, reason = "el test falla con panic por diseño")]

use zx_core::digest::{BlockHash, Digest, MerkleRoot};
use zx_core::preimage::block::BlockHeader;
use zx_node::red::{MAX_TRABAJO_RED, ResultadoEnvioTrabajo, TrabajoRed};

fn h(n: u32) -> BlockHash {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_digest(Digest::from_bytes(b))
}

fn bloque(n: u32) -> zx_p2p::mensaje::BloqueRed {
    zx_p2p::mensaje::BloqueRed::Pow {
        cabecera: BlockHeader {
            consensus_branch_id: 0xa8b4_66a7,
            prev_hash: h(n),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x11; 32])),
            timestamp: 1_000 + u64::from(n),
            bits: 0x1c07_fff8,
            nonce: u64::from(n),
            height: n,
        },
        txs: Vec::new(),
        testigos: Vec::new(),
    }
}

/// **Regresión.** Encolar muchos más elementos que `MAX_TRABAJO_RED` ya no crece sin límite: a
/// partir del tope, `intentar_enviar` devuelve `Lleno` (nunca bloquea, nunca entra en pánico) y el
/// bloque se descarta en vez de acumularse.
#[test]
fn la_cola_de_trabajo_hacia_consenso_tiene_tope_de_elementos() {
    let (tx, mut rx) = zx_node::red::nueva_cola_trabajo_red();

    // Un orden de magnitud por encima del tope, igual que el test original comparaba contra
    // `MAX_DIFERIDOS_PENDIENTES` de `zx-p2p`.
    let n: u32 = (MAX_TRABAJO_RED as u32) * 10;
    assert!(n > 10_000);

    let mut encolados = 0usize;
    let mut llenos = 0usize;
    for i in 0..n {
        match tx.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
            de: libp2p::PeerId::random(),
            bloque: bloque(i),
            llegada: std::time::Instant::now(),
        }) {
            ResultadoEnvioTrabajo::Encolado => encolados += 1,
            ResultadoEnvioTrabajo::Lleno(_) => llenos += 1,
            ResultadoEnvioTrabajo::Cerrado(_) => panic!("el receptor sigue vivo: no debe cerrarse"),
        }
    }

    assert_eq!(
        encolados, MAX_TRABAJO_RED,
        "el tope de elementos MUST ser exactamente MAX_TRABAJO_RED, ni uno más"
    );
    assert_eq!(
        llenos,
        n as usize - MAX_TRABAJO_RED,
        "todo lo que no cupo MUST informarse como Lleno, no perderse en silencio"
    );
    let mut recibidos = 0usize;
    while rx.try_recv().is_ok() {
        recibidos += 1;
    }
    assert_eq!(
        recibidos, MAX_TRABAJO_RED,
        "el receptor no había leído nada todavía: debe tener exactamente el tope de elementos"
    );

    eprintln!(
        "RI-3a (corregido): {n} intentos -> {encolados} encolados, {llenos} descartados por \
         tope de elementos (MAX_TRABAJO_RED = {MAX_TRABAJO_RED}); antes se habrían encolado los \
         {n} sin tope alguno"
    );
}
