//! Regresión RI-3a #1 (`ORDEN-W06d6` decisión 4; `P-ZRX/P-REVISION-CODIGO/REVISION-RI-3a.md`
//! hallazgo 1).
//!
//! **Antes de corregir** (confirmado; el test original de reproducción, ejecutado tal cual contra
//! la base en `deepseek/W06d6/logs/RI-3a-antes.log`, con las mismas aserciones que documentan el
//! hallazgo): pedir el mismo hash repetido hasta `MAX_HASHES_POR_PETICION` (256) veces producía 256
//! clones completos del bloque en `VistaRed::bloques_por_hash` — el recorte a
//! `MAX_BLOQUES_POR_RESPUESTA` (16) ocurría **después**, en `zx-p2p::servicio::servir`, así que 240
//! de esos 256 clones se tiraban sin usarse, dentro del mismo hilo que pollea el `Swarm`.
//!
//! **Después de corregir**: `VistaRed::bloques_por_hash` deduplica y recorta **antes** de clonar
//! nada. El mismo hash repetido 256 veces da como mucho **un** clon.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use std::sync::Arc;
use std::time::Instant;

use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest, MerkleRoot, TxId};
use zx_core::firma::ClavePublica;
use zx_core::preimage::block::BlockHeader;
use zx_core::red::Red;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
use zx_node::red::manejador::ManejadorRed;
use zx_node::red::vista::VistaRed;
use zx_p2p::entrante::ManejadorEntrante;
use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};

/// Registro estructurado de test (`ORDEN-W07a`): `ManejadorRed` lo exige aunque este test no lo use.
fn registro() -> (tempfile::TempDir, Arc<zx_node::registro::Registro>) {
    let dir = tempfile::tempdir().unwrap();
    let r =
        Arc::new(zx_node::registro::Registro::abrir(&dir.path().join("registro.jsonl")).unwrap());
    (dir, r)
}

/// Mempool vacía sobre el estado inicial: este test no admite transacciones.
fn mempool_prueba() -> Arc<std::sync::Mutex<zx_node::mempool::Mempool>> {
    Arc::new(std::sync::Mutex::new(zx_node::mempool::Mempool::nueva(
        zx_node::perfil::parametros_transicion_dev().unwrap(),
        zx_node::perfil::parametros_evidencia_dev(),
        zx_core::CBID_RED_DEV,
        zx_consensus::transicion::Estado::inicial(),
        zx_node::mempool::Politica::dev(),
    )))
}

fn h(n: u32) -> BlockHash {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_digest(Digest::from_bytes(b))
}

fn estado_vacio() -> Estado {
    Estado {
        hash_genesis: h(0),
        red: Red::Dev,
        fase: Fase::Pow,
        punta_pow: PuntaPow {
            hash: h(0),
            altura: 0,
            trabajo_acumulado: [0; 32],
        },
        terminal: None,
        puntas_post: Vec::new(),
        blue_work_virtual: [0; 32],
        longitud_registro: 0,
    }
}

fn tx_simple(n: u32) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: OutPoint {
                prev_txid: TxId::from_digest(Digest::from_bytes([(n % 251) as u8; 32])),
                prev_index: 0,
            },
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::nuevo(1_000).unwrap(),
            lock: Lock::PubKey {
                pubkey: ClavePublica::desde_bytes([(n % 251) as u8; 32]),
            },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

/// Un bloque PoW "grande" (miles de transacciones simples), igual que el test original de
/// reproducción: suficiente para que clonarlo de más sea medible sin llegar al máximo real de 2 MiB.
fn bloque_grande(n_txs: u32) -> BloqueRed {
    let txs: Vec<Tx> = (0..n_txs).map(tx_simple).collect();
    let testigos = vec![vec![vec![0xAAu8; 64]]; n_txs as usize];
    BloqueRed::Pow {
        cabecera: BlockHeader {
            consensus_branch_id: 0xa8b4_66a7,
            prev_hash: h(0),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
            timestamp: 1_000,
            bits: 0x1c07_fff8,
            nonce: 1,
            height: 1,
        },
        txs,
        testigos,
    }
}

/// **Regresión.** `K` repeticiones del mismo hash ya no producen `K` clones: producen **uno**.
#[test]
fn pedir_el_mismo_hash_repetido_no_se_duplica_ni_se_clona_de_mas() {
    const N_TXS: u32 = 4_000;
    const K: usize = zx_p2p::limites::MAX_HASHES_POR_PETICION; // 256: el máximo que permite el códec.

    let bloque = bloque_grande(N_TXS);
    let bytes_bloque = zx_p2p::codec::bloque_a_bytes(&bloque).len();
    println!("RI-3a: bloque de prueba = {bytes_bloque} B ({N_TXS} txs)");

    let vista = Arc::new(VistaRed::nueva(estado_vacio()));
    vista.registrar_pow(0, bloque.clone());
    let hash = zx_node::red::hash_de(&bloque);

    let (tx, _rx) = zx_node::red::nueva_cola_trabajo_red();
    let (_dir, reg) = registro();
    let m = ManejadorRed::nuevo(
        tx,
        Arc::clone(&vista),
        reg,
        mempool_prueba(),
        Arc::new(zx_node::red::registro_direcciones::RegistroRed::nuevo(
            Red::Dev,
            zx_node::red::registro_direcciones::ConfigRegistro::APAGADO,
        )),
    );

    // La misma petición que reproducía el hallazgo: el mismo hash repetido K veces.
    let hashes_repetidos = vec![hash; K];

    let inicio = Instant::now();
    let respuesta = m.bloques_por_hash(&hashes_repetidos);
    let transcurrido = inicio.elapsed();

    assert_eq!(
        respuesta.len(),
        1,
        "las {K} repeticiones del mismo hash deben deduplicarse a un solo bloque, no {K} clones"
    );
    let bytes_totales_clonados: usize = respuesta
        .iter()
        .map(|b| zx_p2p::codec::bloque_a_bytes(b).len())
        .sum();
    println!(
        "RI-3a (corregido): {K} hashes idénticos -> {} clon(es) ({bytes_totales_clonados} B) en \
         {transcurrido:?}: la deduplicación ocurre antes de clonar, no después",
        respuesta.len()
    );

    // Con hashes **distintos**, ninguno repetido, la cota sigue siendo
    // MAX_BLOQUES_POR_RESPUESTA (16): la deduplicación no recorta de más.
    let vista2 = Arc::new(VistaRed::nueva(estado_vacio()));
    let mut hashes_distintos = Vec::new();
    for i in 0..20u32 {
        let b = BloqueRed::Pow {
            cabecera: BlockHeader {
                consensus_branch_id: 0xa8b4_66a7,
                prev_hash: h(i),
                merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x33; 32])),
                timestamp: 1_000 + u64::from(i),
                bits: 0x1c07_fff8,
                nonce: u64::from(i),
                height: i + 1,
            },
            txs: Vec::new(),
            testigos: Vec::new(),
        };
        vista2.registrar_pow(i, b.clone());
        hashes_distintos.push(zx_node::red::hash_de(&b));
    }
    let (tx2, _rx2) = zx_node::red::nueva_cola_trabajo_red();
    let (_dir2, reg2) = registro();
    let m2 = ManejadorRed::nuevo(
        tx2,
        vista2,
        reg2,
        mempool_prueba(),
        Arc::new(zx_node::red::registro_direcciones::RegistroRed::nuevo(
            Red::Dev,
            zx_node::red::registro_direcciones::ConfigRegistro::APAGADO,
        )),
    );
    let respuesta2 = m2.bloques_por_hash(&hashes_distintos);
    assert_eq!(
        respuesta2.len(),
        zx_p2p::limites::MAX_BLOQUES_POR_RESPUESTA,
        "20 hashes distintos, todos presentes: la deduplicación no debe recortar más de lo que \
         ya recortaba MAX_BLOQUES_POR_RESPUESTA (16)"
    );
}
