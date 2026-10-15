//! EV-1: las retiradas son resultados comprometidos, el rollback no las inventa.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "pruebas de operaciones reales de cola"
)]
use super::*;
use crate::votos::{b88 as f, tx_evidencia_votos_peso};
use zx_consensus::transicion::{EntradaUtxo, Origen};
use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};

fn cola() -> (Mempool, TxId, Estado) {
    let sk = f::bls();
    let c = f::cadena(&sk);
    let base = c.estado_virtual().expect("base");
    let mut detector = f::detector();
    let e = f::fabricar(&mut detector, &sk, &c);
    let (pk, ed) = f::reportero();
    let (tx, t) = tx_evidencia_votos_peso(&e, pk, &ed, zx_core::CBID_RED_DEV);
    let id = txid(&tx, zx_core::CBID_RED_DEV);
    let (a, b) = f::votos_tx(&tx);
    let hecho = c.hecho_voto_entre_ventanas(
        &a,
        &b,
        u64::try_from(base.parametros_sector.plazo_slots).expect("plazo"),
    );
    let mut m = Mempool::nueva(
        f::params(),
        ParametrosEvidencia::inactiva(),
        zx_core::CBID_RED_DEV,
        base.clone(),
        Politica::dev(),
    );
    let (r, _) = m.admitir_evidencia(tx, t, hecho, Instant::now(), Punto::Slot(base.slot));
    assert!(matches!(r, AdmisionEvidencia::Admitida(_)));
    (m, id, base)
}

#[test]
fn ev1_ttl_y_expulsion_informan_una_vez() {
    let (mut m, _, base) = cola();
    m.expirar(Punto::Slot(base.slot + m.politica.ttl_puntos + 1));
    assert_eq!(m.estadisticas().n, 0);
    let r = m.tomar_retiradas_evidencia();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].motivo, Rechazo::Limite("caducidad"));
    assert!(m.tomar_retiradas_evidencia().is_empty());
    let (mut m, id, _) = cola();
    assert_eq!(m.expulsar(&[id]), 1);
    assert_eq!(
        m.tomar_retiradas_evidencia()[0].motivo,
        Rechazo::VistaLocal("expulsion")
    );
}

#[test]
fn ev1_desalojo_revertido_no_notifica_y_comprometido_si() {
    let (mut m, id, mut base) = cola();
    let (pk, sk) = f::reportero();
    let op = OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([0x41; 32])),
        prev_index: 0,
    };
    let valor = Amount::nuevo(10_000).expect("valor");
    base.utxo.insert(
        op,
        EntradaUtxo {
            valor,
            lock: Lock::PubKey { pubkey: pk },
            origen: Origen::Tx,
            creada: Punto::Slot(0),
        },
    );
    let hechos = m.hechos_votos.clone();
    let punto = Punto::Slot(base.slot);
    assert!(
        m.rebasear_con_hechos(base, hechos, Instant::now(), punto)
            .is_empty()
    );
    m.politica.s = m.bytes_totales; // Un pago fuerza el plan real de desalojo de tarifa cero.
    let tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: op,
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::nuevo(9_000).expect("salida"),
            lock: Lock::PubKey { pubkey: pk },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let antes = m.estadisticas();
    let rechazo = m.admitir(None, tx.clone(), vec![vec![0; 64]], Instant::now(), punto);
    assert_eq!(rechazo, Err(Rechazo::Limite("global")));
    assert_eq!(
        m.estadisticas(),
        antes,
        "rollback conserva bytes, vista y propietario"
    );
    assert!(m.contiene(&id));
    assert!(
        m.tomar_retiradas_evidencia().is_empty(),
        "no hay retirada del plan fallido"
    );
    let sighash = zx_core::sighash(
        &tx,
        &[SpentOutput {
            value: valor,
            lock: Lock::PubKey { pubkey: pk },
        }],
        HashType::All,
        0,
        zx_core::CBID_RED_DEV,
    )
    .expect("sighash");
    let firma: [u8; 64] = sk.sign(sighash.as_bytes()).into();
    assert_eq!(
        m.admitir(None, tx, vec![firma.to_vec()], Instant::now(), punto),
        Err(Rechazo::Limite("global"))
    );
    assert!(m.contiene(&id));
    let r = m.tomar_retiradas_evidencia();
    assert!(r.is_empty());
    assert_eq!(m.tomar_protecciones_evidencia(), vec![id]);
}

#[test]
#[should_panic(expected = "control rojo: un pago no dispone de la evidencia como victima")]
fn ev1_desalojo_revertido_no_notifica_y_comprometido_si_control_rojo() {
    let (mut m, id, mut base) = cola();
    let (pk, sk) = f::reportero();
    let op = OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([0x41; 32])),
        prev_index: 0,
    };
    let valor = Amount::nuevo(10_000).expect("valor");
    base.utxo.insert(
        op,
        EntradaUtxo {
            valor,
            lock: Lock::PubKey { pubkey: pk },
            origen: Origen::Tx,
            creada: Punto::Slot(0),
        },
    );
    let hechos = m.hechos_votos.clone();
    let punto = Punto::Slot(base.slot);
    assert!(
        m.rebasear_con_hechos(base, hechos, Instant::now(), punto)
            .is_empty()
    );
    m.politica.s = m.bytes_totales; // Un pago fuerza el plan real de desalojo de tarifa cero.
    let tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: op,
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::nuevo(9_000).expect("salida"),
            lock: Lock::PubKey { pubkey: pk },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let antes = m.estadisticas();
    let rechazo = m.admitir(None, tx.clone(), vec![vec![0; 64]], Instant::now(), punto);
    assert_eq!(
        rechazo,
        Err(Rechazo::Demostrable("invalida")),
        "control rojo: un pago no dispone de la evidencia como victima"
    );
    assert_eq!(
        m.estadisticas(),
        antes,
        "rollback conserva bytes, vista y propietario"
    );
    assert!(m.contiene(&id));
    assert!(
        m.tomar_retiradas_evidencia().is_empty(),
        "no hay retirada del plan fallido"
    );
    let sighash = zx_core::sighash(
        &tx,
        &[SpentOutput {
            value: valor,
            lock: Lock::PubKey { pubkey: pk },
        }],
        HashType::All,
        0,
        zx_core::CBID_RED_DEV,
    )
    .expect("sighash");
    let firma: [u8; 64] = sk.sign(sighash.as_bytes()).into();
    assert_eq!(
        m.admitir(None, tx, vec![firma.to_vec()], Instant::now(), punto),
        Ok(Admision::Admitida)
    );
    assert!(!m.contiene(&id));
    let r = m.tomar_retiradas_evidencia();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].motivo, Rechazo::Limite("desalojo"));
}
