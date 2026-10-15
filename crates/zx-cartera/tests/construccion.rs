//! V1 de TX-4: construcción y firma de transferencias v1, depósitos v2 y retiros/liberaciones v2
//! contra las primitivas de `zx-core` (forma, sighash, txid, aceptación y verificación ZIP-215).
//!
//! No hay un fichero de vectores externo: la comprobación es que **una firma producida por la
//! cartera verifica por el mismo camino que usa el consenso** (`zx_core::verificar`) y que la
//! transacción serializada vuelve a decodificarse byte a byte.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]

use proptest::prelude::*;
use zx_cartera::{ClaveCartera, Entrada, deposito_v2, liberacion_v2, retiro_v2, transferencia_v1};
use zx_core::amount::Amount;
use zx_core::digest::{Digest, TxId};
use zx_core::tx::{ExtensionTx, Lock, OutPoint, TipoGarantia, TxOut};
use zx_core::{CBID_RED_DEV, validar_forma_tx};

fn outpoint(n: u8) -> OutPoint {
    OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
        prev_index: u32::from(n),
    }
}

fn brek(n: i64) -> Amount {
    Amount::nuevo(n).expect("importe dentro de rango")
}

fn salida_a(valor: i64, clave: &ClaveCartera) -> TxOut {
    TxOut {
        value: brek(valor),
        lock: Lock::PubKey { pubkey: clave.pk },
    }
}

/// Una transferencia v1 firma cada entrada y la firma verifica por el camino de consenso.
#[test]
fn transferencia_v1_firma_y_verifica() {
    let emisor = ClaveCartera::derivar(101, 0);
    let receptor = ClaveCartera::derivar(101, 1);
    let entradas = vec![
        Entrada::p2k(outpoint(1), brek(1_000), emisor.clone()),
        Entrada::p2k(outpoint(2), brek(500), emisor),
    ];
    let salidas = vec![salida_a(1_400, &receptor)];
    let tx = transferencia_v1(&entradas, salidas).expect("v1 construida");

    assert_eq!(tx.testigos.len(), 2, "una firma por entrada");
    assert!(tx.testigos.iter().all(|t| t.len() == 64));
    tx.verificar_entradas(&entradas).expect("firmas válidas");
    validar_forma_tx(&tx.tx, &tx.testigos).expect("forma válida");

    // La tarifa implícita es 1000 + 500 - 1400 = 100.
    let suma_entradas: i64 = entradas.iter().map(|e| e.valor.brek()).sum();
    let suma_salidas: i64 = tx.tx.outputs.iter().map(|s| s.value.brek()).sum();
    assert_eq!(suma_entradas - suma_salidas, 100);
}

/// El txid es determinista y depende de todos los datos de efecto; la firma es determinista.
#[test]
fn el_txid_y_la_firma_son_deterministas() {
    let a = ClaveCartera::derivar(7, 0);
    let b = ClaveCartera::derivar(7, 1);
    let entradas = vec![Entrada::p2k(outpoint(3), brek(10_000), a)];
    let armar = || transferencia_v1(&entradas, vec![salida_a(9_000, &b)]).expect("v1");
    let t1 = armar();
    let t2 = armar();
    assert_eq!(t1.txid(), t2.txid(), "txid determinista");
    assert_eq!(t1.a_hex(), t2.a_hex(), "serialización determinista");
    assert_eq!(
        t1.txid().as_bytes(),
        zx_core::txid(&t1.tx, CBID_RED_DEV).as_bytes()
    );
    assert_eq!(t1.txid(), t1.txid());
}

/// La serialización `tx_a_bytes` se decodifica de vuelta sin perder nada (C-WIRE-03).
#[test]
fn ida_y_vuelta_del_wire() {
    let a = ClaveCartera::derivar(5, 0);
    let b = ClaveCartera::derivar(5, 1);
    let entradas = vec![Entrada::p2k(outpoint(9), brek(777), a.clone())];
    for tx in [
        transferencia_v1(&entradas, vec![salida_a(600, &b)]).expect("v1"),
        deposito_v2(&entradas, vec![], &b, brek(700), 0).expect("depósito"),
        retiro_v2(&b, brek(1), 3).expect("retiro"),
        liberacion_v2(&b, brek(2), 4).expect("liberación"),
    ] {
        let bytes = tx.a_bytes();
        let vuelta = zx_cartera::TxFirmada::desde_bytes(&bytes).expect("decodifica");
        assert_eq!(vuelta.tx, tx.tx, "datos de efecto");
        assert_eq!(vuelta.testigos, tx.testigos, "testigos");
        assert_eq!(vuelta.txid(), tx.txid(), "txid estable");
    }
}

/// Un depósito v2 lleva `n_in + 1` testigos y el último es la aceptación de la clave destino.
#[test]
fn deposito_v2_lleva_aceptacion_del_destino() {
    let emisor = ClaveCartera::derivar(101, 0);
    let destino = ClaveCartera::derivar(101, 3);
    let entradas = vec![Entrada::p2k(outpoint(4), brek(50), emisor)];
    let tx = deposito_v2(&entradas, vec![], &destino, brek(50), 0).expect("depósito");

    assert_eq!(tx.tx.version, 2);
    assert_eq!(tx.testigos.len(), 2);
    match &tx.tx.extension {
        ExtensionTx::Garantia {
            tipo,
            clave,
            importe,
            nonce,
        } => {
            assert_eq!(*tipo, TipoGarantia::Deposito);
            assert_eq!(*clave, destino.pk);
            assert_eq!(importe.brek(), 50);
            assert_eq!(*nonce, 0);
        }
        otra => panic!("extensión inesperada: {otra:?}"),
    }
    tx.verificar_entradas(&entradas)
        .expect("entrada + aceptación");
}

/// El `nonce` entra en el txid del depósito (F-15): dos nonces no son la misma tx.
#[test]
fn el_nonce_cambia_el_txid_del_deposito() {
    let emisor = ClaveCartera::derivar(101, 0);
    let destino = ClaveCartera::derivar(101, 3);
    let entradas = vec![Entrada::p2k(outpoint(4), brek(50), emisor)];
    let a = deposito_v2(&entradas, vec![], &destino, brek(50), 0).expect("depósito 0");
    let b = deposito_v2(&entradas, vec![], &destino, brek(50), 1).expect("depósito 1");
    assert_ne!(a.txid(), b.txid());
}

/// Una retiro v2 no tiene entradas ni salidas y solo lleva la aceptación (F-08).
#[test]
fn retiro_v2_sin_entradas_ni_salidas() {
    let clave = ClaveCartera::derivar(101, 3);
    let tx = retiro_v2(&clave, brek(1), 1).expect("retiro");
    assert!(tx.tx.inputs.is_empty());
    assert!(tx.tx.outputs.is_empty());
    assert_eq!(tx.testigos.len(), 1);
    tx.verificar().expect("forma y aceptación");
}

/// Una firma corrompida no verifica (lo que V3 comprueba contra el nodo real).
#[test]
fn una_firma_corrompida_no_verifica() {
    let emisor = ClaveCartera::derivar(101, 0);
    let destino = ClaveCartera::derivar(101, 3);
    let entradas = vec![Entrada::p2k(outpoint(4), brek(50), emisor)];
    let mut tx = deposito_v2(&entradas, vec![], &destino, brek(50), 0).expect("depósito");
    if let Some(firma) = tx.testigos.first_mut()
        && let Some(b) = firma.first_mut()
    {
        *b ^= 0x01;
    }
    assert!(tx.verificar_entradas(&entradas).is_err());
    assert_eq!(tx.testigos.first().map(Vec::len), Some(64));
}

/// Un byte de más tras la transacción se rechaza (una tx suelta MUST autodelimitarse, TX-R-04).
#[test]
fn se_rechazan_bytes_sobrantes() {
    let clave = ClaveCartera::derivar(1, 0);
    let tx = retiro_v2(&clave, brek(1), 0).expect("retiro");
    let mut bytes = tx.a_bytes();
    bytes.push(0);
    assert!(zx_cartera::TxFirmada::desde_bytes(&bytes).is_err());
}

/// El importe cero se rechaza en la construcción (F-07).
#[test]
fn importe_cero_se_rechaza() {
    let clave = ClaveCartera::derivar(1, 0);
    assert!(retiro_v2(&clave, brek(0), 0).is_err());
}

proptest! {
    /// Para cualquier combinación razonable de semilla, índice y valores, la v1 se firma y verifica.
    #[test]
    fn v1_verifica_para_valores_arbitrarios(
        semilla in any::<u64>(),
        indice in 0u32..64,
        valor in 1i64..1_000_000,
        salida in 0i64..1_000_000,
    ) {
        let emisor = ClaveCartera::derivar(semilla, indice);
        let receptor = ClaveCartera::derivar(semilla, indice.wrapping_add(1));
        let salida = salida.min(valor);
        let entradas = vec![Entrada::p2k(outpoint(1), brek(valor), emisor)];
        let tx = transferencia_v1(&entradas, vec![salida_a(salida, &receptor)]).expect("v1");
        prop_assert!(tx.verificar_entradas(&entradas).is_ok());
    }
}
