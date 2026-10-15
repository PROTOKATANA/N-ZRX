//! EV-2: firmas, cola y cadena reales; cabeceras prevalidadas del fixture B88-C.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "aserciones de integración"
)]
use super::*;
use crate::claves::ClaveDev;
use crate::votos::{b88 as f, tx_evidencia_votos_peso};
use zx_consensus::transicion::{EntradaUtxo, Origen};
use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};

fn evidencia() -> (Mempool, TxConTestigos, HechoVoto, Estado) {
    let sk = f::bls();
    let c = f::cadena(&sk);
    let base = c.estado_virtual().expect("base real");
    let e = f::fabricar(&mut f::detector(), &sk, &c);
    let (pk, ed) = f::reportero();
    let sobre = tx_evidencia_votos_peso(&e, pk, &ed, zx_core::CBID_RED_DEV);
    let (a, b) = f::votos_tx(&sobre.0);
    let hecho = c
        .hecho_voto_entre_ventanas(
            &a,
            &b,
            u64::try_from(base.parametros_sector.plazo_slots).expect("plazo"),
        )
        .expect("hecho calculado por Cadena");
    let m = Mempool::nueva(
        f::params(),
        ParametrosEvidencia::inactiva(),
        zx_core::CBID_RED_DEV,
        base.clone(),
        Politica::dev(),
    );
    (m, sobre, hecho, base)
}

fn financiar(m: &mut Mempool, mut base: Estado) -> (ClaveDev, OutPoint) {
    let (pk, sk) = f::reportero();
    let clave = ClaveDev { indice: 0, pk, sk };
    let op = OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([0x41; 32])),
        prev_index: 0,
    };
    base.utxo.insert(
        op,
        EntradaUtxo {
            valor: Amount::nuevo(100_000).expect("fondo"),
            lock: Lock::PubKey { pubkey: pk },
            origen: Origen::Tx,
            creada: Punto::Slot(0),
        },
    );
    let punto = Punto::Slot(base.slot);
    m.rebasear(base, Instant::now(), punto);
    (clave, op)
}

fn pago(clave: &ClaveDev, op: OutPoint, salidas: usize) -> TxConTestigos {
    let tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: op,
            sequence: 0,
        }],
        outputs: (0..salidas)
            .map(|_| TxOut {
                value: Amount::nuevo(100).expect("salida"),
                lock: Lock::PubKey { pubkey: clave.pk },
            })
            .collect(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let digest = zx_core::sighash(
        &tx,
        &[SpentOutput {
            value: Amount::nuevo(100_000).expect("fondo"),
            lock: Lock::PubKey { pubkey: clave.pk },
        }],
        HashType::All,
        0,
        zx_core::CBID_RED_DEV,
    )
    .expect("sighash");
    let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
    (tx, vec![firma.to_vec()])
}

#[test]
fn ev2_cuota_reportero_agotada_no_impide_evidencia() {
    let (mut m, (tx, t), h, base) = evidencia();
    let punto = Punto::Slot(base.slot);
    let (clave, op) = financiar(&mut m, base);
    let (d, w) = crate::pow::construir_deposito(
        op.prev_txid,
        Amount::nuevo(100_000).expect("importe"),
        &clave,
        0,
        zx_core::CBID_RED_DEV,
    )
    .expect("depósito");
    let anterior = txid(&d, zx_core::CBID_RED_DEV);
    assert_eq!(
        m.admitir(None, d, w, Instant::now(), punto),
        Ok(Admision::Admitida)
    );
    assert_eq!(m.por_clave.get(&clave.pk), Some(&anterior));
    let (r, _) = m.admitir_evidencia(tx, t, Some(h), Instant::now(), punto);
    assert!(
        matches!(r, AdmisionEvidencia::Admitida(_)),
        "evidencia con cuota agotada: {r:?}"
    );
    assert_eq!(m.por_clave.get(&clave.pk), Some(&anterior));
    assert_eq!(m.estadisticas().n, 2);
}

#[test]
fn ev2_evidencia_entra_en_cola_llena_de_pagos_y_no_es_desalojable() {
    let (mut m, sobre, h, base) = evidencia();
    let punto = Punto::Slot(base.slot);
    let (clave, op) = financiar(&mut m, base);
    let p = pago(&clave, op, 64);
    let ip = txid(&p.0, zx_core::CBID_RED_DEV);
    let ie = txid(&sobre.0, zx_core::CBID_RED_DEV);
    assert_eq!(
        m.admitir(None, p.0.clone(), p.1.clone(), Instant::now(), punto),
        Ok(Admision::Admitida)
    );
    m.politica.s = m.bytes_totales;
    let (r, _) = m.admitir_evidencia(sobre.0, sobre.1, Some(h), Instant::now(), punto);
    assert!(
        matches!(r, AdmisionEvidencia::Admitida(_)),
        "admisión bajo presión: {r:?}"
    );
    assert!(!m.entradas.contains_key(&ip));
    assert!(m.entradas.contains_key(&ie));
    assert!(m.bytes_totales <= m.politica.s);
    m.politica.s = m.bytes_totales;
    let presion = pago(&clave, op, 1);
    let mut bytes = Vec::new();
    zx_core::wire::tx_a_bytes(&mut bytes, &presion.0, &presion.1);
    assert!(bytes.len() <= m.politica.s);
    assert_eq!(
        m.admitir(None, presion.0, presion.1, Instant::now(), punto),
        Err(Rechazo::Limite("global"))
    );
    assert!(m.entradas.contains_key(&ie));
    assert_eq!(m.tomar_protecciones_evidencia(), vec![ie]);
    assert!(m.tomar_retiradas_evidencia().is_empty());
}

#[test]
fn ev2_cola_llena_evidencias_rechaza_con_causa() {
    let (_, (tx, t), h, mut base) = evidencia();
    let punto = Punto::Slot(base.slot);
    // Dos acusados registrados: ambos sobres validan por separado contra esta misma base.
    let sk2 = zx_votos::ClaveSecreta::generar(&[0x42; 32]).expect("segunda clave");
    let c = f::cadena(&sk2);
    let e = f::fabricar(&mut f::detector(), &sk2, &c);
    let (pk, ed) = f::reportero();
    let (tx2, t2) = tx_evidencia_votos_peso(&e, pk, &ed, zx_core::CBID_RED_DEV);
    let acusado2 = zx_core::ClavePublica::desde_bytes([2; 32]);
    let mut voto = base.claves_voto[&f::acusado()];
    voto.clave_bls = sk2.clave_publica().bytes();
    base.claves_voto.insert(acusado2, voto);
    base.garantias
        .insert(acusado2, base.garantias[&f::acusado()].clone());
    let mut sector = *base
        .sectores
        .values()
        .next()
        .expect("sector del primer acusado");
    sector.id.clave = acusado2;
    base.sectores.insert(sector.id, sector);
    let nueva = || {
        Mempool::nueva(
            f::params(),
            ParametrosEvidencia::inactiva(),
            zx_core::CBID_RED_DEV,
            base.clone(),
            Politica::dev(),
        )
    };
    let mut control = nueva();
    let (r, _) = control.admitir_evidencia(tx2.clone(), t2.clone(), Some(h), Instant::now(), punto);
    assert!(
        matches!(r, AdmisionEvidencia::Admitida(_)),
        "segunda evidencia válida sin presión: {r:?}"
    );
    let mut m = nueva();
    let (r, _) = m.admitir_evidencia(tx, t, Some(h), Instant::now(), punto);
    assert!(matches!(r, AdmisionEvidencia::Admitida(_)));
    m.politica.s = m.bytes_totales;
    let (r, _) = m.admitir_evidencia(tx2, t2, Some(h), Instant::now(), punto);
    assert_eq!(
        r,
        AdmisionEvidencia::Rechazada(Rechazo::Limite("global_evidencias"))
    );
    assert_eq!(m.estadisticas().n, 1);
    assert_eq!(m.rechazos_limite.global, 1);
}

#[test]
fn ev2_evidencia_invalida_no_desaloja_pago_y_no_elude_validacion() {
    let (mut m, mut sobre, h, base) = evidencia();
    let punto = Punto::Slot(base.slot);
    let (clave, op) = financiar(&mut m, base);
    let p = pago(&clave, op, 64);
    let id = txid(&p.0, zx_core::CBID_RED_DEV);
    assert_eq!(
        m.admitir(None, p.0, p.1, Instant::now(), punto),
        Ok(Admision::Admitida)
    );
    m.politica.s = m.bytes_totales;
    let antes = m.estadisticas();
    sobre.1[0][0] ^= 1;
    let (r, _) = m.admitir_evidencia(sobre.0, sobre.1, Some(h), Instant::now(), punto);
    assert!(matches!(r, AdmisionEvidencia::Rechazada(_)));
    assert_eq!(m.estadisticas(), antes);
    assert!(m.entradas.contains_key(&id));
    assert!(m.tomar_retiradas_evidencia().is_empty());
}
