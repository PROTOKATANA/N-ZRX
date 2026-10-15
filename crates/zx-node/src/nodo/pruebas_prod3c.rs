//! Pruebas de aceptación PROD-3c: el hilo sin clave privada, C09 y C03 (IPA B-06).
//!
//! - **P1**: el hilo real arranca con material **público** (`ClavePublicaConParcela`) y produce
//!   un bloque por el camino de PROD-3b.
//! - **C09**: dos candidatas del mismo billete y slot con `pre_hash` distinto por el camino del
//!   bucle (`procesar_candidata_propia`): la primera se firma; la segunda acaba en
//!   `firmante_abstenido` (conflicto), sin segunda entrada del firmante y el hilo recibe
//!   `Continuar`. La misma candidata tras cerrar y reabrir el registro se reemite.
//! - **C03**: la copia aprobada no se puede cambiar: un byte de un testigo alterado se
//!   recomprueba entero y nunca sale firmado con el `pre_hash` de la primera.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::wildcard_imports,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cloned_instead_of_copied,
    clippy::clone_on_copy,
    clippy::unwrap_used,
    clippy::redundant_clone,
    reason = "aserciones y fixtures internos"
)]

use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use zx_core::PadresDag;
use zx_core::wire_dag::BloqueDag;
use zx_post::firmante::{Firmante, Resultado as ResultadoFirmante};
use zx_post::productor_regimen::CuerpoProductor;

use super::dgcand_tests::{nodo_corte, oportunidad};
use super::firma_contextual::{
    DestinoCandidata, contador_comprobaciones as contador_comprobaciones_local,
    reset_contador_comprobaciones as reset_contador_comprobaciones_local, ultimo_sellado,
};
use super::{MsgBucle, Nodo, abrir_o_crear_parcela};
use crate::perfil;
use crate::regimen::{ClavePublicaConParcela, MsgProductor, hilo_productor_regimen};

fn entradas_firmante(nodo: &Nodo) -> u64 {
    nodo.registro_firmante
        .as_ref()
        .expect("registro de firmante")
        .entradas()
}

/// P1. El hilo real con material **público** (sin `SigningKey`) produce un bloque por el camino
///    de PROD-3b. Es `prod3b_1` con `ClavePublicaConParcela`: el tipo del hilo no tiene clave
///    privada (se comprueba al construirlo, sin `sk`).
#[test]
fn prod3c_1_hilo_sin_clave_privada_produce_bloque() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let servicio = nodo.servicios_verificacion[&terminal].clone();
    let historia = Arc::clone(&nodo.historia);
    let registro_hilo = Arc::clone(&nodo.registro);
    let cbid = nodo.cbid;
    // Material **público** del hilo: índice, clave pública y parcela. Sin clave privada.
    let mut claves_hilo = Vec::new();
    for clave in nodo.claves.clone() {
        let parcela =
            abrir_o_crear_parcela(&nodo.dir_datos, &clave, &nodo.historia).expect("parcela");
        claves_hilo.push(ClavePublicaConParcela {
            indice: clave.indice,
            pk: clave.pk,
            parcela,
        });
    }
    assert!(!claves_hilo.is_empty(), "el corte tiene claves");
    let (tx_hilo, rx_hilo) = mpsc::channel::<MsgBucle>();
    let (tx_prod, rx_prod) = mpsc::channel::<MsgProductor>();
    let hilo = thread::spawn(move || {
        hilo_productor_regimen(
            servicio,
            u64::MAX,
            cbid,
            perfil::subsidio_post(0),
            claves_hilo,
            &historia,
            Some(250),
            &rx_hilo,
            &tx_prod,
            &registro_hilo,
        );
    });

    let mut bloques_admitidos: Vec<zx_core::BlockHash> = Vec::new();
    nodo.producir_bloque_transicion(terminal)
        .expect("transición");
    let transicion = nodo
        .cadena
        .tips_validas()
        .into_iter()
        .next()
        .expect("la transición deja punta");
    bloques_admitidos.push(transicion);
    let inicio = Instant::now();
    while bloques_admitidos.len() < 2 && inicio.elapsed() < Duration::from_secs(180) {
        match rx_prod.recv_timeout(Duration::from_millis(500)) {
            Ok(MsgProductor::Candidata {
                id,
                candidata,
                instante_salida,
                clave_indice,
            }) => {
                assert_eq!(
                    candidata.cabecera.sello, [0; 64],
                    "la candidata del hilo llega sin sello"
                );
                let destino = nodo
                    .procesar_candidata_propia(
                        id,
                        *candidata,
                        instante_salida,
                        clave_indice,
                        terminal,
                        false,
                        &tx_hilo,
                    )
                    .expect("proceso real del bucle");
                if let DestinoCandidata::Admitido { hash } = destino {
                    let sellado = ultimo_sellado().expect("hubo bloque sellado");
                    sellado.cabecera.verificar_sello().expect("sello Ed25519");
                    bloques_admitidos.push(hash);
                }
            }
            Ok(MsgProductor::PeticionPadres { id, slot }) => {
                let _ = nodo.atender_msg_productor(
                    MsgProductor::PeticionPadres { id, slot },
                    false,
                    terminal,
                    &tx_hilo,
                );
            }
            Ok(otro) => {
                let _ = nodo.atender_msg_productor(otro, false, terminal, &tx_hilo);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = tx_hilo.send(MsgBucle::Parar);
    let _ = hilo.join();
    assert!(
        bloques_admitidos.len() >= 2,
        "la transición y al menos un bloque del hilo con material público (total={})",
        bloques_admitidos.len()
    );
}

/// C09. Dos candidatas del **mismo billete y slot** (misma identidad RAT-1) con `pre_hash`
///      distinto por el camino del bucle: la primera se firma; la segunda acaba en
///      `firmante_abstenido` (conflicto), sin segunda entrada del firmante y el hilo recibe
///      `Continuar`. Tras cerrar y reabrir el registro, la misma primera candidata se
///      **reemite** (misma firma, `Resultado::Reemitido`) sin entrada nueva.
#[test]
fn prod3c_c09_dos_peticiones_mismo_billete_conflicto_y_reemision() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 200, &[0, 1, 2, 3]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres de transición");
    // Dos candidatas del mismo billete y slot: misma solución (misma identidad RAT-1),
    // `pre_hash` distinto (timestamp distinto; el reloj está inactivo en `nodo_corte`).
    let a = super::pruebas_prod3b::candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres.clone(),
        slot,
        indice,
        CuerpoProductor::vacio(),
    );
    let mut b = super::pruebas_prod3b::candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres,
        slot,
        indice,
        CuerpoProductor::vacio(),
    );
    b.cabecera.timestamp = a.cabecera.timestamp.wrapping_add(1);
    assert_ne!(
        a.cabecera.pre_hash(),
        b.cabecera.pre_hash(),
        "pre_hash distinto"
    );
    assert_eq!(
        Firmante::identidad(&a.cabecera).huella(),
        Firmante::identidad(&b.cabecera).huella(),
        "misma identidad de oportunidad (RAT-1)"
    );

    let (tx_canal, rx_canal) = mpsc::channel::<MsgBucle>();
    // 1. La primera se firma y se admite.
    let antes = entradas_firmante(&nodo);
    let destino_a = nodo
        .procesar_candidata_propia(
            1,
            a.clone(),
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx_canal,
        )
        .expect("proceso de la primera");
    let DestinoCandidata::Admitido { hash } = destino_a else {
        panic!("la primera debe acabar admitida: {destino_a:?}");
    };
    assert_eq!(
        entradas_firmante(&nodo),
        antes + 1,
        "una entrada nueva del firmante"
    );
    let sellado_a = ultimo_sellado().expect("bloque sellado");
    let sello_a = sellado_a.cabecera.sello;
    assert_ne!(sello_a, [0; 64], "la primera tiene sello real");

    // 2. La segunda, mismo billete y slot y otro pre_hash: conflicto → `firmante_abstenido`,
    //    sin segunda entrada, y el hilo recibe `Continuar`.
    let destino_b = nodo
        .procesar_candidata_propia(
            2,
            b.clone(),
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx_canal,
        )
        .expect("proceso de la segunda");
    assert!(
        matches!(destino_b, DestinoCandidata::FirmanteAbstenido { .. }),
        "la segunda acaba en firmante_abstenido: {destino_b:?}"
    );
    assert_eq!(
        entradas_firmante(&nodo),
        antes + 1,
        "sin segunda entrada del firmante"
    );
    let msg = rx_canal.try_recv().expect("el hilo recibe respuesta");
    assert!(
        matches!(msg, MsgBucle::Continuar { .. }),
        "el hilo recibe Continuar"
    );

    // 3. Tras cerrar y reabrir el registro, la misma primera candidata se reemite
    //    (misma firma, `Resultado::Reemitido`) sin entrada nueva.
    let ruta_registro = dir.path().join("firmante-c09.log");
    {
        let reg = zx_post::firmante::Registro::nueva(&ruta_registro).expect("registro nuevo");
        let f = Firmante::nuevo(&reg);
        let mut prim = a.clone();
        // La primera candidata sin sello: la sella el firmante del registro nuevo.
        let r = f
            .firmar(&mut prim.cabecera, &nodo.claves[indice].sk)
            .expect("firma");
        assert!(matches!(r, ResultadoFirmante::Sellado), "{r:?}");
    }
    // Reabrir el mismo registro (mismo billete y slot ya en él).
    let reg = zx_post::firmante::Registro::abrir(&ruta_registro, slot, 1).expect("reabrir");
    assert_eq!(reg.entradas(), 1, "una sola entrada tras el primer sello");
    let f = Firmante::nuevo(&reg);
    let mut otra_vez = a.clone();
    let r = f
        .firmar(&mut otra_vez.cabecera, &nodo.claves[indice].sk)
        .expect("reemisión");
    assert!(
        matches!(r, ResultadoFirmante::Reemitido),
        "se reemite: {r:?}"
    );
    assert_eq!(
        otra_vez.cabecera.sello, sello_a,
        "la misma firma (mismo pre_hash)"
    );
    assert_eq!(reg.entradas(), 1, "sin entrada nueva");
    // Y la segunda candidata (otro pre_hash, mismo billete) sigue en conflicto.
    let mut conflicto = b.clone();
    let r2 = f
        .firmar(&mut conflicto.cabecera, &nodo.claves[indice].sk)
        .expect("conflicto");
    assert!(
        matches!(r2, ResultadoFirmante::AbstenidoPorConflicto { .. }),
        "misma identidad y otro pre_hash: conflicto {r2:?}"
    );
    assert_eq!(reg.entradas(), 1, "sin entrada nueva por el conflicto");
    assert_eq!(
        conflicto.cabecera.sello, [0; 64],
        "el sello de la conflicto queda intacto"
    );
    let _ = hash;
}

/// C03. La copia aprobada no se puede cambiar: una candidata se firma; se cambia **un byte de un
///      testigo sin cambiar su longitud** y se vuelve a entregar: se recomprueba entera (el
///      contador de pruebas sube) y nunca sale firmada con el `pre_hash` de la primera.
#[test]
fn prod3c_c03_testigo_alterado_nunca_firma_con_el_pre_hash_aprobado() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 200, &[0, 1, 2, 3]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres de transición");
    // Cuerpo con una tx y un testigo de longitud > 0 (aunque la depuración la quite, el testigo
    // existe en la candidata de entrada y es el que se altera en C03).
    let tx = zx_core::Tx {
        version: 1,
        inputs: vec![zx_core::TxIn {
            outpoint: zx_core::OutPoint {
                prev_txid: zx_core::TxId::from_digest(zx_core::digest::Digest::from_bytes([9; 32])),
                prev_index: 0,
            },
            sequence: 0,
        }],
        outputs: vec![zx_core::TxOut {
            value: zx_core::Amount::nuevo(1).expect("importe"),
            lock: zx_core::Lock::PubKey {
                pubkey: nodo.claves[indice].pk,
            },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: zx_core::ExtensionTx::Ninguna,
    };
    let testigo_original: Vec<u8> = vec![0xAA; 32];
    let cuerpo = CuerpoProductor::nuevo(vec![tx], vec![vec![testigo_original.clone()]])
        .expect("cuerpo con testigo");
    let candidata = super::pruebas_prod3b::candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres,
        slot,
        indice,
        cuerpo,
    );
    // La candidata de entrada lleva al menos un testigo de longitud 32.
    let tiene_testigo = candidata
        .testigos()
        .iter()
        .any(|lista| lista.iter().any(|t| t.len() == 32));
    assert!(tiene_testigo, "la candidata de entrada lleva testigos");

    // 1. Primera entrega: se comprueba, se ensaya y se firma (o se descarta por depuración,
    //    pero nunca con sello si no se admitió). Tomamos el pre_hash firmado si lo hay.
    reset_contador_comprobaciones_local();
    let (tx_canal, _rx_canal) = mpsc::channel();
    let destino1 = nodo
        .procesar_candidata_propia(
            1,
            candidata.clone(),
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx_canal,
        )
        .expect("primera entrega");
    let contador_tras_primera = contador_comprobaciones_local();
    assert!(contador_tras_primera >= 1, "la primera entrega se comprobó");
    let pre_hash_firmado_1: Option<zx_core::digest::PreHash> = match &destino1 {
        DestinoCandidata::Admitido { .. } => {
            let s = ultimo_sellado().expect("sellado");
            Some(s.cabecera.pre_hash())
        }
        // Si la primera no llegó a firmarse (depuración/ensayo), el pre_hash «de la primera»
        // es el de la candidata de entrada (sello a cero).
        _ => Some(candidata.cabecera.pre_hash()),
    };
    let pre_hash_1 = pre_hash_firmado_1.expect("pre_hash de la primera");

    // 2. Cambiar **un byte de un testigo sin cambiar su longitud** y volver a entregar.
    //    La cabecera (y por tanto el `pre_hash`) queda como estaba: es la misma copia
    //    aprobada con el cuerpo alterado. La puerta de compromisos tiene que rechazarla
    //    (o, si la rearmara, firmar con un `pre_hash` nuevo —nunca con el de la primera—).
    let mut testigos_alterados = candidata.testigos().to_vec();
    {
        let mut hecho = false;
        for lista in testigos_alterados.iter_mut() {
            for t in lista.iter_mut() {
                if t.len() == 32 && !hecho {
                    t[0] ^= 0xFF; // un byte, misma longitud
                    hecho = true;
                }
            }
        }
        assert!(hecho, "había un testigo de 32 bytes para alterar");
    }
    let alterada = BloqueDag::nuevo(
        candidata.cabecera.clone(),
        candidata.justificacion.clone(),
        candidata.txs().to_vec(),
        testigos_alterados,
    )
    .expect("cuerpo alterado bien formado");
    assert_eq!(
        alterada.cabecera.pre_hash(),
        candidata.cabecera.pre_hash(),
        "misma cabecera ⇒ mismo pre_hash; el cuerpo ya no cuadra con body_commitment"
    );
    assert_ne!(
        alterada.testigos(),
        candidata.testigos(),
        "el testigo cambió de verdad"
    );

    let contador_antes_segunda = contador_comprobaciones_local();
    let destino2 = nodo
        .procesar_candidata_propia(
            2,
            alterada.clone(),
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx_canal,
        )
        .expect("segunda entrega");
    let contador_tras_segunda = contador_comprobaciones_local();
    assert!(
        contador_tras_segunda > contador_antes_segunda,
        "la alterada se recomprueba entera (contador {contador_antes_segunda} → {contador_tras_segunda})"
    );
    // Nunca sale firmada con el pre_hash de la primera.
    match &destino2 {
        DestinoCandidata::Admitido { .. } => {
            let s = ultimo_sellado().expect("sellado de la alterada");
            assert_ne!(
                s.cabecera.pre_hash(),
                pre_hash_1,
                "si se firma, es con su propio pre_hash, no con el de la primera"
            );
        }
        DestinoCandidata::Descartada { .. }
        | DestinoCandidata::FirmanteAbstenido { .. }
        | DestinoCandidata::Eclipse
        | DestinoCandidata::Atrasada
        | DestinoCandidata::Parar => {
            // Rechazo legítimo: no se firmó en absoluto.
        }
    }
}
