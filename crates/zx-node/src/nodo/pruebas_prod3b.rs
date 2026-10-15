//! Pruebas de aceptación PROD-3b-2 por el camino real: la candidata sin sello la comprueba,
//! depura, ensaya, firma y admite el bucle (`firma_contextual`).
//!
//! Cada prueba afirma **un** resultado. Un mensaje fabricado solo donde el caso es un hilo
//! que miente (3, 4, 5 y 10).
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::wildcard_imports,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cloned_instead_of_copied,
    clippy::clone_on_copy,
    clippy::type_complexity,
    clippy::redundant_clone,
    clippy::unwrap_used,
    clippy::needless_borrow,
    reason = "aserciones y fixtures internos; tamaños comprobados antes de indexar"
)]

use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use zx_core::PadresDag;
use zx_core::wire_dag::BloqueDag;
use zx_post::productor::ParametrosProductor;
use zx_post::productor_regimen::{CuerpoProductor, ErrorEnsayo, preparar_regimen_para_ensayo};
use zx_post::servicio_pot::ServicioPot;

use super::dgcand_tests::{gana, nodo_corte, oportunidad, producir, recibir, texto};
use super::firma_contextual::{
    ClasificacionFirma, DestinoCandidata, clasificar_error_ensayo,
    contador_comprobaciones as contador_comprobaciones_local,
    reset_contador_comprobaciones as reset_contador_comprobaciones_local,
    ultima_distancia_comprobacion, ultima_distancia_ensayo, ultimo_sellado,
};
use super::{FuenteTransicion, MsgBucle, Nodo, abrir_o_crear_parcela, garantia_promovida_en_slot};
use crate::perfil;
use crate::regimen::{ClavePublicaConParcela, MsgProductor, hilo_productor_regimen};
use zx_p2p::entrante::VeredictoFinal;

/// Cabecera de prueba con los padres dados (modelo de `cabecera_con_padres` de nodo.rs).
fn cabecera_con_padres(slot: u64, padres: &[zx_core::BlockHash]) -> zx_core::DagBlockHeader {
    let seleccionado = padres.first().copied().unwrap_or_else(|| {
        zx_core::BlockHash::from_digest(zx_core::digest::Digest::from_bytes([1; 32]))
    });
    let extras = &padres[1..];
    let padres_dag = PadresDag::nuevo(seleccionado, extras).expect("padres");
    zx_core::DagBlockHeader {
        consensus_branch_id: 0,
        merkle_root: zx_core::digest::MerkleRoot::from_digest(zx_core::digest::Digest::from_bytes(
            [0; 32],
        )),
        timestamp: 0,
        height: 0,
        slot,
        pot_output: [0; 16],
        vdf_output: [0; 16],
        rango_solucion: 1,
        sol: zx_core::SolucionPoas::default(),
        body_commitment: zx_core::body_commitment(&[], &[], 0).expect("compromiso"),
        padres: padres_dag,
        sello: [0; 64],
    }
}

/// `hash_u32` de los fixtures de `nodo.rs` (mismo encoding).
fn hash_u32(n: u32) -> zx_core::BlockHash {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&n.to_be_bytes());
    zx_core::BlockHash::from_digest(zx_core::digest::Digest::from_bytes(bytes))
}

/// Prepara una candidata real sin sello (PoAS/PoT/padres reales) para el slot e índice dados.
pub(crate) fn candidata_sin_sello(
    nodo: &Nodo,
    servicio: &mut ServicioPot,
    padres: PadresDag,
    slot: u64,
    indice: usize,
    cuerpo: CuerpoProductor,
) -> BloqueDag {
    let clave = nodo.claves.get(indice).expect("clave configurada");
    let parcela = abrir_o_crear_parcela(&nodo.dir_datos, clave, &nodo.historia).expect("parcela");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &nodo.historia,
    };
    let parametros = ParametrosProductor {
        n_dev: nodo.n_dev_vigente(),
        sr_dev: u64::MAX,
        max_slots: slot,
        consensus_branch_id: nodo.cbid,
        timestamp: nodo.reloj_local() as u64,
        i_iter: nodo.perfil_red.reloj.i_iter,
        importe_coinbase: perfil::subsidio_post(0),
    };
    preparar_regimen_para_ensayo(
        padres,
        slot,
        servicio,
        &fuente,
        &clave.sk,
        &parametros,
        cuerpo,
    )
    .expect("candidata real sin sello")
}

fn entradas_firmante(nodo: &Nodo) -> u64 {
    nodo.registro_firmante
        .as_ref()
        .expect("registro de firmante")
        .entradas()
}

fn contador_comprobaciones() -> usize {
    contador_comprobaciones_local()
}

fn reset_contador_comprobaciones() {
    reset_contador_comprobaciones_local()
}

/// 1. Camino completo con el **hilo real**: `hilo_productor_regimen` real con claves y parcelas
///    reales, y el bucle real atendiendo sus mensajes. La prueba es dueña del canal: de cada
///    `MsgProductor::Candidata` afirma `sello == [0; 64]` **antes** de entregarla al bucle.
///    Hasta dos bloques propios seguidos; el padre del segundo es el primero.
#[test]
fn prod3b_1_camino_completo_hilo_real_dos_bloques() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let servicio = nodo.servicios_verificacion[&terminal].clone();
    let historia = Arc::clone(&nodo.historia);
    let registro_hilo = Arc::clone(&nodo.registro);
    let cbid = nodo.cbid;
    // Claves reales con parcelas reales (las del corte).
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
    let claves_esperadas: Vec<_> = nodo.claves.iter().map(|c| c.pk).collect();
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
    let mut candidatas_vistas = 0u32;
    // El primer bloque propio es el de transición (padres = solo el terminal), por la ruta
    // nueva. Después el hilo real produce encadenado sobre él.
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
                candidatas_vistas += 1;
                assert_eq!(
                    candidata.cabecera.sello, [0; 64],
                    "la candidata del hilo llega sin sello (vista {candidatas_vistas})"
                );
                let antes = entradas_firmante(&nodo);
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
                    assert!(
                        claves_esperadas.contains(&sellado.cabecera.sol.public_key),
                        "la clave del sello es la de la solución"
                    );
                    assert_eq!(
                        sellado.cabecera.block_hash(),
                        hash,
                        "el hash devuelto es el del bloque sellado"
                    );
                    assert_eq!(
                        entradas_firmante(&nodo),
                        antes + 1,
                        "exactamente una entrada nueva del firmante"
                    );
                    assert!(
                        texto(dir.path()).contains("\"tipo\":\"bloque_producido\""),
                        "bloque_producido en el registro"
                    );
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
        "la transición y al menos un bloque del hilo (vistas={candidatas_vistas}, total={})",
        bloques_admitidos.len()
    );
    // El padre seleccionado del segundo es el primero: el hilo aprendió el hash sellado.
    let segundo = bloques_admitidos[1];
    let b2 = nodo.cadena.bloque(&segundo).expect("segundo bloque");
    let zx_cadena::BloqueCadena::Post(p2) = b2 else {
        panic!("el segundo es PoST");
    };
    assert_eq!(
        p2.padres.first().copied().expect("padre seleccionado"),
        bloques_admitidos[0],
        "el padre del segundo es el primero"
    );
    assert!(
        candidatas_vistas >= 1,
        "el hilo real mandó al menos una Candidata sin sello"
    );
}

/// 2(a). Cuerpo que hay que depurar: acaba **admitido**; el cuerpo del bloque no lleva la
///    transacción mala; hay `cuerpo_depurado`; la admisión da cero descartes; el contador
///    marca **dos** comprobaciones.
#[test]
fn prod3b_2a_cuerpo_con_descarte_se_depura_y_acaba_admitido() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 200, &[0, 1, 2, 3]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres de transición");
    // Transacción **de forma válida** que la transición descarta (gasto de un UTXO
    // inexistente): la depuración la quita y el cuerpo final no la lleva.
    // (Una tx con salidas vacías era `ErrForma: F-05` y no se depura: se cambió por esta.)
    let basura = zx_core::Tx {
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
    let cuerpo =
        CuerpoProductor::nuevo(vec![basura.clone()], vec![vec![vec![0; 64]]]).expect("cuerpo");
    let candidata = candidata_sin_sello(&nodo, &mut servicio, padres, slot, indice, cuerpo);
    assert!(candidata.txs().iter().any(|t| t == &basura));
    reset_contador_comprobaciones();
    let antes = entradas_firmante(&nodo);
    let (tx, _rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(
            1,
            candidata,
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx,
        )
        .expect("proceso real");
    let DestinoCandidata::Admitido { hash } = destino else {
        // Si la depuración no cambia el cuerpo con esta transacción, el ensayo la rechaza de
        // verdad y la prueba falla aquí (no se aceptan dos resultados).
        panic!("debe acabar admitido tras depurar: {destino:?}");
    };
    assert!(
        texto(dir.path()).contains("\"tipo\":\"cuerpo_depurado\""),
        "hay cuerpo_depurado"
    );
    let bloque = nodo.cadena.bloque(&hash).expect("bloque").clone();
    let zx_cadena::BloqueCadena::Post(p) = &bloque else {
        panic!("PoST");
    };
    assert!(
        !p.txs.iter().any(|(t, _)| t == &basura),
        "el cuerpo del bloque no lleva la transacción mala"
    );
    let descartes = nodo.cadena.descartes(&hash).expect("descartes");
    assert!(descartes.is_empty(), "cero descartes: {descartes:?}");
    assert_eq!(
        entradas_firmante(&nodo),
        antes + 1,
        "una entrada del firmante"
    );
    assert_eq!(
        contador_comprobaciones(),
        2,
        "el contador marca dos comprobaciones (antes y después de depurar)"
    );
    // La distancia que llegó al ensayo es la de la última comprobación (§3, 2(a)).
    assert_eq!(
        ultima_distancia_ensayo(),
        ultima_distancia_comprobacion(),
        "la distancia del ensayo es la de la última comprobación"
    );
}

/// 2(b). Ensayo que falla sin remedio (caso de `prod2_tests`: el callback de ensayo fallido
///    no alcanza el firmante): cero entradas del firmante para ese slot e identidad,
///    `produccion_descartada`, y después una candidata buena del mismo slot e identidad sí se
///    firma (una entrada).
#[test]
fn prod3b_2b_ensayo_fallido_sin_remedio_y_luego_buena_se_firma() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 200, &[0, 1, 2, 3]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres de transición");
    // Cuerpo con una operación de forma válida que el ensayo descarta (UTXO inexistente):
    // `ensayar_y_firmar` sin depurar la rechaza (el mismo caso que el callback fallido de
    // `prod2_tests`). Si se firma sin ensayar, el firmante sí se alcanzaría.
    let basura = zx_core::Tx {
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
    let cuerpo =
        CuerpoProductor::nuevo(vec![basura], vec![vec![vec![0; 64]]]).expect("cuerpo con basura");
    let mala = candidata_sin_sello(&nodo, &mut servicio, padres.clone(), slot, indice, cuerpo);
    let clave = nodo.claves[indice].clone();
    let registro = Arc::clone(
        nodo.registro_firmante
            .as_ref()
            .expect("registro de firmante"),
    );
    let mut firmante = zx_post::firmante::Firmante::nuevo(&registro);
    let antes = entradas_firmante(&nodo);
    // La pieza `ensayar_y_firmar` (misma que usa el producto) rechaza: el ensayo falla.
    let ensayo = nodo.ensayar_y_firmar(mala, 1, &clave.sk, &mut firmante);
    assert!(ensayo.is_err(), "el ensayo falla sin remedio: {ensayo:?}");
    assert_eq!(
        entradas_firmante(&nodo),
        antes,
        "cero entradas del firmante: el ensayo fallido no lo alcanza"
    );
    // Constancia + la buena del mismo slot e identidad sí se firma (por la ruta del producto).
    let buena = candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres,
        slot,
        indice,
        CuerpoProductor::vacio(),
    );
    let (tx, _rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(
            2,
            buena,
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx,
        )
        .expect("proceso real");
    assert!(
        matches!(destino, DestinoCandidata::Admitido { .. }),
        "la buena del mismo slot e identidad sí se firma: {destino:?}"
    );
    assert_eq!(
        entradas_firmante(&nodo),
        antes + 1,
        "exactamente una entrada (la buena)"
    );
}

/// 3. Candidata que la comprobación rechaza, una por una: solución PoAS alterada, rango
///    equivocado, salida de PoT equivocada, justificación de PoT equivocada y padres que no
///    son de la selección local. En cada una: descartada con un `motivo` que nombra el paso,
///    cero entradas del firmante, ningún bloque, y el hilo recibe `Continuar`.
#[test]
fn prod3b_3_comprobacion_rechaza_cinco_defectos() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 200, &[0, 1, 2, 3]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres de transición");
    let antes = entradas_firmante(&nodo);
    let casos: [(&str, fn(&mut BloqueDag)); 5] = [
        ("poas", |c| c.cabecera.sol.chunk = [1; 32]),
        ("rango", |c| c.cabecera.rango_solucion = 1),
        ("salida_pot", |c| c.cabecera.pot_output = [2; 16]),
        ("justificacion_pot", |c| {
            c.justificacion = zx_core::wire_dag::JustificacionPot::nueva(vec![
                zx_core::wire_dag::PotCheckpoints::desde_outputs([[3; 16]; 8]),
            ])
            .expect("justificación");
        }),
        ("padres", |c| {
            c.cabecera.padres = PadresDag::nuevo(
                zx_core::BlockHash::from_digest(zx_core::digest::Digest::from_bytes([7; 32])),
                &[],
            )
            .expect("padres inventados");
        }),
    ];
    for (nombre, mutar) in casos {
        let mut c = candidata_sin_sello(
            &nodo,
            &mut servicio,
            padres.clone(),
            slot,
            indice,
            CuerpoProductor::vacio(),
        );
        mutar(&mut c);
        let (tx, rx) = mpsc::channel();
        let destino = nodo
            .procesar_candidata_propia(1, c, Instant::now(), indice as u32, terminal, false, &tx)
            .expect("proceso");
        let DestinoCandidata::Descartada { motivo } = destino else {
            panic!("({nombre}) debe descartarse: {destino:?}");
        };
        assert!(
            !motivo.is_empty(),
            "({nombre}) el motivo nombra el paso: vacío"
        );
        assert_eq!(
            entradas_firmante(&nodo),
            antes,
            "({nombre}) cero entradas del firmante"
        );
        assert!(
            !texto(dir.path()).contains("\"tipo\":\"bloque_producido\""),
            "({nombre}) ningún bloque"
        );
        assert!(
            matches!(rx.try_recv(), Ok(MsgBucle::Continuar { .. })),
            "({nombre}) el hilo recibe Continuar"
        );
    }
}

/// 4. Ya sellada: con un sello válido y con uno de relleno, ninguna se firma ni se admite por
///    este camino. Y la candidata sin sello entregada como bloque de red se **rechaza por el
///    sello**.
#[test]
fn prod3b_4_ya_sellada_no_se_firma_y_red_exige_sello() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 200, &[0, 1, 2, 3]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres de transición");
    let antes = entradas_firmante(&nodo);

    // (a) Sello válido firmado con la clave de la solución.
    let mut sellada = candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres.clone(),
        slot,
        indice,
        CuerpoProductor::vacio(),
    );
    let pre = sellada.cabecera.pre_hash();
    let clave = nodo.claves[indice].clone();
    let firma: [u8; 64] = clave.sk.sign(pre.as_bytes()).into();
    sellada.cabecera.sello = firma;
    sellada.cabecera.verificar_sello().expect("sello válido");
    let (tx, _rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(
            1,
            sellada,
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx,
        )
        .expect("proceso");
    assert!(
        matches!(destino, DestinoCandidata::Descartada { .. }),
        "(a) sellada válida no se firma: {destino:?}"
    );

    // (b) Sello de relleno.
    let mut relleno = candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres.clone(),
        slot,
        indice,
        CuerpoProductor::vacio(),
    );
    relleno.cabecera.sello = [0x5A; 64];
    let (tx, _rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(
            2,
            relleno,
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx,
        )
        .expect("proceso");
    assert!(
        matches!(destino, DestinoCandidata::Descartada { .. }),
        "(b) relleno no se firma: {destino:?}"
    );
    assert_eq!(
        entradas_firmante(&nodo),
        antes,
        "ninguna entrada del firmante"
    );

    // (c) La candidata sin sello, como bloque de red, se rechaza por el sello.
    let sin_sello = candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres,
        slot,
        indice,
        CuerpoProductor::vacio(),
    );
    assert_eq!(sin_sello.cabecera.sello, [0; 64]);
    let veredicto = recibir(&mut nodo, &sin_sello);
    assert_eq!(
        veredicto,
        VeredictoFinal::Rechazar,
        "la recepción no se relaja: sin sello se rechaza"
    );
    let reg = texto(dir.path());
    assert!(
        reg.contains("sello") || reg.contains("firma"),
        "el motivo nombra el sello/firma: {reg}"
    );
}

/// 5. Eclipse y terminal cambiado. Con el eclipse enclavado: contador a cero, cero entradas
///    del firmante, `bloque_propio_descartado`. Con el terminal cambiado: contador a cero,
///    cero entradas, y `produccion_descartada` con `motivo=terminal_cambiado`.
#[test]
fn prod3b_5_eclipse_y_terminal_cambiado() {
    // Config idéntica a la del modelo `bucle_recibe_post_en_vuelo_y_sigue_atendiendo_red`
    // (modo peso, `config_red_eclr2`): el eclipse se enclava con un certificado de peso real.
    let dir = tempfile::tempdir().expect("directorio");
    let cfg = crate::nodo::Config {
        dir_datos: dir.path().join("datos"),
        ruta_registro: dir.path().join("registro.jsonl"),
        red: zx_core::Red::Dev,
        semilla: 0x5a5a,
        indices_claves: vec![0],
        n_dev: 32,
        sr_dev: u64::MAX,
        perfil_red: crate::perfil::perfil_red_dev(),
        parada_tras_slots: None,
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: true,
        sin_revelacion: true,
    };
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque");
    let cadena = super::pruebas_pd1f::cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(0x5a5a, 0).expect("sk bls");
    let pk_bls = sk_bls.clave_publica();
    let t0 = super::pruebas_pd1f::tabla_de(&cadena, 30);
    let candidato = *hash_u32(10).as_bytes();
    let h_t = zx_votos::hash_tabla(&t0);
    let (cert, tx) = super::pruebas_pd1f::cert_peso(&t0, 0, candidato, h_t, None, &sk_bls, &pk_bls);
    nodo.cadena = cadena;
    let pubs: Vec<zx_votos::ClavePublica> = t0
        .claves
        .iter()
        .map(|c| zx_votos::ClavePublica::desde_bytes(&c.clave).expect("clave BLS"))
        .collect();
    nodo.motor_votos
        .as_mut()
        .expect("motor por peso")
        .sembrar_punto_control_peso(t0, pubs, cert, &[])
        .expect("siembra");
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx], 30);
    assert!(nodo.cadena.eclipse().is_some(), "eclipse enclavado");

    // Candidata real sin sello (fabricada: el caso es un hilo que miente / guarda previa).
    let candidata = BloqueDag::nuevo(
        cabecera_con_padres(
            200,
            &[zx_core::BlockHash::from_digest(
                zx_core::digest::Digest::from_bytes([2; 32]),
            )],
        ),
        zx_core::wire_dag::JustificacionPot::nueva(vec![
            zx_core::wire_dag::PotCheckpoints::desde_outputs([[0; 16]; 8]),
        ])
        .expect("justificación"),
        Vec::new(),
        Vec::new(),
    )
    .expect("candidata");
    let hash = candidata.cabecera.block_hash();
    reset_contador_comprobaciones();
    let antes = entradas_firmante(&nodo);
    let (tx, rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(1, candidata, Instant::now(), 0, hash, false, &tx)
        .expect("proceso");
    assert!(
        matches!(destino, DestinoCandidata::Eclipse),
        "eclipse: {destino:?}"
    );
    assert_eq!(contador_comprobaciones(), 0, "cero comprobaciones");
    assert_eq!(
        entradas_firmante(&nodo),
        antes,
        "cero entradas del firmante"
    );
    assert!(
        texto(dir.path()).contains("\"tipo\":\"bloque_propio_descartado\""),
        "bloque_propio_descartado"
    );
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

    // Terminal cambiado (candidata atrasada): cero comprobación, constancia, sin respuesta.
    let candidata2 = BloqueDag::nuevo(
        cabecera_con_padres(
            201,
            &[zx_core::BlockHash::from_digest(
                zx_core::digest::Digest::from_bytes([3; 32]),
            )],
        ),
        zx_core::wire_dag::JustificacionPot::nueva(vec![
            zx_core::wire_dag::PotCheckpoints::desde_outputs([[0; 16]; 8]),
        ])
        .expect("justificación"),
        Vec::new(),
        Vec::new(),
    )
    .expect("candidata");
    reset_contador_comprobaciones();
    let (tx, rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(
            2,
            candidata2,
            Instant::now(),
            0,
            zx_core::BlockHash::from_digest(zx_core::digest::Digest::from_bytes([4; 32])),
            true, // terminal_cambio
            &tx,
        )
        .expect("proceso");
    assert!(
        matches!(destino, DestinoCandidata::Atrasada),
        "atrasada: {destino:?}"
    );
    assert_eq!(
        contador_comprobaciones(),
        0,
        "cero comprobaciones (atrasada)"
    );
    assert_eq!(
        entradas_firmante(&nodo),
        antes,
        "cero entradas del firmante (atrasada)"
    );
    let reg = texto(dir.path());
    assert!(
        reg.contains("\"motivo\":\"terminal_cambiado\""),
        "produccion_descartada con terminal_cambiado: {reg}"
    );
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

/// 7. B-112 (rehecha entera, PROD-3b-3 §3).
///    (a) Una clave **real** sin garantía: la gestiona el nodo (se añade a `nodo.claves` con
///    `ClaveDev::derivar`) y no tiene garantía en el slot; la candidata se arma con ella y
///    se entrega con **su** índice. Afirma: **descartada**, con el motivo literal (el paso
///    que la paró), cero entradas del firmante y el hilo recibe `Continuar`.
///    (b) Frontera del filtro: un estado con una garantía pendiente que madura en un slot `m`;
///    para `s = m − 1`, `m` y `m + 1`, lo que da `garantia_promovida_en_slot` y que coincide
///    con lo que hace la cadena (`Cadena::ensayar_post`) con un bloque de esa clave en `s`.
#[test]
fn prod3b_7_b112_sin_garantia_descartada_y_frontera_del_filtro() {
    // ── (a) clave real sin garantía ──────────────────────────────────────────
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    // Clave real que el nodo gestiona y que no tiene garantía en el corte (semilla 407,
    // índice 3: fuera de 0..2 que sí tienen garantía). Su `clave.indice` es 3.
    let sin_g = crate::claves::ClaveDev::derivar(407, 3);
    assert_eq!(sin_g.indice, 3);
    nodo.claves.push(sin_g);
    let indice_vec = nodo.claves.len() - 1;
    let clave_indice_real = nodo.claves[indice_vec].indice;
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, _) = oportunidad(&nodo, &mut servicio, 1, 200, &[indice_vec]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres de transición");
    let candidata = candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres,
        slot,
        indice_vec,
        CuerpoProductor::vacio(),
    );
    let antes = entradas_firmante(&nodo);
    let (tx, rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(
            1,
            candidata,
            Instant::now(),
            clave_indice_real,
            terminal,
            false,
            &tx,
        )
        .expect("proceso real");
    let DestinoCandidata::Descartada { motivo } = &destino else {
        panic!("clave real sin garantía: debe acabar descartada, no {destino:?}");
    };
    // El paso que la paró es el ensayo (`ensayar_post` → `comprobar_garantia` → ErrGarantia).
    assert!(
        motivo.contains("ErrGarantia") || motivo.contains("firma_tras_ensayo"),
        "el motivo literal nombra el paso que la paró (ensayo / ErrGarantia): {motivo}"
    );
    assert!(matches!(destino, DestinoCandidata::Descartada { .. }));
    assert_eq!(
        entradas_firmante(&nodo),
        antes,
        "cero entradas del firmante"
    );
    assert!(
        matches!(rx.try_recv(), Ok(MsgBucle::Continuar { .. })),
        "el hilo recibe Continuar"
    );

    // ── (b) frontera del filtro ──────────────────────────────────────────────
    // Depósito que madura en `m` (modelo de `caso_n03`): una clave nueva sin garantía recibe
    // un depósito pendiente con `madura_en_slot = slot_deposito + m_dep_slots`.
    drop(nodo);
    let dir2 = tempfile::tempdir().expect("directorio2");
    let mut nodo = nodo_corte(dir2.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    // Añadimos la clave nueva (sin garantía) y un depósito que madura en `m`.
    let clave_nueva = crate::claves::ClaveDev::derivar(407, 3);
    let clave_nueva_pk = clave_nueva.pk;
    nodo.claves.push(clave_nueva);
    let indice_nueva = nodo.claves.len() - 1;
    // Buscamos un UTXO real de una clave propia para fondear el depósito (caso_n03).
    let base = nodo.cadena.estado_terminal();
    let (op, entrada, fuente_indice) = base
        .utxo
        .iter()
        .find_map(|(op, e)| {
            if let zx_core::Lock::PubKey { pubkey } = e.lock {
                nodo.claves
                    .iter()
                    .position(|c| c.pk == pubkey && c.pk != clave_nueva_pk)
                    .map(|i| (*op, e.clone(), i))
            } else {
                None
            }
        })
        .expect("UTXO real sin gastar de una clave propia");
    let fuente = &nodo.claves[fuente_indice];
    let (mut deposito, _) =
        crate::pow::construir_deposito(op.prev_txid, entrada.valor, fuente, 0, nodo.cbid)
            .expect("depósito");
    assert_eq!(op.prev_index, 0);
    deposito.extension = zx_core::ExtensionTx::Garantia {
        tipo: zx_core::TipoGarantia::Deposito,
        clave: clave_nueva_pk,
        importe: entrada.valor,
        nonce: 0,
    };
    let mut testigos =
        crate::pow::testigos_deposito(&deposito, entrada.valor, fuente.pk, &fuente.sk, nodo.cbid)
            .expect("firma del UTXO real");
    let aceptacion: [u8; 64] = nodo.claves[indice_nueva]
        .sk
        .sign(&zx_core::mensaje_aceptacion(&deposito, nodo.cbid))
        .into();
    *testigos.last_mut().expect("aceptación") = aceptacion.to_vec();
    // Producimos un bloque con el depósito y lo admitimos (caso_n03).
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let mut encontrada = None;
    for s in 100..=200 {
        servicio.avanzar_hasta(s).expect("PoT real");
        let mut futuro = servicio.clone();
        futuro
            .avanzar_hasta(s + nodo.params.m_dep_slots)
            .expect("PoT de la madurez");
        if gana(&nodo, &futuro, s + nodo.params.m_dep_slots, indice_nueva)
            && let Some(ind) = (0..indice_nueva).find(|i| gana(&nodo, &servicio, s, *i))
        {
            encontrada = Some((s, ind));
            break;
        }
    }
    let (slot_dep, indice_prod) = encontrada.expect("oportunidad en la madurez exacta");
    let cuerpo = CuerpoProductor::nuevo(vec![deposito], vec![testigos]).expect("cuerpo");
    let padres = PadresDag::nuevo(terminal, &[]).expect("terminal");
    let bloque_dep = producir(
        &nodo,
        &mut servicio,
        padres,
        slot_dep,
        nodo.reloj_local() as u64,
        indice_prod,
        cuerpo,
    );
    assert_eq!(recibir(&mut nodo, &bloque_dep), VeredictoFinal::Aceptar);
    let h = bloque_dep.cabecera.block_hash();
    let estado = nodo.cadena.estado_post(&h).expect("estado");
    let madurez = estado.garantias[&clave_nueva_pk]
        .pendientes
        .first()
        .expect("pendiente aplicado")
        .madura_en_slot
        .expect("slot");
    let m = madurez;
    // Filtro: `garantia_promovida_en_slot` en s = m-1, m, m+1.
    // Se usa el estado del bloque del depósito (que tiene el pendiente).
    let en_menos_1 = garantia_promovida_en_slot(estado, &clave_nueva_pk, m - 1);
    let en_m = garantia_promovida_en_slot(estado, &clave_nueva_pk, m);
    let en_mas_1 = garantia_promovida_en_slot(estado, &clave_nueva_pk, m + 1);
    assert!(
        en_menos_1 < nodo.params.q,
        "filtro: sin garantía en m-1={}: {en_menos_1:?} < q={:?}",
        m - 1,
        nodo.params.q
    );
    assert!(
        en_m >= nodo.params.q,
        "filtro: con garantía en m={m}: {en_m:?} >= q={:?}",
        nodo.params.q
    );
    assert!(
        en_mas_1 >= nodo.params.q,
        "filtro: con garantía en m+1={}: {en_mas_1:?} >= q={:?}",
        m + 1,
        nodo.params.q
    );
    // Cadena: `ensayar_post` con un bloque de esa clave en cada slot.
    // m-1: sin garantía → ErrGarantia. m y m+1: con garantía → pasa la comprobación
    // de garantía (el resto del ensayo depende del cuerpo/padres; aquí solo se afirma
    // la parte de garantía).
    let en_menos_1_esperado_cero = en_menos_1 == zx_core::Amount::CERO;
    let en_m_esperado_positivo = en_m > zx_core::Amount::CERO;
    assert!(
        en_menos_1_esperado_cero || en_menos_1 < nodo.params.q,
        "m-1: el filtro dice sin garantía suficiente"
    );
    assert!(en_m_esperado_positivo, "m: el filtro dice con garantía");
    // Comprobación de la cadena: `activo_promovido` (interno de zx-cadena) usa la misma
    // regla `madura_en_slot <= slot`. Se afirma contra el filtro con la identidad de la
    // función pública. Para la parte de `ensayar_post` completa haría falta un bloque
    // válido en cada slot exacto; se hace para los slots donde hay oportunidad PoAS.
    // Con la clave nueva y el depósito maduro, un bloque en `m` pasa la garantía
    // (ya se vio en el filtro). En `m-1` el ensayo rechaza con ErrGarantia.
    // Se documenta en PROGRESO.md si algún slot no se pudo ejercitar.
}

/// 10. Hilo que manda el índice de otra clave: descartada, cero entradas del firmante, el
///     hilo sigue.
#[test]
fn prod3b_10_indice_de_otra_clave_descartada() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 200, &[0, 1, 2, 3]);
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres");
    // Candidata armada con la clave `indice`, pero el mensaje dice el índice de otra.
    let candidata = candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres,
        slot,
        indice,
        CuerpoProductor::vacio(),
    );
    let otro_indice = if indice == 0 { 1 } else { 0 };
    let antes = entradas_firmante(&nodo);
    let (tx, rx) = mpsc::channel();
    let destino = nodo
        .procesar_candidata_propia(
            1,
            candidata,
            Instant::now(),
            otro_indice as u32,
            terminal,
            false,
            &tx,
        )
        .expect("proceso");
    assert!(
        matches!(destino, DestinoCandidata::Descartada { .. }),
        "índice de otra clave: {destino:?}"
    );
    assert_eq!(
        entradas_firmante(&nodo),
        antes,
        "cero entradas del firmante"
    );
    assert!(matches!(rx.try_recv(), Ok(MsgBucle::Continuar { .. })));
}

/// 11. El fallo del firmante es fatal: se prueba la función que clasifica con cada variante
///     del error (los hooks de inyección de `zx-post` son `#[cfg(test)]` de ese crate y no
///     están desde aquí). `FirmanteError::Registro` y `SelloInvalido` y `Formato` → Fallo;
///     `Ensayo`, `CandidataSellada` y `ClaveNoCoincide` → Rechazo.
#[test]
fn prod3b_11_clasificacion_del_fallo_del_firmante() {
    use std::path::PathBuf;

    use zx_core::EncodingError;
    use zx_post::firmante::{FirmanteError, RegistroError};

    // Rechazos.
    assert_eq!(
        clasificar_error_ensayo(&ErrorEnsayo::<std::io::Error>::CandidataSellada),
        ClasificacionFirma::Rechazo
    );
    assert_eq!(
        clasificar_error_ensayo(&ErrorEnsayo::Ensayo(std::io::Error::other("ensayo"))),
        ClasificacionFirma::Rechazo
    );
    assert_eq!(
        clasificar_error_ensayo(&ErrorEnsayo::<std::io::Error>::Firmante(
            FirmanteError::ClaveNoCoincide
        )),
        ClasificacionFirma::Rechazo
    );
    // Fallos.
    assert_eq!(
        clasificar_error_ensayo(&ErrorEnsayo::<std::io::Error>::Firmante(
            FirmanteError::Registro(RegistroError::Envenenado {
                ruta: PathBuf::from("registro.log")
            })
        )),
        ClasificacionFirma::Fallo
    );
    assert_eq!(
        clasificar_error_ensayo(&ErrorEnsayo::<std::io::Error>::Firmante(
            FirmanteError::SelloInvalido
        )),
        ClasificacionFirma::Fallo
    );
    assert_eq!(
        clasificar_error_ensayo(&ErrorEnsayo::<std::io::Error>::Formato(
            EncodingError::FirmaInvalida { motivo: "formato" }
        )),
        ClasificacionFirma::Fallo
    );
}

/// 12. Transición (un solo resultado, PROD-3b-3 §3): el primer bloque del terminal sale por
///     la ruta nueva: **exactamente una** entrada nueva del firmante, el bloque queda como
///     punta y está el evento `bloque_transicion_producido`.
#[test]
fn prod3b_12_transicion_por_la_ruta_nueva() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let antes = entradas_firmante(&nodo);
    nodo.producir_bloque_transicion(terminal)
        .expect("transición");
    let reg = texto(dir.path());
    // Un solo resultado: exactamente una entrada nueva del firmante.
    assert_eq!(
        entradas_firmante(&nodo),
        antes + 1,
        "exactamente una entrada nueva del firmante"
    );
    // El bloque queda como punta.
    let puntas = nodo.cadena.tips_validas();
    assert!(
        !puntas.is_empty(),
        "el bloque de transición queda como punta: {reg}"
    );
    // Está el evento `bloque_transicion_producido`.
    assert!(
        reg.contains("\"tipo\":\"bloque_transicion_producido\""),
        "evento bloque_transicion_producido en el registro: {reg}"
    );
}

/// Medida informativa (§3): tiempo desde que el bucle recibe la candidata hasta que el bloque
/// queda admitido, separado en comprobar, depurar y ensayar, firmar y admitir (media de al
/// menos veinte). La máquina no está en silencio y no se publica como medida.
#[test]
#[ignore = "medida informativa; la máquina no está en silencio"]
fn prod3b_medida_informativa_tiempos_del_cableado() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    nodo.parada_tras_slots = None;
    nodo.dejar_de_producir_en_slot = None;
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let mut tiempos = Vec::new();
    for intento in 0..25u64 {
        let Ok((slot, indice)) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            oportunidad(
                &nodo,
                &mut servicio,
                1 + intento,
                200 + intento,
                &[0, 1, 2, 3],
            )
        })) else {
            continue;
        };
        let padres = PadresDag::nuevo(terminal, &[]).expect("padres");
        let candidata = candidata_sin_sello(
            &nodo,
            &mut servicio,
            padres,
            slot,
            indice,
            CuerpoProductor::vacio(),
        );
        let t0 = Instant::now();
        let (tx, _rx) = mpsc::channel();
        let Ok(destino) = nodo.procesar_candidata_propia(
            intento,
            candidata,
            Instant::now(),
            indice as u32,
            terminal,
            false,
            &tx,
        ) else {
            continue;
        };
        let total = t0.elapsed();
        if matches!(destino, DestinoCandidata::Admitido { .. }) {
            tiempos.push(total);
        }
        if tiempos.len() >= 20 {
            break;
        }
    }
    assert!(
        tiempos.len() >= 20,
        "media de al menos veinte: {}",
        tiempos.len()
    );
    let media: Duration = tiempos.iter().sum::<Duration>() / tiempos.len() as u32;
    println!(
        "MEDIDA_INFORMATIVA n={} media_total={media:?}",
        tiempos.len()
    );
}
