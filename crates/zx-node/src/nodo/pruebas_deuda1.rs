//! DEUDA-1 · pruebas 6, 9a y 9b — evidencia BLS real por el camino de la candidata,
//! votante real que emite, y el reinicio que no reabre una ventana vieja.
//!
//! 6: evidencia de doble voto con firmas BLS reales en el cuerpo de una candidata real,
//!    entregada a `procesar_candidata_propia`; se compara el estado del ensayo con el de la
//!    admisión del bloque sellado y se muestra el castigo.
//! 9a: el hilo productor real envía la frontera y el motor **emite** exactamente un
//!    `voto_emitido` en esa ventana, sin producir bloque.
//! 9b (DEUDA-2): reinicio **real** sobre el mismo directorio, con la cadena en disco reconstruida
//!    por repetición del almacén. Montaje común en `super::pruebas_deuda2`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    reason = "fixtures de integración con aserciones"
)]

use super::firma_contextual::DestinoCandidata;
use super::pruebas_deuda2::{
    anclar_finalidad, config_deuda2, correr_hasta_ventana, lineas_de, montar, producir_post,
};
use super::pruebas_eclr2::{genesis, hash_u32};
use super::*;
use crate::votos::b88 as f;
use crate::votos::{DetectorFalta, VotoDetector, clave_voto_dev, tx_evidencia_votos_peso};
use std::collections::HashSet;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Instant;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::Garantia;
use zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo;
use zx_core::Amount;
use zx_post::productor_regimen::CuerpoProductor;
use zx_votos::{DOMINIO_VOTO, firmar, mensaje_voto_peso};

// ---------------------------------------------------------------------------------------------
// Helpers de fixture (patrón de vnt1: cadena con `claves_voto` registrada + PoAS real)
// ---------------------------------------------------------------------------------------------

/// Estado con las claves `clave_voto_dev(1, i)` registradas, cada una con sectores activos.
/// Se deriva la tabla sin base (`derivar_tabla_sin_base_con_undo`) para que `cola_tablas_voto`
/// tenga la huella que el votante declara al abrir la primera ventana (TB-1c-2 · X3).
fn estado_deuda1(n_claves: usize) -> EstadoTransicion {
    let mut estado = EstadoTransicion::inicial();
    for i in 0..n_claves {
        let indice = u32::try_from(i).expect("índice Ed25519");
        let c = ClaveDev::derivar(1, indice);
        let sk = clave_voto_dev(1, indice).expect("BLS dev");
        estado.claves_voto.insert(
            c.pk,
            ClaveVoto {
                clave_bls: sk.clave_publica().bytes(),
                prueba_posesion: zx_votos::probar_posesion(&sk).bytes(),
            },
        );
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(10_000).expect("garantía");
        estado.garantias.insert(c.pk, g);
        for j in 0..2 * n_claves {
            let id = SectorId {
                clave: c.pk,
                sector_index: u16::try_from(j).expect("sector"),
                version: 0,
            };
            estado.sectores.insert(
                id,
                RegistroSector {
                    id,
                    r2: [0; 4],
                    history_size: 1,
                    etapa: Etapa::Activo,
                    alta_slot: 0,
                    renovacion_slot: 0,
                    retiro_slot: -1,
                    fianza: ParametrosSector::dev().q_sec,
                    aud_apertura: -1,
                    aud_contestada: -1,
                },
            );
        }
    }
    let (con_cola, _undo) = derivar_tabla_sin_base_con_undo(&estado, 0);
    con_cola
}

/// Nodo real (parcelas, firmante) con la cadena sustituida por un estado con `claves_voto`.
/// El motor de votos que crea `arrancar` (con diario durable vinculado) se **conserva**:
/// es el que emite en 9a y cuyo candado persiste en 9b. `indices_claves = [0]` deja una sola
/// clave emisora para que el «exactamente un `voto_emitido`» de 9a sea directo; el estado
/// puede registrar más claves con peso — solo votan las del motor.
fn nodo_deuda1(dir: &Path, estado: EstadoTransicion, sin_voto: bool) -> Nodo {
    let cfg = Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: vec![0],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto,
        sin_revelacion: false,
    };
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque");
    let params = perfil::parametros_transicion_dev().expect("perfil dev íntegro");
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params,
        perfil::ghostdag_k(),
        nodo.cbid,
        perfil::ghostdag_max_padres(),
        perfil::parametros_evidencia_dev(),
        estado,
    );
    cadena.admitir(genesis()).expect("génesis");
    for altura in 1..=params.h_corte_min {
        cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::PoW {
                    hash: hash_u32(altura),
                    padre: hash_u32(altura - 1),
                    altura,
                    trabajo: params.w_min / U256::from(params.h_corte_min),
                    pow_valido: true,
                },
                Vec::new(),
            )))
            .expect("avance PoW");
    }
    nodo.params = params;
    nodo.cadena = cadena;
    nodo.asegurar_servicios_verificacion()
        .expect("servicio del terminal PoW");
    nodo
}

fn base_del_terminal(nodo: &Nodo) -> (BlockHash, EstadoTransicion) {
    let terminal = nodo.cadena.terminal().expect("terminal PoW");
    let base = nodo
        .cadena
        .estado_past(&terminal)
        .cloned()
        .unwrap_or_else(|| nodo.cadena.estado_terminal().clone());
    (terminal, base)
}

/// Evidencia de doble voto con firmas BLS reales para la clave `clave_voto_dev(1, 0)`
/// (registrada en `estado_deuda1`). Dos votos de la misma ventana con candidatos distintos.
fn evidencia_real(nodo: &Nodo) -> crate::votos::EvidenciaVotosPesoCompleta {
    let sk = clave_voto_dev(1, 0).expect("clave BLS");
    let clave_bls = sk.clave_publica().bytes();
    let mut detector = DetectorFalta::nuevo(
        perfil::parametros_votos_dev().t_inst,
        crate::perfil::PLAZO_SLOTS,
    );
    let candidato_a = f::hash(3);
    let candidato_b = f::hash(4);
    let h_t = f::hash(90);
    let raiz = [0u8; 32];
    let firma_a = firmar(
        &sk,
        DOMINIO_VOTO,
        &mensaje_voto_peso(1, &candidato_a, &h_t, &raiz),
    )
    .expect("firma A3 real");
    let firma_b = firmar(
        &sk,
        DOMINIO_VOTO,
        &mensaje_voto_peso(1, &candidato_b, &h_t, &raiz),
    )
    .expect("firma A3 real");
    detector.registrar(
        clave_bls,
        VotoDetector {
            n: 1,
            candidato: candidato_a,
            h_t_siguiente: h_t,
            raiz_estado: raiz,
            firma: firma_a,
        },
        &nodo.cadena,
    );
    detector.registrar(
        clave_bls,
        VotoDetector {
            n: 1,
            candidato: candidato_b,
            h_t_siguiente: h_t,
            raiz_estado: raiz,
            firma: firma_b,
        },
        &nodo.cadena,
    );
    let mut evidencias = detector.ofrecer_en(
        &nodo.cadena,
        1,
        0,
        crate::perfil::PLAZO_SLOTS,
        &HashSet::new(),
    );
    assert_eq!(
        evidencias.len(),
        1,
        "la pareja contradictoria produce una evidencia"
    );
    evidencias.pop().expect("evidencia")
}

/// Resumen canónico del estado para la comparación (b): campos de consenso, sin `terminal`.
fn resumen(estado: &EstadoTransicion) -> String {
    format!(
        "garantias={:?}|sectores={:?}|quemado={}|emitido={}|utxo={:?}|claves_voto={:?}",
        estado.garantias,
        estado.sectores,
        estado.quemado,
        estado.emitido,
        estado.utxo,
        estado.claves_voto
    )
}

// ---------------------------------------------------------------------------------------------
// 6 — evidencia bien firmada por el camino de la candidata
// ---------------------------------------------------------------------------------------------

/// 6. La evidencia de doble voto con firmas BLS reales viaja en el cuerpo de una candidata real
///    que pasa por `procesar_candidata_propia`. Se afirma:
///    (a) se firma y se admite;
///    (b) el estado del ensayo es el de la admisión del bloque sellado (resumen canónico);
///    (c) el castigo es visible en ese estado (incidentes, congelado, activo, quemado).
#[test]
fn deuda1_6_evidencia_bls_real_por_el_camino_de_la_candidata() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_deuda1(dir.path(), estado_deuda1(3), true);
    let (terminal, base) = base_del_terminal(&nodo);

    // Evidencia real (firmas BLS reales) para la clave `clave_voto_dev(1, 0)`.
    let evidencia = evidencia_real(&nodo);
    let acusado = ClaveDev::derivar(1, 0).pk;
    let (pk_rep, sk_rep) = f::reportero();
    let (tx_evidencia, testigos_evidencia) =
        tx_evidencia_votos_peso(&evidencia, pk_rep, &sk_rep, nodo.cbid);

    // Estado antes del castigo.
    let garantia_antes = base.garantias[&acusado].clone();
    let quemado_antes = base.quemado;
    assert!(
        garantia_antes.incidentes.is_empty(),
        "antes del castigo no hay incidentes"
    );

    // Candidata real con la evidencia en el cuerpo.
    nodo.parada_tras_slots = None;
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let padres = PadresDag::nuevo(terminal, &[]).expect("padres");
    let (slot, indice) = super::dgcand_tests::oportunidad(&nodo, &mut servicio, 1, 200, &[0]);
    let cuerpo = CuerpoProductor::nuevo(vec![tx_evidencia], vec![testigos_evidencia])
        .expect("cuerpo con evidencia");
    let candidata = super::pruebas_prod3b::candidata_sin_sello(
        &nodo,
        &mut servicio,
        padres,
        slot,
        indice,
        cuerpo,
    );

    // (a) Ensayo previo + entrega a `procesar_candidata_propia`.
    let candidata_clon = candidata.clone();
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
        panic!("debe acabar admitido: {destino:?}");
    };

    // (b) Ensayo de la candidata (sin sello) vs admisión del bloque sellado.
    let distancia = super::firma_contextual::ultima_distancia_comprobacion();
    let post_ensayo =
        post_de_candidata(&candidata_clon, distancia).expect("post de la candidata sin sello");
    let (estado_ensayo, descartes) = nodo
        .cadena
        .ensayar_post(&post_ensayo)
        .expect("ensayo de la candidata");
    assert!(
        descartes.is_empty(),
        "el ensayo no descarta nada: {:?}",
        descartes
    );
    let estado_admision = nodo
        .cadena
        .estado_post(&hash)
        .expect("estado post del bloque sellado")
        .clone();
    assert_eq!(
        resumen(&estado_ensayo),
        resumen(&estado_admision),
        "el estado del ensayo es el de la admisión del bloque sellado (resumen canónico; \
         `terminal` difiere porque el hash del bloque sellado lleva el sello)"
    );

    // (c) El castigo es visible en el estado de la admisión.
    let garantia_despues = &estado_admision.garantias[&acusado];
    assert_eq!(
        garantia_despues.incidentes.len(),
        1,
        "un incidente registrado: {:?}",
        garantia_despues.incidentes
    );
    assert!(
        garantia_despues.congelado.brek() > 0,
        "congelado > 0 tras el castigo (antes: {})",
        garantia_antes.congelado.brek()
    );
    assert!(
        garantia_despues.activo.brek() < garantia_antes.activo.brek(),
        "activo debitado: {} -> {}",
        garantia_antes.activo.brek(),
        garantia_despues.activo.brek()
    );
    assert!(
        estado_admision.quemado > quemado_antes,
        "quemado aumenta: {} -> {}",
        quemado_antes,
        estado_admision.quemado
    );
    println!(
        "DEUDA-1 #6 castigo: incidentes {} -> {}, congelado {} -> {}, activo {} -> {}, quemado {} -> {}",
        garantia_antes.incidentes.len(),
        garantia_despues.incidentes.len(),
        garantia_antes.congelado.brek(),
        garantia_despues.congelado.brek(),
        garantia_antes.activo.brek(),
        garantia_despues.activo.brek(),
        quemado_antes,
        estado_admision.quemado
    );
}

// ---------------------------------------------------------------------------------------------
// 9a — un votante real emite
// ---------------------------------------------------------------------------------------------

/// 9a. Nodo con claves de voto y motor que **sí** emite (`sin_voto: false`), hilo productor
///     real y bucle real. El aviso de frontera que abre la ventana sale del hilo.
///     Exactamente un `voto_emitido` en la ventana 1 y ningún bloque producido.
#[test]
fn deuda1_9a_votante_real_emite_un_voto() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_deuda1(dir.path(), estado_deuda1(3), false);
    let (terminal, _base) = base_del_terminal(&nodo);

    // Hilo productor real (sin claves: nadie gana el slot → no se produce bloque).
    let servicio = nodo.servicios_verificacion[&terminal].clone();
    let historia = Arc::clone(&nodo.historia);
    let registro = Arc::clone(&nodo.registro);
    let cbid = nodo.cbid;
    let (tx_prod, rx_prod) = mpsc::channel::<MsgProductor>();
    let (tx_bucle, rx_bucle) = mpsc::channel::<MsgBucle>();
    let hilo = thread::spawn(move || {
        hilo_productor_regimen(
            servicio,
            u64::MAX,
            cbid,
            perfil::subsidio_post(0),
            Vec::new(),
            &historia,
            Some(4),
            &rx_bucle,
            &tx_prod,
            &registro,
        );
    });

    let mut terminal_loop = terminal;
    let mut frontera_enviada = 0u64;
    let mut abierta = None;
    for _ in 0..400 {
        let _ = nodo.iteracion_regimen(
            &rx_prod,
            &tx_bucle,
            &mut terminal_loop,
            &mut frontera_enviada,
        );
        abierta = nodo
            .motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta);
        if abierta == Some(1) {
            break;
        }
    }
    let _ = tx_bucle.send(MsgBucle::Parar);
    let _ = hilo.join();

    assert_eq!(
        abierta,
        Some(1),
        "el hilo real envía la frontera y la ventana n=1 se abre"
    );
    let registro_texto = super::dgcand_tests::texto(dir.path());
    let votos_n1: Vec<&str> = registro_texto
        .lines()
        .filter(|l| l.contains("\"tipo\":\"voto_emitido\"") && l.contains("\"n\":1"))
        .collect();
    assert_eq!(
        votos_n1.len(),
        1,
        "exactamente un voto_emitido en la ventana 1: {:?}",
        votos_n1
    );
    assert!(
        !registro_texto.contains("\"tipo\":\"bloque_producido\""),
        "nadie gana el slot: no se produce bloque"
    );
}

// ---------------------------------------------------------------------------------------------
// 9b-1 — el reiniciado no firma dos cosas distintas en una ventana que ya votó
// ---------------------------------------------------------------------------------------------

/// 9b-1. El nodo vota en `n` con un candidato; antes de reiniciar, la cadena crece con un bloque
/// descendiente que cambia el candidato de la misma ventana. Tras el reinicio real, el diario
/// devuelve `Conflicto` y **no** se firma un segundo `voto_emitido` para `n`; el motor deja
/// constancia del conflicto en el registro (`voto_suprimido` con `conflicto_diario`) y el diario
/// sigue con una sola entrada.
#[test]
fn deuda2_9b1_reinicio_no_firma_otro_candidato_en_la_misma_ventana() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut m = montar(dir.path());
    let n = m.ventana;
    let slot = n * perfil::parametros_votos_dev().t_inst;
    let clave_bls = m.sk_bls.clave_publica().bytes();

    // Fase 1: el nodo vota en `n` con el bloque maduro como candidato.
    correr_hasta_ventana(&mut m.nodo, slot, n, 400);
    assert_eq!(
        m.nodo
            .motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        Some(n),
        "fase 1: se abre la ventana {n}"
    );
    let cand1 = m.nodo.candidato_votos(slot).expect("candidato fase 1");
    assert_eq!(
        cand1, m.bloque_candidato,
        "fase 1: candidato = bloque candidato"
    );
    let (n_diario, cand_diario) = m
        .nodo
        .motor_votos
        .as_ref()
        .expect("motor")
        .diario_para_test()
        .expect("diario")
        .candado(&clave_bls)
        .expect("candado tras el voto");
    assert_eq!(
        (n_diario, cand_diario),
        (n, *cand1.as_bytes()),
        "el diario fija (n, candidato)"
    );
    let registro1 = super::dgcand_tests::texto(dir.path());
    assert_eq!(
        lineas_de(&registro1, "voto_emitido", n).len(),
        1,
        "fase 1: exactamente un voto_emitido en n"
    );

    // La cadena sigue creciendo: un bloque descendiente con slot dentro del tope del candidato
    // cambia el candidato de la misma ventana `n`.
    let (bloque_nuevo, slot_nuevo) = producir_post(
        &mut m.nodo,
        m.terminal,
        m.bloque_candidato,
        m.slot_candidato.saturating_add(1),
        m.slot_candidato.saturating_add(5),
        CuerpoProductor::vacio(),
    );
    let cand2 = m.nodo.candidato_votos(slot).expect("candidato fase 2");
    assert_eq!(
        cand2, bloque_nuevo,
        "el candidato pasa a ser el bloque nuevo"
    );
    assert_ne!(
        cand1, cand2,
        "el candidato tras crecer la cadena es distinto"
    );
    assert!(
        slot_nuevo <= slot.saturating_sub(4),
        "el bloque nuevo cae dentro del tope del candidato ({slot_nuevo} <= {})",
        slot.saturating_sub(4)
    );

    drop(m.nodo);

    // Fase 2: reinicio real sobre el mismo directorio (el diario y la cadena salen del disco).
    let mut nodo2 = Nodo::arrancar(&config_deuda2(dir.path())).expect("reinicio real");
    correr_hasta_ventana(&mut nodo2, slot, n, 400);

    let registro2 = super::dgcand_tests::texto(dir.path());
    assert_eq!(
        lineas_de(&registro2, "voto_emitido", n).len(),
        1,
        "no hay un segundo voto_emitido para n: {:?}",
        lineas_de(&registro2, "voto_emitido", n)
    );
    let suprimidos = lineas_de(&registro2, "voto_suprimido", n);
    assert!(
        suprimidos
            .iter()
            .any(|l| l.contains("\"motivo\":\"conflicto_diario\"")),
        "el motor dejó constancia del conflicto: {:?}",
        suprimidos
    );
    let d2 = nodo2
        .motor_votos
        .as_ref()
        .expect("motor")
        .diario_para_test()
        .expect("diario");
    assert_eq!(d2.entradas(), 1, "el diario sigue con una sola entrada");
    assert_eq!(
        d2.candado(&clave_bls).map(|(nv, _)| nv),
        Some(n),
        "el candado del diario sigue en n"
    );
}

// ---------------------------------------------------------------------------------------------
// 9b-2 — el reiniciado sigue votando una ventana posterior
// ---------------------------------------------------------------------------------------------

/// 9b-2. Tras el mismo reinicio real, el nodo abre y vota una ventana **posterior** a la última
/// que firmó: exactamente un `voto_emitido` para esa ventana.
#[test]
fn deuda2_9b2_reinicio_sigue_votando_una_ventana_posterior() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut m = montar(dir.path());
    let n = m.ventana;
    let t_inst = perfil::parametros_votos_dev().t_inst;

    correr_hasta_ventana(&mut m.nodo, n * t_inst, n, 400);
    let registro1 = super::dgcand_tests::texto(dir.path());
    assert_eq!(
        lineas_de(&registro1, "voto_emitido", n).len(),
        1,
        "fase 1: un voto en n"
    );
    drop(m.nodo);

    let mut nodo2 = Nodo::arrancar(&config_deuda2(dir.path())).expect("reinicio real");
    correr_hasta_ventana(&mut nodo2, (n + 1) * t_inst, n + 1, 400);

    let registro2 = super::dgcand_tests::texto(dir.path());
    assert_eq!(
        lineas_de(&registro2, "voto_emitido", n + 1).len(),
        1,
        "el reiniciado abre y vota exactamente una vez la ventana posterior n+1"
    );
    assert_eq!(
        lineas_de(&registro2, "voto_emitido", n).len(),
        1,
        "la ventana n no se vuelve a firmar"
    );
}

// ---------------------------------------------------------------------------------------------
// 9b-3 — la guarda de arranque, por el camino real
// ---------------------------------------------------------------------------------------------

/// 9b-3. La cadena en disco **sí** recogió la finalidad de la ventana `m = 0` (un `0x09` real en
/// un bloque PoST real y persistido). Al reiniciar con el reloj de votos en `m` o antes, la
/// guarda de arranque no abre ninguna ventana `<= m`: no hay `ventana_abierta` ni `voto_emitido`
/// para la ventana 0, y el nodo deja constancia de la espera del reloj.
#[test]
fn deuda2_9b3_la_guarda_de_arranque_no_abre_una_ventana_ya_finalizada() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut m = montar(dir.path());
    let (_bloque_final, h) = anclar_finalidad(&mut m);
    drop(m.nodo);

    // Fase 2: reinicio real; el estado con finalidad sale de la repetición del almacén.
    let mut nodo2 = Nodo::arrancar(&config_deuda2(dir.path())).expect("reinicio real");
    let estado = nodo2
        .cadena
        .estado_virtual()
        .expect("estado virtual tras el reinicio");
    assert_eq!(
        estado.finalidad_votos_n, 0,
        "la cadena de disco tiene base m = 0"
    );
    assert_eq!(
        estado.finalidad_votos_h_t,
        Some(h),
        "la huella de la finalidad es la del certificado"
    );

    // Reloj de votos en m = 0 (o antes): la guarda no abre ninguna ventana <= m.
    correr_hasta_ventana(&mut nodo2, 0, 0, 8);
    let registro = super::dgcand_tests::texto(dir.path());
    assert!(
        lineas_de(&registro, "ventana_abierta", 0).is_empty(),
        "no se abre la ventana 0: {:?}",
        lineas_de(&registro, "ventana_abierta", 0)
    );
    assert!(
        lineas_de(&registro, "voto_emitido", 0).is_empty(),
        "no se vota la ventana 0"
    );
    assert!(
        registro.contains("\"tipo\":\"votos_espera\"") && registro.contains("espera_reloj"),
        "el nodo está en condiciones y la guarda clasifica la espera: {registro}"
    );
}
