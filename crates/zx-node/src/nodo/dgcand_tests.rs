//! DG-CAND: recepción, bucle, productor, cadena y reinicio reales. Sin cambios de protocolo.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::wildcard_imports,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "aserciones y fixtures internos; tamaños comprobados antes de indexar"
)]

use super::*;
use core::sync::atomic::AtomicBool;
use zx_consensus::{PARAMETROS_POW_DEV, Sha3Dev, minar};
use zx_core::preimage::dag::SolucionPoas;
use zx_core::{ExtensionTx, Lock, TipoGarantia};
use zx_post::productor_regimen::{CuerpoProductor, producir_en_regimen_con_firmante};

pub(crate) fn config(dir: &Path, reloj: bool) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 407,
        indices_claves: vec![0, 1, 2],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: if reloj {
            perfil::perfil_red_dev_reloj().expect("perfil validado")
        } else {
            perfil::perfil_red_dev()
        },
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: Some(0),
        punto_control: None,
        sin_voto: true,
        sin_revelacion: true,
    }
}

pub(crate) fn nodo_corte(dir: &Path, reloj: bool) -> Nodo {
    let mut nodo = Nodo::arrancar(&config(dir, reloj)).expect("arranque real");
    nodo.fase_pow().expect("minado, depósitos y corte reales");
    assert!(nodo.cadena.terminal().is_some());
    nodo.asegurar_servicios_verificacion()
        .expect("servicios reales");
    nodo
}

fn a_red(bloque: &BloqueDag) -> BloqueRed {
    BloqueRed::Post {
        cabecera: bloque.cabecera,
        justificacion: bloque.justificacion.clone(),
        txs: bloque.txs().to_vec(),
        testigos: bloque.testigos().to_vec(),
    }
}

pub(crate) fn recibir(nodo: &mut Nodo, bloque: &BloqueDag) -> VeredictoFinal {
    nodo.intentar_admitir_bloque_red(
        &a_red(bloque),
        Some(libp2p::PeerId::random()),
        Instant::now(),
    )
}

/// Audita la parcela de la clave indicada y construye mediante el firmante de producción.
pub(crate) fn producir(
    nodo: &Nodo,
    servicio: &mut ServicioPot,
    padres: PadresDag,
    slot: u64,
    timestamp: u64,
    indice: usize,
    cuerpo: CuerpoProductor,
) -> BloqueDag {
    let clave = nodo.claves.get(indice).expect("clave configurada");
    let parcela = abrir_o_crear_parcela(&nodo.dir_datos, clave, &nodo.historia)
        .expect("parcela real y persistida");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &nodo.historia,
    };
    let parametros = ParametrosProductor {
        n_dev: nodo.n_dev_vigente(),
        sr_dev: u64::MAX,
        max_slots: slot,
        consensus_branch_id: nodo.cbid,
        timestamp,
        i_iter: nodo.perfil_red.reloj.i_iter,
        importe_coinbase: perfil::subsidio_post(0),
    };
    let registro = nodo
        .registro_firmante
        .as_ref()
        .expect("firmante persistente");
    let mut firmante = Firmante::nuevo(registro);
    match producir_en_regimen_con_firmante(
        padres,
        slot,
        servicio,
        &fuente,
        &clave.sk,
        &parametros,
        cuerpo,
        &mut firmante,
    )
    .expect("productor real")
    {
        ProductoFirmado::Bloque(b, _) => b,
        ProductoFirmado::Abstenido { motivo, .. } => panic!("oportunidad nueva: {motivo:?}"),
    }
}

pub(crate) fn oportunidad(
    nodo: &Nodo,
    servicio: &mut ServicioPot,
    desde: u64,
    hasta: u64,
    indices: &[usize],
) -> (u64, usize) {
    for slot in desde..=hasta {
        servicio.avanzar_hasta(slot).expect("PoT real");
        for indice in indices {
            // Índices de prueba que sobrepasan `claves` se saltan: los fixtures de `nodo_corte`
            // traen 3 claves y varios montajes piden `&[0, 1, 2, 3]` por si acaso.
            let Some(clave) = nodo.claves.get(*indice) else {
                continue;
            };
            let parcela =
                abrir_o_crear_parcela(&nodo.dir_datos, clave, &nodo.historia).expect("parcela");
            let fuente = FuenteTransicion {
                parcela: &parcela,
                historia: &nodo.historia,
            };
            if !fuente
                .soluciones(servicio.salida_de(slot).expect("salida"), slot, u64::MAX)
                .expect("PoAS real")
                .is_empty()
            {
                return (slot, *indice);
            }
        }
    }
    panic!("ninguna oportunidad en la cota declarada {desde}..={hasta}");
}

pub(crate) fn gana(nodo: &Nodo, servicio: &ServicioPot, slot: u64, indice: usize) -> bool {
    let clave = nodo.claves.get(indice).expect("clave");
    let parcela = abrir_o_crear_parcela(&nodo.dir_datos, clave, &nodo.historia).expect("parcela");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &nodo.historia,
    };
    !fuente
        .soluciones(servicio.salida_de(slot).expect("salida"), slot, u64::MAX)
        .expect("PoAS real")
        .is_empty()
}

/// La misma vuelta que usa fase_regimen, con el productor vivo pero sin mensajes ni tráfico.
fn vueltas_observador(nodo: &mut Nodo) {
    let (_tx_bucle, rx_bucle) = mpsc::channel();
    let (tx_productor, _rx_productor) = mpsc::channel();
    let mut terminal = nodo
        .cadena
        .terminal()
        .unwrap_or(nodo.historial_pow[0].block_hash());
    let mut frontera = 0;
    for _ in 0..10 {
        assert!(matches!(
            nodo.iteracion_regimen(&rx_bucle, &tx_productor, &mut terminal, &mut frontera)
                .expect("iteración real ociosa"),
            ControlBucle::Continuar
        ));
    }
}

pub(crate) fn texto(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("registro.jsonl")).expect("registro real")
}

fn pow_futuro(nodo: &Nodo, timestamp: u64) -> BloqueRed {
    let coinbase = pow::construir_coinbase_pow(nodo.claves[0].pk, 1);
    let target = zx_core::decodificar_con(
        PARAMETROS_POW_DEV.bits_iniciales,
        &PARAMETROS_POW_DEV.limites,
    )
    .expect("target dev");
    let cabecera = BlockHeader {
        consensus_branch_id: nodo.cbid,
        prev_hash: nodo.historial_pow[0].block_hash(),
        merkle_root: zx_core::preimage::block::merkle_root(&[zx_core::txid(&coinbase, nodo.cbid)]),
        timestamp,
        bits: PARAMETROS_POW_DEV.bits_iniciales,
        nonce: 0,
        height: 1,
    };
    let cabecera = minar(
        &cabecera,
        target,
        &Sha3Dev,
        u64::MAX,
        &AtomicBool::new(false),
    )
    .expect("PoW real");
    BloqueRed::Pow {
        cabecera,
        txs: vec![coinbase],
        testigos: vec![Vec::new()],
    }
}

fn caso_c03(exigir: bool) {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    let reloj = nodo.historial_pow.last().expect("corte real").timestamp + 1000;
    nodo.reloj_local_simulado = Some(reloj as i64);
    let bloque = pow_futuro(&nodo, reloj + 4);
    let hash = red::hash_de(&bloque);
    assert_eq!(
        nodo.intentar_admitir_bloque_red(&bloque, Some(libp2p::PeerId::random()), Instant::now()),
        VeredictoFinal::Ignorar
    );
    assert!(nodo.cadena.motivo(&hash).is_none());
    assert!(!nodo.headers_pow.contains_key(&hash));
    assert!(nodo.post_pendientes.is_empty());
    assert!(!texto(dir.path()).contains("\"tipo\":\"par_penalizado\""));
    nodo.reloj_local_simulado = Some((reloj + 4) as i64);
    vueltas_observador(&mut nodo);
    let automatico = nodo.cadena.es_valido(&hash);
    println!(
        "C03 hash={hash} reloj={reloj}->{} vueltas=10 automático={automatico}",
        reloj + 4
    );
    // Control alcanzable: los mismos bytes, segunda recepción, ninguna alteración del pasado. Si
    // el disparador por reloj ya lo admitió solo, la retransmisión es un duplicado `Ignorar`.
    let esperado = if automatico {
        VeredictoFinal::Ignorar
    } else {
        VeredictoFinal::Aceptar
    };
    assert_eq!(
        nodo.intentar_admitir_bloque_red(&bloque, Some(libp2p::PeerId::random()), Instant::now()),
        esperado
    );
    assert!(nodo.cadena.es_valido(&hash));
    if exigir {
        assert!(
            automatico,
            "C03: el avance del reloj debe recuperar el PoW sin retransmisión"
        );
    }
}

#[test]
fn dgcand_c03_retransmision_recupera_pow_sin_invalidar_ni_penalizar() {
    caso_c03(false);
}

#[test]
fn dgcand_c03_reloj_solo_debe_recuperar_pow() {
    caso_c03(true);
}

fn caso_c04_n04(exigir: bool, llenar: bool) {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), true);
    let terminal = nodo.cadena.terminal().expect("corte");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let ts = nodo.reloj_local() as u64 + zx_consensus::FTL_POST_DEV as u64 + 1;
    nodo.reloj_local_simulado = Some(ts as i64 - zx_consensus::FTL_POST_DEV - 1);
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 1, 150, &[0, 1, 2]);
    let bloque = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(terminal, &[]).expect("padre"),
        slot,
        ts,
        indice,
        CuerpoProductor::vacio(),
    );
    let hash = bloque.cabecera.block_hash();
    assert_eq!(recibir(&mut nodo, &bloque), VeredictoFinal::Ignorar);
    assert_eq!(nodo.post_pendientes.len(), 1);
    assert!(nodo.cadena.motivo(&hash).is_none());
    assert!(!texto(dir.path()).contains("\"tipo\":\"par_penalizado\""));
    if llenar {
        // Sin duplicados (RLJ-3b §2.3): 64 retransmisiones del mismo bloque dejan **una** entrada.
        for _ in 0..TOPE_POST_PENDIENTES {
            assert_eq!(recibir(&mut nodo, &bloque), VeredictoFinal::Ignorar);
        }
        assert_eq!(nodo.post_pendientes.len(), 1);
        // Un segundo hash distinto, también futuro: otra entrada. 64 copias no lo desalojan.
        let (otro_slot, otro_indice) = oportunidad(&nodo, &mut servicio, slot + 1, 150, &[0, 1, 2]);
        let otro = producir(
            &nodo,
            &mut servicio,
            PadresDag::nuevo(terminal, &[]).expect("padre"),
            otro_slot,
            ts + 1,
            otro_indice,
            CuerpoProductor::vacio(),
        );
        for _ in 0..TOPE_POST_PENDIENTES {
            assert_eq!(recibir(&mut nodo, &otro), VeredictoFinal::Ignorar);
        }
        assert_eq!(nodo.post_pendientes.len(), 2, "dos entradas, no 64 copias");
        assert!(
            nodo.post_pendientes
                .iter()
                .any(|(b, _)| b.cabecera.block_hash() == hash),
            "el primero sigue en la cola"
        );
        assert!(
            nodo.post_pendientes
                .iter()
                .any(|(b, _)| b.cabecera.block_hash() == otro.cabecera.block_hash()),
            "el segundo también"
        );
    }
    nodo.reloj_local_simulado = Some(ts as i64);
    vueltas_observador(&mut nodo);
    let automatico = nodo.cadena.es_valido(&hash);
    println!(
        "C04/N04 hash={hash} slot={slot} cola_llena={llenar} automático={automatico} cola={}",
        nodo.post_pendientes.len()
    );
    // Control: si el disparador por reloj no lo admitió solo, la retransmisión de los mismos bytes
    // lo recupera; si ya se admitió solo, la retransmisión es un duplicado `Ignorar`.
    let esperado = if automatico {
        VeredictoFinal::Ignorar
    } else {
        VeredictoFinal::Aceptar
    };
    assert_eq!(recibir(&mut nodo, &bloque), esperado);
    assert!(nodo.cadena.es_valido(&hash));
    if exigir {
        assert!(
            automatico,
            "C04/N04: reloj válido y vueltas ociosas deben recuperar el PoST"
        );
    }
}

#[test]
fn dgcand_c04_n04_retransmision_recupera_post_futuro() {
    caso_c04_n04(false, false);
}
#[test]
fn dgcand_n04_fifo_llena_y_retransmision_real() {
    caso_c04_n04(false, true);
}
#[test]
fn dgcand_c04_n04_reloj_solo_debe_recuperar_post() {
    caso_c04_n04(true, false);
}

#[test]
fn dgcand_n05_d0_admision_servicio_y_reinicio_alcanzables() {
    let dir = tempfile::tempdir().expect("directorio");
    let cfg = config(dir.path(), false);
    let mut nodo = nodo_corte(dir.path(), false);
    let terminal = nodo.cadena.terminal().expect("corte");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    // Las dos claves ganan en el mismo slot con parcelas auditadas. Ninguna salida se borra.
    let mut encontrada = None;
    for slot in 1..=150 {
        servicio.avanzar_hasta(slot).expect("PoT real");
        if gana(&nodo, &servicio, slot, 0) && gana(&nodo, &servicio, slot, 1) {
            encontrada = Some(slot);
            break;
        }
    }
    let slot = encontrada.expect("dos productores en el mismo slot");
    let ts = nodo.reloj_local() as u64;
    let padre = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(terminal, &[]).expect("terminal"),
        slot,
        ts,
        0,
        CuerpoProductor::vacio(),
    );
    assert_eq!(recibir(&mut nodo, &padre), VeredictoFinal::Aceptar);
    let padre_hash = padre.cabecera.block_hash();
    servicio = nodo.servicios_verificacion[&terminal].clone();
    let hijo = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(padre_hash, &[]).expect("padre real"),
        slot,
        ts,
        1,
        CuerpoProductor::vacio(),
    );
    assert!(hijo.justificacion.bundles().is_empty(), "d=0 real");
    let hash = hijo.cabecera.block_hash();
    assert_eq!(recibir(&mut nodo, &hijo), VeredictoFinal::Aceptar);
    assert!(nodo.cadena.es_valido(&hash));
    assert_eq!(
        nodo.servicios_verificacion[&terminal].slot_de(&hash),
        Some(slot)
    );
    assert_eq!(
        nodo.servicios_verificacion[&terminal]
            .salida_de(slot)
            .expect("salida"),
        hijo.cabecera.pot_output
    );
    let longitud = nodo.almacen.longitud_registro().expect("registro");
    drop(nodo);
    let mut reiniciado = Nodo::arrancar(&cfg).expect("repetición íntegra de disco");
    assert!(reiniciado.cadena.es_valido(&hash));
    assert_eq!(
        reiniciado.servicios_verificacion[&terminal].slot_de(&hash),
        Some(slot)
    );
    assert_eq!(
        reiniciado.almacen.longitud_registro().expect("registro"),
        longitud
    );
    assert_eq!(recibir(&mut reiniciado, &hijo), VeredictoFinal::Ignorar);
    println!(
        "N05 d=0 slot={slot} hash={hash} cadena/servicio/disco/reinicio coherentes, entradas={longitud}"
    );
}

fn caso_n03(exigir: bool) {
    let dir = tempfile::tempdir().expect("directorio");
    let nodo = nodo_corte(dir.path(), false);
    drop(nodo);
    let mut cfg = config(dir.path(), false);
    cfg.indices_claves.push(3);
    let mut nodo =
        Nodo::arrancar(&cfg).expect("importación real de clave mediante configuración de reinicio");
    let terminal = nodo.cadena.terminal().expect("terminal");
    let base = nodo.cadena.estado_terminal();
    let clave_nueva = nodo.claves[3].pk;
    assert_eq!(base.activo_de(&clave_nueva), zx_core::Amount::CERO);
    let (op, entrada, fuente_indice) = base
        .utxo
        .iter()
        .find_map(|(op, e)| {
            if let Lock::PubKey { pubkey } = e.lock {
                nodo.claves
                    .iter()
                    .position(|c| c.pk == pubkey && c.pk != clave_nueva)
                    .map(|i| (*op, e.clone(), i))
            } else {
                None
            }
        })
        .expect("UTXO real sin gastar de una clave propia");
    let fuente = &nodo.claves[fuente_indice];
    let (mut deposito, _) =
        pow::construir_deposito(op.prev_txid, entrada.valor, fuente, 0, nodo.cbid)
            .expect("depósito");
    assert_eq!(op.prev_index, 0);
    deposito.extension = ExtensionTx::Garantia {
        tipo: TipoGarantia::Deposito,
        clave: clave_nueva,
        importe: entrada.valor,
        nonce: 0,
    };
    let mut testigos =
        pow::testigos_deposito(&deposito, entrada.valor, fuente.pk, &fuente.sk, nodo.cbid)
            .expect("firma del UTXO real");
    let aceptacion: [u8; 64] = nodo.claves[3]
        .sk
        .sign(&zx_core::mensaje_aceptacion(&deposito, nodo.cbid))
        .into();
    *testigos.last_mut().expect("aceptación") = aceptacion.to_vec();
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let mut encontrada = None;
    for slot in 100..=140 {
        servicio.avanzar_hasta(slot).expect("PoT real");
        let mut futuro = servicio.clone();
        futuro
            .avanzar_hasta(slot + nodo.params.m_dep_slots)
            .expect("PoT de la madurez");
        if gana(&nodo, &futuro, slot + nodo.params.m_dep_slots, 3)
            && let Some(indice) = (0..3).find(|i| gana(&nodo, &servicio, slot, *i))
        {
            encontrada = Some((slot, indice));
            break;
        }
    }
    let (slot, indice) = encontrada.expect("oportunidad en la madurez exacta");
    let primer = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(terminal, &[]).expect("terminal"),
        slot,
        nodo.reloj_local() as u64,
        indice,
        CuerpoProductor::nuevo(vec![deposito], vec![testigos]).expect("cuerpo"),
    );
    assert_eq!(recibir(&mut nodo, &primer), VeredictoFinal::Aceptar);
    let h = primer.cabecera.block_hash();
    assert!(
        nodo.cadena.descartes(&h).expect("descartes").is_empty(),
        "depósito aplicado, no descartado"
    );
    let estado = nodo.cadena.estado_post(&h).expect("estado");
    assert_eq!(estado.activo_de(&clave_nueva), zx_core::Amount::CERO);
    let madurez = estado.garantias[&clave_nueva]
        .pendientes
        .first()
        .expect("pendiente aplicado")
        .madura_en_slot
        .expect("slot");
    assert_eq!(madurez, slot + nodo.params.m_dep_slots);
    let (tx, rx) = mpsc::channel();
    nodo.atender_msg_productor(
        MsgProductor::PeticionPadres {
            id: 0,
            slot: madurez,
        },
        false,
        terminal,
        &tx,
    )
    .expect("intercambio real");
    let respuesta = rx.try_recv().expect("respuesta real");
    let MsgBucle::Padres {
        con_garantia,
        padres,
        ..
    } = &respuesta
    else {
        panic!("Padres");
    };
    let enviada = con_garantia.contains(&clave_nueva);
    let padres = *padres;
    let mut servicio_hilo = nodo.servicios_verificacion[&terminal].clone();
    servicio_hilo
        .avanzar_hasta(madurez - 1)
        .expect("frontera real anterior a la madurez");
    let propia = nodo.claves[3].clone();
    let parcela =
        abrir_o_crear_parcela(&nodo.dir_datos, &propia, &nodo.historia).expect("parcela propia");
    let historia = Arc::clone(&nodo.historia);
    let registro = Arc::clone(&nodo.registro);
    let cbid = nodo.cbid;
    let (tx_hilo, rx_hilo) = mpsc::channel();
    let (tx_mensajes, rx_mensajes) = mpsc::channel();
    let hilo = thread::spawn(move || {
        hilo_productor_regimen(
            servicio_hilo,
            u64::MAX,
            cbid,
            perfil::subsidio_post(0),
            vec![ClavePublicaConParcela {
                indice: propia.indice,
                pk: propia.pk,
                parcela,
            }],
            &historia,
            Some(madurez),
            &rx_hilo,
            &tx_mensajes,
            &registro,
        );
    });
    let peticion = rx_mensajes
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("petición del hilo real");
    assert!(matches!(peticion, MsgProductor::PeticionPadres { id: 0, slot } if slot == madurez));
    tx_hilo
        .send(respuesta)
        .expect("Padres real al productor real");
    // PROD-3b: el hilo manda la candidata **sin sello**; el bloque admitido se firma en el bucle.
    // Aquí basta saber si el hilo llegó a armarla (la clave estaba en `con_garantia`).
    let producido = match rx_mensajes.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(MsgProductor::Candidata { candidata, .. }) => {
            tx_hilo.send(MsgBucle::Parar).expect("parada del productor");
            Some(*candidata)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => None,
        _ => panic!("el productor debe terminar el slot o entregar su candidata"),
    };
    hilo.join().expect("hilo real recogido");
    if !enviada {
        assert!(
            producido.is_none(),
            "abstención real por la respuesta del nodo"
        );
        assert!(texto(dir.path()).contains("\"tipo\":\"produccion_sin_garantia\""));
    }
    servicio = nodo.servicios_verificacion[&terminal].clone();
    // Asegurar oportunidad en la madurez exacta, no una garantía inventada.
    oportunidad(&nodo, &mut servicio, madurez, madurez, &[3]);
    // El bloque de control se sella por la vía de la prueba (el hilo ya no firma). La aserción
    // es que la cadena promueve el depósito al slot real.
    let _candidata_del_hilo = producido;
    let bloque = producir(
        &nodo,
        &mut servicio,
        padres,
        madurez,
        nodo.reloj_local() as u64,
        3,
        CuerpoProductor::vacio(),
    );
    assert_eq!(
        recibir(&mut nodo, &bloque),
        VeredictoFinal::Aceptar,
        "la cadena promueve el depósito al slot real"
    );
    assert!(
        nodo.cadena
            .estado_post(&bloque.cabecera.block_hash())
            .expect("estado admitido")
            .activo_de(&clave_nueva)
            >= nodo.params.q
    );
    println!(
        "N03 depósito={} slot_base={slot} madurez={madurez} activo_base=0 q={} clave_enviada={enviada} bloque_control=ACEPTADO",
        entrada.valor.brek(),
        nodo.params.q.brek()
    );
    if exigir {
        assert!(
            enviada,
            "N03: Padres debe permitir la clave cuya garantía madura en el slot objetivo"
        );
    }
}

#[test]
fn dgcand_n03_deposito_firmado_maduro_admitido_por_cadena() {
    caso_n03(false);
}
#[test]
fn dgcand_n03_padres_debe_incluir_garantia_que_madura_en_slot() {
    caso_n03(true);
}

/// C06: terminales y sufijos con PoW/PoAS/PoT reales; ningún DAG se borra a mano.
#[test]
fn dgcand_c06_noveno_terminal_recepcion_retransmision_y_cola_llena() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    let original = *nodo.historial_pow.last().expect("terminal minado");
    let original_hash = original.block_hash();
    let cuerpos = nodo.vista_red.bloques_por_hash(&[original_hash]);
    let BloqueRed::Pow { txs, testigos, .. } = cuerpos.first().expect("cuerpo de red real") else {
        panic!("PoW");
    };
    let txs = txs.clone();
    let testigos = testigos.clone();
    let target =
        zx_core::decodificar_con(original.bits, &PARAMETROS_POW_DEV.limites).expect("target real");
    nodo.reloj_local_simulado = Some(original.timestamp as i64 + 1000);
    let mut terminales = vec![original_hash];
    for i in 1..9 {
        let mut cabecera = original;
        cabecera.timestamp += i;
        cabecera.nonce = 0;
        let cabecera = minar(
            &cabecera,
            target,
            &Sha3Dev,
            u64::MAX,
            &AtomicBool::new(false),
        )
        .expect("rama PoW real");
        let hash = cabecera.block_hash();
        let bloque = BloqueRed::Pow {
            cabecera,
            txs: txs.clone(),
            testigos: testigos.clone(),
        };
        assert_eq!(
            nodo.intentar_admitir_bloque_red(
                &bloque,
                Some(libp2p::PeerId::random()),
                Instant::now()
            ),
            VeredictoFinal::Aceptar
        );
        assert!(nodo.cadena.terminal_candidatos().contains(&hash));
        assert_eq!(
            nodo.cadena.trabajo_pow(&hash),
            nodo.cadena.trabajo_pow(&original_hash)
        );
        terminales.push(hash);
    }
    let mut noveno = None;
    for (i, terminal) in terminales.iter().copied().enumerate() {
        nodo.asegurar_servicios_verificacion()
            .expect("servicio creado por el nodo");
        let mut servicio = nodo.servicios_verificacion[&terminal].clone();
        let desde = 1 + i as u64 * 5;
        let (slot, indice) = oportunidad(&nodo, &mut servicio, desde, desde + 4, &[0, 1, 2]);
        let bloque = producir(
            &nodo,
            &mut servicio,
            PadresDag::nuevo(terminal, &[]).expect("terminal"),
            slot,
            original.timestamp + 10,
            indice,
            CuerpoProductor::vacio(),
        );
        let esperado = if i < zx_cadena::MAX_TERMINALES_CON_DAG {
            VeredictoFinal::Aceptar
        } else {
            VeredictoFinal::Ignorar
        };
        assert_eq!(recibir(&mut nodo, &bloque), esperado);
        if i == zx_cadena::MAX_TERMINALES_CON_DAG {
            noveno = Some(bloque);
        }
    }
    let noveno = noveno.expect("noveno");
    let hash = noveno.cabecera.block_hash();
    assert_eq!(
        nodo.cadena.terminales_con_dag().len(),
        zx_cadena::MAX_TERMINALES_CON_DAG
    );
    assert!(nodo.cadena.motivo(&hash).is_none());
    assert!(!nodo.cadena.es_valido(&hash));
    assert!(
        nodo.post_pendientes.is_empty(),
        "VistaLocal no se encola en post_pendientes"
    );
    assert_eq!(recibir(&mut nodo, &noveno), VeredictoFinal::Ignorar);
    let clave = nodo
        .claves
        .iter()
        .find(|c| c.pk == noveno.cabecera.sol.public_key)
        .expect("clave dev de la oportunidad original");
    let clave = clave.sk;
    for i in 0..zx_cadena::cadena::MAX_PENDIENTES_TOPE {
        // Tráfico adversarial: misma prueba real y firma válida, cabeceras distintas.
        // El productor honrado no dobla su firma; aquí solo se construyen entradas de red.
        let mut cabecera = noveno.cabecera;
        cabecera.timestamp += i as u64 + 1;
        cabecera.sello = clave.sign(cabecera.pre_hash().as_bytes()).into();
        let otro = BloqueDag::nuevo(
            cabecera,
            noveno.justificacion.clone(),
            noveno.txs().to_vec(),
            noveno.testigos().to_vec(),
        )
        .expect("entrada de forma válida con prueba y sello reales");
        assert_eq!(recibir(&mut nodo, &otro), VeredictoFinal::Ignorar);
        if (i + 1).is_multiple_of(8) {
            println!("C06 entradas distintas por tope: {}", i + 1);
        }
    }
    assert_eq!(recibir(&mut nodo, &noveno), VeredictoFinal::Ignorar);
    assert!(nodo.cadena.motivo(&hash).is_none());
    assert!(nodo.post_pendientes.is_empty());
    assert!(!texto(dir.path()).contains("\"tipo\":\"par_penalizado\""));
    let minimo_antes = nodo
        .cadena
        .terminales_con_dag()
        .iter()
        .map(|t| {
            nodo.cadena
                .trabajo_pow(t)
                .expect("trabajo fijo del terminal")
        })
        .min()
        .expect("ocho terminales");
    let historico = tempfile::tempdir().expect("emisor de historia real");
    println!("C06 cola ejercida; comienza rama histórica con mayor trabajo");
    let mut cfg = config(historico.path(), false);
    cfg.semilla = 408;
    let mut emisor = Nodo::arrancar(&cfg).expect("emisor independiente");
    let genesis_ts = emisor.historial_pow[0].timestamp;
    emisor.reloj_local_simulado = Some(genesis_ts as i64 + 10_000);
    // Solo se decide la entrada histórica; target, depósitos, PoW y admisión son del producto.
    for altura in 1..=perfil::H_CORTE_MIN {
        let ultimo = *emisor.historial_pow.last().expect("historial");
        let depositos = emisor
            .preparar_depositos(altura)
            .expect("depósitos firmados del producto");
        let indice = altura.saturating_sub(1) as usize % emisor.claves.len();
        let (plantilla, _, _) = pow::construir_plantilla(
            &emisor.historial_pow,
            ultimo.block_hash(),
            altura,
            ultimo.timestamp + 1,
            emisor.cbid,
            emisor.claves[indice].pk,
            depositos,
            emisor.params.max_cuerpo_bloque_bytes,
        )
        .expect("plantilla contextual real");
        let cabecera = minar(
            &plantilla.cabecera_base,
            plantilla.target,
            &Sha3Dev,
            u64::MAX,
            &AtomicBool::new(false),
        )
        .expect("trabajo histórico real");
        let bloque = BloqueRed::Pow {
            cabecera,
            txs: plantilla.txs.clone(),
            testigos: plantilla.testigos.clone(),
        };
        emisor
            .admitir_pow_interno(
                cabecera,
                plantilla.txs,
                plantilla.testigos,
                emisor.almacen.longitud_registro().expect("índice"),
                true,
                true,
            )
            .expect("validación integral del emisor");
        assert_eq!(
            nodo.intentar_admitir_bloque_red(
                &bloque,
                Some(libp2p::PeerId::random()),
                Instant::now()
            ),
            VeredictoFinal::Aceptar
        );
    }
    let fuerte = emisor.cadena.terminal().expect("corte histórico real");
    assert!(emisor.cadena.trabajo_pow(&fuerte).expect("trabajo") > minimo_antes);
    emisor
        .asegurar_servicios_verificacion()
        .expect("servicio del nuevo terminal");
    let mut servicio = emisor.servicios_verificacion[&fuerte].clone();
    let (slot, indice) = oportunidad(&emisor, &mut servicio, 1, 150, &[0, 1, 2]);
    let bloque_fuerte = producir(
        &emisor,
        &mut servicio,
        PadresDag::nuevo(fuerte, &[]).expect("terminal"),
        slot,
        original.timestamp + 10,
        indice,
        CuerpoProductor::vacio(),
    );
    assert_eq!(recibir(&mut nodo, &bloque_fuerte), VeredictoFinal::Aceptar);
    assert!(nodo.cadena.terminales_con_dag().contains(&fuerte));
    assert_eq!(
        nodo.cadena.terminales_con_dag().len(),
        zx_cadena::MAX_TERMINALES_CON_DAG
    );
    let minimo_despues = nodo
        .cadena
        .terminales_con_dag()
        .iter()
        .map(|t| nodo.cadena.trabajo_pow(t).expect("trabajo"))
        .min()
        .expect("ocho terminales tras desalojo");
    assert!(minimo_despues >= minimo_antes);
    assert_eq!(recibir(&mut nodo, &noveno), VeredictoFinal::Ignorar);
    assert!(!nodo.cadena.es_valido(&hash));
    assert!(nodo.cadena.motivo(&hash).is_none());
    println!(
        "C06 desalojo efectivo: mínimo {minimo_antes}->{minimo_despues}, nuevo terminal trabajo={}, noveno sigue no incorporable",
        emisor.cadena.trabajo_pow(&fuerte).expect("trabajo")
    );
    println!(
        "C06 9 terminales reales, 8 DAG, trabajo igual; noveno Ignorar; cola_tope={} retransmisión Ignorar, caché inválida=0",
        zx_cadena::cadena::MAX_PENDIENTES_TOPE
    );
}

fn copiar_arbol(origen: &Path, destino: &Path) {
    std::fs::create_dir_all(destino).expect("destino local");
    for entrada in std::fs::read_dir(origen).expect("listar fixture propia") {
        let entrada = entrada.expect("entrada");
        let desde = entrada.path();
        let hasta = destino.join(entrada.file_name());
        if entrada.file_type().expect("tipo").is_dir() {
            copiar_arbol(&desde, &hasta);
        } else {
            std::fs::copy(&desde, &hasta).expect("copia de fixture propia, con nodo cerrado");
        }
    }
}

// Usa el ancla que la validación de banda lee del servicio real, sin modificar sus timestamps.
fn timestamp_c12(nodo: &Nodo, terminal: BlockHash, slot: u64) -> u64 {
    let ventana = nodo.servicios_verificacion[&terminal].ventana_timestamps(0, slot - 1);
    let ancla = ventana.first().map_or_else(
        || nodo.historial_pow.last().expect("terminal PoW").timestamp,
        |(_, timestamp)| *timestamp,
    );
    ancla + slot + slot.div_euclid(400)
}

/// Prepara una historia persistida sin acortar N, A, F o la ventana de PoT.
/// Cada tramo se ejecuta en una invocación separada con sus dos candados y tope de 600s.
fn preparar_c12(raiz: &Path, hasta: u64) {
    let mut nodo = nodo_corte(raiz, true);
    let terminal = nodo.cadena.terminal().expect("terminal");
    let ancla = nodo.historial_pow.last().expect("terminal PoW").timestamp;
    nodo.reloj_local_simulado = Some(ancla as i64 + 10_000);
    for objetivo in [
        100, 200, 300, 400, 500, 600, 664, 800, 900, 1000, 1100, 1200, 1300,
    ] {
        let actual = nodo.servicios_verificacion[&terminal].slot_actual();
        if objetivo > hasta || objetivo <= actual {
            continue;
        }
        let mut servicio = nodo.servicios_verificacion[&terminal].clone();
        let desde = objetivo.max(
            nodo.registro_firmante
                .as_ref()
                .expect("registro real")
                .max_slot()
                .saturating_add(1),
        );
        let (slot, indice) = oportunidad(&nodo, &mut servicio, desde, desde + 4, &[0, 1, 2]);
        let padre = *nodo.cadena.tips_validas().first().unwrap_or(&terminal);
        let bloque = producir(
            &nodo,
            &mut servicio,
            PadresDag::nuevo(padre, &[]).expect("cadena sin hermanos"),
            slot,
            timestamp_c12(&nodo, terminal, slot),
            indice,
            CuerpoProductor::vacio(),
        );
        assert_eq!(
            recibir(&mut nodo, &bloque),
            VeredictoFinal::Aceptar,
            "prefijo alcanzable del reloj"
        );
        println!(
            "C12 preparación slot={slot} F={:?} calendario={:?}",
            nodo.cadena.slot_finalidad(),
            nodo.servicios_verificacion[&terminal].calendario()
        );
    }
    assert!(nodo.servicios_verificacion[&terminal].slot_actual() >= hasta);
    drop(nodo);
    if hasta == 1200 {
        let retrasado = raiz.with_file_name("c12-retrasado");
        assert!(!retrasado.exists(), "snapshot tomada una sola vez");
        copiar_arbol(raiz, &retrasado);
    }
}

fn pasado_lineal(nodo: &Nodo, mut hash: BlockHash, terminal: BlockHash) -> Vec<BlockHash> {
    let mut pasado = Vec::new();
    while hash != terminal {
        pasado.push(hash);
        let Some(BloqueCadena::Post(b)) = nodo.cadena.bloque(&hash) else {
            panic!("ancestro PoST");
        };
        assert_eq!(b.padres.len(), 1);
        hash = b.padres[0];
    }
    pasado.push(terminal);
    pasado
}

fn caso_c12(raiz: &Path, exigir: bool) {
    let atrasado = raiz.with_file_name("c12-retrasado");
    let local = tempfile::tempdir().expect("copias propias de fixtures cerradas");
    let copia_avanzado = local.path().join("avanzado");
    let copia_retrasado = local.path().join("retrasado");
    copiar_arbol(raiz, &copia_avanzado);
    copiar_arbol(&atrasado, &copia_retrasado);
    let mut avanzado =
        Nodo::arrancar(&config(&copia_avanzado, true)).expect("historia avanzada persistida");
    let mut retrasado =
        Nodo::arrancar(&config(&copia_retrasado, true)).expect("snapshot alcanzable anterior");
    let terminal = avanzado.cadena.terminal().expect("terminal");
    assert_eq!(retrasado.cadena.terminal(), Some(terminal));
    let ancla = avanzado.historial_pow.last().expect("PoW").timestamp;
    avanzado.reloj_local_simulado = Some(ancla as i64 + 10_000);
    retrasado.reloj_local_simulado = avanzado.reloj_local_simulado;
    let padre = *retrasado
        .cadena
        .tips_validas()
        .first()
        .expect("punta anterior");
    let past = pasado_lineal(&retrasado, padre, terminal);
    for h in &past {
        assert!(avanzado.cadena.es_valido(h));
        let bytes_avanzado = avanzado
            .vista_red
            .bloques_por_hash(&[*h])
            .iter()
            .map(zx_p2p::codec::bloque_a_bytes)
            .collect::<Vec<_>>();
        let bytes_retrasado = retrasado
            .vista_red
            .bloques_por_hash(&[*h])
            .iter()
            .map(zx_p2p::codec::bloque_a_bytes)
            .collect::<Vec<_>>();
        assert_eq!(bytes_avanzado.len(), 1, "ancestro avanzado presente");
        assert_eq!(bytes_retrasado.len(), 1, "ancestro retrasado presente");
        assert_eq!(
            bytes_avanzado, bytes_retrasado,
            "mismos bytes de cada ancestro"
        );
    }
    let final_av = avanzado.cadena.slot_finalidad();
    let final_ret = retrasado.cadena.slot_finalidad();
    let desde_ajuste = 2 * avanzado.perfil_red.reloj.a_epoch;
    assert!(final_ret.expect("F anterior") < avanzado.perfil_red.reloj.a_epoch);
    assert!(final_av.expect("F avanzado") >= avanzado.perfil_red.reloj.a_epoch);
    let n_av = avanzado.servicios_verificacion[&terminal].n_vigente(desde_ajuste);
    let n_ret = retrasado.servicios_verificacion[&terminal].n_vigente(desde_ajuste);
    assert_ne!(
        n_av, n_ret,
        "calendarios diferentes, derivados de finales alcanzables"
    );
    let mut servicio = avanzado.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(
        &avanzado,
        &mut servicio,
        desde_ajuste,
        desde_ajuste + 4,
        &[0, 1, 2],
    );
    let bloque = producir(
        &avanzado,
        &mut servicio,
        PadresDag::nuevo(padre, &[]).expect("mismo pasado"),
        slot,
        timestamp_c12(&avanzado, terminal, slot),
        indice,
        CuerpoProductor::vacio(),
    );
    let hash = bloque.cabecera.block_hash();
    let ver_ret = recibir(&mut retrasado, &bloque);
    let ver_av = recibir(&mut avanzado, &bloque);
    for linea in texto(&copia_retrasado).lines() {
        if linea.contains(&hash.to_string()) && linea.contains("motivo") {
            println!("C12 diagnóstico literal: {linea}");
        }
    }
    assert_eq!(
        ver_av,
        VeredictoFinal::Aceptar,
        "control: cadena/servicio con ajuste comprometido"
    );
    assert!(
        retrasado.cadena.motivo(&hash).is_none(),
        "el rechazo de cabecera no deja motivo permanente en Cadena"
    );
    let pendiente = retrasado
        .post_pendientes
        .iter()
        .any(|(b, _)| b.cabecera.block_hash() == hash);
    vueltas_observador(&mut retrasado);
    let automatico = retrasado.cadena.es_valido(&hash);
    println!(
        "C12 mismo_hash={hash} past={past:?} F={final_ret:?}/{final_av:?} slot={slot} N={n_ret}/{n_av} veredicto={ver_ret:?}/{ver_av:?} pendiente={pendiente} automático={automatico}"
    );
    // Completar el contexto con el bloque real de slot 1300 del avanzado, sin cambiar B.
    let extra = avanzado
        .cadena
        .bloques_post()
        .into_iter()
        .find(|b| b.slot >= 1300 && b.slot < slot)
        .expect("bloque que compromete el ajuste")
        .hash;
    let extras = avanzado.vista_red.bloques_por_hash(&[extra]);
    let extra = extras.first().expect("bytes del contexto");
    assert_eq!(
        retrasado.intentar_admitir_bloque_red(
            extra,
            Some(libp2p::PeerId::random()),
            Instant::now()
        ),
        VeredictoFinal::Aceptar
    );
    let recuperado_por_contexto = retrasado.cadena.es_valido(&hash);
    let retransmision = recibir(&mut retrasado, &bloque);
    assert_eq!(
        retransmision,
        if recuperado_por_contexto {
            VeredictoFinal::Ignorar
        } else {
            VeredictoFinal::Aceptar
        },
        "contexto real recupera automáticamente el pendiente o permite retransmitirlo"
    );
    assert!(retrasado.cadena.es_valido(&hash));
    println!(
        "C12 contexto añadido: automático={recuperado_por_contexto}, retransmisión={retransmision:?}"
    );
    if exigir {
        assert_ne!(
            ver_ret,
            VeredictoFinal::Rechazar,
            "C12: la falta local de calendario debe diferir, sin penalizar al par honrado"
        );
    }
}

/// Invocar DGCAND_C12_TRAMO=100,200,... y 664,800,...,1200,1300 para preparar; después sin TRAMO.
#[test]
#[ignore = "DG-CAND C12: falla hoy"]
fn dgcand_c12_contexto_finalizado_debe_diferir_sin_rechazar() {
    let raiz = PathBuf::from(
        std::env::var("DGCAND_C12_DIR")
            .expect("directorio local de fixture incremental; véase INFORME"),
    );
    if let Ok(tramo) = std::env::var("DGCAND_C12_TRAMO") {
        preparar_c12(&raiz, tramo.parse().expect("slot final del tramo"));
    } else {
        caso_c12(&raiz, true);
    }
}

/// N05: admisión, discrepancia y replay reales, en invocaciones separadas de hasta 600s.
#[test]
#[ignore = "DG-CAND N05: falla hoy"]
fn dgcand_n05_actualizacion_tras_admision_debe_ser_coherente_y_reiniciar() {
    let raiz = PathBuf::from(std::env::var("DGCAND_C12_DIR").expect("fixture incremental real"));
    let antiguo = std::env::var("DGCAND_N05_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| raiz.with_file_name("n05-antiguo"));
    let fase = std::env::var("DGCAND_N05_FASE").unwrap_or_else(|_| "incoherencia".to_string());
    let cfg_antiguo = config(&antiguo, true);
    if fase == "reinicio" {
        let reinicio = Nodo::arrancar(&cfg_antiguo);
        if let Err(e) = &reinicio {
            println!("N05 reinicio real falla: {e}");
        }
        assert!(
            reinicio.is_ok(),
            "N05: el registro admitido y persistido debe permitir reiniciar"
        );
        return;
    }
    if fase == "viejo" {
        assert!(!antiguo.exists(), "fixture propia preparada una sola vez");
        copiar_arbol(&raiz.with_file_name("c12-retrasado"), &antiguo);
        let mut atrasado = Nodo::arrancar(&cfg_antiguo).expect("historia antigua alcanzable");
        let terminal = atrasado.cadena.terminal().expect("terminal");
        let padre = *atrasado.cadena.tips_validas().first().expect("padre común");
        let ancla = atrasado.historial_pow.last().expect("PoW").timestamp;
        atrasado.reloj_local_simulado = Some(ancla as i64 + 10_000);
        let desde = 2 * atrasado.perfil_red.reloj.a_epoch;
        let n_antiguo = atrasado.servicios_verificacion[&terminal].n_vigente(desde);
        let mut servicio = atrasado.servicios_verificacion[&terminal].clone();
        let (slot, indice) = oportunidad(&atrasado, &mut servicio, desde, desde + 4, &[0, 1, 2]);
        let viejo = producir(
            &atrasado,
            &mut servicio,
            PadresDag::nuevo(padre, &[]).expect("padre común"),
            slot,
            timestamp_c12(&atrasado, terminal, slot),
            indice,
            CuerpoProductor::vacio(),
        );
        assert_eq!(recibir(&mut atrasado, &viejo), VeredictoFinal::Aceptar);
        let n_despues = atrasado.servicios_verificacion[&terminal].n_vigente(desde);
        assert_ne!(n_antiguo, n_despues, "la admisión compromete el ajuste");
        println!(
            "N05 preparación real: N={n_antiguo}->{n_despues} viejo_slot={slot} viejo_hash={} padre={padre} cadena/disco/servicio admitidos",
            viejo.cabecera.block_hash()
        );
        return;
    }
    assert_eq!(fase, "incoherencia", "fase explícita de la reproducción");
    let local = tempfile::tempdir().expect("productor independiente");
    let nuevo = local.path().join("nuevo");
    copiar_arbol(&raiz, &nuevo);
    let mut atrasado = Nodo::arrancar(&cfg_antiguo).expect("replay del bloque N antiguo admitido");
    let mut productor = Nodo::arrancar(&config(&nuevo, true)).expect("historia nueva alcanzable");
    let terminal = atrasado.cadena.terminal().expect("terminal");
    assert_eq!(productor.cadena.terminal(), Some(terminal));
    let desde = 2 * atrasado.perfil_red.reloj.a_epoch;
    let padre = atrasado
        .cadena
        .bloques_post()
        .into_iter()
        .filter(|b| b.slot < desde)
        .max_by_key(|b| b.slot)
        .expect("padre común anterior al ajuste")
        .hash;
    assert!(productor.cadena.es_valido(&padre));
    let slot_viejo = atrasado
        .cadena
        .bloques_post()
        .into_iter()
        .map(|b| b.slot)
        .max()
        .expect("bloque antiguo persistido");
    assert!((desde..=desde + 4).contains(&slot_viejo));
    let n_nuevo = productor.servicios_verificacion[&terminal].n_vigente(desde);
    assert_eq!(
        atrasado.servicios_verificacion[&terminal].n_vigente(desde),
        n_nuevo
    );
    let ancla = atrasado.historial_pow.last().expect("PoW").timestamp;
    atrasado.reloj_local_simulado = Some(ancla as i64 + 10_000);
    productor.reloj_local_simulado = atrasado.reloj_local_simulado;
    let mut servicio = productor.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(
        &productor,
        &mut servicio,
        slot_viejo + 10,
        slot_viejo + 14,
        &[0, 1, 2],
    );
    let bloque = producir(
        &productor,
        &mut servicio,
        PadresDag::nuevo(padre, &[]).expect("mismo padre común"),
        slot,
        timestamp_c12(&productor, terminal, slot),
        indice,
        CuerpoProductor::vacio(),
    );
    let hash = bloque.cabecera.block_hash();
    assert_eq!(
        recibir(&mut productor, &bloque),
        VeredictoFinal::Aceptar,
        "control: N nuevo admite y reconcilia en su nodo"
    );
    let longitud = atrasado.almacen.longitud_registro().expect("antes");
    let veredicto = recibir(&mut atrasado, &bloque);
    let admitido = atrasado.cadena.es_valido(&hash);
    let registrado = atrasado.servicios_verificacion[&terminal].slot_de(&hash);
    let longitud_despues = atrasado.almacen.longitud_registro().expect("después");
    let duplicado = recibir(&mut atrasado, &bloque);
    for linea in texto(&antiguo).lines() {
        if linea.contains(&hash.to_string()) && linea.contains("motivo") {
            println!("N05 diagnóstico literal: {linea}");
        }
    }
    println!(
        "N05 N_nuevo={n_nuevo} viejo_slot={slot_viejo} nuevo_slot={slot} hash={hash} veredicto={veredicto:?} cadena={admitido} servicio={registrado:?} disco={longitud}->{longitud_despues} duplicado={duplicado:?}"
    );
    // Cerrar el almacén antes del rojo: la siguiente invocación ejercita su replay real.
    drop(atrasado);
    assert!(
        !admitido || registrado == Some(slot),
        "N05: admitir y persistir debe registrar el bloque en su servicio de tiempo"
    );
}

#[test]
fn dgcand_n04_reloj_solo_debe_recuperar_post_desalojado() {
    caso_c04_n04(true, true);
}

// ─── RLJ-3b §3 · pruebas nuevas B1–B4 por el camino real ────────────────────────────────────────

/// Construye el primer bloque futuro que deja un pendiente `FTL`, como `caso_c04_n04`.
fn bloque_futuro_pendiente(nodo: &mut Nodo, servicio: &mut ServicioPot) -> (BloqueDag, u64) {
    let terminal = nodo.cadena.terminal().expect("corte");
    let ts = nodo.reloj_local() as u64 + zx_consensus::FTL_POST_DEV as u64 + 1;
    let (slot, indice) = oportunidad(nodo, servicio, 1, 150, &[0, 1, 2]);
    let bloque = producir(
        nodo,
        servicio,
        PadresDag::nuevo(terminal, &[]).expect("padre"),
        slot,
        ts,
        indice,
        CuerpoProductor::vacio(),
    );
    (bloque, ts)
}

/// B1 (camino real): con un pendiente que aún no vence, cien vueltas del bucle no verifican.
#[test]
fn b1_camino_real_sin_vencer_no_verifica() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), true);
    let terminal = nodo.cadena.terminal().expect("corte");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (bloque, ts) = bloque_futuro_pendiente(&mut nodo, &mut servicio);
    // Reloj por debajo del vencimiento: el bloque se encola con `Ftl` (no con contexto).
    nodo.reloj_local_simulado = Some(ts as i64 - zx_consensus::FTL_POST_DEV - 1);
    assert_eq!(recibir(&mut nodo, &bloque), VeredictoFinal::Ignorar);
    assert_eq!(nodo.post_pendientes.len(), 1);
    assert!(matches!(
        nodo.post_pendientes
            .iter_entradas()
            .next()
            .expect("entrada")
            .motivo(),
        crate::pendientes::MotivoEspera::Ftl { .. }
    ));
    let antes = nodo.post_pendientes.verificaciones();
    for _ in 0..10 {
        vueltas_observador(&mut nodo);
    }
    assert_eq!(
        nodo.post_pendientes.verificaciones(),
        antes,
        "cien vueltas sin vencimiento no ejecutan ninguna verificación"
    );
    assert_eq!(nodo.post_pendientes.len(), 1);
    assert!(!nodo.cadena.es_valido(&bloque.cabecera.block_hash()));
}

/// B2 (camino real): un pendiente por contexto no se reintenta por tiempo.
#[test]
fn b2_camino_real_contexto_no_se_reintenta_por_reloj() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), true);
    let terminal = nodo.cadena.terminal().expect("corte");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (bloque, ts) = bloque_futuro_pendiente(&mut nodo, &mut servicio);
    nodo.encolar_post_pendiente_con(
        bloque,
        Instant::now(),
        crate::pendientes::MotivoEspera::Contexto,
    );
    assert_eq!(nodo.post_pendientes.len(), 1);
    nodo.reloj_local_simulado = Some(ts as i64 + 10_000_000);
    let antes = nodo.post_pendientes.verificaciones();
    for _ in 0..10 {
        vueltas_observador(&mut nodo);
    }
    assert_eq!(nodo.post_pendientes.verificaciones(), antes);
    assert_eq!(nodo.post_pendientes.len(), 1);
}

/// B3 (camino real): un pendiente por `FTL` que al vencer resulta inválido se descarta sin
/// penalizar y sin quedar en la cola.
#[test]
fn b3_camino_real_ftl_vencido_invalido_se_descarta() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), true);
    let terminal = nodo.cadena.terminal().expect("corte");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (mut bloque, ts) = bloque_futuro_pendiente(&mut nodo, &mut servicio);
    // PoAS corrupto: al reintentar por reloj, la admisión es un rechazo permanente, no `Pendiente`.
    bloque.cabecera.sol = SolucionPoas::default();
    let hash = bloque.cabecera.block_hash();
    nodo.encolar_post_pendiente_con(
        bloque,
        Instant::now(),
        crate::pendientes::MotivoEspera::Ftl {
            vence: ts as i64 - zx_consensus::FTL_POST_DEV,
        },
    );
    assert_eq!(nodo.post_pendientes.len(), 1);
    nodo.reloj_local_simulado = Some(ts as i64);
    vueltas_observador(&mut nodo);
    assert!(
        nodo.post_pendientes.is_empty(),
        "un FTL vencido e inválido se descarta sin quedar en la cola"
    );
    assert!(!nodo.cadena.es_valido(&hash));
    assert!(!texto(dir.path()).contains("\"tipo\":\"par_penalizado\""));
}

/// B4 (camino real): la cola de PoW nunca pasa de su tope con 200 bloques futuros distintos y no
/// admite duplicados.
#[test]
fn b4_camino_real_pow_tope_y_sin_duplicados() {
    let dir = tempfile::tempdir().expect("directorio");
    let mut nodo = nodo_corte(dir.path(), false);
    let reloj = nodo.historial_pow.last().expect("corte real").timestamp + 1000;
    nodo.reloj_local_simulado = Some(reloj as i64);
    let mut ultimo = None;
    for k in 0..200u64 {
        let bloque = pow_futuro(&nodo, reloj + 4 + k);
        ultimo = Some(bloque.clone());
        assert_eq!(
            nodo.intentar_admitir_bloque_red(
                &bloque,
                Some(libp2p::PeerId::random()),
                Instant::now()
            ),
            VeredictoFinal::Ignorar
        );
        assert!(nodo.pow_pendientes.len() <= TOPE_POW_PENDIENTES);
    }
    assert_eq!(nodo.pow_pendientes.len(), TOPE_POW_PENDIENTES);
    let bloque = ultimo.expect("algún bloque");
    assert_eq!(
        nodo.intentar_admitir_bloque_red(&bloque, Some(libp2p::PeerId::random()), Instant::now()),
        VeredictoFinal::Ignorar
    );
    assert_eq!(
        nodo.pow_pendientes.len(),
        TOPE_POW_PENDIENTES,
        "sin duplicados por hash"
    );
}
