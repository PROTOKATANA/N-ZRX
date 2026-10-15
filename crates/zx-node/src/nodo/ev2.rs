//! EV-2: frontera de confirmación usada por los llamantes reales de Nodo.
//! Cadena/DAG, transacciones, firmas y Mempool reales; cabeceras prevalidadas como B66-C.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::integer_division,
    reason = "fixtures con aserciones"
)]
use super::*;
use crate::votos::b88 as f;
use zx_consensus::transicion::{BloqueTransicion, Fase, HechosCabecera, ParametrosEvidencia};
use zx_dag::{IdentidadGhostdag, IdentidadTicket};

type Par = (Tx, Vec<Vec<u8>>);

fn registro_cuenta(dir: &Path, nombre: &str) -> usize {
    std::fs::read_to_string(dir.join("registro.jsonl"))
        .expect("registro")
        .lines()
        .filter(|s| s.contains(&format!("\"tipo\":\"{nombre}\"")))
        .count()
}

fn nodo_pago(dir: &Path, post: bool) -> (Nodo, Par, Par) {
    let mut nodo = super::ev1::nodo(dir);
    let (mut inicial, madre, hija) = crate::mempool::tests::b66_madre_hija();
    inicial.fase = Fase::Genesis;
    inicial.altura = 0;
    inicial.slot = 0;
    let mut p = f::params();
    if !post {
        p.h_corte_min = 3;
    }
    let mut c = Cadena::nueva_con_evidencia_e_inicial(
        p,
        1,
        nodo.cbid,
        15,
        ParametrosEvidencia::inactiva(),
        inicial,
    );
    c.admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: f::bh(0) },
        Vec::new(),
    )))
    .expect("génesis");
    c.admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: f::bh(1),
            padre: f::bh(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        Vec::new(),
    )))
    .expect("PoW");
    nodo.params = p;
    nodo.cadena = c;
    nodo.ultima_cadena_seleccionada = vec![f::bh(0), f::bh(1)];
    nodo.motor_votos = None;
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        p,
        ParametrosEvidencia::inactiva(),
        nodo.cbid,
        nodo.estado_base_mempool(),
        Politica::dev(),
    )));
    (nodo, madre, hija)
}

fn vuelta_post(propia: bool) {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, madre, hija) = nodo_pago(dir.path(), true);
    if propia {
        let mut m = nodo.mempool.lock().expect("cola");
        for (tx, w) in [&madre, &hija] {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), Instant::now(), Punto::Slot(0)),
                Ok(crate::mempool::Admision::Admitida)
            );
        }
    }
    let productor = crate::claves::ClaveDev::derivar(66, 0).pk;
    let cuerpo = vec![hija.clone(), madre];
    nodo.cadena
        .admitir(BloqueCadena::Post(BloquePost {
            hash: f::bh(2),
            padres: vec![f::bh(1)],
            slot: 2,
            timestamp: 0,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
            sr: 1,
            distancia: 0,
            identidad: IdentidadGhostdag::Billete(IdentidadTicket::vigente(
                productor, 0, 1, [2; 32], 2,
            )),
            txs: cuerpo.clone(),
        }))
        .expect("bloque con descarte contextual");
    assert_eq!(nodo.cadena.descartes(&f::bh(2)).expect("recibo").len(), 1);
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    let txs: Vec<_> = cuerpo.iter().map(|(t, _)| t.clone()).collect();
    let testigos: Vec<_> = cuerpo.iter().map(|(_, w)| w.clone()).collect();
    nodo.actualizar_mempool_tras_bloque_con_recibo(f::bh(2), &txs, &testigos, None);
    let m = nodo.mempool.lock().expect("cola");
    assert_eq!(m.estadisticas().n, 1);
    assert_eq!(
        m.seleccionar(nodo.params.max_cuerpo_bloque_bytes, 1),
        vec![hija]
    );
    drop(m);
    assert_eq!(
        registro_cuenta(dir.path(), "tx_descartada_devuelta_cola"),
        1
    );
    nodo.actualizar_mempool_tras_bloque_con_recibo(f::bh(2), &txs, &testigos, None);
    assert_eq!(
        registro_cuenta(dir.path(), "tx_descartada_devuelta_cola"),
        1
    );
}

#[test]
fn ev2_post_propio_confirmacion_recupera_pago_con_testigos() {
    vuelta_post(true);
}

#[test]
fn ev2_post_ajeno_confirmacion_recupera_pago_que_no_estaba_en_cola() {
    vuelta_post(false);
}

#[test]
fn ev2_minado_confirma_solo_exito_estricto() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, madre, hija) = nodo_pago(dir.path(), false);
    let cuerpo = vec![madre.clone(), hija.clone()];
    for (tx, w) in &cuerpo {
        assert_eq!(
            nodo.mempool.lock().expect("cola").admitir(
                None,
                tx.clone(),
                w.clone(),
                Instant::now(),
                Punto::Altura(1)
            ),
            Ok(crate::mempool::Admision::Admitida)
        );
    }
    let cab = |id| HechosCabecera::PoW {
        hash: f::bh(id),
        padre: f::bh(1),
        altura: 2,
        trabajo: U256::one(),
        pow_valido: true,
    };
    assert!(
        nodo.cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                cab(2),
                vec![hija, madre]
            )))
            .is_err()
    );
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 2);
    nodo.cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            cab(3),
            cuerpo.clone(),
        )))
        .expect("éxito estricto");
    nodo.ultima_cadena_seleccionada = vec![f::bh(0), f::bh(1), f::bh(3)];
    let txs: Vec<_> = cuerpo.iter().map(|(t, _)| t.clone()).collect();
    let testigos: Vec<_> = cuerpo.iter().map(|(_, w)| w.clone()).collect();
    nodo.actualizar_mempool_tras_bloque_con_recibo(f::bh(3), &txs, &testigos, None);
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 0);
    assert_eq!(registro_cuenta(dir.path(), "tx_readmision_fallida"), 0);
}

#[test]
fn ev2_dos_reporteros_un_incidente_y_reorg_recupera_sobre() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = super::ev1::nodo(dir.path());
    super::ev1::recibir_par(&mut nodo);
    let primera = nodo
        .mempool
        .lock()
        .expect("cola")
        .seleccionar(nodo.params.max_cuerpo_bloque_bytes, 1)
        .into_iter()
        .find(|(tx, _)| crate::mempool::identidad_evidencia_voto(tx).is_some())
        .expect("evidencia local");
    let sk = f::bls();
    let e = f::fabricar(&mut f::detector(), &sk, &nodo.cadena);
    let (pk, ed) = f::reportero();
    let segunda = crate::votos::tx_evidencia_votos_peso(&e, pk, &ed, nodo.cbid);
    assert_ne!(txid(&primera.0, nodo.cbid), txid(&segunda.0, nodo.cbid));
    let identidad = crate::mempool::identidad_evidencia_voto(&primera.0).expect("identidad");
    let antes = nodo.cadena.cadena_virtual();
    nodo.reemplazar_cadena_seleccionada(&antes);
    let slot = nodo.estado_base_mempool().slot + 1;
    let mut bloque = f::post(6, vec![f::bh(5)], slot);
    let BloqueCadena::Post(ref mut b) = bloque else {
        panic!("PoST")
    };
    b.txs = vec![primera.clone(), segunda.clone()];
    nodo.cadena.admitir(bloque).expect("dos reporteros");
    nodo.actualizar_cadena_seleccionada(f::bh(6));
    let txs = vec![primera.0.clone(), segunda.0.clone()];
    let testigos = vec![primera.1.clone(), segunda.1.clone()];
    nodo.actualizar_mempool_tras_bloque_con_recibo(f::bh(6), &txs, &testigos, None);
    let estado = nodo.estado_base_mempool();
    assert!(crate::mempool::incidente_aplicado(
        &estado,
        &identidad.incidente
    ));
    assert_eq!(estado.garantias[&f::acusado()].incidentes.len(), 1);
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 0);
    assert_eq!(
        registro_cuenta(dir.path(), "tx_descartada_devuelta_cola"),
        0
    );
    assert_eq!(registro_cuenta(dir.path(), "tx_readmision_fallida"), 0);
    assert_eq!(
        nodo.mempool.lock().expect("cola").admitir(
            None,
            segunda.0,
            segunda.1,
            Instant::now(),
            Punto::Slot(slot)
        ),
        Ok(crate::mempool::Admision::Duplicada)
    );
    let mut alternativa = f::post(7, vec![f::bh(5)], slot + 1);
    let BloqueCadena::Post(ref mut b) = alternativa else {
        panic!("PoST")
    };
    b.peso = 10;
    nodo.cadena.admitir(alternativa).expect("rama alternativa");
    assert!(nodo.actualizar_cadena_seleccionada(f::bh(7)) > 0);
    assert!(!crate::mempool::incidente_aplicado(
        &nodo.estado_base_mempool(),
        &identidad.incidente
    ));
    let m = nodo.mempool.lock().expect("cola");
    assert_eq!(m.estadisticas().n, 1);
    assert_eq!(
        m.seleccionar(nodo.params.max_cuerpo_bloque_bytes, 1),
        vec![primera]
    );
}

fn nodo_con_pow_prevalidado(dir: &Path) -> (Nodo, Par, Par) {
    let cfg = Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: vec![0],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: None,
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: true,
        sin_revelacion: false,
    };
    let mut nodo = Nodo::arrancar(&cfg).expect("Nodo real");
    let (mut inicial, madre, hija) = crate::mempool::tests::b66_madre_hija();
    inicial.fase = Fase::Genesis;
    inicial.altura = 0;
    inicial.slot = 0;
    for i in 0..perfil::K_MIN {
        let mut g = zx_consensus::transicion::Garantia::nueva();
        g.activo = nodo.params.q;
        inicial.garantias.insert(ClaveDev::derivar(1, i).pk, g);
    }
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        nodo.params,
        perfil::ghostdag_k(),
        nodo.cbid,
        perfil::ghostdag_max_padres(),
        perfil::parametros_evidencia_dev(),
        inicial,
    );
    cadena
        .admitir(super::pruebas_eclr2::genesis())
        .expect("génesis del fixture");
    for altura in 1..=nodo.params.h_corte_min {
        cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::PoW {
                    hash: super::pruebas_eclr2::hash_u32(altura),
                    padre: super::pruebas_eclr2::hash_u32(altura - 1),
                    altura,
                    trabajo: nodo.params.w_min / U256::from(nodo.params.h_corte_min),
                    pow_valido: true,
                },
                Vec::new(),
            )))
            .expect("PoW prevalidados como B66-C");
    }
    nodo.cadena = cadena;
    (nodo, madre, hija)
}

fn rutas_post_reales(modo: u8) {
    use zx_post::productor_regimen::{
        CuerpoProductor, ErrorRegimen, producir_en_regimen_con_firmante,
    };
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, madre, hija) = nodo_con_pow_prevalidado(dir.path());
    let terminal = nodo.cadena.terminal().expect("terminal dev");
    let c = nodo.claves[0].clone();
    let historia = Arc::clone(&nodo.historia);
    let parcela = abrir_o_crear_parcela(&nodo.dir_datos, &c, &historia).expect("parcela real");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &historia,
    };
    let params = ParametrosProductor {
        n_dev: nodo.n_dev,
        sr_dev: nodo.sr_dev_actual,
        max_slots: MAX_BUNDLES_POT as u64,
        consensus_branch_id: nodo.cbid,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("reloj")
            .as_secs(),
        i_iter: 0,
        importe_coinbase: perfil::subsidio_post(0),
    };
    let registro = RegistroFirmante::nueva(dir.path().join("firmante-ev2")).expect("firmante real");
    let mut firmante = Firmante::nuevo(&registro);
    let ProductoFirmado::Bloque(primero, _) =
        producir_con_firmante(terminal, &fuente, &c.sk, &params, &mut firmante)
            .expect("PoAS y PoT reales")
    else {
        panic!("abstención")
    };
    let red_primero = BloqueRed::Post {
        cabecera: primero.cabecera,
        justificacion: primero.justificacion.clone(),
        txs: primero.txs().to_vec(),
        testigos: primero.testigos().to_vec(),
    };
    let padre = primero.cabecera.block_hash();
    let slot_padre = primero.cabecera.slot;
    nodo.admitir_post_interno(primero, 0, true)
        .expect("admisión y persistencia del padre");
    let base = nodo.cadena.estado_post(&padre).expect("base nueva").clone();
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        perfil::parametros_evidencia_dev(),
        nodo.cbid,
        base,
        Politica::dev(),
    )));
    if modo == 0 {
        for (tx, t) in [&madre, &hija] {
            assert_eq!(
                nodo.mempool.lock().expect("cola").admitir(
                    None,
                    tx.clone(),
                    t.clone(),
                    Instant::now(),
                    Punto::Slot(slot_padre)
                ),
                Ok(crate::mempool::Admision::Admitida)
            );
        }
    }
    let mut servicio = nodo
        .servicios_verificacion
        .get(&terminal)
        .expect("ServicioPot real")
        .clone();
    let mut encontrado = None;
    for slot in slot_padre + 1..=slot_padre + 64 {
        let cuerpo = CuerpoProductor::nuevo(
            vec![hija.0.clone(), madre.0.clone()],
            vec![hija.1.clone(), madre.1.clone()],
        )
        .expect("cuerpo y testigos");
        let padres = padres_de_regimen(&nodo.cadena).expect("padres reales");
        match producir_en_regimen_con_firmante(
            padres,
            slot,
            &mut servicio,
            &fuente,
            &c.sk,
            &params,
            cuerpo,
            &mut firmante,
        ) {
            Ok(ProductoFirmado::Bloque(b, _)) => {
                encontrado = Some(b);
                break;
            }
            Err(ErrorRegimen::SinSolucion { .. }) => {}
            otro => panic!("productor real: {otro:?}"),
        }
    }
    let bloque = encontrado.expect("solución en búsqueda acotada");
    let hash = bloque.cabecera.block_hash();
    let mut receptor_dir = None;
    if modo == 0 {
        let (tx, rx) = mpsc::channel();
        assert!(matches!(
            nodo.procesar_post_propio(2, bloque, Instant::now(), 0, terminal, &tx)
                .expect("ruta propia"),
            ControlPost::Continuar
        ));
        assert!(matches!(
            rx.try_recv().expect("respuesta"),
            MsgBucle::Continuar { .. }
        ));
    } else {
        let red = BloqueRed::Post {
            cabecera: bloque.cabecera,
            justificacion: bloque.justificacion.clone(),
            txs: bloque.txs().to_vec(),
            testigos: bloque.testigos().to_vec(),
        };
        let origen = if modo == 1 {
            None
        } else {
            Some(libp2p::PeerId::random())
        };
        if modo == 3 {
            let d = tempfile::tempdir().expect("receptor huérfano");
            let (mut receptor, _, _) = nodo_con_pow_prevalidado(d.path());
            assert_eq!(
                receptor.intentar_admitir_bloque_red(&red, origen, Instant::now()),
                VeredictoFinal::Ignorar
            );
            assert!(!receptor.cadena.es_valido(&hash));
            assert_eq!(
                receptor.intentar_admitir_bloque_red(&red_primero, origen, Instant::now()),
                VeredictoFinal::Aceptar
            );
            assert!(
                receptor.cadena.es_valido(&hash),
                "el huérfano se resolvió por la ruta real"
            );
            nodo = receptor;
            receptor_dir = Some(d);
        } else {
            assert_eq!(
                nodo.intentar_admitir_bloque_red(&red, origen, Instant::now()),
                VeredictoFinal::Aceptar
            );
        }
    }
    assert!(!nodo.poas_simulada);
    assert!(nodo.cadena.es_valido(&hash));
    let descartes = nodo.cadena.descartes(&hash).expect("recibo real");
    assert_eq!(descartes.len(), 1);
    assert_eq!(descartes[0].txid, txid(&hija.0, nodo.cbid));
    let m = nodo.mempool.lock().expect("cola");
    assert_eq!(m.estadisticas().n, 1);
    if modo == 2 {
        assert_eq!(m.estadisticas().pares, 1);
    }
    assert_eq!(
        m.seleccionar(nodo.params.max_cuerpo_bloque_bytes, 1),
        vec![hija]
    );
    drop(m);
    let eventos_dir = receptor_dir.as_ref().map_or(dir.path(), |d| d.path());
    assert_eq!(
        registro_cuenta(eventos_dir, "tx_descartada_devuelta_cola"),
        1
    );
    println!(
        "EV2 ruta real modo={modo}: PoAS/PoT reales; descartes=1; recuperada=1; testigos intactos; evento=1"
    );
}

#[test]
fn ev2_ruta_post_propia_real_recupera_descartada() {
    rutas_post_reales(0);
}

#[test]
fn ev2_ruta_post_gossip_real_recupera_descartada() {
    rutas_post_reales(1);
}

#[test]
fn ev2_ruta_post_sincronizacion_real_recupera_descartada() {
    rutas_post_reales(2);
}

#[test]
fn ev2_ruta_huerfano_resuelto_real_recupera_descartada() {
    rutas_post_reales(3);
}

#[test]
fn ev2_fase_de_minado_real_confirma_los_pagos_estrictamente_aplicados() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, madre, hija) = nodo_con_pow_prevalidado(dir.path());
    let mut inicial = nodo
        .cadena
        .estado_post(&super::pruebas_eclr2::hash_u32(0))
        .expect("inicial")
        .clone();
    inicial.fase = Fase::Genesis;
    inicial.altura = 0;
    inicial.slot = 0;
    inicial.terminal = None;
    let genesis_real = nodo.historial_pow[0].block_hash();
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        nodo.params,
        perfil::ghostdag_k(),
        nodo.cbid,
        perfil::ghostdag_max_padres(),
        perfil::parametros_evidencia_dev(),
        inicial,
    );
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis { hash: genesis_real },
            Vec::new(),
        )))
        .expect("génesis que corresponde al historial real");
    nodo.cadena = cadena;
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        perfil::parametros_evidencia_dev(),
        nodo.cbid,
        nodo.estado_base_mempool(),
        Politica::dev(),
    )));
    for (tx, w) in [&madre, &hija] {
        assert_eq!(
            nodo.mempool.lock().expect("cola").admitir(
                None,
                tx.clone(),
                w.clone(),
                Instant::now(),
                Punto::Altura(0)
            ),
            Ok(crate::mempool::Admision::Admitida)
        );
    }
    nodo.fase_pow().expect("fase de minado real hasta el corte");
    assert!(nodo.cadena.terminal().is_some());
    let mut m = nodo.mempool.lock().expect("cola");
    for (tx, w) in [madre, hija] {
        assert!(
            m.contiene(&txid(&tx, nodo.cbid)),
            "recibo de aplicación reciente"
        );
        assert_eq!(
            m.admitir(None, tx, w, Instant::now(), Punto::Slot(0)),
            Ok(crate::mempool::Admision::Duplicada)
        );
    }
    assert_eq!(registro_cuenta(dir.path(), "tx_readmision_fallida"), 0);
    println!("EV2 minado real: pagos aplicados=2; reenvíos=Duplicada; descartes parciales=0");
}

#[test]
fn ev2_evidencia_lateral_descartada_se_readmite_con_hecho_nuevo_y_testigos() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = super::ev1::nodo(dir.path());
    let sk = f::bls();
    let e = f::fabricar(&mut f::detector(), &sk, &nodo.cadena);
    let (pk, ed) = f::reportero();
    let sobre = crate::votos::tx_evidencia_votos_peso(&e, pk, &ed, nodo.cbid);
    let slot = nodo.estado_base_mempool().slot + 1;
    let mut lateral = f::post(6, vec![f::bh(1)], slot);
    let BloqueCadena::Post(ref mut b) = lateral else {
        panic!("PoST")
    };
    b.txs = vec![sobre.clone()];
    nodo.cadena
        .admitir(lateral)
        .expect("lateral admitido con descarte");
    assert_eq!(nodo.cadena.descartes(&f::bh(6)).expect("recibo").len(), 1);
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    let identidad = crate::mempool::identidad_evidencia_voto(&sobre.0).expect("incidente");
    assert!(!crate::mempool::incidente_aplicado(
        &nodo.estado_base_mempool(),
        &identidad.incidente
    ));
    nodo.actualizar_mempool_tras_bloque_con_recibo(
        f::bh(6),
        std::slice::from_ref(&sobre.0),
        std::slice::from_ref(&sobre.1),
        None,
    );
    let m = nodo.mempool.lock().expect("cola");
    assert_eq!(m.estadisticas().n, 1);
    assert_eq!(
        m.seleccionar(nodo.params.max_cuerpo_bloque_bytes, 1),
        vec![sobre]
    );
    drop(m);
    assert_eq!(
        registro_cuenta(dir.path(), "tx_descartada_devuelta_cola"),
        1
    );
}

#[test]
fn ev2_readmision_fallida_registra_causa_una_sola_vez() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, madre, mut hija) = nodo_pago(dir.path(), true);
    hija.1[0][0] ^= 1;
    let mut bloque = f::post(2, vec![f::bh(1)], 2);
    let BloqueCadena::Post(ref mut b) = bloque else {
        panic!("PoST")
    };
    b.txs = vec![madre.clone(), hija.clone()];
    nodo.cadena
        .admitir(bloque)
        .expect("bloque admitido con firma descartada");
    assert_eq!(nodo.cadena.descartes(&f::bh(2)).expect("recibo").len(), 1);
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    let txs = vec![madre.0, hija.0];
    let testigos = vec![madre.1, hija.1];
    for _ in 0..2 {
        nodo.actualizar_mempool_tras_bloque_con_recibo(f::bh(2), &txs, &testigos, None);
    }
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 0);
    assert_eq!(registro_cuenta(dir.path(), "tx_readmision_fallida"), 1);
    assert_eq!(
        registro_cuenta(dir.path(), "tx_descartada_devuelta_cola"),
        0
    );
    let log = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    let evento = log
        .lines()
        .find(|s| s.contains("tx_readmision_fallida"))
        .expect("evento único");
    assert!(evento.contains("Demostrable"), "causa explícita: {evento}");
    assert!(evento.contains("\"clase\":\"pago\""));
}
