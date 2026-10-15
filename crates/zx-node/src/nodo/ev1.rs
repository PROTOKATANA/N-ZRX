//! EV-1: recepción y armado reales. Génesis/DAG y veredictos de cabecera son fixtures B88-C;
//! no se sustituye el hecho, la cola, el códec, las firmas ni el selector del productor.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "fixtures de integración pequeños con aserciones"
)]
use super::*;
use crate::votos::b88 as f;
use crate::votos::{VotoPeso, serializar_voto_peso};
use zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_hecho_con_undo;

pub(super) fn nodo(dir: &Path) -> Nodo {
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
        sin_voto: true,
        sin_revelacion: false,
    };
    let mut nodo = Nodo::arrancar(&cfg).expect("nodo real sin red");
    nodo.params = f::params();
    nodo.cadena = f::cadena(&f::bls());
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        nodo.cbid,
        nodo.estado_base_mempool(),
        Politica::dev(),
    )));
    let estado = nodo.estado_base_mempool();
    let mut motor = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: perfil::parametros_votos_dev(),
        claves: Vec::new(),
        emitir_votos: false,
    });
    motor
        .avanzar(4, f::bh(5), &estado, 8)
        .expect("abrir tabla real");
    nodo.motor_votos = Some(motor);
    nodo.slot_votos_simulado = Some(8); // reloj, nunca un hecho ni una admisión.
    nodo
}

pub(super) fn recibir_par(nodo: &mut Nodo) {
    let sk = f::bls();
    for (n, candidato) in [(1, 3), (3, 4)] {
        let v = f::voto(&sk, n, candidato);
        let sobre = serializar_voto_peso(&VotoPeso {
            n,
            candidato: v.candidato,
            h_t_siguiente: v.h_t_siguiente,
            raiz_estado: v.raiz_estado,
            clave: sk.clave_publica().bytes(),
            firma: v.firma,
        });
        nodo.procesar_voto_de_red(&sobre);
    }
}

fn armar(nodo: &mut Nodo, slot: u64) -> Vec<(Tx, Vec<Vec<u8>>)> {
    let (tx, rx) = mpsc::channel();
    let terminal = nodo.cadena.terminal().expect("terminal");
    nodo.atender_msg_productor(
        MsgProductor::PeticionPadres { id: 1, slot },
        false,
        terminal,
        &tx,
    )
    .expect("productor real");
    let MsgBucle::Padres { txs, testigos, .. } = rx.try_recv().expect("cuerpo real") else {
        panic!("respuesta Padres");
    };
    let cuerpo = zx_post::productor_regimen::CuerpoProductor::nuevo(txs, testigos)
        .expect("constructor real");
    cuerpo
        .txs()
        .iter()
        .cloned()
        .zip(cuerpo.testigos().iter().cloned())
        .collect()
}

fn eventos(dir: &Path, nombre: &str) -> usize {
    std::fs::read_to_string(dir.join("registro.jsonl"))
        .expect("registro")
        .lines()
        .filter(|l| l.contains(&format!("\"tipo\":\"{nombre}\"")))
        .count()
}

#[test]
fn ev1_e2e_detector_cola_bloque_castigo() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path());
    let base = nodo.estado_base_mempool();
    recibir_par(&mut nodo);
    assert_eq!(
        nodo.mempool.lock().expect("cola").estadisticas().n,
        1,
        "admisión por recepción real"
    );
    for _ in 0..100 {
        nodo.procesar_evidencias_doble_voto();
    }
    assert_eq!(
        eventos(dir.path(), "evidencia_admitida"),
        1,
        "una admisión/firma en la ventana"
    );
    let cuerpo = armar(&mut nodo, base.slot + 1);
    let evidencia = cuerpo
        .iter()
        .find(|(tx, _)| crate::mempool::identidad_evidencia_voto(tx).is_some())
        .expect("selector incluyó evidencia");
    let identidad = crate::mempool::identidad_evidencia_voto(&evidencia.0).expect("incidente");
    let (a, b) = f::votos_tx(&evidencia.0);
    let hecho = nodo.cadena.hecho_voto_entre_ventanas(
        &a,
        &b,
        u64::try_from(base.parametros_sector.plazo_slots).expect("plazo"),
    );
    let (oraculo, _, resultado) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &base,
        f::operacion(&evidencia.0),
        nodo.claves[0].pk,
        &nodo.params,
        &zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        base.slot + 1,
        hecho,
    );
    resultado.expect("oráculo de castigo");
    let mut bloque = f::post(6, vec![f::bh(5)], base.slot + 1);
    let BloqueCadena::Post(ref mut post) = bloque else {
        panic!("PoST");
    };
    // Se traslada TODO el cuerpo recibido del productor, sin introducir una evidencia a mano.
    post.txs = cuerpo;
    nodo.cadena
        .admitir(bloque)
        .expect("aplicación real de Cadena");
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    let seleccionado = nodo.cadena.estado_virtual().expect("estado seleccionado");
    assert!(crate::mempool::incidente_aplicado(
        &seleccionado,
        &identidad.incidente
    ));
    assert_eq!(seleccionado.garantias[&f::acusado()].incidentes.len(), 1);
    assert_eq!(
        seleccionado.garantias[&f::acusado()],
        oraculo.garantias[&f::acusado()],
        "todos los débitos de la garantía coinciden con el consenso"
    );
    assert_eq!(seleccionado.sectores, oraculo.sectores);
    assert_eq!(
        seleccionado.quemado - base.quemado,
        oraculo.quemado - base.quemado
    );
    assert!(
        nodo.cadena
            .descartes(&f::bh(6))
            .expect("descartes")
            .is_empty()
    );
    let txs = nodo
        .cadena
        .bloque(&f::bh(6))
        .expect("bloque")
        .txs()
        .iter()
        .map(|(tx, _)| tx.clone())
        .collect::<Vec<_>>();
    let testigos = nodo
        .cadena
        .bloque(&f::bh(6))
        .expect("bloque")
        .txs()
        .iter()
        .map(|(_, w)| w.clone())
        .collect::<Vec<_>>();
    nodo.actualizar_mempool_tras_bloque_con_recibo(f::bh(6), &txs, &testigos, None);
    nodo.slot_votos_simulado = Some(10);
    nodo.procesar_evidencias_doble_voto();
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 0);
    assert_eq!(eventos(dir.path(), "evidencia_aplicada"), 1);
    println!(
        "EV1 e2e: incidentes=1 quemado={} congelado={} cola=0",
        seleccionado.quemado - base.quemado,
        seleccionado.garantias[&f::acusado()].congelado.brek()
    );
}

#[test]
fn ev1_rechazo_reintento_sin_votos_y_cupo() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path());
    let base = nodo.estado_base_mempool();
    // Provocar un límite de recursos real, no un rechazo del evaluador.
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        nodo.cbid,
        base.clone(),
        Politica {
            s: 0,
            ..Politica::dev()
        },
    )));
    recibir_par(&mut nodo);
    assert_eq!(eventos(dir.path(), "evidencia_rechazada"), 1);
    for _ in 0..100 {
        nodo.procesar_evidencias_doble_voto();
    }
    assert_eq!(eventos(dir.path(), "evidencia_rechazada"), 1);
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        nodo.cbid,
        base,
        Politica::dev(),
    )));
    // La apertura de procesar_votos reconsidera ANTES de sus retornos de espera.
    nodo.slot_votos_simulado = Some(10);
    nodo.procesar_votos().expect("ventana siguiente");
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 1);
    assert_eq!(eventos(dir.path(), "evidencia_admitida"), 1);
    for _ in 0..100 {
        nodo.procesar_evidencias_doble_voto();
    }
    assert_eq!(eventos(dir.path(), "evidencia_admitida"), 1);
}

#[test]
fn ev1_reportero_tardio_conserva_material() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path());
    let claves = std::mem::take(&mut nodo.claves);
    recibir_par(&mut nodo);
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 0);
    nodo.claves = claves;
    nodo.slot_votos_simulado = Some(10);
    nodo.procesar_evidencias_doble_voto();
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 1);
}

#[test]
#[should_panic(expected = "control rojo: marca al fabricar elimina reintento")]
fn ev1_marca_al_fabricar_control_rojo() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path());
    let base = nodo.estado_base_mempool();
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        nodo.cbid,
        base.clone(),
        Politica {
            s: 0,
            ..Politica::dev()
        },
    )));
    recibir_par(&mut nodo);
    assert_eq!(eventos(dir.path(), "evidencia_rechazada"), 1);
    let sk = f::bls();
    let a = f::voto(&sk, 1, 3).a_evidencia();
    let b = f::voto(&sk, 3, 4).a_evidencia();
    let identidad = crate::mempool::identidad_de_votos(&sk.clave_publica().bytes(), &a, &b);
    // Variante antigua del control: resolver fabricación como si fuese admisión.
    nodo.motor_votos
        .as_mut()
        .expect("motor")
        .resolver_evidencia_peso(crate::mempool::AdmisionEvidencia::Admitida(identidad));
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        nodo.cbid,
        base,
        Politica::dev(),
    )));
    nodo.slot_votos_simulado = Some(10);
    nodo.procesar_votos().expect("siguiente ventana");
    println!(
        "CONTROL ROJO marca al fabricar: cola={} sin segundo intento",
        nodo.mempool.lock().expect("cola").estadisticas().n
    );
    assert_eq!(
        nodo.mempool.lock().expect("cola").estadisticas().n,
        1,
        "control rojo: marca al fabricar elimina reintento"
    );
}

#[test]
fn ev1_bloques_tardios_reintenta_sin_recibir_votos_otra_vez() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path());
    let completa = f::cadena(&f::bls());
    let mut inicial = completa
        .estado_post(&f::bh(0))
        .expect("estado génesis")
        .clone();
    inicial.fase = zx_consensus::transicion::Fase::Genesis;
    let mut parcial = Cadena::nueva_con_evidencia_e_inicial(
        f::params(),
        1,
        nodo.cbid,
        15,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        inicial,
    );
    for id in 0..=3 {
        parcial
            .admitir(completa.bloque(&f::bh(id)).expect("bloque fixture").clone())
            .expect("prefijo real");
    }
    nodo.cadena = parcial;
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    nodo.rebasear_mempool();
    recibir_par(&mut nodo);
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 0);
    // Se conocen X/Z y su fusión después de los votos. La consulta false previa no queda cacheada.
    for id in 4..=5 {
        nodo.cadena
            .admitir(completa.bloque(&f::bh(id)).expect("bloque").clone())
            .expect("bloque tardío");
    }
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    nodo.rebasear_mempool();
    nodo.slot_votos_simulado = Some(10);
    nodo.procesar_votos().expect("apertura");
    assert_eq!(
        nodo.mempool.lock().expect("cola").estadisticas().n,
        1,
        "material anterior recuperado sin votos nuevos"
    );
}

#[test]
fn ev1_rebase_retira_libera_y_ventana_siguiente_readmite() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path());
    recibir_par(&mut nodo);
    let base = nodo.estado_base_mempool();
    let mut inicial = nodo.cadena.estado_post(&f::bh(0)).expect("génesis").clone();
    inicial.fase = zx_consensus::transicion::Fase::Genesis;
    let mut parcial = Cadena::nueva_con_evidencia_e_inicial(
        f::params(),
        1,
        nodo.cbid,
        15,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        inicial,
    );
    for id in 0..=3 {
        parcial
            .admitir(nodo.cadena.bloque(&f::bh(id)).expect("prefijo").clone())
            .expect("prefijo real");
    }
    parcial
        .admitir(f::post(7, vec![f::bh(3)], base.slot))
        .expect("mismo punto sin candidato Z");
    let completa = std::mem::replace(&mut nodo.cadena, parcial);
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    assert_eq!(nodo.estado_base_mempool().slot, base.slot);
    nodo.rebasear_mempool(); // consulta y publicación de hechos por el dueño real.
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 0);
    nodo.procesar_evidencias_doble_voto();
    assert_eq!(
        nodo.mempool.lock().expect("cola").estadisticas().n,
        0,
        "retirar no renueva cupo"
    );
    nodo.cadena = completa;
    nodo.ultima_cadena_seleccionada = nodo.cadena.cadena_virtual();
    nodo.rebasear_mempool();
    nodo.slot_votos_simulado = Some(10);
    nodo.procesar_votos().expect("apertura siguiente");
    assert_eq!(nodo.mempool.lock().expect("cola").estadisticas().n, 1);
    assert_eq!(eventos(dir.path(), "evidencia_retirada"), 1);
}
