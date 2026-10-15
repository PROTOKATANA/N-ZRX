//! VNT-1b · pruebas por el **camino real** de las fronteras de voto (VNT-R1/VNT-R2 y los defectos
//! D1–D4 de la segunda ronda). La pieza sola ([`crate::cursor_votos`]) tiene sus pruebas unitarias
//! en su propio módulo; aquí van el hilo productor real, la cola de red real, `ServicioPot`,
//! `Cadena`, `procesar_votos` y `MotorVotos::avanzar_con_vista`.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    reason = "fixtures internas que fallan por panic y tamaños comprobados antes de indexar"
)]

use super::pruebas_eclr2::{genesis, hash_u32};
use super::*;
use std::sync::Arc;
use zx_consensus::sectores::{ClaveVoto, ParametrosSector, RegistroSector};
use zx_consensus::transicion::Garantia;
use zx_core::Amount;
use zx_post::productor_regimen::{CuerpoProductor, producir_en_regimen_con_firmante};

fn estado_inicial(n_claves: usize) -> EstadoTransicion {
    assert!(n_claves >= 3);
    let mut estado = EstadoTransicion::inicial();
    for i in 0..n_claves {
        let indice = u32::try_from(i).expect("índice Ed25519");
        let c = ClaveDev::derivar(1, indice);
        let sk = crate::votos::clave_voto_dev(1, indice).expect("BLS dev");
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
    estado
}

/// Nodo real con el corte PoW (sin bloques PoST): el cursor es la única fuente del tiempo PoT, así
/// que la prueba ve exactamente el efecto de las notificaciones verificadas. Tres claves y sus
/// sectores para poder producir bloques PoST reales en las pruebas D1/§3.3.
fn nodo_corte(dir: &Path, estado: EstadoTransicion) -> Nodo {
    let cfg = Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: vec![0, 1, 2],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: true,
        sin_revelacion: false,
    };
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque sin red");
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
            .expect("avance PoW por interfaz de hechos");
    }
    nodo.params = params;
    nodo.cadena = cadena;
    nodo.motor_votos = None;
    nodo.asegurar_servicios_verificacion()
        .expect("servicio del terminal PoW");
    nodo
}

/// Dos terminales PoW hermanos con el **mismo** trabajo y `f_slots = 5`: el terminal seleccionado se
/// vuelve pegajoso en cuanto su DAG alcanza el slot 5, así que un bloque del otro no le arrebata la
/// selección. Los sectores del estado son los del propio nodo, así que sus bloques PoST son reales.
fn nodo_dos_terminales(dir: &Path) -> (Nodo, BlockHash, BlockHash) {
    let cfg = Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: vec![0, 1, 2],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: true,
        sin_revelacion: false,
    };
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque sin red");
    let mut params = perfil::parametros_transicion_dev().expect("perfil dev íntegro");
    params.f_slots = Some(5);
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params,
        perfil::ghostdag_k(),
        nodo.cbid,
        perfil::ghostdag_max_padres(),
        perfil::parametros_evidencia_dev(),
        estado_inicial(3),
    );
    cadena.admitir(genesis()).expect("génesis");
    let trabajo = params.w_min / U256::from(params.h_corte_min);
    for altura in 1..=params.h_corte_min {
        cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::PoW {
                    hash: hash_u32(altura),
                    padre: hash_u32(altura - 1),
                    altura,
                    trabajo,
                    pow_valido: true,
                },
                Vec::new(),
            )))
            .expect("avance PoW");
    }
    // Hermano del último bloque PoW: mismo padre y altura (mismo trabajo acumulado).
    let hermano = hash_u32(9_001);
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::PoW {
                hash: hermano,
                padre: hash_u32(params.h_corte_min - 1),
                altura: params.h_corte_min,
                trabajo,
                pow_valido: true,
            },
            Vec::new(),
        )))
        .expect("terminal hermano");
    let principal = hash_u32(params.h_corte_min);
    nodo.params = params;
    nodo.cadena = cadena;
    nodo.motor_votos = None;
    nodo.asegurar_servicios_verificacion()
        .expect("servicios de los dos terminales");
    (nodo, principal, hermano)
}

/// Config real (mismo arranque que los arneses DG-CAND): mina el corte PoW, persiste y deja el DAG
/// listo para producir y admitir bloques PoST reales.
fn config_real(dir: &Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 407,
        indices_claves: vec![0, 1, 2],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: Some(0),
        punto_control: None,
        sin_voto: true,
        sin_revelacion: true,
    }
}

fn nodo_real(dir: &Path) -> Nodo {
    let mut nodo = Nodo::arrancar(&config_real(dir)).expect("arranque real");
    nodo.fase_pow().expect("minado, depósitos y corte reales");
    assert!(nodo.cadena.terminal().is_some());
    nodo.motor_votos = None;
    nodo.asegurar_servicios_verificacion()
        .expect("servicios reales");
    nodo
}

fn motor_con_claves() -> MotorVotos {
    MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: perfil::parametros_votos_dev(),
            claves: (0..3)
                .map(|i| crate::votos::clave_voto_dev(1, i).expect("clave BLS dev"))
                .collect(),
            emitir_votos: false,
        },
        1,
    )
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

fn a_red(bloque: &BloqueDag) -> BloqueRed {
    BloqueRed::Post {
        cabecera: bloque.cabecera,
        justificacion: bloque.justificacion.clone(),
        txs: bloque.txs().to_vec(),
        testigos: bloque.testigos().to_vec(),
    }
}

fn recibir(nodo: &mut Nodo, bloque: &BloqueDag) -> VeredictoFinal {
    nodo.intentar_admitir_bloque_red(
        &a_red(bloque),
        Some(libp2p::PeerId::random()),
        Instant::now(),
    )
}

fn texto(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("registro.jsonl")).expect("registro real")
}

/// Ventanas `n` de las líneas `ventana_abierta` del registro, **en orden de escritura**.
fn ventanas_abiertas(registro: &str) -> Vec<u64> {
    registro
        .lines()
        .filter(|l| l.contains("\"tipo\":\"ventana_abierta\""))
        .filter_map(|l| {
            let i = l.find("\"n\":")?;
            let resto = &l[i + 4..];
            let fin = resto
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(resto.len());
            resto[..fin].parse().ok()
        })
        .collect()
}

/// Audita la parcela de la clave indicada y construye el bloque con el firmante de producción.
fn producir(
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

/// Primer slot con solución PoAS para alguna de las claves indicadas.
fn oportunidad(
    nodo: &Nodo,
    servicio: &mut ServicioPot,
    desde: u64,
    hasta: u64,
    indices: &[usize],
) -> (u64, usize) {
    for slot in desde..=hasta {
        servicio.avanzar_hasta(slot).expect("PoT real");
        for indice in indices {
            let clave = nodo.claves.get(*indice).expect("clave");
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

// ---------------------------------------------------------------------------------------------
// §3.1 · El hilo real envía la frontera
// ---------------------------------------------------------------------------------------------

/// VNT-R1 · el hilo productor **real** sin claves (no gana ningún slot) envía `FronteraPot` por su
/// canal; el mensaje entra por `iteracion_regimen` y la ventana se abre **sin ningún bloque
/// admitido** después del corte.
#[test]
fn vnt1_frontera_pot_sin_ganadora_abre_la_ventana() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
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
        "el hilo real envía la frontera y la ventana n=1 se abre sin bloque admitido"
    );
    assert!(
        nodo.slot_votos() >= 2,
        "el cursor registra el tiempo PoT verificado (slot {})",
        nodo.slot_votos()
    );
}

// ---------------------------------------------------------------------------------------------
// §3.3 · Lote de dos bloques
// ---------------------------------------------------------------------------------------------

/// VNT-R2 · dos bloques PoST **reales** de ventanas consecutivas en la misma cola de red, drenada
/// por **una sola** llamada a `procesar_trabajo_red_pendiente`: el registro muestra la apertura de
/// la ventana del primero **entre** las dos admisiones.
#[test]
fn vnt1_dos_fronteras_se_atienden_entre_puntos_completos() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let t_inst = Nodo::t_inst_votos();
    let (slot_a, ind_a) = oportunidad(&nodo, &mut servicio, 2, 400, &[0, 1, 2]);
    let bloque_a = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(terminal, &[]).expect("padres"),
        slot_a,
        nodo.reloj_local() as u64,
        ind_a,
        CuerpoProductor::vacio(),
    );
    let w_a = slot_a.div_euclid(t_inst);
    let hash_a = bloque_a.cabecera.block_hash();
    // El servicio local debe conocer el bloque A como padre para producir el B (mapea hash→slot).
    servicio
        .registrar_validado_con_timestamp(hash_a, slot_a, nodo.reloj_local() as u64)
        .expect("el servicio conoce el bloque A como padre");
    let desde_b = (w_a + 1) * t_inst;
    let (slot_b, ind_b) = oportunidad(&nodo, &mut servicio, desde_b, desde_b + 400, &[0, 1, 2]);
    let w_b = slot_b.div_euclid(t_inst);
    assert!(w_b > w_a, "ventanas consecutivas: {w_a} < {w_b}");
    let bloque_b = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(hash_a, &[]).expect("padres"),
        slot_b,
        nodo.reloj_local() as u64,
        ind_b,
        CuerpoProductor::vacio(),
    );
    let (tx_red, rx_red) = red::nueva_cola_trabajo_red();
    nodo.trabajo_red = Some(rx_red);
    let peer = libp2p::PeerId::random();
    let _ = tx_red.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
        de: peer,
        bloque: a_red(&bloque_a),
        llegada: Instant::now(),
    });
    let _ = tx_red.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
        de: peer,
        bloque: a_red(&bloque_b),
        llegada: Instant::now(),
    });
    nodo.procesar_trabajo_red_pendiente();
    let abiertas = ventanas_abiertas(&texto(dir.path()));
    let pos_a = abiertas
        .iter()
        .position(|n| *n == w_a)
        .expect("la ventana del primer bloque se abrió");
    let pos_b = abiertas
        .iter()
        .position(|n| *n == w_b)
        .expect("la ventana del segundo bloque se abrió");
    assert!(
        pos_a < pos_b,
        "la ventana {w_a} se abrió entre las dos admisiones, antes de {w_b}: {abiertas:?}"
    );
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        Some(w_b)
    );
}

// ---------------------------------------------------------------------------------------------
// §3.4 · Otro terminal (D1)
// ---------------------------------------------------------------------------------------------

/// D1 · con dos terminales, un bloque **válido** admitido en el no seleccionado y con un slot mayor
/// no mueve `slot_votos` ni abre ninguna ventana.
#[test]
fn vnt1b_d1_bloque_de_otro_terminal_no_mueve_el_cursor() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, principal, hermano) = nodo_dos_terminales(dir.path());
    let seleccionado = nodo.cadena.terminal().expect("seleccionado");
    let otro = if seleccionado == principal {
        hermano
    } else {
        principal
    };
    assert_ne!(seleccionado, otro, "el otro terminal no es el seleccionado");
    let base = nodo
        .cadena
        .estado_past(&seleccionado)
        .cloned()
        .unwrap_or_else(|| nodo.cadena.estado_terminal().clone());
    let mut motor = motor_con_claves();
    motor
        .avanzar(0, seleccionado, &base, 0)
        .expect("apertura 0");
    nodo.motor_votos = Some(motor);
    // El seleccionado produce en slot >= 5: su DAG alcanza `f_slots` y la selección se vuelve
    // pegajosa (no la arrebata un bloque del otro terminal).
    let mut servicio_sel = nodo.servicios_verificacion[&seleccionado].clone();
    let (slot_sel, ind_sel) = oportunidad(&nodo, &mut servicio_sel, 5, 55, &[0, 1, 2]);
    assert!(slot_sel >= 5);
    let bloque_sel = producir(
        &nodo,
        &mut servicio_sel,
        PadresDag::nuevo(seleccionado, &[]).expect("padres"),
        slot_sel,
        nodo.reloj_local() as u64,
        ind_sel,
        CuerpoProductor::vacio(),
    );
    assert_eq!(
        recibir(&mut nodo, &bloque_sel),
        VeredictoFinal::Aceptar,
        "bloque PoST del terminal seleccionado"
    );
    assert_eq!(
        nodo.cadena.terminal(),
        Some(seleccionado),
        "la selección queda pegajosa"
    );
    // Primer bloque del otro terminal (le da DAG propio).
    let mut servicio_otro = nodo.servicios_verificacion[&otro].clone();
    let (slot1, ind1) = oportunidad(&nodo, &mut servicio_otro, 1, 50, &[0, 1, 2]);
    let bloque1 = producir(
        &nodo,
        &mut servicio_otro,
        PadresDag::nuevo(otro, &[]).expect("padres"),
        slot1,
        nodo.reloj_local() as u64,
        ind1,
        CuerpoProductor::vacio(),
    );
    let hash1 = bloque1.cabecera.block_hash();
    assert_eq!(
        recibir(&mut nodo, &bloque1),
        VeredictoFinal::Aceptar,
        "primer bloque del otro terminal"
    );
    assert_eq!(
        nodo.cadena.terminal(),
        Some(seleccionado),
        "el otro terminal sigue sin ser el seleccionado"
    );
    // Segundo bloque del otro terminal, con un slot **mayor** que el del seleccionado.
    let slot_antes = nodo.slot_votos();
    let ventana_antes = nodo
        .motor_votos
        .as_ref()
        .and_then(MotorVotos::ultima_ventana_abierta);
    let mut servicio_otro2 = nodo.servicios_verificacion[&otro].clone();
    let (slot2, ind2) = oportunidad(
        &nodo,
        &mut servicio_otro2,
        slot_sel.saturating_add(1),
        slot_sel.saturating_add(50),
        &[0, 1, 2],
    );
    assert!(
        slot2 > slot_sel,
        "el bloque del otro terminal tiene slot mayor"
    );
    let bloque2 = producir(
        &nodo,
        &mut servicio_otro2,
        PadresDag::nuevo(hash1, &[]).expect("padres"),
        slot2,
        nodo.reloj_local() as u64,
        ind2,
        CuerpoProductor::vacio(),
    );
    assert_eq!(
        recibir(&mut nodo, &bloque2),
        VeredictoFinal::Aceptar,
        "el bloque del terminal no seleccionado es válido"
    );
    assert_eq!(
        nodo.cadena.terminal(),
        Some(seleccionado),
        "el terminal sigue siendo el seleccionado"
    );
    assert_eq!(
        nodo.slot_votos(),
        slot_antes,
        "un bloque de otro terminal no mueve slot_votos"
    );
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        ventana_antes,
        "no se abre ninguna ventana"
    );
}

// ---------------------------------------------------------------------------------------------
// §3.6 · Calendario distinto y repetida (D3)
// ---------------------------------------------------------------------------------------------

/// D3 · una notificación con un `N` de slot distinto al del bucle no mueve el cursor ni abre; una
/// repetida (mismo slot, mismo calendario) tampoco abre una ventana nueva.
#[test]
fn vnt1b_d3_calendario_distinto_y_repetida() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
    let n_vigente = nodo.servicios_verificacion[&terminal].n_vigente(2);
    let (tx, _rx) = mpsc::channel();
    nodo.atender_msg_productor(
        MsgProductor::FronteraPot {
            flujo: terminal,
            slot: 2,
            n: n_vigente.saturating_add(1),
        },
        false,
        terminal,
        &tx,
    )
    .expect("notificación con calendario ajeno");
    assert_eq!(nodo.slot_votos(), 0, "el calendario distinto no mueve s_v");
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        Some(0),
        "el calendario distinto no abre"
    );
    // Correcta: mueve y abre n=1.
    nodo.atender_msg_productor(
        MsgProductor::FronteraPot {
            flujo: terminal,
            slot: 2,
            n: n_vigente,
        },
        false,
        terminal,
        &tx,
    )
    .expect("notificación correcta");
    assert_eq!(nodo.slot_votos(), 2);
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        Some(1)
    );
    // Repetida: no abre una ventana nueva.
    nodo.atender_msg_productor(
        MsgProductor::FronteraPot {
            flujo: terminal,
            slot: 2,
            n: n_vigente,
        },
        false,
        terminal,
        &tx,
    )
    .expect("notificación repetida");
    assert_eq!(nodo.slot_votos(), 2, "una repetida no mueve s_v");
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        Some(1),
        "una repetida no abre otra ventana"
    );
}

// ---------------------------------------------------------------------------------------------
// §3.8 · Ruido (D4)
// ---------------------------------------------------------------------------------------------

/// D4 · veinte llamadas seguidas sin que el motor pueda abrir: el intervalo se traza **una** vez.
#[test]
fn vnt1b_d4_ruido_traza_el_intervalo_una_vez() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let terminal = nodo.cadena.terminal().expect("terminal");
    // Motor **sin** tabla: base sembrada pero sin calendario/control, así `avanzar_con_vista` no
    // puede abrir (carga inicial pendiente) y la frontera sigue pendiente.
    let mut motor = motor_con_claves();
    motor
        .sembrar_base_de_estado(5, [0u8; 32], [0u8; 32])
        .expect("base sin tabla");
    nodo.motor_votos = Some(motor);
    nodo.cursor_votos = Some(CursorVotos::nuevo(terminal, 1, 12));
    for _ in 0..20 {
        nodo.atender_fronteras_votos().expect("intento de apertura");
    }
    assert_eq!(
        nodo.trazas_intervalo_fronteras, 1,
        "el intervalo se trazó una sola vez en veinte intentos"
    );
    assert_eq!(
        nodo.ultimo_intervalo_fronteras_votos,
        Some((0, 6)),
        "el intervalo pendiente no cambia"
    );
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        None,
        "el motor no abrió: la frontera sigue pendiente"
    );
}

// ---------------------------------------------------------------------------------------------
// §3.5 · Modo detenido (D2)
// ---------------------------------------------------------------------------------------------

fn config_eclr2(dir: &Path) -> Config {
    Config {
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
    }
}

fn cabecera_min(slot: u64, padres: &[BlockHash]) -> zx_core::preimage::dag::DagBlockHeader {
    use zx_core::digest::{BodyCommitment, Digest, MerkleRoot};
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    let (seleccionado, extras) = padres
        .split_first()
        .expect("la cabecera necesita al menos un padre");
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: 0xa8b4_66a7,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([(slot % 251) as u8; 32])),
        timestamp: 1_000 + slot,
        height: 0,
        slot,
        pot_output: [0; 16],
        rango_solucion: 1,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0xAA; 32])),
        padres: PadresDag::nuevo(*seleccionado, extras).expect("padres de la cabecera"),
        sello: [0; 64],
    }
}

/// D2 · con el eclipse enclavado y un motor en condiciones de abrir, ni un bloque de red ni una
/// `FronteraPot` llegan al motor: la última ventana no cambia y no hay `voto_emitido`; el cursor sí
/// registra el tiempo.
#[test]
fn vnt1b_d2_modo_detenido_no_llega_al_motor() {
    use zx_p2p::mensaje::BloqueRed;
    let dir = tempfile::tempdir().expect("temporal");
    let cfg = config_eclr2(dir.path());
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque");
    let cadena = super::pruebas_pd1f::cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(0x5a5a, 0).expect("clave BLS");
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
        .expect("siembra del punto de control");
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx], 30);
    nodo.asegurar_servicios_verificacion().expect("servicios");
    assert!(nodo.cadena.eclipse().is_some(), "eclipse enclavado");
    let terminal = nodo.cadena.terminal().expect("terminal");
    let n_vigente = nodo.servicios_verificacion[&terminal].n_vigente(2);
    let ventana_antes = nodo
        .motor_votos
        .as_ref()
        .and_then(MotorVotos::ultima_ventana_abierta);
    let llamadas_antes = nodo.procesar_votos_llamadas;
    // Trabajo de red real que el camino completo drena.
    let (tx_red, rx_red) = red::nueva_cola_trabajo_red();
    nodo.trabajo_red = Some(rx_red);
    let bloque_red = BloqueRed::Post {
        cabecera: cabecera_min(300, &[hash_u32(9_001)]),
        justificacion: zx_core::wire_dag::JustificacionPot::nueva(vec![
            zx_core::wire_dag::PotCheckpoints::desde_outputs([[0; 16]; 8]),
        ])
        .expect("justificación"),
        txs: Vec::new(),
        testigos: Vec::new(),
    };
    let _ = tx_red.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
        de: libp2p::PeerId::random(),
        bloque: bloque_red,
        llegada: Instant::now(),
    });
    nodo.procesar_trabajo_red_pendiente();
    // Y una notificación PoT verificada.
    let (tx_bucle, _rx_bucle) = mpsc::channel();
    nodo.atender_msg_productor(
        MsgProductor::FronteraPot {
            flujo: terminal,
            slot: 2,
            n: n_vigente,
        },
        false,
        terminal,
        &tx_bucle,
    )
    .expect("frontera PoT en modo detenido");
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        ventana_antes,
        "en modo detenido no se abre ninguna ventana"
    );
    assert_eq!(
        nodo.procesar_votos_llamadas, llamadas_antes,
        "ningún camino llega a procesar_votos con el eclipse enclavado"
    );
    assert!(
        !texto(dir.path()).contains("\"tipo\":\"voto_emitido\""),
        "no se emite voto en modo detenido"
    );
    assert_eq!(
        nodo.cursor_votos.as_ref().map(CursorVotos::slot_verificado),
        Some(2),
        "el cursor sí registra el tiempo PoT"
    );
}

// ---------------------------------------------------------------------------------------------
// Pruebas conservadas de la primera ronda
// ---------------------------------------------------------------------------------------------

/// VNT-R1 · una salida de otro flujo (terminal ajeno) o repetida no mueve el cursor ni abre nada.
#[test]
fn vnt1_flujo_ajeno_y_repetida_no_mueven_el_cursor() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
    let (tx, _rx) = mpsc::channel();
    let ajeno = hash_u32(9_999);
    nodo.atender_msg_productor(
        MsgProductor::FronteraPot {
            flujo: ajeno,
            slot: 10,
            n: 0,
        },
        false,
        terminal,
        &tx,
    )
    .expect("mensaje ajeno");
    assert_eq!(nodo.slot_votos(), 0, "un flujo ajeno no mueve s_v");
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .expect("motor")
            .ultima_ventana_abierta(),
        Some(0),
        "no se abrió ninguna ventana nueva"
    );
}

/// VNT-R2 · control §3.5(b): con solo el intercalado, si el bloque de la ventana siguiente llega
/// antes y **no** hubo salida PoT local, la ventana intermedia sigue sin abrirse: VNT-1 no es el
/// arreglo completo de B-60 (eso exige la recuperación con instancia de VNT-3).
#[test]
fn vnt1_sin_salida_local_la_ventana_intermedia_sigue_saltandose_control() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
    // El bloque de la ventana siguiente (n=2) se conoce antes que el de n=1, sin PoT local.
    nodo.cursor_votos = Some(CursorVotos::nuevo(terminal, 1, 4));
    nodo.atender_fronteras_votos()
        .expect("despacho en punto completo");
    let motor = nodo.motor_votos.as_ref().expect("motor");
    assert_eq!(
        motor.ultima_ventana_abierta(),
        Some(2),
        "se abre la ventana observada, no la intermedia"
    );
    assert_eq!(
        motor.instancia_actual(),
        Some(2),
        "la ventana intermedia n=1 no tiene instancia"
    );
}

/// VNT-R2 · un salto grande se trata como intervalo y no materializa el rango: el cursor devuelve
/// solo el horizonte. Se comprueba sobre la pieza, que es quien lo garantiza.
#[test]
fn vnt1_salto_grande_no_materializa_el_rango() {
    let dir = tempfile::tempdir().expect("temporal");
    let nodo = nodo_corte(dir.path(), estado_inicial(3));
    let terminal = nodo.cadena.terminal().expect("terminal");
    let cursor = CursorVotos::nuevo(terminal, 1, 10_000);
    let pendientes =
        cursor.fronteras_pendientes(Nodo::t_inst_votos(), Nodo::horizonte_fronteras_votos());
    assert_eq!(pendientes.len(), 82, "H=81 anteriores + la actual");
    assert_eq!(pendientes.first(), Some(&(5_000 - 81)));
    assert_eq!(pendientes.last(), Some(&5_000));
}

/// VNT-1 §3.4 · una reorganización no rebobina el cursor (y, por tanto, tampoco el permiso de
/// firma que depende de `s_v`). Se prueba con el cambio de terminal de la pieza.
#[test]
fn vnt1_reorg_no_rebobina_el_cursor() {
    let original = hash_u32(1);
    let otra = hash_u32(2);
    let mut cursor = CursorVotos::nuevo(original, 1, 100);
    cursor.reconciliar(otra, 1);
    assert_eq!(cursor.slot_verificado(), 100, "s_v no rebobina");
    assert_eq!(cursor.terminal(), otra);
}

// ---------------------------------------------------------------------------------------------
// §3.2 · Los cuatro papeles
// ---------------------------------------------------------------------------------------------

fn notifica_y_abre(sin_voto: bool) {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
    nodo.vota = !sin_voto;
    let n_vigente = nodo.servicios_verificacion[&terminal].n_vigente(2);
    let (tx, _rx) = mpsc::channel();
    nodo.atender_msg_productor(
        MsgProductor::FronteraPot {
            flujo: terminal,
            slot: 2,
            n: n_vigente,
        },
        false,
        terminal,
        &tx,
    )
    .expect("frontera del papel");
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        Some(1),
        "el papel abre la ventana n=1"
    );
    assert!(
        !texto(dir.path()).contains("\"tipo\":\"voto_emitido\""),
        "el papel de la prueba no firma (motor con emitir_votos=false)"
    );
}

/// Papel **votante**: el motor está presente y la frontera abre la ventana.
#[test]
fn vnt1b_papel_votante() {
    notifica_y_abre(false);
}

/// Papel **`--sin-voto`**: recibe la misma notificación y el motor abre la ventana; no firma.
#[test]
fn vnt1b_papel_sin_voto() {
    notifica_y_abre(true);
}

/// Papel **sin claves ni sectores**: no hay motor, así que lo observable es **solo el cursor**; el
/// hilo real (sin claves) sigue enviando sus fronteras.
#[test]
fn vnt1b_papel_sin_claves_solo_cursor() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    assert!(nodo.motor_votos.is_none(), "sin motor en este papel");
    let terminal = nodo.cadena.terminal().expect("terminal");
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
            Some(3),
            &rx_bucle,
            &tx_prod,
            &registro,
        );
    });
    let mut terminal_loop = terminal;
    let mut frontera_enviada = 0u64;
    for _ in 0..400 {
        let _ = nodo.iteracion_regimen(
            &rx_prod,
            &tx_bucle,
            &mut terminal_loop,
            &mut frontera_enviada,
        );
        if nodo.slot_votos() >= 2 {
            break;
        }
    }
    let _ = tx_bucle.send(MsgBucle::Parar);
    let _ = hilo.join();
    assert!(nodo.motor_votos.is_none(), "este papel no tiene motor");
    assert!(
        nodo.slot_votos() >= 2,
        "el cursor registra el tiempo PoT sin motor"
    );
    assert_eq!(
        nodo.cursor_votos.as_ref().map(CursorVotos::slot_verificado),
        Some(nodo.slot_votos()),
        "lo observable es el cursor"
    );
}

/// Papel **productor**: la frontera se atiende tras su propio bloque, por `procesar_post_propio`.
#[test]
fn vnt1b_papel_productor() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 2, 200, &[0, 1, 2]);
    let bloque = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(terminal, &[]).expect("padres"),
        slot,
        nodo.reloj_local() as u64,
        indice,
        CuerpoProductor::vacio(),
    );
    let hash = bloque.cabecera.block_hash();
    let (tx, _rx) = mpsc::channel();
    let _control = nodo
        .procesar_post_propio(
            1,
            bloque,
            Instant::now(),
            u32::try_from(indice).expect("índice"),
            terminal,
            &tx,
        )
        .expect("bloque propio real");
    assert!(
        nodo.cadena.es_valido(&hash),
        "el bloque propio se admitió por la ruta real"
    );
    assert_eq!(
        nodo.motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta),
        Some(slot.div_euclid(Nodo::t_inst_votos())),
        "la frontera se atiende tras el bloque propio"
    );
}

// ---------------------------------------------------------------------------------------------
// §3.7 · Reinicio
// ---------------------------------------------------------------------------------------------

/// Reinicio real sobre el mismo directorio: el servicio se rehace desde la cadena persistida y el
/// cursor se rehace desde el servicio; la guarda de arranque sigue impidiendo reabrir una ventana
/// que no sea posterior a la última firmada.
#[test]
fn vnt1b_reinicio_rehace_cursor_desde_el_servicio() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_real(dir.path());
    let terminal = nodo.cadena.terminal().expect("terminal");
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(&nodo, &mut servicio, 2, 200, &[0, 1, 2]);
    let bloque = producir(
        &nodo,
        &mut servicio,
        PadresDag::nuevo(terminal, &[]).expect("padres"),
        slot,
        nodo.reloj_local() as u64,
        indice,
        CuerpoProductor::vacio(),
    );
    assert_eq!(
        recibir(&mut nodo, &bloque),
        VeredictoFinal::Aceptar,
        "bloque admitido y persistido"
    );
    drop(nodo);
    let mut nodo2 = Nodo::arrancar(&config_real(dir.path())).expect("reinicio real");
    nodo2.asegurar_servicios_verificacion().expect("servicios");
    let terminal2 = nodo2.cadena.terminal().expect("terminal tras reinicio");
    assert_eq!(terminal2, terminal);
    assert!(
        nodo2.slot_cadena_votos() >= slot,
        "el servicio de tiempo se rehace desde la cadena persistida ({} < {slot})",
        nodo2.slot_cadena_votos()
    );
    assert!(nodo2.cursor_votos.is_none(), "cursor nuevo tras reiniciar");
    nodo2.motor_votos = Some(motor_con_claves());
    nodo2.atender_fronteras_votos().expect("resincronización");
    let cursor = nodo2.cursor_votos.as_ref().expect("cursor rehecho");
    assert!(
        cursor.slot_verificado() >= slot,
        "el cursor se rehace desde el servicio"
    );
    // La guarda de arranque que ya existía sigue clasificando n <= última firmada como espera.
    assert_eq!(
        clase_arranque_votos(None, Some(slot), slot),
        Some("espera_reloj")
    );
    assert_eq!(clase_arranque_votos(None, Some(slot), slot + 1), None);
}

// ---------------------------------------------------------------------------------------------
// §3 · Medida informativa (no se publica como medida de máquina)
// ---------------------------------------------------------------------------------------------

/// Medida **informativa** del coste de `atender_fronteras_votos`: media de una llamada que abre
/// ventana y de una que no abre. No se publica como medida de máquina.
#[test]
#[ignore = "medida informativa: orden de magnitud del coste por bloque admitido"]
fn vnt1b_medida_fronteras_abre_y_no_abre() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo_corte(dir.path(), estado_inicial(3));
    let (terminal, base) = base_del_terminal(&nodo);
    let mut motor = motor_con_claves();
    motor.avanzar(0, terminal, &base, 0).expect("apertura 0");
    nodo.motor_votos = Some(motor);
    let mut abre = Vec::with_capacity(30);
    for k in 1..=30u64 {
        nodo.cursor_votos = Some(CursorVotos::nuevo(terminal, 1, 2 * k));
        let t = Instant::now();
        nodo.atender_fronteras_votos().expect("apertura");
        abre.push(t.elapsed().as_nanos());
    }
    // Una llamada que no abre: el mismo cursor ya consumido y sin fronteras pendientes.
    let mut no_abre = Vec::with_capacity(30);
    for _ in 0..30 {
        let t = Instant::now();
        nodo.atender_fronteras_votos().expect("sin apertura");
        no_abre.push(t.elapsed().as_nanos());
    }
    let media = |v: &[u128]| {
        v.iter()
            .sum::<u128>()
            .div_euclid(u128::try_from(v.len()).expect("len"))
    };
    println!(
        "MEDIDA-INFORMATIVA atender_fronteras_votos: abre_media_ns={} no_abre_media_ns={} (30 cada una)",
        media(&abre),
        media(&no_abre)
    );
}
