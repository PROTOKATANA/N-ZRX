//! B78-1: caracterización con el motor, el despacho PoST y la cadena reales.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "fixtures de caracterización; las aserciones fallan por panic"
)]
use super::pruebas_eclr2::{genesis, hash_u32, post_con_txs, tx_coinbase_post};
use super::*;
use zx_consensus::sectores::{ClaveVoto, ParametrosSector, RegistroSector};
use zx_consensus::transicion::{Fase, Garantia};
use zx_core::Amount;
use zx_votos::CertificadoPeso;
use zx_votos::agregacion::Agregado;

type TxTestigos = (Tx, Vec<Vec<u8>>);
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
        // Una clave tiene quórum con su peso real; las demás conservan un sector cada una.
        let sectores = if i == 0 { 2 * n_claves } else { 1 };
        for j in 0..sectores {
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

fn nodo_pow_modo(dir: &Path, estado: EstadoTransicion, sin_voto: bool) -> Nodo {
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
    nodo
}

fn refrescar_cola(nodo: &mut Nodo, base: EstadoTransicion) {
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        perfil::parametros_evidencia_dev(),
        nodo.cbid,
        base,
        Politica::dev(),
    )));
}

fn nodo(dir: &Path, estado: EstadoTransicion) -> Nodo {
    nodo_modo(dir, estado, false)
}

fn nodo_modo(dir: &Path, estado: EstadoTransicion, sin_voto: bool) -> Nodo {
    let mut nodo = nodo_pow_modo(dir, estado, sin_voto);
    let productor = nodo.claves[0].pk;
    nodo.cadena
        .admitir(post_con_txs(
            31,
            vec![hash_u32(nodo.params.h_corte_min)],
            1,
            u64::MAX,
            productor,
            vec![(
                tx_coinbase_post(productor, perfil::SUBSIDIO_POST_BREK, 1),
                Vec::new(),
            )],
        ))
        .expect("primer PoST real en Cadena");
    let base = nodo
        .cadena
        .estado_post(&hash_u32(31))
        .expect("estado PoST")
        .clone();
    assert_eq!(base.fase, Fase::PoST);
    refrescar_cola(&mut nodo, base);
    nodo
}

fn armar(nodo: &mut Nodo, slot: u64) -> Vec<TxTestigos> {
    let (tx, rx) = mpsc::channel();
    let terminal = nodo.cadena.terminal().expect("terminal");
    let resultado = nodo
        .atender_msg_productor(
            MsgProductor::PeticionPadres { id: 1, slot },
            false,
            terminal,
            &tx,
        )
        .expect("despacho REAL del productor");
    assert!(matches!(resultado, ControlBucle::Continuar));
    let MsgBucle::Padres { txs, testigos, .. } = rx.try_recv().expect("cuerpo enviado al hilo")
    else {
        panic!("respuesta distinta de Padres");
    };
    // Constructor real del receptor: tampoco rechaza aquí el exceso de tamaño.
    let cuerpo = zx_post::productor_regimen::CuerpoProductor::nuevo(txs, testigos)
        .expect("el receptor acepta el cuerpo");
    cuerpo
        .txs()
        .iter()
        .cloned()
        .zip(cuerpo.testigos().iter().cloned())
        .collect()
}

fn aplicar_cuerpo(
    nodo: &mut Nodo,
    id: u32,
    slot: u64,
    cuerpo: Vec<TxTestigos>,
) -> Result<(), MotivoBloque> {
    let padres = padres_de_regimen(&nodo.cadena).expect("padres reales");
    let mut pares = vec![(
        tx_coinbase_post(nodo.claves[0].pk, perfil::SUBSIDIO_POST_BREK, slot),
        Vec::new(),
    )];
    pares.extend(cuerpo);
    nodo.cadena.admitir(post_con_txs(
        id,
        std::iter::once(padres.seleccionado())
            .chain(padres.extras().iter().copied())
            .collect(),
        slot,
        u64::MAX,
        nodo.claves[0].pk,
        pares,
    ))
}

fn motor(emitir: bool, con_claves: bool) -> MotorVotos {
    MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: perfil::parametros_votos_dev(),
            claves: if con_claves {
                (0..3)
                    .map(|i| crate::votos::clave_voto_dev(1, i).expect("clave BLS dev"))
                    .collect()
            } else {
                Vec::new()
            },
            emitir_votos: emitir,
        },
        1,
    )
}

fn ventanas(cuerpo: &[TxTestigos]) -> Vec<u64> {
    cuerpo
        .iter()
        .filter_map(|(tx, _)| operacion_certificado_peso(tx))
        .filter_map(ventana_de_certificado_peso)
        .collect()
}

fn operacion(cert: &CertificadoPeso) -> zx_core::OperacionAlmacenamiento {
    zx_core::OperacionAlmacenamiento::CertificadoPeso {
        clave: ClaveDev::derivar(1, 0).pk,
        bytes: zx_votos::serial_certificado_peso(cert),
    }
}

fn rama(nodo: &mut Nodo, padre: u32, id: u32, slot: u64, cert: Option<&CertificadoPeso>) {
    let mut txs = vec![(
        tx_coinbase_post(nodo.claves[0].pk, perfil::SUBSIDIO_POST_BREK, slot),
        Vec::new(),
    )];
    if let Some(cert) = cert {
        let c = &nodo.claves[0];
        txs.push(crate::votos::tx_certificado_peso(
            cert, c.pk, &c.sk, nodo.cbid,
        ));
    }
    nodo.cadena
        .admitir(post_con_txs(
            id,
            vec![hash_u32(padre)],
            slot,
            u64::MAX,
            nodo.claves[0].pk,
            txs,
        ))
        .expect("bloque de rama aplicado por cadena real");
}

#[test]
fn n1_certificado_de_ventana_liquidada_no_cambia_cuentas() {
    use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, cierre_ventana};
    let dir = tempfile::tempdir().expect("temporal");
    let mut inicial = estado_inicial(3);
    for g in inicial.garantias.values_mut() {
        g.activo = Amount::nuevo(2_000_000_000).expect("garantía que permite cobro observable");
    }
    let mut nodo = nodo(dir.path(), inicial);
    let base = nodo
        .cadena
        .estado_post(&hash_u32(31))
        .expect("base")
        .clone();
    let mut motor = motor(true, true);
    motor.avanzar(0, hash_u32(31), &base, 0).expect("abrir");
    let c0 = motor
        .avanzar(1, hash_u32(31), &base, 2)
        .expect("cerrar")
        .certificado_peso
        .expect("certificado auténtico");
    // La primera finalidad da una tabla real al cobro de las ventanas siguientes.
    rama(&mut nodo, 31, 89, 2, Some(&c0));
    let base = nodo
        .cadena
        .estado_post(&hash_u32(89))
        .expect("base certificada")
        .clone();
    let c1 = motor
        .avanzar(2, hash_u32(31), &base, 4)
        .expect("cerrar 1")
        .certificado_peso
        .expect("certificado 1 auténtico");
    let vence = cierre_ventana(c1.n) + W_REVEAL_SLOTS_VOTOS;
    // El primer bloque vencido liquida antes de ejecutar sus transacciones.
    rama(&mut nodo, 89, 90, vence + 1, None);
    let liquidada = nodo.cadena.estado_post(&hash_u32(90)).expect("liquidada");
    assert_eq!(liquidada.liquidacion_voto_hasta, Some(1));
    assert!(
        liquidada.quemado > base.quemado,
        "control: la liquidación cobró una multa real"
    );
    rama(&mut nodo, 90, 91, vence + 2, None);
    rama(&mut nodo, 90, 92, vence + 2, Some(&c1));
    let sin = nodo
        .cadena
        .estado_post(&hash_u32(91))
        .expect("sin certificado");
    let con = nodo
        .cadena
        .estado_post(&hash_u32(92))
        .expect("con certificado");
    assert_eq!(sin.garantias, con.garantias, "ninguna garantía cambia");
    assert_eq!(
        sin.deuda_ausencia, con.deuda_ausencia,
        "ninguna deuda cambia"
    );
    assert_eq!(sin.quemado, con.quemado, "ninguna multa cambia");
    assert_eq!(sin.liquidacion_voto_hasta, con.liquidacion_voto_hasta);
    assert_eq!(sin.finalidad_votos_n, 0);
    assert_eq!(con.finalidad_votos_n, 0);
    assert_eq!(con.finalidad_votos, Some(hash_u32(31)));
    assert_eq!(con.votantes_voto.get(&1), sin.votantes_voto.get(&1));
    let descartes = nodo
        .cadena
        .descartes(&hash_u32(92))
        .expect("descartes reales");
    assert_eq!(descartes.len(), 1);
    assert_eq!(
        descartes[0].motivo,
        zx_consensus::transicion::ErrorTransicion::ErrCertificadoPlazo
    );
    println!(
        "N1 liquidada: slot={}, liquidacion={:?}, garantías_iguales=true, deudas_iguales=true, multas_iguales=true, quemado={}",
        vence + 2,
        con.liquidacion_voto_hasta,
        con.quemado
    );
    // Control positivo: antes de liquidar, el mismo certificado evita el cobro de n=1.
    rama(&mut nodo, 89, 93, 4, Some(&c1));
    rama(&mut nodo, 93, 94, vence + 1, None);
    let puntual = nodo
        .cadena
        .estado_post(&hash_u32(94))
        .expect("control puntual");
    let tardia = nodo
        .cadena
        .estado_post(&hash_u32(90))
        .expect("control sin presencia");
    assert!(
        puntual.quemado < tardia.quemado,
        "control positivo distingue presencia antes de liquidar"
    );
    println!(
        "N1 control positivo: quemado_puntual={}, quemado_sin_certificado={}",
        puntual.quemado, tardia.quemado
    );
}

#[test]
fn b781_certificado_anterior_no_ofrecido_control_rojo() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path(), estado_inicial(3));
    let base = nodo
        .cadena
        .estado_post(&hash_u32(31))
        .expect("base")
        .clone();
    let mut motor = motor(true, true);
    motor.avanzar(0, hash_u32(31), &base, 0).expect("abrir 0");
    let c0 = motor
        .avanzar(1, hash_u32(31), &base, 2)
        .expect("cerrar 0")
        .certificado_peso
        .expect("certificado 0");
    let c1 = motor
        .avanzar(2, hash_u32(31), &base, 4)
        .expect("cerrar 1")
        .certificado_peso
        .expect("certificado 1");
    assert_eq!((c0.n, c1.n), (0, 1));
    assert_eq!(motor.certificados_peso().len(), 2);
    nodo.motor_votos = Some(motor);
    let cuerpo = armar(&mut nodo, 4);
    assert_eq!(
        ventanas(&cuerpo),
        vec![0, 1],
        "ambas ventanas, en orden de aplicación"
    );
    aplicar_cuerpo(&mut nodo, 100, 4, cuerpo).expect("bloque real admitido");
    let aplicado = nodo
        .cadena
        .estado_post(&hash_u32(100))
        .expect("estado real");
    assert_eq!(aplicado.finalidad_votos_n, 1);
    assert!(
        aplicado
            .votantes_voto
            .get(&1)
            .is_some_and(|v| !v.is_empty())
    );
    assert!(
        aplicado
            .votantes_voto
            .get(&0)
            .is_some_and(|v| !v.is_empty())
    );
    let (_e, _u, resultado) = zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo(
        aplicado,
        &operacion(&c0),
        4,
    );
    assert_eq!(
        resultado,
        Err(zx_consensus::transicion::ErrorTransicion::ErrFinalidadRetrocede)
    );
    nodo.reconciliar_ancla_de_bloque(hash_u32(100), &[]);
    assert!(
        nodo.motor_votos
            .as_ref()
            .expect("motor")
            .certificados_peso()
            .is_empty()
    );
    println!(
        "B782 anterior: cuerpo=[0,1], finalidad=1, firmantes de ambas ventanas; pendientes=0 tras aplicación"
    );
}

#[test]
fn b781_agregado_despues_del_cierre_control_rojo() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path(), estado_inicial(3));
    let base = nodo
        .cadena
        .estado_post(&hash_u32(31))
        .expect("base")
        .clone();
    let mut emisor = motor(true, true);
    emisor
        .avanzar(0, hash_u32(31), &base, 0)
        .expect("abrir emisor");
    let agregados: Vec<_> = emisor
        .publicar_agregado(1)
        .expect("agregación real")
        .iter()
        .map(|bytes| Agregado::deserializar(bytes, 3).expect("agregado canónico"))
        .collect();
    assert!(!agregados.is_empty());
    let mut receptor = motor(false, false);
    let apertura = receptor
        .avanzar(0, hash_u32(31), &base, 0)
        .expect("abrir receptor");
    assert!(apertura.votos.is_empty());
    let cierre = receptor
        .avanzar(1, hash_u32(31), &base, 2)
        .expect("cerrar sin cuórum");
    assert!(cierre.certificado_peso.is_none());
    let respuestas = receptor
        .recibir_agregados(&agregados)
        .expect("entrega tardía real");
    assert!(
        respuestas
            .iter()
            .all(|r| *r == crate::votos::RecepcionAgregado::Ignorar)
    );
    assert_eq!(receptor.certificados_peso().len(), 1);
    emisor
        .avanzar(1, hash_u32(31), &base, 2)
        .expect("ventana 1 emisor");
    let agregados1: Vec<_> = emisor
        .publicar_agregado(3)
        .expect("agregado 1")
        .iter()
        .map(|b| Agregado::deserializar(b, 3).expect("agregado 1 válido"))
        .collect();
    receptor
        .recibir_agregados(&agregados1)
        .expect("cuórum de la actual");
    receptor
        .avanzar(2, hash_u32(31), &base, 4)
        .expect("cerrar 1 receptor");
    nodo.motor_votos = Some(receptor);
    let cuerpo = armar(&mut nodo, 4);
    assert_eq!(ventanas(&cuerpo), vec![0, 1]);
    aplicar_cuerpo(&mut nodo, 100, 4, cuerpo).expect("certificado tardío antes del nuevo admitido");
    assert_eq!(
        nodo.cadena
            .estado_post(&hash_u32(100))
            .expect("estado real")
            .finalidad_votos,
        Some(hash_u32(31))
    );
    // Control positivo: el mismo emisor sí produjo un agregado que completa el cuórum.
    let mut a_tiempo = motor(false, false);
    a_tiempo
        .avanzar(0, hash_u32(31), &base, 0)
        .expect("abrir control");
    assert!(
        a_tiempo
            .recibir_agregados(&agregados)
            .expect("entrega a tiempo")
            .contains(&crate::votos::RecepcionAgregado::Reenviar)
    );
    let cert = a_tiempo
        .avanzar(1, hash_u32(31), &base, 2)
        .expect("cerrar control")
        .certificado_peso
        .expect("cuórum real del agregado");
    rama(&mut nodo, 31, 101, 3, Some(&cert));
    assert_eq!(
        nodo.cadena
            .estado_post(&hash_u32(101))
            .expect("estado control")
            .finalidad_votos,
        Some(hash_u32(31))
    );
    println!(
        "B782 tardío: no reenviado; certificado 0 formado tras cierre y aplicado por cadena real"
    );
}

fn preparar_dos(nodo: &mut Nodo) -> Vec<CertificadoPeso> {
    let base = nodo
        .cadena
        .estado_post(&hash_u32(31))
        .expect("base")
        .clone();
    let mut m = motor(true, true);
    m.avanzar(0, hash_u32(31), &base, 0).expect("abrir");
    m.avanzar(1, hash_u32(31), &base, 2).expect("cerrar 0");
    m.avanzar(2, hash_u32(31), &base, 4).expect("cerrar 1");
    let certificados = m.certificados_peso().to_vec();
    nodo.motor_votos = Some(m);
    certificados
}

#[test]
fn presupuesto_justo_ofrece_antiguo_y_conserva_nuevo() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut n = nodo(dir.path(), estado_inicial(3));
    let certs = preparar_dos(&mut n);
    let clave = &n.claves[0];
    let tx = crate::votos::tx_certificado_peso(&certs[0], clave.pk, &clave.sk, n.cbid);
    let coinbase = tx_coinbase_post(clave.pk, perfil::SUBSIDIO_POST_BREK, 4);
    n.params.max_cuerpo_bloque_bytes = bytes_cuerpo_post(&coinbase, &[&[tx]]);
    let cuerpo = armar(&mut n, 4);
    assert_eq!(ventanas(&cuerpo), vec![0]);
    assert!(bytes_cuerpo_post(&coinbase, &[&cuerpo]) <= n.params.max_cuerpo_bloque_bytes);
    assert_eq!(
        n.motor_votos
            .as_ref()
            .expect("motor")
            .certificados_peso()
            .len(),
        2
    );
    aplicar_cuerpo(&mut n, 100, 4, cuerpo).expect("cuerpo justo válido");
    n.reconciliar_ancla_de_bloque(hash_u32(100), &[]);
    assert_eq!(
        n.motor_votos.as_ref().expect("motor").certificados_peso()[0].n,
        1
    );
    assert_eq!(ventanas(&armar(&mut n, 5)), vec![1]);
}

#[test]
fn bloque_ajeno_suelta_aplicado_y_superado() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut n = nodo(dir.path(), estado_inicial(3));
    let certs = preparar_dos(&mut n);
    rama(&mut n, 31, 100, 4, Some(&certs[1]));
    n.reconciliar_ancla_de_bloque(hash_u32(100), &[]);
    assert!(
        n.motor_votos
            .as_ref()
            .expect("motor")
            .certificados_peso()
            .is_empty()
    );
    assert!(ventanas(&armar(&mut n, 5)).is_empty());
    let log = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert_eq!(log.matches("\"causa\":\"aplicado\"").count(), 1);
    assert_eq!(log.matches("\"causa\":\"superado\"").count(), 1);
}

#[test]
fn finalidad_parada_cota_derivada_y_ultimo_siempre() {
    use zx_consensus::transicion::votos::{T_INST_VOTOS, W_REVEAL_SLOTS_VOTOS, cierre_ventana};
    let mut estado = estado_inicial(3);
    let mut m = motor(true, true);
    let cap = MotorVotos::cota_certificados_peso();
    assert_eq!(cap, W_REVEAL_SLOTS_VOTOS.div_ceil(T_INST_VOTOS) + 1);
    let total = cap * 2 + 3;
    for n in 0..=total {
        (estado, _) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
            &estado,
            n * T_INST_VOTOS,
        );
        m.avanzar(
            n,
            hash_u32(31),
            &estado,
            i64::try_from(n * T_INST_VOTOS).expect("slot"),
        )
        .expect("avance sin finalidad de cadena");
        assert!(u64::try_from(m.certificados_peso().len()).expect("len") <= cap);
    }
    assert_eq!(m.ultimo_certificado_peso().expect("último").n, total - 1);
    assert_eq!(crate::votos::resumen(&m).certificados, total);
    let soltados = m.drenar_eventos_certificados_peso();
    assert!(!soltados.is_empty());
    assert!(soltados.iter().all(|(_, c)| *c == "liquidada"));
    let ultimo = total - 1;
    let limite = cierre_ventana(ultimo) + W_REVEAL_SLOTS_VOTOS;
    m.actualizar_certificados_peso(&estado, limite + 1);
    assert_eq!(m.certificados_peso().len(), 1);
    assert_eq!(m.certificados_peso()[0].n, ultimo);
    println!(
        "N1 cota={}, certificados formados={}, pendientes_max<=cota; último retenido tras liquidación",
        cap, total
    );
}

#[test]
fn voto_tardio_solo_anterior_sin_firmar_ni_reenviar() {
    let dir = tempfile::tempdir().expect("temporal");
    let nodo = nodo(dir.path(), estado_inicial(3));
    let estado = nodo
        .cadena
        .estado_post(&hash_u32(31))
        .expect("base")
        .clone();
    let mut e = motor(true, true);
    let paso = e.avanzar(0, hash_u32(31), &estado, 0).expect("emisor");
    let mut r = motor(false, false);
    r.avanzar(0, hash_u32(31), &estado, 0).expect("receptor");
    r.avanzar(1, hash_u32(31), &estado, 2).expect("cerrar");
    for (bytes, subred) in &paso.votos_red {
        assert!(matches!(
            r.recibir_voto_subred(*subred, bytes, &nodo.cadena),
            crate::votos::RecepcionVotoSubred::Ignorar { .. }
        ));
    }
    assert_eq!(r.certificados_peso().len(), 1);
    for (bytes, subred) in &paso.votos_red {
        let _ = r.recibir_voto_subred(*subred, bytes, &nodo.cadena);
    }
    assert_eq!(
        r.drenar_eventos_certificados_peso(),
        vec![(0, "formado_tras_cierre")]
    );
    assert!(r.publicar_agregado(3).expect("sin emisión").is_empty());
    let mut legado = motor(false, false);
    legado
        .avanzar(0, hash_u32(31), &estado, 0)
        .expect("abrir legado");
    legado
        .avanzar(1, hash_u32(31), &estado, 2)
        .expect("cerrar legado");
    for bytes in &paso.votos {
        assert!(matches!(
            legado.recibir_voto_con_vista(bytes, &nodo.cadena),
            crate::votos::RecepcionVoto::Rechazado { motivo: "ventana" }
        ));
    }
    assert_eq!(legado.certificados_peso().len(), 1);
    let mut demasiado_tarde = motor(false, false);
    for n in 0..=2 {
        let paso = demasiado_tarde
            .avanzar(n, hash_u32(31), &estado, n as i64 * 2)
            .expect("avance");
        assert!(paso.votos.is_empty());
        assert!(paso.votos_red.is_empty());
    }
    for (bytes, subred) in &paso.votos_red {
        let _ = demasiado_tarde.recibir_voto_subred(*subred, bytes, &nodo.cadena);
    }
    assert!(demasiado_tarde.certificados_peso().is_empty());
}

#[test]
fn agregado_demasiado_tarde_o_cadena_superada_no_certifica() {
    let estado =
        zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(&estado_inicial(3), 0).0;
    let mut e = motor(true, true);
    e.avanzar(0, hash_u32(31), &estado, 0).expect("emisor");
    let agregados: Vec<_> = e
        .publicar_agregado(1)
        .expect("agregados")
        .iter()
        .map(|b| Agregado::deserializar(b, 3).expect("agregado"))
        .collect();
    assert!(!agregados.is_empty(), "el negativo recibe agregados reales");
    let mut r = motor(false, false);
    for n in 0..=2 {
        r.avanzar(n, hash_u32(31), &estado, n as i64 * 2)
            .expect("avance");
    }
    assert!(
        r.recibir_agregados(&agregados)
            .expect("tarde")
            .iter()
            .all(|v| *v == crate::votos::RecepcionAgregado::Ignorar)
    );
    assert!(r.certificados_peso().is_empty());
    let mut r = motor(false, false);
    r.avanzar(0, hash_u32(31), &estado, 0).expect("abrir");
    r.avanzar(1, hash_u32(31), &estado, 2).expect("cerrar");
    let mut superada = estado;
    superada.finalidad_votos = Some(hash_u32(31));
    superada.finalidad_votos_n = 1;
    r.actualizar_certificados_peso(&superada, 2);
    r.recibir_agregados(&agregados).expect("superada");
    assert!(r.certificados_peso().is_empty());
}

#[test]
fn n5_cada_aplicado_y_oferta_anterior_una_vez() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut n = nodo(dir.path(), estado_inicial(3));
    let certificados = preparar_dos(&mut n);
    let mut cuerpo = armar(&mut n, 4);
    armar(&mut n, 4);
    // Un bloque admitido puede descartar una transacción: no debe inventarse una aplicación.
    let mut descartado = certificados[0].clone();
    descartado.candidato = *hash_u32(999).as_bytes();
    cuerpo.push(crate::votos::tx_certificado_peso(
        &descartado,
        n.claves[0].pk,
        &n.claves[0].sk,
        n.cbid,
    ));
    let mut txs = vec![tx_coinbase_post(
        n.claves[0].pk,
        perfil::SUBSIDIO_POST_BREK,
        4,
    )];
    txs.extend(cuerpo.iter().map(|(tx, _)| tx.clone()));
    aplicar_cuerpo(&mut n, 100, 4, cuerpo).expect("bloque");
    let descartes = n
        .cadena
        .descartes(&hash_u32(100))
        .expect("descartes reales");
    assert_eq!(descartes.len(), 1);
    assert_eq!(descartes[0].indice, 3);
    n.reconciliar_ancla_de_bloque(hash_u32(100), &txs);
    let log = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    let aplicados: Vec<_> = log
        .lines()
        .filter(|l| l.contains("\"tipo\":\"certificado_peso_aplicado\""))
        .collect();
    assert_eq!(aplicados.len(), 2);
    assert!(aplicados[0].contains("\"n\":0"));
    assert!(aplicados[1].contains("\"n\":1"));
    assert_eq!(
        log.matches("\"tipo\":\"certificado_peso_anterior_ofrecido\"")
            .count(),
        1
    );
}

#[test]
fn sin_voto_y_sin_claves_reciben_arman_y_ofrecen() {
    for sin_voto in [true, false] {
        let dir = tempfile::tempdir().expect("temporal");
        let mut n = nodo_modo(dir.path(), estado_inicial(3), sin_voto);
        if sin_voto {
            assert!(!n.vota);
        }
        let base = n.cadena.estado_post(&hash_u32(31)).expect("base").clone();
        let mut e = motor(true, true);
        e.avanzar(0, hash_u32(31), &base, 0).expect("emisor");
        let agregados = e.publicar_agregado(1).expect("agregado");
        let mut r = motor(false, sin_voto);
        assert!(r.certificados_peso().is_empty(), "arranque limpio");
        let apertura = r
            .avanzar(0, hash_u32(31), &base, 0)
            .expect("abrir receptor");
        assert!(apertura.votos.is_empty());
        r.avanzar(1, hash_u32(31), &base, 2)
            .expect("cerrar sin cuórum");
        n.motor_votos = Some(r);
        let lote: Vec<_> = agregados
            .into_iter()
            .map(|b| (IdDiferido::default(), b))
            .collect();
        n.procesar_agregados_lote(&lote);
        n.procesar_agregados_lote(&lote);
        assert_eq!(n.agn.agregados_reenviados, 0);
        let cuerpo = armar(&mut n, 2);
        assert_eq!(ventanas(&cuerpo), vec![0]);
        aplicar_cuerpo(&mut n, 100, 2, cuerpo).expect("certificado de receptor real");
        let log = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
        assert_eq!(
            log.matches("\"tipo\":\"certificado_peso_formado_tras_cierre\"")
                .count(),
            1
        );
    }
}

#[test]
fn limite_deserializador_tardio_si_crece_el_mapa() {
    use zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo;
    let dir = tempfile::tempdir().expect("temporal");
    let mut n = nodo(dir.path(), estado_inicial(3));
    let a = n.cadena.estado_post(&hash_u32(31)).expect("base").clone();
    let mut e = motor(true, true);
    e.avanzar(0, hash_u32(31), &a, 0).expect("emisor");
    let bytes = e.publicar_agregado(1).expect("agregado");
    let (b, _) = derivar_tabla_sin_base_con_undo(&estado_inicial(9), 2);
    let mut r = motor(false, false);
    r.avanzar(0, hash_u32(31), &a, 0).expect("abrir 0");
    r.avanzar(1, hash_u32(31), &b, 2)
        .expect("abrir 1 con nueve claves");
    assert_eq!(r.tabla_actual().expect("tabla").claves.len(), 9);
    let ag = Agregado::deserializar(&bytes[0], 3).expect("válido para anterior");
    assert!(Agregado::deserializar(&bytes[0], 9).is_err());
    n.motor_votos = Some(r);
    let lote: Vec<_> = bytes
        .into_iter()
        .map(|b| (IdDiferido::default(), b))
        .collect();
    n.procesar_agregados_lote(&lote);
    assert!(
        n.motor_votos
            .as_ref()
            .expect("motor")
            .certificados_peso()
            .is_empty()
    );
    let r = n.motor_votos.as_mut().expect("motor");
    r.recibir_agregados(&[ag])
        .expect("entrega ya deserializada");
    assert_eq!(r.certificados_peso().len(), 1);
    println!(
        "Límite N3: nodo ignora agregado 3→9 claves antes del motor; el motor sí certifica la anterior"
    );
}

/// Fixture de cambio de tabla: la finalidad real compromete A; el gancho real deriva B.
fn base_con_cambio(n: &mut Nodo) -> EstadoTransicion {
    use zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo;
    let a = n.cadena.estado_post(&hash_u32(31)).expect("base").clone();
    let mut emisor = motor(true, true);
    emisor.avanzar(0, hash_u32(31), &a, 0).expect("abrir");
    let c = emisor
        .avanzar(1, hash_u32(31), &a, 2)
        .expect("cerrar")
        .certificado_peso
        .expect("certificado inicial");
    rama(n, 31, 100, 2, Some(&c));
    let mut b = n
        .cadena
        .estado_post(&hash_u32(100))
        .expect("base aplicada A")
        .clone();
    // El estado de fixture introduce una alta, sin inventar hashes ni certificados.
    let alta = estado_inicial(4);
    b.claves_voto = alta.claves_voto;
    b.sectores = alta.sectores;
    b.garantias.extend(alta.garantias);
    derivar_tabla_sin_base_con_undo(&b, 4).0
}

#[test]
fn tabla_tras_soltado_remonta_sueltos_y_no_remonta_agregados() {
    use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, cierre_ventana};
    let dir = tempfile::tempdir().expect("temporal");
    let mut n = nodo(dir.path(), estado_inicial(3));
    let b = base_con_cambio(&mut n);
    for con_agregados in [false, true] {
        let mut m = motor(!con_agregados, true);
        let mut emisor = motor(true, true);
        emisor
            .sembrar_base_de_estado(
                0,
                b.finalidad_votos_h_t.expect("A"),
                *hash_u32(31).as_bytes(),
            )
            .expect("base emisor");
        m.sembrar_base_de_estado(
            0,
            b.finalidad_votos_h_t.expect("A"),
            *hash_u32(31).as_bytes(),
        )
        .expect("base aplicada");
        m.avanzar(1, hash_u32(31), &b, 2)
            .expect("abrir 1 A, compromete B");
        emisor.avanzar(1, hash_u32(31), &b, 2).expect("emisor 1");
        if con_agregados {
            let agregados: Vec<_> = emisor
                .publicar_agregado(3)
                .expect("agregado 1")
                .iter()
                .map(|b| Agregado::deserializar(b, 3).expect("agregado A"))
                .collect();
            assert!(!agregados.is_empty());
            m.recibir_agregados(&agregados).expect("recibir A");
        }
        m.avanzar(2, hash_u32(31), &b, 4)
            .expect("cerrar 1, abrir B");
        assert_eq!(m.tabla_actual().expect("tabla B").claves.len(), 4);
        emisor.avanzar(2, hash_u32(31), &b, 4).expect("emisor 2");
        if con_agregados {
            let agregados: Vec<_> = emisor
                .publicar_agregado(5)
                .expect("agregado 2")
                .iter()
                .map(|b| Agregado::deserializar(b, 4).expect("agregado B"))
                .collect();
            assert!(!agregados.is_empty());
            m.recibir_agregados(&agregados).expect("recibir B");
        }
        m.avanzar(3, hash_u32(31), &b, 6).expect("certificado 2 B");
        let ultimo = m.ultimo_certificado_peso().expect("último").clone();
        assert_eq!(ultimo.n, 2);
        let slot = cierre_ventana(1) + W_REVEAL_SLOTS_VOTOS + 1;
        m.actualizar_certificados_peso(&b, slot);
        assert_eq!(
            m.certificados_peso()
                .iter()
                .map(|c| c.n)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert!(
            m.drenar_eventos_certificados_peso()
                .contains(&(1, "liquidada"))
        );
        let tabla_a = tabla_peso_para_bloque(&b, slot, 2);
        let (_, _, resultado_original) =
            zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo(
                &b,
                &operacion(&ultimo),
                i64::try_from(slot).expect("slot"),
            );
        assert!(
            resultado_original.is_err(),
            "el original falla en la transición real sobre A"
        );
        assert_eq!(
            m.certificado_para_tabla(&tabla_a)
                .expect("remonte")
                .is_none(),
            con_agregados
        );
        n.motor_votos = Some(m);
        let cb = tx_coinbase_post(n.claves[0].pk, perfil::SUBSIDIO_POST_BREK, slot);
        let cuerpo = n.certificados_para_cuerpo_post(&b, slot, &cb);
        assert_eq!(
            ventanas(&cuerpo),
            if con_agregados { vec![] } else { vec![2] }
        );
        if let Some((tx, _)) = cuerpo.first() {
            let op = operacion_certificado_peso(tx).expect("operación");
            let (estado, _, resultado) =
                zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo(
                    &b,
                    op,
                    i64::try_from(slot).expect("slot"),
                );
            resultado.expect("el consenso real acepta el remonte");
            assert_eq!(estado.finalidad_votos_n, 2);
        }
        println!(
            "Condición de tabla tras soltado: agregados={}, cuerpo={:?}",
            con_agregados,
            ventanas(&cuerpo)
        );
    }
}

#[test]
fn certificado_con_tabla_invalida_no_bloquea_siguiente() {
    use zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo;
    let dir = tempfile::tempdir().expect("temporal");
    let mut n = nodo(dir.path(), estado_inicial(3));
    let b = base_con_cambio(&mut n);
    let h_b = b.cola_tablas_voto.last().expect("tabla B derivada").1;
    let mut a = n
        .cadena
        .estado_post(&hash_u32(100))
        .expect("base A real")
        .clone();
    a.tablas_voto_contenido.extend(b.tablas_voto_contenido);
    a.cola_tablas_voto = b.cola_tablas_voto;
    let (mut vista_motor, _) = derivar_tabla_sin_base_con_undo(&a, 4);
    vista_motor.finalidad_votos_h_t = Some(h_b);
    let mut m = motor(true, true);
    m.sembrar_base_de_estado(0, h_b, *hash_u32(31).as_bytes())
        .expect("base de otra vista");
    m.avanzar(1, hash_u32(31), &vista_motor, 2)
        .expect("abrir B");
    assert_eq!(m.tabla_actual().expect("tabla B").claves.len(), 4);
    m.avanzar(2, hash_u32(31), &vista_motor, 4)
        .expect("certifica B y abre A");
    assert_eq!(m.tabla_actual().expect("tabla A").claves.len(), 3);
    m.avanzar(3, hash_u32(31), &vista_motor, 6)
        .expect("certifica A");
    let anterior = m.certificados_peso()[0].clone();
    let base = n
        .cadena
        .estado_post(&hash_u32(100))
        .expect("A seleccionada");
    let (_, _, resultado) = zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo(
        base,
        &operacion(&anterior),
        6,
    );
    assert!(resultado.is_err(), "control: el antiguo no verifica en A");
    n.motor_votos = Some(m);
    let cuerpo = armar(&mut n, 6);
    assert_eq!(ventanas(&cuerpo), vec![2]);
    aplicar_cuerpo(&mut n, 101, 6, cuerpo).expect("el siguiente sí se aplica");
    assert_eq!(
        n.cadena
            .estado_post(&hash_u32(101))
            .expect("aplicado")
            .finalidad_votos_n,
        2
    );
}

#[test]
fn certt_productor_no_ofrece_certificado_vencido() {
    use zx_consensus::transicion::votos::{W_REVEAL_SLOTS_VOTOS, cierre_ventana};
    let dir = tempfile::tempdir().expect("temporal");
    let mut n = nodo(dir.path(), estado_inicial(3));
    let certificados = preparar_dos(&mut n);
    let b = n.cadena.estado_post(&hash_u32(31)).expect("base").clone();
    let vence = cierre_ventana(certificados[0].n).saturating_add(W_REVEAL_SLOTS_VOTOS);
    let cb = tx_coinbase_post(n.claves[0].pk, perfil::SUBSIDIO_POST_BREK, vence);
    let puntual = n.certificados_para_cuerpo_post(&b, vence, &cb);
    assert_eq!(
        ventanas(&puntual),
        vec![0, 1],
        "control positivo del armado real"
    );
    let cb = tx_coinbase_post(n.claves[0].pk, perfil::SUBSIDIO_POST_BREK, vence + 1);
    let frontera = n.certificados_para_cuerpo_post(&b, vence + 1, &cb);
    assert_eq!(
        ventanas(&frontera),
        vec![1],
        "se omite solo el vencido; el siguiente sigue vigente"
    );
    let despues = cierre_ventana(certificados[1].n).saturating_add(W_REVEAL_SLOTS_VOTOS) + 1;
    let cb = tx_coinbase_post(n.claves[0].pk, perfil::SUBSIDIO_POST_BREK, despues);
    assert!(n.certificados_para_cuerpo_post(&b, despues, &cb).is_empty());
    assert_eq!(
        n.motor_votos
            .as_ref()
            .expect("motor")
            .certificados_peso()
            .len(),
        2,
        "los certificados siguen pendientes: es el camino de consenso quien filtra"
    );
}
