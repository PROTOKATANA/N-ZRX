//! RLJ-1: armado PoAS/PoT y puerta conjunta reales, sin sustituir el verificador del reloj.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::wildcard_imports,
    reason = "fixtures internas que fallan por panic"
)]

use super::*;
use zx_post::contexto_transicion::ContextoTransicion;
use zx_post::productor_regimen::{CuerpoProductor, producir_en_regimen_con_firmante};

const TS: u64 = 1_791_596_104;

pub(super) fn config(dir: &Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 101,
        indices_claves: vec![0],
        n_dev: 138_873_760,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev_reloj().expect("dev-reloj real"),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: true,
        sin_revelacion: true,
    }
}

pub(super) fn bloque_real(
    nodo: &Nodo,
    servicio: &mut ServicioPot,
    slot: u64,
    timestamp: u64,
) -> BloqueDag {
    let padres = PadresDag::nuevo(servicio.terminal(), &[]).expect("padre terminal");
    bloque_real_con_padres(nodo, servicio, padres, slot, timestamp)
}

/// RLJ-3a-2 · como [`bloque_real`], con los padres declarados explícitos (para encadenar un
/// segundo bloque real sobre el primero en las pruebas por el camino real).
pub(super) fn bloque_real_con_padres(
    nodo: &Nodo,
    servicio: &mut ServicioPot,
    padres: PadresDag,
    slot: u64,
    timestamp: u64,
) -> BloqueDag {
    let clave = nodo.claves.first().expect("clave propia");
    let parcela =
        abrir_o_crear_parcela(&nodo.dir_datos, clave, &nodo.historia).expect("parcela real");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &nodo.historia,
    };
    let registro = nodo.registro_firmante.as_ref().expect("firmante real");
    let mut firmante = Firmante::nuevo(registro);
    let p = ParametrosProductor {
        n_dev: nodo.n_dev_vigente(),
        sr_dev: u64::MAX,
        max_slots: 150,
        consensus_branch_id: nodo.cbid,
        timestamp,
        i_iter: nodo.perfil_red.reloj.i_iter,
        importe_coinbase: perfil::subsidio_post(0),
    };
    let producto = producir_en_regimen_con_firmante(
        padres,
        slot,
        servicio,
        &fuente,
        &clave.sk,
        &p,
        CuerpoProductor::vacio(),
        &mut firmante,
    )
    .expect("armado real de transición en slot exacto");
    match producto {
        ProductoFirmado::Bloque(bloque, _) => bloque,
        ProductoFirmado::Abstenido { .. } => panic!("oportunidad nueva"),
    }
}

pub(super) fn conjunta(nodo: &Nodo, servicio: &ServicioPot, bloque: &BloqueDag) {
    let ctx = ContextoTransicion::nuevo(
        servicio.terminal(),
        nodo.n_dev_vigente(),
        u64::MAX,
        Vec::new(),
    )
    .expect("contexto de transición");
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoIlimitado;
    assert!(
        matches!(
            verificar_cabecera_conjunta(
                bloque,
                servicio,
                &ctx,
                &RangoDev(u64::MAX),
                u64::MAX,
                &mut cache,
                &mut presupuesto,
                Some(&nodo.historia.params_pieza())
            ),
            EstadoCabeceraConjunta::Comprobada(_)
        ),
        "PoAS, PoT, padres, cuerpo y sello reales"
    );
}

/// RLJ-3a · con la ventana por `C(B)` el hermano local ya **no** cambia la PMT: el histórico
/// `..._hoy` (que esperaba un rechazo) deja de describir el producto y pasa a exigir determinismo.
#[test]
fn mismo_bloque_y_pasado_veredictos_distintos_hoy() {
    comprobar_mismo_bloque(true);
}

#[test]
fn mismo_bloque_y_pasado_deben_dar_el_mismo_veredicto_control_rojo() {
    comprobar_mismo_bloque(true);
}

fn comprobar_mismo_bloque(exigir_determinismo: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = Nodo::arrancar(&config(dir.path())).expect("nodo dev-reloj");
    nodo.reloj_local_simulado = Some(TS as i64 + 10);
    let terminal = nodo
        .historial_pow
        .first()
        .expect("génesis como ancla fija")
        .block_hash();
    let mut sin_hermano =
        ServicioPot::nuevo_con_reloj(terminal, nodo.perfil_red.reloj.estado_inicial(), 4096)
            .expect("servicio real");
    let clave = nodo.claves.first().expect("clave");
    let parcela = abrir_o_crear_parcela(&nodo.dir_datos, clave, &nodo.historia).expect("parcela");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &nodo.historia,
    };
    let mut oportunidades = Vec::new();
    for slot in 1..=150 {
        sin_hermano.avanzar_hasta(slot).expect("PoT nativo");
        let salida = sin_hermano.salida_de(slot).expect("salida");
        if !fuente
            .soluciones(salida, slot, u64::MAX)
            .expect("auditoría real")
            .is_empty()
        {
            oportunidades.push(slot);
            if oportunidades.len() == 2 {
                break;
            }
        }
    }
    let [slot_hermano, slot_candidato] = oportunidades.as_slice() else {
        panic!("dos oportunidades reales");
    };
    let hermano = bloque_real(&nodo, &mut sin_hermano, *slot_hermano, TS + 1);
    let candidato = bloque_real(&nodo, &mut sin_hermano, *slot_candidato, TS);
    let mut con_hermano = sin_hermano.clone();
    conjunta(&nodo, &con_hermano, &hermano);
    nodo.verificar_reloj_post(&hermano, &con_hermano, terminal)
        .expect("hermano admisible");
    con_hermano
        .registrar_validado_con_timestamp(hermano.cabecera.block_hash(), *slot_hermano, TS + 1)
        .expect("hermano ya verificado");
    assert_eq!(candidato.cabecera.padres.seleccionado(), terminal);
    assert!(candidato.cabecera.padres.extras().is_empty());
    conjunta(&nodo, &sin_hermano, &candidato);
    conjunta(&nodo, &con_hermano, &candidato);
    let sin = nodo.verificar_reloj_post(&candidato, &sin_hermano, terminal);
    let con = nodo.verificar_reloj_post(&candidato, &con_hermano, terminal);
    if exigir_determinismo {
        assert_eq!(sin.is_ok(), con.is_ok(), "mismo bloque y mismo past(B)");
        sin.expect("causal completo");
        return;
    }
    sin.expect("productor admite");
    let e = con.expect_err("receptor rechaza");
    assert!(
        e.to_string()
            .contains("timestamp 1791596104 < PMT 1791596105 (C-RLJ-TS-01)"),
        "{e}"
    );
    assert!(
        error_atribuible_al_candidato(&e),
        "hoy se penaliza por un contexto ajeno al pasado"
    );
    println!(
        "mismo hash={} slot={slot_candidato} ts={} past(B)=[{}]: sin hermano=OK; hermano slot={slot_hermano} ts={}: {e}",
        candidato.cabecera.block_hash(),
        TS,
        terminal,
        TS + 1
    );
}

/// Precondición de PoW por hechos: terminal y garantías fijados. PoST, parcela, firma,
/// admisión, transición de estado y persistencia usan las rutas reales del Nodo.
pub(super) fn nodo_terminal(dir: &Path) -> Nodo {
    use super::pruebas_eclr2::{genesis, hash_u32};
    use zx_consensus::transicion::Garantia;
    let mut nodo = Nodo::arrancar(&config(dir)).expect("nodo real");
    let mut inicial = EstadoTransicion::inicial();
    for i in 0..nodo.params.k_min {
        let clave = ClaveDev::derivar(101, i);
        let mut g = Garantia::nueva();
        g.activo = nodo.params.q;
        inicial.garantias.insert(clave.pk, g);
    }
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        nodo.params,
        perfil::ghostdag_k(),
        nodo.cbid,
        perfil::ghostdag_max_padres(),
        perfil::parametros_evidencia_dev(),
        inicial,
    );
    cadena.admitir(genesis()).expect("génesis del fixture");
    for altura in 1..=nodo.params.h_corte_min {
        cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::PoW {
                    hash: hash_u32(altura),
                    padre: hash_u32(altura - 1),
                    altura,
                    trabajo: nodo.params.w_min / U256::from(nodo.params.h_corte_min),
                    pow_valido: true,
                },
                Vec::new(),
            )))
            .expect("PoW fijado como precondición");
    }
    nodo.cadena = cadena;
    assert!(nodo.cadena.terminal().is_some(), "corte real de Cadena");
    nodo.asegurar_servicios_verificacion()
        .expect("servicio del terminal");
    nodo
}

#[test]
#[ignore = "control rojo: la transición corregida usa el reloj del validador"]
fn transicion_ignora_el_reloj_del_validador_hoy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_terminal(dir.path());
    let reloj = nodo.reloj_local() + 3600;
    nodo.reloj_local_simulado = Some(reloj);
    let terminal = nodo.cadena.terminal().expect("terminal");
    nodo.producir_bloque_transicion(terminal)
        .expect("producción/admisión completas");
    let hash = *nodo
        .cadena
        .tips_validas()
        .first()
        .expect("transición admitida");
    let Some(BloqueCadena::Post(b)) = nodo.cadena.bloque(&hash) else {
        panic!("PoST");
    };
    println!(
        "transición propia slot={} timestamp={} reloj del validador={reloj}",
        b.slot, b.timestamp
    );
    assert!(
        b.timestamp < reloj as u64,
        "hoy captura SystemTime en vez del reloj de validación"
    );
}

#[test]
#[ignore = "inspección manual del almacén público guardado, copiado a la zona"]
fn cabeceras_de_la_corrida_guardada() {
    let raiz = std::env::var("RLJ1_GUARDADA").expect("ruta explícita de las copias");
    let genesis = BlockHash::from_digest(Digest::from_bytes(HASH_GENESIS_DEV));
    for n in ["A", "B", "C", "D"] {
        let db = AlmacenEnDisco::abrir(&PathBuf::from(&raiz).join(n), Red::Dev, genesis)
            .expect("copia local");
        let mut indice = 0;
        let mut post = 0;
        db.repetir(&mut |hash, valor| -> Result<(), std::convert::Infallible> {
            let b = BloqueAdmitido::desde_almacen(valor).expect("canonicos íntegros");
            if b.familia() == Familia::Post {
                let (dag, _) = bloque_dag_desde_bytes(b.canonicos()).expect("cabecera real");
                if post == 0 {
                    let slot = match n {
                        "A" => 2,
                        "C" => 3,
                        _ => 1,
                    };
                    assert_eq!(dag.cabecera.slot, slot, "transición congelada de {n}");
                    assert_eq!(dag.cabecera.timestamp, TS + u64::from(n == "D"));
                }
                if post < 12 {
                    println!(
                        "{n}\tindice={indice}\thash={hash}\tslot={}\tts={}\tpadres={:?}",
                        dag.cabecera.slot,
                        dag.cabecera.timestamp,
                        padres_dag_a_vec(&dag.cabecera.padres)
                    );
                }
                post += 1;
            }
            indice += 1;
            Ok(())
        })
        .expect("registro público");
        assert!(post > 0, "faltan cabeceras PoST congeladas de {n}");
    }
}

#[test]
fn transicion_elige_el_reloj_de_validacion_antes_de_firmar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_terminal(dir.path());
    let reloj = nodo.reloj_local() + 3600;
    nodo.reloj_local_simulado = Some(reloj);
    let terminal = nodo.cadena.terminal().expect("terminal");
    nodo.producir_bloque_transicion(terminal)
        .expect("producción/admisión completas");
    let hash = *nodo
        .cadena
        .tips_validas()
        .first()
        .expect("transición admitida");
    let Some(BloqueCadena::Post(b)) = nodo.cadena.bloque(&hash) else {
        panic!("PoST");
    };
    println!(
        "slot={} timestamp={} reloj={reloj}: admisión completa y persistencia reales",
        b.slot, b.timestamp
    );
    assert_eq!(
        b.timestamp, reloj as u64,
        "hora elegida por el validador antes de firmar"
    );
}

/// RLJ-3a · el selector del productor firma la hora entera si PMT y `FTL` lo permiten; si la hora
/// es menor que la PMT firma la PMT; si la PMT supera `ahora + FTL` se abstiene. La banda ya no
/// recorta (control rojo: reponer el recorte de banda devolvería `TS + 38`).
#[test]
fn timestamp_propio_intersecta_pmt_banda_y_futuro_con_racional_exacto() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = Nodo::arrancar(&config(dir.path())).expect("nodo dev-reloj");
    let ventana: [(u64, i64); 1] = [(1, (TS + 5) as i64)];
    nodo.reloj_local_simulado = Some(TS as i64 - 5);
    assert_eq!(
        nodo.timestamp_para_ventana(&ventana),
        Some(TS + 5),
        "PMT mayor que la hora propia: firma la PMT"
    );
    nodo.reloj_local_simulado = Some(TS as i64 + 100_000);
    assert_eq!(
        nodo.timestamp_para_ventana(&ventana),
        Some(TS + 100_000),
        "hora entera exacta, sin recorte por banda"
    );
    nodo.reloj_local_simulado = Some(TS as i64 - 600);
    assert_eq!(
        nodo.timestamp_para_ventana(&ventana),
        None,
        "PMT por encima de ahora + FTL: abstención"
    );
    nodo.reloj_local_simulado = Some(TS as i64 + 7);
    let vacia: [(u64, i64); 0] = [];
    assert_eq!(
        nodo.timestamp_para_ventana(&vacia),
        Some(TS + 7),
        "ventana PMT vacía: bootstrap con la hora local"
    );
    // Repuestas por `ORDEN-RLJ3A2` §2.3: no dependen de la banda.
    nodo.reloj_local_simulado = Some(i64::MAX);
    assert_eq!(
        nodo.timestamp_para_ventana(&vacia),
        Some(i64::MAX as u64),
        "FTL saturado como en el validador, con ventana vacía"
    );
    nodo.reloj_local_simulado = Some(-1);
    assert_eq!(
        nodo.timestamp_para_ventana(&vacia),
        None,
        "marca negativa no representable"
    );
}

/// T4: un ancestro causal ausente deja el veredicto en `Pendiente` (no penaliza y se reintenta),
/// mientras que un defecto con el pasado causal completo (`Legitimo`) sí es atribuible al
/// candidato. La ventana causal no se completa con bloques ajenos ni de forma parcial.
#[test]
fn t4_contexto_causal_incompleto_es_pendiente_y_no_penaliza() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nodo = Nodo::arrancar(&config(dir.path())).expect("nodo dev-reloj");
    let terminal = nodo.historial_pow.first().expect("génesis").block_hash();
    let servicio = ServicioPot::nuevo(terminal, 16, 4096).expect("servicio real");
    let ausente = BlockHash::from_digest(Digest::from_bytes([0xAB; 32]));
    let padres = PadresDag::nuevo(ausente, &[]).expect("padres");
    assert!(
        nodo.ventana_reloj_post(&servicio, &padres).is_err(),
        "un ancestro ausente no produce ventana parcial"
    );
    let con = |clasificacion| ErrorNodo::BloquePropioRechazado {
        hash: ausente,
        motivo: "prueba T4".to_string(),
        clasificacion,
    };
    assert!(
        !error_atribuible_al_candidato(&con(crate::rechazo::ClasificacionRechazo::Pendiente)),
        "contexto incompleto no penaliza"
    );
    assert!(
        error_atribuible_al_candidato(&con(crate::rechazo::ClasificacionRechazo::Legitimo)),
        "pasado causal completo e inválido penaliza"
    );
}
