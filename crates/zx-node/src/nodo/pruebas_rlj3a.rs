//! RLJ-3a-2 · pruebas por el **camino real** del nodo (bloques con PoAS, PoT, segundo VDF y firma
//! reales): A4r, A5r y A6r. Cada prueba comprueba que el bloque llegó a la puerta del reloj.
//!
//! Utiliza el utillaje de [`super::pruebas_rlj1`] (`config`, `bloque_real`, `bloque_real_con_padres`,
//! `nodo_terminal`) tal como pide `ORDEN-RLJ3A2` §3.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::wildcard_imports,
    reason = "fixtures internas que fallan por panic"
)]

use super::pruebas_rlj1::{bloque_real, bloque_real_con_padres, nodo_terminal};
use super::*;

/// Marca base de las pruebas (la misma que usó RLJ-1).
const TS: u64 = 1_791_596_104;

fn texto_registro(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("registro.jsonl")).expect("registro jsonl real")
}

fn marca_de(nodo: &Nodo, hash: BlockHash) -> (u64, i64) {
    match nodo.cadena.bloque(&hash) {
        Some(BloqueCadena::Post(p)) => (p.slot, i64::try_from(p.timestamp).expect("marca en i64")),
        _ => panic!("bloque PoST esperado"),
    }
}

/// Primer slot con solución PoAS a partir de `desde` (misma auditoría real que usa `bloque_real`).
fn siguiente_slot_con_oportunidad(nodo: &Nodo, servicio: &mut ServicioPot, desde: u64) -> u64 {
    let clave = nodo.claves.first().expect("clave propia").clone();
    let parcela =
        abrir_o_crear_parcela(&nodo.dir_datos, &clave, &nodo.historia).expect("parcela real");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &nodo.historia,
    };
    for slot in desde..=(desde + 149) {
        servicio.avanzar_hasta(slot).expect("PoT nativo");
        let salida = servicio.salida_de(slot).expect("salida PoT");
        if !fuente
            .soluciones(salida, slot, u64::MAX)
            .expect("auditoría real")
            .is_empty()
        {
            return slot;
        }
    }
    panic!("sin solución PoAS en 150 slots desde {desde}");
}

fn es_rechazo_permanente(error: &ErrorNodo) -> bool {
    matches!(
        error,
        ErrorNodo::BloquePropioRechazado {
            clasificacion: crate::rechazo::ClasificacionRechazo::Legitimo,
            ..
        }
    )
}

/// A4r · por el camino real (`admitir_post_interno`): marca fuera de banda con PMT y `FTL`
/// correctos → admitida y con el evento `reloj_banda_diagnostico`; marca bajo la PMT → inválido
/// permanente; segundo VDF alterado con marca correcta → inválido; marca mayor que `i64::MAX` →
/// inválido permanente.
#[test]
fn a4r_admision_real_diagnostico_y_vetos() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_terminal(dir.path());
    let terminal = nodo.cadena.terminal().expect("terminal real");

    // T1: bloque de transición real (ventana vacía: sin diagnóstico). Firma la hora del reloj.
    nodo.reloj_local_simulado = Some(TS as i64);
    nodo.producir_bloque_transicion(terminal)
        .expect("T1 de transición real");
    let t1 = *nodo.cadena.tips_validas().first().expect("T1 admitida");
    let (slot1, mark1) = marca_de(&nodo, t1);

    let mut servicio = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio del terminal");
    let slot2 = siguiente_slot_con_oportunidad(&nodo, &mut servicio, slot1 + 1);
    let padres2 = PadresDag::nuevo(t1, &[]).expect("padres T2");
    // τ = 1/1 en el perfil dev. Centro fuera de banda: +10 000 s respecto de t0 + (slot2−slot1)·τ.
    let centro = mark1 + i64::try_from(slot2 - slot1).expect("delta de slot");
    let ts2 = centro + 10_000;
    nodo.reloj_local_simulado = Some(ts2);
    let t2 = bloque_real_con_padres(
        &nodo,
        &mut servicio,
        padres2,
        slot2,
        u64::try_from(ts2).expect("ts2"),
    );
    let h2 = t2.cabecera.block_hash();
    nodo.admitir_post_interno(t2.clone(), 0, true)
        .expect("T2 fuera de banda se admite y deja diagnóstico");
    let log = texto_registro(dir.path());
    let linea = log
        .lines()
        .find(|l| l.contains("reloj_banda_diagnostico"))
        .unwrap_or("");
    assert!(!linea.is_empty(), "falta el evento de diagnóstico:\n{log}");
    assert!(
        linea.contains("\"delta_s\":10000"),
        "delta_s del evento: {linea}"
    );
    assert!(linea.contains(&format!("\"banda_s\":{}", zx_consensus::BANDA_SLOT_DEV)));

    // Marca bajo la PMT (PMT = mediana de [mark1, ts2] = ts2): inválido permanente.
    let mut servicio3 = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio");
    let slot3 = siguiente_slot_con_oportunidad(&nodo, &mut servicio3, slot2 + 1);
    let padres3 = PadresDag::nuevo(h2, &[]).expect("padres T3");
    let ts3 = mark1 - 1_000;
    nodo.reloj_local_simulado = Some(mark1);
    let t3 = bloque_real_con_padres(
        &nodo,
        &mut servicio3,
        padres3,
        slot3,
        u64::try_from(ts3).expect("ts3"),
    );
    let error = nodo
        .admitir_post_interno(t3, 0, true)
        .expect_err("marca bajo la PMT debe ser inválida permanente");
    assert!(
        es_rechazo_permanente(&error),
        "se esperaba rechazo permanente: {error:?}"
    );
    assert!(error.to_string().contains("PMT"), "{error}");

    // Segundo VDF alterado (marca correcta): inválido. Se re-firma tras alterar `vdf_output` para
    // que el veto sea del segundo VDF y no del sello.
    let mut servicio4 = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio");
    let slot4 = siguiente_slot_con_oportunidad(&nodo, &mut servicio4, slot3 + 1);
    let padres4 = PadresDag::nuevo(h2, &[]).expect("padres T4");
    nodo.reloj_local_simulado = Some(ts2);
    let mut t4 = bloque_real_con_padres(
        &nodo,
        &mut servicio4,
        padres4,
        slot4,
        u64::try_from(ts2).expect("ts4"),
    );
    t4.cabecera.vdf_output[0] ^= 0xFF;
    {
        let sk = &nodo.claves.first().expect("clave").sk;
        t4.cabecera.sello = sk.sign(t4.cabecera.pre_hash().as_bytes()).into();
    }
    let error = nodo
        .admitir_post_interno(t4, 0, true)
        .expect_err("segundo VDF alterado debe ser inválido");
    assert!(
        es_rechazo_permanente(&error),
        "se esperaba rechazo permanente: {error:?}"
    );
    assert!(error.to_string().contains("VDF"), "{error}");

    // Marca mayor que `i64::MAX`: inválido permanente (`ORDEN-RLJ3A2` §2.2).
    let mut servicio5 = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio");
    let slot5 = siguiente_slot_con_oportunidad(&nodo, &mut servicio5, slot4 + 1);
    let padres5 = PadresDag::nuevo(h2, &[]).expect("padres T5");
    let t5 = bloque_real_con_padres(&nodo, &mut servicio5, padres5, slot5, u64::MAX);
    let error = nodo
        .admitir_post_interno(t5, 0, true)
        .expect_err("marca > i64::MAX debe ser inválida permanente");
    assert!(
        es_rechazo_permanente(&error),
        "se esperaba rechazo permanente: {error:?}"
    );
    assert!(error.to_string().contains("i64"), "{error}");
}

/// A5r · por el camino real: a un bloque solo le falla `FTL` (reloj simulado atrasado) → `Pendiente`
/// sin penalizar y sin quedar guardado como inválido; al adelantar el reloj se admite.
#[test]
fn a5r_solo_ftl_es_pendiente_y_se_admite_al_adelantar_el_reloj() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_terminal(dir.path());
    let terminal = nodo.cadena.terminal().expect("terminal real");

    let mut servicio = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio");
    let slot = siguiente_slot_con_oportunidad(&nodo, &mut servicio, 1);
    let bloque = bloque_real(&nodo, &mut servicio, slot, TS);
    // Reloj muy atrasado: timestamp > reloj + FTL.
    nodo.reloj_local_simulado = Some(TS as i64 - 100_000);
    let error = nodo
        .admitir_post_interno(bloque.clone(), 0, true)
        .expect_err("FTL debe retener");
    assert!(
        matches!(
            &error,
            ErrorNodo::BloquePropioRechazado {
                clasificacion: crate::rechazo::ClasificacionRechazo::Pendiente,
                ..
            }
        ),
        "se esperaba Pendiente: {error:?}"
    );
    assert!(error.to_string().contains("FTL"), "{error}");

    // No quedó guardado como inválido: basta adelantar el reloj y volver a presentarlo.
    nodo.reloj_local_simulado = Some(TS as i64);
    nodo.admitir_post_interno(bloque, 0, true)
        .expect("el mismo bloque se admite al adelantar el reloj");
}

/// A6r · productor real hasta el firmante: la cabecera lleva la hora entera exacta (±100 000 s del
/// centro, sin banda); con la hora menor que la PMT firma la PMT; con la PMT mayor que `ahora + FTL`
/// el selector se abstiene antes de sellar.
#[test]
fn a6r_productor_real_firma_hora_entera_pmt_y_abstencion() {
    // (a) transición con el reloj 100 000 s por delante del centro: firma su hora entera.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = nodo_terminal(dir.path());
        let terminal = nodo.cadena.terminal().expect("terminal");
        let centro = TS as i64 + 50;
        nodo.reloj_local_simulado = Some(centro + 100_000);
        nodo.producir_bloque_transicion(terminal)
            .expect("transición real +100000");
        let t = *nodo.cadena.tips_validas().first().expect("bloque firmado");
        let (_, ts) = marca_de(&nodo, t);
        assert_eq!(ts, centro + 100_000, "hora entera exacta (+100000)");
    }
    // (b) transición con el reloj 100 000 s por detrás del centro: firma su hora entera.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = nodo_terminal(dir.path());
        let terminal = nodo.cadena.terminal().expect("terminal");
        let centro = TS as i64 + 50;
        nodo.reloj_local_simulado = Some(centro - 100_000);
        nodo.producir_bloque_transicion(terminal)
            .expect("transición real -100000");
        let t = *nodo.cadena.tips_validas().first().expect("bloque firmado");
        let (_, ts) = marca_de(&nodo, t);
        assert_eq!(ts, centro - 100_000, "hora entera exacta (-100000)");
    }
    // (c) y (d): segundo bloque real; la PMT es la marca de T1.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_terminal(dir.path());
    let terminal = nodo.cadena.terminal().expect("terminal");
    nodo.reloj_local_simulado = Some(TS as i64);
    nodo.producir_bloque_transicion(terminal).expect("T1 real");
    let t1 = *nodo.cadena.tips_validas().first().expect("T1");
    let (slot1, mark1) = marca_de(&nodo, t1);
    let mut servicio = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio");
    let slot2 = siguiente_slot_con_oportunidad(&nodo, &mut servicio, slot1 + 1);
    let padres = PadresDag::nuevo(t1, &[]).expect("padres del segundo bloque");

    // (c) hora menor que la PMT: firma la PMT.
    nodo.reloj_local_simulado = Some(mark1 - 100);
    let ts_pmt = nodo
        .timestamp_propio_post(&servicio, &padres)
        .expect("PMT como suelo");
    assert_eq!(
        ts_pmt,
        u64::try_from(mark1).expect("mark1"),
        "firma la PMT cuando la hora es menor"
    );
    let bloque = bloque_real_con_padres(&nodo, &mut servicio, padres, slot2, ts_pmt);
    assert_eq!(
        bloque.cabecera.timestamp,
        u64::try_from(mark1).expect("mark1"),
        "cabecera firmada = PMT"
    );

    // (d) PMT mayor que ahora + FTL: se abstiene antes de sellar (no hay firma).
    nodo.reloj_local_simulado = Some(mark1 - 10_000);
    assert_eq!(
        nodo.timestamp_propio_post(&servicio, &padres),
        None,
        "PMT por encima de ahora + FTL: abstención antes de sellar"
    );
}

/// A1r/A3r · camino real del cableado: un candidato con **dos ramas fusionadas** usa solo la cadena
/// del padre seleccionado; la rama lateral (marca alta) no entra en la ventana ni en la PMT.
///
/// Control rojo A1/A3: volver a la unión de padres (`ventana_timestamps_causal`) o arrancar de la
/// punta local mete la rama lateral y la ventana deja de ser `[T1]`.
#[test]
fn a1r_union_de_ramas_no_entra_en_la_ventana() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_terminal(dir.path());
    let terminal = nodo.cadena.terminal().expect("terminal");

    // T1: transición (padre terminal), marca baja.
    nodo.reloj_local_simulado = Some(TS as i64 + 1);
    nodo.producir_bloque_transicion(terminal)
        .expect("T1 de transición");
    let t1 = *nodo.cadena.tips_validas().first().expect("T1");
    let (slot_t1, mark_t1) = marca_de(&nodo, t1);

    // T2: rama lateral (mismo padre terminal), marca alta, en un slot posterior.
    let mut servicio = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio");
    let slot_t2 = siguiente_slot_con_oportunidad(&nodo, &mut servicio, slot_t1 + 1);
    let ts_t2 = TS as i64 + 100;
    nodo.reloj_local_simulado = Some(ts_t2);
    let t2 = bloque_real(
        &nodo,
        &mut servicio,
        slot_t2,
        u64::try_from(ts_t2).expect("ts"),
    );
    nodo.admitir_post_interno(t2.clone(), 0, true)
        .expect("T2 lateral admitida");
    let h2 = t2.cabecera.block_hash();

    // Candidato fusión: padre seleccionado T1 (+extra T2). La ventana debe ser solo T1.
    let servicio2 = nodo
        .servicios_verificacion
        .get(&terminal)
        .cloned()
        .expect("servicio");
    let padres = PadresDag::nuevo(t1, &[h2]).expect("padres con rama lateral");
    let v = nodo
        .ventana_reloj_post(&servicio2, &padres)
        .expect("ventana completa");
    assert_eq!(
        v.marcas(),
        &[(slot_t1, mark_t1)],
        "solo la cadena del padre seleccionado"
    );
    assert_eq!(
        crate::reloj_marcas::pmt_de_marcas(v.marcas(), 264),
        Some(mark_t1),
        "la rama lateral no entra en la PMT"
    );
}
