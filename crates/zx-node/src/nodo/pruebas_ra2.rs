//! RA-2 · pruebas de nodo en modo peso en el rearranque (T6, T9 y T10).
//!
//! Viven en un módulo interno para poder usar `tabla_peso_para_bloque` y `Nodo::iniciar_votos`,
//! privados del producto.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use super::*;
use zx_consensus::sectores::{
    ClaveVoto, Etapa, NO_HAY, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::{
    T_INST_VOTOS, aplicar_certificado_peso_con_undo, calendario_rearranque,
};
use zx_consensus::transicion::{Estado as EstadoC, Fase, Garantia};
use zx_core::{Amount, ClavePublica as ClaveEdC, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

fn semilla(i: u8) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    ikm[0] = i;
    ikm[31] = 0xA5;
    ikm
}

fn bls(i: u8) -> ClaveSecreta {
    ClaveSecreta::generar(&semilla(i)).expect("clave BLS")
}

fn ed(i: u8) -> ClaveEdC {
    ClaveEdC::desde_bytes([i; 32])
}

fn hashv(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn clave_contrato(c: &ClaveTablaVoto) -> Clave {
    Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    }
}

fn tabla_contrato(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves.iter().map(clave_contrato).collect(),
    }
}

fn hash_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_contrato(0, claves))
}

/// Estado con las claves `indices` registradas (clave BLS determinista) y garantía activa.
fn estado_claves(indices: &[u8]) -> (EstadoC, Vec<(u8, ClaveSecreta)>) {
    let mut est = EstadoC::inicial();
    est.parametros_sector = ParametrosSector::dev();
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for i in indices {
        let s = bls(*i);
        est.claves_voto.insert(
            ed(*i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(1_000_000).expect("garantía");
        est.garantias.insert(ed(*i), g);
        secretas.push((*i, s));
    }
    (est, secretas)
}

fn add_sector(est: &mut EstadoC, i: u8) {
    let q = est.parametros_sector.q_sec;
    let id = SectorId {
        clave: ed(i),
        sector_index: 0,
        version: 0,
    };
    est.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0u64; 4],
            history_size: 1,
            etapa: Etapa::Activo,
            alta_slot: 1,
            renovacion_slot: 1_000,
            retiro_slot: NO_HAY,
            fianza: q,
            aud_apertura: NO_HAY,
            aud_contestada: NO_HAY,
        },
    );
}

fn tabla_con_pesos(est: &EstadoC, pesos: &[(u8, u64)]) -> Vec<ClaveTablaVoto> {
    let mut t: Vec<ClaveTablaVoto> = pesos
        .iter()
        .map(|(i, w)| ClaveTablaVoto {
            clave_bls: est.claves_voto[&ed(*i)].clave_bls,
            peso: *w,
            activo: true,
            prueba: false,
            garantia: *w,
        })
        .collect();
    t.sort_by_key(|a| a.clave_bls);
    t
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> &ClaveSecreta {
    &secretas.iter().find(|(j, _)| *j == i).expect("secreta").1
}

fn config_de_prueba(dir: &std::path::Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 0x5a5a,
        indices_claves: vec![0, 1, 2],
        n_dev: 32,
        sr_dev: u64::MAX,
        perfil_red: crate::perfil::perfil_red_dev(),
        parada_tras_slots: None,
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

/// T6 · R3: en la fase activa `tabla_peso_para_bloque` da la tabla del ciclo; fuera, la de hoy; el
/// `0x09` montado con ella lo acepta el consenso.
#[test]
fn t6_tabla_del_ciclo_en_fase_activa() {
    let (mut est, secretas) = estado_claves(&[1, 2, 3]);
    for i in [1u8, 2, 3] {
        add_sector(&mut est, i);
    }
    let t_base = tabla_con_pesos(&est, &[(1, 1), (2, 1)]);
    let t_ciclo = tabla_con_pesos(&est, &[(1, 1), (2, 1), (3, 1)]);
    let h_base = hash_payload(&t_base);
    let h_ciclo = hash_payload(&t_ciclo);
    assert_ne!(h_base, h_ciclo);
    est.finalidad_votos_n = 2;
    est.finalidad_votos = Some(hashv(9));
    est.finalidad_votos_h_t = Some(h_base);
    est.tablas_voto_contenido.insert(h_base, t_base);
    est.tabla_ciclo_rearranque.insert(0, h_ciclo);
    est.tablas_voto_contenido.insert(h_ciclo, t_ciclo);

    let cal = calendario_rearranque(&est.parametros_sector, 2).expect("calendario");
    let n = cal.inicio(0) / T_INST_VOTOS;
    let slot_fase = cal.inicio(0);
    let (est, _) =
        zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(&est, slot_fase);
    let tabla = super::tabla_peso_para_bloque(&est, slot_fase, n);
    assert_eq!(
        zx_votos::hash_tabla(&tabla),
        h_ciclo,
        "en fase activa, la tabla del ciclo"
    );
    let slot_silencio = cal.inicio(0) + cal.a + 1;
    let fuera = super::tabla_peso_para_bloque(&est, slot_silencio, n);
    assert_eq!(
        zx_votos::hash_tabla(&fuera),
        h_base,
        "fuera de la fase activa, la de hoy"
    );

    // El `0x09` montado con la tabla del ciclo lo acepta el consenso.
    let h_siguiente = est
        .cola_tablas_voto
        .last()
        .expect("tabla fresca del gancho")
        .1;
    let candidato = [0x22u8; 32];
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_siguiente, &[0u8; 32]);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for i in [1u8, 2, 3] {
        let bls_i = est.claves_voto[&ed(i)].clave_bls;
        let pos = tabla
            .claves
            .iter()
            .position(|c| c.clave.as_slice() == bls_i.as_slice())
            .expect("clave en la tabla del ciclo");
        let f = zx_votos::firmar(secreta(&secretas, i), DOMINIO_VOTO, &mensaje).expect("firma");
        votos.push((pos + 1, f));
    }
    let cert =
        zx_votos::construir_certificado(n, candidato, h_siguiente, [0u8; 32], &tabla, &votos)
            .expect("certificado");
    let op = OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    };
    let (_nuevo, _undo, r) =
        aplicar_certificado_peso_con_undo(&est, &op, i64::try_from(slot_fase).unwrap_or(0));
    r.expect("el consenso acepta el 0x09 montado con la tabla del ciclo");
}

/// T9 · R6.1: un bloque sin `0x09` no calcula el estado virtual (contador de pruebas).
#[test]
fn t9a_bloque_sin_09_no_calcula_estado_virtual() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_prueba(dir.path());
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque");
    assert!(nodo.motor_votos.is_some(), "el motor arranca por peso");
    super::ESTADO_VIRTUAL_RECONCILIACION.with(|c| c.set(0));
    nodo.reconciliar_ancla_de_bloque(hashv(200), &[]);
    let n = super::ESTADO_VIRTUAL_RECONCILIACION.with(|c| c.get());
    assert_eq!(n, 0, "un bloque sin 0x09 no calcula estado virtual");
    // Con un `0x09` sí lo calcula.
    let bytes = vec![0u8; 8 + 3 * 32 + 96];
    let tx = Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: OperacionAlmacenamiento::CertificadoPeso {
                clave: ed(1),
                bytes,
            },
        },
    };
    nodo.reconciliar_ancla_de_bloque(hashv(201), &[tx]);
    let n2 = super::ESTADO_VIRTUAL_RECONCILIACION.with(|c| c.get());
    assert_eq!(n2, 1, "un bloque con 0x09 sí calcula el estado virtual");
}

/// T10 · R7 con un `Nodo` real: la cadena ya tiene finalidad por votos (`0x09`). Al reiniciar en modo
/// peso el nodo **no** queda en observación, el ancla de la cadena es `(n, bloque sellado)` y el motor
/// abre y firma la primera ventana posterior a la base con la tabla del estado (R0). **Sin R7 falla**
/// (`finalidad_sin_cuerpo_autentico` y la guarda `bootstrap_sobre_finalidad`).
#[test]
fn t10b_reinicio_con_finalidad_sellada_en_peso() {
    const K_LOCAL: u32 = 1;
    const MAX_PADRES_LOCAL: u8 = 15;
    use super::pruebas_eclr2::{
        genesis, hash_u32, params_subsidio, post_con_txs, pow_terminal, productor_firmante,
        tx_alta_sector, tx_clave_voto, tx_coinbase_post,
    };
    use zx_core::CBID_RED_DEV;

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_prueba(dir.path());

    // (1) Cadena real con un `0x09` aplicado.
    let (productor, productor_sk) = productor_firmante();
    let sk_bls = crate::votos::clave_voto_dev(cfg.semilla, 0).expect("clave BLS del nodo");
    let pk_bls = sk_bls.clave_publica();
    let mut cadena = Cadena::nueva(
        params_subsidio(Some(5)),
        K_LOCAL,
        CBID_RED_DEV,
        MAX_PADRES_LOCAL,
    );
    cadena.admitir(genesis()).expect("génesis");
    cadena.admitir(pow_terminal(1, 1)).expect("pow");
    cadena
        .admitir(post_con_txs(
            10,
            vec![hash_u32(1)],
            10,
            10,
            productor,
            vec![(tx_coinbase_post(productor, 10_000, 10), Vec::new())],
        ))
        .expect("coinbase");
    cadena
        .admitir(post_con_txs(
            11,
            vec![hash_u32(10)],
            11,
            10,
            productor,
            Vec::new(),
        ))
        .expect("extensión");
    let (tx_alta, tst_alta) = tx_alta_sector(productor, &productor_sk, CBID_RED_DEV);
    let (tx_cv, tst_cv) = tx_clave_voto(productor, &productor_sk, &pk_bls, &sk_bls, CBID_RED_DEV);
    cadena
        .admitir(post_con_txs(
            12,
            vec![hash_u32(11)],
            12,
            10,
            productor,
            vec![(tx_alta, tst_alta), (tx_cv, tst_cv)],
        ))
        .expect("alta sector y clave");
    // Maduración del sector (precomprometido → activo) antes del `0x09`.
    let mut padre = hash_u32(12);
    for id in 13..=20u32 {
        cadena
            .admitir(post_con_txs(
                id,
                vec![padre],
                u64::from(id),
                10,
                productor,
                Vec::new(),
            ))
            .expect("extensión");
        padre = hash_u32(id);
    }

    // Tabla canónica y certificado por peso (una clave con todo el peso = quórum).
    let estado = cadena.estado_virtual().expect("estado virtual");
    let canonica = zx_consensus::transicion::votos::tabla_canonica(&estado, 30);
    assert!(!canonica.is_empty(), "la tabla canónica tiene al votante");
    let claves: Vec<Clave> = canonica
        .iter()
        .map(|c| Clave {
            clave: c.clave_bls.to_vec(),
            peso: c.peso,
            activo: c.activo,
            prueba: c.prueba,
            garantia: c.garantia,
        })
        .collect();
    let tabla_peso = Tabla { n: 0, claves };
    let h = zx_votos::hash_tabla(&tabla_peso);
    let candidato = *hash_u32(20).as_bytes();
    let mensaje = zx_votos::mensaje_voto_peso(0, &candidato, &h, &[0u8; 32]);
    let firma = zx_votos::firmar(&sk_bls, DOMINIO_VOTO, &mensaje).expect("firma");
    let pos = tabla_peso
        .claves
        .iter()
        .position(|c| c.clave.as_slice() == pk_bls.bytes().as_slice())
        .expect("clave en la tabla");
    let cert = zx_votos::construir_certificado(
        0,
        candidato,
        h,
        [0u8; 32],
        &tabla_peso,
        &[(pos + 1, firma)],
    )
    .expect("certificado");
    let (tx_cert, tst_cert) =
        crate::votos::tx_certificado_peso(&cert, productor, &productor_sk, CBID_RED_DEV);
    cadena
        .admitir(post_con_txs(
            30,
            vec![hash_u32(20)],
            30,
            10,
            productor,
            vec![(tx_cert, tst_cert)],
        ))
        .expect("bloque con 0x09");
    assert_eq!(
        cadena.estado_virtual().expect("estado").finalidad_votos_n,
        0,
        "la cadena tiene finalidad por votos aplicada"
    );

    // (2) Nodo real: se instala la cadena y se reinicia el motor de votos.
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque");
    nodo.cadena = cadena;
    nodo.motor_votos = None;
    nodo.iniciar_votos(&cfg).expect("reinicio de votos");

    let motor = nodo.motor_votos.as_ref().expect("motor");
    assert!(motor.emite_para_test(), "no queda en observación (R7)");
    assert_eq!(
        nodo.cadena.ancla_votos(),
        Some((0, hash_u32(20))),
        "el ancla de la cadena es (n, bloque sellado)"
    );

    // (3) La primera ventana posterior a la base abre y firma.
    let estado = nodo.cadena.estado_virtual().expect("estado");
    let n = 6u64;
    let paso = nodo
        .motor_votos
        .as_mut()
        .expect("motor")
        .avanzar_con_vista(n, hash_u32(30), &estado, 30, &nodo.cadena)
        .expect("abrir la primera ventana posterior a la base");
    let motor = nodo.motor_votos.as_ref().expect("motor");
    assert_eq!(motor.instancia_actual(), Some(n), "abre la ventana");
    assert!(
        motor.reservada_para_test(&pk_bls.bytes(), n),
        "firma su voto propio"
    );
    assert!(!paso.votos.is_empty(), "emite el sobre de voto");
}

/// T9 · R6.3: tras vencer el plazo de una ventana no queda ninguna entrada suya en
/// `actas_aplicadas`; dentro del plazo se conserva y la consulta no clona el conjunto.
#[test]
fn t9c_poda_de_actas_aplicadas() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_prueba(dir.path());
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque");
    let clave = ClaveEdC::desde_bytes([9u8; 32]);
    nodo.actas_aplicadas.insert((1u64, clave));

    // Vencida: el plazo `cierre(1) + W_REVEAL + LAG` ya pasó con holgura.
    let vencido = super::cierre_ventana(1)
        .saturating_add(super::W_REVEAL_SLOTS_VOTOS)
        .saturating_add(100_000);
    nodo.procesar_v6_pendientes(vencido);
    assert!(
        !nodo.actas_aplicadas.contains(&(1u64, clave)),
        "la entrada vencida se poda"
    );

    // Dentro del plazo: se conserva.
    nodo.actas_aplicadas.insert((1u64, clave));
    nodo.procesar_v6_pendientes(0);
    assert!(
        nodo.actas_aplicadas.contains(&(1u64, clave)),
        "dentro del plazo se conserva"
    );
}

/// T10 · R7 (M9-a2): un punto de control **antiguo** `ZXPC1` dado a `--punto-control` se rechaza al
/// arrancar con un error claro (el nodo ya solo lee `ZXPCP1` de peso). Sustituye a la pregunta vieja
/// «`--punto-control` con el interruptor `--votos-peso` da error», que ya no existe.
#[test]
fn t10a_punto_control_antiguo_se_rechaza() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = config_de_prueba(dir.path());
    let ruta = dir.path().join("antiguo.zxpc1");
    let mut bytes = vec![0u8; 64];
    bytes[..5].copy_from_slice(b"ZXPC1");
    std::fs::write(&ruta, &bytes).expect("escritura");
    cfg.punto_control = Some(ruta);
    let error = match Nodo::arrancar(&cfg) {
        Ok(_) => panic!("un punto de control ZXPC1 antiguo debe rechazarse"),
        Err(e) => e,
    };
    let texto = format!("{error}");
    assert!(
        texto.contains("punto de control"),
        "el error de arranque lo nombra: {texto}"
    );
}
