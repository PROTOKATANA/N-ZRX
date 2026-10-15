//! PD-1f · Q1–Q6 · defensas contra el eclipse con el certificado por peso `0x09`.
//!
//! Viven en un módulo interno de `nodo` para poder usar los campos y funciones privados del
//! producto (`estado_verificacion_peso`, `pasos_peso_pendientes`, `estado_reducido_para_peso`,
//! `inspeccionar_certificados_peso_de_bloque`), y reutilizan los fixtures reales de
//! `super::pruebas_eclr2` (cadena, PoST, txs de sector y clave de voto).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use super::pruebas_eclr2::{
    genesis, hash_u32, params_subsidio, post_con_txs, pow_terminal, productor_firmante,
    tx_alta_sector, tx_clave_voto, tx_coinbase_post,
};
use super::*;
use zx_consensus::transicion::votos::tabla_canonica;
use zx_core::{CBID_RED_DEV, ClaveTablaVoto, OperacionAlmacenamiento};
use zx_votos::peso::CertificadoPeso;
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Tabla};

const SEMILLA: u64 = 0x5a5a;

fn config_pd1f(dir: &std::path::Path, punto_control: Option<std::path::PathBuf>) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: SEMILLA,
        indices_claves: vec![0],
        n_dev: 32,
        sr_dev: u64::MAX,
        perfil_red: crate::perfil::perfil_red_dev(),
        parada_tras_slots: None,
        dejar_de_producir_en_slot: None,
        punto_control,
        sin_voto: false,
        sin_revelacion: false,
    }
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

/// Tabla del contrato en orden canónico (ascendente por bytes de clave) a partir del estado
/// seleccionado de la cadena en `slot`.
pub(super) fn tabla_de(cadena: &Cadena, slot: i64) -> Tabla {
    let estado = cadena.estado_virtual().expect("estado virtual");
    let mut canonica = tabla_canonica(&estado, slot);
    canonica.sort_by_key(|c| c.clave_bls);
    Tabla {
        n: 0,
        claves: canonica.iter().map(clave_contrato).collect(),
    }
}

/// Firma un `0x09` con la clave `sk_bls` (una sola clave, todo el peso = quórum) contra `tabla`.
pub(super) fn cert_peso(
    tabla: &Tabla,
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    _tabla_siguiente: Option<Tabla>,
    sk_bls: &ClaveSecreta,
    pk_bls: &zx_votos::ClavePublica,
) -> (CertificadoPeso, Tx) {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &[0u8; 32]);
    let firma = zx_votos::firmar(sk_bls, DOMINIO_VOTO, &mensaje).expect("firma BLS");
    let pos = tabla
        .claves
        .iter()
        .position(|c| c.clave.as_slice() == pk_bls.bytes().as_slice())
        .expect("clave en la tabla");
    let cert = zx_votos::construir_certificado(
        n,
        candidato,
        h_t_siguiente,
        [0u8; 32],
        tabla,
        &[(pos + 1, firma)],
    )
    .expect("certificado");
    let (productor, productor_sk) = productor_firmante();
    let (tx, _tst) =
        crate::votos::tx_certificado_peso(&cert, productor, &productor_sk, CBID_RED_DEV);
    (cert, tx)
}

/// Reconstruye la tx `0x09` (con su testigo Ed25519) de un certificado ya construido.
fn tx_de_cert(cert: &CertificadoPeso) -> (Tx, Vec<Vec<u8>>) {
    let (productor, productor_sk) = productor_firmante();
    crate::votos::tx_certificado_peso(cert, productor, &productor_sk, CBID_RED_DEV)
}

/// Cadena real con dos terminales: A (trabajo 1, con un bloque candidato) y B (trabajo 5,
/// seleccionado, con clave de voto y sector reales). `F = 5`; el sufijo de B supera `F`.
pub(super) fn cadena_fork_peso() -> Cadena {
    let (productor, productor_sk) = productor_firmante();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).expect("clave BLS del nodo");
    let pk_bls = sk_bls.clave_publica();
    let mut cadena = Cadena::nueva(params_subsidio(Some(5)), 1, CBID_RED_DEV, 15);
    cadena.admitir(genesis()).expect("génesis");
    // Terminal A: PoW con trabajo 1 y un bloque candidato.
    cadena.admitir(pow_terminal(1, 1)).expect("pow A");
    cadena
        .admitir(post_con_txs(
            10,
            vec![hash_u32(1)],
            1,
            10,
            productor,
            Vec::new(),
        ))
        .expect("bloque A");
    // Terminal B: PoW con más trabajo (seleccionado) y cadena con clave de voto y sector.
    cadena.admitir(pow_terminal(2, 5)).expect("pow B");
    cadena
        .admitir(post_con_txs(
            20,
            vec![hash_u32(2)],
            10,
            10,
            productor,
            vec![(tx_coinbase_post(productor, 10_000, 10), Vec::new())],
        ))
        .expect("coinbase B");
    let (tx_alta, tst_alta) = tx_alta_sector(productor, &productor_sk, CBID_RED_DEV);
    let (tx_cv, tst_cv) = tx_clave_voto(productor, &productor_sk, &pk_bls, &sk_bls, CBID_RED_DEV);
    cadena
        .admitir(post_con_txs(
            21,
            vec![hash_u32(20)],
            11,
            10,
            productor,
            vec![(tx_alta, tst_alta), (tx_cv, tst_cv)],
        ))
        .expect("alta y clave");
    let mut padre = hash_u32(21);
    for id in 22..=34u32 {
        cadena
            .admitir(post_con_txs(
                id,
                vec![padre],
                u64::from(id),
                10,
                productor,
                Vec::new(),
            ))
            .expect("extensión B");
        padre = hash_u32(id);
    }
    assert_eq!(
        cadena.terminal(),
        Some(hash_u32(2)),
        "la rama B (terminal PoW 2) manda"
    );
    cadena
}

fn nodo_con_cadena(cfg: &Config, cadena: Cadena) -> Nodo {
    let mut nodo = Nodo::arrancar(cfg).expect("arranque");
    nodo.cadena = cadena;
    nodo
}

/// Q1 · un `0x09` válido que sella un candidato de la rama en conflicto más allá de `F` dispara el
/// eclipse por el mismo camino que un `0x04` verificado y deja la selección quieta; D4 lo avisa.
#[test]
fn q1_0x09_en_bloque_rechazado_marca_eclipse() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_pd1f(dir.path(), None);
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    let candidato = *hash_u32(10).as_bytes();
    let h_t = zx_votos::hash_tabla(&t0);
    let (_cert, tx) = cert_peso(&t0, 0, candidato, h_t, None, &sk_bls, &pk_bls);

    let mut nodo = nodo_con_cadena(&cfg, cadena);
    assert!(nodo.motor_votos.is_some(), "motor por peso");
    let terminal_antes = nodo.cadena.terminal();
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx], 30);

    assert!(
        nodo.cadena.eclipse().is_some(),
        "F2 debe disparar el eclipse (candidato en otra rama y sufijo ≥ F)"
    );
    assert_eq!(
        nodo.cadena.terminal(),
        terminal_antes,
        "la parada no cambia la selección"
    );
    nodo.atender_modo_detenido().unwrap();
    let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    assert!(
        registro.contains("\"tipo\":\"eclipse_detectado\""),
        "D4 avisa del eclipse: {registro}"
    );
}

/// Q2 · un `0x09` válido cuyo candidato el nodo no conoce deja el ancla pendiente y avisa una vez.
#[test]
fn q2_0x09_candidato_desconocido_deja_ancla_pendiente() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_pd1f(dir.path(), None);
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    let candidato = *hash_u32(9_999).as_bytes();
    let h_t = zx_votos::hash_tabla(&t0);
    let (_cert, tx) = cert_peso(&t0, 0, candidato, h_t, None, &sk_bls, &pk_bls);

    let mut nodo = nodo_con_cadena(&cfg, cadena);
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx], 30);

    assert!(nodo.cadena.ancla_pendiente(), "ancla pendiente");
    assert!(nodo.ancla_pendiente_emitida, "se emite una vez");
    assert!(nodo.cadena.eclipse().is_none(), "sin eclipse");
    let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    assert_eq!(
        registro.matches("\"tipo\":\"ancla_pendiente\"").count(),
        1,
        "un solo `ancla_pendiente`: {registro}"
    );
    // Una segunda vuelta no repite el evento.
    nodo.avisar_ancla_pendiente();
    let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    assert_eq!(
        registro.matches("\"tipo\":\"ancla_pendiente\"").count(),
        1,
        "el aviso no se repite"
    );
}

/// Q3 · firma falsa, tabla no comprometida y ventana no posterior no cambian nada (ancla, estado de
/// verificación ni depósito).
#[test]
fn q3_certificados_invalidos_no_cambian_nada() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_pd1f(dir.path(), None);
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    let h_t = zx_votos::hash_tabla(&t0);
    let candidato = *hash_u32(10).as_bytes();

    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let base_antes = (
        nodo.cadena.ancla_votos(),
        nodo.estado_verificacion_peso
            .as_ref()
            .map(|e| e.finalidad_votos_n),
    );
    assert_eq!(base_antes.0, None);
    assert_eq!(nodo.pasos_peso_pendientes.len(), 0);

    // (a) firma falsa: el certificado lo firma una clave BLS que no está en la tabla.
    let sk_otra = crate::votos::clave_voto_dev(SEMILLA, 7).unwrap();
    let mensaje = zx_votos::mensaje_voto_peso(0, &candidato, &h_t, &[0u8; 32]);
    let firma_otra = zx_votos::firmar(&sk_otra, DOMINIO_VOTO, &mensaje).unwrap();
    let cert_falsa =
        zx_votos::construir_certificado(0, candidato, h_t, [0u8; 32], &t0, &[(1, firma_otra)])
            .unwrap();
    let (tx_firma, _tst) = tx_de_cert(&cert_falsa);
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx_firma], 30);

    // (b) tabla no comprometida: `tabla_siguiente` que no casa con `h_t_siguiente` (se cambia un
    // campo que `serial_tabla` sí incluye).
    let mut claves_malas = t0.claves.clone();
    claves_malas[0].prueba = !claves_malas[0].prueba;
    let otra = Tabla {
        n: 1,
        claves: claves_malas,
    };
    let (_c, tx_tabla) = cert_peso(&t0, 0, candidato, h_t, Some(otra), &sk_bls, &pk_bls);
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx_tabla], 30);

    // (c) ventana no posterior: una vez aplicado el génesis, un `0x09` de la misma ventana con otro
    // candidato es conflicto y se descarta.
    let (_c0, tx0) = cert_peso(&t0, 0, candidato, h_t, None, &sk_bls, &pk_bls);
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx0], 30);
    let n_tras_valido = nodo
        .estado_verificacion_peso
        .as_ref()
        .map(|e| e.finalidad_votos_n);
    let (_c_dup, tx_dup) = cert_peso(
        &t0,
        0,
        *hash_u32(77).as_bytes(),
        h_t,
        None,
        &sk_bls,
        &pk_bls,
    );
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx_dup], 30);
    assert_eq!(
        nodo.estado_verificacion_peso
            .as_ref()
            .map(|e| e.finalidad_votos_n),
        n_tras_valido,
        "la ventana conflictiva no cambia el estado de verificación"
    );

    // (a) y (b) no dejaron depósito; el génesis válido sí fijó el ancla de la cadena.
    assert!(
        nodo.pasos_peso_pendientes.is_empty(),
        "los inválidos se descartan, no se depositan"
    );
    assert_eq!(
        nodo.cadena.ancla_votos(),
        Some((0, hash_u32(10))),
        "la ventana válida fija el ancla"
    );
}

/// Q4 · F3: `C_2` llega antes que `C_1`; se deposita y, al llegar `C_1` (que cambia de tabla), se
/// aplican los dos en orden. El depósito respeta el tope de número.
///
/// RN-1 · S7: para que `C_2` **no** pueda aplicarse directamente (el paso intentado ya no es
/// `base + 1`), `C_2` se firma contra `T_2`, que solo introduce el `tabla_siguiente` de `C_1`: la
/// tabla vigente tras `C_0` es `T_1`, así que `C_2` da `TablaSiguienteAusente` (fuera de orden) y
/// queda retenido hasta que `C_1` avanza la base e introduce `T_2`.
#[test]
fn q4_fuera_de_orden_se_completa_y_deposito_acotado() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_pd1f(dir.path(), None);
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    // T1 cambia de tabla (`prueba`), que `serial_tabla` sí incluye; el peso no cambia.
    let mut claves_t1 = t0.claves.clone();
    claves_t1[0].prueba = !claves_t1[0].prueba;
    let t1 = Tabla {
        n: 1,
        claves: claves_t1,
    };
    // T2 cambia el `peso` de la única clave (también en `serial_tabla`), para que su hash difiera.
    let mut claves_t2 = t0.claves.clone();
    claves_t2[0].peso = claves_t2[0].peso.saturating_add(1);
    let t2 = Tabla {
        n: 2,
        claves: claves_t2,
    };
    let h_t0 = zx_votos::hash_tabla(&t0);
    let h_t1 = zx_votos::hash_tabla(&t1);
    let h_t2 = zx_votos::hash_tabla(&t2);
    assert_ne!(h_t0, h_t1, "T1 debe cambiar de hash");
    assert_ne!(h_t1, h_t2, "T2 debe cambiar de hash");

    let candidato = *hash_u32(10).as_bytes();
    let c1 = *hash_u32(11).as_bytes();
    let c2 = *hash_u32(12).as_bytes();
    // TB-1c · T3: la única tabla derivable del estado verificado es T0. C_0 la declara.
    let (_cert0, tx0) = cert_peso(&t0, 0, candidato, h_t0, None, &sk_bls, &pk_bls);
    // C_1: firmado contra T0 (la vigente) y sin cambio de tabla.
    let (_cert1, tx1) = cert_peso(&t1, 1, c1, h_t0, None, &sk_bls, &pk_bls);
    // C_2: declara T2, que el estado **no** derivó: T3 lo deja depositado.
    let (_cert2, tx2) = cert_peso(&t2, 2, c2, h_t2, None, &sk_bls, &pk_bls);

    let mut nodo = nodo_con_cadena(&cfg, cadena);
    // Primero C_0 (base) y luego C_2, que no encadena: queda depositado.
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx0], 30);
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx2], 30);
    assert_eq!(
        nodo.estado_verificacion_peso
            .as_ref()
            .map(|e| e.finalidad_votos_n),
        Some(0),
        "C_2 no aplica sin C_1"
    );
    assert!(nodo.pasos_peso_pendientes.contains_key(&2));

    // Llega C_1: avanza la base a 1; C_2 sigue depositado (su huella no se deriva).
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx1], 30);
    assert_eq!(
        nodo.estado_verificacion_peso
            .as_ref()
            .map(|e| e.finalidad_votos_n),
        Some(1),
        "C_1 avanza la base; C_2 no encuentra su huella derivada"
    );
    assert!(nodo.pasos_peso_pendientes.contains_key(&2));
    assert_eq!(nodo.cadena.ancla_votos(), Some((1, hash_u32(11))));

    // Tope de número del depósito: muchas ventanas futuras no lo desbordan.
    for n in 100u64..300u64 {
        let tabla_n = Tabla {
            n,
            claves: t0.claves.clone(),
        };
        let (_c, tx) = cert_peso(
            &tabla_n,
            n,
            *hash_u32(11).as_bytes(),
            zx_votos::hash_tabla(&tabla_n),
            None,
            &sk_bls,
            &pk_bls,
        );
        nodo.pasos_peso_pendientes.insert(n, tx);
    }
    nodo.acotar_pasos_peso_pendientes();
    assert!(nodo.pasos_peso_pendientes.len() <= super::MAX_PASOS_ANCLA_PENDIENTES);
}

/// Q5 · punto de control por peso: válido siembra motor y ancla; manipulado se rechaza; anterior
/// (demasiado antiguo) se observa con el mismo motivo que el camino `ZXPC1`.
#[test]
fn q5_punto_control_por_peso() {
    let dir = tempfile::tempdir().unwrap();
    let _cfg = config_pd1f(dir.path(), None);
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    let h_t = zx_votos::hash_tabla(&t0);
    let candidato = *hash_u32(10).as_bytes();
    let (cert, _tx) = cert_peso(&t0, 0, candidato, h_t, None, &sk_bls, &pk_bls);
    let bytes = crate::votos::serializar_punto_control_peso(&t0, &cert, &[], &[]);
    let ruta = dir.path().join("punto-control.zxp");
    std::fs::write(&ruta, &bytes).unwrap();

    // (a) válido: motor sembrado y ancla fijada.
    let cfg_pc = config_pd1f(dir.path(), Some(ruta.clone()));
    let nodo = Nodo::arrancar(&cfg_pc).expect("arranca con ZXPCP1");
    assert_eq!(nodo.cadena.ancla_votos(), Some((0, hash_u32(10))));
    let motor = nodo.motor_votos.as_ref().expect("motor");
    assert_eq!(motor.base_n(), Some(0), "base del motor sembrada");
    assert!(
        motor.ultimo_certificado_peso().is_some(),
        "certificado cargado"
    );
    assert!(motor.punto().is_some(), "punto fijado");

    // (b) manipulado: un byte cambiado no verifica.
    let ruta_mal = dir.path().join("punto-control-mal.zxp");
    let mut malos = bytes.clone();
    let ultimo = malos.len() - 1;
    malos[ultimo] ^= 0x01;
    std::fs::write(&ruta_mal, &malos).unwrap();
    let cfg_mal = config_pd1f(dir.path(), Some(ruta_mal));
    assert!(
        Nodo::arrancar(&cfg_mal).is_err(),
        "un punto de control manipulado se rechaza"
    );

    // (c) anterior (demasiado antiguo): con un local sellado en `n = 5`, el externo de `n = 0` se
    // observa con `punto_control_anterior_incompatible`.
    let dir2 = tempfile::tempdir().unwrap();
    let mut cfg_local = config_pd1f(dir2.path(), None);
    // Cadena con finalidad por peso sellada en `n = 5`: génesis `0x09` de ventana 5 aplicado en un
    // bloque real de la rama B.
    let mut cadena_local = cadena_fork_peso();
    let (_cert5, _tx5) = cert_peso(&t0, 5, candidato, h_t, None, &sk_bls, &pk_bls);
    let (tx5, tst5) = tx_de_cert(&_cert5);
    let (productor, _sk) = productor_firmante();
    cadena_local
        .admitir(post_con_txs(
            35,
            vec![hash_u32(34)],
            35,
            10,
            productor,
            vec![(tx5, tst5)],
        ))
        .expect("bloque con 0x09 n=5");
    assert_eq!(
        cadena_local
            .estado_virtual()
            .expect("estado")
            .finalidad_votos_n,
        5,
        "finalidad local en n = 5"
    );
    let mut nodo_obs = Nodo::arrancar(&config_pd1f(dir2.path(), None)).expect("arranque");
    nodo_obs.cadena = cadena_local;
    nodo_obs.motor_votos = None;
    cfg_local.punto_control = Some(ruta);
    nodo_obs
        .iniciar_votos(&cfg_local)
        .expect("iniciar con externo antiguo");
    let registro = std::fs::read_to_string(dir2.path().join("registro.jsonl")).unwrap();
    assert!(
        registro.contains("punto_control_anterior_incompatible"),
        "externo anterior se observa: {registro}"
    );
}

/// Q6 · F1: el estado de verificación da el mismo veredicto que el estado completo.
#[test]
fn q6_estado_reducido_mismo_veredicto() {
    let dir = tempfile::tempdir().unwrap();
    let _cfg = config_pd1f(dir.path(), None);
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    let h_t = zx_votos::hash_tabla(&t0);
    let candidato = *hash_u32(10).as_bytes();
    let (cert, _tx) = cert_peso(&t0, 0, candidato, h_t, None, &sk_bls, &pk_bls);
    let op = OperacionAlmacenamiento::CertificadoPeso {
        clave: zx_core::ClavePublica::desde_bytes([0x5a; 32]),
        bytes: zx_votos::peso::serial_certificado_peso(&cert),
    };
    let completo = cadena.estado_virtual().expect("estado");
    let reducido = Nodo::estado_reducido_para_peso(&completo);
    let (_e1, _u1, r1) =
        zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo(&completo, &op, 30);
    let (_e2, _u2, r2) =
        zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo(&reducido, &op, 30);
    assert_eq!(
        r1.is_ok(),
        r2.is_ok(),
        "mismo veredicto completo/reducido: {r1:?} vs {r2:?}"
    );
    assert!(r1.is_ok(), "el certificado válido aplica");
}

/// C7/N3 · el evento `certificado_tabla_no_derivada` se emite con la ventana y la huella cuando un
/// `0x09` de un bloque se rechaza por T3.
#[test]
fn evento_certificado_tabla_no_derivada_se_emite() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_pd1f(dir.path(), None);
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    let h_t0 = zx_votos::hash_tabla(&t0);
    // Una tabla que el estado **no** deriva.
    let mut claves = t0.claves.clone();
    claves[0].peso = claves[0].peso.saturating_add(1);
    let t_x = Tabla { n: 2, claves };
    let h_x = zx_votos::hash_tabla(&t_x);
    let candidato = *hash_u32(10).as_bytes();
    let (_c0, tx0) = cert_peso(&t0, 0, candidato, h_t0, None, &sk_bls, &pk_bls);
    let (_c2, tx2) = cert_peso(
        &t_x,
        2,
        *hash_u32(12).as_bytes(),
        h_x,
        None,
        &sk_bls,
        &pk_bls,
    );
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx0], 30);
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx2], 30);
    assert!(
        nodo.pasos_peso_pendientes.contains_key(&2),
        "C_2 queda depositado por T3"
    );
    let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    assert!(
        registro.contains("\"tipo\":\"certificado_tabla_no_derivada\""),
        "evento N3: {registro}"
    );
    assert!(
        registro.contains(&crate::votos::hex(&h_x)),
        "el evento lleva la huella: {registro}"
    );
}
