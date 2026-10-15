//! A1-D2b · la raíz de estado en el nodo (pieza A1, paso (d), segunda mitad).
//!
//! Pruebas `raizn_01`–`raizn_09` (ORDEN-A1D2b §3): la vista que entrega la raíz del punto, el
//! cálculo en segundo plano solo en el nodo que vota, el aviso de «raíz no lista» y los tres
//! eventos de W5 en el registro. El montaje de cadenas pseudoaleatorias con huecos de slot,
//! bifurcación y reorganización reutiliza el de `crate::nodo::pruebas_idx1::idx1_x2`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    reason = "pruebas de la raíz de estado del nodo: fallan con panic por diseño"
)]

use std::cell::Cell;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, Estado, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Red, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;

use super::{Config, LAG_CANDIDATO_VOTOS, Nodo, VistaConRaiz, punto_de_ventana};
use crate::raiz_punto::{RaicesPunto, tope_de_punto};
use crate::votos::{EventoMotor, RAIZ_ESTADO_CERO, VistaCadena};

const MAX_PADRES: u8 = 15;
const K: u32 = 1;
/// `t_inst` del perfil dev (`perfil::parametros_votos_dev`).
const T_INST: u64 = 2;
const LAG: u64 = LAG_CANDIDATO_VOTOS;
/// Primera ventana con época de raíz 1: `⌊384/128⌋ − 2 = 1`, y su punto cae en el slot 252.
const VENTANA: u64 = 384;

/// Error propio de las calculadoras de prueba.
#[derive(Debug)]
struct ErrorFalso;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

fn params(f_slots: Option<u64>) -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 1,
        w_min: U256::one(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 1,
        f_slots,
        subsidio_pow,
        subsidio_post,
    }
}

fn hash_u32(n: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn productor() -> ClavePublica {
    let digest = zx_core::sha3_256_publico(b"zx-raizn-pruebas");
    let sk = ed25519_zebra::SigningKey::from(*digest.as_bytes());
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

fn tx_coinbase_post(clave: ClavePublica, importe: i64, slot: u64) -> Tx {
    Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave,
            importe: Amount::nuevo(importe).unwrap(),
            slot,
        },
    }
}

fn genesis() -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash_u32(0) },
        Vec::new(),
    ))
}

fn pow_terminal(id: u32, trabajo: u64) -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash_u32(id),
            padre: hash_u32(0),
            altura: 1,
            trabajo: U256::from(trabajo),
            pow_valido: true,
        },
        Vec::new(),
    ))
}

fn post(id: u32, padres: Vec<BlockHash>, slot: u64, sr: u64) -> BloqueCadena {
    let productor = productor();
    let tx = tx_coinbase_post(productor, 1, slot);
    let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor,
        0,
        u64::from(id) + 1,
        [(id & 0xff) as u8; 32],
        slot,
    ));
    BloqueCadena::Post(BloquePost {
        hash: hash_u32(id),
        padres,
        slot,
        timestamp: 0,
        productor,
        peso: 1,
        prueba_valida: true,
        requisito_declarado: 0,
        sr,
        distancia: 0,
        identidad,
        txs: vec![(tx, Vec::new())],
    })
}

/// Cadena con huecos de slot, bifurcación y reorganización hacia el terminal 2 (mismo montaje que
/// `pruebas_idx1::idx1_x2`), con `n_punta` bloques PoST en la rama ganadora. Con `n_punta = 300` el
/// punto de la época 1 (slot 252) es un antepasado propio del candidato de la ventana 384.
fn cadena_reorg(n_punta: u32) -> Cadena {
    let mut cadena = Cadena::nueva(params(None), K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    cadena.admitir(pow_terminal(2, 3)).unwrap();
    // Rama del terminal 1 con huecos de slot crecientes.
    let mut p1 = hash_u32(1);
    let mut slot1 = 0u64;
    for i in 0..30u32 {
        slot1 += 1 + u64::from(i % 3);
        let b = post(100 + i, vec![p1], slot1, 10);
        cadena.admitir(b.clone()).unwrap();
        p1 = b.hash();
    }
    // Bifurcación: dos hijos del mismo padre.
    for i in 0..2u32 {
        let b = post(200 + i, vec![p1], slot1 + 1 + u64::from(i), 10);
        cadena.admitir(b.clone()).unwrap();
    }
    // Rama del terminal 2 (más trabajo): reorganiza la selección.
    let mut p2 = hash_u32(2);
    let mut slot2 = 0u64;
    for i in 0..n_punta {
        slot2 += 1;
        let b = post(300 + i, vec![p2], slot2, 1);
        cadena.admitir(b.clone()).unwrap();
        p2 = b.hash();
    }
    cadena
}

fn cadena_con_finalidad(n: u64, s: BlockHash) -> Cadena {
    let mut inicial = Estado::inicial();
    inicial.finalidad_votos_n = n;
    inicial.finalidad_votos = Some(s);
    inicial.finalidad_votos_h_t = Some([0xEE; 32]);
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params(Some(5)),
        K,
        CBID_RED_DEV,
        MAX_PADRES,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        inicial,
    );
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    cadena.admitir(post(11, vec![hash_u32(1)], 1, 1)).unwrap();
    cadena
}

fn tx_certificado_peso_con_raiz(n: u64, candidato: BlockHash, raiz: [u8; 32]) -> Tx {
    let mut bytes = vec![0u8; 200];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    bytes[8..40].copy_from_slice(candidato.as_bytes());
    bytes[72..104].copy_from_slice(&raiz);
    Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: zx_core::OperacionAlmacenamiento::CertificadoPeso {
                clave: ClavePublica::desde_bytes([9u8; 32]),
                bytes,
            },
        },
    }
}

fn config_nodo(dir: &Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 0x5a5a,
        indices_claves: vec![0],
        n_dev: 32,
        sr_dev: u64::MAX,
        perfil_red: crate::perfil::perfil_red_dev(),
        parada_tras_slots: None,
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: true,
        sin_revelacion: true,
    }
}

/// Sondea el almacén hasta que la raíz esté lista o se agote el margen.
fn esperar_raiz(raices: &RaicesPunto, epoca: u64, punto: &BlockHash) -> Option<[u8; 32]> {
    for _ in 0..2_000_000u32 {
        raices.recoger();
        if let Some(raiz) = raices.raiz(epoca, punto) {
            return Some(raiz);
        }
        std::thread::yield_now();
    }
    None
}

/// `BlockHash` del candidato que produce el nodo para la ventana `n` (mismo cálculo que
/// `Nodo::candidato_votos(n·t_inst)`).
fn candidato_de(cadena: &Cadena, n: u64) -> BlockHash {
    cadena
        .candidato_por_slot(n * T_INST - LAG)
        .expect("candidato")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_01 · la vista entrega la raíz del punto (y no la de otra época)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_01_la_vista_entrega_la_raiz_del_punto() {
    let cadena = cadena_reorg(300);
    let n = VENTANA;
    let (epoca, punto) = punto_de_ventana(&cadena, n, T_INST, LAG).expect("punto de la época 1");
    assert_eq!(epoca, 1);
    let tope2 = tope_de_punto(2, T_INST, LAG).expect("tope de la época 2");
    let punto2 = cadena
        .candidato_por_slot(tope2)
        .expect("punto de la época 2");
    assert_ne!(punto, punto2, "las dos épocas tienen puntos distintos");
    let candidato = candidato_de(&cadena, n);
    assert_ne!(
        punto, candidato,
        "el punto es antepasado propio del candidato"
    );

    let raices = RaicesPunto::nuevo(zx_estado::canon::raiz_de_estado);
    raices.solicitar(1, punto, cadena.estado_post(&punto).unwrap().clone());
    raices.solicitar(2, punto2, cadena.estado_post(&punto2).unwrap().clone());
    let raiz1 = esperar_raiz(&raices, 1, &punto).expect("raíz de la época 1");
    let raiz2 = esperar_raiz(&raices, 2, &punto2).expect("raíz de la época 2");
    assert_ne!(raiz1, raiz2, "cada época tiene su raíz");

    let aviso = Cell::new(None);
    let vista = VistaConRaiz {
        cadena: &cadena,
        raices: &raices,
        vota: true,
        t_inst: T_INST,
        lag: LAG,
        aviso: &aviso,
    };
    assert_eq!(
        vista.raiz_estado_de_voto(n, candidato.as_bytes()),
        raiz1,
        "la vista entrega la raíz del punto de la época de la ventana"
    );
    assert_ne!(vista.raiz_estado_de_voto(n, candidato.as_bytes()), raiz2);
    assert!(aviso.get().is_none(), "la raíz estaba lista: no hay aviso");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_02 · cero antes del primer punto
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_02_cero_antes_del_primer_punto() {
    let cadena = cadena_reorg(300);
    let raices = RaicesPunto::nuevo(zx_estado::canon::raiz_de_estado);
    let aviso = Cell::new(None);
    let vista = VistaConRaiz {
        cadena: &cadena,
        raices: &raices,
        vota: true,
        t_inst: T_INST,
        lag: LAG,
        aviso: &aviso,
    };
    let candidato = hash_u32(1);
    // Las dos primeras épocas no tienen época de raíz y la época 0 no tiene tope (`−lag`).
    for n in [0u64, 1, 127, 128, 255, 256] {
        assert_eq!(
            vista.raiz_estado_de_voto(n, candidato.as_bytes()),
            RAIZ_ESTADO_CERO,
            "n={n} no tiene punto todavía"
        );
    }
    assert!(
        aviso.get().is_none(),
        "sin punto no hay aviso de raíz no lista"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_03 · cero si el candidato no desciende del punto
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_03_cero_si_el_candidato_no_desciende_del_punto() {
    let cadena = cadena_reorg(300);
    let n = VENTANA;
    let (epoca, punto) = punto_de_ventana(&cadena, n, T_INST, LAG).unwrap();
    let raices = RaicesPunto::nuevo(zx_estado::canon::raiz_de_estado);
    raices.solicitar(epoca, punto, cadena.estado_post(&punto).unwrap().clone());
    let raiz = esperar_raiz(&raices, epoca, &punto).expect("raíz lista");

    // Un bloque de la rama perdedora (terminal 1) no desciende del punto de la cadena seleccionada.
    let ajeno = hash_u32(200);
    assert!(!cadena.desciende_en_cadena_seleccionada(&ajeno, &punto));
    let aviso = Cell::new(None);
    let vista = VistaConRaiz {
        cadena: &cadena,
        raices: &raices,
        vota: true,
        t_inst: T_INST,
        lag: LAG,
        aviso: &aviso,
    };
    assert_eq!(
        vista.raiz_estado_de_voto(n, ajeno.as_bytes()),
        RAIZ_ESTADO_CERO,
        "sin descendencia, cero aunque la raíz esté lista"
    );
    assert!(aviso.get().is_none(), "no desciende no es «raíz no lista»");
    let bueno = candidato_de(&cadena, n);
    assert_eq!(vista.raiz_estado_de_voto(n, bueno.as_bytes()), raiz);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_04 · mismo candidato, mismo punto
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_04_mismo_candidato_mismo_punto() {
    let a = cadena_reorg(300);
    let b = cadena_reorg(300);
    let n = VENTANA;
    let (ea, pa) = punto_de_ventana(&a, n, T_INST, LAG).unwrap();
    let (eb, pb) = punto_de_ventana(&b, n, T_INST, LAG).unwrap();
    assert_eq!((ea, pa), (eb, pb), "el mismo candidato da el mismo punto");
    let cand = candidato_de(&a, n);
    assert!(
        cand == pa || a.desciende_en_cadena_seleccionada(&cand, &pa),
        "el punto es antepasado del candidato"
    );

    let raices = RaicesPunto::nuevo(zx_estado::canon::raiz_de_estado);
    raices.solicitar(ea, pa, a.estado_post(&pa).unwrap().clone());
    let raiz = esperar_raiz(&raices, ea, &pa).unwrap();
    let aviso_a = Cell::new(None);
    let vista_a = VistaConRaiz {
        cadena: &a,
        raices: &raices,
        vota: true,
        t_inst: T_INST,
        lag: LAG,
        aviso: &aviso_a,
    };
    let aviso_b = Cell::new(None);
    let vista_b = VistaConRaiz {
        cadena: &b,
        raices: &raices,
        vota: true,
        t_inst: T_INST,
        lag: LAG,
        aviso: &aviso_b,
    };
    assert_eq!(vista_a.raiz_estado_de_voto(n, cand.as_bytes()), raiz);
    assert_eq!(vista_b.raiz_estado_de_voto(n, cand.as_bytes()), raiz);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_05 · el nodo que no vota no calcula
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_05_el_nodo_que_no_vota_no_calcula() {
    let dir = tempfile::tempdir().unwrap();
    let mut nodo = Nodo::arrancar(&config_nodo(dir.path())).unwrap();
    nodo.cadena = cadena_reorg(300);
    nodo.vota = false;
    let llamadas = Arc::new(AtomicUsize::new(0));
    let l = Arc::clone(&llamadas);
    nodo.raices = RaicesPunto::nuevo(move |_e: &Estado| {
        l.fetch_add(1, Ordering::SeqCst);
        Ok::<[u8; 32], ErrorFalso>([0x5A; 32])
    });
    nodo.preparar_raices(VENTANA, T_INST);
    assert_eq!(llamadas.load(Ordering::SeqCst), 0, "no vota: no calcula");
    assert!(nodo.raices_solicitadas.is_empty());
    let (epoca, punto) = punto_de_ventana(&nodo.cadena, VENTANA, T_INST, LAG).unwrap();
    assert!(!nodo.raices.pendiente(epoca, &punto));
    assert!(nodo.raices.raiz(epoca, &punto).is_none());
    let candidato = candidato_de(&nodo.cadena, VENTANA);
    let aviso = Cell::new(None);
    let vista = VistaConRaiz {
        cadena: &nodo.cadena,
        raices: &nodo.raices,
        vota: false,
        t_inst: T_INST,
        lag: LAG,
        aviso: &aviso,
    };
    assert_eq!(
        vista.raiz_estado_de_voto(VENTANA, candidato.as_bytes()),
        RAIZ_ESTADO_CERO,
        "la vista del nodo que no vota entrega cero"
    );
    assert!(aviso.get().is_none());
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_06 · raíz no lista: firma cero y avisa (con el cálculo retenido)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_06_raiz_no_lista_firma_cero_y_avisa() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_nodo(dir.path());
    let mut nodo = Nodo::arrancar(&cfg).unwrap();
    nodo.cadena = cadena_reorg(300);
    nodo.vota = true;
    // Calculadora retenida: la raíz no puede quedar lista.
    let cerrojo = Arc::new((Mutex::new(false), Condvar::new()));
    let c = Arc::clone(&cerrojo);
    nodo.raices = RaicesPunto::nuevo(move |_e: &Estado| {
        let (candado, aviso) = &*c;
        let mut listo = candado.lock().unwrap_or_else(|e| e.into_inner());
        while !*listo {
            listo = aviso.wait(listo).unwrap_or_else(|e| e.into_inner());
        }
        Ok::<[u8; 32], ErrorFalso>([0x66; 32])
    });
    nodo.preparar_raices(VENTANA, T_INST);
    let (epoca, punto) = punto_de_ventana(&nodo.cadena, VENTANA, T_INST, LAG).unwrap();
    // El trabajador puede tardar en arrancar; se espera a que el cálculo esté en curso.
    for _ in 0..2_000_000u32 {
        if nodo.raices.pendiente(epoca, &punto) {
            break;
        }
        std::thread::yield_now();
    }
    assert!(nodo.raices.pendiente(epoca, &punto), "cálculo en curso");
    assert!(nodo.raices.raiz(epoca, &punto).is_none());

    let candidato = candidato_de(&nodo.cadena, VENTANA);
    let recogido = Cell::new(None);
    {
        let vista = VistaConRaiz {
            cadena: &nodo.cadena,
            raices: &nodo.raices,
            vota: true,
            t_inst: T_INST,
            lag: LAG,
            aviso: &recogido,
        };
        assert_eq!(
            vista.raiz_estado_de_voto(VENTANA, candidato.as_bytes()),
            RAIZ_ESTADO_CERO
        );
    }
    let (n_av, ep, pt) = recogido.take().expect("la vista recoge el aviso");
    nodo.avisar_raiz_no_lista(n_av, ep, pt);
    nodo.avisar_raiz_no_lista(n_av, ep, pt);
    let contenido = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    let avisos: Vec<&str> = contenido
        .lines()
        .filter(|l| l.contains("\"tipo\":\"raiz_estado_no_lista\""))
        .collect();
    assert_eq!(avisos.len(), 1, "un solo aviso: {contenido}");
    assert!(avisos[0].contains("\"n\":384"), "{}", avisos[0]);

    // Liberar la calculadora retenida para que el almacén pueda unirse al soltarse.
    {
        let (candado, aviso) = &*cerrojo;
        *candado.lock().unwrap_or_else(|e| e.into_inner()) = true;
        aviso.notify_all();
    }
    drop(nodo);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_07 · tras calcular, el voto lleva la raíz del estado del punto
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_07_tras_calcular_el_voto_lleva_la_raiz() {
    let dir = tempfile::tempdir().unwrap();
    let mut nodo = Nodo::arrancar(&config_nodo(dir.path())).unwrap();
    nodo.cadena = cadena_reorg(300);
    nodo.vota = true;
    nodo.raices = RaicesPunto::nuevo(zx_estado::canon::raiz_de_estado);
    // W2 · el cálculo lo solicita el propio nodo, con el estado del **punto**.
    nodo.preparar_raices(VENTANA, T_INST);
    let (epoca, punto) = punto_de_ventana(&nodo.cadena, VENTANA, T_INST, LAG).unwrap();
    let candidato = candidato_de(&nodo.cadena, VENTANA);
    assert_ne!(punto, candidato, "el punto es un antepasado propio");
    let mut esperada = None;
    for _ in 0..2_000_000u32 {
        nodo.raices.recoger();
        if let Some(raiz) = nodo.raices.raiz(epoca, &punto) {
            esperada = Some(raiz);
            break;
        }
        std::thread::yield_now();
    }
    let esperada = esperada.expect("raíz calculada");
    assert_eq!(
        esperada,
        zx_estado::canon::raiz_de_estado(nodo.cadena.estado_post(&punto).unwrap()).unwrap(),
        "la raíz es la de `raiz_de_estado` del estado del punto"
    );
    let del_candidato =
        zx_estado::canon::raiz_de_estado(nodo.cadena.estado_post(&candidato).unwrap()).unwrap();
    assert_ne!(
        esperada, del_candidato,
        "el estado del candidato no es el del punto"
    );
    let aviso = Cell::new(None);
    {
        let vista = VistaConRaiz {
            cadena: &nodo.cadena,
            raices: &nodo.raices,
            vota: true,
            t_inst: T_INST,
            lag: LAG,
            aviso: &aviso,
        };
        assert_eq!(
            vista.raiz_estado_de_voto(VENTANA, candidato.as_bytes()),
            esperada,
            "la vista que alimenta al motor lleva la raíz del punto"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_08 · si el punto cambia, se recalcula
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_08_si_el_punto_cambia_se_recalcula() {
    let dir = tempfile::tempdir().unwrap();
    let mut nodo = Nodo::arrancar(&config_nodo(dir.path())).unwrap();
    nodo.cadena = cadena_reorg(300);
    nodo.vota = true;
    let llamadas = Arc::new(AtomicUsize::new(0));
    let l = Arc::clone(&llamadas);
    nodo.raices = RaicesPunto::nuevo(move |_e: &Estado| {
        l.fetch_add(1, Ordering::SeqCst);
        Ok::<[u8; 32], ErrorFalso>([0x77; 32])
    });
    nodo.preparar_raices(VENTANA, T_INST);
    let (epoca, punto1) = punto_de_ventana(&nodo.cadena, VENTANA, T_INST, LAG).unwrap();
    assert!(nodo.raices.pendiente(epoca, &punto1) || nodo.raices.raiz(epoca, &punto1).is_some());

    // Reorganización: la punta seleccionada cambia y con ella el punto de la época.
    nodo.cadena = cadena_reorg(200);
    let (_, punto2) = punto_de_ventana(&nodo.cadena, VENTANA, T_INST, LAG).unwrap();
    assert_ne!(punto1, punto2, "el punto cambió");
    nodo.preparar_raices(VENTANA, T_INST);
    assert!(
        nodo.raices.pendiente(epoca, &punto2) || nodo.raices.raiz(epoca, &punto2).is_some(),
        "se recalcula para el punto nuevo"
    );
    assert!(
        nodo.raices.raiz(epoca, &punto1).is_none(),
        "la raíz del punto viejo se descarta"
    );
    assert!(
        llamadas.load(Ordering::SeqCst) >= 2,
        "hubo al menos dos solicitudes"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// raizn_09 · el registro lleva la raíz (los tres eventos de W5)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn raizn_09_el_registro_lleva_la_raiz() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_nodo(dir.path());
    let mut nodo = Nodo::arrancar(&cfg).unwrap();
    nodo.cadena = cadena_reorg(300);
    nodo.vota = true;

    // (a) `raiz_estado_calculada`: con una calculadora inmediata, tras solicitar y recoger.
    let raiz_fija = [0x33u8; 32];
    nodo.raices = RaicesPunto::nuevo(move |_e: &Estado| Ok::<[u8; 32], ErrorFalso>(raiz_fija));
    nodo.preparar_raices(VENTANA, T_INST);
    let (epoca, punto) = punto_de_ventana(&nodo.cadena, VENTANA, T_INST, LAG).unwrap();
    for _ in 0..2_000_000u32 {
        nodo.raices.recoger();
        if nodo.raices.raiz(epoca, &punto).is_some() {
            break;
        }
        std::thread::yield_now();
    }
    nodo.anunciar_raices_calculadas();

    // (b) `raiz_estado_no_lista`.
    nodo.avisar_raiz_no_lista(7, 1, hash_u32(5));

    // (c) `ventana_cerrada` con la raíz certificada.
    let raiz_cert = "ab".repeat(32);
    nodo.escribir_evento_votos(
        EventoMotor::VentanaCerrada {
            n: 7,
            certificado: true,
            plazas: 3,
            umbral: 2,
            slot: 14,
        },
        Some(&raiz_cert),
    );

    // (d) `certificado_peso_aplicado` con la raíz del certificado.
    let s = hash_u32(11);
    nodo.cadena = cadena_con_finalidad(3, s);
    let raiz_peso = [0xCDu8; 32];
    let tx = tx_certificado_peso_con_raiz(3, s, raiz_peso);
    nodo.reconciliar_ancla_de_bloque(
        BlockHash::from_digest(Digest::from_bytes([0x77; 32])),
        &[tx],
    );

    let contenido = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    let lineas: Vec<&str> = contenido.lines().collect();
    let busca = |tipo: &str| -> &str {
        lineas
            .iter()
            .copied()
            .find(|l| l.contains(&format!("\"tipo\":\"{tipo}\"")))
            .unwrap_or_else(|| panic!("sin línea {tipo}: {contenido}"))
    };
    let calculada = busca("raiz_estado_calculada");
    assert!(calculada.contains(&format!("\"raiz\":\"{}\"", crate::votos::hex(&raiz_fija))));
    assert!(calculada.contains("\"epoca\":1"));
    assert!(calculada.contains("\"ms\":"));
    let no_lista = busca("raiz_estado_no_lista");
    assert!(no_lista.contains("\"n\":7"));
    assert!(no_lista.contains("\"punto\":"));
    let cerrada = busca("ventana_cerrada");
    assert!(cerrada.contains(&format!("\"raiz\":\"{raiz_cert}\"")));
    let aplicado = busca("certificado_peso_aplicado");
    assert!(aplicado.contains(&format!("\"raiz\":\"{}\"", crate::votos::hex(&raiz_peso))));
}
