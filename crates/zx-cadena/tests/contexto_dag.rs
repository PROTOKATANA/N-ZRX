//! Test del accesor [`Cadena::contexto_dag`] añadido por `ORDEN-W06d1` («Relanzamiento» punto 3).
//!
//! El nodo no puede confiar en `zx_post::ContextoTransicion::padre_seleccionado` (el atajo dev que
//! devuelve el declarado sin comprobarlo) para verificar la cabecera de un bloque **ajeno**: tiene
//! que consultar el GHOSTDAG real ya admitido en `zx-cadena`. Este test comprueba que el accesor:
//!
//! - es `None` mientras no se ha fijado el terminal (fase PoW, sin DAG que consultar);
//! - es `Some` tras fijarse el terminal, y que el `AlmacenGhostdag` que devuelve es el mismo que usa
//!   `Cadena` internamente para admitir (mismos bloques conocidos, mismo `padre_seleccionado` real).

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "el test falla con panic por diseño"
)]

use ed25519_zebra::{SigningKey, VerificationKey};
use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, PadresDag, Tx};
use zx_dag::bloque_dag::ContextoDag;
use zx_dag::{IdentidadGhostdag, IdentidadTicket};

/// Máximo de padres del perfil dev (`PERFIL-DEV-v0.md` §4).
const MAX_PADRES_PRODUCCION: u8 = 15;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// `q = S_min = 0`: la garantía del productor nunca bloquea (igual que `tests/propiedades.rs`).
fn params() -> ParametrosTransicion {
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
        f_slots: None,
        subsidio_pow,
        subsidio_post,
    }
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn clave(semilla: u8) -> ClavePublica {
    let sk = SigningKey::from([semilla; 32]);
    let vk = VerificationKey::from(&sk);
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

#[test]
fn none_antes_del_terminal_y_none_justo_al_fijarlo_some_tras_el_primer_post() {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES_PRODUCCION);

    let genesis = BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash(0) },
        Vec::new(),
    ));
    cadena.admitir(genesis).unwrap();
    assert!(
        cadena.contexto_dag().is_none(),
        "sin terminal fijado no hay DAG que consultar"
    );

    // h_corte_min = 1, W_min = 1: este bloque fija el terminal.
    let pow = BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(1),
            padre: hash(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        Vec::new(),
    ));
    cadena.admitir(pow).unwrap();
    assert_eq!(cadena.terminal(), Some(hash(1)));
    // `inicializar_dag` vive dentro de `admitir_post`, no de `admitir_pow`: justo al fijar el
    // terminal, antes de admitir ningún bloque PoST, sigue sin haber GHOSTDAG que consultar.
    assert!(
        cadena.contexto_dag().is_none(),
        "el terminal se fijó pero aún no se admitió ningún bloque PoST: sigue sin haber DAG"
    );
}

#[test]
fn el_contexto_dag_es_el_mismo_que_usa_la_admision_real() {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES_PRODUCCION);
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis { hash: hash(0) },
            Vec::new(),
        )))
        .unwrap();
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::PoW {
                hash: hash(1),
                padre: hash(0),
                altura: 1,
                trabajo: U256::one(),
                pow_valido: true,
            },
            Vec::new(),
        )))
        .unwrap();
    let terminal = cadena.terminal().unwrap();

    let productor = clave(7);
    let p1 = BloquePost {
        hash: hash(10),
        padres: vec![terminal],
        slot: 1,
        timestamp: 0,
        productor,
        peso: 5,
        prueba_valida: true,
        requisito_declarado: 0,
        sr: 1,
        distancia: 0,
        identidad: IdentidadGhostdag::Billete(IdentidadTicket::vigente(
            productor, 0, 1, [0x11; 32], 1,
        )),
        txs: vec![(tx_coinbase_post(productor, 3, 1), Vec::new())],
    };
    cadena.admitir(BloqueCadena::Post(p1.clone())).unwrap();

    let dag = cadena
        .contexto_dag()
        .expect("el DAG existe tras el terminal");

    // Bloques conocidos por el accesor: el terminal (raíz) y el bloque PoST recién admitido.
    assert!(dag.es_bloque_validado(&terminal));
    assert!(dag.es_bloque_validado(&p1.hash));
    assert!(!dag.es_bloque_validado(&hash(99)));
    assert!(dag.es_terminal(&terminal));
    assert_eq!(dag.slot_de_padre(&terminal).unwrap(), 0);
    assert_eq!(dag.slot_de_padre(&p1.hash).unwrap(), 1);

    // Un único padre: el `sp` real de GHOSTDAG coincide con el declarado (caso trivial, pero es la
    // MISMA vía que usó `admitir_post` internamente, no una reimplementación local).
    let padres_unicos = PadresDag::nuevo(p1.hash, &[]).unwrap();
    assert_eq!(
        ContextoDag::padre_seleccionado(dag, &padres_unicos).unwrap(),
        p1.hash
    );

    // Un padre desconocido para el accesor es un error explícito, no un `None` silencioso.
    let padres_ajenos = PadresDag::nuevo(hash(99), &[]).unwrap();
    assert!(ContextoDag::padre_seleccionado(dag, &padres_ajenos).is_err());
}

/// `ORDEN-W07a` decisión 2: los accesos de lectura nuevos del registro devuelven exactamente lo que
/// `zx-dag` ya calcula y guarda para el mismo DAG (no una segunda implementación). Se comprueba en
/// la cadena mínima: génesis + PoW terminal + un PoST hijo del terminal.
#[test]
fn accesos_de_lectura_del_registro_coinciden_con_el_dag() {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES_PRODUCCION);
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis { hash: hash(0) },
            Vec::new(),
        )))
        .unwrap();
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::PoW {
                hash: hash(1),
                padre: hash(0),
                altura: 1,
                trabajo: U256::one(),
                pow_valido: true,
            },
            Vec::new(),
        )))
        .unwrap();
    let terminal = cadena.terminal().unwrap();

    let productor = clave(7);
    let p1 = BloquePost {
        hash: hash(10),
        padres: vec![terminal],
        slot: 1,
        timestamp: 0,
        productor,
        peso: 5,
        prueba_valida: true,
        requisito_declarado: 0,
        sr: 1,
        distancia: 0,
        identidad: IdentidadGhostdag::Billete(IdentidadTicket::vigente(
            productor, 0, 1, [0x11; 32], 1,
        )),
        txs: vec![(tx_coinbase_post(productor, 3, 1), Vec::new())],
    };
    cadena.admitir(BloqueCadena::Post(p1.clone())).unwrap();

    // Tres bloques válidos admitidos: génesis, PoW y el PoST.
    assert_eq!(cadena.bloques_admitidos(), 3);
    // El génesis PoW no está en el DAG (no hay `DatosGhostdag` para él).
    assert!(cadena.datos_ghostdag(&hash(0)).is_none());
    assert!(cadena.blue_score(&hash(0)).is_none());
    assert!(cadena.mergeset_de(&hash(0)).is_none());
    // El terminal PoW es la raíz del DAG (índice 0): azules vacíos y `blue_score` 0.
    assert_eq!(cadena.blue_score(&terminal), Some(0));
    assert_eq!(cadena.mergeset_de(&terminal), Some((0, 0)));
    // `p1` solo tiene al terminal como padre seleccionado. El acceso devuelve exactamente el valor
    // que `zx-dag` guardó (no una segunda implementación) y los tamaños del mergeset coinciden con
    // la descomposición `orden_mergeset = azules + rojos`.
    let datos = cadena.datos_ghostdag(&p1.hash).expect("p1 está en el DAG");
    assert_eq!(cadena.blue_score(&p1.hash), Some(datos.blue_score));
    assert_eq!(
        cadena.mergeset_de(&p1.hash),
        Some((
            (datos.orden_mergeset.len() - datos.rojos.len()) as u64,
            datos.rojos.len() as u64
        ))
    );
    assert!(datos.sp.is_some(), "p1 tiene padre seleccionado");
    assert_eq!(cadena.padre_seleccionado(&p1.hash), Some(terminal));
    assert_eq!(cadena.padre_seleccionado(&terminal), None);
}
