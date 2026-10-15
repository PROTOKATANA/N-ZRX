//! `ORDEN-W06d10-B` **V1, familia X2**: el tope **local** de terminales con DAG
//! (`MAX_TERMINALES_CON_DAG = 8`) produce `MotivoBloque::ErrLimiteTerminales` para un noveno
//! terminal cuyo trabajo PoW no supera al peor de los ocho; el nodo debe clasificarlo como
//! `VistaLocal` (`Ignorar` en red, sin penalizar al par).
//!
//! El escenario se construye sobre `zx-cadena` **directamente** (el nodo no expone una costura para
//! inyectar ocho DAGs); lo que este test demuestra es la pieza que sí vive en `zx-node`: que el
//! motivo real del tope local se clasifica como vista local y no penaliza. El comportamiento de
//! `zx-cadena` en este escenario ya está cubierto por
//! `crates/zx-cadena/tests/multiterminal.rs::directed_noveno_terminal_ignorado`.

#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena, MAX_TERMINALES_CON_DAG, MotivoBloque};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;
use zx_node::rechazo::{ClasificacionRechazo, clasificar_motivo_bloque};

const MAX_PADRES: u8 = 15;
const K: u32 = 1;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).expect("10 ZZK representable")
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).expect("3 ZZK representable")
}

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

fn hash(n: u16) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[30] = (n >> 8) as u8;
    bytes[31] = (n & 0xff) as u8;
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn clave(semilla: u8) -> ClavePublica {
    let mensaje = [b"zx-w06d10b-x2", &[semilla][..]].concat();
    let digest = zx_core::sha3_256_publico(&mensaje);
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
            importe: Amount::nuevo(importe).expect("importe representable"),
            slot,
        },
    }
}

fn genesis() -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash(0) },
        Vec::new(),
    ))
}

fn pow_terminal(id: u16, trabajo: u64) -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(id),
            padre: hash(0),
            altura: 1,
            trabajo: U256::from(trabajo),
            pow_valido: true,
        },
        Vec::new(),
    ))
}

fn post(
    id: u16,
    padres: Vec<BlockHash>,
    slot: u64,
    sr: u64,
    productor_semilla: u8,
    chunk: u8,
) -> BloqueCadena {
    let productor = clave(productor_semilla);
    let tx = tx_coinbase_post(productor, 1, slot);
    let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor,
        0,
        u64::from(chunk) + 1,
        [chunk; 32],
        slot,
    ));
    BloqueCadena::Post(BloquePost {
        hash: hash(id),
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

/// Un bloque PoST del terminal `terminal` (basta uno para darle DAG). `id`/`sr`/`productor` únicos.
fn sufijo_de_uno(terminal: BlockHash, id: u16, sr: u64, productor_semilla: u8) -> BloqueCadena {
    post(id, vec![terminal], 1, sr, productor_semilla, id as u8)
}

#[test]
fn noveno_terminal_que_no_supera_al_peor_es_vista_local() {
    let mut cadena = Cadena::nueva(params(), K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).expect("génesis");
    assert_eq!(MAX_TERMINALES_CON_DAG, 8);

    // Ocho terminales con DAG: el terminal `i` tiene trabajo PoW `i*10` (mínimo 10).
    for i in 1..=8u16 {
        cadena
            .admitir(pow_terminal(i, u64::from(i) * 10))
            .expect("terminal PoW");
        cadena
            .admitir(sufijo_de_uno(hash(i), 100 + i, 10, i as u8))
            .expect("sufijo PoST");
    }
    assert_eq!(cadena.terminales_con_dag().len(), 8);

    // Noveno terminal con menos trabajo que cualquiera de los ocho: su sufijo no se admite.
    let t9 = hash(9);
    cadena.admitir(pow_terminal(9, 1)).expect("terminal 9");
    let motivo = cadena
        .admitir(sufijo_de_uno(t9, 200, 10, 9))
        .expect_err("el noveno terminal no supera al peor");
    assert_eq!(motivo, MotivoBloque::ErrLimiteTerminales);

    // La pieza de `zx-node`: es vista local, no penaliza al par.
    let clasificacion = clasificar_motivo_bloque(&motivo);
    assert_eq!(clasificacion, ClasificacionRechazo::VistaLocal);
    assert!(clasificacion.es_vista_local());
    assert!(
        !clasificacion.penaliza_en_red(),
        "el tope de terminales es local: no se penaliza al par"
    );
    assert!(
        !cadena.terminales_con_dag().contains(&t9),
        "el noveno no desaloja: pesaba menos"
    );
}
