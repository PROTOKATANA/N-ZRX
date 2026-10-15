//! `ORDEN-W08f` decisión 3: la consulta de solo lectura
//! [`Cadena::mergeset_de_padres`] devuelve el mismo `|mergeset|` que la admisión real
//! (`C-GD-04`), sobre un DAG con bifurcación y reunión, y devuelve `None` cuando no hay DAG,
//! cuando no hay padres o cuando algún padre es ajeno al DAG del terminal.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::{IdentidadGhostdag, IdentidadTicket};

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}

fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// `q = S_min = 0`: la garantía del productor nunca bloquea.
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

fn productor(byte: u8) -> ClavePublica {
    ClavePublica::desde_bytes([byte; 32])
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

fn ticket(byte: u8, slot: u64) -> IdentidadGhostdag {
    IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor(byte),
        3,
        1 << 20,
        [byte; 32],
        slot,
    ))
}

fn post(hash_n: u8, padres: Vec<BlockHash>, slot: u64, prod: ClavePublica) -> BloqueCadena {
    BloqueCadena::Post(BloquePost {
        hash: hash(hash_n),
        padres,
        slot,
        timestamp: 0,
        productor: prod,
        peso: 5,
        prueba_valida: true,
        requisito_declarado: 0,
        sr: 1,
        distancia: 0,
        identidad: ticket(hash_n, slot),
        txs: vec![(tx_coinbase_post(prod, 3, slot), Vec::new())],
    })
}

fn cadena_con_terminal() -> Cadena {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, 15);
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
    assert_eq!(cadena.terminal(), Some(hash(1)));
    cadena
}

fn admitir_y_registrar(cadena: &mut Cadena, admitidos: &mut Vec<BlockHash>, b: BloqueCadena) {
    let h = b.hash();
    cadena.admitir(b).unwrap();
    admitidos.push(h);
}

/// DAG: terminal → (A1, B1, C1) → (A2, B2) → M(A2, B2) → N(M, C1), con `C1` hermano suelto.
/// La reunión `M` tiene un mergeset no trivial; `N` añade `C1`.
fn dag_de_prueba() -> (Cadena, Vec<BlockHash>) {
    let mut cadena = cadena_con_terminal();
    let t = hash(1);
    let mut admitidos = Vec::new();

    admitir_y_registrar(
        &mut cadena,
        &mut admitidos,
        post(10, vec![t], 1, productor(10)),
    ); // A1
    admitir_y_registrar(
        &mut cadena,
        &mut admitidos,
        post(11, vec![t], 1, productor(11)),
    ); // B1
    admitir_y_registrar(
        &mut cadena,
        &mut admitidos,
        post(12, vec![t], 1, productor(12)),
    ); // C1
    admitir_y_registrar(
        &mut cadena,
        &mut admitidos,
        post(20, vec![hash(10)], 2, productor(20)),
    ); // A2
    admitir_y_registrar(
        &mut cadena,
        &mut admitidos,
        post(21, vec![hash(11)], 2, productor(21)),
    ); // B2
    admitir_y_registrar(
        &mut cadena,
        &mut admitidos,
        post(30, vec![hash(20), hash(21)], 3, productor(30)),
    ); // M
    admitir_y_registrar(
        &mut cadena,
        &mut admitidos,
        post(40, vec![hash(30), hash(12)], 4, productor(40)),
    ); // N
    (cadena, admitidos)
}

/// La consulta coincide con el mergeset realmente almacenado para cada bloque admitido.
#[test]
fn mergeset_de_padres_coincide_con_la_admision() {
    let (cadena, admitidos) = dag_de_prueba();

    let mut vistos_no_triviales = 0;
    for h in &admitidos {
        let Some(bloque) = cadena.bloque(h) else {
            panic!("bloque admitido ausente");
        };
        let padres = bloque.padres();
        let (tamano, tope) = cadena
            .mergeset_de_padres(&padres)
            .expect("padres del DAG y consulta disponible");
        assert_eq!(tope, 180, "el tope devuelto es el del consenso (`C-GD-04`)");

        let (azules, rojos) = cadena.mergeset_de(h).expect("bloque en el DAG");
        assert_eq!(
            tamano,
            azules + rojos,
            "la consulta y el `orden_mergeset` almacenado difieren para {h:?}"
        );
        if tamano > 0 {
            vistos_no_triviales += 1;
        }
    }
    assert!(
        vistos_no_triviales >= 1,
        "el DAG debe tener al menos un bloque con mergeset no trivial"
    );

    // Conjunto antichain {A2, B2, C1}: el mergeset incluye la rama B entera y `C1` (3 bloques).
    let (tamano, tope) = cadena
        .mergeset_de_padres(&[hash(20), hash(21), hash(12)])
        .unwrap();
    assert!(tamano >= 3, "el mergeset debe incluir la rama B: {tamano}");
    assert_eq!(tope, 180);
}

/// Sin DAG, sin padres o con un padre ajeno: `None`, nunca un valor inventado.
#[test]
fn mergeset_de_padres_es_none_cuando_no_puede_responder() {
    let vacia = Cadena::nueva(params(), 1, CBID_RED_DEV, 15);
    assert!(vacia.mergeset_de_padres(&[hash(9)]).is_none());

    // Terminal PoW fijado pero sin ningún bloque PoST: todavía no hay DAG.
    let sin_dag = cadena_con_terminal();
    assert!(sin_dag.mergeset_de_padres(&[hash(1)]).is_none());
    assert!(sin_dag.mergeset_de_padres(&[]).is_none());

    let (cadena, _) = dag_de_prueba();
    assert!(cadena.mergeset_de_padres(&[]).is_none());
    // `hash(250)` no pertenece al DAG del terminal.
    assert!(cadena.mergeset_de_padres(&[hash(250)]).is_none());
    // Duplicados: el formato de padres los rechaza y la consulta no responde.
    assert!(cadena.mergeset_de_padres(&[hash(30), hash(30)]).is_none());
}
