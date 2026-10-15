//! Bifurcaciones PoW y FC-3 (`ORDEN-W06d3` decisión 3).
//!
//! `Cadena::admitir` ya validaba cada bloque PoW contra el estado de su **padre declarado**
//! (`admitir_pow`, `past`/`post` indexados por hash), no contra ninguna "punta" implícita: dos
//! bloques con el mismo padre se admiten los dos, cada uno con su propio estado. Lo que faltaba (el
//! motivo de esta orden) era: (a) saber cuál de las puntas PoW conocidas es la "mejor" (más trabajo
//! acumulado), y (b) fijar el terminal según FC-3 (`P-ZRX/P-TRANSICION/ORDEN-T01.md` §159: sin
//! ningún sufijo PoST, gana el de más trabajo, no el primero que llegó) — antes, `admitir_pow`
//! fijaba `self.terminal` con el primero que llegaba y nunca lo revisaba.
//!
//! Este archivo prueba justo eso: [`Cadena::mejor_punta_pow`] y la selección de terminal por FC-3,
//! incluida su congelación en cuanto existe el primer bloque PoST.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

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

/// `h_corte_min = 2`, `w_min = 3`: ni la altura 1 ni un trabajo total < 3 alcanzan el corte por sí
/// solos, así que se puede construir una rama que "casi" llega y otra que sí, y decidir el orden de
/// llegada libremente en el test. `q = s_min = 0`, `k_min = 0`: `Φ` nunca bloquea.
fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 2,
        w_min: U256::from(3u64),
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

fn ticket(byte: u8, slot: u64) -> IdentidadGhostdag {
    IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor(byte),
        3,
        1 << 20,
        [byte; 32],
        slot,
    ))
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

fn genesis() -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash(0) },
        Vec::new(),
    ))
}

/// Un bloque PoW con `trabajo` explícito (el test decide la asimetría entre ramas; no se recalcula
/// de ningún target real, esto vive por debajo de `zx-node::pow`).
fn pow(hash_n: u8, padre: BlockHash, altura: u32, trabajo: u64) -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(hash_n),
            padre,
            altura,
            trabajo: U256::from(trabajo),
            pow_valido: true,
        },
        Vec::new(),
    ))
}

fn nueva_cadena() -> Cadena {
    let mut c = Cadena::nueva(params(), 1, CBID_RED_DEV, 15);
    c.admitir(genesis()).unwrap();
    c
}

/// **FC-3.** Dos ramas PoW desde el génesis: la rama `A` (un bloque, trabajo 1, no llega a
/// `w_min = 3`) se admite primero y no fija terminal; la rama `B` (dos bloques, trabajo 2 + 2 = 4)
/// llega después y sí alcanza `h_corte_min`/`w_min`. El terminal MUST ser el de `B`, no un
/// candidato de `A` (que ni siquiera llegó a cumplir las condiciones: sirve para comprobar que un
/// bloque que no cumple no se cachea como candidato).
#[test]
fn el_terminal_es_el_de_mayor_trabajo_no_el_primero_en_llegar() {
    let mut c = nueva_cadena();

    // Rama A: un solo bloque, trabajo 1. Altura 1 < h_corte_min = 2: no es candidato a terminal.
    c.admitir(pow(1, hash(0), 1, 1)).unwrap();
    assert_eq!(c.terminal(), None, "A solo no alcanza h_corte_min");

    // Rama B: dos bloques encadenados sobre el género, trabajo 2 cada uno (total 4 >= w_min = 3).
    c.admitir(pow(10, hash(0), 1, 2)).unwrap();
    c.admitir(pow(11, hash(10), 2, 2)).unwrap();

    assert_eq!(
        c.terminal(),
        Some(hash(11)),
        "FC-3: el terminal es la punta de mayor trabajo (B), no A"
    );
    assert_eq!(
        c.mejor_punta_pow(),
        Some(hash(11)),
        "la punta PoW seleccionada también es la de B"
    );
    assert_eq!(c.trabajo_pow(&hash(11)), Some(U256::from(4u64)));
    assert_eq!(c.trabajo_pow(&hash(1)), Some(U256::from(1u64)));
}

/// **FC-3, orden de llegada invertido.** Mismo escenario que el anterior, pero la rama pesada (`B`)
/// llega **antes** que la ligera (`A`): el terminal ya estaba fijado en `B` cuando `A` llega, y
/// `A` (más ligera) no debe desplazarlo. El resultado no depende del orden de llegada.
#[test]
fn el_terminal_no_cambia_por_una_rama_mas_ligera_llegada_despues() {
    let mut c = nueva_cadena();

    c.admitir(pow(10, hash(0), 1, 2)).unwrap();
    c.admitir(pow(11, hash(10), 2, 2)).unwrap();
    assert_eq!(c.terminal(), Some(hash(11)));

    // Una rama nueva, independiente, con menos trabajo total y que también cumple el corte por sí
    // sola (para comprobar que "cumple las condiciones" no basta si hay algo más pesado).
    c.admitir(pow(20, hash(0), 1, 2)).unwrap();
    c.admitir(pow(21, hash(20), 2, 1)).unwrap(); // total 3: cumple w_min = 3 igual, pero es menos.

    assert_eq!(
        c.terminal(),
        Some(hash(11)),
        "FC-3: una rama de menos trabajo no desplaza al terminal ya fijado"
    );
}

/// **Congelación tras el primer bloque PoST.** Con el terminal ya fijado, un bloque PoST de
/// transición se admite sobre él (`self.dag` deja de ser `None`); una rama PoW nueva, más pesada
/// que cualquiera de las anteriores, ya **no** puede cambiar el terminal ni el resumen de estado
/// que arrastra: eso invalidaría todo lo construido sobre el terminal viejo.
#[test]
fn el_terminal_se_congela_en_cuanto_hay_un_bloque_post() {
    let mut c = nueva_cadena();
    c.admitir(pow(10, hash(0), 1, 2)).unwrap();
    c.admitir(pow(11, hash(10), 2, 2)).unwrap();
    let terminal = hash(11);
    assert_eq!(c.terminal(), Some(terminal));

    // Primer bloque PoST (de transición): único padre posible, el terminal.
    c.admitir(post(200, vec![terminal], 1, productor(200)))
        .unwrap();
    assert!(c.contexto_dag().is_some(), "el DAG ya existe");

    // Una rama PoW nueva, mucho más pesada, que en fase pura habría ganado FC-3 con holgura.
    c.admitir(pow(30, hash(0), 1, 1_000)).unwrap();
    c.admitir(pow(31, hash(30), 2, 1_000)).unwrap();

    assert_eq!(
        c.terminal(),
        Some(terminal),
        "el terminal está congelado: ninguna rama PoW posterior lo mueve"
    );
}

/// [`Cadena::mejor_punta_pow`] sigue la rama más pesada **aunque ninguna** cumpla todavía las
/// condiciones de corte (`h_corte_min` alto): es la punta que debe seguir la plantilla de minado,
/// no solo un candidato a terminal.
#[test]
fn mejor_punta_pow_sigue_la_rama_mas_pesada_sin_alcanzar_el_corte() {
    let mut params = params();
    params.h_corte_min = 1_000; // inalcanzable en este test: nadie llega a ser terminal.
    let mut c = Cadena::nueva(params, 1, CBID_RED_DEV, 15);
    c.admitir(genesis()).unwrap();

    c.admitir(pow(1, hash(0), 1, 5)).unwrap();
    c.admitir(pow(2, hash(0), 1, 9)).unwrap();
    assert_eq!(c.terminal(), None, "h_corte_min inalcanzable: sin terminal");
    assert_eq!(
        c.mejor_punta_pow(),
        Some(hash(2)),
        "entre dos puntas de altura 1, gana la de más trabajo (9 > 5)"
    );

    // Extender la rama más ligera la hace más pesada en total (5 + 100 = 105 > 9): la punta
    // seleccionada cambia de rama.
    c.admitir(pow(3, hash(1), 2, 100)).unwrap();
    assert_eq!(c.mejor_punta_pow(), Some(hash(3)));
}
