//! Límite de padres configurable e identidad real de `C-GD-07` (`ORDEN-W06a-C` decisiones 1–3).
//!
//! - [`Cadena::nueva`] recibe `max_padres` **sin valor por defecto oculto**. Con 15, un bloque de 15
//!   padres se admite y uno de 16 se rechaza; con 3 (el arnés de T04) el tope es 3.
//! - `BloquePost::identidad` es una `IdentidadGhostdag` real (tupla de `C-GD-07`). Dos billetes
//!   distintos que una proyección de 8 bytes confundiría se tratan como **distintos** en U2, y el
//!   repetido se rechaza con `ErrU2`.
//!
//! Nota de alcance: una colisión real de los primeros 8 bytes de `huella()` (SHA3-256) no es
//! construible en tiempo de test. El test usa dos billetes con los **mismos** 8 primeros bytes de su
//! codificación canónica (`bytes_canonicos()[..8]`, la clave pública) y distinto `slot`: cualquier
//! proyección a 8 bytes los confundiría, la tupla real no. Esa es exactamente la propiedad que el
//! antiguo `u64` de `zx-node` rompía por construcción.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena, MotivoBloque};
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

/// Billete real de `C-GD-07` con clave y `slot` dados.
fn ticket(byte: u8, slot: u64) -> IdentidadGhostdag {
    IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor(byte),
        3,
        1 << 20,
        [byte; 32],
        slot,
    ))
}

fn post(
    hash_n: u8,
    padres: Vec<BlockHash>,
    slot: u64,
    prod: ClavePublica,
    identidad: IdentidadGhostdag,
) -> BloqueCadena {
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
        identidad,
        txs: vec![(tx_coinbase_post(prod, 3, slot), Vec::new())],
    })
}

/// Cadena con génesis y terminal PoW ya fijados, y el `max_padres` pedido.
fn cadena_con_terminal(max_padres: u8) -> Cadena {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, max_padres);
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

#[test]
fn quince_padres_se_admiten_y_dieciseis_se_rechazan() {
    let mut cadena = cadena_con_terminal(15);
    let terminal = hash(1);

    // 16 hermanos válidos (un solo padre: el terminal), cada uno con su billete real.
    let mut hermanos: Vec<BlockHash> = Vec::new();
    for i in 0..16u8 {
        let slot = u64::from(i) + 1;
        let b = post(
            10 + i,
            vec![terminal],
            slot,
            productor(i + 1),
            ticket(i + 1, slot),
        );
        cadena.admitir(b).unwrap();
        hermanos.push(hash(10 + i));
    }
    assert_eq!(cadena.tips_validas().len(), 16);

    // 15 padres: admitido con `max_padres = 15`.
    let quince = post(
        100,
        hermanos[..15].to_vec(),
        17,
        productor(80),
        ticket(80, 17),
    );
    assert!(
        cadena.admitir(quince).is_ok(),
        "un bloque de 15 padres debe admitirse con max_padres = 15"
    );

    // 16 padres: rechazado.
    let dieciseis = post(101, hermanos.clone(), 18, productor(81), ticket(81, 18));
    assert_eq!(
        cadena.admitir(dieciseis),
        Err(MotivoBloque::ErrSinPadre),
        "un bloque de 16 padres debe rechazarse con max_padres = 15"
    );
}

#[test]
fn con_max_padres_tres_el_cuarto_padre_se_rechaza() {
    let mut cadena = cadena_con_terminal(3);
    let terminal = hash(1);
    let mut hermanos: Vec<BlockHash> = Vec::new();
    for i in 0..4u8 {
        let slot = u64::from(i) + 1;
        cadena
            .admitir(post(
                10 + i,
                vec![terminal],
                slot,
                productor(i + 1),
                ticket(i + 1, slot),
            ))
            .unwrap();
        hermanos.push(hash(10 + i));
    }
    let tres = post(100, hermanos[..3].to_vec(), 5, productor(80), ticket(80, 5));
    assert!(cadena.admitir(tres).is_ok());
    let cuatro = post(101, hermanos.clone(), 6, productor(81), ticket(81, 6));
    assert_eq!(cadena.admitir(cuatro), Err(MotivoBloque::ErrSinPadre));
}

#[test]
fn identidades_reales_distintas_no_colapsan_en_ocho_bytes() {
    let mut cadena = cadena_con_terminal(15);
    let terminal = hash(1);
    let prod = productor(9);

    // Mismos 8 primeros bytes canónicos (misma clave pública), distinto slot.
    let t1 = ticket(9, 100);
    let t2 = ticket(9, 101);
    let (IdentidadGhostdag::Billete(a), IdentidadGhostdag::Billete(b)) = (t1, t2) else {
        panic!("se esperaban dos billetes");
    };
    assert_eq!(
        a.bytes_canonicos()[..8],
        b.bytes_canonicos()[..8],
        "el prefijo de 8 bytes debe coincidir para que la prueba sea significativa"
    );
    assert_ne!(
        t1, t2,
        "la tupla real distingue lo que la proyección confundiría"
    );

    cadena
        .admitir(post(30, vec![terminal], 100, prod, t1))
        .unwrap();
    // Un billete distinto se admite aunque su proyección a 8 bytes coincida con la del abuelo.
    cadena
        .admitir(post(31, vec![hash(30)], 101, prod, t2))
        .unwrap();
    // El mismo billete real repetido en el pasado sí se rechaza (U2).
    assert_eq!(
        cadena.admitir(post(32, vec![hash(31)], 102, prod, t1)),
        Err(MotivoBloque::ErrU2)
    );
}

/// **`ORDEN-W06d2` / RI-2a #1 (ALTA, CONFIRMADO).** Un hijo sometido antes que su padre no debe
/// quedar inválido para siempre: al llegar el padre y volver a someter exactamente el mismo hijo,
/// `admitir` debe admitirlo.
///
/// Antes del arreglo (`Cadena::dependencia_no_disponible`), el primer `admitir(hijo)` cacheaba
/// `ErrSinPadre` en `validos`/`motivos` de forma permanente; el segundo `admitir(hijo)` devolvía el
/// error cacheado sin volver a intentar la tubería, aunque el padre ya fuera válido. Es exactamente
/// la condición de carrera de red que produce divergencia entre nodos honestos según el orden de
/// llegada (sin ningún adversario de por medio).
#[test]
fn w06d2_hijo_antes_que_el_padre_se_admite_al_llegar_el_padre() {
    let mut cadena = cadena_con_terminal(15);
    let terminal = hash(1);

    let padre = post(50, vec![terminal], 1, productor(50), ticket(50, 1));
    let hash_padre = hash(50);
    let hijo = post(60, vec![hash_padre], 2, productor(60), ticket(60, 2));

    // 1) El hijo llega primero: su padre todavía no existe en esta `Cadena`.
    assert_eq!(
        cadena.admitir(hijo.clone()),
        Err(MotivoBloque::ErrSinPadre),
        "sin el padre, el rechazo es correcto (y debe ser provisional, no cacheado)"
    );

    // 2) El padre llega y es válido.
    assert!(
        cadena.admitir(padre).is_ok(),
        "el padre por sí solo es válido"
    );
    assert!(cadena.es_valido(&hash_padre));

    // 3) El mismo hijo, sometido otra vez: MUST admitirse ahora que el padre está disponible.
    assert!(
        cadena.admitir(hijo.clone()).is_ok(),
        "BUG RI-2a #1: el hijo debe admitirse una vez que su padre ya es válido, no quedar \
         cacheado como ErrSinPadre para siempre"
    );
    assert!(cadena.es_valido(&hijo.hash()));
}
