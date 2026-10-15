//! `ORDEN-W08a` — el rechazo por tope de terminales no se guarda para siempre (IPA B-14).
//!
//! Cubre el plan de verificación de la orden:
//!
//! - **V1**: un noveno terminal rechazado por `MAX_TERMINALES_CON_DAG` **no** queda cacheado como
//!   inválido y se **reevalúa** en el siguiente `admitir`. El texto literal de la orden («se
//!   admite tras desalojar a uno de los ocho») **no es alcanzable** con las decisiones 1–3: el
//!   desalojo solo sube el mínimo de trabajo PoW de los terminales con DAG, y el rechazo exige
//!   `W(T) <= mínimo`, así que el mismo bloque vuelve a rechazarse; la demostración va como
//!   aserción explícita más abajo y está razonada en `INFORME.md` §2 y `PROGRESO.md` §0.1.
//! - **V2**: un rechazo **demostrable** (`ErrSlot` aquí) sigue cacheado y se devuelve sin
//!   reevaluar, incluso si el mismo `block_hash` se somete después con contenido válido.
//!
//! También comprueba que el mismo bloque sí se admite cuando el tope tiene cupo: la única razón
//! del rechazo es el conjunto **local** de terminales con DAG.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena, MAX_TERMINALES_CON_DAG, MotivoBloque};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;

const MAX_PADRES: u8 = 15;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
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
    // 2 bytes de variedad bastan para estos tamaños; el resto a cero mantiene el orden
    // lexicográfico == orden numérico de `n`.
    let mut bytes = [0u8; 32];
    bytes[30] = (n >> 8) as u8;
    bytes[31] = (n & 0xff) as u8;
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn clave(semilla: u8) -> ClavePublica {
    let mensaje = [b"zx-w08a-limite", &[semilla][..]].concat();
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
            importe: Amount::nuevo(importe).unwrap(),
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

/// Bloque PoW hijo directo del génesis (candidato a terminal si `trabajo >= w_min = 1`).
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

/// Un bloque PoST de un terminal, con `sr` (que fija su `blue_work`) y productor/identidad únicos.
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

/// Cadena con `genesis` y los terminales `1..=n` (trabajo `i*10`), cada uno con un bloque PoST que
/// le da DAG propio. Devuelve la cadena y los hashes de los terminales.
fn cadena_con_terminales(n: u16) -> (Cadena, Vec<BlockHash>) {
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    let mut terminales = Vec::new();
    for i in 1..=n {
        cadena.admitir(pow_terminal(i, u64::from(i) * 10)).unwrap();
        cadena
            .admitir(post(100 + i, vec![hash(i)], 1, 10, i as u8, i as u8))
            .unwrap();
        terminales.push(hash(i));
    }
    (cadena, terminales)
}

/// **V1 (la parte alcanzable).** Con ocho DAGs, el noveno terminal (trabajo 1) se rechaza por tope,
/// pero el rechazo **no se cachea** y el bloque se **reevalúa** en el siguiente `admitir`.
///
/// Demostración del límite literal: tras desalojar a `T1` (trabajo 10) con `T10` (trabajo 1000), el
/// mínimo sube a `W(T2) = 20 > W(T9) = 1`; la regla `W(T) <= mínimo` vuelve a rechazar el mismo
/// bloque. Se afirma explícitamente para que quede como regresión del hallazgo (no como fallo).
///
/// Sin el cambio (`ws.orig`), este test falla en `motivo(&b9)`: la base devuelve
/// `Some(ErrLimiteTerminales)`.
#[test]
fn v1_noveno_no_cacheado_y_reevaluado() {
    let (mut cadena, _terminales) = cadena_con_terminales(8);
    assert_eq!(MAX_TERMINALES_CON_DAG, 8);
    assert_eq!(cadena.terminales_con_dag().len(), 8);
    assert!(!cadena.limite_terminales_alcanzado());

    // Noveno terminal, con menos trabajo que el peor de los ocho (mínimo 10).
    let t9 = hash(9);
    cadena.admitir(pow_terminal(9, 1)).unwrap();
    let b9 = post(900, vec![t9], 1, 10, 9, 0);
    let hash9 = b9.hash();

    assert_eq!(
        cadena.admitir(b9.clone()),
        Err(MotivoBloque::ErrLimiteTerminales)
    );
    assert!(cadena.limite_terminales_alcanzado());
    assert!(!cadena.terminales_con_dag().contains(&t9));
    assert!(!cadena.es_valido(&hash9));
    assert_eq!(
        cadena.motivo(&hash9),
        None,
        "el rechazo por tope NO debe quedar cacheado (decisión 1)"
    );

    // Reevaluación: el mismo bloque vuelve a pasar por la tubería y vuelve a rechazarse por tope
    // (el tope sigue lleno y su trabajo es el menor); no se cachea.
    assert_eq!(
        cadena.admitir(b9.clone()),
        Err(MotivoBloque::ErrLimiteTerminales)
    );
    assert_eq!(cadena.motivo(&hash9), None);

    // Décimo terminal con más trabajo: desaloja al peor (T1, trabajo 10).
    cadena.admitir(pow_terminal(10, 1_000)).unwrap();
    cadena
        .admitir(post(910, vec![hash(10)], 1, 10, 10, 0))
        .unwrap();
    assert_eq!(cadena.terminales_con_dag().len(), 8);
    assert!(!cadena.terminales_con_dag().contains(&hash(1)));

    // El mínimo subió: la regla del tope hace imposible admitir el noveno por reevaluación.
    assert!(
        cadena.trabajo_pow(&hash(2)).unwrap() > cadena.trabajo_pow(&t9).unwrap(),
        "el desalojo sube el mínimo; ver INFORME.md"
    );
    assert_eq!(
        cadena.admitir(b9.clone()),
        Err(MotivoBloque::ErrLimiteTerminales)
    );
    assert_eq!(
        cadena.motivo(&hash9),
        None,
        "el reintento tras desalojo tampoco lo cachea"
    );
}

/// **V1 (control del mecanismo).** El mismo bloque que el tope rechaza con 8 DAGs se admite si el
/// tope tiene cupo (7 DAGs): la validez del bloque no cambia, solo la vista local. Refuerza que el
/// rechazo es de vista local y que la variable que lo levantaría es `dags.len() < 8`.
#[test]
fn v1_control_cupo_libre_admite() {
    let (mut cadena, _terminales) = cadena_con_terminales(7);
    assert_eq!(cadena.terminales_con_dag().len(), 7);

    let t9 = hash(9);
    cadena.admitir(pow_terminal(9, 1)).unwrap();
    let b9 = post(900, vec![t9], 1, 10, 9, 0);
    assert_eq!(cadena.admitir(b9), Ok(()));
    assert!(cadena.terminales_con_dag().contains(&t9));
}

/// **V2.** Un rechazo demostrable (`ErrSlot`, `slot = 0`) se cachea y se devuelve **sin reevaluar**:
/// el mismo `block_hash` sometido después con contenido válido (`slot = 1`) sigue devolviendo el
/// motivo cacheado. Sin la regla de caché, el bloque válido se admitiría.
#[test]
fn v2_rechazo_demostrable_sigue_cacheado() {
    let t1 = hash(1);
    let mut cadena = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 10)).unwrap();

    let malo = post(50, vec![t1], 0, 10, 1, 0);
    assert_eq!(cadena.admitir(malo), Err(MotivoBloque::ErrSlot));
    assert_eq!(cadena.motivo(&hash(50)), Some(&MotivoBloque::ErrSlot));
    assert!(!cadena.es_valido(&hash(50)));

    // Mismo `block_hash`, contenido válido: la caché del rechazo demostrable manda.
    let bueno = post(50, vec![t1], 1, 10, 1, 0);
    assert_eq!(hash(50), bueno.hash());
    assert_eq!(
        cadena.admitir(bueno.clone()),
        Err(MotivoBloque::ErrSlot),
        "un motivo demostrable NO se reevalúa"
    );
    assert!(!cadena.es_valido(&hash(50)));

    // Control independiente: en una cadena limpia el mismo bloque válido sí se admite.
    let mut limpia = Cadena::nueva(params(), 1, CBID_RED_DEV, MAX_PADRES);
    limpia.admitir(genesis()).unwrap();
    limpia.admitir(pow_terminal(1, 10)).unwrap();
    assert_eq!(limpia.admitir(bueno), Ok(()));
    assert!(limpia.es_valido(&hash(50)));
}
