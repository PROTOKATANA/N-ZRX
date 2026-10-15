//! `FIN-1` · V2 — cota de profundidad `F` dentro del DAG PoST (punto de finalidad).
//!
//! Prueba, con bloques PoST reales (mismo constructor que `reorg_w08b.rs`):
//!
//! 1. el punto de finalidad **avanza** con la punta y **nunca retrocede**;
//! 2. una rama rival más pesada que **excluye** el punto de finalidad se admite pero **no** se
//!    selecciona, y queda anotada la violación;
//! 3. una rama rival más pesada que **contiene** el punto de finalidad sí sustituye (reorg ≤ `F`);
//! 4. sin `F` (`f_slots = None`) no hay cota y la rival vuelve a ganar.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
#![expect(clippy::panic, reason = "un fallo de admisión es un panic del test")]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;

const MAX_PADRES: u8 = 15;
const K: u32 = 1;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// `q = S_min = 0`, `H_corte_min = 1`: sin garantía, para aislar la selección. `f_slots` por test.
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
    let digest = zx_core::sha3_256_publico(b"zx-fin1-finalidad");
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

/// Bloque PoST con identidad única (`id`), `slot` y `sr` (que fija el `blue_work`; menor = más peso).
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

/// Cadena lineal de `n` bloques PoST a partir de `base`, con slots `slot_ini..` y `sr` dado.
fn rama(
    cadena: &mut Cadena,
    n: u32,
    base_id: u32,
    base: BlockHash,
    slot_ini: u64,
    sr: u64,
) -> (BlockHash, Vec<u32>) {
    let mut padre = base;
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        let id = base_id + i;
        let b = post(id, vec![padre], slot_ini + u64::from(i), sr);
        cadena
            .admitir(b.clone())
            .unwrap_or_else(|e| panic!("rama base_id={base_id} i={i}: {e:?}"));
        padre = b.hash();
        ids.push(id);
    }
    (padre, ids)
}

/// Génesis + terminal PoW + rama base de `n` bloques con `sr` (ids 10..). Devuelve cadena y punta.
fn cadena_con_base(f_slots: Option<u64>, n: u32, sr: u64) -> (Cadena, BlockHash) {
    let mut cadena = Cadena::nueva(params(f_slots), K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    let (punta, _) = rama(&mut cadena, n, 10, hash_u32(1), 1, sr);
    (cadena, punta)
}

fn slot_de(cadena: &Cadena, h: BlockHash) -> u64 {
    cadena.bloque(&h).and_then(|b| b.slot()).unwrap_or(0)
}

#[test]
fn punto_finalidad_avanza_y_no_retrocede() {
    let f = 3u64;
    let (mut cadena, _) = cadena_con_base(Some(f), 0, 10);
    let mut anterior = cadena.punto_finalidad();
    for i in 1..=12u64 {
        let padre = if i == 1 {
            hash_u32(1)
        } else {
            hash_u32(100 + i as u32 - 1)
        };
        let b = post(100 + i as u32, vec![padre], i, 10);
        cadena.admitir(b.clone()).unwrap();
        let pf = cadena.punto_finalidad();
        // Slot esperado: mayor bloque con slot ≤ i − f.
        let esperado = i.saturating_sub(f);
        let slot_pf = pf.map_or(0, |h| slot_de(&cadena, h));
        assert_eq!(
            slot_pf, esperado,
            "i={i}: punto de finalidad slot={slot_pf}, esperado={esperado}"
        );
        // Nunca retrocede.
        let slot_anterior = anterior.map_or(0, |h| slot_de(&cadena, h));
        assert!(
            slot_anterior <= slot_pf,
            "i={i}: el punto de finalidad retrocedió de {slot_anterior} a {slot_pf}"
        );
        anterior = pf;
    }
}

#[test]
fn rama_que_excluye_el_punto_es_rechazada_para_seleccion() {
    let f = 3u64;
    // Base honesta de 10 slots (sr=10, poco peso). Su punto de finalidad queda en el slot 7.
    let (mut cadena, punta_honesta) = cadena_con_base(Some(f), 10, 10);
    let pf = cadena
        .punto_finalidad()
        .expect("debe haber punto de finalidad");
    assert_eq!(slot_de(&cadena, pf), 7);

    // Rival mucho más pesada (sr=1) que bifurca del terminal compartido: no contiene el punto.
    let (punta_rival, ids_rival) = rama(&mut cadena, 12, 1_000, hash_u32(1), 1, 1);

    assert!(
        cadena.es_valido(&punta_rival),
        "la rival se admite (es válida)"
    );
    assert_eq!(
        cadena.mejor_punta(),
        Some(punta_honesta),
        "la rama que excluye el punto de finalidad no puede ser elegida"
    );
    let violaciones = cadena.violaciones_finalidad();
    assert!(
        !violaciones.is_empty(),
        "debe registrarse al menos una violación de finalidad"
    );
    assert!(
        violaciones
            .iter()
            .any(|v| v.bloque == punta_rival && v.finalidad == pf),
        "la violación debe señalar el punto de finalidad y la punta rival: {violaciones:?}"
    );
    let cadena_virtual = cadena.cadena_virtual();
    assert!(
        !ids_rival
            .iter()
            .any(|id| cadena_virtual.contains(&hash_u32(*id))),
        "la cadena seleccionada no debe contener la rama que excluye el punto"
    );
}

#[test]
fn rama_que_contiene_el_punto_es_aceptada() {
    let f = 4u64;
    // Base honesta de 6 slots (sr=10, ids 10..15): el punto de finalidad queda en el slot 2 (id 11).
    let (mut cadena, _punta_honesta) = cadena_con_base(Some(f), 6, 10);
    let pf = cadena
        .punto_finalidad()
        .expect("debe haber punto de finalidad");
    assert_eq!(slot_de(&cadena, pf), 2);

    // Rival más pesada (sr=1) que bifurca del bloque honesto del slot 3 (id 12); su cadena contiene
    // el punto de finalidad (slot 2) y la reorganización (6 − 3 = 3 < F = 4) es admisible.
    let (punta_rival, ids_rival) = rama(&mut cadena, 10, 2_000, hash_u32(12), 4, 1);
    assert!(cadena.es_valido(&punta_rival));
    assert!(
        ids_rival.iter().all(|id| cadena.es_valido(&hash_u32(*id))),
        "toda la rival debe ser válida"
    );
    assert_eq!(
        cadena.mejor_punta(),
        Some(punta_rival),
        "una reorg que contiene el punto de finalidad (≤ F) sí debe sustituir"
    );
    assert!(
        cadena.violaciones_finalidad().is_empty(),
        "no debe haber violación cuando la rama contiene el punto"
    );
}

#[test]
fn sin_f_tope_la_rival_vuelve_a_ganar() {
    // Sin cota (`f_slots = None`) no hay punto de finalidad: la rival pesada gana como antes.
    let (mut cadena, _punta_honesta) = cadena_con_base(None, 10, 10);
    assert_eq!(cadena.punto_finalidad(), None);
    let (punta_rival, _) = rama(&mut cadena, 12, 3_000, hash_u32(1), 1, 1);
    assert_eq!(
        cadena.mejor_punta(),
        Some(punta_rival),
        "sin F no hay cota de profundidad"
    );
    assert!(cadena.violaciones_finalidad().is_empty());
}
