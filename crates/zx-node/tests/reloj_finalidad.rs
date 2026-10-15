//! `RL-2d` · **V1**: dos cadenas seleccionadas que difieren en los últimos `< F` slots (una
//! bifurcación viva en el momento de una frontera) calculan el **mismo** calendario `N(s)` si el
//! ajuste se toma de la parte **finalizada** de la cadena.
//!
//! El arnés construye una historia común hasta el slot 8 y dos ramas rivales con los slots 9..12
//! (mismo `slot` de punta, distinto contenido y ritmo de timestamps), cada una en su propia
//! `Cadena`. Con `F = 4`, el punto de finalidad de ambas es el bloque común del slot 8. Después:
//!
//! - el calendario calculado desde la **cadena completa** (`Cadena::cadena_seleccionada_post`,
//!   código de RL-2c) **difiere**: la frontera `f = 12` mira la ventana `(8, 12]`, que ya contiene
//!   bloques de la rama. Ese es el riesgo de partición que motiva RL-2d;
//! - el calendario calculado desde la **parte finalizada**
//!   (`Cadena::cadena_seleccionada_post_finalizada`, RL-2d) es **idéntico** en las dos ramas: la
//!   frontera 12 no se procesa porque el punto de finalidad (slot 8) no la alcanza, y el `N` se
//!   mantiene (decisión 3).
//!
//! Con la base `3ba8654` esta prueba **no compila**: `cadena_seleccionada_post_finalizada` no
//! existe.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;
use zx_post::reloj_post::{PERFIL_RELOJ_DEV, ParametrosRelojPost, calendario_desde_cadena};

const MAX_PADRES: u8 = 15;
const K: u32 = 10;
/// Profundidad de finalidad del arnés: la divergencia de las ramas es de 4 slots, `< F`.
const F_SLOTS_TEST: u64 = 4;
/// `A_epoch` del arnés: cumple `A ≥ F` y es lo bastante pequeño para que la frontera 12 exista.
const A_EPOCH_TEST: u64 = 4;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// Parámetros de DAG pequeños, con la **cota de finalidad activa** (`f_slots = Some(4)`).
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
        f_slots: Some(F_SLOTS_TEST),
        subsidio_pow,
        subsidio_post,
    }
}

fn hash_u32(n: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

/// Clave de relleno: el DAG no verifica firmas, solo bytes de identidad.
fn productor() -> ClavePublica {
    ClavePublica::desde_bytes([0x5c; 32])
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

fn pow_terminal() -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash_u32(1),
            padre: hash_u32(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        Vec::new(),
    ))
}

/// Bloque PoST con identidad única (`history_size = id + 1`) y `timestamp` explícito.
fn post(id: u32, padres: Vec<BlockHash>, slot: u64, timestamp: u64, sr: u64) -> BloqueCadena {
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
        timestamp,
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

/// Especificación de un bloque del arnés: `(id, padres en ids, slot, timestamp, sr)`.
type Spec = (u32, Vec<u32>, u64, u64, u64);

/// Prefijo común: ids 10..=17, slots 1..=8, `sr = 10`, timestamps lentos (`tau ≈ 4`).
fn comun() -> Vec<Spec> {
    let mut specs = Vec::new();
    let mut padre = 1u32; // terminal PoW
    for i in 0..8u32 {
        let id = 10 + i;
        let slot = u64::from(i) + 1;
        specs.push((id, vec![padre], slot, 1_000 + 4 * slot, 10));
        padre = id;
    }
    specs
}

/// Rama A: ids 20..=23, slots 9..=12, timestamps lentos (`tau ≈ 4`).
fn rama_a() -> Vec<Spec> {
    let mut specs = Vec::new();
    let mut padre = 17u32; // P8
    for i in 0..4u32 {
        let id = 20 + i;
        let slot = 9 + u64::from(i);
        specs.push((id, vec![padre], slot, 1_000 + 4 * slot, 10));
        padre = id;
    }
    specs
}

/// Rama B: ids 30..=33, slots 9..=12, timestamps rápidos (`tau ≈ 1`).
fn rama_b() -> Vec<Spec> {
    let mut specs = Vec::new();
    let mut padre = 17u32; // P8
    for i in 0..4u32 {
        let id = 30 + i;
        let slot = 9 + u64::from(i);
        specs.push((id, vec![padre], slot, 1_000 + slot, 1));
        padre = id;
    }
    specs
}

fn construir(specs: &[Spec]) -> Cadena {
    let mut cadena = Cadena::nueva(params(), K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal()).unwrap();
    for (id, padres, slot, timestamp, sr) in specs {
        let bloque = post(
            *id,
            padres.iter().map(|p| hash_u32(*p)).collect(),
            *slot,
            *timestamp,
            *sr,
        );
        cadena.admitir(bloque).unwrap();
    }
    cadena
}

/// Calendario `N(s)` con la cadena completa o solo con su parte finalizada.
fn calendario(cadena: &Cadena, terminal: BlockHash, finalizada: bool) -> Vec<(u64, u64)> {
    let bloques = if finalizada {
        cadena.cadena_seleccionada_post_finalizada(terminal)
    } else {
        cadena.cadena_seleccionada_post(terminal)
    };
    let reloj = ParametrosRelojPost {
        a_epoch: A_EPOCH_TEST,
        ..PERFIL_RELOJ_DEV
    };
    let (cal, _) = calendario_desde_cadena(&reloj, &bloques).expect("calendario válido");
    cal
}

#[test]
fn dos_ramas_en_competencia_calculan_el_mismo_calendario_finalizado() {
    let mut specs_a = comun();
    specs_a.extend(rama_a());
    let mut specs_b = comun();
    specs_b.extend(rama_b());
    let cadena_a = construir(&specs_a);
    let cadena_b = construir(&specs_b);

    let ta = cadena_a.terminal().expect("terminal de A");
    let tb = cadena_b.terminal().expect("terminal de B");

    // Mismo punto de finalidad: la divergencia (slots 9..12) es menor que `F = 4` y el punto es el
    // bloque común del slot 8. Las dos cadenas seleccionadas sí difieren.
    let pf_a = cadena_a.punto_finalidad().expect("punto de finalidad de A");
    let pf_b = cadena_b.punto_finalidad().expect("punto de finalidad de B");
    assert_eq!(
        pf_a, pf_b,
        "la bifurcación viva debe dejar el mismo punto de finalidad"
    );
    let seleccion_a = cadena_a.cadena_seleccionada_post(ta);
    let seleccion_b = cadena_b.cadena_seleccionada_post(tb);
    assert_ne!(
        seleccion_a, seleccion_b,
        "las dos ramas deben tener cadenas seleccionadas distintas"
    );

    // RL-2c: mirar la cadena completa hace que el calendario dependa de la rama (frontera 12).
    let full_a = calendario(&cadena_a, ta, false);
    let full_b = calendario(&cadena_b, tb, false);
    assert_ne!(
        full_a, full_b,
        "el calendario desde la cadena completa debe diferir (riesgo de RL-2c)"
    );

    // RL-2d: desde la parte finalizada el calendario es idéntico en las dos ramas.
    let fin_a = calendario(&cadena_a, ta, true);
    let fin_b = calendario(&cadena_b, tb, true);
    assert_eq!(
        fin_a, fin_b,
        "dos ramas con el mismo punto de finalidad deben calcular el mismo N(s)"
    );
    assert!(
        fin_a.len() > 1,
        "el calendario finalizado debe tener al menos una frontera ajustada: {fin_a:?}"
    );
    // El punto de finalidad está en el slot 8: se procesan las fronteras 4 y 8 (la última rige
    // desde `8 + A = 12`); la frontera viva 12 (que regiría desde 16) **no** se procesa. Con la
    // cadena completa sí aparece la entrada de la frontera 12.
    assert!(
        fin_a
            .iter()
            .all(|(desde, _)| *desde <= F_SLOTS_TEST * 2 + A_EPOCH_TEST),
        "el calendario finalizado no debe incluir la frontera viva: {fin_a:?}"
    );
    assert!(
        full_a
            .iter()
            .any(|(desde, _)| *desde == F_SLOTS_TEST * 3 + A_EPOCH_TEST),
        "el calendario completo sí procesa la frontera viva: {full_a:?}"
    );
}

/// Diagnóstico/regresión con la escala del humo: cadena lineal de ~600 bloques (uno cada 2 slots
/// hasta el 1210) con `F = 600`. Comprueba que el punto de finalidad avanza y que el calendario
/// finalizado sí procesa la frontera 601.
#[test]
fn cadena_larga_con_f600_finaliza_y_ajusta() {
    let mut specs: Vec<Spec> = Vec::new();
    let mut padre = 1u32;
    for (i, slot) in (2..=1_210u64).step_by(2).enumerate() {
        let id = 2_000u32 + i as u32;
        specs.push((id, vec![padre], slot, 1_000 + 4 * slot, 10));
        padre = id;
    }
    let params = ParametrosTransicion {
        f_slots: Some(600),
        ..params()
    };
    let mut cadena = Cadena::nueva(params, K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal()).unwrap();
    for (bid, padres, slot, ts, sr) in &specs {
        cadena
            .admitir(post(
                *bid,
                padres.iter().map(|p| hash_u32(*p)).collect(),
                *slot,
                *ts,
                *sr,
            ))
            .unwrap();
    }
    let terminal = cadena.terminal().unwrap();
    let pf = cadena
        .punto_finalidad()
        .expect("el punto de finalidad debe haber avanzado");
    let bloques = cadena.cadena_seleccionada_post_finalizada(terminal);
    assert!(!bloques.is_empty(), "lista finalizada vacía (pf={pf})");
    let max_slot = bloques.iter().map(|(s, _)| *s).max().unwrap_or(0);
    assert!(max_slot >= 600, "max_slot finalizado {max_slot} < 600");
    let reloj = ParametrosRelojPost {
        a_epoch: 601,
        ..PERFIL_RELOJ_DEV
    };
    let (cal, _) = calendario_desde_cadena(&reloj, &bloques).expect("calendario válido");
    assert!(cal.len() > 1, "sin ajuste en la frontera 601: {cal:?}");
}
