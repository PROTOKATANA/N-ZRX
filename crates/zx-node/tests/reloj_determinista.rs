//! `RL-2c` · V1: el calendario `N(s)` es función **determinista** de la cadena seleccionada.
//!
//! Construye un DAG PoST con una rama principal y una rama rival más profunda (reorganización que
//! cruza fronteras de epoch) y lo admite en 200 órdenes de llegada topológicos aleatorios. En todos
//! ellos el calendario calculado desde `Cadena::cadena_seleccionada_post` debe ser **idéntico**: el
//! `T` y el `N(s)` no pueden depender del orden en que se vieron los bloques.
//!
//! Con el código de hoy (RL-2b) esta prueba **no compila**: `cadena_seleccionada_post` y
//! `calendario_desde_cadena` no existen, y el ajuste de `T` salía del pasado admitido localmente
//! (`ServicioPot::ventana_timestamps`), sensible al orden.

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
#![expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
#![expect(clippy::panic, reason = "un fallo de admisión es un panic del test")]
#![expect(
    clippy::indexing_slicing,
    reason = "el test indexa vectores ya comprobados no vacíos"
)]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;
use zx_node::perfil::perfil_red_dev_reloj;
use zx_post::reloj_post::{ParametrosRelojPost, calendario_desde_cadena};

const MAX_PADRES: u8 = 15;
const K: u32 = 10;
/// Frontera de epoch **local del test**: `RL-2d` subió el `A_epoch` real de dev a `600` (invariante
/// `A ≥ F`), así que la historia pequeña de este arnés fija su propio `A = 8`.
const A_EPOCH: u64 = 8;

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).unwrap()
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).unwrap()
}

/// Parámetros de DAG pequeños (sin `C-FIN-01` ni profundidad de fusión), como el arnés de T04.
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

/// Especificación de la historia: `(id, padres en ids, slot, timestamp, sr)`.
type Spec = (u32, Vec<u32>, u64, u64, u64);

/// Historia fija: rama principal (slots 1..=12, `sr=10`, `tau≈2`) y rama rival (desde el bloque 6,
/// slots 7..=18, `sr=1`, `tau≈1`) que gana por trabajo. La reorganización cruza las fronteras de
/// epoch 8 y 16.
fn historia() -> Vec<Spec> {
    let mut specs: Vec<Spec> = Vec::new();
    // Rama principal: ids 10..=21, slots 1..=12, padre encadenado. Timestamps lentos (`tau≈4`) para
    // que la ventana de la primera frontera mida un `tau_est ≠ tau_ref` y ajuste `T`.
    let mut padre = 1u32; // terminal
    for i in 0..12u32 {
        let id = 10 + i;
        let slot = u64::from(i) + 1;
        specs.push((id, vec![padre], slot, 1_000 + 4 * slot, 10));
        padre = id;
    }
    // Rama rival: ids 100..=111, arranca en el bloque de slot 6 (id 15), slots 7..=18, tau≈1.
    let mut padre_rival = 15u32;
    for i in 0..12u32 {
        let id = 100 + i;
        let slot = 7 + u64::from(i);
        specs.push((id, vec![padre_rival], slot, 1_000 + slot, 1));
        padre_rival = id;
    }
    specs
}

fn construir(orden: &[u32], specs: &[Spec]) -> Cadena {
    let mut cadena = Cadena::nueva(params(), K, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal()).unwrap();
    for id in orden {
        let spec = specs
            .iter()
            .find(|(sid, ..)| sid == id)
            .unwrap_or_else(|| panic!("id {id} sin spec"));
        let (_, padres, slot, timestamp, sr) = spec;
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

/// Generador de órdenes topológicos aleatorios con un xorshift determinista (sin dependencia de
/// `rand`): misma semilla, mismos 200 órdenes, reproducible.
struct Xorshift(u64);
impl Xorshift {
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn indice(&mut self, n: usize) -> usize {
        (self.siguiente() % n as u64) as usize
    }
}

/// Un orden topológico aleatorio: elige al azar entre los bloques cuyos padres ya están admitidos.
fn orden_aleatorio(rng: &mut Xorshift, specs: &[Spec]) -> Vec<u32> {
    let mut pendientes: Vec<&Spec> = specs.iter().collect();
    let mut admitidos: Vec<u32> = vec![0, 1];
    let mut orden = Vec::with_capacity(specs.len());
    while !pendientes.is_empty() {
        let listos: Vec<usize> = pendientes
            .iter()
            .enumerate()
            .filter(|(_, (_, padres, ..))| padres.iter().all(|p| admitidos.contains(p)))
            .map(|(i, _)| i)
            .collect();
        assert!(
            !listos.is_empty(),
            "historia no topológica o especificación incoherente"
        );
        let elegido = listos[rng.indice(listos.len())];
        let spec = pendientes.remove(elegido);
        admitidos.push(spec.0);
        orden.push(spec.0);
    }
    orden
}

/// Calendario calculado desde la cadena seleccionada del terminal.
fn calendario(cadena: &Cadena) -> Vec<(u64, u64)> {
    let terminal = cadena.terminal().expect("terminal seleccionado");
    let bloques = cadena.cadena_seleccionada_post(terminal);
    assert!(
        bloques.len() >= 2 * A_EPOCH as usize,
        "la historia debe cruzar al menos dos fronteras de epoch (hay {} bloques)",
        bloques.len()
    );
    let perfil = perfil_red_dev_reloj().expect("perfil dev-reloj válido");
    let reloj = ParametrosRelojPost {
        a_epoch: A_EPOCH,
        ..perfil.reloj
    };
    let (cal, _) = calendario_desde_cadena(&reloj, &bloques).expect("calendario válido");
    cal
}

#[test]
fn dos_nodos_con_ordenes_distintos_calculan_el_mismo_calendario() {
    let specs = historia();
    let mut rng = Xorshift(0x5a5a_1234_9e37_79b9);
    let referencia = {
        let orden = orden_aleatorio(&mut rng, &specs);
        calendario(&construir(&orden, &specs))
    };
    // La rama rival gana: la cadena seleccionada es la rival, no la principal.
    let cadena_rival = construir(&orden_aleatorio(&mut Xorshift(7), &specs), &specs);
    let terminal = cadena_rival.terminal().unwrap();
    let seleccion = cadena_rival.cadena_seleccionada_post(terminal);
    assert!(
        seleccion.iter().any(|(slot, _)| *slot >= 17),
        "la rama rival (slots hasta 18) debe ser la cadena seleccionada; selección: {seleccion:?}"
    );

    for repeticion in 0..200 {
        let orden = orden_aleatorio(&mut rng, &specs);
        let cal = calendario(&construir(&orden, &specs));
        assert_eq!(
            cal, referencia,
            "repetición {repeticion}: el calendario N(s) depende del orden de llegada"
        );
    }
}

#[test]
fn el_calendario_cambia_de_verdad_en_la_historia_de_prueba() {
    // No basta con que sea constante: la historia debe producir al menos un ajuste de `T`. Se
    // comprueba que el calendario tiene más de una entrada (una por frontera ajustada).
    let specs = historia();
    let orden = orden_aleatorio(&mut Xorshift(1), &specs);
    let cadena = construir(&orden, &specs);
    let cal = calendario(&cadena);
    assert!(
        cal.len() > 1,
        "el calendario debe tener entradas de ajuste, no solo (0, N0): {cal:?}"
    );
    // Y que el `N` de al menos una entrada difiere del inicial.
    let n0 = cal.first().map(|(_, n)| *n).unwrap_or(0);
    assert!(
        cal.iter().any(|(_, n)| *n != n0),
        "ninguna frontera ajustó N: {cal:?}"
    );
}
