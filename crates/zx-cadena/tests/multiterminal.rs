//! `ORDEN-W06d7` — FC-3 de verdad con varios terminales candidatos, cada uno con su propio DAG.
//!
//! Cubre el plan de verificación §5:
//!
//! - **V1**: I-3 por propiedades — historias con 2 o 3 terminales, sufijos PoST de tamaños
//!   distintos (incluido un empate exacto de `blue_work`), en ≥ 200 órdenes aleatorios por
//!   escenario (semilla fija): mismo terminal, misma punta, mismo estado virtual en todos.
//! - **V2**: casos dirigidos — sufijo PoST más pesado en el terminal con menos trabajo PoW; bloque
//!   con padres de dos terminales (`ErrTerminalAmbiguo`); cambio de terminal bloqueado por
//!   `C-FIN-01`; noveno terminal ignorado (`MAX_TERMINALES_CON_DAG`); reinicio que repite el
//!   registro y acaba con la misma selección.
//!
//! **Tabla de cobertura** (`ORDEN-W06d7.md` §5): 0 terminales con sufijo — cubierto por
//! `crates/zx-cadena/tests/*` existentes (fase PoW pura, sin tocar en esta orden); 1 terminal — los
//! diferenciales T01/T04 y `contexto_dag.rs`; 2 terminales — `dos_terminales_pequeno` (V1) y
//! `directed_terminal_ligero_gana_por_post` (V2); 3 terminales — `tres_terminales_tamanos_distintos`
//! (V1); empate exacto de `blue_work` — `empate_exacto_blue_work` (V1); bloqueo por `C-FIN-01` —
//! `directed_c_fin_01_bloquea_el_cambio` (V2); tope — `directed_noveno_terminal_ignorado` (V2);
//! mezcla de terminales (padres de dos terminales) — `directed_padres_de_terminales_distintos` (V2).

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use std::collections::BTreeSet;

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

/// `q = S_min = 0`; `f_slots` se fija por test (`None` salvo el de `C-FIN-01`).
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

fn hash(n: u16) -> BlockHash {
    // 2 bytes de variedad bastan para los tamaños de esta prueba; el resto a cero mantiene el
    // orden lexicográfico == orden numérico de `n`, que varios tests usan para predecir el
    // desempate por "menor hash".
    let mut bytes = [0u8; 32];
    bytes[30] = (n >> 8) as u8;
    bytes[31] = (n & 0xff) as u8;
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn clave(semilla: u8) -> ClavePublica {
    let mensaje = [b"zx-w06d7-multiterminal", &[semilla][..]].concat();
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

/// Bloque PoW hijo directo del génesis con el `trabajo` e `id` dados (candidato a terminal si
/// `trabajo >= 1`, con `H_corte_min = 1`).
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

/// Un bloque PoST de un terminal, con `sr` (que fija su `blue_work`, `w(sr) = 2^128/(sr+1)`) y
/// productor/identidad únicos por bloque para no chocar con U2.
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

/// Construye una cadena de `n` bloques PoST de un terminal (única identidad y productor por
/// bloque), todos con el mismo `sr` (mismo peso por bloque), devolviendo los bloques en orden de
/// construcción (válido para admitir secuencialmente) y el hash de la punta.
#[allow(clippy::too_many_arguments)]
fn suceso_suffix(
    terminal: BlockHash,
    n: usize,
    sr: u64,
    id_base: u16,
    productor_semilla: u8,
) -> (Vec<BloqueCadena>, BlockHash) {
    let mut bloques = Vec::new();
    let mut padre = terminal;
    let mut punta = terminal;
    for i in 0..n {
        let id = id_base + i as u16;
        let slot = i as u64 + 1;
        let b = post(id, vec![padre], slot, sr, productor_semilla, i as u8);
        punta = b.hash();
        bloques.push(b);
        padre = punta;
    }
    (bloques, punta)
}

/// xorshift64* determinista (sin dependencias nuevas): basta para elegir órdenes de llegada
/// distintos con semilla fija, no para criptografía.
struct Xorshift64(u64);
impl Xorshift64 {
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn indice(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.siguiente() as usize) % n
        }
    }
}

/// Orden topológico aleatorio de `bloques` (Kahn con elección aleatoria por `rng`).
fn orden_topologico_aleatorio(bloques: &[BloqueCadena], rng: &mut Xorshift64) -> Vec<usize> {
    let n = bloques.len();
    let mut pos_de = std::collections::BTreeMap::new();
    for (i, b) in bloques.iter().enumerate() {
        pos_de.insert(b.hash(), i);
    }
    let mut padres: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut hijos: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, b) in bloques.iter().enumerate() {
        let ps: Vec<usize> = b
            .padres()
            .iter()
            .filter_map(|p| pos_de.get(p).copied())
            .collect();
        for p in &ps {
            if let Some(h) = hijos.get_mut(*p) {
                h.push(i);
            }
        }
        padres.push(ps);
    }
    let mut listos: Vec<usize> = (0..n)
        .filter(|i| padres.get(*i).is_some_and(Vec::is_empty))
        .collect();
    let mut orden = Vec::with_capacity(n);
    while !listos.is_empty() {
        let j = rng.indice(listos.len());
        let i = listos.swap_remove(j);
        orden.push(i);
        let mut nuevos = Vec::new();
        if let Some(hs) = hijos.get(i) {
            for h in hs {
                if padres
                    .get(*h)
                    .is_some_and(|ps| ps.iter().all(|p| orden.contains(p)))
                {
                    nuevos.push(*h);
                }
            }
        }
        listos.extend(nuevos);
    }
    orden
}

/// Resultado observable de una `Cadena` tras admitir un conjunto de bloques (lo que V1 exige que
/// coincida en todos los órdenes): terminal, punta y estado virtual.
#[derive(Debug, PartialEq)]
struct Resultado {
    terminal: Option<BlockHash>,
    punta: Option<BlockHash>,
    virtual_estado: zx_consensus::transicion::Estado,
}

fn resultado_de(cadena: &Cadena) -> Resultado {
    Resultado {
        terminal: cadena.terminal(),
        punta: cadena.mejor_punta(),
        virtual_estado: cadena.estado_virtual().unwrap(),
    }
}

/// Ejecuta un escenario (`bloques`, en un orden ya válido para construirlo) en 200 órdenes de
/// llegada aleatorios (semilla fija `0xC0FF_EE00 + variante`) y comprueba que los tres observables
/// de V1 coinciden en todos. Devuelve el resultado canónico para que el llamante añada sus propias
/// aserciones (qué terminal exacto se esperaba, etc.).
fn verificar_i3_multiterminal(bloques: &[BloqueCadena], variante: u64) -> Resultado {
    let mut canonica = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
    for b in bloques {
        canonica.admitir(b.clone()).unwrap();
    }
    let esperado = resultado_de(&canonica);

    let mut rng = Xorshift64(0xC0FF_EE00 ^ (variante << 1 | 1));
    for _ in 0..200 {
        let orden = orden_topologico_aleatorio(bloques, &mut rng);
        let mut c = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
        c.resolver(bloques, &orden).unwrap();
        let obtenido = resultado_de(&c);
        assert_eq!(
            obtenido, esperado,
            "I-3 roto: mismo conjunto, orden distinto, resultado distinto (variante {variante})"
        );
    }
    esperado
}

/// V1, caso «2 terminales»: `TA` (trabajo 1) con sufijo de 5 bloques ligeros (`sr` grande, peso
/// pequeño); `TB` (trabajo 1) con sufijo de 2 bloques pesados (`sr` pequeño, peso grande) que gana
/// por `blue_work` a pesar de tener menos bloques.
#[test]
fn dos_terminales_pequeno() {
    let ta = hash(1);
    let tb = hash(2);
    let mut bloques = vec![genesis(), pow_terminal(1, 1), pow_terminal(2, 1)];
    let (suf_a, _) = suceso_suffix(ta, 5, 5_000, 10, 1);
    let (suf_b, punta_b) = suceso_suffix(tb, 2, 10, 20, 2);
    bloques.extend(suf_a);
    bloques.extend(suf_b);

    let resultado = verificar_i3_multiterminal(&bloques, 1);
    assert_eq!(
        resultado.terminal,
        Some(tb),
        "gana el mayor blue_work, no el mayor recuento"
    );
    assert_eq!(resultado.punta, Some(punta_b));
}

/// V1, caso «3 terminales», sufijos de tamaños 1, 3 y 6, pesos claramente distintos: mismo
/// terminal/punta/estado en 200 órdenes.
#[test]
fn tres_terminales_tamanos_distintos() {
    let t1 = hash(1);
    let t2 = hash(2);
    let t3 = hash(3);
    let mut bloques = vec![
        genesis(),
        pow_terminal(1, 1),
        pow_terminal(2, 1),
        pow_terminal(3, 1),
    ];
    let (s1, _) = suceso_suffix(t1, 1, 1_000_000, 10, 1);
    let (s2, _) = suceso_suffix(t2, 3, 500, 20, 2);
    let (s3, punta3) = suceso_suffix(t3, 6, 50, 30, 3);
    bloques.extend(s1);
    bloques.extend(s2);
    bloques.extend(s3);

    let resultado = verificar_i3_multiterminal(&bloques, 2);
    assert_eq!(resultado.terminal, Some(t3));
    assert_eq!(resultado.punta, Some(punta3));
}

/// V1, «empate exacto de `blue_work`»: `w(sr) = ⌊2^128/(sr+1)⌋`. `TA` con **2** bloques `sr = 1`
/// (peso `2 · 2^127 = 2^128`) empata exactamente con `TB` con **1** bloque `sr = 0` (peso `2^128`).
/// `TA = hash(1) < hash(2) = TB`: el desempate de `comparar_terminal` (menor hash) debe elegir `TA`
/// en los 200 órdenes, de forma determinista.
#[test]
fn empate_exacto_blue_work() {
    let ta = hash(1);
    let tb = hash(2);
    let peso_2_128 = U256::one() << 128u32;
    // Confirmación de la aritmética del propio test (no de `zx-dag`): ambos suman exactamente
    // `2^128`, con la misma fórmula que usa `zx_dag::ghostdag::peso`.
    let peso_ta = zx_dag::ghostdag::peso(1) + zx_dag::ghostdag::peso(1);
    let peso_tb = zx_dag::ghostdag::peso(0);
    assert_eq!(
        peso_ta, peso_tb,
        "el test no está construyendo el empate que dice construir"
    );
    assert_eq!(peso_ta, peso_2_128);

    let mut bloques = vec![genesis(), pow_terminal(1, 1), pow_terminal(2, 1)];
    let (suf_a, punta_a) = suceso_suffix(ta, 2, 1, 10, 1);
    let (suf_b, _) = suceso_suffix(tb, 1, 0, 20, 2);
    bloques.extend(suf_a);
    bloques.extend(suf_b);

    let resultado = verificar_i3_multiterminal(&bloques, 3);
    assert_eq!(
        resultado.terminal,
        Some(ta),
        "empate exacto: gana el menor hash de terminal"
    );
    assert_eq!(resultado.punta, Some(punta_a));
}

/// V2: sufijo PoST más pesado en el terminal con **menos** trabajo PoW: `TA` (trabajo 1, sufijo
/// pesado) debe ganar a `TB` (trabajo 1000, sin sufijo hasta que ambos ya tienen DAG, sufijo
/// ligero).
#[test]
fn directed_terminal_ligero_gana_por_post() {
    let ta = hash(1);
    let tb = hash(2);
    let mut cadena = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    cadena.admitir(pow_terminal(2, 1_000)).unwrap();
    // Sin sufijo todavía: gana el trabajo PoW (TB).
    assert_eq!(cadena.terminal(), Some(tb));

    let (suf_a, _punta_a) = suceso_suffix(ta, 4, 1, 10, 1);
    for b in suf_a {
        cadena.admitir(b).unwrap();
    }
    // TA ya tiene sufijo pesado; TB ninguno todavía: FC-3 exige sufijo para competir.
    assert_eq!(cadena.terminal(), Some(ta));

    let (suf_b, _) = suceso_suffix(tb, 1, 1_000_000, 20, 2);
    for b in suf_b {
        cadena.admitir(b).unwrap();
    }
    // Ambos con sufijo: gana el de mayor blue_work (TA), pese a que TB tiene 1000x más trabajo PoW.
    assert_eq!(
        cadena.terminal(),
        Some(ta),
        "el trabajo PoW ya no decide tras el corte (TRN-09)"
    );
}

/// V2: un bloque PoST cuyos padres resuelven a dos terminales distintos es inválido (`I-4`).
#[test]
fn directed_padres_de_terminales_distintos_es_invalido() {
    let ta = hash(1);
    let tb = hash(2);
    let mut cadena = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    cadena.admitir(pow_terminal(2, 1)).unwrap();
    let (suf_a, punta_a) = suceso_suffix(ta, 1, 10, 10, 1);
    let (suf_b, punta_b) = suceso_suffix(tb, 1, 10, 20, 2);
    for b in suf_a {
        cadena.admitir(b).unwrap();
    }
    for b in suf_b {
        cadena.admitir(b).unwrap();
    }

    let mezcla = post(99, vec![punta_a, punta_b], 5, 10, 9, 9);
    let err = cadena.admitir(mezcla).unwrap_err();
    assert_eq!(err, MotivoBloque::ErrTerminalAmbiguo);
}

/// V2: `C-FIN-01` entre terminales — un nodo en línea no cambia de terminal si su sufijo actual ya
/// abarca `>= F_slots`. Con `F_slots = 3`: un sufijo de 5 slots (`d = 5 >= 3`) bloquea el cambio a
/// un terminal más pesado que llega después; el mismo terminal más pesado, si el sufijo local solo
/// tiene 2 slots (`d = 2 < 3`), sí se adopta.
#[test]
fn directed_c_fin_01_bloquea_el_cambio() {
    let ta = hash(1);
    let tb = hash(2);

    // Caso bloqueado: sufijo de TA ya profundo (5 slots) antes de que aparezca TB, más pesado.
    let mut bloqueado = Cadena::nueva(params(Some(3)), 1, CBID_RED_DEV, MAX_PADRES);
    bloqueado.admitir(genesis()).unwrap();
    bloqueado.admitir(pow_terminal(1, 1)).unwrap();
    let (suf_a, _) = suceso_suffix(ta, 5, 10, 10, 1);
    for b in suf_a {
        bloqueado.admitir(b).unwrap();
    }
    assert_eq!(bloqueado.terminal(), Some(ta));
    bloqueado.admitir(pow_terminal(2, 1)).unwrap();
    let (suf_b, _) = suceso_suffix(tb, 1, 1, 20, 2); // mucho más pesado por bloque (sr=1 vs sr=10)
    for b in suf_b {
        bloqueado.admitir(b).unwrap();
    }
    assert_eq!(
        bloqueado.terminal(),
        Some(ta),
        "C-FIN-01 debe impedir el cambio: el sufijo actual ya abarca >= F_slots"
    );

    // Caso permitido: mismo TB más pesado, pero el sufijo local de TA solo tiene 2 slots (d < F_slots).
    let mut permitido = Cadena::nueva(params(Some(3)), 1, CBID_RED_DEV, MAX_PADRES);
    permitido.admitir(genesis()).unwrap();
    permitido.admitir(pow_terminal(1, 1)).unwrap();
    let (suf_a2, _) = suceso_suffix(ta, 2, 10, 10, 1);
    for b in suf_a2 {
        permitido.admitir(b).unwrap();
    }
    assert_eq!(permitido.terminal(), Some(ta));
    permitido.admitir(pow_terminal(2, 1)).unwrap();
    let (suf_b2, _) = suceso_suffix(tb, 1, 1, 20, 2);
    for b in suf_b2 {
        permitido.admitir(b).unwrap();
    }
    assert_eq!(
        permitido.terminal(),
        Some(tb),
        "con d < F_slots, FC-3 sí debe poder sustituir el terminal"
    );
}

/// V2: tope `MAX_TERMINALES_CON_DAG` — un noveno candidato con sufijo se ignora si su trabajo PoW
/// no supera al peor de los ocho ya admitidos.
#[test]
fn directed_noveno_terminal_ignorado() {
    let mut cadena = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    assert_eq!(MAX_TERMINALES_CON_DAG, 8);

    for i in 1..=8u16 {
        cadena.admitir(pow_terminal(i, u64::from(i) * 10)).unwrap();
        let (suf, _) = suceso_suffix(hash(i), 1, 10, 100 + i * 10, i as u8);
        for b in suf {
            cadena.admitir(b).unwrap();
        }
    }
    assert_eq!(cadena.terminales_con_dag().len(), 8);
    assert!(!cadena.limite_terminales_alcanzado());

    // Noveno candidato, con menos trabajo PoW que cualquiera de los 8 (mínimo actual: 10).
    let t9 = hash(9);
    cadena.admitir(pow_terminal(9, 1)).unwrap();
    let (suf9, _) = suceso_suffix(t9, 1, 10, 900, 9);
    let mut ultimo = Ok(());
    for b in suf9 {
        ultimo = cadena.admitir(b);
    }
    assert_eq!(ultimo, Err(MotivoBloque::ErrLimiteTerminales));
    assert!(cadena.limite_terminales_alcanzado());
    assert_eq!(
        cadena.terminales_con_dag().len(),
        8,
        "el noveno no desaloja: pesaba menos"
    );
    assert!(!cadena.terminales_con_dag().contains(&t9));
}

/// V2: el reinicio repite el registro (mismo orden en el que se admitieron los bloques la primera
/// vez) y acaba con la misma selección — réplica, a nivel de `zx-cadena`, de lo que `Nodo::reiniciar`
/// hace admitiendo uno a uno en el orden del almacén (D-N03′).
#[test]
fn directed_reinicio_repite_misma_seleccion() {
    let t1 = hash(1);
    let t2 = hash(2);
    let t3 = hash(3);
    let mut registro: Vec<BloqueCadena> = vec![genesis(), pow_terminal(1, 5), pow_terminal(2, 1)];
    let (s1, _) = suceso_suffix(t1, 2, 100, 10, 1);
    let (s2, _) = suceso_suffix(t2, 3, 40, 20, 2);
    registro.extend(s1);
    registro.extend(s2);
    registro.push(pow_terminal(3, 2));
    let (s3, punta3) = suceso_suffix(t3, 5, 20, 30, 3);
    registro.extend(s3);

    let mut original = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
    for b in &registro {
        original.admitir(b.clone()).unwrap();
    }
    let esperado = resultado_de(&original);
    assert_eq!(esperado.terminal, Some(t3));
    assert_eq!(esperado.punta, Some(punta3));

    // "Reinicio": una `Cadena` nueva, admitiendo el mismo registro en el mismo orden.
    let mut reiniciada = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
    for b in &registro {
        reiniciada.admitir(b.clone()).unwrap();
    }
    assert_eq!(resultado_de(&reiniciada), esperado);
}

/// V2 (cobertura auxiliar): 0/1 terminal con sufijo también pasan por la ruta nueva sin romperse
/// (regresión mínima, ya cubierta a fondo por los diferenciales T01/T04 y `contexto_dag.rs`).
#[test]
fn cero_y_un_terminal_no_se_rompen() {
    let mut cadena = Cadena::nueva(params(None), 1, CBID_RED_DEV, MAX_PADRES);
    cadena.admitir(genesis()).unwrap();
    assert_eq!(cadena.terminal(), None);
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    assert_eq!(cadena.terminal(), Some(hash(1)));
    assert!(cadena.terminales_con_dag().is_empty());
    let (suf, punta) = suceso_suffix(hash(1), 3, 10, 10, 1);
    for b in suf {
        cadena.admitir(b).unwrap();
    }
    assert_eq!(cadena.terminal(), Some(hash(1)));
    assert_eq!(cadena.mejor_punta(), Some(punta));
    assert_eq!(cadena.terminales_con_dag(), vec![hash(1)]);
}

/// Referencia cruzada de tipos no usados directamente arriba (evita `unused_imports` si el
/// refactor de arriba cambia): `BTreeSet` se usa aquí para comprobar unicidad de hashes generados.
#[test]
fn ids_de_bloques_son_unicos_en_este_arnes() {
    let ids: BTreeSet<BlockHash> = (0..40).map(hash).collect();
    assert_eq!(ids.len(), 40);
}
