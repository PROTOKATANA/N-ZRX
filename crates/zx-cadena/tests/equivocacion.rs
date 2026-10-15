//! E-8 «equivocación» (`P-ZRX/P-MEDICION/ESCENARIOS-0.0.1.md` §3): la misma clave firma dos
//! bloques PoST del mismo slot. `C-EVP` está inactivo en 0.0.1 (declarado en el propio escenario):
//! no hay castigo. Lo que este test comprueba es exactamente lo que E-8 pide **registrar**: los dos
//! bloques se admiten (nada los rechaza por ser una repetición de slot/productor — `Cadena` no
//! implementa, ni la orden lo pide, un detector de doble firma), y GHOSTDAG los distingue como dos
//! puntas distintas del mismo padre (el color relativo de un mergeset repetido, blue/red, ya lo
//! prueba `zx-dag/tests/ghostdag_rust.rs::u2_invalida_y_u3_colorea`, a nivel del motor GHOSTDAG;
//! este archivo se queda en el nivel de `Cadena`, que es lo que la orden `W06d3` puede demostrar
//! sin depender de claves de productor reales ni del motor de recompensas completo — ver
//! `INFORME.md`, "no demostrado").

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

fn cadena_con_terminal() -> Cadena {
    let mut c = Cadena::nueva(params(), 1, CBID_RED_DEV, 15);
    c.admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: hash(0) },
        Vec::new(),
    )))
    .unwrap();
    c.admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
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
    c
}

/// **E-8.** La misma identidad (misma clave, mismo slot, mismo billete real de `C-GD-07`) firma dos
/// bloques distintos, ambos hijos directos del terminal. `Cadena::admitir` no tiene ningún cheque
/// de "esta identidad ya produjo este slot en otra rama": los admite los dos.
#[test]
fn la_misma_identidad_firma_dos_bloques_del_mismo_slot_y_los_dos_se_admiten() {
    let mut c = cadena_con_terminal();
    let terminal = hash(1);
    let prod = productor(42);
    let slot = 5u64;
    // La misma tupla real de C-GD-07 (clave, sector, history_size, chunk, slot): una equivocación
    // de verdad, no dos productores distintos que coinciden en slot por casualidad.
    let identidad =
        IdentidadGhostdag::Billete(IdentidadTicket::vigente(prod, 3, 1 << 20, [42; 32], slot));

    let bloque_a = BloqueCadena::Post(BloquePost {
        hash: hash(50),
        padres: vec![terminal],
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
    });
    let bloque_b = BloqueCadena::Post(BloquePost {
        hash: hash(51),
        padres: vec![terminal],
        slot,
        timestamp: 0,
        productor: prod,
        peso: 5,
        prueba_valida: true,
        requisito_declarado: 0,
        sr: 1,
        distancia: 0,
        identidad, // misma identidad real: la equivocación.
        txs: vec![(tx_coinbase_post(prod, 3, slot), Vec::new())],
    });

    // «Se registra qué ocurre» (E-8): ninguno de los dos se rechaza por repetir slot/productor —
    // `C-EVP` inactivo, tal como declara el propio escenario. Esto es el hallazgo, no un defecto de
    // este test: no hay una regla en `Cadena` que lo impida (ORDEN-W06d3 no pide añadirla).
    assert!(
        c.admitir(bloque_a.clone()).is_ok(),
        "el primer bloque de la equivocación se admite"
    );
    assert!(
        c.admitir(bloque_b.clone()).is_ok(),
        "el segundo bloque de la misma identidad y slot TAMBIÉN se admite: no hay castigo (C-EVP \
         inactivo en 0.0.1)"
    );

    // Ambos quedan como puntas válidas y distintas: «ambos bloques» de E-8.
    let tips = c.tips_validas();
    assert!(tips.contains(&bloque_a.hash()));
    assert!(tips.contains(&bloque_b.hash()));
    assert_eq!(
        tips.len(),
        2,
        "las dos caras de la equivocación coexisten como puntas independientes"
    );

    // El color relativo de dos bloques con la misma identidad en el mismo mergeset (uno blue, uno
    // red_U2 o red_U3 según la regla de GHOSTDAG) ya está probado en
    // `padres_e_identidad.rs::identidades_reales_distintas_no_colapsan_en_ocho_bytes` y
    // `u2_invalida_y_u3_colorea` (mismo repositorio, no duplicado aquí): «su color» de E-8 depende
    // de cuál mergeset los junta, no de esta prueba a nivel de dos puntas independientes.
}
