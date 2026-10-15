//! AT-1b2 · J6b, J8 y J14: el hecho de la falta «voto contra la propia atadura» sobre una
//! `zx_cadena::Cadena` real, con firmas BLS reales.
//!
//! Archivo nuevo de `crates/zx-node/tests/` (la orden prohíbe tocar archivos existentes de
//! `crates/zx-node`). La `Cadena` se construye con la API pública de `zx-cadena`; las firmas, con
//! `zx-votos`.
//!
//! El hecho de la evidencia se lee con el gancho `#[doc(hidden)]`
//! `Cadena::hecho_de_tx_de_prueba` (AT-1b2 · X4/J6b), que ejecuta **la misma** `hecho_de_tx` que la
//! admisión; el castigo end-to-end se comprueba por el `estado_resumen`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    reason = "prueba de escenarios con estados y bloques construidos a mano; falla con panic"
)]

use primitive_types::U256;
use zx_cadena::{BloqueCadena, BloquePost, Cadena};
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::HechoVoto;
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Garantia, HechosCabecera, ParametrosEvidencia, ParametrosTransicion,
};
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, OperacionAlmacenamiento,
    Tx, VotoPesoEvidencia,
};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;
use zx_node::estado_resumen::resumen_estado;
use zx_votos::{ClaveSecreta, DOMINIO_VOTO};

const MAX_PADRES: u8 = 15;
const K: u32 = 1;
const PLAZO: i64 = 300;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Fixtures locales (mismo patrón que `zx-cadena/src/cadena.rs` y `nodo::pruebas_at1a2_fixture`).
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn hash_u32(n: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

/// Par Ed25519 real que firma el testigo de la `Tx` v6 y queda registrado como clave acusada.
fn firmante_sk() -> ed25519_zebra::SigningKey {
    ed25519_zebra::SigningKey::from([7u8; 32])
}

fn firmante_pk() -> ClavePublica {
    ClavePublica::desde_bytes(ed25519_zebra::VerificationKey::from(&firmante_sk()).into())
}

fn productor() -> ClavePublica {
    ClavePublica::desde_bytes([0x5a; 32])
}

fn subsidio_pow(_h: u32) -> Amount {
    Amount::nuevo(10).expect("subsidio")
}
fn subsidio_post(_s: u64) -> Amount {
    Amount::nuevo(3).expect("subsidio")
}

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

fn tx_coinbase_post(clave: ClavePublica, importe: i64, slot: u64) -> Tx {
    Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave,
            importe: Amount::nuevo(importe).expect("importe"),
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

/// Bloque PoST con la coinbase y, opcionalmente, la evidencia `0x0B` (segunda transacción).
fn post_con_evidencia(
    id: u32,
    padres: Vec<BlockHash>,
    slot: u64,
    sr: u64,
    evidencia: Option<(Tx, Vec<Vec<u8>>)>,
) -> BloqueCadena {
    let productor = productor();
    let mut txs = vec![(tx_coinbase_post(productor, 1, slot), Vec::new())];
    if let Some((tx, testigos)) = evidencia {
        txs.push((tx, testigos));
    }
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
        txs,
    })
}

fn post(id: u32, padres: Vec<BlockHash>, slot: u64, sr: u64) -> BloqueCadena {
    post_con_evidencia(id, padres, slot, sr, None)
}

/// Voto de peso firmado sobre A3 con la clave `bls(1)` y raíz/`h_t` cero.
fn voto(n: u64, c: BlockHash) -> VotoPesoEvidencia {
    let sk = bls(1);
    let candidato = *c.as_bytes();
    let h_t = [0u8; 32];
    let raiz = [0u8; 32];
    let firma = zx_votos::firmar(
        &sk,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_t, &raiz),
    )
    .expect("firma BLS");
    VotoPesoEvidencia {
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: raiz,
        firma: firma.bytes(),
    }
}

/// Transacción `0x0B` con los dos votos firmados por `bls(1)`, acusando a `firmante_pk()` y con el
/// testigo Ed25519 de 64 B que exige la forma v6.
fn tx_evidencia(n1: u64, b1: BlockHash, n2: u64, b2: BlockHash) -> (Tx, Vec<Vec<u8>>) {
    let tx = Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: OperacionAlmacenamiento::EvidenciaVotosPeso {
                clave: firmante_pk(),
                clave_bls: bls(1).clave_publica().bytes(),
                voto1: voto(n1, b1),
                voto2: voto(n2, b2),
            },
        },
    };
    let firma: [u8; 64] = firmante_sk()
        .sign(&zx_core::mensaje_almacenamiento(&tx, CBID_RED_DEV))
        .into();
    (tx, vec![firma.to_vec()])
}

/// Estado con `firmante_pk()` registrada (clave BLS y 4 sectores activos) y garantía castigable.
fn estado_con_clave() -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.claves_voto.insert(
        firmante_pk(),
        ClaveVoto {
            clave_bls: bls(1).clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    for s in 0..4u16 {
        let id = SectorId {
            clave: firmante_pk(),
            sector_index: s,
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
                id,
                r2: [0u64; 4],
                history_size: 1,
                etapa: Etapa::Activo,
                alta_slot: 0,
                renovacion_slot: 1_000_000,
                retiro_slot: -1,
                fianza: p.q_sec,
                aud_apertura: -1,
                aud_contestada: -1,
            },
        );
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1_000_000).expect("garantia");
    est.garantias.insert(firmante_pk(), g);
    est
}

fn cadena_con(estado: Estado, f_slots: u64) -> Cadena {
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params(Some(f_slots)),
        K,
        CBID_RED_DEV,
        MAX_PADRES,
        ParametrosEvidencia::inactiva(),
        estado,
    );
    cadena.admitir(genesis()).expect("génesis");
    cadena.admitir(pow_terminal(1, 1)).expect("terminal PoW");
    cadena
}

/// Aplica el hecho de la evidencia en `x` con el `plazo_slots` de `PLAZO`.
fn hecho(cadena: &Cadena, terminal: BlockHash, x: BlockHash, tx: &Tx) -> HechoVoto {
    cadena
        .hecho_de_tx_de_prueba(terminal, x, tx, u64::try_from(PLAZO).expect("plazo"))
        .expect("x en el DAG")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// J6b · «aplicado antes» y bloques ajenos.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// DAG base: `t → A → {B1, B2}` y `x` (evidencia) con padres `{B1, B2}`; `A` cuelga de `t`.
struct Base {
    cadena: Cadena,
    terminal: BlockHash,
    b1: BlockHash,
    b2: BlockHash,
    x: BlockHash,
}

fn base_sin_evidencia() -> Base {
    let terminal = hash_u32(1);
    let mut cadena = cadena_con(estado_con_clave(), 600);
    let a = hash_u32(10);
    cadena.admitir(post(10, vec![terminal], 1, 10)).unwrap();
    cadena.admitir(post(11, vec![a], 2, 10)).unwrap();
    cadena.admitir(post(21, vec![a], 2, 10)).unwrap();
    Base {
        cadena,
        terminal,
        b1: hash_u32(11),
        b2: hash_u32(21),
        x: hash_u32(30),
    }
}

/// J6b · (1) `B₁` existe pero no está aplicado antes del bloque de la evidencia → `Inadmisible`.
/// (2) presentada después, en un bloque que sí lo tiene detrás → `Falta` (castigada).
/// (3) dos cadenas, una con un bloque ajeno de más, mismo `estado_resumen`.
/// (4) caso X2: `S₂` conocido fuera del pasado (`Inadmisible`) o desconocido (`Inadmisible`), mismo
/// `estado_resumen`.
#[test]
fn j6b_aplicado_antes_y_cadenas_ajenas() {
    let Base {
        mut cadena,
        terminal,
        b1,
        b2,
        x,
    } = base_sin_evidencia();
    let (ev, tst) = tx_evidencia(1, b1, 4, b2);

    // (1) Bloque temprano `z` cuyo único padre es `B₂`: `B₁` no está aplicado antes → inadmisible.
    let z = hash_u32(31);
    let mut cadena_temprana = base_sin_evidencia().cadena;
    cadena_temprana
        .admitir(post_con_evidencia(
            31,
            vec![b2],
            2,
            10,
            Some((ev.clone(), tst.clone())),
        ))
        .unwrap();
    assert_eq!(
        hecho(&cadena_temprana, terminal, z, &ev),
        HechoVoto::Inadmisible,
        "(1) B₁ sin aplicar antes"
    );
    assert!(
        cadena_temprana
            .descartes(&z)
            .is_some_and(|d| d.iter().any(|t| t.indice == 1)),
        "(1) la evidencia inadmisible se descarta sin invalidar el bloque"
    );

    // (2) El mismo bloque `x`, con `B₁` y `B₂` detrás, sí castiga.
    cadena
        .admitir(post_con_evidencia(
            30,
            vec![b1, b2],
            3,
            10,
            Some((ev.clone(), tst.clone())),
        ))
        .unwrap();
    let estado_x = cadena.estado_post(&x).unwrap();
    assert_eq!(
        estado_x.garantias[&firmante_pk()].incidentes.len(),
        1,
        "(2) la evidencia con falta castiga (un incidente)"
    );
    let post_x = resumen_estado(estado_x);

    // (3) Bloque ajeno `aj` (hijo del terminal, fuera del pasado de `x`): mismo resumen.
    let mut cadena_ajena = base_sin_evidencia().cadena;
    cadena_ajena
        .admitir(post(40, vec![hash_u32(1)], 2, 10))
        .unwrap();
    cadena_ajena
        .admitir(post_con_evidencia(
            30,
            vec![b1, b2],
            3,
            10,
            Some((ev.clone(), tst.clone())),
        ))
        .unwrap();
    assert_eq!(
        resumen_estado(cadena_ajena.estado_post(&x).unwrap()),
        post_x,
        "(3) un bloque ajeno no cambia el estado del bloque de la evidencia"
    );

    // (4) X2 · `finalidad_pasado[B₂] = (1, Some(S₂))` inyectada por el estado inicial: en una cadena
    // `S₂` es un bloque real fuera del pasado de `x`; en la otra, `S₂` es desconocido.
    let mut estado = estado_con_clave();
    estado.finalidad_votos_n = 1;
    estado.finalidad_votos = Some(hash_u32(50));
    estado.finalidad_votos_h_t = Some([0u8; 32]);

    let mut con_s2 = cadena_con(estado.clone(), 600);
    let t = hash_u32(1);
    let a = hash_u32(10);
    con_s2.admitir(post(10, vec![t], 1, 10)).unwrap();
    con_s2.admitir(post(11, vec![a], 2, 10)).unwrap();
    con_s2.admitir(post(21, vec![a], 2, 10)).unwrap();
    con_s2.admitir(post(50, vec![a], 2, 10)).unwrap(); // S₂ real, fuera del pasado de `x`
    con_s2
        .admitir(post_con_evidencia(
            30,
            vec![b1, b2],
            3,
            10,
            Some((ev.clone(), tst.clone())),
        ))
        .unwrap();

    let mut sin_s2 = cadena_con(estado, 600);
    sin_s2.admitir(post(10, vec![t], 1, 10)).unwrap();
    sin_s2.admitir(post(11, vec![a], 2, 10)).unwrap();
    sin_s2.admitir(post(21, vec![a], 2, 10)).unwrap();
    sin_s2
        .admitir(post_con_evidencia(
            30,
            vec![b1, b2],
            3,
            10,
            Some((ev.clone(), tst.clone())),
        ))
        .unwrap();

    assert_eq!(
        hecho(&con_s2, t, x, &ev),
        HechoVoto::Inadmisible,
        "(4) S₂ fuera del pasado de x"
    );
    assert_eq!(
        hecho(&sin_s2, t, x, &ev),
        HechoVoto::Inadmisible,
        "(4) S₂ desconocido"
    );
    assert_eq!(
        resumen_estado(con_s2.estado_post(&x).unwrap()),
        resumen_estado(sin_s2.estado_post(&x).unwrap()),
        "(4) mismo estado en las dos cadenas"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// J8 · mismo estado por admisión, repetición entera y estado virtual.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn j8_estado_por_admision_repeticion_y_virtual() {
    let Base {
        mut cadena,
        b1,
        b2,
        x,
        ..
    } = base_sin_evidencia();
    let (ev, tst) = tx_evidencia(1, b1, 4, b2);
    cadena
        .admitir(post_con_evidencia(30, vec![b1, b2], 3, 10, Some((ev, tst))))
        .unwrap();

    let por_admision = resumen_estado(cadena.estado_post(&x).unwrap());
    let (por_repeticion, _orden, _desc, _undos) = cadena.aplicar_historia_completa().unwrap();
    let por_virtual = cadena.estado_virtual().unwrap();

    assert_eq!(
        resumen_estado(&por_repeticion),
        por_admision,
        "J8 · repetición entera == admisión"
    );
    assert_eq!(
        resumen_estado(&por_virtual),
        por_admision,
        "J8 · estado virtual == admisión"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// J14 · la reconstrucción desde los bloques guardados conserva `finalidad_pasado`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// J14 · Con `finalidad_votos` en el estado inicial (`m = 1`, `S` en la rama de `B₂` y en conflicto
/// con `B₁`), el hecho de J2 es «sin falta» tanto en la cadena original como en la reconstruida
/// re-admitiendo los mismos bloques (`admitir_post` reconstruye `finalidad_pasado`).
#[test]
fn j14_reconstruccion_conserva_finalidad_pasado() {
    let s = hash_u32(12); // rama de B₂, en conflicto con B₁
    let b1 = hash_u32(11);
    let b2 = hash_u32(22);
    let x = hash_u32(30);
    let t = hash_u32(1);

    let mut estado = estado_con_clave();
    estado.finalidad_votos_n = 1;
    estado.finalidad_votos = Some(s);
    estado.finalidad_votos_h_t = Some([0u8; 32]);

    let mut original = cadena_con(estado.clone(), 600);
    original.admitir(post(10, vec![t], 1, 10)).unwrap(); // A
    original
        .admitir(post(11, vec![hash_u32(10)], 2, 10))
        .unwrap(); // B₁
    original
        .admitir(post(12, vec![hash_u32(10)], 2, 10))
        .unwrap(); // S
    original.admitir(post(22, vec![s], 3, 10)).unwrap(); // B₂ desciende de S
    let (ev, tst) = tx_evidencia(1, b1, 4, b2);
    original
        .admitir(post_con_evidencia(
            30,
            vec![b1, b2],
            4,
            10,
            Some((ev.clone(), tst.clone())),
        ))
        .unwrap();
    assert_eq!(
        hecho(&original, t, x, &ev),
        HechoVoto::SinFalta,
        "J14 · el J2 inyectado está justificado"
    );

    // Reconstrucción: misma secuencia de bloques admitida en una `Cadena` nueva.
    let mut reconstruida = cadena_con(estado, 600);
    reconstruida.admitir(post(10, vec![t], 1, 10)).unwrap();
    reconstruida
        .admitir(post(11, vec![hash_u32(10)], 2, 10))
        .unwrap();
    reconstruida
        .admitir(post(12, vec![hash_u32(10)], 2, 10))
        .unwrap();
    reconstruida.admitir(post(22, vec![s], 3, 10)).unwrap();
    reconstruida
        .admitir(post_con_evidencia(
            30,
            vec![b1, b2],
            4,
            10,
            Some((ev.clone(), tst.clone())),
        ))
        .unwrap();
    assert_eq!(
        hecho(&reconstruida, t, x, &ev),
        HechoVoto::SinFalta,
        "J14 · tras reconstruir, el hecho sigue siendo sin falta"
    );
    assert_eq!(
        resumen_estado(original.estado_post(&x).unwrap()),
        resumen_estado(reconstruida.estado_post(&x).unwrap()),
        "J14 · la reconstrucción llega al mismo estado"
    );
}
