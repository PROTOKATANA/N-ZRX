//! Formatos v0 del híbrido (F-05…F-14): vectores del oráculo Julia y validación de forma.
//!
//! El fichero `testdata/formato-v0/vectores.txt` lo produce el **oráculo Julia independiente** de
//! `deepseek/W02/oraculo-formato-v0/`. Este test **recalcula** con Rust y compara byte a byte. Si
//! el fichero no existe, el test falla: no se degrada a «sin verificar».
//!
//! Cubre: igualdad de cada caso con el oráculo (wire, `txid`, mensaje de aceptación), ida y vuelta
//! del códec, los tres `txid` v1 antiguos, `validar_forma_tx` y `validar_forma_cabecera_post` con
//! los negativos de ORDEN-W02 §6, y la firma de aceptación (válida y rechazos).

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::panic,
    reason = "el test falla ruidosamente si falta el oráculo"
)]

use std::collections::HashMap;
use std::path::PathBuf;

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::firma::{ClavePublica, Firma, LONGITUD_FIRMA};
use zx_core::wire::{tx_a_bytes, tx_desde_bytes};
use zx_core::{
    Amount, BlockHash, BodyCommitment, CBID_RED_DEV, DagBlockHeader, Digest, EncodingError,
    ErrorFormaTx, ExtensionTx, Lock, MAGIC_DEV, MerkleRoot, OutPoint, PadresDag, SolucionPoas,
    TAMANO_CABECERA_MAX, TAMANO_CABECERA_MIN, TipoGarantia, Tx, TxId, TxIn, TxOut,
    ZX_VALUE_SANITY_LIMIT, dag_header_a_bytes, dag_header_desde_bytes, mensaje_aceptacion,
    sha3_256_publico, txid, validar_forma_cabecera_post, validar_forma_tx, verificar_aceptacion,
};

const CBID_OTRO: u32 = 0x0102_0304;
const CBID_ANTIGUO: u32 = 0xc478_80ea;

// ── Constructores del escenario (espejo exacto del oráculo Julia) ─────────────

fn clave(n: u8) -> ClavePublica {
    ClavePublica::desde_bytes([n; 32])
}

fn entrada(n: u8, idx: u32, seq: u32) -> TxIn {
    TxIn {
        outpoint: OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: idx,
        },
        sequence: seq,
    }
}

fn salida(valor: i64, k: u8) -> TxOut {
    TxOut {
        value: Amount::nuevo(valor).unwrap(),
        lock: Lock::PubKey { pubkey: clave(k) },
    }
}

fn testigo(b: u8) -> Vec<u8> {
    vec![b; 64]
}

fn wit(bs: &[u8]) -> Vec<Vec<u8>> {
    bs.iter().map(|b| testigo(*b)).collect()
}

fn tx1(entradas: Vec<TxIn>, salidas: Vec<TxOut>) -> Tx {
    Tx {
        version: 1,
        inputs: entradas,
        outputs: salidas,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

fn tx2(
    entradas: Vec<TxIn>,
    salidas: Vec<TxOut>,
    tipo: TipoGarantia,
    k: ClavePublica,
    importe: i64,
) -> Tx {
    tx2_nonce(entradas, salidas, tipo, k, importe, 0)
}

fn tx2_nonce(
    entradas: Vec<TxIn>,
    salidas: Vec<TxOut>,
    tipo: TipoGarantia,
    k: ClavePublica,
    importe: i64,
    nonce: u64,
) -> Tx {
    Tx {
        version: 2,
        inputs: entradas,
        outputs: salidas,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo,
            clave: k,
            importe: Amount::nuevo(importe).unwrap(),
            nonce,
        },
    }
}

fn tx3(k: ClavePublica, importe: i64) -> Tx {
    tx3_slot(k, importe, 0)
}

fn tx3_slot(k: ClavePublica, importe: i64, slot: u64) -> Tx {
    Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave: k,
            importe: Amount::nuevo(importe).unwrap(),
            slot,
        },
    }
}

/// Escenario de cada caso del oráculo, por nombre. Debe coincidir campo a campo con
/// `oraculo-formato-v0.1/src/referencia.jl` (incluidos `nonce` de F-15 y `slot` de F-17); si
/// divergen, el test lo caza.
fn escenario(nombre: &str) -> Option<(Tx, Vec<Vec<u8>>, u32)> {
    let deposito_1in_cambio = |nonce: u64| {
        tx2_nonce(
            vec![entrada(0x21, 1, 0xffff_fffe)],
            vec![salida(1_000, 0xc3)],
            TipoGarantia::Deposito,
            clave(0xd4),
            9_000,
            nonce,
        )
    };
    let deposito_3in = |sin_cambio: bool, nonce: u64| {
        let salidas = if sin_cambio {
            Vec::new()
        } else {
            vec![salida(700, 0xc3)]
        };
        tx2_nonce(
            vec![
                entrada(0x31, 0, 0xffff_fffe),
                entrada(0x32, 2, 0),
                entrada(0x33, 5, 1),
            ],
            salidas,
            TipoGarantia::Deposito,
            clave(0xd4),
            7_000,
            nonce,
        )
    };

    let caso = match nombre {
        "v1_transferencia_dev" => (
            tx1(
                vec![entrada(0x11, 0, 0xffff_fffe)],
                vec![salida(12_345, 0xa1)],
            ),
            wit(&[0x33]),
            CBID_RED_DEV,
        ),
        "v1_transferencia_otro" => (
            tx1(
                vec![entrada(0x11, 0, 0xffff_fffe)],
                vec![salida(12_345, 0xa1)],
            ),
            wit(&[0x33]),
            CBID_OTRO,
        ),
        "v1_coinbase_pow_dev" => (
            tx1(Vec::new(), vec![salida(5_000_000_000, 0xb2)]),
            Vec::new(),
            CBID_RED_DEV,
        ),
        "v2_deposito_1in_cambio_dev" => (deposito_1in_cambio(0), wit(&[0x44, 0x55]), CBID_RED_DEV),
        "v2_deposito_1in_cambio_otro" => (deposito_1in_cambio(7), wit(&[0x44, 0x55]), CBID_OTRO),
        "v2_deposito_1in_sin_cambio_dev" => (
            tx2_nonce(
                vec![entrada(0x21, 1, 0xffff_fffe)],
                Vec::new(),
                TipoGarantia::Deposito,
                clave(0xd5),
                9_000,
                1,
            ),
            wit(&[0x44, 0x55]),
            CBID_RED_DEV,
        ),
        "v2_deposito_3in_cambio_dev" => (
            deposito_3in(false, 2),
            wit(&[0x61, 0x62, 0x63, 0x64]),
            CBID_RED_DEV,
        ),
        "v2_deposito_3in_cambio_otro" => (
            deposito_3in(false, 0xdead),
            wit(&[0x61, 0x62, 0x63, 0x64]),
            CBID_OTRO,
        ),
        "v2_deposito_3in_sin_cambio_dev" => (
            deposito_3in(true, 3),
            wit(&[0x61, 0x62, 0x63, 0x64]),
            CBID_RED_DEV,
        ),
        "v2_retiro_dev" => (
            tx2_nonce(
                Vec::new(),
                Vec::new(),
                TipoGarantia::Retiro,
                clave(0xe6),
                2_500,
                4,
            ),
            wit(&[0x71]),
            CBID_RED_DEV,
        ),
        "v2_retiro_otro" => (
            tx2_nonce(
                Vec::new(),
                Vec::new(),
                TipoGarantia::Retiro,
                clave(0xe6),
                2_500,
                5,
            ),
            wit(&[0x71]),
            CBID_OTRO,
        ),
        "v2_liberacion_dev" => (
            tx2_nonce(
                Vec::new(),
                Vec::new(),
                TipoGarantia::Liberacion,
                clave(0xf7),
                2_500,
                6,
            ),
            wit(&[0x72]),
            CBID_RED_DEV,
        ),
        "v3_coinbase_post_dev" => (
            tx3_slot(clave(0x1a), 5_000_000_000, 0),
            Vec::new(),
            CBID_RED_DEV,
        ),
        "v3_coinbase_post_otro" => (
            tx3_slot(clave(0x1a), 5_000_000_000, 0x2a),
            Vec::new(),
            CBID_OTRO,
        ),
        _ => return None,
    };
    Some(caso)
}

// ── Lectura del fichero del oráculo ──────────────────────────────────────────

#[derive(Clone, Debug)]
struct Caso {
    version: u32,
    cbid: u32,
    tipo: Option<u8>,
    wire: String,
    txid: String,
    mensaje: Option<String>,
}

fn ruta_vectores(carpeta: &str) -> PathBuf {
    [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "testdata",
        carpeta,
        "vectores.txt",
    ]
    .iter()
    .collect()
}

fn leer_vectores_de(carpeta: &str) -> (HashMap<String, String>, HashMap<String, Caso>) {
    let ruta = ruta_vectores(carpeta);
    let texto = std::fs::read_to_string(&ruta).unwrap_or_else(|e| {
        panic!(
            "no se pudo leer el oráculo Julia en {}: {e}. Genera los vectores con \
             deepseek/W02b/oraculo-formato-v0.1/run.jl; este test MUST fallar, no degradarse.",
            ruta.display()
        )
    });

    let mut claves: HashMap<String, String> = HashMap::new();
    let mut casos: HashMap<String, Caso> = HashMap::new();
    for linea in texto.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let campos: Vec<&str> = l.split_whitespace().collect();
        if campos.first() == Some(&"caso") {
            let nombre = campos.get(1).unwrap().to_string();
            let version = campos.get(2).unwrap().parse::<u32>().unwrap();
            let cbid = u32::from_str_radix(campos.get(3).unwrap(), 16).unwrap();
            let tipo = match *campos.get(4).unwrap() {
                "-" => None,
                t => Some(t.parse::<u8>().unwrap()),
            };
            let wire = campos.get(5).unwrap().to_string();
            let txid = campos.get(6).unwrap().to_string();
            let mensaje = match *campos.get(7).unwrap() {
                "-" => None,
                m => Some(m.to_string()),
            };
            casos.insert(
                nombre,
                Caso {
                    version,
                    cbid,
                    tipo,
                    wire,
                    txid,
                    mensaje,
                },
            );
        } else {
            claves.insert(
                campos.first().unwrap().to_string(),
                campos.get(1).unwrap().to_string(),
            );
        }
    }
    (claves, casos)
}

/// Los vectores activos son los **v0.1** (Corrección v0.1 de `FORMATO-v0.md`).
fn leer_vectores() -> (HashMap<String, String>, HashMap<String, Caso>) {
    leer_vectores_de("formato-v0.1")
}

// ── V4: los vectores nuevos coinciden con el oráculo ─────────────────────────

/// Los 14 nombres que `referencia.jl` debe emitir. Que el fichero venga incompleto se caza aquí.
const CASOS_ESPERADOS: [&str; 14] = [
    "v1_transferencia_dev",
    "v1_transferencia_otro",
    "v1_coinbase_pow_dev",
    "v2_deposito_1in_cambio_dev",
    "v2_deposito_1in_cambio_otro",
    "v2_deposito_1in_sin_cambio_dev",
    "v2_deposito_3in_cambio_dev",
    "v2_deposito_3in_cambio_otro",
    "v2_deposito_3in_sin_cambio_dev",
    "v2_retiro_dev",
    "v2_retiro_otro",
    "v2_liberacion_dev",
    "v3_coinbase_post_dev",
    "v3_coinbase_post_otro",
];

#[test]
fn los_vectores_del_oraculo_julia_coinciden() {
    let (claves, casos) = leer_vectores();
    assert!(
        casos.len() >= 12,
        "se exigen ≥ 12 casos, llegaron {}",
        casos.len()
    );
    for nombre in CASOS_ESPERADOS {
        assert!(
            casos.contains_key(nombre),
            "falta el caso {nombre} en el fichero del oráculo"
        );
    }

    assert_eq!(
        sha3_256_publico(b"").to_string(),
        *claves.get("sha3_vacio").unwrap(),
        "SHA3-256 del vacío (NIST)"
    );
    assert_eq!(
        format!("{:08x}", CBID_RED_DEV),
        *claves.get("cbid_red_dev").unwrap(),
        "F-12"
    );
    assert_eq!(
        hex::encode(MAGIC_DEV),
        *claves.get("magic_dev").unwrap(),
        "C-NET-01"
    );

    for (nombre, caso) in &casos {
        let (tx, testigos, cbid) = escenario(nombre).unwrap();
        assert_eq!(tx.version, caso.version, "{nombre}: version");
        assert_eq!(cbid, caso.cbid, "{nombre}: cbid");

        let mut bytes = Vec::new();
        tx_a_bytes(&mut bytes, &tx, &testigos);
        assert_eq!(hex::encode(&bytes), caso.wire, "{nombre}: wire");

        assert_eq!(txid(&tx, cbid).to_string(), caso.txid, "{nombre}: txid");

        if tx.version == 2 {
            let esperado = caso.mensaje.as_ref().unwrap();
            assert_eq!(
                hex::encode(mensaje_aceptacion(&tx, cbid)),
                *esperado,
                "{nombre}: mensaje de aceptación"
            );
        } else {
            assert!(caso.mensaje.is_none(), "{nombre}: no debe tener mensaje");
        }

        match &tx.extension {
            ExtensionTx::Garantia { tipo, .. } => {
                assert_eq!(Some(tipo.byte()), caso.tipo, "{nombre}: tipo");
            }
            _ => assert_eq!(caso.tipo, None, "{nombre}: tipo"),
        }

        // F-14: ida y vuelta del códec y nada sobrante.
        let ((leida, t), resto) = tx_desde_bytes(&bytes).unwrap();
        assert_eq!(leida, tx, "{nombre}: ida y vuelta");
        assert_eq!(t, testigos, "{nombre}: testigos");
        assert!(resto.is_empty(), "{nombre}: bytes sobrantes");
    }

    // Decisión 2 de ORDEN-W02b: los casos **v1 no-coinbase** conservan byte a byte los bytes y el
    // `txid` de los vectores v0; la corrección F-15/F-17 no toca la v1.
    let (_, v0) = leer_vectores_de("formato-v0");
    for nombre in ["v1_transferencia_dev", "v1_transferencia_otro"] {
        let a = casos.get(nombre).unwrap();
        let b = v0.get(nombre).unwrap();
        assert_eq!(a.wire, b.wire, "{nombre}: bytes v1 no-coinbase intactos");
        assert_eq!(a.txid, b.txid, "{nombre}: txid v1 no-coinbase intacto");
    }
}

/// §9(b): los tres `txid` v1 antiguos, reproducidos por el oráculo.
///
/// [1] y [2] son los de `testdata/vectores-cabecera-dag/vectores.txt` (citados por
/// `tests/oraculo_julia.rs` y `tests/vectores_dag.rs`); [3] es el escenario `tx_ejemplo()` de los
/// tests unitarios de `crates/zx-core/src/preimage/tx.rs`.
#[test]
fn los_tres_txid_v1_antiguos_se_reproducen() {
    let (claves, _) = leer_vectores();
    let antiguo = |n: u8, valor: i64| {
        tx1(
            vec![entrada(n, u32::from(n), 0xffff_fffe)],
            vec![salida(valor, n)],
        )
    };
    let ancla_3 = tx1(
        vec![entrada(1, 1, 0xffff_ffff), entrada(2, 2, 0)],
        vec![salida(50_000, 10), salida(25_000, 11)],
    );

    assert_eq!(
        txid(&antiguo(1, 5_000), CBID_ANTIGUO).to_string(),
        *claves.get("txid_v1_antiguo_1").unwrap()
    );
    assert_eq!(
        txid(&antiguo(2, 3_000), CBID_ANTIGUO).to_string(),
        *claves.get("txid_v1_antiguo_2").unwrap()
    );
    assert_eq!(
        txid(&ancla_3, CBID_ANTIGUO).to_string(),
        *claves.get("txid_v1_antiguo_3").unwrap()
    );
}

// ── F-05..F-10: validar_forma_tx ─────────────────────────────────────────────

fn deposito_valido() -> (Tx, Vec<Vec<u8>>) {
    (
        tx2(
            vec![entrada(0x21, 1, 0xffff_fffe)],
            vec![salida(1_000, 0xc3)],
            TipoGarantia::Deposito,
            clave(0xd4),
            9_000,
        ),
        wit(&[0x44, 0x55]),
    )
}

#[test]
fn los_casos_validos_de_forma_pasan() {
    let (d, w) = deposito_valido();
    assert!(validar_forma_tx(&d, &w).is_ok());

    let transferencia = tx1(vec![entrada(0x11, 0, 0xffff_fffe)], vec![salida(1, 0xa1)]);
    assert!(validar_forma_tx(&transferencia, &[testigo(0x33)]).is_ok());

    let coinbase = tx1(Vec::new(), vec![salida(1, 0xb2)]);
    assert!(validar_forma_tx(&coinbase, &[]).is_ok());
    assert!(coinbase.es_candidata_coinbase_pow(), "F-05");

    let retiro = tx2(
        Vec::new(),
        Vec::new(),
        TipoGarantia::Retiro,
        clave(0xe6),
        2_500,
    );
    assert!(validar_forma_tx(&retiro, &[testigo(0x71)]).is_ok());

    let liberacion = tx2(
        Vec::new(),
        Vec::new(),
        TipoGarantia::Liberacion,
        clave(0xf7),
        2_500,
    );
    assert!(validar_forma_tx(&liberacion, &[testigo(0x72)]).is_ok());

    let post = tx3(clave(0x1a), 5_000_000_000);
    assert!(validar_forma_tx(&post, &[]).is_ok());

    // Una v1 con entradas y sin salidas no es transferencia válida; pero una v1 sin entradas es
    // candidata a coinbase y sí pasa (el contexto decide).
    let mut v1_sin_salida = transferencia;
    v1_sin_salida.outputs.clear();
    assert!(matches!(
        validar_forma_tx(&v1_sin_salida, &[testigo(0x33)]),
        Err(ErrorFormaTx::TransferenciaSinSalidas)
    ));
}

#[test]
fn las_versiones_fuera_de_rango_se_rechazan() {
    let (base, w) = deposito_valido();

    let mut t = base.clone();
    t.version = 0;
    assert!(matches!(
        validar_forma_tx(&t, &w),
        Err(ErrorFormaTx::VersionDesconocida { version: 0 })
    ));

    let mut t = base.clone();
    t.version = 4;
    assert!(matches!(
        validar_forma_tx(&t, &w),
        Err(ErrorFormaTx::VersionInactiva { version: 4 })
    ));

    let mut t = base.clone();
    t.version = 7;
    assert!(matches!(
        validar_forma_tx(&t, &w),
        Err(ErrorFormaTx::VersionDesconocida { version: 7 })
    ));

    let mut t = base;
    t.version = u32::MAX;
    assert!(matches!(
        validar_forma_tx(&t, &w),
        Err(ErrorFormaTx::VersionDesconocida { version: u32::MAX })
    ));
}

#[test]
fn la_version_y_la_extension_deben_ser_coherentes() {
    // v1 con extensión de garantía (los «bytes de extensión» en v1, en memoria).
    let (base, w) = deposito_valido();
    let mut t = base;
    t.version = 1;
    assert!(matches!(
        validar_forma_tx(&t, &w),
        Err(ErrorFormaTx::ExtensionIncoherente { version: 1, .. })
    ));

    // v2 sin extensión.
    let mut t = tx1(vec![entrada(0x11, 0, 0xffff_fffe)], vec![salida(1, 0xa1)]);
    t.version = 2;
    assert!(matches!(
        validar_forma_tx(&t, &wit(&[0x44, 0x55])),
        Err(ErrorFormaTx::ExtensionIncoherente { version: 2, .. })
    ));

    // v3 con extensión de garantía.
    let mut t = tx3(clave(0x1a), 5_000_000_000);
    t.extension = ExtensionTx::Garantia {
        tipo: TipoGarantia::Deposito,
        clave: clave(0xd4),
        importe: Amount::nuevo(1).unwrap(),
        nonce: 0,
    };
    assert!(matches!(
        validar_forma_tx(&t, &[]),
        Err(ErrorFormaTx::ExtensionIncoherente { version: 3, .. })
    ));
}

#[test]
fn el_deposito_sin_entradas_se_rechaza() {
    let t = tx2(
        Vec::new(),
        Vec::new(),
        TipoGarantia::Deposito,
        clave(0xd4),
        9_000,
    );
    assert!(matches!(
        validar_forma_tx(&t, &wit(&[0x44])),
        Err(ErrorFormaTx::DepositoSinEntradas)
    ));
}

#[test]
fn retiro_y_liberacion_no_admiten_entradas_ni_salidas() {
    let retiro = tx2(
        vec![entrada(0x21, 1, 0xffff_fffe)],
        Vec::new(),
        TipoGarantia::Retiro,
        clave(0xe6),
        2_500,
    );
    assert!(matches!(
        validar_forma_tx(&retiro, &wit(&[0x71, 0x72])),
        Err(ErrorFormaTx::RetiroConEntradas { entradas: 1 })
    ));

    let retiro = tx2(
        Vec::new(),
        vec![salida(1, 0xc3)],
        TipoGarantia::Retiro,
        clave(0xe6),
        2_500,
    );
    assert!(matches!(
        validar_forma_tx(&retiro, &wit(&[0x71])),
        Err(ErrorFormaTx::RetiroConSalidas { salidas: 1 })
    ));

    let liberacion = tx2(
        vec![entrada(0x21, 1, 0xffff_fffe)],
        Vec::new(),
        TipoGarantia::Liberacion,
        clave(0xf7),
        2_500,
    );
    assert!(matches!(
        validar_forma_tx(&liberacion, &wit(&[0x71, 0x72])),
        Err(ErrorFormaTx::LiberacionConEntradas { entradas: 1 })
    ));

    let liberacion = tx2(
        Vec::new(),
        vec![salida(1, 0xc3)],
        TipoGarantia::Liberacion,
        clave(0xf7),
        2_500,
    );
    assert!(matches!(
        validar_forma_tx(&liberacion, &wit(&[0x71])),
        Err(ErrorFormaTx::LiberacionConSalidas { salidas: 1 })
    ));
}

#[test]
fn el_recuento_de_testigos_de_v2_es_n_in_mas_uno() {
    let (base, _) = deposito_valido();
    let un_testigo = wit(&[0x44]);
    assert!(matches!(
        validar_forma_tx(&base, &un_testigo),
        Err(ErrorFormaTx::NumeroDeTestigosInvalido {
            esperados: 2,
            obtenidos: 1
        })
    ));

    let tres_testigos = wit(&[0x44, 0x55, 0x66]);
    assert!(matches!(
        validar_forma_tx(&base, &tres_testigos),
        Err(ErrorFormaTx::NumeroDeTestigosInvalido {
            esperados: 2,
            obtenidos: 3
        })
    ));
}

#[test]
fn el_testigo_de_aceptacion_mide_64_bytes() {
    let (base, _) = deposito_valido();
    let w63 = vec![testigo(0x44), vec![0x55; 63]];
    assert!(matches!(
        validar_forma_tx(&base, &w63),
        Err(ErrorFormaTx::TestigoAceptacionLongitud { obtenidos: 63 })
    ));

    let w65 = vec![testigo(0x44), vec![0x55; 65]];
    assert!(matches!(
        validar_forma_tx(&base, &w65),
        Err(ErrorFormaTx::TestigoAceptacionLongitud { obtenidos: 65 })
    ));
}

#[test]
fn el_importe_de_la_extension_debe_ser_positivo() {
    let t = tx2(
        vec![entrada(0x21, 1, 0xffff_fffe)],
        vec![salida(1_000, 0xc3)],
        TipoGarantia::Deposito,
        clave(0xd4),
        0,
    );
    assert!(matches!(
        validar_forma_tx(&t, &wit(&[0x44, 0x55])),
        Err(ErrorFormaTx::ImporteCero)
    ));

    // El techo lo impone `Amount` por construcción (C-TX-12): `> ZX_VALUE_SANITY_LIMIT` no es
    // representable en un `Tx`; se cubre aquí y en el códec (bytes hostiles).
    assert!(Amount::nuevo(ZX_VALUE_SANITY_LIMIT + 1).is_err());
    assert!(Amount::nuevo(ZX_VALUE_SANITY_LIMIT).is_ok());
    assert!(Amount::nuevo(-1).is_err());
}

#[test]
fn los_campos_de_altura_estan_inactivos() {
    let (base, w) = deposito_valido();

    let mut t = base.clone();
    t.lock_time = 1;
    assert!(matches!(
        validar_forma_tx(&t, &w),
        Err(ErrorFormaTx::CampoInactivo { campo: "lock_time" })
    ));

    let mut t = base;
    t.expiry_height = 1;
    assert!(matches!(
        validar_forma_tx(&t, &w),
        Err(ErrorFormaTx::CampoInactivo {
            campo: "expiry_height"
        })
    ));
}

#[test]
fn las_salidas_htlc_estan_inactivas() {
    let t = tx1(
        vec![entrada(0x11, 0, 0xffff_fffe)],
        vec![TxOut {
            value: Amount::nuevo(1).unwrap(),
            lock: Lock::Htlc {
                hash: [0u8; 32],
                receiver: clave(1),
                sender: clave(2),
                timeout: 0,
            },
        }],
    );
    assert!(matches!(
        validar_forma_tx(&t, &[testigo(0x33)]),
        Err(ErrorFormaTx::SalidaHtlc)
    ));
}

#[test]
fn la_coinbase_post_no_lleva_entradas_salidas_ni_testigos() {
    let mut t = tx3(clave(0x1a), 5_000_000_000);
    t.inputs = vec![entrada(0x11, 0, 0)];
    assert!(matches!(
        validar_forma_tx(&t, &[]),
        Err(ErrorFormaTx::EntradasEnCoinbasePost { entradas: 1 })
    ));

    let mut t = tx3(clave(0x1a), 5_000_000_000);
    t.outputs = vec![salida(1, 0xc3)];
    assert!(matches!(
        validar_forma_tx(&t, &[]),
        Err(ErrorFormaTx::SalidasEnCoinbasePost { salidas: 1 })
    ));

    let t = tx3(clave(0x1a), 5_000_000_000);
    assert!(matches!(
        validar_forma_tx(&t, &wit(&[0x11])),
        Err(ErrorFormaTx::TestigosEnCoinbasePost { testigos: 1 })
    ));

    // El importe de la coinbase también debe ser > 0.
    let t = tx3(clave(0x1a), 1);
    assert!(validar_forma_tx(&t, &[]).is_ok());
}

// ── F-03: cabecera PoST ──────────────────────────────────────────────────────

fn cabecera_post(height: u32) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: CBID_RED_DEV,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0u8; 32])),
        timestamp: 0,
        height,
        slot: 0,
        pot_output: [0u8; 16],
        rango_solucion: 0,
        sol: SolucionPoas {
            public_key: clave(1),
            sector_index: 0,
            history_size: 0,
            piece_offset: 0,
            record_commitment: [0u8; 32],
            record_witness: [0u8; 256],
            chunk: [0u8; 32],
            chunk_witness: [0u8; 512],
            proof_of_space: [0u8; 160],
        },
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0u8; 32])),
        padres: PadresDag::genesis(),
        sello: [0u8; 64],
    }
}

#[test]
fn la_altura_de_una_cabecera_post_debe_ser_cero() {
    assert!(validar_forma_cabecera_post(&cabecera_post(0)).is_ok());
    assert!(matches!(
        validar_forma_cabecera_post(&cabecera_post(1)),
        Err(ErrorFormaTx::AlturaPostNoCero { height: 1 })
    ));
    assert!(matches!(
        validar_forma_cabecera_post(&cabecera_post(u32::MAX)),
        Err(ErrorFormaTx::AlturaPostNoCero { height: u32::MAX })
    ));
}

// ── Códec: no canónicos, truncados y sobrantes ───────────────────────────────

/// v2 mínima (sin entradas ni salidas) con extensión de garantía y un testigo: offsets fáciles.
fn v2_minima() -> (Tx, Vec<Vec<u8>>) {
    (
        tx2(
            Vec::new(),
            Vec::new(),
            TipoGarantia::Deposito,
            clave(0xd4),
            100,
        ),
        wit(&[0x55]),
    )
}

#[test]
fn el_codec_rechaza_versiones_y_tipos_fuera_de_rango() {
    let (t, w) = v2_minima();
    let mut b = Vec::new();
    tx_a_bytes(&mut b, &t, &w);
    assert_eq!(
        *b.get(14).unwrap(),
        1u8,
        "el tipo de la v2 vive en el offset 14"
    );

    for (version, esperado) in [(0u32, 0u32), (7, 7), (u32::MAX, u32::MAX)] {
        let mut bv = b.clone();
        bv.get_mut(..4)
            .unwrap()
            .copy_from_slice(&version.to_le_bytes());
        assert!(
            matches!(
                tx_desde_bytes(&bv),
                Err(EncodingError::VersionDesconocida { version: v }) if v == esperado
            ),
            "versión {version} MUST rechazarse sin consumir el resto"
        );
    }

    // SL-4c: la v4 ya no es `VersionInactiva` en el códec (FD-5); estos bytes son de una v2, así
    // que el parser v4 no encuentra dos cabeceras DAG y rechaza por truncamiento.
    let mut b4 = b.clone();
    b4.get_mut(..4)
        .unwrap()
        .copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        tx_desde_bytes(&b4),
        Err(EncodingError::Truncado { .. })
    ));

    for tipo in [0u8, 4, 0xff] {
        let mut bt = b.clone();
        *bt.get_mut(14).unwrap() = tipo;
        assert!(matches!(
            tx_desde_bytes(&bt),
            Err(EncodingError::TipoGarantiaInvalido { tipo: t }) if t == tipo
        ));
    }
}

#[test]
fn el_codec_rechaza_una_extension_truncada_y_no_consume_sobrantes() {
    let (t, w) = v2_minima();
    let mut b = Vec::new();
    tx_a_bytes(&mut b, &t, &w);

    // La extensión de v2 (F-15) vive en [14, 63): tipo(14) + clave[15,47) + importe[47,55) +
    // nonce[55,63). Cualquier prefijo estricto a partir de ahí MUST rechazarse por truncamiento.
    for corte in 14..b.len() {
        let truncado = b.get(..corte).unwrap();
        assert!(
            matches!(
                tx_desde_bytes(truncado),
                Err(EncodingError::Truncado { .. })
            ),
            "corte en {corte} MUST ser Truncado"
        );
    }

    // Bytes sobrantes: no se consumen.
    let mut con_sobrante = b.clone();
    con_sobrante.push(0xAA);
    let ((_, _), resto) = tx_desde_bytes(&con_sobrante).unwrap();
    assert_eq!(resto, &[0xAA], "tras el último testigo no se consume nada");

    // Muchos sobrantes.
    let mut con_muchos = b;
    con_muchos.extend_from_slice(&[0xBB; 41]);
    let ((_, _), resto) = tx_desde_bytes(&con_muchos).unwrap();
    assert_eq!(resto.len(), 41, "v1 no consume una extensión colada");
}

#[test]
fn el_codec_rechaza_un_importe_de_extension_fuera_de_rango() {
    let (t, w) = v2_minima();
    let mut b = Vec::new();
    tx_a_bytes(&mut b, &t, &w);

    // importe en [47, 55): lo ponemos a ZX_VALUE_SANITY_LIMIT + 1 (positivo, fuera de rango).
    b.get_mut(47..55)
        .unwrap()
        .copy_from_slice(&(ZX_VALUE_SANITY_LIMIT + 1).to_le_bytes());
    assert!(matches!(
        tx_desde_bytes(&b),
        Err(EncodingError::ImporteFueraDeRango { .. })
    ));

    // Y un valor con el bit alto puesto (u64 > i64::MAX) también se rechaza.
    b.get_mut(47..55)
        .unwrap()
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        tx_desde_bytes(&b),
        Err(EncodingError::ImporteFueraDeRango { .. })
    ));
}

// ── F-06/F-08: txid y firma de aceptación ────────────────────────────────────

#[test]
fn cada_campo_de_la_extension_y_la_version_cambia_el_txid() {
    let (base, _) = deposito_valido();
    let original = txid(&base, CBID_RED_DEV);

    let mut v = base.clone();
    v.version = 3;
    assert_ne!(txid(&v, CBID_RED_DEV), original, "version");

    let mut v = base.clone();
    if let ExtensionTx::Garantia { tipo, .. } = &mut v.extension {
        *tipo = TipoGarantia::Retiro;
    }
    assert_ne!(txid(&v, CBID_RED_DEV), original, "tipo");

    let mut v = base.clone();
    if let ExtensionTx::Garantia { clave: c, .. } = &mut v.extension {
        *c = clave(0x99);
    }
    assert_ne!(txid(&v, CBID_RED_DEV), original, "clave");

    let mut v = base.clone();
    if let ExtensionTx::Garantia { importe, .. } = &mut v.extension {
        *importe = Amount::nuevo(8_999).unwrap();
    }
    assert_ne!(txid(&v, CBID_RED_DEV), original, "importe");

    // F-15: el nonce entra en el txid.
    let mut v = base.clone();
    if let ExtensionTx::Garantia { nonce, .. } = &mut v.extension {
        *nonce = 1;
    }
    assert_ne!(txid(&v, CBID_RED_DEV), original, "nonce");

    // F-17: el slot de la coinbase PoST entra en el txid.
    let post_a = tx3_slot(clave(0x1a), 5_000_000_000, 0);
    let post_b = tx3_slot(clave(0x1a), 5_000_000_000, 1);
    assert_ne!(
        txid(&post_a, CBID_RED_DEV),
        txid(&post_b, CBID_RED_DEV),
        "slot"
    );

    let mut v = base.clone();
    v.extension = ExtensionTx::Ninguna;
    v.version = 1;
    assert_ne!(txid(&v, CBID_RED_DEV), original, "extensión ausente");

    assert_ne!(
        txid(&base, CBID_RED_DEV),
        txid(&base, CBID_OTRO),
        "el CBID entra en el txid"
    );
}

#[test]
fn la_firma_de_aceptacion_verifica_y_rechaza() {
    let sk = SigningKey::from([0x42u8; 32]);
    let vk_bytes: [u8; 32] = VerificationKey::from(&sk).into();
    let vk = ClavePublica::desde_bytes(vk_bytes);

    let tx_ok = tx2(
        vec![entrada(0x21, 1, 0xffff_fffe)],
        vec![salida(1_000, 0xc3)],
        TipoGarantia::Deposito,
        vk,
        9_000,
    );
    let msg = mensaje_aceptacion(&tx_ok, CBID_RED_DEV);
    let firma: [u8; LONGITUD_FIRMA] = sk.sign(&msg).into();
    assert!(verificar_aceptacion(&tx_ok, &firma, CBID_RED_DEV).is_ok());

    // Otra clave.
    let otra = SigningKey::from([0x43u8; 32]);
    let firma_otra: [u8; LONGITUD_FIRMA] = otra.sign(&msg).into();
    assert!(verificar_aceptacion(&tx_ok, &firma_otra, CBID_RED_DEV).is_err());

    // Otro txid: cambiamos un dato de efecto.
    let mut tx_distinta = tx_ok.clone();
    tx_distinta.outputs = vec![salida(999, 0xc3)];
    assert!(verificar_aceptacion(&tx_distinta, &firma, CBID_RED_DEV).is_err());

    // Otra CBID.
    assert!(verificar_aceptacion(&tx_ok, &firma, CBID_OTRO).is_err());

    // Longitudes 63 y 65.
    let f63 = firma.get(..63).unwrap();
    assert!(matches!(
        verificar_aceptacion(&tx_ok, f63, CBID_RED_DEV),
        Err(ErrorFormaTx::TestigoAceptacionLongitud { obtenidos: 63 })
    ));
    let mut f65 = firma.to_vec();
    f65.push(0);
    assert!(matches!(
        verificar_aceptacion(&tx_ok, &f65, CBID_RED_DEV),
        Err(ErrorFormaTx::TestigoAceptacionLongitud { obtenidos: 65 })
    ));

    // Una transacción que no es v2 de garantía no tiene firma de aceptación.
    let v1 = tx1(vec![entrada(0x11, 0, 0xffff_fffe)], vec![salida(1, 0xa1)]);
    assert!(matches!(
        verificar_aceptacion(&v1, &firma, CBID_RED_DEV),
        Err(ErrorFormaTx::ExtensionIncoherente { version: 1, .. })
    ));

    // `Firma` también es utilizable por la API pública.
    let _ = Firma::desde_bytes(firma);
}

// ── SL-4c · V2: ida y vuelta de la `EvidenceTx` v4 y rechazos del códec ──────

/// Cabecera `PoAS_PoT_DAG` determinista y **firmada**, con `padres` padres (1..=15).
///
/// La firma es real (Ed25519): la ida y vuelta del códec se comprueba sobre cabeceras que
/// satisfacen `C-HDR-04`, no sobre relleno.
fn cabecera_v4(semilla: u64, padres: u8) -> DagBlockHeader {
    let sk = SigningKey::from([0x5au8; 32]);
    let vk: [u8; 32] = VerificationKey::from(&sk).into();
    let mut extra = Vec::new();
    for i in 0..padres.saturating_sub(1) {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&semilla.to_le_bytes());
        b[8..16].copy_from_slice(&u64::from(i).to_le_bytes());
        extra.push(BlockHash::from_digest(Digest::from_bytes(b)));
    }
    let mut sel = [0u8; 32];
    sel[..8].copy_from_slice(&semilla.wrapping_add(0x9e37_79b9).to_le_bytes());
    let mut h = DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: CBID_RED_DEV,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0u8; 32])),
        timestamp: semilla,
        height: 0,
        slot: semilla,
        pot_output: [0u8; 16],
        rango_solucion: semilla,
        sol: SolucionPoas {
            public_key: ClavePublica::desde_bytes(vk),
            sector_index: (semilla & 0xffff) as u16,
            history_size: semilla,
            ..Default::default()
        },
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0u8; 32])),
        padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes(sel)), &extra)
            .expect("padres deterministas"),
        sello: [0u8; 64],
    };
    let firma: [u8; LONGITUD_FIRMA] = sk.sign(h.pre_hash().as_bytes()).into();
    h.sello = firma;
    h
}

/// Construye una `Tx` v4 a partir de dos cabeceras, ordenándolas en el orden canónico.
fn tx_v4(mut h1: DagBlockHeader, mut h2: DagBlockHeader) -> Tx {
    if h1.pre_hash().as_bytes() >= h2.pre_hash().as_bytes() {
        core::mem::swap(&mut h1, &mut h2);
    }
    assert!(h1.pre_hash().as_bytes() < h2.pre_hash().as_bytes());
    Tx {
        version: 4,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Evidencia { h1, h2 },
    }
}

/// V2 · ≥ 200 `EvidenceTx` v4 con cabeceras reales firmadas: bytes → tx idéntica, sin sobrantes.
#[test]
fn la_v4_sobrevive_a_ida_y_vuelta() {
    let mut generadas = 0usize;
    for caso in 0u64..210 {
        let n1 = (caso % 15 + 1) as u8;
        let n2 = ((caso * 7) % 15 + 1) as u8;
        let tx = tx_v4(cabecera_v4(caso * 3 + 1, n1), cabecera_v4(caso * 5 + 2, n2));
        let ExtensionTx::Evidencia { h1, h2 } = &tx.extension else {
            unreachable!("tx_v4 siempre es evidencia");
        };
        assert!(h1.verificar_sello().is_ok(), "sello H1 real");
        assert!(h2.verificar_sello().is_ok(), "sello H2 real");

        let mut bytes = Vec::new();
        tx_a_bytes(&mut bytes, &tx, &[]);
        let ((leida, testigos), resto) = tx_desde_bytes(&bytes).expect("la v4 decodifica");
        assert!(resto.is_empty(), "caso {caso}: sin bytes sobrantes");
        assert!(testigos.is_empty(), "caso {caso}: sin testigos");
        assert_eq!(leida, tx, "caso {caso}: ida y vuelta exacta");
        assert_eq!(
            txid(&leida, CBID_RED_DEV),
            txid(&tx, CBID_RED_DEV),
            "caso {caso}: txid comprometido"
        );
        generadas += 1;
    }
    assert!(generadas >= 200, "se generaron {generadas} EvidenceTx");
}

/// V2 · truncamiento en cada frontera, sobrante que no se absorbe y extensión ajena.
#[test]
fn la_v4_rechaza_truncamientos_y_no_absorbe_sobrantes() {
    let tx = tx_v4(cabecera_v4(11, 1), cabecera_v4(22, 3));
    let mut bytes = Vec::new();
    tx_a_bytes(&mut bytes, &tx, &[]);

    // Cualquier prefijo estricto (incluida cada frontera de campo) MUST rechazarse.
    for corte in 0..bytes.len() {
        assert!(
            tx_desde_bytes(bytes.get(..corte).unwrap()).is_err(),
            "prefijo de {corte} bytes MUST rechazarse"
        );
    }

    // Sobrante de 1 byte: F-14 no consume nada tras el último testigo; queda como resto de la
    // transacción contenedora (una transacción suelta MUST exigir el resto vacío).
    let mut con_sobrante = bytes.clone();
    con_sobrante.push(0xAA);
    let ((_, _), resto) = tx_desde_bytes(&con_sobrante).expect("cuerpo íntegro");
    assert_eq!(resto, &[0xAA], "el byte sobrante no se absorbe");

    // `version = 4` con la extensión de otra versión: no hay dos cabeceras DAG que leer.
    let (t2, w2) = v2_minima();
    let mut b2 = Vec::new();
    tx_a_bytes(&mut b2, &t2, &w2);
    b2.get_mut(..4)
        .unwrap()
        .copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        tx_desde_bytes(&b2),
        Err(EncodingError::Truncado { .. })
    ));
}

/// V2 · los límites de 589/1 037 B: 588 trunca y una región de 1 038 B (máxima + 1) deja el byte.
#[test]
fn los_limites_de_tamano_de_cabecera_se_rechazan() {
    // 589 es el mínimo (`P = 1`) y 1 037 el máximo (`P = 15`), fijados por `parent_count ≤ 15`.
    let h_min = cabecera_v4(1, 1);
    let bytes_min = dag_header_a_bytes(&h_min);
    assert_eq!(bytes_min.len(), TAMANO_CABECERA_MIN);
    assert!(matches!(
        dag_header_desde_bytes(bytes_min.get(..TAMANO_CABECERA_MIN - 1).unwrap()),
        Err(EncodingError::Truncado { .. })
    ));

    let h_max = cabecera_v4(2, 15);
    let bytes_max = dag_header_a_bytes(&h_max);
    assert_eq!(bytes_max.len(), TAMANO_CABECERA_MAX);
    let mut con_extra = bytes_max.clone();
    con_extra.push(0x00);
    let (leida, resto) = dag_header_desde_bytes(&con_extra).expect("la cabecera máxima decodifica");
    assert_eq!(leida, h_max);
    assert_eq!(
        resto,
        &[0x00],
        "el byte extra no forma parte de la cabecera"
    );

    // A nivel de transacción: una H1 de 588 B trunca; 1 037 B + 1 byte deja ese byte para H2,
    // que ya no cabe y trunca.
    let tx = tx_v4(h_max, cabecera_v4(3, 1));
    let mut bytes = Vec::new();
    tx_a_bytes(&mut bytes, &tx, &[]);
    const PREFIJO_TX: usize = 14; // version(4) + lock_time(4) + expiry_height(4) + n_in(1) + n_out(1)
    assert!(tx_desde_bytes(bytes.get(..PREFIJO_TX + 588).unwrap()).is_err());
    assert!(tx_desde_bytes(bytes.get(..PREFIJO_TX + TAMANO_CABECERA_MAX + 1).unwrap()).is_err());
}
