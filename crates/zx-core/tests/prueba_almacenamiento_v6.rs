//! PT-3bc · formato v6 (prueba de almacenamiento): códec, wire, `txid` y casos de rechazo 1–7/9.
//!
//! Ejerce las clases de la extensión v6 que quedan (`0x01` PoRep, `0x02` PoSt, `0x03` clave BLS de
//! voto, `0x08` voto propio, `0x09` certificado compacto, `0x0A` acta de presencia y `0x0B`
//! evidencia de dos votos) sobre el códec canónico de `zx-core`, sin consenso. **M9-b2:** las
//! clases `0x04`..=`0x07` quedan reservadas y se rechazan por forma.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño y usan índices acotados"
)]

use zx_core::wire::{tx_a_bytes, tx_desde_bytes};
use zx_core::{
    ClasePruebaAlmacenamiento, ClavePublica, ErrorCodecAlmacenamiento, ErrorFormaTx, ExtensionTx,
    LONGITUD_CLAVE_BLS, LONGITUD_PRUEBA_POSESION_BLS, MAX_PRUEBA_ALMACENAMIENTO_BYTES,
    OperacionAlmacenamiento, Tx, VotoPesoEvidencia, validar_forma_tx,
    verificar_firma_almacenamiento,
};

const CBID: u32 = 0xc478_80ea;

fn clave(n: u8) -> ClavePublica {
    ClavePublica::desde_bytes([n; 32])
}

fn tx_v6(op: OperacionAlmacenamiento) -> Tx {
    Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento { operacion: op },
    }
}

fn post(n: u32) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::PoSt {
        clave: clave(1),
        epoch: 10,
        n_sectores: n,
        raiz_conjunto: [7u8; 32],
        prueba: vec![1, 2, 3],
    }
}

fn testigos() -> Vec<Vec<u8>> {
    vec![vec![0u8; 64]]
}

/// `0x03` · registro de la clave BLS de voto.
fn clave_voto() -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::ClaveVoto {
        clave: clave(2),
        clave_bls: [3u8; LONGITUD_CLAVE_BLS],
        prueba_posesion: [4u8; LONGITUD_PRUEBA_POSESION_BLS],
    }
}

/// `0x08` · voto propio de una clave (`n = 7`).
fn voto_propio() -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::VotoPropio {
        clave: clave(1),
        n: 7,
        candidato: [0x11; 32],
        h_t_siguiente: [0x22; 32],
        raiz_estado: [0x55; 32],
        clave_bls: [3u8; LONGITUD_CLAVE_BLS],
        firma: [4u8; LONGITUD_PRUEBA_POSESION_BLS],
    }
}

/// `0x09` · certificado compacto con cuerpo opaco mínimo.
fn certificado_peso() -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::CertificadoPeso {
        clave: clave(1),
        bytes: vec![5, 6, 7],
    }
}

/// `0x0A` · acta de presencia con el mismo cuerpo.
fn acta_presencia() -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::ActaPresencia {
        clave: clave(1),
        bytes: vec![5, 6, 7],
    }
}

/// `0x0B` · evidencia de dos votos en orden canónico.
fn evidencia_votos_peso() -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: clave(1),
        clave_bls: [3u8; LONGITUD_CLAVE_BLS],
        voto1: VotoPesoEvidencia {
            n: 1,
            candidato: [0x11; 32],
            h_t_siguiente: [0x22; 32],
            raiz_estado: [0x33; 32],
            firma: [4u8; LONGITUD_PRUEBA_POSESION_BLS],
        },
        voto2: VotoPesoEvidencia {
            n: 2,
            candidato: [0x12; 32],
            h_t_siguiente: [0x23; 32],
            raiz_estado: [0x34; 32],
            firma: [5u8; LONGITUD_PRUEBA_POSESION_BLS],
        },
    }
}

/// Decodifica una cadena hexadecimal (solo para los valores fijos tomados de `ws.orig`).
fn de_hex(texto: &str) -> Vec<u8> {
    assert_eq!(texto.len() % 2, 0, "hex de longitud par");
    texto
        .as_bytes()
        .chunks(2)
        .map(|par| u8::from_str_radix(std::str::from_utf8(par).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn los_discriminantes_de_clase_son_cerrados() {
    assert_eq!(ClasePruebaAlmacenamiento::PoRep.byte(), 0x01);
    assert_eq!(ClasePruebaAlmacenamiento::PoSt.byte(), 0x02);
    assert_eq!(ClasePruebaAlmacenamiento::ClaveVoto.byte(), 0x03);
    assert_eq!(ClasePruebaAlmacenamiento::VotoPropio.byte(), 0x08);
    assert_eq!(ClasePruebaAlmacenamiento::CertificadoPeso.byte(), 0x09);
    assert_eq!(ClasePruebaAlmacenamiento::ActaPresencia.byte(), 0x0A);
    assert_eq!(ClasePruebaAlmacenamiento::EvidenciaVotosPeso.byte(), 0x0B);
    assert!(ClasePruebaAlmacenamiento::PoRep.es_prueba());
    assert!(ClasePruebaAlmacenamiento::PoSt.es_prueba());
    assert!(!ClasePruebaAlmacenamiento::ClaveVoto.es_prueba());
    assert!(!ClasePruebaAlmacenamiento::VotoPropio.es_prueba());
    assert!(!ClasePruebaAlmacenamiento::CertificadoPeso.es_prueba());
    assert!(!ClasePruebaAlmacenamiento::ActaPresencia.es_prueba());
    assert!(!ClasePruebaAlmacenamiento::EvidenciaVotosPeso.es_prueba());
    // M9-b2 · `0x04`..=`0x07` reservados; `0x0C` y `0xff` fuera del conjunto.
    for v in [0x04u8, 0x05, 0x06, 0x07, 0x0C, 0xff] {
        assert!(
            ClasePruebaAlmacenamiento::desde_byte(v).is_none(),
            "clase {v:#04x} no debe decodificar"
        );
    }
}

#[test]
fn las_clases_nuevas_dan_la_vuelta_por_el_codec() {
    for op in [
        voto_propio(),
        certificado_peso(),
        acta_presencia(),
        evidencia_votos_peso(),
    ] {
        let bytes = op.bytes_canonicos().unwrap();
        let (vuelta, n) = OperacionAlmacenamiento::desde_canonica(&bytes).unwrap();
        assert_eq!(vuelta, op, "ida y vuelta");
        assert_eq!(n, bytes.len(), "consume todos los bytes");
        assert_eq!(bytes[0], op.clase().byte(), "la clase va primero");
    }
    // El cuerpo de un certificado o acta no puede ir vacío.
    assert!(matches!(
        OperacionAlmacenamiento::CertificadoPeso {
            clave: clave(1),
            bytes: Vec::new(),
        }
        .bytes_canonicos(),
        Err(ErrorCodecAlmacenamiento::CertificadoVacio)
    ));
    // La evidencia de dos votos exige orden canónico estricto.
    let no_canonica = OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: clave(1),
        clave_bls: [3u8; LONGITUD_CLAVE_BLS],
        voto1: VotoPesoEvidencia {
            n: 2,
            candidato: [0x12; 32],
            h_t_siguiente: [0x23; 32],
            raiz_estado: [0x34; 32],
            firma: [5u8; LONGITUD_PRUEBA_POSESION_BLS],
        },
        voto2: VotoPesoEvidencia {
            n: 1,
            candidato: [0x11; 32],
            h_t_siguiente: [0x22; 32],
            raiz_estado: [0x33; 32],
            firma: [4u8; LONGITUD_PRUEBA_POSESION_BLS],
        },
    };
    assert!(matches!(
        no_canonica.bytes_canonicos(),
        Err(ErrorCodecAlmacenamiento::EvidenciaVotosNoCanonica)
    ));
}

/// B6.6 · los códigos `0x04`..=`0x07` (retirados en M9-b2) se rechazan por forma, y los bytes de
/// una operación de cada clase que queda son **idénticos** a los de `ws.orig` (`f541bff5`).
#[test]
fn clases_reservadas_se_rechazan_por_forma() {
    for clase in [0x04u8, 0x05, 0x06, 0x07] {
        for bytes in [vec![clase], vec![clase; 8], vec![clase; 300]] {
            assert!(
                matches!(
                    OperacionAlmacenamiento::desde_canonica(&bytes),
                    Err(ErrorCodecAlmacenamiento::DiscriminanteInvalido(c)) if c == clase
                ),
                "la clase reservada {clase:#04x} debe rechazarse por forma"
            );
        }
    }
    let fijos: [(u8, &str, OperacionAlmacenamiento); 5] = [
        (
            0x03,
            "030202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
            clave_voto(),
        ),
        (
            0x08,
            "0801010101010101010101010101010101010101010101010101010101010101010700000000000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222225555555555555555555555555555555555555555555555555555555555555555030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
            voto_propio(),
        ),
        (
            0x09,
            "09010101010101010101010101010101010101010101010101010101010101010103000000050607",
            certificado_peso(),
        ),
        (
            0x0A,
            "0a010101010101010101010101010101010101010101010101010101010101010103000000050607",
            acta_presencia(),
        ),
        (
            0x0B,
            "0b010101010101010101010101010101010101010101010101010101010101010103030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030301000000000000001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040200000000000000121212121212121212121212121212121212121212121212121212121212121223232323232323232323232323232323232323232323232323232323232323233434343434343434343434343434343434343434343434343434343434343434050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
            evidencia_votos_peso(),
        ),
    ];
    for (clase, hex, op) in fijos {
        let bytes = op.bytes_canonicos().unwrap();
        assert_eq!(bytes, de_hex(hex), "clase {clase:#04x} cambió de bytes");
        let (vuelta, n) = OperacionAlmacenamiento::desde_canonica(&bytes).unwrap();
        assert_eq!(vuelta, op);
        assert_eq!(n, bytes.len());
    }
}

#[test]
fn las_tres_clases_dan_la_vuelta_por_el_codec() {
    let ops = [
        OperacionAlmacenamiento::PoRep {
            clave: clave(1),
            epoch: 5,
            n_sectores: 3,
            raiz_conjunto: [1u8; 32],
            prueba: vec![9; 100],
        },
        post(2),
        OperacionAlmacenamiento::ClaveVoto {
            clave: clave(2),
            clave_bls: [3u8; LONGITUD_CLAVE_BLS],
            prueba_posesion: [4u8; LONGITUD_PRUEBA_POSESION_BLS],
        },
    ];
    for op in &ops {
        let bytes = op.bytes_canonicos().unwrap();
        let (vuelta, n) = OperacionAlmacenamiento::desde_canonica(&bytes).unwrap();
        assert_eq!(&vuelta, op, "ida y vuelta");
        assert_eq!(n, bytes.len(), "consume todos los bytes");
        assert_eq!(bytes[0], op.clase().byte(), "la clase va primero");
    }
}

#[test]
fn la_tx_v6_da_la_vuelta_por_el_wire() {
    for op in [
        post(2),
        OperacionAlmacenamiento::PoRep {
            clave: clave(1),
            epoch: 5,
            n_sectores: 3,
            raiz_conjunto: [1u8; 32],
            prueba: vec![9; 100],
        },
        OperacionAlmacenamiento::ClaveVoto {
            clave: clave(2),
            clave_bls: [3u8; LONGITUD_CLAVE_BLS],
            prueba_posesion: [4u8; LONGITUD_PRUEBA_POSESION_BLS],
        },
    ] {
        let tx = tx_v6(op);
        let testigos = testigos();
        let mut b = Vec::new();
        tx_a_bytes(&mut b, &tx, &testigos);
        let ((vuelta, t), resto) = tx_desde_bytes(&b).unwrap();
        assert_eq!(vuelta, tx, "ida y vuelta de la v6");
        assert_eq!(t, testigos);
        assert!(resto.is_empty());
    }
}

/// Casos 1–7 y 9 del diseño.
#[test]
fn los_rechazos_de_forma_de_la_v6_son_los_esperados() {
    // 1 · clase desconocida.
    let mut malo = post(1).bytes_canonicos().unwrap();
    malo[0] = 0x7f;
    assert!(matches!(
        OperacionAlmacenamiento::desde_canonica(&malo),
        Err(ErrorCodecAlmacenamiento::DiscriminanteInvalido(0x7f))
    ));

    // 2 · prueba vacía.
    let vacia = OperacionAlmacenamiento::PoSt {
        clave: clave(1),
        epoch: 1,
        n_sectores: 1,
        raiz_conjunto: [0; 32],
        prueba: Vec::new(),
    };
    assert!(matches!(
        vacia.bytes_canonicos(),
        Err(ErrorCodecAlmacenamiento::PruebaVacia)
    ));

    // 3 · prueba por encima del tope.
    let larga = OperacionAlmacenamiento::PoSt {
        clave: clave(1),
        epoch: 1,
        n_sectores: 1,
        raiz_conjunto: [0; 32],
        prueba: vec![0u8; MAX_PRUEBA_ALMACENAMIENTO_BYTES + 1],
    };
    assert!(matches!(
        larga.bytes_canonicos(),
        Err(ErrorCodecAlmacenamiento::PruebaDemasiadoLarga(_))
    ));

    // 4 · n_sectores = 0.
    assert!(matches!(
        post(0).bytes_canonicos(),
        Err(ErrorCodecAlmacenamiento::NumeroDeSectoresCero)
    ));

    // 5 · entradas o salidas ≠ 0.
    let mut tx = tx_v6(post(1));
    tx.inputs.push(zx_core::TxIn {
        outpoint: zx_core::OutPoint {
            prev_txid: zx_core::TxId::from_digest(zx_core::Digest::from_bytes([0; 32])),
            prev_index: 0,
        },
        sequence: 0,
    });
    assert!(matches!(
        validar_forma_tx(&tx, &testigos()),
        Err(ErrorFormaTx::SectorConEntradasOSalidas { entradas: 1, .. })
    ));

    // 6 · extensión incoherente.
    let mut incoherente = tx_v6(post(1));
    incoherente.extension = ExtensionTx::Ninguna;
    assert!(matches!(
        validar_forma_tx(&incoherente, &testigos()),
        Err(ErrorFormaTx::ExtensionIncoherente { version: 6, .. })
    ));

    // 7a · número de testigos inválido.
    assert!(matches!(
        validar_forma_tx(&tx_v6(post(1)), &[]),
        Err(ErrorFormaTx::NumeroDeTestigosInvalido { esperados: 1, .. })
    ));
    // 7b · testigo de longitud distinta de 64.
    assert!(matches!(
        validar_forma_tx(&tx_v6(post(1)), &[vec![0u8; 10]]),
        Err(ErrorFormaTx::TestigoAceptacionLongitud { obtenidos: 10 })
    ));

    // 9 · firma que no verifica (64 ceros bajo una clave cualquiera).
    let tx = tx_v6(post(1));
    assert!(
        verificar_firma_almacenamiento(&tx, &[0u8; 64], CBID).is_err(),
        "una firma nula no verifica"
    );
}

#[test]
fn la_v6_valida_pasa_la_forma() {
    let tx = tx_v6(post(1));
    assert!(validar_forma_tx(&tx, &testigos()).is_ok());
    // La variedad `ClaveVoto` también.
    let cv = tx_v6(OperacionAlmacenamiento::ClaveVoto {
        clave: clave(9),
        clave_bls: [0u8; LONGITUD_CLAVE_BLS],
        prueba_posesion: [0u8; LONGITUD_PRUEBA_POSESION_BLS],
    });
    assert!(validar_forma_tx(&cv, &testigos()).is_ok());
}

#[test]
fn el_txid_y_el_mensaje_de_firma_comprometen_la_operacion() {
    let a = tx_v6(post(1));
    let b = tx_v6(post(2));
    assert_ne!(zx_core::txid(&a, CBID), zx_core::txid(&b, CBID));
    assert_ne!(
        zx_core::mensaje_almacenamiento(&a, CBID),
        zx_core::mensaje_almacenamiento(&b, CBID)
    );
}

/// RE-2c · R3/C2′ · el `0x08` codifica la raíz de 32 B: la preimagen mide 281 B y la raíz va y
/// vuelve.
#[test]
fn t_raiz_04_08_codifica_la_raiz() {
    let op = voto_propio();
    let bytes = op.bytes_canonicos().unwrap();
    assert_eq!(bytes.len(), 281, "preimagen canónica del 0x08 con la raíz");
    let (vuelta, consumidos) = OperacionAlmacenamiento::desde_canonica(&bytes).unwrap();
    assert_eq!(consumidos, bytes.len());
    assert!(
        matches!(
            &vuelta,
            OperacionAlmacenamiento::VotoPropio { raiz_estado, .. } if *raiz_estado == [0x55; 32]
        ),
        "la raíz va y vuelve"
    );
}

/// RE-2c · R3/C2′ · un `0x08` con el formato viejo (sin los 32 B de raíz) se rechaza por forma
/// antes de mirar firmas.
#[test]
fn t_raiz_06_08_formato_viejo_se_rechaza() {
    let bytes = voto_propio().bytes_canonicos().unwrap();
    // Reparto del `0x08` nuevo: clase(1) + clave(32) + n(8) + candidato(32) + h_t(32) = 105 B;
    // raíz 105..137; clave_bls 137..185; firma 185..281. El viejo omitía la raíz.
    let mut viejo = Vec::new();
    viejo.extend_from_slice(&bytes[..105]);
    viejo.extend_from_slice(&bytes[137..]);
    assert_eq!(
        viejo.len(),
        249,
        "el formato viejo medía 249 B de preimagen"
    );
    assert!(
        OperacionAlmacenamiento::desde_canonica(&viejo).is_err(),
        "un 0x08 sin los 32 B de raíz se rechaza por forma"
    );
}
