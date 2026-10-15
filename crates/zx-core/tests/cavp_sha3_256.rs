//! Conformidad con FIPS 202 contra los vectores oficiales del NIST (C-HASH-02).
//!
//! Esta suite es la que separa **SHA3-256 de Keccak-256**. Difieren en un solo byte de dominio
//! (`0x06` vs `0x01`) y producen digests no relacionados. El kernel GPU heredado implementa
//! `KECCAK-p[1600,24]` crudo, sin padding ni separación de dominio, y **falla los 237 vectores** —
//! ese es el hallazgo H-001. Si esta suite se rompe, no se sigue: se arregla.
//!
//! Vectores en `testdata/nist-cavp/`, cabecera `CAVS 19.0`, generados 2016-01-28.
//!
//! # Dos trampas del formato, ambas comprobadas
//!
//! 1. **`Len` está en bits, no en bytes.** `nbytes = Len / 8`.
//! 2. **Con `Len = 0`, el campo `Msg = 00` es relleno de formato, no un byte real.** El mensaje es
//!    la cadena vacía. Tratarlo literalmente da `SHA3-256([0x00])`, que resulta ser el digest
//!    esperado del vector `Len = 8` — así que el error pasaría un test comparándose contra el
//!    vector equivocado, en silencio.
//!
//! El fichero `SHA3_256ShortMsg_bitoriented.rsp` **no se usa aquí**: sus mensajes tienen longitudes
//! que no son múltiplo de 8, y ZEROX solo hashea bytes completos. No es cobertura que falte, es
//! cobertura que no aplica.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "un test falla con panic por diseño"
)]
#![expect(clippy::expect_used, reason = "ídem")]

use sha3::{Digest as _, Sha3_256};

/// Un registro del `.rsp`, con el número de línea para poder abrir el fichero por ahí.
struct Vector {
    len_bits: usize,
    msg_hex: String,
    md_hex: String,
    linea: usize,
}

fn ruta(nombre: &str) -> String {
    format!(
        "{}/../../testdata/nist-cavp/{nombre}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn parsear(nombre: &str) -> Vec<Vector> {
    let texto = std::fs::read_to_string(ruta(nombre))
        .unwrap_or_else(|e| panic!("no se pudo leer {nombre}: {e}"));

    let mut vectores = Vec::new();
    let (mut len, mut msg, mut linea_len) = (None, None, 0usize);

    for (i, cruda) in texto.lines().enumerate() {
        let l = cruda.trim();
        if let Some(v) = l.strip_prefix("Len = ") {
            len = Some(v.trim().parse::<usize>().unwrap());
            linea_len = i + 1;
        } else if let Some(v) = l.strip_prefix("Msg = ") {
            msg = Some(v.trim().to_owned());
        } else if let Some(v) = l.strip_prefix("MD = ")
            && let (Some(len_bits), Some(msg_hex)) = (len.take(), msg.take())
        {
            vectores.push(Vector {
                len_bits,
                msg_hex,
                md_hex: v.trim().to_owned(),
                linea: linea_len,
            });
        }
    }
    assert!(!vectores.is_empty(), "{nombre}: no se parseó ningún vector");
    vectores
}

/// Ejecuta un fichero completo y **acumula todos los fallos** antes de abortar.
///
/// Abortar en el primero sería peor: un error sistemático —una confusión de endianness, o Keccak en
/// vez de SHA-3— rompe los 237 de golpe, y conviene verlo de un vistazo en vez de ir uno a uno.
fn correr(nombre: &str, esperados: usize) {
    let vectores = parsear(nombre);
    assert_eq!(
        vectores.len(),
        esperados,
        "{nombre}: se esperaban {esperados} vectores y se parsearon {}. \
         ¿Se cambió el fichero de test?",
        vectores.len()
    );

    let mut fallos = Vec::new();
    for v in &vectores {
        assert_eq!(
            v.len_bits % 8,
            0,
            "{nombre} línea {}: Len={} no es múltiplo de 8. Este es un fichero byte-oriented; \
             si aparece esto, se está leyendo el bit-oriented por error.",
            v.linea,
            v.len_bits
        );

        // La trampa del Len = 0: `Msg = 00` es relleno, el mensaje es vacío.
        let msg = if v.len_bits == 0 {
            Vec::new()
        } else {
            hex::decode(&v.msg_hex).unwrap()
        };
        assert_eq!(
            msg.len() * 8,
            v.len_bits,
            "{nombre} línea {}: longitud incoherente",
            v.linea
        );

        let obtenido = hex::encode(Sha3_256::digest(&msg));
        if obtenido != v.md_hex {
            fallos.push(format!(
                "  línea {:>6}  Len={:<7}  esperado {}  obtenido {}",
                v.linea, v.len_bits, v.md_hex, obtenido
            ));
        }
    }

    assert!(
        fallos.is_empty(),
        "{nombre}: {} de {} vectores fallaron (C-HASH-02)\n{}",
        fallos.len(),
        vectores.len(),
        fallos.join("\n")
    );
}

#[test]
fn cavp_short_msg() {
    correr("SHA3_256ShortMsg.rsp", 137);
}

#[test]
fn cavp_long_msg() {
    correr("SHA3_256LongMsg.rsp", 100);
}

/// Monte Carlo — **la mecánica de SHA-3 no es la de SHA-1/SHA-2**.
///
/// Aquí es simplemente `md = SHA3-256(md)` mil veces por cada `COUNT`, sin combinar los tres
/// digests anteriores para rellenar un bloque de longitud fija: la esponja no lo necesita, porque
/// el mensaje no tiene que tener longitud fija. Portar el MCT de SHA-2 aquí produciría 0/100.
#[test]
fn cavp_monte_carlo() {
    let texto = std::fs::read_to_string(ruta("SHA3_256Monte.rsp"))
        .unwrap_or_else(|e| panic!("no se pudo leer el Monte Carlo: {e}"));

    let mut seed: Option<Vec<u8>> = None;
    let mut esperados: Vec<(usize, String)> = Vec::new();
    let mut count = None;

    for l in texto.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("Seed = ") {
            seed = Some(hex::decode(v.trim()).unwrap());
        } else if let Some(v) = l.strip_prefix("COUNT = ") {
            count = Some(v.trim().parse::<usize>().unwrap());
        } else if let Some(v) = l.strip_prefix("MD = ")
            && let Some(c) = count.take()
        {
            esperados.push((c, v.trim().to_owned()));
        }
    }

    let seed = seed.expect("el fichero Monte Carlo no traía Seed");
    assert_eq!(esperados.len(), 100, "se esperaban 100 checkpoints COUNT");

    let mut md = seed;
    let mut fallos = Vec::new();
    for (c, esperado) in &esperados {
        for _ in 0..1000 {
            md = Sha3_256::digest(&md).to_vec();
        }
        let obtenido = hex::encode(&md);
        if &obtenido != esperado {
            fallos.push(format!(
                "  COUNT={c}  esperado {esperado}  obtenido {obtenido}"
            ));
        }
    }

    assert!(
        fallos.is_empty(),
        "Monte Carlo: {} de 100 checkpoints fallaron (C-HASH-02)\n{}",
        fallos.len(),
        fallos.join("\n")
    );
}

/// El ancla de cordura, aislada: si solo falla esta, es Keccak-256 y no SHA3-256 (H-001).
#[test]
fn ancla_mensaje_vacio() {
    let d = hex::encode(Sha3_256::digest(b""));
    assert_eq!(
        d, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "si obtienes c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 \
         estás usando Keccak-256 (dominio 0x01), no SHA3-256 (0x06). Es H-001."
    );
}
