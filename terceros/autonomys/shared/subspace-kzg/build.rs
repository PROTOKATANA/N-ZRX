//! Reconstruye `eth-public-parameters.bin` (los parámetros públicos KZG de la ceremonia de Ethereum) a partir
//! de su copia en hexadecimal: el repositorio de ZEROX no versiona archivos binarios. Cambio de ZEROX sobre el
//! crate original de Autonomys; ver `terceros/autonomys/README.md`.

use std::path::PathBuf;
use std::{env, fs};

/// Tamaño exacto del archivo original, para detectar una copia en texto incompleta o alterada.
const TAMANO: usize = 1_579_104;

fn main() {
    let origen = "src/eth-public-parameters.hex";
    println!("cargo::rerun-if-changed={origen}");
    let texto = fs::read_to_string(origen).expect("leer los parámetros KZG en hexadecimal");
    let cifras: Vec<u8> = texto.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(
        cifras.len() % 2 == 0,
        "los parámetros KZG en hexadecimal tienen un número impar de cifras"
    );
    let bytes: Vec<u8> = cifras
        .chunks_exact(2)
        .map(|par| (valor(par[0]) << 4) | valor(par[1]))
        .collect();
    assert_eq!(
        bytes.len(),
        TAMANO,
        "los parámetros KZG reconstruidos no tienen el tamaño del original"
    );
    let destino = PathBuf::from(env::var("OUT_DIR").expect("Cargo define OUT_DIR"))
        .join("eth-public-parameters.bin");
    fs::write(destino, bytes).expect("escribir los parámetros KZG reconstruidos");
}

fn valor(cifra: u8) -> u8 {
    match cifra {
        b'0'..=b'9' => cifra - b'0',
        b'a'..=b'f' => cifra - b'a' + 10,
        b'A'..=b'F' => cifra - b'A' + 10,
        _ => panic!(
            "carácter no hexadecimal en los parámetros KZG: {}",
            cifra as char
        ),
    }
}
