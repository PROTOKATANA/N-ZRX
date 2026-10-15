//! KV-1 — memoria de claves públicas BLS ya validadas: pruebas 1, 2, 4 y base de los controles rojos.
//!
//! La prueba del tope (`memoria_respeta_el_tope`, prueba 3 de la orden) vive como test unitario en
//! `crates/zx-bls/src/clave.rs`: necesita la función interna `desde_bytes_con_memoria_tope`, que no
//! es pública fuera del crate.
#![allow(
    clippy::indexing_slicing,
    reason = "el test 4 recorre indices acotados por `% bytes.len()` y el peor caso no existe aqui"
)]

use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};

use zx_bls::{ClavePublica, ClaveSecreta, ErrorBLS, LONGITUD_CLAVE_PUBLICA};

/// Clave pública válida y distinta por índice (semilla fija).
fn valida(i: u32) -> Result<ClavePublica, ErrorBLS> {
    let mut ikm = [0u8; 32];
    ikm[..4].copy_from_slice(&i.to_le_bytes());
    ikm[31] = 0xA7;
    Ok(ClaveSecreta::generar(&ikm)?.clave_publica())
}

/// Primer vector de G1 del fichero oficial ya presente cuyo rechazo menciona `aguja`.
fn vector_con_motivo(aguja: &str) -> Option<Vec<u8>> {
    let vectores = include_str!("vectores/deserialization_g1.txt");
    for linea in vectores.lines() {
        let campos: Vec<&str> = linea.split('\t').collect();
        if campos.len() != 2 {
            continue;
        }
        let bytes = match campos[1].strip_prefix("0x") {
            Some(sin) => hex::decode(sin),
            None => hex::decode(campos[1]),
        };
        let Ok(bytes) = bytes else { continue };
        if let Err(error) = ClavePublica::desde_bytes(&bytes)
            && error.to_string().contains(aguja)
        {
            return Some(bytes);
        }
    }
    None
}

/// Bytes del punto del infinito en G1 (`0xc0` y 47 ceros).
fn infinito_g1() -> Vec<u8> {
    let mut bytes = vec![0u8; LONGITUD_CLAVE_PUBLICA];
    bytes[0] = 0xc0;
    bytes
}

/// Prueba 1: 2 000 claves válidas distintas, cada una pedida tres veces intercaladas; todo resultado
/// es igual byte a byte al de `desde_bytes`.
#[test]
fn memoria_devuelve_lo_mismo_que_desde_bytes() -> Result<(), ErrorBLS> {
    let claves: Vec<ClavePublica> = (0..2_000).map(valida).collect::<Result<_, _>>()?;
    for _ in 0..3 {
        for (i, clave) in claves.iter().enumerate() {
            let bytes = clave.bytes();
            let con_memoria = ClavePublica::desde_bytes_con_memoria(&bytes)?;
            let directa = ClavePublica::desde_bytes(&bytes)?;
            assert_eq!(con_memoria, directa, "difiere la clave {i}");
            assert_eq!(
                con_memoria.bytes(),
                directa.bytes(),
                "difieren los bytes de la clave {i}"
            );
        }
    }
    Ok(())
}

/// Prueba 2: ni la longitud distinta de 48, ni 48 bytes que no son un punto, ni un punto fuera del
/// subgrupo, ni el punto del infinito se guardan: el mismo error que `desde_bytes`, tres veces
/// seguidas (si se guardara un acierto, la segunda o la tercera devolverían `Ok`).
#[test]
fn memoria_no_guarda_errores() -> Result<(), ErrorBLS> {
    let mut casos: Vec<Vec<u8>> = Vec::new();
    casos.push(vec![0u8; LONGITUD_CLAVE_PUBLICA - 1]); // longitud 47
    casos.push(vec![0u8; LONGITUD_CLAVE_PUBLICA + 1]); // longitud 49
    casos.push(vec![0u8; LONGITUD_CLAVE_PUBLICA]); // 48 bytes que no son un punto de la curva
    match vector_con_motivo("subgrupo") {
        Some(fuera) => casos.push(fuera),
        None => println!("AVISO KV-1: el fichero de vectores no trae un punto fuera del subgrupo"),
    }
    casos.push(infinito_g1()); // el punto del infinito

    for (i, bytes) in casos.iter().enumerate() {
        let esperado = ClavePublica::desde_bytes(bytes);
        assert!(
            esperado.is_err(),
            "el caso {i} no es un error de desde_bytes"
        );
        let primero = ClavePublica::desde_bytes_con_memoria(bytes);
        let segundo = ClavePublica::desde_bytes_con_memoria(bytes);
        let tercero = ClavePublica::desde_bytes_con_memoria(bytes);
        assert_eq!(primero, esperado, "el caso {i} difiere de desde_bytes");
        assert_eq!(segundo, esperado, "el caso {i} se guardo como acierto (2a)");
        assert_eq!(tercero, esperado, "el caso {i} se guardo como acierto (3a)");
    }
    Ok(())
}

/// Prueba 4: 8 hilos piden a la vez las mismas 512 claves en órdenes distintos; todos los
/// resultados coinciden con los de `desde_bytes`.
#[test]
fn memoria_con_hilos() -> Result<(), ErrorBLS> {
    let claves: Vec<ClavePublica> = (0..512).map(valida).collect::<Result<_, _>>()?;
    let bytes: Vec<[u8; LONGITUD_CLAVE_PUBLICA]> = claves.iter().map(ClavePublica::bytes).collect();
    let esperados: Vec<ClavePublica> = bytes
        .iter()
        .map(|b| ClavePublica::desde_bytes(b))
        .collect::<Result<_, _>>()?;

    let barrera = Barrier::new(8);
    let fallo = AtomicBool::new(false);
    std::thread::scope(|alcance| {
        for hilo in 0..8usize {
            let bytes = &bytes;
            let esperados = &esperados;
            let barrera = &barrera;
            let fallo = &fallo;
            alcance.spawn(move || {
                barrera.wait();
                for paso in 0..bytes.len() {
                    let indice = (paso * 37 + hilo * 131) % bytes.len();
                    let Ok(con_memoria) = ClavePublica::desde_bytes_con_memoria(&bytes[indice])
                    else {
                        fallo.store(true, Ordering::SeqCst);
                        return;
                    };
                    if con_memoria != esperados[indice] {
                        fallo.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            });
        }
    });
    assert!(
        !fallo.load(Ordering::SeqCst),
        "algun hilo obtuvo un resultado distinto de desde_bytes"
    );
    Ok(())
}
