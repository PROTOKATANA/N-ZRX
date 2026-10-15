//! KV-1 · banco A: `desde_bytes` frente a `desde_bytes_con_memoria` en frío y en caliente, y el peor
//! caso de la memoria (262 144 claves distintas, el doble del tope, que obliga a vaciarla y
//! rellenarla en cada ronda).
//!
//! Se ejecuta a mano, en `--release` y en el bloque 0:
//!
//! ```text
//! KV1_REPS=15 cargo test --release -p zx-bls --test banco_kv1 -- --ignored --nocapture
//! ```
//!
//! Emite una línea `KV1 SAMPLE FASE <fase> N <n> REP <rep> ns <ns>` por muestra y un
//! `KV1 RESUMEN ... min/mediana/max` por configuración. La definición de «frío» está en
//! `PROGRESO.md`: cada muestra fría usa claves nuevas y disjuntas (nunca antes validadas), porque la
//! memoria no tiene reset público y no se añade API para el banco.
#![allow(
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "el banco solo mide y comprueba; los indices y la carga 7/8 se calculan a mano"
)]

use std::collections::BTreeMap;
use std::time::Instant;

use zx_bls::{ClavePublica, ClaveSecreta, ErrorBLS, MEMORIA_CLAVES_MAX};

/// Claves públicas distintas para los escalares `desde+1 ..= desde+n`.
fn claves_distintas(desde: u64, n: usize) -> Result<Vec<ClavePublica>, ErrorBLS> {
    let mut salida = Vec::with_capacity(n);
    for i in 0..n {
        let escalar = desde + i as u64 + 1;
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&escalar.to_be_bytes());
        let secreta = ClaveSecreta::desde_bytes(&bytes)?;
        salida.push(secreta.clave_publica());
    }
    Ok(salida)
}

fn lista(ns: &str) -> Vec<usize> {
    ns.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

fn variable(nombre: &str, por_defecto: &str) -> String {
    std::env::var(nombre).unwrap_or_else(|_| por_defecto.to_string())
}

/// Cuenta exacta de la memoria llena: llena un mapa local con `MEMORIA_CLAVES_MAX` entradas del
/// mismo par (clave de 48 B, valor ya validado) y devuelve `(entradas, capacidad, cubos)`.
///
/// `cubos = capacidad * 8 / 7` es la relacion de carga de `hashbrown` (el mapa del crate usa el
/// mismo `HashMap` de `std`). Bytes asignados ≈ `cubos * (size_of::<([u8;48], ClavePublica)>() + 1)`.
fn cuenta_memoria_llena() -> (usize, usize, usize) {
    let mut mapa: std::collections::HashMap<[u8; 48], ClavePublica> =
        std::collections::HashMap::new();
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let Ok(secreta) = ClaveSecreta::desde_bytes(&bytes) else {
        return (0, 0, 0);
    };
    let clave = secreta.clave_publica();
    for i in 0..MEMORIA_CLAVES_MAX {
        let mut entrada = [0u8; 48];
        entrada[..8].copy_from_slice(&(i as u64).to_le_bytes());
        mapa.insert(entrada, clave);
    }
    let capacidad = mapa.capacity();
    let cubos = capacidad / 7 * 8;
    (mapa.len(), capacidad, cubos)
}

/// Una pasada de `desde_bytes_con_memoria` sobre `claves`; devuelve los ns.
fn pasada_memoria(claves: &[ClavePublica]) -> u128 {
    let inicio = Instant::now();
    for clave in claves {
        let bytes = clave.bytes();
        let resultado = ClavePublica::desde_bytes_con_memoria(&bytes);
        assert_eq!(
            resultado.ok(),
            Some(*clave),
            "resultado distinto de desde_bytes"
        );
    }
    inicio.elapsed().as_nanos()
}

/// Una pasada de `desde_bytes` sobre `claves`; devuelve los ns.
fn pasada_directa(claves: &[ClavePublica]) -> u128 {
    let inicio = Instant::now();
    for clave in claves {
        let bytes = clave.bytes();
        let resultado = ClavePublica::desde_bytes(&bytes);
        assert_eq!(
            resultado.ok(),
            Some(*clave),
            "desde_bytes fallo en una clave valida"
        );
    }
    inicio.elapsed().as_nanos()
}

#[test]
#[ignore = "KV-1: banco de medida; se ejecuta a mano con KV1_NS/KV1_REPS"]
fn banco_kv1() -> Result<(), ErrorBLS> {
    let ns = lista(&variable("KV1_NS", "1000,4096,16384,65536"));
    let reps: usize = variable("KV1_REPS", "15").parse().unwrap_or(15);
    let peor: usize = variable("KV1_PEOR", "262144").parse().unwrap_or(262_144);

    println!(
        "KV1 HDR reps {reps} ns {} peor {peor} tope {MEMORIA_CLAVES_MAX}",
        ns.iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "KV1 TAMANOS size_clave_publica {} size_entrada {} size_valor {}",
        std::mem::size_of::<ClavePublica>(),
        std::mem::size_of::<[u8; 48]>(),
        std::mem::size_of::<ClavePublica>(),
    );
    let (llenas, capacidad, cubos) = cuenta_memoria_llena();
    let por_cubo = std::mem::size_of::<([u8; 48], ClavePublica)>() + 1;
    println!(
        "KV1 MEMORIA llena entradas {llenas} capacidad {capacidad} cubos {cubos} \
         bytes_por_cubo {por_cubo} bytes_totales {}",
        cubos * por_cubo
    );

    let mut muestras: BTreeMap<String, Vec<u128>> = BTreeMap::new();
    let mut semilla: u64 = 10_000;

    for &n in &ns {
        // Conjunto base: se usa para `desde_bytes` y para la pasada caliente.
        let base = claves_distintas(semilla, n)?;
        semilla += n as u64 + 1;

        for rep in 0..reps {
            let ns_directa = pasada_directa(&base);
            println!("KV1 SAMPLE FASE desde_bytes N {n} REP {rep} ns {ns_directa}");
            muestras
                .entry(format!("desde_bytes N {n}"))
                .or_default()
                .push(ns_directa);
        }

        for rep in 0..reps {
            let nuevas = claves_distintas(semilla, n)?;
            semilla += n as u64 + 1;
            let ns_fria = pasada_memoria(&nuevas);
            println!("KV1 SAMPLE FASE frio N {n} REP {rep} ns {ns_fria}");
            muestras
                .entry(format!("frio N {n}"))
                .or_default()
                .push(ns_fria);
        }

        // Tres pasadas de calentamiento (fuera del cronometro): dos bastan para que la memoria
        // contenga el conjunto base aunque una se vaciara a mitad.
        for _ in 0..3 {
            let _ = pasada_memoria(&base);
        }
        for rep in 0..reps {
            let ns_caliente = pasada_memoria(&base);
            println!("KV1 SAMPLE FASE caliente N {n} REP {rep} ns {ns_caliente}");
            muestras
                .entry(format!("caliente N {n}"))
                .or_default()
                .push(ns_caliente);
        }
    }

    if peor > 0 {
        let peor_claves = claves_distintas(semilla, peor)?;
        for rep in 0..reps {
            let ns_directa = pasada_directa(&peor_claves);
            println!("KV1 SAMPLE FASE desde_bytes N {peor} REP {rep} ns {ns_directa}");
            muestras
                .entry(format!("desde_bytes N {peor}"))
                .or_default()
                .push(ns_directa);
        }
        for rep in 0..reps {
            let ns_peor = pasada_memoria(&peor_claves);
            println!("KV1 SAMPLE FASE peor_memoria N {peor} REP {rep} ns {ns_peor}");
            muestras
                .entry(format!("peor_memoria N {peor}"))
                .or_default()
                .push(ns_peor);
        }
    }

    for (configuracion, valores) in &muestras {
        let mut orden = valores.clone();
        orden.sort_unstable();
        let min = orden.first().copied().unwrap_or(0);
        let max = orden.last().copied().unwrap_or(0);
        let mediana = if orden.is_empty() {
            0
        } else {
            orden[orden.len() / 2]
        };
        println!(
            "KV1 RESUMEN {configuracion} reps {} min_ns {min} mediana_ns {mediana} max_ns {max}",
            orden.len()
        );
    }
    println!("KV1 FIN");
    Ok(())
}
