//! Medición del primitivo Merkle: tiempo de verificación por solución y de construcción de las
//! raíces. Pensado para ejecutarse con el candado **exclusivo** de la máquina (clase M) y volcar su
//! salida a `MEDIDA.log`.

#![allow(
    clippy::indexing_slicing,
    reason = "slices internos de anchura fija acotados por construcción"
)]

use std::hint::black_box;
use std::time::Instant;

use zx_merkle::{
    ErrorMerkle, HOJAS_POR_REGISTRO, REGISTROS_POR_SEGMENTO, TestigoChunk, TestigoRegistro,
    TestigoSolucion, camino_chunk, camino_registro, construir_registro, construir_segmento,
    verificar_chunk, verificar_registro, verificar_solucion,
};

/// Número de verificaciones por configuración.
const N: usize = 200_000;

fn hojas(i: usize) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&(i as u64).to_le_bytes());
    h[8..16].copy_from_slice(&((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes());
    h
}

fn resumen(mut muestras: Vec<u64>) -> (u64, u64, u64) {
    muestras.sort_unstable();
    let n = muestras.len();
    let min = *muestras.first().unwrap_or(&0);
    let mediana = *muestras.get(n >> 1).unwrap_or(&0);
    let media = if n == 0 {
        0
    } else {
        muestras.iter().copied().sum::<u64>().div_euclid(n as u64)
    };
    (min, mediana, media)
}

fn main() -> Result<(), ErrorMerkle> {
    let chunks: Vec<[u8; 32]> = (0..HOJAS_POR_REGISTRO).map(hojas).collect();
    let inicio_registro = Instant::now();
    let registro = construir_registro(&chunks)?;
    let construccion_registro = inicio_registro.elapsed();

    let mut compromisos: Vec<[u8; 32]> = (0..REGISTROS_POR_SEGMENTO)
        .map(|i| hojas(i + HOJAS_POR_REGISTRO))
        .collect();
    if let Some(primero) = compromisos.first_mut() {
        *primero = registro.0;
    }
    let inicio_segmento = Instant::now();
    let segmento = construir_segmento(&compromisos)?;
    let construccion_segmento = inicio_segmento.elapsed();

    let s_bucket: u32 = 23_412 % (HOJAS_POR_REGISTRO as u32);
    let position: u32 = 0;
    let chunk = chunks.get(s_bucket as usize).copied().unwrap_or([0u8; 32]);
    let testigo_chunk: TestigoChunk = camino_chunk(&chunks, s_bucket)?;
    let testigo_registro: TestigoRegistro = camino_registro(&compromisos, position)?;
    let testigo = TestigoSolucion {
        chunk: testigo_chunk,
        registro: testigo_registro,
    };

    // Calentamiento (JIT/rampa de caché) antes de medir.
    for _ in 0..2_000 {
        let _ = verificar_solucion(
            &testigo,
            &chunk,
            &registro.0,
            s_bucket,
            position,
            &registro,
            &segmento,
        );
    }

    let mut m_solucion = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        let r = verificar_solucion(
            black_box(&testigo),
            black_box(&chunk),
            black_box(&registro.0),
            black_box(s_bucket),
            black_box(position),
            black_box(&registro),
            black_box(&segmento),
        );
        let d = t.elapsed();
        black_box(r.is_ok());
        m_solucion.push(d.as_nanos() as u64);
    }

    let mut m_chunk = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        let r = verificar_chunk(
            black_box(s_bucket),
            black_box(&chunk),
            black_box(&testigo.chunk),
            black_box(&registro),
        );
        let d = t.elapsed();
        black_box(r.is_ok());
        m_chunk.push(d.as_nanos() as u64);
    }

    let mut m_registro = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        let r = verificar_registro(
            black_box(position),
            black_box(&registro.0),
            black_box(&testigo.registro),
            black_box(&segmento),
        );
        let d = t.elapsed();
        black_box(r.is_ok());
        m_registro.push(d.as_nanos() as u64);
    }

    let (s_min, s_med, s_media) = resumen(m_solucion);
    let (c_min, c_med, c_media) = resumen(m_chunk);
    let (r_min, r_med, r_media) = resumen(m_registro);

    println!("zx_merkle n_chunks={HOJAS_POR_REGISTRO} n_registros={REGISTROS_POR_SEGMENTO} n={N}");
    println!(
        "construir_registro_ms={}",
        construccion_registro.as_secs_f64() * 1e3
    );
    println!(
        "construir_segmento_ms={}",
        construccion_segmento.as_secs_f64() * 1e3
    );
    println!("verificar_solucion_ns min={s_min} mediana={s_med} media={s_media}");
    println!("verificar_chunk_ns min={c_min} mediana={c_med} media={c_media}");
    println!("verificar_registro_ns min={r_min} mediana={r_med} media={r_media}");
    println!(
        "tamano_testigo_b={}",
        TestigoSolucion::a_bytes(&testigo).len()
    );

    Ok(())
}
