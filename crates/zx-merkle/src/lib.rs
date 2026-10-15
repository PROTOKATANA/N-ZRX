//! Árboles de Merkle binarios del PoAS transparente (B-21, PK-09).
//!
//! # Qué sustituye
//!
//! El PoAS heredado abre dos pruebas KZG de pertenencia por solución:
//!
//! 1. **chunk → registro**: el `chunk` cae en uno de los `Record::NUM_S_BUCKETS = 2¹⁶` s-buckets
//!    del registro (`subspace-verification/src/lib.rs:263`).
//! 2. **registro → segmento**: la raíz del registro ocupa una de las
//!    `ArchivedHistorySegment::NUM_PIECES = 2⁸` hojas del segmento (`…/lib.rs:336,419`).
//!
//! Este crate implementa las dos aperturas como **caminos de Merkle binarios** con SHA3-256 y
//! separación de dominio (`h_d`, C-HASH-04), con las decisiones de `REVISION-PT2a-D.md`:
//!
//! - **D2**: dominio del árbol `chunk → registro` de `2¹⁶` s-buckets (fuente y paridad).
//! - **D3**: SHA3-256 con dominio `h_d` (la misma familia de hash del consenso de ZEROX).
//! - **D4**: hoja del árbol de segmento = `H_d(raíz del registro)`.
//! - **Formato wire**: testigo de **tamaño fijo**, 16 hermanos × 32 B + 8 hermanos × 32 B =
//!   **768 B** por solución.
//!
//! # Qué NO es
//!
//! Es el **primitivo** de pertenencia, aislado: **no** cablea el tipo de la solución, **no** toca
//! `subspace-verification`, `subspace-archiving` ni `zx-poas`, y por tanto **no** retira KZG del
//! camino de consenso por sí solo. La integración (traer los crates heredados al workspace y
//! cambiar el wire de `zx-core`, `zx-poas`, `zx-farmer`, `zx-post` y `zx-node`) exige propiedad
//! sobre archivos de otros carriles: ver `PROGRESO.md` §2 y `INFORME.md`.
//!
//! # Estructura de los dos árboles
//!
//! - **Registro** (profundidad 16). Las hojas son `H_d("ZZKPoasHojaChunk", chunk_i)`. El
//!   verificador **recomputa** la hoja desde el `chunk` (o desde `chunk ⊕ proof_of_space.hash()`;
//!   la elección de la preimagen es del cableado, no de este primitivo).
//! - **Segmento** (profundidad 8). Las hojas son `H_d("ZZKPoasHojaSegmt", record_commitment_j)`,
//!   es decir, `H_d(raíz del registro)` (D4).
//! - Nodos internos: `H_d("ZZKPoasNodoMerkl", izquierda ‖ derecha)`.
//! - Relleno a potencia de dos con la hoja vacía `H_d("ZZKPoasHojaVacia", "")`.
//!
//! Etiquetas nuevas de la tabla C-HASH-06 (16 B ASCII, sin prefijo compartido con `ZZKTxIdHash_`):
//! `ZZKPoasHojaChunk`, `ZZKPoasHojaSegmt`, `ZZKPoasNodoMerkl`, `ZZKPoasHojaVacia`. Añadirlas al
//! consenso es un cambio C-HASH-05 y es parte del paso de integración.

use sha3::{Digest as _, Sha3_256};

/// Tamaño de cada hoja y de cada digest, en bytes.
pub const TAMANO_HOJA: usize = 32;

/// Profundidad del árbol `chunk → registro` (D2): `log2(2¹⁶)`.
pub const PROFUNDIDAD_REGISTRO: usize = 16;

/// Profundidad del árbol `registro → segmento`: `log2(2⁸)`.
pub const PROFUNDIDAD_SEGMENTO: usize = 8;

/// Hojas del árbol `chunk → registro`: `Record::NUM_S_BUCKETS = 2¹⁶`.
pub const HOJAS_POR_REGISTRO: usize = 1 << PROFUNDIDAD_REGISTRO;

/// Hojas del árbol `registro → segmento`: `ArchivedHistorySegment::NUM_PIECES = 2⁸`.
pub const REGISTROS_POR_SEGMENTO: usize = 1 << PROFUNDIDAD_SEGMENTO;

/// Bytes del testigo `chunk → registro`: `16 × 32 = 512`.
pub const TAMANO_TESTIGO_CHUNK: usize = PROFUNDIDAD_REGISTRO * TAMANO_HOJA;

/// Bytes del testigo `registro → segmento`: `8 × 32 = 256`.
pub const TAMANO_TESTIGO_REGISTRO: usize = PROFUNDIDAD_SEGMENTO * TAMANO_HOJA;

/// Bytes del testigo por solución: `512 + 256 = **768**`.
pub const TAMANO_TESTIGO_SOLUCION: usize = TAMANO_TESTIGO_CHUNK + TAMANO_TESTIGO_REGISTRO;

/// Etiqueta de la hoja `chunk → registro`.
pub const TAG_HOJA_CHUNK: [u8; 16] = *b"ZZKPoasHojaChunk";
/// Etiqueta de la hoja `registro → segmento` (D4: `H_d(raíz del registro)`).
pub const TAG_HOJA_SEGMENTO: [u8; 16] = *b"ZZKPoasHojaSegmt";
/// Etiqueta del nodo interno del árbol de Merkle.
pub const TAG_NODO_MERKLE: [u8; 16] = *b"ZZKPoasNodoMerkl";
/// Etiqueta de la hoja vacía usada para rellenar a potencia de dos.
pub const TAG_HOJA_VACIA: [u8; 16] = *b"ZZKPoasHojaVacia";

/// Ancho del camino (`TAMANO_TESTIGO_SOLUCION` comprobado en compilación).
const _: () = assert!(TAMANO_TESTIGO_SOLUCION == 768);
const _: () = assert!(TAMANO_TESTIGO_CHUNK == 512);
const _: () = assert!(TAMANO_TESTIGO_REGISTRO == 256);

/// Hash con dominio `H_d(tag ‖ msg) = SHA3-256(tag ‖ msg)` (C-HASH-04).
#[must_use]
pub fn h_d(tag: [u8; 16], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(tag);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Nodo interno: `H_d(TAG_NODO_MERKLE ‖ izquierda ‖ derecha)`.
#[must_use]
pub fn nodo(izquierda: &[u8; 32], derecha: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(TAG_NODO_MERKLE);
    hasher.update(izquierda);
    hasher.update(derecha);
    hasher.finalize().into()
}

/// Hoja vacía del relleno a potencia de dos: `H_d(TAG_HOJA_VACIA, "")`.
#[must_use]
pub fn hoja_vacia() -> [u8; 32] {
    h_d(TAG_HOJA_VACIA, b"")
}

/// Hoja del árbol `chunk → registro` a partir del `chunk` (32 B).
#[must_use]
pub fn hoja_de_chunk(chunk: &[u8; 32]) -> [u8; 32] {
    h_d(TAG_HOJA_CHUNK, chunk)
}

/// Hoja del árbol `registro → segmento` a partir de la raíz del registro (D4).
#[must_use]
pub fn hoja_de_segmento(record_commitment: &[u8; 32]) -> [u8; 32] {
    h_d(TAG_HOJA_SEGMENTO, record_commitment)
}

/// Error del primitivo de Merkle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorMerkle {
    /// El árbol no tiene hojas (`n = 0`).
    #[error("el árbol de Merkle no tiene hojas")]
    SinHojas,
    /// Índice fuera del rango de hojas.
    #[error("índice {indice} fuera de rango para {n} hojas")]
    IndiceFueraDeRango {
        /// Índice consultado.
        indice: usize,
        /// Número de hojas del nivel (potencia de dos).
        n: usize,
    },
    /// El camino no mide la profundidad del árbol.
    #[error("longitud de camino incorrecta: esperada {esperada}, recibida {recibida}")]
    LongitudCaminoIncorrecta {
        /// Profundidad esperada, en hermanos.
        esperada: usize,
        /// Hermanos recibidos.
        recibida: usize,
    },
    /// La lista de hojas no tiene el tamaño exacto del nivel.
    #[error("longitud de hojas incorrecta: esperada {esperada}, recibida {recibida}")]
    LongitudIncorrecta {
        /// Tamaño esperado.
        esperada: usize,
        /// Tamaño recibido.
        recibida: usize,
    },
    /// La apertura no reconstruye el compromiso.
    #[error("la apertura no reconstruye el compromiso de Merkle")]
    PertenenciaFallida,
}

/// Compromiso de registro: raíz del árbol `chunk → registro` (32 B).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompromisoRegistro(pub [u8; 32]);

/// Compromiso de segmento: raíz del árbol `registro → segmento` (32 B).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompromisoSegmento(pub [u8; 32]);

/// Testigo `chunk → registro`: 16 hermanos de 32 B = 512 B.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TestigoChunk(pub [u8; TAMANO_TESTIGO_CHUNK]);

/// Testigo `registro → segmento`: 8 hermanos de 32 B = 256 B.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TestigoRegistro(pub [u8; TAMANO_TESTIGO_REGISTRO]);

/// Testigo por solución: array fijo de **768 B** (512 B de chunk + 256 B de registro).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TestigoSolucion {
    /// Camino `chunk → registro` (512 B).
    pub chunk: TestigoChunk,
    /// Camino `registro → segmento` (256 B).
    pub registro: TestigoRegistro,
}

impl TestigoSolucion {
    /// Serializa el testigo al array fijo de 768 B del wire.
    #[must_use]
    pub fn a_bytes(&self) -> [u8; TAMANO_TESTIGO_SOLUCION] {
        let mut out = [0u8; TAMANO_TESTIGO_SOLUCION];
        for (destino, origen) in out.chunks_exact_mut(TAMANO_HOJA).zip(
            self.chunk
                .0
                .chunks_exact(TAMANO_HOJA)
                .chain(self.registro.0.chunks_exact(TAMANO_HOJA)),
        ) {
            destino.copy_from_slice(origen);
        }
        out
    }

    /// Deserializa el testigo desde el array fijo de 768 B del wire.
    #[must_use]
    pub fn desde_bytes(bytes: &[u8; TAMANO_TESTIGO_SOLUCION]) -> Self {
        let mut chunk = [0u8; TAMANO_TESTIGO_CHUNK];
        let mut registro = [0u8; TAMANO_TESTIGO_REGISTRO];
        for (destino, origen) in chunk
            .chunks_exact_mut(TAMANO_HOJA)
            .chain(registro.chunks_exact_mut(TAMANO_HOJA))
            .zip(bytes.chunks_exact(TAMANO_HOJA))
        {
            destino.copy_from_slice(origen);
        }
        Self {
            chunk: TestigoChunk(chunk),
            registro: TestigoRegistro(registro),
        }
    }
}

/// Rellena `hojas` a la potencia de dos siguiente con [`hoja_vacia`].
fn rellenar(hojas: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, ErrorMerkle> {
    if hojas.is_empty() {
        return Err(ErrorMerkle::SinHojas);
    }
    let n = hojas.len().next_power_of_two();
    let mut relleno = Vec::with_capacity(n);
    relleno.extend_from_slice(hojas);
    relleno.resize(n, hoja_vacia());
    Ok(relleno)
}

/// Calcula un nivel interno a partir del nivel anterior (longitud par garantizada).
fn nivel_siguiente(nivel: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut siguiente = Vec::with_capacity(nivel.len() >> 1);
    for par in nivel.chunks_exact(2) {
        if let [izquierda, derecha] = par {
            siguiente.push(nodo(izquierda, derecha));
        }
    }
    siguiente
}

/// Raíz de Merkle de `hojas` (se rellena a potencia de dos con [`hoja_vacia`]).
///
/// # Errores
/// [`ErrorMerkle::SinHojas`] si `hojas` está vacía.
pub fn raiz(hojas: &[[u8; 32]]) -> Result<[u8; 32], ErrorMerkle> {
    let mut nivel = rellenar(hojas)?;
    while nivel.len() > 1 {
        nivel = nivel_siguiente(&nivel);
    }
    nivel.first().copied().ok_or(ErrorMerkle::SinHojas)
}

/// Camino de Merkle (hermanos de abajo arriba) de la hoja `indice`.
///
/// # Errores
/// [`ErrorMerkle::SinHojas`] si `hojas` está vacía y [`ErrorMerkle::IndiceFueraDeRango`] si
/// `indice >= hojas.len()`.
pub fn camino(hojas: &[[u8; 32]], indice: usize) -> Result<Vec<[u8; 32]>, ErrorMerkle> {
    if hojas.is_empty() {
        return Err(ErrorMerkle::SinHojas);
    }
    if indice >= hojas.len() {
        return Err(ErrorMerkle::IndiceFueraDeRango {
            indice,
            n: hojas.len(),
        });
    }
    let mut nivel = rellenar(hojas)?;
    let mut idx = indice;
    let mut hermanos = Vec::new();
    while nivel.len() > 1 {
        let hermano = idx ^ 1;
        let h = nivel
            .get(hermano)
            .copied()
            .ok_or(ErrorMerkle::IndiceFueraDeRango {
                indice: hermano,
                n: nivel.len(),
            })?;
        hermanos.push(h);
        nivel = nivel_siguiente(&nivel);
        idx >>= 1;
    }
    Ok(hermanos)
}

/// Reconstruye la raíz desde una hoja y su camino, para un árbol de `n_hojas` hojas.
///
/// # Errores
/// [`ErrorMerkle::SinHojas`] si `n_hojas = 0`, [`ErrorMerkle::IndiceFueraDeRango`] si
/// `indice >= n_hojas.next_power_of_two()` y [`ErrorMerkle::LongitudCaminoIncorrecta`] si el
/// camino no mide `log2(next_power_of_two(n_hojas))`.
pub fn raiz_desde_camino(
    indice: usize,
    hoja: [u8; 32],
    camino: &[[u8; 32]],
    n_hojas: usize,
) -> Result<[u8; 32], ErrorMerkle> {
    if n_hojas == 0 {
        return Err(ErrorMerkle::SinHojas);
    }
    let n = n_hojas.next_power_of_two();
    let profundidad = n.trailing_zeros() as usize;
    if indice >= n {
        return Err(ErrorMerkle::IndiceFueraDeRango { indice, n });
    }
    if camino.len() != profundidad {
        return Err(ErrorMerkle::LongitudCaminoIncorrecta {
            esperada: profundidad,
            recibida: camino.len(),
        });
    }
    let mut acumulado = hoja;
    for (nivel, hermano) in camino.iter().enumerate() {
        if ((indice >> nivel) & 1) == 0 {
            acumulado = nodo(&acumulado, hermano);
        } else {
            acumulado = nodo(hermano, &acumulado);
        }
    }
    Ok(acumulado)
}

/// Convierte bytes en hermanos de 32 B (la longitud debe ser múltiplo de 32).
fn hermanos_de(bytes: &[u8]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(bytes.len() >> 5);
    for trozo in bytes.chunks_exact(TAMANO_HOJA) {
        if let Ok(hoja) = <[u8; TAMANO_HOJA]>::try_from(trozo) {
            out.push(hoja);
        }
    }
    out
}

/// Construye el compromiso de registro de un registro de `2¹⁶` chunks.
///
/// # Errores
/// [`ErrorMerkle::LongitudIncorrecta`] si `chunks.len() != 2¹⁶`.
pub fn construir_registro(chunks: &[[u8; 32]]) -> Result<CompromisoRegistro, ErrorMerkle> {
    comprobar_longitud(chunks.len(), HOJAS_POR_REGISTRO)?;
    let hojas: Vec<[u8; 32]> = chunks.iter().map(hoja_de_chunk).collect();
    Ok(CompromisoRegistro(raiz(&hojas)?))
}

/// Camino del `chunk` en `s_bucket` dentro del registro (`2¹⁶` hojas).
///
/// # Errores
/// [`ErrorMerkle::LongitudIncorrecta`] si `chunks.len() != 2¹⁶` y
/// [`ErrorMerkle::IndiceFueraDeRango`] si `s_bucket >= 2¹⁶`.
pub fn camino_chunk(chunks: &[[u8; 32]], s_bucket: u32) -> Result<TestigoChunk, ErrorMerkle> {
    comprobar_longitud(chunks.len(), HOJAS_POR_REGISTRO)?;
    let hojas: Vec<[u8; 32]> = chunks.iter().map(hoja_de_chunk).collect();
    let hermanos = camino(&hojas, s_bucket as usize)?;
    let mut arr = [0u8; TAMANO_TESTIGO_CHUNK];
    for (destino, hermano) in arr.chunks_exact_mut(TAMANO_HOJA).zip(hermanos.iter()) {
        destino.copy_from_slice(hermano);
    }
    Ok(TestigoChunk(arr))
}

/// Raíz del registro y camino del `chunk` en `s_bucket`, construyendo el árbol **una sola vez**.
///
/// Equivale a [`construir_registro`] seguido de [`camino_chunk`], pero sin materializar dos veces
/// las `2¹⁶` hojas. Lo usa el productor (PT-2a-2) por candidato.
///
/// # Errores
/// [`ErrorMerkle::LongitudIncorrecta`] si `chunks.len() != 2¹⁶` y
/// [`ErrorMerkle::IndiceFueraDeRango`] si `s_bucket >= 2¹⁶`.
pub fn raiz_y_camino_chunk(
    chunks: &[[u8; 32]],
    s_bucket: u32,
) -> Result<(CompromisoRegistro, TestigoChunk), ErrorMerkle> {
    comprobar_longitud(chunks.len(), HOJAS_POR_REGISTRO)?;
    if s_bucket as usize >= HOJAS_POR_REGISTRO {
        return Err(ErrorMerkle::IndiceFueraDeRango {
            indice: s_bucket as usize,
            n: HOJAS_POR_REGISTRO,
        });
    }
    let mut nivel: Vec<[u8; 32]> = chunks.iter().map(hoja_de_chunk).collect();
    let mut idx = s_bucket as usize;
    let mut arr = [0u8; TAMANO_TESTIGO_CHUNK];
    let mut nivel_actual = 0usize;
    while nivel.len() > 1 {
        let hermano = nivel
            .get(idx ^ 1)
            .copied()
            .ok_or(ErrorMerkle::IndiceFueraDeRango {
                indice: idx ^ 1,
                n: nivel.len(),
            })?;
        if let Some(destino) = arr.chunks_exact_mut(TAMANO_HOJA).nth(nivel_actual) {
            destino.copy_from_slice(&hermano);
        }
        nivel = nivel_siguiente(&nivel);
        idx >>= 1;
        nivel_actual += 1;
    }
    let raiz = nivel.first().copied().ok_or(ErrorMerkle::SinHojas)?;
    Ok((CompromisoRegistro(raiz), TestigoChunk(arr)))
}

/// Construye el compromiso de segmento sobre `2⁸` raíces de registro (D4).
///
/// # Errores
/// [`ErrorMerkle::LongitudIncorrecta`] si `record_commitments.len() != 2⁸`.
pub fn construir_segmento(
    record_commitments: &[[u8; 32]],
) -> Result<CompromisoSegmento, ErrorMerkle> {
    comprobar_longitud(record_commitments.len(), REGISTROS_POR_SEGMENTO)?;
    let hojas: Vec<[u8; 32]> = record_commitments.iter().map(hoja_de_segmento).collect();
    Ok(CompromisoSegmento(raiz(&hojas)?))
}

/// Camino de la raíz de registro en `position` dentro del segmento (`2⁸` hojas).
///
/// # Errores
/// [`ErrorMerkle::LongitudIncorrecta`] si `record_commitments.len() != 2⁸` y
/// [`ErrorMerkle::IndiceFueraDeRango`] si `position >= 2⁸`.
pub fn camino_registro(
    record_commitments: &[[u8; 32]],
    position: u32,
) -> Result<TestigoRegistro, ErrorMerkle> {
    comprobar_longitud(record_commitments.len(), REGISTROS_POR_SEGMENTO)?;
    let hojas: Vec<[u8; 32]> = record_commitments.iter().map(hoja_de_segmento).collect();
    let hermanos = camino(&hojas, position as usize)?;
    let mut arr = [0u8; TAMANO_TESTIGO_REGISTRO];
    for (destino, hermano) in arr.chunks_exact_mut(TAMANO_HOJA).zip(hermanos.iter()) {
        destino.copy_from_slice(hermano);
    }
    Ok(TestigoRegistro(arr))
}

/// Verifica la pertenencia `chunk → registro` (KZG #1 → Merkle).
///
/// Reconstruye la raíz desde `hoja_de_chunk(chunk)` y el testigo, y la compara con el compromiso.
///
/// # Errores
/// [`ErrorMerkle::PertenenciaFallida`] si no coincide; los de rango/longitud de la primitiva.
pub fn verificar_chunk(
    s_bucket: u32,
    chunk: &[u8; 32],
    testigo: &TestigoChunk,
    compromiso: &CompromisoRegistro,
) -> Result<(), ErrorMerkle> {
    let raiz = raiz_desde_camino(
        s_bucket as usize,
        hoja_de_chunk(chunk),
        &hermanos_de(&testigo.0),
        HOJAS_POR_REGISTRO,
    )?;
    if raiz == compromiso.0 {
        Ok(())
    } else {
        Err(ErrorMerkle::PertenenciaFallida)
    }
}

/// Verifica la pertenencia `registro → segmento` (KZG #2 → Merkle, D4).
///
/// Reconstruye la raíz desde `hoja_de_segmento(record_commitment)` y el testigo, y la compara con
/// el compromiso de segmento.
///
/// # Errores
/// [`ErrorMerkle::PertenenciaFallida`] si no coincide; los de rango/longitud de la primitiva.
pub fn verificar_registro(
    position: u32,
    record_commitment: &[u8; 32],
    testigo: &TestigoRegistro,
    compromiso: &CompromisoSegmento,
) -> Result<(), ErrorMerkle> {
    let raiz = raiz_desde_camino(
        position as usize,
        hoja_de_segmento(record_commitment),
        &hermanos_de(&testigo.0),
        REGISTROS_POR_SEGMENTO,
    )?;
    if raiz == compromiso.0 {
        Ok(())
    } else {
        Err(ErrorMerkle::PertenenciaFallida)
    }
}

/// Verifica una solución completa: las dos aperturas contra sus dos compromisos.
///
/// Es el equivalente Merkle de los dos `kzg.verify` del paso 5 de `C-POT-08`.
///
/// # Errores
/// Propaga [`ErrorMerkle::PertenenciaFallida`] de la primera apertura que falle.
pub fn verificar_solucion(
    testigo: &TestigoSolucion,
    chunk: &[u8; 32],
    record_commitment: &[u8; 32],
    s_bucket: u32,
    position: u32,
    compromiso_registro: &CompromisoRegistro,
    compromiso_segmento: &CompromisoSegmento,
) -> Result<(), ErrorMerkle> {
    verificar_chunk(s_bucket, chunk, &testigo.chunk, compromiso_registro)?;
    verificar_registro(
        position,
        record_commitment,
        &testigo.registro,
        compromiso_segmento,
    )
}

/// Comprueba que una lista tiene el tamaño exacto esperado.
fn comprobar_longitud(recibida: usize, esperada: usize) -> Result<(), ErrorMerkle> {
    if recibida == esperada {
        Ok(())
    } else {
        Err(ErrorMerkle::LongitudIncorrecta { esperada, recibida })
    }
}
