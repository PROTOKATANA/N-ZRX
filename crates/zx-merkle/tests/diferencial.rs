//! Diferencial del primitivo Merkle (V2): aperturas válidas e inválidas, bits cambiados e índices
//! fuera de rango, contra una **implementación de referencia independiente** escrita aquí aparte.
//!
//! La referencia no comparte código con `zx-merkle`: construye un árbol por niveles con bucles
//! explícitos sobre `sha3` directamente, y el árbol de `zx-merkle` se recorre por su API pública.
//! Se comparan raíces y caminos, y se exige la **misma decisión** (aceptar/rechazar) en cada caso.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::wildcard_imports,
    clippy::needless_range_loop,
    reason = "los tests fallan con panic por diseño; la referencia indiza arrays internos acotados"
)]

use proptest::prelude::*;
use sha3::{Digest as _, Sha3_256};
use zx_merkle::{
    ErrorMerkle, HOJAS_POR_REGISTRO, PROFUNDIDAD_REGISTRO, PROFUNDIDAD_SEGMENTO,
    REGISTROS_POR_SEGMENTO, TAMANO_TESTIGO_SOLUCION, TestigoSolucion, camino, camino_chunk,
    camino_registro, construir_registro, construir_segmento, h_d, hoja_de_chunk, hoja_de_segmento,
    hoja_vacia, nodo, raiz, raiz_desde_camino, verificar_chunk, verificar_registro,
    verificar_solucion,
};

// ── Referencia independiente ────────────────────────────────────────────────────────────────────

const TAG_CHUNK: [u8; 16] = *b"ZZKPoasHojaChunk";
const TAG_SEG: [u8; 16] = *b"ZZKPoasHojaSegmt";
const TAG_NODO: [u8; 16] = *b"ZZKPoasNodoMerkl";
const TAG_VACIA: [u8; 16] = *b"ZZKPoasHojaVacia";

fn h_ref(tag: [u8; 16], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(tag);
    hasher.update(msg);
    hasher.finalize().into()
}

fn vacia_ref() -> [u8; 32] {
    h_ref(TAG_VACIA, b"")
}

fn nodo_ref(izquierda: &[u8; 32], derecha: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(TAG_NODO);
    hasher.update(izquierda);
    hasher.update(derecha);
    hasher.finalize().into()
}

/// Niveles del árbol, de hojas (nivel 0) a raíz (último).
fn arbol_ref(hojas: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    assert!(!hojas.is_empty());
    let n = hojas.len().next_power_of_two();
    let mut nivel = hojas.to_vec();
    nivel.resize(n, vacia_ref());
    let mut niveles = vec![nivel];
    while niveles.last().unwrap().len() > 1 {
        let actual = niveles.last().unwrap();
        let mut siguiente = Vec::with_capacity(actual.len() >> 1);
        let mut i = 0;
        while i + 1 < actual.len() {
            siguiente.push(nodo_ref(&actual[i], &actual[i + 1]));
            i += 2;
        }
        niveles.push(siguiente);
    }
    niveles
}

fn raiz_ref(hojas: &[[u8; 32]]) -> [u8; 32] {
    let niveles = arbol_ref(hojas);
    niveles.last().unwrap()[0]
}

fn camino_ref(hojas: &[[u8; 32]], indice: usize) -> Vec<[u8; 32]> {
    let niveles = arbol_ref(hojas);
    let mut idx = indice;
    let mut camino = Vec::new();
    for nivel in niveles.iter().take(niveles.len() - 1) {
        camino.push(nivel[idx ^ 1]);
        idx >>= 1;
    }
    camino
}

/// Verificador de referencia: reconstruye la raíz recorriendo el camino con recursión.
fn verifica_ref(
    indice: usize,
    hoja: [u8; 32],
    camino: &[[u8; 32]],
    n_hojas: usize,
) -> Option<[u8; 32]> {
    let n = n_hojas.next_power_of_two();
    let profundidad = n.trailing_zeros() as usize;
    if n_hojas == 0 || indice >= n || camino.len() != profundidad {
        return None;
    }
    // Acumulación explícita de abajo arriba: en cada nivel el hermano va a la izquierda o a la
    // derecha según el bit del índice. Es una formulación funcional distinta del bucle del crate,
    // que se reconstruye en la referencia desde cero con `nodo_ref`.
    Some(
        camino
            .iter()
            .enumerate()
            .fold(hoja, |acumulado, (nivel, hermano)| {
                if ((indice >> nivel) & 1) == 0 {
                    nodo_ref(&acumulado, hermano)
                } else {
                    nodo_ref(hermano, &acumulado)
                }
            }),
    )
}

/// Generador determinista (xorshift64*) para no depender de un RNG externo.
struct Azar(u64);
impl Azar {
    fn nuevo(semilla: u64) -> Self {
        Self(semilla | 1)
    }
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn hoja(&mut self) -> [u8; 32] {
        let mut h = [0u8; 32];
        for trozo in h.chunks_exact_mut(8) {
            trozo.copy_from_slice(&self.siguiente().to_le_bytes());
        }
        h
    }
}

fn hojas_azar(n: usize, semilla: u64) -> Vec<[u8; 32]> {
    let mut azar = Azar::nuevo(semilla);
    (0..n).map(|_| azar.hoja()).collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────────────────────────

#[test]
fn hash_coincide_con_zx_core() {
    // `h_d(tag, msg)` debe ser exactamente `SHA3-256(tag ‖ msg)` = `zx_core::sha3_256_publico`.
    let tag = TAG_CHUNK;
    for msg in [&b""[..], &b"a"[..], &b"prueba de dominio"[..]] {
        let mut preimagen = Vec::new();
        preimagen.extend_from_slice(&tag);
        preimagen.extend_from_slice(msg);
        let esperado = zx_core::sha3_256_publico(&preimagen);
        assert_eq!(&h_d(tag, msg), esperado.as_bytes());
    }
}

#[test]
fn hojas_y_nodos_coinciden_con_la_referencia() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    assert_eq!(hoja_de_chunk(&a), h_ref(TAG_CHUNK, &a));
    assert_eq!(hoja_de_segmento(&a), h_ref(TAG_SEG, &a));
    assert_eq!(nodo(&a, &b), nodo_ref(&a, &b));
    assert_eq!(hoja_vacia(), vacia_ref());
}

#[test]
fn raiz_y_camino_coinciden_con_la_referencia() {
    for n in [1_usize, 2, 3, 5, 8, 16, 32, 64] {
        let hojas = hojas_azar(n, 0xC0FFEE ^ n as u64);
        let esperada = raiz_ref(&hojas);
        assert_eq!(raiz(&hojas).unwrap(), esperada, "raíz con n = {n}");
        for i in 0..n {
            assert_eq!(
                camino(&hojas, i).unwrap(),
                camino_ref(&hojas, i),
                "camino en {i} con n = {n}"
            );
            let hoja = hojas[i];
            assert_eq!(
                raiz_desde_camino(i, hoja, &camino_ref(&hojas, i), n).unwrap(),
                esperada,
                "apertura válida en {i} con n = {n}"
            );
        }
    }
}

#[test]
fn apertura_invalida_por_hoja_hermano_o_indice() {
    let n = 16;
    let hojas = hojas_azar(n, 0x1234_5678);
    let esperada = raiz_ref(&hojas);
    let i = 7;
    let hoja = hojas[i];
    let c = camino_ref(&hojas, i);
    assert_eq!(verifica_ref(i, hoja, &c, n).unwrap(), esperada);

    // Hoja cambiada.
    let mut hoja_mala = hoja;
    hoja_mala[0] ^= 1;
    assert_ne!(verifica_ref(i, hoja_mala, &c, n).unwrap(), esperada);
    assert_ne!(
        raiz_desde_camino(i, hoja_mala, &c, n).unwrap(),
        esperada,
        "una hoja con un bit cambiado no puede reconstruir la raíz"
    );

    // Hermano cambiado.
    let mut c_malo = c.clone();
    c_malo[3][5] ^= 0x80;
    assert_ne!(verifica_ref(i, hoja, &c_malo, n).unwrap(), esperada);
    assert_ne!(raiz_desde_camino(i, hoja, &c_malo, n).unwrap(), esperada);

    // Índice equivocado (mismo camino, otra posición).
    let j = i + 1;
    assert_ne!(verifica_ref(j, hoja, &c, n).unwrap(), esperada);

    // La referencia y el crate coinciden en la decisión para los 32 casos.
    for indice in 0..n {
        let valida = raiz_desde_camino(indice, hojas[indice], &camino(&hojas, indice).unwrap(), n)
            .unwrap()
            == esperada;
        let referencia = verifica_ref(indice, hojas[indice], &camino_ref(&hojas, indice), n)
            .unwrap()
            == esperada;
        assert_eq!(valida, referencia);
        assert!(valida);
    }
}

#[test]
fn indices_y_longitudes_fuera_de_rango_son_error() {
    let hojas = hojas_azar(5, 42);
    // n = 0.
    assert_eq!(raiz(&[]), Err(ErrorMerkle::SinHojas));
    assert_eq!(camino(&[], 0), Err(ErrorMerkle::SinHojas));
    assert_eq!(
        raiz_desde_camino(0, [0u8; 32], &[], 0),
        Err(ErrorMerkle::SinHojas)
    );
    // Índice fuera de rango.
    assert!(matches!(
        camino(&hojas, 5),
        Err(ErrorMerkle::IndiceFueraDeRango { .. })
    ));
    // Camino de longitud incorrecta (la profundidad de n=5 es 3).
    let c = camino(&hojas, 1).unwrap();
    assert_eq!(c.len(), 3);
    assert!(matches!(
        raiz_desde_camino(1, hojas[1], &c[..2], 5),
        Err(ErrorMerkle::LongitudCaminoIncorrecta {
            esperada: 3,
            recibida: 2
        })
    ));
    assert!(matches!(
        raiz_desde_camino(1, hojas[1], &[], 5),
        Err(ErrorMerkle::LongitudCaminoIncorrecta { .. })
    ));
    // Índice en la zona de relleno (5..8) se rechaza al pedir el camino.
    assert!(camino(&hojas, 6).is_err());
}

#[test]
fn dos_niveles_testigo_768_y_verificacion() {
    assert_eq!(TAMANO_TESTIGO_SOLUCION, 768);
    assert_eq!(PROFUNDIDAD_REGISTRO, 16);
    assert_eq!(PROFUNDIDAD_SEGMENTO, 8);

    // Registro sintético de 2¹⁶ chunks.
    let chunks = hojas_azar(HOJAS_POR_REGISTRO, 0xABCDEF);
    let registro = construir_registro(&chunks).unwrap();

    // Segmento de 2⁸ hojas: la posición 0 lleva la raíz del registro real; el resto, valores dados.
    let mut compromisos = hojas_azar(REGISTROS_POR_SEGMENTO, 0x5EED);
    compromisos[0] = registro.0;
    let segmento = construir_segmento(&compromisos).unwrap();

    let s_bucket: u32 = 23_412 % (HOJAS_POR_REGISTRO as u32);
    let position: u32 = 0;
    let tc = camino_chunk(&chunks, s_bucket).unwrap();
    let tr = camino_registro(&compromisos, position).unwrap();
    assert_eq!(tc.0.len(), 512);
    assert_eq!(tr.0.len(), 256);
    let testigo = TestigoSolucion {
        chunk: tc,
        registro: tr,
    };
    assert_eq!(testigo.a_bytes().len(), 768);

    // Positiva: las dos aperturas verifican.
    verificar_chunk(
        s_bucket,
        &chunks[s_bucket as usize],
        &testigo.chunk,
        &registro,
    )
    .unwrap();
    verificar_registro(position, &registro.0, &testigo.registro, &segmento).unwrap();
    verificar_solucion(
        &testigo,
        &chunks[s_bucket as usize],
        &registro.0,
        s_bucket,
        position,
        &registro,
        &segmento,
    )
    .unwrap();

    // Negativas: bit cambiado en el chunk, en un hermano de chunk, en la raíz de registro, en un
    // hermano de registro, e índice/posición equivocados.
    let mut chunk_malo = chunks[s_bucket as usize];
    chunk_malo[0] ^= 1;
    assert_eq!(
        verificar_chunk(s_bucket, &chunk_malo, &testigo.chunk, &registro),
        Err(ErrorMerkle::PertenenciaFallida)
    );

    let mut tc_malo = testigo.chunk;
    tc_malo.0[31] ^= 1;
    assert_eq!(
        verificar_chunk(s_bucket, &chunks[s_bucket as usize], &tc_malo, &registro),
        Err(ErrorMerkle::PertenenciaFallida)
    );

    let mut registro_malo = registro.0;
    registro_malo[0] ^= 1;
    assert_eq!(
        verificar_registro(position, &registro_malo, &testigo.registro, &segmento),
        Err(ErrorMerkle::PertenenciaFallida)
    );

    let mut tr_malo = testigo.registro;
    tr_malo.0[7] ^= 1;
    assert_eq!(
        verificar_registro(position, &registro.0, &tr_malo, &segmento),
        Err(ErrorMerkle::PertenenciaFallida)
    );

    let otro_chunk = (s_bucket + 1) % (HOJAS_POR_REGISTRO as u32);
    assert_eq!(
        verificar_chunk(
            otro_chunk,
            &chunks[s_bucket as usize],
            &testigo.chunk,
            &registro
        ),
        Err(ErrorMerkle::PertenenciaFallida)
    );

    // Fuera de rango.
    assert!(matches!(
        camino_chunk(&chunks, HOJAS_POR_REGISTRO as u32),
        Err(ErrorMerkle::IndiceFueraDeRango { .. })
    ));
    assert!(matches!(
        camino_registro(&compromisos, REGISTROS_POR_SEGMENTO as u32),
        Err(ErrorMerkle::IndiceFueraDeRango { .. })
    ));

    // Longitud incorrecta de hojas.
    assert!(matches!(
        construir_registro(&chunks[..100]),
        Err(ErrorMerkle::LongitudIncorrecta { .. })
    ));
    assert!(matches!(
        construir_segmento(&compromisos[..100]),
        Err(ErrorMerkle::LongitudIncorrecta { .. })
    ));
}

#[test]
fn wire_768_ida_y_vuelta() {
    let chunks = hojas_azar(64, 7);
    let mut testigo_bytes = [0u8; 768];
    for (i, trozo) in testigo_bytes.chunks_exact_mut(32).enumerate() {
        trozo.copy_from_slice(&chunks[i]);
    }
    let t = TestigoSolucion::desde_bytes(&testigo_bytes);
    assert_eq!(t.a_bytes(), testigo_bytes);
}

#[test]
fn el_compromiso_de_registro_es_la_raiz_de_sus_hojas() {
    let chunks = hojas_azar(8, 99);
    let hojas: Vec<[u8; 32]> = chunks.iter().map(hoja_de_chunk).collect();
    // `construir_registro` exige 2¹⁶, así que la comprobación es sobre el árbol genérico.
    assert_eq!(
        raiz(&hojas).unwrap(),
        raiz_ref(&hojas),
        "la hoja de chunk debe ser H_d(tag, chunk)"
    );

    let compromisos = hojas_azar(4, 100);
    let hojas_seg: Vec<[u8; 32]> = compromisos.iter().map(hoja_de_segmento).collect();
    assert_eq!(raiz(&hojas_seg).unwrap(), raiz_ref(&hojas_seg));
}

// ── Propiedades ─────────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn toda_apertura_valida_reconstruye_la_raiz(hojas in proptest::collection::vec(any::<[u8; 32]>(), 1..40)) {
        let esperada = raiz_ref(&hojas);
        prop_assert_eq!(raiz(&hojas).unwrap(), esperada);
        for i in 0..hojas.len() {
            let c = camino(&hojas, i).unwrap();
            prop_assert_eq!(c.clone(), camino_ref(&hojas, i));
            let reconstruida = raiz_desde_camino(i, hojas[i], &c, hojas.len()).unwrap();
            prop_assert_eq!(reconstruida, esperada);
        }
    }

    #[test]
    fn un_bit_cambiado_nunca_reconstruye_la_raiz(
        hojas in proptest::collection::vec(any::<[u8; 32]>(), 2..40),
        indice in any::<proptest::sample::Index>(),
        bit in 0usize..256,
    ) {
        let i = indice.index(hojas.len());
        let c = camino(&hojas, i).unwrap();
        let esperada = raiz_ref(&hojas);
        let mut malo = hojas[i];
        malo[bit >> 3] ^= 1 << (bit & 7);
        prop_assert_ne!(raiz_desde_camino(i, malo, &c, hojas.len()).unwrap(), esperada);
    }
}
