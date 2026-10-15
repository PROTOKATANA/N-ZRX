//! Pruebas de la semilla del génesis de `zx-consensus::pot` (`C-FLU-06`).
//!
//! # Sin oráculo BLAKE3 independiente
//!
//! En este entorno **no** hay un oráculo BLAKE3 local: `b3sum` no está instalado y OpenSSL 3.5.3
//! solo trae BLAKE2 (`openssl list -digest-algorithms`). Por eso **no** se afirma un vector fijo
//! independiente: se comprueban la longitud, el orden de concatenación con entradas fijas y
//! mutaciones, y la independencia del oráculo queda **pendiente**. Los valores de estos tests no
//! son parámetros de red.
//!
//! Que estos tests vivan en `tests/` y no en `src/pot.rs` es deliberado: `ci/alcance-consenso.sh`
//! cuenta las llamadas dentro de `src` como uso interno, así que una prueba unitaria en el mismo
//! archivo escondería que `semilla_genesis` todavía no tiene llamante de producción. La prueba de
//! integración mantiene el punto de entrada visible para el guardián.

use zx_core::digest::{BlockHash, Digest};
use zx_core::wire_dag::POT_OUTPUT_BYTES;
use zx_post::pot::semilla_genesis;

/// `block_hash` fijo con todos los bytes iguales al argumento.
fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

/// La semilla mide exactamente 16 B (`C-FLU-06` / `C-POT-01`).
#[test]
fn mide_16_bytes() {
    assert_eq!(
        semilla_genesis(&hash(0x11), b"entropia-externa-v1").len(),
        POT_OUTPUT_BYTES
    );
}

/// Es determinista: las mismas entradas dan la misma semilla.
#[test]
fn es_determinista() {
    assert_eq!(
        semilla_genesis(&hash(0x11), b"entropia-externa-v1"),
        semilla_genesis(&hash(0x11), b"entropia-externa-v1")
    );
}

/// Cambiar el `block_hash` del génesis cambia la semilla.
#[test]
fn cambiar_el_genesis_cambia_la_semilla() {
    let entropia = b"entropia-externa-v1";
    assert_ne!(
        semilla_genesis(&hash(0x11), entropia),
        semilla_genesis(&hash(0x12), entropia)
    );
}

/// Cambiar la entropía externa cambia la semilla.
#[test]
fn cambiar_la_entropia_cambia_la_semilla() {
    assert_ne!(
        semilla_genesis(&hash(0x11), b"entropia-externa-v1"),
        semilla_genesis(&hash(0x11), b"entropia-externa-v2")
    );
}

/// Dos entropías distintas con el mismo prefijo dan semillas distintas.
#[test]
fn entropias_con_prefijo_comun_dan_semillas_distintas() {
    assert_ne!(
        semilla_genesis(&hash(0x11), b"abc"),
        semilla_genesis(&hash(0x11), b"abcd")
    );
}

/// El `Hasher` incremental reproduce `blake3(block_hash(génesis) ‖ entropía_externa)[0..16)` con
/// **dos tamaños** de entropía —vacío y uno mayor que el bloque interno de BLAKE3 (64 B)—, y el
/// `block_hash` (32 B fijos) va **primero**: invertir el orden con el mismo contenido da otra
/// semilla, luego la concatenación es inequívoca.
///
/// La referencia se calcula por la ruta one-shot `blake3::hash` sobre la concatenación **explícita**,
/// distinta de la incremental bajo prueba; no se usa `Hasher` en la expectativa, que sería espejo
/// de la implementación. Sin oráculo BLAKE3 independiente (ver cabecera), esto comprueba
/// equivalencia de rutas, no independencia del oráculo. No se duplica la prueba de determinismo.
#[test]
fn coincide_con_la_concatenacion_y_el_orden_importa() {
    let entropias: [&[u8]; 2] = [b"", &[0xAB; 96]];
    for &entropia in &entropias {
        let mut preimagen = Vec::new();
        preimagen.extend_from_slice(hash(0x11).as_bytes());
        preimagen.extend_from_slice(entropia);

        let digest = blake3::hash(&preimagen);
        let (cabeza, _) = digest.as_bytes().split_at(POT_OUTPUT_BYTES);
        let mut esperada = [0u8; POT_OUTPUT_BYTES];
        esperada.copy_from_slice(cabeza);

        assert_eq!(
            semilla_genesis(&hash(0x11), entropia),
            esperada,
            "C-FLU-06: la ruta incremental debe reproducir blake3(block_hash ‖ entropía)[0..16)"
        );
    }

    let entropia = b"entropia-externa-v1";
    let mut preimagen_invertida = Vec::new();
    preimagen_invertida.extend_from_slice(entropia);
    preimagen_invertida.extend_from_slice(hash(0x11).as_bytes());

    let digest = blake3::hash(&preimagen_invertida);
    let (cabeza, _) = digest.as_bytes().split_at(POT_OUTPUT_BYTES);
    let mut esperada_invertida = [0u8; POT_OUTPUT_BYTES];
    esperada_invertida.copy_from_slice(cabeza);

    assert_ne!(
        semilla_genesis(&hash(0x11), entropia),
        esperada_invertida,
        "C-FLU-06: el orden es block_hash(génesis) primero, entropía_externa después"
    );
}
