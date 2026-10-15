//! Vectores y microtraza de las derivaciones **puras** de `zx-consensus::pot`
//! (`C-POT-01`, `C-POT-03`; encargo 03b).
//!
//! Contrastan V1–V4 de `veritas/consenso/pot-primitiva-v1/vectores/vectores.txt` con sus
//! constantes congeladas, y añaden una microtraza de slots consecutivos con una inyección colocada
//! en un slot concreto, más controles que detectan invertir `entropía ‖ salida`, usar big-endian,
//! cambiar el slot o cambiar la salida.
//!
//! # Qué prueban y qué NO
//!
//! Prueban la **forma** de las fórmulas: el orden de la concatenación, el truncado a 16 B, la
//! codificación little-endian y que el encadenado sin inyección devuelve la salida anterior tal
//! cual. **No** son una prueba de procedencia contextual: no acreditan quién decidió inyectar, ni
//! en qué slot, ni que la salida, la semilla o el `N(s)` vengan del pasado DAG validado. Los
//! controles solo detectan errores de fórmula o de codificación; la procedencia la tendría que
//! aportar el verificador contextual de §7.1.2, que no existe.
//!
//! V1/V2 usan semillas y entropía **sintéticas** con `N = 16`, fijadas por
//! `veritas/consenso/pot-primitiva-v1/vectores/`; la evidencia externa del AES siguen siendo los
//! 32 vectores diferenciales de `zx-pot`. V4 fija el hash y el little-endian sobre una **salida
//! fija** y el slot 42: no es una cadena causal evaluada hasta el slot 42.

#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]

use core::num::NonZeroU32;

use zx_core::wire_dag::POT_OUTPUT_BYTES;
use zx_post::pot::{aleatoriedad_de_salida, reto_desde_salida, semilla_siguiente};
use zx_pot::tipos::PotSeed;

/// `N(s)` de los vectores: el mínimo que la primitiva admite.
const N: u32 = 16;

/// Salida AES de un slot con `N = 16` (`C-POT-02`), vía la primitiva de `zx-pot`.
fn salida(semilla: [u8; POT_OUTPUT_BYTES]) -> [u8; POT_OUTPUT_BYTES] {
    let checkpoints = zx_pot::prove(PotSeed::from(semilla), NonZeroU32::new(N).expect("N=16"))
        .expect("16 es múltiplo de 8 x 2");
    *checkpoints.output()
}

/// Semilla sintética de V1: `blake3("ZEROX-P-POT-V1-genesis")[0..16)`.
///
/// No la deriva este módulo: en el diseño la aporta el contexto del génesis, y aquí solo fija el
/// punto de partida del vector.
fn semilla_genesis() -> [u8; POT_OUTPUT_BYTES] {
    let mut semilla = [0u8; POT_OUTPUT_BYTES];
    semilla
        .copy_from_slice(&blake3::hash(b"ZEROX-P-POT-V1-genesis").as_bytes()[..POT_OUTPUT_BYTES]);
    semilla
}

/// Oráculo independiente y explícito de la inyección: `blake3(entropía ‖ salida)[0..16)`.
fn inyeccion_directa(
    entropia: [u8; 32],
    salida_anterior: [u8; POT_OUTPUT_BYTES],
) -> [u8; POT_OUTPUT_BYTES] {
    let mut buffer = [0u8; 48];
    buffer[..32].copy_from_slice(&entropia);
    buffer[32..].copy_from_slice(&salida_anterior);
    let mut semilla = [0u8; POT_OUTPUT_BYTES];
    semilla.copy_from_slice(&blake3::hash(&buffer).as_bytes()[..POT_OUTPUT_BYTES]);
    semilla
}

fn hex16(s: &str) -> [u8; 16] {
    let mut v = [0u8; 16];
    for (i, b) in v.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex de 32 dígitos");
    }
    v
}

fn hex32(s: &str) -> [u8; 32] {
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex de 64 dígitos");
    }
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// V1 · encadenado sin inyección (C-POT-01)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v1_encadenado_sin_inyeccion_devuelve_la_salida_anterior() {
    let mut semilla = semilla_genesis();
    assert_eq!(semilla, hex16("10c9a9b2be91883dbbd81307655243d9"));

    let esperadas = [
        "81c5ab0e4ce122413b30e6ff45ca1673",
        "0eeb4bbd31aeb1e131bec475649b7063",
        "1b478f8dc23646fc6e7667ade3c09906",
        "01b5433c12027fdb51e8a0aceb53301c",
    ];

    for (slot, esperada) in esperadas.iter().enumerate() {
        let out = salida(semilla);
        assert_eq!(out, hex16(esperada), "V1 salida(f,{slot})");

        // Sin inyección, la semilla siguiente son EXACTAMENTE los mismos 16 bytes.
        let siguiente = semilla_siguiente(out, None);
        assert_eq!(siguiente, out, "V1 semilla(f,{})", slot + 1);
        semilla = siguiente;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// V2 · inyección: entropía primero y truncado a 16 B (C-POT-01)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v2_inyeccion_usa_la_entropia_primero_y_trunca_a_16() {
    let entropia = *blake3::hash(b"ZEROX-P-POT-V2-entropy").as_bytes();
    let previa = salida(semilla_genesis());
    assert_eq!(previa, hex16("81c5ab0e4ce122413b30e6ff45ca1673"));

    let semilla = semilla_siguiente(previa, Some(entropia));
    assert_eq!(semilla, hex16("0c00b302341a3e3c3ba0fb1232e19ea0"));
    // Coincide con el oráculo explícito, que también fija el orden entropía ‖ salida.
    assert_eq!(semilla, inyeccion_directa(entropia, previa));
    assert_eq!(salida(semilla), hex16("ef47c860bcdcd1a3754905ba9a19e7ce"));
}

// ─────────────────────────────────────────────────────────────────────────────
// V3 · aleatoriedad; V4 · hash y LE64(slot) sobre salida fija (C-POT-03)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v3_aleatoriedad_es_blake3_de_la_salida() {
    let previa = salida(semilla_genesis());
    assert_eq!(
        aleatoriedad_de_salida(previa),
        hex32("dbc39011a97deaa84376770553cfee918b16525e7797374dd394e50c8775f370")
    );
}

#[test]
fn v4_reto_codifica_slot_42_en_little_endian_sobre_una_salida_fija() {
    // La salida de partida es la de V1 (fija); el slot 42 solo entra como `LE64(42)`. Esto NO es
    // la cadena causal evaluada hasta el slot 42: es hash y codificación.
    let previa = salida(semilla_genesis());
    assert_eq!(
        reto_desde_salida(previa, 42),
        hex32("722ce84f18b69115eff93d38f42257e4649b7609f4312d25fcb268d47154c7f0")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Microtraza: slots consecutivos con N=16 y una inyección en un slot concreto
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn microtraza_de_ocho_slots_con_inyeccion_en_el_slot_tres() {
    const SLOTS: usize = 8;
    const SLOT_INYECCION: usize = 3;

    let entropia = *blake3::hash(b"ZEROX-03b-microtraza-entropia").as_bytes();

    // Traza con inyección EN `SLOT_INYECCION`: `semilla(s)` del propio slot inyectado es
    // `blake3(entropía ‖ salida(s-1))`; en los demás es la salida anterior tal cual. El slot 0
    // arranca de la semilla sintética del génesis, que en el diseño aporta el contexto.
    let mut semilla = semilla_genesis();
    let mut salidas = [[0u8; POT_OUTPUT_BYTES]; SLOTS];
    let mut anterior: Option<[u8; POT_OUTPUT_BYTES]> = None;
    let mut inyectada = false;
    for (slot, ranura) in salidas.iter_mut().enumerate() {
        if let Some(previa) = anterior {
            semilla = if slot == SLOT_INYECCION {
                let con_entropia = semilla_siguiente(previa, Some(entropia));
                assert_ne!(con_entropia, previa, "la inyección debe cambiar la semilla");
                assert_eq!(con_entropia, inyeccion_directa(entropia, previa));
                inyectada = true;
                con_entropia
            } else {
                let sin_entropia = semilla_siguiente(previa, None);
                assert_eq!(
                    sin_entropia, previa,
                    "sin inyección la semilla es la salida anterior"
                );
                sin_entropia
            };
        }
        let out = salida(semilla);
        *ranura = out;
        anterior = Some(out);
    }
    assert!(
        inyectada,
        "la inyección estaba colocada en un slot del rango"
    );

    // Traza gemela sin inyección: idéntica hasta el slot anterior a la inyección; distinta desde
    // el slot de inyección en adelante. La inyección se aplica EN el slot declarado, no después.
    let mut semilla_sin = semilla_genesis();
    for (slot, esperada) in salidas.iter().enumerate() {
        let out = salida(semilla_sin);
        if slot < SLOT_INYECCION {
            assert_eq!(out, *esperada, "slot {slot} no debería cambiar");
        } else {
            assert_ne!(
                out, *esperada,
                "slot {slot} debería diferir por la inyección"
            );
        }
        semilla_sin = semilla_siguiente(out, None);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Controles de forma: detectan invertir el orden, big-endian, otro slot u otra salida
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn control_detecta_invertir_entropia_y_salida() {
    let previa = salida(semilla_genesis());
    let entropia = *blake3::hash(b"ZEROX-03b-control-entropia").as_bytes();

    // Oráculo invertido: salida ‖ entropía. Debe dar OTRA semilla.
    let mut invertido = [0u8; 48];
    invertido[..POT_OUTPUT_BYTES].copy_from_slice(&previa);
    invertido[POT_OUTPUT_BYTES..].copy_from_slice(&entropia);
    let mut esperado_invertido = [0u8; POT_OUTPUT_BYTES];
    esperado_invertido.copy_from_slice(&blake3::hash(&invertido).as_bytes()[..POT_OUTPUT_BYTES]);

    assert_ne!(
        semilla_siguiente(previa, Some(entropia)),
        esperado_invertido,
        "el orden es entropía primero"
    );
}

#[test]
fn control_detecta_big_endian_en_el_reto() {
    let previa = salida(semilla_genesis());
    let aleatoriedad = aleatoriedad_de_salida(previa);
    let slot = 0x0102_0304_0506_0708u64;

    let mut buffer_be = [0u8; 40];
    buffer_be[..32].copy_from_slice(&aleatoriedad);
    buffer_be[32..].copy_from_slice(&slot.to_be_bytes());
    let esperado_be: [u8; 32] = blake3::hash(&buffer_be).into();

    let mut buffer_le = [0u8; 40];
    buffer_le[..32].copy_from_slice(&aleatoriedad);
    buffer_le[32..].copy_from_slice(&slot.to_le_bytes());
    let esperado_le: [u8; 32] = blake3::hash(&buffer_le).into();

    assert_ne!(
        reto_desde_salida(previa, slot),
        esperado_be,
        "la codificación es LE64, no BE64"
    );
    assert_eq!(
        reto_desde_salida(previa, slot),
        esperado_le,
        "coincide con el oráculo LE64 independiente"
    );
}

#[test]
fn control_detecta_cambiar_el_slot_o_cambiar_la_salida() {
    let previa = salida(semilla_genesis());
    let otra = salida([0x42; POT_OUTPUT_BYTES]);
    let entropia = *blake3::hash(b"ZEROX-03b-control-entropia").as_bytes();

    assert_ne!(reto_desde_salida(previa, 42), reto_desde_salida(previa, 43));
    assert_ne!(reto_desde_salida(previa, 42), reto_desde_salida(otra, 42));
    assert_ne!(aleatoriedad_de_salida(previa), aleatoriedad_de_salida(otra));
    assert_ne!(
        semilla_siguiente(previa, Some(entropia)),
        semilla_siguiente(otra, Some(entropia))
    );
    assert_ne!(
        semilla_siguiente(previa, None),
        semilla_siguiente(otra, None)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Límite declarado: la fórmula no acredita procedencia contextual
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn la_formula_no_acredita_quien_inyecta_ni_en_que_slot() {
    let previa = salida(semilla_genesis());
    let entropia = *blake3::hash(b"ZEROX-03b-procedencia").as_bytes();

    // La API no recibe el slot: la misma (salida anterior, entropía) da la misma semilla aunque
    // un llamante afirme inyectar en slots distintos. Eso es ausencia de acreditación, no una
    // garantía; la procedencia la tendría que aportar el contexto.
    let en_un_slot = semilla_siguiente(previa, Some(entropia));
    let en_otro_slot = semilla_siguiente(previa, Some(entropia));
    assert_eq!(en_un_slot, en_otro_slot);

    // Y "cero inyecciones" es una elección del llamante, no una decisión acreditada.
    assert_ne!(semilla_siguiente(previa, None), en_un_slot);
}
