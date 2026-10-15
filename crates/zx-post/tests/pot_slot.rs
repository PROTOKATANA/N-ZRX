//! Pruebas **contextuales** del adaptador `zx-consensus::pot`.
//!
//! Comprueban el borde entre el wire de 128 B, la proyección de `N(s)` y la primitiva PoT: la
//! conversión wire↔primitiva, la corrupción de cada uno de los ocho checkpoints, semilla y
//! trabajo distintos, y que la salida sea el último checkpoint. **No** son pruebas de la primitiva
//! —esas viven en `crates/zx-pot/tests/`— ni de validación de bloque: aquí no hay flujo, caché,
//! anclaje de `pot_output` ni tres estados.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre los ocho checkpoints que construye el propio test"
)]

use core::num::NonZeroU32;

use zx_core::wire_dag::{CHECKPOINTS_POR_BUNDLE, PotCheckpoints as PotCheckpointsWire};
use zx_post::pot::{
    ErrorContextoPot, checkpoints_a_primitiva, checkpoints_a_wire, proyectar_iteraciones,
    verificar_slot_aes,
};
use zx_pot::tipos::{PotCheckpoints, PotOutput, PotSeed};

const SEMILLA: [u8; 16] = [0x42; 16];
const SEMILLA_OTRA: [u8; 16] = [0x43; 16];
const TRABAJO: u64 = 1_600;

fn prueba(n: u32) -> PotCheckpoints {
    zx_pot::prove(
        PotSeed::from(SEMILLA),
        NonZeroU32::new(n).expect("positivo"),
    )
    .expect("múltiplo de 16")
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversión wire ↔ primitiva
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn la_conversion_wire_a_primitiva_y_vuelta_conserva_los_ocho_valores_en_orden() {
    let original = prueba(TRABAJO as u32);
    let wire = checkpoints_a_wire(&original);
    let vuelta = checkpoints_a_primitiva(&wire);

    assert_eq!(vuelta, original);
    let crudos = wire.outputs();
    assert_eq!(crudos.len(), CHECKPOINTS_POR_BUNDLE);
    for (indice, salida) in original.iter().enumerate() {
        assert_eq!(
            PotOutput::from(crudos[indice]),
            *salida,
            "posición {indice} reordenada o alterada"
        );
    }
}

#[test]
fn la_conversion_no_reordena_los_ocho_bloques_crudos() {
    let mut crudos = [[0u8; 16]; CHECKPOINTS_POR_BUNDLE];
    for (indice, bloque) in crudos.iter_mut().enumerate() {
        bloque[0] = indice as u8;
        bloque[15] = 0xA0 + indice as u8;
    }
    let wire = PotCheckpointsWire::desde_outputs(crudos);
    let primitiva = checkpoints_a_primitiva(&wire);

    assert_eq!(checkpoints_a_wire(&primitiva).outputs(), crudos);
    for (indice, salida) in primitiva.iter().enumerate() {
        assert_eq!(**salida, crudos[indice], "posición {indice}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// La salida es el último checkpoint
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn la_salida_es_el_ultimo_de_los_ocho_checkpoints() {
    let original = prueba(TRABAJO as u32);
    let wire = checkpoints_a_wire(&original);
    let crudos = wire.outputs();

    assert_eq!(original.output(), original[CHECKPOINTS_POR_BUNDLE - 1]);
    assert_eq!(
        original.output(),
        PotOutput::from(crudos[CHECKPOINTS_POR_BUNDLE - 1])
    );
    // El ancla del wire no cambia al verificar: sigue siendo la última salida.
    assert!(verificar_slot_aes(SEMILLA, TRABAJO, &wire).unwrap());
    assert_eq!(wire.outputs(), crudos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Verificación de un slot: corrupción, semilla y trabajo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn corromper_cualquiera_de_los_ocho_checkpoints_del_wire_rompe_la_verificacion() {
    let wire = checkpoints_a_wire(&prueba(TRABAJO as u32));
    assert!(verificar_slot_aes(SEMILLA, TRABAJO, &wire).unwrap());

    for indice in 0..CHECKPOINTS_POR_BUNDLE {
        let mut crudos = wire.outputs();
        crudos[indice][0] ^= 0x01;
        let corrompido = PotCheckpointsWire::desde_outputs(crudos);
        assert!(
            !verificar_slot_aes(SEMILLA, TRABAJO, &corrompido).unwrap(),
            "checkpoint {indice} alterado y la verificación lo aceptó"
        );
    }
}

#[test]
fn semilla_o_trabajo_distintos_del_contexto_no_verifican_la_misma_prueba() {
    let wire = checkpoints_a_wire(&prueba(TRABAJO as u32));

    assert!(!verificar_slot_aes(SEMILLA_OTRA, TRABAJO, &wire).unwrap());
    assert!(!verificar_slot_aes(SEMILLA, TRABAJO * 2, &wire).unwrap());
    assert!(!verificar_slot_aes(SEMILLA, TRABAJO + 16, &wire).unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// Dominio de N(s): error de contexto, no prueba inválida
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn la_proyeccion_de_ns_comprueba_cero_rango_y_multiplo_de_16() {
    assert_eq!(proyectar_iteraciones(16).unwrap().get(), 16);
    assert_eq!(
        proyectar_iteraciones(u64::from(u32::MAX) - 15)
            .unwrap()
            .get(),
        u32::MAX - 15
    );

    assert_eq!(
        proyectar_iteraciones(0),
        Err(ErrorContextoPot::IteracionesCero)
    );
    assert_eq!(
        proyectar_iteraciones(17),
        Err(ErrorContextoPot::IteracionesNoMultiploDe16 { valor: 17 })
    );
    // 2^32 es múltiplo de 16 y aun así queda fuera: el rango se comprueba, no se envuelve.
    assert_eq!(
        proyectar_iteraciones(4_294_967_296),
        Err(ErrorContextoPot::IteracionesExcedenU32 {
            valor: 4_294_967_296
        })
    );
    assert_eq!(
        proyectar_iteraciones(u64::MAX),
        Err(ErrorContextoPot::IteracionesExcedenU32 { valor: u64::MAX })
    );
}

#[test]
fn el_dominio_del_contexto_se_rechaza_sin_ejecutar_aes() {
    let wire = checkpoints_a_wire(&prueba(16));

    // Los tres valores enormes o mal formados salen antes de tocar la cadena AES.
    assert_eq!(
        verificar_slot_aes(SEMILLA, 0, &wire),
        Err(ErrorContextoPot::IteracionesCero)
    );
    assert_eq!(
        verificar_slot_aes(SEMILLA, 17, &wire),
        Err(ErrorContextoPot::IteracionesNoMultiploDe16 { valor: 17 })
    );
    assert_eq!(
        verificar_slot_aes(SEMILLA, u64::MAX, &wire),
        Err(ErrorContextoPot::IteracionesExcedenU32 { valor: u64::MAX })
    );
}
