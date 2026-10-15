//! `ORDEN-RD3c` §3: pruebas del registro firmado de direcciones del nodo (N1–N5).
//!
//! Van en un archivo de integración para que los nombres de la orden sean exactamente los de
//! `cargo test`. Ejercen las funciones puras del módulo `red::registro_direcciones` (no hacen falta
//! nodos reales para estas; los humos de cuatro nodos cubren el cableado completo).

#![expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]

use std::time::{Duration, Instant};

use zx_core::firma::Firma;
use zx_core::red::Red;
use zx_node::claves::ClaveDev;
use zx_node::red::registro_direcciones::{
    ConfigRegistro, PlanificadorRegistro, RegistroRed, aplicar_pagina_recibida,
    construir_entrada_propia, debe_pedir_pagina,
};
use zx_p2p::limites::{MAX_ENTRADAS_REGISTRO_POR_PAGINA, MAX_RESPUESTA_BYTES};
use zx_p2p::registro::EntradaRegistro;

/// Un instante de reloj de pared fijo para las entradas de prueba.
fn ahora() -> u64 {
    1_000_000
}

fn dir(puerto: u16) -> libp2p::Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{puerto}").parse().unwrap()
}

/// Una entrada bien firmada por la clave dev `(semilla, indice)`.
fn entrada_valida(semilla: u64, indice: u32, epoch: u64, puerto: u16) -> EntradaRegistro {
    let clave = ClaveDev::derivar(semilla, indice);
    construir_entrada_propia(&clave, &[dir(puerto)], epoch, Red::Dev)
}

/// **N1.** Apagado, el nodo ni pide ni guarda.
#[test]
fn registro_apagado_no_pide_ni_guarda() {
    let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::APAGADO);
    let plan = PlanificadorRegistro::default();
    assert!(
        !debe_pedir_pagina(&reg, &plan, Instant::now()),
        "apagado no se pide"
    );
    let e = entrada_valida(1, 0, ahora(), 49_400);
    assert!(!aplicar_pagina_recibida(&reg, &[e], ahora()));
    assert_eq!(reg.longitud(), 0, "apagado no guarda");
}

/// **N1.** Apagado, responde a la petición con una página vacía.
#[test]
fn registro_apagado_responde_pagina_vacia() {
    let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::APAGADO);
    let (pagina, total) = reg.pagina(0, MAX_ENTRADAS_REGISTRO_POR_PAGINA, MAX_RESPUESTA_BYTES);
    assert!(pagina.is_empty());
    assert_eq!(total, 0);
}

/// **N2.** Una petición se sirve con una página acotada por los topes de RD-1c.
#[test]
fn peticion_registro_direcciones_sirve_pagina_acotada() {
    let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(false));
    let total_entradas = MAX_ENTRADAS_REGISTRO_POR_PAGINA + 3;
    for i in 0..total_entradas {
        let e = entrada_valida(7, i as u32, ahora(), 49_500 + i as u16);
        reg.insertar(e, ahora()).unwrap();
    }
    let (pagina, total) = reg.pagina(0, MAX_ENTRADAS_REGISTRO_POR_PAGINA, MAX_RESPUESTA_BYTES);
    assert_eq!(pagina.len(), MAX_ENTRADAS_REGISTRO_POR_PAGINA);
    assert_eq!(total, total_entradas as u64);
    // El tope de bytes también acota; al menos una entrada siempre entra.
    let (pagina_corta, _) = reg.pagina(0, MAX_ENTRADAS_REGISTRO_POR_PAGINA, 1);
    assert_eq!(pagina_corta.len(), 1);
}

/// **N4.** Una respuesta con entradas válidas alimenta el registro.
#[test]
fn respuesta_registro_alimenta_el_registro() {
    let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(false));
    let e = entrada_valida(2, 0, ahora(), 49_401);
    assert!(!aplicar_pagina_recibida(&reg, &[e], ahora()));
    assert_eq!(reg.longitud(), 1);
}

/// **N4.** Una firma inválida se descarta y **penaliza** al par.
#[test]
fn respuesta_con_firma_invalida_se_descarta_y_penaliza() {
    let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(false));
    let mut e = entrada_valida(3, 0, ahora(), 49_402);
    e.firma = Firma::desde_bytes([0u8; 64]);
    assert!(
        aplicar_pagina_recibida(&reg, &[e], ahora()),
        "la firma inválida MUST penalizar"
    );
    assert_eq!(reg.longitud(), 0);
}

/// **N4.** Una entrada válida pero vieja o repetida se descarta **sin** penalizar.
#[test]
fn respuesta_vieja_o_repetida_no_penaliza() {
    let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(false));
    let e = entrada_valida(4, 0, ahora(), 49_403);
    assert!(!aplicar_pagina_recibida(
        &reg,
        std::slice::from_ref(&e),
        ahora()
    ));
    assert_eq!(reg.longitud(), 1);
    // Repetida (misma época): se descarta sin penalizar.
    assert!(!aplicar_pagina_recibida(
        &reg,
        std::slice::from_ref(&e),
        ahora()
    ));
    assert_eq!(reg.longitud(), 1);
    // Vieja, fuera de la ventana V: se descarta sin penalizar.
    let vieja = entrada_valida(4, 0, ahora() - 10_000, 49_403);
    assert!(!aplicar_pagina_recibida(&reg, &[vieja], ahora()));
    assert_eq!(reg.longitud(), 1);
}

/// **N3.** Una petición por par y por `T_par`, y nunca con otra sin responder.
#[test]
fn una_peticion_de_registro_por_par_y_t_par() {
    let t0 = Instant::now();
    let t_par = Duration::from_secs(60);
    let mut plan = PlanificadorRegistro::default();
    assert!(plan.debe_pedir(t0));
    plan.registrar_peticion(t0, t_par);
    assert!(
        !plan.debe_pedir(t0),
        "no se repite mientras la anterior esté sin responder"
    );
    plan.respuesta_llego();
    assert!(!plan.debe_pedir(t0 + Duration::from_secs(59)));
    assert!(plan.debe_pedir(t0 + t_par));
    plan.registrar_peticion(t0 + t_par, t_par);
    assert!(!plan.debe_pedir(t0 + t_par + Duration::from_secs(59)));
}

/// **N5.** La entrada propia se firma con la clave de productor y se sirve.
#[test]
fn entrada_propia_se_firma_y_se_sirve() {
    let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(true));
    let clave = ClaveDev::derivar(9, 0);
    let direcciones = vec![dir(49_404)];
    assert!(reg.publicar_propia(&clave, &direcciones, ahora()).unwrap());
    let (pagina, total) = reg.pagina(0, MAX_ENTRADAS_REGISTRO_POR_PAGINA, MAX_RESPUESTA_BYTES);
    assert_eq!(total, 1);
    let e = pagina.first().unwrap();
    assert_eq!(e.productor, clave.pk);
    e.verificar_firma().unwrap();
}

/// **N5.** Con la publicación apagada, el nodo no publica nada.
#[test]
fn publicacion_apagada_no_publica() {
    let config = ConfigRegistro {
        publicar: false,
        ..ConfigRegistro::encendido(true)
    };
    let reg = RegistroRed::nuevo(Red::Dev, config);
    let clave = ClaveDev::derivar(11, 0);
    assert!(
        !reg.publicar_propia(&clave, &[dir(49_405)], ahora())
            .unwrap()
    );
    let (pagina, total) = reg.pagina(0, MAX_ENTRADAS_REGISTRO_POR_PAGINA, MAX_RESPUESTA_BYTES);
    assert!(pagina.is_empty());
    assert_eq!(total, 0);
}
