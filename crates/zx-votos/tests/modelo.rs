//! V1/V4 — unitarias del núcleo exacto, del perfil y de la serialización.
//!
//! Cubre: serialización canónica y hash de `T_7` (confirmado contra el vector `pos-01`), peso
//! efectivo y total, multa de perfil, estado de finalidad y la fuente de peso por sectores.
//! **M9-b2:** las unitarias de plazas, cuantil exacto, umbral de quórum, `a_pausa`/`a_rompe` y
//! `q_atacante` se retiraron con la evaluación por plazas.

use num_bigint::BigUint;
use zx_votos::binomial::{peso_efectivo, peso_total};
use zx_votos::perfil::{
    EstadoFinalidad, FuenteSectores, ParametrosPerfil, clave_desde_fuente, estado_finalidad,
};
use zx_votos::serial::{hash_a_hex, hash_tabla, serial_tabla};
use zx_votos::tipos::{Clave, Tabla};

/// Tabla `T_7` del generador de FV-3 (A/B/C activas, D retirada).
fn tabla_t7() -> Tabla {
    Tabla {
        n: 7,
        claves: vec![
            Clave {
                clave: vec![0x11; 32],
                peso: 30,
                activo: true,
                prueba: true,
                garantia: 3000,
            },
            Clave {
                clave: vec![0x22; 32],
                peso: 20,
                activo: true,
                prueba: true,
                garantia: 2000,
            },
            Clave {
                clave: vec![0x33; 32],
                peso: 10,
                activo: true,
                prueba: false,
                garantia: 1000,
            },
            Clave {
                clave: vec![0x44; 32],
                peso: 5,
                activo: false,
                prueba: true,
                garantia: 500,
            },
        ],
    }
}

#[test]
fn serial_y_hash_de_t7() -> Result<(), zx_votos::ErrorVotos> {
    let esperado = "9fc3a8282c8f5281ab9072da739c8ba5b109927bea75a9cd2b6e14c94857ab06";
    assert_eq!(hash_a_hex(&hash_tabla(&tabla_t7())), esperado);
    // 4 claves × (32 pk + 8 peso + 1 activo + 1 prueba) = 168 bytes.
    assert_eq!(serial_tabla(&tabla_t7()).len(), 4 * 42);
    Ok(())
}

#[test]
fn peso_efectivo_y_total() -> Result<(), zx_votos::ErrorVotos> {
    let prueba = Clave {
        clave: vec![0x11; 32],
        peso: 10,
        activo: true,
        prueba: true,
        garantia: 0,
    };
    let sin_prueba = Clave {
        prueba: false,
        ..prueba.clone()
    };
    assert_eq!(peso_efectivo(&prueba, 2)?, BigUint::from(20u8));
    assert_eq!(peso_efectivo(&sin_prueba, 2)?, BigUint::from(10u8));
    // W(T_7) = 30·2 + 20·2 + 10·1 = 110 (D está retirada).
    assert_eq!(peso_total(&tabla_t7(), 2)?, BigUint::from(110u16));
    Ok(())
}

#[test]
fn multa_y_estado_de_finalidad() -> Result<(), zx_votos::ErrorVotos> {
    let perfil = ParametrosPerfil {
        b: 2,
        f_aus_numerador: 1,
        f_aus_denominador: 10,
        m_min: 5,
        n_pausa: 3,
        t_inst: 4,
    };
    // m_aus = floor(100/10) + 5 = 15.
    assert_eq!(perfil.multa_ausencia(100)?, 15);
    assert_eq!(
        estado_finalidad(true, 9, &perfil),
        EstadoFinalidad::Certificada
    );
    assert_eq!(
        estado_finalidad(false, 2, &perfil),
        EstadoFinalidad::Pausada
    );
    assert_eq!(
        estado_finalidad(false, 3, &perfil),
        EstadoFinalidad::PausaObservable
    );
    Ok(())
}

#[test]
fn fuente_definitiva_por_sectores() -> Result<(), zx_votos::ErrorVotos> {
    // El peso registrado son los sectores con garantía de la identidad (FV-D01); una clave con
    // garantía y sin sectores tiene peso 0 y no entra en la tabla.
    let clave = clave_desde_fuente(&[0xAA; 32], true, true, 777, &FuenteSectores)?;
    assert_eq!(clave.peso, 777);
    assert_eq!(clave.garantia, 777);
    // El cómputo global no cambia: w = 777·2.
    assert_eq!(peso_efectivo(&clave, 2)?, BigUint::from(1554u16));

    let sin_sectores = clave_desde_fuente(&[0xBB; 32], true, true, 0, &FuenteSectores)?;
    assert_eq!(sin_sectores.peso, 0);
    assert_eq!(peso_efectivo(&sin_sectores, 2)?, BigUint::from(0u8));
    Ok(())
}

#[test]
fn perfil_dev_admite_los_valores_de_fv4b1() -> Result<(), zx_votos::ErrorVotos> {
    let perfil = ParametrosPerfil::dev();
    assert_eq!(perfil.b, 2);
    assert_eq!(perfil.f_aus_numerador, 1);
    assert_eq!(perfil.f_aus_denominador, 420_000);
    assert_eq!(perfil.m_min, 1);
    assert_eq!(perfil.t_inst, 2);
    assert_eq!(perfil.n_pausa, 2);
    // En la escala dev `floor(f_aus·garantia) = 0` y la multa observable es `m_min`; con
    // `garantia = 420 000` la parte proporcional es 1 y la multa 2.
    assert_eq!(perfil.multa_ausencia(10)?, 1);
    assert_eq!(perfil.multa_ausencia(420_000)?, 2);
    Ok(())
}
