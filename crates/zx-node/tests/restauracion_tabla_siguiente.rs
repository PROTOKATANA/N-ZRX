//! FV-N6-C6 · carga inicial segura y tabla siguiente, devueltas al **modo por peso** (M9-a2).
//!
//! La carga inicial del modo por peso es `MotorVotos::sembrar_punto_control_peso(tabla, claves,
//! certificado)` (`0x09`), y la base del motor es la finalidad **aplicada** del estado o el
//! certificado sembrado. Los rechazos que siguen vivos son `motor_ya_abierto`, `claves_desalineadas`
//! e `indice_certificado`.
//!
//! Retiradas (listas B y J · salida (c), M9-a2): `legado_resuelve_la_tabla_guardada_y_certifica`,
//! `legado_reconstruye_la_tabla_canonica_del_estado_y_certifica`,
//! `legado_sin_tabla_verificable_espera_y_reintenta`, `legado_rechaza_n_max_sin_mutar_y_recupera` y
//! `rechaza_k_local` (lista B: el legado y la `K` del sorteo ya no existen);
//! `carga_explicita_con_tabla_siguiente_certifica_y_consenso_aplica`, `rechaza_hash_de_tabla_siguiente`,
//! `rechaza_desbordamiento_n_max`, `idempotencia_y_conflicto_de_segunda_carga` y
//! `explicita_rechaza_n_max_sin_mutar_y_recupera` (lista J, salida (c): la API
//! `sembrar_punto_control_con_tabla_siguiente` y sus motivos `tabla_siguiente_indice`,
//! `tabla_siguiente_hash`, `n_max`, `segunda_carga` y `k_local` no existen en el modo por peso; los
//! sustitutos vivos se cubren en `votos::pruebas_rean2::{r1,r2,r3}` para la tabla guardada).

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "los tests fallan con panic por diseño"
)]

use std::error::Error;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{
    PRIMA_DISPONIBILIDAD_ACTIVA, derivar_tabla_sin_base_con_undo,
};
use zx_consensus::transicion::{Estado, Garantia, fuente_peso_de};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, ClaveTablaVoto, Digest};
use zx_node::votos::{ConfigMotorVotos, MotorVotos, PasoVotos};
use zx_votos::peso::{CertificadoPeso, verificar_firma_peso};
use zx_votos::{
    Clave, ClavePublica, ClaveSecreta, DOMINIO_VOTO, ErrorVotos, Tabla, construir_certificado,
    firmar, hash_tabla, mensaje_voto_peso,
};

/// Slot de construcción de las tablas.
const SLOT: i64 = 13;

type Res = Result<(), Box<dyn Error>>;

/// Clave BLS secreta determinista por índice (misma derivación que los arneses de votos).
fn bls(indice: u8) -> Result<ClaveSecreta, Box<dyn Error>> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

/// Clave Ed25519 sintética de la identidad (fixture; no viene de una `Tx`).
fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

fn registro(p: &ParametrosSector, clave: ClaveEd, indice: u16) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    let reg = RegistroSector {
        id,
        r2: [0; 4],
        history_size: 1,
        etapa: Etapa::Activo,
        alta_slot: 0,
        renovacion_slot: 0,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado con `claves = (índice, nº de sectores activos)` y garantía activa `garantia` (fixture).
fn estado(
    claves: &[(u8, usize)],
    garantia: i64,
) -> Result<(Estado, Vec<ClaveSecreta>), Box<dyn Error>> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let mut secretas = Vec::new();
    for (indice, n_sectores) in claves {
        let secreta = bls(*indice)?;
        let pk = secreta.clave_publica();
        let e = ed(*indice);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for i in 0..*n_sectores {
            let (id, reg) = registro(&p, e, u16::try_from(i)?);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(garantia)?;
        est.garantias.insert(e, g);
        secretas.push(secreta);
    }
    Ok((est, secretas))
}

/// Tabla `T_n` derivada del estado vivo en `SLOT` (peso real), en **orden canónico** por bytes de
/// clave BLS, que es el que indexa el mapa de bits del certificado por peso.
fn tabla_de(est: &Estado, n: u64) -> Result<(Vec<ClaveTablaVoto>, Tabla), Box<dyn Error>> {
    let p = est.parametros_sector;
    let mut pares: Vec<(ClaveTablaVoto, Clave)> = Vec::new();
    for (e, cv) in &est.claves_voto {
        let peso = fuente_peso_de(est, e, SLOT, &p);
        if peso <= 0 {
            continue;
        }
        let peso = u64::try_from(peso)?;
        let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && est.pruebas.contains_key(e);
        pares.push((
            ClaveTablaVoto {
                clave_bls: cv.clave_bls,
                peso,
                activo: true,
                prueba,
                garantia: peso,
            },
            Clave {
                clave: cv.clave_bls.to_vec(),
                peso,
                activo: true,
                prueba,
                garantia: peso,
            },
        ));
    }
    pares.sort_by_key(|a| a.0.clave_bls);
    let (claves_payload, tabla_claves) = pares.into_iter().unzip();
    Ok((
        claves_payload,
        Tabla {
            n,
            claves: tabla_claves,
        },
    ))
}

fn pubs_de(tabla: &Tabla) -> Result<Vec<ClavePublica>, Box<dyn Error>> {
    tabla
        .claves
        .iter()
        .map(|c| Ok(ClavePublica::desde_bytes(&c.clave)?))
        .collect()
}

/// Certificado por peso `0x09` real (firma BLS agregada) de `sk` sobre la tabla dada. La clave de
/// `sk` tiene más de `2/3` del peso de la tabla, así que su voto basta para el quórum. TB-1c · T2:
/// el certificado ya **no** adjunta la tabla siguiente; la huella declarada es la que el consenso
/// exige que esté en la cola `Q` del estado.
fn cert_peso(
    tabla: &Tabla,
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    _tabla_siguiente: Option<Tabla>,
    sk: &ClaveSecreta,
) -> Result<CertificadoPeso, Box<dyn Error>> {
    let mensaje = mensaje_voto_peso(n, &candidato, &h_t_siguiente, &[0u8; 32]);
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje)?;
    let pk = sk.clave_publica();
    let pos = tabla
        .claves
        .iter()
        .position(|c| c.clave.as_slice() == pk.bytes().as_slice())
        .ok_or("clave en la tabla")?;
    let cert = construir_certificado(
        n,
        candidato,
        h_t_siguiente,
        [0u8; 32],
        tabla,
        &[(pos + 1, firma)],
    )?;
    Ok(cert)
}

/// Extrae el motivo estático de un rechazo de carga de `avanzar`.
fn motivo_carga(resultado: Result<PasoVotos, ErrorVotos>) -> Result<&'static str, Box<dyn Error>> {
    match resultado {
        Ok(_) => Err("se esperaba un rechazo de carga".into()),
        Err(ErrorVotos::CargaInicialInvalida { motivo }) => Ok(motivo),
        Err(otro) => Err(format!("motivo inesperado: {otro:?}").into()),
    }
}

fn motor_con_claves(claves: Vec<ClaveSecreta>) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: zx_node::perfil::parametros_votos_dev(),
        claves,
        emitir_votos: true,
    })
}

/// Escenario: `T_1` (100+1 sectores) y `T_2` (101+1 sectores, contenido distinto), con `C_1` sobre
/// `T_1` que compromete `h_T(T_2)`.
struct Escenario {
    /// Estado con `C_1` aplicado (finalidad `n=1`, `h_t = h_T(T_2)`).
    e1: Estado,
    /// `T_1`.
    tabla_n: Tabla,
    /// `C_1`.
    cert_n: CertificadoPeso,
    /// `h_T(T_2)`.
    hash_n1: [u8; 32],
}

fn escenario_cn_tabla_distinta() -> Result<Escenario, Box<dyn Error>> {
    let (base0, _secretas) = estado(&[(1, 100), (2, 1)], 50)?;
    let (_claves_n, tabla_n) = tabla_de(&base0, 1)?;
    let mut base1 = base0.clone();
    let (id, reg) = registro(&base1.parametros_sector, ed(1), 100);
    base1.sectores.insert(id, reg);
    let (claves_n1, tabla_n1) = tabla_de(&base1, 2)?;
    let hash_n1 = hash_tabla(&tabla_n1);
    let cert_n = cert_peso(
        &tabla_n,
        1,
        [0x11u8; 32],
        hash_n1,
        Some(tabla_n1.clone()),
        &bls(1)?,
    )?;
    let mut e1 = base1.clone();
    e1.finalidad_votos_n = 1;
    e1.finalidad_votos = Some(BlockHash::from_digest(Digest::from_bytes([0x11u8; 32])));
    e1.finalidad_votos_h_t = Some(hash_n1);
    e1.tablas_voto_contenido.insert(hash_n1, claves_n1.clone());
    Ok(Escenario {
        e1,
        tabla_n,
        cert_n,
        hash_n1,
    })
}

/// Regresión 5 · REAN-2 · N6: la primera apertura ya **no** exige contigüidad; con base `m` y
/// `n > m+1` se abre el intento `n` (el retroceso `n <= m` lo frena el guard del nodo, no el motor).
#[test]
fn primera_apertura_con_salto_se_abre() -> Res {
    let esc = escenario_cn_tabla_distinta()?;
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    motor.sembrar_punto_control_peso(
        esc.tabla_n.clone(),
        pubs_de(&esc.tabla_n)?,
        esc.cert_n.clone(),
        &[(1, esc.hash_n1)],
    )?;
    motor.avanzar(
        3,
        BlockHash::from_digest(Digest::from_bytes([0x22u8; 32])),
        &esc.e1,
        SLOT,
    )?;
    assert_eq!(
        motor.instancia_actual(),
        Some(3),
        "el salto n > m+1 abre el intento (ya no se rechaza por contigüidad)"
    );
    Ok(())
}

/// Regresión 6 · un motor **nuevo** (sin checkpoint) sobre un estado con finalidad por votos ya
/// aplicada no debe emitir génesis local.
#[test]
fn motor_nuevo_sobre_finalidad_no_emite_genesis() -> Res {
    let esc = escenario_cn_tabla_distinta()?;
    assert!(
        esc.e1.finalidad_votos_h_t.is_some(),
        "el estado de partida tiene finalidad por votos"
    );
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    let salida = motor.avanzar(
        3,
        BlockHash::from_digest(Digest::from_bytes([0x33u8; 32])),
        &esc.e1,
        SLOT,
    );
    assert_eq!(
        motivo_carga(salida)?,
        "bootstrap_sobre_finalidad",
        "sin checkpoint no se inventa génesis sobre estado finalizado"
    );
    assert_eq!(motor.punto(), None, "sin punto");
    assert!(motor.ultimo_certificado_peso().is_none(), "sin certificado");
    assert_eq!(motor.instancia_actual(), None, "sin instancia");
    Ok(())
}

/// Positivo existente · desde un estado realmente sin finalidad, el bootstrap local sigue vigente.
#[test]
fn estado_sin_finalidad_conserva_bootstrap() -> Res {
    let (base, secretas) = estado(&[(1, 100), (2, 1)], 50)?;
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (base, _u) = derivar_tabla_sin_base_con_undo(&base, u64::try_from(SLOT)?);
    assert!(
        base.finalidad_votos_h_t.is_none(),
        "sin finalidad de partida"
    );
    let mut motor = motor_con_claves(secretas);
    motor.avanzar(
        0,
        BlockHash::from_digest(Digest::from_bytes([0x10u8; 32])),
        &base,
        SLOT,
    )?;
    let cierre = motor.cerrar()?;
    assert!(
        cierre.certificado_peso.is_some(),
        "el bootstrap desde estado sin finalidad conserva su comportamiento"
    );
    Ok(())
}

/// Positivo existente · `T_1`/`T_2` de igual contenido conservan el funcionamiento del punto de
/// control por peso.
#[test]
fn sembrado_tabla_igual_certifica() -> Res {
    let (base, secretas) = estado(&[(1, 100), (2, 1)], 50)?;
    let (_claves1, tabla1) = tabla_de(&base, 1)?;
    let (_claves2, tabla2) = tabla_de(&base, 2)?;
    let h2 = hash_tabla(&tabla2);
    assert_eq!(
        h2,
        hash_tabla(&tabla1),
        "T_1 y T_2 de igual contenido (el hash no incluye n)"
    );
    let cert1 = cert_peso(&tabla1, 1, [0x11u8; 32], h2, None, &bls(1)?)?;
    let mut e1 = base.clone();
    e1.finalidad_votos_n = 1;
    e1.finalidad_votos = Some(BlockHash::from_digest(Digest::from_bytes([0x11u8; 32])));
    e1.finalidad_votos_h_t = Some(h2);
    let mut motor = motor_con_claves(secretas);
    motor.sembrar_punto_control_peso(tabla1, pubs_de(&tabla2)?, cert1, &[])?;
    motor.avanzar(
        2,
        BlockHash::from_digest(Digest::from_bytes([0x22u8; 32])),
        &e1,
        SLOT,
    )?;
    let cierre = motor.cerrar()?;
    assert!(
        cierre.certificado_peso.is_some(),
        "con tabla de igual contenido el encadenado casa"
    );
    assert_eq!(motor.ultimo_certificado_peso().map(|c| c.n), Some(2));
    Ok(())
}

/// Positivo · una tabla guardada comprometida de contenido distinto al estado vivo se prefiere
/// frente a la reconstrucción viva (que ya no casa el hash).
#[test]
fn prefiere_tabla_guardada_distinta_del_estado_vivo() -> Res {
    let esc = escenario_cn_tabla_distinta()?;
    // El estado vivo suma otro sector a la clave 1: su tabla canónica ya no es la comprometida.
    let mut e1_vivo = esc.e1.clone();
    let (id, reg) = registro(&e1_vivo.parametros_sector, ed(1), 200);
    e1_vivo.sectores.insert(id, reg);
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    motor.sembrar_punto_control_peso(
        esc.tabla_n.clone(),
        pubs_de(&esc.tabla_n)?,
        esc.cert_n.clone(),
        &[(1, esc.hash_n1)],
    )?;
    motor.avanzar(
        2,
        BlockHash::from_digest(Digest::from_bytes([0x22u8; 32])),
        &e1_vivo,
        SLOT,
    )?;
    assert_eq!(
        motor.tabla_actual().map(hash_tabla),
        Some(esc.hash_n1),
        "se usó la T_2 guardada, no la reconstrucción viva"
    );
    let cierre = motor.cerrar()?;
    assert!(
        cierre.certificado_peso.is_some(),
        "la tabla guardada comprometida se prefiere al estado vivo"
    );
    Ok(())
}

/// Regresión 4 · una carga sobre un motor que ya abrió instancia debe rechazarse.
#[test]
fn carga_sobre_motor_abierto_se_rechaza() -> Res {
    let esc = escenario_cn_tabla_distinta()?;
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    let pubs = pubs_de(&esc.tabla_n)?;
    motor.sembrar_punto_control_peso(
        esc.tabla_n.clone(),
        pubs.clone(),
        esc.cert_n.clone(),
        &[(1, esc.hash_n1)],
    )?;
    motor.avanzar(
        2,
        BlockHash::from_digest(Digest::from_bytes([0x22u8; 32])),
        &esc.e1,
        SLOT,
    )?;
    assert_eq!(motor.instancia_actual(), Some(2));
    let segunda = motor.sembrar_punto_control_peso(
        esc.tabla_n.clone(),
        pubs,
        esc.cert_n.clone(),
        &[(1, esc.hash_n1)],
    );
    assert_eq!(
        segunda,
        Err(ErrorVotos::CargaInicialInvalida {
            motivo: "motor_ya_abierto"
        }),
        "un motor ya abierto no puede resembrarse"
    );
    Ok(())
}

/// Negativo · una tabla con índice distinto del certificado se rechaza sin mutar.
#[test]
fn rechaza_tabla_siguiente_con_indice_erroneo() -> Res {
    let esc = escenario_cn_tabla_distinta()?;
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    let mut tabla_mala = esc.tabla_n.clone();
    tabla_mala.n = 5;
    let error = motor.sembrar_punto_control_peso(
        tabla_mala,
        pubs_de(&esc.tabla_n)?,
        esc.cert_n.clone(),
        &[],
    );
    assert_eq!(
        error,
        Err(ErrorVotos::CargaInicialInvalida {
            motivo: "indice_certificado"
        })
    );
    assert_eq!(motor.punto(), None);
    assert!(motor.ultimo_certificado_peso().is_none());
    Ok(())
}

/// Negativo · claves públicas no alineadas con la tabla se rechazan.
#[test]
fn rechaza_claves_desalineadas() -> Res {
    let esc = escenario_cn_tabla_distinta()?;
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    let mut pubs = pubs_de(&esc.tabla_n)?;
    // Misma longitud, pero una clave distinta: desalineación (no `LongitudesIncompatibles`).
    pubs[0] = bls(9)?.clave_publica();
    let error = motor.sembrar_punto_control_peso(
        esc.tabla_n.clone(),
        pubs,
        esc.cert_n.clone(),
        &[(1, esc.hash_n1)],
    );
    assert_eq!(
        error,
        Err(ErrorVotos::CargaInicialInvalida {
            motivo: "claves_desalineadas"
        })
    );
    assert!(motor.ultimo_certificado_peso().is_none());
    Ok(())
}

/// Positivo · tras un rechazo de carga, la carga correcta aún funciona (atomicidad).
#[test]
fn tras_rechazo_la_carga_correcta_funciona() -> Res {
    let esc = escenario_cn_tabla_distinta()?;
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    let mut tabla_mala = esc.tabla_n.clone();
    tabla_mala.n = 7;
    let error = motor.sembrar_punto_control_peso(
        tabla_mala,
        pubs_de(&esc.tabla_n)?,
        esc.cert_n.clone(),
        &[],
    );
    assert!(error.is_err(), "la carga mala se rechaza");
    assert!(motor.ultimo_certificado_peso().is_none());
    let buena = motor.sembrar_punto_control_peso(
        esc.tabla_n.clone(),
        pubs_de(&esc.tabla_n)?,
        esc.cert_n.clone(),
        &[(1, esc.hash_n1)],
    );
    assert_eq!(buena, Ok(()), "tras el rechazo la carga correcta entra");
    motor.avanzar(
        2,
        BlockHash::from_digest(Digest::from_bytes([0x22u8; 32])),
        &esc.e1,
        SLOT,
    )?;
    assert!(motor.cerrar()?.certificado_peso.is_some());
    Ok(())
}

/// C6-2 · un certificado por peso con `n = u64::MAX` **auténtico** (firma agregada real sobre el
/// mensaje de `nMAX`) verifica con `verificar_firma_peso`.
#[test]
fn certificado_n_max_autentico_verifica() -> Res {
    let (base, _secretas) = estado(&[(1, 100), (2, 1)], 50)?;
    let (_claves, tabla) = tabla_de(&base, u64::MAX)?;
    let pubs = pubs_de(&tabla)?;
    let cert = cert_peso(&tabla, u64::MAX, [0x11u8; 32], [0xABu8; 32], None, &bls(1)?)?;
    assert_eq!(cert.n, u64::MAX, "el certificado se firma con n=u64::MAX");
    assert_eq!(tabla.n, u64::MAX, "la tabla lleva el mismo índice");
    verificar_firma_peso(&tabla, &pubs, &cert)?;
    Ok(())
}

#[test]
fn certt_checkpoint_viejo_siembra_y_certificado_actual_aplica() -> Res {
    use zx_consensus::transicion::votos::{
        W_REVEAL_SLOTS_VOTOS, apertura_ventana, aplicar_certificado_peso_con_undo, cierre_ventana,
    };
    use zx_consensus::transicion::{ErrorTransicion, Fase};
    use zx_core::OperacionAlmacenamiento;
    let esc = escenario_cn_tabla_distinta()?;
    let n = 100;
    let slot = apertura_ventana(n);
    assert!(slot > cierre_ventana(esc.cert_n.n).saturating_add(W_REVEAL_SLOTS_VOTOS));
    let mut estado = esc.e1;
    estado.fase = Fase::PoST;
    let (estado, _) = derivar_tabla_sin_base_con_undo(&estado, slot);
    let op = OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(1),
        bytes: zx_votos::serial_certificado_peso(&esc.cert_n),
    };
    let (sin_cambio, _, r) = aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(slot)?);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPlazo));
    assert_eq!(sin_cambio, estado);
    let mut motor = motor_con_claves(vec![bls(1)?, bls(2)?]);
    motor.sembrar_punto_control_peso(
        esc.tabla_n.clone(),
        pubs_de(&esc.tabla_n)?,
        esc.cert_n,
        &[(1, esc.hash_n1)],
    )?;
    motor.avanzar(
        n,
        BlockHash::from_digest(Digest::from_bytes([0x22; 32])),
        &estado,
        i64::try_from(slot)?,
    )?;
    let certificado = motor
        .cerrar()?
        .certificado_peso
        .ok_or("sin certificado nuevo")?;
    assert_eq!(certificado.n, n);
    let op = OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(1),
        bytes: zx_votos::serial_certificado_peso(&certificado),
    };
    let (recuperado, _, r) = aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(slot)?);
    r?;
    assert_eq!(recuperado.finalidad_votos_n, n);
    assert_eq!(
        recuperado.finalidad_votos.map(|h| *h.as_bytes()),
        Some(certificado.candidato)
    );
    Ok(())
}
