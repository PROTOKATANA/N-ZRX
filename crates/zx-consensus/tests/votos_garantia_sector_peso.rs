//! FV-N6-C4 · las penas de voto alcanzan la **fianza no terminal** del propietario.
//!
//! Cubre R1 (ausencia al certificar), R2 (ausencia revelada) y R3 (doble voto) cuando el
//! propietario tiene `Garantia.activo = 0` y su peso sale solo de `RegistroSector.fianza`.
//! Comprueba además: débito una sola vez R1↔R2 en ambos órdenes, fianza parcial ⇒ `Suspendido`
//! (peso 0 y no elegible), refresco de caja, conservación `I-1` (que ahora suma fianzas no
//! terminales) y undo bit a bit.
//!
//! Fixtures: los sectores se montan con `fianza = q_sec` y `Garantia.activo` declarado, con
//! `emitido = Σ activo + Σ fianza` (estado inicial **contablemente conservado** y declarado). Las
//! claves BLS, el sorteo VRF y las firmas son reales.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::panic,
    dead_code,
    reason = "test de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use zx_consensus::cajas::{CajaId, EstadoHueco, EtapaCaja, Ocupante, RegistroCaja};
use zx_consensus::sectores::{
    ClaveVoto, EstadoEfectivo, Etapa, ParametrosSector, RegistroSector, SectorId, estado_efectivo,
};
use zx_consensus::transicion::caja::{fianza_caja, invariante_caja, raiz_de_caja};
use zx_consensus::transicion::votos::{
    PRIMA_DISPONIBILIDAD_ACTIVA, W_REVEAL_SLOTS_VOTOS, aplicar_certificado_peso_con_undo,
    aplicar_evidencia_votos_peso_con_undo, cierre_ventana, derivar_tabla_sin_base_con_undo,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo, deshacer, elegible_sector, fuente_peso_de,
    total_garantia,
};
use zx_core::{
    Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento,
    VotoPesoEvidencia,
};
use zx_votos::{Clave, DOMINIO_VOTO, Firma, Tabla};

const K: u64 = 65_536;
const B: u64 = 2;
const SLOT: i64 = 13;
const Q_SEC: i128 = 140;

type Error = Box<dyn std::error::Error>;

/// TB-1c-2 · X2 · montaje autorizado: llama al gancho de producto `derivar_tabla_sin_base` con el
/// slot del bloque (no una copia) para que la derivada que el primer certificado declara esté en `Q`.
fn preparar_cola_sin_base(est: &mut Estado, slot: u64) {
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(est, slot);
    *est = nuevo;
}

/// Clave BLS determinista por índice (misma semilla que `finalidad_votos.rs`).
fn bls(indice: u8) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
}

/// Clave Ed25519 determinista por índice (identificador del estado).
fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn registro(p: &ParametrosSector, clave: ClavePublica, indice: u16) -> (SectorId, RegistroSector) {
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

/// Estado conservado: `emitido = Σ activo + Σ fianza`, `quemado = 0`, `utxo` vacío.
///
/// Cada tupla es `(índice de clave, nº de sectores, garantía activa)`.
fn estado_conservado(
    claves: &[(u8, usize, i64)],
) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let mut secretas = Vec::new();
    let mut emitido: i128 = 0;
    for (indice, n_sectores, activo) in claves {
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
            emitido += i128::from(reg.fianza);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(*activo)?;
        emitido += i128::from(*activo);
        est.garantias.insert(e, g);
        secretas.push(secreta);
    }
    est.emitido = emitido;
    est.quemado = 0;
    Ok((est, secretas))
}

/// Σ fianzas no terminales de `clave` (lo que la producción debe sumar en `I-1`).
fn fianza_de(est: &Estado, clave: &ClavePublica) -> i128 {
    est.sectores
        .iter()
        .filter(|(id, r)| id.clave == *clave && !r.es_terminal())
        .map(|(_, r)| i128::from(r.fianza))
        .sum()
}

/// Total castigable calculado **desde la API pública** (oráculo del test).
fn total_castigable_test(est: &Estado, clave: &ClavePublica) -> i128 {
    let cuenta = est.garantias.get(clave).map_or(0, total_garantia);
    cuenta + fianza_de(est, clave)
}

/// Conservación **independiente** calculada dentro del test: `UTXO` + las cuatro sub-cuentas de
/// `Garantia` (`activo`, `pendientes`, `en_retirada`, `creditos`) + `Σ fianza` no terminal
/// `== emitido − quemado`.
///
/// No usa `invariante_i1` productiva: en la base sin C4 esa función no suma fianzas y enmascararía
/// el rojo de las penas antes de ejercer el débito. El test dedicado de `I-1` vive en
/// `alcance_garantia.rs` y sí comprueba `invariante_i1`.
fn conservacion(est: &Estado) -> bool {
    let mut total: i128 = est.utxo.values().map(|e| i128::from(e.valor.brek())).sum();
    for g in est.garantias.values() {
        total += i128::from(g.activo.brek());
        total += g
            .pendientes
            .iter()
            .map(|p| i128::from(p.importe.brek()))
            .sum::<i128>();
        total += g
            .en_retirada
            .iter()
            .map(|r| i128::from(r.importe.brek()))
            .sum::<i128>();
        total += g
            .creditos
            .iter()
            .map(|p| i128::from(p.importe.brek()))
            .sum::<i128>();
    }
    for r in est.sectores.values() {
        if !r.es_terminal() {
            total += i128::from(r.fianza);
        }
    }
    total == est.emitido - est.quemado
}

/// Tabla `T_n` del contrato derivada del estado.
fn tabla_de(est: &Estado, n: u64) -> Result<(Vec<ClaveTablaVoto>, Tabla), Error> {
    let p = est.parametros_sector;
    let mut claves_payload = Vec::new();
    let mut tabla_claves = Vec::new();
    for (e, cv) in &est.claves_voto {
        let peso = fuente_peso_de(est, e, SLOT, &p);
        if peso <= 0 {
            continue;
        }
        let peso = u64::try_from(peso)?;
        let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && est.pruebas.contains_key(e);
        claves_payload.push(ClaveTablaVoto {
            clave_bls: cv.clave_bls,
            peso,
            activo: true,
            prueba,
            garantia: peso,
        });
        tabla_claves.push(Clave {
            clave: cv.clave_bls.to_vec(),
            peso,
            activo: true,
            prueba,
            garantia: peso,
        });
    }
    Ok((
        claves_payload,
        Tabla {
            n,
            claves: tabla_claves,
        },
    ))
}

/// M9-b1 · orden canónico (ascendente por bytes de clave BLS).
fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

fn hash_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&Tabla {
        n: 0,
        claves: claves
            .iter()
            .map(|c| Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    })
}

/// M9-b1 · deja la tabla de la ventana `n` como el flujo por peso (contenido + asociación).
fn poner_tabla(est: &mut Estado, n: u64, claves: Vec<ClaveTablaVoto>) {
    let h = hash_payload(&claves);
    est.tablas_voto_contenido.insert(h, claves);
    est.tabla_ventana_voto.insert(n, h);
}

/// Certificado compacto `0x09` con firmas BLS reales sobre el mensaje A3 (raíz cero) y la tabla
/// vigente `claves`; declara como siguiente el hash de esa misma tabla (sin cambio).
fn certificado_peso(
    _est: &Estado,
    secretas: &[zx_votos::ClaveSecreta],
    n: u64,
    claves: &[ClaveTablaVoto],
    firmantes: &[usize],
    _tabla_siguiente: Option<&[ClaveTablaVoto]>,
) -> Result<OperacionAlmacenamiento, Error> {
    let vigente = canoniza(claves.to_vec());
    let tabla = Tabla {
        n,
        claves: vigente
            .iter()
            .map(|c| Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    };
    let h_t = zx_votos::hash_tabla(&tabla);
    let candidato = [0x11u8; 32];
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for (orden, secreta) in secretas.iter().enumerate() {
        if !firmantes.contains(&orden) {
            continue;
        }
        let pk = secreta.clave_publica();
        let Some(pos) = tabla
            .claves
            .iter()
            .position(|c| c.clave == pk.bytes().to_vec())
        else {
            continue;
        };
        let firma = zx_votos::firmar(secreta, DOMINIO_VOTO, &mensaje)?;
        votos.push((pos + 1, firma));
    }
    let cert = zx_votos::construir_certificado(n, candidato, h_t, [0u8; 32], &tabla, &votos)?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

fn param_evidencia() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 0,
        m_margen_slots: 0,
        cbid: 0,
        evp: true,
    }
}

fn params_transicion() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 0,
        w_min: primitive_types::U256::zero(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 600,
        f_slots: Some(600),
        subsidio_pow: |_| Amount::CERO,
        subsidio_post: |_| Amount::CERO,
    }
}

/// AUS-2a R7: el certificado **ya no** cobra la ausencia de la fianza ni suspende el sector; el
/// cobro vive en la liquidación de la ventana. (Aserción cambiada: antes fijaba el paso (6).)
#[test]
fn r7_certificado_no_cobra_ni_suspende_peso() -> Result<(), Error> {
    let (mut base, secretas) = estado_conservado(&[(1, 20, 0), (2, 1, 0)])?;
    assert!(conservacion(&base), "fixture conservado con fianza");
    preparar_cola_sin_base(&mut base, u64::try_from(SLOT)?);
    let (claves, _) = tabla_de(&base, 1)?;
    assert_eq!(total_castigable_test(&base, &ed(2)), Q_SEC);
    let op = certificado_peso(&base, &secretas, 1, &claves, &[0], None)?;
    let (nuevo, undo, r) = aplicar_certificado_peso_con_undo(&base, &op, SLOT);
    r?;

    assert_eq!(
        fianza_de(&nuevo, &ed(2)),
        Q_SEC,
        "R7: el certificado no cobra de la fianza (antes cobraba m_min)"
    );
    assert_eq!(
        fianza_de(&nuevo, &ed(1)),
        fianza_de(&base, &ed(1)),
        "el votante no paga"
    );
    assert_eq!(nuevo.quemado, base.quemado, "R7: el certificado no quema");
    let p = nuevo.parametros_sector;
    assert_eq!(
        fuente_peso_de(&nuevo, &ed(2), SLOT, &p),
        1,
        "R7: sin cobro, la fianza sigue completa y el peso vivo es 1"
    );
    let sid2 = SectorId {
        clave: ed(2),
        sector_index: 0,
        version: 0,
    };
    assert_eq!(
        estado_efectivo(&nuevo.sectores[&sid2], SLOT, &p),
        EstadoEfectivo::Activo,
        "R7: el sector sigue activo"
    );
    assert!(
        elegible_sector(&nuevo, &ed(2), 0, 1, SLOT, &p),
        "R7: conserva la producción"
    );
    assert!(conservacion(&nuevo), "conservación tras R7");
    assert_eq!(deshacer(&nuevo, &undo), base, "undo bit a bit");
    Ok(())
}

/// R3: el doble voto confisca sobre `V = total_castigable` (fianza incluida) y quema el resto.
#[test]
fn r3_doble_voto_alcanza_la_fianza_sin_activo_peso() -> Result<(), Error> {
    let (base, secretas) = estado_conservado(&[(1, 1, 0)])?;
    let secreta = secretas.first().ok_or("sin clave")?;
    let pk = secreta.clave_publica();
    let n = 3;
    let h_t = [0x33u8; 32];
    let h1 = [0x01u8; 32];
    let h2 = [0x02u8; 32];
    let f1 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &h1, &h_t, &h1),
    )?;
    let f2 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &h2, &h_t, &h2),
    )?;
    let op = OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: pk.bytes(),
        voto1: VotoPesoEvidencia {
            n,
            candidato: h1,
            h_t_siguiente: h_t,
            raiz_estado: h1,
            firma: f1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n,
            candidato: h2,
            h_t_siguiente: h_t,
            raiz_estado: h2,
            firma: f2.bytes(),
        },
    };
    assert_eq!(total_castigable_test(&base, &ed(1)), Q_SEC);
    let (nuevo, undo, r) = aplicar_evidencia_votos_peso_con_undo(
        &base,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    r?;
    assert_eq!(
        fianza_de(&nuevo, &ed(1)),
        0,
        "V = 140, f = 1 ⇒ confisca la fianza"
    );
    assert_eq!(nuevo.quemado, Q_SEC - Q_SEC / 4, "quema C − suelo(C/4)");
    let g9 = nuevo.garantias.get(&ed(9)).ok_or("productor")?;
    let credito: i64 = g9.creditos.iter().map(|p| p.importe.brek()).sum();
    assert_eq!(
        i128::from(credito),
        Q_SEC / 4,
        "recompensa real al incluidor"
    );
    assert!(conservacion(&nuevo), "conservación tras R3");
    assert_eq!(deshacer(&nuevo, &undo), base, "undo bit a bit");

    let (_, _, dup) = aplicar_evidencia_votos_peso_con_undo(
        &nuevo,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        11,
    );
    assert_eq!(dup, Err(ErrorTransicion::ErrEvidenciaDuplicada));
    Ok(())
}

/// AUS-2a R7: el certificado **no** debita de la caja; con el cobro retirado, la caché sigue
/// coherente y con el hueco Activo. (Aserción cambiada: antes fijaba el paso (6).)
#[test]
fn r7_certificado_no_refresca_la_cache_por_pena_peso() -> Result<(), Error> {
    let (base, secretas) = estado_conservado(&[(1, 20, 0), (2, 1, 0)])?;
    let p = base.parametros_sector;
    let sid = SectorId {
        clave: ed(2),
        sector_index: 0,
        version: 0,
    };
    let cid = CajaId {
        clave: ed(2),
        seq: 1,
    };
    let mut con_caja = base.clone();
    let mut caja = RegistroCaja::nueva(cid, 1, 0);
    caja.huecos[0] = Ocupante {
        sector_index: 0,
        version: 0,
        ocupado: true,
    };
    caja.ocupacion = 1;
    caja.n = 1;
    caja.etapa = EtapaCaja::Abierta;
    caja.raiz = raiz_de_caja(&con_caja, &caja);
    caja.fianza = fianza_caja(&con_caja, &caja);
    caja.estado_hueco = EstadoHueco::poner(0, 0, EstadoHueco::Activo.codigo());
    con_caja.cajas.insert(cid, caja);
    assert!(invariante_caja(&con_caja, &p));
    preparar_cola_sin_base(&mut con_caja, u64::try_from(SLOT)?);

    let (claves, _) = tabla_de(&con_caja, 1)?;
    let op = certificado_peso(&con_caja, &secretas, 1, &claves, &[0], None)?;
    let (nuevo, undo, r) = aplicar_certificado_peso_con_undo(&con_caja, &op, SLOT);
    r?;
    assert_eq!(
        i128::from(nuevo.sectores[&sid].fianza),
        Q_SEC,
        "R7: no debita"
    );
    let c = nuevo.cajas.get(&cid).ok_or("caja")?;
    assert_eq!(
        c.fianza,
        fianza_caja(&nuevo, c),
        "caché de fianza coherente"
    );
    assert_eq!(i128::from(c.fianza), Q_SEC);
    assert_eq!(
        EstadoHueco::de_mascara(c.estado_hueco, 0),
        EstadoHueco::Activo.codigo(),
        "el hueco sigue Activo"
    );
    assert!(invariante_caja(&nuevo, &p), "invariante de caja tras R7");
    assert_eq!(deshacer(&nuevo, &undo), con_caja, "undo bit a bit con caja");
    Ok(())
}

/// Bloque PoST vacío: su aplicación dispara la liquidación de las ventanas vencidas.
fn bloque_post_vacio(
    est: &Estado,
    slot: u64,
) -> Result<(Estado, zx_consensus::transicion::Undo), Error> {
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: BlockHash::from_digest(Digest::from_bytes([0x9A; 32])),
            padre: BlockHash::from_digest(Digest::from_bytes([0x9B; 32])),
            slot,
            productor: ed(1),
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        Vec::new(),
    );
    Ok(aplicar_con_undo(
        est,
        &bloque,
        &params_transicion(),
        0,
        &param_evidencia(),
    )?)
}

/// AUS-2b · B7 / PD-1b · C6: el deber usa el **mismo peso** que el reparto del certificado
/// (`peso_de_clave` con el `b` vigente) y **solo claves activas**, pero **sin** cuota entera: toda
/// clave activa con peso de voto > 0 debe. Una clave inactiva no tiene deber.
#[test]
fn b7_peso_efectivo_y_claves_activas_deciden_el_deber_peso() -> Result<(), Error> {
    let (mut est, _secretas) = estado_conservado(&[(1, 1, 1), (2, 1, 1), (3, 1, 1), (4, 1, 1)])?;
    est.fase = Fase::PoST;
    let n = 1u64;
    let bls_de = |i: u8| est.claves_voto[&ed(i)].clave_bls;
    let tabla = vec![
        ClaveTablaVoto {
            clave_bls: bls_de(1),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        },
        ClaveTablaVoto {
            clave_bls: bls_de(2),
            peso: 1_000_000,
            activo: false,
            prueba: false,
            garantia: 1_000_000,
        },
        ClaveTablaVoto {
            clave_bls: bls_de(3),
            peso: 1,
            activo: true,
            prueba: true,
            garantia: 1,
        },
        ClaveTablaVoto {
            clave_bls: bls_de(4),
            peso: 100_000,
            activo: true,
            prueba: false,
            garantia: 100_000,
        },
    ];
    // Oráculo independiente con las **mismas** funciones canónicas que C6 manda usar.
    let a_contrato = |c: &ClaveTablaVoto| Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    };
    let esperado: Vec<bool> = tabla
        .iter()
        .map(|c| Ok(zx_votos::peso::peso_de_clave(&a_contrato(c), B)? > 0))
        .collect::<Result<_, zx_votos::ErrorVotos>>()?;
    // PD-1b · C6: toda clave activa con peso de voto > 0 tiene deber, **sin** cuota entera. Antes de
    // PD-1b, la clave 1 (peso 1 con `K < W`) no tenía cuota entera y no debía; ahora sí.
    assert_eq!(
        esperado,
        vec![true, false, true, true],
        "oráculo C6 del deber"
    );

    poner_tabla(&mut est, n, tabla);
    let slot = cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1;
    let (nuevo, _undo) = bloque_post_vacio(&est, slot)?;
    let d = |i: u8| nuevo.deuda_ausencia.get(&ed(i)).copied().unwrap_or(0);
    for i in 1u8..=4 {
        assert_eq!(
            d(i) > 0,
            esperado[usize::from(i - 1)],
            "clave {i}: deber según N8"
        );
    }
    Ok(())
}

/// AUS-2b · B8 · el cobro de la liquidación sale de la **fianza** del sector: se cumplen
/// `invariante_caja` y `conservacion`, la caché de fianza queda refrescada y el undo es exacto (las
/// aserciones que antes fijaba `la_pena_refresca_la_cache_de_la_caja`).
#[test]
fn b8_cobro_de_liquidacion_desde_la_fianza_conserva_caja_y_cuenta_peso() -> Result<(), Error> {
    // `G·7 = 1 401 600 004` ⇒ cobra 1 brek y deja resto 4.
    const G_B8: i128 = 200_228_572;
    let (base, _secretas) = estado_conservado(&[(1, 1, 0)])?;
    let mut base = base;
    base.fase = Fase::PoST;
    let sid = SectorId {
        clave: ed(1),
        sector_index: 0,
        version: 0,
    };
    {
        let r = base.sectores.get_mut(&sid).ok_or("sector")?;
        r.fianza = i64::try_from(G_B8)?;
    }
    base.emitido = G_B8;
    base.quemado = 0;
    assert!(conservacion(&base), "fixture conservado con fianza");

    // Caja del sector: es la caché que `debitar_castigable` refresca al cobrar.
    let p = base.parametros_sector;
    let cid = CajaId {
        clave: ed(1),
        seq: 1,
    };
    let mut caja = RegistroCaja::nueva(cid, 1, 0);
    caja.huecos[0] = Ocupante {
        sector_index: 0,
        version: 0,
        ocupado: true,
    };
    caja.ocupacion = 1;
    caja.n = 1;
    caja.etapa = EtapaCaja::Abierta;
    caja.raiz = raiz_de_caja(&base, &caja);
    caja.fianza = fianza_caja(&base, &caja);
    caja.estado_hueco = EstadoHueco::poner(0, 0, EstadoHueco::Activo.codigo());
    base.cajas.insert(cid, caja);
    assert!(invariante_caja(&base, &p));

    let n = 1u64;
    // Tabla manual con la clave del estado: el objeto de B8 es el cobro de la liquidación desde la
    // fianza, no el reparto (que ya fija B7).
    let mut est = base.clone();
    let t = vec![ClaveTablaVoto {
        clave_bls: base.claves_voto[&ed(1)].clave_bls,
        peso: 1,
        activo: true,
        prueba: false,
        garantia: 1,
    }];
    poner_tabla(&mut est, n, t);
    let slot = cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1;
    let (nuevo, undo) = bloque_post_vacio(&est, slot)?;
    assert_eq!(
        nuevo.liquidacion_voto_hasta,
        Some(1),
        "la ventana 1 se liquida"
    );
    assert_eq!(nuevo.quemado, 1, "cobra 1 brek de la fianza");
    assert_eq!(
        i128::from(nuevo.sectores[&sid].fianza),
        G_B8 - 1,
        "el cobro sale de la fianza del sector"
    );
    assert_eq!(
        nuevo.deuda_ausencia.get(&ed(1)).copied(),
        Some(4),
        "resto exacto de la deuda"
    );
    assert!(
        invariante_caja(&nuevo, &p),
        "invariante de caja tras el cobro"
    );
    assert!(conservacion(&nuevo), "conservación tras el cobro");
    let c = nuevo.cajas.get(&cid).ok_or("caja")?;
    assert_eq!(
        c.fianza,
        fianza_caja(&nuevo, c),
        "caché de fianza refrescada"
    );
    assert_eq!(deshacer(&nuevo, &undo), est, "undo bit a bit");
    Ok(())
}
