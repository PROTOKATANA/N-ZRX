//! M9-b1 · gemelas por el flujo por peso de `finalidad_continuidad.rs` (lista P, 4 pruebas).
//!
//! `0x04`/`0x06` se sustituyen por el certificado compacto `0x09`
//! (`aplicar_certificado_peso_con_undo`). El estado se monta como lo deja el flujo por peso. La
//! parte de VRF del fraude desaparece (el `0x09` no lleva sorteo): se anota.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::type_complexity,
    dead_code,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use zx_consensus::sectores::{
    ClaveVoto, Etapa, MotivoSector, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::{
    aplicar_certificado_peso_con_undo, derivar_tabla_sin_base_con_undo,
};
use zx_consensus::transicion::{
    ErrorTransicion, Estado, Garantia, aplicar_operacion_con_undo, deshacer, fuente_peso_de,
    materializar_con_undo,
};
use zx_core::{Amount, ClavePublica, ClaveTablaVoto, OperacionAlmacenamiento, OperacionSector};
use zx_votos::peso::MotivoPeso;
use zx_votos::{Clave, DOMINIO_VOTO, Firma, Tabla};

const B: u64 = 2;
const N_CLAVES: usize = 16;

type Error = Box<dyn std::error::Error>;

/// TB-1c-2 · X2 · montaje autorizado: llama al gancho de producto `derivar_tabla_sin_base` con el
/// slot del bloque (no una copia) para que la derivada que el primer certificado declara esté en `Q`.
fn preparar_cola_sin_base(est: &mut Estado, slot: u64) {
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(est, slot);
    *est = nuevo;
}

fn ed(i: u8) -> ClavePublica {
    ClavePublica::desde_bytes([i; 32])
}

/// Registro de sector activo (para montar una segunda tabla auténtica).
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

fn bls(indice: usize) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = u8::try_from(indice)?;
    ikm[30] = 0xD3;
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
}

fn tabla_de(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
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
    }
}

fn hash_tabla(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_de(0, claves))
}

fn estado_fixture(extra: i64) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let mut secretas = Vec::with_capacity(N_CLAVES);
    for i in 0..N_CLAVES {
        let s = bls(i)?;
        let pk = s.clave_publica();
        let e = ed(u8::try_from(i)?);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(p.q_sec.saturating_add(extra))?;
        est.garantias.insert(e, g);
        secretas.push(s);
    }
    Ok((est, secretas))
}

fn estado_una_clave(extra: i64) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let s = bls(0)?;
    let pk = s.clave_publica();
    let e = ed(0);
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: pk.bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(p.q_sec.saturating_add(extra))?;
    est.garantias.insert(e, g);
    Ok((est, vec![s]))
}

fn slot_de(n: u64) -> i64 {
    core::cmp::max(
        zx_consensus::transicion::votos::apertura_ventana(n) as i64,
        12,
    )
}

fn alta(est: &Estado, i: u8, slot: i64) -> Result<Estado, Error> {
    let p = est.parametros_sector;
    let op = OperacionSector::Alta {
        clave: ed(i),
        sector_index: 0,
        version: 0,
        r2: [0u8; 32],
        history_size: 1,
    };
    let (nuevo, res) = aplicar_operacion_con_undo(est, &op, slot, &p);
    assert_eq!(res.motivo, MotivoSector::Ok, "alta de la clave {i}");
    Ok(nuevo)
}

fn activar(est: &Estado, claves: &[u8]) -> Result<Estado, Error> {
    let p = est.parametros_sector;
    let mut actual = est.clone();
    for i in claves {
        actual = alta(&actual, *i, 0)?;
    }
    let (activo, _) = materializar_con_undo(&actual, p.m_sec, &p);
    Ok(activo)
}

fn payload_tabla(est: &Estado, slot: i64) -> Result<Vec<ClaveTablaVoto>, Error> {
    let p = est.parametros_sector;
    let mut claves = Vec::new();
    for e in est.claves_voto.keys() {
        let peso = fuente_peso_de(est, e, slot, &p);
        if peso <= 0 {
            continue;
        }
        let peso = u64::try_from(peso)?;
        let cv = est.claves_voto.get(e).ok_or("clave de voto ausente")?;
        claves.push(ClaveTablaVoto {
            clave_bls: cv.clave_bls,
            peso,
            activo: true,
            prueba: false,
            garantia: peso,
        });
    }
    Ok(claves)
}

fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

/// Certificado compacto `0x09` con firmas BLS reales sobre el mensaje A3 (raíz cero).
fn certificado_peso(
    secretas: &[zx_votos::ClaveSecreta],
    n: u64,
    claves_payload: &[ClaveTablaVoto],
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    firmantes: &[usize],
    _tabla_siguiente: Option<&[ClaveTablaVoto]>,
) -> Result<OperacionAlmacenamiento, Error> {
    let vigente = canoniza(claves_payload.to_vec());
    let tabla = tabla_de(n, &vigente);
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &[0u8; 32]);
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
    let cert =
        zx_votos::construir_certificado(n, candidato, h_t_siguiente, [0u8; 32], &tabla, &votos)?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

/// Adultera el primer byte de la firma BLS agregada del certificado por peso.
fn adulterar_firma(op: &mut OperacionAlmacenamiento) {
    let OperacionAlmacenamiento::CertificadoPeso { bytes, .. } = op else {
        return;
    };
    // La firma de 96 bytes cierra el cuerpo fijo del certificado.
    if let Some(byte) = bytes.last_mut() {
        *byte ^= 0xFF;
    }
}

/// (1) `C_71 → C_73` se acepta (reanudación R4); el salto a 74 con otra tabla se rechaza; y `C_72`
/// tras `C_71` sigue encadenando.
#[test]
fn hueco_desde_ancla_se_aplica_y_la_tabla_distinta_se_rechaza_peso() -> Result<(), Error> {
    let (base, secretas) = estado_fixture(0)?;
    let mut activo = activar(
        &base,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    )?;
    let p = activo.parametros_sector;
    let claves16 = canoniza(payload_tabla(&activo, p.m_sec)?);
    assert_eq!(claves16.len(), N_CLAVES);
    let claves15: Vec<ClaveTablaVoto> = claves16
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != 5)
        .map(|(_, c)| *c)
        .collect();
    let h16 = hash_tabla(&claves16);
    let h15 = hash_tabla(&claves15);
    assert_ne!(h16, h15);

    let firmantes16: Vec<usize> = (0..N_CLAVES).collect();
    let firmantes15: Vec<usize> = (0..N_CLAVES - 1).collect();
    let cand_x = [0x11u8; 32];
    let cand_z = [0x22u8; 32];
    let cand_w = [0x33u8; 32];
    // TB-1c-2 · X2 · T5′: sin base, el gancho X1 ya derivó y guardó la tabla de la ventana.
    preparar_cola_sin_base(&mut activo, u64::try_from(slot_de(71))?);

    // Base: `0x09` de la ventana 71 con `T_16` y compromiso siguiente `h16`.
    let c71 = certificado_peso(&secretas, 71, &claves16, cand_x, h16, &firmantes16, None)?;
    let (ancla, undo71, r) = aplicar_certificado_peso_con_undo(&activo, &c71, slot_de(71));
    r?;
    assert_eq!(ancla.finalidad_votos_n, 71);
    assert_eq!(ancla.finalidad_votos_h_t, Some(h16));
    assert_eq!(deshacer(&ancla, &undo71), activo, "undo de C_71 exacto");

    // Reanudación: el salto `C_71 → C_73` con la tabla vigente se acepta.
    let c73 = certificado_peso(&secretas, 73, &claves16, cand_w, h16, &firmantes16, None)?;
    let (reanudado, undo_salto, r_salto) =
        aplicar_certificado_peso_con_undo(&ancla, &c73, slot_de(73));
    println!("P1_SALTO C_71->C_73 -> {r_salto:?}");
    r_salto?;
    assert_eq!(reanudado.finalidad_votos_n, 73);
    assert_eq!(deshacer(&reanudado, &undo_salto), ancla, "undo del salto");

    // Contraste: el salto a 74 con otra tabla se rechaza sin mutar.
    let c74 = certificado_peso(&secretas, 74, &claves15, cand_w, h15, &firmantes15, None)?;
    let (sin_mutar, _, r74) = aplicar_certificado_peso_con_undo(&ancla, &c74, slot_de(74));
    assert!(r74.is_err(), "tabla distinta rechazada: {r74:?}");
    assert_eq!(sin_mutar, ancla);

    // `C_72` tras `C_71` también encadena.
    let c72 = certificado_peso(&secretas, 72, &claves16, cand_z, h16, &firmantes16, None)?;
    let (paso1, undo72, r) = aplicar_certificado_peso_con_undo(&ancla, &c72, slot_de(72));
    r?;
    assert_eq!(paso1.finalidad_votos_n, 72);
    assert_eq!(deshacer(&paso1, &undo72), ancla, "undo de C_72 exacto");
    Ok(())
}

/// (2) Bootstrap: primera adopción `n > 0` sin ancla y primera adopción `n = 0` siguen válidas.
#[test]
fn bootstrap_primera_adopcion_sigue_valida_peso() -> Result<(), Error> {
    // (a) `n = 72` sin certificado previo.
    let (base, secretas) = estado_una_clave(0)?;
    let mut activo = activar(&base, &[0])?;
    let n: u64 = 72;
    let slot = slot_de(n);
    preparar_cola_sin_base(&mut activo, u64::try_from(slot)?);
    let claves = canoniza(payload_tabla(&activo, activo.parametros_sector.m_sec)?);
    let h_siguiente = hash_tabla(&claves);
    let cert = certificado_peso(&secretas, n, &claves, [0x44; 32], h_siguiente, &[0], None)?;
    let (nodo, undo, r) = aplicar_certificado_peso_con_undo(&activo, &cert, slot);
    r?;
    println!(
        "P2_BOOTSTRAP n={} aceptado_sin_{} finalidad={}",
        nodo.finalidad_votos_n,
        n - 1,
        nodo.finalidad_votos.is_some()
    );
    assert_eq!(nodo.finalidad_votos_n, n);
    assert_eq!(nodo.finalidad_votos_h_t, Some(h_siguiente));
    assert_eq!(deshacer(&nodo, &undo), activo, "undo de bootstrap exacto");

    // (b) `n = 0` como primera adopción.
    let (base0, secretas0) = estado_una_clave(0)?;
    let mut activo0 = activar(&base0, &[0])?;
    let p0 = activo0.parametros_sector;
    let claves0 = canoniza(payload_tabla(&activo0, p0.m_sec)?);
    let h1 = hash_tabla(&claves0);
    preparar_cola_sin_base(&mut activo0, u64::try_from(p0.m_sec)?);
    let cert0 = certificado_peso(&secretas0, 0, &claves0, [0x55; 32], h1, &[0], None)?;
    let (nodo0, undo0, r0) = aplicar_certificado_peso_con_undo(&activo0, &cert0, p0.m_sec);
    r0?;
    assert_eq!(nodo0.finalidad_votos_n, 0);
    assert_eq!(nodo0.finalidad_votos_h_t, Some(h1));
    assert_eq!(deshacer(&nodo0, &undo0), activo0, "undo de C_0 exacto");
    Ok(())
}

/// (3) Repetición idempotente pero con validación completa; conflicto de candidato/compromiso.
#[test]
fn repeticion_exige_validacion_completa_y_es_idempotente_peso() -> Result<(), Error> {
    let (base, secretas) = estado_una_clave(0)?;
    let mut activo = activar(&base, &[0])?;
    let p = activo.parametros_sector;
    let slot = p.m_sec;
    let claves = canoniza(payload_tabla(&activo, slot)?);
    let n: u64 = 1;
    let h_siguiente = hash_tabla(&claves);
    preparar_cola_sin_base(&mut activo, u64::try_from(slot)?);
    let cert = certificado_peso(&secretas, n, &claves, [0x11; 32], h_siguiente, &[0], None)?;
    let (tras, _, r) = aplicar_certificado_peso_con_undo(&activo, &cert, slot);
    r?;
    assert_eq!(tras.finalidad_votos_n, n);

    // Idempotencia: repetir el mismo certificado no muta.
    let (repetido, _, r) = aplicar_certificado_peso_con_undo(&tras, &cert, slot);
    r?;
    assert_eq!(repetido, tras, "la repetición es idempotente");

    // Validación completa: firma adulterada -> rechazo sin mutar (el `0x09` no tiene cuota: T1
    // anota que la parte de cuota no pasa).
    let mut adulterado = cert.clone();
    adulterar_firma(&mut adulterado);
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&tras, &adulterado, slot);
    assert!(r.is_err(), "firma adulterada rechazada: {r:?}");
    assert_eq!(nuevo, tras, "una repetición inválida no muta");

    // Conflicto de candidato (mismo `n` y `h_t`, certificado válido).
    let variante_cand =
        certificado_peso(&secretas, n, &claves, [0x77; 32], h_siguiente, &[0], None)?;
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&tras, &variante_cand, slot);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoConflictivo));
    assert_eq!(nuevo, tras);

    // Conflicto de compromiso (mismo `n` y candidato, `h_t` distinto): una segunda tabla auténtica.
    let mut activo2 = activo.clone();
    let (id, reg) = registro(&activo2.parametros_sector, ed(0), 9);
    activo2.sectores.insert(id, reg);
    let claves2 = canoniza(payload_tabla(&activo2, slot)?);
    let h2 = hash_tabla(&claves2);
    assert_ne!(h2, h_siguiente);
    let variante_h = certificado_peso(&secretas, n, &claves, [0x11; 32], h2, &[0], None)?;
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&tras, &variante_h, slot);
    // TB-1c · T3: una segunda tabla auténtica que el estado no derivó se rechaza por
    // `TablaNoDerivada` (antes, con la tabla adjunta, llegaba a `Conflictivo`).
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada
        ))
    );
    assert_eq!(nuevo, tras);
    Ok(())
}

/// (4) Retroceso y fraude de firma siguen rechazados sin mutar. La parte de VRF del fraude
/// desaparece (el `0x09` no lleva sorteo); se anota.
#[test]
fn retroceso_y_fraude_siguen_rechazados_peso() -> Result<(), Error> {
    let (base, secretas) = estado_una_clave(0)?;
    let mut activo = activar(&base, &[0])?;
    let p = activo.parametros_sector;
    let slot = p.m_sec;
    let claves = canoniza(payload_tabla(&activo, slot)?);
    let h = hash_tabla(&claves);
    preparar_cola_sin_base(&mut activo, u64::try_from(slot)?);

    let c1 = certificado_peso(&secretas, 1, &claves, [0x11; 32], h, &[0], None)?;
    let (tras1, _, r) = aplicar_certificado_peso_con_undo(&activo, &c1, slot);
    r?;
    let c2 = certificado_peso(&secretas, 2, &claves, [0x22; 32], h, &[0], None)?;
    let (tras2, _, r) = aplicar_certificado_peso_con_undo(&tras1, &c2, slot);
    r?;

    // Retroceso: `C_1` sobre un estado con `n = 2`.
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&tras2, &c1, slot);
    println!("P4_RETROCESO -> {r:?}");
    assert_eq!(r, Err(ErrorTransicion::ErrFinalidadRetrocede));
    assert_eq!(nuevo, tras2, "el retroceso no muta");

    // Fraude de firma agregada adulterada -> rechazo sin mutar.
    let mut firma_rota = c1.clone();
    adulterar_firma(&mut firma_rota);
    let (nuevo, _, r) = aplicar_certificado_peso_con_undo(&tras1, &firma_rota, slot);
    assert!(r.is_err(), "la firma adulterada no muta: {r:?}");
    assert_eq!(nuevo, tras1, "la firma adulterada no muta");
    Ok(())
}
