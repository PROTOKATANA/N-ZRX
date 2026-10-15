//! PT-3bc · pruebas de almacenamiento en la transición real.
//!
//! Cubre: (a) activación en dos fases con PoRep, (b) puerta de peso de la PoSt vigente y (e) undo
//! exacto de los deltas de prueba/atestación/clave de voto.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]

use zx_consensus::cajas::r2_a_bytes;
use zx_consensus::sectores::{Etapa, MotivoSector, ParametrosSector, SectorId, clave_de};
use zx_consensus::transicion::{
    Estado, Garantia, aplicar_almacenamiento_con_undo, aplicar_operacion_con_undo, deshacer,
    elegible_sector, fuente_peso_de, materializar_con_undo, prueba_vigente, raiz_conjunto_de,
    raiz_lote_de, sectores_activos_de,
};
use zx_core::{Amount, OperacionAlmacenamiento, OperacionSector};

const CLAVE: u8 = 1;
const HS: u64 = 1 << 20;

fn params() -> ParametrosSector {
    let mut p = ParametrosSector::fixture();
    p.capacidad_caja = 1;
    p.exigir_prueba_almacenamiento = true;
    p.t_prueba = 100;
    p.t_gracia = 50;
    p.f_slots = 0;
    p
}

fn estado_fund(activo: i64, p: &ParametrosSector) -> Estado {
    let mut e = Estado::inicial();
    e.parametros_sector = *p;
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(activo).unwrap();
    e.garantias.insert(clave_de(CLAVE), g);
    e
}

fn alta_ok(e: &Estado, si: u16, slot: i64, p: &ParametrosSector) -> Estado {
    let op = OperacionSector::Alta {
        clave: clave_de(CLAVE),
        sector_index: si,
        version: 0,
        r2: [u8::try_from(si).unwrap_or(0) + 0x10; 32],
        history_size: HS,
    };
    let (e2, r) = aplicar_operacion_con_undo(e, &op, slot, p);
    assert_eq!(r.motivo, MotivoSector::Ok, "el alta debe aceptarse");
    e2
}

fn porep_de(e: &Estado, epoch: i64) -> OperacionAlmacenamiento {
    let clave = clave_de(CLAVE);
    let raiz = raiz_lote_de(e, &clave);
    let n = e
        .sectores
        .iter()
        .filter(|(id, r)| id.clave == clave && !r.es_terminal())
        .count();
    OperacionAlmacenamiento::PoRep {
        clave,
        epoch: u64::try_from(epoch).unwrap_or(0),
        n_sectores: u32::try_from(n).unwrap_or(0),
        raiz_conjunto: r2_a_bytes(raiz),
        prueba: vec![1, 2],
    }
}

fn post_de(e: &Estado, epoch: i64, p: &ParametrosSector) -> OperacionAlmacenamiento {
    let clave = clave_de(CLAVE);
    let raiz = raiz_conjunto_de(e, &clave, epoch, p);
    let n = sectores_activos_de(e, &clave, epoch, p);
    OperacionAlmacenamiento::PoSt {
        clave,
        epoch: u64::try_from(epoch).unwrap_or(0),
        n_sectores: u32::try_from(n).unwrap_or(0),
        raiz_conjunto: r2_a_bytes(raiz),
        prueba: vec![1, 2],
    }
}

/// Deja un sector `Activo` (alta + PoRep que cubre el lote + maduración).
fn sector_activo(e: &Estado, p: &ParametrosSector) -> Estado {
    let e = alta_ok(e, 0, 0, p);
    let epoch = p.m_sec;
    let op = porep_de(&e, epoch);
    let (e2, _u, m) = aplicar_almacenamiento_con_undo(&e, &op, epoch, p);
    assert_eq!(m, MotivoSector::Ok, "la PoRep debe aceptarse");
    let (e3, _) = materializar_con_undo(&e2, epoch, p);
    e3
}

#[test]
fn a_un_precomprometido_no_activa_sin_porep() {
    let p = params();
    let e = alta_ok(&estado_fund(10_000, &p), 0, 0, &p);
    let id = SectorId {
        clave: clave_de(CLAVE),
        sector_index: 0,
        version: 0,
    };

    // Madura `M_sec` sin PoRep: sigue `Precomprometido` y no es elegible.
    let (e2, _) = materializar_con_undo(&e, p.m_sec, &p);
    assert_eq!(
        e2.sectores.get(&id).copied().unwrap().etapa,
        Etapa::Precomprometido
    );
    assert!(!elegible_sector(&e2, &clave_de(CLAVE), 0, HS, p.m_sec, &p));

    // Con la atestación PoRep que cubre el lote, activa.
    let op = porep_de(&e2, p.m_sec);
    let (e3, _u, m) = aplicar_almacenamiento_con_undo(&e2, &op, p.m_sec, &p);
    assert_eq!(m, MotivoSector::Ok);
    let (e4, _) = materializar_con_undo(&e3, p.m_sec, &p);
    assert_eq!(e4.sectores.get(&id).copied().unwrap().etapa, Etapa::Activo);
    // La activación por PoRep no da elegibilidad por sí sola: falta la PoSt vigente (test b).
    assert!(!elegible_sector(&e4, &clave_de(CLAVE), 0, HS, p.m_sec, &p));
}

#[test]
fn b_sin_post_vigente_pesa_cero_y_no_es_elegible() {
    let p = params();
    let e = sector_activo(&estado_fund(10_000, &p), &p);

    // Activo, pero sin PoSt: pesa 0 y no es elegible.
    assert_eq!(fuente_peso_de(&e, &clave_de(CLAVE), p.m_sec, &p), 0);
    assert!(!elegible_sector(&e, &clave_de(CLAVE), 0, HS, p.m_sec, &p));

    // Llega la PoSt vigente.
    let op = post_de(&e, p.m_sec, &p);
    let (e2, _u, m) = aplicar_almacenamiento_con_undo(&e, &op, p.m_sec, &p);
    assert_eq!(m, MotivoSector::Ok);
    assert!(prueba_vigente(&e2, &clave_de(CLAVE), p.m_sec, &p));
    assert_eq!(fuente_peso_de(&e2, &clave_de(CLAVE), p.m_sec, &p), 1);
    assert!(elegible_sector(&e2, &clave_de(CLAVE), 0, HS, p.m_sec, &p));

    // Pasado `T_gracia`, la prueba deja de pesar y de ser elegible.
    let tarde = p.m_sec + p.t_gracia + 1;
    assert!(!prueba_vigente(&e2, &clave_de(CLAVE), tarde, &p));
    assert_eq!(fuente_peso_de(&e2, &clave_de(CLAVE), tarde, &p), 0);
    assert!(!elegible_sector(&e2, &clave_de(CLAVE), 0, HS, tarde, &p));
}

#[test]
fn e_el_undo_de_prueba_y_clave_de_voto_es_exacto() {
    let p = params();
    let e = sector_activo(&estado_fund(10_000, &p), &p);

    // La PoSt aplicada se deshace bit a bit.
    let op = post_de(&e, p.m_sec, &p);
    let (e2, u, m) = aplicar_almacenamiento_con_undo(&e, &op, p.m_sec, &p);
    assert_eq!(m, MotivoSector::Ok);
    assert_eq!(deshacer(&e2, &u), e);

    // Una PoP de ceros se rechaza y el undo restituye el estado.
    let cv = OperacionAlmacenamiento::ClaveVoto {
        clave: clave_de(CLAVE),
        clave_bls: [0u8; 48],
        prueba_posesion: [0u8; 96],
    };
    let (e3, u3, m3) = aplicar_almacenamiento_con_undo(&e, &cv, p.m_sec, &p);
    assert_eq!(m3, MotivoSector::ErrPrueba);
    assert_eq!(deshacer(&e3, &u3), e);
}

#[test]
fn la_clave_de_voto_con_pop_valida_se_registra_y_se_deshace() {
    let p = params();
    let e = estado_fund(100, &p);
    let sk = zx_bls::ClaveSecreta::generar(&[7u8; 32]).unwrap();
    let pk = sk.clave_publica();
    let pop = zx_bls::probar_posesion(&sk);
    let op = OperacionAlmacenamiento::ClaveVoto {
        clave: clave_de(CLAVE),
        clave_bls: pk.bytes(),
        prueba_posesion: pop.bytes(),
    };
    let (e2, u, m) = aplicar_almacenamiento_con_undo(&e, &op, 1, &p);
    assert_eq!(m, MotivoSector::Ok);
    assert!(e2.claves_voto.contains_key(&clave_de(CLAVE)));
    assert_eq!(deshacer(&e2, &u), e);
}

/// FV-4b-N4 · R-ECL-06: la misma clave BLS no puede registrarse bajo **otra** identidad Ed25519.
#[test]
fn recl06_bls_duplicada_bajo_otra_identidad_se_rechaza() {
    let p = params();
    let e = estado_fund(100, &p);
    let sk = zx_bls::ClaveSecreta::generar(&[7u8; 32]).unwrap();
    let pk = sk.clave_publica();
    let pop = zx_bls::probar_posesion(&sk);
    let op1 = OperacionAlmacenamiento::ClaveVoto {
        clave: clave_de(1),
        clave_bls: pk.bytes(),
        prueba_posesion: pop.bytes(),
    };
    let (e2, _u, m) = aplicar_almacenamiento_con_undo(&e, &op1, 1, &p);
    assert_eq!(m, MotivoSector::Ok);

    // La misma BLS bajo otra identidad: rechazo y estado intacto.
    let op2 = OperacionAlmacenamiento::ClaveVoto {
        clave: clave_de(2),
        clave_bls: pk.bytes(),
        prueba_posesion: pop.bytes(),
    };
    let (e3, u3, m2) = aplicar_almacenamiento_con_undo(&e2, &op2, 1, &p);
    assert_eq!(m2, MotivoSector::ErrClaveVotoDuplicada);
    assert_eq!(
        e3.claves_voto, e2.claves_voto,
        "el rechazo no registra nada"
    );
    assert_eq!(deshacer(&e3, &u3), e2);
}

/// FV-4b-N4 · R-ECL-06 **ampliado por RK-2 · V4**: tras rotar, la clave antigua **sigue atribuida**
/// a su identidad durante la retención (no queda libre hasta el vencimiento). Pasado el vencimiento,
/// otra identidad puede registrarla. La nueva sigue protegida contra duplicación bajo otra identidad.
#[test]
fn recl06_la_rotacion_libera_la_bls_vieja_y_rechaza_la_tabla_vieja() {
    let p = params();
    let e = estado_fund(100, &p);
    let k1 = zx_bls::ClaveSecreta::generar(&[1u8; 32]).unwrap();
    let k2 = zx_bls::ClaveSecreta::generar(&[2u8; 32]).unwrap();
    let k3 = zx_bls::ClaveSecreta::generar(&[3u8; 32]).unwrap();
    let op = |clave: zx_core::ClavePublica, sk: &zx_bls::ClaveSecreta| {
        OperacionAlmacenamiento::ClaveVoto {
            clave,
            clave_bls: sk.clave_publica().bytes(),
            prueba_posesion: zx_bls::probar_posesion(sk).bytes(),
        }
    };

    let (e1, _u1, m1) = aplicar_almacenamiento_con_undo(&e, &op(clave_de(1), &k1), 1, &p);
    assert_eq!(m1, MotivoSector::Ok);
    // Rotación de la misma identidad: `k2` sustituye a `k1`.
    let (e2, _u2, m2) = aplicar_almacenamiento_con_undo(&e1, &op(clave_de(1), &k2), 1, &p);
    assert_eq!(m2, MotivoSector::Ok);
    assert_eq!(
        e2.claves_voto
            .get(&clave_de(1))
            .copied()
            .map(|cv| cv.clave_bls),
        Some(k2.clave_publica().bytes())
    );
    assert!(
        e2.claves_voto_previas.contains_key(&clave_de(1)),
        "la clave anterior queda guardada"
    );

    // RK-2 · V3: no se admite una segunda rotación mientras la anterior esté viva.
    let (_e3, _u3, m3) = aplicar_almacenamiento_con_undo(&e2, &op(clave_de(1), &k3), 1, &p);
    assert_eq!(m3, MotivoSector::ErrClaveVotoRotacionViva);

    // RK-2 · V4: `k1` es la anterior viva de la identidad 1; otra identidad no puede registrarla
    // dentro de la retención. El vencimiento es `slot de rotación + retención`.
    let venc = e2
        .claves_voto_previas
        .get(&clave_de(1))
        .map(|prev| prev.vencimiento)
        .unwrap_or(0);
    assert_eq!(
        venc,
        1 + zx_consensus::transicion::votos::retencion_clave_voto(&p),
        "vencimiento = slot de rotación + retención"
    );
    let dentro = i64::try_from(venc).unwrap_or(i64::MAX);
    let (_e4, _u4, m4) = aplicar_almacenamiento_con_undo(&e2, &op(clave_de(2), &k1), dentro, &p);
    assert_eq!(m4, MotivoSector::ErrClaveVotoDuplicada);

    // Pasado el vencimiento (`slot > 1 + retención`), `k1` queda libre para otra identidad.
    let (e5, _u5, m5) = aplicar_almacenamiento_con_undo(&e2, &op(clave_de(2), &k1), dentro + 1, &p);
    assert_eq!(m5, MotivoSector::Ok);
    // Y la nueva sigue protegida contra duplicación bajo otra identidad.
    let (_e6, _u6, m6) =
        aplicar_almacenamiento_con_undo(&e5, &op(clave_de(3), &k2), dentro + 1, &p);
    assert_eq!(m6, MotivoSector::ErrClaveVotoDuplicada);
}
