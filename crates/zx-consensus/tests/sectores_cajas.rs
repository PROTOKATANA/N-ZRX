//! `SR-G2b` · V2/V3 de las cajas de sectores (`C-CAJA-*`) sobre la transición real.
//!
//! Reproduce los 15 vectores de `SRG2a/vectores/cajas.jsonl` **con la regla de madurez** del
//! orquestador (`slot ≥ ultima_alta_slot + M_sec`) y añade el vector nuevo `K-16` («añadir antes de
//! que madure el anterior»). Ejerce `aplicar_operacion_con_undo`, `materializar_con_undo` y
//! `deshacer`; comprueba las invariantes `I-CAJA-1…5` y el undo bit a bit en 200 reorganizaciones.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test de escenarios con estados construidos a mano y aserciones por diseño"
)]

use zx_consensus::cajas::{
    CajaId, EtapaCaja, hoja_libre, hoja_ocupada, raiz_merkle, ruta_merkle, verificar_prueba,
};
use zx_consensus::sectores::{EstadoEfectivo, MotivoSector, ParametrosSector, clave_de};
use zx_consensus::transicion::caja::{
    capacidad, estado_hueco, invariante_caja, raiz_de_caja, todos_en_caja,
};
use zx_consensus::transicion::{
    Estado, Garantia, Incidente, aplicar_operacion_con_undo, deshacer, materializar_con_undo,
};
use zx_core::{Amount, OperacionSector};

const CLAVE: u8 = 1;

fn params16() -> ParametrosSector {
    let mut p = ParametrosSector::fixture();
    p.capacidad_caja = 16;
    p
}

fn clave() -> zx_core::ClavePublica {
    clave_de(CLAVE)
}

fn r2(x: u8) -> [u8; 32] {
    [x; 32]
}

fn estado_fund(activo: i64, p: &ParametrosSector) -> Estado {
    let mut e = Estado::inicial();
    e.parametros_sector = *p;
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(activo).unwrap();
    e.garantias.insert(clave(), g);
    e
}

fn alta(
    e: &Estado,
    si: u16,
    v: u32,
    hs: u64,
    slot: i64,
    p: &ParametrosSector,
) -> (Estado, MotivoSector) {
    let op = OperacionSector::Alta {
        clave: clave(),
        sector_index: si,
        version: v,
        r2: r2(u8::try_from(si).unwrap_or(0) + 0x10),
        history_size: hs,
    };
    let (e2, r) = aplicar_operacion_con_undo(e, &op, slot, p);
    (e2, r.motivo)
}

/// Añade `n` altas espaciadas `M_sec` (cumplen la regla de madurez).
fn altas(
    e: &Estado,
    n: u16,
    hs: u64,
    inicio: i64,
    p: &ParametrosSector,
) -> (Estado, Vec<MotivoSector>) {
    let mut e = e.clone();
    let mut motivos = Vec::new();
    for i in 0..n {
        let slot = inicio + i64::from(i) * p.m_sec;
        let (e2, m) = alta(&e, i, 0, hs, slot, p);
        e = e2;
        motivos.push(m);
    }
    (e, motivos)
}

fn cerrar(e: &Estado, seq: u32, slot: i64, p: &ParametrosSector) -> (Estado, MotivoSector) {
    let op = OperacionSector::CerrarCaja {
        clave: clave(),
        seq,
    };
    let (e2, r) = aplicar_operacion_con_undo(e, &op, slot, p);
    (e2, r.motivo)
}

fn retirar_caja(e: &Estado, seq: u32, slot: i64, p: &ParametrosSector) -> (Estado, MotivoSector) {
    let op = OperacionSector::RetirarCaja {
        clave: clave(),
        seq,
    };
    let (e2, r) = aplicar_operacion_con_undo(e, &op, slot, p);
    (e2, r.motivo)
}

fn retirar_sector(e: &Estado, si: u16, slot: i64, p: &ParametrosSector) -> (Estado, MotivoSector) {
    let op = OperacionSector::Retirar {
        clave: clave(),
        sector_index: si,
    };
    let (e2, r) = aplicar_operacion_con_undo(e, &op, slot, p);
    (e2, r.motivo)
}

fn abrir_aud(e: &Estado, si: u16, slot: i64, p: &ParametrosSector) -> (Estado, MotivoSector) {
    let op = OperacionSector::AbrirAuditoria {
        clave: clave(),
        sector_index: si,
        auditoria_id: 7,
    };
    let (e2, r) = aplicar_operacion_con_undo(e, &op, slot, p);
    (e2, r.motivo)
}

fn contestar(e: &Estado, si: u16, slot: i64, p: &ParametrosSector) -> (Estado, MotivoSector) {
    let op = OperacionSector::ContestarAuditoria {
        clave: clave(),
        sector_index: si,
        auditoria_id: 7,
        prueba: vec![1, 2, 3],
    };
    let (e2, r) = aplicar_operacion_con_undo(e, &op, slot, p);
    (e2, r.motivo)
}

fn mat(e: &Estado, slot: i64, p: &ParametrosSector) -> Estado {
    let (e2, _) = materializar_con_undo(e, slot, p);
    e2
}

fn caja(e: &Estado, seq: u32) -> zx_consensus::cajas::RegistroCaja {
    e.cajas[&CajaId {
        clave: clave(),
        seq,
    }]
        .clone()
}

// ── K-01 · caja llena ───────────────────────────────────────────────────────

#[test]
fn k01_caja_llena() {
    let p = params16();
    assert_eq!(capacidad(&p), 16);
    let e = estado_fund(1000, &p);
    let (e, ms) = altas(&e, 16, 1, 1, &p);
    assert!(ms.iter().all(|m| *m == MotivoSector::Ok), "{ms:?}");
    let c = caja(&e, 1);
    assert_eq!(c.n, 16);
    assert_eq!(c.etapa, EtapaCaja::Cerrada);
    assert_eq!(c.raiz, raiz_de_caja(&e, &c));
    assert!(invariante_caja(&e, &p));
    assert!(todos_en_caja(&e));
}

// ── K-16 (nuevo) · añadir antes de que madure el anterior ───────────────────

#[test]
fn k16_anadir_antes_de_madurar() {
    let p = params16();
    let e = estado_fund(1000, &p);
    let (e, m0) = alta(&e, 0, 0, 1, 1, &p);
    assert_eq!(m0, MotivoSector::Ok);
    let (e, m1) = alta(&e, 1, 0, 1, 1 + p.m_sec - 1, &p);
    assert_eq!(m1, MotivoSector::ErrMaduracion);
    let c = caja(&e, 1);
    assert_eq!(c.n, 1);
    assert_eq!(c.etapa, EtapaCaja::Abierta);
    assert!(invariante_caja(&e, &p));
    // En el slot exacto de maduración sí entra.
    let (e, m2) = alta(&e, 1, 0, 1, 1 + p.m_sec, &p);
    assert_eq!(m2, MotivoSector::Ok);
    assert_eq!(caja(&e, 1).n, 2);
}

// ── K-02 · una sola caja abierta ────────────────────────────────────────────

#[test]
fn k02_dos_cajas_una_abierta() {
    let p = params16();
    let e = estado_fund(1000, &p);
    let (e, _) = altas(&e, 16, 1, 1, &p);
    let (e, m) = alta(&e, 16, 0, 1, 1 + 16 * p.m_sec, &p);
    assert_eq!(m, MotivoSector::Ok);
    let c1 = caja(&e, 1);
    let c2 = caja(&e, 2);
    assert_eq!(c1.etapa, EtapaCaja::Cerrada);
    assert_eq!(c2.etapa, EtapaCaja::Abierta);
    assert_eq!(c2.n, 1);
    assert!(invariante_caja(&e, &p));
}

// ── K-03 · history_size distinto ────────────────────────────────────────────

#[test]
fn k03_history_distinta() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, m0) = alta(&e, 0, 0, 1, 1, &p);
    assert_eq!(m0, MotivoSector::Ok);
    let (e, m1) = alta(&e, 1, 0, 2, 1 + p.m_sec, &p);
    assert_eq!(m1, MotivoSector::ErrHistory);
    assert_eq!(caja(&e, 1).n, 1);
}

// ── K-04 · cierre explícito + caja nueva ────────────────────────────────────

#[test]
fn k04_cierre_incompleto() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, _) = altas(&e, 3, 1, 1, &p);
    let t = 1 + 3 * p.m_sec;
    let (e, mc) = cerrar(&e, 1, t, &p);
    assert_eq!(mc, MotivoSector::Ok);
    assert_eq!(caja(&e, 1).etapa, EtapaCaja::Cerrada);
    assert_eq!(caja(&e, 1).n, 3);
    let (e, ma) = alta(&e, 3, 0, 1, t + p.m_sec, &p);
    assert_eq!(ma, MotivoSector::Ok);
    assert_eq!(caja(&e, 2).n, 1);
    assert!(invariante_caja(&e, &p));
}

// ── K-05 · retirada antes de R_sec ──────────────────────────────────────────

#[test]
fn k05_retirar_antes_r_sec() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, _) = altas(&e, 2, 1, 1, &p);
    let t = 1 + 2 * p.m_sec;
    let (e, mc) = cerrar(&e, 1, t, &p);
    assert_eq!(mc, MotivoSector::Ok);
    let (e, mr) = retirar_caja(&e, 1, t, &p);
    assert_eq!(mr, MotivoSector::Ok);
    assert_eq!(caja(&e, 1).etapa, EtapaCaja::EnRetirada);
    let e = mat(&e, t + 1, &p);
    assert_eq!(caja(&e, 1).etapa, EtapaCaja::EnRetirada);
    assert!(invariante_caja(&e, &p));
}

// ── K-06 · retirada correcta ────────────────────────────────────────────────

#[test]
fn k06_retirar_ok() {
    let p = params16();
    let e = estado_fund(1000, &p);
    let (e, _) = altas(&e, 2, 1, 1, &p);
    let t = 1 + 2 * p.m_sec;
    let (e, _) = cerrar(&e, 1, t, &p);
    let (e, _) = retirar_caja(&e, 1, t, &p);
    let e = mat(&e, t + p.r_sec + 10, &p);
    assert_eq!(caja(&e, 1).etapa, EtapaCaja::Retirada);
    assert!(invariante_caja(&e, &p));
    // La fianza se ha devuelto a la garantía.
    let activo = e.garantias[&clave()].activo.brek();
    assert!(activo >= 1000, "activo={activo}");
}

// ── K-07 · incidente abierto bloquea EV-24(i) ───────────────────────────────

#[test]
fn k07_incidente_bloquea() {
    let p = params16();
    let e = estado_fund(1000, &p);
    let (e, _) = altas(&e, 2, 1, 1, &p);
    let t = 1 + 2 * p.m_sec;
    let (e, _) = cerrar(&e, 1, t, &p);
    let (mut e, _) = retirar_caja(&e, 1, t, &p);
    e.garantias
        .get_mut(&clave())
        .unwrap()
        .incidentes
        .push(Incidente {
            id: [0u8; 32],
            slot_falta: 0,
        });
    let e = mat(&e, t + p.r_sec + 10, &p);
    assert_eq!(caja(&e, 1).etapa, EtapaCaja::EnRetirada);
}

// ── K-08 · reorg que deshace un añadido (undo bit a bit) ────────────────────

#[test]
fn k08_reorg_undo_exacto() {
    let p = params16();
    let e0 = estado_fund(100, &p);
    let (e1, _) = alta(&e0, 0, 0, 1, 1, &p);
    // Rama A: segundo añadido.
    let (e_a, r_a) = aplicar_operacion_con_undo(
        &e1,
        &OperacionSector::Alta {
            clave: clave(),
            sector_index: 1,
            version: 0,
            r2: r2(0x21),
            history_size: 1,
        },
        1 + p.m_sec,
        &p,
    );
    assert_eq!(r_a.motivo, MotivoSector::Ok);
    assert_eq!(caja(&e_a, 1).n, 2);
    // Undo bit a bit.
    let vuelta = deshacer(&e_a, &r_a.undo);
    assert_eq!(
        vuelta, e1,
        "el undo no restituye el estado previo bit a bit"
    );
    assert_eq!(caja(&vuelta, 1).n, 1);
    // Rama B: añadido distinto en el mismo slot.
    let (e_b, r_b) = aplicar_operacion_con_undo(
        &e1,
        &OperacionSector::Alta {
            clave: clave(),
            sector_index: 2,
            version: 0,
            r2: r2(0x22),
            history_size: 1,
        },
        1 + p.m_sec,
        &p,
    );
    assert_eq!(r_b.motivo, MotivoSector::Ok);
    assert_eq!(caja(&e_b, 1).n, 2);
    assert_ne!(caja(&e_a, 1).raiz, caja(&e_b, 1).raiz);
    assert!(invariante_caja(&e_a, &p) && invariante_caja(&e_b, &p));
}

// ── K-09 · alta duplicada ───────────────────────────────────────────────────

#[test]
fn k09_duplicado() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, m0) = alta(&e, 0, 0, 1, 1, &p);
    assert_eq!(m0, MotivoSector::Ok);
    let (e, m1) = alta(&e, 0, 0, 1, 1 + p.m_sec, &p);
    assert_eq!(m1, MotivoSector::ErrDobleAlta);
    assert_eq!(caja(&e, 1).n, 1);
}

// ── K-10 · retirada de hueco suelto ─────────────────────────────────────────

#[test]
fn k10_retirar_hueco_suelto() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, _) = altas(&e, 2, 1, 1, &p);
    let (_, m) = retirar_sector(&e, 0, 1 + p.m_sec, &p);
    assert_eq!(m, MotivoSector::ErrEstado);
}

// ── K-11 · retirar caja abierta ─────────────────────────────────────────────

#[test]
fn k11_retirar_sin_cerrar() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, _) = altas(&e, 2, 1, 1, &p);
    let (_, m) = retirar_caja(&e, 1, 1 + p.m_sec, &p);
    assert_eq!(m, MotivoSector::ErrEstado);
}

// ── K-12 · cerrar sin caja ──────────────────────────────────────────────────

#[test]
fn k12_cerrar_sin_caja() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (_, m) = cerrar(&e, 1, 1, &p);
    assert_eq!(m, MotivoSector::ErrNoExiste);
}

// ── K-13 · ruta Merkle de las 16 hojas ──────────────────────────────────────

#[test]
fn k13_ruta_merkle() {
    let p = params16();
    let e = estado_fund(1000, &p);
    let (e, _) = altas(&e, 16, 1, 1, &p);
    let c = caja(&e, 1);
    let hojas: Vec<[u64; 4]> = (1..=16)
        .map(|j| {
            e.sectores
                .values()
                .find(|r| r.id.sector_index == (j - 1))
                .map_or(hoja_libre(), |r| hoja_ocupada(r.r2))
        })
        .collect();
    assert_eq!(raiz_merkle(&hojas), c.raiz);
    for j in 1..=16usize {
        assert!(verificar_prueba(
            c.raiz,
            j,
            hojas[j - 1],
            &ruta_merkle(&hojas, j)
        ));
    }
    let mut malas = hojas.clone();
    malas[0] = hoja_ocupada([0xEE; 4]);
    assert!(!verificar_prueba(
        c.raiz,
        1,
        malas[0],
        &ruta_merkle(&hojas, 1)
    ));
}

// ── K-14 · suspensión y recuperación por hueco ──────────────────────────────

#[test]
fn k14_suspension_recuperacion() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, _) = altas(&e, 2, 1, 1, &p);
    let t = 1 + 2 * p.m_sec;
    let (e, _) = cerrar(&e, 1, t, &p);
    let (e, m) = abrir_aud(&e, 0, t, &p);
    assert_eq!(m, MotivoSector::Ok);
    let e = mat(&e, t + p.p_aud, &p);
    let c = caja(&e, 1);
    assert_eq!(
        estado_hueco(&e, &c, 1, t + p.p_aud, &p),
        Some(EstadoEfectivo::Suspendido)
    );
    assert_eq!(
        estado_hueco(&e, &c, 2, t + p.p_aud, &p),
        Some(EstadoEfectivo::Activo)
    );
    let (e, m) = contestar(&e, 0, t + p.p_aud + p.p_rec - 1, &p);
    assert_eq!(m, MotivoSector::Ok);
    let e = mat(&e, t + p.p_aud + p.p_rec - 1, &p);
    let c = caja(&e, 1);
    assert_eq!(
        estado_hueco(&e, &c, 1, t + p.p_aud + p.p_rec - 1, &p),
        Some(EstadoEfectivo::Activo)
    );
    assert!(invariante_caja(&e, &p));
}

// ── K-15 · suspensión sin recuperar ─────────────────────────────────────────

#[test]
fn k15_suspension_sin_recuperar() {
    let p = params16();
    let e = estado_fund(100, &p);
    let (e, _) = altas(&e, 2, 1, 1, &p);
    let t = 1 + 2 * p.m_sec;
    let (e, _) = cerrar(&e, 1, t, &p);
    let (e, _) = abrir_aud(&e, 0, t, &p);
    let fin = t + p.p_aud + p.p_rec + 1;
    let e = mat(&e, fin, &p);
    let c = caja(&e, 1);
    assert_eq!(
        estado_hueco(&e, &c, 1, fin, &p),
        Some(EstadoEfectivo::Suspendido)
    );
    assert_eq!(
        estado_hueco(&e, &c, 2, fin, &p),
        Some(EstadoEfectivo::Activo)
    );
    assert_eq!(c.etapa, EtapaCaja::Cerrada);
    assert!(invariante_caja(&e, &p));
}

// ── V3 · 200 reorganizaciones con cajas y undo bit a bit ────────────────────

#[test]
fn v3_200_reorgs_con_cajas() {
    let p = params16();
    let mut rng = 0x5a5a_5a5a_5a5a_5a5au64;
    let mut siguientes = || {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        rng >> 33
    };
    let mut exitos = 0usize;
    for _ in 0..200 {
        let base = estado_fund(1000, &p);
        // Prefijo: hasta 3 altas espaciadas.
        let n = 1 + (siguientes() % 3) as u16;
        let (comun, ms) = altas(&base, n, 1, 1, &p);
        assert!(ms.iter().all(|m| *m == MotivoSector::Ok));
        // Rama con un añadido más (si cabe).
        if n < 16 {
            let slot = 1 + i64::from(n) * p.m_sec;
            let si = n;
            let (rama, r) = aplicar_operacion_con_undo(
                &comun,
                &OperacionSector::Alta {
                    clave: clave(),
                    sector_index: si,
                    version: 0,
                    r2: r2(u8::try_from(siguientes() & 0xff).unwrap_or(1)),
                    history_size: 1,
                },
                slot,
                &p,
            );
            assert_eq!(r.motivo, MotivoSector::Ok);
            assert_eq!(u16::from(caja(&rama, 1).n), n + 1);
            assert!(invariante_caja(&rama, &p));
            // Undo bit a bit.
            let vuelta = deshacer(&rama, &r.undo);
            assert_eq!(vuelta, comun, "reorg {exitos}: undo no exacto");
            assert_eq!(u16::from(caja(&vuelta, 1).n), n);
        }
        exitos += 1;
    }
    assert_eq!(exitos, 200);
}
