//! RET-1b E6/Q7 · el camino **real** del sector (`materializar_sectores`) no libera a `retiro + 96`
//! ni a `retiro + 1 023`; sí a `retiro + R_V = 1 024` (perfil dev). Antes de RET-1b el camino real
//! liberaba a `retiro + R_sec = 96` (el oráculo ya tenía la puerta desde RET-1a).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test de escenario; falla con panic por diseño"
)]

use zx_consensus::sectores::{Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{Estado, Garantia, materializar_con_undo};
use zx_core::{Amount, ClavePublica};

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

#[test]
fn q7_sector_real_retiene_hasta_rv() {
    let p = ParametrosSector::dev();
    assert_eq!(p.r_votos_slots, 1_024, "R_V del perfil dev");
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let e = ed(1);
    let s: i64 = 7;
    let id = SectorId {
        clave: e,
        sector_index: 0,
        version: 0,
    };
    est.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0; 4],
            history_size: 1,
            etapa: Etapa::EnRetirada,
            alta_slot: 0,
            renovacion_slot: 0,
            retiro_slot: s,
            fianza: p.q_sec,
            aud_apertura: -1,
            aud_contestada: -1,
        },
    );
    let mut g = Garantia::nueva();
    g.activo = Amount::CERO;
    est.garantias.insert(e, g);

    // No se libera en `s + 96` (la regla antigua) ni en `s + 1 023`.
    let (no_96, _u96) = materializar_con_undo(&est, s + 96, &p);
    assert_eq!(
        no_96.sectores[&id].etapa,
        Etapa::EnRetirada,
        "s + 96 no libera con R_V vigente"
    );
    let (no_1023, _u1023) = materializar_con_undo(&est, s + 1_023, &p);
    assert_eq!(
        no_1023.sectores[&id].etapa,
        Etapa::EnRetirada,
        "s + 1 023 no libera"
    );

    // Sí se libera en `s + R_V = s + 1 024`.
    let (libre, _ul) = materializar_con_undo(&est, s + p.r_votos_slots, &p);
    assert_eq!(libre.sectores[&id].etapa, Etapa::Retirado);
    assert_eq!(libre.sectores[&id].fianza, 0);
    assert_eq!(libre.garantias[&e].activo.brek(), p.q_sec);
}
