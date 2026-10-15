//! DEUDA-1 · prueba 10 — la tabla de votantes del nodo es la del consenso (AUD-1, regla 3).
//!
//! Compara `construir_tabla` (`crates/zx-node/src/votos.rs`, la del nodo) con `tabla_canonica`
//! (`crates/zx-consensus/src/transicion/votos.rs`, la del consenso) campo a campo:
//! `clave`/`clave_bls`, `peso`, `activo`, `prueba` y `garantia`, mismo número de claves y mismo orden.
//!
//! No es la copia `construir_tabla_referencia` (que compara con una versión vieja).
//!
//! La clave BLS no válida **no puede entrar por el registro real** (lo impide
//! `crates/zx-consensus/src/transicion/sector.rs`, el brazo `OperacionAlmacenamiento::ClaveVoto`:
//! `zx_bls::ClavePublica::desde_bytes(clave_bls)` devuelve `Err` → `MotivoSector::ErrPrueba`).
//! Aquí se prueba esa prevención; el estado con una clave BLS inválida insertada a mano **no** es un
//! estado real y no se usa como caso de la comparación.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "fixtures de integración pequeños con aserciones"
)]

use super::construir_tabla;
use zx_consensus::sectores::{
    ClaveVoto, Etapa, MotivoSector, ParametrosSector, PruebaVigente, RegistroSector, SectorId,
};
use zx_consensus::transicion::sector::aplicar_almacenamiento_con_undo;
use zx_consensus::transicion::votos::{PRIMA_DISPONIBILIDAD_ACTIVA, tabla_canonica};
use zx_consensus::transicion::{Estado, Garantia};
use zx_core::{Amount, ClavePublica as Ed25519, OperacionAlmacenamiento};
use zx_votos::ClaveSecreta;

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(indice: u8) -> Ed25519 {
    Ed25519::desde_bytes([indice; 32])
}

fn sector(id: SectorId, etapa: Etapa, alta_slot: i64, p: &ParametrosSector) -> RegistroSector {
    RegistroSector {
        id,
        r2: [0; 4],
        history_size: 1,
        etapa,
        alta_slot,
        renovacion_slot: 0,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    }
}

/// Inserta una clave con `n_sectores` sectores en la etapa dada.
fn insertar_clave(
    est: &mut Estado,
    e: Ed25519,
    sk: &ClaveSecreta,
    n_sectores: usize,
    etapa: Etapa,
    alta_slot: i64,
) {
    let p = est.parametros_sector;
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: sk.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    for j in 0..n_sectores {
        let id = SectorId {
            clave: e,
            sector_index: u16::try_from(j).expect("sector"),
            version: 0,
        };
        est.sectores.insert(id, sector(id, etapa, alta_slot, &p));
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1_000).expect("garantía");
    est.garantias.insert(e, g);
}

fn base() -> Estado {
    let mut est = Estado::inicial();
    est.parametros_sector = ParametrosSector::dev();
    est
}

/// Compara campo a campo `construir_tabla` y `tabla_canonica`.
/// Devuelve `Some(descripción)` si difieren, `None` si coinciden.
fn comparar(estado: &Estado, slot: i64, etiqueta: &str) -> Option<String> {
    let (tabla, _pubs) = construir_tabla(1, estado, slot)
        .unwrap_or_else(|e| panic!("{etiqueta}: construir_tabla dio error: {e:?}"));
    let canonica = tabla_canonica(estado, slot);
    if tabla.claves.len() != canonica.len() {
        return Some(format!(
            "{etiqueta}: número de claves {} vs {}",
            tabla.claves.len(),
            canonica.len()
        ));
    }
    for (i, (a, b)) in tabla.claves.iter().zip(canonica.iter()).enumerate() {
        if a.clave.as_slice() != b.clave_bls.as_slice() {
            return Some(format!("{etiqueta}: clave[{i}] bytes distintos"));
        }
        if a.peso != b.peso {
            return Some(format!(
                "{etiqueta}: clave[{i}] peso {} vs {}",
                a.peso, b.peso
            ));
        }
        if a.activo != b.activo {
            return Some(format!(
                "{etiqueta}: clave[{i}] activo {} vs {}",
                a.activo, b.activo
            ));
        }
        if a.prueba != b.prueba {
            return Some(format!(
                "{etiqueta}: clave[{i}] prueba {} vs {}",
                a.prueba, b.prueba
            ));
        }
        if a.garantia != b.garantia {
            return Some(format!(
                "{etiqueta}: clave[{i}] garantía {} vs {}",
                a.garantia, b.garantia
            ));
        }
    }
    None
}

#[test]
fn deuda1_10_tabla_del_nodo_es_la_del_consenso() {
    // PRIMA_DISPONIBILIDAD_ACTIVA es false hoy: la marca `prueba` sale false en las dos.
    // No se fuerza.
    const {
        assert!(
            !PRIMA_DISPONIBILIDAD_ACTIVA,
            "DEUDA-1: la prima está inerte hoy; la marca `prueba` sale false en las dos tablas"
        );
    };
    let p = ParametrosSector::dev();

    // (a) clave sin clave BLS de voto: identidad con sectores pero NO en `claves_voto`.
    {
        let mut est = base();
        let e = ed(1);
        for j in 0..2 {
            let id = SectorId {
                clave: e,
                sector_index: j,
                version: 0,
            };
            est.sectores
                .insert(id, sector(id, Etapa::Activo, 0, &est.parametros_sector));
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(10).expect("g");
        est.garantias.insert(e, g);
        assert!(
            comparar(&est, 0, "clave sin clave BLS de voto").is_none(),
            "sin clave BLS registrada, las dos tablas la omiten"
        );
    }

    // (b) clave con peso cero (sin sectores).
    {
        let mut est = base();
        insertar_clave(&mut est, ed(1), &bls(1), 0, Etapa::Activo, 0);
        assert!(
            comparar(&est, 0, "clave con peso cero").is_none(),
            "peso 0: las dos la saltan"
        );
    }

    // (c) clave con peso que madura justo en el slot (Precomprometido → Activo en `alta + m_sec`).
    {
        let mut est = base();
        let e = ed(1);
        let sk = bls(1);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: sk.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let id = SectorId {
            clave: e,
            sector_index: 0,
            version: 0,
        };
        // `alta_slot = 0`, `m_sec = 12` ⇒ madura en el slot 12 exacto.
        est.sectores.insert(
            id,
            sector(id, Etapa::Precomprometido, 0, &est.parametros_sector),
        );
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(10).expect("g");
        est.garantias.insert(e, g);
        let madurez = p.m_sec;
        assert!(
            comparar(&est, madurez - 1, "peso que madura justo (antes)").is_none(),
            "justo antes de madurar, las dos la omiten"
        );
        assert!(
            comparar(&est, madurez, "peso que madura justo (en el slot)").is_none(),
            "en el slot exacto de maduración las dos la incluyen (estado_efectivo: slot >= alta+m_sec)"
        );
    }

    // (d) clave con la marca de prueba y sin ella. Con la prima inerte, `prueba=false` en las dos.
    {
        let mut est = base();
        insertar_clave(&mut est, ed(1), &bls(1), 1, Etapa::Activo, 0);
        est.pruebas.insert(
            ed(1),
            PruebaVigente {
                slot_prueba: 0,
                raiz_conjunto: [0; 4],
                n_sectores: 1,
            },
        );
        assert!(comparar(&est, 0, "clave con marca de prueba").is_none());
        est.pruebas.remove(&ed(1));
        assert!(comparar(&est, 0, "clave sin marca de prueba").is_none());
    }

    // (e) tabla con varias claves en orden distinto de inserción.
    {
        for &(orden_a, orden_b) in &[(1u8, 2u8), (2u8, 1u8)] {
            let mut est = base();
            insertar_clave(&mut est, ed(orden_a), &bls(orden_a), 1, Etapa::Activo, 0);
            insertar_clave(&mut est, ed(orden_b), &bls(orden_b), 2, Etapa::Activo, 0);
            insertar_clave(&mut est, ed(3), &bls(3), 3, Etapa::Activo, 0);
            assert!(
                comparar(
                    &est,
                    0,
                    &format!("varias claves, inserción {orden_a},{orden_b}")
                )
                .is_none(),
                "el orden de inserción no cambia las dos tablas"
            );
        }
    }
}

/// La clave BLS que no es un punto válido **no puede existir en un estado real**: el registro la
/// rechaza. Aquí se prueba esa prevención (la comparación de tablas no necesita ese estado).
#[test]
fn deuda1_10_el_registro_no_deja_una_clave_bls_invalida() {
    let p = ParametrosSector::dev();
    let est = base();
    let e = ed(1);
    let op = OperacionAlmacenamiento::ClaveVoto {
        clave: e,
        // 48 bytes que no son un punto válido de G1 comprimido.
        clave_bls: [9u8; 48],
        prueba_posesion: [0u8; 96],
    };
    let (_nuevo, _undo, motivo) = aplicar_almacenamiento_con_undo(&est, &op, 0, &p);
    assert_eq!(
        motivo,
        MotivoSector::ErrPrueba,
        "el registro de la clave BLS inválida se rechaza en \
         crates/zx-consensus/src/transicion/sector.rs (brazo ClaveVoto: \
         zx_bls::ClavePublica::desde_bytes → Err → MotivoSector::ErrPrueba)"
    );
    // Y el estado no cambia: la clave no llega a `claves_voto`.
    let (_nuevo, _undo, motivo2) = aplicar_almacenamiento_con_undo(&est, &op, 0, &p);
    assert_eq!(motivo2, MotivoSector::ErrPrueba);
    assert!(
        est.claves_voto.is_empty(),
        "la clave inválida no se registra"
    );
    // `construir_tabla` y `tabla_canonica` sobre ese estado (sin la clave inválida) coinciden.
    assert!(comparar(&est, 0, "estado sin la clave inválida").is_none());
}
