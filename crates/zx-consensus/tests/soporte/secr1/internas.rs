#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_arguments,
    reason = "referencias literales y pruebas deterministas SEC-R1"
)]
mod caja_base;
mod estado_base;
use crate::sectores::secr1_legacy::fixture;
mod sector_base;
use crate::sectores::SectorId;
use crate::transicion::caja;
use crate::transicion::estado::{Aplicador, debitar_castigable, fianza_no_terminal};

#[test]
fn secr1_equivalencia_real_diez_mil_estados() {
    for caso in 0..10_000 {
        let est = fixture::estado_generado(caso);
        let clave = fixture::clave(2);
        let p = est.parametros_sector;
        let slot = (caso % 151) as i64;
        for indice in [0, 1, u16::MAX] {
            assert_eq!(
                super::sector_vivo(&est, &clave, indice),
                sector_base::sector_vivo(&est, &clave, indice),
                "vivo caso={caso}"
            );
            for version in [0, 1, u32::MAX] {
                let sid = SectorId {
                    clave,
                    sector_index: indice,
                    version,
                };
                assert_eq!(
                    caja::caja_de_sector(&est, &sid),
                    caja_base::caja_de_sector(&est, &sid),
                    "caja sector caso={caso}"
                );
            }
        }
        assert_eq!(
            super::sectores_activos_de(&est, &clave, slot, &p),
            sector_base::sectores_activos_de(&est, &clave, slot, &p),
            "activos caso={caso}"
        );
        assert_eq!(
            super::fuente_peso_de(&est, &clave, slot, &p),
            sector_base::fuente_peso_de(&est, &clave, slot, &p),
            "peso caso={caso}"
        );
        assert_eq!(
            super::raiz_de_cajas(&est, &clave, |_| true),
            sector_base::raiz_de_cajas(&est, &clave, |_| true),
            "raiz cajas caso={caso}"
        );
        assert_eq!(
            super::raiz_lote_de(&est, &clave),
            sector_base::raiz_lote_de(&est, &clave),
            "lote caso={caso}"
        );
        assert_eq!(
            super::raiz_conjunto_de(&est, &clave, slot, &p),
            sector_base::raiz_conjunto_de(&est, &clave, slot, &p),
            "conjunto caso={caso}"
        );
        assert_eq!(
            caja::caja_abierta(&est, &clave),
            caja_base::caja_abierta(&est, &clave),
            "abierta caso={caso}"
        );
        assert_eq!(
            caja::siguiente_seq(&est, &clave),
            caja_base::siguiente_seq(&est, &clave),
            "seq caso={caso}"
        );
        assert_eq!(
            fianza_no_terminal(&est, &clave),
            estado_base::fianza_no_terminal_base(&est, &clave),
            "fianza caso={caso}"
        );
        let c = [-1, 0, 1, 140, 1_000, i128::from(i64::MAX)][caso as usize % 6];
        let mut ap = Aplicador::nuevo(est.clone());
        let mut referencia = Aplicador::nuevo(est.clone());
        assert_eq!(
            debitar_castigable(&mut ap, clave, c, slot),
            estado_base::debitar_castigable_base(&mut referencia, clave, c, slot),
            "cobro caso={caso}"
        );
        assert_eq!(ap.estado, referencia.estado, "estado débito caso={caso}");
        assert_eq!(ap.undo, referencia.undo, "undo débito caso={caso}");
        let indice = [0, 1, 2, u16::MAX][caso as usize % 4];
        let version = [0, 1, 2, u32::MAX][(caso as usize / 4) % 4];
        let mut ap = Aplicador::nuevo(est.clone());
        let mut referencia = Aplicador::nuevo(est);
        assert_eq!(
            super::op_alta(&mut ap, clave, indice, version, [9; 4], 1, slot, &p),
            sector_base::op_alta(&mut referencia, clave, indice, version, [9; 4], 1, slot, &p),
            "alta motivo caso={caso}"
        );
        assert_eq!(ap.estado, referencia.estado, "alta estado caso={caso}");
        assert_eq!(ap.undo, referencia.undo, "alta undo caso={caso}");
    }
    println!(
        "SEC-R1: diez funciones reales, 10000 estados cada una; estado, resultados y undo iguales"
    );
}
