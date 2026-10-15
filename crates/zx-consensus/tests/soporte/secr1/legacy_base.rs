//! Implementaciones literales de la base 2e1fc023: solo cambia el nombre.
#![allow(
    dead_code,
    clippy::wildcard_imports,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "oráculos literales de la base y aserciones deterministas"
)]
use crate as consensus;
pub(crate) mod fixture;
use super::*;
pub fn sector_vivo_base(
    est: &EstadoSector,
    clave: &ClavePublica,
    sector_index: u16,
) -> Option<RegistroSector> {
    let mut mejor: Option<RegistroSector> = None;
    for (id, r) in &est.sectores {
        if id.clave == *clave && id.sector_index == sector_index && !r.es_terminal() {
            match mejor {
                Some(m) if m.id.version >= id.version => {}
                _ => mejor = Some(*r),
            }
        }
    }
    mejor
}

pub fn sectores_activos_base(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> i64 {
    let mut n: i64 = 0;
    for (id, r) in &est.sectores {
        if id.clave == *clave && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo {
            n = n.saturating_add(1);
        }
    }
    n
}

pub fn raiz_lote_de_base(est: &EstadoSector, clave: &ClavePublica) -> R2 {
    let hojas: Vec<R2> = est
        .sectores
        .iter()
        .filter(|(id, r)| id.clave == *clave && !r.es_terminal())
        .map(|(_, r)| crate::cajas::hoja_ocupada(r.r2))
        .collect();
    if hojas.is_empty() {
        return crate::cajas::hoja_libre();
    }
    crate::cajas::raiz_merkle(&hojas)
}

pub fn raiz_conjunto_de_base(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> R2 {
    let hojas: Vec<R2> = est
        .sectores
        .iter()
        .filter(|(id, r)| {
            id.clave == *clave && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo
        })
        .map(|(_, r)| crate::cajas::hoja_ocupada(r.r2))
        .collect();
    if hojas.is_empty() {
        return crate::cajas::hoja_libre();
    }
    crate::cajas::raiz_merkle(&hojas)
}

pub fn fianza_comprometida_base(est: &EstadoSector, clave: &ClavePublica) -> i64 {
    let mut t: i64 = 0;
    for (id, r) in &est.sectores {
        if id.clave == *clave && !r.es_terminal() {
            t = t.saturating_add(r.fianza);
        }
    }
    t
}

pub fn total_castigable_base(est: &EstadoSector, clave: &ClavePublica) -> i64 {
    let mut t = est.garantias.get(clave).map_or(0, total_cuenta);
    for (id, r) in &est.sectores {
        if id.clave == *clave && !r.es_terminal() {
            t = t.saturating_add(r.fianza);
        }
    }
    t
}

pub fn fuente_peso_de_base(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> i64 {
    let mut n: i64 = 0;
    for (id, r) in &est.sectores {
        if id.clave == *clave
            && !r.es_terminal()
            && r.fianza == p.q_sec
            && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo
            && (!p.exigir_prueba_almacenamiento || prueba_vigente(est, clave, slot, p))
        {
            n = n.saturating_add(1);
        }
    }
    n
}

impl AplicadorSector<'_> {
    /// Copia literal del débito anterior al cambio SEC-R1.
    pub fn debitar_cuenta_base(&mut self, clave: ClavePublica, c: i64) -> i64 {
        if c <= 0 {
            return 0;
        }
        let mut restante = c;
        {
            let cu = self.cuenta_mut(clave);
            let d = restante.min(cu.activo);
            cu.activo -= d;
            restante -= d;
            if restante > 0 && !cu.pendientes.is_empty() {
                let mut nuevas = Vec::with_capacity(cu.pendientes.len());
                for pp in cu.pendientes.drain(..) {
                    if restante > 0 {
                        let d = restante.min(pp.importe);
                        restante -= d;
                        if d != pp.importe {
                            nuevas.push(Pendiente {
                                importe: pp.importe - d,
                                madura_slot: pp.madura_slot,
                            });
                        }
                    } else {
                        nuevas.push(pp);
                    }
                }
                cu.pendientes = nuevas;
            }
            if restante > 0 && !cu.en_retirada.is_empty() {
                let mut nuevas = Vec::with_capacity(cu.en_retirada.len());
                for rr in cu.en_retirada.drain(..) {
                    if restante > 0 {
                        let d = restante.min(rr.importe);
                        restante -= d;
                        if d != rr.importe {
                            nuevas.push(Retiro {
                                importe: rr.importe - d,
                                inicio_slot: rr.inicio_slot,
                            });
                        }
                    } else {
                        nuevas.push(rr);
                    }
                }
                cu.en_retirada = nuevas;
            }
            if restante > 0 && !cu.creditos.is_empty() {
                let mut nuevas = Vec::with_capacity(cu.creditos.len());
                for cc in cu.creditos.drain(..) {
                    if restante > 0 {
                        let d = restante.min(cc.importe);
                        restante -= d;
                        if d != cc.importe {
                            nuevas.push(Pendiente {
                                importe: cc.importe - d,
                                madura_slot: cc.madura_slot,
                            });
                        }
                    } else {
                        nuevas.push(cc);
                    }
                }
                cu.creditos = nuevas;
            }
        }
        if restante > 0 {
            let ids: Vec<SectorId> = self
                .estado
                .sectores
                .iter()
                .filter(|(id, r)| id.clave == clave && !r.es_terminal() && r.fianza > 0)
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                if restante <= 0 {
                    break;
                }
                self.tocar_sector(id);
                if let Some(r) = self.estado.sectores.get_mut(&id) {
                    let d = restante.min(r.fianza);
                    restante -= d;
                    r.fianza -= d;
                }
            }
        }
        c - restante
    }

    /// Copia literal del alta anterior al cambio SEC-R1.
    pub fn op_alta_base(
        &mut self,
        op: &Operacion,
        slot: i64,
        p: &ParametrosSector,
    ) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let mut vmax: i64 = -1;
        let mut prev: Option<RegistroSector> = None;
        for (id, r) in &self.estado.sectores {
            if id.clave == op.clave
                && id.sector_index == op.sector_index
                && i64::from(id.version) > vmax
            {
                vmax = i64::from(id.version);
                prev = Some(*r);
            }
        }
        if vmax < 0 {
            if op.version != 0 {
                return MotivoSector::ErrVersion;
            }
        } else {
            if op.version == u32::try_from(vmax).unwrap_or(u32::MAX) {
                return MotivoSector::ErrDobleAlta;
            }
            if op.version != u32::try_from(vmax.saturating_add(1)).unwrap_or(u32::MAX) {
                return MotivoSector::ErrVersion;
            }
            if prev.is_some_and(|r| !r.es_terminal()) {
                return MotivoSector::ErrDobleAlta;
            }
        }
        if op.history_size < p.h_min || op.history_size > p.h_max {
            return MotivoSector::ErrHistory;
        }
        if op.importe != p.q_sec {
            return MotivoSector::ErrFianza;
        }
        let cu = self.cuenta_mut(op.clave);
        if cu.activo < p.q_sec {
            return MotivoSector::ErrFianza;
        }
        cu.activo -= p.q_sec;
        let id = SectorId {
            clave: op.clave,
            sector_index: op.sector_index,
            version: op.version,
        };
        let reg = RegistroSector {
            id,
            r2: op.r2,
            history_size: op.history_size,
            etapa: Etapa::Precomprometido,
            alta_slot: slot,
            renovacion_slot: slot.saturating_add(p.m_sec),
            retiro_slot: NO_HAY,
            fianza: p.q_sec,
            aud_apertura: NO_HAY,
            aud_contestada: NO_HAY,
        };
        self.tocar_sector(id);
        self.estado.sectores.insert(id, reg);
        MotivoSector::Ok
    }
}

#[test]
fn secr1_equivalencia_legacy_diez_mil_estados() {
    for caso in 0..10_000 {
        let real = fixture::estado_generado(caso);
        let mut est = EstadoSector {
            sectores: real.sectores,
            pruebas: real.pruebas,
            ..EstadoSector::default()
        };
        for (clave, g) in real.garantias {
            let mut cuenta = CuentaGarantia {
                activo: g.activo.brek(),
                ..CuentaGarantia::nueva(clave)
            };
            cuenta.pendientes.push(Pendiente {
                importe: 7,
                madura_slot: 1_000,
            });
            cuenta.en_retirada.push(Retiro {
                importe: 11,
                inicio_slot: 0,
            });
            cuenta.creditos.push(Pendiente {
                importe: 13,
                madura_slot: 1_000,
            });
            est.garantias.insert(clave, cuenta);
        }
        let clave = fixture::clave(2);
        let slot = (caso % 151) as i64;
        let p = real.parametros_sector;
        for indice in [0, 1, u16::MAX] {
            assert_eq!(
                super::sector_vivo(&est, &clave, indice),
                sector_vivo_base(&est, &clave, indice),
                "legacy vivo caso={caso}"
            );
        }
        assert_eq!(
            super::sectores_activos(&est, &clave, slot, &p),
            sectores_activos_base(&est, &clave, slot, &p),
            "legacy activos caso={caso}"
        );
        assert_eq!(
            super::raiz_lote_de(&est, &clave),
            raiz_lote_de_base(&est, &clave),
            "legacy lote caso={caso}"
        );
        assert_eq!(
            super::raiz_conjunto_de(&est, &clave, slot, &p),
            raiz_conjunto_de_base(&est, &clave, slot, &p),
            "legacy conjunto caso={caso}"
        );
        assert_eq!(
            super::fianza_comprometida(&est, &clave),
            fianza_comprometida_base(&est, &clave),
            "legacy fianza caso={caso}"
        );
        assert_eq!(
            super::total_castigable(&est, &clave),
            total_castigable_base(&est, &clave),
            "legacy total caso={caso}"
        );
        assert_eq!(
            super::fuente_peso_de(&est, &clave, slot, &p),
            fuente_peso_de_base(&est, &clave, slot, &p),
            "legacy peso caso={caso}"
        );
        let c = [-1, 0, 1, 140, 1_000, i64::MAX][caso as usize % 6];
        let mut a = est.clone();
        let mut b = est.clone();
        let mut ap = AplicadorSector::nuevo(&mut a);
        let mut referencia = AplicadorSector::nuevo(&mut b);
        assert_eq!(
            ap.debitar_cuenta(clave, c),
            referencia.debitar_cuenta_base(clave, c),
            "legacy cobro caso={caso}"
        );
        assert_eq!(ap.undo, referencia.undo, "legacy undo débito caso={caso}");
        drop(ap);
        drop(referencia);
        assert_eq!(a, b, "legacy estado débito caso={caso}");
        let mut op = Operacion::base(TipoOp::Alta);
        op.clave = clave;
        op.importe = p.q_sec;
        op.history_size = 1;
        op.r2 = [9; 4];
        op.sector_index = [0, 1, 2, u16::MAX][caso as usize % 4];
        op.version = [0, 1, 2, u32::MAX][(caso as usize / 4) % 4];
        let mut a = est.clone();
        let mut b = est;
        let mut ap = AplicadorSector::nuevo(&mut a);
        let mut referencia = AplicadorSector::nuevo(&mut b);
        assert_eq!(
            ap.op_alta(&op, slot, &p),
            referencia.op_alta_base(&op, slot, &p),
            "legacy alta motivo caso={caso}"
        );
        assert_eq!(ap.undo, referencia.undo, "legacy alta undo caso={caso}");
        drop(ap);
        drop(referencia);
        assert_eq!(a, b, "legacy alta estado caso={caso}");
    }
    println!(
        "SEC-R1: nueve funciones legacy, 10000 estados cada una; estado, resultados y undo iguales"
    );
}
