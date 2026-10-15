//! Apoyo de test SR-1-2 · puente entre el oráculo SR-0 y la **transición real**.
//!
//! `ORDEN-SR1-2` §2: el diferencial V2 debe pasar por la transición real, no por un modelo
//! paralelo. Aquí el estado de la traza es [`transicion::Estado`] (envuelto en [`EstadoSector`] solo
//! para conservar el `slot_actual` del oráculo) y la aplicación de las operaciones de sector llama a
//! [`zx_consensus::transicion::aplicar_operacion_con_undo`] / `materializar_con_undo`. Las
//! operaciones de **valor** del oráculo (`fondear`, `depósito`, `retiro`, `liberación`, coinbase
//! PoST, evidencia) se traducen a mutaciones directas de la `Garantia` real porque la traza las usa
//! como montaje, no como objeto de la orden.
//!
//! Este módulo sustituye a `zx_consensus::sectores::generadores` (que sale de `src/`, `ORDEN-SR1-2`
//! §3) y reexporta con el mismo nombre las piezas que ese fichero espera.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "módulo de apoyo compartido: cada test usa un subconjunto y falla con panic por diseño"
)]

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use zx_core::{Amount, ClavePublica, OperacionSector};

pub use zx_consensus::sectores::{
    BloqueSector, DagSector, EstadoEfectivo, Etapa, MotivoSector, Operacion, ParametrosSector, R2,
    ResultadoPrueba, Solucion, TipoOp, clave_de, estado_efectivo, prueba_sucinta,
};
use zx_consensus::transicion::deshacer as deshacer_transicion;
pub use zx_consensus::transicion::{
    EnRetirada, Estado, Garantia, Incidente, Pendiente, total_garantia,
};

pub mod generadores;

/// Estado de la traza: la transición real más el `slot_actual` que usa el oráculo.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EstadoSector {
    /// Estado de consenso real.
    pub estado: Estado,
    /// Último slot materializado por la traza.
    pub slot_actual: i64,
}

impl Default for EstadoSector {
    fn default() -> Self {
        Self {
            estado: Estado::inicial(),
            slot_actual: 0,
        }
    }
}

impl Deref for EstadoSector {
    type Target = Estado;
    fn deref(&self) -> &Estado {
        &self.estado
    }
}

impl DerefMut for EstadoSector {
    fn deref_mut(&mut self) -> &mut Estado {
        &mut self.estado
    }
}

/// Mutable a la `Garantia` de `clave`, creándola si no existe.
fn garantia_mut(est: &mut Estado, clave: ClavePublica) -> &mut Garantia {
    est.garantias.entry(clave).or_insert_with(Garantia::nueva)
}

fn activo(g: &mut Garantia, delta: i64) -> Result<(), MotivoSector> {
    let v = i128::from(g.activo.brek()) + i128::from(delta);
    if v < 0 {
        return Err(MotivoSector::ErrFianza);
    }
    g.activo = Amount::nuevo(i64::try_from(v).map_err(|_| MotivoSector::ErrDesbordamiento)?)
        .map_err(|_| MotivoSector::ErrDesbordamiento)?;
    Ok(())
}

/// Identificador determinista de incidente (FNV-1a, igual que el oráculo S03).
fn incidente_id(clave: &ClavePublica, si: u16, aud: u64, h1: &R2, h2: &R2) -> u64 {
    let mut bytes = Vec::with_capacity(32 + 2 + 8 + 64);
    bytes.extend_from_slice(clave.bytes());
    bytes.extend_from_slice(&si.to_le_bytes());
    bytes.extend_from_slice(&aud.to_le_bytes());
    for w in h1.iter().chain(h2.iter()) {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `Σ fianzas no terminales` de `clave`.
#[must_use]
pub fn fianza_comprometida(est: &EstadoSector, clave: &ClavePublica) -> i64 {
    let mut t = 0i64;
    for (id, r) in &est.estado.sectores {
        if id.clave == *clave && !r.es_terminal() {
            t = t.saturating_add(r.fianza);
        }
    }
    t
}

/// Total castigable: cuenta + fianzas no terminales.
#[must_use]
pub fn total_castigable(est: &EstadoSector, clave: &ClavePublica) -> i64 {
    let cuenta = est
        .estado
        .garantias
        .get(clave)
        .map_or(0, |g| i64::try_from(total_garantia(g)).unwrap_or(i64::MAX));
    cuenta.saturating_add(fianza_comprometida(est, clave))
}

/// Número de sectores activos de `clave` en `slot`.
#[must_use]
pub fn sectores_activos(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> i64 {
    let mut n = 0i64;
    for (id, r) in &est.estado.sectores {
        if id.clave == *clave && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo {
            n = n.saturating_add(1);
        }
    }
    n
}

/// `requisito(clave, slot) = q_sec × sectores_activos`.
#[must_use]
pub fn requisito(est: &EstadoSector, clave: &ClavePublica, slot: i64, p: &ParametrosSector) -> i64 {
    p.q_sec
        .saturating_mul(sectores_activos(est, clave, slot, p))
}

/// Índice del sector vivo de `(clave, sector_index)` (versión mayor si hubiera varias).
#[must_use]
pub fn sector_vivo(
    est: &EstadoSector,
    clave: &ClavePublica,
    sector_index: u16,
) -> Option<zx_consensus::sectores::RegistroSector> {
    let mut mejor: Option<zx_consensus::sectores::RegistroSector> = None;
    for (id, r) in &est.estado.sectores {
        if id.clave == *clave && id.sector_index == sector_index && !r.es_terminal() {
            match mejor {
                Some(m) if m.id.version >= id.version => {}
                _ => mejor = Some(*r),
            }
        }
    }
    mejor
}

/// `FuentePeso` por clave (`C-SEC-15`).
#[must_use]
pub fn fuente_peso_de(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> i64 {
    let mut n = 0i64;
    for (id, r) in &est.estado.sectores {
        if id.clave == *clave
            && !r.es_terminal()
            && r.fianza == p.q_sec
            && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo
        {
            n = n.saturating_add(1);
        }
    }
    n
}

/// `I-1` extendida: `UTXO + garantías + fianzas no terminales == emitido − quemado`.
#[must_use]
pub fn invariante_valor(est: &EstadoSector) -> bool {
    let mut t: i128 = zx_consensus::transicion::suma_utxo(&est.estado)
        + zx_consensus::transicion::suma_garantias(&est.estado);
    for r in est.estado.sectores.values() {
        if !r.es_terminal() {
            t += i128::from(r.fianza);
        }
    }
    t == est.estado.emitido - est.estado.quemado
}

/// `requisito` cubierto por clave.
#[must_use]
pub fn invariante_requisito(est: &EstadoSector, p: &ParametrosSector) -> bool {
    for clave in est.estado.garantias.keys() {
        let n = sectores_activos(est, clave, est.slot_actual, p);
        if fianza_comprometida(est, clave) < p.q_sec.saturating_mul(n) {
            return false;
        }
    }
    true
}

// ── operaciones de valor del oráculo (montaje) ──────────────────────────────

fn r2_a_bytes(r2: &R2) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in r2.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn a_real(op: &Operacion) -> OperacionSector {
    match op.tipo {
        TipoOp::Alta => OperacionSector::Alta {
            clave: op.clave,
            sector_index: op.sector_index,
            version: op.version,
            r2: r2_a_bytes(&op.r2),
            history_size: op.history_size,
        },
        TipoOp::Renovar => OperacionSector::Renovar {
            clave: op.clave,
            sector_index: op.sector_index,
        },
        TipoOp::AbrirAud => OperacionSector::AbrirAuditoria {
            clave: op.clave,
            sector_index: op.sector_index,
            auditoria_id: op.auditoria_id,
        },
        TipoOp::Contestar => OperacionSector::ContestarAuditoria {
            clave: op.clave,
            sector_index: op.sector_index,
            auditoria_id: op.auditoria_id,
            prueba: if op.prueba { vec![1] } else { Vec::new() },
        },
        TipoOp::RetirarSector => OperacionSector::Retirar {
            clave: op.clave,
            sector_index: op.sector_index,
        },
        _ => unreachable!("a_real solo se llama con operaciones de sector"),
    }
}

fn es_sector_op(t: TipoOp) -> bool {
    matches!(
        t,
        TipoOp::Alta
            | TipoOp::Renovar
            | TipoOp::AbrirAud
            | TipoOp::Contestar
            | TipoOp::RetirarSector
    )
}

/// Debita `c` de la cuenta en el orden `activo → pendientes → en_retirada → créditos → fianzas`.
fn debitar(est: &mut EstadoSector, clave: ClavePublica, c: i64) -> i64 {
    if c <= 0 {
        return 0;
    }
    let mut restante = c;
    {
        let g = garantia_mut(&mut est.estado, clave);
        let d = restante.min(g.activo.brek());
        let _ = activo(g, -d);
        restante -= d;
        if restante > 0 {
            let mut nuevas = Vec::with_capacity(g.pendientes.len());
            for p in g.pendientes.drain(..) {
                if restante > 0 {
                    let d = restante.min(p.importe.brek());
                    restante -= d;
                    if d != p.importe.brek() {
                        nuevas.push(Pendiente {
                            importe: Amount::nuevo(p.importe.brek() - d).unwrap_or(Amount::CERO),
                            ..p
                        });
                    }
                } else {
                    nuevas.push(p);
                }
            }
            g.pendientes = nuevas;
        }
        if restante > 0 {
            let mut nuevas = Vec::with_capacity(g.en_retirada.len());
            for r in g.en_retirada.drain(..) {
                if restante > 0 {
                    let d = restante.min(r.importe.brek());
                    restante -= d;
                    if d != r.importe.brek() {
                        nuevas.push(EnRetirada {
                            importe: Amount::nuevo(r.importe.brek() - d).unwrap_or(Amount::CERO),
                            inicio_slot: r.inicio_slot,
                        });
                    }
                } else {
                    nuevas.push(r);
                }
            }
            g.en_retirada = nuevas;
        }
        if restante > 0 {
            let mut nuevas = Vec::with_capacity(g.creditos.len());
            for p in g.creditos.drain(..) {
                if restante > 0 {
                    let d = restante.min(p.importe.brek());
                    restante -= d;
                    if d != p.importe.brek() {
                        nuevas.push(Pendiente {
                            importe: Amount::nuevo(p.importe.brek() - d).unwrap_or(Amount::CERO),
                            ..p
                        });
                    }
                } else {
                    nuevas.push(p);
                }
            }
            g.creditos = nuevas;
        }
    }
    if restante > 0 {
        let ids: Vec<_> = est
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
            if let Some(r) = est.estado.sectores.get_mut(&id) {
                let d = restante.min(r.fianza);
                restante -= d;
                r.fianza -= d;
            }
        }
    }
    c - restante
}

/// Aplica una operación de **valor** del oráculo sobre el estado real (montaje de la traza).
fn aplicar_valor(
    est: &mut EstadoSector,
    op: &Operacion,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    match op.tipo {
        TipoOp::Fondear => {
            if !op.firma {
                return MotivoSector::ErrFirma;
            }
            if op.importe <= 0 {
                return MotivoSector::ErrFianza;
            }
            est.estado.emitido += i128::from(op.importe);
            let g = garantia_mut(&mut est.estado, op.clave);
            match activo(g, op.importe) {
                Ok(()) => MotivoSector::Ok,
                Err(m) => m,
            }
        }
        TipoOp::Deposito => {
            if !op.firma {
                return MotivoSector::ErrFirma;
            }
            if op.importe <= 0 {
                return MotivoSector::ErrFianza;
            }
            // El oráculo baja el UTXO total; aquí se acredita contra emisión para conservar I-1.
            est.estado.emitido += i128::from(op.importe);
            let g = garantia_mut(&mut est.estado, op.clave);
            match activo(g, op.importe) {
                Ok(()) => MotivoSector::Ok,
                Err(m) => m,
            }
        }
        TipoOp::Retiro => {
            if !op.firma {
                return MotivoSector::ErrFirma;
            }
            let g = garantia_mut(&mut est.estado, op.clave);
            if op.importe <= 0 || op.importe > g.activo.brek() {
                return MotivoSector::ErrFianza;
            }
            if !g.en_retirada.is_empty() {
                return MotivoSector::ErrRetiroPendiente;
            }
            let v = g.activo.brek();
            g.activo = Amount::nuevo(v - op.importe).unwrap_or(Amount::CERO);
            g.en_retirada.push(EnRetirada {
                importe: Amount::nuevo(op.importe).unwrap_or(Amount::CERO),
                inicio_slot: u64::try_from(slot.max(0)).unwrap_or(0),
            });
            MotivoSector::Ok
        }
        TipoOp::Liberacion => {
            if !op.firma {
                return MotivoSector::ErrFirma;
            }
            let sin_incidentes = est
                .estado
                .garantias
                .get(&op.clave)
                .is_none_or(|g| g.incidentes.is_empty());
            if !sin_incidentes {
                return MotivoSector::ErrEstado;
            }
            let ultimo = est.estado.ultimo_slot_producido.get(&op.clave).copied();
            if ultimo.is_some_and(|u| {
                slot < i64::try_from(u)
                    .unwrap_or(i64::MAX)
                    .saturating_add(p.plazo_slots)
                    .saturating_add(p.m_margen_slots)
            }) {
                return MotivoSector::ErrPlazo;
            }
            let g = garantia_mut(&mut est.estado, op.clave);
            let mut vencido = 0i64;
            for r in &g.en_retirada {
                if i64::try_from(r.inicio_slot)
                    .unwrap_or(i64::MAX)
                    .saturating_add(p.r_slots)
                    <= slot
                {
                    vencido = vencido.saturating_add(r.importe.brek());
                }
            }
            if op.importe <= 0 || op.importe > vencido {
                return MotivoSector::ErrFianza;
            }
            let mut restante = op.importe;
            let mut nuevas = Vec::with_capacity(g.en_retirada.len());
            for r in g.en_retirada.drain(..) {
                let vencida = i64::try_from(r.inicio_slot)
                    .unwrap_or(i64::MAX)
                    .saturating_add(p.r_slots)
                    <= slot;
                if restante > 0 && vencida {
                    if r.importe.brek() <= restante {
                        restante -= r.importe.brek();
                    } else {
                        nuevas.push(EnRetirada {
                            importe: Amount::nuevo(r.importe.brek() - restante)
                                .unwrap_or(Amount::CERO),
                            inicio_slot: r.inicio_slot,
                        });
                        restante = 0;
                    }
                } else {
                    nuevas.push(r);
                }
            }
            g.en_retirada = nuevas;
            let _ = activo(g, op.importe);
            MotivoSector::Ok
        }
        TipoOp::CoinbasePost => {
            if op.importe <= 0 {
                return MotivoSector::ErrFianza;
            }
            est.estado.emitido += i128::from(op.importe);
            let g = garantia_mut(&mut est.estado, op.clave);
            g.creditos.push(Pendiente {
                importe: Amount::nuevo(op.importe).unwrap_or(Amount::CERO),
                madura_en_altura: None,
                madura_en_slot: Some(u64::try_from(slot.max(0)).unwrap_or(0)),
            });
            MotivoSector::Ok
        }
        TipoOp::Evidencia => {
            if !op.firma {
                return MotivoSector::ErrFirma;
            }
            let iid = incidente_id(&op.clave, op.sector_index, op.auditoria_id, &op.h1, &op.h2);
            let mut id32 = [0u8; 32];
            id32[..8].copy_from_slice(&iid.to_le_bytes());
            let v = total_castigable(est, &op.clave);
            {
                let g = garantia_mut(&mut est.estado, op.clave);
                if g.incidentes.iter().any(|i| i.id == id32) {
                    return MotivoSector::ErrAuditoria;
                }
                g.incidentes.push(Incidente {
                    id: id32,
                    slot_falta: slot,
                });
                g.congelado = Amount::nuevo(v).unwrap_or(Amount::CERO);
            }
            let num = v
                .saturating_mul(p.f_num)
                .saturating_add(p.f_den.saturating_sub(1));
            let cap = if p.f_den == 0 || p.f_num == 0 {
                0
            } else {
                num.div_euclid(p.f_den)
            }
            .min(v);
            let _ = debitar(est, op.clave, cap);
            est.estado.quemado += i128::from(cap);
            MotivoSector::Ok
        }
        _ => MotivoSector::Ok,
    }
}

/// Resultado de [`aplicar_bloque`] (undo = estado previo, suficiente para la traza).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResultadoBloqueSector {
    /// Estado previo al bloque.
    pub undo: EstadoSector,
    /// Operaciones descartadas con su motivo.
    pub descartadas: Vec<MotivoSector>,
    /// ¿Fue admitido?
    pub valido: bool,
    /// ¿La solución era elegible?
    pub elegible: bool,
}

/// Aplica un bloque del oráculo sobre el estado **real** (`ORDEN-SR1-2` §2).
pub fn aplicar_bloque(
    est: &mut EstadoSector,
    b: &BloqueSector,
    p: &ParametrosSector,
) -> ResultadoBloqueSector {
    let previo = est.clone();
    est.estado.parametros_sector = *p;
    let (nuevo, _) = zx_consensus::transicion::materializar_con_undo(&est.estado, b.slot, p);
    est.estado = nuevo;
    let mut valido = true;
    let mut eleg = true;
    if let Some(sol) = &b.sol {
        eleg = zx_consensus::transicion::elegible_sector(
            &est.estado,
            &sol.clave,
            sol.sector_index,
            sol.history_size,
            b.slot,
            p,
        );
        if eleg {
            let slot_u = u64::try_from(b.slot.max(0)).unwrap_or(0);
            let prev = est.estado.ultimo_slot_producido.get(&sol.clave).copied();
            if prev.is_none_or(|x| slot_u > x) {
                est.estado.ultimo_slot_producido.insert(sol.clave, slot_u);
            }
        } else {
            valido = false;
        }
    }
    if valido && b.ops.len() > p.max_ops_bloque {
        valido = false;
    }
    let mut descartadas = Vec::new();
    if valido {
        for op in &b.ops {
            if op.tipo == TipoOp::Alta && op.importe != p.q_sec {
                // El oráculo usa `importe` como fianza declarada; el real la fija en `q_sec`.
                descartadas.push(MotivoSector::ErrFianza);
                continue;
            }
            if !op.firma {
                descartadas.push(MotivoSector::ErrFirma);
                continue;
            }
            let snapshot = est.clone();
            let m = if es_sector_op(op.tipo) {
                let real = a_real(op);
                let (nuevo, r) = zx_consensus::transicion::aplicar_operacion_con_undo(
                    &est.estado,
                    &real,
                    b.slot,
                    p,
                );
                if r.motivo == MotivoSector::Ok {
                    est.estado = nuevo;
                    MotivoSector::Ok
                } else {
                    let revertido = deshacer_transicion(&nuevo, &r.undo);
                    est.estado = revertido;
                    r.motivo
                }
            } else {
                aplicar_valor(est, op, b.slot, p)
            };
            if m != MotivoSector::Ok {
                est.estado = snapshot.estado;
                descartadas.push(m);
            }
        }
    }
    if b.slot >= est.slot_actual {
        est.slot_actual = b.slot;
    }
    ResultadoBloqueSector {
        undo: previo,
        descartadas,
        valido,
        elegible: eleg,
    }
}

/// Restituye el estado previo al bloque (undo de la traza).
pub fn deshacer(est: &mut EstadoSector, previo: &EstadoSector) {
    *est = previo.clone();
}

/// Repliega el pasado de `id` desde cero, en orden C-ORD-03.
#[must_use]
pub fn fold_referencia(
    d: &DagSector,
    id: u64,
    p: &ParametrosSector,
) -> (EstadoSector, BTreeMap<u64, Vec<MotivoSector>>) {
    let mut est = EstadoSector::default();
    let mut descartes = BTreeMap::new();
    for x in d.orden_total(id) {
        let Some(b) = d.bloques.get(&x) else {
            continue;
        };
        let r = aplicar_bloque(&mut est, b, p);
        if r.valido {
            descartes.insert(x, r.descartadas);
        } else {
            deshacer(&mut est, &r.undo);
            descartes.insert(x, vec![MotivoSector::ErrEstado]);
        }
    }
    (est, descartes)
}

/// Cadena incremental con undo por bloque.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct CadenaSector {
    /// Estado aplicado.
    pub estado: EstadoSector,
    /// Bloques aplicados.
    pub aplicados: Vec<u64>,
    /// Estado **después** de cada bloque aplicado.
    pub despues: Vec<EstadoSector>,
}

/// Sincroniza `c` con la punta `id` del DAG `d`, deshaciendo y reaplicando el prefijo que sobra.
pub fn avanzar(c: &mut CadenaSector, d: &DagSector, id: u64, p: &ParametrosSector) {
    let objetivo = d.orden_total(id);
    let mut k = 0;
    while k < c.aplicados.len() && k < objetivo.len() && c.aplicados.get(k) == objetivo.get(k) {
        k += 1;
    }
    c.aplicados.truncate(k);
    c.despues.truncate(k);
    c.estado = if k == 0 {
        EstadoSector::default()
    } else {
        c.despues.get(k - 1).cloned().unwrap_or_default()
    };
    for x in objetivo.iter().skip(k) {
        let Some(b) = d.bloques.get(x) else {
            continue;
        };
        let r = aplicar_bloque(&mut c.estado, b, p);
        if r.valido {
            c.aplicados.push(*x);
            c.despues.push(c.estado.clone());
        } else {
            deshacer(&mut c.estado, &r.undo);
            c.aplicados.push(*x);
            c.despues.push(c.estado.clone());
        }
    }
}

/// Comprueba que aplicar y deshacer cada bloque vuelve al estado previo bit a bit.
#[must_use]
pub fn undo_exacto(d: &DagSector, id: u64, p: &ParametrosSector) -> bool {
    let mut est = EstadoSector::default();
    for x in d.orden_total(id) {
        let Some(b) = d.bloques.get(&x) else {
            continue;
        };
        let previo = est.clone();
        let r = aplicar_bloque(&mut est, b, p);
        deshacer(&mut est, &r.undo);
        if est != previo {
            return false;
        }
        let r2 = aplicar_bloque(&mut est, b, p);
        if !r2.valido {
            deshacer(&mut est, &r2.undo);
        }
    }
    true
}

/// Cuenta las operaciones descartadas de un bloque en un repliegue concreto.
#[must_use]
pub fn descartes_de(d: &DagSector, id: u64, p: &ParametrosSector) -> Vec<MotivoSector> {
    let (_, desc) = fold_referencia(d, id, p);
    desc.get(&id).cloned().unwrap_or_default()
}

/// Mapa de descartes por bloque de un repliegue.
#[must_use]
pub fn descartes_mapa(
    d: &DagSector,
    id: u64,
    p: &ParametrosSector,
) -> BTreeMap<u64, Vec<MotivoSector>> {
    fold_referencia(d, id, p).1
}

/// Deja `Etapa` y `ResultadoPrueba` disponibles para los tests.
#[must_use]
pub fn es_terminal_etapa(e: Etapa) -> bool {
    matches!(e, Etapa::Retirado | Etapa::Caducado)
}
