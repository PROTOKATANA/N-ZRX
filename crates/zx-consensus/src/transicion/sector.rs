//! SR-1-2 · registro de sectores dentro de la **transición real** (`Estado` de consenso).
//!
//! `ORDEN-SR1-2` §2: `transicion/aplicar.rs` aplica las operaciones de sector y su undo; la
//! validación de bloques rechaza las inválidas. Las reglas `C-SEC-02/04/05/06/08` se implementan
//! aquí sobre [`Estado`] (el mismo estado que usa el motor PoW→PoST), mutando `Estado::sectores` y
//! la [`Garantia`] de la clave, con el undo por delta de [`crate::transicion::Aplicador`].
//!
//! `crate::sectores` conserva los tipos canónicos (`SectorId`, `RegistroSector`, `ParametrosSector`,
//! `MotivoSector`), las consultas puras (`estado_efectivo`, `elegible`) y su oráculo de S03. La
//! **aplicación** vive aquí, de modo que el diferencial V2 puede ejercer el estado real.

use std::collections::BTreeMap;

use zx_core::{Amount, ClavePublica, OperacionSector};

use crate::sectores::{
    EstadoEfectivo, Etapa, MotivoSector, ParametrosSector, R2, RegistroSector, SectorId, Solucion,
    estado_efectivo,
};
use crate::transicion::ErrorTransicion;
use crate::transicion::caja;
use crate::transicion::estado::Aplicador;
use crate::transicion::tipos::{Estado, Garantia, Undo};

/// Convierte el `R2` de 32 B de la operación canónica al `[u64; 4]` del registro.
fn r2_de_bytes(b: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (w, ocho) in out.iter_mut().zip(b.chunks_exact(8)) {
        let e: [u8; 8] = ocho.try_into().unwrap_or_default();
        *w = u64::from_le_bytes(e);
    }
    out
}

/// Índice del sector **vivo** (no terminal) de `(clave, sector_index)` en el estado real.
#[must_use]
pub fn sector_vivo(
    est: &Estado,
    clave: &ClavePublica,
    sector_index: u16,
) -> Option<RegistroSector> {
    let mut mejor: Option<RegistroSector> = None;
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
        if id.clave == *clave && id.sector_index == sector_index && !r.es_terminal() {
            match mejor {
                Some(m) if m.id.version >= id.version => {}
                _ => mejor = Some(*r),
            }
        }
    }
    mejor
}

/// `C-SEC-12` · ¿la solución `(clave, sector_index, history_size)` es elegible en `slot`?
#[must_use]
pub fn elegible_sector(
    est: &Estado,
    clave: &ClavePublica,
    sector_index: u16,
    history_size: u64,
    slot: i64,
    p: &ParametrosSector,
) -> bool {
    let Some(r) = sector_vivo(est, clave, sector_index) else {
        return false;
    };
    if r.history_size != history_size {
        return false;
    }
    if p.exigir_prueba_almacenamiento && !prueba_vigente(est, clave, slot, p) {
        return false;
    }
    estado_efectivo(&r, slot, p) == EstadoEfectivo::Activo
}

// ── PT-3bc · prueba de almacenamiento en el estado real ──────────────────────

/// PT-3bc · ¿hay prueba de almacenamiento **vigente** de `clave` en `slot`? (`C-SEC-15`).
#[must_use]
pub fn prueba_vigente(est: &Estado, clave: &ClavePublica, slot: i64, p: &ParametrosSector) -> bool {
    let Some(pr) = est.pruebas.get(clave) else {
        return false;
    };
    slot.saturating_sub(pr.slot_prueba) <= p.t_gracia
}

/// PT-3c-2 · raíz Merkle de las hojas `hoja_ocupada(raiz_caja)` de las cajas no terminales de
/// `clave` que cumplen `incluir`; `hoja_libre()` si no hay ninguna.
///
/// Decisión del orquestador (no se reabre): el `r2` de cada sector vive en el árbol de su caja y
/// la raíz se compone de **raíces de caja**, no de los `r2` individuales.
fn raiz_de_cajas(
    est: &Estado,
    clave: &ClavePublica,
    incluir: impl Fn(&crate::cajas::RegistroCaja) -> bool,
) -> R2 {
    let hojas: Vec<R2> = crate::cajas::cajas_de_clave(&est.cajas, clave)
        .map(|(_, c)| c)
        .filter(|c| c.id.clave == *clave && !c.es_terminal() && c.n > 0 && incluir(c))
        .map(|c| crate::cajas::hoja_ocupada(c.raiz))
        .collect();
    if hojas.is_empty() {
        return crate::cajas::hoja_libre();
    }
    crate::cajas::raiz_merkle(&hojas)
}

/// PT-3c-2 · raíz del lote de cajas **no terminales** de `clave` (PoRep).
#[must_use]
pub fn raiz_lote_de(est: &Estado, clave: &ClavePublica) -> R2 {
    raiz_de_cajas(est, clave, |_| true)
}

/// PT-3c-2 · raíz del conjunto de cajas con algún hueco **`Activo`** de `clave` en `slot`
/// (`C-SEC-15`). El `raiz_conjunto` de la PoSt se ancla a las raíces de caja activas.
#[must_use]
pub fn raiz_conjunto_de(est: &Estado, clave: &ClavePublica, slot: i64, p: &ParametrosSector) -> R2 {
    raiz_de_cajas(est, clave, |c| {
        (1..=usize::from(c.n))
            .any(|j| caja::estado_hueco(est, c, j, slot, p) == Some(EstadoEfectivo::Activo))
    })
}

/// PT-3bc · número de sectores `Activo` de `clave` en `slot`.
#[must_use]
pub fn sectores_activos_de(
    est: &Estado,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> u64 {
    let mut n: u64 = 0;
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
        if id.clave == *clave && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo {
            n = n.saturating_add(1);
        }
    }
    n
}

/// PT-3bc · ¿una atestación PoRep cubre al sector `r`? (`REVISION-PT3a` decisión 5).
#[must_use]
pub fn cubierto_por_porep(est: &Estado, r: &RegistroSector, p: &ParametrosSector) -> bool {
    let Some(po) = est.poreps.get(&r.id.clave) else {
        return false;
    };
    po.n_sectores > 0
        && po.slot_ventana >= r.alta_slot.saturating_add(p.f_slots)
        && po.raiz_lote == raiz_lote_de(est, &r.id.clave)
}

/// PT-3bc · aplica una operación de la extensión v6 al estado real.
///
/// Las clases `0x01`/`0x02` registran la atestación PoRep y la prueba PoSt; `0x03` verifica la
/// prueba de posesión BLS con `zx-bls` y registra la clave de voto (`REVISION-FV4bD` decisión 2).
/// El verificador de la prueba de almacenamiento es inerte en dev (`REVISION-PT3a` decisión 7): la
/// validez de forma, raíz y número de sectores se comprueba aquí.
pub(crate) fn aplicar_operacion_almacenamiento(
    ap: &mut Aplicador,
    op: &zx_core::OperacionAlmacenamiento,
    slot: i64,
) -> MotivoSector {
    use zx_core::OperacionAlmacenamiento;
    let p = ap.estado.parametros_sector;
    match op {
        OperacionAlmacenamiento::PoSt {
            clave,
            epoch,
            n_sectores,
            raiz_conjunto,
            ..
        } => {
            let epoch_i = i64::try_from(*epoch).unwrap_or(i64::MAX);
            if epoch_i > slot {
                return MotivoSector::ErrPlazo;
            }
            if let Some(prev) = ap.estado.pruebas.get(clave)
                && epoch_i <= prev.slot_prueba
            {
                return MotivoSector::ErrPlazo;
            }
            let r = raiz_conjunto_de(&ap.estado, clave, slot, &p);
            if r != r2_de_bytes(raiz_conjunto) {
                return MotivoSector::ErrPrueba;
            }
            let n = sectores_activos_de(&ap.estado, clave, slot, &p);
            if n == 0 || u64::from(*n_sectores) != n {
                return MotivoSector::ErrPrueba;
            }
            ap.guardar_prueba(
                *clave,
                crate::sectores::PruebaVigente {
                    slot_prueba: i64::try_from(*epoch).unwrap_or(i64::MAX),
                    raiz_conjunto: r,
                    n_sectores: *n_sectores,
                },
            );
            MotivoSector::Ok
        }
        OperacionAlmacenamiento::PoRep {
            clave,
            epoch,
            n_sectores,
            raiz_conjunto,
            ..
        } => {
            if *n_sectores == 0 {
                return MotivoSector::ErrPrueba;
            }
            let r = raiz_lote_de(&ap.estado, clave);
            if r != r2_de_bytes(raiz_conjunto) {
                return MotivoSector::ErrPrueba;
            }
            ap.guardar_porep(
                *clave,
                crate::sectores::PorepVigente {
                    slot_ventana: i64::try_from(*epoch).unwrap_or(i64::MAX),
                    raiz_lote: r,
                    n_sectores: *n_sectores,
                },
            );
            MotivoSector::Ok
        }
        OperacionAlmacenamiento::ClaveVoto {
            clave,
            clave_bls,
            prueba_posesion,
        } => {
            let Ok(bls) = zx_bls::ClavePublica::desde_bytes(clave_bls) else {
                return MotivoSector::ErrPrueba;
            };
            let Ok(firma) = zx_bls::Firma::desde_bytes(prueba_posesion) else {
                return MotivoSector::ErrPrueba;
            };
            if zx_bls::verificar_posesion(&bls, &firma).is_err() {
                return MotivoSector::ErrPrueba;
            }
            let slot_u = u64::try_from(slot).unwrap_or(0);
            // RK-2 · V2 · registrar la **misma** clave no cambia nada.
            if ap
                .estado
                .claves_voto
                .get(clave)
                .is_some_and(|cv| cv.clave_bls == *clave_bls)
            {
                return MotivoSector::Ok;
            }
            // RK-2 · V3 · no se admite una segunda rotación mientras viva la anterior.
            if ap
                .estado
                .claves_voto_previas
                .get(clave)
                .is_some_and(|prev| slot_u <= prev.vencimiento)
            {
                return MotivoSector::ErrClaveVotoRotacionViva;
            }
            // FV-4b-N4 · R-ECL-06 ampliado (RK-2 · V4): una clave BLS no puede estar registrada bajo
            // **otra** identidad Ed25519 ni ser la clave **anterior viva** de otra identidad.
            let duplicada_actual = ap
                .estado
                .claves_voto
                .iter()
                .any(|(ed, cv)| ed != clave && cv.clave_bls == *clave_bls);
            let duplicada_anterior = ap.estado.claves_voto_previas.iter().any(|(ed, prev)| {
                ed != clave && slot_u <= prev.vencimiento && prev.clave_bls == *clave_bls
            });
            if duplicada_actual || duplicada_anterior {
                return MotivoSector::ErrClaveVotoDuplicada;
            }
            // RK-2 · V2 · la clave actual pasa a ser la anterior, con vencimiento
            // `slot + retencion_clave_voto(p)`. La anterior que hubiera (vencida, por V3) se retira.
            if let Some(cv) = ap.estado.claves_voto.get(clave).copied() {
                if let Some(prev) = ap.estado.claves_voto_previas.remove(clave)
                    && let Some(mut edades) =
                        ap.estado.vencimientos_clave_voto.remove(&prev.vencimiento)
                {
                    edades.remove(clave);
                    if !edades.is_empty() {
                        ap.estado
                            .vencimientos_clave_voto
                            .insert(prev.vencimiento, edades);
                    }
                }
                let vencimiento =
                    slot_u.saturating_add(crate::transicion::votos::retencion_clave_voto(&p));
                ap.estado.claves_voto_previas.insert(
                    *clave,
                    crate::sectores::ClaveVotoAnterior {
                        clave_bls: cv.clave_bls,
                        prueba_posesion: cv.prueba_posesion,
                        vencimiento,
                    },
                );
                ap.estado
                    .vencimientos_clave_voto
                    .entry(vencimiento)
                    .or_default()
                    .insert(*clave);
            }
            ap.guardar_clave_voto(
                *clave,
                crate::sectores::ClaveVoto {
                    clave_bls: *clave_bls,
                    prueba_posesion: *prueba_posesion,
                },
            );
            MotivoSector::Ok
        }
        // PD-1b/PD-1c · el voto propio (AUS-2a), el certificado compacto, el acta y la evidencia de
        // dos votos por peso no son operaciones del autómata de sectores: las despacha `aplicar_tx`.
        // Esta rama es defensiva.
        OperacionAlmacenamiento::VotoPropio { .. }
        | OperacionAlmacenamiento::CertificadoPeso { .. }
        | OperacionAlmacenamiento::ActaPresencia { .. }
        | OperacionAlmacenamiento::EvidenciaVotosPeso { .. } => MotivoSector::ErrPrueba,
    }
}

/// Suma `delta` (≥ 0) al `activo` de la garantía con aritmética comprobada.
fn activo_sumar(g: &mut Garantia, delta: i64) -> Result<(), ErrorTransicion> {
    let v = i128::from(g.activo.brek()) + i128::from(delta);
    let b = i64::try_from(v).map_err(|_| ErrorTransicion::ErrDesbordamiento)?;
    g.activo = Amount::nuevo(b).map_err(|_| ErrorTransicion::ErrDesbordamiento)?;
    Ok(())
}

/// `C-SEC-03/07/08` · materializa maduración, caducidad y liberación de retiradas hasta `slot`.
///
/// Se invoca tras `Aplicador::promover` en cada bloque, igual que hacen `aplicar_pow`/`aplicar_post`.
///
/// # Errores
/// [`ErrorTransicion::ErrDesbordamiento`] si la devolución de una fianza desborda.
pub(crate) fn materializar_sectores(ap: &mut Aplicador, slot: i64) -> Result<(), ErrorTransicion> {
    let p = ap.estado.parametros_sector;
    let ids: Vec<SectorId> = ap.estado.sectores.keys().copied().collect();
    for id in ids {
        let Some(r) = ap.estado.sectores.get(&id).copied() else {
            continue;
        };
        match r.etapa {
            Etapa::Precomprometido
                if slot >= r.alta_slot.saturating_add(p.m_sec)
                    && (!p.exigir_prueba_almacenamiento
                        || cubierto_por_porep(&ap.estado, &r, &p)) =>
            {
                ap.tocar_sector(id);
                if let Some(rr) = ap.estado.sectores.get_mut(&id) {
                    rr.etapa = Etapa::Activo;
                }
            }
            Etapa::Activo if slot >= r.renovacion_slot.saturating_add(p.t_cad) => {
                ap.tocar_sector(id);
                if let Some(rr) = ap.estado.sectores.get_mut(&id) {
                    rr.etapa = Etapa::Caducado;
                    rr.fianza = 0;
                }
                let g = ap.garantia_mut(id.clave);
                activo_sumar(g, r.fianza)?;
            }
            Etapa::EnRetirada
                if slot >= r.retiro_slot.saturating_add(p.r_sec)
                    && slot >= r.retiro_slot.saturating_add(p.r_votos_slots) =>
            {
                // DP-7: liberar exige EV-24(i) (sin incidente abierto) **y** EV-24(ii).
                let incidentes = ap
                    .estado
                    .garantias
                    .get(&id.clave)
                    .map_or(0, |g| g.incidentes.len());
                let ultimo = ap.estado.ultimo_slot_producido.get(&id.clave).copied();
                let bloqueada_i = incidentes != 0;
                let bloqueada_ii = ultimo.is_some_and(|u| {
                    slot < i64::try_from(u)
                        .unwrap_or(i64::MAX)
                        .saturating_add(p.plazo_slots)
                        .saturating_add(p.m_margen_slots)
                });
                if bloqueada_i || bloqueada_ii {
                    continue;
                }
                ap.tocar_sector(id);
                if let Some(rr) = ap.estado.sectores.get_mut(&id) {
                    rr.etapa = Etapa::Retirado;
                    rr.fianza = 0;
                }
                let g = ap.garantia_mut(id.clave);
                activo_sumar(g, r.fianza)?;
            }
            _ => {}
        }
    }
    // SR-G2b · C-CAJA-08: la caja `EN_RETIRADA` pasa a `RETIRADA` cuando todos sus huecos son
    // terminales (los sectores ya los liberó el bucle anterior).
    caja::materializar_cajas(ap, slot)?;
    Ok(())
}

/// Aplica una operación de sector (`C-SEC-*`) al estado en curso; devuelve el motivo (`C-SEC-13`).
///
/// El llamante conserva el undo; ante un motivo distinto de `Ok`, revierte con
/// [`Aplicador::revertir_a`] (modo fusión) o invalida el bloque entero (modo estricto).
pub(crate) fn aplicar_operacion_sector(
    ap: &mut Aplicador,
    op: &OperacionSector,
    slot: i64,
) -> MotivoSector {
    let p = ap.estado.parametros_sector;
    match op {
        OperacionSector::Alta {
            clave,
            sector_index,
            version,
            r2,
            history_size,
        } => op_alta(
            ap,
            *clave,
            *sector_index,
            *version,
            r2_de_bytes(r2),
            *history_size,
            slot,
            &p,
        ),
        OperacionSector::Renovar {
            clave,
            sector_index,
        } => op_renovar(ap, *clave, *sector_index, slot, &p),
        OperacionSector::AbrirAuditoria {
            clave,
            sector_index,
            ..
        } => op_abrir_aud(ap, *clave, *sector_index, slot, &p),
        OperacionSector::ContestarAuditoria {
            clave,
            sector_index,
            prueba,
            ..
        } => op_contestar(ap, *clave, *sector_index, prueba.is_empty(), slot, &p),
        OperacionSector::Retirar {
            clave,
            sector_index,
        } => op_retirar_sector(ap, *clave, *sector_index, slot, &p),
        OperacionSector::CerrarCaja { clave, seq } => {
            caja::op_cerrar_caja(ap, *clave, *seq, slot, &p)
        }
        OperacionSector::RetirarCaja { clave, seq } => {
            caja::op_retirar_caja(ap, *clave, *seq, slot, &p)
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "la operación de alta lleva cinco campos canónicos; agruparlos ocultaría la regla"
)]
fn op_alta(
    ap: &mut Aplicador,
    clave: ClavePublica,
    sector_index: u16,
    version: u32,
    r2: [u64; 4],
    history_size: u64,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let mut vmax: i64 = -1;
    let mut prev: Option<RegistroSector> = None;
    for (id, r) in crate::sectores::sectores_de_clave(&ap.estado.sectores, &clave) {
        if id.clave == clave && id.sector_index == sector_index && i64::from(id.version) > vmax {
            vmax = i64::from(id.version);
            prev = Some(*r);
        }
    }
    if vmax < 0 {
        if version != 0 {
            return MotivoSector::ErrVersion;
        }
    } else {
        if version == u32::try_from(vmax).unwrap_or(u32::MAX) {
            return MotivoSector::ErrDobleAlta;
        }
        if version != u32::try_from(vmax.saturating_add(1)).unwrap_or(u32::MAX) {
            return MotivoSector::ErrVersion;
        }
        if prev.is_some_and(|r| !r.es_terminal()) {
            return MotivoSector::ErrDobleAlta;
        }
    }
    if history_size < p.h_min || history_size > p.h_max {
        return MotivoSector::ErrHistory;
    }
    // SR-G2b · C-CAJA-04: precondiciones de la caja antes de tocar fianza ni registro.
    let pre = caja::precondiciones_alta(&ap.estado, &clave, history_size, slot, p);
    if pre != MotivoSector::Ok {
        return pre;
    }
    {
        let g = ap.garantia_mut(clave);
        if g.activo.brek() < p.q_sec {
            return MotivoSector::ErrFianza;
        }
        let v = i128::from(g.activo.brek()) - i128::from(p.q_sec);
        match i64::try_from(v) {
            Ok(b) => match Amount::nuevo(b) {
                Ok(a) => g.activo = a,
                Err(_) => return MotivoSector::ErrDesbordamiento,
            },
            Err(_) => return MotivoSector::ErrDesbordamiento,
        }
    }
    let id = SectorId {
        clave,
        sector_index,
        version,
    };
    let reg = RegistroSector {
        id,
        r2,
        history_size,
        etapa: Etapa::Precomprometido,
        alta_slot: slot,
        renovacion_slot: slot.saturating_add(p.m_sec),
        retiro_slot: crate::sectores::NO_HAY,
        fianza: p.q_sec,
        aud_apertura: crate::sectores::NO_HAY,
        aud_contestada: crate::sectores::NO_HAY,
    };
    ap.tocar_sector(id);
    ap.estado.sectores.insert(id, reg);
    // SR-G2b · C-CAJA-03/04: la caja se abre/crece con la alta (con `capacidad_caja = 1` cada alta
    // es su propia caja, que reproduce el registro sector a sector de SR-0).
    caja::anadir_a_caja(ap, id, r2, history_size, slot, p)
}

fn op_renovar(
    ap: &mut Aplicador,
    clave: ClavePublica,
    sector_index: u16,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let Some(r) = sector_vivo(&ap.estado, &clave, sector_index) else {
        return MotivoSector::ErrNoExiste;
    };
    if estado_efectivo(&r, slot, p) != EstadoEfectivo::Activo {
        return MotivoSector::ErrEstado;
    }
    ap.tocar_sector(r.id);
    if let Some(rr) = ap.estado.sectores.get_mut(&r.id) {
        rr.renovacion_slot = slot;
    }
    MotivoSector::Ok
}

fn op_abrir_aud(
    ap: &mut Aplicador,
    clave: ClavePublica,
    sector_index: u16,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let Some(r) = sector_vivo(&ap.estado, &clave, sector_index) else {
        return MotivoSector::ErrNoExiste;
    };
    if estado_efectivo(&r, slot, p) != EstadoEfectivo::Activo {
        return MotivoSector::ErrEstado;
    }
    if r.aud_apertura >= 0 {
        return MotivoSector::ErrLimite;
    }
    ap.tocar_sector(r.id);
    if let Some(rr) = ap.estado.sectores.get_mut(&r.id) {
        rr.aud_apertura = slot;
        rr.aud_contestada = crate::sectores::NO_HAY;
    }
    MotivoSector::Ok
}

fn op_contestar(
    ap: &mut Aplicador,
    clave: ClavePublica,
    sector_index: u16,
    sin_prueba: bool,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let Some(r) = sector_vivo(&ap.estado, &clave, sector_index) else {
        return MotivoSector::ErrNoExiste;
    };
    if r.aud_apertura < 0 || r.aud_contestada >= 0 {
        return MotivoSector::ErrAuditoria;
    }
    let ee = estado_efectivo(&r, slot, p);
    if !matches!(ee, EstadoEfectivo::Activo | EstadoEfectivo::Suspendido) {
        return MotivoSector::ErrEstado;
    }
    if slot < r.aud_apertura
        || slot
            >= r.aud_apertura
                .saturating_add(p.p_aud)
                .saturating_add(p.p_rec)
    {
        return MotivoSector::ErrPlazo;
    }
    if sin_prueba {
        return MotivoSector::ErrPrueba;
    }
    ap.tocar_sector(r.id);
    if let Some(rr) = ap.estado.sectores.get_mut(&r.id) {
        rr.aud_contestada = slot;
    }
    MotivoSector::Ok
}

fn op_retirar_sector(
    ap: &mut Aplicador,
    clave: ClavePublica,
    sector_index: u16,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let Some(r) = sector_vivo(&ap.estado, &clave, sector_index) else {
        return MotivoSector::ErrNoExiste;
    };
    // SR-G2b · C-CAJA-08: con `capacidad_caja > 1` el retiro es de la **caja entera**; el hueco
    // suelto se rechaza (K-10). Con capacidad 1 se conserva el camino de SR-0.
    if p.capacidad_caja > 1 {
        return MotivoSector::ErrEstado;
    }
    let ee = estado_efectivo(&r, slot, p);
    if !matches!(ee, EstadoEfectivo::Activo | EstadoEfectivo::Suspendido) {
        return MotivoSector::ErrEstado;
    }
    ap.tocar_sector(r.id);
    if let Some(rr) = ap.estado.sectores.get_mut(&r.id) {
        rr.etapa = Etapa::EnRetirada;
        rr.retiro_slot = slot;
    }
    MotivoSector::Ok
}

/// Resultado de aplicar una operación de sector suelta con su undo.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResultadoOperacionSector {
    /// Undo por delta de la operación (revierte con [`crate::transicion::deshacer`]).
    pub undo: Undo,
    /// Motivo devuelto por el autómata (`C-SEC-13`).
    pub motivo: MotivoSector,
}

/// Aplica **una** operación de sector sobre el estado real y devuelve el undo por delta.
///
/// Si `motivo != Ok`, el estado devuelto puede tener mutaciones parciales: el llamante las revierte
/// con [`crate::transicion::deshacer`] y el `undo` recibido.
#[must_use]
pub fn aplicar_operacion_con_undo(
    estado: &Estado,
    op: &OperacionSector,
    slot: i64,
    params: &ParametrosSector,
) -> (Estado, ResultadoOperacionSector) {
    let mut ap = Aplicador::nuevo(estado.clone());
    ap.estado.parametros_sector = *params;
    let motivo = aplicar_operacion_sector(&mut ap, op, slot);
    (
        ap.estado,
        ResultadoOperacionSector {
            undo: ap.undo,
            motivo,
        },
    )
}

/// Materializa el ciclo de vida de los sectores hasta `slot` y devuelve el undo por delta.
#[must_use]
pub fn materializar_con_undo(
    estado: &Estado,
    slot: i64,
    params: &ParametrosSector,
) -> (Estado, Undo) {
    let mut ap = Aplicador::nuevo(estado.clone());
    ap.estado.parametros_sector = *params;
    let _ = materializar_sectores(&mut ap, slot);
    (ap.estado, ap.undo)
}

/// PT-3bc · aplica **una** operación de almacenamiento v6 sobre el estado real con su undo.
///
/// Si el motivo no es `Ok`, el llamante revierte con [`crate::transicion::deshacer`] y el `undo`.
#[must_use]
pub fn aplicar_almacenamiento_con_undo(
    estado: &Estado,
    op: &zx_core::OperacionAlmacenamiento,
    slot: i64,
    params: &ParametrosSector,
) -> (Estado, Undo, MotivoSector) {
    let mut ap = Aplicador::nuevo(estado.clone());
    ap.estado.parametros_sector = *params;
    let motivo = aplicar_operacion_almacenamiento(&mut ap, op, slot);
    (ap.estado, ap.undo, motivo)
}

/// PT-3bc · `FuentePeso` por clave con la puerta de prueba (`C-SEC-15`).
#[must_use]
pub fn fuente_peso_de(est: &Estado, clave: &ClavePublica, slot: i64, p: &ParametrosSector) -> i64 {
    let mut n = 0i64;
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
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

/// TB-0 · `FuentePeso` **por clave** en un solo recorrido de `est.sectores` (IPA B-67).
///
/// Acumula, por cada clave con sectores que pesan, el número de sectores que cumplen las mismas
/// cinco condiciones que [`fuente_peso_de`]: no terminales, `fianza == q_sec`, `Activo` en `slot` y
/// con prueba vigente cuando `p.exigir_prueba_almacenamiento`. Para toda clave `c`,
/// `pesos_por_clave(est, slot, p).get(c).copied().unwrap_or(0)` coincide con
/// `fuente_peso_de(est, c, slot, p)`.
///
/// `tabla_canonica` y `construir_tabla` la usan para no recorrer todos los sectores por cada clave
/// de voto. `fuente_peso_de` se conserva con su firma como oráculo del diferencial.
#[must_use]
pub fn pesos_por_clave(
    est: &Estado,
    slot: i64,
    p: &ParametrosSector,
) -> BTreeMap<ClavePublica, i64> {
    let mut pesos: BTreeMap<ClavePublica, i64> = BTreeMap::new();
    for (id, r) in &est.sectores {
        if !r.es_terminal()
            && r.fianza == p.q_sec
            && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo
            && (!p.exigir_prueba_almacenamiento || prueba_vigente(est, &id.clave, slot, p))
        {
            let contador = pesos.entry(id.clave).or_insert(0);
            *contador = contador.saturating_add(1);
        }
    }
    pesos
}

/// Resultado de aplicar un bloque del autómata de sectores sobre el estado real.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResultadoBloqueSector {
    /// Undo por delta del bloque completo.
    pub undo: Undo,
    /// Operaciones descartadas con su motivo (`C-SEC-13`).
    pub descartadas: Vec<MotivoSector>,
    /// ¿Fue admitido el bloque?
    pub valido: bool,
    /// ¿La solución PoAS del bloque era elegible (`C-SEC-12`)?
    pub elegible: bool,
}

/// Aplica un bloque del autómata de sectores sobre el `Estado` **real**, con su undo.
///
/// Es la entrada que usa el diferencial V2 (`ORDEN-SR1-2` §2): muta [`Estado::sectores`] y las
/// garantías del mismo estado que el motor PoW→PoST, y devuelve el [`Undo`] de
/// `crate::transicion::deshacer`. `sol = None` modela un bloque sin requisito de sector.
#[must_use]
pub fn aplicar_bloque_sector(
    estado: &Estado,
    ops: &[OperacionSector],
    productor: ClavePublica,
    sol: Option<&Solucion>,
    slot: i64,
    params: &ParametrosSector,
) -> (Estado, ResultadoBloqueSector) {
    let mut ap = Aplicador::nuevo(estado.clone());
    // Fija los parámetros del perfil de este bloque (el arnés puede usar el fixture de SR-0).
    ap.estado.parametros_sector = *params;
    let _ = materializar_sectores(&mut ap, slot);
    let mut valido = true;
    let mut eleg = true;
    if let Some(sol) = sol {
        eleg = elegible_sector(
            &ap.estado,
            &sol.clave,
            sol.sector_index,
            sol.history_size,
            slot,
            params,
        );
        if eleg {
            let slot_u = u64::try_from(slot).unwrap_or(0);
            let prev = ap.estado.ultimo_slot_producido.get(&sol.clave).copied();
            if prev.is_none_or(|p| slot_u > p) {
                ap.estado.ultimo_slot_producido.insert(sol.clave, slot_u);
            }
        } else {
            valido = false;
        }
    }
    if valido && ops.len() > params.max_ops_bloque {
        valido = false;
    }
    let mut descartadas = Vec::new();
    if valido {
        for op in ops {
            let m = ap.marcar();
            let r = aplicar_operacion_sector(&mut ap, op, slot);
            if r != MotivoSector::Ok {
                ap.revertir_a(m);
                descartadas.push(r);
            }
        }
    }
    let _ = productor;
    (
        ap.estado,
        ResultadoBloqueSector {
            undo: ap.undo,
            descartadas,
            valido,
            elegible: eleg,
        },
    )
}

#[cfg(test)]
#[path = "../../tests/soporte/secr1/internas.rs"]
mod secr1_internas;
