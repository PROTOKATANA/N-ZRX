//! `SR-G2b` · aplicación de las cajas de sectores (`C-CAJA-*`) sobre el [`Estado`] real.
//!
//! `crate::cajas` tiene los tipos canónicos y el árbol Merkle; aquí vive la mutación con undo por
//! delta de [`crate::transicion::Aplicador`]: abrir/añadir ([`anadir_a_caja`]), cerrar
//! ([`op_cerrar_caja`]), retirar en bloque ([`op_retirar_caja`]) y materializar el ciclo de vida
//! ([`materializar_cajas`]).
//!
//! La caja es una **capa de agrupación** sobre `Estado::sectores` (D-2 declarado en `PROGRESO.md`
//! §1): guarda la raíz Merkle, `n`, `ocupacion`, `estado_hueco`, timers y fianza, y un índice
//! compacto `huecos[j] = (sector_index, version)`. Las hojas `R2` se reconstruyen desde el registro
//! por sector, de modo que el autómata `C-SEC-*` de SR-1-2 sigue siendo la única fuente del ciclo de
//! vida de cada sector.

#![expect(
    clippy::indexing_slicing,
    reason = "índices de hueco 1-based acotados por `n ≤ capacidad_caja`; el rango lo fija el autómata"
)]

use zx_core::ClavePublica;

use crate::cajas::{
    CAPACIDAD_MAX, CajaId, EstadoHueco, EtapaCaja, Ocupante, RegistroCaja, hoja_libre,
    hoja_ocupada, raiz_merkle,
};
use crate::sectores::{
    EstadoEfectivo, MotivoSector, ParametrosSector, R2, SectorId, estado_efectivo,
};
use crate::transicion::ErrorTransicion;
use crate::transicion::estado::Aplicador;
use crate::transicion::tipos::Estado;

/// Capacidad efectiva de la caja (acota el índice de `CAPACIDAD_MAX` huecos).
#[must_use]
pub fn capacidad(p: &ParametrosSector) -> usize {
    p.capacidad_caja.clamp(1, CAPACIDAD_MAX)
}

/// Caja `ABIERTA` de una clave, si la hay (`I-CAJA-1`).
#[must_use]
pub fn caja_abierta(est: &Estado, clave: &ClavePublica) -> Option<CajaId> {
    crate::cajas::cajas_de_clave(&est.cajas, clave)
        .map(|(_, c)| c)
        .find(|c| c.id.clave == *clave && c.etapa == EtapaCaja::Abierta)
        .map(|c| c.id)
}

/// Siguiente `seq` del contador por clave (`C-CAJA-01`).
#[must_use]
pub fn siguiente_seq(est: &Estado, clave: &ClavePublica) -> u32 {
    crate::cajas::cajas_de_clave(&est.cajas, clave)
        .map(|(id, _)| id)
        .filter(|id| id.clave == *clave)
        .map(|id| id.seq)
        .max()
        .map_or(1, |m| m.saturating_add(1))
}

/// Localiza el `(caja, hueco 1-based)` de un sector, si está en alguna caja (`C-CAJA-12`).
#[must_use]
pub fn caja_de_sector(est: &Estado, sid: &SectorId) -> Option<(CajaId, usize)> {
    for c in crate::cajas::cajas_de_clave(&est.cajas, &sid.clave).map(|(_, c)| c) {
        if c.id.clave != sid.clave {
            continue;
        }
        for (i, o) in c.huecos.iter().enumerate() {
            if o.ocupado && o.sector_index == sid.sector_index && o.version == sid.version {
                return Some((c.id, i + 1));
            }
        }
    }
    None
}

/// `SectorId` del hueco `j` (1-based) de una caja.
#[must_use]
pub fn sector_del_hueco(c: &RegistroCaja, j: usize) -> Option<SectorId> {
    let o = c.huecos.get(j.checked_sub(1)?)?;
    o.ocupado.then_some(SectorId {
        clave: c.id.clave,
        sector_index: o.sector_index,
        version: o.version,
    })
}

/// `R2` de un hueco ocupado, leído del registro por sector.
#[must_use]
pub fn r2_de_hueco(est: &Estado, c: &RegistroCaja, j: usize) -> Option<R2> {
    let sid = sector_del_hueco(c, j)?;
    est.sectores.get(&sid).map(|r| r.r2)
}

/// Raíz Merkle de una caja reconstruida desde el estado (`I-CAJA-4`).
#[must_use]
pub fn raiz_de_caja(est: &Estado, c: &RegistroCaja) -> R2 {
    let cap = c.huecos.len();
    let mut hojas = Vec::with_capacity(cap);
    for j in 1..=cap {
        match r2_de_hueco(est, c, j) {
            Some(r2) => hojas.push(hoja_ocupada(r2)),
            None => hojas.push(hoja_libre()),
        }
    }
    raiz_merkle(&hojas)
}

/// Código de 2 bits del estado efectivo de un sector.
#[must_use]
const fn codigo_estado(ee: EstadoEfectivo) -> u32 {
    match ee {
        EstadoEfectivo::Precomprometido => EstadoHueco::Comprometido.codigo(),
        EstadoEfectivo::Activo => EstadoHueco::Activo.codigo(),
        EstadoEfectivo::Suspendido => EstadoHueco::Suspendido.codigo(),
        EstadoEfectivo::EnRetirada | EstadoEfectivo::Retirado | EstadoEfectivo::Caducado => {
            EstadoHueco::Comprometido.codigo()
        }
    }
}

/// Estado efectivo del hueco `j` (1-based) en `slot` (`C-CAJA-06/09`).
#[must_use]
pub fn estado_hueco(
    est: &Estado,
    c: &RegistroCaja,
    j: usize,
    slot: i64,
    p: &ParametrosSector,
) -> Option<EstadoEfectivo> {
    let sid = sector_del_hueco(c, j)?;
    let r = est.sectores.get(&sid)?;
    Some(estado_efectivo(r, slot, p))
}

/// Fianza comprometida por los huecos no terminales de la caja (`C-CAJA-10`).
#[must_use]
pub fn fianza_caja(est: &Estado, c: &RegistroCaja) -> i64 {
    let mut t = 0i64;
    for j in 1..=c.huecos.len() {
        if let Some(sid) = sector_del_hueco(c, j)
            && let Some(r) = est.sectores.get(&sid)
            && !r.es_terminal()
        {
            t = t.saturating_add(r.fianza);
        }
    }
    t
}

/// Refresca la caché (`estado_hueco`, `fianza`) de una caja desde el registro por sector.
fn refrescar_cache(est: &Estado, c: &mut RegistroCaja, slot: i64, p: &ParametrosSector) {
    let mut mascara = 0u32;
    for j in 1..=c.huecos.len() {
        let code = match estado_hueco(est, c, j, slot, p) {
            Some(ee) => codigo_estado(ee),
            None if c.huecos[j - 1].ocupado => EstadoHueco::Comprometido.codigo(),
            None => EstadoHueco::Libre.codigo(),
        };
        mascara = EstadoHueco::poner(mascara, j - 1, code);
    }
    c.estado_hueco = mascara;
    c.fianza = fianza_caja(est, c);
}

/// Wrapper **interno** (no API pública) para que el débito de penas sobre la fianza refresque la
/// caché (`estado_hueco`, `fianza`) de una caja afectada, con undo por delta (`C-CAJA-10`).
pub(crate) fn refrescar_caja(ap: &mut Aplicador, id: CajaId, slot: i64) {
    let Some(c) = ap.estado.cajas.get(&id).cloned() else {
        return;
    };
    let mut nuevo = c;
    refrescar_cache(&ap.estado, &mut nuevo, slot, &ap.estado.parametros_sector);
    if nuevo != ap.estado.cajas[&id] {
        ap.tocar_caja(id);
        ap.estado.cajas.insert(id, nuevo);
    }
}

/// `C-CAJA-04` · precondiciones de un alta evaluadas **antes** de mutar el estado.
///
/// Evita que un rechazo en modo estricto deje mutaciones parciales (la fianza o el registro del
/// sector ya escritos).
pub(crate) fn precondiciones_alta(
    est: &Estado,
    clave: &ClavePublica,
    history_size: u64,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let cap = capacidad(p);
    match caja_abierta(est, clave) {
        Some(id) => {
            let Some(c) = est.cajas.get(&id) else {
                return MotivoSector::ErrEstado;
            };
            if usize::from(c.n) >= cap {
                return MotivoSector::ErrEstado;
            }
            if c.history_size != history_size {
                return MotivoSector::ErrHistory;
            }
            if c.n > 0 && slot < c.ultima_alta_slot.saturating_add(p.m_sec) {
                return MotivoSector::ErrMaduracion;
            }
            MotivoSector::Ok
        }
        None => MotivoSector::Ok,
    }
}

/// `C-CAJA-04` · añade el sector `sid` (ya insertado en `Estado::sectores`) a la caja abierta de su
/// clave, abriéndola si no existe. Aplica la regla de madurez del orquestador.
pub(crate) fn anadir_a_caja(
    ap: &mut Aplicador,
    sid: SectorId,
    r2: R2,
    history_size: u64,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let cap = capacidad(p);
    let id = match caja_abierta(&ap.estado, &sid.clave) {
        Some(id) => id,
        None => {
            let id = CajaId {
                clave: sid.clave,
                seq: siguiente_seq(&ap.estado, &sid.clave),
            };
            ap.tocar_caja(id);
            ap.estado
                .cajas
                .insert(id, RegistroCaja::nueva(id, history_size, slot));
            id
        }
    };
    let Some(c) = ap.estado.cajas.get(&id).cloned() else {
        return MotivoSector::ErrEstado;
    };
    if usize::from(c.n) >= cap {
        return MotivoSector::ErrEstado;
    }
    if c.history_size != history_size {
        return MotivoSector::ErrHistory;
    }
    // Decisión 1 del orquestador: el hueco anterior debe haber madurado.
    if c.n > 0 && slot < c.ultima_alta_slot.saturating_add(p.m_sec) {
        return MotivoSector::ErrMaduracion;
    }
    let j = usize::from(c.n) + 1;
    let mut nuevo = c;
    nuevo.huecos[j - 1] = Ocupante {
        sector_index: sid.sector_index,
        version: sid.version,
        ocupado: true,
    };
    nuevo.ocupacion |= 1u16 << (j - 1);
    nuevo.n += 1;
    nuevo.ultima_alta_slot = slot;
    nuevo.renovacion_slot = slot.saturating_add(p.m_sec);
    nuevo.raiz = raiz_de_caja(&ap.estado, &nuevo);
    let _ = r2;
    refrescar_cache(&ap.estado, &mut nuevo, slot, p);
    if usize::from(nuevo.n) == cap {
        nuevo.etapa = EtapaCaja::Cerrada;
        nuevo.cierre_slot = slot;
    }
    ap.tocar_caja(id);
    ap.estado.cajas.insert(id, nuevo);
    MotivoSector::Ok
}

/// `C-CAJA-05` · cierre explícito de la caja abierta (la última puede quedar incompleta).
pub(crate) fn op_cerrar_caja(
    ap: &mut Aplicador,
    clave: ClavePublica,
    _seq: u32,
    slot: i64,
    _p: &ParametrosSector,
) -> MotivoSector {
    let Some(id) = caja_abierta(&ap.estado, &clave) else {
        return MotivoSector::ErrNoExiste;
    };
    let c = ap
        .estado
        .cajas
        .get(&id)
        .cloned()
        .unwrap_or_else(|| RegistroCaja::nueva(id, 0, slot));
    if c.n == 0 {
        return MotivoSector::ErrEstado;
    }
    let mut nuevo = c;
    nuevo.etapa = EtapaCaja::Cerrada;
    nuevo.cierre_slot = slot;
    ap.tocar_caja(id);
    ap.estado.cajas.insert(id, nuevo);
    MotivoSector::Ok
}

/// `C-CAJA-08` · retiro atómico de la caja entera (`EV-24(i)+(ii)` se materializa después).
pub(crate) fn op_retirar_caja(
    ap: &mut Aplicador,
    clave: ClavePublica,
    seq: u32,
    slot: i64,
    p: &ParametrosSector,
) -> MotivoSector {
    let id = CajaId { clave, seq };
    let Some(c) = ap.estado.cajas.get(&id).cloned() else {
        return MotivoSector::ErrNoExiste;
    };
    if c.etapa != EtapaCaja::Cerrada || c.n == 0 {
        return MotivoSector::ErrEstado;
    }
    // Todos los huecos deben ser activos o suspendidos.
    for j in 1..=usize::from(c.n) {
        match estado_hueco(&ap.estado, &c, j, slot, p) {
            Some(EstadoEfectivo::Activo | EstadoEfectivo::Suspendido) => {}
            _ => return MotivoSector::ErrEstado,
        }
    }
    let mut nuevo = c;
    nuevo.etapa = EtapaCaja::EnRetirada;
    nuevo.retiro_slot = slot;
    // Los huecos pasan a `en_retirada` (no elegibles) y se les fija el slot de retiro.
    for j in 1..=usize::from(nuevo.n) {
        let Some(sid) = sector_del_hueco(&nuevo, j) else {
            continue;
        };
        ap.tocar_sector(sid);
        if let Some(r) = ap.estado.sectores.get_mut(&sid) {
            r.etapa = crate::sectores::Etapa::EnRetirada;
            r.retiro_slot = slot;
        }
    }
    refrescar_cache(&ap.estado, &mut nuevo, slot, p);
    ap.tocar_caja(id);
    ap.estado.cajas.insert(id, nuevo);
    MotivoSector::Ok
}

/// Materializa el ciclo de vida de las cajas hasta `slot` (`C-CAJA-08`).
///
/// Los sectores ya los libera [`crate::transicion::sector::materializar_sectores`]; aquí una caja
/// `EN_RETIRADA` pasa a `RETIRADA` cuando **todos** sus huecos son terminales.
pub(crate) fn materializar_cajas(ap: &mut Aplicador, slot: i64) -> Result<(), ErrorTransicion> {
    let p = ap.estado.parametros_sector;
    let ids: Vec<CajaId> = ap.estado.cajas.keys().copied().collect();
    for id in ids {
        let Some(c) = ap.estado.cajas.get(&id).cloned() else {
            continue;
        };
        let mut nuevo = c;
        refrescar_cache(&ap.estado, &mut nuevo, slot, &p);
        if nuevo.etapa == EtapaCaja::EnRetirada {
            let todos = (1..=usize::from(nuevo.n)).all(|j| {
                sector_del_hueco(&nuevo, j)
                    .and_then(|sid| ap.estado.sectores.get(&sid))
                    .is_some_and(crate::sectores::RegistroSector::es_terminal)
            });
            if todos {
                nuevo.etapa = EtapaCaja::Retirada;
            }
        }
        if nuevo != ap.estado.cajas[&id] {
            ap.tocar_caja(id);
            ap.estado.cajas.insert(id, nuevo);
        }
    }
    Ok(())
}

/// `C-CAJA-12` · consulta `(caja, hueco, raíz)` de un sector.
#[must_use]
pub fn consulta_caja(est: &Estado, sid: &SectorId) -> Option<(CajaId, usize, R2)> {
    let (id, j) = caja_de_sector(est, sid)?;
    let c = est.cajas.get(&id)?;
    Some((id, j, c.raiz))
}

/// Invariantes `I-CAJA-1…5` (`C-CAJA-02/03/10`).
#[must_use]
pub fn invariante_caja(est: &Estado, p: &ParametrosSector) -> bool {
    let cap = capacidad(p);
    let mut abiertas: Vec<ClavePublica> = Vec::new();
    let mut vistos: std::collections::BTreeSet<SectorId> = std::collections::BTreeSet::new();
    for c in est.cajas.values() {
        if c.n > u8::try_from(cap).unwrap_or(u8::MAX) {
            return false;
        }
        if u32::from(c.ocupacion).count_ones() != u32::from(c.n) {
            return false;
        }
        for (i, o) in c.huecos.iter().enumerate() {
            let ocupado_bit = (c.ocupacion >> i) & 1 == 1;
            if ocupado_bit != o.ocupado {
                return false;
            }
            if !o.ocupado {
                continue;
            }
            let sid = SectorId {
                clave: c.id.clave,
                sector_index: o.sector_index,
                version: o.version,
            };
            if !vistos.insert(sid) {
                return false;
            }
            let Some(r) = est.sectores.get(&sid) else {
                return false;
            };
            if r.history_size != c.history_size {
                return false;
            }
        }
        if raiz_de_caja(est, c) != c.raiz {
            return false;
        }
        if c.etapa == EtapaCaja::Abierta {
            if abiertas.contains(&c.id.clave) {
                return false;
            }
            abiertas.push(c.id.clave);
            if usize::from(c.n) >= cap {
                return false;
            }
        }
        if fianza_caja(est, c) != c.fianza {
            return false;
        }
    }
    true
}

/// ¿Todo sector no terminal está en exactamente una caja? (agrupación obligatoria, `PK-14`).
#[must_use]
pub fn todos_en_caja(est: &Estado) -> bool {
    for (id, r) in &est.sectores {
        if r.es_terminal() {
            continue;
        }
        if caja_de_sector(est, id).is_none() {
            return false;
        }
    }
    true
}
