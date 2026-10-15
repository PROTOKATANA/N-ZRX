//! PROD-3a · **cálculo único** de la admisión PoST sobre una vista de solo lectura.
//!
//! El cuerpo del cálculo que antes vivía en `Cadena::admitir_post` (colores y conjunto de fusión
//! reales, `Estado(past(B))`, garantía, contexto y hechos, transición de fusión y suma del peso) se
//! escribe **una sola vez** aquí, sobre el trait privado [`FuentePost`]:
//!
//! - la **admisión** lo invoca con `&Cadena` (tras insertar el bloque en el DAG real) y después
//!   escribe `past`/`post`/`descartes`/`post_terminal`/`finalidad_pasado`;
//! - el **ensayo** lo invoca con [`VistaPost`], que superpone el `DagTerminal` del terminal (con la
//!   candidata añadida) y la propia candidata en la consulta por `hash`, sin copiar la cadena ni sus
//!   mapas.
//!
//! Nada de este módulo es API pública: es hijo de `cadena` para poder leer sus campos privados sin
//! hacer público ningún campo ni función (`D6` de `ORDEN-PROD3A.md`).

use zx_consensus::transicion::votos::{ESPERA_REARRANQUE_SLOTS, cierre_ventana};
use zx_consensus::transicion::{
    Estado, HechoVoto, ParametrosEvidencia, ParametrosTransicion, Punto, TxDescartada, Undo,
    aplicar_fusion,
};
use zx_core::{BlockHash, Tx};
use zx_dag::ghostdag::{Color, Idx};

use super::{Cadena, ContextoAplicacion, DagTerminal, MAX_TERMINALES_CON_DAG};
use crate::bloque::{BloqueCadena, BloquePost};
use crate::error::MotivoBloque;

/// Acceso de solo lectura a lo que el cálculo de admisión PoST consulta de una cadena.
///
/// Lo implementan `&Cadena` (admisión real) y [`VistaPost`] (ensayo con superposición). Todas las
/// consultas son de solo lectura; el único estado propio de la vista es el `DagTerminal` superpuesto,
/// que el llamante ya dejó con la candidata añadida.
pub(super) trait FuentePost {
    /// Parámetros de transición vigentes.
    fn params(&self) -> &ParametrosTransicion;
    /// Parámetros de evidencia vigentes.
    fn evidencia(&self) -> &ParametrosEvidencia;
    /// `CBID` de la red.
    fn cbid(&self) -> u32;
    /// `DagTerminal` de `terminal` (con la candidata añadida en el ensayo).
    fn dag(&self, terminal: BlockHash) -> Option<&DagTerminal>;
    /// Bloque por `hash` (con la candidata superpuesta en el ensayo).
    fn por_hash(&self, hash: &BlockHash) -> Option<&BloqueCadena>;
    /// `Estado(post)` de `hash`.
    fn post(&self, hash: &BlockHash) -> Option<&Estado>;
    /// `(finalidad_votos_n, finalidad_votos)` del pasado de `hash`.
    fn finalidad_pasado(&self, hash: &BlockHash) -> Option<(u64, Option<BlockHash>)>;
    /// Cuenta una visita de los recorridos del hecho (no-op en producción; en pruebas incrementa el
    /// contador de la cadena).
    fn visita(&self);
}

impl FuentePost for Cadena {
    fn params(&self) -> &ParametrosTransicion {
        &self.params
    }

    fn evidencia(&self) -> &ParametrosEvidencia {
        &self.evidencia
    }

    fn cbid(&self) -> u32 {
        self.cbid
    }

    fn dag(&self, terminal: BlockHash) -> Option<&DagTerminal> {
        self.dags.get(&terminal)
    }

    fn por_hash(&self, hash: &BlockHash) -> Option<&BloqueCadena> {
        self.por_hash.get(hash)
    }

    fn post(&self, hash: &BlockHash) -> Option<&Estado> {
        self.post.get(hash)
    }

    fn finalidad_pasado(&self, hash: &BlockHash) -> Option<(u64, Option<BlockHash>)> {
        self.finalidad_pasado.get(hash).copied()
    }

    fn visita(&self) {
        Self::visita(self);
    }
}

/// Vista de ensayo: la cadena tal cual más el `DagTerminal` del terminal (con la candidata ya
/// añadida) y la propia candidata allí donde el cálculo la busca por su `hash`.
pub(super) struct VistaPost<'a> {
    cadena: &'a Cadena,
    terminal: BlockHash,
    /// Copia del DAG del terminal con la candidata añadida (o uno nuevo vacío si no existía).
    dag: DagTerminal,
    /// La candidata, para que `por_hash(hash)` la devuelva (el bloque firmado no está en la cadena).
    bloque: BloqueCadena,
}

impl<'a> VistaPost<'a> {
    /// Construye la vista con el DAG superpuesto ya preparado y la candidata.
    pub(super) fn nueva(
        cadena: &'a Cadena,
        terminal: BlockHash,
        dag: DagTerminal,
        bloque: BloqueCadena,
    ) -> Self {
        Self {
            cadena,
            terminal,
            dag,
            bloque,
        }
    }

    /// La candidata superpuesta.
    pub(super) fn bloque(&self) -> &BloqueCadena {
        &self.bloque
    }
}

impl FuentePost for VistaPost<'_> {
    fn params(&self) -> &ParametrosTransicion {
        &self.cadena.params
    }

    fn evidencia(&self) -> &ParametrosEvidencia {
        &self.cadena.evidencia
    }

    fn cbid(&self) -> u32 {
        self.cadena.cbid
    }

    fn dag(&self, terminal: BlockHash) -> Option<&DagTerminal> {
        if terminal == self.terminal {
            return Some(&self.dag);
        }
        self.cadena.dags.get(&terminal)
    }

    fn por_hash(&self, hash: &BlockHash) -> Option<&BloqueCadena> {
        if self.bloque.hash() == *hash {
            return Some(&self.bloque);
        }
        self.cadena.por_hash.get(hash)
    }

    fn post(&self, hash: &BlockHash) -> Option<&Estado> {
        self.cadena.post.get(hash)
    }

    fn finalidad_pasado(&self, hash: &BlockHash) -> Option<(u64, Option<BlockHash>)> {
        self.cadena.finalidad_pasado.get(hash).copied()
    }

    fn visita(&self) {
        self.cadena.visita();
    }
}

/// Resultado de aplicar el tope de terminales al pedir el DAG de un terminal nuevo.
pub(super) enum TopeDag {
    /// Hay cupo: el `DagTerminal` se crea.
    Cabe,
    /// No hay cupo y el terminal supera al peor: hay que desalojar `peor`.
    Desaloja(BlockHash),
    /// No hay cupo y el terminal no supera al peor: `ErrLimiteTerminales`.
    NoCabe,
}

/// Decide el tope de terminales **sin mutar nada** (lo comparten `dag_de_terminal_mut` y el ensayo).
pub(super) fn decidir_tope(cadena: &Cadena, terminal: BlockHash) -> TopeDag {
    if cadena.dags.len() < MAX_TERMINALES_CON_DAG {
        return TopeDag::Cabe;
    }
    let Some(peor) = cadena.dags.keys().copied().min_by(|a, b| {
        cadena
            .trabajo_de(a)
            .cmp(&cadena.trabajo_de(b))
            .then_with(|| b.cmp(a))
    }) else {
        // Inalcanzable: `cadena.dags.len() >= MAX_TERMINALES_CON_DAG > 0` garantiza al
        // menos una clave. Defensivo, no un pánico: se trata como el mismo rechazo que
        // el resto de esta función ante un estado interno inesperado.
        return TopeDag::NoCabe;
    };
    if cadena.trabajo_de(&terminal) <= cadena.trabajo_de(&peor) {
        TopeDag::NoCabe
    } else {
        TopeDag::Desaloja(peor)
    }
}

/// Añade la candidata a un `DagTerminal` (implementación única para admisión y ensayo).
pub(super) fn anadir_al_dag(dt: &mut DagTerminal, p: &BloquePost) -> Result<Idx, MotivoBloque> {
    let idx = dt
        .dag
        .anadir_sintetico(super::bloque_ghostdag(
            p.hash,
            &p.padres,
            p.slot,
            p.distancia,
            p.sr,
            p.identidad,
        ))
        .map_err(|e| super::mapear_error_dag(&e))?;
    dt.dag_idx.insert(p.hash, idx);
    dt.dag_orden.push(p.hash);
    Ok(idx)
}

/// Prepara el `DagTerminal` superpuesto del ensayo: copia el del terminal si existe o crea uno nuevo
/// vacío; aplica el tope de terminales **sin** tocar `limite_alcanzado` ni `desalojo_reciente`.
pub(super) fn dag_para_ensayo(
    cadena: &Cadena,
    terminal: BlockHash,
) -> Result<DagTerminal, MotivoBloque> {
    if let Some(existente) = cadena.dags.get(&terminal) {
        return Ok(existente.clone());
    }
    if let TopeDag::NoCabe = decidir_tope(cadena, terminal) {
        return Err(MotivoBloque::ErrLimiteTerminales);
    }
    Ok(DagTerminal::nueva(terminal, cadena.k, cadena.max_padres))
}

/// Traduce un índice denso del DAG de `terminal` al `block_hash`.
pub(super) fn hash_de_idx<F: FuentePost>(
    f: &F,
    terminal: BlockHash,
    idx: Idx,
) -> Option<BlockHash> {
    if idx == 0 {
        return Some(terminal);
    }
    let dt = f.dag(terminal)?;
    let pos = (idx as usize).checked_sub(1)?;
    dt.dag_orden.get(pos).copied()
}

/// Contexto de aplicación de `x` dentro del bloque de índice `idx` del DAG de `terminal`.
pub(super) fn contexto_real<F: FuentePost>(
    f: &F,
    terminal: BlockHash,
    idx: Idx,
) -> Option<ContextoAplicacion> {
    let dt = f.dag(terminal)?;
    let gd = dt.dag.datos(idx)?;
    let mergeset = gd
        .orden_mergeset
        .iter()
        .filter(|m| dt.dag.color_en(idx, **m) != Some(Color::RojoU3))
        .copied()
        .collect();
    let sp = gd.sp?;
    let hash = hash_de_idx(f, terminal, idx)?;
    let slot_g = f.por_hash(&hash).and_then(BloqueCadena::slot)?;
    Some(ContextoAplicacion {
        terminal,
        g_idx: Some(idx),
        mergeset,
        sp,
        slot_g,
    })
}

/// AT-1b · W2 · `true` si `b_hash` está «aplicado antes que `x_hash`» en la aplicación de
/// `x_hash` dentro de `g` (o del virtual). Definición de la orden: se recorre la cadena de
/// padres seleccionados desde `g` hacia atrás **mientras** `slot(bloque de cadena) ≥ slot(B)`;
/// cuenta `B` como bloque de cadena anterior a `g`, en el conjunto de fusión (sin `RojoU3`) de un
/// bloque anterior a `g`, o en el de `g` **antes** que `x`.
pub(super) fn aplicado_antes_que<F: FuentePost>(
    f: &F,
    ctx: &ContextoAplicacion,
    x_hash: BlockHash,
    b_hash: BlockHash,
) -> bool {
    let Some(dt) = f.dag(ctx.terminal) else {
        return false;
    };
    let (Some(&b_idx), Some(&x_idx)) = (dt.dag_idx.get(&b_hash), dt.dag_idx.get(&x_hash)) else {
        return false;
    };
    let Some(b_slot) = f.por_hash(&b_hash).and_then(BloqueCadena::slot) else {
        return false;
    };
    if ctx.slot_g < b_slot {
        return false;
    }
    // Conjunto de fusión de `g`: solo las entradas anteriores a `x` (si `x` está en él).
    for &m in &ctx.mergeset {
        if m == x_idx {
            break;
        }
        f.visita();
        if m == b_idx {
            return true;
        }
    }
    // Bloques de cadena anteriores a `g`, retrocediendo por el padre seleccionado.
    let mut cur_idx = match ctx.g_idx {
        Some(gi) => match dt.dag.datos(gi).and_then(|d| d.sp) {
            Some(sp) => sp,
            None => return false,
        },
        None => ctx.sp,
    };
    loop {
        f.visita();
        if cur_idx == b_idx {
            return true;
        }
        let Some(cur_slot) = hash_de_idx(f, ctx.terminal, cur_idx)
            .and_then(|h| f.por_hash(&h).and_then(BloqueCadena::slot))
        else {
            return false;
        };
        if cur_slot < b_slot {
            return false;
        }
        let Some(gd) = dt.dag.datos(cur_idx) else {
            return false;
        };
        for &m in &gd.orden_mergeset {
            if dt.dag.color_en(cur_idx, m) == Some(Color::RojoU3) {
                continue;
            }
            f.visita();
            if m == b_idx {
                return true;
            }
        }
        let Some(sp) = gd.sp else {
            return false;
        };
        if sp == cur_idx {
            return false;
        }
        cur_idx = sp;
    }
}

/// X1 · `desciende_acotado(c, a)` — igual que
/// [`Cadena::cadena_contiene`]`(terminal, c, a)` salvo que devuelve `false` en cuanto el bloque
/// recorrido tiene `slot` menor que el de `a`. Acota los recorridos de los pasos 6 y 10 del
/// hecho. [`Cadena::cadena_contiene`] no se toca (la usa `FIN-1`).
fn desciende_acotado<F: FuentePost>(
    f: &F,
    terminal: BlockHash,
    c: BlockHash,
    a: BlockHash,
) -> bool {
    let Some(dt) = f.dag(terminal) else {
        return false;
    };
    let Some(a_slot) = f.por_hash(&a).and_then(BloqueCadena::slot) else {
        return false;
    };
    let Some(mut idx) = dt.dag_idx.get(&c).copied() else {
        return false;
    };
    loop {
        f.visita();
        if hash_de_idx(f, terminal, idx) == Some(a) {
            return true;
        }
        let Some(cur_slot) =
            hash_de_idx(f, terminal, idx).and_then(|h| f.por_hash(&h).and_then(BloqueCadena::slot))
        else {
            return false;
        };
        if cur_slot < a_slot {
            return false;
        }
        if idx == 0 {
            return false;
        }
        match dt.dag.datos(idx).and_then(|d| d.sp) {
            Some(sp) if sp != idx => idx = sp,
            _ => return false,
        }
    }
}

/// Hecho de una transacción `0x0B` de `x`; `Inadmisible` para cualquier otra transacción.
pub(super) fn hecho_de_tx<F: FuentePost>(
    f: &F,
    ctx: &ContextoAplicacion,
    plazo_slots: u64,
    x_hash: BlockHash,
    tx: &Tx,
) -> HechoVoto {
    // Paso 1 · forma de la evidencia: `0x0B` con `n₁ < n₂`.
    let Some((voto1, voto2)) = super::evidencia_votos_peso(tx) else {
        return HechoVoto::Inadmisible;
    };
    if voto1.n >= voto2.n {
        return HechoVoto::Inadmisible;
    }
    let b1 = BlockHash::from_digest(zx_core::Digest::from_bytes(voto1.candidato));
    let b2 = BlockHash::from_digest(zx_core::Digest::from_bytes(voto2.candidato));
    // Paso 2 · los dos candidatos deben ser bloques PoST (tener slot); sin recorrer el DAG.
    let (Some(slot_b1), Some(slot_b2)) = (
        f.por_hash(&b1).and_then(BloqueCadena::slot),
        f.por_hash(&b2).and_then(BloqueCadena::slot),
    ) else {
        return HechoVoto::Inadmisible;
    };
    let cierre_n2 = cierre_ventana(voto2.n);
    // Paso 3 · el hecho solo se calcula dentro del plazo de la evidencia.
    if ctx.slot_g > cierre_n2.saturating_add(plazo_slots) {
        return HechoVoto::Inadmisible;
    }
    // Paso 4 · fuera de `F` por `B₁` o por `B₂` (límite declarado B1.4) no hay falta.
    if cierre_n2 >= slot_b1.saturating_add(ESPERA_REARRANQUE_SLOTS)
        || cierre_n2 >= slot_b2.saturating_add(ESPERA_REARRANQUE_SLOTS)
    {
        return HechoVoto::SinFalta;
    }
    // Paso 5 · X2 · ninguna consulta parte de un bloque no aplicado antes que `x`.
    if !aplicado_antes_que(f, ctx, x_hash, b1) || !aplicado_antes_que(f, ctx, x_hash, b2) {
        return HechoVoto::Inadmisible;
    }
    // Paso 6 · sin conflicto (recorrido acotado por slot) no hay falta.
    let en_conflicto =
        !desciende_acotado(f, ctx.terminal, b1, b2) && !desciende_acotado(f, ctx.terminal, b2, b1);
    if !en_conflicto {
        return HechoVoto::SinFalta;
    }
    // Paso 7 · sin finalidad guardada del pasado de `B₂`, inadmisible (puede volver a
    // presentarse): antes contaba como «no justificado».
    let Some((m2, s2_opt)) = f.finalidad_pasado(&b2) else {
        return HechoVoto::Inadmisible;
    };
    // Paso 8 · `(m₂, None)` o `m₂ < n₁` → falta directa.
    if m2 < voto1.n {
        return HechoVoto::Falta;
    }
    let Some(s2) = s2_opt else {
        return HechoVoto::Falta;
    };
    // Paso 8b · cota de `S₂` (único bloque sin tope de antigüedad): si cae por debajo del
    // horizonte `slot(g) − plazo_slots − F`, inadmisible.
    let Some(slot_s2) = f.por_hash(&s2).and_then(BloqueCadena::slot) else {
        return HechoVoto::Inadmisible;
    };
    if slot_s2
        .saturating_add(plazo_slots)
        .saturating_add(ESPERA_REARRANQUE_SLOTS)
        < ctx.slot_g
    {
        return HechoVoto::Inadmisible;
    }
    // Paso 9 · X2 · `S₂` debe estar aplicado antes que `x`.
    if !aplicado_antes_que(f, ctx, x_hash, s2) {
        return HechoVoto::Inadmisible;
    }
    // Paso 10 · `S₂` en conflicto con `B₁` justifica; si no, falta.
    let justificado =
        !desciende_acotado(f, ctx.terminal, s2, b1) && !desciende_acotado(f, ctx.terminal, b1, s2);
    if justificado {
        HechoVoto::SinFalta
    } else {
        HechoVoto::Falta
    }
}

/// AT-1b · W2 · hechos, por índice de transacción, del bloque `x` en el contexto `ctx`.
fn hechos_de<F: FuentePost>(
    f: &F,
    ctx: &ContextoAplicacion,
    plazo_slots: u64,
    x: &BloqueCadena,
) -> Vec<HechoVoto> {
    let x_hash = x.hash();
    x.txs()
        .iter()
        .map(|(tx, _)| hecho_de_tx(f, ctx, plazo_slots, x_hash, tx))
        .collect()
}

/// Aplica `bloque` en modo fusión pasando los hechos calculados con `ctx`.
pub(super) fn aplicar_bloque_con_hechos<F: FuentePost>(
    f: &F,
    estado: &Estado,
    bloque: &BloqueCadena,
    punto: Punto,
    ctx: &ContextoAplicacion,
) -> Result<(Estado, Undo, Vec<TxDescartada>), MotivoBloque> {
    let plazo_slots = u64::try_from(estado.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
    let hechos = hechos_de(f, ctx, plazo_slots, bloque);
    let bt = bloque.como_transicion().con_hechos_votos(hechos);
    Ok(aplicar_fusion(
        estado,
        &bt,
        punto,
        f.params(),
        f.cbid(),
        f.evidencia(),
    )?)
}

/// `Estado(past(B))` para la candidata ya coloreada en `idx` del DAG de `terminal`.
pub(super) fn estado_past_de_idx<F: FuentePost>(
    f: &F,
    terminal: BlockHash,
    idx: Idx,
    p: &BloquePost,
) -> Result<Estado, MotivoBloque> {
    let Some(dt) = f.dag(terminal) else {
        return Err(MotivoBloque::ErrSinPadre);
    };
    let gd = dt.dag.datos(idx).ok_or(MotivoBloque::ErrSinPadre)?;
    let sp = gd.sp.ok_or(MotivoBloque::ErrSinPadre)?;
    let mut base = if sp == 0 {
        f.post(&terminal)
            .cloned()
            .ok_or(MotivoBloque::ErrSinPadre)?
    } else {
        let sp_hash = hash_de_idx(f, terminal, sp).ok_or(MotivoBloque::ErrSinPadre)?;
        f.post(&sp_hash).cloned().ok_or(MotivoBloque::ErrSinPadre)?
    };
    let ctx = contexto_real(f, terminal, idx).ok_or(MotivoBloque::ErrSinPadre)?;
    for x_idx in &gd.orden_mergeset {
        if dt.dag.color_en(idx, *x_idx) == Some(Color::RojoU3) {
            continue;
        }
        let x_hash = hash_de_idx(f, terminal, *x_idx).ok_or(MotivoBloque::ErrSinPadre)?;
        let Some(x) = f.por_hash(&x_hash) else {
            return Err(MotivoBloque::ErrSinPadre);
        };
        let Some(x_slot) = x.slot() else {
            return Err(MotivoBloque::ErrSinPadre);
        };
        if let Some(fs) = f.params().f_slots
            && p.slot > x_slot
            && p.slot - x_slot > fs
        {
            return Err(MotivoBloque::ErrMergeDepth);
        }
        let (nuevo, _undo, _desc) =
            aplicar_bloque_con_hechos(f, &base, x, Punto::Slot(p.slot), &ctx)?;
        base = nuevo;
    }
    Ok(base)
}

/// Garantía del productor sobre `Estado(past(B))` promovido en `slot(B)`.
pub(super) fn comprobar_garantia<F: FuentePost>(
    f: &F,
    base: &Estado,
    p: &BloquePost,
) -> Result<(), MotivoBloque> {
    let activo = super::activo_promovido(base, &p.productor, p.slot)?;
    if activo < f.params().q {
        return Err(MotivoBloque::ErrGarantia);
    }
    Ok(())
}

/// Mitad previa del cálculo único: `Estado(past(B))` y garantía del productor.
pub(super) fn calcular_base<F: FuentePost>(
    f: &F,
    terminal: BlockHash,
    idx: Idx,
    p: &BloquePost,
) -> Result<Estado, MotivoBloque> {
    let base = estado_past_de_idx(f, terminal, idx, p)?;
    comprobar_garantia(f, &base, p)?;
    Ok(base)
}

/// Mitad final del cálculo único: contexto real, hechos, transición de fusión y suma del peso.
pub(super) fn aplicar_candidata<F: FuentePost>(
    f: &F,
    base: &Estado,
    terminal: BlockHash,
    idx: Idx,
    p: &BloquePost,
    bloque: &BloqueCadena,
) -> Result<(Estado, Vec<TxDescartada>), MotivoBloque> {
    let ctx = contexto_real(f, terminal, idx).ok_or(MotivoBloque::ErrSinPadre)?;
    let (mut nuevo, _undo, desc) =
        aplicar_bloque_con_hechos(f, base, bloque, Punto::Slot(p.slot), &ctx)?;
    nuevo.peso_sufijo =
        nuevo
            .peso_sufijo
            .checked_add(p.peso)
            .ok_or(MotivoBloque::ErrTransicion(
                zx_consensus::transicion::ErrorTransicion::ErrDesbordamiento,
            ))?;
    Ok((nuevo, desc))
}
