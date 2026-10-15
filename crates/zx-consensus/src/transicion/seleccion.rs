//! Selección transversal (`FC-3`), construcción de válidos y nodo en línea (`C-FIN-01`).
//!
//! `seleccionar` es **pura**: valida contextualmente todo el conjunto (un bloque es válido solo si su
//! padre lo es y su aplicación sobre el estado del padre no da error), descarta inválidos y
//! descendientes y aplica la interfaz por defecto `FC-3` (`TRN-09`). Los desempates usan el
//! `BlockHash` real en orden de bytes big-endian (§3.8).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use zx_core::BlockHash;

use crate::transicion::ErrorTransicion;
use crate::transicion::aplicar::aplicar_con_undo;
use crate::transicion::tipos::{
    BloqueTransicion, Estado, HechosCabecera, ParametrosEvidencia, ParametrosTransicion,
};

/// Resultado de seleccionar: punta, estado de la punta y estados de todos los válidos.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResultadoSeleccion {
    /// Hash de la punta seleccionada (`None` si no hay ningún válido).
    pub punta: Option<BlockHash>,
    /// Estado de la punta.
    pub estado: Estado,
    /// Estados de todos los bloques válidos, por hash.
    pub validos: BTreeMap<BlockHash, Estado>,
}

/// Índice de bloques por hash.
#[must_use]
pub fn mapa_por_hash(bloques: &[BloqueTransicion]) -> BTreeMap<BlockHash, &BloqueTransicion> {
    let mut mapa = BTreeMap::new();
    for b in bloques {
        mapa.insert(b.hash(), b);
    }
    mapa
}

/// Construye el conjunto de bloques válidos desde el primer génesis de `bloques` (`construir_validos`
/// de T01). Un bloque cuya aplicación sobre el estado de su padre falla no entra; sus descendientes
/// tampoco.
///
/// # Errores
/// Solo errores internos de aplicación imposibles de aislar (ninguno esperado); un bloque inválido se
/// omite, no se propaga.
pub fn construir_validos(
    bloques: &[BloqueTransicion],
    params: &ParametrosTransicion,
    cbid: u32,
    evp: &ParametrosEvidencia,
) -> Result<BTreeMap<BlockHash, Estado>, ErrorTransicion> {
    construir_validos_con_inicial(&Estado::inicial(), bloques, params, cbid, evp)
}

/// RET-1a · Igual que [`construir_validos`] pero con un estado inicial explícito.
///
/// Lo usa el arnés diferencial T01 con un perfil sin `r_votos_slots` (el oráculo no conoce `R_V`);
/// el camino de producción sigue partiendo de [`Estado::inicial`].
pub fn construir_validos_con_inicial(
    inicial: &Estado,
    bloques: &[BloqueTransicion],
    params: &ParametrosTransicion,
    cbid: u32,
    evp: &ParametrosEvidencia,
) -> Result<BTreeMap<BlockHash, Estado>, ErrorTransicion> {
    let mut memo: BTreeMap<BlockHash, Estado> = BTreeMap::new();
    let Some(genesis) = bloques
        .iter()
        .find(|b| matches!(b.hechos, HechosCabecera::Genesis { .. }))
    else {
        return Ok(memo);
    };
    let Ok((estado_genesis, _)) = aplicar_con_undo(inicial, genesis, params, cbid, evp) else {
        return Ok(memo);
    };
    memo.insert(genesis.hash(), estado_genesis);
    let mut cola: VecDeque<BlockHash> = VecDeque::new();
    cola.push_back(genesis.hash());
    while let Some(pid) = cola.pop_front() {
        let Some(estado_padre) = memo.get(&pid).cloned() else {
            continue;
        };
        for b in bloques {
            let Some(padre) = b.padre() else {
                continue;
            };
            if padre != pid || memo.contains_key(&b.hash()) {
                continue;
            }
            if let Ok((nuevo, _)) = aplicar_con_undo(&estado_padre, b, params, cbid, evp) {
                memo.insert(b.hash(), nuevo);
                cola.push_back(b.hash());
            }
        }
    }
    Ok(memo)
}

/// Prioridad de terminales para `FC-3`: `None` (sin terminal) gana; entre terminales, el **menor**
/// hash.
///
/// Pública desde `ORDEN-W06d7` decisión 2: `zx-cadena` la reutiliza como desempate de `FC-3`
/// **entre terminales candidatos** (varios DAG a la vez), en vez de reimplementar el mismo criterio
/// («no una segunda implementación divergente»). El comportamiento no cambia: solo la visibilidad.
#[must_use]
pub fn comparar_terminal(a: Option<BlockHash>, b: Option<BlockHash>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => y.cmp(&x),
    }
}

/// Compara dos candidatos con la clave de `FC-3`. `Greater` = gana `a`.
fn comparar_fc3(
    a: &Estado,
    a_hash: BlockHash,
    b: &Estado,
    b_hash: BlockHash,
    hay_post: bool,
) -> Ordering {
    if hay_post {
        a.peso_sufijo
            .cmp(&b.peso_sufijo)
            .then_with(|| comparar_terminal(a.terminal, b.terminal))
            .then_with(|| b_hash.cmp(&a_hash))
    } else {
        a.trabajo.cmp(&b.trabajo).then_with(|| b_hash.cmp(&a_hash))
    }
}

/// Selecciona la punta de un conjunto de bloques con `FC-3` (`TRN-09`).
///
/// # Errores
/// Solo errores internos no aislables de la construcción de válidos.
pub fn seleccionar(
    bloques: &[BloqueTransicion],
    params: &ParametrosTransicion,
    cbid: u32,
    evp: &ParametrosEvidencia,
) -> Result<ResultadoSeleccion, ErrorTransicion> {
    seleccionar_con_inicial(&Estado::inicial(), bloques, params, cbid, evp)
}

/// RET-1a · Igual que [`seleccionar`] pero con un estado inicial explícito (perfil T01 sin `R_V`).
pub fn seleccionar_con_inicial(
    inicial: &Estado,
    bloques: &[BloqueTransicion],
    params: &ParametrosTransicion,
    cbid: u32,
    evp: &ParametrosEvidencia,
) -> Result<ResultadoSeleccion, ErrorTransicion> {
    let memo = construir_validos_con_inicial(inicial, bloques, params, cbid, evp)?;
    if memo.is_empty() {
        return Ok(ResultadoSeleccion {
            punta: None,
            estado: inicial.clone(),
            validos: memo,
        });
    }
    let por_hash = mapa_por_hash(bloques);
    let mut padres: BTreeSet<BlockHash> = BTreeSet::new();
    for hash in memo.keys() {
        if let Some(b) = por_hash.get(hash)
            && let Some(p) = b.padre()
        {
            padres.insert(p);
        }
    }
    let hay_post = memo
        .keys()
        .filter_map(|h| por_hash.get(h))
        .any(|b| matches!(b.hechos, HechosCabecera::PoST { .. }));
    let mut mejor: Option<(BlockHash, Estado)> = None;
    for (hash, estado) in &memo {
        if padres.contains(hash) {
            continue;
        }
        let gana = match &mejor {
            None => true,
            Some((mejor_hash, mejor_estado)) => {
                comparar_fc3(estado, *hash, mejor_estado, *mejor_hash, hay_post)
                    == Ordering::Greater
            }
        };
        if gana {
            mejor = Some((*hash, estado.clone()));
        }
    }
    match mejor {
        Some((punta, estado)) => Ok(ResultadoSeleccion {
            punta: Some(punta),
            estado,
            validos: memo,
        }),
        None => Ok(ResultadoSeleccion {
            punta: None,
            estado: inicial.clone(),
            validos: memo,
        }),
    }
}

/// Slot de un bloque para `C-FIN-01`: el slot si es PoST, 0 en otro caso.
fn slot_de(hash: BlockHash, por_hash: &BTreeMap<BlockHash, &BloqueTransicion>) -> u64 {
    match por_hash.get(&hash) {
        Some(b) => b.hechos.slot().unwrap_or(0),
        None => 0,
    }
}

/// Cadena de hashes desde `id` hasta la raíz (sin incluir el padre nulo).
fn cadena_hasta(
    id: BlockHash,
    por_hash: &BTreeMap<BlockHash, &BloqueTransicion>,
) -> Vec<BlockHash> {
    let mut cadena = Vec::new();
    let mut actual = Some(id);
    while let Some(hash) = actual {
        cadena.push(hash);
        actual = por_hash.get(&hash).and_then(|b| b.padre());
    }
    cadena.reverse();
    cadena
}

/// Último ancestro común de `a` y `b` (`None` si solo comparten la raíz nula).
fn ancestro_comun(
    a: BlockHash,
    b: BlockHash,
    por_hash: &BTreeMap<BlockHash, &BloqueTransicion>,
) -> Option<BlockHash> {
    let ca = cadena_hasta(a, por_hash);
    let cb = cadena_hasta(b, por_hash);
    let mut comun = None;
    for (x, y) in ca.iter().zip(cb.iter()) {
        if x == y {
            comun = Some(*x);
        } else {
            break;
        }
    }
    comun
}

/// Nodo en línea con huérfanos en espera y `C-FIN-01` (`TRN-09`).
///
/// Procesa `secuencia` en el orden recibido, recalcula la selección sobre el conjunto ya conocido y
/// **no** sustituye su punta por una candidata si
/// `d = slot(punta) − slot(ancestro común) ≥ F_slots`.
///
/// `FIN-1` (decisión 2 de `ORDEN-FIN1`): además, mantiene un **punto de finalidad** —el bloque de la
/// cadena seleccionada con el mayor `slot ≤ slot(punta) − F_slots`, que nunca retrocede— y no
/// sustituye la punta por una candidata cuya cadena seleccionada no lo contenga. La candidata sigue
/// siendo válida; solo deja de ser elegible.
///
/// # Errores
/// Solo errores internos no aislables de la selección.
pub fn nodo_en_linea(
    secuencia: &[BloqueTransicion],
    params: &ParametrosTransicion,
    cbid: u32,
    evp: &ParametrosEvidencia,
) -> Result<(Option<BlockHash>, Estado), ErrorTransicion> {
    let mut buffer: Vec<BloqueTransicion> = Vec::new();
    let mut punta: Option<BlockHash> = None;
    let mut estado_punta = Estado::inicial();
    let mut punto_finalidad: Option<BlockHash> = None;
    for b in secuencia {
        buffer.push(b.clone());
        let resultado = seleccionar(&buffer, params, cbid, evp)?;
        let Some(nueva) = resultado.punta else {
            continue;
        };
        let por_hash = mapa_por_hash(&buffer);
        match punta {
            None => {
                punta = Some(nueva);
                estado_punta = resultado.estado;
            }
            Some(actual) => {
                let comun = ancestro_comun(actual, nueva, &por_hash);
                let slot_actual = slot_de(actual, &por_hash);
                let slot_comun = comun.map_or(0, |c| slot_de(c, &por_hash));
                let d = i128::from(slot_actual) - i128::from(slot_comun);
                let dentro_de_f = match params.f_slots {
                    None => true,
                    Some(tope) => d < i128::from(tope),
                };
                // `FIN-1`: la candidata debe contener el punto de finalidad vigente.
                let contiene_finalidad = match punto_finalidad {
                    None => true,
                    Some(pf) => cadena_hasta(nueva, &por_hash).contains(&pf),
                };
                if dentro_de_f && contiene_finalidad {
                    punta = Some(nueva);
                    estado_punta = resultado.estado;
                }
            }
        }
        // `FIN-1`: avanza (nunca retrocede) el punto de finalidad sobre la cadena de la punta.
        if let (Some(p), Some(tope)) = (punta, params.f_slots) {
            let limite = slot_de(p, &por_hash).saturating_sub(tope);
            let cadena = cadena_hasta(p, &por_hash);
            let mut candidato = cadena.first().copied().unwrap_or(p);
            for h in &cadena {
                if slot_de(*h, &por_hash) <= limite {
                    candidato = *h;
                } else {
                    break;
                }
            }
            let slot_candidato = slot_de(candidato, &por_hash);
            let slot_actual = punto_finalidad.map_or(0, |pf| slot_de(pf, &por_hash));
            if punto_finalidad.is_none() || slot_candidato > slot_actual {
                punto_finalidad = Some(candidato);
            }
        }
    }
    Ok((punta, estado_punta))
}

#[cfg(test)]
mod tests_comparar_terminal {
    //! `ORDEN-W06d7`: prueba de la visibilidad nueva de [`comparar_terminal`], sin cambiar su
    //! comportamiento (los diferenciales T01/T04 siguen siendo la prueba de no-regresión real).
    use super::comparar_terminal;
    use std::cmp::Ordering;
    use zx_core::{BlockHash, Digest};

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    #[test]
    fn none_gana_a_cualquier_terminal() {
        // Convención documentada de `comparar_terminal` («`None` gana»), la misma que usa
        // `comparar_fc3`: `Greater` = gana el primer argumento.
        assert_eq!(comparar_terminal(None, Some(h(1))), Ordering::Greater);
        assert_eq!(comparar_terminal(Some(h(1)), None), Ordering::Less);
        assert_eq!(comparar_terminal(None, None), Ordering::Equal);
    }

    #[test]
    fn entre_terminales_gana_el_menor_hash() {
        // `Greater` = gana `a` (convención de `comparar_fc3`): con `a` de hash menor que `b`, `a`
        // debe ganar.
        assert_eq!(comparar_terminal(Some(h(1)), Some(h(2))), Ordering::Greater);
        assert_eq!(comparar_terminal(Some(h(2)), Some(h(1))), Ordering::Less);
    }
}
