//! Implementaciones literales de la base 2e1fc023: solo cambia el nombre.
use crate::cajas::CajaId;
use crate::sectores::SectorId;
use crate::transicion::estado::Aplicador;
use crate::transicion::{ErrorTransicion, Estado, debitar_garantia, total_garantia};
use zx_core::ClavePublica;
pub(crate) fn fianza_no_terminal_base(estado: &Estado, clave: &ClavePublica) -> i128 {
    estado
        .sectores
        .iter()
        .filter(|(id, r)| id.clave == *clave && !r.es_terminal())
        .map(|(_, r)| i128::from(r.fianza))
        .sum()
}

pub(crate) fn debitar_castigable_base(
    ap: &mut Aplicador,
    clave: ClavePublica,
    c: i128,
    slot: i64,
) -> Result<i128, ErrorTransicion> {
    if c <= 0 {
        return Ok(0);
    }
    let antes = ap.estado.garantias.get(&clave).map_or(0, total_garantia);
    debitar_garantia(ap.garantia_mut(clave), c)?;
    let despues = ap.estado.garantias.get(&clave).map_or(0, total_garantia);
    let mut restante = c - (antes - despues);

    let ids: Vec<SectorId> = ap
        .estado
        .sectores
        .iter()
        .filter(|(id, r)| id.clave == clave && !r.es_terminal() && r.fianza > 0)
        .map(|(id, _)| *id)
        .collect();
    let mut cajas: std::collections::BTreeSet<CajaId> = std::collections::BTreeSet::new();
    for id in ids {
        if restante <= 0 {
            break;
        }
        let Some(r) = ap.estado.sectores.get(&id) else {
            continue;
        };
        let d = core::cmp::min(restante, i128::from(r.fianza));
        if d <= 0 {
            continue;
        }
        if let Some((caja, _)) = super::caja_base::caja_de_sector(&ap.estado, &id) {
            cajas.insert(caja);
        }
        ap.tocar_sector(id);
        if let Some(r) = ap.estado.sectores.get_mut(&id) {
            r.fianza -= i64::try_from(d).map_err(|_| ErrorTransicion::ErrDesbordamiento)?;
        }
        restante -= d;
    }
    for caja in cajas {
        super::caja_base::refrescar_caja(ap, caja, slot);
    }
    Ok(c - restante)
}
