//! Depósito **acotado** de bloques huérfanos (`ORDEN-W06d2` decisión 3).
//!
//! Un bloque cuyo padre no conocemos todavía no es inválido: puede haber llegado por una ruta más
//! rápida que la de su padre. Se retiene aquí, indexado por el padre que le falta, hasta que ese
//! padre se admite (o hasta que el desalojo determinista de este depósito lo descarta por falta de
//! sitio: nunca por edad de reloj, siempre por orden de llegada — FIFO).
//!
//! Dos topes, los dos declarados por quien construye el depósito, nunca ocultos:
//! - **por padre** (`max_por_padre`): una ráfaga de huérfanos que apuntan al mismo padre ausente no
//!   puede agotar por sí sola el depósito entero.
//! - **total** (`max_total`): el depósito entero tiene un techo de memoria, sea cual sea la
//!   distribución de padres.
//!
//! El desalojo es **FIFO determinista**: al llenarse un cupo, se descarta siempre el huérfano más
//! viejo de ese cupo (nunca uno al azar, nunca "el que estorbe"). Desalojar **no penaliza** a nadie:
//! es la misma razón que [`zx_p2p::entrante::Veredicto::Ignorar`] — falta de recursos locales, no
//! una prueba de mala fe del par que lo mandó.

use std::collections::{BTreeMap, VecDeque};

use zx_core::BlockHash;
use zx_p2p::mensaje::BloqueRed;

/// Un huérfano desalojado por falta de sitio (para que quien llama pueda registrarlo).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desalojado {
    /// El padre que este huérfano estaba esperando.
    pub padre_esperado: BlockHash,
    /// El hash del propio huérfano desalojado.
    pub hijo: BlockHash,
}

/// El depósito. Ver el docstring del módulo.
pub struct DepositoHuerfanos {
    max_total: usize,
    max_por_padre: usize,
    espera: BTreeMap<BlockHash, Vec<(BlockHash, BloqueRed)>>,
    /// Orden de llegada real, `(padre_esperado, hijo)`: la única fuente de "qué es más viejo" para
    /// el desalojo FIFO. `espera` por sí solo no basta porque un `Vec` por padre no ordena entre
    /// padres distintos.
    orden: VecDeque<(BlockHash, BlockHash)>,
}

impl DepositoHuerfanos {
    /// Un depósito vacío con los dos topes dados.
    ///
    /// # Pánico
    /// Si algún tope es cero: un depósito que no puede guardar nada no es un depósito, es un `Ignorar`
    /// disfrazado, y hay que decidirlo explícitamente en la llamada, no dejar que ocurra por un `0`
    /// puesto por error.
    #[must_use]
    pub fn nuevo(max_total: usize, max_por_padre: usize) -> Self {
        assert!(
            max_total > 0 && max_por_padre > 0,
            "los topes deben ser > 0"
        );
        Self {
            max_total,
            max_por_padre,
            espera: BTreeMap::new(),
            orden: VecDeque::new(),
        }
    }

    /// Cuántos huérfanos hay en total.
    #[must_use]
    pub fn total(&self) -> usize {
        self.orden.len()
    }

    /// Cuántos huérfanos esperan a `padre`.
    #[must_use]
    pub fn por_padre(&self, padre: &BlockHash) -> usize {
        self.espera.get(padre).map_or(0, Vec::len)
    }

    /// ¿Ya hay un huérfano con este hash en el depósito? (deduplicación; el mismo bloque puede
    /// llegar dos veces por rutas de gossip distintas antes de que su padre aparezca).
    #[must_use]
    pub fn contiene_hijo(&self, hijo: &BlockHash) -> bool {
        self.orden.iter().any(|(_, h)| h == hijo)
    }

    /// Inserta un huérfano que espera a `padre_esperado`. Si ya hay un huérfano con el mismo `hijo`,
    /// no se duplica (se ignora la inserción; quien llama no necesita tratarlo como error).
    ///
    /// Devuelve lo que el desalojo determinista tuvo que sacar para hacer sitio (0, 1 o 2 entradas:
    /// como mucho una por el cupo de este padre y una por el cupo total).
    pub fn insertar(
        &mut self,
        padre_esperado: BlockHash,
        hijo: BlockHash,
        bloque: BloqueRed,
    ) -> Vec<Desalojado> {
        if self.contiene_hijo(&hijo) {
            return Vec::new();
        }
        let mut desalojados = Vec::new();

        if self
            .espera
            .get(&padre_esperado)
            .is_some_and(|v| v.len() >= self.max_por_padre)
            && let Some(d) = self.desalojar_mas_viejo_de(&padre_esperado)
        {
            desalojados.push(d);
        }
        if self.orden.len() >= self.max_total
            && let Some((p, _)) = self.orden.front().copied()
            && let Some(d) = self.desalojar_mas_viejo_de(&p)
        {
            desalojados.push(d);
        }

        self.espera
            .entry(padre_esperado)
            .or_default()
            .push((hijo, bloque));
        self.orden.push_back((padre_esperado, hijo));
        desalojados
    }

    /// Saca el huérfano más viejo que espera a `padre` (el primero en `orden` con ese padre).
    fn desalojar_mas_viejo_de(&mut self, padre: &BlockHash) -> Option<Desalojado> {
        let pos = self.orden.iter().position(|(p, _)| p == padre)?;
        let (p, h) = self.orden.remove(pos)?;
        if let Some(v) = self.espera.get_mut(&p) {
            v.retain(|(hh, _)| *hh != h);
            if v.is_empty() {
                self.espera.remove(&p);
            }
        }
        Some(Desalojado {
            padre_esperado: p,
            hijo: h,
        })
    }

    /// `padre` acaba de admitirse: saca (y quita del depósito) todos los huérfanos que lo esperaban,
    /// para que quien llama los reintente contra la tubería de admisión.
    pub fn tomar_para_padre(&mut self, padre: &BlockHash) -> Vec<(BlockHash, BloqueRed)> {
        let v = self.espera.remove(padre).unwrap_or_default();
        if !v.is_empty() {
            self.orden.retain(|(p, _)| p != padre);
        }
        v
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::DepositoHuerfanos;
    use zx_core::digest::{BlockHash, Digest};
    use zx_core::preimage::block::BlockHeader;
    use zx_p2p::mensaje::BloqueRed;

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn bloque(n: u8) -> BloqueRed {
        BloqueRed::Pow {
            cabecera: BlockHeader {
                consensus_branch_id: 0,
                prev_hash: h(n),
                merkle_root: zx_core::digest::MerkleRoot::from_digest(Digest::from_bytes([0; 32])),
                timestamp: 0,
                bits: 0,
                nonce: u64::from(n),
                height: u32::from(n),
            },
            txs: Vec::new(),
            testigos: Vec::new(),
        }
    }

    #[test]
    fn inserta_y_recupera_por_padre() {
        let mut d = DepositoHuerfanos::nuevo(10, 10);
        assert!(d.insertar(h(1), h(10), bloque(10)).is_empty());
        assert_eq!(d.total(), 1);
        assert_eq!(d.por_padre(&h(1)), 1);
        assert!(d.contiene_hijo(&h(10)));

        let salen = d.tomar_para_padre(&h(1));
        assert_eq!(salen.len(), 1);
        assert_eq!(salen[0].0, h(10));
        assert_eq!(d.total(), 0);
        assert!(!d.contiene_hijo(&h(10)));
    }

    #[test]
    fn no_duplica_el_mismo_hijo() {
        let mut d = DepositoHuerfanos::nuevo(10, 10);
        d.insertar(h(1), h(10), bloque(10));
        let desalojados = d.insertar(h(1), h(10), bloque(10));
        assert!(desalojados.is_empty());
        assert_eq!(d.total(), 1, "el segundo intento no debe duplicar");
    }

    #[test]
    fn el_cupo_por_padre_desaloja_al_mas_viejo_de_ese_padre() {
        let mut d = DepositoHuerfanos::nuevo(100, 2);
        d.insertar(h(1), h(10), bloque(10));
        d.insertar(h(1), h(11), bloque(11));
        // El tercero del mismo padre desaloja al primero (h(10)), no a uno de otro padre.
        let desalojados = d.insertar(h(1), h(12), bloque(12));
        assert_eq!(desalojados.len(), 1);
        assert_eq!(
            desalojados[0].hijo,
            h(10),
            "FIFO: el más viejo de ese padre"
        );
        assert_eq!(d.por_padre(&h(1)), 2);
        assert!(!d.contiene_hijo(&h(10)));
        assert!(d.contiene_hijo(&h(11)));
        assert!(d.contiene_hijo(&h(12)));
    }

    #[test]
    fn el_cupo_total_desaloja_al_mas_viejo_global() {
        let mut d = DepositoHuerfanos::nuevo(2, 10);
        d.insertar(h(1), h(10), bloque(10));
        d.insertar(h(2), h(20), bloque(20));
        let desalojados = d.insertar(h(3), h(30), bloque(30));
        assert_eq!(desalojados.len(), 1);
        assert_eq!(
            desalojados[0].hijo,
            h(10),
            "FIFO global: el primero que llegó"
        );
        assert_eq!(d.total(), 2);
        assert!(d.contiene_hijo(&h(20)));
        assert!(d.contiene_hijo(&h(30)));
    }

    #[test]
    fn tomar_para_un_padre_sin_huerfanos_no_falla() {
        let mut d = DepositoHuerfanos::nuevo(10, 10);
        assert!(d.tomar_para_padre(&h(99)).is_empty());
    }

    #[test]
    #[should_panic(expected = "los topes deben ser > 0")]
    fn un_tope_cero_entra_en_panico_al_construir() {
        let _ = DepositoHuerfanos::nuevo(0, 10);
    }
}
