//! Pieza **N** (`REGLA-PIEZAS.md` §4, plan MA-1): cola acotada de bloques retenidos como
//! `Pendiente`.
//!
//! No conoce [`crate::nodo::Nodo`] ni ninguna otra pieza: guarda cada bloque con su hash, su
//! instante de llegada y **por qué espera**; no admite duplicados (mismo hash); desaloja al más
//! antiguo al llegar a su tope; y responde a dos preguntas con la hora local que se le pasa como
//! parámetro: cuál es el vencimiento más temprano y qué pendientes han vencido. Es genérica en el
//! tipo de bloque, así que sirve igual para PoST ([`zx_core::wire_dag::BloqueDag`]) y para PoW
//! ([`zx_p2p::mensaje::BloqueRed`]).
//!
//! Un pendiente que espera **solo** por el límite de futuro (`C-RLJ-TS-02`) vence en
//! `timestamp(B) − FTL`; uno que espera por contexto (un ancestro, el segundo VDF) solo se
//! reintenta cuando otra admisión hace avanzar el contexto, nunca por reloj.

use std::collections::VecDeque;
use std::time::Instant;

use zx_core::BlockHash;

/// Por qué espera un bloque retenido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotivoEspera {
    /// Solo falló el límite de futuro (`C-RLJ-TS-02`): vence cuando el reloj local alcance `vence`.
    Ftl {
        /// Instante del reloj local (`timestamp(B) − FTL`) en que dejará de ser futuro.
        vence: i64,
    },
    /// Falta contexto local (un ancestro, el segundo VDF): se reintenta al admitir otro bloque.
    Contexto,
}

/// Una entrada de la cola: el bloque, su hash, cuándo llegó y por qué espera.
#[derive(Debug, Clone)]
pub struct Pendiente<B> {
    bloque: B,
    hash: BlockHash,
    llegada: Instant,
    motivo: MotivoEspera,
}

impl<B> Pendiente<B> {
    /// Bloque retenido.
    #[must_use]
    pub fn bloque(&self) -> &B {
        &self.bloque
    }

    /// Hash del bloque (clave de no-duplicados).
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.hash
    }

    /// Instante de llegada original del bloque.
    #[must_use]
    pub fn llegada(&self) -> Instant {
        self.llegada
    }

    /// Motivo por el que sigue esperando.
    #[must_use]
    pub fn motivo(&self) -> MotivoEspera {
        self.motivo
    }

    /// Consume la entrada y devuelve el bloque.
    #[must_use]
    pub fn en_bloque(self) -> B {
        self.bloque
    }
}

/// Cola acotada FIFO de bloques pendientes, sin duplicados por hash.
///
/// El vencimiento más temprano se mantiene en caché para que la vuelta del bucle sin pendientes
/// vencidos pague una sola comparación.
#[derive(Debug, Clone)]
pub struct Pendientes<B> {
    tope: usize,
    entradas: VecDeque<Pendiente<B>>,
    vencimiento_min: Option<i64>,
    verificaciones: u64,
}

impl<B> Pendientes<B> {
    /// Crea una cola con el tope indicado. Con tope `0` no se encola nada.
    #[must_use]
    pub fn nuevo(tope: usize) -> Self {
        Self {
            tope,
            entradas: VecDeque::new(),
            vencimiento_min: None,
            verificaciones: 0,
        }
    }

    /// Número de entradas retenidas.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entradas.len()
    }

    /// ¿Está vacía?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entradas.is_empty()
    }

    /// Tope configurado.
    #[must_use]
    pub fn tope(&self) -> usize {
        self.tope
    }

    /// Lectura por pares `(bloque, llegada)`, con la misma forma que la cola histórica.
    pub fn iter(&self) -> impl Iterator<Item = (&B, Instant)> {
        self.entradas.iter().map(|p| (&p.bloque, p.llegada))
    }

    /// Primera entrada (la más antigua), como par `(bloque, llegada)`.
    #[must_use]
    pub fn front(&self) -> Option<(&B, Instant)> {
        self.entradas.front().map(|p| (&p.bloque, p.llegada))
    }

    /// Última entrada (la más reciente), como par `(bloque, llegada)`.
    #[must_use]
    pub fn back(&self) -> Option<(&B, Instant)> {
        self.entradas.back().map(|p| (&p.bloque, p.llegada))
    }

    /// Lectura completa de las entradas (para diagnóstico y pruebas).
    pub fn iter_entradas(&self) -> impl Iterator<Item = &Pendiente<B>> {
        self.entradas.iter()
    }

    /// Encola un bloque. Devuelve `false` si otro con el mismo hash ya estaba (no se duplica) o si
    /// el tope es `0`. Si la cola está llena, desaloja al más antiguo antes de insertar.
    pub fn encolar(
        &mut self,
        bloque: B,
        hash: BlockHash,
        llegada: Instant,
        motivo: MotivoEspera,
    ) -> bool {
        if self.tope == 0 || self.entradas.iter().any(|p| p.hash == hash) {
            return false;
        }
        if self.entradas.len() >= self.tope {
            let desalojado = self.entradas.pop_front();
            if desalojado.is_some_and(|p| min_de(p.motivo) == self.vencimiento_min) {
                self.recalcular_vencimiento();
            }
        }
        if let MotivoEspera::Ftl { vence } = motivo {
            self.vencimiento_min = Some(self.vencimiento_min.map_or(vence, |m| m.min(vence)));
        }
        self.entradas.push_back(Pendiente {
            bloque,
            hash,
            llegada,
            motivo,
        });
        true
    }

    /// Reencola una entrada que ha vuelto a quedar `Pendiente`. Respeta el no-duplicado y el tope.
    pub fn reencolar(&mut self, p: Pendiente<B>) -> bool {
        self.encolar(p.bloque, p.hash, p.llegada, p.motivo)
    }

    /// Vencimiento `FTL` más temprano de la cola, o `None` si no hay pendientes solo-`FTL`.
    #[must_use]
    pub fn vencimiento_mas_temprano(&self) -> Option<i64> {
        self.vencimiento_min
    }

    /// ¿Hay algún pendiente solo-`FTL` vencido a la hora `ahora`?
    #[must_use]
    pub fn hay_vencidos(&self, ahora: i64) -> bool {
        self.vencimiento_mas_temprano().is_some_and(|v| ahora >= v)
    }

    /// Saca de la cola **solo** los pendientes `FTL` vencidos a la hora `ahora`, conservando el
    /// orden. Cada entrada entregada cuenta como una verificación.
    pub fn tomar_vencidos(&mut self, ahora: i64) -> Vec<Pendiente<B>> {
        let mut vencidos = Vec::new();
        let mut resto = VecDeque::with_capacity(self.entradas.len());
        for p in self.entradas.drain(..) {
            if matches!(p.motivo, MotivoEspera::Ftl { vence } if ahora >= vence) {
                vencidos.push(p);
            } else {
                resto.push_back(p);
            }
        }
        self.entradas = resto;
        self.recalcular_vencimiento();
        self.verificaciones = self
            .verificaciones
            .saturating_add(u64::try_from(vencidos.len()).unwrap_or(u64::MAX));
        vencidos
    }

    /// Saca de la cola los pendientes por contexto, conservando el orden. Cada entrada entregada
    /// cuenta como una verificación.
    pub fn tomar_contexto(&mut self) -> Vec<Pendiente<B>> {
        let mut contexto = Vec::new();
        let mut resto = VecDeque::with_capacity(self.entradas.len());
        for p in self.entradas.drain(..) {
            if p.motivo == MotivoEspera::Contexto {
                contexto.push(p);
            } else {
                resto.push_back(p);
            }
        }
        self.entradas = resto;
        self.verificaciones = self
            .verificaciones
            .saturating_add(u64::try_from(contexto.len()).unwrap_or(u64::MAX));
        contexto
    }

    /// Entradas entregadas para verificación desde el arranque. Es el contador que exige B1.
    #[must_use]
    pub fn verificaciones(&self) -> u64 {
        self.verificaciones
    }

    fn recalcular_vencimiento(&mut self) {
        self.vencimiento_min = self.entradas.iter().filter_map(|p| min_de(p.motivo)).min();
    }
}

/// Vencimiento de una entrada si espera solo por `FTL`.
fn min_de(motivo: MotivoEspera) -> Option<i64> {
    match motivo {
        MotivoEspera::Ftl { vence } => Some(vence),
        MotivoEspera::Contexto => None,
    }
}

#[cfg(test)]
mod pruebas {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "aserciones de pruebas internas; índices comprobados por la propia prueba"
    )]

    use std::time::Instant;

    use zx_core::digest::Digest;

    use super::{MotivoEspera, Pendientes};

    fn hash(n: u8) -> zx_core::BlockHash {
        zx_core::BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    /// B1 (pieza sola): un pendiente que aún no vence no se entrega a verificación.
    #[test]
    fn b1_pieza_pendiente_sin_vencer_no_verifica() {
        let mut cola = Pendientes::<u64>::nuevo(4);
        assert!(cola.encolar(7, hash(1), Instant::now(), MotivoEspera::Ftl { vence: 100 }));
        assert_eq!(cola.vencimiento_mas_temprano(), Some(100));
        assert!(!cola.hay_vencidos(50));
        for _ in 0..100 {
            assert!(!cola.hay_vencidos(50));
        }
        assert_eq!(cola.verificaciones(), 0);
        assert_eq!(cola.len(), 1);
    }

    /// B2 (pieza sola): un pendiente por contexto no se reintenta por tiempo.
    #[test]
    fn b2_pieza_contexto_no_vence() {
        let mut cola = Pendientes::<u64>::nuevo(4);
        assert!(cola.encolar(1, hash(1), Instant::now(), MotivoEspera::Contexto));
        assert_eq!(cola.vencimiento_mas_temprano(), None);
        assert!(!cola.hay_vencidos(i64::MAX));
        assert!(cola.tomar_vencidos(i64::MAX).is_empty());
        assert_eq!(cola.verificaciones(), 0);
        assert_eq!(cola.len(), 1);
    }

    /// B3 (pieza sola): un pendiente vencido sale de la cola una sola vez.
    #[test]
    fn b3_pieza_vencido_sale_y_deja_de_estar() {
        let mut cola = Pendientes::<u64>::nuevo(4);
        assert!(cola.encolar(1, hash(1), Instant::now(), MotivoEspera::Ftl { vence: 10 }));
        let vencidos = cola.tomar_vencidos(10);
        assert_eq!(vencidos.len(), 1);
        assert_eq!(vencidos[0].motivo(), MotivoEspera::Ftl { vence: 10 });
        assert_eq!(cola.len(), 0);
        assert_eq!(cola.vencimiento_mas_temprano(), None);
        assert_eq!(cola.verificaciones(), 1);
        assert!(cola.tomar_vencidos(10).is_empty());
    }

    /// B4 (pieza sola): el tope se respeta con 200 bloques distintos y las repeticiones no crecen.
    #[test]
    fn b4_pieza_tope_con_200_distintos_y_sin_duplicados() {
        let mut cola = Pendientes::<u64>::nuevo(64);
        for n in 0..200u16 {
            let h = hash(u8::try_from(n % 251).expect("cabe"));
            assert!(cola.encolar(u64::from(n), h, Instant::now(), MotivoEspera::Contexto));
        }
        assert_eq!(cola.len(), 64);
        assert_eq!(cola.tope(), 64);
        // Repetición de uno que sigue vivo (el último): no duplica; y el más antiguo desalojado.
        assert!(!cola.encolar(199, hash(199), Instant::now(), MotivoEspera::Contexto));
        assert_eq!(cola.len(), 64);
        assert_eq!(cola.back().expect("entrada").0, &199);
    }

    /// No-duplicados: el mismo hash no entra dos veces.
    #[test]
    fn sin_duplicados_por_hash() {
        let mut cola = Pendientes::<u64>::nuevo(4);
        assert!(cola.encolar(1, hash(9), Instant::now(), MotivoEspera::Contexto));
        assert!(!cola.encolar(2, hash(9), Instant::now(), MotivoEspera::Contexto));
        assert_eq!(cola.len(), 1);
        assert_eq!(cola.front().expect("entrada").0, &1);
    }

    /// El desalojo es del más antiguo y el contexto no se entrega por reloj.
    #[test]
    fn fifo_y_contexto() {
        let mut cola = Pendientes::<u64>::nuevo(2);
        assert!(cola.encolar(1, hash(1), Instant::now(), MotivoEspera::Ftl { vence: 5 }));
        assert!(cola.encolar(2, hash(2), Instant::now(), MotivoEspera::Contexto));
        assert!(cola.encolar(3, hash(3), Instant::now(), MotivoEspera::Ftl { vence: 9 }));
        assert_eq!(cola.front().expect("entrada").0, &2);
        assert_eq!(cola.back().expect("entrada").0, &3);
        let contexto = cola.tomar_contexto();
        assert_eq!(contexto.len(), 1);
        assert_eq!(contexto[0].bloque(), &2);
        assert_eq!(cola.len(), 1);
    }
}
