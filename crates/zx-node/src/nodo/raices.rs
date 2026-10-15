//! Pieza R (MAP-1): raíces de estado.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    BlockHash, Cadena, Digest, Instant, LAG_CANDIDATO_VOTOS, Nodo, RAIZ_ESTADO_CERO, VistaCadena,
    hex,
};

impl Nodo {
    /// A1-D2b · W2 · al ir a abrir la ventana `n`, el nodo que vota recoge los cálculos terminados
    /// (y los anota), solicita la raíz de las épocas `⌊n/E⌋ − 2` y `⌊n/E⌋ − 1` que aún no la tengan
    /// ni la estén calculando, y poda las anteriores. **Nunca espera** a un cálculo.
    pub(super) fn preparar_raices(&mut self, n: u64, t_inst: u64) {
        if !self.vota {
            return;
        }
        self.raices.recoger();
        self.anunciar_raices_calculadas();
        let Some(epoca_actual) = crate::raiz_punto::epoca_de_raiz(n) else {
            return;
        };
        for epoca in [epoca_actual, epoca_actual.saturating_add(1)] {
            let Some(tope) = crate::raiz_punto::tope_de_punto(epoca, t_inst, LAG_CANDIDATO_VOTOS)
            else {
                continue;
            };
            let Some(punto) = self.cadena.candidato_por_slot(tope) else {
                continue;
            };
            if self.raices.raiz(epoca, &punto).is_some() || self.raices.pendiente(epoca, &punto) {
                continue;
            }
            let Some(estado) = self.cadena.estado_post(&punto).cloned() else {
                continue;
            };
            self.raices.solicitar(epoca, punto, estado);
            self.raices_solicitadas
                .insert(epoca, (punto, Instant::now()));
        }
        self.raices.podar(epoca_actual);
        self.raices_solicitadas
            .retain(|epoca, _| *epoca >= epoca_actual);
        self.raiz_no_lista_avisadas.retain(|(n_aviso, _)| {
            crate::raiz_punto::epoca_de_raiz(*n_aviso).is_some_and(|e| e >= epoca_actual)
        });
    }

    /// A1-D2b · W5 · anota en el registro los cálculos terminados desde la última vez, con su
    /// cronómetro (del nodo, no medida limpia).
    pub(super) fn anunciar_raices_calculadas(&mut self) {
        let mut listas: Vec<(u64, BlockHash, [u8; 32], u64)> = Vec::new();
        for (epoca, (punto, inicio)) in &self.raices_solicitadas {
            if let Some(raiz) = self.raices.raiz(*epoca, punto) {
                let ms = u64::try_from(inicio.elapsed().as_millis()).unwrap_or(u64::MAX);
                listas.push((*epoca, *punto, raiz, ms));
            }
        }
        for (epoca, punto, raiz, ms) in listas {
            self.raices_solicitadas.remove(&epoca);
            let _ = self.registro.escribir(
                self.registro
                    .evento("raiz_estado_calculada")
                    .u64("epoca", epoca)
                    .str("punto", &hex(punto.as_bytes()))
                    .str("raiz", &hex(&raiz))
                    .u64("ms", ms),
                false,
            );
        }
    }

    /// A1-D2b · W3 · escribe **una** línea `raiz_estado_no_lista` por `(ventana, punto)`.
    pub(super) fn avisar_raiz_no_lista(&mut self, n: u64, epoca: u64, punto: BlockHash) {
        if !self.raiz_no_lista_avisadas.insert((n, punto)) {
            return;
        }
        let _ = self.registro.escribir(
            self.registro
                .evento("raiz_estado_no_lista")
                .u64("n", n)
                .u64("epoca", epoca)
                .str("punto", &hex(punto.as_bytes())),
            false,
        );
    }
}

/// REAN-2 · N4/N5 · vista real del candado del motor de votos sobre la **cadena seleccionada**.
impl crate::votos::VistaCadena for zx_cadena::Cadena {
    fn desciende(&self, candidato: &zx_votos::Hash, ancestro: &zx_votos::Hash) -> bool {
        let c = BlockHash::from_digest(Digest::from_bytes(*candidato));
        let a = BlockHash::from_digest(Digest::from_bytes(*ancestro));
        self.desciende_en_cadena_seleccionada(&c, &a)
    }

    fn en_cadena_seleccionada(&self, hash: &zx_votos::Hash) -> bool {
        let h = BlockHash::from_digest(Digest::from_bytes(*hash));
        self.en_cadena_seleccionada(&h)
    }

    fn slot_de(&self, hash: &zx_votos::Hash) -> Option<u64> {
        let h = BlockHash::from_digest(Digest::from_bytes(*hash));
        self.slot_de(&h)
    }

    /// DFV-1 · D5 · conflicto **en el grafo de bloques** (no solo en la cadena seleccionada).
    fn en_conflicto(&self, a: &zx_votos::Hash, b: &zx_votos::Hash) -> bool {
        let a = BlockHash::from_digest(Digest::from_bytes(*a));
        let b = BlockHash::from_digest(Digest::from_bytes(*b));
        self.en_conflicto_en_dag(&a, &b)
    }

    /// DFV-1 · D6 · hecho de la evidencia entre ventanas con la misma función que la cadena usa al
    /// incluirla.
    fn hecho_evidencia_entre_ventanas(
        &self,
        voto1: &zx_core::VotoPesoEvidencia,
        voto2: &zx_core::VotoPesoEvidencia,
        plazo_slots: u64,
    ) -> Option<zx_consensus::transicion::HechoVoto> {
        self.hecho_voto_entre_ventanas(voto1, voto2, plazo_slots)
    }
}

/// A1-D2b · W1 · el bloque punto que toca a la ventana `n`: época `epoca_de_raiz(n)`, tope de slot
/// `tope_de_punto(época, t_inst, lag)` y `Cadena::candidato_por_slot`. `None` si falta cualquier
/// paso.
pub(super) fn punto_de_ventana(
    cadena: &Cadena,
    n: u64,
    t_inst: u64,
    lag: u64,
) -> Option<(u64, BlockHash)> {
    let epoca = crate::raiz_punto::epoca_de_raiz(n)?;
    let tope = crate::raiz_punto::tope_de_punto(epoca, t_inst, lag)?;
    let punto = cadena.candidato_por_slot(tope)?;
    Some((epoca, punto))
}

/// A1-D2b · W1 · vista del motor de votos que entrega la raíz de estado del punto de la época.
///
/// Delega **todo** en la cadena seleccionada (igual que `impl VistaCadena for zx_cadena::Cadena`,
/// que no se toca) y solo añade [`VistaCadena::raiz_estado_de_voto`]: busca el punto de la época de
/// `n` y devuelve la raíz guardada **para esa época y ese punto**. Si falta cualquier paso, si el
/// nodo no vota (W4), o si el candidato no desciende del punto ni es el punto: [`RAIZ_ESTADO_CERO`].
pub(super) struct VistaConRaiz<'a> {
    pub(super) cadena: &'a Cadena,
    pub(super) raices: &'a crate::raiz_punto::RaicesPunto,
    pub(super) vota: bool,
    pub(super) t_inst: u64,
    pub(super) lag: u64,
    /// A1-D2b · W3 · el punto de la ventana cuya raíz no estaba lista, para que el nodo escriba su
    /// aviso una sola vez.
    pub(super) aviso: &'a std::cell::Cell<Option<(u64, u64, BlockHash)>>,
}

impl VistaCadena for VistaConRaiz<'_> {
    fn desciende(&self, candidato: &zx_votos::Hash, ancestro: &zx_votos::Hash) -> bool {
        <Cadena as VistaCadena>::desciende(self.cadena, candidato, ancestro)
    }

    fn en_cadena_seleccionada(&self, hash: &zx_votos::Hash) -> bool {
        <Cadena as VistaCadena>::en_cadena_seleccionada(self.cadena, hash)
    }

    fn slot_de(&self, hash: &zx_votos::Hash) -> Option<u64> {
        <Cadena as VistaCadena>::slot_de(self.cadena, hash)
    }

    fn en_conflicto(&self, a: &zx_votos::Hash, b: &zx_votos::Hash) -> bool {
        <Cadena as VistaCadena>::en_conflicto(self.cadena, a, b)
    }

    fn hecho_evidencia_entre_ventanas(
        &self,
        voto1: &zx_core::VotoPesoEvidencia,
        voto2: &zx_core::VotoPesoEvidencia,
        plazo_slots: u64,
    ) -> Option<zx_consensus::transicion::HechoVoto> {
        <Cadena as VistaCadena>::hecho_evidencia_entre_ventanas(
            self.cadena,
            voto1,
            voto2,
            plazo_slots,
        )
    }

    fn raiz_estado_de_voto(&self, n: u64, candidato: &zx_votos::Hash) -> zx_votos::Hash {
        if !self.vota {
            return RAIZ_ESTADO_CERO;
        }
        let Some((epoca, punto)) = punto_de_ventana(self.cadena, n, self.t_inst, self.lag) else {
            return RAIZ_ESTADO_CERO;
        };
        let punto_hash = *punto.as_bytes();
        if *candidato != punto_hash && !self.desciende(candidato, &punto_hash) {
            return RAIZ_ESTADO_CERO;
        }
        match self.raices.raiz(epoca, &punto) {
            Some(raiz) => raiz,
            None => {
                self.aviso.set(Some((n, epoca, punto)));
                RAIZ_ESTADO_CERO
            }
        }
    }
}
