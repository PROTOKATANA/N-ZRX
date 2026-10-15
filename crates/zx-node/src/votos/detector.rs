//! DFV-1 · D1–D10 · detector de la **falta entre ventanas** (contrato v2, parte B; IPA B-63).
//!
//! El motor de votos, hasta hoy, solo emparejaba votos de la **misma** instancia: al abrir una
//! ventana nueva, `Instancia` se sustituía y los votos viejos se perdían. Este módulo conserva los
//! votos válidos de las ventanas del **horizonte**, los empareja por clave cuando sus candidatos
//! están en conflicto **en el grafo de bloques** y deja la evidencia `0x0B` lista para el nodo.
//!
//! Límites declarados (ver `INFORME.md`):
//! - **A5-c-1c · T1/T2 · B-71.** El detector solo guarda las claves que caen en las **subredes
//!   vigiladas** que fija el motor (`fijar_vigiladas`; `None` = todas, el modo biblioteca y las
//!   pruebas existentes). La subred de una clave es `zx_votos::agregacion::subred(clave, S)`. Un
//!   voto de otra subred no entra por ningún camino, y en `registrar_voto_pasado` la comprobación
//!   va antes de la criptografía.
//! - La validación local de un voto de ventana pasada es (G1) **pertenencia** de su clave a la
//!   tabla de la ventana **abierta** o a los **apuntes salientes** de T4 (`v.n ≤ última`), después
//!   firma BLS (con la clave que el propio voto lleva) + mensaje A3. La pertenencia/peso de la clave
//!   en la tabla de **esa** ventana pasada la decide la cadena al admitir la evidencia; el nodo no
//!   guarda 450 tablas, así que una clave retirada antes de la ventana abierta, sin apunte vigente,
//!   no se considera (límite de DFV-1-2, acotado por T4).
//! - G2 · el detector no guarda más de `2 · horizonte · claves vigiladas` votos en total, donde
//!   «claves vigiladas» son las de la tabla abierta que caen en subredes vigiladas más las claves
//!   salientes apuntadas (T3/T4); al llegar al tope descarta el voto nuevo y no borra los guardados.
//! - El detector se pierde al reiniciar (memoria del proceso).
//! - La relación «en conflicto» es la del **grafo de bloques** (D5). La `hecho_de_tx` de la cadena
//!   usa un recorrido por la cadena seleccionada (B1.1); D6 filtra con ella, de modo que nunca se
//!   publica una evidencia que la cadena no considere falta. Caso declarado en `PROGRESO.md`.

use std::collections::{HashMap, HashSet};

use zx_consensus::transicion::HechoVoto;
use zx_core::VotoPesoEvidencia;
use zx_votos::agregacion::subred;
use zx_votos::{Firma, Hash};

use super::{EvidenciaVotosPesoCompleta, LONGITUD_CLAVE_BLS, SUBREDES_VOTO_RED, VistaCadena};
use crate::mempool::identidad_de_votos;

/// DFV-1 · un voto por peso guardado por el detector.
///
/// Son 200 B (`8` de ventana + `3·32` de hashes + `96` de firma), el mismo tamaño que documenta
/// `zx-votos` para un voto.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VotoDetector {
    /// Ventana del voto.
    pub n: u64,
    /// Candidato `h_B` votado.
    pub candidato: Hash,
    /// `h_T(n+1)` declarado.
    pub h_t_siguiente: Hash,
    /// Raíz de estado firmada.
    pub raiz_estado: Hash,
    /// Firma BLS individual sobre A3.
    pub firma: Firma,
}

impl VotoDetector {
    /// Bytes exactos que ocupa este voto dentro del detector.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn bytes() -> usize {
        8 + 3 * 32 + 96
    }

    /// Convierte al formato de voto de la operación `0x0B`.
    #[must_use]
    pub(crate) fn a_evidencia(&self) -> VotoPesoEvidencia {
        VotoPesoEvidencia {
            n: self.n,
            candidato: self.candidato,
            h_t_siguiente: self.h_t_siguiente,
            raiz_estado: self.raiz_estado,
            firma: self.firma.bytes(),
        }
    }
}

/// DFV-1 · camino rápido por clave.
#[derive(Clone, Copy, Debug)]
struct ClaveEstado {
    /// Candidato del que descienden todos los votos guardados cuando `cadena`.
    tip: VotoDetector,
    /// ¿Todos los votos guardados forman cadena desde `tip`?
    cadena: bool,
    /// ¿Hay algún voto que no desciende del `tip` y exige revisar parejas al drenar?
    revisar: bool,
}

/// DFV-1 · D1–D9 · estado del detector entre ventanas.
pub(crate) struct DetectorFalta {
    /// D2 · ventanas del horizonte (`(F_SLOTS + plazo) / T_inst`).
    horizonte: u64,
    /// Plazo de admisión de la evidencia (slots), el del perfil/estado.
    plazo_slots: u64,
    /// D1 · por clave, todos los votos guardados dentro del horizonte (≤ 2 por ventana).
    por_clave: HashMap<[u8; LONGITUD_CLAVE_BLS], Vec<VotoDetector>>,
    /// Camino rápido del votante honesto (`D4`).
    estado: HashMap<[u8; LONGITUD_CLAVE_BLS], ClaveEstado>,
    /// D4 · caché de la relación «en conflicto» entre candidatos, una vez por pareja de bloques.
    conflictos: HashMap<(Hash, Hash), bool>,
    /// D8 · claves cubiertas por una entrada real admitida y aún no aplicada.
    acusadas: HashSet<[u8; LONGITUD_CLAVE_BLS]>,
    /// EV-1 · una oferta por clave/ventana, sin confundir oferta con acusación.
    ofrecidas: HashMap<[u8; LONGITUD_CLAVE_BLS], u64>,
    revisadas: HashMap<[u8; LONGITUD_CLAVE_BLS], u64>,
    /// Solo el incidente del par operativo; los votos siguen siendo las únicas copias del material.
    operativas: HashMap<[u8; LONGITUD_CLAVE_BLS], [u8; 32]>,
    ventana: u64,
    /// DFV-1-2 · G2 · tope total de votos guardados (`2 · horizonte · claves de la tabla abierta`);
    /// `usize::MAX` mientras no lo fija el motor (modo biblioteca, tests del detector).
    tope: usize,
    /// DFV-1-2 · G2 · votos guardados ahora mismo; crece al registrar y se recalcula al podar.
    total: usize,
    /// T1 · B-71 · número de subredes `S` de la red (para repartir las claves).
    subredes: u16,
    /// T1 · B-71 · subredes vigiladas; `None` = todas (comportamiento de hoy: un olvido del nodo
    /// peca de vigilar de más, no de menos). Una lista vacía se representa como `Some(∅)`.
    vigiladas: Option<HashSet<u16>>,
}

impl DetectorFalta {
    /// Crea el detector con el horizonte derivado de las constantes del consenso.
    #[must_use]
    pub(crate) fn nuevo(t_inst: u64, plazo_slots: u64) -> Self {
        let t = t_inst.max(1);
        let horizonte = crate::perfil::F_SLOTS
            .saturating_add(crate::perfil::PLAZO_SLOTS)
            .div_euclid(t);
        Self {
            horizonte,
            plazo_slots,
            por_clave: HashMap::new(),
            estado: HashMap::new(),
            conflictos: HashMap::new(),
            acusadas: HashSet::new(),
            ofrecidas: HashMap::new(),
            revisadas: HashMap::new(),
            operativas: HashMap::new(),
            ventana: 0,
            tope: usize::MAX,
            total: 0,
            subredes: SUBREDES_VOTO_RED,
            vigiladas: None,
        }
    }

    /// D2 · horizonte efectivo en ventanas.
    #[must_use]
    pub(crate) const fn horizonte(&self) -> u64 {
        self.horizonte
    }

    /// T1 · B-71 · ¿la clave cae en una subred vigilada?
    ///
    /// Mientras nadie llame a [`Self::fijar_vigiladas`], devuelve `true` para toda clave (se vigila
    /// todo). Con lista vacía, `false` siempre.
    #[must_use]
    pub(crate) fn vigila(&self, clave: &[u8; LONGITUD_CLAVE_BLS]) -> bool {
        match &self.vigiladas {
            None => true,
            Some(set) => subred(clave, self.subredes).is_ok_and(|s| set.contains(&s)),
        }
    }

    /// T1 · B-71 · fija `S` y las subredes vigiladas, y **borra** lo ya guardado de otras subredes.
    pub(crate) fn fijar_vigiladas(&mut self, subredes: u16, vigiladas: Option<HashSet<u16>>) {
        self.subredes = subredes;
        self.vigiladas = vigiladas;
        // Copia local de la vigilancia para no pelear con el préstamo de los mapas.
        let s = self.subredes;
        let v = self.vigiladas.clone();
        let vigila = |clave: &[u8; LONGITUD_CLAVE_BLS]| -> bool {
            match &v {
                None => true,
                Some(set) => subred(clave, s).is_ok_and(|x| set.contains(&x)),
            }
        };
        self.por_clave.retain(|clave, _| vigila(clave));
        self.estado.retain(|clave, _| vigila(clave));
        self.acusadas.retain(vigila);
        self.ofrecidas.retain(|k, _| vigila(k));
        self.revisadas.retain(|k, _| vigila(k));
        self.operativas.retain(|k, _| vigila(k));
        self.total = self.por_clave.values().map(Vec::len).sum();
    }

    /// Solo pruebas: tope total vigente.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn tope(&self) -> usize {
        self.tope
    }

    /// D2 · parámetro interno: fija el horizonte (solo pruebas).
    #[cfg(test)]
    pub(crate) fn fijar_horizonte(&mut self, horizonte: u64) {
        self.horizonte = horizonte;
    }

    /// DFV-1-2 · G2 · fija el tope total **derivado** de las claves de la tabla de la ventana
    /// abierta: `2 · horizonte · claves_tabla` (ningún literal). No borra lo ya guardado; a partir
    /// de aquí, todo voto nuevo que llegue con el tope alcanzado se descarta.
    pub(crate) fn fijar_tope(&mut self, claves_tabla: usize) {
        let horizonte = usize::try_from(self.horizonte).unwrap_or(usize::MAX);
        self.tope = claves_tabla.saturating_mul(2).saturating_mul(horizonte);
    }

    /// Solo pruebas: votos guardados en total.
    #[cfg(test)]
    pub(crate) fn votos_guardados(&self) -> usize {
        self.total
    }

    /// D9 · al abrir la ventana `n` se borra lo anterior al horizonte.
    pub(crate) fn al_abrir(&mut self, n: u64) {
        self.ventana = self.ventana.max(n);
        let limite = n.saturating_sub(self.horizonte);
        self.por_clave.retain(|_, votos| {
            votos.retain(|v| v.n > limite);
            !votos.is_empty()
        });
        let sin_votos: Vec<[u8; LONGITUD_CLAVE_BLS]> = self
            .estado
            .keys()
            .filter(|clave| !self.por_clave.contains_key(*clave))
            .copied()
            .collect();
        for clave in sin_votos {
            self.estado.remove(&clave);
            self.acusadas.remove(&clave);
            // La marca de servicio vive mientras la clave conserva material.
            self.ofrecidas.remove(&clave);
            self.revisadas.remove(&clave);
            self.operativas.remove(&clave);
        }
        for (clave, estado) in &mut self.estado {
            // D4: el votante honesto sigue por el camino lineal; no revisar todos sus pares.
            let mut ventanas = HashSet::new();
            let misma = self
                .por_clave
                .get(clave)
                .is_some_and(|votos| votos.iter().any(|v| !ventanas.insert(v.n)));
            estado.revisar = !estado.cadena || misma;
        }
        // La ausencia de un bloque no es un conflicto false permanente.
        self.conflictos.clear();
        // G2 · la poda cambia el total guardado; se recalcula una vez por apertura.
        self.total = self.por_clave.values().map(Vec::len).sum();
    }

    /// D1/D4/D5 · registra un voto ya validado (firma A3 y raíz) y decide si hay que revisar la
    /// clave al drenar. `vista` da la relación de conflicto **en el grafo**.
    pub(crate) fn registrar(
        &mut self,
        clave: [u8; LONGITUD_CLAVE_BLS],
        voto: VotoDetector,
        vista: &dyn VistaCadena,
    ) {
        // T2 · B-71 · solo entra el voto cuya clave cae en una subred vigilada, por cualquier
        // camino. El motor además comprueba lo mismo **antes de la criptografía**; esta guarda es
        // la red de seguridad para no guardar nunca lo que no se vigila.
        if !self.vigila(&clave) {
            return;
        }
        // DFV-1-2 · G2 · al llegar al tope total se descarta el voto nuevo; no se borra ninguno de
        // los guardados.
        if self.total >= self.tope {
            return;
        }
        // D1 · a lo sumo dos votos **distintos** por clave y ventana; un duplicado exacto no cuenta.
        if let Some(votos) = self.por_clave.get(&clave) {
            let mut en_ventana = 0usize;
            for v in votos {
                if v.n != voto.n {
                    continue;
                }
                if v.candidato == voto.candidato
                    && v.h_t_siguiente == voto.h_t_siguiente
                    && v.raiz_estado == voto.raiz_estado
                {
                    return;
                }
                en_ventana += 1;
            }
            if en_ventana >= 2 {
                return;
            }
        }
        // Camino rápido: con votante honesto, cada voto desciende del `tip` y no hay nada que
        // revisar; cualquier voto que no descienda del `tip` deja la clave pendiente de revisión.
        let nuevo = match self.estado.get(&clave).copied() {
            None => ClaveEstado {
                tip: voto,
                cadena: true,
                revisar: false,
            },
            Some(estado) if estado.cadena => {
                if voto.candidato == estado.tip.candidato
                    || vista.desciende(&voto.candidato, &estado.tip.candidato)
                {
                    ClaveEstado {
                        tip: voto,
                        cadena: true,
                        revisar: false,
                    }
                } else {
                    ClaveEstado {
                        tip: estado.tip,
                        cadena: false,
                        revisar: true,
                    }
                }
            }
            Some(estado) => ClaveEstado {
                revisar: true,
                ..estado
            },
        };
        let misma_ventana = self
            .por_clave
            .get(&clave)
            .is_some_and(|votos| votos.iter().any(|v| v.n == voto.n));
        self.estado.insert(
            clave,
            ClaveEstado {
                revisar: nuevo.revisar || misma_ventana,
                ..nuevo
            },
        );
        self.por_clave.entry(clave).or_default().push(voto);
        self.total = self.total.saturating_add(1);
    }

    /// Oferta recuperable de biblioteca: no marca acusadas. Una oferta por apertura.
    pub(crate) fn drenar(&mut self, vista: &dyn VistaCadena) -> Vec<EvidenciaVotosPesoCompleta> {
        self.ofrecer(vista, None, self.plazo_slots, &HashSet::new(), false)
    }

    /// EV-1 · producción: consultas y ofertas acotadas por clave y ventana de servicio.
    pub(crate) fn hay_material_revisable_en(&self, n: u64) -> bool {
        let ventana = self.ventana.max(n);
        self.estado.iter().any(|(clave, estado)| {
            estado.revisar
                && !self.acusadas.contains(clave)
                && self
                    .ofrecidas
                    .get(clave)
                    .is_none_or(|ultima| *ultima < ventana)
                && self
                    .revisadas
                    .get(clave)
                    .is_none_or(|ultima| *ultima < ventana)
        })
    }

    /// EV-1 · producción: consultas y ofertas acotadas por clave y ventana de servicio.
    pub(crate) fn ofrecer_en(
        &mut self,
        vista: &dyn VistaCadena,
        n: u64,
        slot: u64,
        plazo: u64,
        aplicados: &HashSet<[u8; 32]>,
    ) -> Vec<EvidenciaVotosPesoCompleta> {
        // Solo una poda por apertura de servicio, también si el motor espera tabla/candidato.
        if n > self.ventana {
            self.al_abrir(n);
        }
        self.ofrecer(vista, Some(slot), plazo, aplicados, true)
    }

    fn ofrecer(
        &mut self,
        vista: &dyn VistaCadena,
        slot: Option<u64>,
        plazo: u64,
        aplicados: &HashSet<[u8; 32]>,
        misma_ventana: bool,
    ) -> Vec<EvidenciaVotosPesoCompleta> {
        let mut salida = Vec::new();
        let revisar: Vec<_> = self
            .estado
            .iter()
            .filter(|(clave, estado)| estado.revisar && !self.acusadas.contains(*clave))
            .map(|(clave, _)| *clave)
            .collect();
        for clave in revisar {
            if self
                .ofrecidas
                .get(&clave)
                .is_some_and(|n| *n >= self.ventana)
                || (slot.is_some()
                    && self
                        .revisadas
                        .get(&clave)
                        .is_some_and(|n| *n >= self.ventana))
            {
                continue;
            }
            if slot.is_some() {
                self.revisadas.insert(clave, self.ventana);
            }
            let Some(votos) = self.por_clave.get(&clave) else {
                continue;
            };
            let mut elegido: Option<(bool, u64, [u8; 32], VotoDetector, VotoDetector)> = None;
            'parejas: for (i, &a) in votos.iter().enumerate() {
                for &b in votos.iter().skip(i + 1) {
                    let (v1, v2) = orden_canonico(a, b);
                    let e1 = v1.a_evidencia();
                    let e2 = v2.a_evidencia();
                    let fin =
                        zx_consensus::transicion::votos::cierre_ventana(v2.n).saturating_add(plazo);
                    if slot.is_some_and(|s| s > fin) {
                        continue;
                    }
                    if a.n == b.n {
                        if !misma_ventana {
                            continue;
                        }
                    } else if a.candidato == b.candidato
                        || !en_conflicto_cache(
                            &mut self.conflictos,
                            vista,
                            &a.candidato,
                            &b.candidato,
                        )
                        || vista.hecho_evidencia_entre_ventanas(&e1, &e2, plazo)
                            != Some(HechoVoto::Falta)
                    {
                        continue;
                    }
                    let identidad = identidad_de_votos(&clave, &e1, &e2);
                    if aplicados.contains(&identidad.incidente) {
                        continue;
                    }
                    // Mantener el mismo par mientras sea vigente. Después, menor plazo e incidente.
                    let distinto = self.operativas.get(&clave) != Some(&identidad.incidente);
                    if elegido
                        .as_ref()
                        .is_none_or(|e| (distinto, fin, identidad.incidente) < (e.0, e.1, e.2))
                    {
                        elegido = Some((distinto, fin, identidad.incidente, v1, v2));
                        if !distinto {
                            break 'parejas;
                        }
                    }
                }
            }
            if let Some((_, _, incidente, v1, v2)) = elegido {
                self.ofrecidas.insert(clave, self.ventana);
                self.operativas.insert(clave, incidente);
                salida.push(EvidenciaVotosPesoCompleta {
                    n: v1.n,
                    n2: v2.n,
                    h1: v1.candidato,
                    h_t1: v1.h_t_siguiente,
                    raiz1: v1.raiz_estado,
                    firma1: v1.firma,
                    clave_bls: clave,
                    h2: v2.candidato,
                    h_t2: v2.h_t_siguiente,
                    raiz2: v2.raiz_estado,
                    firma2: v2.firma,
                });
            }
            // SinFalta/Inadmisible siguen recuperables; al_abrir invalida la caché y revisa.
        }
        salida.sort_by(|a, b| {
            a.clave_bls
                .cmp(&b.clave_bls)
                .then_with(|| a.n.cmp(&b.n))
                .then_with(|| a.h1.cmp(&b.h1))
                .then_with(|| a.h2.cmp(&b.h2))
        });
        salida
    }

    /// Una entrega de biblioteca consume el cupo pero no acusa.
    pub(crate) fn anotar_oferta(&mut self, clave: &[u8; LONGITUD_CLAVE_BLS]) -> bool {
        if self.acusadas.contains(clave)
            || self
                .ofrecidas
                .get(clave)
                .is_some_and(|n| *n >= self.ventana)
        {
            return false;
        }
        self.ofrecidas.insert(*clave, self.ventana);
        true
    }

    pub(crate) fn liberar_acusada(&mut self, clave: &[u8; LONGITUD_CLAVE_BLS]) {
        self.acusadas.remove(clave);
    }

    /// D8 · marca únicamente después de que la cola pruebe admisión o cobertura real.
    pub(crate) fn marcar_acusada(&mut self, clave: &[u8; LONGITUD_CLAVE_BLS]) {
        self.acusadas.insert(*clave);
    }

    /// DH-2 · cuenta de bytes lógicos ocupados por el detector: por voto (`VotoDetector::bytes`),
    /// por clave (48 B) y por caché/acusadas. No cuenta la sobrecarga interna de los `HashMap`
    /// (cubos); se declara en `INFORME.md`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn memoria_bytes(&self) -> usize {
        const CLAVE: usize = 48;
        let mut total = 0usize;
        for votos in self.por_clave.values() {
            total = total.saturating_add(CLAVE + std::mem::size_of::<Vec<VotoDetector>>());
            total = total.saturating_add(votos.capacity() * VotoDetector::bytes());
        }
        total = total.saturating_add(
            self.estado
                .len()
                .saturating_mul(CLAVE + std::mem::size_of::<ClaveEstado>()),
        );
        total = total.saturating_add(
            self.conflictos
                .len()
                .saturating_mul(std::mem::size_of::<(Hash, Hash)>() + 1),
        );
        total = total.saturating_add(self.acusadas.len() * CLAVE);
        total = total.saturating_add(self.ofrecidas.len().saturating_mul(CLAVE + 8));
        total = total.saturating_add(self.revisadas.len().saturating_mul(CLAVE + 8));
        total = total.saturating_add(self.operativas.len().saturating_mul(CLAVE + 32));
        total
    }
}

/// D4/D5 · conflicto entre dos candidatos con caché por pareja de bloques.
fn en_conflicto_cache(
    cache: &mut HashMap<(Hash, Hash), bool>,
    vista: &dyn VistaCadena,
    a: &Hash,
    b: &Hash,
) -> bool {
    if a == b {
        return false;
    }
    let k = if a < b { (*a, *b) } else { (*b, *a) };
    if let Some(&r) = cache.get(&k) {
        return r;
    }
    let r = vista.en_conflicto(a, b);
    cache.insert(k, r);
    r
}

/// D7 · orden canónico del `0x0B`: `(n, candidato, h_t_siguiente, raíz)` creciente.
fn orden_canonico(a: VotoDetector, b: VotoDetector) -> (VotoDetector, VotoDetector) {
    if (a.n, a.candidato, a.h_t_siguiente, a.raiz_estado)
        < (b.n, b.candidato, b.h_t_siguiente, b.raiz_estado)
    {
        (a, b)
    } else {
        (b, a)
    }
}
