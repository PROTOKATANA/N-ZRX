//! Detector de doble firma (`ORDEN-SL4b2` decisión 3) y lista de evidencias pendientes de incluir
//! (decisión 4).
//!
//! # Qué indexa y qué no
//!
//! [`DetectorDobleFirma::observar`] indexa por identidad de oportunidad `RAT-1`
//! (`zx_post::firmante::Firmante::identidad`, la misma que usa el firmante seguro y la evidencia de
//! consenso) la **primera** cabecera PoST vista cuya puerta conjunta (sello, PoT, PoAS, padres) ya
//! pasó, **con independencia** de que la admisión posterior (GHOSTDAG, estado) la acepte o la
//! rechace: el llamante (`crate::nodo`) solo invoca [`DetectorDobleFirma::observar`] después de que
//! `zx_post::cabecera_conjunta::verificar_cabecera_conjunta` haya verificado la cabecera, nunca
//! antes — es la manera de que el detector no pueda llenarse con sellos de la propia clave de un
//! par sobre cabeceras inventadas (decisión 3, último párrafo): indexar solo lo que costó una
//! prueba PoAS real.
//!
//! Una segunda cabecera con la **misma** identidad y **otro** `pre_hash` produce una `EvidenceTx`
//! v4 en orden canónico (`pre_hash(H1) <_lex pre_hash(H2)`, EV-01) y una entrada en la lista de
//! pendientes, con clave `incident_id` (EV-10): tres cabeceras del mismo billete comparten
//! `incident_id` y solo la primera detección produce una pendiente nueva (EV-10/EV-12).
//!
//! # Poda y tope
//!
//! Las vistas se podan por `slot < slot_actual − plazo_slots` (mismo criterio que el registro del
//! firmante, FIR-10/EV-11). El tope explícito `MAX_IDENTIDADES_DETECTOR` desaloja, al superarse, la
//! identidad de **menor slot** conocida (evento `limite_alcanzado`, igual que cualquier otro límite
//! `C-NET`): es una cota de memoria local, no una regla de consenso.
//!
//! Las pendientes se podan cuando su ventana de admisión cierra (`EV-13/EV-14`:
//! `slot_actual >= slot_falta + Plazo_slots`). **No** se podan por haberse incluido en un bloque
//! propio: decisión 4 exige que, si ese bloque sale de la cadena seleccionada, la pendiente
//! **vuelva a ser elegible** — así que la única fuente de verdad sobre "ya está resuelta" es el
//! estado de la punta que se consulta en cada intento de inclusión (`crate::nodo`), nunca un
//! marcado interno de este módulo.

use std::collections::BTreeMap;

use zx_consensus::transicion::Estado;
use zx_core::preimage::dag::DagBlockHeader;
use zx_core::{ExtensionTx, PreHash, Tx, incident_id_evidencia};
use zx_post::firmante::{Firmante, IdentidadTicket};

/// Un incidente de doble firma detectado, con su `EvidenceTx` v4 ya construida.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pendiente {
    /// `incident_id` (EV-10): la clave de esta lista.
    pub incident_id: [u8; 32],
    /// `slot_falta = slot(H1) = slot(H2)` (EV-13).
    pub slot_falta: u64,
    /// La transacción v4 (`ExtensionTx::Evidencia { h1, h2 }`), con `H1`/`H2` en orden canónico.
    pub tx: Tx,
}

/// Resultado de [`DetectorDobleFirma::observar`].
#[derive(Debug)]
pub enum Observacion {
    /// Primera vez que se ve esta identidad: queda indexada, no hay falta.
    Nueva,
    /// Misma identidad, mismo `pre_hash`: retransmisión de la misma cabecera, no hay falta.
    MismaCabecera,
    /// Misma identidad, otro `pre_hash`, y el incidente **no** estaba ya pendiente: se detectó una
    /// falta nueva. Trae la [`Pendiente`] recién construida (el llamante decide si escribe
    /// `evidencia_detectada` y la añade a su lista). Boxeada: `Pendiente` lleva dos cabeceras
    /// completas (hasta 1037 B cada una) y `Nueva`/`MismaCabecera` no llevan nada.
    Incidente(Box<Pendiente>),
    /// Misma identidad, otro `pre_hash`, pero **ya** había una pendiente con este `incident_id`
    /// (tercera cabecera del mismo billete, EV-10/EV-12): no se produce una evidencia nueva.
    IncidenteYaPendiente {
        /// El `incident_id` ya conocido.
        incident_id: [u8; 32],
    },
}

/// Detector de doble firma + lista de pendientes (decisiones 3 y 4 de `ORDEN-SL4b2`).
pub struct DetectorDobleFirma {
    /// Primera cabecera vista por identidad de oportunidad.
    vistas: BTreeMap<IdentidadTicket, DagBlockHeader>,
    /// Índice secundario `slot -> identidades con ese slot`, para podar/desalojar por el más viejo
    /// sin recorrer todo `vistas` (`MAX_IDENTIDADES_DETECTOR` hace que un recorrido lineal por
    /// inserción sea descartable, pero mantener este índice es igual de simple y evita
    /// reconsiderarlo si el tope sube).
    por_slot: BTreeMap<u64, Vec<IdentidadTicket>>,
    /// Incidentes detectados, pendientes de incluir (decisión 4), por `incident_id`.
    pendientes: BTreeMap<[u8; 32], Pendiente>,
    /// Tope de `vistas` (`MAX_IDENTIDADES_DETECTOR`).
    tope: usize,
}

/// Evento a registrar cuando el tope se alcanza y se desaloja una identidad (decisión 3).
#[derive(Debug, Clone, Copy)]
pub struct LimiteAlcanzado {
    /// Slot de la identidad desalojada.
    pub slot_desalojado: u64,
}

impl DetectorDobleFirma {
    /// Un detector nuevo, vacío, con el tope dado (`crate::perfil::MAX_IDENTIDADES_DETECTOR`).
    #[must_use]
    pub fn nuevo(tope: usize) -> Self {
        Self {
            vistas: BTreeMap::new(),
            por_slot: BTreeMap::new(),
            pendientes: BTreeMap::new(),
            tope,
        }
    }

    /// Cuántas identidades indexa ahora mismo.
    #[must_use]
    pub fn identidades_indexadas(&self) -> usize {
        self.vistas.len()
    }

    fn quitar_de_por_slot(&mut self, slot: u64, id: &IdentidadTicket) {
        if let std::collections::btree_map::Entry::Occupied(mut e) = self.por_slot.entry(slot) {
            e.get_mut().retain(|x| x != id);
            if e.get().is_empty() {
                e.remove();
            }
        }
    }

    /// Desaloja la identidad de menor slot conocido (decisión 3: tope explícito). Devuelve el slot
    /// desalojado si había algo que desalojar.
    fn desalojar_mas_vieja(&mut self) -> Option<LimiteAlcanzado> {
        let (&slot_mas_viejo, ids) = self.por_slot.iter().next()?;
        let id = *ids.first()?;
        self.vistas.remove(&id);
        self.quitar_de_por_slot(slot_mas_viejo, &id);
        Some(LimiteAlcanzado {
            slot_desalojado: slot_mas_viejo,
        })
    }

    /// Observa una cabecera PoST **cuya puerta conjunta ya pasó** (decisión 3: el llamante nunca
    /// invoca esto para una cabecera que la puerta conjunta rechazó — el detector no comprueba PoT,
    /// PoAS ni el sello, se fía de que el llamante lo hizo). `cbid_local` es el
    /// `consensus_branch_id` de la red local (`ParametrosEvidencia::cbid`): el `EvidenceTx` que se
    /// construya solo es válido en la red local (`RAT-1`), y la cabecera ya lo trae (RAT-1 exige
    /// que ambas coincidan con el local, comprobado por `validar_forma_tx_v4` al aplicarla; aquí no
    /// hace falta duplicar esa comprobación porque ambas cabeceras del par salen de este mismo
    /// nodo, que solo observa cabeceras ya verificadas contra su propia red).
    ///
    /// Devuelve también, si el tope se superó al indexar una identidad nueva, el evento de
    /// desalojo (`limite_alcanzado`).
    pub fn observar(&mut self, cabecera: DagBlockHeader) -> (Observacion, Option<LimiteAlcanzado>) {
        let identidad = Firmante::identidad(&cabecera);
        let pre_hash_nueva = cabecera.pre_hash();

        if let Some(vista) = self.vistas.get(&identidad) {
            if vista.pre_hash() == pre_hash_nueva {
                return (Observacion::MismaCabecera, None);
            }
            // Identidad conocida, `pre_hash` distinto: doble firma (EV-06/EV-07 ya se satisfacen
            // por construcción: ambas cabeceras verificaron su sello bajo la misma `sol.public_key`
            // porque las dos pasaron la puerta conjunta antes de llegar aquí, C-HDR-04).
            let incident_id = *incident_id_evidencia(
                cabecera.consensus_branch_id,
                cabecera.sol.public_key.bytes(),
                cabecera.sol.sector_index,
                cabecera.sol.history_size,
                &cabecera.sol.chunk,
                cabecera.slot,
            )
            .as_bytes();
            if self.pendientes.contains_key(&incident_id) {
                return (Observacion::IncidenteYaPendiente { incident_id }, None);
            }
            let (h1, h2) = en_orden_canonico(*vista, cabecera);
            let tx = Tx {
                version: 4,
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: 0,
                expiry_height: 0,
                extension: ExtensionTx::Evidencia { h1, h2 },
            };
            let pendiente = Pendiente {
                incident_id,
                slot_falta: identidad.slot(),
                tx,
            };
            self.pendientes.insert(incident_id, pendiente.clone());
            return (Observacion::Incidente(Box::new(pendiente)), None);
        }

        // Identidad nueva: se indexa, con desalojo si hace falta.
        let mut limite = None;
        if self.vistas.len() >= self.tope {
            limite = self.desalojar_mas_vieja();
        }
        let slot = identidad.slot();
        self.vistas.insert(identidad, cabecera);
        self.por_slot.entry(slot).or_default().push(identidad);
        (Observacion::Nueva, limite)
    }

    /// Poda vistas con `slot < slot_actual − plazo_slots` (mismo criterio que el registro del
    /// firmante). Devuelve cuántas se podaron.
    pub fn podar_vistas(&mut self, slot_actual: u64, plazo_slots: u64) -> usize {
        let corte = slot_actual.saturating_sub(plazo_slots);
        let viejos: Vec<u64> = self.por_slot.range(..corte).map(|(&s, _)| s).collect();
        let mut podadas = 0usize;
        for slot in viejos {
            if let Some(ids) = self.por_slot.remove(&slot) {
                for id in ids {
                    self.vistas.remove(&id);
                    podadas += 1;
                }
            }
        }
        podadas
    }

    /// Poda pendientes cuya ventana de admisión cerró (`EV-13/EV-14`:
    /// `slot_actual >= slot_falta + plazo_slots`). Devuelve los `incident_id` podados (para que el
    /// llamante, si quiere, registre diagnóstico).
    pub fn podar_pendientes(&mut self, slot_actual: u64, plazo_slots: u64) -> Vec<[u8; 32]> {
        let cerrados: Vec<[u8; 32]> = self
            .pendientes
            .iter()
            .filter(|(_, p)| slot_actual >= p.slot_falta.saturating_add(plazo_slots))
            .map(|(id, _)| *id)
            .collect();
        for id in &cerrados {
            self.pendientes.remove(id);
        }
        cerrados
    }

    /// Las pendientes actuales, en orden de `incident_id` (determinista).
    pub fn pendientes(&self) -> impl Iterator<Item = &Pendiente> {
        self.pendientes.values()
    }

    /// Cuántas pendientes hay ahora mismo.
    #[must_use]
    pub fn pendientes_len(&self) -> usize {
        self.pendientes.len()
    }
}

/// Ordena dos cabeceras por `pre_hash` estrictamente ascendente (EV-01). Nunca produce `H1 = H2`
/// en la práctica: [`DetectorDobleFirma::observar`] solo llega aquí cuando los `pre_hash` ya se
/// comprobaron distintos.
fn en_orden_canonico(a: DagBlockHeader, b: DagBlockHeader) -> (DagBlockHeader, DagBlockHeader) {
    let (ph_a, ph_b): (PreHash, PreHash) = (a.pre_hash(), b.pre_hash());
    if ph_a < ph_b { (a, b) } else { (b, a) }
}

/// Filtra, de las pendientes del detector, las que un bloque con el estado base y el slot objetivo
/// dados puede incluir (`ORDEN-SL4b2` decisión 4; unitarios de inclusión de `ORDEN-SL4b3`).
///
/// Una pendiente es elegible si su ventana sigue abierta en `slot_objetivo`
/// (`slot_falta ≤ slot_objetivo < slot_falta + plazo_slots`) y su incidente **no** está ya procesado
/// en `estado_base` (el estado sobre el que se construye el bloque; `None` cuenta como no
/// procesado). Devuelve hasta `max_por_bloque` transacciones, en orden de `incident_id`.
///
/// No marca nada como incluido: si el bloque portador sale después de la cadena seleccionada, esta
/// misma consulta vuelve a devolver la pendiente (decisión 4: «vuelve a ser elegible»). La poda de
/// pendientes por cierre de ventana la hace [`DetectorDobleFirma::podar_pendientes`].
#[must_use]
pub fn elegibles(
    detector: &DetectorDobleFirma,
    estado_base: Option<&Estado>,
    slot_objetivo: u64,
    plazo_slots: u64,
    max_por_bloque: usize,
) -> Vec<Tx> {
    detector
        .pendientes()
        .filter(|p| ventana_abierta(p, slot_objetivo, plazo_slots))
        .filter(|p| !ya_procesado(p, estado_base))
        .take(max_por_bloque)
        .map(|p| p.tx.clone())
        .collect()
}

/// ¿La ventana de admisión de `p` sigue abierta en `slot_objetivo`? (`EV-13`).
fn ventana_abierta(p: &Pendiente, slot_objetivo: u64, plazo_slots: u64) -> bool {
    p.slot_falta <= slot_objetivo && slot_objetivo < p.slot_falta.saturating_add(plazo_slots)
}

/// ¿El incidente de `p` está ya procesado en `estado_base`? (`EV-11`).
fn ya_procesado(p: &Pendiente, estado_base: Option<&Estado>) -> bool {
    estado_base.is_some_and(|estado| {
        let clave = match &p.tx.extension {
            ExtensionTx::Evidencia { h1, .. } => h1.sol.public_key,
            _ => return false,
        };
        estado
            .garantias
            .get(&clave)
            .is_some_and(|g| g.incidentes.iter().any(|i| i.id == p.incident_id))
    })
}

#[cfg(test)]
#[expect(
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{DetectorDobleFirma, Observacion, elegibles};
    use zx_consensus::transicion::{Estado, Garantia, Incidente};
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_core::{BodyCommitment, ClavePublica, Digest, MerkleRoot};

    /// Cabecera de prueba. `sal` controla el `pre_hash` (vía `timestamp`) sin tocar la identidad.
    fn cabecera(
        cbid: u32,
        clave: u8,
        sector: u16,
        historia: u64,
        chunk: u8,
        slot: u64,
        sal: u64,
    ) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: cbid,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
            timestamp: sal,
            height: 0,
            slot,
            pot_output: [0x33; 16],
            rango_solucion: 7,
            sol: SolucionPoas {
                public_key: ClavePublica::desde_bytes([clave; 32]),
                sector_index: sector,
                history_size: historia,
                chunk: [chunk; 32],
                ..Default::default()
            },
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x44; 32])),
            padres: PadresDag::genesis(),
            sello: [0u8; 64],
        }
    }

    /// V1: misma identidad y otro `pre_hash` produce una evidencia con el orden canónico correcto.
    #[test]
    fn misma_identidad_otro_pre_hash_detecta_un_incidente() {
        let mut d = DetectorDobleFirma::nuevo(10);
        let h1 = cabecera(7, 1, 3, 1 << 20, 5, 100, 1);
        let h2 = cabecera(7, 1, 3, 1 << 20, 5, 100, 2);
        assert!(h1.pre_hash() != h2.pre_hash());

        let (obs1, lim1) = d.observar(h1);
        assert!(matches!(obs1, Observacion::Nueva));
        assert!(lim1.is_none());

        let (obs2, lim2) = d.observar(h2);
        assert!(lim2.is_none());
        match obs2 {
            Observacion::Incidente(p) => {
                assert_eq!(p.slot_falta, 100);
                let zx_core::ExtensionTx::Evidencia { h1: a, h2: b } = &p.tx.extension else {
                    panic!("se esperaba ExtensionTx::Evidencia")
                };
                assert!(a.pre_hash() < b.pre_hash(), "orden canónico EV-01");
                assert_eq!(p.tx.version, 4);
                assert!(p.tx.inputs.is_empty());
                assert!(p.tx.outputs.is_empty());
            }
            otro => panic!("se esperaba Incidente, llegó {otro:?}"),
        }
        assert_eq!(d.pendientes_len(), 1);
    }

    /// Misma cabecera dos veces: no hay falta.
    #[test]
    fn la_misma_cabecera_dos_veces_no_produce_nada() {
        let mut d = DetectorDobleFirma::nuevo(10);
        let h = cabecera(7, 1, 3, 1 << 20, 5, 100, 1);
        let (obs1, _) = d.observar(h);
        assert!(matches!(obs1, Observacion::Nueva));
        let (obs2, _) = d.observar(h);
        assert!(matches!(obs2, Observacion::MismaCabecera));
        assert_eq!(d.pendientes_len(), 0);
    }

    /// Cada uno de los seis campos de la identidad RAT-1 distinto: no hay falta (identidades
    /// distintas, cada una se indexa como "Nueva").
    #[test]
    fn cada_campo_de_la_identidad_distinto_no_produce_incidente() {
        let base = cabecera(7, 1, 3, 1 << 20, 5, 100, 1);
        let variantes = [
            cabecera(8, 1, 3, 1 << 20, 5, 100, 2),       // cbid
            cabecera(7, 2, 3, 1 << 20, 5, 100, 2),       // public_key
            cabecera(7, 1, 4, 1 << 20, 5, 100, 2),       // sector_index
            cabecera(7, 1, 3, (1 << 20) + 1, 5, 100, 2), // history_size
            cabecera(7, 1, 3, 1 << 20, 6, 100, 2),       // chunk
            cabecera(7, 1, 3, 1 << 20, 5, 101, 2),       // slot
        ];
        for variante in variantes {
            let mut d = DetectorDobleFirma::nuevo(10);
            let (obs1, _) = d.observar(base);
            assert!(matches!(obs1, Observacion::Nueva));
            let (obs2, _) = d.observar(variante);
            assert!(
                matches!(obs2, Observacion::Nueva),
                "campo distinto debe indexarse como identidad nueva, no como incidente"
            );
            assert_eq!(d.pendientes_len(), 0);
        }
    }

    /// Poda por ventana: una vista con `slot` fuera de `[slot_actual - plazo_slots, ..]` se poda.
    #[test]
    fn poda_por_ventana_de_vistas() {
        let mut d = DetectorDobleFirma::nuevo(10);
        d.observar(cabecera(7, 1, 3, 1 << 20, 5, 50, 1));
        d.observar(cabecera(7, 1, 3, 1 << 20, 5, 200, 1));
        assert_eq!(d.identidades_indexadas(), 2);
        // slot_actual = 300, plazo_slots = 100 => corte = 200: el slot 50 se poda, el 200 no.
        let podadas = d.podar_vistas(300, 100);
        assert_eq!(podadas, 1);
        assert_eq!(d.identidades_indexadas(), 1);
    }

    /// Tope y desalojo: al superar el tope, se desaloja la identidad de menor slot.
    #[test]
    fn tope_desaloja_la_mas_vieja() {
        let mut d = DetectorDobleFirma::nuevo(2);
        d.observar(cabecera(7, 1, 3, 1 << 20, 5, 10, 1));
        d.observar(cabecera(7, 2, 3, 1 << 20, 5, 20, 1));
        assert_eq!(d.identidades_indexadas(), 2);
        let (obs, limite) = d.observar(cabecera(7, 3, 3, 1 << 20, 5, 30, 1));
        assert!(matches!(obs, Observacion::Nueva));
        let limite = limite.expect("se esperaba desalojo al superar el tope");
        assert_eq!(limite.slot_desalojado, 10);
        assert_eq!(d.identidades_indexadas(), 2);
    }

    /// Tercera cabecera del mismo billete: mismo `incident_id`, ninguna evidencia nueva.
    #[test]
    fn tercera_cabecera_no_produce_evidencia_nueva_del_mismo_incidente() {
        let mut d = DetectorDobleFirma::nuevo(10);
        let h1 = cabecera(7, 1, 3, 1 << 20, 5, 100, 1);
        let h2 = cabecera(7, 1, 3, 1 << 20, 5, 100, 2);
        let h3 = cabecera(7, 1, 3, 1 << 20, 5, 100, 3);
        d.observar(h1);
        let (obs2, _) = d.observar(h2);
        let incident_id = match obs2 {
            Observacion::Incidente(p) => p.incident_id,
            otro => panic!("se esperaba Incidente, llegó {otro:?}"),
        };
        assert_eq!(d.pendientes_len(), 1);
        let (obs3, _) = d.observar(h3);
        match obs3 {
            Observacion::IncidenteYaPendiente { incident_id: id } => {
                assert_eq!(id, incident_id, "mismo incident_id (EV-10)");
            }
            otro => panic!("se esperaba IncidenteYaPendiente, llegó {otro:?}"),
        }
        assert_eq!(
            d.pendientes_len(),
            1,
            "la tercera cabecera no añade una segunda pendiente del mismo incidente"
        );
    }

    /// Poda de pendientes por cierre de ventana (EV-13/EV-14).
    #[test]
    fn poda_pendientes_por_cierre_de_ventana() {
        let mut d = DetectorDobleFirma::nuevo(10);
        d.observar(cabecera(7, 1, 3, 1 << 20, 5, 100, 1));
        d.observar(cabecera(7, 1, 3, 1 << 20, 5, 100, 2));
        assert_eq!(d.pendientes_len(), 1);
        // Ventana abierta todavía: slot_actual = 150 < 100 + 300.
        assert!(d.podar_pendientes(150, 300).is_empty());
        assert_eq!(d.pendientes_len(), 1);
        // Ventana cerrada: slot_actual = 400 >= 100 + 300.
        let podadas = d.podar_pendientes(400, 300);
        assert_eq!(podadas.len(), 1);
        assert_eq!(d.pendientes_len(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // V2 de `ORDEN-SL4b3`: inclusión de evidencias (unitaria, sin montar un `Nodo`).
    // ─────────────────────────────────────────────────────────────────────────────

    /// Detector con un único incidente (slot_falta = 100): devuelve también su `incident_id`, la
    /// clave del firmante y el slot de la falta, para construir el estado base de cada caso.
    fn detector_con_incidente() -> (DetectorDobleFirma, [u8; 32], ClavePublica, u64) {
        let mut d = DetectorDobleFirma::nuevo(10);
        d.observar(cabecera(7, 1, 3, 1 << 20, 5, 100, 1));
        let (obs, _) = d.observar(cabecera(7, 1, 3, 1 << 20, 5, 100, 2));
        match obs {
            Observacion::Incidente(p) => {
                let clave = match &p.tx.extension {
                    zx_core::ExtensionTx::Evidencia { h1, .. } => h1.sol.public_key,
                    _ => panic!("la pendiente debía ser una EvidenceTx"),
                };
                (d, p.incident_id, clave, p.slot_falta)
            }
            otro => panic!("se esperaba Incidente, llegó {otro:?}"),
        }
    }

    /// Estado base con el incidente `id` ya procesado en la garantía de `clave`.
    fn estado_con_incidente(clave: ClavePublica, id: [u8; 32], slot_falta: u64) -> Estado {
        let mut estado = Estado::inicial();
        estado.garantias.insert(
            clave,
            Garantia {
                incidentes: vec![Incidente {
                    id,
                    slot_falta: i64::try_from(slot_falta).expect("el slot cabe en i64"),
                }],
                ..Garantia::nueva()
            },
        );
        estado
    }

    /// Pendiente con ventana abierta → se incluye (una `EvidenceTx` v4).
    #[test]
    fn pendiente_con_ventana_abierta_se_incluye() {
        let (d, _id, _clave, _slot) = detector_con_incidente();
        let incluidas = elegibles(&d, None, 150, 300, 4);
        assert_eq!(incluidas.len(), 1, "una pendiente con ventana abierta");
        assert_eq!(incluidas[0].version, 4, "la transacción incluida es la v4");
        assert!(matches!(
            incluidas[0].extension,
            zx_core::ExtensionTx::Evidencia { .. }
        ));
    }

    /// Incidente ya procesado en el estado base → no se incluye.
    #[test]
    fn incidente_ya_procesado_en_el_estado_base_no_se_incluye() {
        let (d, id, clave, slot_falta) = detector_con_incidente();
        let estado = estado_con_incidente(clave, id, slot_falta);
        assert!(
            elegibles(&d, Some(&estado), 150, 300, 4).is_empty(),
            "el estado base ya tiene el incidente: nada que incluir"
        );
    }

    /// Ventana cerrada → no se incluye y la pendiente sale de la lista.
    #[test]
    fn ventana_cerrada_no_se_incluye_y_sale_de_la_lista() {
        let (mut d, _id, _clave, _slot) = detector_con_incidente();
        // `slot_falta = 100`, plazo 300 ⇒ la ventana cierra en 400.
        assert_eq!(
            elegibles(&d, None, 399, 300, 4).len(),
            1,
            "en 399 la ventana sigue abierta"
        );
        assert_eq!(
            d.podar_pendientes(400, 300).len(),
            1,
            "la poda retira la pendiente cerrada"
        );
        assert_eq!(d.pendientes_len(), 0);
        assert!(
            elegibles(&d, None, 400, 300, 4).is_empty(),
            "cerrada la ventana, ya no es elegible"
        );
    }

    /// El bloque portador sale de la cadena seleccionada tras una reorganización → la pendiente
    /// vuelve a ser elegible (no hay marca interna de «incluida»).
    #[test]
    fn bloque_portador_fuera_de_la_cadena_vuelve_a_ser_elegible() {
        let (d, id, clave, slot_falta) = detector_con_incidente();
        let con_bloque = estado_con_incidente(clave, id, slot_falta);
        assert!(
            elegibles(&d, Some(&con_bloque), 150, 300, 4).is_empty(),
            "con el bloque portador en la cadena, el incidente ya está procesado"
        );
        // Reorganización: la nueva punta seleccionada no trae el incidente procesado.
        let sin_bloque = Estado::inicial();
        let tras_reorg = elegibles(&d, Some(&sin_bloque), 150, 300, 4);
        assert_eq!(tras_reorg.len(), 1, "vuelve a ser elegible");
        assert_eq!(
            d.pendientes_len(),
            1,
            "la pendiente nunca se borró del detector"
        );
    }
}
