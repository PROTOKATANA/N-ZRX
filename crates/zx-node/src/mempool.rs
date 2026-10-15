//! Mempool de transacciones de `zx-node` (`ORDEN-TX3`, `CONTRATO-RELEVO-v0` con DR-01…DR-10).
//!
//! Es el **único** camino de admisión de transacciones que no vienen dentro de un bloque:
//! `preparar_depositos` mete aquí sus depósitos, el detector mete aquí sus evidencias, y el gossip
//! (`zx-p2p`) entrega aquí lo que le llega de otros nodos. La validación es **estricta contra el
//! estado virtual del terminal seleccionado** (TX-R-14): se aplica la transacción con el mismo motor
//! de consenso (`zx-consensus`) sobre una copia del estado, y solo si el motor la acepta entra.
//!
//! # Qué implementa y qué no
//!
//! - Reglas `[P]` de admisión (TX-R-06…TX-R-20), topes globales y por par (TX-R-21/22), topes de
//!   huérfanas (TX-R-18/19), mínimo rodante con desalojo (TX-R-15), TTL por puntos (TX-R-36),
//!   vuelta tras reorganización (TX-R-32…TX-R-35) y selección para el bloque (TX-R-27/28/46).
//! - **No** decide consenso: nada de lo que hace aquí cambia la validez de un bloque. Los topes y
//!   la caducidad son política local.
//!
//! # Hilos
//!
//! El estado del nodo lo posee el hilo de consenso; la red corre en `tokio`. La mempool se comparte
//! como `Arc<Mutex<Mempool>>` porque la validación de una transacción de gossip debe ser
//! **síncrona** (C-NET-12: nada se reenvía antes del veredicto) y rápida. `rebasear` es lo único
//! que recorre toda la mempool y lo llama el hilo de consenso al cambiar la punta.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use libp2p::PeerId;
use primitive_types::U256;
use zx_consensus::transicion::votos::{
    W_REVEAL_SLOTS_VOTOS, apertura_ventana, cierre_ventana, incident_id_doble_voto_peso,
    incident_id_doble_voto_peso_ventanas,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, HechoVoto, HechosCabecera,
    ParametrosEvidencia, ParametrosTransicion, Punto, aplicar_con_undo, aplicar_fusion,
};
use zx_core::digest::Digest;
use zx_core::{
    BlockHash, ClasePruebaAlmacenamiento, ClavePublica, ExtensionTx, OperacionAlmacenamiento,
    OutPoint, TipoGarantia, TipoOperacionSector, Tx, TxId, txid, validar_forma_tx,
    validar_forma_tx_v4,
};

/// RN-1 · S5 · clase de operación de una transacción **con operación de sector o de
/// almacenamiento**; `None` para cualquier otra (pagos corrientes, garantías, evidencias v4…). Es
/// lo que etiqueta los eventos `tx_admitida`/`tx_rechazada`/`tx_descartada`: solo estas
/// transacciones dejan rastro, tal y como fija la orden.
#[must_use]
pub(crate) fn clase_de_operacion(tx: &Tx) -> Option<&'static str> {
    match &tx.extension {
        ExtensionTx::Sector { operacion } => Some(match operacion.tipo() {
            TipoOperacionSector::Alta => "sector_alta",
            TipoOperacionSector::Renovar => "sector_renovar",
            TipoOperacionSector::AbrirAuditoria => "sector_abrir_auditoria",
            TipoOperacionSector::ContestarAuditoria => "sector_contestar_auditoria",
            TipoOperacionSector::Retirar => "sector_retirar",
            TipoOperacionSector::CerrarCaja => "sector_cerrar_caja",
            TipoOperacionSector::RetirarCaja => "sector_retirar_caja",
        }),
        ExtensionTx::PruebaAlmacenamiento { operacion } => Some(match operacion.clase() {
            ClasePruebaAlmacenamiento::PoRep => "almacenamiento_porep",
            ClasePruebaAlmacenamiento::PoSt => "almacenamiento_post",
            ClasePruebaAlmacenamiento::ClaveVoto => "almacenamiento_clave_voto",
            ClasePruebaAlmacenamiento::VotoPropio => "almacenamiento_voto_propio",
            ClasePruebaAlmacenamiento::CertificadoPeso => "almacenamiento_certificado_peso",
            ClasePruebaAlmacenamiento::ActaPresencia => "almacenamiento_acta_presencia",
            ClasePruebaAlmacenamiento::EvidenciaVotosPeso => "almacenamiento_evidencia_votos_peso",
        }),
        ExtensionTx::Ninguna
        | ExtensionTx::Garantia { .. }
        | ExtensionTx::CoinbasePost { .. }
        | ExtensionTx::Evidencia { .. } => None,
    }
}

/// RN-1 · S5 · texto del motivo tal y como lo devuelve la mempool (conserva su clase:
/// `Demostrable`/`VistaLocal`/`Limite`), para el campo `motivo` de `tx_rechazada`.
#[must_use]
pub(crate) fn motivo_de_rechazo(r: &Rechazo) -> String {
    format!("{r:?}")
}

/// Un MiB, en bytes, para los topes de DR-07.
pub const MIB: usize = 1024 * 1024;

/// Política local de la mempool (no consenso). Valores de `DECISIONES.md` DR-04/DR-07/DR-10.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Politica {
    /// `S`: tope global de la mempool (DR-07, 128 MiB).
    pub s: usize,
    /// `S_par`: tope por par (DR-07, 16 MiB).
    pub s_par: usize,
    /// `R_par`: tasa de admisión por par, en bytes por ventana (DR-07, 1 MiB/s).
    pub r_par: usize,
    /// Ventana de la tasa por par, en milisegundos.
    pub ventana_tasa_ms: u64,
    /// `TTL_slots` (DR-04, 300 puntos sin aplicarse).
    pub ttl_puntos: u64,
    /// `H_max`: huérfanas máximas por número (TX-R-18, 500).
    pub h_max: usize,
    /// `H_bytes`: huérfanas máximas por bytes (TX-R-18, 2 MiB).
    pub h_bytes: usize,
    /// `W_reserva`: bytes por bloque reservados al depósito del granjero sin garantía (DR-10).
    pub w_reserva: u64,
    /// `α` del muestreo ponderado por tarifa (DR-08, 3).
    pub alpha: u32,
    /// `φ_min`: tarifa mínima por byte, en brek/B (TX-R-11). El valor dev vive en el perfil
    /// (`perfil::PHI_MIN_BREK_POR_BYTE`, E-08), no incrustado aquí.
    pub phi_min: u64,
}

impl Politica {
    /// La política dev: DR-07, DR-04, DR-10 y TX-R-11/TX-R-18/DR-08.
    #[must_use]
    pub const fn dev() -> Self {
        Self {
            s: 128 * MIB,
            s_par: 16 * MIB,
            r_par: MIB,
            ventana_tasa_ms: 1_000,
            ttl_puntos: 300,
            h_max: 500,
            h_bytes: 2 * MIB,
            w_reserva: 64_000,
            alpha: 3,
            phi_min: crate::perfil::PHI_MIN_BREK_POR_BYTE,
        }
    }
}

impl Default for Politica {
    fn default() -> Self {
        Self::dev()
    }
}

/// Resultado de admitir una transacción.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admision {
    /// Entró en la mempool (o ya estaba, en cuyo caso `Duplicada`).
    Admitida,
    /// Ya la teníamos por `txid` (en la mempool, en huérfanas o aplicada hace poco).
    Duplicada,
    /// Sus entradas no están ni en el estado ni en la mempool: fue al depósito de huérfanas.
    Huerfana,
}

/// Motivo de rechazo, con la clase que decide el veredicto de gossip (TX-R-10, DR-06).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rechazo {
    /// Defecto **demostrable** para cualquier nodo con los padres: forma, tamaño o firma con salidas
    /// conocidas. En gossip ⇒ `Rechazar` (penaliza).
    Demostrable(&'static str),
    /// Depende de la **vista local** (conflicto, nonce, saldo, inmadurez, doble gasto): en gossip ⇒
    /// `Ignorar` (no penaliza, RFT-27/DR-06).
    VistaLocal(&'static str),
    /// Límite **local** de recursos (topes, cuota, tasa): en gossip ⇒ `Ignorar`.
    Limite(&'static str),
}

/// EV-1 · identidad canónica, independiente del reportero y del txid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IdentidadEvidenciaVoto {
    pub clave_bls: [u8; 48],
    pub incidente: [u8; 32],
}

/// EV-1 · resultado local; `Cubierta` siempre identifica una entrada real o un incidente aplicado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmisionEvidencia {
    Admitida(IdentidadEvidenciaVoto),
    Cubierta {
        por: IdentidadEvidenciaVoto,
        aplicada: bool,
    },
    Rechazada(Rechazo),
}

/// EV-1 · retirada comprometida de una entrada seguida por el detector local.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetiradaEvidencia {
    pub identidad: IdentidadEvidenciaVoto,
    pub motivo: Rechazo,
}

pub(crate) fn identidad_evidencia_voto(tx: &Tx) -> Option<IdentidadEvidenciaVoto> {
    let ExtensionTx::PruebaAlmacenamiento {
        operacion:
            OperacionAlmacenamiento::EvidenciaVotosPeso {
                clave_bls,
                voto1,
                voto2,
                ..
            },
    } = &tx.extension
    else {
        return None;
    };
    Some(identidad_de_votos(clave_bls, voto1, voto2))
}

pub(crate) fn identidad_de_votos(
    clave_bls: &[u8; 48],
    a: &zx_core::VotoPesoEvidencia,
    b: &zx_core::VotoPesoEvidencia,
) -> IdentidadEvidenciaVoto {
    let incidente = if a.n == b.n {
        incident_id_doble_voto_peso(
            a.n,
            clave_bls,
            &a.candidato,
            &a.h_t_siguiente,
            &a.raiz_estado,
            &b.candidato,
            &b.h_t_siguiente,
            &b.raiz_estado,
        )
    } else {
        incident_id_doble_voto_peso_ventanas(
            a.n,
            b.n,
            clave_bls,
            &a.candidato,
            &a.h_t_siguiente,
            &a.raiz_estado,
            &b.candidato,
            &b.h_t_siguiente,
            &b.raiz_estado,
        )
    };
    IdentidadEvidenciaVoto {
        clave_bls: *clave_bls,
        incidente,
    }
}

pub(crate) fn incidente_aplicado(estado: &Estado, incidente: &[u8; 32]) -> bool {
    estado
        .garantias
        .values()
        .any(|g| g.incidentes.iter().any(|i| &i.id == incidente))
}

/// EV-2: recibo por ocurrencia; el cuerpo conserva los testigos originales.
pub(crate) struct ReciboBloque {
    pub hash: BlockHash,
    pub peer: Option<PeerId>,
    pub txs: Vec<TxConTestigos>,
    pub descartes: Vec<zx_consensus::transicion::TxDescartada>,
}

pub(crate) struct ReadmisionDescarte {
    pub indice: usize,
    pub txid: TxId,
    pub clase: &'static str,
    pub motivo: ErrorTransicion,
    pub resultado: Result<Admision, Rechazo>,
}

fn incidente_evidencia(tx: &Tx) -> Option<[u8; 32]> {
    if let Some(i) = identidad_evidencia_voto(tx) {
        return Some(i.incidente);
    }
    if let ExtensionTx::Evidencia { h1, .. } = &tx.extension {
        return Some(
            *zx_core::incident_id_evidencia(
                h1.consensus_branch_id,
                h1.sol.public_key.bytes(),
                h1.sol.sector_index,
                h1.sol.history_size,
                &h1.sol.chunk,
                h1.slot,
            )
            .as_bytes(),
        );
    }
    None
}

fn es_evidencia(tx: &Tx) -> bool {
    incidente_evidencia(tx).is_some()
}

/// Estadísticas de la mempool, para tests y diagnóstico.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Estadisticas {
    /// Transacciones admitidas.
    pub n: usize,
    /// Bytes estimados admitidos.
    pub bytes: usize,
    /// Huérfanas en el depósito.
    pub huerfanas: usize,
    /// Bytes de las huérfanas.
    pub bytes_huerfanas: usize,
    /// Mínimo rodante como `(num, den)` = fee/byte.
    pub minimo_rodante: (u128, u128),
    /// Pares con bytes contabilizados (TX-6): tantos como entradas de `bytes_por_par`.
    pub pares: usize,
    /// Máximo de `bytes_por_par` entre los pares (TX-6): acota el tope por par de DR-07.
    pub bytes_max_par: usize,
}

/// Contadores **acumulados** de rechazos por tope local (`Rechazo::Limite`), desde el arranque.
///
/// Instrumentación de TX-6: [`Mempool::admitir`] ya tomaba estas decisiones; aquí solo se cuentan
/// para poder publicarlas en el evento periódico `mempool`. No cambia ninguna regla.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct RechazosLimite {
    /// Total de rechazos por tope (`Rechazo::Limite`), suma de los motivos de abajo.
    pub total: u64,
    /// Motivo `global`: se superaba el tope `S` y no se pudo desalojar (TX-R-15).
    pub global: u64,
    /// Motivo `par_memoria`: tope `S_par` por par (TX-R-21).
    pub par_memoria: u64,
    /// Motivo `par_tasa`: tasa `R_par` por par (TX-R-22).
    pub par_tasa: u64,
    /// Motivo `tarifa_minima` (TX-R-11).
    pub tarifa_minima: u64,
    /// Motivo `tarifa_rodante` (TX-R-15).
    pub tarifa_rodante: u64,
    /// Motivo `huerfanas`: topes del depósito de huérfanas (TX-R-18).
    pub huerfanas: u64,
    /// Motivo `cuota_por_clave` (TX-R-20).
    pub cuota_por_clave: u64,
    /// Motivo `cuota_por_incidente` (TX-R-20).
    pub cuota_por_incidente: u64,
    /// FV-4b-N4 · motivo `cuota_por_ventana`: ya hay una pendiente del mismo `(clave, n, clase)`.
    pub cuota_por_ventana: u64,
    /// FV-4b-N4 · motivo `ventana_voto`: la ventana no es admisible respecto al slot actual.
    pub ventana_voto: u64,
}

/// Una transacción admitida, con lo que hace falta para desalojarla y revalidarla.
#[derive(Clone, Debug)]
struct Entrada {
    tx: Tx,
    testigos: Vec<Vec<u8>>,
    txid: TxId,
    peso: u64,
    fee: u64,
    origen: Punto,
    peer: Option<PeerId>,
    clave: Option<ClavePublica>,
    incidente: Option<[u8; 32]>,
    creados: Vec<OutPoint>,
}

impl Entrada {
    /// feerate como `(fee, peso)`: comparar con productos cruzados evita floats y redondeos.
    fn feerate(&self) -> (u128, u128) {
        (self.fee as u128, self.peso.max(1) as u128)
    }
}

/// Análisis previo de una transacción candidata: lo que se puede decidir sin tocar el estado.
struct Analisis {
    tx: Tx,
    testigos: Vec<Vec<u8>>,
    txid: TxId,
    peso: u64,
    /// `None` si alguna entrada no se conoce (huérfana): la tarifa se calcula al resolverla.
    fee: Option<u64>,
    clave: Option<ClavePublica>,
    incidente: Option<[u8; 32]>,
    /// FV-4b-N3-2 · ¿la operación entra en la cuota de una pendiente por clave? Los compromisos y
    /// revelaciones de ventana (`0x06`/`0x07`) están **exentos**: un mismo nodo mantiene varias
    /// ventanas solapadas en vuelo y todas deben poder viajar a la vez.
    cuota_clave: bool,
    /// B26-1 · ¿es una operación de sector (v5)? La admisión la exime de competir por tarifa: con
    /// la mempool llena desaloja la transacción normal de menor `feerate` en vez de rechazarse.
    es_sector: bool,
}

/// B26-3 · Plan de desalojo calculado **sin mutar** la mempool. `nuevo_minimo` solo se rellena en el
/// camino normal cuando el plan sube el mínimo rodante (nunca en el camino de sector).
struct PlanDesalojo {
    ids: Vec<TxId>,
    nuevo_minimo: Option<(u128, u128)>,
}

/// B26-3 · Instantánea del estado mutable que un plan de desalojo puede cambiar, para deshacerlo si
/// la candidata no valida sobre la vista resultante. No incluye `tasa_por_par`: es contabilidad de
/// intento (TX-R-22), no pérdida de entradas.
struct InstantaneaMempool {
    vista: Estado,
    entradas: BTreeMap<TxId, Entrada>,
    orden: Vec<TxId>,
    gastados: BTreeMap<OutPoint, TxId>,
    creados: BTreeMap<OutPoint, u64>,
    bytes_totales: usize,
    bytes_por_par: BTreeMap<PeerId, usize>,
    por_clave: BTreeMap<ClavePublica, TxId>,
    por_incidente: BTreeMap<[u8; 32], TxId>,
    minimo_rodante: (u128, u128),
    hechos_votos: BTreeMap<TxId, HechoVoto>,
    seguidas: BTreeSet<[u8; 48]>,
    retiradas: BTreeMap<[u8; 48], RetiradaEvidencia>,
}

/// La mempool.
pub struct Mempool {
    politica: Politica,
    params: ParametrosTransicion,
    evp: ParametrosEvidencia,
    cbid: u32,
    /// Estado virtual del terminal seleccionado **sin** las transacciones de la mempool.
    base: Estado,
    /// `base` más todas las entradas admitidas, en orden de admisión. Es la vista contra la que se
    /// valida la siguiente transacción (TX-R-14).
    vista: Estado,
    entradas: BTreeMap<TxId, Entrada>,
    orden: Vec<TxId>,
    gastados: BTreeMap<OutPoint, TxId>,
    creados: BTreeMap<OutPoint, u64>,
    huerfanas: BTreeMap<TxId, Entrada>,
    bytes_huerfanas: usize,
    bytes_totales: usize,
    bytes_por_par: BTreeMap<PeerId, usize>,
    tasa_por_par: BTreeMap<PeerId, (Instant, usize)>,
    por_clave: BTreeMap<ClavePublica, TxId>,
    por_incidente: BTreeMap<[u8; 32], TxId>,
    /// `txid -> punto` de las transacciones aplicadas hace poco (TX-R-24): evita readmitir lo ya
    /// aplicado y acota el mapa por TTL.
    aplicadas: BTreeMap<TxId, Punto>,
    minimo_rodante: (u128, u128),
    /// Punto actual del estado base (altura en PoW, slot en PoST): lo consulta el manejador de red.
    punto_actual: Punto,
    /// TX-6: contadores acumulados de rechazos por tope local, para el evento `mempool`.
    rechazos_limite: RechazosLimite,
    /// Solo hechos entregados por el dueño de Cadena para esta base y entradas reales.
    hechos_votos: BTreeMap<TxId, HechoVoto>,
    /// Una notificación por clave cubierta localmente; nunca un historial de entradas de red.
    seguidas: BTreeSet<[u8; 48]>,
    retiradas: BTreeMap<[u8; 48], RetiradaEvidencia>,
    /// EV-2: ocurrencias ya tratadas, acotadas por el TTL existente.
    descartes_tratados: BTreeMap<(BlockHash, usize), Punto>,
    /// Avisos coalescidos; nunca se retienen IDs de entradas retiradas.
    protegidas: BTreeSet<TxId>,
}

/// MP-2 · transacción de la cola con sus testigos: la unidad que devuelve la selección.
type TxConTestigos = (Tx, Vec<Vec<u8>>);

impl Mempool {
    /// Crea una mempool vacía sobre `base` (el estado virtual del terminal seleccionado).
    #[must_use]
    pub fn nueva(
        params: ParametrosTransicion,
        evp: ParametrosEvidencia,
        cbid: u32,
        base: Estado,
        politica: Politica,
    ) -> Self {
        Self {
            politica,
            params,
            evp,
            cbid,
            vista: base.clone(),
            base,
            entradas: BTreeMap::new(),
            orden: Vec::new(),
            gastados: BTreeMap::new(),
            creados: BTreeMap::new(),
            huerfanas: BTreeMap::new(),
            bytes_huerfanas: 0,
            bytes_totales: 0,
            bytes_por_par: BTreeMap::new(),
            tasa_por_par: BTreeMap::new(),
            por_clave: BTreeMap::new(),
            por_incidente: BTreeMap::new(),
            aplicadas: BTreeMap::new(),
            minimo_rodante: (0, 1),
            punto_actual: Punto::Altura(0),
            rechazos_limite: RechazosLimite::default(),
            hechos_votos: BTreeMap::new(),
            seguidas: BTreeSet::new(),
            retiradas: BTreeMap::new(),
            descartes_tratados: BTreeMap::new(),
            protegidas: BTreeSet::new(),
        }
    }

    /// El punto del estado base vigente (altura en PoW, slot en PoST).
    #[must_use]
    pub const fn punto_actual(&self) -> Punto {
        self.punto_actual
    }

    /// RN-1 · S5 · `consensus_branch_id` con el que la mempool calcula los `txid`; lo necesita quien
    /// escribe el identificador de una transacción en el registro sin pasar por una admisión.
    #[must_use]
    pub const fn cbid(&self) -> u32 {
        self.cbid
    }

    /// La política vigente.
    #[must_use]
    pub const fn politica(&self) -> &Politica {
        &self.politica
    }

    /// Estadísticas actuales (tests y diagnóstico).
    #[must_use]
    pub fn estadisticas(&self) -> Estadisticas {
        Estadisticas {
            n: self.entradas.len(),
            bytes: self.bytes_totales,
            huerfanas: self.huerfanas.len(),
            bytes_huerfanas: self.bytes_huerfanas,
            minimo_rodante: self.minimo_rodante,
            pares: self.bytes_por_par.len(),
            bytes_max_par: self.bytes_por_par.values().copied().max().unwrap_or(0),
        }
    }

    /// Contadores acumulados de rechazos por tope local (TX-6).
    #[must_use]
    pub const fn rechazos_limite(&self) -> RechazosLimite {
        self.rechazos_limite
    }

    /// ¿Está el `txid` admitido o aplicado hace poco?
    #[must_use]
    pub fn contiene(&self, txid: &TxId) -> bool {
        self.entradas.contains_key(txid) || self.aplicadas.contains_key(txid)
    }

    /// Copia mínima para que el dueño calcule hechos fuera del mutex de la cola.
    pub(crate) fn evidencias_entre_ventanas(
        &self,
    ) -> Vec<(TxId, zx_core::VotoPesoEvidencia, zx_core::VotoPesoEvidencia)> {
        self.entradas
            .values()
            .filter_map(|e| match &e.tx.extension {
                ExtensionTx::PruebaAlmacenamiento {
                    operacion: OperacionAlmacenamiento::EvidenciaVotosPeso { voto1, voto2, .. },
                } if voto1.n != voto2.n => Some((e.txid, *voto1, *voto2)),
                _ => None,
            })
            .collect()
    }

    /// EV-1 · base y mapa se publican bajo el mismo mutex. No conserva hechos de la base anterior.
    pub(crate) fn rebasear_con_hechos(
        &mut self,
        base: Estado,
        hechos: BTreeMap<TxId, HechoVoto>,
        ahora: Instant,
        punto: Punto,
    ) -> Vec<RetiradaEvidencia> {
        self.hechos_votos = hechos;
        self.rebasear_interno(base, ahora, punto);
        self.tomar_retiradas_evidencia()
    }

    /// Resultado coalescido de operaciones ya comprometidas, incluidas las ejecutadas por red.
    pub(crate) fn tomar_retiradas_evidencia(&mut self) -> Vec<RetiradaEvidencia> {
        std::mem::take(&mut self.retiradas).into_values().collect()
    }

    fn notificar_retirada(&mut self, tx: &Tx, motivo: Rechazo) {
        if let Some(identidad) = identidad_evidencia_voto(tx)
            && self.seguidas.remove(&identidad.clave_bls)
        {
            self.retiradas
                .insert(identidad.clave_bls, RetiradaEvidencia { identidad, motivo });
        }
    }

    /// EV-1 · pasa siempre por admitir; D8 se arbitra aquí, sin carrera con la red.
    pub(crate) fn admitir_evidencia(
        &mut self,
        tx: Tx,
        testigos: Vec<Vec<u8>>,
        hecho: Option<HechoVoto>,
        ahora: Instant,
        punto: Punto,
    ) -> (AdmisionEvidencia, Vec<RetiradaEvidencia>) {
        let Some(identidad) = identidad_evidencia_voto(&tx) else {
            return (
                AdmisionEvidencia::Rechazada(Rechazo::Demostrable("no_evidencia_voto")),
                self.tomar_retiradas_evidencia(),
            );
        };
        if incidente_aplicado(&self.base, &identidad.incidente) {
            return (
                AdmisionEvidencia::Cubierta {
                    por: identidad,
                    aplicada: true,
                },
                self.tomar_retiradas_evidencia(),
            );
        }
        let id = txid(&tx, self.cbid);
        if let Some(hecho) = hecho
            && !self.entradas.contains_key(&id)
        {
            self.hechos_votos.insert(id, hecho);
        }
        let resultado = self.admitir(None, tx, testigos, ahora, punto);
        let cobertura = self
            .entradas
            .values()
            .filter_map(|e| identidad_evidencia_voto(&e.tx))
            .find(|i| i.clave_bls == identidad.clave_bls || i.incidente == identidad.incidente);
        let respuesta = match (resultado, cobertura) {
            (Ok(Admision::Admitida), Some(_)) => AdmisionEvidencia::Admitida(identidad),
            (Ok(_), Some(por)) => AdmisionEvidencia::Cubierta {
                por,
                aplicada: false,
            },
            (Err(r), _) => AdmisionEvidencia::Rechazada(r),
            (Ok(_), None) => AdmisionEvidencia::Rechazada(Rechazo::VistaLocal("sin_entrada_real")),
        };
        if let Some(por) = cobertura
            && !matches!(respuesta, AdmisionEvidencia::Rechazada(_))
        {
            self.seguidas.insert(por.clave_bls);
        }
        self.hechos_votos
            .retain(|id, _| self.entradas.contains_key(id));
        (respuesta, self.tomar_retiradas_evidencia())
    }

    /// Reemplaza el estado base (nueva punta/terminal) y revalida todo lo admitido contra él.
    ///
    /// Las entradas que ya no validan se descartan (TX-R-32/33); las huérfanas se reintentan al
    /// final (TX-R-19). Se recorren las entradas en su orden de admisión.
    pub fn rebasear(&mut self, base: Estado, ahora: Instant, punto: Punto) {
        // Sin mapa nuevo no se reutiliza un hecho antiguo.
        self.hechos_votos.clear();
        self.rebasear_interno(base, ahora, punto);
    }

    fn rebasear_interno(&mut self, base: Estado, ahora: Instant, punto: Punto) {
        self.base = base;
        self.punto_actual = punto;
        let anteriores: Vec<Entrada> = self
            .orden
            .iter()
            .filter_map(|id| self.entradas.get(id).cloned())
            .collect();
        self.entradas.clear();
        self.orden.clear();
        self.gastados.clear();
        self.creados.clear();
        self.por_clave.clear();
        self.por_incidente.clear();
        self.bytes_por_par.clear();
        self.bytes_totales = 0;
        self.vista = self.base.clone();
        for mut e in anteriores {
            if self.aplicadas.contains_key(&e.txid)
                || incidente_evidencia(&e.tx).is_some_and(|i| incidente_aplicado(&self.base, &i))
            {
                self.notificar_retirada(&e.tx, Rechazo::VistaLocal("aplicada"));
                continue;
            }
            e.origen = punto;
            match self.aplicar_entrada(&e, ahora) {
                Ok(()) => self.insertar(e),
                Err(motivo) => {
                    self.notificar_retirada(&e.tx, motivo);
                    // La entrada ya no valida contra el estado nuevo: se descarta. Si la reemiten,
                    // se readmite (TX-R-37).
                }
            }
        }
        self.expirar(punto);
        self.resolver_huerfanas(ahora, punto);
        self.hechos_votos
            .retain(|id, _| self.entradas.contains_key(id));
        self.protegidas.retain(|id| self.entradas.contains_key(id));
    }

    /// EV-2/S3: confirma efectos, publica la base y readmite una vez por descarte.
    pub(crate) fn actualizar_tras_bloque(
        &mut self,
        base: Estado,
        hechos: BTreeMap<TxId, HechoVoto>,
        recibo: &ReciboBloque,
        ahora: Instant,
        punto: Punto,
    ) -> (Vec<ReadmisionDescarte>, Vec<RetiradaEvidencia>) {
        let procedencias: BTreeMap<TxId, Option<PeerId>> = self
            .entradas
            .values()
            .chain(self.huerfanas.values())
            .map(|e| (e.txid, e.peer))
            .collect();
        let descartados: BTreeSet<usize> = recibo.descartes.iter().map(|d| d.indice).collect();
        let mut confirmar = BTreeSet::new();
        for (indice, (tx, _)) in recibo.txs.iter().enumerate() {
            let id = txid(tx, self.cbid);
            let aplicada = incidente_evidencia(tx).map_or_else(
                || !descartados.contains(&indice) || self.aplicadas.contains_key(&id),
                |i| incidente_aplicado(&base, &i),
            );
            if aplicada {
                confirmar.insert(id);
            } else if es_evidencia(tx) {
                // Una marca de cuerpo lateral no sustituye el incidente seleccionado.
                self.aplicadas.remove(&id);
            }
        }
        for id in confirmar {
            self.aplicadas.insert(id, punto);
            if let Some(e) = self.huerfanas.remove(&id) {
                self.bytes_huerfanas = self.bytes_huerfanas.saturating_sub(e.peso as usize);
            }
        }
        self.hechos_votos = hechos.clone();
        self.rebasear_interno(base, ahora, punto);
        let mut resultados = Vec::new();
        for d in &recibo.descartes {
            let Some((tx, testigos)) = recibo.txs.get(d.indice) else {
                continue;
            };
            let id = txid(tx, self.cbid);
            if self.aplicadas.contains_key(&id)
                || incidente_evidencia(tx).is_some_and(|i| incidente_aplicado(&self.base, &i))
                || self
                    .descartes_tratados
                    .contains_key(&(recibo.hash, d.indice))
            {
                continue;
            }
            self.descartes_tratados
                .insert((recibo.hash, d.indice), punto);
            // No se borra una marca acreditada por otra ocurrencia del mismo txid.
            if let Some(hecho) = hechos.get(&id) {
                self.hechos_votos.insert(id, *hecho);
            }
            let peer = procedencias.get(&id).copied().unwrap_or(recibo.peer);
            // Un sobre conservado no es un segundo ingreso de red; mantiene su presupuesto por par.
            let resultado = self.admitir_con(
                peer,
                tx.clone(),
                testigos.clone(),
                ahora,
                punto,
                !procedencias.contains_key(&id),
            );
            let resultado = match resultado {
                Ok(Admision::Duplicada) if !self.entradas.contains_key(&id) => {
                    if self.huerfanas.contains_key(&id) {
                        Ok(Admision::Huerfana)
                    } else {
                        Err(Rechazo::VistaLocal("sin_entrada_real"))
                    }
                }
                otro => otro,
            };
            resultados.push(ReadmisionDescarte {
                indice: d.indice,
                txid: id,
                clase: clase_de_operacion(tx).unwrap_or(if es_evidencia(tx) {
                    "evidencia_bloque"
                } else if matches!(tx.extension, ExtensionTx::Garantia { .. }) {
                    "garantia"
                } else {
                    "pago"
                }),
                motivo: d.motivo.clone(),
                resultado,
            });
        }
        self.hechos_votos
            .retain(|id, _| self.entradas.contains_key(id));
        (resultados, self.tomar_retiradas_evidencia())
    }

    /// EV-2: la reorganización publica el contexto nuevo antes de recuperar los sobres.
    pub(crate) fn reinsertar_con_hechos(
        &mut self,
        base: Estado,
        hechos: BTreeMap<TxId, HechoVoto>,
        txs: &[TxConTestigos],
        ahora: Instant,
        punto: Punto,
    ) -> Vec<RetiradaEvidencia> {
        self.hechos_votos = hechos.clone();
        self.rebasear_interno(base, ahora, punto);
        for (tx, testigos) in txs {
            let id = txid(tx, self.cbid);
            if incidente_evidencia(tx).is_some_and(|i| incidente_aplicado(&self.base, &i)) {
                continue;
            }
            self.aplicadas.remove(&id);
            if let Some(hecho) = hechos.get(&id) {
                self.hechos_votos.insert(id, *hecho);
            }
            let _ = self.admitir(None, tx.clone(), testigos.clone(), ahora, punto);
        }
        self.hechos_votos
            .retain(|id, _| self.entradas.contains_key(id));
        self.tomar_retiradas_evidencia()
    }

    pub(crate) fn tomar_protecciones_evidencia(&mut self) -> Vec<TxId> {
        std::mem::take(&mut self.protegidas).into_iter().collect()
    }

    /// Marca como aplicadas unas transacciones (las de un bloque admitido) y las saca de la
    /// mempool y de huérfanas (TX-R-24/33).
    pub fn confirmar_aplicadas(&mut self, txids: &[TxId], punto: Punto) {
        for t in txids {
            self.eliminar(t, Rechazo::VistaLocal("confirmacion_cuerpo"));
            self.aplicadas.insert(*t, punto);
        }
    }

    /// Añade a la mempool las transacciones de bloques que salen de la cadena seleccionada
    /// (TX-R-32). Se revalidan contra el estado nuevo; las que no valgan se descartan.
    pub fn reinsertar(
        &mut self,
        txs: &[(Tx, Vec<Vec<u8>>)],
        ahora: Instant,
        punto: Punto,
    ) -> usize {
        let mut n = 0;
        for (tx, testigos) in txs {
            let id = txid(tx, self.cbid);
            self.aplicadas.remove(&id);
            if self
                .admitir(None, tx.clone(), testigos.clone(), ahora, punto)
                .is_ok()
            {
                n += 1;
            }
        }
        n
    }

    /// Elimina lo caducado (TX-R-36): entradas y huérfanas con más de `ttl_puntos` puntos, y
    /// `aplicadas` viejas (acota su mapa).
    pub fn expirar(&mut self, punto: Punto) {
        let ttl = self.politica.ttl_puntos;
        let caducadas: Vec<TxId> = self
            .entradas
            .iter()
            .filter(|(_, e)| puntos_transcurridos(e.origen, punto) > ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in caducadas {
            self.eliminar(&id, Rechazo::Limite("caducidad"));
        }
        let huerfanas_viejas: Vec<TxId> = self
            .huerfanas
            .iter()
            .filter(|(_, e)| puntos_transcurridos(e.origen, punto) > ttl)
            .map(|(id, _)| *id)
            .collect();
        for id in huerfanas_viejas {
            if let Some(e) = self.huerfanas.remove(&id) {
                self.bytes_huerfanas = self.bytes_huerfanas.saturating_sub(e.peso as usize);
            }
        }
        self.aplicadas
            .retain(|_, p| puntos_transcurridos(*p, punto) <= ttl);
        self.descartes_tratados
            .retain(|_, p| puntos_transcurridos(*p, punto) <= ttl);
    }

    /// Admite una transacción. `peer` es `None` para las que produce este mismo nodo.
    ///
    /// # Errores
    /// [`Rechazo`] con su clase (demostrable, vista local o límite).
    pub fn admitir(
        &mut self,
        peer: Option<PeerId>,
        tx: Tx,
        testigos: Vec<Vec<u8>>,
        ahora: Instant,
        punto: Punto,
    ) -> Result<Admision, Rechazo> {
        // MP-3 · H1: el camino externo sí resuelve huérfanas al final, una sola vez: la resolución
        // ya no anida (su bucle hace las pasadas que antes hacia la recursión).
        self.admitir_con(peer, tx, testigos, ahora, punto, true)
    }

    /// MP-3 · Cuerpo común de [`Self::admitir`] con el interruptor `anidar`: `true` deja que una
    /// admisión con éxito vuelva a [`Self::resolver_huerfanas`] (caminos externos de hoy); `false`
    /// es la admisión que hace la propia [`Self::resolver_huerfanas`], que ya itera ella. La
    /// contabilidad del evento `mempool` (TX-6) es idéntica: cada rechazo por tope se cuenta aquí.
    fn admitir_con(
        &mut self,
        peer: Option<PeerId>,
        tx: Tx,
        testigos: Vec<Vec<u8>>,
        ahora: Instant,
        punto: Punto,
        anidar: bool,
    ) -> Result<Admision, Rechazo> {
        let resultado = self.admitir_interno(peer, tx, testigos, ahora, punto, anidar);
        if let Err(Rechazo::Limite(motivo)) = &resultado {
            self.registrar_rechazo_limite(motivo);
        }
        resultado
    }

    /// Cuerpo de [`Self::admitir`] sin la contabilidad del evento `mempool` (TX-6).
    fn admitir_interno(
        &mut self,
        peer: Option<PeerId>,
        tx: Tx,
        testigos: Vec<Vec<u8>>,
        ahora: Instant,
        punto: Punto,
        anidar: bool,
    ) -> Result<Admision, Rechazo> {
        let analisis = self.analizar(&tx, &testigos)?;
        if let Some(i) = incidente_evidencia(&tx) {
            if incidente_aplicado(&self.base, &i) {
                return Ok(Admision::Duplicada);
            }
            // Una reorganización puede retirar el incidente sin cambiar el sobre.
            self.aplicadas.remove(&analisis.txid);
        }
        if let Some(i) = identidad_evidencia_voto(&tx)
            && self
                .entradas
                .values()
                .filter_map(|e| identidad_evidencia_voto(&e.tx))
                .any(|e| e.clave_bls == i.clave_bls || e.incidente == i.incidente)
        {
            return Ok(Admision::Duplicada);
        }
        // Dedup antes de gastar tiempo en contexto.
        if self.entradas.contains_key(&analisis.txid)
            || self.huerfanas.contains_key(&analisis.txid)
            || self.aplicadas.contains_key(&analisis.txid)
        {
            return Ok(Admision::Duplicada);
        }
        // FV-4b-N4 · tope por **(clave, ventana)** y admisibilidad de la ventana de las tx v6
        // `0x06`/`0x07`. Se decide **antes** de aplicar: como mucho un compromiso y una revelación
        // pendientes por `(clave, n)` y solo si el slot actual cae en `[desde, hasta]`.
        if let Some(v) = ventana_de(&tx) {
            if let Punto::Slot(slot) = punto
                && (slot < v.desde || slot > v.hasta)
            {
                return Err(Rechazo::Limite("ventana_voto"));
            }
            if self.entradas.values().any(|e| ventana_de(&e.tx) == Some(v)) {
                return Err(Rechazo::Limite("cuota_por_ventana"));
            }
        }
        // Cuota por clave/incidente para v2/v4 sin tarifa (TX-R-20, DR-02/DR-09).
        if let Some(clave) = analisis.clave
            && analisis.cuota_clave
            && analisis.fee == Some(0)
            && self.por_clave.contains_key(&clave)
        {
            return Err(Rechazo::Limite("cuota_por_clave"));
        }
        if let Some(inc) = analisis.incidente
            && self.por_incidente.contains_key(&inc)
        {
            return Err(Rechazo::Limite("cuota_por_incidente"));
        }
        // Entradas conocidas: si falta alguna, va a huérfanas (TX-R-18).
        let entradas_conocidas = tx
            .inputs
            .iter()
            .all(|i| self.valor_de(&i.outpoint).is_some());
        if !entradas_conocidas {
            // Un conflicto con la mempool es `VistaLocal` (TX-R-14); una entrada que falta en el
            // estado local es huérfana.
            for i in &tx.inputs {
                if self.gastados.contains_key(&i.outpoint) {
                    return Err(Rechazo::VistaLocal("conflicto"));
                }
            }
            self.guardar_huerfana(peer, analisis, ahora, punto)?;
            return Ok(Admision::Huerfana);
        }
        self.aplicar_analisis(&analisis, peer, ahora, punto, anidar)
    }

    /// Cuenta un rechazo por tope local (TX-6). La decisión ya está tomada; esto solo la contabiliza.
    fn registrar_rechazo_limite(&mut self, motivo: &'static str) {
        let r = &mut self.rechazos_limite;
        r.total = r.total.saturating_add(1);
        let campo = match motivo {
            "global" | "global_evidencias" => &mut r.global,
            "par_memoria" => &mut r.par_memoria,
            "par_tasa" => &mut r.par_tasa,
            "tarifa_minima" => &mut r.tarifa_minima,
            "tarifa_rodante" => &mut r.tarifa_rodante,
            "huerfanas" => &mut r.huerfanas,
            "cuota_por_clave" => &mut r.cuota_por_clave,
            "cuota_por_incidente" => &mut r.cuota_por_incidente,
            "cuota_por_ventana" => &mut r.cuota_por_ventana,
            "ventana_voto" => &mut r.ventana_voto,
            _ => return,
        };
        *campo = campo.saturating_add(1);
    }

    /// Comprueba forma, tamaño e identidad, y clasifica clave/incidente. No toca el estado.
    fn analizar(&self, tx: &Tx, testigos: &[Vec<u8>]) -> Result<Analisis, Rechazo> {
        if tx.version == 4 && self.evp.evp {
            validar_forma_tx_v4(tx, testigos, self.evp.cbid)
                .map_err(|_| Rechazo::Demostrable("forma_v4"))?;
        } else {
            validar_forma_tx(tx, testigos).map_err(|_| Rechazo::Demostrable("forma"))?;
        }
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
        let peso = buf.len() as u64;
        if peso > self.params.max_tx_bytes {
            return Err(Rechazo::Demostrable("tamano"));
        }
        // Las coinbases no se relevan (decisión 3 del director): ni v1 sin entradas ni v3.
        if (tx.version == 1 && tx.inputs.is_empty()) || tx.version == 3 {
            return Err(Rechazo::VistaLocal("coinbase"));
        }
        if !matches!(tx.version, 1 | 2 | 4 | 5 | 6) {
            return Err(Rechazo::Demostrable("version"));
        }
        // Entradas repetidas en la propia transacción: doble gasto demostrable.
        for (i, a) in tx.inputs.iter().enumerate() {
            if tx.inputs.iter().take(i).any(|b| b.outpoint == a.outpoint) {
                return Err(Rechazo::Demostrable("doble_gasto_interno"));
            }
        }
        let (clave, incidente, cuota_clave) = match &tx.extension {
            ExtensionTx::Garantia { clave, tipo, .. } => {
                // La cuota por clave aplica a las operaciones de garantía v2 sin tarifa (TX-R-20).
                let _ = tipo;
                (Some(*clave), None, true)
            }
            ExtensionTx::Evidencia { h1, .. } => {
                let inc = zx_core::incident_id_evidencia(
                    h1.consensus_branch_id,
                    h1.sol.public_key.bytes(),
                    h1.sol.sector_index,
                    h1.sol.history_size,
                    &h1.sol.chunk,
                    h1.slot,
                );
                (None, Some(*inc.as_bytes()), true)
            }
            ExtensionTx::Ninguna | ExtensionTx::CoinbasePost { .. } => (None, None, true),
            // SR-1-2 · v5: la firma la verifica el motor de transición al aplicarla.
            // SR-G2b · cuota por clave: a lo sumo **una** operación de sector pendiente por clave
            // (`REVISION-SR1.md` límite 1). Entra por la misma cuota `por_clave` que la v2 sin
            // tarifa, porque `tarifa_conocida` devuelve `Some(0)` para la v5 sin entradas.
            ExtensionTx::Sector { operacion } => (Some(operacion.clave()), None, true),
            // PT-3bc · v6: cuota de **una** operación pendiente por clave para las clases de prueba
            // (`REVISION-PT3a` decisión 3); el voto propio de ventana queda exento (`AUS-2b` N6) para
            // que una clave acumule ventanas en vuelo.
            ExtensionTx::PruebaAlmacenamiento { operacion } => {
                if let Some(i) = identidad_evidencia_voto(tx) {
                    // S2(c): la evidencia no ocupa ni consume la cuota del reportero.
                    (None, Some(i.incidente), false)
                } else {
                    let exenta = matches!(operacion.clase(), ClasePruebaAlmacenamiento::VotoPropio);
                    (Some(operacion.clave()), None, !exenta)
                }
            }
        };
        let fee = self.tarifa_conocida(tx);
        Ok(Analisis {
            tx: tx.clone(),
            testigos: testigos.to_vec(),
            txid: txid(tx, self.cbid),
            peso,
            fee,
            clave,
            incidente,
            cuota_clave,
            es_sector: matches!(tx.extension, ExtensionTx::Sector { .. }),
        })
    }

    /// Tarifa de una transacción si todas sus entradas se conocen; `None` si falta alguna.
    fn tarifa_conocida(&self, tx: &Tx) -> Option<u64> {
        let mut entradas: i128 = 0;
        for i in &tx.inputs {
            let v = self.valor_de(&i.outpoint)?;
            entradas = entradas.checked_add(i128::from(v))?;
        }
        let mut salidas: i128 = 0;
        for o in &tx.outputs {
            salidas = salidas.checked_add(i128::from(o.value.brek()))?;
        }
        let importe = match &tx.extension {
            ExtensionTx::Garantia {
                tipo: TipoGarantia::Deposito,
                importe,
                ..
            } => i128::from(importe.brek()),
            _ => 0,
        };
        let fee = entradas.checked_sub(salidas)?.checked_sub(importe)?;
        u64::try_from(fee).ok()
    }

    /// Aplica la transacción sobre la vista actual y, si pasa los topes, la inserta.
    fn aplicar_analisis(
        &mut self,
        a: &Analisis,
        peer: Option<PeerId>,
        ahora: Instant,
        punto: Punto,
        anidar: bool,
    ) -> Result<Admision, Rechazo> {
        // Topes por par (TX-R-21/22).
        if let Some(p) = peer {
            let usados = self.bytes_por_par.get(&p).copied().unwrap_or(0);
            if usados.saturating_add(a.peso as usize) > self.politica.s_par {
                return Err(Rechazo::Limite("par_memoria"));
            }
            // MP-4 · U2: la tasa de una huérfana ya se contó al llegar al depósito; la admisión
            // que nace de `resolver_huerfanas` (`anidar == false`) no la cuenta otra vez.
            if anidar && !self.consumir_tasa(p, a.peso as usize, ahora) {
                return Err(Rechazo::Limite("par_tasa"));
            }
        }
        let fee = a.fee.unwrap_or(0);
        // B26-3 · La tarifa mínima y el mínimo rodante se comprueban **antes** de tocar la mempool:
        // con B26-2 se desalojaba primero y una candidata rechazada por tarifa ya había borrado
        // normales (y, en el camino normal, ya había subido el mínimo rodante).
        // Tarifa mínima para transferencias v1 (TX-R-11). v2/v4 sin tarifa van por cuota (TX-R-45).
        if a.tx.version == 1 && fee < self.politica.phi_min.saturating_mul(a.peso) {
            return Err(Rechazo::Limite("tarifa_minima"));
        }
        // TX-R-15: una transferencia por debajo del mínimo rodante se rechaza sin entrar (las
        // operaciones sin tarifa de v2/v4 no compiten por tarifa, TX-R-45).
        if a.tx.version == 1
            && self.minimo_rodante.0 > 0
            && comparar_feerate(
                (u128::from(fee), a.peso.max(1) as u128),
                self.minimo_rodante,
            ) == std::cmp::Ordering::Less
        {
            return Err(Rechazo::Limite("tarifa_rodante"));
        }
        let entrada = Entrada {
            tx: a.tx.clone(),
            testigos: a.testigos.clone(),
            txid: a.txid,
            peso: a.peso,
            fee,
            origen: punto,
            peer,
            clave: a.clave,
            incidente: a.incidente,
            creados: a
                .tx
                .outputs
                .iter()
                .enumerate()
                .map(|(j, _)| OutPoint {
                    prev_txid: a.txid,
                    prev_index: u32::try_from(j).unwrap_or(u32::MAX),
                })
                .collect(),
        };
        // Tope global con desalojo por tarifa (TX-R-15). B26-1: una operación de sector v5 no
        // compite por tarifa (no tiene entradas y su tarifa es 0); con la mempool llena desaloja
        // la transacción **normal** de menor `feerate` —nunca un depósito reservado ni otra
        // operación de sector— para hacerse sitio. B26-3: el desalojo se planifica sin mutar y la
        // candidata se valida sobre la vista que resultaría del plan antes de confirmarlo.
        if self.bytes_totales.saturating_add(a.peso as usize) > self.politica.s {
            return self.desalojar_y_aplicar(a, entrada, fee, ahora, punto, anidar);
        }
        // Aplicación al estado virtual: es la validación estricta de contexto (TX-R-09/14).
        self.aplicar_entrada(&entrada, ahora)?;
        self.insertar(entrada);
        // TX-R-19: las salidas nuevas pueden resolver huérfanas que esperaban por ellas. MP-3 · H5:
        // la llamada sigue en su sitio; solo se omite cuando esta admisión nace de la propia
        // resolución (`anidar == false`), cuyo bucle ya recorre el depósito.
        if anidar {
            self.resolver_huerfanas(ahora, punto);
        }
        Ok(Admision::Admitida)
    }

    /// B26-3 · Hace sitio para `entrada` con la mempool llena: planifica el desalojo **sin mutar**,
    /// confirma el plan y solo entonces valida la candidata sobre la vista resultante. Si la
    /// validación falla, restaura la instantánea: el rechazo conserva entradas, txids, bytes,
    /// mínimo rodante y vista virtual. La tasa por par ya consumida es contabilidad de **intento**
    /// (TX-R-22) y no se deshace.
    fn desalojar_y_aplicar(
        &mut self,
        a: &Analisis,
        entrada: Entrada,
        fee: u64,
        ahora: Instant,
        punto: Punto,
        anidar: bool,
    ) -> Result<Admision, Rechazo> {
        if !es_evidencia(&a.tx) {
            self.protegidas.extend(
                self.entradas
                    .values()
                    .filter(|e| es_evidencia(&e.tx))
                    .map(|e| e.txid),
            );
        }
        let Some(plan) =
            self.plan_de_desalojo(a.peso as usize, fee, a.es_sector || es_evidencia(&a.tx))
        else {
            return Err(Rechazo::Limite(
                if es_evidencia(&a.tx)
                    && !self.entradas.is_empty()
                    && self.entradas.values().all(|e| es_evidencia(&e.tx))
                {
                    "global_evidencias"
                } else {
                    "global"
                },
            ));
        };
        let instantanea = self.instantanea();
        self.confirmar_desalojo(&plan);
        if let Err(motivo) = self.aplicar_entrada(&entrada, ahora) {
            self.restaurar(instantanea);
            return Err(motivo);
        }
        self.insertar(entrada);
        // MP-3 · H5: misma llamada que en `aplicar_analisis`, omitida solo desde la resolución.
        if anidar {
            self.resolver_huerfanas(ahora, punto);
        }
        Ok(Admision::Admitida)
    }

    /// B26-3 · Copia del estado mutable que un plan de desalojo puede cambiar, para deshacerlo si la
    /// candidata no valida sobre la vista resultante (transacción local equivalente). Incluye la
    /// vista, los índices, los bytes y el mínimo rodante; **excluye** la tasa por par, que es
    /// contabilidad de intento y no pérdida de entradas.
    fn instantanea(&self) -> InstantaneaMempool {
        InstantaneaMempool {
            vista: self.vista.clone(),
            entradas: self.entradas.clone(),
            orden: self.orden.clone(),
            gastados: self.gastados.clone(),
            creados: self.creados.clone(),
            bytes_totales: self.bytes_totales,
            bytes_por_par: self.bytes_por_par.clone(),
            por_clave: self.por_clave.clone(),
            por_incidente: self.por_incidente.clone(),
            minimo_rodante: self.minimo_rodante,
            hechos_votos: self.hechos_votos.clone(),
            seguidas: self.seguidas.clone(),
            retiradas: self.retiradas.clone(),
        }
    }

    /// B26-3 · Restaura una instantánea tomada antes de confirmar un plan de desalojo.
    fn restaurar(&mut self, i: InstantaneaMempool) {
        self.vista = i.vista;
        self.entradas = i.entradas;
        self.orden = i.orden;
        self.gastados = i.gastados;
        self.creados = i.creados;
        self.bytes_totales = i.bytes_totales;
        self.bytes_por_par = i.bytes_por_par;
        self.por_clave = i.por_clave;
        self.por_incidente = i.por_incidente;
        self.minimo_rodante = i.minimo_rodante;
        self.hechos_votos = i.hechos_votos;
        self.seguidas = i.seguidas;
        self.retiradas = i.retiradas;
    }

    /// Aplica la transacción de `e` sobre `self.vista`. Si falla, la vista no cambia.
    fn aplicar_entrada(&mut self, e: &Entrada, _ahora: Instant) -> Result<(), Rechazo> {
        let clon = self.vista.clone();
        match self.aplicar_a_vista(&clon, &e.tx, &e.testigos) {
            Ok(nuevo) => {
                self.vista = nuevo;
                Ok(())
            }
            Err(motivo) => Err(clasificar_motivo_tx(&motivo, &e.tx)),
        }
    }

    /// Aplica una transacción a `vista` con el motor de consenso y devuelve el estado nuevo.
    ///
    /// En fase PoW (sin terminal) usa el modo **estricto** con un bloque PoW sintético de la altura
    /// siguiente; con terminal fijo o en PoST usa el modo **fusión** con un bloque PoST sintético.
    /// El bloque sintético no se persiste ni se difunde: es solo el vehículo para que el motor
    /// valide la transacción contra el estado virtual (TX-R-14).
    ///
    /// **P1 (`ORDEN-MP1`):** el punto es **siempre** [`punto_siguiente`] del estado base de la
    /// cola, no el que la vista hubiera alcanzado por las transacciones ya admitidas; y el estado
    /// devuelto repone los escalares de punto para que `vista` no avance (invariante
    /// `vista.altura == base.altura` y `vista.slot == base.slot`). Así la transacción número `k` se
    /// valida en el mismo punto que la primera y no hay deriva de madurez (IPA B-62).
    fn aplicar_a_vista(
        &self,
        vista: &Estado,
        tx: &Tx,
        testigos: &[Vec<u8>],
    ) -> Result<Estado, ErrorTransicion> {
        let hash_sintetico = BlockHash::from_digest(Digest::from_bytes([0xA5; 32]));
        let mut nuevo = match punto_siguiente(&self.base) {
            Punto::Altura(altura) => {
                let bloque = BloqueTransicion::nuevo(
                    HechosCabecera::PoW {
                        hash: hash_sintetico,
                        padre: hash_sintetico,
                        altura,
                        trabajo: U256::one(),
                        pow_valido: true,
                    },
                    vec![(tx.clone(), testigos.to_vec())],
                );
                let (nuevo, _) =
                    aplicar_con_undo(vista, &bloque, &self.params, self.cbid, &self.evp)?;
                nuevo
            }
            Punto::Slot(slot) => {
                let padre = self.base.terminal.unwrap_or(hash_sintetico);
                let bloque = BloqueTransicion::nuevo(
                    HechosCabecera::PoST {
                        hash: hash_sintetico,
                        padre,
                        slot,
                        productor: productor_sintetico(vista),
                        peso: 1,
                        prueba_valida: true,
                        requisito_declarado: 0,
                    },
                    vec![(tx.clone(), testigos.to_vec())],
                )
                .con_hechos_votos(vec![
                    self.hechos_votos
                        .get(&txid(tx, self.cbid))
                        .copied()
                        .unwrap_or(HechoVoto::Inadmisible),
                ]);
                let (mut nuevo, _undo, descartadas) = aplicar_fusion(
                    vista,
                    &bloque,
                    Punto::Slot(slot),
                    &self.params,
                    self.cbid,
                    &self.evp,
                )?;
                if let Some(d) = descartadas.first() {
                    return Err(d.motivo.clone());
                }
                // COLA-1 · el vehículo sintético no produce un bloque ni cobra por incluir
                // evidencias. La clave no decodifica a un punto Ed25519: ninguna operación
                // firmada puede ser suya. Conservamos los efectos de la tx sobre claves reales.
                let productor = productor_sintetico(vista);
                if let Some(anterior) = vista.garantias.get(&productor) {
                    nuevo.garantias.insert(productor, anterior.clone());
                } else {
                    nuevo.garantias.remove(&productor);
                }
                nuevo
                    .ultimo_slot_producido
                    .clone_from(&vista.ultimo_slot_producido);
                nuevo
            }
        };
        restaurar_punto(&mut nuevo, &self.base);
        Ok(nuevo)
    }

    /// P1 · Expulsa de la cola las entradas indicadas y las que dependan de ellas (las que gastan,
    /// directa o transitivamente, salidas creadas por ellas), **sin** marcarlas como aplicadas, y
    /// recompone la vista. Devuelve cuántas entradas se retiraron de la cola.
    ///
    /// Es la retirada que usa P2 cuando un bloque propio es rechazado por su cuerpo: las
    /// transacciones que el nodo iba a minar no deben seguir en la cola (volverían a formar el mismo
    /// cuerpo inválido), pero tampoco se han aplicado.
    pub fn expulsar(&mut self, ids: &[TxId]) -> usize {
        let antes = self.entradas.len();
        let mut a_expulsar: BTreeSet<TxId> = ids
            .iter()
            .copied()
            .filter(|id| self.entradas.contains_key(id))
            .collect();
        // Cierre transitivo: una entrada que gasta una salida creada por una expulsada también
        // sale (su `prev_txid` es el de la creadora), y así sucesivamente.
        loop {
            let candidatos: Vec<(TxId, Vec<OutPoint>)> = self
                .entradas
                .iter()
                .filter(|(id, _)| !a_expulsar.contains(id))
                .map(|(id, e)| (*id, e.tx.inputs.iter().map(|i| i.outpoint).collect()))
                .collect();
            let nuevas: Vec<TxId> = candidatos
                .into_iter()
                .filter(|(_, entradas)| {
                    entradas.iter().any(|op| a_expulsar.contains(&op.prev_txid))
                })
                .map(|(id, _)| id)
                .collect();
            if nuevas.is_empty() {
                break;
            }
            a_expulsar.extend(nuevas);
        }
        for id in &a_expulsar {
            self.eliminar(id, Rechazo::VistaLocal("expulsion"));
        }
        antes.saturating_sub(self.entradas.len())
    }

    /// MP-1 · P2 · gancho **solo de test** (`ORDEN-MP1` §4.7): mete en la cola una entrada sin
    /// validarla contra el motor, para poder reproducir el caso «el bloque propio lleva una tx que
    /// la cola admitió pero el motor rechaza» sin depender del fallo real. Rellena los índices como
    /// [`Self::insertar`] y no toca la vista (la entrada no se aplica).
    #[cfg(test)]
    pub(crate) fn insertar_sin_validar_para_test(&mut self, tx: Tx, testigos: Vec<Vec<u8>>) {
        let txid = txid(&tx, self.cbid);
        if self.entradas.contains_key(&txid) {
            return;
        }
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, &tx, &testigos);
        let peso = buf.len() as u64;
        let creados: Vec<OutPoint> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(j, _)| OutPoint {
                prev_txid: txid,
                prev_index: u32::try_from(j).unwrap_or(u32::MAX),
            })
            .collect();
        let e = Entrada {
            tx,
            testigos,
            txid,
            peso,
            fee: 0,
            origen: Punto::Altura(0),
            peer: None,
            clave: None,
            incidente: None,
            creados,
        };
        self.insertar(e);
    }

    /// Valor (en brek) de una salida conocida: del estado base o creada por la propia mempool.
    fn valor_de(&self, op: &OutPoint) -> Option<u64> {
        if let Some(e) = self.vista.utxo.get(op) {
            return u64::try_from(e.valor.brek()).ok();
        }
        self.creados.get(op).copied()
    }

    /// Inserta una entrada ya validada y actualiza todos los índices.
    fn insertar(&mut self, e: Entrada) {
        for i in &e.tx.inputs {
            self.creados.remove(&i.outpoint);
            self.gastados.insert(i.outpoint, e.txid);
        }
        for op in &e.creados {
            self.creados.insert(
                *op,
                self.vista
                    .utxo
                    .get(op)
                    .map_or(0, |u| u64::try_from(u.valor.brek()).unwrap_or(0)),
            );
        }
        self.bytes_totales = self.bytes_totales.saturating_add(e.peso as usize);
        if let Some(p) = e.peer {
            *self.bytes_por_par.entry(p).or_insert(0) += e.peso as usize;
        }
        if let Some(c) = e.clave {
            self.por_clave.insert(c, e.txid);
        }
        if let Some(i) = e.incidente {
            self.por_incidente.insert(i, e.txid);
        }
        self.orden.push(e.txid);
        self.entradas.insert(e.txid, e);
    }

    /// Saca una entrada de la mempool y limpia sus índices (sin recomputar la vista).
    fn eliminar(&mut self, id: &TxId, motivo: Rechazo) {
        let Some(e) = self.entradas.remove(id) else {
            return;
        };
        self.protegidas.remove(id);
        self.notificar_retirada(&e.tx, motivo);
        self.hechos_votos.remove(id);
        self.orden.retain(|x| x != id);
        self.bytes_totales = self.bytes_totales.saturating_sub(e.peso as usize);
        if let Some(p) = e.peer
            && let Some(b) = self.bytes_por_par.get_mut(&p)
        {
            *b = b.saturating_sub(e.peso as usize);
        }
        for i in &e.tx.inputs {
            if self.gastados.get(&i.outpoint) == Some(id) {
                self.gastados.remove(&i.outpoint);
            }
        }
        for op in &e.creados {
            self.creados.remove(op);
        }
        if let Some(c) = e.clave
            && self.por_clave.get(&c) == Some(id)
        {
            self.por_clave.remove(&c);
        }
        if let Some(i) = e.incidente
            && self.por_incidente.get(&i) == Some(id)
        {
            self.por_incidente.remove(&i);
        }
        // Recomputa la vista desde el estado base: es la única forma de que quitar una transacción
        // no deje sus efectos en el estado virtual.
        self.recomputar_vista();
    }

    /// Reconstruye `vista`, `gastados` y `creados` aplicando en orden lo que queda en `entradas`.
    fn recomputar_vista(&mut self) {
        self.vista = self.base.clone();
        self.gastados.clear();
        self.creados.clear();
        let ids: Vec<TxId> = self.orden.clone();
        let mut conservadas: Vec<TxId> = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(e) = self.entradas.get(&id).cloned() else {
                continue;
            };
            let clon = self.vista.clone();
            match self.aplicar_a_vista(&clon, &e.tx, &e.testigos) {
                Ok(nuevo) => {
                    self.vista = nuevo;
                    for i in &e.tx.inputs {
                        self.gastados.insert(i.outpoint, e.txid);
                    }
                    for op in &e.creados {
                        self.creados.insert(
                            *op,
                            self.vista
                                .utxo
                                .get(op)
                                .map_or(0, |u| u64::try_from(u.valor.brek()).unwrap_or(0)),
                        );
                    }
                    conservadas.push(id);
                }
                Err(motivo) => {
                    self.notificar_retirada(&e.tx, clasificar_motivo_tx(&motivo, &e.tx));
                    self.hechos_votos.remove(&id);
                    self.entradas.remove(&id);
                    self.bytes_totales = self.bytes_totales.saturating_sub(e.peso as usize);
                    if let Some(p) = e.peer
                        && let Some(b) = self.bytes_por_par.get_mut(&p)
                    {
                        *b = b.saturating_sub(e.peso as usize);
                    }
                    if let Some(c) = e.clave
                        && self.por_clave.get(&c) == Some(&id)
                    {
                        self.por_clave.remove(&c);
                    }
                    if let Some(i) = e.incidente
                        && self.por_incidente.get(&i) == Some(&id)
                    {
                        self.por_incidente.remove(&i);
                    }
                }
            }
        }
        self.orden = conservadas;
    }

    /// B26-1 · ¿la entrada es una operación de sector (v5)?
    fn es_operacion_sector(e: &Entrada) -> bool {
        matches!(e.tx.extension, ExtensionTx::Sector { .. })
    }

    /// B26-1 · ¿la entrada ocupa la **reserva**? Lo son los depósitos de claves sin garantía
    /// activa en el estado base (misma condición que `seleccionar`) y las operaciones de sector
    /// pendientes. Las entradas de reserva **no se desalojan**: ni al admitir una normal —dejarían
    /// de ser reserva— ni, por decisión de la orden, al admitir una operación de sector.
    /// EV-2: este predicado de desalojo incluye evidencia ya admitida; no lo usa la selección.
    fn es_reserva(&self, e: &Entrada) -> bool {
        es_evidencia(&e.tx)
            || Self::es_operacion_sector(e)
            || (e
                .clave
                .is_some_and(|c| self.base.activo_de(&c) < self.params.q)
                && matches!(
                    e.tx.extension,
                    ExtensionTx::Garantia {
                        tipo: TipoGarantia::Deposito,
                        ..
                    }
                ))
    }

    /// B26-1 · Ids de las entradas **desalojables** (ni reserva ni sector), ordenadas por `feerate`
    /// ascendente con desempate por `txid` para ser determinista.
    fn desalojables_por_feerate(&self) -> Vec<TxId> {
        let mut ids: Vec<TxId> = self
            .entradas
            .iter()
            .filter(|(_, e)| !self.es_reserva(e))
            .map(|(id, _)| *id)
            .collect();
        ids.sort_by(|a, b| {
            let ea = self.entradas.get(a);
            let eb = self.entradas.get(b);
            match (ea, eb) {
                (Some(x), Some(y)) => comparar_feerate(x.feerate(), y.feerate()).then(a.cmp(b)),
                _ => a.cmp(b),
            }
        });
        ids
    }

    /// B26-1/B26-3/B26-4 · Plan de desalojo **sin mutar** para que quepa `peso`.
    ///
    /// Para una operación de sector (`es_sector`) expulsa normales por `feerate` ascendente sin
    /// comparar tarifas ni tocar el mínimo rodante; para una normal, solo expulsa las de `feerate`
    /// estrictamente menor que la candidata y sube el mínimo al mayor feerate expulsado. Cada
    /// expulsión se cuenta una sola vez (`liberado` es el único descuento). Devuelve `None` si las
    /// normales elegibles no bastan, sin tocar la mempool.
    ///
    /// B26-4 · Una entrada solo entra en el plan si, tras expulsar las ya planificadas, **toda
    /// reserva vigente** sigue validando en la vista recompuesta. Así no se puede evadir la
    /// protección de reservas desalojando un padre (o un ancestro transitivo) del que dependan, ni
    /// una dependencia de estado. Las entradas que no cumplen se saltan y se prueban las
    /// siguientes: si no quedan normales elegibles suficientes, el plan es `None` y el rechazo es
    /// atómico.
    fn plan_de_desalojo(&self, peso: usize, fee: u64, es_sector: bool) -> Option<PlanDesalojo> {
        let candidato = (u128::from(fee), peso.max(1) as u128);
        let mut ids: Vec<TxId> = Vec::new();
        let mut liberado = 0usize;
        let mut mayor_evicto: Option<(u128, u128)> = None;
        for id in self.desalojables_por_feerate() {
            if self.cabe_tras_liberar(peso, liberado) {
                break;
            }
            let Some((fe, peso_e)) = self
                .entradas
                .get(&id)
                .map(|e| ((u128::from(e.fee), e.peso.max(1) as u128), e.peso as usize))
            else {
                continue;
            };
            // Una normal no desaloja a quien tiene mejor o igual feerate que ella; una operación de
            // sector no compite por tarifa (B26-1).
            if !es_sector && comparar_feerate(fe, candidato) != std::cmp::Ordering::Less {
                break;
            }
            ids.push(id);
            if !self.reservas_sobreviven(&ids) {
                // Expulsar `id` invalidaría una reserva vigente: no es elegible.
                ids.pop();
                continue;
            }
            liberado = liberado.saturating_add(peso_e);
            if mayor_evicto.is_none_or(|m| comparar_feerate(m, fe) == std::cmp::Ordering::Less) {
                mayor_evicto = Some(fe);
            }
        }
        if !self.cabe_tras_liberar(peso, liberado) {
            return None;
        }
        let nuevo_minimo = match mayor_evicto {
            Some(m)
                if !es_sector
                    && comparar_feerate(m, self.minimo_rodante) == std::cmp::Ordering::Greater =>
            {
                Some(m)
            }
            _ => None,
        };
        Some(PlanDesalojo { ids, nuevo_minimo })
    }

    /// B26-4 · ¿Sobrevive toda reserva vigente si se expulsan `evictos`?
    ///
    /// Reaplica en orden las entradas que quedan sobre el estado base, con la misma semántica que
    /// [`Self::recomputar_vista`], y devuelve `false` en cuanto una reserva deja de validar. Cubre
    /// dependencias por UTXO (inputs inmediatos y ancestros transitivos) y por estado (por ejemplo,
    /// la garantía que necesita un alta de sector), no solo los inputs inmediatos. No muta nada.
    fn reservas_sobreviven(&self, evictos: &[TxId]) -> bool {
        if !self.entradas.values().any(|e| self.es_reserva(e)) {
            return true;
        }
        let mut vista = self.base.clone();
        for id in &self.orden {
            if evictos.contains(id) {
                continue;
            }
            let Some(e) = self.entradas.get(id) else {
                continue;
            };
            match self.aplicar_a_vista(&vista, &e.tx, &e.testigos) {
                Ok(nuevo) => vista = nuevo,
                Err(_) if self.es_reserva(e) => return false,
                Err(_) => {}
            }
        }
        true
    }

    /// B26-3 · Confirma un plan de desalojo ya validado: saca las entradas y sube el mínimo rodante.
    fn confirmar_desalojo(&mut self, plan: &PlanDesalojo) {
        for id in &plan.ids {
            self.eliminar(id, Rechazo::Limite("desalojo"));
        }
        if let Some(m) = plan.nuevo_minimo {
            self.minimo_rodante = m;
        }
    }

    /// B26-2 · ¿caben `peso` bytes si se liberan `liberado` (plan aún sin aplicar)? Consulta los
    /// bytes reales que quedan y no muta nada.
    fn cabe_tras_liberar(&self, peso: usize, liberado: usize) -> bool {
        self.bytes_totales
            .saturating_sub(liberado)
            .saturating_add(peso)
            <= self.politica.s
    }

    /// Consume `peso` de la ventana de tasa del par (TX-R-22). `false` si la excede.
    fn consumir_tasa(&mut self, peer: PeerId, peso: usize, ahora: Instant) -> bool {
        let ventana = std::time::Duration::from_millis(self.politica.ventana_tasa_ms);
        let entrada = self.tasa_por_par.entry(peer).or_insert((ahora, 0));
        if ahora.duration_since(entrada.0) >= ventana {
            *entrada = (ahora, 0);
        }
        if entrada.1.saturating_add(peso) > self.politica.r_par {
            return false;
        }
        entrada.1 = entrada.1.saturating_add(peso);
        true
    }

    /// MP-4 · U3 · víctima del desalojo con el depósito lleno: la huérfana **más antigua** del par
    /// que **más bytes** de huérfanas ocupa. En empate gana el par de identificador menor en orden
    /// de bytes (`Option<PeerId>` ordena `None` primero, que es el par de las transacciones propias
    /// del nodo). `None` si el depósito está vacío.
    fn huerfana_del_par_que_mas_ocupa(&self) -> Option<TxId> {
        let mut bytes_por_par: BTreeMap<Option<PeerId>, usize> = BTreeMap::new();
        for e in self.huerfanas.values() {
            *bytes_por_par.entry(e.peer).or_insert(0) += e.peso as usize;
        }
        // `BTreeMap` recorre en orden ascendente de clave: en empate de bytes se queda el primero,
        // que es el par de identificador menor.
        let mut elegido: Option<(Option<PeerId>, usize)> = None;
        for (par, bytes) in bytes_por_par {
            match &elegido {
                Some((_, max)) if *max >= bytes => {}
                _ => elegido = Some((par, bytes)),
            }
        }
        let (par, _) = elegido?;
        self.huerfanas
            .iter()
            .filter(|(_, e)| e.peer == par)
            .min_by_key(|(_, e)| e.origen)
            .map(|(id, _)| *id)
    }

    /// Guarda una huérfana, acotada por número y bytes (TX-R-18).
    ///
    /// MP-4 · U1: recuerda `peer` (el par que la mandó; `None` si es propia del nodo). U2: la tasa
    /// `R_par` del par se cuenta **aquí**, al llegar, una sola vez (la resolución no la vuelve a
    /// contar). U3: con el depósito lleno se desaloja la más antigua del par que más bytes ocupa.
    fn guardar_huerfana(
        &mut self,
        peer: Option<PeerId>,
        a: Analisis,
        ahora: Instant,
        punto: Punto,
    ) -> Result<(), Rechazo> {
        // U2 · misma contabilidad de intento que una tx recién llegada: se consume aunque el
        // depósito acabe rechazándola.
        if let Some(p) = peer
            && !self.consumir_tasa(p, a.peso as usize, ahora)
        {
            return Err(Rechazo::Limite("par_tasa"));
        }
        if self.huerfanas.len() >= self.politica.h_max
            || self.bytes_huerfanas.saturating_add(a.peso as usize) > self.politica.h_bytes
        {
            // U3 · se descarta la más antigua del par que más bytes ocupa (política local, no
            // consenso).
            if let Some(vieja) = self.huerfana_del_par_que_mas_ocupa()
                && let Some(e) = self.huerfanas.remove(&vieja)
            {
                self.bytes_huerfanas = self.bytes_huerfanas.saturating_sub(e.peso as usize);
            }
            if self.huerfanas.len() >= self.politica.h_max
                || self.bytes_huerfanas.saturating_add(a.peso as usize) > self.politica.h_bytes
            {
                return Err(Rechazo::Limite("huerfanas"));
            }
        }
        let e = Entrada {
            tx: a.tx,
            testigos: a.testigos,
            txid: a.txid,
            peso: a.peso,
            fee: a.fee.unwrap_or(0),
            origen: punto,
            peer,
            clave: a.clave,
            incidente: a.incidente,
            creados: Vec::new(),
        };
        self.bytes_huerfanas = self.bytes_huerfanas.saturating_add(e.peso as usize);
        self.huerfanas.insert(e.txid, e);
        Ok(())
    }

    /// Reintenta las huérfanas que ya tienen todas sus entradas (TX-R-19). Se revalida **entera**
    /// (forma, peso, cuota y contexto) readmitiéndolas por la misma puerta que una tx nueva.
    ///
    /// MP-3 · H1: **sin reentrada**. Admitir una huérfana desde aquí ya no abre otra resolución
    /// anidada (`anidar == false`); la cascada la resuelve este bucle, que repite pasadas hasta que
    /// una pasada entera no admite ninguna. La pila usada deja de crecer con las huérfanas.
    ///
    /// MP-3 · H3: el orden de intento es el de la recursión de hoy: recorrido del depósito por su
    /// orden de claves (`BTreeMap`), **reiniciado tras cada admisión con éxito** (la recursión
    /// abría una resolución nueva que volvía a recorrer desde la menor clave).
    ///
    /// MP-3 · H2: cada intento saca antes la huérfana del depósito (como hoy), de modo que una
    /// llamada externa hace como mucho tantos intentos como huérfanas había al entrar; la que no
    /// valida se descarta y no se reencola.
    pub fn resolver_huerfanas(&mut self, ahora: Instant, punto: Punto) {
        let max_intentos = self.huerfanas.len();
        let mut intentos = 0usize;
        loop {
            let ids: Vec<TxId> = self.huerfanas.keys().copied().collect();
            let mut admitio = false;
            for id in ids {
                if intentos >= max_intentos {
                    // H2 · cota estructural. No se alcanza (cada intento saca una huérfana y
                    // ninguna se reencola), pero se deja como red de seguridad.
                    return;
                }
                let Some(e) = self.huerfanas.get(&id).cloned() else {
                    continue;
                };
                let conocidas =
                    e.tx.inputs
                        .iter()
                        .all(|i| self.valor_de(&i.outpoint).is_some());
                if !conocidas {
                    continue;
                }
                self.huerfanas.remove(&id);
                self.bytes_huerfanas = self.bytes_huerfanas.saturating_sub(e.peso as usize);
                intentos += 1;
                // Si no pasa la validación, se descarta y no se reencola (la pasada sigue). Si se
                // admite, se reinicia la pasada para recoger lo que la nueva entrada desbloquee.
                if matches!(
                    self.admitir_con(e.peer, e.tx, e.testigos, ahora, punto, false),
                    Ok(Admision::Admitida)
                ) {
                    admitio = true;
                    break;
                }
            }
            if !admitio {
                break;
            }
        }
    }

    /// Selecciona transacciones para un bloque: primero el depósito del granjero sin garantía
    /// (reserva de TX-R-46/DR-10) y después muestreo aleatorio ponderado por `feerate^α`
    /// (TX-R-28/DR-08). La semilla es local del bloque.
    ///
    /// MP-2 · Regla S: la lista devuelta es aceptable por **un solo bloque**. Si una transacción
    /// está, todas sus madres (UTXO y nonce anterior de garantía de la misma clave) están y
    /// aparecen antes que ella. La selección se hace igual que antes (reserva, muestreo, topes y
    /// una prueba de almacenamiento por bloque); después se retiran las hijas sin madre y se
    /// reordena topológicamente de forma estable. **No** se añade ninguna transacción que el
    /// muestreo no eligiera.
    #[must_use]
    pub fn seleccionar(&self, max_bytes: u64, semilla: u64) -> Vec<(Tx, Vec<Vec<u8>>)> {
        let elegidas = self.seleccionar_bruta(max_bytes, semilla);
        self.aplicar_regla_s(elegidas)
    }

    /// MP-2 · La selección **sin** la regla S: la reserva, el muestreo por `feerate^α`, los topes
    /// de bytes y la regla de una prueba de almacenamiento por bloque, tal y como eran antes de
    /// esta orden. La usa [`Self::seleccionar`] y la conserva como «selección anterior» la prueba
    /// de no-regresión `seleccion_sin_cadenas_no_cambia`.
    fn seleccionar_bruta(&self, max_bytes: u64, semilla: u64) -> Vec<(Tx, Vec<Vec<u8>>)> {
        let base_estado = &self.base;
        let q = self.params.q;
        let mut elegidas: Vec<(Tx, Vec<Vec<u8>>)> = Vec::new();
        let mut bytes: u64 = 0;
        // 1) Reserva: depósitos de claves sin garantía activa en el estado base **y** operaciones de
        // sector pendientes (B26-1). Hay a lo sumo una pendiente por clave por la cuota de
        // admisión, así que no pueden inundar la reserva. Se ordenan por `txid` y comparten el tope
        // total `w_reserva`.
        let mut reservados: Vec<&Entrada> = self
            .entradas
            .values()
            .filter(|e| {
                let es_deposito = e.clave.is_some_and(|c| base_estado.activo_de(&c) < q)
                    && matches!(
                        e.tx.extension,
                        ExtensionTx::Garantia {
                            tipo: TipoGarantia::Deposito,
                            ..
                        }
                    );
                let es_sector = matches!(e.tx.extension, ExtensionTx::Sector { .. });
                (es_deposito || es_sector) && e.peso <= self.politica.w_reserva
            })
            .collect();
        reservados.sort_by_key(|e| e.txid);
        for e in reservados {
            let Some(nuevo) = bytes.checked_add(e.peso) else {
                continue;
            };
            if nuevo > max_bytes || nuevo > self.politica.w_reserva {
                continue;
            }
            bytes = nuevo;
            elegidas.push((e.tx.clone(), e.testigos.clone()));
        }
        // 2) Resto: muestreo por peso `feerate^α` sin reemplazo (Efraimidis-Spirakis).
        let mut candidatas: Vec<(&Entrada, f64)> = self
            .entradas
            .values()
            .filter(|e| !elegidas.iter().any(|(t, _)| txid(t, self.cbid) == e.txid))
            .map(|e| {
                let fr = if e.peso == 0 {
                    0.0
                } else {
                    e.fee as f64 / e.peso as f64
                };
                let peso = fr.max(1.0).powi(self.politica.alpha as i32);
                let u = (numero_de_pago(semilla, &e.txid) as f64 + 1.0) / (u64::MAX as f64 + 2.0);
                let clave = u.powf(1.0 / peso.max(1e-9));
                (e, clave)
            })
            .collect();
        candidatas.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        // PT-3bc · como mucho **una** tx v6 de clase `0x01`/`0x02` por bloque
        // (`REVISION-PT3a` decisión 3): la segunda se queda en la mempool para el bloque siguiente.
        let mut pruebas_almacenamiento: usize = 0;
        for (e, _) in candidatas {
            let es_prueba = matches!(
                &e.tx.extension,
                ExtensionTx::PruebaAlmacenamiento { operacion } if operacion.clase().es_prueba()
            );
            if es_prueba && pruebas_almacenamiento >= 1 {
                continue;
            }
            let Some(nuevo) = bytes.checked_add(e.peso) else {
                continue;
            };
            if nuevo > max_bytes {
                continue;
            }
            if es_prueba {
                pruebas_almacenamiento += 1;
            }
            bytes = nuevo;
            elegidas.push((e.tx.clone(), e.testigos.clone()));
        }
        elegidas
    }

    /// MP-2 · Regla S sobre una selección ya hecha: (1) retira iterativamente toda transacción a
    /// la que le falte una madre **en la cola** hasta que no se retire ninguna; (2) reordena
    /// topológicamente de forma **estable** (cada transacción detrás de sus madres y, entre las
    /// que no dependen unas de otras, el orden que tenían). No añade transacciones: solo retira y
    /// reordena.
    ///
    /// Una madre de `T` es una entrada `M` de la cola tal que `T` gasta una salida creada por `M`
    /// (el `prev_txid` de ese `OutPoint` es el `txid` de `M`), o la operación de garantía de la
    /// misma clave con el nonce anterior (F-15: depósito, retiro y liberación). La retirada se
    /// repite porque quitar una transacción puede dejar a otra sin su predecesora seleccionada.
    fn aplicar_regla_s(&self, elegidas: Vec<(Tx, Vec<Vec<u8>>)>) -> Vec<(Tx, Vec<Vec<u8>>)> {
        let ids: Vec<TxId> = elegidas.iter().map(|(t, _)| txid(t, self.cbid)).collect();
        let por_nonce: BTreeMap<(ClavePublica, u64), TxId> = self
            .entradas
            .values()
            .filter_map(|e| match e.tx.extension {
                ExtensionTx::Garantia { clave, nonce, .. } => Some(((clave, nonce), e.txid)),
                _ => None,
            })
            .collect();
        // Se calcula una vez sobre toda la cola, incluso si la predecesora no fue sorteada.
        let madres: BTreeMap<TxId, Vec<TxId>> = self
            .entradas
            .values()
            .map(|e| {
                let mut dependencias: Vec<TxId> =
                    e.tx.inputs
                        .iter()
                        .map(|i| i.outpoint.prev_txid)
                        .filter(|id| self.entradas.contains_key(id))
                        .collect();
                if let ExtensionTx::Garantia { clave, nonce, .. } = e.tx.extension
                    && let Some(previo) = nonce.checked_sub(1)
                    && let Some(id) = por_nonce.get(&(clave, previo))
                {
                    dependencias.push(*id);
                }
                (e.txid, dependencias)
            })
            .collect();
        // 1) Cierre hacia abajo: se retira toda elegida con una madre en la cola que no esté
        // también elegida; repetir hasta el punto fijo.
        let mut conservadas: BTreeSet<TxId> = ids.iter().copied().collect();
        loop {
            let mut retirar: Vec<TxId> = Vec::new();
            for id in &conservadas {
                let Some(dependencias) = madres.get(id) else {
                    continue;
                };
                let falta_madre = dependencias.iter().any(|m| !conservadas.contains(m));
                if falta_madre {
                    retirar.push(*id);
                }
            }
            if retirar.is_empty() {
                break;
            }
            for id in retirar {
                conservadas.remove(&id);
            }
        }
        // 2) Orden topológico estable por pasadas: en cada una se colocan, en el orden que tenían,
        // las transacciones con todas sus madres ya colocadas.
        let mut pendientes: Vec<(TxId, TxConTestigos)> = elegidas
            .into_iter()
            .zip(ids)
            .filter(|(_, id)| conservadas.contains(id))
            .map(|((t, w), id)| (id, (t, w)))
            .collect();
        let mut colocadas: BTreeSet<TxId> = BTreeSet::new();
        let mut salida: Vec<(Tx, Vec<Vec<u8>>)> = Vec::with_capacity(pendientes.len());
        while !pendientes.is_empty() {
            let antes = pendientes.len();
            let mut siguiente: Vec<(TxId, TxConTestigos)> = Vec::with_capacity(antes);
            for (id, par) in pendientes {
                let listo = madres
                    .get(&id)
                    .is_none_or(|dependencias| dependencias.iter().all(|m| colocadas.contains(m)));
                if listo {
                    colocadas.insert(id);
                    salida.push(par);
                } else {
                    siguiente.push((id, par));
                }
            }
            // Si una pasada no coloca nada hay un ciclo, que la cola no admite (cada transacción
            // gasta salidas ya existentes); se conserva el orden restante para no perder nada.
            if siguiente.len() == antes {
                salida.extend(siguiente.into_iter().map(|(_, par)| par));
                break;
            }
            pendientes = siguiente;
        }
        salida
    }

    /// Evidencias elegibles de la mempool (v4), hasta `max`, para incluirlas en un bloque PoST.
    #[must_use]
    pub fn elegir_evidencias(&self, max: usize) -> Vec<(Tx, Vec<Vec<u8>>)> {
        self.entradas
            .values()
            .filter(|e| matches!(e.tx.extension, ExtensionTx::Evidencia { .. }))
            .take(max)
            .map(|e| (e.tx.clone(), e.testigos.clone()))
            .collect()
    }

    /// FV-4b-N3-2 · Saca de la mempool las transacciones v6 de **compromiso** (`0x06`),
    /// **revelación** (`0x07`) y **voto propio** (`0x08`, AUS-2b) para que el hilo de consenso las
    /// gestione como pendientes prioritarias: las conserva hasta verlas aplicadas (sobreviven al
    /// rebase de la mempool) y las incluye en cada bloque propio antes que el resto del cuerpo.
    /// Devuelve `(tx, testigos)`.
    ///
    /// Solo se extraen las de origen ajeno (las propias del productor no pasan por la mempool): si
    /// la operación ya no valida en la vista, [`Self::recomputar_vista`] la habría descartado.
    pub fn tomar_v6(&mut self) -> Vec<(Tx, Vec<Vec<u8>>)> {
        let ids: Vec<TxId> = self
            .entradas
            .values()
            .filter(|e| {
                matches!(
                    &e.tx.extension,
                    ExtensionTx::PruebaAlmacenamiento { operacion }
                        if matches!(
                            operacion.clase(),
                            ClasePruebaAlmacenamiento::VotoPropio
                        )
                )
            })
            .map(|e| e.txid)
            .collect();
        let mut salida = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(e) = self.entradas.get(&id) {
                salida.push((e.tx.clone(), e.testigos.clone()));
            }
            self.eliminar(&id, Rechazo::VistaLocal("voto_extraido"));
        }
        salida
    }
}

/// PD-1c · ventana de una tx v6 de voto propio (`0x08`).
///
/// `(clase, clave, n, desde, hasta)`: la clave Ed25519 dueña y la ventana `n` identifican la
/// pendiente; `[desde, hasta]` es el rango de slots en el que la operación es admisible respecto al
/// slot actual (`[apertura(n), cierre(n)+W]`, la misma regla que `aplicar_voto_propio`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct VentanaVoto {
    clase: ClasePruebaAlmacenamiento,
    clave: ClavePublica,
    n: u64,
    desde: u64,
    hasta: u64,
}

/// PD-1c · metadatos de ventana de una tx v6 de voto propio; `None` para las demás.
fn ventana_de(tx: &Tx) -> Option<VentanaVoto> {
    let ExtensionTx::PruebaAlmacenamiento { operacion } = &tx.extension else {
        return None;
    };
    match operacion {
        // AUS-2b · N6 · el voto propio ajeno se admite desde la apertura de la ventana hasta
        // `cierre + W_reveal` (la misma ventana de consenso de `aplicar_voto_propio`).
        OperacionAlmacenamiento::VotoPropio { clave, n, .. } => Some(VentanaVoto {
            clase: ClasePruebaAlmacenamiento::VotoPropio,
            clave: *clave,
            n: *n,
            desde: apertura_ventana(*n),
            hasta: cierre_ventana(*n).saturating_add(W_REVEAL_SLOTS_VOTOS),
        }),
        _ => None,
    }
}

/// COLA-1 · clave que no decodifica a un punto Ed25519 bajo ZIP-215 (probado con el verificador).
/// No puede ser dueña de una operación firmada. RD-10 permite usarla en el vehículo de fusión;
/// sus apuntes temporales se retiran antes de devolver la vista.
fn productor_sintetico(_vista: &Estado) -> ClavePublica {
    ClavePublica::desde_bytes([2; 32])
}

/// P1 · El punto en el que la cola valida **todas** sus transacciones: el siguiente del estado base
/// (el que hoy recibe la primera), sin deriva por el número de entradas ya admitidas.
///
/// `Punto::Altura(base.altura + 1)` en `Fase::PoW` sin terminal; `Punto::Slot(base.slot + 1)` en
/// cualquier otro caso (fusión o tras el corte).
fn punto_siguiente(base: &Estado) -> Punto {
    if base.fase == Fase::PoW && base.terminal.is_none() {
        Punto::Altura(base.altura.saturating_add(1))
    } else {
        Punto::Slot(base.slot.saturating_add(1))
    }
}

/// P1 · Repone en `nuevo` los escalares que el bloque sintético movió **al margen de las
/// transacciones** (punto, trabajo, subsidio acumulado y decisión de corte), para que la vista no
/// avance y la siguiente transacción se valide en el mismo punto siguiente de `base`.
///
/// No se reponen los mapas (UTXO, garantías, sectores, votos…): contienen los efectos de las
/// transacciones y los efectos de punto idempotentes, que sí deben acumularse. `emitido` tampoco se
/// repone: en el bloque sintético (sin coinbase) solo cambia por `−Σtarifas`, que es efecto de las
/// transacciones.
fn restaurar_punto(nuevo: &mut Estado, base: &Estado) {
    nuevo.fase = base.fase;
    nuevo.terminal = base.terminal;
    nuevo.altura = base.altura;
    nuevo.trabajo = base.trabajo;
    nuevo.slot = base.slot;
    nuevo.s0 = base.s0;
    nuevo.altura_terminal = base.altura_terminal;
    nuevo.subsidio_acum = base.subsidio_acum;
}

/// EV-1 · conserva el nombre canónico del error completo que recibió la cola.
/// La clasificación de transacciones ordinarias mantiene su contrato anterior.
fn clasificar_motivo_tx(e: &ErrorTransicion, tx: &Tx) -> Rechazo {
    let es_evidencia = matches!(
        &tx.extension,
        ExtensionTx::PruebaAlmacenamiento {
            operacion: OperacionAlmacenamiento::EvidenciaVotosPeso { .. }
        }
    );
    if !es_evidencia {
        return clasificar_motivo(e);
    }
    let nombre = match e {
        ErrorTransicion::ErrGenesis => "ErrGenesis",
        ErrorTransicion::ErrPow => "ErrPow",
        ErrorTransicion::ErrEmision => "ErrEmision",
        ErrorTransicion::ErrInmaduro => "ErrInmaduro",
        ErrorTransicion::ErrDepositoTemprano => "ErrDepositoTemprano",
        ErrorTransicion::ErrAutorizacion => "ErrAutorizacion",
        ErrorTransicion::ErrSaldo => "ErrSaldo",
        ErrorTransicion::ErrDobleGasto => "ErrDobleGasto",
        ErrorTransicion::ErrPowTrasCorte => "ErrPowTrasCorte",
        ErrorTransicion::ErrSinTerminal => "ErrSinTerminal",
        ErrorTransicion::ErrTerminalAmbiguo => "ErrTerminalAmbiguo",
        ErrorTransicion::ErrGarantia => "ErrGarantia",
        ErrorTransicion::ErrOperacionFase => "ErrOperacionFase",
        ErrorTransicion::ErrPruebaTardia => "ErrPruebaTardia",
        ErrorTransicion::ErrSectorInactivo => "ErrSectorInactivo",
        ErrorTransicion::ErrSlot => "ErrSlot",
        ErrorTransicion::ErrDesbordamiento => "ErrDesbordamiento",
        ErrorTransicion::ErrFueraDeAlcanceV0 => "ErrFueraDeAlcanceV0",
        ErrorTransicion::ErrRetiroPendiente => "ErrRetiroPendiente",
        ErrorTransicion::ErrNonce => "ErrNonce",
        ErrorTransicion::ErrFirma => "ErrFirma",
        ErrorTransicion::ErrForma(_) => "ErrForma",
        ErrorTransicion::ErrSinPadre => "ErrSinPadre",
        ErrorTransicion::ErrSinEvidencia => "ErrSinEvidencia",
        ErrorTransicion::ErrEvidenciaTardia => "ErrEvidenciaTardia",
        ErrorTransicion::ErrEvidenciaDuplicada => "ErrEvidenciaDuplicada",
        ErrorTransicion::ErrCasoAbierto => "ErrCasoAbierto",
        ErrorTransicion::ErrVentanaAbierta => "ErrVentanaAbierta",
        ErrorTransicion::ErrPuertaRAT3 => "ErrPuertaRAT3",
        ErrorTransicion::ErrSector(m) => m.nombre(),
        ErrorTransicion::ErrDosPruebasAlmacenamiento => "ErrDosPruebasAlmacenamiento",
        ErrorTransicion::ErrCertificadoInstancia => "ErrCertificadoInstancia",
        ErrorTransicion::ErrCertificadoPeso => "ErrCertificadoPeso",
        ErrorTransicion::ErrCertificadoVrf => "ErrCertificadoVrf",
        ErrorTransicion::ErrCertificadoPlazas => "ErrCertificadoPlazas",
        ErrorTransicion::ErrCertificadoFirma => "ErrCertificadoFirma",
        ErrorTransicion::ErrCertificadoConflictivo => "ErrCertificadoConflictivo",
        ErrorTransicion::ErrFinalidadRetrocede => "ErrFinalidadRetrocede",
        ErrorTransicion::ErrEvidenciaVoto => "ErrEvidenciaVoto",
        ErrorTransicion::ErrEvidenciaInadmisible => "ErrEvidenciaInadmisible",
        ErrorTransicion::ErrEvidenciaSinFalta => "ErrEvidenciaSinFalta",
        ErrorTransicion::ErrCompromisoInstancia => "ErrCompromisoInstancia",
        ErrorTransicion::ErrCompromisoPeso => "ErrCompromisoPeso",
        ErrorTransicion::ErrCompromisoDuplicado => "ErrCompromisoDuplicado",
        ErrorTransicion::ErrRevelacionSinCompromiso => "ErrRevelacionSinCompromiso",
        ErrorTransicion::ErrRevelacionPrematura => "ErrRevelacionPrematura",
        ErrorTransicion::ErrRevelacionTardia => "ErrRevelacionTardia",
        ErrorTransicion::ErrRevelacionDuplicada => "ErrRevelacionDuplicada",
        ErrorTransicion::ErrRevelacionNoCoincide => "ErrRevelacionNoCoincide",
        ErrorTransicion::ErrVotoPropioPlazo => "ErrVotoPropioPlazo",
        ErrorTransicion::ErrVotoPropioClave => "ErrVotoPropioClave",
        ErrorTransicion::ErrVotoPropioFirma => "ErrVotoPropioFirma",
        ErrorTransicion::ErrVotoPropioDuplicado => "ErrVotoPropioDuplicado",
        ErrorTransicion::ErrCertificadoPesoMotivo(_) => "ErrCertificadoPesoMotivo",
        ErrorTransicion::ErrCertificadoPesoBytes => "ErrCertificadoPesoBytes",
        ErrorTransicion::ErrCertificadoPesoTabla => "ErrCertificadoPesoTabla",
        ErrorTransicion::ErrCertificadoPesoTablaDesconocida => "ErrCertificadoPesoTablaDesconocida",
        ErrorTransicion::ErrCertificadoVentanaFutura => "ErrCertificadoVentanaFutura",
        ErrorTransicion::ErrCertificadoPlazo => "ErrCertificadoPlazo",
        ErrorTransicion::ErrTablaDerivadaSinContenido => "ErrTablaDerivadaSinContenido",
        ErrorTransicion::ErrActaPlazo => "ErrActaPlazo",
        ErrorTransicion::ErrActaTablaDesconocida => "ErrActaTablaDesconocida",
        ErrorTransicion::ErrActaLiquidada => "ErrActaLiquidada",
        ErrorTransicion::ErrActaRepetida => "ErrActaRepetida",
        ErrorTransicion::ErrRearranqueFueraDeFase => "ErrRearranqueFueraDeFase",
        ErrorTransicion::ErrRearranqueSinTabla => "ErrRearranqueSinTabla",
    };
    match clasificar_motivo(e) {
        Rechazo::Demostrable(_) => Rechazo::Demostrable(nombre),
        Rechazo::VistaLocal(_) | Rechazo::Limite(_) => Rechazo::VistaLocal(nombre),
    }
}

/// Clasifica el error del motor para una transacción de mempool (TX-R-09/10, DR-06).
fn clasificar_motivo(e: &ErrorTransicion) -> Rechazo {
    match e {
        ErrorTransicion::ErrEvidenciaInadmisible => Rechazo::VistaLocal("ErrEvidenciaInadmisible"),
        ErrorTransicion::ErrEvidenciaSinFalta => Rechazo::VistaLocal("ErrEvidenciaSinFalta"),
        ErrorTransicion::ErrEvidenciaVoto => Rechazo::VistaLocal("ErrEvidenciaVoto"),
        ErrorTransicion::ErrForma(_)
        | ErrorTransicion::ErrFirma
        | ErrorTransicion::ErrAutorizacion => Rechazo::Demostrable("invalida"),
        ErrorTransicion::ErrSaldo | ErrorTransicion::ErrDobleGasto => {
            Rechazo::VistaLocal("conflicto")
        }
        ErrorTransicion::ErrInmaduro
        | ErrorTransicion::ErrNonce
        | ErrorTransicion::ErrDepositoTemprano
        | ErrorTransicion::ErrOperacionFase
        | ErrorTransicion::ErrRetiroPendiente
        | ErrorTransicion::ErrVentanaAbierta
        | ErrorTransicion::ErrCasoAbierto
        | ErrorTransicion::ErrEvidenciaTardia
        | ErrorTransicion::ErrEvidenciaDuplicada
        | ErrorTransicion::ErrSinEvidencia
        | ErrorTransicion::ErrSlot => Rechazo::VistaLocal("vista"),
        // MRS-1 · IPA B-72: un rechazo del autómata de sectores lleva el nombre canónico del
        // motivo (`MotivoSector::nombre`) para que el registro diga la causa. La clase no cambia
        // (sigue siendo de vista local: en difusión se ignora y no se penaliza).
        ErrorTransicion::ErrSector(m) => Rechazo::VistaLocal(m.nombre()),
        _ => Rechazo::VistaLocal("vista"),
    }
}

/// Compara dos feerates `(fee, peso)` por producto cruzado (sin floats).
fn comparar_feerate(a: (u128, u128), b: (u128, u128)) -> std::cmp::Ordering {
    let ia = a.0 * b.1.max(1);
    let ib = b.0 * a.1.max(1);
    ia.cmp(&ib)
}

/// Puntos transcurridos entre dos puntos del mismo tipo; `0` si cambian de tipo (no caduca).
fn puntos_transcurridos(desde: Punto, hasta: Punto) -> u64 {
    match (desde, hasta) {
        (Punto::Altura(a), Punto::Altura(b)) => u64::from(b).saturating_sub(u64::from(a)),
        (Punto::Slot(a), Punto::Slot(b)) => b.saturating_sub(a),
        _ => 0,
    }
}

/// Número pseudoaleatorio determinista de un pago: encadena `splitmix64` sobre las cuatro palabras
/// de 8 bytes (big-endian) del identificador, partiendo de la semilla. Mezclar el identificador
/// **entero** evita que dos pagos que comparten el primer byte reciban el mismo número y se elijan
/// juntos (IPA B-85); antes solo entraba `txid.as_bytes()[0]`.
fn numero_de_pago(semilla: u64, txid: &TxId) -> u64 {
    let mut s = semilla;
    for trozo in txid.as_bytes().chunks_exact(8) {
        let palabra: [u8; 8] = trozo.try_into().unwrap_or_default();
        s = splitmix64(s ^ u64::from_be_bytes(palabra));
    }
    s
}

/// PRNG determinista (splitmix64), solo para el muestreo local del productor.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño"
)]
pub(crate) mod tests {
    use super::*;
    use crate::claves::ClaveDev;
    use std::collections::BTreeSet;

    use zx_consensus::transicion::{EntradaUtxo, Origen};
    use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};

    const CBID: u32 = zx_core::CBID_RED_DEV;

    fn params() -> ParametrosTransicion {
        crate::perfil::parametros_transicion_dev().expect("perfil dev")
    }

    fn evp() -> ParametrosEvidencia {
        crate::perfil::parametros_evidencia_dev()
    }

    fn op_id(n: u8) -> OutPoint {
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: 0,
        }
    }

    /// Estado base en fase PoW con los UTXO indicados (origen `Tx`, sin inmadurez).
    fn base_pow(utxos: &[(OutPoint, i64, ClavePublica)]) -> Estado {
        let mut e = Estado::inicial();
        e.fase = Fase::PoW;
        e.altura = 1;
        for (op, v, pk) in utxos {
            e.utxo.insert(
                *op,
                EntradaUtxo {
                    valor: Amount::nuevo(*v).unwrap(),
                    lock: Lock::PubKey { pubkey: *pk },
                    origen: Origen::Tx,
                    creada: Punto::Altura(0),
                },
            );
        }
        e
    }

    /// FV-4b-N4 · estado base en fase PoST (la única con ventanas de voto) con la clave BLS de voto
    fn mempool(base: Estado) -> Mempool {
        Mempool::nueva(params(), evp(), CBID, base, Politica::dev())
    }

    fn peso_de(tx: &Tx, testigos: &[Vec<u8>]) -> u64 {
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
        buf.len() as u64
    }

    /// Transferencia v1 firmada que gasta `op` (con `valor_in`) y paga `valor_out` a `destino`.
    fn transferencia(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        valor_out: i64,
        destino: ClavePublica,
    ) -> (Tx, Vec<Vec<u8>>) {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(valor_out).unwrap(),
                lock: Lock::PubKey { pubkey: destino },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = [SpentOutput {
            value: Amount::nuevo(valor_in).unwrap(),
            lock: Lock::PubKey { pubkey: clave.pk },
        }];
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).unwrap();
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    /// Depósito v2 firmado que gasta por completo la coinbase `op` (importe = valor, tarifa 0).
    fn deposito(clave: &ClaveDev, op: OutPoint, valor: i64, nonce: u64) -> (Tx, Vec<Vec<u8>>) {
        crate::pow::construir_deposito(
            op.prev_txid,
            Amount::nuevo(valor).unwrap(),
            clave,
            nonce,
            CBID,
        )
        .expect("depósito")
    }

    /// Alta de sector v5 firmada por `clave` (SR-G2b: para la cuota de sector).
    fn alta_sector(clave: &ClaveDev, si: u16) -> (Tx, Vec<Vec<u8>>) {
        let op = zx_core::OperacionSector::Alta {
            clave: clave.pk,
            sector_index: si,
            version: 0,
            r2: [7u8; 32],
            history_size: 1 << 20,
        };
        let tx = Tx {
            version: 5,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Sector { operacion: op },
        };
        let firma: [u8; 64] = clave.sk.sign(&zx_core::mensaje_sector(&tx, CBID)).into();
        (tx, vec![firma.to_vec()])
    }

    /// Un `PeerId` cualquiera para los topes por par.
    fn peer() -> PeerId {
        PeerId::random()
    }

    fn ahora() -> Instant {
        Instant::now()
    }

    // ── V2 · una prueba por regla de la orden ────────────────────────────────────────────────

    /// **TX-R-06/07/14 · admisión válida.** Una transferencia que paga φ_min entra.
    #[test]
    fn admision_valida() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        assert_eq!(m.estadisticas().n, 1);
    }

    /// **TX-6 · los rechazos por tope se cuentan por motivo.** Instrumentación del evento
    /// `mempool`: no cambia la decisión, solo la contabiliza.
    #[test]
    fn rechazos_limite_se_cuentan_por_motivo() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        // Tope global: con `s` menor que la transacción, no cabe y no hay a quién desalojar.
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        m.politica.s = 1;
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("global"))
        );
        let r = m.rechazos_limite();
        assert_eq!(r.total, 1);
        assert_eq!(r.global, 1);
        // Tope de tasa por par: `R_par = 0` rechaza cualquier peso con origen de red.
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        m.politica.r_par = 0;
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        assert_eq!(
            m.admitir(Some(peer()), tx, tst, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("par_tasa"))
        );
        let r = m.rechazos_limite();
        assert_eq!(r.total, 1);
        assert_eq!(r.par_tasa, 1);
    }

    /// **TX-R-07/08 · forma y tamaño demostrables.**
    #[test]
    fn forma_y_tamano_son_demostrables() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        // Forma: transferencia sin salidas.
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op_id(1),
                sequence: 0,
            }],
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        assert!(matches!(
            m.admitir(None, tx, Vec::new(), ahora(), Punto::Altura(1)),
            Err(Rechazo::Demostrable(_))
        ));
        // Tamaño: se baja el tope por debajo del tamaño real.
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        let peso = peso_de(&tx, &tst);
        m.params.max_tx_bytes = peso - 1;
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Err(Rechazo::Demostrable("tamano"))
        );
    }

    /// **TX-R-11 · tarifa mínima para v1.**
    #[test]
    fn tarifa_minima_rechaza_v1_sin_tarifa() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        m.politica.phi_min = 1; // perfil con tarifa positiva: mantiene el sentido del test
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 1_000, b.pk);
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("tarifa_minima"))
        );
    }

    /// **E-08 · la escala dev admite una v1 con la tarifa del perfil.** La coinbase PoW dev vale
    /// 50 brek y la v1 mínima pesa 161 B: con `phi_min = 0` (perfil dev) una v1 con tarifa 0 entra.
    #[test]
    fn la_escala_dev_admite_v1_sin_tarifa() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 50, a.pk)]));
        assert_eq!(m.politica().phi_min, 0);
        let (tx, tst) = transferencia(&a, op_id(1), 50, 40, b.pk); // tarifa 10
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }

    /// **TX-R-14 · conflicto: el primero que llega gana, el segundo no entra.**
    #[test]
    fn conflicto_gana_el_primero() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        let (t1, w1) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        let (t2, w2) = transferencia(&a, op_id(1), 1_000, 700, b.pk);
        assert_eq!(
            m.admitir(None, t1.clone(), w1, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(None, t2, w2, ahora(), Punto::Altura(1)),
            Err(Rechazo::VistaLocal("conflicto"))
        );
        assert_eq!(m.estadisticas().n, 1);
    }

    /// **TX-R-15 · mínimo rodante y desalojo por tarifa.** Con sitio para una, la de mayor feerate
    /// desaloja a la de menor.
    #[test]
    fn desalojo_por_tarifa() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[
            (op_id(1), 1_000, a.pk),
            (op_id(2), 1_000, a.pk),
            (op_id(3), 1_000, a.pk),
        ]));
        let (baja, wb) = transferencia(&a, op_id(1), 1_000, 800, b.pk); // fee 200
        let (alta, wa) = transferencia(&a, op_id(2), 1_000, 600, b.pk); // fee 400
        let pb = peso_de(&baja, &wb);
        let pa = peso_de(&alta, &wa);
        m.politica.s = pb.max(pa) as usize; // solo cabe una
        assert_eq!(
            m.admitir(None, baja.clone(), wb, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(None, alta.clone(), wa, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        let est = m.estadisticas();
        assert_eq!(est.n, 1, "la de menor tarifa se desaloja");
        assert!(m.contiene(&txid(&alta, CBID)));
        assert!(!m.contiene(&txid(&baja, CBID)));
        assert!(est.minimo_rodante.0 > 0, "el mínimo rodante sube");
        // TX-R-15 · con sitio libre, una v1 por debajo del mínimo rodante se rechaza sin entrar.
        let (tercera, w3) = transferencia(&a, op_id(3), 1_000, 830, b.pk); // fee 170, > φ_min
        m.politica.s = 1 << 20;
        assert_eq!(
            m.admitir(None, tercera, w3, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("tarifa_rodante"))
        );
    }

    /// **† B26-3 · regresión 2 (mínimo rodante).** En mempool llena, una candidata v1 firmada con
    /// feerate por debajo del mínimo rodante confiable (y por encima de las normales elegibles) se
    /// rechaza **sin** desalojar, sin subir el mínimo y sin tocar la vista virtual.
    #[test]
    fn b26_3_tarifa_rodante_no_desaloja() {
        let a = ClaveDev::derivar(3, 0);
        let b = ClaveDev::derivar(3, 1);
        let mut m = mempool(base_pow(&[
            (op_id(1), 1_000, a.pk),
            (op_id(2), 1_000, a.pk),
            (op_id(3), 1_000, a.pk),
            (op_id(4), 1_000, a.pk),
        ]));
        let (n1, w1) = transferencia(&a, op_id(1), 1_000, 900, b.pk); // fee 100
        let (n2, w2) = transferencia(&a, op_id(2), 1_000, 900, b.pk); // fee 100
        let (n3, w3) = transferencia(&a, op_id(3), 1_000, 900, b.pk); // fee 100
        let (cand, wc) = transferencia(&a, op_id(4), 1_000, 750, b.pk); // fee 250
        let p = peso_de(&n1, &w1);
        assert_eq!(p, peso_de(&cand, &wc), "misma forma: mismo peso");
        m.politica.s = (3 * p) as usize; // las tres normales llenan S exactamente
        let ids = [txid(&n1, CBID), txid(&n2, CBID), txid(&n3, CBID)];
        for (tx, w) in [(n1, w1), (n2, w2), (n3, w3)] {
            assert_eq!(
                m.admitir(None, tx, w, ahora(), Punto::Altura(1)),
                Ok(Admision::Admitida)
            );
        }
        // Mínimo rodante confiable por encima del feerate de la candidata (250/p < 300/p).
        m.minimo_rodante = (300, u128::from(p));
        let vista_antes = m.vista.clone();
        let antes = (
            m.estadisticas().n,
            m.estadisticas().bytes,
            m.estadisticas().minimo_rodante,
        );
        assert_eq!(
            m.admitir(None, cand, wc, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("tarifa_rodante"))
        );
        assert_eq!(
            (
                m.estadisticas().n,
                m.estadisticas().bytes,
                m.estadisticas().minimo_rodante,
            ),
            antes,
            "el rechazo por mínimo rodante no toca la mempool"
        );
        assert_eq!(m.vista, vista_antes, "la vista virtual no cambia");
        for id in &ids {
            assert!(m.contiene(id), "la normal {id:?} sigue en la mempool");
        }
        assert_eq!(m.rechazos_limite().tarifa_rodante, 1);
    }

    /// **TX-R-18/19 · huérfanas.** El hijo que llega antes que el padre espera y se resuelve cuando
    /// el padre entra.
    #[test]
    fn huerfanas_se_resuelven_al_llegar_el_padre() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let c = ClaveDev::derivar(1, 2);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        let (padre, wp) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        let padre_id = txid(&padre, CBID);
        let op_hijo = OutPoint {
            prev_txid: padre_id,
            prev_index: 0,
        };
        let (hijo, wh) = transferencia(&b, op_hijo, 800, 600, c.pk);
        assert_eq!(
            m.admitir(None, hijo, wh, ahora(), Punto::Altura(1)),
            Ok(Admision::Huerfana)
        );
        assert_eq!(m.estadisticas().huerfanas, 1);
        assert_eq!(
            m.admitir(None, padre, wp, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        let est = m.estadisticas();
        assert_eq!(est.n, 2, "el hijo se resuelve al entrar el padre");
        assert_eq!(est.huerfanas, 0);
    }

    /// **TX-R-36 · caducidad por TTL.** A los `ttl_puntos` + 1, la entrada se va.
    #[test]
    fn caducidad_por_ttl() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        let ttl = m.politica.ttl_puntos;
        m.expirar(Punto::Altura(u32::try_from(1 + ttl).unwrap()));
        assert_eq!(m.estadisticas().n, 1, "justo en el TTL todavía vive");
        m.expirar(Punto::Altura(u32::try_from(2 + ttl).unwrap()));
        assert_eq!(m.estadisticas().n, 0, "un punto más tarde caduca");
    }

    /// **TX-R-20 · cuota por clave.** Dos operaciones de garantía sin tarifa de la misma clave: la
    /// segunda no entra.
    #[test]
    fn cuota_por_clave() {
        let a = ClaveDev::derivar(1, 0);
        let mut m = mempool(base_pow(&[
            (op_id(1), 1_000, a.pk),
            (op_id(2), 1_000, a.pk),
        ]));
        let (d1, w1) = deposito(&a, op_id(1), 1_000, 0);
        let (d2, w2) = deposito(&a, op_id(2), 1_000, 0);
        assert_eq!(
            m.admitir(None, d1, w1, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(None, d2, w2, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("cuota_por_clave"))
        );
    }

    /// **SR-G2b · cuota de sector.** A lo sumo **una** operación de sector v5 pendiente por clave:
    /// la segunda alta de la misma clave no entra en la mempool.
    #[test]
    fn cuota_sector_por_clave() {
        let a = ClaveDev::derivar(1, 0);
        let mut base = base_pow(&[]);
        base.garantias.insert(
            a.pk,
            zx_consensus::transicion::Garantia {
                activo: Amount::nuevo(500).unwrap(),
                ..zx_consensus::transicion::Garantia::nueva()
            },
        );
        let mut m = mempool(base);
        let (s1, w1) = alta_sector(&a, 0);
        let (s2, w2) = alta_sector(&a, 1);
        assert_eq!(
            m.admitir(None, s1, w1, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(None, s2, w2, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("cuota_por_clave"))
        );
    }

    /// **MRS-1 · IPA B-72 · el registro ya puede decir por qué se rechaza un sector.**
    ///
    /// Un alta de sector v5 rechazada por el motor (`ErrorTransicion::ErrSector`) sale de la
    /// mempool con el **nombre canónico** del motivo (`MotivoSector::nombre`) y sigue siendo de
    /// **vista local** (en gossip: `Ignorar`, sin penalizar). Un rechazo de otra causa que hoy da
    /// `VistaLocal("vista")` (aquí un gasto inmaduro, `ErrInmaduro`) conserva su texto.
    #[test]
    fn rechazo_de_sector_lleva_el_motivo_canonico() {
        use zx_consensus::sectores::MotivoSector;

        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);

        // (1) Alta de sector sin fianza: la clave no tiene garantía (0 < q_sec) ⇒ `ErrFianza`.
        let mut m = mempool(base_pow(&[]));
        let (s, ws) = alta_sector(&a, 0);
        assert_eq!(
            m.admitir(None, s, ws, ahora(), Punto::Altura(1)),
            Err(Rechazo::VistaLocal(MotivoSector::ErrFianza.nombre())),
            "el rechazo de sector debe llevar el motivo canónico, no \"vista\""
        );
        assert_eq!(
            MotivoSector::ErrFianza.nombre(),
            "ERR_FIANZA",
            "nombre canónico del motivo (la orden §3 lo escribe como `ErrFianza`)"
        );

        // (2) Otra causa que hoy da `VistaLocal("vista")` no cambia: gasto de una coinbase
        //     inmadura (`ErrInmaduro`), con `creada + M_cb > punto`.
        let mut base = base_pow(&[(op_id(1), 1_000, a.pk)]);
        let entrada = base.utxo.get_mut(&op_id(1)).expect("utxo de la base");
        entrada.origen = Origen::CoinbasePow;
        entrada.creada = Punto::Altura(0);
        let mut m2 = mempool(base);
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        assert_eq!(
            m2.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Err(Rechazo::VistaLocal("vista")),
            "un rechazo no sectorial conserva el texto \"vista\""
        );
    }

    /// **TX-R-21/22 · topes por par.** Memoria y tasa se aplican por propagador.
    #[test]
    fn topes_por_par() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let p = peer();
        // Memoria por par.
        let mut m = mempool(base_pow(&[
            (op_id(1), 1_000, a.pk),
            (op_id(2), 1_000, a.pk),
        ]));
        let (t1, w1) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        let (t2, w2) = transferencia(&a, op_id(2), 1_000, 800, b.pk);
        m.politica.s_par = peso_de(&t1, &w1) as usize;
        assert_eq!(
            m.admitir(Some(p), t1.clone(), w1.clone(), ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(Some(p), t2.clone(), w2.clone(), ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("par_memoria"))
        );
        // Tasa por par (ventana larga, cuota de un solo tx).
        let mut m2 = mempool(base_pow(&[
            (op_id(1), 1_000, a.pk),
            (op_id(2), 1_000, a.pk),
        ]));
        m2.politica.r_par = peso_de(&t1, &w1) as usize;
        m2.politica.ventana_tasa_ms = 60_000;
        assert_eq!(
            m2.admitir(Some(p), t1, w1, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m2.admitir(Some(p), t2, w2, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("par_tasa"))
        );
    }

    /// **TX-R-15/16 · tope global.** Si la candidata sola no cabe, se rechaza sin desalojar.
    #[test]
    fn tope_global_sin_espacio() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        m.politica.s = 1; // ni una transacción cabe
        assert_eq!(
            m.admitir(None, tx, tst, ahora(), Punto::Altura(1)),
            Err(Rechazo::Limite("global"))
        );
        assert_eq!(m.estadisticas().n, 0);
    }

    #[test]
    fn b66_01_la_descartada_en_fusion_sale_de_la_cola() {
        let a = ClaveDev::derivar(66, 0);
        let b = ClaveDev::derivar(66, 1);
        let mut base = base_pow(&[(op_id(66), 1_000, a.pk)]);
        base.fase = Fase::PoST;
        base.slot = 1;
        let perdedora = transferencia(&a, op_id(66), 1_000, 800, b.pk);
        let id = txid(&perdedora.0, CBID);
        let mut m = mempool(base.clone());
        assert_eq!(
            m.admitir(
                None,
                perdedora.0.clone(),
                perdedora.1.clone(),
                ahora(),
                Punto::Slot(1)
            ),
            Ok(Admision::Admitida)
        );
        let bloque = b66_post(
            vec![transferencia(&a, op_id(66), 1_000, 700, b.pk), perdedora],
            2,
        );
        let (nuevo, _, descartes) =
            aplicar_fusion(&base, &bloque, Punto::Slot(2), &params(), CBID, &evp()).unwrap();
        assert_eq!(descartes.len(), 1);
        let recibo = ReciboBloque {
            peer: None,
            hash: b66_hash(200),
            txs: bloque.txs,
            descartes,
        };
        let (r, _) =
            m.actualizar_tras_bloque(nuevo, BTreeMap::new(), &recibo, ahora(), Punto::Slot(2));
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.first().expect("un resultado").motivo,
            ErrorTransicion::ErrDobleGasto
        );
        assert_eq!(
            r.first().expect("un resultado").resultado,
            Ok(Admision::Huerfana)
        );
        assert!(!m.aplicadas.contains_key(&id));
        assert!(!m.entradas.contains_key(&id));
        assert_eq!(m.huerfanas.len(), 1);
        println!("B66-01 corregida: descartes=1; falsa_aplicacion=0; tentativa=1; causa=huerfana");
    }

    #[test]
    fn b66_02_no_se_readmite_mientras_dura_el_registro_de_aplicadas() {
        let (base, madre, hija) = b66_madre_hija();
        let id = txid(&hija.0, CBID);
        let mut m = mempool(base.clone());
        for (tx, w) in [&madre, &hija] {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Slot(1)),
                Ok(Admision::Admitida)
            );
        }
        let bloque = b66_post(vec![hija.clone(), madre], 2);
        let (nuevo, _, descartes) =
            aplicar_fusion(&base, &bloque, Punto::Slot(2), &params(), CBID, &evp()).unwrap();
        let recibo = ReciboBloque {
            peer: None,
            hash: b66_hash(200),
            txs: bloque.txs,
            descartes,
        };
        let (r, _) = m.actualizar_tras_bloque(
            nuevo.clone(),
            BTreeMap::new(),
            &recibo,
            ahora(),
            Punto::Slot(2),
        );
        assert_eq!(r.len(), 1);
        assert!(matches!(
            r.first().expect("un resultado").resultado,
            Ok(Admision::Admitida | Admision::Duplicada)
        ));
        assert_eq!(
            m.entradas.get(&id).expect("entrada recuperada").testigos,
            hija.1
        );
        assert!(!m.aplicadas.contains_key(&id));
        assert_eq!(m.estadisticas().n, 1);
        let (r, _) =
            m.actualizar_tras_bloque(nuevo, BTreeMap::new(), &recibo, ahora(), Punto::Slot(2));
        assert!(r.is_empty(), "el mismo recibo no repite la tentativa");
        println!(
            "B66-02 corregida: recuperada=1; testigos_intactos=1; falsa_aplicacion=0; repeticion=0"
        );
    }

    #[test]
    fn ev2_readmision_conserva_el_presupuesto_del_par_conocido() {
        let (base, madre, hija) = b66_madre_hija();
        let mut m = mempool(base.clone());
        m.politica.s_par = 0;
        let bloque = b66_post(vec![hija, madre], 2);
        let (nuevo, _, descartes) =
            aplicar_fusion(&base, &bloque, Punto::Slot(2), &params(), CBID, &evp()).unwrap();
        let recibo = ReciboBloque {
            peer: Some(PeerId::random()),
            hash: b66_hash(200),
            txs: bloque.txs,
            descartes,
        };
        let (r, _) =
            m.actualizar_tras_bloque(nuevo, BTreeMap::new(), &recibo, ahora(), Punto::Slot(2));
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.first().expect("un resultado").resultado,
            Err(Rechazo::Limite("par_memoria"))
        );
        assert_eq!(m.estadisticas().n, 0);
    }

    #[test]
    fn ev2_dos_descartes_distintos_dan_dos_tentativas() {
        let (base, _, hija) = b66_madre_hija();
        let mut m = mempool(base.clone());
        let mut actual = base;
        for slot in [2, 3] {
            let bloque = b66_post(vec![hija.clone()], slot);
            let (nuevo, _, descartes) =
                aplicar_fusion(&actual, &bloque, Punto::Slot(slot), &params(), CBID, &evp())
                    .unwrap();
            let recibo = ReciboBloque {
                peer: None,
                hash: b66_hash(u8::try_from(slot).unwrap()),
                txs: bloque.txs,
                descartes,
            };
            let (r, _) = m.actualizar_tras_bloque(
                nuevo.clone(),
                BTreeMap::new(),
                &recibo,
                ahora(),
                Punto::Slot(slot),
            );
            assert_eq!(r.len(), 1);
            let (r, _) = m.actualizar_tras_bloque(
                nuevo.clone(),
                BTreeMap::new(),
                &recibo,
                ahora(),
                Punto::Slot(slot),
            );
            assert!(r.is_empty());
            actual = nuevo;
        }
        assert_eq!(m.descartes_tratados.len(), 2);
        assert!(!m.aplicadas.contains_key(&txid(&hija.0, CBID)));
    }

    #[test]
    fn ev2_txid_aplicado_en_un_bloque_y_descartado_en_otro_sigue_aplicado() {
        let (base, madre, _) = b66_madre_hija();
        let id = txid(&madre.0, CBID);
        let mut m = mempool(base.clone());
        let primero = b66_post(vec![madre.clone()], 2);
        let (nuevo, _, descartes) =
            aplicar_fusion(&base, &primero, Punto::Slot(2), &params(), CBID, &evp()).unwrap();
        let recibo = ReciboBloque {
            peer: None,
            hash: b66_hash(2),
            txs: primero.txs,
            descartes,
        };
        m.actualizar_tras_bloque(
            nuevo.clone(),
            BTreeMap::new(),
            &recibo,
            ahora(),
            Punto::Slot(2),
        );
        let segundo = b66_post(vec![madre], 3);
        let (nuevo, _, descartes) =
            aplicar_fusion(&nuevo, &segundo, Punto::Slot(3), &params(), CBID, &evp()).unwrap();
        assert_eq!(descartes.len(), 1);
        let recibo = ReciboBloque {
            peer: None,
            hash: b66_hash(3),
            txs: segundo.txs,
            descartes,
        };
        let (r, _) =
            m.actualizar_tras_bloque(nuevo, BTreeMap::new(), &recibo, ahora(), Punto::Slot(3));
        assert!(r.is_empty());
        assert!(m.aplicadas.contains_key(&id));
        assert_eq!(m.estadisticas().n, 0);
    }

    #[test]
    fn ev2_mismo_txid_descartado_y_aplicado_en_el_mismo_cuerpo() {
        let (base, madre, hija) = b66_madre_hija();
        let id = txid(&hija.0, CBID);
        let bloque = b66_post(vec![hija.clone(), madre, hija], 2);
        let (nuevo, _, descartes) =
            aplicar_fusion(&base, &bloque, Punto::Slot(2), &params(), CBID, &evp()).unwrap();
        assert_eq!(descartes.len(), 1);
        assert_eq!(descartes.first().expect("un descarte").txid, id);
        let mut m = mempool(base);
        let recibo = ReciboBloque {
            peer: None,
            hash: b66_hash(2),
            txs: bloque.txs,
            descartes,
        };
        let (r, _) =
            m.actualizar_tras_bloque(nuevo, BTreeMap::new(), &recibo, ahora(), Punto::Slot(2));
        assert!(r.is_empty());
        assert!(m.aplicadas.contains_key(&id));
        assert_eq!(m.estadisticas().n, 0);
    }

    pub(crate) fn b66_hash(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn b66_post(txs: Vec<TxConTestigos>, slot: u64) -> BloqueTransicion {
        BloqueTransicion::nuevo(
            HechosCabecera::PoST {
                hash: b66_hash(200),
                padre: b66_hash(199),
                slot,
                productor: ClaveDev::derivar(66, 0).pk,
                peso: 1,
                prueba_valida: true,
                requisito_declarado: 0,
            },
            txs,
        )
    }

    pub(crate) fn b66_madre_hija() -> (Estado, TxConTestigos, TxConTestigos) {
        let a = ClaveDev::derivar(66, 0);
        let b = ClaveDev::derivar(66, 1);
        let c = ClaveDev::derivar(66, 2);
        let mut base = base_pow(&[(op_id(66), 1_000, a.pk)]);
        base.fase = Fase::PoST;
        base.slot = 1;
        let madre = transferencia(&a, op_id(66), 1_000, 800, b.pk);
        let hija = transferencia(
            &b,
            OutPoint {
                prev_txid: txid(&madre.0, CBID),
                prev_index: 0,
            },
            800,
            600,
            c.pk,
        );
        (base, madre, hija)
    }

    /// B66-C: una descartada real por doble gasto se retira y se marca como aplicada.
    /// Se ejecutan los componentes de la actualización; el método privado del nodo se cita en
    /// el informe y no se invoca desde este módulo.
    #[test]
    fn b66_01_la_descartada_en_fusion_sale_de_la_cola_control_rojo() {
        let a = ClaveDev::derivar(66, 0);
        let b = ClaveDev::derivar(66, 1);
        let mut base = base_pow(&[(op_id(66), 1_000, a.pk)]);
        base.fase = Fase::PoST;
        base.slot = 1;
        let descartada = transferencia(&a, op_id(66), 1_000, 800, b.pk);
        let ganadora = transferencia(&a, op_id(66), 1_000, 700, b.pk);
        let id = txid(&descartada.0, CBID);
        let mut m = mempool(base.clone());
        assert_eq!(
            m.admitir(
                None,
                descartada.0.clone(),
                descartada.1.clone(),
                ahora(),
                Punto::Slot(1)
            ),
            Ok(Admision::Admitida)
        );
        let bloque = b66_post(vec![ganadora, descartada], 2);
        let (nuevo, _, descartes) =
            aplicar_fusion(&base, &bloque, Punto::Slot(2), &params(), CBID, &evp()).unwrap();
        assert_eq!(descartes.len(), 1);
        let descarte = descartes.first().expect("un descarte");
        assert_eq!((descarte.indice, descarte.txid), (1, id));
        assert_eq!(descarte.motivo, ErrorTransicion::ErrDobleGasto);
        assert!(!nuevo.utxo.contains_key(&OutPoint {
            prev_txid: id,
            prev_index: 0
        }));
        let ids: Vec<TxId> = bloque.txs.iter().map(|(tx, _)| txid(tx, CBID)).collect();
        // nodo.rs: actualizar_mempool_tras_bloque confirma todo el cuerpo, sin filtrar descartes.
        m.confirmar_aplicadas(&ids, Punto::Slot(2));
        m.rebasear(nuevo, ahora(), Punto::Slot(2));
        m.expirar(Punto::Slot(2));
        assert_eq!(m.estadisticas().n, 0);
        assert_eq!(m.estadisticas().huerfanas, 0);
        assert!(!m.entradas.contains_key(&id));
        assert_eq!(m.aplicadas.get(&id), Some(&Punto::Slot(2)));
        assert!(
            m.contiene(&id),
            "contiene también incluye el registro, no solo la cola"
        );
        println!(
            "B66-01: descartadas=1; cola=1->0; aplicada_sin_efecto=true; motivo=ErrDobleGasto"
        );
    }

    /// B66-C: el perfil dev retiene el registro hasta diferencia 300 inclusive. Solo una poda
    /// con diferencia 301 permite readmitir esta hija, válida después de que se aplica la madre.
    #[test]
    fn b66_02_no_se_readmite_mientras_dura_el_registro_de_aplicadas_control_rojo() {
        let (base, madre, hija) = b66_madre_hija();
        let id = txid(&hija.0, CBID);
        let mut m = mempool(base.clone());
        for (tx, w) in [&madre, &hija] {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Slot(1)),
                Ok(Admision::Admitida)
            );
        }
        let bloque = b66_post(vec![hija.clone(), madre], 2);
        let (nuevo, _, descartes) =
            aplicar_fusion(&base, &bloque, Punto::Slot(2), &params(), CBID, &evp()).unwrap();
        assert_eq!(descartes.len(), 1);
        let descarte = descartes.first().expect("un descarte");
        assert_eq!((descarte.indice, descarte.txid), (0, id));
        assert_eq!(descarte.motivo, ErrorTransicion::ErrDobleGasto);
        let ids: Vec<TxId> = bloque.txs.iter().map(|(tx, _)| txid(tx, CBID)).collect();
        m.confirmar_aplicadas(&ids, Punto::Slot(2));
        m.rebasear(nuevo.clone(), ahora(), Punto::Slot(2));
        assert_eq!(m.politica().ttl_puntos, 300);
        for transcurridos in [0, 299, 300] {
            let punto = Punto::Slot(2 + transcurridos);
            m.expirar(punto);
            assert_eq!(
                m.admitir(None, hija.0.clone(), hija.1.clone(), ahora(), punto),
                Ok(Admision::Duplicada)
            );
            assert_eq!(m.aplicadas.get(&id), Some(&Punto::Slot(2)));
            assert_eq!(m.estadisticas().n, 0);
        }
        let punto = Punto::Slot(303);
        // Pasar un punto futuro a admitir no expira por sí solo el registro.
        assert_eq!(
            m.admitir(None, hija.0.clone(), hija.1.clone(), ahora(), punto),
            Ok(Admision::Duplicada)
        );
        let mut control = mempool(nuevo);
        assert_eq!(
            control.admitir(None, hija.0.clone(), hija.1.clone(), ahora(), punto),
            Ok(Admision::Admitida),
            "la misma tx y el mismo estado validan sin el registro de aplicadas"
        );
        m.expirar(punto);
        assert!(!m.aplicadas.contains_key(&id));
        assert_eq!(
            m.estadisticas().n,
            0,
            "expirar no la devuelve automáticamente"
        );
        assert_eq!(
            m.admitir(None, hija.0, hija.1, ahora(), punto),
            Ok(Admision::Admitida)
        );
        println!(
            "B66-02: ttl_dev=300; delta_300=Duplicada; delta_301_sin_poda=Duplicada; delta_301_con_poda_y_reenvio=Admitida"
        );
    }

    /// B66-C: GHOSTDAG y Cadena reales colocan el bloque de la hija antes de su creador en el
    /// mergeset de una reunión. La hija sería válida en el estado posterior, pero no vuelve sola.
    #[test]
    fn b66_03_vale_en_otro_contexto_y_aun_asi_no_vuelve_control_rojo() {
        use zx_cadena::{BloqueCadena, BloquePost, Cadena};
        use zx_consensus::transicion::Garantia;
        use zx_dag::{IdentidadGhostdag, IdentidadTicket};

        let (mut inicial, madre, hija) = b66_madre_hija();
        inicial.fase = Fase::Genesis;
        for i in 0..crate::perfil::K_MIN {
            inicial.garantias.insert(
                ClaveDev::derivar(66, i).pk,
                Garantia {
                    activo: params().q,
                    ..Garantia::nueva()
                },
            );
        }
        let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
            params(),
            crate::perfil::GHOSTDAG_K,
            CBID,
            crate::perfil::MAX_PADRES,
            evp(),
            inicial,
        );
        cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::Genesis { hash: b66_hash(0) },
                Vec::new(),
            )))
            .unwrap();
        // Parámetros dev intactos; los hechos de cabecera llegan prevalidados a Cadena.
        let trabajo = params().w_min / U256::from(crate::perfil::H_CORTE_MIN);
        for altura in 1..=crate::perfil::H_CORTE_MIN {
            cadena
                .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                    HechosCabecera::PoW {
                        hash: b66_hash(u8::try_from(altura).unwrap()),
                        padre: b66_hash(u8::try_from(altura - 1).unwrap()),
                        altura,
                        trabajo,
                        pow_valido: true,
                    },
                    Vec::new(),
                )))
                .unwrap();
        }
        let terminal = b66_hash(u8::try_from(crate::perfil::H_CORTE_MIN).unwrap());
        assert_eq!(cadena.terminal(), Some(terminal));
        let mut m = mempool(cadena.estado_terminal().clone());
        let hija_id = txid(&hija.0, CBID);
        for (tx, w) in [&madre, &hija] {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Slot(0)),
                Ok(Admision::Admitida)
            );
        }
        let prod = ClaveDev::derivar(66, 0).pk;
        let post =
            |n: u8, padres: Vec<BlockHash>, slot: u64, peso: u128, txs: Vec<TxConTestigos>| {
                BloqueCadena::Post(BloquePost {
                    hash: b66_hash(n),
                    padres,
                    slot,
                    timestamp: 0,
                    productor: prod,
                    peso,
                    prueba_valida: true,
                    requisito_declarado: 0,
                    sr: 1,
                    distancia: 0,
                    identidad: IdentidadGhostdag::Billete(IdentidadTicket::vigente(
                        prod,
                        u16::from(n),
                        1 << 20,
                        [n; 32],
                        slot,
                    )),
                    txs,
                })
            };
        let sp = post(100, vec![terminal], 1, 10, Vec::new());
        let b_hija = post(101, vec![terminal], 2, 1, vec![hija.clone()]);
        let b_madre = post(102, vec![terminal], 3, 1, vec![madre]);
        let reunion = post(
            103,
            vec![b66_hash(100), b66_hash(101), b66_hash(102)],
            4,
            1,
            Vec::new(),
        );
        for bloque in [sp, b_hija, b_madre, reunion] {
            let ids: Vec<TxId> = bloque.txs().iter().map(|(tx, _)| txid(tx, CBID)).collect();
            let hash = bloque.hash();
            cadena.admitir(bloque).unwrap();
            if hash == b66_hash(101) {
                let d = cadena.descartes(&hash).unwrap();
                assert_eq!(d.len(), 1);
                assert_eq!(d.first().expect("un descarte").txid, hija_id);
            }
            let nuevo = cadena.estado_virtual().unwrap();
            let punto = Punto::Slot(nuevo.slot);
            m.confirmar_aplicadas(&ids, punto);
            m.rebasear(nuevo, ahora(), punto);
            m.expirar(punto);
        }
        assert_eq!(cadena.mergeset_de(&b66_hash(103)), Some((2, 0)));
        let (nuevo, orden, descartes) = cadena.aplicar_historia().unwrap();
        assert_eq!(
            orden,
            vec![b66_hash(100), b66_hash(101), b66_hash(102), b66_hash(103)]
        );
        assert_eq!(descartes.len(), 1);
        let descarte = descartes.first().expect("un descarte");
        assert_eq!((descarte.bloque, descarte.indice), (b66_hash(101), 0));
        assert_eq!(descarte.motivo, ErrorTransicion::ErrDobleGasto);
        let siguiente = b66_post(vec![hija.clone()], nuevo.slot + 1);
        let (_, _, desc_siguiente) = aplicar_fusion(
            &nuevo,
            &siguiente,
            Punto::Slot(nuevo.slot + 1),
            &params(),
            CBID,
            &evp(),
        )
        .unwrap();
        assert!(
            desc_siguiente.is_empty(),
            "la hija valida en el contexto siguiente"
        );
        let mut control = mempool(nuevo.clone());
        assert_eq!(
            control.admitir(
                None,
                hija.0.clone(),
                hija.1.clone(),
                ahora(),
                Punto::Slot(nuevo.slot)
            ),
            Ok(Admision::Admitida)
        );
        assert_eq!(m.estadisticas().n, 0);
        assert!(!m.entradas.contains_key(&hija_id));
        assert!(m.aplicadas.contains_key(&hija_id));
        assert_eq!(
            m.admitir(
                None,
                hija.0.clone(),
                hija.1.clone(),
                ahora(),
                Punto::Slot(nuevo.slot)
            ),
            Ok(Admision::Duplicada)
        );
        assert_eq!(m.reinsertar(&[hija], ahora(), Punto::Slot(nuevo.slot)), 1);
        assert!(
            m.entradas.contains_key(&hija_id),
            "reinsertar explícito sí la recupera"
        );
        println!(
            "B66-03: mergeset=2_azules_0_rojos; orden=hija,madre; descartadas=1; fusion_siguiente_descartes=0; cola_automatica=0; control=Admitida; reinsertar=1"
        );
    }

    #[test]
    fn b66_03_vale_en_otro_contexto_y_aun_asi_no_vuelve() {
        use zx_cadena::{BloqueCadena, BloquePost, Cadena};
        use zx_consensus::transicion::Garantia;
        use zx_dag::{IdentidadGhostdag, IdentidadTicket};

        let (mut inicial, madre, hija) = b66_madre_hija();
        inicial.fase = Fase::Genesis;
        for i in 0..crate::perfil::K_MIN {
            inicial.garantias.insert(
                ClaveDev::derivar(66, i).pk,
                Garantia {
                    activo: params().q,
                    ..Garantia::nueva()
                },
            );
        }
        let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
            params(),
            crate::perfil::GHOSTDAG_K,
            CBID,
            crate::perfil::MAX_PADRES,
            evp(),
            inicial,
        );
        cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::Genesis { hash: b66_hash(0) },
                Vec::new(),
            )))
            .unwrap();
        // Parámetros dev intactos; los hechos de cabecera llegan prevalidados a Cadena.
        let trabajo = params().w_min / U256::from(crate::perfil::H_CORTE_MIN);
        for altura in 1..=crate::perfil::H_CORTE_MIN {
            cadena
                .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                    HechosCabecera::PoW {
                        hash: b66_hash(u8::try_from(altura).unwrap()),
                        padre: b66_hash(u8::try_from(altura - 1).unwrap()),
                        altura,
                        trabajo,
                        pow_valido: true,
                    },
                    Vec::new(),
                )))
                .unwrap();
        }
        let terminal = b66_hash(u8::try_from(crate::perfil::H_CORTE_MIN).unwrap());
        assert_eq!(cadena.terminal(), Some(terminal));
        let mut m = mempool(cadena.estado_terminal().clone());
        let hija_id = txid(&hija.0, CBID);
        for (tx, w) in [&madre, &hija] {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Slot(0)),
                Ok(Admision::Admitida)
            );
        }
        let prod = ClaveDev::derivar(66, 0).pk;
        let post =
            |n: u8, padres: Vec<BlockHash>, slot: u64, peso: u128, txs: Vec<TxConTestigos>| {
                BloqueCadena::Post(BloquePost {
                    hash: b66_hash(n),
                    padres,
                    slot,
                    timestamp: 0,
                    productor: prod,
                    peso,
                    prueba_valida: true,
                    requisito_declarado: 0,
                    sr: 1,
                    distancia: 0,
                    identidad: IdentidadGhostdag::Billete(IdentidadTicket::vigente(
                        prod,
                        u16::from(n),
                        1 << 20,
                        [n; 32],
                        slot,
                    )),
                    txs,
                })
            };
        let sp = post(100, vec![terminal], 1, 10, Vec::new());
        let b_hija = post(101, vec![terminal], 2, 1, vec![hija.clone()]);
        let b_madre = post(102, vec![terminal], 3, 1, vec![madre]);
        let reunion = post(
            103,
            vec![b66_hash(100), b66_hash(101), b66_hash(102)],
            4,
            1,
            Vec::new(),
        );
        for bloque in [sp, b_hija, b_madre, reunion] {
            let cuerpo = bloque.txs().to_vec();
            let hash = bloque.hash();
            cadena.admitir(bloque).unwrap();
            if hash == b66_hash(101) {
                let d = cadena.descartes(&hash).unwrap();
                assert_eq!(d.len(), 1);
                assert_eq!(d.first().expect("un descarte").txid, hija_id);
            }
            let nuevo = cadena.estado_virtual().unwrap();
            let punto = Punto::Slot(nuevo.slot);
            let recibo = ReciboBloque {
                peer: None,
                hash,
                txs: cuerpo,
                descartes: cadena.descartes(&hash).unwrap_or_default().to_vec(),
            };
            m.actualizar_tras_bloque(nuevo, BTreeMap::new(), &recibo, ahora(), punto);
        }
        assert_eq!(cadena.mergeset_de(&b66_hash(103)), Some((2, 0)));
        let (nuevo, orden, descartes) = cadena.aplicar_historia().unwrap();
        assert_eq!(
            orden,
            vec![b66_hash(100), b66_hash(101), b66_hash(102), b66_hash(103)]
        );
        assert_eq!(descartes.len(), 1);
        let descarte = descartes.first().expect("un descarte");
        assert_eq!((descarte.bloque, descarte.indice), (b66_hash(101), 0));
        assert_eq!(descarte.motivo, ErrorTransicion::ErrDobleGasto);
        let siguiente = b66_post(vec![hija.clone()], nuevo.slot + 1);
        let (_, _, desc_siguiente) = aplicar_fusion(
            &nuevo,
            &siguiente,
            Punto::Slot(nuevo.slot + 1),
            &params(),
            CBID,
            &evp(),
        )
        .unwrap();
        assert!(
            desc_siguiente.is_empty(),
            "la hija valida en el contexto siguiente"
        );
        let mut control = mempool(nuevo.clone());
        assert_eq!(
            control.admitir(
                None,
                hija.0.clone(),
                hija.1.clone(),
                ahora(),
                Punto::Slot(nuevo.slot)
            ),
            Ok(Admision::Admitida)
        );
        assert_eq!(m.estadisticas().n, 1);
        assert!(m.entradas.contains_key(&hija_id));
        assert!(!m.aplicadas.contains_key(&hija_id));
        assert_eq!(
            m.admitir(
                None,
                hija.0.clone(),
                hija.1.clone(),
                ahora(),
                Punto::Slot(nuevo.slot)
            ),
            Ok(Admision::Duplicada)
        );
        assert_eq!(m.reinsertar(&[hija], ahora(), Punto::Slot(nuevo.slot)), 1);
        assert!(
            m.entradas.contains_key(&hija_id),
            "reinsertar explícito sí la recupera"
        );
        println!(
            "B66-03 corregida: mergeset=2_azules_0_rojos; orden=hija,madre; descartadas=1; fusion_siguiente_descartes=0; cola_automatica=1; control=Admitida; reinsertar=1"
        );
    }

    /// **TX-R-32/33 · vuelta tras reorganización.** Una tx confirmada en un bloque descartado
    /// vuelve; una que sigue aplicada no se readmite.
    #[test]
    fn vuelta_tras_reorganizacion() {
        let a = ClaveDev::derivar(1, 0);
        let b = ClaveDev::derivar(1, 1);
        let mut m = mempool(base_pow(&[(op_id(1), 1_000, a.pk)]));
        let (tx, tst) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        let id = txid(&tx, CBID);
        assert_eq!(
            m.admitir(None, tx.clone(), tst.clone(), ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        // El bloque que la llevaba se confirma: sale de la mempool y queda como aplicada.
        m.confirmar_aplicadas(&[id], Punto::Altura(1));
        assert_eq!(m.estadisticas().n, 0);
        assert!(m.contiene(&id), "aplicada: dedup con el estado");
        assert_eq!(
            m.admitir(None, tx.clone(), tst.clone(), ahora(), Punto::Altura(1)),
            Ok(Admision::Duplicada)
        );
        // Ese bloque sale de la cadena: la tx vuelve a la mempool.
        let n = m.reinsertar(&[(tx, tst)], ahora(), Punto::Altura(1));
        assert_eq!(n, 1);
        assert_eq!(m.estadisticas().n, 1);
    }

    /// **V3 · propiedad.** Para cualquier orden de llegada de un conjunto fijo de txs (con una
    /// dependencia padre→hijo), el conjunto final de la mempool es el mismo. La excepción son los
    /// **conflictos**, que no se incluyen aquí: en ellos gana el primero y el resultado depende del
    /// orden (declarado en `PROGRESO.md`).
    #[test]
    fn v3_propiedad_200_ordenes() {
        let a = ClaveDev::derivar(7, 0);
        let b = ClaveDev::derivar(7, 1);
        let base = base_pow(&[
            (op_id(1), 1_000, a.pk),
            (op_id(2), 1_000, a.pk),
            (op_id(3), 1_000, a.pk),
            (op_id(4), 1_000, a.pk),
            (op_id(5), 1_000, a.pk),
            (op_id(6), 1_000, a.pk),
        ]);
        // 5 transferencias independientes + 1 padre→hijo.
        let mut libres = Vec::new();
        for (op, n) in [
            (op_id(1), 1u8),
            (op_id(2), 2),
            (op_id(3), 3),
            (op_id(4), 4),
            (op_id(5), 5),
        ] {
            libres.push(transferencia(
                &a,
                op,
                1_000,
                800,
                ClavePublica::desde_bytes([n; 32]),
            ));
        }
        let (padre, wp) = transferencia(&a, op_id(6), 1_000, 800, b.pk);
        let op_hijo = OutPoint {
            prev_txid: txid(&padre, CBID),
            prev_index: 0,
        };
        let (hijo, wh) = transferencia(&b, op_hijo, 800, 600, ClavePublica::desde_bytes([9; 32]));
        let mut conjunto: Vec<(Tx, Vec<Vec<u8>>)> = libres;
        conjunto.push((padre, wp));
        conjunto.push((hijo, wh));
        let esperado: BTreeSet<TxId> = conjunto.iter().map(|(t, _)| txid(t, CBID)).collect();

        for orden in 0..200u64 {
            let mut m = mempool(base.clone());
            let mut indices: Vec<usize> = (0..conjunto.len()).collect();
            // Fisher-Yates determinista con splitmix64.
            for i in (1..indices.len()).rev() {
                let j = (splitmix64(orden.wrapping_mul(0x9E37_79B9) ^ i as u64) % (i as u64 + 1))
                    as usize;
                indices.swap(i, j);
            }
            for i in indices {
                let Some((tx, tst)) = conjunto.get(i).cloned() else {
                    continue;
                };
                let _ = m.admitir(None, tx, tst, ahora(), Punto::Altura(1));
            }
            let obtenido: BTreeSet<TxId> = m.entradas.keys().copied().collect();
            assert_eq!(obtenido, esperado, "orden {orden} discrepa");
            assert_eq!(m.estadisticas().huerfanas, 0, "orden {orden}: huérfanas");
        }
    }
}

/// MP-1 · pruebas de P1 (la cola valida en el punto del bloque siguiente) y P2 (`expulsar`). Módulo
/// propio para no tocar el `mod tests` existente.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]
mod pruebas_mp1 {
    use super::*;
    use crate::claves::ClaveDev;
    use zx_consensus::transicion::{EntradaUtxo, Origen};
    use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};

    const CBID: u32 = zx_core::CBID_RED_DEV;

    fn params() -> ParametrosTransicion {
        crate::perfil::parametros_transicion_dev().expect("perfil dev")
    }

    fn evp() -> ParametrosEvidencia {
        crate::perfil::parametros_evidencia_dev()
    }

    fn ahora() -> Instant {
        Instant::now()
    }

    fn op_id(n: u8) -> OutPoint {
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: 0,
        }
    }

    fn transferencia(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        valor_out: i64,
        destino: ClavePublica,
    ) -> (Tx, Vec<Vec<u8>>) {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(valor_out).unwrap(),
                lock: Lock::PubKey { pubkey: destino },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = [SpentOutput {
            value: Amount::nuevo(valor_in).unwrap(),
            lock: Lock::PubKey { pubkey: clave.pk },
        }];
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).unwrap();
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    fn base_pow_utxos(altura: u32, utxos: &[(OutPoint, i64, ClavePublica, Origen, u32)]) -> Estado {
        let mut e = Estado::inicial();
        e.fase = Fase::PoW;
        e.altura = altura;
        for (op, v, pk, origen, creada) in utxos {
            e.utxo.insert(
                *op,
                EntradaUtxo {
                    valor: Amount::nuevo(*v).unwrap(),
                    lock: Lock::PubKey { pubkey: *pk },
                    origen: *origen,
                    creada: Punto::Altura(*creada),
                },
            );
        }
        e
    }

    fn base_post_utxos(
        slot: u64,
        s0: u64,
        utxos: &[(OutPoint, i64, ClavePublica, Origen, u32)],
    ) -> Estado {
        let mut e = base_pow_utxos(0, utxos);
        e.fase = Fase::PoST;
        e.slot = slot;
        e.s0 = s0;
        e.altura_terminal = None;
        e
    }

    fn mempool(base: Estado) -> Mempool {
        Mempool::nueva(params(), evp(), CBID, base, Politica::dev())
    }

    fn punto_igual(m: &Mempool) {
        assert_eq!(m.vista.altura, m.base.altura, "vista.altura != base.altura");
        assert_eq!(m.vista.slot, m.base.slot, "vista.slot != base.slot");
    }

    // ── 1 ────────────────────────────────────────────────────────────────────────────────────

    fn base_b62(h: u32, a: &ClaveDev) -> Estado {
        let mut utxos: Vec<(OutPoint, i64, ClavePublica, Origen, u32)> = Vec::new();
        for (i, creada) in [h - 4, h - 3, h - 2, h - 1].into_iter().enumerate() {
            utxos.push((
                op_id(30 + i as u8),
                1_000,
                a.pk,
                Origen::CoinbasePow,
                creada,
            ));
        }
        for i in 0..4u8 {
            utxos.push((op_id(40 + i), 1_000, a.pk, Origen::Tx, 0));
        }
        base_pow_utxos(h, &utxos)
    }

    fn gasto_en_posicion(
        base: &Estado,
        a: &ClaveDev,
        b: &ClaveDev,
        h: u32,
        op: OutPoint,
        pos: usize,
    ) -> Result<Admision, Rechazo> {
        let mut m = mempool(base.clone());
        for i in 0..pos.saturating_sub(1) {
            let (tx, tst) = transferencia(a, op_id(40 + i as u8), 1_000, 800, b.pk);
            assert_eq!(
                m.admitir(None, tx, tst, ahora(), Punto::Altura(h)),
                Ok(Admision::Admitida),
                "relleno {i} de la posición {pos}"
            );
        }
        let (tx, tst) = transferencia(a, op, 1_000, 800, b.pk);
        m.admitir(None, tx, tst, ahora(), Punto::Altura(h))
    }

    /// **P1 (B-62)**: la posición en la cola no cambia el punto de validación. La recompensa de
    /// `h-4` (madura en `h+1`) entra en la posición 1 y en la 5; la de `h-3` (madura en `h+2`) se
    /// rechaza en la 1, la 2 y la 5. Antes de P1, la 2 y la 5 se admitían.
    #[test]
    fn cola_no_admite_gasto_inmaduro_en_ninguna_posicion() {
        let a = ClaveDev::derivar(21, 0);
        let b = ClaveDev::derivar(21, 1);
        let h = 10u32;
        let base = base_b62(h, &a);
        assert_eq!(
            gasto_en_posicion(&base, &a, &b, h, op_id(30), 1),
            Ok(Admision::Admitida),
            "h-4 en la posición 1"
        );
        assert_eq!(
            gasto_en_posicion(&base, &a, &b, h, op_id(30), 5),
            Ok(Admision::Admitida),
            "h-4 en la posición 5"
        );
        for pos in [1usize, 2, 5] {
            let r = gasto_en_posicion(&base, &a, &b, h, op_id(31), pos);
            assert!(
                matches!(r, Err(Rechazo::VistaLocal(_))),
                "h-3 en la posición {pos} debe rechazarse (era la reproducción de B-62): {r:?}"
            );
        }
    }

    // ── 2 ────────────────────────────────────────────────────────────────────────────────────

    /// **P1**: tras admitir 1, 2 y 8, tras `rebasear`, tras `expulsar` y tras resolver huérfanas,
    /// `vista.altura == base.altura` y `vista.slot == base.slot`, en minado y en fusión.
    #[test]
    fn vista_de_la_cola_no_avanza_el_punto() {
        let a = ClaveDev::derivar(32, 0);
        let b = ClaveDev::derivar(32, 1);
        let h = 10u32;
        let utxos: Vec<(OutPoint, i64, ClavePublica, Origen, u32)> = (1..=10u8)
            .map(|i| (op_id(i), 1_000, a.pk, Origen::Tx, 0))
            .collect();
        let base = base_pow_utxos(h, &utxos);
        let txs: Vec<(Tx, Vec<Vec<u8>>)> = (1..=8u8)
            .map(|i| transferencia(&a, op_id(i), 1_000, 800, b.pk))
            .collect();

        let mut m = mempool(base.clone());
        assert_eq!(
            m.admitir(
                None,
                txs[0].0.clone(),
                txs[0].1.clone(),
                ahora(),
                Punto::Altura(h)
            ),
            Ok(Admision::Admitida)
        );
        punto_igual(&m);
        assert_eq!(
            m.admitir(
                None,
                txs[1].0.clone(),
                txs[1].1.clone(),
                ahora(),
                Punto::Altura(h)
            ),
            Ok(Admision::Admitida)
        );
        punto_igual(&m);
        for t in &txs[2..] {
            let _ = m.admitir(None, t.0.clone(), t.1.clone(), ahora(), Punto::Altura(h));
        }
        assert_eq!(m.estadisticas().n, 8);
        punto_igual(&m);

        // rebasear a otra punta
        let base2 = base_pow_utxos(h + 1, &utxos);
        m.rebasear(base2.clone(), ahora(), Punto::Altura(h + 1));
        assert_eq!(m.base.altura, h + 1);
        punto_igual(&m);

        // expulsar una
        let id0 = txid(&txs[0].0, CBID);
        assert!(m.contiene(&id0));
        m.expulsar(&[id0]);
        punto_igual(&m);

        // huérfanas: el hijo entra antes que el padre y se resuelve al llegar el padre
        let mut mh = mempool(base.clone());
        let (padre, wp) = transferencia(&a, op_id(9), 1_000, 800, b.pk);
        let padre_id = txid(&padre, CBID);
        let (hijo, wh) = transferencia(
            &b,
            OutPoint {
                prev_txid: padre_id,
                prev_index: 0,
            },
            800,
            600,
            a.pk,
        );
        assert_eq!(
            mh.admitir(None, hijo, wh, ahora(), Punto::Altura(h)),
            Ok(Admision::Huerfana)
        );
        punto_igual(&mh);
        assert_eq!(
            mh.admitir(None, padre, wp, ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida)
        );
        assert_eq!(mh.estadisticas().huerfanas, 0);
        punto_igual(&mh);

        // fusión
        let basep = base_post_utxos(8, 10, &utxos);
        let mut mp = mempool(basep.clone());
        for t in &txs[..3] {
            let _ = mp.admitir(None, t.0.clone(), t.1.clone(), ahora(), Punto::Slot(8));
        }
        assert!(mp.estadisticas().n >= 1, "fusión: alguna tx debe admitirse");
        punto_igual(&mp);
    }

    // ── 3 ────────────────────────────────────────────────────────────────────────────────────

    /// **P1, fusión**: una `coinbase_pow` tardía se rechaza en la posición 1 y detrás de
    /// `m_res_slots + 2` transacciones válidas (hoy la última se admitía por la deriva del slot).
    #[test]
    fn cola_no_deriva_el_slot_en_fusion() {
        let a = ClaveDev::derivar(33, 0);
        let b = ClaveDev::derivar(33, 1);
        let s = 8u64;
        let s0 = 10u64;
        let m_res = params().m_res_slots;
        let mut utxos: Vec<(OutPoint, i64, ClavePublica, Origen, u32)> =
            vec![(op_id(200), 1_000, a.pk, Origen::CoinbasePow, 100u32)];
        for i in 0..(m_res as u8 + 4) {
            utxos.push((op_id(210 + i), 1_000, a.pk, Origen::Tx, 0));
        }
        let base = base_post_utxos(s, s0, &utxos);
        assert!(s + 1 < s0 + m_res);

        let mut m = mempool(base.clone());
        let (tx, tst) = transferencia(&a, op_id(200), 1_000, 800, b.pk);
        let r = m.admitir(None, tx, tst, ahora(), Punto::Slot(s));
        assert!(
            matches!(r, Err(Rechazo::VistaLocal(_))),
            "la coinbase tardía en la posición 1 debe rechazarse: {r:?}"
        );

        let mut m = mempool(base.clone());
        for i in 0..(m_res + 2) {
            let (tx, tst) = transferencia(&a, op_id(210 + i as u8), 1_000, 800, b.pk);
            assert_eq!(
                m.admitir(None, tx, tst, ahora(), Punto::Slot(s)),
                Ok(Admision::Admitida),
                "relleno {i}"
            );
        }
        let (tx, tst) = transferencia(&a, op_id(200), 1_000, 800, b.pk);
        let r = m.admitir(None, tx, tst, ahora(), Punto::Slot(s));
        assert!(
            matches!(r, Err(Rechazo::VistaLocal(_))),
            "detrás de m_res+2 válidas debe seguir rechazándose (deriva de la 5.ª): {r:?}"
        );
        punto_igual(&m);
    }

    // ── 6 ────────────────────────────────────────────────────────────────────────────────────

    /// **P2**: `expulsar` retira las entradas indicadas y sus dependientes, no las marca como
    /// aplicadas y deja la vista como la de una cola nueva con las restantes.
    #[test]
    fn expulsar_retira_las_entradas_y_sus_dependientes() {
        let a = ClaveDev::derivar(34, 0);
        let b = ClaveDev::derivar(34, 1);
        let c = ClaveDev::derivar(34, 2);
        let h = 10u32;
        let base = base_pow_utxos(
            h,
            &[
                (op_id(1), 1_000, a.pk, Origen::Tx, 0),
                (op_id(2), 1_000, a.pk, Origen::Tx, 0),
            ],
        );
        let mut m = mempool(base.clone());
        let (padre, wp) = transferencia(&a, op_id(1), 1_000, 800, b.pk);
        let padre_id = txid(&padre, CBID);
        let (hijo, wh) = transferencia(
            &b,
            OutPoint {
                prev_txid: padre_id,
                prev_index: 0,
            },
            800,
            600,
            c.pk,
        );
        let hijo_id = txid(&hijo, CBID);
        let (indep, wi) = transferencia(&a, op_id(2), 1_000, 800, c.pk);
        let indep_id = txid(&indep, CBID);
        assert_eq!(
            m.admitir(None, padre.clone(), wp.clone(), ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(None, hijo.clone(), wh.clone(), ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(None, indep.clone(), wi.clone(), ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida)
        );
        assert!(m.contiene(&padre_id) && m.contiene(&hijo_id) && m.contiene(&indep_id));

        let n = m.expulsar(&[padre_id]);
        assert_eq!(n, 2, "padre + hijo dependiente");
        assert!(!m.contiene(&padre_id), "el padre no está");
        assert!(!m.contiene(&hijo_id), "el hijo dependiente no está");
        assert!(m.contiene(&indep_id), "la independiente sigue");
        assert_eq!(m.estadisticas().n, 1);
        punto_igual(&m);

        // La vista equivale a la de una cola nueva con las restantes.
        let mut m2 = mempool(base);
        assert_eq!(
            m2.admitir(None, indep, wi, ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida)
        );
        assert_eq!(m.vista, m2.vista, "vista equivalente a una cola nueva");

        // No figura como aplicada: se puede volver a admitir.
        assert_eq!(
            m.admitir(None, padre, wp, ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida),
            "expulsar no marca como aplicada"
        );
    }

    // ── 4 y 5: diferencial contra el motor ────────────────────────────────────────────────────

    fn prev_sintetico(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn bloque_pow_para(
        seleccion: Vec<(Tx, Vec<Vec<u8>>)>,
        clave: ClavePublica,
        altura: u32,
    ) -> BloqueTransicion {
        let prev = prev_sintetico(0x11);
        let (plantilla, _txid, _valor) = crate::pow::construir_plantilla(
            &[],
            prev,
            altura,
            1_700_000_000,
            CBID,
            clave,
            seleccion,
            1 << 20,
        )
        .expect("plantilla PoW");
        let trabajo = zx_core::trabajo_bloque(plantilla.target).expect("trabajo del target dev");
        let hechos = HechosCabecera::PoW {
            hash: plantilla.cabecera_base.block_hash(),
            padre: prev,
            altura,
            trabajo,
            pow_valido: true,
        };
        let txs: Vec<(Tx, Vec<Vec<u8>>)> =
            plantilla.txs.into_iter().zip(plantilla.testigos).collect();
        BloqueTransicion::nuevo(hechos, txs)
    }

    fn bloque_post_para(seleccion: Vec<(Tx, Vec<Vec<u8>>)>, slot: u64) -> BloqueTransicion {
        let hash = prev_sintetico(0x22);
        let hechos = HechosCabecera::PoST {
            hash,
            padre: hash,
            slot,
            productor: ClavePublica::desde_bytes([0x33; 32]),
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        };
        BloqueTransicion::nuevo(hechos, seleccion)
    }

    /// Pool de transacciones del diferencial: válidas, inmadura, doble gasto y una cadena.
    fn pool_diferencial(a: &ClaveDev, b: &ClaveDev, c: &ClaveDev) -> Vec<(Tx, Vec<Vec<u8>>)> {
        let (t1, w1) = transferencia(a, op_id(1), 1_000, 800, b.pk);
        let (t2, w2) = transferencia(a, op_id(2), 1_000, 900, b.pk);
        let (t3, w3) = transferencia(a, op_id(3), 1_000, 850, b.pk);
        let (t4, w4) = transferencia(a, op_id(4), 1_000, 950, b.pk);
        let (t5, w5) = transferencia(a, op_id(7), 1_000, 800, b.pk);
        let (t6, w6) = transferencia(a, op_id(8), 1_000, 800, b.pk);
        let (t7, w7) = transferencia(a, op_id(1), 1_000, 700, b.pk);
        let (padre, wp) = transferencia(a, op_id(5), 1_000, 800, c.pk);
        let padre_id = txid(&padre, CBID);
        let (hijo, wh) = transferencia(
            c,
            OutPoint {
                prev_txid: padre_id,
                prev_index: 0,
            },
            800,
            600,
            b.pk,
        );
        vec![
            (t1, w1),
            (t2, w2),
            (t3, w3),
            (t4, w4),
            (t5, w5),
            (t6, w6),
            (t7, w7),
            (padre, wp),
            (hijo, wh),
        ]
    }

    fn utxos_diferencial(h: u32, a: &ClaveDev) -> Vec<(OutPoint, i64, ClavePublica, Origen, u32)> {
        let mut utxos: Vec<(OutPoint, i64, ClavePublica, Origen, u32)> = Vec::new();
        for i in 1..=5u8 {
            utxos.push((op_id(i), 1_000, a.pk, Origen::Tx, 0));
        }
        utxos.push((op_id(7), 1_000, a.pk, Origen::CoinbasePow, h - 4));
        utxos.push((op_id(8), 1_000, a.pk, Origen::CoinbasePow, h - 3));
        utxos
    }

    /// Orden determinista del pool para cada semilla (Fisher-Yates con `splitmix64`).
    fn orden_para(pool: &[(Tx, Vec<Vec<u8>>)], semilla: u64) -> Vec<usize> {
        let mut orden: Vec<usize> = (0..pool.len()).collect();
        for i in (1..orden.len()).rev() {
            let j = (splitmix64(semilla.wrapping_mul(0x9E37_79B9) ^ i as u64) % (i as u64 + 1))
                as usize;
            orden.swap(i, j);
        }
        orden
    }

    /// MP-2 · ¿La selección contiene una cadena madre-hija? Es decir, ¿alguna transacción
    /// seleccionada gasta una salida creada por otra transacción seleccionada?
    fn seleccion_con_cadena(sel: &[(Tx, Vec<Vec<u8>>)]) -> bool {
        let ids: BTreeSet<TxId> = sel.iter().map(|(t, _)| txid(t, CBID)).collect();
        sel.iter()
            .any(|(t, _)| t.inputs.iter().any(|i| ids.contains(&i.outpoint.prev_txid)))
    }

    /// **P1 (diferencial, 300 casos)**: lo que la cola admite, seleccionado y montado como hace
    /// `fase_pow` (**sin** ordenar la selección en la prueba), lo acepta un bloque PoW en
    /// `base.altura + 1`. Cuenta, además, cuántos de los 300 casos traen una cadena madre-hija
    /// seleccionada y cuántos intentan un gasto inmaduro detrás de dos o más transacciones válidas
    /// (la condición que la deriva de la vista explotaría: `Orden MP-2` §4).
    #[test]
    fn lo_que_la_cola_admite_cabe_en_un_bloque_pow() {
        let a = ClaveDev::derivar(35, 0);
        let b = ClaveDev::derivar(35, 1);
        let c = ClaveDev::derivar(35, 2);
        let h = 10u32;
        let base = base_pow_utxos(h, &utxos_diferencial(h, &a));
        let pool = pool_diferencial(&a, &b, &c);
        let mut con_cadena = 0usize;
        let mut inmaduro_detras = 0usize;
        for semilla in 0..300u64 {
            let mut m = mempool(base.clone());
            let mut inmaduro_detras_de_dos = false;
            for i in orden_para(&pool, semilla) {
                let (tx, tst) = pool[i].clone();
                let antes = m.estadisticas().n;
                let r = m.admitir(None, tx, tst, ahora(), Punto::Altura(h));
                if antes >= 2 && matches!(r, Err(Rechazo::VistaLocal("vista"))) {
                    inmaduro_detras_de_dos = true;
                }
            }
            let seleccion = m.seleccionar(u64::MAX, semilla);
            if seleccion_con_cadena(&seleccion) {
                con_cadena += 1;
            }
            if inmaduro_detras_de_dos {
                inmaduro_detras += 1;
            }
            let bloque = bloque_pow_para(seleccion, a.pk, h + 1);
            let r = aplicar_con_undo(&base, &bloque, &params(), CBID, &evp());
            assert!(
                r.is_ok(),
                "semilla {semilla}: un bloque con lo admitido no se acepta: {:?}",
                r.err()
            );
        }
        eprintln!(
            "diferencial PoW: con_cadena={con_cadena}/300 inmaduro_detras_de_dos={inmaduro_detras}/300"
        );
        assert!(
            con_cadena >= 30,
            "solo {con_cadena}/300 con cadena madre-hija seleccionada"
        );
        assert!(
            inmaduro_detras >= 30,
            "solo {inmaduro_detras}/300 con gasto inmaduro detrás de dos válidas"
        );
    }

    /// **P1 (diferencial, fusión)**: tras el corte, `aplicar_fusion` del bloque en `base.slot + 1`
    /// devuelve cero `descartadas` para lo que la cola admite (**sin** ordenar la selección en la
    /// prueba). Cuenta, además, los casos con cadena madre-hija y con gasto inmaduro detrás de dos
    /// o más válidas, como la diferencial PoW.
    #[test]
    fn lo_que_la_cola_admite_no_se_descarta_en_fusion() {
        let a = ClaveDev::derivar(36, 0);
        let b = ClaveDev::derivar(36, 1);
        let c = ClaveDev::derivar(36, 2);
        let h = 10u32;
        // `s0 = 0` y `slot = 18`: el umbral de madurez es `s0 + m_res_slots = 20`, un punto por
        // delante del de validación (`slot + 1 = 19`), de modo que la deriva de la vista admitiría
        // el gasto inmaduro en cuanto hubiera dos transacciones válidas por delante. `base.slot`
        // sigue siendo el del corte.
        let base = base_post_utxos(18, 0, &utxos_diferencial(h, &a));
        let pool = pool_diferencial(&a, &b, &c);
        let mut con_cadena = 0usize;
        let mut inmaduro_detras = 0usize;
        for semilla in 0..300u64 {
            let mut m = mempool(base.clone());
            let mut inmaduro_detras_de_dos = false;
            for i in orden_para(&pool, semilla) {
                let (tx, tst) = pool[i].clone();
                let antes = m.estadisticas().n;
                let r = m.admitir(None, tx, tst, ahora(), Punto::Slot(base.slot));
                if antes >= 2 && matches!(r, Err(Rechazo::VistaLocal("vista"))) {
                    inmaduro_detras_de_dos = true;
                }
            }
            let seleccion = m.seleccionar(u64::MAX, semilla);
            if seleccion_con_cadena(&seleccion) {
                con_cadena += 1;
            }
            if inmaduro_detras_de_dos {
                inmaduro_detras += 1;
            }
            let bloque = bloque_post_para(seleccion, base.slot + 1);
            let r = aplicar_fusion(
                &base,
                &bloque,
                Punto::Slot(base.slot + 1),
                &params(),
                CBID,
                &evp(),
            );
            let (_nuevo, _undo, descartadas) = r.expect("un bloque de fusión debe aplicarse");
            assert!(
                descartadas.is_empty(),
                "semilla {semilla}: la fusión descartó {:?}",
                descartadas
                    .iter()
                    .map(|d| d.motivo.clone())
                    .collect::<Vec<_>>()
            );
        }
        eprintln!(
            "diferencial fusión: con_cadena={con_cadena}/300 inmaduro_detras_de_dos={inmaduro_detras}/300"
        );
        assert!(
            con_cadena >= 30,
            "solo {con_cadena}/300 con cadena madre-hija seleccionada"
        );
        assert!(
            inmaduro_detras >= 30,
            "solo {inmaduro_detras}/300 con gasto inmaduro detrás de dos válidas"
        );
    }

    /// Identificador sintético con el primer byte fijado y un relleno distinto por pago.
    fn id_con_primer_byte(primer: u8, relleno: u64) -> TxId {
        let mut bytes = [0u8; 32];
        bytes[0] = primer;
        bytes[8..16].copy_from_slice(&relleno.to_be_bytes());
        TxId::from_digest(Digest::from_bytes(bytes))
    }

    /// **IPA B-85 · 1**: dos pagos que comparten el primer byte del identificador reciben números
    /// distintos.
    #[test]
    fn bolsa_01_dos_pagos_con_el_mismo_primer_byte_reciben_numeros_distintos() {
        let semilla = 0x1234_5678_9ABC_DEF0_u64;
        let primero = id_con_primer_byte(0x42, 0);
        let segundo = id_con_primer_byte(0x42, 1);
        assert_eq!(
            primero.as_bytes()[0],
            segundo.as_bytes()[0],
            "los dos identificadores deben compartir el primer byte"
        );
        assert_ne!(
            numero_de_pago(semilla, &primero),
            numero_de_pago(semilla, &segundo),
            "dos pagos con el mismo primer byte no pueden recibir el mismo número"
        );
    }

    /// **IPA B-85 · 2**: 4000 identificadores sintéticos que comparten el primer byte, con una
    /// semilla fija, dan 4000 números distintos.
    #[test]
    fn bolsa_02_cuatro_mil_pagos_con_el_mismo_primer_byte_dan_cuatro_mil_numeros() {
        let semilla = 0xDEAD_BEEF_CAFE_1234_u64;
        let mut numeros: BTreeSet<u64> = BTreeSet::new();
        for relleno in 0..4_000u64 {
            numeros.insert(numero_de_pago(semilla, &id_con_primer_byte(0x00, relleno)));
        }
        assert_eq!(
            numeros.len(),
            4_000,
            "4000 pagos con el mismo primer byte deben dar 4000 números"
        );
    }

    /// **IPA B-85 · 3**: la selección sigue siendo determinista con la misma semilla.
    #[test]
    fn bolsa_03_la_seleccion_sigue_siendo_determinista_con_la_misma_semilla() {
        let a = ClaveDev::derivar(85, 0);
        let b = ClaveDev::derivar(85, 1);
        let utxos: Vec<(OutPoint, i64, ClavePublica, Origen, u32)> = (1..=6u8)
            .map(|i| (op_id(i), 1_000, a.pk, Origen::Tx, 0))
            .collect();
        let base = base_pow_utxos(1, &utxos);
        let txs: Vec<(Tx, Vec<Vec<u8>>)> = (1..=6u8)
            .map(|i| transferencia(&a, op_id(i), 1_000, 900, b.pk))
            .collect();
        let mut m = mempool(base);
        for (tx, w) in &txs {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Altura(1)),
                Ok(Admision::Admitida)
            );
        }
        let semilla = 0x5A5A_5A5A_5A5A_5A5A_u64;
        assert_eq!(
            m.seleccionar(u64::MAX, semilla),
            m.seleccionar(u64::MAX, semilla),
            "la selección debe ser la misma con la misma semilla"
        );
        for (tx, _) in &txs {
            let id = txid(tx, CBID);
            assert_eq!(
                numero_de_pago(semilla, &id),
                numero_de_pago(semilla, &id),
                "el número de pago debe ser determinista"
            );
        }
    }

    /// **IPA B-85 · 4**: cambiar cualquiera de los 32 bytes del identificador cambia el número.
    #[test]
    fn bolsa_04_cambiar_cualquier_byte_del_identificador_cambia_el_numero() {
        let semilla = 0x0FED_CBA9_8765_4321_u64;
        let original = [0x11u8; 32];
        let numero_original =
            numero_de_pago(semilla, &TxId::from_digest(Digest::from_bytes(original)));
        for i in 0..32usize {
            let mut bytes = original;
            for (j, byte) in bytes.iter_mut().enumerate() {
                if j == i {
                    *byte ^= 0x01;
                }
            }
            let numero = numero_de_pago(semilla, &TxId::from_digest(Digest::from_bytes(bytes)));
            assert_ne!(
                numero, numero_original,
                "cambiar el byte {i} del identificador no cambió el número"
            );
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño"
)]
mod pruebas_mp2 {
    use super::*;
    use crate::claves::ClaveDev;
    use zx_consensus::transicion::{EntradaUtxo, Origen};
    use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};

    const CBID: u32 = zx_core::CBID_RED_DEV;

    fn params() -> ParametrosTransicion {
        crate::perfil::parametros_transicion_dev().expect("perfil dev")
    }

    fn ahora() -> Instant {
        Instant::now()
    }

    fn op_id(n: u8) -> OutPoint {
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: 0,
        }
    }

    fn base_pow_utxos(altura: u32, utxos: &[(OutPoint, ClavePublica)]) -> Estado {
        let mut e = Estado::inicial();
        e.fase = Fase::PoW;
        e.altura = altura;
        for (op, pk) in utxos {
            e.utxo.insert(
                *op,
                EntradaUtxo {
                    valor: Amount::nuevo(1_000).unwrap(),
                    lock: Lock::PubKey { pubkey: *pk },
                    origen: Origen::Tx,
                    creada: Punto::Altura(0),
                },
            );
        }
        e
    }

    fn mempool(base: Estado) -> Mempool {
        Mempool::nueva(
            params(),
            crate::perfil::parametros_evidencia_dev(),
            CBID,
            base,
            Politica::dev(),
        )
    }

    fn peso_de(tx: &Tx, testigos: &[Vec<u8>]) -> u64 {
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
        buf.len() as u64
    }

    /// Transferencia v1 firmada por `clave` que gasta `op` (con `valor_in`) y paga `salidas`.
    fn transferencia_salidas(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        salidas: &[i64],
        destino: ClavePublica,
    ) -> (Tx, Vec<Vec<u8>>) {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: salidas
                .iter()
                .map(|v| TxOut {
                    value: Amount::nuevo(*v).unwrap(),
                    lock: Lock::PubKey { pubkey: destino },
                })
                .collect(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = [SpentOutput {
            value: Amount::nuevo(valor_in).unwrap(),
            lock: Lock::PubKey { pubkey: clave.pk },
        }];
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).unwrap();
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    fn transferencia(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        valor_out: i64,
        destino: ClavePublica,
    ) -> (Tx, Vec<Vec<u8>>) {
        transferencia_salidas(clave, op, valor_in, &[valor_out], destino)
    }

    fn en_seleccion(sel: &[(Tx, Vec<Vec<u8>>)], id: &TxId) -> bool {
        sel.iter().any(|(t, _)| txid(t, CBID) == *id)
    }

    fn indice_de(sel: &[(Tx, Vec<Vec<u8>>)], id: &TxId) -> usize {
        sel.iter()
            .position(|(t, _)| txid(t, CBID) == *id)
            .expect("la transacción debe estar en la selección")
    }

    /// **MP-2 §4.1**: cadena A→B→C con tarifa creciente y varias independientes; para 300 semillas
    /// la selección pone a la madre antes que a la hija y las independientes conservan su orden
    /// relativo respecto de la selección sin reordenar.
    #[test]
    fn seleccion_pone_a_la_madre_antes_que_a_la_hija() {
        let a = ClaveDev::derivar(41, 0);
        let b = ClaveDev::derivar(41, 1);
        let h = 10u32;
        let base = base_pow_utxos(
            h,
            &[
                (op_id(1), a.pk),
                (op_id(10), a.pk),
                (op_id(11), a.pk),
                (op_id(12), a.pk),
                (op_id(13), a.pk),
            ],
        );
        // Cadena A→B→C, con salida siempre al dueño que la gasta y tarifa creciente.
        let (ta, wa) = transferencia(&a, op_id(1), 1_000, 950, b.pk);
        let a_id = txid(&ta, CBID);
        let (tb, wb) = transferencia(
            &b,
            OutPoint {
                prev_txid: a_id,
                prev_index: 0,
            },
            950,
            700,
            a.pk,
        );
        let b_id = txid(&tb, CBID);
        let (tc, wc) = transferencia(
            &a,
            OutPoint {
                prev_txid: b_id,
                prev_index: 0,
            },
            700,
            100,
            b.pk,
        );
        let c_id = txid(&tc, CBID);
        let independientes: Vec<(Tx, Vec<Vec<u8>>)> = (10..=13u8)
            .map(|i| transferencia(&a, op_id(i), 1_000, 900, b.pk))
            .collect();
        let ind_ids: Vec<TxId> = independientes.iter().map(|(t, _)| txid(t, CBID)).collect();

        for semilla in 0..300u64 {
            let mut m = mempool(base.clone());
            for (tx, w) in &independientes {
                assert_eq!(
                    m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Altura(h)),
                    Ok(Admision::Admitida)
                );
            }
            for (tx, w) in [(&ta, &wa), (&tb, &wb), (&tc, &wc)] {
                assert_eq!(
                    m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Altura(h)),
                    Ok(Admision::Admitida)
                );
            }
            let sel = m.seleccionar(u64::MAX, semilla);
            assert!(
                en_seleccion(&sel, &a_id) && en_seleccion(&sel, &b_id) && en_seleccion(&sel, &c_id),
                "semilla {semilla}: falta alguna de la cadena"
            );
            assert!(
                indice_de(&sel, &a_id) < indice_de(&sel, &b_id),
                "semilla {semilla}: A no va antes que B"
            );
            assert!(
                indice_de(&sel, &b_id) < indice_de(&sel, &c_id),
                "semilla {semilla}: B no va antes que C"
            );
            // Orden relativo de las independientes: igual que en la selección sin reordenar.
            let brutas = m.seleccionar_bruta(u64::MAX, semilla);
            let solo_ind = |v: &[(Tx, Vec<Vec<u8>>)]| -> Vec<TxId> {
                v.iter()
                    .map(|(t, _)| txid(t, CBID))
                    .filter(|id| ind_ids.contains(id))
                    .collect()
            };
            assert_eq!(
                solo_ind(&sel),
                solo_ind(&brutas),
                "semilla {semilla}: cambió el orden de las independientes"
            );
        }
    }

    /// **MP-2 §4.2**: una hija sin madre no entra en la selección. (a) la madre no cabe y la hija
    /// sí; (b) cadena de tres en la que no cabe la del medio: no están ni la del medio ni la
    /// última.
    #[test]
    fn seleccion_no_incluye_hija_sin_madre() {
        let a = ClaveDev::derivar(42, 0);
        let b = ClaveDev::derivar(42, 1);
        let h = 10u32;

        // (a) Madre pesada (ocho salidas) e hija ligera.
        let base = base_pow_utxos(h, &[(op_id(1), a.pk)]);
        let (madre, wm) = transferencia_salidas(&a, op_id(1), 1_000, &[100; 8], b.pk);
        let madre_id = txid(&madre, CBID);
        let (hija, wh) = transferencia(
            &b,
            OutPoint {
                prev_txid: madre_id,
                prev_index: 0,
            },
            100,
            50,
            a.pk,
        );
        let hija_id = txid(&hija, CBID);
        let mut m = mempool(base);
        assert_eq!(
            m.admitir(None, madre.clone(), wm.clone(), ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida)
        );
        assert_eq!(
            m.admitir(None, hija.clone(), wh.clone(), ahora(), Punto::Altura(h)),
            Ok(Admision::Admitida)
        );
        let max = peso_de(&hija, &wh);
        assert!(
            peso_de(&madre, &wm) > max,
            "la madre debe pesar más que la hija"
        );
        for semilla in 0..300u64 {
            let sel = m.seleccionar(max, semilla);
            assert!(
                !en_seleccion(&sel, &hija_id),
                "semilla {semilla}: la hija entró sin la madre"
            );
        }

        // (b) Cadena A→B→C con B (la del medio) pesada: ni B ni C.
        let base2 = base_pow_utxos(h, &[(op_id(2), a.pk)]);
        let (ta, wa) = transferencia(&a, op_id(2), 1_000, 950, b.pk);
        let a_id = txid(&ta, CBID);
        let (tb, wb) = transferencia_salidas(
            &b,
            OutPoint {
                prev_txid: a_id,
                prev_index: 0,
            },
            950,
            &[100; 8],
            a.pk,
        );
        let b_id = txid(&tb, CBID);
        let (tc, wc) = transferencia(
            &a,
            OutPoint {
                prev_txid: b_id,
                prev_index: 0,
            },
            100,
            50,
            b.pk,
        );
        let c_id = txid(&tc, CBID);
        let mut m2 = mempool(base2);
        for (tx, w) in [(&ta, &wa), (&tb, &wb), (&tc, &wc)] {
            assert_eq!(
                m2.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Altura(h)),
                Ok(Admision::Admitida)
            );
        }
        let max2 = peso_de(&tc, &wc).max(peso_de(&ta, &wa));
        assert!(
            peso_de(&tb, &wb) > max2,
            "la del medio debe ser la más pesada"
        );
        for semilla in 0..300u64 {
            let sel = m2.seleccionar(max2, semilla);
            assert!(
                !en_seleccion(&sel, &b_id),
                "semilla {semilla}: entró la del medio sin caber"
            );
            assert!(
                !en_seleccion(&sel, &c_id),
                "semilla {semilla}: entró la última sin su madre"
            );
        }
    }

    /// **MP-2 §4.3**: sin dependencias en la cola, la lista es idéntica (mismos elementos y mismo
    /// orden) a la que devolvía la selección antes de esta orden, para 300 semillas.
    #[test]
    fn seleccion_sin_cadenas_no_cambia() {
        let a = ClaveDev::derivar(43, 0);
        let b = ClaveDev::derivar(43, 1);
        let h = 10u32;
        let utxos: Vec<(OutPoint, ClavePublica)> = (1..=8u8).map(|i| (op_id(i), a.pk)).collect();
        let base = base_pow_utxos(h, &utxos);
        let txs: Vec<(Tx, Vec<Vec<u8>>)> = (1..=8u8)
            .map(|i| transferencia(&a, op_id(i), 1_000, 900 - i64::from(i), b.pk))
            .collect();
        let mut m = mempool(base);
        for (tx, w) in &txs {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Altura(h)),
                Ok(Admision::Admitida)
            );
        }
        for semilla in 0..300u64 {
            let con_regla = m.seleccionar(u64::MAX, semilla);
            let anterior = m.seleccionar_bruta(u64::MAX, semilla);
            assert_eq!(
                con_regla, anterior,
                "semilla {semilla}: la selección cambió sin cadenas"
            );
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "MP-3 · los tests fallan con panic por diseño"
)]
mod pruebas_mp3 {
    use super::*;
    use crate::claves::ClaveDev;
    use zx_consensus::transicion::{EntradaUtxo, Origen};
    use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};

    const CBID: u32 = zx_core::CBID_RED_DEV;
    /// MP-3 · par «transacción + testigos» que usan los escenarios de las pruebas.
    type Par = (Tx, Vec<Vec<u8>>);
    /// MP-3 · §3.2–§3.4 · pila de las cascadas pequeñas. Potencia de dos; si la medida 1 diera un
    /// mínimo de una cascada de 1 mayor que 256 KiB, se subiría a la siguiente potencia de dos
    /// mayor o igual que 4× ese mínimo (se declara en el informe).
    const PILA_PEQUENA: usize = MIB;
    /// MP-3 · §3.1 · techo de la bisección de la medida de pila.
    const PILA_MAX_MEDIDA: usize = 128 * MIB;

    fn params() -> ParametrosTransicion {
        crate::perfil::parametros_transicion_dev().expect("perfil dev")
    }

    fn evp() -> ParametrosEvidencia {
        crate::perfil::parametros_evidencia_dev()
    }

    fn ahora() -> Instant {
        Instant::now()
    }

    fn op_id(n: u8) -> OutPoint {
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: 0,
        }
    }

    fn base_pow(utxos: &[(OutPoint, i64, ClavePublica)]) -> Estado {
        let mut e = Estado::inicial();
        e.fase = Fase::PoW;
        e.altura = 1;
        for (op, v, pk) in utxos {
            e.utxo.insert(
                *op,
                EntradaUtxo {
                    valor: Amount::nuevo(*v).unwrap(),
                    lock: Lock::PubKey { pubkey: *pk },
                    origen: Origen::Tx,
                    creada: Punto::Altura(0),
                },
            );
        }
        e
    }

    fn mempool(base: Estado) -> Mempool {
        Mempool::nueva(params(), evp(), CBID, base, Politica::dev())
    }

    fn transferencia_salidas(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        salidas: &[i64],
        destino: ClavePublica,
    ) -> (Tx, Vec<Vec<u8>>) {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: salidas
                .iter()
                .map(|v| TxOut {
                    value: Amount::nuevo(*v).unwrap(),
                    lock: Lock::PubKey { pubkey: destino },
                })
                .collect(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = [SpentOutput {
            value: Amount::nuevo(valor_in).unwrap(),
            lock: Lock::PubKey { pubkey: clave.pk },
        }];
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).unwrap();
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    fn transferencia(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        valor_out: i64,
        destino: ClavePublica,
    ) -> (Tx, Vec<Vec<u8>>) {
        transferencia_salidas(clave, op, valor_in, &[valor_out], destino)
    }

    fn deposito(clave: &ClaveDev, op: OutPoint, valor: i64, nonce: u64) -> (Tx, Vec<Vec<u8>>) {
        crate::pow::construir_deposito(
            op.prev_txid,
            Amount::nuevo(valor).unwrap(),
            clave,
            nonce,
            CBID,
        )
        .expect("depósito")
    }

    // ── §3.1 · medida de pila por nivel ─────────────────────────────────────────────────────

    /// MP-3 · cascada **en cadena** de `n` huérfanas sobre una base con un UTXO para la madre.
    /// Devuelve `(base, madre, H_1..H_n)`; H_i gasta la salida de H_{i-1} (H_1 la de la madre).
    fn cascada_cadena(n: usize) -> (Estado, Par, Vec<Par>) {
        let a = ClaveDev::derivar(51, 0);
        let b = ClaveDev::derivar(51, 1);
        let base = base_pow(&[(op_id(1), 1_000_000, a.pk)]);
        let (madre, wm) = transferencia(&a, op_id(1), 1_000_000, 999_000, b.pk);
        let mut prev = OutPoint {
            prev_txid: txid(&madre, CBID),
            prev_index: 0,
        };
        let mut valor = 999_000i64;
        let mut hs = Vec::with_capacity(n);
        for i in 0..n {
            let (firmante, destino) = if i % 2 == 0 { (&b, a.pk) } else { (&a, b.pk) };
            let out = valor - 1;
            let (tx, w) = transferencia(firmante, prev, valor, out, destino);
            prev = OutPoint {
                prev_txid: txid(&tx, CBID),
                prev_index: 0,
            };
            valor = out;
            hs.push((tx, w));
        }
        (base, (madre, wm), hs)
    }

    /// MP-3 · admite las huérfanas y después la madre (que dispara la resolución).
    fn admitir_cascada(m: &mut Mempool, madre: Par, hs: &[Par], punto: Punto) {
        for (tx, w) in hs {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), punto),
                Ok(Admision::Huerfana),
                "la hija debe esperar"
            );
        }
        assert_eq!(
            m.admitir(None, madre.0, madre.1, ahora(), punto),
            Ok(Admision::Admitida),
            "la madre debe entrar"
        );
    }

    fn en_hilo(pila: usize, f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(pila)
            .spawn(f)
            .expect("crear el hilo de la cascada")
            .join()
            .expect("la cascada no debe desbordar la pila");
    }

    fn correr_cascada_medida(n: usize, pila: usize) {
        let (base, madre, hs) = cascada_cadena(n);
        en_hilo(pila, move || {
            let mut m = mempool(base);
            admitir_cascada(&mut m, madre, &hs, Punto::Altura(1));
            assert_eq!(m.estadisticas().n, 1 + n, "n={n}: no entraron todas");
            assert_eq!(m.estadisticas().huerfanas, 0, "n={n}: quedaron huérfanas");
        });
    }

    fn probar_hijo(exe: &std::path::Path, n: usize, pila: usize) -> bool {
        std::process::Command::new(exe)
            .arg("mempool::pruebas_mp3::mp3_medida_pila_por_nivel")
            .arg("--exact")
            .arg("--ignored")
            .env("MP3_ESCALON", n.to_string())
            .env("MP3_PILA", pila.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("hijo de la medida")
            .success()
    }

    /// MP-3 · §3.1 · medida de pila por nivel. Sin `MP3_PILA`, el padre bisecciona el mínimo con el
    /// que cada cascada (1, 10, 100 y `h_max`) termina, lanzando hijos de sí mismo (un desborde
    /// aborta el proceso y hay que aislarlo). Con `MP3_PILA`, el hijo corre una sola cascada.
    #[test]
    #[ignore = "MP-3 · medida de pila; se ejecuta a mano, en dev y en release"]
    fn mp3_medida_pila_por_nivel() {
        if let Some(pila) = std::env::var_os("MP3_PILA") {
            let n: usize = std::env::var("MP3_ESCALON")
                .expect("MP3_ESCALON")
                .parse()
                .expect("número de escalón");
            let pila: usize = pila.to_string_lossy().parse().expect("bytes de pila");
            correr_cascada_medida(n, pila);
            return;
        }
        let exe = std::env::current_exe().expect("binario de pruebas");
        let perfil = if cfg!(debug_assertions) {
            "dev"
        } else {
            "release"
        };
        for n in [1usize, 10, 100, Politica::dev().h_max] {
            let mut lo = 16 * 1024;
            if probar_hijo(&exe, n, lo) {
                println!("MP3MEDIDA perfil={perfil} n={n} pila_min={lo} (bajo la resolución)");
                continue;
            }
            let mut hi = 64 * 1024;
            while !probar_hijo(&exe, n, hi) {
                hi *= 2;
                assert!(
                    hi <= PILA_MAX_MEDIDA,
                    "n={n}: no termina ni con {PILA_MAX_MEDIDA} bytes"
                );
            }
            while hi - lo > 4096 {
                let mid = ((lo + hi) >> 1) & !0xFFF_usize;
                if mid <= lo {
                    break;
                }
                if probar_hijo(&exe, n, mid) {
                    hi = mid;
                } else {
                    lo = mid;
                }
            }
            println!("MP3MEDIDA perfil={perfil} n={n} pila_min={hi}");
        }
    }

    // ── §3.2/§3.3 · cascadas de h_max con pila pequeña ──────────────────────────────────────

    /// MP-3 · abanico de `n` huérfanas: una madre con `n` salidas, una por hija.
    fn cascada_abanico(n: usize) -> (Estado, Par, Vec<Par>) {
        let a = ClaveDev::derivar(52, 0);
        let b = ClaveDev::derivar(52, 1);
        let base = base_pow(&[(op_id(1), 1_000_000, a.pk)]);
        let salidas = vec![1_000i64; n];
        let (madre, wm) = transferencia_salidas(&a, op_id(1), 1_000_000, &salidas, b.pk);
        let madre_id = txid(&madre, CBID);
        let mut hs = Vec::with_capacity(n);
        for j in 0..n {
            let op = OutPoint {
                prev_txid: madre_id,
                prev_index: u32::try_from(j).unwrap(),
            };
            let (tx, w) = transferencia(&b, op, 1_000, 999, a.pk);
            hs.push((tx, w));
        }
        (base, (madre, wm), hs)
    }

    #[test]
    fn mp3_cascada_en_cadena_de_h_max_con_pila_pequena() {
        let h_max = Politica::dev().h_max;
        let (base, madre, hs) = cascada_cadena(h_max);
        en_hilo(PILA_PEQUENA, move || {
            let mut m = mempool(base);
            admitir_cascada(&mut m, madre, &hs, Punto::Altura(1));
            assert_eq!(m.estadisticas().n, 1 + h_max);
            assert_eq!(m.estadisticas().huerfanas, 0, "depósito vacío");
        });
    }

    #[test]
    fn mp3_cascada_en_abanico_de_h_max_con_pila_pequena() {
        let h_max = Politica::dev().h_max;
        let (base, madre, hs) = cascada_abanico(h_max);
        en_hilo(PILA_PEQUENA, move || {
            let mut m = mempool(base);
            admitir_cascada(&mut m, madre, &hs, Punto::Altura(1));
            assert_eq!(m.estadisticas().n, 1 + h_max);
            assert_eq!(m.estadisticas().huerfanas, 0, "depósito vacío");
        });
    }

    #[test]
    fn mp3_cascada_al_cambiar_la_punta() {
        let h_max = Politica::dev().h_max;
        let (base, madre, hs) = cascada_cadena(h_max);
        let b = ClaveDev::derivar(51, 1);
        let madre_id = txid(&madre.0, CBID);
        // La madre llega dentro de un bloque: se construye la base nueva con su salida aplicada.
        let mut base1 = base.clone();
        base1.utxo.remove(&op_id(1));
        base1.utxo.insert(
            OutPoint {
                prev_txid: madre_id,
                prev_index: 0,
            },
            EntradaUtxo {
                valor: Amount::nuevo(999_000).unwrap(),
                lock: Lock::PubKey { pubkey: b.pk },
                origen: Origen::Tx,
                creada: Punto::Altura(1),
            },
        );
        base1.altura = 2;
        en_hilo(PILA_PEQUENA, move || {
            let mut m = mempool(base);
            for (tx, w) in &hs {
                assert_eq!(
                    m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Altura(1)),
                    Ok(Admision::Huerfana)
                );
            }
            assert_eq!(m.estadisticas().huerfanas, h_max);
            m.rebasear(base1, ahora(), Punto::Altura(2));
            assert_eq!(
                m.estadisticas().huerfanas,
                0,
                "la cascada se resuelve tras el rebase"
            );
            assert_eq!(m.estadisticas().n, h_max);
        });
    }

    // ── §3.5 · mismo resultado que la recursión ─────────────────────────────────────────────

    /// MP-3 · mezcla de `k` huérfanas válidas en cadena más casos que deben descartarse: doble
    /// gasto entre hermanas, tarifa insuficiente y cuota de clave agotada. Devuelve
    /// `(base, huérfanas, depósito_que_agota_la_cuota, madre)`.
    fn escenario_mezcla(k: usize) -> (Estado, Vec<Par>, Par, Par) {
        let a = ClaveDev::derivar(53, 0);
        let b = ClaveDev::derivar(53, 1);
        let base = base_pow(&[(op_id(1), 1_000_000, a.pk), (op_id(2), 1_000, a.pk)]);
        // Salidas de la madre, todas a `a` (que firma a sus hijas); `construir_deposito` gasta el
        // índice 0, así que la cuota va ahí.
        let salidas = [10_000i64, 500_000, 10_000, 10_000];
        let (madre, wm) = transferencia_salidas(&a, op_id(1), 1_000_000, &salidas, a.pk);
        let madre_id = txid(&madre, CBID);
        let op_cuota = OutPoint {
            prev_txid: madre_id,
            prev_index: 0,
        };
        let op_cadena = OutPoint {
            prev_txid: madre_id,
            prev_index: 1,
        };
        let op_doble = OutPoint {
            prev_txid: madre_id,
            prev_index: 2,
        };
        let op_tarifa = OutPoint {
            prev_txid: madre_id,
            prev_index: 3,
        };
        let mut hs: Vec<(Tx, Vec<Vec<u8>>)> = Vec::new();
        let mut prev = op_cadena;
        let mut valor = 500_000i64;
        for i in 0..k {
            let (firmante, destino) = if i % 2 == 0 { (&a, b.pk) } else { (&b, a.pk) };
            let out = valor - 200;
            let (tx, w) = transferencia(firmante, prev, valor, out, destino);
            prev = OutPoint {
                prev_txid: txid(&tx, CBID),
                prev_index: 0,
            };
            valor = out;
            hs.push((tx, w));
        }
        let (s1, w1) = transferencia(&a, op_doble, 10_000, 9_500, b.pk);
        let (s2, w2) = transferencia(&a, op_doble, 10_000, 9_400, b.pk);
        hs.push((s1, w1));
        hs.push((s2, w2));
        let (tf, wf) = transferencia(&a, op_tarifa, 10_000, 10_000, b.pk);
        hs.push((tf, wf));
        let (dep_h, wdep) = deposito(&a, op_cuota, 10_000, 7);
        hs.push((dep_h, wdep));
        let (d1, wd1) = deposito(&a, op_id(2), 1_000, 0);
        (base, hs, (d1, wd1), (madre, wm))
    }

    /// MP-3 · admite las huérfanas y el depósito que ocupa la cuota; deja la madre para el final.
    fn preparar(m: &mut Mempool, hs: &[Par], d1: &Par) {
        for (tx, w) in hs {
            assert_eq!(
                m.admitir(None, tx.clone(), w.clone(), ahora(), Punto::Altura(1)),
                Ok(Admision::Huerfana)
            );
        }
        assert_eq!(
            m.admitir(None, d1.0.clone(), d1.1.clone(), ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
    }

    /// MP-3 · §3.5 · la recursión de hoy copiada como función local: una pasada sobre el depósito
    /// y, tras cada admisión con éxito, una resolución anidada. Es el patrón que `resolver_huerfanas`
    /// tenía antes de MP-3; sirve de referencia para el contraste.
    fn resolver_recursivo_ref(m: &mut Mempool, ahora: Instant, punto: Punto) {
        let ids: Vec<TxId> = m.huerfanas.keys().copied().collect();
        for id in ids {
            let Some(e) = m.huerfanas.get(&id).cloned() else {
                continue;
            };
            let conocidas =
                e.tx.inputs
                    .iter()
                    .all(|i| m.valor_de(&i.outpoint).is_some());
            if !conocidas {
                continue;
            }
            m.huerfanas.remove(&id);
            m.bytes_huerfanas = m.bytes_huerfanas.saturating_sub(e.peso as usize);
            let admitida = matches!(
                m.admitir_con(e.peer, e.tx, e.testigos, ahora, punto, false),
                Ok(Admision::Admitida)
            );
            if admitida {
                resolver_recursivo_ref(m, ahora, punto);
            }
        }
    }

    #[test]
    fn mp3_mismo_resultado_que_la_recursion() {
        for k in 2..=12usize {
            let (base, hs, d1, madre) = escenario_mezcla(k);
            // Implementación nueva (el bucle de `resolver_huerfanas`).
            let mut a = mempool(base.clone());
            a.politica.phi_min = 1;
            preparar(&mut a, &hs, &d1);
            assert_eq!(
                a.admitir(
                    None,
                    madre.0.clone(),
                    madre.1.clone(),
                    ahora(),
                    Punto::Altura(1)
                ),
                Ok(Admision::Admitida),
                "k={k}: la madre entra"
            );
            // Referencia: la recursión de hoy.
            let mut b = mempool(base);
            b.politica.phi_min = 1;
            preparar(&mut b, &hs, &d1);
            assert_eq!(
                b.admitir_con(None, madre.0, madre.1, ahora(), Punto::Altura(1), false),
                Ok(Admision::Admitida),
                "k={k}: la madre entra (referencia)"
            );
            resolver_recursivo_ref(&mut b, ahora(), Punto::Altura(1));
            assert_eq!(a.orden, b.orden, "k={k}: orden de admisión");
            assert_eq!(
                a.entradas.keys().copied().collect::<Vec<_>>(),
                b.entradas.keys().copied().collect::<Vec<_>>(),
                "k={k}: admitidas"
            );
            assert_eq!(
                a.huerfanas.keys().copied().collect::<Vec<_>>(),
                b.huerfanas.keys().copied().collect::<Vec<_>>(),
                "k={k}: huérfanas restantes"
            );
            assert_eq!(a.bytes_totales, b.bytes_totales, "k={k}: bytes");
            assert_eq!(
                a.bytes_huerfanas, b.bytes_huerfanas,
                "k={k}: bytes huérfanas"
            );
            assert_eq!(a.rechazos_limite, b.rechazos_limite, "k={k}: rechazos");
            assert_eq!(a.minimo_rodante, b.minimo_rodante, "k={k}: mínimo rodante");
            assert_eq!(a.gastados, b.gastados, "k={k}: gastados");
            assert_eq!(a.creados, b.creados, "k={k}: creados");
            assert_eq!(a.por_clave, b.por_clave, "k={k}: por clave");
            assert_eq!(a.por_incidente, b.por_incidente, "k={k}: por incidente");
            assert_eq!(a.vista, b.vista, "k={k}: vista virtual");
            // La hermana perdedora del doble gasto no se descarta: al gastar la ganadora su salida,
            // deja de tener todas las entradas conocidas y el depósito ya no la reintenta. Queda una
            // huérfana, idéntica en las dos implementaciones (la aserción de arriba ya lo comparó).
            assert_eq!(
                a.estadisticas().huerfanas,
                1,
                "k={k}: solo la hermana perdedora sigue en el depósito"
            );
            assert_eq!(
                a.estadisticas().n,
                k + 3,
                "k={k}: madre + depósito + cadena + una hermana"
            );
        }
    }

    // ── §3.6 · la que no valida se descarta y no vuelve ─────────────────────────────────────

    #[test]
    fn mp3_huerfana_que_no_valida_se_descarta_y_no_vuelve() {
        // La huérfana se vuelve resoluble (todas sus entradas están) pero no valida: tarifa
        // insuficiente. La resolución la saca del depósito, la intenta y la descarta; no se
        // reencola.
        let a = ClaveDev::derivar(54, 0);
        let b = ClaveDev::derivar(54, 1);
        let base = base_pow(&[(op_id(1), 1_000_000, a.pk)]);
        let (madre, wm) = transferencia(&a, op_id(1), 1_000_000, 999_000, b.pk);
        let op = OutPoint {
            prev_txid: txid(&madre, CBID),
            prev_index: 0,
        };
        // Sin tarifa: con `phi_min = 1` queda por debajo del mínimo en cuanto se resuelve.
        let (h, wh) = transferencia(&b, op, 999_000, 999_000, a.pk);
        let mut m = mempool(base);
        m.politica.phi_min = 1;
        assert_eq!(
            m.admitir(None, h, wh, ahora(), Punto::Altura(1)),
            Ok(Admision::Huerfana),
            "espera: su entrada todavía no está"
        );
        assert_eq!(m.estadisticas().huerfanas, 1);
        assert_eq!(
            m.admitir(None, madre, wm, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        let est = m.estadisticas();
        assert_eq!(est.huerfanas, 0, "la huérfana que no valida se descarta");
        assert_eq!(est.n, 1, "solo la madre");
        assert_eq!(m.rechazos_limite().tarifa_minima, 1);
        // No vuelve: otra resolución no la resucita.
        m.resolver_huerfanas(ahora(), Punto::Altura(1));
        assert_eq!(m.estadisticas().huerfanas, 0);
        assert_eq!(m.estadisticas().n, 1);
    }
}

/// MP-4 · pruebas de IPA B-77: la huérfana recuerda su par, al resolverse cuenta para él y el
/// depósito es justo entre pares. Módulo propio para no tocar los `mod` de pruebas anteriores.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "MP-4 · los tests fallan con panic por diseño"
)]
mod pruebas_mp4 {
    use super::*;
    use crate::claves::ClaveDev;
    use zx_consensus::transicion::{EntradaUtxo, Origen};
    use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};

    const CBID: u32 = zx_core::CBID_RED_DEV;
    /// MP-4 · par «transacción + testigos» que usan los escenarios de las pruebas.
    type Par = (Tx, Vec<Vec<u8>>);

    fn params() -> ParametrosTransicion {
        crate::perfil::parametros_transicion_dev().expect("perfil dev")
    }

    fn evp() -> ParametrosEvidencia {
        crate::perfil::parametros_evidencia_dev()
    }

    fn ahora() -> Instant {
        Instant::now()
    }

    fn op_id(n: u8) -> OutPoint {
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: 0,
        }
    }

    /// MP-4 · salida que **no** está en la base: la tx que la gasta nace huérfana.
    fn op_ausente(semilla: u32) -> OutPoint {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&semilla.to_le_bytes());
        bytes[31] = 0xA5;
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes(bytes)),
            prev_index: 0,
        }
    }

    fn base_pow(utxos: &[(OutPoint, i64, ClavePublica)]) -> Estado {
        let mut e = Estado::inicial();
        e.fase = Fase::PoW;
        e.altura = 1;
        for (op, v, pk) in utxos {
            e.utxo.insert(
                *op,
                EntradaUtxo {
                    valor: Amount::nuevo(*v).unwrap(),
                    lock: Lock::PubKey { pubkey: *pk },
                    origen: Origen::Tx,
                    creada: Punto::Altura(0),
                },
            );
        }
        e
    }

    fn mempool(base: Estado) -> Mempool {
        Mempool::nueva(params(), evp(), CBID, base, Politica::dev())
    }

    fn peso_de(tx: &Tx, testigos: &[Vec<u8>]) -> u64 {
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
        buf.len() as u64
    }

    fn transferencia_salidas(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        salidas: &[i64],
        destino: ClavePublica,
    ) -> Par {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: salidas
                .iter()
                .map(|v| TxOut {
                    value: Amount::nuevo(*v).unwrap(),
                    lock: Lock::PubKey { pubkey: destino },
                })
                .collect(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = [SpentOutput {
            value: Amount::nuevo(valor_in).unwrap(),
            lock: Lock::PubKey { pubkey: clave.pk },
        }];
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).unwrap();
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    fn transferencia(
        clave: &ClaveDev,
        op: OutPoint,
        valor_in: i64,
        valor_out: i64,
        destino: ClavePublica,
    ) -> Par {
        transferencia_salidas(clave, op, valor_in, &[valor_out], destino)
    }

    /// MP-4 · huérfana independiente: gasta una salida ausente y paga a su propio firmante.
    fn huerfana(clave: &ClaveDev, semilla: u32) -> Par {
        assert!(
            op_ausente(semilla) != op_id(1) && op_ausente(semilla) != op_id(2),
            "la salida ausente no debe chocar con la base"
        );
        transferencia(clave, op_ausente(semilla), 1_000, 999, clave.pk)
    }

    /// MP-4 · admite una huérfana y devuelve su `txid`.
    fn admitir_huerfana(m: &mut Mempool, peer: Option<PeerId>, par: &Par, punto: Punto) -> TxId {
        assert_eq!(
            m.admitir(peer, par.0.clone(), par.1.clone(), ahora(), punto),
            Ok(Admision::Huerfana),
            "la tx debe quedar huérfana"
        );
        txid(&par.0, CBID)
    }

    /// MP-4 · §3.1 · una huérfana resuelta cuenta en el tope `S_par` de su par. Un par llena su
    /// tope y manda hijas antes que la madre: solo la que cabe entra; el resto se rechaza por
    /// `par_memoria`, como una recién llegada. Con el código de la base (huérfana sin par) entran
    /// todas.
    #[test]
    fn mp4_huerfana_resuelta_cuenta_en_el_tope_de_su_par() {
        const N: usize = 8;
        let a = ClaveDev::derivar(60, 0);
        let b = ClaveDev::derivar(60, 1);
        let base = base_pow(&[(op_id(1), 10_000_000, a.pk), (op_id(2), 1_000_000, b.pk)]);
        let p = PeerId::random();
        // t0: una tx normal del par que ya ocupa bytes en la mempool.
        let t0 = transferencia(&b, op_id(2), 1_000_000, 999_000, a.pk);
        // Madre con `N` salidas (una por hija) y sus `N` hijas.
        let salidas = [1_000i64; N];
        let (madre, wm) = transferencia_salidas(&a, op_id(1), 10_000_000, &salidas, b.pk);
        let madre_id = txid(&madre, CBID);
        let mut hijas: Vec<Par> = Vec::with_capacity(N);
        for j in 0..N {
            let op = OutPoint {
                prev_txid: madre_id,
                prev_index: u32::try_from(j).unwrap(),
            };
            hijas.push(transferencia(&b, op, 1_000, 999, a.pk));
        }
        let primera = hijas.first().expect("hay N >= 1 hijas");
        let peso_hija = peso_de(&primera.0, &primera.1) as usize;
        let peso_madre = peso_de(&madre, &wm) as usize;
        let mut m = mempool(base);
        assert_eq!(
            m.admitir(Some(p), t0.0, t0.1, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        // `S_par` deja sitio para exactamente una hija más (t0 + madre + 1 hija).
        let usados_t0 = m.bytes_por_par.get(&p).copied().unwrap_or(0);
        m.politica.s_par = usados_t0 + peso_madre + peso_hija;
        println!(
            "MP4-CIFRA s_par={} t0={} madre={} hija={} N={N}",
            m.politica.s_par, usados_t0, peso_madre, peso_hija
        );
        // Las hijas llegan antes que la madre: van al depósito recordando su par.
        for h in &hijas {
            admitir_huerfana(&mut m, Some(p), h, Punto::Altura(1));
        }
        assert_eq!(m.estadisticas().huerfanas, N);
        assert_eq!(
            m.admitir(Some(p), madre, wm, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        // Solo una hija cabe en el tope de su par; las demás se rechazan por `par_memoria`.
        assert_eq!(
            m.estadisticas().huerfanas,
            0,
            "la resolución vacía el depósito"
        );
        assert_eq!(m.estadisticas().n, 3, "t0 + madre + 1 hija");
        assert_eq!(m.rechazos_limite().par_memoria, (N - 1) as u64);
        println!(
            "MP4-CIFRA-fix n={} par_memoria={} bytes_par_p={}",
            m.estadisticas().n,
            m.rechazos_limite().par_memoria,
            m.bytes_por_par.get(&p).copied().unwrap_or(0)
        );
    }

    /// MP-4 · §3.2 · la tasa `R_par` se cuenta **una sola vez**, al llegar la huérfana; la
    /// resolución no la vuelve a contar. `R_par` es exactamente el peso de la hija, así que un
    /// segundo consumo la rechazaría.
    #[test]
    fn mp4_huerfana_resuelta_no_cuenta_dos_veces_en_la_tasa() {
        let a = ClaveDev::derivar(61, 0);
        let b = ClaveDev::derivar(61, 1);
        let base = base_pow(&[(op_id(1), 1_000_000, a.pk)]);
        let p = PeerId::random();
        let (madre, wm) = transferencia(&a, op_id(1), 1_000_000, 999_000, b.pk);
        let madre_id = txid(&madre, CBID);
        let op_hija = OutPoint {
            prev_txid: madre_id,
            prev_index: 0,
        };
        let hija = transferencia(&b, op_hija, 999_000, 998_000, a.pk);
        let peso_hija = peso_de(&hija.0, &hija.1) as usize;
        let mut m = mempool(base);
        m.politica.r_par = peso_hija;
        admitir_huerfana(&mut m, Some(p), &hija, Punto::Altura(1));
        // La tasa se consumió al llegar.
        assert_eq!(m.tasa_por_par.get(&p).map(|(_, w)| *w), Some(peso_hija));
        // La madre es propia del nodo: no toca la tasa del par.
        assert_eq!(
            m.admitir(None, madre, wm, ahora(), Punto::Altura(1)),
            Ok(Admision::Admitida)
        );
        // La hija se resuelve con su par y no vuelve a contar la tasa.
        assert_eq!(m.estadisticas().huerfanas, 0);
        assert_eq!(m.estadisticas().n, 2, "madre + hija");
        assert_eq!(
            m.tasa_por_par.get(&p).map(|(_, w)| *w),
            Some(peso_hija),
            "la tasa no se cuenta dos veces"
        );
        assert_eq!(m.rechazos_limite().par_tasa, 0);
    }

    /// MP-4 · §3.3 · un par no desaloja las huérfanas de otro: A manda `h_max + 50` huérfanas y
    /// las 3 de B, más antiguas, siguen en el depósito. Con el desalojo de la base (la más antigua
    /// de todas) caerían primero las de B.
    #[test]
    fn mp4_un_par_no_desaloja_las_huerfanas_de_otro() {
        let h_max = Politica::dev().h_max;
        let a = ClaveDev::derivar(62, 0);
        let b = ClaveDev::derivar(62, 1);
        let pa = PeerId::random();
        let pb = PeerId::random();
        let mut m = mempool(base_pow(&[]));
        let mut de_b: Vec<TxId> = Vec::new();
        for i in 0..3u32 {
            let h = huerfana(&b, 10_000 + i);
            de_b.push(admitir_huerfana(&mut m, Some(pb), &h, Punto::Altura(1 + i)));
        }
        for i in 0..(h_max + 50) {
            let h = huerfana(&a, i as u32);
            admitir_huerfana(&mut m, Some(pa), &h, Punto::Altura(100 + i as u32));
        }
        assert_eq!(m.estadisticas().huerfanas, h_max, "el depósito queda lleno");
        for id in &de_b {
            assert!(
                m.huerfanas.contains_key(id),
                "la huérfana {id:?} del par B no debe desalojarse"
            );
        }
    }

    /// MP-4 · §3.4 · con el depósito lleno se desaloja la más antigua del par que más bytes ocupa.
    #[test]
    fn mp4_deposito_lleno_desaloja_la_mas_antigua_del_que_mas_ocupa() {
        let a = ClaveDev::derivar(63, 0);
        let px = PeerId::random();
        let py = PeerId::random();
        let pz = PeerId::random();
        let mut m = mempool(base_pow(&[]));
        m.politica.h_max = 4;
        let x1 = admitir_huerfana(&mut m, Some(px), &huerfana(&a, 20_000), Punto::Altura(1));
        let x2 = admitir_huerfana(&mut m, Some(px), &huerfana(&a, 20_001), Punto::Altura(2));
        let x3 = admitir_huerfana(&mut m, Some(px), &huerfana(&a, 20_002), Punto::Altura(3));
        let y1 = admitir_huerfana(&mut m, Some(py), &huerfana(&a, 20_100), Punto::Altura(4));
        assert_eq!(m.estadisticas().huerfanas, 4);
        // Z llega con el depósito lleno: X, que más bytes ocupa, pierde su más antigua.
        let z1 = admitir_huerfana(&mut m, Some(pz), &huerfana(&a, 20_200), Punto::Altura(5));
        assert!(!m.huerfanas.contains_key(&x1), "X pierde su más antigua");
        assert!(m.huerfanas.contains_key(&x2));
        assert!(m.huerfanas.contains_key(&x3));
        assert!(m.huerfanas.contains_key(&y1));
        assert!(m.huerfanas.contains_key(&z1));
        assert_eq!(m.estadisticas().huerfanas, 4);
    }

    /// MP-4 · §3.4 · en empate de bytes se desaloja al par de identificador menor.
    #[test]
    fn mp4_empate_desaloja_al_par_menor() {
        let a = ClaveDev::derivar(64, 0);
        let (p1, p2) = (PeerId::random(), PeerId::random());
        let (menor, mayor) = if p1 < p2 { (p1, p2) } else { (p2, p1) };
        let pz = PeerId::random();
        let mut m = mempool(base_pow(&[]));
        m.politica.h_max = 4;
        let menor_1 =
            admitir_huerfana(&mut m, Some(menor), &huerfana(&a, 30_000), Punto::Altura(1));
        admitir_huerfana(&mut m, Some(menor), &huerfana(&a, 30_001), Punto::Altura(2));
        let mayor_1 =
            admitir_huerfana(&mut m, Some(mayor), &huerfana(&a, 30_002), Punto::Altura(3));
        let mayor_2 =
            admitir_huerfana(&mut m, Some(mayor), &huerfana(&a, 30_003), Punto::Altura(4));
        assert_eq!(m.estadisticas().huerfanas, 4);
        let z1 = admitir_huerfana(&mut m, Some(pz), &huerfana(&a, 30_100), Punto::Altura(5));
        assert!(
            !m.huerfanas.contains_key(&menor_1),
            "en empate se desaloja al par menor"
        );
        assert!(m.huerfanas.contains_key(&mayor_1));
        assert!(m.huerfanas.contains_key(&mayor_2));
        assert!(m.huerfanas.contains_key(&z1));
        assert_eq!(m.estadisticas().huerfanas, 4);
    }

    /// MP-4 · §3.5 · una huérfana propia del nodo (`peer == None`) sigue sin par; una ajena lo
    /// conserva.
    #[test]
    fn mp4_huerfana_propia_del_nodo_sigue_sin_par() {
        let a = ClaveDev::derivar(65, 0);
        let p = PeerId::random();
        let mut m = mempool(base_pow(&[]));
        let id_propia = admitir_huerfana(&mut m, None, &huerfana(&a, 40_000), Punto::Altura(1));
        let id_ajena = admitir_huerfana(&mut m, Some(p), &huerfana(&a, 40_001), Punto::Altura(2));
        assert_eq!(m.huerfanas.get(&id_propia).expect("propia").peer, None);
        assert_eq!(m.huerfanas.get(&id_ajena).expect("ajena").peer, Some(p));
    }

    /// MP-4 · §3.6 · la instantánea de desalojo **no** incluye las huérfanas
    /// (`InstantaneaMempool`, `crates/zx-node/src/mempool.rs:258-269`); por eso restaurarla no
    /// pierde el depósito ni el par que guarda. La orden autoriza sustituir la prueba por una que
    /// afirme ese hecho cuando la instantánea no las incluye.
    #[test]
    fn mp4_instantanea_y_restauracion_conservan_el_par_de_las_huerfanas() {
        let a = ClaveDev::derivar(66, 0);
        let p = PeerId::random();
        let mut m = mempool(base_pow(&[]));
        let id = admitir_huerfana(&mut m, Some(p), &huerfana(&a, 50_000), Punto::Altura(1));
        // Instantánea de desalojo: no copia el depósito de huérfanas.
        let instantanea = m.instantanea();
        // Se muta el depósito después de la instantánea: una segunda huérfana del mismo par.
        let id_otra = admitir_huerfana(&mut m, Some(p), &huerfana(&a, 50_001), Punto::Altura(2));
        assert_eq!(m.estadisticas().huerfanas, 2);
        m.restaurar(instantanea);
        // No se restauran (no estaban en la instantánea): siguen las dos, con su par intacto.
        assert!(m.huerfanas.contains_key(&id));
        assert!(m.huerfanas.contains_key(&id_otra));
        assert_eq!(m.huerfanas.get(&id).expect("h").peer, Some(p));
        assert_eq!(m.huerfanas.get(&id_otra).expect("otra").peer, Some(p));
        assert_eq!(m.estadisticas().huerfanas, 2);
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "caracterización CAR-COLA: fallos e índices del fixture provocan panic"
)]
mod pruebas_carcola {
    use super::*;
    use crate::claves::ClaveDev;
    use zx_cadena::{BloqueCadena, BloquePost, Cadena};
    use zx_consensus::transicion::{EnRetirada, EntradaUtxo, Garantia, Origen, TxDescartada};
    use zx_core::{Amount, HashType, Lock, SpentOutput, TxIn, TxOut};
    use zx_dag::ghostdag::IdentidadGhostdag;
    use zx_dag::identidad::IdentidadTicket;

    const CBID: u32 = zx_core::CBID_RED_DEV;
    const SLOT_BASE: u64 = 2_024;
    const SLOT_TX: u64 = SLOT_BASE + 1;
    const IMPORTE_LIB: i64 = 5_000;
    const IMPORTE_DEP: i64 = 99_999;
    const SEMILLAS: u64 = 128;
    type Par = (Tx, Vec<Vec<u8>>);

    fn importe(n: i64) -> Amount {
        Amount::nuevo(n).expect("importe del fixture")
    }

    fn params() -> ParametrosTransicion {
        let mut p = crate::perfil::parametros_transicion_dev().expect("perfil dev");
        // Solo abrevia la creación del terminal. Se conservan q, madureces, retenciones,
        // tarifas, tamaños y los parámetros de evidencia del perfil dev.
        p.h_corte_min = 1;
        p.w_min = U256::one();
        p.s_min = Amount::CERO;
        p.k_min = 0;
        p
    }

    fn evp() -> ParametrosEvidencia {
        crate::perfil::parametros_evidencia_dev()
    }

    fn hash(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn op(n: u8) -> OutPoint {
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: 0,
        }
    }

    fn salida(tx: &Tx) -> OutPoint {
        OutPoint {
            prev_txid: txid(tx, CBID),
            prev_index: 0,
        }
    }

    fn post(
        padre: BlockHash,
        id: u8,
        slot: u64,
        productor: ClavePublica,
        txs: Vec<Par>,
    ) -> BloqueCadena {
        BloqueCadena::Post(BloquePost {
            hash: hash(id),
            padres: vec![padre],
            slot,
            timestamp: 0,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
            sr: 1,
            distancia: 0,
            identidad: IdentidadGhostdag::Billete(IdentidadTicket::vigente(
                productor, 0, 1, [id; 32], slot,
            )),
            txs,
        })
    }

    struct Escenario {
        cadena: Cadena,
        base: Estado,
        clave: ClaveDev,
        productor: ClaveDev,
    }

    impl Escenario {
        fn nuevo() -> Self {
            let a = ClaveDev::derivar(929_395, 0);
            let b = ClaveDev::derivar(929_395, 1);
            let (clave, productor) = if a.pk < b.pk { (a, b) } else { (b, a) };
            let p = params();
            let mut inicial = Estado::inicial();
            for pk in [clave.pk, productor.pk] {
                let mut g = Garantia::nueva();
                g.activo = p.q;
                inicial.garantias.insert(pk, g);
            }
            inicial
                .garantias
                .get_mut(&clave.pk)
                .expect("garantía")
                .en_retirada
                .push(EnRetirada {
                    importe: importe(IMPORTE_LIB),
                    inicio_slot: 0,
                });
            inicial.ultimo_slot_producido.insert(clave.pk, 0);
            for n in 10..13 {
                inicial.utxo.insert(
                    op(n),
                    EntradaUtxo {
                        valor: importe(100_000),
                        lock: Lock::PubKey { pubkey: clave.pk },
                        origen: Origen::Tx,
                        creada: Punto::Altura(0),
                    },
                );
            }
            inicial.emitido = 2 * i128::from(p.q.brek()) + 300_000 + i128::from(IMPORTE_LIB);
            let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
                p,
                crate::perfil::ghostdag_k(),
                CBID,
                crate::perfil::ghostdag_max_padres(),
                evp(),
                inicial,
            );
            cadena
                .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                    HechosCabecera::Genesis { hash: hash(0) },
                    Vec::new(),
                )))
                .expect("génesis real");
            cadena
                .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                    HechosCabecera::PoW {
                        hash: hash(1),
                        padre: hash(0),
                        altura: 1,
                        trabajo: U256::one(),
                        pow_valido: true,
                    },
                    Vec::new(),
                )))
                .expect("terminal real");
            assert_eq!(cadena.terminal(), Some(hash(1)));
            cadena
                .admitir(post(hash(1), 2, SLOT_BASE, productor.pk, Vec::new()))
                .expect("punta PoST real");
            let base = cadena.estado_virtual().expect("estado virtual real");
            assert_eq!(base.slot, SLOT_BASE);
            assert!(!base.garantias.contains_key(&productor_sintetico(&base)));
            assert_eq!(base.ultimo_slot_producido.get(&clave.pk), Some(&0));
            assert!(base.activo_de(&productor.pk) >= p.q);
            Self {
                cadena,
                base,
                clave,
                productor,
            }
        }

        fn cola(&self) -> Mempool {
            Mempool::nueva(params(), evp(), CBID, self.base.clone(), Politica::dev())
        }

        fn aplicar(&mut self, txs: Vec<Par>) -> (Estado, Vec<TxDescartada>) {
            let bloque = post(hash(2), 3, SLOT_TX, self.productor.pk, txs);
            let (fusion, _, descartadas) = aplicar_fusion(
                &self.base,
                &bloque.como_transicion(),
                Punto::Slot(SLOT_TX),
                &params(),
                CBID,
                &evp(),
            )
            .expect("fusión real");
            self.cadena
                .admitir(bloque)
                .expect("bloque real admitido por Cadena");
            assert!(self.cadena.es_valido(&hash(3)));
            assert_eq!(
                self.cadena.estado_past(&hash(3)),
                Some(&self.base),
                "mismo estado de aplicación"
            );
            let estado = self
                .cadena
                .estado_post(&hash(3))
                .expect("post real")
                .clone();
            assert_eq!(
                self.cadena.descartes(&hash(3)),
                Some(descartadas.as_slice())
            );
            // Cadena suma el peso del bloque de cadena; aplicar_fusion delega ese incremento.
            let mut esperada = fusion;
            esperada.peso_sufijo += 1;
            assert_eq!(estado, esperada);
            (estado, descartadas)
        }
    }

    fn admitir(m: &mut Mempool, par: &Par) {
        assert_eq!(
            m.admitir(
                None,
                par.0.clone(),
                par.1.clone(),
                Instant::now(),
                Punto::Slot(SLOT_BASE)
            ),
            Ok(Admision::Admitida)
        );
    }

    fn transferencia(
        clave: &ClaveDev,
        entrada: OutPoint,
        valor_in: i64,
        valor_out: i64,
        sequence: u32,
    ) -> Par {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: entrada,
                sequence,
            }],
            outputs: vec![TxOut {
                value: importe(valor_out),
                lock: Lock::PubKey { pubkey: clave.pk },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = [SpentOutput {
            value: importe(valor_in),
            lock: Lock::PubKey { pubkey: clave.pk },
        }];
        let digest =
            zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).expect("sighash real");
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    fn par_b92(e: &Escenario, hija_antes: bool) -> (Par, Par) {
        let madre = transferencia(&e.clave, op(10), 100_000, 80_000, 0);
        // Misma madre, base, gasto y valores. Solo cambia sequence (y su firma) para obtener
        // los dos órdenes de identificador. Búsqueda finita; no altera IDs ni inserta sin validar.
        for sequence in 0..256 {
            let hija = transferencia(&e.clave, salida(&madre.0), 80_000, 60_000, sequence);
            let im = txid(&madre.0, CBID);
            let ih = txid(&hija.0, CBID);
            if ih != im && (ih < im) == hija_antes {
                eprintln!(
                    "B92 hija_antes={hija_antes} sequence={sequence} madre={im:?} hija={ih:?}"
                );
                return (madre, hija);
            }
        }
        panic!("no se encontró el orden de txid en 256 candidatas");
    }

    #[test]
    fn car_b92_el_rebase_pierde_a_la_hija_si_su_txid_va_antes() {
        let mut e = Escenario::nuevo();
        let (madre, hija) = par_b92(&e, true);
        let mut m = e.cola();
        admitir(&mut m, &madre);
        admitir(&mut m, &hija);
        assert_eq!(m.estadisticas().n, 2);
        assert!(!m.vista.utxo.contains_key(&salida(&madre.0)));
        assert_eq!(m.vista.utxo[&salida(&hija.0)].valor, importe(60_000));
        assert_eq!(
            m.aplicar_a_vista(&e.base, &hija.0, &hija.1),
            Err(ErrorTransicion::ErrDobleGasto)
        );
        m.rebasear(e.base.clone(), Instant::now(), Punto::Slot(SLOT_BASE));
        assert_eq!(m.estadisticas().n, 2);
        assert!(m.contiene(&txid(&madre.0, CBID)));
        assert!(m.contiene(&txid(&hija.0, CBID)));
        assert_eq!(m.estadisticas().huerfanas, 0);
        assert_eq!(m.orden, vec![txid(&madre.0, CBID), txid(&hija.0, CBID)]);
        assert!(!m.vista.utxo.contains_key(&salida(&madre.0)));
        assert_eq!(m.vista.utxo[&salida(&hija.0)].valor, importe(60_000));
        m.resolver_huerfanas(Instant::now(), Punto::Slot(SLOT_BASE));
        assert!(m.contiene(&txid(&hija.0, CBID)));
        let seleccion = m.seleccionar(params().max_cuerpo_bloque_bytes, 0);
        assert_eq!(seleccion, vec![madre.clone(), hija.clone()]);
        let (estado, descartes) = e.aplicar(seleccion);
        assert!(descartes.is_empty());
        assert_eq!(estado.utxo[&salida(&hija.0)].valor, importe(60_000));
        assert!(!estado.utxo.contains_key(&salida(&madre.0)));
        eprintln!(
            "B92 rebase idéntico: 2->2; huérfanas=0; hija sola=ErrDobleGasto; bloque seleccionado: 2 aplicadas, 0 descartes"
        );
    }

    #[test]
    fn car_b92_si_va_despues_sobreviven_las_dos() {
        let mut e = Escenario::nuevo();
        let (madre, hija) = par_b92(&e, false);
        let mut m = e.cola();
        admitir(&mut m, &madre);
        admitir(&mut m, &hija);
        m.rebasear(e.base.clone(), Instant::now(), Punto::Slot(SLOT_BASE));
        assert_eq!(m.estadisticas().n, 2);
        assert_eq!(m.orden, vec![txid(&madre.0, CBID), txid(&hija.0, CBID)]);
        assert_eq!(m.estadisticas().huerfanas, 0);
        assert_eq!(m.vista.utxo[&salida(&hija.0)].valor, importe(60_000));
        assert!(!m.vista.utxo.contains_key(&salida(&madre.0)));
        let seleccion = m.seleccionar(params().max_cuerpo_bloque_bytes, 0);
        assert_eq!(seleccion, vec![madre, hija.clone()]);
        let (estado, descartes) = e.aplicar(seleccion);
        assert!(descartes.is_empty());
        assert_eq!(estado.utxo[&salida(&hija.0)].valor, importe(60_000));
        eprintln!(
            "B92 control: rebase idéntico 2->2; bloque seleccionado: 2 aplicadas, 0 descartes"
        );
    }

    fn liberacion(e: &Escenario) -> Par {
        let tx = Tx {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Garantia {
                tipo: TipoGarantia::Liberacion,
                clave: e.clave.pk,
                importe: importe(IMPORTE_LIB),
                nonce: 0,
            },
        };
        let firma: [u8; 64] = e
            .clave
            .sk
            .sign(&zx_core::mensaje_aceptacion(&tx, CBID))
            .into();
        (tx, vec![firma.to_vec()])
    }

    #[test]
    fn car_b93_la_cola_rechaza_la_liberacion_de_la_primera_clave_tras_admitir_otra_tx() {
        let e = Escenario::nuevo();
        let lib = liberacion(&e);
        let otra = transferencia(&e.clave, op(12), 100_000, 80_000, 0);
        let mut vacia = e.cola();
        admitir(&mut vacia, &lib);
        assert_eq!(
            vacia.vista.utxo[&salida(&lib.0)].valor,
            importe(IMPORTE_LIB)
        );
        let mut m = e.cola();
        admitir(&mut m, &otra);
        assert_eq!(m.vista.slot, SLOT_BASE);
        assert_eq!(m.vista.ultimo_slot_producido.get(&e.clave.pk), Some(&0));
        assert_eq!(
            m.vista.ultimo_slot_producido.get(&e.productor.pk),
            Some(&SLOT_BASE)
        );
        assert_eq!(m.vista.ultimo_slot_producido, e.base.ultimo_slot_producido);
        assert!(m.aplicar_a_vista(&m.vista, &lib.0, &lib.1).is_ok());
        assert_eq!(
            m.admitir(
                None,
                lib.0.clone(),
                lib.1.clone(),
                Instant::now(),
                Punto::Slot(SLOT_BASE)
            ),
            Ok(Admision::Admitida)
        );
        assert_eq!(m.estadisticas().n, 2);
        assert_eq!(m.estadisticas().huerfanas, 0);
        assert!(m.contiene(&txid(&lib.0, CBID)));
        assert_eq!(m.vista.utxo[&salida(&lib.0)].valor, importe(IMPORTE_LIB));
        assert_eq!(m.vista.garantias[&e.clave.pk].nonce_siguiente, 1);
        assert!(m.vista.garantias[&e.clave.pk].en_retirada.is_empty());
        assert_eq!(m.vista.ultimo_slot_producido, e.base.ultimo_slot_producido);
        eprintln!(
            "B93 cola: última producción real=0, vista.slot=2024; liberación de 5000 admitida, nonce=1; mapa de producción idéntico a la base"
        );
    }

    #[test]
    fn car_b93_un_bloque_real_de_otro_productor_la_aplica() {
        let mut e = Escenario::nuevo();
        let lib = liberacion(&e);
        let otra = transferencia(&e.clave, op(12), 100_000, 80_000, 0);
        let (estado, descartes) = e.aplicar(vec![otra.clone(), lib.clone()]);
        assert!(descartes.is_empty());
        assert_eq!(estado.utxo[&salida(&otra.0)].valor, importe(80_000));
        assert_eq!(estado.utxo[&salida(&lib.0)].valor, importe(IMPORTE_LIB));
        assert_eq!(
            estado.utxo[&salida(&lib.0)].lock,
            Lock::PubKey { pubkey: e.clave.pk }
        );
        assert_eq!(estado.garantias[&e.clave.pk].nonce_siguiente, 1);
        assert!(estado.garantias[&e.clave.pk].en_retirada.is_empty());
        assert_eq!(estado.ultimo_slot_producido.get(&e.clave.pk), Some(&0));
        assert_eq!(
            estado.ultimo_slot_producido.get(&e.productor.pk),
            Some(&SLOT_TX)
        );
        eprintln!(
            "B93 Cadena/fusión: mismo estado/slot/tx; productor distinto elegible; 5000 liberados, nonce=1, 0 descartes, última producción de la clave=0"
        );
    }

    fn deposito(e: &Escenario, entrada: OutPoint, nonce: u64) -> Par {
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                outpoint: entrada,
                sequence: 0,
            }],
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Garantia {
                tipo: TipoGarantia::Deposito,
                clave: e.clave.pk,
                importe: importe(IMPORTE_DEP),
                nonce,
            },
        };
        let testigos =
            crate::pow::testigos_deposito(&tx, importe(100_000), e.clave.pk, &e.clave.sk, CBID)
                .expect("firmas reales del depósito");
        (tx, testigos)
    }

    fn depositos_admitidos(e: &Escenario) -> (Mempool, Par, Par) {
        let d0 = deposito(e, op(10), 0);
        let d1 = deposito(e, op(11), 1);
        let mut m = e.cola();
        assert!(
            m.base.activo_de(&e.clave.pk) >= m.params.q,
            "fuera de la reserva"
        );
        admitir(&mut m, &d0);
        admitir(&mut m, &d1);
        for id in [txid(&d0.0, CBID), txid(&d1.0, CBID)] {
            assert_eq!(
                m.entradas[&id].fee, 1,
                "tarifa positiva evita cuota de tarifa cero"
            );
        }
        assert_eq!(m.estadisticas().n, 2);
        assert_eq!(m.vista.garantias[&e.clave.pk].nonce_siguiente, 2);
        assert!(!m.vista.utxo.contains_key(&op(10)));
        assert!(!m.vista.utxo.contains_key(&op(11)));
        (m, d0, d1)
    }

    fn pendiente(e: &Estado, clave: ClavePublica) -> i64 {
        e.garantias[&clave]
            .pendientes
            .iter()
            .map(|p| p.importe.brek())
            .sum()
    }

    #[test]
    fn car_b95_el_segundo_deposito_sale_antes_o_solo_y_el_bloque_lo_descarta() {
        let mut e = Escenario::nuevo();
        let (m, d0, d1) = depositos_admitidos(&e);
        let id0 = txid(&d0.0, CBID);
        let id1 = txid(&d1.0, CBID);
        let presupuesto_uno = m.entradas[&id0].peso;
        assert_eq!(presupuesto_uno, m.entradas[&id1].peso);
        let mut primero_solo = 0;
        let mut vacias = 0;
        for semilla in 0..SEMILLAS {
            let llena = m.seleccionar(params().max_cuerpo_bloque_bytes, semilla);
            assert_eq!(llena, vec![d0.clone(), d1.clone()], "semilla {semilla}");
            let una = m.seleccionar(presupuesto_uno, semilla);
            assert!(
                una.is_empty() || una == vec![d0.clone()],
                "semilla {semilla}"
            );
            if una.is_empty() {
                vacias += 1;
            } else {
                primero_solo += 1;
            }
        }
        assert!(
            vacias > 0 && primero_solo > 0,
            "se ejercen ambos presupuestos parciales"
        );
        let seleccion = m.seleccionar(params().max_cuerpo_bloque_bytes, 2);
        let (estado, descartes) = e.aplicar(seleccion);
        assert!(descartes.is_empty());
        assert_eq!(estado.garantias[&e.clave.pk].nonce_siguiente, 2);
        assert_eq!(pendiente(&estado, e.clave.pk), 2 * IMPORTE_DEP);
        assert!(!estado.utxo.contains_key(&op(10)));
        assert!(!estado.utxo.contains_key(&op(11)));
        assert_eq!(m.estadisticas().n, 2, "selección no borra de la cola");
        assert!(m.contiene(&id0) && m.contiene(&id1));
        eprintln!(
            "B95 semillas=0..{SEMILLAS}: inversas=0, solo_segundo=0, primero_solo={primero_solo}, vacías={vacias}, bytes_uno={presupuesto_uno}; Cadena/fusión: 2 aplicadas, 0 descartes"
        );
    }

    #[test]
    fn car_b95_en_orden_se_aplican_los_dos() {
        let mut e = Escenario::nuevo();
        let (m, d0, d1) = depositos_admitidos(&e);
        let semilla = (0..SEMILLAS)
            .find(|s| {
                m.seleccionar(params().max_cuerpo_bloque_bytes, *s) == vec![d0.clone(), d1.clone()]
            })
            .expect("una semilla conserva el orden");
        let seleccion = m.seleccionar(params().max_cuerpo_bloque_bytes, semilla);
        let (estado, descartes) = e.aplicar(seleccion);
        assert!(descartes.is_empty());
        assert_eq!(estado.garantias[&e.clave.pk].nonce_siguiente, 2);
        assert_eq!(pendiente(&estado, e.clave.pk), 2 * IMPORTE_DEP);
        assert!(!estado.utxo.contains_key(&op(10)));
        assert!(!estado.utxo.contains_key(&op(11)));
        eprintln!(
            "B95 control semilla={semilla}: 2 depósitos aplicados; pendiente=199998, nonce=2, 0 descartes"
        );
    }

    #[test]
    fn cola1_cadena_de_tres_pagos_sobrevive_a_diez_rebases() {
        let mut e = Escenario::nuevo();
        let (madre, hija) = par_b92(&e, true);
        let nieta = transferencia(&e.clave, salida(&hija.0), 60_000, 40_000, 0);
        let mut m = e.cola();
        for par in [&madre, &hija, &nieta] {
            admitir(&mut m, par);
        }
        let vista = m.vista.clone();
        let orden = m.orden.clone();
        let bytes = m.estadisticas().bytes;
        for vuelta in 0..10 {
            m.rebasear(e.base.clone(), Instant::now(), Punto::Slot(SLOT_BASE));
            m.recomputar_vista();
            assert_eq!(m.orden, orden, "rebase {vuelta}");
            assert_eq!(m.vista, vista, "rebase {vuelta}");
            assert_eq!(m.estadisticas().n, 3);
            assert_eq!(m.estadisticas().bytes, bytes);
            assert_eq!(m.estadisticas().huerfanas, 0);
        }
        let seleccion = m.seleccionar(params().max_cuerpo_bloque_bytes, 2);
        assert_eq!(seleccion, vec![madre.clone(), hija.clone(), nieta.clone()]);
        let (estado, descartes) = e.aplicar(seleccion);
        assert!(descartes.is_empty());
        assert_eq!(estado.utxo[&salida(&nieta.0)].valor, importe(40_000));
        assert!(!estado.utxo.contains_key(&salida(&madre.0)));
        assert!(!estado.utxo.contains_key(&salida(&hija.0)));
        // Control negativo: una base que gastó la entrada de la madre invalida las tres.
        let mut invalida = e.base.clone();
        invalida.utxo.remove(&op(10));
        m.rebasear(invalida, Instant::now(), Punto::Slot(SLOT_BASE));
        assert_eq!(m.estadisticas().n, 0);
        assert_eq!(m.vista, m.base);
        eprintln!(
            "COLA1 cadena: 3 pagos, 10 rebases + recomputaciones, 3 aplicados; base inválida: 0 retenidos"
        );
    }

    #[test]
    fn cola1_si_la_primera_no_cabe_la_segunda_no_sale_y_sigue_en_cola() {
        let mut e = Escenario::nuevo();
        let mut d0 = deposito(&e, op(10), 0);
        if let ExtensionTx::Garantia { importe: valor, .. } = &mut d0.0.extension {
            *valor = importe(90_000);
        }
        d0.0.outputs = vec![
            TxOut {
                value: importe(1_000),
                lock: Lock::PubKey { pubkey: e.clave.pk },
            };
            8
        ];
        d0.1 =
            crate::pow::testigos_deposito(&d0.0, importe(100_000), e.clave.pk, &e.clave.sk, CBID)
                .expect("depósito pesado firmado");
        let d1 = deposito(&e, op(11), 1);
        let mut m = e.cola();
        admitir(&mut m, &d0);
        admitir(&mut m, &d1);
        let id0 = txid(&d0.0, CBID);
        let id1 = txid(&d1.0, CBID);
        let max = m.entradas[&id1].peso;
        assert!(m.entradas[&id0].peso > max);
        let vista = m.vista.clone();
        for semilla in 0..SEMILLAS {
            assert_eq!(m.seleccionar_bruta(max, semilla), vec![d1.clone()]);
            assert!(m.seleccionar(max, semilla).is_empty());
            assert!(m.contiene(&id0) && m.contiene(&id1));
            assert_eq!(m.estadisticas().n, 2);
            assert_eq!(m.vista, vista);
        }
        let (base1, descartes) = e.aplicar(vec![d0]);
        assert!(descartes.is_empty());
        m.rebasear(base1, Instant::now(), Punto::Slot(SLOT_TX));
        m.confirmar_aplicadas(&[id0], Punto::Slot(SLOT_TX));
        assert_eq!(m.estadisticas().n, 1);
        assert_eq!(m.seleccionar(max, 2), vec![d1]);
        eprintln!(
            "COLA1 presupuesto: 128/128 cuerpos sin sucesor, ambos siguen en cola; tras confirmar el primero sale el segundo"
        );
    }

    fn operacion_firmada(clave: &ClaveDev, extension: ExtensionTx) -> Par {
        let version = match extension {
            ExtensionTx::Garantia { .. } => 2,
            ExtensionTx::Sector { .. } => 5,
            ExtensionTx::PruebaAlmacenamiento { .. } => 6,
            _ => panic!("solo operaciones firmadas"),
        };
        let tx = Tx {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension,
        };
        let mensaje = match version {
            2 => zx_core::mensaje_aceptacion(&tx, CBID).to_vec(),
            5 => zx_core::mensaje_sector(&tx, CBID).to_vec(),
            6 => zx_core::mensaje_almacenamiento(&tx, CBID).to_vec(),
            _ => panic!("versión de operación"),
        };
        let firma: [u8; 64] = clave.sk.sign(&mensaje).into();
        (tx, vec![firma.to_vec()])
    }

    #[test]
    fn cola1_orden_por_clave_incluye_retiro_y_liberacion() {
        for tipo in [TipoGarantia::Retiro, TipoGarantia::Liberacion] {
            let mut e = Escenario::nuevo();
            let primera = if tipo == TipoGarantia::Liberacion {
                liberacion(&e)
            } else {
                e.base
                    .garantias
                    .get_mut(&e.clave.pk)
                    .expect("garantía")
                    .en_retirada
                    .clear();
                operacion_firmada(
                    &e.clave,
                    ExtensionTx::Garantia {
                        tipo,
                        clave: e.clave.pk,
                        importe: importe(1),
                        nonce: 0,
                    },
                )
            };
            let segunda = deposito(&e, op(10), 1);
            let mut m = e.cola();
            admitir(&mut m, &primera);
            admitir(&mut m, &segunda);
            let presupuesto = m.entradas[&txid(&segunda.0, CBID)].peso;
            for semilla in 0..SEMILLAS {
                let llena = m.seleccionar(params().max_cuerpo_bloque_bytes, semilla);
                assert_eq!(llena, vec![primera.clone(), segunda.clone()]);
                let una = m.seleccionar(presupuesto, semilla);
                assert!(una.is_empty() || una == vec![primera.clone()]);
            }
            let bloque = post(
                hash(2),
                3,
                SLOT_TX,
                e.productor.pk,
                m.seleccionar(params().max_cuerpo_bloque_bytes, 2),
            );
            let (estado, _, descartes) = aplicar_fusion(
                &e.base,
                &bloque.como_transicion(),
                Punto::Slot(SLOT_TX),
                &params(),
                CBID,
                &evp(),
            )
            .expect("cuerpo en orden por clave");
            assert!(descartes.is_empty());
            assert_eq!(estado.garantias[&e.clave.pk].nonce_siguiente, 2);
            eprintln!(
                "COLA1 F-15 {tipo:?} -> depósito: 128/128 en orden y sin sucesor aislado; 0 descartes"
            );
        }
    }

    #[test]
    fn ev2_evidencia_doble_firma_admitida_sobrevive_a_pago() {
        let e = Escenario::nuevo();
        let mut m = e.cola();
        let evidencia = evidencia_cabeceras(&e);
        let id = txid(&evidencia.0, CBID);
        admitir(&mut m, &evidencia);
        m.politica.s = m.bytes_totales;
        let p = transferencia(&e.clave, op(10), 100_000, 80_000, 0);
        let antes = m.estadisticas();
        assert_eq!(
            m.admitir(None, p.0, p.1, Instant::now(), Punto::Slot(SLOT_BASE)),
            Err(Rechazo::Limite("global"))
        );
        assert_eq!(m.estadisticas(), antes);
        assert!(m.entradas.contains_key(&id));
        assert_eq!(m.tomar_protecciones_evidencia(), vec![id]);
    }

    fn evidencia_cabeceras(e: &Escenario) -> Par {
        let cabecera = |sal| zx_core::DagBlockHeader {
            vdf_output: [0; 16],
            consensus_branch_id: CBID,
            merkle_root: zx_core::MerkleRoot::from_digest(Digest::from_bytes([0; 32])),
            timestamp: sal,
            height: 0,
            slot: SLOT_TX,
            pot_output: [0; 16],
            rango_solucion: 1,
            sol: zx_core::SolucionPoas {
                public_key: e.clave.pk,
                ..Default::default()
            },
            body_commitment: zx_core::BodyCommitment::from_digest(Digest::from_bytes([0; 32])),
            padres: zx_core::PadresDag::genesis(),
            sello: [0; 64],
        };
        let mut h1 = cabecera(0);
        let mut h2 = cabecera(1);
        if h1.pre_hash() > h2.pre_hash() {
            std::mem::swap(&mut h1, &mut h2);
        }
        h1.sello = e.clave.sk.sign(h1.pre_hash().as_bytes()).into();
        h2.sello = e.clave.sk.sign(h2.pre_hash().as_bytes()).into();
        (
            Tx {
                version: 4,
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: 0,
                expiry_height: 0,
                extension: ExtensionTx::Evidencia { h1, h2 },
            },
            Vec::new(),
        )
    }

    fn fusion_con_productor(
        base: &Estado,
        par: &Par,
        productor: ClavePublica,
    ) -> Result<Estado, ErrorTransicion> {
        let slot = base.slot + 1;
        let bloque = post(hash(2), 3, slot, productor, vec![par.clone()]);
        let (estado, _, descartadas) = aplicar_fusion(
            base,
            &bloque.como_transicion(),
            Punto::Slot(slot),
            &params(),
            CBID,
            &evp(),
        )?;
        if let Some(d) = descartadas.first() {
            return Err(d.motivo.clone());
        }
        Ok(estado)
    }

    fn comparar_apuntes(e: &Escenario, base: &Estado, par: Par, clase: &str) {
        let mut m = Mempool::nueva(params(), evp(), CBID, base.clone(), Politica::dev());
        let productor = productor_sintetico(base);
        assert!(!base.garantias.contains_key(&productor));
        assert!(!base.ultimo_slot_producido.contains_key(&productor));
        // El algoritmo anterior elegía la primera garantía. Se compara su veredicto con el
        // nuevo y con un incluidor real distinto de la clave operante/acusada.
        let anterior = *base.garantias.keys().next().expect("garantías reales");
        assert!(
            fusion_con_productor(base, &par, anterior).is_ok(),
            "{clase}: anterior"
        );
        let mut esperada = fusion_con_productor(base, &par, e.productor.pk)
            .expect("transacción válida con productor real");
        let recompensa = matches!(par.0.extension, ExtensionTx::Evidencia { .. })
            || matches!(
                &par.0.extension,
                ExtensionTx::PruebaAlmacenamiento {
                    operacion: OperacionAlmacenamiento::EvidenciaVotosPeso { .. }
                }
            );
        if recompensa {
            assert!(
                !esperada.garantias[&e.productor.pk].creditos.is_empty(),
                "{clase}: recompensa real"
            );
        }
        // El productor real no es ni dueña ni acusada y no tiene créditos previos. Su único
        // efecto en estos fixtures es el premio de inclusión; el resto del estado es el oráculo.
        assert!(base.garantias[&e.productor.pk].creditos.is_empty());
        esperada
            .garantias
            .insert(e.productor.pk, base.garantias[&e.productor.pk].clone());
        esperada
            .ultimo_slot_producido
            .clone_from(&base.ultimo_slot_producido);
        restaurar_punto(&mut esperada, base);
        assert_eq!(
            m.admitir(
                None,
                par.0.clone(),
                par.1.clone(),
                Instant::now(),
                Punto::Slot(base.slot)
            ),
            Ok(Admision::Admitida),
            "{clase}"
        );
        assert_eq!(m.vista, esperada, "{clase}: efectos completos de la vista");
        assert_eq!(
            m.vista.ultimo_slot_producido, base.ultimo_slot_producido,
            "{clase}"
        );
        assert!(!m.vista.garantias.contains_key(&productor), "{clase}");
        assert_eq!(
            m.vista.garantias[&e.productor.pk], base.garantias[&e.productor.pk],
            "{clase}"
        );
        let vista = m.vista.clone();
        m.rebasear(base.clone(), Instant::now(), Punto::Slot(base.slot));
        m.recomputar_vista();
        assert_eq!(m.vista, vista, "{clase}: rebase y recomputación");

        let mut invalida = par;
        if let ExtensionTx::Evidencia { h1, .. } = &mut invalida.0.extension {
            h1.sello[0] ^= 1;
        } else {
            invalida.1[0][0] ^= 1;
        }
        let rechazo = fusion_con_productor(base, &invalida, anterior);
        assert!(rechazo.is_err(), "{clase}: control de firma");
        assert_eq!(
            m.aplicar_a_vista(base, &invalida.0, &invalida.1),
            rechazo,
            "{clase}: mismo veredicto negativo con productor distinto"
        );
        eprintln!(
            "COLA1 clase={clase}: admitida; vista completa sin producción/recompensa ficticia; firma inválida rechazada igual"
        );
    }

    fn base_sector(e: &Escenario, individual: bool) -> Estado {
        use zx_consensus::sectores::MotivoSector;
        let mut base = e.base.clone();
        base.garantias
            .get_mut(&e.clave.pk)
            .expect("garantía")
            .activo = importe(10_000);
        if individual {
            // La retirada de un sector suelto solo existe con capacidad 1 (compatibilidad SR-0).
            base.parametros_sector.capacidad_caja = 1;
        }
        let alta = zx_core::OperacionSector::Alta {
            clave: e.clave.pk,
            sector_index: 0,
            version: 0,
            r2: [7; 32],
            history_size: 1 << 20,
        };
        let (base, r) = zx_consensus::transicion::aplicar_operacion_con_undo(
            &base,
            &alta,
            SLOT_BASE as i64 - base.parametros_sector.m_sec,
            &base.parametros_sector,
        );
        assert_eq!(r.motivo, MotivoSector::Ok);
        let (base, _) = zx_consensus::transicion::materializar_con_undo(
            &base,
            SLOT_BASE as i64,
            &base.parametros_sector,
        );
        base
    }

    #[expect(
        clippy::integer_division,
        reason = "el índice de ventana es el cociente entero del slot entre su duración"
    )]
    fn comprobar_almacenamiento(e: &Escenario, base_sector: &Estado) {
        use zx_consensus::cajas::r2_a_bytes;
        use zx_consensus::transicion::votos::T_INST_VOTOS;
        use zx_consensus::transicion::{raiz_conjunto_de, raiz_lote_de};
        let sk = zx_votos::ClaveSecreta::generar(&[0xC1; 32]).expect("BLS real");
        let pk = sk.clave_publica().bytes();
        let pop = zx_votos::probar_posesion(&sk).bytes();
        for (clase, operacion) in [
            (
                "v6_porep",
                OperacionAlmacenamiento::PoRep {
                    clave: e.clave.pk,
                    epoch: SLOT_TX,
                    n_sectores: 1,
                    raiz_conjunto: r2_a_bytes(raiz_lote_de(base_sector, &e.clave.pk)),
                    prueba: vec![1],
                },
            ),
            (
                "v6_post",
                OperacionAlmacenamiento::PoSt {
                    clave: e.clave.pk,
                    epoch: SLOT_TX,
                    n_sectores: 1,
                    raiz_conjunto: r2_a_bytes(raiz_conjunto_de(
                        base_sector,
                        &e.clave.pk,
                        SLOT_TX as i64,
                        &base_sector.parametros_sector,
                    )),
                    prueba: vec![1],
                },
            ),
            (
                "v6_clave_voto",
                OperacionAlmacenamiento::ClaveVoto {
                    clave: e.clave.pk,
                    clave_bls: pk,
                    prueba_posesion: pop,
                },
            ),
        ] {
            comparar_apuntes(
                e,
                base_sector,
                operacion_firmada(&e.clave, ExtensionTx::PruebaAlmacenamiento { operacion }),
                clase,
            );
        }
        let registro = operacion_firmada(
            &e.clave,
            ExtensionTx::PruebaAlmacenamiento {
                operacion: OperacionAlmacenamiento::ClaveVoto {
                    clave: e.clave.pk,
                    clave_bls: pk,
                    prueba_posesion: pop,
                },
            },
        );
        let registrada = fusion_con_productor(base_sector, &registro, e.productor.pk)
            .expect("registro real BLS");
        // El registro llega después de la prepasada. Se avanza un bloque vacío hasta la
        // siguiente ventana, donde el gancho real deriva la tabla con la BLS ya registrada.
        let slot = registrada.slot + 1;
        let bloque = post(hash(3), 4, slot, e.productor.pk, Vec::new());
        let (mut registrada, _, descartes) = aplicar_fusion(
            &registrada,
            &bloque.como_transicion(),
            Punto::Slot(slot),
            &params(),
            CBID,
            &evp(),
        )
        .expect("avance real de ventana");
        assert!(descartes.is_empty());
        let n = slot / T_INST_VOTOS;
        let (k, h) = *registrada
            .cola_tablas_voto
            .last()
            .expect("tabla derivada por producto");
        assert!(k <= n);
        let claves = &registrada.tablas_voto_contenido[&h];
        assert_eq!(claves.len(), 1);
        let tabla = zx_votos::Tabla {
            n,
            claves: claves
                .iter()
                .map(|c| zx_votos::Clave {
                    clave: c.clave_bls.to_vec(),
                    peso: c.peso,
                    activo: c.activo,
                    prueba: c.prueba,
                    garantia: c.garantia,
                })
                .collect(),
        };
        let candidato = [0x31; 32];
        let raiz = [0x32; 32];
        let firma = zx_votos::firmar(
            &sk,
            zx_votos::DOMINIO_VOTO,
            &zx_votos::mensaje_voto_peso(n, &candidato, &h, &raiz),
        )
        .expect("voto BLS real");
        let voto = OperacionAlmacenamiento::VotoPropio {
            clave: e.clave.pk,
            n,
            candidato,
            h_t_siguiente: h,
            raiz_estado: raiz,
            clave_bls: pk,
            firma: firma.bytes(),
        };
        comparar_apuntes(
            e,
            &registrada,
            operacion_firmada(
                &e.clave,
                ExtensionTx::PruebaAlmacenamiento { operacion: voto },
            ),
            "v6_voto_propio",
        );
        let certificado =
            zx_votos::peso::construir_certificado(n, candidato, h, raiz, &tabla, &[(1, firma)])
                .expect("certificado real de la tabla derivada");
        let bytes = zx_votos::peso::serial_certificado_peso(&certificado);
        comparar_apuntes(
            e,
            &registrada,
            operacion_firmada(
                &e.clave,
                ExtensionTx::PruebaAlmacenamiento {
                    operacion: OperacionAlmacenamiento::CertificadoPeso {
                        clave: e.clave.pk,
                        bytes: bytes.clone(),
                    },
                },
            ),
            "v6_certificado_peso",
        );
        // El acta exige tabla conocida para su ventana; asociación por el estado de certificado.
        registrada.tabla_ventana_voto.insert(n, h);
        comparar_apuntes(
            e,
            &registrada,
            operacion_firmada(
                &e.clave,
                ExtensionTx::PruebaAlmacenamiento {
                    operacion: OperacionAlmacenamiento::ActaPresencia {
                        clave: e.clave.pk,
                        bytes,
                    },
                },
            ),
            "v6_acta_presencia",
        );
        let voto_evidencia = |candidato| {
            let firma = zx_votos::firmar(
                &sk,
                zx_votos::DOMINIO_VOTO,
                &zx_votos::mensaje_voto_peso(n, &candidato, &h, &raiz),
            )
            .expect("doble voto BLS real");
            zx_core::VotoPesoEvidencia {
                n,
                candidato,
                h_t_siguiente: h,
                raiz_estado: raiz,
                firma: firma.bytes(),
            }
        };
        comparar_apuntes(
            e,
            &registrada,
            operacion_firmada(
                &e.clave,
                ExtensionTx::PruebaAlmacenamiento {
                    operacion: OperacionAlmacenamiento::EvidenciaVotosPeso {
                        clave: e.clave.pk,
                        clave_bls: pk,
                        voto1: voto_evidencia([1; 32]),
                        voto2: voto_evidencia([2; 32]),
                    },
                },
            ),
            "v6_evidencia_votos_peso",
        );
    }

    #[test]
    fn cola1_ningun_apunte_del_productor_sintetico_queda_en_la_vista() {
        use zx_consensus::sectores::MotivoSector;
        use zx_core::OperacionSector;
        let e = Escenario::nuevo();
        assert!(
            ed25519_zebra::VerificationKey::try_from(*productor_sintetico(&e.base).bytes())
                .is_err(),
            "el productor sintético no es una clave ZIP-215"
        );
        comparar_apuntes(
            &e,
            &e.base,
            transferencia(&e.clave, op(10), 100_000, 80_000, 0),
            "v1_pago",
        );
        comparar_apuntes(&e, &e.base, deposito(&e, op(10), 0), "v2_deposito");
        comparar_apuntes(&e, &e.base, liberacion(&e), "v2_liberacion");
        let mut base_retiro = e.base.clone();
        base_retiro
            .garantias
            .get_mut(&e.clave.pk)
            .expect("garantía")
            .en_retirada
            .clear();
        comparar_apuntes(
            &e,
            &base_retiro,
            operacion_firmada(
                &e.clave,
                ExtensionTx::Garantia {
                    tipo: TipoGarantia::Retiro,
                    clave: e.clave.pk,
                    importe: importe(1),
                    nonce: 0,
                },
            ),
            "v2_retiro",
        );
        comparar_apuntes(&e, &e.base, evidencia_cabeceras(&e), "v4_evidencia");

        let base = base_sector(&e, false);
        let mut sin_sector = e.base.clone();
        sin_sector
            .garantias
            .get_mut(&e.clave.pk)
            .expect("garantía")
            .activo = importe(10_000);
        let alta = OperacionSector::Alta {
            clave: e.clave.pk,
            sector_index: 0,
            version: 0,
            r2: [7; 32],
            history_size: 1 << 20,
        };
        comparar_apuntes(
            &e,
            &sin_sector,
            operacion_firmada(&e.clave, ExtensionTx::Sector { operacion: alta }),
            "v5_alta",
        );
        for (clase, operacion) in [
            (
                "v5_renovar",
                OperacionSector::Renovar {
                    clave: e.clave.pk,
                    sector_index: 0,
                },
            ),
            (
                "v5_abrir_auditoria",
                OperacionSector::AbrirAuditoria {
                    clave: e.clave.pk,
                    sector_index: 0,
                    auditoria_id: 7,
                },
            ),
            (
                "v5_cerrar_caja",
                OperacionSector::CerrarCaja {
                    clave: e.clave.pk,
                    seq: 1,
                },
            ),
        ] {
            comparar_apuntes(
                &e,
                &base,
                operacion_firmada(&e.clave, ExtensionTx::Sector { operacion }),
                clase,
            );
        }
        let abrir = OperacionSector::AbrirAuditoria {
            clave: e.clave.pk,
            sector_index: 0,
            auditoria_id: 7,
        };
        let (auditoria, r) = zx_consensus::transicion::aplicar_operacion_con_undo(
            &base,
            &abrir,
            SLOT_BASE as i64,
            &base.parametros_sector,
        );
        assert_eq!(r.motivo, MotivoSector::Ok);
        comparar_apuntes(
            &e,
            &auditoria,
            operacion_firmada(
                &e.clave,
                ExtensionTx::Sector {
                    operacion: OperacionSector::ContestarAuditoria {
                        clave: e.clave.pk,
                        sector_index: 0,
                        auditoria_id: 7,
                        prueba: vec![1],
                    },
                },
            ),
            "v5_contestar_auditoria",
        );
        let cerrar = OperacionSector::CerrarCaja {
            clave: e.clave.pk,
            seq: 1,
        };
        let (cerrada, r) = zx_consensus::transicion::aplicar_operacion_con_undo(
            &base,
            &cerrar,
            SLOT_BASE as i64,
            &base.parametros_sector,
        );
        assert_eq!(r.motivo, MotivoSector::Ok);
        comparar_apuntes(
            &e,
            &cerrada,
            operacion_firmada(
                &e.clave,
                ExtensionTx::Sector {
                    operacion: OperacionSector::RetirarCaja {
                        clave: e.clave.pk,
                        seq: 1,
                    },
                },
            ),
            "v5_retirar_caja",
        );
        comparar_apuntes(
            &e,
            &base_sector(&e, true),
            operacion_firmada(
                &e.clave,
                ExtensionTx::Sector {
                    operacion: OperacionSector::Retirar {
                        clave: e.clave.pk,
                        sector_index: 0,
                    },
                },
            ),
            "v5_retirar_individual_capacidad_1",
        );
        comprobar_almacenamiento(&e, &base);
    }
}

#[cfg(test)]
mod ev1;

#[cfg(test)]
mod ev2;
