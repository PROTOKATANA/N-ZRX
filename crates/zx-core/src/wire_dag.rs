//! Wire del bloque DAG: justificación PoT y cuerpo completo (SPEC §6, `C-WIRE-07`).
//!
//! # Qué viaja y qué no
//!
//! ```text
//! dag_header
//! ‖ pot_bundle_count:u8
//! ‖ pot_bundle_count × PotCheckpoints        (128 B cada uno)
//! ‖ CompactSize(n_tx)
//! ‖ n_tx × tx_con_testigos                   (C-WIRE-03)
//! ```
//!
//! La justificación PoT **no** entra en `block_hash`: la cabecera firma/hashea `slot`,
//! `pot_output` y los padres, pero el PoT es evidencia contextual reemplazable. Eso no la hace
//! opcional: sin ella no se puede declarar válido ni adoptar el bloque (C-HDR-07).
//!
//! # Límites antes de reservar
//!
//! `0 <= pot_bundle_count <= 150` se comprueba leyendo el byte, **antes** de reservar por los
//! portadores. El parser devuelve `Result` y no entra en pánico ante bytes arbitrarios
//! (C-WIRE-04, C-WIRE-05).

use thiserror::Error;

use crate::encoding::{compact_size, int};
use crate::error::EncodingError;
use crate::preimage::dag::{DagBlockHeader, dag_header_a_bytes, dag_header_desde_bytes};
use crate::tx::Tx;
use crate::wire::{leer_contador, tx_a_bytes, tx_desde_bytes};

/// Bytes de una salida PoT.
pub const POT_OUTPUT_BYTES: usize = 16;

/// Salidas por portador (`PotCheckpoints`).
pub const CHECKPOINTS_POR_BUNDLE: usize = 8;

/// Bytes por portador: `8 × 16 = 128`.
pub const BUNDLE_BYTES: usize = CHECKPOINTS_POR_BUNDLE * POT_OUTPUT_BYTES;

/// Máximo de portadores de una justificación: `S_max_slots = 150`.
pub const MAX_BUNDLES_POT: usize = 150;

/// Payload máximo de la justificación PoT: `150 × 128 = 19 200 B`.
///
/// Es solo el payload, **sin** el byte de contador de [`JustificacionPot::escribir`].
pub const MAX_JUSTIFICACION_POT_PAYLOAD: usize = MAX_BUNDLES_POT * BUNDLE_BYTES;

/// Justificación PoT **codificada**: `1 + 19 200 = 19 201 B`, con su `pot_bundle_count`.
pub const MAX_JUSTIFICACION_POT_CODIFICADA: usize = 1 + MAX_JUSTIFICACION_POT_PAYLOAD;

/// Agregado máximo cabecera + justificación codificada: `1 037 + 19 201 = 20 238 B`.
pub const MAX_BLOQUE_DAG_AGREGADO: usize =
    crate::preimage::dag::TAMANO_CABECERA_MAX + MAX_JUSTIFICACION_POT_CODIFICADA;

/// Ocho salidas PoT de 16 bytes, exactamente 128 bytes.
///
/// Tipo wire **transparente**: conserva los bytes tal cual y permite convertir en el futuro al
/// `PotCheckpoints` de `prototipos/pot-estable` sin reimplementar AES ni reinterpretar el
/// contenido. La única operación que conoce es la agrupación en ocho salidas.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PotCheckpoints([u8; BUNDLE_BYTES]);

impl PotCheckpoints {
    /// Construye desde ocho salidas de 16 bytes.
    #[must_use]
    pub fn desde_outputs(outputs: [[u8; POT_OUTPUT_BYTES]; CHECKPOINTS_POR_BUNDLE]) -> Self {
        let mut bytes = [0u8; BUNDLE_BYTES];
        for (i, o) in outputs.iter().enumerate() {
            let inicio = i * POT_OUTPUT_BYTES;
            if let Some(dst) = bytes.get_mut(inicio..inicio + POT_OUTPUT_BYTES) {
                dst.copy_from_slice(o);
            }
        }
        Self(bytes)
    }

    /// Los 128 bytes crudos.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BUNDLE_BYTES] {
        &self.0
    }

    /// Desde 128 bytes crudos.
    #[must_use]
    pub const fn desde_bytes(bytes: [u8; BUNDLE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Las ocho salidas, en orden.
    #[must_use]
    pub fn outputs(&self) -> [[u8; POT_OUTPUT_BYTES]; CHECKPOINTS_POR_BUNDLE] {
        let mut out = [[0u8; POT_OUTPUT_BYTES]; CHECKPOINTS_POR_BUNDLE];
        for (i, o) in out.iter_mut().enumerate() {
            let inicio = i * POT_OUTPUT_BYTES;
            if let Some(src) = self.0.get(inicio..inicio + POT_OUTPUT_BYTES) {
                o.copy_from_slice(src);
            }
        }
        out
    }
}

/// Lista canónica de portadores PoT, en orden cronológico.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct JustificacionPot {
    bundles: Vec<PotCheckpoints>,
}

impl JustificacionPot {
    /// La lista vacía canónica de `d = 0`.
    #[must_use]
    pub const fn vacia() -> Self {
        Self {
            bundles: Vec::new(),
        }
    }

    /// Construye una justificación, acotando el número de portadores.
    ///
    /// # Errores
    /// [`EncodingError::DemasiadosBundlesPot`] si supera [`MAX_BUNDLES_POT`].
    pub fn nueva(bundles: Vec<PotCheckpoints>) -> Result<Self, EncodingError> {
        if bundles.len() > MAX_BUNDLES_POT {
            return Err(EncodingError::DemasiadosBundlesPot {
                declarados: bundles.len() as u64,
                maximo: MAX_BUNDLES_POT as u64,
            });
        }
        Ok(Self { bundles })
    }

    /// Número de portadores.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// ¿Está vacía?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Los portadores, en orden.
    #[must_use]
    pub fn bundles(&self) -> &[PotCheckpoints] {
        &self.bundles
    }

    /// Escribe `count ‖ portadores`.
    pub fn escribir(&self, salida: &mut Vec<u8>) {
        salida.push(u8::try_from(self.bundles.len()).unwrap_or(u8::MAX));
        for b in &self.bundles {
            salida.extend_from_slice(b.as_bytes());
        }
    }
}

/// Un bloque DAG completo.
///
/// `txs` y `testigos` son **privados**: el invariante `txs.len() == testigos.len()` lo garantiza
/// [`BloqueDag::nuevo`], de modo que el descuadre es **inconstruible** y el códec puede ser
/// infalible. Un bloque no puede tener dos codificaciones distintas por listas ausentes o
/// sobrantes (H-01).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BloqueDag {
    /// Cabecera DAG.
    pub cabecera: DagBlockHeader,
    /// Justificación PoT, fuera de la cabecera y del `block_hash`.
    pub justificacion: JustificacionPot,
    txs: Vec<Tx>,
    testigos: Vec<Vec<Vec<u8>>>,
}

impl BloqueDag {
    /// Construye un bloque DAG emparejando transacciones y testigos.
    ///
    /// # Errores
    /// [`EncodingError::CuerpoTestigosDescuadrados`] si los dos conjuntos no miden lo mismo. No se
    /// sustituyen listas ausentes por listas vacías ni se descartan las sobrantes: el descuadre es
    /// un error, no una normalización.
    pub fn nuevo(
        cabecera: DagBlockHeader,
        justificacion: JustificacionPot,
        txs: Vec<Tx>,
        testigos: Vec<Vec<Vec<u8>>>,
    ) -> Result<Self, EncodingError> {
        if txs.len() != testigos.len() {
            return Err(EncodingError::CuerpoTestigosDescuadrados {
                txs: txs.len(),
                testigos: testigos.len(),
            });
        }
        Ok(Self {
            cabecera,
            justificacion,
            txs,
            testigos,
        })
    }

    /// Las transacciones, en orden. La primera es la coinbase.
    #[must_use]
    pub fn txs(&self) -> &[Tx] {
        &self.txs
    }

    /// `testigos[i][j]` es el testigo de la entrada `j` de la transacción `i`.
    #[must_use]
    pub fn testigos(&self) -> &[Vec<Vec<u8>>] {
        &self.testigos
    }
}

/// Escribe un bloque DAG completo (C-WIRE-07).
///
/// **Infalible por construcción**: `txs` y `testigos` miden lo mismo porque [`BloqueDag::nuevo`] lo
/// exige. No hay índice que pueda faltar.
pub fn bloque_dag_a_bytes(salida: &mut Vec<u8>, b: &BloqueDag) {
    salida.extend_from_slice(&dag_header_a_bytes(&b.cabecera));
    b.justificacion.escribir(salida);
    compact_size::escribir(salida, b.txs.len() as u64);
    for (tx, t) in b.txs.iter().zip(&b.testigos) {
        tx_a_bytes(salida, tx, t);
    }
}

/// Lee un bloque DAG completo.
///
/// Acota el número de portadores antes de reservar y nunca entra en pánico. El número de listas de
/// testigos se conserva tal cual: el codec no sustituye listas ausentes ni exige que cuadren —
/// hacerlo es tarea de [`crate::preimage::dag::comprobar_compromisos`].
///
/// # Errores
/// El error de codificación que corresponda.
pub fn bloque_dag_desde_bytes(bytes: &[u8]) -> Result<(BloqueDag, &[u8]), EncodingError> {
    let (cabecera, r) = dag_header_desde_bytes(bytes)?;
    let (count, r) = int::leer_u8(r)?;
    if usize::from(count) > MAX_BUNDLES_POT {
        return Err(EncodingError::DemasiadosBundlesPot {
            declarados: u64::from(count),
            maximo: MAX_BUNDLES_POT as u64,
        });
    }
    let n = usize::from(count);
    let (bloque, r) = r
        .split_at_checked(n * BUNDLE_BYTES)
        .ok_or(EncodingError::Truncado {
            esperados: n * BUNDLE_BYTES,
            disponibles: r.len(),
        })?;
    let mut bundles = Vec::with_capacity(n);
    for trozo in bloque.chunks_exact(BUNDLE_BYTES) {
        let mut b = [0u8; BUNDLE_BYTES];
        b.copy_from_slice(trozo);
        bundles.push(PotCheckpoints::desde_bytes(b));
    }
    let justificacion = JustificacionPot { bundles };

    let (n_tx, mut r) = leer_contador(r)?;
    let mut txs = Vec::with_capacity(n_tx.min(4_096));
    let mut testigos = Vec::with_capacity(n_tx.min(4_096));
    for _ in 0..n_tx {
        let ((tx, t), resto) = tx_desde_bytes(r)?;
        txs.push(tx);
        testigos.push(t);
        r = resto;
    }

    let bloque = BloqueDag::nuevo(cabecera, justificacion, txs, testigos)?;
    Ok((bloque, r))
}

/// Comprueba la diferencia de slots de un bloque **tomando el bloque, no el contador** (H-05).
///
/// Deriva los portadores de `b.justificacion` y el slot de `b.cabecera.slot`. Así el llamante no
/// puede validar un número y transmitir otro: la función solo puede ver el bloque real.
///
/// # Errores
/// [`ErrorDiferenciaSlots::Underflow`] si `slot(B) < slot_sp`;
/// [`ErrorDiferenciaSlots::ExcedeMaximo`] si la diferencia supera 150;
/// [`ErrorDiferenciaSlots::NoCoincide`] si el número de portadores no es la diferencia.
pub fn comprobar_diferencia_slots_del_bloque(
    b: &BloqueDag,
    slot_sp: u64,
) -> Result<(), ErrorDiferenciaSlots> {
    let bundles = u64::try_from(b.justificacion.len()).unwrap_or(u64::MAX);
    comprobar_diferencia_slots(bundles, b.cabecera.slot, slot_sp)
}

/// Comprobación de bajo nivel, con los índices y el conteo ya extraídos.
///
/// Es `pub(crate)` a propósito: la ruta pública es
/// [`comprobar_diferencia_slots_del_bloque`], que **no** admite que el conteo venga de fuera.
pub(crate) fn comprobar_diferencia_slots(
    bundles: u64,
    slot_b: u64,
    slot_sp: u64,
) -> Result<(), ErrorDiferenciaSlots> {
    if slot_b < slot_sp {
        return Err(ErrorDiferenciaSlots::Underflow { slot_b, slot_sp });
    }
    let d = slot_b - slot_sp;
    if d > MAX_BUNDLES_POT as u64 {
        return Err(ErrorDiferenciaSlots::ExcedeMaximo { diferencia: d });
    }
    if bundles != d {
        return Err(ErrorDiferenciaSlots::NoCoincide {
            bundles,
            diferencia: d,
        });
    }
    Ok(())
}

/// Fallo de la comprobación estructural `slot(B) − slot(sp(B)) == pot_bundle_count`.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorDiferenciaSlots {
    /// `slot(B) < slot(sp(B))`: viola C-HDR-05.
    #[error("C-HDR-05: slot(B) = {slot_b} < slot(sp) = {slot_sp}")]
    Underflow {
        /// Slot del bloque.
        slot_b: u64,
        /// Slot del padre seleccionado.
        slot_sp: u64,
    },
    /// La diferencia supera `S_max_slots = 150`.
    #[error("S_max: la diferencia de slots {diferencia} supera 150")]
    ExcedeMaximo {
        /// Diferencia observada.
        diferencia: u64,
    },
    /// El número de portadores no es la diferencia de slots.
    #[error("justificación PoT: {bundles} portadores para una diferencia de {diferencia} slots")]
    NoCoincide {
        /// Portadores declarados.
        bundles: u64,
        /// Diferencia de slots.
        diferencia: u64,
    },
}

/// Estado explícito cuando el verificador PoT completo todavía no puede llamarse.
///
/// **No es un `Ok(())` provisional.** Se devuelve como error para que ningún llamante confunda
/// "no verificado" con "verificado".
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("verificación PoT pendiente de integración: {0}")]
pub struct IntegracionPotPendiente(pub &'static str);

/// Contexto que la verificación criptográfica del PoT necesita y que **no** está en el wire.
///
/// La implementación de este trait la aporta el llamante, derivada del pasado DAG validado
/// (R-FIN-3, R-FIN-5, R-FIN-14). Este incremento define la interfaz, no valores.
pub trait ContextoVerificacionPot {
    /// Flujo del bloque candidato en su slot (R-FIN-3/R-FIN-5).
    fn flujo(&self, slot: u64) -> [u8; 32];
    /// Semilla PoT re-sembrada por inyección (R-FIN-14a).
    fn semilla(&self, slot: u64) -> [u8; 16];
    /// Retardo de autoría `D` (R-FIN-14d).
    fn retardo_autoria(&self) -> u64;
    /// `N(s)` vigente en el slot (R-FIN-14a, R-FIN-9).
    fn iteraciones(&self, slot: u64) -> u64;
}

/// Verificación criptográfica de la justificación PoT.
///
/// Este incremento implementa el contenedor, el codec y las comprobaciones estructurales. El
/// verificador AES secuencial no está integrado, así que esta función **debe** devolver
/// [`IntegracionPotPendiente`] y nunca un `Ok(())` fabricado. El contraste entre el límite
/// estructural y la cadena completa se realiza en `zx-consensus`.
///
/// # Errores
/// [`IntegracionPotPendiente`] siempre, mientras no exista verificador integrado.
pub fn verificar_justificacion_pot<C: ContextoVerificacionPot>(
    _ctx: &C,
    _header: &DagBlockHeader,
    _justificacion: &JustificacionPot,
) -> Result<(), IntegracionPotPendiente> {
    Err(IntegracionPotPendiente(
        "el verificador PoT AES secuencial no está integrado en este incremento",
    ))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{
        BUNDLE_BYTES, BloqueDag, CHECKPOINTS_POR_BUNDLE, ErrorDiferenciaSlots,
        IntegracionPotPendiente, JustificacionPot, MAX_BLOQUE_DAG_AGREGADO, MAX_BUNDLES_POT,
        MAX_JUSTIFICACION_POT_CODIFICADA, MAX_JUSTIFICACION_POT_PAYLOAD, POT_OUTPUT_BYTES,
        PotCheckpoints, bloque_dag_a_bytes, bloque_dag_desde_bytes,
        comprobar_diferencia_slots_del_bloque, verificar_justificacion_pot,
    };
    use crate::amount::Amount;
    use crate::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot, TxId};
    use crate::error::EncodingError;
    use crate::firma::ClavePublica;
    use crate::preimage::dag::{
        DagBlockHeader, MAX_PADRES_EXTRA, PadresDag, SolucionPoas, TAMANO_CABECERA_MAX,
        TAMANO_CABECERA_MIN,
    };
    use crate::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
    use crate::wire::tx_a_bytes;

    fn cabecera_con_padres(n: usize) -> DagBlockHeader {
        let extras: Vec<BlockHash> = (0..n)
            .map(|i| BlockHash::from_digest(Digest::from_bytes([0x40 + i as u8; 32])))
            .collect();
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xc478_80ea,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
            timestamp: 1_788_480_000,
            height: 1,
            slot: 250,
            pot_output: [9; 16],
            rango_solucion: 5,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
            padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([3; 32])), &extras)
                .unwrap(),
            sello: [0u8; 64],
        }
    }

    fn cabecera() -> DagBlockHeader {
        cabecera_con_padres(0)
    }

    fn tx(n: u8) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: OutPoint {
                    prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                    prev_index: 0,
                },
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(i64::from(n) * 100).unwrap(),
                lock: Lock::PubKey {
                    pubkey: ClavePublica::desde_bytes([n; 32]),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        }
    }

    fn justificacion(bundles: usize) -> JustificacionPot {
        let lista: Vec<PotCheckpoints> = (0..bundles)
            .map(|i| PotCheckpoints::desde_bytes([i as u8; BUNDLE_BYTES]))
            .collect();
        JustificacionPot::nueva(lista).unwrap()
    }

    fn bloque(bundles: usize, txs: usize) -> BloqueDag {
        BloqueDag::nuevo(
            cabecera(),
            justificacion(bundles),
            (1..=txs as u8).map(tx).collect(),
            (1..=txs as u8).map(|n| vec![vec![n; 64]]).collect(),
        )
        .unwrap()
    }

    // ── H-01 · El descuadre tx/testigos es inconstruible ──────────────────────

    #[test]
    fn nuevo_rechaza_el_descuadre_en_las_dos_direcciones() {
        let faltan = BloqueDag::nuevo(
            cabecera(),
            justificacion(0),
            (1..=2u8).map(tx).collect(),
            vec![vec![vec![1; 64]]],
        );
        assert!(matches!(
            faltan,
            Err(EncodingError::CuerpoTestigosDescuadrados {
                txs: 2,
                testigos: 1
            })
        ));

        let sobran = BloqueDag::nuevo(
            cabecera(),
            justificacion(0),
            (1..=1u8).map(tx).collect(),
            vec![vec![vec![1; 64]], vec![vec![2; 64]]],
        );
        assert!(matches!(
            sobran,
            Err(EncodingError::CuerpoTestigosDescuadrados {
                txs: 1,
                testigos: 2
            })
        ));
    }

    /// La codificación es **inyectiva**: bloques que difieren en un solo campo —incluido el número
    /// de testigos de una transacción— producen bytes distintos dos a dos.
    #[test]
    fn la_codificacion_del_bloque_es_inyectiva() {
        let base = BloqueDag::nuevo(
            cabecera(),
            justificacion(2),
            vec![tx(1), tx(2)],
            vec![vec![vec![1; 64]], vec![vec![2; 64]]],
        )
        .unwrap();

        // Variantes: una tx menos (y su testigo), un testigo distinto en una sola tx, un número
        // distinto de testigos internos en una sola tx, y otro número de bundles.
        let variantes: Vec<BloqueDag> = vec![
            BloqueDag::nuevo(
                cabecera(),
                justificacion(2),
                vec![tx(1)],
                vec![vec![vec![1; 64]]],
            )
            .unwrap(),
            BloqueDag::nuevo(
                cabecera(),
                justificacion(2),
                vec![tx(1), tx(2)],
                vec![vec![vec![9; 64]], vec![vec![2; 64]]],
            )
            .unwrap(),
            BloqueDag::nuevo(
                cabecera(),
                justificacion(2),
                vec![tx(1), tx(2)],
                vec![vec![vec![1; 64], vec![1; 64]], vec![vec![2; 64]]],
            )
            .unwrap(),
            BloqueDag::nuevo(
                cabecera(),
                justificacion(1),
                vec![tx(1), tx(2)],
                vec![vec![vec![1; 64]], vec![vec![2; 64]]],
            )
            .unwrap(),
        ];

        // Se comparan **dos a dos**: base y todas las variantes, bytes distintos entre sí.
        let mut todos: Vec<Vec<u8>> = Vec::new();
        let codificar = |b: &BloqueDag| {
            let mut v = Vec::new();
            bloque_dag_a_bytes(&mut v, b);
            v
        };
        todos.push(codificar(&base));
        for v in &variantes {
            todos.push(codificar(v));
        }
        for i in 0..todos.len() {
            for j in (i + 1)..todos.len() {
                assert_ne!(
                    todos.get(i),
                    todos.get(j),
                    "los bloques {i} y {j} produjeron los mismos bytes"
                );
            }
        }
    }

    // ── H-07 · Los máximos están atados a la codificación ────────────────────

    #[test]
    fn el_bloque_maximo_mide_exactamente_el_agregado() {
        let cab = cabecera_con_padres(MAX_PADRES_EXTRA);
        let just = justificacion(MAX_BUNDLES_POT);

        // La cabecera máxima, codificada.
        let header_bytes = crate::preimage::dag::dag_header_a_bytes(&cab);
        assert_eq!(header_bytes.len(), TAMANO_CABECERA_MAX, "P = 15");

        // La justificación máxima, codificada (con su byte de contador).
        let mut just_bytes = Vec::new();
        just.escribir(&mut just_bytes);
        assert_eq!(just_bytes.len(), MAX_JUSTIFICACION_POT_CODIFICADA);

        // Y el agregado del bloque (cabecera ‖ justificación) mide la constante.
        let mut agregado = header_bytes.clone();
        agregado.extend_from_slice(&just_bytes);
        assert_eq!(agregado.len(), MAX_BLOQUE_DAG_AGREGADO);
        assert_eq!(MAX_BLOQUE_DAG_AGREGADO, 20_910);

        // El bloque completo real empieza por ese agregado y añade contador y txs.
        let b = BloqueDag::nuevo(cab, just, vec![tx(1)], vec![vec![vec![1; 64]]]).unwrap();
        let mut completo = Vec::new();
        bloque_dag_a_bytes(&mut completo, &b);
        assert_eq!(
            completo.get(..MAX_BLOQUE_DAG_AGREGADO).unwrap(),
            &agregado[..],
            "el prefijo cabecera+justificación MUST medir el agregado"
        );
        let mut tx_bytes = Vec::new();
        tx_a_bytes(&mut tx_bytes, &tx(1), &[vec![1; 64]]);
        assert_eq!(completo.len(), MAX_BLOQUE_DAG_AGREGADO + 1 + tx_bytes.len());
    }

    #[test]
    fn la_cabecera_minima_y_la_maxima() {
        let minima = crate::preimage::dag::dag_header_a_bytes(&cabecera());
        assert_eq!(minima.len(), TAMANO_CABECERA_MIN, "P = 1");
        assert_eq!(TAMANO_CABECERA_MIN, 1261);
        assert_eq!(TAMANO_CABECERA_MAX, 1709);
    }

    #[test]
    fn los_tamanos_son_los_presupuestados() {
        assert_eq!(BUNDLE_BYTES, 128);
        assert_eq!(CHECKPOINTS_POR_BUNDLE, 8);
        assert_eq!(POT_OUTPUT_BYTES, 16);
        assert_eq!(MAX_JUSTIFICACION_POT_PAYLOAD, 19_200);
        assert_eq!(MAX_JUSTIFICACION_POT_CODIFICADA, 19_201);
        assert_eq!(MAX_BLOQUE_DAG_AGREGADO, 20_910);
    }

    // ── Resto ────────────────────────────────────────────────────────────────

    #[test]
    fn un_bundle_conserva_ocho_outputs() {
        let outputs = core::array::from_fn(|i| [i as u8; POT_OUTPUT_BYTES]);
        let c = PotCheckpoints::desde_outputs(outputs);
        assert_eq!(c.as_bytes().len(), 128);
        assert_eq!(c.outputs(), outputs);
        assert_eq!(c.outputs()[7], [7u8; 16], "el último output es el octavo");
    }

    #[test]
    fn justificacion_de_cero_uno_y_150_bundles() {
        for n in [0usize, 1, MAX_BUNDLES_POT] {
            let b = bloque(n, 1);
            let mut bytes = Vec::new();
            bloque_dag_a_bytes(&mut bytes, &b);
            let (leido, resto) = bloque_dag_desde_bytes(&bytes).unwrap();
            assert_eq!(leido, b, "n={n}");
            assert!(resto.is_empty());
        }
    }

    #[test]
    fn rechaza_151_bundles_antes_de_reservar() {
        let mut bytes = bloque(1, 1).cabecera.a_bytes();
        bytes.push(151);
        assert!(matches!(
            bloque_dag_desde_bytes(&bytes),
            Err(EncodingError::DemasiadosBundlesPot {
                declarados: 151,
                ..
            })
        ));
    }

    #[test]
    fn truncados_y_basura_no_hacen_panico() {
        let mut completo = Vec::new();
        bloque_dag_a_bytes(&mut completo, &bloque(2, 2));
        for n in 0..completo.len() {
            let _ = bloque_dag_desde_bytes(completo.get(..n).unwrap());
        }

        let mut x: u64 = 0x0123_4567_89AB_CDEF;
        for _ in 0..1_000 {
            let mut buf = Vec::new();
            for _ in 0..(x % 800) {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                buf.push((x >> 33) as u8);
            }
            let _ = bloque_dag_desde_bytes(&buf);
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        }
    }

    /// **H-05** · La comprobación pública toma el bloque; el conteo no lo pasa el llamante.
    #[test]
    fn la_diferencia_de_slots_se_comprueba_sobre_el_bloque() {
        // slot(B) = 250, con 150 portadores y slot_sp = 100 ⇒ 150, pasa.
        let b = BloqueDag::nuevo(
            cabecera_con_padres(0),
            justificacion(MAX_BUNDLES_POT),
            vec![tx(1)],
            vec![vec![vec![1; 64]]],
        )
        .unwrap();
        assert!(comprobar_diferencia_slots_del_bloque(&b, 100).is_ok());

        // El mismo bloque contra slot_sp = 101 ⇒ la diferencia es 149, no 150 ⇒ rechazo.
        assert!(matches!(
            comprobar_diferencia_slots_del_bloque(&b, 101),
            Err(ErrorDiferenciaSlots::NoCoincide {
                bundles: 150,
                diferencia: 149
            })
        ));

        // Underflow.
        assert!(matches!(
            comprobar_diferencia_slots_del_bloque(&b, 251),
            Err(ErrorDiferenciaSlots::Underflow { .. })
        ));
    }

    struct CtxNulo;
    impl super::ContextoVerificacionPot for CtxNulo {
        fn flujo(&self, _slot: u64) -> [u8; 32] {
            [0; 32]
        }
        fn semilla(&self, _slot: u64) -> [u8; 16] {
            [0; 16]
        }
        fn retardo_autoria(&self) -> u64 {
            0
        }
        fn iteraciones(&self, _slot: u64) -> u64 {
            0
        }
    }

    #[test]
    fn el_verificador_pot_no_finge_exito() {
        let b = bloque(1, 1);
        assert_eq!(
            verificar_justificacion_pot(&CtxNulo, &b.cabecera, &b.justificacion),
            Err(IntegracionPotPendiente(
                "el verificador PoT AES secuencial no está integrado en este incremento"
            ))
        );
    }
}
