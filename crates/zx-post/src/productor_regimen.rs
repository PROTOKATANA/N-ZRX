//! Productor PoST **en régimen**: bloque DAG con varios padres, justificación PoT del rango
//! `(slot(sp(B)) + D, slot(B) + D]` y cuerpo con coinbase v3 (`C-POT-03`, `C-POT-05`, `C-HDR-03`,
//! `C-HDR-04`, `C-HDR-07`, `C-BON-03`, F-03, F-09, F-17, D-P09…D-P11).
//!
//! # Qué produce
//!
//! [`producir_en_regimen_sin_firmante`] recibe los **padres ya elegidos** por el llamante (`PadresDag`),
//! el **slot objetivo**, el [`ServicioPot`] ya arrancado en el terminal, una fuente de soluciones
//! PoAS, la clave que firma, los parámetros dev y el cuerpo (transacciones sin la coinbase) y
//! devuelve el bloque completo con la cabecera sellada.
//!
//! 1. Localiza `slot(sp(B))` en el pasado **registrado** del servicio (el terminal en slot 0 o un
//!    bloque que el llamante registró con [`ServicioPot::registrar_validado`]).
//! 2. Exige `slot(B) >= slot(sp)` (cota no estricta de `C-HDR-05`/`C-FLU-02`), salvo si el padre
//!    seleccionado es el terminal, que exige `slot(B) > s_0`, y que la diferencia no supere
//!    `MAX_BUNDLES_POT = 150` (`C-HDR-07`). Con `D = 0` (D-P10), `pot_output = salida(f, slot(B))`;
//!    con `slot(B) = slot(sp)` la justificación es la lista vacía (`d = 0`).
//! 3. Avanza el servicio hasta el slot objetivo si hace falta y audita la parcela **solo** en ese
//!    slot (el slot es exacto: los hermanos de un slot ya calculado se pueden producir sin volver
//!    a avanzar).
//! 4. Con la primera solución verificada construye: `padres` tal cual, `height = 0` (F-03), `slot`,
//!    `pot_output`, el rango `SR_dev`, los campos de la solución, la **justificación** con los
//!    portadores de `(slot(sp), slot(B)]`, el compromiso del cuerpo —coinbase v3 con **el slot de
//!    este bloque** (F-17) y las transacciones del llamante— y el **sello** sobre la prefirma.
//!
//! # Lo que NO hace
//!
//! **No elige padres ni su orden**: recibe el `PadresDag` ya construido (seleccionado primero).
//! No decide si la clave tiene garantía: eso es del motor de estado (`zx-cadena`). No elige `SR`
//! (constante dev, D-P11), no admite el bloque, no comprueba el cuerpo y no publica.
//!
//! # Firmante seguro (SL-4b1, SL-4b3)
//!
//! [`producir_en_regimen_sin_firmante`] sella directamente y **no** protege contra la doble firma:
//! **solo para tests y arneses**; el nodo ya no la alcanza (SL-4b2 lo dejó fuera y SL-4b3 lo hace
//! explícito con un guardián de CI). La variante [`producir_en_regimen_con_firmante`] construye
//! **exactamente** el mismo bloque y lo sella **solo** a través de [`Firmante`] (`C-EVP-06`,
//! FIR-01…FIR-15).
//!
//! # Frontera de confianza
//!
//! [`FuenteSoluciones`] afirma que la solución verificó contra las entradas proporcionadas; el
//! productor vuelve a exigir que sea de la clave que firma (C-HDR-04) y construye el sello. La
//! puerta conjunta de [`crate::cabecera_conjunta`] vuelve a comprobar todo con su contexto.
//! Producir no es admitir.

use ed25519_zebra::SigningKey;
use zx_core::firma::LONGITUD_FIRMA;
use zx_core::preimage::block::merkle_root;
use zx_core::wire_dag::{BloqueDag, JustificacionPot, MAX_BUNDLES_POT};
use zx_core::{
    ClavePublica, DagBlockHeader, EncodingError, ExtensionTx, PadresDag, Tx, body_commitment, txid,
};

use crate::firmante::{Firmante, FirmanteError};
use crate::productor::{
    CandidatoPoST, ErrorSellado, FuenteSoluciones, ParametrosProductor, ProductoFirmado,
    clave_publica_de, finalizar_con_firmante, finalizar_directo,
};
use crate::servicio_pot::{ErrorServicioPot, ServicioPot};

/// Cuerpo que aporta el llamante: transacciones **sin** la coinbase y sus testigos, en paralelo.
///
/// La coinbase v3 la construye [`producir_en_regimen_sin_firmante`] con el `slot` del bloque (F-17);
/// por eso una coinbase en esta lista es un error explícito y no una segunda coinbase silenciosa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CuerpoProductor {
    txs: Vec<Tx>,
    testigos: Vec<Vec<Vec<u8>>>,
}

/// Cuerpo inválido para el productor.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ErrorCuerpo {
    /// El número de listas de testigos no es el de transacciones.
    #[error("cuerpo: {txs} transacciones y {testigos} listas de testigos")]
    Descuadre {
        /// Transacciones.
        txs: usize,
        /// Listas de testigos.
        testigos: usize,
    },
    /// Una de las transacciones ya es una coinbase (v3, o v1 sin entradas).
    #[error("cuerpo: la transacción {indice} ya es una coinbase; la construye el productor")]
    CoinbaseEnCuerpo {
        /// Índice de la transacción infractora.
        indice: usize,
    },
}

impl CuerpoProductor {
    /// Cuerpo vacío: solo la coinbase que antepone el productor.
    #[must_use]
    pub const fn vacio() -> Self {
        Self {
            txs: Vec::new(),
            testigos: Vec::new(),
        }
    }

    /// Construye el cuerpo a partir de las transacciones **sin** la coinbase y sus testigos.
    ///
    /// # Errores
    /// [`ErrorCuerpo::Descuadre`] si las dos listas no miden lo mismo;
    /// [`ErrorCuerpo::CoinbaseEnCuerpo`] si alguna transacción es ya una coinbase.
    pub fn nuevo(txs: Vec<Tx>, testigos: Vec<Vec<Vec<u8>>>) -> Result<Self, ErrorCuerpo> {
        if txs.len() != testigos.len() {
            return Err(ErrorCuerpo::Descuadre {
                txs: txs.len(),
                testigos: testigos.len(),
            });
        }
        if let Some(indice) = txs.iter().position(es_coinbase) {
            return Err(ErrorCuerpo::CoinbaseEnCuerpo { indice });
        }
        Ok(Self { txs, testigos })
    }

    /// Las transacciones, en orden (sin la coinbase).
    #[must_use]
    pub fn txs(&self) -> &[Tx] {
        &self.txs
    }

    /// Las listas de testigos, paralelas a [`Self::txs`].
    #[must_use]
    pub fn testigos(&self) -> &[Vec<Vec<u8>>] {
        &self.testigos
    }

    /// ¿El cuerpo solo llevará la coinbase?
    #[must_use]
    pub fn esta_vacio(&self) -> bool {
        self.txs.is_empty()
    }
}

/// ¿La transacción es una coinbase (v3, o v1 sin entradas)?
fn es_coinbase(tx: &Tx) -> bool {
    tx.version == 3 || (tx.version == 1 && tx.inputs.is_empty())
}

/// Fallo al producir un bloque PoST en régimen.
#[derive(Debug, thiserror::Error)]
pub enum ErrorRegimen<E>
where
    E: std::error::Error + 'static,
{
    /// Una cabecera PoST sin padres es siempre inválida (D-P08).
    #[error("el bloque de régimen necesita al menos un padre (D-P08)")]
    SinPadres,
    /// `N_dev` del productor y del servicio no coinciden.
    #[error("N_dev discrepante: productor {productor}, servicio {servicio}")]
    NDevDiscrepante {
        /// `N_dev` de los parámetros del productor.
        productor: u64,
        /// `N_dev` del servicio PoT.
        servicio: u64,
    },
    /// El padre seleccionado no está registrado en el pasado del servicio.
    #[error("el padre seleccionado {padre} no está registrado en el ServicioPot")]
    PadreSeleccionadoDesconocido {
        /// Hash del padre seleccionado.
        padre: zx_core::BlockHash,
    },
    /// El slot objetivo no progresa respecto de `slot(sp(B))`.
    #[error("slot objetivo {slot} no progresa respecto de slot(sp) = {slot_sp}")]
    SlotNoProgreso {
        /// Slot objetivo.
        slot: u64,
        /// Slot del padre seleccionado.
        slot_sp: u64,
    },
    /// El rango `slot(B) − slot(sp)` supera `MAX_BUNDLES_POT`.
    #[error("el rango {d} excede MAX_BUNDLES_POT = {max}")]
    RangoExcedeMaximo {
        /// Diferencia pedida.
        d: u64,
        /// Cota del formato.
        max: u64,
    },
    /// Fallo del servicio PoT.
    #[error("servicio PoT: {0}")]
    Servicio(#[from] ErrorServicioPot),
    /// El segundo VDF no se pudo calcular (`C-RLJ-VDF-02`).
    #[error("segundo VDF del productor: {0}")]
    Vdf(#[from] crate::reloj_post::ErrorVdfPost),
    /// La solución no está sellada por la clave que firma (C-HDR-04, F-09).
    #[error("la solución no es de la clave que firma: solución {solucion:?}, firma {firma:?}")]
    ClaveDeLaSolucionNoCoincide {
        /// Clave de la solución.
        solucion: ClavePublica,
        /// Clave del firmante.
        firma: ClavePublica,
    },
    /// Fallo del firmante (clave ajena, sello inválido o E/S del registro).
    #[error("firmante: {0}")]
    Firmante(#[from] FirmanteError),
    /// Fallo de la fuente de soluciones.
    #[error("fuente de soluciones: {0}")]
    Fuente(#[source] E),
    /// No apareció ninguna solución en el slot objetivo.
    #[error("sin solución PoAS en el slot objetivo {slot}")]
    SinSolucion {
        /// Slot objetivo.
        slot: u64,
    },
    /// `zx-core` rechazó el formato (padres o compromiso del cuerpo).
    #[error("formato del bloque: {0}")]
    Formato(#[from] EncodingError),
}

impl<E> From<ErrorSellado> for ErrorRegimen<E>
where
    E: std::error::Error + 'static,
{
    fn from(fallo: ErrorSellado) -> Self {
        match fallo {
            ErrorSellado::Firmante(e) => Self::Firmante(e),
            ErrorSellado::Formato(e) => Self::Formato(e),
        }
    }
}

/// Produce un bloque PoST en régimen para los padres y el slot dados.
///
/// **Solo tests y arneses; no protege contra la doble firma:** sella directamente con `clave`. El
/// nodo produce **solo** con [`producir_en_regimen_con_firmante`] (SL-4b2/SL-4b3);
/// `ci/firmante-obligatorio.sh` comprueba que `crates/zx-node/src/` no invoca esta ruta.
///
/// # Argumentos
/// - `padres`: padres ya elegidos por el llamante (seleccionado primero, `≤ 15`). El productor no
///   los reordena.
/// - `slot_objetivo`: slot **exacto** del bloque; debe ser `> slot(sp)`.
/// - `servicio`: estado PoT local; se avanza hasta `slot_objetivo` si hace falta.
/// - `fuente`: soluciones PoAS verificadas contra `(salida, slot, SR_dev)`.
/// - `clave`: clave Ed25519 que firma el sello y a la que paga la coinbase.
/// - `parametros`: `N_dev` (debe coincidir con el del servicio), `SR_dev`, rama, timestamp e importe.
/// - `cuerpo`: transacciones sin la coinbase (el productor la antepone).
///
/// # Errores
/// [`ErrorRegimen`] con la variante que corresponda. En particular
/// [`ErrorRegimen::SlotNoProgreso`] si `slot ≤ slot(sp)` y
/// [`ErrorRegimen::RangoExcedeMaximo`] si el rango excede `MAX_BUNDLES_POT`.
pub fn producir_en_regimen_sin_firmante<F>(
    padres: PadresDag,
    slot_objetivo: u64,
    servicio: &mut ServicioPot,
    fuente: &F,
    clave: &SigningKey,
    parametros: &ParametrosProductor,
    cuerpo: CuerpoProductor,
) -> Result<BloqueDag, ErrorRegimen<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    let productor = clave_publica_de(clave);
    let candidato = ensamblar_regimen(
        padres,
        slot_objetivo,
        servicio,
        fuente,
        &productor,
        parametros,
        cuerpo,
    )?;
    finalizar_directo(candidato, clave).map_err(ErrorRegimen::from)
}

/// Produce un bloque PoST en régimen sellándolo **solo** con `firmante` (SL-4b1).
///
/// Construye exactamente el mismo bloque que [`producir_en_regimen_sin_firmante`] y lo sella por
/// [`Firmante::firmar`]. Devuelve [`ProductoFirmado::Abstenido`] cuando el firmante se niega
/// (conflicto o pérdida de registro) y [`ProductoFirmado::Bloque`] con su veredicto cuando sella.
///
/// # Errores
/// Los mismos que [`producir_en_regimen_sin_firmante`], más [`ErrorRegimen::Firmante`] para un fallo
/// real del registro (E/S, envenenamiento, corrupción), la clave ajena o un sello inválido.
#[expect(
    clippy::too_many_arguments,
    reason = "firma pública del productor seguro; agrupar rompería la simetría con producir_en_regimen_sin_firmante"
)]
pub fn producir_en_regimen_con_firmante<F>(
    padres: PadresDag,
    slot_objetivo: u64,
    servicio: &mut ServicioPot,
    fuente: &F,
    clave: &SigningKey,
    parametros: &ParametrosProductor,
    cuerpo: CuerpoProductor,
    firmante: &mut Firmante<'_>,
) -> Result<ProductoFirmado, ErrorRegimen<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    let productor = clave_publica_de(clave);
    let candidato = ensamblar_regimen(
        padres,
        slot_objetivo,
        servicio,
        fuente,
        &productor,
        parametros,
        cuerpo,
    )?;
    finalizar_con_firmante(candidato, clave, firmante).map_err(ErrorRegimen::from)
}

/// PROD-3c: candidata real sin sellar a partir de la **clave pública** del productor.
///
/// Mismo armado y las mismas comprobaciones que [`preparar_regimen_para_ensayo`]: la solución
/// tiene que ser de esta clave y la coinbase le paga a ella. No recibe ninguna clave privada:
/// el hilo productor puede usarla sin tener material de firma.
///
/// # Errores
/// Los mismos errores de armado que [`preparar_regimen_para_ensayo`], incluido
/// [`ErrorRegimen::ClaveDeLaSolucionNoCoincide`] si la solución no es de `clave`.
pub fn preparar_regimen_con_clave_publica<F>(
    padres: PadresDag,
    slot_objetivo: u64,
    servicio: &mut ServicioPot,
    fuente: &F,
    clave: &ClavePublica,
    parametros: &ParametrosProductor,
    cuerpo: CuerpoProductor,
) -> Result<BloqueDag, ErrorRegimen<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    let candidato = ensamblar_regimen(
        padres,
        slot_objetivo,
        servicio,
        fuente,
        clave,
        parametros,
        cuerpo,
    )?;
    BloqueDag::nuevo(
        candidato.cabecera,
        candidato.justificacion,
        candidato.txs,
        candidato.testigos,
    )
    .map_err(ErrorRegimen::Formato)
}

/// PROD-2: candidata real sin sellar, para ensayar en el dueño de la cadena.
///
/// Conserva la solución, padres, identidad, coinbase y justificación del armado habitual.
/// El llamante debe depurar y ensayar antes de usar [`firmar_regimen_tras_ensayo`].
/// Deriva la clave pública y llama a [`preparar_regimen_con_clave_publica`].
///
/// # Errores
/// Los mismos errores de armado que [`producir_en_regimen_con_firmante`].
pub fn preparar_regimen_para_ensayo<F>(
    padres: PadresDag,
    slot_objetivo: u64,
    servicio: &mut ServicioPot,
    fuente: &F,
    clave: &SigningKey,
    parametros: &ParametrosProductor,
    cuerpo: CuerpoProductor,
) -> Result<BloqueDag, ErrorRegimen<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    let productor = clave_publica_de(clave);
    preparar_regimen_con_clave_publica(
        padres,
        slot_objetivo,
        servicio,
        fuente,
        &productor,
        parametros,
        cuerpo,
    )
}

/// Error de la puerta de ensayo anterior al firmante seguro.
#[derive(Debug, thiserror::Error)]
pub enum ErrorEnsayo<E: std::error::Error + 'static> {
    /// La candidata ya estaba sellada; no se ensaya después de firmar.
    #[error("la candidata de ensayo ya tiene sello")]
    CandidataSellada,
    /// El ensayo del cuerpo final falló: no se llama al firmante.
    #[error("ensayo: {0}")]
    Ensayo(E),
    /// Fallo del firmante seguro.
    #[error("firmante: {0}")]
    Firmante(FirmanteError),
    /// Fallo de formato del cuerpo.
    #[error("formato: {0}")]
    Formato(EncodingError),
}

/// PROD-2: ensaya exactamente el cuerpo final y solo entonces solicita el sello seguro.
///
/// `ensayar` debe aplicar la candidata sobre su misma base/contexto y devolver error si
/// encuentra algún descarte. No puede cambiarla; el sello se solicita sobre esos mismos bytes.
/// La API habitual sigue disponible hasta cablear esta puerta en el hilo del nodo.
///
/// # Errores
/// [`ErrorEnsayo`] si había sello, falla el ensayo, el formato o el firmante.
pub fn firmar_regimen_tras_ensayo<E: std::error::Error + 'static>(
    candidata: BloqueDag,
    clave: &SigningKey,
    firmante: &mut Firmante<'_>,
    ensayar: impl FnOnce(&BloqueDag) -> Result<(), E>,
) -> Result<ProductoFirmado, ErrorEnsayo<E>> {
    if candidata.cabecera.sello != [0; LONGITUD_FIRMA] {
        return Err(ErrorEnsayo::CandidataSellada);
    }
    ensayar(&candidata).map_err(ErrorEnsayo::Ensayo)?;
    let candidato = CandidatoPoST {
        cabecera: candidata.cabecera,
        justificacion: candidata.justificacion.clone(),
        txs: candidata.txs().to_vec(),
        testigos: candidata.testigos().to_vec(),
    };
    finalizar_con_firmante(candidato, clave, firmante).map_err(|e| match e {
        ErrorSellado::Firmante(e) => ErrorEnsayo::Firmante(e),
        ErrorSellado::Formato(e) => ErrorEnsayo::Formato(e),
    })
}

/// Valida el rango, avanza el servicio y ensambla cabecera (sin sello) y cuerpo (coinbase v3).
///
/// Recibe la **clave pública** del productor: la solución tiene que ser de ella y la coinbase
/// le paga a ella (C-HDR-04 y F-09). No necesita ninguna clave privada.
#[allow(
    clippy::too_many_arguments,
    reason = "mismos argumentos públicos del productor"
)]
fn ensamblar_regimen<F>(
    padres: PadresDag,
    slot_objetivo: u64,
    servicio: &mut ServicioPot,
    fuente: &F,
    productor: &ClavePublica,
    parametros: &ParametrosProductor,
    cuerpo: CuerpoProductor,
) -> Result<CandidatoPoST, ErrorRegimen<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    if padres.es_genesis() || padres.count() == 0 {
        return Err(ErrorRegimen::SinPadres);
    }
    if parametros.n_dev != servicio.n_dev() {
        return Err(ErrorRegimen::NDevDiscrepante {
            productor: parametros.n_dev,
            servicio: servicio.n_dev(),
        });
    }

    let seleccionado = padres.seleccionado();
    let slot_sp =
        servicio
            .slot_de(&seleccionado)
            .ok_or(ErrorRegimen::PadreSeleccionadoDesconocido {
                padre: seleccionado,
            })?;
    // `C-HDR-05`/`C-FLU-02` fijan la cota de slot **no estricta** `slot(p) <= slot(B)` para todos
    // los padres. El caso `d = 0` (mismo slot que un padre seleccionado **no terminal**) es válido y
    // `pot_rango` lo verifica con justificación vacía anclada en la salida del mismo slot: es la
    // forma natural de encadenar hermanos de un mismo slot (varios productores compiten por el
    // mismo slot y el más lento solo puede construir sobre el bloque del más rápido).
    //
    // La única excepción es el **bloque de transición**: si el padre seleccionado es el terminal
    // (`s_0`), la puerta conjunta exige `slot(B) > s_0` (`TransicionSinProgresoDeSlot`), así que el
    // productor mantiene ahí la cota estricta. Antes de W08c el productor exigía `slot(B) > slot(sp)`
    // siempre, más estricto que el verificador, y descartaba todos sus candidatos con
    // `SlotNoProgreso` en cuanto otro nodo producía antes en el mismo slot.
    let hacia_el_terminal = seleccionado == servicio.terminal();
    if slot_objetivo < slot_sp || (hacia_el_terminal && slot_objetivo == slot_sp) {
        return Err(ErrorRegimen::SlotNoProgreso {
            slot: slot_objetivo,
            slot_sp,
        });
    }
    let d = slot_objetivo - slot_sp;
    if d > MAX_BUNDLES_POT as u64 {
        return Err(ErrorRegimen::RangoExcedeMaximo {
            d,
            max: MAX_BUNDLES_POT as u64,
        });
    }

    // El slot objetivo puede estar ya calculado (hermanos del mismo slot) o por delante.
    if servicio.slot_actual() < slot_objetivo {
        servicio.avanzar_hasta(slot_objetivo)?;
    }
    let salida = servicio.salida_de(slot_objetivo)?;
    // Ancla del segundo VDF: la salida del **padre seleccionado** (`slot(sp)`), que está en
    // `past(B)` ya validado. No se usa `slot_objetivo − 1` porque el productor puede saltar slots y
    // ese hueco no tendría salida registrada en el verificador (`C-RLJ-VDF-03` exige que el ancla
    // esté en el pasado).
    let salida_anterior = servicio.salida_de(slot_sp)?;

    let candidatas = fuente
        .soluciones(salida, slot_objetivo, parametros.sr_dev)
        .map_err(ErrorRegimen::Fuente)?;
    let Some(candidata) = candidatas.into_iter().next() else {
        return Err(ErrorRegimen::SinSolucion {
            slot: slot_objetivo,
        });
    };

    // C-HDR-04 y F-09: la solución debe ser de la clave que firma y paga la coinbase.
    if candidata.solucion.public_key != *productor {
        return Err(ErrorRegimen::ClaveDeLaSolucionNoCoincide {
            solucion: candidata.solucion.public_key,
            firma: *productor,
        });
    }

    // Justificación del rango `(slot(sp), slot(B)]` con `D = 0`. Con `d = 0` la lista vacía canónica
    // (`JustificacionPot::vacia`) es la justificación correcta: `pot_rango` ancla en la salida del
    // mismo slot en vez de declarar un rango vacío por omisión. `portadores_para` rechaza `d = 0`
    // (`completar_portadores` devuelve `RangoInvalido`), así que se evita esa llamada.
    let justificacion = if d == 0 {
        JustificacionPot::vacia()
    } else {
        JustificacionPot::nueva(servicio.portadores_para(slot_sp, slot_objetivo)?)?
    };

    // Coinbase v3 con **el slot de este bloque** (F-17).
    let coinbase = Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave: *productor,
            importe: parametros.importe_coinbase,
            slot: slot_objetivo,
        },
    };
    let CuerpoProductor {
        txs: cuerpo_txs,
        testigos: cuerpo_testigos,
    } = cuerpo;
    let mut txs = Vec::with_capacity(cuerpo_txs.len() + 1);
    txs.push(coinbase);
    txs.extend(cuerpo_txs);
    let mut testigos = Vec::with_capacity(cuerpo_testigos.len() + 1);
    testigos.push(Vec::new());
    testigos.extend(cuerpo_testigos);

    let txids: Vec<_> = txs
        .iter()
        .map(|t| txid(t, parametros.consensus_branch_id))
        .collect();
    let merkle_root = merkle_root(&txids);
    let body_commitment = body_commitment(&txs, &testigos, parametros.consensus_branch_id)?;

    let vdf_output = if parametros.i_iter == 0 {
        [0u8; 16]
    } else {
        crate::reloj_post::calcular_v_j(salida_anterior, slot_objetivo, parametros.i_iter)?
    };

    let cabecera = DagBlockHeader {
        vdf_output,
        consensus_branch_id: parametros.consensus_branch_id,
        merkle_root,
        timestamp: parametros.timestamp,
        // F-03: el campo `height` de la cabecera PoST está reservado y MUST ser 0 en v0.
        height: 0,
        slot: slot_objetivo,
        pot_output: salida,
        rango_solucion: parametros.sr_dev,
        sol: candidata.solucion,
        body_commitment,
        padres,
        sello: [0u8; LONGITUD_FIRMA],
    };

    Ok(CandidatoPoST {
        cabecera,
        justificacion,
        txs,
        testigos,
    })
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests usan expect por diseño")]
mod pruebas {
    use zx_core::{ExtensionTx, Tx, TxId};

    use super::{CuerpoProductor, ErrorCuerpo};

    /// Transacción **de efecto** v1 (con una entrada): no es coinbase.
    fn tx_v1(min: u8) -> Tx {
        Tx {
            version: 1,
            inputs: vec![zx_core::TxIn {
                outpoint: zx_core::OutPoint {
                    prev_txid: TxId::from_digest(zx_core::digest::Digest::from_bytes([min; 32])),
                    prev_index: 0,
                },
                sequence: 0,
            }],
            outputs: vec![zx_core::TxOut {
                value: zx_core::Amount::nuevo(i64::from(min)).expect("importe"),
                lock: zx_core::Lock::PubKey {
                    pubkey: zx_core::ClavePublica::desde_bytes([min; 32]),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        }
    }

    fn tx_v3() -> Tx {
        Tx {
            version: 3,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::CoinbasePost {
                clave: zx_core::ClavePublica::desde_bytes([9; 32]),
                importe: zx_core::Amount::nuevo(1).expect("importe"),
                slot: 1,
            },
        }
    }

    #[test]
    fn el_cuerpo_vacio_solo_lleva_la_coinbase() {
        let c = CuerpoProductor::vacio();
        assert!(c.esta_vacio());
        assert!(c.txs().is_empty());
        assert!(c.testigos().is_empty());
    }

    #[test]
    fn descuadre_y_coinbase_se_rechazan() {
        let tx = tx_v1(1);
        assert_eq!(
            CuerpoProductor::nuevo(vec![tx.clone()], Vec::new()),
            Err(ErrorCuerpo::Descuadre {
                txs: 1,
                testigos: 0
            })
        );
        assert_eq!(
            CuerpoProductor::nuevo(vec![tx], vec![Vec::new()])
                .expect("cuerpo válido")
                .txs()
                .len(),
            1
        );
        assert_eq!(
            CuerpoProductor::nuevo(vec![tx_v3()], vec![Vec::new()]),
            Err(ErrorCuerpo::CoinbaseEnCuerpo { indice: 0 })
        );
    }
}

/// P2 (PROD-3c): la preparación con clave pública produce la misma candidata que la de la
/// privada, y con una clave que no es la de la solución devuelve el mismo error que hoy.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]
mod pruebas_clave_publica {
    use ed25519_zebra::SigningKey;
    use zx_core::preimage::dag::{PadresDag, SolucionPoas};
    use zx_core::{Amount, BlockHash, ClavePublica, Digest};

    use super::{
        CuerpoProductor, ErrorRegimen, clave_publica_de, preparar_regimen_con_clave_publica,
        preparar_regimen_para_ensayo,
    };
    use crate::productor::{FuenteSoluciones, ParametrosProductor, SolucionCandidata};
    use crate::servicio_pot::ServicioPot;

    const N_DEV: u64 = 2_048;
    const VENTANA: u64 = 64;
    const SR_DEV: u64 = u64::MAX;

    fn terminal() -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([7; 32]))
    }

    fn sk(semilla: u8) -> SigningKey {
        SigningKey::from([semilla; 32])
    }

    fn pk_de(semilla: u8) -> ClavePublica {
        clave_publica_de(&sk(semilla))
    }

    /// Fuente fija: siempre devuelve la misma solución, de la clave `public_key`.
    struct FuenteFija {
        public_key: ClavePublica,
    }

    impl FuenteSoluciones for FuenteFija {
        type Error = std::convert::Infallible;

        fn soluciones(
            &self,
            _salida: [u8; 16],
            _slot: u64,
            _rango: u64,
        ) -> Result<Vec<SolucionCandidata>, Self::Error> {
            Ok(vec![SolucionCandidata {
                solucion: SolucionPoas {
                    public_key: self.public_key,
                    sector_index: 1,
                    history_size: 1 << 20,
                    chunk: [0x2a; 32],
                    ..SolucionPoas::default()
                },
                distancia: 1,
            }])
        }
    }

    fn parametros() -> ParametrosProductor {
        ParametrosProductor {
            n_dev: N_DEV,
            sr_dev: SR_DEV,
            max_slots: 16,
            consensus_branch_id: zx_core::CBID_RED_DEV,
            timestamp: 1_700_000_000,
            i_iter: 0,
            importe_coinbase: Amount::nuevo(5).expect("importe"),
        }
    }

    fn preparar_con_publica(
        pk: &ClavePublica,
        slot: u64,
    ) -> Result<zx_core::wire_dag::BloqueDag, ErrorRegimen<std::convert::Infallible>> {
        let mut servicio = ServicioPot::nuevo(terminal(), N_DEV, VENTANA).expect("servicio");
        let padres = PadresDag::nuevo(terminal(), &[]).expect("padres");
        // La solución es **siempre** de la clave 42 (la buena); `pk` es la del armado.
        let fuente = FuenteFija {
            public_key: pk_de(42),
        };
        preparar_regimen_con_clave_publica(
            padres,
            slot,
            &mut servicio,
            &fuente,
            pk,
            &parametros(),
            CuerpoProductor::vacio(),
        )
    }

    fn preparar_con_privada(
        sk: &SigningKey,
        slot: u64,
    ) -> Result<zx_core::wire_dag::BloqueDag, ErrorRegimen<std::convert::Infallible>> {
        let mut servicio = ServicioPot::nuevo(terminal(), N_DEV, VENTANA).expect("servicio");
        let padres = PadresDag::nuevo(terminal(), &[]).expect("padres");
        // La solución es **siempre** de la clave 42 (la buena); `sk` es la del firmante.
        let fuente = FuenteFija {
            public_key: pk_de(42),
        };
        preparar_regimen_para_ensayo(
            padres,
            slot,
            &mut servicio,
            &fuente,
            sk,
            &parametros(),
            CuerpoProductor::vacio(),
        )
    }

    /// P2(a): la función nueva produce la misma candidata (mismos bytes, mismo `pre_hash`) que
    /// `preparar_regimen_para_ensayo` con la privada correspondiente.
    #[test]
    fn p2a_clave_publica_misma_candidata_mismo_pre_hash() {
        let slot = 1;
        let por_publica = preparar_con_publica(&pk_de(42), slot).expect("con clave pública");
        let por_privada = preparar_con_privada(&sk(42), slot).expect("con clave privada");
        assert_eq!(
            por_publica.cabecera.pre_hash(),
            por_privada.cabecera.pre_hash(),
            "mismo pre_hash"
        );
        assert_eq!(
            por_publica.cabecera.prefirma(),
            por_privada.cabecera.prefirma(),
            "mismos bytes de cabecera sin sello"
        );
        assert_eq!(por_publica.txs(), por_privada.txs(), "mismo cuerpo");
        assert_eq!(
            por_publica.testigos(),
            por_privada.testigos(),
            "mismos testigos"
        );
        assert_eq!(por_publica.cabecera.sello, [0; 64], "sin sello");
    }

    /// P2(b): con una clave pública que no es la de la solución devuelve el mismo error que hoy
    /// (`ClaveDeLaSolucionNoCoincide`), idéntico al de la privada equivocada.
    #[test]
    fn p2b_clave_publica_ajena_mismo_error_que_hoy() {
        let slot = 1;
        let buena = pk_de(42);
        let ajena = pk_de(7);
        assert_ne!(buena, ajena);
        // La solución es de la clave 42; se pide armar con la pública de la 7.
        let mut servicio = ServicioPot::nuevo(terminal(), N_DEV, VENTANA).expect("servicio");
        let padres = PadresDag::nuevo(terminal(), &[]).expect("padres");
        let fuente = FuenteFija { public_key: buena };
        let err_pub = preparar_regimen_con_clave_publica(
            padres,
            slot,
            &mut servicio,
            &fuente,
            &ajena,
            &parametros(),
            CuerpoProductor::vacio(),
        )
        .expect_err("clave pública ajena");
        // El mismo error que hoy con la privada ajena.
        let err_priv = preparar_con_privada(&sk(7), slot).expect_err("clave privada ajena");
        match (&err_pub, &err_priv) {
            (
                ErrorRegimen::ClaveDeLaSolucionNoCoincide {
                    solucion: s1,
                    firma: f1,
                },
                ErrorRegimen::ClaveDeLaSolucionNoCoincide {
                    solucion: s2,
                    firma: f2,
                },
            ) => {
                assert_eq!(s1, s2);
                assert_eq!(f1, f2);
                assert_eq!(*f1, ajena);
                assert_eq!(*s1, buena);
            }
            (a, b) => panic!("se esperaba ClaveDeLaSolucionNoCoincide, llegó {a:?} / {b:?}"),
        }
        // Y también con una `ClavePublica` arbitraria distinta de la solución.
        let otra = ClavePublica::desde_bytes([9; 32]);
        let err_otra = preparar_con_publica(&otra, slot).expect_err("clave arbitraria");
        assert!(
            matches!(err_otra, ErrorRegimen::ClaveDeLaSolucionNoCoincide { .. }),
            "{err_otra:?}"
        );
    }
}
