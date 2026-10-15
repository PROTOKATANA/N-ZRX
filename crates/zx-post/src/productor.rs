//! Productor del **bloque de transición** PoST hijo de un terminal dev (`C-POT-03`, `C-POT-05`,
//! `C-HDR-03`, `C-HDR-04`, `C-HDR-09`, `C-BON-03`, F-03, F-09, D-P09…D-P11).
//!
//! # Qué produce
//!
//! Dado el terminal PoW `T`, una fuente de soluciones PoAS (el puente real a `zx-farmer` lo aporta
//! el llamante), una clave Ed25519 dev y los parámetros de desarrollo, [`producir_sin_firmante`]:
//!
//! 1. arranca el PoT desde S1 (`semilla(f_0, 0)`, D-P09) y **calcula el PoT slot a slot** desde S1
//!    con `N_dev` ([`zx_pot::prove`]);
//! 2. para cada slot `s`, deriva la salida `salida(f, s)` y **audita la parcela** por
//!    [`FuenteSoluciones::soluciones`], que recibe `(salida, slot, rango)` —la fuente deriva el reto
//!    con `zx_poas::reto_desde_salida(salida, slot)`, la función que la revisión W05b1 ordena
//!    reutilizar— hasta hallar una solución verificada;
//! 3. con la primera solución construye la cabecera: `padres = [T]`, `height = 0` (F-03), `slot`,
//!    `pot_output = salida(f, s)`, la **justificación** con los portadores de los slots 1..=s, el
//!    rango `SR_dev`, los campos de la solución, el compromiso del cuerpo de una **coinbase v3**
//!    pagada a la clave (`F-09`), y el **sello** Ed25519 sobre la prefirma (`C-HDR-04`);
//! 4. devuelve el [`BloqueDag`] completo con su cuerpo.
//!
//! # Lo que NO hace
//!
//! No elige `SR` desde el pasado (usa la constante dev, D-P11), no aplica el controlador de rango,
//! no elige padres con GHOSTDAG (el de transición es hijo único de `T`), no firma con una clave de
//! red, no publica y no admite. No arranca desde génesis: el terminal lo aporta el llamante.
//!
//! # Firmante seguro (SL-4b1, SL-4b3)
//!
//! [`producir_sin_firmante`] sella directamente y **no** protege contra la doble firma: **solo para
//! tests y arneses**; el nodo ya no la alcanza (SL-4b2 lo dejó fuera y SL-4b3 lo hace explícito con
//! un guardián de CI). La variante [`producir_con_firmante`] construye **exactamente** la misma
//! cabecera y el mismo cuerpo y los sella **solo** a través de [`Firmante`], que persiste
//! `(identidad, slot) -> pre_hash` con `fsync` antes de emitir el sello (`C-EVP-06`, FIR-01…FIR-15).
//!
//! # Por qué la parcela es un rasgo
//!
//! La frontera §V8 `zx-post → {zx-core, zx-pot, zx-dag, zx-poas}` **no** incluye `zx-farmer`, pero
//! §3.6 pide al productor usar una parcela. [`FuenteSoluciones`] abstrae ese puente: el test de
//! extremo a extremo lo implementa sobre `zx_farmer::ParcelaDisco` (dev-dependency) y W06 lo
//! aportará en el nodo. Así el crate de producción respeta la frontera explícita.
//!
//! # Frontera de confianza
//!
//! [`SolucionCandidata`] afirma que la solución verificó **contra las entradas proporcionadas**: el
//! mismo `slot`, la misma salida y el mismo `rango`. La fuente no acredita la procedencia causal de
//! esas entradas; la puerta conjunta ([`crate::cabecera_conjunta`]) las vuelve a comprobar con su
//! propio contexto. Producir no es admitir.

use core::num::NonZeroU32;

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::firma::LONGITUD_FIRMA;
use zx_core::preimage::block::merkle_root;
use zx_core::wire_dag::{BloqueDag, JustificacionPot, MAX_BUNDLES_POT, PotCheckpoints};
use zx_core::{
    Amount, BlockHash, ClavePublica, DagBlockHeader, EncodingError, ExtensionTx, PadresDag,
    PreHash, SolucionPoas, Tx, body_commitment, txid,
};
use zx_pot::tipos::PotSeed;

use crate::firmante::{Firmante, FirmanteError, Resultado as ResultadoFirmante};
use crate::pot::{
    ErrorContextoPot, checkpoints_a_wire, proyectar_iteraciones, semilla_genesis, semilla_siguiente,
};

/// Una solución PoAS ya verificada contra `(salida, slot, rango)` por la fuente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolucionCandidata {
    /// La solución verificada.
    pub solucion: SolucionPoas,
    /// Distancia de solución que devolvió la primitiva.
    pub distancia: u64,
}

/// Fuente de soluciones PoAS para un `(salida, slot, rango)`.
///
/// El contrato de una implementación de producción es auditar la parcela con el reto
/// `zx_poas::reto_desde_salida(salida, slot)` y verificar cada candidato con
/// `zx_poas::verificar_solucion_poas`. Un vector vacío significa «sin candidato», **no** error.
pub trait FuenteSoluciones {
    /// Error de la fuente (auditoría, conversión, lectura de disco…).
    type Error;

    /// Soluciones verificadas para ese `(salida, slot, rango)`.
    ///
    /// # Errores
    /// El error propio de la fuente.
    fn soluciones(
        &self,
        salida: [u8; 16],
        slot: u64,
        rango: u64,
    ) -> Result<Vec<SolucionCandidata>, Self::Error>;
}

/// Parámetros de desarrollo del productor. **No** son parámetros de red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParametrosProductor {
    /// `N_dev`: iteraciones AES por slot (D-P10).
    pub n_dev: u64,
    /// `SR_dev`: rango de solución constante (D-P11).
    pub sr_dev: u64,
    /// Máximo de slots a barrer; los portadores de la justificación lo acotan a 150 (`C-HDR-07`).
    pub max_slots: u64,
    /// Rama de consenso (red dev).
    pub consensus_branch_id: u32,
    /// `timestamp` declarado por la cabecera.
    pub timestamp: u64,
    /// Longitud del segundo VDF (`I_iter`, `C-RLJ-VDF-02`). `0` = sin segundo VDF (fixtures y
    /// bloques pre-reloj): el campo `vdf_output` de la cabecera queda a ceros.
    pub i_iter: u64,
    /// Importe de la coinbase v3 (`> 0`, F-09 / R-8).
    pub importe_coinbase: Amount,
}

/// Motivo por el que un productor con firmante **no** emite bloque.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MotivoAbstencion {
    /// El firmante ya registró otro `pre_hash` para esta identidad y slot: el candidato se
    /// descarta y no se sella.
    Conflicto {
        /// El `pre_hash` que ya estaba registrado.
        pre_hash_registrado: PreHash,
    },
    /// El registro se perdió y el firmante sigue en su ventana de abstención (FIR-10).
    PerdidaRegistro {
        /// Último slot en el que todavía se abstiene.
        hasta: u64,
        /// `s_max_slots` del perfil con el que se abrió el registro.
        s_max_slots: u64,
    },
}

/// Lo que devuelve un productor que sella a través de [`Firmante`].
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "el bloque es el producto normal; boxearlo obligaría a desempaquetar en cada llamante sin ganancia medible"
)]
pub enum ProductoFirmado {
    /// Se ensambló y selló el bloque. El segundo campo es el veredicto del firmante: `Sellado`
    /// (entrada nueva) o `Reemitido` (mismo `pre_hash`).
    Bloque(BloqueDag, ResultadoFirmante),
    /// El firmante se abstuvo: no se emitió bloque y el candidato se descarta.
    Abstenido {
        /// Slot de la oportunidad que se descartó (`header.slot` del candidato). `ORDEN-SL4b3`: el
        /// llamante lo necesita para el evento `firmante_abstenido` cuando no tiene el candidato
        /// (la transición producida por `Nodo::producir_bloque_transicion`).
        slot: u64,
        /// Causa de la abstención.
        motivo: MotivoAbstencion,
    },
}

/// Traduce el veredicto del firmante a un motivo de abstención, si lo hay.
fn motivo_de(resultado: ResultadoFirmante) -> Option<MotivoAbstencion> {
    match resultado {
        ResultadoFirmante::Sellado | ResultadoFirmante::Reemitido => None,
        ResultadoFirmante::AbstenidoPorConflicto {
            pre_hash_registrado,
        } => Some(MotivoAbstencion::Conflicto {
            pre_hash_registrado,
        }),
        ResultadoFirmante::AbstenidoPorPerdida { hasta, s_max_slots } => {
            Some(MotivoAbstencion::PerdidaRegistro { hasta, s_max_slots })
        }
    }
}

/// Fallo al producir el bloque de transición.
#[derive(Debug, thiserror::Error)]
pub enum ErrorProductor<E>
where
    E: std::error::Error + 'static,
{
    /// `N_dev` fuera del dominio de la primitiva.
    #[error("N_dev inválido: {0}")]
    NDevInvalido(#[from] ErrorContextoPot),
    /// `max_slots` fuera de `1..=150`.
    #[error("max_slots {declarados} fuera de 1..={maximo}")]
    MaxSlotsFueraDeRango {
        /// Valor pedido.
        declarados: u64,
        /// `MAX_BUNDLES_POT`.
        maximo: u64,
    },
    /// La primitiva PoT rechazó la terna (no debería ocurrir con `N_dev` válido).
    #[error("la primitiva PoT rechazó el slot: {0}")]
    Pot(#[from] zx_pot::PotError),
    /// La solución no está sellada por la clave que firma: violaría `C-HDR-04` y F-09.
    #[error("la solución no es de la clave que firma: solución {solucion:?}, firma {firma:?}")]
    ClaveDeLaSolucionNoCoincide {
        /// Clave de la solución.
        solucion: ClavePublica,
        /// Clave del firmante.
        firma: ClavePublica,
    },
    /// `zx-core` rechazó el formato (padres o compromiso del cuerpo).
    #[error("formato del bloque: {0}")]
    Formato(#[from] EncodingError),
    /// Fallo del firmante (clave ajena, sello inválido o E/S del registro).
    #[error("firmante: {0}")]
    Firmante(#[from] FirmanteError),
    /// Fallo de la fuente de soluciones.
    #[error("fuente de soluciones: {0}")]
    Fuente(#[source] E),
    /// No apareció ninguna solución en la ventana barrida.
    #[error("sin solución PoAS en los primeros {hasta_slot} slots")]
    SinSolucion {
        /// Último slot barrido.
        hasta_slot: u64,
    },
    /// El segundo VDF no se pudo calcular (`C-RLJ-VDF-02`).
    #[error("segundo VDF del productor: {0}")]
    Vdf(#[from] crate::reloj_post::ErrorVdfPost),
}

/// Fallo interno del sellado, común a las dos rutas del productor.
#[derive(Debug)]
pub(crate) enum ErrorSellado {
    /// El firmante rechazó el candidato.
    Firmante(FirmanteError),
    /// `zx-core` rechazó el bloque ensamblado.
    Formato(EncodingError),
}

impl<E> From<ErrorSellado> for ErrorProductor<E>
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

/// Candidato PoST ensamblado **sin sello**: cabecera con `sello = 0`, justificación y cuerpo.
///
/// La construcción vive aquí una sola vez; las dos rutas de sellado ([`finalizar_directo`] y
/// [`finalizar_con_firmante`]) la comparten para que el bloque sea idéntico byte a byte.
pub(crate) struct CandidatoPoST {
    /// Cabecera con `sello = [0; 64]`.
    pub(crate) cabecera: DagBlockHeader,
    /// Justificación del rango de slots.
    pub(crate) justificacion: JustificacionPot,
    /// Transacciones (la primera es la coinbase).
    pub(crate) txs: Vec<Tx>,
    /// Testigos paralelos a `txs`.
    pub(crate) testigos: Vec<Vec<Vec<u8>>>,
}

/// Sella directamente el candidato con la clave (ruta antigua, sin firmante seguro).
pub(crate) fn finalizar_directo(
    candidato: CandidatoPoST,
    clave: &SigningKey,
) -> Result<BloqueDag, ErrorSellado> {
    let CandidatoPoST {
        mut cabecera,
        justificacion,
        txs,
        testigos,
    } = candidato;
    let pre_hash = cabecera.pre_hash();
    cabecera.sello = clave.sign(pre_hash.as_bytes()).into();
    BloqueDag::nuevo(cabecera, justificacion, txs, testigos).map_err(ErrorSellado::Formato)
}

/// Sella el candidato **solo** a través del firmante seguro y traduce su veredicto.
pub(crate) fn finalizar_con_firmante(
    candidato: CandidatoPoST,
    clave: &SigningKey,
    firmante: &mut Firmante<'_>,
) -> Result<ProductoFirmado, ErrorSellado> {
    let CandidatoPoST {
        mut cabecera,
        justificacion,
        txs,
        testigos,
    } = candidato;
    // El slot de la oportunidad se conserva antes de que `firmar` pueda negarse: el llamante lo
    // necesita para registrar la abstención (SL-4b3).
    let slot = cabecera.slot;
    let resultado = firmante
        .firmar(&mut cabecera, clave)
        .map_err(ErrorSellado::Firmante)?;
    match motivo_de(resultado) {
        Some(motivo) => Ok(ProductoFirmado::Abstenido { slot, motivo }),
        None => {
            let bloque = BloqueDag::nuevo(cabecera, justificacion, txs, testigos)
                .map_err(ErrorSellado::Formato)?;
            Ok(ProductoFirmado::Bloque(bloque, resultado))
        }
    }
}

/// Produce el primer bloque PoST hijo de `terminal` (D-P09…D-P11, F-03, F-09).
///
/// **Solo tests y arneses; no protege contra la doble firma.** Sella directamente con `clave` sin
/// consultar registro alguno. El nodo produce **solo** con [`producir_con_firmante`] (SL-4b2/SL-4b3);
/// `ci/firmante-obligatorio.sh` comprueba que `crates/zx-node/src/` no invoca esta ruta.
///
/// # Procedimiento
/// Arranca de S1, avanza el PoT slot a slot con `N_dev` y, en cada slot, pide a `fuente` las
/// soluciones verificadas. Con la primera, ensambla cabecera y cuerpo, sella y devuelve el bloque.
///
/// # Errores
/// [`ErrorProductor::NDevInvalido`], [`ErrorProductor::MaxSlotsFueraDeRango`],
/// [`ErrorProductor::Pot`], [`ErrorProductor::Fuente`], [`ErrorProductor::Formato`],
/// [`ErrorProductor::ClaveDeLaSolucionNoCoincide`] o [`ErrorProductor::SinSolucion`].
pub fn producir_sin_firmante<F>(
    terminal: BlockHash,
    fuente: &F,
    clave: &SigningKey,
    parametros: &ParametrosProductor,
) -> Result<BloqueDag, ErrorProductor<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    let candidato = ensamblar(terminal, fuente, clave, parametros)?;
    finalizar_directo(candidato, clave).map_err(ErrorProductor::from)
}

/// Produce el primer bloque PoST hijo de `terminal` sellándolo **solo** con `firmante` (SL-4b1).
///
/// Construye exactamente el mismo candidato que [`producir_sin_firmante`] y lo sella por
/// [`Firmante::firmar`]. Devuelve [`ProductoFirmado::Abstenido`] cuando el firmante se niega
/// (conflicto o pérdida de registro) y [`ProductoFirmado::Bloque`] con su veredicto cuando sella.
///
/// # Errores
/// Los mismos que [`producir_sin_firmante`], más [`ErrorProductor::Firmante`] para un fallo real del
/// registro (E/S, envenenamiento, corrupción), la clave ajena o un sello inválido.
pub fn producir_con_firmante<F>(
    terminal: BlockHash,
    fuente: &F,
    clave: &SigningKey,
    parametros: &ParametrosProductor,
    firmante: &mut Firmante<'_>,
) -> Result<ProductoFirmado, ErrorProductor<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    let candidato = ensamblar(terminal, fuente, clave, parametros)?;
    finalizar_con_firmante(candidato, clave, firmante).map_err(ErrorProductor::from)
}

/// Barre los slots desde S1 y ensambla el primer candidato con solución.
fn ensamblar<F>(
    terminal: BlockHash,
    fuente: &F,
    clave: &SigningKey,
    parametros: &ParametrosProductor,
) -> Result<CandidatoPoST, ErrorProductor<F::Error>>
where
    F: FuenteSoluciones,
    F::Error: std::error::Error + 'static,
{
    let iteraciones: NonZeroU32 = proyectar_iteraciones(parametros.n_dev)?;
    if parametros.max_slots == 0 || parametros.max_slots > MAX_BUNDLES_POT as u64 {
        return Err(ErrorProductor::MaxSlotsFueraDeRango {
            declarados: parametros.max_slots,
            maximo: MAX_BUNDLES_POT as u64,
        });
    }

    let productor = ClavePublica::desde_bytes(VerificationKey::from(clave).into());

    // S1: salida confiada del slot 0 (D-P09). Es el **ancla** del segundo VDF del bloque de
    // transición: el único bloque de `past(B)` es el terminal en el slot 0.
    let mut salida = semilla_genesis(&terminal, &[]);
    let ancla_vdf = salida;
    let mut portadores: Vec<PotCheckpoints> = Vec::new();

    for slot in 1..=parametros.max_slots {
        // Sin inyecciones en dev: la semilla del slot es la salida anterior tal cual.
        let semilla = semilla_siguiente(salida, None);
        let carrier = zx_pot::prove(PotSeed::from(semilla), iteraciones)?;
        salida = *carrier.output();
        portadores.push(checkpoints_a_wire(&carrier));

        let candidatas = fuente
            .soluciones(salida, slot, parametros.sr_dev)
            .map_err(ErrorProductor::Fuente)?;
        let Some(candidata) = candidatas.into_iter().next() else {
            continue;
        };

        // C-HDR-04 y F-09: la solución debe ser de la clave que firma y paga la coinbase.
        if candidata.solucion.public_key != productor {
            return Err(ErrorProductor::ClaveDeLaSolucionNoCoincide {
                solucion: candidata.solucion.public_key,
                firma: productor,
            });
        }

        return construir_sin_sello(
            terminal,
            parametros,
            slot,
            salida,
            ancla_vdf,
            portadores,
            candidata.solucion,
        );
    }

    Err(ErrorProductor::SinSolucion {
        hasta_slot: parametros.max_slots,
    })
}

/// Ensambla cabecera (sin sello) y cuerpo (coinbase v3) del candidato.
fn construir_sin_sello<E>(
    terminal: BlockHash,
    parametros: &ParametrosProductor,
    slot: u64,
    pot_output: [u8; 16],
    salida_anterior: [u8; 16],
    portadores: Vec<PotCheckpoints>,
    solucion: SolucionPoas,
) -> Result<CandidatoPoST, ErrorProductor<E>>
where
    E: std::error::Error + 'static,
{
    let productor = solucion.public_key;
    // Coinbase v3 (F-05, F-09, F-17): sin entradas ni salidas, campos extra `clave ‖ importe ‖
    // slot`, con el slot de **esta** cabecera (el que se le pasa a `construir_sin_sello`).
    let coinbase = Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave: productor,
            importe: parametros.importe_coinbase,
            slot,
        },
    };
    // El `txid` de la coinbase se calcula antes de moverla al vector del cuerpo.
    let txid_coinbase = txid(&coinbase, parametros.consensus_branch_id);
    let txs = vec![coinbase];
    let testigos: Vec<Vec<Vec<u8>>> = vec![Vec::new()];
    let txids = vec![txid_coinbase];
    let merkle_root = merkle_root(&txids);
    let body_commitment = body_commitment(&txs, &testigos, parametros.consensus_branch_id)?;

    let vdf_output = if parametros.i_iter == 0 {
        [0u8; 16]
    } else {
        crate::reloj_post::calcular_v_j(salida_anterior, slot, parametros.i_iter)?
    };

    let cabecera = DagBlockHeader {
        vdf_output,
        consensus_branch_id: parametros.consensus_branch_id,
        merkle_root,
        timestamp: parametros.timestamp,
        // F-03: el campo `height` de la cabecera PoST está reservado y MUST ser 0 en v0.
        height: 0,
        slot,
        pot_output,
        rango_solucion: parametros.sr_dev,
        sol: solucion,
        body_commitment,
        padres: PadresDag::nuevo(terminal, &[])?,
        sello: [0u8; LONGITUD_FIRMA],
    };

    let justificacion = JustificacionPot::nueva(portadores)?;
    Ok(CandidatoPoST {
        cabecera,
        justificacion,
        txs,
        testigos,
    })
}

/// La clave pública Ed25519 que firmará el bloque de una `SigningKey` dada.
///
/// Es la misma clave que la solución PoAS debe tener en `sol.public_key` para que sello y coinbase
/// sean coherentes (`C-HDR-04`, F-09).
#[must_use]
pub fn clave_publica_de(clave: &SigningKey) -> ClavePublica {
    ClavePublica::desde_bytes(VerificationKey::from(clave).into())
}
