//! Tipos del motor de transición (`ORDEN-W03` §3.2–§3.5, `CONTRATO-v0` §1–§3).
//!
//! Se usan los tipos **reales** de `zx-core`: transacciones v1/v2/v3, `OutPoint`, `ClavePublica`,
//! `Lock`, `Amount`, `BlockHash`. Las únicas adiciones locales son las que la orden fija con nombre
//! propio (`HechosCabecera`, `BloqueTransicion`, `ParametrosTransicion`, `Estado`, `Undo`).

use std::collections::{BTreeMap, BTreeSet};

use primitive_types::U256;
use zx_core::{
    Amount, BlockHash, ClavePublica, ClaveTablaVoto, DagBlockHeader, Lock, OutPoint, Tx, TxId,
};

use crate::cajas::{CajaId, RegistroCaja};
use crate::sectores::{
    ClaveVoto, ClaveVotoAnterior, ParametrosSector, PorepVigente, PruebaVigente, RegistroSector,
    SectorId,
};
use crate::transicion::ErrorTransicion;

/// TB-1a · R1 · `K_TABLAS_VOTO` · tamaño máximo de la cola de tablas derivadas `Q` del estado.
///
/// Pares `(ventana, huella)` en orden de inserción; al añadir uno por encima del tope se descarta el
/// más antiguo (T1).
pub const K_TABLAS_VOTO: usize = 16;

/// Lo que las verificaciones de cabecera, **que no son de esta orden**, ya decidieron (§3.2).
///
/// El motor no comprueba PoW, PoT, PoAS ni sellos: recibe el veredicto. Lo único que mira es que los
/// indicadores `pow_valido`/`prueba_valida` sean verdaderos y usa el resto de campos para la
/// transición.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HechosCabecera {
    /// Bloque génesis: solo su hash. La coinbase constructiva la valida `aplicar_genesis`.
    Genesis {
        /// `block_hash` del génesis.
        hash: BlockHash,
    },
    /// Bloque de la fase PoW de arranque.
    PoW {
        /// `block_hash` del bloque.
        hash: BlockHash,
        /// `block_hash` del padre.
        padre: BlockHash,
        /// Altura declarada en la cabecera.
        altura: u32,
        /// Trabajo aportado por el bloque (`≥ 1`).
        trabajo: U256,
        /// Resultado de la verificación de PoW, ya decidida.
        pow_valido: bool,
    },
    /// Bloque `PoAS_PoT_DAG` (fase PoST).
    PoST {
        /// `block_hash` del bloque.
        hash: BlockHash,
        /// `block_hash` del padre seleccionado.
        padre: BlockHash,
        /// Índice de PoT del bloque (`≥ 1`).
        slot: u64,
        /// Clave del productor (`sol.public_key`).
        productor: ClavePublica,
        /// Peso PoST del bloque (`≥ 1`).
        peso: u128,
        /// Resultado de la verificación de sello/prueba, ya decidida.
        prueba_valida: bool,
        /// `requisito` declarado en la cabecera. Se ignora para decidir (`X-10`).
        requisito_declarado: u64,
    },
}

impl HechosCabecera {
    /// Hash del bloque.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        match self {
            Self::Genesis { hash } | Self::PoW { hash, .. } | Self::PoST { hash, .. } => *hash,
        }
    }

    /// Hash del padre, si el bloque tiene uno (el génesis no).
    #[must_use]
    pub const fn padre(&self) -> Option<BlockHash> {
        match self {
            Self::Genesis { .. } => None,
            Self::PoW { padre, .. } | Self::PoST { padre, .. } => Some(*padre),
        }
    }

    /// Altura de un bloque PoW, si la tiene.
    #[must_use]
    pub const fn altura(&self) -> Option<u32> {
        match self {
            Self::PoW { altura, .. } => Some(*altura),
            _ => None,
        }
    }

    /// Slot de un bloque PoST, si lo tiene.
    #[must_use]
    pub const fn slot(&self) -> Option<u64> {
        match self {
            Self::PoST { slot, .. } => Some(*slot),
            _ => None,
        }
    }

    /// Clave del productor de un bloque PoST, si la tiene.
    #[must_use]
    pub const fn productor(&self) -> Option<ClavePublica> {
        match self {
            Self::PoST { productor, .. } => Some(*productor),
            _ => None,
        }
    }
}

/// AT-1b · W2 · Hecho de la falta «voto contra la propia atadura» de una transacción `0x0B`
/// (contrato v2 B1). Lo calcula **`zx-cadena`** con sus propios datos (DAG y ventanas) y lo consume
/// [`crate::transicion::votos::aplicar_evidencia_votos_peso`] (W4).
///
/// `Inadmisible` es el valor por defecto: sin hecho (o `Inadmisible`) la evidencia de ventanas
/// distintas se descarta sin invalidar el bloque.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HechoVoto {
    /// No hay hecho (bloque sin cadena) o alguno de los dos bloques no está aplicado antes que `x`.
    #[default]
    Inadmisible,
    /// Los dos votos no constituyen la falta de la parte B (sin conflicto, fuera de `F` o justificados).
    SinFalta,
    /// Los dos votos constituyen la falta de la parte B: castigo del doble voto.
    Falta,
}

/// Un bloque de la transición: sus hechos de cabecera, sus transacciones con testigos y, para PoST,
/// la cabecera real si el llamante la tiene.
///
/// `txs` lleva cada transacción con **su lista de testigos** en el orden del wire.
///
/// El campo `cabecera_post` es una adición **aditiva** a §3.2 (ver `PROGRESO.md`, falta de
/// definición 2): permite llamar a `validar_forma_cabecera_post` (F-03) cuando el llamante construye
/// la cabecera real. Si es `None` el motor no la exige; el arnés siempre la aporta con `height = 0`.
///
/// `hechos_votos` es una adición **aditiva** de AT-1b (contrato v2 parte B): un [`HechoVoto`] por
/// índice de transacción, calculado por `zx-cadena`. Un bloque construido sin él (`Vec::new()`)
/// trata cualquier `0x0B` de ventanas distintas como `Inadmisible`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BloqueTransicion {
    /// Hechos ya decididos por las verificaciones de cabecera.
    pub hechos: HechosCabecera,
    /// Transacciones con sus testigos.
    pub txs: Vec<(Tx, Vec<Vec<u8>>)>,
    /// Cabecera PoST real, si el llamante la tiene (F-03).
    pub cabecera_post: Option<DagBlockHeader>,
    /// AT-1b · W2/W4 · hecho de la falta por índice de transacción.
    pub hechos_votos: Vec<HechoVoto>,
}

impl BloqueTransicion {
    /// Construye un bloque sin cabecera PoST explícita.
    #[must_use]
    pub fn nuevo(hechos: HechosCabecera, txs: Vec<(Tx, Vec<Vec<u8>>)>) -> Self {
        Self {
            hechos,
            txs,
            cabecera_post: None,
            hechos_votos: Vec::new(),
        }
    }

    /// Construye un bloque PoST con su cabecera real.
    #[must_use]
    pub fn con_cabecera_post(
        hechos: HechosCabecera,
        txs: Vec<(Tx, Vec<Vec<u8>>)>,
        cabecera_post: DagBlockHeader,
    ) -> Self {
        Self {
            hechos,
            txs,
            cabecera_post: Some(cabecera_post),
            hechos_votos: Vec::new(),
        }
    }

    /// AT-1b · fija los hechos de la falta por índice de transacción (W2/W3).
    #[must_use]
    pub fn con_hechos_votos(mut self, hechos_votos: Vec<HechoVoto>) -> Self {
        self.hechos_votos = hechos_votos;
        self
    }

    /// Hash del bloque.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hechos.hash()
    }

    /// Hash del padre, si lo tiene.
    #[must_use]
    pub const fn padre(&self) -> Option<BlockHash> {
        self.hechos.padre()
    }
}

/// Parámetros simbólicos de la transición (§3.3). **Ningún valor por defecto**: los fija la red dev.
#[derive(Clone, Copy)]
pub struct ParametrosTransicion {
    /// Primera altura PoW que admite depósitos (`H_dep`).
    pub h_dep: u32,
    /// Madurez de la coinbase PoW (`M_cb`).
    pub m_cb: u32,
    /// Madurez de un depósito aplicado en fase PoW (`M_dep`).
    pub m_dep: u32,
    /// Altura mínima del terminal (`H_corte_min`).
    pub h_corte_min: u32,
    /// Trabajo acumulado mínimo del terminal (`W_min`).
    pub w_min: U256,
    /// Garantía activa total mínima para el corte (`S_min`).
    pub s_min: Amount,
    /// Garantía activa mínima por clave para `Φ` (`q`).
    pub q: Amount,
    /// Número mínimo de claves con garantía activa (`K_min`).
    pub k_min: u32,
    /// TXL-01 · tamaño máximo de una transacción con testigos (`max_tx_bytes`).
    ///
    /// Es comprobación de **forma** (`C-...`, DR-01): un bloque con una transacción por encima
    /// es inválido tanto en modo estricto como en fusión. Nada de «peso» (DR-01): la magnitud es
    /// `|tx_a_bytes(tx, testigos)|`.
    pub max_tx_bytes: u64,
    /// TXL-02 · tamaño máximo del cuerpo del bloque, coinbase incluida
    /// (`max_cuerpo_bloque_bytes`). Comprobación de forma (DR-01). Rige para bloques PoW y PoST.
    pub max_cuerpo_bloque_bytes: u64,
    /// Madurez residual de coinbases PoW en el sufijo (`M_res_slots`).
    pub m_res_slots: u64,
    /// Madurez de depósitos no maduros en el terminal (`M_dep_slots`).
    pub m_dep_slots: u64,
    /// Madurez del crédito de coinbase PoST (`M_rec_slots`).
    pub m_rec_slots: u64,
    /// Retención tras retiro (`R_slots`).
    pub r_slots: u64,
    /// Profundidad máxima de sustitución para un nodo en línea (`F_slots`; `None` = sin tope).
    pub f_slots: Option<u64>,
    /// `subsidio_pow(altura)`.
    pub subsidio_pow: fn(u32) -> Amount,
    /// `subsidio_post(slot)`.
    pub subsidio_post: fn(u64) -> Amount,
}

/// Parámetros de la evidencia (`SL-4a`, `CONTRATO-EVIDENCIA-v0` con Ratificación v0).
///
/// Se mantienen **fuera** de [`ParametrosTransicion`] para no tocar los perfiles de `zx-node`
/// (fuera de alcance de SL-4a): el nodo sigue con la evidencia inactiva hasta SL-4b. Los arneses
/// diferenciales y los tests construyen este bloque con los valores de cada vector.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParametrosEvidencia {
    /// Numerador de `f = f_num/f_den` (EV-19).
    pub f_num: u64,
    /// Denominador de `f` (`> 0`).
    pub f_den: u64,
    /// Ventana de admisión `Plazo_slots` (EV-13).
    pub plazo_slots: u64,
    /// Margen `M_margen_slots` (EV-15/EV-15b).
    pub m_margen_slots: u64,
    /// `consensus_branch_id` de la red local (RAT-1).
    pub cbid: u32,
    /// Activación de `C-EVP` (equivalente a `P.evp` del oráculo).
    pub evp: bool,
}

impl Default for ParametrosEvidencia {
    fn default() -> Self {
        Self::inactiva()
    }
}

impl ParametrosEvidencia {
    /// Perfil con la evidencia **desactivada** (el de `zx-node` hasta SL-4b).
    #[must_use]
    pub const fn inactiva() -> Self {
        Self {
            f_num: 1,
            f_den: 1,
            plazo_slots: 0,
            m_margen_slots: 0,
            cbid: 0,
            evp: false,
        }
    }

    /// `true` si la evidencia está activa.
    #[must_use]
    pub const fn activa(&self) -> bool {
        self.evp
    }
}

/// Fase del estado.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fase {
    /// Fase génesis (antes de aplicar `G`).
    Genesis,
    /// Fase PoW de arranque.
    PoW,
    /// Fase PoST, después del corte.
    PoST,
}

/// Punto de aplicación: altura PoW o slot PoST (§3.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Punto {
    /// Altura de la fase PoW.
    Altura(u32),
    /// Slot de la fase PoST.
    Slot(u64),
}

impl Punto {
    /// La altura, si es un punto de altura.
    #[must_use]
    pub const fn como_altura(self) -> Option<u32> {
        match self {
            Self::Altura(h) => Some(h),
            Self::Slot(_) => None,
        }
    }

    /// El slot, si es un punto de slot.
    #[must_use]
    pub const fn como_slot(self) -> Option<u64> {
        match self {
            Self::Slot(s) => Some(s),
            Self::Altura(_) => None,
        }
    }

    /// Representación `i64` usada por el render canónico del oráculo (`-1` = no aplica).
    #[must_use]
    pub const fn como_i64(self) -> i64 {
        match self {
            Self::Altura(h) => h as i64,
            Self::Slot(s) => s as i64,
        }
    }
}

/// Origen de una salida del UTXO (`CONTRATO-v0` §3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origen {
    /// Salida de una coinbase PoW.
    CoinbasePow,
    /// Salida de una transferencia o del cambio de un depósito.
    Tx,
    /// Salida implícita de una liberación de garantía.
    Liberacion,
}

/// Una salida no gastada.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntradaUtxo {
    /// Importe.
    pub valor: Amount,
    /// Condición de gasto (`P2K` o `MultiSig`).
    pub lock: Lock,
    /// Origen.
    pub origen: Origen,
    /// Punto en que se creó (altura PoW o slot PoST).
    pub creada: Punto,
}

/// Un pendiente de garantía con su doble madurez (falta de definición 3 de `PROGRESO.md`).
///
/// Un depósito creado en fase PoW madura por **altura** dentro de la fase PoW y por **slot** una vez
/// cruzado el corte; por eso se conservan ambos, como en el oráculo T01.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pendiente {
    /// Importe pendiente.
    pub importe: Amount,
    /// Altura de madurez, si madura por altura.
    pub madura_en_altura: Option<u32>,
    /// Slot de madurez, si madura por slot.
    pub madura_en_slot: Option<u64>,
}

/// Una retirada viva.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnRetirada {
    /// Importe retirado.
    pub importe: Amount,
    /// Slot desde el que cuenta `R_slots`.
    pub inicio_slot: u64,
}

/// Un incidente de evidencia registrado en una garantía (EV-11).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Incidente {
    /// `incident_id` (32 B). En esta implementación es `H_d(dom_incidente, bytes de la identidad)`.
    pub id: [u8; 32],
    /// `slot_falta = slot(H1) = slot(H2)` (EV-13). **`i64`**: el oráculo T04 admite slots
    /// negativos en su generador de evidencia tardía; la cabecera real los transporta en dos's
    /// complemento (`u64`) y el motor los reinterpreta.
    pub slot_falta: i64,
}

/// Garantía de una clave (`C-BON-01`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Garantia {
    /// Garantía activa.
    pub activo: Amount,
    /// Pendientes con su madurez.
    pub pendientes: Vec<Pendiente>,
    /// Retiradas vivas.
    pub en_retirada: Vec<EnRetirada>,
    /// Congelado: gravamen **derivado** (no bucket) mientras haya incidentes abiertos (EV-17).
    pub congelado: Amount,
    /// Créditos D-T08 pendientes de madurar.
    pub creditos: Vec<Pendiente>,
    /// Nonce siguiente de la clave (F-15): 0 al crearse. Toda operación de garantía de esta clave
    /// exige `nonce == nonce_siguiente` y lo incrementa al aplicarse.
    pub nonce_siguiente: u64,
    /// Incidentes de evidencia admitidos y aún no podados (EV-11).
    pub incidentes: Vec<Incidente>,
}

impl Garantia {
    /// Garantía vacía.
    #[must_use]
    pub const fn nueva() -> Self {
        Self {
            activo: Amount::CERO,
            pendientes: Vec::new(),
            en_retirada: Vec::new(),
            congelado: Amount::CERO,
            creditos: Vec::new(),
            nonce_siguiente: 0,
            incidentes: Vec::new(),
        }
    }
}

/// Estado canónico de consenso (§3.4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Estado {
    /// Salidas no gastadas.
    pub utxo: BTreeMap<OutPoint, EntradaUtxo>,
    /// Garantías por clave.
    pub garantias: BTreeMap<ClavePublica, Garantia>,
    /// Suma de subsidios efectivos (puede ser negativa en el término de tarifas).
    pub emitido: i128,
    /// Pérdidas por `C-SLA` (siempre 0 en v0).
    pub quemado: i128,
    /// Fase.
    pub fase: Fase,
    /// Hash del terminal de esta rama, si existe.
    pub terminal: Option<BlockHash>,
    /// Altura PoW alcanzada.
    pub altura: u32,
    /// Trabajo PoW acumulado.
    pub trabajo: U256,
    /// Último slot PoST aplicado.
    pub slot: u64,
    /// Slot de referencia del corte (`s_0`).
    pub s0: u64,
    /// Peso PoST del sufijo.
    pub peso_sufijo: u128,
    /// Altura del terminal, para la madurez residual.
    pub altura_terminal: Option<u32>,
    /// Suma de subsidios nominales, para `I-1b`.
    pub subsidio_acum: i128,
    /// SL-4a · `último_slot_producido(P)`: mayor `slot(B)` de un bloque PoST aplicado con
    /// `sol.public_key = P` (EV-15b/EV-24(ii)). Solo lo consume la liberación.
    pub ultimo_slot_producido: BTreeMap<ClavePublica, u64>,
    /// SR-1 · registro de sectores (`C-SEC-01`), ordenado por `SectorId`.
    ///
    /// SR-1-2: el motor de `transicion` **sí** lo muta desde `aplicar_tx` (v5) y materializa el
    /// ciclo de vida en cada bloque. El undo por delta lo restaura completo.
    pub sectores: BTreeMap<SectorId, RegistroSector>,
    /// SR-1-2 · parámetros del autómata de sectores (`DP-2`…`DP-6`, `DP-13`).
    ///
    /// Se copian al estado en lugar de añadirse a [`ParametrosTransicion`] para no reescribir sus 43
    /// literales; `Estado::inicial()` usa el perfil dev y los arneses pueden sobrescribirlo.
    pub parametros_sector: ParametrosSector,
    /// SR-G2b · cajas de sectores (`C-CAJA-01`), ordenadas por [`CajaId`].
    ///
    /// La caja agrupa hasta `capacidad_caja` sectores que se añaden al sellar; el estado sigue
    /// conservando el registro por sector (`sectores`) y la caja aporta la raíz Merkle, el índice
    /// `hueco → sector` y el ciclo de vida de la agrupación (D-2 en `PROGRESO.md` §1).
    pub cajas: BTreeMap<CajaId, RegistroCaja>,
    /// PT-3bc · prueba de almacenamiento vigente por clave (`Estado.pruebas`, `C-SEC-15`).
    pub pruebas: BTreeMap<ClavePublica, PruebaVigente>,
    /// PT-3bc · atestación PoRep por clave (activación en dos fases, `REVISION-PT3a` decisión 5).
    pub poreps: BTreeMap<ClavePublica, PorepVigente>,
    /// PT-3bc · clave BLS de voto por clave con su prueba de posesión (`REVISION-FV4bD` decisión 2).
    pub claves_voto: BTreeMap<ClavePublica, ClaveVoto>,
    /// RK-2 · V2/V3 · clave de voto **anterior** viva de cada identidad (a lo sumo una), con su
    /// vencimiento. La escribe el brazo `0x03` al rotar; el índice de dueños (V5) la usa.
    pub claves_voto_previas: BTreeMap<ClavePublica, ClaveVotoAnterior>,
    /// RK-2 · V6 · índice por vencimiento (`vencimiento → identidades`) para borrar al aplicar un
    /// bloque solo las anteriores que vencen en ese bloque, no todas las identidades.
    pub vencimientos_clave_voto: BTreeMap<u64, BTreeSet<ClavePublica>>,
    /// FV-4b-N2 · instancia del último certificado de finalidad por votos aplicado.
    pub finalidad_votos_n: u64,
    /// FV-4b-N2 · bloque certificado por los votos (punto de finalidad, monótono).
    pub finalidad_votos: Option<BlockHash>,
    /// FV-4b-N2 · `h_T(n+1)` comprometido por el último certificado (encadenado `RFT-19`).
    pub finalidad_votos_h_t: Option<[u8; 32]>,
    /// RE-2c · C1′ · raíz de estado del **último certificado** `0x09` aplicado con éxito (`None`
    /// mientras no se haya aplicado ninguno). Un solo valor, no un mapa: no se calcula, no se
    /// compara y no rechaza nada por él.
    pub raiz_estado: Option<[u8; 32]>,
    /// M9-b2 · tabla de poder `T_n` de cada instancia/ventana abierta. El flujo por peso la escribe
    /// al certificar (`votos.rs`) y la consulta al liquidar; el flujo antiguo le añadía la `K`, que
    /// se retiró con el sorteo.
    pub tablas_voto: BTreeMap<u64, Vec<ClaveTablaVoto>>,
    /// PD-1b · C2 · contenido de las tablas conocidas, indexado por `hash_tabla` y guardado **una
    /// sola vez** por hash. El contenido de la tabla cuyo hash es `finalidad_votos_h_t` (la tabla
    /// vigente) es `tablas_voto_contenido[finalidad_votos_h_t]`; si falta, la tabla vigente es
    /// «desconocida».
    pub tablas_voto_contenido: BTreeMap<[u8; 32], Vec<ClaveTablaVoto>>,
    /// PD-1b · C5 · tabla vigente en cada ventana aún no liquidada, por el hash de su contenido
    /// (`tabla_ventana_voto[k]` es el hash de la tabla que estaba vigente al cerrarse `k`).
    pub tabla_ventana_voto: BTreeMap<u64, [u8; 32]>,
    /// RA-1 · Y1 · instantánea de la tabla del **ciclo de rearranque** `j → hash` del contenido
    /// canónico de la tabla vigente en `ref(j)` (el estado del último bloque con slot `≤ ref(j)`).
    /// El contenido vive en [`Self::tablas_voto_contenido`] y la poda lo respeta. Se borra la de un
    /// ciclo al terminar su fase activa y **todas** cuando la base avanza (Y2).
    pub tabla_ciclo_rearranque: BTreeMap<u64, [u8; 32]>,
    /// TB-1a · R1 · cola `Q` de tablas derivadas: pares `(ventana, huella)` en orden de inserción,
    /// como mucho [`K_TABLAS_VOTO`]. El contenido de cada huella vive en
    /// [`Self::tablas_voto_contenido`]. Vacía en el estado inicial.
    pub cola_tablas_voto: Vec<(u64, [u8; 32])>,
    /// TB-1c-2 · X1 · TB4-R1/R8 · P1 · última ventana `k` para la que este estado derivó una tabla
    /// (el gancho de T1): como mucho una derivación por ventana y cadena. `None` = ninguna. **Vale
    /// con y sin base** (TB4-R1 lo generaliza; el nombre histórico se conserva). No se renombra:
    /// el campo entra en la raíz de estado y en el resumen.
    pub ultima_ventana_derivada_sin_base: Option<u64>,
    /// FV-4b-N3 · claves que votaron en cada instancia (voto admitido, AV-12).
    pub votantes_voto: BTreeMap<u64, BTreeSet<ClavePublica>>,
    /// AUS-2a · R5 · deuda de ausencia acumulada por clave Ed25519, en unidades de
    /// `F_AUS_VENTANA = 7/1 401 600 000` de la garantía por ventana sin voto. Al liquidar cada
    /// ventana se suma `G·7`; cuando la deuda cruza `1 401 600 000` se cobra la parte entera
    /// (`deuda / 1 401 600 000`) y se conserva el resto como nueva deuda.
    pub deuda_ausencia: BTreeMap<ClavePublica, i128>,
    /// AUS-2a · R6 · última ventana ya liquidada (cobrada una sola vez). `None` = ninguna; toda
    /// ventana `n` con `cierre(n) + W_REVEAL < slot` y `n` por encima de esta marca se liquida en
    /// el primer bloque que la vence.
    pub liquidacion_voto_hasta: Option<u64>,
}

/// Escalares del estado, para el undo por delta (`ORDEN-W03` §3.5).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Escalares {
    /// `emitido`.
    pub emitido: i128,
    /// `quemado`.
    pub quemado: i128,
    /// `fase`.
    pub fase: Fase,
    /// `terminal`.
    pub terminal: Option<BlockHash>,
    /// `altura`.
    pub altura: u32,
    /// `trabajo`.
    pub trabajo: U256,
    /// `slot`.
    pub slot: u64,
    /// `s0`.
    pub s0: u64,
    /// `peso_sufijo`.
    pub peso_sufijo: u128,
    /// `altura_terminal`.
    pub altura_terminal: Option<u32>,
    /// `subsidio_acum`.
    pub subsidio_acum: i128,
    /// `ultimo_slot_producido` (SL-4a). Se restaura completo en `deshacer`.
    pub ultimo_slot_producido: BTreeMap<ClavePublica, u64>,
    /// SR-1 · registro de sectores previo (`C-SEC-01`, `C-SEC-11`). Se restaura completo.
    pub sectores: BTreeMap<SectorId, RegistroSector>,
    /// SR-1-2 · parámetros del autómata de sectores (constantes; se restauran por igualdad).
    pub parametros_sector: ParametrosSector,
    /// SR-G2b · cajas de sectores previas (`C-CAJA-11`). Se restauran completas.
    pub cajas: BTreeMap<CajaId, RegistroCaja>,
    /// PT-3bc · pruebas de almacenamiento previas. Se restauran completas.
    pub pruebas: BTreeMap<ClavePublica, PruebaVigente>,
    /// PT-3bc · atestaciones PoRep previas. Se restauran completas.
    pub poreps: BTreeMap<ClavePublica, PorepVigente>,
    /// PT-3bc · claves BLS de voto previas. Se restauran completas.
    pub claves_voto: BTreeMap<ClavePublica, ClaveVoto>,
    /// RK-2 · claves de voto anteriores vivas previas. Se restauran completas.
    pub claves_voto_previas: BTreeMap<ClavePublica, ClaveVotoAnterior>,
    /// RK-2 · índice de vencimientos previo. Se restaura completo.
    pub vencimientos_clave_voto: BTreeMap<u64, BTreeSet<ClavePublica>>,
    /// FV-4b-N2 · instancia de finalidad por votos previa.
    pub finalidad_votos_n: u64,
    /// FV-4b-N2 · bloque de finalidad por votos previo.
    pub finalidad_votos: Option<BlockHash>,
    /// FV-4b-N2 · `h_T(n+1)` del certificado previo.
    pub finalidad_votos_h_t: Option<[u8; 32]>,
    /// RE-2c · C1′ · raíz del último certificado previa (se restituye en `deshacer`).
    pub raiz_estado: Option<[u8; 32]>,
    /// M9-b2 · tablas de instancia previas. Se restauran completas.
    pub tablas_voto: BTreeMap<u64, Vec<ClaveTablaVoto>>,
    /// PD-1b · C2 · contenidos de tabla previos. Se restauran completos.
    pub tablas_voto_contenido: BTreeMap<[u8; 32], Vec<ClaveTablaVoto>>,
    /// PD-1b · C5 · asociación ventana→tabla previa. Se restaura completa.
    pub tabla_ventana_voto: BTreeMap<u64, [u8; 32]>,
    /// RA-1 · Y1 · instantáneas de ciclo previas. Se restauran completas.
    pub tabla_ciclo_rearranque: BTreeMap<u64, [u8; 32]>,
    /// TB-1a · R1 · cola de tablas derivadas previa. Se restaura completa.
    pub cola_tablas_voto: Vec<(u64, [u8; 32])>,
    /// TB-1c-2 · X1 · TB4-R1/R8 · última ventana derivada previa (con y sin base). Se restaura por
    /// igualdad. El nombre histórico se conserva (P1).
    pub ultima_ventana_derivada_sin_base: Option<u64>,
    /// FV-4b-N3 · votantes por instancia previos. Se restauran completos.
    pub votantes_voto: BTreeMap<u64, BTreeSet<ClavePublica>>,
    /// AUS-2a · deuda de ausencia previa. Se restaura completa.
    pub deuda_ausencia: BTreeMap<ClavePublica, i128>,
    /// AUS-2a · marca de liquidación previa.
    pub liquidacion_voto_hasta: Option<u64>,
}

impl From<&Estado> for Escalares {
    fn from(e: &Estado) -> Self {
        Self {
            emitido: e.emitido,
            quemado: e.quemado,
            fase: e.fase,
            terminal: e.terminal,
            altura: e.altura,
            trabajo: e.trabajo,
            slot: e.slot,
            s0: e.s0,
            peso_sufijo: e.peso_sufijo,
            altura_terminal: e.altura_terminal,
            subsidio_acum: e.subsidio_acum,
            ultimo_slot_producido: e.ultimo_slot_producido.clone(),
            sectores: e.sectores.clone(),
            parametros_sector: e.parametros_sector,
            cajas: e.cajas.clone(),
            pruebas: e.pruebas.clone(),
            poreps: e.poreps.clone(),
            claves_voto: e.claves_voto.clone(),
            claves_voto_previas: e.claves_voto_previas.clone(),
            vencimientos_clave_voto: e.vencimientos_clave_voto.clone(),
            finalidad_votos_n: e.finalidad_votos_n,
            finalidad_votos: e.finalidad_votos,
            finalidad_votos_h_t: e.finalidad_votos_h_t,
            raiz_estado: e.raiz_estado,
            tablas_voto: e.tablas_voto.clone(),
            tablas_voto_contenido: e.tablas_voto_contenido.clone(),
            tabla_ventana_voto: e.tabla_ventana_voto.clone(),
            tabla_ciclo_rearranque: e.tabla_ciclo_rearranque.clone(),
            cola_tablas_voto: e.cola_tablas_voto.clone(),
            ultima_ventana_derivada_sin_base: e.ultima_ventana_derivada_sin_base,
            votantes_voto: e.votantes_voto.clone(),
            deuda_ausencia: e.deuda_ausencia.clone(),
            liquidacion_voto_hasta: e.liquidacion_voto_hasta,
        }
    }
}

/// Undo por **delta**: valor previo de cada `OutPoint` y `ClavePublica` tocados y escalares previos.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Undo {
    /// Escalares previos.
    pub escalares: Escalares,
    /// `(outpoint, valor previo)` de cada salida tocada, en orden de primer toque.
    pub utxo: Vec<(OutPoint, Option<EntradaUtxo>)>,
    /// `(clave, garantía previa)` de cada garantía tocada, en orden de primer toque.
    pub garantias: Vec<(ClavePublica, Option<Garantia>)>,
    /// SR-1-2 · `(id, registro previo)` de cada sector tocado, en orden de primer toque.
    ///
    /// Permite revertir una operación descartada en modo fusión sin tocar el resto del registro; el
    /// undo por bloque sigue restaurando el mapa completo desde [`Escalares::sectores`].
    pub sectores: Vec<(SectorId, Option<RegistroSector>)>,
    /// SR-G2b · `(id, caja previa)` de cada caja tocada, en orden de primer toque.
    pub cajas: Vec<(CajaId, Option<RegistroCaja>)>,
    /// PT-3bc · `(clave, prueba previa)` de cada prueba tocada.
    pub pruebas: Vec<(ClavePublica, Option<PruebaVigente>)>,
    /// PT-3bc · `(clave, atestación PoRep previa)` de cada atadura tocada.
    pub poreps: Vec<(ClavePublica, Option<PorepVigente>)>,
    /// PT-3bc · `(clave, clave de voto previa)` de cada registro tocado.
    pub claves_voto: Vec<(ClavePublica, Option<ClaveVoto>)>,
    pub(crate) utxo_vistos: BTreeSet<OutPoint>,
    pub(crate) garantia_vistos: BTreeSet<ClavePublica>,
    pub(crate) sector_vistos: BTreeSet<SectorId>,
    pub(crate) caja_vistos: BTreeSet<CajaId>,
    pub(crate) prueba_vistos: BTreeSet<ClavePublica>,
    pub(crate) porep_vistos: BTreeSet<ClavePublica>,
    pub(crate) clave_voto_vistos: BTreeSet<ClavePublica>,
}

/// Marca de posición dentro de un [`Undo`], para revertir una transacción descartada en modo fusión.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Marca {
    /// Longitud de la lista de UTXO.
    pub utxo: usize,
    /// Longitud de la lista de garantías.
    pub garantias: usize,
    /// Longitud de la lista de sectores.
    pub sectores: usize,
    /// Longitud de la lista de cajas.
    pub cajas: usize,
    /// PT-3bc · longitud de la lista de pruebas.
    pub pruebas: usize,
    /// PT-3bc · longitud de la lista de atestaciones PoRep.
    pub poreps: usize,
    /// PT-3bc · longitud de la lista de claves de voto.
    pub claves_voto: usize,
    /// RE-2c · C6 · valor de [`Estado::raiz_estado`] en el momento de la marca; `revertir_a`
    /// lo restituye al descartar una transacción en modo fusión.
    pub raiz_estado: Option<[u8; 32]>,
}

/// Una transacción descartada en modo fusión (`ED-4`…`ED-6`) con su motivo.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxDescartada {
    /// Índice de la transacción dentro del bloque.
    pub indice: usize,
    /// `txid` de la transacción descartada.
    pub txid: TxId,
    /// Motivo.
    pub motivo: ErrorTransicion,
}
