//! Errores del orden DAG.
//!
//! Un solo enum, [`ErrorDag`], con una variante explícita por rechazo del orden DAG y de la
//! comprobación contextual de padres (D-P08). Sustituye a `ConsensusError` en los módulos
//! portados: se conservan **las mismas variantes usadas** por `ghostdag.rs`, `bloque_dag.rs` y
//! `dag_causal.rs`, y el génesis DAG se reemplaza por la batería de terminal de D-P08.

use thiserror::Error;

use crate::ghostdag::IdentidadGhostdag;

/// Fallo al aplicar una regla del orden DAG.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorDag {
    /// C-HDR-06 (reescrita): `rango_solucion` no es el rango esperado contextual.
    #[error("C-HDR-06: rango_solucion {encontrado}, esperado {esperado}")]
    RangoIncorrecto {
        /// Rango derivado del pasado DAG validado y del flujo.
        esperado: u64,
        /// Rango declarado en la cabecera.
        encontrado: u64,
    },

    /// C-HDR-06 · C-GD-01: un `SR` validado para un bloque se intenta insertar en otro.
    ///
    /// El rango validado queda atado al `block_hash` de la cabecera que lo superó; colocarlo en un
    /// bloque distinto es un error explícito, no una aceptación.
    #[error("C-HDR-06: el SR validado para {validado_para} se intenta usar en {bloque}")]
    RangoDeOtroBloque {
        /// El bloque en el que se intenta insertar.
        bloque: zx_core::BlockHash,
        /// El bloque para el que se validó el `SR`.
        validado_para: zx_core::BlockHash,
    },

    /// D-P08 · Una cabecera PoST con `parent_count = 0` es **siempre** inválida.
    ///
    /// No existe un génesis DAG: la historia PoST continúa la misma historia PoW a partir del
    /// terminal `T` (D-T02, TRN-06). El bloque de transición tiene exactamente un padre, `T`.
    #[error(
        "D-P08: cabecera PoST con 0 padres: no hay génesis DAG (el primer bloque es hijo de T)"
    )]
    CabeceraPostSinPadres,

    /// D-P08 · El padre seleccionado es el terminal `T` y la cabecera declara padres adicionales.
    ///
    /// El bloque de transición tiene **exactamente un** padre, que es `T` (TRN-06).
    #[error(
        "D-P08: el terminal es el padre seleccionado pero la cabecera declara {declarados} padres"
    )]
    TerminalConPadresExtra {
        /// Número total de padres declarados (`parent_count`).
        declarados: u64,
    },

    /// D-P08 · Un bloque PoST declara el terminal `T` como **padre adicional**.
    ///
    /// Un bloque PoST no puede tener como padre un bloque PoW distinto de `T`, ni `T` como padre
    /// adicional (TRN-06).
    #[error("D-P08: el terminal {terminal} no puede ser un padre adicional")]
    TerminalComoPadreExtra {
        /// Hash del terminal declarado como padre adicional.
        terminal: zx_core::BlockHash,
    },

    /// H-04 · Un padre no está entre los bloques validados del contexto.
    ///
    /// Con D-P08, «validado» significa: el terminal `T` (validado por W04/W03) o un bloque PoST ya
    /// admitido en el contexto. Un bloque PoW ajeno no es ninguno de los dos.
    #[error("contexto DAG: el padre {padre} no está validado")]
    PadreNoValidado {
        /// El hash del padre desconocido.
        padre: zx_core::BlockHash,
    },

    /// H-04 · Dos padres en relación de ancestro: el conjunto no es una anticadena.
    #[error("contexto DAG: {antepasado} está en el pasado de {descendiente}, no es anticadena")]
    PadresNoAnticadena {
        /// El padre que aparece antes.
        antepasado: zx_core::BlockHash,
        /// El padre que lo contiene en su pasado.
        descendiente: zx_core::BlockHash,
    },

    /// H-04 · `prev_hash` no es el `sp(B)` de C-GD-03.
    #[error("C-GD-03: padre seleccionado {encontrado}, esperado {esperado}")]
    PadreSeleccionadoIncorrecto {
        /// El que devuelve el contexto.
        esperado: zx_core::BlockHash,
        /// El declarado en `prev_hash`.
        encontrado: zx_core::BlockHash,
    },

    /// C-HDR-05 · C-FLU-02: **algún** padre tiene un `slot` posterior al del bloque.
    ///
    /// La cota es **no estricta** y alcanza a **todos** los padres, no solo al seleccionado
    /// (`sp(B)`, que es el caso particular de `C-GD-03`). Se informa del padre infractor y de los
    /// dos `slot` para poder localizar la violación; el slot se toma del contexto validado, nunca
    /// del candidato.
    #[error(
        "C-HDR-05/C-FLU-02: el padre {padre} tiene slot {slot_padre} posterior a slot(B) = {slot_b}"
    )]
    SlotDePadrePosterior {
        /// Hash del padre infractor.
        padre: zx_core::BlockHash,
        /// `slot` del padre, tomado del contexto.
        slot_padre: u64,
        /// `slot` del bloque candidato.
        slot_b: u64,
    },

    /// C-HDR-05 · C-FLU-02: el contexto no puede dar el `slot` de un padre que dice conocer.
    ///
    /// Sin ese slot la cota no es comprobable. La ausencia **MUST NOT** sustituirse por cero ni
    /// por ningún valor por defecto.
    #[error("contexto DAG: no hay slot contextual para el padre {padre}")]
    SlotDePadreAusente {
        /// Hash del padre cuyo slot falta.
        padre: zx_core::BlockHash,
    },

    /// C-GD-02 · C-ENC-03: un `blue_work` que desborda `u256` es **fallo de consenso explícito**,
    /// nunca una envoltura ni un truncamiento.
    #[error("C-GD-02: blue_work desborda u256 (C-ENC-03: nunca en silencio)")]
    BlueWorkDesbordado,

    /// C-GD-04 · R-FIN-12: más de 15 padres.
    #[error("R-FIN-12: {declarados} padres, máximo {maximo}")]
    DemasiadosPadresDag {
        /// Padres declarados.
        declarados: u64,
        /// `MAX_PADRES`.
        maximo: u64,
    },

    /// C-GD-04 · R-FIN-12: `|mergeset(B)| + 1 > 180` con `k = 30`.
    #[error("R-FIN-12: |mergeset| + 1 = {tamano}, máximo {maximo}")]
    MergesetExcedeLimite {
        /// `|mergeset(B)| + 1`.
        tamano: u64,
        /// Límite de R-FIN-12.
        maximo: u64,
    },

    /// C-GD-04: `slot(B) − slot(sp(B)) > S_max`.
    #[error("C-GD-04: salto de slot {salto} > S_max")]
    SaltoMayorSmax {
        /// Diferencia de slots.
        salto: u64,
    },

    /// C-GD-07 · U2: la identidad de billete ya aparece en un padre o su pasado estricto.
    #[error("C-GD-07/U2: el billete {identidad} ya está en el pasado del bloque")]
    BilleteDuplicadoU2 {
        /// Identidad del billete repetida (tupla exacta de `C-GD-07` o fixture sintética).
        identidad: IdentidadGhostdag,
    },

    /// Un hash que el almacén GHOSTDAG no conoce.
    #[error("GHOSTDAG: bloque desconocido {hash}")]
    BloqueDesconocido {
        /// El hash ausente.
        hash: zx_core::BlockHash,
    },

    /// El almacén GHOSTDAG ya tiene ese `block_hash`.
    ///
    /// Es un **duplicado de almacenamiento**, no un veredicto sobre la prueba PoST del bloque ni
    /// motivo automático para penalizar al par: el mismo bloque puede llegar dos veces por
    /// retransmisión. Rechazarlo es lo que impide que `indice.insert` sustituya el índice mientras
    /// `ids` crece y deje dos entradas para un solo id.
    #[error("GHOSTDAG: el bloque {hash} ya está almacenado (duplicado de almacenamiento)")]
    BloqueDuplicado {
        /// El hash repetido.
        hash: zx_core::BlockHash,
    },

    /// Estado GHOSTDAG incoherente: una consulta que por construcción no debería ocurrir.
    #[error("GHOSTDAG: estado incoherente: {motivo}")]
    GhostdagIncoherente {
        /// Qué invariante interna se rompió.
        motivo: &'static str,
    },

    /// C-BLK-01: la raíz de Merkle recalculada no coincide con la cabecera DAG.
    #[error("C-BLK-01: la raíz de Merkle no coincide con la cabecera DAG")]
    MerkleRaizNoCoincide,

    /// El compromiso completo del cuerpo no coincide con la cabecera DAG.
    #[error("compromiso del cuerpo (txid ‖ auth_digest) no coincide con la cabecera DAG")]
    CuerpoCompromisoNoCoincide,

    /// El número de listas de testigos no es el de transacciones.
    #[error("cuerpo DAG: {testigos} listas de testigos para {txs} transacciones")]
    CuerpoTestigosDescuadrados {
        /// Transacciones.
        txs: usize,
        /// Listas de testigos.
        testigos: usize,
    },
}
