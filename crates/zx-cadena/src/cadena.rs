//! Gestor del estado del DAG en memoria (`ORDEN-W06a`, `D-N02`; rediseño `ORDEN-W06d7`).
//!
//! Implementa `ED-1…ED-6` y `RD-1…RD-10` del contrato `P-ZRX/P-DAG/CONTRATO-ESTADO-DAG-v0.md`
//! sobre el motor de W03 (`aplicar` para PoW, `aplicar_fusion` para PoST) y `zx-dag` (GHOSTDAG):
//!
//! - **ED-1** la fase PoW se aplica en modo estricto sobre su padre;
//! - **ED-2** `Estado(past(B))` parte del estado del padre seleccionado y aplica, en orden
//!   `C-GD-05`, el mergeset de `B` sin `rojo_U3`, en modo fusión con punto `slot(B)`;
//! - **ED-3** el virtual `V` tiene por padres las puntas válidas, `slot(V) = máx slot(puntas)`, y la
//!   cadena seleccionada es la de `sp` desde `V`;
//! - **RD-4/RD-1** un bloque de cadena se aplica en su propio slot; uno fusionado de lado, en el
//!   slot del fusionador; el importe de la coinbase usa `subsidio_post(slot(X))`;
//! - **RD-5** `slot(B) − slot(X) > F_slots` invalida el bloque (`ErrMergeDepth`);
//! - **RD-9/RD-10** la garantía del productor se comprueba en `Estado(past(B))` promovido en
//!   `slot(B)`, una sola vez, en la admisión.
//!
//! # `ORDEN-W06d7`: un DAG por terminal candidato (FC-3 de verdad)
//!
//! `W06d6` descubrió que esta implementación **congelaba** el terminal al admitir el primer bloque
//! PoST (`recalcular_terminal` solo corría mientras `dag.is_none()`) y solo mantenía **un** DAG. Eso
//! no es `TRN-09` (FC-3): dos nodos que cruzan el corte con terminales distintos no convergían nunca
//! (I-3 roto). El rediseño (decisiones del director en `ORDEN-W06d7.md` §3):
//!
//! 1. **Un [`DagTerminal`] por candidato** (`self.dags`): cada terminal que cumple el corte
//!    (`TRN-04`, [`es_primero_en_rama`](Cadena::es_primero_en_rama)) y tiene al menos un bloque PoST
//!    válido cuelga de su propio `AlmacenGhostdag` con raíz en ese terminal. Un bloque PoST
//!    pertenece al DAG del terminal de su pasado ([`Cadena::terminal_de_bloque_post`]); padres de
//!    terminales distintos son inválidos (`ErrTerminalAmbiguo`, `I-4`).
//! 2. **Selección FC-3 entre terminales** ([`Cadena::mejor_terminal_candidato`]): sin ningún DAG
//!    (sufijo PoST), gana el mayor trabajo PoW acumulado; en cuanto alguno tiene sufijo, solo esos
//!    compiten por mayor `blue_work` de su virtual, desempate por `comparar_terminal` (menor hash,
//!    reutilizado de `zx_consensus::transicion`, ya no reimplementado) y, si aún empata, por la
//!    regla `C-GD` (`solution_distance`, `id`).
//! 3. **`C-FIN-01` entre terminales** ([`Cadena::recalcular_seleccion`]): un nodo en línea no
//!    sustituye su terminal seleccionado por otro si el sufijo actual ya abarca `≥ F_slots` desde el
//!    corte (`s_0 = 0`, `CONTRATO-v0.md` §1); se mide con el `slot` máximo de las puntas válidas del
//!    terminal actual.
//! 4. **Tope** [`MAX_TERMINALES_CON_DAG`] = 8 ([`Cadena::dag_de_terminal_mut`]): un noveno candidato
//!    con sufijo PoST se ignora si su trabajo PoW no supera al peor de los ocho (se marca
//!    [`Cadena::limite_terminales_alcanzado`]); si lo supera, desaloja al peor. `ORDEN-W08a`: ese
//!    rechazo **no se cachea** (el tope es vista local), el bloque queda pendiente (acotado por
//!    [`MAX_PENDIENTES_TOPE`]) y se reevalúa en el siguiente `admitir` y tras cada desalojo.
//! 5. **API** (`terminal()`, `contexto_dag()`, `estado_virtual()`, `cadena_virtual()`,
//!    `mejor_punta()`…) devuelve lo del terminal **seleccionado**; hay accesos «_de» explícitos por
//!    terminal para quien (el nodo) necesite verificar contra un terminal que no es el seleccionado.
//!
//! Coste declarado (`V-ZRX/LINEO.md`, disciplina general): cada [`Cadena::dag_virtual_de`]
//! reconstruye el `AlmacenGhostdag` del virtual de ese terminal desde cero (patrón ya existente en
//! esta implementación antes de esta orden); con hasta 8 terminales y los tamaños de esta orden
//! (cientos de bloques), el coste adicional de recorrer varios terminales en cada selección es
//! aceptable sin banco de pruebas dedicado; si el número de terminales o de bloques creciera muy por
//! encima de esto, sería el primer punto a perfilar.
//!
//! La verificación de cabeceras no es de esta orden: `pow_valido`/`prueba_valida` llegan decididos.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use primitive_types::U256;
use zx_consensus::transicion::{
    Estado, HechoVoto, ParametrosEvidencia, ParametrosTransicion, Punto, TxDescartada, Undo,
    aplicar, comparar_terminal, deshacer, es_terminal_condiciones,
};
use zx_core::{
    Amount, BlockHash, ClavePublica, ExtensionTx, OperacionAlmacenamiento, PadresDag, Tx,
    VotoPesoEvidencia, validar_forma_tx_v4,
};
use zx_dag::bloque_dag::ContextoDag;
use zx_dag::ghostdag::{
    Algoritmo, AlmacenGhostdag, BloqueGhostdag, Color, DatosGhostdag, IdentidadGhostdag, Idx,
    ModoMerge, ModoSp, Parametros as ParametrosGhostdag, Rank,
};
use zx_dag::{ErrorDag, RangoSolucionValidado, hash_de_id_textual};

use crate::bloque::{BloqueCadena, BloquePost};
use crate::error::MotivoBloque;

mod admision_post;

#[cfg(test)]
mod prod3a_tests;

/// Tope de mergeset del oráculo (`C-GD-04`).
const MERGESET_LIMITE_ORACULO: u32 = 180;

/// Tope de terminales candidatos con DAG propio (`ORDEN-W06d7` decisión 4).
pub const MAX_TERMINALES_CON_DAG: usize = 8;

/// FV-4b-N1 · Motivo por el que [`Cadena::anclar_finalidad_por_votos`] no adopta un candidato.
///
/// Un certificado con candidato **desconocido** o en una **rama en conflicto** (ni ancestro ni
/// descendiente del punto vigente) no se adopta: se registra y la decisión de recuperación es
/// ECL-R2. Nunca se produce un `panic` ni un `Ok` ficticio.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MotivoAncla {
    /// El bloque no es un bloque admitido de la cadena seleccionada del terminal actual.
    Desconocido,
    /// El bloque no desciende del punto de finalidad vigente (rama en conflicto).
    Conflicto,
}

/// ECL-R2a · D4 · Certificado verificado que obliga a ir **más allá de `F_slots`** en una rama en
/// conflicto con la selección actual. El nodo entra en **modo detenido**: no produce, no vota y
/// avisa; solo el reinicio del operador lo saca.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eclipse {
    /// Instancia `n` del ancla vigente antes del certificado.
    pub n_ancla: u64,
    /// Candidato `h` del ancla vigente antes del certificado.
    pub h_ancla: BlockHash,
    /// Instancia `n'` del certificado que disparó la detección.
    pub n_certificado: u64,
    /// Candidato `h'` del certificado que disparó la detección.
    pub h_certificado: BlockHash,
    /// Profundidad en slots (`d ≥ F_slots`) del terminal seleccionado.
    pub profundidad: u64,
}

/// ECL-R2a · Resultado de considerar un ancla `(n, h)` del estado o de un certificado verificado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultadoAncla {
    /// El ancla se adoptó (primera vez o instancia mayor) y su terminal es alcanzable dentro de `F`.
    Adoptada,
    /// Misma instancia y mismo candidato: no cambia nada.
    Idempotente,
    /// `n' < n`: se ignora (el ancla nunca retrocede).
    Ignorada,
    /// `n' == n` con otro candidato: conflicto de misma instancia, no se adopta.
    ConflictoMismaInstancia,
    /// El candidato no está en ningún DAG conocido: ancla **pendiente** (sin cambio de terminal).
    Pendiente,
}

/// Tope de bloques pendientes por [`MotivoBloque::ErrLimiteTerminales`] (`ORDEN-W08a` decisión 2).
/// El tope de terminales es 8, así que cada terminal pendiente aporta, en el peor caso, un puñado
/// de bloques PoST rechazados. `64` (= 8 por terminal) acota el reintento de un desalojo a 64
/// admisiones, despreciable frente al coste de admitir; el propio `BloqueCadena` ya vive en
/// `por_hash`, el depósito general de bloques conocidos que esta implementación no poda. Esta cola
/// solo guarda el `BlockHash` (32 B) y un índice de antigüedad (otros 32 B), luego su memoria es
/// inferior a 3 KiB: no mueve la aguja frente al presupuesto de memoria del nodo. Al superarse el
/// tope se descarta el más antiguo (FIFO determinista).
pub const MAX_PENDIENTES_TOPE: usize = 64;

/// Una transacción descartada al aplicar la historia seleccionada, con el bloque del que procede.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Descarte {
    /// Bloque que contenía la transacción.
    pub bloque: BlockHash,
    /// Índice **0-based** de la transacción dentro del bloque.
    pub indice: usize,
    /// Motivo del descarte.
    pub motivo: zx_consensus::transicion::ErrorTransicion,
}

/// Resultado de aplicar la historia o una rama: estado, orden y descartes, más los undos.
type HistoriaAplicada = (Estado, Vec<BlockHash>, Vec<Descarte>, Vec<Undo>);

/// `FIN-1` · Intento de seleccionar un bloque cuya cadena seleccionada **no** contiene el punto de
/// finalidad vigente (decisión 2 de `ORDEN-FIN1`).
///
/// El bloque es válido y queda admitido en el almacén, pero no puede ser elegido como punta ni hacer
/// que el virtual cambie. Se guarda aquí en vez de emitirse desde `zx-cadena` (que no tiene interfaz
/// de eventos); `zx-node` puede consultarlo y escribir el evento `violacion_finalidad` en su registro.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ViolacionFinalidad {
    /// Punto de finalidad vigente que el candidato no contiene.
    pub finalidad: BlockHash,
    /// Bloque que habría ganado la selección sin la cota (su cadena no contiene `finalidad`).
    pub bloque: BlockHash,
    /// `slot(bloque) − slot(finalidad)`, en slots.
    pub profundidad: u64,
}

/// El DAG GHOSTDAG propio de **un** terminal candidato (`ORDEN-W06d7` decisión 1).
///
/// Vive desde que se admite el primer bloque PoST que cuelga de ese terminal
/// ([`Cadena::dag_de_terminal_mut`]); antes de eso el terminal es solo una entrada de
/// [`Cadena::terminal_candidatos`], sin `DagTerminal`.
#[derive(Clone)]
struct DagTerminal {
    dag: AlmacenGhostdag,
    dag_idx: BTreeMap<BlockHash, Idx>,
    dag_orden: Vec<BlockHash>,
}

impl DagTerminal {
    /// Crea el almacén con el terminal como raíz (D-P07).
    fn nueva(terminal: BlockHash, k: u32, max_padres: u8) -> Self {
        let params = ParametrosGhostdag {
            k,
            max_padres,
            mergeset_limite: MERGESET_LIMITE_ORACULO,
            s_max: u64::MAX,
            u2: true,
            u3_dinamica: true,
            sp: ModoSp::Zerox,
            merge: ModoMerge::Terna,
        };
        let dag = AlmacenGhostdag::con_raiz_terminal(
            params,
            Algoritmo::Kernel,
            terminal,
            RangoSolucionValidado::para_oraculos(0),
        );
        let mut dag_idx = BTreeMap::new();
        dag_idx.insert(terminal, 0);
        Self {
            dag,
            dag_idx,
            dag_orden: Vec::new(),
        }
    }
}

/// Datos GHOSTDAG de la punta virtual `V` de un terminal, calculados **sobre su DAG existente**
/// (sin reconstruirlo).
struct Virtual {
    datos: DatosGhostdag,
    slot: u64,
}

/// Gestor del estado del DAG en memoria.
#[derive(Clone)]
pub struct Cadena {
    params: ParametrosTransicion,
    /// SL-4a · parámetros de evidencia. `zx-node` los deja inactivos (SL-4b); los arneses usan
    /// [`Cadena::nueva_con_evidencia`].
    evidencia: ParametrosEvidencia,
    k: u32,
    cbid: u32,
    max_padres: u8,
    por_hash: BTreeMap<BlockHash, BloqueCadena>,
    validos: BTreeMap<BlockHash, bool>,
    motivos: BTreeMap<BlockHash, MotivoBloque>,
    past: BTreeMap<BlockHash, Estado>,
    post: BTreeMap<BlockHash, Estado>,
    descartes: BTreeMap<BlockHash, Vec<TxDescartada>>,
    /// Terminal **seleccionado** por FC-3 (`ORDEN-W06d7` decisión 2), con `C-FIN-01` entre
    /// terminales (decisión 3). `None` mientras no hay ningún candidato.
    terminal_seleccionado: Option<BlockHash>,
    /// `Estado(terminal_seleccionado)`, cacheado para que [`Cadena::estado_terminal`] pueda seguir
    /// devolviendo una referencia (compatibilidad de API, decisión 6). Se refresca en
    /// [`Cadena::recalcular_seleccion`].
    estado_t: Estado,
    /// `RET-1a/RET-1b` · Estado inicial **explícito** del que parten los bloques sin padre conocido
    /// y los respaldos de historia (`admitir_pow`, `estado_virtual*` y `aplicar_rama`).
    ///
    /// Aditivo: [`Cadena::nueva`] y [`Cadena::nueva_con_evidencia`] lo fijan a [`Estado::inicial`]
    /// (comportamiento de producción, sin cambio). [`Cadena::nueva_con_evidencia_e_inicial`] permite
    /// que un arnés diferencial use el perfil del oráculo (p. ej. `r_votos_slots = 0`, T01/T04).
    estado_inicial: Estado,
    /// Un DAG por terminal que ya tiene al menos un bloque PoST válido (decisión 1). Acotado a
    /// [`MAX_TERMINALES_CON_DAG`] (decisión 4).
    dags: BTreeMap<BlockHash, DagTerminal>,
    /// Terminal al que pertenece cada bloque PoST ya admitido (para resolver `chequear_forma` y los
    /// accesos «_de» por terminal sin recorrer todo `por_hash`).
    post_terminal: BTreeMap<BlockHash, BlockHash>,
    /// `ORDEN-IDX1` · I1 · Puntas PoST **válidas** por terminal (índice incremental): bloques PoST
    /// válidos del terminal sin ningún hijo válido, actualizado al admitir cada bloque en
    /// [`Cadena::admitir_uno`]. [`Cadena::tips_validas_de`] lo lee sin recorrer `por_hash`; la
    /// función anterior se conserva como referencia solo de pruebas (`tips_validas_referencia`).
    puntas_post: BTreeMap<BlockHash, BTreeSet<BlockHash>>,
    /// Se marcó al menos una vez el tope de [`MAX_TERMINALES_CON_DAG`] (decisión 4, `limite_alcanzado`).
    limite_alcanzado: bool,
    /// Puntas PoW válidas conocidas: bloques PoW sin ningún hijo PoW válido todavía
    /// (`ORDEN-W06d3` decisión 3). Varias a la vez es exactamente una bifurcación PoW.
    tips_pow: BTreeSet<BlockHash>,
    /// Bloques PoW que, en su propia rama, ya cumplen `es_terminal_condiciones` (altura, trabajo,
    /// `Φ`) y son el **primero** de su rama en cumplirlo (`TRN-04`,
    /// [`Cadena::es_primero_en_rama`]). Candidatos a terminal para siempre (`ORDEN-W06d7`: ya no se
    /// deja de admitir candidatos nuevos al aparecer el primer bloque PoST, que era el hallazgo de
    /// `W06d6`).
    terminal_candidatos: BTreeSet<BlockHash>,
    /// Bloques PoST rechazados por [`MotivoBloque::ErrLimiteTerminales`] que quedan **pendientes**
    /// de reevaluar (`ORDEN-W08a` decisiones 1–2): no se cachean como inválidos y se reintentan en
    /// orden determinista por hash. Acotado por [`MAX_PENDIENTES_TOPE`].
    pendientes_tope: BTreeSet<BlockHash>,
    /// Antigüedad de inserción en `pendientes_tope` (FIFO): al superar [`MAX_PENDIENTES_TOPE`] se
    /// descarta el más antiguo.
    pendientes_tope_edad: VecDeque<BlockHash>,
    /// Se desalojó un terminal en la última admisión: dispara el reintento de `pendientes_tope`
    /// (`ORDEN-W08a` decisión 2). Se limpia al terminar el reintento.
    desalojo_reciente: bool,
    /// `FIN-1` · Punto de finalidad del nodo: bloque de la cadena seleccionada del virtual con el
    /// mayor `slot ≤ slot(punta seleccionada) − F_slots`. Se recalcula al avanzar la punta y
    /// **nunca retrocede**. `None` mientras `f_slots` es `None` o no hay terminal con DAG.
    punto_finalidad: Option<BlockHash>,
    /// `FIN-1` · Violaciones de la cota registradas, clave `(finalidad, bloque)` para no repetir, con
    /// la profundidad en slots. Solo se escribe; `zx-node` lo consulta con
    /// [`Cadena::violaciones_finalidad`].
    violaciones_finalidad: BTreeMap<(BlockHash, BlockHash), u64>,
    /// `FIN-1` · `true` (por defecto) aplica la cota de finalidad en la selección, que es el
    /// comportamiento del **nodo**. Los diferenciales contra oráculos que **no** modelan `R1`
    /// (`T04`, mono-terminal) lo desactivan con [`Cadena::sin_finalidad_dag`] para comparar el
    /// motor de DAG puro (validez, GHOSTDAG y estado), que la cota no cambia.
    finalidad_dag: bool,
    /// FV-4b-N1 · `true` cuando el punto de finalidad lo gobiernan los **votos**.
    ///
    /// Con esta bandera, `FIN-1` dentro del terminal solo **avanza** (nunca re-basa el punto a la
    /// cadena de otro terminal): un certificado en conflicto no puede hacer que el nodo salte de
    /// rama solo. El ancla explícita la fija [`Cadena::anclar_finalidad_por_votos`].
    finalidad_por_votos: bool,
    /// ECL-R2a · D1 · Ancla de votos `(n, h)` = último certificado aplicado en el estado o
    /// verificado por D2. Solo avanza; se reconstruye del estado al reiniciar.
    ancla_votos: Option<(u64, BlockHash)>,
    /// ECL-R2a · Ancla anterior a la última adopción (para el evento de eclipse).
    ancla_previa: Option<(u64, BlockHash)>,
    /// ECL-R2a · Último certificado `(n, h)` que movió el ancla.
    certificado_ancla: Option<(u64, BlockHash)>,
    /// ECL-R2a · D5 · `true` si el candidato del ancla no está en ningún DAG conocido.
    ancla_pendiente: bool,
    /// ECL-R2a · D4 · Eclipse detectado, si lo hay.
    eclipse: Option<Eclipse>,
    /// ECL-R2a · Conflictos de misma instancia registrados `(n, h_actual, h_recibido)`.
    conflictos_ancla: Vec<(u64, BlockHash, BlockHash)>,
    /// AT-1b · W1 · `(finalidad_votos_n, finalidad_votos)` del estado del **pasado** de cada bloque
    /// PoST admitido. No se borra mientras exista el bloque. Lo consume el cálculo del hecho de la
    /// falta entre ventanas (W2).
    finalidad_pasado: BTreeMap<BlockHash, (u64, Option<BlockHash>)>,
    /// AT-1b2 · X4 · contador de bloques visitados por [`Cadena::aplicado_antes_que`] y
    /// [`Cadena::desciende_acotado`], legible desde las pruebas. El campo **solo existe** con
    /// `cfg(test)`: en producción los recorridos no pagan ningún incremento (el cuerpo de
    /// [`Cadena::visita`] queda vacío).
    #[cfg(test)]
    visitas: std::cell::Cell<u64>,
}

/// AT-1b · W2 · contexto de aplicación de un bloque `x` dentro de un bloque de cadena `g` (o del
/// virtual `V`): con los propios datos del DAG decide «aplicado antes que `x`».
struct ContextoAplicacion {
    /// Terminal del DAG.
    terminal: BlockHash,
    /// Índice de `g` en el DAG, o `None` si `g` es el virtual `V`.
    g_idx: Option<Idx>,
    /// Conjunto de fusión de `g` (sin `RojoU3`) en orden de aplicación.
    mergeset: Vec<Idx>,
    /// Padre seleccionado de `g` (para `V`, `v.datos.sp`).
    sp: Idx,
    /// `slot(g)` (para `V`, `slot(V)`).
    slot_g: u64,
}

impl Cadena {
    /// PROD-3a: ensaya una candidata PoST con el **cálculo único** de la admisión sobre una vista de
    /// solo lectura, sin copiar la cadena ni ninguno de sus mapas.
    ///
    /// Superpone el `DagTerminal` del terminal de la candidata (con la candidata añadida) y la
    /// propia candidata en la consulta por `hash`. Reutiliza la admisión PoST: colores y mergeset
    /// reales, estado del pasado, garantía, hechos de las evidencias y transición de fusión. No
    /// recalcula la selección ni toca el original. La verificación criptográfica de cabecera sigue
    /// siendo del llamante, igual que en `admitir`; una candidata sin sello puede ensayar su cuerpo.
    ///
    /// # Errores
    /// El mismo motivo que la admisión PoST. Una candidata cuyo hash ya existe se rechaza
    /// para impedir que el ensayo reutilice silenciosamente un resultado cacheado.
    pub fn ensayar_post(
        &self,
        candidata: &BloquePost,
    ) -> Result<(Estado, Vec<TxDescartada>), MotivoBloque> {
        if self.por_hash.contains_key(&candidata.hash) {
            return Err(MotivoBloque::ErrSinPadre);
        }
        let terminal = self.chequear_forma(candidata)?;
        let mut dag = admision_post::dag_para_ensayo(self, terminal)?;
        admision_post::anadir_al_dag(&mut dag, candidata)?;
        let idx = dag
            .dag_idx
            .get(&candidata.hash)
            .copied()
            .ok_or(MotivoBloque::ErrSinPadre)?;
        let bloque = BloqueCadena::Post(candidata.clone());
        let vista = admision_post::VistaPost::nueva(self, terminal, dag, bloque);
        let base = admision_post::calcular_base(&vista, terminal, idx, candidata)?;
        let (estado, descartes) = admision_post::aplicar_candidata(
            &vista,
            &base,
            terminal,
            idx,
            candidata,
            vista.bloque(),
        )?;
        Ok((estado, descartes))
    }

    /// Crea una cadena vacía con los parámetros de transición, el `k` de GHOSTDAG, el `CBID` y el
    /// **máximo de padres** de un bloque PoST.
    ///
    /// `max_padres` no tiene valor por defecto oculto (`ORDEN-W06a-C` decisión 1): el nodo usa el
    /// del perfil dev (15, `PERFIL-DEV-v0.md` §4) y el arnés diferencial de T04 usa 3, el límite de
    /// su generador. Es el tope que `zx-cadena` impone a cada `AlmacenGhostdag` interno; `zx-dag` lo
    /// acota a [`zx_core::MAX_PADRES`] (15) y a `u8`.
    #[must_use]
    pub fn nueva(params: ParametrosTransicion, k: u32, cbid: u32, max_padres: u8) -> Self {
        Self::nueva_con_evidencia(params, k, cbid, max_padres, ParametrosEvidencia::inactiva())
    }

    /// Igual que [`Cadena::nueva`], con los parámetros de evidencia explícitos (SL-4a).
    ///
    /// No cambia de comportamiento: delega en [`Cadena::nueva_con_evidencia_e_inicial`] con
    /// [`Estado::inicial`].
    #[must_use]
    pub fn nueva_con_evidencia(
        params: ParametrosTransicion,
        k: u32,
        cbid: u32,
        max_padres: u8,
        evidencia: ParametrosEvidencia,
    ) -> Self {
        Self::nueva_con_evidencia_e_inicial(
            params,
            k,
            cbid,
            max_padres,
            evidencia,
            Estado::inicial(),
        )
    }

    /// `RET-1a/RET-1b` · Igual que [`Cadena::nueva_con_evidencia`] pero con el **estado inicial
    /// explícito** `inicial`.
    ///
    /// Construcción **aditiva**: las construcciones existentes no cambian de firma ni de
    /// comportamiento (siguen partiendo de [`Estado::inicial`]). La usa el arnés diferencial T04
    /// para correr con `parametros_sector.r_votos_slots = 0`, igual que el T01
    /// ([`zx_consensus::transicion::seleccion::seleccionar_con_inicial`]), porque el oráculo no
    /// modela el plazo de retención por votos.
    #[must_use]
    pub fn nueva_con_evidencia_e_inicial(
        params: ParametrosTransicion,
        k: u32,
        cbid: u32,
        max_padres: u8,
        evidencia: ParametrosEvidencia,
        inicial: Estado,
    ) -> Self {
        Self {
            params,
            evidencia,
            k,
            cbid,
            max_padres,
            por_hash: BTreeMap::new(),
            validos: BTreeMap::new(),
            motivos: BTreeMap::new(),
            past: BTreeMap::new(),
            post: BTreeMap::new(),
            descartes: BTreeMap::new(),
            terminal_seleccionado: None,
            estado_t: inicial.clone(),
            estado_inicial: inicial,
            dags: BTreeMap::new(),
            post_terminal: BTreeMap::new(),
            puntas_post: BTreeMap::new(),
            limite_alcanzado: false,
            tips_pow: BTreeSet::new(),
            terminal_candidatos: BTreeSet::new(),
            pendientes_tope: BTreeSet::new(),
            pendientes_tope_edad: VecDeque::new(),
            desalojo_reciente: false,
            punto_finalidad: None,
            violaciones_finalidad: BTreeMap::new(),
            finalidad_dag: true,
            finalidad_por_votos: false,
            ancla_votos: None,
            ancla_previa: None,
            certificado_ancla: None,
            ancla_pendiente: false,
            eclipse: None,
            conflictos_ancla: Vec::new(),
            finalidad_pasado: BTreeMap::new(),
            #[cfg(test)]
            visitas: std::cell::Cell::new(0),
        }
    }

    /// `FIN-1` · Desactiva la cota de finalidad en la selección: el comportamiento previo (GHOSTDAG
    /// puro), que es el que modelan los oráculos T04/T01. El nodo **no** la desactiva.
    #[must_use]
    pub fn sin_finalidad_dag(mut self) -> Self {
        self.finalidad_dag = false;
        self.punto_finalidad = None;
        self
    }

    /// ¿Está admitido y es válido el bloque `hash`?
    #[must_use]
    pub fn es_valido(&self, hash: &BlockHash) -> bool {
        self.validos.get(hash).copied().unwrap_or(false)
    }

    /// Motivo por el que `hash` no se admitió, si se procesó y falló.
    #[must_use]
    pub fn motivo(&self, hash: &BlockHash) -> Option<&MotivoBloque> {
        self.motivos.get(hash)
    }

    /// `Estado(past(B))`, si `B` se admitió con éxito.
    #[must_use]
    pub fn estado_past(&self, hash: &BlockHash) -> Option<&Estado> {
        self.past.get(hash)
    }

    /// `Estado(past(B) ∪ {B})`, si `B` se admitió con éxito.
    #[must_use]
    pub fn estado_post(&self, hash: &BlockHash) -> Option<&Estado> {
        self.post.get(hash)
    }

    /// Descartes registrados al aplicar `B` sobre `Estado(past(B))`.
    #[must_use]
    pub fn descartes(&self, hash: &BlockHash) -> Option<&[TxDescartada]> {
        self.descartes.get(hash).map(Vec::as_slice)
    }

    /// Hash del terminal **seleccionado** por FC-3 (`ORDEN-W06d7` decisión 2), si existe algún
    /// candidato.
    #[must_use]
    pub fn terminal(&self) -> Option<BlockHash> {
        self.terminal_seleccionado
    }

    /// `Estado(T)` del terminal seleccionado (el estado tras aplicar ese bloque PoW).
    #[must_use]
    pub fn estado_terminal(&self) -> &Estado {
        &self.estado_t
    }

    /// Todos los terminales candidatos conocidos (con DAG o sin él), en orden de hash.
    #[must_use]
    pub fn terminal_candidatos(&self) -> Vec<BlockHash> {
        self.terminal_candidatos.iter().copied().collect()
    }

    /// Terminales que ya tienen su propio DAG (al menos un bloque PoST válido), en orden de hash
    /// (`ORDEN-W06d7` decisión 1).
    #[must_use]
    pub fn terminales_con_dag(&self) -> Vec<BlockHash> {
        self.dags.keys().copied().collect()
    }

    /// ¿Se alcanzó alguna vez el tope [`MAX_TERMINALES_CON_DAG`] (decisión 4)?
    #[must_use]
    pub fn limite_terminales_alcanzado(&self) -> bool {
        self.limite_alcanzado
    }

    /// `FIN-1` · Punto de finalidad vigente del nodo, si existe. Es el bloque de la cadena
    /// seleccionada del virtual con el mayor `slot ≤ slot(punta seleccionada) − F_slots`; se
    /// recalcula al avanzar la punta y nunca retrocede.
    #[must_use]
    pub fn punto_finalidad(&self) -> Option<BlockHash> {
        self.punto_finalidad
    }

    /// FV-4b-N1 · Activa la finalidad por votos: a partir de aquí, `FIN-1` solo **avanza** el punto
    /// dentro del DAG que ya lo contiene y nunca lo re-basa a otra rama al cambiar de terminal.
    pub fn activar_finalidad_por_votos(&mut self) {
        self.finalidad_por_votos = true;
    }

    /// FV-4b-N1 · ¿Gobiernan los votos el punto de finalidad?
    #[must_use]
    pub const fn finalidad_por_votos(&self) -> bool {
        self.finalidad_por_votos
    }

    /// FV-4b-N1 · Ancla el punto de finalidad en `h`, adoptando el candidato de un certificado de
    /// votos.
    ///
    /// Solo se adopta si `h` es un bloque admitido de la **cadena seleccionada** del terminal actual
    /// y **desciende-o-igual** del punto vigente (o no hay punto). Un certificado **atrasado** cuyo
    /// candidato es un **antepasado** del punto vigente en esa cadena no es un ataque y no retrocede
    /// la finalidad: devuelve `Ok(())` sin mover el punto (ANC-1 · A2). Un candidato desconocido, o
    /// de una rama en conflicto (ni ancestro ni descendiente del punto), devuelve `Err`: el nodo
    /// **no** adopta el certificado y no salta de rama solo (se registra `certificado_en_conflicto`;
    /// la recuperación es ECL-R2).
    ///
    /// # Errores
    /// [`MotivoAncla::Desconocido`] si `h` no está en el DAG del terminal seleccionado;
    /// [`MotivoAncla::Conflicto`] si no desciende del punto de finalidad vigente ni es su ancestro.
    pub fn anclar_finalidad_por_votos(&mut self, h: BlockHash) -> Result<(), MotivoAncla> {
        let Some(terminal) = self.terminal_seleccionado else {
            return Err(MotivoAncla::Desconocido);
        };
        if !self.hash_en_dag(terminal, h) {
            return Err(MotivoAncla::Desconocido);
        }
        if let Some(pf) = self.punto_finalidad {
            // ANC-1 · A2 · Un antepasado del punto vigente (misma cadena seleccionada) es un
            // certificado atrasado, no un conflicto: no mueve el punto y no se registra conflicto.
            if !self.cadena_contiene(terminal, h, pf) {
                if self.cadena_contiene(terminal, pf, h) {
                    return Ok(());
                }
                return Err(MotivoAncla::Conflicto);
            }
        }
        self.punto_finalidad = Some(h);
        self.finalidad_por_votos = true;
        Ok(())
    }

    /// ECL-R2a · D1 · Ancla de votos vigente `(n, h)`, si existe.
    #[must_use]
    pub fn ancla_votos(&self) -> Option<(u64, BlockHash)> {
        self.ancla_votos
    }

    /// ECL-R2a · D5 · `true` si el candidato del ancla no está en ningún DAG conocido.
    #[must_use]
    pub fn ancla_pendiente(&self) -> bool {
        self.ancla_pendiente
    }

    /// ECL-R2a · D4 · Eclipse detectado, si lo hay.
    #[must_use]
    pub fn eclipse(&self) -> Option<Eclipse> {
        self.eclipse
    }

    /// ECL-R2a · Conflictos de misma instancia registrados `(n, h_actual, h_recibido)`.
    #[must_use]
    pub fn conflictos_ancla(&self) -> &[(u64, BlockHash, BlockHash)] {
        &self.conflictos_ancla
    }

    /// ECL-R2a · D1 · Deriva el ancla del **estado** admitido (`finalidad_votos_n`,
    /// `finalidad_votos`). Es monótona: `n' < n` se ignora; `n' == n` con otro candidato es
    /// conflicto de misma instancia y no se adopta. Si el candidato está en un terminal conocido
    /// dentro de `F`, guía la selección (D3); si no está en ningún DAG, queda **pendiente** (D5).
    pub fn considerar_ancla_de_estado(&mut self, n: u64, h: BlockHash) -> ResultadoAncla {
        self.considerar_ancla(n, h)
    }

    /// ECL-R2a · D2 · Adopta el ancla de un certificado **verificado desde el ancla** (sin estado
    /// local). Mismas reglas de monotonía que [`Cadena::considerar_ancla_de_estado`].
    pub fn considerar_ancla_verificada(&mut self, n: u64, h: BlockHash) -> ResultadoAncla {
        self.considerar_ancla(n, h)
    }

    /// Núcleo de [`Cadena::considerar_ancla_de_estado`] / [`Cadena::considerar_ancla_verificada`].
    fn considerar_ancla(&mut self, n: u64, h: BlockHash) -> ResultadoAncla {
        match self.ancla_votos {
            None => {
                self.ancla_previa = None;
                self.ancla_votos = Some((n, h));
                self.certificado_ancla = Some((n, h));
                self.recalcular_seleccion();
                self.resultado_ancla()
            }
            Some((actual_n, actual_h)) => {
                if n < actual_n {
                    return ResultadoAncla::Ignorada;
                }
                if n == actual_n {
                    if h == actual_h {
                        return ResultadoAncla::Idempotente;
                    }
                    self.conflictos_ancla.push((n, actual_h, h));
                    return ResultadoAncla::ConflictoMismaInstancia;
                }
                self.ancla_previa = Some((actual_n, actual_h));
                self.ancla_votos = Some((n, h));
                self.certificado_ancla = Some((n, h));
                self.recalcular_seleccion();
                self.resultado_ancla()
            }
        }
    }

    /// Resultado tras adoptar un ancla: pendiente (sin datos) o adoptada.
    fn resultado_ancla(&self) -> ResultadoAncla {
        if self.ancla_pendiente {
            ResultadoAncla::Pendiente
        } else {
            ResultadoAncla::Adoptada
        }
    }

    /// ECL-R2a · D5/D4 · Recalcula `ancla_pendiente` y `eclipse` desde el ancla y la selección.
    ///
    /// - Si el candidato `h` no está en ningún DAG: ancla pendiente (no cambia de terminal).
    /// - Si está en el terminal seleccionado: nada que hacer.
    /// - Si está en **otro** terminal y el sufijo del actual ya abarca `F_slots`: ir a esa rama
    ///   exige ir más allá de `F` en conflicto ⇒ eclipse (D4).
    fn evaluar_ancla(&mut self) {
        // ECL-R2a-2 · D4 **enclavado**: una vez demostrada la condición de parada, ni un recálculo,
        // ni nuevos bloques/certificados, ni un cambio de ancla la borran en esta sesión. Se conserva
        // la primera causa (y el fichero de recuperación ya escrito); solo el reinicio del operador
        // levanta la parada.
        if self.eclipse.is_some() {
            return;
        }
        self.ancla_pendiente = false;
        let Some((n_ancla, h)) = self.ancla_votos else {
            return;
        };
        let contenedores = self.terminales_que_contienen(h);
        if contenedores.is_empty() {
            self.ancla_pendiente = true;
            return;
        }
        let Some(actual) = self.terminal_seleccionado else {
            return;
        };
        let tope = self.params.f_slots.unwrap_or(u64::MAX);
        if contenedores.contains(&actual) {
            // ECL-R2a-3 · Mismo terminal: pertenecer al DAG **no** prueba descender del `F` vigente
            // (el DAG incluye ramas en conflicto). Si hay punto de finalidad en este terminal, el
            // candidato solo es compatible si está en la **misma cadena** que `F`: descendiente
            // suyo (progresa) o ancestro suyo (certificado atrasado: no es ataque y no retrocede
            // `F`). Una rama incompatible obliga a rebasar `F`; si el sufijo ya abarca `F_slots`,
            // eso es el conflicto profundo de PK-27B y deja el eclipse enclavado.
            if let Some(pf) = self.punto_finalidad
                && self.hash_en_dag(actual, pf)
                && !self.cadena_contiene(actual, h, pf)
                && !self.cadena_contiene(actual, pf, h)
            {
                let d = self.slot_max_de(actual);
                if d >= tope {
                    self.marcar_eclipse(n_ancla, h, d);
                }
            }
            return;
        }
        let d = self.slot_max_de(actual);
        if d >= tope {
            self.marcar_eclipse(n_ancla, h, d);
        }
    }

    /// ECL-R2a · Fija el eclipse con la primera causa: el ancla previa (si la hay), el certificado
    /// que lo disparó y la profundidad.
    fn marcar_eclipse(&mut self, n_ancla: u64, h: BlockHash, d: u64) {
        let (n_cert, h_cert) = self.certificado_ancla.unwrap_or((n_ancla, h));
        let (n_prev, h_prev) = self.ancla_previa.unwrap_or((n_ancla, h));
        self.eclipse = Some(Eclipse {
            n_ancla: n_prev,
            h_ancla: h_prev,
            n_certificado: n_cert,
            h_certificado: h_cert,
            profundidad: d,
        });
    }

    /// ECL-R2a · Terminales con DAG que contienen `h`.
    fn terminales_que_contienen(&self, h: BlockHash) -> Vec<BlockHash> {
        self.dags
            .keys()
            .copied()
            .filter(|t| self.hash_en_dag(*t, h))
            .collect()
    }

    /// ECL-R2a · D3 · Terminal objetivo que contiene el candidato del ancla. Si el seleccionado ya
    /// lo contiene, se mantiene (la regla `F` gobierna dentro de él); entre varios, desempate FC-3.
    /// Si el ancla está pendiente o no hay terminal que lo contenga, devuelve `fallback`.
    fn terminal_objetivo_ancla(&self, fallback: BlockHash) -> BlockHash {
        let Some((_n, h)) = self.ancla_votos else {
            return fallback;
        };
        if self.ancla_pendiente {
            return fallback;
        }
        if let Some(actual) = self.terminal_seleccionado
            && self.hash_en_dag(actual, h)
        {
            return actual;
        }
        let contenedores = self.terminales_que_contienen(h);
        match contenedores.as_slice() {
            [] => fallback,
            [unico] => *unico,
            _ => contenedores
                .into_iter()
                .min_by(|a, b| {
                    let ra = self.rank_virtual_de(*a);
                    let rb = self.rank_virtual_de(*b);
                    comparar_blue_work(ra, rb)
                        .then_with(|| comparar_terminal(Some(*a), Some(*b)).reverse())
                        .then_with(|| comparar_rank(ra, rb))
                })
                .unwrap_or(fallback),
        }
    }

    /// `FIN-1` · Violaciones de la cota registradas hasta ahora, en orden determinista por
    /// `(finalidad, bloque)`. `zx-node` puede consultarlas para emitir `violacion_finalidad`.
    #[must_use]
    pub fn violaciones_finalidad(&self) -> Vec<ViolacionFinalidad> {
        self.violaciones_finalidad
            .iter()
            .map(|((finalidad, bloque), profundidad)| ViolacionFinalidad {
                finalidad: *finalidad,
                bloque: *bloque,
                profundidad: *profundidad,
            })
            .collect()
    }

    /// Terminal al que pertenece un bloque PoST ya admitido, si se conoce.
    #[must_use]
    pub fn terminal_de(&self, hash: &BlockHash) -> Option<BlockHash> {
        self.post_terminal.get(hash).copied()
    }

    /// Acceso al bloque por su hash, si se conoce.
    #[must_use]
    pub fn bloque(&self, hash: &BlockHash) -> Option<&BloqueCadena> {
        self.por_hash.get(hash)
    }

    /// El `AlmacenGhostdag` real del terminal **seleccionado**, si ya tiene DAG (`ORDEN-W06d1`,
    /// «Relanzamiento» punto 3; multi-terminal desde `ORDEN-W06d7`).
    ///
    /// `AlmacenGhostdag` ya implementa [`zx_dag::bloque_dag::ContextoDag`] sobre sus propios
    /// bloques admitidos, con `padre_seleccionado` calculado por GHOSTDAG real (`comparar_sp`,
    /// `C-GD-03`), no declarado por el candidato. Este accesor es lo que le faltaba a `Cadena` para
    /// que un llamante externo (el nodo) pueda verificar la cabecera de un candidato **antes** de
    /// admitirlo, sin volver a implementar la selección de padre en otro sitio.
    ///
    /// `None` hasta que se admite el **primer bloque PoST** del terminal seleccionado. Para
    /// verificar contra un terminal que no es el seleccionado (varios DAG a la vez), usa
    /// [`Cadena::contexto_dag_de`].
    #[must_use]
    pub fn contexto_dag(&self) -> Option<&zx_dag::ghostdag::AlmacenGhostdag> {
        self.terminal_seleccionado
            .and_then(|t| self.dags.get(&t))
            .map(|dt| &dt.dag)
    }

    /// El `AlmacenGhostdag` real de un terminal concreto, sea o no el seleccionado (`ORDEN-W06d7`
    /// decisión 5: el nodo necesita un servicio de verificación por terminal con DAG, no solo el
    /// seleccionado).
    #[must_use]
    pub fn contexto_dag_de(
        &self,
        terminal: BlockHash,
    ) -> Option<&zx_dag::ghostdag::AlmacenGhostdag> {
        self.dags.get(&terminal).map(|dt| &dt.dag)
    }

    /// Bloques PoST conocidos (válidos e inválidos), en orden de hash.
    #[must_use]
    pub fn bloques_post(&self) -> Vec<&BloquePost> {
        self.por_hash
            .values()
            .filter_map(|b| match b {
                BloqueCadena::Post(p) => Some(p),
                BloqueCadena::Pow(_) => None,
            })
            .collect()
    }

    /// Admite un bloque (PoW o PoST). Devuelve `Ok` si es válido.
    ///
    /// Un bloque ya procesado devuelve el resultado almacenado, sin reprocesarlo.
    ///
    /// # `ErrSinPadre` por una dependencia que **todavía no ha llegado** no se cachea (RI-2a #1)
    ///
    /// Si el padre (o, en PoST, algún terminal candidato) del bloque no está disponible
    /// **todavía**, el rechazo es provisional: el mismo bloque, sometido otra vez después de que su
    /// dependencia llegue, MUST poder admitirse. La comprobación
    /// ([`Self::dependencia_no_disponible`]) se hace **antes** de tocar `admitir_pow`/`admitir_post`
    /// —y por tanto antes de cualquier mutación del DAG interno—, así que reintentar más tarde
    /// vuelve a ejecutar la tubería completa desde cero, nunca a medias.
    ///
    /// # `ErrLimiteTerminales` no se cachea (`ORDEN-W08a` decisiones 1–2)
    ///
    /// El tope [`MAX_TERMINALES_CON_DAG`] depende del conjunto **local** de terminales con DAG, no
    /// del candidato: un rechazo por [`MotivoBloque::ErrLimiteTerminales`] queda **pendiente** (en
    /// `por_hash` y en `pendientes_tope`, acotado por [`MAX_PENDIENTES_TOPE`]) y se reevalúa en el
    /// siguiente `admitir` del mismo bloque. Además, cuando una admisión desaloja un terminal, se
    /// reintentan los pendientes en orden determinista por hash. Los rechazos demostrables se
    /// siguen cacheando.
    ///
    /// # Errores
    /// El [`MotivoBloque`] que haya invalidado el bloque.
    pub fn admitir(&mut self, bloque: BloqueCadena) -> Result<(), MotivoBloque> {
        let resultado = self.admitir_uno(bloque);
        if self.desalojo_reciente {
            self.desalojo_reciente = false;
            self.reintentar_pendientes_tope();
            // El propio reintento puede desalojar; no deja trabajo pendiente para la próxima
            // llamada (la cola ya se recorrió hasta el punto fijo).
            self.desalojo_reciente = false;
        }
        resultado
    }

    /// Una admisión, sin el reintento posterior por desalojo (`ORDEN-W08a`).
    ///
    /// Es la tubería de [`Self::admitir`]. Un rechazo por
    /// [`MotivoBloque::ErrLimiteTerminales`] **no** se cachea en `validos`/`motivos` (decisión 1);
    /// el bloque queda anotado en `pendientes_tope`.
    fn admitir_uno(&mut self, bloque: BloqueCadena) -> Result<(), MotivoBloque> {
        let hash = bloque.hash();
        if let Some(v) = self.validos.get(&hash).copied() {
            self.quitar_pendiente_tope(&hash);
            return if v {
                Ok(())
            } else {
                Err(self
                    .motivos
                    .get(&hash)
                    .cloned()
                    .unwrap_or(MotivoBloque::ErrSinPadre))
            };
        }
        if self.dependencia_no_disponible(&bloque) {
            // Vuelve a ser pendiente por dependencia, no por tope: sale de la cola del tope.
            self.quitar_pendiente_tope(&hash);
            self.por_hash.insert(hash, bloque);
            return Err(MotivoBloque::ErrSinPadre);
        }
        self.por_hash.insert(hash, bloque.clone());
        let resultado = match &bloque {
            BloqueCadena::Pow(_) => self.admitir_pow(&bloque),
            BloqueCadena::Post(_) => self.admitir_post(&bloque),
        };
        match &resultado {
            Ok(()) => {
                self.quitar_pendiente_tope(&hash);
                self.validos.insert(hash, true);
                // `ORDEN-IDX1` · I1: el índice de puntas se actualiza **antes** de recalcular la
                // selección, para que el bloque recién admitido cuente igual que contaba el
                // recorrido de `por_hash` de la referencia (comparten la vista de `validos`).
                self.actualizar_indice_puntas(&hash);
                // `ORDEN-W06d7`: la selección FC-3 entre terminales se recalcula **aquí**, después
                // de marcar `hash` como válido — no dentro de `admitir_pow`/`admitir_post`. Un bloque
                // PoST recién admitido participa en `tips_validas_de`/`dag_virtual_de` (que filtran
                // por `Self::es_valido`) solo a partir de este punto; recalcular la selección antes
                // (como hacía una versión previa de este cambio) veía una vista atrasada de un
                // bloque —el que se acaba de admitir con éxito—, y un empate de `blue_work` que este
                // mismo bloque resolvía se evaluaba con el estado de un paso antes: no violaba
                // ningún invariante de aplicación (`past`/`post` ya estaban completos), pero sí I-3
                // por un paso de más entre "admitido" y "contado para la selección".
                self.recalcular_seleccion();
            }
            // `ORDEN-W08a` decisión 1: el tope de terminales es vista local; no se fija como
            // inválido para poder reevaluarlo cuando la vista cambie.
            Err(MotivoBloque::ErrLimiteTerminales) => self.anotar_pendiente_tope(hash),
            Err(motivo) => {
                self.quitar_pendiente_tope(&hash);
                self.validos.insert(hash, false);
                self.motivos.insert(hash, motivo.clone());
            }
        }
        resultado
    }

    /// Anota `hash` como pendiente por [`MotivoBloque::ErrLimiteTerminales`], respetando
    /// [`MAX_PENDIENTES_TOPE`] (al superarlo se descarta el más antiguo, decisión 2).
    fn anotar_pendiente_tope(&mut self, hash: BlockHash) {
        if !self.pendientes_tope.insert(hash) {
            return;
        }
        self.pendientes_tope_edad.push_back(hash);
        while self.pendientes_tope.len() > MAX_PENDIENTES_TOPE {
            let Some(viejo) = self.pendientes_tope_edad.pop_front() else {
                break;
            };
            self.pendientes_tope.remove(&viejo);
        }
    }

    /// Saca `hash` de la cola de pendientes por tope (si estaba).
    fn quitar_pendiente_tope(&mut self, hash: &BlockHash) {
        if self.pendientes_tope.remove(hash)
            && let Some(pos) = self.pendientes_tope_edad.iter().position(|h| h == hash)
        {
            self.pendientes_tope_edad.remove(pos);
        }
    }

    /// Reintenta los bloques pendientes por tope, en orden determinista por hash (`ORDEN-W08a`
    /// decisión 2). Se llama tras una admisión que desalojó un terminal.
    ///
    /// Coste: a lo sumo `MAX_PENDIENTES_TOPE` admisiones por pasada; cada pasada que progresa
    /// (admite un pendiente o lo reclasifica) saca al menos uno de la cola, así que termina.
    fn reintentar_pendientes_tope(&mut self) {
        loop {
            if self.pendientes_tope.is_empty() {
                return;
            }
            let mut progreso = false;
            for hash in self.pendientes_tope.iter().copied().collect::<Vec<_>>() {
                if !self.pendientes_tope.contains(&hash) {
                    continue;
                }
                let Some(bloque) = self.por_hash.get(&hash).cloned() else {
                    self.quitar_pendiente_tope(&hash);
                    continue;
                };
                let resultado = self.admitir_uno(bloque);
                // `admitir_uno` saca de la cola todo salvo `ErrLimiteTerminales`; si algo salió,
                // puede haberse liberado cupo y conviene otra pasada.
                if !matches!(resultado, Err(MotivoBloque::ErrLimiteTerminales)) {
                    progreso = true;
                }
            }
            if !progreso {
                return;
            }
        }
    }

    /// ¿Depende `bloque` de algo (un padre PoW, o **cualquier** terminal candidato para un PoST)
    /// que esta `Cadena` todavía no tiene?
    #[must_use]
    fn dependencia_no_disponible(&self, bloque: &BloqueCadena) -> bool {
        match bloque {
            BloqueCadena::Pow(_) => bloque
                .padre_seleccionado()
                .is_some_and(|p| !self.post.contains_key(&p)),
            BloqueCadena::Post(p) => {
                if self.terminal_candidatos.is_empty() {
                    return true;
                }
                p.padres
                    .iter()
                    .any(|x| !self.terminal_candidatos.contains(x) && !self.es_valido(x))
            }
        }
    }

    /// Procesa un conjunto de bloques con un orden de llegada arbitrario, reintentando los que
    /// tienen padres aún no procesados (espejo de `resolver!`/`padres_listos` del oráculo T04).
    ///
    /// # Errores
    /// `ErrSinPadre` si no se puede progresar (ciclo o padre ausente no rechazable).
    pub fn resolver(
        &mut self,
        bloques: &[BloqueCadena],
        llegada: &[usize],
    ) -> Result<(), MotivoBloque> {
        for b in bloques {
            self.por_hash.entry(b.hash()).or_insert_with(|| b.clone());
        }
        let mut pendientes: Vec<usize> = llegada.to_vec();
        while !pendientes.is_empty() {
            let mut quedan = Vec::new();
            let mut progreso = false;
            for j in &pendientes {
                let Some(b) = bloques.get(*j) else {
                    continue;
                };
                if self.validos.contains_key(&b.hash()) {
                    continue;
                }
                if self.padres_listos(b) {
                    let _ = self.admitir(b.clone());
                    progreso = true;
                } else {
                    quedan.push(*j);
                }
            }
            pendientes = quedan;
            if !progreso {
                return Err(MotivoBloque::ErrSinPadre);
            }
        }
        Ok(())
    }

    /// ¿Están listos los padres de `b` (desconocido ⇒ se puede rechazar ya)?
    fn padres_listos(&self, b: &BloqueCadena) -> bool {
        if !self.por_hash.contains_key(&b.hash()) {
            return true;
        }
        for p in b.padres() {
            if self.terminal_candidatos.contains(&p) {
                continue;
            }
            if !self.por_hash.contains_key(&p) {
                return true;
            }
            if !self.validos.contains_key(&p) {
                return false;
            }
        }
        true
    }

    /// Admite un bloque PoW en modo estricto (`ED-1`).
    ///
    /// Cada bloque se valida contra el estado de **su padre declarado** (`self.post.get(&p)`), no
    /// contra ninguna noción de "la punta": dos bloques con el mismo padre (una bifurcación PoW) se
    /// admiten los dos, cada uno con su propio `Estado(past)`/`Estado(post)` independiente.
    fn admitir_pow(&mut self, bloque: &BloqueCadena) -> Result<(), MotivoBloque> {
        let (hash, padre) = match bloque {
            BloqueCadena::Pow(b) => (b.hash(), b.padre()),
            BloqueCadena::Post(_) => return Err(MotivoBloque::ErrSinPadre),
        };
        let estado_padre = match padre {
            None => self.estado_inicial.clone(),
            Some(p) => self
                .post
                .get(&p)
                .cloned()
                .ok_or(MotivoBloque::ErrSinPadre)?,
        };
        let nuevo = aplicar(
            &estado_padre,
            &bloque.como_transicion(),
            &self.params,
            self.cbid,
            &self.evidencia,
        )?;

        // Una bifurcación PoW real: el padre deja de ser punta (si lo era) y este bloque lo es.
        if let Some(p) = padre {
            self.tips_pow.remove(&p);
        }
        self.tips_pow.insert(hash);

        // `ORDEN-W06d7` decisión 1: ya no se congela el primer terminal (hallazgo de W06d6); se
        // sigue registrando cualquier candidato nuevo, tenga o no otro terminal ya un DAG.
        let es_candidato = bloque
            .como_transicion()
            .hechos
            .altura()
            .is_some_and(|altura| es_terminal_condiciones(&nuevo, &self.params, altura))
            && self.es_primero_en_rama(padre);

        self.past.insert(hash, estado_padre);
        self.post.insert(hash, nuevo);

        if es_candidato {
            self.terminal_candidatos.insert(hash);
            // La recomputación de la selección FC-3 la hace `Cadena::admitir` (el llamante), después
            // de marcar `hash` como válido (`ORDEN-W06d7`, ver su comentario).
        }
        Ok(())
    }

    /// ¿Es `hash` (de padre `padre`) el **primer** bloque de su rama en cumplir
    /// `es_terminal_condiciones` (`TRN-04`: «ningún ancestro suyo cumple las tres condiciones»)?
    fn es_primero_en_rama(&self, padre: Option<BlockHash>) -> bool {
        let mut actual = padre;
        while let Some(p) = actual {
            if self.terminal_candidatos.contains(&p) {
                return false;
            }
            actual = match self.por_hash.get(&p) {
                Some(BloqueCadena::Pow(bt)) => bt.padre(),
                _ => None,
            };
        }
        true
    }

    /// Trabajo PoW acumulado de `hash`, si se conoce (`U256::zero()` si no).
    fn trabajo_de(&self, hash: &BlockHash) -> U256 {
        self.post.get(hash).map(|e| e.trabajo).unwrap_or_default()
    }

    /// Mejor terminal candidato **sin** ningún DAG con sufijo (fase puramente PoW, `TRN-09`
    /// primera cláusula): mayor trabajo acumulado, empate por menor hash.
    fn mejor_terminal_por_trabajo(&self) -> Option<BlockHash> {
        self.terminal_candidatos.iter().copied().min_by(|a, b| {
            self.trabajo_de(b)
                .cmp(&self.trabajo_de(a))
                .then_with(|| a.cmp(b))
        })
    }

    /// `Rank` (`blue_work`, `solution_distance`, `id`) del virtual de un terminal con DAG, si existe.
    fn rank_virtual_de(&self, terminal: BlockHash) -> Option<Rank> {
        let v = self.dag_virtual_de(terminal).ok().flatten()?;
        Some(Rank {
            blue_work: v.datos.blue_work,
            solution_distance: 0,
            id: hash_de_id_textual("V"),
        })
    }

    /// Mejor terminal candidato por FC-3 (`TRN-09`): sin ningún sufijo PoST conocido, por trabajo
    /// PoW; en cuanto alguno tiene sufijo, solo esos compiten por `blue_work` de su virtual,
    /// desempate por [`comparar_terminal`] (reutilizado de `zx_consensus::transicion`, menor hash) y,
    /// si aún empata, por la regla `C-GD` completa (`solution_distance`, `id`) — inalcanzable en la
    /// práctica porque dos terminales son hashes distintos, pero se conserva por completitud
    /// (`ORDEN-W06d7` decisión 2, «después la de C-GD»).
    fn mejor_terminal_candidato(&self) -> Option<BlockHash> {
        if self.dags.is_empty() {
            return self.mejor_terminal_por_trabajo();
        }
        self.dags.keys().copied().min_by(|a, b| {
            let ra = self.rank_virtual_de(*a);
            let rb = self.rank_virtual_de(*b);
            comparar_blue_work(ra, rb)
                .then_with(|| comparar_terminal(Some(*a), Some(*b)).reverse())
                .then_with(|| comparar_rank(ra, rb))
        })
    }

    /// `slot` máximo entre las puntas válidas del DAG de `terminal` (0 si no tiene DAG o no tiene
    /// puntas todavía): es `d` para `C-FIN-01` entre terminales, con `s_0 = 0` (`CONTRATO-v0.md` §1).
    fn slot_max_de(&self, terminal: BlockHash) -> u64 {
        self.tips_validas_de(terminal)
            .iter()
            .filter_map(|h| self.por_hash.get(h).and_then(BloqueCadena::slot))
            .max()
            .unwrap_or(0)
    }

    /// Recalcula el terminal seleccionado tras un cambio (nuevo candidato o nuevo bloque PoST):
    /// FC-3 (`TRN-09`) con `C-FIN-01` entre terminales (`ORDEN-W06d7` decisión 3): un nodo en línea
    /// no sustituye su terminal si el sufijo actual ya abarca `≥ F_slots` desde el corte.
    fn recalcular_seleccion(&mut self) {
        // ECL-R2a · D5/D4: decide si el ancla está pendiente o si hay eclipse antes de seleccionar.
        self.evaluar_ancla();
        if let Some(nuevo) = self.mejor_terminal_candidato() {
            // ECL-R2a · D3: si hay ancla con candidato en un terminal conocido, ese guía la
            // selección (dentro de `F`); si no, el mejor por FC-3.
            let objetivo = self.terminal_objetivo_ancla(nuevo);
            let acepta = match self.terminal_seleccionado {
                None => true,
                Some(actual) if actual == objetivo => false,
                Some(actual) => match self.dags.get(&actual) {
                    None => true,
                    Some(_) => {
                        let d = self.slot_max_de(actual);
                        match self.params.f_slots {
                            None => true,
                            Some(tope) => d < tope,
                        }
                    }
                },
            };
            if acepta {
                self.terminal_seleccionado = Some(objetivo);
            }
        }
        // `FIN-1`: tras fijar el terminal seleccionado, se avanza el punto de finalidad sobre su
        // cadena seleccionada (que ya se calcula con la cota vigente) y se anotan las violaciones.
        self.actualizar_punto_finalidad();
        // ECL-R2a · D1/D3: el candidato del ancla es el punto de finalidad; si el terminal
        // seleccionado lo contiene, se fija (monótono por slot) sin rebasar más atrás.
        self.sincronizar_punto_con_ancla();
        self.registrar_violaciones();
        self.estado_t = self
            .terminal_seleccionado
            .and_then(|t| self.post.get(&t).cloned())
            .unwrap_or_else(|| self.estado_inicial.clone());
    }

    /// ECL-R2a · Fija `punto_finalidad` al candidato del ancla si el terminal seleccionado lo
    /// contiene y no retrocede en slot (el ancla solo avanza).
    ///
    /// ECL-R2a-3 · La pertenencia al DAG no basta: dentro de un terminal, el ancla solo fija `F` si
    /// desciende del `F` vigente (ascendencia real de cadena). Un certificado atrasado que sea
    /// ancestro del `F` no lo mueve; una rama incompatible tampoco.
    fn sincronizar_punto_con_ancla(&mut self) {
        let Some((_n, h)) = self.ancla_votos else {
            return;
        };
        let Some(terminal) = self.terminal_seleccionado else {
            return;
        };
        if !self.hash_en_dag(terminal, h) {
            return;
        }
        if let Some(pf) = self.punto_finalidad
            && self.hash_en_dag(terminal, pf)
            && !self.cadena_contiene(terminal, h, pf)
        {
            return;
        }
        let slot_h = self
            .por_hash
            .get(&h)
            .and_then(BloqueCadena::slot)
            .unwrap_or(0);
        let slot_actual = self
            .punto_finalidad
            .and_then(|p| self.por_hash.get(&p).and_then(BloqueCadena::slot))
            .unwrap_or(0);
        if self.punto_finalidad.is_none() || slot_h >= slot_actual {
            self.punto_finalidad = Some(h);
        }
    }

    /// `FIN-1` · `true` si la cadena seleccionada del bloque `punta` (subiendo por `sp` hasta el
    /// terminal del DAG `terminal`) contiene `objetivo`. El objetivo puede ser el propio terminal
    /// (`idx 0`). `false` si `punta` u `objetivo` no pertenecen a ese DAG.
    fn cadena_contiene(&self, terminal: BlockHash, punta: BlockHash, objetivo: BlockHash) -> bool {
        let Some(dt) = self.dags.get(&terminal) else {
            return false;
        };
        let Some(mut idx) = dt.dag_idx.get(&punta).copied() else {
            return false;
        };
        loop {
            if self.hash_de_idx(terminal, idx) == Some(objetivo) {
                return true;
            }
            if idx == 0 {
                return false;
            }
            match dt.dag.datos(idx).and_then(|d| d.sp) {
                Some(sp) if sp != idx => idx = sp,
                _ => return false,
            }
        }
    }

    /// `FIN-1` · `true` si `hash` es un bloque del DAG de `terminal` (el terminal es el índice 0).
    fn hash_en_dag(&self, terminal: BlockHash, hash: BlockHash) -> bool {
        self.dags
            .get(&terminal)
            .is_some_and(|dt| dt.dag_idx.contains_key(&hash))
    }

    /// AT-1b · W2 · contexto de `x` dentro del bloque de cadena `g` del índice `idx`.
    ///
    /// PROD-3a: la implementación única vive en `admision_post::contexto_real`.
    fn contexto_real(&self, terminal: BlockHash, idx: Idx) -> Option<ContextoAplicacion> {
        admision_post::contexto_real(self, terminal, idx)
    }

    /// AT-1b · W2 · contexto de `x` dentro del virtual `V` de `terminal`.
    fn contexto_virtual(&self, terminal: BlockHash, v: &Virtual) -> ContextoAplicacion {
        let mergeset = v
            .datos
            .orden_mergeset
            .iter()
            .filter(|m| color_en_datos(&v.datos, **m) != Some(Color::RojoU3))
            .copied()
            .collect();
        ContextoAplicacion {
            terminal,
            g_idx: None,
            mergeset,
            sp: v.datos.sp.unwrap_or(0),
            slot_g: v.slot,
        }
    }

    /// AT-1b2 · X4 · cuenta un bloque visitado por los recorridos del hecho. En producción el cuerpo
    /// queda vacío (sin campo ni incremento); en pruebas lleva la cuenta que lee J13.
    #[inline(always)]
    fn visita(&self) {
        #[cfg(test)]
        self.visitas.set(self.visitas.get().saturating_add(1));
    }

    /// AT-1b2 · X4 · reinicia el contador (solo pruebas).
    #[cfg(test)]
    fn reiniciar_visitas(&self) {
        self.visitas.set(0);
    }

    /// AT-1b2 · X4 · bloques visitados desde el último [`Cadena::reiniciar_visitas`] (solo pruebas).
    #[cfg(test)]
    fn visitas(&self) -> u64 {
        self.visitas.get()
    }

    /// AT-1b2 · X4 · gancho de prueba: `true` si `b_hash` está «aplicado antes que `x_hash`» en el
    /// contexto `ctx`. La implementación única vive en `admision_post::aplicado_antes_que`.
    #[cfg(test)]
    fn aplicado_antes_que(
        &self,
        ctx: &ContextoAplicacion,
        x_hash: BlockHash,
        b_hash: BlockHash,
    ) -> bool {
        admision_post::aplicado_antes_que(self, ctx, x_hash, b_hash)
    }

    /// X1 · hecho de una transacción `0x0B` de `x` (`n₁ < n₂`); `Inadmisible` para cualquier otra
    /// transacción. Orden de evaluación y salidas baratas de la orden AT-1b2 §3, X1: los pasos 1–4 se
    /// deciden sin recorrer el DAG, de modo que una evidencia fuera del horizonte cuesta cero
    /// bloques visitados. `plazo_slots` es el de `e.parametros_sector` (pasos 3 y 8b).
    fn hecho_de_tx(
        &self,
        ctx: &ContextoAplicacion,
        plazo_slots: u64,
        x_hash: BlockHash,
        tx: &Tx,
    ) -> HechoVoto {
        admision_post::hecho_de_tx(self, ctx, plazo_slots, x_hash, tx)
    }

    /// AT-1b2 · gancho **de prueba** (`#[doc(hidden)]`): calcula el hecho de `tx` en el contexto
    /// real del bloque de cadena `x` del DAG `terminal`, con `plazo_slots` explícito. No es API de
    /// producción: existe para que `crates/zx-node/tests/` pueda leer el hecho sin montar el castigo
    /// completo (J6b/J8 y AT-1c). Devuelve `None` si `x` no está en ese DAG.
    #[doc(hidden)]
    #[must_use]
    pub fn hecho_de_tx_de_prueba(
        &self,
        terminal: BlockHash,
        x: BlockHash,
        tx: &Tx,
        plazo_slots: u64,
    ) -> Option<HechoVoto> {
        let dt = self.dags.get(&terminal)?;
        let idx = *dt.dag_idx.get(&x)?;
        let ctx = self.contexto_real(terminal, idx)?;
        Some(self.hecho_de_tx(&ctx, plazo_slots, x, tx))
    }

    /// DFV-1 · D5 · `true` si `a` y `b` son bloques **distintos y en conflicto en el grafo** del
    /// terminal seleccionado: ninguno desciende del otro. Recorre el DAG (`sp` + mergesets), no solo
    /// la cadena seleccionada. Consulta **nueva de solo lectura**; ninguna regla cambia.
    #[must_use]
    pub fn en_conflicto_en_dag(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b {
            return false;
        }
        let Some(terminal) = self.terminal_seleccionado else {
            return false;
        };
        if !self.hash_en_dag(terminal, *a) || !self.hash_en_dag(terminal, *b) {
            return false;
        }
        !self.desciende_en_dag(terminal, *a, *b) && !self.desciende_en_dag(terminal, *b, *a)
    }

    /// DFV-1 · D5 · `c == a` o `c` desciende de `a` en el DAG de `terminal`. Recorrido por `sp` y
    /// mergesets con cota de visitas: un DAG adversarial no puede hacer explotar la consulta.
    fn desciende_en_dag(&self, terminal: BlockHash, c: BlockHash, a: BlockHash) -> bool {
        if c == a {
            return self.hash_en_dag(terminal, c);
        }
        let Some(dt) = self.dags.get(&terminal) else {
            return false;
        };
        let (Some(&inicio), Some(&objetivo)) = (dt.dag_idx.get(&c), dt.dag_idx.get(&a)) else {
            return false;
        };
        const COTA_VISITAS: u32 = 200_000;
        let mut vistas: BTreeSet<Idx> = BTreeSet::new();
        let mut pila: Vec<Idx> = vec![inicio];
        let mut visitas = 0u32;
        while let Some(idx) = pila.pop() {
            if idx == objetivo {
                return true;
            }
            if !vistas.insert(idx) {
                continue;
            }
            visitas = visitas.saturating_add(1);
            if visitas > COTA_VISITAS {
                return false;
            }
            let Some(datos) = dt.dag.datos(idx) else {
                continue;
            };
            if let Some(sp) = datos.sp
                && sp != idx
            {
                pila.push(sp);
            }
            for &m in &datos.orden_mergeset {
                pila.push(m);
            }
        }
        false
    }

    /// DFV-1 · D6 · hecho de una eventual evidencia `0x0B` **entre ventanas**, calculado con la
    /// **misma** función que la cadena usa al incluirla (`hecho_de_tx`). Evalúa en el contexto
    /// **virtual** del terminal seleccionado (lo que se aplicaría al incluir la evidencia en el
    /// próximo bloque); `None` si no hay terminal/DAG. Consulta **nueva de solo lectura**; ninguna
    /// regla cambia.
    #[must_use]
    pub fn hecho_voto_entre_ventanas(
        &self,
        voto1: &VotoPesoEvidencia,
        voto2: &VotoPesoEvidencia,
        plazo_slots: u64,
    ) -> Option<HechoVoto> {
        let terminal = self.terminal_seleccionado?;
        let Ok(Some(v)) = self.dag_virtual_de(terminal) else {
            return None;
        };
        let ctx = self.contexto_virtual(terminal, &v);
        // `x` solo sirve para localizar el corte en el mergeset virtual; debe ser un bloque real del
        // DAG. Se usa la punta de la cadena virtual y, si no hubiera, el ancla del DAG.
        let x = self
            .cadena_virtual_de(terminal)
            .last()
            .copied()
            .or_else(|| self.hash_de_idx(terminal, 0))
            .unwrap_or(terminal);
        let operacion = OperacionAlmacenamiento::EvidenciaVotosPeso {
            clave: ClavePublica::desde_bytes([0u8; 32]),
            clave_bls: [0u8; zx_core::LONGITUD_CLAVE_BLS],
            voto1: *voto1,
            voto2: *voto2,
        };
        let tx = Tx {
            version: 6,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::PruebaAlmacenamiento { operacion },
        };
        Some(self.hecho_de_tx(&ctx, plazo_slots, x, &tx))
    }

    /// AT-1b · W3 · aplica `bloque` en modo fusión pasando los hechos calculados con `ctx` (una sola
    /// función para los tres caminos: admisión, repetición entera y estado virtual).
    ///
    /// PROD-3a: la implementación única vive en `admision_post::aplicar_bloque_con_hechos`.
    fn aplicar_bloque_con_hechos(
        &self,
        estado: &Estado,
        bloque: &BloqueCadena,
        punto: Punto,
        ctx: &ContextoAplicacion,
    ) -> Result<(Estado, Undo, Vec<TxDescartada>), MotivoBloque> {
        admision_post::aplicar_bloque_con_hechos(self, estado, bloque, punto, ctx)
    }

    /// `FIN-1` · Puntas válidas de `terminal` cuya cadena seleccionada **contiene** el punto de
    /// finalidad vigente. La cota solo restringe la selección **dentro del DAG que contiene el punto
    /// de finalidad** (el terminal seleccionado en la operación normal). En otro terminal, la
    /// selección la sigue gobernando `C-FIN-01`, que ya acota la profundidad a `F_slots`; al aceptar
    /// el cambio de terminal el punto se re-basa a la cadena nueva. Sin punto de finalidad
    /// (`f_slots = None`, todavía no fijado o de otro terminal) devuelve todas las puntas: el
    /// comportamiento previo queda intacto.
    fn tips_seleccionables_de(&self, terminal: BlockHash) -> Vec<BlockHash> {
        let tips = self.tips_validas_de(terminal);
        if !self.finalidad_dag {
            return tips;
        }
        let Some(pf) = self.punto_finalidad else {
            return tips;
        };
        if !self.hash_en_dag(terminal, pf) {
            return tips;
        }
        tips.into_iter()
            .filter(|h| self.cadena_contiene(terminal, *h, pf))
            .collect()
    }

    /// `FIN-1` · Mejor punta de `terminal` por la regla `C-GD-03` **sin** la cota de finalidad: la
    /// que habría ganado si la cota no existiera. Se usa para anotar la violación (decisión 2).
    fn mejor_punta_sin_finalidad_de(&self, terminal: BlockHash) -> Option<BlockHash> {
        let tips = self.tips_validas_de(terminal);
        if tips.is_empty() {
            return None;
        }
        let dt = self.dags.get(&terminal)?;
        tips.into_iter().min_by(|a, b| {
            let ra = dt.dag_idx.get(a).and_then(|i| dt.dag.rank(*i));
            let rb = dt.dag_idx.get(b).and_then(|i| dt.dag.rank(*i));
            comparar_rank(ra, rb)
        })
    }

    /// `FIN-1` · Avanza el punto de finalidad del terminal seleccionado (decisión 1): bloque de la
    /// cadena seleccionada del virtual con el mayor `slot ≤ slot(punta seleccionada) − F_slots`. Es
    /// monótono: solo se sustituye si el candidato tiene `slot` estrictamente mayor (nunca retrocede).
    fn actualizar_punto_finalidad(&mut self) {
        if !self.finalidad_dag {
            self.punto_finalidad = None;
            return;
        }
        let Some(tope) = self.params.f_slots else {
            self.punto_finalidad = None;
            return;
        };
        let Some(terminal) = self.terminal_seleccionado else {
            return;
        };
        let Some(punta) = self.mejor_punta_de(terminal) else {
            return;
        };
        let Some(slot_punta) = self.por_hash.get(&punta).and_then(BloqueCadena::slot) else {
            return;
        };
        let limite = slot_punta.saturating_sub(tope);
        // La cadena seleccionada va del primer PoST al `sp`; el terminal es el candidato por defecto.
        let mut candidato = terminal;
        for h in self.cadena_virtual_de(terminal) {
            match self.por_hash.get(&h).and_then(BloqueCadena::slot) {
                Some(s) if s <= limite => candidato = h,
                // Los slots crecen a lo largo de la cadena seleccionada: al superar el límite, no
                // hay ningún bloque posterior que lo cumpla.
                Some(_) => break,
                None => break,
            }
        }
        let slot_candidato = self
            .por_hash
            .get(&candidato)
            .and_then(BloqueCadena::slot)
            .unwrap_or(0);
        let slot_actual = self
            .punto_finalidad
            .and_then(|h| self.por_hash.get(&h).and_then(BloqueCadena::slot))
            .unwrap_or(0);
        // Si el punto anterior no pertenece al DAG del terminal ahora seleccionado (cambio de
        // terminal permitido por `C-FIN-01`, con `d < F_slots`), se re-basa a la cadena nueva; dentro
        // de un mismo terminal solo avanza (nunca retrocede).
        let pf_en_terminal = self
            .punto_finalidad
            .is_some_and(|pf| self.hash_en_dag(terminal, pf));
        // FV-4b-N1 · con finalidad por votos, el punto solo se fija la primera vez (cota de
        // profundidad) y, a partir de ahí, solo **avanza dentro del DAG que ya lo contiene**: nunca
        // se re-basa a otra rama (un certificado en conflicto no debe mover la finalidad).
        if self.finalidad_por_votos {
            if self.punto_finalidad.is_none() || (pf_en_terminal && slot_candidato > slot_actual) {
                self.punto_finalidad = Some(candidato);
            }
            return;
        }
        if !pf_en_terminal || self.punto_finalidad.is_none() || slot_candidato > slot_actual {
            self.punto_finalidad = Some(candidato);
        }
    }

    /// `FIN-1` · Anota una violación cuando la mejor punta **sin** la cota no contiene el punto de
    /// finalidad vigente (decisión 2: se admite, pero no puede ser elegida). Deduplica por
    /// `(finalidad, bloque)` y no escribe para `f_slots = None`.
    fn registrar_violaciones(&mut self) {
        if !self.finalidad_dag {
            return;
        }
        let (Some(pf), Some(terminal)) = (self.punto_finalidad, self.terminal_seleccionado) else {
            return;
        };
        if !self.hash_en_dag(terminal, pf) {
            return;
        }
        let Some(mejor) = self.mejor_punta_sin_finalidad_de(terminal) else {
            return;
        };
        if self.cadena_contiene(terminal, mejor, pf) {
            return;
        }
        let slot_pf = self
            .por_hash
            .get(&pf)
            .and_then(BloqueCadena::slot)
            .unwrap_or(0);
        let slot_mejor = self
            .por_hash
            .get(&mejor)
            .and_then(BloqueCadena::slot)
            .unwrap_or(0);
        let profundidad = slot_mejor.saturating_sub(slot_pf);
        self.violaciones_finalidad
            .entry((pf, mejor))
            .or_insert(profundidad);
    }

    /// Mejor punta PoW conocida por trabajo acumulado (empate: hash menor), sea o no ya terminal
    /// (`ORDEN-W06d3` decisión 3): es lo que sigue la plantilla de minado, para que un bloque propio
    /// siempre extienda la rama más pesada conocida, no una punta cualquiera.
    #[must_use]
    pub fn mejor_punta_pow(&self) -> Option<BlockHash> {
        self.tips_pow.iter().copied().min_by(|a, b| {
            self.trabajo_de(b)
                .cmp(&self.trabajo_de(a))
                .then_with(|| a.cmp(b))
        })
    }

    /// Trabajo PoW acumulado de un bloque admitido, si se conoce (`ORDEN-W06d3` decisión 3): lo que
    /// el nodo publica como `trabajo_acumulado` de su punta seleccionada en el saludo de red.
    #[must_use]
    pub fn trabajo_pow(&self, hash: &BlockHash) -> Option<U256> {
        self.post.get(hash).map(|e| e.trabajo)
    }

    /// Terminal al que resuelve un padre declarado: el propio hash si es un terminal candidato, o
    /// el terminal del bloque PoST ya admitido en ese hash.
    fn terminal_de_padre(&self, x: &BlockHash) -> Option<BlockHash> {
        if self.terminal_candidatos.contains(x) {
            Some(*x)
        } else {
            self.post_terminal.get(x).copied()
        }
    }

    /// Terminal único al que pertenecen **todos** los padres de `p` (`ORDEN-W06d7` decisión 1: un
    /// bloque PoST pertenece al DAG del terminal de su pasado).
    ///
    /// # Errores
    /// `ErrSinPadre` si algún padre es desconocido o inválido; `ErrTerminalAmbiguo` si los padres
    /// resuelven a más de un terminal distinto (`I-4`).
    fn terminal_de_bloque_post(&self, p: &BloquePost) -> Result<BlockHash, MotivoBloque> {
        let mut terminal_ref: Option<BlockHash> = None;
        for x in &p.padres {
            let Some(t) = self.terminal_de_padre(x) else {
                return Err(MotivoBloque::ErrSinPadre);
            };
            match terminal_ref {
                None => terminal_ref = Some(t),
                Some(prev) if prev != t => return Err(MotivoBloque::ErrTerminalAmbiguo),
                Some(_) => {}
            }
        }
        terminal_ref.ok_or(MotivoBloque::ErrSinPadre)
    }

    /// Admite un bloque PoST: forma, terminal de su pasado, GHOSTDAG, `Estado(past(B))`, garantía y
    /// `post(B)` (`ORDEN-W06d7`: opera sobre el [`DagTerminal`] de `p`, no necesariamente el
    /// seleccionado).
    fn admitir_post(&mut self, bloque: &BloqueCadena) -> Result<(), MotivoBloque> {
        let BloqueCadena::Post(p) = bloque else {
            return Err(MotivoBloque::ErrSinPadre);
        };
        let terminal = self.chequear_forma(p)?;
        self.dag_de_terminal_mut(terminal)?;
        let idx = self.anadir_al_dag(terminal, p)?;
        // PROD-3a · D1: el cálculo (estado del pasado, garantía, contexto, hechos, fusión y peso) es
        // el mismo que usa el ensayo; la admisión lo invoca sobre `&Cadena` y después escribe.
        let base = self.estado_past_de_idx(terminal, idx, p)?;
        self.comprobar_garantia(&base, p)?;
        // AT-1b · W1 · al admitir el bloque PoST se guarda la finalidad por votos de **su pasado**;
        // no se borra mientras exista el bloque. Se escribe **antes** de aplicar el bloque, como
        // antes de PROD-3a (los hechos de sus propias evidencias pueden consultarla).
        self.finalidad_pasado
            .insert(p.hash, (base.finalidad_votos_n, base.finalidad_votos));
        let (nuevo, desc) =
            admision_post::aplicar_candidata(self, &base, terminal, idx, p, bloque)?;
        self.past.insert(p.hash, base);
        self.post.insert(p.hash, nuevo);
        self.descartes.insert(p.hash, desc);
        self.post_terminal.insert(p.hash, terminal);
        // La recomputación de la selección FC-3 la hace `Cadena::admitir` (el llamante), después de
        // marcar `p.hash` como válido: solo entonces `tips_validas_de`/`dag_virtual_de` (que filtran
        // por `Self::es_valido`) cuentan este bloque para el `blue_work` de su terminal
        // (`ORDEN-W06d7`, ver el comentario en `Cadena::admitir`).
        Ok(())
    }

    /// Comprueba forma y padres sin tocar el DAG (`ORDEN-W06a` §3, T04 `chequear_forma`); resuelve
    /// y devuelve el terminal único de `p` (`ORDEN-W06d7`).
    fn chequear_forma(&self, p: &BloquePost) -> Result<BlockHash, MotivoBloque> {
        if p.padres.is_empty() {
            return Err(MotivoBloque::ErrSinPadre);
        }
        let mut vistos = BTreeSet::new();
        for x in &p.padres {
            if !vistos.insert(*x) {
                return Err(MotivoBloque::ErrSinPadre);
            }
        }
        let terminal = self.terminal_de_bloque_post(p)?;
        if p.padres.contains(&terminal) && p.padres.len() != 1 {
            return Err(MotivoBloque::ErrSinPadre);
        }
        for x in &p.padres {
            if *x == terminal {
                continue;
            }
            if !self.por_hash.contains_key(x) || !self.es_valido(x) {
                return Err(MotivoBloque::ErrSinPadre);
            }
        }
        if p.slot < 1 {
            return Err(MotivoBloque::ErrSlot);
        }
        let mut ncb = 0usize;
        let mut icb = 0usize;
        for (i, (tx, _)) in p.txs.iter().enumerate() {
            if es_coinbase(tx) {
                ncb += 1;
                icb = i;
            }
        }
        if ncb > 1 {
            return Err(MotivoBloque::ErrEmision);
        }
        if ncb == 1 {
            if icb != 0 {
                return Err(MotivoBloque::ErrEmision);
            }
            let Some((tx, _)) = p.txs.first() else {
                return Err(MotivoBloque::ErrEmision);
            };
            if tx.version != 3 {
                return Err(MotivoBloque::ErrEmision);
            }
            if importe_de_coinbase_post(tx).is_some_and(|v| v.brek() == 0) {
                return Err(MotivoBloque::ErrSaldo);
            }
        }
        // SL-4c (§3.2): la forma de la `EvidenceTx` v4 (`EV-04`, `RAT-1`, `EV-01`) es forma de
        // bloque y se comprueba **antes** de la garantía del productor y de la semántica, igual
        // que `chequear_forma_evidencia` del oráculo T04 (`EstadoDAG.jl:292-294`).
        if self.evidencia.evp {
            for (tx, testigos) in &p.txs {
                if tx.version == 4 && matches!(tx.extension, ExtensionTx::Evidencia { .. }) {
                    validar_forma_tx_v4(tx, testigos, self.evidencia.cbid)
                        .map_err(|e| MotivoBloque::ErrTransicion(e.into()))?;
                }
            }
        }
        Ok(terminal)
    }

    /// Consigue (o crea) el [`DagTerminal`] de `terminal`, aplicando el tope
    /// [`MAX_TERMINALES_CON_DAG`] (`ORDEN-W06d7` decisión 4): si ya hay 8 y `terminal` es nuevo, se
    /// desaloja al peor (menor trabajo PoW) si `terminal` lo supera; si no, se ignora
    /// (`ErrLimiteTerminales`) y se marca [`Cadena::limite_terminales_alcanzado`].
    fn dag_de_terminal_mut(
        &mut self,
        terminal: BlockHash,
    ) -> Result<&mut DagTerminal, MotivoBloque> {
        if !self.dags.contains_key(&terminal) {
            // PROD-3a · D1: la decisión del tope se comparte con el ensayo (`decidir_tope` no muta);
            // aquí se aplican los efectos de la admisión (marca y desalojo).
            match admision_post::decidir_tope(self, terminal) {
                admision_post::TopeDag::Cabe => {}
                admision_post::TopeDag::NoCabe => {
                    self.limite_alcanzado = true;
                    return Err(MotivoBloque::ErrLimiteTerminales);
                }
                admision_post::TopeDag::Desaloja(peor) => {
                    self.limite_alcanzado = true;
                    self.dags.remove(&peor);
                    // `ORDEN-W08a` decisión 2: un desalojo cambia la vista local de terminales; al
                    // terminar esta admisión se reintentan los pendientes por tope.
                    self.desalojo_reciente = true;
                }
            }
            self.dags.insert(
                terminal,
                DagTerminal::nueva(terminal, self.k, self.max_padres),
            );
        }
        self.dags
            .get_mut(&terminal)
            .ok_or(MotivoBloque::ErrSinPadre)
    }

    /// Añade un bloque PoST al DAG de `terminal` y guarda sus datos para reconstruirlo.
    fn anadir_al_dag(&mut self, terminal: BlockHash, p: &BloquePost) -> Result<Idx, MotivoBloque> {
        let Some(dt) = self.dags.get_mut(&terminal) else {
            return Err(MotivoBloque::ErrSinPadre);
        };
        admision_post::anadir_al_dag(dt, p)
    }

    /// `Estado(past(B))` para el bloque `p` ya coloreado en el índice `idx` del DAG de `terminal`
    /// (`ED-2`, `RD-4`).
    fn estado_past_de_idx(
        &self,
        terminal: BlockHash,
        idx: Idx,
        p: &BloquePost,
    ) -> Result<Estado, MotivoBloque> {
        admision_post::estado_past_de_idx(self, terminal, idx, p)
    }

    /// Garantía del productor sobre `Estado(past(B))` promovido en `slot(B)` (`RD-9`).
    fn comprobar_garantia(&self, base: &Estado, p: &BloquePost) -> Result<(), MotivoBloque> {
        admision_post::comprobar_garantia(self, base, p)
    }

    /// Puntas válidas **seleccionables** del terminal **seleccionado** (`tips_validas` del oráculo).
    ///
    /// `FIN-1`: excluye las puntas cuya cadena seleccionada no contiene el punto de finalidad
    /// vigente, para que no puedan usarse como padres del siguiente bloque (decisión 2: la rama se
    /// admite, pero no puede hacer que el virtual cambie). Sin punto de finalidad devuelve todas.
    #[must_use]
    pub fn tips_validas(&self) -> Vec<BlockHash> {
        self.terminal_seleccionado
            .map(|t| self.tips_seleccionables_de(t))
            .unwrap_or_default()
    }

    /// Puntas válidas de un terminal concreto: bloques PoST válidos de su DAG sin hijo válido.
    ///
    /// `ORDEN-IDX1` · I1: lee el índice incremental [`Cadena::puntas_post`]; no recorre `por_hash`.
    /// Devuelve exactamente lo mismo (contenido y orden) que la referencia de pruebas
    /// [`Cadena::tips_validas_referencia`].
    #[must_use]
    pub fn tips_validas_de(&self, terminal: BlockHash) -> Vec<BlockHash> {
        self.puntas_post
            .get(&terminal)
            .map(|puntas| puntas.iter().copied().collect())
            .unwrap_or_default()
    }

    /// `ORDEN-IDX1` · I2 · Cálculo anterior a I1, **conservado solo para pruebas**: recorre
    /// `por_hash` entero dos veces. La prueba de propiedad compara el índice contra esta referencia
    /// tras **cada** operación.
    #[cfg(test)]
    fn tips_validas_referencia(&self, terminal: BlockHash) -> Vec<BlockHash> {
        let mut con_hijo = BTreeSet::new();
        for (hash, bloque) in &self.por_hash {
            if !matches!(bloque, BloqueCadena::Post(_)) || !self.es_valido(hash) {
                continue;
            }
            if self.post_terminal.get(hash) != Some(&terminal) {
                continue;
            }
            for padre in bloque.padres() {
                if padre == terminal {
                    continue;
                }
                if self.es_valido(&padre) {
                    con_hijo.insert(padre);
                }
            }
        }
        let mut tips: Vec<BlockHash> = self
            .por_hash
            .iter()
            .filter(|(hash, bloque)| {
                matches!(bloque, BloqueCadena::Post(_))
                    && self.es_valido(hash)
                    && self.post_terminal.get(*hash) == Some(&terminal)
                    && !con_hijo.contains(*hash)
            })
            .map(|(hash, _)| *hash)
            .collect();
        tips.sort_unstable();
        tips
    }

    /// `ORDEN-IDX1` · I1 · Actualiza [`Cadena::puntas_post`] al admitir **válido** el bloque `hash`.
    ///
    /// El bloque entra como punta de su terminal y cada padre PoST válido del **mismo** terminal deja
    /// de serlo. Es lo que hacía `con_hijo` en la referencia, pero sin recorrer `por_hash`: los
    /// padres de un bloque admitido ya estaban admitidos y son válidos (`chequear_forma`), así que
    /// basta con dar de baja a los que el índice tiene como puntas.
    fn actualizar_indice_puntas(&mut self, hash: &BlockHash) {
        let Some(terminal) = self.post_terminal.get(hash).copied() else {
            return;
        };
        let Some(BloqueCadena::Post(p)) = self.por_hash.get(hash) else {
            return;
        };
        let padres = p.padres.clone();
        self.puntas_post.entry(terminal).or_default().insert(*hash);
        for padre in padres {
            if padre == terminal {
                continue;
            }
            if self.es_valido(&padre)
                && self.post_terminal.get(&padre) == Some(&terminal)
                && let Some(puntas) = self.puntas_post.get_mut(&terminal)
            {
                puntas.remove(&padre);
            }
        }
    }

    /// `ORDEN-IDX1` · I3 · Candidato de voto de la **cadena seleccionada** del terminal seleccionado:
    /// el bloque con `slot` máximo `<= tope`, desempate por hash menor; `None` si no hay ninguno.
    ///
    /// Retrocede desde la punta virtual por el padre seleccionado (`sp`) del DAG en lugar de
    /// materializar `cadena_virtual()` y recorrer `bloques_post()`. El coste depende de los bloques
    /// entre la punta y el candidato (a lo sumo `slot(punta) - tope`), no de la historia: los slots
    /// crecen a lo largo de la cadena del `sp` (la regla es `slot(padre) ≤ slot(hijo)`, no estricta),
    /// así que el primer bloque con `slot <= tope` ya tiene el slot máximo; se siguen
    /// mirando los de igual `slot` para el desempate por hash.
    #[must_use]
    pub fn candidato_por_slot(&self, tope: u64) -> Option<BlockHash> {
        let terminal = self.terminal_seleccionado?;
        let dt = self.dags.get(&terminal)?;
        let v = self.dag_virtual_de(terminal).ok().flatten()?;
        let mut idx = v.datos.sp?;
        let mut mejor: Option<(u64, BlockHash)> = None;
        loop {
            if idx == 0 {
                break;
            }
            let hash = self.hash_de_idx(terminal, idx)?;
            let slot = self.por_hash.get(&hash).and_then(BloqueCadena::slot)?;
            if slot <= tope {
                match mejor {
                    None => mejor = Some((slot, hash)),
                    Some((mejor_slot, mejor_hash)) => {
                        if slot > mejor_slot || (slot == mejor_slot && hash < mejor_hash) {
                            mejor = Some((slot, hash));
                        } else if slot < mejor_slot {
                            break;
                        }
                    }
                }
            }
            let Some(sp) = dt.dag.datos(idx).and_then(|d| d.sp) else {
                break;
            };
            if sp == idx {
                break;
            }
            idx = sp;
        }
        mejor.map(|(_, hash)| hash)
    }

    /// Mejor punta del terminal **seleccionado** por la regla C: mayor `blue_work`, menor `sd`,
    /// menor id (`C-GD-03`).
    #[must_use]
    pub fn mejor_punta(&self) -> Option<BlockHash> {
        self.terminal_seleccionado
            .and_then(|t| self.mejor_punta_de(t))
    }

    /// Como [`Cadena::mejor_punta`], para un terminal concreto. `FIN-1`: solo considera las puntas
    /// cuya cadena seleccionada contiene el punto de finalidad vigente.
    #[must_use]
    pub fn mejor_punta_de(&self, terminal: BlockHash) -> Option<BlockHash> {
        let tips = self.tips_seleccionables_de(terminal);
        if tips.is_empty() {
            return None;
        }
        let dt = self.dags.get(&terminal)?;
        tips.into_iter().min_by(|a, b| {
            let ra = dt.dag_idx.get(a).and_then(|i| dt.dag.rank(*i));
            let rb = dt.dag_idx.get(b).and_then(|i| dt.dag.rank(*i));
            comparar_rank(ra, rb)
        })
    }

    /// Cadena seleccionada desde la virtual del terminal **seleccionado**, sin el terminal
    /// (`cadena_virtual`).
    #[must_use]
    pub fn cadena_virtual(&self) -> Vec<BlockHash> {
        self.terminal_seleccionado
            .map(|t| self.cadena_virtual_de(t))
            .unwrap_or_default()
    }

    /// Como [`Cadena::cadena_virtual`], para un terminal concreto.
    #[must_use]
    pub fn cadena_virtual_de(&self, terminal: BlockHash) -> Vec<BlockHash> {
        let Some(v) = self.dag_virtual_de(terminal).ok().flatten() else {
            return Vec::new();
        };
        let Some(sp) = v.datos.sp else {
            return Vec::new();
        };
        let Some(dt) = self.dags.get(&terminal) else {
            return Vec::new();
        };
        dt.dag
            .cadena_seleccionada(sp)
            .into_iter()
            .filter(|i| *i != 0)
            .filter_map(|i| self.hash_de_idx(terminal, i))
            .collect()
    }

    /// ECL-REAN2 · N4 · `true` si `hash` pertenece a la **cadena seleccionada** del terminal
    /// seleccionado (incluido el propio terminal).
    #[must_use]
    pub fn en_cadena_seleccionada(&self, hash: &BlockHash) -> bool {
        if self.terminal_seleccionado == Some(*hash) {
            return true;
        }
        self.cadena_virtual().contains(hash)
    }

    /// ECL-REAN2 · N4 · `true` si `candidato` es `ancestro` o **desciende** de él en la cadena
    /// seleccionada del terminal seleccionado.
    #[must_use]
    pub fn desciende_en_cadena_seleccionada(
        &self,
        candidato: &BlockHash,
        ancestro: &BlockHash,
    ) -> bool {
        let Some(terminal) = self.terminal_seleccionado else {
            return false;
        };
        self.cadena_contiene(terminal, *candidato, *ancestro)
    }

    /// ECL-REAN2 · N5 · slot PoT de un bloque, si se conoce.
    #[must_use]
    pub fn slot_de(&self, hash: &BlockHash) -> Option<u64> {
        self.por_hash.get(hash).and_then(BloqueCadena::slot)
    }

    /// `RL-2c` · bloques **PoST** de la cadena seleccionada de `terminal`, en orden de cadena
    /// (antiguo → nuevo), como `(slot, timestamp)`.
    ///
    /// Es la entrada determinista del calendario de `T` (`C-RLJ-04`/`C-RLJ-06`): una función del
    /// DAG admitido (GHOSTDAG), no del orden de llegada. Los bloques PoW no tienen `slot`/`timestamp`
    /// de régimen y se omiten.
    #[must_use]
    pub fn cadena_seleccionada_post(&self, terminal: BlockHash) -> Vec<(u64, u64)> {
        self.cadena_virtual_de(terminal)
            .into_iter()
            .filter_map(|h| match self.por_hash.get(&h) {
                Some(BloqueCadena::Post(p)) => Some((p.slot, p.timestamp)),
                _ => None,
            })
            .collect()
    }

    /// `RL-2d` · `slot` del punto de finalidad vigente, si lo hay y es un bloque con `slot` de
    /// régimen (no el terminal PoW).
    #[must_use]
    pub fn slot_finalidad(&self) -> Option<u64> {
        self.punto_finalidad
            .and_then(|pf| self.por_hash.get(&pf))
            .and_then(BloqueCadena::slot)
    }

    /// `RL-2d` · bloques **PoST** de la cadena seleccionada de `terminal` **hasta el punto de
    /// finalidad vigente** (inclusive), en orden de cadena (antiguo → nuevo).
    ///
    /// Es la parte de la cadena que todos los nodos honestos comparten (FIN-1 garantiza que un
    /// bloque que no desciende del punto de finalidad no se selecciona). El calendario `N(s)` del
    /// reloj se calcula **solo** con ella, de modo que una bifurcación viva en los últimos `< F`
    /// slots no puede hacer que dos nodos honestos calculen `N(s)` distinto.
    ///
    /// Si no hay punto de finalidad, si no pertenece al DAG de `terminal`, o si el punto es un
    /// bloque sin `slot` de régimen, devuelve una lista vacía: el reloj mantiene su `N` anterior
    /// (decisión 3 de `ORDEN-RL2d`).
    #[must_use]
    pub fn cadena_seleccionada_post_finalizada(&self, terminal: BlockHash) -> Vec<(u64, u64)> {
        let Some(pf) = self.punto_finalidad else {
            return Vec::new();
        };
        if !self.hash_en_dag(terminal, pf) {
            return Vec::new();
        }
        let Some(slot_pf) = self.slot_finalidad() else {
            return Vec::new();
        };
        self.cadena_seleccionada_post(terminal)
            .into_iter()
            .filter(|(s, _)| *s <= slot_pf)
            .collect()
    }

    /// Bloques `rojo_U3` inertes en la historia seleccionada del terminal seleccionado
    /// (`u3_virtual`).
    #[must_use]
    pub fn u3_virtual(&self) -> BTreeSet<BlockHash> {
        self.terminal_seleccionado
            .map(|t| self.u3_virtual_de(t))
            .unwrap_or_default()
    }

    /// Como [`Cadena::u3_virtual`], para un terminal concreto.
    #[must_use]
    pub fn u3_virtual_de(&self, terminal: BlockHash) -> BTreeSet<BlockHash> {
        let mut inertes = BTreeSet::new();
        let Ok(Some(v)) = self.dag_virtual_de(terminal) else {
            return inertes;
        };
        let Some(sp) = v.datos.sp else {
            return inertes;
        };
        let Some(dt) = self.dags.get(&terminal) else {
            return inertes;
        };
        for g in dt.dag.cadena_seleccionada(sp) {
            if g == 0 {
                continue;
            }
            if let Some(gd) = dt.dag.datos(g) {
                for x in &gd.orden_mergeset {
                    if color_en_datos(gd, *x) == Some(Color::RojoU3)
                        && let Some(h) = self.hash_de_idx(terminal, *x)
                    {
                        inertes.insert(h);
                    }
                }
            }
        }
        for x in &v.datos.orden_mergeset {
            if color_en_datos(&v.datos, *x) == Some(Color::RojoU3)
                && let Some(h) = self.hash_de_idx(terminal, *x)
            {
                inertes.insert(h);
            }
        }
        inertes
    }

    /// `Estado(past(V))` (`ED-3`) del terminal **seleccionado**: merge­set completo de `V` en orden
    /// `C-GD-05`, sin `rojo_U3`.
    ///
    /// # Errores
    /// Un fallo de aplicación en modo fusión.
    pub fn estado_virtual(&self) -> Result<Estado, MotivoBloque> {
        match self.terminal_seleccionado {
            Some(t) => self.estado_virtual_de(t),
            None => Ok(self.estado_t.clone()),
        }
    }

    /// Como [`Cadena::estado_virtual`], para un terminal concreto.
    ///
    /// # Errores
    /// Un fallo de aplicación en modo fusión.
    pub fn estado_virtual_de(&self, terminal: BlockHash) -> Result<Estado, MotivoBloque> {
        let estado_terminal = || {
            self.post
                .get(&terminal)
                .cloned()
                .unwrap_or_else(|| self.estado_inicial.clone())
        };
        let Ok(Some(v)) = self.dag_virtual_de(terminal) else {
            return Ok(estado_terminal());
        };
        let Some(sp) = v.datos.sp else {
            return Ok(estado_terminal());
        };
        let mut estado = if sp == 0 {
            estado_terminal()
        } else {
            let sp_hash = self
                .hash_de_idx(terminal, sp)
                .ok_or(MotivoBloque::ErrSinPadre)?;
            self.post
                .get(&sp_hash)
                .cloned()
                .ok_or(MotivoBloque::ErrSinPadre)?
        };
        let ctx = self.contexto_virtual(terminal, &v);
        for x_hash in self.mergeset_virtual(terminal, &v) {
            let Some(x) = self.por_hash.get(&x_hash) else {
                return Err(MotivoBloque::ErrSinPadre);
            };
            let (nuevo, _undo, _desc) =
                self.aplicar_bloque_con_hechos(&estado, x, Punto::Slot(v.slot), &ctx)?;
            estado = nuevo;
        }
        Ok(estado)
    }

    /// Recomputa desde `Estado(T)` la historia seleccionada del terminal **seleccionado**
    /// (`R-FIN-8′(4)`).
    ///
    /// # Errores
    /// Un fallo de aplicación en modo fusión.
    pub fn aplicar_historia(
        &self,
    ) -> Result<(Estado, Vec<BlockHash>, Vec<Descarte>), MotivoBloque> {
        let (estado, orden, descartes, _undos) = self.aplicar_historia_completa()?;
        Ok((estado, orden, descartes))
    }

    /// Como [`Self::aplicar_historia`], pero devuelve además los `Undo` por delta en orden de
    /// aplicación, para demostrar el undo exacto (`IE-4`).
    ///
    /// # Errores
    /// Un fallo de aplicación en modo fusión.
    pub fn aplicar_historia_completa(&self) -> Result<HistoriaAplicada, MotivoBloque> {
        let Some(terminal) = self.terminal_seleccionado else {
            return Ok((self.estado_t.clone(), Vec::new(), Vec::new(), Vec::new()));
        };
        let Ok(Some(v)) = self.dag_virtual_de(terminal) else {
            return Ok((self.estado_t.clone(), Vec::new(), Vec::new(), Vec::new()));
        };
        let Some(sp) = v.datos.sp else {
            return Ok((self.estado_t.clone(), Vec::new(), Vec::new(), Vec::new()));
        };
        let Some(dt) = self.dags.get(&terminal) else {
            return Ok((self.estado_t.clone(), Vec::new(), Vec::new(), Vec::new()));
        };
        let (mut estado, mut orden, mut descartes, mut undos) = self.aplicar_cadena(
            terminal,
            &dt.dag,
            sp,
            self.post
                .get(&terminal)
                .cloned()
                .unwrap_or_else(|| self.estado_inicial.clone()),
        )?;
        // Merge­set de V a `slot(V)`.
        let ctx = self.contexto_virtual(terminal, &v);
        for x_hash in self.mergeset_virtual(terminal, &v) {
            let Some(x) = self.por_hash.get(&x_hash) else {
                continue;
            };
            let (nuevo, undo, desc) =
                self.aplicar_bloque_con_hechos(&estado, x, Punto::Slot(v.slot), &ctx)?;
            estado = nuevo;
            orden.push(x_hash);
            undos.push(undo);
            for d in desc {
                descartes.push(Descarte {
                    bloque: x_hash,
                    indice: d.indice,
                    motivo: d.motivo,
                });
            }
        }
        Ok((estado, orden, descartes, undos))
    }

    /// Orden de aplicación de la historia seleccionada (bloques, sin transacciones).
    ///
    /// # Errores
    /// Un fallo de aplicación en modo fusión.
    pub fn orden_aplicacion(&self) -> Result<Vec<BlockHash>, MotivoBloque> {
        Ok(self.aplicar_historia_completa()?.1)
    }

    /// Aplica la rama que termina en `punta` desde `Estado(T)` de **su** terminal y devuelve los
    /// `Undo` por delta (`ED-3`, `C-REORG`); resuelve el terminal de `punta` por
    /// [`Cadena::terminal_de`].
    ///
    /// # Errores
    /// Un fallo de aplicación en modo fusión, o una punta desconocida.
    pub fn aplicar_rama(&self, punta: &BlockHash) -> Result<(Estado, Vec<Undo>), MotivoBloque> {
        let terminal = self.terminal_de(punta).ok_or(MotivoBloque::ErrSinPadre)?;
        let Some(dt) = self.dags.get(&terminal) else {
            return Err(MotivoBloque::ErrSinPadre);
        };
        let Some(idx) = dt.dag_idx.get(punta).copied() else {
            return Err(MotivoBloque::ErrSinPadre);
        };
        let estado_inicial = self
            .post
            .get(&terminal)
            .cloned()
            .unwrap_or_else(|| self.estado_inicial.clone());
        let (estado, _orden, _desc, undos) =
            self.aplicar_cadena(terminal, &dt.dag, idx, estado_inicial)?;
        Ok((estado, undos))
    }

    /// Deshace una historia aplicada con [`Self::aplicar_historia_completa`] o
    /// [`Self::aplicar_rama`], en orden inverso (`I-2`).
    #[must_use]
    pub fn deshacer_historia(&self, estado: &Estado, undos: &[Undo]) -> Estado {
        let mut restaurado = estado.clone();
        for undo in undos.iter().rev() {
            restaurado = deshacer(&restaurado, undo);
        }
        restaurado
    }

    /// Aplica la cadena seleccionada de `terminal` desde `sp` (sin el merge­set de `V`) y devuelve
    /// el estado, el orden, los descartes y los undos.
    fn aplicar_cadena(
        &self,
        terminal: BlockHash,
        dag: &AlmacenGhostdag,
        sp: Idx,
        estado_inicial: Estado,
    ) -> Result<HistoriaAplicada, MotivoBloque> {
        let mut estado = estado_inicial;
        let mut orden = Vec::new();
        let mut descartes = Vec::new();
        let mut undos = Vec::new();
        for g in dag.cadena_seleccionada(sp) {
            if g == 0 {
                continue;
            }
            let c_hash = self
                .hash_de_idx(terminal, g)
                .ok_or(MotivoBloque::ErrSinPadre)?;
            let Some(c) = self.por_hash.get(&c_hash) else {
                return Err(MotivoBloque::ErrSinPadre);
            };
            let c_slot = c.slot().ok_or(MotivoBloque::ErrSinPadre)?;
            let Some(gd) = dag.datos(g) else {
                return Err(MotivoBloque::ErrSinPadre);
            };
            let ctx = self
                .contexto_real(terminal, g)
                .ok_or(MotivoBloque::ErrSinPadre)?;
            for x_idx in &gd.orden_mergeset {
                if dag.color_en(g, *x_idx) == Some(Color::RojoU3) {
                    continue;
                }
                let x_hash = self
                    .hash_de_idx(terminal, *x_idx)
                    .ok_or(MotivoBloque::ErrSinPadre)?;
                let Some(x) = self.por_hash.get(&x_hash) else {
                    return Err(MotivoBloque::ErrSinPadre);
                };
                let (nuevo, undo, desc) =
                    self.aplicar_bloque_con_hechos(&estado, x, Punto::Slot(c_slot), &ctx)?;
                estado = nuevo;
                orden.push(x_hash);
                undos.push(undo);
                for d in desc {
                    descartes.push(Descarte {
                        bloque: x_hash,
                        indice: d.indice,
                        motivo: d.motivo,
                    });
                }
            }
            let (mut nuevo, undo, desc) =
                self.aplicar_bloque_con_hechos(&estado, c, Punto::Slot(c_slot), &ctx)?;
            let Some(peso) = c.peso() else {
                return Err(MotivoBloque::ErrSinPadre);
            };
            nuevo.peso_sufijo =
                nuevo
                    .peso_sufijo
                    .checked_add(peso)
                    .ok_or(MotivoBloque::ErrTransicion(
                        zx_consensus::transicion::ErrorTransicion::ErrDesbordamiento,
                    ))?;
            estado = nuevo;
            orden.push(c_hash);
            undos.push(undo);
            for d in desc {
                descartes.push(Descarte {
                    bloque: c_hash,
                    indice: d.indice,
                    motivo: d.motivo,
                });
            }
        }
        Ok((estado, orden, descartes, undos))
    }

    /// Hashes del merge­set de `V` a aplicar (sin `rojo_U3`), en orden `C-GD-05`, para `terminal`.
    fn mergeset_virtual(&self, terminal: BlockHash, v: &Virtual) -> Vec<BlockHash> {
        v.datos
            .orden_mergeset
            .iter()
            .filter(|x| color_en_datos(&v.datos, **x) != Some(Color::RojoU3))
            .filter_map(|x| self.hash_de_idx(terminal, *x))
            .collect()
    }

    /// Calcula los datos GHOSTDAG de la punta virtual `V` de `terminal` **sobre su DAG ya
    /// existente**, sin reconstruirlo: el almacén del terminal ya mantiene la alcanzabilidad y el
    /// coloreo incrementales, y `datos_de_virtual` solo colorea el bloque virtual sobre ellos.
    ///
    /// `V` no se inserta en el almacén: se recalcula cada vez que se consulta.
    fn dag_virtual_de(&self, terminal: BlockHash) -> Result<Option<Virtual>, MotivoBloque> {
        let Some(dt) = self.dags.get(&terminal) else {
            return Ok(None);
        };
        // `FIN-1`: el virtual solo se construye con las puntas cuya cadena seleccionada contiene el
        // punto de finalidad vigente; así una rama que lo excluye no puede hacer que el virtual
        // cambie (decisión 2).
        let tips = self.tips_seleccionables_de(terminal);
        if tips.is_empty() {
            return Ok(None);
        }
        if tips.len() > usize::from(zx_dag::ghostdag::MAX_PADRES_POR_DEFECTO) {
            // T04 usa `max_parents = typemax` para `V`; `zx-dag` acota a `MAX_PADRES`.
            return Err(MotivoBloque::ErrSinPadre);
        }
        let slot = tips
            .iter()
            .filter_map(|h| self.por_hash.get(h).and_then(BloqueCadena::slot))
            .max()
            .ok_or(MotivoBloque::ErrSinPadre)?;
        let mut indices: Vec<Idx> = Vec::with_capacity(tips.len());
        for h in &tips {
            let idx = *dt.dag_idx.get(h).ok_or(MotivoBloque::ErrSinPadre)?;
            indices.push(idx);
        }
        let datos = dt
            .dag
            .datos_de_virtual(&indices, slot)
            .map_err(|e| mapear_error_dag(&e))?;
        Ok(Some(Virtual { datos, slot }))
    }

    /// Traduce un índice denso del DAG de `terminal` al `block_hash`.
    ///
    /// PROD-3a: la implementación única vive en `admision_post::hash_de_idx`.
    fn hash_de_idx(&self, terminal: BlockHash, idx: Idx) -> Option<BlockHash> {
        admision_post::hash_de_idx(self, terminal, idx)
    }

    // ---------------------------------------------------------------------------------------------
    // Accesos de lectura para el registro estructurado (`ORDEN-W07a` decisión 2, reimplementados
    // sobre el diseño multi-terminal de `ORDEN-W06d7`). Funciones nuevas y aisladas: no tocan
    // ninguna existente. Devuelven exactamente lo que ya calcula y guarda el código para el
    // terminal **seleccionado** (nunca una segunda implementación); `None` si el bloque no está en
    // el DAG de ese terminal.
    // ---------------------------------------------------------------------------------------------

    /// `DagTerminal` del terminal **seleccionado**, si ya tiene DAG propio.
    fn dag_terminal_seleccionado(&self) -> Option<&DagTerminal> {
        self.terminal_seleccionado.and_then(|t| self.dags.get(&t))
    }

    /// `DatosGhostdag` guardados de `hash` en el DAG del terminal **seleccionado**. `None` si
    /// `hash` no pertenece a ese DAG (p. ej. un bloque PoW, o uno de otro terminal).
    #[must_use]
    pub fn datos_ghostdag(&self, hash: &BlockHash) -> Option<&zx_dag::ghostdag::DatosGhostdag> {
        let dt = self.dag_terminal_seleccionado()?;
        let idx = *dt.dag_idx.get(hash)?;
        dt.dag.datos(idx)
    }

    /// `blue_score(B)` (`C-GD-08`) del bloque `hash`, si está en el DAG del terminal seleccionado.
    #[must_use]
    pub fn blue_score(&self, hash: &BlockHash) -> Option<u64> {
        self.datos_ghostdag(hash).map(|d| d.blue_score)
    }

    /// `(|azules del mergeset|, |rojos|)` de `hash` en el DAG del terminal seleccionado. El
    /// mergeset completo es `orden_mergeset`; los rojos, `rojos`; los azules son la diferencia.
    #[must_use]
    pub fn mergeset_de(&self, hash: &BlockHash) -> Option<(u64, u64)> {
        let datos = self.datos_ghostdag(hash)?;
        let azules = datos.orden_mergeset.len().saturating_sub(datos.rojos.len());
        Some((azules as u64, datos.rojos.len() as u64))
    }

    /// Tamaño (`|mergeset(B)|`) que tendría un bloque cuyos padres fueran `padres` en el DAG del
    /// terminal **seleccionado**, junto con el tope de mergeset efectivo de ese DAG (`C-GD-04`).
    ///
    /// **Solo lectura:** no muta la `Cadena`, no admite ni valida bloques. El `sp` se recalcula como
    /// en la admisión ([`ContextoDag::padre_seleccionado`], que ignora el orden declarado) y el
    /// mergeset se recorre sobre el DAG ya almacenado
    /// (`mergeset(B) = past(B) \ (past(sp) ∪ {sp})`, `C-GD-04`), sin reconstruir índices ni
    /// colorear. La comprobación de la admisión es `tamano + 1 > tope` ⇒ `ErrMergeset` (`+1` cuenta
    /// el propio bloque); el llamante compara con esa misma desigualdad.
    ///
    /// La usa `zx-node` para elegir los padres de un bloque sin superar el tope de consenso. El
    /// `tope` sale del propio `AlmacenGhostdag` del terminal, de modo que no hay una segunda copia
    /// del 180 que pueda divergir.
    ///
    /// Devuelve `None` si no hay terminal con DAG, si `padres` está vacío, si hay duplicados o si
    /// algún padre no pertenece al DAG del terminal seleccionado.
    #[must_use]
    pub fn mergeset_de_padres(&self, padres: &[BlockHash]) -> Option<(u64, u32)> {
        let terminal = self.terminal_seleccionado?;
        let dt = self.dags.get(&terminal)?;
        let (primero, resto) = padres.split_first()?;
        // `PadresDag` ordena y rechaza duplicados; el `sp` lo recalcula GHOSTDAG sobre `padres`.
        let provisional = PadresDag::nuevo(*primero, resto).ok()?;
        let sp = ContextoDag::padre_seleccionado(&dt.dag, &provisional).ok()?;
        let sp_idx = *dt.dag_idx.get(&sp)?;

        // Recorrido de `past(P) \ (past(sp) ∪ {sp})`, idéntico al `mergeset` interno del almacén
        // pero apoyado en la API pública (`padres_de`, `id`, `esta_en_el_pasado_de`).
        let mut visto: BTreeSet<Idx> = BTreeSet::new();
        let mut pila: Vec<Idx> = Vec::new();
        for p in padres {
            let idx = *dt.dag_idx.get(p)?;
            if idx == sp_idx || dt.dag.esta_en_el_pasado_de(p, &sp).ok()? {
                continue;
            }
            if visto.insert(idx) {
                pila.push(idx);
            }
        }
        while let Some(cur) = pila.pop() {
            let Some(ps) = dt.dag.padres_de(cur) else {
                continue;
            };
            for &pidx in ps {
                if pidx == sp_idx {
                    continue;
                }
                let ph = dt.dag.id(pidx)?;
                if dt.dag.esta_en_el_pasado_de(&ph, &sp).ok()? {
                    continue;
                }
                if visto.insert(pidx) {
                    pila.push(pidx);
                }
            }
        }
        Some((visto.len() as u64, dt.dag.parametros().mergeset_limite))
    }

    /// Número de bloques admitidos (válidos) en esta `Cadena`, contando PoW y PoST.
    #[must_use]
    pub fn bloques_admitidos(&self) -> u64 {
        self.validos.values().filter(|v| **v).count() as u64
    }

    /// Padre seleccionado (`sp`, `C-GD-03`) de un bloque del DAG del terminal **seleccionado**, como
    /// hash. `None` para la raíz (el terminal), para un bloque de otro terminal o si `hash` no está
    /// en ese DAG.
    #[must_use]
    pub fn padre_seleccionado(&self, hash: &BlockHash) -> Option<BlockHash> {
        let terminal = self.terminal_seleccionado?;
        let datos = self.datos_ghostdag(hash)?;
        self.hash_de_idx(terminal, datos.sp?)
    }

    /// RD-4a · H1 · Bloques por productor en la **ventana** de `v` bloques hacia atrás desde el
    /// ancla de votos ([`Cadena::ancla_votos`]).
    ///
    /// Recorre como mucho `v` bloques PoST empezando por el bloque del ancla y siguiendo el padre
    /// seleccionado ([`Cadena::padre_seleccionado`]); para antes si la cadena se acaba (un bloque
    /// que no es PoST o sin padre seleccionado). Los bloques **posteriores** al ancla no cuentan:
    /// el recorrido empieza en ella, nunca en la punta. Sin ancla devuelve el mapa vacío.
    ///
    /// Es de **solo lectura**: no guarda estado ni cambia nada de la cadena. La suma de los valores
    /// es el número de bloques recorridos (a lo sumo `v`).
    #[must_use]
    pub fn productores_en_ventana(&self, v: u64) -> BTreeMap<ClavePublica, u64> {
        let mut cuenta: BTreeMap<ClavePublica, u64> = BTreeMap::new();
        let Some((_n, mut hash)) = self.ancla_votos else {
            return cuenta;
        };
        for _ in 0..v {
            let Some(BloqueCadena::Post(p)) = self.por_hash.get(&hash) else {
                break;
            };
            let contador = cuenta.entry(p.productor).or_insert(0);
            *contador = contador.saturating_add(1);
            let Some(padre) = self.padre_seleccionado(&hash) else {
                break;
            };
            hash = padre;
        }
        cuenta
    }
}

/// AT-1b · W2 · extrae los dos votos de una transacción `0x0B`, si lo es.
fn evidencia_votos_peso(tx: &Tx) -> Option<(&VotoPesoEvidencia, &VotoPesoEvidencia)> {
    if tx.version != 6 {
        return None;
    }
    let ExtensionTx::PruebaAlmacenamiento { operacion } = &tx.extension else {
        return None;
    };
    match operacion {
        OperacionAlmacenamiento::EvidenciaVotosPeso { voto1, voto2, .. } => Some((voto1, voto2)),
        _ => None,
    }
}

/// Color contextual de `cand` dentro de unos [`DatosGhostdag`] concretos (incluida la punta virtual,
/// que no vive en el almacén).
fn color_en_datos(datos: &DatosGhostdag, cand: Idx) -> Option<Color> {
    if datos.blues.contains(&cand) {
        return Some(Color::Azul);
    }
    datos
        .colores
        .iter()
        .find_map(|(c, color)| (*c == cand).then_some(*color))
}

/// Construye la entrada de `zx-dag` de un bloque PoST.
///
/// La identidad se recibe ya construida: la ruta real (`IdentidadGhostdag::Billete`, derivada de la
/// cabecera por `zx_dag::identidad_de_cabecera`) no se proyecta a `u64`; el arnés diferencial pasa
/// `de_fixture` explícitamente.
fn bloque_ghostdag(
    id: BlockHash,
    padres: &[BlockHash],
    slot: u64,
    distancia: u64,
    sr: u64,
    identidad: IdentidadGhostdag,
) -> BloqueGhostdag {
    BloqueGhostdag {
        id,
        padres: padres.to_vec(),
        slot,
        solution_distance: distancia,
        rango_espacio: RangoSolucionValidado::para_oraculos(sr),
        identidad,
    }
}

/// ¿La transacción es una coinbase (v1 sin entradas, o v3)?
fn es_coinbase(tx: &Tx) -> bool {
    (tx.version == 1 && tx.inputs.is_empty()) || tx.version == 3
}

/// Importe declarado de una coinbase PoST, si la extensión lo es.
fn importe_de_coinbase_post(tx: &Tx) -> Option<Amount> {
    match &tx.extension {
        zx_core::ExtensionTx::CoinbasePost { importe, .. } => Some(*importe),
        _ => None,
    }
}

/// Activo de `clave` tras promover pendientes y créditos madurados en `slot` (`promover!` de T04).
fn activo_promovido(
    estado: &Estado,
    clave: &ClavePublica,
    slot: u64,
) -> Result<Amount, MotivoBloque> {
    let Some(g) = estado.garantias.get(clave) else {
        return Ok(Amount::CERO);
    };
    let mut total = g.activo;
    for p in g.pendientes.iter().chain(g.creditos.iter()) {
        if p.madura_en_slot.is_some_and(|s| s <= slot) {
            total = total
                .suma_comprobada(p.importe)
                .ok_or(MotivoBloque::ErrTransicion(
                    zx_consensus::transicion::ErrorTransicion::ErrDesbordamiento,
                ))?;
        }
    }
    Ok(total)
}

/// Orden de la regla C: mayor `blue_work`, menor `sd`, menor id.
fn comparar_rank(a: Option<Rank>, b: Option<Rank>) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => y
            .blue_work
            .cmp(&x.blue_work)
            .then(x.solution_distance.cmp(&y.solution_distance))
            .then(x.id.cmp(&y.id)),
        _ => Ordering::Equal,
    }
}

/// Comparador de **solo** `blue_work` entre virtuales de dos terminales (`ORDEN-W06d7` decisión 2,
/// primera cláusula de FC-3 entre terminales); el desempate por hash y por el resto de `C-GD` va
/// aparte (`comparar_terminal`, `comparar_rank`), porque el `id`/`solution_distance` del nodo
/// sintético `V` no distingue terminales (es la misma constante en todos).
fn comparar_blue_work(a: Option<Rank>, b: Option<Rank>) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => y.blue_work.cmp(&x.blue_work),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Traduce un rechazo de `zx-dag` al motivo de bloque del oráculo (`mapear_motivo_gdr`).
fn mapear_error_dag(error: &ErrorDag) -> MotivoBloque {
    match error {
        ErrorDag::DemasiadosPadresDag { .. } | ErrorDag::BloqueDesconocido { .. } => {
            MotivoBloque::ErrSinPadre
        }
        ErrorDag::MergesetExcedeLimite { .. } => MotivoBloque::ErrMergeset,
        ErrorDag::BilleteDuplicadoU2 { .. } => MotivoBloque::ErrU2,
        ErrorDag::SaltoMayorSmax { .. } | ErrorDag::SlotDePadrePosterior { .. } => {
            MotivoBloque::ErrSlot
        }
        _ => MotivoBloque::ErrSinPadre,
    }
}

/// FV-4b-N1 · pruebas de la puerta `anclar_finalidad_por_votos` y de la bandera
/// `finalidad_por_votos` (decisión 4 de `REVISION-FV4bD.md`).
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
#[expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
#[expect(
    clippy::integer_division,
    reason = "la ventana se deriva de un cierre par conocido"
)]
mod pruebas_fv4b {
    use primitive_types::U256;
    use std::collections::BTreeMap;
    use zx_consensus::transicion::HechoVoto;
    use zx_consensus::transicion::votos::ESPERA_REARRANQUE_SLOTS;
    use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
    use zx_core::{
        Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx,
        OperacionAlmacenamiento, Tx, VotoPesoEvidencia,
    };
    use zx_dag::IdentidadTicket;
    use zx_dag::ghostdag::{IdentidadGhostdag, Idx};

    use super::{BloqueCadena, BloquePost, Cadena, ContextoAplicacion, MotivoAncla};

    const MAX_PADRES: u8 = 15;
    const K: u32 = 1;

    fn subsidio_pow(_h: u32) -> Amount {
        Amount::nuevo(10).unwrap()
    }
    fn subsidio_post(_s: u64) -> Amount {
        Amount::nuevo(3).unwrap()
    }

    fn params(f_slots: Option<u64>) -> ParametrosTransicion {
        ParametrosTransicion {
            h_dep: 1,
            m_cb: 1,
            m_dep: 0,
            h_corte_min: 1,
            w_min: U256::one(),
            s_min: Amount::CERO,
            q: Amount::CERO,
            k_min: 0,
            max_tx_bytes: 100_000,
            max_cuerpo_bloque_bytes: 320_000,
            m_res_slots: 1,
            m_dep_slots: 1,
            m_rec_slots: 1,
            r_slots: 1,
            f_slots,
            subsidio_pow,
            subsidio_post,
        }
    }

    fn hash_u32(n: u32) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&n.to_be_bytes());
        BlockHash::from_digest(Digest::from_bytes(bytes))
    }

    fn productor() -> ClavePublica {
        let digest = zx_core::sha3_256_publico(b"zx-fv4b-ancla");
        let sk = ed25519_zebra::SigningKey::from(*digest.as_bytes());
        let vk = ed25519_zebra::VerificationKey::from(&sk);
        ClavePublica::desde_bytes(vk.into())
    }

    fn tx_coinbase_post(clave: ClavePublica, importe: i64, slot: u64) -> Tx {
        Tx {
            version: 3,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::CoinbasePost {
                clave,
                importe: Amount::nuevo(importe).unwrap(),
                slot,
            },
        }
    }

    fn genesis() -> BloqueCadena {
        BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis { hash: hash_u32(0) },
            Vec::new(),
        ))
    }

    fn pow_terminal(id: u32, trabajo: u64) -> BloqueCadena {
        BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::PoW {
                hash: hash_u32(id),
                padre: hash_u32(0),
                altura: 1,
                trabajo: U256::from(trabajo),
                pow_valido: true,
            },
            Vec::new(),
        ))
    }

    fn post(id: u32, padres: Vec<BlockHash>, slot: u64, sr: u64) -> BloqueCadena {
        let productor = productor();
        let tx = tx_coinbase_post(productor, 1, slot);
        let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
            productor,
            0,
            u64::from(id) + 1,
            [(id & 0xff) as u8; 32],
            slot,
        ));
        BloqueCadena::Post(BloquePost {
            hash: hash_u32(id),
            padres,
            slot,
            timestamp: 0,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
            sr,
            distancia: 0,
            identidad,
            txs: vec![(tx, Vec::new())],
        })
    }

    fn cadena_base(f_slots: u64, n: u32) -> Cadena {
        let mut cadena = Cadena::nueva(params(Some(f_slots)), K, CBID_RED_DEV, MAX_PADRES);
        cadena.admitir(genesis()).unwrap();
        cadena.admitir(pow_terminal(1, 1)).unwrap();
        let mut padre = hash_u32(1);
        for i in 0..n {
            let id = 10 + i;
            let b = post(id, vec![padre], u64::from(i) + 1, 10);
            cadena.admitir(b.clone()).unwrap();
            padre = b.hash();
        }
        cadena
    }

    /// Cadena de `n` bloques PoST que arranca en `base`, con `sr` dado (menor = más peso).
    fn rama(
        cadena: &mut Cadena,
        n: u32,
        base_id: u32,
        base: BlockHash,
        slot_ini: u64,
        sr: u64,
    ) -> BlockHash {
        let mut padre = base;
        for i in 0..n {
            let id = base_id + i;
            let b = post(id, vec![padre], slot_ini + u64::from(i), sr);
            cadena.admitir(b.clone()).unwrap();
            padre = b.hash();
        }
        padre
    }

    /// Un candidato **descendiente** del punto vigente se ancla; el mismo punto se acepta.
    #[test]
    fn ancla_un_descendiente_y_activa_la_bandera() {
        let mut cadena = cadena_base(3, 6);
        assert!(!cadena.finalidad_por_votos());
        let punta = cadena.mejor_punta().expect("punta");
        cadena.anclar_finalidad_por_votos(punta).unwrap();
        assert_eq!(cadena.punto_finalidad(), Some(punta));
        assert!(cadena.finalidad_por_votos());
    }

    /// **ANC-1 · A2** · Un **ancestro** del punto vigente es un certificado atrasado: `Ok` y el
    /// punto **no** retrocede (antes devolvía `Conflicto`, que el nodo registraba como
    /// `certificado_en_conflicto`).
    #[test]
    fn anclar_un_ancestro_no_es_conflicto_y_no_retrocede() {
        let mut cadena = cadena_base(3, 6);
        let punta = cadena.mejor_punta().expect("punta");
        cadena.anclar_finalidad_por_votos(punta).unwrap();
        let ancestro = hash_u32(12);
        assert_eq!(cadena.anclar_finalidad_por_votos(ancestro), Ok(()));
        assert_eq!(cadena.punto_finalidad(), Some(punta), "no retrocede");
    }

    /// Un hash que no pertenece al DAG es **desconocido**: no se adopta.
    #[test]
    fn anclar_un_desconocido_falla() {
        let mut cadena = cadena_base(3, 6);
        assert_eq!(
            cadena.anclar_finalidad_por_votos(hash_u32(9_999)),
            Err(MotivoAncla::Desconocido)
        );
    }

    /// Con la bandera activa, un cambio a otro terminal **no re-basa** el punto de finalidad.
    #[test]
    fn la_bandera_evita_el_rebase_al_cambiar_de_terminal() {
        // Sufijo de 2 slots con `F = 10`: FC-3 puede cambiar al terminal rival (`d < F`).
        let mut cadena = cadena_base(10, 2);
        let pf = cadena.punto_finalidad();
        cadena
            .anclar_finalidad_por_votos(pf.expect("punto vigente"))
            .unwrap();
        assert_eq!(cadena.punto_finalidad(), pf);
        // Terminal rival (más trabajo) **con DAG** (sr=1, más pesado) para que FC-3 lo seleccione.
        cadena.admitir(pow_terminal(2, 5)).unwrap();
        let _ = rama(&mut cadena, 12, 1_000, hash_u32(2), 1, 1);
        assert_eq!(cadena.terminal(), Some(hash_u32(2)), "cambia de terminal");
        // Sin la bandera, `FIN-1` re-basaría el punto a la cadena del terminal nuevo; con ella, no.
        assert_eq!(cadena.punto_finalidad(), pf, "el punto no se re-basa");
    }

    /// ECL-R2a · D3: dentro de `F`, el certificado guía la selección al terminal que contiene su
    /// candidato, aunque no sea el de más trabajo.
    #[test]
    fn eclr2_dentro_de_f_el_certificado_guia_la_seleccion() {
        let mut cadena = cadena_base(20, 2);
        cadena.admitir(pow_terminal(2, 5)).unwrap();
        let _ = rama(&mut cadena, 5, 1_000, hash_u32(2), 1, 1);
        assert_eq!(cadena.terminal(), Some(hash_u32(2)), "B manda sin ancla");
        let resultado = cadena.considerar_ancla_de_estado(7, hash_u32(11));
        assert_eq!(resultado, super::ResultadoAncla::Adoptada);
        assert_eq!(cadena.terminal(), Some(hash_u32(1)), "el ancla guía a A");
        assert!(cadena.cadena_virtual().contains(&hash_u32(11)));
    }

    /// ECL-R2a · D4: más allá de `F`, un certificado en conflicto no cambia la selección y marca
    /// eclipse.
    #[test]
    fn eclr2_mas_alla_de_f_marca_eclipse_sin_cambiar() {
        let mut cadena = cadena_base(5, 2);
        cadena.admitir(pow_terminal(2, 5)).unwrap();
        let _ = rama(&mut cadena, 12, 1_000, hash_u32(2), 1, 1);
        assert_eq!(cadena.terminal(), Some(hash_u32(2)));
        let resultado = cadena.considerar_ancla_verificada(7, hash_u32(11));
        assert_eq!(resultado, super::ResultadoAncla::Adoptada);
        assert!(cadena.eclipse().is_some(), "mas alla de F: eclipse");
        assert_eq!(
            cadena.terminal(),
            Some(hash_u32(2)),
            "la seleccion no cambia"
        );
    }

    /// ECL-R2a · D5: sin datos, el ancla queda pendiente y no cambia de terminal.
    #[test]
    fn eclr2_ancla_pendiente_sin_datos() {
        let mut cadena = cadena_base(20, 2);
        let antes = cadena.terminal();
        let resultado = cadena.considerar_ancla_de_estado(9, hash_u32(9_999));
        assert_eq!(resultado, super::ResultadoAncla::Pendiente);
        assert!(cadena.ancla_pendiente());
        assert!(cadena.eclipse().is_none());
        assert_eq!(cadena.terminal(), antes, "no cambia de terminal");
    }

    /// ECL-R2a · D1: el ancla no retrocede y el conflicto de misma instancia no se adopta.
    #[test]
    fn eclr2_ancla_no_retrocede_y_conflicto_no_se_adopta() {
        let mut cadena = cadena_base(20, 2);
        assert_eq!(
            cadena.considerar_ancla_de_estado(7, hash_u32(11)),
            super::ResultadoAncla::Adoptada
        );
        assert_eq!(
            cadena.considerar_ancla_de_estado(6, hash_u32(10)),
            super::ResultadoAncla::Ignorada
        );
        assert_eq!(
            cadena.considerar_ancla_de_estado(7, hash_u32(10)),
            super::ResultadoAncla::ConflictoMismaInstancia
        );
        assert_eq!(cadena.ancla_votos(), Some((7, hash_u32(11))));
        assert_eq!(cadena.conflictos_ancla().len(), 1);
    }

    /// ECL-R2a-2 · D4 **enclavado**: una parada demostrada no se borra con recálculos, nuevos
    /// bloques ni un ancla posterior, y conserva la primera causa y la selección.
    #[test]
    fn eclr2_eclipse_queda_enclavado() {
        let mut cadena = cadena_base(5, 2);
        cadena.admitir(pow_terminal(2, 5)).unwrap();
        let _ = rama(&mut cadena, 12, 1_000, hash_u32(2), 1, 1);
        assert_eq!(cadena.terminal(), Some(hash_u32(2)));
        assert_eq!(
            cadena.considerar_ancla_verificada(7, hash_u32(11)),
            super::ResultadoAncla::Adoptada
        );
        let primera = cadena.eclipse().expect("eclipse");
        // (1) Un ancla posterior en otra instancia no levanta la parada.
        let _ = cadena.considerar_ancla_verificada(8, hash_u32(12_001));
        // (2) Nuevos bloques del terminal seleccionado recalculan la selección.
        let _ = rama(&mut cadena, 2, 2_000, hash_u32(2), 100, 1);
        assert_eq!(
            cadena.eclipse(),
            Some(primera),
            "la parada sigue y conserva la primera causa"
        );
        assert_eq!(
            cadena.terminal(),
            Some(hash_u32(2)),
            "la parada no cambia de terminal"
        );
    }

    /// ECL-R2a-3 · Una rama **incompatible dentro del mismo terminal** (misma pertenencia al DAG)
    /// no mueve `F` ni la selección virtual y, con sufijo ≥ `F_slots`, deja eclipse (PK-27B). †
    #[test]
    fn eclr2_rama_incompatible_mismo_terminal_no_mueve_f_y_marca_eclipse() {
        // 10 bloques PoST (slots 1..10) con `F = 5`: `F` = id 14 (slot 5), no el terminal.
        let mut cadena = cadena_base(5, 10);
        assert_eq!(
            cadena.punto_finalidad(),
            Some(hash_u32(14)),
            "F es el bloque del slot 5"
        );
        assert_eq!(cadena.mejor_punta(), Some(hash_u32(19)));
        // Bifurcación desde `id 12` (por debajo de F); `sr` peor para que la selección no cambie.
        cadena
            .admitir(post(500, vec![hash_u32(12)], 11, 100))
            .unwrap();
        assert_eq!(cadena.terminal(), Some(hash_u32(1)), "mismo terminal");
        assert!(
            !cadena.cadena_virtual().contains(&hash_u32(500)),
            "la rama incompatible no entra en la cadena seleccionada"
        );
        let f_antes = cadena.punto_finalidad();
        let resultado = cadena.considerar_ancla_de_estado(7, hash_u32(500));
        assert_eq!(resultado, super::ResultadoAncla::Adoptada);
        assert_eq!(
            cadena.punto_finalidad(),
            f_antes,
            "una rama incompatible no mueve F"
        );
        assert!(cadena.eclipse().is_some(), "conflicto profundo: eclipse");
        assert!(
            !cadena.cadena_virtual().contains(&hash_u32(500)),
            "la virtual no salta a la rama incompatible"
        );
    }

    /// ECL-R2a-3 · Un certificado atrasado **ancestro del `F`** no lo retrocede ni produce un falso
    /// eclipse: no todo retraso es ataque.
    #[test]
    fn eclr2_ancestro_del_f_no_retrocede_ni_marca_eclipse() {
        let mut cadena = cadena_base(5, 10);
        let pf = cadena.punto_finalidad().expect("F vigente");
        let resultado = cadena.considerar_ancla_de_estado(7, hash_u32(12));
        assert_eq!(resultado, super::ResultadoAncla::Adoptada);
        assert_eq!(cadena.punto_finalidad(), Some(pf), "no retrocede");
        assert!(cadena.eclipse().is_none(), "un ancestro no es eclipse");
    }

    /// ECL-R2a-3 · Un descendiente compatible del `F` sí progresa (D3) sin eclipse.
    #[test]
    fn eclr2_descendiente_compatible_del_f_progresa() {
        let mut cadena = cadena_base(5, 10);
        let resultado = cadena.considerar_ancla_de_estado(7, hash_u32(17));
        assert_eq!(resultado, super::ResultadoAncla::Adoptada);
        assert_eq!(cadena.punto_finalidad(), Some(hash_u32(17)));
        assert!(cadena.eclipse().is_none());
    }

    /// `ORDEN-IDX1` · X1 (I2) · Tras **cada** operación de una secuencia aleatoria con semilla fija,
    /// el índice de puntas devuelve exactamente lo mismo que la referencia (contenido y orden).
    ///
    /// 12 semillas × 2 000 pasos. Cada paso admite un bloque PoST (válido con bifurcaciones y huecos
    /// de slot, o inválido) en uno de dos terminales PoW; los dos terminales reciben ramas, de modo
    /// que la selección cambia de terminal durante la secuencia.
    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "índices elegidos por el generador, siempre dentro de rango"
    )]
    fn idx1_x1_indice_igual_a_referencia_tras_cada_paso() {
        // xorshift64 determinista: no añade dependencias y fija la semilla.
        fn siguiente(estado: &mut u64) -> u64 {
            let mut x = *estado;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *estado = x;
            x
        }
        let terminales = [hash_u32(1), hash_u32(2)];
        for semilla in 1u64..=12 {
            let mut cadena = Cadena::nueva(params(None), K, CBID_RED_DEV, MAX_PADRES);
            cadena.admitir(genesis()).unwrap();
            cadena.admitir(pow_terminal(1, 1)).unwrap();
            cadena.admitir(pow_terminal(2, 5)).unwrap();
            // Bloques PoST válidos por terminal, con su slot, para elegir padres.
            let mut validos: [Vec<(BlockHash, u64)>; 2] = [Vec::new(), Vec::new()];
            let mut id: u32 = 100;
            let mut estado = semilla.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            for _ in 0..2_000u32 {
                let t = (siguiente(&mut estado) as usize) % 2;
                let terminal = terminales[t];
                let r = siguiente(&mut estado);
                if r.is_multiple_of(8) {
                    // Bloque inválido: `ErrSlot` (slot 0) o `ErrSinPadre` (padre desconocido).
                    let malo = if r.is_multiple_of(16) {
                        post(id, vec![terminal], 0, 10)
                    } else {
                        post(id, vec![hash_u32(9_000_000)], 7, 10)
                    };
                    id += 1;
                    assert!(
                        cadena.admitir(malo).is_err(),
                        "el bloque inválido se admitió"
                    );
                } else {
                    // Bifurcación: a veces el padre es el terminal, a veces un bloque anterior
                    // (posiblemente ya con un hijo). Hueco de slot de 1 a 3.
                    let (padre, slot_padre) =
                        if validos[t].is_empty() || siguiente(&mut estado).is_multiple_of(3) {
                            (terminal, 0)
                        } else {
                            validos[t][(siguiente(&mut estado) as usize) % validos[t].len()]
                        };
                    let slot = slot_padre + 1 + siguiente(&mut estado) % 3;
                    let bloque = post(id, vec![padre], slot, 10);
                    id += 1;
                    let hash = bloque.hash();
                    if cadena.admitir(bloque).is_ok() {
                        validos[t].push((hash, slot));
                    }
                }
                // I2: índice == referencia tras **cada** operación, para cada terminal conocido.
                for terminal in terminales {
                    assert_eq!(
                        cadena.tips_validas_de(terminal),
                        cadena.tips_validas_referencia(terminal),
                        "semilla {semilla}: índice y referencia difieren en {terminal:?}"
                    );
                }
            }
            assert!(
                validos[0].len() > 1 && validos[1].len() > 1,
                "semilla {semilla}: los dos terminales deben tener sufijo PoST"
            );
            assert!(cadena.terminal().is_some(), "no hay terminal seleccionado");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────
    // AT-1b · W1/W2 · el hecho de la falta «voto contra la propia atadura» con los datos del DAG
    // (J1–J5) y la equivalencia «aplicado antes» ↔ orden de `aplicar_cadena` (J7).
    //
    // Se prueba la **decisión** (W2) sobre una `Cadena` real con votos sintéticos (el hecho no
    // verifica firmas). El castigo end-to-end de W4 lo cubre `crates/zx-consensus/tests/at1b.rs`.
    // ─────────────────────────────────────────────────────────────────────────────────────────

    fn tx_evidencia(n1: u64, c1: BlockHash, n2: u64, c2: BlockHash) -> Tx {
        let voto = |n: u64, c: BlockHash| VotoPesoEvidencia {
            n,
            candidato: *c.as_bytes(),
            h_t_siguiente: [0u8; 32],
            raiz_estado: [0u8; 32],
            firma: [0u8; 96],
        };
        Tx {
            version: 6,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::PruebaAlmacenamiento {
                operacion: OperacionAlmacenamiento::EvidenciaVotosPeso {
                    clave: ClavePublica::desde_bytes([200; 32]),
                    clave_bls: [9u8; 48],
                    voto1: voto(n1, c1),
                    voto2: voto(n2, c2),
                },
            },
        }
    }

    fn idx_de(cadena: &Cadena, terminal: BlockHash, hash: BlockHash) -> Idx {
        cadena
            .dags
            .get(&terminal)
            .unwrap()
            .dag_idx
            .get(&hash)
            .copied()
            .unwrap()
    }

    fn ctx_de(cadena: &Cadena, terminal: BlockHash, hash: BlockHash) -> ContextoAplicacion {
        let idx = idx_de(cadena, terminal, hash);
        cadena.contexto_real(terminal, idx).unwrap()
    }

    fn hecho(cadena: &Cadena, terminal: BlockHash, x: BlockHash, op: &Tx) -> HechoVoto {
        let ctx = ctx_de(cadena, terminal, x);
        let plazo =
            u64::try_from(cadena.estado_t.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
        cadena.hecho_de_tx(&ctx, plazo, x, op)
    }

    /// DAG con bifurcación: `t → (A(10), B1(11), B2(12))` y `X(20)` que reúne los tres.
    fn dag_bifurcacion() -> (Cadena, BlockHash, BlockHash, BlockHash, BlockHash) {
        let mut cadena = cadena_base(600, 0);
        let t = hash_u32(1);
        cadena.admitir(post(10, vec![t], 1, 10)).unwrap();
        cadena.admitir(post(11, vec![t], 1, 10)).unwrap();
        cadena.admitir(post(12, vec![t], 1, 10)).unwrap();
        cadena
            .admitir(post(
                20,
                vec![hash_u32(10), hash_u32(11), hash_u32(12)],
                2,
                10,
            ))
            .unwrap();
        (cadena, t, hash_u32(11), hash_u32(12), hash_u32(20))
    }

    /// J1 · la pregunta (1): bifurcación sin certificado que justifique → `Falta`. Además, W1 dejó
    /// guardada la finalidad del pasado de `B2` (sin certificados: `(0, None)`).
    #[test]
    fn j1_falta_sin_certificado() {
        let (cadena, t, b1, b2, x) = dag_bifurcacion();
        assert_eq!(cadena.finalidad_pasado.get(&b2), Some(&(0, None)));
        let op = tx_evidencia(1, b1, 4, b2);
        assert_eq!(hecho(&cadena, t, x, &op), HechoVoto::Falta);
    }

    /// J2 · la pregunta (2): la finalidad del pasado de `B2` selló un bloque en conflicto con `B1`
    /// en una ventana `≥ n₁` → `SinFalta`.
    #[test]
    fn j2_justificado_por_certificado_en_conflicto() {
        let (mut cadena, t, b1, b2, x) = dag_bifurcacion();
        cadena.finalidad_pasado.insert(b2, (1, Some(b2)));
        let op = tx_evidencia(1, b1, 4, b2);
        assert_eq!(hecho(&cadena, t, x, &op), HechoVoto::SinFalta);
    }

    /// J3 · el contraejemplo del modelo (`REVISION-ATM1.md`): el certificado intermedio selló el
    /// antepasado común `A` de `B1` y `B2` → no justifica → `Falta`.
    #[test]
    fn j3_antecesor_comun_sellado_es_falta() {
        let mut cadena = cadena_base(600, 0);
        let t = hash_u32(1);
        let a = hash_u32(10);
        cadena.admitir(post(10, vec![t], 1, 10)).unwrap();
        cadena.admitir(post(11, vec![a], 2, 10)).unwrap();
        cadena.admitir(post(12, vec![a], 2, 10)).unwrap();
        cadena
            .admitir(post(20, vec![hash_u32(11), hash_u32(12)], 3, 10))
            .unwrap();
        cadena.finalidad_pasado.insert(hash_u32(12), (1, Some(a)));
        let op = tx_evidencia(1, hash_u32(11), 4, hash_u32(12));
        assert_eq!(hecho(&cadena, t, hash_u32(20), &op), HechoVoto::Falta);
    }

    /// J4 · `B2` desciende de `B1` → `SinFalta`; `B2 = B1` → `SinFalta`.
    #[test]
    fn j4_descendencia_o_igualdad_no_es_conflicto() {
        let mut cadena = cadena_base(600, 0);
        let t = hash_u32(1);
        cadena.admitir(post(10, vec![t], 1, 10)).unwrap();
        cadena.admitir(post(11, vec![t], 1, 10)).unwrap();
        cadena.admitir(post(12, vec![hash_u32(11)], 2, 10)).unwrap();
        cadena
            .admitir(post(20, vec![hash_u32(10), hash_u32(12)], 3, 10))
            .unwrap();
        let op = tx_evidencia(1, hash_u32(11), 4, hash_u32(12));
        assert_eq!(hecho(&cadena, t, hash_u32(20), &op), HechoVoto::SinFalta);
        let op_igual = tx_evidencia(1, hash_u32(11), 4, hash_u32(11));
        assert_eq!(
            hecho(&cadena, t, hash_u32(20), &op_igual),
            HechoVoto::SinFalta
        );
    }

    /// J5 · frontera de `F`: con `slot(B1) = 1`, `cierre(299) = 600 < 601` es falta y
    /// `cierre(300) = 602` no.
    #[test]
    fn j5_frontera_de_f() {
        let (cadena, t, b1, b2, x) = dag_bifurcacion();
        let dentro = tx_evidencia(1, b1, 299, b2);
        assert_eq!(hecho(&cadena, t, x, &dentro), HechoVoto::Falta);
        let fuera = tx_evidencia(1, b1, 300, b2);
        assert_eq!(hecho(&cadena, t, x, &fuera), HechoVoto::SinFalta);
    }

    /// J7 · «aplicado antes que `x`» coincide con el prefijo del `orden` de `aplicar_cadena` en un
    /// DAG con conjunto de fusión de más de un bloque, para `x = X` y para cada bloque del
    /// conjunto de fusión de `X`.
    #[test]
    fn j7_aplicado_antes_coincide_con_el_orden() {
        let (cadena, t, _, _, x) = dag_bifurcacion();
        let (_, orden, _, _) = cadena.aplicar_historia_completa().unwrap();
        let pos: BTreeMap<BlockHash, usize> =
            orden.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let ctx = ctx_de(&cadena, t, x);
        let idx_x = idx_de(&cadena, t, x);
        let mut a_comprobar = vec![x];
        {
            let dt = cadena.dags.get(&t).unwrap();
            let gd = dt.dag.datos(idx_x).unwrap();
            for m in &gd.orden_mergeset {
                if dt.dag.color_en(idx_x, *m) != Some(super::Color::RojoU3) {
                    a_comprobar.push(cadena.hash_de_idx(t, *m).unwrap());
                }
            }
        }
        for xp in &a_comprobar {
            for b in &orden {
                // La definición solo cuenta bloques PoST (`B` es PoST).
                if cadena
                    .por_hash
                    .get(b)
                    .and_then(BloqueCadena::slot)
                    .is_none()
                {
                    continue;
                }
                let pb = pos.get(b).copied().unwrap_or(usize::MAX);
                let px = pos.get(xp).copied().unwrap_or(usize::MAX);
                assert_eq!(
                    cadena.aplicado_antes_que(&ctx, *xp, *b),
                    pb < px,
                    "x={xp:?} b={b:?}"
                );
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────
    // AT-1b2 · X4/J13 · la cota del coste del hecho (contador de bloques visitados).
    // ─────────────────────────────────────────────────────────────────────────────────────────

    /// Cadena lineal de `n` bloques PoST (un bloque por slot `1..n`) colgando del terminal PoW.
    fn cadena_lineal(n: u32) -> Cadena {
        let mut cadena = cadena_base(600, 0);
        let mut padre = hash_u32(1);
        for i in 1..=n {
            let b = post(10 + i, vec![padre], u64::from(i), 10);
            cadena.admitir(b.clone()).unwrap();
            padre = b.hash();
        }
        cadena
    }

    /// Cadena lineal de `n` bloques (slots `1..n`) más **dos hermanos** del terminal PoW
    /// (`id1`/`id2`, slots `slot1`/`slot2`) que no están en el pasado de la punta. Devuelve
    /// `(cadena, punta_de_la_rama_lineal)`.
    fn cadena_con_hermanos(
        n: u32,
        id1: u32,
        id2: u32,
        slot1: u64,
        slot2: u64,
    ) -> (Cadena, BlockHash) {
        let mut cadena = cadena_lineal(n);
        let t = hash_u32(1);
        cadena.admitir(post(id1, vec![t], slot1, 10)).unwrap();
        cadena.admitir(post(id2, vec![t], slot2, 10)).unwrap();
        (cadena, hash_u32(10 + n))
    }

    /// Ventana `n` con `cierre_ventana(n) = cierre` (el cierre siempre es par).
    fn ventana_para_cierre(cierre: u64) -> u64 {
        assert_eq!(cierre % 2, 0, "cierre debe ser par");
        cierre / 2 - 1
    }

    /// X4/J13 · cota del coste: (a) candidatos por debajo del horizonte → cero bloques visitados;
    /// (b) peor caso dentro del horizonte → visitas ≤ bloques del tramo `plazo_slots + F` más sus
    /// conjuntos de fusión; (c) el recuento no crece al doblar la cadena.
    #[test]
    fn j13_cota_de_visitas() {
        const PLAZO: u64 = 300;
        let terminal = hash_u32(1);

        // (a) cierre(300) = 602 ≥ slot(B₁) + F = 601: el paso 4 decide sin recorrer.
        let cadena = cadena_lineal(20);
        let x = hash_u32(30);
        cadena.reiniciar_visitas();
        let op_fuera = tx_evidencia(1, hash_u32(11), 300, hash_u32(12));
        assert_eq!(hecho(&cadena, terminal, x, &op_fuera), HechoVoto::SinFalta);
        assert_eq!(cadena.visitas(), 0, "(a) fuera del horizonte no recorre");

        // (b) peor caso dentro del horizonte: `slot(B₁) = slot(punta) − (plazo + F − 2)` y
        // `cierre(n₂) = slot(punta) − plazo`. El hermano no está aplicado antes de la punta, así que
        // `aplicado_antes_que` recorre el tramo entero antes de decidir `Inadmisible`.
        let n = 900u32;
        let slot_punta = u64::from(n);
        let cierre = slot_punta - PLAZO; // 600
        let n2 = ventana_para_cierre(cierre); // 299
        let slot_b = slot_punta - (PLAZO + ESPERA_REARRANQUE_SLOTS - 2); // 2
        let (cadena_b, punta_b) = cadena_con_hermanos(n, 3000, 3001, slot_b, slot_b + 1);
        cadena_b.reiniciar_visitas();
        let op_b = tx_evidencia(1, hash_u32(3000), n2, hash_u32(3001));
        assert_eq!(
            hecho(&cadena_b, terminal, punta_b, &op_b),
            HechoVoto::Inadmisible
        );
        let visitas_b = cadena_b.visitas();
        assert!(
            visitas_b >= PLAZO + ESPERA_REARRANQUE_SLOTS - 2,
            "(b) debe recorrer el tramo (visitas = {visitas_b})"
        );
        assert!(
            visitas_b <= PLAZO + ESPERA_REARRANQUE_SLOTS + 2,
            "(b) cota = bloques del tramo + conjuntos de fusión (visitas = {visitas_b})"
        );

        // (c) el doble de cadena, el mismo tramo y el mismo recuento.
        let n_c = 1800u32;
        let slot_punta_c = u64::from(n_c);
        let cierre_c = slot_punta_c - PLAZO; // 1500
        let n2_c = ventana_para_cierre(cierre_c); // 749
        let slot_b_c = slot_punta_c - (PLAZO + ESPERA_REARRANQUE_SLOTS - 2); // 902
        let (cadena_c, punta_c) = cadena_con_hermanos(n_c, 3100, 3101, slot_b_c, slot_b_c + 1);
        cadena_c.reiniciar_visitas();
        let op_c = tx_evidencia(1, hash_u32(3100), n2_c, hash_u32(3101));
        assert_eq!(
            hecho(&cadena_c, terminal, punta_c, &op_c),
            HechoVoto::Inadmisible
        );
        assert_eq!(
            cadena_c.visitas(),
            visitas_b,
            "(c) el recuento no depende de la longitud de la cadena"
        );
    }

    /// RD-4a · H1 · productor distinto por semilla, para la ventana con varios productores.
    fn productor_de(semilla: &[u8]) -> ClavePublica {
        let digest = zx_core::sha3_256_publico(semilla);
        let sk = ed25519_zebra::SigningKey::from(*digest.as_bytes());
        let vk = ed25519_zebra::VerificationKey::from(&sk);
        ClavePublica::desde_bytes(vk.into())
    }

    /// RD-4a · H1 · como [`post`], pero con un productor explícito.
    fn post_de(
        id: u32,
        padres: Vec<BlockHash>,
        slot: u64,
        sr: u64,
        productor: ClavePublica,
    ) -> BloqueCadena {
        let tx = tx_coinbase_post(productor, 1, slot);
        let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
            productor,
            0,
            u64::from(id) + 1,
            [(id & 0xff) as u8; 32],
            slot,
        ));
        BloqueCadena::Post(BloquePost {
            hash: hash_u32(id),
            padres,
            slot,
            timestamp: 0,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
            sr,
            distancia: 0,
            identidad,
            txs: vec![(tx, Vec::new())],
        })
    }

    /// RD-4a · H1 · cadena de `seq.len()` bloques PoST, el bloque `i` con `seq[i]`, sobre el mismo
    /// génesis PoW que [`cadena_base`]. `f_slots` fija la ventana de finalidad.
    fn cadena_de_productores_seq(seq: &[ClavePublica], f_slots: u64) -> Cadena {
        let mut cadena = Cadena::nueva(params(Some(f_slots)), K, CBID_RED_DEV, MAX_PADRES);
        cadena.admitir(genesis()).unwrap();
        cadena.admitir(pow_terminal(1, 1)).unwrap();
        let mut padre = hash_u32(1);
        for (i, productor) in seq.iter().enumerate() {
            let id = 10 + i as u32;
            let b = post_de(id, vec![padre], (i as u64) + 1, 10, *productor);
            cadena.admitir(b.clone()).unwrap();
            padre = b.hash();
        }
        cadena
    }

    /// RD-4a · H1 · adopta el ancla de votos en el bloque `id` y lo comprueba.
    fn anclar_en(cadena: &mut Cadena, id: u32) {
        let _ = cadena.considerar_ancla_de_estado(1, hash_u32(id));
        assert_eq!(
            cadena.ancla_votos(),
            Some((1, hash_u32(id))),
            "ancla adoptada"
        );
    }

    /// RD-4a · H1 · la suma de la tabla es el número de bloques recorridos y cada productor cuenta
    /// exactamente los suyos.
    #[test]
    fn productores_en_ventana_cuenta_por_productor() {
        let a = productor_de(b"rd4a-a");
        let b = productor_de(b"rd4a-b");
        let c = productor_de(b"rd4a-c");
        let productores = [a, b, c];
        // 12 bloques con 3 productores que rotan: 4 por productor.
        let seq: Vec<ClavePublica> = productores.iter().cycle().take(12).copied().collect();
        let mut cadena = cadena_de_productores_seq(&seq, 10);
        anclar_en(&mut cadena, 21); // último bloque (12.º, id 21)
        let tabla = cadena.productores_en_ventana(12);
        assert_eq!(tabla.get(&a), Some(&4));
        assert_eq!(tabla.get(&b), Some(&4));
        assert_eq!(tabla.get(&c), Some(&4));
        assert_eq!(tabla.values().sum::<u64>(), 12, "la suma es el recorrido");
    }

    /// RD-4a · H1 · **control R1**: un bloque **posterior al ancla** no entra en la tabla. Si la
    /// consulta partiese de la punta, contaría los 5 bloques de `b` y esta prueba caería.
    #[test]
    fn productores_en_ventana_solo_hasta_el_ancla() {
        let a = productor_de(b"rd4a-a");
        let b = productor_de(b"rd4a-b");
        // 10 bloques: los 5 primeros (id 10..14) de `a`; los 5 posteriores (id 15..19) de `b`.
        let mut seq = vec![a; 5];
        seq.extend(vec![b; 5]);
        let mut cadena = cadena_de_productores_seq(&seq, 10);
        anclar_en(&mut cadena, 14); // 5.º bloque, producido por `a`
        let tabla = cadena.productores_en_ventana(100);
        assert_eq!(tabla.get(&a), Some(&5), "solo los bloques hasta el ancla");
        assert!(
            !tabla.contains_key(&b),
            "los bloques posteriores al ancla no cuentan"
        );
        assert_eq!(tabla.values().sum::<u64>(), 5);
    }

    /// RD-4a · H1 · sin ancla de votos, la tabla es vacía aunque la cadena tenga bloques.
    #[test]
    fn productores_en_ventana_sin_ancla_es_vacia() {
        let a = productor_de(b"rd4a-a");
        let cadena = cadena_de_productores_seq(&[a; 5], 10);
        assert!(cadena.ancla_votos().is_none());
        assert!(cadena.productores_en_ventana(100).is_empty());
    }

    /// RD-4a · H1 · con `v` menor que la cadena, la suma es exactamente `v` (el tope manda).
    #[test]
    fn productores_en_ventana_respeta_el_tope() {
        let a = productor_de(b"rd4a-a");
        let b = productor_de(b"rd4a-b");
        let seq: Vec<ClavePublica> = (0..20).map(|i| if i % 2 == 0 { a } else { b }).collect();
        let mut cadena = cadena_de_productores_seq(&seq, 20);
        anclar_en(&mut cadena, 29); // último bloque (20.º, id 29)
        let tabla = cadena.productores_en_ventana(7);
        // Últimos 7 bloques (ids 23..29): i = id-10 ∈ {13..19}: impares `b` (4), pares `a` (3).
        assert_eq!(tabla.get(&a), Some(&3));
        assert_eq!(tabla.get(&b), Some(&4));
        assert_eq!(tabla.values().sum::<u64>(), 7, "el tope manda");
    }

    /// RD-4a · H1 · dos llamadas seguidas dan la misma tabla (idempotencia, sin estado).
    #[test]
    fn productores_en_ventana_es_idempotente() {
        let a = productor_de(b"rd4a-a");
        let b = productor_de(b"rd4a-b");
        let seq: Vec<ClavePublica> = (0..10).map(|i| if i % 3 == 0 { b } else { a }).collect();
        let mut cadena = cadena_de_productores_seq(&seq, 10);
        anclar_en(&mut cadena, 19); // último bloque (10.º, id 19)
        let primera = cadena.productores_en_ventana(10);
        let segunda = cadena.productores_en_ventana(10);
        assert_eq!(primera, segunda);
        assert_eq!(primera.values().sum::<u64>(), 10);
    }

    /// RD-4a · banco del §4. **`#[ignore]`**: 15 repeticiones por configuración, en `--release` y
    /// con `perf stat` en el bloque 0 (no corre en la suite normal).
    ///
    /// Configuración por entorno: `BANCO_N` (tamaños de cadena, por defecto `10000,50000,236250`)
    /// y `BANCO_P` (productores distintos, por defecto `4,64,4096`). Cada línea es una
    /// configuración; `med_ns` es la mediana de 15 repeticiones.
    #[test]
    #[ignore = "banco: se corre a mano en release, en el bloque 0 con perf stat"]
    fn banco_productores_en_ventana() {
        fn lista_env(nombre: &str, por_defecto: &str) -> Vec<u64> {
            std::env::var(nombre)
                .unwrap_or_else(|_| por_defecto.to_string())
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect()
        }
        fn rss_kb() -> u64 {
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            status
                .lines()
                .find_map(|l| l.strip_prefix("VmHWM:"))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        }
        for n in lista_env("BANCO_N", "10000,50000,236250") {
            for p in lista_env("BANCO_P", "4,64,4096") {
                let productores: Vec<ClavePublica> = (0..p)
                    .map(|i| productor_de(format!("rd4a-banco-{i}").as_bytes()))
                    .collect();
                let seq: Vec<ClavePublica> = productores
                    .iter()
                    .cycle()
                    .take(n as usize)
                    .copied()
                    .collect();
                // Fijar `F_slots` pequeño (no `n`): `admitir` recalcula finalidad por bloque y con
                // `F = n` saldría O(n²) en tiempo y memoria. La consulta no depende de `F`.
                let mut cadena = cadena_de_productores_seq(&seq, 10);
                anclar_en(&mut cadena, 10 + (n as u32) - 1);
                let _ = cadena.productores_en_ventana(n); // calentamiento (nunca se mide)
                let mut tiempos = Vec::with_capacity(15);
                let mut recorrido = 0u64;
                for _ in 0..15 {
                    let t0 = std::time::Instant::now();
                    let tabla = cadena.productores_en_ventana(n);
                    tiempos.push(t0.elapsed().as_nanos() as u64);
                    recorrido = tabla.values().sum::<u64>();
                }
                tiempos.sort_unstable();
                println!(
                    "BANCO n={n} p={p} reps=15 min_ns={} med_ns={} max_ns={} recorrido={recorrido} productores={} rss_kb={}",
                    tiempos.first().copied().unwrap_or(0),
                    tiempos.get(tiempos.len() / 2).copied().unwrap_or(0),
                    tiempos.last().copied().unwrap_or(0),
                    p,
                    rss_kb()
                );
            }
        }
    }
}
