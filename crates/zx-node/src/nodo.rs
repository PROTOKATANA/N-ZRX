//! Bucle de consenso: el único dueño de `zx-cadena` y `zx-storage` (decisión 3).
//!
//! Arranque limpio o reinicio (D-N03′), tubería de admisión única (decisión 4), fases PoW y PoST en
//! régimen (decisión 5, 6), resumen de estado (decisión 8) y registro estructurado (decisión 9).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use primitive_types::U256;
use subspace_core_primitives::PublicKey;
use zx_cadena::{BloqueCadena, BloquePost, Cadena, Eclipse, MotivoBloque};
use zx_consensus::genesis::{GENESIS_DEV, HASH_GENESIS_DEV, construir as construir_genesis};
use zx_consensus::sectores::{Etapa, SectorId};
use zx_consensus::transicion::votos::{
    CADUCIDAD_TABLA_VENTANAS, G_SLOTS_VOTOS, W_REVEAL_SLOTS_VOTOS, apertura_ventana,
    calendario_rearranque, cierre_ventana,
};
use zx_consensus::transicion::{
    BloqueTransicion, Estado as EstadoTransicion, HechosCabecera, Origen, ParametrosTransicion,
    Punto,
};
use zx_consensus::verificador::{ContextoPow, validar_cabecera_pow};
use zx_consensus::{PARAMETROS_POW_DEV, Sha3Dev};
use zx_core::digest::Digest;
use zx_core::preimage::block::BlockHeader;
use zx_core::wire::cuerpo_desde_bytes;
use zx_core::wire_dag::{BloqueDag, MAX_BUNDLES_POT, bloque_dag_desde_bytes};
use zx_core::{BlockHash, ExtensionTx, PadresDag, Red, Tx, TxId, trabajo_bloque, txid};
use zx_dag::ErrorDag;
use zx_dag::bloque_dag::{CandidatoSinRango, ContextoRangoDag};
use zx_farmer::farmer::{ParcelaDisco, plotear_sector_en_disco};
use zx_p2p::entrante::{IdDiferido, VeredictoFinal};
use zx_p2p::mensaje::{BloqueRed, Estado, Fase as FaseRed, PuntaPow};
use zx_poas::HistoriaGenesis;
#[cfg(test)]
use zx_post::producir_con_firmante;

use zx_post::cabecera_conjunta::{EstadoCabeceraConjunta, verificar_cabecera_conjunta};
use zx_post::pot_rango::{CachePotVerificada, InstantaneaPot, PresupuestoPot};
use zx_post::productor::{
    FuenteSoluciones, ParametrosProductor, ProductoFirmado, SolucionCandidata,
};
use zx_post::servicio_pot::ServicioPot;
use zx_storage::disco::AlmacenEnDisco;
use zx_storage::{Almacen, BloqueAdmitido, ErrorRepeticion, Familia};

use crate::claves::ClaveDev;
use crate::compendio::compendio_de_almacen;
use crate::cursor_votos::{CursorVotos, Movimiento, SalidaVerificada};
use crate::error::{ErrorNodo, ResultadoNodo};
use crate::estado_resumen::resumen_estado;
use crate::identidad::identidad_de_cabecera_post;
use crate::mempool::{Mempool, Politica};
use crate::padres::padres_de_regimen;
use crate::parada;
use crate::perfil;
use crate::pow;
use crate::red::huerfanos::DepositoHuerfanos;
use crate::red::vista::VistaRed;
use crate::red::{self, ManijaRed, ReceptorTrabajoRed, TrabajoRed};
use crate::regimen::{ClavePublicaConParcela, MsgBucle, MsgProductor, hilo_productor_regimen};
use crate::registro::Registro;
use crate::votos::{
    ConfigMotorVotos, EventoMotor, MotorVotos, RAIZ_ESTADO_CERO, RecepcionAgregado, RecepcionVoto,
    RecepcionVotoSubred, VistaCadena, deserializar_punto_control_peso, hex,
    verificar_punto_control_peso,
};
#[cfg(test)]
use zx_post::firmante::Firmante;
use zx_post::firmante::Registro as RegistroFirmante;
use zx_votos::agregacion::{AGREGADORES_POR_SUBRED, Agregado, Reparto, subred};

/// `SR_dev`/`ContextoRangoDag` constante del perfil dev (D-P11: sin controlador).
pub struct RangoDev(pub(crate) u64);

impl ContextoRangoDag for RangoDev {
    fn rango_esperado(&self, _candidato: &CandidatoSinRango<'_>) -> Result<u64, ErrorDag> {
        Ok(self.0)
    }
}

/// Presupuesto sin tope: el nodo dev no impone `C-NET-33` en un proceso propio y sin red.
struct PresupuestoIlimitado;

impl PresupuestoPot for PresupuestoIlimitado {
    fn consumir_slot(&mut self, _slot: u64) -> bool {
        true
    }
}

/// Configuración del nodo (decisión 10, CLI).
pub struct Config {
    /// Directorio de datos (almacén + parcelas).
    pub dir_datos: PathBuf,
    /// Ruta del registro estructurado.
    pub ruta_registro: PathBuf,
    /// Red configurada (decisión 2: debe ser `Red::Dev`).
    pub red: Red,
    /// Semilla de derivación de claves.
    pub semilla: u64,
    /// Índices de claves a derivar.
    pub indices_claves: Vec<u32>,
    /// `N_dev`.
    pub n_dev: u64,
    /// `SR_dev`.
    pub sr_dev: u64,
    /// RL-2c: perfil de **red** (reloj por ticks, segundo VDF y reglas de timestamp PoST). Es una
    /// propiedad de la red, igual para todos sus nodos; sustituye a la bandera `--reloj-dev`.
    pub perfil_red: crate::perfil::PerfilRedConsenso,
    /// Parada tras N slots de régimen (`None` = sin límite).
    pub parada_tras_slots: Option<u64>,
    /// `ORDEN-W06d6` decisión 6: desde este slot el nodo deja de **producir**, pero sigue
    /// validando, propagando y sincronizando. `None` = nunca deja de producir por esta vía.
    pub dejar_de_producir_en_slot: Option<u64>,
    /// FV-4b-N1 · Punto de control externo (V-3 A): fichero con un certificado `C_n` y su tabla
    /// `T_n`. Si está, el nodo nuevo arranca la finalidad por votos desde ahí.
    pub punto_control: Option<PathBuf>,
    /// FV-4b-N3 · interruptor dev: el nodo **no** emite ni difunde votos (`--sin-voto`), pero sí
    /// revela el sorteo al cerrar la ventana (nodo «revela sin votar» del humo).
    pub sin_voto: bool,
    /// FV-4b-N3 · interruptor dev: el nodo **no** publica la revelación obligatoria
    /// (`--sin-revelacion`), quedando suspendido (nodo «en silencio» del humo).
    pub sin_revelacion: bool,
}

// AUS-2c · contadores **solo de prueba** de las dos cifras de la pregunta falsable. Son
// `thread_local!` porque `cargo test` corre las pruebas en paralelo en el mismo proceso: cada hilo
// cuenta lo suyo y ninguna prueba contamina a otra.
#[cfg(test)]
thread_local! {
    /// Intentos de difusión de una tx propia (C3).
    pub(crate) static DIFUSIONES_TX_PROPIAS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// RA-2 · R6.1 · llamadas a `Cadena::estado_virtual()` desde
    /// `Nodo::reconciliar_ancla_de_bloque` en modo peso: solo deben contarse cuando el bloque trae
    /// algún `0x09`.
    static ESTADO_VIRTUAL_RECONCILIACION: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    /// RN-1 · S1 · llamadas a `Cadena::estado_virtual()` desde `Nodo::renovar_sectores_propios`.
    /// Debe ser 0 en vueltas sin cambio de slot (una sola evaluación por slot).
    static ESTADO_VIRTUAL_RENOVACION: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    /// RD-4b · P1 · consultas a `Cadena::productores_en_ventana` (para probar que sin red o con el
    /// registro apagado la consulta **no se ejecuta**).
    pub(crate) static CONSULTAS_TABLA_PESOS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// A5-c-2b · intentos de difusión de un voto de red por su subred.
    pub(crate) static DIFUSIONES_VOTO_SUBRED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// A5-c-2b · intentos de difusión de un agregado propio.
    pub(crate) static DIFUSIONES_AGREGADO: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// A5-c-2b · llamadas a `MotorVotos::recibir_agregados` (para probar el lote único por vuelta).
    static LOTES_AGREGADOS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Estado completo del nodo, dueño único de `zx-cadena` y `zx-storage`.
pub struct Nodo {
    params: ParametrosTransicion,
    cadena: Cadena,
    almacen: AlmacenEnDisco,
    /// Registro estructurado compartido (`ORDEN-W07a`): el hilo de consenso y la tarea de red
    /// escriben en él (el `Mutex` interno serializa cada línea).
    registro: Arc<Registro>,
    /// `ORDEN-SL4b2` decisión 2: registro durable del firmante seguro (`C-EVP-06`, FIR-01…FIR-15),
    /// único por nodo (compartido entre todas sus claves: la identidad RAT-1 ya incluye
    /// `public_key`). `None` hasta que `arranque_limpio`/`reiniciar` lo abre; `fase_regimen` es lo
    /// único que lo usa y corre siempre después de que uno de los dos se haya ejecutado.
    registro_firmante: Option<Arc<RegistroFirmante>>,
    /// `ORDEN-SL4b2` decisiones 3/4: detector de doble firma y lista de `EvidenceTx` pendientes de
    /// incluir. En memoria, no persiste entre reinicios (declarado en `DEFINICIONES-FALTANTES.md`).
    detector: crate::evidencia::DetectorDobleFirma,
    claves: Vec<ClaveDev>,
    cbid: u32,
    /// Cadena de cabeceras `[0..=altura]` de la punta PoW **seleccionada** (mayor trabajo
    /// acumulado, `ORDEN-W06d3` decisión 3): la reconstruye [`Nodo::actualizar_seleccion_pow`] cada
    /// vez que cambia. No es "todo lo que se ha visto": para eso está [`Self::headers_pow`].
    historial_pow: Vec<BlockHeader>,
    /// Todas las cabeceras PoW conocidas y válidas, indexadas por hash, de cualquier rama
    /// (`ORDEN-W06d3` decisión 3): permite reconstruir el historial de **cualquier** punta con
    /// `Nodo::historial_hasta`, no solo el de la rama seleccionada hoy.
    headers_pow: BTreeMap<BlockHash, BlockHeader>,
    /// Un `ServicioPot` de verificación **por terminal candidato** (`ORDEN-W06d7` decisión 5: ya no
    /// hay uno solo, porque puede haber varios terminales con DAG a la vez). Se crea en cuanto
    /// `zx-cadena` reconoce el candidato ([`Nodo::asegurar_servicios_verificacion`]), antes incluso
    /// de que tenga DAG propio (el bloque de transición de ese terminal necesita el servicio para
    /// verificarse, y todavía no hay DAG en ese punto).
    servicios_verificacion: BTreeMap<BlockHash, ServicioPot>,
    historia: Arc<HistoriaGenesis>,
    ultima_punta_registrada: Option<BlockHash>,
    dir_datos: PathBuf,
    n_dev: u64,
    sr_dev_actual: u64,
    /// RL-2c: perfil de red (reloj por ticks, segundo VDF y timestamps PoST). Si
    /// `perfil_red.reloj_activo`, el PoT usa `N(s) = T(s)·n_iter` desde el génesis.
    perfil_red: crate::perfil::PerfilRedConsenso,
    parada_tras_slots: Option<u64>,
    /// `ORDEN-W06d6` decisión 6.
    dejar_de_producir_en_slot: Option<u64>,
    /// Trabajo PoW acumulado de la cadena admitida (para el saludo de red, decisión 4).
    trabajo_acumulado: U256,
    /// Red configurada (`ORDEN-W06d2` lo necesita en cada saludo).
    red_configurada: Red,
    /// Instantánea de solo lectura que sirve el saludo y la sincronización (`ORDEN-W06d2`).
    /// Existe siempre, con o sin red: así no hay dos caminos de construcción de `Nodo`.
    vista_red: Arc<VistaRed>,
    /// Depósito acotado de bloques huérfanos (decisión 3).
    huerfanos: DepositoHuerfanos,
    /// El handle hacia la red, si [`Self::conectar_red`] se llamó. `None` reproduce exactamente el
    /// comportamiento de `ORDEN-W06d1`: un nodo sin red.
    red: Option<ManijaRed>,
    /// Cola de trabajo que el manejador de red encola y este hilo drena (decisión 1).
    trabajo_red: Option<ReceptorTrabajoRed>,
    /// RD-4b · P1: último empuje de la tabla de pesos al director (ancla y momento). `None` hasta
    /// el primer empuje.
    ultimo_empuje_pesos: Option<UltimoEmpujePesos>,
    /// Mempool de transacciones compartida con el manejador de red (`ORDEN-TX3`). El hilo de
    /// consenso la rebasa al cambiar la punta; el bucle de red la consulta para validar antes de
    /// reenviar (C-NET-12).
    mempool: Arc<std::sync::Mutex<Mempool>>,
    /// FV-4b-N1 · motor de finalidad por votos. `Some` solo en `Red::Dev` (la capa no arranca sin
    /// fuente de peso con prueba fuera de dev, FV-D08); vive en este hilo de consenso.
    motor_votos: Option<MotorVotos>,
    /// VNT-R1 · cursor monotónico del tiempo PoT **verificado en local**. Lo alimentan las
    /// admisiones completas (bloques propios, de red y pendientes reintentados) y las salidas del
    /// hilo PoT sin ganadora; `slot_votos` lo lee como fuente primaria. No mueve consenso.
    cursor_votos: Option<CursorVotos>,
    /// VNT-1b · D4 · último intervalo `(primera, última)` de fronteras ya trazado por
    /// `registrar_intervalo_fronteras`, para no repetir la traza en cada intento mientras el motor
    /// sigue sin abrir. Solo cambia cuando cambia el intervalo pendiente.
    ultimo_intervalo_fronteras_votos: Option<(u64, u64)>,
    /// VNT-1b · D4 · contador **solo de prueba** de trazas de intervalo emitidas: permite afirmar
    /// «una traza por intervalo» sin depender del sumidero de `tracing`.
    #[cfg(test)]
    trazas_intervalo_fronteras: u32,
    /// VNT-1b · D2 · contador **solo de prueba** de entradas al motor de votos: permite afirmar que
    /// con el eclipse enclavado ningún camino llega a `procesar_votos`.
    #[cfg(test)]
    procesar_votos_llamadas: u32,
    /// FV-4b-N3 · txs v6 `0x06`/`0x07` (compromiso y revelación) firmadas y listas para incluir en
    /// el siguiente bloque propio, con el slot a partir del cual son admisibles (`0` = ya).
    /// FV-4b-N3-2 · persistentes hasta observarlas aplicadas o vencidas, y también las ajenas que
    /// llegan por gossip (drenadas de la mempool con prioridad).
    v6_pendientes: Vec<PendienteV6>,
    /// EV-1 · recogida de resultados de red una vez por apertura, nunca por vuelta del bucle.
    ventana_retiradas_evidencia: Option<u64>,
    /// AUS-2c · K1 · `votantes_voto` del estado **aplicado** de la última ventana abierta por
    /// [`Nodo::procesar_votos`] (el mismo `estado_past` que usa la apertura). Con él se decide «mi
    /// voto ya consta» sin volver a consultar `estado_virtual()` en cada vuelta. `None` hasta la
    /// primera apertura.
    votantes_voto_ventana: Option<BTreeMap<u64, BTreeSet<zx_core::ClavePublica>>>,
    /// VS-2 · V5 · pares `(ventana, firmante)` de actas `0x0A` ya observadas aplicadas. Permite
    /// etiquetar `en_acta` (y no `en_certificado`) el descarte de un voto propio.
    actas_aplicadas: BTreeSet<(u64, zx_core::ClavePublica)>,
    /// ECL-R2a · Instante del último aviso `eclipse_detectado` (cada 60 s).
    eclipse_ultimo_aviso: Option<Instant>,
    /// ECL-R2a · `true` si ya se escribió el fichero de recuperación del eclipse.
    eclipse_recuperacion_escrita: bool,
    /// ECL-R2a · `true` si ya se emitió `ancla_pendiente`.
    ancla_pendiente_emitida: bool,
    /// ECL-R2a-2/3 · D5 · último par `(candidato, par)` para el que ya se pidió el bloque por sync.
    ancla_pendiente_solicitada: Option<(BlockHash, libp2p::PeerId)>,
    /// ECL-R2a-2 · D5 · último par del que llegó un bloque, para pedirle el candidato del ancla que
    /// falta (mismo `Peticion::Bloques` que usa la sincronización de huérfanos).
    par_sync: Option<libp2p::PeerId>,
    /// PD-1f · F1 · Copia **reducida** del estado seleccionado que solo lleva los campos que lee
    /// `zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo` (ver
    /// [`estado_reducido_para_peso`]). Se usa para verificar un `0x09` suelto sin tocar el estado
    /// canónico ni pagar el clon completo (sin `utxo`, etc.).
    estado_verificacion_peso: Option<zx_consensus::transicion::Estado>,
    /// PD-1f · F1 · `(finalidad_votos_n, finalidad_votos)` del estado seleccionado con el que se
    /// construyó `estado_verificacion_peso`. Cuando la finalidad seleccionada avanza, la copia se
    /// rehace. `None` = nunca construida.
    base_verificacion_peso: Option<(u64, Option<BlockHash>)>,
    /// PD-1f · F3 · txs `0x09` retenidas por llegar fuera de orden (clave = ventana `n`), con los
    /// **mismos topes** que [`Self::pasos_ancla_pendientes`]. Se reintentan cuando avanza el estado
    /// de verificación.
    pasos_peso_pendientes: BTreeMap<u64, Tx>,
    /// RN-1 · S1/S2/S3 · renovación en vuelo por clave propia (S2: como mucho una por clave). Vive en
    /// memoria; un reinicio la pierde y el estado seleccionado vuelve a decidir.
    renovaciones_propias: BTreeMap<zx_core::ClavePublica, RenovacionEnVuelo>,
    /// RN-1 · S1 · último slot para el que se evaluó [`Self::renovar_sectores_propios`]. La
    /// renovación se evalúa **una vez por cambio de slot**, no en cada vuelta del bucle.
    ultimo_slot_renovacion: Option<u64>,
    /// Bloques de red **pendientes** (no inválidos) en su cola por familia. La pieza N
    /// ([`crate::pendientes`]) guarda cada bloque con su hash, su llegada y por qué espera; no
    /// admite duplicados y desaloja al más antiguo al llegar a su tope. Los PoST esperan contexto
    /// (`Pot(PasadoIncompleto)` mientras este nodo sincroniza fuera de orden) o solo el límite de
    /// futuro; los PoW solo el límite de futuro (RLJ-3b §2.4). El disparador por reloj
    /// ([`Self::reintentar_pendientes_por_reloj`]) reintenta los vencidos en cada vuelta del bucle;
    /// [`Self::reintentar_post_pendientes`] reintenta los de contexto al avanzar el pasado. Nunca
    /// se cachean como inválidos ni penalizan al remitente.
    post_pendientes: crate::pendientes::Pendientes<BloqueDag>,
    /// Cola propia del PoW diferido por `FTL` (RLJ-3b §2.4): no se mezcla con `headers_pow` ni con
    /// `post_pendientes`.
    pow_pendientes: crate::pendientes::Pendientes<BloqueRed>,
    /// `ORDEN-SR1-2` / `REVISION-FIN1.md` límite 2: pares `(finalidad, bloque)` de
    /// [`Cadena::violaciones_finalidad`] ya escritos al registro, para no repetir el evento.
    violaciones_emitidas: BTreeSet<(BlockHash, BlockHash)>,
    /// `ORDEN-W07a`: modo del arranque (`true` = limpio, `false` = reinicio), para el evento
    /// `arranque`, que se emite al empezar `ejecutar` (cuando ya se conoce, si la hay, la red).
    modo_limpio: bool,
    /// FV-N6-C7 · última clasificación `(reloj_n, certificado_n)` avisada como espera/hueco, para
    /// no repetir el evento en cada tick mientras el estado no cambia.
    votos_aviso: Option<(u64, u64)>,
    /// FV-N6-C7-3 · `(n, candidato)` del `C_n` **aplicado** con el que se sembró/reconcilió el
    /// motor de votos, para detectar un cambio pertinente de selección/admisión antes de la
    /// primera apertura y no resembrar por repetir el mismo contexto.
    votos_carga_aplicada: Option<(u64, BlockHash)>,
    /// FV-N6-C7-3 · última punta seleccionada observada por la reconciliación preprimera-apertura;
    /// FV-N6-C7-3 · `true` si la carga inicial vigente vino de un `--punto-control` **explícito**
    /// del operador: la reconciliación preprimera-apertura no la sustituye (se conserva la
    /// confianza explícita).
    votos_carga_externa: bool,
    /// `ORDEN-W07a`: `PeerId` de libp2p del nodo, si hay red (para `arranque`).
    peer_id: Option<String>,
    /// `ORDEN-W07a`: dirección donde escucha el nodo, si hay red (para `arranque`).
    red_escuchar: Option<String>,
    /// `ORDEN-W07a`: desglose de la última admisión (etapas envueltas con `Instant`), para el
    /// `bloque_red_admitido`/`bloque_red_rechazado`.
    medicion: Medicion,
    /// `ORDEN-W07a`: cadena seleccionada en el último `cambio_punta`, para calcular
    /// `profundidad_reorg` sin tocar `zx-cadena`. `ultima_cadena_indice` es su índice por hash
    /// (evita reconstruirlo en cada cambio de punta).
    ultima_cadena_seleccionada: Vec<BlockHash>,
    /// Índice `hash -> posición` de [`Self::ultima_cadena_seleccionada`].
    ultima_cadena_indice: BTreeMap<BlockHash, usize>,
    /// RLJ-3a-2 · caché en memoria del ancla diagnóstica ([`CacheAnclaDiagnostico`]); ver
    /// [`Self::ancla_diagnostica`]. No es almacén.
    ancla_diagnostico: std::cell::RefCell<CacheAnclaDiagnostico>,
    /// TX-6: instante del próximo evento periódico `mempool` (bytes, transacciones y rechazos por
    /// tope). `None` hasta el primer bucle, que lo emite de inmediato.
    proximo_muestreo: Option<Instant>,
    /// A1-D2b · W1–W3 · almacén de raíces de estado por época, calculadas en segundo plano por el
    /// nodo que vota. La vista que recibe el motor lee de aquí.
    raices: crate::raiz_punto::RaicesPunto,
    /// A1-D2b · ¿este nodo emite votos? Si no, no solicita ni recoge cálculos y su vista entrega
    /// cero (W4). Es `!cfg.sin_voto` **y** con el diario durable vinculado (si el motor quedó en
    /// observación tampoco firma).
    vota: bool,
    /// A5-c-2b · X2/X7 · claves BLS públicas propias (bytes), para suscribirse a sus subredes de
    /// voto y para fijar el cupo de agregación con la tabla abierta.
    claves_bls_propias: Vec<Vec<u8>>,
    /// A5-c-2b · X8 · contadores de la ventana abierta para `agregacion_ventana`.
    agn: ContadoresAgregacion,
    /// A5-c-2c · N2 · B-83 · ¿ya se escribió, al arrancar, el aviso
    /// `azar_del_sistema_no_disponible`? Se escribe **una sola vez**.
    aviso_sin_azar_escrito: bool,
    /// A1-D2b · W5 · épocas con un cálculo solicitado, con su punto y el instante de la solicitud
    /// (el cronómetro del nodo que alimenta `raiz_estado_calculada`).
    raices_solicitadas: BTreeMap<u64, (BlockHash, Instant)>,
    /// A1-D2b · W3 · pares `(ventana, punto)` ya avisados con `raiz_estado_no_lista`; no se repite
    /// la línea en los reintentos de apertura. Se poda con las épocas.
    raiz_no_lista_avisadas: BTreeSet<(u64, BlockHash)>,
    /// `ORDEN-W06d10-B`, **solo en tests**: fallo **local** inyectado (persistencia/servicio) para
    /// poder demostrar que el borde de red lo trata como `Ignorar` y lo registra, sin depender de
    /// romper de verdad el disco. Nunca existe en el binario de producción.
    #[cfg(test)]
    fallo_local_simulado: Option<String>,
    /// `ORDEN-W06d10-B`, **solo en tests**: reloj local inyectado, para poder demostrar que X1
    /// (timestamp futuro, C-TS-03) se difiere sin cachearse y se admite cuando el reloj avanza, sin
    /// depender del reloj real de la máquina. Nunca existe en el binario de producción.
    #[cfg(test)]
    reloj_local_simulado: Option<i64>,
    /// ECL-R2a-2, **solo en tests**: salta la verificación PoAS (que exige una prueba de espacio
    /// real) para poder ejercitar la ruta real de `admitir_post_interno` con un bloque que la
    /// cadena rechaza por `F`. Nunca existe en el binario de producción.
    #[cfg(test)]
    poas_simulada: bool,
    /// FV-N6-C7-3, **solo en tests**: slot PoT inyectado para `slot_votos`, de modo que un test
    /// pueda situar el reloj de instancias en `n` sin producir bloques PoST reales.
    #[cfg(test)]
    slot_votos_simulado: Option<u64>,
    /// FV-N6-C7-3, **solo en tests**: candidato inyectado para `procesar_votos` cuando el Nodo de
    /// prueba aún no tiene una punta seleccionable (sin bloques PoST).
    #[cfg(test)]
    candidato_votos_simulado: Option<BlockHash>,
}

/// Margen histórico de TX3-2, conservado solo para reproducir el relleno de CAR-PROD.
/// PROD-1 mide en producción la coinbase v3 con el códec real.
#[cfg(test)]
const MARGEN_COINBASE_POST: u64 = 512;

/// `ORDEN-SL4b2` decisión 1: puerta RAT-3, factorizada de [`Nodo::arrancar`] para poder probarla
/// con un perfil que la incumple sin tener que construir un nodo entero (disco, génesis, parcelas).
fn comprobar_puerta_rat3(
    r_slots: u64,
    evidencia: &zx_consensus::transicion::ParametrosEvidencia,
) -> ResultadoNodo<()> {
    if perfil::puerta_rat3(r_slots, evidencia) {
        Ok(())
    } else {
        Err(ErrorNodo::PuertaRat3Incumplida {
            r_slots,
            plazo_mas_margen: evidencia.plazo_slots + evidencia.m_margen_slots,
        })
    }
}

/// FV-4b-N4 · R-ECL-05: puerta `R_slots >= V_slots + Plazo_voto + M_margen_voto`, factorizada de
/// [`Nodo::arrancar`] para poder probarla sin construir un nodo entero.
fn comprobar_puerta_recl05(
    r_slots: u64,
    t_inst: u64,
    plazo_voto_slots: u64,
    m_margen_voto_slots: u64,
) -> ResultadoNodo<()> {
    let v_slots = perfil::ventana_voto_slots(perfil::LOOKBACK_VOTOS_DEV, t_inst);
    if perfil::puerta_recl05(r_slots, v_slots, plazo_voto_slots, m_margen_voto_slots) {
        Ok(())
    } else {
        Err(ErrorNodo::PuertaRecl05Incumplida {
            r_slots,
            v_slots,
            plazos: plazo_voto_slots.saturating_add(m_margen_voto_slots),
        })
    }
}

impl Nodo {
    /// Arranca el nodo: comprueba la red **antes** de abrir disco o parcelas (decisión 2), abre (o
    /// crea) el almacén y repite su registro sobre una `Cadena` nueva si no está vacío (D-N03′).
    ///
    /// # Errores
    /// [`ErrorNodo::RedNoEsDev`] si `cfg.red != Red::Dev`; el resto de variantes según la fase.
    pub fn arrancar(cfg: &Config) -> ResultadoNodo<Self> {
        if cfg.red != Red::Dev {
            return Err(ErrorNodo::RedNoEsDev {
                encontrada: cfg.red,
            });
        }
        std::fs::create_dir_all(&cfg.dir_datos)?;
        let registro = Arc::new(Registro::abrir(&cfg.ruta_registro)?);

        let params = perfil::parametros_transicion_dev()?;
        let cbid = zx_core::CBID_RED_DEV;
        // `ORDEN-SL4b2` decisión 1: puerta RAT-3, comprobada **antes** de tocar disco (mismo
        // espíritu que la comprobación de `Red::Dev` de arriba, decisión 2 de `ORDEN-W06d1`). Un
        // perfil que la incumple no arranca, con el mensaje exacto en el error.
        let evidencia = perfil::parametros_evidencia_dev();
        comprobar_puerta_rat3(params.r_slots, &evidencia)?;
        // FV-4b-N4 · R-ECL-05: la retención de la garantía debe cubrir la ventana de voto más su
        // plazo y margen; si no, el nodo se niega a arrancar (misma filosofía que RAT-3).
        comprobar_puerta_recl05(
            params.r_slots,
            perfil::parametros_votos_dev().t_inst,
            evidencia.plazo_slots,
            evidencia.m_margen_slots,
        )?;
        let (cabecera_genesis, tx_genesis) = construir_genesis(GENESIS_DEV)?;
        let hash_genesis_esperado = BlockHash::from_digest(Digest::from_bytes(HASH_GENESIS_DEV));
        if cabecera_genesis.block_hash() != hash_genesis_esperado {
            return Err(ErrorNodo::GenesisDiscrepante {
                encontrado: cabecera_genesis.block_hash(),
                esperado: hash_genesis_esperado,
            });
        }

        let ruta_almacen = cfg.dir_datos.join("storage");
        let almacen =
            AlmacenEnDisco::abrir(&ruta_almacen, Red::Dev, cabecera_genesis.block_hash())?;
        let claves = ClaveDev::derivar_varias(cfg.semilla, &cfg.indices_claves);
        let historia = Arc::new(HistoriaGenesis::construir()?);

        let identidad_red = perfil::identidad_red(&cfg.perfil_red);
        let estado_inicial = Estado {
            hash_genesis: identidad_red,
            red: cfg.red,
            fase: FaseRed::Pow,
            punta_pow: PuntaPow {
                hash: hash_genesis_esperado,
                altura: 0,
                trabajo_acumulado: [0; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [0; 32],
            longitud_registro: 0,
        };

        let mut nodo = Self {
            params,
            // `ORDEN-SL4b2` decisión 1: `nueva_con_evidencia`, con el perfil de evidencia dev
            // (`f = 1/1`, `Plazo_slots = 300`, `M_margen_slots = 60`, `cbid`, activa) ya validado
            // por la puerta RAT-3 de arriba.
            cadena: Cadena::nueva_con_evidencia(
                perfil::parametros_transicion_dev()?,
                perfil::ghostdag_k(),
                cbid,
                perfil::ghostdag_max_padres(),
                evidencia,
            ),
            almacen,
            registro,
            registro_firmante: None,
            detector: crate::evidencia::DetectorDobleFirma::nuevo(perfil::MAX_IDENTIDADES_DETECTOR),
            claves,
            cbid,
            historial_pow: Vec::new(),
            headers_pow: BTreeMap::new(),
            servicios_verificacion: BTreeMap::new(),
            historia,
            ultima_punta_registrada: None,
            dir_datos: cfg.dir_datos.clone(),
            n_dev: cfg.n_dev,
            sr_dev_actual: cfg.sr_dev,
            perfil_red: cfg.perfil_red,
            parada_tras_slots: cfg.parada_tras_slots,
            dejar_de_producir_en_slot: cfg.dejar_de_producir_en_slot,
            trabajo_acumulado: U256::zero(),
            red_configurada: cfg.red,
            vista_red: Arc::new(VistaRed::nueva(estado_inicial)),
            huerfanos: red::nuevo_deposito_huerfanos(),
            red: None,
            trabajo_red: None,
            ultimo_empuje_pesos: None,
            mempool: Arc::new(std::sync::Mutex::new(Mempool::nueva(
                params,
                evidencia,
                cbid,
                EstadoTransicion::inicial(),
                Politica::dev(),
            ))),
            motor_votos: None,
            cursor_votos: None,
            ultimo_intervalo_fronteras_votos: None,
            #[cfg(test)]
            trazas_intervalo_fronteras: 0,
            #[cfg(test)]
            procesar_votos_llamadas: 0,
            v6_pendientes: Vec::new(),
            ventana_retiradas_evidencia: None,
            votantes_voto_ventana: None,
            actas_aplicadas: BTreeSet::new(),
            eclipse_ultimo_aviso: None,
            eclipse_recuperacion_escrita: false,
            ancla_pendiente_emitida: false,
            ancla_pendiente_solicitada: None,
            par_sync: None,
            estado_verificacion_peso: None,
            base_verificacion_peso: None,
            pasos_peso_pendientes: BTreeMap::new(),
            renovaciones_propias: BTreeMap::new(),
            ultimo_slot_renovacion: None,
            post_pendientes: crate::pendientes::Pendientes::nuevo(TOPE_POST_PENDIENTES),
            pow_pendientes: crate::pendientes::Pendientes::nuevo(TOPE_POW_PENDIENTES),
            violaciones_emitidas: BTreeSet::new(),
            modo_limpio: false,
            votos_aviso: None,
            votos_carga_aplicada: None,
            votos_carga_externa: false,
            peer_id: None,
            red_escuchar: None,
            medicion: Medicion::default(),
            ultima_cadena_seleccionada: Vec::new(),
            ultima_cadena_indice: BTreeMap::new(),
            ancla_diagnostico: std::cell::RefCell::new(CacheAnclaDiagnostico::default()),
            proximo_muestreo: None,
            raices: crate::raiz_punto::RaicesPunto::nuevo(zx_estado::canon::raiz_de_estado),
            vota: false,
            claves_bls_propias: Vec::new(),
            agn: ContadoresAgregacion::default(),
            aviso_sin_azar_escrito: false,
            raices_solicitadas: BTreeMap::new(),
            raiz_no_lista_avisadas: BTreeSet::new(),
            #[cfg(test)]
            fallo_local_simulado: None,
            #[cfg(test)]
            reloj_local_simulado: None,
            #[cfg(test)]
            poas_simulada: false,
            #[cfg(test)]
            slot_votos_simulado: None,
            #[cfg(test)]
            candidato_votos_simulado: None,
        };

        let longitud = nodo.almacen.longitud_registro()?;
        nodo.modo_limpio = longitud == 0;
        if longitud == 0 {
            nodo.arranque_limpio(cabecera_genesis, tx_genesis)?;
        } else {
            nodo.reiniciar(longitud)?;
        }
        nodo.rebasear_mempool();
        nodo.iniciar_votos(cfg)?;
        // A1-D2b · W4 · el nodo calcula raíces solo si el motor emite votos de verdad: ni con
        // `--sin-voto` ni en observación (diario no vinculado).
        nodo.vota = !cfg.sin_voto && nodo.motor_votos.as_ref().is_some_and(|m| m.tiene_diario());
        // A5-c-2c · N1 · B-71/B-74 · el motor vigila **las mismas** subredes a las que el nodo se
        // suscribe (`subredes_propias`); el que no emite votos va con la lista vacía. Se hace una
        // sola vez, ya con `vota` fijado y antes de cualquier `avanzar`/`recibir`.
        let vigiladas: Vec<u16> = nodo.subredes_propias().into_iter().map(u16::from).collect();
        if let Some(motor) = nodo.motor_votos.as_mut() {
            motor.fijar_subredes_vigiladas(&vigiladas);
        }
        // A5-c-2c · N2 · B-83 · el aviso de «sin azar del sistema» llega al registro una sola vez.
        nodo.avisar_sin_azar_del_sistema();
        Ok(nodo)
    }

    /// Fase PoW: mina hasta fijar el terminal, con un depósito por clave madura en cada altura que
    /// lo permita (decisión 5). Devuelve cuando `Cadena` fija el terminal.
    ///
    /// # Errores
    /// [`ErrorNodo::BloquePropioRechazado`] con `clasificacion` interna (`ORDEN-W06d5` decisión 3, `crate::rechazo`); un rechazo legítimo se descarta y no llega a devolverse.
    fn fase_pow(&mut self) -> ResultadoNodo<()> {
        if self.cadena.terminal().is_some() {
            return Ok(());
        }
        let (tx_trabajo, rx_trabajo) = mpsc::channel::<pow::TrabajoMinero>();
        let (tx_minado, rx_minado) = mpsc::channel::<BlockHeader>();
        let hilo = thread::spawn(move || pow::hilo_minero(rx_trabajo, tx_minado));

        loop {
            // TX-6: muestra periódica de la mempool (bytes, transacciones y rechazos por tope).
            self.muestrear_mempool_si_toca();
            // `ORDEN-W07d` decisión 2: parada ordenada por señal. Se cierra el canal del minero (el
            // hilo termina tras su búsqueda en curso) y se sale para que `ejecutar` escriba `parada`.
            if parada::hay_solicitud() {
                drop(tx_trabajo);
                drop(hilo);
                return Ok(());
            }
            #[expect(
                clippy::indexing_slicing,
                reason = "historial_pow siempre tiene al menos el génesis"
            )]
            let ultimo = self.historial_pow[self.historial_pow.len() - 1];
            let altura = ultimo
                .height
                .checked_add(1)
                .ok_or_else(|| ErrorNodo::Otro("altura PoW desbordada".to_string()))?;
            let ahora = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let timestamp = ahora.max(ultimo.timestamp.saturating_add(1));
            // C-TS-01 exige `ts > ts_padre` (permanente); con la dificultad inicial dev y el
            // binario en release, minar un bloque tarda mucho menos de 1 s, así que el reloj de
            // pared se queda atrás del `timestamp` mínimo exigible. Sin esta espera, el propio
            // bloque violaría C-TS-03 (`ts > reloj_local + FTL`) al admitirse: un rechazo fatal
            // (decisión 4) por una condición que el nodo mismo puede evitar, no un fallo del motor.
            if timestamp > ahora {
                std::thread::sleep(std::time::Duration::from_secs(timestamp - ahora));
            }
            let propios = self.preparar_depositos(altura)?;
            // `ORDEN-TX3` §2.6: los depósitos propios entran en la mempool (ya no hay una cola
            // aparte) y la plantilla se arma **seleccionando de la mempool** (TX-R-27/28/46).
            let mut a_difundir: Vec<Vec<u8>> = Vec::new();
            let depositos = {
                let ahora = Instant::now();
                let punto = Punto::Altura(altura);
                let semilla = u64::from(altura).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                let mut m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
                for (tx, tst) in propios {
                    if m.admitir(None, tx.clone(), tst.clone(), ahora, punto)
                        .is_ok()
                    {
                        // TX-R-01: la transacción propia también se difunde por el tema de tx.
                        let mut buf = Vec::new();
                        zx_core::wire::tx_a_bytes(&mut buf, &tx, &tst);
                        a_difundir.push(buf);
                    }
                }
                m.expirar(punto);
                m.seleccionar(self.params.max_cuerpo_bloque_bytes, semilla)
            };
            for bytes in a_difundir {
                let _ = self.difundir_tx_si_hay_red(&bytes);
            }
            #[expect(
                clippy::indexing_slicing,
                reason = "claves nunca está vacía: la CLI exige al menos un índice"
            )]
            let clave_de_este_bloque = self.claves[(altura as usize) % self.claves.len()].pk;
            let (plantilla, _txid_cb, _valor_cb) = pow::construir_plantilla(
                &self.historial_pow,
                ultimo.block_hash(),
                altura,
                timestamp,
                self.cbid,
                clave_de_este_bloque,
                depositos,
                self.params.max_cuerpo_bloque_bytes,
            )?;
            let txs = plantilla.txs.clone();
            let testigos = plantilla.testigos.clone();
            let trabajo = pow::TrabajoMinero::from(&plantilla);
            if tx_trabajo.send(trabajo).is_err() {
                return Err(ErrorNodo::Otro(
                    "el hilo minero terminó inesperadamente".to_string(),
                ));
            }
            // `ORDEN-W07d` decisión 2: `recv_timeout` en vez de `recv` para atender la señal
            // mientras el minero busca trabajo; un timeout no es una desconexión, solo se vuelve a
            // esperar. No cambia ninguna decisión del nodo.
            let cabecera_minada = loop {
                match rx_minado.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(cabecera) => break cabecera,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if parada::hay_solicitud() {
                            drop(tx_trabajo);
                            drop(hilo);
                            return Ok(());
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(ErrorNodo::Otro("el hilo minero cerró el canal".to_string()));
                    }
                }
            };
            // Se drena el trabajo de red **entre** intentos de minado, nunca durante uno: si se
            // interleara mientras `rx_minado` está bloqueado, un bloque de red podría admitirse a
            // la misma altura que estamos minando, y cuando nuestro propio hilo termine,
            // `admitir_pow_interno` lo admitiría como una bifurcación real de PoW —cosa que ni
            // `zx-cadena::admitir_pow` ni el `historial_pow` lineal de este nodo saben resolver
            // (límite conocido, `PROGRESO.md`: sin reorg de PoW en W06d2). En vez de eso, se
            // comprueba justo aquí si la red ya avanzó la punta mientras minábamos y, si es así, se
            // descarta el bloque propio (obsoleto) y se reintenta sobre la punta nueva.
            self.procesar_trabajo_red_pendiente();
            // `ORDEN-W06d3`, hallazgo en vivo (`PROGRESO.md`): el terminal puede fijarlo un bloque
            // de **red** admitido aquí mismo (dentro de `procesar_trabajo_red_pendiente`), no solo
            // uno propio. La comprobación de `self.cadena.terminal()` de más abajo, al final del
            // cuerpo del bucle, solo se alcanza si el bloque propio de esta vuelta se admite; si es
            // obsoleto (`continue`, justo abajo) el bucle vuelve a la cabecera **sin** pasar por
            // ella. Sin este cheque aquí, una vuelta puede minar sobre un padre cuyo propio estado
            // ya tiene `terminal = Some` (fijado por el bloque de red que el `procesar_trabajo_red_
            // pendiente` de arriba acaba de admitir) y `zx-cadena` la rechaza con
            // `ErrPowTrasCorte` — un bloque propio rechazado, fatal por la decisión 4 general de
            // `ORDEN-W06d1`. El bloque recién minado en esta vuelta queda descartado (ya es tarde
            // para él de todas formas: el corte ya ocurrió).
            if self.cadena.terminal().is_some() {
                drop(tx_trabajo);
                let _ = hilo.join();
                return Ok(());
            }
            let punta_sigue_siendo_la_esperada = self
                .historial_pow
                .last()
                .is_some_and(|u| u.block_hash() == cabecera_minada.prev_hash);
            if !punta_sigue_siendo_la_esperada {
                tracing::info!(
                    altura = cabecera_minada.height,
                    "bloque propio obsoleto: la red ya avanzó la punta mientras se minaba"
                );
                continue;
            }
            let n_txs = txs.len() as u64;
            let bytes = zx_p2p::codec::bloque_a_bytes(&BloqueRed::Pow {
                cabecera: cabecera_minada,
                txs: txs.clone(),
                testigos: testigos.clone(),
            })
            .len() as u64;
            let evento = self
                .registro
                .evento("bloque_minado")
                .str("hash", &cabecera_minada.block_hash().to_string())
                .u64("altura", u64::from(cabecera_minada.height))
                .u64("bytes", bytes)
                .u64("n_txs", n_txs);
            self.registro.escribir(evento, false)?;

            // `ORDEN-W06d5` decisión 3: mismo criterio que `fase_regimen` — un rechazo legítimo
            // (p. ej. `ErrPowTrasCorte`, el corte lo fijó un bloque de red justo entre que este
            // nodo empezó a minar y a admitir; ver `crate::rechazo`) se registra y se descarta;
            // solo una violación de invariante interna sigue siendo fatal.
            let indice_registro = self.almacen.longitud_registro()?;
            match self.admitir_pow_interno(
                cabecera_minada,
                txs,
                testigos,
                indice_registro,
                true,
                true,
            ) {
                Ok(()) => {
                    // Las transacciones del bloque propio ya están aplicadas: salen de la mempool.
                    self.actualizar_mempool_tras_bloque_con_recibo(
                        cabecera_minada.block_hash(),
                        &plantilla.txs,
                        &plantilla.testigos,
                        None,
                    );
                }
                Err(ErrorNodo::BloquePropioRechazado {
                    hash,
                    motivo,
                    clasificacion,
                }) if clasificacion.es_legitimo() => {
                    let evento = self
                        .registro
                        .evento("bloque_propio_rechazado_legitimo")
                        .str("hash", &hash.to_string())
                        .str("motivo", &motivo);
                    self.registro.escribir(evento, false)?;
                    continue;
                }
                Err(ErrorNodo::BloquePropioRechazadoPorTx {
                    hash,
                    altura,
                    motivo,
                    n_txs,
                }) => {
                    // P2 (`ORDEN-MP1`): un bloque propio rechazado por su cuerpo cuando lleva
                    // transacciones (una de terceros pudo entrar por la cola). Se expulsan de la
                    // cola las transacciones del bloque que no son la coinbase, se escribe el evento
                    // y se sigue con la vuelta siguiente. No se difunde el bloque (el `continue`
                    // sale antes de `difundir_si_hay_red`).
                    self.manejar_bloque_propio_rechazado_por_tx(
                        hash,
                        altura,
                        &motivo,
                        n_txs,
                        &plantilla.txs,
                    )?;
                    continue;
                }
                Err(e) => return Err(e),
            }
            self.difundir_si_hay_red(cabecera_minada.block_hash());

            if self.cadena.terminal().is_some() {
                drop(tx_trabajo);
                let _ = hilo.join();
                return Ok(());
            }
        }
    }

    /// ECL-R2a-5 · Una iteración **común** del bucle de régimen, la **misma** que ejecuta
    /// [`Self::fase_regimen`]. Se extrae para que la prueba del bucle pueda ejercitarla con el canal
    /// del productor y la cola de red reales, sin un segundo bucle exclusivo de test.
    ///
    /// Devuelve [`ControlBucle::Romper`] en parada ordenada o canal del productor cerrado; en
    /// cualquier otro caso [`ControlBucle::Continuar`].
    fn iteracion_regimen(
        &mut self,
        rx_en_bucle: &mpsc::Receiver<MsgProductor>,
        tx_a_productor: &mpsc::Sender<MsgBucle>,
        terminal: &mut BlockHash,
        frontera_enviada: &mut u64,
    ) -> ResultadoNodo<ControlBucle> {
        // RLJ-3b §2.2: disparador por tiempo. Con pendientes vencidos reintenta **solo** esos; sin
        // pendientes vencidos cuesta una comparación. Va en la vuelta común, así que cubre al nodo
        // que produce y al que solo observa (`vueltas_observador`).
        self.reintentar_pendientes_por_reloj();
        // TX-6: muestra periódica de la mempool (bytes, transacciones y rechazos por tope).
        self.muestrear_mempool_si_toca();
        // ECL-R2a · D4: en modo detenido no se produce ni se vota; sí se recibe, valida y responde a
        // la sincronización. El aviso `eclipse_detectado` y el fichero de recuperación se atienden
        // aquí (cada 60 s).
        if self.cadena.eclipse().is_some() {
            self.atender_modo_detenido()?;
        } else {
            // FV-4b-N1: avanza el motor de votos (cierra/abre instancias y ancla certificados).
            self.procesar_votos()?;
            // RN-1 · S1/S2/S4 · ciclo de vida de los sectores propios. Es independiente del voto y
            // del motor: corre igual con `--sin-voto` y en los dos modos de voto. VNT-1 · conserva
            // el reloj de **cadena aplicada** (la renovación no se adelanta por PoT local).
            let slot = self.slot_cadena_votos();
            self.renovar_si_cambia_slot(slot);
        }
        // `ORDEN-W07d` decisión 2: parada ordenada por señal. Se le pide al productor que pare
        // (responde a `Parar` en su `esperar`) y se sale del bucle.
        if parada::hay_solicitud() {
            let _ = tx_a_productor.send(MsgBucle::Parar);
            return Ok(ControlBucle::Romper);
        }
        let msg = match rx_en_bucle.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(m) => m,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.procesar_trabajo_red_pendiente();
                // Decisión 0: entre dos mensajes del hilo (hasta un slot entero) es exactamente
                // cuando una reunión con producción en marcha puede haber reseleccionado el
                // terminal (E-6b): hay que sincronizar aquí, no solo tras recibir un mensaje.
                // W08h: aquí es también donde se reenvía la frontera verificada del mismo terminal
                // en cuanto avanza.
                self.sincronizar_productor(terminal, frontera_enviada, tx_a_productor)?;
                return Ok(ControlBucle::Continuar);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(ControlBucle::Romper),
        };
        self.procesar_trabajo_red_pendiente();
        // Decisión 0: si el terminal seleccionado cambió, se sincroniza el hilo **antes** de decidir
        // qué hacer con `msg` — si `msg` es `PeticionPadres`, esa petición era del terminal anterior
        // y no se contesta (el hilo la abandona al ver `CambiarTerminal`,
        // `regimen::Recepcion::Interrumpido`); si es `Candidata`, se descarta como atrasada
        // (`produccion_descartada` con `motivo = "terminal_cambiado"`), sin firmar ni admitir.
        let terminal_cambio =
            self.sincronizar_productor(terminal, frontera_enviada, tx_a_productor)?;
        self.atender_msg_productor(msg, terminal_cambio, *terminal, tx_a_productor)
    }

    fn fase_regimen(&mut self) -> ResultadoNodo<()> {
        // `ORDEN-SL4b2` decisión 0 (paso previo): `terminal` es el que este bucle sigue
        // **produciendo** ahora mismo; puede quedar por detrás de `self.cadena.terminal()` (FC-3
        // puede reseleccionar mientras se produce, `ORDEN-W06d7`). Mutable: lo actualiza
        // `sincronizar_productor` en cuanto detecta la discrepancia.
        let mut terminal = self
            .cadena
            .terminal()
            .ok_or_else(|| ErrorNodo::Otro("fase_regimen sin terminal".to_string()))?;
        // `ORDEN-W06d7` decisión 5: un `ServicioPot` por terminal candidato, no uno solo; se
        // asegura (crea si falta) el de `terminal` y el de cualquier otro candidato ya conocido.
        // Entre que `fase_pow` vio el terminal seleccionado por última vez y aquí, una rama más
        // pesada llegada por red pudo haber cambiado la selección (FC-3): `terminal` sigue siendo
        // válido como terminal candidato (tiene su propio servicio para siempre, no se "pierde" al
        // dejar de ser el seleccionado), aunque ya no sea `self.cadena.terminal()`.
        self.asegurar_servicios_verificacion()?;

        // El primer bloque de régimen (transición) se produce con el firmante seguro
        // (`producir_con_firmante`, `ORDEN-SL4b3` decisión 1), ya no con la ruta que sellaba sin
        // registrar. El resto del comentario conserva el motivo de la espera.
        //
        // `ORDEN-W06d5` decisión 1, extensión encontrada **en vivo** al repetir V5 con esta misma
        // orden ya aplicada (evidencia en `PROGRESO.md`): un nodo que llega tarde también puede
        // llegar aquí con `tips_validas()` vacío (los bloques PoST que le llegaron por red antes de
        // fijar su propio terminal se ignoran como `bloque_post_de_red_sin_terminal`, sin
        // reintentarse) y con la clave que firma la transición (`self.claves[0]`, decisión 6 de
        // `producir_bloque_transicion`) **sin garantía propia** (nunca minó ni depositó: exactamente
        // el perfil de una clave nueva de V5). Producir de todos modos repite el mismo `ErrGarantia`
        // fatal que la decisión 1 ya evita en régimen — el hilo productor nunca llega a arrancar
        // porque el proceso muere antes, en esta única producción previa al bucle de mensajes. Igual
        // que en régimen: no se intenta sin garantía; en vez de eso, se espera (procesando red) a
        // que **otro** nodo produzca y sincronice la transición, lo que llena `tips_validas()` por
        // la vía normal de `intentar_admitir_post_de_red`.
        if self.cadena.tips_validas().is_empty() {
            let hay_garantia_propia = self
                .claves
                .first()
                .is_some_and(|c| self.cadena.estado_terminal().activo_de(&c.pk) >= self.params.q);
            if hay_garantia_propia {
                self.producir_bloque_transicion(terminal)?;
            } else {
                tracing::info!(
                    "sin garantía propia en el terminal: no se intenta producir el bloque de \
                     transición; se espera a sincronizarlo de otro nodo"
                );
            }
            // `ORDEN-SL4b3` decisión 1: si `producir_bloque_transicion` se abstuvo (conflicto o
            // pérdida de registro), no produjo nada y `tips_validas()` sigue vacío. Reintentar el
            // mismo candidato determinista solo repetiría la abstención (misma identidad y slot), así
            // que la recuperación es la sincronización con la red, no un bucle de producción; el
            // hilo productor de régimen retomará la producción en los slots siguientes en cuanto la
            // transición esté en la cadena.
            while self.cadena.tips_validas().is_empty() {
                // `ORDEN-W07d` decisión 2: la parada por señal también se atiende aquí, antes de
                // arrancar el hilo productor.
                if parada::hay_solicitud() {
                    return Ok(());
                }
                self.procesar_trabajo_red_pendiente();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }

        let mut claves_con_parcela = Vec::new();
        for clave in self.claves.clone() {
            let parcela = abrir_o_crear_parcela(&self.dir_datos, &clave, &self.historia)?;
            // PROD-3c: al hilo solo le va material público (índice, clave pública y parcela).
            // Las `ClaveDev` se quedan en el bucle, que es el único que firma.
            claves_con_parcela.push(ClavePublicaConParcela {
                indice: clave.indice,
                pk: clave.pk,
                parcela,
            });
        }

        // Clon del `ServicioPot` de verificación (ya trae el terminal y todo bloque PoST admitido:
        // el de transición recién producido, o toda la historia de régimen si esto es un reinicio a
        // mitad de régimen). El hilo avanza y produce sobre su propio clon; el del bucle solo se usa
        // para verificar (ver el doc de `hilo_productor_regimen`).
        let servicio_hilo = self
            .servicios_verificacion
            .get(&terminal)
            .cloned()
            .ok_or_else(|| {
                ErrorNodo::Otro("fase_regimen sin ServicioPot de verificación".to_string())
            })?;
        // `ORDEN-W08h` decisión 1: slot de la última frontera verificada enviada al hilo. Arranca en
        // el del clon entregado al hilo; a partir de ahí, cada avance del `ServicioPot` de
        // verificación del bucle se manda por `CambiarTerminal` (mismo terminal) para que el
        // timelord salte a él si va por delante.
        let mut frontera_enviada = servicio_hilo.slot_actual();

        let (tx_a_bucle, rx_en_bucle) = mpsc::channel::<MsgProductor>();
        let (tx_a_productor, rx_en_productor) = mpsc::channel::<MsgBucle>();
        let cbid = self.cbid;
        let sr_dev = self.sr_dev_actual;
        // `ORDEN-W06d6` decisión 6: el hilo productor para de producir en el primero de los dos
        // límites que esté fijado (`--parada-tras-slots` sigue parando el nodo entero; el nuevo
        // `--dejar-de-producir-en-slot` solo para de producir, ver más abajo tras el bucle).
        let parada = self.limite_productor();
        let importe_coinbase = perfil::subsidio_post(0);
        let historia_hilo: Arc<HistoriaGenesis> = Arc::clone(&self.historia);
        // PROD-3b: el hilo ya no firma; el registro del firmante se usa solo en el bucle.
        if self.registro_firmante.is_none() {
            return Err(ErrorNodo::Otro(
                "fase_regimen sin registro de firmante".into(),
            ));
        }
        // `ORDEN-W06d8` decisión 1: el hilo escribe desde su lado el evento de diagnóstico
        // `productor_respuesta_descartada` cuando descarta una respuesta atrasada; comparte el mismo
        // registro que el bucle (que ya es `Arc` y serializa con un `Mutex`).
        let registro_hilo: Arc<Registro> = Arc::clone(&self.registro);
        let hilo = thread::spawn(move || {
            hilo_productor_regimen(
                servicio_hilo,
                sr_dev,
                cbid,
                importe_coinbase,
                claves_con_parcela,
                &historia_hilo,
                parada,
                &rx_en_productor,
                &tx_a_bucle,
                &registro_hilo,
            );
        });

        // `recv_timeout`, no `for msg in rx_en_bucle`: entre dos mensajes del productor (que puede
        // tardar hasta un slot entero) hace falta seguir drenando `procesar_trabajo_red_pendiente`
        // (decisión 1/3/4 de `ORDEN-W06d2`), o un bloque de red llegaría y esperaría sin motivo
        // hasta el siguiente mensaje del hilo productor.
        // Una iteración común por vuelta; `Romper` (parada ordenada o canal cerrado) sale.
        while let ControlBucle::Continuar = self.iteracion_regimen(
            &rx_en_bucle,
            &tx_a_productor,
            &mut terminal,
            &mut frontera_enviada,
        )? {}
        drop(tx_a_productor);
        // Decisión 4: un fallo interno del nodo termina el proceso con código ≠ 0, nunca en
        // silencio. `hilo_productor_regimen` no valida entrada ajena (sin red): un panic ahí es una
        // incoherencia interna, no un evento de red que se pueda ignorar (el bug real que motivó
        // esto, `PROGRESO.md`, era exactamente un hilo que moría sin decir por qué).
        if let Err(panico) = hilo.join() {
            let motivo = panico
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panico.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic sin mensaje representable".to_string());
            return self.fallo_productor(&format!("el hilo productor terminó con panic: {motivo}"));
        }
        // `ORDEN-W07d` decisión 2: si la parada la pidió una señal, no se entra en el reposo
        // indefinido de `--dejar-de-producir-en-slot`; `ejecutar` escribe `parada` y sale con 0.
        if parada::hay_solicitud() {
            return Ok(());
        }
        // `ORDEN-W06d6` decisión 6: si lo que paró de producir fue **solo**
        // `--dejar-de-producir-en-slot` (no `--parada-tras-slots`), el nodo entero **no** termina
        // aquí: sigue vivo, validando, propagando y sincronizando, para poder compararse en reposo
        // contra otros nodos (`P-ZRX/P-MEDICION/REVISION-W07c.md`). Solo `--parada-tras-slots`
        // (con o sin el otro) termina el proceso, como siempre.
        if self.parada_tras_slots.is_none() && self.dejar_de_producir_en_slot.is_some() {
            let evento = self.registro.evento("dejar_de_producir").str(
                "motivo",
                "--dejar-de-producir-en-slot alcanzado: sigue en reposo activo",
            );
            self.registro.escribir(evento, false)?;
            loop {
                if parada::hay_solicitud() {
                    return Ok(());
                }
                self.procesar_trabajo_red_pendiente();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        Ok(())
    }

    /// Conecta el nodo a la red (`ORDEN-W06d2`): a partir de aquí, `ejecutar` también procesa el
    /// trabajo de red (bloques difundidos o de sincronización) intercalado con su propia
    /// producción (D-N07: un único hilo de consenso). Sin llamar a esto, el nodo se comporta
    /// exactamente como en `ORDEN-W06d1` (sin red).
    ///
    /// A5-c-2b · X2: si este nodo emite votos, se suscribe aquí a las subredes de sus claves de
    /// voto (el que no vota no se suscribe a ninguna; el tema de agregados lo suscribe el bucle de
    /// `zx-p2p` al arrancar para todos).
    pub fn conectar_red(&mut self, manija: ManijaRed, receptor: ReceptorTrabajoRed) {
        if self.vota {
            let subredes = self.subredes_propias();
            manija.suscribir_subredes(&subredes);
        }
        self.red = Some(manija);
        self.trabajo_red = Some(receptor);
    }

    /// `ORDEN-W07a`: fija el `peer_id` y la dirección de escucha para el `arranque`. Se llama tras
    /// arrancar la red (si la hay) y antes de [`Self::ejecutar`].
    pub fn fijar_arranque_red(&mut self, peer_id: String, red_escuchar: Option<String>) {
        self.peer_id = Some(peer_id);
        self.red_escuchar = red_escuchar;
    }

    /// Ejecuta el nodo de punta a punta: fase PoW hasta el corte, luego régimen.
    ///
    /// # Errores
    /// Cualquier fallo fatal de admisión propia (decisión 4).
    pub fn ejecutar(&mut self) -> ResultadoNodo<()> {
        // `ORDEN-W07a` §1: `arranque`, al terminar el arranque (ya con la red conectada, si la hay).
        let claves: Vec<String> = self.claves.iter().map(|c| c.indice.to_string()).collect();
        let mut evento = self
            .registro
            .evento("arranque")
            .u64("version_esquema", 1)
            .u64("n_dev", self.n_dev)
            .u64("sr_dev", self.sr_dev_actual)
            .str("claves", &claves.join(","))
            .str(
                "modo",
                if self.modo_limpio {
                    "limpio"
                } else {
                    "reinicio"
                },
            );
        if let Some(peer_id) = self.peer_id.as_deref() {
            evento = evento.str("peer_id", peer_id);
        }
        if let Some(red) = self.red_escuchar.as_deref() {
            evento = evento.str("red_escuchar", red);
        }
        self.registro.escribir(evento, true)?;

        self.fase_pow()?;
        // `ORDEN-W07d` decisión 2: una señal durante la fase PoW detiene el proceso **sin** entrar
        // en régimen (todavía no hay terminal y `fase_regimen` fallaría con «fase_regimen sin
        // terminal»). El flag ya está puesto, así que el motivo es de señal.
        if let Some(motivo) = parada::motivo_solicitado() {
            self.escribir_parada(motivo)?;
            return Ok(());
        }
        self.fase_regimen()?;
        // `ORDEN-W07a` §1 y `ORDEN-W07d` decisión 2: `parada`, salida ordenada (crítico). Si la
        // pidió una señal, ese es el motivo; si no, el final normal de la fase.
        let motivo = if let Some(motivo) = parada::motivo_solicitado() {
            motivo
        } else if self.parada_tras_slots.is_some() {
            "parada_tras_slots"
        } else {
            "fin"
        };
        self.escribir_parada(motivo)?;
        Ok(())
    }
}

/// PROD-3b: cableado contextual de la firma del productor (pieza con su interfaz).
pub(crate) mod firma_contextual;

/// Pieza O (MAP-1): registro estructurado y resúmenes.
mod observabilidad;

/// Pieza T (MAP-1): reloj local, servicios de verificación del PoT y calendario.
mod tiempo;

/// Pieza A (MAP-1): admisión de bloques y vista de cadena.
mod admision;

/// Pieza R (MAP-1): raíces de estado.
mod raices;

/// Pieza M (MAP-1): cola de transacciones vista desde el nodo.
mod cola_tx;

/// Pieza D (MAP-1): disco: arranque, repetición y reinicio.
mod disco;

/// Pieza N (MAP-1): red — difusión, peticiones, admisión de lo que llega y colas de pendientes.
mod red_nodo;

/// Pieza E (MAP-1): evidencias, certificados de peso, anclas y recuperación de eclipse.
mod evidencias;

/// Pieza V (MAP-1): votos del nodo y cola de operaciones v6.
mod votos_nodo;

/// Pieza S (MAP-1): renovación de los sectores propios.
mod renovacion;

/// Pieza P (MAP-1): producción — el bucle del productor, la ruta PoST propia y la transición.
mod produccion;

use self::observabilidad::Medicion;
use self::raices::VistaConRaiz;
#[cfg(test)]
use self::raices::punto_de_ventana;

use self::evidencias::{
    CLASE_EVIDENCIA_PESO, CacheAnclaDiagnostico, FinalidadEstado, evidencias_para_cuerpo_post,
    finalidad_estado_de, garantia_promovida_en_slot, operacion_certificado_peso,
    tx_es_certificado_peso, ventana_de_certificado_peso, ventana_y_huella_de_certificado_peso,
};
#[cfg(test)]
use self::evidencias::{MAX_PASOS_ANCLA_PENDIENTES, tabla_peso_para_bloque};
use self::red_nodo::{TOPE_POST_PENDIENTES, TOPE_POW_PENDIENTES, UltimoEmpujePesos};

pub use self::produccion::reloj_produccion_permitida;
use self::produccion::{
    ControlBucle, ControlPost, DepuracionPost, TxCuerpoPost, bytes_cuerpo_post, bytes_de,
    depurar_candidata_post, error_atribuible_al_candidato, es_coinbase_pow, es_ftl_pow,
    es_rechazo_propio_por_cuerpo, escribir_fallo_productor, familia_de, motivo_abstencion_texto,
    padres_dag_a_vec, peso_u128, post_de_candidata, pow_target_de,
};
#[cfg(test)]
use self::produccion::{FuenteTransicion, presupuestar_cuerpo_post, recomponer_candidata_post};
use self::renovacion::{RenovacionEnVuelo, abrir_o_crear_parcela};
#[cfg(test)]
pub(crate) use self::votos_nodo::clase_arranque_votos;
#[cfg(test)]
use self::votos_nodo::{CLASE_ACTA_PESO, CLASE_VOTO_PROPIO, metadatos_v6, subred_de_agregado};
use self::votos_nodo::{
    ContadoresAgregacion, LAG_CANDIDATO_VOTOS, PendienteV6, encajar_votos_propios, tabla_a_payload,
    votos_propios_para_bloque,
};

/// Pruebas de aceptación PROD-3b-2.
#[cfg(test)]
mod pruebas_prod3b;

/// Pruebas de aceptación PROD-3c (hilo sin clave privada, C09 y C03).
#[cfg(test)]
mod pruebas_prod3c;

#[cfg(test)]
mod pruebas_ra2;

#[cfg(test)]
mod ev1;

#[cfg(test)]
mod ev2;

/// PD-1f · Q1–Q6 · defensas contra el eclipse con el certificado por peso.
#[cfg(test)]
mod pruebas_pd1f;

/// RN-1 · N1–N5 y N7 · renovación de sectores propios, rastro de transacciones y S7.
#[cfg(test)]
mod pruebas_rn1;

/// AT-1c · C2 · la prueba real del votante honesto frente a la falta entre ventanas.
#[cfg(test)]
mod pruebas_at1c;

/// AUS-2b · pruebas B1–B6 del voto propio del nodo (AV-11); devueltas por M9-a2 al modo por peso.
#[cfg(test)]
mod aus2b_tests;

#[cfg(test)]
mod carprod_tests;

#[cfg(test)]
mod b782_tests;

/// FV-N6-C7-3 · pruebas por el camino común del Nodo (`procesar_votos`); devueltas por M9-a2 al modo
/// por peso.
#[cfg(test)]
mod pruebas_fvn6c7_3;

/// A1-D2b · W1–W5 · la raíz de estado en el nodo: la vista que la entrega al motor, el cálculo en
/// segundo plano, el aviso de raíz no lista y los eventos del registro.
#[cfg(test)]
mod pruebas_raizn;

/// A5-c-2b · la agregación de votos en el nodo: suscripción por subred, votos de red, lotes de
/// agregados, agregado propio y registro.
#[cfg(test)]
mod pruebas_agn;

#[cfg(test)]
mod pruebas_puerta_rat3 {
    use super::comprobar_puerta_rat3;
    use zx_consensus::transicion::ParametrosEvidencia;

    /// El perfil dev real (`R_slots = 600`, `Plazo_slots = 300`, `M_margen_slots = 60`) arranca.
    #[test]
    fn el_perfil_dev_real_pasa_la_puerta() {
        let evidencia = crate::perfil::parametros_evidencia_dev();
        assert!(comprobar_puerta_rat3(crate::perfil::R_SLOTS, &evidencia).is_ok());
    }

    /// Un perfil de prueba con `R_slots` demasiado corto para su propia ventana **no** arranca, y
    /// el error trae el mensaje con los números exactos.
    #[test]
    #[expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
    fn un_perfil_que_incumple_rat3_no_arranca() {
        let evidencia = ParametrosEvidencia {
            plazo_slots: 300,
            m_margen_slots: 60,
            ..crate::perfil::parametros_evidencia_dev()
        };
        let err = comprobar_puerta_rat3(300, &evidencia).unwrap_err();
        let texto = err.to_string();
        assert!(texto.contains("puerta RAT-3"), "{texto}");
        assert!(texto.contains("300"), "{texto}");
        assert!(texto.contains("360"), "{texto}");
    }

    /// El caso límite exacto (`R_slots == Plazo_slots + M_margen_slots`) también incumple: la
    /// desigualdad es estricta (EV-15).
    #[test]
    fn el_limite_exacto_tambien_incumple() {
        let evidencia = ParametrosEvidencia {
            plazo_slots: 300,
            m_margen_slots: 60,
            ..crate::perfil::parametros_evidencia_dev()
        };
        assert!(comprobar_puerta_rat3(360, &evidencia).is_err());
        assert!(comprobar_puerta_rat3(361, &evidencia).is_ok());
    }
}

/// FV-4b-N4 · R-ECL-05: la puerta en el punto exacto que usa `Nodo::arrancar`.
#[cfg(test)]
mod pruebas_puerta_recl05 {
    use super::comprobar_puerta_recl05;
    use crate::perfil::{LOOKBACK_VOTOS_DEV, M_MARGEN_SLOTS, PLAZO_SLOTS, R_SLOTS};

    /// El perfil dev real (`600 >= 120·2 + 300 + 60 = 600`) arranca.
    #[test]
    fn el_perfil_dev_real_pasa_la_puerta() {
        let t_inst = crate::perfil::parametros_votos_dev().t_inst;
        assert!(comprobar_puerta_recl05(R_SLOTS, t_inst, PLAZO_SLOTS, M_MARGEN_SLOTS).is_ok());
    }

    /// Un `LOOKBACK` de una instancia más no arranca y el error trae los números exactos.
    #[test]
    #[expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
    fn un_lookback_excesivo_no_arranca() {
        let t_inst = crate::perfil::parametros_votos_dev().t_inst;
        // Simula el perfil inválido reduciendo la retención una unidad por debajo del umbral.
        let err =
            comprobar_puerta_recl05(R_SLOTS - 1, t_inst, PLAZO_SLOTS, M_MARGEN_SLOTS).unwrap_err();
        let texto = err.to_string();
        assert!(texto.contains("R-ECL-05"), "{texto}");
        // `V_slots = LOOKBACK·T_inst = 120·2 = 240`.
        assert!(
            texto.contains(
                &crate::perfil::ventana_voto_slots(LOOKBACK_VOTOS_DEV, t_inst).to_string()
            ),
            "{texto}"
        );
    }

    /// El límite exacto (`==`) **sí** cumple: R-ECL-05 usa `>=`, a diferencia de RAT-3.
    #[test]
    fn el_limite_exacto_cumple() {
        let t_inst = crate::perfil::parametros_votos_dev().t_inst;
        let v_slots = crate::perfil::ventana_voto_slots(LOOKBACK_VOTOS_DEV, t_inst);
        let exacto = v_slots + PLAZO_SLOTS + M_MARGEN_SLOTS;
        assert!(comprobar_puerta_recl05(exacto, t_inst, PLAZO_SLOTS, M_MARGEN_SLOTS).is_ok());
        assert!(comprobar_puerta_recl05(exacto - 1, t_inst, PLAZO_SLOTS, M_MARGEN_SLOTS).is_err());
    }
}

/// `ORDEN-W06d8` decisión 3 (V1): el fallo del hilo productor no es silencioso: se escribe el
/// evento crítico `fallo_productor` y se devuelve error (el proceso sale ≠ 0 por `main`).
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
mod pruebas_fallo_productor {
    use crate::registro::Registro;

    use super::escribir_fallo_productor;

    #[test]
    fn fallo_productor_escribe_evento_critico_y_devuelve_error() {
        let dir = tempfile::tempdir().unwrap();
        let registro = Registro::abrir(&dir.path().join("registro.jsonl")).unwrap();
        let err =
            escribir_fallo_productor(&registro, "respuesta con id 7 > esperado 2").unwrap_err();
        assert!(
            err.to_string().contains("fallo del hilo productor"),
            "{err}"
        );
        let texto = std::fs::read_to_string(dir.path().join("registro.jsonl")).unwrap();
        assert!(texto.contains("\"tipo\":\"fallo_productor\""), "{texto}");
        assert!(texto.contains("respuesta con id 7 > esperado 2"), "{texto}");
    }
}

/// `ORDEN-W06d1` V7: un bloque **propio** alterado, inyectado directamente en la tubería de
/// admisión (sin pasar por el minero), se rechaza con su motivo y no cambia el estado.
///
/// Es un test unitario (no de `tests/`) porque `admitir_pow_interno` es privado a propósito: la
/// tubería única (decisión 4) no tiene una puerta trasera pública para inyectar candidatos ya
/// verificados. La alteración es la más básica posible —un `nonce` que no cumple el PoW real, sin
/// minar— y por eso la rechaza ya el primer paso de la tubería (`validar_cabecera_pow`).
#[cfg(test)]
#[expect(clippy::expect_used, reason = "el test falla con panic por diseño")]
mod pruebas_v7 {
    use zx_core::preimage::block::merkle_root;

    use zx_core::txid;

    use super::{BlockHeader, Config, Nodo, Red};

    #[test]
    fn bloque_pow_propio_alterado_se_rechaza_y_no_cambia_el_estado() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = Config {
            dir_datos: dir.path().join("datos"),
            ruta_registro: dir.path().join("registro.jsonl"),
            red: Red::Dev,
            semilla: 7,
            indices_claves: vec![0],
            n_dev: 16,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: Some(0),
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        };
        let mut nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
        let estado_antes = nodo.resumen_estado_actual();

        #[expect(
            clippy::indexing_slicing,
            reason = "el arranque deja al menos el génesis"
        )]
        let ultimo = nodo.historial_pow[nodo.historial_pow.len() - 1];
        let clave = nodo.claves.first().expect("al menos una clave").pk;
        let coinbase = crate::pow::construir_coinbase_pow(clave, 1);
        let txid_coinbase = txid(&coinbase, nodo.cbid);
        let cabecera = BlockHeader {
            consensus_branch_id: nodo.cbid,
            prev_hash: ultimo.block_hash(),
            merkle_root: merkle_root(&[txid_coinbase]),
            timestamp: ultimo.timestamp + 10,
            bits: ultimo.bits,
            // `nonce = 0` sin minar: no cumple `hash_pow < target` salvo una casualidad
            // astronómicamente improbable con la dificultad inicial real de la red dev.
            nonce: 0,
            height: 1,
        };
        let hash_alterado = cabecera.block_hash();

        let resultado =
            nodo.admitir_pow_interno(cabecera, vec![coinbase], vec![Vec::new()], 0, true, true);
        assert!(
            resultado.is_err(),
            "un bloque propio con PoW inválido debe rechazarse"
        );
        assert!(
            !nodo.cadena.es_valido(&hash_alterado),
            "el bloque alterado no debe quedar admitido"
        );
        assert_eq!(
            nodo.resumen_estado_actual(),
            estado_antes,
            "el estado no debe cambiar tras el rechazo"
        );
    }
}

/// `ORDEN-W06d4` decisión 1/2: reproduce y corrige que el indicador local de depósito no sea
/// sensible a la rama (`REVISION-W06d3.md`, hipótesis del director).
///
/// Construye, con la tubería real de admisión (`admitir_pow_interno`, sin red), dos ramas PoW que
/// comparten el bloque `A1` (paga una coinbase a una clave propia): la rama `A` gasta esa coinbase
/// en su segundo bloque (el depósito F-15); la rama `B` (más pesada, sin ese depósito) se acaba
/// seleccionando por FC-3. Tras la reorganización, la coinbase de `A1` nunca se gastó en la rama
/// `B`: `preparar_depositos`, evaluado sobre la punta ya seleccionada, debe volver a proponerla.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]
mod pruebas_deposito_sensible_a_la_rama {
    use zx_consensus::PARAMETROS_POW_DEV;
    use zx_core::preimage::block::merkle_root;
    use zx_core::txid as calc_txid;

    use super::{BlockHeader, Config, Nodo, Red};
    use crate::claves::ClaveDev;
    use crate::pow;

    fn cabecera(prev: BlockHeader, height: u32, txids: &[zx_core::TxId], cbid: u32) -> BlockHeader {
        BlockHeader {
            consensus_branch_id: cbid,
            prev_hash: prev.block_hash(),
            merkle_root: merkle_root(txids),
            timestamp: prev.timestamp + 1,
            bits: PARAMETROS_POW_DEV.bits_iniciales,
            nonce: 0,
            height,
        }
    }

    #[test]
    fn preparar_depositos_vuelve_a_depositar_tras_perder_el_bloque_del_deposito() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = Config {
            dir_datos: dir.path().join("datos"),
            ruta_registro: dir.path().join("registro.jsonl"),
            red: Red::Dev,
            semilla: 11,
            indices_claves: vec![0],
            n_dev: 16,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: Some(0),
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        };
        let mut nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
        let clave_propia = nodo.claves.first().cloned().expect("al menos una clave");
        let clave_ajena = ClaveDev::derivar(cfg.semilla, 999);
        let cbid = nodo.cbid;

        #[expect(
            clippy::indexing_slicing,
            reason = "el arranque deja al menos el génesis"
        )]
        let genesis = nodo.historial_pow[0];

        // A1 (altura 1, común a las dos ramas): coinbase paga a la clave propia.
        let cb_a1 = pow::construir_coinbase_pow(clave_propia.pk, 1);
        #[expect(clippy::indexing_slicing, reason = "una coinbase tiene una salida")]
        let valor_a1 = cb_a1.outputs[0].value;
        let txid_a1 = calc_txid(&cb_a1, cbid);
        let cab_a1 = cabecera(genesis, 1, &[txid_a1], cbid);
        nodo.admitir_pow_interno(cab_a1, vec![cb_a1], vec![Vec::new()], 0, false, false)
            .expect("A1 se admite");

        // M2..M6 (comunes a las dos ramas): solo hacen madurar la coinbase de A1 (`M_CB = 5`:
        // madura en la altura 6). Ninguno la toca.
        let mut prev = cab_a1;
        for altura in 2..=6u32 {
            let cb = pow::construir_coinbase_pow(clave_ajena.pk, altura);
            let txid_cb = calc_txid(&cb, cbid);
            let cab = cabecera(prev, altura, &[txid_cb], cbid);
            nodo.admitir_pow_interno(cab, vec![cb], vec![Vec::new()], 0, false, false)
                .unwrap_or_else(|e| panic!("M{altura} se admite: {e}"));
            prev = cab;
        }
        let cab_m6 = prev;

        // A7 (altura 7, rama A): la coinbase de A1 ya está madura; la gasta con el depósito F-15.
        let (tx_deposito, testigos_deposito) =
            pow::construir_deposito(txid_a1, valor_a1, &clave_propia, 0, cbid)
                .expect("depósito firmado");
        let cb_a7 = pow::construir_coinbase_pow(clave_ajena.pk, 7);
        let txid_a7 = calc_txid(&cb_a7, cbid);
        let txid_dep = calc_txid(&tx_deposito, cbid);
        let cab_a7 = cabecera(cab_m6, 7, &[txid_a7, txid_dep], cbid);
        nodo.admitir_pow_interno(
            cab_a7,
            vec![cb_a7, tx_deposito],
            vec![Vec::new(), testigos_deposito],
            0,
            false,
            false,
        )
        .expect("A7 (con el depósito) se admite");

        // Antes de la reorganización: la rama seleccionada es A7, donde la coinbase de A1 ya se
        // gastó; no hay nada pendiente que depositar.
        let depositos_antes = nodo
            .preparar_depositos(10)
            .expect("preparar_depositos (antes de la reorganización)");
        assert!(
            depositos_antes.is_empty(),
            "tras depositar en A7 no debería haber depósitos pendientes todavía"
        );

        // Rama B (más pesada, sin el depósito): B7, B8, ambas descendientes de M6 (no de A7), sin
        // gastar la coinbase de A1. Dos bloques (B7, B8) pesan más que el único bloque de la rama A
        // (A7) desde el ancestro común M6, así que FC-3 debe conmutar la selección.
        let mut prev = cab_m6;
        for altura in 7..=8u32 {
            let cb = pow::construir_coinbase_pow(clave_ajena.pk, altura);
            let txid_cb = calc_txid(&cb, cbid);
            let cab = cabecera(prev, altura, &[txid_cb], cbid);
            nodo.admitir_pow_interno(cab, vec![cb], vec![Vec::new()], 0, false, false)
                .unwrap_or_else(|e| panic!("B{altura} se admite: {e}"));
            prev = cab;
        }
        let punta_b = prev.block_hash();
        assert_eq!(
            nodo.cadena.mejor_punta_pow(),
            Some(punta_b),
            "la rama B, más pesada, debe ser la punta PoW seleccionada (FC-3)"
        );
        assert_eq!(
            nodo.historial_pow.last().map(BlockHeader::block_hash),
            Some(punta_b),
            "historial_pow debe reflejar la reorganización a la rama B"
        );

        // La coinbase de A1 nunca se gastó en la rama B: sigue viva (sin gastar) en su estado.
        let estado_b = nodo
            .cadena
            .estado_post(&punta_b)
            .expect("estado de la punta B");
        assert!(
            estado_b.utxo.contains_key(&zx_core::OutPoint {
                prev_txid: txid_a1,
                prev_index: 0,
            }),
            "la coinbase de A1 debe seguir viva (sin gastar) en el estado de la rama B"
        );

        // La corrección (`ORDEN-W06d4` decisión 2): evaluado sobre la rama B ya seleccionada,
        // `preparar_depositos` debe volver a proponer el depósito de la coinbase de A1 (madura en
        // la altura 1 + M_CB(5) = 6; se evalúa en la altura 8). Con el indicador local
        // `depositada` (bug de `ORDEN-W06d3`, `PROGRESO.md`), esta lista queda vacía: el nodo
        // nunca vuelve a intentar depositar esa coinbase, y con ella nunca reúne `Φ`.
        let depositos_despues = nodo
            .preparar_depositos(8)
            .expect("preparar_depositos (después de la reorganización)");
        assert!(
            depositos_despues
                .iter()
                .any(|(tx, _)| tx.inputs.first().map(|i| i.outpoint.prev_txid) == Some(txid_a1)),
            "tras perder el bloque del depósito por la reorganización, el nodo debe volver a \
             proponer el depósito de la coinbase de A1 (bug de ORDEN-W06d3, corregido en \
             ORDEN-W06d4)"
        );
    }
}

/// `ORDEN-W06d6`, paso previo (RI-3c H1, `REVISION-RI-3c.md`): el orden **admitir → persistir**
/// (sustituye al orden de RI-2b, persistir → admitir) impide la entrada fantasma que bloqueaba el
/// reinicio, y el punto de inyección de fallo entre admitir y persistir no deja rastro observable.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño"
)]
mod pruebas_ri3c_orden_admitir_persistir {
    use core::sync::atomic::AtomicBool;

    use zx_consensus::{PARAMETROS_POW_DEV, Sha3Dev, minar};
    use zx_core::preimage::block::{BlockHeader, merkle_root};
    use zx_core::{Amount, decodificar_con, txid};

    use zx_storage::Almacen as _;

    use super::{Config, Nodo, Red};
    use crate::pow;

    fn cfg_de_test(dir: &std::path::Path) -> Config {
        Config {
            dir_datos: dir.join("datos"),
            ruta_registro: dir.join("registro.jsonl"),
            red: Red::Dev,
            semilla: 42,
            indices_claves: vec![0],
            n_dev: 16,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: Some(0),
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        }
    }

    /// Mina un PoW real de altura 1 sobre el génesis del nodo, con la coinbase que se le pase (para
    /// poder viciarla y forzar un rechazo del motor de transición sin tocar el PoW en sí).
    fn minar_altura_1(nodo: &Nodo, mut coinbase: zx_core::Tx, importe: i64) -> BlockHeader {
        coinbase.outputs[0].value = Amount::nuevo(importe).expect("importe representable");
        let genesis = nodo.historial_pow[nodo.historial_pow.len() - 1];
        let txid_coinbase = txid(&coinbase, nodo.cbid);
        let target = decodificar_con(
            PARAMETROS_POW_DEV.bits_iniciales,
            &PARAMETROS_POW_DEV.limites,
        )
        .expect("bits_iniciales decodifica");
        let cabecera_base = BlockHeader {
            consensus_branch_id: nodo.cbid,
            prev_hash: genesis.block_hash(),
            merkle_root: merkle_root(&[txid_coinbase]),
            timestamp: genesis.timestamp + 1,
            bits: PARAMETROS_POW_DEV.bits_iniciales,
            nonce: 0,
            height: 1,
        };
        let cancelar = AtomicBool::new(false);
        minar(&cabecera_base, target, &Sha3Dev, u64::MAX, &cancelar)
            .expect("un PoW real se encuentra con la dificultad dev inicial (~2^17 intentos)")
    }

    /// **Regresión de RI-3c H1** (test adaptado de `resultados-RI-3c/ri3c_nodo.diff`, con las
    /// aserciones invertidas a lo correcto tras la corrección — el original, ejecutado tal cual
    /// contra la base sin corregir, se conservó como evidencia "antes" en
    /// `deepseek/W06d6/logs/RI-3c-antes.log`): una coinbase que paga de más se **rechaza** por
    /// `ErrEmision` y, con el orden nuevo, **nunca llega a persistirse** — el registro sigue en 1
    /// (solo el génesis) tras el rechazo, y el nodo **reinicia sin problema**.
    #[test]
    fn bloque_pow_propio_rechazado_no_persiste_y_el_reinicio_funciona() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_de_test(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
        let clave = nodo.claves.first().expect("al menos una clave").pk;

        // Coinbase que paga **más** que `subsidio_pow(1)` (perfil dev: 50 ZZK): el motor de
        // transición la rechaza con `ErrEmision` (`Interno` para `crate::rechazo`).
        let coinbase = pow::construir_coinbase_pow(clave, 1);
        let cabecera_minada = minar_altura_1(&nodo, coinbase.clone(), 51);
        let hash = cabecera_minada.block_hash();
        let mut coinbase_viciada = coinbase;
        coinbase_viciada.outputs[0].value = Amount::nuevo(51).expect("importe representable");

        let resultado = nodo.admitir_pow_interno(
            cabecera_minada,
            vec![coinbase_viciada],
            vec![Vec::new()],
            0,
            true,
            true,
        );
        assert!(
            resultado.is_err(),
            "la coinbase con importe incorrecto debe rechazarse"
        );
        assert!(
            !nodo.cadena.es_valido(&hash),
            "el bloque rechazado no debe quedar admitido en zx-cadena"
        );

        // La corrección: admitir se intenta **antes** de persistir, así que un rechazo no deja
        // ninguna entrada fantasma en el almacén.
        let longitud_tras_rechazo = nodo
            .almacen
            .longitud_registro()
            .expect("longitud del almacén");
        assert_eq!(
            longitud_tras_rechazo, 1,
            "el bloque rechazado NO debe persistirse: el registro solo tiene el génesis"
        );

        drop(nodo);

        // El reinicio ya no repite ninguna entrada fantasma: debe funcionar sin más.
        let reinicio = Nodo::arrancar(&cfg);
        if let Err(e) = &reinicio {
            eprintln!("RI-3c (corregido): Nodo::arrancar (reinicio) devolvió Err inesperado: {e}");
        }
        assert!(
            reinicio.is_ok(),
            "el reinicio debe funcionar: el bloque rechazado nunca se persistió, así que no hay \
             nada que repetir ni que vuelva a fallar"
        );
    }

    /// **Punto de inyección de fallo entre admitir y persistir** (decisión 7, paso previo): se
    /// admite un bloque PoW **válido** en `zx-cadena` (memoria) replicando exactamente los pasos
    /// de `admitir_pow_interno` hasta ese punto, y se simula la caída del proceso **sin** llegar a
    /// `almacen.admitir` (el paso siguiente, que esta prueba omite a propósito). Comprueba que:
    /// (a) nada se difunde — estructuralmente imposible, porque `difundir_si_hay_red` solo se
    /// llama *después* de que `admitir_pow_interno` devuelva `Ok`, y aquí nunca se completa esa
    /// llamada; y (b) el nodo reinicia bien — el bloque "caído" no está en el almacén, así que el
    /// reinicio simplemente no lo ve, sin fallar ni dejar rastro.
    #[test]
    fn fallo_entre_admitir_y_persistir_no_deja_rastro_y_el_reinicio_funciona() {
        use zx_cadena::BloqueCadena;
        use zx_consensus::genesis::HASH_GENESIS_DEV;
        use zx_consensus::transicion::{BloqueTransicion, HechosCabecera};
        use zx_core::digest::Digest;
        use zx_core::{BlockHash, trabajo_bloque};

        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = cfg_de_test(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
        let clave = nodo.claves.first().expect("al menos una clave").pk;

        let coinbase = pow::construir_coinbase_pow(clave, 1);
        let cabecera_minada = minar_altura_1(&nodo, coinbase.clone(), 50); // subsidio exacto: válido
        let hash = cabecera_minada.block_hash();

        // Replica el paso "admitir en zx-cadena" de `admitir_pow_interno`, **sin** el paso
        // siguiente (`almacen.admitir`) — exactamente el instante en que un `SIGKILL` real
        // interrumpiría entre los dos.
        let target = zx_core::decodificar_con(
            zx_consensus::PARAMETROS_POW_DEV.bits_iniciales,
            &zx_consensus::PARAMETROS_POW_DEV.limites,
        )
        .expect("bits decodifica");
        let trabajo = trabajo_bloque(target).expect("trabajo del bloque");
        let hechos = HechosCabecera::PoW {
            hash,
            padre: cabecera_minada.prev_hash,
            altura: cabecera_minada.height,
            trabajo,
            pow_valido: true,
        };
        let bt = BloqueTransicion::nuevo(hechos, vec![(coinbase, vec![Vec::new()])]);
        nodo.cadena
            .admitir(BloqueCadena::Pow(bt))
            .expect("un bloque válido se admite en memoria");
        assert!(
            nodo.cadena.es_valido(&hash),
            "el bloque queda admitido en memoria (paso 1, ya ocurrió)"
        );

        // "Caída": el proceso termina aquí, sin haber llegado a `almacen.admitir` (paso 2) ni,
        // mucho menos, a la difusión (paso 3, posterior en el llamante real). No hay manejo de red
        // en este nodo de test, así que "no se difunde" es además estructuralmente cierto: no hay
        // ningún `ManijaRed` al que `difundir_si_hay_red` pudiera llamar.
        assert!(
            nodo.red.is_none(),
            "sin red conectada: no hay a quién difundir nada"
        );
        let longitud_antes_de_caer = nodo
            .almacen
            .longitud_registro()
            .expect("longitud del almacén");
        assert_eq!(
            longitud_antes_de_caer, 1,
            "el bloque admitido en memoria todavía NO está en el almacén: la caída simulada \
             ocurre exactamente antes de persistir"
        );
        drop(nodo);

        // El reinicio: el bloque "caído" no está en el almacén, así que sencillamente no existe
        // para el nodo que reinicia — ni error, ni entrada fantasma, ni doble firma observable
        // (nunca se difundió; RI-2b quedaba a salvo por eso, no por el orden de escritura).
        let reinicio = Nodo::arrancar(&cfg).expect("el reinicio debe funcionar sin problema");
        assert_eq!(
            reinicio.historial_pow.len(),
            1,
            "el reinicio solo ve el génesis: el bloque de altura 1 nunca se persistió"
        );
        assert_eq!(
            reinicio.headers_pow.keys().find(|h| **h == hash),
            None,
            "el bloque que 'cayó' entre admitir y persistir no reaparece tras el reinicio"
        );
        // El génesis dev es una constante fija; comprobación de sanidad de que el reinicio partió
        // del mismo génesis, no de uno distinto por accidente.
        assert_eq!(
            reinicio.historial_pow[0].block_hash(),
            BlockHash::from_digest(Digest::from_bytes(HASH_GENESIS_DEV))
        );
    }
}

/// `ORDEN-W06d6` decisión 5: test pendiente de `ORDEN-W06d5` (la cola de `post_pendientes`) — se
/// verificaba solo con ejecuciones reales, sin test unitario del propio tope.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "el test falla con panic por diseño"
)]
mod pruebas_cola_post_pendientes {
    use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_core::wire_dag::{BloqueDag, JustificacionPot, PotCheckpoints};

    use super::{Config, Nodo, Red};

    fn cabecera_post(slot: u64) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xa8b4_66a7,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([(slot % 251) as u8; 32])),
            timestamp: 1_000 + slot,
            height: 0,
            slot,
            pot_output: [0; 16],
            rango_solucion: 1,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0xAA; 32])),
            padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([0xEE; 32])), &[])
                .unwrap(),
            sello: [0; 64],
        }
    }

    fn bloque_post_de_prueba(slot: u64) -> BloqueDag {
        let portador = PotCheckpoints::desde_outputs([[0; 16]; 8]);
        let justificacion = JustificacionPot::nueva(vec![portador]).unwrap();
        BloqueDag::nuevo(cabecera_post(slot), justificacion, Vec::new(), Vec::new()).unwrap()
    }

    fn nodo_de_prueba(dir: &std::path::Path) -> Nodo {
        let cfg = Config {
            dir_datos: dir.join("datos"),
            ruta_registro: dir.join("registro.jsonl"),
            red: Red::Dev,
            semilla: 1,
            indices_claves: vec![0],
            n_dev: 16,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: Some(0),
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        };
        Nodo::arrancar(&cfg).expect("arranque limpio")
    }

    /// **Regresión de la decisión 3 extendida (`ORDEN-W06d5`).** La cola de `Pendiente` está
    /// acotada a `TOPE_POST_PENDIENTES` (64): superarlo descarta el más viejo (FIFO), nunca crece
    /// sin límite.
    #[test]
    fn la_cola_de_pendientes_esta_acotada_y_descarta_el_mas_viejo() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = nodo_de_prueba(dir.path());

        assert!(nodo.post_pendientes.is_empty());

        // Encolar bastantes más que el tope: cada slot es distinto para poder identificar cuál
        // sobrevive.
        let total = super::TOPE_POST_PENDIENTES * 2;
        for slot in 0..total {
            nodo.encolar_post_pendiente(
                bloque_post_de_prueba(slot as u64),
                std::time::Instant::now(),
            );
        }

        assert_eq!(
            nodo.post_pendientes.len(),
            super::TOPE_POST_PENDIENTES,
            "la cola nunca debe superar el tope declarado"
        );
        // FIFO: sobreviven los `TOPE_POST_PENDIENTES` últimos, no los primeros.
        let primero_que_sobrevive = nodo.post_pendientes.front().expect("no vacía");
        assert_eq!(
            primero_que_sobrevive.0.cabecera.slot,
            (total - super::TOPE_POST_PENDIENTES) as u64,
            "el más viejo de los que sobreviven es exactamente el primero no descartado"
        );
        let ultimo = nodo.post_pendientes.back().expect("no vacía");
        assert_eq!(ultimo.0.cabecera.slot, (total - 1) as u64);
    }
}

/// `ORDEN-W07a-R`: cobertura de eventos de diagnóstico que no aparecen en V3. Los tres se emiten en
/// rutas que un nodo sin red puede recorrer con bloques construidos a mano (sin minar); así cada uno
/// queda producido al menos una vez por un test, como pide la tabla de cobertura de la orden.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "el test falla con panic por diseño"
)]
mod pruebas_diagnostico_registro {
    use std::time::Instant;

    use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
    use zx_core::preimage::block::BlockHeader;
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_core::wire_dag::{JustificacionPot, PotCheckpoints};
    use zx_p2p::entrante::VeredictoFinal;
    use zx_p2p::mensaje::BloqueRed;

    use super::{Config, Nodo, Red};

    fn cfg(dir: &std::path::Path) -> Config {
        Config {
            dir_datos: dir.join("datos"),
            ruta_registro: dir.join("registro.jsonl"),
            red: Red::Dev,
            semilla: 1,
            indices_claves: vec![0],
            n_dev: 16,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: Some(0),
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        }
    }

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn bloque_pow_red(nonce: u64, prev: BlockHash) -> BloqueRed {
        BloqueRed::Pow {
            cabecera: BlockHeader {
                consensus_branch_id: 0xa8b4_66a7,
                prev_hash: prev,
                merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x33; 32])),
                timestamp: 1_000 + nonce,
                bits: 0x1c07_fff8,
                nonce,
                height: 1,
            },
            txs: Vec::new(),
            testigos: Vec::new(),
        }
    }

    fn bloque_post_red(slot: u64, padre: BlockHash) -> BloqueRed {
        let cabecera = DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xa8b4_66a7,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x44; 32])),
            timestamp: 1_000 + slot,
            height: 0,
            slot,
            pot_output: [0; 16],
            rango_solucion: 1,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x55; 32])),
            padres: PadresDag::nuevo(padre, &[]).unwrap(),
            sello: [0; 64],
        };
        let portador = PotCheckpoints::desde_outputs([[0; 16]; 8]);
        let justificacion = JustificacionPot::nueva(vec![portador]).unwrap();
        BloqueRed::Post {
            cabecera,
            justificacion,
            txs: Vec::new(),
            testigos: Vec::new(),
        }
    }

    fn registro(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("registro.jsonl")).expect("leer registro")
    }

    /// Un PoST de red en fase PoW pura (sin candidatos) deja la traza del §1 bis
    /// `bloque_post_de_red_sin_terminal`.
    #[test]
    fn un_post_sin_terminal_candidato_traza_sin_terminal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = Nodo::arrancar(&cfg(dir.path())).expect("arranque limpio");
        let bloque = bloque_post_red(1, h(0xAB));
        let veredicto = nodo.intentar_admitir_bloque_red(&bloque, None, Instant::now());
        assert_eq!(veredicto, VeredictoFinal::Ignorar);
        let texto = registro(dir.path());
        assert!(
            texto.contains("\"tipo\":\"bloque_post_de_red_sin_terminal\""),
            "falta bloque_post_de_red_sin_terminal: {texto}"
        );
    }

    /// El cupo por padre del depósito de huérfanos, al llenarse, traza `huerfano_desalojado`.
    #[test]
    fn el_cupo_por_padre_traza_el_desalojo_de_huerfanos() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = Nodo::arrancar(&cfg(dir.path())).expect("arranque limpio");
        // Mismo padre ausente para todos: al pasar de `MAX_HUERFANOS_POR_PADRE` hay desalojo FIFO.
        let padre = h(0xCD);
        for i in 0..=(crate::red::MAX_HUERFANOS_POR_PADRE as u64) {
            let bloque = bloque_pow_red(i, padre);
            let _ = nodo.intentar_admitir_bloque_red(&bloque, None, Instant::now());
        }
        let texto = registro(dir.path());
        assert!(
            texto.contains("\"tipo\":\"huerfano_desalojado\""),
            "falta huerfano_desalojado: {texto}"
        );
    }

    /// Un huérfano que sale del depósito al resolverse su padre traza `huerfano_resuelto`.
    #[test]
    fn un_huerfano_retirado_del_deposito_traza_su_resolucion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = Nodo::arrancar(&cfg(dir.path())).expect("arranque limpio");
        let padre = h(0xEE);
        let bloque = bloque_pow_red(7, padre);
        let _ = nodo.intentar_admitir_bloque_red(&bloque, None, Instant::now());
        // Simula que `padre` acaba de admitirse: el depósito entrega al hijo y este se reintenta.
        nodo.resolver_huerfanos_de(padre);
        let texto = registro(dir.path());
        assert!(
            texto.contains("\"tipo\":\"huerfano_resuelto\""),
            "falta huerfano_resuelto: {texto}"
        );
    }
}

/// `ORDEN-W06d10-B`: X1/X2/X3 no penalizan al par en ninguna de las dos rutas y lo demostrablemente
/// inválido sigue penalizando (V1/V2). Bloque PoW de altura 1 con **PoW real** minado, para que X1
/// (timestamp futuro) falle exactamente en la comprobación FTL y no antes.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño"
)]
mod pruebas_w06d10b {
    use core::sync::atomic::AtomicBool;
    use std::time::Instant;

    use zx_consensus::{PARAMETROS_POW_DEV, Sha3Dev, minar};
    use zx_core::digest::Digest;
    use zx_core::preimage::block::{BlockHeader, merkle_root};
    use zx_core::{Amount, BlockHash, Tx, decodificar_con, txid};
    use zx_p2p::entrante::VeredictoFinal;
    use zx_p2p::mensaje::BloqueRed;

    use super::{Config, ErrorNodo, Nodo, Red};
    use crate::pow;
    use crate::rechazo::ClasificacionRechazo;

    fn cfg(dir: &std::path::Path) -> Config {
        Config {
            dir_datos: dir.join("datos"),
            ruta_registro: dir.join("registro.jsonl"),
            red: Red::Dev,
            semilla: 7,
            indices_claves: vec![0],
            n_dev: 16,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: Some(0),
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        }
    }

    /// `FTL_dev = N·T/20 = 20·2/20 = 2 s` (`PARAMETROS_POW_DEV`): margen conocido de X1.
    const FTL_DEV_SEG: u64 = 2;

    fn ahora_seg() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("reloj posterior a 1970")
            .as_secs()
    }

    /// Cabecera PoW de altura 1 sobre el génesis del nodo con la `coinbase` dada y `timestamp`
    /// elegido, con PoW real minado. `bits`/target son los iniciales dev: un bloque válido.
    fn cabecera_altura_1(nodo: &Nodo, coinbase: Tx, timestamp: u64) -> BlockHeader {
        let genesis = nodo.historial_pow[nodo.historial_pow.len() - 1];
        let txid_coinbase = txid(&coinbase, nodo.cbid);
        let target = decodificar_con(
            PARAMETROS_POW_DEV.bits_iniciales,
            &PARAMETROS_POW_DEV.limites,
        )
        .expect("bits_iniciales decodifica");
        let cabecera_base = BlockHeader {
            consensus_branch_id: nodo.cbid,
            prev_hash: genesis.block_hash(),
            merkle_root: merkle_root(&[txid_coinbase]),
            timestamp,
            bits: PARAMETROS_POW_DEV.bits_iniciales,
            nonce: 0,
            height: 1,
        };
        let cancelar = AtomicBool::new(false);
        minar(&cabecera_base, target, &Sha3Dev, u64::MAX, &cancelar)
            .expect("un PoW dev se encuentra en ~2^17 intentos")
    }

    fn coinbase_valida(nodo: &Nodo) -> Tx {
        let clave = nodo.claves.first().expect("al menos una clave").pk;
        pow::construir_coinbase_pow(clave, 1)
    }

    fn bloque_pow_red(cabecera: BlockHeader, coinbase: Tx) -> BloqueRed {
        BloqueRed::Pow {
            cabecera,
            txs: vec![coinbase],
            testigos: vec![Vec::new()],
        }
    }

    fn registro(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("registro.jsonl")).expect("leer registro")
    }

    /// `ORDEN-W06d10-B` **X1** en las dos rutas: un PoW con `timestamp > reloj + FTL` (FTL dev
    /// `= 20·2/20 = 2 s`) es `Ignorar`, no se cachea ni penaliza, y al reenviarlo con el reloj
    /// local ya al día se admite (C-TS-03: se difiere, no se castiga). El reloj se inyecta
    /// (`reloj_local_simulado`) para no depender del reloj real de la máquina.
    #[test]
    fn x1_timestamp_futuro_se_ignora_y_se_admite_al_avanzar_el_reloj() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = Nodo::arrancar(&cfg(dir.path())).expect("arranque limpio");
        let genesis_ts = i64::try_from(nodo.historial_pow[0].timestamp).unwrap_or(0);
        let reloj0 = genesis_ts + 1000;
        nodo.reloj_local_simulado = Some(reloj0);
        // `FTL_dev + 2 s`: por encima del FTL de 2 s (y con margen).
        let ts = u64::try_from(reloj0 + (FTL_DEV_SEG as i64) + 2).expect("timestamp representable");
        let cabecera = cabecera_altura_1(&nodo, coinbase_valida(&nodo), ts);
        let hash = cabecera.block_hash();
        let bloque = bloque_pow_red(cabecera, coinbase_valida(&nodo));

        // Ruta gossip (`origen = None`).
        assert_eq!(
            nodo.intentar_admitir_bloque_red(&bloque, None, Instant::now()),
            VeredictoFinal::Ignorar,
            "C-TS-03: el bloque futuro se difiere, no se rechaza"
        );
        assert!(
            nodo.cadena.motivo(&hash).is_none(),
            "X1 no debe cachearse como inválido en zx-cadena"
        );
        assert!(
            !nodo.headers_pow.contains_key(&hash),
            "X1 no debe cachearse en headers_pow"
        );
        let texto = registro(dir.path());
        assert!(
            texto.contains("\"tipo\":\"bloque_red_vista_local\""),
            "falta la traza de vista local: {texto}"
        );
        assert!(
            !texto.contains("\"tipo\":\"par_penalizado\""),
            "X1 no debe penalizar al par: {texto}"
        );

        // El reloj local avanza (la vista cambia): el mismo bloque vuelve a juzgarse por la ruta de
        // sincronización y pasa.
        nodo.reloj_local_simulado = Some(reloj0 + (FTL_DEV_SEG as i64) + 2);
        assert_eq!(
            nodo.intentar_admitir_bloque_red(
                &bloque,
                Some(libp2p::PeerId::random()),
                Instant::now()
            ),
            VeredictoFinal::Aceptar,
            "con el reloj al día el mismo bloque debe admitirse"
        );
        assert!(nodo.cadena.es_valido(&hash));
        assert!(registro(dir.path()).contains("\"tipo\":\"bloque_red_admitido\""));
    }

    /// `ORDEN-W06d10-B` **X3** en las dos rutas: un fallo **local** (persistencia/servicio
    /// simulado) es `Ignorar`, queda registrado con su motivo y no penaliza; sin el fallo, el mismo
    /// bloque válido se admite (no quedó cacheado).
    #[test]
    fn x3_fallo_local_se_ignora_y_se_registra() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = Nodo::arrancar(&cfg(dir.path())).expect("arranque limpio");
        let cabecera = cabecera_altura_1(&nodo, coinbase_valida(&nodo), ahora_seg());
        let hash = cabecera.block_hash();
        let bloque = bloque_pow_red(cabecera, coinbase_valida(&nodo));

        nodo.fallo_local_simulado = Some("persistencia simulada de prueba".to_string());
        assert_eq!(
            nodo.intentar_admitir_bloque_red(
                &bloque,
                Some(libp2p::PeerId::random()),
                Instant::now()
            ),
            VeredictoFinal::Ignorar,
            "un fallo local no es defecto del candidato"
        );
        let texto = registro(dir.path());
        assert!(
            texto.contains("\"tipo\":\"bloque_red_vista_local\""),
            "falta la traza del fallo local: {texto}"
        );
        assert!(
            texto.contains("persistencia simulada de prueba"),
            "el motivo local debe quedar visible: {texto}"
        );
        assert!(!texto.contains("\"tipo\":\"par_penalizado\""), "{texto}");
        assert!(
            !texto.contains("\"tipo\":\"bloque_red_admitido\""),
            "{texto}"
        );
        assert!(nodo.cadena.motivo(&hash).is_none());

        // Sin fallo, el bloque válido se admite: el `Ignorar` no dejó nada cacheado.
        assert_eq!(
            nodo.intentar_admitir_bloque_red(&bloque, None, Instant::now()),
            VeredictoFinal::Aceptar
        );
    }

    /// `ORDEN-W06d10-B` **V2** (regresión): un bloque **demostrablemente** inválido (coinbase que
    /// paga de más, `ErrEmision`) sigue dando `Rechazar` en las dos rutas, también cuando ya está
    /// cacheado el motivo.
    #[test]
    fn v2_defecto_demostrable_sigue_rechazando() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = Nodo::arrancar(&cfg(dir.path())).expect("arranque limpio");
        let clave = nodo.claves.first().expect("al menos una clave").pk;
        let mut coinbase = pow::construir_coinbase_pow(clave, 1);
        let doble = coinbase.outputs[0]
            .value
            .brek()
            .checked_mul(2)
            .expect("sin desbordar");
        coinbase.outputs[0].value = Amount::nuevo(doble).expect("importe representable");
        let cabecera = cabecera_altura_1(&nodo, coinbase.clone(), ahora_seg());
        let hash = cabecera.block_hash();
        let bloque = bloque_pow_red(cabecera, coinbase);

        // Primer intento (gossip): defecto demostrable del candidato → Rechazar.
        assert_eq!(
            nodo.intentar_admitir_bloque_red(&bloque, None, Instant::now()),
            VeredictoFinal::Rechazar
        );
        // El motivo queda cacheado; un reenvío por sincronización tampoco se libra.
        assert!(nodo.cadena.motivo(&hash).is_some());
        assert_eq!(
            nodo.intentar_admitir_bloque_red(
                &bloque,
                Some(libp2p::PeerId::random()),
                Instant::now()
            ),
            VeredictoFinal::Rechazar
        );
        assert!(
            registro(dir.path()).contains("\"tipo\":\"bloque_red_rechazado\""),
            "lo demostrablemente inválido debe seguir registrándose como rechazo"
        );
    }

    /// El mapeo de errores del borde de red: solo un defecto atribuible al candidato penaliza; un
    /// fallo local (`Otro`/`Almacen`/…) o una clasificación de vista local, no.
    #[test]
    fn solo_el_defecto_del_candidato_penaliza() {
        let hash = BlockHash::from_digest(Digest::from_bytes([0x42; 32]));
        let con_clasificacion = |clasificacion| ErrorNodo::BloquePropioRechazado {
            hash,
            motivo: "prueba".to_string(),
            clasificacion,
        };
        assert!(super::error_atribuible_al_candidato(&con_clasificacion(
            ClasificacionRechazo::Interno
        )));
        assert!(super::error_atribuible_al_candidato(&con_clasificacion(
            ClasificacionRechazo::Legitimo
        )));
        for local in [
            ClasificacionRechazo::VistaLocal,
            ClasificacionRechazo::Pendiente,
            ClasificacionRechazo::ImposibleSinPenalizar,
        ] {
            assert!(
                !super::error_atribuible_al_candidato(&con_clasificacion(local)),
                "{local:?}"
            );
        }
        assert!(!super::error_atribuible_al_candidato(&ErrorNodo::Otro(
            "persistencia simulada".to_string()
        )));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]
mod pruebas_eclr2 {
    use super::*;
    use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
    use zx_core::{Amount, ClavePublica as ClaveEd, OperacionAlmacenamiento};
    use zx_dag::IdentidadTicket;
    use zx_dag::ghostdag::IdentidadGhostdag;
    use zx_votos::{ClavePublica as ClaveBls, ClaveSecreta};

    pub(super) fn hash_u32(n: u32) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&n.to_be_bytes());
        BlockHash::from_digest(Digest::from_bytes(bytes))
    }

    fn subsidio_pow(_: u32) -> Amount {
        Amount::nuevo(10).unwrap()
    }

    fn subsidio_post(_: u64) -> Amount {
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

    /// ECL-R2a-5 · Subsidio PoST alto: permite fondear la garantía (q_sec = 140) del productor en
    /// un solo bloque y habilitar el alta real de sector dentro de la `Cadena`.
    fn subsidio_post_grande(_: u64) -> Amount {
        Amount::nuevo(10_000).unwrap()
    }

    pub(super) fn params_subsidio(f_slots: Option<u64>) -> ParametrosTransicion {
        let mut p = params(f_slots);
        p.subsidio_post = subsidio_post_grande;
        p
    }

    pub(super) fn tx_coinbase_post(clave: ClaveEd, importe: i64, slot: u64) -> Tx {
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

    pub(super) fn genesis() -> BloqueCadena {
        BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis { hash: hash_u32(0) },
            Vec::new(),
        ))
    }

    pub(super) fn pow_terminal(id: u32, trabajo: u64) -> BloqueCadena {
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

    /// ECL-R2a-5 · Bloque PoST con productor y txs explícitos, para la `Cadena` real que admite y
    /// aplica el `0x04` (sin inyectar estado ni sustituir la `Cadena`).
    pub(super) fn post_con_txs(
        id: u32,
        padres: Vec<BlockHash>,
        slot: u64,
        sr: u64,
        productor: ClaveEd,
        txs: Vec<(Tx, Vec<Vec<u8>>)>,
    ) -> BloqueCadena {
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
            txs,
        })
    }

    /// ECL-R2a-5 · Alta de sector v5 firmada por su `clave` (mismo camino que
    /// `aplicar_operacion_sector`), para que la `Cadena` real registre el sector que da peso a la
    /// tabla del certificado.
    pub(super) fn tx_alta_sector(
        productor: ClaveEd,
        sk: &ed25519_zebra::SigningKey,
        cbid: u32,
    ) -> (Tx, Vec<Vec<u8>>) {
        let tx = Tx {
            version: 5,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Sector {
                operacion: zx_core::OperacionSector::Alta {
                    clave: productor,
                    sector_index: 0,
                    version: 0,
                    r2: [3u8; 32],
                    history_size: 1 << 10,
                },
            },
        };
        let firma: [u8; 64] = sk.sign(&zx_core::mensaje_sector(&tx, cbid)).into();
        (tx, vec![firma.to_vec()])
    }

    /// ECL-R2a-5 · Registro v6 `0x03` de la clave BLS de voto con prueba de posesión real.
    pub(super) fn tx_clave_voto(
        productor: ClaveEd,
        sk: &ed25519_zebra::SigningKey,
        bls: &ClaveBls,
        sk_bls: &ClaveSecreta,
        cbid: u32,
    ) -> (Tx, Vec<Vec<u8>>) {
        let pop = zx_votos::probar_posesion(sk_bls);
        let tx = Tx {
            version: 6,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::PruebaAlmacenamiento {
                operacion: OperacionAlmacenamiento::ClaveVoto {
                    clave: productor,
                    clave_bls: bls.bytes(),
                    prueba_posesion: pop.bytes(),
                },
            },
        };
        let firma: [u8; 64] = sk.sign(&zx_core::mensaje_almacenamiento(&tx, cbid)).into();
        (tx, vec![firma.to_vec()])
    }

    /// ECL-R2a-5 · Par (clave pública, secreta) Ed25519 real para firmar los testigos de las txs v6.
    pub(super) fn productor_firmante() -> (ClaveEd, ed25519_zebra::SigningKey) {
        let sk = ed25519_zebra::SigningKey::from([0x5a; 32]);
        let vk = ed25519_zebra::VerificationKey::from(&sk);
        (ClaveEd::desde_bytes(vk.into()), sk)
    }

    /// ECL-R2a-4 · Puerto TCP creciente para el test de red real, fuera del rango de `red_tcp.rs`
    /// y `dial_reintento.rs` para no chocar si los binarios corren en paralelo.
    fn puerto_d5() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static SIGUIENTE: AtomicU16 = AtomicU16::new(41_701);
        SIGUIENTE.fetch_add(1, Ordering::Relaxed)
    }

    /// Config dev para las pruebas de red de ECL-R2a que devuelve M9-a2 (mismo perfil dev que el
    /// resto de arneses con `Cadena` real).
    fn config_red_eclr2(dir: &std::path::Path) -> Config {
        Config {
            dir_datos: dir.join("datos"),
            ruta_registro: dir.join("registro.jsonl"),
            red: Red::Dev,
            semilla: 0x5a5a,
            indices_claves: vec![0],
            n_dev: 32,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: None,
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: true,
            sin_revelacion: true,
        }
    }

    /// Cabecera PoST mínima con padres concretos (para la ruta real de admisión).
    fn cabecera_con_padres(
        slot: u64,
        padres: &[BlockHash],
    ) -> zx_core::preimage::dag::DagBlockHeader {
        use zx_core::digest::{BodyCommitment, Digest, MerkleRoot};
        use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
        let (seleccionado, extras) = padres
            .split_first()
            .expect("la cabecera necesita al menos un padre");
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xa8b4_66a7,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([(slot % 251) as u8; 32])),
            timestamp: 1_000 + slot,
            height: 0,
            slot,
            pot_output: [0; 16],
            rango_solucion: 1,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0xAA; 32])),
            padres: PadresDag::nuevo(*seleccionado, extras).unwrap(),
            sello: [0; 64],
        }
    }

    /// D5 (ECL-R2a-4): la petición pendiente sale por el camino de red **real** (`ManijaRed` /
    /// `ManejoRed` de `red::arrancar_con_datos`, no `red_simulada`). Sin red/par no se marca; con un
    /// par real conectado, la petición se acepta y el par remoto la recibe y responde con el bloque,
    /// que llega al trabajo de sincronización. Fija además el límite exacto de deduplicación. †
    #[test]
    fn d5_peticion_real_por_red_y_limite_de_intentos() {
        use std::time::Duration;
        use zx_p2p::mensaje::BloqueRed;

        let dir = tempfile::tempdir().unwrap();
        let cfg = config_red_eclr2(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).unwrap();

        // Bloque real que el par remoto servirá; su hash es el candidato pendiente.
        let cabecera = cabecera_con_padres(200, &[hash_u32(1)]);
        let candidato = cabecera.block_hash();
        let bloque = BloqueRed::Post {
            cabecera,
            justificacion: zx_core::wire_dag::JustificacionPot::nueva(vec![
                zx_core::wire_dag::PotCheckpoints::desde_outputs([[0; 16]; 8]),
            ])
            .unwrap(),
            txs: Vec::new(),
            testigos: Vec::new(),
        };

        // Fase 1: sin red/par no se marca ni se pide (no se quema el intento).
        let _ = nodo.cadena.considerar_ancla_de_estado(9, candidato);
        assert!(nodo.cadena.ancla_pendiente());
        nodo.avisar_ancla_pendiente();
        assert_eq!(nodo.ancla_pendiente_solicitada, None);

        // Fase 2: red real. B (remoto) sirve el bloque; A (este nodo) lo pide. El saludo de B debe
        // declarar el **mismo** génesis/red que A o `zx-p2p` lo penaliza como ajeno.
        let dir_b = tempfile::tempdir().unwrap();
        let vista_b = Arc::new(VistaRed::nueva(nodo.vista_red.estado()));
        vista_b.registrar_post(candidato, bloque.clone());
        let registro_b = Arc::new(
            crate::registro::Registro::abrir(&dir_b.path().join("registro-b.jsonl")).unwrap(),
        );
        let addr_b: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", puerto_d5())
            .parse()
            .unwrap();
        let b = red::arrancar_con_datos(
            Some(addr_b.clone()),
            Vec::new(),
            vista_b,
            registro_b,
            None,
            Arc::clone(&nodo.mempool),
            crate::cli::OpcionesRegistro::apagado(),
        )
        .expect("red remota");
        let peer_b: libp2p::PeerId = b.peer_id.parse().expect("peer id remoto");

        let a = red::arrancar_con_datos(
            None,
            vec![addr_b],
            Arc::clone(&nodo.vista_red),
            Arc::clone(&nodo.registro),
            None,
            Arc::clone(&nodo.mempool),
            crate::cli::OpcionesRegistro::apagado(),
        )
        .expect("red local");
        let red::RedArrancada {
            runtime: _rt_a,
            manija,
            trabajo,
            peer_id: _,
        } = a;
        let _rt_b = b.runtime; // mantiene vivo el runtime remoto
        nodo.conectar_red(manija, trabajo);

        // Espera a la conexión real (evento `par_conectado` en el registro del nodo A).
        let limite = Instant::now() + Duration::from_secs(20);
        loop {
            let reg = std::fs::read_to_string(&cfg.ruta_registro).unwrap_or_default();
            if reg.contains("\"tipo\":\"par_conectado\"") {
                break;
            }
            assert!(
                Instant::now() < limite,
                "sin conexion real con el par: {reg}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }

        // Con par real, el encolado se acepta y se marca el intento.
        nodo.par_sync = Some(peer_b);
        nodo.avisar_ancla_pendiente();
        assert_eq!(nodo.ancla_pendiente_solicitada, Some((candidato, peer_b)));

        // El par remoto recibió la `Peticion::Bloques` y respondió con el bloque: llega al trabajo
        // de sincronización del nodo. Eso —no el `Ok` del enqueue— demuestra la recepción remota.
        let mut recibido = None;
        let limite = Instant::now() + Duration::from_secs(20);
        while Instant::now() < limite {
            if let Some(receptor) = nodo.trabajo_red.as_mut()
                && let Ok(TrabajoRed::BloqueDeSincronizacion { de, bloque, .. }) =
                    receptor.try_recv()
            {
                recibido = Some((de, bloque));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let (de, bloque_recibido) = recibido.expect("el par remoto respondio la peticion");
        assert_eq!(de, peer_b);
        assert_eq!(red::hash_de(&bloque_recibido), candidato);

        // Límite exacto declarado: **una petición por `(candidato, par)`**, con memoria constante del
        // último intento aceptado (no promete una vez por todos los pares históricos). Repetir no
        // reenvía; un candidato nuevo sí; A → B → A vuelve a pedir por la memoria del último par.
        nodo.avisar_ancla_pendiente();
        assert_eq!(nodo.ancla_pendiente_solicitada, Some((candidato, peer_b)));
        let candidato2 = hash_u32(8_888);
        let _ = nodo.cadena.considerar_ancla_de_estado(10, candidato2);
        nodo.avisar_ancla_pendiente();
        assert_eq!(nodo.ancla_pendiente_solicitada, Some((candidato2, peer_b)));
        let peer_c = libp2p::PeerId::random();
        nodo.par_sync = Some(peer_c);
        nodo.avisar_ancla_pendiente();
        assert_eq!(nodo.ancla_pendiente_solicitada, Some((candidato2, peer_c)));
        nodo.par_sync = Some(peer_b);
        nodo.avisar_ancla_pendiente();
        assert_eq!(nodo.ancla_pendiente_solicitada, Some((candidato2, peer_b)));

        let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap_or_default();
        assert!(registro.contains("\"tipo\":\"ancla_pendiente\""));
        assert!(registro.contains("\"tipo\":\"ancla_pendiente_solicitada\""));
    }

    /// ECL-R2a-5 · La `Post` propia en vuelo llega a una **iteración común del bucle de régimen**
    /// (`iteracion_regimen`, la misma que ejecuta `fase_regimen`) tras el eclipse: la despacha por la
    /// ruta real y la descarta sin admitir, persistir, difundir ni registrar `bloque_producido`, y
    /// sin responder al productor (queda aparcado). La **misma** iteración atiende trabajo de red
    /// real y conserva aviso/fichero; no reinicia ni apaga la red. †
    ///
    /// M9-a2 · el eclipse se monta con el fixture por peso de PD-1f (`0x09` válido en la rama en
    /// conflicto más allá de `F`), en lugar del antiguo `AnclaD2`; el ancla viva es el certificado
    /// por peso del motor.
    #[test]
    fn bucle_recibe_post_en_vuelo_y_sigue_atendiendo_red() {
        use zx_p2p::mensaje::BloqueRed;

        let dir = tempfile::tempdir().unwrap();
        let cfg = config_red_eclr2(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).unwrap();

        let cadena = super::pruebas_pd1f::cadena_fork_peso();
        let sk_bls = crate::votos::clave_voto_dev(0x5a5a, 0).unwrap();
        let pk_bls = sk_bls.clave_publica();
        let t0 = super::pruebas_pd1f::tabla_de(&cadena, 30);
        let candidato = *hash_u32(10).as_bytes();
        let h_t = zx_votos::hash_tabla(&t0);
        let (cert, tx) =
            super::pruebas_pd1f::cert_peso(&t0, 0, candidato, h_t, None, &sk_bls, &pk_bls);
        nodo.cadena = cadena;
        let pubs: Vec<zx_votos::ClavePublica> = t0
            .claves
            .iter()
            .map(|c| zx_votos::ClavePublica::desde_bytes(&c.clave).expect("clave BLS"))
            .collect();
        nodo.motor_votos
            .as_mut()
            .expect("motor por peso")
            .sembrar_punto_control_peso(t0, pubs, cert, &[])
            .expect("siembra del punto de control por peso");
        nodo.inspeccionar_certificados_peso_de_bloque(&[tx], 30);
        assert!(nodo.cadena.eclipse().is_some());

        // Trabajo de red real en la cola que el bucle drena (padre desconocido: no exige PoAS).
        let (tx_red, rx_red) = red::nueva_cola_trabajo_red();
        nodo.trabajo_red = Some(rx_red);
        let bloque_red = BloqueRed::Post {
            cabecera: cabecera_con_padres(300, &[hash_u32(9_001)]),
            justificacion: zx_core::wire_dag::JustificacionPot::nueva(vec![
                zx_core::wire_dag::PotCheckpoints::desde_outputs([[0; 16]; 8]),
            ])
            .unwrap(),
            txs: Vec::new(),
            testigos: Vec::new(),
        };
        let _ = tx_red.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
            de: libp2p::PeerId::random(),
            bloque: bloque_red,
            llegada: Instant::now(),
        });

        // `Post` propia en vuelo por el **mismo canal** que lee el bucle.
        let padres = nodo.cadena.tips_validas();
        assert!(!padres.is_empty(), "hay puntas para la plantilla");
        let bloque = zx_core::wire_dag::BloqueDag::nuevo(
            cabecera_con_padres(200, &padres[..1]),
            zx_core::wire_dag::JustificacionPot::nueva(vec![
                zx_core::wire_dag::PotCheckpoints::desde_outputs([[0; 16]; 8]),
            ])
            .unwrap(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let hash = bloque.cabecera.block_hash();
        let (tx_prod, rx_prod) = mpsc::channel::<MsgProductor>();
        let (tx_bucle, rx_bucle) = mpsc::channel::<MsgBucle>();
        tx_prod
            .send(MsgProductor::Candidata {
                id: 1,
                candidata: Box::new(bloque),
                instante_salida: Instant::now(),
                clave_indice: 0,
            })
            .unwrap();

        // Una iteración **común** del bucle real (`iteracion_regimen`, la misma que ejecuta
        // `fase_regimen`) recibe la `Post` en vuelo, drena la red y la despacha por la ruta real.
        let mut terminal = nodo.cadena.terminal().expect("terminal");
        let mut frontera_enviada = 0u64;
        let control = nodo
            .iteracion_regimen(&rx_prod, &tx_bucle, &mut terminal, &mut frontera_enviada)
            .unwrap();
        assert_eq!(control, ControlBucle::Continuar);
        assert!(
            !nodo.cadena.es_valido(&hash),
            "no se admite la salida propia en vuelo"
        );
        assert!(
            matches!(rx_bucle.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "no se responde al productor (queda aparcado)"
        );
        let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
        assert!(registro.contains("\"tipo\":\"bloque_propio_descartado\""));
        assert!(
            !registro.contains("\"tipo\":\"bloque_producido\""),
            "no se registra bloque_producido"
        );
        // La misma iteración atendió el trabajo de red real; el eclipse sigue enclavado.
        assert!(
            registro.contains("\"tipo\":\"bloque_recibido\""),
            "el bucle atiende el trabajo de red"
        );
        assert!(
            nodo.cadena.eclipse().is_some(),
            "el eclipse sigue enclavado"
        );
        assert!(nodo.motor_votos.is_some(), "no se apaga el ancla");

        // Aviso y fichero de recuperación se conservan.
        nodo.atender_modo_detenido().unwrap();
        assert!(
            nodo.dir_datos.join("recuperacion-eclipse.zxp").exists(),
            "se conserva el fichero de recuperacion"
        );
        let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
        assert!(registro.contains("\"tipo\":\"eclipse_detectado\""));

        // FV-N6-C7-2 · segunda vuelta del **mismo** bucle común (`iteracion_regimen`), sin nuevo
        // mensaje del productor y con trabajo de red que llega **después** de estar detenido: se
        // atiende red/sync, no se produce ni se vota, no se difunde bloque propio y el productor
        // sigue aparcado. Es el camino común, no un bucle alternativo de test.
        let recibidos_antes = registro.matches("\"tipo\":\"bloque_recibido\"").count();
        let bloque_red2 = BloqueRed::Post {
            cabecera: cabecera_con_padres(301, &[hash_u32(9_002)]),
            justificacion: zx_core::wire_dag::JustificacionPot::nueva(vec![
                zx_core::wire_dag::PotCheckpoints::desde_outputs([[0; 16]; 8]),
            ])
            .unwrap(),
            txs: Vec::new(),
            testigos: Vec::new(),
        };
        let _ = tx_red.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
            de: libp2p::PeerId::random(),
            bloque: bloque_red2,
            llegada: Instant::now(),
        });
        let control2 = nodo
            .iteracion_regimen(&rx_prod, &tx_bucle, &mut terminal, &mut frontera_enviada)
            .unwrap();
        assert_eq!(control2, ControlBucle::Continuar);
        let registro2 = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
        assert!(
            registro2.matches("\"tipo\":\"bloque_recibido\"").count() > recibidos_antes,
            "la segunda vuelta atiende el trabajo de red que llega tras detenerse"
        );
        assert!(
            !registro2.contains("\"tipo\":\"bloque_producido\""),
            "seguimos sin producir tras detenernos"
        );
        assert!(
            !registro2.contains("\"tipo\":\"voto_emitido\""),
            "seguimos sin votar tras detenernos"
        );
        assert!(
            matches!(rx_bucle.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "el productor sigue aparcado (sin respuesta propia)"
        );
        assert!(
            nodo.cadena.eclipse().is_some(),
            "el eclipse sigue enclavado en la segunda vuelta"
        );
    }

    /// REAN-2 · N6 · El guard de arranque **no** bloquea el avance de una instancia viva ni la
    /// reanudación con salto: con `C_m` adoptado y `m+1` abierta, `n = m+2` no es «hueco». La
    /// clasificación solo aplica sin instancia: `n <= m` espera, `n > m` abre el intento `n`.
    #[test]
    fn clasificacion_arranque_no_bloquea_avance_vivo() {
        assert_eq!(clase_arranque_votos(Some(6), Some(5), 7), None);
        assert_eq!(clase_arranque_votos(None, Some(5), 6), None);
        assert_eq!(clase_arranque_votos(None, Some(5), 4), Some("espera_reloj"));
        assert_eq!(clase_arranque_votos(None, Some(5), 7), None);
        assert_eq!(clase_arranque_votos(None, None, 3), None);
    }

    /// FV-N6-C7-2 · Contraste **rojo/verde** del guard de la propuesta C7 rechazada: la condición
    /// antigua (`n <= m || n > m+1`, sin comprobar si hay instancia viva) retornaba por «hueco» con
    /// `C_m` adoptado, `m+1` abierta y `n = m+2`, impidiendo cerrar `m+1`. La condición corregida
    /// devuelve `None` en ese mismo caso.
    #[test]
    fn rojo_del_guard_antiguo_de_c7() {
        let m = 5u64;
        let n = 7u64;
        let retornaba_antiguo = n <= m || n > m.saturating_add(1);
        assert!(
            retornaba_antiguo,
            "el guard antiguo retornaba por hueco (defecto reproducido)"
        );
        assert_eq!(
            clase_arranque_votos(Some(m + 1), Some(m), n),
            None,
            "el guard corregido no bloquea el avance vivo"
        );
    }
}
/// `ORDEN-IDX1` · Pruebas X2 (I3, diferencial del candidato de voto) y X3 (la pregunta falsable:
/// tiempos de las tres consultas con 100 / 2 000 / 20 000 bloques). Módulo **de pruebas**: accede a
/// `Nodo::candidato_votos` (privado) y a la referencia conservada solo para tests.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño"
)]
mod pruebas_idx1 {
    use std::time::Instant;

    use primitive_types::U256;
    use zx_cadena::{BloqueCadena, BloquePost, Cadena};
    use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
    use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Red, Tx};
    use zx_dag::IdentidadTicket;
    use zx_dag::ghostdag::IdentidadGhostdag;

    use super::{Config, LAG_CANDIDATO_VOTOS, Nodo};

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
        let digest = zx_core::sha3_256_publico(b"zx-idx1-pruebas");
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

    /// Cadena lineal de `n` bloques PoST sobre el terminal `1` (slots `1..=n`). Devuelve la cadena
    /// y el slot de su punta.
    fn cadena_lineal(n: usize) -> (Cadena, u64) {
        let mut cadena = Cadena::nueva(params(None), K, CBID_RED_DEV, MAX_PADRES);
        cadena.admitir(genesis()).unwrap();
        cadena.admitir(pow_terminal(1, 1)).unwrap();
        let mut padre = hash_u32(1);
        let mut slot = 0u64;
        for i in 0..n {
            slot += 1;
            let bloque = post(10 + i as u32, vec![padre], slot, 10);
            cadena.admitir(bloque.clone()).unwrap();
            padre = bloque.hash();
        }
        (cadena, slot)
    }

    fn config_de_test(dir: &std::path::Path) -> Config {
        Config {
            dir_datos: dir.join("datos"),
            ruta_registro: dir.join("registro.jsonl"),
            red: Red::Dev,
            semilla: 0x5a5a,
            indices_claves: vec![0],
            n_dev: 32,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: None,
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: true,
            sin_revelacion: true,
        }
    }

    /// VS-2 · `0x09` sintético con la ventana `n` y el candidato dados (solo importan esos campos
    /// para el observador del nodo).
    fn tx_certificado_peso(n: u64, candidato: BlockHash) -> Tx {
        let mut bytes = vec![0u8; 200];
        bytes[..8].copy_from_slice(&n.to_be_bytes());
        bytes[8..40].copy_from_slice(candidato.as_bytes());
        Tx {
            version: 6,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::PruebaAlmacenamiento {
                operacion: zx_core::OperacionAlmacenamiento::CertificadoPeso {
                    clave: ClavePublica::desde_bytes([9u8; 32]),
                    bytes,
                },
            },
        }
    }

    /// Cadena real con un estado inicial que ya trae la finalidad por votos de la ventana `n`
    /// sellando el bloque PoST `s` (en el DAG). El hash de la tabla es distinto del bloque: es el
    /// defecto E7.
    fn cadena_con_finalidad(n: u64, s: BlockHash) -> Cadena {
        let mut inicial = zx_consensus::transicion::Estado::inicial();
        inicial.finalidad_votos_n = n;
        inicial.finalidad_votos = Some(s);
        inicial.finalidad_votos_h_t = Some([0xEE; 32]);
        let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
            params(Some(5)),
            K,
            CBID_RED_DEV,
            MAX_PADRES,
            zx_consensus::transicion::ParametrosEvidencia::inactiva(),
            inicial,
        );
        cadena.admitir(genesis()).unwrap();
        cadena.admitir(pow_terminal(1, 1)).unwrap();
        cadena.admitir(post(11, vec![hash_u32(1)], 1, 1)).unwrap();
        cadena
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RD-4b · P1/P3: entrega de la tabla de pesos al director
    // ─────────────────────────────────────────────────────────────────────────

    /// RD-4b · un `ManijaRed` real con un canal de comandos **sin bucle** (seam de prueba de
    /// `zx_p2p::servicio::manejo_sin_bucle`), para ejercitar la entrega sin red real. El `Runtime`
    /// se devuelve para mantener vivo el `Handle`.
    fn manija_pesos(
        nodo: &Nodo,
        registro_activo: bool,
        capacidad: usize,
    ) -> (
        crate::red::ManijaRed,
        zx_p2p::servicio::GuardaCanal,
        tokio::runtime::Runtime,
    ) {
        let (manejo, guarda) = zx_p2p::servicio::manejo_sin_bucle(capacidad);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let manija = crate::red::manija_de_prueba(
            manejo,
            rt.handle().clone(),
            std::sync::Arc::clone(&nodo.vista_red),
            registro_activo,
        );
        (manija, guarda, rt)
    }

    /// RD-4b · nodo con ancla de votos `(3, hash_u32(11))` y la red de prueba ya conectada.
    fn nodo_con_ancla(
        dir: &std::path::Path,
        registro_activo: bool,
        capacidad: usize,
    ) -> (Nodo, zx_p2p::servicio::GuardaCanal, tokio::runtime::Runtime) {
        let cfg = config_de_test(dir);
        let mut nodo = Nodo::arrancar(&cfg).unwrap();
        nodo.cadena = cadena_con_finalidad(3, hash_u32(11));
        let _ = nodo.cadena.considerar_ancla_de_estado(3, hash_u32(11));
        let (manija, guarda, rt) = manija_pesos(&nodo, registro_activo, capacidad);
        nodo.red = Some(manija);
        (nodo, guarda, rt)
    }

    fn consultas_tabla_pesos() -> usize {
        super::CONSULTAS_TABLA_PESOS.with(std::cell::Cell::get)
    }

    /// **RD-4b · P1.** Un ancla nueva se entrega al director.
    #[test]
    fn rd4b_tabla_se_entrega_al_cambiar_el_ancla() {
        let dir = tempfile::tempdir().unwrap();
        let (mut nodo, mut guarda, _rt) = nodo_con_ancla(dir.path(), true, 16);
        let t0 = Instant::now();
        nodo.entregar_tabla_pesos(t0);
        let tablas = guarda.tablas_recibidas();
        assert_eq!(tablas.len(), 1, "la primera ancla se entrega");
        assert!(
            !tablas[0].is_empty(),
            "la tabla entregada lleva pesos certificados reales, no vacía"
        );
        // El ancla avanza de (3, h) a (4, h): es otra ancla.
        let _ = nodo.cadena.considerar_ancla_de_estado(4, hash_u32(11));
        nodo.entregar_tabla_pesos(t0 + std::time::Duration::from_secs(60));
        assert_eq!(
            guarda.tablas_recibidas().len(),
            1,
            "la segunda ancla se entrega"
        );
    }

    /// **RD-4b · P1 (control R1).** Con la misma ancla no se vuelve a entregar aunque pase `T_par`.
    #[test]
    fn rd4b_tabla_no_se_entrega_si_el_ancla_no_cambia() {
        let dir = tempfile::tempdir().unwrap();
        let (mut nodo, mut guarda, _rt) = nodo_con_ancla(dir.path(), true, 16);
        let t0 = Instant::now();
        nodo.entregar_tabla_pesos(t0);
        assert_eq!(guarda.tablas_recibidas().len(), 1);
        // Misma ancla (idempotente) y `T_par` cumplido: no debe entregarse otra vez.
        let _ = nodo.cadena.considerar_ancla_de_estado(3, hash_u32(11));
        nodo.entregar_tabla_pesos(t0 + std::time::Duration::from_secs(61));
        assert_eq!(
            guarda.tablas_recibidas().len(),
            0,
            "sin cambio de ancla no hay entrega"
        );
    }

    /// **RD-4b · P1 (control R2).** Un ancla nueva antes de `T_par` no se entrega; al cumplirlo, sí.
    #[test]
    fn rd4b_tabla_no_se_entrega_antes_de_t_par() {
        let dir = tempfile::tempdir().unwrap();
        let (mut nodo, mut guarda, _rt) = nodo_con_ancla(dir.path(), true, 16);
        let t0 = Instant::now();
        nodo.entregar_tabla_pesos(t0);
        assert_eq!(guarda.tablas_recibidas().len(), 1);
        let _ = nodo.cadena.considerar_ancla_de_estado(4, hash_u32(11));
        nodo.entregar_tabla_pesos(t0 + std::time::Duration::from_secs(59));
        assert_eq!(
            guarda.tablas_recibidas().len(),
            0,
            "antes de T_par no hay entrega"
        );
        nodo.entregar_tabla_pesos(t0 + std::time::Duration::from_secs(60));
        assert_eq!(
            guarda.tablas_recibidas().len(),
            1,
            "cumplido T_par, la ancla nueva se entrega"
        );
    }

    /// **RD-4b · P1.** Sin red no se consulta la cadena.
    #[test]
    fn rd4b_sin_red_no_se_calcula() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_de_test(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).unwrap();
        nodo.cadena = cadena_con_finalidad(3, hash_u32(11));
        let _ = nodo.cadena.considerar_ancla_de_estado(3, hash_u32(11));
        assert!(nodo.red.is_none());
        let antes = consultas_tabla_pesos();
        nodo.entregar_tabla_pesos(Instant::now());
        assert_eq!(consultas_tabla_pesos(), antes, "sin red no se consulta");
    }

    /// **RD-4b · P1.** Con el registro apagado no se consulta la cadena (se observa con el contador
    /// `CONSULTAS_TABLA_PESOS`, que solo incrementa la llamada real a `productores_en_ventana`).
    #[test]
    fn rd4b_registro_apagado_no_se_calcula() {
        let dir = tempfile::tempdir().unwrap();
        let (mut nodo, _guarda, _rt) = nodo_con_ancla(dir.path(), false, 16);
        let antes = consultas_tabla_pesos();
        nodo.entregar_tabla_pesos(Instant::now());
        assert_eq!(
            consultas_tabla_pesos(),
            antes,
            "con el registro apagado no se consulta la cadena"
        );
    }

    /// **RD-4b · P3 (control R3).** Con el canal de comandos lleno, fijar la tabla no bloquea (con
    /// plazo de 1 s: si la llamada tarda más, falla) y devuelve `false`.
    #[test]
    fn rd4b_entrega_no_bloquea_con_el_canal_lleno() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_de_test(dir.path());
        let nodo = Nodo::arrancar(&cfg).unwrap();
        let (manija, _guarda, _rt) = manija_pesos(&nodo, true, 1);
        let clave = crate::claves::ClaveDev::derivar(1, 0).pk;
        assert!(
            manija.fijar_tabla_pesos(vec![(clave, 1)]),
            "el primer envío cabe"
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            let r = manija.fijar_tabla_pesos(vec![(clave, 1)]);
            tx.send(r).ok();
            r
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(1)).is_ok(),
            "fijar_tabla_pesos se bloqueó con el canal lleno"
        );
        assert!(!h.join().unwrap(), "la tabla descartada devuelve false");
    }

    /// PD-1e · U4/E7 · corregido por VS-2 · **sin** finalidad aplicada en el estado seleccionado,
    /// un `0x09` sintético **no** escribe `certificado_peso_aplicado` (el ancla no puede ser el hash
    /// de la tabla ni un evento sin aplicación).
    #[test]
    fn pd1e_u4_observador_no_escribe_evento_sin_finalidad() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_de_test(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).unwrap();
        assert!(nodo.motor_votos.is_some());
        let tx = tx_certificado_peso(3, hash_u32(0xAB));
        let hash = BlockHash::from_digest(Digest::from_bytes([0x77; 32]));
        nodo.reconciliar_ancla_de_bloque(hash, std::slice::from_ref(&tx));
        let contenido = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
        assert!(
            !contenido.contains("\"tipo\":\"certificado_peso_aplicado\""),
            "sin finalidad no hay evento: {contenido}"
        );
    }

    /// VS-2 · W1 · V1 · con un `Nodo` real en modo peso: tras admitir un bloque con un `0x09`
    /// válido, el ancla de votos de la cadena es `(n, bloque sellado)` y el bloque está en el DAG.
    #[test]
    fn w1_ancla_peso_es_el_bloque_sellado() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_de_test(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).unwrap();

        let s = hash_u32(11);
        let cadena = cadena_con_finalidad(3, s);
        assert_eq!(
            cadena.estado_virtual().unwrap().finalidad_votos,
            Some(s),
            "el estado seleccionado sella el bloque PoST"
        );
        assert!(
            cadena.cadena_virtual().contains(&s),
            "el bloque sellado está en el DAG"
        );
        nodo.cadena = cadena;

        let tx = tx_certificado_peso(3, s);
        let hash = BlockHash::from_digest(Digest::from_bytes([0x77; 32]));
        nodo.reconciliar_ancla_de_bloque(hash, std::slice::from_ref(&tx));

        assert_eq!(
            nodo.cadena.ancla_votos(),
            Some((3, s)),
            "el ancla es (ventana, bloque sellado), no el hash de la tabla"
        );
        assert!(nodo.cadena.cadena_virtual().contains(&s));
        let contenido = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
        assert!(
            contenido.contains("\"tipo\":\"certificado_peso_aplicado\""),
            "el `0x09` que coincide con la finalidad deja su evento: {contenido}"
        );
    }

    /// VS-2 · W2 · V1 · un `0x09` de una ventana ya superada en el mismo bloque no escribe
    /// `certificado_peso_aplicado`.
    #[test]
    fn w2_certificado_de_ventana_superada_no_escribe_evento() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_de_test(dir.path());
        let mut nodo = Nodo::arrancar(&cfg).unwrap();

        let s = hash_u32(11);
        nodo.cadena = cadena_con_finalidad(3, s);

        let viejo = tx_certificado_peso(2, hash_u32(10));
        let bueno = tx_certificado_peso(3, s);
        let hash = BlockHash::from_digest(Digest::from_bytes([0x77; 32]));
        nodo.reconciliar_ancla_de_bloque(hash, &[viejo, bueno]);

        let contenido = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
        let aplicados: Vec<&str> = contenido
            .lines()
            .filter(|l| l.contains("\"tipo\":\"certificado_peso_aplicado\""))
            .collect();
        assert_eq!(
            aplicados.len(),
            1,
            "solo el `0x09` vigente deja evento: {contenido}"
        );
        assert!(
            aplicados[0].contains("\"n\":3"),
            "el evento es de la ventana vigente: {}",
            aplicados[0]
        );
    }

    /// VS-2 · W6 · V2 · al avanzar el reloj **slot a slot** en modo peso, cada ventana se abre.
    #[test]
    fn w6_cada_ventana_se_abre_slot_a_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config_de_test(dir.path());
        cfg.sin_voto = true;
        let mut nodo = Nodo::arrancar(&cfg).unwrap();
        nodo.candidato_votos_simulado = Some(hash_u32(1));
        let t = crate::perfil::parametros_votos_dev().t_inst.max(1);
        let mut abiertas = std::collections::BTreeSet::new();
        for slot in 0..(6 * t) {
            nodo.slot_votos_simulado = Some(slot);
            nodo.procesar_votos().expect("procesar_votos por slot");
            if let Some(n) = nodo
                .motor_votos
                .as_ref()
                .and_then(|m| m.ultima_ventana_abierta())
            {
                abiertas.insert(n);
            }
        }
        for n in 0..6u64 {
            assert!(
                abiertas.contains(&n),
                "la ventana {n} no se abrió al avanzar slot a slot: {abiertas:?}"
            );
        }
        let registro =
            std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
        for n in 0..6u64 {
            assert!(
                registro.lines().any(|l| {
                    l.contains("\"tipo\":\"ventana_abierta\"") && l.contains(&format!("\"n\":{n}"))
                }),
                "la ventana {n} no dejó ventana_abierta"
            );
        }
    }

    // ── VS-2 · W4/W5 · voto tardío por el borde del `Nodo` (salto de ventana) ──────────────────

    fn bls_vs2(i: u8) -> zx_votos::ClaveSecreta {
        let mut ikm = [0u8; 32];
        ikm[0] = i;
        ikm[31] = 0xA5;
        zx_votos::ClaveSecreta::generar(&ikm).unwrap()
    }

    /// Estado PoST con la clave Ed25519 `c` registrada (BLS `sk`) y `n_sectores` activos. Añade una
    /// segunda clave con más peso: así el voto propio no alcanza quórum y el cierre **no** certifica
    /// (el motor no avanza su base y la apertura posterior puede construir su tabla).
    fn estado_peso(
        n_sectores: usize,
        c: &ClavePublica,
        sk: &zx_votos::ClaveSecreta,
    ) -> zx_consensus::transicion::Estado {
        use zx_consensus::sectores::{
            ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId,
        };
        let p = ParametrosSector::dev();
        let mut est = zx_consensus::transicion::Estado::inicial();
        est.parametros_sector = p;
        est.fase = zx_consensus::transicion::Fase::PoST;
        let insertar = |est: &mut zx_consensus::transicion::Estado,
                        c: &ClavePublica,
                        sk: &zx_votos::ClaveSecreta,
                        n_sectores: usize| {
            est.claves_voto.insert(
                *c,
                ClaveVoto {
                    clave_bls: sk.clave_publica().bytes(),
                    prueba_posesion: [0u8; 96],
                },
            );
            for i in 0..n_sectores {
                let id = SectorId {
                    clave: *c,
                    sector_index: u16::try_from(i).unwrap(),
                    version: 0,
                };
                est.sectores.insert(
                    id,
                    RegistroSector {
                        id,
                        r2: [0; 4],
                        history_size: 1,
                        etapa: Etapa::Activo,
                        alta_slot: 0,
                        renovacion_slot: 1_000_000,
                        retiro_slot: -1,
                        fianza: p.q_sec,
                        aud_apertura: -1,
                        aud_contestada: -1,
                    },
                );
            }
            let mut g = zx_consensus::transicion::Garantia::nueva();
            g.activo = Amount::nuevo(1000).unwrap();
            est.garantias.insert(*c, g);
        };
        insertar(&mut est, c, sk, n_sectores);
        let c2 = ClavePublica::desde_bytes([0x22; 32]);
        let sk2 = bls_vs2(2);
        insertar(&mut est, &c2, &sk2, n_sectores.saturating_mul(2).max(1));
        // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
        let (con_cola, _u) =
            zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(&est, 100);
        con_cola
    }

    /// Nodo en modo peso con la clave propia registrada con peso en un estado real y un bloque PoST
    /// admitido (para que `candidato_votos` devuelva candidato).
    fn nodo_peso(dir: &std::path::Path, n_sectores: usize) -> Nodo {
        let mut cfg = config_de_test(dir);
        cfg.sin_voto = false;
        let mut nodo = Nodo::arrancar(&cfg).unwrap();
        let c = nodo.claves[0].pk;
        let sk = bls_vs2(1);
        let mut est = estado_peso(n_sectores, &c, &sk);
        // El génesis solo se admite desde `Fase::Genesis`; el corte PoW pasa la cadena a PoST.
        est.fase = zx_consensus::transicion::Fase::Genesis;
        let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
            params(Some(5)),
            K,
            CBID_RED_DEV,
            MAX_PADRES,
            zx_consensus::transicion::ParametrosEvidencia::inactiva(),
            est,
        );
        cadena.admitir(genesis()).unwrap();
        cadena.admitir(pow_terminal(1, 1)).unwrap();
        cadena.admitir(post(50, vec![hash_u32(1)], 1, 1)).unwrap();
        nodo.cadena = cadena;
        let mut motor = crate::votos::MotorVotos::nuevo(crate::votos::ConfigMotorVotos {
            perfil: crate::perfil::parametros_votos_dev(),
            claves: vec![sk],
            emitir_votos: true,
        });
        let d =
            crate::votos::DiarioVotos::nueva(dir.join("vs2-w45.registro"), CBID_RED_DEV).unwrap();
        motor.vincular_diario(d);
        nodo.motor_votos = Some(motor);
        nodo.slot_votos_simulado = Some(0);
        nodo
    }

    /// Aplica un bloque PoST vacío para disparar la liquidación de la ventana.
    fn aplica_post_peso(
        est: &zx_consensus::transicion::Estado,
        slot: u64,
    ) -> zx_consensus::transicion::Estado {
        let bloque = BloqueTransicion::nuevo(
            HechosCabecera::PoST {
                hash: hash_u32(0xE0),
                padre: hash_u32(0xE1),
                slot,
                productor: productor(),
                peso: 1,
                prueba_valida: true,
                requisito_declarado: 0,
            },
            Vec::new(),
        );
        let (nuevo, _) = zx_consensus::transicion::aplicar_con_undo(
            est,
            &bloque,
            &params(Some(5)),
            CBID_RED_DEV,
            &zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        )
        .expect("bloque PoST de liquidación");
        nuevo
    }

    /// VS-2 · W4 · con un `Nodo` real y el reloj saltando de la ventana 2 a la 4, queda encolado el
    /// `0x08` de la 3 **antes** del de la 4; el consenso lo acepta y, liquidada la ventana, la deuda
    /// de ausencia no crece. Sin V3 no hay `0x08` de la 3.
    #[test]
    fn w4_salto_encola_el_tardio_antes_del_voto_de_la_ventana() {
        let dir = tempfile::tempdir().unwrap();
        let mut nodo = nodo_peso(dir.path(), 2);
        let c = nodo.claves[0].pk;
        let sk = bls_vs2(1);
        let t = crate::perfil::parametros_votos_dev().t_inst.max(1);

        nodo.slot_votos_simulado = Some(2 * t);
        nodo.procesar_votos().expect("abrir ventana 2");
        assert_eq!(
            nodo.motor_votos
                .as_ref()
                .and_then(|m| m.ultima_ventana_abierta()),
            Some(2)
        );
        // Salto de la 2 a la 4: la 3 se pierde.
        nodo.slot_votos_simulado = Some(4 * t);
        nodo.procesar_votos().expect("salto a la ventana 4");

        let pos = |n: u64| {
            nodo.v6_pendientes
                .iter()
                .position(|p| p.clase == super::CLASE_VOTO_PROPIO && p.n == n)
        };
        let n3 = pos(3).expect("hay 0x08 de la ventana 3");
        let n4 = pos(4).unwrap_or_else(|| {
            panic!(
                "hay 0x08 de la ventana 4; propios={:?}",
                nodo.v6_pendientes
                    .iter()
                    .filter(|p| p.clase == super::CLASE_VOTO_PROPIO)
                    .map(|p| p.n)
                    .collect::<Vec<_>>()
            )
        });
        assert!(
            n3 < n4,
            "el 0x08 tardío de la 3 se encola antes que el de la 4"
        );

        // El consenso acepta el A3 y, tras liquidar, la deuda no crece.
        let ExtensionTx::PruebaAlmacenamiento { operacion } = &nodo.v6_pendientes[n3].tx.extension
        else {
            panic!("voto propio");
        };
        let zx_core::OperacionAlmacenamiento::VotoPropio { clave, .. } = operacion else {
            panic!("voto propio");
        };
        let mut est0 = estado_peso(2, &c, &sk);
        // Habilita la liquidación con cobro: tabla guardada de la ventana 3.
        let contenido = vec![
            zx_core::ClaveTablaVoto {
                clave_bls: sk.clave_publica().bytes(),
                peso: 2,
                activo: true,
                prueba: false,
                garantia: 2,
            },
            zx_core::ClaveTablaVoto {
                clave_bls: bls_vs2(2).clave_publica().bytes(),
                peso: 4,
                activo: true,
                prueba: false,
                garantia: 4,
            },
        ];
        est0.tablas_voto.insert(3, contenido);
        let (con_voto, _undo, r) = zx_consensus::transicion::votos::aplicar_voto_propio_con_undo(
            &est0,
            operacion,
            i64::try_from(3 * t).unwrap(),
        );
        r.expect("el consenso acepta el A3 tardío");
        assert!(
            con_voto
                .votantes_voto
                .get(&3)
                .is_some_and(|v| v.contains(clave)),
            "la clave consta en votantes_voto[3]"
        );
        // `cobrar_ausencia_ventana` solo acumula deuda para claves **ausentes** de
        // `votantes_voto[n]`; con el voto tardío aplicado, la deuda no crece.
        let liq_con = aplica_post_peso(&con_voto, 400);
        let liq_sin = aplica_post_peso(&est0, 400);
        let d_con = liq_con.deuda_ausencia.get(clave).copied().unwrap_or(0);
        let d_sin = liq_sin.deuda_ausencia.get(clave).copied().unwrap_or(0);
        assert!(
            d_con < d_sin,
            "con el voto tardío la deuda no crece (con={d_con}, sin={d_sin})"
        );
    }

    /// VS-2 · W5 · sin salto no hay voto tardío; un salto de más de 8 ventanas vota tarde solo las 8
    /// más recientes dentro de plazo, en orden creciente.
    #[test]
    fn w5_salto_grande_vota_solo_las_ocho_mas_recientes_en_orden() {
        let dir = tempfile::tempdir().unwrap();
        let mut nodo = nodo_peso(dir.path(), 2);
        let t = crate::perfil::parametros_votos_dev().t_inst.max(1);

        // Sin salto: 1 → 2 no genera tardío (solo los votos normales de sus ventanas).
        nodo.slot_votos_simulado = Some(t);
        nodo.procesar_votos().expect("abrir 1");
        nodo.slot_votos_simulado = Some(2 * t);
        nodo.procesar_votos().expect("abrir 2");
        let sin_salto: Vec<u64> = nodo
            .v6_pendientes
            .iter()
            .filter(|p| p.clase == super::CLASE_VOTO_PROPIO)
            .map(|p| p.n)
            .collect();
        assert_eq!(
            sin_salto,
            vec![1, 2],
            "sin salto no hay tardío: solo los votos normales 1 y 2"
        );

        // Salto de la 2 a la 21 (18 ventanas): solo las 8 más recientes 13..20, en orden.
        nodo.slot_votos_simulado = Some(21 * t);
        nodo.procesar_votos().expect("salto a la ventana 21");
        let votos: Vec<u64> = nodo
            .v6_pendientes
            .iter()
            .filter(|p| p.clase == super::CLASE_VOTO_PROPIO && p.n >= 4)
            .map(|p| p.n)
            .collect();
        assert_eq!(
            votos,
            (13..=21).collect::<Vec<u64>>(),
            "8 tardías (13..20) en orden y luego la 21"
        );
    }

    /// X2 · El candidato nuevo coincide con la referencia en cadenas con huecos de slot,
    /// bifurcaciones y reorganización (dos terminales; el de más trabajo cambia la selección).
    #[test]
    fn idx1_x2_candidato_igual_a_referencia() {
        let dir = tempfile::tempdir().unwrap();
        let mut nodo = Nodo::arrancar(&config_de_test(dir.path())).unwrap();
        let mut cadena = Cadena::nueva(params(None), K, CBID_RED_DEV, MAX_PADRES);
        cadena.admitir(genesis()).unwrap();
        cadena.admitir(pow_terminal(1, 1)).unwrap();
        cadena.admitir(pow_terminal(2, 3)).unwrap();
        // Rama del terminal 1 con huecos de slot crecientes.
        let mut p1 = hash_u32(1);
        let mut slot1 = 0u64;
        for i in 0..30u32 {
            slot1 += 1 + u64::from(i % 3);
            let b = post(100 + i, vec![p1], slot1, 10);
            cadena.admitir(b.clone()).unwrap();
            p1 = b.hash();
        }
        // Bifurcación: dos hijos del mismo padre (`p1`) en el terminal 1.
        for i in 0..2u32 {
            let b = post(200 + i, vec![p1], slot1 + 1 + u64::from(i), 10);
            cadena.admitir(b.clone()).unwrap();
        }
        // Rama del terminal 2 (más trabajo): reorganiza la selección hacia el terminal 2.
        let mut p2 = hash_u32(2);
        let mut slot2 = 0u64;
        for i in 0..40u32 {
            slot2 += 1;
            let b = post(300 + i, vec![p2], slot2, 1);
            cadena.admitir(b.clone()).unwrap();
            p2 = b.hash();
        }
        // PD-1e · E11 · dos bloques seguidos de la cadena seleccionada con el **mismo slot** que su
        // padre (la regla es `slot(padre) ≤ slot(hijo)`, no estricta).
        for i in 0..2u32 {
            let b = post(400 + i, vec![p2], slot2, 1);
            cadena.admitir(b.clone()).unwrap();
            p2 = b.hash();
        }
        nodo.cadena = cadena;
        assert_eq!(nodo.cadena.terminal(), Some(hash_u32(2)), "reorganiza a B");
        for slot in 0..(slot2 + 2 * LAG_CANDIDATO_VOTOS + 2) {
            assert_eq!(
                nodo.candidato_votos(slot),
                nodo.candidato_votos_referencia(slot),
                "candidato difiere en slot {slot}"
            );
        }
    }

    /// X3 · La pregunta falsable: tiempos de `estado_virtual()`, `mejor_punta()` y
    /// `Nodo::candidato_votos()` con 100 / 2 000 / 20 000 bloques PoST de historia. Es una
    /// comparación **dentro del espacio** (no clase M); la prueba informa, no afirma cota.
    #[test]
    fn idx1_x3_tiempos_no_crecen_con_la_historia() {
        let dir = tempfile::tempdir().unwrap();
        let mut nodo = Nodo::arrancar(&config_de_test(dir.path())).unwrap();
        for n in [100usize, 2_000, 20_000] {
            let (cadena, slot_max) = cadena_lineal(n);
            nodo.cadena = cadena;
            let slot = slot_max + LAG_CANDIDATO_VOTOS;
            // Calentamiento.
            let _ = nodo.cadena.estado_virtual().unwrap();
            let _ = nodo.cadena.mejor_punta();
            let _ = nodo.candidato_votos(slot);
            let t0 = Instant::now();
            let _ = nodo.cadena.estado_virtual().unwrap();
            let estado_us = t0.elapsed().as_micros();
            let t0 = Instant::now();
            let _ = nodo.cadena.mejor_punta();
            let punta_us = t0.elapsed().as_micros();
            let t0 = Instant::now();
            let _ = nodo.candidato_votos(slot);
            let cand_us = t0.elapsed().as_micros();
            println!(
                "X3 bloques={n} estado_virtual_us={estado_us} mejor_punta_us={punta_us} candidato_votos_us={cand_us}"
            );
        }
    }
}

/// AT-1a2 · fixture de pruebas: `zx_cadena::Cadena` **real** con una bifurcación, para las pruebas
/// R1–R6 (cadena real). Módulo **de pruebas**; no añade líneas de producción.
///
/// La rama principal (`A → B → C`) es la seleccionada; la rama `A → X → Y` queda abandonada, de modo
/// que `X` está en el DAG pero fuera de la cadena seleccionada y `C` está en conflicto con `X`.
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "el test falla con panic por diseño")]
pub(crate) mod pruebas_at1a2_fixture {
    use primitive_types::U256;
    use zx_cadena::{BloqueCadena, BloquePost, Cadena};
    use zx_consensus::transicion::{BloqueTransicion, HechosCabecera, ParametrosTransicion};
    use zx_core::{Amount, BlockHash, CBID_RED_DEV, ClavePublica, Digest, ExtensionTx, Tx};
    use zx_dag::IdentidadTicket;
    use zx_dag::ghostdag::IdentidadGhostdag;

    const MAX_PADRES: u8 = 15;
    const K: u32 = 1;

    fn subsidio_pow(_h: u32) -> Amount {
        Amount::nuevo(10).unwrap()
    }
    fn subsidio_post(_s: u64) -> Amount {
        Amount::nuevo(3).unwrap()
    }

    fn params() -> ParametrosTransicion {
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
            f_slots: Some(5),
            subsidio_pow,
            subsidio_post,
        }
    }

    /// Hash determinista `n` (mismo esquema que los demás arneses de `nodo.rs`).
    pub(crate) fn hash_u32(n: u32) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&n.to_be_bytes());
        BlockHash::from_digest(Digest::from_bytes(bytes))
    }

    fn productor() -> ClavePublica {
        ClavePublica::desde_bytes([0x5a; 32])
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

    /// Cadena real con la bifurcación:
    ///
    /// ```text
    /// G(0) → P(1) → A(10) → B(11) → C(12)   (rama seleccionada)
    ///                    \→ X(20) → Y(21)   (rama abandonada; X es el bloque votado)
    /// ```
    pub(crate) struct Bifurcacion {
        pub(crate) cadena: Cadena,
        /// Antepasado propio de `X` (y de la rama principal).
        pub(crate) a: BlockHash,
        /// Bloque votado: en el DAG, fuera de la cadena seleccionada.
        pub(crate) x: BlockHash,
        /// Descendiente de `X` en la rama abandonada.
        pub(crate) y: BlockHash,
        /// Punta de la rama principal, en conflicto con `X`.
        pub(crate) c: BlockHash,
        /// Hash que **no** pertenece al DAG de la vista.
        pub(crate) desconocido: BlockHash,
    }

    pub(crate) fn bifurcacion() -> Bifurcacion {
        let mut cadena = Cadena::nueva(params(), K, CBID_RED_DEV, MAX_PADRES);
        cadena.admitir(genesis()).unwrap();
        cadena.admitir(pow_terminal(1, 1)).unwrap();
        let a = hash_u32(10);
        cadena.admitir(post(10, vec![hash_u32(1)], 1, 1)).unwrap();
        cadena.admitir(post(11, vec![a], 2, 1)).unwrap();
        let c = hash_u32(12);
        cadena.admitir(post(12, vec![hash_u32(11)], 3, 1)).unwrap();
        let x = hash_u32(20);
        cadena.admitir(post(20, vec![a], 4, 10)).unwrap();
        let y = hash_u32(21);
        cadena.admitir(post(21, vec![x], 5, 10)).unwrap();
        assert!(
            cadena.en_cadena_seleccionada(&c),
            "el fixture exige que la rama principal (C) sea la seleccionada"
        );
        assert!(
            !cadena.en_cadena_seleccionada(&x),
            "el fixture exige que X quede en la rama abandonada"
        );
        Bifurcacion {
            cadena,
            a,
            x,
            y,
            c,
            desconocido: hash_u32(0xEEEE),
        }
    }
}

/// MP-1 · P2: pruebas de la variante no fatal `BloquePropioRechazadoPorTx`, de su frontera
/// (solo coinbase) y del rechazo de red. La tabla de decisión pura (`es_rechazo_propio_por_cuerpo`)
/// y la producción real de la variante por `admitir_pow_interno` se prueban aquí.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]
mod pruebas_mp1_p2 {
    use core::sync::atomic::AtomicBool;

    use zx_consensus::transicion::ErrorTransicion;
    use zx_consensus::{PARAMETROS_POW_DEV, Sha3Dev, minar};
    use zx_core::preimage::block::{BlockHeader, merkle_root};
    use zx_core::{
        Amount, ExtensionTx, HashType, Lock, OutPoint, SpentOutput, Tx, TxId, TxIn, TxOut,
        decodificar_con, digest::Digest, txid,
    };

    use super::{
        Config, ErrorNodo, Nodo, Red, error_atribuible_al_candidato, es_rechazo_propio_por_cuerpo,
    };
    use crate::claves::ClaveDev;
    use crate::rechazo::ClasificacionRechazo;

    const CBID: u32 = zx_core::CBID_RED_DEV;

    fn cfg_mp1(dir: &std::path::Path) -> Config {
        Config {
            dir_datos: dir.join("datos"),
            ruta_registro: dir.join("registro.jsonl"),
            red: Red::Dev,
            semilla: 77,
            indices_claves: vec![0],
            n_dev: 16,
            sr_dev: u64::MAX,
            perfil_red: crate::perfil::perfil_red_dev(),
            parada_tras_slots: Some(0),
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        }
    }

    /// Transferencia v1 firmada que gasta un `OutPoint` inexistente: `aplicar_transferencia`
    /// devuelve `ErrDobleGasto` (un `ErrTransicion` no legítimo) sin llegar a la firma.
    fn transferencia_a_outpoint_inexistente(clave: &ClaveDev) -> (Tx, Vec<Vec<u8>>) {
        let op = OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([0x99; 32])),
            prev_index: 0,
        };
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(800).unwrap(),
                lock: Lock::PubKey { pubkey: clave.pk },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = [SpentOutput {
            value: Amount::nuevo(1_000).unwrap(),
            lock: Lock::PubKey { pubkey: clave.pk },
        }];
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, CBID).unwrap();
        let firma: [u8; 64] = clave.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    /// Mina un PoW real de altura 1 sobre el génesis con el cuerpo indicado.
    fn minar_altura_1(nodo: &Nodo, txs: &[Tx]) -> BlockHeader {
        let genesis = nodo.historial_pow[0];
        let txids: Vec<TxId> = txs.iter().map(|t| txid(t, nodo.cbid)).collect();
        let target = decodificar_con(
            PARAMETROS_POW_DEV.bits_iniciales,
            &PARAMETROS_POW_DEV.limites,
        )
        .expect("bits_iniciales decodifica");
        let cabecera_base = BlockHeader {
            consensus_branch_id: nodo.cbid,
            prev_hash: genesis.block_hash(),
            merkle_root: merkle_root(&txids),
            timestamp: genesis.timestamp + 1,
            bits: PARAMETROS_POW_DEV.bits_iniciales,
            nonce: 0,
            height: 1,
        };
        let cancelar = AtomicBool::new(false);
        minar(&cabecera_base, target, &Sha3Dev, u64::MAX, &cancelar)
            .expect("un PoW real se encuentra con la dificultad dev inicial")
    }

    /// **P2 (tabla de decisión, camino real hasta la admisión)**: un bloque propio con una
    /// transacción inválida (además de la coinbase) produce `BloquePropioRechazadoPorTx`; el mismo
    /// bloque como red produce `BloquePropioRechazado` (fatal/penalizante). Un bloque solo con la
    /// coinbase nunca produce la variante no fatal.
    #[test]
    fn bloque_propio_rechazado_por_su_cuerpo_no_es_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = Nodo::arrancar(&cfg_mp1(dir.path())).expect("arranque limpio");
        let clave = nodo.claves[0].clone();
        let coinbase = crate::pow::construir_coinbase_pow(clave.pk, 1);
        let (tx_inv, tst_inv) = transferencia_a_outpoint_inexistente(&clave);
        assert!(matches!(tx_inv.version, 1) && !tx_inv.inputs.is_empty());
        let cabecera = minar_altura_1(&nodo, &[coinbase.clone(), tx_inv.clone()]);

        // Bloque propio: variante no fatal.
        let r = nodo.admitir_pow_interno(
            cabecera,
            vec![coinbase.clone(), tx_inv.clone()],
            vec![Vec::new(), tst_inv.clone()],
            0,
            true,
            true,
        );
        match r {
            Err(ErrorNodo::BloquePropioRechazadoPorTx {
                hash,
                altura,
                n_txs,
                ..
            }) => {
                assert_eq!(altura, 1);
                assert_eq!(n_txs, 2);
                // Gancho de test (`ORDEN-MP1` §4.7): la tx inválida en la cola sin validar.
                {
                    let mut m = nodo.mempool.lock().unwrap_or_else(|p| p.into_inner());
                    m.insertar_sin_validar_para_test(tx_inv.clone(), tst_inv.clone());
                    assert!(m.contiene(&txid(&tx_inv, nodo.cbid)));
                }
                // P2: escribe el evento y expulsa la tx del bloque; el nodo no muere.
                nodo.manejar_bloque_propio_rechazado_por_tx(
                    hash,
                    altura,
                    "ErrDobleGasto",
                    n_txs,
                    &[coinbase.clone(), tx_inv.clone()],
                )
                .expect("manejo P2");
                {
                    let m = nodo.mempool.lock().unwrap_or_else(|p| p.into_inner());
                    assert!(
                        !m.contiene(&txid(&tx_inv, nodo.cbid)),
                        "la transacción del bloque debe quedar expulsada de la cola"
                    );
                }
                let texto = std::fs::read_to_string(dir.path().join("registro.jsonl"))
                    .expect("registro legible");
                assert!(
                    texto.contains("bloque_propio_rechazado_por_tx"),
                    "el evento P2 debe quedar escrito: {texto}"
                );
            }
            otro => panic!("se esperaba BloquePropioRechazadoPorTx, fue {otro:?}"),
        }

        // El mismo bloque como red: variante de siempre, clasificación interna (penaliza).
        let dir2 = tempfile::tempdir().expect("tempdir2");
        let mut nodo2 = Nodo::arrancar(&cfg_mp1(dir2.path())).expect("arranque limpio 2");
        let cabecera2 = minar_altura_1(&nodo2, &[coinbase.clone(), tx_inv.clone()]);
        let r2 = nodo2.admitir_pow_interno(
            cabecera2,
            vec![coinbase, tx_inv],
            vec![Vec::new(), tst_inv],
            0,
            true,
            false,
        );
        match r2 {
            Err(e @ ErrorNodo::BloquePropioRechazado { clasificacion, .. }) => {
                assert_eq!(clasificacion, ClasificacionRechazo::Interno);
                assert!(error_atribuible_al_candidato(&e), "en red penaliza");
            }
            otro => panic!("se esperaba BloquePropioRechazado, fue {otro:?}"),
        }
    }

    /// **P2 (frontera)**: sin transacciones además de la coinbase, la tabla decide que no es un
    /// rechazo «por cuerpo» (sigue fatal); con una, sí.
    #[test]
    fn bloque_propio_solo_coinbase_rechazado_sigue_siendo_fatal() {
        let err = zx_cadena::MotivoBloque::ErrTransicion(ErrorTransicion::ErrInmaduro);
        assert!(
            !es_rechazo_propio_por_cuerpo(&err, ClasificacionRechazo::Interno, 0),
            "solo coinbase: fatal"
        );
        assert!(
            es_rechazo_propio_por_cuerpo(&err, ClasificacionRechazo::Interno, 1),
            "con una tx además de la coinbase: no fatal"
        );
        // Un motivo que no es de transición no entra por esta tabla.
        assert!(!es_rechazo_propio_por_cuerpo(
            &zx_cadena::MotivoBloque::ErrEmision,
            ClasificacionRechazo::Interno,
            1
        ));
        // Una clasificación legítima sigue su camino propio (`ErrPowTrasCorte`).
        assert!(!es_rechazo_propio_por_cuerpo(
            &zx_cadena::MotivoBloque::ErrTransicion(ErrorTransicion::ErrPowTrasCorte),
            ClasificacionRechazo::Legitimo,
            1
        ));
    }

    /// **P2 (red)**: un bloque de red rechazado por la transición sigue penalizando, tanto por la
    /// variante de siempre (`Interno`) como si llegara la variante nueva.
    #[test]
    fn bloque_de_red_rechazado_por_transicion_sigue_penalizando() {
        let hash = zx_core::BlockHash::from_digest(Digest::from_bytes([0x44; 32]));
        let interno = ErrorNodo::BloquePropioRechazado {
            hash,
            motivo: "ErrInmaduro".to_string(),
            clasificacion: ClasificacionRechazo::Interno,
        };
        assert!(error_atribuible_al_candidato(&interno));
        let por_tx = ErrorNodo::BloquePropioRechazadoPorTx {
            hash,
            altura: 26,
            motivo: "ErrInmaduro".to_string(),
            n_txs: 5,
        };
        assert!(error_atribuible_al_candidato(&por_tx));
    }
}

#[cfg(test)]
mod pruebas_rlj1;

#[cfg(test)]
mod pruebas_rlj3a;

#[cfg(test)]
mod dgcand_tests;

#[cfg(test)]
mod pruebas_vnt1;

#[cfg(test)]
mod pruebas_deuda1;

#[cfg(test)]
mod pruebas_deuda2;
