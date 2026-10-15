//! Núcleo de verificación de un **rango PoT** de un bloque DAG (SPEC §7.1.2 y §7.1.5).
//!
//! Verifica la justificación `PotCheckpoints` que cubre `(slot(sp(B)) + D, slot(B) + D]` contra
//! una **instantánea contextual** del pasado, y ancla el resultado en `cabecera.pot_output`
//! (`C-POT-05`, `C-HDR-07`). Devuelve **tres estados** expresa y únicamente tres:
//! [`EstadoPot::PotValido`], [`EstadoPot::PotInvalido`] y [`EstadoPot::PotPendiente`]
//! (`C-POT-06`). Ningún pendiente se convierte en válido por defecto.
//!
//! # Dos fases públicas, y el sello entre ellas (`C-POT-08`)
//!
//! El orden de `C-POT-08` no cabe en una sola llamada cuando A3 debe insertar el paso 2 (cabecera
//! y sello ZIP-215, `C-HDR-03`/`C-HDR-04`) entre el paso 1b y el paso 3. Por eso el núcleo se
//! separa en dos funciones públicas:
//!
//! - [`verificar_rango_pot_fase_previa`] cubre el paso 0 (génesis), el paso 1 (estructura, sin
//!   AES) y el paso 1b (flujo, sin AES). Devuelve un token opaco [`TokenRangoPot`] o un
//!   [`EstadoPot::PotInvalido`]/[`EstadoPot::PotPendiente`]. **No** consulta la caché ni consume
//!   presupuesto AES.
//! - [`verificar_rango_pot_fase_aes`] recibe ese token —que ya retiene el mismo `&C` acreditado en
//!   la fase previa—, el reloj PoT, la caché y el presupuesto; **no** admite un argumento de
//!   contexto. Ejecuta los pasos 3 (caché contextual, `C-POT-07`) y 4 (cadena AES del rango,
//!   `C-POT-01`/`C-POT-02`/`C-POT-04`) y el anclaje final (`C-POT-05`).
//!
//! A3 puede entonces llamar a la primera fase, verificar el sello ZIP-215 (`C-HDR-04`) y **solo
//! entonces** llamar a la segunda. El paso 2 (cabecera y sello) y el paso 5 (reto y solución
//! PoAS) **no** se cubren aquí: pertenecen a la validación de cabecera y al verificador PoAS, y
//! este núcleo no los sustituye ni los finge. Tampoco se llama `validar_bloque`.
//!
//! [`verificar_rango_pot`] se conserva como conveniencia **solo para el núcleo PoT**: encadena las
//! dos fases anteriores. **No** verifica sello ni PoAS, **no** es un validador integral y
//! **MUST NOT** publicarse como tal.
//!
//! # Qué comprueba y en qué orden
//!
//! - **Estructura, sin AES** (paso 1, `C-HDR-05` · `C-FLU-02`, `C-HDR-07`): `slot(p) ≤ slot(B)`
//!   para todos los padres, `d = slot(B) − slot(sp(B))` sin underflow, `d ≤ 150` y número real
//!   de portadores igual a `d`.
//! - **Flujo, sin AES** (paso 1b, `C-FLU-14`): `flujo(B, slot(X)) == flujo(X, slot(X))` para
//!   todo `X ∈ past(B)`. Discrepar es `Inválido`; que falte pasado es `Pendiente`.
//! - **Caché por clave contextual** (paso 3, `C-POT-07`): `(f, s, semilla(f,s), N(s))`, los
//!   cuatro del contexto. Una discrepancia **bajo la misma clave** es `Inválido`; una entrada
//!   de **otra clave no invalida**.
//! - **Cadena AES del rango** (paso 4, `C-POT-01`, `C-POT-02`, `C-POT-04`): se parte de la
//!   salida ya validada en `slot(sp(B)) + D`, se aplica la inyección declarada **exactamente en
//!   su slot** (a lo sumo una, `C-FLU-12`), se proyecta `N(s)`, se verifica cada portador con
//!   [`verificar_slot_aes`] y se encadena la salida. El último resultado **MUST** ser
//!   `cabecera.pot_output`; con `d = 0` se exige que el ancla acreditada del mismo slot sea
//!   `pot_output`, sin declarar válido un rango vacío por omisión.
//!
//! # Ancla del rango y salida auditada: dos posiciones (`C-POT-03`, `C-POT-05`)
//!
//! El núcleo maneja **dos posiciones** de salida de 16 B que no deben confundirse:
//!
//! - El **ancla de inicio del rango** es `salida(f, slot(sp(B)) + D)`. Es **siempre** una salida del
//!   pasado validado y la aporta [`InstantaneaPot::salida_validada`]; de ahí arranca la cadena AES.
//! - La **salida auditada** es `salida(f, slot(B))`, la que `C-POT-03` necesita para derivar el
//!   reto del slot auditado. Esa salida sale siempre de una fuente **ya verificada**: del **propio
//!   portador de `B` ya verificado** si `d > D` (el slot auditado cae dentro del rango), o de la
//!   instantánea del pasado si `d ≤ D` (incluido `d = 0`).
//! - `cabecera.pot_output` es, por definición, `salida(f, slot(B) + D)` (`C-POT-05`): la salida del
//!   **último slot del rango**. Con `D = 0` esa posición es la **misma** que la auditada,
//!   `slot(B) + D = slot(B)`, sea cual sea `d`; con `D > 0` son posiciones de slots distintos.
//!
//! Que dos posiciones de slots distintos den los mismos 16 B sería una coincidencia accidental que
//! el núcleo no prohíbe ni usa: compara posiciones, no bytes. La prueba conserva la salida de la
//! posición auditada, no la de `pot_output`.
//!
//! La prueba [`PruebaPotValidada`] solo se construye al final, cuando los dos recorridos coinciden:
//! el rango entero pasó caché/AES, el último resultado es `pot_output` y la salida auditada quedó
//! resuelta de su fuente correcta. No se publica nada antes.
//!
//! # Prohibición de circularidad (`C-POT-06`)
//!
//! El flujo, la semilla del rango, las inyecciones, `N(s)` y `D` llegan **solo** por
//! [`InstantaneaPot`], cuyos métodos no reciben la cabecera ni el cuerpo. Eso evita una vía
//! directa de lectura, pero un implementador podría haber capturado datos del candidato por
//! otra vía: la procedencia causal sigue siendo una precondición por acreditar. El candidato
//! aporta únicamente su `slot`, sus padres, los portadores y el `pot_output` que se usa como
//! **redundancia comprobada**, nunca como fuente de verdad. El token de la fase previa está
//! ligado por préstamo a la cabecera, la justificación **y la instantánea contextual** con las que
//! se obtuvo, así que la segunda fase **no** puede recibir otro `&C`: no existe un argumento de
//! contexto, el token lo retiene. No hay constructor público y sus campos son privados.
//!
//! **Límite real, dicho sin adorno:** `&C` impide pasar otro contexto o mutar normalmente el objeto
//! entre fases, pero una implementación con **mutabilidad interior** podría cambiar sus respuestas
//! entre la fase previa y la AES. Por eso esta preparación **no acredita producción**; el derivador
//! futuro deberá entregar una instantánea inmutable del pasado ya validado. El rasgo
//! [`InstantaneaPot`] por sí solo **no** prueba procedencia ni inmutabilidad.
//!
//! # Qué acredita hoy `past(B)` — y qué no
//!
//! **Ningún objeto del código actual acredita un `past(B)` validado para el PoT, y este módulo
//! no fabrica la fábrica que lo aparente.**
//!
//! - `AlmacenGhostdag` guarda por bloque `id`, `padres`, `slot`, `rango_espacio` validado e
//!   identidad, y responde a las consultas de `ContextoDag` (`slot_de_padre`,
//!   `esta_en_el_pasado_de`, `padre_seleccionado`). **No** guarda `pot_output`, ni el
//!   identificador de flujo, ni las inyecciones, ni `N(s)`, ni las salidas de slot; y su entrada
//!   sintética (`anadir_sintetico`) admite datos libres.
//! - `zx_core::wire_dag::ContextoVerificacionPot` es una interfaz **sin implementación de
//!   producción**.
//! - La derivación del identificador de flujo de §7.1.4 y el cálculo de la vista de época
//!   `V_j(B)` y del ancla de §7.1.3 **no existen**. Por eso [`InstantaneaPot`] se declara como
//!   la costura que el derivador real deberá implementar, y su precondición —derivar todo del
//!   pasado DAG validado— queda documentada, **no comprobada** por el núcleo.
//!
//! Consecuencia, dicha sin adorno: **este núcleo no puede producir `PotValido` para un bloque en
//! la ruta activa**, porque no hay fuente causal que produzca una [`InstantaneaPot`] acreditada.
//! `zx_core::wire_dag::verificar_justificacion_pot` sigue devolviendo
//! [`zx_core::wire_dag::IntegracionPotPendiente`] hasta que exista esa integración. Las
//! implementaciones de prueba del trait que viven en los tests **no acreditan** la validez de
//! ningún bloque: sirven para probar el núcleo.
//!
//! # Caché contextual concreta: solo lo verificado entra (`C-POT-07`)
//!
//! [`CachePotVerificada`] es la única caché que la segunda fase acepta. Su estado es privado:
//! **ninguna API pública inserta ni deserializa una entrada**. Una entrada se registra
//! *únicamente* tras un [`verificar_slot_aes`] exitoso, bajo la clave contextual
//! `(f, s, semilla(f,s), N(s))` y con el portador de 128 B ya verificado. Un acierto **completo**
//! de clave y 128 B evita repetir AES; si bajo la misma clave difieren la salida o el portador,
//! es [`MotivoPotInvalido::CacheDiscrepante`] **sin** gastar AES. Una entrada de **otra clave no
//! invalida**. No se guarda nada tras una verificación fallida. Con esto se elimina el caso de
//! «solo 16 B»: una coincidencia de la salida de 16 B no acredita los siete checkpoints
//! anteriores y, al no existir entradas parciales, el núcleo **no** acepta por esa coincidencia.
//!
//! # Contexto circular cuando `D ≥ L_slots`
//!
//! No se presupone `D < L_slots`. Si un bloque puede ser su propia ancla, la entropía de
//! `C-FLU-12` dependería de su propio `pot_output`. [`InyeccionPot`] declara el **ancla** de cada
//! inyección; si el ancla es el propio candidato, el estado es `Pendiente` por contexto circular,
//! nunca `Inválido` ni `Válido`. Tampoco se fijan aquí `D`, `L_slots`, `N(s)` ni presupuesto
//! alguno: los tres primeros llegan por el contexto y el presupuesto se inyecta.

use std::collections::BTreeMap;

use zx_core::BlockHash;
use zx_core::wire_dag::{
    ErrorDiferenciaSlots, JustificacionPot, MAX_BUNDLES_POT, POT_OUTPUT_BYTES, PotCheckpoints,
};

use crate::pot::{
    ENTROPIA_BYTES, ErrorContextoPot, checkpoints_a_primitiva, proyectar_iteraciones,
    semilla_siguiente, verificar_slot_aes,
};

/// Bytes de un identificador de flujo (definición del flujo, §7.1.4).
pub const FLUJO_BYTES: usize = 32;

/// Estado de la verificación de un rango PoT. Son **tres**, no dos (`C-POT-06`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstadoPot {
    /// Cadena completa verificada y anclada en `pot_output`, con la salida del slot auditado.
    ///
    /// La prueba que acompaña acredita **solo el núcleo PoT** contra la [`InstantaneaPot`] recibida
    /// (pasos 1–4 de `C-POT-08`). No cubre el sello (`C-HDR-04`) ni el PoAS (`C-POT-03`), y la
    /// instantánea puede ser un mock o tener procedencia falsa. **No** es un certificado de validez
    /// de bloque.
    PotValido(PruebaPotValidada),
    /// Defecto **del candidato**, verificable y final.
    PotInvalido(MotivoPotInvalido),
    /// Sin prueba de invalidez, pero tampoco de validez. Nunca pasa a válido por defecto.
    PotPendiente(MotivoPotPendiente),
}

/// Salida del **slot auditado** ya verificada por el núcleo PoT.
///
/// `C-POT-03` deriva el reto del slot `s` de `salida(f, s)`. Para auditar la `SolucionPoas` de un
/// bloque `B`, el slot auditado es `slot(B)` y su salida es `salida(f, slot(B))`. `pot_output` es
/// la salida de la posición `slot(B) + D` (`C-POT-05`); ambas posiciones coinciden solo cuando
/// `D = 0`, y con slots distintos sus 16 B podrían coincidir por azar sin ser la misma variable.
///
/// # De dónde sale la salida auditada
///
/// - Si `slot(B) > slot(sp(B)) + D` (`d > D`), el slot auditado cae **dentro del propio rango** de
///   `B` y su salida se captura del portador ya verificado, **nunca** de la instantánea del pasado.
/// - Si `slot(B) ≤ slot(sp(B)) + D` (`d ≤ D`, incluido `d = 0`), el slot auditado está en el pasado
///   validado y la salida la aporta [`InstantaneaPot::salida_validada`].
///
/// # Qué acredita y qué no
///
/// Vincula la salida al candidato (`bloque`) cuyo núcleo PoT pasó, y solo existe si el rango entero
/// verificó y ancló en `pot_output`. Pero **solo acredita el núcleo PoT contra la `InstantaneaPot`
/// recibida**: esa instantánea puede ser un mock o tener procedencia falsa, y el sello (`C-HDR-04`)
/// y el PoAS (`C-POT-03`) quedan fuera. **No es un certificado de validez de bloque.**
///
/// Los campos son privados y **no hay constructor público**: fuera de este módulo no compila
/// construir una [`PruebaPotValidada`] con campos arbitrarios (lo fija el `compile_fail` de abajo).
/// Eso impide la **construcción directa**, no la **inducción**: cualquier llamante puede obtener un
/// [`EstadoPot::PotValido`] con una prueba así llamando a [`verificar_rango_pot`] con una
/// implementación inventada de [`InstantaneaPot`].
///
/// Contraejemplo de procedencia, con `d = 0` y `D > 0`: un contexto falso devuelve
/// `cabecera.pot_output` como ancla acreditada del rango y una salida auditada arbitraria para
/// `slot(B)`; el rango está vacío, no se ejecuta un solo AES y el núcleo devuelve `PotValido` con
/// esos bytes. La prueba no distingue ese contexto de un pasado real. Por eso **no** acredita
/// validez de bloque y la puerta A3 **no** debe aceptar un `PotValido` de la conveniencia pública
/// como tal: debe verificar antes el sello (`C-HDR-04`) e interponer la procedencia causal del
/// pasado.
///
/// ```compile_fail
/// use zx_post::pot_rango::PruebaPotValidada;
///
/// fn fabricar(bloque: zx_core::BlockHash) -> PruebaPotValidada {
///     // Campos privados y sin constructor público: fuera del módulo no compila.
///     PruebaPotValidada {
///         bloque,
///         slot_auditado: 0,
///         salida_auditada: [0u8; 16],
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruebaPotValidada {
    /// `block_hash` del candidato cuyo núcleo PoT pasó.
    bloque: BlockHash,
    /// `slot(B)`, el slot cuyo reto audita la `SolucionPoas` (`C-POT-03`).
    slot_auditado: u64,
    /// `salida(f, slot_auditado)` ya verificada.
    salida_auditada: [u8; POT_OUTPUT_BYTES],
}

// Los getters existen para que el paso 5 de A3 (`poas::verificar_solucion_poas`) lea la salida
// auditada. Hasta que A3 los llame, en la compilación sin tests quedarían muertos; se permite ese
// estado solo fuera de `test`, donde las pruebas internas del módulo sí los observan.
#[cfg_attr(not(test), allow(dead_code))]
impl PruebaPotValidada {
    /// `block_hash` del candidato cuya fase previa superó la prueba.
    #[must_use]
    pub(crate) fn bloque(&self) -> BlockHash {
        self.bloque
    }

    /// Slot auditado (`slot(B)`) cuyo reto consume el PoAS (`C-POT-03`).
    #[must_use]
    pub(crate) fn slot_auditado(&self) -> u64 {
        self.slot_auditado
    }

    /// Salida del slot auditado, lista para [`crate::poas::verificar_solucion_poas`].
    #[must_use]
    pub(crate) fn salida_auditada(&self) -> [u8; POT_OUTPUT_BYTES] {
        self.salida_auditada
    }
}

/// Defecto del candidato: la prueba es falsa o está descuadrada (`C-POT-06`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MotivoPotInvalido {
    /// `C-HDR-07`: underflow `slot(B) < slot(sp)`, diferencia `> 150` o número de portadores
    /// distinto de `d`. Reutiliza la semántica del código de `zx-core`.
    DiferenciaDeSlots(ErrorDiferenciaSlots),
    /// `C-HDR-05` · `C-FLU-02`: algún padre tiene un `slot` posterior al del bloque.
    SlotDePadrePosterior {
        /// Padre infractor.
        padre: BlockHash,
        /// Su `slot`, tomado del contexto.
        slot_padre: u64,
        /// El `slot` declarado por el bloque.
        slot_bloque: u64,
    },
    /// `C-FLU-14`: el flujo del candidato en el slot de un ancestro no es el del ancestro.
    FlujoDePasadoDiscrepa {
        /// Ancestro cuyo flujo discrepó.
        bloque: BlockHash,
        /// Slot en el que se comparó.
        slot: u64,
    },
    /// `C-POT-07`: discrepancia con la caché **bajo la misma clave**. Se decide comparando los
    /// 128 B (salida y portador) y **sin** gastar AES.
    CacheDiscrepante {
        /// Slot del portador.
        slot: u64,
    },
    /// `C-POT-02`: la cadena AES no reproduce el portador con la semilla y `N(s)` del contexto.
    AesFallido {
        /// Slot del portador.
        slot: u64,
    },
    /// `C-POT-05` · `C-HDR-07`: el resultado encadenado no es `cabecera.pot_output`.
    PotOutputNoCoincide {
        /// Salida obtenida del contexto y de la cadena.
        obtenido: [u8; POT_OUTPUT_BYTES],
    },
    /// **D-P08:** una cabecera PoST sin padres es inválida. No hay génesis DAG; el primer bloque es
    /// hijo del terminal `T` y [`zx_dag::comprobar_padres_contextual`] ya lo exige. Aquí se rechaza
    /// también, sin tocar AES, para que el núcleo no dependa de que el llamante haya pasado por esa
    /// comprobación.
    SinPadres,
}

/// Falta de contexto o imposibilidad de verificarlo: **no** es una prueba inválida (`C-POT-06`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MotivoPotPendiente {
    /// El contexto no puede aportar un dato del pasado validado.
    ContextoAusente {
        /// Qué dato falta.
        que: &'static str,
    },
    /// `C-FLU-14`: el contexto no tiene todo `past(B)` o no puede enumerarlo.
    PasadoIncompleto,
    /// `C-POT-04`: `N(s)` fuera del dominio de la primitiva (cero, `> u32::MAX` o no múltiplo
    /// de 16). Es fallo del pasado validado, nunca del candidato.
    IteracionesFueraDeDominio {
        /// Slot cuyo `N(s)` falló.
        slot: u64,
        /// Diagnóstico de `C-POT-04`.
        error: ErrorContextoPot,
    },
    /// `C-NET-32.2`: hay slots del rango por delante del reloj PoT del nodo. Se retienen.
    RelojFuturo {
        /// Primer slot retenido.
        slot: u64,
        /// Reloj PoT declarado por el nodo.
        reloj_pot: u64,
    },
    /// `C-NET-33`: presupuesto agotado. **Nunca** `Inválido`.
    PresupuestoAgotado {
        /// Slot que no se pudo verificar.
        slot: u64,
    },
    /// `C-POT-01`: el contexto declara más de una inyección en un slot.
    InyeccionesMultiples {
        /// Slot con más de una inyección.
        slot: u64,
    },
    /// `C-FLU-12`: el ancla de una inyección del rango es el propio candidato, así que su
    /// entropía dependería de su `pot_output`. No se presupone `D < L_slots`.
    ContextoCircular {
        /// Slot de la inyección circular.
        slot: u64,
    },
    /// `slot + D` no cabe en `u64` con aritmética comprobada.
    AritmeticaDeSlotsDesbordada,
}

/// Un bloque de `past(B)` con lo que `C-FLU-14` y la parte B necesitan de él.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloqueDelPasado {
    /// Identificador del ancestro.
    pub hash: BlockHash,
    /// Su slot validado.
    pub slot: u64,
    /// `timestamp` declarado por su cabecera (para la PMT de `C-RLJ-TS-01`).
    pub timestamp: u64,
    /// `flujo(X, slot(X))` ya validado de `X`.
    pub flujo: [u8; FLUJO_BYTES],
}

/// Inyección declarada por el pasado en un slot (`C-POT-01`, `C-FLU-12`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InyeccionPot {
    /// Los 32 B de entropía de la inyección.
    pub entropia: [u8; ENTROPIA_BYTES],
    /// Ancla `I_j(B)` que la produce. Sirve para detectar el contexto circular.
    pub ancla: BlockHash,
}

/// Cuántas inyecciones declara el contexto en un slot.
///
/// Existe para que el núcleo pueda rechazar **más de una** sin confiar en que el contexto las
/// cuente bien (`C-POT-01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InyeccionesPot {
    /// Ninguna.
    Ninguna,
    /// Exactamente una.
    Una(InyeccionPot),
    /// Más de una: `Pendiente` por error de contexto.
    Varias,
}

/// Instantánea contextual **acreditada** del pasado de un candidato (`C-POT-06`).
///
/// # Precondición que el núcleo NO comprueba
///
/// Toda implementación de producción **MUST** derivar estos valores **exclusivamente** del pasado
/// DAG validado de `B`, y **MUST NOT** aceptarlos del candidato, de su cabecera, de su cuerpo, del
/// orden de llegada, del reloj local ni de la punta local. Ninguno de los métodos recibe la
/// cabecera directamente. Una implementación aún podría capturar datos del candidato por
/// fuera: excluir esa circularidad y acreditar el pasado son precondiciones que este contrato
/// **no** demuestra.
///
/// Una implementación de prueba (o un mock) cumple la firma pero **no acredita** procedencia
/// alguna: sirve para probar el núcleo, no para declarar válido un bloque.
pub trait InstantaneaPot {
    /// `flujo(B, s)` del candidato, derivado de `past(B)` (§7.1.4).
    ///
    /// # Errores
    /// [`MotivoPotPendiente::ContextoAusente`] si la derivación no existe todavía: en ese caso el
    /// núcleo devuelve `Pendiente`, nunca un flujo supuesto.
    fn flujo_candidato_en(&self, slot: u64) -> Result<[u8; FLUJO_BYTES], MotivoPotPendiente>;

    /// `past(B)` completo, para la comprobación `C-FLU-14`.
    ///
    /// # Errores
    /// [`MotivoPotPendiente::PasadoIncompleto`] si no puede enumerarse entero.
    fn pasado(&self) -> Result<&[BloqueDelPasado], MotivoPotPendiente>;

    /// Inyecciones declaradas por el pasado **exactamente** en `slot` (`C-POT-01`, `C-FLU-12`).
    ///
    /// # Errores
    /// El error contextual que impida calcularlas (por ejemplo, ancla no derivable).
    fn inyecciones_en(&self, slot: u64) -> Result<InyeccionesPot, MotivoPotPendiente>;

    /// `N(s)` vigente en el slot, del pasado validado (`C-POT-04`).
    ///
    /// # Errores
    /// [`MotivoPotPendiente::ContextoAusente`] si el calendario no está disponible.
    fn iteraciones(&self, slot: u64) -> Result<u64, MotivoPotPendiente>;

    /// Retardo de autoría `D` del contexto.
    ///
    /// # Errores
    /// [`MotivoPotPendiente::ContextoAusente`] si no está fijado.
    fn retardo_autoria(&self) -> Result<u64, MotivoPotPendiente>;

    /// `salida(f, s)` **ya validada** en el pasado, para anclar el rango (`C-POT-05`).
    ///
    /// # Errores
    /// [`MotivoPotPendiente::ContextoAusente`] si esa salida no está anclada en un bloque
    /// anterior.
    fn salida_validada(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], MotivoPotPendiente>;
}

/// Clave de caché contextual de `C-POT-07`: los **cuatro** valores del contexto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClaveCachePot {
    /// `f`, identificador de flujo.
    pub flujo: [u8; FLUJO_BYTES],
    /// Slot `s`.
    pub slot: u64,
    /// `semilla(f, s)`.
    pub semilla: [u8; POT_OUTPUT_BYTES],
    /// `N(s)` en `u64`.
    pub iteraciones: u64,
}

/// Entrada de caché **ya verificada** con [`verificar_slot_aes`]. Estado privado.
///
/// Conserva la salida de 16 B y el portador completo de 128 B que el propio verificador validó.
/// No hay constructor público ni deserialización: la única vía de alta es la segunda fase tras un
/// AES exitoso (`C-POT-07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntradaCacheVerificada {
    salida: [u8; POT_OUTPUT_BYTES],
    portador: PotCheckpoints,
}

/// Caché del nodo indexada por [`ClaveCachePot`] (`C-POT-07`).
///
/// Su estado interno es **privado**: ningún llamante puede insertar, reemplazar ni deserializar
/// una entrada. Solo se puede crear vacía con [`CachePotVerificada::nueva`]. La segunda fase
/// registra una entrada *únicamente* después de un `verificar_slot_aes` exitoso y con el portador
/// completo ya verificado. Una entrada **de otra clave no invalida** al candidato: son cadenas de
/// PoT distintas, ambas legítimas.
#[derive(Debug, Default)]
pub struct CachePotVerificada {
    entradas: BTreeMap<ClaveCachePot, EntradaCacheVerificada>,
}

impl CachePotVerificada {
    /// Crea una caché **vacía**. Es la única forma pública de construirla.
    #[must_use]
    pub fn nueva() -> Self {
        Self {
            entradas: BTreeMap::new(),
        }
    }

    /// Busca la entrada ya verificada de esa clave, si existe.
    fn buscar(&self, clave: &ClaveCachePot) -> Option<&EntradaCacheVerificada> {
        self.entradas.get(clave)
    }

    /// Registra la entrada de esa clave. **Solo** la llama la segunda fase tras un AES exitoso.
    fn registrar(&mut self, clave: ClaveCachePot, entrada: EntradaCacheVerificada) {
        self.entradas.insert(clave, entrada);
    }
}

/// Presupuesto de CPU inyectado (`C-NET-33`).
///
/// El núcleo **no fija** `PRESUP_PAR` ni `PRESUP_NODO`: los aporta el llamante. Se consume una
/// unidad por **verificación AES**; un acierto rápido de caché no consume. Agotarlo produce
/// `Pendiente`, nunca `Inválido`.
///
/// # Alcance del medidor
///
/// Este núcleo **solo** acota la cadena AES del rango (paso 4). El coste estructural del paso 1b
/// (`C-FLU-14`) va en la fase previa y el trabajo de adopción de flujo rival de §16.6 pertenece al
/// nodo, cuyos presupuestos siguen `<<PENDIENTE>>`: el núcleo no los calibra ni los sustituye.
pub trait PresupuestoPot {
    /// Intenta consumir una verificación AES del slot `slot`; `false` si no queda presupuesto.
    fn consumir_slot(&mut self, slot: u64) -> bool;
}

/// Token **opaco** de la fase previa de `C-POT-08` (pasos 0, 1 y 1b).
///
/// # Por qué es opaco
///
/// Los campos son privados y no hay constructor público: solo
/// [`verificar_rango_pot_fase_previa`] puede fabricarlo. Está ligado **por préstamo** a la
/// cabecera, a la justificación y a la instantánea contextual (`&C`) con las que se obtuvo. Por eso
/// no existe una llamada que reciba este token y **otro** contexto: la fase AES lee `&C` del propio
/// token, no de un argumento. Tampoco puede aplicarse a otra cabecera ni a otra justificación.
///
/// # Qué NO acredita
///
/// No acredita que `InstantaneaPot` provenga de un pasado DAG validado (precondición pendiente) ni
/// sustituye al sello (`C-HDR-04`) ni al PoAS (`C-POT-03`). Solo dice que los pasos 1 y 1b se
/// superaron para **ese** candidato, **esa** justificación y **ese** contexto. El préstamo `&C`
/// impide pasar otro contexto o mutar normalmente el objeto, pero **no** impide la mutabilidad
/// interior: un implementador así podría cambiar sus respuestas entre fases. Esta preparación **no
/// acredita producción**.
pub struct TokenRangoPot<'a, C> {
    cabecera: &'a zx_core::DagBlockHeader,
    justificacion: &'a JustificacionPot,
    contexto: &'a C,
    hash_candidato: BlockHash,
    slot_sp: u64,
}

impl<C> TokenRangoPot<'_, C> {
    /// `block_hash` de la cabecera con la que se obtuvo el token. Solo lectura.
    #[must_use]
    pub fn bloque(&self) -> BlockHash {
        self.hash_candidato
    }
}

/// Fase previa de `C-POT-08`: pasos 0 (génesis), 1 (estructura, `C-HDR-05`/`C-HDR-07`) y 1b
/// (`C-FLU-14`), **sin** caché ni presupuesto AES.
///
/// Devuelve el token opaco [`TokenRangoPot`] atado por préstamo a `cabecera`, `justificacion` y
/// `contexto`, o un [`EstadoPot::PotInvalido`]/[`EstadoPot::PotPendiente`]. Nunca devuelve
/// [`EstadoPot::PotValido`]: eso exige los pasos 3 y 4 de [`verificar_rango_pot_fase_aes`].
///
/// # Entradas
///
/// - `cabecera`: **candidato**. Solo se leen `padres` y `slot`; no se usa `pot_output` como salida
///   del slot auditado.
/// - `justificacion`: los portadores declarados, evidencia reemplazable.
/// - `contexto`: la instantánea del pasado validado ([`InstantaneaPot`]). Aporta el flujo; en esta
///   fase **no** se consultan `D`, `N(s)`, inyecciones ni salidas ancla. El token retiene esta
///   misma referencia, así que la fase AES **no** puede recibir otro contexto.
///
/// # Errores
/// Siempre `Err(EstadoPot::PotInvalido(..))` o `Err(EstadoPot::PotPendiente(..))`. El valor
/// `PotValido` **no** es alcanzable aquí.
pub fn verificar_rango_pot_fase_previa<'a, C>(
    cabecera: &'a zx_core::DagBlockHeader,
    justificacion: &'a JustificacionPot,
    contexto: &'a C,
) -> Result<TokenRangoPot<'a, C>, EstadoPot>
where
    C: InstantaneaPot,
{
    // 0 · D-P08: no hay génesis DAG. Una cabecera PoST con cero padres es inválida **siempre**,
    //     sin tocar AES; `zx-dag` ya la rechaza y aquí se repite para no depender del llamante.
    if cabecera.padres.count() == 0 {
        return Err(EstadoPot::PotInvalido(MotivoPotInvalido::SinPadres));
    }

    // 1 · Estructura, sin AES: cota de slot de TODOS los padres (C-HDR-05 · C-FLU-02).
    let pasado = match contexto.pasado() {
        Ok(p) => p,
        Err(motivo) => return Err(EstadoPot::PotPendiente(motivo)),
    };
    let seleccionado = cabecera.padres.seleccionado();
    let mut slot_sp: Option<u64> = None;
    for padre in core::iter::once(&seleccionado).chain(cabecera.padres.extras().iter()) {
        let Some(entrada) = entrada_de(pasado, padre) else {
            return Err(EstadoPot::PotPendiente(
                MotivoPotPendiente::PasadoIncompleto,
            ));
        };
        if entrada.slot > cabecera.slot {
            return Err(EstadoPot::PotInvalido(
                MotivoPotInvalido::SlotDePadrePosterior {
                    padre: *padre,
                    slot_padre: entrada.slot,
                    slot_bloque: cabecera.slot,
                },
            ));
        }
        if padre == &seleccionado {
            slot_sp = Some(entrada.slot);
        }
    }
    let Some(slot_sp) = slot_sp else {
        return Err(EstadoPot::PotPendiente(
            MotivoPotPendiente::PasadoIncompleto,
        ));
    };

    // 1 · `d = slot(B) − slot(sp(B))` y número real de portadores (C-HDR-07).
    if let Err(motivo) = diferencia_de_slots(justificacion, cabecera.slot, slot_sp) {
        return Err(EstadoPot::PotInvalido(
            MotivoPotInvalido::DiferenciaDeSlots(motivo),
        ));
    }

    // 1b · Flujo, sin AES: pasado consistente de flujo (C-FLU-14).
    match contexto.flujo_candidato_en(cabecera.slot) {
        Ok(_) => {}
        Err(motivo) => return Err(EstadoPot::PotPendiente(motivo)),
    }
    for x in pasado {
        match contexto.flujo_candidato_en(x.slot) {
            Ok(flujo_candidato) if flujo_candidato == x.flujo => {}
            Ok(_) => {
                return Err(EstadoPot::PotInvalido(
                    MotivoPotInvalido::FlujoDePasadoDiscrepa {
                        bloque: x.hash,
                        slot: x.slot,
                    },
                ));
            }
            Err(motivo) => return Err(EstadoPot::PotPendiente(motivo)),
        }
    }

    Ok(TokenRangoPot {
        cabecera,
        justificacion,
        contexto,
        hash_candidato: cabecera.block_hash(),
        slot_sp,
    })
}

/// Fase AES de `C-POT-08`: pasos 3 (caché contextual, `C-POT-07`) y 4 (cadena AES y anclaje,
/// `C-POT-05`), más la retención por reloj (`C-NET-32.2`) y el presupuesto (`C-NET-33`).
///
/// Recibe el token de [`verificar_rango_pot_fase_previa`], ya atado por préstamo al candidato, a su
/// justificación y a la **misma** instantánea contextual `&C` que acreditó la fase previa. **No**
/// recibe el contexto como argumento: lo lee del token. A3 debe verificar el sello ZIP-215
/// (`C-HDR-04`) **antes** de llamar aquí; esta función **no** comprueba sello ni PoAS.
///
/// La salida ancla se toma de `contexto.salida_validada(slot(sp) + D)`, **nunca** de
/// `cabecera.pot_output`; `pot_output` solo se usa al final como redundancia comprobada.
///
/// # La prueba se construye solo al final
///
/// [`EstadoPot::PotValido`] lleva una [`PruebaPotValidada`]. Se construye **después** de que todos
/// los portadores del rango hayan pasado caché o AES, de que el resultado encadenado iguale
/// `cabecera.pot_output` y de que la **salida auditada** `salida(f, slot(B))` quede resuelta:
///
/// - con `d > D` el slot auditado cae en el rango y la salida se captura del portador **ya
///   verificado** (jamás de `contexto.salida_validada`, que no la tiene);
/// - con `d ≤ D` (incluido `d = 0`) la salida auditada la aporta `contexto.salida_validada`, y si
///   falta el estado es `Pendiente`, nunca `cabecera.pot_output` ni cero.
///
/// Si `d > D` y el portador del slot auditado no aparece por inconsistencia, también es
/// `Pendiente(ContextoAusente)`, nunca `Válido`. El `bloque` de la prueba es el `block_hash` del
/// candidato acreditado por la fase previa.
///
/// # La firma impide pasar otro contexto
///
/// Como el token retiene `&C`, no existe una llamada que reciba el token obtenido con un contexto
/// A y un contexto B distinto. La forma antigua de dos argumentos ya no compila:
///
/// ```compile_fail
/// use zx_post::pot_rango::{
///     CachePotVerificada, InstantaneaPot, PresupuestoPot, TokenRangoPot,
///     verificar_rango_pot_fase_aes,
/// };
///
/// fn llamada_antigua<C: InstantaneaPot, P: PresupuestoPot>(
///     token: TokenRangoPot<'_, C>,
///     ctx_b: &C,
///     reloj: u64,
///     cache: &mut CachePotVerificada,
///     presupuesto: &mut P,
/// ) {
///     // El contexto ya no es un argumento: la llamada de cinco argumentos falla.
///     let _ = verificar_rango_pot_fase_aes(token, ctx_b, reloj, cache, presupuesto);
/// }
/// # fn main() {}
/// ```
///
/// # Límite real
///
/// `&C` impide pasar otro contexto o mutarlo normalmente entre fases, pero **no** impide la
/// mutabilidad interior: una implementación podría cambiar sus respuestas entre ambas fases. Este
/// núcleo **no acredita producción** por esa vía; el derivador futuro entregará una instantánea
/// inmutable del pasado ya validado.
#[must_use]
pub fn verificar_rango_pot_fase_aes<C, P>(
    token: TokenRangoPot<'_, C>,
    reloj_pot: u64,
    cache: &mut CachePotVerificada,
    presupuesto: &mut P,
) -> EstadoPot
where
    C: InstantaneaPot,
    P: PresupuestoPot,
{
    let cabecera = token.cabecera;
    let justificacion = token.justificacion;
    let contexto = token.contexto;

    // 4 · Aritmética comprobada del rango y reloj PoT (C-NET-32.2).
    let retardo = match contexto.retardo_autoria() {
        Ok(d) => d,
        Err(motivo) => return EstadoPot::PotPendiente(motivo),
    };
    let Some(slot_base) = token.slot_sp.checked_add(retardo) else {
        return EstadoPot::PotPendiente(MotivoPotPendiente::AritmeticaDeSlotsDesbordada);
    };
    let Some(slot_fin) = cabecera.slot.checked_add(retardo) else {
        return EstadoPot::PotPendiente(MotivoPotPendiente::AritmeticaDeSlotsDesbordada);
    };
    if slot_fin > reloj_pot {
        let primer_slot_del_rango = if justificacion.is_empty() {
            slot_fin
        } else {
            let Some(slot) = slot_base.checked_add(1) else {
                return EstadoPot::PotPendiente(MotivoPotPendiente::AritmeticaDeSlotsDesbordada);
            };
            slot
        };
        return EstadoPot::PotPendiente(MotivoPotPendiente::RelojFuturo {
            slot: primer_slot_del_rango.max(reloj_pot.saturating_add(1)),
            reloj_pot,
        });
    }

    // 4 · Salida ya validada en `slot(sp(B)) + D`, del pasado (C-POT-05).
    let mut salida = match contexto.salida_validada(slot_base) {
        Ok(s) => s,
        Err(motivo) => return EstadoPot::PotPendiente(motivo),
    };

    // Slot auditado (C-POT-03): `slot(B)`. Si cae dentro del rango (`d > D`) se captura del
    // portador ya verificado; si está en el pasado (`d ≤ D`, incluido `d = 0`) se resuelve al
    // final desde la instantánea. Nunca se consulta el pasado para el primer caso.
    let slot_auditado = cabecera.slot;
    let mut salida_auditada_del_portador: Option<[u8; POT_OUTPUT_BYTES]> = None;

    for (indice, portador) in justificacion.bundles().iter().enumerate() {
        let indice = u64::try_from(indice).unwrap_or(u64::MAX);
        let Some(slot) = slot_base.checked_add(indice.saturating_add(1)) else {
            return EstadoPot::PotPendiente(MotivoPotPendiente::AritmeticaDeSlotsDesbordada);
        };

        // Inyección declarada EXACTAMENTE en su slot, a lo sumo una (C-POT-01, C-FLU-12).
        let entropia = match contexto.inyecciones_en(slot) {
            Ok(InyeccionesPot::Ninguna) => None,
            Ok(InyeccionesPot::Una(inyeccion)) => {
                if inyeccion.ancla == token.hash_candidato {
                    return EstadoPot::PotPendiente(MotivoPotPendiente::ContextoCircular { slot });
                }
                Some(inyeccion.entropia)
            }
            Ok(InyeccionesPot::Varias) => {
                return EstadoPot::PotPendiente(MotivoPotPendiente::InyeccionesMultiples { slot });
            }
            Err(motivo) => return EstadoPot::PotPendiente(motivo),
        };
        let semilla = semilla_siguiente(salida, entropia);

        // `N(s)` del contexto, proyectado sin panic ni envoltura (C-POT-04).
        let iteraciones = match contexto.iteraciones(slot) {
            Ok(n) => n,
            Err(motivo) => return EstadoPot::PotPendiente(motivo),
        };
        if let Err(error) = proyectar_iteraciones(iteraciones) {
            return EstadoPot::PotPendiente(MotivoPotPendiente::IteracionesFueraDeDominio {
                slot,
                error,
            });
        }

        // El rango puede cruzar `t_j`: la clave usa el flujo vigente EN ESTE slot,
        // no el de `slot(B)` (SPEC §7.1.3–4, C-POT-07).
        let flujo = match contexto.flujo_candidato_en(slot) {
            Ok(f) => f,
            Err(motivo) => return EstadoPot::PotPendiente(motivo),
        };
        let salida_portador = salida_de(portador);
        let clave = ClaveCachePot {
            flujo,
            slot,
            semilla,
            iteraciones,
        };

        // 3 · Caché por clave contextual (C-POT-07). Solo entran portadores de 128 B ya
        //     verificados: no hay entradas parciales de 16 B.
        let mut verificado_sin_aes = false;
        if let Some(entrada) = cache.buscar(&clave) {
            // Misma clave pero salida o portador distintos: discrepancia sin AES.
            if entrada.salida != salida_portador || entrada.portador != *portador {
                return EstadoPot::PotInvalido(MotivoPotInvalido::CacheDiscrepante { slot });
            }
            verificado_sin_aes = true;
        }

        // 4 · Cadena AES del rango (C-POT-02).
        if !verificado_sin_aes {
            if !presupuesto.consumir_slot(slot) {
                return EstadoPot::PotPendiente(MotivoPotPendiente::PresupuestoAgotado { slot });
            }
            match verificar_slot_aes(semilla, iteraciones, portador) {
                Ok(true) => {}
                Ok(false) => {
                    return EstadoPot::PotInvalido(MotivoPotInvalido::AesFallido { slot });
                }
                Err(error) => {
                    return EstadoPot::PotPendiente(
                        MotivoPotPendiente::IteracionesFueraDeDominio { slot, error },
                    );
                }
            }
            // Solo tras un AES exitoso se registra el portador completo.
            cache.registrar(
                clave,
                EntradaCacheVerificada {
                    salida: salida_portador,
                    portador: *portador,
                },
            );
        }

        // La salida auditada solo se captura DESPUÉS de que este portador haya pasado caché o AES
        // (C-POT-03): un portador mutado no debe dejar una prueba utilizable.
        if slot == slot_auditado {
            salida_auditada_del_portador = Some(salida_portador);
        }

        salida = salida_portador;
    }

    // 4 · Anclaje final (C-POT-05). Con `d = 0` la «cadena» es el ancla acreditada del mismo
    //     slot: no se declara válido un rango vacío por omisión.
    if salida != cabecera.pot_output {
        return EstadoPot::PotInvalido(MotivoPotInvalido::PotOutputNoCoincide { obtenido: salida });
    }

    // 4 · Salida del slot auditado (C-POT-03). Solo se publica la prueba al final, con el rango
    //     entero anclado y la salida resuelta de su fuente correcta.
    let salida_auditada = if slot_auditado > slot_base {
        match salida_auditada_del_portador {
            Some(salida) => salida,
            None => {
                return EstadoPot::PotPendiente(MotivoPotPendiente::ContextoAusente {
                    que: "salida del slot auditado",
                });
            }
        }
    } else {
        match contexto.salida_validada(slot_auditado) {
            Ok(salida) => salida,
            Err(motivo) => return EstadoPot::PotPendiente(motivo),
        }
    };

    EstadoPot::PotValido(PruebaPotValidada {
        bloque: token.hash_candidato,
        slot_auditado,
        salida_auditada,
    })
}

/// Verifica el rango PoT de `cabecera` contra su instantánea contextual (`C-POT-08`).
///
/// Encadena [`verificar_rango_pot_fase_previa`] y [`verificar_rango_pot_fase_aes`]. Es una
/// conveniencia **solo para el núcleo PoT**: **no** comprueba el sello (`C-HDR-04`) ni el reto y
/// la solución PoAS (`C-POT-03`), ni la anticadena, ni que `prev_hash` sea el `sp` de GHOSTDAG
/// (`C-GD-03`); usa el padre seleccionado **declarado** como base de `d`, igual que el gate de
/// `zx-core`. **No** es `validar_bloque` ni un validador integral. Cuando A3 deba insertar el
/// sello entre las dos fases, debe llamar a las dos funciones por separado.
///
/// El `EstadoPot::PotValido` que devuelve ya es el **enriquecido**: al superar el núcleo, lleva la
/// [`PruebaPotValidada`] con `bloque`, `slot_auditado` y `salida_auditada`, lista para el paso 5
/// (reto y PoAS), que esta conveniencia **no** ejecuta.
///
/// Ese `PotValido` **no** es validez de bloque: puede inducirse con una [`InstantaneaPot`]
/// inventada (ver el contraejemplo de procedencia en [`PruebaPotValidada`]). Por eso la puerta A3
/// **no** debe aceptarlo como tal: debe interponer el sello (`C-HDR-04`) y la procedencia causal
/// del pasado, y encadenar las dos fases por separado.
///
/// # Entradas
///
/// - `cabecera`: **candidato**. Solo se leen `slot`, `padres` y `pot_output`.
/// - `justificacion`: los portadores del candidato, evidencia reemplazable.
/// - `contexto`: la instantánea del pasado validado ([`InstantaneaPot`]). Aporta `f`, las
///   inyecciones, `N(s)`, `D` y la salida ancla; **nunca** el candidato.
/// - `reloj_pot`: reloj PoT **del nodo** (`C-NET-32.2`), estado local que no viaja en el bloque.
/// - `cache`: caché verificada del nodo (`C-POT-07`), con estado privado.
/// - `presupuesto`: presupuesto de CPU inyectado (`C-NET-33`).
#[must_use]
pub fn verificar_rango_pot<C, P>(
    cabecera: &zx_core::DagBlockHeader,
    justificacion: &JustificacionPot,
    contexto: &C,
    reloj_pot: u64,
    cache: &mut CachePotVerificada,
    presupuesto: &mut P,
) -> EstadoPot
where
    C: InstantaneaPot,
    P: PresupuestoPot,
{
    let token = match verificar_rango_pot_fase_previa(cabecera, justificacion, contexto) {
        Ok(token) => token,
        Err(estado) => return estado,
    };
    // El token retiene `contexto`: la fase AES no lo recibe como argumento.
    verificar_rango_pot_fase_aes(token, reloj_pot, cache, presupuesto)
}

/// `slot(B) − slot(sp(B))` comprobado, con el número real de portadores (`C-HDR-07`).
///
/// Reutiliza la semántica y el tipo de error del gate de `zx-core`
/// (`comprobar_diferencia_slots_del_bloque`), que toma el bloque entero; aquí la entrada es la
/// pareja cabecera + justificación y el `slot(sp)` lo aporta el contexto.
fn diferencia_de_slots(
    justificacion: &JustificacionPot,
    slot_b: u64,
    slot_sp: u64,
) -> Result<(), ErrorDiferenciaSlots> {
    let Some(d) = slot_b.checked_sub(slot_sp) else {
        return Err(ErrorDiferenciaSlots::Underflow { slot_b, slot_sp });
    };
    if d > MAX_BUNDLES_POT as u64 {
        return Err(ErrorDiferenciaSlots::ExcedeMaximo { diferencia: d });
    }
    let portadores = u64::try_from(justificacion.len()).unwrap_or(u64::MAX);
    if portadores != d {
        return Err(ErrorDiferenciaSlots::NoCoincide {
            bundles: portadores,
            diferencia: d,
        });
    }
    Ok(())
}

/// Busca un ancestro en el pasado por su identificador.
fn entrada_de<'a>(pasado: &'a [BloqueDelPasado], hash: &BlockHash) -> Option<&'a BloqueDelPasado> {
    pasado.iter().find(|bloque| &bloque.hash == hash)
}

/// La salida de un portador es su **último** checkpoint (`C-POT-02`).
fn salida_de(portador: &PotCheckpoints) -> [u8; POT_OUTPUT_BYTES] {
    *checkpoints_a_primitiva(portador).output()
}

/// Pruebas **internas** que observan la [`PruebaPotValidada`] a través de sus getters `pub(crate)`.
///
/// La integración (`tests/pot_rango.rs`) solo puede ver el estado y comparar pruebas entre sí; para
/// comprobar que `salida_auditada` es exactamente la del portador o la del contexto hacen falta los
/// getters, que se mantienen `pub(crate)` para no exponer al nodo un inspector de un dato interno.
#[cfg(test)]
mod pruebas_salida_auditada {
    #![expect(
        clippy::expect_used,
        clippy::panic,
        reason = "los tests fallan con panic por diseño"
    )]

    use core::num::NonZeroU32;
    use std::collections::BTreeMap;

    use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
    use zx_core::wire_dag::{
        CHECKPOINTS_POR_BUNDLE, JustificacionPot, POT_OUTPUT_BYTES, PotCheckpoints,
    };
    use zx_core::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_pot::tipos::{PotCheckpoints as PotCheckpointsPrimitiva, PotSeed};

    use super::{
        BloqueDelPasado, CachePotVerificada, EstadoPot, FLUJO_BYTES, InstantaneaPot,
        InyeccionesPot, MotivoPotPendiente, PresupuestoPot, verificar_rango_pot_fase_aes,
        verificar_rango_pot_fase_previa,
    };
    use crate::pot::semilla_siguiente;

    const FLUJO: [u8; FLUJO_BYTES] = [0x11; FLUJO_BYTES];
    const BASE: [u8; POT_OUTPUT_BYTES] = [0xAB; POT_OUTPUT_BYTES];
    const AUDITADA: [u8; POT_OUTPUT_BYTES] = [0x5A; POT_OUTPUT_BYTES];
    const N: u64 = 16;
    const SLOT_SP: u64 = 100;
    const RETARDO: u64 = 2;
    const RELOJ: u64 = 1_000;

    /// Instantánea mínima para las pruebas internas: datos libres, sin procedencia acreditada.
    struct ContextoUnit {
        flujo: [u8; FLUJO_BYTES],
        pasado: Vec<BloqueDelPasado>,
        iteraciones: BTreeMap<u64, u64>,
        retardo: u64,
        salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
    }

    impl InstantaneaPot for ContextoUnit {
        fn flujo_candidato_en(&self, _slot: u64) -> Result<[u8; FLUJO_BYTES], MotivoPotPendiente> {
            Ok(self.flujo)
        }

        fn pasado(&self) -> Result<&[BloqueDelPasado], MotivoPotPendiente> {
            Ok(&self.pasado)
        }

        fn inyecciones_en(&self, _slot: u64) -> Result<InyeccionesPot, MotivoPotPendiente> {
            Ok(InyeccionesPot::Ninguna)
        }

        fn iteraciones(&self, slot: u64) -> Result<u64, MotivoPotPendiente> {
            self.iteraciones
                .get(&slot)
                .copied()
                .ok_or(MotivoPotPendiente::ContextoAusente { que: "N(s)" })
        }

        fn retardo_autoria(&self) -> Result<u64, MotivoPotPendiente> {
            Ok(self.retardo)
        }

        fn salida_validada(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], MotivoPotPendiente> {
            self.salidas
                .get(&slot)
                .copied()
                .ok_or(MotivoPotPendiente::ContextoAusente {
                    que: "salida ancla",
                })
        }
    }

    struct PresupuestoUnit(usize);

    impl PresupuestoPot for PresupuestoUnit {
        fn consumir_slot(&mut self, _slot: u64) -> bool {
            if self.0 == 0 {
                false
            } else {
                self.0 -= 1;
                true
            }
        }
    }

    fn hash_de(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    /// Portadores, iteraciones y salidas por slot de una cadena AES de prueba.
    type CadenaGenerada = (
        Vec<PotCheckpoints>,
        BTreeMap<u64, u64>,
        BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
    );

    /// Convierte un portador de la primitiva al wire **sin** llamar a `pot::checkpoints_a_wire`:
    /// ese punto de entrada público está declarado huérfano y una llamada desde tests internos lo
    /// daría por alcanzado (ver `ci/alcance-consenso.sh`). Aquí se reproduce la conversión valor a
    /// valor, igual que el adaptador.
    fn a_wire(carrier: &PotCheckpointsPrimitiva) -> PotCheckpoints {
        let mut outputs = [[0u8; POT_OUTPUT_BYTES]; CHECKPOINTS_POR_BUNDLE];
        for (destino, fuente) in outputs.iter_mut().zip(carrier.iter()) {
            *destino = **fuente;
        }
        PotCheckpoints::desde_outputs(outputs)
    }

    /// Genera una cadena AES real del rango: portadores, iteraciones y salidas por slot.
    fn cadena(slot_sp: u64, retardo: u64, d: u64) -> CadenaGenerada {
        let mut portadores = Vec::new();
        let mut iteraciones = BTreeMap::new();
        let mut salidas = BTreeMap::new();
        salidas.insert(slot_sp + retardo, BASE);
        let mut salida = BASE;
        for i in 1..=d {
            let slot = slot_sp + retardo + i;
            let semilla = semilla_siguiente(salida, None);
            iteraciones.insert(slot, N);
            let carrier = zx_pot::prove(
                PotSeed::from(semilla),
                NonZeroU32::new(u32::try_from(N).expect("N cabe en u32")).expect("N > 0"),
            )
            .expect("N múltiplo de 16");
            salida = *carrier.output();
            salidas.insert(slot, salida);
            portadores.push(a_wire(&carrier));
        }
        (portadores, iteraciones, salidas)
    }

    fn cabecera(slot: u64, pot_output: [u8; POT_OUTPUT_BYTES], sp: BlockHash) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xc478_80ea,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
            timestamp: 1_788_480_000,
            height: 1,
            slot,
            pot_output,
            rango_solucion: 5,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
            padres: PadresDag::nuevo(sp, &[]).expect("padres canónicos"),
            sello: [0u8; 64],
        }
    }

    fn contexto_con(
        sp: BlockHash,
        retardo: u64,
        iteraciones: BTreeMap<u64, u64>,
        salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
    ) -> ContextoUnit {
        ContextoUnit {
            flujo: FLUJO,
            pasado: vec![BloqueDelPasado {
                hash: sp,
                slot: SLOT_SP,
                timestamp: 0,
                flujo: FLUJO,
            }],
            iteraciones,
            retardo,
            salidas,
        }
    }

    /// Núcleo completo: devuelve el estado para poder exigir variantes o una prueba.
    ///
    /// Encadena las dos fases explícitamente para no llamar a `verificar_rango_pot`, que está
    /// declarado huérfano en `ci/alcance-consenso.sh`: una llamada desde tests internos lo daría
    /// por alcanzado sin que exista una ruta de producción.
    fn verificar(
        cabecera: &DagBlockHeader,
        contexto: &ContextoUnit,
        justificacion: &JustificacionPot,
    ) -> EstadoPot {
        let token = match verificar_rango_pot_fase_previa(cabecera, justificacion, contexto) {
            Ok(token) => token,
            Err(estado) => return estado,
        };
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoUnit(1_000);
        // El token retiene `contexto`: la fase AES no lo recibe como argumento.
        verificar_rango_pot_fase_aes(token, RELOJ, &mut cache, &mut presupuesto)
    }

    #[test]
    fn con_d_mayor_que_d_la_prueba_lleva_la_salida_del_portador_auditado() {
        // `d = 3 > D = 2`: el slot auditado (103) cae en el rango y hay portadores posteriores.
        let (portadores, iteraciones, salidas) = cadena(SLOT_SP, RETARDO, 3);
        let slot_b = SLOT_SP + 3;
        let slot_base = SLOT_SP + RETARDO;
        assert!(slot_b > slot_base, "d > D");
        let esperada = *salidas.get(&slot_b).expect("salida del portador auditado");
        let pot_output = *salidas.get(&(slot_b + RETARDO)).expect("último portador");

        // El mapa que recibe la instantánea es SOLO lo que el verificador puede conocer del pasado:
        // el ancla del rango y cualquier salida ancestral anterior. Se eliminan **todos** los
        // portadores de `B` (103, 104 y 105), no solo el auditado, para no dejar una vía accidental
        // desde datos del candidato hacia el contexto.
        let solo_pasado: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]> = salidas
            .iter()
            .filter(|(slot, _)| **slot <= slot_base)
            .map(|(slot, salida)| (*slot, *salida))
            .collect();
        assert!(!solo_pasado.contains_key(&slot_b));
        assert!(
            solo_pasado.contains_key(&slot_base),
            "el ancla del rango sí entra en el pasado"
        );

        let sp = hash_de(0x01);
        let cabecera = cabecera(slot_b, pot_output, sp);
        let justificacion = JustificacionPot::nueva(portadores).expect("≤ 150 portadores");
        let contexto = contexto_con(sp, RETARDO, iteraciones, solo_pasado);

        match verificar(&cabecera, &contexto, &justificacion) {
            EstadoPot::PotValido(prueba) => {
                assert_eq!(prueba.bloque(), cabecera.block_hash());
                assert_eq!(prueba.slot_auditado(), slot_b);
                assert_eq!(prueba.salida_auditada(), esperada);
                assert_ne!(
                    prueba.salida_auditada(),
                    cabecera.pot_output,
                    "la prueba debe ser la salida auditada, no el pot_output futuro"
                );
            }
            otro => panic!("se esperaba prueba válida, llegó {otro:?}"),
        }
    }

    #[test]
    fn con_d_cero_y_d_positivo_la_prueba_lleva_el_ultimo_portador_sin_tocar_el_contexto() {
        // `D = 0`, `d = 3`: el slot auditado (103) es el ÚLTIMO portador del rango y su posición
        // coincide con `pot_output` (`slot(B) + D = slot(B)`). La salida auditada debe salir del
        // portador ya verificado, nunca de `contexto.salida_validada(103)`, que aquí no existe.
        let (portadores, iteraciones, salidas) = cadena(SLOT_SP, 0, 3);
        let slot_b = SLOT_SP + 3;
        let slot_base = SLOT_SP;
        assert_eq!(slot_b, slot_base + 3, "el auditado es el último portador");
        let pot_output = *salidas.get(&slot_b).expect("último portador");

        // El contexto recibe solo el ancla del rango: ninguna salida de los portadores de `B`.
        let solo_pasado: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]> = salidas
            .iter()
            .filter(|(slot, _)| **slot <= slot_base)
            .map(|(slot, salida)| (*slot, *salida))
            .collect();
        assert_eq!(solo_pasado.len(), 1, "solo el ancla");
        assert!(!solo_pasado.contains_key(&slot_b));

        let sp = hash_de(0x01);
        let cabecera = cabecera(slot_b, pot_output, sp);
        let justificacion = JustificacionPot::nueva(portadores).expect("≤ 150 portadores");
        let contexto = contexto_con(sp, 0, iteraciones, solo_pasado);

        match verificar(&cabecera, &contexto, &justificacion) {
            EstadoPot::PotValido(prueba) => {
                assert_eq!(
                    prueba.bloque(),
                    cabecera.block_hash(),
                    "ligada al candidato"
                );
                assert_eq!(prueba.slot_auditado(), slot_b);
                assert_eq!(prueba.salida_auditada(), pot_output);
                assert_eq!(prueba.salida_auditada(), cabecera.pot_output);
            }
            otro => panic!("se esperaba prueba válida, llegó {otro:?}"),
        }
    }

    #[test]
    fn con_d_cero_y_d_cero_la_salida_auditada_es_el_ancla_de_slot_b() {
        // `D = 0`, `d = 0`: justificación vacía; el ancla del contexto está en `slot(B)` (100), que
        // es a la vez el ancla del rango y el slot auditado. Salida auditada y `pot_output` son esa
        // misma posición.
        let (portadores, iteraciones, salidas) = cadena(SLOT_SP, 0, 0);
        let slot_b = SLOT_SP;
        assert!(portadores.is_empty());
        let ancla = *salidas.get(&slot_b).expect("ancla en slot(B)");
        let sp = hash_de(0x01);
        let cabecera = cabecera(slot_b, ancla, sp);
        let justificacion = JustificacionPot::nueva(portadores).expect("cero portadores");
        let contexto = contexto_con(sp, 0, iteraciones.clone(), salidas);

        match verificar(&cabecera, &contexto, &justificacion) {
            EstadoPot::PotValido(prueba) => {
                assert_eq!(prueba.bloque(), cabecera.block_hash());
                assert_eq!(prueba.slot_auditado(), slot_b);
                assert_eq!(prueba.salida_auditada(), ancla);
                assert_eq!(prueba.salida_auditada(), cabecera.pot_output);
            }
            otro => panic!("se esperaba prueba válida, llegó {otro:?}"),
        }

        // Sin el ancla en `slot(B)`: `Pendiente`, nunca `PotValido`.
        let sin_ancla = contexto_con(sp, 0, iteraciones, BTreeMap::new());
        assert_eq!(
            verificar(&cabecera, &sin_ancla, &justificacion),
            EstadoPot::PotPendiente(MotivoPotPendiente::ContextoAusente {
                que: "salida ancla"
            })
        );
    }

    #[test]
    fn con_d_menor_o_igual_que_d_la_prueba_lleva_la_salida_del_contexto() {
        // `d = 1 ≤ D = 2`: el slot auditado (101) está en el pasado validado.
        let (portadores, iteraciones, mut salidas) = cadena(SLOT_SP, RETARDO, 1);
        let slot_b = SLOT_SP + 1;
        let slot_base = SLOT_SP + RETARDO;
        assert!(slot_b <= slot_base, "d ≤ D");
        salidas.insert(slot_b, AUDITADA);

        let pot_output = *salidas.get(&(slot_b + RETARDO)).expect("último portador");
        let sp = hash_de(0x01);
        let cabecera = cabecera(slot_b, pot_output, sp);
        let justificacion = JustificacionPot::nueva(portadores).expect("≤ 150 portadores");
        let contexto = contexto_con(sp, RETARDO, iteraciones, salidas);

        match verificar(&cabecera, &contexto, &justificacion) {
            EstadoPot::PotValido(prueba) => {
                assert_eq!(prueba.slot_auditado(), slot_b);
                assert_eq!(prueba.salida_auditada(), AUDITADA);
                assert_ne!(prueba.salida_auditada(), cabecera.pot_output);
            }
            otro => panic!("se esperaba prueba válida, llegó {otro:?}"),
        }
    }

    #[test]
    fn sin_la_salida_auditada_del_contexto_no_hay_prueba() {
        // Con `d ≤ D`, quitar la salida auditada del pasado deja `Pendiente` aunque el rango y el
        // anclaje final verifiquen.
        let (portadores, iteraciones, mut salidas) = cadena(SLOT_SP, RETARDO, 1);
        let slot_b = SLOT_SP + 1;
        let pot_output = *salidas.get(&(slot_b + RETARDO)).expect("último portador");
        let sp = hash_de(0x01);
        let cabecera = cabecera(slot_b, pot_output, sp);
        let justificacion = JustificacionPot::nueva(portadores).expect("≤ 150 portadores");

        let sin_auditada = contexto_con(sp, RETARDO, iteraciones.clone(), salidas.clone());
        assert!(matches!(
            verificar(&cabecera, &sin_auditada, &justificacion),
            EstadoPot::PotPendiente(MotivoPotPendiente::ContextoAusente { .. })
        ));

        salidas.insert(slot_b, AUDITADA);
        let con_auditada = contexto_con(sp, RETARDO, iteraciones, salidas);
        assert!(matches!(
            verificar(&cabecera, &con_auditada, &justificacion),
            EstadoPot::PotValido(_)
        ));
    }

    /// La prueba se puede nombrar y comparar fuera, pero no fabricar: fuera del módulo los campos
    /// son privados. Este uso comprueba que el tipo es público sin exponer un constructor.
    #[test]
    fn dos_verificaciones_del_mismo_candidato_dan_la_misma_prueba() {
        let (portadores, iteraciones, salidas) = cadena(SLOT_SP, RETARDO, 0);
        let slot_b = SLOT_SP;
        let pot_output = *salidas.get(&(slot_b + RETARDO)).expect("ancla");
        let sp = hash_de(0x01);
        let cabecera = cabecera(slot_b, pot_output, sp);
        let justificacion = JustificacionPot::nueva(portadores).expect("cero portadores");
        let mut salidas = salidas;
        salidas.insert(slot_b, AUDITADA);
        let contexto = contexto_con(sp, RETARDO, iteraciones, salidas);

        let primera = match verificar(&cabecera, &contexto, &justificacion) {
            EstadoPot::PotValido(prueba) => prueba,
            otro => panic!("se esperaba prueba válida, llegó {otro:?}"),
        };
        let segunda = match verificar(&cabecera, &contexto, &justificacion) {
            EstadoPot::PotValido(prueba) => prueba,
            otro => panic!("se esperaba prueba válida, llegó {otro:?}"),
        };
        assert_eq!(primera, segunda);
    }
}
