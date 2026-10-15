//! Crate `zx-post`: PoT puro, rango PoT, puerta conjunta, contexto de transición dev,
//! justificación PoT del wire, productor del bloque de transición (W05b2), servicio PoT local y
//! productor en régimen (W05b3) y firmante seguro local (SL-4b1) (D-P14).
//!
//! Depende solo de `zx-core`, `zx-pot`, `zx-dag` y `zx-poas` (frontera §V8). No depende de
//! `zx-consensus` salvo como `dev-dependency` para minar la cadena PoW de los tests de extremo a
//! extremo.
//!
//! # Lo que este crate NO hace
//!
//! No admite bloques, no inserta en GHOSTDAG, no aplica UTXO, no comprueba el cuerpo y no elige
//! `SR` desde el pasado. `EstadoCabeceraConjunta::Comprobada` acredita solo las pruebas locales
//! contra los contextos recibidos.

#![doc = include_str!("../README.md")]

pub mod cabecera_conjunta;
pub mod contexto_transicion;
pub mod firmante;
pub mod justificacion;
pub mod pot;
pub mod pot_rango;
pub mod productor;
pub mod productor_regimen;
pub mod publicador_pot;
pub mod reloj;
pub mod reloj_post;
pub mod servicio_pot;
pub mod vdf;

pub use cabecera_conjunta::{
    CandidataComprobada, EstadoCabeceraConjunta, EstadoCandidata, HechosPost,
    MotivoCabeceraInvalida, MotivoCabeceraPendiente, verificar_cabecera_conjunta,
    verificar_candidata_para_firma,
};
pub use contexto_transicion::{
    ContextoTransicion, ETIQUETA_PERFIL_DEV, ErrorContextoTransicion, MARCADOR_SEMILLA_S1,
    RegistroValidado,
};
pub use justificacion::{
    ErrorJustificacion, MotivoJustificacion, leer_justificacion, verificar_justificacion_pot,
};
pub use pot::{
    ALEATORIEDAD_BYTES, ENTROPIA_BYTES, ErrorContextoPot, aleatoriedad_de_salida,
    checkpoints_a_primitiva, checkpoints_a_wire, proyectar_iteraciones, reto_desde_salida,
    semilla_genesis, semilla_siguiente, verificar_slot_aes,
};
pub use pot_rango::{
    BloqueDelPasado, CachePotVerificada, ClaveCachePot, EstadoPot, FLUJO_BYTES, InstantaneaPot,
    InyeccionPot, InyeccionesPot, MotivoPotInvalido, MotivoPotPendiente, PresupuestoPot,
    PruebaPotValidada, TokenRangoPot, verificar_rango_pot, verificar_rango_pot_fase_aes,
    verificar_rango_pot_fase_previa,
};
pub use productor::{
    ErrorProductor, FuenteSoluciones, MotivoAbstencion, ParametrosProductor, ProductoFirmado,
    SolucionCandidata, clave_publica_de, producir_con_firmante, producir_sin_firmante,
};
pub use productor_regimen::{
    CuerpoProductor, ErrorCuerpo, ErrorRegimen, preparar_regimen_con_clave_publica,
    producir_en_regimen_con_firmante, producir_en_regimen_sin_firmante,
};
pub use publicador_pot::{ReceptorSalidas, SalidaPublicada, TOPE_COLA_SALIDAS, Timelord};
pub use reloj::{
    Accion, Ajuste, ErrorReloj, EstadoReloj, Racional, Sesgo, T_UMBRAL_DUP, adelanto_con_vdf,
    adelanto_sin_vdf, ajustar, cuantil_mediana_bajo_ataque, mediana, recorte, rho_umbral,
    segundo_vdf_util, sesgo_por_mitades, tau_estimado_ventana,
};
pub use reloj_post::{
    A_EPOCH_DEV, ErrorVdfPost, I_DEV, I_ITER_DEV, L_DEV, N_ITER_DEV, N_MAX_DEV, PERFIL_RELOJ_DEV,
    ParametrosRelojPost, T0_DEV, calcular_v_j, semilla_vdf, verificar_v_j,
};
pub use servicio_pot::{ErrorServicioPot, ServicioPot};
pub use vdf::{
    CadenaSegmentada, EntradaVdf, ErrorVdf, EstadoOrdenVdf, MAX_SEG, PASOS_VALIDOS, PasoVdf,
    cadena_segmentada, contexto_circular, orden_vdf, segmentos,
};
