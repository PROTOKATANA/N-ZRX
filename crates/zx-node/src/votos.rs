//! M9-a · Motor de finalidad por votos del nodo, **solo por peso** (contrato v2, sin la cadena).
//!
//! Vive en el hilo de consenso (el único dueño de `zx-cadena`, D-N07) y no toca la regla de
//! selección: produce votos BLS A3, los evalúa con el contrato de `zx-votos`
//! (`evaluar_certificado` + `verificar_firma_peso`) y devuelve el certificado compacto `0x09` (o el
//! acta de presencia `0x0A`) para que `zx-cadena` ancle el punto de finalidad
//! (`Cadena::anclar_finalidad_por_votos`).
//!
//! ## Piezas
//!
//! - **Tabla `T_n`** (`C-FV-01`): se construye desde el estado de consenso. Solo entran las claves
//!   con **clave BLS de voto registrada** ([`Estado::claves_voto`]) y peso = **sectores que pesan**
//!   (`zx_consensus::transicion::fuente_peso_de`, PT-3bc). El peso de la tabla sigue `C-FV-01.3`
//!   (`b = 2` duplica el peso si la clave tiene prueba PoSt vigente **y** la prima está activa;
//!   B-27: con el verificador inerte `PRIMA_DISPONIBILIDAD_ACTIVA = false`, no cuenta).
//! - **Voto firmado** (contrato v2 A3): `firma = BLS(sk, DOMINIO_VOTO,
//!   mensaje_voto_peso(n, h_B, h_T(n+1), raíz_estado))`; el sobre de red `ZXV3` es de longitud fija
//!   y no lleva VRF ni plazas.
//! - **Cierre**: `evaluar_certificado` valida el certificado por peso (ventana, anclas, encadenado y
//!   quórum por peso) y `verificar_firma_peso` comprueba la firma agregada y el mapa de bits antes
//!   de darlo por adoptado.
//!
//! ## Límites declarados (ver `INFORME.md`)
//!
//! - En dev el peso es de **sectores** con el verificador inerte de PT-3bc; ninguna cifra de
//!   seguridad se publica (FV-D08).
//! - El certificado **no** es estado de consenso en FV-4b-N1: se persiste como evidencia en el
//!   registro estructurado y gobierna el punto de finalidad del nodo (el castigo es FV-4b-N2).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

mod detector;
mod diario;

pub(crate) use detector::{DetectorFalta, VotoDetector};
pub(crate) use diario::{DiarioVotos, ErrorDiario, ResolucionDiario};

use zx_consensus::transicion::sector::pesos_por_clave;
use zx_consensus::transicion::tipos::K_TABLAS_VOTO;
use zx_consensus::transicion::votos::{
    CADUCIDAD_TABLA_VENTANAS, PRIMA_DISPONIBILIDAD_ACTIVA, T_INST_VOTOS, W_REVEAL_SLOTS_VOTOS,
    cierre_ventana,
};
use zx_consensus::transicion::{Estado, HechoVoto};
use zx_core::VotoPesoEvidencia;
use zx_core::{BlockHash, ClaveTablaVoto, OperacionAlmacenamiento};
use zx_votos::agregacion::{
    AGREGADORES_POR_SUBRED, Agregado, DOMINIO_SORTEO, ErrorAgregacion, GeneradorEscalares,
    MensajeVoto, MotivoAgregado, VotoRed, armar_certificado, subred,
};
use zx_votos::agregador::{DatosVentana, ResultadoAgregado};
use zx_votos::peso::CertPrevioPeso;
use zx_votos::ventana_raices::{ResultadoSuelto, VentanaPorRaices};
use zx_votos::{
    CertificadoPeso, Clave, ClavePublica, ClaveSecreta, DOMINIO_VOTO, EntradaPeso, ErrorVotos,
    Firma, FuenteSectores, Hash, LONGITUD_FIRMA, LONGITUD_HASH, ParametrosPerfil, Tabla,
    clave_desde_fuente, construir_certificado, evaluar_certificado, firmar, hash_tabla,
    mensaje_voto_peso, peso_de_clave, peso_total_u128, quorum_peso, serial_certificado_peso,
    umbral_peso, verificar, verificar_firma_peso,
};

// DFV-1-2 · G1 · solo pruebas: verificaciones de firma ejecutadas por `registrar_voto_pasado`.
// Permite demostrar que un voto de una clave no registrada se descarta **antes** de verificar.
// (Comentario normal, no doc: `thread_local!` es una invocación de macro y rustdoc no la documenta.)
#[cfg(test)]
thread_local! {
    static VERIFICACIONES_VOTO_PASADO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// DFV-1-2 · G1 · solo pruebas: reinicia el contador de verificaciones de `registrar_voto_pasado`.
#[cfg(test)]
pub(crate) fn reiniciar_verificaciones_voto_pasado() {
    VERIFICACIONES_VOTO_PASADO.with(|c| c.set(0));
}

/// DFV-1-2 · G1 · solo pruebas: nº de verificaciones de firma en `registrar_voto_pasado`.
#[cfg(test)]
#[must_use]
pub(crate) fn verificaciones_voto_pasado() -> u64 {
    VERIFICACIONES_VOTO_PASADO.with(std::cell::Cell::get)
}

// MOT-2 · B-84 · solo pruebas: verificaciones de firma del voto de subred. `SUBRED` cuenta las que
// hace `recibir_voto_subred` y `ACTUAL` las que repite `recibir_voto_actual`; con el arreglo, un
// voto de subred válido suma `(1, 0)` y no `(1, 1)`.
#[cfg(test)]
thread_local! {
    static VERIFICACIONES_VOTO_SUBRED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static VERIFICACIONES_VOTO_ACTUAL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// MOT-2 · solo pruebas: reinicia los dos contadores de verificación del voto de subred.
#[cfg(test)]
pub(crate) fn reiniciar_verificaciones_voto_subred() {
    VERIFICACIONES_VOTO_SUBRED.with(|c| c.set(0));
    VERIFICACIONES_VOTO_ACTUAL.with(|c| c.set(0));
}

/// MOT-2 · solo pruebas: `(verificaciones en recibir_voto_subred, repeticiones en recibir_voto_actual)`.
#[cfg(test)]
#[must_use]
pub(crate) fn verificaciones_voto_subred() -> (u64, u64) {
    (
        VERIFICACIONES_VOTO_SUBRED.with(std::cell::Cell::get),
        VERIFICACIONES_VOTO_ACTUAL.with(std::cell::Cell::get),
    )
}

// MOT-2 · solo pruebas: nº de veces que `recibir_agregados` tomó el camino **por lotes**. Con azar
// del sistema es ≥ 1; sin azar (C2) es 0, que es la prueba de que se verifica de uno en uno.
#[cfg(test)]
thread_local! {
    static LOTES_AGREGADOS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// MOT-2 · solo pruebas: reinicia el contador de lotes.
#[cfg(test)]
pub(crate) fn reiniciar_lotes_agregados() {
    LOTES_AGREGADOS.with(|c| c.set(0));
}

/// MOT-2 · solo pruebas: nº de lotes verificados por lotes.
#[cfg(test)]
#[must_use]
pub(crate) fn lotes_agregados() -> u64 {
    LOTES_AGREGADOS.with(std::cell::Cell::get)
}

/// PD-1d · M4 · cabecera del sobre de red del voto **por peso** (contrato v2 A3).
pub const CABECERA_VOTO_PESO: &[u8; 4] = b"ZXV3";
/// PD-1d · M12 · cabecera del punto de control externo por peso.
pub const CABECERA_PUNTO_CONTROL_PESO: &[u8; 6] = b"ZXPCP1";
/// PD-1d · M3 · raíz de estado nula (`0^32`) del mensaje A3 mientras PK-24 B no exista.
pub const RAIZ_ESTADO_CERO: Hash = [0u8; 32];
/// Longitud de la clave pública BLS (G1 comprimido).
const LONGITUD_CLAVE_BLS: usize = 48;

/// G2 · número de subredes `S` **constante de la red** (`zx-p2p::config::SUBREDES_VOTO = 64`).
///
/// El motor no importa `zx-p2p` (frontera de crates): este es el valor por defecto de las tres
/// redes y el nodo lo sustituye con [`MotorVotos::nuevo_con_subredes`] cuando su red difiera.
pub const SUBREDES_VOTO_RED: u16 = 64;

/// FV-4b-N1-2 · Material de clave (32 B) de la clave BLS de voto **dev** del nodo, derivado de la
/// semilla y el índice igual que [`crate::claves::ClaveDev`] (misma reproducibilidad por escenario).
///
/// Es la **misma** derivación que usa [`crate::nodo`] al arrancar el motor de votos; se expone aquí
/// para que `zx-txcliente` pueda construir el registro `0x03` de la clave que el nodo firmará y la
/// prueba de posesión. **Solo dev**: no es una ruta de seguridad de red.
#[must_use]
pub fn derivar_ikm_voto(semilla: u64, indice: u32) -> [u8; 32] {
    let mut mensaje = Vec::with_capacity(b"zx-node/voto-bls-dev/v1".len() + 8 + 4);
    mensaje.extend_from_slice(b"zx-node/voto-bls-dev/v1");
    mensaje.extend_from_slice(&semilla.to_le_bytes());
    mensaje.extend_from_slice(&indice.to_le_bytes());
    *zx_core::sha3_256_publico(&mensaje).as_bytes()
}

/// FV-4b-N1-2 · Clave BLS de voto dev para `(semilla, indice)`.
///
/// # Errores
/// [`ErrorVotos::Bls`] si el material derivado no produce una clave válida.
pub fn clave_voto_dev(semilla: u64, indice: u32) -> Result<ClaveSecreta, ErrorVotos> {
    ClaveSecreta::generar(&derivar_ikm_voto(semilla, indice)).map_err(ErrorVotos::Bls)
}

/// Configuración del motor de votos.
#[derive(Debug)]
pub struct ConfigMotorVotos {
    /// Parámetros de perfil (`b`, `f_aus`, `m_min`, `t_inst`…).
    pub perfil: ParametrosPerfil,
    /// Claves BLS secretas **propias** del nodo (las que firma).
    pub claves: Vec<ClaveSecreta>,
    /// FV-4b-N3 · interruptor dev: ¿emite y difunde sus votos? (`--sin-voto` lo apaga).
    pub emitir_votos: bool,
}

/// G4 · resultado de recibir un voto de red **por el tema de su subred**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecepcionVotoSubred {
    /// Voto válido y registrado por el mismo camino que un voto suelto.
    Aceptado {
        /// Clave de voto, en hexadecimal.
        clave: String,
        /// Peso que aporta.
        plazas: u64,
    },
    /// No hay hecho objetivo: se ignora sin penalizar.
    Ignorar {
        /// Motivo corto y estable.
        motivo: &'static str,
    },
    /// Hecho objetivo: se penaliza al par que lo reenvió.
    Penalizar {
        /// Motivo corto y estable.
        motivo: &'static str,
    },
}

/// G5 · respuesta del motor a un agregado recibido de la red.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecepcionAgregado {
    /// Agregado válido: hay que reenviarlo.
    Reenviar,
    /// Otro mensaje, otra tabla o plaza repetida: se ignora sin penalizar.
    Ignorar,
    /// Hecho objetivo: se penaliza al par con este motivo.
    Penalizar(MotivoAgregado),
}

/// G8 · métrica de una subred en una ventana cerrada.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricaSubred {
    /// Subred 0-based.
    pub subred: u16,
    /// Peso del agregado elegido por AG-R14 en la raíz certificada (0 si no hubo agregado).
    pub peso_agregado_elegido: u128,
    /// Agregados válidos aceptados de la subred.
    pub agregados_validos: u64,
}

/// G8 · lo que el motor deja a la vista de una ventana cerrada.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricasAgregacion {
    /// Ventana cerrada.
    pub n: u64,
    /// Votos sueltos registrados **antes** de publicar el agregado propio.
    pub sueltos_antes_de_publicar: u64,
    /// Votos sueltos registrados **después** de publicar el agregado propio.
    pub sueltos_despues_de_publicar: u64,
    /// Peso cubierto por el agregado propio publicado.
    pub peso_agregado_propio: u128,
    /// Por subred, el agregado elegido y cuántos válidos llegaron.
    pub subredes: Vec<MetricaSubred>,
}

/// Una instancia abierta del motor (`T_n`, `h_B`, `h_T` y los votos recibidos).
struct Instancia {
    /// Instancia `n`.
    n: u64,
    /// Candidato `h_B(n)` (mejor punta en la frontera).
    candidato: Hash,
    /// Ancla `h_T(n)` (hash de la tabla de poder).
    ancla: Hash,
    /// Tabla de poder `T_n`.
    tabla: Tabla,
    /// Claves públicas BLS alineadas con `tabla.claves`.
    claves_pub: Vec<ClavePublica>,
    /// Tabla `T_{n+1}` que queda comprometida por el certificado.
    tabla_siguiente: Tabla,
    /// Claves públicas BLS de `tabla_siguiente`.
    pubs_siguiente: Vec<ClavePublica>,
    /// `h_T(n+1)` declarado por los votos de esta instancia.
    h_t_siguiente: Hash,
    /// M1 · raíz de estado propia de esta instancia: la entregó la vista al abrirla y es la que
    /// firman todos los votos propios de la ventana. El motor no la calcula.
    raiz_estado: Hash,
    /// Índice por bytes de clave de voto sobre `tabla.claves`.
    indice: HashMap<Vec<u8>, usize>,
    /// PD-1d · votos por peso aceptados, en orden de llegada.
    votos_peso: Vec<VotoPesoAceptado>,
    /// PD-1d · memoria acotada por clave de votos por peso y evidencias pendientes.
    pares_peso: HashMap<Vec<u8>, ParContradictorioPeso>,
    /// G1 · una sola contabilidad por raíces de la instancia (votos sueltos y agregados).
    ventana: VentanaPorRaices,
    /// G1 · bloque inmutable de la ventana (tabla, claves, pesos, reparto y huella).
    datos: Arc<DatosVentana>,
    /// G5 · agregados válidos aceptados en la ventana, en orden de llegada (métricas G8).
    agregados: Vec<Agregado>,
    /// G6 · ¿ya se publicó el agregado propio de esta ventana?
    agregado_publicado: bool,
    /// G8 · votos sueltos registrados antes de publicar el agregado propio.
    sueltos_antes: u64,
    /// G8 · votos sueltos registrados después de publicar el agregado propio.
    sueltos_despues: u64,
    /// G8 · peso cubierto por el agregado propio publicado.
    peso_agregado_propio: u128,
}

impl Instancia {
    /// A5-c-2c · N3 · B-87 · índices globales (0-based) de la tabla que ya tienen un voto en esta
    /// ventana: un voto suelto aceptado (`votos_peso`) o un bit puesto en un agregado válido
    /// aceptado de esa subred (`agregados`). No se exige la misma raíz: es cobertura observada.
    fn claves_cubiertas(&self) -> HashSet<usize> {
        let mut cubiertas = HashSet::new();
        for voto in &self.votos_peso {
            if let Some(&indice) = self.indice.get(voto.clave.as_slice()) {
                cubiertas.insert(indice);
            }
        }
        for agregado in &self.agregados {
            let indices = self.datos.reparto().claves_de(agregado.subred);
            for (posicion, &global) in indices.iter().enumerate() {
                let bit = agregado
                    .mapa_local
                    .get(posicion >> 3)
                    .is_some_and(|byte| (*byte >> (posicion & 7)) & 1 == 1);
                if bit {
                    cubiertas.insert(global);
                }
            }
        }
        cubiertas
    }
}

/// Recepción de un voto de red.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecepcionVoto {
    /// Voto válido y almacenado para el cierre.
    Aceptado {
        /// Clave de voto, en hexadecimal.
        clave: String,
        /// Plazas que aporta.
        plazas: u64,
    },
    /// Voto rechazado con un motivo corto y estable (para el registro).
    Rechazado {
        /// Motivo del rechazo.
        motivo: &'static str,
    },
}

/// Evento del motor de votos, para el registro estructurado (decisión 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventoMotor {
    /// El nodo emitió un voto.
    VotoEmitido {
        /// Instancia.
        n: u64,
        /// Clave de voto (hex).
        clave: String,
        /// Plazas.
        plazas: u64,
    },
    /// Se adoptó un certificado.
    CertificadoAdoptado {
        /// Instancia.
        n: u64,
        /// Candidato anclado (hex).
        candidato: String,
        /// Plazas contadas.
        plazas: u64,
        /// Umbral de quórum.
        umbral: u64,
    },
    /// FV-N6-C7 · firma propia **suprimida** por el diario durable (conflicto o duda de E/S).
    VotoSuprimido {
        /// Instancia.
        n: u64,
        /// Clave de voto (hex).
        clave: String,
        /// Motivo estático de la supresión.
        motivo: &'static str,
    },
    /// REAN-2 · N5 · candado R4 **liberado** por `F` (el candidato votado ya no está en la cadena
    /// seleccionada y pasó `F_SLOTS` desde su slot). Queda en el registro.
    CandadoLiberado {
        /// Instancia en la que se libera.
        n: u64,
        /// Clave de voto (hex) cuyo candado se suelta.
        clave: String,
        /// Candidato votado que se libera (hex).
        candidato_v: String,
    },
    /// PD-1e · E3 · voto propio observado en **modo peso**: la clave, su peso, si se llegó a firmar
    /// y emitir y, si no, el motivo (`fuera_de_tabla`, `inactiva`, `sin_peso`, `observacion`,
    /// `candado`, `conflicto_diario`, `diario_en_duda`).
    VotoPesoPropio {
        /// Instancia.
        n: u64,
        /// Clave de voto (hex).
        clave: String,
        /// Peso de la clave en la tabla (`0` si no está o no pesa).
        peso: u64,
        /// ¿Se llegó a firmar y emitir el voto propio?
        emitido: bool,
        /// Motivo estático.
        motivo: &'static str,
    },
    /// FV-N6-C7-2 §D · ventana abierta (haya o no emisión propia).
    VentanaAbierta {
        /// Instancia.
        n: u64,
        /// Ancla `T_n` comprometida (hex).
        ancla: String,
        /// `h_T(n+1)` comprometido (hex).
        h_t_siguiente: String,
        /// Candidato de la instancia (hex).
        candidato: String,
        /// FV-N6-C7-3 · reloj del Registro en el que se abrió la ventana (slot PoT).
        slot: u64,
    },
    /// FV-N6-C7-2 §D · ventana cerrada, **con o sin** certificado alcanzado.
    VentanaCerrada {
        /// Instancia cerrada.
        n: u64,
        /// ¿Se alcanzó y adoptó certificado?
        certificado: bool,
        /// Plazas válidas contadas.
        plazas: u64,
        /// Umbral de quórum.
        umbral: u64,
        /// FV-N6-C7-3 · reloj del Registro en el que se cerró la ventana (slot PoT).
        slot: u64,
    },
    /// M8 · al cerrar una ventana, hubo votos aceptados de **más de una** raíz de estado. Un único
    /// aviso por ventana, con la raíz propia, la certificada (si la hubo), los dos grupos de más
    /// peso en el orden de desempate de M5 y si la división dejó sin quórum a todos los grupos
    /// aunque su suma lo alcanzase. Memoria acotada por las claves de la tabla.
    RaizEstadoDiscrepante {
        /// Instancia/ventana cerrada.
        n: u64,
        /// Raíz propia de la instancia (hex).
        propia: String,
        /// Raíz del grupo certificado (hex), o `None` si no hubo certificado.
        certificada: Option<String>,
        /// Raíz del grupo de más peso (hex).
        raiz_mayor: String,
        /// Peso del grupo de más peso.
        peso_mayor: u64,
        /// Raíz del segundo grupo por peso (hex).
        raiz_segunda: String,
        /// Peso del segundo grupo.
        peso_segunda: u64,
        /// Nº de raíces distintas con al menos un voto aceptado.
        raices_distintas: u64,
        /// `true` si ningún grupo llegó al quórum y la suma de todos sí.
        sin_quorum_por_division: bool,
    },
    /// FV-N6-C7-2 · la ventana previa se cerró pero la apertura de `n` resultó inadmisible; el
    /// resultado del cierre ya viaja en el mismo [`PasoVotos`]. No se pierde payload ni eventos.
    AperturaDiferida {
        /// Instancia cuya apertura se difiere.
        n: u64,
        /// Motivo estático del rechazo de apertura.
        motivo: &'static str,
    },
    /// RET-1b E4 · la base `(m, h)` pasó de `m + CADUCIDAD_TABLA_VENTANAS`: el motor no abre ni
    /// firma. Se emite **una sola vez** por motor.
    BaseCaducada {
        /// Ventana de la base caducada.
        m: u64,
        /// Ventana que se intentó abrir.
        n: u64,
    },
    /// RA-2 · R1 · con la base caducada, la ventana `n` no abre en la fase activa del ciclo: el
    /// motor espera a la fase activa siguiente, la del ciclo `j`, que arranca en `inicio`. Se emite
    /// **una vez por ciclo**.
    RearranqueEnEspera {
        /// Ventana de la base caducada.
        m: u64,
        /// Ventana que se intentó abrir.
        n: u64,
        /// Ciclo de la fase activa siguiente.
        j: u64,
        /// Slot de inicio de esa fase activa siguiente.
        inicio: u64,
    },
    /// RA-2 · R1 · con la base caducada y la ventana en la fase activa del ciclo `j`, el estado no
    /// trae la instantánea de la tabla del ciclo (o su contenido): el motor no abre ni firma.
    RearranqueSinTabla {
        /// Ventana de la base caducada.
        m: u64,
        /// Ventana que se intentó abrir.
        n: u64,
        /// Ciclo del que falta la instantánea.
        j: u64,
    },
    /// TB-1c-2 · X4 · N6 · el motor abandona una base **provisional** que la cadena no confirmó.
    BaseProvisionalAbandonada {
        /// Ventana que se abría cuando se abandonó la base.
        n: u64,
        /// Ventana de la base abandonada.
        m_base: u64,
        /// Huella `h_T` de la base abandonada (hex).
        huella: String,
    },
}

/// Resultado de cerrar una instancia.
#[derive(Clone, Debug, Default)]
pub struct CierreVotos {
    /// PD-1d · M6 · certificado compacto por peso de la ventana cerrada, si lo hubo.
    pub certificado_peso: Option<CertificadoPeso>,
    /// PD-1d · M6 · bytes canónicos (`serial_certificado_peso`) del certificado por peso.
    pub certificado_peso_bytes: Option<Vec<u8>>,
    /// PD-1d · M7 · acta de presencia de la ventana cerrada sin quórum, si hubo votos.
    pub acta_peso: Option<CertificadoPeso>,
    /// PD-1d · M7 · bytes canónicos del acta por peso.
    pub acta_peso_bytes: Option<Vec<u8>>,
    /// PD-1e · E9 · claves BLS firmantes del acta por peso, para que el nodo resuelva sus dueños
    /// Ed25519 y deje de incluirla cuando todos consten en `votantes_voto[n]`.
    pub acta_peso_firmantes: Vec<[u8; LONGITUD_CLAVE_BLS]>,
    /// Plazas válidas contadas.
    pub plazas_validas: u64,
    /// Umbral de quórum `U = ceil(2K/3)`.
    pub umbral: u64,
    /// M8 · eventos del cierre (hoy, a lo sumo el aviso de raíz discrepante). `avanzar_con_vista`
    /// los vuelca en los eventos del paso.
    pub eventos: Vec<EventoMotor>,
}

/// PD-1d · M4 · voto de red del modo por peso, longitud fija (contrato v2 A3).
///
/// Codificación: `ZXV3` (4) ‖ `n` u64 BE (8) ‖ `candidato` (32) ‖ `h_t_siguiente` (32) ‖
/// `raiz_estado` (32) ‖ `clave` BLS (48) ‖ `firma` BLS (96) = **252 bytes**. Sin ancla, sin VRF y
/// sin plazas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VotoPeso {
    /// Instancia/ventana `n`.
    pub n: u64,
    /// Candidato `h_B` votado.
    pub candidato: Hash,
    /// `h_T(n+1)` declarado por el voto.
    pub h_t_siguiente: Hash,
    /// Raíz de estado firmada (`0^32` hasta PK-24 B).
    pub raiz_estado: Hash,
    /// Clave pública BLS de voto (G1 comprimido).
    pub clave: [u8; LONGITUD_CLAVE_BLS],
    /// Firma BLS individual sobre A3.
    pub firma: Firma,
}

/// PD-1d · M11/M9 · la firma BLS del voto por peso ya emitida, lista para el `0x08`.
///
/// # Errores
/// No falla: el voto por peso ya lleva la clave BLS de 48 bytes.
#[must_use]
pub fn voto_propio_de_peso(voto: &VotoPeso) -> VotoPropioPayload {
    VotoPropioPayload {
        n: voto.n,
        candidato: voto.candidato,
        h_t_siguiente: voto.h_t_siguiente,
        raiz_estado: voto.raiz_estado,
        clave_bls: voto.clave,
        firma: voto.firma.bytes(),
    }
}

/// PD-1d · voto por peso **aceptado** para el cierre de su ventana.
///
/// Conserva lo que necesitan el certificado (firma, índice por clave) y la evidencia `0x0B`
/// (candidato, `h_t_siguiente` y raíz firmados).
#[derive(Clone, Copy, Debug)]
struct VotoPesoAceptado {
    /// Instancia `n`.
    n: u64,
    /// Candidato `h_B` votado.
    candidato: Hash,
    /// `h_T(n+1)` declarado.
    h_t_siguiente: Hash,
    /// Raíz de estado firmada.
    raiz_estado: Hash,
    /// Clave BLS que firma.
    clave: [u8; LONGITUD_CLAVE_BLS],
    /// Firma BLS individual sobre A3.
    firma: Firma,
}

/// PD-1d · M10 · evidencia de dos votos por peso contradictorios, lista para el `0x0B`.
///
/// El par va en el orden canónico estricto del `0x0B`: `(n, candidato, h_t_siguiente, raíz)` de
/// `voto1` estrictamente menor que el de `voto2`.
#[derive(Clone, Debug)]
pub struct EvidenciaVotosPesoCompleta {
    /// Ventana del primer voto (**menor** en el orden canónico).
    pub n: u64,
    /// DFV-1 · D7 · ventana del segundo voto. En la evidencia de **misma** ventana coincide con
    /// [`Self::n`]; en la falta entre ventanas lleva la ventana mayor.
    pub n2: u64,
    /// Candidato del primer voto (menor).
    pub h1: Hash,
    /// `h_t_siguiente` del primer voto.
    pub h_t1: Hash,
    /// Raíz de estado del primer voto.
    pub raiz1: Hash,
    /// Firma del primer voto.
    pub firma1: Firma,
    /// Clave BLS que votó dos veces.
    pub clave_bls: [u8; LONGITUD_CLAVE_BLS],
    /// Candidato del segundo voto (mayor).
    pub h2: Hash,
    /// `h_t_siguiente` del segundo voto.
    pub h_t2: Hash,
    /// Raíz de estado del segundo voto.
    pub raiz2: Hash,
    /// Firma del segundo voto.
    pub firma2: Firma,
}

/// PD-1d · M10 · memoria acotada por clave de votos por peso válidos y evidencia pendiente.
#[derive(Default)]
struct ParContradictorioPeso {
    /// Hasta dos votos válidos con contenido distinto.
    votos: [Option<VotoPesoAceptado>; 2],
    /// Evidencia pendiente de drenar (a lo sumo una por `(clave, n)`).
    evidencia: Option<EvidenciaVotosPesoCompleta>,
}

impl ParContradictorioPeso {
    /// Registra un voto **ya validado** (clave registrada y activa, con peso y firma A3 válida).
    /// Devuelve `true` si acaba de formarse una pareja contradictoria nueva.
    fn registrar(&mut self, voto: VotoPesoAceptado) -> bool {
        if self.votos.iter().flatten().any(|v| {
            v.candidato == voto.candidato
                && v.h_t_siguiente == voto.h_t_siguiente
                && v.raiz_estado == voto.raiz_estado
        }) {
            return false;
        }
        let Some(hueco) = self.votos.iter_mut().find(|v| v.is_none()) else {
            return false;
        };
        *hueco = Some(voto);
        if self.evidencia.is_some() {
            return false;
        }
        let mut vistos = self.votos.iter().flatten();
        let (Some(a), Some(b)) = (vistos.next(), vistos.next()) else {
            return false;
        };
        // Orden canónico del `0x0B`: `(candidato, h_t_siguiente, raíz)` estrictamente creciente.
        let (v1, v2) = if (a.candidato, a.h_t_siguiente, a.raiz_estado)
            < (b.candidato, b.h_t_siguiente, b.raiz_estado)
        {
            (a, b)
        } else {
            (b, a)
        };
        self.evidencia = Some(EvidenciaVotosPesoCompleta {
            n: v1.n,
            n2: v2.n,
            h1: v1.candidato,
            h_t1: v1.h_t_siguiente,
            raiz1: v1.raiz_estado,
            firma1: v1.firma,
            clave_bls: v1.clave,
            h2: v2.candidato,
            h_t2: v2.h_t_siguiente,
            raiz2: v2.raiz_estado,
            firma2: v2.firma,
        });
        true
    }
}

/// PD-1d · M8 · votos aceptados de la **última ventana cerrada** por peso, para poder remontar un
/// certificado contra **otra** tabla (la del bloque que lo va a incluir).
#[derive(Clone, Debug)]
struct VentanaPesoCerrada {
    /// Instancia cerrada.
    n: u64,
    /// Candidato certificado/votado.
    candidato: Hash,
    /// `h_T(n+1)` declarado.
    h_t_siguiente: Hash,
    /// M5 · raíz de estado del grupo certificado.
    raiz_estado: Hash,
    /// Votos del grupo certificado.
    votos: Vec<VotoPesoAceptado>,
    /// G7 · ¿el grupo certificado llevaba algún agregado? (entonces no se remonta a otra tabla).
    con_agregados: bool,
}

/// Resultado de avanzar el reloj de instancias: lo que hay que difundir y registrar.
#[derive(Clone, Debug, Default)]
pub struct PasoVotos {
    /// PD-1d · M6 · certificado compacto por peso de la instancia cerrada, si lo hubo.
    pub certificado_peso: Option<CertificadoPeso>,
    /// PD-1d · M6 · bytes canónicos (`serial_certificado_peso`) del certificado por peso.
    pub certificado_peso_bytes: Option<Vec<u8>>,
    /// PD-1d · M7 · acta de presencia de la instancia cerrada sin quórum, si hubo votos.
    pub acta_peso: Option<CertificadoPeso>,
    /// PD-1d · M7 · bytes canónicos del acta por peso.
    pub acta_peso_bytes: Option<Vec<u8>>,
    /// PD-1e · E9 · claves BLS firmantes del acta por peso (ver [`CierreVotos`]).
    pub acta_peso_firmantes: Vec<[u8; LONGITUD_CLAVE_BLS]>,
    /// Sobres de voto listos para difundir (`VotoRed` serializado).
    pub votos: Vec<Vec<u8>>,
    /// G3 · voto de red compacto `VotoRed` serializado (248 B) y su subred, por cada voto propio.
    pub votos_red: Vec<(Vec<u8>, u16)>,
    /// Eventos para el registro estructurado.
    pub eventos: Vec<EventoMotor>,
}

/// VS-2 · V3 · resultado de un voto **tardío** del motor (no abre instancia).
///
/// Lo integra [`MotorVotos::votar_tardio`]: los votos A3 ya firmados y los eventos con el motivo de
/// cada negativa. El nodo los encola como tx `0x08` y los registra.
#[derive(Clone, Debug, Default)]
pub struct PasoTardio {
    /// Votos propios firmados (A3), listos para la tx `0x08`.
    pub votos: Vec<VotoPeso>,
    /// G3 · voto de red compacto `VotoRed` serializado (248 B) y su subred, por cada voto tardío.
    pub votos_red: Vec<(Vec<u8>, u16)>,
    /// Eventos para el registro estructurado.
    pub eventos: Vec<EventoMotor>,
}

/// Etiqueta de dominio de los coeficientes del lote (C1 · MOT-2, IPA B-83).
const ETIQUETA_ESCALAR: &[u8] = b"ZX-MOT2-COEFICIENTE-V1";

/// G5 · generador de escalares del lote de agregados del motor (C1 · MOT-2, IPA B-83).
///
/// Cada coeficiente es `SHA3-256(etiqueta ‖ secreto ‖ resumen_del_lote ‖ contador)` y se toman sus
/// 16 primeros bytes. El **secreto** son 32 B del azar del sistema leídos al crear el motor; no se
/// registra, no se guarda en disco y no sale por `Debug`. El **resumen del lote** es el SHA3-256 de
/// la serialización de **todos** los agregados de la llamada a `recibir_agregados`, en su orden,
/// fijado **antes** de verificar. El **contador** sube con cada coeficiente y no vuelve a cero
/// mientras viva el motor. Los coeficientes **sí** se consumen: la [`VentanaPorRaices`] resuelve el
/// lote agregado a agregado y cada bisección pide coeficientes nuevos.
///
/// Sin secreto no existe este generador (C2): el motor entrega los agregados de uno en uno. No hay
/// respaldo predecible.
struct GeneradorAgregados {
    /// Contador monótono de escalares pedidos. No vuelve a cero.
    contador: u64,
    /// Secreto de 32 B del azar del sistema. Solo existe si se pudo leer.
    secreto: [u8; 32],
    /// Resumen SHA3-256 del lote vigente, fijado antes de verificar.
    resumen_lote: Hash,
}

impl GeneradorAgregados {
    /// Generador recién creado, o `None` si el azar del sistema no se pudo leer (C2).
    fn nuevo() -> Option<Self> {
        Some(Self {
            contador: 0,
            secreto: leer_azar_del_sistema()?,
            resumen_lote: [0u8; 32],
        })
    }

    /// C1 · fija el resumen del lote que usarán los coeficientes siguientes, antes de verificar.
    fn fijar_resumen(&mut self, resumen: Hash) {
        self.resumen_lote = resumen;
    }

    /// MOT-2 · solo pruebas: generador con un secreto elegido.
    #[cfg(test)]
    fn con_secreto_para_test(secreto: [u8; 32]) -> Self {
        Self {
            contador: 0,
            secreto,
            resumen_lote: [0u8; 32],
        }
    }
}

/// C1 · lee 32 B del azar del sistema (`/dev/urandom`), con el molde de
/// `zx_p2p::gestor::n_key_aleatoria` (`crates/zx-p2p/src/gestor.rs:776-787`). `None` si no se pudo
/// abrir o leer.
fn leer_azar_del_sistema() -> Option<[u8; 32]> {
    use std::io::Read;
    let mut secreto = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    f.read_exact(&mut secreto).ok()?;
    Some(secreto)
}

impl GeneradorEscalares for GeneradorAgregados {
    fn escalar(&mut self) -> [u8; 16] {
        loop {
            let mut mensaje = Vec::with_capacity(ETIQUETA_ESCALAR.len() + 32 + 32 + 8);
            mensaje.extend_from_slice(ETIQUETA_ESCALAR);
            mensaje.extend_from_slice(&self.secreto);
            mensaje.extend_from_slice(&self.resumen_lote);
            mensaje.extend_from_slice(&self.contador.to_be_bytes());
            self.contador = self.contador.wrapping_add(1);
            let digest = zx_core::sha3_256_publico(&mensaje);
            let mut escalar = [0u8; 16];
            escalar.copy_from_slice(&digest.as_bytes()[..16]);
            // C3 · un coeficiente cero se descarta y se pide el siguiente.
            if escalar != [0u8; 16] {
                return escalar;
            }
        }
    }
}

/// Motor de finalidad por votos.
pub struct MotorVotos {
    /// Parámetros de perfil.
    perfil: ParametrosPerfil,
    /// Claves BLS propias.
    claves: Vec<ClaveSecreta>,
    /// FV-4b-N3 · ¿emite votos?
    emitir_votos: bool,
    /// Instancia abierta, si la hay.
    instancia: Option<Instancia>,
    /// B78-2 · N3: se recibe en una sola ventana cerrada, sin volver a firmar.
    instancia_anterior: Option<Instancia>,
    /// Punto de finalidad anclado por el motor (candidato del último certificado).
    punto: Option<Hash>,
    /// PD-1d · M14 · último certificado por peso adoptado.
    ultimo_certificado_peso: Option<CertificadoPeso>,
    /// B78-2 · N1/N1-bis: pendientes en orden, con cota derivada de la revelación.
    certificados_peso: Vec<CertificadoPeso>,
    /// Contador acumulado para el resumen; no necesita un historial de certificados.
    certificados_adoptados: u64,
    /// Última ventana/slot observados para caducar la recepción y los pendientes.
    reloj_certificados: (u64, u64),
    /// Finalidad y liquidación observadas en la cadena; no son la base provisional.
    finalidad_certificados: Option<u64>,
    liquidacion_certificados: Option<u64>,
    /// N5: el nodo drena después de cada avance/recepción. También está acotada.
    eventos_certificados: VecDeque<(u64, &'static str)>,
    /// N5: solo la primera oferta de un pendiente anterior deja el evento.
    certificados_ofrecidos: HashSet<u64>,
    /// PD-1d · M8 · votos de la última ventana cerrada por peso.
    ventana_peso: Option<VentanaPesoCerrada>,
    /// PD-1d · M12 · tabla y claves de la carga inicial por peso (punto de control externo).
    control_peso: Option<(Tabla, Vec<ClavePublica>)>,
    /// FV-N6-C7 · diario durable de voto, si el nodo lo vinculó. Sin él el motor conserva el
    /// comportamiento en memoria **sin garantía durable** (solo biblioteca/tests).
    diario: Option<DiarioVotos>,
    /// REAN-2 · N2 · `T_{n+1}` **certificada** por la instancia recién cerrada cuya apertura se
    /// difirió por salto de reloj. Solo se guarda una tabla de una instancia que **certificó** (una
    /// instancia sin quórum nunca transmite su tabla siguiente) y solo se usa para su índice exacto.
    apertura_pendiente: Option<(Tabla, Vec<ClavePublica>)>,
    /// FV-4b-N1-2 · votos de una instancia **futura** recibidos antes de abrirla (la red puede
    /// adelantarse unos milisegundos a este nodo). Se reproducen al abrir la instancia; tope
    /// [`MAX_VOTOS_PENDIENTES`] para que un emisor no haga crecer la memoria.
    pendientes: Vec<(u64, Vec<u8>)>,
    /// FV-N6-C7-4 · memoria **monotónica** de primera apertura efectiva: se fija cuando el motor
    /// abre de verdad su primera ventana y **jamás** se rehabilita por cerrarla o por fallar una
    /// apertura posterior. `instancia`/`certificados` pueden quedar vacíos tras ese recorrido
    /// (cerrar sin quórum y diferir la apertura siguiente); esta marca es la que impide volver a
    /// sembrar/reconciliar un motor que ya abrió.
    apertura_efectiva: bool,
    /// VS-2 · V3 · índice de la **última ventana abierta** de verdad por el motor (aunque hoy no
    /// tenga instancia por una apertura diferida). Es el límite inferior del voto tardío.
    ultima_ventana_abierta: Option<u64>,
    /// REAN-2 · N1 · **base** del motor `(m, h)`: ventana del último certificado y su `h_T`
    /// siguiente. Es la más avanzada entre el último certificado adoptado por el motor y la
    /// finalidad **aplicada** en el estado de la cadena seleccionada. Solo avanza.
    ///
    /// AT-1a2 · K1 · el **bloque sellado** que exige B3 **no** vive aquí: sale de la finalidad
    /// aplicada en el `Estado` que el motor recibe al abrir la ventana (`finalidad_votos`), no de un
    /// certificado que el motor conozca pero que ese estado todavía no tenga aplicado.
    base: Option<(u64, Hash)>,
    /// RET-1b E4 · ¿ya se emitió el evento [`EventoMotor::BaseCaducada`]? La emisión es única.
    caducidad_anunciada: bool,
    /// RA-2 · R1 · último ciclo `j` para el que ya se emitió [`EventoMotor::RearranqueEnEspera`]
    /// (una vez por ciclo mientras la ventana no cae en la fase activa).
    rearranque_espera_anunciado: Option<u64>,
    /// RA-2 · R1 · último ciclo `j` para el que ya se emitió [`EventoMotor::RearranqueSinTabla`]
    /// (falta la instantánea del ciclo); una vez por ciclo.
    rearranque_sin_tabla_anunciado: Option<u64>,
    /// RA-2 · R7 · la base se sembró desde la finalidad **ya sellada** del estado (modo peso) sin un
    /// cuerpo `0x04` autenticado; autoriza la primera apertura sobre esa base sin confundirla con un
    /// bootstrap génesis sobre un estado con finalidad.
    base_de_estado: bool,
    /// TB-1c-2 · X4 · N6 · ¿la base vigente es **provisional**? La fija `cerrar_peso` al adoptar el
    /// certificado fuera de cadena y solo deja de serlo cuando el estado de un candidato la confirma
    /// (misma huella con ventana `≥ m`) o cuando se abandona. Sembrar desde el estado o desde un
    /// punto de control **no** es provisional.
    base_provisional: bool,
    /// DFV-1 · D1–D9 · detector de la falta entre ventanas (votos del horizonte y pares).
    detector: DetectorFalta,
    /// G2 · número de subredes `S` de la red (por defecto, [`SUBREDES_VOTO_RED`]).
    subredes: u16,
    /// T1 · B-71 · subredes vigiladas; `None` = todas (mientras nadie fije nada, comportamiento de
    /// hoy). `Some(∅)` = no se vigila ninguna.
    subredes_vigiladas: Option<HashSet<u16>>,
    /// T4 · B-74 · claves salientes vigiladas: clave BLS → **última ventana** en cuya tabla se la
    /// vio. Se olvidan cuando `última + horizonte < n` (T4) y su número no pasa de las claves
    /// vigiladas de la tabla abierta (T5).
    salientes: HashMap<[u8; LONGITUD_CLAVE_BLS], u64>,
    /// T4 · B-74 · tabla de la **ventana anterior que el motor abrió** (`n`, claves), para hallar
    /// las salientes al abrir la siguiente. Una sola estructura, no una por ventana (T7).
    tabla_anterior: Option<(u64, HashSet<[u8; LONGITUD_CLAVE_BLS]>)>,
    /// G8 · métricas de la última ventana cerrada (la orden siguiente las consulta).
    ultimas_metricas: Option<MetricasAgregacion>,
    /// G5 · generador de escalares del lote de agregados (la ventana lo resuelve uno a uno).
    ///
    /// `None` si el azar del sistema no se pudo leer (C2): entonces el motor **no** verifica por
    /// lotes y entrega los agregados de uno en uno. No hay respaldo predecible.
    generador_agregados: Option<GeneradorAgregados>,
    /// C2 · MOT-2 · aviso `azar_del_sistema_no_disponible`: el secreto no se pudo leer al crear el
    /// motor. Se emite una sola vez (es un hecho de creación, no se repite).
    azar_del_sistema_no_disponible: bool,
}

/// REAN-2 · N4/N5 · vista de **solo lectura** de la cadena seleccionada que el candado R4 necesita.
///
/// El motor no posee la cadena: quien lo avanza le pasa esta vista. La implementación real vive en
/// `nodo.rs` sobre `zx_cadena::Cadena`; las pruebas del contrato pueden usar una vista simulada.
pub trait VistaCadena {
    /// `true` si `candidato` es `ancestro` o **desciende** de él en la cadena seleccionada.
    fn desciende(&self, candidato: &Hash, ancestro: &Hash) -> bool;
    /// `true` si `hash` pertenece a la cadena seleccionada.
    fn en_cadena_seleccionada(&self, hash: &Hash) -> bool;
    /// Slot PoT del bloque `hash`, si se conoce.
    fn slot_de(&self, hash: &Hash) -> Option<u64>;
    /// M1 · raíz de estado que este votante firma para la ventana `n` y el candidato dados.
    ///
    /// El motor **no** calcula ninguna raíz: la vista de la cadena se la entrega. La implementación
    /// por defecto devuelve [`RAIZ_ESTADO_CERO`], el comportamiento byte a byte de la base;
    /// `zx_cadena::Cadena` hereda ese valor por defecto y la orden que conecte la raíz de verdad lo
    /// sobrescribirá.
    fn raiz_estado_de_voto(&self, _n: u64, _candidato: &Hash) -> Hash {
        RAIZ_ESTADO_CERO
    }
    /// `true` si `hash` pertenece al **DAG** de la vista (es conocido por ella), esté o no en su
    /// cadena seleccionada.
    ///
    /// La implementación por defecto usa [`Self::desciende`]: en la cadena real `desciende(h, h)`
    /// recorre la cadena seleccionada de `h` y solo es cierto si `h` pertenece al DAG del terminal
    /// seleccionado; un `h` desconocido devuelve `false`. Es la guarda que exige B3 (AT-1a2 · K2),
    /// distinta de [`Self::en_cadena_seleccionada`].
    fn pertenece_al_dag(&self, hash: &Hash) -> bool {
        self.desciende(hash, hash)
    }
    /// DFV-1 · D5 · `true` si `a` y `b` son **bloques distintos en conflicto en el grafo**: ninguno
    /// desciende del otro. Por defecto usa [`Self::desciende`]; la cadena real lo resuelve sobre su
    /// DAG (no solo sobre la cadena seleccionada).
    fn en_conflicto(&self, a: &Hash, b: &Hash) -> bool {
        a != b && !self.desciende(a, b) && !self.desciende(b, a)
    }
    /// DFV-1 · D6 · hecho de la eventual evidencia `0x0B` entre ventanas, calculado con la misma
    /// función que usa la cadena al incluirla (`hecho_de_tx`). `None` si la vista no monta cadena.
    fn hecho_evidencia_entre_ventanas(
        &self,
        _voto1: &VotoPesoEvidencia,
        _voto2: &VotoPesoEvidencia,
        _plazo_slots: u64,
    ) -> Option<HechoVoto> {
        None
    }
}

/// Vista **permisiva** (sin cadena): conserva el comportamiento en memoria de la biblioteca y de
/// los arneses que no montan cadena. El nodo real usa la vista estricta de `nodo.rs`.
struct VistaPermisiva;

impl VistaCadena for VistaPermisiva {
    fn desciende(&self, _candidato: &Hash, _ancestro: &Hash) -> bool {
        true
    }
    fn en_cadena_seleccionada(&self, _hash: &Hash) -> bool {
        true
    }
    fn slot_de(&self, _hash: &Hash) -> Option<u64> {
        None
    }
}

/// REAN-2 · N4/N5 · resultado de aplicar el candado durable a una clave propia.
enum PermisoCandado {
    /// No hay candado guardado para la clave.
    SinCandado,
    /// El candidato es el votado, desciende de él, o la base ya superó `n_v`.
    Permitido,
    /// Liberado por `F`: se suelta el candado con el candidato votado indicado.
    Liberado(Hash),
    /// Candado vigente y candidato en conflicto: no se firma.
    Bloqueado,
}

/// AT-1a2 · K1 · base de B3 tomada del **estado aplicado** que el motor recibe al abrir la ventana.
///
/// Devuelve `(m, S)` solo si `estado.finalidad_votos_h_t` está presente: `m = finalidad_votos_n` y
/// `S = finalidad_votos` (el bloque sellado por esa finalidad; `None` si el estado lo trae de forma
/// incoherente). Un certificado que el motor conoce pero que no está aplicado en este estado **no**
/// cuenta para B3.
fn base_b3_de_estado(estado: &Estado) -> Option<(u64, Option<Hash>)> {
    estado.finalidad_votos_h_t.map(|_| {
        (
            estado.finalidad_votos_n,
            estado.finalidad_votos.map(|b| *b.as_bytes()),
        )
    })
}

/// VS-2 · V6 · ¿el candidato desciende del bloque sellado por la base aplicada en `estado`?
///
/// Sin base (`finalidad_votos_h_t` ausente) no cambia nada: `true`. Con base, solo se firma si el
/// bloque sellado es `Some(S)`, `S` pertenece al DAG de la vista y el candidato desciende de `S`
/// (incluido `candidato == S`). Un sellado ausente, fuera del DAG o del que el candidato no
/// desciende bloquea la firma.
fn desciende_del_sello(estado: &Estado, candidato: &Hash, vista: &dyn VistaCadena) -> bool {
    match base_b3_de_estado(estado) {
        None => true,
        Some((_m, Some(s))) => vista.pertenece_al_dag(&s) && vista.desciende(candidato, &s),
        Some((_m, None)) => false,
    }
}

/// AT-1a2 · K2 (B3) · ¿el bloque `sellado` por la base levanta el candado `(n_v, X)`?
///
/// `true` solo si `sellado` y `X` pertenecen al **DAG** de la vista y `sellado` es `X`, desciende de
/// `X` o está en conflicto con `X` (ni uno desciende del otro). Si `sellado` es un antepasado propio
/// de `X`, es desconocido, o `X` no pertenece al DAG, devuelve `false`: el candado sigue rigiendo.
/// No usa `en_cadena_seleccionada`: dos bloques en conflicto nunca están ambos en la cadena
/// seleccionada vigente, pero sí pueden estarlo en el DAG.
fn b3_levanta_candado(sellado: Option<&Hash>, candidato_v: &Hash, vista: &dyn VistaCadena) -> bool {
    let Some(s) = sellado else {
        return false;
    };
    // K2 · pertenencia al DAG: si `S` o `X` no son conocidos por la vista, el candado sigue.
    if !vista.pertenece_al_dag(s) || !vista.pertenece_al_dag(candidato_v) {
        return false;
    }
    // `desciende(c, a)` es cierto si `c == a` o `c` desciende de `a`: cubre `S = X` y `S`
    // descendiente de `X` → se suelta.
    if vista.desciende(s, candidato_v) {
        return true;
    }
    // Ya se sabe que `S` no desciende de `X`. Si `X` desciende de `S`, `S` es antepasado propio y el
    // candado sigue; si tampoco, hay conflicto y se suelta.
    !vista.desciende(candidato_v, s)
}

/// REAN-2 · N4/N5 · decide si la clave puede firmar `candidato` en la ventana.
///
/// El candado deja de regir cuando la base **aplicada en el estado** avanza a `m ≥ n_v` **y** el
/// bloque que selló levanta el candado según B3 (AT-1a2 · K1/K2). Si rige, la clave firma si el
/// candidato es `candidato_v` o desciende de él; si no, se libera cuando `candidato_v` no está en la
/// cadena seleccionada y `slot_actual ≥ slot(candidato_v) + F_SLOTS` (N5); en otro caso se bloquea.
fn candidato_permitido(
    diario: &DiarioVotos,
    clave: &[u8; 48],
    candidato: &Hash,
    base: Option<(u64, Option<Hash>)>,
    slot_actual: i64,
    vista: &dyn VistaCadena,
) -> Result<PermisoCandado, ErrorDiario> {
    let Some((n_v, candidato_v)) = diario.candado(clave) else {
        return Ok(PermisoCandado::SinCandado);
    };
    if let Some((m, sellado)) = base
        && m >= n_v
        && b3_levanta_candado(sellado.as_ref(), &candidato_v, vista)
    {
        return Ok(PermisoCandado::Permitido);
    }
    if *candidato == candidato_v || vista.desciende(candidato, &candidato_v) {
        return Ok(PermisoCandado::Permitido);
    }
    if !vista.en_cadena_seleccionada(&candidato_v) {
        // RET-1b E7 · si el bloque votado ya no está en la vista (`slot_de` no lo encuentra), la
        // liberación por `F` usa `n_v · T_inst` como cota inferior de su slot: el candado se suelta
        // cuando `slot_actual ≥ n_v · T_inst + F_SLOTS`.
        let slot_v = vista
            .slot_de(&candidato_v)
            .unwrap_or_else(|| n_v.saturating_mul(T_INST_VOTOS));
        let slot_u = u64::try_from(slot_actual).unwrap_or(u64::MAX);
        if slot_u >= slot_v.saturating_add(crate::perfil::F_SLOTS) {
            return Ok(PermisoCandado::Liberado(candidato_v));
        }
    }
    Ok(PermisoCandado::Bloqueado)
}

/// REAN-2 · N2 · claves públicas alineadas con una tabla para `verificar_certificado_bls`.
fn claves_publicas_de_tabla(tabla: &Tabla) -> Result<Vec<ClavePublica>, ErrorVotos> {
    let mut pubs = Vec::with_capacity(tabla.claves.len());
    for clave in &tabla.claves {
        // TB-1b · N5 · claves ya validadas con memoria (mismo resultado que `desde_bytes`).
        let pk = ClavePublica::desde_bytes_con_memoria(&clave.clave).map_err(|_| {
            ErrorVotos::CargaInicialInvalida {
                motivo: "tabla_guardada_clave_invalida",
            }
        })?;
        pubs.push(pk);
    }
    Ok(pubs)
}

/// RA-2 · R1 · ciclo `j` de la **fase activa siguiente** a `apertura` (o el que la contiene si ya
/// está en fase activa); se usa solo para etiquetar el evento de espera del rearranque.
fn ciclo_siguiente_rearranque(
    cal: &zx_consensus::transicion::votos::CalendarioRearranque,
    apertura: u64,
) -> u64 {
    if apertura < cal.s0 {
        return 0;
    }
    let j = (apertura - cal.s0).div_euclid(cal.periodo);
    if apertura < cal.inicio(j).saturating_add(cal.a) {
        j
    } else {
        j.saturating_add(1)
    }
}

/// FV-4b-N1-2 · Tope de votos futuros en espera (≈ 300 B cada uno ⇒ < 0,3 MiB).
const MAX_VOTOS_PENDIENTES: usize = 1024;

/// PD-1d · M2 · ordena una tabla (y sus claves públicas alineadas) por bytes de clave BLS, el
/// orden canónico que indexa el mapa de bits del certificado por peso.
fn canonizar_tabla(tabla: Tabla, pubs: Vec<ClavePublica>) -> (Tabla, Vec<ClavePublica>) {
    let n = tabla.n;
    let mut pares: Vec<(Clave, ClavePublica)> = tabla.claves.into_iter().zip(pubs).collect();
    pares.sort_by(|a, b| a.0.clave.cmp(&b.0.clave));
    let (claves, claves_pub) = pares.into_iter().unzip();
    (Tabla { n, claves }, claves_pub)
}

/// T1 · B-71 · ¿la clave cae en el conjunto de subredes vigiladas? `None` = todas.
fn subred_vigilada(
    clave: &[u8; LONGITUD_CLAVE_BLS],
    s: u16,
    vigiladas: &Option<HashSet<u16>>,
) -> bool {
    match vigiladas {
        None => true,
        Some(set) => subred(clave, s).is_ok_and(|x| set.contains(&x)),
    }
}

impl MotorVotos {
    /// Crea el motor con su configuración (perfil, `K` y claves BLS propias).
    #[must_use]
    pub fn nuevo(cfg: ConfigMotorVotos) -> Self {
        let detector = DetectorFalta::nuevo(cfg.perfil.t_inst, crate::perfil::PLAZO_SLOTS);
        // C1/C2 · el secreto se lee **una sola vez**, al crear el motor.
        let generador_agregados = GeneradorAgregados::nuevo();
        let azar_del_sistema_no_disponible = generador_agregados.is_none();
        Self {
            perfil: cfg.perfil,
            claves: cfg.claves,
            emitir_votos: cfg.emitir_votos,
            instancia: None,
            instancia_anterior: None,
            punto: None,
            ultimo_certificado_peso: None,
            certificados_peso: Vec::new(),
            certificados_adoptados: 0,
            reloj_certificados: (0, 0),
            finalidad_certificados: None,
            liquidacion_certificados: None,
            eventos_certificados: VecDeque::new(),
            certificados_ofrecidos: HashSet::new(),
            ventana_peso: None,
            control_peso: None,
            diario: None,
            apertura_pendiente: None,
            pendientes: Vec::new(),
            apertura_efectiva: false,
            ultima_ventana_abierta: None,
            base: None,
            caducidad_anunciada: false,
            rearranque_espera_anunciado: None,
            rearranque_sin_tabla_anunciado: None,
            base_de_estado: false,
            base_provisional: false,
            detector,
            subredes: SUBREDES_VOTO_RED,
            subredes_vigiladas: None,
            salientes: HashMap::new(),
            tabla_anterior: None,
            ultimas_metricas: None,
            generador_agregados,
            azar_del_sistema_no_disponible,
        }
    }

    /// G2 · crea el motor con el número de subredes `S` de su red.
    ///
    /// El valor por defecto de [`Self::nuevo`] es [`SUBREDES_VOTO_RED`] (la constante de las tres
    /// redes); el nodo usa este constructor cuando su `S` difiera.
    #[must_use]
    pub fn nuevo_con_subredes(cfg: ConfigMotorVotos, subredes: u16) -> Self {
        let mut motor = Self::nuevo(cfg);
        motor.subredes = subredes;
        // El detector reparte las claves con el mismo `S` de la red.
        motor.detector.fijar_vigiladas(subredes, None);
        motor
    }

    /// C2 · MOT-2 · ¿el motor se quedó sin azar del sistema al crearse? Es el aviso
    /// `azar_del_sistema_no_disponible`: se emite una sola vez, al crear el motor, y con él el
    /// motor **no** verifica por lotes los agregados (los entrega de uno en uno).
    #[must_use]
    pub fn azar_del_sistema_no_disponible(&self) -> bool {
        self.azar_del_sistema_no_disponible
    }

    /// C2 · MOT-2 · solo pruebas: motor como [`Self::nuevo`] pero **sin** azar del sistema, para
    /// ejercitar el camino de «uno en uno». No hay respaldo predecible: el generador es `None`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn nuevo_sin_azar_para_test(cfg: ConfigMotorVotos, subredes: u16) -> Self {
        let mut motor = Self::nuevo_con_subredes(cfg, subredes);
        motor.generador_agregados = None;
        motor.azar_del_sistema_no_disponible = true;
        motor
    }

    /// T1 · B-71 · fija las **subredes vigiladas** (`S` es el del motor).
    ///
    /// Mientras nadie llame a este método, el motor vigila **todas** (comportamiento de hoy: un
    /// olvido del nodo peca de vigilar de más, no de menos). Una lista vacía es «no vigilo
    /// ninguna». Al fijarlas, **lo ya guardado de otras subredes se borra** (T1).
    pub fn fijar_subredes_vigiladas(&mut self, subredes: &[u16]) {
        let set: HashSet<u16> = subredes.iter().copied().collect();
        self.subredes_vigiladas = Some(set.clone());
        self.detector.fijar_vigiladas(self.subredes, Some(set));
        // T1 · los apuntes salientes de subredes ahora no vigiladas también se borran.
        let s = self.subredes;
        let vigiladas = self.subredes_vigiladas.clone();
        self.salientes
            .retain(|clave, _| subred_vigilada(clave, s, &vigiladas));
        self.fijar_tope_detector();
    }

    /// T1 · B-71 · ¿la clave cae en una subred vigilada?
    #[must_use]
    pub fn clave_vigilada(&self, clave: &[u8; LONGITUD_CLAVE_BLS]) -> bool {
        subred_vigilada(clave, self.subredes, &self.subredes_vigiladas)
    }

    /// G2 · número de subredes `S` de la red de este motor.
    #[must_use]
    pub fn subredes(&self) -> u16 {
        self.subredes
    }

    /// FV-N6-C7 · vincula el diario durable de voto. El nodo lo llama **antes** de cualquier
    /// apertura/firma; `MotorVotos::nuevo` (biblioteca) conserva el modo en memoria sin garantía
    /// durable si no se vincula.
    pub(crate) fn vincular_diario(&mut self, diario: DiarioVotos) {
        self.diario = Some(diario);
    }

    /// FV-N6-C7 · fuerza el modo observación: recibe y valida votos pero **no** firma los propios.
    pub(crate) fn poner_en_observacion(&mut self) {
        self.emitir_votos = false;
    }

    /// FV-N6-C7 · ¿hay diario durable vinculado?
    #[must_use]
    pub(crate) fn tiene_diario(&self) -> bool {
        self.diario.is_some()
    }

    /// RA-2 · R7 · solo en tests: ¿el motor firma sus propios votos (no está en observación)?
    #[cfg(test)]
    pub(crate) fn emite_para_test(&self) -> bool {
        self.emitir_votos
    }

    /// FV-N6-C7-4 · solo en tests: ¿el motor ya abrió una ventana de verdad? (marca monotónica de
    /// primera apertura efectiva; M9-a2 · T4a · acceso de prueba que necesitan las pruebas
    /// devueltas).
    #[cfg(test)]
    pub(crate) fn apertura_efectiva_para_test(&self) -> bool {
        self.apertura_efectiva
    }

    /// VS-2 · W3 · solo en tests: ¿hay reserva para `(clave, n)`?
    #[cfg(test)]
    pub(crate) fn reservada_para_test(&self, clave: &[u8; LONGITUD_CLAVE_BLS], n: u64) -> bool {
        self.diario.as_ref().is_some_and(|d| d.reservada(clave, n))
    }

    /// VS-2 · W3/W10 · solo en tests: candado `(n_v, candidato_v)` de la clave.
    #[cfg(test)]
    pub(crate) fn candado_para_test(
        &self,
        clave: &[u8; LONGITUD_CLAVE_BLS],
    ) -> Option<(u64, Hash)> {
        self.diario.as_ref().and_then(|d| d.candado(clave))
    }

    /// VS-2 · W3 · solo en tests: acceso al diario vinculado.
    #[cfg(test)]
    pub(crate) fn diario_para_test(&self) -> Option<&DiarioVotos> {
        self.diario.as_ref()
    }

    /// Instancia abierta actual, si la hay.
    #[must_use]
    pub fn instancia_actual(&self) -> Option<u64> {
        self.instancia.as_ref().map(|i| i.n)
    }

    /// VS-2 · V3 · última ventana **abierta de verdad** por el motor, aunque hoy no tenga instancia
    /// (cierre sin quórum y apertura diferida). `None` antes de la primera apertura.
    #[must_use]
    pub fn ultima_ventana_abierta(&self) -> Option<u64> {
        self.ultima_ventana_abierta
    }

    /// PD-1d · M12 · siembra el motor con un **punto de control por peso**: un `CertificadoPeso` y
    /// su tabla. La tabla se canoniza, se verifica con `verificar_punto_control_peso` (firma agregada
    /// y evaluación del contrato) y el certificado fija `punto` y `base`. Guardas de carga única
    /// equivalentes a [`Self::sembrar_punto_control`].
    ///
    /// # Errores
    /// [`ErrorVotos::CargaInicialInvalida`] (`motor_ya_abierto`, `n_max`, `indice_certificado`) o
    /// los de `zx-votos`.
    pub fn sembrar_punto_control_peso(
        &mut self,
        tabla: Tabla,
        claves: Vec<ClavePublica>,
        certificado: CertificadoPeso,
        cola: &[(u64, [u8; 32])],
    ) -> Result<(), ErrorVotos> {
        if self.instancia.is_some() || !self.certificados_peso.is_empty() || self.apertura_efectiva
        {
            return Err(ErrorVotos::CargaInicialInvalida {
                motivo: "motor_ya_abierto",
            });
        }
        // B-57 · `n = u64::MAX` no tiene ventana siguiente que abrir: se rechaza sin efecto, con el
        // motivo que usaba la carga antigua (retirada en 68666eca).
        if certificado.n == u64::MAX {
            return Err(ErrorVotos::CargaInicialInvalida { motivo: "n_max" });
        }
        validar_claves_alineadas(&tabla, &claves)?;
        let (tabla, claves) = canonizar_tabla(tabla, claves);
        if tabla.n != certificado.n {
            return Err(ErrorVotos::CargaInicialInvalida {
                motivo: "indice_certificado",
            });
        }
        verificar_punto_control_peso(
            &PuntoControlPeso {
                tabla: tabla.clone(),
                claves: claves.clone(),
                certificado: certificado.clone(),
                cola: cola.to_vec(),
                contenidos: Vec::new(),
            },
            self.perfil.b,
        )?;
        self.punto = Some(certificado.candidato);
        self.base = Some((certificado.n, certificado.h_t_siguiente));
        self.base_provisional = false;
        self.ultimo_certificado_peso = Some(certificado);
        self.control_peso = Some((tabla, claves));
        Ok(())
    }

    /// RA-2 · R7 · siembra el motor con la **base** `(n, h_T(n+1))` y el punto `S` de una finalidad
    /// **ya sellada** en el estado (modo peso) que no tiene cuerpo `0x04` autenticado. No es un punto
    /// de control: no hay certificado ni se exige uno. La primera ventana posterior a la base se
    /// abre con la tabla del estado por el camino normal (R0).
    ///
    /// # Errores
    /// [`ErrorVotos::CargaInicialInvalida`] con motivo `motor_ya_abierto` si ya hay instancia o
    /// certificado local.
    pub(crate) fn sembrar_base_de_estado(
        &mut self,
        n: u64,
        h_t: Hash,
        punto: Hash,
    ) -> Result<(), ErrorVotos> {
        if self.instancia.is_some() || !self.certificados_peso.is_empty() || self.apertura_efectiva
        {
            return Err(ErrorVotos::CargaInicialInvalida {
                motivo: "motor_ya_abierto",
            });
        }
        self.base = Some((n, h_t));
        self.punto = Some(punto);
        self.base_de_estado = true;
        self.base_provisional = false;
        Ok(())
    }

    /// Punto de finalidad anclado por el motor, si existe.
    #[must_use]
    pub fn punto(&self) -> Option<Hash> {
        self.punto
    }

    /// REAN-2 · N1 · ventana `m` de la base vigente del motor, si existe.
    #[must_use]
    pub fn base_n(&self) -> Option<u64> {
        self.base.map(|(m, _)| m)
    }

    /// PD-1d · M14 · último certificado **por peso** adoptado (vacío en modo sorteo).
    #[must_use]
    pub fn ultimo_certificado_peso(&self) -> Option<&CertificadoPeso> {
        self.ultimo_certificado_peso.as_ref()
    }

    /// B78-2 · certificados formados que siguen pendientes, del más antiguo al más nuevo.
    #[must_use]
    pub fn certificados_peso(&self) -> &[CertificadoPeso] {
        &self.certificados_peso
    }

    /// Control autenticado de arranque: conserva la oferta previa sin inventar una adopción.
    pub(crate) fn certificado_control_sin_adopciones(&self) -> Option<&CertificadoPeso> {
        if self.certificados_adoptados == 0
            && self.certificados_peso.is_empty()
            && self.control_peso.is_some()
        {
            self.ultimo_certificado_peso.as_ref()
        } else {
            None
        }
    }

    /// N1: una ventana cada T slots, un horizonte de revelación y el más reciente.
    pub(crate) const fn cota_certificados_peso() -> u64 {
        W_REVEAL_SLOTS_VOTOS.div_ceil(T_INST_VOTOS) + 1
    }

    /// Actualiza la vista de cadena aplicada, independientemente de la base provisional.
    pub(crate) fn actualizar_certificados_peso(&mut self, estado: &Estado, slot: u64) {
        self.reloj_certificados.1 = self.reloj_certificados.1.max(slot);
        self.finalidad_certificados = self
            .finalidad_certificados
            .max(estado.finalidad_votos.map(|_| estado.finalidad_votos_n));
        self.liquidacion_certificados = self
            .liquidacion_certificados
            .max(estado.liquidacion_voto_hasta);
        self.podar_certificados_peso();
        if self.instancia_anterior.as_ref().is_some_and(|i| {
            i.n.checked_add(1) != Some(self.reloj_certificados.0)
                || self.finalidad_certificados.is_some_and(|m| m >= i.n)
        }) {
            self.instancia_anterior = None;
        }
    }

    fn evento_certificado(&mut self, n: u64, causa: &'static str) {
        // El nodo consume tras cada acción. Un consumidor de biblioteca que no lo haga solo
        // conserva el último horizonte, sin convertir los eventos en otro historial sin cota.
        if u64::try_from(self.eventos_certificados.len()).unwrap_or(u64::MAX)
            >= Self::cota_certificados_peso()
        {
            self.eventos_certificados.pop_front();
        }
        self.eventos_certificados.push_back((n, causa));
    }

    fn podar_certificados_peso(&mut self) {
        let ultimo = self.ultimo_certificado_peso.as_ref().map(|c| c.n);
        let finalidad = self.finalidad_certificados;
        let liquidacion = self.liquidacion_certificados;
        let slot = self.reloj_certificados.1;
        let mut soltados = Vec::new();
        self.certificados_peso.retain(|cert| {
            let causa = if finalidad.is_some_and(|m| m >= cert.n) {
                Some(if finalidad == Some(cert.n) {
                    "aplicado"
                } else {
                    "superado"
                })
            } else if Some(cert.n) != ultimo
                && (liquidacion.is_some_and(|m| m >= cert.n)
                    || cierre_ventana(cert.n).saturating_add(W_REVEAL_SLOTS_VOTOS) < slot)
            {
                Some("liquidada")
            } else {
                None
            };
            if let Some(causa) = causa {
                soltados.push((cert.n, causa));
                false
            } else {
                true
            }
        });
        for (n, causa) in soltados {
            self.certificados_ofrecidos.remove(&n);
            self.evento_certificado(n, causa);
        }
    }

    /// N5: consumo obligatorio después de cada acción del motor por el nodo.
    pub(crate) fn drenar_eventos_certificados_peso(&mut self) -> Vec<(u64, &'static str)> {
        self.eventos_certificados.drain(..).collect()
    }

    /// N5: registra una sola oferta de cada pendiente anterior al más reciente.
    pub(crate) fn marcar_certificado_anterior_ofrecido(&mut self, n: u64) -> bool {
        self.ultimo_certificado_peso
            .as_ref()
            .is_some_and(|c| n < c.n)
            && self.certificados_peso.iter().any(|c| c.n == n)
            && self.certificados_ofrecidos.insert(n)
    }

    fn recibe_anterior(&self, n: u64) -> bool {
        self.instancia_anterior.as_ref().is_some_and(|i| i.n == n)
            && n.checked_add(1) == Some(self.reloj_certificados.0)
            && self.finalidad_certificados.is_none_or(|m| m < n)
    }

    fn certificar_anterior(&mut self) -> Result<(), ErrorVotos> {
        let Some(n) = self.instancia.as_ref().map(|i| i.n) else {
            return Ok(());
        };
        if self
            .ultimo_certificado_peso
            .as_ref()
            .is_some_and(|c| c.n >= n)
        {
            return Ok(());
        }
        let cierre = self.cerrar_peso()?;
        if cierre.certificado_peso.is_some() {
            self.evento_certificado(n, "formado_tras_cierre");
        }
        Ok(())
    }

    fn recibir_voto_anterior(
        &mut self,
        voto: VotoPeso,
        vista: &dyn VistaCadena,
        firma_ya_verificada: bool,
    ) {
        if !self.recibe_anterior(voto.n) {
            return;
        }
        std::mem::swap(&mut self.instancia, &mut self.instancia_anterior);
        let aceptado = matches!(
            self.recibir_voto_actual(voto, vista, firma_ya_verificada),
            RecepcionVoto::Aceptado { .. }
        );
        if aceptado && let Err(error) = self.certificar_anterior() {
            tracing::warn!(%error, "no se pudo formar el certificado tardío");
        }
        std::mem::swap(&mut self.instancia, &mut self.instancia_anterior);
    }

    /// Tabla de poder `T_n` de la instancia abierta, si la hay.
    #[must_use]
    pub fn tabla_actual(&self) -> Option<&Tabla> {
        self.instancia.as_ref().map(|i| &i.tabla)
    }

    /// PD-1f · F5/D4 · tabla del punto de control por peso sembrado (si lo hay), para escribir la
    /// recuperación de eclipse como `ZXPCP1`.
    #[must_use]
    pub fn tabla_control_peso(&self) -> Option<&Tabla> {
        self.control_peso.as_ref().map(|(tabla, _)| tabla)
    }

    /// Claves públicas BLS de la tabla de la instancia abierta, si la hay.
    #[must_use]
    pub fn claves_publicas_actuales(&self) -> Option<&[ClavePublica]> {
        self.instancia.as_ref().map(|i| i.claves_pub.as_slice())
    }

    /// Avanza el reloj de instancias: si `n` supera a la instancia abierta, cierra la anterior
    /// (evaluando su certificado) y abre `n` con la tabla comprometida por el certificado anterior.
    ///
    /// `candidato` es `h_B(n)` = mejor punta del terminal seleccionado; `estado` es `Estado` en el
    /// que se construye la tabla (en la frontera) y `slot` el slot PoT actual.
    ///
    /// Devuelve el certificado adoptado (si lo hubo), los sobres de voto propios a difundir y los
    /// eventos que el nodo debe escribir en el registro.
    ///
    /// # Errores
    /// Los de `zx-votos` (aritmética exacta, longitudes, BLS).
    pub fn avanzar(
        &mut self,
        n: u64,
        candidato: BlockHash,
        estado: &Estado,
        slot: i64,
    ) -> Result<PasoVotos, ErrorVotos> {
        self.avanzar_con_vista(n, candidato, estado, slot, &VistaPermisiva)
    }

    /// REAN-2 · como [`Self::avanzar`] pero con la **vista de cadena** que exige el candado R4
    /// (N4/N5). El nodo real pasa una vista de solo lectura sobre `zx_cadena::Cadena`; los arneses
    /// que no montan cadena usan [`VistaPermisiva`].
    ///
    /// # Errores
    /// Los de `zx-votos` (aritmética exacta, longitudes, BLS).
    pub fn avanzar_con_vista(
        &mut self,
        n: u64,
        candidato: BlockHash,
        estado: &Estado,
        slot: i64,
        vista: &dyn VistaCadena,
    ) -> Result<PasoVotos, ErrorVotos> {
        let mut paso = PasoVotos::default();
        // FV-N6-C7-3 · reloj del Registro (slot PoT) que se adjunta a los eventos de observación.
        let slot_registro = u64::try_from(slot).unwrap_or(u64::MAX);
        self.reloj_certificados.0 = self.reloj_certificados.0.max(n);
        self.actualizar_certificados_peso(estado, slot_registro);
        let abrir = match &self.instancia {
            None => true,
            Some(actual) => n > actual.n,
        };
        if !abrir {
            return Ok(paso);
        }

        // TB-1c-2 · X4 · N6 · antes de avanzar la base desde el estado, una base **provisional** se
        // confirma o se abandona (en el acto si la cadena muestra otra huella con ventana `≥ m`, o
        // pasado el margen `K_TABLAS_VOTO`).
        paso.eventos
            .extend(self.resolver_base_provisional(n, estado));
        // REAN-2 · N1 · la base es la más avanzada entre el último certificado del motor y la
        // finalidad **aplicada** en el estado de la cadena seleccionada. Solo avanza.
        self.actualizar_base_desde_estado(estado);

        // RET-1b E4 / RA-2 · R1 · caducidad de la tabla: con base `(m, h)` y `n > m +
        // CADUCIDAD_TABLA_VENTANAS`, la ventana ya no se abre por el camino normal. Si el calendario
        // de rearranque existe y `n` abre en su **fase activa**, se abre con la tabla de la
        // instantánea del ciclo (contrato v2, parte D); si no, no se abre. `BaseCaducada` se sigue
        // emitiendo **una sola vez** por motor.
        let mut tabla_rearranque: Option<(Tabla, Vec<ClavePublica>)> = None;
        if let Some((m, _)) = self.base
            && n > m.saturating_add(CADUCIDAD_TABLA_VENTANAS)
        {
            if !self.caducidad_anunciada {
                self.caducidad_anunciada = true;
                paso.eventos.push(EventoMotor::BaseCaducada { m, n });
            }
            let Some(cal) = zx_consensus::transicion::votos::calendario_rearranque(
                &estado.parametros_sector,
                m,
            ) else {
                return Ok(paso);
            };
            let apertura = n.saturating_mul(T_INST_VOTOS);
            match cal.ciclo_de_apertura(apertura) {
                None => {
                    // La ventana no abre en la fase activa: no se abre. Un evento por ciclo.
                    let j = ciclo_siguiente_rearranque(&cal, apertura);
                    if self.rearranque_espera_anunciado != Some(j) {
                        self.rearranque_espera_anunciado = Some(j);
                        paso.eventos.push(EventoMotor::RearranqueEnEspera {
                            m,
                            n,
                            j,
                            inicio: cal.inicio(j),
                        });
                    }
                    return Ok(paso);
                }
                Some(j) => {
                    // La instantánea del ciclo `j` y su contenido: si faltan, no se abre.
                    let contenido = estado
                        .tabla_ciclo_rearranque
                        .get(&j)
                        .copied()
                        .and_then(|h| estado.tablas_voto_contenido.get(&h));
                    let Some(contenido) = contenido else {
                        if self.rearranque_sin_tabla_anunciado != Some(j) {
                            self.rearranque_sin_tabla_anunciado = Some(j);
                            paso.eventos
                                .push(EventoMotor::RearranqueSinTabla { m, n, j });
                        }
                        return Ok(paso);
                    };
                    let tabla = Tabla {
                        n,
                        claves: contenido.iter().map(clave_de_payload).collect(),
                    };
                    match claves_publicas_de_tabla(&tabla) {
                        Ok(pubs) => {
                            self.rearranque_sin_tabla_anunciado = None;
                            tabla_rearranque = Some((tabla, pubs));
                        }
                        Err(_) => {
                            if self.rearranque_sin_tabla_anunciado != Some(j) {
                                self.rearranque_sin_tabla_anunciado = Some(j);
                                paso.eventos
                                    .push(EventoMotor::RearranqueSinTabla { m, n, j });
                            }
                            return Ok(paso);
                        }
                    }
                }
            }
        }

        // FV-N6-C6 · un motor **nuevo** (sin carga inicial ni certificado) no puede inventar
        // génesis local sobre un estado que ya tiene finalidad por votos: el bootstrap solo vale
        // desde un estado realmente sin finalidad (el cableado de arranque/replay tendrá que
        // aportar el punto de control). Se rechaza antes de firmar o mutar.
        if self.instancia.is_none()
            && self.ultimo_certificado_peso.is_none()
            && self.certificados_peso.is_empty()
            && !self.base_de_estado
            && estado.finalidad_votos_h_t.is_some()
        {
            return Err(ErrorVotos::CargaInicialInvalida {
                motivo: "bootstrap_sobre_finalidad",
            });
        }

        // Cierra la instancia abierta (si la había) antes de abrir la nueva.
        let habia_instancia = self.instancia.is_some();
        let mut certifico = false;
        if habia_instancia {
            let mut cierre = self.cerrar()?;
            certifico = cierre.certificado_peso.is_some();
            let n_cerrada = self.instancia.as_ref().map(|i| i.n).unwrap_or(0);
            // PD-1d · M14 · el certificado por peso se observa, con el peso contado.
            if let Some(cert) = &cierre.certificado_peso {
                paso.eventos.push(EventoMotor::CertificadoAdoptado {
                    n: cert.n,
                    candidato: hex(&cert.candidato),
                    plazas: cierre.plazas_validas,
                    umbral: cierre.umbral,
                });
            }
            // FV-N6-C7-2 §D · cierre observado, haya o no certificado.
            paso.eventos.push(EventoMotor::VentanaCerrada {
                n: n_cerrada,
                certificado: cierre.certificado_peso.is_some(),
                plazas: cierre.plazas_validas,
                umbral: cierre.umbral,
                slot: slot_registro,
            });
            // M8 · eventos propios del cierre (aviso de raíz discrepante).
            paso.eventos.append(&mut cierre.eventos);
            paso.certificado_peso = cierre.certificado_peso;
            paso.certificado_peso_bytes = cierre.certificado_peso_bytes;
            paso.acta_peso = cierre.acta_peso;
            paso.acta_peso_bytes = cierre.acta_peso_bytes;
            paso.acta_peso_firmantes = cierre.acta_peso_firmantes;
        }

        // REAN-2 · N2 · la `T_{n+1}` comprometida por la instancia recién cerrada solo se hereda si
        // esa instancia **certificó**; una instancia sin quórum nunca transmite su tabla siguiente.
        // La propia tabla de la instancia cerrada queda como candidata para la resolución por hash.
        let mut tabla_certificada: Option<(Tabla, Vec<ClavePublica>)> = None;
        let mut tabla_propia: Option<(Tabla, Vec<ClavePublica>)> = None;
        if let Some(inst) = self.instancia.take() {
            if certifico {
                tabla_certificada =
                    Some((inst.tabla_siguiente.clone(), inst.pubs_siguiente.clone()));
            }
            tabla_propia = Some((inst.tabla.clone(), inst.claves_pub.clone()));
            self.instancia_anterior = (inst.n.checked_add(1) == Some(n)
                && self.finalidad_certificados.is_none_or(|m| m < inst.n))
            .then_some(inst);
        }
        // REAN-2 · N2 · la `T_{n+1}` certificada de un salto de reloj se conserva para reintentar
        // **su índice exacto**; si el reloj ya lo rebasó, se descarta y la base resuelve `T_n`. La
        // tabla de una instancia que **no** certificó nunca entra aquí.
        let tabla_previa = if let Some(t) = tabla_rearranque {
            // RA-2 · R1 · la ventana de rearranque se abre con la tabla de la instantánea del ciclo.
            Some(t)
        } else {
            match self.apertura_pendiente.take() {
                Some((tabla, pubs)) if tabla.n == n => Some((tabla, pubs)),
                _ => {
                    if certifico {
                        tabla_certificada
                    } else {
                        None
                    }
                }
            }
        };
        let respaldo = tabla_previa.clone();
        let abierto = self.abrir(
            n,
            *candidato.as_bytes(),
            estado,
            slot,
            tabla_previa,
            tabla_propia,
            vista,
        );
        let (propios, sobres, votos_red, suprimidos, eventos_sorteo) = match abierto {
            Ok(tupla) => tupla,
            // REAN-2 · N2 · ninguna tabla de la base casa: la apertura se difiere **sin firmar**
            // (evento con motivo) y se reintenta en la vuelta siguiente con el estado nuevo. La
            // `T_{n+1}` certificada del salto se conserva para retentar su índice exacto. El cierre
            // previo ya viaja en `paso`, así que no se pierde.
            Err(ErrorVotos::CargaInicialInvalida { motivo }) if habia_instancia => {
                self.apertura_pendiente = respaldo;
                paso.eventos
                    .push(EventoMotor::AperturaDiferida { n, motivo });
                return Ok(paso);
            }
            Err(e) => return Err(e),
        };
        for (clave, plazas) in &propios {
            paso.eventos.push(EventoMotor::VotoEmitido {
                n,
                clave: hex(clave),
                plazas: *plazas,
            });
        }
        // FV-N6-C7 · observación de firmas suprimidas por el diario durable.
        for (clave, motivo) in suprimidos {
            paso.eventos.push(EventoMotor::VotoSuprimido {
                n,
                clave: hex(&clave),
                motivo,
            });
        }
        // FV-N6-C7-2 §D · sorteos propios observados (se emitan o no) y apertura de la ventana.
        paso.eventos.extend(eventos_sorteo);
        if let Some(inst) = self.instancia.as_ref() {
            paso.eventos.push(EventoMotor::VentanaAbierta {
                n,
                ancla: hex(&inst.ancla),
                h_t_siguiente: hex(&inst.h_t_siguiente),
                candidato: candidato.to_string(),
                slot: slot_registro,
            });
        }
        // FV-4b-N1-2 · `gossipsub` no entrega al emisor sus propios mensajes, así que un nodo no
        // recibiría su voto por el cuarto tema. Se registra aquí (idempotente: `recibir_voto`
        // deduplica por clave) para que el cierre cuente con **todos** los votantes y los cuatro
        // nodos compongan el mismo certificado; el sobre se sigue difundiendo.
        for sobre in &sobres {
            let _ = self.recibir_voto_con_vista(sobre, vista);
        }
        paso.votos = sobres;
        paso.votos_red = votos_red;
        Ok(paso)
    }

    /// VS-2 · V3 · firma un **voto tardío** de la ventana `k` (contrato v2, A3) **sin abrir
    /// instancia**.
    ///
    /// Recupera una ventana que el reloj saltó. Por cada clave propia que esté en la tabla `T_k`
    /// (construida desde el estado del pasado del candidato, por el mismo camino que la apertura),
    /// activa, con peso y con `emitir_votos`, en este orden:
    ///
    /// 1. el diario no tiene ya reserva para `(clave, k)` (si la tiene: `ya_reservada`);
    /// 2. no hay candado, o el candado es de una ventana estrictamente menor que `k` (si no:
    ///    `candado_posterior`; nunca se firma una ventana menor o igual que la del candado);
    /// 3. V6 · el candidato desciende del bloque sellado por la base aplicada (si no:
    ///    `no_desciende_del_sello`);
    /// 4. `candidato_permitido` con `slot_regla = k · T_INST_VOTOS` (la apertura de `k`), no el slot
    ///    actual: el consenso mide `F` contra `cierre(k)` (motivos `candado` y `diario_en_duda`);
    /// 5. reserva del mensaje A3, firma y candado `(k, candidato)`.
    ///
    /// Sin diario no hay voto tardío. No abre instancia ni toca la base.
    ///
    /// # Errores
    /// Los de `zx-votos` (aritmética exacta, longitudes, BLS).
    pub fn votar_tardio(
        &self,
        k: u64,
        candidato: Hash,
        estado: &Estado,
        vista: &dyn VistaCadena,
    ) -> Result<PasoTardio, ErrorVotos> {
        let mut paso = PasoTardio::default();
        if !self.emitir_votos {
            return Ok(paso);
        }
        let Some(diario) = &self.diario else {
            return Ok(paso);
        };
        // RA-2 · R5 · no hay voto tardío de ventanas posteriores a la caducidad de la base: no
        // tienen deber de voto (contrato v2, parte D).
        if let Some((m, _)) = self.base
            && k > m.saturating_add(CADUCIDAD_TABLA_VENTANAS)
        {
            return Ok(paso);
        }
        // Tabla `T_k` desde el estado del pasado del candidato, por el mismo camino que la apertura
        // cuando no hay tabla previa; en modo peso, en orden canónico.
        let (tabla, pubs) = construir_tabla(k, estado, self.slot_de_apertura(k))?;
        let (tabla, _pubs) = canonizar_tabla(tabla, pubs);
        let (tabla_siguiente, pubs_siguiente) = construir_tabla(
            k.saturating_add(1),
            estado,
            self.slot_de_apertura(k.saturating_add(1)),
        )?;
        let (tabla_siguiente, _pubs_siguiente) = canonizar_tabla(tabla_siguiente, pubs_siguiente);
        let h_t_siguiente = hash_tabla(&tabla_siguiente);
        let mut indice: HashMap<Vec<u8>, usize> = HashMap::new();
        for (i, clave) in tabla.claves.iter().enumerate() {
            indice.insert(clave.clave.clone(), i);
        }
        // V3 · el consenso mide `F` contra `cierre(k)`, no contra el slot actual.
        let slot_regla = i64::try_from(k.saturating_mul(T_INST_VOTOS)).unwrap_or(i64::MAX);
        // M1 · la raíz propia la entrega la vista, una sola vez para toda la ventana tardía.
        let raiz_propia = vista.raiz_estado_de_voto(k, &candidato);
        for sk in &self.claves {
            let pk = sk.clave_publica();
            let clave_bytes = pk.bytes().to_vec();
            let clave_hex = hex(&clave_bytes);
            let Ok(clave_bls) = <[u8; LONGITUD_CLAVE_BLS]>::try_from(clave_bytes.as_slice()) else {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "fuera_de_tabla",
                });
                continue;
            };
            let Some(&i) = indice.get(&clave_bytes) else {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "fuera_de_tabla",
                });
                continue;
            };
            let Some(registro) = tabla.claves.get(i) else {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "fuera_de_tabla",
                });
                continue;
            };
            if !registro.activo {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "inactiva",
                });
                continue;
            }
            let Ok(w) = peso_de_clave(registro, self.perfil.b) else {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "sin_peso",
                });
                continue;
            };
            let peso = u64::try_from(w).unwrap_or(u64::MAX);
            if w == 0 {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "sin_peso",
                });
                continue;
            }
            // (1) reserva ya hecha para `(clave, k)`.
            if diario.reservada(&clave_bls, k) {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso,
                    emitido: false,
                    motivo: "ya_reservada",
                });
                continue;
            }
            // (2) candado: solo puede ser de una ventana estrictamente anterior a `k`.
            if let Some((n_v, _)) = diario.candado(&clave_bls)
                && n_v >= k
            {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso,
                    emitido: false,
                    motivo: "candado_posterior",
                });
                continue;
            }
            // (3) V6 · el candidato debe descender del bloque sellado por la base aplicada.
            if !desciende_del_sello(estado, &candidato, vista) {
                paso.eventos.push(EventoMotor::VotoPesoPropio {
                    n: k,
                    clave: clave_hex,
                    peso,
                    emitido: false,
                    motivo: "no_desciende_del_sello",
                });
                continue;
            }
            // (4) `candidato_permitido` con el slot de apertura de `k`.
            let mut motivo: &'static str = "emitido";
            let mut reservado = true;
            match candidato_permitido(
                diario,
                &clave_bls,
                &candidato,
                base_b3_de_estado(estado),
                slot_regla,
                vista,
            ) {
                Ok(PermisoCandado::SinCandado | PermisoCandado::Permitido) => {}
                Ok(PermisoCandado::Liberado(candidato_v)) => {
                    paso.eventos.push(EventoMotor::CandadoLiberado {
                        n: k,
                        clave: clave_hex.clone(),
                        candidato_v: hex(&candidato_v),
                    });
                }
                Ok(PermisoCandado::Bloqueado) => {
                    motivo = "candado";
                    reservado = false;
                }
                Err(_) => {
                    motivo = "diario_en_duda";
                    reservado = false;
                }
            }
            let mensaje = mensaje_voto_peso(k, &candidato, &h_t_siguiente, &raiz_propia);
            // (5) reserva durable, firma y candado `(k, candidato)`.
            if reservado {
                match diario.resolver(&clave_bls, k, &mensaje) {
                    Ok(ResolucionDiario::Nueva | ResolucionDiario::Conocida) => {}
                    Ok(ResolucionDiario::Conflicto { .. }) => {
                        motivo = "conflicto_diario";
                        reservado = false;
                    }
                    Err(_) => {
                        motivo = "diario_en_duda";
                        reservado = false;
                    }
                }
            }
            if reservado && diario.fijar_candado(&clave_bls, k, &candidato).is_err() {
                motivo = "diario_en_duda";
                reservado = false;
            }
            let mut emitido = false;
            if reservado {
                let firma = firmar(sk, DOMINIO_VOTO, &mensaje)?;
                paso.votos.push(VotoPeso {
                    n: k,
                    candidato,
                    h_t_siguiente,
                    raiz_estado: raiz_propia,
                    clave: clave_bls,
                    firma,
                });
                // G3 · el voto tardío sale también como voto de red por su subred.
                let sub = subred(&clave_bytes, self.subredes).map_err(error_agregacion)?;
                paso.votos_red.push((
                    VotoRed {
                        n: k,
                        candidato,
                        h_t_siguiente,
                        raiz_estado: raiz_propia,
                        clave: pk,
                        firma,
                    }
                    .serializar(),
                    sub,
                ));
                emitido = true;
            }
            paso.eventos.push(EventoMotor::VotoPesoPropio {
                n: k,
                clave: clave_hex,
                peso,
                emitido,
                motivo,
            });
        }
        Ok(paso)
    }

    /// REAN-2 · N1 · actualiza la base `(m, h)` de forma **monótona** con la finalidad aplicada en
    /// el estado recibido: solo avanza (mayor `m`).
    fn actualizar_base_desde_estado(&mut self, estado: &Estado) {
        if let Some(h) = estado.finalidad_votos_h_t {
            let m = estado.finalidad_votos_n;
            if self.base.is_none_or(|(base_m, _)| m > base_m) {
                self.base = Some((m, h));
            }
        }
    }

    /// TB-1c-2 · X4 · N6 · resuelve la base **provisional** antes de abrir la ventana `n`.
    ///
    /// - La **confirma** si el estado del candidato muestra la misma huella con ventana `≥ m_base`.
    /// - La **abandona en el acto** si el estado muestra otra finalidad con ventana `≥ m_base`.
    /// - La **abandona** si no la confirma y `n > m_base + K_TABLAS_VOTO`.
    ///
    /// Al abandonar suelta la base (el llamante, vía [`Self::actualizar_base_desde_estado`], toma la
    /// finalidad del estado del candidato o deja el motor sin ninguna) y devuelve el evento
    /// `base_provisional_abandonada`. Una base sembrada desde el estado o desde un punto de control
    /// no es provisional y esta función no la toca.
    fn resolver_base_provisional(&mut self, n: u64, estado: &Estado) -> Vec<EventoMotor> {
        let mut eventos = Vec::new();
        if !self.base_provisional {
            return eventos;
        }
        let Some((m, h)) = self.base else {
            self.base_provisional = false;
            return eventos;
        };
        let estado_h = if estado.finalidad_votos.is_some() {
            estado.finalidad_votos_h_t
        } else {
            None
        };
        let estado_n = estado.finalidad_votos_n;
        if estado_h == Some(h) && estado_n >= m {
            self.base_provisional = false;
            return eventos;
        }
        let otra = estado_h.is_some_and(|h_e| h_e != h) && estado_n >= m;
        let pasado = n > m.saturating_add(u64::try_from(K_TABLAS_VOTO).unwrap_or(u64::MAX));
        if otra || pasado {
            eventos.push(EventoMotor::BaseProvisionalAbandonada {
                n,
                m_base: m,
                huella: hex(&h),
            });
            self.base = None;
            self.base_provisional = false;
            self.punto = estado.finalidad_votos.map(|h| *h.as_bytes());
        }
        eventos
    }

    /// REAN-2 · N3 · slot de apertura determinista de la ventana `n`: `n · t_inst`.
    fn slot_de_apertura(&self, n: u64) -> i64 {
        i64::try_from(n.saturating_mul(self.perfil.t_inst)).unwrap_or(i64::MAX)
    }

    /// REAN-2 · N2 · resuelve la tabla `T_n` de la ventana `n` a partir de la **base** `(m, h)`.
    ///
    /// Con base, es la tabla cuyo `hash_tabla` vale `h`, reetiquetada con `n` (el hash de una tabla
    /// no depende de `n`, solo de sus claves). La precedencia es:
    /// 1. la propia tabla de la instancia recién cerrada si su hash es `h`;
    /// 2. el contenido guardado por el consenso en `Estado.tablas_voto_contenido`, ya en orden
    ///    canónico;
    /// 3. la tabla canónica del estado (`tabla_canonica` del consenso) si su hash es `h`;
    /// 4. la tabla del punto de control **por peso** sembrado si su hash es `h`.
    ///
    /// Sin base (fase génesis) la tabla se construye del estado. Si ninguna casa, error explícito
    /// **antes** de firmar; la apertura se difiere y se reintenta.
    fn tabla_de_base(
        &self,
        n: u64,
        estado: &Estado,
        slot_apertura: i64,
        tabla_cerrada: Option<(Tabla, Vec<ClavePublica>)>,
    ) -> Result<(Tabla, Vec<ClavePublica>), ErrorVotos> {
        let Some((_m, h)) = self.base else {
            // TB-1c-2 · X3 · N1′ · sin base (ni del motor ni del estado del candidato, que
            // `actualizar_base_desde_estado` ya habría copiado): la tabla con la que firma es el
            // contenido de la **última huella de `cola_tablas_voto`** del estado del candidato, y esa
            // huella es la que declara. Por C1 de TB4-C-2, la última es la de mayor ventana fresca.
            //
            // TB-1c-3 · X3′ · si esa cola está **vacía**, la ventana se abre con la **tabla vacía**,
            // exactamente como cuando ninguna identidad tiene peso: la instancia se abre y se cierra,
            // nadie vota (cada clave propia sale por `fuera_de_tabla`) y no hay ningún motivo nuevo.
            // Falta de contenido de una huella que sí está en la cola incumpliría la invariante de T8
            // (el depósito precede siempre a la entrada en la cola): se difiere sin firmar por el
            // camino genérico de «tabla no hallada», nunca con un motivo inventado.
            let Some((_k, huella)) = estado.cola_tablas_voto.last() else {
                return Ok((
                    Tabla {
                        n,
                        claves: Vec::new(),
                    },
                    Vec::new(),
                ));
            };
            let Some(contenido) = estado.tablas_voto_contenido.get(huella) else {
                return Err(ErrorVotos::CargaInicialInvalida {
                    motivo: "tabla_base_no_hallada",
                });
            };
            let tabla = Tabla {
                n,
                claves: contenido.iter().map(clave_de_payload).collect(),
            };
            let pubs = claves_publicas_de_tabla(&tabla)?;
            return Ok(canonizar_tabla(tabla, pubs));
        };
        // 2 · la propia tabla de la instancia recién cerrada.
        if let Some((tabla, pubs)) = &tabla_cerrada
            && hash_tabla(tabla) == h
        {
            return Ok((
                Tabla {
                    n,
                    claves: tabla.claves.clone(),
                },
                pubs.clone(),
            ));
        }
        // 2b · RA-2 · R0 · el contenido guardado por el consenso desde PD-1b (`tablas_voto_contenido`):
        // es donde la transición deposita la tabla vigente de la base. Se conserva el orden canónico
        // ya guardado (el consenso guarda `contenido_canonico`).
        if let Some(contenido) = estado.tablas_voto_contenido.get(&h) {
            let tabla = Tabla {
                n,
                claves: contenido.iter().map(clave_de_payload).collect(),
            };
            if hash_tabla(&tabla) == h {
                let pubs = claves_publicas_de_tabla(&tabla)?;
                return Ok((tabla, pubs));
            }
        }
        // 4 · la tabla canónica del estado.
        let canonica = zx_consensus::transicion::votos::tabla_canonica(estado, slot_apertura);
        let tabla_canonica = Tabla {
            n,
            claves: canonica.iter().map(clave_de_payload).collect(),
        };
        if hash_tabla(&tabla_canonica) == h {
            let pubs = claves_publicas_de_tabla(&tabla_canonica)?;
            return Ok((tabla_canonica, pubs));
        }
        // 5 · PD-1d · M12 · la tabla del punto de control **por peso**, si su hash casa.
        if let Some((tabla_control, pubs_control)) = &self.control_peso {
            let tabla_control = Tabla {
                n,
                claves: tabla_control.claves.clone(),
            };
            if hash_tabla(&tabla_control) == h {
                return Ok((tabla_control, pubs_control.clone()));
            }
        }
        Err(ErrorVotos::CargaInicialInvalida {
            motivo: "tabla_base_no_hallada",
        })
    }

    /// Abre la instancia `n`: construye `T_n`/`T_{n+1}` y firma los votos propios por peso.
    ///
    /// Devuelve `(claves y pesos propios emitidos, sobres de voto, firmas suprimidas, eventos)`.
    #[allow(
        clippy::type_complexity,
        clippy::too_many_arguments,
        reason = "el retorno combina los votos propios y sus sobres, y los argumentos son el contexto de la apertura; es una funcion privada"
    )]
    fn abrir(
        &mut self,
        n: u64,
        candidato: Hash,
        estado: &Estado,
        slot: i64,
        tabla_previa: Option<(Tabla, Vec<ClavePublica>)>,
        tabla_cerrada: Option<(Tabla, Vec<ClavePublica>)>,
        vista: &dyn VistaCadena,
    ) -> Result<
        (
            Vec<(Vec<u8>, u64)>,
            Vec<Vec<u8>>,
            Vec<(Vec<u8>, u16)>,
            Vec<(Vec<u8>, &'static str)>,
            Vec<EventoMotor>,
        ),
        ErrorVotos,
    > {
        // REAN-2 · N3 · toda tabla se construye con el **slot de apertura** de su ventana
        // (`n · t_inst`), no con el slot actual: dos nodos que abren la misma ventana en slots
        // distintos construyen la misma tabla.
        let slot_apertura = self.slot_de_apertura(n);
        // M1 · la raíz propia la entrega la vista, una sola vez por apertura.
        let raiz_propia = vista.raiz_estado_de_voto(n, &candidato);
        let (tabla, claves_pub) = match tabla_previa {
            // La tabla heredada de un cierre **certificado** es la `T_{n}` comprometida por ese
            // certificado: solo vale para abrir **su propio índice**. Reetiquetarla con otro `n`
            // fabricaría continuidad; se difiere sin firmar.
            Some((tabla, pubs)) => {
                if tabla.n != n {
                    return Err(ErrorVotos::CargaInicialInvalida {
                        motivo: "salto_tabla_no_sucesora",
                    });
                }
                (tabla, pubs)
            }
            // TB-1c-3 · X3′ · la cola vacía ya **no** devuelve error: `tabla_de_base` entrega la
            // tabla vacía y la instancia se abre y se cierra como cuando ninguna identidad tiene
            // peso. Aquí solo quedan los errores reales (invariantes rotas), que se propagan.
            None => self.tabla_de_base(n, estado, slot_apertura, tabla_cerrada)?,
        };
        // PD-1d · M2 · en modo peso la tabla (y sus claves públicas) va en **orden canónico** (por
        // bytes de clave BLS), que es el que indexa el mapa de bits del certificado.
        let (tabla, claves_pub) = canonizar_tabla(tabla, claves_pub);
        let ancla = hash_tabla(&tabla);
        // TB-1b · N1 · al abrir `n`, el votante declara la **última huella de `Q`** del estado del
        // candidato (el que recibe `abrir`), no la de su punta, y deja de construir `T_{n+1}` por su
        // cuenta. Por C1 de TB4-C-2, la última es la de mayor ventana fresca, también sin base y
        // en rearranque. Con `Q` vacía declara la huella de la tabla con la que firma (`ancla`).
        let h_t_siguiente = huella_siguiente_n1(estado, n, ancla);
        // TB-1b · N1/B2 · la tabla que acompaña al voto y al certificado es el **contenido de esa
        // huella tal como está en el estado**; si la huella declarada es la de la tabla con la que
        // firma, vale esa misma tabla (reetiquetada con `n+1`). Si el contenido no está, el votante
        // no vota esta ventana y lo deja por el camino de error que ya existe.
        let (tabla_siguiente, pubs_siguiente) =
            tabla_de_huella_siguiente(estado, n, h_t_siguiente, ancla, &tabla, &claves_pub)?;

        // G1 · una sola contabilidad por raíces de la ventana: tabla, claves y pesos (`peso_de_clave`),
        // con el número de subredes de la red y `AGREGADORES_POR_SUBRED`.
        let pesos: Vec<u128> = tabla
            .claves
            .iter()
            .map(|registro| peso_de_clave(registro, self.perfil.b))
            .collect::<Result<Vec<u128>, ErrorVotos>>()?;
        let datos = DatosVentana::nuevo(&tabla, &claves_pub, &pesos, self.subredes)
            .map_err(error_agregacion)?;
        let ventana = VentanaPorRaices::nuevo(
            Arc::clone(&datos),
            AGREGADORES_POR_SUBRED,
            n,
            candidato,
            h_t_siguiente,
        );

        let mut indice: HashMap<Vec<u8>, usize> = HashMap::new();
        for (i, clave) in tabla.claves.iter().enumerate() {
            indice.insert(clave.clave.clone(), i);
        }

        let mut propios: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut sobres: Vec<Vec<u8>> = Vec::new();
        // G3 · voto de red compacto por cada voto propio emitido, con su subred.
        let mut votos_red: Vec<(Vec<u8>, u16)> = Vec::new();
        // FV-N6-C7 · firmas propias suprimidas por el diario, con su motivo observado.
        let mut suprimidos: Vec<(Vec<u8>, &'static str)> = Vec::new();
        // FV-N6-C7-2 §D · un sorteo observado por clave propia, se emita o no.
        let mut eventos_sorteo: Vec<EventoMotor> = Vec::new();
        // PD-1d · M3 · en modo peso no hay VRF, ni plazas, ni compromisos, ni ancla: cada clave
        // propia de la tabla, activa y con peso, firma A3 tras la reserva en el diario y el
        // candado. La lista `propios` lleva el peso (antes plazas).
        // PD-1e · E3 · además, **cada** clave propia deja un evento con su peso, si emitió y el
        // motivo cuando no lo hizo (incluidas fuera de tabla, inactivas y sin peso).
        for sk in &self.claves {
            let pk = sk.clave_publica();
            let clave_bytes = pk.bytes().to_vec();
            let clave_hex = hex(&clave_bytes);
            let Ok(clave_bls) = <[u8; LONGITUD_CLAVE_BLS]>::try_from(clave_bytes.as_slice()) else {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "fuera_de_tabla",
                });
                continue;
            };
            let Some(&i) = indice.get(&clave_bytes) else {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "fuera_de_tabla",
                });
                continue;
            };
            let Some(registro) = tabla.claves.get(i) else {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "fuera_de_tabla",
                });
                continue;
            };
            if !registro.activo {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "inactiva",
                });
                continue;
            }
            let Ok(w) = peso_de_clave(registro, self.perfil.b) else {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "sin_peso",
                });
                continue;
            };
            let peso = u64::try_from(w).unwrap_or(u64::MAX);
            if w == 0 {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso: 0,
                    emitido: false,
                    motivo: "sin_peso",
                });
                continue;
            }
            if !self.emitir_votos {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso,
                    emitido: false,
                    motivo: "observacion",
                });
                continue;
            }
            // VS-2 · V6 · no se firma un candidato que no descienda del bloque sellado por la
            // base aplicada en el estado.
            if !desciende_del_sello(estado, &candidato, vista) {
                eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                    n,
                    clave: clave_hex,
                    peso,
                    emitido: false,
                    motivo: "no_desciende_del_sello",
                });
                continue;
            }
            let mensaje = mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz_propia);
            let mut reservado = true;
            let mut motivo: &'static str = "emitido";
            if let Some(diario) = &self.diario {
                match candidato_permitido(
                    diario,
                    &clave_bls,
                    &candidato,
                    base_b3_de_estado(estado),
                    slot,
                    vista,
                ) {
                    Ok(PermisoCandado::SinCandado | PermisoCandado::Permitido) => {}
                    Ok(PermisoCandado::Liberado(candidato_v)) => {
                        eventos_sorteo.push(EventoMotor::CandadoLiberado {
                            n,
                            clave: clave_hex.clone(),
                            candidato_v: hex(&candidato_v),
                        });
                    }
                    Ok(PermisoCandado::Bloqueado) => {
                        motivo = "candado";
                        reservado = false;
                    }
                    Err(_) => {
                        motivo = "diario_en_duda";
                        reservado = false;
                    }
                }
            }
            // La reserva durable va **antes** de firmar, con el mensaje A3 real.
            if reservado && let Some(diario) = &self.diario {
                match diario.resolver(&clave_bls, n, &mensaje) {
                    Ok(ResolucionDiario::Nueva | ResolucionDiario::Conocida) => {}
                    Ok(ResolucionDiario::Conflicto { .. }) => {
                        motivo = "conflicto_diario";
                        reservado = false;
                    }
                    Err(_) => {
                        motivo = "diario_en_duda";
                        reservado = false;
                    }
                }
            }
            if reservado
                && let Some(diario) = &self.diario
                && diario.fijar_candado(&clave_bls, n, &candidato).is_err()
            {
                motivo = "diario_en_duda";
                reservado = false;
            }
            let mut emitido = false;
            if reservado {
                let firma = firmar(sk, DOMINIO_VOTO, &mensaje)?;
                sobres.push(serializar_voto_peso(&VotoPeso {
                    n,
                    candidato,
                    h_t_siguiente,
                    raiz_estado: raiz_propia,
                    clave: clave_bls,
                    firma,
                }));
                // G3 · el voto propio sale también como voto de red por su subred.
                let sub = subred(&clave_bytes, self.subredes).map_err(error_agregacion)?;
                votos_red.push((
                    VotoRed {
                        n,
                        candidato,
                        h_t_siguiente,
                        raiz_estado: raiz_propia,
                        clave: pk,
                        firma,
                    }
                    .serializar(),
                    sub,
                ));
                propios.push((clave_bytes.clone(), peso));
                emitido = true;
            } else {
                suprimidos.push((clave_bytes.clone(), motivo));
            }
            eventos_sorteo.push(EventoMotor::VotoPesoPropio {
                n,
                clave: clave_hex,
                peso,
                emitido,
                motivo,
            });
        }

        // T4 · B-74 · compara la tabla nueva con la de la ventana anterior que **este** motor abrió
        // y apunta las claves que salieron (si caen en subredes vigiladas) con la última ventana en
        // cuya tabla se las vio. Se hace antes de mover `tabla`/`datos` a la instancia.
        self.actualizar_salientes(n, &tabla, &datos);

        self.instancia = Some(Instancia {
            n,
            candidato,
            ancla,
            tabla,
            claves_pub,
            tabla_siguiente,
            pubs_siguiente,
            h_t_siguiente,
            raiz_estado: raiz_propia,
            indice,
            votos_peso: Vec::new(),
            pares_peso: HashMap::new(),
            ventana,
            datos,
            agregados: Vec::new(),
            agregado_publicado: false,
            sueltos_antes: 0,
            sueltos_despues: 0,
            peso_agregado_propio: 0,
        });
        // FV-N6-C7-4 · primera apertura efectiva: se fija aquí, cuando la instancia queda abierta
        // de verdad. Un intento que devolvió error antes de este punto no cuenta, y la marca no se
        // borra al cerrar la ventana ni al diferir una apertura posterior.
        self.apertura_efectiva = true;
        // VS-2 · V3 · última ventana abierta de verdad (para el voto tardío).
        self.ultima_ventana_abierta = Some(n);
        // T3 · B-71 · el tope (G2) se deriva de las claves vigiladas de la tabla abierta y de las
        // salientes apuntadas (T4). Ningún literal.
        self.fijar_tope_detector();
        // DFV-1 · D9 · la ventana nueva poda el detector y reintenta lo pendiente.
        self.detector.al_abrir(n);
        // FV-4b-N1-2 · revalida los votos que llegaron adelantados para esta instancia.
        self.reproducir_pendientes(vista);
        Ok((propios, sobres, votos_red, suprimidos, eventos_sorteo))
    }

    /// Recibe un sobre de voto de red y lo valida contra la instancia abierta (voto por peso).
    #[must_use]
    pub fn recibir_voto(&mut self, bytes: &[u8]) -> RecepcionVoto {
        self.recibir_voto_con_vista(bytes, &VistaPermisiva)
    }

    /// DFV-1 · como [`Self::recibir_voto`], con la vista de cadena que resuelve D5 (conflicto en el
    /// grafo) y D6 (hecho). El nodo pasa su `Cadena`; la biblioteca y los arneses sin cadena usan la
    /// vista permisiva.
    #[must_use]
    pub(crate) fn recibir_voto_con_vista(
        &mut self,
        bytes: &[u8],
        vista: &dyn VistaCadena,
    ) -> RecepcionVoto {
        let Ok(v) = deserializar_voto_peso(bytes) else {
            return RecepcionVoto::Rechazado { motivo: "formato" };
        };
        match self.instancia.as_ref().map(|i| i.n) {
            Some(actual) if v.n > actual => {
                self.encolar_pendiente(v.n, bytes);
                return RecepcionVoto::Rechazado { motivo: "ventana" };
            }
            Some(actual) if v.n < actual => {
                // DFV-1 · D3 · voto de una ventana pasada: se valida y guarda dentro del horizonte,
                // pero la respuesta al llamante es la de hoy.
                self.registrar_voto_pasado(&v, vista);
                self.recibir_voto_anterior(v, vista, false);
                return RecepcionVoto::Rechazado { motivo: "ventana" };
            }
            None => {
                if self.recibe_anterior(v.n) {
                    self.recibir_voto_anterior(v, vista, false);
                    return RecepcionVoto::Rechazado { motivo: "ventana" };
                }
                self.encolar_pendiente(v.n, bytes);
                return RecepcionVoto::Rechazado {
                    motivo: "sin_instancia",
                };
            }
            _ => {}
        }
        self.recibir_voto_actual(v, vista, false)
    }

    /// DFV-1-2 · G1 · ¿`clave` es una clave de voto **registrada** en la tabla de la ventana
    /// abierta? Búsqueda por bytes en `Instancia.indice`, el índice de `T_n` que `abrir` construye
    /// sobre `Instancia.tabla`; la tabla sale de `construir_tabla`, que recorre
    /// `Estado.claves_voto` con peso. Es el registro que el motor tiene a mano: `claves_voto_previas`
    /// (la clave anterior aún viva de una identidad) no se retiene (límite en `INFORME.md`).
    fn clave_voto_registrada(&self, clave: &[u8; LONGITUD_CLAVE_BLS]) -> bool {
        self.instancia
            .as_ref()
            .is_some_and(|inst| inst.indice.contains_key(clave.as_slice()))
    }

    /// T3 · B-71 · claves de la tabla abierta que caen en subredes vigiladas. Sin instancia, 0.
    fn claves_tabla_vigiladas(&self) -> usize {
        let Some(inst) = self.instancia.as_ref() else {
            return 0;
        };
        match &self.subredes_vigiladas {
            None => inst.tabla.claves.len(),
            Some(set) => {
                let reparto = inst.datos.reparto();
                set.iter().map(|s| reparto.claves_de(*s).len()).sum()
            }
        }
    }

    /// T3 · B-71 · fija el tope G2 a `2 · horizonte · (claves vigiladas + salientes apuntadas)`.
    fn fijar_tope_detector(&mut self) {
        let claves = self
            .claves_tabla_vigiladas()
            .saturating_add(self.salientes.len());
        self.detector.fijar_tope(claves);
    }

    /// T4 · B-74 · ¿`clave` puede entregar un voto de la ventana `n_voto` por la vía de las
    /// **pasadas**? Sí si está en la tabla abierta, o si está apuntada como saliente y `n_voto` no
    /// es posterior a la última ventana en cuya tabla se la vio.
    fn clave_aceptada_pasado(&self, clave: &[u8; LONGITUD_CLAVE_BLS], n_voto: u64) -> bool {
        if self.clave_voto_registrada(clave) {
            return true;
        }
        self.salientes
            .get(clave)
            .is_some_and(|ultima| n_voto <= *ultima)
    }

    /// T4/T5 · B-74 · actualiza el apunte de claves salientes al abrir la ventana `n` con la tabla
    /// `tabla` (y su reparto en `datos`).
    fn actualizar_salientes(&mut self, n: u64, tabla: &Tabla, datos: &DatosVentana) {
        let actuales: HashSet<[u8; LONGITUD_CLAVE_BLS]> = tabla
            .claves
            .iter()
            .filter_map(|registro| {
                <[u8; LONGITUD_CLAVE_BLS]>::try_from(registro.clave.as_slice()).ok()
            })
            .collect();
        // Claves que estaban en la tabla anterior y ya no: apunte con su última ventana vista.
        if let Some((n_previa, previas)) = self.tabla_anterior.take() {
            for clave in previas.difference(&actuales) {
                if subred_vigilada(clave, self.subredes, &self.subredes_vigiladas) {
                    self.salientes.insert(*clave, n_previa);
                }
            }
        }
        // Claves que vuelven a la tabla: la última ventana vista pasa a ser la actual (así sus
        // votos viejos siguen emparejándose hasta que venza).
        for clave in &actuales {
            if let Some(ultima) = self.salientes.get_mut(clave) {
                *ultima = n;
            }
        }
        // T4 · una clave apuntada se olvida cuando `última + horizonte < n`.
        let horizonte = self.detector.horizonte();
        self.salientes
            .retain(|_, ultima| ultima.saturating_add(horizonte) >= n);
        // T5 · cota: como mucho tantas salientes como claves de la tabla abierta caen en subredes
        // vigiladas; al llenarse sale la de última ventana más antigua.
        let cap = match &self.subredes_vigiladas {
            None => tabla.claves.len(),
            Some(set) => set
                .iter()
                .map(|s| datos.reparto().claves_de(*s).len())
                .sum(),
        };
        while self.salientes.len() > cap {
            let Some((&mas_antigua, _)) = self.salientes.iter().min_by_key(|(_, v)| **v) else {
                break;
            };
            self.salientes.remove(&mas_antigua);
        }
        self.tabla_anterior = Some((n, actuales));
    }

    /// DFV-1 · D1/D3 · voto válido de una ventana **pasada** dentro del horizonte.
    ///
    /// DFV-1-2 · G1 · la **pertenencia** (tabla abierta, o saliente apuntada con `v.n ≤ última`)
    /// y la **subred vigilada** (T2/T4) se comprueban antes de `ClavePublica::desde_bytes` y de
    /// `verificar`; un voto de una clave no registrada o de una subred no vigilada se descarta sin
    /// tocar criptografía y sin dejar rastro en el detector. T3 · el tope total se deriva de las
    /// claves vigiladas de la tabla abierta más las salientes apuntadas.
    ///
    /// La pertenencia/peso de la clave en la tabla de **esa** ventana pasada la decide la cadena al
    /// admitir la evidencia (el nodo no guarda 450 tablas).
    fn registrar_voto_pasado(&mut self, v: &VotoPeso, vista: &dyn VistaCadena) {
        let Some(actual) = self.instancia.as_ref().map(|i| i.n) else {
            return;
        };
        if v.n.saturating_add(self.detector.horizonte()) < actual {
            return;
        }
        // G1/T4 · pertenencia antes que criptografía: tabla abierta o saliente apuntada.
        if !self.clave_aceptada_pasado(&v.clave, v.n) {
            return;
        }
        // T2 · B-71 · subred vigilada antes que criptografía (junto a la pertenencia).
        if !self.detector.vigila(&v.clave) {
            return;
        }
        // M4 · fuera la guarda de raíz cero: el voto válido entra en el detector con la raíz que
        // trae (el mensaje A3 se reconstruye con ella).
        // T3 · tope derivado de las claves vigiladas (ningún literal).
        self.fijar_tope_detector();
        let Ok(pk) = ClavePublica::desde_bytes(&v.clave) else {
            return;
        };
        let mensaje = mensaje_voto_peso(v.n, &v.candidato, &v.h_t_siguiente, &v.raiz_estado);
        #[cfg(test)]
        VERIFICACIONES_VOTO_PASADO.with(|c| c.set(c.get().saturating_add(1)));
        if verificar(&pk, &v.firma, DOMINIO_VOTO, &mensaje).is_err() {
            return;
        }
        self.detector.registrar(
            v.clave,
            VotoDetector {
                n: v.n,
                candidato: v.candidato,
                h_t_siguiente: v.h_t_siguiente,
                raiz_estado: v.raiz_estado,
                firma: v.firma,
            },
            vista,
        );
    }

    /// PD-1d · M5 · recibe un voto v2 por peso de la instancia **abierta**.
    ///
    /// Motivos, **en este orden**: `no_registrada`, `retirada`, `sin_peso`, `firma_falsa`, y
    /// después `otro_candidato`/`otra_tabla` (guardando el voto para evidencia). Un voto repetido de
    /// la misma clave es idempotente. M3 · no hay motivo `raiz`: un voto válido se acepta con
    /// cualquier raíz y se agrupa por ella.
    ///
    /// B-84 · MOT-2 · `firma_ya_verificada` lo pone `recibir_voto_subred` (`true`) cuando ya
    /// comprobó la firma del voto contra la misma clave y el mismo mensaje A3 que se reconstruye
    /// aquí: así no se verifica dos veces. El sobre antiguo (`recibir_voto_con_vista`) y todos los
    /// demás caminos pasan `false` y se comportan como hoy.
    fn recibir_voto_actual(
        &mut self,
        v: VotoPeso,
        vista: &dyn VistaCadena,
        firma_ya_verificada: bool,
    ) -> RecepcionVoto {
        let Some(inst) = self.instancia.as_mut() else {
            return RecepcionVoto::Rechazado {
                motivo: "sin_instancia",
            };
        };
        let Some(&i) = inst.indice.get(v.clave.as_slice()) else {
            return RecepcionVoto::Rechazado {
                motivo: "no_registrada",
            };
        };
        let Some(registro) = inst.tabla.claves.get(i) else {
            return RecepcionVoto::Rechazado {
                motivo: "no_registrada",
            };
        };
        if !registro.activo {
            return RecepcionVoto::Rechazado { motivo: "retirada" };
        }
        let Ok(w) = peso_de_clave(registro, self.perfil.b) else {
            return RecepcionVoto::Rechazado { motivo: "sin_peso" };
        };
        if w == 0 {
            return RecepcionVoto::Rechazado { motivo: "sin_peso" };
        }
        let Ok(pk) = ClavePublica::desde_bytes(&v.clave) else {
            return RecepcionVoto::Rechazado {
                motivo: "clave_invalida",
            };
        };
        // El mensaje A3 se construye con los campos del **propio** voto (no con los locales): así un
        // voto por otro candidato o tabla es un hecho auténtico sin ser una firma falsa.
        let mensaje = mensaje_voto_peso(inst.n, &v.candidato, &v.h_t_siguiente, &v.raiz_estado);
        if !firma_ya_verificada {
            #[cfg(test)]
            VERIFICACIONES_VOTO_ACTUAL.with(|c| c.set(c.get().saturating_add(1)));
            if verificar(&pk, &v.firma, DOMINIO_VOTO, &mensaje).is_err() {
                return RecepcionVoto::Rechazado {
                    motivo: "firma_falsa",
                };
            }
        }
        let peso = u64::try_from(w).unwrap_or(u64::MAX);
        let n = inst.n;
        let aceptado = VotoPesoAceptado {
            n,
            candidato: v.candidato,
            h_t_siguiente: v.h_t_siguiente,
            raiz_estado: v.raiz_estado,
            clave: v.clave,
            firma: v.firma,
        };
        // DFV-1 · D1 · el voto de la instancia abierta también entra en el detector, que lo empareja
        // con los votos de ventanas pasadas del horizonte.
        self.detector.registrar(
            v.clave,
            VotoDetector {
                n,
                candidato: v.candidato,
                h_t_siguiente: v.h_t_siguiente,
                raiz_estado: v.raiz_estado,
                firma: v.firma,
            },
            vista,
        );
        if v.candidato != inst.candidato || v.h_t_siguiente != inst.h_t_siguiente {
            let motivo = if v.candidato != inst.candidato {
                "otro_candidato"
            } else {
                "otra_tabla"
            };
            inst.pares_peso
                .entry(v.clave.to_vec())
                .or_default()
                .registrar(aceptado);
            return RecepcionVoto::Rechazado { motivo };
        }
        // G1 · el voto suelto del mensaje de la instancia entra en la contabilidad única de la
        // ventana; la ventana resuelve la idempotencia y "una clave, un grupo".
        if let Ok(resultado) =
            inst.ventana
                .registrar_suelto(i.saturating_add(1), v.raiz_estado, v.firma)
            && resultado == ResultadoSuelto::Registrado
        {
            if inst.agregado_publicado {
                inst.sueltos_despues = inst.sueltos_despues.saturating_add(1);
            } else {
                inst.sueltos_antes = inst.sueltos_antes.saturating_add(1);
            }
        }
        if inst.votos_peso.iter().any(|a| a.clave == v.clave) {
            // M3/M6 · una clave cuenta en un solo grupo: si ya votó esta ventana (con cualquier
            // raíz), el voto nuevo no suma, pero se registra para que dos raíces distintas formen
            // pareja contradictoria (evidencia `0x0B`).
            inst.pares_peso
                .entry(v.clave.to_vec())
                .or_default()
                .registrar(aceptado);
            return RecepcionVoto::Aceptado {
                clave: hex(&v.clave),
                plazas: peso,
            };
        }
        inst.votos_peso.push(aceptado);
        inst.pares_peso
            .entry(v.clave.to_vec())
            .or_default()
            .registrar(aceptado);
        RecepcionVoto::Aceptado {
            clave: hex(&v.clave),
            plazas: peso,
        }
    }

    /// G4 · recibe un voto de red **por el tema de su subred**.
    ///
    /// Comprueba, en este orden: forma → subred de la clave (`subred(clave) == subred_llegada`,
    /// penalizable) → clave en la tabla de la ventana abierta **o saliente apuntada con
    /// `v.n ≤ última`** (T4; si no, se ignora **sin** penalizar) → firma contra la clave que el
    /// propio voto trae (penalizable). Si vale, sigue el mismo camino que un voto suelto.
    #[must_use]
    pub fn recibir_voto_subred(
        &mut self,
        subred_llegada: u16,
        bytes: &[u8],
        vista: &dyn VistaCadena,
    ) -> RecepcionVotoSubred {
        let Ok(voto_red) = VotoRed::deserializar(bytes) else {
            return RecepcionVotoSubred::Penalizar { motivo: "formato" };
        };
        let Ok(sub) = subred(&voto_red.clave.bytes(), self.subredes) else {
            return RecepcionVotoSubred::Penalizar { motivo: "subred" };
        };
        if sub != subred_llegada {
            return RecepcionVotoSubred::Penalizar { motivo: "subred" };
        }
        // La clave tiene que estar en la tabla de la ventana abierta o apuntada como saliente con
        // `v.n ≤ última` (T4); si no, se ignora sin penalizar.
        let registrada_anterior = self.recibe_anterior(voto_red.n)
            && self
                .instancia_anterior
                .as_ref()
                .is_some_and(|i| i.indice.contains_key(voto_red.clave.bytes().as_slice()));
        if !self.clave_aceptada_pasado(&voto_red.clave.bytes(), voto_red.n) && !registrada_anterior
        {
            return RecepcionVotoSubred::Ignorar {
                motivo: "no_registrada",
            };
        }
        // La firma se comprueba contra la clave que el propio voto trae: hecho objetivo.
        #[cfg(test)]
        VERIFICACIONES_VOTO_SUBRED.with(|c| c.set(c.get().saturating_add(1)));
        if voto_red.verificar().is_err() {
            return RecepcionVotoSubred::Penalizar {
                motivo: "firma_falsa",
            };
        }
        let voto = VotoPeso {
            n: voto_red.n,
            candidato: voto_red.candidato,
            h_t_siguiente: voto_red.h_t_siguiente,
            raiz_estado: voto_red.raiz_estado,
            clave: voto_red.clave.bytes(),
            firma: voto_red.firma,
        };
        match self.instancia.as_ref().map(|i| i.n) {
            Some(actual) if voto.n > actual => {
                self.encolar_pendiente(voto.n, &serializar_voto_peso(&voto));
                RecepcionVotoSubred::Ignorar { motivo: "ventana" }
            }
            Some(actual) if voto.n < actual => {
                self.registrar_voto_pasado(&voto, vista);
                self.recibir_voto_anterior(voto, vista, true);
                RecepcionVotoSubred::Ignorar { motivo: "ventana" }
            }
            None => {
                if self.recibe_anterior(voto.n) {
                    self.recibir_voto_anterior(voto, vista, true);
                    return RecepcionVotoSubred::Ignorar { motivo: "ventana" };
                }
                self.encolar_pendiente(voto.n, &serializar_voto_peso(&voto));
                RecepcionVotoSubred::Ignorar {
                    motivo: "sin_instancia",
                }
            }
            Some(_) => match self.recibir_voto_actual(voto, vista, true) {
                RecepcionVoto::Aceptado { clave, plazas } => {
                    RecepcionVotoSubred::Aceptado { clave, plazas }
                }
                RecepcionVoto::Rechazado {
                    motivo: "firma_falsa",
                } => RecepcionVotoSubred::Penalizar {
                    motivo: "firma_falsa",
                },
                RecepcionVoto::Rechazado { motivo } => RecepcionVotoSubred::Ignorar { motivo },
            },
        }
    }

    /// G5 · recibe un **lote** de agregados de la ventana abierta.
    ///
    /// Los agregados de otra ventana se ignoran. La ventana por raíces decide por cada uno y el
    /// motor traduce su resultado a la respuesta de red (reenviar / ignorar / penalizar). Un agregado
    /// no entra en el detector.
    ///
    /// C1 · MOT-2 · los coeficientes de la verificación por lotes salen de un secreto del azar del
    /// sistema, del **resumen de todos los agregados de esta llamada** (fijado antes de verificar) y
    /// de un contador. C2 · sin secreto no hay lote: se verifica **de uno en uno**.
    ///
    /// # Errores
    /// Los de `zx-votos` (aritmética exacta, BLS, longitudes).
    pub fn recibir_agregados(
        &mut self,
        agregados: &[Agregado],
    ) -> Result<Vec<RecepcionAgregado>, ErrorVotos> {
        let mut respuestas = self.recibir_agregados_actuales(agregados)?;
        let anterior = self.instancia_anterior.as_ref().map(|i| i.n);
        if let Some(n) = anterior
            && self.recibe_anterior(n)
            && agregados.iter().any(|a| a.n == n)
        {
            std::mem::swap(&mut self.instancia, &mut self.instancia_anterior);
            let recibidos = self.recibir_agregados_actuales(agregados);
            let certificado = if recibidos.is_ok() {
                self.certificar_anterior()
            } else {
                Ok(())
            };
            std::mem::swap(&mut self.instancia, &mut self.instancia_anterior);
            for ((agregado, respuesta), tardia) in
                agregados.iter().zip(&mut respuestas).zip(recibidos?)
            {
                if agregado.n == n {
                    // N3: se procesa, pero jamás se reenvía lo recibido tarde.
                    *respuesta = match tardia {
                        RecepcionAgregado::Penalizar(motivo) => {
                            RecepcionAgregado::Penalizar(motivo)
                        }
                        _ => RecepcionAgregado::Ignorar,
                    };
                }
            }
            certificado?;
        }
        Ok(respuestas)
    }

    fn recibir_agregados_actuales(
        &mut self,
        agregados: &[Agregado],
    ) -> Result<Vec<RecepcionAgregado>, ErrorVotos> {
        let Self {
            instancia,
            generador_agregados,
            ..
        } = self;
        let Some(inst) = instancia.as_mut() else {
            return Ok(agregados
                .iter()
                .map(|_| RecepcionAgregado::Ignorar)
                .collect());
        };
        // C1 · el resumen del lote se fija **antes** de verificar: SHA3-256 de la serialización de
        // **todos** los agregados de esta llamada, en su orden.
        let mut serial = Vec::new();
        for agregado in agregados.iter() {
            serial.extend_from_slice(&agregado.serializar());
        }
        let resumen = *zx_core::sha3_256_publico(&serial).as_bytes();
        let resultados = match generador_agregados.as_mut() {
            Some(generador) => {
                generador.fijar_resumen(resumen);
                #[cfg(test)]
                LOTES_AGREGADOS.with(|c| c.set(c.get().saturating_add(1)));
                inst.ventana
                    .recibir_lote(agregados, generador)
                    .map_err(error_agregacion)?
            }
            // C2 · sin azar del sistema no hay lote: uno a uno y sin respaldo predecible.
            None => {
                let mut resultados = Vec::with_capacity(agregados.len());
                for agregado in agregados.iter() {
                    resultados.push(
                        inst.ventana
                            .recibir_agregado(agregado)
                            .map_err(error_agregacion)?,
                    );
                }
                resultados
            }
        };
        let mut respuestas = Vec::with_capacity(resultados.len());
        for (agregado, resultado) in agregados.iter().zip(resultados) {
            let respuesta = match resultado {
                ResultadoAgregado::Aceptado => {
                    inst.agregados.push(agregado.clone());
                    RecepcionAgregado::Reenviar
                }
                ResultadoAgregado::OtroMensaje
                | ResultadoAgregado::OtraTabla
                | ResultadoAgregado::Repetido => RecepcionAgregado::Ignorar,
                ResultadoAgregado::Invalido(motivo) => RecepcionAgregado::Penalizar(motivo),
            };
            respuestas.push(respuesta);
        }
        Ok(respuestas)
    }

    /// G6 · publica el agregado propio de la ventana abierta (AG-R13′).
    ///
    /// Devuelve los agregados propios serializados cuando hay ventana, el motor emite votos, el slot
    /// es **el último de la ventana o posterior** (`slot + 1 ≥ cierre_ventana(n)`) y todavía no se ha
    /// publicado en esta ventana. En cualquier otro caso devuelve el vector vacío. Una vez por
    /// ventana.
    ///
    /// # Errores
    /// Los de `zx-votos` (aritmética exacta, BLS, longitudes) y los del sorteo.
    pub fn publicar_agregado(&mut self, slot: i64) -> Result<Vec<Vec<u8>>, ErrorVotos> {
        if !self.emitir_votos {
            return Ok(Vec::new());
        }
        let Some(inst) = self.instancia.as_ref() else {
            return Ok(Vec::new());
        };
        if inst.agregado_publicado {
            return Ok(Vec::new());
        }
        let cierre = i64::try_from(cierre_ventana(inst.n)).unwrap_or(i64::MAX);
        // A5-c-2c · N3 · B-87 · se publica en cuanto el motor tiene el voto de **todas** las claves
        // de **cada** subred propia en la tabla de la ventana abierta; si no llega a cubrirlas, al
        // empezar el último slot, como antes. Sigue siendo una sola vez por ventana.
        let ultimo_slot = slot.saturating_add(1) >= cierre;
        if !ultimo_slot && !self.subredes_propias_cubiertas() {
            return Ok(Vec::new());
        }
        let n = inst.n;
        let raiz = inst.raiz_estado;
        let mut peticiones: Vec<(usize, Firma)> = Vec::new();
        for sk in &self.claves {
            let pk = sk.clave_publica();
            let Some(&posicion) = inst.indice.get(pk.bytes().as_slice()) else {
                continue;
            };
            let firma_sorteo = firmar(sk, DOMINIO_SORTEO, &n.to_be_bytes())?;
            peticiones.push((posicion.saturating_add(1), firma_sorteo));
        }
        let Some(inst) = self.instancia.as_mut() else {
            return Ok(Vec::new());
        };
        inst.agregado_publicado = true;
        let mut salida = Vec::new();
        for (posicion, firma_sorteo) in peticiones {
            let Some(agregado) = inst
                .ventana
                .agregado_propio(posicion, raiz, &firma_sorteo)
                .map_err(error_agregacion)?
            else {
                continue;
            };
            inst.peso_agregado_propio = inst
                .peso_agregado_propio
                .saturating_add(peso_de_agregado(&inst.datos, &agregado));
            salida.push(agregado.serializar());
        }
        Ok(salida)
    }

    /// A5-c-2c · N3 · B-87 · ¿tiene el motor ya un voto (suelto o dentro de un agregado válido) de
    /// **todas** las claves de **cada** subred propia en la tabla de la ventana abierta?
    ///
    /// Subredes propias = las subredes de las claves de voto del motor. Sin instancia abierta, o
    /// sin claves propias, devuelve `false` (no adelanta la publicación).
    fn subredes_propias_cubiertas(&self) -> bool {
        let Some(inst) = self.instancia.as_ref() else {
            return false;
        };
        let mut propias: Vec<u16> = Vec::new();
        for sk in &self.claves {
            if let Ok(sub) = subred(sk.clave_publica().bytes().as_slice(), self.subredes)
                && !propias.contains(&sub)
            {
                propias.push(sub);
            }
        }
        if propias.is_empty() {
            return false;
        }
        let cubiertas = inst.claves_cubiertas();
        for sub in propias {
            if inst
                .datos
                .reparto()
                .claves_de(sub)
                .iter()
                .any(|global| !cubiertas.contains(global))
            {
                return false;
            }
        }
        true
    }

    /// G8 · métricas de la última ventana cerrada, si la hay.
    #[must_use]
    pub fn metricas_agregacion(&self) -> Option<&MetricasAgregacion> {
        self.ultimas_metricas.as_ref()
    }

    /// PD-1d · M10 · drena las evidencias `0x0B` de la misma ventana (vista permisiva).
    #[must_use]
    pub fn drenar_evidencias_peso(&mut self) -> Vec<EvidenciaVotosPesoCompleta> {
        self.drenar_evidencias_peso_con_vista(&VistaPermisiva)
    }

    /// DFV-1 · D6/D8 · drena las evidencias `0x0B`: primero las de la **misma** ventana (que no
    /// consultan hecho) y después las de **entre ventanas**, que solo se presentan si la cadena
    /// confirma `Falta`. Los pares `Inadmisible` quedan pendientes.
    ///
    /// Orden determinista (clave BLS, `n`, `h1`, `h2`) para que el registro y las pruebas no
    /// dependan del orden del `HashMap`.
    #[must_use]
    pub(crate) fn drenar_evidencias_peso_con_vista(
        &mut self,
        vista: &dyn VistaCadena,
    ) -> Vec<EvidenciaVotosPesoCompleta> {
        let mut salida: Vec<EvidenciaVotosPesoCompleta> = Vec::new();
        if let Some(inst) = self.instancia.as_ref() {
            for par in inst.pares_peso.values() {
                if let Some(evidencia) = par.evidencia.as_ref()
                    && self.detector.anotar_oferta(&evidencia.clave_bls)
                {
                    // EV-1 · ofrecer no consume el par: reporter/cola todavía no han respondido.
                    salida.push(evidencia.clone());
                }
            }
        }
        salida.extend(self.detector.drenar(vista));
        salida.sort_by(|a, b| {
            a.clave_bls
                .cmp(&b.clave_bls)
                .then_with(|| a.n.cmp(&b.n))
                .then_with(|| a.h1.cmp(&b.h1))
                .then_with(|| a.h2.cmp(&b.h2))
        });
        salida
    }

    /// EV-1 · el nodo ofrece material sin consumir el par de la instancia ni marcar acusadas.
    pub(crate) fn hay_evidencias_pendientes_en(&self, n: u64) -> bool {
        self.detector.hay_material_revisable_en(n)
    }

    /// EV-1 · el nodo ofrece material sin consumir el par de la instancia ni marcar acusadas.
    pub(crate) fn ofrecer_evidencias_peso(
        &mut self,
        vista: &dyn VistaCadena,
        n: u64,
        slot: u64,
        estado: &Estado,
    ) -> Vec<EvidenciaVotosPesoCompleta> {
        let aplicados = estado
            .garantias
            .values()
            .flat_map(|g| g.incidentes.iter().map(|i| i.id))
            .collect();
        let plazo = u64::try_from(estado.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
        self.detector.ofrecer_en(vista, n, slot, plazo, &aplicados)
    }

    /// EV-1 · solo una respuesta que prueba presencia real activa D8.
    pub(crate) fn resolver_evidencia_peso(&mut self, respuesta: crate::mempool::AdmisionEvidencia) {
        match respuesta {
            crate::mempool::AdmisionEvidencia::Admitida(i)
            | crate::mempool::AdmisionEvidencia::Cubierta {
                por: i,
                aplicada: false,
            } => self.detector.marcar_acusada(&i.clave_bls),
            crate::mempool::AdmisionEvidencia::Cubierta { aplicada: true, .. }
            | crate::mempool::AdmisionEvidencia::Rechazada(_) => {}
        }
    }

    pub(crate) fn retirar_evidencia_peso(&mut self, retirada: &crate::mempool::RetiradaEvidencia) {
        self.detector.liberar_acusada(&retirada.identidad.clave_bls);
    }

    /// DFV-1 · D2 · parámetro interno del horizonte (solo pruebas).
    #[cfg(test)]
    pub(crate) fn fijar_horizonte_detector(&mut self, horizonte: u64) {
        self.detector.fijar_horizonte(horizonte);
    }

    /// FV-4b-N1-2 · Encola un voto de una instancia futura, con tope de memoria.
    fn encolar_pendiente(&mut self, n: u64, bytes: &[u8]) {
        if self.pendientes.len() >= MAX_VOTOS_PENDIENTES {
            self.pendientes.remove(0);
        }
        self.pendientes.push((n, bytes.to_vec()));
    }

    /// FV-4b-N1-2 · Revalida los votos encolados para la instancia recién abierta y conserva los de
    /// instancias aún futuras; los de instancias pasadas se descartan. Se llama desde [`Self::abrir`]
    /// después de fijar `self.instancia`.
    fn reproducir_pendientes(&mut self, vista: &dyn VistaCadena) {
        let Some(actual) = self.instancia.as_ref().map(|i| i.n) else {
            return;
        };
        let pendientes = std::mem::take(&mut self.pendientes);
        for (n, bytes) in pendientes {
            if n == actual {
                let _ = self.recibir_voto_con_vista(&bytes, vista);
            } else if n > actual {
                self.pendientes.push((n, bytes));
            }
        }
    }

    /// Cierra la instancia abierta (por peso) y devuelve el certificado o el acta.
    ///
    /// # Errores
    /// Los de `zx-votos`.
    pub fn cerrar(&mut self) -> Result<CierreVotos, ErrorVotos> {
        self.cerrar_peso()
    }

    /// PD-1d · M6/M7 · cierra la instancia abierta en **modo peso**.
    ///
    /// Firmantes = claves con voto A3 aceptado para el candidato y la tabla siguiente de la
    /// instancia. Si `quorum_peso(Σ, W)`: monta el `CertificadoPeso` (mapa en orden canónico; lleva
    /// la tabla siguiente solo si su hash difiere del de la vigente), lo comprueba con
    /// `evaluar_certificado` **y** `verificar_firma_peso`, entrega sus bytes y avanza base y punto.
    /// Si no hay quórum y hay al menos un voto aceptado, entrega un **acta** de presencia (mismos
    /// campos, sin tabla siguiente). No consume la instancia.
    ///
    /// # Errores
    /// Los de `zx-votos` (aritmética exacta, BLS, longitudes).
    fn cerrar_peso(&mut self) -> Result<CierreVotos, ErrorVotos> {
        let Some(inst) = self.instancia.as_ref() else {
            return Ok(CierreVotos::default());
        };
        let n = inst.n;
        let candidato = inst.candidato;
        let h_t_siguiente = inst.h_t_siguiente;
        let raiz_propia = inst.raiz_estado;
        let tabla = inst.tabla.clone();
        let votos = inst.votos_peso.clone();
        let agregados = inst.agregados.clone();
        let datos = Arc::clone(&inst.datos);
        let sueltos_antes = inst.sueltos_antes;
        let sueltos_despues = inst.sueltos_despues;
        let peso_agregado_propio = inst.peso_agregado_propio;
        // G1 · certificado, acta y resumen salen de la contabilidad única de la ventana.
        let resumen = inst.ventana.resumen().map_err(error_agregacion)?;
        let certificado_ventana = inst.ventana.certificado().map_err(error_agregacion)?;
        let acta_raiz = inst
            .ventana
            .acta()
            .map_err(error_agregacion)?
            .map(|(raiz, _)| raiz);
        let b = self.perfil.b;

        let w = peso_total_u128(&tabla, b)?;
        let umbral = u64::try_from(umbral_peso(w)).unwrap_or(u64::MAX);
        let h_vig = hash_tabla(&tabla);
        let raices_distintas = u64::try_from(resumen.raices).unwrap_or(u64::MAX);
        let mut cierre = CierreVotos {
            plazas_validas: u64::try_from(resumen.mayor.map_or(0, |g| g.peso_cubierto))
                .unwrap_or(u64::MAX),
            umbral,
            ..CierreVotos::default()
        };
        // G8 · métricas de la ventana cerrada, para la orden del nodo.
        let metricas = metricas_de_cierre(
            n,
            &tabla,
            &datos,
            &votos,
            &agregados,
            certificado_ventana
                .as_ref()
                .map(|cert| cert.raiz_estado)
                .or(acta_raiz),
            sueltos_antes,
            sueltos_despues,
            peso_agregado_propio,
        );
        // RA-2 · R2 · ¿la ventana que se cierra es de rearranque (`n > m + CADUCIDAD`)? En ese caso
        // el previo encadena con la tabla del ciclo (`h_vig`), como la rama de rearranque del
        // consenso; en el camino normal se conserva el hash de la base, que detecta una base que no
        // casa (E2).
        let es_rearranque = self
            .base
            .is_some_and(|(m, _)| n > m.saturating_add(CADUCIDAD_TABLA_VENTANAS));
        let claves_bls = claves_publicas_de_tabla(&tabla)?;
        let mut raiz_certificada: Option<Hash> = None;
        if let Some(cert) = &certificado_ventana {
            // G1 · el certificado sale de la ventana; se comprueba antes de adoptarlo.
            verificar_firma_peso(&tabla, &claves_bls, cert)?;
            let (genesis, cert_previo) = match self.base {
                Some((m, h)) if m < n => (
                    false,
                    Some(CertPrevioPeso {
                        n: m,
                        h_t_siguiente: if es_rearranque { h_vig } else { h },
                    }),
                ),
                Some(_) => (false, None),
                None => (true, None),
            };
            let entrada = EntradaPeso {
                b,
                genesis,
                n_certificado: cert.n,
                ventana: n,
                tabla_vigente: &tabla,
                cert_previo,
                tabla_comprometida: &h_vig,
                raiz_estado: &cert.raiz_estado,
                raiz_firmada: &cert.raiz_estado,
                firma_ok: true,
                h_t_siguiente_declarada: &cert.h_t_siguiente,
                h_t_siguiente_aceptadas: std::slice::from_ref(&cert.h_t_siguiente),
                acta: false,
                mapa_bits: &cert.mapa,
            };
            let resultado = evaluar_certificado(&entrada)?;
            if resultado.valido {
                let raiz = cert.raiz_estado;
                raiz_certificada = Some(raiz);
                cierre.certificado_peso_bytes = Some(serial_certificado_peso(cert));
                cierre.certificado_peso = Some(cert.clone());
                let votos_ganador: Vec<VotoPesoAceptado> = votos
                    .iter()
                    .filter(|v| v.raiz_estado == raiz)
                    .copied()
                    .collect();
                let con_agregados = agregados.iter().any(|a| a.raiz_estado == raiz);
                self.ventana_peso = Some(VentanaPesoCerrada {
                    n,
                    candidato,
                    h_t_siguiente,
                    raiz_estado: raiz,
                    votos: votos_ganador,
                    con_agregados,
                });
                self.punto = Some(candidato);
                self.base = Some((n, h_t_siguiente));
                self.base_provisional = true;
                self.certificados_peso.push(cert.clone());
                self.certificados_adoptados = self.certificados_adoptados.saturating_add(1);
                self.ultimo_certificado_peso = Some(cert.clone());
                self.reloj_certificados.1 = self.reloj_certificados.1.max(cierre_ventana(n));
                self.podar_certificados_peso();
            }
            // PD-1e · E1 · una evaluación no válida (p. ej. base ya en esta ventana) no es un error
            // del motor: cierra sin certificado y deja abrir la ventana siguiente.
        } else if let Some(raiz_acta) = acta_raiz {
            // G1 · el acta sale de la contabilidad única: sueltos y agregados aceptados de la raíz
            // del grupo de más peso, con la elección AG-R14 de la propia ventana.
            let mensaje = MensajeVoto {
                n,
                candidato,
                h_t_siguiente,
                raiz_estado: raiz_acta,
            };
            let agregados_raiz: Vec<Agregado> = agregados
                .iter()
                .filter(|a| a.raiz_estado == raiz_acta)
                .cloned()
                .collect();
            let sueltos_raiz: Vec<(usize, Firma)> = votos
                .iter()
                .filter(|v| v.raiz_estado == raiz_acta)
                .filter_map(|v| {
                    tabla
                        .claves
                        .iter()
                        .position(|c| c.clave == v.clave)
                        .map(|pos| (pos.saturating_add(1), v.firma))
                })
                .collect();
            let acta = armar_certificado(
                mensaje,
                &tabla,
                datos.pesos(),
                datos.reparto(),
                &agregados_raiz,
                &sueltos_raiz,
            )
            .map_err(error_agregacion)?;
            // El acta no transporta tabla siguiente; se valida como acta (sin exigir quórum).
            verificar_firma_peso(&tabla, &claves_bls, &acta)?;
            let (genesis, cert_previo) = match self.base {
                Some((m, h)) => (
                    false,
                    Some(CertPrevioPeso {
                        n: m,
                        h_t_siguiente: if es_rearranque { h_vig } else { h },
                    }),
                ),
                None => (true, None),
            };
            let entrada = EntradaPeso {
                b,
                genesis,
                n_certificado: acta.n,
                ventana: n,
                tabla_vigente: &tabla,
                cert_previo,
                tabla_comprometida: &h_vig,
                raiz_estado: &acta.raiz_estado,
                raiz_firmada: &acta.raiz_estado,
                firma_ok: true,
                h_t_siguiente_declarada: &h_vig,
                h_t_siguiente_aceptadas: std::slice::from_ref(&h_vig),
                acta: true,
                mapa_bits: &acta.mapa,
            };
            let resultado = evaluar_certificado(&entrada)?;
            if resultado.valido {
                // ACTA-1 · R4 · la lista auxiliar sale de **todos** los bits del mapa firmado
                // (sueltos y agregados), no solo de los sueltos: una lista parcial no puede decidir
                // la inclusión ni la poda. La traducción a identidad la hace el nodo con la función
                // de la cadena (R1).
                cierre.acta_peso_firmantes = zx_votos::peso::firmantes_de_mapa(&acta.mapa)
                    .iter()
                    .filter_map(|pos| {
                        pos.checked_sub(1)
                            .and_then(|p| tabla.claves.get(p))
                            .and_then(|c| {
                                <[u8; LONGITUD_CLAVE_BLS]>::try_from(c.clave.as_slice()).ok()
                            })
                    })
                    .collect();
                cierre.acta_peso_bytes = Some(serial_certificado_peso(&acta));
                cierre.acta_peso = Some(acta);
            }
            // PD-1e · E1 · acta no válida: se cierra sin acta, sin error del motor.
        }
        // M8 · un único aviso por ventana si hubo votos de más de una raíz.
        if raices_distintas > 1
            && let Some(segunda) = resumen.segunda
        {
            cierre.eventos.push(EventoMotor::RaizEstadoDiscrepante {
                n,
                propia: hex(&raiz_propia),
                certificada: raiz_certificada.map(|r| hex(&r)),
                raiz_mayor: hex(&resumen.mayor.map_or(raiz_propia, |g| g.raiz)),
                peso_mayor: u64::try_from(resumen.mayor.map_or(0, |g| g.peso_cubierto))
                    .unwrap_or(u64::MAX),
                raiz_segunda: hex(&segunda.raiz),
                peso_segunda: u64::try_from(segunda.peso_cubierto).unwrap_or(u64::MAX),
                raices_distintas,
                sin_quorum_por_division: resumen.sin_quorum_por_division,
            });
        }
        self.ultimas_metricas = Some(metricas);
        Ok(cierre)
    }

    /// PD-1d · M8 · vuelve a montar el certificado de la **última ventana cerrada por peso** contra
    /// **otra** tabla (la del bloque que va a incluir el certificado), en orden canónico.
    ///
    /// Reasigna índices por clave BLS, descarta firmantes que no estén en la tabla o no pesen,
    /// recalcula el quórum y la firma agregada. Devuelve `None` si no hay quórum con esa tabla; el
    /// certificado no lleva tabla siguiente (el llamante decide la del bloque).
    ///
    /// # Errores
    /// Los de `zx-votos` (longitudes, BLS, aritmética).
    pub fn certificado_para_tabla(
        &self,
        tabla: &Tabla,
    ) -> Result<Option<CertificadoPeso>, ErrorVotos> {
        let Some(ventana) = &self.ventana_peso else {
            return Ok(None);
        };
        // G7 · un agregado está atado a su tabla: si el grupo certificado llevaba alguno, no se
        // puede remontar. Con solo sueltos, como hoy.
        if ventana.con_agregados {
            return Ok(None);
        }
        let b = self.perfil.b;
        let w = peso_total_u128(tabla, b)?;
        let mut firmas_votos: Vec<(usize, Firma)> = Vec::with_capacity(ventana.votos.len());
        let mut sigma: u128 = 0;
        for voto in &ventana.votos {
            let Some(pos) = tabla.claves.iter().position(|c| c.clave == voto.clave) else {
                continue;
            };
            let Some(registro) = tabla.claves.get(pos) else {
                continue;
            };
            if !registro.activo {
                continue;
            }
            let Ok(w_i) = peso_de_clave(registro, b) else {
                continue;
            };
            if w_i == 0 {
                continue;
            }
            sigma = sigma.saturating_add(w_i);
            firmas_votos.push((pos + 1, voto.firma));
        }
        if !quorum_peso(sigma, w) {
            return Ok(None);
        }
        let cert = construir_certificado(
            ventana.n,
            ventana.candidato,
            ventana.h_t_siguiente,
            ventana.raiz_estado,
            tabla,
            &firmas_votos,
        )?;
        let claves = claves_publicas_de_tabla(tabla)?;
        verificar_firma_peso(tabla, &claves, &cert)?;
        // TB-1c · T2/N2: el certificado no lleva tabla; la huella va firmada en `h_t_siguiente`.
        Ok(Some(cert))
    }
}

impl std::fmt::Debug for MotorVotos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MotorVotos")
            .field("perfil", &self.perfil)
            .field("claves", &self.claves.len())
            .field("instancia", &self.instancia.as_ref().map(|i| i.n))
            .field("punto", &self.punto.map(|h| hex(&h)))
            .field("certificados_peso", &self.certificados_peso.len())
            .field("diario", &self.diario.is_some())
            .finish()
    }
}

/// Traduce un error de la pieza de agregación al vocabulario del motor.
fn error_agregacion(error: ErrorAgregacion) -> ErrorVotos {
    match error {
        ErrorAgregacion::LongitudInesperada { esperado, obtenido } => {
            ErrorVotos::LongitudInesperada { esperado, obtenido }
        }
        ErrorAgregacion::SubredesCero => ErrorVotos::CargaInicialInvalida {
            motivo: "subredes_cero",
        },
        ErrorAgregacion::FueraDeU16 => ErrorVotos::CargaInicialInvalida {
            motivo: "agregacion_fuera_de_u16",
        },
        ErrorAgregacion::LongitudesIncompatibles { claves, plazas } => {
            ErrorVotos::LongitudesIncompatibles { claves, plazas }
        }
        ErrorAgregacion::ClaveNoRegistrada => ErrorVotos::ClaveNoRegistrada,
        ErrorAgregacion::Bls(error) => ErrorVotos::Bls(error),
    }
}

/// Lee el bit `posicion` (0-based) de un mapa de bits.
fn bit_mapa(mapa: &[u8], posicion: usize) -> bool {
    mapa.get(posicion >> 3)
        .is_some_and(|byte| (byte >> (posicion & 7)) & 1 == 1)
}

/// G6 · peso cubierto por el mapa local de un agregado propio.
fn peso_de_agregado(datos: &DatosVentana, agregado: &Agregado) -> u128 {
    let mut total: u128 = 0;
    for (pos, &idx_global) in datos
        .reparto()
        .claves_de(agregado.subred)
        .iter()
        .enumerate()
    {
        if bit_mapa(&agregado.mapa_local, pos) {
            total = total.saturating_add(datos.pesos().get(idx_global).copied().unwrap_or(0));
        }
    }
    total
}

/// G8 · métricas de una ventana cerrada.
///
/// `raiz` es la raíz certificada (o la del acta); el peso del agregado elegido se calcula, por
/// subred, con la misma regla AG-R14 que la ventana: máximo peso de la unión del mapa del agregado
/// con los votos sueltos de esa raíz y, a igualdad, menor `indice_agregadora`.
#[allow(
    clippy::too_many_arguments,
    reason = "los argumentos son el contexto ya extraido de la instancia; es una funcion de cierre"
)]
fn metricas_de_cierre(
    n: u64,
    tabla: &Tabla,
    datos: &DatosVentana,
    votos: &[VotoPesoAceptado],
    agregados: &[Agregado],
    raiz: Option<Hash>,
    sueltos_antes: u64,
    sueltos_despues: u64,
    peso_agregado_propio: u128,
) -> MetricasAgregacion {
    let mut subredes = Vec::with_capacity(usize::from(datos.reparto().s()));
    for sub in 0..datos.reparto().s() {
        let indices = datos.reparto().claves_de(sub);
        let mut validos: u64 = 0;
        let mut mejor: Option<(u128, u16)> = None;
        for agregado in agregados.iter().filter(|a| a.subred == sub) {
            validos = validos.saturating_add(1);
            if Some(agregado.raiz_estado) != raiz {
                continue;
            }
            let mut peso_union: u128 = 0;
            for (pos, &idx_global) in indices.iter().enumerate() {
                let en_mapa = bit_mapa(&agregado.mapa_local, pos);
                let en_suelto = votos.iter().any(|v| {
                    v.raiz_estado == agregado.raiz_estado
                        && tabla
                            .claves
                            .get(idx_global)
                            .is_some_and(|c| c.clave == v.clave)
                });
                if en_mapa || en_suelto {
                    peso_union = peso_union
                        .saturating_add(datos.pesos().get(idx_global).copied().unwrap_or(0));
                }
            }
            let mejora = match mejor {
                None => true,
                Some((peso_previo, indice_previo)) => {
                    peso_union > peso_previo
                        || (peso_union == peso_previo && agregado.indice_agregadora < indice_previo)
                }
            };
            if mejora {
                mejor = Some((peso_union, agregado.indice_agregadora));
            }
        }
        subredes.push(MetricaSubred {
            subred: sub,
            peso_agregado_elegido: mejor.map_or(0, |(peso, _)| peso),
            agregados_validos: validos,
        });
    }
    MetricasAgregacion {
        n,
        sueltos_antes_de_publicar: sueltos_antes,
        sueltos_despues_de_publicar: sueltos_despues,
        peso_agregado_propio,
        subredes,
    }
}

/// TB4-R7 · huella siguiente que declara el votante al abrir la ventana `n`.
///
/// Es la **última huella de `Q`** (`cola_tablas_voto`) del estado del candidato —el que recibe
/// `MotorVotos::abrir`, que es `estado_past(candidato)`— en las **tres** ramas (con base, sin base y
/// rearranque). La última es la de mayor ventana fresca porque C1 de TB4-C-2 mueve la refrescada
/// al final. Con `Q` vacía, declara la huella de la tabla con la que firma (`ancla`). Antes de
/// TB4-R7, con la base caducada (`n > m + CADUCIDAD_TABLA_VENTANAS`) declaraba `ancla` (la
/// instantánea en el rearranque): la regla TB4-R3 lo rechazaría.
fn huella_siguiente_n1(estado: &Estado, _n: u64, ancla: Hash) -> Hash {
    match estado.cola_tablas_voto.last() {
        Some((_, h)) => *h,
        None => ancla,
    }
}

/// TB-1b · N1/B2 · tabla que acompaña a la huella declarada: el contenido de `h` tal como está en
/// el estado (`tablas_voto_contenido`) o, si `h` es la huella de la tabla con la que se firma, esa
/// misma tabla reetiquetada con `n+1`. El hash de una tabla no depende de `n`, así que reetiquetarla
/// conserva `h`.
///
/// Si el contenido de la huella declarada no está, devuelve el error de carga inicial que ya existe:
/// el votante no vota esa ventana y el llamante la difiere.
fn tabla_de_huella_siguiente(
    estado: &Estado,
    n: u64,
    h: Hash,
    ancla: Hash,
    tabla: &Tabla,
    claves_pub: &[ClavePublica],
) -> Result<(Tabla, Vec<ClavePublica>), ErrorVotos> {
    if h == ancla {
        return Ok((
            Tabla {
                n: n.saturating_add(1),
                claves: tabla.claves.clone(),
            },
            claves_pub.to_vec(),
        ));
    }
    let Some(contenido) = estado.tablas_voto_contenido.get(&h) else {
        return Err(ErrorVotos::CargaInicialInvalida {
            motivo: "tabla_siguiente_no_hallada",
        });
    };
    let siguiente = Tabla {
        n: n.saturating_add(1),
        claves: contenido.iter().map(clave_de_payload).collect(),
    };
    let pubs = claves_publicas_de_tabla(&siguiente)?;
    Ok(canonizar_tabla(siguiente, pubs))
}

/// Construye `T_n` desde el estado: claves con clave BLS de voto registrada y peso = sectores.
///
/// El orden es el de [`Estado::claves_voto`] (un `BTreeMap`, determinista); las claves públicas
/// devueltas quedan alineadas con `tabla.claves` para `verificar_certificado_bls`.
fn construir_tabla(
    n: u64,
    estado: &Estado,
    slot: i64,
) -> Result<(Tabla, Vec<ClavePublica>), ErrorVotos> {
    let pesos = pesos_por_clave(estado, slot, &estado.parametros_sector);
    let mut claves: Vec<Clave> = Vec::new();
    let mut pubs: Vec<ClavePublica> = Vec::new();
    for (clave_ed, clave_voto) in &estado.claves_voto {
        let peso = pesos.get(clave_ed).copied().unwrap_or(0);
        if peso <= 0 {
            continue;
        }
        // TB-1b · N5 · claves ya validadas con memoria (mismo resultado que `desde_bytes`).
        let Ok(pk) = ClavePublica::desde_bytes_con_memoria(&clave_voto.clave_bls) else {
            continue;
        };
        let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && estado.pruebas.contains_key(clave_ed);
        let peso = u64::try_from(peso).map_err(|_| ErrorVotos::Desbordamiento)?;
        // FV-4b-N4 · la fuente de peso definitiva es la de **sectores registrados con garantía** de
        // la identidad Ed25519 (`pesos_por_clave` ya la computó); `FuenteSectores` la materializa y
        // sustituye a la fuente provisional por garantía de FV-D08.
        let clave_tabla =
            clave_desde_fuente(&clave_voto.clave_bls, true, prueba, peso, &FuenteSectores)?;
        claves.push(clave_tabla);
        pubs.push(pk);
    }
    Ok((Tabla { n, claves }, pubs))
}
/// FV-N6-C6 · exige correspondencia exacta `claves[i]` ↔ bytes de `tabla.claves[i]`.
fn validar_claves_alineadas(tabla: &Tabla, claves: &[ClavePublica]) -> Result<(), ErrorVotos> {
    if claves.len() != tabla.claves.len() {
        return Err(ErrorVotos::LongitudesIncompatibles {
            claves: claves.len(),
            plazas: tabla.claves.len(),
        });
    }
    for (clave, publica) in tabla.claves.iter().zip(claves.iter()) {
        if publica.bytes().as_slice() != clave.clave.as_slice() {
            return Err(ErrorVotos::CargaInicialInvalida {
                motivo: "claves_desalineadas",
            });
        }
    }
    Ok(())
}

/// Convierte una clave de tabla del estado (`ClaveTablaVoto`) al tipo del contrato de `zx-votos`.
fn clave_de_payload(c: &ClaveTablaVoto) -> Clave {
    Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    }
}

/// PD-1e · E6 · construye la `Tabla` del contrato a partir del **contenido** de tabla del estado
/// (`tablas_voto_contenido` o `tabla_canonica`), en orden canónico por bytes de clave BLS.
#[must_use]
pub(crate) fn tabla_de_contenido(n: u64, contenido: &[ClaveTablaVoto]) -> Tabla {
    let mut claves: Vec<Clave> = contenido.iter().map(clave_de_payload).collect();
    claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    Tabla { n, claves }
}

/// Comprueba **baratamente** la estructura del sobre de voto por peso (`ZXV3`), sin tocar BLS.
///
/// Es lo que usa el manejador de red asíncrono para descartar basura demostrable sin bloquear el
/// bucle; la validación criptográfica completa la hace [`MotorVotos::recibir_voto`] en el hilo de
/// consenso.
#[must_use]
pub fn voto_es_plausible(bytes: &[u8]) -> bool {
    /// PD-1d · M4 · longitud fija exacta del voto por peso.
    const PESO: usize = 4 + 8 + 3 * 32 + LONGITUD_CLAVE_BLS + LONGITUD_FIRMA;
    bytes.len() == PESO && bytes.starts_with(&CABECERA_VOTO_PESO[..])
}

/// FV-N6-C7-2 §D · datos de observación de un sobre de voto por peso con **formato válido**.
///
/// Devuelve `(n, clave hex, peso, candidato hex)`; `None` si el sobre no deserializa. No altera la
/// validación criptográfica: es solo instrumentación acotada. El peso viaja fuera del sobre, así
/// que aquí se observa `0`.
#[must_use]
pub(crate) fn observar_voto(bytes: &[u8]) -> Option<(u64, String, u64, String)> {
    let v = deserializar_voto_peso(bytes).ok()?;
    Some((v.n, hex(&v.clave), 0, hex(&v.candidato)))
}

/// Convierte un hash de 32 bytes a texto hexadecimal.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
///
/// `ZXV3` (4) ‖ `n` u64 BE (8) ‖ candidato (32) ‖ `h_t_siguiente` (32) ‖ raíz (32) ‖ clave BLS (48)
/// ‖ firma BLS (96) = 252 bytes. Una sola codificación válida.
#[must_use]
pub fn serializar_voto_peso(voto: &VotoPeso) -> Vec<u8> {
    let mut salida = Vec::with_capacity(4 + 8 + 3 * 32 + LONGITUD_CLAVE_BLS + LONGITUD_FIRMA);
    salida.extend_from_slice(CABECERA_VOTO_PESO);
    salida.extend_from_slice(&voto.n.to_be_bytes());
    salida.extend_from_slice(&voto.candidato);
    salida.extend_from_slice(&voto.h_t_siguiente);
    salida.extend_from_slice(&voto.raiz_estado);
    salida.extend_from_slice(&voto.clave);
    salida.extend_from_slice(&voto.firma.bytes());
    salida
}

/// PD-1d · M4 · deserializa el sobre `ZXV3` de longitud fija. Un sobre de hoy (`ZXV2`) se rechaza
/// por cabecera.
///
/// # Errores
/// [`ErrorVotos::CabeceraInvalida`] si no empieza por `ZXV3`; [`ErrorVotos::LongitudInesperada`] si
/// la longitud no es la exacta; [`ErrorVotos::Bls`] si la firma no es un punto válido de G2.
pub fn deserializar_voto_peso(bytes: &[u8]) -> Result<VotoPeso, ErrorVotos> {
    const EXACTA: usize = 4 + 8 + 3 * 32 + LONGITUD_CLAVE_BLS + LONGITUD_FIRMA;
    let mut lector = Lector { bytes, pos: 0 };
    if lector.tomar(CABECERA_VOTO_PESO.len())? != &CABECERA_VOTO_PESO[..] {
        return Err(ErrorVotos::CabeceraInvalida);
    }
    if bytes.len() != EXACTA {
        return Err(ErrorVotos::LongitudInesperada {
            esperado: EXACTA,
            obtenido: bytes.len(),
        });
    }
    let n = lector.u64()?;
    let candidato = lector.hash()?;
    let h_t_siguiente = lector.hash()?;
    let raiz_estado = lector.hash()?;
    let clave_bytes = lector.tomar(LONGITUD_CLAVE_BLS)?;
    let mut clave = [0u8; LONGITUD_CLAVE_BLS];
    clave.copy_from_slice(clave_bytes);
    let firma = Firma::desde_bytes(lector.tomar(LONGITUD_FIRMA)?)?;
    if lector.pos != bytes.len() {
        return Err(ErrorVotos::BytesSobrantes {
            sobran: bytes.len() - lector.pos,
        });
    }
    Ok(VotoPeso {
        n,
        candidato,
        h_t_siguiente,
        raiz_estado,
        clave,
        firma,
    })
}
/// AUS-2b · N1 · carga útil del voto propio `0x08` (AV-11): la firma BLS **ya emitida** por el motor
/// para esa ventana, sin firmar nada nuevo.
#[derive(Clone, Debug)]
pub struct VotoPropioPayload {
    /// Instancia/ventana `n`.
    pub n: u64,
    /// Candidato `h_B` votado.
    pub candidato: Hash,
    /// `h_T(n+1)` con el que se firmó el voto.
    pub h_t_siguiente: Hash,
    /// RE-2c · C2′ · raíz de estado que el votante firmó para esa ventana (hoy, siempre cero).
    pub raiz_estado: Hash,
    /// Clave BLS de voto que firma (G1 comprimido, 48 B).
    pub clave_bls: [u8; 48],
    /// Firma BLS del voto (G2 comprimida, 96 B).
    pub firma: [u8; 96],
}

/// AUS-2b · N1 · Construye la `Tx` v6 `0x08` de voto propio y su testigo Ed25519, reutilizando la
/// firma BLS del voto ya emitido por el motor.
#[must_use]
pub fn tx_voto_propio(
    payload: &VotoPropioPayload,
    firmante_pk: zx_core::ClavePublica,
    firmante_sk: &ed25519_zebra::SigningKey,
    cbid: u32,
) -> (zx_core::Tx, Vec<Vec<u8>>) {
    let operacion = zx_core::OperacionAlmacenamiento::VotoPropio {
        clave: firmante_pk,
        n: payload.n,
        candidato: payload.candidato,
        h_t_siguiente: payload.h_t_siguiente,
        raiz_estado: payload.raiz_estado,
        clave_bls: payload.clave_bls,
        firma: payload.firma,
    };
    let tx = zx_core::Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: zx_core::ExtensionTx::PruebaAlmacenamiento { operacion },
    };
    let firma: [u8; 64] = firmante_sk
        .sign(&zx_core::mensaje_almacenamiento(&tx, cbid))
        .into();
    (tx, vec![firma.to_vec()])
}

// ─────────────────────────────────────────────────────────────────────────────
// PD-1d · M11 · transacciones v6 del flujo por peso (`0x09`, `0x0A`, `0x0B`)
// ─────────────────────────────────────────────────────────────────────────────

/// PD-1d · M11 · construye la `Tx` v6 `0x09` de un certificado compacto por peso y su testigo
/// Ed25519.
#[must_use]
pub fn tx_certificado_peso(
    certificado: &CertificadoPeso,
    firmante_pk: zx_core::ClavePublica,
    firmante_sk: &ed25519_zebra::SigningKey,
    cbid: u32,
) -> (zx_core::Tx, Vec<Vec<u8>>) {
    let bytes = serial_certificado_peso(certificado);
    let operacion = OperacionAlmacenamiento::CertificadoPeso {
        clave: firmante_pk,
        bytes,
    };
    let tx = zx_core::Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: zx_core::ExtensionTx::PruebaAlmacenamiento { operacion },
    };
    let firma: [u8; 64] = firmante_sk
        .sign(&zx_core::mensaje_almacenamiento(&tx, cbid))
        .into();
    (tx, vec![firma.to_vec()])
}

/// PD-1d · M11 · construye la `Tx` v6 `0x0A` de un acta de presencia por peso y su testigo Ed25519.
#[must_use]
pub fn tx_acta_presencia(
    acta: &CertificadoPeso,
    firmante_pk: zx_core::ClavePublica,
    firmante_sk: &ed25519_zebra::SigningKey,
    cbid: u32,
) -> (zx_core::Tx, Vec<Vec<u8>>) {
    let bytes = serial_certificado_peso(acta);
    let operacion = OperacionAlmacenamiento::ActaPresencia {
        clave: firmante_pk,
        bytes,
    };
    let tx = zx_core::Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: zx_core::ExtensionTx::PruebaAlmacenamiento { operacion },
    };
    let firma: [u8; 64] = firmante_sk
        .sign(&zx_core::mensaje_almacenamiento(&tx, cbid))
        .into();
    (tx, vec![firma.to_vec()])
}

/// PD-1d · M11 · construye la `Tx` v6 `0x0B` de una evidencia de dos votos por peso y su testigo.
#[must_use]
pub fn tx_evidencia_votos_peso(
    evidencia: &EvidenciaVotosPesoCompleta,
    firmante_pk: zx_core::ClavePublica,
    firmante_sk: &ed25519_zebra::SigningKey,
    cbid: u32,
) -> (zx_core::Tx, Vec<Vec<u8>>) {
    let operacion = OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: firmante_pk,
        clave_bls: evidencia.clave_bls,
        voto1: VotoPesoEvidencia {
            n: evidencia.n,
            candidato: evidencia.h1,
            h_t_siguiente: evidencia.h_t1,
            raiz_estado: evidencia.raiz1,
            firma: evidencia.firma1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n: evidencia.n2,
            candidato: evidencia.h2,
            h_t_siguiente: evidencia.h_t2,
            raiz_estado: evidencia.raiz2,
            firma: evidencia.firma2.bytes(),
        },
    };
    let tx = zx_core::Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: zx_core::ExtensionTx::PruebaAlmacenamiento { operacion },
    };
    let firma: [u8; 64] = firmante_sk
        .sign(&zx_core::mensaje_almacenamiento(&tx, cbid))
        .into();
    (tx, vec![firma.to_vec()])
}
// ─────────────────────────────────────────────────────────────────────────────
// PD-1d · M12 · punto de control externo **por peso**
// ─────────────────────────────────────────────────────────────────────────────

/// TB-1c · C8/N4 · punto de control por peso: tabla vigente con sus claves, certificado, cola `Q`
/// y contenidos de las huellas de la cola (en lugar de «la tabla y su siguiente»).
#[derive(Clone, Debug)]
pub struct PuntoControlPeso {
    /// Tabla vigente.
    pub tabla: Tabla,
    /// Claves públicas BLS alineadas con `tabla.claves`.
    pub claves: Vec<ClavePublica>,
    /// Certificado que fija el punto y la base.
    pub certificado: CertificadoPeso,
    /// Cola `Q`: pares `(ventana, huella)`.
    pub cola: Vec<(u64, [u8; 32])>,
    /// Contenidos de las huellas de la cola (huella → tabla).
    pub contenidos: Vec<([u8; 32], Tabla)>,
}

/// Escribe una tabla del punto de control: `n u64 ‖ n_claves u64 ‖ claves…`.
fn escribir_tabla_control(salida: &mut Vec<u8>, tabla: &Tabla) {
    salida.extend_from_slice(&tabla.n.to_be_bytes());
    salida.extend_from_slice(&(tabla.claves.len() as u64).to_be_bytes());
    for clave in &tabla.claves {
        salida.extend_from_slice(&(clave.clave.len() as u64).to_be_bytes());
        salida.extend_from_slice(&clave.clave);
        salida.extend_from_slice(&clave.peso.to_be_bytes());
        salida.push(u8::from(clave.activo));
        salida.push(u8::from(clave.prueba));
        salida.extend_from_slice(&clave.garantia.to_be_bytes());
    }
}

/// Lee una tabla del punto de control y sus claves públicas alineadas.
fn leer_tabla_control(lector: &mut Lector<'_>) -> Result<(Tabla, Vec<ClavePublica>), ErrorVotos> {
    let n = lector.u64()?;
    let n_claves =
        usize::try_from(lector.u64()?).map_err(|_| ErrorVotos::EnteroFueraDePlataforma)?;
    let mut claves = Vec::with_capacity(n_claves.min(1 << 16));
    let mut pubs = Vec::with_capacity(n_claves.min(1 << 16));
    for _ in 0..n_claves {
        let longitud_clave =
            usize::try_from(lector.u64()?).map_err(|_| ErrorVotos::EnteroFueraDePlataforma)?;
        let clave = lector.tomar(longitud_clave)?.to_vec();
        let peso = lector.u64()?;
        let activo = lector.u8()? != 0;
        let prueba = lector.u8()? != 0;
        let garantia = lector.u64()?;
        let pk =
            ClavePublica::desde_bytes(&clave).map_err(|_| ErrorVotos::CargaInicialInvalida {
                motivo: "clave_control_peso_invalida",
            })?;
        claves.push(Clave {
            clave,
            peso,
            activo,
            prueba,
            garantia,
        });
        pubs.push(pk);
    }
    Ok((Tabla { n, claves }, pubs))
}

/// PD-1d · M12 · serializa un punto de control por peso (TB-1c · N4):
/// `ZXPCP1 ‖ tabla ‖ long_cert u64 ‖ cert_bytes ‖ n_cola u64 ‖ (ventana u64, huella 32)…
///  ‖ n_contenidos u64 ‖ (huella 32, tabla)…`.
///
/// La tabla se escribe en **orden canónico** (por bytes de clave BLS). El certificado va tal cual
/// (`serial_certificado_peso`), ya **sin** tabla.
#[must_use]
pub fn serializar_punto_control_peso(
    tabla: &Tabla,
    certificado: &CertificadoPeso,
    cola: &[(u64, [u8; 32])],
    contenidos: &[([u8; 32], Tabla)],
) -> Vec<u8> {
    let mut ordenada = tabla.clone();
    ordenada.claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    let cert_bytes = serial_certificado_peso(certificado);
    let mut salida = Vec::new();
    salida.extend_from_slice(CABECERA_PUNTO_CONTROL_PESO);
    escribir_tabla_control(&mut salida, &ordenada);
    salida.extend_from_slice(&(cert_bytes.len() as u64).to_be_bytes());
    salida.extend_from_slice(&cert_bytes);
    salida.extend_from_slice(&(cola.len() as u64).to_be_bytes());
    for (ventana, huella) in cola {
        salida.extend_from_slice(&ventana.to_be_bytes());
        salida.extend_from_slice(huella);
    }
    salida.extend_from_slice(&(contenidos.len() as u64).to_be_bytes());
    for (huella, t) in contenidos {
        salida.extend_from_slice(huella);
        escribir_tabla_control(&mut salida, t);
    }
    salida
}

/// PD-1d · M12 · deserializa un punto de control por peso (TB-1c · N4). La tabla reconstruida
/// queda en orden canónico y sus claves públicas alineadas.
///
/// # Errores
/// Los de longitud de `zx-votos`, los de BLS y `EnteroFueraDePlataforma`.
pub fn deserializar_punto_control_peso(bytes: &[u8]) -> Result<PuntoControlPeso, ErrorVotos> {
    let mut lector = Lector { bytes, pos: 0 };
    if lector.tomar(CABECERA_PUNTO_CONTROL_PESO.len())? != &CABECERA_PUNTO_CONTROL_PESO[..] {
        return Err(ErrorVotos::CabeceraInvalida);
    }
    let (tabla, claves) = leer_tabla_control(&mut lector)?;
    let long_cert =
        usize::try_from(lector.u64()?).map_err(|_| ErrorVotos::EnteroFueraDePlataforma)?;
    let cert_bytes = lector.tomar(long_cert)?;
    let certificado = zx_votos::deserializar_certificado_peso(cert_bytes, tabla.claves.len())?;
    let n_cola = usize::try_from(lector.u64()?).map_err(|_| ErrorVotos::EnteroFueraDePlataforma)?;
    let mut cola = Vec::with_capacity(n_cola.min(1 << 16));
    for _ in 0..n_cola {
        let ventana = lector.u64()?;
        let bytes_huella = lector.tomar(LONGITUD_HASH)?;
        let mut huella = [0u8; LONGITUD_HASH];
        huella.copy_from_slice(bytes_huella);
        cola.push((ventana, huella));
    }
    let n_contenidos =
        usize::try_from(lector.u64()?).map_err(|_| ErrorVotos::EnteroFueraDePlataforma)?;
    let mut contenidos = Vec::with_capacity(n_contenidos.min(1 << 16));
    for _ in 0..n_contenidos {
        let bytes_huella = lector.tomar(LONGITUD_HASH)?;
        let mut huella = [0u8; LONGITUD_HASH];
        huella.copy_from_slice(bytes_huella);
        let (t, _pubs) = leer_tabla_control(&mut lector)?;
        contenidos.push((huella, t));
    }
    if lector.pos != bytes.len() {
        return Err(ErrorVotos::BytesSobrantes {
            sobran: bytes.len() - lector.pos,
        });
    }
    Ok(PuntoControlPeso {
        tabla,
        claves,
        certificado,
        cola,
        contenidos,
    })
}

/// PD-1d · M12 · comprueba un punto de control por peso: firma agregada y quórum del certificado
/// contra su tabla, con `verificar_firma_peso` y `evaluar_certificado`, y que cada contenido case
/// con su huella.
///
/// # Errores
/// Los de `zx-votos`; `CargaInicialInvalida` con `certificado_peso_invalido` si la evaluación falla
/// o `contenido_no_casa` si un contenido no casa con su huella.
pub fn verificar_punto_control_peso(punto: &PuntoControlPeso, b: u64) -> Result<(), ErrorVotos> {
    verificar_firma_peso(&punto.tabla, &punto.claves, &punto.certificado)?;
    let h = hash_tabla(&punto.tabla);
    // C8 · cada contenido tiene que casar con la huella con la que viaja.
    for (huella, tabla) in &punto.contenidos {
        if hash_tabla(tabla) != *huella {
            return Err(ErrorVotos::CargaInicialInvalida {
                motivo: "contenido_no_casa",
            });
        }
    }
    let mut aceptadas: Vec<[u8; 32]> = punto.cola.iter().map(|(_, huella)| *huella).collect();
    if !aceptadas.contains(&h) {
        aceptadas.push(h);
    }
    let entrada = EntradaPeso {
        b,
        genesis: true,
        n_certificado: punto.certificado.n,
        ventana: punto.certificado.n,
        tabla_vigente: &punto.tabla,
        cert_previo: None,
        tabla_comprometida: &h,
        raiz_estado: &punto.certificado.raiz_estado,
        raiz_firmada: &punto.certificado.raiz_estado,
        firma_ok: true,
        h_t_siguiente_declarada: &punto.certificado.h_t_siguiente,
        h_t_siguiente_aceptadas: &aceptadas,
        acta: false,
        mapa_bits: &punto.certificado.mapa,
    };
    let resultado = evaluar_certificado(&entrada)?;
    if !resultado.valido {
        return Err(ErrorVotos::CargaInicialInvalida {
            motivo: "certificado_peso_invalido",
        });
    }
    Ok(())
}

/// Estado de los votos que el nodo resume en el registro (`parada`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResumenVotos {
    /// Número de instancias con certificado adoptado.
    pub certificados: u64,
    /// Punto de finalidad anclado por votos, si existe.
    pub punto: Option<Hash>,
}

/// Resumen del motor para el registro de parada.
#[must_use]
pub fn resumen(motor: &MotorVotos) -> ResumenVotos {
    ResumenVotos {
        certificados: motor.certificados_adoptados,
        punto: motor.punto,
    }
}

/// Cursor de lectura acotado del sobre de voto y del punto de control.
struct Lector<'a> {
    /// Bytes de entrada.
    bytes: &'a [u8],
    /// Posición actual.
    pos: usize,
}

impl<'a> Lector<'a> {
    /// Toma exactamente `n` bytes o falla.
    fn tomar(&mut self, n: usize) -> Result<&'a [u8], ErrorVotos> {
        let fin = self.pos.checked_add(n).ok_or(ErrorVotos::Desbordamiento)?;
        let bytes: &'a [u8] = self.bytes;
        let trozo = bytes
            .get(self.pos..fin)
            .ok_or(ErrorVotos::LongitudInesperada {
                esperado: fin,
                obtenido: bytes.len(),
            })?;
        self.pos = fin;
        Ok(trozo)
    }

    /// Lee un `u64` big-endian.
    fn u64(&mut self) -> Result<u64, ErrorVotos> {
        let b = self.tomar(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// Lee un `u8`.
    fn u8(&mut self) -> Result<u8, ErrorVotos> {
        let b = self.tomar(1)?;
        b.first().copied().ok_or(ErrorVotos::LongitudInesperada {
            esperado: 1,
            obtenido: 0,
        })
    }

    /// Lee 32 bytes fijos.
    fn hash(&mut self) -> Result<Hash, ErrorVotos> {
        let b = self.tomar(32)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(b);
        Ok(h)
    }
}

#[cfg(test)]
pub(crate) mod b88;

#[cfg(test)]
mod ev1;

#[cfg(test)]
mod pruebas_rean2;

#[cfg(test)]
mod ret1b;

/// DEUDA-1 · prueba 10 — `construir_tabla` del nodo frente a `tabla_canonica` del consenso (AUD-1).
#[cfg(test)]
mod pruebas_deuda1_tabla;

#[cfg(test)]
mod pruebas_at1a;

/// FV-N6-C7 · diario, reserva y supresión (devueltas por M9-a2 al modo por peso).
#[cfg(test)]
mod pruebas_fvn6c7;

/// ECL-R2b-2 · evidencia `0x0B` del doble voto recibido por red.
#[cfg(test)]
mod pruebas_eclr2b2;

/// DFV-1 · detector de la falta entre ventanas (D1–D10).
#[cfg(test)]
mod detector_pruebas;

/// A5-c-1c · B-71/B-74 · el detector vigila solo las subredes fijadas y sigue vigilando a la clave
/// que salió de la tabla.
#[cfg(test)]
mod pruebas_detector_subredes;

/// MOT-2 · B-83/B-84 · coeficientes impredecibles en la verificación por lotes de agregados y una
/// sola comprobación de firma por voto de subred.
#[cfg(test)]
mod pruebas_mot2;

#[cfg(test)]
mod pd1d_peso;

#[cfg(test)]
mod vs2_peso;

#[cfg(test)]
mod pruebas_ra2;

/// A1-D1-2 · M1–M9 · la raíz de estado en el motor de votos: firma la que da la vista, agrupa los
/// votos por raíz y certifica la que alcanza el quórum.
#[cfg(test)]
mod pruebas_raiz;

/// A5-c-1b · la agregación de votos en el motor: una sola contabilidad por raíces, voto de red por
/// subred, recepción de agregados y publicación del propio.
#[cfg(test)]
mod pruebas_agregacion;

/// TB-1b · N1/N5 · el votante declara la última huella de `Q` del candidato, el nodo usa la
/// memoria de claves y el banco de `construir_tabla`.
#[cfg(test)]
mod tb1b;

/// TB-1c-2 · X3 (N1′) y X4 (N6): el votante sin base firma con la última de la cola y el motor
/// abandona una base provisional que la cadena no confirmó.
#[cfg(test)]
mod tb1c2;

/// TB4-R7 · el votante declara la última huella de `Q` también en el rearranque y el certificado que
/// arma el motor lo admite la cadena (TB4-R4).
#[cfg(test)]
mod tb4;

#[cfg(test)]
mod tests_b27 {
    #![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]

    use super::construir_tabla;
    use zx_consensus::sectores::{
        ClaveVoto, Etapa, ParametrosSector, PruebaVigente, RegistroSector, SectorId,
    };
    use zx_consensus::transicion::votos::{B_VOTOS, PRIMA_DISPONIBILIDAD_ACTIVA};
    use zx_consensus::transicion::{Estado, Garantia};
    use zx_core::{Amount, ClavePublica};
    use zx_votos::ClaveSecreta;
    use zx_votos::binomial::peso_efectivo;

    fn bls(indice: u8) -> ClaveSecreta {
        let mut ikm = [0u8; 32];
        ikm[0] = indice;
        ikm[31] = 0xA5;
        ClaveSecreta::generar(&ikm).expect("clave BLS de prueba")
    }

    fn ed(indice: u8) -> ClavePublica {
        ClavePublica::desde_bytes([indice; 32])
    }

    /// Estado dev con dos claves registradas, cada una con un sector activo (peso bruto 1).
    fn estado_dos_claves() -> Estado {
        let p = ParametrosSector::dev();
        let mut est = Estado::inicial();
        est.parametros_sector = p;
        for indice in [1u8, 2u8] {
            let e = ed(indice);
            est.claves_voto.insert(
                e,
                ClaveVoto {
                    clave_bls: bls(indice).clave_publica().bytes(),
                    prueba_posesion: [0u8; 96],
                },
            );
            let id = SectorId {
                clave: e,
                sector_index: 0,
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
                    renovacion_slot: 0,
                    retiro_slot: -1,
                    fianza: p.q_sec,
                    aud_apertura: -1,
                    aud_contestada: -1,
                },
            );
            let mut g = Garantia::nueva();
            g.activo = Amount::nuevo(50).expect("garantia");
            est.garantias.insert(e, g);
        }
        est
    }

    /// B-27 · una clave registra una PoSt (inerte) y otra no: construida la tabla de votos, la
    /// clave con PoSt **no** puede llevar `prueba = true` ni peso efectivo doblado. La regla es la
    /// misma que comprueba el consenso: `prueba_i = PRIMA_DISPONIBILIDAD_ACTIVA && pruebas[clave]`.
    #[test]
    fn b27_una_post_inerte_no_da_prima_en_la_tabla() {
        let mut est = estado_dos_claves();
        let clave_post = ed(1);
        est.pruebas.insert(
            clave_post,
            PruebaVigente {
                slot_prueba: 0,
                raiz_conjunto: [0; 4],
                n_sectores: 1,
            },
        );
        let (tabla, _pubs) = construir_tabla(1, &est, 0).expect("tabla de votos");
        assert_eq!(
            tabla.claves.len(),
            2,
            "las dos claves pesan (1 sector activo cada una)"
        );
        for c in &tabla.claves {
            let id = if c.clave == bls(1).clave_publica().bytes().to_vec() {
                ed(1)
            } else {
                ed(2)
            };
            assert_eq!(
                c.prueba,
                PRIMA_DISPONIBILIDAD_ACTIVA && est.pruebas.contains_key(&id),
                "B-27: la tabla del nodo aplica la misma regla que el consenso"
            );
        }
        const {
            assert!(
                !PRIMA_DISPONIBILIDAD_ACTIVA,
                "B-27: con el verificador de dev inerte la prima no puede estar activa"
            );
        }
        let bls_post = bls(1).clave_publica().bytes().to_vec();
        let con_post = tabla
            .claves
            .iter()
            .find(|c| c.clave == bls_post)
            .expect("clave con PoSt en la tabla");
        assert_eq!(
            peso_efectivo(con_post, B_VOTOS)
                .expect("peso efectivo")
                .to_string(),
            con_post.peso.to_string(),
            "sin prima, w_i = peso_i (la PoSt inerte no dobla el peso)"
        );
    }
}

/// TB-0 · pruebas del coste cuadrático de derivar la tabla de votantes (IPA B-67).
///
/// Diferencial de `pesos_por_clave` contra `fuente_peso_de` y copias literales de `999625b9` de
/// `tabla_canonica` y `construir_tabla`, sobre 500 estados aleatorios de semilla fija.
#[cfg(test)]
mod tb0 {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::integer_division,
        clippy::needless_range_loop,
        clippy::too_many_lines,
        clippy::similar_names,
        clippy::doc_markdown,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        dead_code,
        reason = "diferencial TB-0: generador determinista y fallo con panic por diseño"
    )]

    use super::construir_tabla;
    use zx_consensus::sectores::{
        ClaveVoto, Etapa, ParametrosSector, PruebaVigente, RegistroSector, SectorId,
    };
    use zx_consensus::transicion::Estado;
    use zx_consensus::transicion::sector::{fuente_peso_de, pesos_por_clave};
    use zx_consensus::transicion::votos::{PRIMA_DISPONIBILIDAD_ACTIVA, tabla_canonica};
    use zx_core::{ClavePublica as Ed25519, ClaveTablaVoto};
    use zx_votos::{
        Clave, ClavePublica, ClaveSecreta, ErrorVotos, FuenteSectores, Tabla, clave_desde_fuente,
    };

    /// Generador determinista (xorshift64*), semilla fija; sin dependencias nuevas.
    struct Azar(u64);

    impl Azar {
        fn nuevo(semilla: u64) -> Self {
            Self(semilla | 1)
        }

        fn siguiente(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn abajo(&mut self, tope: u64) -> u64 {
            self.siguiente() % tope
        }

        fn elige<T: Copy>(&mut self, opciones: &[T]) -> T {
            let tope = u64::try_from(opciones.len()).expect("longitud");
            let i = usize::try_from(self.abajo(tope)).expect("indice");
            opciones[i]
        }
    }

    /// Clave Ed25519 sintética distinta por índice.
    fn ed(i: u8) -> Ed25519 {
        Ed25519::desde_bytes([i; 32])
    }

    /// Par BLS real y distinto por índice.
    fn bls(i: u8) -> ClaveSecreta {
        let mut ikm = [0u8; 32];
        ikm[0] = i;
        ikm[31] = 0x5B;
        ClaveSecreta::generar(&ikm).expect("clave BLS de prueba")
    }

    /// Estado aleatorio con las coberturas de la orden §3.1: claves con 0, 1 y varios sectores;
    /// sectores terminales, con fianza distinta de `q_sec`, no activos y caducados; claves sin
    /// clave de voto y claves de voto sin sectores; prueba vigente y no vigente.
    fn estado_aleatorio(rng: &mut Azar, pool: &[ClaveSecreta]) -> Estado {
        let p = ParametrosSector::dev();
        let mut est = Estado::inicial();
        est.parametros_sector = p;
        let n_claves = usize::try_from(1 + rng.abajo(6)).expect("claves"); // 1..6
        for i in 0..n_claves {
            // 3 de cada 4 claves registran clave de voto; las demás quedan sin ella.
            if rng.abajo(4) != 0 {
                let e = ed(u8::try_from(i).expect("u8"));
                est.claves_voto.insert(
                    e,
                    ClaveVoto {
                        clave_bls: pool[i].clave_publica().bytes(),
                        prueba_posesion: [0u8; 96],
                    },
                );
            }
        }
        let n_sectores = rng.abajo(12);
        for _ in 0..n_sectores {
            // Incluye claves sin clave de voto (índices >= n_claves).
            let tope = u64::try_from(n_claves).expect("tope") + 2;
            let i = u8::try_from(rng.abajo(tope)).expect("clave");
            let etapa = rng.elige(&[
                Etapa::Precomprometido,
                Etapa::Activo,
                Etapa::Activo,
                Etapa::EnRetirada,
                Etapa::Retirado,
                Etapa::Caducado,
            ]);
            let fianza = rng.elige(&[
                0,
                p.q_sec / 2,
                p.q_sec,
                p.q_sec + 1,
                p.q_sec.saturating_mul(3),
            ]);
            let alta_slot = i64::try_from(rng.abajo(30)).expect("slot");
            let renovacion_slot = i64::try_from(rng.abajo(40)).expect("slot");
            let retiro_slot = if matches!(etapa, Etapa::EnRetirada | Etapa::Retirado) {
                i64::try_from(rng.abajo(40)).expect("slot")
            } else {
                -1
            };
            let aud_apertura = if rng.abajo(4) == 0 {
                i64::try_from(rng.abajo(40)).expect("slot")
            } else {
                -1
            };
            let aud_contestada = if aud_apertura >= 0 && rng.abajo(2) == 0 {
                aud_apertura + i64::try_from(rng.abajo(20)).expect("slot")
            } else {
                -1
            };
            let id = SectorId {
                clave: ed(i),
                sector_index: u16::try_from(rng.abajo(3)).expect("indice"),
                version: u32::try_from(rng.abajo(2)).expect("version"),
            };
            let reg = RegistroSector {
                id,
                r2: [0; 4],
                history_size: 1,
                etapa,
                alta_slot,
                renovacion_slot,
                retiro_slot,
                fianza,
                aud_apertura,
                aud_contestada,
            };
            est.sectores.insert(id, reg);
        }
        // Pruebas vigentes para algunas claves (con y sin prueba).
        for i in 0..=(n_claves + 1) {
            if rng.abajo(3) == 0 {
                let e = ed(u8::try_from(i).expect("u8"));
                est.pruebas.insert(
                    e,
                    PruebaVigente {
                        slot_prueba: i64::try_from(rng.abajo(200)).expect("slot"),
                        raiz_conjunto: [0; 4],
                        n_sectores: 1,
                    },
                );
            }
        }
        est.parametros_sector.exigir_prueba_almacenamiento = rng.abajo(2) == 1;
        est
    }

    /// Slots a probar por estado, con las fronteras de activación, caducidad y prueba.
    fn slots(p: &ParametrosSector, rng: &mut Azar) -> Vec<i64> {
        let mut v = vec![
            0,
            p.m_sec - 1,
            p.m_sec,
            p.m_sec + 1,
            p.p_aud,
            p.t_cad - 1,
            p.t_cad,
            p.t_cad + 1,
            p.t_gracia - 1,
            p.t_gracia,
            p.t_gracia + 1,
        ];
        for _ in 0..3 {
            v.push(i64::try_from(rng.abajo(140_000)).expect("slot"));
        }
        v
    }

    /// Todas las claves de interés: con voto, con sectores sin voto y sin nada.
    fn claves_interes(estado: &Estado) -> Vec<Ed25519> {
        let mut claves: Vec<Ed25519> = estado.claves_voto.keys().copied().collect();
        for id in estado.sectores.keys() {
            if !claves.contains(&id.clave) {
                claves.push(id.clave);
            }
        }
        claves.push(ed(200));
        claves.push(ed(201));
        claves
    }

    /// Copia literal de `tabla_canonica` de `999625b9`, conservada solo bajo `cfg(test)`.
    fn tabla_canonica_referencia(estado: &Estado, slot: i64) -> Vec<ClaveTablaVoto> {
        let mut claves: Vec<ClaveTablaVoto> = Vec::with_capacity(estado.claves_voto.len());
        for (clave_ed, clave_voto) in &estado.claves_voto {
            let peso = fuente_peso_de(estado, clave_ed, slot, &estado.parametros_sector);
            if peso <= 0 {
                continue;
            }
            let Ok(peso) = u64::try_from(peso) else {
                continue;
            };
            let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && estado.pruebas.contains_key(clave_ed);
            claves.push(ClaveTablaVoto {
                clave_bls: clave_voto.clave_bls,
                peso,
                activo: true,
                prueba,
                garantia: peso,
            });
        }
        claves
    }

    /// Copia literal de `construir_tabla` de `999625b9`, conservada solo bajo `cfg(test)`.
    fn construir_tabla_referencia(
        n: u64,
        estado: &Estado,
        slot: i64,
    ) -> Result<(Tabla, Vec<ClavePublica>), ErrorVotos> {
        let mut claves: Vec<Clave> = Vec::new();
        let mut pubs: Vec<ClavePublica> = Vec::new();
        for (clave_ed, clave_voto) in &estado.claves_voto {
            let peso = fuente_peso_de(estado, clave_ed, slot, &estado.parametros_sector);
            if peso <= 0 {
                continue;
            }
            let Ok(pk) = ClavePublica::desde_bytes(&clave_voto.clave_bls) else {
                continue;
            };
            let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && estado.pruebas.contains_key(clave_ed);
            let peso = u64::try_from(peso).map_err(|_| ErrorVotos::Desbordamiento)?;
            let clave_tabla =
                clave_desde_fuente(&clave_voto.clave_bls, true, prueba, peso, &FuenteSectores)?;
            claves.push(clave_tabla);
            pubs.push(pk);
        }
        Ok((Tabla { n, claves }, pubs))
    }

    fn pool() -> Vec<ClaveSecreta> {
        (0..8u8).map(bls).collect()
    }

    /// §3.1 · diferencial: `pesos_por_clave` coincide con `fuente_peso_de` en 500 estados.
    #[test]
    fn pesos_por_clave_coincide_con_fuente_peso_de() {
        let pool = pool();
        for semilla in 0..500u64 {
            let mut rng = Azar::nuevo(0x5A5A_0000 ^ semilla);
            let estado = estado_aleatorio(&mut rng, &pool);
            let p = estado.parametros_sector;
            let interes = claves_interes(&estado);
            for slot in slots(&p, &mut rng) {
                let pesos = pesos_por_clave(&estado, slot, &p);
                for clave in &interes {
                    assert_eq!(
                        pesos.get(clave).copied().unwrap_or(0),
                        fuente_peso_de(&estado, clave, slot, &p),
                        "semilla {semilla} slot {slot} clave {clave:?}"
                    );
                }
            }
        }
    }

    /// §3.2 · `tabla_canonica` nueva == copia literal de `999625b9`, sobre los mismos estados.
    #[test]
    fn tabla_canonica_no_cambia() {
        let pool = pool();
        for semilla in 0..500u64 {
            let mut rng = Azar::nuevo(0x5A5A_0000 ^ semilla);
            let estado = estado_aleatorio(&mut rng, &pool);
            let p = estado.parametros_sector;
            for slot in slots(&p, &mut rng) {
                assert_eq!(
                    tabla_canonica(&estado, slot),
                    tabla_canonica_referencia(&estado, slot),
                    "semilla {semilla} slot {slot}"
                );
            }
        }
    }

    /// §3.2 · `construir_tabla` nueva == copia literal de `999625b9`, sobre los mismos estados.
    #[test]
    fn construir_tabla_no_cambia() {
        let pool = pool();
        for semilla in 0..500u64 {
            let mut rng = Azar::nuevo(0x5A5A_0000 ^ semilla);
            let estado = estado_aleatorio(&mut rng, &pool);
            let p = estado.parametros_sector;
            for slot in slots(&p, &mut rng) {
                let nueva = construir_tabla(1, &estado, slot).expect("tabla nueva");
                let referencia =
                    construir_tabla_referencia(1, &estado, slot).expect("tabla referencia");
                assert_eq!(
                    nueva.0.claves, referencia.0.claves,
                    "semilla {semilla} slot {slot}"
                );
                assert_eq!(nueva.1, referencia.1, "pubs semilla {semilla} slot {slot}");
            }
        }
    }
}
