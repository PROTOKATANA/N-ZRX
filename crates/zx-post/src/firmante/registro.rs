//! Registro persistente de oportunidades: `(huella, slot) -> pre_hash`.
//!
//! Es la pieza que hace que el firmante local sirva de algo: **persistir antes de firmar**, de
//! forma atómica y duradera. Un `Vec` en memoria, o un `write` sin `sync_all`, reproducen
//! exactamente el accidente que se quiere evitar —corte de energía entre la firma y el apunte—.
//!
//! # Frontera
//!
//! Este registro es **política local del productor**: ningún verificador DAG puede consultarlo ni
//! rechazar un bloque remoto porque falte. No entra en ningún `pre_hash`, no viaja por el wire y no
//! fija ningún parámetro de consenso: `s_max_slots` entra como argumento del perfil (FIR-10).
//!
//! # Formato (versión 3)
//!
//! Un fichero por registro, solo-anexar, con cabecera de 56 bytes y entradas de 80:
//!
//! ```text
//! cabecera (56 B)
//!   0..8    magia "ZXRGFIRM"
//!   8..16   versión de formato (u64 LE) = 3
//!   16..24  slot_perdida: slot del alta conservadora (u64 LE)
//!   24..32  abstener_hasta: último slot de la ventana de abstención (u64 LE)
//!   32..40  abstencion_activa (u64 LE: 0 o 1)
//!   40..56  comprobación = SHA3-256(cabecera[0..40])[0..16]
//! entrada (80 B)
//!   0..8    slot (u64 LE)
//!   8..40   huella de la identidad de oportunidad (32 B)
//!   40..72  pre_hash (32 B)
//!   72..80  comprobación = SHA3-256(entrada[0..72])[0..8]
//! ```
//!
//! La versión 2 guardaba la abstención en una cabecera de 40 B **sin integridad**: cambiar la
//! bandera de 1 a 0 o acortar el horizonte borraba la abstención sin entrada alguna. La versión 3
//! añade el checksum de cabecera y **no se migra** desde 1/2: un fichero de versión desconocida
//! falla cerrado ([`RegistroError::VersionInvalida`]).
//!
//! La cabecera es **inmutable tras crearse** (no hay poda en 0.0.1): el slot de pérdida, el
//! horizonte y la bandera se escriben una vez. La abstención se decide con `slot <= horizonte` para
//! siempre, y `max_slot` se deriva en memoria del slot de pérdida y las entradas validadas. Así no
//! hay ninguna reescritura en sitio que un corte a mitad de `append` pueda romper.
//!
//! # Qué garantiza y qué no
//!
//! - **Durabilidad**: [`Registro::resolver`] escribe la entrada y llama a `sync_all` **antes** de
//!   devolver `Ok`. Si devuelve `Ok`, la entrada está en disco; si falla, el índice en memoria no
//!   cambia y el firmante no firma.
//! - **Exclusión entre procesos**: `File::try_lock` (bloqueo exclusivo de fichero) durante toda la
//!   vida del [`Registro`]. Un segundo proceso recibe [`RegistroError::Bloqueado`].
//! - **Exclusión entre hilos**: `Mutex` alrededor del estado.
//! - **Envenenamiento**: cualquier fallo ambiguo de escritura o de `sync_all` deja la instancia
//!   envenenada. Toda llamada posterior a [`Registro::resolver`] —la única que puede autorizar una
//!   firma— devuelve [`RegistroError::Envenenado`] hasta cerrar y reabrir, momento en que la
//!   recuperación relee el log. Las consultas de solo lectura no firman.
//! - **Recuperación**: al reabrir un fichero existente se valida **entero** y se **sincroniza**
//!   antes de devolver el [`Registro`]. Un fallo de esa sincronización devuelve error y no crea
//!   instancia utilizable: no basta con releer una entrada que quizá solo estaba en caché.
//! - **NO** cubre: dos procesos con registros distintos, un atacante que borre el fichero, ni un
//!   `sync_all` que mienta (p. ej. un sistema de ficheros en red). Es un filtro de accidentes
//!   honestos, no un mecanismo de seguridad.
//! - **NO** guarda claves privadas: solo huellas de identidad y `pre_hash`.
//! - **NO** implementa poda durante 0.0.1: el log solo crece. Reescribir en sitio podía dejar un
//!   log válido pero incompleto tras un corte, así que no se porta esa operación (FIR-09).

use std::collections::HashMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zx_core::PreHash;

use super::identidad::{IdentidadTicket, LONGITUD_HUELLA};

/// Magia del fichero. Ocho bytes, sin ceros, para que un fichero vacío o de basura no se confunda.
pub const MAGIA: [u8; 8] = *b"ZXRGFIRM";

/// Versión del formato de fichero. La 3 añade el checksum de cabecera a la abstención durable.
pub const VERSION_FORMATO: u64 = 3;

/// Longitud de la cabecera, en bytes.
pub const TAMANO_CABECERA: u64 = 56;

/// Longitud de la parte **firmada** de la cabecera: los campos que cubre el checksum.
const TAMANO_CABECERA_FIRMADA: usize = 40;

/// Longitud del checksum de cabecera, en bytes.
const TAMANO_COMPROBACION_CABECERA: usize = 16;

/// Longitud de una entrada, en bytes.
pub const TAMANO_ENTRADA: u64 = 80;

/// Offset de `slot_perdida` dentro de la cabecera.
pub const OFFSET_SLOT_PERDIDA: usize = 16;

/// Offset de `abstener_hasta` dentro de la cabecera.
pub const OFFSET_ABSTENER_HASTA: usize = 24;

/// Offset de la bandera de abstención dentro de la cabecera.
pub const OFFSET_ABSTENCION_ACTIVA: usize = 32;

/// Offset del checksum de la cabecera dentro de la cabecera.
pub const OFFSET_COMPROBACION_CABECERA: usize = 40;

/// Offset del campo de comprobación dentro de la entrada.
const OFFSET_COMPROBACION: usize = 72;

/// Longitud del campo de comprobación de una entrada.
const TAMANO_COMPROBACION: usize = 8;

/// Offset de la huella dentro de la entrada.
const OFFSET_HUELLA: usize = 8;

/// Offset del `pre_hash` dentro de la entrada.
const OFFSET_PRE_HASH: usize = 40;

/// Lo que el registro sabe de una oportunidad.
///
/// Es un tipo interno: la única ruta que lo consume es [`crate::firmante::Firmante::firmar`], que
/// traduce el resultado a [`crate::firmante::Resultado`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Resolucion {
    /// No había entrada: se escribió, se sincronizó y **ahora** se puede firmar.
    Nueva,
    /// Ya había entrada con el **mismo** `pre_hash`: es el mismo bloque. Se puede reemitir.
    Conocida,
    /// Ya había entrada con **otro** `pre_hash`: no se firma y el candidato se descarta.
    Conflicto {
        /// El `pre_hash` que ya estaba registrado.
        pre_hash_registrado: PreHash,
    },
}

/// Fallos del registro. Todos son **motivo para no firmar**.
#[derive(Debug, thiserror::Error)]
pub enum RegistroError {
    /// El fichero no se pudo abrir, crear, leer o sincronizar.
    #[error("registro: E/S en {ruta}: {origen}")]
    Io {
        /// Ruta del registro.
        ruta: PathBuf,
        /// Error de E/S subyacente.
        #[source]
        origen: std::io::Error,
    },

    /// Otro proceso tiene el registro bloqueado. No se escribe nada.
    #[error("registro: {ruta} está bloqueado por otro proceso")]
    Bloqueado {
        /// Ruta del registro.
        ruta: PathBuf,
    },

    /// El fichero no empieza por la magia esperada.
    #[error("registro: {ruta} no es un registro del firmante (magia inesperada)")]
    MagiaInvalida {
        /// Ruta del registro.
        ruta: PathBuf,
    },

    /// El fichero declara una versión de formato que este binario no sabe leer.
    #[error("registro: {ruta} declara versión de formato {encontrada}, esperada {esperada}")]
    VersionInvalida {
        /// Ruta del registro.
        ruta: PathBuf,
        /// Versión encontrada.
        encontrada: u64,
        /// Versión que este binario escribe.
        esperada: u64,
    },

    /// Una entrada **completa** con comprobación inválida. **No se trunca**, ni aunque la entrada
    /// sea toda cero ni aunque esté al final: olvidar una entrada es la única forma de
    /// doble-firmar, así que se falla cerrado y el operador decide.
    #[error(
        "registro: {ruta} corrupto en el byte {offset} (entrada completa con comprobación inválida)"
    )]
    Corrupto {
        /// Ruta del registro.
        ruta: PathBuf,
        /// Offset del primer byte de la entrada inválida.
        offset: u64,
        /// Bytes desde `offset` hasta el final del fichero.
        bytes_perdidos: u64,
    },

    /// La cabecera no supera su comprobación de integridad.
    ///
    /// Un bit cambiado en la bandera, en el horizonte o en el slot de pérdida la invalida. Falla
    /// cerrado: una abstención no se puede borrar editando el fichero.
    #[error("registro: {ruta} tiene la cabecera corrupta (comprobación SHA3-256 inválida)")]
    CabeceraCorrupta {
        /// Ruta del registro.
        ruta: PathBuf,
    },

    /// El fichero termina en una cola parcial (< 80 B).
    ///
    /// Esa cola no lleva marca de comprobación que demuestre que la entrada llegó a ser durable,
    /// así que no se trunca: falla cerrado (FIR-08).
    #[error("registro: {ruta} termina en una cola parcial de {bytes} bytes en el offset {offset}")]
    ColaParcial {
        /// Ruta del registro.
        ruta: PathBuf,
        /// Offset donde empieza la cola parcial.
        offset: u64,
        /// Bytes de la cola parcial (menos de una entrada).
        bytes: u64,
    },

    /// Una entrada completa aparece dos veces con el mismo índice y **distinto** `pre_hash`.
    ///
    /// Rechaza el fichero: elegir por orden de llegada es exactamente lo que el registro existe
    /// para no hacer.
    #[error(
        "registro: {ruta} repite la misma oportunidad con dos pre_hash distintos (slot {slot})"
    )]
    DuplicadoConflictivo {
        /// Ruta del registro.
        ruta: PathBuf,
        /// Slot de la oportunidad repetida.
        slot: u64,
    },

    /// Un tamaño o desplazamiento del fichero no cabe en `u64`. Se falla cerrado en vez de
    /// saturar, porque ese número podría autorizar una firma.
    #[error("registro: {ruta} tiene un tamaño o desplazamiento no representable")]
    TamanoNoRepresentable {
        /// Ruta del registro.
        ruta: PathBuf,
    },

    /// El registro está en su ventana de abstención: perdió el estado y aún no puede firmar.
    ///
    /// El firmante lo traduce a [`crate::firmante::Resultado::AbstenidoPorPerdida`], que es un
    /// resultado distinguible de un error de E/S.
    #[error(
        "registro: abstinencia por pérdida; slot actual {slot_actual} ≤ {hasta} (S_max_slots = {s_max_slots})"
    )]
    EnAbstinencia {
        /// Slot actual de la consulta.
        slot_actual: u64,
        /// Último slot en el que todavía se abstiene (`slot_perdida + s_max_slots`).
        hasta: u64,
        /// `s_max_slots` vigente en esta instancia.
        s_max_slots: u64,
    },

    /// La instancia quedó envenenada por un fallo ambiguo de persistencia.
    ///
    /// Toda llamada posterior a [`Registro::resolver`] falla cerrado hasta cerrar y reabrir el
    /// registro, momento en que la recuperación relee el log (FIR-07).
    #[error("registro: {ruta} envenenado por un fallo de persistencia; hay que reabrir")]
    Envenenado {
        /// Ruta del registro.
        ruta: PathBuf,
    },
}

/// Clave del índice en memoria: la huella de la identidad (`RAT-1`) y el slot.
type Clave = ([u8; LONGITUD_HUELLA], u64);

/// Índice en memoria del registro.
type Indice = HashMap<Clave, PreHash>;

/// Punto de inyección de fallo de E/S, **solo para tests**.
///
/// En producción es un tipo vacío y la rama que lo consulta no existe: no hay ninguna ruta que
/// convierta un `Ok` falso en real.
#[derive(Debug, Default)]
struct InyeccionSync {
    /// Fuerza que la siguiente sincronización falle.
    #[cfg(test)]
    falla_sync: bool,
    /// Cuántas sincronizaciones reales se han pedido. Permite comprobar que la recuperación
    /// sincroniza el fichero y no se limita a releerlo.
    #[cfg(test)]
    syncs: std::sync::atomic::AtomicU32,
}

/// Estado mutable protegido por el mutex.
#[derive(Debug)]
struct Estado {
    fichero: File,
    ruta: PathBuf,
    /// Índice en memoria: `(huella, slot) -> pre_hash`. Se actualiza **solo** tras un `sync_all`
    /// correcto.
    indice: Indice,
    /// Mayor slot conocido por el registro: el de pérdida de la cabecera o el mayor de las
    /// entradas validadas, el que sea mayor. Se deriva en memoria; la cabecera no se reescribe.
    max_slot: u64,
    /// Último slot en el que todavía se abstiene, si [`Estado::abstencion_activa`].
    abstener_hasta: u64,
    /// ¿Está activa la abstención por pérdida de estado? La cabecera es inmutable, así que esta
    /// bandera no se limpia al anexar: pasado el horizonte no impide firmar.
    abstencion_activa: bool,
    /// Número de entradas vivas en el índice.
    entradas: u64,
    /// `s_max_slots` con el que se abrió. La ruta [`Registro::nueva`] lo deja a 0 porque no se
    /// abstiene nunca.
    s_max_slots: u64,
    /// La instancia dejó de ser fiable tras un fallo ambiguo de persistencia.
    envenenado: bool,
    /// Inyección de fallo de sincronización, solo para tests.
    inyeccion: InyeccionSync,
}

impl Estado {
    /// Último slot en el que este registro todavía se abstiene.
    ///
    /// Un bloque para el slot `s` solo puede aparecer mientras `slot(B) − slot(sp(B)) ≤ S_max`
    /// (`C-GD-04`), así que pasado `s + S_max` ningún bloque nuevo puede reclamar `s`. La
    /// abstención se decide con `slot <= horizonte`: para slots posteriores la cabecera ya no
    /// impide firmar aunque la bandera siga activa. Devuelve `None` cuando no hay abstención
    /// declarada (registro de test sin pérdida, o cabecera con la bandera a 0).
    fn abstencion_hasta(&self) -> Option<u64> {
        if self.abstencion_activa {
            Some(self.abstener_hasta)
        } else {
            None
        }
    }

    /// Escribe una entrada nueva y **solo después** actualiza el índice en memoria.
    ///
    /// Cualquier fallo deja el estado envenenado: no se puede saber si la escritura llegó a disco,
    /// y esa duda es exactamente lo que prohíbe firmar.
    fn escribir_entrada(
        &mut self,
        slot: u64,
        huella: &[u8; LONGITUD_HUELLA],
        pre_hash: PreHash,
    ) -> Result<(), RegistroError> {
        let ruta = self.ruta.clone();
        let bytes = entrada_bytes(slot, huella, pre_hash);

        // Solo-anexar: la posición de escritura se calcula desde el tamaño lógico del fichero. El
        // desplazamiento tiene que ser exacto; si no lo es, el fichero no está íntegro.
        let fin = match self.fichero.seek(SeekFrom::End(0)) {
            Ok(fin) => fin,
            Err(origen) => {
                self.envenenado = true;
                return Err(io_err(&ruta, origen));
            }
        };
        if fin < TAMANO_CABECERA || !(fin - TAMANO_CABECERA).is_multiple_of(TAMANO_ENTRADA) {
            self.envenenado = true;
            return Err(RegistroError::Corrupto {
                ruta,
                offset: fin,
                bytes_perdidos: 0,
            });
        }

        if let Err(origen) = self.fichero.write_all(&bytes) {
            self.envenenado = true;
            return Err(io_err(&ruta, origen));
        }
        if let Err(fallo) = sincronizar(&self.fichero, &ruta, &self.inyeccion) {
            self.envenenado = true;
            return Err(fallo);
        }

        // A partir de aquí la entrada está en disco. El índice en memoria se actualiza después.
        self.indice.insert((*huella, slot), pre_hash);
        match a_u64(self.indice.len(), &ruta) {
            Ok(n) => self.entradas = n,
            Err(fallo) => {
                self.envenenado = true;
                return Err(fallo);
            }
        }

        // La cabecera es inmutable tras crearse: no se reescribe al anexar. La abstención se sigue
        // decidiendo con `slot <= horizonte` y `max_slot` vive solo en memoria, así que un corte a
        // mitad de un `append` ya no puede romper la cabecera.
        self.max_slot = self.max_slot.max(slot);
        Ok(())
    }
}

/// El registro persistente.
///
/// Se comparte entre hilos con `&Registro` (lleva su propio `Mutex`); ver
/// [`crate::firmante::Firmante`].
#[derive(Debug)]
pub struct Registro {
    estado: Mutex<Estado>,
}

impl Registro {
    /// Abre el registro de `ruta`, creándolo si no existe.
    ///
    /// Si el fichero **no existe**, se crea en abstención: el registro no sabe qué firmó antes de
    /// existir, así que se ancla al `slot_actual` y no firma hasta pasado
    /// `slot_actual + s_max_slots`. Es la ruta segura para una clave que **ya existía** y perdió su
    /// estado (FIR-10/FIR-11). Para una identidad genuinamente nueva, la ruta es
    /// [`Registro::nueva`].
    ///
    /// `s_max_slots` es un valor **explícito del perfil**; este módulo no fija ninguna constante
    /// de consenso.
    ///
    /// # Errores
    /// [`RegistroError::Bloqueado`] si otro proceso lo tiene abierto;
    /// [`RegistroError::VersionInvalida`] si la versión de formato es desconocida (1 y 2 incluidas:
    /// no se migran en silencio); [`RegistroError::CabeceraCorrupta`] si el checksum de la cabecera
    /// no cuadra; [`RegistroError::Corrupto`], [`RegistroError::ColaParcial`] o
    /// [`RegistroError::DuplicadoConflictivo`] si el log no es íntegro; [`RegistroError::Io`] para
    /// el resto de fallos de E/S, incluida la imposibilidad de sincronizar el fichero recuperado o
    /// el directorio padre.
    pub fn abrir(
        ruta: impl AsRef<Path>,
        slot_actual: u64,
        s_max_slots: u64,
    ) -> Result<Self, RegistroError> {
        Self::abrir_con_politica(
            ruta,
            slot_actual,
            s_max_slots,
            true,
            InyeccionSync::default(),
        )
    }

    /// Implementación común de [`Registro::abrir`] y de la ruta sin abstención que solo usan los
    /// tests del crate (`abstener_si_nuevo = false`).
    ///
    /// No hay una ruta pública de «registro nuevo sin historia» aleatoria: la única ruta sin
    /// abstención y con historia es [`Registro::nueva`], que exige que el fichero **no** exista y
    /// la usa el aprovisionamiento de una identidad nueva.
    fn abrir_con_politica(
        ruta: impl AsRef<Path>,
        slot_actual: u64,
        s_max_slots: u64,
        abstener_si_nuevo: bool,
        inyeccion: InyeccionSync,
    ) -> Result<Self, RegistroError> {
        let ruta = ruta.as_ref().to_path_buf();
        let mut fichero = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&ruta)
            .map_err(|origen| io_err(&ruta, origen))?;

        // `try_lock` toma el bloqueo exclusivo del fichero durante toda la vida del `Registro`.
        // `File` se abre con `O_CLOEXEC` en Unix, así que el cerrojo no sobrevive a un `exec`.
        bloquear(&fichero, &ruta)?;

        let len = fichero
            .metadata()
            .map_err(|origen| io_err(&ruta, origen))?
            .len();

        let (indice, max_slot, abstener_hasta, abstencion_activa) = if len == 0 {
            // Fichero recién creado: cabecera. Sin historia, la única alta segura es abstenerse.
            let slot_perdida = if abstener_si_nuevo { slot_actual } else { 0 };
            let activa = abstener_si_nuevo;
            // Un horizonte que desborda `u64` se satura a `u64::MAX` **a propósito**: sigue
            // absteniéndose para siempre, que es la decisión segura. No es un tamaño de fichero ni
            // un desplazamiento, así que la saturación no puede autorizar una firma.
            let hasta = if activa {
                slot_actual.saturating_add(s_max_slots)
            } else {
                0
            };
            let cabecera = cabecera_bytes(slot_perdida, hasta, activa);
            fichero
                .write_all(&cabecera)
                .and_then(|()| fichero.sync_all())
                .map_err(|origen| io_err(&ruta, origen))?;
            // La creación del fichero también tiene que ser durable: se sincroniza el directorio
            // padre cuando el sistema lo permite; si no, se falla cerrado.
            sincronizar_directorio(&ruta)?;
            (HashMap::new(), slot_perdida, hasta, activa)
        } else {
            let recuperado = recuperar(&mut fichero, &ruta)?;
            // El fichero validado se sincroniza **antes** de devolver el registro. Un `write_all`
            // anterior pudo llegar solo a la caché y que su `sync_all` fallara; releerlo no
            // demuestra que sea durable, y una reemisión sin esa garantía es justo lo que el
            // registro existe para impedir. Un fallo aquí devuelve error: no hay instancia.
            sincronizar(&fichero, &ruta, &inyeccion)?;
            (
                recuperado.indice,
                recuperado.max_slot,
                recuperado.abstener_hasta,
                recuperado.abstencion_activa,
            )
        };

        let entradas = a_u64(indice.len(), &ruta)?;
        Ok(Self {
            estado: Mutex::new(Estado {
                fichero,
                ruta,
                indice,
                max_slot,
                abstener_hasta,
                abstencion_activa,
                entradas,
                s_max_slots,
                envenenado: false,
                inyeccion,
            }),
        })
    }

    /// Crea un registro **inicialmente limpio** para una identidad nueva: cabecera v3 con
    /// `slot_perdida = 0`, `abstener_hasta = 0` y `abstencion_activa = false`, sin abstención.
    ///
    /// # Uso restringido al alta local
    ///
    /// Esta función **no** es la ruta de una pérdida de registro y no debe usarse como tal: un
    /// registro sin historia solo es legítimo si la clave que va a firmar se generó en la misma
    /// operación de aprovisionamiento y no ha firmado nunca (FIR-12). Tras una pérdida, la única
    /// entrada es [`Registro::abrir`], que se abstiene `s_max_slots`.
    ///
    /// A diferencia de [`Registro::abrir`], aquí el fichero se abre con `create_new(true)`: si ya
    /// existe un fichero —aunque esté vacío— la llamada falla y **no** se sobrescribe ni se
    /// interpreta como un alta nueva. Toma el mismo bloqueo exclusivo y escribe la misma cabecera
    /// v3, con `sync_all` del fichero y del directorio padre antes de devolver.
    ///
    /// No recibe `s_max_slots` (DF-2): esta ruta no se abstiene nunca, así que el perfil es inerte
    /// aquí y la instancia guarda 0. El horizonte de abstención de una pérdida lo fija
    /// [`Registro::abrir`], que es la única ruta que sí lo necesita (FIR-10).
    ///
    /// # Errores
    /// [`RegistroError::Io`] si el fichero ya existe, si falla la apertura, la escritura o
    /// cualquiera de las dos sincronizaciones; [`RegistroError::Bloqueado`] si otro proceso lo
    /// tiene abierto.
    pub fn nueva(ruta: impl AsRef<Path>) -> Result<Self, RegistroError> {
        let ruta = ruta.as_ref().to_path_buf();
        let mut fichero = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&ruta)
            .map_err(|origen| io_err(&ruta, origen))?;

        // El mismo bloqueo exclusivo que `abrir`, antes de escribir nada.
        bloquear(&fichero, &ruta)?;

        // La misma cabecera v3, pero sin historia: no hay firma previa que perder.
        let cabecera = cabecera_bytes(0, 0, false);
        fichero
            .write_all(&cabecera)
            .and_then(|()| fichero.sync_all())
            .map_err(|origen| io_err(&ruta, origen))?;
        sincronizar_directorio(&ruta)?;

        Ok(Self {
            estado: Mutex::new(Estado {
                fichero,
                ruta,
                indice: HashMap::new(),
                max_slot: 0,
                abstener_hasta: 0,
                abstencion_activa: false,
                entradas: 0,
                s_max_slots: 0,
                envenenado: false,
                inyeccion: InyeccionSync::default(),
            }),
        })
    }

    /// Consulta y, si procede, **persiste antes de devolver**.
    ///
    /// Es la única operación de escritura que el firmante usa, y es atómica respecto de la clave:
    /// mira, decide, escribe y sincroniza bajo el mismo cerrojo.
    ///
    /// - Sin entrada: escribe `(huella, slot) -> pre_hash`, sincroniza y devuelve
    ///   [`Resolucion::Nueva`]. **Solo entonces** el llamante puede firmar.
    /// - Con entrada y el mismo `pre_hash`: [`Resolucion::Conocida`], sin escritura.
    /// - Con entrada y otro `pre_hash`: [`Resolucion::Conflicto`], **sin escritura**.
    ///
    /// # Errores
    /// [`RegistroError::EnAbstinencia`] si el registro perdió el estado y aún no puede firmar (el
    /// firmante lo convierte en un resultado, no en error); [`RegistroError::Envenenado`] si una
    /// persistencia anterior quedó en duda; [`RegistroError::Io`] si la escritura o la
    /// sincronización fallan (y entonces el índice en memoria no cambia y la instancia queda
    /// envenenada).
    pub(crate) fn resolver(
        &self,
        identidad: &IdentidadTicket,
        pre_hash: PreHash,
    ) -> Result<Resolucion, RegistroError> {
        let mut estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        if estado.envenenado {
            return Err(RegistroError::Envenenado {
                ruta: estado.ruta.clone(),
            });
        }

        let slot = identidad.slot();
        let huella = identidad.huella();

        // La abstención va primero: si el registro no es de fiar, no se escribe ni se firma.
        if let Some(hasta) = estado.abstencion_hasta()
            && slot <= hasta
        {
            return Err(RegistroError::EnAbstinencia {
                slot_actual: slot,
                hasta,
                s_max_slots: estado.s_max_slots,
            });
        }

        if let Some(registrado) = estado.indice.get(&(huella, slot)).copied() {
            if registrado == pre_hash {
                return Ok(Resolucion::Conocida);
            }
            return Ok(Resolucion::Conflicto {
                pre_hash_registrado: registrado,
            });
        }

        // Camino de escritura: entrada nueva. Se persiste y se sincroniza ANTES de devolver.
        estado.escribir_entrada(slot, &huella, pre_hash)?;
        Ok(Resolucion::Nueva)
    }

    /// ¿Está el registro en abstención para `slot`?
    #[must_use]
    pub fn en_abstinencia(&self, slot: u64) -> bool {
        let estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        estado.abstencion_hasta().is_some_and(|hasta| slot <= hasta)
    }

    /// Horizonte **histórico** de la abstención, si la cabecera la declara activa.
    ///
    /// Puede devolver un horizonte ya pasado: la cabecera es inmutable y no se limpia al anexar.
    /// La respuesta para un slot concreto es [`Registro::en_abstinencia`], que compara
    /// `slot <= horizonte`.
    #[must_use]
    pub fn abstener_hasta(&self) -> Option<u64> {
        self.estado
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abstencion_hasta()
    }

    /// El mayor slot conocido: el de pérdida de la cabecera o el mayor de las entradas.
    #[must_use]
    pub fn max_slot(&self) -> u64 {
        self.estado
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .max_slot
    }

    /// Número de entradas vivas en el índice.
    #[must_use]
    pub fn entradas(&self) -> u64 {
        self.estado
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entradas
    }

    /// La ruta del fichero.
    #[must_use]
    pub fn ruta(&self) -> PathBuf {
        self.estado
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ruta
            .clone()
    }

    /// Tamaño del fichero en bytes.
    ///
    /// # Errores
    /// [`RegistroError::Io`] si el `metadata` falla.
    pub fn tamano_bytes(&self) -> Result<u64, RegistroError> {
        let estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        estado
            .fichero
            .metadata()
            .map(|m| m.len())
            .map_err(|origen| io_err(&estado.ruta, origen))
    }

    /// Fuerza el envenenamiento de la instancia, **solo para tests**.
    ///
    /// Permite cubrir `FirmanteError::Registro(Envenenado)` sin depender de un fallo de E/S real.
    /// No existe en builds de producción.
    #[cfg(test)]
    pub(crate) fn forzar_envenenamiento_para_test(&self) {
        self.estado
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .envenenado = true;
    }
}

/// Cabecera de formato 3: 56 bytes, con checksum sobre los 40 primeros.
fn cabecera_bytes(
    slot_perdida: u64,
    abstener_hasta: u64,
    abstencion_activa: bool,
) -> [u8; TAMANO_CABECERA as usize] {
    let mut firmada = Vec::with_capacity(TAMANO_CABECERA_FIRMADA);
    firmada.extend_from_slice(&MAGIA);
    firmada.extend_from_slice(&VERSION_FORMATO.to_le_bytes());
    firmada.extend_from_slice(&slot_perdida.to_le_bytes());
    firmada.extend_from_slice(&abstener_hasta.to_le_bytes());
    firmada.extend_from_slice(&u64::from(abstencion_activa).to_le_bytes());

    let comprobacion = comprobacion_cabecera(&firmada);
    firmada.extend_from_slice(&comprobacion);

    let mut cabecera = [0u8; TAMANO_CABECERA as usize];
    if let Some(destino) = cabecera.get_mut(..) {
        destino.copy_from_slice(&firmada);
    }
    cabecera
}

/// Comprobación de integridad de la cabecera: `SHA3-256(cabecera[0..40])[0..16]`.
fn comprobacion_cabecera(firmada: &[u8]) -> [u8; TAMANO_COMPROBACION_CABECERA] {
    let d = zx_core::sha3_256_publico(firmada.get(..TAMANO_CABECERA_FIRMADA).unwrap_or(&[]));
    let mut comprobacion = [0u8; TAMANO_COMPROBACION_CABECERA];
    if let (Some(destino), Some(origen)) = (
        comprobacion.get_mut(..),
        d.as_bytes().get(..TAMANO_COMPROBACION_CABECERA),
    ) {
        destino.copy_from_slice(origen);
    }
    comprobacion
}

/// Comprobación de integridad de una entrada: `SHA3-256(entrada[0..72])[0..8]`.
fn comprobacion(entrada: &[u8]) -> [u8; TAMANO_COMPROBACION] {
    let d = zx_core::sha3_256_publico(entrada.get(..OFFSET_COMPROBACION).unwrap_or(&[]));
    let mut comprobacion = [0u8; TAMANO_COMPROBACION];
    if let (Some(destino), Some(origen)) = (
        comprobacion.get_mut(..),
        d.as_bytes().get(..TAMANO_COMPROBACION),
    ) {
        destino.copy_from_slice(origen);
    }
    comprobacion
}

/// Serializa una entrada.
fn entrada_bytes(slot: u64, huella: &[u8; LONGITUD_HUELLA], pre_hash: PreHash) -> [u8; 80] {
    let mut entrada = Vec::with_capacity(TAMANO_ENTRADA as usize);
    entrada.extend_from_slice(&slot.to_le_bytes());
    entrada.extend_from_slice(huella);
    entrada.extend_from_slice(pre_hash.as_bytes());
    let comprobacion = comprobacion(&entrada);
    entrada.extend_from_slice(&comprobacion);

    let mut salida = [0u8; 80];
    if let Some(destino) = salida.get_mut(..) {
        destino.copy_from_slice(&entrada);
    }
    salida
}

/// Lo recuperado de un fichero existente.
#[derive(Debug)]
struct Recuperado {
    indice: Indice,
    max_slot: u64,
    abstener_hasta: u64,
    abstencion_activa: bool,
}

/// Recupera el índice y la cabecera. **No trunca nada**: falla cerrado (FIR-08).
///
/// - La cabecera debe medir 56 B, empezar por la magia, declarar la versión 3 y superar su
///   checksum. Cualquier discordancia rechaza el fichero antes de construir estado.
/// - Toda entrada **completa** (80 B) con comprobación inválida rechaza el fichero, aunque sea
///   toda cero y aunque esté al final: truncarla olvidaría una firma previa si hubo corrupción.
/// - Una cola **parcial** (< 80 B) no lleva marca que demuestre que fuera durable: también rechaza.
/// - Dos entradas completas con el mismo `(huella, slot)` y distinto `pre_hash` rechazan el
///   fichero: nunca se elige por orden de llegada.
fn recuperar(fichero: &mut File, ruta: &Path) -> Result<Recuperado, RegistroError> {
    let mut todo = Vec::new();
    fichero
        .seek(SeekFrom::Start(0))
        .and_then(|_| fichero.read_to_end(&mut todo))
        .map_err(|origen| io_err(ruta, origen))?;

    let cabecera = match todo.get(..TAMANO_CABECERA as usize) {
        Some(cabecera) => cabecera,
        None => {
            return Err(RegistroError::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: 0,
                bytes_perdidos: a_u64(todo.len(), ruta)?,
            });
        }
    };
    if cabecera.get(..8) != Some(MAGIA.as_slice()) {
        return Err(RegistroError::MagiaInvalida {
            ruta: ruta.to_path_buf(),
        });
    }
    let version = leer_u64(cabecera.get(8..16), ruta)?;
    if version != VERSION_FORMATO {
        // No se migran formatos 1/2 en silencio: la 2 no tenía integridad de cabecera.
        return Err(RegistroError::VersionInvalida {
            ruta: ruta.to_path_buf(),
            encontrada: version,
            esperada: VERSION_FORMATO,
        });
    }

    // Integridad de la cabecera antes de mirar ningún campo: la bandera y el horizonte no se
    // pueden editar sin que el checksum deje de cuadrar.
    let firmada = cabecera.get(..TAMANO_CABECERA_FIRMADA).unwrap_or(&[][..]);
    let esperado = comprobacion_cabecera(firmada);
    if cabecera.get(OFFSET_COMPROBACION_CABECERA..TAMANO_CABECERA as usize)
        != Some(esperado.as_slice())
    {
        return Err(RegistroError::CabeceraCorrupta {
            ruta: ruta.to_path_buf(),
        });
    }

    let slot_perdida = leer_u64(
        cabecera.get(OFFSET_SLOT_PERDIDA..OFFSET_SLOT_PERDIDA + 8),
        ruta,
    )?;
    let abstener_hasta = leer_u64(
        cabecera.get(OFFSET_ABSTENER_HASTA..OFFSET_ABSTENER_HASTA + 8),
        ruta,
    )?;
    let bandera = leer_u64(
        cabecera.get(OFFSET_ABSTENCION_ACTIVA..OFFSET_ABSTENCION_ACTIVA + 8),
        ruta,
    )?;
    let abstencion_activa = match bandera {
        0 => false,
        1 => true,
        _ => {
            return Err(RegistroError::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: OFFSET_ABSTENCION_ACTIVA as u64,
                bytes_perdidos: 0,
            });
        }
    };

    let mut indice = HashMap::new();
    let mut max_slot = slot_perdida;
    let mut offset = TAMANO_CABECERA as usize;
    while offset + TAMANO_ENTRADA as usize <= todo.len() {
        let entrada = match todo.get(offset..offset + TAMANO_ENTRADA as usize) {
            Some(entrada) => entrada,
            None => break,
        };
        let c = comprobacion(entrada);
        if entrada.get(OFFSET_COMPROBACION..) != Some(c.as_slice()) {
            // Entrada completa con comprobación inválida: no se trunca, ni aunque sea cero.
            return Err(RegistroError::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset, ruta)?,
                bytes_perdidos: a_u64(todo.len() - offset, ruta)?,
            });
        }
        let slot = leer_u64(entrada.get(0..8), ruta)?;
        let mut huella = [0u8; LONGITUD_HUELLA];
        if let Some(h) = entrada.get(OFFSET_HUELLA..OFFSET_HUELLA + LONGITUD_HUELLA) {
            huella.copy_from_slice(h);
        }
        let mut bytes_pre_hash = [0u8; 32];
        if let Some(p) = entrada.get(OFFSET_PRE_HASH..OFFSET_PRE_HASH + 32) {
            bytes_pre_hash.copy_from_slice(p);
        }
        let pre_hash = PreHash::from_digest(zx_core::Digest::from_bytes(bytes_pre_hash));
        match indice.entry((huella, slot)) {
            std::collections::hash_map::Entry::Occupied(ya) => {
                if ya.get() != &pre_hash {
                    return Err(RegistroError::DuplicadoConflictivo {
                        ruta: ruta.to_path_buf(),
                        slot,
                    });
                }
            }
            std::collections::hash_map::Entry::Vacant(hueco) => {
                hueco.insert(pre_hash);
            }
        }
        max_slot = max_slot.max(slot);
        offset += TAMANO_ENTRADA as usize;
    }

    if offset < todo.len() {
        // Cola parcial (< 80 B): sin marca de commit no se puede demostrar que fuera durable.
        return Err(RegistroError::ColaParcial {
            ruta: ruta.to_path_buf(),
            offset: a_u64(offset, ruta)?,
            bytes: a_u64(todo.len() - offset, ruta)?,
        });
    }

    Ok(Recuperado {
        indice,
        max_slot,
        abstener_hasta,
        abstencion_activa,
    })
}

/// Lee un `u64` LE de ocho bytes exactos. Falla cerrado si el campo no mide ocho bytes.
fn leer_u64(bytes: Option<&[u8]>, ruta: &Path) -> Result<u64, RegistroError> {
    let array: [u8; 8] =
        bytes
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| RegistroError::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: 0,
                bytes_perdidos: 0,
            })?;
    Ok(u64::from_le_bytes(array))
}

/// Convierte un tamaño o desplazamiento de memoria a `u64` sin saturar ni inventar un cero.
fn a_u64(valor: usize, ruta: &Path) -> Result<u64, RegistroError> {
    u64::try_from(valor).map_err(|_| RegistroError::TamanoNoRepresentable {
        ruta: ruta.to_path_buf(),
    })
}

/// Envuelve un `io::Error` con la ruta del registro.
fn io_err(ruta: &Path, origen: std::io::Error) -> RegistroError {
    RegistroError::Io {
        ruta: ruta.to_path_buf(),
        origen,
    }
}

/// Sincroniza el fichero en disco. En tests puede fallar de forma inyectada y cuenta las llamadas.
fn sincronizar(
    fichero: &File,
    ruta: &Path,
    inyeccion: &InyeccionSync,
) -> Result<(), RegistroError> {
    #[cfg(test)]
    {
        inyeccion
            .syncs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if inyeccion.falla_sync {
            return Err(io_err(
                ruta,
                std::io::Error::other("fallo de sync inyectado en test"),
            ));
        }
    }
    let _ = inyeccion;
    fichero.sync_all().map_err(|origen| io_err(ruta, origen))
}

/// Sincroniza el directorio padre para que la creación del fichero sea durable.
///
/// Si no se puede abrir o sincronizar el directorio, se devuelve error: el módulo no finge una
/// durabilidad que no puede garantizar.
fn sincronizar_directorio(ruta: &Path) -> Result<(), RegistroError> {
    let padre = ruta
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = File::open(padre).map_err(|origen| io_err(ruta, origen))?;
    dir.sync_all().map_err(|origen| io_err(ruta, origen))
}

/// Toma el bloqueo exclusivo del fichero, con reintentos acotados.
///
/// `flock` vive en la *open file description*: un `fork` —el de cualquier `Command::spawn`— duplica
/// los descriptores del padre y, entre el `fork` y el `exec`, el hijo comparte el cerrojo. Si el
/// padre cierra y reabre su registro en ese hueco, `try_lock` devuelve `WouldBlock` **sin que haya
/// un segundo escritor**: es un titular transitorio. Por eso se reintenta durante un plazo corto;
/// un segundo escritor real no suelta el cerrojo, así que al agotar el plazo se devuelve
/// [`RegistroError::Bloqueado`] igual. El cerrojo se toma antes de leer o escribir nada.
fn bloquear(fichero: &File, ruta: &Path) -> Result<(), RegistroError> {
    use std::time::{Duration, Instant};

    // Cuánto se espera a que un titular transitorio suelte el cerrojo.
    const PLAZO: Duration = Duration::from_secs(2);
    // Primer intervalo entre reintentos.
    const INTERVALO_INICIAL: Duration = Duration::from_micros(50);
    // Techo del intervalo entre reintentos.
    const INTERVALO_MAXIMO: Duration = Duration::from_millis(20);

    let inicio = Instant::now();
    let mut intervalo = INTERVALO_INICIAL;
    loop {
        match fichero.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::Error(origen)) => return Err(io_err(ruta, origen)),
            Err(TryLockError::WouldBlock) => {
                let esperado = inicio.elapsed();
                if esperado >= PLAZO {
                    return Err(RegistroError::Bloqueado {
                        ruta: ruta.to_path_buf(),
                    });
                }
                std::thread::sleep(intervalo.min(PLAZO.saturating_sub(esperado)));
                intervalo = (intervalo * 2).min(INTERVALO_MAXIMO);
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño y manipulan bytes con índices constantes"
)]
mod tests {
    use super::{
        InyeccionSync, MAGIA, OFFSET_ABSTENCION_ACTIVA, OFFSET_ABSTENER_HASTA, Registro,
        RegistroError, Resolucion, TAMANO_CABECERA, TAMANO_ENTRADA, VERSION_FORMATO,
        cabecera_bytes, comprobacion_cabecera, entrada_bytes, sincronizar_directorio,
    };
    use crate::firmante::identidad::IdentidadTicket;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use zx_core::{ClavePublica, Digest, PreHash};

    static CONTADOR: AtomicU64 = AtomicU64::new(0);

    struct DirTemporal {
        ruta: PathBuf,
    }

    impl DirTemporal {
        fn nuevo(etiqueta: &str) -> Self {
            let pid = std::process::id();
            let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
            let unico = format!("zx-firmante-{pid}-{n}-{etiqueta}");
            let ruta = std::env::temp_dir().join(unico);
            std::fs::create_dir_all(&ruta).unwrap();
            Self { ruta }
        }

        fn ruta(&self) -> &Path {
            &self.ruta
        }
    }

    impl Drop for DirTemporal {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.ruta);
        }
    }

    fn id(chunk: u8, slot: u64) -> IdentidadTicket {
        IdentidadTicket::rat1(
            7,
            ClavePublica::desde_bytes([1u8; 32]),
            0,
            1 << 20,
            [chunk; 32],
            slot,
        )
    }

    fn ph(n: u8) -> PreHash {
        PreHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn sin_abstencion(ruta: &Path, s_max: u64) -> Registro {
        Registro::abrir_con_politica(ruta, 0, s_max, false, InyeccionSync::default()).unwrap()
    }

    #[test]
    fn entrada_nueva_conocida_y_conflicto() {
        let dir = DirTemporal::nuevo("resolver");
        let reg = sin_abstencion(&dir.ruta().join("r.log"), 150);

        assert_eq!(reg.resolver(&id(1, 100), ph(1)).unwrap(), Resolucion::Nueva);
        assert_eq!(
            reg.resolver(&id(1, 100), ph(1)).unwrap(),
            Resolucion::Conocida
        );
        assert_eq!(
            reg.resolver(&id(1, 100), ph(2)).unwrap(),
            Resolucion::Conflicto {
                pre_hash_registrado: ph(1)
            }
        );
        // La clave incluye el slot: otra oportunidad no colisiona.
        assert_eq!(reg.resolver(&id(1, 101), ph(2)).unwrap(), Resolucion::Nueva);
        assert_eq!(reg.entradas(), 2);
    }

    #[test]
    fn el_formato_declara_version_tres_y_cabecera_de_cincuenta_y_seis() {
        let dir = DirTemporal::nuevo("formato");
        let ruta = dir.ruta().join("r.log");
        let reg = sin_abstencion(&ruta, 150);
        reg.resolver(&id(1, 7), ph(1)).unwrap();
        drop(reg);

        let bytes = std::fs::read(&ruta).unwrap();
        assert_eq!(&bytes[..8], &MAGIA);
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[8..16]);
        assert_eq!(u64::from_le_bytes(b), VERSION_FORMATO);
        assert_eq!(VERSION_FORMATO, 3);
        assert_eq!(bytes.len() as u64, TAMANO_CABECERA + TAMANO_ENTRADA);

        // El checksum de la cabecera cubre los 40 primeros bytes y se guarda en los 16 siguientes.
        let esperado = comprobacion_cabecera(&bytes[..40]);
        assert_eq!(&bytes[40..56], esperado.as_slice());
    }

    #[test]
    fn sobrevive_a_reabrir_y_conserva_entradas() {
        let dir = DirTemporal::nuevo("reabrir");
        let ruta = dir.ruta().join("r.log");
        {
            let reg = sin_abstencion(&ruta, 150);
            assert_eq!(reg.resolver(&id(1, 100), ph(1)).unwrap(), Resolucion::Nueva);
            assert_eq!(reg.resolver(&id(2, 140), ph(3)).unwrap(), Resolucion::Nueva);
        }
        let reg = Registro::abrir(&ruta, 140, 150).unwrap();
        assert_eq!(reg.entradas(), 2);
        assert_eq!(reg.max_slot(), 140);
        assert_eq!(
            reg.resolver(&id(1, 100), ph(9)).unwrap(),
            Resolucion::Conflicto {
                pre_hash_registrado: ph(1)
            }
        );
    }

    #[test]
    fn nueva_falla_si_el_fichero_ya_existe() {
        let dir = DirTemporal::nuevo("nueva-existe");
        let ruta = dir.ruta().join("r.log");
        let primera = Registro::nueva(&ruta).unwrap();
        assert_eq!(primera.entradas(), 0);
        assert_eq!(primera.abstener_hasta(), None);
        drop(primera);

        // Un segundo alta sobre el mismo fichero NO se interpreta como registro limpio.
        assert!(matches!(
            Registro::nueva(&ruta).unwrap_err(),
            RegistroError::Io { .. }
        ));
    }

    #[test]
    fn nueva_permite_firmar_de_inmediato() {
        let dir = DirTemporal::nuevo("nueva-firma");
        let reg = Registro::nueva(dir.ruta().join("r.log")).unwrap();
        assert_eq!(reg.resolver(&id(1, 5), ph(1)).unwrap(), Resolucion::Nueva);
        assert_eq!(reg.entradas(), 1);
    }

    #[test]
    fn una_entrada_completa_a_ceros_tras_una_valida_falla_cerrado() {
        let dir = DirTemporal::nuevo("ceros-80");
        let ruta = dir.ruta().join("r.log");
        {
            let reg = sin_abstencion(&ruta, 150);
            assert_eq!(reg.resolver(&id(1, 100), ph(1)).unwrap(), Resolucion::Nueva);
        }
        // 80 bytes a cero tras la entrada válida: es una entrada **completa** con comprobación
        // inválida. Truncarla olvidaría una firma previa si hubo corrupción; falla cerrado.
        let mut f = std::fs::OpenOptions::new().write(true).open(&ruta).unwrap();
        use std::io::{Seek, SeekFrom, Write};
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(&[0u8; 80]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        match Registro::abrir(&ruta, 100, 150).unwrap_err() {
            RegistroError::Corrupto { offset, .. } => {
                assert_eq!(offset, TAMANO_CABECERA + TAMANO_ENTRADA);
            }
            otro => panic!("se esperaba Corrupto, llegó {otro:?}"),
        }
        // Y el fichero sigue con los 80 bytes: no se truncó.
        assert_eq!(
            std::fs::metadata(&ruta).unwrap().len(),
            TAMANO_CABECERA + 2 * TAMANO_ENTRADA
        );
    }

    #[test]
    fn una_cola_parcial_falla_cerrado() {
        let dir = DirTemporal::nuevo("cola-parcial");
        let ruta = dir.ruta().join("r.log");
        {
            let reg = sin_abstencion(&ruta, 150);
            assert_eq!(reg.resolver(&id(1, 100), ph(1)).unwrap(), Resolucion::Nueva);
        }
        // Media entrada a cero: cola parcial sin marca de comprobación que demuestre durabilidad.
        let mut f = std::fs::OpenOptions::new().write(true).open(&ruta).unwrap();
        use std::io::{Seek, SeekFrom, Write};
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(&[0u8; 40]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        match Registro::abrir(&ruta, 100, 150).unwrap_err() {
            RegistroError::ColaParcial { offset, bytes, .. } => {
                assert_eq!(offset, TAMANO_CABECERA + TAMANO_ENTRADA);
                assert_eq!(bytes, 40);
            }
            otro => panic!("se esperaba ColaParcial, llegó {otro:?}"),
        }
    }

    #[test]
    fn bytes_alterados_en_medio_fallan_cerrado() {
        let dir = DirTemporal::nuevo("corrupto");
        let ruta = dir.ruta().join("r.log");
        {
            let reg = sin_abstencion(&ruta, 150);
            assert_eq!(reg.resolver(&id(1, 100), ph(1)).unwrap(), Resolucion::Nueva);
            assert_eq!(reg.resolver(&id(2, 200), ph(2)).unwrap(), Resolucion::Nueva);
        }
        // Un bit cambiado en la PRIMERA entrada, con una segunda válida detrás.
        let mut f = std::fs::OpenOptions::new().write(true).open(&ruta).unwrap();
        use std::io::{Seek, SeekFrom, Write};
        f.seek(SeekFrom::Start(TAMANO_CABECERA + 10)).unwrap();
        f.write_all(&[0xFF]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        match Registro::abrir(&ruta, 200, 150).unwrap_err() {
            RegistroError::Corrupto { offset, .. } => assert_eq!(offset, TAMANO_CABECERA),
            otro => panic!("se esperaba Corrupto, llegó {otro:?}"),
        }
    }

    #[test]
    fn un_duplicado_conflictivo_falla_cerrado() {
        let dir = DirTemporal::nuevo("duplicado");
        let ruta = dir.ruta().join("r.log");
        let huella = id(5, 300).huella();
        let mut bytes = cabecera_bytes(0, 0, false).to_vec();
        bytes.extend_from_slice(&entrada_bytes(300, &huella, ph(1)));
        bytes.extend_from_slice(&entrada_bytes(300, &huella, ph(2)));
        std::fs::write(&ruta, &bytes).unwrap();

        match Registro::abrir(&ruta, 300, 150).unwrap_err() {
            RegistroError::DuplicadoConflictivo { slot, .. } => assert_eq!(slot, 300),
            otro => panic!("se esperaba DuplicadoConflictivo, llegó {otro:?}"),
        }
    }

    #[test]
    fn un_duplicado_identico_no_falla() {
        let dir = DirTemporal::nuevo("duplicado-igual");
        let ruta = dir.ruta().join("r.log");
        let huella = id(5, 300).huella();
        let mut bytes = cabecera_bytes(0, 0, false).to_vec();
        bytes.extend_from_slice(&entrada_bytes(300, &huella, ph(1)));
        bytes.extend_from_slice(&entrada_bytes(300, &huella, ph(1)));
        std::fs::write(&ruta, &bytes).unwrap();

        let reg = Registro::abrir(&ruta, 300, 150).unwrap();
        assert_eq!(reg.entradas(), 1);
    }

    #[test]
    fn una_magia_ajena_se_rechaza() {
        let dir = DirTemporal::nuevo("magia");
        let ruta = dir.ruta().join("r.log");
        std::fs::write(&ruta, [0u8; TAMANO_CABECERA as usize]).unwrap();
        assert!(matches!(
            Registro::abrir(&ruta, 0, 150).unwrap_err(),
            RegistroError::MagiaInvalida { .. }
        ));
        assert_eq!(&MAGIA, b"ZXRGFIRM");
    }

    #[test]
    fn una_version_desconocida_falla_cerrado() {
        let dir = DirTemporal::nuevo("version");
        let ruta = dir.ruta().join("r.log");
        let mut cabecera = cabecera_bytes(0, 0, false);
        cabecera[8..16].copy_from_slice(&99u64.to_le_bytes());
        std::fs::write(&ruta, cabecera).unwrap();
        assert!(matches!(
            Registro::abrir(&ruta, 0, 150).unwrap_err(),
            RegistroError::VersionInvalida {
                encontrada: 99,
                esperada: VERSION_FORMATO,
                ..
            }
        ));
    }

    #[test]
    fn un_formato_dos_no_se_migra_en_silencio() {
        let dir = DirTemporal::nuevo("version-2");
        let ruta = dir.ruta().join("r.log");
        // Cabecera de formato 2: 40 B, versión 2. No se migra; se rechaza.
        let mut cabecera = [0u8; TAMANO_CABECERA as usize];
        cabecera[..8].copy_from_slice(&MAGIA);
        cabecera[8..16].copy_from_slice(&2u64.to_le_bytes());
        std::fs::write(&ruta, cabecera).unwrap();
        assert!(matches!(
            Registro::abrir(&ruta, 0, 150).unwrap_err(),
            RegistroError::VersionInvalida {
                encontrada: 2,
                esperada: VERSION_FORMATO,
                ..
            }
        ));
    }

    #[test]
    fn un_bit_en_la_cabecera_rompe_el_checksum() {
        let dir = DirTemporal::nuevo("cabecera-bits");
        let ruta = dir.ruta().join("r.log");
        let slot_perdida = 1_000u64;
        let s_max = 150u64;
        {
            let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
            assert!(reg.en_abstinencia(slot_perdida));
        }
        let original = std::fs::read(&ruta).unwrap();

        // Bandera de abstención (1 -> 0 al invertir el bit bajo) y horizonte por separado.
        for (etiqueta, offset) in [
            ("bandera", OFFSET_ABSTENCION_ACTIVA),
            ("horizonte", OFFSET_ABSTENER_HASTA),
        ] {
            let mut bytes = original.clone();
            bytes[offset] ^= 0x01;
            let ruta_editada = dir.ruta().join(format!("{etiqueta}.log"));
            std::fs::write(&ruta_editada, &bytes).unwrap();
            assert!(
                matches!(
                    Registro::abrir(&ruta_editada, slot_perdida, s_max).unwrap_err(),
                    RegistroError::CabeceraCorrupta { .. }
                ),
                "{etiqueta}: un bit cambiado debe fallar cerrado"
            );
        }
    }

    #[test]
    fn la_recuperacion_sincroniza_antes_de_autorizar_firma() {
        let dir = DirTemporal::nuevo("recuperacion-sync");
        let ruta = dir.ruta().join("r.log");

        // Primer proceso: `write_all` llega a la caché, `sync_all` falla inyectado y la instancia
        // se envenena. La entrada puede estar en el fichero sin ser durable.
        {
            let reg = sin_abstencion(&ruta, 150);
            reg.estado.lock().unwrap().inyeccion.falla_sync = true;
            let e = reg.resolver(&id(1, 100), ph(1)).unwrap_err();
            assert!(matches!(e, RegistroError::Io { .. }), "{e:?}");
        }

        // Reapertura con la sincronización de recuperación fallando: no hay `Registro` utilizable.
        let inyeccion = InyeccionSync {
            falla_sync: true,
            ..InyeccionSync::default()
        };
        let e = Registro::abrir_con_politica(&ruta, 100, 150, false, inyeccion).unwrap_err();
        assert!(matches!(e, RegistroError::Io { .. }), "{e:?}");

        // Reapertura real: la recuperación sincroniza el fichero (no se limita a releerlo) y solo
        // entonces autoriza reemitir la firma.
        let reg =
            Registro::abrir_con_politica(&ruta, 100, 150, false, InyeccionSync::default()).unwrap();
        assert_eq!(reg.entradas(), 1);
        assert!(
            reg.estado
                .lock()
                .unwrap()
                .inyeccion
                .syncs
                .load(Ordering::Relaxed)
                >= 1,
            "la recuperación debe sincronizar el fichero, no solo releerlo"
        );
        assert_eq!(
            reg.resolver(&id(1, 100), ph(1)).unwrap(),
            Resolucion::Conocida
        );
    }

    #[test]
    fn la_abstencion_de_un_alta_nueva_persiste_tras_dos_reinicios() {
        let dir = DirTemporal::nuevo("abstencion");
        let ruta = dir.ruta().join("r.log");
        let s_max = 150;
        let slot_perdida = 1_000;

        // Alta conservadora sobre fichero inexistente.
        {
            let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
            assert!(reg.en_abstinencia(slot_perdida + s_max));
            assert_eq!(reg.abstener_hasta(), Some(slot_perdida + s_max));
        }
        // Primer reinicio: sigue en abstención.
        {
            let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
            assert!(reg.en_abstinencia(slot_perdida + s_max));
            let e = reg
                .resolver(&id(1, slot_perdida + s_max), ph(1))
                .unwrap_err();
            assert!(matches!(e, RegistroError::EnAbstinencia { .. }));
        }
        // Segundo reinicio: sigue en abstención, y el slot siguiente ya se firma.
        let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
        assert!(reg.en_abstinencia(slot_perdida + s_max));
        assert_eq!(
            reg.resolver(&id(1, slot_perdida + s_max + 1), ph(1))
                .unwrap(),
            Resolucion::Nueva
        );
        assert!(!reg.en_abstinencia(slot_perdida + s_max + 1));
        assert_eq!(reg.entradas(), 1);
    }

    #[test]
    fn un_horizonte_que_desborda_u64_sigue_absteniendose() {
        let dir = DirTemporal::nuevo("desborde");
        let ruta = dir.ruta().join("r.log");
        let reg = Registro::abrir(&ruta, u64::MAX - 1, 150).unwrap();
        assert_eq!(reg.abstener_hasta(), Some(u64::MAX));
        assert!(reg.en_abstinencia(u64::MAX));
    }

    #[test]
    fn el_fallo_de_persistencia_envenena_la_instancia() {
        let dir = DirTemporal::nuevo("envenenado");
        let ruta = dir.ruta().join("r.log");
        let reg = sin_abstencion(&ruta, 150);
        reg.estado.lock().unwrap().inyeccion.falla_sync = true;

        let e = reg.resolver(&id(1, 100), ph(1)).unwrap_err();
        assert!(matches!(e, RegistroError::Io { .. }), "{e:?}");
        // Aunque el fallo se desactive, la instancia ya no es de fiar: hay que reabrir.
        reg.estado.lock().unwrap().inyeccion.falla_sync = false;
        assert!(matches!(
            reg.resolver(&id(1, 100), ph(1)).unwrap_err(),
            RegistroError::Envenenado { .. }
        ));
        drop(reg);

        // Al reabrir, la recuperación valida, **sincroniza** y solo entonces devuelve instancia.
        // El `write_all` anterior llegó a la caché, así que la entrada está y es reemitible.
        let reg = Registro::abrir(&ruta, 100, 150).unwrap();
        assert_eq!(reg.entradas(), 1);
        assert_eq!(
            reg.resolver(&id(1, 100), ph(1)).unwrap(),
            Resolucion::Conocida
        );
    }

    #[test]
    fn el_bloqueo_entre_dos_descriptores_se_detecta() {
        // `try_lock` es por open file description: dos `File` distintos del mismo proceso chocan,
        // que es lo que permite probar el camino de Bloqueado sin lanzar un proceso.
        let dir = DirTemporal::nuevo("bloqueo");
        let ruta = dir.ruta().join("r.log");
        let _primero = sin_abstencion(&ruta, 150);
        assert!(matches!(
            Registro::abrir(&ruta, 0, 150),
            Err(RegistroError::Bloqueado { .. })
        ));
    }

    #[test]
    fn la_creacion_sincroniza_el_directorio_padre() {
        // No se puede observar el fsync del directorio directamente, pero sí que la ruta sin
        // directorio padre no falla y que la función existe y devuelve Ok en un directorio real.
        let dir = DirTemporal::nuevo("directorio");
        let ruta = dir.ruta().join("r.log");
        let _reg = sin_abstencion(&ruta, 150);
        sincronizar_directorio(&ruta).unwrap();
        assert!(ruta.exists());
    }
}
