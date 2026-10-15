//! FV-N6-C7 · Diario local de voto del nodo (privado de `votos.rs`).
//!
//! Diario **solo-anexar** y **fuera del wire**: reserva durable de la identidad completa del voto
//! propio antes de firmar. La clave es `(CBID u32, claveBLS 48, n u64)` y el valor es el digest
//! completo que devuelve [`zx_votos::mensaje_voto`] (incluye `n`, `h_B`, `h_T(n+1)` y `h_cand`).
//!
//! ## Contrato
//!
//! - **Reserva antes de firmar**: [`DiarioVotos::resolver`] escribe y **sincroniza** una entrada
//!   nueva antes de devolver [`ResolucionDiario::Nueva`]; solo entonces el motor puede firmar.
//! - **Reemisión exacta**: la misma clave con el **mismo** digest devuelve
//!   [`ResolucionDiario::Conocida`] sin escribir.
//! - **Conflicto**: la misma clave con otro digest devuelve [`ResolucionDiario::Conflicto`] y no
//!   escribe: no se firma un mensaje distinto para `(CBID, claveBLS, n)`.
//! - **Fallo cerrado**: una E/S ambigua (`write` o `sync_all`) **envenena** la instancia; no se
//!   trunca ni se recrea para seguir firmando. Una reapertura válida es la única que rehabilita.
//! - **Exclusión**: el fichero se abre con `create_new` o se reabre existente, y se mantiene
//!   bloqueado en exclusiva (`File::try_lock`) durante toda la vida del diario. Un segundo proceso
//!   sobre el mismo directorio no obtiene permiso de firma.
//! - **Durabilidad**: cabecera y entradas con checksum SHA3-256; al reabrir se valida el log
//!   completo (magia, versión, checksums, duplicados y colas) y se sincroniza antes de autorizar
//!   cualquier reemisión.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zx_votos::Hash;

/// Magia de cabecera del diario (8 B).
const MAGIA: [u8; 8] = *b"ZXVOTOD1";
/// Versión de formato que escribe esta versión del nodo. Añade el **candado durable** (N4): la
/// entrada de candado guarda `(clave, n_v, candidato_v)` con la misma durabilidad que la reserva.
const VERSION_FORMATO: u64 = 2;
/// Versión de formato anterior, admitida en lectura: solo reservas, **sin candados** (N4).
const VERSION_LEGADA: u64 = 1;
/// Longitud de la parte firmada de la cabecera: magia + versión.
const TAM_CABECERA_FIRMADA: usize = 16;
/// Longitud del checksum **efectivo** almacenado: SHA3-256 truncado a 8 bytes (64 bits).
const TAM_COMPROBACION: usize = 8;
/// Longitud total de la cabecera.
const TAM_CABECERA: usize = TAM_CABECERA_FIRMADA + TAM_COMPROBACION;
/// Longitud de la clave BLS comprimida (G1).
const LONGITUD_CLAVE_BLS: usize = 48;
/// Cuerpo de una entrada, común a reservas y candados: CBID + clave + `n` + 32 B de carga.
const TAM_CUERPO: usize = 4 + LONGITUD_CLAVE_BLS + 8 + 32;
/// Marca de entrada de **reserva** `(CBID, clave, n) -> digest` (formato v2).
const TIPO_RESERVA: u8 = 1;
/// Marca de entrada de **candado** `(CBID, clave) -> (n_v, candidato_v)` (formato v2).
const TIPO_CANDADO: u8 = 2;
/// Longitud firmada de una entrada v2: tipo + cuerpo.
const TAM_ENTRADA_V2_FIRMADA: usize = 1 + TAM_CUERPO;
/// Longitud total de una entrada v2.
const TAM_ENTRADA_V2: usize = TAM_ENTRADA_V2_FIRMADA + TAM_COMPROBACION;
/// Longitud firmada de una entrada del formato anterior (v1): CBID + clave + n + digest.
const TAM_ENTRADA_V1_FIRMADA: usize = TAM_CUERPO;
/// Longitud total de una entrada del formato anterior (v1).
const TAM_ENTRADA_V1: usize = TAM_ENTRADA_V1_FIRMADA + TAM_COMPROBACION;

/// Clave del diario: `(CBID, claveBLS, n)`.
type ClaveDiario = (u32, [u8; LONGITUD_CLAVE_BLS], u64);
/// Índice en memoria de claves ya reservadas.
type Indice = HashMap<ClaveDiario, Hash>;
/// Candado durable por clave: `(CBID, claveBLS) -> (n_v, candidato_v)`.
type Candados = HashMap<(u32, [u8; LONGITUD_CLAVE_BLS]), (u64, Hash)>;

/// Resultado de resolver una reserva.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResolucionDiario {
    /// No había entrada: se escribió y sincronizó antes de devolver.
    Nueva,
    /// Ya había una entrada con el **mismo** digest: reemisión exacta permitida.
    Conocida,
    /// Ya había una entrada con **otro** digest: conflicto, no se firma.
    Conflicto { registrado: Hash },
}

/// Error del diario de voto.
#[derive(Debug)]
pub(crate) enum ErrorDiario {
    /// E/S con la ruta asociada.
    Io {
        /// Ruta del fichero.
        ruta: PathBuf,
        /// Error de origen.
        origen: std::io::Error,
    },
    /// Otro proceso mantiene el bloqueo exclusivo.
    Bloqueado {
        /// Ruta del fichero.
        ruta: PathBuf,
    },
    /// El fichero ya existía donde se pedía crear uno nuevo.
    YaExiste {
        /// Ruta del fichero.
        ruta: PathBuf,
    },
    /// La cabecera no empieza por la magia esperada.
    MagiaInvalida {
        /// Ruta del fichero.
        ruta: PathBuf,
    },
    /// Versión de formato desconocida.
    VersionInvalida {
        /// Ruta del fichero.
        ruta: PathBuf,
        /// Versión encontrada.
        encontrada: u64,
        /// Versión esperada.
        esperada: u64,
    },
    /// El checksum de la cabecera no cuadra.
    CabeceraCorrupta {
        /// Ruta del fichero.
        ruta: PathBuf,
    },
    /// Una entrada completa no supera su checksum.
    Corrupto {
        /// Ruta del fichero.
        ruta: PathBuf,
        /// Desplazamiento de la entrada.
        offset: u64,
    },
    /// Cola parcial sin marca de durabilidad.
    ColaParcial {
        /// Ruta del fichero.
        ruta: PathBuf,
        /// Desplazamiento donde empieza la cola.
        offset: u64,
        /// Bytes de la cola.
        bytes: u64,
    },
    /// Dos entradas de la misma clave con distinto digest.
    DuplicadoConflictivo {
        /// Ruta del fichero.
        ruta: PathBuf,
        /// Desplazamiento de la segunda entrada.
        offset: u64,
    },
    /// El CBID de una entrada no es el del nodo.
    CbidAjeno {
        /// Ruta del fichero.
        ruta: PathBuf,
        /// CBID encontrado.
        encontrado: u32,
        /// CBID esperado.
        esperado: u32,
    },
    /// Una operación anterior dejó el diario en duda: no se firma hasta reabrir.
    Envenenado {
        /// Ruta del fichero.
        ruta: PathBuf,
    },
}

impl std::fmt::Display for ErrorDiario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { ruta, origen } => write!(f, "diario {}: {origen}", ruta.display()),
            Self::Bloqueado { ruta } => {
                write!(f, "diario {}: bloqueado por otro proceso", ruta.display())
            }
            Self::YaExiste { ruta } => write!(f, "diario {}: ya existe", ruta.display()),
            Self::MagiaInvalida { ruta } => write!(f, "diario {}: magia inválida", ruta.display()),
            Self::VersionInvalida {
                ruta,
                encontrada,
                esperada,
            } => write!(
                f,
                "diario {}: versión {encontrada} inesperada (se espera {esperada})",
                ruta.display()
            ),
            Self::CabeceraCorrupta { ruta } => {
                write!(f, "diario {}: cabecera corrupta", ruta.display())
            }
            Self::Corrupto { ruta, offset } => write!(
                f,
                "diario {}: entrada corrupta en el desplazamiento {offset}",
                ruta.display()
            ),
            Self::ColaParcial {
                ruta,
                offset,
                bytes,
            } => write!(
                f,
                "diario {}: cola parcial de {bytes} bytes en el desplazamiento {offset}",
                ruta.display()
            ),
            Self::DuplicadoConflictivo { ruta, offset } => write!(
                f,
                "diario {}: duplicado conflictivo en el desplazamiento {offset}",
                ruta.display()
            ),
            Self::CbidAjeno {
                ruta,
                encontrado,
                esperado,
            } => write!(
                f,
                "diario {}: CBID {encontrado} ajeno (se espera {esperado})",
                ruta.display()
            ),
            Self::Envenenado { ruta } => write!(
                f,
                "diario {}: envenenado por un fallo de E/S previo",
                ruta.display()
            ),
        }
    }
}

impl std::error::Error for ErrorDiario {}

/// Estado interior del diario.
struct Estado {
    /// Fichero abierto y bloqueado.
    fichero: File,
    /// Ruta del fichero.
    ruta: PathBuf,
    /// CBID del nodo dueño.
    cbid: u32,
    /// Índice de claves reservadas.
    indice: Indice,
    /// N4 · último voto emitido por clave (candado durable).
    candados: Candados,
    /// ¿El fichero abierto está en el formato con candados? Un diario de formato anterior se
    /// reabre **sin** candados (N4): no se escriben y `candado` siempre devuelve `None`.
    soporta_candados: bool,
    /// Una E/S ambigua deja el diario en duda.
    envenenado: bool,
    /// Fuerza un fallo de `sync_all` de la **reserva** en tests, dentro del camino real.
    #[cfg(test)]
    falla_sync: bool,
    /// Fuerza un fallo de `sync_all` del **candado** en tests, dentro del camino real.
    #[cfg(test)]
    falla_sync_candado: bool,
}

/// Diario local de voto, solo-anexar y con exclusión de fichero.
pub(crate) struct DiarioVotos {
    /// Estado interior compartido.
    estado: Mutex<Estado>,
}

impl DiarioVotos {
    /// Crea un diario **nuevo**: exige que el fichero no exista (`create_new`) y escribe y
    /// sincroniza la cabecera (fichero y directorio padre) antes de devolver.
    ///
    /// # Errores
    /// [`ErrorDiario::YaExiste`] si el fichero ya está, [`ErrorDiario::Bloqueado`] si otro proceso
    /// lo tiene, o [`ErrorDiario::Io`] si falla la escritura o la sincronización.
    pub(crate) fn nueva(ruta: impl AsRef<Path>, cbid: u32) -> Result<Self, ErrorDiario> {
        let ruta = ruta.as_ref().to_path_buf();
        let mut fichero = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&ruta)
            .map_err(|origen| {
                if origen.kind() == std::io::ErrorKind::AlreadyExists {
                    ErrorDiario::YaExiste { ruta: ruta.clone() }
                } else {
                    io_err(&ruta, origen)
                }
            })?;
        bloquear(&fichero, &ruta)?;
        let cabecera = cabecera_bytes(VERSION_FORMATO);
        fichero
            .write_all(&cabecera)
            .and_then(|()| fichero.sync_all())
            .map_err(|origen| io_err(&ruta, origen))?;
        sincronizar_directorio(&ruta)?;
        Ok(Self {
            estado: Mutex::new(Estado {
                fichero,
                ruta,
                cbid,
                indice: HashMap::new(),
                candados: HashMap::new(),
                soporta_candados: true,
                envenenado: false,
                #[cfg(test)]
                falla_sync: false,
                #[cfg(test)]
                falla_sync_candado: false,
            }),
        })
    }

    /// Reabre un diario existente: valida el log completo y lo sincroniza antes de devolverlo.
    ///
    /// # Errores
    /// Las de formato/checksum/duplicados/colas, [`ErrorDiario::Bloqueado`] si otro proceso lo
    /// tiene, o [`ErrorDiario::Io`].
    pub(crate) fn abrir(ruta: impl AsRef<Path>, cbid: u32) -> Result<Self, ErrorDiario> {
        let ruta = ruta.as_ref().to_path_buf();
        let mut fichero = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&ruta)
            .map_err(|origen| io_err(&ruta, origen))?;
        bloquear(&fichero, &ruta)?;
        let (indice, candados, soporta_candados) = recuperar(&mut fichero, &ruta, cbid)?;
        fichero.sync_all().map_err(|origen| io_err(&ruta, origen))?;
        // FV-N6-C7-2 · la reapertura también sincroniza el **directorio padre**: completa el resto
        // de una creación interrumpida (la entrada del directorio pudo quedar sin confirmar) antes
        // de autorizar cualquier reemisión.
        sincronizar_directorio(&ruta)?;
        Ok(Self {
            estado: Mutex::new(Estado {
                fichero,
                ruta,
                cbid,
                indice,
                candados,
                soporta_candados,
                envenenado: false,
                #[cfg(test)]
                falla_sync: false,
                #[cfg(test)]
                falla_sync_candado: false,
            }),
        })
    }

    /// Reserva durable de la identidad completa del voto.
    ///
    /// Sin entrada, escribe y **sincroniza** antes de devolver [`ResolucionDiario::Nueva`]. Con el
    /// mismo digest, [`ResolucionDiario::Conocida`]. Con otro digest, [`ResolucionDiario::Conflicto`]
    /// sin escribir.
    ///
    /// # Errores
    /// [`ErrorDiario::Envenenado`] si un fallo previo dejó el diario en duda, o [`ErrorDiario::Io`]
    /// si falla la escritura/`sync_all` (y entonces la instancia queda envenenada).
    pub(crate) fn resolver(
        &self,
        clave: &[u8; LONGITUD_CLAVE_BLS],
        n: u64,
        digest: &Hash,
    ) -> Result<ResolucionDiario, ErrorDiario> {
        let mut estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        if estado.envenenado {
            return Err(ErrorDiario::Envenenado {
                ruta: estado.ruta.clone(),
            });
        }
        let clave_diario = (estado.cbid, *clave, n);
        if let Some(registrado) = estado.indice.get(&clave_diario).copied() {
            if registrado == *digest {
                return Ok(ResolucionDiario::Conocida);
            }
            return Ok(ResolucionDiario::Conflicto { registrado });
        }
        let entrada = entrada_bytes(estado.cbid, clave, n, digest);
        if let Err(origen) = estado.fichero.write_all(&entrada) {
            estado.envenenado = true;
            return Err(io_err(&estado.ruta, origen));
        }
        if let Err(origen) = sincronizar(&estado.fichero, &estado.ruta, &estado) {
            estado.envenenado = true;
            return Err(origen);
        }
        estado.indice.insert(clave_diario, *digest);
        Ok(ResolucionDiario::Nueva)
    }

    /// N4 · último voto emitido por la clave, si el diario tiene candado para ella.
    ///
    /// Un diario de formato anterior no tiene candados y devuelve siempre `None`.
    #[must_use]
    pub(crate) fn candado(&self, clave: &[u8; LONGITUD_CLAVE_BLS]) -> Option<(u64, Hash)> {
        let estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        if !estado.soporta_candados {
            return None;
        }
        estado.candados.get(&(estado.cbid, *clave)).copied()
    }

    /// N4 · fija el candado durable `(n_v, candidato_v)` de la clave **antes de firmar**.
    ///
    /// Misma durabilidad que [`Self::resolver`]: escribe y sincroniza la entrada antes de devolver
    /// `Ok`. Un fallo de E/S deja el diario envenenado (no se firma). En un diario de formato
    /// anterior es un no-op: ese formato se abre sin candados.
    ///
    /// # Errores
    /// [`ErrorDiario::Envenenado`] si ya lo estaba, o [`ErrorDiario::Io`] si falla la escritura o el
    /// `sync_all` (y entonces queda envenenado).
    pub(crate) fn fijar_candado(
        &self,
        clave: &[u8; LONGITUD_CLAVE_BLS],
        n_v: u64,
        candidato: &Hash,
    ) -> Result<(), ErrorDiario> {
        let mut estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        if !estado.soporta_candados {
            return Ok(());
        }
        if estado.envenenado {
            return Err(ErrorDiario::Envenenado {
                ruta: estado.ruta.clone(),
            });
        }
        let clave_candado = (estado.cbid, *clave);
        if estado.candados.get(&clave_candado) == Some(&(n_v, *candidato)) {
            return Ok(());
        }
        let entrada = entrada_candado_bytes(estado.cbid, clave, n_v, candidato);
        if let Err(origen) = estado.fichero.write_all(&entrada) {
            estado.envenenado = true;
            return Err(io_err(&estado.ruta, origen));
        }
        if let Err(origen) = sincronizar_candado(&estado.fichero, &estado.ruta, &estado) {
            estado.envenenado = true;
            return Err(origen);
        }
        estado.candados.insert(clave_candado, (n_v, *candidato));
        Ok(())
    }

    /// Número de entradas vivas en el índice.
    #[must_use]
    pub(crate) fn entradas(&self) -> u64 {
        let estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        u64::try_from(estado.indice.len()).unwrap_or(u64::MAX)
    }

    /// VS-2 · V3 · ¿existe una reserva para `(clave, n)`? Consulta **sin escribir**.
    #[must_use]
    pub(crate) fn reservada(&self, clave: &[u8; LONGITUD_CLAVE_BLS], n: u64) -> bool {
        let estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        estado.indice.contains_key(&(estado.cbid, *clave, n))
    }

    /// Ruta del fichero.
    #[must_use]
    pub(crate) fn ruta(&self) -> PathBuf {
        self.estado
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ruta
            .clone()
    }

    /// Fuerza un fallo de `sync_all` en el siguiente camino de escritura, **solo en tests**.
    #[cfg(test)]
    pub(crate) fn fallar_proximo_sync_para_test(&self) {
        let mut estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        estado.falla_sync = true;
    }

    /// Fuerza un fallo de `sync_all` del **candado** en el siguiente camino de escritura, **solo en
    /// tests** (M9-a2 · R6: un fallo del candado impide firmar). Gancho de prueba que la orden
    /// devuelve tal cual estaba en `10a4aaea` (T4a).
    #[cfg(test)]
    pub(crate) fn fallar_proximo_sync_candado_para_test(&self) {
        let mut estado = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        estado.falla_sync_candado = true;
    }
}

/// Cabecera con checksum para la versión indicada.
fn cabecera_bytes(version: u64) -> Vec<u8> {
    let mut firmada = Vec::with_capacity(TAM_CABECERA_FIRMADA);
    firmada.extend_from_slice(&MAGIA);
    firmada.extend_from_slice(&version.to_le_bytes());
    let comprobacion = comprobacion(&firmada);
    firmada.extend_from_slice(&comprobacion);
    firmada
}

/// Serializa una entrada v2 con su checksum a partir del tipo y el cuerpo.
fn entrada_v2(
    tipo: u8,
    cbid: u32,
    clave: &[u8; LONGITUD_CLAVE_BLS],
    n: u64,
    carga: &Hash,
) -> Vec<u8> {
    let mut entrada = Vec::with_capacity(TAM_ENTRADA_V2);
    entrada.push(tipo);
    entrada.extend_from_slice(&cbid.to_le_bytes());
    entrada.extend_from_slice(clave);
    entrada.extend_from_slice(&n.to_le_bytes());
    entrada.extend_from_slice(carga);
    let comprobacion = comprobacion(&entrada);
    entrada.extend_from_slice(&comprobacion);
    entrada
}

/// Serializa una entrada de **reserva** con su checksum (formato v2, tipo [`TIPO_RESERVA`]).
fn entrada_bytes(cbid: u32, clave: &[u8; LONGITUD_CLAVE_BLS], n: u64, digest: &Hash) -> Vec<u8> {
    entrada_v2(TIPO_RESERVA, cbid, clave, n, digest)
}

/// Serializa una entrada de **candado** con su checksum (formato v2, tipo [`TIPO_CANDADO`]).
fn entrada_candado_bytes(
    cbid: u32,
    clave: &[u8; LONGITUD_CLAVE_BLS],
    n_v: u64,
    candidato: &Hash,
) -> Vec<u8> {
    entrada_v2(TIPO_CANDADO, cbid, clave, n_v, candidato)
}

/// Checksum SHA3-256 truncado a [`TAM_COMPROBACION`].
fn comprobacion(bytes: &[u8]) -> [u8; TAM_COMPROBACION] {
    let digest = zx_core::sha3_256_publico(bytes);
    let mut salida = [0u8; TAM_COMPROBACION];
    if let (Some(destino), Some(origen)) = (
        salida.get_mut(..),
        digest.as_bytes().get(..TAM_COMPROBACION),
    ) {
        destino.copy_from_slice(origen);
    }
    salida
}

/// Valida el log completo y construye el índice y los candados. **No trunca nada**: falla cerrado.
///
/// Admite el formato v1 (solo reservas; se abre **sin** candados, N4) y el v2 (reservas y candados).
/// Devuelve `(indice, candados, soporta_candados)`.
fn recuperar(
    fichero: &mut File,
    ruta: &Path,
    cbid: u32,
) -> Result<(Indice, Candados, bool), ErrorDiario> {
    let mut todo = Vec::new();
    fichero
        .seek(SeekFrom::Start(0))
        .and_then(|_| fichero.read_to_end(&mut todo))
        .map_err(|origen| io_err(ruta, origen))?;

    let cabecera = todo
        .get(..TAM_CABECERA)
        .ok_or_else(|| ErrorDiario::Corrupto {
            ruta: ruta.to_path_buf(),
            offset: 0,
        })?;
    if cabecera.get(..MAGIA.len()) != Some(MAGIA.as_slice()) {
        return Err(ErrorDiario::MagiaInvalida {
            ruta: ruta.to_path_buf(),
        });
    }
    let version = cabecera
        .get(MAGIA.len()..TAM_CABECERA_FIRMADA)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| ErrorDiario::Corrupto {
            ruta: ruta.to_path_buf(),
            offset: 0,
        })?;
    if version != VERSION_FORMATO && version != VERSION_LEGADA {
        return Err(ErrorDiario::VersionInvalida {
            ruta: ruta.to_path_buf(),
            encontrada: version,
            esperada: VERSION_FORMATO,
        });
    }
    let firmada = cabecera
        .get(..TAM_CABECERA_FIRMADA)
        .ok_or_else(|| ErrorDiario::Corrupto {
            ruta: ruta.to_path_buf(),
            offset: 0,
        })?;
    let esperado = comprobacion(firmada);
    if cabecera.get(TAM_CABECERA_FIRMADA..TAM_CABECERA) != Some(esperado.as_slice()) {
        return Err(ErrorDiario::CabeceraCorrupta {
            ruta: ruta.to_path_buf(),
        });
    }

    let con_candados = version == VERSION_FORMATO;
    // En v2 la entrada empieza por el tipo; en v1 no hay tipo y el cuerpo es idéntico.
    let base = usize::from(con_candados);
    let tam_firmada = if con_candados {
        TAM_ENTRADA_V2_FIRMADA
    } else {
        TAM_ENTRADA_V1_FIRMADA
    };
    let tam_entrada = if con_candados {
        TAM_ENTRADA_V2
    } else {
        TAM_ENTRADA_V1
    };

    let mut indice: Indice = HashMap::new();
    let mut candados: Candados = HashMap::new();
    let mut offset = TAM_CABECERA;
    while offset < todo.len() {
        let fin = offset.saturating_add(tam_entrada);
        let Some(entrada) = todo.get(offset..fin) else {
            return Err(ErrorDiario::ColaParcial {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset),
                bytes: a_u64(todo.len().saturating_sub(offset)),
            });
        };
        let firmada = entrada
            .get(..tam_firmada)
            .ok_or_else(|| ErrorDiario::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset),
            })?;
        let esperado = comprobacion(firmada);
        if entrada.get(tam_firmada..tam_entrada) != Some(esperado.as_slice()) {
            return Err(ErrorDiario::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset),
            });
        }
        let tipo = if con_candados {
            match entrada.first().copied() {
                Some(t) if t == TIPO_RESERVA || t == TIPO_CANDADO => t,
                _ => {
                    return Err(ErrorDiario::Corrupto {
                        ruta: ruta.to_path_buf(),
                        offset: a_u64(offset),
                    });
                }
            }
        } else {
            TIPO_RESERVA
        };
        let cbid_entrada = entrada
            .get(base..base + 4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| ErrorDiario::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset),
            })?;
        if cbid_entrada != cbid {
            return Err(ErrorDiario::CbidAjeno {
                ruta: ruta.to_path_buf(),
                encontrado: cbid_entrada,
                esperado: cbid,
            });
        }
        let clave = entrada
            .get(base + 4..base + 4 + LONGITUD_CLAVE_BLS)
            .and_then(|s| <[u8; LONGITUD_CLAVE_BLS]>::try_from(s).ok())
            .ok_or_else(|| ErrorDiario::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset),
            })?;
        let n = entrada
            .get(base + 4 + LONGITUD_CLAVE_BLS..base + 4 + LONGITUD_CLAVE_BLS + 8)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(u64::from_le_bytes)
            .ok_or_else(|| ErrorDiario::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset),
            })?;
        let carga = entrada
            .get(base + 4 + LONGITUD_CLAVE_BLS + 8..tam_firmada)
            .and_then(|s| <[u8; 32]>::try_from(s).ok())
            .ok_or_else(|| ErrorDiario::Corrupto {
                ruta: ruta.to_path_buf(),
                offset: a_u64(offset),
            })?;
        match tipo {
            TIPO_RESERVA => {
                let clave_diario = (cbid_entrada, clave, n);
                if let Some(previo) = indice.get(&clave_diario) {
                    if *previo != carga {
                        return Err(ErrorDiario::DuplicadoConflictivo {
                            ruta: ruta.to_path_buf(),
                            offset: a_u64(offset),
                        });
                    }
                } else {
                    indice.insert(clave_diario, carga);
                }
            }
            // N4 · el último candado escrito para la clave es el que rige al reabrir.
            TIPO_CANDADO => {
                candados.insert((cbid_entrada, clave), (n, carga));
            }
            _ => unreachable!("el tipo ya se validó"),
        }
        offset = fin;
    }
    Ok((indice, candados, con_candados))
}

/// Sincroniza el fichero, con fallo inyectable en tests.
fn sincronizar(fichero: &File, ruta: &Path, estado: &Estado) -> Result<(), ErrorDiario> {
    #[cfg(test)]
    if estado.falla_sync {
        return Err(io_err(
            ruta,
            std::io::Error::other("fallo de sync inyectado en test"),
        ));
    }
    let _ = estado;
    fichero.sync_all().map_err(|origen| io_err(ruta, origen))
}

/// Sincroniza el candado, con fallo inyectable en tests (R6).
fn sincronizar_candado(fichero: &File, ruta: &Path, estado: &Estado) -> Result<(), ErrorDiario> {
    #[cfg(test)]
    if estado.falla_sync_candado {
        return Err(io_err(
            ruta,
            std::io::Error::other("fallo de sync del candado inyectado en test"),
        ));
    }
    let _ = estado;
    fichero.sync_all().map_err(|origen| io_err(ruta, origen))
}

/// Sincroniza el directorio padre para que la creación sea durable.
fn sincronizar_directorio(ruta: &Path) -> Result<(), ErrorDiario> {
    let padre = ruta
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = File::open(padre).map_err(|origen| io_err(ruta, origen))?;
    dir.sync_all().map_err(|origen| io_err(ruta, origen))
}

/// Toma el bloqueo exclusivo del fichero con reintentos acotados.
fn bloquear(fichero: &File, ruta: &Path) -> Result<(), ErrorDiario> {
    use std::time::{Duration, Instant};

    const PLAZO: Duration = Duration::from_secs(2);
    const INTERVALO_INICIAL: Duration = Duration::from_micros(50);
    const INTERVALO_MAXIMO: Duration = Duration::from_millis(20);

    let inicio = Instant::now();
    let mut intervalo = INTERVALO_INICIAL;
    loop {
        match fichero.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::Error(origen)) => return Err(io_err(ruta, origen)),
            Err(std::fs::TryLockError::WouldBlock) => {
                let transcurrido = inicio.elapsed();
                if transcurrido >= PLAZO {
                    return Err(ErrorDiario::Bloqueado {
                        ruta: ruta.to_path_buf(),
                    });
                }
                std::thread::sleep(intervalo.min(PLAZO.saturating_sub(transcurrido)));
                intervalo = (intervalo * 2).min(INTERVALO_MAXIMO);
            }
        }
    }
}

/// Convierte un `usize` a `u64` sin panic.
fn a_u64(valor: usize) -> u64 {
    u64::try_from(valor).unwrap_or(u64::MAX)
}

/// Envuelve un `io::Error` con la ruta.
fn io_err(ruta: &Path, origen: std::io::Error) -> ErrorDiario {
    ErrorDiario::Io {
        ruta: ruta.to_path_buf(),
        origen,
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
mod pruebas {
    use super::*;

    fn digest(b: u8) -> Hash {
        [b; 32]
    }

    fn diario(dir: &Path) -> DiarioVotos {
        DiarioVotos::nueva(dir.join("votos.registro"), 7).unwrap()
    }

    #[test]
    fn reserva_reemision_y_conflicto() {
        let dir = tempfile::tempdir().unwrap();
        let d = diario(dir.path());
        let clave = [9u8; 48];
        assert_eq!(
            d.resolver(&clave, 4, &digest(1)).unwrap(),
            ResolucionDiario::Nueva
        );
        assert_eq!(
            d.resolver(&clave, 4, &digest(1)).unwrap(),
            ResolucionDiario::Conocida
        );
        assert_eq!(
            d.resolver(&clave, 4, &digest(2)).unwrap(),
            ResolucionDiario::Conflicto {
                registrado: digest(1)
            }
        );
        // Otra clave y otro n son independientes dentro del mismo CBID.
        assert_eq!(
            d.resolver(&[8u8; 48], 4, &digest(2)).unwrap(),
            ResolucionDiario::Nueva
        );
        assert_eq!(
            d.resolver(&clave, 5, &digest(2)).unwrap(),
            ResolucionDiario::Nueva
        );
        assert_eq!(d.entradas(), 3);
    }

    #[test]
    fn reabrir_conserva_la_reserva() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        {
            let d = DiarioVotos::nueva(&ruta, 7).unwrap();
            assert_eq!(
                d.resolver(&[3u8; 48], 9, &digest(7)).unwrap(),
                ResolucionDiario::Nueva
            );
        }
        let d = DiarioVotos::abrir(&ruta, 7).unwrap();
        assert_eq!(
            d.resolver(&[3u8; 48], 9, &digest(7)).unwrap(),
            ResolucionDiario::Conocida
        );
        assert_eq!(
            d.resolver(&[3u8; 48], 9, &digest(8)).unwrap(),
            ResolucionDiario::Conflicto {
                registrado: digest(7)
            }
        );
    }

    #[test]
    fn cbid_ajeno_se_rechaza() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        {
            let d = DiarioVotos::nueva(&ruta, 7).unwrap();
            assert_eq!(
                d.resolver(&[1u8; 48], 1, &digest(1)).unwrap(),
                ResolucionDiario::Nueva
            );
        }
        assert!(matches!(
            DiarioVotos::abrir(&ruta, 8),
            Err(ErrorDiario::CbidAjeno { .. })
        ));
    }

    #[test]
    fn cola_parcial_se_rechaza() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        {
            let _ = DiarioVotos::nueva(&ruta, 7).unwrap();
        }
        let mut f = OpenOptions::new().append(true).open(&ruta).unwrap();
        f.write_all(&[0u8; 5]).unwrap();
        f.sync_all().unwrap();
        assert!(matches!(
            DiarioVotos::abrir(&ruta, 7),
            Err(ErrorDiario::ColaParcial { .. })
        ));
    }

    #[test]
    fn entrada_corrupta_se_rechaza() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        {
            let d = DiarioVotos::nueva(&ruta, 7).unwrap();
            assert_eq!(
                d.resolver(&[2u8; 48], 2, &digest(2)).unwrap(),
                ResolucionDiario::Nueva
            );
        }
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&ruta)
                .unwrap();
            f.seek(SeekFrom::Start((TAM_CABECERA + 10) as u64)).unwrap();
            f.write_all(&[0xFF]).unwrap();
            f.sync_all().unwrap();
        }
        assert!(matches!(
            DiarioVotos::abrir(&ruta, 7),
            Err(ErrorDiario::Corrupto { .. })
        ));
    }

    #[test]
    fn duplicado_conflictivo_se_rechaza() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        {
            let _ = DiarioVotos::nueva(&ruta, 7).unwrap();
        }
        let clave = [4u8; 48];
        let mut f = OpenOptions::new().append(true).open(&ruta).unwrap();
        f.write_all(&entrada_bytes(7, &clave, 3, &digest(1)))
            .unwrap();
        f.write_all(&entrada_bytes(7, &clave, 3, &digest(2)))
            .unwrap();
        f.sync_all().unwrap();
        assert!(matches!(
            DiarioVotos::abrir(&ruta, 7),
            Err(ErrorDiario::DuplicadoConflictivo { .. })
        ));
    }

    #[test]
    fn sync_fallido_envenena_hasta_reabrir() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        let d = DiarioVotos::nueva(&ruta, 7).unwrap();
        d.fallar_proximo_sync_para_test();
        assert!(matches!(
            d.resolver(&[5u8; 48], 1, &digest(1)),
            Err(ErrorDiario::Io { .. })
        ));
        // Mientras siga envenenado no se rehabilita la firma.
        assert!(matches!(
            d.resolver(&[5u8; 48], 1, &digest(1)),
            Err(ErrorDiario::Envenenado { .. })
        ));
        drop(d);
        // La reapertura valida el log y **acredita la reserva original**: el `write_all` del intento
        // fallido quedó en la caché de página, así que la identidad reservada se recupera y un
        // digest distinto es conflicto. Solo una reapertura válida rehabilita.
        let d = DiarioVotos::abrir(&ruta, 7).expect("reabrir");
        assert_eq!(
            d.resolver(&[5u8; 48], 1, &digest(1)).unwrap(),
            ResolucionDiario::Conocida
        );
        assert_eq!(
            d.resolver(&[5u8; 48], 1, &digest(2)).unwrap(),
            ResolucionDiario::Conflicto {
                registrado: digest(1)
            }
        );
    }

    /// FV-N6-C7-2 · proceso hijo real que reserva, sincroniza y **corta antes de firmar**.
    ///
    /// El hijo se reejecuta con `--exact` sobre este mismo test y la variable de entorno; el padre
    /// comprueba que, al reabrir, la reserva original se acredita (reemisión exacta y conflicto).
    #[test]
    fn hijo_cortado_tras_sync_conserva_reserva() {
        if let Ok(ruta) = std::env::var("FVN6C7_DIARIO_HIJO") {
            // Modo hijo: reserva sincronizada y corte inmediato (sin firmar).
            let d = DiarioVotos::nueva(&ruta, 7).expect("diario hijo");
            assert_eq!(
                d.resolver(&[6u8; 48], 2, &digest(9)).unwrap(),
                ResolucionDiario::Nueva
            );
            std::process::exit(0);
        }
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        let exe = std::env::current_exe().unwrap();
        let salida = std::process::Command::new(exe)
            .args([
                "--exact",
                "votos::diario::pruebas::hijo_cortado_tras_sync_conserva_reserva",
                "--nocapture",
            ])
            .env("FVN6C7_DIARIO_HIJO", &ruta)
            .status()
            .unwrap();
        assert!(salida.success(), "el hijo debió reservar y salir con 0");
        let d = DiarioVotos::abrir(&ruta, 7).expect("reabrir tras hijo");
        assert_eq!(
            d.resolver(&[6u8; 48], 2, &digest(9)).unwrap(),
            ResolucionDiario::Conocida
        );
        assert_eq!(
            d.resolver(&[6u8; 48], 2, &digest(10)).unwrap(),
            ResolucionDiario::Conflicto {
                registrado: digest(9)
            }
        );
    }

    /// FV-N6-C7-2 · segundo **proceso real** sobre el mismo directorio: no obtiene la firma.
    #[test]
    fn segundo_proceso_real_rechazado() {
        if let Ok(ruta) = std::env::var("FVN6C7_DIARIO_SEGUNDO") {
            let rechazado = matches!(
                DiarioVotos::abrir(&ruta, 7),
                Err(ErrorDiario::Bloqueado { .. })
            );
            std::process::exit(if rechazado { 0 } else { 3 });
        }
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        let _padre = DiarioVotos::nueva(&ruta, 7).unwrap();
        let exe = std::env::current_exe().unwrap();
        let salida = std::process::Command::new(exe)
            .args([
                "--exact",
                "votos::diario::pruebas::segundo_proceso_real_rechazado",
                "--nocapture",
            ])
            .env("FVN6C7_DIARIO_SEGUNDO", &ruta)
            .status()
            .unwrap();
        assert!(
            salida.success(),
            "el segundo proceso debió recibir Bloqueado"
        );
    }

    #[test]
    fn segundo_abridor_no_obtiene_el_fichero() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        let _d = DiarioVotos::nueva(&ruta, 7).unwrap();
        // `try_lock` es por open file description: aun en el mismo proceso, el segundo `open`
        // choca con el cerrojo vivo.
        assert!(matches!(
            DiarioVotos::abrir(&ruta, 7),
            Err(ErrorDiario::Bloqueado { .. })
        ));
    }

    /// FV-N6-C7-3 · corrección 5: **SIGKILL real** por canal local. El hijo reserva y sincroniza
    /// (sin firmar), comunica la etapa por `stdout` y espera; el padre confirma la reserva, le envía
    /// la señal 9 (no capturable) y, al reabrir, acredita la misma reserva: reemisión exacta y
    /// conflicto con un digest distinto (el análogo de candidato igual/`h_T` distinto).
    #[test]
    fn sigkill_tras_reserva_conserva_la_reserva() {
        use std::io::BufRead as _;
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::{Command, Stdio};

        if let Ok(ruta) = std::env::var("FVN6C7_DIARIO_SIGKILL") {
            let d = DiarioVotos::nueva(&ruta, 7).expect("diario hijo");
            assert_eq!(
                d.resolver(&[7u8; 48], 4, &digest(0xAB)).unwrap(),
                ResolucionDiario::Nueva
            );
            println!("reservado");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("votos.registro");
        let exe = std::env::current_exe().unwrap();
        let mut hijo = Command::new(exe)
            .args([
                "--exact",
                "votos::diario::pruebas::sigkill_tras_reserva_conserva_la_reserva",
                "--nocapture",
            ])
            .env("FVN6C7_DIARIO_SIGKILL", &ruta)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        {
            let salida = hijo.stdout.take().unwrap();
            let mut lector = std::io::BufReader::new(salida);
            let mut linea = String::new();
            let mut reservo = false;
            while lector.read_line(&mut linea).unwrap() > 0 {
                if linea.contains("reservado") {
                    reservo = true;
                    break;
                }
                linea.clear();
            }
            assert!(reservo, "el hijo debió comunicar la reserva por stdout");
        }
        // SIGKILL real: `Child::kill` manda la señal 9, que no puede capturarse.
        hijo.kill().unwrap();
        let estado = hijo.wait().unwrap();
        assert_eq!(estado.signal(), Some(9), "el hijo murió por SIGKILL");
        // Reapertura: la reserva sincronizada **antes** de firmar se acredita.
        let d = DiarioVotos::abrir(&ruta, 7).expect("reabrir tras SIGKILL");
        assert_eq!(
            d.resolver(&[7u8; 48], 4, &digest(0xAB)).unwrap(),
            ResolucionDiario::Conocida
        );
        assert_eq!(
            d.resolver(&[7u8; 48], 4, &digest(0xCD)).unwrap(),
            ResolucionDiario::Conflicto {
                registrado: digest(0xAB)
            }
        );
    }
}
