//! Códec del protocolo de sincronización y de los anuncios de bloque (C-NET-11, C-WIRE-04).
//!
//! # El trait `Codec` no impone ningún límite de tamaño
//!
//! `read_request`/`read_response` reciben un `AsyncRead` y **nada** acota cuánto leen. El `.take(N)`
//! es responsabilidad de cada implementación. La de referencia del propio crate
//! (`request-response/src/cbor.rs`) lo hace explícitamente; una escrita "de forma natural" con
//! `read_to_end` deja que un peer reserve la memoria que quiera **antes** de que el parser pueda
//! rechazar nada.
//!
//! # Y `.take(N)` por sí solo NO basta
//!
//! `AsyncReadExt::take(N)` acota la lectura a `N` bytes, así que la memoria queda contenida — bien.
//! Pero si el emisor manda **más** de `N`, no produce un error de "demasiado grande": **trunca en
//! silencio**, y lo que falla después es el parseo, con un error de datos corruptos que no dice nada
//! del tamaño. Eso importa: un truncamiento silencioso se clasificaría como `Ilegible` —"este peer
//! habla otro dialecto"— cuando en realidad es `Excedido` —"este peer mandó algo que no debía"—.
//! Así que aquí se lee hasta `N` y **se comprueba si se llegó al tope**.
//!
//! # La familia de bloque se declara, no se adivina
//!
//! [`bloque_desde_bytes`] recibe la familia esperada y **rechaza** otra (F-04). La variante
//! [`bloque_desde_bytes_autotag`] existe para las respuestas, donde el wire lleva el byte de familia
//! explícito por bloque; **nunca** se deduce por longitud.

use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use libp2p::request_response;
use thiserror::Error;

use crate::limites;
use crate::mensaje::{
    BloqueRed, Estado, FamiliaBloque, Fase, MAX_PUNTAS_POST, Peticion, PuntaPow, Respuesta,
    red_desde_discriminante, red_discriminante,
};
use crate::presupuesto::{Presupuesto, Reserva};
use crate::registro::{entrada_a_bytes, entrada_desde_bytes};
use crate::zrxc;
use zx_core::digest::{BlockHash, Digest};
use zx_core::encoding::{compact_size, int};
use zx_core::error::EncodingError;
use zx_core::wire;

/// Máximo de hashes en un locator.
///
/// Un locator es logarítmico por construcción —denso cerca de la punta, espaciado hacia atrás—, así
/// que 64 entradas cubren una cadena de `2^40` bloques de sobra. Cualquier cosa mayor es un peer
/// que no está construyendo un locator, sino gastándonos tiempo.
pub const MAX_LOCATOR: usize = 64;

/// Sobre máximo del códec de un bloque: el byte de familia y el `CompactSize` del contador.
///
/// [`limites::MAX_BLOQUE_RED_BYTES`] mide cabecera + cuerpo; el wire añade el byte de familia y, como
/// mucho, un `CompactSize` de 9 bytes. Esta constante es la holgura que el códec admite por encima.
pub const SOBRE_CODEC_BLOQUE: u64 = 1 + 9;

/// Error del códec de la red.
///
/// Envuelve [`EncodingError`] de `zx-core` y añade solo lo que es específico de estos mensajes: la
/// familia declarada, la red y la fase. Cada caso tiene **su** variante, para que un rechazo diga
/// exactamente qué se rechazó.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorCodec {
    /// Error de codificación de `zx-core` (truncado, contador no mínimo, etc.).
    #[error(transparent)]
    Codificacion(#[from] EncodingError),

    /// `ORDEN-RD1c`: error de una entrada del registro firmado de direcciones dentro de una
    /// respuesta.
    #[error("registro de direcciones: {0}")]
    Registro(#[from] crate::registro::ErrorRegistro),

    /// F-04: el bloque llegó con una familia distinta de la declarada.
    #[error("F-04: familia de bloque inesperada: se esperaba {esperada:?}, llegó {encontrada:?}")]
    FamiliaInesperada {
        /// Familia que el llamante exigía.
        esperada: FamiliaBloque,
        /// Familia que el wire declaró.
        encontrada: FamiliaBloque,
    },

    /// El byte de familia del wire no es ninguna conocida.
    #[error("F-04: familia de bloque desconocida en el wire: {discriminante:#04x}")]
    FamiliaDesconocida {
        /// Byte leído.
        discriminante: u8,
    },

    /// C-NET-11: el bloque supera el tamaño máximo admitido.
    #[error("C-NET-11: el bloque de red mide {bytes} B y el máximo es {max} B")]
    BloqueDemasiadoGrande {
        /// Bytes recibidos.
        bytes: usize,
        /// Cota del códec.
        max: u64,
    },

    /// El byte de red del saludo no es ninguna red conocida.
    #[error("red desconocida en el saludo: {discriminante:#04x}")]
    RedDesconocida {
        /// Byte leído.
        discriminante: u8,
    },

    /// El byte de fase del saludo no es ninguna fase conocida.
    #[error("fase desconocida en el saludo: {discriminante:#04x}")]
    FaseDesconocida {
        /// Byte leído.
        discriminante: u8,
    },

    /// El booleano del wire **MUST** ser `0` o `1`: nada de "cualquier cosa distinta de cero".
    ///
    /// Sin esto habría dos codificaciones del mismo mensaje, y dos codificaciones del mismo mensaje
    /// son maleabilidad — el mismo razonamiento que C-ENC-05 para `CompactSize`.
    #[error("booleano no canónico: {valor:#04x} (MUST ser 0 o 1)")]
    BooleanoNoCanonico {
        /// Byte leído.
        valor: u8,
    },
}

/// El códec de ZEROX para `request-response`.
///
/// Lleva el [`Presupuesto`] porque **es aquí donde se reserva la memoria**. Ponerlo más arriba
/// significaría contabilizar después de haber leído, que es contabilizar tarde.
#[derive(Clone, Debug, Default)]
pub struct ZxCodec {
    presupuesto: Presupuesto,
}

impl ZxCodec {
    /// Uno que comparte presupuesto con los demás.
    ///
    /// **Comparten el contador a propósito**: el recurso que se agota es global, así que repartirlo
    /// por conexión no acotaría la suma. Ver [`crate::presupuesto`].
    #[must_use]
    pub fn con_presupuesto(presupuesto: Presupuesto) -> Self {
        Self { presupuesto }
    }

    /// El presupuesto que usa.
    #[must_use]
    pub const fn presupuesto(&self) -> &Presupuesto {
        &self.presupuesto
    }
}

impl request_response::Codec for ZxCodec {
    type Protocol = StreamProtocol;
    type Request = Peticion;
    type Response = Respuesta;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Peticion>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = leer_acotado(io, limites::MAX_PETICION_BYTES, &self.presupuesto).await?;
        let (datos, _reserva) = zrxc_o_crudo(
            bytes,
            limites::MAX_DESCOMPRIMIDO_PETICION,
            &self.presupuesto,
        )?;
        peticion_desde_bytes(&datos).map_err(a_io)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Respuesta>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = leer_acotado(io, limites::MAX_RESPUESTA_BYTES, &self.presupuesto).await?;
        let (datos, _reserva) = zrxc_o_crudo(
            bytes,
            limites::MAX_DESCOMPRIMIDO_RESPUESTA,
            &self.presupuesto,
        )?;
        respuesta_desde_bytes(&datos).map_err(a_io)
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Peticion,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = peticion_a_bytes(&req);
        // Un emisor que se pasa de su propio límite es un bug nuestro, no de nadie más. Fallar aquí
        // es mejor que mandar algo que el otro extremo va a tirar.
        if bytes.len() as u64 > limites::MAX_PETICION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "la petición supera MAX_PETICION_BYTES",
            ));
        }
        escribir_zrxc(io, &bytes, None).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: Respuesta,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = respuesta_a_bytes(&res);
        if bytes.len() as u64 > limites::MAX_RESPUESTA_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "la respuesta supera MAX_RESPUESTA_BYTES",
            ));
        }
        escribir_zrxc(io, &bytes, None).await
    }
}

/// Escribe un mensaje de sync con ZRX-C **solo si compensa**; si no, crudo.
///
/// Los mensajes pequeños (`Estado`, listas de hashes) viajan crudos: el marco de 35 B costaría más
/// que el ahorro (R-9). El receptor distingue por la magia `ZXC1` ([`zrxc::es_marco`]), que ningún
/// mensaje crudo de ZEROX puede empezar (empiezan por un discriminante `0x00..=0x04`).
async fn escribir_zrxc<T>(
    io: &mut T,
    bytes: &[u8],
    dicc: Option<&zrxc::Diccionario>,
) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let marco = zrxc::comprimir_red(bytes, dicc);
    if marco.len() < bytes.len() {
        io.write_all(&marco).await?;
    } else {
        io.write_all(bytes).await?;
    }
    io.close().await
}

/// Descomprime un mensaje de sync si viene enmarcado; si no, lo devuelve tal cual.
///
/// La [`Reserva`] que devuelve cubre el tamaño descomprimido declarado y **debe vivir hasta que
/// termine el parseo** para que C-NET-21 cuente la memoria real, no solo la comprimida.
fn zrxc_o_crudo(
    bytes: Vec<u8>,
    max_salida: u64,
    p: &Presupuesto,
) -> io::Result<(Vec<u8>, Option<Reserva>)> {
    if !zrxc::es_marco(&bytes) {
        return Ok((bytes, None));
    }
    let cab = zrxc::cabecera(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if cab.len_original > max_salida {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ZRX-C: la salida declarada supera el tope del camino (bomba)",
        ));
    }
    let bytes_declarados = usize::try_from(cab.len_original).unwrap_or(usize::MAX);
    let reserva = p.reservar(bytes_declarados).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "C-NET-21: no queda presupuesto para la salida ZRX-C",
        )
    })?;
    let salida = zrxc::descomprimir_por_id(&bytes, &zrxc::Limites::nuevo(max_salida))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok((salida, Some(reserva)))
}

/// Trozo de lectura de [`leer_acotado`] (`ORDEN-W06d6`, RI-3a #2).
///
/// **64 KiB.** Antes, `leer_acotado` reservaba `max + 1` (hasta ≈25,6 MB en una respuesta) **antes**
/// de leer un solo byte. Un par que abre varios flujos de sincronización y no escribe nada retenía
/// esa reserva completa durante todo `TIMEOUT_SYNC`, y con menos flujos que `MAX_STREAMS_SYNC`
/// bastaba para agotar el presupuesto agregado (`Presupuesto`, 256 MiB) — confirmado
/// (`REVISION-RI-3a.md` hallazgo 2). Reservando por trozos, lo que un par silencioso retiene nunca
/// pasa de un trozo: el coste de un ataque de silencio deja de escalar con `MAX_RESPUESTA_BYTES`.
pub const TROZO_LECTURA_BYTES: usize = 64 * 1024;

/// Lee hasta `max` bytes y **distingue truncamiento de tamaño legítimo**.
///
/// `ORDEN-W06d6` (RI-3a #2): la reserva es **incremental**, en trozos de [`TROZO_LECTURA_BYTES`],
/// cada uno pedido **antes** de leerlo (C-NET-21 se mantiene: nunca se lee sin haber reservado
/// primero lo que se va a leer). Lo reservado en cualquier instante nunca supera lo ya leído más un
/// trozo — nunca el máximo del mensaje entero por adelantado. Todas las reservas de esta lectura se
/// sueltan juntas al terminar (éxito, exceso o error de E/S): el total en vuelo mientras la lectura
/// está en curso es exactamente lo que se ha leído hasta ahora (redondeado hacia arriba a trozos).
///
/// Se pide `max + 1` en total (vía `.take`): si llegan `max + 1`, es que había más de lo permitido
/// y se rechaza como exceso. Con `take(max)` a secas, el mismo caso llegaría al parser como datos
/// corruptos, y el peer se clasificaría como `Ilegible` en vez de `Excedido` (C-NET-05).
async fn leer_acotado<T>(io: &mut T, max: u64, p: &Presupuesto) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let max_usize = usize::try_from(max).unwrap_or(usize::MAX);
    let mut buf = Vec::new();
    // Las reservas de todos los trozos de esta lectura viven hasta el final de la función (éxito o
    // error): sueltan su cupo juntas, como un lote, no una a una a medida que se leen — pero cada
    // una se pidió **antes** de leer su trozo, así que el máximo en vuelo en cualquier instante
    // durante la lectura es `trozos_leídos_hasta_ahora × TROZO_LECTURA_BYTES`, nunca `max + 1`.
    let mut reservas = Vec::new();
    let mut acotado = io.take(max.saturating_add(1));
    loop {
        let reserva = p.reservar(TROZO_LECTURA_BYTES).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "C-NET-21: no queda presupuesto de memoria en vuelo",
            )
        })?;
        reservas.push(reserva);

        let inicio = buf.len();
        buf.resize(inicio.saturating_add(TROZO_LECTURA_BYTES), 0);
        let destino = buf.get_mut(inicio..).unwrap_or(&mut []);
        let leidos = acotado.read(destino).await?;
        buf.truncate(inicio.saturating_add(leidos));

        if leidos == 0 {
            break; // EOF: el otro extremo cerró (o `.take` agotó su cupo de `max + 1`).
        }
        if buf.len() > max_usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "C-NET-11: el mensaje supera el límite de tamaño",
            ));
        }
    }
    Ok(buf)
    // `reservas` se suelta aquí y devuelve todo el cupo — también por los `?` de arriba.
}

fn a_io(e: ErrorCodec) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn truncado(que: &'static str) -> ErrorCodec {
    let _ = que;
    ErrorCodec::Codificacion(EncodingError::Truncado {
        esperados: 1,
        disponibles: 0,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Bloque
// ─────────────────────────────────────────────────────────────────────────────

/// Serializa un bloque de red, con su byte de familia delante.
#[must_use]
pub fn bloque_a_bytes(b: &BloqueRed) -> Vec<u8> {
    let mut out = Vec::new();
    int::escribir_u8(&mut out, b.familia().discriminante());
    match b {
        BloqueRed::Pow {
            cabecera,
            txs,
            testigos,
        } => {
            out.extend_from_slice(&wire::cabecera_a_bytes(cabecera));
            escribir_cuerpo(&mut out, txs, testigos);
        }
        BloqueRed::Post {
            cabecera,
            justificacion,
            txs,
            testigos,
        } => {
            // `ORDEN-W06d3` decisión 1: mismo orden que [`zx_core::wire_dag::bloque_dag_a_bytes`]
            // (cabecera ‖ justificación PoT ‖ cuerpo) — es también lo que `zx-storage` persiste, así
            // que un `BloqueRed::Post` y el `BloqueDag` que guarda el almacén tienen el mismo códec.
            out.extend_from_slice(&zx_core::preimage::dag::dag_header_a_bytes(cabecera));
            justificacion.escribir(&mut out);
            escribir_cuerpo(&mut out, txs, testigos);
        }
    }
    out
}

/// Escribe el cuerpo común: contador de transacciones y cada `(tx, testigos)`.
fn escribir_cuerpo(out: &mut Vec<u8>, txs: &[zx_core::tx::Tx], testigos: &[Vec<Vec<u8>>]) {
    compact_size::escribir(out, txs.len() as u64);
    for (i, tx) in txs.iter().enumerate() {
        let vacio = Vec::new();
        let t = testigos.get(i).unwrap_or(&vacio);
        wire::tx_a_bytes(out, tx, t);
    }
}

/// Deserializa un bloque **exigiendo** la familia declarada (F-04).
///
/// # Errores
/// [`ErrorCodec`] con la familia inesperada o desconocida, el exceso de tamaño, o el error de
/// codificación del campo que no decodifique.
pub fn bloque_desde_bytes(
    bytes: &[u8],
    familia: FamiliaBloque,
) -> Result<(BloqueRed, &[u8]), ErrorCodec> {
    let max = limites::MAX_BLOQUE_RED_BYTES + SOBRE_CODEC_BLOQUE;
    if bytes.len() as u64 > max {
        return Err(ErrorCodec::BloqueDemasiadoGrande {
            bytes: bytes.len(),
            max,
        });
    }

    let (disc, r) = int::leer_u8(bytes)?;
    let encontrada = FamiliaBloque::desde_byte(disc).ok_or(ErrorCodec::FamiliaDesconocida {
        discriminante: disc,
    })?;
    if encontrada != familia {
        return Err(ErrorCodec::FamiliaInesperada {
            esperada: familia,
            encontrada,
        });
    }
    bloque_cuerpo(r, familia)
}

/// Deserializa un bloque tomando la familia del **byte de familia del wire**.
///
/// Es la ruta de las respuestas: el wire lleva la familia explícita por bloque y el parser la
/// **exige** contra el cuerpo, sin deducirla por longitud.
pub fn bloque_desde_bytes_autotag(bytes: &[u8]) -> Result<(BloqueRed, &[u8]), ErrorCodec> {
    let (disc, _) = int::leer_u8(bytes)?;
    let familia = FamiliaBloque::desde_byte(disc).ok_or(ErrorCodec::FamiliaDesconocida {
        discriminante: disc,
    })?;
    bloque_desde_bytes(bytes, familia)
}

/// Parsea cabecera y cuerpo una vez ya comprobada la familia.
///
/// PoST usa directamente [`zx_core::wire_dag::bloque_dag_desde_bytes`] (cabecera, justificación PoT
/// y cuerpo en un único parser, ya acotado en `pot_bundle_count` antes de reservar): es el mismo
/// códec que `zx-storage` persiste, así que no hay dos formas de leer un bloque PoST (`ORDEN-W06d3`
/// decisión 1). PoW no lleva justificación y sigue con su propio parser de cabecera + cuerpo.
fn bloque_cuerpo(bytes: &[u8], familia: FamiliaBloque) -> Result<(BloqueRed, &[u8]), ErrorCodec> {
    match familia {
        FamiliaBloque::Pow => {
            let (cabecera, r) = wire::cabecera_desde_bytes(bytes)?;
            let (n_tx, mut r) = leer_contador(r, usize::MAX)?;
            let mut txs = Vec::with_capacity(n_tx.min(4096));
            let mut testigos = Vec::with_capacity(n_tx.min(4096));
            for _ in 0..n_tx {
                let ((tx, t), resto) = wire::tx_desde_bytes(r)?;
                txs.push(tx);
                testigos.push(t);
                r = resto;
            }
            Ok((
                BloqueRed::Pow {
                    cabecera,
                    txs,
                    testigos,
                },
                r,
            ))
        }
        FamiliaBloque::Post => {
            let (bloque_dag, r) = zx_core::wire_dag::bloque_dag_desde_bytes(bytes)?;
            let cabecera = bloque_dag.cabecera;
            let justificacion = bloque_dag.justificacion.clone();
            let txs = bloque_dag.txs().to_vec();
            let testigos = bloque_dag.testigos().to_vec();
            Ok((
                BloqueRed::Post {
                    cabecera,
                    justificacion,
                    txs,
                    testigos,
                },
                r,
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Petición
// ─────────────────────────────────────────────────────────────────────────────

/// Serializa una petición.
#[must_use]
pub fn peticion_a_bytes(p: &Peticion) -> Vec<u8> {
    let mut b = Vec::new();
    int::escribir_u8(&mut b, p.discriminante());
    match p {
        Peticion::Estado => {}
        Peticion::CabecerasPow { locator, parada } => {
            compact_size::escribir(&mut b, locator.len() as u64);
            for h in locator {
                b.extend_from_slice(h.as_bytes());
            }
            match parada {
                Some(h) => {
                    int::escribir_u8(&mut b, 1);
                    b.extend_from_slice(h.as_bytes());
                }
                None => int::escribir_u8(&mut b, 0),
            }
        }
        Peticion::Bloques { hashes } => {
            compact_size::escribir(&mut b, hashes.len() as u64);
            for h in hashes {
                b.extend_from_slice(h.as_bytes());
            }
        }
        Peticion::Registro { desde } => {
            int::escribir_u64(&mut b, *desde);
        }
        Peticion::RegistroDirecciones { desde } => {
            int::escribir_u64(&mut b, *desde);
        }
        Peticion::Prueba { huella } => {
            b.extend_from_slice(huella);
        }
    }
    b
}

/// Deserializa una petición.
///
/// # Errores
/// El error de codificación que corresponda. **Nunca entra en pánico** (C-WIRE-05).
pub fn peticion_desde_bytes(bytes: &[u8]) -> Result<Peticion, ErrorCodec> {
    let (disc, r) = int::leer_u8(bytes)?;
    let (p, resto) = match disc {
        Peticion::DISC_ESTADO => (Peticion::Estado, r),
        Peticion::DISC_CABECERAS_POW => {
            let (locator, r) = leer_hashes(r, MAX_LOCATOR)?;
            let (tiene, r) = int::leer_u8(r)?;
            let (parada, r) = match tiene {
                0 => (None, r),
                1 => {
                    let (h, r) = int::leer_32(r)?;
                    (Some(BlockHash::from_digest(Digest::from_bytes(h))), r)
                }
                // C-ENC-09 · un booleano que no es 0 ni 1 es una segunda codificación del mismo
                // valor lógico, y solo se acepta una.
                otro => return Err(ErrorCodec::BooleanoNoCanonico { valor: otro }),
            };
            (Peticion::CabecerasPow { locator, parada }, r)
        }
        Peticion::DISC_BLOQUES => {
            let (hashes, r) = leer_hashes(r, limites::MAX_HASHES_POR_PETICION)?;
            (Peticion::Bloques { hashes }, r)
        }
        Peticion::DISC_REGISTRO => {
            let (desde, r) = int::leer_u64(r)?;
            (Peticion::Registro { desde }, r)
        }
        Peticion::DISC_REGISTRO_DIRECCIONES => {
            let (desde, r) = int::leer_u64(r)?;
            (Peticion::RegistroDirecciones { desde }, r)
        }
        Peticion::DISC_PRUEBA => {
            let (huella, r) = int::leer_32(r)?;
            (Peticion::Prueba { huella }, r)
        }
        otro => {
            return Err(ErrorCodec::Codificacion(EncodingError::LockDesconocido {
                discriminante: otro,
            }));
        }
    };

    // Nada de relleno. Sin esta comprobación, la basura sobrante viaja gratis.
    if resto.is_empty() {
        Ok(p)
    } else {
        Err(truncado("bytes sobrantes tras la petición"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Respuesta
// ─────────────────────────────────────────────────────────────────────────────

/// Serializa una respuesta.
#[must_use]
pub fn respuesta_a_bytes(r: &Respuesta) -> Vec<u8> {
    let mut b = Vec::new();
    int::escribir_u8(&mut b, r.discriminante());
    match r {
        Respuesta::Estado(e) => escribir_estado(&mut b, e),
        Respuesta::CabecerasPow(cs) => {
            compact_size::escribir(&mut b, cs.len() as u64);
            for c in cs {
                b.extend_from_slice(&wire::cabecera_a_bytes(c));
            }
        }
        Respuesta::Bloques(bs) => {
            compact_size::escribir(&mut b, bs.len() as u64);
            for bl in bs {
                b.extend_from_slice(&bloque_a_bytes(bl));
            }
        }
        Respuesta::NoDisponible => {}
        Respuesta::Registro {
            desde,
            bloques,
            longitud,
        } => {
            int::escribir_u64(&mut b, *desde);
            compact_size::escribir(&mut b, bloques.len() as u64);
            for bl in bloques {
                b.extend_from_slice(&bloque_a_bytes(bl));
            }
            int::escribir_u64(&mut b, *longitud);
        }
        Respuesta::RegistroDirecciones {
            desde,
            entradas,
            total,
        } => {
            int::escribir_u64(&mut b, *desde);
            compact_size::escribir(&mut b, entradas.len() as u64);
            for e in entradas {
                b.extend_from_slice(&entrada_a_bytes(e));
            }
            int::escribir_u64(&mut b, *total);
        }
        Respuesta::Prueba { huella, bytes } => {
            b.extend_from_slice(huella);
            compact_size::escribir(&mut b, bytes.len() as u64);
            b.extend_from_slice(bytes);
        }
    }
    b
}

/// Deserializa una respuesta.
///
/// # Errores
/// El error de codificación que corresponda. **Nunca entra en pánico** (C-WIRE-05).
pub fn respuesta_desde_bytes(bytes: &[u8]) -> Result<Respuesta, ErrorCodec> {
    let (disc, r) = int::leer_u8(bytes)?;
    let (resp, resto) = match disc {
        Respuesta::DISC_ESTADO => {
            let (e, r) = leer_estado(r)?;
            (Respuesta::Estado(e), r)
        }
        Respuesta::DISC_CABECERAS_POW => {
            let (n, mut r) = leer_contador(r, limites::MAX_CABECERAS_POR_RESPUESTA)?;
            let mut cs = Vec::with_capacity(n);
            for _ in 0..n {
                let (c, resto) = wire::cabecera_desde_bytes(r)?;
                cs.push(c);
                r = resto;
            }
            (Respuesta::CabecerasPow(cs), r)
        }
        Respuesta::DISC_BLOQUES => {
            let (n, mut r) = leer_contador(r, limites::MAX_BLOQUES_POR_RESPUESTA)?;
            let mut bs = Vec::with_capacity(n);
            for _ in 0..n {
                let (bloque, resto) = bloque_desde_bytes_autotag(r)?;
                bs.push(bloque);
                r = resto;
            }
            (Respuesta::Bloques(bs), r)
        }
        Respuesta::DISC_NO_DISPONIBLE => (Respuesta::NoDisponible, r),
        Respuesta::DISC_REGISTRO => {
            let (desde, r) = int::leer_u64(r)?;
            let (n, mut r) = leer_contador(r, limites::MAX_BLOQUES_POR_RESPUESTA)?;
            let mut bloques = Vec::with_capacity(n);
            for _ in 0..n {
                let (bloque, resto) = bloque_desde_bytes_autotag(r)?;
                bloques.push(bloque);
                r = resto;
            }
            let (longitud, r) = int::leer_u64(r)?;
            (
                Respuesta::Registro {
                    desde,
                    bloques,
                    longitud,
                },
                r,
            )
        }
        Respuesta::DISC_REGISTRO_DIRECCIONES => {
            let (desde, r) = int::leer_u64(r)?;
            let (n, mut r) = leer_contador(r, limites::MAX_ENTRADAS_REGISTRO_POR_PAGINA)?;
            let mut entradas = Vec::with_capacity(n);
            for _ in 0..n {
                let (entrada, resto) = entrada_desde_bytes(r)?;
                entradas.push(entrada);
                r = resto;
            }
            let (total, r) = int::leer_u64(r)?;
            (
                Respuesta::RegistroDirecciones {
                    desde,
                    entradas,
                    total,
                },
                r,
            )
        }
        Respuesta::DISC_PRUEBA => {
            let (huella, r) = int::leer_32(r)?;
            // El contador es una **longitud de bytes**, no un número de elementos: se acota contra
            // el tope del camino, no contra `MAX_ELEMENTOS_DECLARADOS`. No se rechaza aquí por
            // superar `MAX_RESPUESTA_PRUEBA_BYTES`: eso lo decide el servicio, que además penaliza
            // (orden Q3); el códec solo impide la reserva por encima del tope de sync.
            let (n, r) = compact_size::leer(r)?;
            let n = usize::try_from(n)
                .map_err(|_| truncado("longitud de la prueba fuera del direccionamiento"))?;
            let (bytes, r) = r
                .split_at_checked(n)
                .ok_or_else(|| truncado("bytes de la prueba truncados"))?;
            (
                Respuesta::Prueba {
                    huella,
                    bytes: bytes.to_vec(),
                },
                r,
            )
        }
        otro => {
            return Err(ErrorCodec::Codificacion(EncodingError::LockDesconocido {
                discriminante: otro,
            }));
        }
    };

    if resto.is_empty() {
        Ok(resp)
    } else {
        Err(truncado("bytes sobrantes tras la respuesta"))
    }
}

/// Escribe el saludo `Estado` con su longitud exacta.
fn escribir_estado(b: &mut Vec<u8>, e: &Estado) {
    b.extend_from_slice(e.hash_genesis.as_bytes());
    int::escribir_u8(b, red_discriminante(e.red));
    int::escribir_u8(b, e.fase.discriminante());
    b.extend_from_slice(e.punta_pow.hash.as_bytes());
    int::escribir_u32(b, e.punta_pow.altura);
    b.extend_from_slice(&e.punta_pow.trabajo_acumulado);
    match e.terminal {
        Some(h) => {
            int::escribir_u8(b, 1);
            b.extend_from_slice(h.as_bytes());
        }
        None => int::escribir_u8(b, 0),
    }
    compact_size::escribir(b, e.puntas_post.len() as u64);
    for h in &e.puntas_post {
        b.extend_from_slice(h.as_bytes());
    }
    b.extend_from_slice(&e.blue_work_virtual);
    // `ORDEN-W06d6` decisión 1: campo nuevo, añadido al **final** del saludo (no se reordena nada
    // de lo existente).
    int::escribir_u64(b, e.longitud_registro);
}

/// Lee un saludo `Estado`.
fn leer_estado(bytes: &[u8]) -> Result<(Estado, &[u8]), ErrorCodec> {
    let (genesis, r) = int::leer_32(bytes)?;
    let (red_b, r) = int::leer_u8(r)?;
    let red = red_desde_discriminante(red_b).ok_or(ErrorCodec::RedDesconocida {
        discriminante: red_b,
    })?;
    let (fase_b, r) = int::leer_u8(r)?;
    let fase = Fase::desde_byte(fase_b).ok_or(ErrorCodec::FaseDesconocida {
        discriminante: fase_b,
    })?;
    let (hash_pow, r) = int::leer_32(r)?;
    let (altura, r) = int::leer_u32(r)?;
    let (trabajo, r) = int::leer_32(r)?;
    let (tiene_terminal, r) = int::leer_u8(r)?;
    let (terminal, r) = match tiene_terminal {
        0 => (None, r),
        1 => {
            let (h, r) = int::leer_32(r)?;
            (Some(BlockHash::from_digest(Digest::from_bytes(h))), r)
        }
        otro => return Err(ErrorCodec::BooleanoNoCanonico { valor: otro }),
    };
    let (punta_post, r) = leer_hashes(r, MAX_PUNTAS_POST)?;
    let (blue_work, r) = int::leer_32(r)?;
    let (longitud_registro, r) = int::leer_u64(r)?;

    let estado = Estado {
        hash_genesis: BlockHash::from_digest(Digest::from_bytes(genesis)),
        red,
        fase,
        punta_pow: PuntaPow {
            hash: BlockHash::from_digest(Digest::from_bytes(hash_pow)),
            altura,
            trabajo_acumulado: trabajo,
        },
        terminal,
        puntas_post: punta_post,
        blue_work_virtual: blue_work,
        longitud_registro,
    };
    Ok((estado, r))
}

// ─────────────────────────────────────────────────────────────────────────────
// Auxiliares
// ─────────────────────────────────────────────────────────────────────────────

/// Lee un contador y lo acota **antes** de reservar (C-WIRE-04).
fn leer_contador(bytes: &[u8], max: usize) -> Result<(usize, &[u8]), ErrorCodec> {
    let (n, r) = compact_size::leer(bytes)?;
    let tope = (max as u64).min(wire::MAX_ELEMENTOS_DECLARADOS);
    if n > tope {
        return Err(ErrorCodec::Codificacion(
            EncodingError::DemasiadosElementos {
                declarados: n,
                maximo: tope,
            },
        ));
    }
    let n = usize::try_from(n).map_err(|_| {
        ErrorCodec::Codificacion(EncodingError::DemasiadosElementos {
            declarados: n,
            maximo: tope,
        })
    })?;
    Ok((n, r))
}

fn leer_hashes(bytes: &[u8], max: usize) -> Result<(Vec<BlockHash>, &[u8]), ErrorCodec> {
    let (n, mut r) = leer_contador(bytes, max)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let (h, resto) = int::leer_32(r)?;
        v.push(BlockHash::from_digest(Digest::from_bytes(h)));
        r = resto;
    }
    Ok((v, r))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{
        ErrorCodec, MAX_LOCATOR, ZxCodec, bloque_a_bytes, bloque_desde_bytes,
        bloque_desde_bytes_autotag, peticion_a_bytes, peticion_desde_bytes, respuesta_a_bytes,
        respuesta_desde_bytes,
    };
    use crate::limites;
    use crate::mensaje::{
        BloqueRed, Estado, FamiliaBloque, Fase, MAX_PUNTAS_POST, Peticion, PuntaPow, Respuesta,
    };
    use crate::presupuesto::Presupuesto;
    use crate::registro::EntradaRegistro;
    use futures::AsyncWriteExt;
    use futures_ringbuf::Endpoint;
    use libp2p::multiaddr::Protocol;
    use libp2p::request_response::Codec;
    use libp2p::{Multiaddr, StreamProtocol};
    use zx_core::amount::Amount;
    use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot, TxId};
    use zx_core::firma::{ClavePublica, Firma};
    use zx_core::preimage::block::BlockHeader;
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_core::red::Red;
    use zx_core::tx::{Lock, OutPoint, Tx, TxIn, TxOut};
    use zx_core::wire_dag::{JustificacionPot, PotCheckpoints};

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn proto() -> StreamProtocol {
        StreamProtocol::new("/zx-dev/1")
    }

    fn cabecera(n: u8) -> BlockHeader {
        BlockHeader {
            consensus_branch_id: 0xa8b4_66a7,
            prev_hash: h(n),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([n ^ 0xff; 32])),
            timestamp: 1_788_480_000 + u64::from(n),
            bits: 0x1c07_fff8,
            nonce: u64::from(n),
            height: u32::from(n),
        }
    }

    fn cabecera_post(n: u8) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xa8b4_66a7,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([n ^ 0x55; 32])),
            timestamp: 1_788_480_000 + u64::from(n),
            height: 0,
            slot: u64::from(n),
            pot_output: [n; 16],
            rango_solucion: 1,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([n ^ 0xaa; 32])),
            padres: PadresDag::nuevo(h(n), &[]).unwrap(),
            sello: [n; 64],
        }
    }

    fn tx_simple(n: u8) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: OutPoint {
                    prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                    prev_index: 0,
                },
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(1_000).unwrap(),
                lock: Lock::PubKey {
                    pubkey: ClavePublica::desde_bytes([n; 32]),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: zx_core::tx::ExtensionTx::Ninguna,
        }
    }

    fn bloque_pow(n: u8) -> BloqueRed {
        BloqueRed::Pow {
            cabecera: cabecera(n),
            txs: vec![tx_simple(n)],
            testigos: vec![vec![vec![0x11; 64]]],
        }
    }

    /// Una justificación PoT no vacía (dos portadores), para ejercitar de verdad el nuevo campo del
    /// wire (`ORDEN-W06d3` decisión 1), no solo el caso trivial `vacia()`.
    fn justificacion_simple(n: u8) -> JustificacionPot {
        let portador = PotCheckpoints::desde_outputs([[n; 16]; 8]);
        JustificacionPot::nueva(vec![portador, portador]).expect("2 <= MAX_BUNDLES_POT")
    }

    fn bloque_post(n: u8) -> BloqueRed {
        BloqueRed::Post {
            cabecera: cabecera_post(n),
            justificacion: justificacion_simple(n),
            txs: vec![tx_simple(n)],
            testigos: vec![vec![vec![0x22; 64]]],
        }
    }

    fn estado() -> Estado {
        Estado {
            hash_genesis: h(0),
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: h(1),
                altura: 12_345,
                trabajo_acumulado: [0xab; 32],
            },
            terminal: Some(h(9)),
            puntas_post: vec![h(2), h(3)],
            blue_work_virtual: [0xcd; 32],
            longitud_registro: 777,
        }
    }

    /// Una entrada `ZXREG1` sintáctica (la firma no verifica; el códec no la comprueba).
    fn entrada_registro(n: u8) -> EntradaRegistro {
        EntradaRegistro {
            version: crate::registro::VERSION,
            red: Red::Dev,
            productor: ClavePublica::desde_bytes([n; 32]),
            epoch: u64::from(n),
            direcciones: vec![Multiaddr::from(Protocol::Ip4(std::net::Ipv4Addr::new(
                10, 0, 0, n,
            )))],
            firma: Firma::desde_bytes([n; 64]),
        }
    }

    fn todas_las_peticiones() -> Vec<Peticion> {
        vec![
            Peticion::Estado,
            Peticion::CabecerasPow {
                locator: vec![],
                parada: None,
            },
            Peticion::CabecerasPow {
                locator: vec![h(1), h(2), h(3)],
                parada: Some(h(9)),
            },
            Peticion::Bloques {
                hashes: vec![h(4), h(5)],
            },
            Peticion::Registro { desde: 0 },
            Peticion::Registro { desde: 123_456 },
            Peticion::RegistroDirecciones { desde: 7 },
        ]
    }

    fn todas_las_respuestas() -> Vec<Respuesta> {
        vec![
            Respuesta::Estado(estado()),
            Respuesta::CabecerasPow(vec![]),
            Respuesta::CabecerasPow((0..5).map(cabecera).collect()),
            Respuesta::Bloques(vec![]),
            Respuesta::Bloques(vec![bloque_pow(1), bloque_post(2)]),
            Respuesta::NoDisponible,
            Respuesta::Registro {
                desde: 0,
                bloques: vec![],
                longitud: 0,
            },
            Respuesta::Registro {
                desde: 3,
                bloques: vec![bloque_pow(1), bloque_post(2)],
                longitud: 5,
            },
            Respuesta::RegistroDirecciones {
                desde: 7,
                entradas: vec![entrada_registro(1), entrada_registro(2)],
                total: 9,
            },
        ]
    }

    // ── Ida y vuelta, sin Swarm ──────────────────────────────────────────────

    #[test]
    fn todas_las_peticiones_dan_la_vuelta() {
        for p in todas_las_peticiones() {
            let b = peticion_a_bytes(&p);
            assert_eq!(peticion_desde_bytes(&b).unwrap(), p, "{p:?}");
        }
    }

    #[test]
    fn todas_las_respuestas_dan_la_vuelta() {
        for r in todas_las_respuestas() {
            let b = respuesta_a_bytes(&r);
            assert_eq!(respuesta_desde_bytes(&b).unwrap(), r, "{r:?}");
        }
    }

    /// Cada bloque da la vuelta por su familia declarada y por autotag.
    #[test]
    fn los_bloques_dan_la_vuelta_por_familia() {
        for b in [bloque_pow(1), bloque_post(2)] {
            let bytes = bloque_a_bytes(&b);
            let (leido, resto) = bloque_desde_bytes(&bytes, b.familia()).unwrap();
            assert_eq!(leido, b);
            assert!(resto.is_empty());
            let (leido2, resto2) = bloque_desde_bytes_autotag(&bytes).unwrap();
            assert_eq!(leido2, b);
            assert!(resto2.is_empty());
        }
    }

    /// **La ida y vuelta por un stream real**, con el patrón de `request-response/src/cbor.rs`.
    #[tokio::test]
    async fn el_codec_da_la_vuelta_por_un_stream() {
        for p in todas_las_peticiones() {
            let (mut a, mut b) = Endpoint::pair(4096, 4096);
            let mut codec = ZxCodec::default();

            codec
                .write_request(&proto(), &mut a, p.clone())
                .await
                .expect("escribe");
            a.close().await.unwrap();

            let leida = codec.read_request(&proto(), &mut b).await.expect("lee");
            assert_eq!(leida, p);
        }

        for r in todas_las_respuestas() {
            let (mut a, mut b) = Endpoint::pair(4 * 1024 * 1024, 4 * 1024 * 1024);
            let mut codec = ZxCodec::default();

            codec
                .write_response(&proto(), &mut a, r.clone())
                .await
                .expect("escribe");
            a.close().await.unwrap();

            let leida = codec.read_response(&proto(), &mut b).await.expect("lee");
            assert_eq!(leida, r);
        }
    }

    // ── Familia declarada (F-04) ─────────────────────────────────────────────

    /// **Familia cambiada: se rechaza con su error, sin adivinar por longitud.**
    #[test]
    fn una_familia_cambiada_se_rechaza() {
        let bytes_pow = bloque_a_bytes(&bloque_pow(1));
        let e = bloque_desde_bytes(&bytes_pow, FamiliaBloque::Post).unwrap_err();
        assert!(
            matches!(
                e,
                ErrorCodec::FamiliaInesperada {
                    esperada: FamiliaBloque::Post,
                    encontrada: FamiliaBloque::Pow
                }
            ),
            "{e}"
        );

        let bytes_post = bloque_a_bytes(&bloque_post(2));
        let e = bloque_desde_bytes(&bytes_post, FamiliaBloque::Pow).unwrap_err();
        assert!(
            matches!(
                e,
                ErrorCodec::FamiliaInesperada {
                    esperada: FamiliaBloque::Pow,
                    encontrada: FamiliaBloque::Post
                }
            ),
            "{e}"
        );
    }

    /// Un byte de familia desconocido se rechaza, no se interpreta como PoW.
    #[test]
    fn una_familia_desconocida_se_rechaza() {
        let mut bytes = bloque_a_bytes(&bloque_pow(1));
        if let Some(primero) = bytes.first_mut() {
            *primero = 0x7f;
        }
        let e = bloque_desde_bytes_autotag(&bytes).unwrap_err();
        assert!(
            matches!(
                e,
                ErrorCodec::FamiliaDesconocida {
                    discriminante: 0x7f
                }
            ),
            "{e}"
        );
    }

    // ── Límites de tamaño y contadores ───────────────────────────────────────

    /// **El matiz que casi se cuela: `.take(N)` trunca en silencio.**
    #[tokio::test]
    async fn una_peticion_demasiado_grande_se_rechaza_por_tamano_y_no_por_parseo() {
        let exceso = (limites::MAX_PETICION_BYTES + 1_000) as usize;
        let (mut a, mut b) = Endpoint::pair(exceso + 4096, exceso + 4096);

        let basura = vec![Peticion::DISC_ESTADO; exceso];
        a.write_all(&basura).await.unwrap();
        a.close().await.unwrap();

        let e = ZxCodec::default()
            .read_request(&proto(), &mut b)
            .await
            .expect_err("MUST rechazarse");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            e.to_string().contains("C-NET-11"),
            "el error debe decir que es por tamaño, no por parseo: {e}"
        );
    }

    /// Un bloque por encima del máximo se rechaza con su error, antes de parsear.
    #[test]
    fn un_bloque_demasiado_grande_se_rechaza() {
        let max = limites::MAX_BLOQUE_RED_BYTES + super::SOBRE_CODEC_BLOQUE;
        let basura = vec![FamiliaBloque::DISC_POW; (max + 1) as usize];
        let e = bloque_desde_bytes(&basura, FamiliaBloque::Pow).unwrap_err();
        assert!(matches!(e, ErrorCodec::BloqueDemasiadoGrande { .. }), "{e}");
    }

    /// **C-NET-21 · sin presupuesto, no se lee.**
    #[tokio::test]
    async fn sin_presupuesto_la_lectura_se_rechaza() {
        let p = Presupuesto::nuevo(10);
        let mut codec = ZxCodec::con_presupuesto(p.clone());

        let (mut a, mut b) = Endpoint::pair(4096, 4096);
        let bytes = peticion_a_bytes(&Peticion::Estado);
        futures::AsyncWriteExt::write_all(&mut a, &bytes)
            .await
            .unwrap();
        a.close().await.unwrap();

        let e = codec
            .read_request(&proto(), &mut b)
            .await
            .expect_err("MUST rechazarse por presupuesto");
        assert_eq!(e.kind(), std::io::ErrorKind::OutOfMemory);
        assert!(e.to_string().contains("C-NET-21"), "{e}");
        assert_eq!(p.en_vuelo(), 0);
    }

    /// **La reserva se devuelve tras una lectura correcta.**
    #[tokio::test]
    async fn una_lectura_correcta_devuelve_su_reserva() {
        let p = Presupuesto::nuevo(crate::presupuesto::PRESUPUESTO_BYTES);
        let mut codec = ZxCodec::con_presupuesto(p.clone());

        for _ in 0..50 {
            let (mut a, mut b) = Endpoint::pair(4096, 4096);
            codec
                .write_request(&proto(), &mut a, Peticion::Estado)
                .await
                .unwrap();
            a.close().await.unwrap();
            codec.read_request(&proto(), &mut b).await.unwrap();
            assert_eq!(p.en_vuelo(), 0, "cada lectura devuelve lo suyo");
        }
    }

    /// **El contador mentiroso, el ataque más barato.**
    #[test]
    fn un_locator_mentiroso_se_rechaza_sin_reservar() {
        use zx_core::encoding::compact_size;
        for declarados in [MAX_LOCATOR as u64 + 1, u32::MAX as u64, u64::MAX] {
            let mut b = vec![Peticion::DISC_CABECERAS_POW];
            compact_size::escribir(&mut b, declarados);
            let e = peticion_desde_bytes(&b).expect_err("MUST rechazarse");
            assert!(
                matches!(
                    e,
                    ErrorCodec::Codificacion(
                        zx_core::error::EncodingError::DemasiadosElementos { .. }
                    )
                ),
                "declarar {declarados} hashes debe fallar por la cota: {e}"
            );
        }
    }

    /// Una petición de bloques con más hashes que el límite se rechaza.
    #[test]
    fn una_peticion_con_demasiados_hashes_se_rechaza() {
        use zx_core::encoding::compact_size;
        let mut b = vec![Peticion::DISC_BLOQUES];
        compact_size::escribir(&mut b, (limites::MAX_HASHES_POR_PETICION + 1) as u64);
        let e = peticion_desde_bytes(&b).expect_err("MUST rechazarse");
        assert!(
            matches!(
                e,
                ErrorCodec::Codificacion(zx_core::error::EncodingError::DemasiadosElementos { .. })
            ),
            "{e}"
        );
    }

    /// Un saludo con demasiadas puntas PoST se rechaza.
    #[test]
    fn un_estado_con_demasiadas_puntas_post_se_rechaza() {
        use zx_core::encoding::compact_size;
        let mut b = vec![Respuesta::DISC_ESTADO];
        b.extend_from_slice(&[0u8; 32]); // genesis
        b.push(0x02); // red Dev
        b.push(0x00); // fase Pow
        b.extend_from_slice(&[0u8; 32]); // punta pow hash
        b.extend_from_slice(&[0u8; 4]); // altura
        b.extend_from_slice(&[0u8; 32]); // trabajo
        b.push(0x00); // sin terminal
        compact_size::escribir(&mut b, (MAX_PUNTAS_POST + 1) as u64);
        let e = respuesta_desde_bytes(&b).expect_err("MUST rechazarse");
        assert!(
            matches!(
                e,
                ErrorCodec::Codificacion(zx_core::error::EncodingError::DemasiadosElementos { .. })
            ),
            "{e}"
        );
    }

    /// Una respuesta con contador mentiroso se rechaza.
    #[test]
    fn una_respuesta_con_contador_mentiroso_se_rechaza() {
        use zx_core::encoding::compact_size;
        for disc in [Respuesta::DISC_CABECERAS_POW, Respuesta::DISC_BLOQUES] {
            let mut b = vec![disc];
            compact_size::escribir(&mut b, u64::MAX);
            assert!(
                matches!(
                    respuesta_desde_bytes(&b),
                    Err(ErrorCodec::Codificacion(
                        zx_core::error::EncodingError::DemasiadosElementos { .. }
                    ))
                ),
                "disc {disc:#04x}"
            );
        }
    }

    /// **CompactSize no mínimo.** El mismo valor con un prefijo más largo se rechaza.
    #[test]
    fn un_contador_no_minimo_se_rechaza() {
        // `CompactSize` de 5 con el prefijo de 2 bytes (0xfd) no es mínimo.
        let mut b = vec![Peticion::DISC_BLOQUES];
        b.push(0xfd);
        b.extend_from_slice(&5u16.to_le_bytes());
        let e = peticion_desde_bytes(&b).expect_err("MUST rechazarse");
        assert!(
            matches!(
                e,
                ErrorCodec::Codificacion(zx_core::error::EncodingError::CompactSizeNoMinimo { .. })
            ),
            "{e}"
        );
    }

    /// **C-WIRE-05.** Ningún byte arbitrario hace entrar en pánico a los lectores.
    #[test]
    fn ningun_byte_arbitrario_hace_entrar_en_panico() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..2_000 {
            let mut buf = Vec::new();
            for _ in 0..(x % 300) {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                buf.push((x >> 33) as u8);
            }
            let _ = peticion_desde_bytes(&buf);
            let _ = respuesta_desde_bytes(&buf);
            let _ = bloque_desde_bytes_autotag(&buf);
            let _ = bloque_desde_bytes(&buf, FamiliaBloque::Pow);
            let _ = bloque_desde_bytes(&buf, FamiliaBloque::Post);
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        }
    }

    /// Truncar en cualquier punto se rechaza, nunca se acepta a medias.
    #[test]
    fn un_mensaje_truncado_nunca_se_acepta_a_medias() {
        for p in todas_las_peticiones() {
            let b = peticion_a_bytes(&p);
            for n in 0..b.len() {
                assert!(
                    peticion_desde_bytes(b.get(..n).unwrap()).is_err(),
                    "{p:?} truncada a {n} bytes NO debe aceptarse"
                );
            }
        }
        for b in [bloque_pow(1), bloque_post(2)] {
            let bytes = bloque_a_bytes(&b);
            for n in 0..bytes.len() {
                assert!(
                    bloque_desde_bytes(bytes.get(..n).unwrap(), b.familia()).is_err(),
                    "bloque truncado a {n} bytes NO debe aceptarse"
                );
            }
        }
    }

    /// **Nada de relleno.** Un byte de más invalida.
    #[test]
    fn el_relleno_sobrante_se_rechaza() {
        for p in todas_las_peticiones() {
            let mut b = peticion_a_bytes(&p);
            b.push(0x00);
            assert!(peticion_desde_bytes(&b).is_err(), "{p:?} + 1 byte");
        }
        for r in todas_las_respuestas() {
            let mut b = respuesta_a_bytes(&r);
            b.push(0x00);
            assert!(respuesta_desde_bytes(&b).is_err(), "{r:?} + 1 byte");
        }
    }

    /// Un discriminante desconocido se rechaza, nunca se interpreta como otra cosa.
    #[test]
    fn un_discriminante_desconocido_se_rechaza() {
        // En la petición, 0x03 ya no es válido (solo 0x00..=0x02).
        for disc in [0x03u8, 0x7f, 0x80, 0xff] {
            assert!(
                peticion_desde_bytes(&[disc]).is_err(),
                "petición {disc:#04x}"
            );
        }
        // En la respuesta, 0x03 es `NoDisponible`; el primero desconocido es 0x04.
        for disc in [0x04u8, 0x7f, 0x80, 0xff] {
            assert!(
                respuesta_desde_bytes(&[disc]).is_err(),
                "respuesta {disc:#04x}"
            );
        }
    }

    /// El booleano de `parada` **MUST** ser 0 o 1.
    #[test]
    fn el_booleano_de_parada_debe_ser_canonico() {
        use zx_core::encoding::compact_size;
        for valor in [2u8, 3, 0x7f, 0xff] {
            let mut b = vec![Peticion::DISC_CABECERAS_POW];
            compact_size::escribir(&mut b, 0);
            b.push(valor);
            b.extend_from_slice(&[0u8; 32]);
            assert!(
                peticion_desde_bytes(&b).is_err(),
                "un booleano de {valor:#04x} MUST rechazarse"
            );
        }
    }

    /// El booleano del terminal del saludo **MUST** ser 0 o 1.
    #[test]
    fn el_booleano_del_terminal_debe_ser_canonico() {
        for valor in [2u8, 0x7f, 0xff] {
            let mut b = vec![Respuesta::DISC_ESTADO];
            b.extend_from_slice(&[0u8; 32]);
            b.push(0x02);
            b.push(0x00);
            b.extend_from_slice(&[0u8; 32]);
            b.extend_from_slice(&[0u8; 4]);
            b.extend_from_slice(&[0u8; 32]);
            b.push(valor);
            b.extend_from_slice(&[0u8; 32]);
            let e = respuesta_desde_bytes(&b).expect_err("MUST rechazarse");
            assert!(
                matches!(e, ErrorCodec::BooleanoNoCanonico { valor: v } if v == valor),
                "{e}"
            );
        }
    }

    /// El `magic` no está en el wire: el saludo empieza por su discriminante.
    #[test]
    fn el_magic_no_es_una_barrera_del_wire() {
        let dev = crate::config::ParametrosRed::dag_dev().magic();
        let peticion = peticion_a_bytes(&Peticion::Estado);
        assert_eq!(peticion, vec![Peticion::DISC_ESTADO]);
        assert_ne!(peticion.get(..4), Some(dev.as_slice()));

        let respuesta = respuesta_a_bytes(&Respuesta::Estado(estado()));
        assert_eq!(respuesta.first().copied(), Some(Respuesta::DISC_ESTADO));
        assert_ne!(respuesta.get(..4), Some(dev.as_slice()));
    }

    /// Un lote lleno de cabeceras pasa la cota y da la vuelta.
    #[test]
    fn un_lote_lleno_de_cabeceras_pasa_la_cota() {
        let cs: Vec<_> = (0..limites::MAX_CABECERAS_POR_RESPUESTA)
            .map(|i| cabecera((i % 256) as u8))
            .collect();
        let r = Respuesta::CabecerasPow(cs);
        let b = respuesta_a_bytes(&r);

        assert!(
            b.len() as u64 <= limites::MAX_RESPUESTA_BYTES,
            "{} B no caben en {} B",
            b.len(),
            limites::MAX_RESPUESTA_BYTES
        );
        assert_eq!(respuesta_desde_bytes(&b).unwrap(), r);
    }

    /// **ORDEN-RD1c (G6).** Una petición del registro responde con una página acotada: el tope de
    /// entradas por página se respeta y una página llena cabe en `MAX_RESPUESTA_BYTES`.
    #[test]
    fn peticion_registro_responde_una_pagina_acotada() {
        let entradas: Vec<EntradaRegistro> = (0..limites::MAX_ENTRADAS_REGISTRO_POR_PAGINA)
            .map(|i| entrada_registro((i % 256) as u8))
            .collect();
        let resp = Respuesta::RegistroDirecciones {
            desde: 0,
            entradas,
            total: 1,
        };
        let bytes = respuesta_a_bytes(&resp);
        assert!(
            bytes.len() as u64 <= limites::MAX_RESPUESTA_BYTES,
            "{} B no caben en {} B",
            bytes.len(),
            limites::MAX_RESPUESTA_BYTES
        );
        assert_eq!(respuesta_desde_bytes(&bytes).unwrap(), resp);
        assert!(resp.responde_a(&Peticion::RegistroDirecciones { desde: 0 }));

        // Un contador por encima del tope se rechaza antes de reservar.
        let mut b = vec![Respuesta::DISC_REGISTRO_DIRECCIONES];
        zx_core::encoding::int::escribir_u64(&mut b, 0);
        zx_core::encoding::compact_size::escribir(
            &mut b,
            (limites::MAX_ENTRADAS_REGISTRO_POR_PAGINA + 1) as u64,
        );
        let e = respuesta_desde_bytes(&b).expect_err("MUST rechazarse");
        assert!(
            matches!(
                e,
                ErrorCodec::Codificacion(zx_core::error::EncodingError::DemasiadosElementos { .. })
            ),
            "{e}"
        );
    }

    /// **ORDEN-ZC3 (c), sincronización.** Una respuesta de sync con bloques comprime ≥ 20 %.
    #[test]
    fn una_respuesta_de_sync_baja_los_bytes() {
        let bloques: Vec<BloqueRed> = (0..4u8).map(bloque_post).collect();
        let resp = Respuesta::Bloques(bloques);
        let crudo = respuesta_a_bytes(&resp);
        let marco = crate::zrxc::comprimir_red(&crudo, None);
        assert!(
            crudo.len() > 1_000,
            "la respuesta de sync MUST ser representativa: {} B",
            crudo.len()
        );
        let factor = marco.len() as f64 / crudo.len() as f64;
        eprintln!(
            "ZRX-C sync: crudo={} comprimido={} factor={factor:.4}",
            crudo.len(),
            marco.len()
        );
        assert!(
            factor < 0.80,
            "ORDEN-ZC3 (c): la respuesta de sync MUST bajar >=20%; factor={factor}"
        );
    }
}
