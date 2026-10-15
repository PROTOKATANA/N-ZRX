//! El marco ZXC1 y sus funciones de compresión y descomposición.
//!
//! Este es el **único** formato de marco de ZRX-C (ZC-4): el que viaja por la red
//! en `zx-p2p` y el que consumen los demás crates a través de `zx-compresion`. El
//! marco es la frontera de ZRX-C: bytes opacos que entran (ya serializados, con
//! sus identificadores y firmas calculados) y bytes opacos que salen idénticos, o
//! un error. La compresión va **después** de calcular cualquier compromiso y la
//! descompresión **antes** de volver a verificarlo.
//!
//! # Anti-bomba
//!
//! [`descomprimir`] recibe un [`Limites`] con el tope duro de salida y lo
//! comprueba **antes** de asignar: rechaza un `len_original` por encima del tope,
//! un ratio declarado mayor que [`Limites::ratio_max`] y cualquier salida cuyo
//! tamaño real no cuadre con el declarado. La descompresión de zstd se hace con
//! capacidad acotada (`zstd::bulk::Decompressor`), nunca con `read_to_end` sin
//! cota.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dict::{Diccionario, diccionario};
use crate::error::ErrorCompresion;
use crate::limites::Limites;

/// Magia del marco: `ZXC1`.
pub const MAGIA: [u8; 4] = *b"ZXC1";

/// Alias inglés de [`MAGIA`].
pub const MAGIC: [u8; 4] = MAGIA;

/// Versión del marco que entiende este binario.
pub const VERSION: u8 = 1;

/// Algoritmo `almacenado` (sin comprimir).
pub const ALG_ALMACENADO: u8 = 0x00;

/// Algoritmo `zstd`.
pub const ALG_ZSTD: u8 = 0x01;

/// Alias de [`ALG_ZSTD`] con el nombre de la API antigua de la crate.
pub const ALGORITMO_ZSTD: u8 = ALG_ZSTD;

/// Bytes de la cabecera del marco: `magia(4) + version(1) + algoritmo(1) + nivel(1) +
/// dict_id(4) + len_original(8) + len_comprimido(8) + checksum(8)`.
pub const CABECERA: usize = 4 + 1 + 1 + 1 + 4 + 8 + 8 + 8;

/// Alias de [`CABECERA`] con el nombre que usaba `zx-p2p`.
pub const TAMANO_CABECERA: usize = CABECERA;

/// Nivel de zstd del camino de red y del camino caliente (R-3: 1–3).
pub const NIVEL: i32 = 3;

/// Nivel de compresión por omisión en disco (R-3 de ZRX-C).
pub const NIVEL_DISCO: i32 = 3;

/// Por debajo de este tamaño no se intenta comprimir (R-9): el marco domina.
pub const UMBRAL_MINIMO_BYTES: usize = 64;

/// Ratio máximo declarado `original / comprimido` (R-7).
pub const MAX_RATIO: u64 = 1_000;

/// Marca que un nodo ZRX-C anuncia en su `agent_version` (R-8).
pub const MARCA_ZRXC: &str = "+zrxc1";

/// Cabecera de un marco ZXC1 ya interpretada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cabecera {
    /// Versión del marco.
    pub version: u8,
    /// Algoritmo de compresión (`0` = almacenado, `1` = zstd).
    pub algoritmo: u8,
    /// Nivel de compresión con el que se generó el payload.
    pub nivel: u8,
    /// Identificador del diccionario (`0` = sin diccionario).
    pub dict_id: u32,
    /// Bytes originales antes de comprimir.
    pub len_original: u64,
    /// Bytes del payload tal y como viaja.
    pub len_comprimido: u64,
    /// Checksum xxhash64 de los bytes originales.
    pub checksum: u64,
}

/// ¿Empieza `marco` por la magia de un marco ZXC1?
///
/// Los mensajes crudos de ZEROX empiezan por un discriminante `0x00..=0x04`, así
/// que nunca pueden colisionar con la `Z` (`0x5a`) de la magia: la detección es
/// inequívoca.
#[must_use]
pub fn es_marco(marco: &[u8]) -> bool {
    marco.get(..MAGIA.len()) == Some(MAGIA.as_slice())
}

/// Alias de [`es_marco`] con el nombre de la API antigua de la crate.
#[must_use]
pub fn esta_comprimido(guardado: &[u8]) -> bool {
    es_marco(guardado)
}

/// ¿Este `agent_version` anuncia capacidad ZRX-C? (R-8)
#[must_use]
pub fn anuncia_zrxc(agent_version: &str) -> bool {
    agent_version.contains(MARCA_ZRXC)
}

fn array<const N: usize>(marco: &[u8], desde: usize) -> Result<[u8; N], ErrorCompresion> {
    let fin = desde.saturating_add(N);
    marco
        .get(desde..fin)
        .ok_or(ErrorCompresion::MarcoCorto { bytes: marco.len() })?
        .try_into()
        .map_err(|_| ErrorCompresion::MarcoCorto { bytes: marco.len() })
}

/// Lee y valida la cabecera de un marco ZXC1.
///
/// No comprueba todavía los límites del tipo ni las longitudes contra el búfer;
/// eso lo hace [`descomprimir`].
///
/// # Errores
/// [`ErrorCompresion::MarcoCorto`] si el búfer no cubre la cabecera;
/// [`ErrorCompresion::MagiaInvalida`] si no empieza por `ZXC1`.
pub fn leer_cabecera(marco: &[u8]) -> Result<Cabecera, ErrorCompresion> {
    let magia = marco
        .get(..MAGIA.len())
        .ok_or(ErrorCompresion::MarcoCorto { bytes: marco.len() })?;
    if magia != MAGIA.as_slice() {
        return Err(ErrorCompresion::MagiaInvalida);
    }
    if marco.len() < CABECERA {
        return Err(ErrorCompresion::MarcoCorto { bytes: marco.len() });
    }
    Ok(Cabecera {
        version: *marco
            .get(4)
            .ok_or(ErrorCompresion::MarcoCorto { bytes: marco.len() })?,
        algoritmo: *marco
            .get(5)
            .ok_or(ErrorCompresion::MarcoCorto { bytes: marco.len() })?,
        nivel: *marco
            .get(6)
            .ok_or(ErrorCompresion::MarcoCorto { bytes: marco.len() })?,
        dict_id: u32::from_be_bytes(array::<4>(marco, 7)?),
        len_original: u64::from_be_bytes(array::<8>(marco, 11)?),
        len_comprimido: u64::from_be_bytes(array::<8>(marco, 19)?),
        checksum: u64::from_be_bytes(array::<8>(marco, 27)?),
    })
}

/// Alias de [`leer_cabecera`] con el nombre que usaba `zx-p2p`.
pub fn cabecera(marco: &[u8]) -> Result<Cabecera, ErrorCompresion> {
    leer_cabecera(marco)
}

/// Comprime `datos` y devuelve el marco ZXC1 completo.
///
/// Si `datos` es menor que [`UMBRAL_MINIMO_BYTES`] o si comprimir no compensa la
/// cabecera, el payload viaja **almacenado** dentro del mismo marco (algoritmo
/// `0`). El checksum xxhash64 cubre los bytes originales, de modo que una
/// descompresión sobre bytes alterados falla en vez de devolver una salida
/// distinta.
///
/// # Errores
/// [`ErrorCompresion::NivelInvalido`] si `nivel` no está en `1..=22`;
/// [`ErrorCompresion::Zstd`] si el compresor falla.
pub fn comprimir(
    datos: &[u8],
    nivel: i32,
    dict: Option<&Diccionario>,
) -> Result<Vec<u8>, ErrorCompresion> {
    if !(1..=22).contains(&nivel) {
        return Err(ErrorCompresion::NivelInvalido { nivel });
    }
    let checksum = xxh64(datos, 0);
    if datos.len() < UMBRAL_MINIMO_BYTES {
        return Ok(marco_almacenado(datos, checksum));
    }
    let comprimido = match dict {
        Some(d) => zstd::bulk::Compressor::with_dictionary(nivel, d.bytes())
            .and_then(|mut c| c.compress(datos)),
        None => zstd::bulk::compress(datos, nivel),
    };
    match comprimido {
        Ok(c) if c.len().saturating_add(CABECERA) < datos.len() => {
            let dict_id = dict.map_or(0, Diccionario::id);
            Ok(marco_zstd(datos.len(), &c, checksum, dict_id, nivel))
        }
        Ok(_) => Ok(marco_almacenado(datos, checksum)),
        Err(e) => Err(ErrorCompresion::zstd(e)),
    }
}

/// Comprime para el camino de red: nunca falla (si zstd no ayuda, almacena).
///
/// Usa [`NIVEL`] y recurre al marco almacenado ante cualquier error de zstd, de
/// modo que el llamante del camino caliente no tiene que decidir.
#[must_use]
pub fn comprimir_red(datos: &[u8], dict: Option<&Diccionario>) -> Vec<u8> {
    comprimir(datos, NIVEL, dict).unwrap_or_else(|_| marco_almacenado(datos, xxh64(datos, 0)))
}

/// Descomprime un marco ZXC1 aplicando los límites del tipo.
///
/// Si el marco declara un `dict_id`, se debe pasar el diccionario correspondiente
/// (o usar [`descomprimir_por_id`] para resolverlo del registro de la crate).
///
/// # Errores
/// Cualquier [`ErrorCompresion`]: el marco puede ser corto, de otra versión o
/// algoritmo, con longitudes que no cuadran, con un tamaño original por encima
/// del tope, con un ratio imposible (bomba), con un checksum que no cuadra o con
/// un diccionario distinto.
pub fn descomprimir(
    marco: &[u8],
    dict: Option<&Diccionario>,
    limites: &Limites,
) -> Result<Vec<u8>, ErrorCompresion> {
    let cabecera = leer_cabecera(marco)?;
    if cabecera.version != VERSION {
        return Err(ErrorCompresion::VersionDesconocida {
            encontrada: cabecera.version,
        });
    }
    if cabecera.len_original > limites.max_original {
        return Err(ErrorCompresion::DemasiadoGrande {
            declarado: cabecera.len_original,
            max: limites.max_original,
        });
    }

    let comprimido = usize::try_from(cabecera.len_comprimido)
        .map_err(|_| ErrorCompresion::LongitudIncoherente)?;
    let total = CABECERA
        .checked_add(comprimido)
        .ok_or(ErrorCompresion::LongitudIncoherente)?;
    if marco.len() != total {
        return Err(ErrorCompresion::LongitudIncoherente);
    }
    let payload = marco
        .get(CABECERA..)
        .ok_or(ErrorCompresion::MarcoCorto { bytes: marco.len() })?;

    // Un ratio declarado imposible se rechaza antes de tocar zstd.
    let tope_ratio = (comprimido as u64).saturating_mul(u64::from(limites.ratio_max));
    if cabecera.len_original > tope_ratio {
        return Err(ErrorCompresion::RatioExcesivo {
            original: cabecera.len_original,
            comprimido: cabecera.len_comprimido,
        });
    }

    match cabecera.dict_id {
        0 => {}
        esperado => match dict {
            Some(d) if d.id() == esperado => {}
            Some(d) => {
                return Err(ErrorCompresion::DiccionarioDesconocido {
                    esperado,
                    recibido: d.id(),
                });
            }
            None => {
                return Err(ErrorCompresion::DiccionarioDesconocido {
                    esperado,
                    recibido: 0,
                });
            }
        },
    }

    match cabecera.algoritmo {
        ALG_ALMACENADO => {
            if cabecera.len_comprimido != cabecera.len_original {
                return Err(ErrorCompresion::LongitudIncoherente);
            }
            verificar_checksum(payload, cabecera.checksum)?;
            Ok(payload.to_vec())
        }
        ALG_ZSTD => {
            let capacidad = usize::try_from(cabecera.len_original)
                .map_err(|_| ErrorCompresion::LongitudIncoherente)?;
            // Un original vacío necesita al menos un byte de búfer para que zstd
            // materialice su frame; la comprobación posterior exige la longitud exacta.
            let buffer = capacidad.max(1);
            let mut motor = match dict {
                Some(d) => zstd::bulk::Decompressor::with_dictionary(d.bytes()),
                None => zstd::bulk::Decompressor::new(),
            }
            .map_err(ErrorCompresion::zstd)?;
            motor
                .window_log_max(limites.window_log_max)
                .map_err(ErrorCompresion::zstd)?;
            let salida = motor
                .decompress(payload, buffer)
                .map_err(|_| ErrorCompresion::Corrupto)?;
            if salida.len() != capacidad {
                return Err(ErrorCompresion::LongitudIncoherente);
            }
            verificar_checksum(&salida, cabecera.checksum)?;
            Ok(salida)
        }
        otro => Err(ErrorCompresion::AlgoritmoDesconocido { encontrada: otro }),
    }
}

/// Descomprime resolviendo el diccionario por el `dict_id` del marco.
///
/// Es la puerta que usa la red: el receptor no conoce de antemano qué diccionario
/// usó el emisor, solo su identificador versionado.
///
/// # Errores
/// Igual que [`descomprimir`], más [`ErrorCompresion::DiccionarioDesconocido`] si
/// el registro de la crate no conoce el `dict_id` declarado.
pub fn descomprimir_por_id(marco: &[u8], limites: &Limites) -> Result<Vec<u8>, ErrorCompresion> {
    let cabecera = leer_cabecera(marco)?;
    let dict = match cabecera.dict_id {
        0 => None,
        id => Some(
            diccionario(id).ok_or(ErrorCompresion::DiccionarioDesconocido {
                esperado: id,
                recibido: 0,
            })?,
        ),
    };
    descomprimir(marco, dict, limites)
}

fn marco_almacenado(datos: &[u8], checksum: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(CABECERA.saturating_add(datos.len()));
    escribir_cabecera(
        &mut out,
        ALG_ALMACENADO,
        0,
        0,
        datos.len() as u64,
        datos.len() as u64,
        checksum,
    );
    out.extend_from_slice(datos);
    out
}

fn marco_zstd(
    len_original: usize,
    comprimido: &[u8],
    checksum: u64,
    dict_id: u32,
    nivel: i32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CABECERA.saturating_add(comprimido.len()));
    escribir_cabecera(
        &mut out,
        ALG_ZSTD,
        nivel as u8,
        dict_id,
        len_original as u64,
        comprimido.len() as u64,
        checksum,
    );
    out.extend_from_slice(comprimido);
    out
}

#[allow(
    clippy::too_many_arguments,
    reason = "una cabecera tiene exactamente estos ocho campos; agruparlos en un struct solo para el escritor no aporta"
)]
fn escribir_cabecera(
    out: &mut Vec<u8>,
    algoritmo: u8,
    nivel: u8,
    dict_id: u32,
    len_original: u64,
    len_comprimido: u64,
    checksum: u64,
) {
    out.extend_from_slice(&MAGIA);
    out.push(VERSION);
    out.push(algoritmo);
    out.push(nivel);
    out.extend_from_slice(&dict_id.to_be_bytes());
    out.extend_from_slice(&len_original.to_be_bytes());
    out.extend_from_slice(&len_comprimido.to_be_bytes());
    out.extend_from_slice(&checksum.to_be_bytes());
}

fn verificar_checksum(bytes: &[u8], esperado: u64) -> Result<(), ErrorCompresion> {
    let calculado = xxh64(bytes, 0);
    if calculado == esperado {
        Ok(())
    } else {
        Err(ErrorCompresion::ChecksumInvalido {
            esperado,
            calculado,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// xxHash64 (checksum de transporte, R-5)
// ─────────────────────────────────────────────────────────────────────────────

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

fn ronda(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

fn merge(acc: u64, val: u64) -> u64 {
    let v = ronda(0, val);
    (acc ^ v).wrapping_mul(P1).wrapping_add(P4)
}

fn lee8(b: &[u8]) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(b);
    u64::from_le_bytes(v)
}

fn lee4(b: &[u8]) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(b);
    u32::from_le_bytes(v)
}

/// xxHash64 con semilla, usado como checksum de transporte del marco (R-5).
#[must_use]
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut h: u64;
    let mut consumidos = 0usize;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(P1).wrapping_add(P2);
        let mut v2 = seed.wrapping_add(P2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(P1);
        let mut trozos = data.chunks_exact(32);
        for c in &mut trozos {
            let (a, b) = c.split_at(16);
            let (a1, a2) = a.split_at(8);
            let (b1, b2) = b.split_at(8);
            v1 = ronda(v1, lee8(a1));
            v2 = ronda(v2, lee8(a2));
            v3 = ronda(v3, lee8(b1));
            v4 = ronda(v4, lee8(b2));
        }
        consumidos = len - trozos.remainder().len();
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge(h, v1);
        h = merge(h, v2);
        h = merge(h, v3);
        h = merge(h, v4);
    } else {
        h = seed.wrapping_add(P5);
    }

    h = h.wrapping_add(len as u64);
    let resto = data.get(consumidos..).unwrap_or(&[]);

    let mut trozos8 = resto.chunks_exact(8);
    for c in &mut trozos8 {
        let k1 = ronda(0, lee8(c));
        h ^= k1;
        h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
    }
    let r8 = trozos8.remainder();

    let mut trozos4 = r8.chunks_exact(4);
    for c in &mut trozos4 {
        h ^= u64::from(lee4(c)).wrapping_mul(P1);
        h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
    }
    let r4 = trozos4.remainder();

    for &b in r4 {
        h ^= u64::from(b).wrapping_mul(P5);
        h = h.rotate_left(11).wrapping_mul(P1);
    }

    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^= h >> 32;
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// Contadores de bytes (instrumentación de medida de ZC-3/ZC-4)
// ─────────────────────────────────────────────────────────────────────────────

/// Contadores de bytes de ZRX-C por nodo: lo que se habría enviado **sin**
/// comprimir (`originales`) frente a lo que se envía **con** ZRX-C (`enviados`).
///
/// Es instrumentación de diagnóstico y de medida: no cambia ninguna decisión.
/// Compartido entre los clones de `zx_p2p::servicio::ManejoRed`.
#[derive(Clone, Debug, Default)]
pub struct Metricas {
    originales: Arc<AtomicU64>,
    enviados: Arc<AtomicU64>,
}

impl Metricas {
    /// Un contador a cero.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Suma un mensaje: `originales` eran sus bytes crudos; `enviados`, los del marco ZRX-C.
    pub fn sumar(&self, originales: u64, enviados: u64) {
        self.originales.fetch_add(originales, Ordering::Relaxed);
        self.enviados.fetch_add(enviados, Ordering::Relaxed);
    }

    /// Bytes crudos acumulados.
    #[must_use]
    pub fn bytes_originales(&self) -> u64 {
        self.originales.load(Ordering::Relaxed)
    }

    /// Bytes ZRX-C acumulados.
    #[must_use]
    pub fn bytes_enviados(&self) -> u64 {
        self.enviados.load(Ordering::Relaxed)
    }

    /// Fracción que representan los bytes enviados sobre los originales (`1.0` = no hay ahorro).
    ///
    /// Devuelve `1.0` si todavía no se ha contabilizado nada.
    #[must_use]
    pub fn factor(&self) -> f64 {
        let originales = self.bytes_originales();
        if originales == 0 {
            return 1.0;
        }
        self.bytes_enviados() as f64 / originales as f64
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::{
        ALG_ALMACENADO, ALG_ZSTD, CABECERA, ErrorCompresion, MAGIA, Metricas, VERSION,
        anuncia_zrxc, cabecera, comprimir, descomprimir, es_marco, escribir_cabecera,
        leer_cabecera, xxh64,
    };
    use crate::dict::{DICT_ID_TX, diccionario_tx};
    use crate::limites::Limites;

    #[test]
    fn xxhash64_contra_vectores_conocidos() {
        // Vectores comprobados con `xxh64sum` 0.8.3 (Yann Collet) en esta máquina.
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"a", 0), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
        assert_eq!(xxh64(b"1234567890", 0), 0xA9D4_D413_2EFF_23B6);
        // > 32 B: ejercita el bucle de 4 acumuladores y `merge`.
        assert_eq!(
            xxh64(b"The quick brown fox jumps over the lazy dog", 0),
            0x0B24_2D36_1FDA_71BC
        );
        assert_eq!(
            xxh64(b"abcdefghijklmnopqrstuvwxyz0123456789", 0),
            0x64F2_3ECF_1609_B766
        );
    }

    #[test]
    fn un_payload_grande_da_la_vuelta_con_y_sin_diccionario() {
        let datos: Vec<u8> = (0..8_000u32)
            .map(|i| (i.wrapping_mul(31) % 251) as u8)
            .collect();
        assert!(datos.len() >= super::UMBRAL_MINIMO_BYTES);

        for dict in [None, Some(diccionario_tx())] {
            let marco = comprimir(&datos, super::NIVEL, dict).unwrap();
            assert!(es_marco(&marco));
            let cab = cabecera(&marco).unwrap();
            assert_eq!(cab.version, VERSION);
            assert_eq!(cab.algoritmo, ALG_ZSTD);
            if dict.is_some() {
                assert_eq!(cab.dict_id, DICT_ID_TX);
            }
            let salida = descomprimir(&marco, dict, &Limites::nuevo(u64::MAX)).unwrap();
            assert_eq!(salida, datos, "la compresión MUST ser reversible bit a bit");
        }
    }

    #[test]
    fn un_payload_diminuto_viaja_almacenado() {
        let datos = b"ZXV1 diminuto";
        let marco = comprimir(datos, super::NIVEL, Some(diccionario_tx())).unwrap();
        let cab = cabecera(&marco).unwrap();
        assert_eq!(cab.algoritmo, ALG_ALMACENADO);
        assert_eq!(cab.dict_id, 0, "almacenado no referencia diccionario");
        let dict = diccionario_tx();
        assert_eq!(
            descomprimir(&marco, Some(dict), &Limites::nuevo(64)).unwrap(),
            datos
        );
    }

    #[test]
    fn un_byte_corrupto_en_el_payload_se_detecta() {
        let datos = vec![0xABu8; 4_000];
        let mut marco = comprimir(&datos, super::NIVEL, None).unwrap();
        let n = marco.len();
        if let Some(ultimo) = marco.get_mut(n.saturating_sub(1)) {
            *ultimo ^= 0xFF;
        }
        assert!(
            matches!(
                descomprimir(&marco, None, &Limites::nuevo(u64::MAX)),
                Err(ErrorCompresion::Corrupto | ErrorCompresion::ChecksumInvalido { .. })
            ),
            "un payload corrupto MUST rechazarse"
        );
    }

    #[test]
    fn una_bomba_por_encima_del_tope_se_rechaza_sin_asignar() {
        let datos = vec![0u8; 1_000];
        let marco = comprimir(&datos, super::NIVEL, None).unwrap();
        let e = descomprimir(&marco, None, &Limites::nuevo(10)).unwrap_err();
        assert!(
            matches!(e, ErrorCompresion::DemasiadoGrande { max: 10, .. }),
            "{e}"
        );
    }

    #[test]
    fn un_ratio_declarado_absurdo_se_rechaza() {
        let mut marco = Vec::new();
        escribir_cabecera(&mut marco, ALG_ZSTD, 3, 0, 1_000_000, 1, 0);
        marco.extend_from_slice(&[0u8; 1]);
        let e = descomprimir(&marco, None, &Limites::nuevo(u64::MAX)).unwrap_err();
        assert!(matches!(e, ErrorCompresion::RatioExcesivo { .. }), "{e}");
    }

    #[test]
    fn declarar_menos_de_lo_que_descomprime_se_rechaza() {
        // Un zstd real de 4 000 bytes, pero la cabecera dice 8: la capacidad acotada lo corta.
        let datos = vec![7u8; 4_000];
        let comprimido = zstd::bulk::compress(&datos, 3).unwrap();
        let mut marco = Vec::new();
        escribir_cabecera(
            &mut marco,
            ALG_ZSTD,
            3,
            0,
            8,
            comprimido.len() as u64,
            xxh64(&datos, 0),
        );
        marco.extend_from_slice(&comprimido);
        let e = descomprimir(&marco, None, &Limites::nuevo(u64::MAX)).unwrap_err();
        assert!(
            matches!(
                e,
                ErrorCompresion::Corrupto | ErrorCompresion::LongitudIncoherente
            ),
            "{e}"
        );
    }

    #[test]
    fn un_diccionario_desconocido_se_rechaza() {
        let datos = vec![3u8; 1_000];
        let comprimido = zstd::bulk::compress(&datos, 3).unwrap();
        let mut marco = Vec::new();
        escribir_cabecera(
            &mut marco,
            ALG_ZSTD,
            3,
            0xDEAD_BEEF,
            datos.len() as u64,
            comprimido.len() as u64,
            xxh64(&datos, 0),
        );
        marco.extend_from_slice(&comprimido);
        let e = descomprimir(&marco, None, &Limites::nuevo(u64::MAX)).unwrap_err();
        assert!(
            matches!(
                e,
                ErrorCompresion::DiccionarioDesconocido {
                    esperado: 0xDEAD_BEEF,
                    recibido: 0
                }
            ),
            "{e}"
        );
        assert!(crate::dict::diccionario(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn un_marco_con_magia_ajena_no_se_confunde() {
        assert!(!es_marco(&[0x00]));
        assert!(!es_marco(&[0x01, 0x02, 0x03, 0x04]));
        assert!(es_marco(&MAGIA));
        assert!(matches!(
            leer_cabecera(&MAGIA),
            Err(ErrorCompresion::MarcoCorto { .. })
        ));
        assert_eq!(
            leer_cabecera(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap_err(),
            ErrorCompresion::MagiaInvalida
        );
    }

    #[test]
    fn la_version_de_marco_se_comprueba() {
        let datos = vec![1u8; 500];
        let comprimido = zstd::bulk::compress(&datos, 3).unwrap();
        let mut marco = Vec::new();
        escribir_cabecera(&mut marco, ALG_ZSTD, 3, 0, 500, comprimido.len() as u64, 0);
        // Corrompe la versión (posición 4).
        if let Some(v) = marco.get_mut(4) {
            *v = VERSION.wrapping_add(9);
        }
        let e = descomprimir(&marco, None, &Limites::nuevo(u64::MAX)).unwrap_err();
        assert!(
            matches!(e, ErrorCompresion::VersionDesconocida { .. }),
            "{e}"
        );
        assert_eq!(CABECERA, 35);
    }

    #[test]
    fn el_agent_version_anuncia_zrxc() {
        assert!(anuncia_zrxc("zerox/0.0.0/dev+zrxc1"));
        assert!(!anuncia_zrxc("zerox/0.0.0/dev"));
        assert!(!anuncia_zrxc("rust-libp2p/0.56.0"));
    }

    #[test]
    fn las_metricas_suman_y_dan_factor() {
        let m = Metricas::nuevo();
        assert_eq!(m.factor(), 1.0);
        m.sumar(100, 25);
        m.sumar(100, 25);
        assert_eq!(m.bytes_originales(), 200);
        assert_eq!(m.bytes_enviados(), 50);
        assert!((m.factor() - 0.25).abs() < f64::EPSILON);
    }
}
