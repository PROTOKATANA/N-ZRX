//! Agregación de votos por subred (pieza A5, paso (a)): tipos, códecs, reparto, sorteo y
//! verificación por lotes.
//!
//! Implementa las reglas A1–A8 del contrato adoptado (`CONTRATO-PROPUESTO.md` §2–§3 con las
//! correcciones de `ADOPCION-A5.md`):
//!
//! - **A1 · reparto fijo:** [`subred`] = `SHA-256("ZX-AGREGACION-REPARTO" ‖ pk) mod S`; [`Reparto`]
//!   precalcula las claves de cada subred (orden ascendente de `pk`).
//! - **A2 · voto de red:** [`VotoRed`], 248 B, con la **clave BLS entera** y la firma A3 de
//!   [`mensaje_voto_peso`].
//! - **A3 · agregado:** [`Agregado`], `332 + ⌈n_s/8⌉` B, con la **huella de la tabla** y la firma de
//!   sorteo.
//! - **A4 · sorteo:** [`sale_agregadora`], comparación exacta en `BigUint`.
//! - **A5 · veredicto:** [`VeredictoAgregado`] con tres resultados (otra tabla / inválido / válido) y
//!   [`MotivoAgregado`].
//! - **A6 · lotes:** [`verificar_lote`] con coeficientes de un [`GeneradorEscalares`] y aislamiento
//!   por bisección; su resultado por agregado es idéntico al de [`veredicto`] uno a uno.
//! - **A7 · certificado:** [`armar_certificado`] arma el mapa global y la firma agregada de un
//!   [`CertificadoPeso`] verificable, con un agregado por subred y los votos sueltos que falten.
//!
//! **A8:** sin `unsafe`, sin `unwrap`/`expect` fuera de las pruebas, sin dependencias nuevas y con
//! errores propios ([`ErrorAgregacion`]). No toca `peso.rs`.
//!
//! Este módulo **no tiene llamantes** todavía: solo añade API.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use zx_bls::{
    ClaveAgregada, ClavePublica, Firma, FirmaAgregada, LONGITUD_CLAVE_PUBLICA,
    LONGITUD_ESCALAR_LOTE, LONGITUD_FIRMA, agregar_firmas, verificar, verificar_agregado_con_clave,
    verificar_lote_con_escalares, verificar_lote_de_agregados_con_clave,
};

use crate::bls::DOMINIO_VOTO;
use crate::peso::{CertificadoPeso, mensaje_voto_peso};
use crate::serial::{hash_bytes, hash_tabla};
use crate::tipos::{Hash, LONGITUD_HASH, Tabla};

/// Dominio del reparto por subred (A1).
pub const DOMINIO_REPARTO: &[u8] = b"ZX-AGREGACION-REPARTO";

/// Dominio de la firma de sorteo (A4).
pub const DOMINIO_SORTEO: &[u8] = b"ZX-AGREGACION-SORTEO";

/// Longitud exacta del voto de red (A2): `8 + 3·32 + 48 + 96 = 248` B.
pub const LONGITUD_VOTO_RED: usize =
    8 + 3 * LONGITUD_HASH + LONGITUD_CLAVE_PUBLICA + LONGITUD_FIRMA;

/// Longitud fija del agregado sin `mapa_local` (A3): `332` B.
pub const LONGITUD_FIJA_AGREGADO: usize =
    8 + 3 * LONGITUD_HASH + LONGITUD_FIRMA + LONGITUD_HASH + 2 + 2 + LONGITUD_FIRMA;

/// Offset del `mapa_local` dentro del agregado serializado.
const OFFSET_MAPA_LOCAL: usize = 8 + 3 * LONGITUD_HASH + LONGITUD_FIRMA + LONGITUD_HASH + 2 + 2;

/// Error propio de la agregación (A8).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ErrorAgregacion {
    /// Una longitud no es la que el formato exige.
    #[error("longitud inesperada: se esperaban {esperado} bytes y hay {obtenido}")]
    LongitudInesperada {
        /// Longitud exigida.
        esperado: usize,
        /// Longitud recibida.
        obtenido: usize,
    },
    /// `S = 0`: el reparto por subred no está definido.
    #[error("el numero de subredes S MUST ser > 0")]
    SubredesCero,
    /// Un entero del reparto no cabe en `u16`.
    #[error("entero del reparto fuera de u16")]
    FueraDeU16,
    /// El número de claves públicas no coincide con las claves de la tabla.
    #[error("{claves} claves publicas y {plazas} claves de tabla; MUST coincidir")]
    LongitudesIncompatibles {
        /// Claves públicas suministradas.
        claves: usize,
        /// Claves de la tabla.
        plazas: usize,
    },
    /// Un índice de voto suelto cae fuera de la tabla.
    #[error("clave no registrada en la tabla de poder")]
    ClaveNoRegistrada,
    /// La primitiva BLS rechazó una operación.
    #[error("error de BLS: {0}")]
    Bls(#[from] zx_bls::ErrorBLS),
}

/// Reparto A1 de una tabla en `S` subredes: las claves de cada subred, en orden ascendente de `pk`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reparto {
    s: u16,
    subredes: Vec<Vec<usize>>,
}

impl Reparto {
    /// Construye el reparto de `tabla` en `s` subredes con [`subred`].
    ///
    /// # Errores
    /// [`ErrorAgregacion::SubredesCero`] si `s == 0`; el de `subred` si una clave no se puede
    /// repartir.
    pub fn construir(tabla: &Tabla, s: u16) -> Result<Self, ErrorAgregacion> {
        if s == 0 {
            return Err(ErrorAgregacion::SubredesCero);
        }
        let mut subredes: Vec<Vec<usize>> = vec![Vec::new(); s as usize];
        for (indice, clave) in tabla.claves.iter().enumerate() {
            let destino = subred(&clave.clave, s)? as usize;
            if let Some(lista) = subredes.get_mut(destino) {
                lista.push(indice);
            }
        }
        for lista in &mut subredes {
            lista.sort_by(|a, b| {
                let ca = tabla.claves.get(*a).map(|clave| clave.clave.as_slice());
                let cb = tabla.claves.get(*b).map(|clave| clave.clave.as_slice());
                ca.cmp(&cb).then_with(|| a.cmp(b))
            });
        }
        Ok(Self { s, subredes })
    }

    /// Número de subredes `S`.
    #[must_use]
    pub fn s(&self) -> u16 {
        self.s
    }

    /// Índices en `tabla.claves` de las claves de la subred `subred`, en orden.
    #[must_use]
    pub fn claves_de(&self, subred: u16) -> &[usize] {
        self.subredes
            .get(subred as usize)
            .map_or(&[][..], Vec::as_slice)
    }
}

/// Reparto fijo A1: `SHA-256(DOMINIO_REPARTO ‖ clave) mod S`, 0-based.
///
/// Solo depende de los bytes de la clave.
///
/// # Errores
/// [`ErrorAgregacion::SubredesCero`] si `s == 0`;
/// [`ErrorAgregacion::FueraDeU16`] si el resto no cabe en `u16` (imposible con `s ≤ 65535`).
pub fn subred(clave: &[u8], s: u16) -> Result<u16, ErrorAgregacion> {
    if s == 0 {
        return Err(ErrorAgregacion::SubredesCero);
    }
    let mut bytes = Vec::with_capacity(DOMINIO_REPARTO.len() + clave.len());
    bytes.extend_from_slice(DOMINIO_REPARTO);
    bytes.extend_from_slice(clave);
    let hash = BigUint::from_bytes_be(&hash_bytes(&bytes));
    let resto = hash % BigUint::from(s);
    let valor = resto.to_u64().ok_or(ErrorAgregacion::FueraDeU16)?;
    u16::try_from(valor).map_err(|_| ErrorAgregacion::FueraDeU16)
}

/// Número de agregadores por subred `A` de la red (`REVISION-AGM6.md`; adoptado en `ADOPCION-A5.md`
/// y citado en `ADOPCION-A5-PASO-C.md`).
pub const AGREGADORES_POR_SUBRED: u32 = 62;

/// A4: `true` si `SHA-256(firma_sorteo) · N < A · S · 2^256`, con enteros exactos.
///
/// `huella` es el `SHA-256` de los 96 bytes de la firma de sorteo; `n` es el número de claves de la
/// tabla; `s` y `a` son `S` y `A`. Si `A·S ≥ N`, devuelve `true` para toda huella.
#[must_use]
pub fn sale_agregadora(huella: &Hash, n: usize, s: u16, a: u32) -> bool {
    let umbral = BigUint::from(a) * BigUint::from(s) * (BigUint::from(1u8) << 256usize);
    BigUint::from_bytes_be(huella) * BigUint::from(n) < umbral
}

/// Campos comunes del mensaje A3 que comparten el voto de red y el agregado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MensajeVoto {
    /// Instancia `n`.
    pub n: u64,
    /// Candidato sellado.
    pub candidato: Hash,
    /// `h_T(n+1)` declarado.
    pub h_t_siguiente: Hash,
    /// Raíz de estado firmada.
    pub raiz_estado: Hash,
}

impl MensajeVoto {
    /// Mensaje A3 (`mensaje_voto_peso`).
    #[must_use]
    pub fn mensaje(&self) -> Hash {
        mensaje_voto_peso(
            self.n,
            &self.candidato,
            &self.h_t_siguiente,
            &self.raiz_estado,
        )
    }
}

/// Voto de red compacto A2 (248 B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VotoRed {
    /// Instancia `n`.
    pub n: u64,
    /// Candidato sellado.
    pub candidato: Hash,
    /// `h_T(n+1)` declarado.
    pub h_t_siguiente: Hash,
    /// Raíz de estado firmada.
    pub raiz_estado: Hash,
    /// Clave BLS entera del votante (48 B).
    pub clave: ClavePublica,
    /// Firma A3 del votante.
    pub firma: Firma,
}

impl VotoRed {
    /// Mensaje A3 que firma el voto (`mensaje_voto_peso`).
    #[must_use]
    pub fn mensaje(&self) -> Hash {
        mensaje_voto_peso(
            self.n,
            &self.candidato,
            &self.h_t_siguiente,
            &self.raiz_estado,
        )
    }

    /// Serializa los `248` bytes canónicos.
    #[must_use]
    pub fn serializar(&self) -> Vec<u8> {
        let mut salida = Vec::with_capacity(LONGITUD_VOTO_RED);
        salida.extend_from_slice(&self.n.to_be_bytes());
        salida.extend_from_slice(&self.candidato);
        salida.extend_from_slice(&self.h_t_siguiente);
        salida.extend_from_slice(&self.raiz_estado);
        salida.extend_from_slice(&self.clave.bytes());
        salida.extend_from_slice(&self.firma.bytes());
        salida
    }

    /// Deserializa exactamente `248` bytes.
    ///
    /// # Errores
    /// [`ErrorAgregacion::LongitudInesperada`] si no mide 248; el error de `zx-bls` si la clave o
    /// la firma no son puntos válidos.
    pub fn deserializar(bytes: &[u8]) -> Result<Self, ErrorAgregacion> {
        if bytes.len() != LONGITUD_VOTO_RED {
            return Err(ErrorAgregacion::LongitudInesperada {
                esperado: LONGITUD_VOTO_RED,
                obtenido: bytes.len(),
            });
        }
        let n = u64_be(bytes, 0)?;
        let candidato = hash_be(bytes, 8)?;
        let h_t_siguiente = hash_be(bytes, 40)?;
        let raiz_estado = hash_be(bytes, 72)?;
        let clave = ClavePublica::desde_bytes(trozo(bytes, 104, LONGITUD_CLAVE_PUBLICA)?)?;
        let firma = Firma::desde_bytes(trozo(bytes, 152, LONGITUD_FIRMA)?)?;
        Ok(Self {
            n,
            candidato,
            h_t_siguiente,
            raiz_estado,
            clave,
            firma,
        })
    }

    /// Verifica la firma del voto contra la clave que el propio voto trae sobre A3.
    ///
    /// # Errores
    /// El de `zx-bls` si la firma no verifica.
    pub fn verificar(&self) -> Result<(), ErrorAgregacion> {
        let mensaje = self.mensaje();
        verificar(&self.clave, &self.firma, DOMINIO_VOTO, mensaje.as_slice())?;
        Ok(())
    }
}

/// Agregado de subred A3: `332 + ⌈n_s/8⌉` B.
#[derive(Clone, Debug)]
pub struct Agregado {
    /// Instancia `n`.
    pub n: u64,
    /// Candidato sellado.
    pub candidato: Hash,
    /// `h_T(n+1)` declarado.
    pub h_t_siguiente: Hash,
    /// Raíz de estado firmada.
    pub raiz_estado: Hash,
    /// Firma agregada de los firmantes del mapa.
    pub firma_agregada: FirmaAgregada,
    /// `h_T(n)` de la tabla contra la que está indexado.
    pub huella_tabla: Hash,
    /// Subred 0-based.
    pub subred: u16,
    /// Posición de la agregadora en el orden de la subred.
    pub indice_agregadora: u16,
    /// Mapa local de la subred (`⌈n_s/8⌉` bytes).
    pub mapa_local: Vec<u8>,
    /// Firma de sorteo de la agregadora.
    pub firma_sorteo: Firma,
}

impl PartialEq for Agregado {
    fn eq(&self, otra: &Self) -> bool {
        self.n == otra.n
            && self.candidato == otra.candidato
            && self.h_t_siguiente == otra.h_t_siguiente
            && self.raiz_estado == otra.raiz_estado
            && self.firma_agregada.bytes() == otra.firma_agregada.bytes()
            && self.huella_tabla == otra.huella_tabla
            && self.subred == otra.subred
            && self.indice_agregadora == otra.indice_agregadora
            && self.mapa_local == otra.mapa_local
            && self.firma_sorteo == otra.firma_sorteo
    }
}

impl Eq for Agregado {}

impl Agregado {
    /// Longitud serializada del agregado para una subred de `n_s` claves.
    #[must_use]
    pub fn longitud(n_s: usize) -> usize {
        LONGITUD_FIJA_AGREGADO + n_s.div_ceil(8)
    }

    /// Serializa el agregado (`332 + ⌈n_s/8⌉` bytes).
    #[must_use]
    pub fn serializar(&self) -> Vec<u8> {
        let mut salida = Vec::with_capacity(LONGITUD_FIJA_AGREGADO + self.mapa_local.len());
        salida.extend_from_slice(&self.n.to_be_bytes());
        salida.extend_from_slice(&self.candidato);
        salida.extend_from_slice(&self.h_t_siguiente);
        salida.extend_from_slice(&self.raiz_estado);
        salida.extend_from_slice(&self.firma_agregada.bytes());
        salida.extend_from_slice(&self.huella_tabla);
        salida.extend_from_slice(&self.subred.to_be_bytes());
        salida.extend_from_slice(&self.indice_agregadora.to_be_bytes());
        salida.extend_from_slice(&self.mapa_local);
        salida.extend_from_slice(&self.firma_sorteo.bytes());
        salida
    }

    /// Deserializa un agregado sabiendo el tamaño `n_s` de su subred.
    ///
    /// # Errores
    /// [`ErrorAgregacion::LongitudInesperada`] si el flujo no mide lo que `n_s` exige; el error de
    /// `zx-bls` si la firma agregada o la de sorteo no son puntos válidos.
    pub fn deserializar(bytes: &[u8], n_s: usize) -> Result<Self, ErrorAgregacion> {
        let bytes_mapa = n_s.div_ceil(8);
        let esperado = LONGITUD_FIJA_AGREGADO + bytes_mapa;
        if bytes.len() != esperado {
            return Err(ErrorAgregacion::LongitudInesperada {
                esperado,
                obtenido: bytes.len(),
            });
        }
        let n = u64_be(bytes, 0)?;
        let candidato = hash_be(bytes, 8)?;
        let h_t_siguiente = hash_be(bytes, 40)?;
        let raiz_estado = hash_be(bytes, 72)?;
        let firma_individual = Firma::desde_bytes(trozo(bytes, 104, LONGITUD_FIRMA)?)?;
        let firma_agregada = FirmaAgregada::desde_firma(&firma_individual);
        let huella_tabla = hash_be(bytes, 200)?;
        let subred = u16_be(bytes, 232)?;
        let indice_agregadora = u16_be(bytes, 234)?;
        let mapa_local = trozo(bytes, OFFSET_MAPA_LOCAL, bytes_mapa)?.to_vec();
        let inicio_sorteo = OFFSET_MAPA_LOCAL
            .checked_add(bytes_mapa)
            .ok_or(ErrorAgregacion::FueraDeU16)?;
        let firma_sorteo = Firma::desde_bytes(trozo(bytes, inicio_sorteo, LONGITUD_FIRMA)?)?;
        Ok(Self {
            n,
            candidato,
            h_t_siguiente,
            raiz_estado,
            firma_agregada,
            huella_tabla,
            subred,
            indice_agregadora,
            mapa_local,
            firma_sorteo,
        })
    }
}

/// Contador de sumas de subred calculadas, **solo para las pruebas** (V2, `resta_03`).
///
/// Es un contador por hilo: cuenta cuántas sumas de subred ha calculado este hilo desde el último
/// [`reiniciar`]. No altera ninguna verificación ni ningún resultado; existe para demostrar que la
/// suma de una subred se calcula **una vez por ventana** y no una vez por agregado.
#[doc(hidden)]
pub mod contador_sumas {
    use std::cell::Cell;

    thread_local! {
        static SUMAS: Cell<u64> = const { Cell::new(0) };
    }

    /// Pone a cero el contador de este hilo.
    pub fn reiniciar() {
        SUMAS.with(|celda| celda.set(0));
    }

    /// Número de sumas de subred calculadas en este hilo desde el último [`reiniciar`].
    #[must_use]
    pub fn leer() -> u64 {
        SUMAS.with(Cell::get)
    }

    /// Suma uno al contador de este hilo.
    pub(crate) fn incrementar() {
        SUMAS.with(|celda| celda.set(celda.get().wrapping_add(1)));
    }
}

/// Sumas de las claves de cada subred de una tabla, calculadas **una sola vez por ventana**.
///
/// `sumas[sub]` es la suma de las claves de la subred `sub`; `None` si la subred no tiene claves.
/// Se construye junto a la huella en [`crate::agregador::DatosVentana`] y se comparte entre los
/// estados de la misma ventana. [`SumasSubred::clave_de_mapa`] obtiene la clave de un agregado
/// **restando las ausentes** de la suma de su subred cuando son menos que las presentes; si no,
/// sumando las presentes como antes.
#[derive(Clone, Debug)]
pub struct SumasSubred {
    sumas: Vec<Option<ClaveAgregada>>,
}

impl SumasSubred {
    /// Calcula la suma de cada subred de `reparto` sobre `claves` (paralelas a `tabla.claves`).
    ///
    /// # Errores
    /// El de [`ClaveAgregada::sumar`]; no debería ocurrir, porque una subred no vacía tiene al
    /// menos una clave. [`ErrorAgregacion::ClaveNoRegistrada`] si un índice del reparto no cae en
    /// `claves`.
    pub fn construir(reparto: &Reparto, claves: &[ClavePublica]) -> Result<Self, ErrorAgregacion> {
        let mut sumas: Vec<Option<ClaveAgregada>> = Vec::with_capacity(reparto.s() as usize);
        for sub in 0..reparto.s() {
            let indices = reparto.claves_de(sub);
            if indices.is_empty() {
                sumas.push(None);
                continue;
            }
            let mut publicas: Vec<&ClavePublica> = Vec::with_capacity(indices.len());
            for &idx in indices {
                publicas.push(claves.get(idx).ok_or(ErrorAgregacion::ClaveNoRegistrada)?);
            }
            sumas.push(Some(ClaveAgregada::sumar(&publicas)?));
            contador_sumas::incrementar();
        }
        Ok(Self { sumas })
    }

    /// La suma de la subred `sub`, o `None` si la subred no tiene claves o `sub >= S`.
    #[must_use]
    pub fn de_subred(&self, sub: u16) -> Option<&ClaveAgregada> {
        self.sumas.get(sub as usize).and_then(Option::as_ref)
    }

    /// Número de subredes `S`.
    #[must_use]
    pub fn s(&self) -> usize {
        self.sumas.len()
    }

    /// Clave agregada del mapa de `agregado`: resta las claves **ausentes** de la suma de su subred
    /// cuando son **menos** que las presentes; si no, suma las presentes como antes.
    ///
    /// # Errores
    /// [`ErrorAgregacion::ClaveNoRegistrada`] si un índice del reparto no cae en `claves`.
    pub fn clave_de_mapa(
        &self,
        reparto: &Reparto,
        claves: &[ClavePublica],
        agregado: &Agregado,
    ) -> Result<ClaveAgregada, ErrorAgregacion> {
        let indices = reparto.claves_de(agregado.subred);
        let n_s = indices.len();
        let presentes = (0..n_s)
            .filter(|pos| bit_marcado(&agregado.mapa_local, *pos))
            .count();
        let ausentes = n_s.saturating_sub(presentes);
        if let Some(suma) = self.de_subred(agregado.subred)
            && ausentes < presentes
        {
            let mut clave = *suma;
            for (pos, &idx_global) in indices.iter().enumerate() {
                if !bit_marcado(&agregado.mapa_local, pos) {
                    let publica = claves
                        .get(idx_global)
                        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
                    clave.restar(publica);
                }
            }
            return Ok(clave);
        }
        let mut publicas: Vec<&ClavePublica> = Vec::with_capacity(presentes);
        for (pos, &idx_global) in indices.iter().enumerate() {
            if bit_marcado(&agregado.mapa_local, pos) {
                publicas.push(
                    claves
                        .get(idx_global)
                        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
                );
            }
        }
        Ok(ClaveAgregada::sumar(&publicas)?)
    }
}

/// Motivo por el que un agregado es inválido (A5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MotivoAgregado {
    /// Longitud del mapa o bits sobrantes del último byte.
    Forma,
    /// `subred ≥ S`.
    Subred,
    /// `indice_agregadora` fuera del rango de su subred.
    Indice,
    /// El bit de la agregadora no está marcado en `mapa_local`.
    AgregadoraFueraDeMapa,
    /// La firma de sorteo no cumple la condición del A4.
    SorteoNoSale,
    /// La firma de sorteo no verifica contra la agregadora.
    FirmaSorteo,
    /// La firma agregada no verifica contra las claves del mapa.
    FirmaAgregada,
}

impl MotivoAgregado {
    /// Todos los motivos, en el orden de la orden.
    pub const TODOS: [MotivoAgregado; 7] = [
        MotivoAgregado::Forma,
        MotivoAgregado::Subred,
        MotivoAgregado::Indice,
        MotivoAgregado::AgregadoraFueraDeMapa,
        MotivoAgregado::SorteoNoSale,
        MotivoAgregado::FirmaSorteo,
        MotivoAgregado::FirmaAgregada,
    ];
}

/// Veredicto de un agregado contra una tabla (A5): tres resultados distintos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VeredictoAgregado {
    /// La huella no es la de la tabla dada: se ignora sin penalizar.
    OtraTabla,
    /// Hecho objetivo: forma, subred, índice, bit, sorteo o firma.
    Invalido(MotivoAgregado),
    /// Agregado válido contra la tabla.
    Valido,
}

/// Un candidato que ha pasado las comprobaciones de forma y de sorteo, pendiente de criptografía.
#[derive(Clone, Debug)]
struct Candidato<'a> {
    /// Clave pública agregada que cubre el mapa local: la suma de las claves presentes, obtenida
    /// restando las ausentes de la suma de la subred o sumando las presentes (V2).
    clave_mapa: ClaveAgregada,
    /// Clave pública de la agregadora.
    agregadora: &'a ClavePublica,
}

/// Resultado de preparar un agregado: inválido objetivo o candidato a criptografía.
enum Preparado<'a> {
    Invalido(MotivoAgregado),
    Candidato(Candidato<'a>),
}

/// Longitud en bytes del mapa local de una subred con `n_s` claves.
fn bytes_mapa(n_s: usize) -> usize {
    n_s.div_ceil(8)
}

/// Lee el bit `posicion` (0-based) del mapa local.
fn bit_marcado(mapa: &[u8], posicion: usize) -> bool {
    mapa.get(posicion >> 3)
        .map(|byte| (byte >> (posicion & 7)) & 1 == 1)
        .unwrap_or(false)
}

/// Comprueba forma, subred, índice, bit, sorteo y devuelve el candidato listo para criptografía.
fn preparar<'a>(
    agregado: &Agregado,
    reparto: &Reparto,
    tabla: &Tabla,
    claves: &'a [ClavePublica],
    a: u32,
    sumas: Option<&SumasSubred>,
) -> Result<Preparado<'a>, ErrorAgregacion> {
    if claves.len() != tabla.claves.len() {
        return Err(ErrorAgregacion::LongitudesIncompatibles {
            claves: claves.len(),
            plazas: tabla.claves.len(),
        });
    }
    if agregado.subred >= reparto.s() {
        return Ok(Preparado::Invalido(MotivoAgregado::Subred));
    }
    let indices_subred = reparto.claves_de(agregado.subred);
    let n_s = indices_subred.len();
    if agregado.mapa_local.len() != bytes_mapa(n_s) {
        return Ok(Preparado::Invalido(MotivoAgregado::Forma));
    }
    let sobrantes = n_s.rem_euclid(8);
    if sobrantes != 0 {
        let mascara = 0xFFu8 << sobrantes;
        if agregado
            .mapa_local
            .last()
            .map(|ultimo| ultimo & mascara != 0)
            .unwrap_or(false)
        {
            return Ok(Preparado::Invalido(MotivoAgregado::Forma));
        }
    }
    let posicion = agregado.indice_agregadora as usize;
    if posicion >= n_s {
        return Ok(Preparado::Invalido(MotivoAgregado::Indice));
    }
    if !bit_marcado(&agregado.mapa_local, posicion) {
        return Ok(Preparado::Invalido(MotivoAgregado::AgregadoraFueraDeMapa));
    }
    let huella_sorteo = hash_bytes(&agregado.firma_sorteo.bytes());
    if !sale_agregadora(&huella_sorteo, tabla.claves.len(), reparto.s(), a) {
        return Ok(Preparado::Invalido(MotivoAgregado::SorteoNoSale));
    }
    let clave_mapa = match sumas {
        Some(sumas) => sumas.clave_de_mapa(reparto, claves, agregado)?,
        None => {
            let presentes = indices_marcados(agregado, indices_subred, claves)?;
            ClaveAgregada::sumar(&presentes)?
        }
    };
    let idx_agregadora = indices_subred
        .get(posicion)
        .copied()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let agregadora = claves
        .get(idx_agregadora)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    Ok(Preparado::Candidato(Candidato {
        clave_mapa,
        agregadora,
    }))
}

/// Claves marcadas en el mapa local de un agregado, en orden de subred.
fn indices_marcados<'a>(
    agregado: &Agregado,
    indices_subred: &[usize],
    claves: &'a [ClavePublica],
) -> Result<Vec<&'a ClavePublica>, ErrorAgregacion> {
    let mut publicas = Vec::new();
    for (pos, &idx_global) in indices_subred.iter().enumerate() {
        if bit_marcado(&agregado.mapa_local, pos) {
            let clave = claves
                .get(idx_global)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
            publicas.push(clave);
        }
    }
    Ok(publicas)
}

/// Criptografía de un candidato: firma de sorteo y firma agregada (A5).
fn veredicto_candidato(
    agregado: &Agregado,
    candidato: &Candidato<'_>,
) -> Result<VeredictoAgregado, ErrorAgregacion> {
    let mensaje_sorteo = agregado.n.to_be_bytes();
    if verificar(
        candidato.agregadora,
        &agregado.firma_sorteo,
        DOMINIO_SORTEO,
        &mensaje_sorteo,
    )
    .is_err()
    {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::FirmaSorteo));
    }
    let mensaje = mensaje_voto_peso(
        agregado.n,
        &agregado.candidato,
        &agregado.h_t_siguiente,
        &agregado.raiz_estado,
    );
    if verificar_agregado_con_clave(
        &candidato.clave_mapa,
        &agregado.firma_agregada,
        DOMINIO_VOTO,
        mensaje.as_slice(),
    )
    .is_err()
    {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::FirmaAgregada));
    }
    Ok(VeredictoAgregado::Valido)
}

/// A5: veredicto de un agregado contra una tabla.
///
/// Calcula `h_T = hash_tabla(tabla)` y delega en [`veredicto_con_huella`]; conserva firma y
/// resultado.
///
/// `claves` es la lista de claves públicas **paralela** a `tabla.claves` (mismo orden) y `reparto`
/// el reparto A1 de esa tabla. `a` es `A`.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `claves` no es paralela a la tabla.
pub fn veredicto(
    agregado: &Agregado,
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
) -> Result<VeredictoAgregado, ErrorAgregacion> {
    let huella = hash_tabla(tabla);
    veredicto_con_huella(agregado, tabla, claves, reparto, a, huella)
}

/// A5 (B1): veredicto de un agregado contra una tabla y su huella `h_T` **ya calculada**.
///
/// Es la variante que usan [`crate::agregador::EstadoVentana`] y
/// [`crate::ventana_raices::VentanaPorRaices`] con la huella de
/// [`crate::agregador::DatosVentana`], de modo que recibir un agregado **no** vuelve a serializar
/// ni hashear la tabla. El resultado es **idéntico** al de [`veredicto`] cuando `huella ==
/// hash_tabla(tabla)`.
///
/// `claves` es la lista de claves públicas **paralela** a `tabla.claves` (mismo orden) y `reparto`
/// el reparto A1 de esa tabla. `a` es `A`.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `claves` no es paralela a la tabla.
pub fn veredicto_con_huella(
    agregado: &Agregado,
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
    huella: Hash,
) -> Result<VeredictoAgregado, ErrorAgregacion> {
    veredicto_con_huella_opcional(agregado, tabla, claves, reparto, a, huella, None)
}

/// A5 (V2): veredicto de un agregado contra una tabla y su huella `h_T` **ya calculada**, con las
/// **sumas de subred de la ventana**.
///
/// Igual que [`veredicto_con_huella`], pero la clave que cubre el mapa local se obtiene de
/// [`SumasSubred`]: restando las claves ausentes de la suma de la subred cuando son menos que las
/// presentes, o sumando las presentes como antes. El resultado es **idéntico** al de
/// [`veredicto_con_huella`] para toda entrada.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `claves` no es paralela a la tabla.
pub fn veredicto_con_huella_y_sumas(
    agregado: &Agregado,
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
    huella: Hash,
    sumas: &SumasSubred,
) -> Result<VeredictoAgregado, ErrorAgregacion> {
    veredicto_con_huella_opcional(agregado, tabla, claves, reparto, a, huella, Some(sumas))
}

/// Implementación única de [`veredicto_con_huella`] y [`veredicto_con_huella_y_sumas`].
fn veredicto_con_huella_opcional(
    agregado: &Agregado,
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
    huella: Hash,
    sumas: Option<&SumasSubred>,
) -> Result<VeredictoAgregado, ErrorAgregacion> {
    if claves.len() != tabla.claves.len() {
        return Err(ErrorAgregacion::LongitudesIncompatibles {
            claves: claves.len(),
            plazas: tabla.claves.len(),
        });
    }
    if agregado.huella_tabla != huella {
        return Ok(VeredictoAgregado::OtraTabla);
    }
    match preparar(agregado, reparto, tabla, claves, a, sumas)? {
        Preparado::Invalido(motivo) => Ok(VeredictoAgregado::Invalido(motivo)),
        Preparado::Candidato(candidato) => veredicto_candidato(agregado, &candidato),
    }
}

/// Generador de escalares de 128 bits para el lote (A6). En las pruebas, con semilla.
pub trait GeneradorEscalares {
    /// Devuelve el siguiente escalar de 128 bits.
    fn escalar(&mut self) -> [u8; LONGITUD_ESCALAR_LOTE];

    /// Gancho de observación: se llama **una vez** al empezar cada verificación por lotes (cada
    /// grupo de mensaje; también cada bisección de aislamiento). La implementación por defecto no
    /// hace nada. Las pruebas lo cuentan para demostrar que un lote sin inválidos hace una sola
    /// verificación por mensaje. **No** altera la verificación ni su resultado.
    fn inicio_verificacion(&mut self) {}

    /// Gancho de observación (A5-c-1a-4): se llama **una vez por agregado** que entra en una
    /// verificación por lotes (también en cada bisección de aislamiento). La implementación por
    /// defecto no hace nada. Las pruebas y los cronómetros lo cuentan para decir cuántos agregados
    /// hubo que verificar tras descartar los que no añaden ninguna clave. **No** altera la
    /// verificación ni su resultado.
    fn verificacion_de_agregado(&mut self) {}
}

/// Comprueba un subconjunto de candidatos con coeficientes frescos del generador.
fn lote_pasa(
    candidatos: &[(usize, Candidato<'_>)],
    agregados: &[Agregado],
    indices: &[usize],
    mensaje: &Hash,
    n: u64,
    generador: &mut impl GeneradorEscalares,
) -> Result<bool, ErrorAgregacion> {
    generador.inicio_verificacion();
    let mut escalares_agregados = Vec::with_capacity(indices.len());
    let mut escalares_sorteos = Vec::with_capacity(indices.len());
    let mut claves_agregadas: Vec<&ClaveAgregada> = Vec::with_capacity(indices.len());
    let mut firmas_agregadas: Vec<&FirmaAgregada> = Vec::with_capacity(indices.len());
    let mut claves_sorteo: Vec<&ClavePublica> = Vec::with_capacity(indices.len());
    let mut firmas_sorteo: Vec<&Firma> = Vec::with_capacity(indices.len());

    for &j in indices {
        let (i, candidato) = candidatos
            .get(j)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let agregado = agregados
            .get(*i)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        generador.verificacion_de_agregado();
        escalares_agregados.push(generador.escalar());
        escalares_sorteos.push(generador.escalar());
        claves_agregadas.push(&candidato.clave_mapa);
        firmas_agregadas.push(&agregado.firma_agregada);
        claves_sorteo.push(candidato.agregadora);
        firmas_sorteo.push(&agregado.firma_sorteo);
    }

    let mensaje_sorteo = n.to_be_bytes();
    let agregados_ok = verificar_lote_de_agregados_con_clave(
        &claves_agregadas,
        &firmas_agregadas,
        &escalares_agregados,
        DOMINIO_VOTO,
        mensaje.as_slice(),
    )
    .is_ok();
    let sorteos_ok = verificar_lote_con_escalares(
        &claves_sorteo,
        &firmas_sorteo,
        &escalares_sorteos,
        DOMINIO_SORTEO,
        &mensaje_sorteo,
    )
    .is_ok();
    Ok(agregados_ok && sorteos_ok)
}

/// Aísla los inválidos de un grupo partiendo en dos (A6).
fn aislar(
    candidatos: &[(usize, Candidato<'_>)],
    agregados: &[Agregado],
    indices: &[usize],
    mensaje: &Hash,
    n: u64,
    generador: &mut impl GeneradorEscalares,
    valido: &mut [bool],
) -> Result<(), ErrorAgregacion> {
    if indices.is_empty() {
        return Ok(());
    }
    if lote_pasa(candidatos, agregados, indices, mensaje, n, generador)? {
        for &j in indices {
            if let Some(v) = valido.get_mut(j) {
                *v = true;
            }
        }
        return Ok(());
    }
    if indices.len() == 1 {
        return Ok(());
    }
    let medio = indices.len().div_ceil(2);
    let (izquierda, derecha) = indices.split_at(medio);
    aislar(
        candidatos, agregados, izquierda, mensaje, n, generador, valido,
    )?;
    aislar(
        candidatos, agregados, derecha, mensaje, n, generador, valido,
    )
}

/// A6: verifica muchos agregados y sus firmas de sorteo con coeficientes aleatorios.
///
/// Calcula `h_T = hash_tabla(tabla)` y delega en [`verificar_lote_con_huella`]; conserva firma y
/// resultado.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `claves` no es paralela a la tabla.
pub fn verificar_lote(
    agregados: &[Agregado],
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
    generador: &mut impl GeneradorEscalares,
) -> Result<Vec<VeredictoAgregado>, ErrorAgregacion> {
    let huella = hash_tabla(tabla);
    verificar_lote_con_huella(agregados, tabla, claves, reparto, a, huella, generador)
}

/// A6 (B1): verifica muchos agregados y sus firmas de sorteo con coeficientes aleatorios, contra
/// una tabla y su huella `h_T` **ya calculada**.
///
/// Agrupa por mensaje/ventana (los lotes criptográficos solo admiten un mensaje común), verifica
/// cada grupo por lotes y, si un grupo falla, **aísla** los inválidos partiendo en dos. El veredicto
/// devuelto por agregado es idéntico al de [`veredicto_con_huella`] uno a uno, y al de
/// [`verificar_lote`] cuando `huella == hash_tabla(tabla)`.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `claves` no es paralela a la tabla.
pub fn verificar_lote_con_huella(
    agregados: &[Agregado],
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
    huella: Hash,
    generador: &mut impl GeneradorEscalares,
) -> Result<Vec<VeredictoAgregado>, ErrorAgregacion> {
    verificar_lote_con_huella_opcional(
        agregados, tabla, claves, reparto, a, huella, None, generador,
    )
}

/// A6 (V2): verifica muchos agregados contra una tabla, su huella `h_T` ya calculada y las **sumas
/// de subred de la ventana**.
///
/// Igual que [`verificar_lote_con_huella`], pero la clave de cada agregado se obtiene de
/// [`SumasSubred`] (resta de ausentes o suma de presentes). El veredicto por agregado es
/// **idéntico** al de [`verificar_lote_con_huella`] y al de [`veredicto_con_huella`] uno a uno.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `claves` no es paralela a la tabla.
#[allow(
    clippy::too_many_arguments,
    reason = "espeja la firma publica con un parametro adicional (las sumas de la ventana)"
)]
pub fn verificar_lote_con_huella_y_sumas(
    agregados: &[Agregado],
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
    huella: Hash,
    sumas: &SumasSubred,
    generador: &mut impl GeneradorEscalares,
) -> Result<Vec<VeredictoAgregado>, ErrorAgregacion> {
    verificar_lote_con_huella_opcional(
        agregados,
        tabla,
        claves,
        reparto,
        a,
        huella,
        Some(sumas),
        generador,
    )
}

/// Implementación única de [`verificar_lote_con_huella`] y
/// [`verificar_lote_con_huella_y_sumas`].
#[allow(
    clippy::too_many_arguments,
    reason = "espeja la firma publica con un parametro opcional interno"
)]
fn verificar_lote_con_huella_opcional(
    agregados: &[Agregado],
    tabla: &Tabla,
    claves: &[ClavePublica],
    reparto: &Reparto,
    a: u32,
    huella: Hash,
    sumas: Option<&SumasSubred>,
    generador: &mut impl GeneradorEscalares,
) -> Result<Vec<VeredictoAgregado>, ErrorAgregacion> {
    if claves.len() != tabla.claves.len() {
        return Err(ErrorAgregacion::LongitudesIncompatibles {
            claves: claves.len(),
            plazas: tabla.claves.len(),
        });
    }
    let mut veredictos: Vec<VeredictoAgregado> = Vec::with_capacity(agregados.len());
    let mut candidatos: Vec<(usize, Candidato<'_>)> = Vec::new();

    for (i, agregado) in agregados.iter().enumerate() {
        if agregado.huella_tabla != huella {
            veredictos.push(VeredictoAgregado::OtraTabla);
            continue;
        }
        match preparar(agregado, reparto, tabla, claves, a, sumas)? {
            Preparado::Invalido(motivo) => {
                veredictos.push(VeredictoAgregado::Invalido(motivo));
            }
            Preparado::Candidato(candidato) => {
                // Marcador que se sobrescribe al resolver la criptografía; mantiene `veredictos`
                // alineado con `agregados`.
                veredictos.push(VeredictoAgregado::Invalido(MotivoAgregado::Forma));
                candidatos.push((i, candidato));
            }
        }
    }

    // Agrupa por (ventana, mensaje A3): el lote criptográfico exige un mensaje común.
    let mut grupos: BTreeMap<(u64, Hash), Vec<usize>> = BTreeMap::new();
    for (j, (i, _)) in candidatos.iter().enumerate() {
        let agregado = agregados
            .get(*i)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let mensaje = mensaje_voto_peso(
            agregado.n,
            &agregado.candidato,
            &agregado.h_t_siguiente,
            &agregado.raiz_estado,
        );
        grupos.entry((agregado.n, mensaje)).or_default().push(j);
    }

    let mut valido = vec![false; candidatos.len()];
    for ((n, mensaje), indices) in &grupos {
        aislar(
            &candidatos,
            agregados,
            indices,
            mensaje,
            *n,
            generador,
            &mut valido,
        )?;
    }

    for (j, (i, candidato)) in candidatos.iter().enumerate() {
        let agregado = agregados
            .get(*i)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let resultado = if valido.get(j).copied().unwrap_or(false) {
            VeredictoAgregado::Valido
        } else {
            veredicto_candidato(agregado, candidato)?
        };
        if let Some(slot) = veredictos.get_mut(*i) {
            *slot = resultado;
        }
    }

    Ok(veredictos)
}

/// A7: arma el mapa global y la firma agregada de un [`CertificadoPeso`] verificable (AG-R14).
///
/// `pesos` es el peso de cada clave, **paralelo** a `tabla.claves`. De los agregados dados (del
/// mismo mensaje) toma **uno por subred**: el que maximiza el peso de las claves de esa subred
/// cubiertas por su `mapa_local` **o por un voto suelto** (aritmética `u128` saturada); a igualdad,
/// el de `indice_agregadora` menor. Añade los votos sueltos `(índice 1-based en `tabla.claves`,
/// firma)` que no estén ya cubiertos; una subred sin agregado aporta sus sueltos. No decide el
/// quórum.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `pesos` no es paralelo a `tabla.claves`;
/// [`ErrorAgregacion::ClaveNoRegistrada`] si un voto suelto cae fuera de la tabla;
/// [`ErrorAgregacion::Bls`] si la firma combinada no se puede construir (por ejemplo, sin firmantes).
pub fn armar_certificado(
    mensaje: MensajeVoto,
    tabla: &Tabla,
    pesos: &[u128],
    reparto: &Reparto,
    agregados: &[Agregado],
    votos_sueltos: &[(usize, Firma)],
) -> Result<CertificadoPeso, ErrorAgregacion> {
    let (mapa, firmas) = elegir_mapa_firmas(tabla, pesos, reparto, agregados, votos_sueltos)?;
    let referencias: Vec<&Firma> = firmas.iter().collect();
    let firma = agregar_firmas(&referencias)?;
    Ok(CertificadoPeso {
        n: mensaje.n,
        candidato: mensaje.candidato,
        h_t_siguiente: mensaje.h_t_siguiente,
        raiz_estado: mensaje.raiz_estado,
        firma,
        mapa,
    })
}

/// Elige el mapa global y las firmas que hay que agregar (AG-R14), sin criptografía.
///
/// Implementación **única** de la elección por peso unido, compartida por [`armar_certificado`] y el
/// estado de ventana de [`crate::agregador`]. Devuelve el mapa global y las firmas en el orden en
/// que se agregan: primero la de cada agregado elegido (por subred ascendente) y después los
/// sueltos no cubiertos, en el orden de `votos_sueltos`.
///
/// # Errores
/// [`ErrorAgregacion::LongitudesIncompatibles`] si `pesos` no es paralelo a `tabla.claves`;
/// [`ErrorAgregacion::ClaveNoRegistrada`] si un voto suelto cae fuera de la tabla.
pub(crate) fn elegir_mapa_firmas(
    tabla: &Tabla,
    pesos: &[u128],
    reparto: &Reparto,
    agregados: &[Agregado],
    votos_sueltos: &[(usize, Firma)],
) -> Result<(Vec<u8>, Vec<Firma>), ErrorAgregacion> {
    let n_claves = tabla.claves.len();
    if pesos.len() != n_claves {
        return Err(ErrorAgregacion::LongitudesIncompatibles {
            claves: pesos.len(),
            plazas: n_claves,
        });
    }

    // Claves con voto suelto registrado, por índice global 0-based.
    let mut suelto = vec![false; n_claves];
    for (indice, _) in votos_sueltos {
        let posicion = indice
            .checked_sub(1)
            .filter(|posicion| *posicion < n_claves)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        if let Some(marca) = suelto.get_mut(posicion) {
            *marca = true;
        }
    }

    // El mejor agregado por subred: más peso unido (mapa ∪ sueltos de la subred); a igualdad, menor
    // índice de agregadora.
    let mut mejores: BTreeMap<u16, (usize, u128, u16)> = BTreeMap::new();
    for (i, agregado) in agregados.iter().enumerate() {
        let indices_subred = reparto.claves_de(agregado.subred);
        let mut peso_union: u128 = 0;
        for (pos, &idx_global) in indices_subred.iter().enumerate() {
            let en_mapa = bit_marcado(&agregado.mapa_local, pos);
            let en_suelto = suelto.get(idx_global).copied().unwrap_or(false);
            if en_mapa || en_suelto {
                let peso = pesos.get(idx_global).copied().unwrap_or(0);
                peso_union = peso_union.saturating_add(peso);
            }
        }
        let mejora = match mejores.get(&agregado.subred) {
            None => true,
            Some((_, peso_previo, indice_previo)) => {
                peso_union > *peso_previo
                    || (peso_union == *peso_previo && agregado.indice_agregadora < *indice_previo)
            }
        };
        if mejora {
            mejores.insert(agregado.subred, (i, peso_union, agregado.indice_agregadora));
        }
    }

    let mut mapa = vec![0u8; bytes_mapa(n_claves)];
    let mut firmas: Vec<Firma> = Vec::new();
    for (i, _, _) in mejores.values() {
        let agregado = agregados
            .get(*i)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let indices_subred = reparto.claves_de(agregado.subred);
        for (pos, &idx_global) in indices_subred.iter().enumerate() {
            if bit_marcado(&agregado.mapa_local, pos)
                && let Some(byte) = mapa.get_mut(idx_global >> 3)
            {
                *byte |= 1 << (idx_global & 7);
            }
        }
        let firma = Firma::desde_bytes(&agregado.firma_agregada.bytes())?;
        firmas.push(firma);
    }

    for (indice, firma) in votos_sueltos {
        let posicion = indice
            .checked_sub(1)
            .filter(|posicion| *posicion < n_claves)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        if !bit_marcado(&mapa, posicion) {
            if let Some(byte) = mapa.get_mut(posicion >> 3) {
                *byte |= 1 << (posicion & 7);
            }
            firmas.push(*firma);
        }
    }

    Ok((mapa, firmas))
}

/// Trozo acotado `[inicio, inicio+n)`.
fn trozo(bytes: &[u8], inicio: usize, n: usize) -> Result<&[u8], ErrorAgregacion> {
    let fin = inicio
        .checked_add(n)
        .ok_or(ErrorAgregacion::LongitudInesperada {
            esperado: inicio,
            obtenido: bytes.len(),
        })?;
    bytes
        .get(inicio..fin)
        .ok_or(ErrorAgregacion::LongitudInesperada {
            esperado: fin,
            obtenido: bytes.len(),
        })
}

/// `u64` big-endian en `inicio`.
fn u64_be(bytes: &[u8], inicio: usize) -> Result<u64, ErrorAgregacion> {
    let mut arreglo = [0u8; 8];
    arreglo.copy_from_slice(trozo(bytes, inicio, 8)?);
    Ok(u64::from_be_bytes(arreglo))
}

/// `u16` big-endian en `inicio`.
fn u16_be(bytes: &[u8], inicio: usize) -> Result<u16, ErrorAgregacion> {
    let mut arreglo = [0u8; 2];
    arreglo.copy_from_slice(trozo(bytes, inicio, 2)?);
    Ok(u16::from_be_bytes(arreglo))
}

/// `Hash` de 32 bytes en `inicio`.
fn hash_be(bytes: &[u8], inicio: usize) -> Result<Hash, ErrorAgregacion> {
    let mut hash = [0u8; LONGITUD_HASH];
    hash.copy_from_slice(trozo(bytes, inicio, LONGITUD_HASH)?);
    Ok(hash)
}
