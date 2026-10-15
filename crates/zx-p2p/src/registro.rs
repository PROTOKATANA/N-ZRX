//! Registro firmado de direcciones de productores (entrada `ZXREG1`) y su retención
//! (`ORDEN-RD1c`, pasos 1 y 2; contrato `PCRD2` con las correcciones de `ADOPCION-A8-PARTE1`).
//!
//! # Qué resuelve
//!
//! Un productor de bloques firma con su **clave de productor** (Ed25519, la misma que firma el
//! campo `productor` de un bloque) una entrada que ata esa clave a sus **direcciones de marcado**.
//! La entrada viaja fuera de la cadena y el nodo la publica y la pide por el stream de sync. El
//! director puede entonces **sortear** a qué productor marcar con probabilidad proporcional a sus
//! bloques certificados, en vez de elegir uniformemente.
//!
//! # Formato exacto (contrato §3)
//!
//! ```text
//! version(1)=0x01 ‖ red(1) ‖ productor(32) ‖ epoch(8 BE) ‖ CompactSize(n_addr) ‖
//! addr[i] = CompactSize(len) ‖ multiaddr cruda   ‖ firma(64)
//! ```
//!
//! La firma cubre el **cuerpo entero** (todo menos la firma) y se verifica con
//! [`zx_core::firma::verificar`] sobre `SHA3-256("ZXREG01" ‖ cuerpo)`. El contrato fija `epoch` en
//! **big-endian**; se escribe con `to_be_bytes` explícito (la primitiva `int::escribir_u64` del
//! códec es little-endian y no se usa aquí).
//!
//! # Retención (G2)
//!
//! Hay **una** entrada por productor. Una entrada es *productiva* si su productor está en la tabla
//! de pesos vigente y *pendiente* si no. Las pendientes tienen tope y caducidad propios y **nunca**
//! desalojan a una productiva; una productiva solo la sustituye otra del mismo productor con época
//! mayor. Sin tabla de pesos, o con el registro vacío, no hay sorteo.

use std::collections::BTreeMap;

use libp2p::Multiaddr;
use thiserror::Error;
use zx_core::digest::Digest;
use zx_core::encoding::{compact_size, int};
use zx_core::error::EncodingError;
use zx_core::firma::{ClavePublica, Firma, verificar};
use zx_core::red::Red;

use crate::gestor::{Entrada, es_enrutable};
use crate::limites;
use crate::mensaje::{red_desde_discriminante, red_discriminante};

/// Dominio de firma de la entrada `ZXREG1`.
pub const DOMINIO_FIRMA: &[u8] = b"ZXREG01";

/// Versión del formato de la entrada `ZXREG1`.
pub const VERSION: u8 = 0x01;

/// Error del registro firmado de direcciones.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorRegistro {
    /// Error del códec de `zx-core` (truncado, contador no mínimo…).
    #[error(transparent)]
    Codificacion(#[from] EncodingError),

    /// La versión del wire no es [`VERSION`].
    #[error("ZXREG1: versión desconocida {0:#04x}")]
    VersionDesconocida(u8),

    /// El byte de red del wire no es ninguna red conocida.
    #[error("ZXREG1: red desconocida en el wire: {0:#04x}")]
    RedDesconocida(u8),

    /// La entrada es de otra red.
    #[error("ZXREG1: red distinta: se esperaba {esperada:?}, llegó {encontrada:?}")]
    RedDistinta {
        /// Red esperada.
        esperada: Red,
        /// Red declarada.
        encontrada: Red,
    },

    /// La firma no verifica con la clave de productor declarada.
    #[error("ZXREG1: firma inválida")]
    FirmaInvalida,

    /// La época no es estrictamente mayor que la última vista de ese productor.
    #[error("ZXREG1: época {epoch} no es mayor que la última vista {ultima}")]
    EpocaNoCreciente {
        /// Época de la entrada nueva.
        epoch: u64,
        /// Última época aceptada de ese productor.
        ultima: u64,
    },

    /// La época está fuera de la ventana `V` del reloj local.
    #[error("ZXREG1: época {epoch} fuera de la ventana V={v} de {ahora}")]
    EpocaFueraDeVentana {
        /// Época de la entrada.
        epoch: u64,
        /// Reloj local de referencia.
        ahora: u64,
        /// Semiancho de la ventana.
        v: u64,
    },

    /// La entrada declara más direcciones que [`limites::MAX_DIRECCIONES_POR_ENTRADA`].
    #[error("ZXREG1: demasiadas direcciones ({declaradas} > {maximo})")]
    DemasiadasDirecciones {
        /// Cuántas declara.
        declaradas: u64,
        /// Tope.
        maximo: usize,
    },

    /// Una dirección cruda supera [`limites::MAX_MULTIADDR_BYTES`].
    #[error("ZXREG1: multiaddr de {bytes} B supera {maximo} B")]
    MultiaddrDemasiadoGrande {
        /// Bytes declarados.
        bytes: u64,
        /// Tope.
        maximo: usize,
    },

    /// La multiaddr no decodifica.
    #[error("ZXREG1: multiaddr inválida")]
    MultiaddrInvalida,

    /// Ninguna dirección es aceptable por las reglas del gestor (C-NET-36/44).
    #[error("ZXREG1: dirección no aceptable por el gestor")]
    DireccionNoAceptable,

    /// La entrada codificada supera [`limites::MAX_ENTRADA_REGISTRO_BYTES`].
    #[error("ZXREG1: la entrada supera el máximo del códec ({bytes} > {max})")]
    EntradaDemasiadoGrande {
        /// Bytes consumidos.
        bytes: u64,
        /// Tope.
        max: u64,
    },

    /// El registro está apagado (`registro_activo = false`).
    #[error("ZXREG1: el registro está apagado")]
    RegistroApagado,

    /// La tabla de pendientes está llena (tope de `G2`).
    #[error("ZXREG1: tabla de pendientes llena ({max})")]
    PendientesLlenas {
        /// Tope de pendientes.
        max: usize,
    },
}

/// Una entrada firmada del registro de direcciones (`ZXREG1`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntradaRegistro {
    /// Versión del formato ([`VERSION`]).
    pub version: u8,
    /// Red a la que pertenece la entrada.
    pub red: Red,
    /// Clave Ed25519 de productor (32 B).
    pub productor: ClavePublica,
    /// Época, estrictamente creciente por productor.
    pub epoch: u64,
    /// Direcciones de marcado publicadas.
    pub direcciones: Vec<Multiaddr>,
    /// Firma Ed25519 sobre `SHA3-256("ZXREG01" ‖ cuerpo)`.
    pub firma: Firma,
}

/// Toma `n` bytes de `bytes` o falla con el error de truncado del códec.
fn tomar(bytes: &[u8], n: usize) -> Result<(&[u8], &[u8]), ErrorRegistro> {
    if bytes.len() < n {
        return Err(ErrorRegistro::Codificacion(EncodingError::Truncado {
            esperados: n,
            disponibles: bytes.len(),
        }));
    }
    Ok(bytes.split_at(n))
}

/// Lee un `u64` **big-endian** y devuelve el resto (contrato §3).
fn leer_u64_be(bytes: &[u8]) -> Result<(u64, &[u8]), ErrorRegistro> {
    let (crudo, resto) = tomar(bytes, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(crudo);
    Ok((u64::from_be_bytes(arr), resto))
}

/// ¿Acepta el gestor esta dirección en esta red? (misma regla que `GestorDirecciones::acepta`).
#[must_use]
pub fn direccion_aceptable(addr: &Multiaddr, red: Red) -> bool {
    let Some(e) = Entrada::de_multiaddr(addr.clone(), None) else {
        return false;
    };
    if e.ip.is_loopback() || !es_enrutable(e.ip) {
        red == Red::Dev
    } else {
        true
    }
}

impl EntradaRegistro {
    /// El cuerpo firmado: todo menos la firma.
    #[must_use]
    pub fn cuerpo(&self) -> Vec<u8> {
        let mut b = Vec::new();
        int::escribir_u8(&mut b, self.version);
        int::escribir_u8(&mut b, red_discriminante(self.red));
        b.extend_from_slice(self.productor.bytes());
        b.extend_from_slice(&self.epoch.to_be_bytes());
        compact_size::escribir(&mut b, self.direcciones.len() as u64);
        for a in &self.direcciones {
            let crudo = a.to_vec();
            compact_size::escribir(&mut b, crudo.len() as u64);
            b.extend_from_slice(&crudo);
        }
        b
    }

    /// El `signature_digest` de la entrada: `SHA3-256("ZXREG01" ‖ cuerpo)`.
    #[must_use]
    pub fn preimagen(&self) -> Digest {
        let mut b = Vec::with_capacity(DOMINIO_FIRMA.len() + 64);
        b.extend_from_slice(DOMINIO_FIRMA);
        b.extend_from_slice(&self.cuerpo());
        zx_core::sha3_256_publico(&b)
    }

    /// Verifica la firma contra la clave de productor declarada (ZIP-215).
    ///
    /// # Errores
    /// [`ErrorRegistro::FirmaInvalida`] si no verifica.
    pub fn verificar_firma(&self) -> Result<(), ErrorRegistro> {
        verificar(&self.productor, &self.firma, self.preimagen().as_bytes())
            .map_err(|_| ErrorRegistro::FirmaInvalida)
    }

    /// Valida los campos que no dependen del estado (`G1`): versión, red, ventana de época y
    /// direcciones aceptables.
    ///
    /// # Errores
    /// El [`ErrorRegistro`] del primer campo que no cumpla.
    pub fn validar(&self, red_esperada: Red, ahora: u64, v: u64) -> Result<(), ErrorRegistro> {
        if self.version != VERSION {
            return Err(ErrorRegistro::VersionDesconocida(self.version));
        }
        if self.red != red_esperada {
            return Err(ErrorRegistro::RedDistinta {
                esperada: red_esperada,
                encontrada: self.red,
            });
        }
        validar_epoca(self.epoch, None, ahora, v)?;
        if self.direcciones.is_empty() {
            return Err(ErrorRegistro::DireccionNoAceptable);
        }
        if self.direcciones.len() > limites::MAX_DIRECCIONES_POR_ENTRADA {
            return Err(ErrorRegistro::DemasiadasDirecciones {
                declaradas: self.direcciones.len() as u64,
                maximo: limites::MAX_DIRECCIONES_POR_ENTRADA,
            });
        }
        for a in &self.direcciones {
            if !direccion_aceptable(a, self.red) {
                return Err(ErrorRegistro::DireccionNoAceptable);
            }
        }
        Ok(())
    }

    /// Comprueba la época contra la última vista de ese productor y contra la ventana `V`.
    ///
    /// # Errores
    /// [`ErrorRegistro::EpocaNoCreciente`] o [`ErrorRegistro::EpocaFueraDeVentana`].
    pub fn verificar_epoca(
        &self,
        ultima: Option<u64>,
        ahora: u64,
        v: u64,
    ) -> Result<(), ErrorRegistro> {
        validar_epoca(self.epoch, ultima, ahora, v)
    }
}

/// ¿Cae `epoch` dentro de `[ahora - V, ahora + V]` y es mayor que `ultima`?
///
/// # Errores
/// [`ErrorRegistro::EpocaNoCreciente`] o [`ErrorRegistro::EpocaFueraDeVentana`].
pub fn validar_epoca(
    epoch: u64,
    ultima: Option<u64>,
    ahora: u64,
    v: u64,
) -> Result<(), ErrorRegistro> {
    if let Some(u) = ultima
        && epoch <= u
    {
        return Err(ErrorRegistro::EpocaNoCreciente { epoch, ultima: u });
    }
    let minimo = ahora.saturating_sub(v);
    let maximo = ahora.saturating_add(v);
    if epoch < minimo || epoch > maximo {
        return Err(ErrorRegistro::EpocaFueraDeVentana { epoch, ahora, v });
    }
    Ok(())
}

/// Serializa una entrada `ZXREG1` completa (cuerpo ‖ firma).
#[must_use]
pub fn entrada_a_bytes(e: &EntradaRegistro) -> Vec<u8> {
    let mut b = e.cuerpo();
    b.extend_from_slice(e.firma.bytes());
    b
}

/// Deserializa una entrada `ZXREG1` y devuelve el resto del buffer.
///
/// El parser acota **cada campo** antes de reservar: el número de direcciones, la longitud de cada
/// una y la firma. No reserva por adelantado el tamaño del buffer de entrada (C-WIRE-04).
///
/// # Errores
/// [`ErrorRegistro`] con el campo que no decodifique o el tope que se supere.
pub fn entrada_desde_bytes(bytes: &[u8]) -> Result<(EntradaRegistro, &[u8]), ErrorRegistro> {
    let (version, r) = int::leer_u8(bytes)?;
    let (red_b, r) = int::leer_u8(r)?;
    let red = red_desde_discriminante(red_b).ok_or(ErrorRegistro::RedDesconocida(red_b))?;
    let (prod_b, r) = tomar(r, 32)?;
    let mut prod = [0u8; 32];
    prod.copy_from_slice(prod_b);
    let (epoch, r) = leer_u64_be(r)?;

    let (n, r) = compact_size::leer(r)?;
    if n > limites::MAX_DIRECCIONES_POR_ENTRADA as u64 {
        return Err(ErrorRegistro::DemasiadasDirecciones {
            declaradas: n,
            maximo: limites::MAX_DIRECCIONES_POR_ENTRADA,
        });
    }
    let n = usize::try_from(n).map_err(|_| ErrorRegistro::DemasiadasDirecciones {
        declaradas: u64::MAX,
        maximo: limites::MAX_DIRECCIONES_POR_ENTRADA,
    })?;

    let mut direcciones = Vec::with_capacity(n);
    let mut r = r;
    for _ in 0..n {
        let (len, resto) = compact_size::leer(r)?;
        if len > limites::MAX_MULTIADDR_BYTES as u64 {
            return Err(ErrorRegistro::MultiaddrDemasiadoGrande {
                bytes: len,
                maximo: limites::MAX_MULTIADDR_BYTES,
            });
        }
        let len = usize::try_from(len).map_err(|_| ErrorRegistro::MultiaddrDemasiadoGrande {
            bytes: u64::MAX,
            maximo: limites::MAX_MULTIADDR_BYTES,
        })?;
        let (crudo, resto) = tomar(resto, len)?;
        let addr =
            Multiaddr::try_from(crudo.to_vec()).map_err(|_| ErrorRegistro::MultiaddrInvalida)?;
        direcciones.push(addr);
        r = resto;
    }

    let (sig_b, r) = tomar(r, 64)?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_b);

    let consumido = (bytes.len() - r.len()) as u64;
    if consumido > limites::MAX_ENTRADA_REGISTRO_BYTES {
        return Err(ErrorRegistro::EntradaDemasiadoGrande {
            bytes: consumido,
            max: limites::MAX_ENTRADA_REGISTRO_BYTES,
        });
    }

    let entrada = EntradaRegistro {
        version,
        red,
        productor: ClavePublica::desde_bytes(prod),
        epoch,
        direcciones,
        firma: Firma::desde_bytes(sig),
    };
    Ok((entrada, r))
}

/// Clase de una entrada del registro (`G2`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaseRegistro {
    /// Su productor está en la tabla de pesos vigente.
    Productiva,
    /// Su productor no está en la tabla: queda pendiente, acotada y con caducidad.
    Pendiente,
}

/// Una candidata sorteada: productor, dirección de marcado y peso.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidataSorteada {
    /// Productor al que pertenece la dirección.
    pub productor: ClavePublica,
    /// Dirección de marcado elegida (la primera aceptable de la entrada).
    pub addr: Multiaddr,
    /// Peso del productor (bloques certificados) en el momento del sorteo.
    pub peso: u64,
}

#[derive(Clone, Debug)]
struct Guardada {
    entrada: EntradaRegistro,
    desde: u64,
}

/// Registro de direcciones con retención por clase y sorteo ponderado (`G2`/`G4`).
#[derive(Clone, Debug)]
pub struct RegistroDirecciones {
    red: Red,
    v_epoca: u64,
    max_pendientes: usize,
    ttl_pendiente: u64,
    activo: bool,
    pesos: BTreeMap<ClavePublica, u64>,
    entradas: BTreeMap<ClavePublica, Guardada>,
}

impl RegistroDirecciones {
    /// Un registro vacío con su red, ventana de época y topes.
    #[must_use]
    pub fn nuevo(
        red: Red,
        v_epoca: u64,
        max_pendientes: usize,
        ttl_pendiente: u64,
        activo: bool,
    ) -> Self {
        Self {
            red,
            v_epoca,
            max_pendientes,
            ttl_pendiente,
            activo,
            pesos: BTreeMap::new(),
            entradas: BTreeMap::new(),
        }
    }

    /// ¿Está el registro encendido?
    #[must_use]
    pub const fn activo(&self) -> bool {
        self.activo
    }

    /// ¿No hay ninguna entrada retenida?
    #[must_use]
    pub fn esta_vacio(&self) -> bool {
        self.entradas.is_empty()
    }

    /// Fija la tabla de pesos vigente: `productor → bloques certificados`.
    ///
    /// Un peso `0` no entra: no aporta probabilidad y no debe clasificar como productiva.
    pub fn fijar_pesos<I>(&mut self, pesos: I)
    where
        I: IntoIterator<Item = (ClavePublica, u64)>,
    {
        self.pesos = pesos
            .into_iter()
            .filter(|(_, w)| *w > 0)
            .collect::<BTreeMap<_, _>>();
    }

    /// Vacía la tabla de pesos. Sin tabla no hay sorteo (`G3`).
    pub fn limpiar_pesos(&mut self) {
        self.pesos.clear();
    }

    /// El peso vigente de un productor, si está en la tabla.
    #[must_use]
    pub fn peso(&self, p: &ClavePublica) -> Option<u64> {
        self.pesos.get(p).copied()
    }

    /// La clase retenida de un productor, si tiene entrada.
    #[must_use]
    pub fn clase(&self, p: &ClavePublica) -> Option<ClaseRegistro> {
        self.entradas.get(p).map(|_| {
            if self.pesos.contains_key(p) {
                ClaseRegistro::Productiva
            } else {
                ClaseRegistro::Pendiente
            }
        })
    }

    /// La entrada retenida de un productor.
    #[must_use]
    pub fn get(&self, p: &ClavePublica) -> Option<&EntradaRegistro> {
        self.entradas.get(p).map(|g| &g.entrada)
    }

    /// Cuántas entradas pendientes hay ahora mismo (productores fuera de la tabla).
    #[must_use]
    pub fn pendientes(&self) -> usize {
        self.entradas
            .keys()
            .filter(|p| !self.pesos.contains_key(p))
            .count()
    }

    /// Cuántas entradas retenidas hay ahora mismo (productivas y pendientes).
    #[must_use]
    pub fn longitud(&self) -> u64 {
        self.entradas.len() as u64
    }

    /// Una página de entradas retenidas, en el orden estable de la tabla (clave de productor),
    /// empezando en el índice `desde`. Devuelve como mucho `max_entradas` entradas y respeta
    /// `max_bytes` (tamaño en el wire de cada entrada); siempre incluye al menos una si `desde` está
    /// dentro de rango, para no dejar a quien pide sin poder avanzar. Devuelve también la longitud
    /// **total** del registro.
    ///
    /// `ORDEN-RD3c` (N2): el nodo sirve `Peticion::RegistroDirecciones` con esta página. RD-1c dejó
    /// el registro pero no una vía de paginación; esta es la corrección mínima que el paso 3
    /// necesita (se entrega con su `diff`).
    #[must_use]
    pub fn pagina(
        &self,
        desde: u64,
        max_entradas: usize,
        max_bytes: u64,
    ) -> (Vec<EntradaRegistro>, u64) {
        let longitud = self.entradas.len() as u64;
        let inicio = usize::try_from(desde).unwrap_or(usize::MAX);
        let mut salida = Vec::new();
        let mut bytes: u64 = 0;
        for g in self.entradas.values().skip(inicio).take(max_entradas) {
            let tam = entrada_a_bytes(&g.entrada).len() as u64;
            if !salida.is_empty() && bytes.saturating_add(tam) > max_bytes {
                break;
            }
            salida.push(g.entrada.clone());
            bytes = bytes.saturating_add(tam);
        }
        (salida, longitud)
    }

    /// Expira las pendientes cuyo TTL venció. **Nunca** toca a las productivas.
    pub fn expirar(&mut self, ahora: u64) {
        let ttl = self.ttl_pendiente;
        let pesos = &self.pesos;
        self.entradas
            .retain(|p, g| pesos.contains_key(p) || ahora.saturating_sub(g.desde) < ttl);
    }

    /// Retiene una entrada, aplicando `G1` (validación y firma, salvo la época contra la última
    /// vista) y `G2` (clases, tope y caducidad de pendientes).
    ///
    /// # Errores
    /// [`ErrorRegistro`] si el registro está apagado, la entrada no valida, la firma no verifica,
    /// la época no crece o la tabla de pendientes está llena.
    pub fn insertar(
        &mut self,
        e: EntradaRegistro,
        ahora: u64,
    ) -> Result<ClaseRegistro, ErrorRegistro> {
        if !self.activo {
            return Err(ErrorRegistro::RegistroApagado);
        }
        e.validar(self.red, ahora, self.v_epoca)?;
        e.verificar_firma()?;

        if let Some(g) = self.entradas.get(&e.productor)
            && e.epoch <= g.entrada.epoch
        {
            return Err(ErrorRegistro::EpocaNoCreciente {
                epoch: e.epoch,
                ultima: g.entrada.epoch,
            });
        }

        let productiva = self.pesos.contains_key(&e.productor);
        if !productiva && !self.entradas.contains_key(&e.productor) {
            self.expirar(ahora);
            if self.pendientes() >= self.max_pendientes {
                return Err(ErrorRegistro::PendientesLlenas {
                    max: self.max_pendientes,
                });
            }
        }

        self.entradas.insert(
            e.productor,
            Guardada {
                entrada: e,
                desde: ahora,
            },
        );
        Ok(if productiva {
            ClaseRegistro::Productiva
        } else {
            ClaseRegistro::Pendiente
        })
    }

    /// Sortea **una** entrada productiva con probabilidad proporcional a su peso (`G4`).
    ///
    /// `r` es la entropía del generador del director; el índice objetivo es `r mod Σ pesos`.
    /// Devuelve `None` si no hay tabla, no hay productivas con dirección aceptable o el peso total
    /// es cero. No elige entradas sin dirección publicada (`sorteo_no_elige_sin_direccion_publicada`).
    #[must_use]
    pub fn sortear(&self, r: u64) -> Option<CandidataSorteada> {
        let mut total: u64 = 0;
        let mut elegibles: Vec<(&ClavePublica, &EntradaRegistro, u64, &Multiaddr)> = Vec::new();
        for (p, g) in &self.entradas {
            let Some(peso) = self.pesos.get(p).copied() else {
                continue;
            };
            if peso == 0 {
                continue;
            }
            let Some(addr) = g
                .entrada
                .direcciones
                .iter()
                .find(|a| direccion_aceptable(a, self.red))
            else {
                continue;
            };
            total = total.saturating_add(peso);
            elegibles.push((p, &g.entrada, peso, addr));
        }
        if total == 0 {
            return None;
        }
        let objetivo = r % total;
        let mut acumulado: u64 = 0;
        for (p, _entrada, peso, addr) in elegibles {
            acumulado = acumulado.saturating_add(peso);
            if objetivo < acumulado {
                return Some(CandidataSorteada {
                    productor: *p,
                    addr: addr.clone(),
                    peso,
                });
            }
        }
        None
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::*;
    use libp2p::identity::ed25519;
    use libp2p::multiaddr::Protocol;

    fn par(semilla: u8) -> (ed25519::Keypair, ClavePublica) {
        let sk = ed25519::SecretKey::try_from_bytes([semilla; 32]).unwrap();
        let kp = ed25519::Keypair::from(sk);
        let pk = ClavePublica::desde_bytes(kp.public().to_bytes());
        (kp, pk)
    }

    fn prod(semilla: u8) -> ClavePublica {
        par(semilla).1
    }

    fn dir(n: u8) -> Multiaddr {
        Multiaddr::from(Protocol::Ip4(std::net::Ipv4Addr::new(10, 0, 0, n)))
    }

    /// Una entrada con firma **válida** (el productor firma su propio cuerpo).
    fn firmada(semilla: u8, epoch: u64, dirs: Vec<Multiaddr>) -> EntradaRegistro {
        let (kp, pk) = par(semilla);
        let mut e = EntradaRegistro {
            version: VERSION,
            red: Red::Dev,
            productor: pk,
            epoch,
            direcciones: dirs,
            firma: Firma::desde_bytes([0u8; 64]),
        };
        let sig = kp.sign(e.preimagen().as_bytes());
        let arr: [u8; 64] = sig.try_into().unwrap();
        e.firma = Firma::desde_bytes(arr);
        e
    }

    fn registro(max_pendientes: usize, ttl: u64) -> RegistroDirecciones {
        RegistroDirecciones::nuevo(Red::Dev, 1_000, max_pendientes, ttl, true)
    }

    fn multiaddr_de_longitud(objetivo: usize) -> Multiaddr {
        (1..=objetivo)
            .map(|n| Multiaddr::from(Protocol::Dns("a".repeat(n).into())))
            .find(|a| a.to_vec().len() == objetivo)
            .expect("existe una multiaddr de esa longitud")
    }

    /// El códec de la entrada da la vuelta y la firma verifica.
    #[test]
    fn zxreg1_ida_y_vuelta() {
        let e = firmada(1, 42, vec![dir(1), dir(2)]);
        let b = entrada_a_bytes(&e);
        let (leida, resto) = entrada_desde_bytes(&b).unwrap();
        assert_eq!(leida, e);
        assert!(resto.is_empty());
        assert_eq!(leida.cuerpo(), e.cuerpo());
        assert_eq!(leida.preimagen(), e.preimagen());
        leida.verificar_firma().unwrap();
    }

    /// Una firma que no verifica se rechaza.
    #[test]
    fn zxreg1_firma_invalida_se_rechaza() {
        let mut e = firmada(2, 42, vec![dir(1)]);
        e.firma = Firma::desde_bytes([0u8; 64]);
        assert_eq!(e.verificar_firma(), Err(ErrorRegistro::FirmaInvalida));

        // Cambiar un campo del cuerpo (después de firmar) también invalida.
        let mut e2 = firmada(3, 42, vec![dir(1)]);
        e2.epoch = 43;
        assert_eq!(e2.verificar_firma(), Err(ErrorRegistro::FirmaInvalida));
    }

    /// La época no puede ser no creciente ni caer fuera de la ventana `V`.
    #[test]
    fn zxreg1_epoca_vieja_o_futura_se_rechaza() {
        let ahora = 10_000u64;
        let v = 100u64;
        assert!(validar_epoca(ahora, None, ahora, v).is_ok());
        assert!(validar_epoca(9_900, None, ahora, v).is_ok());
        assert!(validar_epoca(10_100, None, ahora, v).is_ok());
        assert_eq!(
            validar_epoca(10_101, None, ahora, v).unwrap_err(),
            ErrorRegistro::EpocaFueraDeVentana {
                epoch: 10_101,
                ahora,
                v
            }
        );
        assert_eq!(
            validar_epoca(9_899, None, ahora, v).unwrap_err(),
            ErrorRegistro::EpocaFueraDeVentana {
                epoch: 9_899,
                ahora,
                v
            }
        );
        assert_eq!(
            validar_epoca(500, Some(500), ahora, v).unwrap_err(),
            ErrorRegistro::EpocaNoCreciente {
                epoch: 500,
                ultima: 500
            }
        );

        // Sobre la entrada: `verificar_epoca` y `validar` comprueban la ventana.
        let e = firmada(4, 9_000, vec![dir(1)]);
        assert!(matches!(
            e.verificar_epoca(None, ahora, v),
            Err(ErrorRegistro::EpocaFueraDeVentana { .. })
        ));
        assert!(matches!(
            e.validar(Red::Dev, ahora, v),
            Err(ErrorRegistro::EpocaFueraDeVentana { .. })
        ));
        let mut e2 = firmada(5, ahora, vec![dir(1)]);
        e2.epoch = ahora + v + 1;
        assert!(matches!(
            e2.validar(Red::Dev, ahora, v),
            Err(ErrorRegistro::EpocaFueraDeVentana { .. })
        ));
    }

    /// El tamaño máximo de una entrada está atado al códec: la entrada maximal cabe y los topes de
    /// cada campo se rechazan antes de reservar.
    #[test]
    fn zxreg1_tamano_maximo_atado_al_codec() {
        let larga = multiaddr_de_longitud(limites::MAX_MULTIADDR_BYTES);
        let dirs: Vec<Multiaddr> = (0..limites::MAX_DIRECCIONES_POR_ENTRADA)
            .map(|_| larga.clone())
            .collect();
        let e = firmada(6, 100, dirs);
        let b = entrada_a_bytes(&e);
        assert!(
            b.len() as u64 <= limites::MAX_ENTRADA_REGISTRO_BYTES,
            "{} > {}",
            b.len(),
            limites::MAX_ENTRADA_REGISTRO_BYTES
        );
        assert!(
            limites::MAX_ENTRADA_REGISTRO_BYTES - (b.len() as u64) < 9,
            "la cota no está atada al códec"
        );
        let (leida, resto) = entrada_desde_bytes(&b).unwrap();
        assert_eq!(leida, e);
        assert!(resto.is_empty());

        // Un contador de direcciones por encima del tope se rechaza.
        let mut malo = vec![VERSION, 0x02];
        malo.extend_from_slice(&[0u8; 32]);
        malo.extend_from_slice(&0u64.to_be_bytes());
        zx_core::encoding::compact_size::escribir(
            &mut malo,
            (limites::MAX_DIRECCIONES_POR_ENTRADA + 1) as u64,
        );
        assert!(matches!(
            entrada_desde_bytes(&malo),
            Err(ErrorRegistro::DemasiadasDirecciones { .. })
        ));

        // Una multiaddr por encima del tope se rechaza sin construirla.
        let mut malo2 = vec![VERSION, 0x02];
        malo2.extend_from_slice(&[0u8; 32]);
        malo2.extend_from_slice(&0u64.to_be_bytes());
        zx_core::encoding::compact_size::escribir(&mut malo2, 1);
        zx_core::encoding::compact_size::escribir(
            &mut malo2,
            (limites::MAX_MULTIADDR_BYTES + 1) as u64,
        );
        assert!(matches!(
            entrada_desde_bytes(&malo2),
            Err(ErrorRegistro::MultiaddrDemasiadoGrande { .. })
        ));
    }

    /// Una pendiente **nunca** desaloja a una productiva; el tope de pendientes se respeta.
    #[test]
    fn registro_pendiente_no_desaloja_productiva() {
        let mut r = registro(1, 1_000);
        let p = prod(10);
        r.fijar_pesos([(p, 5)]);
        r.insertar(firmada(10, 1_000, vec![dir(10)]), 1_000)
            .unwrap();

        let q = prod(11);
        r.insertar(firmada(11, 1_000, vec![dir(11)]), 1_000)
            .unwrap();
        assert_eq!(r.clase(&p), Some(ClaseRegistro::Productiva));
        assert_eq!(r.clase(&q), Some(ClaseRegistro::Pendiente));

        let s = prod(12);
        assert_eq!(
            r.insertar(firmada(12, 1_000, vec![dir(12)]), 1_000),
            Err(ErrorRegistro::PendientesLlenas { max: 1 })
        );
        assert_eq!(r.clase(&p), Some(ClaseRegistro::Productiva));
        assert_eq!(r.clase(&q), Some(ClaseRegistro::Pendiente));
        assert!(r.get(&s).is_none());
    }

    /// Las pendientes caducan por TTL y liberan su sitio en el tope.
    #[test]
    fn registro_pendiente_caduca_y_respeta_el_tope() {
        let mut r = registro(1, 10);
        let q = prod(11);
        r.insertar(firmada(11, 1_000, vec![dir(11)]), 1_000)
            .unwrap();
        assert_eq!(r.pendientes(), 1);

        r.expirar(1_009);
        assert!(r.get(&q).is_some(), "antes del TTL sigue");
        r.expirar(1_010);
        assert!(r.get(&q).is_none(), "al vencer el TTL caduca");

        let s = prod(12);
        r.insertar(firmada(12, 1_010, vec![dir(12)]), 1_010)
            .unwrap();
        assert_eq!(r.clase(&s), Some(ClaseRegistro::Pendiente));
    }

    /// Una productiva solo la sustituye otra del mismo productor con época mayor.
    #[test]
    fn registro_sustituye_solo_por_epoca_mayor() {
        let mut r = registro(4, 1_000);
        let p = prod(20);
        r.fijar_pesos([(p, 7)]);
        r.insertar(firmada(20, 1_000, vec![dir(20)]), 1_000)
            .unwrap();

        assert!(matches!(
            r.insertar(firmada(20, 1_000, vec![dir(21)]), 1_000),
            Err(ErrorRegistro::EpocaNoCreciente { .. })
        ));
        assert!(matches!(
            r.insertar(firmada(20, 999, vec![dir(21)]), 1_000),
            Err(ErrorRegistro::EpocaNoCreciente { .. })
        ));

        r.insertar(firmada(20, 1_001, vec![dir(21)]), 1_000)
            .unwrap();
        assert_eq!(r.get(&p).unwrap().direcciones, vec![dir(21)]);
    }
}
