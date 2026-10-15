//! Gestor de direcciones de la red (C-NET-35…C-NET-39, DN-02/04/07/08/09).
//!
//! # Qué resuelve
//!
//! Las direcciones descubiertas **no entran directamente en las salientes**: entran primero en este
//! gestor, que las clasifica en dos tablas (`nuevos` y `probados`), las agrupa por prefijo de red y
//! solo promociona a `probados` lo que ya respondió a una conexión saliente. La selección de
//! candidatos es **uniforme** (C-NET-37): el sesgo por frescura es justo lo que Heilman explota.
//!
//! # Unidad de coste
//!
//! La identidad (`PeerId`) es gratis; el recurso escaso es la **IP y el prefijo** (A.3). Por eso los
//! topes son por `grupo_ancho` (`/16` IPv4, `/32` IPv6) y `grupo_estrecho` (`/24` IPv4, `/48` IPv6),
//! y Teredo, 6to4 y las IPv4-mapeadas se agrupan por su IPv4 enlazada para no regalar diversidad
//! falsa (C-NET-36).
//!
//! # Modo dev (C-NET-44, DN-09)
//!
//! Toda relajación depende de [`Red::Dev`]. En loopback, el grupo es el `PeerId` —igual que la
//! penalización de `limites_ip`— para que los nodos de la red dev no colapsen en `127.0.0.0/24`.
//! Fuera de `Red::Dev`, una dirección no enrutable se rechaza y el modo dev no puede activarse: la
//! prueba de que `ParametrosRed::de(Mainnet/Testnet)` no lo enciende vive en [`crate::config`].
//!
//! # Persistencia
//!
//! Formato binario propio (sin dependencias nuevas), inspirado en `peers.dat`/`anchors.dat`: la
//! `nKey` aleatoria viaja en el fichero y hace impredecible la posición de bucket. `nuevos` y
//! `probados` se guardan juntas en `gestor-red.dat`; las anclas, aparte, en `anclas-red.dat`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use zx_core::red::Red;

use crate::config::PerfilRed;

/// Nombre del fichero que persiste `nuevos`, `probados` y la `nKey`.
pub const FICHERO_GESTOR: &str = "gestor-red.dat";
/// Nombre del fichero que persiste las anclas.
pub const FICHERO_ANCLAS: &str = "anclas-red.dat";

/// Número máximo de entradas por bucket (precedente: 64 en `addrman`).
const CAP_BUCKET: usize = 64;

/// Etiqueta de dominio de hash para la tabla `nuevos`.
const ETIQUETA_NUEVOS: u8 = 1;
/// Etiqueta de dominio de hash para la tabla `probados`.
const ETIQUETA_PROBADOS: u8 = 2;

const MAGIC_GESTOR: [u8; 8] = *b"ZXGEST01";
const MAGIC_ANCLAS: [u8; 8] = *b"ZXANCL01";

/// Error del gestor de direcciones.
#[derive(Debug, thiserror::Error)]
pub enum ErrorGestor {
    /// Fallo de entrada/salida al leer o escribir la persistencia.
    #[error("E/S del gestor de direcciones: {0}")]
    Io(#[from] io::Error),
    /// El fichero de persistencia no tiene el formato esperado.
    #[error("fichero del gestor de direcciones corrupto: {0}")]
    Corrupto(&'static str),
    /// El `PeerId` persistido no decodifica.
    #[error("PeerId persistido inválido")]
    PeerId,
    /// La `Multiaddr` persistida no decodifica.
    #[error("multiaddr persistida inválida")]
    Multiaddr,
}

/// Grupo **ancho**: reparte buckets y acota la diversidad de salientes (`/16` IPv4, `/32` IPv6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GrupoAncho {
    /// Un prefijo `/16` de IPv4.
    V4([u8; 2]),
    /// Un prefijo `/32` de IPv6.
    V6([u8; 4]),
    /// Modo dev sobre loopback: el grupo es el `PeerId` (DN-09).
    Peer(PeerId),
}

/// Grupo **estrecho**: acota la acumulación dentro de un grupo ancho (`/24` IPv4, `/48` IPv6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GrupoEstrecho {
    /// Un prefijo `/24` de IPv4.
    V4([u8; 3]),
    /// Un prefijo `/48` de IPv6.
    V6([u8; 6]),
    /// Modo dev sobre loopback: el grupo es el `PeerId` (DN-09).
    Peer(PeerId),
}

/// Aplica la agrupación por IPv4 enlazada a Teredo, 6to4 e IPv4-mapeada (C-NET-36).
#[must_use]
pub fn ip_agrupable(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let o = v6.octets();
    // 6to4 (2002::/16): el IPv4 va en los bytes 2..6.
    if o.first() == Some(&0x20) && o.get(1) == Some(&0x02) {
        let (Some(a), Some(b), Some(c), Some(d)) = (o.get(2), o.get(3), o.get(4), o.get(5)) else {
            return ip;
        };
        return IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d));
    }
    // Teredo (2001::/32): cliente IPv4 en los bytes 12..16, complementados a uno.
    if o.first() == Some(&0x20)
        && o.get(1) == Some(&0x01)
        && o.get(2) == Some(&0x00)
        && o.get(3) == Some(&0x00)
    {
        let (Some(a), Some(b), Some(c), Some(d)) = (o.get(12), o.get(13), o.get(14), o.get(15))
        else {
            return ip;
        };
        let cliente = Ipv4Addr::new(!*a, !*b, !*c, !*d);
        if !cliente.is_unspecified() {
            return IpAddr::V4(cliente);
        }
        let (Some(a), Some(b), Some(c), Some(d)) = (o.get(4), o.get(5), o.get(6), o.get(7)) else {
            return ip;
        };
        let servidor = Ipv4Addr::new(*a, *b, *c, *d);
        if !servidor.is_unspecified() {
            return IpAddr::V4(servidor);
        }
    }
    ip
}

impl GrupoAncho {
    /// El grupo ancho de una IP, ya normalizada por [`ip_agrupable`].
    #[must_use]
    pub fn de_ip(ip: IpAddr) -> Self {
        match ip_agrupable(ip) {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Self::V4([
                    o.first().copied().unwrap_or(0),
                    o.get(1).copied().unwrap_or(0),
                ])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                let mut g = [0u8; 4];
                g.copy_from_slice(o.get(..4).unwrap_or(&[0u8; 4]));
                Self::V6(g)
            }
        }
    }
}

impl GrupoEstrecho {
    /// El grupo estrecho de una IP, ya normalizada por [`ip_agrupable`].
    #[must_use]
    pub fn de_ip(ip: IpAddr) -> Self {
        match ip_agrupable(ip) {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Self::V4([
                    o.first().copied().unwrap_or(0),
                    o.get(1).copied().unwrap_or(0),
                    o.get(2).copied().unwrap_or(0),
                ])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                let mut g = [0u8; 6];
                g.copy_from_slice(o.get(..6).unwrap_or(&[0u8; 6]));
                Self::V6(g)
            }
        }
    }
}

/// ¿Es una dirección enrutable en producción?
///
/// No enrutables: loopback, privadas, link-local, multicast, no especificada, broadcast y
/// documentación. En `Red::Dev` el gestor las admite (relajación de C-NET-44); fuera de dev, no.
#[must_use]
pub fn es_enrutable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments().first().copied().unwrap_or(0);
            let link_local = (seg0 & 0xffc0) == 0xfe80;
            let unique_local = (seg0 & 0xfe00) == 0xfc00;
            let multicast = (seg0 & 0xff00) == 0xff00;
            let documentacion = seg0 == 0x2001 && v6.segments().get(1) == Some(&0x0db8);
            !(v6.is_loopback()
                || v6.is_unspecified()
                || link_local
                || unique_local
                || multicast
                || documentacion)
        }
    }
}

/// Una dirección de la tabla: la `Multiaddr`, su `PeerId` si se conoce, y su IP/puerto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entrada {
    /// Multiaddr completa (sin el componente `/p2p`, que va en `peer`).
    pub addr: Multiaddr,
    /// `PeerId` asociado, si se conoce.
    pub peer: Option<PeerId>,
    /// IP extraída de la multiaddr.
    pub ip: IpAddr,
    /// Puerto TCP/UDP extraído de la multiaddr (`0` si no lleva).
    pub puerto: u16,
}

impl Entrada {
    /// Construye una entrada a partir de una multiaddr, si lleva IP.
    ///
    /// Si `peer` es `None` y la multiaddr termina en `/p2p/<PeerId>`, se extrae de ahí.
    #[must_use]
    pub fn de_multiaddr(addr: Multiaddr, peer: Option<PeerId>) -> Option<Self> {
        let mut ip = None;
        let mut puerto = 0u16;
        let mut peer = peer;
        for p in addr.iter() {
            match p {
                Protocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
                Protocol::Ip6(v6) => ip = Some(IpAddr::V6(v6)),
                Protocol::Tcp(p) | Protocol::Udp(p) => puerto = p,
                Protocol::P2p(p) => peer = Some(p),
                _ => {}
            }
        }
        ip.map(|ip| Self {
            addr,
            peer,
            ip,
            puerto,
        })
    }

    /// Clave de deduplicación: `(IP, puerto)`.
    #[must_use]
    fn clave(&self) -> (IpAddr, u16) {
        (ip_agrupable(self.ip), self.puerto)
    }
}

/// Resultado de intentar insertar una entrada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Insercion {
    /// Se insertó.
    Insertada,
    /// Ya estaba (misma `(IP, puerto)`).
    Duplicada,
    /// Hay que probar a la incumbente antes de desalojarla (`test-before-evict`, C-NET-40).
    Colision {
        /// La entrada que ocupa el sitio y debe probarse.
        desaloja: Entrada,
    },
    /// Rechazada (no enrutable fuera de dev, o tabla/grupo llenos sin candidata a desalojo).
    Rechazada,
}

/// Una tabla de direcciones con buckets y cuentas por grupo.
#[derive(Clone, Debug)]
struct Tabla {
    buckets: Vec<Vec<Entrada>>,
    n_buckets: usize,
    cap_ancho: usize,
    cap_estrecho: usize,
    cuenta_ancho: HashMap<GrupoAncho, usize>,
    cuenta_estrecho: HashMap<GrupoEstrecho, usize>,
    total: usize,
    dev_peer: bool,
}

impl Tabla {
    #[expect(
        clippy::integer_division,
        reason = "división entera deliberada: el número de buckets es total/64"
    )]
    fn nueva(total_objetivo: usize, cap_ancho: usize, cap_estrecho: usize, dev_peer: bool) -> Self {
        let n_buckets = (total_objetivo / CAP_BUCKET).max(1);
        let mut buckets = Vec::with_capacity(n_buckets);
        for _ in 0..n_buckets {
            buckets.push(Vec::new());
        }
        Self {
            buckets,
            n_buckets,
            cap_ancho,
            cap_estrecho,
            cuenta_ancho: HashMap::new(),
            cuenta_estrecho: HashMap::new(),
            total: 0,
            dev_peer,
        }
    }

    fn grupos(&self, e: &Entrada) -> (GrupoAncho, GrupoEstrecho) {
        if self.dev_peer
            && e.ip.is_loopback()
            && let Some(p) = e.peer
        {
            return (GrupoAncho::Peer(p), GrupoEstrecho::Peer(p));
        }
        (GrupoAncho::de_ip(e.ip), GrupoEstrecho::de_ip(e.ip))
    }

    fn contiene(&self, e: &Entrada) -> bool {
        let c = e.clave();
        self.buckets
            .iter()
            .any(|b| b.iter().any(|x| x.clave() == c))
    }

    fn iter(&self) -> impl Iterator<Item = Entrada> + '_ {
        self.buckets.iter().flat_map(|b| b.iter().cloned())
    }

    fn candidata_desalojo(&self, ga: GrupoAncho, inicio: usize) -> Option<Entrada> {
        for i in 0..self.n_buckets {
            let b = (inicio + i) % self.n_buckets;
            if let Some(e) = self
                .buckets
                .get(b)
                .and_then(|bucket| bucket.iter().find(|x| self.grupos(x).0 == ga))
            {
                return Some(e.clone());
            }
        }
        self.iter().find(|x| self.grupos(x).0 == ga)
    }

    fn anotar(&mut self, e: &Entrada, delta: isize) {
        let (ga, gs) = self.grupos(e);
        let a = self.cuenta_ancho.entry(ga).or_insert(0);
        *a = a.saturating_add_signed(delta);
        if *a == 0 {
            self.cuenta_ancho.remove(&ga);
        }
        let s = self.cuenta_estrecho.entry(gs).or_insert(0);
        *s = s.saturating_add_signed(delta);
        if *s == 0 {
            self.cuenta_estrecho.remove(&gs);
        }
        self.total = self.total.saturating_add_signed(delta);
    }

    fn insertar(
        &mut self,
        e: Entrada,
        n_key: &[u8; 32],
        etiqueta: u8,
        probados: bool,
    ) -> Insercion {
        if self.contiene(&e) {
            return Insercion::Duplicada;
        }
        let (ga, _gs) = self.grupos(&e);
        let inicio = (posicion(n_key, etiqueta, &e.ip, e.puerto) as usize) % self.n_buckets;

        let lleno_ancho = self.cuenta_ancho.get(&ga).copied().unwrap_or(0) >= self.cap_ancho;
        let lleno_estrecho = {
            let gs = self.grupos(&e).1;
            self.cuenta_estrecho.get(&gs).copied().unwrap_or(0) >= self.cap_estrecho
        };
        if lleno_ancho || lleno_estrecho {
            if probados {
                return match self.candidata_desalojo(ga, inicio) {
                    Some(desaloja) => Insercion::Colision { desaloja },
                    None => Insercion::Rechazada,
                };
            }
            return Insercion::Rechazada;
        }

        for i in 0..self.n_buckets {
            let b = (inicio + i) % self.n_buckets;
            let libre = self
                .buckets
                .get(b)
                .is_some_and(|bucket| bucket.len() < CAP_BUCKET);
            if !libre {
                continue;
            }
            if probados
                && self
                    .buckets
                    .get(b)
                    .is_some_and(|bucket| bucket.iter().any(|x| self.grupos(x).0 == ga))
            {
                continue;
            }
            if let Some(bucket) = self.buckets.get_mut(b) {
                bucket.push(e.clone());
                self.anotar(&e, 1);
                return Insercion::Insertada;
            }
        }

        if probados {
            return match self.candidata_desalojo(ga, inicio) {
                Some(desaloja) => Insercion::Colision { desaloja },
                None => Insercion::Rechazada,
            };
        }
        Insercion::Rechazada
    }

    fn desalojar(&mut self, e: &Entrada) -> bool {
        let c = e.clave();
        for bucket in &mut self.buckets {
            if let Some(pos) = bucket.iter().position(|x| x.clave() == c)
                && let Some(quitada) = bucket.get(pos).cloned()
            {
                let _ = bucket.remove(pos);
                self.anotar(&quitada, -1);
                return true;
            }
        }
        false
    }
}

/// Posición de bucket: `hash(nKey, tabla, IP, puerto)`, impredecible sin `nKey` (C-NET-35).
fn posicion(n_key: &[u8; 32], etiqueta: u8, ip: &IpAddr, puerto: u16) -> u64 {
    let mut buf = Vec::with_capacity(32 + 1 + 17 + 2);
    buf.extend_from_slice(n_key);
    buf.push(etiqueta);
    match ip {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&puerto.to_be_bytes());
    let d = zx_core::sha3_256_publico(&buf);
    let mut out = [0u8; 8];
    out.copy_from_slice(d.as_bytes().get(..8).unwrap_or(&[0u8; 8]));
    u64::from_be_bytes(out)
}

/// Cuota de direcciones por par y ventana (DN-07).
#[derive(Clone, Debug)]
struct CuotaDirecciones {
    por_mensaje: usize,
    tope: usize,
    ventana: Duration,
    por_par: HashMap<PeerId, (Instant, usize)>,
}

impl CuotaDirecciones {
    fn nuevo(por_mensaje: usize, tope: usize, ventana: Duration) -> Self {
        Self {
            por_mensaje,
            tope,
            ventana,
            por_par: HashMap::new(),
        }
    }

    fn admitir(&mut self, peer: PeerId, n: usize, ahora: Instant) -> usize {
        let entrada = self.por_par.entry(peer).or_insert((ahora, 0));
        if ahora.duration_since(entrada.0) >= self.ventana {
            *entrada = (ahora, 0);
        }
        let restante = self.tope.saturating_sub(entrada.1);
        let admitidas = n.min(self.por_mensaje).min(restante);
        entrada.1 = entrada.1.saturating_add(admitidas);
        admitidas
    }
}

/// Gestor de direcciones: `nuevos`, `probados`, anclas y cuota de mensajes.
#[derive(Clone, Debug)]
pub struct GestorDirecciones {
    n_key: [u8; 32],
    red: Red,
    perfil: PerfilRed,
    nuevos: Tabla,
    probados: Tabla,
    anclas: Vec<Entrada>,
    cuota: CuotaDirecciones,
}

impl GestorDirecciones {
    /// Un gestor vacío con una `nKey` aleatoria de `/dev/urandom`.
    #[must_use]
    pub fn nuevo(red: Red, perfil: PerfilRed) -> Self {
        Self::con_n_key(red, perfil, n_key_aleatoria())
    }

    /// Igual, con una `nKey` explícita (para pruebas reproducibles).
    #[must_use]
    pub fn con_n_key(red: Red, perfil: PerfilRed, n_key: [u8; 32]) -> Self {
        let dev_peer = red == Red::Dev;
        Self {
            n_key,
            red,
            perfil,
            nuevos: Tabla::nueva(
                perfil.nuevos,
                perfil.cap_ancho,
                perfil.cap_estrecho,
                dev_peer,
            ),
            probados: Tabla::nueva(
                perfil.probados,
                perfil.cap_ancho,
                perfil.cap_estrecho,
                dev_peer,
            ),
            anclas: Vec::new(),
            cuota: CuotaDirecciones::nuevo(
                perfil.dirs_por_mensaje,
                perfil.cuota_tope,
                perfil.cuota_ventana,
            ),
        }
    }

    /// La `nKey` persistida.
    #[must_use]
    pub const fn n_key(&self) -> &[u8; 32] {
        &self.n_key
    }

    /// La red de este gestor.
    #[must_use]
    pub const fn red(&self) -> Red {
        self.red
    }

    /// ¿Admite esta dirección? Fuera de `Red::Dev` las no enrutables se rechazan (C-NET-36/44).
    #[must_use]
    pub fn acepta(&self, e: &Entrada) -> bool {
        if e.ip.is_loopback() || !es_enrutable(e.ip) {
            return self.red == Red::Dev;
        }
        true
    }

    /// El grupo ancho con el que se contabiliza una entrada (expuesto para pruebas y para salientes).
    #[must_use]
    pub fn grupo_ancho(&self, e: &Entrada) -> GrupoAncho {
        self.probados.grupos(e).0
    }

    /// Cuántas entradas hay en `probados`.
    #[must_use]
    pub const fn total_probados(&self) -> usize {
        self.probados.total
    }

    /// Cuántas entradas hay en `nuevos`.
    #[must_use]
    pub const fn total_nuevos(&self) -> usize {
        self.nuevos.total
    }

    /// Inserta en `nuevos` (nunca desaloja). Devuelve si se insertó.
    pub fn insertar_nuevo(&mut self, e: Entrada) -> bool {
        if !self.acepta(&e) {
            return false;
        }
        matches!(
            self.nuevos.insertar(e, &self.n_key, ETIQUETA_NUEVOS, false),
            Insercion::Insertada
        )
    }

    /// Inserta en `probados`, devolviendo colisión si hay que probar a una incumbente.
    pub fn insertar_probado(&mut self, e: Entrada) -> Insercion {
        if !self.acepta(&e) {
            return Insercion::Rechazada;
        }
        self.probados
            .insertar(e, &self.n_key, ETIQUETA_PROBADOS, true)
    }

    /// Desaloja a `victima` y reintenta insertar `nueva` (tras un `test-before-evict` fallido).
    pub fn desalojar_y_insertar(&mut self, victima: &Entrada, nueva: Entrada) -> Insercion {
        self.probados.desalojar(victima);
        self.probados
            .insertar(nueva, &self.n_key, ETIQUETA_PROBADOS, true)
    }

    /// Promociona a `probados` (tras una conexión saliente con éxito), sacándola de `nuevos`.
    pub fn promover(&mut self, e: &Entrada) -> Insercion {
        let _ = self.nuevos.desalojar(e);
        self.insertar_probado(e.clone())
    }

    /// Selecciona una entrada de `probados` de forma **uniforme** (C-NET-37).
    #[must_use]
    pub fn elegir_probado(&self, semilla: u64) -> Option<Entrada> {
        let total = self.probados.total;
        if total == 0 {
            return None;
        }
        let objetivo = (semilla % total as u64) as usize;
        self.probados.iter().nth(objetivo)
    }

    /// Selecciona una entrada de `nuevos` para el sondeo (`feeler`).
    #[must_use]
    pub fn elegir_nuevo(&self, semilla: u64) -> Option<Entrada> {
        let total = self.nuevos.total;
        if total == 0 {
            return None;
        }
        let objetivo = (semilla % total as u64) as usize;
        self.nuevos.iter().nth(objetivo)
    }

    /// ¿Está esta dirección en `probados`?
    #[must_use]
    pub fn esta_probado(&self, e: &Entrada) -> bool {
        self.probados.contiene(e)
    }

    /// Fija una ancla explícitamente (si hay sitio y el grupo no repite).
    pub fn fijar_ancla(&mut self, e: Entrada) -> bool {
        if self.anclas.len() >= self.perfil.anclas {
            return false;
        }
        let g = self.grupo_ancho(&e);
        if self.anclas.iter().any(|a| self.grupo_ancho(a) == g) {
            return false;
        }
        self.anclas.push(e);
        true
    }

    /// Las anclas actuales.
    #[must_use]
    pub fn anclas(&self) -> &[Entrada] {
        &self.anclas
    }

    /// `true` si la dirección es un ancla persistente.
    #[must_use]
    pub fn es_ancla(&self, e: &Entrada) -> bool {
        let c = e.clave();
        self.anclas.iter().any(|a| a.clave() == c)
    }

    /// Elige hasta `A_ANCLA` anclas de `probados` en grupos anchos **distintos** (C-NET-39, DN-04).
    pub fn elegir_anclas(&mut self) -> Vec<Entrada> {
        let mut grupos = HashSet::new();
        let mut elegidas = Vec::new();
        for e in self.probados.iter() {
            if elegidas.len() >= self.perfil.anclas {
                break;
            }
            let g = self.grupo_ancho(&e);
            if grupos.insert(g) {
                elegidas.push(e);
            }
        }
        self.anclas.clone_from(&elegidas);
        elegidas
    }

    /// Admite hasta `n` direcciones de un par, aplicando la cuota por mensaje y por ventana (DN-07).
    pub fn admitir_direcciones(&mut self, peer: PeerId, n: usize, ahora: Instant) -> usize {
        self.cuota.admitir(peer, n, ahora)
    }

    /// Persiste `nuevos`, `probados`, la `nKey` y las anclas en `dir`.
    ///
    /// # Errores
    /// [`ErrorGestor::Io`] si no se puede escribir.
    pub fn guardar(&self, dir: &Path) -> Result<(), ErrorGestor> {
        fs::create_dir_all(dir)?;
        let ruta = dir.join(FICHERO_GESTOR);
        let mut f = fs::File::create(ruta)?;
        f.write_all(&MAGIC_GESTOR)?;
        f.write_all(&self.n_key)?;
        escribir_tabla(&mut f, &self.nuevos)?;
        escribir_tabla(&mut f, &self.probados)?;
        f.sync_all()?;

        let ruta_anclas = dir.join(FICHERO_ANCLAS);
        let mut fa = fs::File::create(ruta_anclas)?;
        fa.write_all(&MAGIC_ANCLAS)?;
        escribir_lista(&mut fa, &self.anclas)?;
        fa.sync_all()?;
        Ok(())
    }

    /// Carga el gestor de `dir`. Si no hay fichero, devuelve uno nuevo vacío.
    ///
    /// # Errores
    /// [`ErrorGestor`] si el fichero existe y está corrupto.
    pub fn cargar(red: Red, perfil: PerfilRed, dir: &Path) -> Result<Self, ErrorGestor> {
        let ruta = dir.join(FICHERO_GESTOR);
        let mut g = match fs::read(&ruta) {
            Ok(bytes) => Self::desde_bytes(red, perfil, &bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::nuevo(red, perfil),
            Err(e) => return Err(e.into()),
        };
        let ruta_anclas = dir.join(FICHERO_ANCLAS);
        if let Ok(bytes) = fs::read(&ruta_anclas) {
            let anclas = leer_lista(&bytes, MAGIC_ANCLAS)?;
            for a in &anclas {
                if !g.esta_probado(a) && g.acepta(a) {
                    let nk = g.n_key;
                    let _ = g.probados.insertar(a.clone(), &nk, ETIQUETA_PROBADOS, true);
                }
            }
            g.anclas = anclas;
        }
        Ok(g)
    }

    fn desde_bytes(red: Red, perfil: PerfilRed, bytes: &[u8]) -> Result<Self, ErrorGestor> {
        let mut c = Cursor::new(bytes);
        let mut magic = [0u8; 8];
        c.read_exact(&mut magic)?;
        if magic != MAGIC_GESTOR {
            return Err(ErrorGestor::Corrupto("magia de gestor incorrecta"));
        }
        let mut n_key = [0u8; 32];
        c.read_exact(&mut n_key)?;
        let dev_peer = red == Red::Dev;
        let mut nuevos = Tabla::nueva(
            perfil.nuevos,
            perfil.cap_ancho,
            perfil.cap_estrecho,
            dev_peer,
        );
        let mut probados = Tabla::nueva(
            perfil.probados,
            perfil.cap_ancho,
            perfil.cap_estrecho,
            dev_peer,
        );
        leer_tabla(&mut c, &mut nuevos, &n_key, ETIQUETA_NUEVOS)?;
        leer_tabla(&mut c, &mut probados, &n_key, ETIQUETA_PROBADOS)?;
        Ok(Self {
            n_key,
            red,
            perfil,
            nuevos,
            probados,
            anclas: Vec::new(),
            cuota: CuotaDirecciones::nuevo(
                perfil.dirs_por_mensaje,
                perfil.cuota_tope,
                perfil.cuota_ventana,
            ),
        })
    }
}

/// Una `nKey` de 32 bytes de `/dev/urandom`; si no existe, un respaldo hasheado.
fn n_key_aleatoria() -> [u8; 32] {
    let mut k = [0u8; 32];
    if let Ok(mut f) = fs::File::open("/dev/urandom")
        && f.read_exact(&mut k).is_ok()
    {
        return k;
    }
    let s = format!("zx-gestor-{}-{:?}", std::process::id(), Instant::now());
    k.copy_from_slice(zx_core::sha3_256_publico(s.as_bytes()).as_bytes());
    k
}

fn escribir_tabla<W: Write>(w: &mut W, t: &Tabla) -> Result<(), ErrorGestor> {
    escribir_lista(w, &t.iter().collect::<Vec<_>>())
}

fn escribir_lista<W: Write>(w: &mut W, lista: &[Entrada]) -> Result<(), ErrorGestor> {
    let n = u32::try_from(lista.len()).map_err(|_| ErrorGestor::Corrupto("demasiadas entradas"))?;
    w.write_all(&n.to_be_bytes())?;
    for e in lista {
        escribir_entrada(w, e)?;
    }
    Ok(())
}

fn escribir_entrada<W: Write>(w: &mut W, e: &Entrada) -> Result<(), ErrorGestor> {
    let av = e.addr.to_vec();
    let al =
        u16::try_from(av.len()).map_err(|_| ErrorGestor::Corrupto("multiaddr demasiado larga"))?;
    w.write_all(&al.to_be_bytes())?;
    w.write_all(&av)?;
    match e.peer {
        Some(p) => {
            let pb = p.to_bytes();
            let pl = u16::try_from(pb.len())
                .map_err(|_| ErrorGestor::Corrupto("PeerId demasiado largo"))?;
            w.write_all(&[1u8])?;
            w.write_all(&pl.to_be_bytes())?;
            w.write_all(&pb)?;
        }
        None => w.write_all(&[0u8])?,
    }
    Ok(())
}

fn leer_tabla<R: Read>(
    r: &mut R,
    t: &mut Tabla,
    n_key: &[u8; 32],
    etiqueta: u8,
) -> Result<(), ErrorGestor> {
    for e in leer_lista_desde(r)? {
        let _ = t.insertar(e, n_key, etiqueta, etiqueta == ETIQUETA_PROBADOS);
    }
    Ok(())
}

fn leer_lista(bytes: &[u8], magic: [u8; 8]) -> Result<Vec<Entrada>, ErrorGestor> {
    let mut c = Cursor::new(bytes);
    let mut m = [0u8; 8];
    c.read_exact(&mut m)?;
    if m != magic {
        return Err(ErrorGestor::Corrupto("magia de anclas incorrecta"));
    }
    leer_lista_desde(&mut c)
}

fn leer_lista_desde<R: Read>(r: &mut R) -> Result<Vec<Entrada>, ErrorGestor> {
    let n = leer_u32(r)? as usize;
    let mut salida = Vec::with_capacity(n.min(1_000_000));
    for _ in 0..n {
        salida.push(leer_entrada(r)?);
    }
    Ok(salida)
}

fn leer_u16<R: Read>(r: &mut R) -> Result<u16, ErrorGestor> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

fn leer_u32<R: Read>(r: &mut R) -> Result<u32, ErrorGestor> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn leer_entrada<R: Read>(r: &mut R) -> Result<Entrada, ErrorGestor> {
    let al = leer_u16(r)? as usize;
    let mut av = vec![0u8; al];
    r.read_exact(&mut av)?;
    let addr = Multiaddr::try_from(av).map_err(|_| ErrorGestor::Multiaddr)?;
    let mut tiene = [0u8; 1];
    r.read_exact(&mut tiene)?;
    let peer = if tiene.first() == Some(&1) {
        let pl = leer_u16(r)? as usize;
        let mut pb = vec![0u8; pl];
        r.read_exact(&mut pb)?;
        Some(PeerId::from_bytes(&pb).map_err(|_| ErrorGestor::PeerId)?)
    } else {
        None
    };
    Entrada::de_multiaddr(addr, peer).ok_or(ErrorGestor::Multiaddr)
}

/// Directorio de datos por defecto del gestor (junto al del nodo).
#[must_use]
pub fn dir_por_defecto(datos: &Path) -> PathBuf {
    datos.join("red")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño y construyen direcciones conocidas"
)]
mod tests {
    use super::{
        Entrada, ErrorGestor, GestorDirecciones, GrupoAncho, Insercion, es_enrutable, ip_agrupable,
    };
    use crate::config::PerfilRed;
    use libp2p::{Multiaddr, PeerId};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use zx_core::red::Red;

    fn perfil() -> PerfilRed {
        PerfilRed::de(Red::Dev)
    }

    fn entrada(s: &str) -> Entrada {
        let addr: Multiaddr = s.parse().unwrap();
        Entrada::de_multiaddr(addr, None).unwrap()
    }

    fn entrada_peer(s: &str, peer: PeerId) -> Entrada {
        let addr: Multiaddr = s.parse().unwrap();
        Entrada::de_multiaddr(addr, Some(peer)).unwrap()
    }

    static CONTADOR: AtomicU64 = AtomicU64::new(0);

    fn dir_temporal() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "zx-gestor-test-{}-{}",
            std::process::id(),
            CONTADOR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Inserción y deduplicación por `(IP, puerto)`.
    #[test]
    fn inserta_y_deduplica() {
        let mut g = GestorDirecciones::nuevo(Red::Dev, perfil());
        let e = entrada("/ip4/93.184.216.34/tcp/9833");
        assert!(g.insertar_nuevo(e.clone()));
        assert!(!g.insertar_nuevo(e.clone()), "duplicada");
        assert_eq!(g.total_nuevos(), 1);
    }

    /// **C-NET-36/DN-08.** No caben más de `CAP_ANCHO` por `/16`: la novena colisiona.
    #[test]
    fn cap_por_grupo_ancho() {
        let mut g = GestorDirecciones::nuevo(Red::Dev, perfil());
        for i in 1..=8u8 {
            let e = entrada(&format!("/ip4/93.184.{i}.1/tcp/9833"));
            assert_eq!(g.insertar_probado(e), Insercion::Insertada, "la {i} cabe");
        }
        let novena = entrada("/ip4/93.184.9.1/tcp/9833");
        assert!(
            matches!(g.insertar_probado(novena), Insercion::Colision { .. }),
            "la novena del mismo /16 MUST colisionar, no entrar"
        );
        assert_eq!(g.total_probados(), 8);
    }

    /// **C-NET-36/DN-08.** `CAP_ESTRECHO = 1` por `/24`: misma /24 colisiona.
    #[test]
    fn cap_por_grupo_estrecho() {
        let mut g = GestorDirecciones::nuevo(Red::Dev, perfil());
        assert_eq!(
            g.insertar_probado(entrada("/ip4/93.184.1.1/tcp/9833")),
            Insercion::Insertada
        );
        assert!(
            matches!(
                g.insertar_probado(entrada("/ip4/93.184.1.2/tcp/9833")),
                Insercion::Colision { .. }
            ),
            "dos direcciones de la misma /24 no pueden estar en probados"
        );
    }

    /// **C-NET-40.** `test-before-evict`: solo se desaloja tras probar (y fallar) a la incumbente.
    #[test]
    fn desalojo_tras_test_before_evict() {
        let mut g = GestorDirecciones::nuevo(Red::Dev, perfil());
        let incumbente = entrada("/ip4/93.184.1.1/tcp/9833");
        assert_eq!(g.insertar_probado(incumbente.clone()), Insercion::Insertada);

        let nueva = entrada("/ip4/93.184.1.2/tcp/9833");
        let Insercion::Colision { desaloja } = g.insertar_probado(nueva.clone()) else {
            panic!("se esperaba colisión de grupo estrecho");
        };
        assert_eq!(
            desaloja, incumbente,
            "la incumbente es la que hay que probar"
        );
        assert!(
            g.esta_probado(&incumbente),
            "sin probar y fallar, la incumbente sigue"
        );

        // La incumbente no respondió: ahora sí se desaloja y entra la nueva.
        assert_eq!(
            g.desalojar_y_insertar(&desaloja, nueva.clone()),
            Insercion::Insertada
        );
        assert!(!g.esta_probado(&incumbente));
        assert!(g.esta_probado(&nueva));
    }

    /// **C-NET-35.** Persistencia y recarga: `probados`, `nuevos` y `nKey` sobreviven.
    #[test]
    fn persistencia_y_recarga() {
        let dir = dir_temporal();
        let n_key = [7u8; 32];
        let mut g = GestorDirecciones::con_n_key(Red::Dev, perfil(), n_key);
        assert_eq!(
            g.insertar_probado(entrada("/ip4/93.184.1.1/tcp/9833")),
            Insercion::Insertada
        );
        assert!(g.insertar_nuevo(entrada("/ip4/198.51.100.7/tcp/9833")));
        assert!(g.fijar_ancla(entrada("/ip4/93.184.1.1/tcp/9833")));
        g.guardar(&dir).unwrap();

        let recargado = GestorDirecciones::cargar(Red::Dev, perfil(), &dir).unwrap();
        assert_eq!(recargado.n_key(), &n_key, "la nKey MUST sobrevivir");
        assert_eq!(recargado.total_probados(), 1);
        assert_eq!(recargado.total_nuevos(), 1);
        assert_eq!(recargado.anclas().len(), 1);
        assert!(recargado.esta_probado(&entrada("/ip4/93.184.1.1/tcp/9833")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **C-NET-39/DN-04.** Las anclas se eligen en grupos anchos distintos.
    #[test]
    fn anclas_en_grupos_distintos() {
        let mut g = GestorDirecciones::nuevo(Red::Dev, perfil());
        for s in [
            "/ip4/10.0.0.1/tcp/9833",
            "/ip4/10.0.0.2/tcp/9833",
            "/ip4/10.1.0.1/tcp/9833",
        ] {
            let _ = g.insertar_probado(entrada(s));
        }
        let anclas = g.elegir_anclas();
        assert_eq!(anclas.len(), 2, "A_ANCLA = 2");
        let g0 = g.grupo_ancho(&anclas[0]);
        let g1 = g.grupo_ancho(&anclas[1]);
        assert_ne!(g0, g1, "las dos anclas MUST estar en /16 distintos");
        assert!(g.es_ancla(&anclas[0]));
    }

    /// **DN-07.** Cuota de direcciones: por mensaje y por ventana.
    #[test]
    fn cuota_por_mensaje_y_ventana() {
        let mut g = GestorDirecciones::nuevo(Red::Dev, perfil());
        let peer = PeerId::random();
        let t0 = Instant::now();
        assert_eq!(
            g.admitir_direcciones(peer, 150, t0),
            100,
            "tope por mensaje"
        );
        for _ in 0..9 {
            assert_eq!(
                g.admitir_direcciones(peer, 100, t0),
                100,
                "resto de ventana"
            );
        }
        assert_eq!(g.admitir_direcciones(peer, 10, t0), 0, "ventana agotada");
        let t1 = t0 + Duration::from_secs(3_601);
        assert_eq!(g.admitir_direcciones(peer, 10, t1), 10, "ventana nueva");
    }

    /// **DN-09/C-NET-44.** En dev, loopback se agrupa por `PeerId` (no colapsa en `127.0.0.0/24`).
    #[test]
    fn dev_agrupa_loopback_por_peer() {
        let mut g = GestorDirecciones::nuevo(Red::Dev, perfil());
        for i in 1..=9u16 {
            let e = entrada_peer(&format!("/ip4/127.0.0.1/tcp/{i}"), PeerId::random());
            assert_eq!(
                g.insertar_probado(e),
                Insercion::Insertada,
                "cada PeerId es un grupo distinto en loopback"
            );
        }
        let a = entrada_peer("/ip4/127.0.0.1/tcp/1", PeerId::random());
        assert!(matches!(g.grupo_ancho(&a), GrupoAncho::Peer(_)));
    }

    /// **C-NET-44.** Fuera de dev no se admiten loopback ni privadas.
    #[test]
    fn fuera_de_dev_no_se_admiten_no_enrutables() {
        let mut g = GestorDirecciones::nuevo(Red::Mainnet, perfil());
        assert!(!g.insertar_nuevo(entrada("/ip4/127.0.0.1/tcp/9833")));
        assert_eq!(
            g.insertar_probado(entrada("/ip4/10.0.0.1/tcp/9833")),
            Insercion::Rechazada
        );
        assert!(g.insertar_nuevo(entrada("/ip4/93.184.216.34/tcp/9833")));
    }

    /// **C-NET-36.** Teredo, 6to4 e IPv4-mapeada se agrupan por su IPv4 enlazada.
    #[test]
    fn agrupa_ipv4_enlazada() {
        let mapeada: IpAddr = "::ffff:93.184.216.34".parse::<Ipv6Addr>().unwrap().into();
        assert_eq!(
            ip_agrupable(mapeada),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        let seis_a_cuatro: IpAddr = "2002:5db8:d822::1".parse::<Ipv6Addr>().unwrap().into();
        assert_eq!(
            ip_agrupable(seis_a_cuatro),
            IpAddr::V4(Ipv4Addr::new(0x5d, 0xb8, 0xd8, 0x22))
        );
        assert!(es_enrutable(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!es_enrutable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    /// Un fichero con magia incorrecta se rechaza en vez de cargarse a medias.
    #[test]
    fn fichero_corrupto_se_rechaza() {
        let dir = dir_temporal();
        std::fs::write(dir.join(super::FICHERO_GESTOR), b"NOESGEST").unwrap();
        assert!(matches!(
            GestorDirecciones::cargar(Red::Dev, perfil(), &dir),
            Err(ErrorGestor::Corrupto(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
