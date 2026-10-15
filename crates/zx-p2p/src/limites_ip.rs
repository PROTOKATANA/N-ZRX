//! Límites y baneo **por dirección IP** (SPEC §16.3, C-NET-05, C-NET-20).
//!
//! # Por qué `connection_limits` de libp2p no basta
//!
//! Lo comprobé en el crate: sus únicos ajustes son `with_max_pending_incoming`,
//! `with_max_established_incoming/outgoing`, `with_max_established` y
//! `with_max_established_per_peer`. **Ninguno mira la IP de origen.** Todos son globales o por
//! `PeerId`.
//!
//! Y ese es el problema, porque **un `PeerId` es gratis**: `Keypair::generate_ed25519()` es
//! instantáneo, sin PoW, sin registro, sin coste. Así que `MAX_CONEXIONES_POR_PEER = 1` no defiende
//! de nada — basta con generar una identidad nueva por conexión.
//!
//! Dos ataques que eso deja abiertos, ambos desde **una sola máquina**:
//!
//! | Ataque | Cómo | Efecto |
//! |---|---|---|
//! | *Slowloris* | Abrir conexiones y no terminar nunca el handshake | El contador global de pendientes se llena y el nodo **rechaza a todo el mundo**, honesto o no |
//! | Relleno de cupo | 72 `PeerId` distintos desde la misma IP | Se ocupa el cupo entrante entero y el nodo queda sordo a peers nuevos |
//!
//! Es lo que hacen Bitcoin Core y Zebra, y por eso hay que escribirlo: libp2p no lo trae.
//!
//! # Por qué por /24 y /64, y no por IP exacta
//!
//! Contar por IP exacta es trivial de evadir: cualquier VPS barato viene con varias, y un /64 de
//! IPv6 son 18 trillones de direcciones asignadas **a un solo cliente**. Contar por prefijo hace que
//! el coste de evadir sea el de alquilar redes distintas, no el de pedir una IP más.
//!
//! IPv4 se agrupa por **/24** y IPv6 por **/64**, que es la unidad que los proveedores asignan.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, dummy,
};
use libp2p::{Multiaddr, PeerId};
use zx_core::red::Red;

/// Conexiones simultáneas desde un mismo prefijo de red.
///
/// Deliberadamente bajo: un operador honesto no necesita varias conexiones al mismo nodo desde la
/// misma subred, y un atacante sí.
pub const MAX_POR_PREFIJO: u32 = 3;

/// Conexiones **a medio negociar** desde un mismo prefijo. La defensa contra *slowloris*.
pub const MAX_PENDIENTES_POR_PREFIJO: u32 = 2;

/// Cuánto puntúa una violación de consenso.
pub const PUNTOS_VIOLACION_CONSENSO: u32 = 100;

/// A partir de cuántos puntos se banea un prefijo.
///
/// 100 significa **un solo golpe**: una violación de consenso positivamente identificada no admite
/// segunda oportunidad. Es el valor de Zebra, y la razón es que fabricar una violación de consenso
/// cuesta trabajo real — no ocurre por accidente.
pub const UMBRAL_BANEO: u32 = 100;

// Una conexión pendiente le cuesta menos al atacante que una establecida —no ha completado el
// handshake— así que su cupo MUST ser más estrecho, no más ancho. Aserción de compilación y no
// test: es una relación entre constantes, y una aserción de compilación no se puede saltar.
const _: () = assert!(
    MAX_PENDIENTES_POR_PREFIJO < MAX_POR_PREFIJO && MAX_PENDIENTES_POR_PREFIJO > 0,
    "el cupo de pendientes debe ser más estrecho que el de establecidas, y no cero"
);

/// Cuántos prefijos baneados se recuerdan.
///
/// Acotado, y con desalojo del más antiguo. Sin la cota, el propio registro de baneos sería el
/// vector: un atacante con muchas redes haría crecer la tabla sin límite.
pub const MAX_BANEADOS: usize = 20_000;

/// Un prefijo de red: /24 en IPv4, /64 en IPv6.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Prefijo {
    /// Los tres primeros octetos de una IPv4.
    V4([u8; 3]),
    /// Los ocho primeros bytes de una IPv6.
    V6([u8; 8]),
}

impl Prefijo {
    /// El prefijo de una IP.
    #[must_use]
    pub fn de_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::de_v4(v4),
            IpAddr::V6(v6) => Self::de_v6(v6),
        }
    }

    fn de_v4(v4: Ipv4Addr) -> Self {
        let o = v4.octets();
        Self::V4([o[0], o[1], o[2]])
    }

    fn de_v6(v6: Ipv6Addr) -> Self {
        let o = v6.octets();
        let mut p = [0u8; 8];
        p.copy_from_slice(o.get(..8).unwrap_or(&[0u8; 8]));
        Self::V6(p)
    }

    /// El prefijo de una `Multiaddr`, o `None` si no lleva IP.
    ///
    /// Una dirección sin IP —memoria, por ejemplo— **no se limita**: el transporte en memoria solo
    /// existe en tests, y limitarlo ahí rompería el arnés sin defender nada.
    #[must_use]
    pub fn de_multiaddr(addr: &Multiaddr) -> Option<Self> {
        use libp2p::multiaddr::Protocol;
        addr.iter().find_map(|p| match p {
            Protocol::Ip4(v4) => Some(Self::de_v4(v4)),
            Protocol::Ip6(v6) => Some(Self::de_v6(v6)),
            _ => None,
        })
    }

    /// ¿Es un prefijo **loopback** (`127.0.0.0/8` en IPv4, `::1` en IPv6)?
    ///
    /// `ORDEN-W06d10` decisión 3: para loopback la penalización es por `PeerId`, no por prefijo.
    /// Es una **excepción de la red local** (todos los nodos de la red dev comparten
    /// `127.0.0.0/24`), no un cambio de producción: en una red real los pares honestos no
    /// comparten prefijo con el adversario.
    ///
    /// En IPv6 se reconoce `::1` por su /64 (`::/64`): `Prefijo::de_v6` guarda solo los ocho
    /// primeros bytes, así que los bits bajos de `::1` no llegan hasta aquí — y `::/64` no es una
    /// red enrutable, es justo el ámbito local.
    #[must_use]
    pub const fn es_loopback(self) -> bool {
        matches!(
            self,
            Self::V4([127, _, _]) | Self::V6([0, 0, 0, 0, 0, 0, 0, 0])
        )
    }
}

/// Behaviour que limita y banea por prefijo de red.
#[derive(Debug, Default)]
pub struct LimitesPorIp {
    /// ¿Red de desarrollo? En `Red::Dev` los nodos del humo comparten `127.0.0.0/24`, así que el
    /// cupo por prefijo se sustituye por `PeerId` (DN-09): contar por prefijo caparía la malla a 3
    /// entrantes por nodo e impediría que cada uno alcance las salientes que mide la orden.
    dev: bool,
    /// Conexiones **entrantes** establecidas por prefijo. Es el cupo de C-NET-20: las salientes
    /// **no** cuentan aquí (se contabilizan aparte), o una saliente propia gastaría el cupo de
    /// entrantes del mismo prefijo.
    establecidas: HashMap<Prefijo, u32>,
    /// Conexiones **salientes** establecidas por prefijo (C-NET-37/38: registrarlas y poder
    /// contarlas). La diversidad de salientes la impone el director (≤1 por grupo ancho).
    salientes: HashMap<Prefijo, u32>,
    pendientes: HashMap<Prefijo, u32>,
    /// Qué prefijo tiene cada conexión y si era saliente (`true`) o entrante (`false`), para poder
    /// descontar del contador correcto al cerrarse.
    de_conexion: HashMap<ConnectionId, (Prefijo, bool)>,
    /// Qué prefijos usa cada peer, para poder puntuarlo cuando se le condena.
    ///
    /// Un peer puede estar conectado desde varios: se puntúan **todos**, porque la identidad que
    /// violó consenso es la misma detrás de cada uno.
    de_peer: HashMap<PeerId, Vec<Prefijo>>,
    puntos: HashMap<Prefijo, u32>,
    /// Prefijos baneados, en orden de llegada para desalojar el más antiguo.
    baneados: Vec<Prefijo>,
    /// Puntos por `PeerId`, **solo** para pares conectados desde direcciones loopback
    /// (`ORDEN-W06d10` decisión 3: excepción de la red local, donde vetar el prefijo común
    /// `127.0.0.0/24` dejaría fuera a los nodos honestos).
    puntos_peer: HashMap<PeerId, u32>,
    /// `PeerId` baneados (solo loopback), en orden de llegada para desalojar el más antiguo.
    baneados_peer: Vec<PeerId>,
    /// El mismo conjunto que [`Self::baneados_peer`], para consultar en O(1).
    conjunto_baneados_peer: HashSet<PeerId>,
}

/// Por qué se denegó una conexión.
#[derive(Debug, thiserror::Error)]
pub enum Denegada {
    /// El prefijo está baneado.
    #[error("prefijo baneado por violación de consenso")]
    Baneado,
    /// El `PeerId` está baneado (solo direcciones loopback, `ORDEN-W06d10` decisión 3).
    #[error("PeerId baneado por violación de consenso (dirección loopback)")]
    PeerBaneado,
    /// Demasiadas conexiones establecidas desde ese prefijo.
    #[error("demasiadas conexiones desde el mismo prefijo de red ({actual}/{max})")]
    DemasiadasEstablecidas {
        /// Cuántas hay.
        actual: u32,
        /// Cuántas se admiten.
        max: u32,
    },
    /// Demasiadas conexiones a medio negociar desde ese prefijo.
    #[error("demasiadas conexiones pendientes desde el mismo prefijo ({actual}/{max})")]
    DemasiadasPendientes {
        /// Cuántas hay.
        actual: u32,
        /// Cuántas se admiten.
        max: u32,
    },
}

/// Lo que se baneó al aplicar una penalización a un par (`ORDEN-W06d10` decisión 3).
///
/// Separado para que el bucle pueda registrarlo (`tracing::warn!`) sin volver a consultar el estado,
/// y para poder probar la política loopback/`PeerId` sin construir un `Swarm`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Penalizacion {
    /// Prefijos de red que cruzaron el umbral con esta penalización.
    pub prefijos_baneados: Vec<Prefijo>,
    /// `true` si el `PeerId` (dirección loopback) cruzó el umbral.
    pub peer_baneado: bool,
}

impl LimitesPorIp {
    /// Uno vacío.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Uno con el modo de la red: en `Red::Dev` no se capa por prefijo loopback (DN-09).
    #[must_use]
    pub fn para_red(red: Red) -> Self {
        Self {
            dev: red == Red::Dev,
            ..Self::default()
        }
    }

    /// ¿Está baneado este prefijo?
    #[must_use]
    pub fn esta_baneado(&self, p: Prefijo) -> bool {
        self.baneados.contains(&p)
    }

    /// Conexiones **salientes** establecidas desde un prefijo (C-NET-37/38).
    ///
    /// Es un contador aparte del de entrantes: la diversidad de salientes la impone el director
    /// (≤1 por grupo ancho) y este contador existe para poder registrarla y contarla.
    #[must_use]
    pub fn salientes_de(&self, p: Prefijo) -> u32 {
        self.salientes.get(&p).copied().unwrap_or(0)
    }

    /// Puntos acumulados por un prefijo.
    #[must_use]
    pub fn puntos_de(&self, p: Prefijo) -> u32 {
        self.puntos.get(&p).copied().unwrap_or(0)
    }

    /// Cuántos prefijos hay baneados.
    #[must_use]
    pub fn baneados(&self) -> usize {
        self.baneados.len()
    }

    /// Los prefijos desde los que está conectado un peer.
    #[must_use]
    pub fn prefijos_de(&self, peer: PeerId) -> Vec<Prefijo> {
        self.de_peer.get(&peer).cloned().unwrap_or_default()
    }

    /// Suma puntos a un prefijo y lo banea si cruza el umbral.
    ///
    /// Devuelve `true` si acaba de banearse.
    ///
    /// **Solo debe llamarse con violaciones de consenso positivamente identificadas** (C-NET-05).
    /// Un peer lento, uno que habla otra versión o uno que va por detrás **no** puntúan: la razón
    /// es la de Zebra —*quien te entrega un bloque no es quien eligió su altura*— y penalizar al
    /// mensajero deja que un tercero haga que baneemos a peers honestos.
    pub fn puntuar(&mut self, p: Prefijo, puntos: u32) -> bool {
        let total = self.puntos.entry(p).or_insert(0);
        *total = total.saturating_add(puntos);

        if *total >= UMBRAL_BANEO && !self.baneados.contains(&p) {
            // Desalojo FIFO: sin la cota, el propio registro de baneos sería el vector.
            if self.baneados.len() >= MAX_BANEADOS {
                let viejo = self.baneados.remove(0);
                self.puntos.remove(&viejo);
            }
            self.baneados.push(p);
            return true;
        }
        false
    }

    /// Suma puntos a un `PeerId` y lo banea si cruza el umbral.
    ///
    /// Devuelve `true` si acaba de banearse.
    ///
    /// **Solo para direcciones loopback** (`ORDEN-W06d10` decisión 3): en la red dev todos los
    /// nodos comparten el prefijo `127.0.0.0/24`, así que penalizar el prefijo por culpa de un
    /// adversario vetaría también a los honestos. Fuera de loopback la penalización sigue siendo por
    /// prefijo ([`Self::puntuar`]), sin cambios. El registro está acotado por [`MAX_BANEADOS`] con
    /// desalojo FIFO, igual que el de prefijos.
    pub fn puntuar_peer(&mut self, peer: PeerId, puntos: u32) -> bool {
        let total = self.puntos_peer.entry(peer).or_insert(0);
        *total = total.saturating_add(puntos);

        if *total >= UMBRAL_BANEO && !self.conjunto_baneados_peer.contains(&peer) {
            if self.baneados_peer.len() >= MAX_BANEADOS {
                let viejo = self.baneados_peer.remove(0);
                self.puntos_peer.remove(&viejo);
                self.conjunto_baneados_peer.remove(&viejo);
            }
            self.baneados_peer.push(peer);
            self.conjunto_baneados_peer.insert(peer);
            return true;
        }
        false
    }

    /// Puntos acumulados por un `PeerId` (solo loopback).
    #[must_use]
    pub fn puntos_de_peer(&self, peer: PeerId) -> u32 {
        self.puntos_peer.get(&peer).copied().unwrap_or(0)
    }

    /// ¿Está baneado este `PeerId`?
    #[must_use]
    pub fn esta_baneado_peer(&self, peer: PeerId) -> bool {
        self.conjunto_baneados_peer.contains(&peer)
    }

    /// Cuántos `PeerId` hay baneados.
    #[must_use]
    pub fn baneados_peer(&self) -> usize {
        self.baneados_peer.len()
    }

    /// Aplica `puntos` a un par con la política de `ORDEN-W06d10` y devuelve qué se baneó.
    ///
    /// `prefijos` son los prefijos de red **conocidos** del par (los que devuelve
    /// [`Self::prefijos_de`]; se reciben explícitos para poder probar la política sin un `Swarm`).
    ///
    /// - Con **algún** prefijo loopback (`127.0.0.0/8`, `::1`): se puntúa el `PeerId` (excepción de
    ///   la red local) y **no** el prefijo.
    /// - Sin loopback: se puntúa cada prefijo como siempre (C-NET-20). Nada cambia para producción.
    /// - Sin prefijos conocidos (conexión saliente que no pasó por el handler entrante): no hay
    ///   nada que penalizar; mismo comportamiento que antes de esta orden.
    #[must_use]
    pub fn penalizar_peer(
        &mut self,
        peer: PeerId,
        prefijos: &[Prefijo],
        puntos: u32,
    ) -> Penalizacion {
        let mut resultado = Penalizacion::default();
        let mut loopback = false;
        for &p in prefijos {
            if p.es_loopback() {
                loopback = true;
            } else if self.puntuar(p, puntos) {
                resultado.prefijos_baneados.push(p);
            }
        }
        if loopback && self.puntuar_peer(peer, puntos) {
            resultado.peer_baneado = true;
        }
        resultado
    }

    /// Un `PeerId` baneado (loopback) no vuelve a entrar, igual que un prefijo baneado.
    fn comprobar_peer(&self, peer: PeerId) -> Result<(), Denegada> {
        if self.esta_baneado_peer(peer) {
            return Err(Denegada::PeerBaneado);
        }
        Ok(())
    }

    fn comprobar(&self, p: Prefijo, pendiente: bool) -> Result<(), Denegada> {
        if self.baneados.contains(&p) {
            return Err(Denegada::Baneado);
        }
        // DN-09 · En `Red::Dev` los nodos del humo comparten `127.0.0.0/24`. Contarlos por prefijo
        // caparía la malla a 3 entrantes por nodo: con 8 nodos, el total de conexiones no pasaría de
        // 24 y sería imposible que cada uno tuviera ≥4 salientes (la cuenta se mide en la orden). En
        // dev sobre loopback se cuenta por `PeerId` (el cupo por peer de `connection_limits` sigue
        // vigente), que es la misma excepción que ya aplica el gestor de direcciones. Fuera de
        // loopback, y en mainnet/testnet, nada cambia.
        if self.dev && p.es_loopback() {
            return Ok(());
        }
        if pendiente {
            let n = self.pendientes.get(&p).copied().unwrap_or(0);
            if n >= MAX_PENDIENTES_POR_PREFIJO {
                return Err(Denegada::DemasiadasPendientes {
                    actual: n,
                    max: MAX_PENDIENTES_POR_PREFIJO,
                });
            }
        } else {
            let n = self.establecidas.get(&p).copied().unwrap_or(0);
            if n >= MAX_POR_PREFIJO {
                return Err(Denegada::DemasiadasEstablecidas {
                    actual: n,
                    max: MAX_POR_PREFIJO,
                });
            }
        }
        Ok(())
    }
}

impl NetworkBehaviour for LimitesPorIp {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        _local: &Multiaddr,
        remoto: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // Sin IP no se limita: el transporte en memoria solo existe en tests.
        let Some(p) = Prefijo::de_multiaddr(remoto) else {
            return Ok(());
        };
        self.comprobar(p, true).map_err(ConnectionDenied::new)?;

        *self.pendientes.entry(p).or_insert(0) += 1;
        self.de_conexion.insert(id, (p, false));
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _local: &Multiaddr,
        remoto: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let Some(p) = Prefijo::de_multiaddr(remoto) else {
            return Ok(dummy::ConnectionHandler);
        };
        // Deja de estar pendiente pase lo que pase: si se deniega ahora, la pendiente ya no lo es.
        if let Some(n) = self.pendientes.get_mut(&p) {
            *n = n.saturating_sub(1);
        }
        self.comprobar(p, false).map_err(ConnectionDenied::new)?;
        // `ORDEN-W06d10` decisión 3: un `PeerId` vetado (loopback) no vuelve a entrar aunque su
        // prefijo (compartido con los honestos en la red dev) no esté vetado.
        self.comprobar_peer(peer).map_err(ConnectionDenied::new)?;

        *self.establecidas.entry(p).or_insert(0) += 1;
        self.de_conexion.insert(id, (p, false));
        let prefijos = self.de_peer.entry(peer).or_default();
        if !prefijos.contains(&p) {
            prefijos.push(p);
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _rol: libp2p::core::Endpoint,
        _puerto: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // C-NET-37: el prefijo de TODA conexión, entrante **y saliente**, MUST registrarse para
        // poder contabilizar y banear por prefijo. Antes esta ruta devolvía `Ok` sin anotar nada, y
        // por eso las salientes no se contaban. Se cuenta en `salientes` y **no** en
        // `establecidas`: esa es la cuota de entrantes de C-NET-20, y una saliente propia del mismo
        // /24 no debe gastarla.
        let Some(p) = Prefijo::de_multiaddr(addr) else {
            return Ok(dummy::ConnectionHandler);
        };
        *self.salientes.entry(p).or_insert(0) += 1;
        self.de_conexion.insert(id, (p, true));
        let prefijos = self.de_peer.entry(peer).or_default();
        if !prefijos.contains(&p) {
            prefijos.push(p);
        }
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, evento: FromSwarm) {
        match evento {
            FromSwarm::ConnectionClosed(c) => {
                if let Some((p, es_saliente)) = self.de_conexion.remove(&c.connection_id) {
                    let contador = if es_saliente {
                        &mut self.salientes
                    } else {
                        &mut self.establecidas
                    };
                    if let Some(n) = contador.get_mut(&p) {
                        *n = n.saturating_sub(1);
                    }
                    // El mapa de peer→prefijos se limpia al cerrar la última conexión suya, o
                    // crecería sin límite con cada peer que pase por aquí.
                    if let Some(v) = self.de_peer.get_mut(&c.peer_id) {
                        v.retain(|q| *q != p);
                        if v.is_empty() {
                            self.de_peer.remove(&c.peer_id);
                        }
                    }
                }
            }
            // Una conexión entrante que falla antes de establecerse deja de estar pendiente. Sin
            // esto, un atacante que abre y abandona conexiones agota el cupo de pendientes **para
            // siempre**: es el slowloris, convertido en permanente por una fuga de contador.
            FromSwarm::ListenFailure(f) => {
                if let Some((p, _)) = self.de_conexion.remove(&f.connection_id)
                    && let Some(n) = self.pendientes.get_mut(&p)
                {
                    *n = n.saturating_sub(1);
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer: PeerId,
        _id: ConnectionId,
        evento: THandlerOutEvent<Self>,
    ) {
        // `dummy::ConnectionHandler` no emite eventos: su tipo es `Infallible`.
        match evento {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::integer_division,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño; la división entera genera prefijos distintos; \
              los índices del test de la cota están dentro del rango construido"
)]
mod tests {
    use super::{
        Denegada, LimitesPorIp, MAX_BANEADOS, MAX_POR_PREFIJO, PUNTOS_VIOLACION_CONSENSO, Prefijo,
        UMBRAL_BANEO,
    };
    use libp2p::{Multiaddr, PeerId};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use zx_core::red::Red;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Prefijo {
        Prefijo::de_ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    /// **La propiedad que hace útil todo esto: agrupar por prefijo, no por IP.**
    ///
    /// Contar por IP exacta es trivial de evadir — cualquier VPS trae varias, y un /64 de IPv6 son
    /// 18 trillones de direcciones asignadas a **un solo cliente**. Agrupar hace que evadir cueste
    /// alquilar redes distintas, no pedir una IP más.
    #[test]
    fn las_ips_del_mismo_prefijo_cuentan_como_una() {
        assert_eq!(v4(1, 2, 3, 4), v4(1, 2, 3, 200), "mismo /24");
        assert_ne!(v4(1, 2, 3, 4), v4(1, 2, 4, 4), "distinto /24");

        // IPv6: el /64 es la unidad que asignan los proveedores.
        let a = Prefijo::de_ip(IpAddr::V6(
            "2001:db8:1:2:3:4:5:6".parse::<Ipv6Addr>().unwrap(),
        ));
        let b = Prefijo::de_ip(IpAddr::V6(
            "2001:db8:1:2:ffff:ffff:ffff:ffff"
                .parse::<Ipv6Addr>()
                .unwrap(),
        ));
        let c = Prefijo::de_ip(IpAddr::V6("2001:db8:1:3::1".parse::<Ipv6Addr>().unwrap()));
        assert_eq!(
            a, b,
            "mismo /64: 18 trillones de direcciones son un cliente"
        );
        assert_ne!(a, c, "distinto /64");
    }

    #[test]
    fn el_prefijo_se_extrae_de_una_multiaddr() {
        let m: Multiaddr = "/ip4/192.168.1.5/tcp/9833".parse().unwrap();
        assert_eq!(Prefijo::de_multiaddr(&m), Some(v4(192, 168, 1, 0)));

        let m6: Multiaddr = "/ip6/2001:db8::1/tcp/9833".parse().unwrap();
        assert!(matches!(Prefijo::de_multiaddr(&m6), Some(Prefijo::V6(_))));

        // Memoria: sin IP, **no se limita**. Limitarlo rompería el arnés de tests sin defender nada.
        let mem: Multiaddr = "/memory/12345".parse().unwrap();
        assert_eq!(Prefijo::de_multiaddr(&mem), None);
    }

    /// **Un solo golpe basta para banear.**
    ///
    /// Fabricar una violación de consenso cuesta trabajo real: no ocurre por accidente, así que no
    /// hay segunda oportunidad. Es el valor de Zebra.
    #[test]
    fn una_violacion_de_consenso_banea_de_un_golpe() {
        let mut l = LimitesPorIp::nuevo();
        let p = v4(10, 0, 0, 1);

        assert!(!l.esta_baneado(p));
        assert!(
            l.puntuar(p, PUNTOS_VIOLACION_CONSENSO),
            "banea al primer golpe"
        );
        assert!(l.esta_baneado(p));
        assert_eq!(l.puntos_de(p), UMBRAL_BANEO);

        // Y no se banea dos veces: la segunda no vuelve a devolver `true`.
        assert!(!l.puntuar(p, PUNTOS_VIOLACION_CONSENSO));
        assert_eq!(l.baneados(), 1);
    }

    /// Puntos por debajo del umbral **no** banean, y se acumulan.
    #[test]
    fn los_puntos_se_acumulan_hasta_el_umbral() {
        let mut l = LimitesPorIp::nuevo();
        let p = v4(10, 0, 0, 1);

        assert!(!l.puntuar(p, UMBRAL_BANEO - 1));
        assert!(!l.esta_baneado(p), "uno menos que el umbral no banea");
        assert!(l.puntuar(p, 1), "el que cruza sí");
        assert!(l.esta_baneado(p));
    }

    /// **El registro de baneos está acotado, o sería el vector.**
    ///
    /// Sin la cota, un atacante con muchas redes haría crecer la tabla sin límite — convertiría la
    /// defensa en el ataque.
    #[test]
    fn el_registro_de_baneos_no_crece_sin_limite() {
        let mut l = LimitesPorIp::nuevo();
        // Banear MAX_BANEADOS + 100 prefijos distintos.
        for i in 0..(MAX_BANEADOS + 100) {
            let p = Prefijo::V4([(i / 65_536) as u8, ((i / 256) % 256) as u8, (i % 256) as u8]);
            l.puntuar(p, PUNTOS_VIOLACION_CONSENSO);
        }
        assert_eq!(l.baneados(), MAX_BANEADOS, "la tabla está acotada");

        // Y el desalojo es FIFO: el primero ya no está.
        assert!(
            !l.esta_baneado(Prefijo::V4([0, 0, 0])),
            "el más viejo se desalojó"
        );
        // El último sí.
        let i = MAX_BANEADOS + 99;
        let ultimo = Prefijo::V4([(i / 65_536) as u8, ((i / 256) % 256) as u8, (i % 256) as u8]);
        assert!(l.esta_baneado(ultimo));
    }

    /// Un prefijo baneado se deniega antes que nada, sin mirar cupos.
    #[test]
    fn un_prefijo_baneado_se_deniega_de_inmediato() {
        let mut l = LimitesPorIp::nuevo();
        let p = v4(203, 0, 113, 7);
        l.puntuar(p, PUNTOS_VIOLACION_CONSENSO);

        assert!(matches!(l.comprobar(p, true), Err(Denegada::Baneado)));
        assert!(matches!(l.comprobar(p, false), Err(Denegada::Baneado)));

        // Y uno limpio pasa.
        let limpio = v4(198, 51, 100, 1);
        assert!(l.comprobar(limpio, true).is_ok());
        assert!(l.comprobar(limpio, false).is_ok());
    }

    /// **Loopback se reconoce por prefijo.**
    ///
    /// `ORDEN-W06d10` decisión 3: `127.0.0.0/8` y `::1` son la excepción de la red local.
    #[test]
    fn el_loopback_se_reconoce_por_su_prefijo() {
        assert!(v4(127, 0, 0, 1).es_loopback());
        assert!(v4(127, 5, 6, 7).es_loopback(), "todo 127.0.0.0/8");
        assert!(!v4(10, 0, 0, 1).es_loopback());
        assert!(!v4(126, 255, 255, 255).es_loopback());

        let v6_loop = Prefijo::de_ip(IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap()));
        assert!(v6_loop.es_loopback());
        let v6 = Prefijo::de_ip(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()));
        assert!(!v6.es_loopback());
    }

    /// **DN-09.** En `Red::Dev` el cupo entrante por prefijo **no** se aplica a loopback: si no,
    /// todos los nodos del humo (mismo `127.0.0.0/24`) quedarían capados a 3 entrantes y, con 8
    /// nodos, el total de conexiones no pasaría de 24 — imposible que cada uno tenga ≥4 salientes.
    /// Fuera de dev el cupo sigue igual.
    #[test]
    fn en_dev_el_loopback_no_se_capa_por_prefijo() {
        let loopback = v4(127, 0, 0, 1);
        let mut dev = LimitesPorIp::para_red(Red::Dev);
        *dev.establecidas.entry(loopback).or_insert(0) = MAX_POR_PREFIJO + 5;
        assert!(
            dev.comprobar(loopback, false).is_ok(),
            "en dev, loopback no se capa por prefijo"
        );

        let mut produccion = LimitesPorIp::nuevo();
        *produccion.establecidas.entry(loopback).or_insert(0) = MAX_POR_PREFIJO + 5;
        assert!(
            matches!(
                produccion.comprobar(loopback, false),
                Err(Denegada::DemasiadasEstablecidas { .. })
            ),
            "fuera de dev el cupo por prefijo sigue vigente"
        );
    }

    /// **La penalización de loopback es por `PeerId` y no veta el prefijo.**
    ///
    /// Es la propiedad que evita que un adversario en `127.0.0.1` arrastre a los nodos honestos de
    /// la red dev, que comparten el prefijo `127.0.0.0/24`.
    #[test]
    fn la_penalizacion_loopback_es_por_peer_id_y_no_veta_el_prefijo() {
        let mut l = LimitesPorIp::nuevo();
        let loopback = v4(127, 0, 0, 1);
        let adversario = PeerId::random();
        let honesto1 = PeerId::random();
        let honesto2 = PeerId::random();

        let r = l.penalizar_peer(adversario, &[loopback], PUNTOS_VIOLACION_CONSENSO);
        assert!(r.peer_baneado, "el PeerId del adversario se veta");
        assert!(r.prefijos_baneados.is_empty(), "el prefijo NO se veta");
        assert!(l.esta_baneado_peer(adversario));
        assert!(
            !l.esta_baneado(loopback),
            "127.0.0.0/24 sigue limpio: los honestos pueden reconectar"
        );
        assert!(l.comprobar(loopback, false).is_ok());
        assert!(matches!(
            l.comprobar_peer(adversario),
            Err(Denegada::PeerBaneado)
        ));
        assert!(l.comprobar_peer(honesto1).is_ok());
        assert!(l.comprobar_peer(honesto2).is_ok());
    }

    /// **Fuera de loopback nada cambia:** la puntuación sigue siendo por prefijo (C-NET-20).
    #[test]
    fn fuera_de_loopback_la_puntuacion_sigue_siendo_por_prefijo() {
        let mut l = LimitesPorIp::nuevo();
        let p = v4(203, 0, 113, 0);
        let peer = PeerId::random();

        let r = l.penalizar_peer(peer, &[p], PUNTOS_VIOLACION_CONSENSO);
        assert!(
            !r.peer_baneado,
            "un prefijo público no se sustituye por PeerId"
        );
        assert_eq!(r.prefijos_baneados, vec![p]);
        assert!(l.esta_baneado(p));
        assert!(!l.esta_baneado_peer(peer));
        // Otro par del mismo prefijo público cae con el prefijo, como antes.
        assert!(matches!(l.comprobar(p, false), Err(Denegada::Baneado)));
    }

    /// El registro de `PeerId` baneados está acotado como el de prefijos (desalojo FIFO).
    #[test]
    fn el_registro_de_peers_baneados_no_crece_sin_limite() {
        let mut l = LimitesPorIp::nuevo();
        let loopback = v4(127, 0, 0, 1);
        let peers: Vec<PeerId> = (0..(MAX_BANEADOS + 100))
            .map(|_| PeerId::random())
            .collect();
        for &peer in &peers {
            let _ = l.penalizar_peer(peer, &[loopback], PUNTOS_VIOLACION_CONSENSO);
        }
        assert_eq!(l.baneados_peer(), MAX_BANEADOS, "la tabla está acotada");
        assert!(!l.esta_baneado_peer(peers[0]), "el más viejo se desalojó");
        assert!(l.esta_baneado_peer(peers[MAX_BANEADOS + 99]));
    }

    /// **C-NET-37.** El prefijo de una conexión **saliente** también se registra: antes esta ruta
    /// devolvía `Ok` sin anotar nada y por eso las salientes no se contaban.
    #[test]
    fn la_saliente_registra_su_prefijo() {
        use libp2p::core::Endpoint;
        use libp2p::core::transport::PortUse;
        use libp2p::swarm::{ConnectionId, NetworkBehaviour};

        let mut l = LimitesPorIp::nuevo();
        let peer = PeerId::random();
        let addr: Multiaddr = "/ip4/198.51.100.7/tcp/9833".parse().unwrap();
        let r = NetworkBehaviour::handle_established_outbound_connection(
            &mut l,
            ConnectionId::new_unchecked(1),
            peer,
            &addr,
            Endpoint::Dialer,
            PortUse::Reuse,
        );
        assert!(r.is_ok());
        let prefijos = l.prefijos_de(peer);
        assert_eq!(prefijos, vec![v4(198, 51, 100, 0)]);
        // Se cuenta como saliente y **no** consume el cupo de entrantes por prefijo (C-NET-20).
        assert_eq!(l.salientes_de(v4(198, 51, 100, 0)), 1);
        assert!(
            l.comprobar(v4(198, 51, 100, 0), false).is_ok(),
            "una saliente propia no gasta el cupo de entrantes del mismo prefijo"
        );
        // Con el prefijo registrado, la penalización por prefijo (C-NET-20) funciona también para
        // un par del que solo teníamos la saliente.
        let r = l.penalizar_peer(peer, &prefijos, PUNTOS_VIOLACION_CONSENSO);
        assert_eq!(r.prefijos_baneados, prefijos);
    }
}
