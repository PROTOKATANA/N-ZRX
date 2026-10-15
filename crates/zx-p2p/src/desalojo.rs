//! Protección de los entrantes al desalojar (C-NET-42).
//!
//! Cuando el nodo está al tope de entrantes (`MAX_PEERS_ENTRANTES = 72`), a quién se sacrifica no
//! puede decidirlo el atacante: hay que proteger, por este orden, a quien **entregó primero un
//! bloque válido**, a quien tiene **menor latencia** y a los más **antiguos** (mitad protegida),
//! desalojando del grupo más sobrerrepresentado y más joven. Lo que dependa de la **vista local**
//! no cuenta (RFT-27).
//!
//! # Dos piezas
//!
//! - [`elegir_victima`] es la **política pura**: recibe candidatos y decide. No tiene estado.
//! - [`DesalojoEntrantes`] es el **estado vivo** que la alimenta desde el bucle de `Swarm`
//!   (`crate::servicio`): altas al establecerse una conexión entrante, bajas al caer, latencia de
//!   los eventos de `ping` y marca de «entregó un bloque válido» cuando gossipsub acepta un mensaje
//!   propagado por ese par. El desalojo se dispara en el **punto de aceptación**: al aceptar una
//!   entrante nueva estando lleno, se elige víctima entre las ya establecidas y se la desconecta.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId};

use crate::limites::MAX_PEERS_ENTRANTES;
use crate::limites_ip::Prefijo;

/// Grupo de red de un candidato a desalojo (paso 4 de C-NET-42).
///
/// Es [`Prefijo`] cuando la dirección lleva IP. En los tests sobre transporte **en memoria** no la
/// lleva: sin este caso, todos los pares caerían en un mismo grupo ficticio y el desempate por
/// sobrerrepresentación perdería sentido. Ahí se agrupa por `PeerId`, la misma excepción de la red
/// local que usa el gestor de direcciones en `Red::Dev` (DN-09).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Grupo {
    /// Prefijo de red real (`/24` IPv4, `/64` IPv6).
    Red(Prefijo),
    /// Dirección sin IP (p. ej. transporte en memoria): se agrupa por `PeerId`.
    Peer(PeerId),
}

impl Grupo {
    /// El grupo de una dirección de conexión y su par.
    #[must_use]
    pub fn de_multiaddr(addr: &Multiaddr, peer: PeerId) -> Self {
        match Prefijo::de_multiaddr(addr) {
            Some(p) => Self::Red(p),
            None => Self::Peer(peer),
        }
    }
}

/// Lo que el nodo sabe de un entrante para decidir a quién sacrifica.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidato {
    /// El par.
    pub peer: PeerId,
    /// ¿Entregó primero un bloque válido? (protección 1)
    pub entrego_valido: bool,
    /// Posición de entrega entre los que entregaron (menor = antes). Desempate de la protección 1.
    pub orden_entrega: Option<u64>,
    /// Latencia medida (menor = mejor). `None` = desconocida (peor).
    pub latencia: Option<Duration>,
    /// Antigüedad de la conexión (mayor = más antiguo).
    pub antiguedad: Duration,
    /// Grupo de red de origen.
    pub grupo: Grupo,
}

/// Elige la víctima a desalojar (C-NET-42). `None` solo si no hay candidatos.
///
/// La decisión **no mira la vista local**: no hay ningún campo de `VistaLocal` en [`Candidato`].
#[must_use]
#[expect(
    clippy::integer_division,
    reason = "la mitad entera es deliberada: se protege a los len/2 más antiguos"
)]
pub fn elegir_victima(candidatos: &[Candidato]) -> Option<PeerId> {
    if candidatos.is_empty() {
        return None;
    }
    let mut vivos: Vec<&Candidato> = candidatos.iter().collect();

    // 1 · Quien no entregó un bloque válido se sacrifica antes.
    if vivos.iter().any(|c| !c.entrego_valido) {
        vivos.retain(|c| !c.entrego_valido);
    } else {
        // Desempate: los que entregaron más tarde, primero.
        if let Some(peor_orden) = vivos.iter().filter_map(|c| c.orden_entrega).max() {
            let filtrados: Vec<&Candidato> = vivos
                .iter()
                .copied()
                .filter(|c| c.orden_entrega == Some(peor_orden))
                .collect();
            if !filtrados.is_empty() {
                vivos = filtrados;
            }
        }
    }

    // 2 · Peor latencia primero (`None` = desconocida = peor que cualquier medida).
    let con_peor: Vec<&Candidato> = if vivos.iter().any(|c| c.latencia.is_none()) {
        vivos
            .iter()
            .copied()
            .filter(|c| c.latencia.is_none())
            .collect()
    } else {
        let peor = vivos.iter().filter_map(|c| c.latencia).max();
        vivos
            .iter()
            .copied()
            .filter(|c| c.latencia == peor)
            .collect()
    };
    if !con_peor.is_empty() {
        vivos = con_peor;
    }

    // 3 · Se protege a la mitad más antigua; se desaloja del resto.
    if vivos.len() > 1 {
        let mut por_antiguedad = vivos.clone();
        por_antiguedad.sort_by_key(|c| std::cmp::Reverse(c.antiguedad));
        let proteger = por_antiguedad.len() / 2;
        let no_protegidos: Vec<&Candidato> = por_antiguedad.into_iter().skip(proteger).collect();
        if !no_protegidos.is_empty() {
            vivos = no_protegidos;
        }
    }

    // 4 · Grupo más sobrerrepresentado (contado sobre TODOS los candidatos) y, dentro, el más joven.
    let mut conteo: HashMap<Grupo, usize> = HashMap::new();
    for c in candidatos {
        *conteo.entry(c.grupo).or_insert(0) += 1;
    }
    let mas_sobrerrepresentado = vivos
        .iter()
        .map(|c| conteo.get(&c.grupo).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let victima = vivos
        .iter()
        .copied()
        .filter(|c| conteo.get(&c.grupo).copied().unwrap_or(0) == mas_sobrerrepresentado)
        .min_by_key(|c| c.antiguedad)
        .or_else(|| vivos.iter().copied().min_by_key(|c| c.antiguedad))?;
    Some(victima.peer)
}

/// Lo que el bucle de red guarda de un entrante establecido.
#[derive(Clone, Debug)]
struct InfoEntrante {
    grupo: Grupo,
    desde: Instant,
    latencia: Option<Duration>,
    entrego_valido: bool,
    orden_entrega: Option<u64>,
}

impl InfoEntrante {
    fn a_candidato(&self, peer: PeerId, ahora: Instant) -> Candidato {
        Candidato {
            peer,
            entrego_valido: self.entrego_valido,
            orden_entrega: self.orden_entrega,
            latencia: self.latencia,
            antiguedad: ahora.saturating_duration_since(self.desde),
            grupo: self.grupo,
        }
    }
}

/// Estado vivo de los entrantes para aplicar C-NET-42 en el punto de aceptación.
///
/// Se alimenta desde el bucle de `Swarm` ([`crate::servicio`]) y no toma ninguna decisión por su
/// cuenta salvo responder a [`Self::admitir`] con la víctima a desconectar.
pub struct DesalojoEntrantes {
    /// Tope de entrantes. Se puede bajar en tests para no montar 73 conexiones reales; en
    /// producción es [`MAX_PEERS_ENTRANTES`].
    max: usize,
    /// Orden de entrega global, monótono.
    contador_entrega: u64,
    entrantes: HashMap<PeerId, InfoEntrante>,
}

impl DesalojoEntrantes {
    /// Uno vacío con un tope explícito (tests) o el de producción ([`Self::de_produccion`]).
    #[must_use]
    pub fn nuevo(max: usize) -> Self {
        Self {
            max,
            contador_entrega: 0,
            entrantes: HashMap::new(),
        }
    }

    /// El de la red: tope [`MAX_PEERS_ENTRANTES`].
    #[must_use]
    pub fn de_produccion() -> Self {
        Self::nuevo(MAX_PEERS_ENTRANTES as usize)
    }

    /// El tope configurado.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }

    /// Cuántos entrantes se conocen ahora.
    #[must_use]
    pub fn total(&self) -> usize {
        self.entrantes.len()
    }

    /// ¿Se conoce a este entrante?
    #[must_use]
    pub fn contiene(&self, peer: &PeerId) -> bool {
        self.entrantes.contains_key(peer)
    }

    /// Registra una conexión entrante establecida.
    ///
    /// Idempotente: reconectar al mismo par no duplica ni reinicia su antigüedad si ya estaba.
    pub fn al_establecer(&mut self, peer: PeerId, addr: &Multiaddr, ahora: Instant) {
        self.entrantes.entry(peer).or_insert_with(|| InfoEntrante {
            grupo: Grupo::de_multiaddr(addr, peer),
            desde: ahora,
            latencia: None,
            entrego_valido: false,
            orden_entrega: None,
        });
    }

    /// Quita un entrante al caer su conexión.
    pub fn al_desconectar(&mut self, peer: &PeerId) {
        self.entrantes.remove(peer);
    }

    /// Actualiza la latencia medida (evento de `ping`).
    pub fn al_latencia(&mut self, peer: &PeerId, latencia: Duration) {
        if let Some(i) = self.entrantes.get_mut(peer) {
            i.latencia = Some(latencia);
        }
    }

    /// Marca que este par propagó un bloque que el nodo consideró válido (`Aceptar`). Solo cuenta
    /// la **primera** entrega; la posición queda fijada entonces.
    pub fn al_entrego_valido(&mut self, peer: &PeerId) {
        let orden = self.contador_entrega;
        let Some(i) = self.entrantes.get_mut(peer) else {
            return;
        };
        if !i.entrego_valido {
            i.entrego_valido = true;
            i.orden_entrega = Some(orden);
            self.contador_entrega = self.contador_entrega.wrapping_add(1);
        }
    }

    /// Elige víctima entre los entrantes ya establecidos, excluyendo a `excluir` (el que se está
    /// aceptando) si se pasa.
    #[must_use]
    pub fn elegir(&self, ahora: Instant, excluir: Option<PeerId>) -> Option<PeerId> {
        let candidatos: Vec<Candidato> = self
            .entrantes
            .iter()
            .filter(|(p, _)| Some(**p) != excluir)
            .map(|(p, i)| i.a_candidato(*p, ahora))
            .collect();
        elegir_victima(&candidatos)
    }

    /// **El punto de aceptación.** Al aceptar la entrante `peer`, si ya se está en el tope devuelve
    /// la víctima a desconectar (elegida entre las ya establecidas) y registra a `peer`. El bucle
    /// desconecta a la víctima; la entrada de la víctima se limpia al llegar su `ConnectionClosed`.
    pub fn admitir(&mut self, peer: PeerId, addr: &Multiaddr, ahora: Instant) -> Option<PeerId> {
        let victima = if self.entrantes.len() >= self.max {
            self.elegir(ahora, Some(peer))
        } else {
            None
        };
        self.al_establecer(peer, addr, ahora);
        victima
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{Candidato, DesalojoEntrantes, Grupo, elegir_victima};
    use crate::limites_ip::Prefijo;
    use libp2p::{Multiaddr, PeerId};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    fn grupo(a: u8, b: u8, c: u8) -> Grupo {
        Grupo::Red(Prefijo::de_ip(IpAddr::V4(Ipv4Addr::new(a, b, c, 1))))
    }

    fn cand(entrego: bool, latencia: Option<u64>, antiguedad: u64, g: Grupo) -> Candidato {
        Candidato {
            peer: PeerId::random(),
            entrego_valido: entrego,
            orden_entrega: Some(0),
            latencia: latencia.map(Duration::from_millis),
            antiguedad: Duration::from_secs(antiguedad),
            grupo: g,
        }
    }

    #[test]
    fn sin_candidatos_no_hay_victima() {
        assert_eq!(elegir_victima(&[]), None);
    }

    /// 1 · Quien **no** entregó un bloque válido cae antes que quien sí.
    #[test]
    fn protege_a_quien_entrego_un_bloque_valido() {
        let malo = cand(false, Some(1), 10, grupo(10, 0, 0));
        let bueno = cand(true, Some(100), 1, grupo(11, 0, 0));
        let v = elegir_victima(&[malo.clone(), bueno.clone()]).unwrap();
        assert_eq!(v, malo.peer, "se sacrifica al que no entregó");
    }

    /// 2 · Entre los que entregaron, cae el de peor latencia.
    #[test]
    fn sacrifica_al_de_peor_latencia() {
        let lento = cand(true, Some(500), 10, grupo(10, 0, 0));
        let rapido = cand(true, Some(5), 10, grupo(11, 0, 0));
        let v = elegir_victima(&[lento.clone(), rapido.clone()]).unwrap();
        assert_eq!(v, lento.peer);
    }

    /// 4 · Se desaloja del grupo sobrerrepresentado y al más joven de él.
    #[test]
    fn desaloja_del_grupo_sobrerrepresentado_y_mas_joven() {
        let gx = grupo(10, 0, 0);
        let gy = grupo(11, 0, 0);
        let muy_joven_x = cand(true, Some(1), 1, gx);
        let joven_x = cand(true, Some(1), 2, gx);
        let viejo_x = cand(true, Some(1), 100, gx);
        let viejo_y = cand(true, Some(1), 100, gy);
        let v = elegir_victima(&[muy_joven_x.clone(), joven_x.clone(), viejo_x, viejo_y]).unwrap();
        // El grupo X está sobrerrepresentado (3 frente a 1) y el más joven de X es `muy_joven_x`.
        assert_eq!(v, muy_joven_x.peer);
    }

    /// **V4 (estado vivo).** Con las 72 entrantes llenas, la 73.ª desaloja a una de las ya
    /// establecidas, nunca a un par protegido: el más joven de los no protegidos.
    #[test]
    fn con_72_llenas_la_73_desaloja_a_la_mas_joven_no_protegida() {
        let t0 = Instant::now();
        let mut d = DesalojoEntrantes::de_produccion();
        let addr: Multiaddr = "/memory/1".parse().unwrap();
        let mut pares = Vec::new();
        for i in 0..72u64 {
            let p = PeerId::random();
            pares.push(p);
            d.al_establecer(p, &addr, t0 + Duration::from_secs(i));
        }
        // El más joven de todos es el último (i = 71); los 36 primeros son la mitad protegida.
        let joven = pares.get(71).copied().expect("72 pares");
        let protegido = pares.first().copied().expect("72 pares");

        let nueva = PeerId::random();
        let victima = d
            .admitir(nueva, &addr, t0 + Duration::from_secs(100))
            .expect("con 72 llenas, la 73 debe desalojar");
        assert_eq!(victima, joven, "cae el más joven de la mitad no protegida");
        assert_ne!(
            victima, protegido,
            "nunca un par de la mitad antigua protegida"
        );
        assert_ne!(victima, nueva, "no se desaloja a la que se está aceptando");
        assert_eq!(d.total(), 73, "hasta que llegue su ConnectionClosed");
    }

    /// **V4 (reingreso inmediato).** Documenta por qué la integración no puede exigir «la
    /// recién aceptada nunca se desconecta»: si la desalojada vuelve antes de que su baja se
    /// contabilice —lo que hace el *bootstrap* automático de Kademlia al redescubrir al único
    /// par conocido—, el tope sigue lleno y el siguiente desalojo recae en la más joven de las
    /// no probadas, que es la que se acaba de aceptar. Es la política C-NET-42 aplicada a una
    /// admisión nueva, no una carrera; el caso de FIX-06.
    #[test]
    fn el_reingreso_de_la_desalojada_vuelve_a_desalojar_y_cae_la_mas_joven() {
        let t0 = Instant::now();
        let mut d = DesalojoEntrantes::nuevo(3);
        let addr: Multiaddr = "/memory/1".parse().unwrap();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();
        for (i, p) in [p1, p2, p3].iter().enumerate() {
            d.al_establecer(*p, &addr, t0 + Duration::from_secs(i as u64));
        }
        let p4 = PeerId::random();
        let v1 = d
            .admitir(p4, &addr, t0 + Duration::from_secs(10))
            .expect("con el tope lleno, la 4.ª desaloja");
        assert_eq!(v1, p3, "cae la más joven de las tres");
        // La desalojada vuelve antes de que llegue su `ConnectionClosed`: el tope sigue
        // lleno (4 conocidos) y el nuevo desalojo recae en la más joven, P4.
        let v2 = d
            .admitir(v1, &addr, t0 + Duration::from_secs(11))
            .expect("el reingreso vuelve a desalojar");
        assert_eq!(
            v2, p4,
            "el reingreso de la desalojada desaloja a la recién aceptada"
        );
    }

    /// **V4 (protección).** Aunque sea el más joven, si entregó un bloque válido y hay otros que no,
    /// no se le desaloja.
    #[test]
    fn nunca_desaloja_a_quien_entrego_valido() {
        let t0 = Instant::now();
        let mut d = DesalojoEntrantes::nuevo(4);
        let addr: Multiaddr = "/memory/1".parse().unwrap();
        let mut pares = Vec::new();
        for i in 0..4u64 {
            let p = PeerId::random();
            pares.push(p);
            d.al_establecer(p, &addr, t0 + Duration::from_secs(i));
        }
        // El más joven (el último) entregó un bloque válido.
        d.al_entrego_valido(pares.get(3).expect("4 pares"));

        let victima = d
            .admitir(PeerId::random(), &addr, t0 + Duration::from_secs(10))
            .expect("debe desalojar");
        assert_ne!(
            victima,
            *pares.get(3).expect("4 pares"),
            "el que entregó un bloque válido no cae mientras haya uno que no"
        );
    }

    /// Altas, bajas, latencia y entrega se reflejan en el estado.
    #[test]
    fn altas_bajas_latencia_y_entrega_se_reflejan() {
        let t0 = Instant::now();
        let mut d = DesalojoEntrantes::nuevo(2);
        let a = PeerId::random();
        let b = PeerId::random();
        let addr: Multiaddr = "/ip4/10.0.0.1/tcp/1".parse().unwrap();
        d.al_establecer(a, &addr, t0);
        d.al_establecer(a, &addr, t0 + Duration::from_secs(5));
        assert_eq!(d.total(), 1, "reconectar no duplica");
        d.al_establecer(b, &addr, t0);
        assert_eq!(d.total(), 2);
        d.al_latencia(&a, Duration::from_millis(3));
        d.al_entrego_valido(&a);
        d.al_entrego_valido(&a);
        assert_eq!(d.contador_entrega, 1, "solo cuenta la primera entrega");
        // La 3.ª desaloja, pero `a` entregó válido: cae `b`.
        let victima = d.admitir(PeerId::random(), &addr, t0 + Duration::from_secs(1));
        assert_eq!(victima, Some(b), "a está protegido por entrega");
        d.al_desconectar(&b);
        assert!(!d.contiene(&b));
        assert!(d.contiene(&a));
    }
}
