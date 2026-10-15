//! Composición de behaviours de libp2p (SPEC §16).
//!
//! # Aquí no hay ni un solo default de transporte
//!
//! Es el punto del crate donde se aplica C-NET-11. Cada `Config` que se construye aquí sobrescribe
//! explícitamente lo que libp2p trae de fábrica, porque **sus defaults no son seguros para una
//! cadena y ninguno falla al compilar**. Si alguien borra una línea de este archivo, el código
//! sigue compilando y la red deja de funcionar de una de estas maneras:
//!
//! - los bloques dejan de propagarse (`max_transmit_size`),
//! - un bloque inválido se reenvía antes de validarse (`validate_messages`),
//! - un peer abre conexiones sin límite (`ConnectionLimits`),
//! - la DHT habla con IPFS (`kad::Config::default()`).
//!
//! Por eso cada uno lleva su test.

// `#[derive(NetworkBehaviour)]` genera `ZxBehaviourEvent` con una variante por campo, y no puede
// documentarlas por nosotros. La alternativa —declarar el evento a mano con `to_swarm`— duplicaría
// la lista de behaviours.
#![expect(
    missing_docs,
    reason = "las variantes del evento las genera el derive de libp2p"
)]

use std::time::Duration;

use libp2p::{
    Multiaddr, PeerId, StreamProtocol, connection_limits, gossipsub, identify, identity, kad, mdns,
    ping, request_response, swarm::NetworkBehaviour, swarm::behaviour::toggle::Toggle,
};
use zx_core::red::Red;

use crate::codec::ZxCodec;
use crate::limites_ip::LimitesPorIp;
use crate::presupuesto::Presupuesto;

use crate::config::ParametrosRed;
use crate::error::P2pError;
use crate::limites;

/// Cada cuánto late gossipsub.
///
/// 🔶 **PLAUSIBLE NO DEMOSTRADO — P-019.** Se toma el default de libp2p (1 s) y se marca para
/// **medir**, no para justificar a posteriori.
const HEARTBEAT: Duration = Duration::from_secs(1);

/// Grado objetivo de la malla de gossipsub.
///
/// 8/6/12 en vez del default 6/5/12 de libp2p. La **topología** sí es transferible desde Ethereum.
const MESH_N: usize = 8;
/// Marca de agua inferior de la malla.
const MESH_N_BAJO: usize = 6;
/// Marca de agua superior de la malla.
const MESH_N_ALTO: usize = 12;

/// Cuánto se espera una respuesta de sincronización.
///
/// El default de `request_response::Config` son **10 s**, pensados para peticiones pequeñas. Un
/// lote de bloques puede ser de megabytes: por un enlace lento, 10 s se agotan y el peer parece
/// muerto cuando solo iba despacio.
const TIMEOUT_SYNC: Duration = Duration::from_secs(30);

// La coherencia de la malla es una aserción de compilación, no un test.
const _: () = assert!(
    MESH_N_BAJO < MESH_N && MESH_N < MESH_N_ALTO,
    "la malla MUST cumplir bajo < objetivo < alto"
);

/// Los behaviours que componen un nodo de ZEROX.
#[derive(NetworkBehaviour)]
pub struct ZxBehaviour {
    /// Rechaza conexiones por encima de los límites. **Primero en la lista a propósito.**
    pub limites: connection_limits::Behaviour,
    /// Límites y baneo **por prefijo de red** (C-NET-20).
    pub limites_ip: LimitesPorIp,
    /// Intercambio de direcciones y protocolos soportados.
    pub identify: identify::Behaviour,
    /// Detecta peers muertos, y **mantiene viva** la conexión frente al `idle_connection_timeout`.
    pub ping: ping::Behaviour,
    /// Descubrimiento por DHT.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Descubrimiento en LAN. **Solo testnet** — ver [`ZxBehaviour::nueva`].
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    /// Difusión de bloques completos (PoW y PoST).
    ///
    /// `pub(crate)` y no `pub`: es el behaviour **suscrito** a los temas, y
    /// [`crate::servicio::ManejoRed`] conserva su propia copia de esos temas para fijar el canal de
    /// difusión.
    pub(crate) gossipsub: gossipsub::Behaviour,
    /// Sincronización punto a punto: `CabecerasPow`/`Bloques`.
    ///
    /// **Separado de gossipsub a propósito.** Gossipsub difunde hacia la malla actual y no es un
    /// almacén direccionable: no hay forma de pedirle "el bloque de hace seis meses". Un nodo que
    /// arrancara de cero esperando el historial por gossip **se quedaría atascado en el génesis**.
    pub sync: request_response::Behaviour<ZxCodec>,
    /// Los parámetros de red con los que se construyó esta composición.
    ///
    /// Es un behaviour **sin tráfico propio** para poder viajar dentro del
    /// `#[derive(NetworkBehaviour)]` y ser la única fuente de los temas que usa el handle.
    pub(crate) parametros: ParametrosDelNodo,
}

/// Un behaviour de libp2p que **no hace nada**: solo transporta [`ParametrosRed`].
///
/// `#[derive(NetworkBehaviour)]` exige que **todos** los campos implementen `NetworkBehaviour`; no
/// admite un campo de datos al margen. `poll` devuelve `Pending` siempre —no genera eventos— y su
/// `ConnectionHandler` es el `dummy::ConnectionHandler` de libp2p, que no negocia ningún protocolo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParametrosDelNodo(ParametrosRed);

impl ParametrosDelNodo {
    /// Envuelve los parámetros de una red.
    #[must_use]
    pub const fn nuevos(p: ParametrosRed) -> Self {
        Self(p)
    }

    /// Los parámetros envueltos.
    #[must_use]
    pub const fn de_red(self) -> ParametrosRed {
        self.0
    }
}

impl NetworkBehaviour for ParametrosDelNodo {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), libp2p::swarm::ConnectionDenied> {
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: libp2p::core::Endpoint,
        _: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _: libp2p::swarm::FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: libp2p::swarm::ConnectionId,
        evento: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        libp2p::core::util::unreachable(evento);
    }

    fn poll(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>>
    {
        std::task::Poll::Pending
    }
}

impl ZxBehaviour {
    /// Los parámetros de red de esta composición.
    #[must_use]
    pub const fn parametros_de_red(&self) -> ParametrosRed {
        self.parametros.de_red()
    }

    /// Construye la composición con **todos** los límites de C-NET-11 fijados explícitamente.
    ///
    /// `limite_bloque` es el límite de cuerpo de la cadena **en el momento de arrancar**.
    ///
    /// # Errores
    /// [`P2pError::Configuracion`] si algún nombre de protocolo o parámetro es inválido, o
    /// [`P2pError::MargenDeTransporteInsuficiente`] si el límite de bloque ya se ha acercado
    /// demasiado a lo que este binario puede transportar.
    pub fn nueva(
        clave: &identity::Keypair,
        p: ParametrosRed,
        limite_bloque: u64,
    ) -> Result<Self, P2pError> {
        Self::con_presupuesto(clave, p, limite_bloque, Presupuesto::default())
    }

    /// Igual, pero con un presupuesto de memoria concreto. Para tests que quieran agotarlo.
    ///
    /// # Errores
    /// Las de [`Self::nueva`].
    pub fn con_presupuesto(
        clave: &identity::Keypair,
        p: ParametrosRed,
        limite_bloque: u64,
        presupuesto: Presupuesto,
    ) -> Result<Self, P2pError> {
        let peer_id = clave.public().to_peer_id();

        // ── C-NET-11 · límites de conexión. El default es `None` en todos los campos. ──
        let limites = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(limites::MAX_CONEXIONES_PENDIENTES))
                .with_max_established_incoming(Some(
                    limites::MAX_PEERS_ENTRANTES + limites::MARGEN_ACEPTACION_DESALOJO,
                ))
                .with_max_established_outgoing(Some(limites::MAX_PEERS_SALIENTES))
                .with_max_established_per_peer(Some(limites::MAX_CONEXIONES_POR_PEER))
                .with_max_established(Some(
                    limites::MAX_CONEXIONES + limites::MARGEN_ACEPTACION_DESALOJO,
                )),
        );

        let limites_ip = LimitesPorIp::para_red(p.red());

        let identify = identify::Behaviour::new(
            identify::Config::new(p.protocolo_identify().to_owned(), clave.public())
                .with_agent_version(p.agent_version()),
        );

        let ping = ping::Behaviour::default();

        // ── C-NET-02 · protocolo propio. El default es la DHT PÚBLICA de IPFS. ──
        let proto_kad = StreamProtocol::try_from_owned(p.protocolo_kad().to_owned())
            .map_err(|_| P2pError::Configuracion("nombre de protocolo de Kademlia inválido"))?;
        let mut kademlia = kad::Behaviour::with_config(
            peer_id,
            kad::store::MemoryStore::new(peer_id),
            kad::Config::new(proto_kad),
        );
        // ── C-NET-34 · modo SERVIDOR explícito. ──
        //
        // `kad::Behaviour` nace en `Mode::Client` con `auto_mode = true` y solo pasa a `Server`
        // cuando tiene una dirección externa **confirmada**. En la red dev sobre loopback eso no
        // ocurre nunca, así que todos los nodos quedan clientes y **ninguno responde
        // `FIND_NODE`**: el paseo aleatorio solo ve a los pares ya conectados y la malla degenera
        // en estrella (humo de RED-2). Un nodo completo de ZEROX sirve su tabla: C-NET-34 exige
        // descubrimiento por DHT sin servidores privilegiados, y eso es exactamente ser servidor.
        kademlia.set_mode(Some(kad::Mode::Server));

        // mDNS **solo en testnet**. En mainnet un nodo anunciaría por multicast su presencia a todo
        // el segmento L2. En dev el descubrimiento lo fija el runner local.
        let mdns = match p.red() {
            Red::Testnet => Toggle::from(Some(
                mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                    .map_err(|_| P2pError::Configuracion("no se pudo iniciar mDNS"))?,
            )),
            Red::Mainnet | Red::Dev => Toggle::from(None),
        };

        let mut gossipsub = Self::gossipsub(clave, p, limite_bloque)?;

        // ── C-NET-11 · la suscripción es exacta y es obligatoria ──
        //
        // Un `ConfigBuilder` sin `subscribe` deja el behaviour **suscrito a nada**: los mensajes
        // entrantes no llegan al bucle, y publicar falla con `NoPeersSubscribedToTopic`.
        //
        // Se suscriben **exactamente cuatro temas** por perfil: el de bloques PoW, el de bloques
        // PoST, el de transacciones sueltas (TX-R-01, `ORDEN-TX3`) y el de votos de finalidad
        // (FV-4b-N1), todos con el cuerpo que fija su contrato (bloque completo / bloque completo /
        // `tx_a_bytes` / sobre `ZXV1` opaco).
        //
        // AG-2c · G3: el tema de agregados lo añade **el servicio** al arrancar
        // (`servicio::arrancar_*`), porque es suscripción permanente del nodo y no de esta
        // composición genérica (que usan los tests sin nodo). Las subredes se piden en caliente.
        for tema in [
            p.topic_bloques_pow(),
            p.topic_bloques_post(),
            p.topic_txs(),
            p.topic_votos(),
        ] {
            let t = gossipsub::IdentTopic::new(tema);
            gossipsub.subscribe(&t).map_err(|_| {
                P2pError::Configuracion("no se pudo suscribir a un tema de gossipsub")
            })?;
        }

        let proto_sync = StreamProtocol::try_from_owned(p.protocolo_sync().to_owned())
            .map_err(|_| P2pError::Configuracion("nombre de protocolo de sync inválido"))?;
        let codec = ZxCodec::con_presupuesto(presupuesto);
        let sync = request_response::Behaviour::with_codec(
            codec,
            [(proto_sync, request_response::ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(TIMEOUT_SYNC)
                .with_max_concurrent_streams(limites::MAX_STREAMS_SYNC),
        );

        Ok(Self {
            limites,
            limites_ip,
            identify,
            ping,
            kademlia,
            mdns,
            gossipsub,
            sync,
            parametros: ParametrosDelNodo::nuevos(p),
        })
    }

    /// Gossipsub con los defaults peligrosos corregidos y **puntuación de pares explícita**
    /// (C-NET-43): P4 (mensajes inválidos) y P7 (comportamiento) penalizan; P6 (colocación por IP)
    /// lleva un umbral alto para no castigar un NAT; P1/P2/P3/P5 quedan para el ajuste posterior.
    fn gossipsub(
        clave: &identity::Keypair,
        p: ParametrosRed,
        limite_bloque: u64,
    ) -> Result<gossipsub::Behaviour, P2pError> {
        // C-NET-13 · se comprueba ANTES de construir nada. El límite de gossipsub se fija al crear
        // el behaviour y no se puede cambiar en caliente, así que si ya vamos justos, arrancar sería
        // arrancar roto.
        let techo = limites::limite_gossip(limite_bloque).ok_or(
            P2pError::MargenDeTransporteInsuficiente {
                limite_bloque,
                limite_transporte: 0,
            },
        )?;
        if !limites::margen_suficiente(limite_bloque, techo) {
            return Err(P2pError::MargenDeTransporteInsuficiente {
                limite_bloque,
                limite_transporte: techo,
            });
        }

        let cfg = gossipsub::ConfigBuilder::default()
            // C-NET-11 · el default son 65 536 B y un bloque completo no cabe.
            .max_transmit_size(techo)
            // C-NET-12 · el default es `false`: reenviaría antes de que validemos.
            .validate_messages()
            .validation_mode(gossipsub::ValidationMode::Strict)
            // El default identifica por (emisor, secuencia), NO por contenido.
            .message_id_fn(id_por_contenido)
            .heartbeat_interval(HEARTBEAT)
            .mesh_n(MESH_N)
            .mesh_n_low(MESH_N_BAJO)
            .mesh_n_high(MESH_N_ALTO)
            .build()
            .map_err(|_| P2pError::Configuracion("configuración de gossipsub inválida"))?;

        let mut behaviour =
            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(clave.clone()), cfg)
                .map_err(|_| P2pError::Configuracion("no se pudo construir gossipsub"))?;

        let (params, umbrales) = puntuacion_de(p);
        behaviour
            .with_peer_score(params, umbrales)
            .map_err(|_| P2pError::Configuracion("puntuación de gossipsub inválida"))?;
        Ok(behaviour)
    }
}

/// Construye la puntuación de pares de gossipsub a partir del perfil (C-NET-43, DN-06).
///
/// Los `default()` del crate son válidos por construcción; solo se sobrescribe lo que la decisión
/// fija: se **desactiva** P1/P2/P3 y el castigo por lentitud (`slow_peer_weight = 0`, C-NET-05), se
/// deja P4 con el peso del perfil, P7 con el suyo y P6 con un umbral alto.
#[must_use]
pub fn puntuacion_de(
    p: ParametrosRed,
) -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    let perfil = crate::config::PerfilRed::de(p.red());

    let tp = gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_weight: 0.0,
        first_message_deliveries_weight: 0.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: perfil.p4_peso,
        ..Default::default()
    };

    let mut topics = std::collections::HashMap::new();
    for tema in [
        p.topic_bloques_pow(),
        p.topic_bloques_post(),
        p.topic_txs(),
        p.topic_votos(),
        // A6-02 · Q1: el tema de anuncios de prueba usa los mismos parámetros que los demás. El
        // tema se suscribe en `servicio::arrancar_*` (como el agregado de AG-2c), no aquí: así las
        // pruebas existentes de «exactamente cuatro temas» siguen afirmando lo mismo.
        p.topic_pruebas(),
    ] {
        topics.insert(gossipsub::IdentTopic::new(tema).hash(), tp.clone());
    }
    // AG-2c · G7: los 65 temas nuevos (64 subredes + el agregado) usan los **mismos** parámetros
    // de gossipsub que el tema de votos de hoy: no se inventa ningún valor.
    for s in 0..p.subredes_voto() {
        topics.insert(
            gossipsub::IdentTopic::new(p.topic_voto_subred(s)).hash(),
            tp.clone(),
        );
    }
    topics.insert(gossipsub::IdentTopic::new(p.topic_agregado()).hash(), tp);

    let params = gossipsub::PeerScoreParams {
        topics,
        topic_score_cap: 0.0,
        app_specific_weight: 1.0,
        // P6 · DN-06: umbral alto para no castigar a los pares legítimos tras un NAT.
        ip_colocation_factor_weight: perfil.p6_peso,
        ip_colocation_factor_threshold: perfil.p6_umbral,
        // P7 · comportamiento.
        behaviour_penalty_weight: perfil.p7_peso,
        behaviour_penalty_threshold: 0.0,
        // C-NET-05 · lentitud NO puntúa: se desactiva el castigo por peer lento del crate.
        slow_peer_weight: 0.0,
        slow_peer_threshold: 0.0,
        ..Default::default()
    };

    let umbrales = gossipsub::PeerScoreThresholds {
        gossip_threshold: perfil.gossip_umbral,
        publish_threshold: perfil.pub_umbral,
        graylist_threshold: perfil.gray_umbral,
        ..Default::default()
    };
    (params, umbrales)
}

/// Identifica un mensaje por el **tema exacto y su contenido**, no por quién lo mandó.
///
/// # Por qué el tema entra en el ID
///
/// El default de libp2p usa `(source_peer_id, sequence_number)`. Con él, el mismo bloque recibido
/// por dos rutas son dos mensajes distintos: se valida dos veces y se reenvía dos veces.
///
/// Pero hashear **solo** `SHA3(datos)` tiene un agujero: dos temas distintos pueden llevar los
/// mismos bytes. Con el tema dentro del hash, mismo tema + mismos bytes = mismo ID; mismos bytes +
/// otro tema = ID distinto.
///
/// ⚠️ **Esto es un identificador de transporte, no un hash de consenso.**
fn id_por_contenido(m: &gossipsub::Message) -> gossipsub::MessageId {
    let tema = zx_core::sha3_256_publico(m.topic.as_str().as_bytes());
    let datos = zx_core::sha3_256_publico(&m.data);
    let mut intermedio = [0u8; 64];
    let (izquierda, derecha) = intermedio.split_at_mut(32);
    izquierda.copy_from_slice(tema.as_bytes());
    derecha.copy_from_slice(datos.as_bytes());
    gossipsub::MessageId::from(*zx_core::sha3_256_publico(&intermedio).as_bytes())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{
        MESH_N, MESH_N_ALTO, MESH_N_BAJO, ParametrosDelNodo, ZxBehaviour, id_por_contenido,
    };
    use crate::config::ParametrosRed;
    use crate::error::P2pError;
    use crate::limites;
    use libp2p::swarm::NetworkBehaviour;
    use libp2p::{PeerId, gossipsub, identity};
    use zx_core::red::Red;

    fn clave() -> identity::Keypair {
        identity::Keypair::generate_ed25519()
    }

    /// Necesita runtime de tokio: `mdns::tokio::Behaviour` abre un socket netlink al construirse.
    #[tokio::test]
    async fn se_construye_en_las_tres_redes() {
        for red in [Red::Mainnet, Red::Testnet, Red::Dev] {
            assert!(
                ZxBehaviour::nueva(&clave(), ParametrosRed::de(red), limites::LIMITE_BLOQUE_DEV)
                    .is_ok(),
                "{red:?}"
            );
        }
    }

    /// **La red dev construye un behaviour con sync, temas, identify y mDNS propios.**
    #[tokio::test]
    async fn la_red_dev_construye_con_sync_y_temas_propios_y_sin_mdns() {
        let p = ParametrosRed::dag_dev();
        let b = ZxBehaviour::nueva(&clave(), p, limites::LIMITE_BLOQUE_DEV).unwrap();

        assert_eq!(b.parametros_de_red().protocolo_sync(), "/zx-dev/2");
        assert_eq!(b.parametros_de_red().protocolo_identify(), "/zx-dev/id/1");
        assert!(!b.mdns.is_enabled(), "la red dev MUST NOT usar mDNS");

        let temas: Vec<String> = b.gossipsub.topics().map(ToString::to_string).collect();
        assert_eq!(temas.len(), 4, "se suscriben exactamente cuatro temas");
        assert!(temas.contains(&p.topic_bloques_pow().to_owned()));
        assert!(temas.contains(&p.topic_bloques_post().to_owned()));
        assert!(temas.contains(&p.topic_txs().to_owned()));
        assert!(temas.contains(&p.topic_votos().to_owned()));
    }

    /// **C-NET-34.** Kademlia nace en modo **servidor** en las tres redes: un nodo completo no
    /// delega el descubrimiento en un servidor privilegiado ni espera una dirección externa
    /// confirmada (que en loopback dev nunca llega).
    #[tokio::test]
    async fn kademlia_es_servidor_en_las_tres_redes() {
        for red in [Red::Mainnet, Red::Testnet, Red::Dev] {
            let b =
                ZxBehaviour::nueva(&clave(), ParametrosRed::de(red), limites::LIMITE_BLOQUE_DEV)
                    .unwrap();
            assert_eq!(
                b.kademlia.mode(),
                libp2p::kad::Mode::Server,
                "{red:?}: sin servidor no hay FIND_NODE que propague terceros"
            );
        }
    }

    /// **C-NET-11 + C-NET-25.** El mismo tema y los mismos bytes dan el mismo id; cambia el tema o
    /// cambian los datos y cambia el id.
    #[test]
    fn el_id_de_mensaje_depende_del_tema_y_del_contenido() {
        let emisor_a = clave().public().to_peer_id();
        let emisor_b = clave().public().to_peer_id();
        assert_ne!(
            emisor_a, emisor_b,
            "hacen falta dos emisores distintos para probar la independencia"
        );

        let mensaje = |tema: &str, datos: &[u8], source: PeerId| gossipsub::Message {
            source: Some(source),
            data: datos.to_vec(),
            sequence_number: None,
            topic: gossipsub::IdentTopic::new(tema).hash(),
        };

        let a = id_por_contenido(&mensaje("/zx-dev/bloques/pow/1", b"bloque", emisor_a));
        let b = id_por_contenido(&mensaje("/zx-dev/bloques/pow/1", b"bloque", emisor_b));
        assert_eq!(
            a, b,
            "mismo tema y bytes desde emisores distintos: es UN mensaje"
        );

        let c = id_por_contenido(&mensaje("/zx-dev/bloques/pow/1", b"otro bloque", emisor_a));
        assert_ne!(a, c, "datos distintos, id distinto");

        let t = id_por_contenido(&mensaje("/zx-dev/bloques/post/1", b"bloque", emisor_a));
        assert_ne!(a, t, "mismos bytes en otro tema MUST NOT consumir el id");
    }

    /// **`ParametrosDelNodo` es inerte: no emite tráfico ni eventos.**
    #[test]
    fn parametros_del_nodo_no_emite_trafico_ni_eventos() {
        use libp2p::swarm::dummy;
        use std::task::{Context, Poll};

        let _: <ParametrosDelNodo as NetworkBehaviour>::ConnectionHandler =
            dummy::ConnectionHandler;

        let mut p = ParametrosDelNodo::nuevos(ParametrosRed::de(Red::Testnet));
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(p.poll(&mut cx), Poll::Pending),
            "un behaviour sin tráfico no puede producir eventos"
        );
    }

    /// El id es un SHA3-256 completo: 32 bytes, no un truncado.
    #[test]
    fn el_id_de_mensaje_mide_32_bytes() {
        let m = gossipsub::Message {
            source: None,
            data: b"x".to_vec(),
            sequence_number: None,
            topic: gossipsub::IdentTopic::new("/zx-dev/bloques/pow/1").hash(),
        };
        assert_eq!(id_por_contenido(&m).0.len(), 32);
    }

    /// **La suscripción es exacta: los cuatro temas de la red, ni uno más.**
    #[tokio::test]
    async fn la_suscripcion_son_los_cuatro_temas_exactos_de_la_red() {
        for red in [Red::Mainnet, Red::Testnet, Red::Dev] {
            let p = ParametrosRed::de(red);
            let b = ZxBehaviour::nueva(&clave(), p, limites::LIMITE_BLOQUE_DEV).unwrap();
            let temas: Vec<String> = b.gossipsub.topics().map(ToString::to_string).collect();

            assert_eq!(temas.len(), 4, "{red:?}: exactamente cuatro temas");
            assert!(
                temas.contains(&p.topic_bloques_pow().to_owned()),
                "{red:?}: falta {}",
                p.topic_bloques_pow()
            );
            assert!(
                temas.contains(&p.topic_bloques_post().to_owned()),
                "{red:?}: falta {}",
                p.topic_bloques_post()
            );
            assert!(
                temas.contains(&p.topic_txs().to_owned()),
                "{red:?}: falta {}",
                p.topic_txs()
            );
            assert!(
                temas.contains(&p.topic_votos().to_owned()),
                "{red:?}: falta {}",
                p.topic_votos()
            );
        }
    }

    /// **Los temas suscritos son de la red pedida, no de la otra.**
    #[tokio::test]
    async fn ningun_tema_suscrito_viene_de_la_otra_red() {
        let m = ParametrosRed::de(Red::Mainnet);
        let bm = ZxBehaviour::nueva(&clave(), m, limites::LIMITE_BLOQUE_DEV).unwrap();
        for t in bm.gossipsub.topics() {
            assert!(!t.to_string().contains("testnet"), "mainnet: {t}");
        }

        let t = ParametrosRed::de(Red::Testnet);
        let bt = ZxBehaviour::nueva(&clave(), t, limites::LIMITE_BLOQUE_DEV).unwrap();
        for tema in bt.gossipsub.topics() {
            assert!(tema.to_string().contains("testnet"), "testnet: {tema}");
        }
    }

    /// **C-NET-11.** La malla es 8/6/12, no el 6/5/12 de fábrica, y es coherente.
    #[test]
    fn la_malla_es_la_de_produccion_y_no_la_de_fabrica() {
        assert_eq!((MESH_N, MESH_N_BAJO, MESH_N_ALTO), (8, 6, 12));
        assert_ne!(MESH_N, 6, "6 es el default de libp2p");
    }

    /// **C-NET-14.** mDNS está en testnet y **NO** en mainnet ni en dev.
    #[tokio::test]
    async fn mdns_solo_esta_en_testnet() {
        let t = ZxBehaviour::nueva(
            &clave(),
            ParametrosRed::de(Red::Testnet),
            limites::LIMITE_BLOQUE_DEV,
        )
        .unwrap();
        assert!(
            t.mdns.is_enabled(),
            "testnet lo necesita para el arnés local"
        );

        for red in [Red::Mainnet, Red::Dev] {
            let b =
                ZxBehaviour::nueva(&clave(), ParametrosRed::de(red), limites::LIMITE_BLOQUE_DEV)
                    .unwrap();
            assert!(!b.mdns.is_enabled(), "{red:?} MUST NOT usar mDNS");
        }
    }

    /// **C-NET-13.** Sin margen de transporte, el behaviour **no se construye**.
    #[tokio::test]
    async fn sin_margen_de_transporte_no_se_construye() {
        for absurdo in [u64::MAX, limites::LIMITE_BLOQUE_ABSURDO + 1, 0] {
            let e = ZxBehaviour::nueva(&clave(), ParametrosRed::de(Red::Testnet), absurdo);
            assert!(
                matches!(e, Err(P2pError::MargenDeTransporteInsuficiente { .. })),
                "un límite de bloque de {absurdo} MUST impedir construir el behaviour"
            );
        }
        assert!(
            ZxBehaviour::nueva(
                &clave(),
                ParametrosRed::de(Red::Testnet),
                limites::LIMITE_BLOQUE_DEV
            )
            .is_ok()
        );
    }

    /// **C-NET-43.** La puntuación de pares existe, P4/P7 penalizan, P6 tiene umbral alto y la
    /// lentitud **no** puntúa (C-NET-05).
    #[tokio::test]
    async fn la_puntuacion_de_pares_esta_activa_y_sin_castigo_por_lentitud() {
        let p = ParametrosRed::de(Red::Dev);
        let (params, umbrales) = super::puntuacion_de(p);
        assert!(params.validate().is_ok(), "parámetros válidos");
        assert!(umbrales.validate().is_ok(), "umbrales válidos");
        assert_eq!(params.slow_peer_weight, 0.0, "C-NET-05: lento no puntúa");
        assert!(
            params.ip_colocation_factor_threshold >= 10.0,
            "DN-06: umbral alto para P6"
        );
        assert!(params.behaviour_penalty_weight < 0.0, "P7 penaliza");
        for tema in [p.topic_bloques_pow(), p.topic_bloques_post()] {
            let th = gossipsub::IdentTopic::new(tema).hash();
            let tp = params.topics.get(&th).expect("tema con parámetros");
            assert!(tp.invalid_message_deliveries_weight < 0.0, "P4 penaliza");
        }

        let b = ZxBehaviour::nueva(&clave(), p, limites::LIMITE_BLOQUE_DEV).unwrap();
        let topic = gossipsub::IdentTopic::new(p.topic_bloques_pow());
        assert!(
            b.gossipsub.get_topic_params(&topic).is_some(),
            "el behaviour real activa la puntuación"
        );
    }

    /// La identidad de `identify` es de ZEROX y nombra la red.
    #[test]
    fn identify_anuncia_zerox_y_no_la_libreria() {
        for p in [
            ParametrosRed::de(Red::Mainnet),
            ParametrosRed::de(Red::Testnet),
            ParametrosRed::dag_dev(),
        ] {
            assert!(
                p.protocolo_identify().starts_with("/zerox")
                    || p.protocolo_identify().starts_with("/zx-dev"),
                "{p:?}"
            );
            let v = p.agent_version();
            assert!(v.starts_with("zerox/"), "{v}");
            assert!(
                !v.contains("rust-libp2p"),
                "el default delata la librería: {v}"
            );
        }
    }
}
