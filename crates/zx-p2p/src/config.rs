//! Parámetros de red por cadena (SPEC §16, C-NET-01, C-NET-02).
//!
//! # Los nombres de protocolo NO son cosmética
//!
//! `kad::Config::default()` usa `/ipfs/kad/1.0.0` — la DHT **pública de IPFS** — y no falla al
//! compilar. Verificado en `rust-libp2p@v0.56.0`, `protocols/kad/src/behaviour.rs:196-241`. Por eso
//! todos los nombres se derivan de [`ParametrosRed`] y ninguno se deja por defecto.
//!
//! # Aislamiento de red
//!
//! C-NET-01 exige que todo mensaje del protocolo P2P vaya precedido de un prefijo mágico de 4 bytes
//! propio de la red. El `magic` sigue siendo **metadato** (no se escribe en el wire): el aislamiento
//! real de los mensajes de aplicación se apoya en protocolos y temas distintos, y el saludo
//! [`crate::mensaje::Estado`] coteja `hash_genesis` y `red` para cortar la conexión cruzada.
//!
//! # La red dev de 0.0.1
//!
//! [`ParametrosRed::dag_dev`] construye el perfil de desarrollo: protocolo `/zx-dev/2` y **cuatro**
//! temas de gossip, `/zx-dev/bloques/pow/2`, `/zx-dev/bloques/post/2`, `/zx-dev/tx/2` (TX-R-01,
//! `ORDEN-TX3`) y `/zx-dev/votos/2` (FV-4b-N1): los dos primeros con el bloque completo, el tercero
//! con `tx_a_bytes` (TX-R-02) y el cuarto con el sobre de voto `ZXV1` (bytes opacos). El sufijo `/2`
//! es ZRX-C (`ORDEN-ZC3`, R-8): esos cuerpos viajan comprimidos; el `/1` de la base queda atrás
//! porque ZRX-C es obligatorio y un par sin la capacidad se rechaza en `identify`.
//! El relé compacto (BIP 152) no se porta en 0.0.1.

use std::time::Duration;

use zx_core::red::Red;

/// Perfil de la red de descubrimiento y salientes (RED-2 §2.8: ningún valor cableado).
///
/// Los valores **medidos o decididos** (DN-02/03/04/07/08) van aquí con su valor; los que el
/// contrato deja `<<POR MEDIR>> / <<POR DECIDIR>>` y la orden no fija se declaran como provisionales
/// de dev y están anotados en `PROGRESO.md`. Ninguno es un parámetro de consenso.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PerfilRed {
    /// Capacidad de la tabla `nuevos` (DN-02).
    pub nuevos: usize,
    /// Capacidad de la tabla `probados` (DN-02).
    pub probados: usize,
    /// Entradas por grupo ancho (`/16`, `/32`) (DN-08).
    pub cap_ancho: usize,
    /// Entradas por grupo estrecho (`/24`, `/48`) (DN-08).
    pub cap_estrecho: usize,
    /// Anclas persistentes (DN-04).
    pub anclas: usize,
    /// Direcciones admitidas por mensaje (DN-07).
    pub dirs_por_mensaje: usize,
    /// Tope de direcciones por par y ventana (DN-07).
    pub cuota_tope: usize,
    /// Ventana de la cuota por par (DN-07; duración provisional).
    pub cuota_ventana: Duration,
    /// `T_par`: rotación de una saliente (DN-03).
    pub t_par: Duration,
    /// Cadencia del paseo aleatorio de Kademlia (provisional).
    pub t_paseo: Duration,
    /// `T_feeler`: cadencia del sondeo (provisional).
    pub t_feeler: Duration,
    /// Plazo de un sondeo (provisional).
    pub plazo_feeler: Duration,
    /// Ventana de resolución de `test-before-evict` (provisional).
    pub ventana_evict: Duration,
    /// Salientes objetivo (`omega`).
    pub omega: u32,
    // ── ORDEN-RD1c · registro firmado de direcciones (ZXREG1) ──────────────────
    /// ¿Está encendido el registro firmado de direcciones? **Apagado por defecto**: los pasos 1 y 2
    /// dejan el registro listo pero nada del nodo lo enciende todavía.
    pub registro_activo: bool,
    /// Semiancho `V` de la ventana de época del registro.
    ///
    /// **<<PENDIENTE DE MODELO>>**: el valor real sale del mismo modelo que la ventana de pesos
    /// (`REVISION-RDM1`/`REDB4D2`). El de aquí es **solo para las pruebas**.
    pub registro_v: u64,
    /// Tope de entradas **pendientes** del registro.
    ///
    /// **<<PENDIENTE DE MODELO>>**: sale del tamaño de la ventana. El de aquí es solo para pruebas.
    pub registro_pendientes: usize,
    /// Caducidad (`TTL`) de una entrada pendiente, en la misma unidad que `epoch`.
    ///
    /// **<<PENDIENTE DE MODELO>>**: el valor real sale del mismo modelo. El de aquí es solo para
    /// pruebas.
    pub registro_ttl: u64,
    /// Peso de P4 (`invalid_message_deliveries`) en gossipsub (C-NET-43).
    pub p4_peso: f64,
    /// Peso de P7 (`behaviour_penalty`) en gossipsub (C-NET-43).
    pub p7_peso: f64,
    /// Peso de P6 (`ip_colocation_factor`) en gossipsub (C-NET-43).
    pub p6_peso: f64,
    /// Umbral de P6 (DN-06: alto, para no castigar un NAT legítimo).
    pub p6_umbral: f64,
    /// Umbral de gossip (por debajo no se propaga).
    pub gossip_umbral: f64,
    /// Umbral de publicación (por debajo no se publica).
    pub pub_umbral: f64,
    /// Umbral de graylist (por debajo no se procesa).
    pub gray_umbral: f64,
}

impl PerfilRed {
    /// El perfil de una red.
    ///
    /// Hoy es el mismo para las tres: son parámetros de la red dev de 0.0.1 y **ninguno** toca
    /// consenso. La separación por red existe para poder medir y ajustar sin tocar código.
    #[must_use]
    pub const fn de(_red: Red) -> Self {
        Self {
            nuevos: 16_384,
            probados: 4_096,
            cap_ancho: 8,
            cap_estrecho: 1,
            anclas: 2,
            dirs_por_mensaje: 100,
            cuota_tope: 1_000,
            cuota_ventana: Duration::from_secs(3_600),
            t_par: Duration::from_secs(60),
            t_paseo: Duration::from_secs(45),
            t_feeler: Duration::from_secs(20),
            plazo_feeler: Duration::from_secs(5),
            ventana_evict: Duration::from_secs(10),
            omega: 24,
            p4_peso: -100.0,
            p7_peso: -20.0,
            p6_peso: -5.0,
            p6_umbral: 20.0,
            gossip_umbral: -100.0,
            pub_umbral: -200.0,
            gray_umbral: -300.0,
            // ORDEN-RD1c · valores provisionales SOLO para pruebas; `<<PENDIENTE DE MODELO>>`.
            // El registro queda apagado por defecto (G1).
            registro_activo: false,
            registro_v: 3_600,
            registro_pendientes: 64,
            registro_ttl: 7_200,
        }
    }
}

/// Puerto por defecto de mainnet (C-NET-02).
pub const PUERTO_MAINNET: u16 = 9833;

/// Puerto por defecto de testnet (C-NET-02).
pub const PUERTO_TESTNET: u16 = 19833;

/// AG-2c · G1: número de subredes de voto `S`, **constante de las tres redes**.
///
/// El reparto de una clave a su subred es `hash(clave) mod S` (lo hace quien llama, no `zx-p2p`):
/// cambiar `S` mueve a todas las claves. `S = 64`.
pub const SUBREDES_VOTO: u8 = 64;

/// AG-2c · G2: base exacta del tema de subred de mainnet.
pub const BASE_VOTOS_SUB_MAINNET: &str = "/zerox/votos-sub/";
/// AG-2c · G2: base exacta del tema de subred de testnet.
pub const BASE_VOTOS_SUB_TESTNET: &str = "/zerox-testnet/votos-sub/";
/// AG-2c · G2: base exacta del tema de subred de la red dev.
pub const BASE_VOTOS_SUB_DEV: &str = "/zx-dev/votos-sub/";

/// AG-2c · G2: las tres bases, en el orden en que [`crate::servicio::clasificar_tema`] las reconoce.
pub const BASES_VOTO_SUBRED: [&str; 3] = [
    BASE_VOTOS_SUB_MAINNET,
    BASE_VOTOS_SUB_TESTNET,
    BASE_VOTOS_SUB_DEV,
];

/// AG-2c · G2: tema de agregados de mainnet.
pub const TOPIC_AGREGADO_MAINNET: &str = "/zerox/votos-agr/1";
/// AG-2c · G2: tema de agregados de testnet.
pub const TOPIC_AGREGADO_TESTNET: &str = "/zerox-testnet/votos-agr/1";
/// AG-2c · G2: tema de agregados de la red dev.
pub const TOPIC_AGREGADO_DEV: &str = "/zx-dev/votos-agr/1";

/// AG-2c · G2: ¿es `topico` **exactamente** `"<base><s>/1"`, con `s` decimal canónico en `0..S`?
///
/// La igualdad es **exacta**: no se acepta por prefijo ni subcadena. En particular
/// `"<base>64/1"` (fuera de rango), `"<base>07/1"` (cero a la izquierda) y `"<base>7/1x"`
/// (sufijo distinto) devuelven `None`.
#[must_use]
pub(crate) fn subred_de_tema_en_base(base: &str, topico: &str) -> Option<u8> {
    let resto = topico.strip_prefix(base)?;
    let numero = resto.strip_suffix("/1")?;
    // Decimal canónico: ni vacío, ni más de dos dígitos (S <= 99), ni cero a la izquierda.
    if numero.is_empty() || numero.len() > 2 || (numero.len() > 1 && numero.starts_with('0')) {
        return None;
    }
    let mut v: u32 = 0;
    for b in numero.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(b - b'0');
    }
    (v < u32::from(SUBREDES_VOTO)).then_some(v as u8)
}

/// Parámetros de red de una cadena.
///
/// # Los campos son privados, y eso es la garantía (C-NET-15)
///
/// El único constructor es [`ParametrosRed::de`], así que **no existe** la combinación "me
/// identifico como mainnet pero hablo el prefijo de testnet". Con los campos públicos esa
/// combinación se podía escribir con un literal de struct y el compilador la aceptaba sin
/// rechistar.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParametrosRed {
    red: Red,
    puerto: u16,
    topic_pow: &'static str,
    topic_post: &'static str,
    topic_tx: &'static str,
    /// FV-4b-N1 · tema de gossip del certificado/voto de finalidad (bytes opacos).
    topic_votos: &'static str,
    /// AG-2c · G1: número de subredes de voto `S`. Constante de la red (`64` en las tres).
    subredes_voto: u8,
    /// AG-2c · G2: base exacta de los temas de subred de esta red (`/<red>/votos-sub/`).
    base_votos_sub: &'static str,
    /// AG-2c · G2: tema de agregados de esta red (`/<red>/votos-agr/1`).
    topic_agregado: &'static str,
    /// A6-02 · Q1: tema de gossip del **anuncio de prueba** (`/<red>/pruebas/2`).
    topic_pruebas: &'static str,
    protocolo_sync: &'static str,
    protocolo_kad: &'static str,
    protocolo_identify: &'static str,
}

impl ParametrosRed {
    /// La red de estos parámetros.
    #[must_use]
    pub const fn red(&self) -> Red {
        self.red
    }

    /// Prefijo mágico de 4 bytes (C-NET-01).
    ///
    /// ⚠️ Hoy es **metadato**: no está en el wire y no aísla por sí solo.
    #[must_use]
    pub const fn magic(&self) -> [u8; 4] {
        self.red.magic()
    }

    /// Puerto TCP/QUIC por defecto (C-NET-02). En dev es `0` (efímero).
    #[must_use]
    pub const fn puerto(&self) -> u16 {
        self.puerto
    }

    /// Tópico de gossipsub para **bloques PoW completos**.
    #[must_use]
    pub const fn topic_bloques_pow(&self) -> &'static str {
        self.topic_pow
    }

    /// Tópico de gossipsub para **bloques PoST completos**.
    #[must_use]
    pub const fn topic_bloques_post(&self) -> &'static str {
        self.topic_post
    }

    /// Tópico de gossipsub para **transacciones sueltas** (TX-R-01, DR-05): `/zx-<red>/tx/1`.
    ///
    /// El cuerpo es `tx_a_bytes(tx, testigos)` (`zx_core::wire::tx_a_bytes`), sin envoltorio
    /// (TX-R-02). La suscripción y la puntuación de gossipsub lo usan igual que los dos temas de
    /// bloque; el nodo decide el veredicto antes de reenviar (C-NET-12).
    #[must_use]
    pub const fn topic_txs(&self) -> &'static str {
        self.topic_tx
    }

    /// FV-4b-N1 · Tópico de gossipsub para el **voto/certificado de finalidad**.
    ///
    /// El cuerpo son bytes opacos para `zx-p2p`: el sobre `ZXV1` lo codifica y decodifica
    /// `zx-node` con `zx-votos`. Va en su propio tema (decisión 5 de `REVISION-FV4bD.md`, opción A)
    /// para no pasar por la mempool ni pagar tarifa.
    #[must_use]
    pub const fn topic_votos(&self) -> &'static str {
        self.topic_votos
    }

    /// AG-2c · G1: número de subredes de voto `S` de esta red.
    #[must_use]
    pub const fn subredes_voto(&self) -> u8 {
        self.subredes_voto
    }

    /// AG-2c · G2: base exacta de los temas de subred de esta red.
    #[must_use]
    pub const fn base_votos_sub(&self) -> &'static str {
        self.base_votos_sub
    }

    /// AG-2c · G2: tema de agregados de esta red (`/<red>/votos-agr/1`).
    #[must_use]
    pub const fn topic_agregado(&self) -> &'static str {
        self.topic_agregado
    }

    /// A6-02 · Q1: tema de gossip de los **anuncios de prueba** de esta red
    /// (`/<red>/pruebas/2`).
    #[must_use]
    pub const fn topic_pruebas(&self) -> &'static str {
        self.topic_pruebas
    }

    /// AG-2c · G2: tema de la subred `s` (0-based) de esta red: `/<red>/votos-sub/<s>/1`.
    ///
    /// **No valida el rango**: quien llama MUST comprobar `s < S` antes (como hace
    /// [`crate::servicio::ManejoRed::difundir_voto_subred`]); este método solo construye el nombre.
    #[must_use]
    pub fn topic_voto_subred(&self, s: u8) -> String {
        format!("{}{s}/1", self.base_votos_sub)
    }

    /// AG-2c · G2: la subred de un tema **de esta red**, por igualdad exacta, o `None`.
    ///
    /// Un tema de **otra** red con el mismo sufijo no es una subred de esta red.
    #[must_use]
    pub fn subred_del_tema(&self, topico: &str) -> Option<u8> {
        subred_de_tema_en_base(self.base_votos_sub, topico)
    }

    /// AG-2c · G2/G6: ¿es `topico` uno de los **65** temas nuevos de esta red?
    ///
    /// Lo usan la comprobación de difusión (defensa en profundidad) y las pruebas.
    #[must_use]
    pub fn es_tema_de_votos_nuevo(&self, topico: &str) -> bool {
        topico == self.topic_agregado || self.subred_del_tema(topico).is_some()
    }

    /// Protocolo de request-response para sincronización.
    #[must_use]
    pub const fn protocolo_sync(&self) -> &'static str {
        self.protocolo_sync
    }

    /// Protocolo de Kademlia. **Nunca el de IPFS.**
    #[must_use]
    pub const fn protocolo_kad(&self) -> &'static str {
        self.protocolo_kad
    }

    /// Protocolo del handshake `identify`.
    #[must_use]
    pub const fn protocolo_identify(&self) -> &'static str {
        self.protocolo_identify
    }

    /// Los parámetros de una red. Único constructor.
    #[must_use]
    pub const fn de(red: Red) -> Self {
        match red {
            Red::Mainnet => Self {
                red,
                puerto: PUERTO_MAINNET,
                topic_pow: "/zerox/bloques/pow/2",
                topic_post: "/zerox/bloques/post/2",
                topic_tx: "/zerox/tx/2",
                topic_votos: "/zerox/votos/2",
                subredes_voto: SUBREDES_VOTO,
                base_votos_sub: BASE_VOTOS_SUB_MAINNET,
                topic_agregado: TOPIC_AGREGADO_MAINNET,
                topic_pruebas: "/zerox/pruebas/2",
                protocolo_sync: "/zerox/sync/2",
                protocolo_kad: "/zerox/kad/1",
                protocolo_identify: "/zerox/id/1",
            },
            Red::Testnet => Self {
                red,
                puerto: PUERTO_TESTNET,
                topic_pow: "/zerox-testnet/bloques/pow/2",
                topic_post: "/zerox-testnet/bloques/post/2",
                topic_tx: "/zerox-testnet/tx/2",
                topic_votos: "/zerox-testnet/votos/2",
                subredes_voto: SUBREDES_VOTO,
                base_votos_sub: BASE_VOTOS_SUB_TESTNET,
                topic_agregado: TOPIC_AGREGADO_TESTNET,
                topic_pruebas: "/zerox-testnet/pruebas/2",
                protocolo_sync: "/zerox-testnet/sync/2",
                protocolo_kad: "/zerox-testnet/kad/1",
                protocolo_identify: "/zerox/id/1",
            },
            Red::Dev => Self {
                red,
                puerto: 0,
                topic_pow: "/zx-dev/bloques/pow/2",
                topic_post: "/zx-dev/bloques/post/2",
                topic_tx: "/zx-dev/tx/2",
                topic_votos: "/zx-dev/votos/2",
                subredes_voto: SUBREDES_VOTO,
                base_votos_sub: BASE_VOTOS_SUB_DEV,
                topic_agregado: TOPIC_AGREGADO_DEV,
                topic_pruebas: "/zx-dev/pruebas/2",
                protocolo_sync: "/zx-dev/2",
                protocolo_kad: "/zx-dev/kad/1",
                protocolo_identify: "/zx-dev/id/1",
            },
        }
    }

    /// Perfil de **desarrollo** de la red dev de 0.0.1. Sin parámetros libres.
    ///
    /// Todos los valores son solo para desarrollo: puerto `0` (efímero/loopback que el runner
    /// decide), temas y protocolos bajo `/zx-dev/...` y `agent_version` `zerox/<versión>/dev`. No
    /// son parámetros de consenso ni de lanzamiento.
    #[must_use]
    pub const fn dag_dev() -> Self {
        Self::de(Red::Dev)
    }

    /// La cadena de `agent_version` que anuncia `identify`.
    ///
    /// El default de libp2p es `rust-libp2p/<versión>`, que dice qué librería usamos y nada sobre
    /// qué red somos. Lleva la marca ZRX-C ([`crate::zrxc::MARCA_ZRXC`]): en `identify`, un par que
    /// no la anuncie se rechaza (ORDEN-ZC3, pregunta (b)).
    #[must_use]
    pub fn agent_version(&self) -> String {
        format!(
            "zerox/{}/{}{}",
            env!("CARGO_PKG_VERSION"),
            self.red.nombre(),
            crate::zrxc::MARCA_ZRXC
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{PUERTO_MAINNET, PUERTO_TESTNET, ParametrosRed};
    use zx_core::red::Red;

    /// Los prefijos que expone la config son los de la red, no una copia.
    #[test]
    fn los_prefijos_vienen_de_la_red_y_no_de_una_copia() {
        for red in [Red::Mainnet, Red::Testnet, Red::Dev] {
            assert_eq!(ParametrosRed::de(red).magic(), red.magic(), "{red:?}");
        }
    }

    /// Nada se comparte entre mainnet y testnet.
    #[test]
    fn ninguna_red_comparte_nada_con_la_otra() {
        let m = ParametrosRed::de(Red::Mainnet);
        let t = ParametrosRed::de(Red::Testnet);

        assert_ne!(m.magic(), t.magic());
        assert_ne!(m.puerto(), t.puerto());
        assert_ne!(m.topic_bloques_pow(), t.topic_bloques_pow());
        assert_ne!(m.topic_bloques_post(), t.topic_bloques_post());
        assert_ne!(m.topic_txs(), t.topic_txs());
        assert_ne!(m.topic_votos(), t.topic_votos());
        assert_ne!(m.protocolo_sync(), t.protocolo_sync());
        assert_ne!(m.protocolo_kad(), t.protocolo_kad());
        assert_ne!(m.agent_version(), t.agent_version());
    }

    /// **La red dev no comparte nada con las públicas.**
    #[test]
    fn la_red_dev_no_comparte_nada_con_las_publicas() {
        let dev = ParametrosRed::dag_dev();
        assert_eq!(dev.red(), Red::Dev);
        assert_eq!(dev.protocolo_sync(), "/zx-dev/2");

        for red in [Red::Mainnet, Red::Testnet] {
            let p = ParametrosRed::de(red);
            assert_ne!(dev.magic(), p.magic(), "{red:?}");
            assert_ne!(dev.puerto(), p.puerto(), "{red:?}");
            assert_ne!(dev.topic_bloques_pow(), p.topic_bloques_pow(), "{red:?}");
            assert_ne!(dev.topic_bloques_post(), p.topic_bloques_post(), "{red:?}");
            assert_ne!(dev.topic_txs(), p.topic_txs(), "{red:?}");
            assert_ne!(dev.topic_votos(), p.topic_votos(), "{red:?}");
            assert_ne!(dev.protocolo_sync(), p.protocolo_sync(), "{red:?}");
            assert_ne!(dev.protocolo_kad(), p.protocolo_kad(), "{red:?}");
            assert_ne!(dev.protocolo_identify(), p.protocolo_identify(), "{red:?}");
            assert_ne!(dev.agent_version(), p.agent_version(), "{red:?}");
        }
    }

    /// **Mainnet y testnet conservan sus puertos.** Red de seguridad contra un cambio de perfil.
    #[test]
    fn mainnet_y_testnet_conservan_sus_puertos() {
        assert_eq!(ParametrosRed::de(Red::Mainnet).puerto(), PUERTO_MAINNET);
        assert_eq!(ParametrosRed::de(Red::Testnet).puerto(), PUERTO_TESTNET);
    }

    /// **La red dev usa los temas y el protocolo que fija la orden.**
    #[test]
    fn la_red_dev_usa_los_nombres_de_la_orden() {
        let dev = ParametrosRed::dag_dev();
        assert_eq!(dev.topic_bloques_pow(), "/zx-dev/bloques/pow/2");
        assert_eq!(dev.topic_bloques_post(), "/zx-dev/bloques/post/2");
        assert_eq!(dev.topic_txs(), "/zx-dev/tx/2");
        assert_eq!(dev.topic_votos(), "/zx-dev/votos/2");
        assert_eq!(dev.protocolo_sync(), "/zx-dev/2");
        assert_eq!(dev.protocolo_identify(), "/zx-dev/id/1");
        assert_eq!(dev.puerto(), 0);
    }

    /// Cada perfil tiene **cuatro** temas de gossip distintos entre sí y no hay suscripción cruzada.
    #[test]
    fn cada_perfil_tiene_sus_temas_y_no_hay_suscripcion_cruzada() {
        let perfiles = [
            ParametrosRed::de(Red::Mainnet),
            ParametrosRed::de(Red::Testnet),
            ParametrosRed::dag_dev(),
        ];
        for p in perfiles {
            assert_ne!(
                p.topic_bloques_pow(),
                p.topic_bloques_post(),
                "{:?}",
                p.red()
            );
            assert_ne!(p.topic_bloques_pow(), p.topic_txs(), "{:?}", p.red());
            assert_ne!(p.topic_bloques_post(), p.topic_txs(), "{:?}", p.red());
            assert_ne!(p.topic_bloques_pow(), p.topic_votos(), "{:?}", p.red());
            assert_ne!(p.topic_bloques_post(), p.topic_votos(), "{:?}", p.red());
            assert_ne!(p.topic_txs(), p.topic_votos(), "{:?}", p.red());
        }

        let mut todos = Vec::new();
        for p in perfiles {
            todos.push(p.topic_bloques_pow());
            todos.push(p.topic_bloques_post());
            todos.push(p.topic_txs());
            todos.push(p.topic_votos());
        }
        todos.sort_unstable();
        let antes = todos.len();
        todos.dedup();
        assert_eq!(antes, todos.len(), "hay un tema compartido entre perfiles");
    }

    /// **El nombre de Kademlia MUST NOT ser el de IPFS.**
    #[test]
    fn kademlia_nunca_usa_el_protocolo_de_ipfs() {
        for p in [
            ParametrosRed::de(Red::Mainnet),
            ParametrosRed::de(Red::Testnet),
            ParametrosRed::dag_dev(),
        ] {
            assert!(
                p.protocolo_kad().starts_with("/zerox") || p.protocolo_kad().starts_with("/zx-dev"),
                "{:?}: el protocolo de Kademlia MUST ser propio, no {}",
                p.red(),
                p.protocolo_kad()
            );
            assert!(!p.protocolo_kad().contains("ipfs"));
        }
    }

    /// Todos los nombres empiezan por `/` y no acaban en `/`: libp2p lo exige.
    #[test]
    fn los_nombres_de_protocolo_tienen_la_forma_que_libp2p_exige() {
        for p in [
            ParametrosRed::de(Red::Mainnet),
            ParametrosRed::de(Red::Testnet),
            ParametrosRed::dag_dev(),
        ] {
            for nombre in [
                p.topic_bloques_pow(),
                p.topic_bloques_post(),
                p.topic_txs(),
                p.topic_votos(),
                p.protocolo_sync(),
                p.protocolo_kad(),
                p.protocolo_identify(),
            ] {
                assert!(nombre.starts_with('/'), "{nombre} debe empezar por /");
                assert!(!nombre.ends_with('/'), "{nombre} no debe acabar en /");
            }
        }
    }

    /// El `agent_version` dev nombra la red dev y anuncia ZRX-C.
    #[test]
    fn el_agent_version_dev_no_se_hace_pasar_por_publico() {
        let dev = ParametrosRed::dag_dev().agent_version();
        assert!(dev.starts_with("zerox/"), "{dev}");
        assert!(dev.contains("/dev+zrxc"), "{dev}");
        assert!(crate::zrxc::anuncia_zrxc(&dev), "{dev}");
        assert_ne!(dev, ParametrosRed::de(Red::Testnet).agent_version());
    }
}
