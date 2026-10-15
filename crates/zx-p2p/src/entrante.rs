//! El trait que rompe el ciclo red↔consenso.
//!
//! # El problema
//!
//! La red necesita **validar** lo que recibe, y validar es consenso. El sincronizador necesita
//! **pedir** bloques, y pedir es red. Se necesitan en las dos direcciones, y un ciclo de
//! dependencias entre crates no compila.
//!
//! # La solución, y por qué esta y no otra
//!
//! `zx-p2p` **define** este trait y **no lo implementa**. Lo implementa `zx-node`, que es el único
//! crate que ve la red y el consenso a la vez. Así el ciclo se rompe donde debe romperse, y el
//! `Cargo.toml` de este crate no menciona `zx-consensus` — lo comprueba `ci/frontera-crates.sh`.
//!
//! # Los veredictos son cuatro, no tres (`ORDEN-W06d2`)
//!
//! Un bloque cuyo padre todavía no conocemos **no es un bloque inválido**: es un bloque que llegó
//! antes de tiempo. Distinguirlo importa: en gossipsub es literalmente la diferencia entre
//! `MessageAcceptance::Ignore` y `::Reject` — solo el segundo aplica la penalización. Castigar a
//! quien nos adelanta un bloque penaliza a peers honestos con otro *timing*.
//!
//! # Por qué existe [`Veredicto::Diferir`]
//!
//! Un bloque PoST real tarda del orden de decenas de milisegundos en verificarse (PoT + PoAS). Si
//! [`ManejadorEntrante::bloque_difundido`] se queda ahí dentro, el bucle de `zx-p2p` — que también
//! pollea el `Swarm` — deja de hacerlo mientras tanto, y la red entera se para. `Diferir` deja que
//! el manejador conteste **de inmediato** "todavía no lo sé" y siga la validación de verdad en su
//! propio hilo; cuando termine, informa el veredicto final con
//! [`crate::servicio::ManejoRed::informar_validacion`] (o su variante bloqueante para un hilo que no
//! es `tokio`), usando el mismo [`IdDiferido`] que recibió aquí. `zx-p2p` retiene el mensaje de
//! gossipsub entre tanto (`report_message_validation_result` no se llama hasta entonces) y, si el
//! informe no llega dentro de un plazo declarado, lo trata como `Ignorar` — nunca como `Rechazar`:
//! un manejador lento o caído no es un peer culpable.

use libp2p::PeerId;
use zx_core::digest::BlockHash;
use zx_core::preimage::block::BlockHeader;

use crate::mensaje::{BloqueRed, Estado};

/// Identificador opaco de una validación diferida.
///
/// Lo asigna `zx-p2p` **antes** de llamar a [`ManejadorEntrante::bloque_difundido`] y no significa
/// nada fuera del crate: el manejador solo lo guarda y lo devuelve tal cual con
/// [`crate::servicio::ManejoRed::informar_validacion`]. El campo es `pub(crate)` para que los tests
/// de este crate puedan construirlo directamente; fuera de aquí es opaco (no hay forma pública de
/// leer su valor). `Default` existe **solo** para que un manejador de otro crate pueda escribir un
/// test unitario de su propio `bloque_difundido` sin depender de un `Swarm` real; el valor que
/// produce no tiene ningún significado de protocolo y nunca coincide con uno de producción salvo
/// por casualidad de conteo.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct IdDiferido(pub(crate) u64);

/// Qué hacer con algo que llegó por difusión.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Veredicto {
    /// Válido. Se retransmite a la malla.
    Aceptar,
    /// **No se puede juzgar todavía** — típicamente, un bloque cuyo padre no conocemos, o algo que
    /// ya teníamos. Se descarta **sin penalizar**.
    Ignorar,
    /// Inválido de forma demostrable. Se descarta **y** se penaliza al que lo propagó.
    Rechazar,
    /// **Todavía no se sabe.** La validación de verdad sigue en otro hilo; el resultado llegará
    /// después por [`crate::servicio::ManejoRed::informar_validacion`] con el mismo [`IdDiferido`]
    /// que trajo la llamada a [`ManejadorEntrante::bloque_difundido`]. `zx-p2p` retiene el mensaje.
    Diferir,
}

/// El veredicto final de una validación que se difirió. No incluye `Diferir`: una validación
/// diferida no puede volver a diferirse indefinidamente sin que alguien acabe decidiendo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VeredictoFinal {
    /// Válido. Se retransmite a la malla.
    Aceptar,
    /// No juzgable (p. ej. quedó huérfano, o llegó duplicado mientras se validaba). No penaliza.
    Ignorar,
    /// Inválido de forma demostrable. Penaliza a quien lo propagó.
    Rechazar,
}

/// Lo que `zx-p2p` necesita del resto del nodo.
///
/// Implementarlo es trabajo de `zx-node`. Cada método debe ser **rápido y no bloqueante**: se
/// llaman desde el bucle de eventos, y mientras uno corre el `Swarm` no se pollea — o sea, la red
/// entera está parada. Lo que tarde debe delegarse a otra tarea y devolver [`Veredicto::Diferir`].
pub trait ManejadorEntrante: Send + Sync + 'static {
    /// Nuestro estado, para responder a un saludo.
    fn estado(&self) -> Estado;

    /// Un bloque llegó por difusión. **Se valida antes de retransmitir.**
    ///
    /// `id` es el identificador opaco a devolver más tarde si el veredicto es
    /// [`Veredicto::Diferir`]. El default de este trait no existe: cada implementación decide. El
    /// veredicto es del manejador, no del códec.
    fn bloque_difundido(&self, id: IdDiferido, bloque: &BloqueRed) -> Veredicto;

    /// Una transacción llegó por difusión (`ORDEN-TX3`, TX-R-01…TX-R-10).
    ///
    /// `peer` es el propagador (`propagation_source` de gossipsub): la mempool de `zx-node` lo
    /// necesita para los topes **por par** de TX-R-21 (16 MiB) y TX-R-22 (1 MiB/s). El veredicto lo
    /// decide el nodo con la transacción ya decodificada y sin resto (TX-R-02/04); este crate no
    /// reenvía nada antes de ese veredicto (C-NET-12). `Diferir` no tiene sentido aquí (no hay
    /// [`IdDiferido`] que devolver) y el bucle lo trata como `Ignorar`.
    fn tx_difundida(&self, peer: PeerId, tx_serializada: &[u8]) -> Veredicto;

    /// FV-4b-N1 · un **sobre de voto/certificado de finalidad** llegó por difusión (tema
    /// `/zx-<red>/votos/1`).
    ///
    /// El cuerpo son **bytes opacos**: `zx-p2p` no los decodifica; los interpreta `zx-node` con
    /// `zx-votos` (`voto_difundida`). Tiene implementación por defecto (`Ignorar`) para no romper
    /// los manejadores de test que no cablean votos.
    fn voto_difundida(&self, _peer: PeerId, _bytes: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    /// AG-2c · G5 · A5-c-2a: un **voto de red** de la subred `subred` llegó por difusión en el tema
    /// `/<red>/votos-sub/<subred>/1`.
    ///
    /// `bytes` son los `248 B` del voto A2, **opacos** para `zx-p2p`; los interpreta `zx-node` con
    /// `zx-votos`. `subred` es la que declara el tema (0-based, ya clasificada por igualdad exacta),
    /// y `peer` es el propagador.
    ///
    /// Como [`Self::bloque_difundido`], recibe un [`IdDiferido`] y puede contestar
    /// [`Veredicto::Diferir`]: `zx-p2p` **retiene** el mensaje y no lo reenvía hasta que el nodo
    /// llame a [`crate::servicio::ManejoRed::informar_validacion`] con ese identificador
    /// (`Aceptar` reenvía; `Ignorar` suelta sin penalizar; `Rechazar` suelta y penaliza al
    /// propagador). Un diferido que nadie resuelve vence y se trata como `Ignorar`. Los veredictos
    /// inmediatos siguen valiendo igual.
    ///
    /// Tiene **implementación por defecto** (`Ignorar`, sin reenviar y sin penalizar) para que los
    /// manejadores existentes —de test y de `zx-node`— sigan compilando sin cambios: el paso (c)
    /// será quien la cablee.
    fn voto_subred_difundida(
        &self,
        _id: IdDiferido,
        _subred: u8,
        _bytes: &[u8],
        _peer: PeerId,
    ) -> Veredicto {
        Veredicto::Ignorar
    }

    /// AG-2c · G5 · A5-c-2a: un **agregado de subred** A3 llegó por difusión en el tema
    /// `/<red>/votos-agr/1`.
    ///
    /// `bytes` son los `332 + ⌈n_s/8⌉ B` del agregado, **opacos** para `zx-p2p`; los interpreta
    /// `zx-node` con `zx-votos`. Igual que [`Self::voto_subred_difundida`], recibe un
    /// [`IdDiferido`] y puede diferir el veredicto.
    ///
    /// Tiene **implementación por defecto** (`Ignorar`) por el mismo motivo que
    /// [`Self::voto_subred_difundida`].
    fn agregado_difundido(&self, _id: IdDiferido, _bytes: &[u8], _peer: PeerId) -> Veredicto {
        Veredicto::Ignorar
    }

    /// A6-02 · Q4: un **anuncio de prueba** ya comprobado (forma y firma) llegó por el tema
    /// `/<red>/pruebas/2`. `peer` es el propagador y `anuncio` el mensaje ya validado por `zx-p2p`
    /// (Q2); `zx-p2p` nunca llama aquí con un anuncio de forma o firma inválidas.
    ///
    /// Tiene **implementación por defecto** (`Ignorar`: no se reenvía, no se penaliza) para que los
    /// manejadores existentes —de test y de `zx-node`— sigan compilando sin cambios: el nodo se
    /// conecta y decide en el paso CP-C4.
    fn anuncio_prueba(&self, _peer: PeerId, _anuncio: &crate::mensaje::AnuncioPrueba) -> Veredicto {
        Veredicto::Ignorar
    }

    /// A6-02 · Q4: sirve el **cuerpo** de una prueba por su huella.
    ///
    /// Devuelve el marco ZRX-C completo de la prueba (opaco para `zx-p2p`, con su tope de
    /// [`crate::limites::MAX_RESPUESTA_PRUEBA_BYTES`]), o `None` para responder
    /// [`crate::mensaje::Respuesta::NoDisponible`], que **no** penaliza. Tiene implementación por
    /// defecto («no la tengo») por el mismo motivo que [`Self::anuncio_prueba`].
    fn servir_prueba(&self, _huella: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }

    /// Un peer pide cabeceras PoW desde el primer hash de su locator que reconozcamos.
    ///
    /// Devolver un vector vacío es una respuesta legítima: significa "no reconozco nada de tu
    /// locator", y quien lo recibe debe entenderlo como que no compartimos historia.
    fn cabeceras_desde(&self, locator: &[BlockHash], hasta: Option<BlockHash>) -> Vec<BlockHeader>;

    /// Un peer pide cuerpos de bloque (PoW o PoST). Los que no tengamos simplemente no van en la
    /// respuesta.
    fn bloques_por_hash(&self, hashes: &[BlockHash]) -> Vec<BloqueRed>;

    /// `ORDEN-W06d6` decisión 1: una página del registro de admisión propio, empezando en el
    /// índice `desde`. Devuelve los bloques de la página (como mucho
    /// [`crate::limites::MAX_BLOQUES_POR_RESPUESTA`], acotados también en
    /// [`crate::limites::MAX_RESPUESTA_BYTES`]) y la longitud **total** del registro propio.
    ///
    /// Con implementación por defecto (vacía, longitud 0) para no romper los manejadores de test
    /// que no la necesitan (`Espia`, `Contador`, `Diferidor`...); `zx-node::red::manejador::ManejadorRed`
    /// la sobrescribe con la real.
    fn pagina_registro(&self, _desde: u64) -> (Vec<BloqueRed>, u64) {
        (Vec::new(), 0)
    }

    /// `ORDEN-RD3c` (N2): una página del **registro firmado de direcciones** propio (`ZXREG1`),
    /// empezando en el índice `desde`. Devuelve las entradas de la página (como mucho
    /// [`crate::limites::MAX_ENTRADAS_REGISTRO_POR_PAGINA`], acotadas también en bytes) y la
    /// longitud **total** del registro.
    ///
    /// El registro **apagado por defecto** devuelve una página vacía con longitud 0 (N1). Tiene
    /// implementación por defecto para no romper los manejadores de test que no la necesitan; el
    /// `ManejadorRed` de `zx-node` la sobrescribe con la real.
    fn pagina_registro_direcciones(
        &self,
        _desde: u64,
    ) -> (Vec<crate::registro::EntradaRegistro>, u64) {
        (Vec::new(), 0)
    }

    /// El bucle de red acaba de penalizar a un par por difundir un bloque
    /// **demostrablemente inválido** (`Veredicto::Rechazar`) — `ORDEN-W06d10` decisión 1.
    ///
    /// El bucle ya desconectó al par y le aplicó la puntuación que corresponda (prefijo de red, o
    /// `PeerId` si es una dirección **loopback**: excepción de la red local, ver
    /// [`crate::limites_ip::LimitesPorIp::penalizar_peer`]). Este callback es el aviso al nodo para
    /// que deje la constancia estructurada (`par_penalizado`, `par`/`motivo`/`accion`, según
    /// `P-ZRX/P-MEDICION/ESQUEMA-REGISTRO-v1.md`); `motivo` y `accion` los fija `zx-p2p`.
    ///
    /// **Nunca se llama con `Aceptar` ni con `Ignorar`.** Tiene implementación por defecto (no hace
    /// nada) para que los manejadores de test que no observan el registro (`Espia`, `Contador`,
    /// `Diferidor`…) sigan compilando sin cambios.
    fn par_penalizado(&self, _peer: PeerId, _motivo: &str, _accion: &str) {}
}
