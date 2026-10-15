//! Límites explícitos de la capa de red (SPEC §16.3, C-NET-11).
//!
//! # Por qué existe este módulo
//!
//! **La capa de transporte de libp2p no es segura por defecto para una cadena**, y lo peor es que
//! ninguno de sus defectos falla al compilar. Cuatro defaults, verificados contra
//! `rust-libp2p@v0.56.0`:
//!
//! | Límite | Default | Qué provoca en ZEROX |
//! |---|---|---|
//! | `gossipsub::max_transmit_size` | **65 536 B** | Un bloque completo no se propaga |
//! | `gossipsub::validate_messages` | **`false`** | El mensaje se reenvía **antes** de validarlo |
//! | `ConnectionLimits` | todo `None` | Sin límite de conexiones |
//! | Tamaño en `request_response::Codec` | **no existe** | El trait no impone ninguno |
//!
//! Reunirlos aquí, con nombre y con la razón al lado, es lo que impide que alguien "simplifique"
//! uno de ellos más adelante sin saber qué está quitando.
//!
//! # Los límites nuevos de la red dev
//!
//! La orden fija tres: tamaño máximo de [`crate::mensaje::BloqueRed`], hashes por petición (256) y
//! cabeceras por respuesta (2 000). El primero se declara **con valor dev** porque `zx-core` todavía
//! no ha portado `peso.rs`: cuando exista el límite de peso, este valor se derivará de él.

use zx_core::preimage::block::TAMANO_CABECERA;
use zx_core::preimage::dag::TAMANO_CABECERA_MAX;
use zx_core::wire_dag::MAX_JUSTIFICACION_POT_CODIFICADA;

/// Cuerpo máximo de un bloque en la red dev, en bytes.
///
/// **Valor dev declarado.** La orden pide «el límite de peso que ya use `zx-core`, o, si no existe,
/// 2 MiB dev». `peso.rs` no está portado (lo dirá W03+), así que se toma 2 MiB. No es una medición
/// ni una regla de consenso: es una cota de transporte provisional y revisable.
pub const MAX_CUERPO_DEV_BYTES: u64 = 2 * 1024 * 1024;

/// Tamaño máximo de un [`crate::mensaje::BloqueRed`], en bytes.
///
/// Desglose: cabecera PoST máxima ([`TAMANO_CABECERA_MAX`] = 1 709 B, la más grande de las dos
/// familias) **más** la justificación PoT codificada al máximo
/// ([`MAX_JUSTIFICACION_POT_CODIFICADA`] = 19 201 B; `ORDEN-W06d3` decisión 1: `BloqueRed::Post`
/// ahora la lleva, igual que `zx_core::wire_dag::BloqueDag`) **más** el cuerpo máximo dev. Un bloque
/// PoW no tiene justificación y por tanto siempre mide menos que este máximo. No incluye el byte de
/// familia ni el `CompactSize` del contador de transacciones: eso lo añade el códec al comprobar el
/// buffer recibido.
pub const MAX_BLOQUE_RED_BYTES: u64 =
    TAMANO_CABECERA_MAX as u64 + MAX_JUSTIFICACION_POT_CODIFICADA as u64 + MAX_CUERPO_DEV_BYTES;

/// Cuántas veces el límite de bloque dev admite el transporte.
///
/// El transporte **MUST** dejar pasar cualquier bloque que quepa con holgura para la cabecera, los
/// sobres del protocolo y cambios futuros del límite de cuerpo.
pub const FACTOR_MARGEN: u64 = 8;

/// Techo absoluto que ningún `LIMITE(H)` legítimo puede alcanzar: **1 TiB**.
pub const LIMITE_BLOQUE_ABSURDO: u64 = 1 << 40;

/// Techo de gossip derivado del límite de bloque, o `None` si el límite es absurdo.
///
/// # Por qué devuelve `Option` y no satura
///
/// Saturar a `usize::MAX` significaría "sin límite", que es exactamente el fallo que C-NET-11 existe
/// para impedir. Un valor corrupto no debe traducirse en desactivar la defensa; debe traducirse en
/// no arrancar.
#[must_use]
pub const fn limite_gossip(limite_bloque: u64) -> Option<usize> {
    if limite_bloque == 0 || limite_bloque > LIMITE_BLOQUE_ABSURDO {
        return None;
    }
    let bytes = limite_bloque * FACTOR_MARGEN;
    if bytes > usize::MAX as u64 {
        // Solo alcanzable en un objetivo de 32 bits.
        None
    } else {
        Some(bytes as usize)
    }
}

/// Límite de bloque del arranque dev: [`MAX_BLOQUE_RED_BYTES`].
pub const LIMITE_BLOQUE_DEV: u64 = MAX_BLOQUE_RED_BYTES;

/// Tamaño máximo de un mensaje de gossipsub en el arranque dev.
pub const MAX_GOSSIP_BYTES: usize = match limite_gossip(LIMITE_BLOQUE_DEV) {
    Some(v) => v,
    // Inalcanzable: `MAX_BLOQUE_RED_BYTES` es ~2 MiB. Si fallara al compilar, es que alguien ha
    // tocado el límite del cuerpo hasta un valor imposible.
    None => panic!("MAX_BLOQUE_RED_BYTES debe dar un techo de gossip válido"),
};

/// A partir de qué fracción del margen el nodo **se niega a seguir**.
pub const MARGEN_MINIMO: u64 = 2;

/// ¿Puede este nodo seguir sirviendo con el límite de transporte que tiene?
///
/// El límite de gossipsub se fija al construir el behaviour y no cambia en caliente; un nodo que se
/// para diciendo "mi límite de transporte se ha quedado corto" es mejor que uno que deja de ver la
/// mitad de los mensajes sin decirlo.
#[must_use]
pub const fn margen_suficiente(limite_bloque: u64, limite_transporte: usize) -> bool {
    let necesario = limite_bloque.saturating_mul(MARGEN_MINIMO);
    necesario <= limite_transporte as u64
}

/// Tamaño máximo de una **petición** de sincronización, en bytes.
///
/// Una petición es un locator o una lista de hashes: unos pocos KiB como mucho. Que sea pequeño es
/// la primera línea de defensa — no hay razón legítima para una petición grande.
pub const MAX_PETICION_BYTES: u64 = 64 * 1024;

/// Bloques por respuesta de `Bloques`.
pub const MAX_BLOQUES_POR_RESPUESTA: usize = 16;

/// Tamaño máximo de una **respuesta** de sincronización, en bytes.
///
/// Una respuesta carga hasta [`MAX_BLOQUES_POR_RESPUESTA`] bloques completos. Sin cota, un peer
/// puede hacer que reservemos memoria arbitraria **antes** de que el parser rechace nada.
pub const MAX_RESPUESTA_BYTES: u64 =
    MAX_BLOQUES_POR_RESPUESTA as u64 * MAX_BLOQUE_RED_BYTES + 64 * 1024;

/// Cabeceras PoW por respuesta de `CabecerasPow`.
///
/// A 92 bytes por cabecera son ~184 KB por respuesta llena. Bitcoin usa 2000.
pub const MAX_CABECERAS_POR_RESPUESTA: usize = 2_000;

/// Hashes por petición de `Bloques`.
///
/// La orden lo fija en 256. Con 32 B por hash son 8 KiB de cuerpo: la petición sigue siendo diminuta
/// y el receptor sabe de antemano cuánto va a servir.
pub const MAX_HASHES_POR_PETICION: usize = 256;

/// Peers salientes: los que **elegimos** nosotros.
pub const MAX_PEERS_SALIENTES: u32 = 24;

/// Peers entrantes: los que nos eligen a nosotros.
pub const MAX_PEERS_ENTRANTES: u32 = 72;

/// Conexiones establecidas simultáneas, en total.
pub const MAX_CONEXIONES: u32 = MAX_PEERS_SALIENTES + MAX_PEERS_ENTRANTES;

/// Margen transitorio para poder **desalojar** una entrante al llegar al tope (C-NET-42).
///
/// `connection_limits` denegaría la conexión 73 sin dejarla establecerse, y entonces no habría
/// ocasión de elegir víctima: el `Swarm` ya la habría rechazado. Con un hueco de una conexión, la
/// 73.ª se establece, el bucle elige víctima entre las 72 anteriores y la desconecta, de modo que
/// el número vuelve al tope. No es un aumento del cupo: es el espacio para **aplicar** la política.
pub const MARGEN_ACEPTACION_DESALOJO: u32 = 1;

/// Conexiones establecidas con un **mismo** peer.
pub const MAX_CONEXIONES_POR_PEER: u32 = 1;

/// Conexiones entrantes a medio negociar (defensa contra *slowloris*).
pub const MAX_CONEXIONES_PENDIENTES: u32 = 32;

/// Peticiones de sincronización simultáneas que se aceptan de **un mismo peer**.
///
/// El default de `request_response::Config` son **100**. Con respuestas de hasta
/// [`MAX_RESPUESTA_BYTES`], eso serían decenas de gigabytes por peer. Bajarlo a 8 es la mitad de la
/// mitigación; la otra mitad es el presupuesto agregado de [`crate::presupuesto`].
pub const MAX_STREAMS_SYNC: usize = 8;

/// Plazo, en segundos, para que llegue el veredicto de una validación diferida
/// (`ORDEN-W06d2` decisión 1) antes de tratarla como [`crate::entrante::Veredicto::Ignorar`].
///
/// Un bloque PoST real verifica en decenas de milisegundos (PoT + PoAS); 5 s es generoso incluso
/// bajo carga y sigue acotando cuánto tiempo puede quedar un mensaje de gossipsub retenido sin
/// reenviarse ni descartarse.
pub const PLAZO_VALIDACION_DIFERIDA_S: u64 = 5;

// ── RD-1c · registro firmado de direcciones (ZXREG1) ─────────────────────────

/// Direcciones de marcado que caben en una entrada `ZXREG1`.
///
/// Un productor no necesita anunciar más: la entrada ata **una** clave de productor a sus
/// direcciones de marcado, y unas pocas cubren cambio de IP/puerto y NAT. El tope acota la entrada
/// antes de parsear (C-WIRE-04).
pub const MAX_DIRECCIONES_POR_ENTRADA: usize = 8;

/// Tamaño máximo de una `Multiaddr` cruda dentro de una entrada `ZXREG1`.
///
/// Acota la reserva por dirección antes de construirla. 256 B cubre con holgura una dirección con
/// `/dns` y componentes de transporte.
pub const MAX_MULTIADDR_BYTES: usize = 256;

/// Entradas `ZXREG1` que caben en una página de respuesta.
///
/// Una página por petición (contrato §3), con el mismo presupuesto de red que las demás respuestas.
pub const MAX_ENTRADAS_REGISTRO_POR_PAGINA: usize = 16;

/// Longitud de la codificación **mínima** de `v` en `CompactSize`.
const fn tamano_compact_size(v: u64) -> u64 {
    if v < 0xFD {
        1
    } else if v <= u16::MAX as u64 {
        3
    } else if v <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

/// Tamaño máximo del códec de una entrada `ZXREG1`, en bytes.
///
/// Derivado del códec real: `version(1) + red(1) + productor(32) + epoch(8) +
/// CompactSize(n_addr) + n_addr × (CompactSize(len) + len) + firma(64)`, con los topes de
/// [`MAX_DIRECCIONES_POR_ENTRADA`] y [`MAX_MULTIADDR_BYTES`].
pub const MAX_ENTRADA_REGISTRO_BYTES: u64 = 42
    + tamano_compact_size(MAX_DIRECCIONES_POR_ENTRADA as u64)
    + MAX_DIRECCIONES_POR_ENTRADA as u64
        * (tamano_compact_size(MAX_MULTIADDR_BYTES as u64) + MAX_MULTIADDR_BYTES as u64)
    + 64;

/// Cuántas validaciones diferidas puede tener pendientes `zx-p2p` a la vez.
///
/// Acota la memoria de la tabla de pendientes (`ORDEN-W06d2`, disciplina de recursos de `LINEO`):
/// un manejador que difiere sin nunca informar no debe crecer sin límite entre barridos del plazo.
/// Al llegar al tope, la entrada más antigua se expira como `Ignorar` para dejar sitio.
pub const MAX_DIFERIDOS_PENDIENTES: usize = 4_096;

/// A5-c-2a · D4 · A5-c-2a-2: **valor de arranque** del cupo de validaciones diferidas de los dos
/// temas nuevos de AG-2c (voto de red por subred y agregado).
///
/// **El cupo no es una constante**: lo fija el nodo en marcha con
/// [`crate::servicio::ManejoRed::fijar_cupo_diferidos_agregacion`], porque es el único que conoce
/// cuántos agregadores y cuántas subredes hay. Este es el valor con el que arranca el bucle —
/// **valor de arranque; el nodo lo fija con el número de agregadores y de subredes** —: el de la
/// primera ronda (el número de subredes, S = 64, [`crate::config::SUBREDES_VOTO`]), dimensionado a un
/// pendiente por subred.
///
/// **No comparte cupo con los bloques** ([`MAX_DIFERIDOS_PENDIENTES`]): un aluvión de agregados no
/// puede desalojar ni bloquear un bloque pendiente.
pub const CUPO_DIFERIDOS_VOTOS_ARRANQUE: usize = crate::config::SUBREDES_VOTO as usize;

// ── ZRX-C · compresión en la red (ORDEN-ZC3, ZRX-C.md §4) ────────────────────

/// R-9 · por debajo de este tamaño no se comprime: el marco domina.
///
/// ZC-4: el tope se declara una sola vez en `zx-compresion`.
pub const UMBRAL_COMPRESION_BYTES: usize = zx_compresion::UMBRAL_MINIMO_BYTES;

/// R-7 · ratio máximo declarado `original / comprimido`.
///
/// ZC-4: el tope se declara una sola vez en `zx-compresion`.
pub const MAX_RATIO_COMPRESION: u64 = zx_compresion::MAX_RATIO;

/// R-6 · tope de bytes **descomprimidos** de un bloque de red.
///
/// El payload original admite el byte de familia y el `CompactSize` del contador
/// ([`crate::codec::SOBRE_CODEC_BLOQUE`]), además de cabecera + justificación + cuerpo.
pub const MAX_DESCOMPRIMIDO_BLOQUE: u64 = MAX_BLOQUE_RED_BYTES + 1 + 9;

/// R-6 · tope de una petición de sincronización descomprimida.
pub const MAX_DESCOMPRIMIDO_PETICION: u64 = MAX_PETICION_BYTES;

/// R-6 · tope de una respuesta de sincronización descomprimida.
pub const MAX_DESCOMPRIMIDO_RESPUESTA: u64 = MAX_RESPUESTA_BYTES;

/// R-6 · tope de una transacción difundida descomprimida.
pub const MAX_DESCOMPRIMIDO_TX: u64 = MAX_BLOQUE_RED_BYTES;

/// R-6 · tope de un voto/certificado difundido descomprimido (4 KiB).
pub const MAX_DESCOMPRIMIDO_VOTO: u64 = 4 * 1024;

// ── AG-2c · temas nuevos de agregación (G4) ─────────────────────────────────

/// AG-2c · G4: tope de un **voto de red** (A2) descomprimido: **248 B exactos**.
///
/// El voto lleva la clave BLS entera (48 B), no el índice (`ADOPCION-A5.md` corrección 1):
/// `8 + 3·32 + 48 + 96 = 248` (`zx-votos/src/agregacion.rs:47-49`, `LONGITUD_VOTO_RED`).
pub const MAX_DESCOMPRIMIDO_VOTO_RED: u64 = 248;

/// AG-2c · G4: tope de un **agregado de subred** (A3) descomprimido.
///
/// `332 + 65 536 / 8 = 8 524 B`: la parte fija más el mapa de una subred que tuviera **todas** las
/// claves de la tabla (`N = 65 536`), porque elegir la subred de una clave cuesta 64 intentos y
/// nadie garantiza subredes parejas. La parte fija de `332 B` es `LONGITUD_FIJA_AGREGADO`
/// (`zx-votos/src/agregacion.rs:51-53`).
pub const MAX_DESCOMPRIMIDO_AGREGADO: u64 = 332 + (65_536 >> 3);

// ── A6-02 · carril de pruebas en red (CP-C3, CP-R-04/05) ────────────────────

/// A6-02 · `CP-R-04`: tope de la prueba **comprimida**, en bytes.
///
/// **Gemela** de `crates/zx-pruebas/src/limites.rs::MAX_PRUEBA_COMPRIMIDA_BYTES`: el tope se repite
/// aquí porque `zx-p2p` no puede depender de `zx-pruebas` (lo comprueba `ci/frontera-crates.sh`; la
/// orden Q6 prohíbe tocar el guardián). Es el tope del **payload** del marco ZRX-C, no del marco
/// completo: la cabecera `ZXC1` ([`zx_compresion::CABECERA`], 35 B) no cuenta.
pub const MAX_PRUEBA_COMPRIMIDA_BYTES: u64 = 352_000;

/// A6-02 · `CP-R-05`: tope de la prueba **canónica descomprimida**, en bytes.
///
/// **Gemela** de `crates/zx-pruebas/src/limites.rs::MAX_PRUEBA_CANONICA_BYTES`. En este paso el
/// cuerpo es opaco para `zx-p2p` (no se descomprime aquí), pero la orden Q6 manda declarar el tope
/// junto a su gemela.
pub const MAX_PRUEBA_CANONICA_BYTES: u64 = 400_000;

/// A6-02 · Q3: tope de los `bytes` de `Respuesta::Prueba`, en bytes.
///
/// Es la prueba comprimida (payload) más la cabecera del marco ZRX-C:
/// `352 000 + 35 = 352 035` (`zx_compresion::CABECERA`, `crates/zx-compresion/src/marco.rs:46`).
/// Una respuesta que lo supere, o con una huella distinta de la pedida, se rechaza y penaliza.
pub const MAX_RESPUESTA_PRUEBA_BYTES: u64 =
    MAX_PRUEBA_COMPRIMIDA_BYTES + zx_compresion::CABECERA as u64;

// ── Coherencia de los límites ────────────────────────────────────────────────
// Aserciones de compilación y no tests: una relación entre constantes no se puede saltar con
// `--skip`, y un cambio que rompa la coherencia MUST impedir compilar.

// El techo de gossip cubre el bloque máximo completo.
const _: () = assert!(
    MAX_GOSSIP_BYTES as u64 >= MAX_BLOQUE_RED_BYTES,
    "C-NET-11: el techo de gossip debe admitir un bloque completo"
);

// El techo de gossip supera el default de libp2p, o no estaríamos arreglando nada.
const _: () = assert!(
    MAX_GOSSIP_BYTES > 65_536,
    "C-NET-11: el default de libp2p es 65536 y es demasiado pequeño"
);

// El margen del arranque dev MUST ser suficiente, o el nodo no arrancaría nunca.
const _: () = assert!(margen_suficiente(LIMITE_BLOQUE_DEV, MAX_GOSSIP_BYTES));

// Una respuesta de sincronización carga varios bloques: MUST ser mayor que un mensaje suelto.
const _: () = assert!(MAX_RESPUESTA_BYTES > MAX_GOSSIP_BYTES as u64);

// Una petición es un locator, no un lote: MUST ser mucho menor que una respuesta.
const _: () = assert!(MAX_PETICION_BYTES * 100 < MAX_RESPUESTA_BYTES);

// Un lote lleno de cabeceras PoW cabe en una respuesta.
const _: () = assert!(
    (MAX_CABECERAS_POR_RESPUESTA * TAMANO_CABECERA) as u64 <= MAX_RESPUESTA_BYTES,
    "un lote de cabeceras al máximo MUST caber en una respuesta"
);

// Un lote lleno de hashes cabe en una petición (32 B por hash + discriminante + CompactSize).
const _: () = assert!(
    1 + 9 + (MAX_HASHES_POR_PETICION * 32) as u64 <= MAX_PETICION_BYTES,
    "una petición con el máximo de hashes MUST caber en MAX_PETICION_BYTES"
);

// ZRX-C (ORDEN-ZC3): cada tope de descompresión cubre su forma cruda.
const _: () = assert!(MAX_DESCOMPRIMIDO_BLOQUE >= MAX_BLOQUE_RED_BYTES);
const _: () = assert!(MAX_DESCOMPRIMIDO_PETICION >= MAX_PETICION_BYTES);
const _: () = assert!(MAX_DESCOMPRIMIDO_RESPUESTA >= MAX_RESPUESTA_BYTES);
const _: () = assert!(MAX_DESCOMPRIMIDO_TX >= MAX_CUERPO_DEV_BYTES);
const _: () = assert!(MAX_DESCOMPRIMIDO_VOTO >= 1024);
// AG-2c (G4): los dos topes nuevos, con su valor exacto.
const _: () = assert!(MAX_DESCOMPRIMIDO_VOTO_RED == 248);
const _: () = assert!(MAX_DESCOMPRIMIDO_AGREGADO == 332 + (65_536 >> 3));
const _: () = assert!(MAX_DESCOMPRIMIDO_AGREGADO == 8_524);
const _: () = assert!(MAX_RATIO_COMPRESION >= 100);

// A6-02 (Q3): la cuenta exacta del tope de la respuesta de prueba y su encaje en el de sync.
const _: () = assert!(MAX_RESPUESTA_PRUEBA_BYTES == 352_035);
const _: () = assert!(
    MAX_RESPUESTA_PRUEBA_BYTES <= MAX_RESPUESTA_BYTES,
    "una respuesta de prueba entera MUST caber en MAX_RESPUESTA_BYTES"
);

// RD-1c: una página llena de entradas `ZXREG1` MUST caber en una respuesta de sync.
const _: () = assert!(
    MAX_ENTRADAS_REGISTRO_POR_PAGINA as u64 * MAX_ENTRADA_REGISTRO_BYTES <= MAX_RESPUESTA_BYTES,
    "una página llena del registro MUST caber en MAX_RESPUESTA_BYTES"
);

// Coherencia de los límites de conexión.
const _: () = assert!(MAX_CONEXIONES == MAX_PEERS_SALIENTES + MAX_PEERS_ENTRANTES);
const _: () = assert!(
    MAX_PEERS_ENTRANTES > MAX_PEERS_SALIENTES,
    "trade-off asumido: aceptamos más peers de los que elegimos"
);
const _: () = assert!(MAX_PEERS_SALIENTES > 0 && MAX_CONEXIONES_POR_PEER == 1);

#[cfg(test)]
#[expect(
    clippy::integer_division,
    reason = "aritmética entera deliberada: modelar el crecimiento con enteros evita floats"
)]
mod tests {
    use super::{
        FACTOR_MARGEN, LIMITE_BLOQUE_ABSURDO, LIMITE_BLOQUE_DEV, MARGEN_MINIMO,
        MAX_BLOQUE_RED_BYTES, MAX_CABECERAS_POR_RESPUESTA, MAX_CUERPO_DEV_BYTES, MAX_GOSSIP_BYTES,
        MAX_HASHES_POR_PETICION, MAX_PETICION_BYTES, MAX_RESPUESTA_BYTES, limite_gossip,
        margen_suficiente,
    };
    use zx_core::preimage::block::TAMANO_CABECERA;
    use zx_core::preimage::dag::TAMANO_CABECERA_MAX;
    use zx_core::wire_dag::MAX_JUSTIFICACION_POT_CODIFICADA;

    /// El límite de `BloqueRed` se **deriva** de la cabecera PoST máxima, la justificación PoT
    /// codificada al máximo y el cuerpo dev declarado (`ORDEN-W06d3` decisión 1).
    #[test]
    fn el_limite_de_bloque_red_se_deriva() {
        assert_eq!(TAMANO_CABECERA_MAX, 1_709, "la cabecera PoST máxima");
        assert_eq!(MAX_JUSTIFICACION_POT_CODIFICADA, 19_201);
        assert_eq!(MAX_CUERPO_DEV_BYTES, 2 * 1024 * 1024);
        assert_eq!(
            MAX_BLOQUE_RED_BYTES,
            1_709 + 19_201 + 2 * 1024 * 1024,
            "cabecera + justificación PoT + cuerpo"
        );
        assert_eq!(LIMITE_BLOQUE_DEV, MAX_BLOQUE_RED_BYTES);
    }

    /// **C-NET-13.** Cuando el margen se agota, el nodo debe **negarse**, no seguir a medias.
    #[test]
    fn sin_margen_suficiente_se_detecta() {
        let techo = MAX_GOSSIP_BYTES;

        let borde = techo as u64 / MARGEN_MINIMO;
        assert!(margen_suficiente(borde, techo), "el borde exacto vale");
        assert!(
            !margen_suficiente(borde + 1, techo),
            "un byte más allá del borde MUST detectarse"
        );

        assert!(!margen_suficiente(u64::MAX, techo));
        assert_eq!(
            limite_gossip(u64::MAX),
            None,
            "absurdo ⇒ sin techo, no techo infinito"
        );
        assert_eq!(limite_gossip(LIMITE_BLOQUE_ABSURDO + 1), None);
        assert_eq!(
            limite_gossip(0),
            None,
            "un límite de cero también es absurdo"
        );
        assert!(limite_gossip(LIMITE_BLOQUE_ABSURDO).is_some());
    }

    /// El techo de gossip cubre el bloque máximo con el margen pactado.
    #[test]
    fn el_limite_de_gossip_admite_bloques_reales() {
        assert_eq!(
            MAX_GOSSIP_BYTES as u64,
            MAX_BLOQUE_RED_BYTES * FACTOR_MARGEN
        );
        assert!(MAX_GOSSIP_BYTES as u64 >= MAX_BLOQUE_RED_BYTES);
    }

    /// Un lote lleno de cabeceras cabe en la respuesta.
    #[test]
    fn un_lote_lleno_de_cabeceras_cabe_en_una_respuesta() {
        let lote = (MAX_CABECERAS_POR_RESPUESTA * TAMANO_CABECERA) as u64;
        assert!(lote <= MAX_RESPUESTA_BYTES);
    }

    /// Un lote lleno de hashes cabe en la petición.
    #[test]
    fn un_lote_lleno_de_hashes_cabe_en_una_peticion() {
        let lote = 1 + 9 + (MAX_HASHES_POR_PETICION * 32) as u64;
        assert!(lote <= MAX_PETICION_BYTES, "{lote} B");
        assert_eq!(MAX_HASHES_POR_PETICION, 256);
    }

    /// Un lote lleno de bloques al máximo cabe en una respuesta.
    #[test]
    fn un_lote_lleno_de_bloques_cabe_en_una_respuesta() {
        let lote = super::MAX_BLOQUES_POR_RESPUESTA as u64 * MAX_BLOQUE_RED_BYTES;
        assert!(lote <= MAX_RESPUESTA_BYTES);
    }
}
