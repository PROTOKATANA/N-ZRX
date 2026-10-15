//! Tipos de dominio de una transacción (SPEC §5).
//!
//! Estos structs **no** saben serializarse a wire: eso es Cap'n Proto, en otro crate, y no es
//! consensus-critical (C-ENC-08). Lo único que saben es escribirse en la preimagen canónica, y solo
//! a través de [`crate::preimage`].

use crate::amount::Amount;
use crate::digest::TxId;
use crate::error::EncodingError;
use crate::firma::ClavePublica;
use crate::preimage::dag::DagBlockHeader;

/// Máximo de claves en un `MultiSig` (C-TX-11).
pub const MAX_MULTISIG_KEYS: usize = 16;

/// Longitud de un hash (32 B), para los campos de la extensión v6 de FV-4b-N2.
const LONGITUD_HASH: usize = 32;

/// Referencia a una salida concreta de una transacción anterior.
///
/// Deriva `Hash` porque es la clave natural del UTXO set. La igualdad es la de sus dos campos, así
/// que dos referencias a la misma salida son la misma clave — que es exactamente lo que C-TX-16 y
/// C-BLK-09 necesitan detectar.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct OutPoint {
    /// Transacción que creó la salida.
    pub prev_txid: TxId,
    /// Índice de la salida dentro de esa transacción.
    pub prev_index: u32,
}

/// Entrada de una transacción (§5.2).
///
/// **La firma no está aquí.** Es dato de autorización y vive en el testigo (§4.4). Que el txid no
/// la incluya es lo que lo hace no maleable (C-TX-01).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxIn {
    /// Salida que se consume.
    pub outpoint: OutPoint,
    /// Campo `sequence`.
    pub sequence: u32,
}

/// Condición de gasto de una salida (C-TX-09).
///
/// Enum **cerrado**. No hay lenguaje de script en v1.0, y ese es el punto: un conjunto cerrado de
/// tipos tiene una superficie de ataque acotada y enumerable. La puerta a futuras extensiones es el
/// campo `version` de la transacción, no un intérprete.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Lock {
    /// Gastable con la firma de esta clave.
    ///
    /// **P2K, no P2KH** (P-020): la salida guarda la clave Ed25519 en claro, no su hash. Como
    /// `SHA3-256` produce 32 bytes y una clave Ed25519 mide **exactamente** 32 bytes, hashear no
    /// ahorraba un solo byte aquí y costaba 32 bytes por entrada en el testigo.
    PubKey {
        /// La clave pública Ed25519, 32 bytes.
        pubkey: ClavePublica,
    },
    /// Gastable con `k` firmas de `k` claves distintas del conjunto.
    MultiSig {
        /// Umbral de firmas necesarias.
        k: u8,
        /// Las claves admitidas, en claro (P2K, ver [`Lock::PubKey`]).
        pubkeys: Vec<ClavePublica>,
    },
    /// Hash Time-Locked Contract.
    ///
    /// Gastable por *(a)* preimagen `p` con `SHA3-256(p) = hash` **y** firma de `receiver`; o
    /// *(b)* altura de bloque `≥ timeout` **y** firma de `sender`.
    ///
    /// Es el gancho para canales de pago: junto con `MultiSig` y `lock_time` basta para construir
    /// canales unidireccionales.
    Htlc {
        /// `SHA3-256(preimagen)`.
        hash: [u8; 32],
        /// Clave de quien puede gastar presentando la preimagen.
        receiver: ClavePublica,
        /// Clave de quien recupera los fondos pasado el `timeout`.
        sender: ClavePublica,
        /// Altura a partir de la cual `sender` puede recuperar.
        timeout: u32,
    },
}

/// Discriminantes de [`Lock`] (C-TX-09). Son consenso: no se reordenan jamás.
impl Lock {
    /// Discriminante de `PubKey`.
    pub const DISC_PUBKEY: u8 = 0x00;
    /// Discriminante de `MultiSig`.
    pub const DISC_MULTISIG: u8 = 0x01;
    /// Discriminante de `Htlc`.
    pub const DISC_HTLC: u8 = 0x02;

    /// El byte discriminante de esta variante.
    #[must_use]
    pub const fn discriminante(&self) -> u8 {
        match self {
            Self::PubKey { .. } => Self::DISC_PUBKEY,
            Self::MultiSig { .. } => Self::DISC_MULTISIG,
            Self::Htlc { .. } => Self::DISC_HTLC,
        }
    }

    /// Construye un `MultiSig` validando C-TX-11.
    ///
    /// # Errores
    /// [`EncodingError::MultiSigInvalido`] si `k` está fuera de `1..=n`, si `n > MAX_MULTISIG_KEYS`,
    /// o si hay claves repetidas.
    pub fn multisig(k: u8, pubkeys: Vec<ClavePublica>) -> Result<Self, EncodingError> {
        let n = pubkeys.len();
        let fallo = |motivo| EncodingError::MultiSigInvalido { k, n, motivo };

        if n == 0 || n > MAX_MULTISIG_KEYS {
            return Err(fallo("n debe estar en 1..=MAX_MULTISIG_KEYS"));
        }
        if k == 0 || usize::from(k) > n {
            return Err(fallo("k debe estar en 1..=n"));
        }
        // C-TX-11: las claves MUST ser distintas entre sí. Con n ≤ 16 la comparación cuadrática es
        // más barata y más simple de auditar que ordenar.
        let mut vistas: Vec<&ClavePublica> = Vec::with_capacity(n);
        for h in &pubkeys {
            if vistas.contains(&h) {
                return Err(fallo("las claves deben ser distintas"));
            }
            vistas.push(h);
        }
        Ok(Self::MultiSig { k, pubkeys })
    }
}

/// Salida de una transacción (§5.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    /// Importe, en brek.
    pub value: Amount,
    /// Condición de gasto.
    pub lock: Lock,
}

/// Tipo de operación de garantía (F-07, `C-BON-02/05/06`).
///
/// Los valores son consenso: no se reordenan. El `u8` del wire es el discriminante.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum TipoGarantia {
    /// Depósito: entradas ≥ 1, salidas ≥ 0 (cambio). `Σ entradas = Σ salidas + importe`.
    Deposito = 1,
    /// Retiro: sin entradas ni salidas; mueve `importe` de activo a en retirada.
    Retiro = 2,
    /// Liberación: sin entradas ni salidas; crea la salida implícita por `importe`.
    Liberacion = 3,
}

impl TipoGarantia {
    /// El byte de wire (F-07).
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Decodifica el byte de wire (F-07). Conjunto **cerrado**: otro valor se rechaza.
    #[must_use]
    pub const fn desde_byte(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Deposito),
            2 => Some(Self::Retiro),
            3 => Some(Self::Liberacion),
            _ => None,
        }
    }
}

/// Campos de efecto extra por versión (F-05, F-06, F-07, F-06/SL-4a).
///
/// Es el «gancho de extensión» de `C-TX-07`. La coherencia con `version` es obligatoria:
/// `1 ⇔ Ninguna`, `2 ⇔ Garantia`, `3 ⇔ CoinbasePost`, `4 ⇔ Evidencia`; `validar_forma_tx` la exige
/// (para la v4, `validar_forma_tx_v4`, que el motor invoca cuando el perfil activa la evidencia).
#[derive(Clone, PartialEq, Eq, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "EV-01/EV-02: la v4 transporta dos cabeceras PoAS_PoT_DAG completas (hasta 1 037 B \
              cada una); boxearlas complicaría el wire, la preimagen y el undo sin beneficio"
)]
pub enum ExtensionTx {
    /// Versión 1: sin campos extra (idéntica a `9681061`).
    Ninguna,
    /// Versión 2: operación de garantía (F-07), con el nonce por clave de F-15.
    Garantia {
        /// Operación.
        tipo: TipoGarantia,
        /// Clave a la que se acredita / de la que se retira / a la que se libera.
        clave: ClavePublica,
        /// Importe de la operación. `> 0` y `≤ ZX_VALUE_SANITY_LIMIT`.
        importe: Amount,
        /// Nonce por clave de garantía (F-15): debe ser `nonce_siguiente[clave]` al aplicarse.
        nonce: u64,
    },
    /// Versión 3: coinbase PoST (F-09). `clave` MUST ser `sol.public_key` de su cabecera y `slot`
    /// MUST ser el slot del bloque (F-17); ambas cosas las comprueba la máquina de estados.
    CoinbasePost {
        /// Clave pagada.
        clave: ClavePublica,
        /// Importe de la coinbase.
        importe: Amount,
        /// Slot del bloque que la contiene (F-17).
        slot: u64,
    },
    /// Versión 4 · `EvidenceTx` (EV-01…EV-04): **exactamente dos** cabeceras `PoAS_PoT_DAG`
    /// completas, con su sello, en orden canónico `pre_hash(h1) < pre_hash(h2)`.
    ///
    /// No lleva entradas, ni salidas, ni testigos de transacción: el sello vive dentro de cada
    /// cabecera. El `txid` compromete los bytes completos de ambas (`EV-03`).
    Evidencia {
        /// `H1`: cabecera con el `pre_hash` lexicográficamente menor.
        h1: DagBlockHeader,
        /// `H2`: cabecera con el `pre_hash` lexicográficamente mayor.
        h2: DagBlockHeader,
    },
    /// Versión 5 · operación del **registro de sectores** (`ORDEN-SR1-2` §1, `C-SEC-02/04/05/06/08`).
    ///
    /// La operación viaja entera en la extensión; su preimagen canónica
    /// ([`OperacionSector::bytes_canonicos`]) entra en el `txid` (`ZZKTxIdSector__`) y la firma de
    /// `operacion.clave` sobre el `txid` (`ZZKTxSigSector__`) la compromete campo a campo.
    Sector {
        /// Operación de sector transportada.
        operacion: OperacionSector,
    },
    /// Versión 6 · **prueba de almacenamiento** (`ORDEN-PT3bc`, `REVISION-PT3a` decisión 2).
    ///
    /// Tres clases en una sola extensión: `0x01` PoRep agregada por lote, `0x02` PoSt diaria
    /// agregada y `0x03` registro de la clave BLS de voto con prueba de posesión. La operación
    /// viaja entera; su preimagen canónica entra en el `txid` (`ZZKTxIdAlmacen__`) y la firma
    /// Ed25519 de `operacion.clave` sobre el `txid` (`ZZKTxSigAlmacen_`) la compromete.
    PruebaAlmacenamiento {
        /// Operación de prueba de almacenamiento o de registro de clave de voto.
        operacion: OperacionAlmacenamiento,
    },
}

/// Discriminantes de operación de sector (`ORDEN-SR1` §2.3, `AUTOMATA.md:184-198`).
///
/// Son consenso: **no se reordenan jamás**. El byte es el discriminante canónico.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum TipoOperacionSector {
    /// `C-SEC-02` · alta.
    Alta = 1,
    /// `C-SEC-04` · renovación.
    Renovar = 2,
    /// `C-SEC-05` · apertura de auditoría.
    AbrirAuditoria = 3,
    /// `C-SEC-06` · contestación de auditoría.
    ContestarAuditoria = 4,
    /// `C-SEC-08` · retirada de sector.
    Retirar = 5,
    /// `SR-G2b` · `C-CAJA-05` · cierre explícito de la caja abierta.
    CerrarCaja = 6,
    /// `SR-G2b` · `C-CAJA-08` · retirada atómica de la caja entera.
    RetirarCaja = 7,
}

impl TipoOperacionSector {
    /// El byte canónico.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Decodifica el byte. Conjunto **cerrado**: otro valor se rechaza.
    #[must_use]
    pub const fn desde_byte(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Alta),
            2 => Some(Self::Renovar),
            3 => Some(Self::AbrirAuditoria),
            4 => Some(Self::ContestarAuditoria),
            5 => Some(Self::Retirar),
            6 => Some(Self::CerrarCaja),
            7 => Some(Self::RetirarCaja),
            _ => None,
        }
    }
}

/// Tope de la prueba opaca de `ContestarAuditoria` (`C-SEC-06`): 64 B.
pub const MAX_PRUEBA_SECTOR_BYTES: usize = 64;

/// Tope canónico de una operación de sector. La operación más ancha es `Alta` (79 B); con la prueba
/// opaca de 64 B y su prefijo de longitud, `ContestarAuditoria` cabe en 108 B. Se fija 128 B.
pub const MAX_OPERACION_SECTOR_BYTES: usize = 128;

/// Tope de la prueba de almacenamiento v6 (`REVISION-PT3a` decisión 3). **Solo** para v6.
///
/// `MAX_TX_BYTES` **no cambia** para el resto de versiones. El cuerpo del bloque (320 000 B) es el
/// tope real de la transacción v6 completa.
pub const MAX_PRUEBA_ALMACENAMIENTO_BYTES: usize = 160_000;

/// Longitud de la clave BLS de voto (punto de G1 comprimido, `PK-04`).
pub const LONGITUD_CLAVE_BLS: usize = 48;

/// Longitud de la prueba de posesión BLS (firma en G2 comprimida, `PK-04`).
pub const LONGITUD_PRUEBA_POSESION_BLS: usize = 96;

/// TB-1c · C9 · tope de claves de la tabla de votantes. Debe valer lo mismo que
/// `zx_consensus::transicion::votos::MAX_CLAVES_TABLA` (una prueba lo fija).
pub const MAX_CLAVES_CERTIFICADO_VOTOS: usize = 65_536;

/// TB-1c · C9 · tope de bytes del cuerpo de un certificado compacto por peso (`0x09`) o de un acta
/// (`0x0A`): `200` fijos + mapa de `⌈N/8⌉` con `N ≤ MAX_CLAVES_CERTIFICADO_VOTOS` (8 192 B). El
/// certificado ya **no** lleva tabla, así que no suma `N·58`.
pub const MAX_CERTIFICADO_PESO_BYTES: usize = 200 + MAX_CLAVES_CERTIFICADO_VOTOS.div_ceil(8);

/// Clase de una operación de la extensión v6 (`REVISION-PT3a` decisión 2; FV-4b-N2; FV-4b-N3).
///
/// Los bytes son consenso: **no se reordenan**. `0x01` y `0x02` son pruebas de almacenamiento
/// (sujetas a la cuota de una por bloque); `0x03` registra la clave BLS de voto; `0x08` el **voto
/// propio** de una clave elegida (AV-11/AV-12, orden AUS-2a); `0x09` el **certificado compacto por
/// peso** y `0x0A` el **acta de presencia** (PD-1b).
///
/// **M9-b2 · códigos reservados.** `0x04` (certificado de finalidad por votos), `0x05` (evidencia
/// de doble voto del mensaje antiguo), `0x06` (compromiso Merkle del sorteo) y `0x07` (revelación
/// obligatoria) se retiraron: **no se reutilizan** y [`Self::desde_byte`] los rechaza, de modo que
/// toda transacción que los lleve es inválida por forma.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ClasePruebaAlmacenamiento {
    /// `0x01` · PoRep agregada por lote del granjero.
    PoRep = 0x01,
    /// `0x02` · PoSt diaria agregada por granjero.
    PoSt = 0x02,
    /// `0x03` · registro de la clave BLS de voto con prueba de posesión.
    ClaveVoto = 0x03,
    // `0x04`..=`0x07` reservados (M9-b2): no se reutilizan.
    /// `0x08` · voto propio de una clave elegida (`AUS-2a`, AV-11/AV-12): mete el voto firmado por
    /// la propia clave dentro del plazo de gracia, sin depender de que un productor lo incluya en
    /// el certificado.
    VotoPropio = 0x08,
    /// `0x09` · certificado compacto por peso (`PD-1b`, contrato v2 A5): firma agregada BLS con mapa
    /// de bits por clave y la tabla siguiente solo si cambia.
    CertificadoPeso = 0x09,
    /// `0x0A` · acta de presencia (`PD-1b`, contrato v2 A6): mismo formato que `0x09`, sin quórum y
    /// sin tabla siguiente; solo acredita a sus firmantes.
    ActaPresencia = 0x0A,
    /// `0x0B` · evidencia de dos votos por peso (`PD-1c`, contrato v2 B2, formato PR-A): la misma
    /// clave BLS firmó dos votos distintos sobre A3 en la misma ventana. El incidente incluye las
    /// dos raíces de estado.
    EvidenciaVotosPeso = 0x0B,
}

impl ClasePruebaAlmacenamiento {
    /// El byte canónico.
    #[must_use]
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Decodifica el byte. Conjunto **cerrado**: otro valor se rechaza.
    #[must_use]
    pub const fn desde_byte(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::PoRep),
            0x02 => Some(Self::PoSt),
            0x03 => Some(Self::ClaveVoto),
            0x08 => Some(Self::VotoPropio),
            0x09 => Some(Self::CertificadoPeso),
            0x0A => Some(Self::ActaPresencia),
            0x0B => Some(Self::EvidenciaVotosPeso),
            _ => None,
        }
    }

    /// ¿Es una prueba de almacenamiento (`0x01`/`0x02`)? Solo estas entran en la cuota de bloque.
    #[must_use]
    pub const fn es_prueba(self) -> bool {
        matches!(self, Self::PoRep | Self::PoSt)
    }
}

/// Una clave de la tabla de poder `T_n` transportada por un certificado de finalidad (`FV-4b-N2`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClaveTablaVoto {
    /// Clave pública BLS de voto (G1 comprimido).
    pub clave_bls: [u8; LONGITUD_CLAVE_BLS],
    /// Peso registrado `peso_i` (sectores que pesan).
    pub peso: u64,
    /// `activo_i`.
    pub activo: bool,
    /// `prueba_i` (prueba de disponibilidad vigente).
    pub prueba: bool,
    /// Garantía confiscable declarada.
    pub garantia: u64,
}

/// PD-1c · un voto por peso de la evidencia `0x0B` (contrato v2 B2, formato PR-A).
///
/// Cada voto lleva su ventana, candidato, `h_t_siguiente`, raíz de estado y la firma BLS individual
/// sobre el mensaje A3 `SHA-256(n_u64_be ‖ candidato ‖ h_t_siguiente ‖ raíz_de_estado)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VotoPesoEvidencia {
    /// Ventana `n` del voto.
    pub n: u64,
    /// Candidato `h_B` votado.
    pub candidato: [u8; LONGITUD_HASH],
    /// `h_T(n+1)` declarado por el voto.
    pub h_t_siguiente: [u8; LONGITUD_HASH],
    /// Raíz de estado firmada (`0^32` hasta PK-24 B).
    pub raiz_estado: [u8; LONGITUD_HASH],
    /// Firma BLS individual sobre A3 (G2 comprimida).
    pub firma: [u8; LONGITUD_PRUEBA_POSESION_BLS],
}

/// Error del códec canónico de [`OperacionAlmacenamiento`]. Local a `zx-core::tx`.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ErrorCodecAlmacenamiento {
    /// Discriminante de clase desconocido.
    #[error("clase de prueba de almacenamiento inválida: {0:#04x}")]
    DiscriminanteInvalido(u8),
    /// La prueba de almacenamiento (`0x01`/`0x02`) va vacía.
    #[error("prueba de almacenamiento vacía")]
    PruebaVacia,
    /// La prueba supera [`MAX_PRUEBA_ALMACENAMIENTO_BYTES`].
    #[error("prueba de almacenamiento de {0} B excede {MAX_PRUEBA_ALMACENAMIENTO_BYTES}")]
    PruebaDemasiadoLarga(usize),
    /// `n_sectores` debe ser `> 0` en una prueba de almacenamiento.
    #[error("n_sectores debe ser > 0 en una prueba de almacenamiento")]
    NumeroDeSectoresCero,
    /// El cuerpo de un certificado compacto por peso o de un acta va vacío.
    #[error("certificado por peso vacío")]
    CertificadoVacio,
    /// Una colección del certificado supera su tope.
    #[error("colección del certificado de {0} elementos excede el tope")]
    ColeccionDemasiadoLarga(usize),
    /// La evidencia de dos votos por peso no viene en orden canónico estricto
    /// `(ventana, candidato, h_t_siguiente, raíz)`.
    #[error("evidencia de votos por peso fuera del orden canónico")]
    EvidenciaVotosNoCanonica,
    /// Bytes insuficientes para decodificar.
    #[error("bytes insuficientes para decodificar la operación de almacenamiento")]
    BytesInsuficientes,
}

/// Operación transportada por la extensión v6 (`ORDEN-PT3bc`).
///
/// Preimagen canónica (little-endian, autodelimitada por la clase):
///
/// - `0x01`/`0x02`: `clase u8 ‖ clave 32 B ‖ epoch u64 ‖ n_sectores u32 ‖ raiz_conjunto 32 B ‖
///   len u32 ‖ prueba[len]` (cuerpo fijo `1+32+8+4+32+4 = 81` B + `len`);
/// - `0x03`: `clase u8 ‖ clave 32 B ‖ clave_bls 48 B ‖ prueba_posesion 96 B`.
#[derive(Clone, PartialEq, Eq, Debug)]
// RE-2c: al ganar `VotoPropio` los 32 B de la raíz (248 → 280 B), la diferencia con
// `EvidenciaVotosPeso` (480 B) queda en el umbral de `clippy::large_enum_variant` (200 B) y el lint
// deja de dispararse; se retira la `#[expect]` para que no quede sin cumplir. No se boxea.
pub enum OperacionAlmacenamiento {
    /// `0x01` · PoRep agregada por lote. La prueba cubre el lote de altas `Precomprometido`.
    PoRep {
        /// Clave del granjero que firma (Ed25519).
        clave: ClavePublica,
        /// Slot de la ventana (el `slot_ventana` que ancla la prueba).
        epoch: u64,
        /// Número de sectores cubiertos (`> 0`).
        n_sectores: u32,
        /// Raíz del conjunto de sectores cubiertos.
        raiz_conjunto: [u8; 32],
        /// Prueba opaca (`1..=MAX_PRUEBA_ALMACENAMIENTO_BYTES`).
        prueba: Vec<u8>,
    },
    /// `0x02` · PoSt diaria agregada por granjero.
    PoSt {
        /// Clave del granjero que firma (Ed25519).
        clave: ClavePublica,
        /// Slot de la ventana.
        epoch: u64,
        /// Número de sectores cubiertos (`> 0`).
        n_sectores: u32,
        /// Raíz del conjunto de sectores cubiertos.
        raiz_conjunto: [u8; 32],
        /// Prueba opaca (`1..=MAX_PRUEBA_ALMACENAMIENTO_BYTES`).
        prueba: Vec<u8>,
    },
    /// `0x03` · clave BLS de voto (48 B) con prueba de posesión (96 B).
    ClaveVoto {
        /// Clave Ed25519 que registra y firma la transacción.
        clave: ClavePublica,
        /// Clave pública BLS de voto (G1 comprimido).
        clave_bls: [u8; LONGITUD_CLAVE_BLS],
        /// Prueba de posesión de la clave BLS (firma en G2 comprimida).
        prueba_posesion: [u8; LONGITUD_PRUEBA_POSESION_BLS],
    },
    /// `0x08` · voto propio de una clave elegida (`AUS-2a`, AV-11/AV-12): la clave Ed25519 firma la
    /// transacción y aporta su firma BLS sobre el mismo mensaje que un voto de certificado para
    /// `(n, candidato, h_t_siguiente, raiz_estado)`. Cuenta como voto admitido de la ventana `n` sin
    /// exigir que la tabla o el candidato coincidan (AV-12: cualquier voto bien firmado).
    VotoPropio {
        /// Clave Ed25519 dueña que registró la clave BLS y firma la transacción.
        clave: ClavePublica,
        /// Instancia/ventana `n` a la que se refiere el voto.
        n: u64,
        /// Candidato `h_B` votado.
        candidato: [u8; LONGITUD_HASH],
        /// `h_T(n+1)` con el que se firmó el voto.
        h_t_siguiente: [u8; LONGITUD_HASH],
        /// RE-2c · C2′ · raíz de estado sobre la que el votante firmó A3 (32 B). La cadena la usa solo
        /// para verificar la firma; no la compara con nada.
        raiz_estado: [u8; LONGITUD_HASH],
        /// Clave pública BLS de voto que firma (G1 comprimido).
        clave_bls: [u8; LONGITUD_CLAVE_BLS],
        /// Firma BLS del voto (G2 comprimida).
        firma: [u8; LONGITUD_PRUEBA_POSESION_BLS],
    },
    /// `0x09` · certificado compacto por peso (`PD-1b`, contrato v2 A5): la clave Ed25519 firma la
    /// transacción y el cuerpo transporta los bytes de `serial_certificado_peso` (firma agregada
    /// BLS de 96 B, mapa de bits de `⌈N/8⌉` bytes y, solo si la tabla cambia, `serial_tabla(T_{n+1})`
    /// tal cual). El consenso resuelve la tabla vigente por el estado.
    CertificadoPeso {
        /// Clave Ed25519 dueña que firma la transacción.
        clave: ClavePublica,
        /// Bytes canónicos de `serial_certificado_peso` (sin la clave Ed25519).
        bytes: Vec<u8>,
    },
    /// `0x0A` · acta de presencia (`PD-1b`, contrato v2 A6): mismo formato que `0x09`, **sin** tabla
    /// siguiente. Acredita a sus firmantes en la ventana sin mover la finalidad ni la tabla.
    ActaPresencia {
        /// Clave Ed25519 dueña que firma la transacción.
        clave: ClavePublica,
        /// Bytes canónicos de `serial_certificado_peso`, sin cola de tabla siguiente.
        bytes: Vec<u8>,
    },
    /// `0x0B` · evidencia de dos votos por peso (`PD-1c`, contrato v2 B2): la misma clave BLS acusada
    /// firmó dos votos A3 distintos (contenido distinto) en la misma ventana. Los dos votos van en
    /// orden estrictamente creciente de `(ventana, candidato, h_t_siguiente, raíz)`.
    EvidenciaVotosPeso {
        /// Clave Ed25519 que firma la transacción.
        clave: ClavePublica,
        /// Clave pública BLS acusada (G1 comprimido).
        clave_bls: [u8; LONGITUD_CLAVE_BLS],
        /// Primer voto (menor en orden canónico).
        voto1: VotoPesoEvidencia,
        /// Segundo voto (mayor en orden canónico).
        voto2: VotoPesoEvidencia,
    },
}

impl OperacionAlmacenamiento {
    /// Clase de la operación.
    #[must_use]
    pub const fn clase(&self) -> ClasePruebaAlmacenamiento {
        match self {
            Self::PoRep { .. } => ClasePruebaAlmacenamiento::PoRep,
            Self::PoSt { .. } => ClasePruebaAlmacenamiento::PoSt,
            Self::ClaveVoto { .. } => ClasePruebaAlmacenamiento::ClaveVoto,
            Self::VotoPropio { .. } => ClasePruebaAlmacenamiento::VotoPropio,
            Self::CertificadoPeso { .. } => ClasePruebaAlmacenamiento::CertificadoPeso,
            Self::ActaPresencia { .. } => ClasePruebaAlmacenamiento::ActaPresencia,
            Self::EvidenciaVotosPeso { .. } => ClasePruebaAlmacenamiento::EvidenciaVotosPeso,
        }
    }

    /// Clave Ed25519 que debe firmar la transacción.
    #[must_use]
    pub const fn clave(&self) -> ClavePublica {
        match self {
            Self::PoRep { clave, .. }
            | Self::PoSt { clave, .. }
            | Self::ClaveVoto { clave, .. }
            | Self::VotoPropio { clave, .. } => *clave,
            Self::CertificadoPeso { clave, .. } | Self::ActaPresencia { clave, .. } => *clave,
            Self::EvidenciaVotosPeso { clave, .. } => *clave,
        }
    }

    /// Escribe la preimagen canónica en `out` **sin comprobar topes ni predicados**.
    pub fn escribir_canonica_cruda(&self, out: &mut Vec<u8>) {
        out.push(self.clase().byte());
        match self {
            Self::PoRep {
                clave,
                epoch,
                n_sectores,
                raiz_conjunto,
                prueba,
            }
            | Self::PoSt {
                clave,
                epoch,
                n_sectores,
                raiz_conjunto,
                prueba,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(&epoch.to_le_bytes());
                out.extend_from_slice(&n_sectores.to_le_bytes());
                out.extend_from_slice(raiz_conjunto);
                out.extend_from_slice(
                    &u32::try_from(prueba.len())
                        .unwrap_or(u32::MAX)
                        .to_le_bytes(),
                );
                out.extend_from_slice(prueba);
            }
            Self::ClaveVoto {
                clave,
                clave_bls,
                prueba_posesion,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(clave_bls);
                out.extend_from_slice(prueba_posesion);
            }
            Self::VotoPropio {
                clave,
                n,
                candidato,
                h_t_siguiente,
                raiz_estado,
                clave_bls,
                firma,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(&n.to_le_bytes());
                out.extend_from_slice(candidato);
                out.extend_from_slice(h_t_siguiente);
                out.extend_from_slice(raiz_estado);
                out.extend_from_slice(clave_bls);
                out.extend_from_slice(firma);
            }
            Self::CertificadoPeso { clave, bytes } | Self::ActaPresencia { clave, bytes } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(
                    &u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes(),
                );
                out.extend_from_slice(bytes);
            }
            Self::EvidenciaVotosPeso {
                clave,
                clave_bls,
                voto1,
                voto2,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(clave_bls);
                for voto in [voto1, voto2] {
                    out.extend_from_slice(&voto.n.to_le_bytes());
                    out.extend_from_slice(&voto.candidato);
                    out.extend_from_slice(&voto.h_t_siguiente);
                    out.extend_from_slice(&voto.raiz_estado);
                    out.extend_from_slice(&voto.firma);
                }
            }
        }
    }

    /// Escribe la preimagen canónica en `out` y comprueba el tope y los predicados de la clase.
    ///
    /// # Errores
    /// [`ErrorCodecAlmacenamiento`] si la prueba va vacía, supera el tope o `n_sectores = 0`.
    pub fn escribir_canonica(&self, out: &mut Vec<u8>) -> Result<(), ErrorCodecAlmacenamiento> {
        if let Self::PoRep {
            n_sectores, prueba, ..
        }
        | Self::PoSt {
            n_sectores, prueba, ..
        } = self
        {
            if prueba.is_empty() {
                return Err(ErrorCodecAlmacenamiento::PruebaVacia);
            }
            if prueba.len() > MAX_PRUEBA_ALMACENAMIENTO_BYTES {
                return Err(ErrorCodecAlmacenamiento::PruebaDemasiadoLarga(prueba.len()));
            }
            if *n_sectores == 0 {
                return Err(ErrorCodecAlmacenamiento::NumeroDeSectoresCero);
            }
        }
        if let Self::CertificadoPeso { bytes, .. } | Self::ActaPresencia { bytes, .. } = self {
            if bytes.is_empty() {
                return Err(ErrorCodecAlmacenamiento::CertificadoVacio);
            }
            if bytes.len() > MAX_CERTIFICADO_PESO_BYTES {
                return Err(ErrorCodecAlmacenamiento::ColeccionDemasiadoLarga(
                    bytes.len(),
                ));
            }
        }
        if let Self::EvidenciaVotosPeso { voto1, voto2, .. } = self
            && (
                voto1.n,
                voto1.candidato,
                voto1.h_t_siguiente,
                voto1.raiz_estado,
            ) >= (
                voto2.n,
                voto2.candidato,
                voto2.h_t_siguiente,
                voto2.raiz_estado,
            )
        {
            return Err(ErrorCodecAlmacenamiento::EvidenciaVotosNoCanonica);
        }
        self.escribir_canonica_cruda(out);
        Ok(())
    }

    /// Preimagen canónica **cruda** como `Vec<u8>` (sin comprobar topes).
    #[must_use]
    pub fn bytes_canonicos_crudos(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.escribir_canonica_cruda(&mut out);
        out
    }

    /// Preimagen canónica como `Vec<u8>`.
    ///
    /// # Errores
    /// Las de [`Self::escribir_canonica`].
    pub fn bytes_canonicos(&self) -> Result<Vec<u8>, ErrorCodecAlmacenamiento> {
        let mut out = Vec::new();
        self.escribir_canonica(&mut out)?;
        Ok(out)
    }

    /// Longitud canónica de esta operación.
    ///
    /// # Errores
    /// Las de [`Self::escribir_canonica`].
    pub fn longitud_canonica(&self) -> Result<usize, ErrorCodecAlmacenamiento> {
        self.bytes_canonicos().map(|b| b.len())
    }

    /// Decodifica una operación de su preimagen canónica; devuelve `(operación, bytes_consumidos)`.
    ///
    /// No comprueba `n_sectores > 0` ni la no-vacuidad de la prueba: son **forma**
    /// (`validar_forma_tx`), no códec. Sí acota `len` antes de reservar memoria.
    ///
    /// # Errores
    /// [`ErrorCodecAlmacenamiento`] si la clase, la longitud o los bytes no cuadran.
    pub fn desde_canonica(bytes: &[u8]) -> Result<(Self, usize), ErrorCodecAlmacenamiento> {
        let mut i = 0usize;
        let disc = *alm_tomar(bytes, &mut i, 1)?.first().unwrap_or(&0);
        let clase = ClasePruebaAlmacenamiento::desde_byte(disc)
            .ok_or(ErrorCodecAlmacenamiento::DiscriminanteInvalido(disc))?;
        match clase {
            ClasePruebaAlmacenamiento::PoRep | ClasePruebaAlmacenamiento::PoSt => {
                let clave = ClavePublica::desde_bytes(
                    alm_tomar(bytes, &mut i, 32)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?,
                );
                let epoch = alm_u64(bytes, &mut i)?;
                let n_sectores = alm_u32(bytes, &mut i)?;
                let raiz_conjunto: [u8; 32] = alm_tomar(bytes, &mut i, 32)?
                    .try_into()
                    .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                let len = usize::try_from(alm_u32(bytes, &mut i)?)
                    .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                if len > MAX_PRUEBA_ALMACENAMIENTO_BYTES {
                    return Err(ErrorCodecAlmacenamiento::PruebaDemasiadoLarga(len));
                }
                let prueba = alm_tomar(bytes, &mut i, len)?.to_vec();
                let op = if clase == ClasePruebaAlmacenamiento::PoRep {
                    Self::PoRep {
                        clave,
                        epoch,
                        n_sectores,
                        raiz_conjunto,
                        prueba,
                    }
                } else {
                    Self::PoSt {
                        clave,
                        epoch,
                        n_sectores,
                        raiz_conjunto,
                        prueba,
                    }
                };
                Ok((op, i))
            }
            ClasePruebaAlmacenamiento::ClaveVoto => {
                let clave = ClavePublica::desde_bytes(
                    alm_tomar(bytes, &mut i, 32)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?,
                );
                let clave_bls: [u8; LONGITUD_CLAVE_BLS] =
                    alm_tomar(bytes, &mut i, LONGITUD_CLAVE_BLS)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                let prueba_posesion: [u8; LONGITUD_PRUEBA_POSESION_BLS] =
                    alm_tomar(bytes, &mut i, LONGITUD_PRUEBA_POSESION_BLS)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                Ok((
                    Self::ClaveVoto {
                        clave,
                        clave_bls,
                        prueba_posesion,
                    },
                    i,
                ))
            }
            ClasePruebaAlmacenamiento::VotoPropio => {
                let clave = ClavePublica::desde_bytes(
                    alm_tomar(bytes, &mut i, 32)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?,
                );
                let n = alm_u64(bytes, &mut i)?;
                let candidato: [u8; LONGITUD_HASH] = alm_tomar(bytes, &mut i, LONGITUD_HASH)?
                    .try_into()
                    .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                let h_t_siguiente: [u8; LONGITUD_HASH] = alm_tomar(bytes, &mut i, LONGITUD_HASH)?
                    .try_into()
                    .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                let raiz_estado: [u8; LONGITUD_HASH] = alm_tomar(bytes, &mut i, LONGITUD_HASH)?
                    .try_into()
                    .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                let clave_bls: [u8; LONGITUD_CLAVE_BLS] =
                    alm_tomar(bytes, &mut i, LONGITUD_CLAVE_BLS)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                let firma: [u8; LONGITUD_PRUEBA_POSESION_BLS] =
                    alm_tomar(bytes, &mut i, LONGITUD_PRUEBA_POSESION_BLS)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                Ok((
                    Self::VotoPropio {
                        clave,
                        n,
                        candidato,
                        h_t_siguiente,
                        raiz_estado,
                        clave_bls,
                        firma,
                    },
                    i,
                ))
            }
            ClasePruebaAlmacenamiento::CertificadoPeso
            | ClasePruebaAlmacenamiento::ActaPresencia => {
                let clave = ClavePublica::desde_bytes(
                    alm_tomar(bytes, &mut i, 32)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?,
                );
                let len = usize::try_from(alm_u32(bytes, &mut i)?)
                    .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                if len > MAX_CERTIFICADO_PESO_BYTES {
                    return Err(ErrorCodecAlmacenamiento::ColeccionDemasiadoLarga(len));
                }
                let cuerpo = alm_tomar(bytes, &mut i, len)?.to_vec();
                let op = if clase == ClasePruebaAlmacenamiento::CertificadoPeso {
                    Self::CertificadoPeso {
                        clave,
                        bytes: cuerpo,
                    }
                } else {
                    Self::ActaPresencia {
                        clave,
                        bytes: cuerpo,
                    }
                };
                Ok((op, i))
            }
            ClasePruebaAlmacenamiento::EvidenciaVotosPeso => {
                let clave = ClavePublica::desde_bytes(
                    alm_tomar(bytes, &mut i, 32)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?,
                );
                let clave_bls: [u8; LONGITUD_CLAVE_BLS] =
                    alm_tomar(bytes, &mut i, LONGITUD_CLAVE_BLS)?
                        .try_into()
                        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
                let voto1 = alm_voto_peso(bytes, &mut i)?;
                let voto2 = alm_voto_peso(bytes, &mut i)?;
                Ok((
                    Self::EvidenciaVotosPeso {
                        clave,
                        clave_bls,
                        voto1,
                        voto2,
                    },
                    i,
                ))
            }
        }
    }
}

/// Lee un [`VotoPesoEvidencia`] little-endian.
fn alm_voto_peso(
    bytes: &[u8],
    i: &mut usize,
) -> Result<VotoPesoEvidencia, ErrorCodecAlmacenamiento> {
    let n = alm_u64(bytes, i)?;
    let candidato: [u8; LONGITUD_HASH] = alm_tomar(bytes, i, LONGITUD_HASH)?
        .try_into()
        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    let h_t_siguiente: [u8; LONGITUD_HASH] = alm_tomar(bytes, i, LONGITUD_HASH)?
        .try_into()
        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    let raiz_estado: [u8; LONGITUD_HASH] = alm_tomar(bytes, i, LONGITUD_HASH)?
        .try_into()
        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    let firma: [u8; LONGITUD_PRUEBA_POSESION_BLS] =
        alm_tomar(bytes, i, LONGITUD_PRUEBA_POSESION_BLS)?
            .try_into()
            .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    Ok(VotoPesoEvidencia {
        n,
        candidato,
        h_t_siguiente,
        raiz_estado,
        firma,
    })
}

/// Toma `n` bytes con el error de [`ErrorCodecAlmacenamiento`].
fn alm_tomar<'a>(
    bytes: &'a [u8],
    i: &mut usize,
    n: usize,
) -> Result<&'a [u8], ErrorCodecAlmacenamiento> {
    let fin = i
        .checked_add(n)
        .ok_or(ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    let s = bytes
        .get(*i..fin)
        .ok_or(ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    *i = fin;
    Ok(s)
}

/// Lee un `u64` little-endian con el error de [`ErrorCodecAlmacenamiento`].
fn alm_u64(bytes: &[u8], i: &mut usize) -> Result<u64, ErrorCodecAlmacenamiento> {
    let b: [u8; 8] = alm_tomar(bytes, i, 8)?
        .try_into()
        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    Ok(u64::from_le_bytes(b))
}

/// Lee un `u32` little-endian con el error de [`ErrorCodecAlmacenamiento`].
fn alm_u32(bytes: &[u8], i: &mut usize) -> Result<u32, ErrorCodecAlmacenamiento> {
    let b: [u8; 4] = alm_tomar(bytes, i, 4)?
        .try_into()
        .map_err(|_| ErrorCodecAlmacenamiento::BytesInsuficientes)?;
    Ok(u32::from_le_bytes(b))
}

/// Error del códec canónico de [`OperacionSector`]. Es local a `zx-core::tx` para no tocar
/// [`crate::error`] (fuera de los archivos que posee este carril).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ErrorCodecSector {
    /// Discriminante desconocido.
    #[error("discriminante de operación de sector inválido: {0:#04x}")]
    DiscriminanteInvalido(u8),
    /// Prueba opaca por encima de [`MAX_PRUEBA_SECTOR_BYTES`].
    #[error("prueba de sector de {0} B excede {MAX_PRUEBA_SECTOR_BYTES}")]
    PruebaDemasiadoLarga(usize),
    /// Bytes insuficientes para decodificar.
    #[error("bytes insuficientes para decodificar la operación de sector")]
    BytesInsuficientes,
    /// Longitud declarada que no cuadra.
    #[error(
        "longitud inconsistente en la operación de sector: declarada {declarada}, quedan {quedan}"
    )]
    LongitudInconsistente {
        /// Longitud declarada.
        declarada: usize,
        /// Bytes disponibles.
        quedan: usize,
    },
    /// El resultado excede [`MAX_OPERACION_SECTOR_BYTES`].
    #[error("operación de sector de {0} B excede {MAX_OPERACION_SECTOR_BYTES}")]
    OperacionDemasiadoLarga(usize),
}

/// Operación de sector transportable en una transacción (`C-SEC-02/04/05/06/08`).
///
/// La **preimagen canónica** es, en little-endian y sin ambigüedad:
/// `discriminante u8 ‖ clave 32 B ‖ sector_index u16 ‖ ...`; `ContestarAuditoria` añade
/// `auditoria_id u64 ‖ CompactSize(len(prueba)) ‖ prueba`. La asociación con `version` de
/// transacción la hace `validar_forma_tx` al integrarse (ver incidencia B-1 en `PROGRESO.md`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OperacionSector {
    /// `C-SEC-02`.
    Alta {
        /// Clave del productor.
        clave: ClavePublica,
        /// Índice de sector.
        sector_index: u16,
        /// Versión del índice.
        version: u32,
        /// Compromiso `R2`.
        r2: [u8; 32],
        /// `history_size`.
        history_size: u64,
    },
    /// `C-SEC-04`.
    Renovar {
        /// Clave.
        clave: ClavePublica,
        /// Índice de sector.
        sector_index: u16,
    },
    /// `C-SEC-05`.
    AbrirAuditoria {
        /// Clave.
        clave: ClavePublica,
        /// Índice de sector.
        sector_index: u16,
        /// Identificador determinista de auditoría (S02b).
        auditoria_id: u64,
    },
    /// `C-SEC-06`.
    ContestarAuditoria {
        /// Clave.
        clave: ClavePublica,
        /// Índice de sector.
        sector_index: u16,
        /// Identificador de la auditoría.
        auditoria_id: u64,
        /// Prueba opaca (hoy inerte; PT-3 la llenará).
        prueba: Vec<u8>,
    },
    /// `C-SEC-08`.
    Retirar {
        /// Clave.
        clave: ClavePublica,
        /// Índice de sector.
        sector_index: u16,
    },
    /// `SR-G2b` · `C-CAJA-05` · cierre de la caja abierta de `clave`.
    CerrarCaja {
        /// Clave dueña de la caja.
        clave: ClavePublica,
        /// Contador de caja (`seq`); `0` = la caja abierta.
        seq: u32,
    },
    /// `SR-G2b` · `C-CAJA-08` · retirada atómica de la caja `(clave, seq)`.
    RetirarCaja {
        /// Clave dueña de la caja.
        clave: ClavePublica,
        /// Contador de caja (`seq`).
        seq: u32,
    },
}

impl OperacionSector {
    /// Discriminante de esta operación.
    #[must_use]
    pub const fn tipo(&self) -> TipoOperacionSector {
        match self {
            Self::Alta { .. } => TipoOperacionSector::Alta,
            Self::Renovar { .. } => TipoOperacionSector::Renovar,
            Self::AbrirAuditoria { .. } => TipoOperacionSector::AbrirAuditoria,
            Self::ContestarAuditoria { .. } => TipoOperacionSector::ContestarAuditoria,
            Self::Retirar { .. } => TipoOperacionSector::Retirar,
            Self::CerrarCaja { .. } => TipoOperacionSector::CerrarCaja,
            Self::RetirarCaja { .. } => TipoOperacionSector::RetirarCaja,
        }
    }

    /// Clave del productor que debe firmar la operación.
    #[must_use]
    pub const fn clave(&self) -> ClavePublica {
        match self {
            Self::Alta { clave, .. }
            | Self::Renovar { clave, .. }
            | Self::AbrirAuditoria { clave, .. }
            | Self::ContestarAuditoria { clave, .. }
            | Self::Retirar { clave, .. }
            | Self::CerrarCaja { clave, .. }
            | Self::RetirarCaja { clave, .. } => *clave,
        }
    }

    /// Escribe la preimagen canónica en `out` **sin comprobar topes**.
    ///
    /// La usan el wire y el sub-digest del `txid`, que deben comprometer exactamente los mismos
    /// bytes. `escribir_canonica` es la puerta pública que sí valida el tope.
    pub fn escribir_canonica_cruda(&self, out: &mut Vec<u8>) {
        out.push(self.tipo().byte());
        match self {
            Self::Alta {
                clave,
                sector_index,
                version,
                r2,
                history_size,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(&sector_index.to_le_bytes());
                out.extend_from_slice(&version.to_le_bytes());
                out.extend_from_slice(r2);
                out.extend_from_slice(&history_size.to_le_bytes());
            }
            Self::Renovar {
                clave,
                sector_index,
            }
            | Self::Retirar {
                clave,
                sector_index,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(&sector_index.to_le_bytes());
            }
            Self::AbrirAuditoria {
                clave,
                sector_index,
                auditoria_id,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(&sector_index.to_le_bytes());
                out.extend_from_slice(&auditoria_id.to_le_bytes());
            }
            Self::ContestarAuditoria {
                clave,
                sector_index,
                auditoria_id,
                prueba,
            } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(&sector_index.to_le_bytes());
                out.extend_from_slice(&auditoria_id.to_le_bytes());
                out.push(u8::try_from(prueba.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(prueba);
            }
            Self::CerrarCaja { clave, seq } | Self::RetirarCaja { clave, seq } => {
                out.extend_from_slice(clave.bytes());
                out.extend_from_slice(&seq.to_le_bytes());
            }
        }
    }

    /// Escribe la preimagen canónica en `out` y comprueba el tope.
    ///
    /// # Errores
    /// [`ErrorCodecSector`] si la prueba opaca o la operación exceden su tope.
    pub fn escribir_canonica(&self, out: &mut Vec<u8>) -> Result<(), ErrorCodecSector> {
        let inicio = out.len();
        if let Self::ContestarAuditoria { prueba, .. } = self
            && prueba.len() > MAX_PRUEBA_SECTOR_BYTES
        {
            out.truncate(inicio);
            return Err(ErrorCodecSector::PruebaDemasiadoLarga(prueba.len()));
        }
        self.escribir_canonica_cruda(out);
        if out.len() - inicio > MAX_OPERACION_SECTOR_BYTES {
            let n = out.len() - inicio;
            out.truncate(inicio);
            return Err(ErrorCodecSector::OperacionDemasiadoLarga(n));
        }
        Ok(())
    }

    /// Preimagen canónica **cruda** como `Vec<u8>` (sin comprobar topes).
    #[must_use]
    pub fn bytes_canonicos_crudos(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.escribir_canonica_cruda(&mut out);
        out
    }

    /// Preimagen canónica como `Vec<u8>`.
    ///
    /// # Errores
    /// Las de [`Self::escribir_canonica`].
    pub fn bytes_canonicos(&self) -> Result<Vec<u8>, ErrorCodecSector> {
        let mut out = Vec::new();
        self.escribir_canonica(&mut out)?;
        Ok(out)
    }

    /// Longitud canónica de esta operación.
    ///
    /// # Errores
    /// Las de [`Self::escribir_canonica`].
    pub fn longitud_canonica(&self) -> Result<usize, ErrorCodecSector> {
        self.bytes_canonicos().map(|b| b.len())
    }

    /// Decodifica una operación de su preimagen canónica; devuelve `(operación, bytes_consumidos)`.
    ///
    /// # Errores
    /// [`ErrorCodecSector`] si el discriminante, el tope o la longitud no cuadran.
    pub fn desde_canonica(bytes: &[u8]) -> Result<(Self, usize), ErrorCodecSector> {
        let mut i = 0usize;
        let disc = *tomar_sector(bytes, &mut i, 1)?.first().unwrap_or(&0);
        let clave = ClavePublica::desde_bytes(
            tomar_sector(bytes, &mut i, 32)?
                .try_into()
                .map_err(|_| ErrorCodecSector::BytesInsuficientes)?,
        );
        let op = match TipoOperacionSector::desde_byte(disc) {
            Some(TipoOperacionSector::Alta) => {
                let sector_index = leer_u16_sector(bytes, &mut i)?;
                let vb: [u8; 4] = tomar_sector(bytes, &mut i, 4)?
                    .try_into()
                    .map_err(|_| ErrorCodecSector::BytesInsuficientes)?;
                let version = u32::from_le_bytes(vb);
                let r2: [u8; 32] = tomar_sector(bytes, &mut i, 32)?
                    .try_into()
                    .map_err(|_| ErrorCodecSector::BytesInsuficientes)?;
                let hb: [u8; 8] = tomar_sector(bytes, &mut i, 8)?
                    .try_into()
                    .map_err(|_| ErrorCodecSector::BytesInsuficientes)?;
                Self::Alta {
                    clave,
                    sector_index,
                    version,
                    r2,
                    history_size: u64::from_le_bytes(hb),
                }
            }
            Some(TipoOperacionSector::Renovar) => Self::Renovar {
                clave,
                sector_index: leer_u16_sector(bytes, &mut i)?,
            },
            Some(TipoOperacionSector::AbrirAuditoria) => Self::AbrirAuditoria {
                clave,
                sector_index: leer_u16_sector(bytes, &mut i)?,
                auditoria_id: leer_u64_sector(bytes, &mut i)?,
            },
            Some(TipoOperacionSector::ContestarAuditoria) => {
                let sector_index = leer_u16_sector(bytes, &mut i)?;
                let auditoria_id = leer_u64_sector(bytes, &mut i)?;
                let len = usize::from(*tomar_sector(bytes, &mut i, 1)?.first().unwrap_or(&0));
                if len > MAX_PRUEBA_SECTOR_BYTES {
                    return Err(ErrorCodecSector::PruebaDemasiadoLarga(len));
                }
                let prueba = tomar_sector(bytes, &mut i, len)?.to_vec();
                Self::ContestarAuditoria {
                    clave,
                    sector_index,
                    auditoria_id,
                    prueba,
                }
            }
            Some(TipoOperacionSector::Retirar) => Self::Retirar {
                clave,
                sector_index: leer_u16_sector(bytes, &mut i)?,
            },
            Some(TipoOperacionSector::CerrarCaja) => Self::CerrarCaja {
                clave,
                seq: leer_u32_sector(bytes, &mut i)?,
            },
            Some(TipoOperacionSector::RetirarCaja) => Self::RetirarCaja {
                clave,
                seq: leer_u32_sector(bytes, &mut i)?,
            },
            None => return Err(ErrorCodecSector::DiscriminanteInvalido(disc)),
        };
        if i > MAX_OPERACION_SECTOR_BYTES {
            return Err(ErrorCodecSector::OperacionDemasiadoLarga(i));
        }
        Ok((op, i))
    }
}

/// Toma `n` bytes de `bytes` a partir de `*i`, avanzando `*i`.
fn tomar_sector<'a>(
    bytes: &'a [u8],
    i: &mut usize,
    n: usize,
) -> Result<&'a [u8], ErrorCodecSector> {
    let fin = i
        .checked_add(n)
        .ok_or(ErrorCodecSector::BytesInsuficientes)?;
    let s = bytes
        .get(*i..fin)
        .ok_or(ErrorCodecSector::BytesInsuficientes)?;
    *i = fin;
    Ok(s)
}

/// Lee un entero `u64` little-endian.
fn leer_u64_sector(bytes: &[u8], i: &mut usize) -> Result<u64, ErrorCodecSector> {
    let b: [u8; 8] = tomar_sector(bytes, i, 8)?
        .try_into()
        .map_err(|_| ErrorCodecSector::BytesInsuficientes)?;
    Ok(u64::from_le_bytes(b))
}

/// Lee un entero `u32` little-endian.
fn leer_u32_sector(bytes: &[u8], i: &mut usize) -> Result<u32, ErrorCodecSector> {
    let b: [u8; 4] = tomar_sector(bytes, i, 4)?
        .try_into()
        .map_err(|_| ErrorCodecSector::BytesInsuficientes)?;
    Ok(u32::from_le_bytes(b))
}

/// Lee un entero `u16` little-endian.
fn leer_u16_sector(bytes: &[u8], i: &mut usize) -> Result<u16, ErrorCodecSector> {
    let b: [u8; 2] = tomar_sector(bytes, i, 2)?
        .try_into()
        .map_err(|_| ErrorCodecSector::BytesInsuficientes)?;
    Ok(u16::from_le_bytes(b))
}

/// Una transacción, solo con sus **datos de efecto** (§5.1).
///
/// Los datos de autorización —las firmas— viajan aparte, en el testigo. Ver [`crate::preimage`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tx {
    /// Versión. En v0: `1` transferencia/coinbase PoW, `2` garantía, `3` coinbase PoST. Es el
    /// gancho de extensión del protocolo (C-TX-07).
    pub version: u32,
    /// Entradas consumidas.
    pub inputs: Vec<TxIn>,
    /// Salidas creadas.
    pub outputs: Vec<TxOut>,
    /// Altura o timestamp antes del cual la transacción no es válida.
    pub lock_time: u32,
    /// Altura tras la cual deja de ser válida; `0` = sin expiración (C-TX-08).
    pub expiry_height: u32,
    /// Campos de efecto extra de la versión (F-05). Coherencia obligatoria con `version`.
    pub extension: ExtensionTx,
}

impl Tx {
    /// ¿Esta transacción es candidata a **coinbase PoW**?
    ///
    /// F-05: una v1 con `n_in = 0` solo es válida como coinbase PoW (o como la coinbase sin salidas
    /// de valor del génesis, F-13). `validar_forma_tx` no puede saber si la transacción es la
    /// primera de un bloque PoW, así que no la rechaza: la acepta y expone esta marca para que el
    /// contexto decida. No sustituye a la comprobación contextual.
    #[must_use]
    pub fn es_candidata_coinbase_pow(&self) -> bool {
        self.version == 1
            && self.inputs.is_empty()
            && matches!(self.extension, ExtensionTx::Ninguna)
    }
}

/// La salida que una entrada consume, tal y como existía en el UTXO set.
///
/// Hace falta para el sighash: `amounts_digest` y `scripts_digest` (C-SIG-02) comprometen el
/// importe y la condición de bloqueo de **las salidas gastadas**, no de las que se crean. Es lo que
/// permite a un firmante *offline* verificar el fee real sin recibir las transacciones previas
/// enteras.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpentOutput {
    /// Importe de la salida consumida.
    pub value: Amount,
    /// Condición de bloqueo que se está satisfaciendo.
    pub lock: Lock,
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "los tests fallan con panic por diseño y usan índices acotados"
    )]

    use super::{
        ClavePublica, ErrorCodecSector, Lock, MAX_MULTISIG_KEYS, MAX_OPERACION_SECTOR_BYTES,
        MAX_PRUEBA_SECTOR_BYTES, OperacionSector, TipoOperacionSector,
    };

    fn clave(n: u8) -> ClavePublica {
        ClavePublica::desde_bytes([n; 32])
    }

    #[test]
    fn los_discriminantes_son_los_del_spec() {
        assert_eq!(Lock::PubKey { pubkey: clave(0) }.discriminante(), 0x00);
        assert_eq!(Lock::DISC_MULTISIG, 0x01);
        assert_eq!(Lock::DISC_HTLC, 0x02);
    }

    #[test]
    fn multisig_valido() {
        assert!(Lock::multisig(2, vec![clave(1), clave(2), clave(3)]).is_ok());
        assert!(Lock::multisig(1, vec![clave(1)]).is_ok());
    }

    #[test]
    fn multisig_rechaza_k_fuera_de_rango() {
        assert!(Lock::multisig(0, vec![clave(1)]).is_err(), "k = 0");
        assert!(
            Lock::multisig(3, vec![clave(1), clave(2)]).is_err(),
            "k > n"
        );
    }

    #[test]
    fn multisig_rechaza_n_fuera_de_rango() {
        assert!(Lock::multisig(1, vec![]).is_err(), "n = 0");
        let demasiadas: Vec<ClavePublica> = (0..=u8::try_from(MAX_MULTISIG_KEYS).unwrap_or(16))
            .map(clave)
            .collect();
        assert!(
            Lock::multisig(1, demasiadas).is_err(),
            "n > MAX_MULTISIG_KEYS"
        );
    }

    #[test]
    fn multisig_rechaza_claves_repetidas() {
        assert!(
            Lock::multisig(2, vec![clave(7), clave(7)]).is_err(),
            "C-TX-11: las claves deben ser distintas"
        );
    }

    #[test]
    fn dieciseis_claves_es_el_limite_exacto() {
        let justas: Vec<ClavePublica> = (0..16).map(clave).collect();
        assert_eq!(justas.len(), MAX_MULTISIG_KEYS);
        assert!(Lock::multisig(16, justas).is_ok());
    }

    // ── `ORDEN-SR1` §2.3 · códec canónico de operaciones de sector ──────────

    fn alta() -> OperacionSector {
        OperacionSector::Alta {
            clave: clave(3),
            sector_index: 7,
            version: 2,
            r2: [9u8; 32],
            history_size: 1_234_567,
        }
    }

    #[test]
    fn los_discriminantes_de_sector_son_cerrados() {
        assert_eq!(TipoOperacionSector::Alta.byte(), 1);
        assert_eq!(TipoOperacionSector::Renovar.byte(), 2);
        assert_eq!(TipoOperacionSector::AbrirAuditoria.byte(), 3);
        assert_eq!(TipoOperacionSector::ContestarAuditoria.byte(), 4);
        assert_eq!(TipoOperacionSector::Retirar.byte(), 5);
        assert_eq!(TipoOperacionSector::CerrarCaja.byte(), 6);
        assert_eq!(TipoOperacionSector::RetirarCaja.byte(), 7);
        for v in [0u8, 8, 0xFF] {
            assert!(TipoOperacionSector::desde_byte(v).is_none());
        }
    }

    #[test]
    fn la_operacion_de_sector_va_y_vuelve() {
        let ops = [
            alta(),
            OperacionSector::Renovar {
                clave: clave(4),
                sector_index: 1,
            },
            OperacionSector::AbrirAuditoria {
                clave: clave(5),
                sector_index: 2,
                auditoria_id: 99,
            },
            OperacionSector::ContestarAuditoria {
                clave: clave(6),
                sector_index: 3,
                auditoria_id: 100,
                prueba: vec![1, 2, 3, 4],
            },
            OperacionSector::Retirar {
                clave: clave(7),
                sector_index: 8,
            },
            OperacionSector::CerrarCaja {
                clave: clave(8),
                seq: 3,
            },
            OperacionSector::RetirarCaja {
                clave: clave(9),
                seq: 4,
            },
        ];
        for op in &ops {
            let bytes = op.bytes_canonicos().unwrap();
            let (vuelta, n) = OperacionSector::desde_canonica(&bytes).unwrap();
            assert_eq!(&vuelta, op, "ida y vuelta");
            assert_eq!(n, bytes.len(), "consume todos los bytes");
            assert_eq!(bytes[0], op.tipo().byte(), "discriminante primero");
        }
    }

    #[test]
    fn el_tope_de_la_prueba_y_de_la_operacion_se_respeta() {
        let justa = OperacionSector::ContestarAuditoria {
            clave: clave(1),
            sector_index: 0,
            auditoria_id: 1,
            prueba: vec![0u8; MAX_PRUEBA_SECTOR_BYTES],
        };
        let n = justa.longitud_canonica().unwrap();
        assert!(n <= MAX_OPERACION_SECTOR_BYTES);

        let larga = OperacionSector::ContestarAuditoria {
            clave: clave(1),
            sector_index: 0,
            auditoria_id: 1,
            prueba: vec![0u8; MAX_PRUEBA_SECTOR_BYTES + 1],
        };
        assert!(larga.bytes_canonicos().is_err());
    }

    #[test]
    fn la_decodificacion_rechaza_bytes_cortos_y_discriminantes_malos() {
        let bytes = alta().bytes_canonicos().unwrap();
        assert!(OperacionSector::desde_canonica(&bytes[..10]).is_err());
        let mut malo = bytes.clone();
        malo[0] = 0x7F;
        assert!(matches!(
            OperacionSector::desde_canonica(&malo),
            Err(ErrorCodecSector::DiscriminanteInvalido(0x7F))
        ));
    }

    #[test]
    fn la_codificacion_del_alta_no_es_ambigua() {
        // Cambiar cualquier campo cambia los bytes (compromiso total).
        let base = alta().bytes_canonicos().unwrap();
        let otra_h = OperacionSector::Alta {
            clave: clave(3),
            sector_index: 7,
            version: 2,
            r2: [9u8; 32],
            history_size: 1_234_568,
        };
        assert_ne!(base, otra_h.bytes_canonicos().unwrap(), "history_size");
        let otra_v = OperacionSector::Alta {
            clave: clave(3),
            sector_index: 7,
            version: 3,
            r2: [9u8; 32],
            history_size: 1_234_567,
        };
        assert_ne!(base, otra_v.bytes_canonicos().unwrap(), "version");
    }
}
