//! Mensajes del protocolo de la red dev híbrida (SPEC §16.1, FORMATO-v0).
//!
//! # El saludo va primero, y no es cortesía
//!
//! Antes de pedir nada, los dos extremos intercambian un [`Estado`]: de qué red y génesis vienen,
//! en qué fase están, dónde tienen la punta PoW y qué puntas PoST conocen. Sirve para dos cosas:
//! decidir **quién pide a quién**, y detectar que se habla con otra red o con otra bifurcación
//! aunque el prefijo mágico haya coincidido. Génesis o red distintos ⇒ desconexión.
//!
//! # Por qué la petición de cabeceras lleva un *locator* y no una altura
//!
//! Pedir "las cabeceras desde la altura 1000" supone que los dos estáis en la misma cadena. Un
//! **locator** —una lista de hashes conocidos, densa cerca de la punta y espaciada hacia atrás— no
//! lo supone: el otro extremo busca el primero que reconoce y responde desde ahí. Es el mecanismo
//! de Bitcoin desde el principio.
//!
//! # Las dos familias de bloque no se adivinan
//!
//! [`BloqueRed`] es un enum con la familia **explícita** en el wire ([`FamiliaBloque`]). El códec
//! exige la familia declarada por el llamante (F-04): una cabecera PoW mide exactamente 92 B y una
//! PoST entre 589 y 1 037 B, y **nunca** se intenta deducir cuál es por la longitud de un buffer
//! ambiguo.

use zx_core::digest::BlockHash;
use zx_core::firma::{ClavePublica, Firma, verificar};
use zx_core::preimage::block::BlockHeader;
use zx_core::preimage::dag::DagBlockHeader;
use zx_core::red::Red;
use zx_core::tx::Tx;
use zx_core::wire_dag::JustificacionPot;

use crate::registro::EntradaRegistro;

/// Máximo de puntas PoST que caben en un [`Estado`].
///
/// La cabecera PoST admite hasta 15 padres; 16 puntas cubren ese conjunto con holgura y acotan el
/// saludo. No es una regla de consenso, es una cota del transporte.
pub const MAX_PUNTAS_POST: usize = 16;

/// Familia de bloque del híbrido.
///
/// El discriminante viaja **explícito** en el wire: es la familia declarada que el códec exige, no
/// algo que se deduzca de la longitud (F-04). Son consenso de protocolo: no se reordenan.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum FamiliaBloque {
    /// Cabecera lineal PoW (92 B).
    Pow,
    /// Cabecera DAG PoST (589–1 037 B).
    Post,
}

impl FamiliaBloque {
    /// Discriminante de [`FamiliaBloque::Pow`].
    pub const DISC_POW: u8 = 0x00;
    /// Discriminante de [`FamiliaBloque::Post`].
    pub const DISC_POST: u8 = 0x01;

    /// El byte que identifica esta familia en el wire.
    #[must_use]
    pub const fn discriminante(self) -> u8 {
        match self {
            Self::Pow => Self::DISC_POW,
            Self::Post => Self::DISC_POST,
        }
    }

    /// Interpreta un byte como familia, o `None` si no es ninguna.
    ///
    /// Devuelve `Option` en vez de un valor por defecto: un byte desconocido **no** se interpreta
    /// como PoW "porque es lo primero".
    #[must_use]
    pub const fn desde_byte(b: u8) -> Option<Self> {
        match b {
            Self::DISC_POW => Some(Self::Pow),
            Self::DISC_POST => Some(Self::Post),
            _ => None,
        }
    }
}

/// Un bloque tal y como viaja: cabecera, transacciones y testigos, en su familia.
///
/// Es una versión **con dueño** de lo que el nodo valida por referencia. Vive aquí y no en otro
/// crate porque este crate no depende de consenso (ver el diagrama en `lib.rs`), y sus campos son
/// tipos de `zx-core`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "el enum define las dos familias con la cabecera en línea, como pide la orden; \
              boxearla añadiría indirección sin cambiar el wire"
)]
pub enum BloqueRed {
    /// Bloque PoW: cabecera lineal y cuerpo.
    Pow {
        /// Cabecera lineal (F-01).
        cabecera: BlockHeader,
        /// Transacciones, la primera de las cuales es la coinbase PoW.
        txs: Vec<Tx>,
        /// `testigos[i][j]` es el testigo de la entrada `j` de la transacción `i`.
        testigos: Vec<Vec<Vec<u8>>>,
    },
    /// Bloque PoST: cabecera DAG, justificación PoT y cuerpo.
    Post {
        /// Cabecera DAG (F-02).
        cabecera: DagBlockHeader,
        /// Justificación PoT (`ORDEN-W06d3` decisión 1): sin ella,
        /// `zx_post::cabecera_conjunta::verificar_cabecera_conjunta` no puede comprobar el PoT ni el
        /// PoAS de un bloque ajeno (`REVISION-W06d2.md`, bloqueo). Va **fuera** de `block_hash`
        /// (igual que en [`zx_core::wire_dag::BloqueDag`]): es evidencia contextual, no consenso de
        /// la cabecera.
        justificacion: JustificacionPot,
        /// Transacciones, la primera de las cuales es la coinbase PoST.
        txs: Vec<Tx>,
        /// `testigos[i][j]` es el testigo de la entrada `j` de la transacción `i`.
        testigos: Vec<Vec<Vec<u8>>>,
    },
}

impl BloqueRed {
    /// La familia declarada de este bloque.
    #[must_use]
    pub const fn familia(&self) -> FamiliaBloque {
        match self {
            Self::Pow { .. } => FamiliaBloque::Pow,
            Self::Post { .. } => FamiliaBloque::Post,
        }
    }

    /// Las transacciones del bloque, sea cual sea la familia.
    #[must_use]
    pub fn txs(&self) -> &[Tx] {
        match self {
            Self::Pow { txs, .. } | Self::Post { txs, .. } => txs,
        }
    }

    /// Las listas de testigos del bloque, sea cual sea la familia.
    #[must_use]
    pub fn testigos(&self) -> &[Vec<Vec<u8>>] {
        match self {
            Self::Pow { testigos, .. } | Self::Post { testigos, .. } => testigos,
        }
    }
}

/// Fase del híbrido en la que está un nodo.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Fase {
    /// Fase PoW (antes del corte).
    Pow,
    /// Fase PoST (después del corte).
    Post,
}

impl Fase {
    /// Discriminante de [`Fase::Pow`].
    pub const DISC_POW: u8 = 0x00;
    /// Discriminante de [`Fase::Post`].
    pub const DISC_POST: u8 = 0x01;

    /// El byte que identifica esta fase en el wire.
    #[must_use]
    pub const fn discriminante(self) -> u8 {
        match self {
            Self::Pow => Self::DISC_POW,
            Self::Post => Self::DISC_POST,
        }
    }

    /// Interpreta un byte como fase, o `None` si no es ninguna.
    #[must_use]
    pub const fn desde_byte(b: u8) -> Option<Self> {
        match b {
            Self::DISC_POW => Some(Self::Pow),
            Self::DISC_POST => Some(Self::Post),
            _ => None,
        }
    }
}

/// La punta PoW declarada en el saludo: hash, altura y trabajo acumulado.
///
/// Es la terna `(hash, altura, trabajo_acumulado 32 B BE)` de la orden. El trabajo va en bytes
/// crudos **big-endian** y no como entero porque el *fork choice* es del nodo y este crate no lo ve:
/// aquí solo se transporta; quien compare será quien sepa comparar.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PuntaPow {
    /// Hash de la punta PoW.
    pub hash: BlockHash,
    /// Altura de esa punta.
    pub altura: u32,
    /// Trabajo acumulado, en big-endian de 32 bytes.
    pub trabajo_acumulado: [u8; 32],
}

/// Lo que un peer dice de sí mismo al saludar.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Estado {
    /// Hash del génesis. **Distinto ⇒ no hay nada que hablar**, aunque la red cuadrase.
    pub hash_genesis: BlockHash,
    /// Red de la que se viene. **Distinta ⇒ desconexión.**
    pub red: Red,
    /// Fase en la que está el peer.
    pub fase: Fase,
    /// Su punta PoW.
    pub punta_pow: PuntaPow,
    /// Hash del terminal PoW, si ya se cruzó el corte.
    pub terminal: Option<BlockHash>,
    /// Puntas PoST conocidas, como mucho [`MAX_PUNTAS_POST`].
    pub puntas_post: Vec<BlockHash>,
    /// `blue_work_virtual`, en big-endian de 32 bytes.
    pub blue_work_virtual: [u8; 32],
    /// `ORDEN-W06d6` decisión 1: longitud del registro de admisión de quien saluda (PoW + PoST, en
    /// el orden real en que los admitió). Es lo que permite al que sincroniza saber, sin pedir
    /// nada más, cuánto le falta: compara esto con lo que ya tiene y decide cuántas páginas de
    /// `Peticion::Registro` pedir.
    pub longitud_registro: u64,
}

/// El byte de red en el wire.
///
/// La orden nombra el campo `red` sin fijar su codificación. Se fija aquí, explícita y **cerrada**:
/// `Mainnet = 0`, `Testnet = 1`, `Dev = 2`. Un byte fuera de ese conjunto se rechaza en el códec;
/// no se interpreta como una red por defecto.
#[must_use]
pub const fn red_discriminante(red: Red) -> u8 {
    match red {
        Red::Mainnet => 0x00,
        Red::Testnet => 0x01,
        Red::Dev => 0x02,
    }
}

/// Interpreta el byte de red del wire, o `None` si no es una red conocida.
#[must_use]
pub const fn red_desde_discriminante(b: u8) -> Option<Red> {
    match b {
        0x00 => Some(Red::Mainnet),
        0x01 => Some(Red::Testnet),
        0x02 => Some(Red::Dev),
        _ => None,
    }
}

/// A6-02 · Q2: longitud exacta del [`AnuncioPrueba`] en el wire, en bytes.
pub const LONGITUD_ANUNCIO_PRUEBA: usize = 146;

/// A6-02 · Q2: dominio propio de la firma del anuncio de prueba.
///
/// Se antepone a `huella ‖ clase ‖ epoch` para que esa firma no pueda valer como firma de otra cosa
/// de la misma clave. El contrato (`CP-R-03`) firmaba solo `huella ‖ clase ‖ epoch`; la orden Q2
/// añade el dominio. Todavía no hay firmas emitidas con el formato viejo.
pub const DOMINIO_FIRMA_ANUNCIO_PRUEBA: &[u8] = b"ZX-ANUNCIO-PRUEBA";

/// A6-02 · Q2: por qué se rechaza la forma o la firma de un [`AnuncioPrueba`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ErrorAnuncio {
    /// La longitud recibida no es [`LONGITUD_ANUNCIO_PRUEBA`].
    #[error("longitud de anuncio de prueba inválida: {0} B")]
    Longitud(usize),
    /// La versión no es [`AnuncioPrueba::VERSION`].
    #[error("versión de anuncio de prueba desconocida: {0}")]
    VersionDesconocida(u8),
    /// La clase no pertenece al conjunto cerrado `{0x01, 0x02, 0x0C}`.
    #[error("clase de prueba fuera del conjunto cerrado: {0:#04x}")]
    ClaseDesconocida(u8),
    /// `len_comprimido` no está en `(0, 352 000]`.
    #[error("len_comprimido fuera de rango: {0}")]
    LenComprimido(u32),
    /// La firma Ed25519 de `clave_productor` no verifica.
    #[error("firma del anuncio de prueba inválida")]
    FirmaInvalida,
}

/// Copia `N` bytes de `bytes[desde..]` sin indexar (evita `clippy::indexing_slicing`).
fn trozo<const N: usize>(bytes: &[u8], desde: usize) -> Option<[u8; N]> {
    let fin = desde.checked_add(N)?;
    <[u8; N]>::try_from(bytes.get(desde..fin)?).ok()
}

/// A6-02 · Q2: anuncio de una prueba **por su huella** (mensaje de difusión de 146 B exactos).
///
/// Cuerpo: `version 1 ‖ clase 1 ‖ huella 32 ‖ clave_productor 32 ‖ epoch 8 (BE) ‖ n_sectores 4 (BE) ‖
/// len_comprimido 4 (BE) ‖ firma 64`. El **cuerpo** de la prueba no viaja aquí: se anuncia y se pide
/// aparte (`CP-R-11`); `zx-p2p` solo comprueba forma y firma antes de entregarlo al nodo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AnuncioPrueba {
    /// Versión del formato; siempre [`Self::VERSION`].
    pub version: u8,
    /// Clase de la prueba: `0x01` PoRep, `0x02` PoSt o `0x0C` turno.
    pub clase: u8,
    /// Huella de 32 B del cuerpo canónico (identificador de la prueba).
    pub huella: [u8; 32],
    /// Clave pública Ed25519 del productor que firma.
    pub clave_productor: ClavePublica,
    /// Época o turno de la prueba.
    pub epoch: u64,
    /// Sectores cubiertos por la prueba.
    pub n_sectores: u32,
    /// Longitud del cuerpo **comprimido** (payload del marco ZRX-C), no del marco completo.
    pub len_comprimido: u32,
    /// Firma Ed25519 de `clave_productor` sobre [`Self::preimagen_firma`].
    pub firma: Firma,
}

impl AnuncioPrueba {
    /// Versión única del formato.
    pub const VERSION: u8 = 1;

    /// Clase `0x01`: PoRep (registro).
    pub const CLASE_POREP: u8 = 0x01;
    /// Clase `0x02`: PoSt.
    pub const CLASE_POST: u8 = 0x02;
    /// Clase `0x0C`: prueba de turno (`0x06` está retirada y no se reutiliza; `REVISION-PTCP.md`).
    pub const CLASE_TURNO: u8 = 0x0C;

    /// ¿Pertenece `clase` al conjunto cerrado `{0x01, 0x02, 0x0C}`?
    #[must_use]
    pub const fn clase_valida(clase: u8) -> bool {
        matches!(
            clase,
            Self::CLASE_POREP | Self::CLASE_POST | Self::CLASE_TURNO
        )
    }

    /// Serializa el anuncio a sus [`LONGITUD_ANUNCIO_PRUEBA`] bytes.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(LONGITUD_ANUNCIO_PRUEBA);
        b.push(self.version);
        b.push(self.clase);
        b.extend_from_slice(&self.huella);
        b.extend_from_slice(self.clave_productor.bytes());
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&self.n_sectores.to_be_bytes());
        b.extend_from_slice(&self.len_comprimido.to_be_bytes());
        b.extend_from_slice(self.firma.bytes());
        b
    }

    /// La preimagen firmada: `"ZX-ANUNCIO-PRUEBA" ‖ huella ‖ clase ‖ epoch (BE)`.
    #[must_use]
    pub fn preimagen_firma(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DOMINIO_FIRMA_ANUNCIO_PRUEBA.len() + 32 + 1 + 8);
        b.extend_from_slice(DOMINIO_FIRMA_ANUNCIO_PRUEBA);
        b.extend_from_slice(&self.huella);
        b.push(self.clase);
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b
    }

    /// Comprueba la **forma** del anuncio, en el orden de Q2: longitud exacta, versión, clase y
    /// `len_comprimido` (el `0 <` va antes que el `≤ 352 000`). **No** verifica la firma.
    ///
    /// # Errores
    /// El [`ErrorAnuncio`] del primer campo que no cumpla.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, ErrorAnuncio> {
        let n = bytes.len();
        if n != LONGITUD_ANUNCIO_PRUEBA {
            return Err(ErrorAnuncio::Longitud(n));
        }
        let Some(&version) = bytes.first() else {
            return Err(ErrorAnuncio::Longitud(n));
        };
        if version != Self::VERSION {
            return Err(ErrorAnuncio::VersionDesconocida(version));
        }
        let Some(&clase) = bytes.get(1) else {
            return Err(ErrorAnuncio::Longitud(n));
        };
        if !Self::clase_valida(clase) {
            return Err(ErrorAnuncio::ClaseDesconocida(clase));
        }
        let huella = trozo::<32>(bytes, 2).ok_or(ErrorAnuncio::Longitud(n))?;
        let clave = trozo::<32>(bytes, 34).ok_or(ErrorAnuncio::Longitud(n))?;
        let epoch = u64::from_be_bytes(trozo::<8>(bytes, 66).ok_or(ErrorAnuncio::Longitud(n))?);
        let n_sectores =
            u32::from_be_bytes(trozo::<4>(bytes, 74).ok_or(ErrorAnuncio::Longitud(n))?);
        let len_comprimido =
            u32::from_be_bytes(trozo::<4>(bytes, 78).ok_or(ErrorAnuncio::Longitud(n))?);
        if len_comprimido == 0
            || u64::from(len_comprimido) > crate::limites::MAX_PRUEBA_COMPRIMIDA_BYTES
        {
            return Err(ErrorAnuncio::LenComprimido(len_comprimido));
        }
        let firma = trozo::<64>(bytes, 82).ok_or(ErrorAnuncio::Longitud(n))?;
        Ok(Self {
            version,
            clase,
            huella,
            clave_productor: ClavePublica::desde_bytes(clave),
            epoch,
            n_sectores,
            len_comprimido,
            firma: Firma::desde_bytes(firma),
        })
    }

    /// Verifica la firma Ed25519 de `clave_productor` sobre [`Self::preimagen_firma`] (ZIP-215).
    ///
    /// # Errores
    /// [`ErrorAnuncio::FirmaInvalida`] si no verifica.
    pub fn verificar_firma(&self) -> Result<(), ErrorAnuncio> {
        verificar(&self.clave_productor, &self.firma, &self.preimagen_firma())
            .map_err(|_| ErrorAnuncio::FirmaInvalida)
    }

    /// Forma **y** firma, en el orden de Q2; es lo que `zx-p2p` exige antes de entregar el anuncio
    /// al nodo.
    ///
    /// # Errores
    /// El [`ErrorAnuncio`] del primer campo que no cumpla.
    pub fn desde_bytes_validado(bytes: &[u8]) -> Result<Self, ErrorAnuncio> {
        let anuncio = Self::desde_bytes(bytes)?;
        anuncio.verificar_firma()?;
        Ok(anuncio)
    }
}

/// Lo que se le pide a un peer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Peticion {
    /// Saludo. Se manda al conectar, antes que nada.
    Estado,
    /// Cabeceras **PoW** a partir del primer hash del locator que el otro reconozca.
    CabecerasPow {
        /// Hashes conocidos, **de la punta hacia atrás**, densos al principio y espaciados después.
        locator: Vec<BlockHash>,
        /// Dónde parar. `None` = hasta donde quepa en la respuesta.
        parada: Option<BlockHash>,
    },
    /// Bloques completos (PoW o PoST), por hash. Solo se piden **tras** validar sus cabeceras.
    Bloques {
        /// Los bloques que faltan, como mucho [`crate::limites::MAX_HASHES_POR_PETICION`].
        hashes: Vec<BlockHash>,
    },
    /// `ORDEN-W06d6` decisión 1: una página del registro de admisión del que responde, empezando
    /// en el índice `desde` (0 = desde el génesis). Sustituye a la resolución de huérfanos PoST de
    /// uno en uno como vía **principal** de puesta al día (la resolución por padres se queda para
    /// los huecos pequeños).
    Registro {
        /// Índice del registro de admisión desde el que empezar (0 = el génesis).
        desde: u64,
    },
    /// `ORDEN-RD1c` (G6): una página del **registro firmado de direcciones** de productores
    /// (`ZXREG1`). Variante nueva al final, sin reordenar los discriminantes existentes.
    RegistroDirecciones {
        /// Índice de la página del registro de direcciones desde el que empezar (0 = el principio).
        desde: u64,
    },
    /// A6-02 · Q3: pide una prueba **entera** por su huella. El cuerpo (opaco) vuelve en
    /// [`Respuesta::Prueba`]. El siguiente discriminante libre tras `RegistroDirecciones` (`0x04`)
    /// es `0x05`; el registro de direcciones no se toca.
    Prueba {
        /// Huella de 32 B del cuerpo canónico pedido.
        huella: [u8; 32],
    },
}

impl Peticion {
    /// Discriminante de wire. Son consenso de protocolo: no se reordenan.
    pub const DISC_ESTADO: u8 = 0x00;
    /// Discriminante de [`Peticion::CabecerasPow`].
    pub const DISC_CABECERAS_POW: u8 = 0x01;
    /// Discriminante de [`Peticion::Bloques`].
    pub const DISC_BLOQUES: u8 = 0x02;
    /// Discriminante de [`Peticion::Registro`]. Nuevo en `ORDEN-W06d6`: se añade al final, sin
    /// reordenar los discriminantes existentes.
    pub const DISC_REGISTRO: u8 = 0x03;

    /// Discriminante de [`Peticion::RegistroDirecciones`]. `ORDEN-RD1c`: se añade al final, sin
    /// reordenar los existentes (0x03 ya es el registro de admisión de `ORDEN-W06d6`).
    pub const DISC_REGISTRO_DIRECCIONES: u8 = 0x04;

    /// Discriminante de [`Peticion::Prueba`]. A6-02: siguiente libre tras `0x04`.
    pub const DISC_PRUEBA: u8 = 0x05;

    /// El byte que identifica esta variante.
    #[must_use]
    pub const fn discriminante(&self) -> u8 {
        match self {
            Self::Estado => Self::DISC_ESTADO,
            Self::CabecerasPow { .. } => Self::DISC_CABECERAS_POW,
            Self::Bloques { .. } => Self::DISC_BLOQUES,
            Self::Registro { .. } => Self::DISC_REGISTRO,
            Self::RegistroDirecciones { .. } => Self::DISC_REGISTRO_DIRECCIONES,
            Self::Prueba { .. } => Self::DISC_PRUEBA,
        }
    }
}

/// Lo que un peer responde.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Respuesta {
    /// Respuesta al saludo.
    Estado(Estado),
    /// Cabeceras **PoW** consecutivas, de menor a mayor altura.
    CabecerasPow(Vec<BlockHeader>),
    /// Bloques completos, **en el orden en que se pidieron**.
    Bloques(Vec<BloqueRed>),
    /// "No tengo eso." No es un error: un peer honesto puede no tener un bloque que ya podó, o que
    /// pertenece a una rama que él descartó.
    ///
    /// Distinguirlo de un error de protocolo importa: esto **no puntúa**.
    NoDisponible,
    /// `ORDEN-W06d6` decisión 1: respuesta a [`Peticion::Registro`]. Como mucho
    /// [`crate::limites::MAX_BLOQUES_POR_RESPUESTA`] bloques y
    /// [`crate::limites::MAX_RESPUESTA_BYTES`] bytes, en el orden real de admisión del que
    /// responde, empezando en `desde`.
    Registro {
        /// El mismo `desde` de la petición (para que quien sincroniza pueda casarlo sin ambigüedad
        /// si algún día hay más de una página en vuelo).
        desde: u64,
        /// Los bloques de esta página, en orden de admisión.
        bloques: Vec<BloqueRed>,
        /// Longitud **total** del registro del que responde, en el momento de responder.
        longitud: u64,
    },
    /// `ORDEN-RD1c` (G6): una página acotada del **registro firmado de direcciones**, con las
    /// mismas cuotas y el mismo presupuesto de red que las demás respuestas. Variante nueva al
    /// final.
    RegistroDirecciones {
        /// El mismo `desde` de la petición.
        desde: u64,
        /// Las entradas de esta página, como mucho
        /// [`crate::limites::MAX_ENTRADAS_REGISTRO_POR_PAGINA`].
        entradas: Vec<EntradaRegistro>,
        /// Longitud **total** del registro del que responde, en el momento de responder.
        total: u64,
    },
    /// A6-02 · Q3: la prueba pedida, entera y **opaca** para `zx-p2p`. `bytes` es el marco ZRX-C
    /// completo (payload ≤ 352 000 B + cabecera de 35 B); su tope es
    /// [`crate::limites::MAX_RESPUESTA_PRUEBA_BYTES`]. El siguiente discriminante libre tras
    /// `RegistroDirecciones` (`0x05`) es `0x06`.
    Prueba {
        /// La huella pedida; debe casar con la de la petición o la respuesta se rechaza.
        huella: [u8; 32],
        /// El marco ZRX-C de la prueba, opaco.
        bytes: Vec<u8>,
    },
}

impl Respuesta {
    /// Discriminante de [`Respuesta::Estado`].
    pub const DISC_ESTADO: u8 = 0x00;
    /// Discriminante de [`Respuesta::CabecerasPow`].
    pub const DISC_CABECERAS_POW: u8 = 0x01;
    /// Discriminante de [`Respuesta::Bloques`].
    pub const DISC_BLOQUES: u8 = 0x02;
    /// Discriminante de [`Respuesta::NoDisponible`].
    pub const DISC_NO_DISPONIBLE: u8 = 0x03;
    /// Discriminante de [`Respuesta::Registro`]. Nuevo en `ORDEN-W06d6`: al final, sin reordenar.
    pub const DISC_REGISTRO: u8 = 0x04;

    /// Discriminante de [`Respuesta::RegistroDirecciones`]. `ORDEN-RD1c`: al final, sin reordenar.
    pub const DISC_REGISTRO_DIRECCIONES: u8 = 0x05;

    /// Discriminante de [`Respuesta::Prueba`]. A6-02: siguiente libre tras `0x05`.
    pub const DISC_PRUEBA: u8 = 0x06;

    /// El byte que identifica esta variante.
    #[must_use]
    pub const fn discriminante(&self) -> u8 {
        match self {
            Self::Estado(_) => Self::DISC_ESTADO,
            Self::CabecerasPow(_) => Self::DISC_CABECERAS_POW,
            Self::Bloques(_) => Self::DISC_BLOQUES,
            Self::NoDisponible => Self::DISC_NO_DISPONIBLE,
            Self::Registro { .. } => Self::DISC_REGISTRO,
            Self::RegistroDirecciones { .. } => Self::DISC_REGISTRO_DIRECCIONES,
            Self::Prueba { .. } => Self::DISC_PRUEBA,
        }
    }

    /// ¿Responde esta respuesta a esa petición?
    ///
    /// libp2p correlaciona petición y respuesta por identificador de stream, así que un peer no
    /// puede colar una respuesta a una petición que no hiciste. Pero **sí puede responder con el
    /// tipo equivocado**: pides cabeceras y te manda bloques. Sin esta comprobación, el código de
    /// sincronización tendría que hacer `match` sobre una respuesta que no espera, y el camino menos
    /// malo de ese `match` acaba siendo ignorarla en silencio.
    #[must_use]
    pub const fn responde_a(&self, p: &Peticion) -> bool {
        matches!(
            (self, p),
            (Self::Estado(_), Peticion::Estado)
                | (Self::CabecerasPow(_), Peticion::CabecerasPow { .. })
                | (Self::Bloques(_), Peticion::Bloques { .. })
                | (Self::Registro { .. }, Peticion::Registro { .. })
                | (
                    Self::RegistroDirecciones { .. },
                    Peticion::RegistroDirecciones { .. }
                )
                | (Self::Prueba { .. }, Peticion::Prueba { .. })
                // NoDisponible vale para cualquier petición de datos, pero NO para el saludo:
                // un peer que no sabe decir quién es no sirve para nada.
                | (
                    Self::NoDisponible,
                    Peticion::CabecerasPow { .. }
                        | Peticion::Bloques { .. }
                        | Peticion::Registro { .. }
                        | Peticion::RegistroDirecciones { .. }
                        | Peticion::Prueba { .. }
                )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Estado, FamiliaBloque, Fase, MAX_PUNTAS_POST, Peticion, PuntaPow, Respuesta,
        red_desde_discriminante, red_discriminante,
    };
    use zx_core::digest::{BlockHash, Digest};
    use zx_core::red::Red;

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn estado() -> Estado {
        Estado {
            hash_genesis: h(1),
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: h(2),
                altura: 100,
                trabajo_acumulado: [3; 32],
            },
            terminal: None,
            puntas_post: vec![h(4)],
            blue_work_virtual: [5; 32],
            longitud_registro: 42,
        }
    }

    /// Los discriminantes son distintos entre sí en cada enum. Si dos coincidieran, un mensaje se
    /// decodificaría como otro.
    #[test]
    fn los_discriminantes_no_colisionan() {
        let peticiones = [
            Peticion::Estado,
            Peticion::CabecerasPow {
                locator: vec![],
                parada: None,
            },
            Peticion::Bloques { hashes: vec![] },
            Peticion::Registro { desde: 0 },
            Peticion::RegistroDirecciones { desde: 0 },
        ];
        let mut vistos = Vec::new();
        for p in &peticiones {
            assert!(!vistos.contains(&p.discriminante()), "{p:?} colisiona");
            vistos.push(p.discriminante());
        }

        let respuestas = [
            Respuesta::Estado(estado()),
            Respuesta::CabecerasPow(vec![]),
            Respuesta::Bloques(vec![]),
            Respuesta::NoDisponible,
            Respuesta::Registro {
                desde: 0,
                bloques: vec![],
                longitud: 0,
            },
            Respuesta::RegistroDirecciones {
                desde: 0,
                entradas: vec![],
                total: 0,
            },
        ];
        let mut vistos = Vec::new();
        for r in &respuestas {
            assert!(!vistos.contains(&r.discriminante()), "{r:?} colisiona");
            vistos.push(r.discriminante());
        }

        assert_eq!(Peticion::Estado.discriminante(), 0x00);
        assert_eq!(Peticion::DISC_CABECERAS_POW, 0x01);
        assert_eq!(Peticion::DISC_BLOQUES, 0x02);
        assert_eq!(Peticion::DISC_REGISTRO, 0x03);
        assert_eq!(Peticion::DISC_REGISTRO_DIRECCIONES, 0x04);
        assert_eq!(Respuesta::DISC_ESTADO, 0x00);
        assert_eq!(Respuesta::DISC_CABECERAS_POW, 0x01);
        assert_eq!(Respuesta::DISC_BLOQUES, 0x02);
        assert_eq!(Respuesta::DISC_NO_DISPONIBLE, 0x03);
        assert_eq!(Respuesta::DISC_REGISTRO, 0x04);
        assert_eq!(Respuesta::DISC_REGISTRO_DIRECCIONES, 0x05);
    }

    /// Cada familia y cada fase tiene su byte, y no se interpreta un byte desconocido.
    #[test]
    fn las_familias_y_fases_tienen_byte_cerrado() {
        assert_eq!(FamiliaBloque::Pow.discriminante(), 0x00);
        assert_eq!(FamiliaBloque::Post.discriminante(), 0x01);
        assert_eq!(FamiliaBloque::desde_byte(0x00), Some(FamiliaBloque::Pow));
        assert_eq!(FamiliaBloque::desde_byte(0x01), Some(FamiliaBloque::Post));
        for b in [0x02u8, 0x7f, 0xff] {
            assert_eq!(FamiliaBloque::desde_byte(b), None, "familia {b:#04x}");
        }

        assert_eq!(Fase::Pow.discriminante(), 0x00);
        assert_eq!(Fase::Post.discriminante(), 0x01);
        assert_eq!(Fase::desde_byte(0x01), Some(Fase::Post));
        assert_eq!(Fase::desde_byte(0x02), None);
    }

    /// El byte de red está cerrado: cada `Red` tiene el suyo y ninguno se adivina.
    #[test]
    fn el_byte_de_red_es_cerrado() {
        for red in [Red::Mainnet, Red::Testnet, Red::Dev] {
            let b = red_discriminante(red);
            assert_eq!(red_desde_discriminante(b), Some(red), "{red:?}");
        }
        assert_eq!(red_desde_discriminante(0x03), None);
        assert_eq!(red_desde_discriminante(0xff), None);
    }

    /// Cada respuesta responde a su petición y **solo** a la suya.
    #[test]
    fn una_respuesta_del_tipo_equivocado_se_detecta() {
        let cabeceras = Peticion::CabecerasPow {
            locator: vec![h(1)],
            parada: None,
        };
        let bloques = Peticion::Bloques { hashes: vec![h(1)] };

        assert!(Respuesta::Estado(estado()).responde_a(&Peticion::Estado));
        assert!(Respuesta::CabecerasPow(vec![]).responde_a(&cabeceras));
        assert!(Respuesta::Bloques(vec![]).responde_a(&bloques));

        assert!(!Respuesta::CabecerasPow(vec![]).responde_a(&bloques));
        assert!(!Respuesta::Bloques(vec![]).responde_a(&cabeceras));
        assert!(!Respuesta::Estado(estado()).responde_a(&cabeceras));
        assert!(!Respuesta::CabecerasPow(vec![]).responde_a(&Peticion::Estado));
    }

    /// `NoDisponible` vale para datos, **nunca** para el saludo.
    #[test]
    fn no_disponible_no_vale_como_saludo() {
        assert!(!Respuesta::NoDisponible.responde_a(&Peticion::Estado));
        assert!(Respuesta::NoDisponible.responde_a(&Peticion::Bloques { hashes: vec![] }));
        assert!(Respuesta::NoDisponible.responde_a(&Peticion::CabecerasPow {
            locator: vec![],
            parada: None
        }));
        assert!(Respuesta::NoDisponible.responde_a(&Peticion::Registro { desde: 0 }));
        assert!(Respuesta::NoDisponible.responde_a(&Peticion::RegistroDirecciones { desde: 0 }));
    }

    /// `ORDEN-W06d6` decisión 1: `Respuesta::Registro` responde solo a `Peticion::Registro`.
    #[test]
    fn registro_responde_solo_a_registro() {
        let peticion_registro = Peticion::Registro { desde: 7 };
        let respuesta_registro = Respuesta::Registro {
            desde: 7,
            bloques: vec![],
            longitud: 10,
        };
        assert!(respuesta_registro.responde_a(&peticion_registro));
        assert!(!respuesta_registro.responde_a(&Peticion::Estado));
        assert!(!Respuesta::Bloques(vec![]).responde_a(&peticion_registro));
        assert!(!Respuesta::CabecerasPow(vec![]).responde_a(&peticion_registro));
    }

    /// **ORDEN-RD1c (G6).** `Respuesta::RegistroDirecciones` responde **solo** a su petición: una
    /// respuesta de otro tipo se rechaza.
    #[test]
    fn respuesta_registro_de_otro_tipo_se_rechaza() {
        let peticion = Peticion::RegistroDirecciones { desde: 3 };
        let respuesta = Respuesta::RegistroDirecciones {
            desde: 3,
            entradas: vec![],
            total: 0,
        };
        assert!(respuesta.responde_a(&peticion));
        assert!(!respuesta.responde_a(&Peticion::Estado));
        assert!(!respuesta.responde_a(&Peticion::Registro { desde: 3 }));
        assert!(
            !Respuesta::Registro {
                desde: 3,
                bloques: vec![],
                longitud: 0
            }
            .responde_a(&peticion)
        );
        assert!(!Respuesta::Bloques(vec![]).responde_a(&peticion));
        assert!(!Respuesta::CabecerasPow(vec![]).responde_a(&peticion));
    }

    /// La cota de puntas PoST es la declarada.
    #[test]
    fn la_cota_de_puntas_post_es_dieciseis() {
        assert_eq!(MAX_PUNTAS_POST, 16);
    }
}
