//! Registro de sectores (`C-SEC-01`…`C-SEC-16`) — port a Rust del oráculo de SR-0.
//!
//! Este módulo es la **transición de Rust** del registro de sectores: tipos canónicos, autómata de
//! ciclo de vida, contabilidad de garantía por sector, elegibilidad desde `past(B)`, undo por delta
//! y reorganización por prefijo común. Es la traducción fiel de
//! `P-ZRX/P-REGISTRO-SECTORES/SR0/src/{modelo,referencia,rapido,contrato}.jl` a enteros exactos
//! (`i64`/`u64`), sin coma flotante y sin dependencias externas nuevas.
//!
//! Las reglas `C-SEC-*` viven aquí:
//!
//! | Regla | Función |
//! |---|---|
//! | `C-SEC-01` identidad y estados | [`SectorId`], [`Etapa`], [`EstadoEfectivo`], [`estado_efectivo`] |
//! | `C-SEC-02` alta | [`AplicadorSector::op_alta`] |
//! | `C-SEC-03` activación | [`AplicadorSector::materializar`] |
//! | `C-SEC-04` renovación | [`AplicadorSector::op_renovar`] |
//! | `C-SEC-05` auditoría / suspensión | [`AplicadorSector::op_abrir_aud`], [`estado_efectivo`] |
//! | `C-SEC-06` recuperación | [`AplicadorSector::op_contestar`] |
//! | `C-SEC-07` expiración | [`AplicadorSector::materializar`] |
//! | `C-SEC-08` retirada / liberación (DP-7: EV-24(i)+(ii)) | [`AplicadorSector::op_retirar_sector`], [`AplicadorSector::materializar`] |
//! | `C-SEC-09` garantía por sector | [`requisito`], [`fianza_comprometida`], [`invariante_requisito`] |
//! | `C-SEC-10` valor y cascada de confiscación (DP-8) | [`AplicadorSector::debitar_cuenta`], [`AplicadorSector::op_evidencia`] |
//! | `C-SEC-11` undo en reorganizaciones | [`deshacer`], [`revertir_a`](AplicadorSector::revertir_a), [`avanzar`] |
//! | `C-SEC-12` consulta y elegibilidad | [`elegible`] |
//! | `C-SEC-13` rechazos explícitos | [`MotivoSector`] |
//! | `C-SEC-14` interfaz de prueba sucinta (inerte) | [`prueba_sucinta`] |
//! | `C-SEC-15` `FuentePeso` | [`fuente_peso`] |
//! | `C-SEC-16` coste de entrada | [`coste_entrada`] |
//!
//! Los parámetros de red son **símbolos** ([`ParametrosSector`]); los valores de [`fixture`] son los
//! del oráculo SR-0 y **no** son parámetros de consenso.

use std::collections::{BTreeMap, BTreeSet};

use zx_core::ClavePublica;

/// Compromiso `R2` de 32 B (representante de anchura fija).
pub type R2 = [u64; 4];

/// Marca de «no aplica» para slots.
pub const NO_HAY: i64 = -1;

/// Clave de un productor concreta usada por los generadores (`Clave(n)` del oráculo).
///
/// Solo para pruebas y vectores: en consenso la clave es una [`ClavePublica`] real.
#[must_use]
pub fn clave_de(n: u8) -> ClavePublica {
    ClavePublica::desde_bytes([n; 32])
}

/// Identidad lógica del sector: `(clave, sector_index, version)` (`C-SEC-01`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SectorId {
    /// Clave del productor.
    pub clave: ClavePublica,
    /// Índice de sector (`sol.sector_index`).
    pub sector_index: u16,
    /// Versión que distingue reciclados del mismo `(clave, sector_index)`.
    pub version: u32,
}

/// Sectores de una clave, en el mismo orden ascendente que el mapa completo.
/// `SectorId` y `ClavePublica` derivan `Ord`: la clave es el primer campo y todos
/// sus índices/versiones están entre estos dos extremos inclusivos.
pub(crate) fn sectores_de_clave<'a>(
    sectores: &'a BTreeMap<SectorId, RegistroSector>,
    clave: &ClavePublica,
) -> std::collections::btree_map::Range<'a, SectorId, RegistroSector> {
    sectores.range(
        SectorId {
            clave: *clave,
            sector_index: 0,
            version: 0,
        }..=SectorId {
            clave: *clave,
            sector_index: u16::MAX,
            version: u32::MAX,
        },
    )
}

/// Etapa **almacenada** del registro (`C-SEC-01`). `Suspendido` es derivado, no está aquí.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Etapa {
    /// Almacenado pero aún no maduro.
    Precomprometido = 0,
    /// Activo nominal.
    Activo = 1,
    /// En retirada, reteniendo la fianza.
    EnRetirada = 2,
    /// Retirado (terminal).
    Retirado = 3,
    /// Caducado (terminal).
    Caducado = 4,
}

/// Estado **efectivo** de un sector en un slot (`C-SEC-01`, `C-SEC-05`, `C-SEC-07`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EstadoEfectivo {
    /// Aún no maduro.
    Precomprometido,
    /// Activo.
    Activo,
    /// Suspendido (fianza incompleta o auditoría sin contestar a plazo).
    Suspendido,
    /// En retirada.
    EnRetirada,
    /// Retirado.
    Retirado,
    /// Caducado.
    Caducado,
}

/// Motivo de aceptación o rechazo de una operación (`C-SEC-13`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MotivoSector {
    /// Aceptada.
    Ok = 0,
    /// Firma ausente.
    ErrFirma = 1,
    /// Doble alta de la misma versión.
    ErrDobleAlta = 2,
    /// Salto o reutilización de versión inválida.
    ErrVersion = 3,
    /// `history_size` fuera de `[h_min, h_max]`.
    ErrHistory = 4,
    /// Fianza insuficiente.
    ErrFianza = 5,
    /// Estado o elegibilidad inválidos.
    ErrEstado = 6,
    /// Fuera de plazo.
    ErrPlazo = 7,
    /// Prueba ausente o inválida.
    ErrPrueba = 8,
    /// Auditoría inexistente o duplicada.
    ErrAuditoria = 9,
    /// No existe sector vivo.
    ErrNoExiste = 10,
    /// Ya hay una retirada de valor pendiente.
    ErrRetiroPendiente = 11,
    /// Límite violado (segunda auditoría).
    ErrLimite = 12,
    /// Desbordamiento aritmético.
    ErrDesbordamiento = 13,
    /// `SR-G2b` · añadir antes de que madure el hueco anterior de la caja
    /// (`slot ≥ ultima_alta_slot + M_sec`, `C-CAJA-04`).
    ErrMaduracion = 14,
    /// FV-4b-N4 · R-ECL-06: la clave BLS ya está registrada bajo **otra** identidad Ed25519.
    ErrClaveVotoDuplicada = 15,
    /// RK-2 · V3: la identidad ya tiene una clave de voto anterior **viva** (retención en curso);
    /// no se admite una segunda rotación.
    ErrClaveVotoRotacionViva = 16,
}

impl MotivoSector {
    /// Nombre canónico usado por los vectores de SR-0.
    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::ErrFirma => "ERR_FIRMA",
            Self::ErrDobleAlta => "ERR_DOBLE_ALTA",
            Self::ErrVersion => "ERR_VERSION",
            Self::ErrHistory => "ERR_HISTORY",
            Self::ErrFianza => "ERR_FIANZA",
            Self::ErrEstado => "ERR_ESTADO",
            Self::ErrPlazo => "ERR_PLAZO",
            Self::ErrPrueba => "ERR_PRUEBA",
            Self::ErrAuditoria => "ERR_AUDITORIA",
            Self::ErrNoExiste => "ERR_NO_EXISTE",
            Self::ErrRetiroPendiente => "ERR_RETIRO_PENDIENTE",
            Self::ErrLimite => "ERR_LIMITE",
            Self::ErrDesbordamiento => "ERR_DESBORDAMIENTO",
            Self::ErrMaduracion => "ERR_MADURACION",
            Self::ErrClaveVotoDuplicada => "ERR_CLAVE_VOTO_DUPLICADA",
            Self::ErrClaveVotoRotacionViva => "ERR_CLAVE_VOTO_ROTACION_VIVA",
        }
    }
}

/// Parámetros simbólicos del autómata (`DP-2`…`DP-6`, `DP-13`).
///
/// **Ningún** valor es de red: [`Self::fixture`] reproduce el perfil del oráculo SR-0 y
/// [`Self::dev`] es el perfil dev que cumple las desigualdades de `DECISIONES-PENDIENTES.md`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParametrosSector {
    /// Fianza por sector (`q_sec`, u.e.).
    pub q_sec: i64,
    /// Maduración `precomprometido → activo` (`M_sec`, slots).
    pub m_sec: i64,
    /// Caducidad desde activación/renovación (`T_cad`, slots).
    pub t_cad: i64,
    /// Plazo de contestación de auditoría (`P_aud`, slots).
    pub p_aud: i64,
    /// Ventana de recuperación (`P_rec`, slots).
    pub p_rec: i64,
    /// Retención de la fianza en retirada (`R_sec`, slots).
    pub r_sec: i64,
    /// Cota inferior de `history_size`.
    pub h_min: u64,
    /// Cota superior de `history_size`.
    pub h_max: u64,
    /// Retención de la garantía por clave (`R_slots`).
    pub r_slots: i64,
    /// RV-3 · Retención por votos (`R_V`, slots) desde la retirada de un sector o de un importe de
    /// garantía. Es una cota **además** de `r_sec`/`r_slots`; con `0` el comportamiento es el
    /// anterior a RET-1a (perfil `fixture`).
    pub r_votos_slots: i64,
    /// Ventana de admisión de evidencia (`Plazo_slots`).
    pub plazo_slots: i64,
    /// Margen de inclusión (`M_margen_slots`).
    pub m_margen_slots: i64,
    /// Madurez del crédito D-T08 (`M_rec_slots`).
    pub m_rec_slots: i64,
    /// Numerador de la fracción confiscada `f = f_num/f_den` (`EV-19`).
    pub f_num: i64,
    /// Denominador de `f`.
    pub f_den: i64,
    /// Cota de operaciones por bloque (`max_ops_bloque`, `DP-13`).
    pub max_ops_bloque: usize,
    /// Capacidad de una caja (`PK-14`): 1 reproduce SR-0; 16 es la caja de PK-14.
    ///
    /// `SR-G2b` · `C-CAJA-02`. No es un valor de red fijado por este carril más allá del fixture.
    pub capacidad_caja: usize,
    /// PT-3bc · `T_prueba`: longitud de la ventana de la PoSt diaria (slots).
    ///
    /// La ventana de cada clave **empieza** en `H(clave) mod T_prueba` (`REVISION-PT3a` decisión 4).
    pub t_prueba: i64,
    /// PT-3bc · `T_gracia`: desde `slot − slot_prueba > T_gracia` la prueba deja de pesar.
    pub t_gracia: i64,
    /// PT-3bc · `F_slots` de la PoRep: los retos salen del faro PoT de un slot
    /// `≥ slot(Alta) + F_slots`. `0` desactiva el adelanto (fixture).
    pub f_slots: i64,
    /// PT-3bc · puerta de peso/activación de la prueba de almacenamiento.
    ///
    /// `false` en dev hasta PT-3d: las reglas nuevas de estado se aplican (se registran pruebas y
    /// claves de voto, se aceptan las tx v6) pero **sin** la puerta de peso ni el requisito de PoRep
    /// para activar. Fuera de dev el perfil lo fuerza a `true`.
    pub exigir_prueba_almacenamiento: bool,
}

impl ParametrosSector {
    /// Perfil de fixture del oráculo SR-0. **No** son parámetros de red.
    #[must_use]
    pub const fn fixture() -> Self {
        Self {
            q_sec: 10,
            m_sec: 5,
            t_cad: 100,
            p_aud: 8,
            p_rec: 4,
            r_sec: 30,
            h_min: 1,
            h_max: 1 << 20,
            r_slots: 20,
            r_votos_slots: 0,
            plazo_slots: 6,
            m_margen_slots: 2,
            m_rec_slots: 3,
            f_num: 1,
            f_den: 1,
            max_ops_bloque: 64,
            capacidad_caja: 1,
            t_prueba: 5,
            t_gracia: 10,
            f_slots: 0,
            exigir_prueba_almacenamiento: false,
        }
    }

    /// Perfil **dev** declarado en `INFORME.md` (cumple las desigualdades de
    /// `DECISIONES-PENDIENTES.md`: `M_sec > 0`, `M_sec < T_cad`, `T_cad > M_sec + P_aud + P_rec`,
    /// `R_sec > P_aud + P_rec`, `P_rec < T_cad − M_sec`, `P_aud > 0`, `R_sec > 0`).
    #[must_use]
    pub const fn dev() -> Self {
        Self {
            q_sec: 140,
            m_sec: 12,
            t_cad: 600,
            p_aud: 24,
            p_rec: 16,
            r_sec: 96,
            h_min: 1,
            h_max: 1 << 20,
            r_slots: 600,
            // RV-3 · `(L + G)·T_inst + plazo_slots + m_margen_slots = (2 + 330)·2 + 300 + 60`;
            // `L = 2` ventanas es lo que tarda una clave en retirada en dejar de entrar en tablas
            // nuevas; `REVISION-RETM1.md`.
            r_votos_slots: 1_024,
            plazo_slots: 300,
            m_margen_slots: 60,
            m_rec_slots: 24,
            f_num: 1,
            f_den: 1,
            max_ops_bloque: 64,
            capacidad_caja: 16,
            t_prueba: 67_500,
            t_gracia: 135_000,
            f_slots: 0,
            exigir_prueba_almacenamiento: false,
        }
    }
}

/// Registro de un sector (`C-SEC-01`). Cabe en copia de valor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegistroSector {
    /// Identidad.
    pub id: SectorId,
    /// Compromiso `R2`.
    pub r2: R2,
    /// `history_size` registrado.
    pub history_size: u64,
    /// Etapa almacenada.
    pub etapa: Etapa,
    /// Slot de alta.
    pub alta_slot: i64,
    /// Slot desde el que cuenta `T_cad`.
    pub renovacion_slot: i64,
    /// Slot de retirada (`-1` si no está en retirada).
    pub retiro_slot: i64,
    /// Fianza retenida (`q_sec` mientras retiene; `0` al liberar).
    pub fianza: i64,
    /// Slot de apertura de auditoría (`-1` si no hay).
    pub aud_apertura: i64,
    /// Slot de contestación aceptada (`-1` si no contestada).
    pub aud_contestada: i64,
}

impl RegistroSector {
    /// ¿Es terminal (no retiene fianza ni es elegible)?
    #[must_use]
    pub const fn es_terminal(&self) -> bool {
        matches!(self.etapa, Etapa::Retirado | Etapa::Caducado)
    }
}

/// PT-3bc · prueba de almacenamiento **vigente** de una clave (`Estado.pruebas`, `C-SEC-15`).
///
/// Se fija al aplicar una tx v6 de clase `0x02` (PoSt diaria). La puerta de peso la consulta
/// [`prueba_vigente`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PruebaVigente {
    /// Slot de la ventana en que se probó (`slot_prueba`).
    pub slot_prueba: i64,
    /// Raíz del conjunto de sectores cubiertos (`raiz_conjunto`).
    pub raiz_conjunto: R2,
    /// Número de sectores cubiertos.
    pub n_sectores: u32,
}

/// PT-3bc · atestación PoRep de un lote de altas (`Estado.poreps`, `REVISION-PT3a` decisión 5).
///
/// Se fija al aplicar una tx v6 de clase `0x01`. La activación en dos fases de un sector
/// `Precomprometido` la consulta `transicion::sector::materializar_sectores`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PorepVigente {
    /// Slot de la ventana (faro PoT) de la que salen los retos.
    pub slot_ventana: i64,
    /// Raíz del lote cubierto.
    pub raiz_lote: R2,
    /// Número de sectores cubiertos.
    pub n_sectores: u32,
}

/// PT-3bc · clave BLS de voto con su prueba de posesión (`Estado.claves_voto`, `PK-04`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClaveVoto {
    /// Clave pública BLS (G1 comprimido, 48 B).
    pub clave_bls: [u8; 48],
    /// Prueba de posesión (firma en G2 comprimida, 96 B).
    pub prueba_posesion: [u8; 96],
}

/// RK-2 · V2 · clave de voto **anterior** de una identidad y el slot hasta el que sigue viva.
///
/// La guarda el estado (`Estado.claves_voto_previas`) cuando una identidad que ya tenía clave de
/// voto registra **otra** distinta con la operación `0x03`. La clave anterior sigue atribuida a su
/// identidad (castigo, ausencia, certificado y acta, voto propio) mientras `slot ≤ vencimiento`
/// (V5). No entra en el formato de votos, tablas ni certificados (V7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClaveVotoAnterior {
    /// Clave pública BLS anterior (G1 comprimido, 48 B).
    pub clave_bls: [u8; 48],
    /// Prueba de posesión de la clave anterior (firma en G2 comprimida, 96 B).
    pub prueba_posesion: [u8; 96],
    /// Slot hasta el que la clave anterior sigue viva, **inclusive** (`s + retención`).
    pub vencimiento: u64,
}

/// Pendiente con su slot de madurez (`D-T08`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pendiente {
    /// Importe.
    pub importe: i64,
    /// Slot de madurez.
    pub madura_slot: i64,
}

/// Retirada viva (`C-SEC-10`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Retiro {
    /// Importe.
    pub importe: i64,
    /// Slot desde el que cuenta `R_slots`.
    pub inicio_slot: i64,
}

/// Incidente de evidencia admitido (`EV-11`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Incidente {
    /// Identificador determinista.
    pub id: u64,
    /// `slot_falta` del incidente.
    pub slot_falta: i64,
}

/// Cuenta de garantía de una clave (`C-BON-01`, `EV-17`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CuentaGarantia {
    /// Clave.
    pub clave: ClavePublica,
    /// Garantía activa.
    pub activo: i64,
    /// Pendientes con madurez.
    pub pendientes: Vec<Pendiente>,
    /// Retiradas vivas.
    pub en_retirada: Vec<Retiro>,
    /// Créditos D-T08 pendientes.
    pub creditos: Vec<Pendiente>,
    /// Gravamen **derivado** (no es sub-cuenta).
    pub congelado: i64,
    /// Incidentes admitidos.
    pub incidentes: Vec<Incidente>,
    /// `último_slot_producido(P)` (`EV-24(ii)`), `-1` si no aplica.
    pub ultimo_slot_producido: i64,
}

impl CuentaGarantia {
    /// Cuenta vacía.
    #[must_use]
    pub const fn nueva(clave: ClavePublica) -> Self {
        Self {
            clave,
            activo: 0,
            pendientes: Vec::new(),
            en_retirada: Vec::new(),
            creditos: Vec::new(),
            congelado: 0,
            incidentes: Vec::new(),
            ultimo_slot_producido: NO_HAY,
        }
    }
}

/// Suma de una cuenta (`EV-19`): `activo + pendientes + en_retirada + créditos`.
#[must_use]
pub fn total_cuenta(c: &CuentaGarantia) -> i64 {
    let mut t = c.activo;
    for p in &c.pendientes {
        t = t.saturating_add(p.importe);
    }
    for r in &c.en_retirada {
        t = t.saturating_add(r.importe);
    }
    for p in &c.creditos {
        t = t.saturating_add(p.importe);
    }
    t
}

/// Estado de consenso del registro de sectores y su contabilidad de valor.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EstadoSector {
    /// Registro ordenado por [`SectorId`].
    pub sectores: BTreeMap<SectorId, RegistroSector>,
    /// Cuentas de garantía ordenadas por clave.
    pub garantias: BTreeMap<ClavePublica, CuentaGarantia>,
    /// UTXO total (modelo reducido).
    pub utxo_total: i64,
    /// Emitido.
    pub emitido: i64,
    /// Quemado.
    pub quemado: i64,
    /// Slot actual.
    pub slot_actual: i64,
    /// PT-3bc · prueba de almacenamiento vigente por clave (`C-SEC-15`).
    pub pruebas: BTreeMap<ClavePublica, PruebaVigente>,
    /// PT-3bc · atestación PoRep por clave (activación en dos fases).
    pub poreps: BTreeMap<ClavePublica, PorepVigente>,
    /// PT-3bc · clave BLS de voto por clave con su prueba de posesión.
    pub claves_voto: BTreeMap<ClavePublica, ClaveVoto>,
}

/// Undo por **delta** de un bloque (o de una operación): escalares previos y valor previo (o
/// ausencia) de cada sector/cuenta tocados (`C-SEC-11`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UndoSector {
    /// `utxo_total` previo.
    pub utxo_total: i64,
    /// `emitido` previo.
    pub emitido: i64,
    /// `quemado` previo.
    pub quemado: i64,
    /// `slot_actual` previo.
    pub slot_actual: i64,
    /// `(id, valor previo)` en orden de primer toque.
    pub sectores: Vec<(SectorId, Option<RegistroSector>)>,
    /// `(clave, valor previo)` en orden de primer toque.
    pub garantias: Vec<(ClavePublica, Option<CuentaGarantia>)>,
    pub(crate) vistos_s: BTreeSet<SectorId>,
    pub(crate) vistos_g: BTreeSet<ClavePublica>,
}

/// Marca de posición dentro de un [`UndoSector`] (descarte de una operación).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MarcaSector {
    /// Longitud de la lista de sectores.
    pub sectores: usize,
    /// Longitud de la lista de garantías.
    pub garantias: usize,
}

/// Estado efectivo de `r` en `slot` (`C-SEC-01`, `C-SEC-03`, `C-SEC-05`, `C-SEC-07`).
#[must_use]
pub fn estado_efectivo(r: &RegistroSector, slot: i64, p: &ParametrosSector) -> EstadoEfectivo {
    match r.etapa {
        Etapa::Retirado => EstadoEfectivo::Retirado,
        Etapa::Caducado => EstadoEfectivo::Caducado,
        Etapa::EnRetirada => EstadoEfectivo::EnRetirada,
        Etapa::Precomprometido => {
            if slot >= r.alta_slot.saturating_add(p.m_sec) {
                EstadoEfectivo::Activo
            } else {
                EstadoEfectivo::Precomprometido
            }
        }
        Etapa::Activo => {
            if slot >= r.renovacion_slot.saturating_add(p.t_cad) {
                return EstadoEfectivo::Caducado;
            }
            if r.fianza < p.q_sec {
                return EstadoEfectivo::Suspendido;
            }
            if r.aud_apertura >= 0
                && r.aud_contestada < 0
                && slot >= r.aud_apertura.saturating_add(p.p_aud)
            {
                return EstadoEfectivo::Suspendido;
            }
            EstadoEfectivo::Activo
        }
    }
}

/// Índice del sector **vivo** (no terminal) de `(clave, sector_index)`, si existe.
///
/// Si hubiera más de uno, gana la versión mayor (no debería ocurrir).
#[must_use]
pub fn sector_vivo(
    est: &EstadoSector,
    clave: &ClavePublica,
    sector_index: u16,
) -> Option<RegistroSector> {
    let mut mejor: Option<RegistroSector> = None;
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
        if id.clave == *clave && id.sector_index == sector_index && !r.es_terminal() {
            match mejor {
                Some(m) if m.id.version >= id.version => {}
                _ => mejor = Some(*r),
            }
        }
    }
    mejor
}

/// Número de sectores activos de `clave` en `slot` (`C-SEC-09`).
#[must_use]
pub fn sectores_activos(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> i64 {
    let mut n: i64 = 0;
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
        if id.clave == *clave && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo {
            n = n.saturating_add(1);
        }
    }
    n
}

/// PT-3bc · `H(clave) mod T_prueba`: inicio de la ventana de la PoSt de `clave`.
///
/// `H` es `SHA3-256` sin dominio (el digest público de `zx-core`); el offset reparte las ventanas
/// para que las pruebas no lleguen en ráfaga (`REVISION-PT3a` decisión 4).
#[must_use]
pub fn inicio_ventana(clave: &ClavePublica, p: &ParametrosSector) -> i64 {
    if p.t_prueba <= 0 {
        return 0;
    }
    let d = zx_core::sha3_256_publico(clave.bytes());
    let b = d.as_bytes();
    let mut ocho = [0u8; 8];
    if let Some(src) = b.get(..8) {
        ocho.copy_from_slice(src);
    }
    let h = u64::from_le_bytes(ocho);
    let t = u64::try_from(p.t_prueba).unwrap_or(1);
    i64::try_from(h % t).unwrap_or(0)
}

/// PT-3bc · ¿hay prueba de almacenamiento **vigente** de `clave` en `slot`? (`C-SEC-15`).
///
/// Vigente si existe y `slot − slot_prueba ≤ T_gracia`.
#[must_use]
pub fn prueba_vigente(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> bool {
    let Some(pr) = est.pruebas.get(clave) else {
        return false;
    };
    slot.saturating_sub(pr.slot_prueba) <= p.t_gracia
}

/// PT-3bc · raíz del lote de sectores **no terminales** de `clave`.
#[must_use]
pub fn raiz_lote_de(est: &EstadoSector, clave: &ClavePublica) -> R2 {
    let hojas: Vec<R2> = crate::sectores::sectores_de_clave(&est.sectores, clave)
        .filter(|(id, r)| id.clave == *clave && !r.es_terminal())
        .map(|(_, r)| crate::cajas::hoja_ocupada(r.r2))
        .collect();
    if hojas.is_empty() {
        return crate::cajas::hoja_libre();
    }
    crate::cajas::raiz_merkle(&hojas)
}

/// PT-3bc · raíz del conjunto de sectores **`Activo`** de `clave` en `slot` (`C-SEC-15`).
#[must_use]
pub fn raiz_conjunto_de(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> R2 {
    let hojas: Vec<R2> = crate::sectores::sectores_de_clave(&est.sectores, clave)
        .filter(|(id, r)| {
            id.clave == *clave && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo
        })
        .map(|(_, r)| crate::cajas::hoja_ocupada(r.r2))
        .collect();
    if hojas.is_empty() {
        return crate::cajas::hoja_libre();
    }
    crate::cajas::raiz_merkle(&hojas)
}

/// PT-3bc · ¿una atestación PoRep cubre al sector `r`? (`REVISION-PT3a` decisión 5).
///
/// Cubre si existe atestación de la clave, su `raiz_lote` coincide con la raíz actual de los
/// sectores no terminales de la clave y sus retos salen de un faro PoT en
/// `slot_ventana ≥ alta_slot + F_slots`.
#[must_use]
pub fn cubierto_por_porep(est: &EstadoSector, r: &RegistroSector, p: &ParametrosSector) -> bool {
    let Some(po) = est.poreps.get(&r.id.clave) else {
        return false;
    };
    po.n_sectores > 0
        && po.slot_ventana >= r.alta_slot.saturating_add(p.f_slots)
        && po.raiz_lote == raiz_lote_de(est, &r.id.clave)
}

/// `requisito(clave, slot) = q_sec × sectores_activos(clave, slot)` (`C-SEC-09`).
#[must_use]
pub fn requisito(est: &EstadoSector, clave: &ClavePublica, slot: i64, p: &ParametrosSector) -> i64 {
    p.q_sec
        .saturating_mul(sectores_activos(est, clave, slot, p))
}

/// Fianza comprometida de `clave`: suma de fianzas de sectores no terminales.
#[must_use]
pub fn fianza_comprometida(est: &EstadoSector, clave: &ClavePublica) -> i64 {
    let mut t: i64 = 0;
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
        if id.clave == *clave && !r.es_terminal() {
            t = t.saturating_add(r.fianza);
        }
    }
    t
}

/// Total castigable de `clave`: cuenta + fianzas de sus sectores no terminales (`EV-17`).
#[must_use]
pub fn total_castigable(est: &EstadoSector, clave: &ClavePublica) -> i64 {
    let mut t = est.garantias.get(clave).map_or(0, total_cuenta);
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
        if id.clave == *clave && !r.es_terminal() {
            t = t.saturating_add(r.fianza);
        }
    }
    t
}

/// `techo_exacto(f·V)` con enteros (`EV-19`), sin coma flotante.
#[must_use]
pub fn techo_fraccion(v: i64, f_num: i64, f_den: i64) -> i64 {
    if f_den == 0 || f_num == 0 || v <= 0 {
        return 0;
    }
    let num = v
        .saturating_mul(f_num)
        .saturating_add(f_den.saturating_sub(1));
    num.div_euclid(f_den)
}

/// `I-1` extendida: `UTXO + garantías + fianzas no terminales == emitido − quemado`.
#[must_use]
pub fn invariante_valor(est: &EstadoSector) -> bool {
    let mut t = est.utxo_total;
    for c in est.garantias.values() {
        t = t.saturating_add(total_cuenta(c));
    }
    for r in est.sectores.values() {
        if !r.es_terminal() {
            t = t.saturating_add(r.fianza);
        }
    }
    t == est.emitido.saturating_sub(est.quemado)
}

/// `requisito` cubierto: para toda clave, `fianza_comprometida ≥ q_sec × nº activos`.
#[must_use]
pub fn invariante_requisito(est: &EstadoSector, p: &ParametrosSector) -> bool {
    for c in est.garantias.values() {
        let n = sectores_activos(est, &c.clave, est.slot_actual, p);
        if fianza_comprometida(est, &c.clave) < p.q_sec.saturating_mul(n) {
            return false;
        }
    }
    true
}

/// Solución PoAS portadora de la oportunidad.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Solucion {
    /// Clave del productor.
    pub clave: ClavePublica,
    /// Índice de sector.
    pub sector_index: u16,
    /// `history_size`.
    pub history_size: u64,
    /// `chunk` (simbólico).
    pub chunk: u64,
    /// `rango` (simbólico).
    pub rango: u64,
}

/// ¿La solución `sol` es elegible en `est` a `slot`? (`C-SEC-12`).
#[must_use]
pub fn elegible(est: &EstadoSector, sol: &Solucion, slot: i64, p: &ParametrosSector) -> bool {
    let Some(r) = sector_vivo(est, &sol.clave, sol.sector_index) else {
        return false;
    };
    if r.history_size != sol.history_size {
        return false;
    }
    if p.exigir_prueba_almacenamiento && !prueba_vigente(est, &sol.clave, slot, p) {
        return false;
    }
    estado_efectivo(&r, slot, p) == EstadoEfectivo::Activo
}

/// Tipos de operación del autómata.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TipoOp {
    /// Asignación de arranque (coinbase PoW ya depositada).
    Fondear = 0,
    /// Depósito.
    Deposito = 1,
    /// Retiro de valor.
    Retiro = 2,
    /// Liberación de valor.
    Liberacion = 3,
    /// Coinbase PoST.
    CoinbasePost = 4,
    /// Evidencia / confiscación.
    Evidencia = 5,
    /// Alta de sector.
    Alta = 6,
    /// Renovación.
    Renovar = 7,
    /// Apertura de auditoría.
    AbrirAud = 8,
    /// Contestación de auditoría.
    Contestar = 9,
    /// Retirada de sector.
    RetirarSector = 10,
}

/// Operación del autómata (un solo `struct` con todos los campos, como en el oráculo).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Operacion {
    /// Tipo.
    pub tipo: TipoOp,
    /// Clave.
    pub clave: ClavePublica,
    /// Índice de sector.
    pub sector_index: u16,
    /// Versión.
    pub version: u32,
    /// Importe.
    pub importe: i64,
    /// Compromiso `R2`.
    pub r2: R2,
    /// `history_size`.
    pub history_size: u64,
    /// Id de auditoría.
    pub auditoria_id: u64,
    /// `h1` de evidencia.
    pub h1: R2,
    /// `h2` de evidencia.
    pub h2: R2,
    /// Prueba presente.
    pub prueba: bool,
    /// Firma presente.
    pub firma: bool,
}

impl Operacion {
    /// Operación con los valores por defecto del oráculo para `tipo`.
    #[must_use]
    pub const fn base(tipo: TipoOp) -> Self {
        Self {
            tipo,
            clave: ClavePublica::desde_bytes([0; 32]),
            sector_index: 0,
            version: 0,
            importe: 0,
            r2: [0; 4],
            history_size: 0,
            auditoria_id: 0,
            h1: [0; 4],
            h2: [0; 4],
            prueba: true,
            firma: true,
        }
    }
}

/// Identificador determinista de un incidente (`hash` del oráculo, FNV-1a estable).
fn incidente_id(clave: &ClavePublica, si: u16, aud: u64, h1: &R2, h2: &R2) -> u64 {
    let mut bytes = Vec::with_capacity(32 + 2 + 8 + 64);
    bytes.extend_from_slice(clave.bytes());
    bytes.extend_from_slice(&si.to_le_bytes());
    bytes.extend_from_slice(&aud.to_le_bytes());
    for w in h1.iter().chain(h2.iter()) {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Aplicador: referencia mutable al estado en curso y su undo por delta.
pub struct AplicadorSector<'a> {
    /// Estado en curso.
    pub estado: &'a mut EstadoSector,
    /// Undo acumulado.
    pub undo: UndoSector,
}

impl<'a> AplicadorSector<'a> {
    /// Arranca desde `estado` y registra sus escalares previos.
    #[must_use]
    pub fn nuevo(estado: &'a mut EstadoSector) -> Self {
        let undo = UndoSector {
            utxo_total: estado.utxo_total,
            emitido: estado.emitido,
            quemado: estado.quemado,
            slot_actual: estado.slot_actual,
            sectores: Vec::new(),
            garantias: Vec::new(),
            vistos_s: BTreeSet::new(),
            vistos_g: BTreeSet::new(),
        };
        Self { estado, undo }
    }

    /// Marca la posición actual del undo.
    #[must_use]
    pub fn marcar(&self) -> MarcaSector {
        MarcaSector {
            sectores: self.undo.sectores.len(),
            garantias: self.undo.garantias.len(),
        }
    }

    /// Revierte las mutaciones posteriores a `marca` (descarte de operación).
    pub fn revertir_a(&mut self, m: MarcaSector) {
        while self.undo.sectores.len() > m.sectores {
            if let Some((id, prev)) = self.undo.sectores.pop() {
                self.undo.vistos_s.remove(&id);
                match prev {
                    Some(r) => {
                        self.estado.sectores.insert(id, r);
                    }
                    None => {
                        self.estado.sectores.remove(&id);
                    }
                }
            }
        }
        while self.undo.garantias.len() > m.garantias {
            if let Some((clave, prev)) = self.undo.garantias.pop() {
                self.undo.vistos_g.remove(&clave);
                match prev {
                    Some(c) => {
                        self.estado.garantias.insert(clave, c);
                    }
                    None => {
                        self.estado.garantias.remove(&clave);
                    }
                }
            }
        }
    }

    fn tocar_sector(&mut self, id: SectorId) {
        if self.undo.vistos_s.insert(id) {
            let prev = self.estado.sectores.get(&id).copied();
            self.undo.sectores.push((id, prev));
        }
    }

    fn tocar_garantia(&mut self, clave: ClavePublica) {
        if self.undo.vistos_g.insert(clave) {
            let prev = self.estado.garantias.get(&clave).cloned();
            self.undo.garantias.push((clave, prev));
        }
    }

    /// Acceso mutable a la cuenta de `clave`, registrando su valor previo la primera vez.
    pub fn cuenta_mut(&mut self, clave: ClavePublica) -> &mut CuentaGarantia {
        self.tocar_garantia(clave);
        self.estado
            .garantias
            .entry(clave)
            .or_insert_with(|| CuentaGarantia::nueva(clave))
    }

    /// Promueve pendientes y créditos madurados a `activo`.
    pub fn promover(&mut self, slot: i64) {
        let claves: Vec<ClavePublica> = self.estado.garantias.keys().copied().collect();
        for clave in claves {
            let Some(c) = self.estado.garantias.get(&clave) else {
                continue;
            };
            if c.pendientes.is_empty() && c.creditos.is_empty() {
                continue;
            }
            self.tocar_garantia(clave);
            if let Some(cu) = self.estado.garantias.get_mut(&clave) {
                let mut quedan = Vec::with_capacity(cu.pendientes.len());
                for p in cu.pendientes.drain(..) {
                    if p.madura_slot <= slot {
                        cu.activo = cu.activo.saturating_add(p.importe);
                    } else {
                        quedan.push(p);
                    }
                }
                cu.pendientes = quedan;
                let mut quedanc = Vec::with_capacity(cu.creditos.len());
                for p in cu.creditos.drain(..) {
                    if p.madura_slot <= slot {
                        cu.activo = cu.activo.saturating_add(p.importe);
                    } else {
                        quedanc.push(p);
                    }
                }
                cu.creditos = quedanc;
            }
        }
    }

    /// Avanza el estado hasta `slot`: maduraciones, activación, caducidad y liberación de
    /// retiradas (`C-SEC-03`, `C-SEC-07`, `C-SEC-08`).
    pub fn materializar(&mut self, slot: i64, p: &ParametrosSector) {
        if slot < self.estado.slot_actual {
            return;
        }
        self.promover(slot);
        let ids: Vec<SectorId> = self.estado.sectores.keys().copied().collect();
        for id in ids {
            let Some(r) = self.estado.sectores.get(&id).copied() else {
                continue;
            };
            match r.etapa {
                Etapa::Precomprometido
                    if slot >= r.alta_slot.saturating_add(p.m_sec)
                        && (!p.exigir_prueba_almacenamiento
                            || cubierto_por_porep(&*self.estado, &r, p)) =>
                {
                    self.tocar_sector(id);
                    if let Some(rr) = self.estado.sectores.get_mut(&id) {
                        rr.etapa = Etapa::Activo;
                    }
                }
                Etapa::Activo if slot >= r.renovacion_slot.saturating_add(p.t_cad) => {
                    self.tocar_sector(id);
                    if let Some(rr) = self.estado.sectores.get_mut(&id) {
                        rr.etapa = Etapa::Caducado;
                        rr.fianza = 0;
                    }
                    let cu = self.cuenta_mut(id.clave);
                    cu.activo = cu.activo.saturating_add(r.fianza);
                }
                Etapa::EnRetirada
                    if slot >= r.retiro_slot.saturating_add(p.r_sec)
                        && slot >= r.retiro_slot.saturating_add(p.r_votos_slots) =>
                {
                    // DP-7: liberar exige EV-24(i) (sin incidente abierto) **y** EV-24(ii)
                    // (`slot ≥ último_slot_producido + Plazo_slots + M_margen_slots`).
                    let (incidentes, ultimo) = self
                        .estado
                        .garantias
                        .get(&id.clave)
                        .map_or((0, NO_HAY), |c| {
                            (c.incidentes.len(), c.ultimo_slot_producido)
                        });
                    let bloqueada_i = incidentes != 0;
                    let bloqueada_ii = ultimo != NO_HAY
                        && slot
                            < ultimo
                                .saturating_add(p.plazo_slots)
                                .saturating_add(p.m_margen_slots);
                    if bloqueada_i || bloqueada_ii {
                        continue;
                    }
                    self.tocar_sector(id);
                    if let Some(rr) = self.estado.sectores.get_mut(&id) {
                        rr.etapa = Etapa::Retirado;
                        rr.fianza = 0;
                    }
                    let cu = self.cuenta_mut(id.clave);
                    cu.activo = cu.activo.saturating_add(r.fianza);
                }
                _ => {}
            }
        }
        self.estado.slot_actual = slot;
    }

    // ── operaciones de valor ────────────────────────────────────────────────

    /// `OP_FONDEAR`.
    pub fn op_fondear(&mut self, op: &Operacion) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        if op.importe <= 0 {
            return MotivoSector::ErrFianza;
        }
        self.estado.emitido = self.estado.emitido.saturating_add(op.importe);
        let cu = self.cuenta_mut(op.clave);
        cu.activo = cu.activo.saturating_add(op.importe);
        MotivoSector::Ok
    }

    /// `OP_DEPOSITO`.
    pub fn op_deposito(&mut self, op: &Operacion) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        if op.importe <= 0 || self.estado.utxo_total < op.importe {
            return MotivoSector::ErrFianza;
        }
        self.estado.utxo_total -= op.importe;
        let cu = self.cuenta_mut(op.clave);
        cu.activo = cu.activo.saturating_add(op.importe);
        MotivoSector::Ok
    }

    /// `OP_RETIRO` (valor).
    pub fn op_retiro(&mut self, op: &Operacion, slot: i64) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let c = self.cuenta_mut(op.clave);
        if op.importe <= 0 || op.importe > c.activo {
            return MotivoSector::ErrFianza;
        }
        if !c.en_retirada.is_empty() {
            return MotivoSector::ErrRetiroPendiente;
        }
        c.activo -= op.importe;
        c.en_retirada.push(Retiro {
            importe: op.importe,
            inicio_slot: slot,
        });
        MotivoSector::Ok
    }

    /// `OP_LIBERACION` (valor, `EV-15b`/`EV-24`).
    pub fn op_liberacion(
        &mut self,
        op: &Operacion,
        slot: i64,
        p: &ParametrosSector,
    ) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let c = self.cuenta_mut(op.clave);
        if !c.incidentes.is_empty() {
            return MotivoSector::ErrEstado;
        }
        if c.ultimo_slot_producido != NO_HAY
            && slot
                < c.ultimo_slot_producido
                    .saturating_add(p.plazo_slots)
                    .saturating_add(p.m_margen_slots)
        {
            return MotivoSector::ErrPlazo;
        }
        let mut vencido: i64 = 0;
        for r in &c.en_retirada {
            if r.inicio_slot.saturating_add(p.r_slots) <= slot
                && r.inicio_slot.saturating_add(p.r_votos_slots) <= slot
            {
                vencido = vencido.saturating_add(r.importe);
            }
        }
        if op.importe <= 0 || op.importe > vencido {
            return MotivoSector::ErrFianza;
        }
        let mut restante = op.importe;
        let mut nuevas = Vec::with_capacity(c.en_retirada.len());
        for r in c.en_retirada.drain(..) {
            if restante > 0
                && r.inicio_slot.saturating_add(p.r_slots) <= slot
                && r.inicio_slot.saturating_add(p.r_votos_slots) <= slot
            {
                if r.importe <= restante {
                    restante -= r.importe;
                } else {
                    nuevas.push(Retiro {
                        importe: r.importe - restante,
                        inicio_slot: r.inicio_slot,
                    });
                    restante = 0;
                }
            } else {
                nuevas.push(r);
            }
        }
        c.en_retirada = nuevas;
        self.estado.utxo_total = self.estado.utxo_total.saturating_add(op.importe);
        MotivoSector::Ok
    }

    /// `OP_COINBASE_POST`.
    pub fn op_coinbase_post(
        &mut self,
        op: &Operacion,
        slot: i64,
        p: &ParametrosSector,
    ) -> MotivoSector {
        if op.importe <= 0 {
            return MotivoSector::ErrFianza;
        }
        self.estado.emitido = self.estado.emitido.saturating_add(op.importe);
        let cu = self.cuenta_mut(op.clave);
        cu.creditos.push(Pendiente {
            importe: op.importe,
            madura_slot: slot.saturating_add(p.m_rec_slots),
        });
        MotivoSector::Ok
    }

    /// `OP_EVIDENCIA`: confiscación `EV-17`/`EV-19` con la cascada de S03 (`DP-8`).
    pub fn op_evidencia(
        &mut self,
        op: &Operacion,
        slot: i64,
        productor: ClavePublica,
        p: &ParametrosSector,
    ) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let iid = incidente_id(&op.clave, op.sector_index, op.auditoria_id, &op.h1, &op.h2);
        let v = total_castigable(self.estado, &op.clave);
        {
            let c = self.cuenta_mut(op.clave);
            if c.incidentes.iter().any(|inc| inc.id == iid) {
                return MotivoSector::ErrAuditoria;
            }
            c.incidentes.push(Incidente {
                id: iid,
                slot_falta: slot,
            });
            c.congelado = v;
        }
        let cap = v.min(techo_fraccion(v, p.f_num, p.f_den));
        self.debitar_cuenta(op.clave, cap);
        let recompensa = cap.div_euclid(4);
        if recompensa > 0 {
            let cp = self.cuenta_mut(productor);
            cp.creditos.push(Pendiente {
                importe: recompensa,
                madura_slot: slot.saturating_add(p.m_rec_slots),
            });
        }
        self.estado.quemado = self.estado.quemado.saturating_add(cap - recompensa);
        let v2 = total_castigable(self.estado, &op.clave);
        if let Some(c) = self.estado.garantias.get_mut(&op.clave) {
            c.congelado = v2;
        }
        MotivoSector::Ok
    }

    /// Debita `c` de `clave` en el orden `activo → pendientes → en_retirada → créditos → fianzas
    /// (SectorId ascendente)` (`DP-8`). Devuelve lo efectivamente debitado.
    pub fn debitar_cuenta(&mut self, clave: ClavePublica, c: i64) -> i64 {
        if c <= 0 {
            return 0;
        }
        let mut restante = c;
        {
            let cu = self.cuenta_mut(clave);
            let d = restante.min(cu.activo);
            cu.activo -= d;
            restante -= d;
            if restante > 0 && !cu.pendientes.is_empty() {
                let mut nuevas = Vec::with_capacity(cu.pendientes.len());
                for pp in cu.pendientes.drain(..) {
                    if restante > 0 {
                        let d = restante.min(pp.importe);
                        restante -= d;
                        if d != pp.importe {
                            nuevas.push(Pendiente {
                                importe: pp.importe - d,
                                madura_slot: pp.madura_slot,
                            });
                        }
                    } else {
                        nuevas.push(pp);
                    }
                }
                cu.pendientes = nuevas;
            }
            if restante > 0 && !cu.en_retirada.is_empty() {
                let mut nuevas = Vec::with_capacity(cu.en_retirada.len());
                for rr in cu.en_retirada.drain(..) {
                    if restante > 0 {
                        let d = restante.min(rr.importe);
                        restante -= d;
                        if d != rr.importe {
                            nuevas.push(Retiro {
                                importe: rr.importe - d,
                                inicio_slot: rr.inicio_slot,
                            });
                        }
                    } else {
                        nuevas.push(rr);
                    }
                }
                cu.en_retirada = nuevas;
            }
            if restante > 0 && !cu.creditos.is_empty() {
                let mut nuevas = Vec::with_capacity(cu.creditos.len());
                for cc in cu.creditos.drain(..) {
                    if restante > 0 {
                        let d = restante.min(cc.importe);
                        restante -= d;
                        if d != cc.importe {
                            nuevas.push(Pendiente {
                                importe: cc.importe - d,
                                madura_slot: cc.madura_slot,
                            });
                        }
                    } else {
                        nuevas.push(cc);
                    }
                }
                cu.creditos = nuevas;
            }
        }
        if restante > 0 {
            let ids: Vec<SectorId> =
                crate::sectores::sectores_de_clave(&self.estado.sectores, &clave)
                    .filter(|(id, r)| id.clave == clave && !r.es_terminal() && r.fianza > 0)
                    .map(|(id, _)| *id)
                    .collect();
            for id in ids {
                if restante <= 0 {
                    break;
                }
                self.tocar_sector(id);
                if let Some(r) = self.estado.sectores.get_mut(&id) {
                    let d = restante.min(r.fianza);
                    restante -= d;
                    r.fianza -= d;
                }
            }
        }
        c - restante
    }

    // ── operaciones de sector ───────────────────────────────────────────────

    /// `C-SEC-02` · alta de sector.
    pub fn op_alta(&mut self, op: &Operacion, slot: i64, p: &ParametrosSector) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let mut vmax: i64 = -1;
        let mut prev: Option<RegistroSector> = None;
        for (id, r) in crate::sectores::sectores_de_clave(&self.estado.sectores, &op.clave) {
            if id.clave == op.clave
                && id.sector_index == op.sector_index
                && i64::from(id.version) > vmax
            {
                vmax = i64::from(id.version);
                prev = Some(*r);
            }
        }
        if vmax < 0 {
            if op.version != 0 {
                return MotivoSector::ErrVersion;
            }
        } else {
            if op.version == u32::try_from(vmax).unwrap_or(u32::MAX) {
                return MotivoSector::ErrDobleAlta;
            }
            if op.version != u32::try_from(vmax.saturating_add(1)).unwrap_or(u32::MAX) {
                return MotivoSector::ErrVersion;
            }
            if prev.is_some_and(|r| !r.es_terminal()) {
                return MotivoSector::ErrDobleAlta;
            }
        }
        if op.history_size < p.h_min || op.history_size > p.h_max {
            return MotivoSector::ErrHistory;
        }
        if op.importe != p.q_sec {
            return MotivoSector::ErrFianza;
        }
        let cu = self.cuenta_mut(op.clave);
        if cu.activo < p.q_sec {
            return MotivoSector::ErrFianza;
        }
        cu.activo -= p.q_sec;
        let id = SectorId {
            clave: op.clave,
            sector_index: op.sector_index,
            version: op.version,
        };
        let reg = RegistroSector {
            id,
            r2: op.r2,
            history_size: op.history_size,
            etapa: Etapa::Precomprometido,
            alta_slot: slot,
            renovacion_slot: slot.saturating_add(p.m_sec),
            retiro_slot: NO_HAY,
            fianza: p.q_sec,
            aud_apertura: NO_HAY,
            aud_contestada: NO_HAY,
        };
        self.tocar_sector(id);
        self.estado.sectores.insert(id, reg);
        MotivoSector::Ok
    }

    /// `C-SEC-04` · renovación.
    pub fn op_renovar(&mut self, op: &Operacion, slot: i64, p: &ParametrosSector) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let Some(r) = sector_vivo(self.estado, &op.clave, op.sector_index) else {
            return MotivoSector::ErrNoExiste;
        };
        if estado_efectivo(&r, slot, p) != EstadoEfectivo::Activo {
            return MotivoSector::ErrEstado;
        }
        self.tocar_sector(r.id);
        if let Some(rr) = self.estado.sectores.get_mut(&r.id) {
            rr.renovacion_slot = slot;
        }
        MotivoSector::Ok
    }

    /// `C-SEC-05` · apertura de auditoría.
    pub fn op_abrir_aud(
        &mut self,
        op: &Operacion,
        slot: i64,
        p: &ParametrosSector,
    ) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let Some(r) = sector_vivo(self.estado, &op.clave, op.sector_index) else {
            return MotivoSector::ErrNoExiste;
        };
        if estado_efectivo(&r, slot, p) != EstadoEfectivo::Activo {
            return MotivoSector::ErrEstado;
        }
        if r.aud_apertura >= 0 {
            return MotivoSector::ErrLimite;
        }
        self.tocar_sector(r.id);
        if let Some(rr) = self.estado.sectores.get_mut(&r.id) {
            rr.aud_apertura = slot;
            rr.aud_contestada = NO_HAY;
        }
        MotivoSector::Ok
    }

    /// `C-SEC-06` · recuperación (contestar auditoría).
    pub fn op_contestar(
        &mut self,
        op: &Operacion,
        slot: i64,
        p: &ParametrosSector,
    ) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let Some(r) = sector_vivo(self.estado, &op.clave, op.sector_index) else {
            return MotivoSector::ErrNoExiste;
        };
        if r.aud_apertura < 0 || r.aud_contestada >= 0 {
            return MotivoSector::ErrAuditoria;
        }
        let ee = estado_efectivo(&r, slot, p);
        if !matches!(ee, EstadoEfectivo::Activo | EstadoEfectivo::Suspendido) {
            return MotivoSector::ErrEstado;
        }
        if slot < r.aud_apertura
            || slot
                >= r.aud_apertura
                    .saturating_add(p.p_aud)
                    .saturating_add(p.p_rec)
        {
            return MotivoSector::ErrPlazo;
        }
        if !op.prueba {
            return MotivoSector::ErrPrueba;
        }
        self.tocar_sector(r.id);
        if let Some(rr) = self.estado.sectores.get_mut(&r.id) {
            rr.aud_contestada = slot;
        }
        MotivoSector::Ok
    }

    /// `C-SEC-08` · retirada de sector.
    pub fn op_retirar_sector(
        &mut self,
        op: &Operacion,
        slot: i64,
        p: &ParametrosSector,
    ) -> MotivoSector {
        if !op.firma {
            return MotivoSector::ErrFirma;
        }
        let Some(r) = sector_vivo(self.estado, &op.clave, op.sector_index) else {
            return MotivoSector::ErrNoExiste;
        };
        let ee = estado_efectivo(&r, slot, p);
        if !matches!(ee, EstadoEfectivo::Activo | EstadoEfectivo::Suspendido) {
            return MotivoSector::ErrEstado;
        }
        self.tocar_sector(r.id);
        if let Some(rr) = self.estado.sectores.get_mut(&r.id) {
            rr.etapa = Etapa::EnRetirada;
            rr.retiro_slot = slot;
        }
        MotivoSector::Ok
    }

    /// Despacha una operación (`C-SEC-13`).
    pub fn aplicar_operacion(
        &mut self,
        op: &Operacion,
        slot: i64,
        p: &ParametrosSector,
        productor: ClavePublica,
    ) -> MotivoSector {
        match op.tipo {
            TipoOp::Fondear => self.op_fondear(op),
            TipoOp::Deposito => self.op_deposito(op),
            TipoOp::Retiro => self.op_retiro(op, slot),
            TipoOp::Liberacion => self.op_liberacion(op, slot, p),
            TipoOp::CoinbasePost => self.op_coinbase_post(op, slot, p),
            TipoOp::Evidencia => self.op_evidencia(op, slot, productor, p),
            TipoOp::Alta => self.op_alta(op, slot, p),
            TipoOp::Renovar => self.op_renovar(op, slot, p),
            TipoOp::AbrirAud => self.op_abrir_aud(op, slot, p),
            TipoOp::Contestar => self.op_contestar(op, slot, p),
            TipoOp::RetirarSector => self.op_retirar_sector(op, slot, p),
        }
    }
}

/// Restituye el estado previo a partir del undo por delta (`C-SEC-11`).
pub fn deshacer(estado: &mut EstadoSector, u: &UndoSector) {
    estado.utxo_total = u.utxo_total;
    estado.emitido = u.emitido;
    estado.quemado = u.quemado;
    estado.slot_actual = u.slot_actual;
    for (id, prev) in &u.sectores {
        match prev {
            Some(r) => {
                estado.sectores.insert(*id, *r);
            }
            None => {
                estado.sectores.remove(id);
            }
        }
    }
    for (clave, prev) in &u.garantias {
        match prev {
            Some(c) => {
                estado.garantias.insert(*clave, c.clone());
            }
            None => {
                estado.garantias.remove(clave);
            }
        }
    }
}

/// Resultado de aplicar un bloque.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResultadoBloqueSector {
    /// Undo por delta.
    pub undo: UndoSector,
    /// Operaciones descartadas con su motivo.
    pub descartadas: Vec<MotivoSector>,
    /// ¿Fue admitido?
    pub valido: bool,
    /// ¿Fue elegible?
    pub elegible: bool,
}

/// Bloque del autómata. `sol = None` modela un bloque de arranque (PoW): no exige sector.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BloqueSector {
    /// Id del bloque.
    pub id: u64,
    /// Padres.
    pub padres: Vec<u64>,
    /// Slot.
    pub slot: i64,
    /// Productor.
    pub productor: ClavePublica,
    /// Solución PoAS.
    pub sol: Option<Solucion>,
    /// Peso del bloque (dato de entrada).
    pub peso: i64,
    /// Operaciones.
    pub ops: Vec<Operacion>,
}

/// DAG de bloques por id, con orden de llegada.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DagSector {
    /// Bloques por id.
    pub bloques: BTreeMap<u64, BloqueSector>,
    /// Orden de llegada.
    pub llegada: Vec<u64>,
}

impl DagSector {
    /// Inserta un bloque.
    ///
    /// # Panics
    /// Si el id ya existe, como el `error("bloque duplicado")` del oráculo.
    pub fn agregar(&mut self, b: BloqueSector) {
        assert!(
            !self.bloques.contains_key(&b.id),
            "bloque duplicado: {}",
            b.id
        );
        self.llegada.push(b.id);
        self.bloques.insert(b.id, b);
    }

    /// Ancestros estrictos de `id`.
    #[must_use]
    pub fn pasado(&self, id: u64) -> BTreeSet<u64> {
        let mut memo: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        self.pasado_rec(id, &mut memo)
    }

    fn pasado_rec(&self, id: u64, memo: &mut BTreeMap<u64, BTreeSet<u64>>) -> BTreeSet<u64> {
        if let Some(s) = memo.get(&id) {
            return s.clone();
        }
        let mut s = BTreeSet::new();
        if let Some(b) = self.bloques.get(&id) {
            for p in &b.padres {
                s.insert(*p);
                s.extend(self.pasado_rec(*p, memo));
            }
        }
        memo.insert(id, s.clone());
        s
    }

    /// `blue_work(B) = Σ peso de los ancestros` (`C-GD-08`).
    #[must_use]
    pub fn blue_work(&self, id: u64) -> i64 {
        let mut t: i64 = 0;
        for x in self.pasado(id) {
            if let Some(b) = self.bloques.get(&x) {
                t = t.saturating_add(b.peso);
            }
        }
        t
    }

    /// Orden de aplicación `C-ORD-03` del pasado de `id`: `(blue_work, id)` ascendente.
    #[must_use]
    pub fn orden_canonico(&self, id: u64) -> Vec<u64> {
        let ps = self.pasado(id);
        let mut v: Vec<(i64, u64)> = ps.iter().map(|x| (self.blue_work(*x), *x)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, x)| x).collect()
    }

    /// Orden de aplicación del pasado **más** la propia punta.
    #[must_use]
    pub fn orden_total(&self, id: u64) -> Vec<u64> {
        let mut o = self.orden_canonico(id);
        o.push(id);
        o
    }
}

/// Aplica un bloque al estado en curso. **Muta** `estado`; el llamante conserva `undo` para
/// [`deshacer`] si el bloque no resultó admisible.
pub fn aplicar_bloque(
    estado: &mut EstadoSector,
    b: &BloqueSector,
    p: &ParametrosSector,
) -> ResultadoBloqueSector {
    let mut ap = AplicadorSector::nuevo(estado);
    let mut descartadas = Vec::new();
    ap.materializar(b.slot, p);
    let mut valido = true;
    let mut eleg = true;
    if let Some(sol) = &b.sol {
        eleg = elegible(ap.estado, sol, b.slot, p);
        if eleg {
            let c = ap.cuenta_mut(b.productor);
            if b.slot > c.ultimo_slot_producido {
                c.ultimo_slot_producido = b.slot;
            }
        } else {
            valido = false;
        }
    }
    if valido && b.ops.len() > p.max_ops_bloque {
        valido = false;
    }
    if valido {
        for op in &b.ops {
            let m = ap.marcar();
            let r = ap.aplicar_operacion(op, b.slot, p, b.productor);
            if r != MotivoSector::Ok {
                ap.revertir_a(m);
                descartadas.push(r);
            }
        }
    }
    ResultadoBloqueSector {
        undo: ap.undo,
        descartadas,
        valido,
        elegible: eleg,
    }
}

/// Repliega el pasado de `id` desde cero, en orden C-ORD-03.
///
/// Devuelve `(estado, descartes)`, donde `descartes[x]` es la lista de motivos descartados del
/// bloque `x`, o `[ErrEstado]` si el bloque no se admitió.
#[must_use]
pub fn fold_referencia(
    d: &DagSector,
    id: u64,
    p: &ParametrosSector,
) -> (EstadoSector, BTreeMap<u64, Vec<MotivoSector>>) {
    let mut est = EstadoSector::default();
    let mut descartes = BTreeMap::new();
    for x in d.orden_total(id) {
        let Some(b) = d.bloques.get(&x) else {
            continue;
        };
        let r = aplicar_bloque(&mut est, b, p);
        if r.valido {
            descartes.insert(x, r.descartadas);
        } else {
            deshacer(&mut est, &r.undo);
            descartes.insert(x, vec![MotivoSector::ErrEstado]);
        }
    }
    (est, descartes)
}

/// Cadena incremental con undo por bloque (`C-SEC-11`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CadenaSector {
    /// Estado aplicado.
    pub estado: EstadoSector,
    /// Bloques aplicados.
    pub aplicados: Vec<u64>,
    /// Undo por bloque (`None` si el bloque no se admitió).
    pub undos: Vec<Option<UndoSector>>,
}

/// Sincroniza `c` con la punta `id` del DAG `d`, deshaciendo el prefijo que sobra y aplicando el
/// sufijo nuevo (`C-SEC-11`).
pub fn avanzar(c: &mut CadenaSector, d: &DagSector, id: u64, p: &ParametrosSector) {
    let objetivo = d.orden_total(id);
    let mut k = 0;
    while k < c.aplicados.len() && k < objetivo.len() && c.aplicados.get(k) == objetivo.get(k) {
        k += 1;
    }
    for j in (k..c.aplicados.len()).rev() {
        if let Some(Some(u)) = c.undos.get(j) {
            deshacer(&mut c.estado, u);
        }
    }
    c.aplicados.truncate(k);
    c.undos.truncate(k);
    for x in objetivo.iter().skip(k) {
        let Some(b) = d.bloques.get(x) else {
            continue;
        };
        let r = aplicar_bloque(&mut c.estado, b, p);
        if r.valido {
            c.aplicados.push(*x);
            c.undos.push(Some(r.undo));
        } else {
            deshacer(&mut c.estado, &r.undo);
            c.aplicados.push(*x);
            c.undos.push(None);
        }
    }
}

// ── C-SEC-14 / C-SEC-15 / C-SEC-16 ─────────────────────────────────────────

/// Resultado de la interfaz de prueba sucinta (`C-SEC-14`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResultadoPrueba {
    /// No hay prueba (hoy, siempre).
    SinPrueba,
    /// Prueba válida.
    PruebaValida,
    /// Prueba inválida.
    PruebaInvalida,
}

/// Interfaz que PT-3 enchufará en 0.0.3. **Hoy devuelve siempre `SIN_PRUEBA`** y ninguna regla
/// consulta su resultado (`C-SEC-14`; lectura (i) de PK-05 B3, `ORDEN-SR1` §2.1).
///
/// Recibe `(SectorId, R2, history_size, slot, Parametros)`; devuelve `(ResultadoPrueba, prueba)`
/// con `prueba` opaco (hoy `None`).
#[must_use]
pub fn prueba_sucinta(
    _id: SectorId,
    _r2: R2,
    _history_size: u64,
    _slot: i64,
    _p: &ParametrosSector,
) -> (ResultadoPrueba, Option<()>) {
    (ResultadoPrueba::SinPrueba, None)
}

/// `FuentePeso(past(A_n)) : P ↦ #{(P,i) : estado_efectivo = activo ∧ fianza = q_sec}` (`C-SEC-15`).
///
/// Función **pura**; la prueba sucinta no entra hoy (`C-SEC-14`).
#[must_use]
pub fn fuente_peso(est: &EstadoSector, slot: i64, p: &ParametrosSector) -> i64 {
    let mut n: i64 = 0;
    for (id, r) in &est.sectores {
        if !r.es_terminal()
            && r.fianza == p.q_sec
            && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo
            && (!p.exigir_prueba_almacenamiento || prueba_vigente(est, &id.clave, slot, p))
        {
            n = n.saturating_add(1);
        }
    }
    n
}

/// `FuentePeso` por clave.
#[must_use]
pub fn fuente_peso_de(
    est: &EstadoSector,
    clave: &ClavePublica,
    slot: i64,
    p: &ParametrosSector,
) -> i64 {
    let mut n: i64 = 0;
    for (id, r) in crate::sectores::sectores_de_clave(&est.sectores, clave) {
        if id.clave == *clave
            && !r.es_terminal()
            && r.fianza == p.q_sec
            && estado_efectivo(r, slot, p) == EstadoEfectivo::Activo
            && (!p.exigir_prueba_almacenamiento || prueba_vigente(est, clave, slot, p))
        {
            n = n.saturating_add(1);
        }
    }
    n
}

/// `C-SEC-16` · coste de entrada de un productor nuevo: `n · q_sec` inmovilizado `+ M_sec` slots.
#[must_use]
pub fn coste_entrada(n: i64, p: &ParametrosSector) -> (i64, i64) {
    (n.saturating_mul(p.q_sec), p.m_sec)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::transicion::{Escalares, Estado, Undo, deshacer};

    /// El estado de consenso lleva el registro (`C-SEC-01`) y el undo lo restaura completo
    /// (`C-SEC-11`).
    #[test]
    fn el_estado_de_consenso_lleva_el_registro_y_el_undo_lo_restaura() {
        let id = SectorId {
            clave: clave_de(9),
            sector_index: 3,
            version: 0,
        };
        let reg = RegistroSector {
            id,
            r2: [0; 4],
            history_size: 1,
            etapa: Etapa::Activo,
            alta_slot: 0,
            renovacion_slot: 1,
            retiro_slot: NO_HAY,
            fianza: 10,
            aud_apertura: NO_HAY,
            aud_contestada: NO_HAY,
        };
        let mut e = Estado::inicial();
        e.sectores.insert(id, reg);
        assert_eq!(e.sectores.len(), 1);

        let undo = Undo {
            escalares: Escalares::from(&Estado::inicial()),
            utxo: Vec::new(),
            garantias: Vec::new(),
            sectores: Vec::new(),
            cajas: Vec::new(),
            pruebas: Vec::new(),
            poreps: Vec::new(),
            claves_voto: Vec::new(),
            utxo_vistos: BTreeSet::new(),
            garantia_vistos: BTreeSet::new(),
            sector_vistos: BTreeSet::new(),
            caja_vistos: BTreeSet::new(),
            prueba_vistos: BTreeSet::new(),
            porep_vistos: BTreeSet::new(),
            clave_voto_vistos: BTreeSet::new(),
        };
        let restaurado = deshacer(&e, &undo);
        assert!(
            restaurado.sectores.is_empty(),
            "el undo no vació el registro"
        );
        assert_eq!(Escalares::from(&e).sectores.len(), 1);
    }

    /// El perfil dev cumple las desigualdades de `DECISIONES-PENDIENTES.md`.
    #[test]
    fn el_perfil_dev_cumple_las_desigualdades() {
        let p = ParametrosSector::dev();
        assert!(p.m_sec > 0, "M_sec > 0");
        assert!(p.m_sec < p.t_cad, "M_sec < T_cad");
        assert!(
            p.t_cad > p.m_sec + p.p_aud + p.p_rec,
            "T_cad > M_sec + P_aud + P_rec"
        );
        assert!(p.r_sec > p.p_aud + p.p_rec, "R_sec > P_aud + P_rec");
        assert!(p.p_rec >= 0 && p.p_rec < p.t_cad - p.m_sec, "P_rec");
        assert!(p.p_aud > 0 && p.r_sec > 0, "P_aud > 0, R_sec > 0");
    }
}

#[cfg(test)]
#[path = "../../tests/soporte/secr1/legacy_base.rs"]
pub(crate) mod secr1_legacy;
