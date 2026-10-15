//! Certificado de finalidad por votos y doble voto como **estado de consenso**.
//!
//! La transición **no confía** en el productor: reconstruye el contrato del certificado compacto
//! por peso (`0x09`) y del acta (`0x0A`) contra el estado de aplicación
//! (`CONTRATO-VOTOS-v2.md`, parte A).
//!
//! - **Claves y peso**: la tabla vigente la resuelve el estado (`tablas_voto_contenido` o, en
//!   génesis, `tabla_canonica`); `peso.rs` evalúa el mapa de bits, la firma agregada y el quórum.
//! - **Firma agregada**: [`zx_votos::peso::verificar_firma_peso`] comprueba la multifirma BLS.
//!
//! El punto de finalidad por votos vive en el estado
//! ([`Estado::finalidad_votos`](crate::transicion::Estado)) y es **monótono**: un certificado de una
//! instancia anterior se rechaza con [`ErrorTransicion::ErrFinalidadRetrocede`]; uno de la misma
//! instancia solo se admite si coincide con el ya fijado (idempotente, para que varias ramas puedan
//! incluir el mismo certificado sin invalidar bloques).
//!
//! La **evidencia de dos votos** (`0x0B`) reutiliza el castigo del doble voto: `C = min(V,
//! techo(f·V))`, `suelo(C·2/8)` (25 %) al incluidor y el resto quemado, con deduplicación por
//! `incident_id`.
//!
//! **M9-b2:** las operaciones `0x04` (certificado por plazas), `0x05` (evidencia del mensaje
//! antiguo), `0x06` (compromiso) y `0x07` (revelación) se retiraron; el consenso ya no acepta ni
//! guarda nada del sorteo.

use std::collections::{BTreeSet, HashMap};

use zx_core::{
    BlockHash, ClavePublica as ClaveEd25519, ClaveTablaVoto, Digest, OperacionAlmacenamiento,
};
use zx_votos::{Clave, ClavePublica, DOMINIO_VOTO, Firma, Tabla, hash_tabla, verificar};
// PD-1b · el certificado compacto y el acta se evalúan con el módulo por peso de `zx-votos`.
use zx_votos::peso::{
    self as peso, CertPrevioPeso, CertificadoPeso, EntradaPeso, MotivoPeso, peso_de_clave,
};

use crate::transicion::ErrorTransicion;
use crate::transicion::aplicar::{amount_saturado, creditar_post};
use crate::transicion::estado::{
    Aplicador, debitar_castigable, suelo_dos_octavos, techo_fraccion, total_castigable,
};
use crate::transicion::tipos::{
    BloqueTransicion, Estado, Fase, HechoVoto, HechosCabecera, K_TABLAS_VOTO, ParametrosEvidencia,
    ParametrosTransicion, Punto, Undo,
};

/// TB-1a · R2 · T7 · tope de identidades de una tabla derivada por el consenso.
pub const MAX_CLAVES_TABLA: usize = 65_536;

/// Prima de disponibilidad del contrato de votos (FV-D05): `b = 2`. Es parte del contrato, no un
/// parámetro por red.
pub const B_VOTOS: u64 = 2;

/// B-27: la prima solo puede contar con un verificador de almacenamiento real; hoy el único es el
/// inerte (`crates/zx-consensus/src/prueba_almacenamiento.rs`); se activará en 0.0.4 con las
/// pruebas obligatorias (PK-28 A).
pub const PRIMA_DISPONIBILIDAD_ACTIVA: bool = false;

/// FV-4b-N3 · slots PoT por instancia/ventana (`T_inst`, perfil dev de `REVISION-FV4bD`).
pub const T_INST_VOTOS: u64 = 2;
/// RV-1 · `G` ventanas: caducidad de la tabla comprometida.
///
/// `(F_SLOTS + m_margen_slots) / T_INST_VOTOS = (600 + 60) / 2`; la pausa por candados se resuelve
/// cuando `F` decide y hace falta margen para reanudar; `REVISION-RETM1.md`. Tras caducar, la
/// finalidad por votos queda **parada**: no hay génesis nueva.
pub const CADUCIDAD_TABLA_VENTANAS: u64 = 330;
/// RA-1 · Y0 · espera del rearranque (slots) tras caducar la tabla.
///
/// **Igual a la profundidad de finalidad del perfil** (`zx_node::perfil::F_SLOTS = 600`), atada por
/// una prueba en `zx-node` (Z11). No es una constante libre.
pub const ESPERA_REARRANQUE_SLOTS: u64 = 600;

/// RA-1 · Y0 · calendario del rearranque derivado de los parámetros del sector y de la base `m`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CalendarioRearranque {
    /// Longitud de la fase activa `A`.
    pub a: u64,
    /// Longitud de la fase de silencio `SIL`.
    pub sil: u64,
    /// Periodo del ciclo `P = A + SIL`.
    pub periodo: u64,
    /// Arranque del primer ciclo, `s0`.
    pub s0: u64,
    /// `M_margen_slots` con el que se calcula `ref(j)`.
    pub margen: u64,
}

impl CalendarioRearranque {
    /// `inicio(j) = s0 + j·P`.
    #[must_use]
    pub const fn inicio(&self, j: u64) -> u64 {
        self.s0.saturating_add(j.saturating_mul(self.periodo))
    }

    /// `ref(j) = inicio(j) − ESPERA − M_margen`.
    #[must_use]
    pub const fn referencia(&self, j: u64) -> u64 {
        self.inicio(j)
            .saturating_sub(ESPERA_REARRANQUE_SLOTS)
            .saturating_sub(self.margen)
    }

    /// TB4-R5 · ciclo `j` cuya fase activa contiene la ventana `apertura` **y en la que esa ventana
    /// cierra**: `apertura < inicio(j)+A` y `cierre = apertura + T_inst < inicio(j)+A`. Antes de
    /// TB4-R5 bastaba con que abriera; la última ventana de la fase (663 en el perfil dev) cerraba un
    /// slot después y su evidencia quedaba fuera del alcance de quien salió tras la instantánea.
    #[must_use]
    pub fn ciclo_de_apertura(&self, apertura: u64) -> Option<u64> {
        if self.a == 0 || apertura < self.s0 {
            return None;
        }
        #[expect(
            clippy::integer_division,
            reason = "Y3 fija j = (apertura − s0)/P con división entera"
        )]
        let j = (apertura - self.s0) / self.periodo;
        let fin = self.inicio(j).saturating_add(self.a);
        if apertura < fin && apertura.saturating_add(T_INST_VOTOS) < fin {
            Some(j)
        } else {
            None
        }
    }

    /// RA-1 · Y1 · ciclo cuya ventana de instantánea `(ref(j), inicio(j)+A)` contiene `slot`.
    #[must_use]
    pub fn ciclo_de_instantanea(&self, slot: u64) -> Option<u64> {
        if self.a == 0 {
            return None;
        }
        // `ref(j) < slot < inicio(j)+A` ⇔ `lo < j·P < hi`, con
        // `lo = slot − s0 − A` y `hi = slot − s0 + ESPERA + margen`; el intervalo mide
        // `A + ESPERA + margen = P − 1 < P`, así que a lo sumo hay un `j`.
        let lo = i128::from(slot) - i128::from(self.s0) - i128::from(self.a);
        let hi = i128::from(slot) - i128::from(self.s0)
            + i128::from(ESPERA_REARRANQUE_SLOTS)
            + i128::from(self.margen);
        if hi <= 0 {
            return None;
        }
        let p = i128::from(self.periodo);
        let j = (hi - 1).div_euclid(p).max(0);
        let j = u64::try_from(j).ok()?;
        if i128::from(j).saturating_mul(p) <= lo {
            return None;
        }
        if self.referencia(j) < slot && slot < self.inicio(j).saturating_add(self.a) {
            Some(j)
        } else {
            None
        }
    }
}

/// RA-1 · Y0 · calendario del rearranque con base `m`; `None` si `A ≤ 0` (rige la guarda 4 de hoy).
#[must_use]
pub fn calendario_rearranque(
    p: &crate::sectores::ParametrosSector,
    m: u64,
) -> Option<CalendarioRearranque> {
    let espera = i128::from(ESPERA_REARRANQUE_SLOTS);
    let margen = i128::from(p.m_margen_slots);
    let a = i128::from(p.r_votos_slots) - espera - margen - i128::from(p.plazo_slots) + 1;
    if a <= 0 {
        return None;
    }
    let sil = espera + margen + 1;
    if sil <= 0 {
        return None;
    }
    let a = u64::try_from(a).ok()?;
    let sil = u64::try_from(sil).ok()?;
    let periodo = a.checked_add(sil)?;
    let margen = u64::try_from(margen).ok()?;
    let cierre = cierre_ventana(m.saturating_add(CADUCIDAD_TABLA_VENTANAS));
    let s0 = cierre.checked_add(ESPERA_REARRANQUE_SLOTS)?;
    Some(CalendarioRearranque {
        a,
        sil,
        periodo,
        s0,
        margen,
    })
}
/// FV-4b-N3-2 · plazo de gracia dev para la determinación de ausencia (`G_slots`, AV-11).
///
/// **Derivado (no a ojo):** el humo de FV-4b-N3 (`resultados-FV4bN3/`) dio una latencia de inclusión
/// de la revelación de p99 = 10 slots (n = 65 revelaciones del nodo C; mediana 6, máximo 10). Se
/// fija `G_slots = 4 · p99 = 40` (margen ≥ 4×). En producción `G_slots ≈ F_slots = 600`
/// (desviación dev declarada: un humo de ≤ 400 slots no alcanza 600).
pub const G_SLOTS_VOTOS: u64 = 40;
/// FV-4b-N3-2 · plazo de revelación dev (`W_reveal`, AV-08). Se cumple `W_reveal > G_slots`, de modo
/// que hay varios slots de admisión tras el plazo de gracia. **Derivado:** 16 · p99 = 160 (margen
/// ≥ 16× sobre la latencia de inclusión medida), para que un productor honesto tenga ventana de
/// sobra y la ventana de admisión (W − G + 1 = 121 slots) absorba cualquier hueco de producción.
pub const W_REVEAL_SLOTS_VOTOS: u64 = 160;

/// AUS-2a · R8 · `F_AUS_VENTANA = 7/1 401 600 000` de la garantía por ventana sin voto.
///
/// Derivación: PK-11 (2,5 % del ingreso anual para quien apaga 8 h de cada 24), ingreso anual
/// igual a la garantía (supuesto declarado de FV-N1), ventana de `T_INST_VOTOS = 2` slots, slot
/// medido de 1,05 s (IPA B-32): `3·(25/1000)·(2·21/20)/31 536 000 = 7/1 401 600 000`.
///
/// Al liquidar una ventana sin voto se acumula `deuda += G·7` (`G = total_castigable`); se cobra
/// `deuda / 1 401 600 000` y el resto queda como deuda (R5).
pub const F_AUS_VENTANA_NUM: i128 = 7;
/// Denominador de [`F_AUS_VENTANA_NUM`] (`7/1 401 600 000`).
pub const F_AUS_VENTANA_DEN: i128 = 1_401_600_000;

/// FV-4b-N3 · apertura de la ventana/instancia `n` (`n·T_inst`).
#[must_use]
pub const fn apertura_ventana(n: u64) -> u64 {
    n.saturating_mul(T_INST_VOTOS)
}

/// FV-4b-N3 · cierre de la ventana/instancia `n` (`(n+1)·T_inst`).
#[must_use]
pub const fn cierre_ventana(n: u64) -> u64 {
    n.saturating_add(1).saturating_mul(T_INST_VOTOS)
}

/// RK-2 · V1 · segundo término de la retención: `(CADUCIDAD_TABLA_VENTANAS + 1)·T_INST_VOTOS +
/// p.plazo_slots − 1`, en slots. Es el plazo que cubre la tabla vigente más larga (modelo
/// `run-rotacion-clave.jl`, `fórm(a)`).
#[must_use]
pub fn retencion_clave_voto_por_tabla(p: &crate::sectores::ParametrosSector) -> u64 {
    let plazo = u64::try_from(p.plazo_slots).unwrap_or(0);
    CADUCIDAD_TABLA_VENTANAS
        .saturating_add(1)
        .saturating_mul(T_INST_VOTOS)
        .saturating_add(plazo)
        .saturating_sub(1)
}

/// RK-2 · V1 · retención de la clave de voto anterior, en slots:
/// `max(p.r_votos_slots, (CADUCIDAD_TABLA_VENTANAS + 1)·T_INST_VOTOS + p.plazo_slots − 1)`.
///
/// Es una **función de los parámetros**, no una constante nueva. Con el perfil dev da `1 024`
/// (`r_votos_slots`) y el segundo término da `961`.
#[must_use]
pub fn retencion_clave_voto(p: &crate::sectores::ParametrosSector) -> u64 {
    let r = u64::try_from(p.r_votos_slots).unwrap_or(0);
    r.max(retencion_clave_voto_por_tabla(p))
}

/// TB4-R3 · P2 · tope de edad `X` (en ventanas) de una tabla de la cola `Q`.
///
/// Es una función **derivada** de los parámetros, no un literal:
/// `X = ⌊(r_votos_slots − (G·T_inst + T_inst + plazo_slots)) / T_inst⌋`, con
/// `G = CADUCIDAD_TABLA_VENTANAS`. El término `G·T_inst + T_inst` es `cierre(n+G) − n·T_inst` porque
/// `cierre(x) = (x+1)·T_inst`; el numerador es el margen de la retención de la clave sobre la
/// vida útil de la tabla comprometida. Si la fórmula da negativo, el tope es cero.
///
/// Con el perfil dev (`r_votos_slots = 1 024`, `G = 330`, `T_inst = 2`, `plazo_slots = 300`) da
/// `X = 31`.
#[expect(
    clippy::integer_division,
    reason = "P2 fija la división entera de la fórmula del tope; C-ENC-04 prohíbe floats"
)]
#[must_use]
pub fn tope_edad_tabla_ventanas(p: &crate::sectores::ParametrosSector) -> u64 {
    let r = u64::try_from(p.r_votos_slots).unwrap_or(0);
    let plazo = u64::try_from(p.plazo_slots).unwrap_or(0);
    let gasto = CADUCIDAD_TABLA_VENTANAS
        .saturating_mul(T_INST_VOTOS)
        .saturating_add(T_INST_VOTOS)
        .saturating_add(plazo);
    r.saturating_sub(gasto) / T_INST_VOTOS
}

/// TB4-R3 · P4 · huellas de `Q` que un certificado de ventana `n` puede comprometer: las de edad
/// `n − k` **saturada en cero** menor o igual que [`tope_edad_tabla_ventanas`].
fn huellas_aceptadas(estado: &Estado, n: u64) -> Vec<[u8; 32]> {
    let x = tope_edad_tabla_ventanas(&estado.parametros_sector);
    estado
        .cola_tablas_voto
        .iter()
        .filter(|(k, _)| n.saturating_sub(*k) <= x)
        .map(|(_, h)| *h)
        .collect()
}

/// PD-1c · `incident_id` determinista de una evidencia de dos votos por peso (`0x0B`).
///
/// `SHA3-256("ZEROX/doble-voto-peso-incidente/v1" ‖ n_u64_be ‖ clave_bls ‖ voto1 ‖ voto2)`, con los
/// votos en orden canónico y **cada uno con su raíz de estado** (el identificador del `0x05` no las
/// incluye; aquí sí, contrato v2 B2). Digest **opaco**: solo se compara por igualdad.
#[must_use]
#[allow(
    clippy::too_many_arguments,
    reason = "ocho campos del contrato, sin agrupar"
)]
pub fn incident_id_doble_voto_peso(
    n: u64,
    clave_bls: &[u8; 48],
    h1: &[u8; 32],
    h_t1: &[u8; 32],
    r1: &[u8; 32],
    h2: &[u8; 32],
    h_t2: &[u8; 32],
    r2: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(33 + 8 + 48 + 6 * 32);
    bytes.extend_from_slice(b"ZEROX/doble-voto-peso-incidente/v1");
    bytes.extend_from_slice(&n.to_be_bytes());
    bytes.extend_from_slice(clave_bls);
    bytes.extend_from_slice(h1);
    bytes.extend_from_slice(h_t1);
    bytes.extend_from_slice(r1);
    bytes.extend_from_slice(h2);
    bytes.extend_from_slice(h_t2);
    bytes.extend_from_slice(r2);
    *zx_core::sha3_256_publico(&bytes).as_bytes()
}

/// AT-1b · W4 · identificador del incidente de la falta «voto contra la propia atadura» (ventanas
/// distintas): incluye **las dos** ventanas. Dominio propio para no colisionar con el de la misma
/// ventana ([`incident_id_doble_voto_peso`]).
#[must_use]
#[allow(
    clippy::too_many_arguments,
    reason = "las dos ventanas y los seis campos de los votos, sin agrupar"
)]
pub fn incident_id_doble_voto_peso_ventanas(
    n1: u64,
    n2: u64,
    clave_bls: &[u8; 48],
    h1: &[u8; 32],
    h_t1: &[u8; 32],
    r1: &[u8; 32],
    h2: &[u8; 32],
    h_t2: &[u8; 32],
    r2: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(41 + 2 * 8 + 48 + 6 * 32);
    bytes.extend_from_slice(b"ZEROX/doble-voto-peso-incidente-ventanas/v1");
    bytes.extend_from_slice(&n1.to_be_bytes());
    bytes.extend_from_slice(&n2.to_be_bytes());
    bytes.extend_from_slice(clave_bls);
    bytes.extend_from_slice(h1);
    bytes.extend_from_slice(h_t1);
    bytes.extend_from_slice(r1);
    bytes.extend_from_slice(h2);
    bytes.extend_from_slice(h_t2);
    bytes.extend_from_slice(r2);
    *zx_core::sha3_256_publico(&bytes).as_bytes()
}

/// RK-2 · V5 · mapa `clave BLS (48 B) → clave Ed25519` del estado para el `slot` de aplicación.
///
/// Incluye las claves de voto **actuales** y las **anteriores vivas** (`slot ≤ vencimiento`, V6).
/// Como V4 impide registrar la clave anterior viva de otra identidad, no hay colisión: una clave BLS
/// corresponde a lo sumo a una identidad. Las vencidas no se devuelven aunque aún no se hayan
/// borrado (V6).
///
/// ACTA-1 · R1 · es **la** traducción de la cadena, pura sobre el estado: la usan la transición
/// ([`indice_bls_a_ed25519`]) y el productor (`zx-node`) para decidir sobre sus actas, sin una
/// segunda versión. El cuerpo es el de siempre.
#[must_use]
pub fn indice_bls_a_ed25519_estado(estado: &Estado, slot: u64) -> HashMap<[u8; 48], ClaveEd25519> {
    let mut mapa = HashMap::with_capacity(
        estado
            .claves_voto
            .len()
            .saturating_add(estado.claves_voto_previas.len()),
    );
    for (ed, cv) in &estado.claves_voto {
        mapa.insert(cv.clave_bls, *ed);
    }
    for (ed, prev) in &estado.claves_voto_previas {
        if slot <= prev.vencimiento {
            mapa.insert(prev.clave_bls, *ed);
        }
    }
    mapa
}

/// RK-2 · V5 · como [`indice_bls_a_ed25519_estado`], sobre el aplicador. ACTA-1 · R1: delega en la
/// función pura; la suite de `zx-consensus` tiene que dar exactamente lo mismo.
fn indice_bls_a_ed25519(ap: &Aplicador, slot: u64) -> HashMap<[u8; 48], ClaveEd25519> {
    indice_bls_a_ed25519_estado(&ap.estado, slot)
}

/// ACTA-1 · R1/R2 · identidades Ed25519 que aporta el mapa firmado de un acta con la tabla `tabla`,
/// traducido con **la** función de la cadena ([`indice_bls_a_ed25519_estado`]) en `slot`.
///
/// Es el mismo recorrido que [`aplicar_acta_presencia`]: cada posición marcada del mapa se resuelve
/// contra la tabla y, si su clave BLS se traduce, se añade la identidad. Un bit intraducible no
/// aporta identidad (el conjunto puede quedar vacío).
#[must_use]
pub fn votantes_de_mapa(
    estado: &Estado,
    tabla: &[ClaveTablaVoto],
    mapa: &[u8],
    slot: u64,
) -> BTreeSet<ClaveEd25519> {
    let indice = indice_bls_a_ed25519_estado(estado, slot);
    let mut nuevos: BTreeSet<ClaveEd25519> = BTreeSet::new();
    for posicion in peso::firmantes_de_mapa(mapa) {
        if let Some(c) = posicion.checked_sub(1).and_then(|p| tabla.get(p))
            && let Some(ed) = indice.get(&c.clave_bls)
        {
            nuevos.insert(*ed);
        }
    }
    nuevos
}

/// ACTA-1 · R2/R3 · identidades que el acta `bytes` (`0x0A`) aporta a su ventana sobre `estado` en
/// `slot`, con la tabla que la propia transición resolvería ([`tabla_de_ventana`]).
///
/// Devuelve `None` si falta la tabla o no se puede leer el mapa: la ignorancia **no** justifica
/// omitir (R3), y el productor debe incluir el acta como candidata.
#[must_use]
pub fn votantes_de_acta(
    estado: &Estado,
    bytes: &[u8],
    slot: u64,
) -> Option<BTreeSet<ClaveEd25519>> {
    let n = ventana_de_certificado_peso(bytes).ok()?;
    let tabla = tabla_de_ventana(estado, n)?;
    let cert = parsear_certificado_peso(bytes, tabla.len()).ok()?;
    Some(votantes_de_mapa(estado, &tabla, &cert.mapa, slot))
}

/// Convierte una clave de tabla de `zx-core` al tipo del contrato de `zx-votos`.
fn clave_de_tabla(c: &ClaveTablaVoto) -> Clave {
    Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    }
}

/// PD-1b · tabla del contrato a partir de una tabla de `zx-core`.
fn tabla_contrato(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves.iter().map(clave_de_tabla).collect(),
    }
}

/// PD-1b · copia canónica (ascendente por bytes de clave) de una tabla de `zx-core`.
fn contenido_canonico(claves: &[ClaveTablaVoto]) -> Vec<ClaveTablaVoto> {
    let mut copia = claves.to_vec();
    copia.sort_by_key(|a| a.clave_bls);
    copia
}

/// PD-1b · claves públicas BLS de una tabla, en su orden.
fn claves_bls_de_tabla(claves: &[ClaveTablaVoto]) -> Result<Vec<ClavePublica>, ErrorTransicion> {
    claves
        .iter()
        .map(|c| {
            // TB-1a · R6 · N5 · claves ya validadas con memoria (mismo resultado que `desde_bytes`).
            ClavePublica::desde_bytes_con_memoria(&c.clave_bls)
                .map_err(|_| ErrorTransicion::ErrCertificadoPesoBytes)
        })
        .collect()
}

/// PD-1b · lee la ventana `n` de la cabecera fija de `serial_certificado_peso` (big-endian).
fn ventana_de_certificado_peso(bytes: &[u8]) -> Result<u64, ErrorTransicion> {
    let cabecera = bytes
        .get(0..8)
        .ok_or(ErrorTransicion::ErrCertificadoPesoBytes)?;
    let mut arreglo = [0u8; 8];
    arreglo.copy_from_slice(cabecera);
    Ok(u64::from_be_bytes(arreglo))
}

/// TB-1c-2 · X2 · lee el `h_t_siguiente` declarado en la cabecera fija del `0x09` (big-endian).
///
/// La cabecera fija es `n:8 ‖ candidato:32 ‖ h_t_siguiente:32 ‖ raíz:32 ‖ firma:96`; la huella ocupa
/// `bytes[40..72]`. Se lee **sin** conocer la longitud del mapa, que en la rama sin base depende de
/// la tabla vigente (el contenido de esa misma huella).
fn huella_tabla_de_certificado_peso(bytes: &[u8]) -> Result<[u8; 32], ErrorTransicion> {
    let trozo = bytes
        .get(40..72)
        .ok_or(ErrorTransicion::ErrCertificadoPesoBytes)?;
    let mut arreglo = [0u8; 32];
    arreglo.copy_from_slice(trozo);
    Ok(arreglo)
}

/// PD-1b · C1/T2 · deserializa `serial_certificado_peso` desde el cuerpo de la operación.
///
/// El mapa mide `⌈N_vigente/8⌉` y **nada** puede ir detrás: un byte de más es un rechazo **por
/// forma**, antes de verificar ninguna firma.
fn parsear_certificado_peso(
    bytes: &[u8],
    n_claves_vigente: usize,
) -> Result<CertificadoPeso, ErrorTransicion> {
    peso::deserializar_certificado_peso(bytes, n_claves_vigente)
        .map_err(|_| ErrorTransicion::ErrCertificadoPesoBytes)
}

/// PD-1b · C2/C5 · guarda el contenido canónico de una tabla (una sola vez por hash).
fn guardar_contenido(estado: &mut Estado, claves: &[ClaveTablaVoto]) {
    let canonica = contenido_canonico(claves);
    let h = hash_payload(0, &canonica);
    estado.tablas_voto_contenido.entry(h).or_insert(canonica);
}

/// TB-1a · R2 · T7 · tabla derivada `D(E, k)` del estado `E` para la ventana `k`, con el tope real.
///
/// Es `contenido_canonico(tabla_canonica(estado, k · T_INST_VOTOS))` y, si pasa de
/// [`MAX_CLAVES_TABLA`] entradas, se queda con las de mayor peso según el desempate de T7.
#[must_use]
pub fn tabla_derivada(estado: &Estado, k: u64) -> Vec<ClaveTablaVoto> {
    tabla_derivada_con_tope(estado, k, MAX_CLAVES_TABLA)
}

/// TB-1a · R2 · T7 · [`tabla_derivada`] con el tope como argumento.
///
/// Función **interna**: existe para poder probar el recorte sin 65 537 identidades. No es pública
/// fuera de este crate. El desempate a igual peso es: primero la que está en la tabla vigente del
/// estado (el contenido de `finalidad_votos_h_t`, si lo hay); después, la de clave BLS menor en
/// orden de bytes. El resultado va en orden canónico.
fn tabla_derivada_con_tope(estado: &Estado, k: u64, tope: usize) -> Vec<ClaveTablaVoto> {
    let slot = k.saturating_mul(T_INST_VOTOS);
    let slot = i64::try_from(slot).unwrap_or(i64::MAX);
    recortar_tabla(estado, tabla_canonica(estado, slot), tope)
}

/// T7 / TB4-R9 · recorte común de la tabla derivada y la instantánea de rearranque.
/// Conserva las de mayor peso, desempata por pertenencia a la vigente y luego por clave BLS,
/// y devuelve el contenido en orden canónico. El tope interno permite probarlo con pocas claves.
fn recortar_tabla(estado: &Estado, tabla: Vec<ClaveTablaVoto>, tope: usize) -> Vec<ClaveTablaVoto> {
    if tabla.len() <= tope {
        return contenido_canonico(&tabla);
    }
    // El contenido de la tabla vigente del estado, si se conoce.
    let vigentes: BTreeSet<[u8; 48]> = estado
        .finalidad_votos_h_t
        .and_then(|h| estado.tablas_voto_contenido.get(&h))
        .map(|t| t.iter().map(|c| c.clave_bls).collect())
        .unwrap_or_default();
    let mut ordenadas = tabla;
    ordenadas.sort_by(|a, b| {
        b.peso
            .cmp(&a.peso)
            .then_with(|| {
                let fuera_a = !vigentes.contains(&a.clave_bls);
                let fuera_b = !vigentes.contains(&b.clave_bls);
                fuera_a.cmp(&fuera_b)
            })
            .then_with(|| a.clave_bls.cmp(&b.clave_bls))
    });
    ordenadas.truncate(tope);
    contenido_canonico(&ordenadas)
}

/// FV-4b-N3 · tabla canónica `T_n` del estado en `slot` (contrato REAN-1 §3.2 K4.4).
///
/// Es la misma regla que `construir_tabla` de `crates/zx-node/src/votos.rs` (que solo se lee):
/// todas las claves con clave BLS de voto registrada, con peso positivo (`fuente_peso_de`) y con su
/// marca de prueba; en el orden determinista de `Estado.claves_voto`. La usa la fase génesis para
/// resolver la tabla vigente del primer `0x09` comparando por `hash_tabla`, nunca por igualdad de
/// vectores. **M9-b2:** ya no filtra por suspensión (el sorteo y la suspensión por no revelar se
/// retiraron); el conjunto materializado estaba siempre vacío en 0.0.3 (DEC-003-A2).
#[must_use]
pub fn tabla_canonica(estado: &Estado, slot: i64) -> Vec<ClaveTablaVoto> {
    let pesos = crate::transicion::sector::pesos_por_clave(estado, slot, &estado.parametros_sector);
    let mut claves: Vec<ClaveTablaVoto> = Vec::with_capacity(estado.claves_voto.len());
    for (clave_ed, clave_voto) in &estado.claves_voto {
        let peso = pesos.get(clave_ed).copied().unwrap_or(0);
        if peso <= 0 {
            continue;
        }
        let Ok(peso) = u64::try_from(peso) else {
            continue;
        };
        let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && estado.pruebas.contains_key(clave_ed);
        claves.push(ClaveTablaVoto {
            clave_bls: clave_voto.clave_bls,
            peso,
            activo: true,
            prueba,
            garantia: peso,
        });
    }
    claves
}

/// `hash_tabla` del payload de una tabla de una instancia `n`.
fn hash_payload(n: u64, claves: &[ClaveTablaVoto]) -> [u8; 32] {
    hash_tabla(&Tabla {
        n,
        claves: claves.iter().map(clave_de_tabla).collect(),
    })
}

/// PROD-1 · predicado de clave de `aplicar_voto_propio`, compartido con el productor.
/// Exige registro actual y acepta su clave o la anterior hasta su vencimiento inclusive (V5).
#[must_use]
pub fn clave_voto_admisible(
    estado: &Estado,
    clave: &ClaveEd25519,
    clave_bls: &[u8; 48],
    slot: u64,
) -> bool {
    let Some(registro) = estado.claves_voto.get(clave) else {
        return false;
    };
    let es_actual = registro.clave_bls == *clave_bls;
    let es_anterior_viva = estado
        .claves_voto_previas
        .get(clave)
        .is_some_and(|prev| prev.clave_bls == *clave_bls && slot <= prev.vencimiento);
    es_actual || es_anterior_viva
}

/// AUS-2a · R3 · aplica un **voto propio** `0x08` (AV-11/AV-12).
///
/// Admisible si y solo si:
/// 1. el slot del bloque está en `[apertura(n), cierre(n) + W_REVEAL_SLOTS_VOTOS]`;
/// 2. la clave BLS es la registrada por esa clave Ed25519 en el estado;
/// 3. la firma BLS verifica sobre A3 (`peso::mensaje_voto_peso`, contrato v2 §A3) con **la raíz de
///    estado que el propio `0x08` trae** (RE-2c · C2′); la cadena no la compara con nada;
/// 4. la clave no está ya en `votantes_voto[n]` (ni por certificado ni por otro voto propio).
///
/// Efecto: añade la clave a `votantes_voto[n]`. **No** comprueba el candidato ni la tabla: cuenta
/// cualquier voto bien firmado (AV-12). Un rechazo se devuelve con error propio y, como en `0x07`,
/// no invalida el bloque en modo fusión (se descarta) mientras en modo estricto lo invalida.
///
/// # Errores
/// `ErrVotoPropioPlazo`, `ErrVotoPropioClave`, `ErrVotoPropioFirma`, `ErrVotoPropioDuplicado`.
pub(crate) fn aplicar_voto_propio(
    ap: &mut Aplicador,
    operacion: &OperacionAlmacenamiento,
    slot: i64,
) -> Result<(), ErrorTransicion> {
    let OperacionAlmacenamiento::VotoPropio {
        clave,
        n,
        candidato,
        h_t_siguiente,
        raiz_estado,
        clave_bls,
        firma,
    } = operacion
    else {
        return Err(ErrorTransicion::ErrVotoPropioClave);
    };
    // (1) plazo `[apertura(n), cierre(n) + W_reveal]`.
    let slot_u = u64::try_from(slot).unwrap_or(u64::MAX);
    if slot_u < apertura_ventana(*n)
        || slot_u > cierre_ventana(*n).saturating_add(W_REVEAL_SLOTS_VOTOS)
    {
        return Err(ErrorTransicion::ErrVotoPropioPlazo);
    }
    // (2) la clave BLS debe ser la actual del firmante Ed25519 o su anterior viva (V5).
    if !clave_voto_admisible(&ap.estado, clave, clave_bls, slot_u) {
        return Err(ErrorTransicion::ErrVotoPropioClave);
    }
    // (3) RE-2c · C2′ · la firma vale **solo** sobre A3 con la raíz que el `0x08` trae
    //     (`peso::mensaje_voto_peso`, contrato v2 §A3); el mensaje antiguo (raíz = `candidato`) ya no
    //     se acepta. No se compara esa raíz con la del certificado ni con `Estado::raiz_estado`
    //     (regla AV-12: el voto propio cuenta cualquier voto bien firmado).
    let pk =
        ClavePublica::desde_bytes(clave_bls).map_err(|_| ErrorTransicion::ErrVotoPropioClave)?;
    let firma = Firma::desde_bytes(firma).map_err(|_| ErrorTransicion::ErrVotoPropioFirma)?;
    let mensaje_a3 = peso::mensaje_voto_peso(*n, candidato, h_t_siguiente, raiz_estado);
    if verificar(&pk, &firma, DOMINIO_VOTO, &mensaje_a3).is_err() {
        return Err(ErrorTransicion::ErrVotoPropioFirma);
    }
    // (4) no repetido: ni ya admitido por certificado ni por otro voto propio.
    if ap
        .estado
        .votantes_voto
        .get(n)
        .is_some_and(|votantes| votantes.contains(clave))
    {
        return Err(ErrorTransicion::ErrVotoPropioDuplicado);
    }
    ap.estado
        .votantes_voto
        .entry(*n)
        .or_default()
        .insert(*clave);
    Ok(())
}

/// PD-1b · C5 · resuelve la tabla `T_n` de la ventana `n` para liquidarla.
///
/// (i) La tabla **asociada a la ventana** por [`Estado::tabla_ventana_voto`] (fijada al avanzar la
/// base), buscada por hash en el contenido guardado; si la ventana está asociada pero su contenido
/// no se conoce, se liquida **sin cobro** (no se cae al camino viejo). (ii) Para una ventana
/// posterior a la base, la tabla vigente actual (contenido de `finalidad_votos_h_t`). (iii) Si no,
/// el camino anterior: `tablas_voto[n]` y, con base `m < n ≤ m + CADUCIDAD`, la tabla de la base si
/// su hash casa con `finalidad_votos_h_t` (`hash_tabla` no depende de `n`, así que casar `T_m` con
/// `h_T(m+1)` significa que la tabla no cambió). (iv) En otro caso, `None`: sin cobro.
fn tabla_para_liquidar(estado: &Estado, n: u64) -> Option<Vec<ClaveTablaVoto>> {
    // (i) C5 · asociación ventana → tabla, por hash.
    if let Some(h) = estado.tabla_ventana_voto.get(&n) {
        return estado.tablas_voto_contenido.get(h).cloned();
    }
    // PD-1b2 · Q1 · RV-1 · con base `m`, una ventana `n > m + CADUCIDAD_TABLA_VENTANAS` no tiene
    // tabla vigente (tras la caducidad no hay génesis nueva): se liquida **sin cobro**. La
    // asociación explícita de la rama (i) es la única excepción (solo cubre ventanas ≤ la base).
    if estado.finalidad_votos.is_some()
        && n > estado
            .finalidad_votos_n
            .saturating_add(CADUCIDAD_TABLA_VENTANAS)
    {
        return None;
    }
    // (ii) C5 · ventana posterior a la base: la tabla vigente actual.
    if estado.finalidad_votos.is_some()
        && n > estado.finalidad_votos_n
        && let Some(h) = estado.finalidad_votos_h_t
        && let Some(tabla) = estado.tablas_voto_contenido.get(&h)
    {
        return Some(tabla.clone());
    }
    // (iii) Camino anterior: tabla guardada de la ventana (la base de génesis no tiene asociación).
    if let Some(tabla) = estado.tablas_voto.get(&n) {
        return Some(tabla.clone());
    }
    if estado.finalidad_votos.is_some() {
        let m = estado.finalidad_votos_n;
        if m < n
            && n <= m.saturating_add(CADUCIDAD_TABLA_VENTANAS)
            && let Some(tabla_base) = estado.tablas_voto.get(&m)
            && estado.finalidad_votos_h_t == Some(hash_payload(m, tabla_base))
        {
            return Some(tabla_base.clone());
        }
    }
    None
}

/// PD-1b · C5 · tabla vigente de la ventana `n` (la que se usó para votar). Es la asociación de
/// [`Estado::tabla_ventana_voto`] o, para ventanas posteriores a la base, el contenido de
/// `finalidad_votos_h_t`. Devuelve el contenido canónico o `None` si es desconocido.
fn tabla_de_ventana(estado: &Estado, n: u64) -> Option<Vec<ClaveTablaVoto>> {
    if let Some(h) = estado.tabla_ventana_voto.get(&n) {
        return estado.tablas_voto_contenido.get(h).cloned();
    }
    if n > estado.finalidad_votos_n
        && n <= estado
            .finalidad_votos_n
            .saturating_add(CADUCIDAD_TABLA_VENTANAS)
        && let Some(h) = estado.finalidad_votos_h_t
    {
        return estado.tablas_voto_contenido.get(&h).cloned();
    }
    None
}

/// PD-1b · C5 · poda el contenido de tablas que ya no usa ninguna ventana pendiente ni la tabla
/// vigente actual.
pub(crate) fn podar_contenido_voto(ap: &mut Aplicador) {
    let mut usados: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    if let Some(h) = ap.estado.finalidad_votos_h_t {
        usados.insert(h);
    }
    usados.extend(ap.estado.tabla_ventana_voto.values().copied());
    // RA-1 · Y1 · el contenido de las instantáneas de ciclo también está en uso.
    usados.extend(ap.estado.tabla_ciclo_rearranque.values().copied());
    // TB-1a · R4 · T8 · el contenido de toda huella presente en la cola `Q` también está en uso.
    usados.extend(ap.estado.cola_tablas_voto.iter().map(|(_, h)| *h));
    ap.estado
        .tablas_voto_contenido
        .retain(|h, _| usados.contains(h));
}

/// RA-1 · Y1/Y2 · toma/poda las instantáneas de la tabla del ciclo de rearranque.
///
/// Con base presente y `A > 0`: borra la de todo ciclo terminado (`s ≥ inicio(j) + A`) y, para el
/// ciclo `j` con `ref(j) < s < inicio(j) + A` (a lo sumo uno), guarda el contenido canónico de
/// [`tabla_canonica`] evaluada en `ref(j)` con el **estado de entrada** al bloque, recortado por
/// T7 / TB4-R9 a [`MAX_CLAVES_TABLA`] identidades. El contenido va
/// a `tablas_voto_contenido` (la poda lo respeta) y el mapa del estado guarda su hash.
pub(crate) fn tomar_instantaneas_rearranque(ap: &mut Aplicador, slot: u64) {
    tomar_instantaneas_rearranque_con_tope(ap, slot, MAX_CLAVES_TABLA);
}

/// TB4-R9 · mismo gancho con el tope como argumento interno, sin cambiar el calendario.
fn tomar_instantaneas_rearranque_con_tope(ap: &mut Aplicador, slot: u64, tope: usize) {
    if ap.estado.finalidad_votos.is_none() {
        return;
    }
    let Some(cal) =
        calendario_rearranque(&ap.estado.parametros_sector, ap.estado.finalidad_votos_n)
    else {
        return;
    };
    // Y2 · ciclo terminado: su fase activa ya pasó.
    ap.estado
        .tabla_ciclo_rearranque
        .retain(|j, _| slot < cal.inicio(*j).saturating_add(cal.a));
    let Some(j) = cal.ciclo_de_instantanea(slot) else {
        return;
    };
    if ap.estado.tabla_ciclo_rearranque.contains_key(&j) {
        return;
    }
    let referencia = i64::try_from(cal.referencia(j)).unwrap_or(i64::MAX);
    let canonica = recortar_tabla(&ap.estado, tabla_canonica(&ap.estado, referencia), tope);
    let h = hash_payload(0, &canonica);
    ap.estado.tablas_voto_contenido.entry(h).or_insert(canonica);
    ap.estado.tabla_ciclo_rearranque.insert(j, h);
}

/// TB4-R1 · TB4-R2 · T1′ generalizada: **con o sin base**, deriva y guarda la tabla de la ventana al
/// cruzar cada ventana.
///
/// Se llama con el **estado de entrada** al bloque y su slot `s`, justo después de
/// [`tomar_instantaneas_rearranque`], en el mismo punto que cubre los dos caminos de aplicación
/// ([`crate::transicion::aplicar`] y `fusion`, que llaman a `liquidar_ventanas_voto`). Con
/// `k = s / T_INST_VOTOS`:
///
/// (a) como mucho una derivación por ventana y cadena: si el estado ya derivó para `k` (o para una
/// ventana posterior), no hace nada; (b) calcula `tabla_derivada(estado, k)`; (c) si es vacía, no
/// añade nada; (d) si su huella ya está en `Q`, **quita su entrada y añade `(k, huella)` al final**
/// (una entrada por contenido distinto, ordenada por última ventana fresca); (e) si es nueva,
/// guarda el contenido y la añade; si `Q` pasa de
/// `K_TABLAS_VOTO`, descarta la de **menor última ventana fresca** y poda
/// ([`podar_contenido_voto`]).
///
/// El nombre histórico `derivar_tabla_sin_base` se conserva porque `crates/zx-node/src/nodo.rs` (que
/// esta orden no posee) lo usa; su comportamiento ya no es «sin base».
#[expect(
    clippy::integer_division,
    reason = "X1 exige la división entera del índice de ventana; C-ENC-04 prohíbe floats"
)]
pub(crate) fn derivar_tabla_sin_base(ap: &mut Aplicador, slot: u64) {
    let k = slot / T_INST_VOTOS;
    if ap
        .estado
        .ultima_ventana_derivada_sin_base
        .is_some_and(|d| d >= k)
    {
        return;
    }
    // (a) la ventana queda marcada como derivada aunque la tabla salga vacía o repetida: otro
    // bloque de la misma ventana no vuelve a derivar.
    ap.estado.ultima_ventana_derivada_sin_base = Some(k);
    let tabla = tabla_derivada(&ap.estado, k);
    if tabla.is_empty() {
        return;
    }
    let h = hash_payload(0, &tabla);
    // (d) TB4-C-2 · C1 · un par por contenido distinto: la refrescada pasa al final, de modo que
    // la última por posición sea también la de mayor última ventana fresca.
    if let Some(indice) = ap
        .estado
        .cola_tablas_voto
        .iter()
        .position(|(_, huella)| *huella == h)
    {
        ap.estado.cola_tablas_voto.remove(indice);
        ap.estado.cola_tablas_voto.push((k, h));
        podar_contenido_voto(ap);
        return;
    }
    guardar_contenido(&mut ap.estado, &tabla);
    ap.estado.cola_tablas_voto.push((k, h));
    if ap.estado.cola_tablas_voto.len() > K_TABLAS_VOTO {
        // (e) TB4-R2/P3 · sale la entrada de **menor** última ventana fresca (empate: la primera).
        if let Some((indice, _)) = ap
            .estado
            .cola_tablas_voto
            .iter()
            .enumerate()
            .min_by_key(|(_, (ventana, _))| *ventana)
        {
            ap.estado.cola_tablas_voto.remove(indice);
        }
    }
    podar_contenido_voto(ap);
}

/// PD-1b · C5 · asocia las ventanas `m < k ≤ n` a la tabla vigente **antes** de que la base avance
/// de `m` a `n` (el `h_t` que la base tenía comprometido). Es lo que corrige B-47.
fn asociar_ventanas_al_avanzar(ap: &mut Aplicador, m: u64, n: u64, h_vigente: [u8; 32]) {
    let desde = m.saturating_add(1);
    if desde > n {
        return;
    }
    for k in desde..=n {
        ap.estado.tabla_ventana_voto.insert(k, h_vigente);
    }
}

/// AUS-2a · R5 / PD-1b · C6 · cobra la ausencia de la ventana `n` contra `tabla`: por cada clave con
/// deber (toda clave **activa** con `peso_de_clave > 0`, **sin** cuota de plazas) y sin voto admitido
/// (R2), acumula `deuda += G·7` y cobra la parte entera de `deuda / 1 401 600 000` (quemada),
/// conservando el resto.
///
/// AUS-2b · N8 · el peso de cada clave es el **mismo del reparto del certificado** ([`peso_de_clave`]
/// con el `b` vigente, [`B_VOTOS`]); una clave inactiva pesa 0 y no tiene deber.
#[expect(
    clippy::integer_division,
    reason = "R1/R5 exigen división entera exacta (cuota y cobro); C-ENC-04 prohíbe floats"
)]
fn cobrar_ausencia_ventana(ap: &mut Aplicador, n: u64, tabla: &[ClaveTablaVoto], slot: u64) {
    let votantes = ap.estado.votantes_voto.get(&n).cloned().unwrap_or_default();
    let indice = indice_bls_a_ed25519(ap, slot);
    let slot_i64 = i64::try_from(slot).unwrap_or(i64::MAX);
    for c in tabla {
        // PD-1b · C6 · tiene deber toda clave activa con `w_i > 0`, **sin** cuota de plazas.
        // N8 · una clave inactiva no tiene deber (`peso_de_clave` ya devuelve 0).
        let Ok(w_i) = peso_de_clave(&clave_de_tabla(c), B_VOTOS) else {
            continue;
        };
        if w_i == 0 {
            continue;
        }
        let Some(ed) = indice.get(&c.clave_bls).copied() else {
            continue;
        };
        if votantes.contains(&ed) {
            continue;
        }
        // R5 · G = total_castigable en ese momento (puede ser 0: la deuda no crece, no hay cobro).
        let g = total_castigable(&ap.estado, &ed).max(0);
        let incremento = g.saturating_mul(F_AUS_VENTANA_NUM);
        let deuda = {
            let d = ap.estado.deuda_ausencia.entry(ed).or_insert(0);
            *d = d.saturating_add(incremento);
            *d
        };
        let cobrar = deuda / F_AUS_VENTANA_DEN;
        if cobrar > 0 {
            let cobrado = debitar_castigable(ap, ed, cobrar, slot_i64).unwrap_or(0);
            ap.estado.quemado += cobrado;
            if let Some(d) = ap.estado.deuda_ausencia.get_mut(&ed) {
                *d %= F_AUS_VENTANA_DEN;
            }
        }
    }
}

/// AUS-2a · R4/R5/R6 · liquida la ventana `n`: resuelve su tabla, cobra la ausencia y poda el
/// estado de la ventana. La ventana de la base (`n == finalidad_votos_n`) se cobra a su hora pero
/// **conserva** su tabla y sus votantes (como hoy).
pub(crate) fn liquidar_ventana_voto(ap: &mut Aplicador, n: u64, slot: u64) {
    let es_base = ap.estado.finalidad_votos.is_some() && n == ap.estado.finalidad_votos_n;
    if let Some(tabla) = tabla_para_liquidar(&ap.estado, n) {
        cobrar_ausencia_ventana(ap, n, &tabla, slot);
    }
    // PD-1b · C5 · la ventana deja de estar pendiente: se suelta su asociación y se poda el
    // contenido que ninguna otra ventana pendiente (ni la vigente) use.
    ap.estado.tabla_ventana_voto.remove(&n);
    if es_base {
        podar_contenido_voto(ap);
        return;
    }
    ap.estado.tablas_voto.remove(&n);
    ap.estado.votantes_voto.remove(&n);
    podar_contenido_voto(ap);
}

/// PD-1b · C3 · aplica un certificado compacto por peso `0x09`.
///
/// Exige tabla vigente conocida (el contenido de `finalidad_votos_h_t`, o la tabla certificada
/// `tablas_voto[n]` en una repetición); valida con [`zx_votos::peso::evaluar_certificado`] (mapa,
/// firmantes activos, encadenado, ancla y tabla siguiente) y con `verificar_firma_peso` sobre las
/// claves BLS de la tabla vigente en orden canónico. Rigen las guardas del `0x04`: retroceso,
/// caducidad, conflicto y repetición idempotente. Efectos: firmantes a `votantes_voto[n]`, punto de
/// finalidad, tabla vigente (C2) y asociación de ventanas pendientes (C5).
///
/// # Errores
/// [`ErrorTransicion::ErrCertificadoPesoMotivo`] con el motivo del contrato, y las guardas
/// `ErrFinalidadRetrocede`/`ErrCertificadoConflictivo`/`ErrCertificadoPesoTablaDesconocida`.
pub(crate) fn aplicar_certificado_peso(
    ap: &mut Aplicador,
    operacion: &OperacionAlmacenamiento,
    slot: Option<i64>,
) -> Result<(), ErrorTransicion> {
    let OperacionAlmacenamiento::CertificadoPeso { bytes, .. } = operacion else {
        return Err(ErrorTransicion::ErrCertificadoInstancia);
    };
    let slot_app = slot.ok_or(ErrorTransicion::ErrOperacionFase)?;
    let n = ventana_de_certificado_peso(bytes)?;
    // TB-1a · R5 · T9 · la ventana no puede ser futura: el slot del bloque que aplica debe ser al
    // menos la apertura de `n`. Va justo después de leer `n` y antes de cualquier otra guarda.
    if u64::try_from(slot_app).unwrap_or(u64::MAX) < apertura_ventana(n) {
        return Err(ErrorTransicion::ErrCertificadoVentanaFutura);
    }
    // CERT-T · el techo inclusivo rige también para rearranques y repeticiones, antes de
    // cualquier otra guarda, igual que el plazo del acta de presencia.
    if u64::try_from(slot_app).unwrap_or(u64::MAX)
        > cierre_ventana(n).saturating_add(W_REVEAL_SLOTS_VOTOS)
    {
        return Err(ErrorTransicion::ErrCertificadoPlazo);
    }

    let finalidad_presente = ap.estado.finalidad_votos.is_some();
    let compromiso_presente = ap.estado.finalidad_votos_h_t.is_some();
    if finalidad_presente != compromiso_presente
        || (!finalidad_presente && ap.estado.finalidad_votos_n != 0)
    {
        return Err(ErrorTransicion::ErrCertificadoConflictivo);
    }
    if n < ap.estado.finalidad_votos_n {
        return Err(ErrorTransicion::ErrFinalidadRetrocede);
    }
    let repeticion = finalidad_presente && n == ap.estado.finalidad_votos_n;

    // RA-1 · Y3 · un certificado posterior a la caducidad (`n > m + CADUCIDAD`) se admite solo como
    // certificado de **rearranque**: su ventana abre en la fase activa de un ciclo y existe la
    // instantánea de la tabla de ese ciclo. Sustituye la guarda 4 (RV-1) cuando `A > 0`.
    let mut instantanea_rearranque: Option<(Vec<ClaveTablaVoto>, [u8; 32])> = None;
    if finalidad_presente
        && n > ap
            .estado
            .finalidad_votos_n
            .saturating_add(CADUCIDAD_TABLA_VENTANAS)
    {
        let Some(cal) =
            calendario_rearranque(&ap.estado.parametros_sector, ap.estado.finalidad_votos_n)
        else {
            return Err(ErrorTransicion::ErrCertificadoInstancia);
        };
        let Some(j) = cal.ciclo_de_apertura(apertura_ventana(n)) else {
            return Err(ErrorTransicion::ErrRearranqueFueraDeFase);
        };
        let Some(h) = ap.estado.tabla_ciclo_rearranque.get(&j).copied() else {
            return Err(ErrorTransicion::ErrRearranqueSinTabla);
        };
        let Some(tabla) = ap.estado.tablas_voto_contenido.get(&h).cloned() else {
            return Err(ErrorTransicion::ErrRearranqueSinTabla);
        };
        instantanea_rearranque = Some((tabla, h));
    }
    let es_rearranque = instantanea_rearranque.is_some();

    // Tabla vigente (C2): el contenido de `finalidad_votos_h_t`; en una repetición, la tabla
    // certificada guardada de la ventana, que el mapa de bits indexa. En un rearranque, la
    // instantánea del ciclo (Y3).
    let (tabla_vigente, h_vig) = if let Some((tabla, h)) = instantanea_rearranque {
        (tabla, h)
    } else if repeticion {
        let Some(guardada) = ap.estado.tablas_voto.get(&n) else {
            return Err(ErrorTransicion::ErrCertificadoPesoTablaDesconocida);
        };
        let guardada = contenido_canonico(guardada);
        let h = hash_payload(n, &guardada);
        (guardada, h)
    } else if let Some(h) = ap.estado.finalidad_votos_h_t {
        let Some(tabla) = ap.estado.tablas_voto_contenido.get(&h).cloned() else {
            return Err(ErrorTransicion::ErrCertificadoPesoTablaDesconocida);
        };
        (tabla, h)
    } else {
        // TB-1c-2 · X2 · T5′ · sin base (`finalidad_votos` y `finalidad_votos_h_t` ausentes): la
        // tabla vigente del primer `0x09` es el **contenido de la huella declarada** en la cabecera
        // fija, y esa huella tiene que estar en la cola `Q(E)` que el gancho X1 fue llenando al
        // cruzar ventanas. Se decide **antes** de validar claves ni firmas. Ninguna llamada a
        // `tabla_derivada`/`tabla_canonica` interviene en la validez de esta rama.
        let h_declarada = huella_tabla_de_certificado_peso(bytes)?;
        if !ap
            .estado
            .cola_tablas_voto
            .iter()
            .any(|(_, h)| *h == h_declarada)
        {
            return Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                MotivoPeso::TablaNoDerivada,
            ));
        }
        let Some(tabla) = ap.estado.tablas_voto_contenido.get(&h_declarada).cloned() else {
            return Err(ErrorTransicion::ErrTablaDerivadaSinContenido);
        };
        (tabla, h_declarada)
    };

    // TB4-R3/R4 · huellas que el estado acepta como siguiente: las de `Q` con edad `≤ X`, en las
    // **tres** ramas (con base, sin base y rearranque). En el rearranque la tabla que verifica la
    // firma y el cuórum sigue siendo la instantánea (`h_vig`), pero lo que se compromete como
    // siguiente es la tabla fresca de `Q`. Se decide **antes** de validar claves ni firmas.
    let aceptadas = huellas_aceptadas(&ap.estado, n);

    let cert = parsear_certificado_peso(bytes, tabla_vigente.len())?;
    if cert.n != n {
        return Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::Ventana,
        ));
    }
    // T3/T5/T6 · C2: huella no derivada, rechazo **sin** validar claves ni firmas.
    if !aceptadas.contains(&cert.h_t_siguiente) {
        return Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::TablaNoDerivada,
        ));
    }

    let tabla_ref = tabla_contrato(n, &tabla_vigente);
    let claves_bls = claves_bls_de_tabla(&tabla_vigente)?;
    let firma_ok = peso::verificar_firma_peso(&tabla_ref, &claves_bls, &cert).is_ok();
    let (genesis, cert_previo) = if finalidad_presente && n > ap.estado.finalidad_votos_n {
        (
            false,
            Some(CertPrevioPeso {
                n: ap.estado.finalidad_votos_n,
                h_t_siguiente: h_vig,
            }),
        )
    } else {
        (true, None)
    };
    let entrada = EntradaPeso {
        b: B_VOTOS,
        genesis,
        n_certificado: cert.n,
        ventana: n,
        tabla_vigente: &tabla_ref,
        cert_previo,
        tabla_comprometida: &h_vig,
        raiz_estado: &cert.raiz_estado,
        raiz_firmada: &cert.raiz_estado,
        firma_ok,
        h_t_siguiente_declarada: &cert.h_t_siguiente,
        h_t_siguiente_aceptadas: &aceptadas,
        acta: false,
        mapa_bits: &cert.mapa,
    };
    let resultado = peso::evaluar_certificado(&entrada)
        .map_err(|_| ErrorTransicion::ErrCertificadoPesoBytes)?;
    if !resultado.valido {
        let motivo = resultado
            .motivos
            .first()
            .copied()
            .unwrap_or(MotivoPeso::Quorum);
        return Err(ErrorTransicion::ErrCertificadoPesoMotivo(motivo));
    }

    let candidato_hash = BlockHash::from_digest(Digest::from_bytes(cert.candidato));
    if repeticion {
        let coincide = ap.estado.finalidad_votos == Some(candidato_hash)
            && ap.estado.finalidad_votos_h_t == Some(cert.h_t_siguiente);
        return if coincide {
            Ok(())
        } else {
            Err(ErrorTransicion::ErrCertificadoConflictivo)
        };
    }

    // C5 · asocia las ventanas pendientes a la tabla vigente antes del avance. En un rearranque
    // (Y4), las ventanas `m < k ≤ m + CADUCIDAD_TABLA_VENTANAS` **no** se asocian: ya están
    // liquidadas cuando puede llegar un certificado de rearranque (W6.2). Las ventanas
    // `m + CADUCIDAD < k < n` siguen sin tabla (IPA B-48). La `n` queda asociada como cualquier
    // ventana certificada.
    if finalidad_presente {
        let m = ap.estado.finalidad_votos_n;
        if es_rearranque {
            ap.estado.tabla_ventana_voto.insert(n, h_vig);
        } else {
            asociar_ventanas_al_avanzar(ap, m, n, h_vig);
        }
    }

    // Efectos: los firmantes pasan a `votantes_voto[n]`.
    let indice = indice_bls_a_ed25519(ap, u64::try_from(slot_app).unwrap_or(0));
    let mut votantes: BTreeSet<ClaveEd25519> = BTreeSet::new();
    for posicion in peso::firmantes_de_mapa(&cert.mapa) {
        if let Some(c) = posicion.checked_sub(1).and_then(|p| tabla_vigente.get(p))
            && let Some(ed) = indice.get(&c.clave_bls)
        {
            votantes.insert(*ed);
        }
    }
    ap.estado
        .votantes_voto
        .entry(n)
        .or_default()
        .extend(votantes);

    // Tabla vigente (T3): el contenido de la huella declarada, que ya está en el estado (en la cola
    // `Q` o es la vigente). Si faltara, es un error interno, nunca un `panic` ni una aceptación.
    guardar_contenido(&mut ap.estado, &tabla_vigente);
    if !ap
        .estado
        .tablas_voto_contenido
        .contains_key(&cert.h_t_siguiente)
    {
        return Err(ErrorTransicion::ErrTablaDerivadaSinContenido);
    }
    // Compatibilidad con el camino de liquidación previo y las repeticiones.
    ap.estado.tablas_voto.insert(n, tabla_vigente.clone());

    // RA-1 · Y2 · al avanzar la base se borran **todas** las instantáneas de ciclo.
    ap.estado.tabla_ciclo_rearranque.clear();
    ap.estado.finalidad_votos_n = n;
    ap.estado.finalidad_votos = Some(candidato_hash);
    ap.estado.finalidad_votos_h_t = Some(cert.h_t_siguiente);

    // RE-2c · R1/C1′ · el estado guarda la raíz del **último** certificado aplicado con éxito (un
    // solo valor; cubre las tres ramas: con base, sin base y rearranque, que confluyen aquí). No se
    // calcula ni se compara.
    ap.estado.raiz_estado = Some(cert.raiz_estado);

    // TB4-R6 · un solo dueño de `Q`: la ruta de aplicación **no** empuja pares. El gancho por
    // ventana ([`derivar_tabla_sin_base`]) es el único que mantiene la cola, de modo que la edad
    // `n − k` es la última ventana fresca real. La poda retira los contenidos que ya no referencia
    // nadie.
    podar_contenido_voto(ap);
    Ok(())
}

/// PD-1b · C4 · aplica un acta de presencia `0x0A`.
///
/// Admisible en `[apertura(n), cierre(n) + W_REVEAL]`, con la ventana no liquidada y la tabla de la
/// ventana conocida (C5). AT-1b · W6.1: el acta **no** se rechaza porque la base esté ya en su
/// ventana o más allá (no encadena con la base). Se valida como acta (sin quórum) con firma real;
/// efecto único: sus firmantes pasan a `votantes_voto[n]`. Un acta cuyos firmantes ya constan todos
/// se rechaza por repetida.
///
/// # Errores
/// `ErrActaPlazo`, `ErrActaLiquidada`, `ErrActaTablaDesconocida`, `ErrActaRepetida` y
/// [`ErrorTransicion::ErrCertificadoPesoMotivo`].
pub(crate) fn aplicar_acta_presencia(
    ap: &mut Aplicador,
    operacion: &OperacionAlmacenamiento,
    slot: i64,
) -> Result<(), ErrorTransicion> {
    let OperacionAlmacenamiento::ActaPresencia { bytes, .. } = operacion else {
        return Err(ErrorTransicion::ErrActaTablaDesconocida);
    };
    let n = ventana_de_certificado_peso(bytes)?;
    let slot_u = u64::try_from(slot).unwrap_or(u64::MAX);
    if slot_u < apertura_ventana(n)
        || slot_u > cierre_ventana(n).saturating_add(W_REVEAL_SLOTS_VOTOS)
    {
        return Err(ErrorTransicion::ErrActaPlazo);
    }
    if ap
        .estado
        .liquidacion_voto_hasta
        .is_some_and(|hasta| n <= hasta)
    {
        return Err(ErrorTransicion::ErrActaLiquidada);
    }
    let Some(tabla_vigente) = tabla_de_ventana(&ap.estado, n) else {
        return Err(ErrorTransicion::ErrActaTablaDesconocida);
    };
    let cert = parsear_certificado_peso(bytes, tabla_vigente.len())?;
    if cert.n != n {
        return Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            MotivoPeso::Ventana,
        ));
    }
    let tabla_ref = tabla_contrato(n, &tabla_vigente);
    let claves_bls = claves_bls_de_tabla(&tabla_vigente)?;
    let firma_ok = peso::verificar_firma_peso(&tabla_ref, &claves_bls, &cert).is_ok();
    let h_vig = hash_payload(n, &tabla_vigente);
    // El acta no compromete tabla: su huella declarada se compara con la vigente.
    let aceptadas_acta = [h_vig];
    // AT-1b · W6.1 · el acta **no encadena con la base**: vale para cualquier ventana con tabla
    // conocida dentro de su plazo, aunque la base esté ya en esa ventana o más allá (el encadenado
    // solo tiene sentido para el certificado, que mueve la finalidad). `genesis = true` deja inerte
    // la comprobación de encadenado de `evaluar_certificado`; la tabla se sigue comprobando contra
    // `h_vig` (tabla vigente de la ventana) y la firma sobre los campos reales del acta.
    let (genesis, cert_previo) = (true, None);
    let entrada = EntradaPeso {
        b: B_VOTOS,
        genesis,
        n_certificado: cert.n,
        ventana: n,
        tabla_vigente: &tabla_ref,
        cert_previo,
        tabla_comprometida: &h_vig,
        raiz_estado: &cert.raiz_estado,
        raiz_firmada: &cert.raiz_estado,
        firma_ok,
        // PD-1c · G3 · un acta no compromete tabla: declare la tabla siguiente que declare, la
        // comprobación de tabla queda inerte (se le pasa el hash de la tabla vigente). La firma se
        // verifica de verdad sobre A3 con el `h_t_siguiente` y la raíz reales en `firma_ok`
        // (`peso::verificar_firma_peso` usa `cert.h_t_siguiente`).
        h_t_siguiente_declarada: &h_vig,
        h_t_siguiente_aceptadas: &aceptadas_acta,
        acta: true,
        mapa_bits: &cert.mapa,
    };
    let resultado = peso::evaluar_certificado(&entrada)
        .map_err(|_| ErrorTransicion::ErrCertificadoPesoBytes)?;
    if !resultado.valido {
        let motivo = resultado
            .motivos
            .first()
            .copied()
            .unwrap_or(MotivoPeso::Quorum);
        return Err(ErrorTransicion::ErrCertificadoPesoMotivo(motivo));
    }

    // ACTA-1 · R1 · una sola traducción: la misma función pura que consume el productor.
    let nuevos = votantes_de_mapa(
        &ap.estado,
        &tabla_vigente,
        &cert.mapa,
        u64::try_from(slot).unwrap_or(0),
    );
    let ya: BTreeSet<ClaveEd25519> = ap.estado.votantes_voto.get(&n).cloned().unwrap_or_default();
    if nuevos.is_empty() || nuevos.is_subset(&ya) {
        return Err(ErrorTransicion::ErrActaRepetida);
    }
    ap.estado.votantes_voto.entry(n).or_default().extend(nuevos);
    Ok(())
}

/// PD-1c · castigo común del doble voto (`0x05` y `0x0B`): deduplicación por `incident_id`,
/// incidente único, congelación total, confiscación `C = min(V, techo(f·V))`, recompensa al
/// incluidor (25 %) y quema del resto. Devuelve [`ErrorTransicion::ErrEvidenciaDuplicada`] si el
/// incidente ya estaba registrado.
fn castigar_doble_voto(
    ap: &mut Aplicador,
    clave: ClaveEd25519,
    iid: [u8; 32],
    bloque: &BloqueTransicion,
    params: &ParametrosTransicion,
    evp: &ParametrosEvidencia,
    punto: Punto,
) -> Result<(), ErrorTransicion> {
    // Deduplicación por `incident_id`.
    {
        let g = ap.garantia_mut(clave);
        if g.incidentes.iter().any(|i| i.id == iid) {
            return Err(ErrorTransicion::ErrEvidenciaDuplicada);
        }
    }

    // Registro del incidente y congelación total (gravamen derivado, EV-11/EV-17).
    let slot_falta = punto.como_slot().map(|s| s as i64).unwrap_or(0);
    {
        let g = ap.garantia_mut(clave);
        g.incidentes.push(crate::transicion::tipos::Incidente {
            id: iid,
            slot_falta,
        });
        g.incidentes.sort_by_key(|a| a.id);
    }
    let v = total_castigable(&ap.estado, &clave);
    {
        let g = ap.garantia_mut(clave);
        g.congelado = amount_saturado(v);
    }

    // Confiscación `C = min(V, techo(f·V))` sobre el total castigable; el cobro real puede ser
    // menor y la recompensa/quema se calculan sobre él (RAT-2′), sin recompensa ficticia.
    let c = core::cmp::min(v, techo_fraccion(v, evp.f_num, evp.f_den));
    let cobrado = debitar_castigable(ap, clave, c, punto.como_i64())?;
    let productor = bloque
        .hechos
        .productor()
        .ok_or(ErrorTransicion::ErrGenesis)?;
    let recompensa = suelo_dos_octavos(cobrado);
    if recompensa > 0 {
        creditar_post(ap, productor, amount_saturado(recompensa), punto, params)?;
    }
    ap.estado.quemado += cobrado - recompensa;
    let remanente = total_castigable(&ap.estado, &clave);
    {
        let g = ap.garantia_mut(clave);
        g.congelado = amount_saturado(remanente);
    }
    Ok(())
}

/// PD-1c · G5 / AT-1b · W4 · aplica una evidencia de dos votos por peso `0x0B` (contrato v2 B2).
///
/// Admisible si y solo si:
/// 1. los dos votos están en orden **estrictamente creciente** de
///    `(ventana, candidato, h_t_siguiente, raíz)` (forma canónica: contenido distinto);
/// 2. si los dos votos son de **ventanas distintas**, el hecho `hecho_voto` calculado por
///    `zx-cadena` (W2) decide: `Falta` sigue el mismo camino que la misma ventana;
///    `SinFalta` → [`ErrorTransicion::ErrEvidenciaSinFalta`]; sin hecho o `Inadmisible` →
///    [`ErrorTransicion::ErrEvidenciaInadmisible`] (la transacción se descarta);
/// 3. el slot está dentro de `cierre(n) + plazo_slots`;
/// 4. la clave BLS acusada está registrada en el estado;
/// 5. las dos firmas BLS verifican sobre A3 con el candidato, `h_t_siguiente` y raíz de cada voto.
///
/// Efecto: exactamente el castigo del `0x05` ([`castigar_doble_voto`]), con un `incident_id` que
/// incluye las dos raíces.
///
/// # Errores
/// [`ErrorTransicion::ErrEvidenciaVoto`], [`ErrorTransicion::ErrEvidenciaInadmisible`],
/// [`ErrorTransicion::ErrEvidenciaSinFalta`], [`ErrorTransicion::ErrEvidenciaDuplicada`],
/// [`ErrorTransicion::ErrOperacionFase`].
pub(crate) fn aplicar_evidencia_votos_peso(
    ap: &mut Aplicador,
    operacion: &OperacionAlmacenamiento,
    bloque: &BloqueTransicion,
    params: &ParametrosTransicion,
    evp: &ParametrosEvidencia,
    punto: Punto,
    hecho_voto: Option<HechoVoto>,
) -> Result<(), ErrorTransicion> {
    if ap.estado.fase == Fase::PoW {
        return Err(ErrorTransicion::ErrOperacionFase);
    }
    let OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave_bls,
        voto1,
        voto2,
        ..
    } = operacion
    else {
        return Err(ErrorTransicion::ErrEvidenciaVoto);
    };
    // (1) Forma canónica estricta: contenido distinto y en orden.
    if (
        voto1.n,
        voto1.candidato,
        voto1.h_t_siguiente,
        voto1.raiz_estado,
    ) >= (
        voto2.n,
        voto2.candidato,
        voto2.h_t_siguiente,
        voto2.raiz_estado,
    ) {
        return Err(ErrorTransicion::ErrEvidenciaVoto);
    }
    // (2) AT-1b · W4 · ventanas distintas: la falta «voto contra la propia atadura» (contrato v2 B1)
    // la decide el hecho calculado por `zx-cadena` (W2). `Falta` sigue el mismo camino de
    // comprobaciones y castigo que la misma ventana; `SinFalta` e `Inadmisible` (o sin hecho) se
    // descartan sin invalidar el bloque.
    let ventanas_distintas = voto1.n != voto2.n;
    if ventanas_distintas {
        match hecho_voto {
            Some(HechoVoto::Falta) => {}
            Some(HechoVoto::SinFalta) => return Err(ErrorTransicion::ErrEvidenciaSinFalta),
            _ => return Err(ErrorTransicion::ErrEvidenciaInadmisible),
        }
    }
    // (3) Plazo `cierre(n₂) + plazo_slots` (el de `ParametrosSector` del estado), como el `0x05`.
    // Con la misma ventana `n₁ = n₂`, no cambia.
    let slot_app = punto.como_slot().ok_or(ErrorTransicion::ErrOperacionFase)?;
    let plazo_slots = u64::try_from(ap.estado.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
    if slot_app > cierre_ventana(voto2.n).saturating_add(plazo_slots) {
        return Err(ErrorTransicion::ErrEvidenciaVoto);
    }
    // (4) La clave BLS acusada debe estar registrada (actual o anterior viva, V5).
    let indice = indice_bls_a_ed25519(ap, slot_app);
    let clave = *indice
        .get(clave_bls)
        .ok_or(ErrorTransicion::ErrEvidenciaVoto)?;

    // (5) Las dos firmas BLS verifican sobre A3 con la raíz de cada voto.
    let pk = ClavePublica::desde_bytes(clave_bls).map_err(|_| ErrorTransicion::ErrEvidenciaVoto)?;
    let firma1 = Firma::desde_bytes(&voto1.firma).map_err(|_| ErrorTransicion::ErrEvidenciaVoto)?;
    let firma2 = Firma::desde_bytes(&voto2.firma).map_err(|_| ErrorTransicion::ErrEvidenciaVoto)?;
    let m1 = peso::mensaje_voto_peso(
        voto1.n,
        &voto1.candidato,
        &voto1.h_t_siguiente,
        &voto1.raiz_estado,
    );
    let m2 = peso::mensaje_voto_peso(
        voto2.n,
        &voto2.candidato,
        &voto2.h_t_siguiente,
        &voto2.raiz_estado,
    );
    if verificar(&pk, &firma1, DOMINIO_VOTO, &m1).is_err()
        || verificar(&pk, &firma2, DOMINIO_VOTO, &m2).is_err()
    {
        return Err(ErrorTransicion::ErrEvidenciaVoto);
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "ocho campos del contrato, sin agrupar"
    )]
    let iid = if ventanas_distintas {
        // AT-1b · W4 · la falta entre ventanas exige un incidente cuyo identificador incluya las
        // **dos** ventanas; el de la misma ventana no cambia (W5).
        incident_id_doble_voto_peso_ventanas(
            voto1.n,
            voto2.n,
            clave_bls,
            &voto1.candidato,
            &voto1.h_t_siguiente,
            &voto1.raiz_estado,
            &voto2.candidato,
            &voto2.h_t_siguiente,
            &voto2.raiz_estado,
        )
    } else {
        incident_id_doble_voto_peso(
            voto1.n,
            clave_bls,
            &voto1.candidato,
            &voto1.h_t_siguiente,
            &voto1.raiz_estado,
            &voto2.candidato,
            &voto2.h_t_siguiente,
            &voto2.raiz_estado,
        )
    };
    castigar_doble_voto(ap, clave, iid, bloque, params, evp, punto)
}

/// AUS-2a · R3 · Aplica un voto propio `0x08` sobre `estado` y devuelve el undo por delta.
///
/// Interfaz de integración/prueba del mismo camino que usa `aplicar_tx`; el llamante puede revertir
/// con [`crate::transicion::deshacer`].
pub fn aplicar_voto_propio_con_undo(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    slot: i64,
) -> (Estado, Undo, Result<(), ErrorTransicion>) {
    let mut ap = Aplicador::nuevo(estado.clone());
    let resultado = aplicar_voto_propio(&mut ap, op, slot);
    (ap.estado, ap.undo, resultado)
}

/// PD-1b · C3 · Aplica un certificado compacto por peso `0x09` sobre `estado` y devuelve el undo.
pub fn aplicar_certificado_peso_con_undo(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    slot: i64,
) -> (Estado, Undo, Result<(), ErrorTransicion>) {
    let mut ap = Aplicador::nuevo(estado.clone());
    let resultado = aplicar_certificado_peso(&mut ap, op, Some(slot));
    (ap.estado, ap.undo, resultado)
}

/// RA-1 · Y1/Y2 · Ejecuta el gancho de instantáneas de ciclo sobre `estado` y devuelve el undo.
///
/// Interfaz de integración/prueba del mismo camino que usa el gancho por bloque
/// (`liquidar_ventanas_voto`).
pub fn tomar_instantaneas_rearranque_con_undo(estado: &Estado, slot: u64) -> (Estado, Undo) {
    let mut ap = Aplicador::nuevo(estado.clone());
    tomar_instantaneas_rearranque(&mut ap, slot);
    (ap.estado, ap.undo)
}

/// TB-1c-2 · X1 · interfaz de integración/prueba del gancho [`derivar_tabla_sin_base`] por bloque.
///
/// Mismo camino que el bloque real (`liquidar_ventanas_voto`): con el **estado de entrada** y el
/// slot `s` del bloque. Devuelve el estado resultante y su undo para comprobar deshacer exacto.
pub fn derivar_tabla_sin_base_con_undo(estado: &Estado, slot: u64) -> (Estado, Undo) {
    let mut ap = Aplicador::nuevo(estado.clone());
    derivar_tabla_sin_base(&mut ap, slot);
    (ap.estado, ap.undo)
}

/// PD-1b · C4 · Aplica un acta de presencia `0x0A` sobre `estado` y devuelve el undo.
pub fn aplicar_acta_presencia_con_undo(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    slot: i64,
) -> (Estado, Undo, Result<(), ErrorTransicion>) {
    let mut ap = Aplicador::nuevo(estado.clone());
    let resultado = aplicar_acta_presencia(&mut ap, op, slot);
    (ap.estado, ap.undo, resultado)
}

/// PD-1c · G5 · Aplica una evidencia de dos votos por peso `0x0B` sobre `estado` y devuelve el undo.
///
/// Misma interfaz de integración/prueba que [`aplicar_evidencia_votos_peso_con_undo`]: construye un
/// bloque PoST mínimo con `productor` como incluidor (el premio del 25 % se acredita a él).
pub fn aplicar_evidencia_votos_peso_con_undo(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    productor: ClaveEd25519,
    params: &ParametrosTransicion,
    evp: &ParametrosEvidencia,
    slot: u64,
) -> (Estado, Undo, Result<(), ErrorTransicion>) {
    aplicar_evidencia_votos_peso_con_hecho_con_undo(estado, op, productor, params, evp, slot, None)
}

/// AT-1b · W4 · como [`aplicar_evidencia_votos_peso_con_undo`] pero con el hecho explícito
/// calculado por `zx-cadena` (W2). `None` equivale a `Inadmisible` para las ventanas distintas.
///
/// Interfaz de integración/prueba del mismo camino que usa `aplicar_tx`; permite probar la falta de
/// la parte B sin una `Cadena` real.
pub fn aplicar_evidencia_votos_peso_con_hecho_con_undo(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    productor: ClaveEd25519,
    params: &ParametrosTransicion,
    evp: &ParametrosEvidencia,
    slot: u64,
    hecho: Option<HechoVoto>,
) -> (Estado, Undo, Result<(), ErrorTransicion>) {
    let nulo = BlockHash::from_digest(Digest::from_bytes([0u8; 32]));
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: nulo,
            padre: nulo,
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        Vec::new(),
    );
    let mut ap = Aplicador::nuevo(estado.clone());
    let resultado =
        aplicar_evidencia_votos_peso(&mut ap, op, &bloque, params, evp, Punto::Slot(slot), hecho);
    (ap.estado, ap.undo, resultado)
}

#[cfg(test)]
mod tb4_r9 {
    use zx_core::{BlockHash, ClavePublica as ClaveEd25519, ClaveTablaVoto, Digest};
    use zx_votos::{ClaveSecreta, DOMINIO_VOTO};

    use crate::sectores::{ClaveVoto, Etapa, NO_HAY, ParametrosSector, RegistroSector, SectorId};
    use crate::transicion::estado::Aplicador;
    use crate::transicion::tipos::Estado;

    use super::{
        ErrorTransicion, MotivoPeso, aplicar_certificado_peso_con_undo, contenido_canonico,
        derivar_tabla_sin_base_con_undo, hash_payload, tabla_canonica, tabla_contrato,
        tabla_derivada_con_tope, tomar_instantaneas_rearranque_con_tope,
    };

    type Error = Box<dyn std::error::Error>;

    fn identidad(estado: &mut Estado, ed: u8, bls: [u8; 48], peso: u16) {
        let clave = ClaveEd25519::desde_bytes([ed; 32]);
        estado.claves_voto.insert(
            clave,
            ClaveVoto {
                clave_bls: bls,
                prueba_posesion: [0; 96],
            },
        );
        for sector_index in 0..peso {
            let id = SectorId {
                clave,
                sector_index,
                version: 0,
            };
            estado.sectores.insert(
                id,
                RegistroSector {
                    id,
                    r2: [0; 4],
                    history_size: 1,
                    etapa: Etapa::Activo,
                    alta_slot: 1,
                    renovacion_slot: 1_000,
                    retiro_slot: NO_HAY,
                    fianza: estado.parametros_sector.q_sec,
                    aud_apertura: NO_HAY,
                    aud_contestada: NO_HAY,
                },
            );
        }
    }

    fn estado_de_recorte() -> Estado {
        let mut estado = Estado::inicial();
        estado.parametros_sector = ParametrosSector::dev();
        estado.finalidad_votos = Some(BlockHash::from_digest(Digest::from_bytes([9; 32])));
        for (ed, bls, peso) in [
            (1, 0x30, 2),
            (2, 0x31, 2),
            (3, 0x10, 1),
            (4, 0x50, 1),
            (5, 0x20, 1),
            (6, 0x40, 1),
        ] {
            identidad(
                &mut estado,
                ed,
                std::array::from_fn(|i| if i == 0 { bls } else { 0 }),
                peso,
            );
        }
        let vigente: Vec<ClaveTablaVoto> = tabla_canonica(&estado, 602)
            .into_iter()
            .filter(|c| c.clave_bls.first() == Some(&0x40))
            .collect();
        let h = hash_payload(0, &vigente);
        estado.finalidad_votos_h_t = Some(h);
        estado.tablas_voto_contenido.insert(h, vigente);
        estado
    }

    #[test]
    fn tb4_r9_la_instantanea_aplica_el_tope() -> Result<(), Error> {
        let estado = estado_de_recorte();
        let mut ap = Aplicador::nuevo(estado.clone());
        tomar_instantaneas_rearranque_con_tope(&mut ap, 603, 4);
        let h = ap
            .estado
            .tabla_ciclo_rearranque
            .get(&0)
            .ok_or("sin instantánea")?;
        let tabla = ap
            .estado
            .tablas_voto_contenido
            .get(h)
            .ok_or("sin contenido")?;
        assert_eq!(tabla.len(), 4, "se recorta de seis identidades a cuatro");
        let claves: Vec<u8> = tabla
            .iter()
            .filter_map(|c| c.clave_bls.first().copied())
            .collect();
        assert_eq!(
            claves,
            vec![0x10, 0x30, 0x31, 0x40],
            "mayor peso; vigente; menor clave BLS; salida canónica"
        );
        assert_eq!(
            tabla.iter().map(|c| c.peso).collect::<Vec<_>>(),
            vec![1, 2, 2, 1]
        );
        assert_eq!(*tabla, tabla_derivada_con_tope(&estado, 301, 4));
        for tope in [0, 1] {
            let mut ap = Aplicador::nuevo(estado.clone());
            tomar_instantaneas_rearranque_con_tope(&mut ap, 603, tope);
            let h = ap
                .estado
                .tabla_ciclo_rearranque
                .get(&0)
                .ok_or("sin instantánea de borde")?;
            assert_eq!(
                ap.estado
                    .tablas_voto_contenido
                    .get(h)
                    .ok_or("sin contenido de borde")?
                    .len(),
                tope
            );
        }
        Ok(())
    }

    #[test]
    fn tb4_r9_por_debajo_del_tope_la_instantanea_es_identica() -> Result<(), Error> {
        let estado = estado_de_recorte();
        let canonica = contenido_canonico(&tabla_canonica(&estado, 602));
        let h_anterior = hash_payload(0, &canonica);
        for tope in [6, 7] {
            let mut ap = Aplicador::nuevo(estado.clone());
            tomar_instantaneas_rearranque_con_tope(&mut ap, 603, tope);
            assert_eq!(ap.estado.tabla_ciclo_rearranque.get(&0), Some(&h_anterior));
            assert_eq!(
                ap.estado.tablas_voto_contenido.get(&h_anterior),
                Some(&canonica)
            );
            assert_eq!(crate::transicion::deshacer(&ap.estado, &ap.undo), estado);
        }
        Ok(())
    }

    #[test]
    fn tb4_r9_el_rearranque_verifica_con_la_instantanea_recortada() -> Result<(), Error> {
        let mut estado = Estado::inicial();
        estado.parametros_sector = ParametrosSector::dev();
        estado.finalidad_votos = Some(BlockHash::from_digest(Digest::from_bytes([9; 32])));
        let mut secretas = Vec::new();
        for (ed, peso) in [(1, 3), (2, 3), (3, 3), (4, 2), (5, 1), (6, 1)] {
            let ikm: [u8; 32] = std::array::from_fn(|i| match i {
                0 => ed,
                31 => 0xA5,
                _ => 0,
            });
            let secreta = ClaveSecreta::generar(&ikm)?;
            identidad(&mut estado, ed, secreta.clave_publica().bytes(), peso);
            secretas.push(secreta);
        }
        let completa = contenido_canonico(&tabla_canonica(&estado, 602));
        assert_eq!(completa.len(), 6);
        assert_eq!(completa.iter().map(|c| c.peso).sum::<u64>(), 13);
        let h_completa = hash_payload(0, &completa);
        estado.finalidad_votos_h_t = Some(h_completa);
        estado.tablas_voto_contenido.insert(h_completa, completa);
        let mut ap = Aplicador::nuevo(estado);
        tomar_instantaneas_rearranque_con_tope(&mut ap, 603, 3);
        let h = *ap
            .estado
            .tabla_ciclo_rearranque
            .get(&0)
            .ok_or("sin instantánea")?;
        let tabla = ap
            .estado
            .tablas_voto_contenido
            .get(&h)
            .ok_or("sin contenido")?
            .clone();
        assert_ne!(h, h_completa);
        assert_eq!(tabla.len(), 3);
        assert_eq!(tabla.iter().map(|c| c.peso).sum::<u64>(), 9);
        assert!(tabla.iter().all(|c| c.peso == 3));

        // Q procede del gancho real; la fresca difiere de la instantánea que verifica.
        let (estado, _) = derivar_tabla_sin_base_con_undo(&ap.estado, 1_262);
        let h_siguiente = estado.cola_tablas_voto.last().ok_or("sin tabla fresca")?.1;
        assert_eq!(h_siguiente, h_completa);
        let mensaje = zx_votos::mensaje_voto_peso(631, &[0x93; 32], &h_siguiente, &[0; 32]);
        let mut votos = Vec::new();
        for secreta in secretas.iter().take(2) {
            let clave = secreta.clave_publica().bytes();
            let posicion = tabla
                .iter()
                .position(|c| c.clave_bls == clave)
                .ok_or("firmante fuera")?;
            votos.push((
                posicion + 1,
                zx_votos::firmar(secreta, DOMINIO_VOTO, &mensaje)?,
            ));
        }
        for cantidad in [1, 2] {
            let cert = zx_votos::construir_certificado(
                631,
                [0x93; 32],
                h_siguiente,
                [0; 32],
                &tabla_contrato(631, &tabla),
                votos.get(..cantidad).ok_or("faltan votos")?,
            )?;
            let op = zx_core::OperacionAlmacenamiento::CertificadoPeso {
                clave: ClaveEd25519::desde_bytes([200; 32]),
                bytes: zx_votos::serial_certificado_peso(&cert),
            };
            let (nuevo, undo, resultado) = aplicar_certificado_peso_con_undo(&estado, &op, 1_262);
            if cantidad == 1 {
                assert_eq!(
                    resultado,
                    Err(ErrorTransicion::ErrCertificadoPesoMotivo(
                        MotivoPeso::Quorum
                    )),
                    "peso 3/9 no alcanza dos tercios"
                );
            } else {
                resultado?;
                assert_eq!(
                    nuevo.finalidad_votos_n, 631,
                    "6/9 alcanza exactamente dos tercios; 6/13 no"
                );
                assert_eq!(nuevo.finalidad_votos_h_t, Some(h_siguiente));
                assert_eq!(nuevo.tabla_ventana_voto.get(&631), Some(&h));
                assert!(nuevo.tabla_ciclo_rearranque.is_empty());
                assert_eq!(crate::transicion::deshacer(&nuevo, &undo), estado);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tb1a {
    //! TB-1a · R2 · la prueba del recorte de T7 usa [`tabla_derivada_con_tope`], que no es pública
    //! fuera de este crate; por eso vive como test unitario aquí y no en `tests/tb1a_cola.rs`.

    use zx_core::{ClavePublica as ClaveEd25519, ClaveTablaVoto};

    use crate::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
    use crate::transicion::tipos::Estado;

    use super::{hash_payload, tabla_derivada_con_tope};

    /// Entrada de tabla con la clave BLS que empieza por `bls` y el peso dado.
    fn entrada(bls: u8, peso: u64) -> ClaveTablaVoto {
        ClaveTablaVoto {
            clave_bls: std::array::from_fn(|i| if i == 0 { bls } else { 0 }),
            peso,
            activo: true,
            prueba: false,
            garantia: peso,
        }
    }

    /// Inserta una identidad con `peso` sectores activos y la clave BLS que empieza por `bls`.
    fn insertar(estado: &mut Estado, ed: u8, bls: u8, peso: u8, p: &ParametrosSector) {
        let ed_bytes: [u8; 32] = std::array::from_fn(|i| if i == 0 { ed } else { 0 });
        let clave = ClaveEd25519::desde_bytes(ed_bytes);
        estado.claves_voto.insert(
            clave,
            ClaveVoto {
                clave_bls: std::array::from_fn(|i| if i == 0 { bls } else { 0 }),
                prueba_posesion: [0u8; 96],
            },
        );
        for indice in 0..u32::from(peso) {
            let id = SectorId {
                clave,
                sector_index: u16::try_from(indice).unwrap_or(u16::MAX),
                version: 0,
            };
            let reg = RegistroSector {
                id,
                r2: [0; 4],
                history_size: 1,
                etapa: Etapa::Activo,
                alta_slot: 0,
                renovacion_slot: 0,
                retiro_slot: -1,
                fianza: p.q_sec,
                aud_apertura: -1,
                aud_contestada: -1,
            };
            estado.sectores.insert(id, reg);
        }
    }

    /// TB-1a · §4.A · prueba 8 · con tope 4 y 6 identidades: quedan fuera las de menor peso; a igual
    /// peso se queda la que estaba en la tabla vigente; entre las demás, la de clave BLS menor; el
    /// orden final es el canónico; dos estados iguales dan la misma tabla.
    #[test]
    fn tabla_derivada_recorta_por_peso() {
        let p = ParametrosSector::dev();
        let mut estado = Estado::inicial();
        estado.parametros_sector = p;
        // (Ed25519, primer byte de la clave BLS, peso). Pesos: dos 2 y cuatro 1.
        let claves = [
            (1u8, 0x30u8, 2u8),
            (2, 0x31, 2),
            (3, 0x10, 1),
            (4, 0x50, 1),
            (5, 0x20, 1),
            (6, 0x40, 1),
        ];
        for (ed, bls, peso) in claves {
            insertar(&mut estado, ed, bls, peso, &p);
        }
        // Tabla vigente del estado: contiene la clave BLS 0x40 (peso 1), que **no** es la menor.
        let vigente = vec![entrada(0x40, 1)];
        let h = hash_payload(0, &vigente);
        estado.finalidad_votos_h_t = Some(h);
        estado.tablas_voto_contenido.insert(h, vigente);

        let k = 50;
        let tabla = tabla_derivada_con_tope(&estado, k, 4);
        let bls: Vec<u8> = tabla
            .iter()
            .map(|c| c.clave_bls.first().copied().unwrap_or(0))
            .collect();
        assert!(
            bls.windows(2).all(|w| matches!(w, [a, b] if a < b)),
            "la salida va en orden canónico: {bls:?}"
        );
        assert_eq!(
            bls,
            vec![0x10, 0x30, 0x31, 0x40],
            "entran los dos de peso 2, la vigente (0x40) y la menor de las demás (0x10)"
        );
        assert!(!bls.contains(&0x20), "0x20 queda fuera");
        assert!(!bls.contains(&0x50), "0x50 queda fuera");

        let otra = estado.clone();
        assert_eq!(
            tabla_derivada_con_tope(&otra, k, 4),
            tabla,
            "dos estados iguales derivan la misma tabla"
        );
    }
}
