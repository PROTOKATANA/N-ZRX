//! AT-1a2 · pruebas de la regla B3 del votante honesto (contrato v2, parte B) tras la corrección.
//!
//! - **R1–R4** usan la **cadena real** `zx_cadena::Cadena` con una bifurcación (fixture
//!   `crate::nodo::pruebas_at1a2_fixture`): la rama `A → X → Y` queda abandonada y `C` está en la
//!   rama seleccionada, en conflicto con `X`. `X` está en el DAG pero fuera de la cadena
//!   seleccionada.
//! - **R5** es la prueba de K1 a través del motor real: un certificado `m ≥ n_v` que el motor ya
//!   conoce **no** suelta la atadura si el estado recibido al abrir no lo tiene aplicado; sí la
//!   suelta cuando el estado lo trae aplicado.
//! - **R6** comprueba que la vista de juguete corregida da el mismo veredicto que la cadena real en
//!   R1–R4.
//! - **A1–A7** son las de AT-1a sobre la vista de juguete corregida; A4 y A6 ponen `X` **fuera de la
//!   cadena seleccionada**. **A8** es la propiedad aleatoria (12 semillas) que transcribe el
//!   predicado de la falta B1.1–B1.3.
//!
//! K2 (AT-1a2): la guarda de B3 es «pertenece al DAG» (`desciende(h, h)`), no «está en la cadena
//! seleccionada» (`en_cadena_seleccionada`). La vista de juguete se corrige para imitar a la real:
//! `desciende(c, a)` recorre los padres de `c` sin exigir que `a` esté en la cadena seleccionada.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use super::*;
use crate::nodo::pruebas_at1a2_fixture::bifurcacion;
use std::collections::{BTreeMap, BTreeSet};
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::cierre_ventana;
use zx_consensus::transicion::{Estado, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, ClaveTablaVoto, Digest};

/// Slot de reloj de las pruebas (solo afecta al candado; las tablas usan `n·t_inst`).
const SLOT: i64 = 100;
/// Ventana de la base para las pruebas de la regla (ha de ser `≥ n_v`).
const BASE_M: u64 = 3;
/// Ventana del candado en la vista de juguete.
const N_V: u64 = 3;

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn clave_bls_bytes(sk: &ClaveSecreta) -> [u8; 48] {
    <[u8; 48]>::try_from(sk.clave_publica().bytes().as_slice()).expect("clave BLS de 48 B")
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

fn h(x: u8) -> Hash {
    [x; 32]
}

fn bh_de(hash: &Hash) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes(*hash))
}

fn clasificar(p: &PermisoCandado) -> &'static str {
    match p {
        PermisoCandado::SinCandado => "sin_candado",
        PermisoCandado::Permitido => "permitido",
        PermisoCandado::Liberado(_) => "liberado",
        PermisoCandado::Bloqueado => "bloqueado",
    }
}

// ---------------------------------------------------------------------------------------------
// Vista de juguete corregida (imita a `zx_cadena::Cadena`).
// ---------------------------------------------------------------------------------------------

/// Vista de juguete: árbol con padres únicos, una cadena seleccionada (subconjunto cerrado por
/// ancestros) y su DAG (todas las claves de `padres`). `desciende` recorre los padres de `c` sin
/// exigir que `a` esté en la cadena seleccionada, como `Cadena::cadena_contiene`; `c` ha de
/// pertenecer al DAG.
struct VistaArbol {
    padres: BTreeMap<Hash, Option<Hash>>,
    seleccion: BTreeSet<Hash>,
    slots: BTreeMap<Hash, u64>,
}

impl VistaArbol {
    fn es_ancestro_o_igual(&self, candidato: &Hash, ancestro: &Hash) -> bool {
        let mut actual = Some(*candidato);
        while let Some(x) = actual {
            if x == *ancestro {
                return true;
            }
            actual = self.padres.get(&x).copied().flatten();
        }
        false
    }
}

impl VistaCadena for VistaArbol {
    fn desciende(&self, candidato: &Hash, ancestro: &Hash) -> bool {
        self.padres.contains_key(candidato) && self.es_ancestro_o_igual(candidato, ancestro)
    }
    fn en_cadena_seleccionada(&self, hash: &Hash) -> bool {
        self.seleccion.contains(hash)
    }
    fn slot_de(&self, hash: &Hash) -> Option<u64> {
        self.slots.get(hash).copied()
    }
}

// ---------------------------------------------------------------------------------------------
// Árbol AT-1a: G → A → X → H, y G → T → C; S4 cuelga de G. `X` es el bloque votado.
// ---------------------------------------------------------------------------------------------

fn h_g() -> Hash {
    h(0x01)
}
fn h_a() -> Hash {
    h(0x02)
}
fn h_x() -> Hash {
    h(0x10)
}
fn h_hijo() -> Hash {
    h(0x11)
}
fn h_t() -> Hash {
    h(0x03)
}
fn h_c() -> Hash {
    h(0x30)
}
fn h_fuera() -> Hash {
    h(0x04)
}

fn arbol_y_slots() -> (BTreeMap<Hash, Option<Hash>>, BTreeMap<Hash, u64>) {
    let mut padres = BTreeMap::new();
    padres.insert(h_g(), None);
    padres.insert(h_a(), Some(h_g()));
    padres.insert(h_x(), Some(h_a()));
    padres.insert(h_hijo(), Some(h_x()));
    padres.insert(h_t(), Some(h_g()));
    padres.insert(h_c(), Some(h_t()));
    padres.insert(h_fuera(), Some(h_g()));
    let mut slots = BTreeMap::new();
    slots.insert(h_g(), 0);
    slots.insert(h_a(), 1);
    slots.insert(h_x(), 2);
    slots.insert(h_hijo(), 3);
    slots.insert(h_t(), 4);
    slots.insert(h_c(), 5);
    slots.insert(h_fuera(), 6);
    (padres, slots)
}

/// Vista con todo el árbol en el DAG y en la cadena seleccionada.
fn vista_todos() -> VistaArbol {
    let (padres, slots) = arbol_y_slots();
    let seleccion: BTreeSet<Hash> = padres.keys().copied().collect();
    VistaArbol {
        padres,
        seleccion,
        slots,
    }
}

/// Vista con todo el árbol en el DAG, pero `excluidos` **fuera de la cadena seleccionada**.
fn vista_sin_seleccion(excluidos: &[Hash]) -> VistaArbol {
    let (padres, slots) = arbol_y_slots();
    let seleccion: BTreeSet<Hash> = padres
        .keys()
        .copied()
        .filter(|b| !excluidos.contains(b))
        .collect();
    VistaArbol {
        padres,
        seleccion,
        slots,
    }
}

/// Vista que **elimina** `excluidos` del DAG (no los conoce) y de la cadena seleccionada.
fn vista_sin_dag(excluidos: &[Hash]) -> VistaArbol {
    let (mut padres, slots) = arbol_y_slots();
    for b in excluidos {
        padres.remove(b);
    }
    let seleccion: BTreeSet<Hash> = padres.keys().copied().collect();
    VistaArbol {
        padres,
        seleccion,
        slots,
    }
}

// ---------------------------------------------------------------------------------------------
// Árbol espejo de la cadena real (para R6): G → P → A → B → C, y A → X → Y.
// ---------------------------------------------------------------------------------------------

fn m_g() -> Hash {
    h(0x41)
}
fn m_p() -> Hash {
    h(0x42)
}
fn m_a() -> Hash {
    h(0x43)
}
fn m_b() -> Hash {
    h(0x44)
}
fn m_c() -> Hash {
    h(0x45)
}
fn m_x() -> Hash {
    h(0x46)
}
fn m_y() -> Hash {
    h(0x47)
}
fn m_desc() -> Hash {
    h(0xEE)
}

fn arbol_espejo() -> VistaArbol {
    let mut padres = BTreeMap::new();
    padres.insert(m_g(), None);
    padres.insert(m_p(), Some(m_g()));
    padres.insert(m_a(), Some(m_p()));
    padres.insert(m_b(), Some(m_a()));
    padres.insert(m_c(), Some(m_b()));
    padres.insert(m_x(), Some(m_a()));
    padres.insert(m_y(), Some(m_x()));
    let seleccion: BTreeSet<Hash> = [m_g(), m_p(), m_a(), m_b(), m_c()].into_iter().collect();
    let mut slots = BTreeMap::new();
    for (i, b) in [m_g(), m_p(), m_a(), m_b(), m_c(), m_x(), m_y()]
        .into_iter()
        .enumerate()
    {
        slots.insert(b, u64::try_from(i).expect("slot"));
    }
    VistaArbol {
        padres,
        seleccion,
        slots,
    }
}

// ---------------------------------------------------------------------------------------------
// Ayudante común de la regla.
// ---------------------------------------------------------------------------------------------

/// Fija un candado `(n_v, x)` en un diario temporal y evalúa `candidato_permitido` con base
/// `(m, S)`. Devuelve la clasificación del permiso.
fn permiso_clasificado(
    n_v: u64,
    x: &Hash,
    candidato: &Hash,
    m: u64,
    s: Option<Hash>,
    slot_actual: i64,
    vista: &dyn VistaCadena,
) -> &'static str {
    let clave = clave_bls_bytes(&bls(1));
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("at1a2.registro");
    let d = DiarioVotos::nueva(&ruta, 7).expect("diario");
    d.fijar_candado(&clave, n_v, x).expect("candado");
    let permiso = candidato_permitido(&d, &clave, candidato, Some((m, s)), slot_actual, vista)
        .expect("permiso");
    clasificar(&permiso)
}

// ---------------------------------------------------------------------------------------------
// R1–R4 · cadena real.
// ---------------------------------------------------------------------------------------------

/// R1 · cadena real: lo sellado es un antepasado propio de `X` y el candidato está en conflicto →
/// bloqueado.
#[test]
fn r1_cadena_real_antepasado_conflicto_bloquea() {
    let f = bifurcacion();
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.a.as_bytes()),
            SLOT,
            &f.cadena
        ),
        "bloqueado"
    );
}

/// R2 · cadena real: `X` en la rama abandonada y lo sellado en la otra rama (conflicto) → permitido.
/// Con el parche de AT-1a falla (exigía `en_cadena_seleccionada`).
#[test]
fn r2_cadena_real_conflicto_permite() {
    let f = bifurcacion();
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.c.as_bytes()),
            SLOT,
            &f.cadena
        ),
        "permitido"
    );
}

/// R3 · cadena real: lo sellado es `X` → permitido; lo sellado desciende de `X` → permitido.
#[test]
fn r3_cadena_real_igual_o_descendiente_permite() {
    let f = bifurcacion();
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.x.as_bytes()),
            SLOT,
            &f.cadena
        ),
        "permitido",
        "S = X"
    );
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.y.as_bytes()),
            SLOT,
            &f.cadena
        ),
        "permitido",
        "S descendiente de X"
    );
}

/// R4 · cadena real: `S` desconocido para la cadena → bloqueado.
#[test]
fn r4_cadena_real_sellado_desconocido_bloquea() {
    let f = bifurcacion();
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.desconocido.as_bytes()),
            SLOT,
            &f.cadena
        ),
        "bloqueado"
    );
}

/// R6 · la vista de juguete corregida da el mismo veredicto que la cadena real en R1–R4.
#[test]
fn r6_vista_juguete_coincide_con_cadena_real() {
    let f = bifurcacion();
    let toy = arbol_espejo();
    let x = m_x();
    let cand = m_c();

    // R1: S = antepasado propio de X.
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.a.as_bytes()),
            SLOT,
            &f.cadena
        ),
        permiso_clasificado(0, &x, &cand, BASE_M, Some(m_a()), SLOT, &toy),
        "R1 juguete == cadena real"
    );
    // R2: S = conflicto.
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.c.as_bytes()),
            SLOT,
            &f.cadena
        ),
        permiso_clasificado(0, &x, &cand, BASE_M, Some(m_c()), SLOT, &toy),
        "R2 juguete == cadena real"
    );
    // R3: S = X y S descendiente de X.
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.x.as_bytes()),
            SLOT,
            &f.cadena
        ),
        permiso_clasificado(0, &x, &cand, BASE_M, Some(m_x()), SLOT, &toy),
        "R3a juguete == cadena real"
    );
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.y.as_bytes()),
            SLOT,
            &f.cadena
        ),
        permiso_clasificado(0, &x, &cand, BASE_M, Some(m_y()), SLOT, &toy),
        "R3b juguete == cadena real"
    );
    // R4: S desconocido.
    assert_eq!(
        permiso_clasificado(
            0,
            f.x.as_bytes(),
            f.c.as_bytes(),
            BASE_M,
            Some(*f.desconocido.as_bytes()),
            SLOT,
            &f.cadena
        ),
        permiso_clasificado(0, &x, &cand, BASE_M, Some(m_desc()), SLOT, &toy),
        "R4 juguete == cadena real"
    );
}

// ---------------------------------------------------------------------------------------------
// A1–A7 · vista de juguete corregida.
// ---------------------------------------------------------------------------------------------

/// A1 · base sella un antepasado propio de `X` y el candidato está en conflicto → bloqueado.
#[test]
fn a1_antepasado_y_candidato_en_conflicto_bloquea() {
    assert_eq!(
        permiso_clasificado(
            N_V,
            &h_x(),
            &h_c(),
            BASE_M,
            Some(h_a()),
            SLOT,
            &vista_todos()
        ),
        "bloqueado"
    );
}

/// A2 · base sella `X` → permitido.
#[test]
fn a2_base_sella_el_bloque_votado() {
    assert_eq!(
        permiso_clasificado(
            N_V,
            &h_x(),
            &h_c(),
            BASE_M,
            Some(h_x()),
            SLOT,
            &vista_todos()
        ),
        "permitido"
    );
}

/// A3 · base sella un descendiente de `X` → permitido.
#[test]
fn a3_base_sella_un_descendiente() {
    assert_eq!(
        permiso_clasificado(
            N_V,
            &h_x(),
            &h_c(),
            BASE_M,
            Some(h_hijo()),
            SLOT,
            &vista_todos()
        ),
        "permitido"
    );
}

/// A4 · base sella un bloque en conflicto con `X`, con `X` **fuera de la cadena seleccionada** →
/// permitido (conflicto por el DAG).
#[test]
fn a4_base_sella_un_conflicto_con_x_fuera_de_seleccion() {
    let vista = vista_sin_seleccion(&[h_x()]);
    assert_eq!(
        permiso_clasificado(N_V, &h_x(), &h_c(), BASE_M, Some(h_t()), SLOT, &vista),
        "permitido"
    );
}

/// A5 · base sella un antepasado propio y el candidato desciende de `X` → permitido.
#[test]
fn a5_antepasado_y_candidato_descendiente() {
    assert_eq!(
        permiso_clasificado(
            N_V,
            &h_x(),
            &h_hijo(),
            BASE_M,
            Some(h_a()),
            SLOT,
            &vista_todos()
        ),
        "permitido"
    );
}

/// A6 · base sella un antepasado propio, `X` fuera de la cadena seleccionada y pasado `F` →
/// liberado por `F`.
#[test]
fn a6_antepasado_y_liberacion_por_f() {
    let vista = vista_sin_seleccion(&[h_x()]);
    let slot_x = 2u64;
    let en_cota = i64::try_from(slot_x.saturating_add(crate::perfil::F_SLOTS)).expect("slot");
    assert_eq!(
        permiso_clasificado(N_V, &h_x(), &h_c(), BASE_M, Some(h_a()), en_cota, &vista),
        "liberado"
    );
}

/// A7 · bloque sellado desconocido o fuera del DAG y candidato en conflicto → bloqueado.
#[test]
fn a7_sellado_desconocido_o_fuera_de_vista() {
    assert_eq!(
        permiso_clasificado(N_V, &h_x(), &h_c(), BASE_M, None, SLOT, &vista_todos()),
        "bloqueado",
        "sellado desconocido"
    );
    let vista = vista_sin_dag(&[h_fuera()]);
    assert_eq!(
        permiso_clasificado(N_V, &h_x(), &h_c(), BASE_M, Some(h_fuera()), SLOT, &vista),
        "bloqueado",
        "sellado fuera del DAG"
    );
}

// ---------------------------------------------------------------------------------------------
// R5 · K1: la base de B3 sale del estado aplicado, no del certificado que el motor conoce.
// ---------------------------------------------------------------------------------------------

fn registro(p: &ParametrosSector, clave: ClaveEd, indice: u16) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: indice,
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
    (id, reg)
}

/// Estado con la clave `bls(1)` registrada y `n_sectores` activos (toda la tabla para esa clave).
fn estado_con(n_sectores: usize) -> (Estado, ClaveSecreta) {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let sk = bls(1);
    let pk = sk.clave_publica();
    let e = ed(1);
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: pk.bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    for i in 0..n_sectores {
        let (id, reg) = registro(&p, e, u16::try_from(i).expect("indice"));
        est.sectores.insert(id, reg);
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    (con_cola, sk)
}

/// M9-a2 · motor en **modo por peso** (el único que queda): misma configuración que usaban las
/// pruebas de la regla de atadura, sin `modo`/`k`/`revelar`.
fn motor_con(sk: ClaveSecreta) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: true,
    })
}

fn payload_de(tabla: &Tabla) -> Vec<ClaveTablaVoto> {
    tabla
        .claves
        .iter()
        .map(|c| ClaveTablaVoto {
            clave_bls: <[u8; 48]>::try_from(c.clave.as_slice()).expect("clave BLS de 48 B"),
            peso: c.peso,
            activo: c.activo,
            prueba: c.prueba,
            garantia: c.garantia,
        })
        .collect()
}

fn slot_apertura(n: u64) -> i64 {
    let t_inst = crate::perfil::parametros_votos_dev().t_inst;
    i64::try_from(n.saturating_mul(t_inst)).unwrap_or(i64::MAX)
}

/// R5 · K1. El motor abre una vez con un estado que trae aplicada la finalidad de `BASE_M` (sella
/// `h_t()`, en conflicto con `h_x()`) y **ya conoce** esa base. Al abrir la ventana siguiente con un
/// estado **sin** finalidad aplicada, B3 no puede soltar la atadura: `candidato_permitido` bloquea.
/// Con el mismo estado que sí la trae aplicada, la suelta y firma. Sin K1 (base tomada del
/// certificado conocido) el primer caso se permitiría y la prueba mordería.
#[test]
fn r5_k1_base_del_estado_aplicado() {
    let (est0, _sk) = estado_con(100);
    let cand_conf = h_c();
    let x = h_x();
    let n_v = 0u64;

    // Tabla de la base, guardada en el estado para que `tabla_de_base` la encuentre en ventanas
    // posteriores (el hash de una tabla no depende de `n`).
    let (tabla_base, _pubs) =
        construir_tabla(BASE_M, &est0, slot_apertura(BASE_M)).expect("T_base");
    let h_base = hash_tabla(&tabla_base);
    let mut est0_tabla = est0.clone();
    est0_tabla
        .tablas_voto
        .insert(BASE_M, payload_de(&tabla_base));

    // Estado con la finalidad aplicada: sella `h_t()` (conflicto con `h_x()`).
    let mut est_con = est0_tabla.clone();
    est_con.finalidad_votos_n = BASE_M;
    est_con.finalidad_votos = Some(bh_de(&h_t()));
    est_con.finalidad_votos_h_t = Some(h_base);

    let clave = clave_bls_bytes(&bls(1));
    let vista = vista_todos();

    // (a) Motor que ya conoce la base (la trajo del estado), pero la apertura recibe un estado que
    //     no la tiene aplicada → bloqueado.
    let dir = tempfile::tempdir().expect("tempdir");
    let d = DiarioVotos::nueva(dir.path().join("r5a.registro"), 7).expect("diario");
    d.fijar_candado(&clave, n_v, &x).expect("candado");
    let mut m = motor_con(bls(1));
    m.vincular_diario(d);
    m.emitir_votos = false;
    m.avanzar(0, bh_de(&h_g()), &est0_tabla, SLOT)
        .expect("abrir 0");
    // El motor adopta/conoce la base `(BASE_M, h_base)` al abrir 1 con `est_con`.
    m.avanzar(1, bh_de(&h_g()), &est_con, SLOT)
        .expect("abrir 1");
    m.emitir_votos = true;
    // `est0_tabla` no trae `finalidad_votos`: la base de B3 es `None` aunque `self.base` esté puesto.
    let p = m
        .avanzar_con_vista(2, bh_de(&cand_conf), &est0_tabla, SLOT, &vista)
        .expect("abrir 2");
    assert!(p.votos.is_empty(), "K1: sin finalidad aplicada no suelta");
    // M9-a2 · en el modo por peso la apertura observa la supresión con `VotoPesoPropio`
    // (`VotoSuprimido` queda para el voto tardío); la afirmación es la misma: el motivo es
    // `candado`.
    assert!(
        p.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VotoPesoPropio {
                emitido: false,
                motivo: "candado",
                ..
            }
        )),
        "la supresión por candado queda observada"
    );

    // (b) Con el estado que sí trae la finalidad aplicada → permitido y firma.
    let dir2 = tempfile::tempdir().expect("tempdir 2");
    let d2 = DiarioVotos::nueva(dir2.path().join("r5b.registro"), 7).expect("diario 2");
    d2.fijar_candado(&clave, n_v, &x).expect("candado 2");
    let mut m2 = motor_con(bls(1));
    m2.vincular_diario(d2);
    m2.emitir_votos = false;
    m2.avanzar(0, bh_de(&h_g()), &est0_tabla, SLOT)
        .expect("abrir 0");
    m2.emitir_votos = true;
    let p2 = m2
        .avanzar_con_vista(1, bh_de(&cand_conf), &est_con, SLOT, &vista)
        .expect("abrir 1");
    assert_eq!(p2.votos.len(), 1, "K1: con finalidad aplicada sí suelta");
}

// ---------------------------------------------------------------------------------------------
// A8 · propiedad aleatoria: la falta B1.1–B1.3 nunca se satisface.
// ---------------------------------------------------------------------------------------------

/// SplitMix64 determinista: semillas fijas, sin dependencias.
struct Rng(u64);

impl Rng {
    fn nuevo(semilla: u64) -> Self {
        Self(semilla)
    }
    fn siguiente(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn bloque_de(i: usize) -> Hash {
    let mut b = [0u8; 32];
    b[0] = 0xB0;
    b[1] = u8::try_from(i).expect("indice de bloque");
    b[31] = 0x5A;
    b
}

fn es_ancestro_o_igual(
    padres: &BTreeMap<Hash, Option<Hash>>,
    candidato: &Hash,
    ancestro: &Hash,
) -> bool {
    let mut actual = Some(*candidato);
    while let Some(x) = actual {
        if x == *ancestro {
            return true;
        }
        actual = padres.get(&x).copied().flatten();
    }
    false
}

/// `desciende` restringido al DAG, como la vista corregida (se conserva por claridad del predicado
/// de B1.1). En el árbol de juguete cada bloque tiene un único padre, que es su padre seleccionado.
fn en_conflicto(padres: &BTreeMap<Hash, Option<Hash>>, a: &Hash, b: &Hash) -> bool {
    !es_ancestro_o_igual(padres, a, b) && !es_ancestro_o_igual(padres, b, a)
}

struct VotoEmitido {
    n: u64,
    cand: Hash,
}

/// Ejecuta una semilla: árbol pequeño al azar, ventanas con cadenas seleccionadas al azar, bases
/// (certificados) que sellan un antepasado del candidato, y candidatos en la punta. Un nodo que
/// sigue la regla solo vota cuando `candidato_permitido` lo permite; el candado se actualiza tras
/// cada voto como en producción.
fn ejecutar_semilla_a8(semilla: u64) -> usize {
    let mut rng = Rng::nuevo(semilla.wrapping_mul(0xD1B5_4A32_D192_ED03).wrapping_add(7));
    let n_bloques = 5 + usize::try_from(rng.siguiente() % 5).expect("n_bloques");
    let mut padre_idx: Vec<Option<usize>> = vec![None; n_bloques];
    for (i, p) in padre_idx.iter_mut().enumerate().skip(1) {
        *p = Some(usize::try_from(rng.siguiente() % u64::try_from(i).expect("i")).expect("padre"));
    }
    let mut padres: BTreeMap<Hash, Option<Hash>> = BTreeMap::new();
    let mut slots: BTreeMap<Hash, u64> = BTreeMap::new();
    for (i, p) in padre_idx.iter().enumerate() {
        let b = bloque_de(i);
        padres.insert(b, (*p).map(bloque_de));
        slots.insert(b, u64::try_from(i).expect("slot"));
    }
    let camino = |hoja: usize| -> Vec<usize> {
        let mut p = vec![hoja];
        let mut actual = hoja;
        while let Some(pad) = padre_idx[actual] {
            p.push(pad);
            actual = pad;
        }
        p
    };

    let clave = clave_bls_bytes(&bls(1));
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("a8.registro");
    let d = DiarioVotos::nueva(&ruta, 7).expect("diario");

    let ventanas = 4 + u64::from(u8::try_from(rng.siguiente() % 4).expect("ventanas"));
    let mut votos: Vec<VotoEmitido> = Vec::new();
    let mut certificados: Vec<(u64, Hash)> = Vec::new();
    let mut base_m: u64 = 0;
    for n in 1..=ventanas {
        let hoja =
            usize::try_from(rng.siguiente() % u64::try_from(n_bloques).expect("n")).expect("hoja");
        let seleccion: BTreeSet<Hash> = camino(hoja).into_iter().map(bloque_de).collect();
        let candidato = bloque_de(hoja);
        // El certificado de la base sella un antepasado (o el propio) candidato.
        let camino_hoja = camino(hoja);
        let s_idx = camino_hoja[usize::try_from(
            rng.siguiente() % u64::try_from(camino_hoja.len()).expect("camino"),
        )
        .expect("s_idx")];
        let sellado = bloque_de(s_idx);
        base_m = base_m.saturating_add(1).saturating_add(rng.siguiente() % 2);
        certificados.push((base_m, sellado));
        let vista = VistaArbol {
            padres: padres.clone(),
            seleccion: seleccion.clone(),
            slots: slots.clone(),
        };
        let slot_actual = i64::try_from(cierre_ventana(n)).expect("cierre");
        let permiso = candidato_permitido(
            &d,
            &clave,
            &candidato,
            Some((base_m, Some(sellado))),
            slot_actual,
            &vista,
        )
        .expect("permiso");
        let vota = matches!(
            permiso,
            PermisoCandado::SinCandado | PermisoCandado::Permitido | PermisoCandado::Liberado(_)
        );
        if vota {
            votos.push(VotoEmitido { n, cand: candidato });
            d.fijar_candado(&clave, n, &candidato).expect("candado");
        }
    }

    // Predicado de la falta B1.1–B1.3 (contrato, parte B) transcrito: con la regla correcta, todo
    // par en conflicto dentro de `F` queda justificado por el certificado que soltó la atadura, así
    // que el nodo que sigue B3 nunca satisface la falta. El retorno exige que la simulación no sea
    // trivial.
    for i in 0..votos.len() {
        for j in (i + 1)..votos.len() {
            let v1 = &votos[i];
            let v2 = &votos[j];
            if v1.n >= v2.n {
                continue;
            }
            // B1.1 · en conflicto en el DAG que aplica la falta (B2 usa su propia cadena): la
            // semántica corregida de `desciende` es la que caminan los padres de `c` sin exigir que
            // el ancestro esté en la cadena seleccionada.
            let b1_1 = en_conflicto(&padres, &v1.cand, &v2.cand);
            if !b1_1 {
                continue;
            }
            // B1.2 · dentro de F.
            let slot_1 = slots.get(&v1.cand).copied().unwrap_or(0);
            let b1_2 = cierre_ventana(v2.n) < slot_1.saturating_add(crate::perfil::F_SLOTS);
            if !b1_2 {
                continue;
            }
            // B1.3 · sin justificación: ningún certificado de ventana m ≥ n1 sella un bloque en
            // conflicto con B1 dentro del pasado (DAG) de B2.
            let justificado = certificados.iter().any(|(m, s)| {
                *m >= v1.n
                    && en_conflicto(&padres, s, &v1.cand)
                    && es_ancestro_o_igual(&padres, &v2.cand, s)
            });
            assert!(
                justificado,
                "semilla {semilla}: falta B1.1+B1.2+B1.3 sin justificar entre \
                 ({}, {}) y ({}, {})",
                v1.n,
                hex(&v1.cand),
                v2.n,
                hex(&v2.cand)
            );
        }
    }
    votos.len()
}

/// A8 · 12 semillas, árboles pequeños al azar. Con la regla correcta no queda ningún par en
/// conflicto sin justificar y la simulación emite votos.
#[test]
fn a8_propiedad_sin_falta_dentro_de_f() {
    let mut emitidos = 0usize;
    for semilla in 0..12u64 {
        emitidos += ejecutar_semilla_a8(semilla);
    }
    assert!(emitidos > 0, "la simulación no emitió ningún voto");
}
