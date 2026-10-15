//! REAN-2 · pruebas del motor de reanudación R4 (N1–N7).
//!
//! Archivo nuevo (§5): R1–R9. No dependen del número de plazas ni de la regla de reparto: usan una
//! sola clave con **todo** el peso (su voto basta para el quórum y su ausencia lo impide) o vistas
//! simuladas de la cadena seleccionada para el candado.
//!
//! WS-ORIG · R1–R3, R7 y R8 usan solo API existente y se copian a `ws.orig` (subconjunto en su
//! `pruebas_rean2.rs`) para la línea base. R4, R5 y R6 usan la API nueva del candado/vista
//! (`avanzar_con_vista`, `VistaCadena`, `DiarioVotos::candado`/`fijar_candado`), que no existe en
//! la base.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use super::*;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{Estado, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, ClaveTablaVoto, Digest};

/// Slot de reloj de las pruebas (solo afecta al candado; las tablas usan `n·t_inst`).
const SLOT: i64 = 100;

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

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

/// Estado con una clave registrada y `n_sectores` activos (toda la tabla para esa clave).
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
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de `cola_tablas_voto`: el
    // montaje deja una derivada de producto para que el motor real pueda votar.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    (con_cola, sk)
}

/// M9-a2 · motor en **modo por peso** (el único que queda): misma configuración que usaban las
/// pruebas de reanudación, sin `modo`/`k`/`revelar`.
fn motor_con(sk: ClaveSecreta) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: true,
    })
}

fn bh(byte: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([byte; 32]))
}

fn clave_bls_bytes(sk: &ClaveSecreta) -> [u8; 48] {
    <[u8; 48]>::try_from(sk.clave_publica().bytes().as_slice()).expect("clave BLS de 48 B")
}

/// Slot de apertura de la ventana `n` (`n·t_inst`), sin depender de métodos nuevos: así la misma
/// prueba compila contra `ws.orig` y allí falla por comportamiento, no por API.
fn slot_apertura(n: u64) -> i64 {
    let t_inst = crate::perfil::parametros_votos_dev().t_inst;
    i64::try_from(n.saturating_mul(t_inst)).unwrap_or(i64::MAX)
}

/// Payload de tabla de `zx-core` a partir de una `Tabla` del contrato.
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

/// Vista simulada de la cadena seleccionada para el candado.
#[derive(Clone, Copy)]
struct VistaMock {
    desciende: bool,
    en_cadena: bool,
    slot: Option<u64>,
}

impl VistaCadena for VistaMock {
    fn desciende(&self, _candidato: &Hash, _ancestro: &Hash) -> bool {
        self.desciende
    }
    fn en_cadena_seleccionada(&self, _hash: &Hash) -> bool {
        self.en_cadena
    }
    fn slot_de(&self, _hash: &Hash) -> Option<u64> {
        self.slot
    }
}

/// R1 · ventana sin quórum y reanudación en la siguiente, y tras tres ventanas sin quórum.
#[test]
fn r1_reanuda_tras_ventanas_sin_quorum() {
    let (est, sk) = estado_con(100);
    let mut m = motor_con(sk);
    // Ventana 0 con voto ⇒ C_0 al cerrarla.
    m.avanzar(0, bh(0x10), &est, SLOT).expect("abrir 0");
    // Abrir 1 sin votar (sin quórum).
    m.emitir_votos = false;
    let p1 = m.avanzar(1, bh(0x11), &est, SLOT).expect("abrir 1");
    assert!(p1.certificado_peso.is_some(), "C_0 adoptado al cerrar 0");
    // Abrir 2 con voto; al cerrar 1 (sin quórum) se difiere y C_2 encadena con previo 0.
    m.emitir_votos = true;
    let p2 = m.avanzar(2, bh(0x12), &est, SLOT).expect("abrir 2");
    assert!(p2.certificado_peso.is_none(), "la ventana 1 no certifica");
    m.emitir_votos = false;
    let p3 = m.avanzar(3, bh(0x13), &est, SLOT).expect("abrir 3");
    assert_eq!(
        p3.certificado_peso.as_ref().map(|c| c.n),
        Some(2),
        "C_2 con previo m=0 < n=1"
    );
    // Tres ventanas sin quórum (3, 4, 5) y reanudación en la 6.
    m.avanzar(4, bh(0x14), &est, SLOT).expect("abrir 4");
    m.avanzar(5, bh(0x15), &est, SLOT).expect("abrir 5");
    m.emitir_votos = true;
    m.avanzar(6, bh(0x16), &est, SLOT).expect("abrir 6");
    m.emitir_votos = false;
    let p7 = m.avanzar(7, bh(0x17), &est, SLOT).expect("abrir 7");
    assert_eq!(
        p7.certificado_peso.as_ref().map(|c| c.n),
        Some(6),
        "C_6 con previo m=2 < n=5"
    );
}

/// R2 · la tabla de la ventana siguiente tiene el hash de la base, no la `tabla_siguiente` fallida.
#[test]
fn r2_tabla_de_la_base_no_hereda_la_fallida() {
    let (est_a, sk) = estado_con(100);
    let (est_b, _) = estado_con(101);
    let mut m = motor_con(sk);
    m.avanzar(0, bh(0x20), &est_a, SLOT).expect("abrir 0");
    m.emitir_votos = false;
    let p1 = m.avanzar(1, bh(0x21), &est_b, SLOT).expect("abrir 1");
    assert!(p1.certificado_peso.is_some(), "C_0 con la T_1 de estado A");
    let inst1 = m.instancia.as_ref().expect("instancia 1");
    let h_base = hash_tabla(&inst1.tabla);
    let tabla_ok = inst1.tabla.clone();
    let tabla_siguiente = inst1.tabla_siguiente.clone();
    assert_eq!(hash_tabla(&tabla_ok), h_base);
    // TB-1b · N1: la tabla siguiente ya no se construye del estado nuevo; es la de la base.
    let t2_estado_nuevo = construir_tabla(2, &est_b, slot_apertura(2))
        .expect("T_2 del estado nuevo")
        .0;
    // TB4-R7 · el votante declara la **última de `Q`** del estado del candidato (`est_b` en la
    // apertura de la ventana 1), con base y sin base; ya no la tabla de la base.
    let h_q = est_b.cola_tablas_voto.last().expect("cola del candidato").1;
    assert_eq!(
        hash_tabla(&tabla_siguiente),
        h_q,
        "TB4-R7: la tabla siguiente declarada es la última de Q"
    );
    // Cerrar 1 sin cert: la apertura de 2 usa la tabla con hash de la base, no la del estado nuevo.
    let p2 = m.avanzar(2, bh(0x22), &est_b, SLOT).expect("abrir 2");
    assert!(p2.certificado_peso.is_none());
    let t2 = &m.instancia.as_ref().expect("instancia 2").tabla;
    assert_eq!(hash_tabla(t2), h_base, "T_2 tiene el hash de la base");
    assert_ne!(hash_tabla(t2), hash_tabla(&t2_estado_nuevo));
}

/// R3 · el estado aplicado trae un certificado que el motor abierto no adoptó: la apertura
/// siguiente usa esa base (su tabla guardada) y certifica.
#[test]
fn r3_base_del_estado_aplicado() {
    let (est0, _) = estado_con(100);
    // Tabla de la base con un peso distinto del canónico: se guarda en `tablas_voto_contenido`.
    let (mut tabla2, _pubs) = construir_tabla(2, &est0, slot_apertura(2)).expect("T_2");
    for c in &mut tabla2.claves {
        c.peso = c.peso.saturating_add(1);
    }
    let h = hash_tabla(&tabla2);
    let mut est = est0.clone();
    // M9-a2 · en modo por peso la tabla de la base se busca por su hash en
    // `tablas_voto_contenido` (la fuente que queda; `tablas_voto` era del flujo antiguo).
    est.tablas_voto_contenido.insert(h, payload_de(&tabla2));
    est.finalidad_votos_n = 1;
    est.finalidad_votos = Some(bh(0x30));
    est.finalidad_votos_h_t = Some(h);
    let mut m = motor_con(bls(1));
    // Motor **abierto** (no nuevo): el guard de bootstrap no aplica y la base del estado manda.
    m.emitir_votos = false;
    m.avanzar(0, bh(0x31), &est0, SLOT).expect("abrir 0");
    m.emitir_votos = true;
    let p2 = m.avanzar(2, bh(0x32), &est, SLOT).expect("abrir 2");
    assert!(p2.certificado_peso.is_none(), "la ventana 0 no tenía voto");
    // M9-a2 · el certificado por peso es compacto (mapa sobre `T_n`) y no lleva la tabla; que la
    // `T_2` usada es la de la base del estado (y no la canónica) se comprueba sobre la instancia.
    let t2 = m.tabla_actual().expect("tabla de la instancia 2");
    assert_eq!(
        hash_tabla(t2),
        h,
        "la T_2 certificada es la de la base del estado, no la canónica"
    );
    let p3 = m.avanzar(3, bh(0x33), &est, SLOT).expect("abrir 3");
    assert_eq!(
        p3.certificado_peso.as_ref().map(|c| c.n),
        Some(2),
        "certifica con la base traída del estado"
    );
}

/// R4 · el candado impide un candidato en conflicto y permite un descendiente.
#[test]
fn r4_candado_conflicto_y_descendiente() {
    let (est, _) = estado_con(100);
    let x = bh(0x40);
    let y = bh(0x41);
    let z = bh(0x42);
    let clave = clave_bls_bytes(&bls(1));

    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("conflicto.registro");
    let d = DiarioVotos::nueva(&ruta, 7).expect("diario");
    d.fijar_candado(&clave, 0, x.as_bytes()).expect("candado");
    let mut m = motor_con(bls(1));
    m.vincular_diario(d);
    let vista = VistaMock {
        desciende: false,
        en_cadena: true,
        slot: None,
    };
    let p = m
        .avanzar_con_vista(1, y, &est, SLOT, &vista)
        .expect("abrir");
    assert!(p.votos.is_empty(), "un candidato en conflicto no se firma");
    assert!(
        p.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VotoPesoPropio {
                emitido: false,
                motivo: "candado",
                ..
            }
        )),
        "se observa la supresión por candado"
    );

    let ruta2 = dir.path().join("descendiente.registro");
    let d2 = DiarioVotos::nueva(&ruta2, 7).expect("diario 2");
    d2.fijar_candado(&clave, 0, x.as_bytes())
        .expect("candado 2");
    let mut m2 = motor_con(bls(1));
    m2.vincular_diario(d2);
    let vista2 = VistaMock {
        desciende: true,
        en_cadena: true,
        slot: None,
    };
    let p2 = m2
        .avanzar_con_vista(1, z, &est, SLOT, &vista2)
        .expect("abrir 2");
    assert_eq!(p2.votos.len(), 1, "un descendiente de X sí se firma");
}

/// R5 · liberación por `F`: pasado `F_SLOTS` y con X fuera de la cadena, firma y lo registra.
#[test]
fn r5_liberacion_por_f() {
    let (est, _) = estado_con(100);
    let x = bh(0x50);
    let y = bh(0x51);
    let clave = clave_bls_bytes(&bls(1));
    let slot_x = 1_000u64;
    let dir = tempfile::tempdir().expect("tempdir");

    // Antes del plazo: bloqueado.
    let ruta = dir.path().join("antes.registro");
    let d = DiarioVotos::nueva(&ruta, 7).expect("diario");
    d.fijar_candado(&clave, 0, x.as_bytes()).expect("candado");
    let mut m = motor_con(bls(1));
    m.vincular_diario(d);
    let vista = VistaMock {
        desciende: false,
        en_cadena: false,
        slot: Some(slot_x),
    };
    let antes = i64::try_from(slot_x + crate::perfil::F_SLOTS - 1).expect("slot");
    let p = m
        .avanzar_con_vista(1, y, &est, antes, &vista)
        .expect("abrir");
    assert!(p.votos.is_empty(), "antes de F_SLOTS sigue bloqueado");

    // En el plazo: liberado, firma y queda registrado.
    let ruta2 = dir.path().join("despues.registro");
    let d2 = DiarioVotos::nueva(&ruta2, 7).expect("diario 2");
    d2.fijar_candado(&clave, 0, x.as_bytes())
        .expect("candado 2");
    let mut m2 = motor_con(bls(1));
    m2.vincular_diario(d2);
    let despues = i64::try_from(slot_x + crate::perfil::F_SLOTS).expect("slot");
    let p2 = m2
        .avanzar_con_vista(1, y, &est, despues, &vista)
        .expect("abrir 2");
    assert_eq!(p2.votos.len(), 1, "liberado por F: firma");
    assert!(
        p2.eventos
            .iter()
            .any(|e| matches!(e, EventoMotor::CandadoLiberado { candidato_v, .. } if candidato_v == &hex(x.as_bytes()))),
        "la liberación queda en el registro"
    );
}

/// R6 · el candado sobrevive a cerrar y reabrir; un fallo de escritura impide firmar.
#[test]
fn r6_candado_durable_y_fallo_de_escritura() {
    let clave = clave_bls_bytes(&bls(1));
    let x = bh(0x60);
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    {
        let d = DiarioVotos::nueva(&ruta, 7).expect("diario");
        d.fijar_candado(&clave, 3, x.as_bytes()).expect("candado");
    }
    let d = DiarioVotos::abrir(&ruta, 7).expect("reabrir");
    assert_eq!(
        d.candado(&clave),
        Some((3, *x.as_bytes())),
        "el candado persiste"
    );
    drop(d);

    let (est, _) = estado_con(100);
    let ruta2 = dir.path().join("fallo.registro");
    let d2 = DiarioVotos::nueva(&ruta2, 7).expect("diario 2");
    d2.fijar_candado(&clave, 0, x.as_bytes())
        .expect("candado 2");
    d2.fallar_proximo_sync_candado_para_test();
    let mut m = motor_con(bls(1));
    m.vincular_diario(d2);
    let vista = VistaMock {
        desciende: true,
        en_cadena: true,
        slot: None,
    };
    let p = m
        .avanzar_con_vista(1, x, &est, SLOT, &vista)
        .expect("abrir");
    assert!(p.votos.is_empty(), "el fallo del candado impide firmar");
    assert!(
        p.eventos.iter().any(|e| matches!(
            e,
            EventoMotor::VotoPesoPropio {
                emitido: false,
                motivo: "diario_en_duda",
                ..
            }
        )),
        "se observa la supresión por E/S"
    );
}

/// R7 · dos motores con el mismo estado, en slots distintos, construyen las mismas tablas.
#[test]
fn r7_slot_determinista_mismas_tablas() {
    // Sector con alta en un slot futuro: el peso (y la tabla) depende del slot de consulta. Con N3
    // ambos motores usan el **slot de apertura** de la ventana y coinciden; con el slot actual no.
    let (mut est, _) = estado_con(100);
    for reg in est.sectores.values_mut() {
        reg.alta_slot = 500;
    }
    let c = bh(0x70);
    let mut m1 = motor_con(bls(1));
    let mut m2 = motor_con(bls(1));
    m1.avanzar(1, c, &est, 10).expect("abrir 1a");
    m2.avanzar(1, c, &est, 999).expect("abrir 1b");
    assert_eq!(
        hash_tabla(m1.tabla_actual().expect("tabla 1")),
        hash_tabla(m2.tabla_actual().expect("tabla 2")),
        "misma T_n con slots distintos"
    );
    let s1 = &m1.instancia.as_ref().expect("i1").tabla_siguiente;
    let s2 = &m2.instancia.as_ref().expect("i2").tabla_siguiente;
    assert_eq!(
        hash_tabla(s1),
        hash_tabla(s2),
        "misma T_{{n+1}} con slots distintos"
    );
}

/// R8 · con base `m` y reloj `n > m+1`, el intento `n` se abre (ya no hay espera por hueco).
#[test]
fn r8_sin_espera_por_hueco() {
    assert_eq!(
        crate::nodo::clase_arranque_votos(None, Some(5), 7),
        None,
        "n > m+1 abre el intento"
    );
    assert_eq!(
        crate::nodo::clase_arranque_votos(None, Some(5), 5),
        Some("espera_reloj"),
        "n <= m espera al reloj"
    );

    let (est0, sk) = estado_con(100);
    let mut m = motor_con(sk);
    m.emitir_votos = false;
    m.avanzar(0, bh(0x80), &est0, SLOT).expect("abrir 0");
    let t1 = construir_tabla(1, &est0, slot_apertura(1)).expect("T_1").0;
    let mut est = est0.clone();
    est.finalidad_votos_n = 0;
    est.finalidad_votos = Some(bh(0x80));
    est.finalidad_votos_h_t = Some(hash_tabla(&t1));
    let p = m.avanzar(3, bh(0x83), &est, SLOT).expect("abrir 3");
    assert_eq!(m.instancia_actual(), Some(3), "abre n > m+1");
    assert!(p.certificado_peso.is_none(), "la ventana 0 no certificó");
}

/// R9 · la reserva del diario sigue impidiendo dos firmas distintas para `(clave, n)`.
#[test]
fn r9_reserva_impide_dos_firmas() {
    let (est_a, _) = estado_con(100);
    let (est_b, _) = estado_con(101);
    let c = bh(0x90);
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("votos.registro");
    {
        let mut m = motor_con(bls(1));
        m.vincular_diario(DiarioVotos::nueva(&ruta, 7).expect("diario"));
        let p = m.avanzar(1, c, &est_a, SLOT).expect("abrir 1a");
        assert_eq!(p.votos.len(), 1, "primera firma");
    }
    {
        let mut m = motor_con(bls(1));
        m.vincular_diario(DiarioVotos::abrir(&ruta, 7).expect("reabrir"));
        let p = m.avanzar(1, c, &est_b, SLOT).expect("abrir 1b");
        assert!(p.votos.is_empty(), "mismo (clave, n) con otro mensaje");
        assert!(
            p.eventos.iter().any(|e| matches!(
                e,
                EventoMotor::VotoPesoPropio {
                    emitido: false,
                    motivo: "conflicto_diario",
                    ..
                }
            )),
            "la reserva sigue impidiendo la segunda firma"
        );
    }
}
