//! DFV-1 · pruebas del detector de la falta entre ventanas (D1–D10).
//!
//! Con bloques y firmas BLS reales en proceso. La prueba 1 monta una `Cadena` real y usa el hecho
//! que da la cadena; las demás usan una vista de prueba que modela el DAG, el conflicto y el hecho.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    reason = "pruebas con escenarios generados; fallan con panic por diseño"
)]

use super::*;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};

use primitive_types::U256;
use zx_cadena::{BloqueCadena, Cadena};
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{
    BloqueTransicion, Fase, Garantia, HechoVoto, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion,
};
use zx_core::ClavePublica as ClaveEd;
use zx_core::{Amount, BlockHash, CBID_RED_DEV, Digest, ExtensionTx, OperacionAlmacenamiento};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;
use zx_votos::ClaveSecreta;

// ─────────────────────────────────────────────────────────────────────────────
// Claves, hashes y votos reales.
// ─────────────────────────────────────────────────────────────────────────────

const SLOT: i64 = 100;
const PLAZO: u64 = 300;

fn bls(i: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = i;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(i: u8) -> ClaveEd {
    ClaveEd::desde_bytes([i; 32])
}

fn clave_de(sk: &ClaveSecreta) -> [u8; LONGITUD_CLAVE_BLS] {
    sk.clave_publica().bytes()
}

fn hash_n(i: u32) -> Hash {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_be_bytes());
    b
}

fn bh(i: u32) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes(hash_n(i)))
}

/// Construye un voto del detector con firma BLS real sobre el mensaje A3.
fn voto(sk: &ClaveSecreta, n: u64, candidato: Hash, h_t: Hash) -> VotoDetector {
    let mensaje = mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]);
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje).expect("firma BLS");
    VotoDetector {
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        firma,
    }
}

/// Sobre serializado de un voto (para la ruta de red real).
fn sobre(sk: &ClaveSecreta, n: u64, candidato: Hash, h_t: Hash) -> Vec<u8> {
    let mensaje = mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]);
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje).expect("firma BLS");
    serializar_voto_peso(&VotoPeso {
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave: clave_de(sk),
        firma,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Vista de prueba: modela el DAG, el conflicto y el hecho.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct VistaPrueba {
    /// hijo -> padre (un solo padre: cadena simple).
    padres: RefCell<HashMap<Hash, Hash>>,
    /// Pares en conflicto declarados explícitamente (ordenados).
    conflictos: RefCell<BTreeSet<(Hash, Hash)>>,
    /// Hecho por `(n1, n2, h1, h2)` canónico.
    hechos: RefCell<HashMap<(u64, u64, Hash, Hash), HechoVoto>>,
    /// Hecho por defecto si no hay entrada.
    hecho_defecto: RefCell<Option<HechoVoto>>,
    /// Contadores de consultas.
    en_conflicto_llamadas: Cell<u64>,
    desciende_llamadas: Cell<u64>,
}

impl VistaPrueba {
    fn nuevo() -> Self {
        Self {
            hecho_defecto: RefCell::new(Some(HechoVoto::Falta)),
            ..Self::default()
        }
    }

    fn pon_padre(&self, hijo: Hash, padre: Hash) {
        self.padres.borrow_mut().insert(hijo, padre);
    }

    fn pon_hecho(&self, n1: u64, n2: u64, h1: Hash, h2: Hash, h: HechoVoto) {
        self.hechos.borrow_mut().insert((n1, n2, h1, h2), h);
    }

    fn desciende_interno(&self, c: &Hash, a: &Hash) -> bool {
        if c == a {
            return true;
        }
        let padres = self.padres.borrow();
        let mut cur = *c;
        let mut vueltas = 0u32;
        while let Some(&padre) = padres.get(&cur) {
            if &padre == a {
                return true;
            }
            cur = padre;
            vueltas += 1;
            if vueltas > 10_000 {
                return false;
            }
        }
        false
    }
}

impl VistaCadena for VistaPrueba {
    fn desciende(&self, candidato: &Hash, ancestro: &Hash) -> bool {
        self.desciende_llamadas
            .set(self.desciende_llamadas.get().saturating_add(1));
        self.desciende_interno(candidato, ancestro)
    }

    fn en_cadena_seleccionada(&self, _hash: &Hash) -> bool {
        true
    }

    fn slot_de(&self, _hash: &Hash) -> Option<u64> {
        None
    }

    fn en_conflicto(&self, a: &Hash, b: &Hash) -> bool {
        self.en_conflicto_llamadas
            .set(self.en_conflicto_llamadas.get().saturating_add(1));
        let k = if a < b { (*a, *b) } else { (*b, *a) };
        if self.conflictos.borrow().contains(&k) {
            return true;
        }
        !self.desciende_interno(a, b) && !self.desciende_interno(b, a)
    }

    fn hecho_evidencia_entre_ventanas(
        &self,
        voto1: &VotoPesoEvidencia,
        voto2: &VotoPesoEvidencia,
        _plazo_slots: u64,
    ) -> Option<HechoVoto> {
        if let Some(h) =
            self.hechos
                .borrow()
                .get(&(voto1.n, voto2.n, voto1.candidato, voto2.candidato))
        {
            return Some(*h);
        }
        *self.hecho_defecto.borrow()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cadena real mínima (parámetros y bloques de `pruebas_eclr2`).
// ─────────────────────────────────────────────────────────────────────────────

fn params_prueba() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 1,
        w_min: U256::one(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 1,
        f_slots: Some(600),
        subsidio_pow: |_| Amount::nuevo(10).expect("importe"),
        subsidio_post: |_| Amount::nuevo(10_000).expect("importe"),
    }
}

fn genesis() -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: bh(0) },
        Vec::new(),
    ))
}

fn pow_terminal(id: u32, trabajo: u64) -> BloqueCadena {
    BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: bh(id),
            padre: bh(0),
            altura: 1,
            trabajo: U256::from(trabajo),
            pow_valido: true,
        },
        Vec::new(),
    ))
}

fn productor_firmante() -> (ClaveEd, ed25519_zebra::SigningKey) {
    let sk = ed25519_zebra::SigningKey::from([0x5a; 32]);
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    (ClaveEd::desde_bytes(vk.into()), sk)
}

fn post(id: u32, padres: Vec<BlockHash>, slot: u64, productor: ClaveEd) -> BloqueCadena {
    let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor,
        0,
        u64::from(id) + 1,
        [(id & 0xff) as u8; 32],
        slot,
    ));
    BloqueCadena::Post(zx_cadena::BloquePost {
        hash: bh(id),
        padres,
        slot,
        timestamp: 0,
        productor,
        peso: 1,
        prueba_valida: true,
        requisito_declarado: 0,
        sr: 0,
        distancia: 0,
        identidad,
        txs: Vec::new(),
    })
}

fn estado_para_cadena() -> Estado {
    let mut est = Estado::inicial();
    est.parametros_sector = ParametrosSector::dev();
    est
}

/// Cadena real con `P` (2), `X` (3) y `Z` (4) hijos de `P`, y `W` (5) que fusiona `X` y `Z`.
fn cadena_xpz() -> Cadena {
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params_prueba(),
        1,
        CBID_RED_DEV,
        15,
        ParametrosEvidencia::inactiva(),
        estado_para_cadena(),
    );
    cadena.admitir(genesis()).expect("génesis");
    cadena.admitir(pow_terminal(1, 1)).expect("terminal");
    let (productor, _sk) = productor_firmante();
    cadena
        .admitir(post(2, vec![bh(1)], 2, productor))
        .expect("P");
    cadena
        .admitir(post(3, vec![bh(2)], 3, productor))
        .expect("X");
    cadena
        .admitir(post(4, vec![bh(2)], 4, productor))
        .expect("Z");
    cadena
        .admitir(post(5, vec![bh(3), bh(4)], 5, productor))
        .expect("W");
    cadena
}

/// Estado dev con la clave `ed(1)` registrada y `n_sectores` activos (fixture de peso real).
fn estado_con_clave(n_sectores: usize) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::Genesis;
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
        let id = SectorId {
            clave: e,
            sector_index: u16::try_from(i).expect("índice"),
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
                id,
                r2: [0u64; 4],
                history_size: 1,
                etapa: Etapa::Activo,
                alta_slot: 0,
                renovacion_slot: 0,
                retiro_slot: -1,
                fianza: p.q_sec,
                aud_apertura: -1,
                aud_contestada: -1,
            },
        );
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    con_cola
}

fn operacion_de(ev: &EvidenciaVotosPesoCompleta) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(0x5a),
        clave_bls: ev.clave_bls,
        voto1: VotoPesoEvidencia {
            n: ev.n,
            candidato: ev.h1,
            h_t_siguiente: ev.h_t1,
            raiz_estado: ev.raiz1,
            firma: ev.firma1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n: ev.n2,
            candidato: ev.h2,
            h_t_siguiente: ev.h_t2,
            raiz_estado: ev.raiz2,
            firma: ev.firma2.bytes(),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1 · el contraejemplo mínimo de DF-M1
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_falta_entre_ventanas_tres_votos() {
    let cadena = cadena_xpz();
    let sk = bls(1);
    let clave = clave_de(&sk);
    let (x, p, z) = (hash_n(3), hash_n(2), hash_n(4));
    let h_t = hash_n(90);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    d.registrar(clave, voto(&sk, 1, x, h_t), &cadena);
    d.registrar(clave, voto(&sk, 2, p, h_t), &cadena);
    d.registrar(clave, voto(&sk, 3, z, h_t), &cadena);

    let evs = d.drenar(&cadena);
    assert_eq!(evs.len(), 1, "una sola evidencia");
    assert_eq!((evs[0].n, evs[0].n2), (1, 3), "ventanas 1 y 3");
    assert_eq!((evs[0].h1, evs[0].h2), (x, z), "candidatos X y Z");

    // `aplicar_evidencia_votos_peso` con el hecho que da la cadena la acepta.
    let hecho = cadena.hecho_voto_entre_ventanas(&evs[0].a_voto1(), &evs[0].a_voto2(), PLAZO);
    assert_eq!(hecho, Some(HechoVoto::Falta), "la cadena da Falta");
    let estado = estado_con_clave(100);
    // La tx `0x0B` lleva la ventana de cada voto (D7). Bajo R4 (misma ventana en los dos) esto
    // discrepa de la operación canónica y la prueba falla.
    let (tx, _testigos) = tx_evidencia_votos_peso(
        &evs[0],
        ed(0x5a),
        &ed25519_zebra::SigningKey::from([7u8; 32]),
        CBID_RED_DEV,
    );
    let op = match &tx.extension {
        ExtensionTx::PruebaAlmacenamiento { operacion } => operacion.clone(),
        _ => panic!("se esperaba una prueba de almacenamiento"),
    };
    assert_eq!(op, operacion_de(&evs[0]), "la tx lleva las dos ventanas");
    let (castigado, _, r) =
        zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_hecho_con_undo(
            &estado,
            &op,
            ed(0x5a),
            &params_prueba(),
            &ParametrosEvidencia::inactiva(),
            5,
            hecho,
        );
    r.expect("el consenso acepta la evidencia");
    assert_eq!(
        castigado.garantias[&ed(1)].incidentes.len(),
        1,
        "el consenso castiga al votante"
    );
    assert!(castigado.quemado > estado.quemado, "confisca y quema");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2 · el votante honesto no se acusa
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_no_acusa_cadena_honesta() {
    let vista = VistaPrueba::nuevo();
    let sk = bls(2);
    let clave = clave_de(&sk);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    let ventanas = d.horizonte() + 10;
    let mut cand = hash_n(1000);
    for n in 0..=ventanas {
        if n > 0 {
            let nuevo = hash_n(1000 + u32::try_from(n).expect("n cabe"));
            vista.pon_padre(nuevo, cand);
            cand = nuevo;
        }
        d.al_abrir(n);
        d.registrar(clave, voto(&sk, n, cand, hash_n(2000)), &vista);
    }
    let evs = d.drenar(&vista);
    assert!(evs.is_empty(), "cero evidencias");
    assert_eq!(
        vista.en_conflicto_llamadas.get(),
        0,
        "cero consultas de conflicto (el camino rápido del honesto)"
    );
    // El coste es O(1) `desciende` por voto, no O(k) por voto.
    let votos = ventanas + 1;
    assert!(
        vista.desciende_llamadas.get() <= 2 * votos,
        "desciende={} votos={votos}",
        vista.desciende_llamadas.get()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3 · los extremos no bastan (DF-M1, con certificado)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_extremos_no_bastan() {
    // DF-M1: `padre=[0,1,1,3,2]`, falta real (2, B2)-(3, B4); el par (1, B5)-(3, B4) está
    // justificado por el certificado (m=1, Z=B3) y sale `SinFalta`.
    let vista = VistaPrueba::nuevo();
    let b1 = hash_n(1);
    let b2 = hash_n(2);
    let b3 = hash_n(3);
    let b4 = hash_n(4);
    let b5 = hash_n(5);
    vista.pon_padre(b2, b1);
    vista.pon_padre(b3, b1);
    vista.pon_padre(b4, b3);
    vista.pon_padre(b5, b2);
    vista.pon_hecho(2, 3, b2, b4, HechoVoto::Falta);
    vista.pon_hecho(1, 3, b5, b4, HechoVoto::SinFalta);

    let sk = bls(3);
    let clave = clave_de(&sk);
    let h_t = hash_n(91);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    d.registrar(clave, voto(&sk, 2, b2, h_t), &vista);
    d.registrar(clave, voto(&sk, 1, b5, h_t), &vista);
    d.registrar(clave, voto(&sk, 3, b4, h_t), &vista);

    let evs = d.drenar(&vista);
    assert_eq!(evs.len(), 1, "una evidencia");
    assert_eq!(
        (evs[0].n, evs[0].n2, evs[0].h1, evs[0].h2),
        (2, 3, b2, b4),
        "sale el par no justificado, no el de los extremos"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4 · votos de ventanas pasadas
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_voto_de_ventana_pasada_se_guarda() {
    let vista = VistaPrueba::nuevo();
    let sk = bls(1);
    let clave = clave_de(&sk);
    let estado = estado_con_clave(100);
    let mut motor = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![bls(1)],
        emitir_votos: false,
    });
    motor
        .avanzar(1, bh(0x10), &estado, SLOT)
        .expect("abrir ventana 1");

    // Dentro del horizonte: se guarda y empareja; la respuesta es la de hoy.
    let bytes = sobre(&sk, 0, hash_n(0x20), hash_n(92));
    assert_eq!(
        motor.recibir_voto_con_vista(&bytes, &vista),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
    motor
        .detector
        .registrar(clave, voto(&sk, 1, hash_n(0x10), hash_n(92)), &vista);
    vista.pon_hecho(0, 1, hash_n(0x20), hash_n(0x10), HechoVoto::Falta);
    let evs = motor.drenar_evidencias_peso_con_vista(&vista);
    assert_eq!(evs.len(), 1, "el voto pasado se guardó y emparejó");
    assert_eq!((evs[0].n, evs[0].n2), (0, 1));

    // Fuera del horizonte: no se guarda y la respuesta sigue siendo la de hoy.
    motor.fijar_horizonte_detector(1);
    motor
        .avanzar(2, bh(0x11), &estado, SLOT)
        .expect("abrir ventana 2");
    let bytes_viejo = sobre(&sk, 0, hash_n(0x21), hash_n(93));
    assert_eq!(
        motor.recibir_voto_con_vista(&bytes_viejo, &vista),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
    assert!(
        motor.drenar_evidencias_peso_con_vista(&vista).is_empty(),
        "un voto más viejo que el horizonte no se guarda"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5 · bloque ausente: reintenta; si vence el horizonte, se borra
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_bloque_ausente_reintenta() {
    let vista = VistaPrueba::nuevo();
    *vista.hecho_defecto.borrow_mut() = Some(HechoVoto::Inadmisible);
    let sk = bls(4);
    let clave = clave_de(&sk);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    let (x, z) = (hash_n(0xA1), hash_n(0xA2));
    d.registrar(clave, voto(&sk, 0, x, hash_n(94)), &vista);
    d.registrar(clave, voto(&sk, 1, z, hash_n(94)), &vista);
    assert!(d.drenar(&vista).is_empty(), "sin el bloque no se presenta");
    // Llega el bloque: el hecho pasa a Falta.
    vista.pon_hecho(0, 1, x, z, HechoVoto::Falta);
    let evs = d.drenar(&vista);
    assert_eq!(evs.len(), 1, "cuando llega el bloque, sí");
    // Vence el horizonte: se borra todo.
    d.al_abrir(d.horizonte() + 100);
    assert_eq!(d.votos_guardados(), 0, "podado");
    assert!(d.drenar(&vista).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 6 · poda y horizonte por parámetro interno
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_poda_al_vencer_el_horizonte() {
    let vista = VistaPrueba::nuevo();
    let sk = bls(5);
    let clave = clave_de(&sk);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    assert_eq!(d.horizonte(), 450, "derivado de las constantes");
    d.fijar_horizonte(3);
    assert_eq!(d.horizonte(), 3, "el horizonte es un parámetro interno");
    for n in 0..6 {
        if n > 0 {
            // Cadena honesta: ningún candidato conflictúa con el anterior.
            vista.pon_padre(hash_n(0xB0 + n as u32), hash_n(0xB0 + n as u32 - 1));
        }
        d.registrar(
            clave,
            voto(&sk, n, hash_n(0xB0 + n as u32), hash_n(95)),
            &vista,
        );
    }
    assert_eq!(d.votos_guardados(), 6);
    d.al_abrir(5);
    // Horizonte 3 sobre la ventana 5: se conservan 3, 4 y 5.
    assert_eq!(d.votos_guardados(), 3, "nada anterior al horizonte");
    assert!(
        d.drenar(&vista).is_empty(),
        "sin conflictos no hay evidencia"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7 · sin incidentes duplicados
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_no_duplica_incidente() {
    let vista = VistaPrueba::nuevo();
    let sk = bls(6);
    let clave = clave_de(&sk);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    let (a, b) = (hash_n(0xC1), hash_n(0xC2));
    let v0 = voto(&sk, 0, a, hash_n(96));
    let v1 = voto(&sk, 1, b, hash_n(96));
    d.registrar(clave, v0, &vista);
    d.registrar(clave, v0, &vista); // el mismo par visto dos veces
    d.registrar(clave, v1, &vista);
    d.registrar(clave, v1, &vista);
    let evs = d.drenar(&vista);
    assert_eq!(evs.len(), 1, "una sola evidencia");

    // Segundo par de la misma clave con la evidencia sin aplicar: no se presenta otra.
    let (c, e) = (hash_n(0xC3), hash_n(0xC4));
    d.registrar(clave, voto(&sk, 2, c, hash_n(96)), &vista);
    d.registrar(clave, voto(&sk, 3, e, hash_n(96)), &vista);
    assert!(
        d.drenar(&vista).is_empty(),
        "una evidencia por clave acusada a la vez"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8 · como mucho dos votos por clave y ventana
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_dos_votos_por_ventana_como_mucho() {
    let vista = VistaPrueba::nuevo();
    let sk = bls(7);
    let clave = clave_de(&sk);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    d.registrar(clave, voto(&sk, 0, hash_n(0xD1), hash_n(97)), &vista);
    d.registrar(clave, voto(&sk, 0, hash_n(0xD2), hash_n(97)), &vista);
    d.registrar(clave, voto(&sk, 0, hash_n(0xD3), hash_n(97)), &vista);
    assert_eq!(d.votos_guardados(), 2, "el tercero no se guarda");
    assert!(d.drenar(&vista).is_empty(), "sin evidencia entre ventanas");

    // La evidencia de la **misma** ventana sigue saliendo por el camino de siempre.
    let estado = estado_con_clave(100);
    let mut motor = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: false,
    });
    motor
        .avanzar(0, bh(0x10), &estado, SLOT)
        .expect("abrir ventana 0");
    let _ = motor.recibir_voto(&sobre_voto(&bls(1), 0, bh(0x20)));
    let _ = motor.recibir_voto(&sobre_voto(&bls(1), 0, bh(0x21)));
    assert_eq!(
        motor.drenar_evidencias_peso().len(),
        1,
        "evidencia de misma ventana"
    );
}

/// Sobre de un voto de la instancia abierta (clave `sk`) con `h_t` nulo.
fn sobre_voto(sk: &ClaveSecreta, n: u64, candidato: BlockHash) -> Vec<u8> {
    let h = *candidato.as_bytes();
    sobre(sk, n, h, [0u8; 32])
}

// ─────────────────────────────────────────────────────────────────────────────
// 9 · la `0x0B` lleva las dos ventanas y pasa por el códec
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tx_evidencia_entre_ventanas_lleva_las_dos_ventanas() {
    let sk = bls(8);
    let ev = EvidenciaVotosPesoCompleta {
        n: 1,
        n2: 3,
        h1: hash_n(3),
        h_t1: hash_n(90),
        raiz1: [0u8; 32],
        firma1: firma_de(&sk, 1, hash_n(3)),
        clave_bls: clave_de(&sk),
        h2: hash_n(4),
        h_t2: hash_n(90),
        raiz2: [0u8; 32],
        firma2: firma_de(&sk, 3, hash_n(4)),
    };
    let (tx, testigos) = tx_evidencia_votos_peso(
        &ev,
        ed(0),
        &ed25519_zebra::SigningKey::from([7u8; 32]),
        CBID_RED_DEV,
    );
    let op = match &tx.extension {
        ExtensionTx::PruebaAlmacenamiento { operacion } => operacion,
        _ => panic!("se esperaba una prueba de almacenamiento"),
    };
    match op {
        OperacionAlmacenamiento::EvidenciaVotosPeso { voto1, voto2, .. } => {
            assert_eq!(voto1.n, 1);
            assert_eq!(voto2.n, 3);
        }
        _ => panic!("se esperaba EvidenciaVotosPeso"),
    }
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, &tx, &testigos);
    let (dec, resto) = zx_core::wire::tx_desde_bytes(&buf).expect("códec");
    assert!(resto.is_empty(), "sin bytes sobrantes");
    let (tx2, _testigos2) = dec;
    let op2 = match &tx2.extension {
        ExtensionTx::PruebaAlmacenamiento { operacion } => operacion,
        _ => panic!("se esperaba una prueba de almacenamiento"),
    };
    assert_eq!(op2, op, "ida y vuelta");
}

fn firma_de(sk: &ClaveSecreta, n: u64, candidato: Hash) -> Firma {
    let mensaje = mensaje_voto_peso(n, &candidato, &hash_n(90), &[0u8; 32]);
    firmar(sk, DOMINIO_VOTO, &mensaje).expect("firma BLS")
}

// ─────────────────────────────────────────────────────────────────────────────
// 10 · DFV-1-2 · G1 (pertenencia antes que criptografía) y G2 (tope total)
// ─────────────────────────────────────────────────────────────────────────────

/// Clave BLS distinta por `i` (las 10 000 claves nuevas de la inundación).
fn clave_nueva(i: u32) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[..4].copy_from_slice(&i.to_le_bytes());
    ikm[31] = 0xC3;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

/// Motor con la ventana 1 abierta y la clave `bls(1)` registrada (`estado_con_clave`).
fn motor_con_ventana_abierta() -> MotorVotos {
    let estado = estado_con_clave(100);
    let mut motor = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![bls(1)],
        emitir_votos: false,
    });
    motor
        .avanzar(1, bh(0x10), &estado, SLOT)
        .expect("abrir ventana 1");
    motor
}

#[test]
fn detector_ignora_clave_no_registrada_sin_verificar() {
    let vista = VistaPrueba::nuevo();
    let mut motor = motor_con_ventana_abierta();
    // Clave BLS recién generada que no está en la tabla de la ventana abierta.
    let sk = clave_nueva(0xDEAD);
    assert_ne!(clave_de(&sk), clave_de(&bls(1)), "clave distinta");
    reiniciar_verificaciones_voto_pasado();
    let bytes = sobre(&sk, 0, hash_n(0x20), hash_n(92));
    assert_eq!(
        motor.recibir_voto_con_vista(&bytes, &vista),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
    assert_eq!(motor.detector.votos_guardados(), 0, "no se guarda nada");
    assert_eq!(
        verificaciones_voto_pasado(),
        0,
        "no se llamó a verificar la firma"
    );

    // Control positivo: la clave registrada sí se verifica y se guarda.
    let bytes_ok = sobre(&bls(1), 0, hash_n(0x21), hash_n(92));
    assert_eq!(
        motor.recibir_voto_con_vista(&bytes_ok, &vista),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
    assert_eq!(
        verificaciones_voto_pasado(),
        1,
        "la registrada sí se verifica"
    );
    assert_eq!(motor.detector.votos_guardados(), 1, "y se guarda");
}

#[test]
fn detector_guarda_clave_registrada_de_ventana_pasada() {
    let vista = VistaPrueba::nuevo();
    let sk = bls(1);
    let clave = clave_de(&sk);
    let mut motor = motor_con_ventana_abierta();
    reiniciar_verificaciones_voto_pasado();
    let bytes = sobre(&sk, 0, hash_n(0x20), hash_n(92));
    assert_eq!(
        motor.recibir_voto_con_vista(&bytes, &vista),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
    assert_eq!(
        motor.detector.votos_guardados(),
        1,
        "la registrada se guarda"
    );
    assert_eq!(verificaciones_voto_pasado(), 1, "y se verifica una vez");
    // Empareja con un voto de la ventana abierta en conflicto y sale la evidencia.
    motor
        .detector
        .registrar(clave, voto(&sk, 1, hash_n(0x10), hash_n(92)), &vista);
    vista.pon_hecho(0, 1, hash_n(0x20), hash_n(0x10), HechoVoto::Falta);
    let evs = motor.drenar_evidencias_peso_con_vista(&vista);
    assert_eq!(evs.len(), 1, "se empareja la ventana pasada con la abierta");
    assert_eq!((evs[0].n, evs[0].n2), (0, 1));
}

#[test]
fn detector_respeta_el_tope_total() {
    let vista = VistaPrueba::nuevo();
    let sk = bls(10);
    let clave = clave_de(&sk);
    let mut d = DetectorFalta::nuevo(2, PLAZO);
    let horizonte: u64 = 3;
    let claves_tabla: usize = 1;
    d.fijar_horizonte(horizonte);
    d.fijar_tope(claves_tabla);
    let tope = 2 * usize::try_from(horizonte).expect("horizonte") * claves_tabla;
    // Muchos votos distintos, dos por ventana en once ventanas: sin tope se guardarían 22.
    for n in 0..=10u64 {
        for j in 0..2u64 {
            let candidato = hash_n(0xE000 + u32::try_from(n * 10 + j).expect("n"));
            d.registrar(clave, voto(&sk, n, candidato, hash_n(98)), &vista);
        }
    }
    assert_eq!(d.votos_guardados(), tope, "el tope corta en seco");
    // Al llegar al tope, el voto nuevo se descarta y no se borra nada.
    d.registrar(clave, voto(&sk, 11, hash_n(0xE0FF), hash_n(98)), &vista);
    assert_eq!(d.votos_guardados(), tope, "el voto nuevo no entra");
}

#[test]
fn detector_inundacion_de_claves_nuevas_no_crece() {
    let vista = VistaPrueba::nuevo();
    let mut motor = motor_con_ventana_abierta();
    reiniciar_verificaciones_voto_pasado();
    for i in 0..10_000u32 {
        let sk = clave_nueva(i);
        let bytes = sobre(&sk, 0, hash_n(0x1000 + i), hash_n(0x99));
        assert_eq!(
            motor.recibir_voto_con_vista(&bytes, &vista),
            RecepcionVoto::Rechazado { motivo: "ventana" }
        );
    }
    assert_eq!(
        motor.detector.votos_guardados(),
        0,
        "10 000 claves nuevas: cero guardados"
    );
    assert_eq!(
        verificaciones_voto_pasado(),
        0,
        "10 000 claves nuevas: cero firmas verificadas"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Banco DFV-1 (`#[ignore]`, bloque 0, --release, perf).
// ─────────────────────────────────────────────────────────────────────────────

/// Banco del detector. Variables de entorno:
/// `DFV1_CLAVES` (por defecto 4096), `DFV1_REPS` (15), `DFV1_HORIZONTE` (450).
///
/// Mide con `Instant`: (a) coste medio de guardar un voto honesto; (b) coste de abrir una ventana;
/// (c) peor caso, 1/3 de las claves votando un bloque hermano; (d) memoria (`memoria_detector_bytes`).
#[test]
#[ignore = "banco DFV-1: se corre a mano en bloque 0 con --release y perf; ver MEDIDA.log"]
fn banco_detector_entre_ventanas() {
    use std::time::Instant;
    let claves: usize = std::env::var("DFV1_CLAVES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);
    let reps: usize = std::env::var("DFV1_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    let horizonte: usize = std::env::var("DFV1_HORIZONTE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(450);
    // Cadena honesta de `horizonte` candidatos: c_i desciende de c_{i-1}.
    let vista = VistaPrueba::nuevo();
    let mut candidatos = Vec::with_capacity(horizonte);
    let mut cand = hash_n(1);
    for i in 0..horizonte {
        if i > 0 {
            let nuevo = hash_n(u32::try_from(i + 2).expect("i"));
            vista.pon_padre(nuevo, cand);
            cand = nuevo;
        }
        candidatos.push(cand);
    }
    let firma = firmar(
        &bls(1),
        DOMINIO_VOTO,
        &mensaje_voto_peso(0, &hash_n(1), &hash_n(9), &[0u8; 32]),
    )
    .expect("firma válida");
    let voto_de = |_clave: [u8; LONGITUD_CLAVE_BLS], n: usize, cand: Hash| VotoDetector {
        n: u64::try_from(n).expect("n"),
        candidato: cand,
        h_t_siguiente: hash_n(9),
        raiz_estado: [0u8; 32],
        firma,
    };
    // Claves sintéticas (etiquetas de 48 B): el detector no verifica firmas; mide su trabajo.
    let clave_de_i = |i: usize| {
        let mut k = [0u8; LONGITUD_CLAVE_BLS];
        k[..8].copy_from_slice(&u64::try_from(i).expect("i").to_be_bytes());
        k
    };

    let mut guardar = Vec::with_capacity(reps);
    let mut abrir = Vec::with_capacity(reps);
    let mut memoria = Vec::with_capacity(reps);
    for _ in 0..reps {
        let mut d = DetectorFalta::nuevo(2, PLAZO);
        let t0 = Instant::now();
        for i in 0..claves {
            let clave = clave_de_i(i);
            for (n, c) in candidatos.iter().enumerate() {
                d.registrar(clave, voto_de(clave, n, *c), &vista);
            }
        }
        let total = t0.elapsed().as_nanos() as f64;
        guardar.push(total / (claves * horizonte) as f64);
        let t1 = Instant::now();
        d.al_abrir(u64::try_from(horizonte).expect("h"));
        abrir.push(t1.elapsed().as_nanos() as f64);
        memoria.push(d.memoria_bytes());
        println!(
            "DFV1 banco: claves={claves} horizonte={horizonte} voto_bytes={} memoria_bytes={}",
            VotoDetector::bytes(),
            d.memoria_bytes()
        );
    }
    let resumen = |m: &[f64]| {
        let mut v = m.to_vec();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let med = v[v.len() / 2];
        (v[0], med, v[v.len() - 1])
    };
    let (gmin, gmed, gmax) = resumen(&guardar);
    let (amin, amed, amax) = resumen(&abrir);
    println!("DFV1 (a) guardar honesto ns/voto: min={gmin:.1} mediana={gmed:.1} max={gmax:.1}");
    println!("DFV1 (b) abrir ventana ns: min={amin:.1} mediana={amed:.1} max={amax:.1}");
    println!(
        "DFV1 (d) memoria bytes: min={} mediana={} max={}",
        memoria[0],
        memoria[memoria.len() / 2],
        memoria[memoria.len() - 1]
    );

    // (c) peor caso: un tercio de las claves vota un bloque hermano del candidato en cada ventana.
    let hermanos: Vec<Hash> = (0..horizonte)
        .map(|i| hash_n(u32::try_from(10_000 + i).expect("i")))
        .collect();
    let mut peor = Vec::with_capacity(reps);
    for _ in 0..reps {
        let mut d = DetectorFalta::nuevo(2, PLAZO);
        let t0 = Instant::now();
        for i in 0..claves {
            let clave = clave_de_i(i);
            let votar_hermano = i % 3 == 0;
            for (n, c) in candidatos.iter().enumerate() {
                let candidato = if votar_hermano { hermanos[n] } else { *c };
                d.registrar(clave, voto_de(clave, n, candidato), &vista);
            }
        }
        peor.push(t0.elapsed().as_nanos() as f64 / (claves * horizonte) as f64);
    }
    let (pmin, pmed, pmax) = resumen(&peor);
    println!(
        "DFV1 (c) peor caso (1/3 hermanos) ns/voto: min={pmin:.1} mediana={pmed:.1} max={pmax:.1}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Banco A5-c-1c (`#[ignore]`, bloque 0, --release, perf).
// ─────────────────────────────────────────────────────────────────────────────

/// Banco A5-c-1c · B-71 · detector con **una** subred vigilada y con **todas**.
///
/// Variables de entorno: `DFV1B_CLAVES` (por defecto 65 536), `DFV1B_HORIZONTE` (450) y
/// `DFV1B_REPS` (1). Por cada caso imprime las claves efectivamente guardadas, la memoria del
/// detector (`memoria_bytes`) y el tiempo de `al_abrir`. Con `S = 64` la subred vigilada del primer
/// caso es la de la etiqueta sintética `0`; el resto de claves se reparten con `subred`.
#[test]
#[ignore = "banco A5C1C: se corre a mano en bloque 0 con --release y perf; ver MEDIDA.log"]
fn banco_detector_subredes() {
    use std::time::Instant;
    let claves: usize = std::env::var("DFV1B_CLAVES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65_536);
    let horizonte: usize = std::env::var("DFV1B_HORIZONTE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(450);
    let reps: usize = std::env::var("DFV1B_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let s: u16 = 64;
    // Cadena honesta de `horizonte` candidatos: `c_i` desciende de `c_{i-1}`.
    let vista = VistaPrueba::nuevo();
    let mut candidatos = Vec::with_capacity(horizonte);
    let mut cand = hash_n(1);
    for i in 0..horizonte {
        if i > 0 {
            let nuevo = hash_n(u32::try_from(i + 2).expect("i"));
            vista.pon_padre(nuevo, cand);
            cand = nuevo;
        }
        candidatos.push(cand);
    }
    let firma = firmar(
        &bls(1),
        DOMINIO_VOTO,
        &mensaje_voto_peso(0, &hash_n(1), &hash_n(9), &[0u8; 32]),
    )
    .expect("firma válida");
    let voto_de = |_clave: [u8; LONGITUD_CLAVE_BLS], n: usize, cand: Hash| VotoDetector {
        n: u64::try_from(n).expect("n"),
        candidato: cand,
        h_t_siguiente: hash_n(9),
        raiz_estado: [0u8; 32],
        firma,
    };
    // Claves sintéticas (etiquetas de 48 B): el detector no verifica firmas; mide su trabajo.
    let clave_de_i = |i: usize| {
        let mut k = [0u8; LONGITUD_CLAVE_BLS];
        k[..8].copy_from_slice(&u64::try_from(i).expect("i").to_be_bytes());
        k
    };
    let una = zx_votos::agregacion::subred(&clave_de_i(0), s).expect("subred del primer voto");
    let medir = |vigiladas: Option<std::collections::HashSet<u16>>, etiqueta: &str| {
        let mut memoria = Vec::with_capacity(reps);
        let mut abrir = Vec::with_capacity(reps);
        let mut guardados = Vec::with_capacity(reps);
        for _ in 0..reps {
            let mut d = DetectorFalta::nuevo(2, PLAZO);
            d.fijar_vigiladas(s, vigiladas.clone());
            for i in 0..claves {
                let clave = clave_de_i(i);
                for (n, c) in candidatos.iter().enumerate() {
                    d.registrar(clave, voto_de(clave, n, *c), &vista);
                }
            }
            let t = Instant::now();
            d.al_abrir(u64::try_from(horizonte).expect("h"));
            let ns = t.elapsed().as_nanos() as f64;
            memoria.push(d.memoria_bytes());
            abrir.push(ns);
            guardados.push(d.votos_guardados());
        }
        println!(
            "A5C1C banco {etiqueta}: claves_tabla={claves} horizonte={horizonte} \
             subredes_vigiladas={} guardados={} memoria_bytes={} abrir_ns={}",
            vigiladas
                .as_ref()
                .map_or(s as usize, std::collections::HashSet::len),
            guardados[0],
            memoria[0],
            abrir[0]
        );
    };
    medir(Some(std::collections::HashSet::from([una])), "una_subred");
    medir(None, "todas");
}

// ─────────────────────────────────────────────────────────────────────────────
// Accesores de conveniencia de la evidencia.
// ─────────────────────────────────────────────────────────────────────────────

impl EvidenciaVotosPesoCompleta {
    fn a_voto1(&self) -> VotoPesoEvidencia {
        VotoPesoEvidencia {
            n: self.n,
            candidato: self.h1,
            h_t_siguiente: self.h_t1,
            raiz_estado: self.raiz1,
            firma: self.firma1.bytes(),
        }
    }

    fn a_voto2(&self) -> VotoPesoEvidencia {
        VotoPesoEvidencia {
            n: self.n2,
            candidato: self.h2,
            h_t_siguiente: self.h_t2,
            raiz_estado: self.raiz2,
            firma: self.firma2.bytes(),
        }
    }
}
