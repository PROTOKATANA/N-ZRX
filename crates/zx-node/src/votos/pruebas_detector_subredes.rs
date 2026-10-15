//! A5-c-1c · IPA B-71/B-74 · pruebas del detector que vigila **solo las subredes del nodo** y que
//! sigue vigilando a la clave que salió de la tabla.
//!
//! T1–T7 del contrato de la orden. Usan claves BLS y firmas reales en proceso; la vista modela el
//! conflicto y el hecho sin montar una cadena completa (las pruebas T6 que ejercitan
//! `zx-consensus` van por su interfaz de integración, sin tocar el crate).

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

use primitive_types::U256;
use zx_consensus::sectores::{
    ClaveVoto, ClaveVotoAnterior, Etapa, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::{
    Fase, Garantia, HechoVoto, ParametrosEvidencia, ParametrosTransicion,
};
use zx_core::ClavePublica as ClaveEd;
use zx_core::{Amount, BlockHash, Digest, OperacionAlmacenamiento};
use zx_votos::ClaveSecreta;

// ─────────────────────────────────────────────────────────────────────────────
// Claves, hashes y votos reales.
// ─────────────────────────────────────────────────────────────────────────────

const SLOT: i64 = 100;
const S: u16 = 64;

fn clave_bls(i: u32) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[..4].copy_from_slice(&i.to_le_bytes());
    ikm[31] = 0xB7;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn clave_ed(i: u8) -> ClaveEd {
    ClaveEd::desde_bytes([i; 32])
}

fn bytes(sk: &ClaveSecreta) -> [u8; LONGITUD_CLAVE_BLS] {
    sk.clave_publica().bytes()
}

fn subred_de(sk: &ClaveSecreta) -> u16 {
    subred(&bytes(sk), S).expect("subred")
}

fn hash_n(i: u32) -> Hash {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_be_bytes());
    b
}

fn bh(i: u32) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes(hash_n(i)))
}

/// Sobre serializado de un voto (ruta vieja) firmado de verdad.
fn sobre(sk: &ClaveSecreta, n: u64, candidato: Hash, h_t: Hash) -> Vec<u8> {
    let mensaje = mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]);
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje).expect("firma BLS");
    serializar_voto_peso(&VotoPeso {
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave: bytes(sk),
        firma,
    })
}

/// Voto de red `248 B` serializado, firmado de verdad.
fn sobre_red(sk: &ClaveSecreta, n: u64, candidato: Hash, h_t: Hash) -> Vec<u8> {
    let mensaje = mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]);
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje).expect("firma BLS");
    VotoRed {
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave: sk.clave_publica(),
        firma,
    }
    .serializar()
}

/// Vista mínima: `desciende` solo la identidad, todo par distinto conflictúa, y cualquier par de
/// ventanas distintas es `Falta`.
struct Vista;

impl VistaCadena for Vista {
    fn desciende(&self, candidato: &Hash, ancestro: &Hash) -> bool {
        candidato == ancestro
    }

    fn en_cadena_seleccionada(&self, _hash: &Hash) -> bool {
        true
    }

    fn slot_de(&self, _hash: &Hash) -> Option<u64> {
        None
    }

    fn en_conflicto(&self, a: &Hash, b: &Hash) -> bool {
        a != b
    }

    fn hecho_evidencia_entre_ventanas(
        &self,
        _voto1: &VotoPesoEvidencia,
        _voto2: &VotoPesoEvidencia,
        _plazo_slots: u64,
    ) -> Option<HechoVoto> {
        Some(HechoVoto::Falta)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Estados con claves de voto reales.
// ─────────────────────────────────────────────────────────────────────────────

fn estado_de_indices_etapa(indices: &[u32], etapa: Etapa) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::Genesis;
    for (pos, &i) in indices.iter().enumerate() {
        let sk = clave_bls(i);
        let pk = sk.clave_publica();
        let e = clave_ed(u8::try_from(pos).expect("posición"));
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let id = SectorId {
            clave: e,
            sector_index: 0,
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
                id,
                r2: [0u64; 4],
                history_size: 1,
                etapa,
                alta_slot: 0,
                renovacion_slot: 0,
                retiro_slot: -1,
                fianza: p.q_sec,
                aud_apertura: -1,
                aud_contestada: -1,
            },
        );
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(1000).expect("importe");
        est.garantias.insert(e, g);
    }
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    con_cola
}

fn estado_de_indices(indices: &[u32]) -> Estado {
    estado_de_indices_etapa(indices, Etapa::Activo)
}

fn motor() -> MotorVotos {
    MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: crate::perfil::parametros_votos_dev(),
            claves: Vec::new(),
            emitir_votos: false,
        },
        S,
    )
}

fn ventana(m: &MotorVotos) -> (Hash, Hash) {
    let inst = m.instancia.as_ref().expect("instancia abierta");
    (inst.candidato, inst.h_t_siguiente)
}

/// Índices `i` cuya clave cae en la subred `destino`, hasta juntar `cuantos`.
fn indices_en_subred(destino: u16, cuantos: usize) -> Vec<u32> {
    let mut v = Vec::new();
    for i in 0..65_536u32 {
        if subred_de(&clave_bls(i)) == destino {
            v.push(i);
            if v.len() == cuantos {
                break;
            }
        }
    }
    v
}

/// Un índice en `a` y otro fuera de `a`, ambos dentro de la tabla base `0..64` (para los casos
/// «vigilada» / «no vigilada»).
fn par_vigilada_no_vigilada() -> (u32, u32, u16) {
    let a = subred_de(&clave_bls(0));
    let en_a = (0..64u32)
        .find(|&i| subred_de(&clave_bls(i)) == a)
        .expect("una clave en la subred de la primera");
    let fuera = (0..64u32)
        .find(|&i| subred_de(&clave_bls(i)) != a)
        .expect("otra subred en la tabla");
    (en_a, fuera, a)
}

/// Índices de la tabla base de cada prueba de la parte T1/T2.
fn idxs_base() -> Vec<u32> {
    (0..64u32).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// T1/T2 · vigilar solo las subredes fijadas.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dts_01_sin_fijar_se_vigilan_todas_las_subredes() {
    let vista = Vista;
    let idxs = idxs_base();
    let estado = estado_de_indices(&idxs);
    let mut m = motor();
    m.avanzar(1, bh(0x10), &estado, SLOT).expect("abrir");
    let (_cand, h_t) = ventana(&m);
    let (si, no, _a) = par_vigilada_no_vigilada();
    // Nadie ha fijado nada: se vigilan todas.
    assert!(m.clave_vigilada(&bytes(&clave_bls(si))));
    assert!(m.clave_vigilada(&bytes(&clave_bls(no))));
    let _ = m.recibir_voto_con_vista(&sobre(&clave_bls(si), 0, hash_n(0xE1), h_t), &vista);
    let _ = m.recibir_voto_con_vista(&sobre(&clave_bls(no), 0, hash_n(0xE2), h_t), &vista);
    assert_eq!(
        m.detector.votos_guardados(),
        2,
        "sin fijar, se guardan las dos subredes"
    );
}

#[test]
fn dts_02_voto_de_subred_no_vigilada_no_entra_en_el_detector() {
    let vista = Vista;
    let idxs = idxs_base();
    let estado = estado_de_indices(&idxs);
    let mut m = motor();
    m.avanzar(1, bh(0x10), &estado, SLOT).expect("abrir");
    let (cand, h_t) = ventana(&m);
    let (si, no, a) = par_vigilada_no_vigilada();
    let sk_si = clave_bls(si);
    let sk_no = clave_bls(no);
    m.fijar_subredes_vigiladas(&[a]);

    // (a) ventana abierta, sobre antiguo: cuenta para la ventana, no para el detector.
    assert!(matches!(
        m.recibir_voto_con_vista(&sobre(&sk_no, 1, cand, h_t), &vista),
        RecepcionVoto::Aceptado { .. }
    ));
    assert_eq!(m.detector.votos_guardados(), 0, "no vigilada: no se guarda");
    // (b) ventana pasada, sobre antiguo.
    assert_eq!(
        m.recibir_voto_con_vista(&sobre(&sk_no, 0, hash_n(0xE1), h_t), &vista),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
    assert_eq!(m.detector.votos_guardados(), 0);
    // (c) voto de subred, ventana abierta.
    let sub_no = subred_de(&sk_no);
    assert!(matches!(
        m.recibir_voto_subred(sub_no, &sobre_red(&sk_no, 1, cand, h_t), &vista),
        RecepcionVotoSubred::Aceptado { .. }
    ));
    assert_eq!(m.detector.votos_guardados(), 0);
    // (d) voto de subred, ventana pasada.
    let _ = m.recibir_voto_subred(sub_no, &sobre_red(&sk_no, 0, hash_n(0xE2), h_t), &vista);
    assert_eq!(m.detector.votos_guardados(), 0);

    // Control positivo: la subred vigilada sí entra.
    let _ = m.recibir_voto_con_vista(&sobre(&sk_si, 0, hash_n(0xE3), h_t), &vista);
    assert_eq!(m.detector.votos_guardados(), 1, "la vigilada sí se guarda");
}

#[test]
fn dts_03_voto_de_subred_no_vigilada_sigue_contando_para_su_ventana() {
    let vista = Vista;
    let idxs = idxs_base();
    let estado = estado_de_indices(&idxs);
    let mut m = motor();
    m.avanzar(1, bh(0x10), &estado, SLOT).expect("abrir");
    let (cand, h_t) = ventana(&m);
    let (_si, no, a) = par_vigilada_no_vigilada();
    let sk_no = clave_bls(no);
    m.fijar_subredes_vigiladas(&[a]);
    assert!(matches!(
        m.recibir_voto_con_vista(&sobre(&sk_no, 1, cand, h_t), &vista),
        RecepcionVoto::Aceptado { .. }
    ));
    assert_eq!(
        m.detector.votos_guardados(),
        0,
        "no se guarda en el detector"
    );
    let inst = m.instancia.as_ref().expect("instancia");
    assert!(
        inst.votos_peso.iter().any(|v| v.clave == bytes(&sk_no)),
        "el voto cuenta para el cierre de su ventana"
    );
}

#[test]
fn dts_04_lista_vacia_no_guarda_nada() {
    let vista = Vista;
    let idxs = idxs_base();
    let estado = estado_de_indices(&idxs);
    let mut m = motor();
    m.avanzar(1, bh(0x10), &estado, SLOT).expect("abrir");
    let (cand, h_t) = ventana(&m);
    let (si, _no, _a) = par_vigilada_no_vigilada();
    let sk = clave_bls(si);
    m.fijar_subredes_vigiladas(&[]);
    assert!(!m.clave_vigilada(&bytes(&sk)), "lista vacía: nada vigilado");
    assert!(matches!(
        m.recibir_voto_con_vista(&sobre(&sk, 1, cand, h_t), &vista),
        RecepcionVoto::Aceptado { .. }
    ));
    let _ = m.recibir_voto_con_vista(&sobre(&sk, 0, hash_n(0xE1), h_t), &vista);
    assert_eq!(m.detector.votos_guardados(), 0, "no se guarda nada");
}

#[test]
fn dts_05_al_fijar_se_borra_lo_de_otras_subredes() {
    let vista = Vista;
    let idxs = idxs_base();
    let estado = estado_de_indices(&idxs);
    let mut m = motor();
    m.avanzar(1, bh(0x10), &estado, SLOT).expect("abrir");
    let (_cand, h_t) = ventana(&m);
    let (si, no, a) = par_vigilada_no_vigilada();
    let sk_si = clave_bls(si);
    let sk_no = clave_bls(no);
    // Sin fijar, las dos subredes entran.
    let _ = m.recibir_voto_con_vista(&sobre(&sk_si, 0, hash_n(0xE1), h_t), &vista);
    let _ = m.recibir_voto_con_vista(&sobre(&sk_no, 0, hash_n(0xE2), h_t), &vista);
    assert_eq!(m.detector.votos_guardados(), 2);
    // Al fijar, lo de la otra subred se borra.
    m.fijar_subredes_vigiladas(&[a]);
    assert_eq!(
        m.detector.votos_guardados(),
        1,
        "se borra lo ya guardado de otras subredes"
    );
    // Y lo nuevo de la no vigilada ya no entra ni se verifica.
    reiniciar_verificaciones_voto_pasado();
    let _ = m.recibir_voto_con_vista(&sobre(&sk_no, 0, hash_n(0xE3), h_t), &vista);
    assert_eq!(m.detector.votos_guardados(), 1);
    assert_eq!(verificaciones_voto_pasado(), 0);
}

#[test]
fn dts_06_voto_pasado_de_subred_no_vigilada_no_verifica_firmas() {
    let vista = Vista;
    let idxs = idxs_base();
    let estado = estado_de_indices(&idxs);
    let mut m = motor();
    m.avanzar(1, bh(0x10), &estado, SLOT).expect("abrir");
    let (_cand, h_t) = ventana(&m);
    let (si, no, a) = par_vigilada_no_vigilada();
    let sk_si = clave_bls(si);
    let sk_no = clave_bls(no);
    m.fijar_subredes_vigiladas(&[a]);

    reiniciar_verificaciones_voto_pasado();
    let _ = m.recibir_voto_con_vista(&sobre(&sk_no, 0, hash_n(0xE1), h_t), &vista);
    assert_eq!(
        verificaciones_voto_pasado(),
        0,
        "no vigilada: ni se verifica la firma"
    );
    assert_eq!(m.detector.votos_guardados(), 0);

    // Control positivo: la vigilada sí se verifica y se guarda.
    let _ = m.recibir_voto_con_vista(&sobre(&sk_si, 0, hash_n(0xE2), h_t), &vista);
    assert_eq!(verificaciones_voto_pasado(), 1);
    assert_eq!(m.detector.votos_guardados(), 1);
}

#[test]
fn dts_07_el_tope_sale_de_las_claves_vigiladas() {
    let idxs = idxs_base();
    let estado = estado_de_indices(&idxs);
    let mut m = motor();
    m.fijar_horizonte_detector(3);
    m.avanzar(1, bh(0x10), &estado, SLOT).expect("abrir");
    let a = subred_de(&clave_bls(0));
    let n_a = idxs
        .iter()
        .filter(|&&i| subred_de(&clave_bls(i)) == a)
        .count();
    m.fijar_subredes_vigiladas(&[a]);
    assert_eq!(
        m.detector.tope(),
        2 * 3 * n_a,
        "2 · horizonte · claves vigiladas de la tabla"
    );
    let todas: Vec<u16> = (0..S).collect();
    m.fijar_subredes_vigiladas(&todas);
    assert_eq!(
        m.detector.tope(),
        2 * 3 * idxs.len(),
        "con todas, todas las claves de la tabla"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// T4/T5 · claves salientes (B-74).
// ─────────────────────────────────────────────────────────────────────────────

/// Índices para el caso saliente: dos claves en la subred `a` y una fuera. Así la tabla de la
/// ventana siguiente conserva al menos una clave vigilada y la cota T5 deja sitio al apunte.
fn indices_saliente() -> (Vec<u32>, ClaveSecreta, u16) {
    let a = subred_de(&clave_bls(0));
    let en_a = indices_en_subred(a, 2);
    let fuera = (0..65_536u32)
        .find(|&i| subred_de(&clave_bls(i)) != a)
        .expect("otra subred");
    (vec![en_a[0], en_a[1], fuera], clave_bls(en_a[0]), a)
}

/// Abre `w1` con las tres claves y `w2` sin la primera; devuelve el motor y la clave saliente.
fn motor_con_saliente() -> (MotorVotos, ClaveSecreta, Vista) {
    let (idxs, sk, a) = indices_saliente();
    let estado1 = estado_de_indices(&idxs);
    let estado2 = estado_de_indices(&idxs[1..]);
    let mut m = motor();
    m.fijar_subredes_vigiladas(&[a]);
    m.avanzar(1, bh(0x10), &estado1, SLOT).expect("w1");
    m.avanzar(2, bh(0x11), &estado2, SLOT).expect("w2");
    (m, sk, Vista)
}

#[test]
fn dts_08_la_clave_que_salio_de_la_tabla_sigue_vigilada_y_da_evidencia() {
    let (mut m, sk, vista) = motor_con_saliente();
    reiniciar_verificaciones_voto_pasado();
    let _ = m.recibir_voto_con_vista(&sobre(&sk, 0, hash_n(0xA1), hash_n(90)), &vista);
    let _ = m.recibir_voto_con_vista(&sobre(&sk, 1, hash_n(0xA2), hash_n(90)), &vista);
    assert_eq!(
        m.detector.votos_guardados(),
        2,
        "los votos viejos de la saliente entran"
    );
    assert_eq!(verificaciones_voto_pasado(), 2, "y se verifican");
    let evs = m.drenar_evidencias_peso_con_vista(&vista);
    assert_eq!(evs.len(), 1, "la saliente da evidencia");
    assert_eq!(evs[0].clave_bls, bytes(&sk));
    assert_eq!((evs[0].n, evs[0].n2), (0, 1));
}

#[test]
fn dts_09_voto_de_clave_saliente_posterior_a_su_salida_se_descarta_sin_firmas() {
    let (mut m, sk, vista) = motor_con_saliente();
    // Abre la ventana 3: así un voto de la ventana 2 es **pasado** (no el de la ventana abierta) y
    // recorre `registrar_voto_pasado`. La saliente se vio por última vez en la 1.
    let (idxs, _, _) = indices_saliente();
    let estado_sin = estado_de_indices(&idxs[1..]);
    m.avanzar(3, bh(0x12), &estado_sin, SLOT).expect("w3");
    reiniciar_verificaciones_voto_pasado();
    let _ = m.recibir_voto_con_vista(&sobre(&sk, 2, hash_n(0xB1), hash_n(90)), &vista);
    assert_eq!(
        verificaciones_voto_pasado(),
        0,
        "posterior a su salida: sin criptografía"
    );
    assert_eq!(m.detector.votos_guardados(), 0);
    // Control positivo: la ventana 1 (≤ última vista) sí entra.
    let _ = m.recibir_voto_con_vista(&sobre(&sk, 1, hash_n(0xB2), hash_n(90)), &vista);
    assert_eq!(verificaciones_voto_pasado(), 1);
    assert_eq!(m.detector.votos_guardados(), 1);
}

#[test]
fn dts_10_la_clave_saliente_se_olvida_al_pasar_el_horizonte() {
    let (idxs, sk, a) = indices_saliente();
    let estado1 = estado_de_indices(&idxs);
    let estado2 = estado_de_indices(&idxs[1..]);
    let mut m = motor();
    m.fijar_subredes_vigiladas(&[a]);
    m.avanzar(1, bh(0x10), &estado1, SLOT).expect("w1");
    m.fijar_horizonte_detector(2);
    m.avanzar(2, bh(0x11), &estado2, SLOT).expect("w2"); // saliente: última = 1
    m.avanzar(3, bh(0x12), &estado2, SLOT).expect("w3"); // 1 + 2 >= 3: sigue
    assert!(
        m.clave_aceptada_pasado(&bytes(&sk), 1),
        "aún vigilada en la ventana 3"
    );
    m.avanzar(4, bh(0x13), &estado2, SLOT).expect("w4"); // 1 + 2 < 4: se olvida
    assert!(
        !m.clave_aceptada_pasado(&bytes(&sk), 1),
        "venció el horizonte y se olvidó"
    );
    reiniciar_verificaciones_voto_pasado();
    let vista = Vista;
    let _ = m.recibir_voto_con_vista(&sobre(&sk, 1, hash_n(0xC1), hash_n(90)), &vista);
    assert_eq!(verificaciones_voto_pasado(), 0);
    assert_eq!(m.detector.votos_guardados(), 0);
}

#[test]
fn dts_11_el_apunte_de_salientes_tiene_cota_y_sale_la_mas_antigua() {
    let a = subred_de(&clave_bls(0));
    let tres = indices_en_subred(a, 3);
    assert_eq!(tres.len(), 3, "tres claves en la misma subred");
    let _k0 = clave_bls(tres[0]);
    let k1 = clave_bls(tres[1]);
    let k2 = clave_bls(tres[2]);
    // Ventanas con la tabla menguando: {k0,k1,k2} → {k0,k1} → {k0}.
    let estado1 = estado_de_indices(&tres);
    let estado2 = estado_de_indices(&tres[..2]);
    let estado3 = estado_de_indices(&tres[..1]);
    let mut m = motor();
    m.fijar_subredes_vigiladas(&[a]);
    m.avanzar(1, bh(0x10), &estado1, SLOT).expect("w1");
    m.avanzar(2, bh(0x11), &estado2, SLOT).expect("w2"); // sale k2: última = 1
    m.avanzar(3, bh(0x12), &estado3, SLOT).expect("w3"); // sale k1: última = 2; cota 1
    assert!(
        m.clave_aceptada_pasado(&bytes(&k1), 2),
        "la más reciente se conserva"
    );
    assert!(
        !m.clave_aceptada_pasado(&bytes(&k2), 1),
        "la más antigua sale al llenarse la cota"
    );
    // La que vuelve se actualiza: k2 vuelve en la ventana 4 y se conserva su apunte.
    let estado4 = estado_de_indices(&[tres[0], tres[1], tres[2]]);
    m.avanzar(4, bh(0x13), &estado4, SLOT).expect("w4");
    assert!(
        m.clave_aceptada_pasado(&bytes(&k2), 4),
        "al volver, su última ventana vista es la actual"
    );
    assert!(
        m.clave_aceptada_pasado(&bytes(&k2), 5),
        "y acepta hasta ella"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// T6 · la cadena admite la evidencia que el detector presenta.
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

fn firma_de(sk: &ClaveSecreta, n: u64, candidato: Hash) -> Firma {
    let mensaje = mensaje_voto_peso(n, &candidato, &hash_n(90), &[0u8; 32]);
    firmar(sk, DOMINIO_VOTO, &mensaje).expect("firma BLS")
}

fn operacion_de(ev: &EvidenciaVotosPesoCompleta) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: clave_ed(0x5a),
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

fn evidencia(sk: &ClaveSecreta) -> EvidenciaVotosPesoCompleta {
    EvidenciaVotosPesoCompleta {
        n: 1,
        n2: 3,
        h1: hash_n(3),
        h_t1: hash_n(90),
        raiz1: [0u8; 32],
        firma1: firma_de(sk, 1, hash_n(3)),
        clave_bls: bytes(sk),
        h2: hash_n(4),
        h_t2: hash_n(90),
        raiz2: [0u8; 32],
        firma2: firma_de(sk, 3, hash_n(4)),
    }
}

#[test]
fn dts_12_la_cadena_admite_la_evidencia_de_la_clave_saliente() {
    let sk = clave_bls(1);
    // La clave está registrada pero su sector está retirado: **no** está en la tabla vigente.
    let estado = estado_de_indices_etapa(&[1], Etapa::Retirado);
    let op = operacion_de(&evidencia(&sk));
    let (castigado, _undo, r) =
        zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_hecho_con_undo(
            &estado,
            &op,
            clave_ed(0x5a),
            &params_prueba(),
            &ParametrosEvidencia::inactiva(),
            5,
            Some(HechoVoto::Falta),
        );
    r.expect("la cadena admite la evidencia de la clave que salió de la tabla");
    assert_eq!(
        castigado.garantias[&clave_ed(0)].incidentes.len(),
        1,
        "el consenso castiga al votante"
    );
}

#[test]
fn dts_13_la_cadena_admite_la_evidencia_de_la_clave_anterior_tras_rotar() {
    let previa = clave_bls(2);
    let mut estado = estado_de_indices_etapa(&[1], Etapa::Retirado);
    estado.claves_voto_previas.insert(
        clave_ed(0),
        ClaveVotoAnterior {
            clave_bls: bytes(&previa),
            prueba_posesion: [0u8; 96],
            vencimiento: 10_000,
        },
    );
    let op = operacion_de(&evidencia(&previa));
    let (castigado, _undo, r) =
        zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_hecho_con_undo(
            &estado,
            &op,
            clave_ed(0x5a),
            &params_prueba(),
            &ParametrosEvidencia::inactiva(),
            5,
            Some(HechoVoto::Falta),
        );
    r.expect("la cadena admite la evidencia de la clave anterior tras rotar");
    assert_eq!(
        castigado.garantias[&clave_ed(0)].incidentes.len(),
        1,
        "el consenso castiga a la identidad que rotó"
    );
}
