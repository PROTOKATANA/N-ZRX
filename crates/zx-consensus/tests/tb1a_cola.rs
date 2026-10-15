//! TB-1a · la cola de tablas derivadas del consenso (R1–R5): T1 (derivar al aplicar), T7 (tope por
//! peso), T8 (la poda respeta la cola) y T9 (ventana no futura).
//!
//! Pruebas A1–A7, A9 y A10 de la orden `P-ZRX/P-004/ORDEN-TB1A.md` §4. La prueba A8 (recorte con el
//! tope como argumento) y la A11 (resumen sensible a la cola) viven como tests unitarios en
//! `transicion/votos.rs` y `crates/zx-node/src/estado_resumen.rs`, respectivamente, porque usan
//! funciones internas o el módulo del nodo.
//!
//! Los estados se construyen con sectores reales (para que `tabla_canonica` derive pesos) y las
//! firmas BLS son reales.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::similar_names,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use primitive_types::U256;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::tipos::K_TABLAS_VOTO;
use zx_consensus::transicion::votos::{
    MAX_CLAVES_TABLA, T_INST_VOTOS, W_REVEAL_SLOTS_VOTOS, apertura_ventana,
    aplicar_certificado_peso_con_undo, calendario_rearranque, cierre_ventana,
    derivar_tabla_sin_base_con_undo, tabla_canonica, tabla_derivada,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Undo, aplicar_con_undo, deshacer,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

const CBID: u32 = 0;

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Utilidades
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 0,
        w_min: U256::zero(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 300_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 600,
        f_slots: Some(600),
        subsidio_pow: |_| Amount::CERO,
        subsidio_post: |_| Amount::CERO,
    }
}

fn registro(
    p: &ParametrosSector,
    clave: ClavePublica,
    indice: u16,
    etapa: Etapa,
    alta_slot: i64,
    renovacion_slot: i64,
) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    let reg = RegistroSector {
        id,
        r2: [0; 4],
        history_size: 1,
        etapa,
        alta_slot,
        renovacion_slot,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado PoST con las claves 1..=3 (sector activo). Si `con_diferida`, añade la clave 4 con un
/// sector `Precomprometido` que se activa en el slot `50 + m_sec = 62`, de modo que entra en la
/// tabla vigente evaluada en el slot 100 pero no en la derivada evaluada en el slot 4.
fn estado_cola(con_diferida: bool) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for i in 1u8..=3 {
        let s = bls(i)?;
        est.claves_voto.insert(
            ed(i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, ed(i), 0, Etapa::Activo, 0, 10_000);
        est.sectores.insert(id, reg);
        secretas.push((i, s));
    }
    if con_diferida {
        let s = bls(4)?;
        est.claves_voto.insert(
            ed(4),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, ed(4), 0, Etapa::Precomprometido, 50, 0);
        est.sectores.insert(id, reg);
        secretas.push((4, s));
    }
    Ok((est, secretas))
}

fn clave_contrato(c: &ClaveTablaVoto) -> Clave {
    Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    }
}

fn tabla_contrato(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves.iter().map(clave_contrato).collect(),
    }
}

fn hash_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_contrato(0, claves))
}

/// TB-1c-2 · X2 · montaje autorizado para las pruebas que aplican un **primer** certificado sobre un
/// estado montado a mano: llama al gancho de producto `derivar_tabla_sin_base` con el slot del bloque
/// (no una copia), de modo que la derivada que el certificado declara esté en `Q`.
fn preparar_cola_sin_base(est: &mut Estado, slot: u64) {
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(est, slot);
    *est = nuevo;
}

/// Orden canónico (ascendente por bytes de clave BLS), como el que indexa el mapa de bits.
fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

/// Tabla con las claves y pesos dados, en orden canónico.
fn tabla_pesos(est: &Estado, pesos: &[(u8, u64)]) -> Vec<ClaveTablaVoto> {
    let mut tabla: Vec<ClaveTablaVoto> = pesos
        .iter()
        .map(|(i, w)| ClaveTablaVoto {
            clave_bls: est.claves_voto[&ed(*i)].clave_bls,
            peso: *w,
            activo: true,
            prueba: false,
            garantia: *w,
        })
        .collect();
    tabla.sort_by_key(|c| c.clave_bls);
    tabla
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

/// Añade a `est` la clave `i` con un sector activo (para que la tabla derivada cambie).
fn añadir_clave_activa(est: &mut Estado, i: u8) -> Result<(), Error> {
    let s = bls(i)?;
    est.claves_voto.insert(
        ed(i),
        ClaveVoto {
            clave_bls: s.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let p = est.parametros_sector;
    let (id, reg) = registro(&p, ed(i), 0, Etapa::Activo, 0, 10_000);
    est.sectores.insert(id, reg);
    Ok(())
}

/// Certificado compacto `0x09` con firmas BLS reales sobre A3 (raíz cero).
fn op_cert(
    est: &Estado,
    secretas: &[(u8, ClaveSecreta)],
    n: u64,
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    tabla: &[ClaveTablaVoto],
    firmantes: &[u8],
) -> Result<OperacionAlmacenamiento, Error> {
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &[0u8; 32]);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for i in firmantes {
        let bls_i = est.claves_voto[&ed(*i)].clave_bls;
        let Some(pos) = tabla.iter().position(|c| c.clave_bls == bls_i) else {
            continue;
        };
        let f = zx_votos::firmar(secreta(secretas, *i)?, DOMINIO_VOTO, &mensaje)?;
        votos.push((pos + 1, f));
    }
    let cert = zx_votos::construir_certificado(
        n,
        candidato,
        h_t_siguiente,
        [0u8; 32],
        &tabla_contrato(n, tabla),
        &votos,
    )?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

/// Aplica un bloque PoST vacío (dispara `liquidar_ventanas_voto` y la poda) y devuelve estado y undo.
fn aplica_post(est: &Estado, slot: u64) -> Result<(Estado, Undo), Error> {
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash(1),
            padre: hash(2),
            slot,
            productor: ed(1),
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        Vec::new(),
    );
    Ok(aplicar_con_undo(
        est,
        &bloque,
        &params(),
        CBID,
        &ParametrosEvidencia::inactiva(),
    )?)
}

fn slot_liquidacion(n: u64) -> u64 {
    cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1
}

/// LCG determinista para la prueba de los 500 estados aleatorios.
struct Azar(u64);

impl Azar {
    fn nuevo(semilla: u64) -> Self {
        Self(semilla)
    }

    fn siguiente(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn rango(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.siguiente() % n
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A1 · arranque: la cola lleva la vigente y la derivada
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn cola_arranque_lleva_vigente_y_derivada() -> Result<(), Error> {
    let (mut est, secretas) = estado_cola(true)?;
    let slot = 100i64;
    preparar_cola_sin_base(&mut est, u64::try_from(slot)?);
    let tabla = canoniza(tabla_canonica(&est, slot));
    assert_eq!(tabla.len(), 4, "la vigente incluye a la identidad diferida");
    let h = hash_payload(&tabla);
    let antes = est.cola_tablas_voto.clone();
    assert_eq!(antes, vec![(50, h)], "el gancho encoló la derivada");
    let op = op_cert(&est, &secretas, 50, [0x11; 32], h, &tabla, &[1, 2, 3])?;
    let (nuevo, _undo, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
    r?;

    // v1.4 · TB4-R6: la aplicación **no** empuja pares a `Q`; el único dueño es el gancho por
    // ventana. La vigente es el contenido de la huella declarada.
    assert_eq!(
        nuevo.cola_tablas_voto, antes,
        "la aplicación no toca la cola"
    );
    assert_eq!(nuevo.finalidad_votos_h_t, Some(h));
    assert!(nuevo.tablas_voto_contenido.contains_key(&h));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A2 · la cola crece en orden y se recorta a K
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn cola_crece_en_orden_y_se_recorta_a_k() -> Result<(), Error> {
    let (est, _secretas) = estado_cola(false)?;
    // v1.4 · TB4-R2: el contenido repetido no crece la cola; actualiza su ventana en el sitio.
    let (e1, _u1) = derivar_tabla_sin_base_con_undo(&est, 100); // k = 50
    let (e2, _u2) = derivar_tabla_sin_base_con_undo(&e1, 102); // k = 51, misma tabla
    assert_eq!(e2.cola_tablas_voto.len(), 1, "la repetida no crece");
    assert_eq!(
        e2.cola_tablas_voto[0].0, 51,
        "actualiza la ventana en el sitio"
    );

    // Con contenido cambiante (una identidad nueva por ventana), crece en orden y se recorta a K.
    let mut estado = est;
    for j in 0..K_TABLAS_VOTO + 2 {
        añadir_clave_activa(&mut estado, u8::try_from(j + 4)?)?;
        let slot = u64::try_from(j + 1)?.saturating_mul(T_INST_VOTOS);
        let (nuevo, _u) = derivar_tabla_sin_base_con_undo(&estado, slot);
        estado = nuevo;
    }
    assert_eq!(
        estado.cola_tablas_voto.len(),
        K_TABLAS_VOTO,
        "la cola se recorta a K"
    );
    let ventanas: Vec<u64> = estado.cola_tablas_voto.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        ventanas,
        (3..=u64::try_from(K_TABLAS_VOTO).unwrap_or(0) + 2).collect::<Vec<u64>>(),
        "quedan las últimas ventanas, en orden"
    );
    for (_, h) in &estado.cola_tablas_voto {
        assert!(
            estado.tablas_voto_contenido.contains_key(h),
            "el contenido de {h:?} está guardado"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A3 · el rearranque renueva la cola
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn cola_rearranque_se_renueva() -> Result<(), Error> {
    let (mut est, secretas) = estado_cola(false)?;
    let p = est.parametros_sector;
    let m = 0u64;
    let cal = calendario_rearranque(&p, m).ok_or("calendario")?;
    let n = cal.inicio(0) / T_INST_VOTOS;
    let slot = i64::try_from(cal.inicio(0))?;

    let t_base = tabla_pesos(&est, &[(1, 1), (2, 1), (3, 1)]);
    let h_base = hash_payload(&t_base);
    est.finalidad_votos_n = m;
    est.finalidad_votos = Some(hash(9));
    est.finalidad_votos_h_t = Some(h_base);
    est.tablas_voto_contenido.insert(h_base, t_base.clone());
    est.tablas_voto.insert(m, t_base);
    // Instantánea del ciclo 0 con la tabla del ciclo.
    let t_ciclo = tabla_pesos(&est, &[(1, 1), (2, 1), (3, 1)]);
    let h_ciclo = hash_payload(&t_ciclo);
    est.tabla_ciclo_rearranque.insert(0, h_ciclo);
    est.tablas_voto_contenido.insert(h_ciclo, t_ciclo.clone());
    // Cola con una entrada vieja que ya no es fresca.
    est.cola_tablas_voto.push((0, [0xAA; 32]));

    // v1.4 · TB4-R1/R6: el gancho por ventana deposita la tabla fresca; la aplicación ya no renueva
    // la cola por su cuenta (no la vacía ni la empuja).
    let (con_q, _u) = derivar_tabla_sin_base_con_undo(&est, u64::try_from(slot)?);
    assert_eq!(
        con_q.cola_tablas_voto.len(),
        2,
        "la fresca se añade a la vieja"
    );
    let h_fresca = con_q.cola_tablas_voto.last().ok_or("sin fresca")?.1;
    let op = op_cert(
        &con_q,
        &secretas,
        n,
        [0x22; 32],
        h_fresca,
        &t_ciclo,
        &[1, 2],
    )?;
    let (nuevo, _undo, r) = aplicar_certificado_peso_con_undo(&con_q, &op, slot);
    r?;
    assert_eq!(
        nuevo.finalidad_votos_n, n,
        "la base pasa a la ventana del rearranque"
    );
    assert_eq!(
        nuevo.finalidad_votos_h_t,
        Some(h_fresca),
        "la tabla vigente es la fresca de la cola"
    );
    assert!(
        !nuevo.tabla_ciclo_rearranque.contains_key(&0),
        "la instantánea del ciclo se borra al avanzar la base"
    );
    // La entrada vieja sigue en `Q` (la aplicación no la toca), pero ya no es admisible.
    let cert_viejo = op_cert(
        &con_q,
        &secretas,
        n,
        [0x23; 32],
        [0xAA; 32],
        &t_ciclo,
        &[1, 2],
    )?;
    let (_e, _u, r) = aplicar_certificado_peso_con_undo(&con_q, &cert_viejo, slot);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            zx_votos::peso::MotivoPeso::TablaNoDerivada
        )),
        "la entrada vieja no es admisible"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A4 · la repetición no toca la cola
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn cola_repeticion_no_cambia() -> Result<(), Error> {
    let (mut est, secretas) = estado_cola(true)?;
    let slot = 100i64;
    preparar_cola_sin_base(&mut est, u64::try_from(slot)?);
    let tabla = canoniza(tabla_canonica(&est, slot));
    let h = hash_payload(&tabla);
    let op = op_cert(&est, &secretas, 50, [0x11; 32], h, &tabla, &[1, 2, 3])?;
    let (aplicado, _undo, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
    r?;
    let antes = aplicado.cola_tablas_voto.clone();
    let (repetido, _undo2, r2) = aplicar_certificado_peso_con_undo(&aplicado, &op, slot);
    r2?;
    assert_eq!(repetido, aplicado, "la repetición es idempotente");
    assert_eq!(repetido.cola_tablas_voto, antes, "la cola no cambia");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A5 · deshacer exacto, cola incluida
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn cola_deshacer_exacto() -> Result<(), Error> {
    let (mut est, secretas) = estado_cola(true)?;
    let slot = 100i64;
    preparar_cola_sin_base(&mut est, u64::try_from(slot)?);
    let tabla = canoniza(tabla_canonica(&est, slot));
    let h = hash_payload(&tabla);
    let op = op_cert(&est, &secretas, 50, [0x11; 32], h, &tabla, &[1, 2, 3])?;
    let (nuevo, undo, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
    r?;
    assert!(!nuevo.cola_tablas_voto.is_empty(), "la cola creció");
    assert_eq!(
        deshacer(&nuevo, &undo),
        est,
        "el undo devuelve el estado de antes, cola incluida"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A6 · la poda conserva los contenidos de la cola
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn poda_conserva_contenidos_de_la_cola() -> Result<(), Error> {
    let (mut est, secretas) = estado_cola(true)?;
    let slot = 100i64;
    preparar_cola_sin_base(&mut est, u64::try_from(slot)?);
    let tabla = canoniza(tabla_canonica(&est, slot));
    let h = hash_payload(&tabla);
    let op = op_cert(&est, &secretas, 50, [0x11; 32], h, &tabla, &[1, 2, 3])?;
    let (nuevo, _undo, r) = aplicar_certificado_peso_con_undo(&est, &op, slot);
    r?;
    // La huella derivada no está en ninguna otra lista: solo la protege la cola.
    let derivada = nuevo
        .cola_tablas_voto
        .last()
        .map(|(_, h)| *h)
        .ok_or("cola vacía")?;
    // T5 · la identidad diferida está activa tanto en el slot 100 como en el 102, así que la
    // derivada puede coincidir con la vigente; lo que importa es que su contenido siga guardado.

    let (fin, _undo2) = aplica_post(&nuevo, slot_liquidacion(50))?;
    assert_eq!(
        fin.liquidacion_voto_hasta,
        Some(50),
        "la ventana 50 se liquidó"
    );
    for (_, huella) in &fin.cola_tablas_voto {
        assert!(
            fin.tablas_voto_contenido.contains_key(huella),
            "la huella {huella:?} conserva su contenido tras liquidar y podar"
        );
    }
    assert!(fin.tablas_voto_contenido.contains_key(&derivada));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A7 · con el tope real, la derivada es la canónica (500 estados aleatorios)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tabla_derivada_sin_recorte_es_la_canonica() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let k = 100u64;
    let slot = i64::try_from(k.saturating_mul(T_INST_VOTOS))?;
    for semilla in 0..500u64 {
        let mut azar = Azar::nuevo(semilla.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1));
        let n_claves = azar.rango(9);
        let mut est = Estado::inicial();
        est.parametros_sector = p;
        est.fase = Fase::PoST;
        for i in 0..n_claves {
            let ed_bytes: [u8; 32] = std::array::from_fn(|j| {
                if j == 0 {
                    u8::try_from(i).unwrap_or(0)
                } else {
                    0
                }
            });
            let clave = ClavePublica::desde_bytes(ed_bytes);
            let clave_bls: [u8; 48] =
                std::array::from_fn(|j| u8::try_from(azar.rango(256)).unwrap_or(0) ^ (j as u8));
            est.claves_voto.insert(
                clave,
                ClaveVoto {
                    clave_bls,
                    prueba_posesion: [0u8; 96],
                },
            );
            let n_sectores = azar.rango(4);
            for indice in 0..n_sectores {
                let (id, reg) = registro(
                    &p,
                    clave,
                    u16::try_from(indice).unwrap_or(u16::MAX),
                    Etapa::Activo,
                    0,
                    10_000,
                );
                est.sectores.insert(id, reg);
            }
        }
        let esperado = canoniza(tabla_canonica(&est, slot));
        assert_eq!(
            tabla_derivada(&est, k),
            esperado,
            "semilla {semilla}: sin recorte, la derivada es la canónica"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A9 · con el tope real, 65 537 identidades dejan 65 536
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn tabla_derivada_tope_real() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let total = MAX_CLAVES_TABLA + 1;
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    for i in 0..total {
        let mut ed_bytes = [0u8; 32];
        ed_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let clave = ClavePublica::desde_bytes(ed_bytes);
        let mut clave_bls = [0u8; 48];
        clave_bls[..8].copy_from_slice(&(i as u64).to_le_bytes());
        est.claves_voto.insert(
            clave,
            ClaveVoto {
                clave_bls,
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, clave, 0, Etapa::Activo, 0, 10_000);
        est.sectores.insert(id, reg);
    }
    let tabla = tabla_derivada(&est, 100);
    assert_eq!(
        tabla.len(),
        MAX_CLAVES_TABLA,
        "con 65 537 identidades de peso 1 la tabla tiene 65 536"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A10 · la ventana futura se rechaza; en la apertura se acepta
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn certificado_de_ventana_futura_se_rechaza() -> Result<(), Error> {
    let (mut est, secretas) = estado_cola(false)?;
    let n = 2u64;
    let apertura = apertura_ventana(n);
    preparar_cola_sin_base(&mut est, apertura);
    let tabla = canoniza(tabla_canonica(&est, i64::try_from(apertura)?));
    let h = hash_payload(&tabla);
    let op = op_cert(&est, &secretas, n, [0x33; 32], h, &tabla, &[1, 2])?;

    let (rechazado, _undo, r) = aplicar_certificado_peso_con_undo(
        &est,
        &op,
        i64::try_from(apertura.checked_sub(1).ok_or("apertura cero")?)?,
    );
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoVentanaFutura),
        "una unidad por debajo de la apertura se rechaza"
    );
    assert_eq!(rechazado, est, "el estado no cambia");

    let (aceptado, _undo2, r2) =
        aplicar_certificado_peso_con_undo(&est, &op, i64::try_from(apertura)?);
    r2?;
    assert_eq!(aceptado.finalidad_votos_n, n, "en la apertura se acepta");
    Ok(())
}

/// TB-1c · C9: el tope de claves de la tabla derivada y el del certificado valen lo mismo.
#[test]
fn max_claves_tabla_igual_que_certificado() {
    assert_eq!(
        MAX_CLAVES_TABLA,
        zx_core::MAX_CLAVES_CERTIFICADO_VOTOS,
        "MAX_CLAVES_TABLA y MAX_CLAVES_CERTIFICADO_VOTOS coinciden"
    );
}

/// TB-1c · P3: con `K − 1` entradas en la cola la huella vigente sigue dentro y el certificado se
/// acepta; con `K` entradas y la vigente desalojada, T3 lo rechaza.
#[test]
fn k_menos_uno_no_rechaza_y_k_si() -> Result<(), Error> {
    let (base, secretas) = estado_cola(false)?;
    let slot = 100i64;
    let tabla = canoniza(tabla_canonica(&base, slot));
    let h = hash_payload(&tabla);

    let mut con_base = base;
    con_base.finalidad_votos_n = 1;
    con_base.finalidad_votos = Some(hash(9));
    con_base.finalidad_votos_h_t = Some(h);
    con_base.tablas_voto_contenido.insert(h, tabla.clone());
    con_base.cola_tablas_voto.push((1, h));

    // K − 1 entradas: la vigente sigue en la cola.
    let mut k_menos = con_base.clone();
    while k_menos.cola_tablas_voto.len() < K_TABLAS_VOTO - 1 {
        k_menos.cola_tablas_voto.push((1, h));
    }
    let op = op_cert(&k_menos, &secretas, 2, [0x44; 32], h, &tabla, &[1, 2])?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&k_menos, &op, slot);
    r?;

    // K entradas con la vigente desalojada: T3 rechaza.
    let mut k = con_base;
    k.cola_tablas_voto.retain(|(_, x)| *x != h);
    while k.cola_tablas_voto.len() < K_TABLAS_VOTO {
        k.cola_tablas_voto.push((1, [0xAA; 32]));
    }
    let op = op_cert(&k, &secretas, 2, [0x44; 32], h, &tabla, &[1, 2])?;
    let (_, _, r) = aplicar_certificado_peso_con_undo(&k, &op, slot);
    assert_eq!(
        r,
        Err(ErrorTransicion::ErrCertificadoPesoMotivo(
            zx_votos::peso::MotivoPeso::TablaNoDerivada
        ))
    );
    Ok(())
}
