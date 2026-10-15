//! RK-2 · la clave de voto anterior sigue atribuida a su identidad durante la retención.
//!
//! Adapta los cinco casos K1–K5 de `deepseek/RK1/cambios.patch` (escritos antes de M9-b2) a la
//! base `7374157e` (sin la `K` de `tablas_voto`) con el resultado **invertido** en K2–K5, y añade
//! los casos 2–7 de la orden `ORDEN-RK2.md`:
//!
//! - K1–K5: castigo, falta entre ventanas, ausencia, clave liberada y control.
//! - 2: peor caso del modelo en el borde del rearranque (rotación tras la instantánea, voto doble en
//!   la última ventana de la fase activa, evidencia en el último slot admisible).
//! - 4: segunda rotación dentro/fuera del plazo y reutilización de la BLS anterior por otra
//!   identidad dentro/fuera del plazo.
//! - 5: voto propio `0x08` firmado con la clave anterior viva.
//! - 6: deshacer exacto de un bloque que rota (`0x03`) y de uno que borra una anterior vencida.
//! - 7: la función V1 da 1 024 con dev y sus dos términos (1 024 y 961).
//!
//! Todo va por el camino real de la transición; la rotación usa la operación `0x03` con prueba de
//! posesión y las firmas BLS son reales.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    missing_docs,
    reason = "prueba de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use primitive_types::U256;
use zx_consensus::sectores::{
    ClaveVoto, Etapa, MotivoSector, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::{
    T_INST_VOTOS, W_REVEAL_SLOTS_VOTOS, aplicar_evidencia_votos_peso_con_hecho_con_undo,
    aplicar_voto_propio_con_undo, calendario_rearranque, cierre_ventana, retencion_clave_voto,
    retencion_clave_voto_por_tabla, tomar_instantaneas_rearranque_con_undo,
};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechoVoto, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Undo, aplicar_almacenamiento_con_undo, aplicar_con_undo, deshacer,
};
use zx_core::{
    Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, ExtensionTx, OperacionAlmacenamiento,
    Tx, VotoPesoEvidencia,
};
use zx_votos::{ClaveSecreta, DOMINIO_VOTO};

const CBID: u32 = 0;
const DEN: i64 = 1_401_600_000;

type Error = Box<dyn std::error::Error>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Constructores y utilidades
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn bls(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

/// Clave **nueva** para rotar la de `indice` (distinta de [`bls`] y determinista).
fn bls_rot(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[1] = 0x5A;
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

/// `f = 1/2`, `plazo_slots = 300`, como en `at1b.rs`; el castigo real es
/// `C = min(V, techo(f·V))`.
fn param_evidencia() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 2,
        plazo_slots: 300,
        m_margen_slots: 0,
        cbid: 0,
        evp: true,
    }
}

fn registro(p: &ParametrosSector, clave: ClavePublica, indice: u16) -> (SectorId, RegistroSector) {
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
        renovacion_slot: 1_000_000,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado PoST con `(clave, nº de sectores, activo de la garantía)` por clave. La clave BLS de cada
/// identidad se registra directamente (primera alta, sin anterior); la rotación va por el `0x03`.
fn estado_base(claves: &[(u8, u16, i64)]) -> Result<(Estado, Vec<(u8, ClaveSecreta)>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    let mut secretas = Vec::new();
    for (i, n_sectores, activo) in claves {
        let s = bls(*i)?;
        est.claves_voto.insert(
            ed(*i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for k in 0..*n_sectores {
            let (id, reg) = registro(&p, ed(*i), k);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(*activo)?;
        est.garantias.insert(ed(*i), g);
        secretas.push((*i, s));
    }
    Ok((est, secretas))
}

fn secreta(secretas: &[(u8, ClaveSecreta)], i: u8) -> Result<&ClaveSecreta, Error> {
    Ok(&secretas
        .iter()
        .find(|(j, _)| *j == i)
        .ok_or("sin secreta")?
        .1)
}

/// Tabla de peso 1 por clave con la BLS **vigente** en `est`.
fn tabla_unos(est: &Estado, indices: &[u8]) -> Vec<ClaveTablaVoto> {
    indices
        .iter()
        .map(|i| ClaveTablaVoto {
            clave_bls: est.claves_voto[&ed(*i)].clave_bls,
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 1,
        })
        .collect()
}

fn op_clave_voto(clave: ClavePublica, sk: &ClaveSecreta) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::ClaveVoto {
        clave,
        clave_bls: sk.clave_publica().bytes(),
        prueba_posesion: zx_votos::probar_posesion(sk).bytes(),
    }
}

/// Aplica la rotación real `0x03` (prueba de posesión incluida) en `slot`.
fn rotar_en(estado: &Estado, indice: u8, nueva: &ClaveSecreta, slot: i64) -> Result<Estado, Error> {
    let p = ParametrosSector::dev();
    let op = op_clave_voto(ed(indice), nueva);
    let (rotado, _undo, motivo) = aplicar_almacenamiento_con_undo(estado, &op, slot, &p);
    assert_eq!(motivo, MotivoSector::Ok, "la rotación 0x03 debe aceptarse");
    Ok(rotado)
}

fn rotar(estado: &Estado, indice: u8, nueva: &ClaveSecreta) -> Result<Estado, Error> {
    rotar_en(estado, indice, nueva, 0)
}

/// Evidencia de dos votos por peso (`0x0B`) con las dos firmas A3 reales.
fn evidencia_peso(
    secreta: &ClaveSecreta,
    n1: u64,
    c1: [u8; 32],
    t1: [u8; 32],
    r1: [u8; 32],
    n2: u64,
    c2: [u8; 32],
    t2: [u8; 32],
    r2: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let f1 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n1, &c1, &t1, &r1),
    )?;
    let f2 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n2, &c2, &t2, &r2),
    )?;
    Ok(OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: pk.bytes(),
        voto1: VotoPesoEvidencia {
            n: n1,
            candidato: c1,
            h_t_siguiente: t1,
            raiz_estado: r1,
            firma: f1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n: n2,
            candidato: c2,
            h_t_siguiente: t2,
            raiz_estado: r2,
            firma: f2.bytes(),
        },
    })
}

/// Dos votos en conflicto de la **misma** ventana (el caso K1/K2).
fn evidencia_misma_ventana(
    secretas: &[(u8, ClaveSecreta)],
    n: u64,
) -> Result<OperacionAlmacenamiento, Error> {
    evidencia_peso(
        secreta(secretas, 1)?,
        n,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        n,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )
}

/// Dos votos de ventanas distintas (el caso K3).
fn evidencia_entre_ventanas(
    secretas: &[(u8, ClaveSecreta)],
) -> Result<OperacionAlmacenamiento, Error> {
    evidencia_peso(
        secreta(secretas, 1)?,
        3,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        4,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )
}

/// Aplica un bloque PoST vacío (dispara liquidación y poda) y devuelve `(estado, undo)`.
fn aplica_post_con_undo(est: &Estado, slot: u64) -> Result<(Estado, Undo), Error> {
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

/// Slot del primer bloque que liquida la ventana `n`.
fn slot_liquidacion(n: u64) -> u64 {
    cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1
}

fn deuda(est: &Estado, i: u8) -> i128 {
    est.deuda_ausencia.get(&ed(i)).copied().unwrap_or(0)
}

fn aplica_evidencia_en(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    hecho: Option<HechoVoto>,
    slot: u64,
) -> Result<Estado, Error> {
    let (post, undo, r) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        estado,
        op,
        ed(9),
        &params(),
        &param_evidencia(),
        slot,
        hecho,
    );
    r?;
    assert_eq!(deshacer(&post, &undo), *estado, "undo exacto");
    Ok(post)
}

fn aplica_evidencia(
    estado: &Estado,
    op: &OperacionAlmacenamiento,
    hecho: Option<HechoVoto>,
) -> Result<Estado, Error> {
    aplica_evidencia_en(estado, op, hecho, 10)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// K1 · Castigo, control (no cambia)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn k1_castigo_control() -> Result<(), Error> {
    let (base, secretas) = estado_base(&[(1, 1, 50)])?;
    let op = evidencia_misma_ventana(&secretas, 3)?;
    let post = aplica_evidencia(&base, &op, None)?;

    assert_eq!(
        post.garantias[&ed(1)].incidentes.len(),
        1,
        "incidente único"
    );
    assert_eq!(post.quemado - base.quemado, 72, "quema 72 brek");
    assert_eq!(post.activo_de(&ed(1)), Amount::nuevo(0)?, "activo a 0");
    let premio: i64 = post.garantias[&ed(9)]
        .creditos
        .iter()
        .map(|p| p.importe.brek())
        .sum();
    assert_eq!(premio, 23, "premio pendiente al incluidor");
    assert_eq!(
        post.garantias[&ed(1)].congelado.brek(),
        95,
        "congela el remanente"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// K2 · Castigo tras rotar (resultado invertido: ahora castiga)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn k2_castigo_tras_rotar() -> Result<(), Error> {
    let (base, secretas) = estado_base(&[(1, 1, 50)])?;
    let op = evidencia_misma_ventana(&secretas, 3)?;
    let k2 = bls_rot(1)?;
    let rotado = rotar(&base, 1, &k2)?;
    assert_eq!(
        rotado.claves_voto[&ed(1)].clave_bls,
        k2.clave_publica().bytes()
    );
    assert_eq!(
        rotado.claves_voto_previas[&ed(1)].clave_bls,
        secretas[0].1.clave_publica().bytes(),
        "la anterior queda viva"
    );

    let post = aplica_evidencia(&rotado, &op, None)?;
    assert_eq!(
        post.garantias[&ed(1)].incidentes.len(),
        1,
        "castiga a la identidad que firmó"
    );
    assert_eq!(post.quemado - rotado.quemado, 72, "quema 72");
    assert_eq!(post.activo_de(&ed(1)), Amount::nuevo(0)?, "activo a 0");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// K3 · Falta entre ventanas tras rotar (invertido: castiga)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn k3_falta_entre_ventanas_tras_rotar() -> Result<(), Error> {
    let (base, secretas) = estado_base(&[(1, 1, 50)])?;
    let op = evidencia_entre_ventanas(&secretas)?;

    let control = aplica_evidencia(&base, &op, Some(HechoVoto::Falta))?;
    assert_eq!(control.garantias[&ed(1)].incidentes.len(), 1);
    assert_eq!(control.quemado - base.quemado, 72);

    let k2 = bls_rot(1)?;
    let rotado = rotar(&base, 1, &k2)?;
    let post = aplica_evidencia(&rotado, &op, Some(HechoVoto::Falta))?;
    assert_eq!(
        post.garantias[&ed(1)].incidentes.len(),
        1,
        "la falta también castiga tras rotar"
    );
    assert_eq!(post.quemado - rotado.quemado, 72);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// K4 · Ausencia (invertido: la rotada paga)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn k4_ausencia_tras_rotar() -> Result<(), Error> {
    let n = 2u64;
    let (base, _secretas) = estado_base(&[(1, 0, DEN), (2, 0, DEN)])?;
    let mut preparado = base;
    preparado
        .tablas_voto
        .insert(n, tabla_unos(&preparado, &[1, 2]));
    preparado.liquidacion_voto_hasta = Some(n - 1);

    let control = aplica_post_con_undo(&preparado, slot_liquidacion(n))?.0;
    assert_eq!(control.quemado, 14, "control: las dos pagan 7");
    assert_eq!(control.activo_de(&ed(1)), Amount::nuevo(DEN - 7)?);
    assert_eq!(control.activo_de(&ed(2)), Amount::nuevo(DEN - 7)?);

    let k2 = bls_rot(1)?;
    let rotado = rotar(&preparado, 1, &k2)?;
    let con_rotacion = aplica_post_con_undo(&rotado, slot_liquidacion(n))?.0;
    assert_eq!(
        con_rotacion.quemado, 14,
        "tras rotar, la tabla vieja sigue atribuyendo la ausencia a la 1"
    );
    assert_eq!(con_rotacion.activo_de(&ed(1)), Amount::nuevo(DEN - 7)?);
    assert_eq!(con_rotacion.activo_de(&ed(2)), Amount::nuevo(DEN - 7)?);
    assert_eq!(deuda(&con_rotacion, 1), 0);
    assert_eq!(deuda(&con_rotacion, 2), 0);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// K5 · La clave liberada, bajo otra identidad (invertido: se rechaza y castiga a la 1)
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn k5_clave_liberada_bajo_otra_identidad() -> Result<(), Error> {
    let (base, secretas) = estado_base(&[(1, 1, 50), (2, 1, 50)])?;
    let op = evidencia_misma_ventana(&secretas, 3)?;
    let k1 = bls(1)?;
    let k2 = bls_rot(1)?;
    let rotado = rotar(&base, 1, &k2)?;

    // Otra identidad intenta registrar la BLS antigua: la anterior sigue viva, se rechaza.
    let p = ParametrosSector::dev();
    let op_registro = op_clave_voto(ed(2), &k1);
    let (registrado, undo_reg, m) = aplicar_almacenamiento_con_undo(&rotado, &op_registro, 0, &p);
    assert_eq!(
        m,
        MotivoSector::ErrClaveVotoDuplicada,
        "la BLS anterior viva no es de nadie más"
    );
    assert_eq!(
        deshacer(&registrado, &undo_reg),
        rotado,
        "no cambia el estado"
    );

    // La evidencia sigue castigando a la identidad 1 (dueña de la anterior).
    let post = aplica_evidencia(&rotado, &op, None)?;
    assert_eq!(post.garantias[&ed(1)].incidentes.len(), 1, "castiga a la 1");
    assert!(
        post.garantias[&ed(2)].incidentes.is_empty(),
        "la 2 queda sin incidente"
    );
    assert_eq!(post.quemado - rotado.quemado, 72);
    assert_eq!(post.activo_de(&ed(2)), Amount::nuevo(50)?);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 2 · Peor caso del modelo en el borde del rearranque
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn peor_caso_borde_rearranque() -> Result<(), Error> {
    // Base con finalidad por votos en la ventana m = 0.
    let (mut base, secretas) = estado_base(&[(1, 1, 50)])?;
    base.finalidad_votos_n = 0;
    base.finalidad_votos = Some(hash(7));

    let p = ParametrosSector::dev();
    let cal = calendario_rearranque(&p, 0).ok_or("sin calendario de rearranque")?;

    // La instantánea del ciclo 0 se toma justo después de `ref(0)` (peor caso del modelo).
    let s_c = cal.referencia(0) + 1;
    let (con_instantanea, _u) = tomar_instantaneas_rearranque_con_undo(&base, s_c);
    assert!(
        !con_instantanea.tabla_ciclo_rearranque.is_empty(),
        "instantánea tomada"
    );
    let h = con_instantanea.tabla_ciclo_rearranque[&0];
    assert!(
        con_instantanea.tablas_voto_contenido[&h]
            .iter()
            .any(|c| c.clave_bls == secretas[0].1.clave_publica().bytes()),
        "la instantánea congela la clave vieja"
    );

    // Rotación justo después de la instantánea.
    let k2 = bls_rot(1)?;
    let s_r = s_c + 1;
    let rotado = rotar_en(
        &con_instantanea,
        1,
        &k2,
        i64::try_from(s_r).unwrap_or(i64::MAX),
    )?;

    // Última ventana de la fase activa y su último slot de evidencia admisible.
    let ultima_apertura = (cal.inicio(0) + cal.a - 1) / T_INST_VOTOS * T_INST_VOTOS;
    let n = ultima_apertura / T_INST_VOTOS;
    let e_max = cierre_ventana(n) + 300; // `plazo_slots` dev

    // Voto doble en la última ventana de la fase activa, firmado con la clave anterior. La
    // aplicación va **antes** del control de borde: con la retención rebajada en 1 (control rojo)
    // el índice ya no atribuye la clave y la evidencia se rechaza aquí.
    let op = evidencia_peso(
        secreta(&secretas, 1)?,
        n,
        [0x01; 32],
        [0xAA; 32],
        [0x10; 32],
        n,
        [0x02; 32],
        [0xBB; 32],
        [0x20; 32],
    )?;
    let post = aplica_evidencia_en(&rotado, &op, None, e_max)?;
    assert_eq!(
        post.garantias[&ed(1)].incidentes.len(),
        1,
        "castiga en el último slot admisible"
    );
    assert_eq!(post.quemado - rotado.quemado, 72);
    assert_eq!(
        e_max,
        s_r + retencion_clave_voto(&p),
        "la retención alcanza exactamente el último slot admisible"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 4 · Segunda rotación y reutilización dentro/fuera del plazo
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn segunda_rotacion_y_reenvio_dentro_y_fuera_del_plazo() -> Result<(), Error> {
    let p = ParametrosSector::dev();
    let retencion = retencion_clave_voto(&p);
    let vivo = i64::try_from(retencion).unwrap_or(i64::MAX);

    // Segunda rotación de la misma identidad.
    let (base, _s) = estado_base(&[(1, 0, DEN)])?;
    let k2 = bls_rot(1)?;
    let k3 = bls(2)?;
    let rot1 = rotar(&base, 1, &k2)?;
    let venc = rot1.claves_voto_previas[&ed(1)].vencimiento;
    assert_eq!(venc, retencion);

    let op3 = op_clave_voto(ed(1), &k3);
    let (rech, undo, m) = aplicar_almacenamiento_con_undo(&rot1, &op3, vivo, &p);
    assert_eq!(m, MotivoSector::ErrClaveVotoRotacionViva);
    assert_eq!(deshacer(&rech, &undo), rot1, "el rechazo no toca el estado");

    let (acept, undo2, m2) = aplicar_almacenamiento_con_undo(&rot1, &op3, vivo + 1, &p);
    assert_eq!(m2, MotivoSector::Ok, "en vencimiento + 1 se acepta");
    assert_eq!(
        deshacer(&acept, &undo2),
        rot1,
        "la rotación también se deshace exacta"
    );
    assert_eq!(
        acept.claves_voto[&ed(1)].clave_bls,
        k3.clave_publica().bytes()
    );
    assert_eq!(
        acept.claves_voto_previas[&ed(1)].clave_bls,
        k2.clave_publica().bytes(),
        "la anterior pasa a ser la k2"
    );
    assert_ne!(
        acept.claves_voto_previas[&ed(1)].clave_bls,
        bls(1)?.clave_publica().bytes(),
        "la k1 vencida se retira"
    );

    // La misma BLS anterior, registrada por otra identidad.
    let (base2, _s2) = estado_base(&[(1, 0, DEN), (2, 0, DEN)])?;
    let rot = rotar(&base2, 1, &k2)?;
    let k1 = bls(1)?;
    let op_otra = op_clave_voto(ed(2), &k1);
    let (_r, _u, m3) = aplicar_almacenamiento_con_undo(&rot, &op_otra, vivo, &p);
    assert_eq!(m3, MotivoSector::ErrClaveVotoDuplicada, "dentro del plazo");
    let (_r2, _u2, m4) = aplicar_almacenamiento_con_undo(&rot, &op_otra, vivo + 1, &p);
    assert_eq!(m4, MotivoSector::Ok, "después del plazo se acepta");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 5 · Voto propio con la clave anterior viva
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn voto_propio_con_anterior_viva() -> Result<(), Error> {
    let (base, _secretas) = estado_base(&[(1, 0, DEN)])?;
    let k1 = bls(1)?;
    let k2 = bls_rot(1)?;
    let rotado = rotar(&base, 1, &k2)?;

    let n = 1u64;
    let slot = 3i64; // `[apertura(1) = 2, cierre(1) + W = 164]`, con la anterior viva
    let candidato = [0x11; 32];
    let h_t = [0x22; 32];
    let firma = zx_votos::firmar(
        &k1,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]),
    )?;
    let op = OperacionAlmacenamiento::VotoPropio {
        clave: ed(1),
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave_bls: k1.clave_publica().bytes(),
        firma: firma.bytes(),
    };
    let (post, undo, r) = aplicar_voto_propio_con_undo(&rotado, &op, slot);
    r?;
    assert!(
        post.votantes_voto[&n].contains(&ed(1)),
        "el voto con la anterior se admite"
    );
    assert_eq!(deshacer(&post, &undo), rotado, "undo exacto");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 6 · Deshacer exacto: bloque que rota y bloque que borra una anterior vencida
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Tx v6 `0x03` firmada por la clave Ed25519 de la identidad.
fn tx_clave_voto(
    clave: ClavePublica,
    bls_sk: &ClaveSecreta,
    ed_sk: &ed25519_zebra::SigningKey,
) -> (Tx, Vec<Vec<u8>>) {
    let tx = Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: OperacionAlmacenamiento::ClaveVoto {
                clave,
                clave_bls: bls_sk.clave_publica().bytes(),
                prueba_posesion: zx_votos::probar_posesion(bls_sk).bytes(),
            },
        },
    };
    let firma: [u8; 64] = ed_sk
        .sign(&zx_core::mensaje_almacenamiento(&tx, CBID))
        .into();
    (tx, vec![firma.to_vec()])
}

fn bloque_post(
    slot: u64,
    productor: ClavePublica,
    txs: Vec<(Tx, Vec<Vec<u8>>)>,
) -> BloqueTransicion {
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash(1),
            padre: hash(2),
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        txs,
    )
}

#[test]
fn undo_exacto_de_bloque_que_rota_y_de_purga() -> Result<(), Error> {
    // (a) Bloque PoST que rota la clave con una tx `0x03` real y firmada.
    let sk_ed = ed25519_zebra::SigningKey::from([0x33u8; 32]);
    let ed_key = ClavePublica::desde_bytes(ed25519_zebra::VerificationKey::from(&sk_ed).into());
    let p = ParametrosSector::dev();
    let k1 = bls(1)?;
    let k2 = bls_rot(1)?;
    let mut base = Estado::inicial();
    base.parametros_sector = p;
    base.fase = Fase::PoST;
    base.claves_voto.insert(
        ed_key,
        ClaveVoto {
            clave_bls: k1.clave_publica().bytes(),
            prueba_posesion: zx_votos::probar_posesion(&k1).bytes(),
        },
    );
    let (id, reg) = registro(&p, ed_key, 0);
    base.sectores.insert(id, reg);
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(50)?;
    base.garantias.insert(ed_key, g);

    let tx = tx_clave_voto(ed_key, &k2, &sk_ed);
    let bloque = bloque_post(1, ed_key, vec![tx]);
    let (nuevo, undo) = aplicar_con_undo(
        &base,
        &bloque,
        &params(),
        CBID,
        &ParametrosEvidencia::inactiva(),
    )?;
    assert_eq!(
        nuevo.claves_voto[&ed_key].clave_bls,
        k2.clave_publica().bytes(),
        "el bloque rotó la clave"
    );
    assert_eq!(
        nuevo.claves_voto_previas[&ed_key].clave_bls,
        k1.clave_publica().bytes()
    );
    assert_eq!(
        deshacer(&nuevo, &undo),
        base,
        "undo exacto del bloque que rota"
    );

    // (b) Bloque PoST vacío en `vencimiento + 1`: borra la anterior vencida.
    let (base2, _s) = estado_base(&[(1, 0, DEN)])?;
    let rotado = rotar(&base2, 1, &k2)?;
    let venc = rotado.claves_voto_previas[&ed(1)].vencimiento;
    assert!(!rotado.claves_voto_previas.is_empty());
    let (purgado, undo2) = aplica_post_con_undo(&rotado, venc + 1)?;
    assert!(
        purgado.claves_voto_previas.is_empty(),
        "la anterior vencida se borra"
    );
    assert!(
        purgado.vencimientos_clave_voto.is_empty(),
        "el índice queda limpio"
    );
    assert_eq!(deshacer(&purgado, &undo2), rotado, "undo exacto de la poda");

    // En el slot `vencimiento` la anterior sigue viva: no se borra.
    let (vivo, undo3) = aplica_post_con_undo(&rotado, venc)?;
    assert!(
        !vivo.claves_voto_previas.is_empty(),
        "aún viva en el slot de vencimiento"
    );
    assert_eq!(deshacer(&vivo, &undo3), rotado);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 7 · La función de V1
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn funcion_de_retencion() {
    let p = ParametrosSector::dev();
    assert_eq!(retencion_clave_voto(&p), 1_024, "max(r_votos_slots, tabla)");
    assert_eq!(
        retencion_clave_voto_por_tabla(&p),
        961,
        "(CADUCIDAD + 1)·T_inst + plazo − 1"
    );
    assert_eq!(p.r_votos_slots, 1_024, "primer término del máximo");
}
