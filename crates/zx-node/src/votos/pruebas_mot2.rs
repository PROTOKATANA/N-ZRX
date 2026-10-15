//! MOT-2 · B-83/B-84 · pruebas del motor de votos.
//!
//! - **B-83 · coeficientes impredecibles** en la verificación por lotes de agregados: se derivan de
//!   un secreto del azar del sistema, del resumen del lote y de un contador (C1), un coeficiente
//!   cero se descarta (C3) y sin azar del sistema no hay lote (se verifica de uno en uno, C2).
//! - **B-84 · una sola comprobación de firma** por voto de subred: el voto que `recibir_voto_subred`
//!   ya verificó no vuelve a verificarse en el camino del voto de la ventana abierta (C5).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseno"
)]

use std::collections::{HashMap, HashSet};

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo;
use zx_consensus::transicion::{Estado, Fase, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, Digest};
use zx_votos::agregacion::{
    Agregado, DOMINIO_SORTEO, GeneradorEscalares, MensajeVoto, VotoRed, subred,
};
use zx_votos::{
    ClaveSecreta, DOMINIO_VOTO, Firma, Hash, Tabla, agregar_firmas, firmar, hash_tabla,
    mensaje_voto_peso,
};

use super::{
    ConfigMotorVotos, GeneradorAgregados, MotorVotos, RAIZ_ESTADO_CERO, RecepcionVoto,
    RecepcionVotoSubred, VistaPermisiva, VotoPeso, lotes_agregados, reiniciar_lotes_agregados,
    reiniciar_verificaciones_voto_subred, serializar_voto_peso, verificaciones_voto_subred,
};

const DEN: i64 = 1_401_600_000;
const SLOT: i64 = 100;

type Error = Box<dyn std::error::Error>;

// ── utilidades de estado (mismas que `pruebas_agregacion`, para no tocar su módulo) ───────────

fn bls(indice: u8) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

fn hash(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
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

/// Estado PoST con `(clave, nº de sectores, activo de la garantía)` por clave.
fn estado_sectores(claves: &[(u8, u16, i64)]) -> Result<Estado, Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
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
    }
    let (con_cola, _u) = derivar_tabla_sin_base_con_undo(&est, u64::try_from(SLOT)?);
    Ok(con_cola)
}

fn motor_de(indices: &[u8], emitir: bool, subredes: u16) -> Result<MotorVotos, Error> {
    let claves = indices
        .iter()
        .map(|i| bls(*i))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MotorVotos::nuevo_con_subredes(
        ConfigMotorVotos {
            perfil: crate::perfil::parametros_votos_dev(),
            claves,
            emitir_votos: emitir,
        },
        subredes,
    ))
}

/// Igual que `motor_de` pero sin azar del sistema (camino de uno en uno).
fn motor_sin_azar_de(indices: &[u8], emitir: bool, subredes: u16) -> Result<MotorVotos, Error> {
    let claves = indices
        .iter()
        .map(|i| bls(*i))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MotorVotos::nuevo_sin_azar_para_test(
        ConfigMotorVotos {
            perfil: crate::perfil::parametros_votos_dev(),
            claves,
            emitir_votos: emitir,
        },
        subredes,
    ))
}

fn inst_h_t(m: &MotorVotos) -> Hash {
    m.instancia.as_ref().expect("instancia").h_t_siguiente
}

fn inst_cand(m: &MotorVotos) -> Hash {
    m.instancia.as_ref().expect("instancia").candidato
}

fn voto_con(sk: &ClaveSecreta, n: u64, c: Hash, h_t: Hash, raiz: Hash) -> Result<VotoPeso, Error> {
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje_voto_peso(n, &c, &h_t, &raiz))?;
    Ok(VotoPeso {
        n,
        candidato: c,
        h_t_siguiente: h_t,
        raiz_estado: raiz,
        clave: sk.clave_publica().bytes(),
        firma,
    })
}

fn voto_red_con(
    sk: &ClaveSecreta,
    n: u64,
    c: Hash,
    h_t: Hash,
    raiz: Hash,
) -> Result<VotoRed, Error> {
    let firma = firmar(sk, DOMINIO_VOTO, &mensaje_voto_peso(n, &c, &h_t, &raiz))?;
    Ok(VotoRed {
        n,
        candidato: c,
        h_t_siguiente: h_t,
        raiz_estado: raiz,
        clave: sk.clave_publica(),
        firma,
    })
}

fn reparto_de(tabla: &Tabla, s: u16) -> Result<Vec<Vec<usize>>, Error> {
    let mut subredes: Vec<Vec<usize>> = vec![Vec::new(); usize::from(s)];
    for (i, clave) in tabla.claves.iter().enumerate() {
        let sub = subred(clave.clave.as_slice(), s)?;
        if let Some(lista) = subredes.get_mut(usize::from(sub)) {
            lista.push(i);
        }
    }
    for lista in &mut subredes {
        lista.sort_by(|a, b| {
            let ca = tabla.claves.get(*a).map(|c| c.clave.as_slice());
            let cb = tabla.claves.get(*b).map(|c| c.clave.as_slice());
            ca.cmp(&cb).then_with(|| a.cmp(b))
        });
    }
    Ok(subredes)
}

fn secretas_por_pk(indices: &[u8]) -> Result<HashMap<Vec<u8>, ClaveSecreta>, Error> {
    let mut mapa = HashMap::new();
    for i in indices {
        let sk = bls(*i)?;
        mapa.insert(sk.clave_publica().bytes().to_vec(), sk);
    }
    Ok(mapa)
}

/// Agregado válido de la subred `sub` que cubre los índices globales `cubiertos`.
fn agregado_con(
    tabla: &Tabla,
    s: u16,
    secretas: &HashMap<Vec<u8>, ClaveSecreta>,
    sub: u16,
    cubiertos: &[usize],
    indice_agregadora: usize,
    msg: MensajeVoto,
) -> Result<Agregado, Error> {
    let reparto = reparto_de(tabla, s)?;
    let indices = reparto.get(usize::from(sub)).ok_or("subred sin claves")?;
    let n_s = indices.len();
    let mut mapa_local = vec![0u8; n_s.div_ceil(8)];
    let mut firmas: Vec<Firma> = Vec::new();
    for &global in cubiertos {
        let pos = indices
            .iter()
            .position(|g| *g == global)
            .ok_or("global fuera")?;
        if let Some(byte) = mapa_local.get_mut(pos >> 3) {
            *byte |= 1 << (pos & 7);
        }
        let pk = tabla
            .claves
            .get(global)
            .ok_or("global fuera")?
            .clave
            .clone();
        let sk = secretas.get(&pk).ok_or("sin secreta")?;
        firmas.push(firmar(sk, DOMINIO_VOTO, &msg.mensaje())?);
    }
    let referencias: Vec<&Firma> = firmas.iter().collect();
    let firma_agregada = agregar_firmas(&referencias)?;
    let global_agregadora = *indices.get(indice_agregadora).ok_or("agregadora fuera")?;
    let pk_ag = tabla
        .claves
        .get(global_agregadora)
        .ok_or("agregadora fuera")?
        .clave
        .clone();
    let sk_ag = secretas.get(&pk_ag).ok_or("sin secreta")?;
    let firma_sorteo = firmar(sk_ag, DOMINIO_SORTEO, &msg.n.to_be_bytes())?;
    Ok(Agregado {
        n: msg.n,
        candidato: msg.candidato,
        h_t_siguiente: msg.h_t_siguiente,
        raiz_estado: msg.raiz_estado,
        firma_agregada,
        huella_tabla: hash_tabla(tabla),
        subred: sub,
        indice_agregadora: u16::try_from(indice_agregadora)?,
        mapa_local,
        firma_sorteo,
    })
}

fn msg_de(m: &MotorVotos, raiz: Hash) -> MensajeVoto {
    MensajeVoto {
        n: m.instancia.as_ref().expect("instancia").n,
        candidato: inst_cand(m),
        h_t_siguiente: inst_h_t(m),
        raiz_estado: raiz,
    }
}

/// Generador congruencial lineal determinista para las pruebas pseudoaleatorias.
struct Azar(u64);

impl Azar {
    fn nuevo(semilla: u64) -> Self {
        Self(semilla | 1)
    }

    fn siguiente(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn hasta(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.siguiente() % n }
    }
}

/// Agregado pseudoaleatorio: válido o con un defecto (firma, tabla, mensaje, índice).
fn agregado_aleatorio(
    rng: &mut Azar,
    tabla: &Tabla,
    secretas: &HashMap<Vec<u8>, ClaveSecreta>,
    msg: MensajeVoto,
) -> Result<Agregado, Error> {
    let indices = reparto_de(tabla, 1)?
        .into_iter()
        .next()
        .ok_or("sin subred 0")?;
    let mut cubiertos: Vec<usize> = indices
        .iter()
        .copied()
        .filter(|_| rng.hasta(2) == 0)
        .collect();
    if cubiertos.is_empty() {
        cubiertos.push(*indices.first().ok_or("sin claves")?);
    }
    let mut ag = agregado_con(tabla, 1, secretas, 0, &cubiertos, 0, msg)?;
    match rng.hasta(6) {
        0 => {}
        1 => {
            let sk = bls(1)?;
            ag.firma_agregada = agregar_firmas(&[&firmar(&sk, DOMINIO_VOTO, b"no vale")?])?;
        }
        2 => ag.huella_tabla = [0xAB; 32],
        3 => ag.n = ag.n.saturating_add(1),
        4 => {
            ag.indice_agregadora = u16::try_from(indices.len()).unwrap_or(u16::MAX);
        }
        _ => {}
    }
    Ok(ag)
}

// ── coef_01..coef_03 · la derivación de los coeficientes ─────────────────────────────────────

#[test]
fn coef_01_dos_secretos_dan_coeficientes_distintos() {
    // Mismo lote (`resumen_lote`) y mismo contador (ambos a cero): solo cambia el secreto.
    let resumen = [0x11u8; 32];
    let mut a = GeneradorAgregados::con_secreto_para_test([0x01; 32]);
    let mut b = GeneradorAgregados::con_secreto_para_test([0x02; 32]);
    a.fijar_resumen(resumen);
    b.fijar_resumen(resumen);
    for i in 0..16 {
        assert_ne!(a.escalar(), b.escalar(), "coeficiente {i}");
    }
}

#[test]
fn coef_02_cambiar_un_byte_del_lote_cambia_los_coeficientes() -> Result<(), Error> {
    let estado = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;

    let mut motor = motor_de(&[], false, 1)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let tabla = motor.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3])?;
    let msg = msg_de(&motor, RAIZ_ESTADO_CERO);
    let ag = agregado_con(&tabla, 1, &secretas, 0, &[0, 1], 0, msg)?;
    let mut ag2 = ag.clone();
    ag2.mapa_local[0] ^= 0x01;

    let resumen = |a: &Agregado| *zx_core::sha3_256_publico(&a.serializar()).as_bytes();
    let r1 = resumen(&ag);
    let r2 = resumen(&ag2);
    assert_ne!(r1, r2, "un byte distinto cambia el resumen del lote");

    // Mismo secreto y mismo contador; solo cambia el resumen del lote.
    let mut g1 = GeneradorAgregados::con_secreto_para_test([0x42; 32]);
    let mut g2 = GeneradorAgregados::con_secreto_para_test([0x42; 32]);
    g1.fijar_resumen(r1);
    g2.fijar_resumen(r2);
    for i in 0..16 {
        assert_ne!(g1.escalar(), g2.escalar(), "coeficiente {i}");
    }
    Ok(())
}

#[test]
fn coef_03_no_se_repiten_entre_lotes_ni_dentro_de_un_lote() {
    let mut g = GeneradorAgregados::con_secreto_para_test([0x33; 32]);
    let mut vistos: HashSet<[u8; 16]> = HashSet::new();
    let mut total = 0usize;
    for lote in 0..64u8 {
        g.fijar_resumen([lote; 32]);
        for _ in 0..16 {
            assert!(vistos.insert(g.escalar()), "coeficiente repetido");
            total += 1;
        }
    }
    assert_eq!(vistos.len(), total);
    assert_eq!(total, 64 * 16);
}

// ── coef_04..coef_06 · el motor: uno en uno, sin fuga y veredictos iguales ───────────────────

#[test]
fn coef_04_sin_azar_del_sistema_se_verifica_de_uno_en_uno() -> Result<(), Error> {
    let estado = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut con_azar = motor_de(&[], false, 1)?;
    let mut sin_azar = motor_sin_azar_de(&[], false, 1)?;
    let _ = con_azar.avanzar(1, hash(0x11), &estado, SLOT)?;
    let _ = sin_azar.avanzar(1, hash(0x11), &estado, SLOT)?;
    assert!(!con_azar.azar_del_sistema_no_disponible());
    assert!(sin_azar.azar_del_sistema_no_disponible());

    let tabla = con_azar.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3])?;
    let msg = msg_de(&con_azar, RAIZ_ESTADO_CERO);
    let valido = agregado_con(&tabla, 1, &secretas, 0, &[0, 1], 0, msg)?;
    let mut invalido = valido.clone();
    invalido.firma_agregada = agregar_firmas(&[&firmar(&bls(1)?, DOMINIO_VOTO, b"no vale")?])?;
    let lote = vec![valido.clone(), invalido, valido];

    reiniciar_lotes_agregados();
    let con_lotes = con_azar.recibir_agregados(&lote)?;
    assert!(lotes_agregados() >= 1, "con azar se verifica por lotes");

    reiniciar_lotes_agregados();
    let uno_a_uno = sin_azar.recibir_agregados(&lote)?;
    assert_eq!(lotes_agregados(), 0, "sin azar no se verifica por lotes");

    assert_eq!(con_lotes, uno_a_uno, "mismos veredictos");
    Ok(())
}

#[test]
fn coef_05_el_secreto_no_sale_por_debug_ni_por_el_registro() -> Result<(), Error> {
    let estado = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[1], true, 1)?;
    let secreto = motor
        .generador_agregados
        .as_ref()
        .expect("azar del sistema")
        .secreto;
    let hex_secreto = super::hex(&secreto);
    assert!(!hex_secreto.is_empty());

    let paso = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let dbg_motor = format!("{motor:?}");
    assert!(
        !dbg_motor.contains(&hex_secreto),
        "el secreto sale por Debug"
    );
    assert!(
        !dbg_motor.contains("generador_agregados"),
        "Debug del motor no debe exponer el generador"
    );
    let eventos = format!("{:?}", paso.eventos);
    assert!(
        !eventos.contains(&hex_secreto),
        "el secreto sale por los eventos del registro"
    );
    for evento in &paso.eventos {
        assert!(!format!("{evento:?}").contains(&hex_secreto));
    }
    Ok(())
}

#[test]
fn coef_06_veredictos_del_lote_iguales_que_uno_a_uno() -> Result<(), Error> {
    let estado = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN), (4, 1, DEN)])?;
    let mut por_lotes = motor_de(&[], false, 1)?;
    let mut uno_a_uno = motor_sin_azar_de(&[], false, 1)?;
    let _ = por_lotes.avanzar(1, hash(0x11), &estado, SLOT)?;
    let _ = uno_a_uno.avanzar(1, hash(0x11), &estado, SLOT)?;
    let tabla = por_lotes.tabla_actual().expect("tabla").clone();
    let secretas = secretas_por_pk(&[1, 2, 3, 4])?;

    let mut rng = Azar::nuevo(0x00C0_FFEE_1234);
    for iteracion in 0..300 {
        let msg = msg_de(&por_lotes, RAIZ_ESTADO_CERO);
        let n = rng.hasta(5);
        let mut lote = Vec::with_capacity(usize::try_from(n)?);
        for _ in 0..n {
            lote.push(agregado_aleatorio(&mut rng, &tabla, &secretas, msg)?);
        }
        let lote_res = por_lotes.recibir_agregados(&lote)?;
        let mut uno_res = Vec::with_capacity(lote.len());
        for ag in &lote {
            uno_res.push(uno_a_uno.recibir_agregados(std::slice::from_ref(ag))?[0].clone());
        }
        assert_eq!(lote_res, uno_res, "iteracion {iteracion}");
    }
    Ok(())
}

// ── sub_01..sub_02 · una sola comprobación de firma por voto de subred ───────────────────────

#[test]
fn sub_01_voto_de_subred_verifica_la_firma_una_sola_vez() -> Result<(), Error> {
    let estado = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let mut motor = motor_de(&[], true, 4)?;
    let _ = motor.avanzar(1, hash(0x11), &estado, SLOT)?;
    let sk2 = bls(2)?;
    let vr = voto_red_con(
        &sk2,
        1,
        inst_cand(&motor),
        inst_h_t(&motor),
        RAIZ_ESTADO_CERO,
    )?;
    let sub = subred(&vr.clave.bytes(), 4)?;

    reiniciar_verificaciones_voto_subred();
    let r = motor.recibir_voto_subred(sub, &vr.serializar(), &VistaPermisiva);
    assert!(matches!(r, RecepcionVotoSubred::Aceptado { .. }));
    let (en_subred, en_actual) = verificaciones_voto_subred();
    assert_eq!(en_subred, 1, "recibir_voto_subred verifica una vez");
    assert_eq!(en_actual, 0, "recibir_voto_actual no repite la firma");
    assert_eq!(en_subred + en_actual, 1, "una sola comprobación por voto");
    Ok(())
}

/// Traduce el veredicto del sobre antiguo al del voto de subred, para compararlos.
fn esperado_del_sobre(r: RecepcionVoto) -> RecepcionVotoSubred {
    match r {
        RecepcionVoto::Aceptado { clave, plazas } => {
            RecepcionVotoSubred::Aceptado { clave, plazas }
        }
        RecepcionVoto::Rechazado {
            motivo: "firma_falsa",
        } => RecepcionVotoSubred::Penalizar {
            motivo: "firma_falsa",
        },
        RecepcionVoto::Rechazado { motivo } => RecepcionVotoSubred::Ignorar { motivo },
    }
}

/// Instantánea del efecto en la ventana: `(votos aceptados, pares registrados, agregados)`.
fn efecto(m: &MotorVotos) -> (usize, usize, usize) {
    let inst = m.instancia.as_ref().expect("instancia");
    (
        inst.votos_peso.len(),
        inst.pares_peso.len(),
        inst.agregados.len(),
    )
}

#[test]
fn sub_02_voto_de_subred_mismos_resultados_que_antes() -> Result<(), Error> {
    let estado = estado_sectores(&[(1, 1, DEN), (2, 1, DEN), (3, 1, DEN)])?;
    let sk2 = bls(2)?;

    // 1 · válido.
    {
        let mut sub = motor_de(&[], true, 4)?;
        let mut sobre = motor_de(&[], true, 4)?;
        let _ = sub.avanzar(1, hash(0x11), &estado, SLOT)?;
        let _ = sobre.avanzar(1, hash(0x11), &estado, SLOT)?;
        let c = inst_cand(&sub);
        let h_t = inst_h_t(&sub);
        let vr = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let v = voto_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let s = sub.recibir_voto_subred(
            subred(&vr.clave.bytes(), 4)?,
            &vr.serializar(),
            &VistaPermisiva,
        );
        let o = sobre.recibir_voto(&serializar_voto_peso(&v));
        assert_eq!(s, esperado_del_sobre(o));
        assert_eq!(efecto(&sub), efecto(&sobre));
    }

    // 2 · firma falsa.
    {
        let mut sub = motor_de(&[], true, 4)?;
        let mut sobre = motor_de(&[], true, 4)?;
        let _ = sub.avanzar(1, hash(0x11), &estado, SLOT)?;
        let _ = sobre.avanzar(1, hash(0x11), &estado, SLOT)?;
        let c = inst_cand(&sub);
        let h_t = inst_h_t(&sub);
        let firma_mala = firmar(&sk2, DOMINIO_VOTO, b"no es el voto")?;
        let mut vr = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        vr.firma = firma_mala;
        let mut v = voto_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        v.firma = firma_mala;
        let s = sub.recibir_voto_subred(
            subred(&vr.clave.bytes(), 4)?,
            &vr.serializar(),
            &VistaPermisiva,
        );
        let o = sobre.recibir_voto(&serializar_voto_peso(&v));
        assert_eq!(s, esperado_del_sobre(o));
        assert_eq!(efecto(&sub), efecto(&sobre));
    }

    // 3 · otra subred: no tiene camino en el sobre antiguo, se conserva la penalización de hoy.
    {
        let mut sub = motor_de(&[], true, 4)?;
        let _ = sub.avanzar(1, hash(0x11), &estado, SLOT)?;
        let vr = voto_red_con(&sk2, 1, inst_cand(&sub), inst_h_t(&sub), RAIZ_ESTADO_CERO)?;
        let sub_real = subred(&vr.clave.bytes(), 4)?;
        let s = sub.recibir_voto_subred((sub_real + 1) % 4, &vr.serializar(), &VistaPermisiva);
        assert_eq!(s, RecepcionVotoSubred::Penalizar { motivo: "subred" });
    }

    // 4 · sin peso: clave activa con peso 0 (el caso 0 no entra en la tabla por sí solo).
    {
        let mut sub = motor_de(&[], true, 4)?;
        let mut sobre = motor_de(&[], true, 4)?;
        let _ = sub.avanzar(1, hash(0x11), &estado, SLOT)?;
        let _ = sobre.avanzar(1, hash(0x11), &estado, SLOT)?;
        let pk = sk2.clave_publica().bytes().to_vec();
        for m in [&mut sub, &mut sobre] {
            let inst = m.instancia.as_mut().expect("instancia");
            let pos = *inst.indice.get(&pk).expect("clave en la tabla");
            inst.tabla.claves[pos].peso = 0;
            inst.tabla.claves[pos].activo = true;
        }
        let c = inst_cand(&sub);
        let h_t = inst_h_t(&sub);
        let vr = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let v = voto_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let s = sub.recibir_voto_subred(
            subred(&vr.clave.bytes(), 4)?,
            &vr.serializar(),
            &VistaPermisiva,
        );
        let o = sobre.recibir_voto(&serializar_voto_peso(&v));
        assert_eq!(s, esperado_del_sobre(o));
        assert!(matches!(
            s,
            RecepcionVotoSubred::Ignorar { motivo: "sin_peso" }
        ));
        assert_eq!(efecto(&sub), efecto(&sobre));
    }

    // 5 · repetido: idempotente en los dos caminos.
    {
        let mut sub = motor_de(&[], true, 4)?;
        let mut sobre = motor_de(&[], true, 4)?;
        let _ = sub.avanzar(1, hash(0x11), &estado, SLOT)?;
        let _ = sobre.avanzar(1, hash(0x11), &estado, SLOT)?;
        let c = inst_cand(&sub);
        let h_t = inst_h_t(&sub);
        let vr = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let v = voto_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let s1 = sub.recibir_voto_subred(
            subred(&vr.clave.bytes(), 4)?,
            &vr.serializar(),
            &VistaPermisiva,
        );
        let s2 = sub.recibir_voto_subred(
            subred(&vr.clave.bytes(), 4)?,
            &vr.serializar(),
            &VistaPermisiva,
        );
        let o1 = sobre.recibir_voto(&serializar_voto_peso(&v));
        let o2 = sobre.recibir_voto(&serializar_voto_peso(&v));
        assert_eq!(s1, esperado_del_sobre(o1));
        assert_eq!(s2, esperado_del_sobre(o2));
        assert_eq!(efecto(&sub), efecto(&sobre));
    }

    // 6 · conflicto: dos candidatos distintos con la misma clave en la misma ventana.
    {
        let mut sub = motor_de(&[], true, 4)?;
        let mut sobre = motor_de(&[], true, 4)?;
        let _ = sub.avanzar(1, hash(0x11), &estado, SLOT)?;
        let _ = sobre.avanzar(1, hash(0x11), &estado, SLOT)?;
        let c = inst_cand(&sub);
        let h_t = inst_h_t(&sub);
        let otro: Hash = [0x22u8; 32];
        let v1 = voto_red_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let v2 = voto_red_con(&sk2, 1, otro, h_t, RAIZ_ESTADO_CERO)?;
        let p1 = voto_con(&sk2, 1, c, h_t, RAIZ_ESTADO_CERO)?;
        let p2 = voto_con(&sk2, 1, otro, h_t, RAIZ_ESTADO_CERO)?;
        let s1 = sub.recibir_voto_subred(
            subred(&v1.clave.bytes(), 4)?,
            &v1.serializar(),
            &VistaPermisiva,
        );
        let s2 = sub.recibir_voto_subred(
            subred(&v2.clave.bytes(), 4)?,
            &v2.serializar(),
            &VistaPermisiva,
        );
        let o1 = sobre.recibir_voto(&serializar_voto_peso(&p1));
        let o2 = sobre.recibir_voto(&serializar_voto_peso(&p2));
        assert_eq!(s1, esperado_del_sobre(o1));
        assert_eq!(s2, esperado_del_sobre(o2));
        assert!(matches!(
            s2,
            RecepcionVotoSubred::Ignorar {
                motivo: "otro_candidato"
            }
        ));
        assert_eq!(efecto(&sub), efecto(&sobre));
    }
    Ok(())
}
