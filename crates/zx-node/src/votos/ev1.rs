//! EV-1: reglas de cola y conservación con Cadena/firmas/códec reales.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "pruebas pequeñas de reglas con aserciones"
)]
use super::b88 as f;
use super::*;
use crate::mempool::{AdmisionEvidencia, Mempool, Politica, Rechazo, identidad_evidencia_voto};
use std::collections::{BTreeMap, HashSet};
use std::time::Instant;
use zx_consensus::transicion::{
    BloqueTransicion, HechosCabecera, ParametrosEvidencia, Punto, aplicar_fusion,
};
use zx_core::{CBID_RED_DEV, ExtensionTx, Tx, txid};

type Fixture = (
    zx_cadena::Cadena,
    Estado,
    Mempool,
    EvidenciaVotosPesoCompleta,
    Tx,
    Vec<Vec<u8>>,
    HechoVoto,
);
fn fixture() -> Fixture {
    let sk = f::bls();
    let c = f::cadena(&sk);
    let base = c.estado_virtual().expect("base real");
    let mut d = f::detector();
    let e = f::fabricar(&mut d, &sk, &c);
    let (pk, sk) = f::reportero();
    let (tx, t) = tx_evidencia_votos_peso(&e, pk, &sk, CBID_RED_DEV);
    let (a, b) = f::votos_tx(&tx);
    let h = c
        .hecho_voto_entre_ventanas(
            &a,
            &b,
            u64::try_from(base.parametros_sector.plazo_slots).expect("plazo"),
        )
        .expect("hecho real");
    assert_eq!(h, HechoVoto::Falta);
    let m = Mempool::nueva(
        f::params(),
        ParametrosEvidencia::inactiva(),
        CBID_RED_DEV,
        base.clone(),
        Politica::dev(),
    );
    (c, base, m, e, tx, t, h)
}

#[test]
fn ev1_sin_hecho_sinfalta_inadmisible_y_rebase_libera() {
    let (_, base, mut m, _, tx, t, h) = fixture();
    for (hecho, causa) in [
        (None, "ErrEvidenciaInadmisible"),
        (Some(HechoVoto::SinFalta), "ErrEvidenciaSinFalta"),
        (Some(HechoVoto::Inadmisible), "ErrEvidenciaInadmisible"),
    ] {
        let (r, cambios) = m.admitir_evidencia(
            tx.clone(),
            t.clone(),
            hecho,
            Instant::now(),
            Punto::Slot(base.slot),
        );
        assert_eq!(r, AdmisionEvidencia::Rechazada(Rechazo::VistaLocal(causa)));
        assert!(cambios.is_empty());
        assert_eq!(m.estadisticas().n, 0);
    }
    let (r, _) = m.admitir_evidencia(
        tx.clone(),
        t.clone(),
        Some(h),
        Instant::now(),
        Punto::Slot(base.slot),
    );
    assert!(matches!(r, AdmisionEvidencia::Admitida(_)));
    let id = txid(&tx, CBID_RED_DEV);
    let cambios = m.rebasear_con_hechos(
        base.clone(),
        BTreeMap::from([(id, HechoVoto::SinFalta)]),
        Instant::now(),
        Punto::Slot(base.slot),
    );
    assert_eq!(m.estadisticas().n, 0);
    assert_eq!(cambios.len(), 1);
    assert_eq!(
        cambios[0].motivo,
        Rechazo::VistaLocal("ErrEvidenciaSinFalta")
    );
    assert!(
        m.tomar_retiradas_evidencia().is_empty(),
        "resultado consumido una vez"
    );
    let (r, _) = m.admitir_evidencia(tx, t, Some(h), Instant::now(), Punto::Slot(base.slot));
    assert!(
        matches!(r, AdmisionEvidencia::Admitida(_)),
        "la retirada no confirma"
    );
    let cambios = m.rebasear_con_hechos(base, BTreeMap::new(), Instant::now(), Punto::Slot(5));
    assert_eq!(cambios.len(), 1);
    assert_eq!(
        cambios[0].motivo,
        Rechazo::VistaLocal("ErrEvidenciaInadmisible")
    );
}

fn par_misma_ventana(clave_bls: [u8; 48]) -> EvidenciaVotosPesoCompleta {
    let a = f::voto(&f::bls(), 3, 3);
    let b = f::voto(&f::bls(), 3, 4);
    EvidenciaVotosPesoCompleta {
        n: a.n,
        n2: b.n,
        h1: a.candidato,
        h_t1: a.h_t_siguiente,
        raiz1: a.raiz_estado,
        firma1: a.firma,
        clave_bls,
        h2: b.candidato,
        h_t2: b.h_t_siguiente,
        raiz2: b.raiz_estado,
        firma2: b.firma,
    }
}

#[test]
fn ev1_d8_reporteros_incidentes_y_origen_externo() {
    let (_, base, mut m, e, tx, t, h) = fixture();
    let (r, _) = m.admitir_evidencia(
        tx.clone(),
        t,
        Some(h),
        Instant::now(),
        Punto::Slot(base.slot),
    );
    assert!(matches!(r, AdmisionEvidencia::Admitida(_)));
    let sk = ed25519_zebra::SigningKey::from([0x51; 32]);
    let pk = zx_core::ClavePublica::desde_bytes(ed25519_zebra::VerificationKey::from(&sk).into());
    let (otra, tst) = tx_evidencia_votos_peso(&e, pk, &sk, CBID_RED_DEV);
    assert_ne!(txid(&tx, CBID_RED_DEV), txid(&otra, CBID_RED_DEV));
    let (r, _) = m.admitir_evidencia(otra, tst, Some(h), Instant::now(), Punto::Slot(base.slot));
    assert_eq!(
        r,
        AdmisionEvidencia::Cubierta {
            por: identidad_evidencia_voto(&tx).expect("I"),
            aplicada: false
        }
    );
    let otro_incidente = par_misma_ventana(e.clave_bls);
    let (otra, tst) = tx_evidencia_votos_peso(&otro_incidente, pk, &sk, CBID_RED_DEV);
    assert_ne!(
        identidad_evidencia_voto(&tx),
        identidad_evidencia_voto(&otra)
    );
    let (_, _, valido) =
        zx_consensus::transicion::votos::aplicar_evidencia_votos_peso_con_hecho_con_undo(
            &base,
            f::operacion(&otra),
            pk,
            &f::params(),
            &ParametrosEvidencia::inactiva(),
            base.slot + 1,
            None,
        );
    valido.expect("segundo incidente de la misma clave realmente válido");
    let peer = libp2p::PeerId::random();
    assert_eq!(
        m.admitir(
            Some(peer),
            otra,
            tst,
            Instant::now(),
            Punto::Slot(base.slot)
        ),
        Ok(crate::mempool::Admision::Duplicada)
    );
    assert_eq!(m.estadisticas().n, 1);
    assert_eq!(m.expulsar(&[txid(&tx, CBID_RED_DEV)]), 1);
    let cambios = m.tomar_retiradas_evidencia();
    assert_eq!(cambios.len(), 1);
    assert_eq!(cambios[0].motivo, Rechazo::VistaLocal("expulsion"));
}

#[test]
fn ev1_d8_entrada_externa_previa_cubre_y_su_retiro_se_devuelve() {
    let (_, base, mut m, e, tx, t, h) = fixture();
    let (pk, sk) = f::reportero();
    let (externa, testigos) =
        tx_evidencia_votos_peso(&par_misma_ventana(e.clave_bls), pk, &sk, CBID_RED_DEV);
    let por = identidad_evidencia_voto(&externa).expect("incidente externo");
    let id = txid(&externa, CBID_RED_DEV);
    assert_eq!(
        m.admitir(
            Some(libp2p::PeerId::random()),
            externa,
            testigos,
            Instant::now(),
            Punto::Slot(base.slot)
        ),
        Ok(crate::mempool::Admision::Admitida)
    );
    let (respuesta, retiradas) =
        m.admitir_evidencia(tx, t, Some(h), Instant::now(), Punto::Slot(base.slot));
    assert_eq!(
        respuesta,
        AdmisionEvidencia::Cubierta {
            por,
            aplicada: false
        }
    );
    assert!(retiradas.is_empty());
    assert_eq!(m.estadisticas().n, 1);
    assert_eq!(m.expulsar(&[id]), 1);
    let retiradas = m.tomar_retiradas_evidencia();
    assert_eq!(retiradas.len(), 1);
    assert_eq!(retiradas[0].identidad, por);
    assert!(m.tomar_retiradas_evidencia().is_empty());
}

#[test]
fn ev1_detector_conserva_acusadas_y_misma_ventana_rechazada() {
    let sk = f::bls();
    let c = f::cadena(&sk);
    let mut d = f::detector();
    let clave = sk.clave_publica().bytes();
    d.registrar(clave, f::voto(&sk, 3, 3), &c);
    d.registrar(clave, f::voto(&sk, 3, 4), &c);
    let e = d.ofrecer_en(&c, 4, 8, crate::perfil::PLAZO_SLOTS, &HashSet::new());
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].n, e[0].n2);
    assert!(!d.hay_material_revisable_en(4));
    assert!(d.hay_material_revisable_en(5));
    // Un rechazo no activa D8; el mismo par sobrevive a la sustitución de instancia.
    for _ in 0..100 {
        assert!(
            d.ofrecer_en(&c, 4, 8, crate::perfil::PLAZO_SLOTS, &HashSet::new())
                .is_empty()
        );
    }
    let segundo = d.ofrecer_en(&c, 5, 10, crate::perfil::PLAZO_SLOTS, &HashSet::new());
    assert_eq!(segundo.len(), 1);
    d.marcar_acusada(&clave);
    d.registrar(clave, f::voto(&sk, 4, 3), &c);
    d.registrar(clave, f::voto(&sk, 4, 4), &c);
    assert_eq!(d.votos_guardados(), 4, "D1 conserva válidos con D8 activo");
    assert!(
        d.ofrecer_en(&c, 6, 12, crate::perfil::PLAZO_SLOTS, &HashSet::new())
            .is_empty()
    );
    d.liberar_acusada(&clave);
    assert_eq!(
        d.ofrecer_en(&c, 7, 14, crate::perfil::PLAZO_SLOTS, &HashSet::new())
            .len(),
        1
    );
    assert!(
        d.ofrecer_en(&c, 5, 10, crate::perfil::PLAZO_SLOTS, &HashSet::new())
            .is_empty(),
        "oscilar no renueva cupo"
    );
}

#[test]
fn ev1_plazo_de_estado_inclusivo_y_siguiente_no() {
    let (mut c, base, _, e, tx, t, _) = fixture();
    let plazo = u64::try_from(base.parametros_sector.plazo_slots).expect("plazo");
    let fin = cierre_ventana(e.n2).saturating_add(plazo);
    c.admitir(f::post(70, vec![f::bh(5)], fin - 1))
        .expect("avanzar a D-1");
    let base = c.estado_virtual().expect("base D-1");
    let (a, b) = f::votos_tx(&tx);
    let h = c.hecho_voto_entre_ventanas(&a, &b, plazo);
    let mut m = Mempool::nueva(
        f::params(),
        ParametrosEvidencia::inactiva(),
        CBID_RED_DEV,
        base.clone(),
        Politica::dev(),
    );
    let (r, _) = m.admitir_evidencia(
        tx.clone(),
        t.clone(),
        h,
        Instant::now(),
        Punto::Slot(base.slot),
    );
    assert!(matches!(r, AdmisionEvidencia::Admitida(_)), "D inclusivo");
    c.admitir(f::post(71, vec![f::bh(70)], fin))
        .expect("avanzar a D");
    let base = c.estado_virtual().expect("base D");
    let mut m = Mempool::nueva(
        f::params(),
        ParametrosEvidencia::inactiva(),
        CBID_RED_DEV,
        base.clone(),
        Politica::dev(),
    );
    let (r, _) = m.admitir_evidencia(
        tx,
        t,
        c.hecho_voto_entre_ventanas(&a, &b, plazo),
        Instant::now(),
        Punto::Slot(base.slot),
    );
    assert_eq!(
        r,
        AdmisionEvidencia::Rechazada(Rechazo::VistaLocal("ErrEvidenciaVoto"))
    );
    println!("EV1 plazo: D={fin} D+1={} derivados del estado", fin + 1);
}

#[test]
fn ev1_invariancia_consenso_e_indices_intercalados() {
    let (_, base, mut m, _, tx, t, h) = fixture();
    let cb = Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave: f::reportero().0,
            importe: (f::params().subsidio_post)(0),
            slot: base.slot + 1,
        },
    };
    let cabecera = HechosCabecera::PoST {
        hash: f::bh(80),
        padre: base.terminal.expect("terminal"),
        slot: base.slot + 1,
        productor: f::reportero().0,
        peso: 1,
        prueba_valida: true,
        requisito_declarado: 0,
    };
    let antes = BloqueTransicion::nuevo(
        cabecera,
        vec![(cb.clone(), Vec::new()), (tx.clone(), t.clone())],
    )
    .con_hechos_votos(vec![HechoVoto::Inadmisible, h]);
    let esperado = aplicar_fusion(
        &base,
        &antes,
        Punto::Slot(base.slot + 1),
        &f::params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .expect("oráculo antes");
    let (r, _) = m.admitir_evidencia(tx, t, Some(h), Instant::now(), Punto::Slot(base.slot));
    assert!(matches!(r, AdmisionEvidencia::Admitida(_)));
    let seleccion = m.seleccionar(u64::MAX, 0);
    let mut cuerpo = vec![(cb, Vec::new())];
    cuerpo.extend(seleccion);
    let despues =
        BloqueTransicion::nuevo(cabecera, cuerpo).con_hechos_votos(vec![HechoVoto::Inadmisible, h]);
    let resultado = aplicar_fusion(
        &base,
        &despues,
        Punto::Slot(base.slot + 1),
        &f::params(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .expect("después de cola");
    assert_eq!(
        resultado, esperado,
        "mismos bloques, hechos y transición antes/después"
    );
    assert!(
        resultado.2.is_empty(),
        "hecho en índice 1 con coinbase intercalada"
    );
}

#[test]
#[should_panic(expected = "control rojo: sin hechos cae en admision")]
fn ev1_sintetico_sin_hechos_control_rojo() {
    let (_, base, mut m, _, tx, t, _) = fixture();
    let r = m.admitir(None, tx, t, Instant::now(), Punto::Slot(base.slot));
    assert_eq!(
        r,
        Err(Rechazo::VistaLocal("ErrEvidenciaInadmisible")),
        "causa exacta"
    );
    println!("CONTROL ROJO sin hechos: {r:?}");
    assert_eq!(
        m.estadisticas().n,
        1,
        "control rojo: sin hechos cae en admision"
    );
}
