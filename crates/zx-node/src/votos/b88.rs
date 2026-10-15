//! B88-C: caracterización de la supresión local, sin cambiar el producto.
//! Detector, DAG/Cadena, firmas y mempool reales; ninguna vista simulada.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "pruebas de caracterización con fixtures pequeños y aserciones"
)]

use std::time::Instant;

use primitive_types::U256;
use zx_cadena::{BloqueCadena, Cadena};
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{
    T_INST_VOTOS, aplicar_evidencia_votos_peso_con_hecho_con_undo, cierre_ventana,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Punto,
};
use zx_core::{Amount, BlockHash, CBID_RED_DEV, Digest, ExtensionTx, Tx, txid};
use zx_dag::IdentidadTicket;
use zx_dag::ghostdag::IdentidadGhostdag;
use zx_votos::{ClaveSecreta, DOMINIO_VOTO, firmar, mensaje_voto_peso};

use super::{DetectorFalta, EvidenciaVotosPesoCompleta, VotoDetector, tx_evidencia_votos_peso};
use crate::mempool::{Mempool, Politica, Rechazo};

pub(crate) fn bls() -> ClaveSecreta {
    ClaveSecreta::generar(&[0xb8; 32]).expect("clave BLS de prueba")
}

pub(crate) fn hash(id: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.to_be_bytes());
    bytes
}

pub(crate) fn bh(id: u64) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes(hash(id)))
}

pub(crate) fn acusado() -> zx_core::ClavePublica {
    zx_core::ClavePublica::desde_bytes([1; 32])
}

pub(crate) fn reportero() -> (zx_core::ClavePublica, ed25519_zebra::SigningKey) {
    let sk = ed25519_zebra::SigningKey::from([0x5a; 32]);
    let pk = ed25519_zebra::VerificationKey::from(&sk);
    (zx_core::ClavePublica::desde_bytes(pk.into()), sk)
}

pub(crate) fn params() -> ParametrosTransicion {
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
        f_slots: Some(crate::perfil::F_SLOTS),
        subsidio_pow: |_| Amount::nuevo(10).expect("importe"),
        subsidio_post: |_| Amount::nuevo(10_000).expect("importe"),
    }
}

pub(crate) fn post(id: u64, padres: Vec<BlockHash>, slot: u64) -> BloqueCadena {
    let productor = reportero().0;
    let identidad = IdentidadGhostdag::Billete(IdentidadTicket::vigente(
        productor,
        0,
        id + 1,
        hash(id),
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

// Fixture de detector_pruebas: P=2, X=3 y Z=4 hermanos, W=5 fusiona X y Z.
// Los veredictos de cabecera se suministran a la API real, igual que allí.
pub(crate) fn cadena(sk: &ClaveSecreta) -> Cadena {
    let mut estado = Estado::inicial();
    estado.parametros_sector = ParametrosSector::dev();
    estado.claves_voto.insert(
        acusado(),
        ClaveVoto {
            clave_bls: sk.clave_publica().bytes(),
            prueba_posesion: [0; 96],
        },
    );
    let mut garantia = Garantia::nueva();
    garantia.activo =
        Amount::nuevo(1000 - estado.parametros_sector.q_sec).expect("garantía libre del acusado");
    estado.garantias.insert(acusado(), garantia);
    let id = SectorId {
        clave: acusado(),
        sector_index: 0,
        version: 0,
    };
    estado.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0; 4],
            history_size: 1,
            etapa: Etapa::Activo,
            alta_slot: 0,
            renovacion_slot: 0,
            retiro_slot: -1,
            fianza: estado.parametros_sector.q_sec,
            aud_apertura: -1,
            aud_contestada: -1,
        },
    );
    let mut c = Cadena::nueva_con_evidencia_e_inicial(
        params(),
        1,
        CBID_RED_DEV,
        15,
        ParametrosEvidencia::inactiva(),
        estado,
    );
    c.admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::Genesis { hash: bh(0) },
        Vec::new(),
    )))
    .expect("génesis");
    c.admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: bh(1),
            padre: bh(0),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        Vec::new(),
    )))
    .expect("terminal");
    c.admitir(post(2, vec![bh(1)], 2)).expect("P");
    c.admitir(post(3, vec![bh(2)], 3)).expect("X");
    c.admitir(post(4, vec![bh(2)], 4)).expect("Z");
    c.admitir(post(5, vec![bh(3), bh(4)], 5))
        .expect("W fusiona X y Z");
    c
}

pub(crate) fn detector() -> DetectorFalta {
    DetectorFalta::nuevo(
        crate::perfil::parametros_votos_dev().t_inst,
        crate::perfil::PLAZO_SLOTS,
    )
}

pub(crate) fn voto(sk: &ClaveSecreta, n: u64, candidato: u64) -> VotoDetector {
    let candidato = hash(candidato);
    let h_t_siguiente = hash(90);
    let raiz_estado = [0; 32];
    let mensaje = mensaje_voto_peso(n, &candidato, &h_t_siguiente, &raiz_estado);
    VotoDetector {
        n,
        candidato,
        h_t_siguiente,
        raiz_estado,
        firma: firmar(sk, DOMINIO_VOTO, &mensaje).expect("firma real A3"),
    }
}

pub(crate) fn registrar_par(d: &mut DetectorFalta, sk: &ClaveSecreta, c: &Cadena, n: u64) {
    let clave = sk.clave_publica().bytes();
    d.registrar(clave, voto(sk, n, 3), c);
    d.registrar(clave, voto(sk, n + 2, 4), c);
}

pub(crate) fn fabricar(
    d: &mut DetectorFalta,
    sk: &ClaveSecreta,
    c: &Cadena,
) -> EvidenciaVotosPesoCompleta {
    registrar_par(d, sk, c, 1);
    let mut evidencias = d.drenar(c);
    assert_eq!(evidencias.len(), 1);
    evidencias.pop().expect("una evidencia entre ventanas")
}

#[test]
fn b88_01_tras_fabricar_la_evidencia_no_se_guardan_mas_votos_de_la_clave() {
    let sk = bls();
    let c = cadena(&sk);
    let mut d = detector();
    let _evidencia = fabricar(&mut d, &sk, &c);
    assert_eq!(d.votos_guardados(), 2);
    registrar_par(&mut d, &sk, &c, 2);
    assert_eq!(d.votos_guardados(), 4, "se conservan tras fabricar");
}

#[test]
fn b88_02_un_segundo_doble_voto_dentro_del_horizonte_no_da_evidencia() {
    let sk = bls();
    let c = cadena(&sk);
    let mut d = detector();
    let _evidencia = fabricar(&mut d, &sk, &c);
    registrar_par(&mut d, &sk, &c, 2);
    assert!(d.drenar(&c).is_empty());
    // Control positivo: el segundo par sí es castigable sin la marca previa.
    let mut limpio = detector();
    registrar_par(&mut limpio, &sk, &c, 2);
    assert_eq!(limpio.drenar(&c).len(), 1);
}

#[test]
fn b88_03_la_marca_se_quita_cuando_sus_votos_salen_del_horizonte() {
    let sk = bls();
    let mut c = cadena(&sk);
    let mut d = detector();
    assert_eq!(
        d.horizonte(),
        (crate::perfil::F_SLOTS + crate::perfil::PLAZO_SLOTS)
            .div_euclid(crate::perfil::parametros_votos_dev().t_inst)
    );
    let evidencia = fabricar(&mut d, &sk, &c);
    d.marcar_acusada(&evidencia.clave_bls); // simula respuesta de cobertura, nunca fabricación.
    let poda_final = evidencia.n2 + d.horizonte();
    d.al_abrir(poda_final - 1);
    assert_eq!(d.votos_guardados(), 1);
    assert!(d.drenar(&c).is_empty());
    d.al_abrir(poda_final);
    assert_eq!(d.votos_guardados(), 0);
    let n = poda_final + 1;
    c.admitir(post(10, vec![bh(5)], n * T_INST_VOTOS))
        .expect("nuevo X");
    c.admitir(post(11, vec![bh(5)], n * T_INST_VOTOS + 1))
        .expect("nuevo Z");
    c.admitir(post(12, vec![bh(10), bh(11)], (n + 1) * T_INST_VOTOS))
        .expect("fusión");
    let clave = sk.clave_publica().bytes();
    d.registrar(clave, voto(&sk, n, 10), &c);
    d.registrar(clave, voto(&sk, n + 1, 11), &c);
    assert_eq!(d.votos_guardados(), 2);
    assert_eq!(d.drenar(&c).len(), 1);
}

pub(crate) fn operacion(tx: &Tx) -> &zx_core::OperacionAlmacenamiento {
    match &tx.extension {
        ExtensionTx::PruebaAlmacenamiento { operacion } => operacion,
        _ => panic!("se esperaba 0x0B"),
    }
}

#[test]
fn b88_04_evidencia_que_la_cola_rechaza_no_se_vuelve_a_fabricar() {
    // Nombre histórico conservado. Ahora afirma el arreglo: rechazo no acusa y hay reintento.
    let sk = bls();
    let c = cadena(&sk);
    let mut d = detector();
    let evidencia = fabricar(&mut d, &sk, &c);
    let (pk, ed_sk) = reportero();
    let (tx, testigos) = tx_evidencia_votos_peso(&evidencia, pk, &ed_sk, CBID_RED_DEV);
    let base = c.estado_virtual().expect("base");
    let mut m = Mempool::nueva(
        params(),
        ParametrosEvidencia::inactiva(),
        CBID_RED_DEV,
        base.clone(),
        Politica::dev(),
    );
    let r = m.admitir(
        None,
        tx.clone(),
        testigos.clone(),
        Instant::now(),
        Punto::Slot(base.slot),
    );
    assert_eq!(r, Err(Rechazo::VistaLocal("ErrEvidenciaInadmisible")));
    assert_eq!(m.estadisticas().n, 0);
    for _ in 0..100 {
        assert!(d.drenar(&c).is_empty(), "cupo de la ventana");
    }
    d.al_abrir(evidencia.n2 + 1);
    let segundo = d.drenar(&c).pop().expect("reintento sin votos nuevos");
    let (tx2, t2) = tx_evidencia_votos_peso(&segundo, pk, &ed_sk, CBID_RED_DEV);
    assert_eq!(txid(&tx, CBID_RED_DEV), txid(&tx2, CBID_RED_DEV));
    assert_eq!(testigos, t2);
    let (a, b) = votos_tx(&tx2);
    let hecho = c.hecho_voto_entre_ventanas(
        &a,
        &b,
        u64::try_from(base.parametros_sector.plazo_slots).expect("plazo"),
    );
    let (r, retiradas) = m.admitir_evidencia(
        tx2.clone(),
        t2,
        hecho,
        Instant::now(),
        Punto::Slot(base.slot),
    );
    assert!(matches!(r, crate::mempool::AdmisionEvidencia::Admitida(_)));
    assert!(retiradas.is_empty());
    assert!(m.contiene(&txid(&tx2, CBID_RED_DEV)));
    assert_eq!(m.seleccionar(params().max_cuerpo_bloque_bytes, 1).len(), 1);
    let fin = cierre_ventana(evidencia.n2)
        .saturating_add(u64::try_from(base.parametros_sector.plazo_slots).expect("plazo"));
    let (_, _, admisible) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &base,
        operacion(&tx),
        pk,
        &params(),
        &ParametrosEvidencia::inactiva(),
        fin,
        hecho,
    );
    admisible.expect("extremo inclusivo");
    let (_, _, tardia) = aplicar_evidencia_votos_peso_con_hecho_con_undo(
        &base,
        operacion(&tx),
        pk,
        &params(),
        &ParametrosEvidencia::inactiva(),
        fin + 1,
        hecho,
    );
    assert_eq!(tardia, Err(ErrorTransicion::ErrEvidenciaVoto));
}

pub(crate) fn votos_tx(tx: &Tx) -> (zx_core::VotoPesoEvidencia, zx_core::VotoPesoEvidencia) {
    match operacion(tx) {
        zx_core::OperacionAlmacenamiento::EvidenciaVotosPeso { voto1, voto2, .. } => {
            (*voto1, *voto2)
        }
        _ => panic!("operación de evidencia"),
    }
}
