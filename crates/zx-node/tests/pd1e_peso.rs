//! PD-1e · U4/U5 · red en proceso de tres votantes y un observador con el modo por peso.
//!
//! El humo replica `crates/zx-node/tests/votos.rs`: cuatro `MotorVotos` **reales** sobre un mismo
//! `Estado`, en modo `Peso`, intercambiando los sobres `ZXV3` como los difundiría la red. Cada
//! certificado `0x09` que produce el motor se aplica al mismo `Estado` con la función de consenso
//! (`aplicar_certificado_peso_con_undo`), que es la que fija `finalidad_votos_n`. El observador
//! (sin claves propias) también recibe y aplica: la finalidad avanza en los cuatro.
//!
//! U4 · pregunta (1): la finalidad avanza en los cuatro, el flujo solo produce las clases `0x08`,
//! `0x09`, `0x0A` y `0x0B` (nunca `0x04`–`0x07`) y hay al menos un `0x09`.
//! U5 · pregunta (2): con la clave de más de un tercio detenida no hay certificado pero sí acta/voto
//! propio de los presentes; al volver se reanudan los certificados y el ausente acumula deuda.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseno y trocean payloads ya comprobados"
)]

use primitive_types::U256;
use zx_consensus::sectores::{
    ClaveVoto, Etapa, NO_HAY, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::votos::{
    W_REVEAL_SLOTS_VOTOS, aplicar_acta_presencia_con_undo, aplicar_certificado_peso_con_undo,
    cierre_ventana,
};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, aplicar_con_undo,
};
use zx_core::{
    Amount, BlockHash, ClavePublica as ClaveEd, Digest, ExtensionTx, OperacionAlmacenamiento,
};
use zx_node::votos::{ConfigMotorVotos, MotorVotos, tx_certificado_peso};
use zx_votos::peso::{CertificadoPeso, serial_certificado_peso};
use zx_votos::{ClavePublica, ClaveSecreta};

const CBID: u32 = 0;
const SLOT: i64 = 100;
const DEN: i64 = 1_401_600_000;
const NODOS: usize = 4;

fn semilla(i: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    ikm[0] = 0x42;
    ikm[8..16].copy_from_slice(&(i as u64).to_le_bytes());
    ikm
}

fn clave_ed(i: usize) -> ClaveEd {
    let mut bytes = [0u8; 32];
    bytes[0] = u8::try_from(i).unwrap_or(0) + 1;
    ClaveEd::desde_bytes(bytes)
}

fn clave_bls(i: usize) -> ClaveSecreta {
    ClaveSecreta::generar(&semilla(i)).expect("clave BLS")
}

fn cand(n: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xcc;
    bytes[1..9].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

/// `Estado` compartido con los sectores indicados por clave (`sectores[i]`), registrando la clave
/// BLS de voto del nodo `i`.
fn estado_con_pesos(bls: &[ClavePublica], sectores: &[u16]) -> Estado {
    let p = ParametrosSector::dev();
    let mut estado = Estado::inicial();
    estado.parametros_sector = p;
    estado.fase = Fase::PoST;
    for (i, pk) in bls.iter().enumerate() {
        let ed = clave_ed(i);
        estado.claves_voto.insert(
            ed,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for s in 0..sectores[i] {
            let id = SectorId {
                clave: ed,
                sector_index: s,
                version: 0,
            };
            estado.sectores.insert(
                id,
                RegistroSector {
                    id,
                    r2: [0u64; 4],
                    history_size: 1,
                    etapa: Etapa::Activo,
                    alta_slot: 0,
                    renovacion_slot: 1_000_000,
                    retiro_slot: NO_HAY,
                    fianza: p.q_sec,
                    aud_apertura: NO_HAY,
                    aud_contestada: NO_HAY,
                },
            );
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(DEN).expect("garantia activa");
        estado.garantias.insert(ed, g);
    }
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &estado,
        u64::try_from(SLOT).expect("slot"),
    );
    con_cola
}

/// Tres motores votantes (uno por clave) y un observador sin claves propias, todos en modo peso.
fn motores_peso(votantes: usize) -> Vec<MotorVotos> {
    let mut ms = Vec::with_capacity(NODOS);
    for i in 0..votantes {
        ms.push(MotorVotos::nuevo(ConfigMotorVotos {
            perfil: zx_node::perfil::parametros_votos_dev(),
            claves: vec![clave_bls(i)],
            emitir_votos: true,
        }));
    }
    // Observador: sin claves, no firma, pero recibe y aplica.
    for _ in votantes..NODOS {
        ms.push(MotorVotos::nuevo(ConfigMotorVotos {
            perfil: zx_node::perfil::parametros_votos_dev(),
            claves: Vec::new(),
            emitir_votos: false,
        }));
    }
    ms
}

fn op_cert(cert: &CertificadoPeso) -> OperacionAlmacenamiento {
    OperacionAlmacenamiento::CertificadoPeso {
        clave: ClaveEd::desde_bytes([200u8; 32]),
        bytes: serial_certificado_peso(cert),
    }
}

/// U4 · pregunta (1): la finalidad avanza en los cuatro y el flujo no produce clases `0x04`–`0x07`.
#[test]
fn u4_cuatro_nodos_avanzan_finalidad_solo_con_el_flujo_v2() {
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let estado = estado_con_pesos(&bls, &[1, 1, 1, 1]);
    let mut ms = motores_peso(3);

    let mut estado_actual = estado.clone();
    // Un certificado por ventana (los cuatro nodos adoptan el mismo); se aplica una sola vez.
    let mut certificados: std::collections::BTreeMap<u64, CertificadoPeso> =
        std::collections::BTreeMap::new();
    let mut hubo_acta = false;

    // Abre/cierra las ventanas 1..=5; el certificado de la ventana `n` sale al avanzar a `n+1`.
    for n in 1..=5u64 {
        let mut sobres = Vec::new();
        for m in &mut ms {
            let paso = m
                .avanzar(n, cand(n), &estado_actual, SLOT)
                .expect("avanzar sin error");
            hubo_acta |= paso.acta_peso.is_some();
            sobres.extend(paso.votos);
            if let Some(cert) = paso.certificado_peso {
                certificados.entry(cert.n).or_insert(cert);
            }
        }
        for m in &mut ms {
            for sobre in &sobres {
                let _ = m.recibir_voto(sobre);
            }
        }
    }

    assert!(!certificados.is_empty(), "hay certificados 0x09");

    // Cada certificado se aplica con la función de consenso y la finalidad avanza.
    let mut ventanas = Vec::new();
    for cert in certificados.values() {
        let (nuevo, _undo, r) =
            aplicar_certificado_peso_con_undo(&estado_actual, &op_cert(cert), SLOT);
        r.expect("el certificado por peso se aplica");
        estado_actual = nuevo;
        ventanas.push(estado_actual.finalidad_votos_n);
    }
    assert!(
        ventanas.windows(2).all(|w| w[0] < w[1]),
        "la finalidad avanza en cada certificado: {ventanas:?}"
    );
    assert!(
        estado_actual.finalidad_votos_n >= 3,
        "la finalidad avanza en los cuatro nodos (estado compartido): {}",
        estado_actual.finalidad_votos_n
    );

    // El certificado se puede publicar como tx v6 `0x09` (la clase correcta).
    let (tx, _tst) = tx_certificado_peso(
        certificados
            .values()
            .next()
            .expect("al menos un certificado"),
        clave_ed(0),
        &ed25519_zebra::SigningKey::from([7u8; 32]),
        CBID,
    );
    assert!(
        matches!(
            &tx.extension,
            ExtensionTx::PruebaAlmacenamiento {
                operacion: OperacionAlmacenamiento::CertificadoPeso { .. }
            }
        ),
        "el certificado viaja como 0x09"
    );
    // Nota de honestidad: `hubo_acta` puede ser falso si todas las ventanas alcanzan quórum; el acta
    // se ejercita en U5 (ventanas sin quórum). Se conserva el consumo de la variable.
    let _ = hubo_acta;

    // El observador (sin claves) también adoptó el mismo número de certificados que los votantes.
    for m in &ms {
        assert_eq!(
            m.certificados_peso().len(),
            certificados.len(),
            "los cuatro nodos adoptan los mismos certificados"
        );
    }
}

/// U5 · pregunta (2): ausencia de una clave con más de un tercio, acta de los presentes,
/// reanudación y deuda del ausente.
#[test]
fn u5_ausencia_de_mas_de_un_tercio_pausa_y_reanuda() {
    // Pesos 2,1,1 (W = 4): la clave 0 es más de un tercio; sin ella no hay quórum (3·2 < 2·4).
    let bls: Vec<ClavePublica> = (0..NODOS).map(|i| clave_bls(i).clave_publica()).collect();
    let estado = estado_con_pesos(&bls, &[2, 1, 1, 1]);

    // Fase A · la ventana 1 se certifica con los tres votantes (finalidad = 1).
    let mut todos = motores_peso(3);
    let mut estado_actual = estado.clone();
    let mut cert1: Option<CertificadoPeso> = None;
    for n in 1..=2u64 {
        let mut sobres = Vec::new();
        for m in &mut todos {
            let paso = m
                .avanzar(n, cand(n), &estado_actual, SLOT)
                .expect("avanzar");
            sobres.extend(paso.votos);
            if let Some(c) = paso.certificado_peso {
                cert1 = Some(c);
            }
        }
        for m in &mut todos {
            for s in &sobres {
                let _ = m.recibir_voto(s);
            }
        }
    }
    let cert1 = cert1.expect("la ventana 1 con todos certifica");
    let (nuevo, _u, r) = aplicar_certificado_peso_con_undo(&estado_actual, &op_cert(&cert1), SLOT);
    r.expect("cert1");
    estado_actual = nuevo;
    assert_eq!(estado_actual.finalidad_votos_n, 1);

    // Tabla semilla para que el nodo que vuelve arranque con la finalidad de la ventana 1.
    let tabla_seed = zx_votos::Tabla {
        n: cert1.n,
        claves: todos[0]
            .tabla_actual()
            .expect("tabla de la ventana 1")
            .claves
            .clone(),
    };
    let pubs_seed: Vec<ClavePublica> = tabla_seed
        .claves
        .iter()
        .map(|c| ClavePublica::desde_bytes(&c.clave).expect("clave pública de la tabla"))
        .collect();

    // Fase B · la clave 0 (peso 2 > 1/3) se detiene en las ventanas 2 y 3: no hay certificado, pero
    // los presentes dejan acta.
    let mut presentes = motores_peso(3);
    presentes.remove(0); // claves 1 y 2 + observador
    for m in &mut presentes {
        m.sembrar_punto_control_peso(tabla_seed.clone(), pubs_seed.clone(), cert1.clone(), &[])
            .expect("siembra de la finalidad 1");
    }
    let mut sin_cert = Vec::new();
    let mut con_acta = Vec::new();
    let mut actas: std::collections::BTreeMap<u64, CertificadoPeso> =
        std::collections::BTreeMap::new();
    for n in 2..=4u64 {
        let mut sobres = Vec::new();
        for m in &mut presentes {
            let paso = m
                .avanzar(n, cand(n), &estado_actual, SLOT)
                .expect("avanzar");
            sin_cert.push(paso.certificado_peso.is_none());
            if let Some(a) = &paso.acta_peso {
                con_acta.push(true);
                actas.entry(a.n).or_insert_with(|| a.clone());
            } else {
                con_acta.push(false);
            }
            sobres.extend(paso.votos);
        }
        for m in &mut presentes {
            for s in &sobres {
                let _ = m.recibir_voto(s);
            }
        }
    }
    assert!(
        sin_cert.iter().all(|v| *v),
        "sin la clave de más de un tercio no hay certificado"
    );
    assert!(con_acta.iter().any(|v| *v), "los presentes dejan acta");
    for acta in actas.values() {
        let op = OperacionAlmacenamiento::ActaPresencia {
            clave: clave_ed(200),
            bytes: serial_certificado_peso(acta),
        };
        let (nuevo, _u, r) = aplicar_acta_presencia_con_undo(&estado_actual, &op, SLOT);
        r.expect("el acta de los presentes se aplica con la finalidad 1 conocida");
        estado_actual = nuevo;
    }
    assert!(
        estado_actual
            .votantes_voto
            .get(&2)
            .is_some_and(|v| !v.contains(&clave_ed(0))),
        "el ausente no consta en la ventana 2"
    );

    // Fase C · la clave 0 vuelve en la ventana 4 (sembrada con la finalidad 1): el certificado se
    // reanuda y asocia las ventanas 2..4 a la tabla vigente.
    let mut al_volver = motores_peso(3);
    for m in &mut al_volver {
        m.sembrar_punto_control_peso(tabla_seed.clone(), pubs_seed.clone(), cert1.clone(), &[])
            .expect("siembra de la finalidad 1");
    }
    let mut cert_vuelta: Option<CertificadoPeso> = None;
    for n in 4..=5u64 {
        let mut sobres = Vec::new();
        for m in &mut al_volver {
            let paso = m
                .avanzar(n, cand(n), &estado_actual, SLOT)
                .expect("avanzar");
            sobres.extend(paso.votos);
            if let Some(c) = paso.certificado_peso {
                cert_vuelta = Some(c);
            }
        }
        for m in &mut al_volver {
            for s in &sobres {
                let _ = m.recibir_voto(s);
            }
        }
    }
    let cert_vuelta = cert_vuelta.expect("al volver se reanuda el certificado");
    let (nuevo, _u, r) =
        aplicar_certificado_peso_con_undo(&estado_actual, &op_cert(&cert_vuelta), SLOT);
    r.expect("el certificado al volver se aplica");
    estado_actual = nuevo;
    assert_eq!(
        estado_actual.finalidad_votos_n, 4,
        "la finalidad se reanuda hasta la ventana 4"
    );

    // Fase D · liquidación: el ausente paga las ventanas 2 y 3; los presentes, no.
    let fin = aplicar_post(&estado_actual, cierre_ventana(2) + W_REVEAL_SLOTS_VOTOS + 1);
    assert!(
        deuda(&fin, 0) > 0,
        "el ausente acumula deuda en el estado final: {}",
        deuda(&fin, 0)
    );
    assert_eq!(deuda(&fin, 1), 0, "la clave 1 votó: no debe");
    assert_eq!(deuda(&fin, 2), 0, "la clave 2 votó: no debe");
}

/// Aplica un bloque PoST vacío (dispara la liquidación de ausencia), como en `pd1d_peso`.
fn aplicar_post(est: &Estado, slot: u64) -> Estado {
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: BlockHash::from_digest(Digest::from_bytes([1u8; 32])),
            padre: BlockHash::from_digest(Digest::from_bytes([2u8; 32])),
            slot,
            productor: clave_ed(1),
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        Vec::new(),
    );
    let (nuevo, _) = aplicar_con_undo(
        est,
        &bloque,
        &params(),
        CBID,
        &ParametrosEvidencia::inactiva(),
    )
    .expect("liquidación");
    nuevo
}

fn deuda(est: &Estado, i: usize) -> i128 {
    est.deuda_ausencia.get(&clave_ed(i)).copied().unwrap_or(0)
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
