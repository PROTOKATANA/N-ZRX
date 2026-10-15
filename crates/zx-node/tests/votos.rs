//! FV-4b-N1 · pruebas del motor de votos: humo de 4 nodos (in-process), rechazo de certificados
//! falsos y punto de control externo.
//!
//! M9-a2 · devueltas al **modo por peso** (el único que queda): sobre `ZXV3`, certificado `0x09`,
//! evidencia `0x0B`, acta `0x0A`. Las pruebas del sorteo (plazas, VRF) y del punto de control
//! `ZXPC1` se retiran (listas B y S de la orden).
//!
//! El humo (a) monta **cuatro** `MotorVotos` con claves BLS distintas sobre un **mismo** `Estado`
//! (claves de voto registradas y sectores que pesan), intercambia los votos como los difundiría la
//! red y comprueba que los cuatro adoptan el mismo certificado y anclan el mismo punto. Es el
//! equivalente en proceso del humo de 4 nodos: el transporte real del 4.º tema se cubre en los
//! tests de `zx-p2p` (suscripción exacta de cuatro temas y clasificación).
//!
//! El punto (b) de la pregunta falsable (certificado de rama en conflicto que **no** se adopta)
//! vive en `crates/zx-cadena/src/cadena.rs` (`anclar_finalidad_por_votos`), probado allí sobre la
//! propia `Cadena`.
//!
//! El punto (e) (18/18 vectores de FV-3) se conserva en `zx-votos` (`tests/vectores`, privado).

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseno y trocean sobres ya comprobados"
)]

use zx_consensus::sectores::{
    ClaveVoto, Etapa, NO_HAY, ParametrosSector, RegistroSector, SectorId,
};
use zx_consensus::transicion::Estado;
use zx_core::BlockHash;
use zx_core::digest::Digest;
use zx_core::firma::ClavePublica as ClaveEd;
use zx_node::votos::{
    ConfigMotorVotos, MotorVotos, RecepcionVoto, deserializar_voto_peso, voto_es_plausible,
};
use zx_votos::{ClavePublica, ClaveSecreta, ErrorBLS, ErrorVotos, probar_posesion};

/// Número de "nodos" del humo.
const NODOS: usize = 4;

/// Clave dev determinista por índice (material de 32 B distinto).
fn semilla(i: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    ikm[0] = 0x42;
    let bytes = (i as u64).to_le_bytes();
    ikm[8..16].copy_from_slice(&bytes);
    ikm
}

/// Clave Ed25519 sintética (la clave de `Estado.claves_voto` y de los sectores).
fn clave_ed(i: usize) -> ClaveEd {
    let mut bytes = [0u8; 32];
    bytes[0] = u8::try_from(i).unwrap_or(0) + 1;
    ClaveEd::desde_bytes(bytes)
}

/// `Estado` compartido: una clave BLS de voto y dos sectores activos por nodo.
fn estado_con_sectores(bls: &[ClavePublica]) -> Estado {
    let mut estado = Estado::inicial();
    estado.parametros_sector = ParametrosSector::dev();
    for (i, pk) in bls.iter().enumerate() {
        let ed = clave_ed(i);
        estado.claves_voto.insert(
            ed,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for s in 0..2u16 {
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
                    fianza: estado.parametros_sector.q_sec,
                    aud_apertura: NO_HAY,
                    aud_contestada: NO_HAY,
                },
            );
        }
    }
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) =
        zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(&estado, 100);
    con_cola
}

/// Hash determinista por instancia.
fn hash_n(n: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xaa;
    bytes[1..9].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

/// Los cuatro motores y sus claves secretas, en orden (modo por peso).
fn motores() -> Vec<MotorVotos> {
    (0..NODOS)
        .map(|i| {
            let sk = ClaveSecreta::generar(&semilla(i)).expect("clave BLS");
            MotorVotos::nuevo(ConfigMotorVotos {
                perfil: zx_node::perfil::parametros_votos_dev(),
                claves: vec![sk],
                emitir_votos: true,
            })
        })
        .collect()
}

/// Claves públicas BLS de los cuatro nodos.
fn claves_publicas() -> Vec<ClavePublica> {
    (0..NODOS)
        .map(|i| {
            ClaveSecreta::generar(&semilla(i))
                .expect("clave BLS")
                .clave_publica()
        })
        .collect()
}

/// (a) Humo de 4 nodos: los cuatro adoptan los mismos certificados y anclan el mismo punto.
#[test]
fn cuatro_nodos_adoptan_el_mismo_certificado_y_anclan_el_mismo_punto() {
    let bls = claves_publicas();
    let estado = estado_con_sectores(&bls);
    let mut ms = motores();
    const INSTANCIAS: u64 = 3;

    let mut candidatos = Vec::new();
    for n in 0..=INSTANCIAS {
        let candidato = hash_n(n);
        candidatos.push(candidato);
        // Abre la instancia n en cada motor y recoge los votos propios.
        let mut sobres = Vec::new();
        for m in &mut ms {
            let paso = m
                .avanzar(n, candidato, &estado, 0)
                .expect("avanzar sin error");
            sobres.extend(paso.votos);
        }
        // Difunde todos los votos a todos (como haría el 4.º tema de gossipsub).
        for m in &mut ms {
            for sobre in &sobres {
                let _ = m.recibir_voto(sobre);
            }
        }
    }

    // Cierra la última instancia.
    let mut certificados: Vec<Option<zx_votos::peso::CertificadoPeso>> = Vec::new();
    for m in &mut ms {
        let paso = m
            .avanzar(INSTANCIAS + 1, hash_n(INSTANCIAS + 1), &estado, 0)
            .expect("cierre sin error");
        certificados.push(paso.certificado_peso);
    }

    // Cada motor adoptó INSTANCIAS + 1 certificados (n = 0..=INSTANCIAS).
    for (i, m) in ms.iter().enumerate() {
        assert_eq!(
            m.certificados_peso().len() as u64,
            INSTANCIAS + 1,
            "el motor {i} debe haber adoptado {} certificados",
            INSTANCIAS + 1
        );
        assert_eq!(
            m.punto(),
            Some(*candidatos.last().expect("candidato").as_bytes()),
            "el motor {i} ancla el último candidato"
        );
    }
    // Y todos adoptaron el mismo candidato en la última instancia cerrada.
    let ultimo = certificados
        .iter()
        .map(|c| c.as_ref().expect("certificado").candidato)
        .collect::<Vec<_>>();
    assert!(
        ultimo.iter().all(|c| *c == ultimo[0]),
        "los cuatro nodos adoptan el mismo candidato: {ultimo:?}"
    );
}

/// (c2) Un voto con la **firma desplazada** (firma válida de otro mensaje) se rechaza.
#[test]
fn un_voto_con_firma_alterada_se_rechaza() {
    let bls = claves_publicas();
    let estado = estado_con_sectores(&bls);
    let mut ms = motores();
    let candidato = hash_n(0);
    let mut sobres = Vec::new();
    for m in &mut ms {
        sobres.extend(m.avanzar(0, candidato, &estado, 0).expect("avanzar").votos);
    }
    let sobre = sobres.first().expect("al menos un voto").clone();

    // Firma BLS válida (mismo tamaño, punto de G2 del subgrupo) pero de **otro mensaje**: el
    // desplazamiento de firma que el certificado agregado debe rechazar.
    let sk = ClaveSecreta::generar(&semilla(0)).expect("clave");
    let firma_ajena =
        zx_votos::firmar(&sk, zx_votos::DOMINIO_VOTO, b"otro mensaje").expect("firma");
    let mut alterado = sobre.clone();
    // M9-a2 · el voto por peso ZXV3 mide 252 B y la firma BLS (96 B) cierra el sobre.
    let inicio_firma = alterado.len() - 96;
    alterado[inicio_firma..inicio_firma + 96].copy_from_slice(&firma_ajena.bytes());

    let mut receptor = motores().remove(0);
    receptor.avanzar(0, candidato, &estado, 0).expect("avanzar");
    match receptor.recibir_voto(&alterado) {
        RecepcionVoto::Rechazado { motivo } => {
            assert_eq!(motivo, "firma_falsa", "motivo exacto");
        }
        otro => panic!("se esperaba rechazo de firma ajena, llegó {otro:?}"),
    }
}

/// (c3) Un certificado con firma agregada ajena **no verifica** con BLS (ni `Ok` ficticio).
#[test]
fn un_certificado_con_firma_ajena_no_verifica() {
    let bls = claves_publicas();
    let estado = estado_con_sectores(&bls);
    let mut ms = motores();
    let candidato = hash_n(0);
    let mut sobres = Vec::new();
    for m in &mut ms {
        sobres.extend(m.avanzar(0, candidato, &estado, 0).expect("avanzar").votos);
    }
    for m in &mut ms {
        for sobre in &sobres {
            let _ = m.recibir_voto(sobre);
        }
    }
    let mut m = ms.remove(0);
    let cierre = m.cerrar().expect("cierre");
    let cert = cierre.certificado_peso.expect("certificado válido");
    let tabla = m.tabla_actual().expect("tabla").clone();
    let pubs = m.claves_publicas_actuales().expect("claves").to_vec();

    // Firma de otro mensaje (mismo tamaño, punto válido de G2): no verifica.
    let mut firma_ajena = cert.clone();
    let sk = ClaveSecreta::generar(&[0x99; 32]).expect("clave");
    firma_ajena.firma = zx_votos::agregar_firmas(&[&zx_votos::firmar(
        &sk,
        zx_votos::DOMINIO_VOTO,
        b"otro mensaje",
    )
    .expect("firma")])
    .expect("agregada");
    let err = zx_votos::peso::verificar_firma_peso(&tabla, &pubs, &firma_ajena);
    assert_eq!(err, Err(ErrorVotos::Bls(ErrorBLS::VerificacionFallida)));
}

/// El sobre de voto es plausible por cabecera y longitud, y se rechaza si se trunca.
#[test]
fn la_plausibilidad_del_sobre_es_barata_y_estricta() {
    let bls = claves_publicas();
    let estado = estado_con_sectores(&bls);
    let mut m = motores().remove(0);
    let sobres = m.avanzar(0, hash_n(0), &estado, 0).expect("avanzar").votos;
    let sobre = sobres.first().expect("voto");
    assert!(voto_es_plausible(sobre));
    assert!(deserializar_voto_peso(sobre).is_ok());
    assert!(!voto_es_plausible(&sobre[..sobre.len() - 1]));
    assert!(!voto_es_plausible(b"no-es-un-voto"));
}

/// La prueba de posesión de las claves usadas existe (se registra en el estado en PT-3bc).
#[test]
fn las_claves_del_humo_tienen_prueba_de_posesion() {
    for i in 0..NODOS {
        let sk = ClaveSecreta::generar(&semilla(i)).expect("clave");
        let pk = sk.clave_publica();
        let pop = probar_posesion(&sk);
        zx_votos::verificar_posesion(&pk, &pop).expect("PoP válida");
    }
}
