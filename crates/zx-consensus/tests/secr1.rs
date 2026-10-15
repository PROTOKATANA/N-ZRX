//! SEC-R1: caracterización de la base por transiciones públicas y medida manual indicativa.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "pruebas deterministas de caracterización que fallan con panic"
)]
use zx_consensus as consensus;
#[path = "soporte/secr1/fixture.rs"]
mod fixture;
use consensus::cajas::EtapaCaja;
use consensus::sectores::Etapa;
use consensus::transicion::{
    Estado, Garantia, ParametrosEvidencia, aplicar_operacion_con_undo, deshacer,
    materializar_con_undo,
};
use fixture::{DEN, N, bls, caja_para, clave, estado_ausencia, huella, liquidar, params, registro};
use zx_core::{Amount, OperacionAlmacenamiento, OperacionSector, VotoPesoEvidencia};
fn fija(est: &Estado, esperado: &str) {
    let actual = huella(est);
    println!("HUELLA {actual}");
    assert_eq!(actual, esperado);
}
#[test]
fn secr1_caracterizacion_ausencias_256() {
    let est = estado_ausencia(256, 256 * 6, true);
    assert_eq!(
        est.tablas_voto_contenido.values().next().unwrap().len(),
        256
    );
    assert_eq!(&clave(0).bytes()[..31], &clave(255).bytes()[..31]);
    let (nuevo, undo) = liquidar(&est);
    assert!(nuevo.quemado > 0);
    assert_eq!(nuevo.deuda_ausencia[&clave(1)], 7 * 301);
    assert_eq!(nuevo.garantias[&clave(2)].activo.brek(), DEN as i64 - 14);
    assert_eq!(deshacer(&nuevo, &undo), est);
    fija(
        &nuevo,
        "ce0c8c2d592879e3465e63a03850f5ae638a4185dd7bb23af5c5383b4a094249",
    );
}
#[test]
fn secr1_caracterizacion_castigo_debita_sectores_en_orden() {
    let mut est = Estado::inicial();
    est.fase = consensus::transicion::Fase::PoST;
    est.parametros_sector.t_cad = 1_000_000;
    let ed = clave(2);
    let secreta = bls(2);
    let pk = secreta.clave_publica().bytes();
    est.claves_voto.insert(
        ed,
        consensus::sectores::ClaveVoto {
            clave_bls: pk,
            prueba_posesion: [0; 96],
        },
    );
    est.garantias.insert(
        ed,
        Garantia {
            activo: Amount::nuevo(25).unwrap(),
            ..Garantia::nueva()
        },
    );
    for (indice, version, fianza, seq) in [
        (0, 0, 20, 0),
        (0, u32::MAX, 30, 1),
        (u16::MAX, 0, 40, 2),
        (u16::MAX, u32::MAX, 50, u32::MAX),
    ] {
        let r = registro(ed, indice, version, Etapa::Activo, fianza);
        est.sectores.insert(r.id, r);
        caja_para(&mut est, r, seq, EtapaCaja::Cerrada);
    }
    for vecino in [clave(1), clave(3)] {
        let r = registro(vecino, u16::MAX, u32::MAX, Etapa::Activo, 17);
        est.sectores.insert(r.id, r);
        caja_para(&mut est, r, u32::MAX, EtapaCaja::Abierta);
    }
    est.emitido = 25 + 140 + 34;
    let voto = |candidato: [u8; 32]| VotoPesoEvidencia {
        n: N,
        candidato,
        h_t_siguiente: [0x33; 32],
        raiz_estado: candidato,
        firma: zx_votos::firmar(
            &secreta,
            zx_votos::DOMINIO_VOTO,
            &zx_votos::mensaje_voto_peso(N, &candidato, &[0x33; 32], &candidato),
        )
        .unwrap()
        .bytes(),
    };
    let op = OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: clave(9),
        clave_bls: pk,
        voto1: voto([1; 32]),
        voto2: voto([2; 32]),
    };
    let evp = ParametrosEvidencia {
        f_num: 1,
        f_den: 2,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid: 0,
        evp: true,
    };
    let (nuevo, undo, r) = consensus::transicion::votos::aplicar_evidencia_votos_peso_con_undo(
        &est,
        &op,
        clave(9),
        &params(),
        &evp,
        10,
    );
    r.unwrap();
    assert_eq!(nuevo.garantias[&ed].activo, Amount::CERO);
    let fianzas: Vec<_> = nuevo
        .sectores
        .iter()
        .filter(|(id, _)| id.clave == ed)
        .map(|(_, r)| r.fianza)
        .collect();
    assert_eq!(fianzas, [0, 0, 32, 50]); // techo(165/2)=83: cuenta 25, sectores 20+30+8.
    assert_eq!(deshacer(&nuevo, &undo), est);
    fija(
        &nuevo,
        "e6080dc826e0a5d8595802701aaf1a3541d7a8e9fd608b08400efc4af4a14d1b",
    );
}
#[test]
fn secr1_caracterizacion_alta_renovacion_baja_caja() {
    let mut est = Estado::inicial();
    est.parametros_sector.capacidad_caja = 1;
    let ed = clave(2);
    est.garantias.insert(
        ed,
        Garantia {
            activo: Amount::nuevo(1_000).unwrap(),
            ..Garantia::nueva()
        },
    );
    est.emitido = 1_000;
    for vecino in [clave(1), clave(3)] {
        let r = registro(vecino, u16::MAX, u32::MAX, Etapa::Retirado, 0);
        est.sectores.insert(r.id, r);
        caja_para(&mut est, r, u32::MAX, EtapaCaja::Retirada);
    }
    let aplicar = |base: &Estado, op: OperacionSector, slot| {
        let (nuevo, resultado) =
            aplicar_operacion_con_undo(base, &op, slot, &base.parametros_sector);
        assert_eq!(resultado.motivo, consensus::sectores::MotivoSector::Ok);
        assert_eq!(deshacer(&nuevo, &resultado.undo), *base);
        nuevo
    };
    est = aplicar(
        &est,
        OperacionSector::Alta {
            clave: ed,
            sector_index: u16::MAX,
            version: 0,
            r2: [7; 32],
            history_size: 1,
        },
        0,
    );
    est = materializar_con_undo(&est, est.parametros_sector.m_sec, &est.parametros_sector).0;
    est = aplicar(
        &est,
        OperacionSector::Renovar {
            clave: ed,
            sector_index: u16::MAX,
        },
        20,
    );
    est = aplicar(
        &est,
        OperacionSector::Retirar {
            clave: ed,
            sector_index: u16::MAX,
        },
        21,
    );
    fija(
        &est,
        "cce5d9dcc03ada896355a4cb39f30fd82c6eecad4fb5b9ce46f3b0bd43f60ff5",
    );
    let mut est = Estado::inicial();
    est.parametros_sector.capacidad_caja = 16;
    est.garantias.insert(
        ed,
        Garantia {
            activo: Amount::nuevo(1_000).unwrap(),
            ..Garantia::nueva()
        },
    );
    est.emitido = 1_000;
    est = aplicar(
        &est,
        OperacionSector::Alta {
            clave: ed,
            sector_index: 0,
            version: 0,
            r2: [9; 32],
            history_size: 1,
        },
        0,
    );
    est = materializar_con_undo(&est, 20, &est.parametros_sector).0;
    est = aplicar(&est, OperacionSector::CerrarCaja { clave: ed, seq: 1 }, 20);
    est = aplicar(&est, OperacionSector::RetirarCaja { clave: ed, seq: 1 }, 21);
    fija(
        &est,
        "67a2bd949e6ab02326ba35afef5033aedf37592a871d3f46620283f8d77921a5",
    );
}
#[test]
#[ignore = "medida SEC-R1 indicativa: manual, bajo candados compartidos en E2, no pertenece a la suite"]
fn secr1_medida_liquidacion_ventana() {
    for (miembros, sectores) in [(1_000, 100_000), (4_096, 262_144)] {
        let est = estado_ausencia(miembros, sectores, false);
        let inicio = std::time::Instant::now();
        let (nuevo, _) = liquidar(&est);
        let tiempo = inicio.elapsed();
        assert!(nuevo.quemado > 0);
        println!(
            "MEDIDA ausentes={miembros} sectores={sectores} segundos={:.9} quemado={} deuda_claves={}",
            tiempo.as_secs_f64(),
            nuevo.quemado,
            nuevo.deuda_ausencia.len()
        );
    }
}
