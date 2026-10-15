#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use super::*;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{Estado, Garantia};
use zx_core::{Amount, ClavePublica as ClaveEd};
use zx_votos::ClaveSecreta;

/// Slot fijo de la fixture de certificados (independiente del reloj simulado del Nodo).
const SLOT_FIXTURE: i64 = 100;

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

/// Estado dev con una clave registrada y `n_sectores` activos (peso real de la fixture).
fn estado_con(n_sectores: usize) -> (Estado, ClaveSecreta) {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
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
            sector_index: u16::try_from(i).expect("indice"),
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
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
            },
        );
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT_FIXTURE).expect("slot"),
    );
    (con_cola, sk)
}

fn motor_con(sk: ClaveSecreta) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: true,
    })
}

fn nodo_de_prueba(dir: &std::path::Path) -> Nodo {
    let cfg = Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: vec![0],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    };
    Nodo::arrancar(&cfg).expect("arranque limpio")
}

fn t_inst() -> u64 {
    perfil::parametros_votos_dev().t_inst.max(1)
}

/// Deja un motor con `C_0` adoptado y la ventana 1 **abierta con quórum real** (un voto propio
/// con todo el peso), listo para inyectarse en el Nodo.
fn motor_con_ventana_uno_abierta() -> (MotorVotos, Estado) {
    let (est, sk) = estado_con(100);
    let c0 = BlockHash::from_digest(Digest::from_bytes([0x10u8; 32]));
    let c1 = BlockHash::from_digest(Digest::from_bytes([0x11u8; 32]));
    let mut motor = motor_con(sk);
    motor.avanzar(0, c0, &est, SLOT_FIXTURE).expect("abrir 0");
    let p1 = motor.avanzar(1, c1, &est, SLOT_FIXTURE).expect("abrir 1");
    assert!(
        p1.certificado_peso.is_some(),
        "C_0 real adoptado al cerrar 0"
    );
    assert_eq!(motor.instancia_actual(), Some(1));
    (motor, est)
}

/// FV-N6-C7-3 · corrección 4 (verde): por `Nodo::procesar_votos`, con `C_0` adoptado y la
/// ventana 1 abierta, el reloj `m+2 = 2` cierra la 1 (adoptando `C_1`) y abre la 2; el avance
/// sigue en 3 y en 4. Las tres ventanas se cierran por el camino común.
#[test]
fn procesar_votos_cierra_y_abre_por_camino_comun() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (motor, _est) = motor_con_ventana_uno_abierta();
    nodo.motor_votos = Some(motor);
    nodo.candidato_votos_simulado = Some(BlockHash::from_digest(Digest::from_bytes([0xAAu8; 32])));

    let t = t_inst();
    nodo.slot_votos_simulado = Some(2 * t);
    nodo.procesar_votos().expect("procesar 2");
    {
        let m = nodo.motor_votos.as_ref().expect("motor");
        assert_eq!(
            m.instancia_actual(),
            Some(2),
            "se cerró la ventana 1 y se abrió la 2 por el camino común"
        );
        assert!(
            m.certificados_peso().iter().any(|c| c.n == 1),
            "C_1 adoptado por procesar_votos"
        );
    }
    nodo.slot_votos_simulado = Some(3 * t);
    nodo.procesar_votos().expect("procesar 3");
    assert_eq!(
        nodo.motor_votos.as_ref().expect("motor").instancia_actual(),
        Some(3)
    );
    nodo.slot_votos_simulado = Some(4 * t);
    nodo.procesar_votos().expect("procesar 4");
    assert_eq!(
        nodo.motor_votos.as_ref().expect("motor").instancia_actual(),
        Some(4)
    );
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    for n in 1u64..=3 {
        let cerrada = registro.lines().any(|l| {
            l.contains("\"tipo\":\"ventana_cerrada\"") && l.contains(&format!("\"n\":{n}"))
        });
        assert!(cerrada, "ventana {n} cerrada por el camino común");
    }
    // N1: la tabla heredada por la ventana 3 ya no la construye el nodo a partir del estado de la
    // cadena (vacío), sino que es la que declaró la ventana 2 (la del montaje, con 100 sectores);
    // por eso la 3 sí tiene quórum y cierra con certificado real, igual que la 1 y la 2.
    for n in 1u64..=3 {
        let con_cert = registro.lines().any(|l| {
            l.contains("\"tipo\":\"ventana_cerrada\"")
                && l.contains(&format!("\"n\":{n}"))
                && l.contains("\"certificado\":true")
        });
        assert!(con_cert, "ventana {n} con certificado real");
    }
    // Control del camino común con **otra** ventana: al poner el motor de prueba en observación
    // deja de emitir sus votos; la ventana 5 (abierta ya sin voto propio) cierra **sin** quórum y
    // la 6 abre igualmente.
    nodo.motor_votos
        .as_mut()
        .expect("motor")
        .poner_en_observacion();
    nodo.slot_votos_simulado = Some(5 * t);
    nodo.procesar_votos().expect("procesar 5");
    assert_eq!(
        nodo.motor_votos.as_ref().expect("motor").instancia_actual(),
        Some(5),
        "la ventana 4 cierra con certificado y la 5 abre sin emitir"
    );
    nodo.slot_votos_simulado = Some(6 * t);
    nodo.procesar_votos().expect("procesar 6");
    assert_eq!(
        nodo.motor_votos.as_ref().expect("motor").instancia_actual(),
        Some(6),
        "la ventana 6 abre tras cerrar la 5 sin quórum"
    );
    let registro_final =
        std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    let sin_quorum = registro_final.lines().any(|l| {
        l.contains("\"tipo\":\"ventana_cerrada\"")
            && l.contains("\"n\":5")
            && l.contains("\"certificado\":false")
    });
    assert!(
        sin_quorum,
        "la ventana 5 cierra sin quórum (control del camino común)"
    );
}

/// FV-N6-C7-3 · corrección 7: un salto de reloj a `n = m+2+1` con la ventana `m+1` abierta
/// **no** reutiliza la tabla comprometida renumerándola. El cierre ya adoptado no se pierde; el
/// Nodo observa el salto (`salto_tabla_no_sucesora`) sin abrir ni firmar la ventana saltada, y
/// el sucesor exacto (`m+2`) sí abre después.
#[test]
fn procesar_votos_observa_salto_sin_renombrar_tabla_y_luego_abre_sucesor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    let (motor, _est) = motor_con_ventana_uno_abierta();
    nodo.motor_votos = Some(motor);
    nodo.candidato_votos_simulado = Some(BlockHash::from_digest(Digest::from_bytes([0xAAu8; 32])));

    let t = t_inst();
    // Salto: reloj en 3 con la ventana 1 abierta (C_0 adoptado). Debe cerrar 1 y no abrir 3.
    nodo.slot_votos_simulado = Some(3 * t);
    nodo.procesar_votos().expect("procesar salto");
    {
        let m = nodo.motor_votos.as_ref().expect("motor");
        assert_eq!(m.instancia_actual(), None, "no se abre la ventana saltada");
        assert_eq!(
            m.ultimo_certificado_peso().map(|c| c.n),
            Some(1),
            "C_1 del cierre no se pierde en el salto"
        );
    }
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert!(
        registro.contains("\"motivo\":\"salto_tabla_no_sucesora\""),
        "el salto se observa con motivo: {registro}"
    );
    assert!(
        !registro
            .lines()
            .any(|l| l.contains("\"tipo\":\"ventana_abierta\"") && l.contains("\"n\":3")),
        "no se abre la ventana saltada"
    );
    assert!(
        !registro
            .lines()
            .any(|l| l.contains("\"tipo\":\"voto_emitido\"") && l.contains("\"n\":3")),
        "no se firma la ventana saltada"
    );

    // El sucesor exacto `m+2 = 2` sí abre con la tabla que dejó el cierre.
    nodo.slot_votos_simulado = Some(2 * t);
    nodo.procesar_votos().expect("procesar sucesor");
    assert_eq!(
        nodo.motor_votos.as_ref().expect("motor").instancia_actual(),
        Some(2),
        "el sucesor exacto abre tras observar el salto"
    );
}

/// ECL-R2b-2 · Prueba **roja** por el camino real de red: dos sobres `ZXV3` válidos (BLS
/// reales) con candidatos distintos para la misma clave e instancia. En el código viejo
/// `recibir_voto` rechazaba `otro_candidato` antes de validar y **no** generaba evidencia; aquí
/// se exige que la tx `0x0B` quede admitida en la mempool del Nodo.
#[test]
fn doble_voto_de_red_admite_evidencia_en_la_mempool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_de_prueba(dir.path());
    // Receptor: la ventana 0 abierta con candidato local `0x20`. Al abrir, el motor reinyecta
    // su propio voto (gossipsub no se lo devuelve), de modo que un único voto ajeno válido ya
    // cierra la pareja contradictoria.
    let (mut est, _sk) = estado_con(100);
    // El motor abre en PoST; el estado base de la mempool también, para que la evidencia `0x05`
    // sea aplicable contra la vista (clave BLS registrada y fianza presente).
    est.fase = zx_consensus::transicion::Fase::PoST;
    let mut receptor = motor_con(bls(1));
    receptor
        .avanzar(
            0,
            BlockHash::from_digest(Digest::from_bytes([0x20u8; 32])),
            &est,
            SLOT_FIXTURE,
        )
        .expect("abrir 0");
    nodo.motor_votos = Some(receptor);
    {
        let punto = nodo.punto_de_estado_virtual();
        let mut m = nodo.mempool.lock().expect("mempool");
        m.rebasear(est.clone(), Instant::now(), punto);
    }

    // Voto ajeno **auténtico**: misma clave BLS registrada, misma ancla/`h_T(1)`, otro candidato.
    let mut ajeno = motor_con(bls(1));
    let paso = ajeno
        .avanzar(
            0,
            BlockHash::from_digest(Digest::from_bytes([0x21u8; 32])),
            &est,
            SLOT_FIXTURE,
        )
        .expect("abrir ajeno");
    let sobre = paso.votos.first().expect("el ajeno emite su voto").clone();

    // En código viejo esto no toca la mempool; en el nuevo genera y admite la evidencia `0x0B`.
    nodo.procesar_voto_de_red(&sobre);

    let m = nodo.mempool.lock().expect("mempool");
    let hay = m.seleccionar(u64::MAX, 0).into_iter().any(|(tx, _)| {
        matches!(
            &tx.extension,
            ExtensionTx::PruebaAlmacenamiento {
                operacion: zx_core::OperacionAlmacenamiento::EvidenciaVotosPeso { .. }
            }
        )
    });
    assert!(
        hay,
        "la evidencia 0x0B del doble voto ajeno entra en la mempool"
    );
}

// ------------------------------------------------------------------
// CAND-1 · el candidato de la ventana sale de su slot de apertura
// ------------------------------------------------------------------

fn hash_cand1(n: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    for (destino, origen) in bytes.iter_mut().skip(28).zip(n.to_be_bytes()) {
        *destino = origen;
    }
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

/// Cadena de prueba con bloques PoST en slots consecutivos `1..=6` (ids `10..=15`) sobre un
/// génesis y un `PoW` terminal. Selección trivial con `K = 1`, `sr = 10`.
fn cadena_con_posts_consecutivos() -> Cadena {
    const MAX_PADRES: u8 = 15;
    const K: u32 = 1;

    fn subsidio_pow(_: u32) -> Amount {
        Amount::nuevo(10).expect("importe")
    }

    fn subsidio_post(_: u64) -> Amount {
        Amount::nuevo(3).expect("importe")
    }

    fn params() -> ParametrosTransicion {
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
            f_slots: None,
            subsidio_pow,
            subsidio_post,
        }
    }

    fn productor() -> ClaveEd {
        ClaveEd::desde_bytes([0x5a; 32])
    }

    fn tx_coinbase(clave: ClaveEd, slot: u64) -> Tx {
        Tx {
            version: 3,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::CoinbasePost {
                clave,
                importe: Amount::nuevo(1).expect("importe"),
                slot,
            },
        }
    }

    fn post(id: u32, padre: BlockHash, slot: u64) -> BloqueCadena {
        let productor = productor();
        let identidad =
            zx_dag::ghostdag::IdentidadGhostdag::Billete(zx_dag::IdentidadTicket::vigente(
                productor,
                0,
                u64::from(id) + 1,
                [(id & 0xff) as u8; 32],
                slot,
            ));
        BloqueCadena::Post(BloquePost {
            hash: hash_cand1(id),
            padres: vec![padre],
            slot,
            timestamp: 0,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
            sr: 10,
            distancia: 0,
            identidad,
            txs: vec![(tx_coinbase(productor, slot), Vec::new())],
        })
    }

    let mut cadena = Cadena::nueva(params(), K, zx_core::CBID_RED_DEV, MAX_PADRES);
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::Genesis {
                hash: hash_cand1(0),
            },
            Vec::new(),
        )))
        .expect("génesis");
    cadena
        .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
            HechosCabecera::PoW {
                hash: hash_cand1(1),
                padre: hash_cand1(0),
                altura: 1,
                trabajo: U256::from(1u64),
                pow_valido: true,
            },
            Vec::new(),
        )))
        .expect("pow terminal");
    let mut padre = hash_cand1(1);
    for i in 0u64..6 {
        let id = 10 + u32::try_from(i).expect("id");
        let b = post(id, padre, i + 1);
        cadena.admitir(b.clone()).expect("post");
        padre = b.hash();
    }
    cadena
}

/// Deja las ventanas 0 y 1 cerradas con certificado y la **2 abierta** (quórum real con 100
/// sectores), listo para que `procesar_votos` abra la 3.
fn motor_con_ventana_dos_abierta() -> MotorVotos {
    let (est, sk) = estado_con(100);
    let mut motor = motor_con(sk);
    for (n, byte) in [(0u64, 0x10u8), (1, 0x11), (2, 0x12)] {
        let c = BlockHash::from_digest(Digest::from_bytes([byte; 32]));
        motor.avanzar(n, c, &est, SLOT_FIXTURE).expect("abrir");
    }
    assert_eq!(motor.instancia_actual(), Some(2), "ventana 2 abierta");
    motor
}

/// Candidato de la ventana `n` leído del evento `ventana_abierta` del registro.
fn candidato_registrado(registro: &str, n: u64) -> String {
    let aguja = format!("\"n\":{n}");
    let linea = registro
        .lines()
        .find(|l| l.contains("\"tipo\":\"ventana_abierta\"") && l.contains(&aguja))
        .expect("hay ventana_abierta");
    linea
        .split("\"candidato\":\"")
        .nth(1)
        .expect("la ventana lleva candidato")
        .split('"')
        .next()
        .expect("el candidato cierra con comilla")
        .to_owned()
}

/// CAND-1 · Sobre **una misma** cadena con bloques PoST en slots consecutivos, la ventana `n`
/// elige el mismo candidato abriéndose en el primer slot de la ventana o en el último. El
/// candidato sale del tope de su slot de apertura (`n·t_inst - LAG_CANDIDATO_VOTOS`); con el
/// candidato atado al slot actual (código viejo) las dos elecciones difieren.
#[test]
fn candidato_de_ventana_no_depende_del_slot_en_que_se_abre() {
    let t = t_inst();
    let n = 3u64;
    let primero = n * t;
    let ultimo = (n + 1) * t - 1;

    let candidato_en = |slot: u64| -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut nodo = nodo_de_prueba(dir.path());
        nodo.cadena = cadena_con_posts_consecutivos();
        nodo.motor_votos = Some(motor_con_ventana_dos_abierta());
        nodo.slot_votos_simulado = Some(slot);
        nodo.procesar_votos().expect("procesar_votos");
        let registro =
            std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
        candidato_registrado(&registro, n)
    };

    let desde_primero = candidato_en(primero);
    let desde_ultimo = candidato_en(ultimo);
    // `n·t_inst - LAG = 6 - 4 = 2`: el bloque de mayor slot ≤ 2 es el del slot 2 (id 11).
    assert_eq!(
        desde_primero,
        hash_cand1(11).to_string(),
        "el candidato es el del tope del slot de apertura"
    );
    assert_eq!(
        desde_primero, desde_ultimo,
        "mismo candidato abriéndose en el primer slot ({primero}) o en el último ({ultimo})"
    );
}
