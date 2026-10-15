//! CAR-PROD: caracterización sin red por el despacho real de PeticionPadres.
//! Los controles de Cadena usan su interfaz de hechos; el rechazo propio añade PoAS/PoT reales.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "fixtures de caracterización que fallan por panic y comprueban sus tamaños"
)]

use super::pruebas_eclr2::{genesis, hash_u32, post_con_txs, tx_clave_voto, tx_coinbase_post};
use super::*;
use zx_consensus::sectores::{ClaveVoto, ParametrosSector, RegistroSector};
use zx_consensus::transicion::{EntradaUtxo, Fase, Garantia};
use zx_core::{
    Amount, BodyCommitment, HashType, Lock, MerkleRoot, OutPoint, SolucionPoas, SpentOutput, TxIn,
    TxOut,
};
use zx_votos::CertificadoPeso;

type TxTestigos = (Tx, Vec<Vec<u8>>);

fn bytes(par: &TxTestigos) -> u64 {
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, &par.0, &par.1);
    buf.len() as u64
}

fn estado_inicial(n_claves: usize) -> EstadoTransicion {
    assert!(n_claves >= 3);
    let mut estado = EstadoTransicion::inicial();
    for i in 0..n_claves {
        let indice = u32::try_from(i).expect("índice Ed25519");
        let c = ClaveDev::derivar(1, indice);
        let sk = crate::votos::clave_voto_dev(1, indice).expect("BLS dev");
        estado.claves_voto.insert(
            c.pk,
            ClaveVoto {
                clave_bls: sk.clave_publica().bytes(),
                prueba_posesion: zx_votos::probar_posesion(&sk).bytes(),
            },
        );
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(10_000).expect("garantía");
        estado.garantias.insert(c.pk, g);
        // Una clave tiene quórum con su peso real; las demás conservan un sector cada una.
        let sectores = if i == 0 { 2 * n_claves } else { 1 };
        for j in 0..sectores {
            let id = SectorId {
                clave: c.pk,
                sector_index: u16::try_from(j).expect("sector"),
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
                    fianza: ParametrosSector::dev().q_sec,
                    aud_apertura: -1,
                    aud_contestada: -1,
                },
            );
        }
    }
    estado
}

fn nodo_pow(dir: &Path, estado: EstadoTransicion) -> Nodo {
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
    let mut nodo = Nodo::arrancar(&cfg).expect("arranque sin red");
    let params = perfil::parametros_transicion_dev().expect("perfil dev íntegro");
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params,
        perfil::ghostdag_k(),
        nodo.cbid,
        perfil::ghostdag_max_padres(),
        perfil::parametros_evidencia_dev(),
        estado,
    );
    cadena.admitir(genesis()).expect("génesis");
    for altura in 1..=params.h_corte_min {
        cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::PoW {
                    hash: hash_u32(altura),
                    padre: hash_u32(altura - 1),
                    altura,
                    trabajo: params.w_min / U256::from(params.h_corte_min),
                    pow_valido: true,
                },
                Vec::new(),
            )))
            .expect("avance PoW por interfaz de hechos");
    }
    nodo.params = params;
    nodo.cadena = cadena;
    nodo
}

fn refrescar_cola(nodo: &mut Nodo, base: EstadoTransicion) {
    nodo.mempool = Arc::new(std::sync::Mutex::new(Mempool::nueva(
        nodo.params,
        perfil::parametros_evidencia_dev(),
        nodo.cbid,
        base,
        Politica::dev(),
    )));
}

fn nodo(dir: &Path, estado: EstadoTransicion) -> Nodo {
    let mut nodo = nodo_pow(dir, estado);
    let productor = nodo.claves[0].pk;
    nodo.cadena
        .admitir(post_con_txs(
            31,
            vec![hash_u32(nodo.params.h_corte_min)],
            1,
            u64::MAX,
            productor,
            vec![(
                tx_coinbase_post(productor, perfil::SUBSIDIO_POST_BREK, 1),
                Vec::new(),
            )],
        ))
        .expect("primer PoST real en Cadena");
    let base = nodo
        .cadena
        .estado_post(&hash_u32(31))
        .expect("estado PoST")
        .clone();
    assert_eq!(base.fase, Fase::PoST);
    refrescar_cola(&mut nodo, base);
    nodo
}

fn armar(nodo: &mut Nodo, slot: u64) -> Vec<TxTestigos> {
    let (tx, rx) = mpsc::channel();
    let terminal = nodo.cadena.terminal().expect("terminal");
    let resultado = nodo
        .atender_msg_productor(
            MsgProductor::PeticionPadres { id: 1, slot },
            false,
            terminal,
            &tx,
        )
        .expect("despacho REAL del productor");
    assert!(matches!(resultado, ControlBucle::Continuar));
    let MsgBucle::Padres { txs, testigos, .. } = rx.try_recv().expect("cuerpo enviado al hilo")
    else {
        panic!("respuesta distinta de Padres");
    };
    // Constructor real del receptor: tampoco rechaza aquí el exceso de tamaño.
    let cuerpo = zx_post::productor_regimen::CuerpoProductor::nuevo(txs, testigos)
        .expect("el receptor acepta el cuerpo");
    cuerpo
        .txs()
        .iter()
        .cloned()
        .zip(cuerpo.testigos().iter().cloned())
        .collect()
}

fn aplicar_cuerpo(
    nodo: &mut Nodo,
    id: u32,
    slot: u64,
    cuerpo: Vec<TxTestigos>,
) -> Result<(), MotivoBloque> {
    let padres = padres_de_regimen(&nodo.cadena).expect("padres reales");
    let mut pares = vec![(
        tx_coinbase_post(nodo.claves[0].pk, perfil::SUBSIDIO_POST_BREK, slot),
        Vec::new(),
    )];
    pares.extend(cuerpo);
    nodo.cadena.admitir(post_con_txs(
        id,
        std::iter::once(padres.seleccionado())
            .chain(padres.extras().iter().copied())
            .collect(),
        slot,
        u64::MAX,
        nodo.claves[0].pk,
        pares,
    ))
}

fn certificado(nodo: &mut Nodo) -> CertificadoPeso {
    certificado_de_base(nodo, hash_u32(31), 2)
}

fn certificado_de_base(nodo: &mut Nodo, padre: BlockHash, slot: u64) -> CertificadoPeso {
    let base = nodo.cadena.estado_post(&padre).expect("base");
    let tabla = tabla_peso_para_bloque(base, slot, 0);
    let sk = crate::votos::clave_voto_dev(1, 0).expect("BLS dev");
    let h = zx_votos::hash_tabla(&tabla);
    let pos = tabla
        .claves
        .iter()
        .position(|c| c.clave.as_slice() == sk.clave_publica().bytes())
        .expect("firmante");
    let firma = zx_votos::firmar(
        &sk,
        zx_votos::DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(0, padre.as_bytes(), &h, &[0; 32]),
    )
    .expect("firma real BLS");
    let cert = zx_votos::construir_certificado(
        0,
        *padre.as_bytes(),
        h,
        [0; 32],
        &tabla,
        &[(pos + 1, firma)],
    )
    .expect("certificado");
    let publicas = tabla
        .claves
        .iter()
        .map(|c| zx_votos::ClavePublica::desde_bytes(&c.clave).expect("BLS"))
        .collect();
    let mut motor = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: true,
    });
    motor
        .sembrar_punto_control_peso(tabla, publicas, cert.clone(), &[])
        .expect("punto de control con firma y quórum verificados");
    nodo.motor_votos = Some(motor);
    cert
}

/// Solo busca el umbral de longitud con el códec real. La validez se comprueba luego con
/// una tabla de claves distintas, el motor real y el control de Cadena, sin esta plantilla.
fn minimo_certificado() -> (usize, u64) {
    let sk = crate::votos::clave_voto_dev(1, 0).expect("BLS");
    let firma = zx_votos::firmar(&sk, zx_votos::DOMINIO_VOTO, &[0; 104]).expect("firma");
    let c = ClaveDev::derivar(1, 0);
    let coinbase = bytes(&(
        tx_coinbase_post(c.pk, perfil::SUBSIDIO_POST_BREK, 2),
        Vec::new(),
    ));
    for n in 1_usize..=4096 {
        let mut mapa = vec![0; n.div_ceil(8)];
        mapa[0] = 1;
        let cert = CertificadoPeso {
            n: 0,
            candidato: [0; 32],
            h_t_siguiente: [0; 32],
            raiz_estado: [0; 32],
            firma: zx_votos::FirmaAgregada::desde_firma(&firma),
            mapa,
        };
        let par = crate::votos::tx_certificado_peso(&cert, c.pk, &c.sk, zx_core::CBID_RED_DEV);
        if bytes(&par) + coinbase > MARGEN_COINBASE_POST {
            return (n, bytes(&par));
        }
    }
    panic!("umbral no alcanzado dentro del límite declarado de 4096 claves");
}

fn relleno(estado: &mut EstadoTransicion) -> Vec<TxTestigos> {
    let c = ClaveDev::derivar(1, 0);
    let presupuesto = perfil::MAX_CUERPO_BLOQUE_BYTES - MARGEN_COINBASE_POST;
    let mut pares = Vec::new();
    for i in 0_u32..4 {
        let op = OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes(
                [u8::try_from(i + 1).expect("id"); 32],
            )),
            prev_index: 0,
        };
        let mut tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::nuevo(1).expect("importe"),
                    lock: Lock::PubKey { pubkey: c.pk }
                };
                2000
            ],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        if i == 3 {
            let usados: u64 = pares.iter().map(bytes).sum();
            while usados + bytes(&(tx.clone(), vec![vec![0; 64]])) > presupuesto {
                tx.outputs.pop().expect("salida sobrante");
            }
            let mut hueco = presupuesto - usados - bytes(&(tx.clone(), vec![vec![0; 64]]));
            if !hueco.is_multiple_of(2) {
                tx.outputs.pop().expect("ajuste de paridad");
                hueco = presupuesto - usados - bytes(&(tx.clone(), vec![vec![0; 64]]));
            }
            for salida in tx
                .outputs
                .iter_mut()
                .take(usize::try_from(hueco.div_euclid(2)).expect("hueco"))
            {
                salida.lock = Lock::multisig(1, vec![c.pk]).expect("multisig válido");
            }
        }
        let valor =
            Amount::nuevo(i64::try_from(tx.outputs.len()).expect("valor")).expect("importe");
        estado.utxo.insert(
            op,
            EntradaUtxo {
                valor,
                lock: Lock::PubKey { pubkey: c.pk },
                origen: Origen::Tx,
                creada: Punto::Altura(0),
            },
        );
        let gastadas = [SpentOutput {
            value: valor,
            lock: Lock::PubKey { pubkey: c.pk },
        }];
        let digest = zx_core::sighash(&tx, &gastadas, HashType::All, 0, zx_core::CBID_RED_DEV)
            .expect("sighash");
        let firma: [u8; 64] = c.sk.sign(digest.as_bytes()).into();
        let par = (tx, vec![firma.to_vec()]);
        assert!(bytes(&par) <= perfil::MAX_TX_BYTES);
        pares.push(par);
    }
    assert_eq!(pares.iter().map(bytes).sum::<u64>(), presupuesto);
    pares
}

fn caso_b91(dir: &Path, lleno: bool) -> (Nodo, Vec<TxTestigos>, CertificadoPeso) {
    let (n, _) = minimo_certificado();
    let mut est = estado_inicial(n);
    let mut pares = relleno(&mut est);
    if !lleno {
        pares.pop().expect("retirar relleno deja hueco");
    }
    let mut nodo = nodo(dir, est);
    for (tx, tst) in &pares {
        nodo.mempool
            .lock()
            .expect("cola")
            .admitir(
                None,
                tx.clone(),
                tst.clone(),
                Instant::now(),
                Punto::Slot(2),
            )
            .expect("transferencia admitida por la cola real");
    }
    let cert = certificado(&mut nodo);
    (nodo, pares, cert)
}

#[test]
fn car_b91_cuerpo_lleno_mas_certificado_supera_el_tope() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, cola, cert) = caso_b91(dir.path(), true);
    let cuerpo = armar(&mut nodo, 2);
    assert_eq!(cuerpo.len(), cola.len());
    let c = &nodo.claves[0];
    let cert_tx = crate::votos::tx_certificado_peso(&cert, c.pk, &c.sk, nodo.cbid);
    assert_eq!(cuerpo.last().expect("certificado final"), &cert_tx);
    let cb = bytes(&(
        tx_coinbase_post(c.pk, perfil::SUBSIDIO_POST_BREK, 2),
        Vec::new(),
    ));
    let q: u64 = cola.iter().map(bytes).sum();
    let total = cuerpo.iter().map(bytes).sum::<u64>() + cb;
    let (n, tam_min) = minimo_certificado();
    assert_eq!(bytes(&cert_tx), tam_min);
    assert!(total <= nodo.params.max_cuerpo_bloque_bytes);
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    let recortes: Vec<_> = registro
        .lines()
        .filter(|linea| linea.contains("cuerpo_recortado"))
        .collect();
    assert!(
        recortes.is_empty(),
        "el certificado se reserva antes de pedir la cola: {recortes:?}"
    );
    let mut anterior = cert.clone();
    anterior.mapa.truncate((n - 1).div_ceil(8));
    assert!(
        q + cb
            + bytes(&crate::votos::tx_certificado_peso(
                &anterior, c.pk, &c.sk, nodo.cbid
            ))
            <= nodo.params.max_cuerpo_bloque_bytes
    );
    aplicar_cuerpo(&mut nodo, 100, 2, cuerpo).expect("el certificado cabe y el bloque entra");
    assert!(nodo.cadena.es_valido(&hash_u32(100)));
    assert_eq!(
        nodo.cadena
            .estado_post(&hash_u32(100))
            .expect("estado")
            .finalidad_votos,
        Some(hash_u32(31))
    );
    assert!(
        nodo.cadena
            .descartes(&hash_u32(100))
            .expect("descartes")
            .is_empty()
    );
    assert!(cola.iter().all(|(tx, _)| {
        nodo.mempool
            .lock()
            .expect("cola")
            .contiene(&txid(tx, nodo.cbid))
    }));
    println!(
        "B91 reparado tope={} cola_candidata={q} coinbase={cb} certificado_tx={} certificado_payload={} claves_min={n} total={total} admitido=true",
        nodo.params.max_cuerpo_bloque_bytes,
        bytes(&cert_tx),
        zx_votos::peso::serial_certificado_peso(&cert).len()
    );
}

#[test]
fn car_b91_con_hueco_suficiente_el_bloque_entra() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, _, _) = caso_b91(dir.path(), false);
    let cuerpo = armar(&mut nodo, 2);
    aplicar_cuerpo(&mut nodo, 100, 2, cuerpo).expect("mismo certificado, bloque con hueco");
    let est = nodo.cadena.estado_post(&hash_u32(100)).expect("aplicado");
    assert_eq!(est.finalidad_votos, Some(hash_u32(31)));
    assert_eq!(est.finalidad_votos_n, 0);
    assert!(
        nodo.cadena
            .descartes(&hash_u32(100))
            .expect("descartes")
            .is_empty()
    );
    println!("B91 control: bloque y certificado aplicados, descartes=0");
}

#[test]
fn car_b91_el_rechazo_real_de_la_cadena_se_clasifica_interno() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, mut cuerpo, cert) = caso_b91(dir.path(), true);
    let c = &nodo.claves[0];
    cuerpo.push(crate::votos::tx_certificado_peso(
        &cert, c.pk, &c.sk, nodo.cbid,
    ));
    let err = aplicar_cuerpo(&mut nodo, 100, 2, cuerpo).expect_err("tamaño");
    let clasificacion = crate::rechazo::clasificar_motivo_bloque(&err);
    assert_eq!(clasificacion, crate::rechazo::ClasificacionRechazo::Interno);
    assert!(!clasificacion.es_legitimo());
    println!(
        "B91 clasificación real: {clasificacion:?}; motivo literal={}",
        err.nombre()
    );
}

#[test]
fn car_b91_que_hace_el_nodo_cuando_su_bloque_propio_se_rechaza_por_tamano() {
    use zx_post::productor_regimen::{CuerpoProductor, ErrorRegimen, preparar_regimen_para_ensayo};

    let dir = tempfile::tempdir().expect("temporal");
    let (n, _) = minimo_certificado();
    let mut est = estado_inicial(n);
    let cola = relleno(&mut est);
    let mut nodo = nodo_pow(dir.path(), est);
    // El fixture general pide parada en slot 0; aquí se comprueba la continuidad tras admisión.
    nodo.parada_tras_slots = None;
    let terminal = nodo.cadena.terminal().expect("terminal real de Cadena");
    let c = nodo.claves[0].clone();
    let historia = Arc::clone(&nodo.historia);
    let parcela = abrir_o_crear_parcela(&nodo.dir_datos, &c, &historia).expect("parcela REAL");
    let fuente = FuenteTransicion {
        parcela: &parcela,
        historia: &historia,
    };
    let params = ParametrosProductor {
        n_dev: nodo.n_dev,
        sr_dev: nodo.sr_dev_actual,
        max_slots: MAX_BUNDLES_POT as u64,
        consensus_branch_id: nodo.cbid,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("reloj")
            .as_secs(),
        i_iter: 0,
        importe_coinbase: perfil::subsidio_post(0),
    };
    let registro =
        RegistroFirmante::nueva(dir.path().join("firmante-prueba")).expect("registro real nuevo");
    let mut firmante = Firmante::nuevo(&registro);
    let ProductoFirmado::Bloque(primero, _) =
        producir_con_firmante(terminal, &fuente, &c.sk, &params, &mut firmante)
            .expect("PoAS/PoT reales")
    else {
        panic!("abstención inesperada en fixture nuevo");
    };
    let padre = primero.cabecera.block_hash();
    let slot_padre = primero.cabecera.slot;
    nodo.admitir_post_interno(primero, 0, true)
        .expect("puerta conjunta REAL y cadena admiten el padre");
    assert!(!nodo.poas_simulada);
    let base = nodo.cadena.estado_post(&padre).expect("base real").clone();
    refrescar_cola(&mut nodo, base);
    for (tx, tst) in &cola {
        nodo.mempool
            .lock()
            .expect("cola")
            .admitir(
                None,
                tx.clone(),
                tst.clone(),
                Instant::now(),
                Punto::Slot(slot_padre + 1),
            )
            .expect("admisión real del relleno");
    }
    certificado_de_base(&mut nodo, padre, slot_padre + 1);
    let mut servicio = nodo
        .servicios_verificacion
        .get(&terminal)
        .expect("ServicioPot real")
        .clone();
    let mut bloque = None;
    for slot in slot_padre + 1..=slot_padre + 64 {
        let pares = armar(&mut nodo, slot);
        let (txs, testigos) = pares.into_iter().unzip();
        let cuerpo = CuerpoProductor::nuevo(txs, testigos).expect("cuerpo real del nodo");
        let padres = padres_de_regimen(&nodo.cadena).expect("padres");
        match preparar_regimen_para_ensayo(
            padres,
            slot,
            &mut servicio,
            &fuente,
            &c.sk,
            &params,
            cuerpo,
        ) {
            Ok(c) => {
                bloque = Some(c);
                break;
            }
            Err(ErrorRegimen::SinSolucion { .. }) => {}
            Err(e) => panic!("productor real: {e:?}"),
        }
    }
    let bloque = bloque.expect("solución real dentro de la búsqueda acotada");
    let pre_hash = bloque.cabecera.pre_hash();
    let total: u64 = bloque
        .txs()
        .iter()
        .cloned()
        .zip(bloque.testigos().iter().cloned())
        .map(|p| bytes(&p))
        .sum();
    assert!(total <= nodo.params.max_cuerpo_bloque_bytes);
    let (tx, rx) = mpsc::channel();
    // PROD-3b: el camino real es la candidata sin sello → firma_contextual → admisión.
    let destino = nodo
        .procesar_candidata_propia(2, bloque, Instant::now(), 0, terminal, false, &tx)
        .expect("el despacho admite la candidata propia");
    let crate::nodo::firma_contextual::DestinoCandidata::Admitido { hash } = destino else {
        panic!("la candidata debe admitirse: {destino:?}");
    };
    assert!(matches!(
        rx.try_recv().expect("respuesta al productor"),
        MsgBucle::Continuar { .. }
    ));
    assert!(nodo.cadena.es_valido(&hash));
    assert!(nodo.cadena.descartes(&hash).expect("descartes").is_empty());
    println!(
        "B91 nodo real reparado: total={total}; pre_hash={pre_hash:?}; respuesta=Continuar; poas_simulada=false; firmante=bucle"
    );
}

fn evidencia() -> Tx {
    let c = ClaveDev::derivar(1, 1);
    let mut h1 = zx_core::DagBlockHeader {
        vdf_output: [0; 16],
        consensus_branch_id: zx_core::CBID_RED_DEV,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
        timestamp: 1,
        height: 0,
        slot: 1,
        pot_output: [0; 16],
        rango_solucion: u64::MAX,
        sol: SolucionPoas {
            public_key: c.pk,
            sector_index: 0,
            history_size: 1,
            chunk: [1; 32],
            ..Default::default()
        },
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
        padres: PadresDag::nuevo(hash_u32(30), &[]).expect("padres"),
        sello: [0; 64],
    };
    let mut h2 = h1;
    h2.timestamp = 2;
    h1.sello = c.sk.sign(h1.pre_hash().as_bytes()).into();
    h2.sello = c.sk.sign(h2.pre_hash().as_bytes()).into();
    h1.verificar_sello().expect("sello 1 real");
    h2.verificar_sello().expect("sello 2 real");
    let mut detector =
        crate::evidencia::DetectorDobleFirma::nuevo(perfil::MAX_IDENTIDADES_DETECTOR);
    detector.observar(h1);
    detector.observar(h2);
    detector
        .pendientes()
        .next()
        .expect("incidente firmado")
        .tx
        .clone()
}

#[test]
fn car_b94_la_evidencia_v4_de_la_cola_no_entra_en_el_cuerpo() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path(), estado_inicial(3));
    let ev = evidencia();
    let id = txid(&ev, nodo.cbid);
    nodo.mempool
        .lock()
        .expect("cola")
        .admitir(None, ev, Vec::new(), Instant::now(), Punto::Slot(2))
        .expect("v4 admitida");
    assert_eq!(nodo.detector.pendientes_len(), 0);
    assert_eq!(
        nodo.mempool
            .lock()
            .expect("cola")
            .seleccionar(nodo.params.max_cuerpo_bloque_bytes, 1)
            .len(),
        1
    );
    let cuerpo = armar(&mut nodo, 2);
    assert_eq!(cuerpo.len(), 1);
    assert_eq!(txid(&cuerpo[0].0, nodo.cbid), id);
    assert!(nodo.mempool.lock().expect("cola").contiene(&id));
    aplicar_cuerpo(&mut nodo, 100, 2, cuerpo).expect("bloque con evidencia de cola");
    let g = nodo
        .cadena
        .estado_post(&hash_u32(100))
        .expect("estado")
        .garantias
        .get(&ClaveDev::derivar(1, 1).pk)
        .expect("garantía");
    assert_eq!(g.incidentes.len(), 1);
    assert_eq!(g.activo, Amount::CERO);
    assert!(
        nodo.cadena
            .descartes(&hash_u32(100))
            .expect("descartes")
            .is_empty()
    );
    println!(
        "B94 reparado seleccionada=1 cuerpo=1 pendiente=1 incidentes=1 activo={}",
        g.activo.brek()
    );
}

#[test]
fn car_b94_la_misma_evidencia_en_un_bloque_castiga() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path(), estado_inicial(3));
    let ev = evidencia();
    aplicar_cuerpo(&mut nodo, 100, 2, vec![(ev, Vec::new())])
        .expect("evidencia aplicada directamente");
    let g = nodo
        .cadena
        .estado_post(&hash_u32(100))
        .expect("estado")
        .garantias
        .get(&ClaveDev::derivar(1, 1).pk)
        .expect("garantía");
    assert_eq!(g.incidentes.len(), 1);
    assert_eq!(g.activo, Amount::CERO);
    assert!(
        nodo.cadena
            .descartes(&hash_u32(100))
            .expect("descartes")
            .is_empty()
    );
    println!(
        "B94 control: incidentes=1 activo={} congelado={}",
        g.activo.brek(),
        g.congelado.brek()
    );
}

fn voto_anterior(dir: &Path) -> (Nodo, TxTestigos, u64) {
    let mut nodo = nodo(dir, estado_inicial(3));
    let c = nodo.claves[0].clone();
    let anterior = crate::votos::clave_voto_dev(1, 0).expect("anterior");
    let actual = crate::votos::clave_voto_dev(2, 0).expect("actual");
    let rotacion = tx_clave_voto(c.pk, &c.sk, &actual.clave_publica(), &actual, nodo.cbid);
    aplicar_cuerpo(&mut nodo, 32, 2, vec![rotacion]).expect("rotación real 0x03");
    let vencimiento = nodo
        .cadena
        .estado_post(&hash_u32(32))
        .expect("estado")
        .claves_voto_previas
        .get(&c.pk)
        .expect("anterior retenida")
        .vencimiento;
    let n = (vencimiento - G_SLOTS_VOTOS).div_euclid(2) - 1;
    let slot = cierre_ventana(n) + G_SLOTS_VOTOS;
    assert_eq!(slot, vencimiento);
    // Se avanza por bloques, respetando F dev sin cambiarlo para el fixture.
    aplicar_cuerpo(&mut nodo, 33, slot.div_euclid(2), Vec::new()).expect("avance intermedio");
    aplicar_cuerpo(&mut nodo, 34, slot - 1, Vec::new()).expect("padre previo");
    let candidato = *hash_u32(31).as_bytes();
    let h = [0x22; 32];
    let raiz = [0x33; 32];
    let firma = zx_votos::firmar(
        &anterior,
        zx_votos::DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h, &raiz),
    )
    .expect("firma BLS anterior real");
    let par = crate::votos::tx_voto_propio(
        &crate::votos::VotoPropioPayload {
            n,
            candidato,
            h_t_siguiente: h,
            raiz_estado: raiz,
            clave_bls: anterior.clave_publica().bytes(),
            firma: firma.bytes(),
        },
        c.pk,
        &c.sk,
        nodo.cbid,
    );
    (nodo, par, slot)
}

#[test]
fn car_b96_el_voto_con_la_clave_anterior_viva_no_entra_en_el_cuerpo() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, par, slot) = voto_anterior(dir.path());
    let id = txid(&par.0, nodo.cbid);
    let n = metadatos_v6(&par.0).expect("ventana").1;
    nodo.encolar_v6(par.0, par.1, true);
    assert_eq!(nodo.v6_pendientes.len(), 1);
    let p = &nodo.v6_pendientes[0];
    assert!(p.desde_slot <= slot && slot <= p.hasta_slot);
    let cuerpo = armar(&mut nodo, slot);
    assert_eq!(cuerpo.len(), 1);
    assert_eq!(txid(&cuerpo[0].0, nodo.cbid), id);
    assert_eq!(nodo.v6_pendientes.len(), 1);
    aplicar_cuerpo(&mut nodo, 100, slot, cuerpo).expect("voto anterior incluido y aplicado");
    assert!(
        nodo.cadena
            .estado_post(&hash_u32(100))
            .expect("estado")
            .votantes_voto
            .get(&n)
            .expect("votantes")
            .contains(&nodo.claves[0].pk)
    );
    assert!(
        nodo.cadena
            .descartes(&hash_u32(100))
            .expect("descartes")
            .is_empty()
    );
    println!("B96 reparado slot={slot} vencimiento={slot} pendientes=1 cuerpo=1 aplicado=true");
}

#[test]
fn car_b96_la_cadena_lo_aplica() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, par, slot) = voto_anterior(dir.path());
    let n = metadatos_v6(&par.0).expect("ventana").1;
    aplicar_cuerpo(&mut nodo, 100, slot, vec![par]).expect("bloque con voto anterior vivo");
    assert!(
        nodo.cadena
            .estado_post(&hash_u32(100))
            .expect("estado")
            .votantes_voto
            .get(&n)
            .expect("votantes")
            .contains(&nodo.claves[0].pk)
    );
    assert!(
        nodo.cadena
            .descartes(&hash_u32(100))
            .expect("descartes")
            .is_empty()
    );
    println!("B96 control: voto aplicado n={n} slot={slot}, descartes=0");
}

#[test]
fn car_b96_con_la_anterior_vencida_la_cadena_lo_rechaza() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, par, slot) = voto_anterior(dir.path());
    let n = metadatos_v6(&par.0).expect("ventana").1;
    let id = txid(&par.0, nodo.cbid);
    assert!(slot < cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS);
    aplicar_cuerpo(&mut nodo, 100, slot + 1, vec![par])
        .expect("fusión descarta la tx, admite bloque");
    let descartes = nodo.cadena.descartes(&hash_u32(100)).expect("descartes");
    assert_eq!(descartes.len(), 1);
    assert_eq!(descartes[0].txid, id);
    assert_eq!(
        descartes[0].motivo,
        zx_consensus::transicion::ErrorTransicion::ErrVotoPropioClave
    );
    assert!(
        !nodo
            .cadena
            .estado_post(&hash_u32(100))
            .expect("estado")
            .votantes_voto
            .get(&n)
            .is_some_and(|v| v.contains(&nodo.claves[0].pk))
    );
    println!(
        "B96 control vencida slot={} tx descartada={:?}",
        slot + 1,
        descartes[0]
    );
}

/// Tamaño máximo real del códec, inyectado en el mismo armado que llama PeticionPadres.
/// No se afirma validez BLS de esta plantilla: la tabla de 65536 no se firma en este test.
#[test]
fn prod1_con_la_tabla_llena_el_certificado_cabe_y_la_cola_cede() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut estado = estado_inicial(3);
    let cola = relleno(&mut estado);
    let mut nodo = nodo(dir.path(), estado);
    for par in &cola {
        nodo.mempool
            .lock()
            .expect("cola")
            .admitir(
                None,
                par.0.clone(),
                par.1.clone(),
                Instant::now(),
                Punto::Slot(2),
            )
            .expect("admitida");
    }
    let mut cert = certificado(&mut nodo);
    cert.mapa = vec![0xff; zx_consensus::transicion::votos::MAX_CLAVES_TABLA.div_ceil(8)];
    let c = &nodo.claves[0];
    let cert_tx = crate::votos::tx_certificado_peso(&cert, c.pk, &c.sk, nodo.cbid);
    let coinbase = tx_coinbase_post(c.pk, perfil::SUBSIDIO_POST_BREK, 2);
    let bytes_cb = bytes(&(coinbase.clone(), Vec::new()));
    let bytes_cert = bytes(&cert_tx);
    let payload = zx_votos::peso::serial_certificado_peso(&cert);
    assert_eq!(payload.len(), 200 + 8192);
    assert_eq!(
        zx_votos::peso::deserializar_certificado_peso(&payload, 65_536).expect("códec máximo"),
        cert
    );
    let cuerpo = presupuestar_cuerpo_post(
        &coinbase,
        Some(cert_tx.clone()),
        Vec::new,
        Vec::new(),
        nodo.params.max_cuerpo_bloque_bytes,
        |max_cola| {
            assert_eq!(
                max_cola,
                nodo.params.max_cuerpo_bloque_bytes - bytes_cb - bytes_cert
            );
            nodo.mempool.lock().expect("cola").seleccionar(max_cola, 42)
        },
    )
    .expect("armado real con certificado máximo");
    let pares: Vec<_> = cuerpo.txs.into_iter().zip(cuerpo.testigos).collect();
    assert_eq!(pares.last(), Some(&cert_tx));
    assert_eq!(pares.len(), cola.len());
    assert!(cuerpo.recorte.is_none());
    let total = bytes_cb + pares.iter().map(bytes).sum::<u64>();
    assert!(total <= nodo.params.max_cuerpo_bloque_bytes);
    assert!(cola.iter().all(|par| {
        nodo.mempool
            .lock()
            .expect("cola")
            .contiene(&txid(&par.0, nodo.cbid))
    }));
    println!(
        "PROD1 máximo claves=65536 payload={} certificado_tx={bytes_cert} coinbase={bytes_cb} total={total} tope={} tx_cola_candidatas=4 tx_cola_incluidas=3 BLS_maximo=no_verificado",
        payload.len(),
        nodo.params.max_cuerpo_bloque_bytes
    );
}

#[test]
fn prod1_la_evidencia_repetida_en_cola_y_detector_entra_una_vez() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut nodo = nodo(dir.path(), estado_inicial(3));
    let ev = evidencia();
    let ExtensionTx::Evidencia { h1, h2 } = &ev.extension else {
        panic!("evidencia");
    };
    nodo.detector.observar(*h1);
    nodo.detector.observar(*h2);
    // Un tercer bloque del mismo billete produce otro txid y el mismo incidente.
    let mut h3 = *h2;
    h3.timestamp += 1;
    let c = ClaveDev::derivar(1, 1);
    h3.sello = c.sk.sign(h3.pre_hash().as_bytes()).into();
    let mut otro = crate::evidencia::DetectorDobleFirma::nuevo(perfil::MAX_IDENTIDADES_DETECTOR);
    otro.observar(*h1);
    otro.observar(h3);
    let ev_cola = otro
        .pendientes()
        .next()
        .expect("mismo incidente")
        .tx
        .clone();
    assert_ne!(txid(&ev, nodo.cbid), txid(&ev_cola, nodo.cbid));
    nodo.mempool
        .lock()
        .expect("cola")
        .admitir(None, ev_cola, Vec::new(), Instant::now(), Punto::Slot(2))
        .expect("cola");
    let cuerpo = armar(&mut nodo, 2);
    assert_eq!(cuerpo.len(), 1);
    assert_eq!(cuerpo[0].0, ev);
    aplicar_cuerpo(&mut nodo, 100, 2, cuerpo).expect("un incidente");
    let g = nodo
        .cadena
        .estado_post(&hash_u32(100))
        .expect("estado")
        .garantias
        .get(&c.pk)
        .expect("garantía");
    assert_eq!(g.incidentes.len(), 1);
    assert_eq!(g.activo, Amount::CERO);
    assert!(
        nodo.cadena
            .descartes(&hash_u32(100))
            .expect("descartes")
            .is_empty()
    );
    assert_eq!(nodo.detector.pendientes_len(), 1);
    assert_eq!(
        nodo.mempool
            .lock()
            .expect("cola")
            .elegir_evidencias(usize::MAX)
            .len(),
        1
    );
    println!(
        "PROD1 dos txid, un incidente; incluida=1 castigos=1 detector_pendiente=1 cola_pendiente=1"
    );
}

/// Fuerza la defensa P2 con una selección que ignora adrede el presupuesto recibido.
#[test]
fn prod1_lo_recortado_sigue_en_la_cola() {
    let dir = tempfile::tempdir().expect("temporal");
    let mut estado = estado_inicial(3);
    let cola = relleno(&mut estado);
    let mut nodo = nodo(dir.path(), estado);
    for par in &cola {
        nodo.mempool
            .lock()
            .expect("cola")
            .admitir(
                None,
                par.0.clone(),
                par.1.clone(),
                Instant::now(),
                Punto::Slot(2),
            )
            .expect("cola");
    }
    let coinbase = tx_coinbase_post(nodo.claves[0].pk, perfil::SUBSIDIO_POST_BREK, 2);
    let antes = bytes(&(coinbase.clone(), Vec::new())) + cola.iter().map(bytes).sum::<u64>();
    let tope = antes - 1;
    let cuerpo =
        presupuestar_cuerpo_post(&coinbase, None, Vec::new, Vec::new(), tope, |max_cola| {
            assert_eq!(max_cola, cola.iter().map(bytes).sum::<u64>() - 1);
            nodo.mempool
                .lock()
                .expect("cola")
                .seleccionar(nodo.params.max_cuerpo_bloque_bytes, 42)
        })
        .expect("recorte de defensa");
    let (original, despues) = cuerpo.recorte.expect("recorte activado");
    assert_eq!(original, antes);
    assert!(despues <= tope);
    assert_eq!(cuerpo.txs.len(), cola.len() - 1);
    assert!(cola.iter().all(|par| {
        nodo.mempool
            .lock()
            .expect("cola")
            .contiene(&txid(&par.0, nodo.cbid))
    }));
    let siguiente = armar(&mut nodo, 2);
    assert_eq!(
        siguiente.len(),
        cola.len(),
        "las cuatro vuelven a ser seleccionables"
    );
    println!(
        "PROD1 recorte bytes_antes={antes} bytes_despues={despues} tope={tope} cola_pendiente=4 seleccion_siguiente=4"
    );
}

#[test]
fn prod1_cola_y_detector_comparten_plazo_y_tope_de_evidencias() {
    // Fixture solo del filtro de elegibilidad; no afirma validación de estos sellos alterados.
    let ev = evidencia();
    let detector = crate::evidencia::DetectorDobleFirma::nuevo(perfil::MAX_IDENTIDADES_DETECTOR);
    let plazo = perfil::parametros_evidencia_dev().plazo_slots;
    let evidencias: Vec<_> = (0..6)
        .map(|sector| {
            let mut tx = ev.clone();
            let ExtensionTx::Evidencia { h1, h2 } = &mut tx.extension else {
                panic!("v4");
            };
            h1.sol.sector_index = sector;
            h2.sol.sector_index = sector;
            (tx, Vec::new())
        })
        .collect();
    assert_eq!(
        evidencias_para_cuerpo_post(&detector, evidencias.clone(), None, 1, plazo, 4).len(),
        4
    );
    assert_eq!(
        evidencias_para_cuerpo_post(&detector, evidencias.clone(), None, plazo, plazo, 4).len(),
        4
    );
    assert!(
        evidencias_para_cuerpo_post(&detector, evidencias.clone(), None, 0, plazo, 4).is_empty()
    );
    assert!(
        evidencias_para_cuerpo_post(&detector, evidencias, None, plazo + 1, plazo, 4).is_empty()
    );
}

#[test]
fn prod1_clave_anterior_no_entra_despues_del_vencimiento() {
    let dir = tempfile::tempdir().expect("temporal");
    let (mut nodo, par, slot) = voto_anterior(dir.path());
    nodo.encolar_v6(par.0, par.1, true);
    let cuerpo = armar(&mut nodo, slot + 1);
    assert!(cuerpo.is_empty());
    assert_eq!(nodo.v6_pendientes.len(), 1);
}
// DG-ACTA: caracterización del motor, la cola auxiliar, el armado y la Cadena reales.
// No altera producto ni fuerza los descartes. Solo el reloj del nodo se fija como en
// las pruebas existentes; candidato, tabla, firmas y transición son de producto.
#[allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "pruebas con fallo por panic y escenarios completos"
)]
mod dgacta {
    use super::*;
    use crate::votos::{ConfigMotorVotos, RecepcionAgregado};
    use zx_consensus::transicion::{ErrorTransicion, aplicar_fusion};
    use zx_votos::agregacion::{Agregado, DOMINIO_SORTEO, MensajeVoto, Reparto};

    const N: u64 = 5;
    // La ventana 5 cierra en 12; el receptor lento la cierra en 14, después de
    // que otro reportero pudo incluir un acta de esa misma ventana en 13.
    const SLOT: u64 = 14;
    const DEN: i64 = 1_401_600_000;

    fn escenario(dir: &Path) -> (Nodo, CertificadoPeso) {
        let mut estado = estado_inicial(3);
        for garantia in estado.garantias.values_mut() {
            garantia.activo = Amount::nuevo(DEN).expect("garantía visible al liquidar");
        }
        let mut nodo = nodo(dir, estado);
        let cert = certificado(&mut nodo);
        let c = nodo.claves[0].clone();
        let par = crate::votos::tx_certificado_peso(&cert, c.pk, &c.sk, nodo.cbid);
        aplicar_cuerpo(&mut nodo, 32, 2, vec![par]).expect("base certificada real");
        assert!(nodo.cadena.descartes(&hash_u32(32)).unwrap().is_empty());
        (nodo, cert)
    }

    pub(super) fn motor_abierto(nodo: &Nodo, cert: CertificadoPeso, suelto: bool) -> MotorVotos {
        let estado = nodo
            .cadena
            .estado_post(&hash_u32(32))
            .expect("base certificada");
        let tabla = tabla_peso_para_bloque(estado, 2, 0);
        let pubs = tabla
            .claves
            .iter()
            .map(|c| zx_votos::ClavePublica::desde_bytes(&c.clave).expect("BLS real"))
            .collect();
        let sk = crate::votos::clave_voto_dev(1, 1).expect("BLS del votante minoritario");
        let mut motor = MotorVotos::nuevo_con_subredes(
            ConfigMotorVotos {
                perfil: perfil::parametros_votos_dev(),
                claves: if suelto { vec![sk] } else { Vec::new() },
                emitir_votos: suelto,
            },
            1,
        );
        motor
            .sembrar_punto_control_peso(tabla, pubs, cert, &[])
            .expect("checkpoint verificado");
        motor
            .avanzar(N, hash_u32(31), estado, 10)
            .expect("ventana con tabla real");
        motor
    }

    fn agregado(motor: &MotorVotos, estado: &EstadoTransicion, indice: u32) -> Agregado {
        let tabla = motor.tabla_actual().expect("tabla abierta");
        let reparto = Reparto::construir(tabla, 1).expect("una subred");
        let sk = crate::votos::clave_voto_dev(1, indice).expect("BLS");
        let global = tabla
            .claves
            .iter()
            .position(|c| c.clave.as_slice() == sk.clave_publica().bytes())
            .expect("firmante");
        let local = reparto
            .claves_de(0)
            .iter()
            .position(|p| *p == global)
            .expect("posición local");
        let mut mapa_local = vec![0; reparto.claves_de(0).len().div_ceil(8)];
        mapa_local[local >> 3] |= 1 << (local & 7);
        let mensaje = MensajeVoto {
            n: N,
            candidato: *hash_u32(31).as_bytes(),
            h_t_siguiente: estado.cola_tablas_voto.last().expect("Q real").1,
            raiz_estado: [0; 32],
        };
        let firma =
            zx_votos::firmar(&sk, zx_votos::DOMINIO_VOTO, &mensaje.mensaje()).expect("firma real");
        Agregado {
            n: N,
            candidato: mensaje.candidato,
            h_t_siguiente: mensaje.h_t_siguiente,
            raiz_estado: mensaje.raiz_estado,
            firma_agregada: zx_votos::agregar_firmas(&[&firma]).expect("agregación real"),
            huella_tabla: zx_votos::hash_tabla(tabla),
            subred: 0,
            indice_agregadora: u16::try_from(local).expect("índice"),
            mapa_local,
            firma_sorteo: zx_votos::firmar(&sk, DOMINIO_SORTEO, &N.to_be_bytes())
                .expect("sorteo real"),
        }
    }

    fn encolar_desde_motor(nodo: &mut Nodo, cert: CertificadoPeso, suelto: bool) {
        let mut motor = motor_abierto(nodo, cert, suelto);
        if !suelto {
            let estado = nodo.cadena.estado_post(&hash_u32(32)).unwrap();
            let ag = agregado(&motor, estado, 1);
            assert_eq!(
                motor.recibir_agregados(&[ag]).expect("recepción BLS real"),
                vec![RecepcionAgregado::Reenviar]
            );
        }
        nodo.motor_votos = Some(motor);
        nodo.slot_votos_simulado = Some(SLOT);
        nodo.procesar_votos()
            .expect("cierre y encolado por ruta REAL");
        let actas: Vec<_> = nodo
            .v6_pendientes
            .iter()
            .filter(|p| p.clase == CLASE_ACTA_PESO)
            .collect();
        assert_eq!(actas.len(), 1);
        assert_eq!(actas[0].n, N);
        // ACTA-1 · R4 · la lista auxiliar trae **todos** los firmantes del mapa, también los
        // agregados: da igual que el voto llegara suelto o agregado (1 firmante real en ambos casos).
        assert_eq!(
            actas[0].firmantes_acta.len(),
            1,
            "la lista auxiliar debe traer todos los firmantes del mapa"
        );
        assert!(actas[0].propia);
    }

    fn constan(nodo: &Nodo, bloque: u32) -> bool {
        constan_pk(nodo, bloque, ClaveDev::derivar(1, 1).pk)
    }

    fn constan_pk(nodo: &Nodo, bloque: u32, pk: zx_core::ClavePublica) -> bool {
        nodo.cadena
            .estado_post(&hash_u32(bloque))
            .expect("estado real")
            .votantes_voto
            .get(&N)
            .is_some_and(|v| v.contains(&pk))
    }

    fn liquidar(estado: &EstadoTransicion, nodo: &Nodo) -> EstadoTransicion {
        let slot = cierre_ventana(N) + W_REVEAL_SLOTS_VOTOS + 1;
        let bloque = BloqueTransicion::nuevo(
            HechosCabecera::PoST {
                hash: hash_u32(999),
                padre: hash_u32(100),
                slot,
                productor: nodo.claves[0].pk,
                peso: 1,
                prueba_valida: true,
                requisito_declarado: 0,
            },
            Vec::new(),
        );
        let (nuevo, _, descartes) = aplicar_fusion(
            estado,
            &bloque,
            Punto::Slot(slot),
            &nodo.params,
            nodo.cbid,
            &perfil::parametros_evidencia_dev(),
        )
        .expect("liquidación REAL");
        assert!(descartes.is_empty());
        assert_eq!(nuevo.liquidacion_voto_hasta, Some(N));
        nuevo
    }

    #[test]
    fn dgacta_agregado_sin_lista_se_reincluye_pero_consta_sin_multa_control_rojo() {
        let dir = tempfile::tempdir().expect("temporal");
        let (mut nodo, cert) = escenario(dir.path());
        encolar_desde_motor(&mut nodo, cert, false);
        let sin_acta = nodo.cadena.estado_post(&hash_u32(32)).unwrap().clone();
        // ACTA-1 · control rojo: con el filtro viejo (lista solo de sueltos, aquí vacía) el acta se
        // reincluía en cada bloque hasta el plazo (2 descartes `ErrActaRepetida`); con la decisión
        // de la cadena entra UNA vez y no vuelve a entrar.
        let cuerpo = armar(&mut nodo, SLOT);
        assert_eq!(cuerpo.len(), 1);
        let id = txid(&cuerpo[0].0, nodo.cbid);
        let tam = bytes(&cuerpo[0]);
        aplicar_cuerpo(&mut nodo, 100, SLOT, cuerpo).expect("primer acta");
        assert!(constan(&nodo, 100));
        assert!(nodo.cadena.descartes(&hash_u32(100)).unwrap().is_empty());
        let presente = nodo.cadena.estado_post(&hash_u32(100)).unwrap().clone();
        // Diez bloques propios siguientes: el acta no se reincluye y la cadena no descarta nada.
        let mut repeticiones = 0_usize;
        for (bloque, slot) in (101_u32..=110).zip((SLOT + 1)..=(SLOT + 10)) {
            let cuerpo = armar(&mut nodo, slot);
            assert!(
                !cuerpo.iter().any(|(tx, _)| txid(tx, nodo.cbid) == id),
                "el acta consta entera: no debe reincluirse"
            );
            aplicar_cuerpo(&mut nodo, bloque, slot, cuerpo).expect("bloque propio sin acta");
            repeticiones += nodo
                .cadena
                .descartes(&hash_u32(bloque))
                .unwrap()
                .iter()
                .filter(|d| d.motivo == ErrorTransicion::ErrActaRepetida)
                .count();
            assert!(constan(&nodo, bloque));
        }
        assert_eq!(
            repeticiones, 0,
            "cero ErrActaRepetida de esa acta en diez bloques"
        );
        // ACTA-1 · R3/R4 · la poda usa el conjunto **completo** contra la vista de la ventana; si
        // esa vista todavía no ve la presencia, el acta permanece pendiente (no se omite por
        // ignorancia). Lo que esta prueba exige es que no vuelva a entrar ni se descarte; el plazo
        // (o la poda, si la vista ya la ve) la retira.
        let pk = ClaveDev::derivar(1, 1).pk;
        let con = liquidar(&presente, &nodo);
        let sin = liquidar(&sin_acta, &nodo);
        let protegido = con.garantias[&pk].activo.brek();
        let control = sin.garantias[&pk].activo.brek();
        assert_eq!(
            protegido - control,
            7,
            "la ventana del acta evita el cobro; otras ventanas iguales"
        );
        nodo.procesar_v6_pendientes(cierre_ventana(N) + W_REVEAL_SLOTS_VOTOS + 1);
        assert!(
            nodo.v6_pendientes
                .iter()
                .all(|p| p.clase != CLASE_ACTA_PESO)
        );
        // ACTA-1 · R5 · un evento por hecho: encolada, omitida (al armar) y retirada (por poda o
        // por plazo).
        let registro =
            std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
        assert!(
            registro.contains("\"tipo\":\"acta_peso_encolada\""),
            "R5: falta acta_peso_encolada"
        );
        assert!(
            registro.contains("\"tipo\":\"acta_peso_omitida\""),
            "R5: falta acta_peso_omitida"
        );
        assert!(
            registro.contains("\"tipo\":\"acta_peso_retirada\""),
            "R5: falta acta_peso_retirada"
        );
        println!(
            "DGACTA control_rojo agregado firmantes_locales=0 firmantes_reales=1 reinclusiones=0 bytes_tx={tam} presente_activo={protegido} ausente_activo={control} multa_evitable=7"
        );
    }

    #[test]
    fn dgacta_suelto_con_lista_se_retira_al_constar_hoy() {
        let dir = tempfile::tempdir().expect("temporal");
        let (mut nodo, cert) = escenario(dir.path());
        encolar_desde_motor(&mut nodo, cert, true);
        let cuerpo = armar(&mut nodo, SLOT);
        assert_eq!(cuerpo.len(), 1);
        aplicar_cuerpo(&mut nodo, 100, SLOT, cuerpo).expect("acta suelta");
        assert!(constan(&nodo, 100));
        assert!(armar(&mut nodo, SLOT + 1).is_empty());
        println!("DGACTA control_suelto firmantes_locales=1 firmantes_reales=1 siguiente_cuerpo=0");
    }

    #[test]
    fn dgacta_lista_parcial_omite_firmante_presente_y_le_cobra_ausencia_control_rojo() {
        let dir = tempfile::tempdir().expect("temporal");
        let (mut nodo, cert) = escenario(dir.path());
        // Configuración local minoritaria: reportero y voto suelto pertenecen a 1.
        // El checkpoint de 0 ya está verificado; cambiar la clave local no altera la cadena.
        nodo.claves = vec![ClaveDev::derivar(1, 1)];
        // Otra acta ya hizo constar al votante 1. La 2 todavía no consta.
        let mut primero = motor_abierto(&nodo, cert.clone(), true);
        let acta_1 = primero.cerrar().unwrap().acta_peso.expect("acta de 1");
        let c = nodo.claves[0].clone();
        let par_1 = crate::votos::tx_acta_presencia(&acta_1, c.pk, &c.sk, nodo.cbid);
        aplicar_cuerpo(&mut nodo, 33, SLOT - 1, vec![par_1]).expect("presencia previa de 1");
        assert!(constan(&nodo, 33));
        let base = nodo.cadena.estado_post(&hash_u32(33)).unwrap().clone();
        let pk_1 = ClaveDev::derivar(1, 1).pk;
        let pk_2 = ClaveDev::derivar(1, 2).pk;
        assert!(!base.votantes_voto[&N].contains(&pk_2));

        // Ventana real: voto suelto de 1 + agregado de 2, ambos firmados sobre el mismo A3.
        let mut mixto = motor_abierto(&nodo, cert, true);
        let ag = agregado(&mixto, &base, 2);
        assert_eq!(
            mixto.recibir_agregados(&[ag]).unwrap(),
            vec![RecepcionAgregado::Reenviar]
        );
        nodo.motor_votos = Some(mixto);
        nodo.slot_votos_simulado = Some(SLOT);
        nodo.procesar_votos()
            .expect("cierre y encolado REAL del acta mixta");
        let p = nodo
            .v6_pendientes
            .iter()
            .find(|p| p.clase == CLASE_ACTA_PESO)
            .expect("acta mixta pendiente");
        // ACTA-1 · R4 · la lista auxiliar es completa: antes traía solo el suelto (1).
        let firmantes: std::collections::BTreeSet<_> = p.firmantes_acta.iter().copied().collect();
        assert_eq!(
            firmantes,
            std::collections::BTreeSet::from([pk_1, pk_2]),
            "la lista auxiliar debe traer el suelto y el agregado"
        );
        let par_mixto = (p.tx.clone(), p.testigos.clone());
        // ACTA-1 · control rojo: con el filtro viejo (solo el suelto 1) el cuerpo salía vacío y a 2
        // se le cobraba la ausencia; con la decisión de la cadena el acta se incluye.
        let cuerpo = armar(&mut nodo, SLOT);
        assert!(
            !cuerpo.is_empty(),
            "la acta que acredita a 2 debe incluirse"
        );
        aplicar_cuerpo(&mut nodo, 100, SLOT, cuerpo).expect("bloque con el acta");
        let con = nodo.cadena.estado_post(&hash_u32(100)).unwrap().clone();
        assert!(con.votantes_voto[&N].contains(&pk_2), "el agregado consta");
        assert!(nodo.cadena.descartes(&hash_u32(100)).unwrap().is_empty());

        // Control: la MISMA acta pasa firma, tabla e índice de identidades en la transición real.
        let bloque = BloqueTransicion::nuevo(
            HechosCabecera::PoST {
                hash: hash_u32(998),
                padre: hash_u32(33),
                slot: SLOT,
                productor: c.pk,
                peso: 1,
                prueba_valida: true,
                requisito_declarado: 0,
            },
            vec![par_mixto],
        );
        let (control, _, descartes) = aplicar_fusion(
            &base,
            &bloque,
            Punto::Slot(SLOT),
            &nodo.params,
            nodo.cbid,
            &perfil::parametros_evidencia_dev(),
        )
        .expect("control con acta real");
        assert!(descartes.is_empty());
        assert!(control.votantes_voto[&N].contains(&pk_2));
        // Sin acta (base) a 2 se le cobra la ausencia al liquidar; con el acta del productor, no.
        let con_liquidada = liquidar(&con, &nodo);
        let sin_liquidada = liquidar(&base, &nodo);
        let protegido = con_liquidada.garantias[&pk_2].activo.brek();
        let multado = sin_liquidada.garantias[&pk_2].activo.brek();
        assert_eq!(protegido - multado, 7);
        println!(
            "DGACTA control_rojo perdida_presencia firmantes_reales=2 firmantes_locales=2 incluida=true votante_perdido_indice_dev=2 con_acta_activo={protegido} sin_acta_activo={multado} multa_indebida=7 traduccion_bls_correcta=true"
        );
    }

    #[test]
    fn dgacta_gossip_permanece_en_cola_y_no_crea_lista_auxiliar_hoy() {
        let dir = tempfile::tempdir().expect("temporal");
        let (mut nodo, cert) = escenario(dir.path());
        let mut motor = motor_abierto(&nodo, cert, true);
        let cierre = motor.cerrar().expect("acta real de voto suelto");
        assert_eq!(cierre.acta_peso_firmantes.len(), 1);
        let acta = cierre.acta_peso.expect("acta sin quórum");
        let c = ClaveDev::derivar(1, 2);
        let par = crate::votos::tx_acta_presencia(&acta, c.pk, &c.sk, nodo.cbid);
        let id = txid(&par.0, nodo.cbid);
        let tx = par.0.clone();
        aplicar_cuerpo(&mut nodo, 33, SLOT - 1, Vec::new()).expect("punto de admisión");
        let base_cola = nodo.cadena.estado_post(&hash_u32(33)).unwrap().clone();
        refrescar_cola(&mut nodo, base_cola);
        nodo.mempool
            .lock()
            .expect("cola")
            .admitir(None, par.0, par.1, Instant::now(), Punto::Slot(SLOT))
            .expect("gossip admitido por transición real");
        nodo.procesar_v6_pendientes(SLOT);
        assert!(
            nodo.v6_pendientes
                .iter()
                .all(|p| p.clase != CLASE_ACTA_PESO)
        );
        assert!(nodo.mempool.lock().unwrap().contiene(&id));
        let cuerpo = armar(&mut nodo, SLOT);
        assert_eq!(cuerpo.len(), 1);
        aplicar_cuerpo(&mut nodo, 100, SLOT, cuerpo).expect("primera inclusión");
        assert!(constan(&nodo, 100));
        nodo.actualizar_mempool_tras_bloque(&[tx]);
        // contiene incluye los ids confirmados recientes; no equivale a estar en cola.
        let m = nodo.mempool.lock().unwrap();
        assert!(m.contiene(&id));
        assert!(m.seleccionar(perfil::MAX_CUERPO_BLOQUE_BYTES, 1).is_empty());
        drop(m);
        assert!(armar(&mut nodo, SLOT + 1).is_empty());
        println!(
            "DGACTA gossip actas_auxiliar=0 actas_cola=1 presente=true cola_tras_confirmacion=0"
        );
    }

    #[test]
    fn dgacta_dos_actas_distintas_con_lista_divergen_en_el_mismo_cuerpo_hoy() {
        let dir = tempfile::tempdir().expect("temporal");
        let (mut nodo, cert) = escenario(dir.path());
        let mut motor = motor_abierto(&nodo, cert, true);
        let acta = motor.cerrar().unwrap().acta_peso.expect("acta");
        let firmante = ClaveDev::derivar(1, 1).pk;
        for i in [0, 2] {
            let c = ClaveDev::derivar(1, i);
            let (tx, tst) = crate::votos::tx_acta_presencia(&acta, c.pk, &c.sk, nodo.cbid);
            nodo.encolar_v6_con_firmantes(tx, tst, true, vec![firmante], 1);
        }
        let cuerpo = armar(&mut nodo, SLOT);
        assert_eq!(cuerpo.len(), 2);
        assert_ne!(txid(&cuerpo[0].0, nodo.cbid), txid(&cuerpo[1].0, nodo.cbid));
        let (cuerpo, slot_real) = prod2::depurar_dgacta(&nodo, cuerpo);
        assert_eq!(cuerpo.len(), 1);
        aplicar_cuerpo(&mut nodo, 100, slot_real, cuerpo).expect("dos reporteros, cuerpo depurado");
        let descartes = nodo.cadena.descartes(&hash_u32(100)).unwrap();
        assert!(descartes.is_empty());
        assert!(constan(&nodo, 100));
        assert!(armar(&mut nodo, SLOT + 1).is_empty());
        println!(
            "DGACTA misma_base listas_completas=2 actas_distintas=2 depuradas=1 aplicadas=1 descartadas=0"
        );
    }

    /// ACTA-1 · §3.3 · solo agregados: el acta entra en el primer bloque propio y no vuelve a
    /// entrar en los diez siguientes (cero `ErrActaRepetida` de esa acta).
    #[test]
    fn dgacta_solo_agregados_entra_una_vez_y_no_repite_en_diez_bloques() {
        let dir = tempfile::tempdir().expect("temporal");
        let (mut nodo, cert) = escenario(dir.path());
        // Sin ningún voto suelto: el acta es solo del agregado del votante 1; con el filtro viejo la
        // lista de sueltos era vacía y el acta se reincluía hasta el plazo.
        encolar_desde_motor(&mut nodo, cert, false);
        let pk = ClaveDev::derivar(1, 1).pk;
        let cuerpo = armar(&mut nodo, SLOT);
        let actas: Vec<_> = cuerpo
            .iter()
            .filter(|(tx, _)| {
                matches!(
                    &tx.extension,
                    ExtensionTx::PruebaAlmacenamiento {
                        operacion: zx_core::OperacionAlmacenamiento::ActaPresencia { .. }
                    }
                )
            })
            .collect();
        assert_eq!(
            actas.len(),
            1,
            "el acta del agregado entra en el primer bloque propio"
        );
        let id = txid(&actas[0].0, nodo.cbid);
        aplicar_cuerpo(&mut nodo, 100, SLOT, cuerpo).expect("acta solo agregado");
        assert!(nodo.cadena.descartes(&hash_u32(100)).unwrap().is_empty());
        assert!(constan_pk(&nodo, 100, pk));
        let mut repeticiones = 0_usize;
        for (bloque, slot) in (101_u32..=110).zip((SLOT + 1)..=(SLOT + 10)) {
            let cuerpo = armar(&mut nodo, slot);
            assert!(
                !cuerpo.iter().any(|(tx, _)| txid(tx, nodo.cbid) == id),
                "el acta solo-agregado no vuelve a entrar"
            );
            aplicar_cuerpo(&mut nodo, bloque, slot, cuerpo).expect("bloque propio");
            repeticiones += nodo
                .cadena
                .descartes(&hash_u32(bloque))
                .unwrap()
                .iter()
                .filter(|d| d.motivo == ErrorTransicion::ErrActaRepetida)
                .count();
            assert!(constan_pk(&nodo, bloque, pk));
        }
        assert_eq!(
            repeticiones, 0,
            "cero ErrActaRepetida de esa acta en diez bloques"
        );
        println!(
            "DGACTA solo_agregados actas=1 bloques=10 repeticiones={repeticiones} presente=true"
        );
    }

    #[test]
    fn dgacta_bls_anterior_viva_consta_y_la_vencida_esta_fuera_de_plazo_hoy() {
        let dir = tempfile::tempdir().expect("temporal");
        let (mut nodo, cert) = escenario(dir.path());
        let mut motor = motor_abierto(&nodo, cert, true);
        let cierre = motor.cerrar().unwrap();
        assert_eq!(cierre.acta_peso_firmantes.len(), 1);
        let acta = cierre.acta_peso.expect("acta con BLS anterior");
        let c = ClaveDev::derivar(1, 1);
        let actual = crate::votos::clave_voto_dev(2, 1).expect("nueva BLS");
        let rotacion = tx_clave_voto(c.pk, &c.sk, &actual.clave_publica(), &actual, nodo.cbid);
        aplicar_cuerpo(&mut nodo, 33, 3, vec![rotacion]).expect("rotación REAL");
        let base = nodo.cadena.estado_post(&hash_u32(33)).unwrap().clone();
        let vencimiento = base.claves_voto_previas[&c.pk].vencimiento;
        let tercera = crate::votos::clave_voto_dev(3, 1).expect("tercera BLS");
        let segunda_rotacion =
            tx_clave_voto(c.pk, &c.sk, &tercera.clave_publica(), &tercera, nodo.cbid);
        aplicar_cuerpo(&mut nodo, 34, 4, vec![segunda_rotacion])
            .expect("segunda rotación descartada");
        assert_eq!(
            nodo.cadena.descartes(&hash_u32(34)).unwrap()[0].motivo,
            ErrorTransicion::ErrSector(
                zx_consensus::sectores::MotivoSector::ErrClaveVotoRotacionViva
            )
        );
        assert_eq!(
            nodo.cadena
                .estado_post(&hash_u32(34))
                .unwrap()
                .claves_voto_previas[&c.pk]
                .clave_bls,
            base.claves_voto_previas[&c.pk].clave_bls
        );
        let reportero = nodo.claves[0].clone();
        let par = crate::votos::tx_acta_presencia(&acta, reportero.pk, &reportero.sk, nodo.cbid);
        aplicar_cuerpo(&mut nodo, 100, SLOT, vec![par.clone()]).expect("acta BLS anterior viva");
        assert!(constan(&nodo, 100));
        assert!(nodo.cadena.descartes(&hash_u32(100)).unwrap().is_empty());
        let con = liquidar(nodo.cadena.estado_post(&hash_u32(100)).unwrap(), &nodo);
        let sin = liquidar(&base, &nodo);
        assert_eq!(
            con.garantias[&c.pk].activo.brek() - sin.garantias[&c.pk].activo.brek(),
            7
        );
        let op = if let ExtensionTx::PruebaAlmacenamiento { operacion } = &par.0.extension {
            operacion
        } else {
            panic!("acta");
        };
        let (_, _, r) = zx_consensus::transicion::votos::aplicar_acta_presencia_con_undo(
            &base,
            op,
            i64::try_from(vencimiento + 1).unwrap(),
        );
        assert_eq!(r, Err(ErrorTransicion::ErrActaPlazo));
        println!(
            "DGACTA rotacion slot=3 retencion={} vencimiento={vencimiento} acta_slot={SLOT} presente=true multa_ventana=0 vencida=ErrActaPlazo",
            vencimiento - 3
        );
    }

    #[test]
    fn dgacta_coste_transicion_adicional_hoy() {
        let dir = tempfile::tempdir().expect("temporal");
        let (nodo, cert) = escenario(dir.path());
        let mut motor = motor_abierto(&nodo, cert, true);
        let acta = motor.cerrar().unwrap().acta_peso.expect("acta");
        let c = &nodo.claves[0];
        let par = crate::votos::tx_acta_presencia(&acta, c.pk, &c.sk, nodo.cbid);
        let base = nodo.cadena.estado_post(&hash_u32(32)).unwrap();
        let bloque = BloqueTransicion::nuevo(
            HechosCabecera::PoST {
                hash: hash_u32(998),
                padre: hash_u32(32),
                slot: SLOT,
                productor: c.pk,
                peso: 1,
                prueba_valida: true,
                requisito_declarado: 0,
            },
            vec![par],
        );
        let evp = perfil::parametros_evidencia_dev();
        let aplicar = || {
            aplicar_fusion(
                base,
                &bloque,
                Punto::Slot(SLOT),
                &nodo.params,
                nodo.cbid,
                &evp,
            )
            .expect("transición real del cuerpo")
        };
        let (nuevo, _, descartes) = aplicar();
        assert!(descartes.is_empty());
        assert!(nuevo.votantes_voto[&N].contains(&ClaveDev::derivar(1, 1).pk));
        // La rama temporal solo se ejecuta con DGACTA_MEDIR=1, bajo bloque 0 y perf externos.
        if std::env::var("DGACTA_MEDIR").is_ok_and(|valor| valor == "1") {
            for replica in 0..3 {
                let mut nanos = Vec::with_capacity(101);
                for _ in 0..101 {
                    let inicio = Instant::now();
                    let resultado = std::hint::black_box(aplicar());
                    nanos.push(inicio.elapsed().as_nanos());
                    assert!(resultado.2.is_empty());
                }
                nanos.sort_unstable();
                println!(
                    "DATO_MEDIDA replica={replica} claves=3 sectores=8 tx=1 llamadas=101 min_ns={} mediana_ns={} max_ns={} perfil=debug",
                    nanos[0], nanos[50], nanos[100]
                );
            }
        }
    }

    #[test]
    fn dgacta_wire_65536_y_registro_guardado_hoy() {
        let dir = tempfile::tempdir().expect("temporal");
        let (nodo, cert) = escenario(dir.path());
        let mut motor = motor_abierto(&nodo, cert, true);
        let mut acta = motor
            .cerrar()
            .unwrap()
            .acta_peso
            .expect("acta real pequeña");
        let c = &nodo.claves[0];
        let pequena = crate::votos::tx_acta_presencia(&acta, c.pk, &c.sk, nodo.cbid);
        assert_eq!(bytes(&pequena), 318);
        // Solo longitud con el códec real: no se presenta esta plantilla grande como firma válida.
        acta.mapa.resize(65_536_usize.div_ceil(8), 0);
        let grande = crate::votos::tx_acta_presencia(&acta, c.pk, &c.sk, nodo.cbid);
        assert_eq!(bytes(&grande), 8509);
        let coinbase = tx_coinbase_post(c.pk, perfil::SUBSIDIO_POST_BREK, SLOT);
        let reserva = std::cell::Cell::new(0);
        let presupuestado = presupuestar_cuerpo_post(
            &coinbase,
            None,
            Vec::new,
            vec![grande.clone(); 79],
            nodo.params.max_cuerpo_bloque_bytes,
            |max_cola| {
                reserva.set(max_cola);
                Vec::new()
            },
        )
        .expect("presupuesto REAL por bytes");
        assert_eq!(presupuestado.txs.len(), 37);
        assert_eq!(reserva.get(), 5104);
        assert!(presupuestado.recorte.is_none());
        println!(
            "DGACTA wire pequena={} tabla_65536={} plantilla_grande_solo_tamano=true",
            bytes(&pequena),
            bytes(&grande)
        );
        println!(
            "DGACTA presupuesto tope=320000 coinbase=63 actas_candidatas=79 actas_encajadas=37 bytes_actas=314833 disponible_cola={} firma_plantilla_grande_no_validada=true",
            reserva.get()
        );
        if let Ok(ruta) = std::env::var("DGACTA_DB") {
            for (nombre, indice) in [("A", 0), ("B", 1), ("C", 2)] {
                println!(
                    "DATO_REPORTERO\t{nombre}\t{}",
                    crate::votos::hex(ClaveDev::derivar(101, indice).pk.bytes())
                );
            }
            let mut opciones = rocksdb::Options::default();
            let log_local = dir.path().join("lectura-logs");
            std::fs::create_dir_all(&log_local).unwrap();
            opciones.set_db_log_dir(&log_local);
            let familias = rocksdb::DB::list_cf(&opciones, &ruta).expect("familias guardadas");
            let db = rocksdb::DB::open_cf_for_read_only(&opciones, &ruta, familias, false)
                .expect("RocksDB SOLO LECTURA");
            let cf = db.cf_handle("bloques").expect("bloques");
            for fila in db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
                let (clave, valor) = fila.expect("fila guardada");
                let (familia, canonicos) = zx_storage::formato::separar(&valor).expect("sobre");
                if familia != zx_storage::formato::Familia::Post {
                    continue;
                }
                let h = BlockHash::from_digest(Digest::from_bytes(
                    clave.as_ref().try_into().expect("hash"),
                ));
                assert_eq!(
                    zx_storage::formato::hash_de_valor(&h, &valor).expect("compromiso real"),
                    h
                );
                let (bloque, sobra) =
                    zx_core::wire_dag::bloque_dag_desde_bytes(canonicos).expect("códec real");
                assert!(sobra.is_empty());
                for (i, (tx, tst)) in bloque.txs().iter().zip(bloque.testigos()).enumerate() {
                    if let ExtensionTx::PruebaAlmacenamiento {
                        operacion:
                            zx_core::OperacionAlmacenamiento::ActaPresencia {
                                clave,
                                bytes: payload,
                            },
                    } = &tx.extension
                    {
                        let n = u64::from_be_bytes(payload[..8].try_into().unwrap());
                        println!(
                            "DATO_ACTA\t{}\t{i}\t{}\t{n}\t{}\t{}\t{}",
                            crate::votos::hex(h.as_bytes()),
                            crate::votos::hex(
                                txid(tx, bloque.cabecera.consensus_branch_id).as_bytes()
                            ),
                            bytes(&(tx.clone(), tst.clone())),
                            crate::votos::hex(clave.bytes()),
                            bloque.cabecera.slot
                        );
                    }
                }
            }
            drop(db);
            // Replay real en copia de SOLO el almacén público; ningún diario/clave local se copia.
            let copia = dir.path().join("replay");
            let storage = copia.join("datos/storage");
            std::fs::create_dir_all(&storage).unwrap();
            for entrada in std::fs::read_dir(&ruta).unwrap() {
                let entrada = entrada.unwrap();
                if entrada.file_type().unwrap().is_file() {
                    std::fs::copy(entrada.path(), storage.join(entrada.file_name())).unwrap();
                }
            }
            let cfg = Config {
                dir_datos: copia.join("datos"),
                ruta_registro: copia.join("registro.jsonl"),
                red: Red::Dev,
                semilla: 101,
                indices_claves: vec![0],
                n_dev: 138_873_760,
                sr_dev: 13_043_817_825_332_783_104,
                perfil_red: perfil::perfil_red_dev(),
                parada_tras_slots: Some(0),
                dejar_de_producir_en_slot: None,
                punto_control: None,
                sin_voto: true,
                sin_revelacion: true,
            };
            let replay = Nodo::arrancar(&cfg).expect("replay REAL de copia de A, sin red");
            let mut actas = 0;
            let mut firmantes = 0;
            let mut sin_estado = 0;
            let mut sin_tabla = 0;
            let mut sin_identidad = 0;
            let mut sin_constar = 0;
            for bloque in replay.cadena.bloques_post() {
                let Some(estado) = replay.cadena.estado_post(&bloque.hash) else {
                    sin_estado += 1;
                    continue;
                };
                for (tx, _) in &bloque.txs {
                    let ExtensionTx::PruebaAlmacenamiento {
                        operacion: zx_core::OperacionAlmacenamiento::ActaPresencia { bytes, .. },
                    } = &tx.extension
                    else {
                        continue;
                    };
                    actas += 1;
                    let n = u64::from_be_bytes(bytes[..8].try_into().unwrap());
                    let h = estado.tabla_ventana_voto.get(&n).copied().or_else(|| {
                        (n > estado.finalidad_votos_n
                            && n <= estado
                                .finalidad_votos_n
                                .saturating_add(CADUCIDAD_TABLA_VENTANAS))
                        .then_some(estado.finalidad_votos_h_t)
                        .flatten()
                    });
                    let Some(tabla) = h.and_then(|h| estado.tablas_voto_contenido.get(&h)) else {
                        sin_tabla += 1;
                        continue;
                    };
                    let cert = zx_votos::deserializar_certificado_peso(bytes, tabla.len())
                        .expect("mapa guardado canónico");
                    for pos in zx_votos::peso::firmantes_de_mapa(&cert.mapa) {
                        firmantes += 1;
                        let bls = tabla[pos - 1].clave_bls;
                        let ed = estado
                            .claves_voto
                            .iter()
                            .find(|(_, cv)| cv.clave_bls == bls)
                            .map(|(ed, _)| *ed)
                            .or_else(|| {
                                estado
                                    .claves_voto_previas
                                    .iter()
                                    .find(|(_, cv)| {
                                        cv.clave_bls == bls && bloque.slot <= cv.vencimiento
                                    })
                                    .map(|(ed, _)| *ed)
                            });
                        let Some(ed) = ed else {
                            sin_identidad += 1;
                            continue;
                        };
                        if !estado
                            .votantes_voto
                            .get(&n)
                            .is_some_and(|v| v.contains(&ed))
                        {
                            sin_constar += 1;
                        }
                    }
                }
            }
            assert_eq!(sin_identidad, 0);
            assert_eq!(sin_constar, 0);
            println!(
                "DATO_REPLAY actas={actas} firmantes={firmantes} bloques_sin_estado={sin_estado} actas_sin_tabla={sin_tabla} firmantes_sin_identidad={sin_identidad} firmantes_sin_constar={sin_constar}"
            );
        }
    }
}

/// ACTA-1 · R1–R5 · propiedad del productor contra la transición real.
///
/// Genera tablas de 3 a 64 claves con rotaciones (claves anteriores vivas y vencidas), mapas
/// arbitrarios y conjuntos de votantes ya contados arbitrarios, con una semilla escrita. Para cada
/// caso compara «el productor incluye» (predicado de `votantes_de_acta`) con «la transición real no
/// descarta por repetida» (`aplicar_acta_presencia_con_undo`). El control rojo recompone el filtro
/// viejo (solo sueltos y solo claves actuales) y exige que rompa la propiedad al menos una vez.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "pruebas de propiedad con generador determinista y fallo por panic"
)]
mod acta1 {
    use super::*;
    use std::collections::BTreeSet;
    use zx_consensus::sectores::{ClaveVoto, ClaveVotoAnterior};
    use zx_consensus::transicion::ErrorTransicion;
    use zx_consensus::transicion::votos::{aplicar_acta_presencia_con_undo, votantes_de_acta};
    use zx_core::{ClavePublica, ClaveTablaVoto, OperacionAlmacenamiento};
    use zx_votos::{Clave, ClaveSecreta, Firma, Tabla};

    const SEMILLA: u64 = 0x0000_000A_C7A1_2026;
    const N: u64 = 5;
    /// Dentro de `[apertura(5), cierre(5) + W_REVEAL]`.
    const SLOT: u64 = 14;

    /// Generador lineal congruente determinista (semilla escrita; sin azar del sistema).
    struct Azar(u64);
    impl Azar {
        fn siguiente(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn rango(&mut self, n: usize) -> usize {
            assert!(n > 0);
            usize::try_from(self.siguiente() % u64::try_from(n).unwrap()).unwrap()
        }
        fn moneda(&mut self) -> bool {
            self.siguiente() & 1 == 1
        }
    }

    /// Estado y material de firma de una tabla sintética.
    struct Base {
        estado: EstadoTransicion,
        secretas: Vec<ClaveSecreta>,
        /// Posiciones de la tabla (ya en orden canónico) con el índice de su clave secreta.
        entradas: Vec<(ClaveTablaVoto, usize)>,
        claves: Vec<ClaveTablaVoto>,
        tabla: Tabla,
        h: [u8; 32],
    }

    /// Un acta sintética con su estado de aplicación.
    struct Caso {
        estado: EstadoTransicion,
        bytes: Vec<u8>,
        contados: BTreeSet<ClavePublica>,
        /// Claves BLS de las posiciones que el filtro viejo contaba como «sueltas».
        sueltos_bls: Vec<[u8; 48]>,
    }

    fn a_clave(c: &ClaveTablaVoto) -> Clave {
        Clave {
            clave: c.clave_bls.to_vec(),
            peso: c.peso,
            activo: c.activo,
            prueba: c.prueba,
            garantia: c.garantia,
        }
    }

    /// Tabla de `n_claves` identidades dev; `rotaciones[j]` pone en la tabla la clave anterior de
    /// `j` (registrada como anterior en el estado) y `vivas[j]` decide si sigue viva en `SLOT`.
    fn base_sintetica(n_claves: usize, rotaciones: &[bool], vivas: &[bool]) -> Base {
        assert_eq!(rotaciones.len(), n_claves);
        assert_eq!(vivas.len(), n_claves);
        let mut estado = EstadoTransicion::inicial();
        let mut secretas: Vec<ClaveSecreta> = Vec::new();
        let mut entradas: Vec<(ClaveTablaVoto, usize)> = Vec::new();
        for (j, (&rota, &viva)) in rotaciones.iter().zip(vivas.iter()).enumerate() {
            let indice = u32::try_from(j).unwrap();
            let ed = ClaveDev::derivar(1, indice).pk;
            let actual = crate::votos::clave_voto_dev(7, indice).unwrap();
            let actual_bls = actual.clave_publica().bytes();
            let (bls_tabla, firma_key) = if rota {
                let previa = crate::votos::clave_voto_dev(8, indice).unwrap();
                let previa_bls = previa.clave_publica().bytes();
                let margen = u64::try_from(j).unwrap() + 1;
                let vencimiento = if viva {
                    SLOT.saturating_add(margen)
                } else {
                    SLOT.saturating_sub(margen)
                };
                estado.claves_voto_previas.insert(
                    ed,
                    ClaveVotoAnterior {
                        clave_bls: previa_bls,
                        prueba_posesion: [0; 96],
                        vencimiento,
                    },
                );
                (previa_bls, previa)
            } else {
                (actual_bls, actual)
            };
            estado.claves_voto.insert(
                ed,
                ClaveVoto {
                    clave_bls: actual_bls,
                    prueba_posesion: [0; 96],
                },
            );
            secretas.push(firma_key);
            let idx = secretas.len() - 1;
            entradas.push((
                ClaveTablaVoto {
                    clave_bls: bls_tabla,
                    peso: 1,
                    activo: true,
                    prueba: false,
                    garantia: 1,
                },
                idx,
            ));
        }
        entradas.sort_by_key(|(c, _)| c.clave_bls);
        let claves: Vec<ClaveTablaVoto> = entradas.iter().map(|(c, _)| *c).collect();
        let tabla = Tabla {
            n: N,
            claves: claves.iter().map(a_clave).collect(),
        };
        let h = zx_votos::hash_tabla(&tabla);
        estado.tabla_ventana_voto.insert(N, h);
        estado.tablas_voto_contenido.insert(h, claves.clone());
        Base {
            estado,
            secretas,
            entradas,
            claves,
            tabla,
            h,
        }
    }

    fn acta_de(base: &Base, marcadas: &[usize], contados_idx: &[usize], sueltos: &[usize]) -> Caso {
        let candidato = [7_u8; 32];
        let raiz = [0_u8; 32];
        let mut votos: Vec<(usize, Firma)> = Vec::new();
        for &pos in marcadas {
            let (_, idx) = &base.entradas[pos];
            let firma = zx_votos::firmar(
                &base.secretas[*idx],
                zx_votos::DOMINIO_VOTO,
                &zx_votos::mensaje_voto_peso(N, &candidato, &base.h, &raiz),
            )
            .unwrap();
            votos.push((pos + 1, firma));
        }
        let cert = zx_votos::construir_certificado(N, candidato, base.h, raiz, &base.tabla, &votos)
            .unwrap();
        let bytes = zx_votos::serial_certificado_peso(&cert);
        let contados: BTreeSet<ClavePublica> = contados_idx
            .iter()
            .map(|&j| ClaveDev::derivar(1, u32::try_from(j).unwrap()).pk)
            .collect();
        let sueltos_bls: Vec<[u8; 48]> =
            sueltos.iter().map(|&p| base.claves[p].clave_bls).collect();
        let mut estado = base.estado.clone();
        estado.votantes_voto.insert(N, contados.clone());
        Caso {
            estado,
            bytes,
            contados,
            sueltos_bls,
        }
    }

    /// `(productor incluye, cadena incluye, filtro viejo incluye)`.
    fn veredictos(caso: &Caso) -> (bool, bool, bool) {
        let op = OperacionAlmacenamiento::ActaPresencia {
            clave: ClaveDev::derivar(1, 0).pk,
            bytes: caso.bytes.clone(),
        };
        let (_, _, r) =
            aplicar_acta_presencia_con_undo(&caso.estado, &op, i64::try_from(SLOT).unwrap());
        let cadena = match r {
            Ok(()) => true,
            Err(ErrorTransicion::ErrActaRepetida) => false,
            Err(e) => panic!("la transición rechazó por un motivo inesperado: {e:?}"),
        };
        let productor = match votantes_de_acta(&caso.estado, &caso.bytes, SLOT) {
            None => true,
            Some(votantes) => !votantes.is_subset(&caso.contados),
        };
        // Filtro viejo: traducción solo de claves actuales y solo posiciones «sueltas».
        let mut indice_actual: std::collections::HashMap<[u8; 48], ClavePublica> =
            std::collections::HashMap::new();
        for (ed, cv) in &caso.estado.claves_voto {
            indice_actual.insert(cv.clave_bls, *ed);
        }
        let viejos: BTreeSet<ClavePublica> = caso
            .sueltos_bls
            .iter()
            .filter_map(|bls| indice_actual.get(bls).copied())
            .collect();
        let viejo = viejos.is_empty() || viejos.iter().any(|ed| !caso.contados.contains(ed));
        (productor, cadena, viejo)
    }

    /// ACTA-1 · §3.5 · propiedad con la transición real como oráculo, semilla escrita, tablas de 3 a
    /// 64 claves, mapas y conjuntos ya contados arbitrarios y rotaciones. Control rojo: el filtro de
    /// hoy rompe la propiedad.
    #[test]
    fn acta1_productor_incluye_si_y_solo_si_la_cadena_no_descarta_por_repetida() {
        let mut azar = Azar(SEMILLA);
        let mut casos = 0_usize;
        let mut divergencias_viejas = 0_usize;
        for n_claves in [3_usize, 4, 5, 8, 16, 32, 63, 64] {
            for _ in 0..8 {
                let rotaciones: Vec<bool> = (0..n_claves).map(|_| azar.moneda()).collect();
                let vivas: Vec<bool> = (0..n_claves).map(|_| azar.moneda()).collect();
                let base = base_sintetica(n_claves, &rotaciones, &vivas);
                let mut marcadas: Vec<usize> = (0..n_claves).filter(|_| azar.moneda()).collect();
                if marcadas.is_empty() {
                    marcadas.push(azar.rango(n_claves));
                }
                let contados_idx: Vec<usize> = (0..n_claves).filter(|_| azar.moneda()).collect();
                let sueltos: Vec<usize> =
                    marcadas.iter().copied().filter(|_| azar.moneda()).collect();
                let caso = acta_de(&base, &marcadas, &contados_idx, &sueltos);
                let (productor, cadena, viejo) = veredictos(&caso);
                assert_eq!(
                    productor, cadena,
                    "productor y transición deben coincidir (n_claves={n_claves})"
                );
                if viejo != cadena {
                    divergencias_viejas += 1;
                }
                casos += 1;
            }
        }
        assert_eq!(casos, 64);
        assert!(
            divergencias_viejas > 0,
            "control rojo: el filtro viejo debe romper la propiedad en algún caso"
        );
        println!(
            "ACTA1 propiedad casos={casos} divergencias_filtro_viejo={divergencias_viejas} semilla={SEMILLA:#x}"
        );
    }

    /// ACTA-1 · §3.4 · clave anterior viva (la cadena no descarta y el productor incluye) y clave
    /// anterior vencida (conjunto traducido vacío: la cadena descarta y el productor omite).
    #[test]
    fn acta1_clave_anterior_viva_y_vencida_coinciden_con_la_cadena() {
        for (viva, etiqueta) in [(true, "viva"), (false, "vencida")] {
            let base = base_sintetica(1, &[true], &[viva]);
            let caso = acta_de(&base, &[0], &[], &[0]);
            let (productor, cadena, _) = veredictos(&caso);
            if viva {
                assert!(cadena, "la clave anterior viva no se descarta ({etiqueta})");
                assert!(
                    productor,
                    "el productor incluye con la clave anterior viva ({etiqueta})"
                );
            } else {
                assert!(
                    !cadena,
                    "la clave vencida deja el conjunto vacío y la cadena descarta ({etiqueta})"
                );
                assert!(
                    !productor,
                    "el productor omite con la clave vencida ({etiqueta})"
                );
            }
        }
        println!("ACTA1 rotacion anterior_viva=incluye anterior_vencida=omite coinciden=true");
    }

    /// ACTA-1 · R3 · sin la tabla de la ventana no se puede traducir: el productor no puede omitir
    /// (devuelve `None`, que el armado interpreta como «incluir»).
    #[test]
    fn acta1_tabla_desconocida_no_habilita_omitir() {
        let base = base_sintetica(3, &[false, false, false], &[false, false, false]);
        let caso = acta_de(&base, &[0, 1], &[], &[]);
        let mut sin_tabla = caso.estado.clone();
        sin_tabla.tabla_ventana_voto.clear();
        sin_tabla.tablas_voto_contenido.clear();
        assert!(
            votantes_de_acta(&sin_tabla, &caso.bytes, SLOT).is_none(),
            "sin tabla, la traducción es desconocida"
        );
        assert!(
            votantes_de_acta(&caso.estado, &caso.bytes, SLOT).is_some(),
            "con tabla, la traducción existe"
        );
        println!("ACTA1 tabla_desconocida traduccion=None productor_incluye=true");
    }
}

include!("prod2_tests.rs");
