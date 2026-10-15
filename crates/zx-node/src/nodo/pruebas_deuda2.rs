//! DEUDA-2 · montaje compartido de las pruebas 9b-1/9b-2/9b-3.
//!
//! Construye una cadena **real y persistida**: el corte PoW se fabrica (modelo `t10b`; el corte no
//! es la regla bajo prueba) con `H_CORTE_MIN` cabeceras que acumulan trabajo y depositan la
//! garantía de las tres claves del nodo, y **sobre ese corte** se producen bloques PoST **reales**
//! (PoAS/PoT válidos, productor real) que registran la clave BLS de voto del nodo por el camino de
//! las transacciones (`0x03` + alta de sector `0x04`). El reinicio de las pruebas es un
//! `Nodo::arrancar` sobre el mismo directorio: repite el almacén y reconstruye el estado, sin
//! inyectar ni reinstalar estado de cadena.
//!
//! Fabricar el corte PoW es lo que hace `t10b` con `pow_terminal`; se hace porque el minado real
//! del perfil dev dispara la dificultad y `fase_pow` deja de terminar en un plazo razonable
//! (medido en `logs/diag-*`). Los bloques PoST que fijan el estado bajo prueba sí son reales y
//! verificados por el camino de admisión del nodo.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    reason = "fixtures de integración con aserciones"
)]

use super::dgcand_tests::{oportunidad, producir, recibir};
use super::pruebas_eclr2::{tx_alta_sector, tx_clave_voto};
use super::*;
use crate::votos::clave_voto_dev;
use std::sync::{Arc, mpsc};
use std::thread;
use zx_consensus::sectores::ParametrosSector;
use zx_core::preimage::block::merkle_root;
use zx_core::{ClaveTablaVoto, TxId};
use zx_post::productor_regimen::CuerpoProductor;
use zx_votos::{
    Clave, ClavePublica as ClaveBls, ClaveSecreta, DOMINIO_VOTO, Tabla, construir_certificado,
    firmar, hash_tabla, mensaje_voto_peso,
};

/// Bits compactos del target mínimo de la red dev (`decodificar_con` lo acepta: es canónico y su
/// trabajo es muy superior a `w_min`, de modo que el corte se alcanza por altura, no por minado).
const BITS_CORTE_FABRICADO: u32 = 0x0901_0000;

/// Config real de DEUDA-2: nodo que emite votos, sin red, con corte PoW fabricado al empezar.
pub(super) fn config_deuda2(dir: &Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: vec![0, 1, 2],
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

/// Cadena real persistida con la clave BLS del nodo registrada y con peso.
pub(super) struct Montaje {
    /// Nodo vivo con la cadena ya persistida.
    pub nodo: Nodo,
    /// Terminal PoW seleccionado (padre de los bloques PoST).
    pub terminal: BlockHash,
    /// Clave BLS secreta del nodo (la misma que usa su motor).
    pub sk_bls: ClaveSecreta,
    /// Clave BLS pública registrada.
    pub pk_bls: ClaveBls,
    /// Bloque posterior que hace madurar el sector (deposita la tabla vigente en la cola).
    pub bloque_maduro: BlockHash,
    /// Bloque candidato de la ventana: su **pasado** ya contiene la tabla depositada por el maduro.
    pub bloque_candidato: BlockHash,
    /// Slot del bloque candidato.
    pub slot_candidato: u64,
    /// Ventana de voto elegida: el candidato es `bloque_candidato` y el sector ya está activo.
    pub ventana: u64,
}

/// Fabrica y persiste el corte PoW: `H_CORTE_MIN` cabeceras encadenadas con el target mínimo, cada
/// una con su coinbase y los depósitos que maduran, sin minar (el replay tampoco valida el PoW).
fn fabricar_corte(nodo: &mut Nodo) {
    let genesis_ts = nodo.historial_pow[0].timestamp;
    let mut prev = nodo.historial_pow[0].block_hash();
    for altura in 1..=perfil::H_CORTE_MIN {
        let timestamp = genesis_ts.saturating_add(u64::from(altura));
        let depositos = nodo
            .preparar_depositos(altura)
            .expect("depósitos del corte fabricado");
        let clave = nodo.claves[(altura as usize) % nodo.claves.len()].pk;
        let coinbase = pow::construir_coinbase_pow(clave, altura);
        let mut txs = vec![coinbase];
        let mut testigos: Vec<Vec<Vec<u8>>> = vec![Vec::new()];
        for (tx, tst) in depositos {
            txs.push(tx);
            testigos.push(tst);
        }
        let txids: Vec<TxId> = txs.iter().map(|t| txid(t, nodo.cbid)).collect();
        let cabecera = BlockHeader {
            consensus_branch_id: nodo.cbid,
            prev_hash: prev,
            merkle_root: merkle_root(&txids),
            timestamp,
            bits: BITS_CORTE_FABRICADO,
            nonce: 0,
            height: altura,
        };
        let hash = cabecera.block_hash();
        nodo.admitir_pow_interno(
            cabecera,
            txs.clone(),
            testigos.clone(),
            u64::from(altura),
            false,
            false,
        )
        .expect("cabecera de corte admitida sin verificar (ruta de repetición)");
        nodo.almacen
            .admitir(&BloqueAdmitido::pow(&cabecera, &txs, &testigos), true)
            .expect("cabecera de corte persistida");
        prev = hash;
    }
    assert!(nodo.cadena.terminal().is_some(), "el corte queda fijado");
}

/// Produce y admite (por el camino real) un bloque PoST sobre `padre`, buscando el primer slot con
/// solución PoAS en `[desde, hasta]` para alguna de las tres claves.
pub(super) fn producir_post(
    nodo: &mut Nodo,
    terminal: BlockHash,
    padre: BlockHash,
    desde: u64,
    hasta: u64,
    cuerpo: CuerpoProductor,
) -> (BlockHash, u64) {
    let mut servicio = nodo.servicios_verificacion[&terminal].clone();
    let (slot, indice) = oportunidad(nodo, &mut servicio, desde, hasta, &[0, 1, 2]);
    let bloque = producir(
        nodo,
        &mut servicio,
        PadresDag::nuevo(padre, &[]).expect("padres"),
        slot,
        nodo.reloj_local() as u64,
        indice,
        cuerpo,
    );
    let hash = bloque.cabecera.block_hash();
    assert_eq!(
        recibir(nodo, &bloque),
        VeredictoFinal::Aceptar,
        "bloque PoST real admitido por el camino del nodo"
    );
    (hash, slot)
}

/// Arranca el nodo real, fabrica el corte PoW, produce el bloque con `0x04`+`0x03` y un bloque
/// posterior que hace madurar el sector y deposita la tabla vigente en la cola del estado.
pub(super) fn montar(dir: &Path) -> Montaje {
    let mut nodo = Nodo::arrancar(&config_deuda2(dir)).expect("arranque real");
    fabricar_corte(&mut nodo);
    nodo.asegurar_servicios_verificacion()
        .expect("servicios reales");
    let terminal = nodo.cadena.terminal().expect("terminal PoW");
    let sk_bls = clave_voto_dev(config_deuda2(dir).semilla, 0).expect("clave BLS dev");
    let pk_bls = sk_bls.clave_publica();
    let clave = nodo.claves[0].clone();
    let (tx_alta, tst_alta) = tx_alta_sector(clave.pk, &clave.sk, nodo.cbid);
    let (tx_cv, tst_cv) = tx_clave_voto(clave.pk, &clave.sk, &pk_bls, &sk_bls, nodo.cbid);
    let cuerpo = CuerpoProductor::nuevo(vec![tx_alta, tx_cv], vec![tst_alta, tst_cv])
        .expect("cuerpo con alta y clave");
    let (bloque_clave, slot_clave) = producir_post(&mut nodo, terminal, terminal, 1, 60, cuerpo);

    // El sector madura `m_sec` slots después del alta; el bloque maduro lo materializa y deja la
    // tabla activa en `cola_tablas_voto`. El candidato va **después**, porque la apertura usa el
    // estado **pasado** del candidato.
    let m_sec = u64::try_from(ParametrosSector::dev().m_sec).unwrap_or(12);
    let desde = slot_clave.saturating_add(m_sec);
    let (bloque_maduro, slot_maduro) = producir_post(
        &mut nodo,
        terminal,
        bloque_clave,
        desde,
        desde.saturating_add(60),
        CuerpoProductor::vacio(),
    );
    let (bloque_candidato, slot_candidato) = producir_post(
        &mut nodo,
        terminal,
        bloque_maduro,
        slot_maduro.saturating_add(1),
        slot_maduro.saturating_add(61),
        CuerpoProductor::vacio(),
    );

    // Ventana con candidato = bloque candidato y su pasado ya con la tabla: `2n - LAG >=
    // slot_candidato`.
    let t_inst = perfil::parametros_votos_dev().t_inst;
    let ventana = slot_candidato
        .saturating_add(LAG_CANDIDATO_VOTOS)
        .saturating_add(6)
        .div_ceil(t_inst);

    Montaje {
        nodo,
        terminal,
        sk_bls,
        pk_bls,
        bloque_maduro,
        bloque_candidato,
        slot_candidato,
        ventana,
    }
}

/// Extiende la cadena montada con un bloque `0x09` real que fija la finalidad de la ventana `0`.
/// Devuelve el bloque que lo lleva y la huella de la tabla comprometida.
pub(super) fn anclar_finalidad(m: &mut Montaje) -> (BlockHash, [u8; 32]) {
    let estado = m
        .nodo
        .cadena
        .estado_post(&m.bloque_candidato)
        .expect("estado del bloque candidato");
    let (_k, h) = *estado
        .cola_tablas_voto
        .last()
        .expect("el bloque maduro depositó una tabla");
    let contenido = estado
        .tablas_voto_contenido
        .get(&h)
        .cloned()
        .expect("contenido de la huella depositada");
    let claves: Vec<Clave> = contenido
        .iter()
        .map(|c: &ClaveTablaVoto| Clave {
            clave: c.clave_bls.to_vec(),
            peso: c.peso,
            activo: c.activo,
            prueba: c.prueba,
            garantia: c.garantia,
        })
        .collect();
    let tabla = Tabla { n: 0, claves };
    assert_eq!(
        hash_tabla(&tabla),
        h,
        "la tabla de la cola es la canónica del estado"
    );
    let candidato = *m.bloque_maduro.as_bytes();
    let pos = tabla
        .claves
        .iter()
        .position(|c| c.clave.as_slice() == m.pk_bls.bytes().as_slice())
        .expect("la clave BLS del nodo está en la tabla");
    let mensaje = mensaje_voto_peso(0, &candidato, &h, &[0u8; 32]);
    let firma = firmar(&m.sk_bls, DOMINIO_VOTO, &mensaje).expect("firma BLS real");
    let cert = construir_certificado(0, candidato, h, [0u8; 32], &tabla, &[(pos + 1, firma)])
        .expect("certificado por peso");
    let clave = m.nodo.claves[0].clone();
    let (tx_cert, tst_cert) =
        crate::votos::tx_certificado_peso(&cert, clave.pk, &clave.sk, m.nodo.cbid);
    let cuerpo = CuerpoProductor::nuevo(vec![tx_cert], vec![tst_cert]).expect("cuerpo con el 0x09");
    let desde = m.slot_candidato.saturating_add(1);
    let (bloque_final, _slot) = producir_post(
        &mut m.nodo,
        m.terminal,
        m.bloque_candidato,
        desde,
        desde.saturating_add(60),
        cuerpo,
    );
    let estado_final = m
        .nodo
        .cadena
        .estado_post(&bloque_final)
        .expect("estado tras el 0x09");
    assert_eq!(estado_final.finalidad_votos_n, 0, "la finalidad quedó en 0");
    assert_eq!(
        estado_final.finalidad_votos_h_t,
        Some(h),
        "la huella comprometida es la del certificado"
    );
    (bloque_final, h)
}

/// Corre el hilo productor real y el bucle real hasta que el motor abra `ventana` (o hasta agotar
/// `limite` vueltas), con el reloj de votos fijado en `slot`. El reloj simulado es una facilidad de
/// prueba: la decisión de qué ventana y qué candidato sale del estado persistido, no del reloj.
pub(super) fn correr_hasta_ventana(nodo: &mut Nodo, slot: u64, ventana: u64, limite: usize) {
    nodo.slot_votos_simulado = Some(slot);
    let terminal = nodo.cadena.terminal().expect("terminal");
    let servicio = nodo.servicios_verificacion[&terminal].clone();
    let historia = Arc::clone(&nodo.historia);
    let registro = Arc::clone(&nodo.registro);
    let cbid = nodo.cbid;
    let (tx_prod, rx_prod) = mpsc::channel::<MsgProductor>();
    let (tx_bucle, rx_bucle) = mpsc::channel::<MsgBucle>();
    let hilo = thread::spawn(move || {
        hilo_productor_regimen(
            servicio,
            u64::MAX,
            cbid,
            perfil::subsidio_post(0),
            Vec::new(),
            &historia,
            Some(4),
            &rx_bucle,
            &tx_prod,
            &registro,
        );
    });
    let mut terminal_loop = terminal;
    let mut frontera_enviada = 0u64;
    for _ in 0..limite {
        let _ = nodo.iteracion_regimen(
            &rx_prod,
            &tx_bucle,
            &mut terminal_loop,
            &mut frontera_enviada,
        );
        if nodo
            .motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta)
            == Some(ventana)
        {
            break;
        }
    }
    let _ = tx_bucle.send(MsgBucle::Parar);
    let _ = hilo.join();
}

/// Líneas del registro con `tipo` y `n` dados (el `n` debe ser el campo exacto, no un prefijo).
pub(super) fn lineas_de(registro: &str, tipo: &str, n: u64) -> Vec<String> {
    let aguja_tipo = format!("\"tipo\":\"{tipo}\"");
    let aguja_comas = format!("\"n\":{n},");
    let aguja_fin = format!("\"n\":{n}}}");
    registro
        .lines()
        .filter(|l| l.contains(&aguja_tipo) && (l.contains(&aguja_comas) || l.contains(&aguja_fin)))
        .map(str::to_string)
        .collect()
}
