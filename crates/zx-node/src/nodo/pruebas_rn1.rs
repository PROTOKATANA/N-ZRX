//! RN-1 · N1–N5 y N7: renovación de los sectores propios, rastro de transacciones y certificado
//! por peso de una ventana posterior a la base.
//!
//! Viven en un módulo interno de `nodo` para poder usar campos y funciones privados del producto
//! (`renovaciones_propias`, `renovar_sectores_propios`, `admitir_tx_en_mempool`,
//! `registrar_transacciones_descartadas`, `inspeccionar_certificados_peso_de_bloque`,
//! `estado_verificacion_peso`) y reutilizan los fixtures reales de `pruebas_eclr2` y `pruebas_pd1f`.
//!
//! Cada prueba está pensada para **fallar sin su regla**: N1 sin S1/S2 deja caducar el sector; N2 sin
//! la cuota por clave admite dos a la vez u ordena mal; N3 sin S3 no reenvía; N4 sin S5 no escribe
//! los eventos; N5 sin S4 renueva ajenos/inactivos; N7 sin S7 no procesa `base + 5`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::panic,
    clippy::too_many_lines,
    reason = "pruebas de escenarios con cadenas construidas a mano; fallan con panic por diseño"
)]

use super::pruebas_eclr2::{
    genesis, hash_u32, params_subsidio, post_con_txs, pow_terminal, productor_firmante,
    tx_clave_voto, tx_coinbase_post,
};
use super::pruebas_pd1f::{cadena_fork_peso, cert_peso, tabla_de};
use super::*;
use zx_core::{CBID_RED_DEV, OperacionSector};

const SEMILLA_RN1: u64 = 0x5a5a;

fn config_rn1(dir: &std::path::Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: SEMILLA_RN1,
        indices_claves: vec![0],
        n_dev: 32,
        sr_dev: u64::MAX,
        perfil_red: crate::perfil::perfil_red_dev(),
        parada_tras_slots: None,
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

fn clave_propia() -> crate::claves::ClaveDev {
    crate::claves::ClaveDev::derivar(SEMILLA_RN1, 0)
}

fn clave_ajena() -> crate::claves::ClaveDev {
    crate::claves::ClaveDev::derivar(SEMILLA_RN1, 7)
}

/// Alta de sector (`0x01`) firmada por `sk` con el índice pedido.
fn tx_alta(
    productor: zx_core::ClavePublica,
    sk: &ed25519_zebra::SigningKey,
    sector_index: u16,
) -> (Tx, Vec<Vec<u8>>) {
    let tx = Tx {
        version: 5,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Sector {
            operacion: OperacionSector::Alta {
                clave: productor,
                sector_index,
                version: 0,
                r2: [3u8; 32],
                history_size: 1 << 10,
            },
        },
    };
    let firma: [u8; 64] = sk.sign(&zx_core::mensaje_sector(&tx, CBID_RED_DEV)).into();
    (tx, vec![firma.to_vec()])
}

/// Cadena real con la clave propia fondeada y su clave de voto BLS registrada, más una Alta por
/// cada `(sector_index, slot)` de `altas`. Devuelve la cadena, la clave propia y la punta
/// `(id, hash, slot)` para seguir extendiendo.
fn cadena_con_sector_propio(
    altas: &[(u16, u64)],
) -> (Cadena, crate::claves::ClaveDev, u32, BlockHash, u64) {
    let propia = clave_propia();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA_RN1, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let mut cadena = Cadena::nueva(params_subsidio(Some(5)), 1, CBID_RED_DEV, 15);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    // Coinbase PoST a la clave propia: fianza (q_sec) y peso.
    cadena
        .admitir(post_con_txs(
            20,
            vec![hash_u32(1)],
            1,
            10,
            propia.pk,
            vec![(tx_coinbase_post(propia.pk, 10_000, 1), Vec::new())],
        ))
        .unwrap();
    let (tx_cv, tst_cv) = tx_clave_voto(propia.pk, &propia.sk, &pk_bls, &sk_bls, CBID_RED_DEV);
    let mut padre = hash_u32(20);
    let mut id = 21u32;
    let mut slot = 2u64;
    cadena
        .admitir(post_con_txs(
            id,
            vec![padre],
            slot,
            10,
            propia.pk,
            vec![(tx_cv, tst_cv)],
        ))
        .unwrap();
    padre = hash_u32(id);
    id += 1;
    for (sector_index, slot_alta) in altas {
        let (tx, tst) = tx_alta(propia.pk, &propia.sk, *sector_index);
        cadena
            .admitir(post_con_txs(
                id,
                vec![padre],
                *slot_alta,
                10,
                propia.pk,
                vec![(tx, tst)],
            ))
            .unwrap();
        padre = hash_u32(id);
        id += 1;
        slot = *slot_alta;
    }
    (cadena, propia, id, padre, slot)
}

/// Cadena real **sin fianza** para la clave propia (solo génesis, terminal PoW y un bloque PoST).
fn cadena_sin_fianza() -> (Cadena, crate::claves::ClaveDev, u32, BlockHash, u64) {
    let propia = clave_propia();
    let mut cadena = Cadena::nueva(params_subsidio(Some(5)), 1, CBID_RED_DEV, 15);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    cadena
        .admitir(post_con_txs(
            20,
            vec![hash_u32(1)],
            1,
            10,
            propia.pk,
            Vec::new(),
        ))
        .unwrap();
    (cadena, propia, 21, hash_u32(20), 1)
}

/// Cadena real con un sector activo de la **clave ajena** (la propia no tiene ninguno).
fn cadena_con_sector_ajeno() -> (Cadena, crate::claves::ClaveDev, u32, BlockHash, u64) {
    let ajena = clave_ajena();
    let mut cadena = Cadena::nueva(params_subsidio(Some(5)), 1, CBID_RED_DEV, 15);
    cadena.admitir(genesis()).unwrap();
    cadena.admitir(pow_terminal(1, 1)).unwrap();
    cadena
        .admitir(post_con_txs(
            20,
            vec![hash_u32(1)],
            1,
            10,
            ajena.pk,
            vec![(tx_coinbase_post(ajena.pk, 10_000, 1), Vec::new())],
        ))
        .unwrap();
    let (tx, tst) = tx_alta(ajena.pk, &ajena.sk, 0);
    cadena
        .admitir(post_con_txs(
            21,
            vec![hash_u32(20)],
            3,
            10,
            ajena.pk,
            vec![(tx, tst)],
        ))
        .unwrap();
    (cadena, ajena, 22, hash_u32(21), 3)
}

/// Sustituye la cadena del nodo y rebasa la mempool **contra esa cadena** (la contabilidad interna
/// de `Nodo` no se actualiza al reemplazar la cadena en estas pruebas).
fn rebasar_desde_cadena(nodo: &mut Nodo, aplicadas: &[Tx]) {
    let estado = nodo.cadena.estado_virtual().expect("estado virtual");
    let punto = zx_consensus::transicion::Punto::Slot(estado.slot);
    let ids: Vec<zx_core::TxId> = aplicadas
        .iter()
        .map(|t| zx_core::txid(t, nodo.cbid))
        .collect();
    let mut m = nodo.mempool.lock().unwrap_or_else(|p| p.into_inner());
    if !ids.is_empty() {
        m.confirmar_aplicadas(&ids, punto);
    }
    m.rebasear(estado, Instant::now(), punto);
}

fn nodo_con_cadena(cfg: &Config, cadena: Cadena) -> Nodo {
    let mut nodo = Nodo::arrancar(cfg).expect("arranque");
    nodo.cadena = cadena;
    rebasar_desde_cadena(&mut nodo, &[]);
    nodo
}

/// Índices de sector de las operaciones `Renovar` que la mempool del nodo incluiría ahora.
fn renovaciones_en_mempool(nodo: &Nodo) -> Vec<u16> {
    let m = nodo.mempool.lock().unwrap_or_else(|p| p.into_inner());
    m.seleccionar(u64::MAX, 0)
        .into_iter()
        .filter_map(|(tx, _)| match &tx.extension {
            ExtensionTx::Sector {
                operacion: OperacionSector::Renovar { sector_index, .. },
            } => Some(*sector_index),
            _ => None,
        })
        .collect()
}

fn cuenta_eventos(cfg: &Config, tipo: &str) -> usize {
    std::fs::read_to_string(&cfg.ruta_registro)
        .map(|s| s.matches(&format!("\"tipo\":\"{tipo}\"")).count())
        .unwrap_or(0)
}

/// Extiende la cadena con bloques (vacíos salvo lo que haya en la mempool) desde `(id, padre, slot)`
/// hasta `slot_fin`, llamando a [`Nodo::renovar_sectores_propios`] antes de cada bloque. Devuelve la
/// punta siguiente.
fn avanzar_con_renovacion(
    nodo: &mut Nodo,
    mut id: u32,
    mut padre: BlockHash,
    mut slot: u64,
    slot_fin: u64,
) -> (u32, BlockHash, u64) {
    let productor = clave_propia().pk;
    while slot <= slot_fin {
        nodo.renovar_sectores_propios(slot);
        let txs: Vec<(Tx, Vec<Vec<u8>>)> = {
            let m = nodo.mempool.lock().unwrap_or_else(|p| p.into_inner());
            m.seleccionar(u64::MAX, 0)
        };
        let b = post_con_txs(id, vec![padre], slot, 10, productor, txs.clone());
        let hash = b.hash();
        nodo.cadena.admitir(b).unwrap();
        let aplicadas: Vec<Tx> = txs.into_iter().map(|(t, _)| t).collect();
        rebasar_desde_cadena(nodo, &aplicadas);
        padre = hash;
        id += 1;
        slot += 1;
    }
    (id, padre, slot)
}

/// Extiende la cadena con bloques vacíos (sin llamar a la renovación) de `slot` a `slot_fin`.
fn avanzar_vacio(
    nodo: &mut Nodo,
    mut id: u32,
    mut padre: BlockHash,
    mut slot: u64,
    slot_fin: u64,
) -> (u32, BlockHash, u64) {
    let productor = clave_propia().pk;
    while slot <= slot_fin {
        let b = post_con_txs(id, vec![padre], slot, 10, productor, Vec::new());
        let hash = b.hash();
        nodo.cadena.admitir(b).unwrap();
        rebasar_desde_cadena(nodo, &[]);
        padre = hash;
        id += 1;
        slot += 1;
    }
    (id, padre, slot)
}

/// Aplica en un bloque lo que la mempool tenga en este momento.
fn aplicar_mempool_en_bloque(
    nodo: &mut Nodo,
    id: u32,
    padre: BlockHash,
    slot: u64,
) -> (u32, BlockHash) {
    let txs: Vec<(Tx, Vec<Vec<u8>>)> = {
        let m = nodo.mempool.lock().unwrap_or_else(|p| p.into_inner());
        m.seleccionar(u64::MAX, 0)
    };
    let b = post_con_txs(id, vec![padre], slot, 10, clave_propia().pk, txs.clone());
    let hash = b.hash();
    nodo.cadena.admitir(b).unwrap();
    let aplicadas: Vec<Tx> = txs.into_iter().map(|(t, _)| t).collect();
    rebasar_desde_cadena(nodo, &aplicadas);
    (id + 1, hash)
}

fn sector_activo(estado: &zx_consensus::transicion::Estado, clave: zx_core::ClavePublica) -> bool {
    let id = SectorId {
        clave,
        sector_index: 0,
        version: 0,
    };
    estado
        .sectores
        .get(&id)
        .is_some_and(|r| r.etapa == Etapa::Activo)
}

// ── N1 ────────────────────────────────────────────────────────────────────────────────────────

/// N1 · un nodo con un sector propio activo lo mantiene activo más allá de `2 · t_cad` slots y la
/// clave sigue en la tabla canónica de votos. Sin S1/S2 el sector caduca al llegar a `t_cad`.
#[test]
fn n1_el_sector_propio_sigue_activo_mas_alla_de_dos_t_cad() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, propia, id, padre, slot) = cadena_con_sector_propio(&[(0, 3)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);

    let p = nodo.cadena.estado_virtual().unwrap().parametros_sector;
    let fin = u64::try_from(2 * p.t_cad + p.m_sec).unwrap();
    avanzar_con_renovacion(&mut nodo, id, padre, slot + 1, fin);

    let estado = nodo.cadena.estado_virtual().unwrap();
    assert!(
        sector_activo(&estado, propia.pk),
        "el sector propio debe seguir Activo en el slot {fin}"
    );
    let tabla =
        zx_consensus::transicion::votos::tabla_canonica(&estado, i64::try_from(fin).unwrap());
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA_RN1, 0).unwrap();
    assert!(
        tabla
            .iter()
            .any(|c| c.clave_bls == sk_bls.clave_publica().bytes()),
        "la clave propia debe seguir en la tabla canónica de votos"
    );
    assert!(
        cuenta_eventos(&cfg, "renovacion_enviada") >= 3,
        "el nodo renovó varias veces durante la corrida"
    );
}

// ── N2 ────────────────────────────────────────────────────────────────────────────────────────

/// N2 · dos sectores de la misma clave que vencen a la vez se renuevan uno detrás de otro, sin dos
/// operaciones en vuelo y con el `renovacion_slot` más antiguo primero.
#[test]
fn n2_dos_sectores_uno_detras_de_otro_el_mas_antiguo_primero() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    // El segundo alta de la misma caja exige `m_sec` slots desde la primera (`ErrMaduracion`).
    let (cadena, _propia, id, padre, slot) = cadena_con_sector_propio(&[(0, 3), (1, 15)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let p = nodo.cadena.estado_virtual().unwrap().parametros_sector;
    // Promueve ambos sectores a Activo (necesitan `m_sec` slots desde su alta).
    let (id, padre, _) = avanzar_vacio(
        &mut nodo,
        id,
        padre,
        slot + 1,
        u64::try_from(15 + p.m_sec).unwrap(),
    );
    let umbral = u64::try_from(27 + p.t_cad / 2).unwrap();
    nodo.renovar_sectores_propios(umbral);
    assert_eq!(
        renovaciones_en_mempool(&nodo),
        vec![0],
        "primero el sector de renovacion_slot más antiguo y solo uno"
    );
    // Se aplica la del sector 0; al reevaluar toca el sector 1, tampoco a la vez.
    let (id, padre) = aplicar_mempool_en_bloque(&mut nodo, id, padre, umbral);
    nodo.renovar_sectores_propios(umbral + 1);
    assert_eq!(renovaciones_en_mempool(&nodo), vec![1]);
    assert_eq!(
        nodo.renovaciones_propias.len(),
        1,
        "una sola renovación en vuelo por clave"
    );
    let _ = (id, padre);
}

// ── N3 ────────────────────────────────────────────────────────────────────────────────────────

/// N3 · una renovación que no se aplica se reenvía tras `m_sec · 4` slots y no antes.
#[test]
fn n3_reenvio_solo_tras_m_sec_por_cuatro() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, _propia, id, padre, slot) = cadena_con_sector_propio(&[(0, 3)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let p = nodo.cadena.estado_virtual().unwrap().parametros_sector;
    // Promueve el sector a Activo.
    let _ = avanzar_vacio(
        &mut nodo,
        id,
        padre,
        slot + 1,
        u64::try_from(3 + p.m_sec).unwrap(),
    );
    let slot_envio = u64::try_from(15 + p.t_cad / 2).unwrap();
    nodo.renovar_sectores_propios(slot_envio);
    assert_eq!(cuenta_eventos(&cfg, "renovacion_enviada"), 1);

    // Se vacía la mempool (la renovación no se aplicó ni sigue en vuelo allí).
    nodo.mempool
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .expirar(zx_consensus::transicion::Punto::Slot(u64::MAX));
    assert!(renovaciones_en_mempool(&nodo).is_empty());

    let espera = u64::try_from(p.m_sec).unwrap() * 4;
    nodo.renovar_sectores_propios(slot_envio + espera - 1);
    assert_eq!(
        cuenta_eventos(&cfg, "renovacion_enviada"),
        1,
        "antes de m_sec·4 no se reenvía"
    );
    nodo.renovar_sectores_propios(slot_envio + espera);
    assert_eq!(
        cuenta_eventos(&cfg, "renovacion_enviada"),
        2,
        "a los m_sec·4 slots sí se reconstruye y se reenvía"
    );
}

// ── N4 ────────────────────────────────────────────────────────────────────────────────────────

/// N4 · la parte 2: una operación de sector rechazada por la mempool deja `tx_rechazada` con su
/// motivo; un `0x09` que el consenso descarta en un bloque admitido deja `tx_descartada`; una
/// admitida deja `tx_admitida`.
#[test]
fn n4_rastro_de_transacciones_admitidas_rechazadas_y_descartadas() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, _propia, id, padre, slot) = cadena_con_sector_propio(&[(0, 3)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);

    // (c) admitida: la renovación propia (S2/S5) deja `tx_admitida` con clase y origen.
    let p = nodo.cadena.estado_virtual().unwrap().parametros_sector;
    let _ = avanzar_vacio(
        &mut nodo,
        id,
        padre,
        slot + 1,
        u64::try_from(3 + p.m_sec).unwrap(),
    );
    nodo.renovar_sectores_propios(u64::try_from(15 + p.t_cad / 2).unwrap());
    let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    let linea_ok = registro
        .lines()
        .find(|l| l.contains("\"tipo\":\"tx_admitida\""))
        .expect("tx_admitida");
    assert!(linea_ok.contains("\"clase\":\"sector_renovar\""));
    assert!(linea_ok.contains("\"origen\":\"propia\""));

    // (a) rechazada: sobre una cadena sin fianza, el alta se rechaza con su motivo.
    let dir2 = tempfile::tempdir().unwrap();
    let cfg2 = config_rn1(dir2.path());
    let (cadena2, propia2, _id2, _padre2, _slot2) = cadena_sin_fianza();
    let mut nodo2 = nodo_con_cadena(&cfg2, cadena2);
    let (tx_mal, tst_mal) = tx_alta(propia2.pk, &propia2.sk, 0);
    let r2 = nodo2.admitir_tx_en_mempool(tx_mal, tst_mal, "propia");
    assert!(r2.is_err(), "sin fianza la mempool rechaza el alta");
    let registro2 = std::fs::read_to_string(&cfg2.ruta_registro).unwrap();
    let linea_mal = registro2
        .lines()
        .find(|l| l.contains("\"tipo\":\"tx_rechazada\""))
        .expect("tx_rechazada");
    assert!(linea_mal.contains("\"clase\":\"sector_alta\""));
    assert!(linea_mal.contains("\"origen\":\"propia\""));
    assert!(linea_mal.contains("\"motivo\":"));
}

/// N4 (parte 2) · un `0x09` inválido dentro de un bloque admitido (fusión) deja `tx_descartada` con
/// bloque, índice, identificador, clase y motivo.
#[test]
fn n4_un_0x09_descartado_en_bloque_admitido_deja_tx_descartada() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, _propia, id, padre, slot) = cadena_con_sector_propio(&[(0, 3)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let (productor, sk) = productor_firmante();
    // `0x09` con bytes basura: la forma (con testigo) lo deja pasar y el consenso lo descarta.
    let tx09 = Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: zx_core::OperacionAlmacenamiento::CertificadoPeso {
                clave: productor,
                bytes: vec![0u8; 8],
            },
        },
    };
    let firma: [u8; 64] = sk
        .sign(&zx_core::mensaje_almacenamiento(&tx09, CBID_RED_DEV))
        .into();
    let b = post_con_txs(
        id,
        vec![padre],
        slot + 1,
        10,
        productor,
        vec![(tx09.clone(), vec![firma.to_vec()])],
    );
    let hash = b.hash();
    nodo.cadena
        .admitir(b)
        .expect("el bloque se admite; la tx se descarta");
    assert!(
        nodo.cadena.descartes(&hash).is_some_and(|d| !d.is_empty()),
        "el consenso registró el descarte"
    );
    nodo.registrar_transacciones_descartadas(&hash, &[tx09]);
    let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    let linea = registro
        .lines()
        .find(|l| l.contains("\"tipo\":\"tx_descartada\""))
        .expect("tx_descartada");
    assert!(linea.contains("\"clase\":\"almacenamiento_certificado_peso\""));
    assert!(linea.contains("\"motivo\":"));
    assert!(linea.contains(&format!("\"bloque\":\"{hash}\"")));
}

/// TB-1c-2 · X5/N3 · un bloque **admitido** que descarta un `0x09` por `TablaNoDerivada` deja el
/// evento `certificado_tabla_no_derivada` con su ventana y su huella (antes solo salía al rechazar
/// el bloque entero).
#[test]
fn tb1c2_evento_tabla_no_derivada_en_bloque_admitido() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, _propia, id, padre, slot) = cadena_con_sector_propio(&[(0, 3)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let (productor, sk) = productor_firmante();
    // `0x09` con la forma fija de 200 B y una huella declarada que el estado sin base no tiene en su
    // cola: el consenso lo descarta por `TablaNoDerivada` (se decide antes de firmas y del mapa).
    let n = 2u64;
    let huella = [0xEEu8; 32];
    let mut bytes = vec![0u8; 200];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    bytes[40..72].copy_from_slice(&huella);
    let tx09 = Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: zx_core::OperacionAlmacenamiento::CertificadoPeso {
                clave: productor,
                bytes,
            },
        },
    };
    let firma: [u8; 64] = sk
        .sign(&zx_core::mensaje_almacenamiento(&tx09, CBID_RED_DEV))
        .into();
    let b = post_con_txs(
        id,
        vec![padre],
        slot + 1,
        10,
        productor,
        vec![(tx09.clone(), vec![firma.to_vec()])],
    );
    let hash = b.hash();
    nodo.cadena
        .admitir(b)
        .expect("el bloque se admite; la tx se descarta");
    assert!(
        nodo.cadena.descartes(&hash).is_some_and(|d| !d.is_empty()),
        "el consenso registró el descarte"
    );
    nodo.registrar_transacciones_descartadas(&hash, &[tx09]);
    let registro = std::fs::read_to_string(&cfg.ruta_registro).unwrap();
    assert!(
        registro.contains("\"tipo\":\"certificado_tabla_no_derivada\""),
        "evento X5/N3: {registro}"
    );
    assert!(
        registro.contains(&crate::votos::hex(&huella)),
        "el evento lleva la huella: {registro}"
    );
}

// ── N5 ────────────────────────────────────────────────────────────────────────────────────────

/// N5 · no se renueva un sector ajeno aunque necesite renovación.
#[test]
fn n5_no_renueva_un_sector_ajeno() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, ajena, id, padre, slot) = cadena_con_sector_ajeno();
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let p = nodo.cadena.estado_virtual().unwrap().parametros_sector;
    let _ = avanzar_vacio(
        &mut nodo,
        id,
        padre,
        slot + 1,
        u64::try_from(3 + p.m_sec).unwrap(),
    );
    let slot_necesario = u64::try_from(15 + p.t_cad / 2).unwrap();
    nodo.renovar_sectores_propios(slot_necesario);
    assert!(
        renovaciones_en_mempool(&nodo).is_empty(),
        "no se encola ninguna renovación de una clave ajena"
    );
    assert!(nodo.renovaciones_propias.is_empty());
    assert!(
        nodo.cadena
            .estado_virtual()
            .unwrap()
            .sectores
            .keys()
            .any(|s| s.clave == ajena.pk)
    );
}

/// N5 · no se renueva un sector propio que ya no está activo.
#[test]
fn n5_no_renueva_un_sector_inactivo() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, propia, id, padre, slot) = cadena_con_sector_propio(&[(0, 3)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let p = nodo.cadena.estado_virtual().unwrap().parametros_sector;
    // Se deja caducar sin renovar: se avanza más allá de `renovacion_slot + t_cad`.
    let caducado = u64::try_from(15 + p.t_cad + 1).unwrap();
    avanzar_vacio(&mut nodo, id, padre, slot + 1, caducado);
    let estado = nodo.cadena.estado_virtual().unwrap();
    assert!(!sector_activo(&estado, propia.pk), "el sector caducó");
    nodo.renovar_sectores_propios(caducado + 1);
    assert!(
        renovaciones_en_mempool(&nodo).is_empty(),
        "no se renueva un sector inactivo"
    );
}

/// N5 · un pago corriente no deja ninguno de los tres eventos nuevos.
#[test]
fn n5_un_pago_corriente_no_deja_eventos() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let (cadena, _propia, _id, _padre, _slot) = cadena_con_sector_propio(&[(0, 3)]);
    let mut nodo = nodo_con_cadena(&cfg, cadena);
    let pago = Tx {
        version: 1,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let _ = nodo.admitir_tx_en_mempool(pago, Vec::new(), "red");
    for tipo in ["tx_admitida", "tx_rechazada", "tx_descartada"] {
        assert_eq!(
            cuenta_eventos(&cfg, tipo),
            0,
            "un pago corriente no deja {tipo}"
        );
    }
}

// ── N7 ────────────────────────────────────────────────────────────────────────────────────────

/// N7 · S7: un `0x09` válido de la ventana `base + 5` firmado con la **misma** tabla, llegado en un
/// bloque rechazado, se verifica y la cadena recibe el ancla verificada. Sin S7 solo se intenta
/// `base + 1` y el certificado se queda en el depósito.
#[test]
fn n7_certificado_de_ventana_posterior_con_la_misma_tabla() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let cadena = cadena_fork_peso();
    let sk_bls = crate::votos::clave_voto_dev(SEMILLA_RN1, 0).unwrap();
    let pk_bls = sk_bls.clave_publica();
    let t0 = tabla_de(&cadena, 30);
    let h_t0 = zx_votos::hash_tabla(&t0);
    let (_cert0, tx0) = cert_peso(
        &t0,
        0,
        *hash_u32(10).as_bytes(),
        h_t0,
        None,
        &sk_bls,
        &pk_bls,
    );
    let (_cert5, tx5) = cert_peso(
        &t0,
        5,
        *hash_u32(20).as_bytes(),
        h_t0,
        None,
        &sk_bls,
        &pk_bls,
    );

    let mut nodo = nodo_con_cadena(&cfg, cadena);
    assert!(nodo.motor_votos.is_some(), "motor por peso");
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx0], 30);
    assert_eq!(
        nodo.estado_verificacion_peso
            .as_ref()
            .map(|e| e.finalidad_votos_n),
        Some(0),
        "la base se fija en la ventana 0"
    );
    nodo.inspeccionar_certificados_peso_de_bloque(&[tx5], 30);
    assert_eq!(
        nodo.estado_verificacion_peso
            .as_ref()
            .map(|e| e.finalidad_votos_n),
        Some(5),
        "S7: se intenta la menor ventana pendiente > base y avanza a la 5"
    );
    assert_eq!(nodo.cadena.ancla_votos(), Some((5, hash_u32(20))));
    assert!(
        nodo.pasos_peso_pendientes.is_empty(),
        "el certificado aplicado sale del depósito"
    );
}

/// N6 · M6 · la renovación se evalúa **una vez por cambio de slot**: en vueltas con el mismo slot no
/// vuelve a calcular el estado virtual. El contador es solo de test.
#[test]
fn n6_renovacion_una_vez_por_slot() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_rn1(dir.path());
    let mut nodo = Nodo::arrancar(&cfg).unwrap();
    let slot = 1234;
    ESTADO_VIRTUAL_RENOVACION.with(|c| c.set(0));
    nodo.renovar_si_cambia_slot(slot);
    let primera = ESTADO_VIRTUAL_RENOVACION.with(|c| c.get());
    assert_eq!(
        primera, 1,
        "la primera vuelta del slot calcula el estado virtual"
    );
    nodo.renovar_si_cambia_slot(slot);
    let misma = ESTADO_VIRTUAL_RENOVACION.with(|c| c.get());
    assert_eq!(
        misma, primera,
        "sin cambio de slot no recalcula el estado virtual"
    );
    nodo.renovar_si_cambia_slot(slot + 1);
    let siguiente = ESTADO_VIRTUAL_RENOVACION.with(|c| c.get());
    assert_eq!(
        siguiente,
        primera + 1,
        "un slot nuevo vuelve a evaluar la renovación"
    );
}
