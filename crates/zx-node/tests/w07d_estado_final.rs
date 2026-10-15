//! `ORDEN-W07d`: registro del estado final.
//!
//! - **reinicio_completo**: al reabrir, el `resumen_estado` del evento coincide con el estado
//!   virtual que calcula el propio nodo, y lleva `punta`, `n_bloques_dag` y `compendio_bloques`.
//! - **compendio_bloques / resumen_estado**: el mismo conjunto de bloques admitidos en órdenes
//!   distintos da el mismo compendio y el mismo resumen (las funciones exactas que usan los nodos).
//! - **parada por SIGTERM**: un proceso real atiende la señal, escribe `parada` (crítico) y sale con
//!   código 0.
//!
//! Límite declarado (falta de definición 10): no se levantan dos procesos reales con el mismo
//! conjunto en órdenes distintos; se comprueba sobre `compendio_de_almacen` y `resumen_estado`, que
//! son las funciones que esos nodos invocarían.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zx_consensus::transicion::{EntradaUtxo, Estado, Origen, Punto};
use zx_core::digest::{BlockHash, Digest};
use zx_core::preimage::block::{BlockHeader, merkle_root};
use zx_core::red::Red;
use zx_core::{Amount, ClavePublica, Lock, OutPoint, TxId};
use zx_node::compendio::compendio_de_almacen;
use zx_node::estado_resumen::resumen_estado;
use zx_node::nodo::{Config, Nodo};
use zx_storage::{Almacen, AlmacenEnMemoria, BloqueAdmitido};

const N_DEV_TEST: u64 = 32;
const SR_DEV_TEST: u64 = u64::MAX;

fn config_de_test(dir: &Path, parada_tras_slots: u64) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 0x1234,
        indices_claves: vec![0, 1, 2],
        n_dev: N_DEV_TEST,
        sr_dev: SR_DEV_TEST,
        perfil_red: zx_node::perfil::perfil_red_dev(),
        parada_tras_slots: Some(parada_tras_slots),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

fn lanzar(dir: &Path, parada_tras_slots: u64) -> Child {
    Command::new(env!("CARGO_BIN_EXE_zx-node"))
        .args([
            "--datos",
            dir.join("datos").to_str().expect("ruta"),
            "--registro",
            dir.join("registro.jsonl").to_str().expect("ruta"),
            "--red",
            "dev",
            "--semilla",
            "4660", // 0x1234
            "--claves",
            "0,1,2",
            "--n-dev",
            "32",
            "--sr-dev",
            "18446744073709551615",
            "--parada-tras-slots",
            &parada_tras_slots.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("lanza zx-node")
}

/// Espera a que el registro contenga `aguja` (texto JSON exacto, p. ej. `"bloque_minado"`).
fn esperar_aguja(ruta_registro: &Path, aguja: &str, plazo_seg: u64) {
    let limite = Instant::now() + Duration::from_secs(plazo_seg);
    loop {
        let contenido = std::fs::read_to_string(ruta_registro).unwrap_or_default();
        if contenido.contains(aguja) {
            return;
        }
        assert!(
            Instant::now() < limite,
            "no se observó {aguja} en {plazo_seg} s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Valor crudo de `"clave":valor` en una línea JSON plana (cadena sin escapes o número).
fn campo(linea: &str, clave: &str) -> String {
    let patron = format!("\"{clave}\":");
    let inicio = linea
        .find(&patron)
        .unwrap_or_else(|| panic!("sin el campo {clave}: {linea}"))
        + patron.len();
    let resto = &linea[inicio..];
    if let Some(sin_comilla) = resto.strip_prefix('"') {
        let fin = sin_comilla
            .find('"')
            .unwrap_or_else(|| panic!("cadena sin cerrar: {linea}"));
        sin_comilla[..fin].to_string()
    } else {
        let fin = resto
            .find([',', '}'])
            .unwrap_or_else(|| panic!("valor sin cerrar: {linea}"));
        resto[..fin].to_string()
    }
}

fn es_hex64(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Última línea del registro con `tipo`.
fn ultima_de_tipo(contenido: &str, tipo: &str) -> String {
    contenido
        .lines()
        .rev()
        .find(|l| l.contains(&format!("\"tipo\":\"{tipo}\"")))
        .unwrap_or_else(|| panic!("no hay ningún evento {tipo}"))
        .to_string()
}

/// Bloque PoW sintético para el test de determinismo (mismo patrón que `zx-storage`).
fn bloque_sintetico(nonce: u64) -> BloqueAdmitido<'static> {
    let cabecera = BlockHeader {
        consensus_branch_id: zx_core::CBID_RED_DEV,
        prev_hash: BlockHash::from_digest(Digest::from_bytes([0x11; 32])),
        merkle_root: merkle_root(&[]),
        timestamp: 1_788_480_000 + nonce,
        bits: 0x1d00_ffff,
        nonce,
        height: 1,
    };
    BloqueAdmitido::pow(&cabecera, &[], &[])
}

fn entrada_utxo(valor: i64) -> EntradaUtxo {
    EntradaUtxo {
        valor: Amount::nuevo(valor).expect("importe válido"),
        lock: Lock::PubKey {
            pubkey: ClavePublica::desde_bytes([0xAA; 32]),
        },
        origen: Origen::Tx,
        creada: Punto::Altura(3),
    }
}

fn outpoint(marca: u8) -> OutPoint {
    OutPoint {
        prev_txid: TxId::from_digest(Digest::from_bytes([marca; 32])),
        prev_index: u32::from(marca),
    }
}

#[test]
fn reinicio_completo_coincide_con_el_estado_virtual_reabierto() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_test(dir.path(), 100_000);

    // Proceso real: basta un bloque PoW persistido; luego SIGKILL para forzar la repetición.
    let mut hijo = lanzar(dir.path(), 100_000);
    esperar_aguja(&cfg.ruta_registro, "\"bloque_minado\"", 180);
    hijo.kill().expect("mata al hijo");
    hijo.wait().expect("lo entierra");

    // Reabrir repite el almacén y escribe `reinicio_completo` con los campos nuevos.
    let nodo = Nodo::arrancar(&cfg).expect("reabrir y repetir el almacén");
    let punta = nodo
        .cadena()
        .mejor_punta()
        .or(nodo.cadena().terminal())
        .map(|h| h.to_string())
        .unwrap_or_default();
    let resumen_esperado = nodo
        .resumen_estado_actual()
        .expect("el estado virtual del nodo reabierto se calcula");
    let n_bloques_dag = nodo.cadena().bloques_admitidos();
    drop(nodo);

    let contenido = std::fs::read_to_string(&cfg.ruta_registro).expect("leer registro");
    let linea = ultima_de_tipo(&contenido, "reinicio_completo");
    assert_eq!(campo(&linea, "resumen_estado"), resumen_esperado);
    assert_eq!(campo(&linea, "punta"), punta);
    assert_eq!(campo(&linea, "n_bloques_dag"), n_bloques_dag.to_string());
    assert!(es_hex64(&campo(&linea, "compendio_bloques")));
}

#[test]
fn mismo_conjunto_en_orden_distinto_da_el_mismo_compendio_y_resumen() {
    // Compendio: dos almacenes con el mismo conjunto de bloques en orden y en orden inverso.
    let bloques: Vec<BloqueAdmitido<'static>> = (0..5).map(bloque_sintetico).collect();
    let genesis = BlockHash::from_digest(Digest::from_bytes([0; 32]));

    let en_orden = AlmacenEnMemoria::nuevo(Red::Dev, genesis);
    for b in &bloques {
        en_orden.admitir(b, true).expect("admitir");
    }
    let invertido = AlmacenEnMemoria::nuevo(Red::Dev, genesis);
    for b in bloques.iter().rev() {
        invertido.admitir(b, true).expect("admitir");
    }
    let compendio_orden = compendio_de_almacen(&en_orden).expect("compendio");
    assert_eq!(
        compendio_orden,
        compendio_de_almacen(&invertido).expect("compendio")
    );
    assert!(es_hex64(&compendio_orden));

    // Resumen: dos estados con las mismas entradas insertadas en distinto orden.
    let mut e1 = Estado::inicial();
    e1.utxo.insert(outpoint(1), entrada_utxo(10));
    e1.utxo.insert(outpoint(2), entrada_utxo(20));
    e1.emitido = 30;

    let mut e2 = Estado::inicial();
    e2.emitido = 30;
    e2.utxo.insert(outpoint(2), entrada_utxo(20));
    e2.utxo.insert(outpoint(1), entrada_utxo(10));

    assert_eq!(e1, e2);
    assert_eq!(resumen_estado(&e1), resumen_estado(&e2));
}

#[test]
fn parada_por_sigterm_en_proceso_real_sale_con_cero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_test(dir.path(), 100_000);
    let mut hijo = lanzar(dir.path(), 100_000);

    // El nodo ya cruzó el arranque y está minando (fase PoW): la señal se atiende sin depender del
    // corte.
    esperar_aguja(&cfg.ruta_registro, "\"bloque_minado\"", 180);
    let pid = hijo.id();
    let estado_kill = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("ejecutar kill -TERM");
    assert!(estado_kill.success(), "kill -TERM falló");

    let limite = Instant::now() + Duration::from_secs(60);
    let estado = loop {
        match hijo.try_wait().expect("try_wait") {
            Some(estado) => break estado,
            None if Instant::now() < limite => std::thread::sleep(Duration::from_millis(50)),
            None => {
                let _ = hijo.kill();
                panic!("el nodo no terminó en 60 s tras SIGTERM");
            }
        }
    };
    assert_eq!(
        estado.code(),
        Some(0),
        "el nodo debe salir con código 0 tras SIGTERM: {estado:?}"
    );

    let contenido = std::fs::read_to_string(&cfg.ruta_registro).expect("leer registro");
    let linea = ultima_de_tipo(&contenido, "parada");
    assert_eq!(campo(&linea, "motivo"), "sigterm");
    assert!(
        !campo(&linea, "resumen_estado").is_empty(),
        "parada sin resumen_estado: {linea}"
    );
    assert!(es_hex64(&campo(&linea, "compendio_bloques")));
    assert!(
        campo(&linea, "n_bloques_dag")
            .bytes()
            .all(|b| b.is_ascii_digit()),
        "n_bloques_dag no entero: {linea}"
    );
}
