//! RED-1B: identidad congelada y cartera real contra un nodo dev-reloj real.
//! Preparación: `cargo build -p zx-cartera --bin zx-cartera --locked --offline`.
//! No se mina ni se modifica el perfil del nodo.

#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]

use clap::ValueEnum;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use zx_node::cli::{OpcionesRegistro, RedCli};
use zx_node::nodo::{Config, Nodo};

fn cartera() -> PathBuf {
    std::env::current_exe()
        .expect("ruta del test")
        .parent()
        .expect("directorio deps")
        .parent()
        .expect("directorio del perfil")
        .join(format!("zx-cartera{}", std::env::consts::EXE_SUFFIX))
}

#[test]
fn red1b_la_identidad_compartida_es_la_del_nodo_en_cada_red() {
    for seleccion in RedCli::value_variants() {
        let bytes = match seleccion {
            RedCli::Dev => [
                0xc7, 0x2f, 0xdb, 0x3b, 0x37, 0xe7, 0x57, 0x1a, 0x82, 0xec, 0x1e, 0x0e, 0x97, 0x3e,
                0x90, 0xd5, 0xe9, 0x5e, 0x7a, 0xd9, 0xfc, 0x87, 0x17, 0x72, 0x26, 0x5b, 0x19, 0x94,
                0x05, 0x0c, 0x2d, 0x59,
            ],
            RedCli::DevReloj => [
                0xbf, 0x08, 0x47, 0x2e, 0xc4, 0xeb, 0xb5, 0x02, 0xd1, 0xa5, 0xcc, 0xa8, 0x6b, 0x9e,
                0x37, 0x2a, 0x8e, 0x8f, 0x40, 0xde, 0x21, 0x64, 0xe6, 0x8c, 0xc0, 0x31, 0x72, 0x2b,
                0x7c, 0x00, 0x88, 0x36,
            ],
            RedCli::Mainnet | RedCli::Testnet => continue,
        };
        let anterior = zx_core::BlockHash::from_digest(zx_core::Digest::from_bytes(bytes));
        let perfil = seleccion.perfil_red().expect("perfil actual del nodo");
        assert_eq!(perfil.etiqueta, seleccion.etiqueta_consenso());
        assert_eq!(perfil.reloj_activo, seleccion.reloj_activo());
        let del_nodo = zx_node::perfil::identidad_red(&perfil);
        assert_eq!(
            del_nodo,
            zx_core::red::identidad_red(
                zx_consensus::genesis::HASH_GENESIS_DEV,
                seleccion.etiqueta_consenso(),
                seleccion.reloj_activo(),
            ),
            "nodo y cartera comparten la identidad de {seleccion:?}"
        );
        match seleccion {
            RedCli::Dev => assert_eq!(del_nodo, anterior, "la identidad de dev NO cambia (RLJ-3a)"),
            RedCli::DevReloj => {
                assert_ne!(
                    del_nodo, anterior,
                    "la identidad de dev-reloj cambia (RLJ-3a)"
                );
                assert_eq!(
                    zx_core::red::ETIQUETA_DEV_RELOJ_R3,
                    "dev-reloj-r3-pmt-sp-banda-diag-v1",
                    "etiqueta de consenso R3 literal"
                );
            }
            RedCli::Mainnet | RedCli::Testnet => {}
        }
    }
}

#[test]
fn red1b_las_opciones_de_red_de_la_cartera_son_las_del_nodo() {
    let binario = cartera();
    assert!(
        binario.is_file(),
        "construya primero zx-cartera: {}",
        binario.display()
    );
    let valores: Vec<_> = RedCli::value_variants()
        .iter()
        .map(|red| red.to_possible_value().expect("valor del nodo"))
        .collect();
    let nombres: Vec<_> = valores
        .iter()
        .map(clap::builder::PossibleValue::get_name)
        .collect();
    for modo in ["enviar", "observar"] {
        let salida = Command::new(&binario)
            .args([modo, "--help"])
            .output()
            .expect("ayuda cartera");
        assert!(salida.status.success());
        let texto = String::from_utf8(salida.stdout).expect("ayuda UTF-8");
        let mostrados: Vec<_> = texto
            .lines()
            .filter_map(|linea| linea.trim().strip_prefix("- "))
            .filter_map(|valor| valor.split_once(':').map(|(nombre, _)| nombre))
            .collect();
        assert_eq!(mostrados, nombres, "{texto}");
        assert!(
            texto.contains(&format!("[default: {}]", RedCli::POR_DEFECTO.nombre())),
            "{texto}"
        );
    }
    for red in RedCli::value_variants() {
        let cadena = zx_core::Red::from(*red);
        if cadena == zx_core::Red::Dev {
            continue;
        }
        let salida = Command::new(&binario)
            .args([
                "observar",
                "--red",
                red.nombre(),
                "--objetivo",
                "/ip4/127.0.0.1/tcp/1",
                "--segundos",
                "0",
            ])
            .output()
            .expect("cartera reconoce y rechaza red no operativa");
        assert_eq!(salida.status.code(), Some(1));
        let texto = String::from_utf8(salida.stderr).expect("error UTF-8");
        assert!(
            texto.contains(
                &zx_node::error::ErrorNodo::RedNoEsDev { encontrada: cadena }.to_string()
            ),
            "{texto}"
        );
        assert!(
            !texto.contains("no se pudo conectar"),
            "debe rechazar antes de conectar: {texto}"
        );
    }
}

struct Cliente(Child);

impl Drop for Cliente {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn comprobar(expulsado: bool) {
    let binario = cartera();
    assert!(
        binario.is_file(),
        "construya primero zx-cartera: {}",
        binario.display()
    );
    for modo in ["enviar", "observar"] {
        let dir = tempfile::tempdir().expect("tempdir dentro de TMPDIR");
        let ruta_registro = dir.path().join("registro.jsonl");
        let cfg = Config {
            dir_datos: dir.path().join("datos"),
            ruta_registro: ruta_registro.clone(),
            red: zx_core::Red::Dev,
            semilla: 1,
            indices_claves: vec![0],
            n_dev: 32,
            sr_dev: u64::MAX,
            perfil_red: zx_node::perfil::perfil_red_dev_reloj().expect("perfil real"),
            parada_tras_slots: None,
            dejar_de_producir_en_slot: None,
            punto_control: None,
            sin_voto: false,
            sin_revelacion: false,
        };
        let nodo = Nodo::arrancar(&cfg).expect("Nodo real con reloj activo");
        assert_eq!(
            nodo.vista_red().estado().hash_genesis,
            zx_node::perfil::identidad_red(&cfg.perfil_red)
        );
        let reserva = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("puerto libre");
        let puerto = reserva.local_addr().expect("dirección").port();
        drop(reserva);
        let direccion = format!("/ip4/127.0.0.1/tcp/{puerto}");
        let red = zx_node::red::arrancar_con_datos(
            Some(direccion.parse().expect("multiaddr")),
            Vec::new(),
            nodo.vista_red(),
            nodo.registro(),
            Some(cfg.dir_datos.join("red")),
            nodo.mempool(),
            OpcionesRegistro::apagado(),
        )
        .expect("red real con sincronización y comprobación de identidad");
        let plazo_escucha = Instant::now() + Duration::from_secs(5);
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", puerto)).is_ok() {
                break;
            }
            assert!(
                Instant::now() < plazo_escucha,
                "el nodo no escucha en 127.0.0.1"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let ruta_salida = dir.path().join("cliente.log");
        let salida = std::fs::File::create(&ruta_salida).expect("salida cartera");
        let mut comando = Command::new(&binario);
        comando.args([
            "--red",
            if expulsado { "dev" } else { "dev-reloj" },
            modo,
            "--objetivo",
            &direccion,
        ]);
        if modo == "enviar" {
            // Una transacción determinista firmada por el cliente del producto, sin claves en disco.
            let construida = Command::new(&binario)
                .args(["retiro", "--indice", "0", "--importe", "1", "--nonce", "0"])
                .output()
                .expect("construir transacción de cartera");
            assert!(construida.status.success());
            let texto = String::from_utf8(construida.stdout).expect("transacción UTF-8");
            let tx = texto
                .lines()
                .find_map(|l| l.strip_prefix("tx="))
                .expect("tx firmada");
            comando.args(["--hex", tx, "--plazo-s", "2"]);
        } else {
            comando.args(["--segundos", "2"]);
        }
        let mut cliente = Cliente(
            comando
                .stdout(Stdio::from(salida.try_clone().expect("duplicar salida")))
                .stderr(Stdio::from(salida))
                .spawn()
                .expect("binario real de la cartera"),
        );
        let plazo = Instant::now() + Duration::from_secs(45);
        loop {
            let registro = std::fs::read_to_string(&ruta_registro).expect("registro del nodo");
            let texto = std::fs::read_to_string(&ruta_salida).expect("salida de la cartera");
            let rechazo = registro.contains("génesis o red ajenos");
            if expulsado && rechazo && registro.contains("\"tipo\":\"par_desconectado\"") {
                assert!(registro.contains("\"accion\":\"expulsion\""));
                println!("zx-cartera {modo}: dev expulsada por identidad ajena\n{registro}");
                break;
            }
            assert!(
                !rechazo || expulsado,
                "cartera de la misma red expulsada: {registro}\n{texto}"
            );
            if let Some(estado) = cliente.0.try_wait().expect("estado del proceso")
                && !expulsado
            {
                assert_eq!(estado.code(), Some(0), "salida inesperada: {texto}");
                assert!(
                    texto.contains("conectado=true"),
                    "sin conexión: {texto}\n{registro}"
                );
                if !registro.contains("\"tipo\":\"par_desconectado\"") {
                    assert!(
                        Instant::now() < plazo,
                        "el nodo no registra el cierre normal: {texto}\n{registro}"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                if modo == "enviar" {
                    assert!(
                        texto.contains("publicado="),
                        "sin publicación: {texto}\n{registro}"
                    );
                    assert!(
                        !texto.contains("error_publicando="),
                        "publicación fallida: {texto}"
                    );
                } else {
                    assert!(
                        texto.contains("observados="),
                        "observación sin terminar: {texto}"
                    );
                }
                assert!(registro.contains("\"tipo\":\"par_conectado\""));
                assert!(
                    !registro.contains("\"accion\":\"expulsion\""),
                    "hubo expulsión: {registro}"
                );
                println!("zx-cartera {modo}: dev-reloj aceptada\n{texto}\n{registro}");
                break;
            }
            assert!(
                Instant::now() < plazo,
                "sin evidencia en el plazo: {texto}\n{registro}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(cliente);
        drop(red);
        drop(nodo);
    }
}

#[test]
fn red1b_un_nodo_dev_reloj_no_expulsa_a_la_cartera_de_su_red() {
    comprobar(false);
}

#[test]
fn red1b_un_nodo_dev_reloj_expulsa_a_la_de_dev() {
    comprobar(true);
}
