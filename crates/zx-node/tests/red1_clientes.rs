//! RED-1: los dos binarios reales hablan con un Nodo real y su sincronización TCP.
//! No se mina: el objeto Nodo arranca el perfil dev-reloj y la red completa atiende el saludo.

#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use zx_node::cli::OpcionesRegistro;
use zx_node::nodo::{Config, Nodo};

struct Cliente(Child);

impl Drop for Cliente {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn comprobar(expulsado: bool) {
    for (binario, argumentos, aceptado, rc_esperado) in [
        (
            env!("CARGO_BIN_EXE_zx-txcliente"),
            vec!["--plazo-s", "6", "sector-alta"],
            "alta de sector publicada",
            0,
        ),
        (
            env!("CARGO_BIN_EXE_zx-adversario"),
            vec![
                "doble-firma",
                "--clave-indice",
                "0",
                "--plazo-espera-s",
                "2",
            ],
            "el objetivo confirmó su suscripción a los dos temas",
            1,
        ),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
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
        let salida = std::fs::File::create(&ruta_salida).expect("salida cliente");
        let mut cliente = Cliente(
            Command::new(binario)
                .args([
                    "--objetivo",
                    &direccion,
                    "--red",
                    if expulsado { "dev" } else { "dev-reloj" },
                ])
                .args(argumentos)
                .stdout(Stdio::from(salida.try_clone().expect("duplicar salida")))
                .stderr(Stdio::from(salida))
                .spawn()
                .expect("binario real del cliente"),
        );
        let plazo = Instant::now() + Duration::from_secs(15);
        loop {
            let registro = std::fs::read_to_string(&ruta_registro).expect("registro del nodo");
            let texto = std::fs::read_to_string(&ruta_salida).expect("salida del cliente");
            let rechazo = registro.contains("génesis o red ajenos");
            if expulsado && rechazo && registro.contains("\"tipo\":\"par_desconectado\"") {
                assert!(registro.contains("\"accion\":\"expulsion\""));
                println!("{binario}: dev expulsado por identidad ajena\n{registro}");
                break;
            }
            assert!(
                !rechazo || expulsado,
                "cliente de la misma red expulsado: {registro}\n{texto}"
            );
            if let Some(estado) = cliente.0.try_wait().expect("estado del proceso")
                && !expulsado
            {
                assert_eq!(
                    estado.code(),
                    Some(rc_esperado),
                    "salida inesperada: {texto}"
                );
                assert!(
                    texto.contains(aceptado),
                    "no hay prueba de saludo/publicación: {texto}\n{registro}"
                );
                assert!(registro.contains("\"tipo\":\"par_conectado\""));
                assert!(
                    !registro.contains("\"accion\":\"expulsion\""),
                    "hubo expulsión: {registro}"
                );
                println!("{binario}: dev-reloj aceptado\n{texto}\n{registro}");
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
fn red1_un_nodo_dev_reloj_no_expulsa_al_cliente_de_su_red() {
    comprobar(false);
}

#[test]
fn red1_un_nodo_dev_reloj_expulsa_al_cliente_de_dev() {
    comprobar(true);
}
