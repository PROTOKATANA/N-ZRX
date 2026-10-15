//! Binario `zx-node` (`ORDEN-W06d1`, red en `ORDEN-W06d2`).

use clap::Parser as _;
use zx_node::cli::{Cli, OpcionesRegistro, Papel};
use zx_node::nodo::{Config, Nodo};

fn main() {
    let cli = Cli::parse();

    if cli.papel != Papel::Ambos {
        eprintln!(
            "papel {:?}: un nodo que solo mina o solo produce necesita pares que le manden lo que \
             le falta; use --papel ambos, o conecte red con --red-escuchar/--red-marcar",
            cli.papel
        );
        std::process::exit(2);
    }
    if cli.claves.is_empty() {
        eprintln!("--claves no puede estar vacío: el nodo necesita al menos una clave propia");
        std::process::exit(2);
    }

    let escuchar_str = cli.red_escuchar.clone();
    let escuchar = match cli.red_escuchar.as_deref().map(str::parse) {
        None => None,
        Some(Ok(a)) => Some(a),
        Some(Err(e)) => {
            eprintln!("--red-escuchar: dirección inválida: {e}");
            std::process::exit(2);
        }
    };
    let mut marcar = Vec::new();
    for m in &cli.red_marcar {
        match m.parse() {
            Ok(a) => marcar.push(a),
            Err(e) => {
                eprintln!("--red-marcar {m:?}: dirección inválida: {e}");
                std::process::exit(2);
            }
        }
    }
    let con_red = escuchar.is_some() || !marcar.is_empty();

    // `RL-2d`: el perfil de red con reloj valida el invariante `A ≥ F` al construirse; un perfil
    // que lo incumpla no arranca (decisión 2 de `ORDEN-RL2d`).
    let perfil_red = match cli.red.perfil_red() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zx-node: perfil de red inválido: {e}");
            std::process::exit(2);
        }
    };

    if cli.votos_peso {
        eprintln!("zx-node: aviso: --votos-peso ya no tiene efecto; el nodo vota solo por peso");
    }

    // RD-4b · P5: las opciones del registro se derivan de la CLI ya parseada; la red las recibe
    // como parámetro y no vuelve a leer los argumentos del proceso.
    let opciones_registro = OpcionesRegistro::desde(&cli);

    let cfg = Config {
        dir_datos: cli.datos,
        ruta_registro: cli.registro,
        red: cli.red.into(),
        semilla: cli.semilla,
        indices_claves: cli.claves,
        n_dev: cli.n_dev,
        sr_dev: cli.sr_dev,
        perfil_red,
        parada_tras_slots: cli.parada_tras_slots,
        dejar_de_producir_en_slot: cli.dejar_de_producir_en_slot,
        punto_control: cli.punto_control,
        sin_voto: cli.sin_voto,
        sin_revelacion: cli.sin_revelacion,
    };

    // `ORDEN-W07d` decisión 2: parada ordenada con `SIGTERM`/`SIGINT`. Se instala antes de abrir el
    // nodo para que una señal durante el arranque (la repetición del almacén puede ser larga) quede
    // marcada y `ejecutar` escriba `parada` en cuanto empiece. Si no se puede instalar, el nodo no
    // arranca: sin manejo, una señal mataría el proceso a mitad de escritura.
    if let Err(e) = zx_node::parada::instalar() {
        eprintln!("zx-node: no se pudo instalar el manejo de señales: {e}");
        std::process::exit(1);
    }

    let mut nodo = match Nodo::arrancar(&cfg) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("zx-node: error fatal: {e}");
            std::process::exit(1);
        }
    };
    // `_red_arrancada` se mantiene viva hasta el final de `main`: soltar el runtime `tokio` que
    // contiene cancelaría el bucle de red y la sincronización (decisión 1/4 de `ORDEN-W06d2`).
    //
    // RED-3 punto 3: el directorio de datos de la red sale de `--datos` (`<datos>/red`), de modo que
    // un `zx-node` normal conserva anclas y tabla de direcciones al reiniciar sin depender de
    // `ZX_RED_DATOS`. `arrancar` leía esa variable de entorno; aquí se usa la variante explícita.
    let dir_red = Some(cfg.dir_datos.join("red"));
    let _red_arrancada = if con_red {
        match zx_node::red::arrancar_con_datos(
            escuchar,
            marcar,
            nodo.vista_red(),
            nodo.registro(),
            dir_red,
            nodo.mempool(),
            opciones_registro,
        ) {
            Ok(r) => {
                // `ORDEN-W07a`: identidad de red para el `arranque`.
                nodo.fijar_arranque_red(r.peer_id, escuchar_str);
                nodo.conectar_red(r.manija, r.trabajo);
                Some(r.runtime)
            }
            Err(e) => {
                eprintln!("zx-node: no se pudo arrancar la red: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    if let Err(e) = nodo.ejecutar() {
        eprintln!("zx-node: error fatal: {e}");
        std::process::exit(1);
    }
}
