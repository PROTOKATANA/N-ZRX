//! Binario `zx-censor` (`ORDEN-AD2-2`): un nodo **completo** que descarta todo voto ajeno.
//!
//! Arranca el mismo nodo que `zx-node` (`zx_node::nodo::Nodo`) y la misma red real, pero envuelve el
//! [`ManejadorRed`] con [`ManejadorCensor`] mediante el *seam* [`red::arrancar_con_manejador`]. El
//! envoltorio **delega todo** en el manejador real salvo los tres temas de votos
//! (`voto_difundida`, `voto_subred_difundida` y `agregado_difundido`), que devuelven
//! `Veredicto::Ignorar` sin encolar el mensaje: no los cuenta y no los reenvía (censura de red de
//! votos, A5-c-2b · X9). El nodo sigue respondiendo al saludo, sirviendo y pidiendo bloques,
//! produciendo y emitiendo sus **propios** votos (`ORDEN-AD2-2` C1 y C2). El binario real `zx-node`
//! no gana ninguna opción ni camino nuevo.
//!
//! El envoltorio vive aquí, no en `crates/zx-node/src/red/` (`ORDEN-AD2-2` §2 C1).

use std::sync::Arc;

use clap::Parser as _;
use zx_core::digest::BlockHash;
use zx_core::preimage::block::BlockHeader;
use zx_node::cli::{Cli, OpcionesRegistro, Papel};
use zx_node::nodo::{Config, Nodo};
use zx_node::red;
use zx_node::red::manejador::ManejadorRed;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::mensaje::{AnuncioPrueba, BloqueRed, Estado};

/// Envoltorio del manejador real que descarta los votos ajenos.
///
/// Se le pasa el [`ManejadorRed`] real recién construido por
/// [`red::arrancar_con_manejador`]; **todo** método delega en él salvo
/// [`ManejadorEntrante::voto_difundida`], que devuelve `Ignorar` sin encolar el sobre.
struct ManejadorCensor {
    /// El manejador honesto real; el resto de la red pasa por aquí sin cambios.
    real: Arc<ManejadorRed>,
}

impl ManejadorEntrante for ManejadorCensor {
    fn estado(&self) -> Estado {
        self.real.estado()
    }

    fn bloque_difundido(&self, id: IdDiferido, bloque: &BloqueRed) -> Veredicto {
        self.real.bloque_difundido(id, bloque)
    }

    fn tx_difundida(&self, peer: libp2p::PeerId, tx_serializada: &[u8]) -> Veredicto {
        self.real.tx_difundida(peer, tx_serializada)
    }

    /// `ORDEN-AD2-2` E2/C1/C2 + A5-c-2b · X9: descarta todo voto que llega por la red —el del tema
    /// global, el de subred y el agregado— sin encolarlo y sin reenviarlo (`Ignorar` =
    /// `MessageAcceptance::Ignore`). No penaliza al propagador porque un voto descartado no es un
    /// voto demostrablemente inválido.
    fn voto_difundida(&self, _peer: libp2p::PeerId, _bytes: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    /// A5-c-2b · X9: el censor tampoco entrega los votos de subred a su motor ni los reenvía.
    fn voto_subred_difundida(
        &self,
        _id: IdDiferido,
        _subred: u8,
        _bytes: &[u8],
        _peer: libp2p::PeerId,
    ) -> Veredicto {
        Veredicto::Ignorar
    }

    /// A5-c-2b · X9: ni los agregados: el censor los ignora sin encolarlos ni reenviarlos.
    fn agregado_difundido(
        &self,
        _id: IdDiferido,
        _bytes: &[u8],
        _peer: libp2p::PeerId,
    ) -> Veredicto {
        Veredicto::Ignorar
    }

    /// A6-02 · Q4: un anuncio de prueba ya comprobado llegó por difusión; delega en el real
    /// (no es un voto, así que no se censura).
    fn anuncio_prueba(&self, peer: libp2p::PeerId, anuncio: &AnuncioPrueba) -> Veredicto {
        self.real.anuncio_prueba(peer, anuncio)
    }

    /// A6-02 · Q4: sirve el cuerpo de una prueba por su huella; delega en el real (no es un voto).
    fn servir_prueba(&self, huella: &[u8; 32]) -> Option<Vec<u8>> {
        self.real.servir_prueba(huella)
    }

    fn cabeceras_desde(&self, locator: &[BlockHash], hasta: Option<BlockHash>) -> Vec<BlockHeader> {
        self.real.cabeceras_desde(locator, hasta)
    }

    fn bloques_por_hash(&self, hashes: &[BlockHash]) -> Vec<BloqueRed> {
        self.real.bloques_por_hash(hashes)
    }

    fn pagina_registro(&self, desde: u64) -> (Vec<BloqueRed>, u64) {
        self.real.pagina_registro(desde)
    }

    fn pagina_registro_direcciones(
        &self,
        desde: u64,
    ) -> (Vec<zx_p2p::registro::EntradaRegistro>, u64) {
        self.real.pagina_registro_direcciones(desde)
    }

    fn par_penalizado(&self, peer: libp2p::PeerId, motivo: &str, accion: &str) {
        self.real.par_penalizado(peer, motivo, accion)
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.papel != Papel::Ambos {
        eprintln!(
            "papel {:?}: zx-censor es un nodo completo; use --papel ambos",
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

    let perfil_red = match cli.red.perfil_red() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zx-censor: perfil de red inválido: {e}");
            std::process::exit(2);
        }
    };

    if cli.votos_peso {
        eprintln!("zx-censor: aviso: --votos-peso ya no tiene efecto; el nodo vota solo por peso");
    }

    // RD-4b · P5: la misma CLI que `zx-node`; el registro queda apagado salvo que reciba
    // `--red-registro` (y respeta `--red-registro-sin-publicar`). El censor es el atacante de la
    // campaña: necesita poder publicar su entrada firmada como un nodo honesto.
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

    if let Err(e) = zx_node::parada::instalar() {
        eprintln!("zx-censor: no se pudo instalar el manejo de señales: {e}");
        std::process::exit(1);
    }

    let mut nodo = match Nodo::arrancar(&cfg) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("zx-censor: error fatal: {e}");
            std::process::exit(1);
        }
    };

    // Igual que `zx-node`: el runtime `tokio` de la red no debe soltarse hasta el final.
    let dir_red = Some(cfg.dir_datos.join("red"));
    let _red_arrancada = if con_red {
        let envolver = |real: Arc<ManejadorRed>| Arc::new(ManejadorCensor { real });
        match red::arrancar_con_manejador(
            escuchar,
            marcar,
            nodo.vista_red(),
            nodo.registro(),
            dir_red,
            nodo.mempool(),
            opciones_registro,
            envolver,
        ) {
            Ok(r) => {
                nodo.fijar_arranque_red(r.peer_id, escuchar_str);
                nodo.conectar_red(r.manija, r.trabajo);
                Some(r.runtime)
            }
            Err(e) => {
                eprintln!("zx-censor: no se pudo arrancar la red: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    if let Err(e) = nodo.ejecutar() {
        eprintln!("zx-censor: error fatal: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::*;
    use zx_core::amount::Amount;
    use zx_core::digest::{Digest, MerkleRoot, TxId};
    use zx_core::firma::ClavePublica;
    use zx_core::red::Red;
    use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
    use zx_node::red::registro_direcciones::{ConfigRegistro, RegistroRed};
    use zx_node::red::vista::VistaRed;
    use zx_node::red::{TrabajoRed, nueva_cola_trabajo_red};
    use zx_p2p::mensaje::{Fase, PuntaPow};

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn registro() -> (tempfile::TempDir, Arc<zx_node::registro::Registro>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = Arc::new(
            zx_node::registro::Registro::abrir(&dir.path().join("registro.jsonl"))
                .expect("abrir registro"),
        );
        (dir, r)
    }

    fn mempool_test() -> Arc<std::sync::Mutex<zx_node::mempool::Mempool>> {
        Arc::new(std::sync::Mutex::new(zx_node::mempool::Mempool::nueva(
            zx_node::perfil::parametros_transicion_dev().expect("perfil dev"),
            zx_node::perfil::parametros_evidencia_dev(),
            zx_core::CBID_RED_DEV,
            zx_consensus::transicion::Estado::inicial(),
            zx_node::mempool::Politica::dev(),
        )))
    }

    fn reg_dir_apagado() -> Arc<RegistroRed> {
        Arc::new(RegistroRed::nuevo(Red::Dev, ConfigRegistro::APAGADO))
    }

    fn estado_vacio() -> Estado {
        Estado {
            hash_genesis: h(0),
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: h(0),
                altura: 0,
                trabajo_acumulado: [0; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [0; 32],
            longitud_registro: 0,
        }
    }

    fn bloque_pow(n: u8) -> BloqueRed {
        BloqueRed::Pow {
            cabecera: BlockHeader {
                consensus_branch_id: 0xa8b4_66a7,
                prev_hash: h(n),
                merkle_root: MerkleRoot::from_digest(Digest::from_bytes([2; 32])),
                timestamp: 1_000,
                bits: 0x1c07_fff8,
                nonce: u64::from(n),
                height: u32::from(n),
            },
            txs: vec![Tx {
                version: 1,
                inputs: vec![TxIn {
                    outpoint: OutPoint {
                        prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                        prev_index: 0,
                    },
                    sequence: 0,
                }],
                outputs: vec![TxOut {
                    value: Amount::nuevo(1).unwrap(),
                    lock: Lock::PubKey {
                        pubkey: ClavePublica::desde_bytes([n; 32]),
                    },
                }],
                lock_time: 0,
                expiry_height: 0,
                extension: ExtensionTx::Ninguna,
            }],
            testigos: vec![vec![vec![0xAA; 64]]],
        }
    }

    /// `ORDEN-AD2` §3 prueba 1 (vigente en `ORDEN-AD2-2`): con el envoltorio, `voto_difundida`
    /// devuelve `Ignorar` y **no** encola `TrabajoRed::VotoDifundido`; un bloque difundido se trata
    /// igual que con el manejador real (devuelve `Diferir` y encola `TrabajoRed::BloqueDifundido`).
    #[test]
    fn voto_difundido_se_ignora_sin_encolar() {
        let (_dir, real, mut rx) = {
            let (_d, reg) = registro();
            let (tx, rx) = nueva_cola_trabajo_red();
            let real = Arc::new(ManejadorRed::nuevo(
                tx,
                Arc::new(VistaRed::nueva(estado_vacio())),
                reg,
                mempool_test(),
                reg_dir_apagado(),
            ));
            (_d, real, rx)
        };
        let censor = ManejadorCensor {
            real: Arc::clone(&real),
        };

        // A5-c-2b · X3b: el tema global está muerto. El manejador real ya NO acepta ni encola el
        // sobre; el censor tampoco, y la cola queda vacía por ambos lados.
        let mut plausible = b"ZXV3".to_vec();
        plausible.extend(std::iter::repeat_n(0u8, 252 - 4));
        assert!(zx_node::votos::voto_es_plausible(&plausible));
        assert_eq!(
            real.voto_difundida(libp2p::PeerId::random(), &plausible),
            Veredicto::Ignorar
        );
        assert_eq!(
            censor.voto_difundida(libp2p::PeerId::random(), &plausible),
            Veredicto::Ignorar
        );
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "ni el real ni el censor deben encolar el voto del tema global"
        );

        // Control de que la cola funciona: un voto de subred sí lo encola el manejador real con
        // `Diferir`, y el censor lo ignora sin encolarlo ni penalizar.
        let id = IdDiferido::default();
        assert_eq!(
            real.voto_subred_difundida(id, 1, &plausible, libp2p::PeerId::random()),
            Veredicto::Diferir
        );
        match rx.try_recv() {
            Ok(TrabajoRed::VotoSubredDifundido {
                id: id_r, subred, ..
            }) => {
                assert_eq!(id_r, id);
                assert_eq!(subred, 1);
            }
            otro => panic!("el manejador real debía encolar un voto de subred, llegó {otro:?}"),
        }
        assert_eq!(
            censor.voto_subred_difundida(id, 1, &plausible, libp2p::PeerId::random()),
            Veredicto::Ignorar
        );
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "el censor no debe encolar votos de subred"
        );

        // Un bloque difundido se delega tal cual: mismo veredicto y mismo trabajo encolado.
        assert_eq!(
            censor.bloque_difundido(IdDiferido::default(), &bloque_pow(1)),
            Veredicto::Diferir
        );
        match rx.try_recv() {
            Ok(TrabajoRed::BloqueDifundido { bloque, .. }) => assert_eq!(bloque, bloque_pow(1)),
            otro => panic!("el censor debía delegar el bloque, llegó {otro:?}"),
        }
        assert_eq!(censor.estado(), real.estado());
    }

    /// A5-c-2b · X9 · el censor ignora los votos de subred y los agregados: `Ignorar` y nada en la
    /// cola, mientras el manejador honesto los difiere y los encola.
    #[test]
    fn censor_ignora_votos_de_subred_y_agregados() {
        let (_dir, reg) = registro();
        let (tx, mut rx) = nueva_cola_trabajo_red();
        let real = Arc::new(ManejadorRed::nuevo(
            tx,
            Arc::new(VistaRed::nueva(estado_vacio())),
            reg,
            mempool_test(),
            reg_dir_apagado(),
        ));
        let censor = ManejadorCensor {
            real: Arc::clone(&real),
        };
        let peer = libp2p::PeerId::random();
        let voto = [0u8; 248];
        let agregado = [0u8; 334];

        assert_eq!(
            real.voto_subred_difundida(IdDiferido::default(), 3, &voto, peer),
            Veredicto::Diferir
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(TrabajoRed::VotoSubredDifundido { .. })
        ));
        assert_eq!(
            real.agregado_difundido(IdDiferido::default(), &agregado, peer),
            Veredicto::Diferir
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(TrabajoRed::AgregadoDifundido { .. })
        ));

        assert_eq!(
            censor.voto_subred_difundida(IdDiferido::default(), 3, &voto, peer),
            Veredicto::Ignorar
        );
        assert_eq!(
            censor.agregado_difundido(IdDiferido::default(), &agregado, peer),
            Veredicto::Ignorar
        );
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "el censor no debe encolar votos de subred ni agregados"
        );
    }

    /// `ORDEN-AD2-2` E2: el envoltorio delega **cada** método del rasgo en el manejador real y solo
    /// sobrescribe `voto_difundida`.
    ///
    /// Recorre a mano los métodos de hoy comparando el envoltorio con el real. Además, para que la
    /// prueba no se quede corta cuando el rasgo gane un método con implementación por defecto, lee
    /// el **fuente del rasgo** con `include_str!`, saca la lista de métodos declarados y exige que
    /// el fuente de este binario contenga una delegación `self.real.<método>(` para cada uno salvo
    /// `voto_difundida` (y que **no** la contenga para el voto). Si el rasgo gana un método, la
    /// lista parseada crece, falta su delegación y la prueba **falla**; si el archivo del rasgo se
    /// mueve o se renombra, `include_str!` deja de **compilar**. Así el envoltorio no puede quedarse
    /// atrás en silencio.
    #[test]
    fn censor_delega_todo_salvo_el_voto() {
        let (_dir, reg) = registro();
        let (tx, mut rx) = nueva_cola_trabajo_red();
        let vista = Arc::new(VistaRed::nueva(estado_vacio()));
        // Registro de direcciones encendido y con una entrada propia: así
        // `pagina_registro_direcciones` devuelve una página **no** vacía en el real y distinguimos
        // delegar de heredar la implementación por defecto (que sería vacía).
        let registro_direcciones = Arc::new(RegistroRed::nuevo(
            Red::Dev,
            ConfigRegistro::encendido(true),
        ));
        let productor = zx_node::claves::ClaveDev::derivar(0x5a5a, 0);
        let direccion: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("multiaddr");
        let ahora = zx_node::red::registro_direcciones::unix_ahora();
        assert!(
            registro_direcciones
                .publicar_propia(&productor, std::slice::from_ref(&direccion), ahora)
                .expect("publicar entrada propia"),
            "el registro de direcciones debía aceptar la entrada propia"
        );
        // Vista con el génesis registrado: `pagina_registro` devuelve una página no vacía.
        vista.registrar_genesis_pow(bloque_pow(0));

        let real = Arc::new(ManejadorRed::nuevo(
            tx,
            Arc::clone(&vista),
            Arc::clone(&reg),
            mempool_test(),
            Arc::clone(&registro_direcciones),
        ));
        let censor = ManejadorCensor {
            real: Arc::clone(&real),
        };

        // 1) `estado` (obligatorio, sin default).
        assert_eq!(censor.estado(), real.estado());

        // 2) `bloque_difundido`: mismo veredicto y mismo trabajo encolado por las dos vías.
        assert_eq!(
            censor.bloque_difundido(IdDiferido::default(), &bloque_pow(1)),
            real.bloque_difundido(IdDiferido::default(), &bloque_pow(1))
        );
        let mut encolados = 0;
        while let Ok(t) = rx.try_recv() {
            match t {
                TrabajoRed::BloqueDifundido { bloque, .. } => {
                    assert_eq!(bloque, bloque_pow(1));
                    encolados += 1;
                }
                otro => panic!("solo se esperaban bloques difundidos, llegó {otro:?}"),
            }
        }
        assert_eq!(
            encolados, 2,
            "cada llamada a `bloque_difundido` debe encolar un bloque"
        );

        // 3) `tx_difundida`: con bytes que no decodifican, ambos rechazan; el veredicto coincide.
        let peer = libp2p::PeerId::random();
        assert_eq!(censor.tx_difundida(peer, &[]), real.tx_difundida(peer, &[]));

        // 4) `voto_difundida` (tema global): X3b lo deja muerto; el real y el censor ignoran y no
        //    encolan nada.
        let mut plausible = b"ZXV3".to_vec();
        plausible.extend(std::iter::repeat_n(0u8, 252 - 4));
        assert!(zx_node::votos::voto_es_plausible(&plausible));
        assert_eq!(real.voto_difundida(peer, &plausible), Veredicto::Ignorar);
        assert_eq!(censor.voto_difundida(peer, &plausible), Veredicto::Ignorar);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        // 5) `voto_subred_difundida` y 6) `agregado_difundido`: X9 hace que el censor **no** delegue
        //    (los ignora y no los encola); el real sí los difiere y los encola.
        assert_eq!(
            real.voto_subred_difundida(IdDiferido::default(), 1, &plausible, peer),
            Veredicto::Diferir
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(TrabajoRed::VotoSubredDifundido { .. })
        ));
        assert_eq!(
            real.agregado_difundido(IdDiferido::default(), &plausible, peer),
            Veredicto::Diferir
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(TrabajoRed::AgregadoDifundido { .. })
        ));
        assert_eq!(
            censor.voto_subred_difundida(IdDiferido::default(), 1, &plausible, peer),
            Veredicto::Ignorar
        );
        assert_eq!(
            censor.agregado_difundido(IdDiferido::default(), &plausible, peer),
            Veredicto::Ignorar
        );
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        // 7) `cabeceras_desde` y 8) `bloques_por_hash`: mismo resultado.
        assert_eq!(
            censor.cabeceras_desde(&[h(5)], None),
            real.cabeceras_desde(&[h(5)], None)
        );
        assert_eq!(
            censor.bloques_por_hash(&[h(5)]),
            real.bloques_por_hash(&[h(5)])
        );

        // 9) `pagina_registro`: la vista tiene el génesis; el real devuelve página no vacía. Si el
        //    censor heredara el default, devolvería vacía y esto fallaría.
        let (pag_c, lon_c) = censor.pagina_registro(0);
        let (pag_r, lon_r) = real.pagina_registro(0);
        assert_eq!(lon_r, 1, "la vista debía tener el génesis registrado");
        assert!(!pag_r.is_empty());
        assert_eq!((pag_c, lon_c), (pag_r, lon_r));

        // 10) `pagina_registro_direcciones`: el real sirve la entrada publicada; una default vacía no
        //     pasaría.
        let (dir_c, lond_c) = censor.pagina_registro_direcciones(0);
        let (dir_r, lond_r) = real.pagina_registro_direcciones(0);
        assert_eq!((dir_c, lond_c), (dir_r, lond_r));
        assert_eq!(
            lond_r, 1,
            "el registro de direcciones debía tener la entrada propia"
        );

        // 11) `par_penalizado`: el real escribe en el registro; el censor debe escribir también (una
        //     default no-op no escribiría nada).
        let fichero = _dir.path().join("registro.jsonl");
        let antes = std::fs::read_to_string(&fichero).unwrap_or_default();
        censor.par_penalizado(peer, "motivo-test", "accion-test");
        let despues = std::fs::read_to_string(&fichero).expect("leer registro");
        assert!(
            despues.contains("\"tipo\":\"par_penalizado\""),
            "el censor no delegó par_penalizado: {despues}"
        );
        assert!(despues.len() > antes.len());

        // Guardia de futuro: lista de métodos del rasgo leída del fuente, y delegación uno a uno.
        let fuente_rasgo = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../zx-p2p/src/entrante.rs"
        ));
        let metodos = metodos_de_manejador_entrante(fuente_rasgo);
        let esperados: Vec<String> = [
            "estado",
            "bloque_difundido",
            "tx_difundida",
            "voto_difundida",
            "voto_subred_difundida",
            "agregado_difundido",
            "anuncio_prueba",
            "servir_prueba",
            "cabeceras_desde",
            "bloques_por_hash",
            "pagina_registro",
            "pagina_registro_direcciones",
            "par_penalizado",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        assert_eq!(
            metodos, esperados,
            "el rasgo `ManejadorEntrante` cambió: actualiza el envoltorio y esta prueba"
        );
        let fuente_bin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/zx-censor.rs"));
        // A5-c-2b · X9: los tres temas de votos no se delegan (el censor los ignora).
        let no_delegados = [
            "voto_difundida",
            "voto_subred_difundida",
            "agregado_difundido",
        ];
        for metodo in &no_delegados {
            let prohibido = format!("self.real.{metodo}(");
            assert!(
                !fuente_bin.contains(&prohibido),
                "el envoltorio NO debe delegar `{metodo}`"
            );
        }
        for metodo in &metodos {
            if no_delegados.contains(&metodo.as_str()) {
                continue;
            }
            assert!(
                fuente_bin.contains(&format!("self.real.{metodo}(")),
                "el envoltorio no delega `{metodo}` en el manejador real"
            );
        }
    }

    /// Saca los nombres de los métodos declarados dentro de `pub trait ManejadorEntrante` en el
    /// fuente del rasgo. Solo mira las líneas `fn <nombre>(` del cuerpo del rasgo.
    fn metodos_de_manejador_entrante(texto: &str) -> Vec<String> {
        let mut nombres = Vec::new();
        let mut dentro = false;
        for linea in texto.lines() {
            let t = linea.trim_start();
            if !dentro {
                if t.starts_with("pub trait ManejadorEntrante") {
                    dentro = true;
                }
                continue;
            }
            // El cuerpo del rasgo cierra con `}` a columna cero; los cuerpos por defecto de los
            // métodos cierran con `    }` (con sangría), así que no deben cortar el recorrido.
            if linea == "}" {
                break;
            }
            let Some(resto) = t.strip_prefix("fn ") else {
                continue;
            };
            let Some(paren) = resto.find('(') else {
                continue;
            };
            let nombre = &resto[..paren];
            if !nombre.is_empty()
                && nombre
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                nombres.push(nombre.to_string());
            }
        }
        nombres
    }
}
