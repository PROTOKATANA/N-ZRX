//! [`ManejadorEntrante`] real: el puente entre el bucle asíncrono de `zx-p2p` y el hilo de consenso
//! síncrono (`ORDEN-W06d2`, decisión 1).
//!
//! Cada método es deliberadamente trivial: una lectura de [`VistaRed`] (rápida, sin bloquear) o un
//! `send` a un canal **no bloqueante** hacia el hilo de consenso. Ninguno ejecuta la tubería de
//! admisión — eso es exactamente lo que la orden prohíbe hacer aquí (`~66 ms` de PoT pararían la
//! red). El veredicto real llega después, informado por el hilo de consenso con
//! [`zx_p2p::servicio::ManejoRed::informar_validacion_bloqueante`].

use std::sync::Arc;
use std::time::Instant;

use zx_core::digest::BlockHash;
use zx_core::preimage::block::BlockHeader;
use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
use zx_p2p::mensaje::{BloqueRed, Estado};
use zx_p2p::registro::EntradaRegistro;

use super::registro_direcciones::RegistroRed;
use super::vista::VistaRed;
use super::{EmisorTrabajoRed, ResultadoEnvioTrabajo, TrabajoRed};
use crate::registro::Registro;

/// El manejador. Barato de clonar (todo dentro es `Arc`/canal clonable), pero se comparte como
/// `Arc<ManejadorRed>` porque [`zx_p2p::servicio::arrancar_con`] lo exige.
pub struct ManejadorRed {
    trabajo: EmisorTrabajoRed,
    vista: Arc<VistaRed>,
    /// Registro estructurado compartido (`ORDEN-W07a`): solo se usa para el evento no crítico
    /// `limite_alcanzado` (cola de trabajo llena). No se escribe nada por bloque aquí.
    registro: Arc<Registro>,
    /// Mempool compartida (`ORDEN-TX3`): aquí se valida la transacción de gossip **antes** de
    /// reenviarla (C-NET-12). El candado se toma de forma breve; el hilo de consenso lo suelta
    /// enseguida.
    mempool: Arc<std::sync::Mutex<crate::mempool::Mempool>>,
    /// `ORDEN-RD3c` (N2): el registro firmado de direcciones que se sirve por
    /// `Peticion::RegistroDirecciones`.
    registro_direcciones: Arc<RegistroRed>,
}

impl ManejadorRed {
    /// Construye el manejador con el canal hacia el hilo de consenso, la vista compartida, el
    /// registro estructurado, la mempool y el registro de direcciones.
    #[must_use]
    pub const fn nuevo(
        trabajo: EmisorTrabajoRed,
        vista: Arc<VistaRed>,
        registro: Arc<Registro>,
        mempool: Arc<std::sync::Mutex<crate::mempool::Mempool>>,
        registro_direcciones: Arc<RegistroRed>,
    ) -> Self {
        Self {
            trabajo,
            vista,
            registro,
            mempool,
            registro_direcciones,
        }
    }
}

impl ManejadorEntrante for ManejadorRed {
    fn estado(&self) -> Estado {
        self.vista.estado()
    }

    fn bloque_difundido(&self, id: IdDiferido, bloque: &BloqueRed) -> Veredicto {
        // `ORDEN-W06d6` (RI-3a #3): cola acotada en elementos y en bytes. Si está llena, se
        // descarta **sin bloquear la red** (nunca `send().await`) y se registra — un bloque
        // honesto descartado así se recupera por la petición de padres o por la sincronización por
        // registro (decisión 1), nunca queda perdido en silencio sin que nadie lo sepa.
        let llegada = Instant::now();
        match self.trabajo.intentar_enviar(TrabajoRed::BloqueDifundido {
            id,
            bloque: bloque.clone(),
            llegada,
        }) {
            ResultadoEnvioTrabajo::Encolado => Veredicto::Diferir,
            ResultadoEnvioTrabajo::Lleno(_) => {
                tracing::warn!(
                    "cola de trabajo hacia el hilo de consenso llena: bloque difundido descartado \
                     sin juzgar (límite alcanzado, RI-3a #3)"
                );
                // `ORDEN-W07a`: traza estructurada del único límite que `zx-node` ve descartar algo
                // (la cola propia; los límites C-NET internos de `zx-p2p` no son observables aquí).
                let evento = self
                    .registro
                    .evento("limite_alcanzado")
                    .str("limite", "cola_trabajo_consenso")
                    .str(
                        "detalle",
                        "bloque difundido descartado: cola hacia el hilo de consenso llena",
                    );
                let _ = self.registro.escribir(evento, false);
                Veredicto::Ignorar
            }
            ResultadoEnvioTrabajo::Cerrado(_) => {
                // El hilo de consenso ya no existe: no hay a quién diferirle nada. No es un
                // defecto del par que lo propagó, así que `Ignorar` (nunca `Rechazar`) es la única
                // lectura honesta.
                tracing::error!("hilo de consenso caído: bloque difundido descartado sin juzgar");
                Veredicto::Ignorar
            }
        }
    }

    /// `ORDEN-W06d10` decisión 1: `zx-p2p` penalizó al propagador de un bloque difundido
    /// **demostrablemente inválido** (lo desconectó y puntuó). Escribe `par_penalizado` (`par`,
    /// `motivo`, `accion`) según `P-ZRX/P-MEDICION/ESQUEMA-REGISTRO-v1.md` §1. No es crítico: un
    /// fallo de escritura no debe tumbar nada (el par ya está desconectado).
    fn par_penalizado(&self, peer: libp2p::PeerId, motivo: &str, accion: &str) {
        let evento = self
            .registro
            .evento("par_penalizado")
            .str("par", &peer.to_string())
            .str("motivo", motivo)
            .str("accion", accion);
        let _ = self.registro.escribir(evento, false);
    }

    fn tx_difundida(&self, peer: libp2p::PeerId, tx_serializada: &[u8]) -> Veredicto {
        // TX-R-02/04: el códec de `zx-p2p` ya exigió que el cuerpo se autodelimite; aquí se vuelve
        // a decodificar para validar (TX-R-06: forma, peso y contexto, en ese orden).
        let Ok(((tx, testigos), [])) = zx_core::wire::tx_desde_bytes(tx_serializada) else {
            return Veredicto::Rechazar;
        };
        // RN-1 · S5 · las operaciones de sector o de almacenamiento dejan rastro de su admisión o
        // rechazo con su identificador, clase y origen (`red`). Los pagos corrientes no.
        let clase = crate::mempool::clase_de_operacion(&tx);
        let mut m = match self.mempool.lock() {
            Ok(g) => g,
            // Un candado envenenado no debe dejar la red muda: se sigue con el dato interno.
            Err(poison) => poison.into_inner(),
        };
        let txid_val = zx_core::txid(&tx, m.cbid());
        let punto = m.punto_actual();
        let resultado = m.admitir(Some(peer), tx, testigos, Instant::now(), punto);
        if let Some(clase) = clase {
            match &resultado {
                Ok(crate::mempool::Admision::Admitida) => {
                    let evento = self
                        .registro
                        .evento("tx_admitida")
                        .str("txid", &txid_val.to_string())
                        .str("clase", clase)
                        .str("origen", "red");
                    let _ = self.registro.escribir(evento, false);
                }
                Err(r) => {
                    let evento = self
                        .registro
                        .evento("tx_rechazada")
                        .str("txid", &txid_val.to_string())
                        .str("clase", clase)
                        .str("origen", "red")
                        .str("motivo", &crate::mempool::motivo_de_rechazo(r));
                    let _ = self.registro.escribir(evento, false);
                }
                Ok(_) => {}
            }
        }
        match resultado {
            Ok(crate::mempool::Admision::Admitida) => Veredicto::Aceptar,
            // RSS-1 · una huérfana (o una duplicada) se conserva localmente, pero **no se
            // retransmite**: reenviar trabajo que no hemos podido validar multiplica la carga de
            // gossip de toda la malla por el número de pares sin aportar nada al consenso. `Ignorar`
            // no penaliza al propagador (TX-R-10, DR-06/RFT-27).
            Ok(crate::mempool::Admision::Huerfana | crate::mempool::Admision::Duplicada) => {
                Veredicto::Ignorar
            }
            // Solo lo demostrable penaliza al par (TX-R-10, DR-06/RFT-27).
            Err(crate::mempool::Rechazo::Demostrable(_)) => Veredicto::Rechazar,
            Err(_) => Veredicto::Ignorar,
        }
    }

    /// FV-4b-N1 · un sobre de voto/certificado llegó por el tema **global** de votos.
    ///
    /// A5-c-2b · X3b: ese tema queda **muerto**. Un voto que llega por él se ignora: ni se entrega
    /// al motor, ni se reenvía, ni se penaliza. Motivo: si se reenviara, cualquiera podría volver a
    /// publicar por él los votos sueltos de una ventana y cada nodo honesto los verificaría y
    /// reenviaría — justo la carga que la agregación quita.
    fn voto_difundida(&self, _peer: libp2p::PeerId, _bytes: &[u8]) -> Veredicto {
        Veredicto::Ignorar
    }

    /// A5-c-2b · X4 · un voto de red de la subred `subred` llegó por su tema.
    ///
    /// Se difiere el veredicto (el motor de votos vive en el hilo de consenso): se encola el
    /// `IdDiferido` con los bytes opacos y se devuelve `Diferir`. Con la cola llena el mensaje se
    /// ignora sin penalizar y no se retiene.
    fn voto_subred_difundida(
        &self,
        id: IdDiferido,
        subred: u8,
        bytes: &[u8],
        _peer: libp2p::PeerId,
    ) -> Veredicto {
        match self
            .trabajo
            .intentar_enviar(TrabajoRed::VotoSubredDifundido {
                id,
                subred,
                bytes: bytes.to_vec(),
            }) {
            ResultadoEnvioTrabajo::Encolado => Veredicto::Diferir,
            ResultadoEnvioTrabajo::Lleno(_) => {
                let evento = self
                    .registro
                    .evento("limite_alcanzado")
                    .str("limite", "cola_trabajo_consenso")
                    .str(
                        "detalle",
                        "voto de subred descartado: cola hacia el hilo de consenso llena",
                    );
                let _ = self.registro.escribir(evento, false);
                Veredicto::Ignorar
            }
            ResultadoEnvioTrabajo::Cerrado(_) => Veredicto::Ignorar,
        }
    }

    /// A5-c-2b · X5 · un agregado de subred llegó por el tema común de agregados.
    ///
    /// Igual que el voto de subred: se difiere el veredicto y se encola. El hilo de consenso junta
    /// todos los agregados de una vuelta en un lote.
    fn agregado_difundido(&self, id: IdDiferido, bytes: &[u8], _peer: libp2p::PeerId) -> Veredicto {
        match self.trabajo.intentar_enviar(TrabajoRed::AgregadoDifundido {
            id,
            bytes: bytes.to_vec(),
        }) {
            ResultadoEnvioTrabajo::Encolado => Veredicto::Diferir,
            ResultadoEnvioTrabajo::Lleno(_) => {
                let evento = self
                    .registro
                    .evento("limite_alcanzado")
                    .str("limite", "cola_trabajo_consenso")
                    .str(
                        "detalle",
                        "agregado descartado: cola hacia el hilo de consenso llena",
                    );
                let _ = self.registro.escribir(evento, false);
                Veredicto::Ignorar
            }
            ResultadoEnvioTrabajo::Cerrado(_) => Veredicto::Ignorar,
        }
    }

    fn cabeceras_desde(&self, locator: &[BlockHash], hasta: Option<BlockHash>) -> Vec<BlockHeader> {
        self.vista.cabeceras_desde(locator, hasta)
    }

    fn bloques_por_hash(&self, hashes: &[BlockHash]) -> Vec<BloqueRed> {
        self.vista.bloques_por_hash(hashes)
    }

    fn pagina_registro(&self, desde: u64) -> (Vec<BloqueRed>, u64) {
        self.vista.pagina_registro(
            desde,
            zx_p2p::limites::MAX_BLOQUES_POR_RESPUESTA,
            zx_p2p::limites::MAX_RESPUESTA_BYTES,
        )
    }

    fn pagina_registro_direcciones(&self, desde: u64) -> (Vec<EntradaRegistro>, u64) {
        // `ORDEN-RD3c` (N2): la página la acota el propio registro (entradas y bytes); apagado
        // devuelve siempre vacía (N1).
        self.registro_direcciones.pagina(
            desde,
            zx_p2p::limites::MAX_ENTRADAS_REGISTRO_POR_PAGINA,
            zx_p2p::limites::MAX_RESPUESTA_BYTES,
        )
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
    use super::super::TrabajoRed;
    use super::super::registro_direcciones::{ConfigRegistro, RegistroRed};
    use super::super::vista::VistaRed;
    use super::ManejadorRed;
    use std::sync::Arc;
    use zx_core::amount::Amount;
    use zx_core::digest::{BlockHash, Digest, MerkleRoot, TxId};
    use zx_core::firma::ClavePublica;
    use zx_core::preimage::block::BlockHeader;
    use zx_core::red::Red;
    use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
    use zx_p2p::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
    use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    /// Registro estructurado de test (fichero temporal que vive todo el test).
    fn registro() -> (tempfile::TempDir, Arc<crate::registro::Registro>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = Arc::new(
            crate::registro::Registro::abrir(&dir.path().join("registro.jsonl"))
                .expect("abrir registro"),
        );
        (dir, r)
    }

    /// Mempool de test sobre el estado inicial (no se admiten txs en estos tests del manejador).
    fn mempool_test() -> Arc<std::sync::Mutex<crate::mempool::Mempool>> {
        Arc::new(std::sync::Mutex::new(crate::mempool::Mempool::nueva(
            crate::perfil::parametros_transicion_dev().expect("perfil dev"),
            crate::perfil::parametros_evidencia_dev(),
            zx_core::CBID_RED_DEV,
            zx_consensus::transicion::Estado::inicial(),
            crate::mempool::Politica::dev(),
        )))
    }

    /// Registro de direcciones de test (apagado: no se ejerce en estos tests del manejador).
    fn reg_dir() -> Arc<RegistroRed> {
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

    #[test]
    fn bloque_difundido_siempre_difiere_y_encola() {
        let (_dir, reg) = registro();
        let (tx, mut rx) = super::super::nueva_cola_trabajo_red();
        let m = ManejadorRed::nuevo(
            tx,
            Arc::new(VistaRed::nueva(estado_vacio())),
            reg,
            mempool_test(),
            reg_dir(),
        );

        let v = m.bloque_difundido(IdDiferido::default(), &bloque_pow(1));
        assert_eq!(v, Veredicto::Diferir);

        let recibido = rx.try_recv().expect("debe haber encolado trabajo");
        match recibido {
            TrabajoRed::BloqueDifundido { id, bloque, .. } => {
                assert_eq!(id, IdDiferido::default());
                assert_eq!(bloque, bloque_pow(1));
            }
            otro => panic!("no es un bloque difundido: {otro:?}"),
        }
    }

    #[test]
    fn sin_hilo_de_consenso_se_ignora_sin_penalizar() {
        let (_dir, reg) = registro();
        let (tx, rx) = super::super::nueva_cola_trabajo_red();
        drop(rx); // el hilo de consenso "murió": el canal está cerrado.
        let m = ManejadorRed::nuevo(
            tx,
            Arc::new(VistaRed::nueva(estado_vacio())),
            reg,
            mempool_test(),
            reg_dir(),
        );
        assert_eq!(
            m.bloque_difundido(IdDiferido::default(), &bloque_pow(1)),
            Veredicto::Ignorar
        );
    }

    #[test]
    fn estado_y_lecturas_delegan_en_la_vista() {
        let (_dir, reg) = registro();
        let (tx, _rx) = super::super::nueva_cola_trabajo_red();
        let vista = Arc::new(VistaRed::nueva(estado_vacio()));
        let m = ManejadorRed::nuevo(tx, Arc::clone(&vista), reg, mempool_test(), reg_dir());
        assert_eq!(m.estado(), estado_vacio());
        assert!(m.cabeceras_desde(&[h(5)], None).is_empty());
        assert!(m.bloques_por_hash(&[h(5)]).is_empty());
    }

    /// `ORDEN-W07a` §1: con la cola de trabajo llena, un bloque difundido se descarta **sin
    /// bloquear la red** y se traza `limite_alcanzado` (el único límite que `zx-node` ve descartar
    /// algo; los internos de `zx-p2p` no son observables desde aquí).
    #[test]
    fn cola_llena_traza_el_limite_alcanzado() {
        use super::super::ResultadoEnvioTrabajo;

        let (dir, reg) = registro();
        let (tx, _rx) = super::super::nueva_cola_trabajo_red();
        for i in 0..super::super::MAX_TRABAJO_RED {
            let resultado = tx.intentar_enviar(TrabajoRed::BloqueDifundido {
                id: IdDiferido::default(),
                bloque: bloque_pow((i % 200) as u8),
                llegada: std::time::Instant::now(),
            });
            assert!(
                matches!(resultado, ResultadoEnvioTrabajo::Encolado),
                "la cola debe admitir hasta su tope declarado"
            );
        }
        let m = ManejadorRed::nuevo(
            tx,
            Arc::new(VistaRed::nueva(estado_vacio())),
            Arc::clone(&reg),
            mempool_test(),
            reg_dir(),
        );
        assert_eq!(
            m.bloque_difundido(IdDiferido::default(), &bloque_pow(3)),
            Veredicto::Ignorar
        );
        let texto =
            std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("leer registro");
        assert!(
            texto.contains("\"tipo\":\"limite_alcanzado\""),
            "falta limite_alcanzado: {texto}"
        );
    }

    /// **RSS-1 · una tx huérfana no se retransmite.**
    ///
    /// El depósito de huérfanas de la mempool está acotado, pero reenviar cada una multiplicaba la
    /// carga de gossip de toda la malla por el número de pares. El nodo la conserva y devuelve
    /// `Ignorar`, que **no penaliza** al propagador.
    #[test]
    fn una_tx_huerfana_no_se_reenvia() {
        let (_dir, reg) = registro();
        let (tx, _rx) = super::super::nueva_cola_trabajo_red();
        let m = ManejadorRed::nuevo(
            tx,
            Arc::new(VistaRed::nueva(estado_vacio())),
            reg,
            mempool_test(),
            reg_dir(),
        );

        let candidata = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: OutPoint {
                    prev_txid: TxId::from_digest(Digest::from_bytes([9; 32])),
                    prev_index: 0,
                },
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(1).expect("importe"),
                lock: Lock::PubKey {
                    pubkey: ClavePublica::desde_bytes([9; 32]),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let mut bytes = Vec::new();
        zx_core::wire::tx_a_bytes(&mut bytes, &candidata, &[]);

        assert_eq!(
            m.tx_difundida(libp2p::PeerId::random(), &bytes),
            Veredicto::Ignorar,
            "una huérfana se guarda localmente pero no se retransmite"
        );
    }

    /// **A5-c-2b · X3b · agn_12.** Un voto que llega por el tema **global** se ignora: el manejador
    /// no lo entrega al motor (no lo encola) y no lo reenvía (devuelve `Ignorar`).
    #[test]
    fn agn_12_un_voto_por_el_tema_global_se_ignora_y_no_llega_al_motor() {
        let (_dir, reg) = registro();
        let (tx, mut rx) = super::super::nueva_cola_trabajo_red();
        let m = ManejadorRed::nuevo(
            tx,
            Arc::new(VistaRed::nueva(estado_vacio())),
            reg,
            mempool_test(),
            reg_dir(),
        );
        // Sobre con la forma mínima plausible (`ZXV3`, 252 B).
        let mut plausible = b"ZXV3".to_vec();
        plausible.extend(std::iter::repeat_n(0u8, 252 - 4));
        assert!(crate::votos::voto_es_plausible(&plausible));
        assert_eq!(
            m.voto_difundida(libp2p::PeerId::random(), &plausible),
            Veredicto::Ignorar,
            "el tema global de votos está muerto: se ignora"
        );
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "el voto global no debe encolarse hacia el hilo de consenso"
        );
        // Control: un voto de subred sí se difiere y se encola.
        assert_eq!(
            m.voto_subred_difundida(
                IdDiferido::default(),
                2,
                &plausible,
                libp2p::PeerId::random()
            ),
            Veredicto::Diferir
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(TrabajoRed::VotoSubredDifundido { .. })
        ));
    }
}
