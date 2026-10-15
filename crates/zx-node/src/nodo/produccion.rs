//! Pieza P (MAP-1): producción — el bucle del productor, la ruta PoST propia y la transición.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    Almacen, BTreeMap, BlockHash, BlockHeader, BloqueCadena, BloqueDag, BloquePost, BloqueRed,
    Cadena, ClaveDev, ErrorNodo, ExtensionTx, FuenteSoluciones, HistoriaGenesis, Instant,
    MAX_BUNDLES_POT, MsgBucle, MsgProductor, Nodo, Origen, PARAMETROS_POW_DEV, PadresDag,
    ParametrosProductor, ParcelaDisco, ProductoFirmado, Registro, ResultadoNodo, SolucionCandidata,
    Tx, abrir_o_crear_parcela, encajar_votos_propios, evidencias_para_cuerpo_post,
    firma_contextual, garantia_promovida_en_slot, identidad_de_cabecera_post, mpsc,
    operacion_certificado_peso, padres_de_regimen, perfil, pow, txid, ventana_de_certificado_peso,
    votos_propios_para_bloque,
};

impl Nodo {
    /// Sincroniza el hilo productor con el terminal seleccionado **y con la frontera PoT verificada**
    /// (`ORDEN-W08h`, IPA B-22).
    ///
    /// `ORDEN-SL4b2` decisión 0 (paso previo): si `self.cadena.terminal()` (el seleccionado por FC-3,
    /// `ORDEN-W06d7`) ya no es `*terminal` (el que el hilo productor sigue produciendo), manda al
    /// hilo el `ServicioPot` de verificación del nuevo terminal —ya avanzado con toda su historia
    /// admitida, `asegurar_servicios_verificacion` lo garantiza— y actualiza `*terminal`.
    ///
    /// El hilo adopta ese `ServicioPot` como propio (`regimen::MsgBucle::CambiarTerminal`) y elige
    /// sus próximos padres sobre el DAG del terminal nuevo automáticamente: `padres_de_regimen` lee
    /// `self.cadena.contexto_dag()`/`tips_validas()` del terminal **seleccionado**, sin que este
    /// método tenga que tocar nada de la elección de padres.
    ///
    /// `ORDEN-W08h` decisión 1: cuando el terminal **no** cambia, la misma vía (`CambiarTerminal`)
    /// transporta la **frontera verificada** de ese terminal —el `ServicioPot` de verificación del
    /// bucle, avanzado con las salidas de los bloques admitidos, cuyos checkpoints ya se
    /// comprobaron— cada vez que su `slot_actual()` supera el último avisado (`*frontera_enviada`).
    /// El hilo la adopta **solo si va por delante** de su timelord (decisión 2); así un nodo
    /// reiniciado con retraso o una CPU más lenta que la red vuelven a producir en ≤ 30 slots.
    ///
    /// Devuelve `true` si se sincronizó un cambio de terminal (el llamante no debe contestar con
    /// datos del terminal anterior a la petición del hilo que disparó esta llamada, si la había).
    ///
    /// # Errores
    /// El de [`Self::asegurar_servicios_verificacion`].
    pub(super) fn sincronizar_productor(
        &mut self,
        terminal: &mut BlockHash,
        frontera_enviada: &mut u64,
        tx_a_productor: &mpsc::Sender<MsgBucle>,
    ) -> Result<bool, ErrorNodo> {
        let Some(actual) = self.cadena.terminal() else {
            return Ok(false);
        };
        if actual != *terminal {
            self.asegurar_servicios_verificacion()?;
            let Some(servicio) = self.servicios_verificacion.get(&actual).cloned() else {
                // No debería ocurrir tras `asegurar_servicios_verificacion`, pero no es motivo para
                // matar el proceso: se reintentará en la próxima vuelta del bucle.
                return Ok(false);
            };
            tracing::info!(
                terminal_anterior = ?*terminal,
                terminal_nuevo = ?actual,
                slot_frontera = servicio.slot_actual(),
                "fase_regimen: el terminal seleccionado cambió; se sincroniza el hilo productor sin \
                 reiniciar el proceso (decisión 0 de ORDEN-SL4b2)"
            );
            *terminal = actual;
            *frontera_enviada = servicio.slot_actual();
            // Si el hilo ya cerró su extremo del canal (apagado en curso), no hay nada que avisar.
            let _ = tx_a_productor.send(MsgBucle::CambiarTerminal(servicio));
            return Ok(true);
        }
        // Mismo terminal: avisar de la frontera verificada cuando avance (decisión 1 de W08h).
        if let Some(servicio) = self.servicios_verificacion.get(&actual) {
            let slot = servicio.slot_actual();
            if slot > *frontera_enviada {
                *frontera_enviada = slot;
                let _ = tx_a_productor.send(MsgBucle::CambiarTerminal(servicio.clone()));
            }
        }
        Ok(false)
    }

    /// ECL-R2a-3 · Atiende una `Post` **propia** del hilo productor por la ruta real del bucle.
    ///
    /// Si el eclipse se detectó después de que el productor enviara el bloque, la salida propia se
    /// descarta aquí: no se admite, ni se persiste, ni se difunde, ni se registra `bloque_producido`
    /// (cero producción). El bucle sigue con red/sync y el productor queda esperando respuesta, de
    /// modo que no produce más. En cualquier otro caso se comporta exactamente como antes.
    pub(super) fn procesar_post_propio(
        &mut self,
        id: u64,
        bloque: BloqueDag,
        instante_salida: Instant,
        clave_indice: u32,
        terminal: BlockHash,
        tx_a_productor: &mpsc::Sender<MsgBucle>,
    ) -> ResultadoNodo<ControlPost> {
        let hash = bloque.cabecera.block_hash();
        // ECL-R2a-3 · D4 · salida propia en vuelo: el eclipse manda. Se descarta y se registra; el
        // productor no recibe respuesta (queda parado sin producir) y la red/sync siguen.
        if self.cadena.eclipse().is_some() {
            let evento = self
                .registro
                .evento("bloque_propio_descartado")
                .str("hash", &hash.to_string())
                .str("motivo", "eclipse");
            self.registro.escribir(evento, false)?;
            return Ok(ControlPost::Descartado);
        }
        let slot = bloque.cabecera.slot;
        let n_padres = {
            let p = &bloque.cabecera.padres;
            if p.es_genesis() {
                0
            } else {
                (1 + p.extras().len()) as u64
            }
        };
        let n_txs = bloque.txs().len() as u64;
        let bytes = zx_p2p::codec::bloque_a_bytes(&BloqueRed::Post {
            cabecera: bloque.cabecera,
            justificacion: bloque.justificacion.clone(),
            txs: bloque.txs().to_vec(),
            testigos: bloque.testigos().to_vec(),
        })
        .len() as u64;
        let retraso_slot_ns = instante_salida.elapsed().as_nanos() as u64;
        // `ORDEN-SL4b2` decisión 4 (`evidencia_incluida`): los `incident_id` de las `EvidenceTx` que
        // este bloque lleva, calculados **antes** de mover `bloque` a `admitir_post_interno`.
        let incidentes_incluidos: Vec<([u8; 32], zx_core::ClavePublica)> = bloque
            .txs()
            .iter()
            .filter_map(|t| match &t.extension {
                zx_core::ExtensionTx::Evidencia { h1, .. } => Some((
                    *zx_core::incident_id_evidencia(
                        h1.consensus_branch_id,
                        h1.sol.public_key.bytes(),
                        h1.sol.sector_index,
                        h1.sol.history_size,
                        &h1.sol.chunk,
                        h1.slot,
                    )
                    .as_bytes(),
                    h1.sol.public_key,
                )),
                _ => None,
            })
            .collect();
        let txs_bloque: Vec<Tx> = bloque.txs().to_vec();
        let testigos_bloque = bloque.testigos().to_vec();
        match self.admitir_post_interno(bloque, self.almacen.longitud_registro()?, true) {
            Ok(()) => {
                // `ORDEN-TX3`: las transacciones del bloque PoST propio salen de la mempool.
                self.actualizar_mempool_tras_bloque_con_recibo(
                    hash,
                    &txs_bloque,
                    &testigos_bloque,
                    None,
                );
                for (incident_id, _clave) in &incidentes_incluidos {
                    let evento = self
                        .registro
                        .evento("evidencia_incluida")
                        .str(
                            "incident_id",
                            &zx_core::digest::Digest::from_bytes(*incident_id).to_string(),
                        )
                        .str("bloque", &hash.to_string());
                    self.registro.escribir(evento, false)?;
                    // `garantia_clave_tras_evidencia` (diagnóstico con `activo`/`congelado` para V4)
                    // ya lo escribe, para **cualquier** vía de admisión, `admitir_post_interno` (única
                    // tubería, ver el comentario allí); no se repite aquí.
                }
                let mut evento = self
                    .registro
                    .evento("bloque_producido")
                    .str("hash", &hash.to_string())
                    .u64("slot", slot)
                    .u64("n_padres", n_padres)
                    .u64("n_txs", n_txs)
                    .u64("bytes", bytes)
                    .u64("retraso_slot_ns", retraso_slot_ns)
                    // W08c (solo diagnóstico): atribución por clave de la producción.
                    .u64("clave_indice", u64::from(clave_indice));
                if let Some((azules, rojos)) = self.cadena.mergeset_de(&hash) {
                    evento = evento
                        .u64("azules_mergeset", azules)
                        .u64("rojos_mergeset", rojos);
                }
                self.registro.escribir(evento, false)?;
                self.difundir_si_hay_red(hash);
                // El pasado del `ServicioPot` de verificación acaba de avanzar: algún bloque de red
                // que quedó `Pendiente` (decisión 3 extendida) puede haber dejado de estarlo.
                self.reintentar_post_pendientes();
                // VNT-R2 · punto completo tras un bloque propio: atiende las fronteras verificadas
                // antes de responder al productor para el siguiente armado.
                self.atender_fronteras_votos()?;
                let continuar = self.limite_productor().is_none_or(|limite| {
                    self.servicios_verificacion
                        .get(&terminal)
                        .is_some_and(|s| s.slot_actual() < limite)
                });
                let respuesta = if continuar {
                    MsgBucle::Continuar { id }
                } else {
                    MsgBucle::Parar
                };
                if tx_a_productor.send(respuesta).is_err() {
                    return Ok(ControlPost::Parar);
                }
                if continuar {
                    Ok(ControlPost::Continuar)
                } else {
                    Ok(ControlPost::Parar)
                }
            }
            // `ORDEN-W06d5` decisión 3: un rechazo **legítimo** (RD-9/RD-5/carrera de padres, ver
            // `crate::rechazo`) se registra y se descarta; el nodo sigue en régimen. Solo una
            // violación de invariante interna sigue siendo fatal (decisión 4 de `ORDEN-W06d1`).
            Err(e) => {
                if let ErrorNodo::BloquePropioRechazado {
                    hash,
                    motivo,
                    clasificacion,
                } = &e
                    && clasificacion.es_legitimo()
                {
                    if !incidentes_incluidos.is_empty() {
                        let evento = self
                            .registro
                            .evento("bloque_propio_rechazado_con_evidencia")
                            .str("hash", &hash.to_string())
                            .str("motivo", motivo)
                            .u64("slot", slot)
                            .u64("n_padres", n_padres)
                            .u64("n_txs", n_txs)
                            .u64("n_evidencias", incidentes_incluidos.len() as u64);
                        self.registro.escribir(evento, false)?;
                    }
                    let evento = self
                        .registro
                        .evento("bloque_propio_rechazado_legitimo")
                        .str("hash", &hash.to_string())
                        .str("motivo", motivo);
                    self.registro.escribir(evento, false)?;
                    if tx_a_productor.send(MsgBucle::Continuar { id }).is_err() {
                        return Ok(ControlPost::Parar);
                    }
                    return Ok(ControlPost::Continuar);
                }
                Err(e)
            }
        }
    }

    /// Construye los depósitos F-15 pendientes (coinbases maduras propias sin depositar) para la
    /// altura `altura_bloque` (decisión 5).
    pub(super) fn preparar_depositos(
        &self,
        altura_bloque: u32,
    ) -> ResultadoNodo<Vec<(Tx, Vec<Vec<u8>>)>> {
        // `estado_terminal()` solo es el estado de la punta **antes del corte**: es
        // `Estado::inicial()` hasta que `zx-cadena` fija el terminal (comprobado, no una
        // suposición: el primer intento de este test dio `ErrNonce` porque todo depósito de la
        // fase PoW pedía `nonce = 0`, el de `Estado::inicial()`, aunque ya hubiera uno aplicado).
        // El estado correcto para construir la plantilla de la siguiente altura es el de la
        // **última cabecera PoW admitida**, con `estado_post`.
        #[expect(
            clippy::indexing_slicing,
            reason = "historial_pow siempre tiene al menos el génesis"
        )]
        let ultimo_hash = self.historial_pow[self.historial_pow.len() - 1].block_hash();
        let estado = self
            .cadena
            .estado_post(&ultimo_hash)
            .ok_or_else(|| ErrorNodo::Otro("estado del último bloque PoW ausente".to_string()))?;
        let mut depositos = Vec::new();
        // Hallazgo en vivo (`PROGRESO.md`, primera corrida real de V4, no es un bug de esta orden
        // pero impide demostrarla): el `nonce` de una operación de garantía es un contador **por
        // clave**, no por coinbase. Si la misma clave acumula más de una coinbase madura sin
        // depositar todavía (le basta con que el nodo pase un rato sin que su primer depósito
        // tenga éxito — p. ej. mientras está aislado de la red, ver el diagnóstico de la decisión
        // 4), el bucle de abajo construía **todos** los depósitos de esa clave con el mismo
        // `nonce` leído una sola vez del estado: el segundo, en el mismo bloque, siempre
        // discrepaba con el `nonce_siguiente` que el primero ya había incrementado (`ErrNonce`,
        // modo estricto ⇒ bloque entero inválido ⇒ bloque propio rechazado ⇒ fatal). Se lleva un
        // nonce local por clave, sembrado con el real del estado la primera vez que esa clave
        // aparece en este bloque y luego incrementado en memoria por cada depósito adicional de la
        // misma clave — exactamente lo que el motor de transición espera ver, sin tocar el estado
        // (que no cambia hasta que el bloque se aplique de verdad).
        let mut siguiente_nonce: std::collections::BTreeMap<zx_core::ClavePublica, u64> =
            std::collections::BTreeMap::new();
        // `ORDEN-W06d4` decisión 2: qué depositar se decide leyendo **directamente**
        // `estado.utxo`/`estado.garantias` de la punta PoW ya seleccionada, no un indicador local
        // (`CoinbasePropia.depositada`, `ORDEN-W06d3`) que podía desincronizarse de la rama. Una
        // coinbase propia sigue siendo candidata a depósito exactamente mientras su salida está sin
        // gastar **en el estado de esta rama** (`estado.utxo` la vuelve a mostrar por sí solo si el
        // bloque que la gastó queda descartado por una reorganización, sin ninguna poda aparte); y
        // deja de serlo en el instante en que un bloque de esta rama la gasta de verdad (sale de
        // `estado.utxo`). Iterar `estado.utxo` (`BTreeMap`, orden determinista por `OutPoint`) evita
        // además tener que reconstruir qué coinbases siguen vivas tras cada reorganización.
        for (outpoint, entrada) in &estado.utxo {
            if outpoint.prev_index != 0 || entrada.origen != Origen::CoinbasePow {
                continue;
            }
            let zx_core::Lock::PubKey { pubkey } = entrada.lock else {
                continue;
            };
            let Some(clave) = self.claves.iter().find(|c| c.pk == pubkey) else {
                continue;
            };
            let Some(altura_creacion) = entrada.creada.como_altura() else {
                continue;
            };
            let Some(madura_en) = altura_creacion.checked_add(self.params.m_cb) else {
                continue;
            };
            if altura_bloque < madura_en {
                continue;
            }
            let nonce = *siguiente_nonce.entry(clave.pk).or_insert_with(|| {
                estado
                    .garantias
                    .get(&clave.pk)
                    .map_or(0, |g| g.nonce_siguiente)
            });
            siguiente_nonce.insert(clave.pk, nonce.saturating_add(1));
            let (tx, testigos) =
                pow::construir_deposito(outpoint.prev_txid, entrada.valor, clave, nonce, self.cbid)
                    .map_err(|e| ErrorNodo::Otro(format!("construir depósito: {e}")))?;
            depositos.push((tx, testigos));
        }
        Ok(depositos)
    }

    /// P2 (`ORDEN-MP1`): trata el rechazo de un bloque propio **por su cuerpo** sin matar el nodo:
    /// expulsa de la cola las transacciones del bloque que no son la coinbase —sin marcarlas como
    /// aplicadas— y escribe el evento `bloque_propio_rechazado_por_tx` con `hash`, `altura`,
    /// `motivo`, `n_txs` y el número de expulsadas. `fase_pow` sigue con la vuelta siguiente.
    ///
    /// # Errores
    /// Los de E/S al escribir el registro.
    pub(super) fn manejar_bloque_propio_rechazado_por_tx(
        &mut self,
        hash: BlockHash,
        altura: u32,
        motivo: &str,
        n_txs: u64,
        txs: &[Tx],
    ) -> ResultadoNodo<()> {
        let ids: Vec<zx_core::TxId> = txs
            .iter()
            .filter(|t| !es_coinbase_pow(t))
            .map(|t| zx_core::txid(t, self.cbid))
            .collect();
        let expulsadas = {
            let mut m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
            m.expulsar(&ids)
        };
        let evento = self
            .registro
            .evento("bloque_propio_rechazado_por_tx")
            .str("hash", &hash.to_string())
            .u64("altura", u64::from(altura))
            .str("motivo", motivo)
            .u64("n_txs", n_txs)
            .u64("expulsadas", u64::try_from(expulsadas).unwrap_or(u64::MAX));
        self.registro.escribir(evento, false)?;
        Ok(())
    }

    /// `firmar_post_ensayado` vive ahora en `firma_contextual.rs` (PROD-3b-2 §2.1).
    /// Fase PoST en régimen: arranca `ServicioPot` de verificación, las parcelas locales y el hilo
    /// productor, y atiende sus peticiones hasta que se agote (`--parada-tras-slots`) o falle.
    ///
    /// # Errores
    /// [`ErrorNodo::BloquePropioRechazado`] con `clasificacion` interna (`ORDEN-W06d5` decisión 3, `crate::rechazo`); un rechazo legítimo se descarta y no llega a devolverse.
    /// ECL-R2a-4 · Atiende **un** mensaje del productor por la ruta real del bucle de régimen.
    ///
    /// Es el despacho que antes vivía dentro de `fase_regimen`; se extrae para que los tests de la
    /// orden puedan ejercitar la **misma** ruta (incluida la `Post` propia en vuelo) sin duplicar el
    /// `match` ni saltarse el bucle. `terminal_cambio` es el resultado de
    /// [`Self::sincronizar_productor`] en esa vuelta, que el bucle calcula antes de despachar.
    #[allow(clippy::too_many_lines)]
    pub(super) fn atender_msg_productor(
        &mut self,
        msg: MsgProductor,
        terminal_cambio: bool,
        terminal: BlockHash,
        tx_a_productor: &mpsc::Sender<MsgBucle>,
    ) -> ResultadoNodo<ControlBucle> {
        match msg {
            MsgProductor::PeticionPadres { .. } if terminal_cambio => {
                // Petición del terminal anterior: se descarta sin contestar (ver arriba).
            }
            MsgProductor::PeticionPadres {
                id,
                slot: slot_objetivo,
            } => {
                // ECL-R2a · D4: en modo detenido no se produce; no se contesta al productor.
                if self.cadena.eclipse().is_some() {
                    return Ok(ControlBucle::Continuar);
                }
                // `RL-2d-2` (b): si el `N` del ajuste que rige en `slot_objetivo` no está
                // comprometido, no se produce ese slot. No se contesta `Padres` al hilo (no
                // construye bloque) y `reloj_produccion_permitida` ya registró el evento; el
                // hilo reanuda cuando el `ServicioPot` de verificación del bucle avance y
                // `sincronizar_productor` le mande su frontera por `CambiarTerminal`.
                if let Some(servicio) = self.servicios_verificacion.get(&terminal)
                    && !reloj_produccion_permitida(
                        &self.perfil_red,
                        &self.registro,
                        servicio.calendario(),
                        slot_objetivo,
                    )?
                {
                    return Ok(ControlBucle::Continuar);
                }
                let padres = match padres_de_regimen(&self.cadena) {
                    Ok(padres) => padres,
                    Err(crate::padres::ErrorPadres::SinPuntas) => {
                        // FV-4b-N2: la cota de finalidad por votos puede vaciar las puntas de
                        // forma transitoria (candidato lateral o reorganización). Se omite este
                        // slot en vez de morir: el reloj de slots sigue y el nodo reintenta.
                        let evento = self
                            .registro
                            .evento("produccion_sin_puntas")
                            .str("motivo", "sin_puntas");
                        let _ = self.registro.escribir(evento, false);
                        return Ok(ControlBucle::Continuar);
                    }
                    Err(e) => {
                        return Err(ErrorNodo::Otro(format!("padres de régimen: {e}")));
                    }
                };
                // `(hash, slot)` de cada padre (seleccionado y extras): el hilo productor
                // necesita esto para registrar en su propio `ServicioPot` cualquier padre que
                // no haya producido él mismo (`ORDEN-W06d3`, ver el docstring de
                // `MsgBucle::Padres`). Todo padre de régimen es un `BloqueCadena::Post` (el
                // único `Pow` posible, el terminal, no aparece en `tips_validas`).
                let mut info_padres = Vec::with_capacity(1 + padres.extras().len());
                for h in
                    std::iter::once(padres.seleccionado()).chain(padres.extras().iter().copied())
                {
                    if let Some(BloqueCadena::Post(p)) = self.cadena.bloque(&h) {
                        info_padres.push((h, p.slot));
                    }
                }
                // `ORDEN-W06d5` decisión 1 (RD-9): claves (de entre las que gestiona este
                // nodo) con garantía activa `>= q` en `Estado(padre_seleccionado)`. Solo el
                // bucle tiene `Cadena`/`self.params.q`; se calcula aquí, una vez por slot (los
                // hermanos del mismo slot comparten padres), y se manda al hilo productor para
                // que nunca intente `producir_en_regimen` con una clave que no lo alcance
                // (causa de `ErrGarantia` fatal en V5 de `REVISION-W06d4.md`).
                if let Some(base) = self.cadena.estado_post(&padres.seleccionado())
                    && let Some(motor) = self.motor_votos.as_mut()
                {
                    motor.actualizar_certificados_peso(base, slot_objetivo);
                }
                self.registrar_eventos_certificados_pendientes();
                let estado_base = self.cadena.estado_post(&padres.seleccionado());
                // `ORDEN-W06d5` decisión 1 (RD-9), **B-112 (PROD-3b)**: la decisión de garantía
                // es del ensayo. El filtro usa la garantía **promovida** en `slot_objetivo`
                // (activo + pendientes/créditos con `madura_en_slot <= slot_objetivo`).
                let con_garantia: std::collections::BTreeSet<zx_core::ClavePublica> = estado_base
                    .map(|estado| {
                        self.claves
                            .iter()
                            .filter(|c| {
                                garantia_promovida_en_slot(estado, &c.pk, slot_objetivo)
                                    >= self.params.q
                            })
                            .map(|c| c.pk)
                            .collect()
                    })
                    .unwrap_or_default();
                let evp = perfil::parametros_evidencia_dev();
                let mut votos = Vec::new();
                if let Some(base) = estado_base {
                    votos = votos_propios_para_bloque(&self.v6_pendientes, base, slot_objetivo);
                    votos.extend(self.actas_peso_para_bloque(base, slot_objetivo));
                }
                // El receptor antepone una v3 de estos mismos campos. Clave, importe y slot
                // son de anchura fija en el códec; cualquier clave productora mide lo mismo.
                let clave = self.claves.first().ok_or_else(|| {
                    ErrorNodo::Otro("armado PoST sin clave productora".to_string())
                })?;
                let coinbase = Tx {
                    version: 3,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    lock_time: 0,
                    expiry_height: 0,
                    extension: ExtensionTx::CoinbasePost {
                        clave: clave.pk,
                        importe: perfil::subsidio_post(0),
                        slot: slot_objetivo,
                    },
                };
                // PROD-1 · P1/N2: reserva certificados antes de evidencias, votos y cola.
                let certificados = estado_base
                    .map(|base| self.certificados_para_cuerpo_post(base, slot_objetivo, &coinbase))
                    .unwrap_or_default();
                let semilla = slot_objetivo.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                let CuerpoPostPresupuestado {
                    txs,
                    testigos,
                    recorte,
                } = presupuestar_cuerpo_post(
                    &coinbase,
                    certificados,
                    || {
                        let de_cola = self
                            .mempool
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .elegir_evidencias(usize::MAX);
                        evidencias_para_cuerpo_post(
                            &self.detector,
                            de_cola,
                            estado_base,
                            slot_objetivo,
                            evp.plazo_slots,
                            perfil::MAX_EVIDENCIAS_POR_BLOQUE,
                        )
                    },
                    votos,
                    self.params.max_cuerpo_bloque_bytes,
                    |max_cola| {
                        self.mempool
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .seleccionar(max_cola, semilla)
                    },
                )?;
                let ventanas_ofrecidas: Vec<_> = txs
                    .iter()
                    .filter_map(operacion_certificado_peso)
                    .filter_map(ventana_de_certificado_peso)
                    .collect();
                if let Some((antes, despues)) = recorte {
                    let evento = self
                        .registro
                        .evento("cuerpo_recortado")
                        .u64("slot", slot_objetivo)
                        .u64("bytes_antes", antes)
                        .u64("bytes_despues", despues)
                        .u64("bytes_recortados", antes.saturating_sub(despues))
                        .u64(
                            "max_cuerpo_bloque_bytes",
                            self.params.max_cuerpo_bloque_bytes,
                        );
                    self.registro.escribir(evento, false)?;
                }
                // T3: el hilo filtrará estos mismos extras antes de sellar. La marca se
                // calcula para los padres efectivos, con la ventana causal del receptor.
                let marca_reloj = if self.perfil_red.reloj_activo {
                    match crate::regimen::filtrar_padres_extra_por_slot(
                        padres,
                        &info_padres,
                        slot_objetivo,
                    ) {
                        // Si el filtro de padres falla, el hilo lo denuncia como fallo fatal
                        // antes de usar la marca: no se enmascara con una abstención.
                        Err(_) => crate::regimen::MarcaReloj::Inactivo,
                        Ok(efectivos) => {
                            match self
                                .servicios_verificacion
                                .get(&terminal)
                                .and_then(|s| self.timestamp_propio_post(s, &efectivos))
                            {
                                Some(timestamp) => crate::regimen::MarcaReloj::Elegida {
                                    timestamp,
                                    i_iter: self.perfil_red.reloj.i_iter,
                                },
                                None => crate::regimen::MarcaReloj::Abstenerse,
                            }
                        }
                    }
                } else {
                    crate::regimen::MarcaReloj::Inactivo
                };
                // Las operaciones excluidas siguen en mempool/detector/v6_pendientes.
                if tx_a_productor
                    .send(MsgBucle::Padres {
                        id,
                        marca_reloj,
                        padres,
                        info_padres,
                        con_garantia,
                        txs,
                        testigos,
                    })
                    .is_err()
                {
                    return Ok(ControlBucle::Romper);
                }
                for n in ventanas_ofrecidas {
                    if self
                        .motor_votos
                        .as_mut()
                        .is_some_and(|motor| motor.marcar_certificado_anterior_ofrecido(n))
                    {
                        let evento = self
                            .registro
                            .evento("certificado_peso_anterior_ofrecido")
                            .u64("n", n)
                            .u64("slot", slot_objetivo);
                        self.registro.escribir(evento, false)?;
                    }
                }
            }
            MsgProductor::Candidata {
                id,
                candidata,
                instante_salida,
                clave_indice,
            } => {
                use firma_contextual::DestinoCandidata;
                match self.procesar_candidata_propia(
                    id,
                    *candidata,
                    instante_salida,
                    clave_indice,
                    terminal,
                    terminal_cambio,
                    tx_a_productor,
                ) {
                    Ok(DestinoCandidata::Admitido { .. }) => {}
                    Ok(DestinoCandidata::Parar) => return Ok(ControlBucle::Romper),
                    Ok(DestinoCandidata::Eclipse) | Ok(DestinoCandidata::Atrasada) => {
                        return Ok(ControlBucle::Continuar);
                    }
                    Ok(DestinoCandidata::Descartada { .. })
                    | Ok(DestinoCandidata::FirmanteAbstenido { .. }) => {}
                    Err(e) => {
                        let _ = tx_a_productor.send(MsgBucle::Parar);
                        return Err(e);
                    }
                }
            }
            // VNT-R1 · el hilo PoT verificó en local la salida de un slot, con o sin ganadora. No
            // es un bloque ni mueve consenso: solo avanza el cursor y despacha las fronteras. La
            // salida de una generación ajena (otro terminal) no se registra.
            MsgProductor::FronteraPot { flujo, slot, n } => {
                if flujo == terminal {
                    self.registrar_frontera_pot(flujo, slot, n)?;
                    self.atender_fronteras_votos()?;
                }
            }
            // `ORDEN-W06d8` decisión 3: el hilo productor detectó una violación de invariante
            // (o un fallo interno irrecuperable) y pide parar. No es una entrada ajena ni un
            // `panic` del nodo: es una parada ordenada. Evento crítico `fallo_productor` +
            // error fatal (salida ≠ 0), nunca un nodo que valida y deja de producir en silencio.
            MsgProductor::Fallo { motivo } => {
                return self.fallo_productor(&motivo).map(|()| ControlBucle::Romper);
            }
        }
        Ok(ControlBucle::Continuar)
    }

    /// El límite de slot en el que el hilo productor debe dejar de producir (`ORDEN-W06d6`
    /// decisión 6): el más restrictivo de `--parada-tras-slots` y `--dejar-de-producir-en-slot`,
    /// si hay alguno.
    pub(super) fn limite_productor(&self) -> Option<u64> {
        match (self.parada_tras_slots, self.dejar_de_producir_en_slot) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// RLJ-1: audita y calcula primero el slot; toma la hora después, sin volver a auditar.
    ///
    /// PROD-3b-2 §2.5: devuelve la candidata **sin sello**; la firma pasa por los pasos 2 a 5
    /// con las mismas funciones que la candidata del hilo.
    fn armar_transicion_propia(
        &self,
        terminal: BlockHash,
        fuente: &FuenteTransicion<'_>,
        clave: &ClaveDev,
    ) -> ResultadoNodo<Option<BloqueDag>> {
        let mut servicio = self
            .servicios_verificacion
            .get(&terminal)
            .cloned()
            .ok_or_else(|| {
                ErrorNodo::Otro("transición sin ServicioPot de verificación".to_string())
            })?;
        let padres = PadresDag::nuevo(terminal, &[]).map_err(|e| ErrorNodo::Otro(e.to_string()))?;
        if self.registro_firmante.is_none() {
            return Err(ErrorNodo::Otro(
                "transición sin registro de firmante".to_string(),
            ));
        }
        let mut omitido_por_timestamp = false;
        for slot in 1..=MAX_BUNDLES_POT as u64 {
            if servicio.slot_actual() < slot {
                servicio
                    .avanzar_hasta(slot)
                    .map_err(|e| ErrorNodo::Otro(e.to_string()))?;
            }
            let salida = servicio
                .salida_de(slot)
                .map_err(|e| ErrorNodo::Otro(e.to_string()))?;
            let candidatas = fuente
                .soluciones(salida, slot, self.sr_dev_actual)
                .map_err(|e| ErrorNodo::Otro(format!("fuente de transición: {e}")))?;
            let Some(candidata) = candidatas.into_iter().next() else {
                continue;
            };
            let Some(timestamp) = self.timestamp_propio_post(&servicio, &padres) else {
                self.registro.escribir(
                    self.registro
                        .evento("bloque_transicion_abstenido")
                        .u64("slot", slot)
                        .str("motivo", "sin_timestamp_admisible")
                        .i64("reloj_local", self.reloj_local()),
                    true,
                )?;
                omitido_por_timestamp = true;
                continue;
            };
            let preparada = FuenteTransicionPreparada {
                candidata,
                salida,
                slot,
                rango: self.sr_dev_actual,
            };
            let parametros = ParametrosProductor {
                n_dev: self.n_dev_vigente(),
                sr_dev: self.sr_dev_actual,
                max_slots: MAX_BUNDLES_POT as u64,
                consensus_branch_id: self.cbid,
                timestamp,
                i_iter: if self.perfil_red.reloj_activo {
                    self.perfil_red.reloj.i_iter
                } else {
                    zx_post::reloj_post::I_ITER_DEV
                },
                importe_coinbase: perfil::subsidio_post(0),
            };
            // Ruta nueva (PROD-3b-2 §2.5): se arma sin sello; la firma va por los pasos 2 a 5.
            let sin_sello = zx_post::productor_regimen::preparar_regimen_para_ensayo(
                padres,
                slot,
                &mut servicio,
                &preparada,
                &clave.sk,
                &parametros,
                zx_post::productor_regimen::CuerpoProductor::vacio(),
            )
            .map_err(|e| ErrorNodo::Otro(format!("armado de transición: {e}")))?;
            return Ok(Some(sin_sello));
        }
        if omitido_por_timestamp {
            return Ok(None);
        }
        Err(ErrorNodo::Otro(format!(
            "sin solución PoAS en los primeros {MAX_BUNDLES_POT} slots"
        )))
    }

    /// `ORDEN-SL4b3` decisión 1: el bloque de transición se produce con el **mismo** firmante
    /// seguro del nodo que usa el régimen (registro único por nodo, `C-EVP-06`, FIR-01…FIR-15).
    /// PROD-3b-2 §2.5: pasa por los pasos 2 a 5 con las mismas funciones que la candidata del hilo.
    pub(super) fn producir_bloque_transicion(&mut self, terminal: BlockHash) -> ResultadoNodo<()> {
        #[expect(clippy::indexing_slicing, reason = "la CLI exige al menos una clave")]
        let clave = self.claves[0].clone();
        self.asegurar_servicios_verificacion()?;
        let parcela = abrir_o_crear_parcela(&self.dir_datos, &clave, &self.historia)?;
        let sin_sello = {
            let fuente = FuenteTransicion {
                parcela: &parcela,
                historia: &self.historia,
            };
            self.armar_transicion_propia(terminal, &fuente, &clave)?
        };
        let Some(sin_sello) = sin_sello else {
            return Ok(());
        };
        let producto = match self.comprobar_depurar_ensayar_firmar(sin_sello, &clave.sk)? {
            Ok(producto) => producto,
            Err((motivo, clase)) => {
                use firma_contextual::ClasificacionFirma;
                return match clase {
                    ClasificacionFirma::Rechazo => {
                        let evento = self
                            .registro
                            .evento("bloque_transicion_abstenido")
                            .str("motivo", &motivo);
                        self.registro.escribir(evento, true)?;
                        Ok(())
                    }
                    ClasificacionFirma::Fallo => self.fallo_productor(&motivo),
                };
            }
        };
        let bloque = match producto {
            ProductoFirmado::Bloque(bloque, _) => bloque,
            ProductoFirmado::Abstenido { slot, motivo } => {
                // Decisión 1: el bloque no se produce; evento crítico del esquema v1 con el slot
                // real de la oportunidad y el motivo. El llamante espera a otro nodo.
                let evento = self
                    .registro
                    .evento("firmante_abstenido")
                    .u64("slot", slot)
                    .str("motivo", motivo_abstencion_texto(motivo));
                self.registro.escribir(evento, true)?;
                return Ok(());
            }
        };
        let hash = bloque.cabecera.block_hash();
        let slot = bloque.cabecera.slot;
        // `ORDEN-TX2b` decisión 5: la plantilla PoST respeta `max_cuerpo_bloque_bytes`. El bloque
        // de transición solo lleva la coinbase v3 (la incluye `producir_con_firmante`); se
        // comprueba explícitamente para no emitir un cuerpo que el motor rechazaría por TXL-02.
        let bytes_cuerpo = {
            let mut total: u64 = 0;
            let mut buf: Vec<u8> = Vec::new();
            for (tx, tst) in bloque.txs().iter().zip(bloque.testigos().iter()) {
                buf.clear();
                zx_core::wire::tx_a_bytes(&mut buf, tx, tst);
                total = total.checked_add(buf.len() as u64).ok_or_else(|| {
                    ErrorNodo::Otro("cuerpo del bloque PoST desbordado".to_string())
                })?;
            }
            total
        };
        if bytes_cuerpo > self.params.max_cuerpo_bloque_bytes {
            let evento = self
                .registro
                .evento("bloque_transicion_abstenido")
                .u64("slot", slot)
                .u64("bytes_cuerpo", bytes_cuerpo)
                .u64(
                    "max_cuerpo_bloque_bytes",
                    self.params.max_cuerpo_bloque_bytes,
                );
            self.registro.escribir(evento, true)?;
            return Ok(());
        }
        if let Err(error) =
            self.admitir_post_interno(bloque, self.almacen.longitud_registro()?, true)
        {
            if let ErrorNodo::BloquePropioRechazado { clasificacion, .. } = &error
                && matches!(
                    clasificacion,
                    crate::rechazo::ClasificacionRechazo::Legitimo
                        | crate::rechazo::ClasificacionRechazo::Pendiente
                )
            {
                self.registro.escribir(
                    self.registro
                        .evento("bloque_transicion_abstenido")
                        .u64("slot", slot)
                        .str("motivo", &error.to_string()),
                    true,
                )?;
                return Ok(());
            }
            return Err(error);
        }

        // `ORDEN-W07a`: el bloque de transición es un PoST propio admitido y persistido, pero **no**
        // se registra como `bloque_producido`: la base (W06d1…W06d6) no lo hacía y el §1 no fija su
        // `retraso_slot_ns` (no hay hilo productor). Emitirlo antes de que `fase_regimen` abra y
        // plotee las parcelas cambiaba el instante del primer `bloque_producido` y rompía la
        // verificación de reinicio tras `SIGKILL` (`reinicio.rs`): se conserva el comportamiento.
        //
        // `ORDEN-W07d` decisión 3: sí se registra como **diagnóstico** con un tipo propio,
        // `bloque_transicion_producido`, para que el bloque de transición no quede sin rastro sin
        // alterar lo que prueba `reinicio.rs` (que cuenta `bloque_producido`).
        self.registro.escribir(
            self.registro
                .evento("bloque_transicion_producido")
                .str("hash", &hash.to_string())
                .u64("slot", slot),
            false,
        )?;
        self.difundir_si_hay_red(hash);
        Ok(())
    }
}

/// PROD-1 · transacción del cuerpo PoST con todos sus testigos.
pub(super) type TxCuerpoPost = (Tx, Vec<Vec<u8>>);

/// Plantilla sin coinbase; `recorte` cuenta el cuerpo completo antes y después de la defensa P2.
pub(super) struct CuerpoPostPresupuestado {
    pub(super) txs: Vec<Tx>,
    pub(super) testigos: Vec<Vec<Vec<u8>>>,
    pub(super) recorte: Option<(u64, u64)>,
}

/// PROD-2: operación retirada del cuerpo, todavía en su origen.
#[derive(Debug)]
pub struct RetiradaPost {
    /// Transacción y testigos originales, incluso si otro ejemplar tenía el mismo txid.
    pub par: (Tx, Vec<Vec<u8>>),
    /// Motivo emitido por la transición real.
    pub motivo: zx_consensus::transicion::ErrorTransicion,
}

/// Resultado del ensayo puro de una candidata real, anterior al sello.
#[derive(Debug)]
pub struct DepuracionPost {
    /// Candidata sin sello, con compromisos recalculados sobre el cuerpo final.
    pub candidata: BloqueDag,
    /// Operaciones retiradas; el ensayo no toca cola, pendientes ni motor.
    pub retiradas: Vec<RetiradaPost>,
    /// Vueltas sobre el cuerpo candidato (sin contar el ensayo del respaldo).
    pub vueltas: usize,
    /// Se usó el respaldo de solo coinbase por agotar la cota o no poder progresar.
    pub respaldo: bool,
    /// Tamaño final medido con el códec de consenso, con coinbase y testigos.
    pub bytes_finales: u64,
}

pub(super) fn recomponer_candidata_post(
    original: &BloqueDag,
    pares: Vec<TxCuerpoPost>,
) -> ResultadoNodo<BloqueDag> {
    let (txs, testigos): (Vec<_>, Vec<_>) = pares.into_iter().unzip();
    let mut cabecera = original.cabecera;
    cabecera.merkle_root = zx_core::preimage::block::merkle_root(
        &txs.iter()
            .map(|tx| txid(tx, cabecera.consensus_branch_id))
            .collect::<Vec<_>>(),
    );
    cabecera.body_commitment =
        zx_core::body_commitment(&txs, &testigos, cabecera.consensus_branch_id)
            .map_err(|e| ErrorNodo::Otro(format!("compromiso del ensayo: {e}")))?;
    BloqueDag::nuevo(cabecera, original.justificacion.clone(), txs, testigos)
        .map_err(|e| ErrorNodo::Otro(format!("candidata de ensayo: {e}")))
}

pub(super) fn post_de_candidata(
    candidata: &BloqueDag,
    distancia: u64,
) -> ResultadoNodo<BloquePost> {
    Ok(BloquePost {
        hash: candidata.cabecera.block_hash(),
        padres: std::iter::once(candidata.cabecera.padres.seleccionado())
            .chain(candidata.cabecera.padres.extras().iter().copied())
            .collect(),
        slot: candidata.cabecera.slot,
        timestamp: candidata.cabecera.timestamp,
        productor: candidata.cabecera.sol.public_key,
        peso: peso_u128(candidata)?,
        prueba_valida: true,
        requisito_declarado: 0,
        sr: candidata.cabecera.rango_solucion,
        distancia,
        identidad: identidad_de_cabecera_post(&candidata.cabecera),
        txs: candidata
            .txs()
            .iter()
            .cloned()
            .zip(candidata.testigos().iter().cloned())
            .collect(),
    })
}

/// PROD-2: aplica el cuerpo con sus padres, mergeset e identidad reales sobre una copia.
///
/// Quita por índice únicamente lo que la transición descarta, manteniendo el orden y los
/// testigos. Cada vuelta fallida reduce estrictamente el número de operaciones; con N
/// operaciones además de la coinbase hay como máximo N+1 vueltas. El respaldo de solo
/// coinbase se ensaya primero. No se mutan cadena, cola ni motor.
///
/// # Errores
/// Si la candidata ya está sellada, la coinbase de respaldo no aplica, o falla la forma
/// del bloque/contexto. `distancia` es la de su solución PoAS ya verificada por el llamante.
pub fn depurar_candidata_post(
    cadena: &Cadena,
    candidata: &BloqueDag,
    distancia: u64,
    tope: u64,
) -> ResultadoNodo<DepuracionPost> {
    if candidata.cabecera.sello != [0; zx_core::firma::LONGITUD_FIRMA] {
        return Err(ErrorNodo::Otro(
            "el ensayo requiere una candidata sin sello".to_string(),
        ));
    }
    let coinbase = candidata
        .txs()
        .first()
        .ok_or_else(|| ErrorNodo::Otro("ensayo sin coinbase".to_string()))?;
    let tst_coinbase = candidata
        .testigos()
        .first()
        .ok_or_else(|| ErrorNodo::Otro("ensayo sin testigos de coinbase".to_string()))?;
    let respaldo =
        recomponer_candidata_post(candidata, vec![(coinbase.clone(), tst_coinbase.clone())])?;
    let ensayar = |b: &BloqueDag| {
        cadena
            .ensayar_post(&post_de_candidata(b, distancia)?)
            .map_err(|e| ErrorNodo::Otro(format!("ensayo PoST: {e}")))
    };
    let (_, descartes) = ensayar(&respaldo)?;
    if !descartes.is_empty() || bytes_cuerpo_post(coinbase, &[]) > tope {
        return Err(ErrorNodo::Otro(
            "la coinbase de respaldo no aplica o no cabe".to_string(),
        ));
    }
    let cota = candidata.txs().len(); // N+1: incluye la coinbase.
    let mut retiradas = Vec::new();
    // La forma v4 es una puerta de bloque en Cadena, anterior a la fusión. Identificar
    // aquí esas operaciones permite retirarlas sin cambiar la regla que la cadena usa.
    let mut iniciales = Vec::new();
    for (i, par) in candidata
        .txs()
        .iter()
        .cloned()
        .zip(candidata.testigos().iter().cloned())
        .enumerate()
    {
        if i != 0
            && par.0.version == 4
            && matches!(par.0.extension, ExtensionTx::Evidencia { .. })
            && let Err(motivo) =
                zx_core::validar_forma_tx_v4(&par.0, &par.1, candidata.cabecera.consensus_branch_id)
        {
            retiradas.push(RetiradaPost {
                par,
                motivo: motivo.into(),
            });
        } else {
            iniciales.push(par);
        }
    }
    let mut actual = recomponer_candidata_post(candidata, iniciales)?;
    for vuelta in 1..=cota {
        let (_, descartes) = ensayar(&actual)?;
        if descartes.is_empty() {
            let pares: Vec<_> = actual
                .txs()
                .iter()
                .cloned()
                .zip(actual.testigos().iter().cloned())
                .skip(1)
                .collect();
            let bytes_finales = bytes_cuerpo_post(coinbase, &[&pares]);
            if bytes_finales > tope {
                return Err(ErrorNodo::Otro(
                    "cuerpo depurado por encima del tope".to_string(),
                ));
            }
            return Ok(DepuracionPost {
                candidata: actual,
                retiradas,
                vueltas: vuelta,
                respaldo: false,
                bytes_finales,
            });
        }
        let por_indice: BTreeMap<_, _> = descartes
            .into_iter()
            .map(|d| (d.indice, d.motivo))
            .collect();
        if por_indice.contains_key(&0) || por_indice.keys().any(|i| *i >= actual.txs().len()) {
            break;
        }
        let mut conservadas = Vec::new();
        for (i, par) in actual
            .txs()
            .iter()
            .cloned()
            .zip(actual.testigos().iter().cloned())
            .enumerate()
        {
            if let Some(motivo) = por_indice.get(&i) {
                retiradas.push(RetiradaPost {
                    par,
                    motivo: motivo.clone(),
                });
            } else {
                conservadas.push(par);
            }
        }
        if conservadas.len() >= actual.txs().len() {
            break;
        }
        actual = recomponer_candidata_post(candidata, conservadas)?;
    }
    // Defensivo: ninguna operación pendiente se consume al usar el cuerpo seguro conocido.
    Ok(DepuracionPost {
        candidata: respaldo,
        retiradas,
        vueltas: cota,
        respaldo: true,
        bytes_finales: bytes_cuerpo_post(coinbase, &[]),
    })
}

/// Tamaño de consenso: suma del códec real de cada tx, incluidos coinbase y testigos.
pub(super) fn bytes_cuerpo_post(coinbase: &Tx, grupos: &[&[TxCuerpoPost]]) -> u64 {
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, coinbase, &[]);
    let mut total = buf.len() as u64;
    for grupo in grupos {
        for (tx, tst) in *grupo {
            buf.clear();
            zx_core::wire::tx_a_bytes(&mut buf, tx, tst);
            total = total.saturating_add(buf.len() as u64);
        }
    }
    total
}

/// P1/P2: reservar por preferencia y medir otra vez el cuerpo completo antes de enviarlo.
/// La selección de cola no consume entradas. Quitar su sufijo conserva el orden topológico
/// y deja todas las operaciones aplazadas en su origen. El orden de aplicación se conserva.
pub(super) fn presupuestar_cuerpo_post(
    coinbase: &Tx,
    certificado: impl IntoIterator<Item = TxCuerpoPost>,
    evidencias: impl FnOnce() -> Vec<TxCuerpoPost>,
    votos: Vec<TxCuerpoPost>,
    tope: u64,
    seleccionar: impl FnOnce(u64) -> Vec<TxCuerpoPost>,
) -> ResultadoNodo<CuerpoPostPresupuestado> {
    let bytes_coinbase = bytes_cuerpo_post(coinbase, &[]);
    if bytes_coinbase > tope {
        return Err(ErrorNodo::Otro(
            "la coinbase PoST no cabe en el cuerpo".to_string(),
        ));
    }
    let mut certificado =
        encajar_votos_propios(certificado.into_iter().collect(), tope, bytes_coinbase);
    let bytes_certificado = bytes_cuerpo_post(coinbase, &[&certificado]);
    let mut evidencias = encajar_votos_propios(evidencias(), tope, bytes_certificado);
    let bytes_evidencias = bytes_cuerpo_post(coinbase, &[&certificado, &evidencias]);
    let mut votos = encajar_votos_propios(votos, tope, bytes_evidencias);
    let bytes_reservados = bytes_cuerpo_post(coinbase, &[&certificado, &evidencias, &votos]);
    let max_cola = tope.saturating_sub(bytes_reservados);
    let mut cola: Vec<_> = seleccionar(max_cola)
        .into_iter()
        // Las v4 se reservan juntas, con el tope y la deduplicación por incidente.
        .filter(|(tx, _)| !matches!(tx.extension, ExtensionTx::Evidencia { .. }))
        .collect();
    let antes = bytes_cuerpo_post(coinbase, &[&cola, &evidencias, &votos, &certificado]);
    let mut despues = antes;
    // Menor preferencia primero, retirando desde el final de cada clase.
    for grupo in [&mut cola, &mut votos, &mut evidencias, &mut certificado] {
        while despues > tope {
            let Some(par) = grupo.pop() else { break };
            let quitados = bytes_cuerpo_post(coinbase, &[std::slice::from_ref(&par)])
                .saturating_sub(bytes_coinbase);
            despues = despues.saturating_sub(quitados);
        }
    }
    let despues = bytes_cuerpo_post(coinbase, &[&cola, &evidencias, &votos, &certificado]);
    let recorte = (antes > tope).then_some((antes, despues));
    let (txs, testigos) = cola
        .into_iter()
        .chain(evidencias)
        .chain(votos)
        .chain(certificado)
        .unzip();
    Ok(CuerpoPostPresupuestado {
        txs,
        testigos,
        recorte,
    })
}

/// ECL-R2a-3 · Control del bucle tras procesar una `MsgProductor::Post` propia.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ControlPost {
    /// El bloque se atendió (admitido o rechazo legítimo ya respondido): seguir el bucle.
    Continuar,
    /// El productor pidió parar (límite alcanzado): salir del bucle.
    Parar,
    /// Eclipse detectado con la Post en vuelo: descartada sin responder; seguir con red/sync.
    Descartado,
}

/// ECL-R2a-4 · Control del bucle de régimen tras atender **un** mensaje del productor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ControlBucle {
    /// Seguir con la siguiente vuelta del bucle.
    Continuar,
    /// Salir del bucle (parada ordenada o canal del productor cerrado).
    Romper,
}

/// Candidata ya auditada para un único contexto; evita repetir la conversión PoAS al armar.
struct FuenteTransicionPreparada {
    candidata: SolucionCandidata,
    salida: [u8; 16],
    slot: u64,
    rango: u64,
}

impl FuenteSoluciones for FuenteTransicionPreparada {
    type Error = std::io::Error;

    fn soluciones(
        &self,
        salida: [u8; 16],
        slot: u64,
        rango: u64,
    ) -> Result<Vec<SolucionCandidata>, Self::Error> {
        if (salida, slot, rango) != (self.salida, self.slot, self.rango) {
            return Err(std::io::Error::other(
                "candidata de transición fuera de su contexto",
            ));
        }
        Ok(vec![self.candidata])
    }
}

/// Puente `FuenteSoluciones → ParcelaDisco` para el bloque de transición (decisión 6, `producir`).
pub(super) struct FuenteTransicion<'a> {
    pub(super) parcela: &'a ParcelaDisco,
    pub(super) historia: &'a HistoriaGenesis,
}

impl FuenteSoluciones for FuenteTransicion<'_> {
    type Error = zx_farmer::ErrorProductorPoas;

    fn soluciones(
        &self,
        salida: [u8; 16],
        slot: u64,
        rango: u64,
    ) -> Result<Vec<SolucionCandidata>, Self::Error> {
        let params = self.historia.params_pieza();
        let resultado = zx_farmer::productor_poas::convertir_candidatos_locales(
            self.parcela,
            salida,
            slot,
            rango,
            &params,
            self.historia,
            self.historia.erasure_coding(),
        )?;
        Ok(resultado
            .soluciones()
            .iter()
            .map(|c| SolucionCandidata {
                solucion: *c.solucion(),
                distancia: c.distancia(),
            })
            .collect())
    }
}

pub(super) fn pow_target_de(cabecera: &BlockHeader) -> Result<primitive_types::U256, ErrorNodo> {
    zx_core::decodificar_con(cabecera.bits, &PARAMETROS_POW_DEV.limites)
        .map_err(|e| ErrorNodo::Otro(format!("bits de la cabecera PoW: {e}")))
}

/// ¿Es una coinbase? Misma definición que el motor de transición
/// (`zx_consensus::transicion::aplicar::es_coinbase`): v1 sin entradas o v3. La plantilla PoW la
/// coloca en la primera posición; P2 la excluye de la expulsión y del conteo de transacciones que
/// disparan el rechazo no fatal.
pub(super) fn es_coinbase_pow(tx: &Tx) -> bool {
    (tx.version == 1 && tx.inputs.is_empty()) || tx.version == 3
}

/// P2 · Decisión pura de si un rechazo de un bloque **propio** es «por su cuerpo» (no fatal):
/// `Cadena::admitir` devolvió `ErrTransicion`, la clasificación no es legítima y el bloque lleva al
/// menos una transacción además de la coinbase.
///
/// Es exactamente la regla (a)∧(b)∧(c) de `ORDEN-MP1` §3. Si falta cualquiera de las tres, el
/// rechazo conserva la variante `BloquePropioRechazado` y sigue siendo fatal en `fase_pow`, salvo
/// la clasificación legítima, que ya tenía su camino propio.
#[must_use]
pub(super) fn es_rechazo_propio_por_cuerpo(
    motivo: &zx_cadena::MotivoBloque,
    clasificacion: crate::rechazo::ClasificacionRechazo,
    n_txs_sin_coinbase: usize,
) -> bool {
    matches!(motivo, zx_cadena::MotivoBloque::ErrTransicion(_))
        && !clasificacion.es_legitimo()
        && n_txs_sin_coinbase > 0
}

/// `ORDEN-W06d10-B`: ¿este error de la tubería de admisión de un bloque de **red** es un defecto
/// **demostrable del candidato** (penaliza al remitente) o un fallo/vista **local** (X1/X2/X3, se
/// ignora sin penalizar)?
///
/// - `BloquePropioRechazado` con clasificación que penaliza (`Legitimo`/`Interno`, incluidos los
///   defectos que antes llegaban como `ErrorNodo::Otro`: `bits`, `target`, `trabajo`, `peso`).
/// - `BloquePropioRechazadoPorTx` (P2, solo bloques propios en la práctica): un cuerpo rechazado
///   por la transición es un defecto atribuible al candidato, igual que `Interno`; si llegara por
///   esta ruta de red, penaliza.
/// - `RepeticionFallida`/`TestigoPowCorrupto` en la ruta en vivo: PoAS o testigo del candidato.
/// - Todo lo demás (`Otro` de persistencia/servicio/detector, `Almacen`, `Io`, …) es local.
#[must_use]
pub(super) fn error_atribuible_al_candidato(e: &ErrorNodo) -> bool {
    match e {
        ErrorNodo::BloquePropioRechazado { clasificacion, .. } => clasificacion.penaliza_en_red(),
        ErrorNodo::BloquePropioRechazadoPorTx { .. } => true,
        ErrorNodo::RepeticionFallida { .. } | ErrorNodo::TestigoPowCorrupto { .. } => true,
        _ => false,
    }
}

/// RLJ-3b §2.4: ¿el error es el límite de futuro del PoW (`C-TS-03`)? `VistaLocal` es la
/// clasificación de `ErrorPow::TimestampDemasiadoFuturo`, la única variante no permanente.
#[must_use]
pub(super) fn es_ftl_pow(e: &ErrorNodo) -> bool {
    matches!(
        e,
        ErrorNodo::BloquePropioRechazado {
            clasificacion: crate::rechazo::ClasificacionRechazo::VistaLocal,
            motivo,
            ..
        } if motivo.contains("C-TS-03")
    )
}

/// `PadresDag` a `Vec<BlockHash>` (seleccionado primero), para `BloquePost::padres`.
pub(super) fn padres_dag_a_vec(p: &PadresDag) -> Vec<BlockHash> {
    if p.es_genesis() {
        return Vec::new();
    }
    let mut v = vec![p.seleccionado()];
    v.extend_from_slice(p.extras());
    v
}

/// `RL-2d-2` · guarda de producción (decisión (b)): el nodo **no produce** un slot cuyo ajuste de
/// reloj no está comprometido.
///
/// `calendario` son los pares `(desde, N)` del `ServicioPot` de verificación. Si
/// [`perfil::PerfilRedConsenso::ajuste_exigido`] devuelve `desde` (el `desde` del ajuste que rige en
/// `slot`) y esa entrada no está en el calendario, el punto de finalidad todavía no alcanzó la
/// frontera `f = desde − A`: el `N` vigente es el viejo/dudoso y producir con él haría que la
/// admisión del propio bloque lo rechazara (`Pot(AesFallido)`, el fallo medido en RL-2d). En ese
/// caso se escribe el evento `reloj_n_no_comprometido` y se devuelve `Ok(false)`; el llamante no
/// produce ese slot. Sin ajuste exigible (o con la entrada presente) devuelve `Ok(true)`.
///
/// Separada del método para poder probarla sin construir un `Nodo` entero (mismo patrón que
/// `escribir_fallo_productor`).
///
/// # Errores
/// El de escritura del registro estructurado.
pub fn reloj_produccion_permitida(
    perfil: &perfil::PerfilRedConsenso,
    registro: &Registro,
    calendario: &[(u64, u64)],
    slot: u64,
) -> Result<bool, ErrorNodo> {
    if perfil.n_comprometido(calendario, slot) {
        return Ok(true);
    }
    if let Some(desde) = perfil.ajuste_exigido(slot) {
        let evento = registro
            .evento("reloj_n_no_comprometido")
            .u64("slot", slot)
            .u64("frontera", desde.saturating_sub(perfil.reloj.a_epoch))
            .u64("desde_exigido", desde)
            .u64("a_epoch", perfil.reloj.a_epoch);
        registro.escribir(evento, false)?;
    }
    Ok(false)
}

/// Texto del `motivo` del evento `firmante_abstenido` (esquema v1): el mismo para la abstención de
/// la transición (`producir_bloque_transicion`) y la del hilo productor de régimen.
pub(super) fn motivo_abstencion_texto(
    motivo: zx_post::productor::MotivoAbstencion,
) -> &'static str {
    match motivo {
        zx_post::productor::MotivoAbstencion::Conflicto { .. } => "conflicto",
        zx_post::productor::MotivoAbstencion::PerdidaRegistro { .. } => "perdida_registro",
    }
}

/// Familia de un bloque de red, para el registro (`pow`/`post`).
pub(super) fn familia_de(bloque: &BloqueRed) -> &'static str {
    match bloque {
        BloqueRed::Pow { .. } => "pow",
        BloqueRed::Post { .. } => "post",
    }
}

/// Tamaño en bytes de la serialización de red de un bloque (`ORDEN-W07a`).
pub(super) fn bytes_de(bloque: &BloqueRed) -> u64 {
    zx_p2p::codec::bloque_a_bytes(bloque).len() as u64
}

/// `w(SR)` (`U256`) a `u128` para `BloquePost::peso` (no debería desbordar con `SR_dev` de la red
/// dev; se trata como fallo fatal si ocurriera, no como truncamiento silencioso).
pub(super) fn peso_u128(bloque: &BloqueDag) -> Result<u128, ErrorNodo> {
    let peso = zx_dag::peso(bloque.cabecera.rango_solucion);
    u128::try_from(peso).map_err(|_| ErrorNodo::Otro(format!("peso {peso} no cabe en u128")))
}

/// `ORDEN-W06d8` decisión 3: escribe el evento crítico `fallo_productor` y devuelve el error fatal
/// correspondiente. Separado del método para poder probarlo por unidad sin construir un `Nodo`
/// entero. La salida ≠ 0 la garantiza `main` al recibir el `Err` de `ejecutar`.
pub(super) fn escribir_fallo_productor(registro: &Registro, motivo: &str) -> ResultadoNodo<()> {
    registro.escribir(
        registro.evento("fallo_productor").str("motivo", motivo),
        true,
    )?;
    Err(ErrorNodo::Otro(format!(
        "fallo del hilo productor: {motivo}"
    )))
}
