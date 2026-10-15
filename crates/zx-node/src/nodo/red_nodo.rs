//! Pieza N (MAP-1): red — difusión, peticiones, admisión de lo que llega y colas de pendientes.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    Almacen, Arc, BlockHash, BlockHeader, BloqueDag, BloqueRed, ErrorNodo, Estado, FaseRed,
    IdDiferido, Instant, Nodo, PARAMETROS_POW_DEV, PuntaPow, TrabajoRed, Tx, VeredictoFinal,
    VistaRed, error_atribuible_al_candidato, es_ftl_pow, perfil, red,
};

#[cfg(test)]
use super::{
    CONSULTAS_TABLA_PESOS, DIFUSIONES_AGREGADO, DIFUSIONES_TX_PROPIAS, DIFUSIONES_VOTO_SUBRED,
};

impl Nodo {
    /// RD-4b · P1: entrega al director la tabla de pesos certificados (`Cadena::productores_en_ventana`)
    /// **una** vez por cambio de ancla y como mucho cada `T_par`.
    ///
    /// No hace nada si: (a) no hay red o el registro firmado está apagado; (b) el ancla de votos es
    /// la última entregada; (c) no ha pasado `T_par` desde el último empuje. El tiempo entra como
    /// parámetro (`ahora`), **nunca** se lee aquí dentro: la decisión es determinista y las pruebas
    /// le pasan instantes controlados. `T_par` es el de la rotación del director
    /// (`PerfilRed::de(red).t_par`, `crates/zx-p2p/src/config.rs`). Como el ancla solo cambia cuando
    /// avanza la finalidad por votos —no en cada bloque—, la consulta no se paga por bloque.
    pub(super) fn entregar_tabla_pesos(&mut self, ahora: Instant) {
        let Some(red) = self.red.as_ref() else {
            return;
        };
        if !red.registro_activo() {
            return;
        }
        let Some(ancla) = self.cadena.ancla_votos() else {
            return;
        };
        let t_par = zx_p2p::config::PerfilRed::de(self.red_configurada).t_par;
        if let Some(ultimo) = &self.ultimo_empuje_pesos
            && (ultimo.ancla == Some(ancla) || ahora.duration_since(ultimo.momento) < t_par)
        {
            return;
        }
        #[cfg(test)]
        CONSULTAS_TABLA_PESOS.with(|c| c.set(c.get() + 1));
        let pesos = self
            .cadena
            .productores_en_ventana(crate::perfil::VENTANA_PESOS_BLOQUES)
            .into_iter()
            .collect::<Vec<_>>();
        let _ = red.fijar_tabla_pesos(pesos);
        self.ultimo_empuje_pesos = Some(UltimoEmpujePesos {
            ancla: Some(ancla),
            momento: ahora,
        });
    }

    /// Construye el saludo de red actual (`ORDEN-W06d2` decisión 4) a partir del estado propio.
    ///
    /// `blue_work_virtual` queda en cero: 0.0.1 no elige *fork choice* PoST por red (el bloqueo de
    /// `PROGRESO.md` sobre `JustificacionPot` impide verificar un PoST ajeno), así que ningún par
    /// decide todavía nada a partir de este campo. Se deja el tipo correcto para no romper el wire
    /// el día que se resuelva.
    pub(super) fn construir_estado_red(&self) -> Estado {
        #[expect(
            clippy::indexing_slicing,
            reason = "historial_pow siempre tiene al menos el génesis"
        )]
        let ultimo = self.historial_pow[self.historial_pow.len() - 1];
        let trabajo_be = self.trabajo_acumulado.to_big_endian();
        let mut puntas_post = self.cadena.tips_validas();
        puntas_post.truncate(zx_p2p::mensaje::MAX_PUNTAS_POST);
        Estado {
            // `RL-2c`: la identidad de red incluye el perfil (dev clásica vs dev-reloj), para que
            // dos perfiles distintos se desconecten en el saludo. La cadena real sigue siendo la
            // dev (`HASH_GENESIS_DEV`), validada en el arranque.
            hash_genesis: perfil::identidad_red(&self.perfil_red),
            red: self.red_configurada,
            fase: if self.cadena.terminal().is_some() {
                FaseRed::Post
            } else {
                FaseRed::Pow
            },
            punta_pow: PuntaPow {
                hash: ultimo.block_hash(),
                altura: ultimo.height,
                trabajo_acumulado: trabajo_be,
            },
            terminal: self.cadena.terminal(),
            puntas_post,
            blue_work_virtual: [0; 32],
            // `ORDEN-W06d6` decisión 1: longitud real del registro de admisión de la vista, no un
            // relleno — es lo que el par sincronizando compara contra su propio cursor.
            longitud_registro: self.vista_red.longitud_registro(),
        }
    }

    /// Difunde un bloque **propio** ya admitido, si hay red (decisión 2: solo **después** de
    /// persistirse, que ya ocurrió dentro de `admitir_pow_interno`/`admitir_post_interno` antes de
    /// que esta función pueda llamarse con su hash). Se relee de [`VistaRed`] en vez de repetir la
    /// construcción del `BloqueRed`: es el mismo valor exacto que ya se guardó allí al admitir.
    pub(super) fn difundir_si_hay_red(&self, hash: BlockHash) {
        let Some(red) = self.red.as_ref() else {
            return;
        };
        let Some(bloque) = self.vista_red.bloques_por_hash(&[hash]).into_iter().next() else {
            tracing::error!(%hash, "bloque propio recién admitido sin instantánea en VistaRed");
            return;
        };
        if let Err(e) = red.difundir_bloque(&bloque) {
            tracing::warn!(%hash, %e, "no se pudo difundir un bloque propio");
        }
    }

    /// Difunde una transacción **propia** ya serializada (`tx_a_bytes`) por el tema de tx, si hay
    /// red (`ORDEN-TX3`, TX-R-01). El nodo la publica después de admitirla en su mempool, para que
    /// otro productor pueda incluirla (relevo).
    ///
    /// ECL-R2b-3 · Devuelve el resultado **real** de la publicación (`Err("sin_red")` /
    /// `Err("error_difusion")`): el llamante no debe confundir «intentado» con «publicado».
    pub(super) fn difundir_tx_si_hay_red(&self, bytes: &[u8]) -> Result<(), &'static str> {
        #[cfg(test)]
        DIFUSIONES_TX_PROPIAS.with(|c| c.set(c.get().saturating_add(1)));
        let Some(red) = self.red.as_ref() else {
            return Err("sin_red");
        };
        red.difundir_tx(bytes).map_err(|e| {
            tracing::warn!(%e, "no se pudo difundir una transacción propia");
            "error_difusion"
        })
    }

    /// A5-c-2b · X3 · Difunde un **voto de red** por el tema de **su** subred, si hay red.
    ///
    /// El contador de prueba se incrementa antes de mirar la red: así una prueba del nodo puede
    /// comprobar que el voto se encamina por la subred aunque el nodo de prueba no tenga red real.
    pub(super) fn difundir_voto_subred_si_hay_red(&self, subred: u16, bytes: &[u8]) {
        #[cfg(test)]
        DIFUSIONES_VOTO_SUBRED.with(|c| c.set(c.get().saturating_add(1)));
        let Some(red) = self.red.as_ref() else {
            return;
        };
        let Ok(s) = u8::try_from(subred) else {
            return;
        };
        if let Err(e) = red.difundir_voto_subred(s, bytes) {
            tracing::debug!(%e, "no se pudo difundir un voto de red por su subred");
        }
    }

    /// A5-c-2b · X6 · Difunde un **agregado propio** por el tema de agregados, si hay red.
    pub(super) fn difundir_agregado_si_hay_red(&self, bytes: &[u8]) {
        #[cfg(test)]
        DIFUSIONES_AGREGADO.with(|c| c.set(c.get().saturating_add(1)));
        let Some(red) = self.red.as_ref() else {
            return;
        };
        if let Err(e) = red.difundir_agregado(bytes) {
            tracing::debug!(%e, "no se pudo difundir un agregado propio");
        }
    }

    /// ECL-R2a-4 · Entrega una `Peticion` al camino de red **real** y devuelve si el encolado fue
    /// aceptado. `true` acredita solo que el bucle de red aceptó el comando en su cola; no demuestra
    /// entrega del bloque, ni que el par lo recibiera, ni ausencia.
    pub(super) fn enviar_peticion(
        &mut self,
        par: libp2p::PeerId,
        peticion: zx_p2p::mensaje::Peticion,
    ) -> bool {
        let Some(red) = self.red.as_ref() else {
            return false;
        };
        red.runtime
            .block_on(red.manejo.pedir(par, peticion))
            .is_ok()
    }

    pub(super) fn resolver_huerfanos_de(&mut self, padre: BlockHash) {
        for (hijo, bloque) in self.huerfanos.tomar_para_padre(&padre) {
            let _ = self.intentar_admitir_bloque_red(&bloque, None, Instant::now());
            // Sin `IdDiferido` que informar (no llegó por gossipsub en este turno): el único rastro
            // es el registro. La retransmisión de un huérfano que ahora prospera queda pendiente
            // (límite conocido, ver `PROGRESO.md`): difundirlo exigiría reconstruir un `IdDiferido`
            // que no existe para un bloque que nunca pasó por `report_message_validation_result`.
            let evento = self
                .registro
                .evento("huerfano_resuelto")
                .str("hash", &hijo.to_string());
            let _ = self.registro.escribir(evento, false);
        }
    }

    /// Drena, sin bloquear, el trabajo que el manejador de red encoló (decisión 1). Se llama desde
    /// los bucles de `fase_pow`/`fase_regimen`: el hilo de consenso es el único que muta
    /// `zx-cadena`/`zx-storage` (D-N07), así que la admisión de red ocurre aquí, intercalada con la
    /// propia producción, nunca en el hilo asíncrono de `zx-p2p`.
    pub(super) fn procesar_trabajo_red_pendiente(&mut self) {
        // Se saca el receptor de `self` temporalmente: `intentar_admitir_bloque_red` necesita
        // `&mut self` completo (muta `cadena`, `almacen`, `huerfanos`...) y el propio receptor vive
        // dentro de `self.trabajo_red`, así que no se puede tomar prestado a la vez.
        let Some(mut receptor) = self.trabajo_red.take() else {
            return;
        };
        // A5-c-2b · X5 · se drena la cola de una vez para poder juntar **todos** los agregados de la
        // vuelta en un solo lote, sin reordenar el resto del trabajo.
        let mut trabajos: Vec<TrabajoRed> = Vec::new();
        loop {
            match receptor.try_recv() {
                Ok(t) => trabajos.push(t),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                // El hilo de consenso ya no existe: no hay a quién entregarle nada más.
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
            }
        }
        let mut lote_agregados: Vec<(IdDiferido, Vec<u8>)> = Vec::new();
        for trabajo in trabajos {
            match trabajo {
                TrabajoRed::BloqueDifundido {
                    id,
                    bloque,
                    llegada,
                } => {
                    // Gossipsub no dice quién lo propagó a este nivel (`ManejadorEntrante` no lo
                    // expone); si resulta huérfano, no hay a quién pedirle el padre directamente.
                    self.registrar_bloque_recibido(&bloque, None);
                    let veredicto = self.intentar_admitir_bloque_red(&bloque, None, llegada);
                    if let Some(red) = self.red.as_ref() {
                        red.informar_validacion(id, veredicto);
                    }
                    // VNT-R2 · punto completo: el motor atiende las fronteras verificadas antes de
                    // consumir el siguiente trabajo del lote.
                    if let Err(e) = self.atender_fronteras_votos() {
                        tracing::warn!(%e, "fronteras de votos tras admisión de red");
                    }
                }
                TrabajoRed::BloqueDeSincronizacion {
                    de,
                    bloque,
                    llegada,
                } => {
                    self.registrar_bloque_recibido(&bloque, Some(de));
                    let veredicto = self.intentar_admitir_bloque_red(&bloque, Some(de), llegada);
                    // Un bloque de sincronización demostrablemente inválido sí penaliza: no pasó
                    // por gossipsub (no hay `report_message_validation_result` que llame a esto),
                    // así que la única forma de aplicar C-NET-05/C-EVP es desconectar aquí.
                    if veredicto == VeredictoFinal::Rechazar
                        && let Some(red) = self.red.as_ref()
                    {
                        // `ORDEN-W07a`: única penalización que el nodo decide y puede trazar (la de
                        // gossipsub la aplica `zx-p2p` sin exponer el propagador a `zx-node`).
                        let evento = self
                            .registro
                            .evento("par_penalizado")
                            .str("par", &de.to_string())
                            .str("motivo", "bloque de sincronización rechazado")
                            .str("accion", "expulsion");
                        let _ = self.registro.escribir(evento, false);
                        red.desconectar(de, zx_p2p::error::MotivoDesconexion::ViolacionDeConsenso);
                    }
                    // VNT-R2 · punto completo, también por el camino de sincronización.
                    if let Err(e) = self.atender_fronteras_votos() {
                        tracing::warn!(%e, "fronteras de votos tras sincronización");
                    }
                }
                // FV-4b-N1 · sobre de voto/certificado por el tema global: X3b lo deja muerto; el
                // manejador honesto ya no encola esta variante, pero si apareciera se entrega al
                // motor por el camino de siempre.
                TrabajoRed::VotoDifundido { bytes, .. } => {
                    self.procesar_voto_de_red(&bytes);
                }
                // A5-c-2b · X4 · voto de subred: se entrega al motor y se contesta a la red.
                TrabajoRed::VotoSubredDifundido { id, subred, bytes } => {
                    self.procesar_voto_subred(id, subred, &bytes);
                }
                // A5-c-2b · X5 · los agregados se acumulan para llamar **una vez** al motor.
                TrabajoRed::AgregadoDifundido { id, bytes } => {
                    lote_agregados.push((id, bytes));
                }
            }
        }
        if !lote_agregados.is_empty() {
            self.procesar_agregados_lote(&lote_agregados);
        }
        self.trabajo_red = Some(receptor);
    }

    /// Decide y aplica el veredicto de un bloque llegado por red (gossip o sincronización), sin
    /// propagar nunca un error fatal: a diferencia de un bloque **propio** (decisión 4 general de
    /// `ORDEN-W06d1`), un bloque ajeno inválido es un evento normal de la red, no un bug del nodo.
    ///
    /// `origen`: el par que lo mandó, si se conoce (sincronización) — se usa **solo** para pedirle
    /// directamente un padre que falte; nunca para decidir el veredicto del propio bloque.
    pub(super) fn intentar_admitir_bloque_red(
        &mut self,
        bloque: &BloqueRed,
        origen: Option<libp2p::PeerId>,
        llegada: Instant,
    ) -> VeredictoFinal {
        // ECL-R2a-2 · D5: recuerda el último par que entregó un bloque para pedirle el candidato
        // ausente del ancla (mismo `Peticion::Bloques` que la sincronización de huérfanos).
        self.par_sync = origen;
        let veredicto = match bloque {
            BloqueRed::Pow {
                cabecera,
                txs,
                testigos,
            } => self.intentar_admitir_pow_de_red(
                *cabecera,
                txs.clone(),
                testigos.clone(),
                origen,
                llegada,
            ),
            BloqueRed::Post {
                cabecera,
                justificacion,
                txs,
                testigos,
            } => self.intentar_admitir_post_de_red(
                *cabecera,
                justificacion.clone(),
                txs.clone(),
                testigos.clone(),
                origen,
                llegada,
            ),
        };
        if veredicto == VeredictoFinal::Aceptar {
            // `ORDEN-TX3` TX-R-24/33: las transacciones del bloque admitido salen de la mempool.
            let (txs, testigos) = match bloque {
                BloqueRed::Pow { txs, testigos, .. } | BloqueRed::Post { txs, testigos, .. } => {
                    (txs, testigos)
                }
            };
            self.actualizar_mempool_tras_bloque_con_recibo(
                red::hash_de(bloque),
                txs,
                testigos,
                origen,
            );
        }
        veredicto
    }

    fn intentar_admitir_pow_de_red(
        &mut self,
        cabecera: BlockHeader,
        txs: Vec<Tx>,
        testigos: Vec<Vec<Vec<u8>>>,
        origen: Option<libp2p::PeerId>,
        llegada: Instant,
    ) -> VeredictoFinal {
        let hash = cabecera.block_hash();
        if self.cadena.es_valido(&hash) {
            return VeredictoFinal::Ignorar; // ya lo teníamos: nada que hacer, no penaliza.
        }
        if let Some(motivo) = self.cadena.motivo(&hash) {
            // `ORDEN-W06d10-B`: un motivo cacheado que depende de la vista local (X2,
            // `ErrLimiteTerminales`) no se convierte en `Rechazar`. Se ignora sin penalizar y se
            // traza; un motivo demostrable del candidato sigue penalizando igual.
            if !crate::rechazo::clasificar_motivo_bloque(motivo).penaliza_en_red() {
                self.trazar_bloque_vista_local(
                    &hash,
                    "pow",
                    &format!("motivo cacheado no penalizable: {motivo}"),
                    llegada,
                );
                return VeredictoFinal::Ignorar;
            }
            return VeredictoFinal::Rechazar; // ya sabíamos que es inválido.
        }
        if cabecera.height == 0 {
            // Un génesis declarado por red nunca sustituye al nuestro (ya comprobado contra
            // `HASH_GENESIS_DEV` al arrancar): no es demostrablemente inválido en sí mismo (podría
            // ser el génesis real, coincidiendo), así que no penaliza.
            return VeredictoFinal::Ignorar;
        }

        let padre = cabecera.prev_hash;
        let padre_conocido = self.cadena.es_valido(&padre) || self.cadena.motivo(&padre).is_some();
        if !padre_conocido {
            let bloque = BloqueRed::Pow {
                cabecera,
                txs,
                testigos,
            };
            let hijo = red::hash_de(&bloque);
            for d in self.huerfanos.insertar(padre, hijo, bloque) {
                let evento = self
                    .registro
                    .evento("huerfano_desalojado")
                    .str("hash", &d.hijo.to_string())
                    .str("motivo", "desalojado por cupo del depósito de huérfanos");
                let _ = self.registro.escribir(evento, false);
            }
            let mut evento = self
                .registro
                .evento("bloque_red_huerfano")
                .str("hash", &hash.to_string())
                .str("familia", "pow")
                .lista_str("padres_ausentes", &[padre.to_string()]);
            if let Some(par) = origen {
                evento = evento.str("par", &par.to_string());
            }
            let _ = self.registro.escribir(evento, false);
            if let (Some(red), Some(peer)) = (self.red.as_ref(), origen) {
                red.pedir(
                    peer,
                    zx_p2p::mensaje::Peticion::Bloques {
                        hashes: vec![padre],
                    },
                );
            }
            return VeredictoFinal::Ignorar;
        }
        if !self.cadena.es_valido(&padre) {
            // `ORDEN-W06d10-B` decisión 4: si el motivo cacheado del padre depende de **nuestra**
            // vista local (X2), el hijo no es demostrablemente inválido — hereda una invalidación
            // que otro nodo con otra rama lateral no haría. Se ignora sin penalizar.
            if self
                .cadena
                .motivo(&padre)
                .is_some_and(|m| !crate::rechazo::clasificar_motivo_bloque(m).penaliza_en_red())
            {
                self.trazar_bloque_vista_local(
                    &hash,
                    "pow",
                    "padre conocido con motivo de vista local",
                    llegada,
                );
                return VeredictoFinal::Ignorar;
            }
            // El padre es conocido y definitivamente inválido: este bloque no puede ser válido.
            let mut evento = self
                .registro
                .evento("bloque_red_rechazado")
                .str("hash", &hash.to_string())
                .str("familia", "pow")
                .str("etapa", "admision")
                .str("motivo", "padre conocido e inválido")
                .u64("t_hasta_rechazo_ns", llegada.elapsed().as_nanos() as u64);
            if let Some(par) = origen {
                evento = evento.str("par", &par.to_string());
            }
            let _ = self.registro.escribir(evento, false);
            return VeredictoFinal::Rechazar;
        }
        // `ORDEN-W06d3` decisión 3: ya no se exige que el padre sea `historial_pow.last()`.
        // `admitir_pow_interno` calcula el contexto de validación (target, altura, timestamp) a
        // partir del padre **declarado** (`Self::historial_hasta`), así que un bloque que extiende
        // un padre admitido y válido que no es la punta actual es una bifurcación PoW real y se
        // admite con su propio contexto correcto, nunca con el de otra rama. Si tras admitirlo
        // resulta ser la rama más pesada, `Self::actualizar_seleccion_pow` conmuta la punta
        // seleccionada (con la profundidad de la reorganización registrada).
        let indice = self.almacen.longitud_registro().unwrap_or(0);
        // `ORDEN-W07a`: `bytes` (tamaño de la serialización de red) y `altura` se capturan antes de
        // que `cabecera`/`txs`/`testigos` se muevan a la tubería de admisión.
        let altura = cabecera.height;
        let ts_para_reintento = i64::try_from(cabecera.timestamp).unwrap_or(i64::MAX);
        let bloque_para_reintento = BloqueRed::Pow {
            cabecera,
            txs: txs.clone(),
            testigos: testigos.clone(),
        };
        let bytes = zx_p2p::codec::bloque_a_bytes(&bloque_para_reintento).len() as u64;
        match self.admitir_pow_interno(cabecera, txs, testigos, indice, true, false) {
            Ok(()) => {
                // V9: este evento **solo** se escribe después de que `admitir_pow_interno` terminó
                // la tubería completa (cabecera, PoW, motor de transición, persistencia): nunca
                // antes. Es la traza que V9 exige comprobar.
                let mut evento = self
                    .registro
                    .evento("bloque_red_admitido")
                    .str("hash", &hash.to_string())
                    .str("familia", "pow")
                    .u64("altura", u64::from(altura))
                    .u64("bytes", bytes)
                    .u64("t_cabecera_ns", self.medicion.cabecera_ns)
                    .u64("t_admision_ns", self.medicion.admision_ns)
                    .u64("t_persistencia_ns", self.medicion.persistencia_ns)
                    .u64("t_total_ns", llegada.elapsed().as_nanos() as u64)
                    .u64("n_bloques_dag", self.cadena.bloques_admitidos());
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                VeredictoFinal::Aceptar
            }
            Err(e) => {
                // RLJ-3b §2.4: un PoW que solo falla el límite de futuro (`C-TS-03`, no permanente)
                // no se pierde: se retiene en su propia cola y se reintenta por tiempo.
                if es_ftl_pow(&e) {
                    let ftl = PARAMETROS_POW_DEV.ftl().unwrap_or(0);
                    let vence = ts_para_reintento.saturating_sub(ftl);
                    self.encolar_pow_pendiente(
                        bloque_para_reintento,
                        llegada,
                        crate::pendientes::MotivoEspera::Ftl { vence },
                    );
                    self.trazar_bloque_vista_local(&hash, "pow", &e.to_string(), llegada);
                    return VeredictoFinal::Ignorar;
                }
                // `ORDEN-W06d10-B`: solo un defecto **atribuible al candidato** penaliza. Un fallo
                // local (X3: persistencia/servicio) o una clasificación de vista local (X1) se
                // ignoran sin penalizar y se trazan con su motivo.
                if !error_atribuible_al_candidato(&e) {
                    self.trazar_bloque_vista_local(&hash, "pow", &e.to_string(), llegada);
                    return VeredictoFinal::Ignorar;
                }
                let mut evento = self
                    .registro
                    .evento("bloque_red_rechazado")
                    .str("hash", &hash.to_string())
                    .str("familia", "pow")
                    .str("etapa", self.medicion.etapa)
                    .str("motivo", &e.to_string())
                    .u64("t_hasta_rechazo_ns", llegada.elapsed().as_nanos() as u64);
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                VeredictoFinal::Rechazar
            }
        }
    }

    /// Decide y aplica el veredicto de un bloque PoST llegado por red (`ORDEN-W06d3` decisión 2).
    ///
    /// Con `BloqueRed::Post` llevando ya `JustificacionPot` (decisión 1), la tubería única
    /// (`Self::admitir_post_interno`, `verificar = true`) puede verificar de verdad la cabecera
    /// conjunta (PoT, PoAS, sello) y los padres de un bloque ajeno. Antes de eso: si no hay terminal
    /// todavía, el bloque no es juzgable (`Ignorar`, la falta es de fase, no del par); si algún padre
    /// declarado (salvo el terminal, que siempre vale como padre del bloque de transición) no se
    /// conoce, se deposita como huérfano y se pide, igual que en la ruta PoW.
    fn intentar_admitir_post_de_red(
        &mut self,
        cabecera: zx_core::preimage::dag::DagBlockHeader,
        justificacion: zx_core::wire_dag::JustificacionPot,
        txs: Vec<Tx>,
        testigos: Vec<Vec<Vec<u8>>>,
        origen: Option<libp2p::PeerId>,
        llegada: Instant,
    ) -> VeredictoFinal {
        let hash = cabecera.block_hash();
        if self.cadena.es_valido(&hash) {
            return VeredictoFinal::Ignorar; // ya lo teníamos: nada que hacer, no penaliza.
        }
        if let Some(motivo) = self.cadena.motivo(&hash) {
            // `ORDEN-W06d10-B`: X2 (`ErrLimiteTerminales`) cacheado no se reconvierte en `Rechazar`;
            // se ignora sin penalizar. Un motivo demostrable del candidato sigue igual.
            if !crate::rechazo::clasificar_motivo_bloque(motivo).penaliza_en_red() {
                self.trazar_bloque_vista_local(
                    &hash,
                    "post",
                    &format!("motivo cacheado no penalizable: {motivo}"),
                    llegada,
                );
                return VeredictoFinal::Ignorar;
            }
            return VeredictoFinal::Rechazar; // ya sabíamos que es inválido.
        }
        // `ORDEN-W06d7`: ya no hace falta un único terminal seleccionado para juzgar un bloque PoST
        // de red — puede declarar como padre **cualquier** terminal candidato conocido (el suyo, no
        // necesariamente el que este nodo tiene seleccionado hoy). Sin ningún candidato todavía
        // (fase PoW pura), no hay `ServicioPot` ni GHOSTDAG con los que verificar nada: no es
        // demostrablemente inválido (podríamos cruzar el corte nosotros mismos en breve),
        // `Ignorar`, no `Rechazar`.
        if self.cadena.terminal_candidatos().is_empty() {
            let evento = self
                .registro
                .evento("bloque_post_de_red_sin_terminal")
                .str("hash", &hash.to_string());
            let _ = self.registro.escribir(evento, false);
            return VeredictoFinal::Ignorar;
        }
        let candidatos = self.cadena.terminal_candidatos();

        let bloque_red = BloqueRed::Post {
            cabecera,
            justificacion: justificacion.clone(),
            txs: txs.clone(),
            testigos: testigos.clone(),
        };
        for padre in red::padres_declarados(&bloque_red) {
            if candidatos.contains(&padre) {
                continue; // cualquier terminal candidato conocido es un padre válido y conocido.
            }
            let padre_conocido =
                self.cadena.es_valido(&padre) || self.cadena.motivo(&padre).is_some();
            if !padre_conocido {
                // `ORDEN-W06d6` decisión 1: mientras este nodo va muy por detrás de algún par
                // conocido (`VistaRed::sincronizando`), un huérfano PoST llegado por **gossip**
                // (`origen.is_none()`: no sabemos de quién pedir el padre directamente) no se
                // deposita — la sincronización por registro lo traerá en su momento, en orden
                // causal, sin que este nodo tenga que resolver huérfanos de uno en uno mientras la
                // red sigue produciendo (la causa raíz de V5/V6(b), `REVISION-W06d5.md`). Un
                // huérfano de **sincronización** (`origen.is_some()`, llegó como respuesta a una
                // petición nuestra) sigue depositándose igual: es la resolución por padres para los
                // huecos pequeños que la propia decisión 1 conserva.
                if origen.is_none() && self.vista_red.sincronizando() {
                    let evento = self
                        .registro
                        .evento("bloque_post_gossip_descartado_sincronizando")
                        .str("hash", &hash.to_string())
                        .str("padre_ausente", &padre.to_string());
                    let _ = self.registro.escribir(evento, false);
                    return VeredictoFinal::Ignorar;
                }
                for d in self.huerfanos.insertar(padre, hash, bloque_red) {
                    let evento = self
                        .registro
                        .evento("huerfano_desalojado")
                        .str("hash", &d.hijo.to_string())
                        .str("motivo", "desalojado por cupo del depósito de huérfanos");
                    let _ = self.registro.escribir(evento, false);
                }
                let mut evento = self
                    .registro
                    .evento("bloque_red_huerfano")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .lista_str("padres_ausentes", &[padre.to_string()]);
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                if let (Some(red), Some(peer)) = (self.red.as_ref(), origen) {
                    red.pedir(
                        peer,
                        zx_p2p::mensaje::Peticion::Bloques {
                            hashes: vec![padre],
                        },
                    );
                }
                return VeredictoFinal::Ignorar;
            }
            if !self.cadena.es_valido(&padre) {
                // `ORDEN-W06d10-B` decisión 4: si el motivo cacheado del padre depende de nuestra
                // vista local (X2), el hijo no es demostrablemente inválido. `Ignorar` sin penalizar.
                if self
                    .cadena
                    .motivo(&padre)
                    .is_some_and(|m| !crate::rechazo::clasificar_motivo_bloque(m).penaliza_en_red())
                {
                    self.trazar_bloque_vista_local(
                        &hash,
                        "post",
                        "padre conocido con motivo de vista local",
                        llegada,
                    );
                    return VeredictoFinal::Ignorar;
                }
                let mut evento = self
                    .registro
                    .evento("bloque_red_rechazado")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .str("etapa", "admision")
                    .str("motivo", "padre conocido e inválido")
                    .u64("t_hasta_rechazo_ns", llegada.elapsed().as_nanos() as u64);
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                return VeredictoFinal::Rechazar;
            }
        }

        let bloque_dag = match BloqueDag::nuevo(cabecera, justificacion, txs, testigos) {
            Ok(b) => b,
            Err(e) => {
                let mut evento = self
                    .registro
                    .evento("bloque_red_rechazado")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .str("etapa", "decodificacion")
                    .str("motivo", &format!("forma: {e}"))
                    .u64("t_hasta_rechazo_ns", llegada.elapsed().as_nanos() as u64);
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                return VeredictoFinal::Rechazar;
            }
        };
        let indice = self.almacen.longitud_registro().unwrap_or(0);
        // `ORDEN-W07a`: tamaño de red y nº de padres del bloque, antes de admitirlo.
        let n_padres = red::padres_declarados(&bloque_red).len() as u64;
        let bytes = zx_p2p::codec::bloque_a_bytes(&bloque_red).len() as u64;
        // Aviso del director (`ORDEN-W06d5`, tras el hallazgo de V5): la simplificación que
        // trataba `Invalida` y `Pendiente` como el mismo `Rechazar` (declarada en `W06d4`) es un
        // bug real, no solo una simplificación — el mismo riesgo que RI-2a. `Pot(PasadoIncompleto)`
        // es un hueco **local** del `ServicioPot` de verificación (un nodo que sincroniza fuera de
        // orden), no un defecto demostrado del candidato: cachearlo como inválido lo perdería para
        // siempre, y `Rechazar` penaliza (incluso desconecta, `TrabajoRed::BloqueDeSincronizacion`
        // más abajo) a un par honesto por nuestro propio retraso. Ahora se usa la clasificación
        // tipada (`crate::rechazo`, decisión 3): `Pendiente` ⇒ `Ignorar` + se reencola para
        // reintentar cuando el pasado avance (`Self::reintentar_post_pendientes`); el resto, igual
        // que antes.
        let bloque_para_reintento = bloque_dag.clone();
        match self.admitir_post_interno(bloque_dag, indice, true) {
            Ok(()) => {
                // V9: este evento **solo** se escribe después de que `admitir_post_interno` terminó
                // la tubería completa (cabecera conjunta, PoAS, motor de transición, persistencia):
                // nunca antes.
                let mut evento = self
                    .registro
                    .evento("bloque_red_admitido")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .u64("slot", bloque_para_reintento.cabecera.slot)
                    .u64("n_padres", n_padres)
                    .u64("bytes", bytes)
                    .u64("t_cabecera_ns", self.medicion.cabecera_ns)
                    .u64("t_admision_ns", self.medicion.admision_ns)
                    .u64("t_persistencia_ns", self.medicion.persistencia_ns)
                    .u64("t_total_ns", llegada.elapsed().as_nanos() as u64)
                    .u64("n_bloques_dag", self.cadena.bloques_admitidos());
                if let Some((azules, rojos)) = self.cadena.mergeset_de(&hash) {
                    evento = evento
                        .u64("azules_mergeset", azules)
                        .u64("rojos_mergeset", rojos);
                }
                let txs_descartadas = self.cadena.descartes(&hash).map_or(0, |d| d.len() as u64);
                evento = evento.u64("txs_descartadas", txs_descartadas);
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                self.reintentar_post_pendientes();
                VeredictoFinal::Aceptar
            }
            Err(ErrorNodo::BloquePropioRechazado {
                motivo,
                clasificacion,
                ..
            }) if clasificacion.es_pendiente() => {
                // `ORDEN-W07a` §1 bis: evento de diagnóstico restaurado (el bloque no es rechazo
                // demostrable ni huérfano de un padre concreto; se reintenta más tarde).
                let evento = self
                    .registro
                    .evento("bloque_red_pendiente")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .str("motivo", &motivo)
                    .str("veredicto", "Ignorar (reintento encolado)");
                let _ = self.registro.escribir(evento, false);
                let motivo_espera = self.motivo_espera_post(&bloque_para_reintento, &motivo);
                self.encolar_post_pendiente_con(bloque_para_reintento, llegada, motivo_espera);
                VeredictoFinal::Ignorar
            }
            // `ORDEN-W06d10-B` X2: `ErrLimiteTerminales` (tope local de terminales) llega aquí ya
            // clasificado como `VistaLocal`. No se penaliza, no se desconecta y queda visible con su
            // motivo en el evento de diagnóstico `bloque_red_vista_local`.
            Err(ErrorNodo::BloquePropioRechazado {
                motivo,
                clasificacion,
                ..
            }) if clasificacion.es_vista_local() => {
                self.trazar_bloque_vista_local(&hash, "post", &motivo, llegada);
                VeredictoFinal::Ignorar
            }
            // `ORDEN-W06d6`, RI-3c H2: `PruebaPotIncoherente`/`RangoSinAtadura` no se reintentan
            // (a diferencia de `Pendiente`, el hueco no se va a llenar solo) pero tampoco penalizan
            // al remitente (a diferencia del resto de rechazos): no hay certeza de que el defecto
            // sea suyo y no nuestro. `VeredictoFinal::Ignorar` es exactamente "se descarta sin
            // penalizar".
            Err(ErrorNodo::BloquePropioRechazado {
                motivo,
                clasificacion,
                ..
            }) if !clasificacion.penaliza_en_red() => {
                // `ORDEN-W07a` §1 bis: se conserva el evento de diagnóstico original.
                let evento = self
                    .registro
                    .evento("bloque_red_ignorado_sin_penalizar")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .str("motivo", &motivo);
                let _ = self.registro.escribir(evento, false);
                // Y el bloque queda descartado, con su traza de rechazo del §1 (etapa `cabecera`).
                let mut evento = self
                    .registro
                    .evento("bloque_red_rechazado")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .str("etapa", self.medicion.etapa)
                    .str("motivo", &motivo)
                    .u64("t_hasta_rechazo_ns", llegada.elapsed().as_nanos() as u64);
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                VeredictoFinal::Ignorar
            }
            Err(e) => {
                // `ORDEN-W06d10-B`: un fallo local (X3) se ignora sin penalizar y se traza; solo un
                // defecto atribuible al candidato (p. ej. PoAS inválido, `RepeticionFallida`) sigue
                // siendo `Rechazar`.
                if !error_atribuible_al_candidato(&e) {
                    self.trazar_bloque_vista_local(&hash, "post", &e.to_string(), llegada);
                    return VeredictoFinal::Ignorar;
                }
                let mut evento = self
                    .registro
                    .evento("bloque_red_rechazado")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .str("etapa", self.medicion.etapa)
                    .str("motivo", &e.to_string())
                    .u64("t_hasta_rechazo_ns", llegada.elapsed().as_nanos() as u64);
                if let Some(par) = origen {
                    evento = evento.str("par", &par.to_string());
                }
                let _ = self.registro.escribir(evento, false);
                VeredictoFinal::Rechazar
            }
        }
    }

    /// Encola un bloque PoST de red que quedó `Pendiente` (decisión 3 extendida). La pieza N
    /// ([`crate::pendientes`]) acota la cola, no admite duplicados y desaloja al más antiguo. Esta
    /// forma de dos argumentos conserva la que usan las pruebas de la cola; la ruta de red usa
    /// [`Self::encolar_post_pendiente_con`] con el motivo real.
    #[cfg(test)]
    pub(super) fn encolar_post_pendiente(&mut self, bloque: BloqueDag, llegada: Instant) {
        self.encolar_post_pendiente_con(bloque, llegada, crate::pendientes::MotivoEspera::Contexto);
    }

    /// Encola con el motivo de espera explícito: `Ftl` si solo falla el límite de futuro
    /// (`timestamp(B) − FTL`), `Contexto` si falta un ancestro o el segundo VDF.
    pub(super) fn encolar_post_pendiente_con(
        &mut self,
        bloque: BloqueDag,
        llegada: Instant,
        motivo: crate::pendientes::MotivoEspera,
    ) {
        let hash = bloque.cabecera.block_hash();
        self.post_pendientes.encolar(bloque, hash, llegada, motivo);
    }

    /// Motivo de espera de un PoST `Pendiente` a partir del motivo del error de admisión.
    fn motivo_espera_post(
        &self,
        bloque: &BloqueDag,
        motivo: &str,
    ) -> crate::pendientes::MotivoEspera {
        if motivo.starts_with(PREFIJO_FTL_POST) {
            let ftl = self.perfil_red.timestamp.ftl;
            let vence = i64::try_from(bloque.cabecera.timestamp)
                .map_or(i64::MIN, |t| t.saturating_sub(ftl));
            crate::pendientes::MotivoEspera::Ftl { vence }
        } else {
            crate::pendientes::MotivoEspera::Contexto
        }
    }

    /// Encola un PoW de red retenido por `FTL` en su propia cola (RLJ-3b §2.4).
    fn encolar_pow_pendiente(
        &mut self,
        bloque: BloqueRed,
        llegada: Instant,
        motivo: crate::pendientes::MotivoEspera,
    ) {
        let hash = red::hash_de(&bloque);
        self.pow_pendientes.encolar(bloque, hash, llegada, motivo);
    }

    /// Reintenta los bloques PoST pendientes **por contexto** (decisión 3 extendida, aviso del
    /// director tras V5): el `ServicioPot` de verificación pudo completar el hueco que los frenaba
    /// desde la última admisión. Los que sigan `Pendiente` vuelven a la cola; los que ahora sean
    /// demostrablemente inválidos (o una violación interna) se descartan **sin** penalizar — el
    /// remitente original ya no está atado a este intento.
    pub(super) fn reintentar_post_pendientes(&mut self) {
        for p in self.post_pendientes.tomar_contexto() {
            self.reintentar_un_post_pendiente(p);
        }
    }

    /// Disparador por tiempo (RLJ-3b §2.2): en cada vuelta del bucle, si el reloj local alcanzó el
    /// vencimiento `FTL` más temprano, reintenta **solo** los pendientes vencidos (PoST y PoW). Sin
    /// pendientes vencidos cuesta una comparación.
    pub(super) fn reintentar_pendientes_por_reloj(&mut self) {
        let ahora = self.reloj_local();
        if self.post_pendientes.hay_vencidos(ahora) {
            for p in self.post_pendientes.tomar_vencidos(ahora) {
                self.reintentar_un_post_pendiente(p);
            }
        }
        if self.pow_pendientes.hay_vencidos(ahora) {
            for p in self.pow_pendientes.tomar_vencidos(ahora) {
                self.reintentar_un_pow_pendiente(p);
            }
        }
    }

    /// Reintenta un PoST pendiente concreto y lo reencola si vuelve a quedar `Pendiente`.
    fn reintentar_un_post_pendiente(&mut self, p: crate::pendientes::Pendiente<BloqueDag>) {
        let llegada = p.llegada();
        let bloque = p.en_bloque();
        let hash = bloque.cabecera.block_hash();
        let indice = self.almacen.longitud_registro().unwrap_or(0);
        let n_padres = {
            let p = &bloque.cabecera.padres;
            if p.es_genesis() {
                0
            } else {
                (1 + p.extras().len()) as u64
            }
        };
        let bytes = zx_p2p::codec::bloque_a_bytes(&BloqueRed::Post {
            cabecera: bloque.cabecera,
            justificacion: bloque.justificacion.clone(),
            txs: bloque.txs().to_vec(),
            testigos: bloque.testigos().to_vec(),
        })
        .len() as u64;
        match self.admitir_post_interno(bloque.clone(), indice, true) {
            Ok(()) => {
                self.actualizar_mempool_tras_bloque_con_recibo(
                    hash,
                    bloque.txs(),
                    bloque.testigos(),
                    None,
                );
                let mut evento = self
                    .registro
                    .evento("bloque_red_admitido")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .u64("slot", bloque.cabecera.slot)
                    .u64("n_padres", n_padres)
                    .u64("bytes", bytes)
                    .u64("t_cabecera_ns", self.medicion.cabecera_ns)
                    .u64("t_admision_ns", self.medicion.admision_ns)
                    .u64("t_persistencia_ns", self.medicion.persistencia_ns)
                    .u64("t_total_ns", llegada.elapsed().as_nanos() as u64)
                    .u64("n_bloques_dag", self.cadena.bloques_admitidos());
                if let Some((azules, rojos)) = self.cadena.mergeset_de(&hash) {
                    evento = evento
                        .u64("azules_mergeset", azules)
                        .u64("rojos_mergeset", rojos);
                }
                let txs_descartadas = self.cadena.descartes(&hash).map_or(0, |d| d.len() as u64);
                evento = evento.u64("txs_descartadas", txs_descartadas);
                let _ = self.registro.escribir(evento, false);
            }
            Err(ErrorNodo::BloquePropioRechazado {
                motivo,
                clasificacion,
                ..
            }) if clasificacion.es_pendiente() => {
                let motivo_espera = self.motivo_espera_post(&bloque, &motivo);
                self.encolar_post_pendiente_con(bloque, llegada, motivo_espera);
            }
            Err(e) => {
                let evento = self
                    .registro
                    .evento("bloque_red_rechazado")
                    .str("hash", &hash.to_string())
                    .str("familia", "post")
                    .str("etapa", self.medicion.etapa)
                    .str("motivo", &format!("reintento: {e}"))
                    .u64("t_hasta_rechazo_ns", llegada.elapsed().as_nanos() as u64);
                let _ = self.registro.escribir(evento, false);
            }
        }
        // VNT-R2 · punto completo tras una admisión (o un pendiente que sigue pendiente: sin
        // frontera nueva, no cuesta nada): atiende las fronteras antes del siguiente reintento.
        if let Err(e) = self.atender_fronteras_votos() {
            tracing::warn!(%e, "fronteras de votos tras reintento PoST");
        }
    }

    /// Reintenta un PoW pendiente concreto; si vuelve a fallar por `FTL`, el propio
    /// `intentar_admitir_pow_de_red` lo reencola.
    fn reintentar_un_pow_pendiente(&mut self, p: crate::pendientes::Pendiente<BloqueRed>) {
        let llegada = p.llegada();
        if let BloqueRed::Pow {
            cabecera,
            txs,
            testigos,
        } = p.en_bloque()
        {
            let _ = self.intentar_admitir_pow_de_red(cabecera, txs, testigos, None, llegada);
        }
        // VNT-R2 · el reintento PoW también es un camino que admite un bloque.
        if let Err(e) = self.atender_fronteras_votos() {
            tracing::warn!(%e, "fronteras de votos tras reintento PoW");
        }
    }

    /// La instantánea compartida de red (para construir el manejador antes de llamar a
    /// [`Self::conectar_red`], y para que las pruebas la inspeccionen).
    #[must_use]
    pub fn vista_red(&self) -> Arc<VistaRed> {
        Arc::clone(&self.vista_red)
    }
}

/// RD-4b · P1 · Último empuje de la tabla de pesos al director: el ancla de votos que se entregó y
/// el instante de la entrega, para no recalcular por bloque y no repetir dentro de `T_par`.
pub(super) struct UltimoEmpujePesos {
    /// Ancla de votos `(n, h)` que se entregó.
    pub(super) ancla: Option<(u64, BlockHash)>,
    /// Instante (inyectado por el llamante) del empuje.
    pub(super) momento: Instant,
}

/// Tope de [`Nodo::post_pendientes`]: acotar la cola, no la corrección (D-oS local, no de consenso).
pub(super) const TOPE_POST_PENDIENTES: usize = 64;

/// Tope de [`Nodo::pow_pendientes`]: misma cota y política que el PoST (RLJ-3b §2.4).
pub(super) const TOPE_POW_PENDIENTES: usize = 64;

/// Prefijo del motivo de retención por límite de futuro del PoST (`Nodo::verificar_reloj_post`).
/// Es la señal que distingue un pendiente solo-`FTL` de uno por contexto en el `ErrorNodo`.
const PREFIJO_FTL_POST: &str = "FTL del PoST:";
