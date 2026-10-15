//! Pieza A (MAP-1): admisión de bloques y vista de cadena.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    Almacen, BlockHash, BlockHeader, BloqueAdmitido, BloqueCadena, BloqueDag, BloquePost,
    BloqueRed, BloqueTransicion, CachePotVerificada, Cadena, ContextoPow, ErrorNodo,
    EstadoCabeceraConjunta, HechosCabecera, Instant, Medicion, MotivoBloque, Nodo,
    PARAMETROS_POW_DEV, PresupuestoIlimitado, Red, Sha3Dev, Tx, U256, es_coinbase_pow,
    es_rechazo_propio_por_cuerpo, identidad_de_cabecera_post, padres_dag_a_vec, peso_u128, pow,
    pow_target_de, trabajo_bloque, validar_cabecera_pow, verificar_cabecera_conjunta,
};

impl Nodo {
    /// Admite un bloque PoW: verificación W04 (si `verificar`), motor de transición, persistencia.
    ///
    /// `verificar = false` en la repetición (D-N03′): la cabecera ya se comprobó cuando se admitió
    /// la primera vez. El motor de transición (con sus firmas) se ejecuta **siempre**, verificado o
    /// no: es lo que detecta un testigo PoW corrupto (`REVISION-W06b.md`, límite declarado).
    pub(super) fn admitir_pow_interno(
        &mut self,
        cabecera: BlockHeader,
        txs: Vec<Tx>,
        testigos: Vec<Vec<Vec<u8>>>,
        _indice_registro: u64,
        verificar: bool,
        es_propio: bool,
    ) -> Result<(), ErrorNodo> {
        let hash = cabecera.block_hash();
        let es_genesis = cabecera.height == 0;
        // `ORDEN-W06d10-B` (solo tests): fallo local inyectado, como el que produciría un error de
        // persistencia/servicio. Se consume una vez; en producción este bloque no existe.
        #[cfg(test)]
        if let Some(motivo) = self.fallo_local_simulado.take() {
            return Err(ErrorNodo::Otro(motivo));
        }
        // `ORDEN-W07a` decisión 1: solo se envuelven con `Instant` llamadas que ya existen. La
        // etapa se fija para poder etiquetar un rechazo (`bloque_red_rechazado`).
        self.medicion = Medicion {
            etapa: "cabecera",
            ..Medicion::default()
        };
        // Instantánea para la vista de red (decisión 4): se toma **antes** de que `txs`/`testigos`
        // se consuman más abajo (`into_iter().zip`). Solo se usa si el bloque resulta nuevo
        // (`!ya_admitido`, comprobado antes de publicarla); el coste de clonar es aceptable en la
        // red dev (bloques con pocas transacciones) y se revisa si el perfil (W07) lo desmiente.
        let para_vista = BloqueRed::Pow {
            cabecera,
            txs: txs.clone(),
            testigos: testigos.clone(),
        };

        if verificar && !es_genesis {
            let inicio_cabecera = Instant::now();
            // `ORDEN-W06d3` decisión 3: el contexto de validación (target, altura, timestamp) se
            // calcula contra el **padre declarado** de este bloque (`cabecera.prev_hash`), nunca
            // contra `historial_pow.last()`: eso es precisamente lo que hacía imposible admitir una
            // bifurcación PoW real con un contexto correcto (`REVISION-W06d2.md`, límite conocido).
            let historial_padre = self.historial_hasta(cabecera.prev_hash);
            let padre =
                *historial_padre
                    .last()
                    .ok_or_else(|| ErrorNodo::BloquePropioRechazado {
                        hash,
                        motivo: format!("padre {} desconocido (sin cabecera)", cabecera.prev_hash),
                        // Interno: el padre de un bloque que este mismo nodo acaba de minar sobre
                        // su propio `historial_pow` no puede ser desconocido salvo un bug real.
                        clasificacion: crate::rechazo::ClasificacionRechazo::Interno,
                    })?;
            let target_esperado = pow::target_de_altura(&historial_padre, cabecera.height)
                .map_err(|e| ErrorNodo::BloquePropioRechazado {
                    hash,
                    motivo: format!("target de altura: {e}"),
                    // Interno: depende del historial del padre declarado (que este nodo ya tiene),
                    // no de ninguna vista local; cualquier nodo con ese padre calcularía lo mismo.
                    clasificacion: crate::rechazo::ClasificacionRechazo::Interno,
                })?;
            let ctx = ContextoPow {
                red: Red::Dev,
                parametros: PARAMETROS_POW_DEV,
                altura_padre: padre.height,
                hash_padre: padre.block_hash(),
                target_esperado,
                ts_padre: i64::try_from(padre.timestamp).unwrap_or(i64::MAX),
                reloj_local: self.reloj_local(),
            };
            validar_cabecera_pow(&cabecera, &ctx, &Sha3Dev).map_err(|e| {
                ErrorNodo::BloquePropioRechazado {
                    hash,
                    motivo: format!("validar_cabecera_pow: {e}"),
                    // `ORDEN-W06d10-B` X1: el propio tipo declara con `es_permanente()` qué fallo
                    // es diferible (C-TS-03, reloj local → `VistaLocal`) y cuál es un defecto
                    // permanente del candidato (`Interno`). Para un bloque propio la fatalidad no
                    // cambia (`VistaLocal::es_legitimo() == false`).
                    clasificacion: crate::rechazo::clasificar_error_pow(&e),
                }
            })?;
            self.medicion.cabecera_ns = inicio_cabecera.elapsed().as_nanos() as u64;
        }
        // Se registra la cabecera (válida, o el génesis) para poder reconstruir el historial de
        // cualquier rama que la tenga como ancestro, sea o no la punta seleccionada hoy.
        self.headers_pow.insert(hash, cabecera);

        let hechos = if es_genesis {
            HechosCabecera::Genesis { hash }
        } else {
            let target =
                pow_target_de(&cabecera).map_err(|e| ErrorNodo::BloquePropioRechazado {
                    hash,
                    motivo: e.to_string(),
                    // Interno: `bits` no canónico del candidato, demostrable por cualquier nodo.
                    clasificacion: crate::rechazo::ClasificacionRechazo::Interno,
                })?;
            let trabajo =
                trabajo_bloque(target).ok_or_else(|| ErrorNodo::BloquePropioRechazado {
                    hash,
                    motivo: format!("trabajo del bloque {hash} desborda"),
                    // Interno: aritmética del propio bloque.
                    clasificacion: crate::rechazo::ClasificacionRechazo::Interno,
                })?;
            HechosCabecera::PoW {
                hash,
                padre: cabecera.prev_hash,
                altura: cabecera.height,
                trabajo,
                pow_valido: true,
            }
        };
        // `ORDEN-W06d4` decisión 1/2: hasta aquí, el rastro de coinbases/depósitos propios era un
        // indicador local (`CoinbasePropia.depositada`) que marcaba "ya gastada" en cuanto **algún**
        // bloque admitido (propio o ajeno, en cualquier rama) gastaba el `OutPoint`, sin comprobar si
        // ese bloque seguía en la rama seleccionada. Confirmado con evidencia
        // (`pruebas_deposito_sensible_a_la_rama`, más abajo): tras una reorganización que descarta el
        // bloque del depósito pero conserva la coinbase (todavía viva en la rama nueva), el
        // indicador quedaba en `true` para siempre y el nodo nunca volvía a depositarla, así que las
        // `K_min` claves con garantía activa que exige `Φ` nunca llegaban a reunirse con varios
        // procesos minando a la vez (`REVISION-W06d3.md`). `preparar_depositos` ya no mantiene ese
        // indicador: decide qué depositar leyendo directamente `estado.utxo`/`estado.garantias` de
        // la punta PoW **seleccionada** en el momento de construir el bloque, que es sensible a la
        // rama por construcción (una salida gastada en una rama descartada sigue viva en `utxo` de
        // cualquier otra rama que no la gastó).

        let ya_admitido = self.cadena.es_valido(&hash) || self.cadena.motivo(&hash).is_some();
        if !ya_admitido {
            // `ORDEN-W06d6`, paso previo (RI-3c H1, `REVISION-RI-3c.md`): orden **admitir en
            // `zx-cadena` → persistir → difundir** (la difusión la hace quien llama, ya solo tras
            // que esta función devuelva `Ok`). Antes se persistía primero: si `cadena.admitir`
            // rechazaba el bloque con un motivo `Legitimo`/`Interno` normal (`ErrGarantia`,
            // `ErrMergeDepth`... la propia `ORDEN-W06d5` decisión 3 los declara esperables), la
            // entrada quedaba en el almacén **sin que nada la deshiciera**: un bloque rechazado
            // repetía su rechazo en cada reinicio (D-N03′ repite todo el registro) y el nodo no
            // volvía a arrancar nunca (RI-3c, reproducido con un `ErrEmision`). Con el orden nuevo,
            // un rechazo de `cadena.admitir` sale de esta función (el `?` de abajo) **antes** de
            // tocar disco: no hay nada que deshacer. Si el proceso muere justo entre admitir
            // (memoria) y persistir (disco), el bloque simplemente no salió del nodo — nunca se
            // difundió (eso ocurre después, en el llamante) y el reinicio no lo repite porque no
            // está en el almacén; no es la doble firma que RI-2b temía (esa era sobre difundir
            // antes de persistir, no sobre admitir antes de persistir).
            // P2: el número de transacciones (y cuántas no son la coinbase) se captura antes de que
            // `txs` se mueva, para poder decidir si un rechazo por `ErrTransicion` es del cuerpo.
            let n_txs = u64::try_from(txs.len()).unwrap_or(u64::MAX);
            let n_txs_sin_coinbase = txs.iter().filter(|t| !es_coinbase_pow(t)).count();
            let admitido = BloqueAdmitido::pow(&cabecera, &txs, &testigos);
            let txs_con_testigos: Vec<(Tx, Vec<Vec<u8>>)> = txs.into_iter().zip(testigos).collect();
            let txs_descartes: Vec<Tx> = txs_con_testigos.iter().map(|(t, _)| t.clone()).collect();
            let bt = BloqueTransicion::nuevo(hechos, txs_con_testigos);
            self.medicion.etapa = "admision";
            let inicio_admision = Instant::now();
            self.cadena.admitir(BloqueCadena::Pow(bt)).map_err(|m| {
                let clasificacion = crate::rechazo::clasificar_motivo_bloque(&m);
                // P2 (`ORDEN-MP1`): solo un bloque **propio**, rechazado por la transición
                // (`ErrTransicion`), con clasificación no legítima y con al menos una transacción
                // además de la coinbase, se convierte en `BloquePropioRechazadoPorTx` (no fatal en
                // `fase_pow`). Cualquier otro rechazo conserva la variante de siempre.
                if es_propio && es_rechazo_propio_por_cuerpo(&m, clasificacion, n_txs_sin_coinbase)
                {
                    ErrorNodo::BloquePropioRechazadoPorTx {
                        hash,
                        altura: cabecera.height,
                        motivo: m.nombre().to_string(),
                        n_txs,
                    }
                } else {
                    ErrorNodo::BloquePropioRechazado {
                        hash,
                        motivo: m.nombre().to_string(),
                        clasificacion,
                    }
                }
            })?;
            // RN-1 · S5 · rastro de las transacciones que el consenso descartó al aplicar el bloque.
            self.registrar_transacciones_descartadas(&hash, &txs_descartes);
            self.medicion.admision_ns = inicio_admision.elapsed().as_nanos() as u64;
            self.emitir_violaciones_finalidad()?;
            // Solo en la ruta en vivo (`verificar`): en la repetición el bloque ya está en el
            // almacén (viene de ahí) y volver a escribirlo sería una vuelta redundante a disco.
            if verificar {
                self.medicion.etapa = "persistencia";
                let inicio_persistencia = Instant::now();
                self.almacen.admitir(&admitido, true)?;
                self.medicion.persistencia_ns = inicio_persistencia.elapsed().as_nanos() as u64;
            }
            self.vista_red.registrar_pow(cabecera.height, para_vista);
            // Un hijo que esperaba justo este padre puede reintentarse ya (decisión 3).
            self.resolver_huerfanos_de(hash);
        }

        // `ORDEN-W06d3` decisión 3: `historial_pow`/`trabajo_acumulado` ya no se extienden a
        // ciegas con cada bloque admitido (eso asumía una única cadena lineal); se recalculan desde
        // la punta PoW **seleccionada** por `zx-cadena` (mayor trabajo acumulado), lo mismo si este
        // bloque la extiende como si es un bloque de una rama lateral que no la cambia.
        self.actualizar_seleccion_pow()?;
        // `ORDEN-W06d7` decisión 5: un `ServicioPot` de verificación **por terminal candidato**, no
        // solo el seleccionado — puede haber varios terminales con DAG a la vez (decisión 1), y cada
        // uno necesita su propio flujo PoT para verificar los bloques PoST que declaran ese terminal
        // en su pasado, tanto en producción en vivo (lo crea también `fase_regimen`) como en la
        // **repetición** (D-N03′): si el registro trae ya bloques PoST, `admitir_post_interno` los
        // procesa aquí mismo, dentro de `Nodo::arrancar`, antes de que `fase_regimen` llegue a
        // ejecutarse. Sin esto, reabrir un nodo que ya había cruzado el corte fallaba siempre en la
        // primera entrada PoST del registro (bug real encontrado por `tests/reinicio.rs`,
        // `PROGRESO.md` de `W06d3`).
        self.asegurar_servicios_verificacion()?;
        self.registrar_cambio_de_punta()?;
        Ok(())
    }

    /// Terminal único al que resuelven `padres` (réplica, de solo lectura, de
    /// `Cadena::terminal_de_bloque_post`; `ORDEN-W06d7` decisión 5): el nodo necesita saberlo
    /// **antes** de llamar a `Cadena::admitir`, para elegir el `ServicioPot`/contexto de
    /// verificación correctos. `None` si algún padre es desconocido o los padres resuelven a más de
    /// un terminal (en ese caso `Cadena::admitir` lo rechazará con su propio motivo:
    /// `ErrSinPadre`/`ErrTerminalAmbiguo`; aquí basta con no elegir un servicio equivocado).
    pub(super) fn terminal_de_padres(&self, padres: &[BlockHash]) -> Option<BlockHash> {
        let candidatos = self.cadena.terminal_candidatos();
        let mut terminal_ref: Option<BlockHash> = None;
        for x in padres {
            let t = if candidatos.contains(x) {
                Some(*x)
            } else {
                self.cadena.terminal_de(x)
            };
            let t = t?;
            match terminal_ref {
                None => terminal_ref = Some(t),
                Some(prev) if prev != t => return None,
                Some(_) => {}
            }
        }
        terminal_ref
    }

    /// Reconstruye, si hace falta, `historial_pow` (y `trabajo_acumulado`) desde la punta PoW que
    /// `Cadena::mejor_punta_pow` selecciona ahora (`ORDEN-W06d3` decisión 3). Registra la
    /// profundidad de la reorganización cuando la punta cambia de rama, no solo de altura.
    fn actualizar_seleccion_pow(&mut self) -> Result<(), ErrorNodo> {
        let Some(nueva_punta) = self.cadena.mejor_punta_pow() else {
            return Ok(());
        };
        let punta_anterior = self.historial_pow.last().map(BlockHeader::block_hash);
        if punta_anterior == Some(nueva_punta) {
            return Ok(());
        }
        let historial_anterior = std::mem::take(&mut self.historial_pow);
        let nuevo_historial = self.historial_hasta(nueva_punta);
        let comunes = historial_anterior
            .iter()
            .zip(nuevo_historial.iter())
            .take_while(|(a, b)| a.block_hash() == b.block_hash())
            .count();
        let profundidad = historial_anterior.len().saturating_sub(comunes);
        // `ORDEN-W06d4` decisión 2: ya no hay una lista local de `CoinbasePropia` que podar tras una
        // reorganización (`ORDEN-W06d3` la podaba por `bloque`, pero eso no bastaba: ver el
        // comentario en `admitir_pow_interno`). `preparar_depositos` lee `estado.utxo` de la punta
        // ya seleccionada en cada llamada, así que no hay ningún indicador que desincronizar aquí.
        self.historial_pow = nuevo_historial;
        // `ORDEN-W06d3`, hallazgo en vivo (`PROGRESO.md`): `VistaRed::registrar_pow` es
        // *append-only por altura* y nunca sustituye una altura ya ocupada, aunque la rama
        // seleccionada cambie. Se fija aquí la secuencia completa (siempre desde el génesis) para
        // que el localizador y `cabeceras_desde` que sirven a los pares reflejen exactamente la
        // rama que este nodo tiene por buena, tanto en una extensión simple como en una
        // reorganización.
        self.vista_red.fijar_cabeceras_pow(&self.historial_pow);
        self.trabajo_acumulado = self
            .cadena
            .trabajo_pow(&nueva_punta)
            .unwrap_or_else(U256::zero);
        if profundidad > 0 {
            let evento = self
                .registro
                .evento("reorganizacion_pow")
                .str(
                    "punta_anterior",
                    &punta_anterior.map(|h| h.to_string()).unwrap_or_default(),
                )
                .str("punta_nueva", &nueva_punta.to_string())
                .u64("profundidad", profundidad as u64);
            self.registro.escribir(evento, false)?;
        }
        Ok(())
    }

    /// Reconstruye, desde [`Self::headers_pow`], la cadena de cabeceras `[0..=altura(tip)]` que
    /// termina en `tip`, caminando `prev_hash` hacia atrás hasta el génesis. Vacío si `tip` no se
    /// conoce todavía (huérfano o hash ajeno): el llamante lo trata como "sin padre disponible".
    fn historial_hasta(&self, tip: BlockHash) -> Vec<BlockHeader> {
        let mut inverso = Vec::new();
        let mut actual = tip;
        loop {
            let Some(h) = self.headers_pow.get(&actual) else {
                return Vec::new();
            };
            inverso.push(*h);
            if h.height == 0 {
                break;
            }
            actual = h.prev_hash;
        }
        inverso.reverse();
        inverso
    }

    /// Admite un bloque PoST: tubería única (decisión 4) o repetición (`verificar = false`).
    pub(super) fn admitir_post_interno(
        &mut self,
        bloque: BloqueDag,
        _indice_registro: u64,
        verificar: bool,
    ) -> Result<(), ErrorNodo> {
        let hash = bloque.cabecera.block_hash();
        // `ORDEN-W06d10-B` (solo tests): fallo local inyectado (ver `admitir_pow_interno`).
        #[cfg(test)]
        if let Some(motivo) = self.fallo_local_simulado.take() {
            return Err(ErrorNodo::Otro(motivo));
        }
        // `ORDEN-W07a`: misma medición por etapas que `admitir_pow_interno`.
        self.medicion = Medicion {
            etapa: "cabecera",
            ..Medicion::default()
        };
        // `ORDEN-W06d7` decisión 1/5: los padres deciden a qué terminal pertenece este bloque —
        // necesario **ya** para elegir el `ServicioPot`/contexto de verificación, antes incluso de
        // llamar a `Cadena::admitir` (que hace la misma resolución internamente, pero después). Se
        // calcula **siempre** (también en la repetición, `verificar = false`): el servicio de ese
        // terminal necesita actualizarse igual al final de la función.
        let padres_declarados = padres_dag_a_vec(&bloque.cabecera.padres);
        let Some(terminal) = self.terminal_de_padres(&padres_declarados) else {
            // Terminal desconocido o ambiguo aquí: no es prueba de invalidez (podría ser un padre
            // que este nodo todavía no admitió, o una ambigüedad real que `Cadena::admitir`
            // rechazará más abajo con su propio motivo, `ErrTerminalAmbiguo`/`ErrSinPadre`); tratarlo
            // como rechazo fatal de un bloque **propio** sería incorrecto para un bloque de **red**
            // que sincroniza fuera de orden (mismo espíritu que `MotivoCabeceraPendiente`,
            // `crate::rechazo`).
            return Err(ErrorNodo::BloquePropioRechazado {
                hash,
                motivo: "terminal_no_resoluble".to_string(),
                clasificacion: crate::rechazo::ClasificacionRechazo::Pendiente,
            });
        };

        if verificar {
            let inicio_cabecera = Instant::now();
            // Construcción común de contextos (PROD-3b): la misma que usa la comprobación de
            // candidatas (`firma_contextual::contextos_verificacion_listos`).
            self.asegurar_servicios_verificacion()?;
            let ctxs = self.contextos_verificacion_listos(terminal)?;
            let mut cache = CachePotVerificada::nueva();
            let mut presupuesto = PresupuestoIlimitado;
            let estado = verificar_cabecera_conjunta(
                &bloque,
                ctxs.servicio,
                &ctxs.dag,
                &ctxs.rango,
                u64::MAX,
                &mut cache,
                &mut presupuesto,
                Some(&ctxs.params_pieza),
            );
            match estado {
                EstadoCabeceraConjunta::Comprobada(_) => {
                    // RL-2b: con el reloj dev activo, la puerta conjunta no basta: hay que
                    // verificar el segundo VDF (`v_j`) y las reglas de timestamp PoST (parte B).
                    self.verificar_reloj_post(&bloque, ctxs.servicio, terminal)?;
                }
                EstadoCabeceraConjunta::Invalida(m) => {
                    return Err(ErrorNodo::BloquePropioRechazado {
                        hash,
                        motivo: format!("{m:?}"),
                        clasificacion: crate::rechazo::clasificar_cabecera_invalida(&m),
                    });
                }
                EstadoCabeceraConjunta::Pendiente(m) => {
                    return Err(ErrorNodo::BloquePropioRechazado {
                        hash,
                        motivo: format!("pendiente: {m:?}"),
                        clasificacion: crate::rechazo::clasificar_cabecera_pendiente(&m),
                    });
                }
            }
            self.medicion.cabecera_ns = inicio_cabecera.elapsed().as_nanos() as u64;
        }

        // `ORDEN-SL4b2` decisión 3: se indexa aquí, **con independencia** de que la admisión que
        // sigue (GHOSTDAG/estado) acabe aceptando o rechazando este bloque (EV-08: la evidencia no
        // exige reconstruir la rama perdedora ni demostrar validez PoAS/PoT/padres en contexto).
        // Corre en la ruta en vivo (`verificar = true`, la puerta ya pasó arriba) y en la
        // repetición al reiniciar (`verificar = false`: todo lo que hay en el almacén ya pasó la
        // puerta en una ejecución anterior), para que el detector reconstruya el mismo estado tras
        // un reinicio. No se llama nunca para una cabecera cuya puerta conjunta falló (decisión 3,
        // último párrafo): ese caso ya salió por el `?`/`return Err` de arriba.
        self.observar_para_detector(bloque.cabecera)?;

        // ECL-R2a-2 · en tests se puede saltar la prueba PoAS (exige una prueba de espacio real)
        // para ejercitar la ruta de `admitir_post_interno` con un rechazo real por `F`.
        #[cfg(test)]
        let distancia = if self.poas_simulada {
            1u64
        } else {
            zx_poas::verificar_solucion_poas(
                &bloque.cabecera.sol,
                bloque.cabecera.slot,
                bloque.cabecera.pot_output,
                bloque.cabecera.rango_solucion,
                &self.historia.params_pieza(),
            )
            .map_err(|e| ErrorNodo::RepeticionFallida {
                indice: _indice_registro,
                hash,
                motivo: format!("distancia PoAS: {e}"),
            })?
        };
        #[cfg(not(test))]
        let distancia = zx_poas::verificar_solucion_poas(
            &bloque.cabecera.sol,
            bloque.cabecera.slot,
            bloque.cabecera.pot_output,
            bloque.cabecera.rango_solucion,
            &self.historia.params_pieza(),
        )
        .map_err(|e| ErrorNodo::RepeticionFallida {
            indice: _indice_registro,
            hash,
            motivo: format!("distancia PoAS: {e}"),
        })?;
        // Identidad real de `C-GD-07` (`ORDEN-W06a-C` decisión 2): la tupla literal derivada de la
        // misma cabecera que aporta `block_hash`, `slot` y `SR`. Ya **no** se trunca a un `u64`.
        let identidad = identidad_de_cabecera_post(&bloque.cabecera);
        let padres = padres_declarados;
        let txs: Vec<(Tx, Vec<Vec<u8>>)> = bloque
            .txs()
            .iter()
            .cloned()
            .zip(bloque.testigos().iter().cloned())
            .collect();

        let post = BloquePost {
            hash,
            padres,
            slot: bloque.cabecera.slot,
            timestamp: bloque.cabecera.timestamp,
            productor: bloque.cabecera.sol.public_key,
            peso: peso_u128(&bloque).map_err(|e| ErrorNodo::BloquePropioRechazado {
                hash,
                motivo: e.to_string(),
                // Interno: el peso w(SR) de la solución declarada es del candidato.
                clasificacion: crate::rechazo::ClasificacionRechazo::Interno,
            })?,
            prueba_valida: true,
            requisito_declarado: 0,
            sr: bloque.cabecera.rango_solucion,
            distancia,
            identidad,
            txs,
        };

        let ya_admitido = self.cadena.es_valido(&hash) || self.cadena.motivo(&hash).is_some();
        // `ORDEN-W06d6`, paso previo (RI-3c H1, `REVISION-RI-3c.md`): orden **admitir en
        // `zx-cadena` → persistir → difundir**, igual que `admitir_pow_interno` y por el mismo
        // motivo (ver su comentario). Esto **sustituye** el orden de RI-2b (persistir antes de
        // admitir): RI-2b acertaba en el objetivo —evitar la doble firma de «Relanzamiento» punto
        // 4— y se equivocaba en la forma. Lo que de verdad la evita es que la **difusión** ocurra
        // solo después de persistir (eso no cambia: sigue siendo el llamante, tras que esta función
        // devuelva `Ok`), no que la persistencia sea el primer paso. Con persistir primero, un
        // rechazo legítimo de `cadena.admitir` (`ErrGarantia`, `ErrMergeDepth`... la propia
        // `ORDEN-W06d5` decisión 3 los declara esperables) dejaba una entrada fantasma en el
        // almacén que D-N03′ repite en cada reinicio sin deshacerla — el nodo no volvía a arrancar
        // (RI-3c, confirmado). Con el orden nuevo, un rechazo sale por el `?` de abajo antes de
        // tocar disco. Si el proceso muere entre admitir (memoria) y persistir (disco), el slot
        // sigue sin observarse fuera del nodo (nunca se difundió) y el reinicio no repite nada (no
        // está en el almacén): no hay bloque fantasma que reproduzca el rechazo, y no hay doble
        // firma observable porque no hubo difusión.
        if !ya_admitido {
            self.medicion.etapa = "admision";
            let inicio_admision = Instant::now();
            // ECL-R2a · D6: si `zx-cadena` lo rechaza por la cota `F` o por no encadenar con la
            // rama del nodo, sus certificados `0x04` se inspeccionan antes de descartarlo (D2).
            let resultado = self.cadena.admitir(BloqueCadena::Post(post));
            if let Err(m) = &resultado
                && matches!(
                    m,
                    MotivoBloque::ErrMergeDepth
                        | MotivoBloque::ErrSinPadre
                        | MotivoBloque::ErrTerminalAmbiguo
                )
            {
                // PD-1f · F2 · los `0x09` del bloque rechazado pasan por el estado de verificación
                // (F1); el slot del bloque es el que usaría el consenso.
                self.inspeccionar_certificados_peso_de_bloque(
                    bloque.txs(),
                    i64::try_from(bloque.cabecera.slot).unwrap_or(i64::MAX),
                );
            }
            resultado.map_err(|m| ErrorNodo::BloquePropioRechazado {
                hash,
                motivo: m.nombre().to_string(),
                clasificacion: crate::rechazo::clasificar_motivo_bloque(&m),
            })?;
            // RN-1 · S5 · rastro de las transacciones que el consenso descartó al aplicar el bloque.
            self.registrar_transacciones_descartadas(&hash, bloque.txs());
            self.medicion.admision_ns = inicio_admision.elapsed().as_nanos() as u64;
            self.emitir_violaciones_finalidad()?;
            // ECL-R2a · D1 · ancla de votos del estado y ancla D2 del certificado aplicado.
            // ECL-R2a-5 · la reconciliación lee el **estado PoST seleccionado** (no el corte PoW) y
            // solo reconstruye el mergeset cuando el bloque trae un `0x04`.
            self.reconciliar_ancla_de_bloque(hash, bloque.txs());
            // `ORDEN-SL4b2` diagnóstico (no forma parte del esquema mínimo v1): igual que el que
            // escribe el productor tras incluir su propia `EvidenceTx` (`nodo.rs`, manejo de
            // `MsgProductor::Post`), pero aquí para **cualquier** bloque admitido por esta única
            // tubería (propio, de red o repetido): así los tres nodos —no solo el que incluyó la
            // evidencia— dejan en su registro `activo`/`congelado` de la clave castigada tras cada
            // aplicación, que es lo que V4 necesita leer "del estado de los tres nodos".
            //
            // `estado_post(&hash)` (el estado **tras este bloque concreto**), no
            // `estado_terminal()`: ese último es `Estado(T)` del terminal PoW-PoST (el corte), no
            // la punta PoST corriente — leerlo aquí habría dado siempre el estado de antes del
            // corte, sin ninguna garantía ni incidente (hallazgo real de la primera ejecución de
            // V4 con procesos reales, `PROGRESO.md`).
            for (incident_id, clave) in bloque.txs().iter().filter_map(|t| match &t.extension {
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
            }) {
                let g = self
                    .cadena
                    .estado_post(&hash)
                    .and_then(|estado| estado.garantias.get(&clave));
                let evento = self
                    .registro
                    .evento("garantia_clave_tras_evidencia")
                    .str(
                        "incident_id",
                        &zx_core::digest::Digest::from_bytes(incident_id).to_string(),
                    )
                    .str(
                        "clave",
                        &zx_core::digest::Digest::from_bytes(*clave.bytes()).to_string(),
                    )
                    .i64("activo", g.map_or(0, |g| g.activo.brek()))
                    .i64("congelado", g.map_or(0, |g| g.congelado.brek()));
                self.registro.escribir(evento, false)?;
            }
            // Solo en la ruta en vivo (`verificar`): en la repetición el bloque ya está en el
            // almacén (viene de ahí).
            if verificar {
                let admitido = BloqueAdmitido::post(&bloque);
                self.medicion.etapa = "persistencia";
                let inicio_persistencia = Instant::now();
                self.almacen.admitir(&admitido, true)?;
                self.medicion.persistencia_ns = inicio_persistencia.elapsed().as_nanos() as u64;
            }
            let para_vista = BloqueRed::Post {
                cabecera: bloque.cabecera,
                justificacion: bloque.justificacion.clone(),
                txs: bloque.txs().to_vec(),
                testigos: bloque.testigos().to_vec(),
            };
            self.vista_red.registrar_post(hash, para_vista);
            self.resolver_huerfanos_de(hash);
        }

        // El terminal de `hash` ya se conoce: la admisión de arriba (o, en la repetición, una
        // anterior) lo fijó en `zx-cadena` (`ORDEN-W06d7` decisión 1); `terminal` (resuelto arriba
        // desde los padres declarados) es el mismo valor y sirve de respaldo defensivo.
        let terminal_del_bloque = self.cadena.terminal_de(&hash).unwrap_or(terminal);
        self.actualizar_servicio_verificacion(terminal_del_bloque, &bloque)?;
        self.registrar_cambio_de_punta()?;
        Ok(())
    }

    /// Actualiza la cadena seleccionada a la que termina en `punta` y devuelve `profundidad_reorg`
    /// (bloques de la anterior que no están en la nueva). Usa solo lo que `zx-cadena` ya expone
    /// (`padre_seleccionado`) y recorre únicamente el tramo nuevo: una extensión es un solo paso.
    pub(super) fn actualizar_cadena_seleccionada(&mut self, punta: BlockHash) -> u64 {
        // Fase PoW pura (sin DAG): la cadena seleccionada es `historial_pow`, lineal.
        if self.cadena.mejor_punta().is_none() {
            let nueva: Vec<BlockHash> = self
                .historial_pow
                .iter()
                .map(BlockHeader::block_hash)
                .collect();
            let comunes = self
                .ultima_cadena_seleccionada
                .iter()
                .zip(nueva.iter())
                .take_while(|(a, b)| a == b)
                .count();
            let profundidad = self
                .ultima_cadena_seleccionada
                .len()
                .saturating_sub(comunes) as u64;
            self.reemplazar_cadena_seleccionada(&nueva);
            return profundidad;
        }

        // Fase PoST: sube por `sp` desde la punta nueva hasta el primer bloque ya presente.
        let mut sufijo_nuevo = Vec::new();
        let mut actual = Some(punta);
        let mut comun = None;
        while let Some(h) = actual {
            if let Some(&i) = self.ultima_cadena_indice.get(&h) {
                comun = Some(i);
                break;
            }
            sufijo_nuevo.push(h);
            actual = self.cadena.padre_seleccionado(&h);
        }
        let profundidad = match comun {
            Some(i) => self.ultima_cadena_seleccionada.len().saturating_sub(1 + i) as u64,
            None => self.ultima_cadena_seleccionada.len() as u64,
        };
        let descartados: Vec<BlockHash> = match comun {
            Some(i) => self.ultima_cadena_seleccionada.split_off(i + 1),
            None => std::mem::take(&mut self.ultima_cadena_seleccionada),
        };
        for h in &descartados {
            self.ultima_cadena_indice.remove(h);
        }
        sufijo_nuevo.reverse();
        for h in sufijo_nuevo {
            self.ultima_cadena_indice
                .insert(h, self.ultima_cadena_seleccionada.len());
            self.ultima_cadena_seleccionada.push(h);
        }
        // `ORDEN-TX3` TX-R-32: las transacciones de los bloques que salen de la cadena seleccionada
        // vuelven a la mempool (se revalidan contra el estado nuevo; las inválidas se descartan).
        if !descartados.is_empty() {
            let mut txs = Vec::new();
            for h in &descartados {
                if let Some(b) = self.cadena.bloque(h) {
                    txs.extend_from_slice(b.txs());
                }
            }
            if !txs.is_empty() {
                let estado = self.estado_base_mempool();
                let punto = self.punto_de_estado_virtual();
                let hechos = self.hechos_para_mempool(&estado, &txs);
                let retiradas = {
                    let mut m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
                    m.reinsertar_con_hechos(estado.clone(), hechos, &txs, Instant::now(), punto)
                };
                self.reconciliar_retiradas_evidencia(retiradas, &estado);
            }
        }
        profundidad
    }

    /// Reemplaza la cadena seleccionada entera (fase PoW, historia lineal).
    pub(super) fn reemplazar_cadena_seleccionada(&mut self, nueva: &[BlockHash]) {
        self.ultima_cadena_seleccionada.clear();
        self.ultima_cadena_indice.clear();
        for (i, h) in nueva.iter().enumerate() {
            self.ultima_cadena_seleccionada.push(*h);
            self.ultima_cadena_indice.insert(*h, i);
        }
    }

    /// Acceso de solo lectura a `zx-cadena` (para pruebas e inspección; no es API de consenso).
    #[must_use]
    pub fn cadena(&self) -> &Cadena {
        &self.cadena
    }

    /// Altura PoW alcanzada (para pruebas: mide el progreso de la fase PoW sin exponer
    /// `historial_pow` entero).
    #[must_use]
    pub fn altura_pow(&self) -> u32 {
        self.historial_pow.last().map_or(0, |h| h.height)
    }
}
