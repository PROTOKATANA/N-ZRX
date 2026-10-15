//! Pieza E (MAP-1): evidencias, certificados de peso, anclas y recuperación de eclipse.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    BTreeMap, BlockHash, BloqueCadena, CADUCIDAD_TABLA_VENTANAS, Digest, Eclipse, ErrorNodo,
    EstadoTransicion, ExtensionTx, Instant, Nodo, ResultadoNodo, Tx, TxCuerpoPost,
    bytes_cuerpo_post, calendario_rearranque, hex, perfil, tabla_a_payload, txid,
};

impl Nodo {
    /// Crea el `ServicioPot` de verificación de todo terminal candidato que todavía no lo tenga
    /// (`ORDEN-W06d7` decisión 5). Idempotente: un candidato ya conocido no se reconstruye ni
    /// pierde el pasado PoT que ya llevaba (a diferencia del diseño de un único terminal, donde
    /// "reconstruir" significaba tirar el servicio anterior — aquí cada terminal tiene el suyo para
    /// siempre, así que no hace falta).
    /// `ORDEN-SL4b2` decisiones 3/4: observa `cabecera` en el detector de doble firma y traduce su
    /// resultado a eventos del esquema v1 (`evidencia_detectada`, `limite_alcanzado`). No falla
    /// nunca por el resultado del detector en sí (una identidad nueva, una retransmisión o una
    /// tercera cabecera del mismo incidente no son errores); solo puede fallar al escribir el
    /// registro estructurado.
    pub(super) fn observar_para_detector(
        &mut self,
        cabecera: zx_core::preimage::dag::DagBlockHeader,
    ) -> Result<(), ErrorNodo> {
        let slot_actual = cabecera.slot;
        let (observacion, limite) = self.detector.observar(cabecera);
        if let Some(limite) = limite {
            let evento = self
                .registro
                .evento("limite_alcanzado")
                .str("par", "local")
                .str("limite", "MAX_IDENTIDADES_DETECTOR")
                .str(
                    "detalle",
                    &format!(
                        "desalojada la identidad del slot {} (tope {})",
                        limite.slot_desalojado,
                        perfil::MAX_IDENTIDADES_DETECTOR
                    ),
                );
            self.registro.escribir(evento, false)?;
        }
        if let crate::evidencia::Observacion::Incidente(pendiente) = observacion {
            let zx_core::ExtensionTx::Evidencia { h1, h2 } = &pendiente.tx.extension else {
                return Err(ErrorNodo::Otro(
                    "detector: pendiente sin ExtensionTx::Evidencia".to_string(),
                ));
            };
            let clave = h1.sol.public_key;
            let propia = self.claves.iter().any(|c| c.pk == clave);
            let evento = self
                .registro
                .evento("evidencia_detectada")
                .str(
                    "incident_id",
                    &zx_core::digest::Digest::from_bytes(pendiente.incident_id).to_string(),
                )
                .str(
                    "clave",
                    &zx_core::digest::Digest::from_bytes(*clave.bytes()).to_string(),
                )
                .u64("slot_falta", pendiente.slot_falta)
                .str("hash_1", &h1.block_hash().to_string())
                .str("hash_2", &h2.block_hash().to_string())
                .bool("propia", propia);
            self.registro.escribir(evento, true)?;
        }
        // Poda (decisión 3/EV-11): mismo criterio que el registro del firmante, en cada admisión.
        let evp = perfil::parametros_evidencia_dev();
        self.detector.podar_vistas(slot_actual, evp.plazo_slots);
        self.detector.podar_pendientes(slot_actual, evp.plazo_slots);
        Ok(())
    }

    /// `REVISION-FIN1.md` límite 2 · escribe al registro un evento `violacion_finalidad` por cada
    /// violación **nueva** que [`Cadena::violaciones_finalidad`] haya acumulado tras una admisión.
    ///
    /// El `BTreeSet` evita repetir el evento en cada bloque posterior. El evento no cambia la
    /// validez de nada: es la salida del diagnóstico que `zx-cadena` no puede emitir por sí mismo.
    pub(super) fn emitir_violaciones_finalidad(&mut self) -> ResultadoNodo<()> {
        let violaciones = self.cadena.violaciones_finalidad();
        for v in violaciones {
            if !self.violaciones_emitidas.insert((v.finalidad, v.bloque)) {
                continue;
            }
            let evento = self
                .registro
                .evento("violacion_finalidad")
                .str("finalidad", &v.finalidad.to_string())
                .str("bloque", &v.bloque.to_string())
                .u64("profundidad", v.profundidad);
            self.registro.escribir(evento, false)?;
        }
        Ok(())
    }

    /// N2: verifica en orden con la transición real y conserva solo un prefijo que quepa.
    pub(super) fn certificados_para_cuerpo_post(
        &self,
        base: &EstadoTransicion,
        slot: u64,
        coinbase: &Tx,
    ) -> Vec<TxCuerpoPost> {
        let (Some(motor), Some(clave)) = (self.motor_votos.as_ref(), self.claves.first()) else {
            return Vec::new();
        };
        use zx_consensus::transicion::votos::{
            aplicar_certificado_peso_con_undo, derivar_tabla_sin_base_con_undo,
            tomar_instantaneas_rearranque_con_undo,
        };
        let reducido = Self::estado_reducido_para_peso(base);
        let (estado, _) = tomar_instantaneas_rearranque_con_undo(&reducido, slot);
        let (mut estado, _) = derivar_tabla_sin_base_con_undo(&estado, slot);
        let mut usados = bytes_cuerpo_post(coinbase, &[]);
        let slot_i64 = i64::try_from(slot).unwrap_or(i64::MAX);
        let mut salida = Vec::new();
        // El control cargado no es una adopción local ni un pendiente de arranque. La
        // compatibilidad previa lo ofrece cuando la selección aún no lo tiene.
        let control = motor
            .certificado_control_sin_adopciones()
            .filter(|cert| base.finalidad_votos.is_none() || base.finalidad_votos_n < cert.n);
        for pendiente in motor.certificados_peso().iter().chain(control) {
            // La transición decide también caducidad, fase de rearranque y tabla comprometida.
            let operacion = |cert: &zx_votos::CertificadoPeso| {
                zx_core::OperacionAlmacenamiento::CertificadoPeso {
                    clave: clave.pk,
                    bytes: zx_votos::serial_certificado_peso(cert),
                }
            };
            let (mut siguiente, _, mut resultado) =
                aplicar_certificado_peso_con_undo(&estado, &operacion(pendiente), slot_i64);
            let mut cert = pendiente.clone();
            if resultado.is_err() {
                let tabla = tabla_peso_para_bloque(&estado, slot, pendiente.n);
                if let Ok(Some(remontado)) = motor.certificado_para_tabla(&tabla)
                    && remontado.n == pendiente.n
                {
                    (siguiente, _, resultado) = aplicar_certificado_peso_con_undo(
                        &estado,
                        &operacion(&remontado),
                        slot_i64,
                    );
                    cert = remontado;
                }
            }
            if resultado.is_err() {
                continue;
            }
            let par = crate::votos::tx_certificado_peso(&cert, clave.pk, &clave.sk, self.cbid);
            let bytes = bytes_cuerpo_post(coinbase, &[std::slice::from_ref(&par)])
                .saturating_sub(bytes_cuerpo_post(coinbase, &[]));
            if bytes > self.params.max_tx_bytes {
                continue;
            }
            if usados.saturating_add(bytes) > self.params.max_cuerpo_bloque_bytes {
                break;
            }
            usados = usados.saturating_add(bytes);
            estado = siguiente;
            salida.push(par);
        }
        salida
    }

    /// PD-1f · F1 · copia **reducida** del estado seleccionado con los campos que lee
    /// [`zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo`] y sus auxiliares
    /// (`tabla_canonica`, `indice_bls_a_ed25519`, `guardar_contenido`, `podar_contenido_voto`,
    /// `asociar_ventanas_al_avanzar`):
    ///
    /// - directos: `finalidad_votos_n`, `finalidad_votos`, `finalidad_votos_h_t`,
    ///   `parametros_sector`, `tablas_voto`, `tablas_voto_contenido`, `tabla_ventana_voto`,
    ///   `tabla_ciclo_rearranque`, `votantes_voto`;
    /// - de `tabla_canonica` (solo se invoca cuando **no** hay base): `claves_voto`, `sectores`,
    ///   `pruebas`;
    /// - `fase` se copia por fidelidad del contexto, aunque el camino `0x09` no la lee.
    ///
    /// No se copia nada más (UTXO, garantías, PoW, PoRep, cajas, deuda de ausencia…): la parte más
    /// pesada de un estado (el `utxo`) queda fuera.
    pub(super) fn estado_reducido_para_peso(
        estado: &zx_consensus::transicion::Estado,
    ) -> zx_consensus::transicion::Estado {
        let mut r = zx_consensus::transicion::Estado::inicial();
        r.fase = estado.fase;
        r.parametros_sector = estado.parametros_sector;
        r.finalidad_votos_n = estado.finalidad_votos_n;
        r.finalidad_votos = estado.finalidad_votos;
        r.finalidad_votos_h_t = estado.finalidad_votos_h_t;
        r.tablas_voto = estado.tablas_voto.clone();
        r.tablas_voto_contenido = estado.tablas_voto_contenido.clone();
        r.tabla_ventana_voto = estado.tabla_ventana_voto.clone();
        r.tabla_ciclo_rearranque = estado.tabla_ciclo_rearranque.clone();
        r.ultima_ventana_derivada_sin_base = estado.ultima_ventana_derivada_sin_base;
        // TB-1a · R1 · la cola `Q` entra en la copia reducida: `aplicar_certificado_peso` la
        // actualiza al aplicar y el resumen/copia deben reproducirlo.
        r.cola_tablas_voto = estado.cola_tablas_voto.clone();
        r.votantes_voto = estado.votantes_voto.clone();
        r.claves_voto = estado.claves_voto.clone();
        // RK-2 · V5/V6 · el certificado atribuye firmantes también con la clave anterior viva; sin
        // copiarla, la copia reducida no reproduciría el resultado del consenso.
        r.claves_voto_previas = estado.claves_voto_previas.clone();
        r.vencimientos_clave_voto = estado.vencimientos_clave_voto.clone();
        r.sectores = estado.sectores.clone();
        r.pruebas = estado.pruebas.clone();
        r
    }

    /// PD-1f · F1 · construye/refresca la copia reducida cuando la finalidad por votos del estado
    /// seleccionado avanza (o aún no existía).
    fn asegurar_estado_verificacion_peso(&mut self, estado_sel: &zx_consensus::transicion::Estado) {
        let base = (estado_sel.finalidad_votos_n, estado_sel.finalidad_votos);
        if self.estado_verificacion_peso.is_some() && self.base_verificacion_peso == Some(base) {
            return;
        }
        self.estado_verificacion_peso = Some(Self::estado_reducido_para_peso(estado_sel));
        self.base_verificacion_peso = Some(base);
    }

    /// PD-1f · F5 · TB-1c · C8/N4 · siembra el estado de verificación desde un punto de control
    /// externo por peso: copia reducida del estado seleccionado con la finalidad fijada por el
    /// checkpoint, su cola `Q` y los contenidos de las huellas, para que un `0x09` posterior
    /// encadene.
    pub(super) fn sembrar_estado_verificacion_peso(
        &mut self,
        estado_sel: &zx_consensus::transicion::Estado,
        punto: &crate::votos::PuntoControlPeso,
    ) {
        let mut r = Self::estado_reducido_para_peso(estado_sel);
        let contenido = tabla_a_payload(&punto.tabla);
        let h_tabla = zx_votos::hash_tabla(&punto.tabla);
        r.tablas_voto_contenido.entry(h_tabla).or_insert(contenido);
        for (huella, tabla) in &punto.contenidos {
            r.tablas_voto_contenido
                .entry(*huella)
                .or_insert_with(|| tabla_a_payload(tabla));
        }
        r.cola_tablas_voto = punto.cola.clone();
        let h = BlockHash::from_digest(Digest::from_bytes(punto.certificado.candidato));
        r.finalidad_votos_n = punto.certificado.n;
        r.finalidad_votos = Some(h);
        r.finalidad_votos_h_t = Some(punto.certificado.h_t_siguiente);
        self.estado_verificacion_peso = Some(r);
        // La copia se construyó desde el estado seleccionado: su base de refresco es la del estado,
        // no la del checkpoint, para que `asegurar_estado_verificacion_peso` no la rehaga.
        self.base_verificacion_peso =
            Some((estado_sel.finalidad_votos_n, estado_sel.finalidad_votos));
    }

    /// PD-1f · F1 · verifica un `0x09` suelto aplicándolo sobre el estado de verificación con el
    /// **mismo** camino del consenso (`aplicar_certificado_peso_con_undo`); no hay segunda
    /// verificación a mano.
    fn verificar_certificado_peso_suelto(
        &mut self,
        estado_sel: &zx_consensus::transicion::Estado,
        op: &zx_core::OperacionAlmacenamiento,
        slot: i64,
    ) -> ResultadoPeso {
        self.asegurar_estado_verificacion_peso(estado_sel);
        let Some(estado_verif) = self.estado_verificacion_peso.take() else {
            return ResultadoPeso::Descartado;
        };
        let (nuevo, _undo, resultado) =
            zx_consensus::transicion::votos::aplicar_certificado_peso_con_undo(
                &estado_verif,
                op,
                slot,
            );
        match resultado {
            Ok(()) => {
                let n = nuevo.finalidad_votos_n;
                let Some(h) = nuevo.finalidad_votos else {
                    self.estado_verificacion_peso = Some(estado_verif);
                    return ResultadoPeso::Descartado;
                };
                self.estado_verificacion_peso = Some(nuevo);
                ResultadoPeso::Aplicado(n, h)
            }
            Err(e) => {
                // La función no muta el estado antes de fallar; se restaura la copia por completitud.
                self.estado_verificacion_peso = Some(estado_verif);
                if es_fuera_de_orden_peso(&e) {
                    // TB-1c · C7/N3 · un `0x09` de un bloque rechazado por T3 deja el evento con su
                    // ventana y su huella: es la señal de que la cola `Q` se queda corta.
                    if matches!(
                        e,
                        zx_consensus::transicion::ErrorTransicion::ErrCertificadoPesoMotivo(
                            zx_votos::peso::MotivoPeso::TablaNoDerivada
                        )
                    ) && let Some((n, huella)) = ventana_y_huella_de_certificado_peso(op)
                    {
                        let evento = self
                            .registro
                            .evento("certificado_tabla_no_derivada")
                            .u64("n", n)
                            .str("huella", &hex(&huella));
                        let _ = self.registro.escribir(evento, false);
                    }
                    ResultadoPeso::FueraDeOrden
                } else {
                    ResultadoPeso::Descartado
                }
            }
        }
    }

    /// PD-1f · F2 · Inspecciona los `0x09` de un bloque **rechazado** (D6) en modo peso.
    ///
    /// Los deposita por ventana (dedup, como D6) y ejecuta F2/F3. Un certificado verificado se
    /// entrega a la cadena por el **mismo** camino que D6 usa para un `0x04` verificado
    /// ([`zx_cadena::Cadena::considerar_ancla_verificada`], en
    /// [`Self::registrar_ancla_verificada_peso`]).
    pub(super) fn inspeccionar_certificados_peso_de_bloque(&mut self, txs: &[Tx], slot: i64) {
        let Ok(estado_sel) = self.cadena.estado_virtual() else {
            return;
        };
        self.asegurar_estado_verificacion_peso(&estado_sel);
        // Una ventana ya cubierta por el estado de verificación se descarta (no se deposita): así
        // un duplicado/conflicto posterior a una aplicación no deja basura en el depósito.
        let base = self
            .estado_verificacion_peso
            .as_ref()
            .and_then(|e| e.finalidad_votos.map(|_| e.finalidad_votos_n));
        for tx in txs.iter().filter(|tx| tx_es_certificado_peso(tx)) {
            let Some(n) = operacion_certificado_peso(tx).and_then(ventana_de_certificado_peso)
            else {
                continue;
            };
            if base.is_some_and(|b| n <= b) {
                continue;
            }
            self.pasos_peso_pendientes
                .entry(n)
                .or_insert_with(|| tx.clone());
        }
        self.acotar_pasos_peso_pendientes();
        self.procesar_pasos_peso(&estado_sel, slot);
        self.avisar_ancla_pendiente();
    }

    /// PD-1f · F2/F3 · aplica en orden los `0x09` del depósito que encadenen con el estado de
    /// verificación. Los que aplican avanzan la finalidad y se entregan a la cadena; los que no
    /// encadenan se conservan; los inválidos se descartan.
    fn procesar_pasos_peso(&mut self, estado_sel: &zx_consensus::transicion::Estado, slot: i64) {
        self.asegurar_estado_verificacion_peso(estado_sel);
        while let Some(e) = self.estado_verificacion_peso.as_ref() {
            // Se copian los escalares para soltar el préstamo antes de mutar el nodo en la vuelta.
            let (base_n, tiene_finalidad) = (e.finalidad_votos_n, e.finalidad_votos.is_some());
            // RN-1 · S7 · el paso que se intenta es el de **menor ventana pendiente mayor que la
            // base** del estado de verificación, no `base + 1`: un `0x09` de una ventana posterior
            // con la misma tabla es verificable directamente. Si falta una tabla intermedia el
            // intento da «fuera de orden» y el bucle para (más abajo). Sin base, el primero del
            // depósito (génesis).
            let Some(siguiente) = (if tiene_finalidad {
                self.pasos_peso_pendientes
                    .range((
                        std::ops::Bound::Excluded(base_n),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(k, _)| *k)
            } else {
                self.pasos_peso_pendientes.keys().next().copied()
            }) else {
                break;
            };
            let Some(tx) = self.pasos_peso_pendientes.get(&siguiente).cloned() else {
                break;
            };
            let Some(op) = operacion_certificado_peso(&tx).cloned() else {
                self.pasos_peso_pendientes.remove(&siguiente);
                continue;
            };
            match self.verificar_certificado_peso_suelto(estado_sel, &op, slot) {
                ResultadoPeso::Aplicado(n, h) => {
                    self.pasos_peso_pendientes.retain(|k, _| *k > n);
                    self.registrar_ancla_verificada_peso(n, h);
                }
                ResultadoPeso::FueraDeOrden => break,
                ResultadoPeso::Descartado => {
                    self.pasos_peso_pendientes.remove(&siguiente);
                }
            }
        }
    }

    /// PD-1f · F2/F4 · entrega a la cadena un `0x09` verificado y trata su resultado igual que hoy:
    /// `Adoptada`/`Idempotente` → nada; `Pendiente` → [`Self::avisar_ancla_pendiente`];
    /// `ConflictoMismaInstancia` → `certificado_en_conflicto` (el evento de conflicto que ya
    /// existe); el eclipse lo decide la cadena en `evaluar_ancla` y lo atiende D4.
    fn registrar_ancla_verificada_peso(&mut self, n: u64, h: BlockHash) {
        let resultado = self.cadena.considerar_ancla_verificada(n, h);
        self.tratar_resultado_ancla_peso(resultado, n, h);
    }

    /// PD-1f · F4 · ancla de estado de un bloque **admitido** con `0x09`: se usa el resultado de
    /// `considerar_ancla_de_estado` (hoy descartado) con el mismo trato que F2.
    pub(super) fn registrar_ancla_de_estado_peso(&mut self, n: u64, h: BlockHash) {
        let resultado = self.cadena.considerar_ancla_de_estado(n, h);
        self.tratar_resultado_ancla_peso(resultado, n, h);
    }

    /// PD-1f · F4 · trato común del resultado de considerar un ancla por peso.
    fn tratar_resultado_ancla_peso(
        &mut self,
        resultado: zx_cadena::ResultadoAncla,
        n: u64,
        h: BlockHash,
    ) {
        match resultado {
            zx_cadena::ResultadoAncla::Adoptada
            | zx_cadena::ResultadoAncla::Idempotente
            | zx_cadena::ResultadoAncla::Ignorada => {}
            zx_cadena::ResultadoAncla::Pendiente => {
                self.avisar_ancla_pendiente();
            }
            zx_cadena::ResultadoAncla::ConflictoMismaInstancia => {
                let evento = self
                    .registro
                    .evento("certificado_en_conflicto")
                    .str("candidato", &hex(h.as_bytes()))
                    .str("motivo", "ConflictoMismaInstancia")
                    .u64("n", n);
                let _ = self.registro.escribir(evento, false);
            }
        }
    }

    /// ECL-R2a · D5 · avisa e intenta pedir el bloque del ancla de votos pendiente.
    ///
    /// Emite `ancla_pendiente` **una sola vez**; la marca de «solicitada» solo se pone cuando hay
    /// red y par y la petición sale de verdad: un arranque/candidato pendiente sin par no quema la
    /// única petición. Límite exacto: una `Peticion::Bloques` por `(candidato pendiente, par)`.
    pub(super) fn avisar_ancla_pendiente(&mut self) {
        if !self.cadena.ancla_pendiente() {
            return;
        }
        let Some((n, h)) = self.cadena.ancla_votos() else {
            return;
        };
        if !self.ancla_pendiente_emitida {
            self.ancla_pendiente_emitida = true;
            let evento = self
                .registro
                .evento("ancla_pendiente")
                .u64("n", n)
                .str("candidato", &hex(h.as_bytes()));
            let _ = self.registro.escribir(evento, false);
        }
        let Some(par) = self.par_sync else {
            return;
        };
        if self.ancla_pendiente_solicitada == Some((h, par)) {
            return;
        }
        let peticion = zx_p2p::mensaje::Peticion::Bloques { hashes: vec![h] };
        if self.enviar_peticion(par, peticion) {
            self.ancla_pendiente_solicitada = Some((h, par));
            let evento = self
                .registro
                .evento("ancla_pendiente_solicitada")
                .u64("n", n)
                .str("candidato", &hex(h.as_bytes()))
                .str("par", &par.to_string());
            let _ = self.registro.escribir(evento, false);
        }
    }

    /// PD-1f · F3 · acota el depósito de `0x09` fuera de orden por número y por bytes estimados (los
    /// mismos topes que el resto de depósitos del nodo).
    pub(super) fn acotar_pasos_peso_pendientes(&mut self) {
        while self.pasos_peso_pendientes.len() > MAX_PASOS_ANCLA_PENDIENTES {
            let Some(mas_alto) = self.pasos_peso_pendientes.keys().next_back().copied() else {
                break;
            };
            self.pasos_peso_pendientes.remove(&mas_alto);
        }
        while self
            .pasos_peso_pendientes
            .values()
            .map(tamano_estimado_tx_peso)
            .sum::<usize>()
            > MAX_BYTES_ANCLA_PENDIENTES
        {
            let Some(mas_alto) = self.pasos_peso_pendientes.keys().next_back().copied() else {
                break;
            };
            self.pasos_peso_pendientes.remove(&mas_alto);
        }
    }

    /// ECL-R2a · D4 · Modo detenido: avisa cada 60 s y escribe una sola vez el fichero de
    /// recuperación. No produce ni vota; eso lo decide el bucle de régimen.
    pub(super) fn atender_modo_detenido(&mut self) -> ResultadoNodo<()> {
        let Some(eclipse) = self.cadena.eclipse() else {
            return Ok(());
        };
        let ahora = Instant::now();
        let toca = self
            .eclipse_ultimo_aviso
            .is_none_or(|t| ahora.duration_since(t) >= std::time::Duration::from_secs(60));
        if toca {
            self.eclipse_ultimo_aviso = Some(ahora);
            let evento = self
                .registro
                .evento("eclipse_detectado")
                .u64("n", eclipse.n_ancla)
                .str("h", &hex(eclipse.h_ancla.as_bytes()))
                .u64("n_certificado", eclipse.n_certificado)
                .str("h_certificado", &hex(eclipse.h_certificado.as_bytes()))
                .u64("profundidad", eclipse.profundidad);
            self.registro.escribir(evento, true)?;
            // ECL-R2a · D4 · el eclipse también viaja en el resumen de estado periódico (cada 60 s),
            // con el `resumen_estado` de la punta seleccionada que no se ha movido.
            if let Some(resumen) = self.resumen_estado_actual() {
                let evento = self
                    .registro
                    .evento("resumen_estado")
                    .str("resumen_estado", &resumen)
                    .str("modo", "detenido")
                    .u64("n", eclipse.n_ancla)
                    .str("h", &hex(eclipse.h_ancla.as_bytes()))
                    .u64("n_certificado", eclipse.n_certificado)
                    .str("h_certificado", &hex(eclipse.h_certificado.as_bytes()))
                    .u64("profundidad", eclipse.profundidad);
                self.registro.escribir(evento, true)?;
            }
        }
        if !self.eclipse_recuperacion_escrita {
            self.escribir_recuperacion_eclipse(&eclipse)?;
            self.eclipse_recuperacion_escrita = true;
        }
        Ok(())
    }

    /// ECL-R2a · D4 · Escribe el fichero `ZXPCP1` con el certificado por peso verificado y su tabla,
    /// y registra la orden exacta de reinicio con `--punto-control`.
    ///
    /// Si el motor todavía no tiene un certificado por peso, no se escribe fichero (el evento
    /// `eclipse_detectado` ya salió y el operador puede arrancar por estado).
    fn escribir_recuperacion_eclipse(&mut self, eclipse: &Eclipse) -> ResultadoNodo<()> {
        let _ = eclipse;
        if let Some(motor) = self.motor_votos.as_ref()
            && let Some(cert) = motor.ultimo_certificado_peso()
            && let Some(tabla) = motor.tabla_control_peso().or_else(|| motor.tabla_actual())
        {
            // TB-1c · C8/N4: el punto de control lleva la cola `Q` y los contenidos de sus huellas,
            // no «la tabla y su siguiente».
            let (cola, contenidos) = match self.cadena.estado_virtual() {
                Ok(estado) => {
                    let cola = estado.cola_tablas_voto.clone();
                    let mut contenidos: Vec<([u8; 32], zx_votos::Tabla)> = Vec::new();
                    for (_, huella) in &cola {
                        if let Some(contenido) = estado.tablas_voto_contenido.get(huella) {
                            contenidos
                                .push((*huella, crate::votos::tabla_de_contenido(0, contenido)));
                        }
                    }
                    (cola, contenidos)
                }
                Err(_) => (Vec::new(), Vec::new()),
            };
            let bytes =
                crate::votos::serializar_punto_control_peso(tabla, cert, &cola, &contenidos);
            let ruta = self.dir_datos.join("recuperacion-eclipse.zxp");
            std::fs::write(&ruta, &bytes)?;
            let comando = format!(
                "zx-node --datos {} --punto-control {}",
                self.dir_datos.display(),
                ruta.display()
            );
            let evento = self
                .registro
                .evento("recuperacion_eclipse")
                .str("ruta", &ruta.display().to_string())
                .str("comando", &comando);
            self.registro.escribir(evento, true)?;
        }
        Ok(())
    }

    /// ECL-R2b-2 · firma, **admite** en la mempool y difunde las evidencias de doble voto drenadas
    /// del motor de votos.
    ///
    /// Generación (motor), admisión (`Mempool::admitir` con el `Punto` vigente y testigo Ed25519
    /// propio) y difusión (`difundir_tx_si_hay_red`) son eventos **separados**: solo se difunde la
    /// tx efectivamente admitida. El reportero es una clave Ed25519 **propia** del Nodo; no hace
    /// falta ser dueño de la clave BLS infractora ni gastar fianza ajena para informar.
    pub(super) fn procesar_evidencias_doble_voto(&mut self) {
        if self.cadena.eclipse().is_some() {
            return;
        }
        // Sin reportero no se consume material ni cupo de oferta.
        let Some(reportero) = self.claves.first().cloned() else {
            return;
        };
        if self.motor_votos.is_none() {
            return;
        }
        // VNT-1 · EV-1b conserva su reloj de **cadena aplicada**: no debe cambiar de calendario
        // cuando el tiempo PoT local del cursor va por delante.
        let slot = self.slot_cadena_votos();
        let n = slot.div_euclid(perfil::parametros_votos_dev().t_inst.max(1));
        let apertura = self
            .ventana_retiradas_evidencia
            .is_none_or(|ultima| n > ultima);
        if !apertura
            && !self
                .motor_votos
                .as_ref()
                .is_some_and(|motor| motor.hay_evidencias_pendientes_en(n))
        {
            return;
        }
        let estado = self.estado_base_mempool();
        if apertura {
            self.ventana_retiradas_evidencia = Some(n);
            let retiradas = self
                .mempool
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .tomar_retiradas_evidencia();
            self.reconciliar_retiradas_evidencia(retiradas, &estado);
        }
        let slot_aplicacion = slot.max(estado.slot.saturating_add(1));
        let evidencias = self
            .motor_votos
            .as_mut()
            .map(|motor| motor.ofrecer_evidencias_peso(&self.cadena, n, slot_aplicacion, &estado))
            .unwrap_or_default();
        let punto = self.punto_de_estado_virtual();
        let plazo = u64::try_from(estado.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
        for evidencia in evidencias {
            let (tx, testigos) = crate::votos::tx_evidencia_votos_peso(
                &evidencia,
                reportero.pk,
                &reportero.sk,
                self.cbid,
            );
            let id = txid(&tx, self.cbid);
            let ExtensionTx::PruebaAlmacenamiento {
                operacion: zx_core::OperacionAlmacenamiento::EvidenciaVotosPeso { voto1, voto2, .. },
            } = &tx.extension
            else {
                continue;
            };
            let hecho = if evidencia.n != evidencia.n2 {
                self.cadena.hecho_voto_entre_ventanas(voto1, voto2, plazo)
            } else {
                None
            };
            // Ningún préstamo del motor vive mientras se toma el mutex.
            let (respuesta, retiradas) = {
                let mut m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
                m.admitir_evidencia(tx.clone(), testigos.clone(), hecho, Instant::now(), punto)
            };
            self.reconciliar_retiradas_evidencia(retiradas, &estado);
            if let Some(motor) = self.motor_votos.as_mut() {
                motor.resolver_evidencia_peso(respuesta);
            }
            let identidad = crate::mempool::identidad_de_votos(&evidencia.clave_bls, voto1, voto2);
            let (nombre, motivo) = match respuesta {
                crate::mempool::AdmisionEvidencia::Admitida(_) => {
                    ("evidencia_admitida", String::new())
                }
                crate::mempool::AdmisionEvidencia::Cubierta { .. } => {
                    ("evidencia_cubierta", format!("{respuesta:?}"))
                }
                crate::mempool::AdmisionEvidencia::Rechazada(r) => {
                    ("evidencia_rechazada", format!("{r:?}"))
                }
            };
            let _ = self.registro.escribir(
                self.registro
                    .evento(nombre)
                    .str("incidente", &hex(&identidad.incidente))
                    .str("clave_bls", &hex(&identidad.clave_bls))
                    .str("txid", &id.to_string())
                    .u64("n", evidencia.n)
                    .u64("n2", evidencia.n2)
                    .str("punto", &format!("{punto:?}"))
                    .str("motivo", &motivo),
                false,
            );
            if matches!(respuesta, crate::mempool::AdmisionEvidencia::Admitida(_)) {
                let mut buf = Vec::new();
                zx_core::wire::tx_a_bytes(&mut buf, &tx, &testigos);
                if let Err(motivo) = self.difundir_tx_si_hay_red(&buf) {
                    let _ = self.registro.escribir(
                        self.registro
                            .evento("evidencia_no_publicada")
                            .str("incidente", &hex(&identidad.incidente))
                            .str("clave_bls", &hex(&identidad.clave_bls))
                            .str("txid", &id.to_string())
                            .str("motivo", motivo),
                        false,
                    );
                }
            }
        }
    }

    /// Los resultados se reconcilian fuera del candado y no conceden un intento extra.
    pub(super) fn reconciliar_retiradas_evidencia(
        &mut self,
        retiradas: Vec<crate::mempool::RetiradaEvidencia>,
        estado: &EstadoTransicion,
    ) {
        for retirada in retiradas {
            if let Some(motor) = self.motor_votos.as_mut() {
                motor.retirar_evidencia_peso(&retirada);
            }
            let aplicada =
                crate::mempool::incidente_aplicado(estado, &retirada.identidad.incidente);
            let nombre = if aplicada {
                "evidencia_aplicada"
            } else {
                "evidencia_retirada"
            };
            let _ = self.registro.escribir(
                self.registro
                    .evento(nombre)
                    .str("incidente", &hex(&retirada.identidad.incidente))
                    .str("clave_bls", &hex(&retirada.identidad.clave_bls))
                    .str("motivo", &format!("{:?}", retirada.motivo)),
                false,
            );
        }
    }

    /// RLJ-3a-2 · ancla diagnóstica `(s0, t0)` para `terminal`: primer bloque PoST de la cadena
    /// seleccionada **del nodo**. Se calcula una vez y se guarda en memoria; se rehace solo si el
    /// ancla cacheada deja de pertenecer a la cadena seleccionada. No toca el almacén ni influye en
    /// ningún veredicto (`C-RLJ-TS-03`).
    pub(super) fn ancla_diagnostica(&self, terminal: BlockHash) -> Option<(u64, i64)> {
        if self.cadena.terminal() != Some(terminal) {
            // La cadena seleccionada del nodo es de otro terminal: no hay ancla para este.
            return None;
        }
        let mut cache = self.ancla_diagnostico.borrow_mut();
        if cache.terminal == Some(terminal)
            && let Some(h) = cache.hash_ancla
            && self.ultima_cadena_indice.contains_key(&h)
        {
            return cache.par;
        }
        // Recalcular una sola vez: primer PoST de la cadena seleccionada (orden antiguo → nuevo).
        // El recorrido se detiene en el primer PoST, así que no recorre la historia.
        let ancla =
            self.ultima_cadena_seleccionada
                .iter()
                .find_map(|h| match self.cadena.bloque(h) {
                    Some(BloqueCadena::Post(p)) => {
                        i64::try_from(p.timestamp).ok().map(|t| (*h, (p.slot, t)))
                    }
                    _ => None,
                });
        cache.terminal = Some(terminal);
        cache.hash_ancla = ancla.map(|(h, _)| h);
        cache.par = ancla.map(|(_, par)| par);
        cache.par
    }
}

/// PD-1e · E9 · clase `0x0B` `EvidenciaVotosPeso`: prueba de dos votos por peso contradictorios.
pub(super) const CLASE_EVIDENCIA_PESO: u8 = 0x0B;

/// PD-1e · E6 · tabla del bloque para el certificado compacto por peso: con base, el contenido de
/// `estado.tablas_voto_contenido[finalidad_votos_h_t]`; sin base, la tabla canónica del estado
/// ordenada por bytes de clave BLS. `n` es el índice de la ventana certificada.
pub(super) fn tabla_peso_para_bloque(
    estado: &EstadoTransicion,
    slot: u64,
    n: u64,
) -> zx_votos::Tabla {
    // RA-2 · R3 · con la base del estado caducada para `n` y el slot del bloque en una fase activa
    // con instantánea, la tabla es la del ciclo: la misma que usará la rama de rearranque del
    // consenso al admitir el `0x09`.
    if let Some(m) = estado.finalidad_votos_h_t.map(|_| estado.finalidad_votos_n)
        && n > m.saturating_add(CADUCIDAD_TABLA_VENTANAS)
        && let Some(cal) = calendario_rearranque(&estado.parametros_sector, m)
        && let Some(j) = cal.ciclo_de_apertura(slot)
        && let Some(h) = estado.tabla_ciclo_rearranque.get(&j).copied()
        && let Some(contenido) = estado.tablas_voto_contenido.get(&h)
    {
        return crate::votos::tabla_de_contenido(n, contenido);
    }
    // Camino de hoy.
    if let Some(h) = estado.finalidad_votos_h_t
        && let Some(contenido) = estado.tablas_voto_contenido.get(&h)
    {
        return crate::votos::tabla_de_contenido(n, contenido);
    }
    let slot_i64 = i64::try_from(slot).unwrap_or(i64::MAX);
    let canonica = zx_consensus::transicion::votos::tabla_canonica(estado, slot_i64);
    crate::votos::tabla_de_contenido(n, &canonica)
}

/// P4: detector y cola comparten plazo, deduplicación por incidente y tope por bloque.
/// Se conserva el testigo original de la cola y no se marca ningún incidente como consumido.
pub(super) fn evidencias_para_cuerpo_post(
    detector: &crate::evidencia::DetectorDobleFirma,
    cola: Vec<TxCuerpoPost>,
    estado_base: Option<&EstadoTransicion>,
    slot: u64,
    plazo: u64,
    max: usize,
) -> Vec<TxCuerpoPost> {
    let detectadas = crate::evidencia::elegibles(detector, estado_base, slot, plazo, max);
    let mut por_incidente = BTreeMap::new();
    for (tx, tst) in detectadas
        .into_iter()
        .map(|tx| (tx, Vec::new()))
        .chain(cola)
    {
        let ExtensionTx::Evidencia { h1, .. } = &tx.extension else {
            continue;
        };
        if slot < h1.slot || slot >= h1.slot.saturating_add(plazo) {
            continue;
        }
        let id = *zx_core::incident_id_evidencia(
            h1.consensus_branch_id,
            h1.sol.public_key.bytes(),
            h1.sol.sector_index,
            h1.sol.history_size,
            &h1.sol.chunk,
            h1.slot,
        )
        .as_bytes();
        if estado_base.is_some_and(|base| {
            base.garantias
                .get(&h1.sol.public_key)
                .is_some_and(|g| g.incidentes.iter().any(|i| i.id == id))
        }) {
            continue;
        }
        por_incidente.entry(id).or_insert((tx, tst));
    }
    por_incidente.into_values().take(max).collect()
}

/// RA-2 · R7 · finalidad por votos **aplicada** en el estado y si su tabla está en el contenido.
#[derive(Clone, Copy, Debug)]
pub(super) struct FinalidadEstado {
    /// Instancia de la finalidad.
    pub(super) n: u64,
    /// Bloque sellado por la finalidad.
    pub(super) sellado: BlockHash,
    /// `h_T(n+1)` comprometido por la finalidad.
    pub(super) h_t: zx_votos::Hash,
    /// ¿El contenido de `h_T(n+1)` está en `tablas_voto_contenido`?
    pub(super) tiene_contenido: bool,
}

/// RA-2 · R7 · lee la finalidad por votos aplicada en un estado (si la hay) y si el contenido de su
/// tabla está guardado.
pub(super) fn finalidad_estado_de(estado: &EstadoTransicion) -> Option<FinalidadEstado> {
    let h_t = estado.finalidad_votos_h_t?;
    let sellado = estado.finalidad_votos?;
    Some(FinalidadEstado {
        n: estado.finalidad_votos_n,
        sellado,
        h_t,
        tiene_contenido: estado.tablas_voto_contenido.contains_key(&h_t),
    })
}

/// PD-1e · E7 · ¿La tx transporta un certificado compacto por peso `0x09`?
pub(super) fn tx_es_certificado_peso(tx: &Tx) -> bool {
    matches!(
        &tx.extension,
        ExtensionTx::PruebaAlmacenamiento {
            operacion: zx_core::OperacionAlmacenamiento::CertificadoPeso { .. }
        }
    )
}

/// PD-1f · F2/F3 · operación `0x09` de una tx, si la lleva.
pub(super) fn operacion_certificado_peso(tx: &Tx) -> Option<&zx_core::OperacionAlmacenamiento> {
    match &tx.extension {
        ExtensionTx::PruebaAlmacenamiento { operacion } => match operacion {
            zx_core::OperacionAlmacenamiento::CertificadoPeso { .. } => Some(operacion),
            _ => None,
        },
        _ => None,
    }
}

/// PD-1f · F2 · ventana `n` declarada por un `0x09` (primeros 8 bytes big-endian del cuerpo).
pub(super) fn ventana_de_certificado_peso(op: &zx_core::OperacionAlmacenamiento) -> Option<u64> {
    let zx_core::OperacionAlmacenamiento::CertificadoPeso { bytes, .. } = op else {
        return None;
    };
    let mut arreglo = [0u8; 8];
    arreglo.copy_from_slice(bytes.get(..8)?);
    Some(u64::from_be_bytes(arreglo))
}

/// TB-1c · C7/N3 · `(ventana, huella siguiente)` declaradas por un `0x09`, para el evento
/// `certificado_tabla_no_derivada`.
pub(super) fn ventana_y_huella_de_certificado_peso(
    op: &zx_core::OperacionAlmacenamiento,
) -> Option<(u64, [u8; 32])> {
    let zx_core::OperacionAlmacenamiento::CertificadoPeso { bytes, .. } = op else {
        return None;
    };
    let n = u64::from_be_bytes(<[u8; 8]>::try_from(bytes.get(..8)?).ok()?);
    let huella = <[u8; 32]>::try_from(bytes.get(40..72)?).ok()?;
    Some((n, huella))
}

/// PD-1f · F3 · ¿el error de `aplicar_certificado_peso_con_undo` significa «falta el paso anterior»
/// (tabla comprometida desconocida, o el ancla/encadenado que ese paso fijaría)? Un error de
/// tabla/encadenado se deposita; cualquier otro (firma, quórum, ventana, bytes) se descarta.
fn es_fuera_de_orden_peso(e: &zx_consensus::transicion::ErrorTransicion) -> bool {
    use zx_consensus::transicion::ErrorTransicion as E;
    use zx_votos::peso::MotivoPeso;
    matches!(
        e,
        E::ErrCertificadoPesoTablaDesconocida
            | E::ErrCertificadoPesoMotivo(MotivoPeso::Encadenado)
            | E::ErrCertificadoPesoMotivo(MotivoPeso::Ancla)
            | E::ErrCertificadoPesoMotivo(MotivoPeso::TablaNoDerivada)
    )
}

/// PD-1f · F1/F2 · resultado de verificar un `0x09` suelto sobre el estado de verificación.
enum ResultadoPeso {
    /// El certificado se aplicó: la finalidad de verificación avanzó a `(n, h)`.
    Aplicado(u64, BlockHash),
    /// Falta el paso anterior (tabla o encadenado): va al depósito de F3.
    FueraDeOrden,
    /// Cualquier otro error: se descarta.
    Descartado,
}

/// PD-1f · F3 · estimación del tamaño en memoria de una tx `0x09` retenida (cota superior por
/// campos), análoga a [`tamano_estimado_paso`].
fn tamano_estimado_tx_peso(tx: &Tx) -> usize {
    match &tx.extension {
        ExtensionTx::PruebaAlmacenamiento {
            operacion: zx_core::OperacionAlmacenamiento::CertificadoPeso { bytes, .. },
        } => bytes.len().saturating_add(128),
        _ => std::mem::size_of::<Tx>(),
    }
}

/// RLJ-3a-2 · caché en memoria del ancla del diagnóstico: primer bloque PoST de la cadena
/// seleccionada **del nodo** para un terminal. Se calcula una vez y se guarda en memoria; se rehace
/// solo si el ancla cacheada deja de pertenecer a la cadena seleccionada. No escribe en el almacén
/// ni influye en ningún veredicto (`C-RLJ-TS-03`).
#[derive(Default)]
pub(super) struct CacheAnclaDiagnostico {
    pub(super) terminal: Option<BlockHash>,
    pub(super) hash_ancla: Option<BlockHash>,
    pub(super) par: Option<(u64, i64)>,
}

/// ECL-R2a-2 · D6 · tope de pasos de certificado retenidos fuera de orden.
pub(super) const MAX_PASOS_ANCLA_PENDIENTES: usize = 64;

/// ECL-R2a-2 · D6 · tope de bytes estimados de los pasos retenidos fuera de orden.
const MAX_BYTES_ANCLA_PENDIENTES: usize = 1 << 20;

/// Garantía de `clave` **promovida** en `slot`.
///
/// **Copia de `zx_cadena::cadena::activo_promovido`** (`crates/zx-cadena/src/cadena.rs`): misma
/// regla (activo + pendientes/créditos con `madura_en_slot <= slot`). B-112: el filtro
/// `con_garantia` del bucle usa esta cifra, no `Estado(padre)` a secas. **Las dos funciones deben
/// cambiar juntas** si cambia la regla de promoción.
pub(crate) fn garantia_promovida_en_slot(
    estado: &EstadoTransicion,
    clave: &zx_core::ClavePublica,
    slot: u64,
) -> zx_core::Amount {
    let Some(g) = estado.garantias.get(clave) else {
        return zx_core::Amount::CERO;
    };
    let mut total = g.activo;
    for p in g.pendientes.iter().chain(g.creditos.iter()) {
        if p.madura_en_slot.is_some_and(|s| s <= slot)
            && let Some(suma) = total.suma_comprobada(p.importe)
        {
            total = suma;
        }
    }
    total
}
