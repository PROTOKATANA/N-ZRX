//! Pieza M (MAP-1): cola de transacciones vista desde el nodo.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    Arc, BlockHash, BlockHeader, EstadoTransicion, ExtensionTx, Instant, Mempool, Nodo, Punto, Tx,
    TxId, hex, operacion_certificado_peso, txid, ventana_y_huella_de_certificado_peso,
};

impl Nodo {
    /// RN-1 · S5 · deja en el registro el rastro de una operación de sector o de almacenamiento que
    /// entra o se rechaza en la mempool, con identificador, clase, origen y (si lo hay) motivo.
    fn registrar_tx_mempool(
        &self,
        txid: &TxId,
        clase: &str,
        origen: &str,
        rechazo: Option<&crate::mempool::Rechazo>,
    ) {
        let mut evento = self
            .registro
            .evento(if rechazo.is_some() {
                "tx_rechazada"
            } else {
                "tx_admitida"
            })
            .str("txid", &txid.to_string())
            .str("clase", clase)
            .str("origen", origen);
        if let Some(r) = rechazo {
            evento = evento.str("motivo", &crate::mempool::motivo_de_rechazo(r));
        }
        let _ = self.registro.escribir(evento, false);
    }

    /// RN-1 · S5 · por cada entrada de `Cadena::descartes(hash)` de un bloque admitido, deja
    /// `tx_descartada` con bloque, índice, identificador, clase y motivo. Solo las operaciones de
    /// sector o de almacenamiento dejan rastro (los pagos corrientes descartados no).
    pub(super) fn registrar_transacciones_descartadas(&self, hash: &BlockHash, txs: &[Tx]) {
        let Some(descartes) = self.cadena.descartes(hash) else {
            return;
        };
        let entradas: Vec<(usize, TxId, String, bool)> = descartes
            .iter()
            .map(|d| {
                // TB-1c-2 · X5 · N3 · ¿el descarte fue por la tabla del `0x09`?
                let no_derivada = matches!(
                    &d.motivo,
                    zx_consensus::transicion::ErrorTransicion::ErrCertificadoPesoMotivo(
                        zx_votos::peso::MotivoPeso::TablaNoDerivada
                    )
                );
                (d.indice, d.txid, d.motivo.to_string(), no_derivada)
            })
            .collect();
        for (indice, txid_val, motivo, no_derivada) in entradas {
            let Some(clase) = txs.get(indice).and_then(crate::mempool::clase_de_operacion) else {
                continue;
            };
            let evento = self
                .registro
                .evento("tx_descartada")
                .str("bloque", &hash.to_string())
                .u64("indice", u64::try_from(indice).unwrap_or(u64::MAX))
                .str("txid", &txid_val.to_string())
                .str("clase", clase)
                .str("motivo", &motivo);
            let _ = self.registro.escribir(evento, false);
            // TB-1c-2 · X5 · N3 completo: un bloque **admitido** que descarta un `0x09` por
            // `TablaNoDerivada` también deja el evento, con su ventana y su huella (hasta ahora
            // solo salía al rechazar el bloque entero).
            if no_derivada
                && let Some((n, huella)) = txs
                    .get(indice)
                    .and_then(operacion_certificado_peso)
                    .and_then(ventana_y_huella_de_certificado_peso)
            {
                let evento = self
                    .registro
                    .evento("certificado_tabla_no_derivada")
                    .u64("n", n)
                    .str("huella", &hex(&huella));
                let _ = self.registro.escribir(evento, false);
            }
        }
    }

    /// RN-1 · S2/S5 · admite una transacción con operación de sector o de almacenamiento en la
    /// **mempool propia** y deja `tx_admitida` o `tx_rechazada`. Devuelve el resultado de la mempool
    /// para que el llamante decida si la difunde. `origen` ∈ {`propia`, `red`} solo etiqueta el
    /// rastro; la admisión es idéntica.
    pub(super) fn admitir_tx_en_mempool(
        &mut self,
        tx: Tx,
        testigos: Vec<Vec<u8>>,
        origen: &'static str,
    ) -> Result<crate::mempool::Admision, crate::mempool::Rechazo> {
        let clase = crate::mempool::clase_de_operacion(&tx);
        let txid_val = txid(&tx, self.cbid);
        let punto = {
            let m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
            m.punto_actual()
        };
        let resultado = {
            let mut m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
            m.admitir(None, tx, testigos, Instant::now(), punto)
        };
        if let Some(clase) = clase {
            match &resultado {
                Ok(crate::mempool::Admision::Admitida) => {
                    self.registrar_tx_mempool(&txid_val, clase, origen, None);
                }
                Err(r) => {
                    self.registrar_tx_mempool(&txid_val, clase, origen, Some(r));
                }
                // Duplicada/huérfana: ni admisión nueva ni rechazo.
                Ok(_) => {}
            }
        }
        resultado
    }

    /// La mempool compartida con el manejador de red (`ORDEN-TX3`).
    #[must_use]
    pub fn mempool(&self) -> Arc<std::sync::Mutex<Mempool>> {
        Arc::clone(&self.mempool)
    }

    /// Estado base de la mempool: el `Estado(past(punta))` de la cadena **seleccionada**.
    ///
    /// Se usa `estado_post` (una búsqueda en el mapa de estados cacheados, O(log n)) y **no**
    /// `estado_virtual()`, que reconstruye el mergeset del DAG con `aplicar_fusion` en cada
    /// llamada: `rebasear_mempool` corre tras **cada** bloque y reconstruir el mergeset entero cada
    /// vez fue una regresión de rendimiento real (los tests de nodo completo dejaron de terminar).
    pub(super) fn estado_base_mempool(&self) -> EstadoTransicion {
        // En fase PoW la cadena seleccionada es el historial PoW lineal, que puede no haberse
        // registrado aún en `ultima_cadena_seleccionada`; se toma como punta el último PoW.
        let punta = self
            .ultima_cadena_seleccionada
            .last()
            .copied()
            .or_else(|| self.historial_pow.last().map(BlockHeader::block_hash));
        if let Some(h) = punta
            && let Some(e) = self.cadena.estado_post(&h)
        {
            return e.clone();
        }
        self.cadena.estado_terminal().clone()
    }

    /// Punto del estado base vigente: altura en fase PoW, slot con terminal fijo o en PoST.
    pub(super) fn punto_de_estado_virtual(&self) -> Punto {
        let e = self.estado_base_mempool();
        if e.terminal.is_some() || e.fase == zx_consensus::transicion::Fase::PoST {
            Punto::Slot(e.slot)
        } else {
            Punto::Altura(e.altura)
        }
    }

    /// Rebasa la mempool al estado del terminal seleccionado (`ORDEN-TX3`, TX-R-14).
    pub(super) fn rebasear_mempool(&mut self) {
        let estado = self.estado_base_mempool();
        let punto = self.punto_de_estado_virtual();
        let evidencias = self
            .mempool
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .evidencias_entre_ventanas();
        let plazo = u64::try_from(estado.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
        // El dueño calcula con el evaluador de Cadena, fuera del mutex de cola.
        let hechos = evidencias
            .into_iter()
            .filter_map(|(id, a, b)| {
                self.cadena
                    .hecho_voto_entre_ventanas(&a, &b, plazo)
                    .map(|h| (id, h))
            })
            .collect();
        let retiradas = {
            let mut m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
            m.rebasear_con_hechos(estado.clone(), hechos, Instant::now(), punto)
        };
        self.reconciliar_retiradas_evidencia(retiradas, &estado);
    }

    /// EV-2/EV-1b: prepara únicamente las evidencias existentes o que se van a recuperar.
    pub(super) fn hechos_para_mempool(
        &self,
        estado: &EstadoTransicion,
        txs: &[(Tx, Vec<Vec<u8>>)],
    ) -> std::collections::BTreeMap<TxId, zx_consensus::transicion::HechoVoto> {
        let mut evidencias = self
            .mempool
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .evidencias_entre_ventanas();
        evidencias.extend(
            txs.iter().filter_map(|(tx, _)| {
                if let ExtensionTx::PruebaAlmacenamiento {
                    operacion:
                        zx_core::OperacionAlmacenamiento::EvidenciaVotosPeso { voto1, voto2, .. },
                } = &tx.extension
                    && voto1.n != voto2.n
                {
                    Some((txid(tx, self.cbid), *voto1, *voto2))
                } else {
                    None
                }
            }),
        );
        let plazo = u64::try_from(estado.parametros_sector.plazo_slots).unwrap_or(u64::MAX);
        evidencias
            .into_iter()
            .filter_map(|(id, a, b)| {
                self.cadena
                    .hecho_voto_entre_ventanas(&a, &b, plazo)
                    .map(|h| (id, h))
            })
            .collect()
    }

    /// Compatibilidad para la prueba DG-ACTA de un archivo asignado a PROD-2.
    #[cfg(test)]
    #[expect(
        clippy::expect_used,
        reason = "adaptador de un fixture con bloque ya admitido"
    )]
    pub(super) fn actualizar_mempool_tras_bloque(&mut self, txs: &[Tx]) {
        let hash = self
            .cadena
            .mejor_punta()
            .or_else(|| self.cadena.mejor_punta_pow())
            .expect("el fixture tiene un bloque admitido");
        let cuerpo = self
            .cadena
            .bloque(&hash)
            .expect("bloque del fixture")
            .txs()
            .to_vec();
        debug_assert!(txs.iter().all(|tx| cuerpo.iter().any(|(t, _)| t == tx)));
        let txs: Vec<_> = cuerpo.iter().map(|(t, _)| t.clone()).collect();
        let testigos: Vec<_> = cuerpo.iter().map(|(_, w)| w.clone()).collect();
        self.actualizar_mempool_tras_bloque_con_recibo(hash, &txs, &testigos, None);
    }

    /// EV-2: los tres caminos entregan el bloque admitido y sus testigos al mismo recibo.
    pub(super) fn actualizar_mempool_tras_bloque_con_recibo(
        &mut self,
        hash: BlockHash,
        txs: &[Tx],
        testigos: &[Vec<Vec<u8>>],
        peer: Option<libp2p::PeerId>,
    ) {
        let recibo = crate::mempool::ReciboBloque {
            hash,
            peer,
            txs: txs.iter().cloned().zip(testigos.iter().cloned()).collect(),
            descartes: self.cadena.descartes(&hash).unwrap_or_default().to_vec(),
        };
        let estado = self.estado_base_mempool();
        let punto = self.punto_de_estado_virtual();
        let hechos = self.hechos_para_mempool(&estado, &recibo.txs);
        let (readmisiones, retiradas, protegidas) = {
            let mut m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
            let mut protegidas = m.tomar_protecciones_evidencia();
            let (r, retiradas) =
                m.actualizar_tras_bloque(estado.clone(), hechos, &recibo, Instant::now(), punto);
            protegidas.extend(m.tomar_protecciones_evidencia());
            (r, retiradas, protegidas)
        };
        self.reconciliar_retiradas_evidencia(retiradas, &estado);
        for r in readmisiones {
            let (evento, causa) = match r.resultado {
                Ok(crate::mempool::Admision::Admitida | crate::mempool::Admision::Duplicada) => {
                    ("tx_descartada_devuelta_cola", String::new())
                }
                Ok(crate::mempool::Admision::Huerfana) => {
                    ("tx_readmision_fallida", "huerfana".to_owned())
                }
                Err(causa) => ("tx_readmision_fallida", format!("{causa:?}")),
            };
            let _ = self.registro.escribir(
                self.registro
                    .evento(evento)
                    .str("bloque", &hash.to_string())
                    .u64("indice", r.indice as u64)
                    .str("txid", &r.txid.to_string())
                    .str("clase", r.clase)
                    .str("motivo", &r.motivo.to_string())
                    .str("causa", &causa),
                false,
            );
        }
        for id in protegidas {
            let _ = self.registro.escribir(
                self.registro
                    .evento("evidencia_protegida_desalojo")
                    .str("txid", &id.to_string()),
                false,
            );
        }
    }
}
