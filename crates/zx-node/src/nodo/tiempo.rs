//! Pieza T (MAP-1): reloj local, servicios de verificación del PoT y calendario.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    BlockHash, BloqueDag, ErrorNodo, InstantaneaPot, MAX_BUNDLES_POT, Nodo, PadresDag, ServicioPot,
};

impl Nodo {
    /// Reloj local en segundos desde la época Unix (`C-TS-04`: nunca una hora de red). En tests
    /// puede inyectarse con [`Self::reloj_local_simulado`] para probar X1 sin depender del reloj
    /// real de la máquina.
    pub(super) fn reloj_local(&self) -> i64 {
        #[cfg(test)]
        if let Some(t) = self.reloj_local_simulado {
            return t;
        }
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
        .unwrap_or(i64::MAX)
    }

    pub(super) fn asegurar_servicios_verificacion(&mut self) -> Result<(), ErrorNodo> {
        for terminal in self.cadena.terminal_candidatos() {
            if let std::collections::btree_map::Entry::Vacant(e) =
                self.servicios_verificacion.entry(terminal)
            {
                let servicio = if self.perfil_red.reloj_activo {
                    ServicioPot::nuevo_con_reloj(
                        terminal,
                        self.perfil_red.reloj.estado_inicial(),
                        4096,
                    )
                } else {
                    ServicioPot::nuevo(terminal, self.n_dev, 4096)
                }
                .map_err(|err| ErrorNodo::Otro(format!("ServicioPot de verificación: {err}")))?;
                e.insert(servicio);
            }
        }
        Ok(())
    }

    pub(super) fn cadena_sr_dev(&self) -> u64 {
        // El `SR_dev` no vive en `Cadena`; el nodo lo trae de la CLI y lo guarda aquí mismo.
        self.sr_dev_actual
    }

    /// `N_dev` vigente del productor: con el reloj activo es `T0·n_iter` (el `N(s)` inicial);
    /// sin él, el `N_dev` de la CLI. El servicio de verificación usa el mismo valor.
    pub(super) fn n_dev_vigente(&self) -> u64 {
        if self.perfil_red.reloj_activo {
            self.perfil_red.reloj.estado_inicial().iteraciones()
        } else {
            self.n_dev
        }
    }

    /// Mantiene al día el `ServicioPot` de verificación **de `terminal`** (decisión 7 de
    /// `ORDEN-W06a`; por terminal desde `ORDEN-W06d7` decisión 5): inserta la salida y el portador
    /// **de este bloque**, sin recalcular el PoT. El flujo es único y global dentro de cada terminal
    /// (D-P10), así que si el slot ya estaba cubierto por otra rama/hermano **del mismo terminal**,
    /// solo se comprueba que coincide (defensa; nunca debería discrepar: lo impediría antes
    /// `ContextoTransicion`/H2 en la ruta de producción, pero este servicio de verificación no pasa
    /// por ahí).
    pub(super) fn actualizar_servicio_verificacion(
        &mut self,
        terminal: BlockHash,
        bloque: &BloqueDag,
    ) -> Result<(), ErrorNodo> {
        let Some(servicio) = self.servicios_verificacion.get_mut(&terminal) else {
            return Err(ErrorNodo::Otro(
                "ServicioPot de verificación ausente tras el terminal".to_string(),
            ));
        };
        let slot = bloque.cabecera.slot;
        let salida = bloque.cabecera.pot_output;
        let hash = bloque.cabecera.block_hash();
        let bundles = bloque.justificacion.bundles();
        // W08c: un bloque con `d = slot(B) − slot(sp) = 0` (cota de slot no estricta de
        // `C-HDR-05`/`C-FLU-02`, verificado por `pot_rango`) tiene la justificación **vacía** y
        // ningún portador propio. La salida de su slot ya la registró el padre seleccionado del
        // mismo slot (el flujo PoT es único y global, D-P10); aquí solo se comprueba que coincide.
        // Antes de W08c esta función devolvía un `ErrorNodo::Otro` fatal («sin portadores en su
        // justificación») y tumbaba al nodo en cuanto producía o admitía un `d = 0`.
        if let Some(portador) = bundles.last().copied() {
            // `ORDEN-W06d9` (causa de origen del `fallo_productor` de W07b): la justificación de un
            // bloque PoST trae, **ya verificados**, los portadores de `(slot(sp), slot]`; su longitud
            // es `slot - slot(sp)` y su i-ésimo portador pertenece al slot `slot - n + 1 + i`. Antes
            // solo se registraba el último (el del propio bloque), así que un bloque que saltaba
            // slots dejaba los intermedios como huecos permanentes —`insertar_calculado` no los
            // rellena y `avanzar` solo avanza hacia delante—, que más tarde `portadores_para`
            // denunciaba como `PortadorAusente` y el hilo productor convertía en `fallo_productor`.
            // Registrar el rango entero, con datos ya verificados, los elimina en el origen.
            if let Ok(n) = u64::try_from(bundles.len())
                && n >= 1
                && n <= slot
                && n <= MAX_BUNDLES_POT as u64
            {
                servicio
                    .registrar_portadores(slot - n, slot, bundles)
                    .map_err(|e| ErrorNodo::Otro(e.to_string()))?;
            }
            if slot <= servicio.slot_actual() {
                // `ORDEN-W06d4` decisión 3: antes, un slot `<= slot_actual()` se reconciliaba solo
                // con `salida_de`, que exige que el slot **ya tenga** una salida calculada. Si el
                // hueco lo dejó un salto de OTRA rama (`insertar_calculado` los permite a propósito,
                // D-P10), `salida_de` fallaba con `FueraDeVentana` aunque este bloque, ya admitido y
                // verificado, traiga su `pot_output` real — y el bloque se rechazaba sin entrar nunca
                // en `pasado()`: la causa confirmada de `Pot(PasadoIncompleto)` en un hijo que lo
                // declarara padre más tarde (`REVISION-W06d3.md`, hallazgo no resuelto).
                // `declarar_salida_pasada` reconcilia el hueco con el dato ya verificado y sigue
                // detectando una discrepancia real (D-P10) como error.
                servicio
                    .declarar_salida_pasada(slot, salida, portador)
                    .map_err(|e| ErrorNodo::Otro(e.to_string()))?;
            } else {
                servicio
                    .insertar_calculado(slot, salida, portador)
                    .map_err(|e| ErrorNodo::Otro(e.to_string()))?;
            }
        } else {
            let ancla_conocida = servicio.salida_de(slot).map_err(|e| {
                ErrorNodo::Otro(format!(
                    "bloque PoST {hash} con d = 0 y sin salida registrada del slot {slot}: {e}"
                ))
            })?;
            if ancla_conocida != salida {
                return Err(ErrorNodo::Otro(format!(
                    "bloque PoST {hash} con d = 0 y salida del slot {slot} discrepante (D-P10)"
                )));
            }
        }
        if servicio.slot_de(&hash).is_none() {
            servicio
                .registrar_validado_con_timestamp(hash, slot, bloque.cabecera.timestamp)
                .map_err(|e| ErrorNodo::Otro(e.to_string()))?;
        }
        // RL-2c: con el reloj de red activo, recalcula el calendario `N(s)` desde la **cadena
        // seleccionada** en `past(B)` (`C-RLJ-04`…`C-RLJ-06`). No depende del orden de llegada.
        self.recalcular_calendario_reloj(terminal)?;
        // VNT-1b · D1: aquí **no** se alimenta el cursor. `terminal` es el del bloque, que puede no
        // ser el seleccionado (cadenas con varios terminales y numeración de slots propia); el
        // cursor solo se sincroniza con el terminal seleccionado en el punto completo de
        // `atender_fronteras_votos`. Un bloque de otro terminal ni lo mueve ni lo reconcilia.
        Ok(())
    }

    /// `RL-2d` · recalcula el calendario de `T` y `N(s)` desde la **parte finalizada** de la cadena
    /// seleccionada en `past(B)` (`C-RLJ-04`/`C-RLJ-06`), nunca del pasado admitido localmente ni de
    /// la parte todavía reorganizable.
    ///
    /// La entrada es [`Cadena::cadena_seleccionada_post_finalizada`]: solo los bloques hasta el
    /// punto de finalidad de FIN-1, que es común a todos los nodos honestos. Por eso dos nodos cuyas
    /// cadenas seleccionadas difieren en los últimos `< F` slots (una bifurcación viva) calculan el
    /// mismo `N(s)`, y una reorganización dentro de `F` no cambia el calendario. Si el punto de
    /// finalidad aún no alcanza una frontera `f`, esa frontera no se procesa y el `N` se mantiene
    /// (decisión 3 de `ORDEN-RL2d`). Es idempotente: como la finalidad solo avanza, el calendario
    /// solo añade entradas. Registra un evento por cada frontera nueva observada.
    fn recalcular_calendario_reloj(&mut self, terminal: BlockHash) -> Result<(), ErrorNodo> {
        if !self.perfil_red.reloj_activo {
            return Ok(());
        }
        let params = self.perfil_red.reloj;
        let bloques = self.cadena.cadena_seleccionada_post_finalizada(terminal);
        if bloques.is_empty() {
            return Ok(());
        }
        let Ok((calendario, estado)) =
            zx_post::reloj_post::calendario_desde_cadena(&params, &bloques)
        else {
            return Ok(());
        };
        let Some(servicio) = self.servicios_verificacion.get_mut(&terminal) else {
            return Ok(());
        };
        let anteriores: Vec<u64> = servicio.calendario().iter().map(|(d, _)| *d).collect();
        let nuevos: Vec<(u64, u64)> = calendario
            .iter()
            .filter(|(desde, _)| *desde != 0 && !anteriores.contains(desde))
            .copied()
            .collect();
        servicio
            .fijar_calendario(calendario, estado)
            .map_err(|e| ErrorNodo::Otro(format!("fijar calendario del reloj: {e}")))?;
        for (desde, n) in nuevos {
            let frontera = desde.saturating_sub(params.a_epoch);
            let evento = self
                .registro
                .evento("reloj_ajuste")
                .u64("frontera", frontera)
                .u64("desde", desde)
                .u64("T", estado.t())
                .u64("n_iter", estado.n_iter())
                .u64("N", n);
            self.registro.escribir(evento, false)?;
        }
        Ok(())
    }

    /// RLJ-3a · verifica el segundo VDF y las reglas de timestamp PoST (parte B) cuando el
    /// **perfil de red** tiene el reloj activo. La puerta conjunta ya comprobó estructura, PoT y
    /// PoAS.
    ///
    /// La PMT se calcula sobre `C(B)` (pieza `reloj_marcas`, sin la punta virtual local) y es
    /// **permanente**; el FTL depende del reloj local y solo **retrasa** (RFT-27). La banda ya no es
    /// consenso: solo emite el evento `reloj_banda_diagnostico`.
    ///
    /// Una marca que no cabe en `i64` (mayor que `i64::MAX`) es **inválido permanente**: ningún nodo
    /// puede admitirla y retenerla como pendiente ocuparía la cola sin castigo (aceptado como regla
    /// en la segunda ronda, `ORDEN-RLJ3A2` §2.2).
    pub(super) fn verificar_reloj_post(
        &self,
        bloque: &BloqueDag,
        servicio: &ServicioPot,
        _terminal: BlockHash,
    ) -> Result<(), ErrorNodo> {
        if !self.perfil_red.reloj_activo {
            return Ok(());
        }
        let cabecera = &bloque.cabecera;
        let hash = cabecera.block_hash();
        let slot = cabecera.slot;
        let params = self.perfil_red.reloj;
        let invalido = |motivo: String| ErrorNodo::BloquePropioRechazado {
            hash,
            motivo,
            clasificacion: crate::rechazo::ClasificacionRechazo::Legitimo,
        };
        let pendiente = |motivo: String| ErrorNodo::BloquePropioRechazado {
            hash,
            motivo,
            clasificacion: crate::rechazo::ClasificacionRechazo::Pendiente,
        };

        // 1 · Segundo VDF: `v_j` recalculado desde la salida del **padre seleccionado**, que está en
        // `past(B)` ya validado (no se usa `slot(B) − 1`, que puede ser un hueco si se saltaron
        // slots).
        let sp = cabecera.padres.seleccionado();
        if let Some(slot_sp) = servicio.slot_de(&sp) {
            let ancla = servicio
                .salida_validada(slot_sp)
                .map_err(|m| pendiente(format!("ancla del segundo VDF: {m:?}")))?;
            match zx_post::reloj_post::verificar_v_j(
                cabecera.vdf_output,
                ancla,
                slot,
                params.i_iter,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(invalido(
                        "v_j del segundo VDF no coincide (C-RLJ-VDF-03)".to_string(),
                    ));
                }
                Err(e) => return Err(pendiente(format!("segundo VDF: {e}"))),
            }
        } else {
            return Err(pendiente(
                "slot del padre seleccionado ausente para el segundo VDF".to_string(),
            ));
        }

        // 2 · Parte B. Ventana `W_ts(B)` por la cadena seleccionada del bloque (pieza T): PMT
        // permanente y FTL diferible. El diagnóstico de banda no altera el veredicto.
        let ts = i64::try_from(cabecera.timestamp).map_err(|_| {
            invalido(format!(
                "timestamp {} fuera del dominio i64",
                cabecera.timestamp
            ))
        })?;
        let ts_params = self.perfil_red.timestamp;
        let marc = crate::reloj_marcas::ParametrosMarcas {
            m_ts: ts_params.m_ts,
            ftl: ts_params.ftl,
            banda_slot: ts_params.banda_slot,
            tau_num: params.tau_ref.num(),
            tau_den: params.tau_ref.den(),
        };
        let ventana = self
            .ventana_reloj_post(servicio, &cabecera.padres)
            .map_err(|h| pendiente(format!("ancestro de timestamp ausente: {h:?}")))?;
        let resultado = crate::reloj_marcas::verificar_receptor_con_ventana(
            &ventana,
            ts,
            slot,
            self.reloj_local(),
            &marc,
        );
        match resultado.veredicto {
            crate::reloj_marcas::VeredictoReceptor::Valido => {}
            crate::reloj_marcas::VeredictoReceptor::Invalido(
                crate::reloj_marcas::MotivoPermanente::PorDebajoDePmt { ts, pmt },
            ) => {
                return Err(invalido(format!(
                    "timestamp {ts} < PMT {pmt} (C-RLJ-TS-01)"
                )));
            }
            crate::reloj_marcas::VeredictoReceptor::Pendiente(
                crate::reloj_marcas::MotivoPendiente::FaltaContexto(h),
            ) => {
                return Err(pendiente(format!("ancestro de timestamp ausente: {h:?}")));
            }
            crate::reloj_marcas::VeredictoReceptor::Pendiente(
                crate::reloj_marcas::MotivoPendiente::DemasiadoFuturo { limite, .. },
            ) => {
                return Err(pendiente(format!(
                    "FTL del PoST: timestamp {ts} > {limite} (C-RLJ-TS-02, diferible)"
                )));
            }
        }
        // C-RLJ-TS-03: solo diagnóstico. Se escribe una vez por bloque admitido.
        if let crate::reloj_marcas::DiagnosticoBanda::Fuera {
            delta_segundos,
            banda_slot,
        } = resultado.diagnostico
        {
            let evento = self
                .registro
                .evento("reloj_banda_diagnostico")
                .str("hash", &format!("{hash:?}"))
                .u64("slot", slot)
                .i64("marca", ts)
                .i64("delta_s", delta_segundos)
                .u64("banda_s", banda_slot);
            self.registro.escribir(evento, false)?;
        }
        Ok(())
    }

    /// RLJ-3a · ventana `W_ts(B)` de `C-RLJ-TS-01` sobre la cadena seleccionada del bloque.
    ///
    /// Sigue el padre seleccionado **declarado** por cada cabecera; la admisión verifica que es el
    /// que calcula GHOSTDAG (`zx-dag/src/bloque_dag.rs:372-379`). No usa la punta virtual local.
    /// Devuelve la ventana completa o `FaltaContexto`.
    pub(super) fn ventana_reloj_post(
        &self,
        servicio: &ServicioPot,
        padres: &PadresDag,
    ) -> Result<crate::reloj_marcas::VentanaTs, BlockHash> {
        let terminal = servicio.terminal();
        let adaptador = crate::reloj_marcas::AdaptadorCadena::con_cadena_seleccionada(
            &self.cadena,
            &self.ultima_cadena_indice,
            self.ancla_diagnostica(terminal),
        );
        crate::reloj_marcas::ventana_cadena_seleccionada(
            &adaptador,
            &terminal,
            &padres.seleccionado(),
            self.perfil_red.timestamp.m_ts,
        )
        .map_err(|crate::reloj_marcas::FaltaContexto(h)| h)
    }

    /// RLJ-3a · el productor firma su hora entera si PMT y `FTL` lo permiten (§1 precisión 5).
    ///
    /// Consulta los mismos padres efectivos que firmará, nunca la punta local. La banda ya no
    /// interviene; el `slot` no entra en la cuenta de la marca.
    pub(super) fn timestamp_propio_post(
        &self,
        servicio: &ServicioPot,
        padres: &PadresDag,
    ) -> Option<u64> {
        if !self.perfil_red.reloj_activo {
            return u64::try_from(self.reloj_local()).ok();
        }
        let ventana = self.ventana_reloj_post(servicio, padres).ok()?;
        self.timestamp_para_ventana(ventana.marcas())
    }

    /// RLJ-3a · selector del productor sobre una ventana ya extraída (cableado a la pieza T).
    pub(super) fn timestamp_para_ventana(&self, ventana: &[(u64, i64)]) -> Option<u64> {
        let ahora = self.reloj_local();
        if !self.perfil_red.reloj_activo {
            return u64::try_from(ahora).ok();
        }
        let pmt = crate::reloj_marcas::pmt_de_marcas(ventana, self.perfil_red.timestamp.m_ts);
        let ts =
            crate::reloj_marcas::seleccionar_timestamp(ahora, pmt, self.perfil_red.timestamp.ftl)?;
        u64::try_from(ts).ok()
    }
}
