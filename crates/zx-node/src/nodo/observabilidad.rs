//! Pieza O (MAP-1): registro estructurado y resúmenes de estado.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    Arc, BlockHash, BloqueRed, ContadoresAgregacion, ErrorNodo, EventoMotor, Instant, MotorVotos,
    Nodo, Registro, ResultadoNodo, TxId, bytes_de, compendio_de_almacen, escribir_fallo_productor,
    familia_de, hex, red, resumen_estado,
};

impl Nodo {
    /// ACTA-1 · R5 · un evento por decisión de acta, con su ventana, su `txid` y su causa.
    pub(super) fn registrar_decision_acta(&self, nombre: &str, n: u64, txid: TxId, causa: &str) {
        let _ = self.registro.escribir(
            self.registro
                .evento(nombre)
                .u64("n", n)
                .str("txid", &txid.to_string())
                .str("causa", causa),
            false,
        );
    }

    /// Campos del estado final para `reinicio_completo` y `parada` (`ORDEN-W07d` decisiones 1 y 2):
    /// `(punta, resumen_estado, n_bloques_dag, compendio_bloques, n_sectores, finalidad_votos_n,
    /// deuda_ausencia, quemado)`.
    ///
    /// `punta` es `mejor_punta().or(terminal())`, la misma expresión que `cambio_punta`; si no hay
    /// ninguna (fase PoW pura) queda vacía (falta de definición 3). `n_bloques_dag` es
    /// `Cadena::bloques_admitidos()`, la definición que ya usa el esquema v1. El compendio sale del
    /// almacén persistido, que incluye el génesis (falta de definición 1). `n_sectores` es
    /// `Estado::sectores.len()` del estado virtual (SR-1-2: prueba de que el alta llegó al estado).
    /// `finalidad_votos_n` es la instancia del punto de finalidad por votos como estado (FV-4b-N2).
    /// AUS-2b · N7 · `deuda_ausencia` es la del **estado aplicado** para la clave del nodo (la
    /// primera de `self.claves`) y `quemado` el total quemado de ese estado.
    #[expect(
        clippy::type_complexity,
        reason = "el estado final devuelve sus campos como tupla posicional; AUS-2b N7 añade dos"
    )]
    pub(super) fn campos_estado_final(
        &self,
    ) -> ResultadoNodo<(String, String, u64, String, u64, u64, i64, i64, u64, String)> {
        let punta = self.cadena.mejor_punta().or(self.cadena.terminal());
        let estado = self
            .cadena
            .estado_virtual()
            .map_err(|m| ErrorNodo::Otro(format!("estado virtual: {m}")))?;
        let resumen = resumen_estado(&estado);
        let n_bloques_dag = self.cadena.bloques_admitidos();
        let n_sectores = u64::try_from(estado.sectores.len()).unwrap_or(u64::MAX);
        let finalidad_votos_n = estado.finalidad_votos_n;
        let deuda_ausencia = self
            .claves
            .first()
            .and_then(|c| estado.deuda_ausencia.get(&c.pk).copied())
            .unwrap_or(0);
        let deuda_ausencia = i64::try_from(deuda_ausencia).unwrap_or(i64::MAX);
        let quemado = i64::try_from(estado.quemado).unwrap_or(i64::MAX);
        let compendio = compendio_de_almacen(&self.almacen).map_err(ErrorNodo::Almacen)?;
        // RA-2 · R6.4 · ancla de votos de la cadena (ventana y bloque sellado), si la hay.
        let (ancla_votos_n, ancla_votos_bloque) = match self.cadena.ancla_votos() {
            Some((n, h)) => (n, h.to_string()),
            None => (0u64, String::new()),
        };
        Ok((
            punta.map(|h| h.to_string()).unwrap_or_default(),
            resumen,
            n_bloques_dag,
            compendio,
            n_sectores,
            finalidad_votos_n,
            deuda_ausencia,
            quemado,
            ancla_votos_n,
            ancla_votos_bloque,
        ))
    }

    /// Escribe el evento crítico `parada` (`ORDEN-W07d` decisión 2) con el estado final calculado
    /// en ese momento. AUS-2b · N7 añade `deuda_ausencia` (clave del nodo) y `quemado` del estado.
    pub(super) fn escribir_parada(&self, motivo: &str) -> ResultadoNodo<()> {
        let (
            punta,
            resumen,
            n_bloques_dag,
            compendio,
            n_sectores,
            finalidad_votos_n,
            deuda_ausencia,
            quemado,
            ancla_votos_n,
            ancla_votos_bloque,
        ) = self.campos_estado_final()?;
        self.registro.escribir(
            self.registro
                .evento("parada")
                .str("motivo", motivo)
                .str("punta", &punta)
                .str("resumen_estado", &resumen)
                .u64("n_bloques_dag", n_bloques_dag)
                .u64("n_sectores", n_sectores)
                .u64("finalidad_votos_n", finalidad_votos_n)
                .i64("deuda_ausencia", deuda_ausencia)
                .i64("quemado", quemado)
                .str("compendio_bloques", &compendio)
                .u64("ancla_votos_n", ancla_votos_n)
                .str("ancla_votos_bloque", &ancla_votos_bloque),
            true,
        )?;
        Ok(())
    }

    /// Registra en el resumen de estado un cambio de punta seleccionada (decisión 8 y 9), y
    /// republica el saludo de red (`ORDEN-W06d2` decisión 4) tanto si cambió la punta como si no:
    /// la altura PoW/las puntas PoST pueden cambiar sin que la punta *seleccionada* cambie (p. ej.
    /// un huérfano lateral que se resuelve).
    pub(super) fn registrar_cambio_de_punta(&mut self) -> Result<(), ErrorNodo> {
        self.vista_red
            .actualizar_estado(self.construir_estado_red());
        // RD-4b · P1: la tabla de pesos se refresca cuando cambia el ancla (no la punta), con el
        // espaciado de `T_par`. El instante se toma aquí y la decisión no lee ningún reloj.
        self.entregar_tabla_pesos(Instant::now());

        let punta_actual = self.cadena.mejor_punta().or(self.cadena.terminal());
        if punta_actual == self.ultima_punta_registrada {
            return Ok(());
        }
        self.ultima_punta_registrada = punta_actual;
        let estado = self
            .cadena
            .estado_virtual()
            .map_err(|m| ErrorNodo::Otro(format!("estado virtual: {m}")))?;
        let resumen = resumen_estado(&estado);
        // `ORDEN-W07a` decisión 4: profundidad de reorganización = bloques de la cadena
        // seleccionada anterior que no están en la nueva (0 si solo la extiende).
        let profundidad_reorg = punta_actual
            .map(|p| self.actualizar_cadena_seleccionada(p))
            .unwrap_or(0);

        let mut evento = self
            .registro
            .evento("cambio_punta")
            .str(
                "punta",
                &punta_actual.map(|h| h.to_string()).unwrap_or_default(),
            )
            .str("resumen_estado", &resumen)
            .u64("profundidad_reorg", profundidad_reorg);
        // `blue_score` solo existe para bloques del DAG (PoST); en fase PoW se omite (§0).
        if let Some(blue_score) = punta_actual.and_then(|h| self.cadena.blue_score(&h)) {
            evento = evento.u64("blue_score", blue_score);
        }
        // ECL-R2a · D4 · el resumen de estado deja constancia del eclipse (modo detenido).
        if let Some(eclipse) = self.cadena.eclipse() {
            evento = evento
                .str("modo", "detenido")
                .u64("eclipse_n", eclipse.n_ancla)
                .str("eclipse_h", &hex(eclipse.h_ancla.as_bytes()))
                .u64("eclipse_n_certificado", eclipse.n_certificado)
                .str(
                    "eclipse_h_certificado",
                    &hex(eclipse.h_certificado.as_bytes()),
                )
                .u64("eclipse_profundidad", eclipse.profundidad);
        }
        self.registro.escribir(evento, false)?;
        Ok(())
    }

    pub(super) fn registrar_eventos_certificados_pendientes(&mut self) {
        let eventos = self
            .motor_votos
            .as_mut()
            .map(MotorVotos::drenar_eventos_certificados_peso)
            .unwrap_or_default();
        for (n, causa) in eventos {
            let tipo = if causa == "formado_tras_cierre" {
                "certificado_peso_formado_tras_cierre"
            } else {
                "certificado_peso_pendiente_soltado"
            };
            let evento = self.registro.evento(tipo).u64("n", n).str("causa", causa);
            let _ = self.registro.escribir(evento, false);
        }
    }

    /// A5-c-2b · X8 · escribe **un** `agregacion_ventana` con las métricas del motor para `n` y los
    /// contadores de la ventana; después reinicia los contadores para la siguiente.
    pub(super) fn escribir_evento_agregacion_ventana(&mut self, n: u64) {
        let metricas = self
            .motor_votos
            .as_ref()
            .and_then(MotorVotos::metricas_agregacion)
            .filter(|m| m.n == n)
            .cloned();
        let (
            sueltos_antes,
            sueltos_despues,
            peso_propio,
            n_subredes,
            agregados_validos,
            peso_elegido,
        ) = match &metricas {
            Some(m) => {
                let agregados_validos: u64 = m.subredes.iter().map(|s| s.agregados_validos).sum();
                let peso_elegido: u128 = m.subredes.iter().map(|s| s.peso_agregado_elegido).sum();
                (
                    m.sueltos_antes_de_publicar,
                    m.sueltos_despues_de_publicar,
                    m.peso_agregado_propio,
                    u64::try_from(m.subredes.len()).unwrap_or(u64::MAX),
                    agregados_validos,
                    peso_elegido,
                )
            }
            None => (0, 0, 0, 0, 0, 0),
        };
        let agn = self.agn;
        let e = self
            .registro
            .evento("agregacion_ventana")
            .u64("n", n)
            .u64("sueltos_antes_de_publicar", sueltos_antes)
            .u64("sueltos_despues_de_publicar", sueltos_despues)
            .str("peso_agregado_propio", &peso_propio.to_string())
            .u64("subredes", n_subredes)
            .u64("agregados_validos", agregados_validos)
            .str("peso_agregado_elegido", &peso_elegido.to_string())
            .u64("votos_recibidos", agn.votos_recibidos)
            .u64("votos_reenviados", agn.votos_reenviados)
            .u64("votos_ignorados", agn.votos_ignorados)
            .u64("votos_penalizados", agn.votos_penalizados)
            .u64("agregados_recibidos", agn.agregados_recibidos)
            .u64("agregados_reenviados", agn.agregados_reenviados)
            .u64("agregados_ignorados", agn.agregados_ignorados)
            .u64("agregados_penalizados", agn.agregados_penalizados);
        let _ = self.registro.escribir(e, false);
        self.agn = ContadoresAgregacion::default();
    }

    /// Escribe en el registro estructurado un evento del motor de votos (decisión 6).
    ///
    /// A1-D2b · W5 · `raiz_certificada` es la raíz de estado del certificado adoptado por el motor
    /// al cerrar la ventana (si la hubo): el evento `ventana_cerrada` la lleva cuando existe. El
    /// dato viene de `PasoVotos::certificado_peso`, ya disponible en el mismo camino, sin cambiar
    /// la variante de `EventoMotor` (que posee otra orden).
    pub(super) fn escribir_evento_votos(
        &self,
        evento: EventoMotor,
        raiz_certificada: Option<&str>,
    ) {
        let e = match evento {
            EventoMotor::VotoEmitido { n, clave, plazas } => self
                .registro
                .evento("voto_emitido")
                .u64("n", n)
                .str("clave", &clave)
                .u64("plazas", plazas),
            EventoMotor::CertificadoAdoptado {
                n,
                candidato,
                plazas,
                umbral,
            } => self
                .registro
                .evento("certificado_adoptado")
                .u64("n", n)
                .str("candidato", &candidato)
                .u64("plazas", plazas)
                .u64("umbral", umbral),
            EventoMotor::VotoSuprimido { n, clave, motivo } => self
                .registro
                .evento("voto_suprimido")
                .u64("n", n)
                .str("clave", &clave)
                .str("motivo", motivo),
            // REAN-2 · N5 · candado R4 liberado por `F`.
            EventoMotor::CandadoLiberado {
                n,
                clave,
                candidato_v,
            } => self
                .registro
                .evento("candado_liberado")
                .u64("n", n)
                .str("clave", &clave)
                .str("candidato_v", &candidato_v),
            EventoMotor::VotoPesoPropio {
                n,
                clave,
                peso,
                emitido,
                motivo,
            } => self
                .registro
                .evento("voto_peso_propio")
                .u64("n", n)
                .str("clave", &clave)
                .u64("peso", peso)
                .bool("emitido", emitido)
                .str("motivo", motivo),
            EventoMotor::VentanaAbierta {
                n,
                ancla,
                h_t_siguiente,
                candidato,
                slot,
            } => self
                .registro
                .evento("ventana_abierta")
                .u64("n", n)
                .str("ancla", &ancla)
                .str("h_t_siguiente", &h_t_siguiente)
                .str("candidato", &candidato)
                .u64("slot", slot),
            EventoMotor::VentanaCerrada {
                n,
                certificado,
                plazas,
                umbral,
                slot,
            } => {
                let e = self
                    .registro
                    .evento("ventana_cerrada")
                    .u64("n", n)
                    .bool("certificado", certificado)
                    .u64("plazas", plazas)
                    .u64("umbral", umbral)
                    .u64("slot", slot);
                match raiz_certificada {
                    Some(raiz) => e.str("raiz", raiz),
                    None => e,
                }
            }
            EventoMotor::AperturaDiferida { n, motivo } => self
                .registro
                .evento("votos_carga_pendiente")
                .u64("reloj_n", n)
                .str("motivo", motivo),
            EventoMotor::BaseCaducada { m, n } => self
                .registro
                .evento("base_caducada")
                .u64("m", m)
                .u64("n", n),
            // RA-2 · R1 · la ventana no abre en la fase activa; se espera a la siguiente.
            EventoMotor::RearranqueEnEspera { m, n, j, inicio } => self
                .registro
                .evento("rearranque_en_espera")
                .u64("m", m)
                .u64("n", n)
                .u64("j", j)
                .u64("inicio", inicio),
            // RA-2 · R1 · falta la instantánea del ciclo (o su contenido): no se abre ni firma.
            EventoMotor::RearranqueSinTabla { m, n, j } => self
                .registro
                .evento("rearranque_sin_tabla")
                .u64("m", m)
                .u64("n", n)
                .u64("j", j),
            // TB-1c-2 · X4 · N6 · el motor abandona una base provisional que la cadena no confirmó.
            EventoMotor::BaseProvisionalAbandonada { n, m_base, huella } => self
                .registro
                .evento("base_provisional_abandonada")
                .u64("n", n)
                .u64("m_base", m_base)
                .str("huella", &huella),
            // A1-D1-2 · M8 · aviso de discrepancia de raíz de estado al cerrar una ventana.
            EventoMotor::RaizEstadoDiscrepante {
                n,
                propia,
                certificada,
                raiz_mayor,
                peso_mayor,
                raiz_segunda,
                peso_segunda,
                raices_distintas,
                sin_quorum_por_division,
            } => {
                let e = self
                    .registro
                    .evento("raiz_estado_discrepante")
                    .u64("n", n)
                    .str("propia", &propia);
                let e = match certificada {
                    Some(raiz) => e.str("certificada", &raiz),
                    None => e,
                };
                e.str("raiz_mayor", &raiz_mayor)
                    .u64("peso_mayor", peso_mayor)
                    .str("raiz_segunda", &raiz_segunda)
                    .u64("peso_segunda", peso_segunda)
                    .u64("raices_distintas", raices_distintas)
                    .bool("sin_quorum_por_division", sin_quorum_por_division)
            }
        };
        let _ = self.registro.escribir(e, false);
    }

    /// `ORDEN-W07a` §1: `bloque_recibido`, la primera traza de un bloque llegado por red, **antes**
    /// de verificar nada. `par` se omite en gossip (el propagador no es computable en `zx-node`);
    /// se escribe para bloques de sincronización.
    pub(super) fn registrar_bloque_recibido(
        &self,
        bloque: &BloqueRed,
        origen: Option<libp2p::PeerId>,
    ) {
        let mut evento = self
            .registro
            .evento("bloque_recibido")
            .str("hash", &red::hash_de(bloque).to_string())
            .str("familia", familia_de(bloque))
            .u64("bytes", bytes_de(bloque));
        if let Some(par) = origen {
            evento = evento.str("par", &par.to_string());
        }
        let _ = self.registro.escribir(evento, false);
    }

    /// `ORDEN-W06d10-B` §1 bis: traza de diagnóstico de un bloque de red **ignorado** porque su
    /// aparente invalidez depende de la vista local (X1/X2/X3) o porque el fallo es local. No es un
    /// rechazo (no penaliza, no desconecta) pero queda visible con su motivo. `&self` para poder
    /// llamarse mientras un motivo de `self.cadena` sigue prestado.
    pub(super) fn trazar_bloque_vista_local(
        &self,
        hash: &BlockHash,
        familia: &str,
        motivo: &str,
        llegada: Instant,
    ) {
        let evento = self
            .registro
            .evento("bloque_red_vista_local")
            .str("hash", &hash.to_string())
            .str("familia", familia)
            .str("etapa", self.medicion.etapa)
            .str("motivo", motivo)
            .str("veredicto", "Ignorar")
            .u64("t_hasta_ignorar_ns", llegada.elapsed().as_nanos() as u64);
        let _ = self.registro.escribir(evento, false);
    }

    /// `ORDEN-W06d8` decisión 3: parada ordenada por fallo del hilo productor. Escribe el evento
    /// **crítico** `fallo_productor` con el motivo y devuelve error, de modo que `ejecutar`/`main`
    /// salen con código ≠ 0: nunca queda un nodo que valida pero ha dejado de producir sin decirlo.
    pub(super) fn fallo_productor(&self, motivo: &str) -> ResultadoNodo<()> {
        escribir_fallo_productor(&self.registro, motivo)
    }

    /// `ORDEN-W07a`: manija compartida del registro estructurado, para que la red escriba en él los
    /// eventos no críticos de par y de límite.
    #[must_use]
    pub fn registro(&self) -> Arc<Registro> {
        Arc::clone(&self.registro)
    }

    /// TX-6: emite como mucho un evento `mempool` por [`PERIODO_MUESTRA_MEMPOOL`], con los bytes y
    /// el número de transacciones admitidas, el máximo por par (tope `S_par` de DR-07), las
    /// huérfanas y los rechazos **acumulados** por tope local. No cambia ninguna regla de la
    /// mempool: solo publica lo que ella ya sabe.
    pub(super) fn muestrear_mempool_si_toca(&mut self) {
        let ahora = Instant::now();
        if self.proximo_muestreo.is_some_and(|t| ahora < t) {
            return;
        }
        self.proximo_muestreo = Some(ahora + PERIODO_MUESTRA_MEMPOOL);
        let (est, rej) = {
            let m = self.mempool.lock().unwrap_or_else(|p| p.into_inner());
            (m.estadisticas(), m.rechazos_limite())
        };
        let evento = self
            .registro
            .evento("mempool")
            .u64("txs", u64::try_from(est.n).unwrap_or(u64::MAX))
            .u64("bytes", u64::try_from(est.bytes).unwrap_or(u64::MAX))
            .u64("pares", u64::try_from(est.pares).unwrap_or(u64::MAX))
            .u64(
                "bytes_max_par",
                u64::try_from(est.bytes_max_par).unwrap_or(u64::MAX),
            )
            .u64(
                "huerfanas",
                u64::try_from(est.huerfanas).unwrap_or(u64::MAX),
            )
            .u64(
                "bytes_huerfanas",
                u64::try_from(est.bytes_huerfanas).unwrap_or(u64::MAX),
            )
            .u64("rechazos_limite", rej.total)
            .u64("rechazos_global", rej.global)
            .u64("rechazos_par_memoria", rej.par_memoria)
            .u64("rechazos_par_tasa", rej.par_tasa)
            .u64("rechazos_tarifa_minima", rej.tarifa_minima)
            .u64("rechazos_tarifa_rodante", rej.tarifa_rodante)
            .u64("rechazos_huerfanas", rej.huerfanas)
            .u64("rechazos_cuota_por_clave", rej.cuota_por_clave)
            .u64("rechazos_cuota_por_incidente", rej.cuota_por_incidente)
            .u64("rechazos_cuota_por_ventana", rej.cuota_por_ventana)
            .u64("rechazos_ventana_voto", rej.ventana_voto);
        let _ = self.registro.escribir(evento, false);
    }

    /// El resumen de estado (decisión 8) de la punta seleccionada actual, o del terminal si aún no
    /// hay puntas PoST.
    #[must_use]
    pub fn resumen_estado_actual(&self) -> Option<String> {
        let estado = self.cadena.estado_virtual().ok()?;
        Some(resumen_estado(&estado))
    }
}

/// Desglose de tiempos y etapa de la última llamada a `admitir_pow_interno`/`admitir_post_interno`
/// (`ORDEN-W07a` decisión 1: solo `Instant` alrededor de llamadas que ya existen).
#[derive(Clone, Copy, Default)]
pub(super) struct Medicion {
    /// Tiempo de la verificación de cabecera (PoW o cabecera conjunta).
    pub(super) cabecera_ns: u64,
    /// Tiempo de `Cadena::admitir` (GHOSTDAG y estado).
    pub(super) admision_ns: u64,
    /// Tiempo de `Almacen::admitir` (persistencia).
    pub(super) persistencia_ns: u64,
    /// Última etapa **iniciada**; punto de fallo para `bloque_red_rechazado`.
    pub(super) etapa: &'static str,
}

/// TX-6: periodo del evento periódico `mempool` (bytes, número de transacciones y rechazos por
/// tope). 1 s da una muestra por segundo sin ruido apreciable en el registro; el gasto es un
/// `lock` breve del mutex de la mempool y una línea por segundo.
const PERIODO_MUESTRA_MEMPOOL: std::time::Duration = std::time::Duration::from_secs(1);
