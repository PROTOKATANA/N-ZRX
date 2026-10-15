//! Cableado final del productor (PROD-3b): el bucle comprueba, depura, ensaya, firma y admite.
//!
//! El hilo productor **no** firma: manda una candidata sin sello y este módulo la autoriza con el
//! contexto del propio bucle. Regla única: ningún bloque propio se firma sin que el bucle haya
//! comprobado esa candidata con su propio contexto y haya ensayado exactamente los bytes que se
//! firman.
//!
//! Orden obligatorio de pasos ([`Nodo::procesar_candidata_propia`]):
//! 1. Guardas previas (eclipse enclavado, candidata atrasada): cero comprobación, cero firma.
//! 2. Comprobación propia con `verificar_candidata_para_firma` y los mismos contextos que
//!    `admitir_post_interno` (construcción común [`Nodo::contextos_verificacion`]).
//! 3. Depuración y ensayo (`depurar_candidata_post` + `Cadena::ensayar_post`).
//! 4. Si la depuración cambió el cuerpo, se vuelve a comprobar la candidata final. Se firma solo
//!    si el `pre_hash()` comprobado es el de los bytes que van al firmante; tras firmar se
//!    comprueba que el bloque sellado conserva ese `pre_hash`.
//! 5. Firma con el único `Firmante` del proceso, construido en el bucle.
//! 6. Admisión del bloque sellado por el camino de hoy (`procesar_post_propio` →
//!    `admitir_post_interno(…, true)`).

use std::collections::BTreeMap;
use std::sync::mpsc::Sender;
use std::time::Instant;

use ed25519_zebra::SigningKey;
use subspace_verification::PieceCheckParams;
use zx_core::BlockHash;
use zx_core::digest::PreHash;
use zx_core::wire_dag::BloqueDag;
use zx_dag::bloque_dag::ContextoDag;
use zx_post::cabecera_conjunta::{
    CandidataComprobada, EstadoCandidata, verificar_candidata_para_firma,
};
use zx_post::firmante::{Firmante, FirmanteError};
use zx_post::pot_rango::CachePotVerificada;
use zx_post::productor::ProductoFirmado;
use zx_post::productor_regimen::ErrorEnsayo;
use zx_post::servicio_pot::ServicioPot;

use super::{
    ControlPost, DepuracionPost, ErrorNodo, Nodo, PresupuestoIlimitado, RangoDev, ResultadoNodo,
    depurar_candidata_post, motivo_abstencion_texto, padres_dag_a_vec, post_de_candidata,
};
use crate::regimen::MsgBucle;

// Auxiliares solo de pruebas, en el hilo de la prueba (PROD-3b-3 §2.3): la comprobación y la
// firma corren en ese hilo, y los `static` compartidos se pisaban con las pruebas en paralelo.
#[cfg(test)]
thread_local! {
    /// Contador de llamadas a la comprobación de candidatas (2(a), 5 y rojo R6).
    static COMPROBACIONES_CANDIDATA: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    /// Último bloque sellado (solo pruebas): para `cabecera.verificar_sello()` sobre el mismo
    /// objeto que produjo el camino del producto.
    static ULTIMO_SELLADO: std::cell::RefCell<Option<BloqueDag>> =
        const { std::cell::RefCell::new(None) };
    /// Último valor de distancia que llegó al ensayo (solo `#[cfg(test)]`, rojo R3).
    static ULTIMA_DISTANCIA_ENSAYO: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    /// Última distancia de comprobación (solo `#[cfg(test)]`, para 2(a)).
    static ULTIMA_DISTANCIA_COMPROBACION: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

/// Cuenta de comprobaciones de candidatas en este hilo de prueba.
#[cfg(test)]
#[must_use]
pub fn contador_comprobaciones() -> usize {
    COMPROBACIONES_CANDIDATA.with(|c| c.get())
}

/// Pone a cero el contador de comprobaciones de este hilo de prueba.
#[cfg(test)]
pub fn reset_contador_comprobaciones() {
    COMPROBACIONES_CANDIDATA.with(|c| c.set(0));
}

/// Último bloque sellado en este hilo de prueba.
#[cfg(test)]
#[must_use]
pub fn ultimo_sellado() -> Option<BloqueDag> {
    ULTIMO_SELLADO.with(|s| s.borrow().clone())
}

/// Última distancia que llegó al ensayo en este hilo de prueba (rojo R3).
#[cfg(test)]
#[must_use]
pub fn ultima_distancia_ensayo() -> u64 {
    ULTIMA_DISTANCIA_ENSAYO.with(|d| d.get())
}

/// Última distancia de comprobación en este hilo de prueba (2(a)).
#[cfg(test)]
#[must_use]
pub fn ultima_distancia_comprobacion() -> u64 {
    ULTIMA_DISTANCIA_COMPROBACION.with(|d| d.get())
}

/// Clasificación de un error de [`zx_post::productor_regimen::firmar_regimen_tras_ensayo`]
/// (PROD-3b-2 §2.2): un rechazo no para el nodo; un fallo sí.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClasificacionFirma {
    /// Rechazo legítimo: `produccion_descartada`, el hilo sigue.
    Rechazo,
    /// Fallo real del firmante o del formato: `fallo_productor` y error.
    Fallo,
}

/// Clasifica un [`ErrorEnsayo`] sin tocar `zx-post`.
#[must_use]
pub fn clasificar_error_ensayo<E: std::error::Error + 'static>(
    e: &ErrorEnsayo<E>,
) -> ClasificacionFirma {
    match e {
        // El ensayo que no admite, `CandidataSellada` y `FirmanteError::ClaveNoCoincide` (un hilo
        // que manda el índice de otra clave) son rechazos.
        ErrorEnsayo::CandidataSellada | ErrorEnsayo::Ensayo(_) => ClasificacionFirma::Rechazo,
        ErrorEnsayo::Firmante(FirmanteError::ClaveNoCoincide) => ClasificacionFirma::Rechazo,
        // El fallo real del registro del firmante, `SelloInvalido` y el error de formato son fallos.
        ErrorEnsayo::Firmante(FirmanteError::Registro(_))
        | ErrorEnsayo::Firmante(FirmanteError::SelloInvalido)
        | ErrorEnsayo::Formato(_) => ClasificacionFirma::Fallo,
    }
}

/// Resultado del cableado contextual de una candidata propia.
#[derive(Debug)]
pub enum DestinoCandidata {
    /// El bloque sellado se admitió por el camino real.
    Admitido {
        /// `block_hash` **sellado** del bloque admitido (cambia al firmar por C-HDR-09).
        hash: BlockHash,
    },
    /// Rechazo legítimo: no se firmó; se anotó `produccion_descartada`.
    Descartada {
        /// Motivo del paso que la paró.
        motivo: String,
    },
    /// Eclipse enclavado: `bloque_propio_descartado`, sin comprobar nada.
    Eclipse,
    /// Candidata del terminal anterior: se ignora sin comprobar ni firmar.
    Atrasada,
    /// El firmante se abstuvo: `firmante_abstenido`, el hilo sigue.
    FirmanteAbstenido {
        /// Motivo de la abstención (texto del esquema).
        motivo: &'static str,
    },
    /// Se procesó y además alcanzó el límite del productor: el hilo debe parar.
    Parar,
}

/// Contextos de verificación de un bloque/candidata, los mismos que usa `admitir_post_interno`.
pub struct ContextosVerificacion<'a> {
    /// `ServicioPot` de verificación del terminal de los padres.
    pub servicio: &'a ServicioPot,
    /// Rango dev del perfil (`RangoDev(cadena_sr_dev())`).
    pub rango: RangoDev,
    /// Contexto de pieza de la historia.
    pub params_pieza: PieceCheckParams,
    /// Terminal resuelto por `terminal_de_padres`.
    pub terminal: BlockHash,
    /// Contexto DAG: el GHOSTDAG del terminal, o `ContextoTransicion` si aún no hay DAG.
    pub dag: CtxDag<'a>,
}

/// Contexto DAG de la verificación: prestado del terminal o construido para la transición.
pub enum CtxDag<'a> {
    /// GHOSTDAG real del terminal (ya hay al menos un bloque PoST).
    Ghost(&'a zx_dag::ghostdag::AlmacenGhostdag),
    /// Primer bloque de un terminal (todavía sin DAG).
    Transicion(zx_post::contexto_transicion::ContextoTransicion),
}

impl ContextoDag for CtxDag<'_> {
    fn es_bloque_validado(&self, h: &BlockHash) -> bool {
        match self {
            CtxDag::Ghost(d) => d.es_bloque_validado(h),
            CtxDag::Transicion(d) => d.es_bloque_validado(h),
        }
    }
    fn esta_en_el_pasado_de(
        &self,
        antepasado: &BlockHash,
        descendiente: &BlockHash,
    ) -> Result<bool, zx_dag::ErrorDag> {
        match self {
            CtxDag::Ghost(d) => d.esta_en_el_pasado_de(antepasado, descendiente),
            CtxDag::Transicion(d) => d.esta_en_el_pasado_de(antepasado, descendiente),
        }
    }
    fn slot_de_padre(&self, h: &BlockHash) -> Result<u64, zx_dag::ErrorDag> {
        match self {
            CtxDag::Ghost(d) => d.slot_de_padre(h),
            CtxDag::Transicion(d) => d.slot_de_padre(h),
        }
    }
    fn padre_seleccionado(
        &self,
        padres: &zx_core::PadresDag,
    ) -> Result<BlockHash, zx_dag::ErrorDag> {
        match self {
            CtxDag::Ghost(d) => d.padre_seleccionado(padres),
            CtxDag::Transicion(d) => d.padre_seleccionado(padres),
        }
    }
    fn es_terminal(&self, h: &BlockHash) -> bool {
        match self {
            CtxDag::Ghost(d) => d.es_terminal(h),
            CtxDag::Transicion(d) => d.es_terminal(h),
        }
    }
}

impl Nodo {
    /// Construcción **común** de los contextos de verificación (terminal, `ServicioPot`, DAG o
    /// `ContextoTransicion`, `RangoDev`, `params_pieza`). La usan `admitir_post_interno` y la
    /// comprobación de candidatas: no se duplica.
    pub fn contextos_verificacion(
        &mut self,
        terminal: BlockHash,
    ) -> ResultadoNodo<ContextosVerificacion<'_>> {
        self.asegurar_servicios_verificacion()?;
        self.contextos_verificacion_listos(terminal)
    }

    /// Igual que [`Self::contextos_verificacion`] sin crear servicios: para cuando el llamante ya
    /// llamó a `asegurar_servicios_verificacion` y necesita conservar `&self` después.
    pub fn contextos_verificacion_listos(
        &self,
        terminal: BlockHash,
    ) -> ResultadoNodo<ContextosVerificacion<'_>> {
        let servicio = self.servicios_verificacion.get(&terminal).ok_or_else(|| {
            ErrorNodo::Otro(format!(
                "verificación PoST sin ServicioPot para el terminal {terminal}"
            ))
        })?;
        let rango = RangoDev(self.cadena_sr_dev());
        let params_pieza = self.historia.params_pieza();
        // El primer bloque tras el corte de cada terminal se verifica antes de que `zx-cadena`
        // tenga ningún bloque PoST propio de ese terminal: `contexto_dag_de(terminal)` es `None`
        // y se usa `ContextoTransicion`. Para todo lo demás, el GHOSTDAG real de ese terminal.
        let dag = match self.cadena.contexto_dag_de(terminal) {
            Some(dag) => CtxDag::Ghost(dag),
            None => {
                let ctx = zx_post::contexto_transicion::ContextoTransicion::nuevo(
                    terminal,
                    self.n_dev_vigente(),
                    self.sr_dev_actual,
                    Vec::new(),
                )
                .map_err(|e| {
                    ErrorNodo::Otro(format!("ContextoTransicion del bloque de transición: {e}"))
                })?;
                CtxDag::Transicion(ctx)
            }
        };
        Ok(ContextosVerificacion {
            servicio,
            rango,
            params_pieza,
            terminal,
            dag,
        })
    }

    /// Procesa una `MsgProductor::Candidata` por la ruta nueva: comprobar, depurar, ensayar,
    /// firmar y admitir. `nodo.rs` solo la llama desde `atender_msg_productor`.
    #[expect(
        clippy::too_many_arguments,
        reason = "el mensaje del productor y el canal del bucle son la interfaz del cableado"
    )]
    pub fn procesar_candidata_propia(
        &mut self,
        id: u64,
        candidata: BloqueDag,
        instante_salida: Instant,
        clave_indice: u32,
        terminal: BlockHash,
        terminal_cambio: bool,
        tx_a_productor: &Sender<MsgBucle>,
    ) -> ResultadoNodo<DestinoCandidata> {
        // Guarda previa 1: candidata atrasada (otro terminal, id viejo). Cero comprobación.
        // Sigue sin contestar al hilo (ya recibió `CambiarTerminal`), pero deja constancia.
        if terminal_cambio {
            self.anotar_descarte(candidata.cabecera.slot, clave_indice, "terminal_cambiado")?;
            return Ok(DestinoCandidata::Atrasada);
        }
        // Guarda previa 2: eclipse enclavado. Cero comprobación, cero firma.
        // El campo `hash` de `bloque_propio_descartado` es el `block_hash` de la candidata sin
        // sello (API.md).
        if self.cadena.eclipse().is_some() {
            let hash = candidata.cabecera.block_hash();
            let evento = self
                .registro
                .evento("bloque_propio_descartado")
                .str("hash", &hash.to_string())
                .str("motivo", "eclipse");
            self.registro.escribir(evento, false)?;
            return Ok(DestinoCandidata::Eclipse);
        }

        let slot = candidata.cabecera.slot;
        let clave = self
            .claves
            .iter()
            .find(|c| c.indice == clave_indice)
            .cloned();
        let Some(clave) = clave else {
            self.anotar_descarte(slot, clave_indice, "sin_clave_productora")?;
            self.responder_continuar(id, tx_a_productor)?;
            return Ok(DestinoCandidata::Descartada {
                motivo: "sin_clave_productora".into(),
            });
        };

        // Pasos 2 a 5: una sola secuencia, la de `comprobar_depurar_ensayar_firmar`
        // (PROD-3b-3 §2.2). Aquí solo se traduce su resultado.
        let producto = match self.comprobar_depurar_ensayar_firmar(candidata, &clave.sk)? {
            Ok(p) => p,
            Err((motivo, ClasificacionFirma::Rechazo)) => {
                self.anotar_descarte(slot, clave_indice, &motivo)?;
                self.responder_continuar(id, tx_a_productor)?;
                return Ok(DestinoCandidata::Descartada { motivo });
            }
            Err((motivo, ClasificacionFirma::Fallo)) => {
                // Fallo real del registro del firmante, sello inválido o formato:
                // evento crítico `fallo_productor` y error, como hacía el hilo.
                // El caller (`atender_msg_productor`) envía `Parar` al ver el `Err`.
                return self
                    .fallo_productor(&motivo)
                    .map(|()| DestinoCandidata::Parar);
            }
        };
        let bloque = match producto {
            ProductoFirmado::Bloque(b, _r) => b,
            ProductoFirmado::Abstenido { motivo, .. } => {
                // El bucle escribe firmante_abstenido y el hilo sigue.
                let texto = motivo_abstencion_texto(motivo);
                let evento = self
                    .registro
                    .evento("firmante_abstenido")
                    .u64("slot", slot)
                    .str("motivo", texto);
                self.registro.escribir(evento, true)?;
                self.responder_continuar(id, tx_a_productor)?;
                return Ok(DestinoCandidata::FirmanteAbstenido { motivo: texto });
            }
        };
        let hash_sellado = bloque.cabecera.block_hash();
        #[cfg(test)]
        ULTIMO_SELLADO.with(|s| *s.borrow_mut() = Some(bloque.clone()));

        // Paso 6: admisión por el camino de hoy (procesar_post_propio → admitir_post_interno).
        match self.procesar_post_propio(
            id,
            bloque,
            instante_salida,
            clave_indice,
            terminal,
            tx_a_productor,
        ) {
            Ok(ControlPost::Continuar) => Ok(DestinoCandidata::Admitido { hash: hash_sellado }),
            Ok(ControlPost::Parar) => Ok(DestinoCandidata::Parar),
            Ok(ControlPost::Descartado) => Ok(DestinoCandidata::Eclipse),
            Err(e) => Err(e),
        }
    }

    /// Paso 2: `verificar_candidata_para_firma` + `verificar_reloj_post` con los contextos
    /// comunes. Devuelve `(CandidataComprobada, pre_hash)` o el motivo de rechazo.
    /// El `pre_hash` devuelto es [`CandidataComprobada::pre_hash()`] de esta comprobación.
    fn comprobar_candidata_local(
        &mut self,
        candidata: &BloqueDag,
    ) -> ResultadoNodo<Result<(CandidataComprobada, PreHash), String>> {
        #[cfg(test)]
        COMPROBACIONES_CANDIDATA.with(|c| c.set(c.get() + 1));
        let padres_declarados = padres_dag_a_vec(&candidata.cabecera.padres);
        let Some(terminal) = self.terminal_de_padres(&padres_declarados) else {
            return Ok(Err("terminal_no_resoluble".to_string()));
        };
        self.asegurar_servicios_verificacion()?;
        let ctxs = self.contextos_verificacion_listos(terminal)?;
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoIlimitado;
        let estado = verificar_candidata_para_firma(
            candidata,
            ctxs.servicio,
            &ctxs.dag,
            &ctxs.rango,
            u64::MAX,
            &mut cache,
            &mut presupuesto,
            Some(&ctxs.params_pieza),
        );
        let comprobada = match estado {
            EstadoCandidata::Comprobada(c) => c,
            EstadoCandidata::Invalida(m) => return Ok(Err(format!("invalida: {m:?}"))),
            EstadoCandidata::Pendiente(m) => return Ok(Err(format!("pendiente: {m:?}"))),
            EstadoCandidata::YaSellada => return Ok(Err("ya_sellada".to_string())),
        };
        // PROD-3c / C03: la copia aprobada es inmóvil. El cuerpo (txs y testigos) tiene que
        // cuadrar con `merkle_root` y `body_commitment` de la cabecera **antes** de ensayar o
        // firmar: un testigo alterado no puede usar el `pre_hash` de otra copia.
        if let Err(e) = zx_core::preimage::dag::comprobar_compromisos(
            &candidata.cabecera,
            candidata.txs(),
            candidata.testigos(),
        ) {
            return Ok(Err(format!("compromisos: {e}")));
        }
        // Después, verificar_reloj_post, como hace la admisión.
        if let Err(e) = self.verificar_reloj_post(candidata, ctxs.servicio, terminal) {
            return Ok(Err(format!("reloj: {e}")));
        }
        let pre_hash = comprobada.pre_hash();
        #[cfg(test)]
        ULTIMA_DISTANCIA_COMPROBACION.with(|d| d.set(comprobada.distancia()));
        Ok(Ok((comprobada, pre_hash)))
    }

    /// Anota `produccion_descartada` (ya existe, con slot, clave_indice y motivo).
    fn anotar_descarte(&self, slot: u64, clave_indice: u32, motivo: &str) -> ResultadoNodo<()> {
        let evento = self
            .registro
            .evento("produccion_descartada")
            .u64("slot", slot)
            .u64("clave_indice", u64::from(clave_indice))
            .str("motivo", motivo);
        self.registro.escribir(evento, false)?;
        Ok(())
    }

    /// Responde `Continuar`/`Parar` al hilo tras procesar una candidata.
    fn responder_continuar(&self, id: u64, tx_a_productor: &Sender<MsgBucle>) -> ResultadoNodo<()> {
        let continuar = self.limite_productor().is_none();
        let respuesta = if continuar {
            MsgBucle::Continuar { id }
        } else {
            MsgBucle::Parar
        };
        let _ = tx_a_productor.send(respuesta);
        Ok(())
    }

    /// Pieza común (PROD-3b-2 §2.1): depura el cuerpo y registra `cuerpo_depurado` /
    /// `cuerpo_depurado_respaldo`. La usan `procesar_candidata_propia` y `firmar_post_ensayado`.
    pub fn depurar_y_registrar(
        &self,
        candidata: &BloqueDag,
        distancia: u64,
    ) -> ResultadoNodo<DepuracionPost> {
        let depuracion = depurar_candidata_post(
            &self.cadena,
            candidata,
            distancia,
            self.params.max_cuerpo_bloque_bytes,
        )?;
        let mut por_motivo: BTreeMap<(&str, String), u64> = BTreeMap::new();
        for retirada in &depuracion.retiradas {
            let clase = crate::mempool::clase_de_operacion(&retirada.par.0).unwrap_or(
                match retirada.par.0.extension {
                    zx_core::ExtensionTx::Evidencia { .. } => "evidencia_post",
                    zx_core::ExtensionTx::Garantia { .. } => "garantia",
                    _ => "pago",
                },
            );
            *por_motivo
                .entry((clase, retirada.motivo.to_string()))
                .or_default() += 1;
        }
        for ((clase, motivo), cantidad) in por_motivo {
            let evento = self
                .registro
                .evento("cuerpo_depurado")
                .u64("slot", candidata.cabecera.slot)
                .str("clase", clase)
                .str("motivo", &motivo)
                .u64("quitadas", cantidad)
                .u64("quitadas_total", depuracion.retiradas.len() as u64)
                .u64("vueltas", depuracion.vueltas as u64)
                .u64("bytes_finales", depuracion.bytes_finales);
            self.registro.escribir(evento, false)?;
        }
        if depuracion.respaldo {
            let evento = self
                .registro
                .evento("cuerpo_depurado_respaldo")
                .u64("slot", candidata.cabecera.slot)
                .u64("cota", candidata.txs().len() as u64)
                .u64(
                    "quitadas_total",
                    candidata.txs().len().saturating_sub(1) as u64,
                )
                .str("motivo", "cota_depuracion");
            self.registro.escribir(evento, false)?;
        }
        Ok(depuracion)
    }

    /// Pieza común (PROD-3b-2 §2.1): ensaya exactamente el cuerpo final y solo entonces pide el
    /// sello seguro. Devuelve el error **con su tipo** para poder clasificarlo (§2.2).
    pub fn ensayar_y_firmar(
        &self,
        candidata: BloqueDag,
        distancia: u64,
        clave: &SigningKey,
        firmante: &mut Firmante<'_>,
    ) -> Result<ProductoFirmado, ErrorEnsayo<ErrorNodo>> {
        #[cfg(test)]
        ULTIMA_DISTANCIA_ENSAYO.with(|d| d.set(distancia));
        zx_post::productor_regimen::firmar_regimen_tras_ensayo(candidata, clave, firmante, |b| {
            let (_, descartes) = self
                .cadena
                .ensayar_post(&post_de_candidata(b, distancia)?)
                .map_err(|e| ErrorNodo::Otro(format!("ensayo final: {e}")))?;
            if descartes.is_empty() {
                Ok(())
            } else {
                Err(ErrorNodo::Otro(
                    "el ensayo final tiene descartes".to_string(),
                ))
            }
        })
    }

    /// PROD-2: puerta de cuerpo/firma disponible para el hilo cuando se cablee la candidata real.
    ///
    /// Mantiene las retiradas en su origen. La retirada permanente de cola queda pendiente
    /// de una interfaz que no expulse también dependientes (véase FALTA.md de la orden).
    ///
    /// # Errores
    /// Si falla el contexto, el respaldo, el registro de eventos o el firmante seguro.
    ///
    /// PROD-3b-2 §2.1: este método y el camino del producto ejecutan **el mismo código**
    /// ([`Self::depurar_y_registrar`] + [`Self::ensayar_y_firmar`]).
    pub fn firmar_post_ensayado(
        &self,
        candidata: &BloqueDag,
        distancia: u64,
        clave: &SigningKey,
        firmante: &mut Firmante<'_>,
    ) -> ResultadoNodo<ProductoFirmado> {
        let depuracion = self.depurar_y_registrar(candidata, distancia)?;
        self.ensayar_y_firmar(depuracion.candidata, distancia, clave, firmante)
            .map_err(|e| ErrorNodo::Otro(format!("firma tras ensayo: {e}")))
    }

    /// Pasos 2 a 5 del cableado para una candidata ya armada (bloque de transición):
    /// comprobar, depurar, (recomprobar si cambió el cuerpo), ensayar y firmar, con las
    /// **mismas** funciones que [`Self::procesar_candidata_propia`].
    ///
    /// Devuelve el producto firmado, o el motivo con su clasificación (§2.2) si no se firmó.
    pub fn comprobar_depurar_ensayar_firmar(
        &mut self,
        candidata: BloqueDag,
        clave: &SigningKey,
    ) -> ResultadoNodo<Result<ProductoFirmado, (String, ClasificacionFirma)>> {
        let (comprobada, pre_hash_comprobado) = match self.comprobar_candidata_local(&candidata)? {
            Ok(par) => par,
            Err(motivo) => return Ok(Err((motivo, ClasificacionFirma::Rechazo))),
        };
        let mut distancia = comprobada.distancia();
        let mut pre_hash_final = pre_hash_comprobado;
        let depuracion = match self.depurar_y_registrar(&candidata, distancia) {
            Ok(d) => d,
            Err(e) => {
                return Ok(Err((
                    format!("depuracion: {e}"),
                    ClasificacionFirma::Rechazo,
                )));
            }
        };
        let final_candidata = depuracion.candidata;
        let cuerpo_cambio = final_candidata.cabecera.pre_hash() != candidata.cabecera.pre_hash();
        if cuerpo_cambio {
            match self.comprobar_candidata_local(&final_candidata)? {
                Ok((comprobada_final, pre)) => {
                    distancia = comprobada_final.distancia();
                    pre_hash_final = pre;
                }
                Err(motivo) => return Ok(Err((motivo, ClasificacionFirma::Rechazo))),
            }
        }
        if final_candidata.cabecera.pre_hash() != pre_hash_final {
            return Ok(Err((
                "pre_hash_no_coincide_con_los_bytes_firmados".to_string(),
                ClasificacionFirma::Rechazo,
            )));
        }
        let registro_firmante = self.registro_firmante.as_ref().ok_or_else(|| {
            ErrorNodo::Otro("firma contextual sin registro de firmante".to_string())
        })?;
        let mut firmante = Firmante::nuevo(registro_firmante);
        match self.ensayar_y_firmar(final_candidata, distancia, clave, &mut firmante) {
            Ok(ProductoFirmado::Bloque(b, r)) => {
                if b.cabecera.pre_hash() != pre_hash_final {
                    return Ok(Err((
                        "pre_hash_no_preservado_tras_sello".to_string(),
                        ClasificacionFirma::Rechazo,
                    )));
                }
                Ok(Ok(ProductoFirmado::Bloque(b, r)))
            }
            Ok(abstenido @ ProductoFirmado::Abstenido { .. }) => Ok(Ok(abstenido)),
            Err(e) => {
                let motivo = format!("firma_tras_ensayo: {e}");
                let clase = clasificar_error_ensayo(&e);
                Ok(Err((motivo, clase)))
            }
        }
    }
}
