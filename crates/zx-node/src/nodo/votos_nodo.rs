//! Pieza V (MAP-1): votos del nodo y cola de operaciones v6.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    AGREGADORES_POR_SUBRED, Agregado, BTreeSet, BlockHash, CLASE_EVIDENCIA_PESO, Config,
    ConfigMotorVotos, CursorVotos, Digest, ErrorNodo, EstadoTransicion, EventoMotor, ExtensionTx,
    FinalidadEstado, G_SLOTS_VOTOS, IdDiferido, MotorVotos, Movimiento, Nodo, RecepcionAgregado,
    RecepcionVoto, RecepcionVotoSubred, Red, Reparto, ResultadoNodo, SalidaVerificada, Tx, TxId,
    VeredictoFinal, VistaConRaiz, W_REVEAL_SLOTS_VOTOS, apertura_ventana, cierre_ventana,
    deserializar_punto_control_peso, finalidad_estado_de, hex, padres_de_regimen, perfil, subred,
    tx_es_certificado_peso, txid, verificar_punto_control_peso,
};

#[cfg(test)]
use super::{ESTADO_VIRTUAL_RECONCILIACION, LOTES_AGREGADOS};

/// FV-4b-N3 · Clave Ed25519 propia dueña de una clave BLS de voto registrada en `estado`.
///
/// `None` si la clave BLS no está registrada o no pertenece a este nodo.
fn clave_dev_para_bls(
    claves: &[crate::claves::ClaveDev],
    estado: &zx_consensus::transicion::Estado,
    clave_bls: &[u8; 48],
) -> Option<crate::claves::ClaveDev> {
    let owner = estado
        .claves_voto
        .iter()
        .find(|(_, cv)| cv.clave_bls == *clave_bls)
        .map(|(ed, _)| *ed)?;
    claves.iter().find(|c| c.pk == owner).cloned()
}

/// AUS-2b · N1 · clase `0x08` `VotoPropio`: el nodo publica su voto propio cuando no consta.
pub(super) const CLASE_VOTO_PROPIO: u8 = 0x08;

/// PD-1e · E9 · clase `0x0A` `ActaPresencia`: acta de la ventana por peso sin quórum.
pub(super) const CLASE_ACTA_PESO: u8 = 0x0A;

/// FV-4b-N3-2 · tope del depósito de tx v6 pendientes (propias y ajenas) para que un emisor no
/// haga crecer la memoria. Con 4 nodos dev nunca se acerca; es una cota defensiva.
const MAX_V6_PENDIENTES: usize = 4096;

/// A5-c-2b · X8 · la subred declarada por un agregado serializado (offset fijo 232, `u16` BE), sin
/// necesidad de la tabla. `None` si el flujo es demasiado corto.
pub(super) fn subred_de_agregado(bytes: &[u8]) -> Option<u16> {
    let arr: [u8; 2] = bytes.get(232..234)?.try_into().ok()?;
    Some(u16::from_be_bytes(arr))
}

/// A5-c-2b · X8 · contadores de la **ventana abierta** para el evento `agregacion_ventana`: cuántos
/// votos de subred y agregados se recibieron, reenviaron, ignoraron y penalizaron. Se reinician al
/// escribir el evento de la ventana cerrada.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ContadoresAgregacion {
    /// Votos de subred recibidos.
    pub(super) votos_recibidos: u64,
    /// Votos de subred cuyo veredicto fue `Aceptar` (se reenvían).
    pub(super) votos_reenviados: u64,
    /// Votos de subred ignorados sin penalizar.
    pub(super) votos_ignorados: u64,
    /// Votos de subred penalizados.
    pub(super) votos_penalizados: u64,
    /// Agregados recibidos.
    pub(super) agregados_recibidos: u64,
    /// Agregados válidos (se reenvían).
    pub(super) agregados_reenviados: u64,
    /// Agregados ignorados sin penalizar.
    pub(super) agregados_ignorados: u64,
    /// Agregados penalizados.
    pub(super) agregados_penalizados: u64,
}

/// FV-4b-N3-2 · tx v6 `0x06`/`0x07` pendiente de inclusión.
///
/// A diferencia del `v6_pendientes` de FV-4b-N3 (que se consumía al meter la tx en un bloque), esta
/// entrada **sobrevive a la inclusión**: se retira solo cuando la operación se observa aplicada en el
/// estado, cuando vence su plazo o cuando su tabla ya no puede ser la de la ventana. Así, una tx
/// incluida en una rama que pierde no se pierde.
pub(super) struct PendienteV6 {
    /// `true` si es de este nodo (se vuelve a difundir); `false` si llegó de la red.
    pub(super) propia: bool,
    /// Clase: [`CLASE_VOTO_PROPIO`], [`CLASE_ACTA_PESO`] o [`CLASE_EVIDENCIA_PESO`].
    pub(super) clase: u8,
    /// Ventana/instancia `n`.
    pub(super) n: u64,
    /// PD-1e · E9 · dueños Ed25519 de los firmantes de un acta `0x0A` (vacío en las demás clases):
    /// el acta deja de incluirse cuando **todos** constan en `votantes_voto[n]` del estado base.
    pub(super) firmantes_acta: Vec<zx_core::ClavePublica>,
    /// Clave Ed25519 dueña de la operación (la que firma).
    pub(super) clave: zx_core::ClavePublica,
    /// Slot PoT mínimo de admisión (`0` = ya).
    pub(super) desde_slot: u64,
    /// Slot PoT máximo de admisión (`u64::MAX` = sin plazo).
    pub(super) hasta_slot: u64,
    /// Transacción firmada.
    pub(super) tx: Tx,
    /// Testigos Ed25519.
    pub(super) testigos: Vec<Vec<u8>>,
    /// Identidad para deduplicar.
    pub(super) txid: TxId,
    /// `true` si ya se difundió al menos una vez (para emitir `revelacion_enviada` una vez).
    pub(super) difundida: bool,
    /// VS-2 · V5 · `true` si ya se emitió `acta_peso_aplicada` para este acta.
    pub(super) acta_aplicada: bool,
}

/// FV-4b-N3-2 · metadatos de admisión de una tx v6 de voto propio, acta o evidencia:
/// `(clase, n, clave, desde_slot, hasta_slot)`. `None` para cualquier otra transacción.
///
/// AUS-2b · N1 · el voto propio se difunde e incluye en `[cierre(n) + G_slots, cierre(n) + W_reveal]`
/// (AV-11); su admisión de consenso es más ancha, pero el nodo no lo publica fuera de la ventana de
/// gracia.
pub(super) fn metadatos_v6(tx: &Tx) -> Option<(u8, u64, zx_core::ClavePublica, u64, u64)> {
    let ExtensionTx::PruebaAlmacenamiento { operacion } = &tx.extension else {
        return None;
    };
    match operacion {
        zx_core::OperacionAlmacenamiento::VotoPropio { clave, n, .. } => {
            let cierre = cierre_ventana(*n);
            Some((
                CLASE_VOTO_PROPIO,
                *n,
                *clave,
                cierre.saturating_add(G_SLOTS_VOTOS),
                cierre.saturating_add(W_REVEAL_SLOTS_VOTOS),
            ))
        }
        // PD-1e · E9 · el acta `0x0A` es admisible desde la apertura de su ventana hasta
        // `cierre(n) + W_REVEAL_SLOTS_VOTOS`; lleva `n` en los 8 primeros bytes de su cuerpo.
        zx_core::OperacionAlmacenamiento::ActaPresencia { clave, bytes } => {
            let n = u64::from_be_bytes(<[u8; 8]>::try_from(bytes.get(..8)?).ok()?);
            Some((
                CLASE_ACTA_PESO,
                n,
                *clave,
                apertura_ventana(n),
                cierre_ventana(n).saturating_add(W_REVEAL_SLOTS_VOTOS),
            ))
        }
        // PD-1e · E9 · la evidencia `0x0B` se encola sin plazo (como la `0x05`).
        zx_core::OperacionAlmacenamiento::EvidenciaVotosPeso { clave, voto1, .. } => {
            Some((CLASE_EVIDENCIA_PESO, voto1.n, *clave, 0, u64::MAX))
        }
        _ => None,
    }
}

/// AUS-2b · N4 · votos propios admisibles en `slot_objetivo`: en plazo (`[desde, hasta]`), no
/// aplicados en el estado base y con la clave BLS todavía registrada a nombre del firmante. Se
/// colocan **después** de la selección de la mempool y **antes** del certificado pendiente; se
/// reserva su espacio antes de pedir la cola. La deduplicación garantiza una sola por `(clave, n)`.
pub(super) fn votos_propios_para_bloque(
    pendientes: &[PendienteV6],
    estado_base: &EstadoTransicion,
    slot_objetivo: u64,
) -> Vec<(Tx, Vec<Vec<u8>>)> {
    let mut salida = Vec::new();
    // N4 · una sola por `(clave, n)`: dos entradas con el mismo par (p. ej. una tx re-firmada)
    // jamás van en el mismo bloque.
    let mut vistos: std::collections::BTreeSet<(zx_core::ClavePublica, u64)> =
        std::collections::BTreeSet::new();
    for p in pendientes.iter().filter(|p| p.clase == CLASE_VOTO_PROPIO) {
        if !vistos.insert((p.clave, p.n)) {
            continue;
        }
        if slot_objetivo < p.desde_slot || slot_objetivo > p.hasta_slot {
            continue;
        }
        if estado_base
            .votantes_voto
            .get(&p.n)
            .is_some_and(|votantes| votantes.contains(&p.clave))
        {
            continue;
        }
        // N4 · la clave BLS debe seguir registrada a nombre del firmante: si no, el consenso
        // rechazaría la operación y un bloque propio no puede llevar una operación inválida.
        let ExtensionTx::PruebaAlmacenamiento { operacion } = &p.tx.extension else {
            continue;
        };
        let zx_core::OperacionAlmacenamiento::VotoPropio { clave_bls, .. } = operacion else {
            continue;
        };
        if !zx_consensus::transicion::votos::clave_voto_admisible(
            estado_base,
            &p.clave,
            clave_bls,
            slot_objetivo,
        ) {
            continue;
        }
        salida.push((p.tx.clone(), p.testigos.clone()));
    }
    salida
}

/// AUS-2b · N4 · encaja los votos propios candidatos en el hueco que quede dentro del tope del
/// cuerpo, en orden y sin rebasarlo. Los que no caben quedan pendientes para el bloque siguiente.
pub(super) fn encajar_votos_propios(
    candidatos: Vec<(Tx, Vec<Vec<u8>>)>,
    presupuesto: u64,
    bytes_usados: u64,
) -> Vec<(Tx, Vec<Vec<u8>>)> {
    let mut salida = Vec::new();
    let mut usados = bytes_usados;
    for (tx, tst) in candidatos {
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, &tx, &tst);
        let bytes = buf.len() as u64;
        if usados.saturating_add(bytes) > presupuesto {
            break;
        }
        usados = usados.saturating_add(bytes);
        salida.push((tx, tst));
    }
    salida
}

/// PD-1f · F5 · contenido de una tabla del contrato en el formato que usa
/// `Estado::tablas_voto_contenido` (`Vec<ClaveTablaVoto>`). Solo se llama con tablas ya
/// verificadas; las claves que no midan 48 bytes (imposibles tras `verificar_punto_control_peso`)
/// se omiten.
pub(super) fn tabla_a_payload(tabla: &zx_votos::Tabla) -> Vec<zx_core::ClaveTablaVoto> {
    tabla
        .claves
        .iter()
        .filter_map(|c| {
            let clave_bls = <[u8; 48]>::try_from(c.clave.as_slice()).ok()?;
            Some(zx_core::ClaveTablaVoto {
                clave_bls,
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
        })
        .collect()
}

/// REAN-2 · N6 · Clasificación de **arranque/carga inicial** del reloj de votos.
///
/// Devuelve `Some("espera_reloj")` si `n <= m` (la base ya alcanzó esa ventana) y `None` cuando
/// procede avanzar. **Ya no existe la clase `hueco`:** con base `m` y `n > m + 1` se abre el intento
/// `n`, porque la reanudación R4 no espera a que el reloj sea contiguo. La clasificación no aplica a
/// una instancia viva: con `m+1` abierta y `n = m+2`, el motor debe cerrar `m+1` y adoptar su
/// certificado antes de decidir la apertura siguiente.
pub(crate) fn clase_arranque_votos(
    instancia_actual: Option<u64>,
    base_m: Option<u64>,
    n: u64,
) -> Option<&'static str> {
    if instancia_actual.is_some() {
        return None;
    }
    let m = base_m?;
    if n <= m { Some("espera_reloj") } else { None }
}

/// FV-4b-N1-2 · Retardo (en slots) del candidato de voto: el candidato de la ventana `n` se toma
/// del bloque PoST admitido de mayor slot `<= n·t_inst - LAG_CANDIDATO_VOTOS`, usando el slot de
/// **apertura** de la ventana (no el slot actual del nodo, que puede caer en cualquier punto de
/// ella según cuándo cada nodo descubra el cambio de ventana).
///
/// **Sin modelo ni medida que respalde el valor `4`** (`D-ZRX/SPEC.md` §0.1): queda anotado para
/// validar y no se usa para acreditar ninguna propiedad de seguridad ni de vivacidad mientras no
/// tenga esa validación.
pub(super) const LAG_CANDIDATO_VOTOS: u64 = 4;

/// ACTA-1 · R2/R3/R5 · decisión del productor sobre sus actas `0x0A`.
///
/// La decisión se calcula **al armar**, con el estado base del bloque y su slot, y es exactamente el
/// predicado de la transición real (`zx_consensus::transicion::votos::votantes_de_acta`): se omite
/// solo si el conjunto traducido **ya consta entero** en `votantes_voto[n]` (incluido el conjunto
/// vacío). Si falta la tabla o el mapa, se incluye y se registra (R3): la ignorancia nunca justifica
/// omitir. La lista auxiliar `firmantes_acta` ya no decide.
impl Nodo {
    pub(super) fn actas_peso_para_bloque(
        &self,
        estado_base: &EstadoTransicion,
        slot_objetivo: u64,
    ) -> Vec<(Tx, Vec<Vec<u8>>)> {
        let mut salida = Vec::new();
        for p in self
            .v6_pendientes
            .iter()
            .filter(|p| p.clase == CLASE_ACTA_PESO)
        {
            if slot_objetivo < p.desde_slot || slot_objetivo > p.hasta_slot {
                continue;
            }
            let ExtensionTx::PruebaAlmacenamiento { operacion } = &p.tx.extension else {
                continue;
            };
            let zx_core::OperacionAlmacenamiento::ActaPresencia { bytes, .. } = operacion else {
                continue;
            };
            match zx_consensus::transicion::votos::votantes_de_acta(
                estado_base,
                bytes,
                slot_objetivo,
            ) {
                // R3 · falta la tabla o el mapa: se incluye como candidata y queda el evento.
                None => {
                    self.registrar_decision_acta(
                        "acta_peso_incluida",
                        p.n,
                        p.txid,
                        "traduccion_desconocida",
                    );
                    salida.push((p.tx.clone(), p.testigos.clone()));
                }
                Some(votantes) => {
                    let ya = estado_base.votantes_voto.get(&p.n);
                    let consta_entera =
                        ya.is_some_and(|votantes_ya| votantes.is_subset(votantes_ya));
                    if consta_entera {
                        // R2 · la cadena la descartaría: no se incluye. Causa explícita.
                        let causa = if votantes.is_empty() {
                            "conjunto_vacio"
                        } else {
                            "consta_entera"
                        };
                        self.registrar_decision_acta("acta_peso_omitida", p.n, p.txid, causa);
                    } else {
                        self.registrar_decision_acta(
                            "acta_peso_incluida",
                            p.n,
                            p.txid,
                            "firmantes_nuevos",
                        );
                        salida.push((p.tx.clone(), p.testigos.clone()));
                    }
                }
            }
        }
        salida
    }
}

impl Nodo {
    /// FV-4b-N1 · Arranca la capa de votos **solo en `Red::Dev`** (FV-D08): deriva las claves BLS de
    /// voto de la semilla/índices, carga el punto de control externo si lo hay y activa la bandera
    /// de finalidad por votos en la cadena.
    /// FV-N6-C7 · abre el diario durable de voto reutilizando la condición previa
    /// `modo_limpio = almacen.longitud_registro() == 0` (nodo.rs954@a11). Un directorio
    /// verdaderamente nuevo aprovisiona el diario con `create_new`; un directorio previo sin diario
    /// **no** se interpreta como identidad nueva. Devuelve `(diario, motivo_observacion)`.
    fn abrir_diario_votos(&self) -> (Option<crate::votos::DiarioVotos>, Option<String>) {
        let ruta = self.dir_datos.join("votos.registro");
        if self.modo_limpio {
            match crate::votos::DiarioVotos::nueva(&ruta, self.cbid) {
                Ok(d) => return (Some(d), None),
                Err(crate::votos::ErrorDiario::YaExiste { .. }) => {
                    // Resto de un aprovisionamiento interrumpido: se reabre y valida, nunca se
                    // recrea en limpio para habilitar la firma.
                    match crate::votos::DiarioVotos::abrir(&ruta, self.cbid) {
                        Ok(d) => return (Some(d), None),
                        Err(e) => {
                            return (None, Some(format!("diario_existente_no_reabrible:{e}")));
                        }
                    }
                }
                Err(e) => return (None, Some(format!("diario_no_creado:{e}"))),
            }
        }
        match crate::votos::DiarioVotos::abrir(&ruta, self.cbid) {
            Ok(d) => (Some(d), None),
            Err(e) => (
                None,
                Some(format!("directorio_previo_sin_diario_valido:{e}")),
            ),
        }
    }

    /// FV-N6-C7 · arranca el motor de votos del nodo.
    ///
    /// Orden: (1) vincula el diario durable o entra en observación; (2) restaura el último `C_n`
    /// **aplicado** desde el replay; (3) reconcilia el `--punto-control` explícito con lo aplicado.
    /// El motor solo firma si el diario está vinculado y la carga no quedó en observación.
    pub(super) fn iniciar_votos(&mut self, cfg: &Config) -> ResultadoNodo<()> {
        if cfg.red != Red::Dev {
            // Fuera de dev no hay fuente de peso con prueba: la capa no arranca (FV-D08); el
            // llamante ya rechaza la red no-dev, así que esto es defensa en profundidad.
            self.motor_votos = None;
            return Ok(());
        }
        let mut claves = Vec::with_capacity(cfg.indices_claves.len());
        let mut claves_bls_propias = Vec::with_capacity(cfg.indices_claves.len());
        for indice in &cfg.indices_claves {
            let sk = crate::votos::clave_voto_dev(cfg.semilla, *indice)
                .map_err(|e| ErrorNodo::Otro(format!("clave BLS de voto: {e}")))?;
            claves_bls_propias.push(sk.clave_publica().bytes().to_vec());
            claves.push(sk);
        }
        // A5-c-2b · X1 · el motor se construye con el número de subredes `S` de la red (`zx-p2p`).
        let subredes = u16::from(zx_p2p::config::SUBREDES_VOTO);
        let mut motor = MotorVotos::nuevo_con_subredes(
            ConfigMotorVotos {
                perfil: perfil::parametros_votos_dev(),
                claves,
                emitir_votos: !cfg.sin_voto,
            },
            subredes,
        );
        self.claves_bls_propias = claves_bls_propias;

        // (1) Diario durable de voto.
        let (diario, mut motivo_observacion) = self.abrir_diario_votos();
        let diario_ruta = diario
            .as_ref()
            .map(|d| d.ruta().display().to_string())
            .unwrap_or_default();
        let diario_entradas = diario
            .as_ref()
            .map_or(0, crate::votos::DiarioVotos::entradas);
        let mut en_observacion = false;
        if let Some(d) = diario {
            motor.vincular_diario(d);
        } else {
            motor.poner_en_observacion();
            en_observacion = true;
        }

        // (2) RA-2 · R7 · la finalidad por votos **aplicada** en el estado seleccionado es la única
        // fuente de la base del modo por peso: no hay cuerpo `0x04` que leer.
        let finalidad_estado: Option<FinalidadEstado> = match self.cadena.estado_virtual() {
            Ok(estado) => finalidad_estado_de(&estado),
            Err(motivo) => {
                en_observacion = true;
                motivo_observacion = Some(format!("estado_no_leible:{motivo:?}"));
                None
            }
        };
        let finalidad_en_estado = finalidad_estado.is_some();

        // PD-1f · F5 · punto de control por peso: `--punto-control` lee `ZXPCP1`, lo verifica y
        // aplica las mismas comprobaciones y motivos de observación que el resto del arranque,
        // adaptadas al certificado por peso y a la finalidad del estado.
        if let Some(ruta) = &cfg.punto_control {
            let bytes = std::fs::read(ruta).map_err(|e| {
                ErrorNodo::Otro(format!("punto de control {}: {e}", ruta.display()))
            })?;
            let punto = deserializar_punto_control_peso(&bytes)
                .map_err(|e| ErrorNodo::Otro(format!("punto de control por peso inválido: {e}")))?;
            verificar_punto_control_peso(&punto, perfil::parametros_votos_dev().b).map_err(
                |e| ErrorNodo::Otro(format!("punto de control por peso no verifica: {e}")),
            )?;
            let cert = punto.certificado.clone();
            let candidato = BlockHash::from_digest(Digest::from_bytes(cert.candidato));
            let mut origen = "punto_control_peso";
            // Comprobaciones conservadas del camino `ZXPC1`, una a una:
            //  (a) compatibilidad / mismo contexto → `replay_y_punto_control_coinciden`;
            //  (b) mismo `n` distinto → `punto_control_mismo_n_distinto` (conflicto + observación);
            //  (c) externo posterior → `punto_control_posterior`;
            //  (d) anterior incompatible (cota de antigüedad: un punto más viejo que la finalidad
            //      local no se puede autenticar como compatible sin la cadena intermedia) →
            //      `punto_control_anterior_incompatible` (observación).
            if let Some(f) = &finalidad_estado {
                if cert.n == f.n {
                    if cert.candidato == *f.sellado.as_bytes() && cert.h_t_siguiente == f.h_t {
                        origen = "replay_y_punto_control_coinciden";
                    } else {
                        en_observacion = true;
                        origen = "punto_control_mismo_n_distinto";
                        self.registro.escribir(
                            self.registro
                                .evento("punto_control_conflicto")
                                .u64("n", cert.n)
                                .str("candidato_externo", &hex(&cert.candidato))
                                .str("candidato_aplicado", &hex(f.sellado.as_bytes()))
                                .str("h_t_externo", &hex(&cert.h_t_siguiente))
                                .str("h_t_aplicado", &hex(&f.h_t)),
                            true,
                        )?;
                    }
                } else if cert.n > f.n {
                    origen = "punto_control_posterior";
                } else {
                    en_observacion = true;
                    origen = "punto_control_anterior_incompatible";
                }
            }
            motor
                .sembrar_punto_control_peso(
                    punto.tabla.clone(),
                    punto.claves.clone(),
                    cert.clone(),
                    &punto.cola,
                )
                .map_err(|e| ErrorNodo::Otro(format!("punto de control por peso: {e}")))?;
            if let Ok(estado_sel) = self.cadena.estado_virtual() {
                self.sembrar_estado_verificacion_peso(&estado_sel, &punto);
            }
            let resultado = self.cadena.considerar_ancla_de_estado(cert.n, candidato);
            if !matches!(
                resultado,
                zx_cadena::ResultadoAncla::Adoptada | zx_cadena::ResultadoAncla::Idempotente
            ) {
                en_observacion = true;
                motivo_observacion
                    .get_or_insert_with(|| format!("ancla_estado_peso:{resultado:?}"));
            }
            self.votos_carga_aplicada = Some((cert.n, candidato));
            self.votos_carga_externa = true;
            self.registro.escribir(
                self.registro
                    .evento("punto_control_cargado")
                    .str("punto", &hex(&cert.candidato)),
                true,
            )?;
            if en_observacion {
                motor.poner_en_observacion();
            }
            let motivo = motivo_observacion.unwrap_or_else(|| {
                if en_observacion {
                    "carga_inicial_en_observacion".to_string()
                } else {
                    "diario_vinculado".to_string()
                }
            });
            self.registro.escribir(
                self.registro
                    .evento("votos_arranque")
                    .str("origen", origen)
                    .bool("diario", motor.tiene_diario())
                    .bool("observacion", en_observacion)
                    .u64("diario_entradas", diario_entradas)
                    .str("diario_ruta", &diario_ruta)
                    .str("motivo", &motivo),
                false,
            )?;
            self.motor_votos = Some(motor);
            return Ok(());
        }

        let mut origen = "bootstrap_sin_finalidad";

        // RA-2 · R7 · modo peso con finalidad ya sellada en el estado y su tabla en el contenido: el
        // nodo **no** entra en observación por no haber cuerpo `0x04`. El motor toma la base del
        // estado, fija el ancla de la cadena con `(n, bloque sellado)` (observación solo si el ancla
        // no se adopta) y abrirá la primera ventana posterior a la base con la tabla del estado (R0).
        let mut base_de_estado_sembrada = false;
        if let Some(f) = finalidad_estado
            && f.tiene_contenido
        {
            motor
                .sembrar_base_de_estado(f.n, f.h_t, *f.sellado.as_bytes())
                .map_err(|e| ErrorNodo::Otro(format!("base de estado en modo peso: {e}")))?;
            let resultado = self.cadena.considerar_ancla_de_estado(f.n, f.sellado);
            if !matches!(
                resultado,
                zx_cadena::ResultadoAncla::Adoptada | zx_cadena::ResultadoAncla::Idempotente
            ) {
                en_observacion = true;
                motivo_observacion
                    .get_or_insert_with(|| format!("ancla_estado_finalidad:{resultado:?}"));
            }
            origen = "estado_finalidad_peso";
            base_de_estado_sembrada = true;
        }

        // FV-N6-C7-3 · finalidad en estado sin cuerpo autenticado: observar con motivo, nunca
        // bootstrapear desde el estado (el motor tampoco lo permitiría al abrir).
        if finalidad_en_estado && !base_de_estado_sembrada {
            en_observacion = true;
            motivo_observacion.get_or_insert_with(|| "finalidad_sin_cuerpo_autentico".to_string());
        }

        if en_observacion {
            motor.poner_en_observacion();
        }
        let motivo = motivo_observacion.unwrap_or_else(|| {
            if en_observacion {
                "carga_inicial_en_observacion".to_string()
            } else {
                "diario_vinculado".to_string()
            }
        });
        self.registro.escribir(
            self.registro
                .evento("votos_arranque")
                .str("origen", origen)
                .bool("diario", motor.tiene_diario())
                .bool("observacion", en_observacion)
                .u64("diario_entradas", diario_entradas)
                .str("diario_ruta", &diario_ruta)
                .str("motivo", &motivo),
            false,
        )?;
        self.motor_votos = Some(motor);
        Ok(())
    }

    /// VNT-R1 · Reloj **de cadena aplicado** (lectura anterior, sin el tiempo PoT local del
    /// cursor): el slot del `ServicioPot` del terminal seleccionado o el mayor slot PoST admitido.
    /// Lo conservan quienes no deben cambiar de calendario en silencio (evidencia EV-1b y
    /// renovación de sectores).
    pub(super) fn slot_cadena_votos(&self) -> u64 {
        #[cfg(test)]
        if let Some(slot) = self.slot_votos_simulado {
            return slot;
        }
        if let Some(terminal) = self.cadena.terminal()
            && let Some(s) = self.servicios_verificacion.get(&terminal)
        {
            return s.slot_actual();
        }
        self.cadena
            .bloques_post()
            .iter()
            .map(|b| b.slot)
            .max()
            .unwrap_or(0)
    }

    /// VNT-R1 · Slot PoT de régimen vigente para el reloj de instancias: el mayor entre el tiempo
    /// **verificado en local** del cursor ([`CursorVotos`], alimentado por admisiones completas y
    /// por las salidas del hilo PoT) y el slot del `ServicioPot` del terminal seleccionado (o el
    /// mayor slot PoST admitido como respaldo). El máximo conserva la monotonía y cubre el arranque
    /// y la repetición, donde el cursor todavía no existe o el servicio aún no lo alcanzó.
    pub(super) fn slot_votos(&self) -> u64 {
        #[cfg(test)]
        if let Some(slot) = self.slot_votos_simulado {
            return slot;
        }
        let cursor = self
            .cursor_votos
            .as_ref()
            .map_or(0, CursorVotos::slot_verificado);
        cursor.max(self.slot_cadena_votos())
    }

    /// VNT-1b · D5 · Duración de la ventana de instancias, **la misma que usa el motor**
    /// (`procesar_votos`): una sola fuente, `perfil::parametros_votos_dev().t_inst`. Ni el cursor ni
    /// su horizonte mantienen una copia propia (`T_INST_VOTOS`) que pueda divergir.
    pub(super) fn t_inst_votos() -> u64 {
        perfil::parametros_votos_dev().t_inst.max(1)
    }

    /// VNT-R1 · Horizonte de instancias que todavía pueden tener efecto: `⌈W/T⌉ + 1` (81 con
    /// `T=2`, `W=160`; 82 incluyendo la actual). No es la cota de certificados pendientes de B78-2.
    pub(super) fn horizonte_fronteras_votos() -> u64 {
        W_REVEAL_SLOTS_VOTOS.div_ceil(Self::t_inst_votos()) + 1
    }

    /// VNT-R1 · crea o reconcilia el cursor con `terminal` y le entrega el slot ya verificado del
    /// servicio de ese terminal. No rebobina: un terminal nuevo avanza la generación y una salida
    /// vieja queda abandonada.
    fn sincronizar_cursor_votos(&mut self, terminal: BlockHash) {
        let servicio_slot = self
            .servicios_verificacion
            .get(&terminal)
            .map_or(0, |s| s.slot_actual());
        match self.cursor_votos.as_mut() {
            None => {
                self.cursor_votos = Some(CursorVotos::nuevo(terminal, 1, servicio_slot));
            }
            Some(cursor) => {
                if cursor.terminal() != terminal {
                    cursor.reconciliar(terminal, 0);
                }
                let generacion = cursor.generacion();
                let _ =
                    cursor.registrar(SalidaVerificada::nueva(terminal, generacion, servicio_slot));
            }
        }
    }

    /// VNT-R1 · registra una salida PoT del flujo `flujo` que el hilo productor ya verificó en
    /// local. VNT-1b · D3: antes de mover el cursor contrasta el `N(slot)` declarado por el hilo
    /// con el que el propio `ServicioPot` de verificación tiene por vigente para ese slot, sin
    /// recalcular PoT; si no coincide, no lo mueve y deja traza. Solo la acepta si es del terminal
    /// vigente del cursor; una generación distinta queda abandonada.
    pub(super) fn registrar_frontera_pot(
        &mut self,
        flujo: BlockHash,
        slot: u64,
        n: u64,
    ) -> ResultadoNodo<()> {
        // D3 · la comparación es por slot, no por longitud del calendario: dos calendarios que solo
        // difieren en una época futura no descartan nada.
        let Some(n_vigente) = self
            .servicios_verificacion
            .get(&flujo)
            .map(|servicio| servicio.n_vigente(slot))
        else {
            tracing::debug!(
                slot,
                "frontera PoT de un flujo sin servicio de verificación: se ignora"
            );
            return Ok(());
        };
        if n_vigente != n {
            tracing::debug!(
                slot,
                n_declarado = n,
                n_vigente,
                "frontera PoT con calendario distinto al del bucle: no mueve el cursor"
            );
            return Ok(());
        }
        if self.cursor_votos.is_none() {
            // Primer contacto con el flujo PoT: el cursor nace con el terminal del mensaje.
            self.sincronizar_cursor_votos(flujo);
        }
        let movimiento = {
            let Some(cursor) = self.cursor_votos.as_mut() else {
                return Ok(());
            };
            if cursor.terminal() != flujo {
                return Ok(());
            }
            let salida = SalidaVerificada::nueva(flujo, cursor.generacion(), slot);
            cursor.registrar(salida)
        };
        if let Movimiento::Avanza { anterior, nuevo } = movimiento {
            // Diagnóstico por `tracing`, no por el registro estructurado: el vocabulario de eventos
            // del §1 es finito y no admite tipos nuevos en esta orden.
            tracing::debug!(
                slot_anterior = anterior,
                slot = nuevo,
                n = nuevo.div_euclid(Self::t_inst_votos()),
                "frontera PoT verificada en local"
            );
        }
        Ok(())
    }

    /// VNT-R2 · atiende las fronteras pendientes del motor **en un punto completo**.
    ///
    /// Se llama tras admitir íntegramente un bloque (servicio, selección, calendario y efectos ya
    /// actualizados), tras un bloque propio y tras una salida PoT sin ganadora. El motor recibe en
    /// orden el intervalo; las ventanas intermedias las atiende la vía tardía que ya existe (sin
    /// instancia: VNT-R3 queda fuera de esta orden) y la actual se abre como ventana vigente. Nada
    /// corre dentro de una transición a medio aplicar.
    pub(super) fn atender_fronteras_votos(&mut self) -> ResultadoNodo<()> {
        if self.motor_votos.is_none() {
            return Ok(());
        }
        let Some(terminal) = self.cadena.terminal() else {
            return Ok(());
        };
        self.sincronizar_cursor_votos(terminal);
        // VNT-1b · D2 · ECL-R2a D4: con el eclipse enclavado ningún camino llega al motor de votos.
        // El cursor ya registró el tiempo del terminal seleccionado; la guarda, en este único sitio,
        // cubre la red, la sincronización, los reintentos y la notificación `FronteraPot`.
        if self.cadena.eclipse().is_some() {
            return Ok(());
        }
        let t_inst = Self::t_inst_votos();
        let horizonte = Self::horizonte_fronteras_votos();
        let pendientes = self
            .cursor_votos
            .as_ref()
            .map_or_else(Vec::new, |c| c.fronteras_pendientes(t_inst, horizonte));
        if pendientes.is_empty() {
            return Ok(());
        }
        self.registrar_intervalo_fronteras(&pendientes);
        self.procesar_votos()?;
        if let Some(ultima) = self
            .motor_votos
            .as_ref()
            .and_then(MotorVotos::ultima_ventana_abierta)
            && let Some(cursor) = self.cursor_votos.as_mut()
        {
            cursor.consumir_hasta(ultima);
        }
        Ok(())
    }

    /// VNT-R2 · deja constancia por `tracing` del intervalo de fronteras atendido (nunca dentro de
    /// una transición). No usa el registro estructurado: su vocabulario es finito y no se amplía en
    /// esta orden.
    fn registrar_intervalo_fronteras(&mut self, pendientes: &[u64]) {
        let (Some(&primera), Some(&ultima)) = (pendientes.first(), pendientes.last()) else {
            return;
        };
        // VNT-1b · D4: una traza por intervalo pendiente **distinto**, no una por llamada. Mientras
        // el motor no abre, la frontera sigue pendiente y se reintenta la apertura sin retrazar.
        if self.ultimo_intervalo_fronteras_votos == Some((primera, ultima)) {
            return;
        }
        self.ultimo_intervalo_fronteras_votos = Some((primera, ultima));
        #[cfg(test)]
        {
            self.trazas_intervalo_fronteras = self.trazas_intervalo_fronteras.saturating_add(1);
        }
        tracing::debug!(
            desde = primera,
            hasta = ultima,
            n = pendientes.len(),
            slot_verificado = self.slot_votos(),
            "fronteras de voto atendidas en un punto completo"
        );
    }

    /// FV-4b-N1-2 · Candidato `h_B(n)` determinista entre nodos: el bloque PoST admitido de mayor
    /// slot `<= apertura - LAG_CANDIDATO_VOTOS`, con desempate por hash menor. `apertura` es el slot
    /// de apertura de la ventana (`n·t_inst`); así el candidato no depende del slot en que cada nodo
    /// descubra la ventana. Devuelve `None` mientras no haya ningún bloque admitido tan antiguo
    /// (arranque), y el llamante cae a la punta.
    ///
    /// FV-4b-N2: se restringe a la **cadena seleccionada** del terminal. Un candidato de una rama
    /// lateral anclaría la finalidad por votos fuera de las puntas y `tips_seleccionables_de` las
    /// vaciaría (stall del productor). El candidato de la cadena seleccionada es ancestro de las
    /// puntas actuales.
    ///
    /// `ORDEN-IDX1` · I3: delega en [`Cadena::candidato_por_slot`], que retrocede desde la punta por
    /// el padre seleccionado del DAG en vez de materializar `cadena_virtual()` y recorrer
    /// `bloques_post()`. El resultado es idéntico al de [`Nodo::candidato_votos_referencia`].
    pub(super) fn candidato_votos(&self, slot: u64) -> Option<BlockHash> {
        let tope = slot.saturating_sub(LAG_CANDIDATO_VOTOS);
        self.cadena.candidato_por_slot(tope)
    }

    /// `ORDEN-IDX1` · I3 · Código anterior a I3, **conservado solo para pruebas**: materializa la
    /// cadena seleccionada y recorre todos los bloques PoST. La prueba diferencial X2 comprueba que
    /// [`Nodo::candidato_votos`] devuelve lo mismo en cadenas con huecos de slot, bifurcaciones y
    /// reorganización.
    #[cfg(test)]
    pub(super) fn candidato_votos_referencia(&self, slot: u64) -> Option<BlockHash> {
        let tope = slot.saturating_sub(LAG_CANDIDATO_VOTOS);
        let seleccionada: BTreeSet<BlockHash> = self.cadena.cadena_virtual().into_iter().collect();
        let mut mejor: Option<BlockHash> = None;
        let mut mejor_slot: u64 = 0;
        for b in self.cadena.bloques_post() {
            if b.slot > tope || !seleccionada.contains(&b.hash) {
                continue;
            }
            let es_mejor = match mejor {
                None => true,
                Some(h) => b.slot > mejor_slot || (b.slot == mejor_slot && b.hash < h),
            };
            if es_mejor {
                mejor = Some(b.hash);
                mejor_slot = b.slot;
            }
        }
        mejor
    }

    /// ANC-1 · A1 · Reconciliación de la finalidad por votos tras admitir un bloque.
    ///
    /// Condición explícita: solo cuando el bloque trae un certificado `0x04` (lo único que puede
    /// fijar `finalidad_votos` del estado canónico) se alimenta la **caché** con sus ocurrencias y
    /// se intenta el camino barato: la evidencia del estado aplicado de la selección vigente
    /// (`Cadena::estado_virtual`, que parte del estado `post` incremental y solo fusiona el
    /// mergeset del virtual, no la historia) se autentica contra el paso cacheado de la misma clave
    /// (`paso_autentica_evidencia`). Si no hay entrada en la caché (p. ej. tras reiniciar) se hace
    /// **un** recorrido completo como el de hoy, que además rellena la caché, con el evento
    /// `ancla_recorrido_completo`. En los bloques sin certificado se conserva el aviso pendiente
    /// (D5), que no depende del estado, y no se paga ninguna lectura de historia.
    pub(super) fn reconciliar_ancla_de_bloque(&mut self, hash: BlockHash, txs: &[Tx]) {
        // PD-1e · E7 · en modo peso no corre la lógica del ancla D2 ni de la caché de pasos, ni sus
        // avisos. Al admitir un bloque con `0x09` se fija el ancla de la cadena con la finalidad
        // aplicada del estado seleccionado (`considerar_ancla_de_estado`) y se escribe
        // `certificado_peso_aplicado`.
        // VS-2 · V1 · el ancla de votos de la cadena es `(finalidad_votos_n, bloque sellado)`,
        // no el hash de la tabla. Se fija **una vez** con la finalidad aplicada del estado
        // seleccionado. N5 registra cada `0x09` realmente aplicado; los arneses sintéticos
        // conservan la comprobación de coincidencia con esa finalidad.
        //
        // RA-2 · R6.1 · `estado_virtual()` es caro y solo hace falta si el bloque trae algún
        // `0x09`: un bloque admitido sin `0x09` no lo calcula.
        //
        // PD-1f · F4 · el resultado de `considerar_ancla_de_estado` ya no se descarta.
        if !txs.iter().any(tx_es_certificado_peso) {
            self.actualizar_pendientes_certificados_seleccionados();
            return;
        }
        #[cfg(test)]
        ESTADO_VIRTUAL_RECONCILIACION.with(|c| c.set(c.get().saturating_add(1)));
        let estado = self.cadena.estado_virtual().ok();
        // Un bloque admitido pasó la transición, que puede descartar alguna transacción.
        // Las llamadas sintéticas de los arneses conservan la guarda de finalidad de VS-2.
        let admitido = self.cadena.estado_post(&hash).is_some();
        let mut ancla_hecha = false;
        for (indice, tx) in txs
            .iter()
            .enumerate()
            .filter(|(_, tx)| tx_es_certificado_peso(tx))
        {
            let ExtensionTx::PruebaAlmacenamiento {
                operacion: zx_core::OperacionAlmacenamiento::CertificadoPeso { bytes, .. },
            } = &tx.extension
            else {
                continue;
            };
            let (Some(nb), Some(cb)) = (bytes.get(..8), bytes.get(8..40)) else {
                continue;
            };
            let n = u64::from_be_bytes(<[u8; 8]>::try_from(nb).unwrap_or([0; 8]));
            let candidato = <[u8; 32]>::try_from(cb).unwrap_or([0; 32]);
            let finalidad = estado.as_ref().and_then(|e| {
                e.finalidad_votos
                    .map(|sellado| (e.finalidad_votos_n, sellado))
            });
            if !ancla_hecha && let Some((n_final, sellado)) = finalidad {
                self.registrar_ancla_de_estado_peso(n_final, sellado);
                ancla_hecha = true;
            }
            let descartado = self
                .cadena
                .descartes(&hash)
                .is_some_and(|d| d.iter().any(|d| d.indice == indice));
            if descartado {
                continue;
            }
            if admitido
                || finalidad.is_some_and(|(m, sellado)| n == m && candidato == *sellado.as_bytes())
            {
                // A1-D2b · W5 · la raíz de estado que sella el certificado (bytes 72..104 de
                // `serial_certificado_peso`), en hexadecimal.
                let raiz = bytes
                    .get(72..104)
                    .and_then(|r| <[u8; 32]>::try_from(r).ok())
                    .unwrap_or([0u8; 32]);
                let evento = self
                    .registro
                    .evento("certificado_peso_aplicado")
                    .u64("n", n)
                    .str("candidato", &hex(&candidato))
                    .str("raiz", &hex(&raiz))
                    .str("bloque", &hash.to_string());
                let _ = self.registro.escribir(evento, false);
            }
        }
        if let Some(estado) = estado.as_ref()
            && let Some(motor) = self.motor_votos.as_mut()
        {
            // La finalidad fusionada del virtual puede superar la del padre seleccionado.
            motor.actualizar_certificados_peso(estado, 0);
        }
        self.actualizar_pendientes_certificados_seleccionados();
    }

    /// N1/N5: la poda observa la selección, nunca el slot de una rama ajena.
    fn actualizar_pendientes_certificados_seleccionados(&mut self) {
        if let Ok(padres) = padres_de_regimen(&self.cadena)
            && let Some(estado) = self.cadena.estado_post(&padres.seleccionado())
            && let Some(motor) = self.motor_votos.as_mut()
        {
            motor.actualizar_certificados_peso(
                estado,
                self.cadena.slot_de(&padres.seleccionado()).unwrap_or(0),
            );
        }
        self.registrar_eventos_certificados_pendientes();
    }

    /// FV-4b-N1 · Avanza el motor de votos en el hilo de consenso: cierra y abre instancias por
    /// fronteras de `t_inst` slots, ancla los certificados adoptados y difunde los votos propios.
    ///
    /// # Errores
    /// [`ErrorNodo::Otro`] si el motor de `zx-votos` falla (aritmética, longitudes o BLS).
    pub(super) fn procesar_votos(&mut self) -> ResultadoNodo<()> {
        #[cfg(test)]
        {
            self.procesar_votos_llamadas = self.procesar_votos_llamadas.saturating_add(1);
        }
        // FV-4b-N3-2 · la gestión de tx v6 pendientes corre en cada vuelta, aunque el motor no abra
        // instancia: hay que drenar el gossip, difundir las revelaciones propias y podar las ya
        // observadas o vencidas.
        let slot = self.slot_votos();
        self.procesar_v6_pendientes(slot);
        if self.motor_votos.is_none() {
            return Ok(());
        }
        // PD-1e · E5/E6/E7 · el motor corre siempre el flujo por peso del contrato v2.
        let t_inst = Self::t_inst_votos();
        let slot_i64 = i64::try_from(slot).unwrap_or(i64::MAX);
        // A5-c-2b · X6 · en **cada** vuelta el nodo pregunta al motor por su agregado propio y lo
        // difunde por el tema de agregados (el motor decide el «último slot» y la unicidad).
        self.publicar_agregado_propio(slot_i64)?;
        let n = slot.div_euclid(t_inst);
        let abrir = self
            .motor_votos
            .as_ref()
            .is_some_and(|m| m.instancia_actual().is_none_or(|actual| n > actual));
        if !abrir {
            return Ok(());
        }
        // EV-1 · reconsideración por apertura incluso si el motor aún espera candidato o tabla.
        // La oferta anterior de esta ventana impide una segunda admisión tras avanzar el motor.
        self.procesar_evidencias_doble_voto();
        // A1-D2b · W2 · el nodo que vota prepara las raíces de las dos épocas que le tocan antes de
        // abrir: recoge lo terminado, solicita lo que falte y poda. Nunca espera al cálculo.
        self.preparar_raices(n, t_inst);
        // VS-2 · V3 · voto tardío, en orden de ventana: recupera las ventanas que el reloj saltó
        // (`última abierta < k < n`) antes de abrir `n`. Solo en modo peso, solo si el motor ya
        // abrió alguna ventana y solo dentro del plazo `cierre(k) + W_REVEAL`. Si hay más de 8, se
        // atienden las 8 más recientes, en orden creciente.
        if let Some(ultima) = self
            .motor_votos
            .as_ref()
            .and_then(|m| m.ultima_ventana_abierta())
        {
            let slot_actual = slot;
            let mut candidatas: Vec<u64> = (ultima.saturating_add(1)..n)
                .filter(|k| cierre_ventana(*k).saturating_add(W_REVEAL_SLOTS_VOTOS) >= slot_actual)
                .collect();
            if candidatas.len() > 8 {
                candidatas.drain(..candidatas.len() - 8);
            }
            let aviso_tardio: std::cell::Cell<Option<(u64, u64, BlockHash)>> =
                std::cell::Cell::new(None);
            let mut tardios: Vec<(crate::votos::PasoTardio, zx_consensus::transicion::Estado)> =
                Vec::new();
            for k in candidatas {
                let Some(cand) = self.candidato_votos(k.saturating_mul(t_inst)) else {
                    continue;
                };
                let estado_k = self
                    .cadena
                    .estado_past(&cand)
                    .cloned()
                    .unwrap_or_else(|| self.cadena.estado_terminal().clone());
                let resultado = {
                    // A1-D2b · W1 · el motor recibe la vista con raíz también en el voto tardío.
                    let vista = VistaConRaiz {
                        cadena: &self.cadena,
                        raices: &self.raices,
                        vota: self.vota,
                        t_inst,
                        lag: LAG_CANDIDATO_VOTOS,
                        aviso: &aviso_tardio,
                    };
                    self.motor_votos
                        .as_ref()
                        .map(|m| m.votar_tardio(k, *cand.as_bytes(), &estado_k, &vista))
                };
                let Some(resultado) = resultado else {
                    continue;
                };
                match resultado {
                    Ok(paso_t) => tardios.push((paso_t, estado_k)),
                    // RA-2 · R6.2 · un error del voto tardío no impide abrir la ventana en curso:
                    // se observa con su ventana y su texto, y se sigue.
                    Err(e) => {
                        let _ = self.registro.escribir(
                            self.registro
                                .evento("voto_tardio_error")
                                .u64("n", k)
                                .str("error", &e.to_string()),
                            false,
                        );
                    }
                }
            }
            for (paso_t, estado_k) in tardios {
                for voto in paso_t.votos {
                    let payload = crate::votos::voto_propio_de_peso(&voto);
                    if let Some(clave) =
                        clave_dev_para_bls(&self.claves, &estado_k, &payload.clave_bls)
                    {
                        let (tx, tst) =
                            crate::votos::tx_voto_propio(&payload, clave.pk, &clave.sk, self.cbid);
                        self.encolar_v6(tx, tst, true);
                    }
                }
                for evento in paso_t.eventos {
                    self.escribir_evento_votos(evento, None);
                }
                // A5-c-2b · X3 · el voto **tardío** también sale como voto de red por su subred.
                for (bytes, subred) in &paso_t.votos_red {
                    self.difundir_voto_subred_si_hay_red(*subred, bytes);
                }
            }
            // A1-D2b · W3 · aviso de raíz no lista recogido por la vista del voto tardío.
            if let Some((n_av, epoca, punto)) = aviso_tardio.take() {
                self.avisar_raiz_no_lista(n_av, epoca, punto);
            }
        }
        // FV-4b-N1-2 · candidato determinista (bloque con retardo) y, solo al arranque, la punta.
        // B-28/CAND-1 · el candidato de la ventana `n` se calcula con su **slot de apertura**
        // (`n·t_inst`, la misma cuenta que `zx_consensus::transicion::votos::apertura_ventana`),
        // no con el slot actual: todos los nodos eligen el mismo candidato aunque descubran la
        // ventana en slots distintos de ella.
        let candidato = self
            .candidato_votos(n * t_inst)
            .or_else(|| self.cadena.mejor_punta())
            .or_else(|| self.cadena.terminal());
        #[cfg(test)]
        let candidato = candidato.or(self.candidato_votos_simulado);
        let Some(candidato) = candidato else {
            return Ok(());
        };
        let estado = self
            .cadena
            .estado_past(&candidato)
            .cloned()
            .unwrap_or_else(|| self.cadena.estado_terminal().clone());
        // AUS-2c · K1 · fija el `votantes_voto` del estado aplicado de esta apertura de ventana.
        // `procesar_v6_pendientes` lo usa para decidir «mi voto ya consta» sin `estado_virtual()`.
        self.votantes_voto_ventana = Some(estado.votantes_voto.clone());
        // REAN-2 · N1/N6 · la base del motor es la más avanzada entre su último certificado y la
        // finalidad **aplicada** del estado; con `n <= base` se espera al reloj y **ya no existe**
        // la clase `hueco`: con base `m` y `n > m+1` se abre el intento `n`.
        let instancia_actual = self.motor_votos.as_ref().and_then(|m| m.instancia_actual());
        let base_motor = self.motor_votos.as_ref().and_then(|m| m.base_n());
        let base_estado = estado.finalidad_votos_h_t.map(|_| estado.finalidad_votos_n);
        let base_m = match (base_motor, base_estado) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let certificado_n = self
            .motor_votos
            .as_ref()
            .and_then(|m| m.ultimo_certificado_peso().map(|c| c.n));
        if let Some(clase) = clase_arranque_votos(instancia_actual, base_m, n) {
            let m = base_m.unwrap_or(0);
            if self.votos_aviso != Some((n, m)) {
                self.votos_aviso = Some((n, m));
                let _ = self.registro.escribir(
                    self.registro
                        .evento("votos_espera")
                        .str("clase", clase)
                        .u64("reloj_n", n)
                        .u64("certificado_n", certificado_n.unwrap_or(0)),
                    false,
                );
            }
            return Ok(());
        }
        let aviso_apertura: std::cell::Cell<Option<(u64, u64, BlockHash)>> =
            std::cell::Cell::new(None);
        let resultado = {
            let motor = self
                .motor_votos
                .as_mut()
                .ok_or_else(|| ErrorNodo::Otro("motor de votos ausente".to_string()))?;
            // A1-D2b · W1 · el motor recibe la vista que entrega la raíz del punto de la época.
            let vista = VistaConRaiz {
                cadena: &self.cadena,
                raices: &self.raices,
                vota: self.vota,
                t_inst,
                lag: LAG_CANDIDATO_VOTOS,
                aviso: &aviso_apertura,
            };
            motor.avanzar_con_vista(n, candidato, &estado, slot_i64, &vista)
        };
        self.registrar_eventos_certificados_pendientes();
        // A1-D2b · W3 · si la vista no tenía la raíz, el voto salió con cero: un aviso por ventana.
        if let Some((n_av, epoca, punto)) = aviso_apertura.take() {
            self.avisar_raiz_no_lista(n_av, epoca, punto);
        }
        let paso = match resultado {
            Ok(paso) => paso,
            // FV-N6-C7 · falta de tabla/cuerpo o apertura no contigua: observación con motivo, sin
            // excepción fatal y sin rescatar el motor (RFT-33 sigue abierto).
            Err(zx_votos::ErrorVotos::CargaInicialInvalida { motivo }) => {
                let marca = (n, u64::MAX);
                if self.votos_aviso != Some(marca) {
                    self.votos_aviso = Some(marca);
                    let _ = self.registro.escribir(
                        self.registro
                            .evento("votos_carga_pendiente")
                            .str("motivo", motivo)
                            .u64("reloj_n", n),
                        false,
                    );
                }
                return Ok(());
            }
            Err(e) => return Err(ErrorNodo::Otro(format!("motor de votos: {e}"))),
        };
        // A5-c-2b · X7 · al abrir la ventana, el nodo fija el cupo de diferidos de agregación:
        // `AGREGADORES_POR_SUBRED × subredes` más las claves de la tabla abierta en subredes propias.
        if let Some(red) = self.red.as_ref() {
            let cupo = self.cupo_diferidos_agregacion();
            if let Err(e) = red.fijar_cupo_diferidos_agregacion(cupo) {
                tracing::warn!(%e, "no se pudo fijar el cupo de diferidos de agregación");
            }
        }
        // ECL-R2b-2 · tras abrir/avanzar, `reproducir_pendientes` pudo cerrar parejas contradictorias
        // con votos adelantados que llevaban esperando: el Nodo las drena y publica también aquí,
        // aunque en esta vuelta no haya llegado ningún voto nuevo.
        self.procesar_evidencias_doble_voto();
        // PD-1e · E5 · certificado por peso: ancla la finalidad de la cadena con la misma condición
        // y el mismo evento de conflicto que hoy.
        if let Some(cert) = &paso.certificado_peso {
            let candidato_hash = BlockHash::from_digest(Digest::from_bytes(cert.candidato));
            let en_cadena = self.cadena.cadena_virtual().contains(&candidato_hash);
            let anclaje = if en_cadena {
                self.cadena.anclar_finalidad_por_votos(candidato_hash).err()
            } else {
                Some(zx_cadena::MotivoAncla::Desconocido)
            };
            if let Some(motivo) = anclaje {
                let evento = self
                    .registro
                    .evento("certificado_en_conflicto")
                    .str("candidato", &hex(&cert.candidato))
                    .str("motivo", &format!("{motivo:?}"));
                let _ = self.registro.escribir(evento, false);
            }
        }
        // A5-c-2b · X8 · la ventana que este paso cierra (si la hay), para escribir su
        // `agregacion_ventana` después de los eventos del motor.
        let ventana_cerrada_n = paso.eventos.iter().find_map(|evento| match evento {
            EventoMotor::VentanaCerrada { n, .. } => Some(*n),
            _ => None,
        });
        // A1-D2b · W5 · la raíz certificada de la ventana cerrada, para el evento de cierre.
        let raiz_certificada = paso
            .certificado_peso
            .as_ref()
            .map(|cert| hex(&cert.raiz_estado));
        for evento in paso.eventos {
            self.escribir_evento_votos(evento, raiz_certificada.as_deref());
        }
        // A5-c-2b · X8 · un evento por ventana cerrada, con las métricas del motor y los contadores
        // de la ventana; después se reinician para la siguiente.
        if let Some(cerrada) = ventana_cerrada_n {
            self.escribir_evento_agregacion_ventana(cerrada);
        }
        // A5-c-2b · X3 · cada voto de red sale por **su** subred; el sobre antiguo ya no se difunde
        // por el tema global (se sigue usando para el voto propio `0x08`, que no cambia).
        for (bytes, subred) in &paso.votos_red {
            self.difundir_voto_subred_si_hay_red(*subred, bytes);
        }
        for sobre in &paso.votos {
            // AUS-2b · N1 · con la **misma** firma BLS que el motor acaba de emitir se construye la
            // tx `VotoPropio` (firmada con la Ed25519 del nodo) y se encola como propia. No se firma
            // nada nuevo ni se reserva en el diario; N2 la descartará si el certificado ya la admite.
            // PD-1e · E5 · en modo peso el sobre es `ZXV3` y el mensaje firmado es el A3: se
            // deserializa con `deserializar_voto_peso` y el payload sale de `voto_propio_de_peso`.
            let Ok(voto) = crate::votos::deserializar_voto_peso(sobre) else {
                continue;
            };
            let payload = crate::votos::voto_propio_de_peso(&voto);
            let Some(clave) = clave_dev_para_bls(&self.claves, &estado, &payload.clave_bls) else {
                continue;
            };
            let (tx, tst) = crate::votos::tx_voto_propio(&payload, clave.pk, &clave.sk, self.cbid);
            self.encolar_v6(tx, tst, true);
        }
        // PD-1e · E5 · acta de presencia `0x0A` de la ventana cerrada por peso: se encola con su
        // plazo, se difunde como el voto propio y se deja de incluir cuando todos sus firmantes
        // constan en `votantes_voto[n]` del estado base o vence el plazo.
        if let Some(acta) = &paso.acta_peso
            && let Some(firmante) = self.claves.first().cloned()
        {
            let (tx, tst) =
                crate::votos::tx_acta_presencia(acta, firmante.pk, &firmante.sk, self.cbid);
            // ACTA-1 · R1/R4 · la traducción de claves BLS a identidades es la de la cadena
            // (actuales y anteriores vivas en el slot): sin una segunda versión en el nodo.
            let indice = zx_consensus::transicion::votos::indice_bls_a_ed25519_estado(
                &estado,
                u64::try_from(slot_i64).unwrap_or(u64::MAX),
            );
            let firmantes_acta: Vec<zx_core::ClavePublica> = paso
                .acta_peso_firmantes
                .iter()
                .filter_map(|bls| indice.get(bls).copied())
                .collect();
            self.encolar_v6_con_firmantes(
                tx,
                tst,
                true,
                firmantes_acta,
                paso.acta_peso_firmantes.len(),
            );
        }
        Ok(())
    }

    /// A5-c-2b · X6 · pregunta al motor por su agregado propio de la ventana abierta y, si lo hay,
    /// lo difunde por el tema de agregados y lo registra (`agregado_publicado`). Una vez por ventana.
    pub(super) fn publicar_agregado_propio(&mut self, slot: i64) -> ResultadoNodo<()> {
        let publicados = {
            let Some(motor) = self.motor_votos.as_mut() else {
                return Ok(());
            };
            motor
                .publicar_agregado(slot)
                .map_err(|e| ErrorNodo::Otro(format!("motor de votos: {e}")))?
        };
        if publicados.is_empty() {
            return Ok(());
        }
        let n = self
            .motor_votos
            .as_ref()
            .and_then(MotorVotos::instancia_actual)
            .unwrap_or(0);
        for bytes in publicados {
            let subred = subred_de_agregado(&bytes).unwrap_or(0);
            self.difundir_agregado_si_hay_red(&bytes);
            let _ = self.registro.escribir(
                self.registro
                    .evento("agregado_publicado")
                    .u64("n", n)
                    .u64("subred", u64::from(subred))
                    .u64("bytes", u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
                false,
            );
        }
        Ok(())
    }

    /// A5-c-2c · N2 · B-83 · escribe **una** vez, al arrancar, el evento
    /// `azar_del_sistema_no_disponible` si el motor no pudo leer azar del sistema. Idempotente: el
    /// segundo intento (o el de un motor que sí tiene azar) no escribe nada.
    pub(super) fn avisar_sin_azar_del_sistema(&mut self) {
        if self.aviso_sin_azar_escrito {
            return;
        }
        let Some(motor) = self.motor_votos.as_ref() else {
            return;
        };
        if !motor.azar_del_sistema_no_disponible() {
            return;
        }
        self.aviso_sin_azar_escrito = true;
        let _ = self.registro.escribir(
            self.registro.evento("azar_del_sistema_no_disponible"),
            false,
        );
    }

    /// FV-4b-N3-2 · encola una tx v6 de voto propio para incluirla con prioridad,
    /// deduplicando por `txid`. Las propias se vuelven a difundir; las ajenas llegan de la mempool.
    pub(super) fn encolar_v6(&mut self, tx: Tx, testigos: Vec<Vec<u8>>, propia: bool) {
        self.encolar_v6_con_firmantes(tx, testigos, propia, Vec::new(), 0);
    }

    /// PD-1e · E9 · como [`Self::encolar_v6`] pero para un acta `0x0A`, con los dueños Ed25519 de
    /// sus firmantes (traducidos con la función de la cadena) y el número de bits del mapa, para
    /// poder retirarla cuando ya constan en el estado base y registrarlo (ACTA-1 · R4/R5).
    pub(super) fn encolar_v6_con_firmantes(
        &mut self,
        tx: Tx,
        testigos: Vec<Vec<u8>>,
        propia: bool,
        firmantes_acta: Vec<zx_core::ClavePublica>,
        firmantes_mapa: usize,
    ) {
        let Some((clase, n, clave, desde_slot, hasta_slot)) = metadatos_v6(&tx) else {
            return;
        };
        let id = txid(&tx, self.cbid);
        if self.v6_pendientes.iter().any(|p| p.txid == id) {
            return;
        }
        if self.v6_pendientes.len() >= MAX_V6_PENDIENTES {
            self.v6_pendientes.remove(0);
        }
        let n_firmantes_acta = firmantes_acta.len();
        self.v6_pendientes.push(PendienteV6 {
            propia,
            clase,
            n,
            clave,
            desde_slot,
            hasta_slot,
            firmantes_acta,
            tx,
            testigos,
            txid: id,
            difundida: false,
            acta_aplicada: false,
        });
        // AUS-2b · N7 · observabilidad de la cola de votos propios.
        if clase == CLASE_VOTO_PROPIO {
            let evento = self
                .registro
                .evento("voto_propio_pendiente")
                .u64("n", n)
                .str("clave", &hex(clave.bytes()));
            let _ = self.registro.escribir(evento, false);
        }
        // VS-2 · V5 · rastro del acta `0x0A` al encolarla. ACTA-1 · R5: `firmantes` es el número de
        // bits del mapa firmado (R4), no solo los sueltos.
        if clase == CLASE_ACTA_PESO {
            let evento = self.registro.evento("acta_peso_encolada").u64("n", n).u64(
                "firmantes",
                u64::try_from(firmantes_mapa.max(n_firmantes_acta)).unwrap_or(u64::MAX),
            );
            let _ = self.registro.escribir(evento, false);
        }
    }

    /// FV-4b-N3-2 · cada vuelta: drena las tx v6 ajenas de la mempool, difunde las revelaciones y
    /// votos propios admisibles y poda los ya aplicados, vencidos o imposibles.
    ///
    /// AUS-2c · K1/K3 · la decisión «mi voto ya consta» usa el `votantes_voto` del estado aplicado
    /// de la última ventana abierta ([`Nodo::votantes_voto_ventana`]), **no** el `estado_terminal()`
    /// del corte PoW (que no contiene operaciones PoST). `estado_virtual()` solo se consulta si la
    /// cola trae algún compromiso (`0x06`) o revelación (`0x07`); con solo votos propios, nunca.
    pub(super) fn procesar_v6_pendientes(&mut self, slot: u64) {
        // RA-2 · R6.3 · la memoria de actas aplicadas se poda al vencer el plazo de su ventana
        // (`cierre(n) + W_REVEAL + LAG_CANDIDATO`), siempre (aunque no haya pendientes), para que no
        // crezca sin límite.
        self.actas_aplicadas.retain(|(n, _)| {
            slot <= cierre_ventana(*n)
                .saturating_add(W_REVEAL_SLOTS_VOTOS)
                .saturating_add(LAG_CANDIDATO_VOTOS)
        });
        // 1) Drena de la mempool las v6 de gossip (prioridad sobre el resto del cuerpo).
        let ajenas = {
            let mut m = match self.mempool.lock() {
                Ok(g) => g,
                Err(poison) => poison.into_inner(),
            };
            m.tomar_v6()
        };
        for (tx, testigos) in ajenas {
            self.encolar_v6(tx, testigos, false);
        }
        if self.v6_pendientes.is_empty() {
            return;
        }
        let mut a_difundir: Vec<Vec<u8>> = Vec::new();
        // AUS-2c · K2 · descartes de votos propios: `(n, motivo)`.
        let mut descartes: Vec<(u64, &'static str)> = Vec::new();
        // AUS-2c · K1/K2/K4 · votos propios. Las **ajenas** no consultan estado (vencen al pasar
        // `hasta_slot`); las **propias** se deciden con el `votantes_voto` de la última ventana
        // abierta, sin `estado_virtual()` ni `estado_terminal()`. La decisión por ventana es una
        // sola: difundir una vez dentro del plazo, retirar si ya consta o si venció con el retardo
        // del candidato (`LAG_CANDIDATO_VOTOS`).
        let votantes_ventana = self.votantes_voto_ventana.as_ref();
        // VS-2 · V5 · pares `(ventana, firmante)` que constan por un acta `0x0A`: las ya observadas
        // aplicadas y los firmantes de las actas aún pendientes. Solo esos descartes son `en_acta`;
        // el resto sigue siendo `en_certificado`.
        //
        // RA-2 · R6.3 · la consulta se hace por referencia (sin clonar el conjunto en cada vuelta);
        // la poda de las entradas vencidas ya se hizo al entrar.
        let actas_vigentes = &self.actas_aplicadas;
        let mut actas_pendientes: BTreeSet<(u64, zx_core::ClavePublica)> = BTreeSet::new();
        for q in self
            .v6_pendientes
            .iter()
            .filter(|q| q.clase == CLASE_ACTA_PESO)
        {
            for c in &q.firmantes_acta {
                actas_pendientes.insert((q.n, *c));
            }
        }
        // K2.2 · `(n, clave-hex)` de los votos propios difundidos en esta vuelta.
        let mut voto_difundido: Vec<(u64, String)> = Vec::new();
        self.v6_pendientes.retain_mut(|p| {
            if p.clase != CLASE_VOTO_PROPIO {
                return true;
            }
            if !p.propia {
                return slot <= p.hasta_slot;
            }
            // K2.1 · ¿ya consta en el estado aplicado de la ventana?
            let ya_aplicada = votantes_ventana
                .and_then(|v| v.get(&p.n))
                .is_some_and(|votantes| votantes.contains(&p.clave));
            if ya_aplicada {
                // Si nunca se difundió, entró por el certificado o por un acta; si ya se difundió,
                // se aplicó.
                descartes.push((
                    p.n,
                    if p.difundida {
                        "aplicado"
                    } else if actas_vigentes.contains(&(p.n, p.clave))
                        || actas_pendientes.contains(&(p.n, p.clave))
                    {
                        // VS-2 · V5 · la clave consta por un acta de la ventana.
                        "en_acta"
                    } else {
                        "en_certificado"
                    },
                ));
                return false;
            }
            if (p.desde_slot..=p.hasta_slot).contains(&slot) {
                // K2.2 · una sola difusión por voto propio.
                if !p.difundida {
                    let mut buf = Vec::new();
                    zx_core::wire::tx_a_bytes(&mut buf, &p.tx, &p.testigos);
                    a_difundir.push(buf);
                    p.difundida = true;
                    voto_difundido.push((p.n, hex(p.clave.bytes())));
                }
                return true;
            }
            if slot > p.hasta_slot.saturating_add(LAG_CANDIDATO_VOTOS) {
                // K2.3 · vencido: el candidato de la ventana ya pasó el plazo con su retardo.
                descartes.push((p.n, "vencido"));
                return false;
            }
            true
        });
        // PD-1e · E9 · actas de presencia `0x0A`: se difunden una vez dentro del plazo y se retiran
        // cuando todos sus firmantes constan en `votantes_voto[n]` o vence el plazo.
        // VS-2 · V5 · la primera vez que constan todos, se emite `acta_peso_aplicada` y se recuerda
        // `(ventana, firmante)` para clasificar después los descartes `en_acta`.
        // ACTA-1 · R4/R5 · la poda usa el conjunto **completo** de firmantes (R2/R1) y deja un único
        // evento de retirada con su causa.
        let mut actas_nuevas: Vec<(u64, zx_core::ClavePublica)> = Vec::new();
        let mut actas_retiradas: Vec<(u64, TxId, &'static str)> = Vec::new();
        self.v6_pendientes.retain_mut(|p| {
            if p.clase != CLASE_ACTA_PESO {
                return true;
            }
            let todos_constan = votantes_ventana
                .and_then(|v| v.get(&p.n))
                .is_some_and(|votantes| p.firmantes_acta.iter().all(|c| votantes.contains(c)));
            if todos_constan {
                if !p.acta_aplicada {
                    p.acta_aplicada = true;
                    for c in &p.firmantes_acta {
                        actas_nuevas.push((p.n, *c));
                    }
                }
                // R5 · retirada por el predicado (conjunto vacío o ya consta entero).
                actas_retiradas.push((
                    p.n,
                    p.txid,
                    if p.firmantes_acta.is_empty() {
                        "conjunto_vacio"
                    } else {
                        "consta_entera"
                    },
                ));
                return false;
            }
            if slot > p.hasta_slot {
                // R5 · retirada por plazo.
                actas_retiradas.push((p.n, p.txid, "plazo"));
                return false;
            }
            if p.propia && !p.difundida && (p.desde_slot..=p.hasta_slot).contains(&slot) {
                let mut buf = Vec::new();
                zx_core::wire::tx_a_bytes(&mut buf, &p.tx, &p.testigos);
                a_difundir.push(buf);
                p.difundida = true;
            }
            true
        });
        for buf in &a_difundir {
            let _ = self.difundir_tx_si_hay_red(buf);
        }
        // ACTA-1 · R5 · un evento por acta retirada, con su causa.
        for (n, txid, causa) in actas_retiradas {
            self.registrar_decision_acta("acta_peso_retirada", n, txid, causa);
        }
        // VS-2 · V5 · `acta_peso_aplicada` (una vez por acta) y memoria de sus firmantes.
        let mut n_actas: Vec<u64> = Vec::new();
        for (n, c) in actas_nuevas {
            self.actas_aplicadas.insert((n, c));
            if !n_actas.contains(&n) {
                n_actas.push(n);
            }
        }
        for n in n_actas {
            let evento = self.registro.evento("acta_peso_aplicada").u64("n", n);
            let _ = self.registro.escribir(evento, false);
        }
        // K2.2 · `voto_propio_difundido` (una vez por voto propio).
        for (n, clave) in voto_difundido {
            let evento = self
                .registro
                .evento("voto_propio_difundido")
                .u64("n", n)
                .str("clave", &clave)
                .u64("slot", slot);
            let _ = self.registro.escribir(evento, false);
        }
        // AUS-2c · K2 · `voto_propio_aplicado` (n, slot) o `voto_propio_descartado` (n, motivo).
        for (n, motivo) in descartes {
            if motivo == "aplicado" {
                let evento = self
                    .registro
                    .evento("voto_propio_aplicado")
                    .u64("n", n)
                    .u64("slot", slot);
                let _ = self.registro.escribir(evento, false);
            } else {
                let evento = self
                    .registro
                    .evento("voto_propio_descartado")
                    .u64("n", n)
                    .str("motivo", motivo);
                let _ = self.registro.escribir(evento, false);
            }
        }
    }

    /// FV-4b-N3 · Clave Ed25519 propia dueña de una clave BLS de voto registrada en `estado`.
    ///
    /// Devuelve una copia para poder firmar sin mantener el préstamo del estado.
    pub(super) fn procesar_voto_de_red(&mut self, bytes: &[u8]) {
        // DFV-1 · D5/D6 · el motor recibe el voto con la vista de la cadena para que el detector
        // resuelva el conflicto en el grafo y consulte el hecho.
        let resultado = match self.motor_votos.as_mut() {
            Some(m) => Some(m.recibir_voto_con_vista(bytes, &self.cadena)),
            None => None,
        };
        self.registrar_eventos_certificados_pendientes();
        let (aceptado, motivo) = match resultado {
            Some(RecepcionVoto::Aceptado { .. }) => (true, "aceptado"),
            Some(RecepcionVoto::Rechazado { motivo }) => (false, motivo),
            None => return,
        };
        // FV-N6-C7-2 §D · observación del voto recibido con formato válido (`n`/clave/plazas/
        // candidato), aceptado o rechazado con motivo.
        // FV-N6-C7-3 · un sobre mal formado **no** pierde el rechazo: se registra con su motivo
        // acotado y sin inventar campos de contexto que el sobre no aporta.
        let mut evento = self
            .registro
            .evento("voto_recibido")
            .bool("aceptado", aceptado)
            .str("motivo", motivo);
        if let Some((n, clave, plazas, candidato)) = crate::votos::observar_voto(bytes) {
            evento = evento
                .u64("n", n)
                .str("clave", &clave)
                .u64("plazas", plazas)
                .str("candidato", &candidato);
        }
        let _ = self.registro.escribir(evento, false);
        // ECL-R2b-2 · un voto ajeno válido puede cerrar una pareja contradictoria aunque el Nodo no
        // lo adopte para el cierre: la evidencia se firma, admite y difunde aquí mismo.
        self.procesar_evidencias_doble_voto();
    }

    /// A5-c-2b · X4 · entrega al motor un voto de red de la subred `subred_llegada` y contesta a la
    /// red con su veredicto (aceptado → reenviar; ignorar → ignorar; penalizar → rechazar).
    pub(super) fn procesar_voto_subred(
        &mut self,
        id: IdDiferido,
        subred_llegada: u8,
        bytes: &[u8],
    ) {
        self.agn.votos_recibidos = self.agn.votos_recibidos.saturating_add(1);
        let resultado = match self.motor_votos.as_mut() {
            Some(m) => Some(m.recibir_voto_subred(u16::from(subred_llegada), bytes, &self.cadena)),
            None => None,
        };
        self.registrar_eventos_certificados_pendientes();
        let veredicto = match resultado {
            Some(RecepcionVotoSubred::Aceptado { .. }) => {
                self.agn.votos_reenviados = self.agn.votos_reenviados.saturating_add(1);
                VeredictoFinal::Aceptar
            }
            Some(RecepcionVotoSubred::Penalizar { .. }) => {
                self.agn.votos_penalizados = self.agn.votos_penalizados.saturating_add(1);
                VeredictoFinal::Rechazar
            }
            Some(RecepcionVotoSubred::Ignorar { .. }) | None => {
                self.agn.votos_ignorados = self.agn.votos_ignorados.saturating_add(1);
                VeredictoFinal::Ignorar
            }
        };
        if let Some(red) = self.red.as_ref() {
            red.informar_validacion(id, veredicto);
        }
        self.procesar_evidencias_doble_voto();
    }

    /// A5-c-2b · X5 · entrega al motor **todos** los agregados de la vuelta en una sola llamada y
    /// contesta a la red uno a uno con el resultado de cada uno.
    ///
    /// Un agregado que no se puede deserializar contra la tabla abierta se **ignora** sin penalizar:
    /// la longitud depende de la tabla de cada nodo (RFT-27), no es un hecho objetivo.
    pub(super) fn procesar_agregados_lote(&mut self, lote: &[(IdDiferido, Vec<u8>)]) {
        #[cfg(test)]
        LOTES_AGREGADOS.with(|c| c.set(c.get().saturating_add(1)));
        self.agn.agregados_recibidos = self
            .agn
            .agregados_recibidos
            .saturating_add(u64::try_from(lote.len()).unwrap_or(u64::MAX));
        // El reparto de la tabla abierta da el tamaño `n_s` de la subred de cada agregado.
        let reparto = self
            .motor_votos
            .as_ref()
            .and_then(|m| m.tabla_actual().map(|t| (m.subredes(), t)))
            .and_then(|(s, t)| Reparto::construir(t, s).ok());
        let mut agregados: Vec<Agregado> = Vec::with_capacity(lote.len());
        let mut posiciones: Vec<Option<usize>> = Vec::with_capacity(lote.len());
        for (_, bytes) in lote {
            let parsed = reparto.as_ref().and_then(|r| {
                let sub = subred_de_agregado(bytes)?;
                let n_s = r.claves_de(sub).len();
                Agregado::deserializar(bytes, n_s).ok()
            });
            match parsed {
                Some(ag) => {
                    posiciones.push(Some(agregados.len()));
                    agregados.push(ag);
                }
                None => posiciones.push(None),
            }
        }
        let respuestas = match self.motor_votos.as_mut() {
            Some(m) => m.recibir_agregados(&agregados).unwrap_or_else(|e| {
                tracing::warn!(%e, "el motor no pudo procesar el lote de agregados; se ignoran");
                vec![RecepcionAgregado::Ignorar; agregados.len()]
            }),
            None => vec![RecepcionAgregado::Ignorar; agregados.len()],
        };
        self.registrar_eventos_certificados_pendientes();
        for ((id, _), posicion) in lote.iter().zip(posiciones.iter()) {
            let veredicto = match posicion {
                None => {
                    self.agn.agregados_ignorados = self.agn.agregados_ignorados.saturating_add(1);
                    VeredictoFinal::Ignorar
                }
                Some(pos) => match respuestas.get(*pos) {
                    Some(RecepcionAgregado::Reenviar) => {
                        self.agn.agregados_reenviados =
                            self.agn.agregados_reenviados.saturating_add(1);
                        VeredictoFinal::Aceptar
                    }
                    Some(RecepcionAgregado::Penalizar(_)) => {
                        self.agn.agregados_penalizados =
                            self.agn.agregados_penalizados.saturating_add(1);
                        VeredictoFinal::Rechazar
                    }
                    _ => {
                        self.agn.agregados_ignorados =
                            self.agn.agregados_ignorados.saturating_add(1);
                        VeredictoFinal::Ignorar
                    }
                },
            };
            if let Some(red) = self.red.as_ref() {
                red.informar_validacion(*id, veredicto);
            }
        }
    }

    /// A5-c-2b · X2 · subredes propias de voto (0-based), deduplicadas y ordenadas. Vacías si este
    /// nodo **no** emite votos: el que no vota no se suscribe a ninguna subred.
    pub(super) fn subredes_propias(&self) -> Vec<u8> {
        if !self.vota {
            return Vec::new();
        }
        let s = self.motor_votos.as_ref().map_or(
            u16::from(zx_p2p::config::SUBREDES_VOTO),
            MotorVotos::subredes,
        );
        let mut subredes: Vec<u8> = self
            .claves_bls_propias
            .iter()
            .filter_map(|clave| subred(clave, s).ok().and_then(|x| u8::try_from(x).ok()))
            .collect();
        subredes.sort_unstable();
        subredes.dedup();
        subredes
    }

    /// A5-c-2b · X7 · cupo de diferidos de los dos temas nuevos: `AGREGADORES_POR_SUBRED ×
    /// subredes` más el número de claves de la tabla abierta que caen en las subredes propias.
    pub(super) fn cupo_diferidos_agregacion(&self) -> usize {
        let s = self.motor_votos.as_ref().map_or(
            u16::from(zx_p2p::config::SUBREDES_VOTO),
            MotorVotos::subredes,
        );
        let base = (AGREGADORES_POR_SUBRED as usize).saturating_mul(usize::from(s));
        let propias = self.subredes_propias();
        let Some(motor) = self.motor_votos.as_ref() else {
            return base;
        };
        let Some(tabla) = motor.tabla_actual() else {
            return base;
        };
        let Ok(reparto) = Reparto::construir(tabla, motor.subredes()) else {
            return base;
        };
        let extra: usize = propias
            .iter()
            .map(|&sub| reparto.claves_de(u16::from(sub)).len())
            .sum();
        base.saturating_add(extra)
    }
}
