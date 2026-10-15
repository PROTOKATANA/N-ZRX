//! Errores del motor de transición (`ErrorTransicion`).
//!
//! Los nombres de las variantes son **los mismos** que el `Err` del oráculo T01 (`ORDEN-W03` §3.9),
//! más los propios de la implementación real. La correspondencia declarada para el diferencial está
//! en §4 de la orden:
//!
//! - [`ErrorTransicion::ErrFirma`] equivale a `ErrAutorizacion` de T01;
//! - [`ErrorTransicion::ErrForma`] transporta el [`ErrorFormaTx`] de `zx-core` y §4 fija qué
//!   variantes cuentan como qué nombre de T01.

use thiserror::Error;
use zx_core::ErrorFormaTx;
use zx_votos::peso::MotivoPeso;

use crate::sectores::MotivoSector;

/// Fallo al aplicar un bloque o al rehacer el estado.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorTransicion {
    /// El bloque génesis no respeta `C-GEN-03`, o un génesis aparece fuera de la fase génesis.
    #[error("ErrGenesis")]
    ErrGenesis,
    /// `pow_ok`/`prueba_valida` en falso (§3.2).
    #[error("ErrPow")]
    ErrPow,
    /// Emisión por encima del subsidio más tarifas, o coinbase mal colocada o ausente donde se exige.
    #[error("ErrEmision")]
    ErrEmision,
    /// Gasto de una salida `coinbase_pow` antes de su madurez (`TRN-02`, `TRN-02b`).
    #[error("ErrInmaduro")]
    ErrInmaduro,
    /// Depósito en fase PoW antes de `H_dep`.
    #[error("ErrDepositoTemprano")]
    ErrDepositoTemprano,
    /// Operación de garantía cuyo firmante no es la clave, o entrada cuya firma no verifica.
    #[error("ErrAutorizacion")]
    ErrAutorizacion,
    /// Saldo insuficiente o desajuste de valor en un depósito.
    #[error("ErrSaldo")]
    ErrSaldo,
    /// Entrada repetida, entrada inexistente o salida creada dos veces.
    #[error("ErrDobleGasto")]
    ErrDobleGasto,
    /// Bloque PoW cuyo padre es terminal o descendiente de un terminal (`TRN-05`).
    #[error("ErrPowTrasCorte")]
    ErrPowTrasCorte,
    /// Bloque PoST sin terminal en su pasado (`TRN-06`).
    #[error("ErrSinTerminal")]
    ErrSinTerminal,
    /// Dos terminales en el pasado de un bloque PoST. Reservado: no alcanzable con un padre.
    #[error("ErrTerminalAmbiguo")]
    ErrTerminalAmbiguo,
    /// El productor no alcanza `requisito(B)` en `past(B)` (`TRN-07`).
    #[error("ErrGarantia")]
    ErrGarantia,
    /// Operación válida solo en la otra fase (`TRN-04`, `X-13`, `X-14`).
    #[error("ErrOperacionFase")]
    ErrOperacionFase,
    /// Prueba de sector después de `P_sec` (`TRN-12`). Fuera de alcance en `SEC-0`.
    #[error("ErrPruebaTardia")]
    ErrPruebaTardia,
    /// Bloque PoST que usa un sector no activo. Fuera de alcance en `SEC-0`.
    #[error("ErrSectorInactivo")]
    ErrSectorInactivo,
    /// Altura, slot o peso que no progresan (`R-10`).
    #[error("ErrSlot")]
    ErrSlot,
    /// Desbordamiento aritmético detectado; nunca silencioso.
    #[error("ErrDesbordamiento")]
    ErrDesbordamiento,
    /// Operación declarada en el contrato pero no modelada en v0 (`SEC-A`, evidencias).
    #[error("ErrFueraDeAlcanceV0")]
    ErrFueraDeAlcanceV0,
    /// Segundo retiro de una clave con una retirada viva (`R-2`).
    #[error("ErrRetiroPendiente")]
    ErrRetiroPendiente,
    /// Nonce de una operación de garantía distinto del `nonce_siguiente` de la clave (F-15).
    #[error("ErrNonce")]
    ErrNonce,
    /// La firma de una entrada o de aceptación no verifica (equivale a `ErrAutorizacion` de T01).
    #[error("ErrFirma")]
    ErrFirma,
    /// Fallo de forma de una transacción o de una cabecera PoST (`zx-core`).
    #[error("ErrForma: {0}")]
    ErrForma(#[from] ErrorFormaTx),
    /// Un bloque cuyo padre no es válido o no se conoce (`R-15`).
    #[error("ErrSinPadre")]
    ErrSinPadre,
    // ── SL-4a · evidencia y castigo (CONTRATO-EVIDENCIA-v0 con Ratificación v0) ──────────────
    /// `EV-01`/`EV-06`/`EV-07`: no hay dos decisiones de firma válidas.
    #[error("ErrSinEvidencia")]
    ErrSinEvidencia,
    /// `EV-14`: `slot_aplicacion ≥ slot_falta + Plazo_slots`.
    #[error("ErrEvidenciaTardia")]
    ErrEvidenciaTardia,
    /// `EV-12`: el `incident_id` ya está registrado.
    #[error("ErrEvidenciaDuplicada")]
    ErrEvidenciaDuplicada,
    /// `EV-24(i)`: la liberación encuentra un incidente admitido y no liquidado.
    #[error("ErrCasoAbierto")]
    ErrCasoAbierto,
    /// `EV-24(ii)`/`EV-15b`: producción reciente de la clave (ventana abierta).
    #[error("ErrVentanaAbierta")]
    ErrVentanaAbierta,
    /// `RAT-3`: la puerta `R_slots > Plazo_slots + M_margen_slots` no se cumple.
    #[error("ErrPuertaRAT3")]
    ErrPuertaRAT3,
    // ── SR-1-2 · registro de sectores ───────────────────────────────────────────────────────
    /// Una operación de sector v5 rechazada por el autómata (`C-SEC-13`).
    #[error("ErrSector({0:?})")]
    ErrSector(MotivoSector),
    // ── PT-3bc · prueba de almacenamiento ───────────────────────────────────────────────────
    /// Un bloque con más de una tx v6 de clase `0x01`/`0x02` (`REVISION-PT3a` decisión 3).
    #[error("ErrDosPruebasAlmacenamiento")]
    ErrDosPruebasAlmacenamiento,
    // ── FV-4b-N2 · certificado de finalidad y doble voto como estado ────────────────────────
    /// La tabla del certificado no coincide con las claves/pesos registrados del estado.
    #[error("ErrCertificadoInstancia")]
    ErrCertificadoInstancia,
    /// El peso de una clave del certificado no coincide con `fuente_peso_de` del estado.
    #[error("ErrCertificadoPeso")]
    ErrCertificadoPeso,
    /// La verificación VRF por lotes del certificado falla.
    #[error("ErrCertificadoVrf")]
    ErrCertificadoVrf,
    /// Las plazas declaradas no son las recomputadas por el sorteo exacto.
    #[error("ErrCertificadoPlazas")]
    ErrCertificadoPlazas,
    /// La firma BLS agregada o el quórum del certificado no verifican.
    #[error("ErrCertificadoFirma")]
    ErrCertificadoFirma,
    /// Un certificado de la misma instancia no coincide con el ya adoptado (rama en conflicto).
    #[error("ErrCertificadoConflictivo")]
    ErrCertificadoConflictivo,
    /// El certificado es de una instancia anterior a la finalidad ya fijada (retroceso).
    #[error("ErrFinalidadRetrocede")]
    ErrFinalidadRetrocede,
    /// La evidencia de doble voto no verifica (firmas o clave no registrada).
    #[error("ErrEvidenciaVoto")]
    ErrEvidenciaVoto,
    /// AT-1b · W4 · la evidencia de ventanas distintas no es admisible: falta el hecho o es
    /// `Inadmisible` (alguno de los dos bloques no está aplicado antes que `x`).
    #[error("ErrEvidenciaInadmisible")]
    ErrEvidenciaInadmisible,
    /// AT-1b · W4 · la evidencia de ventanas distintas es admisible pero **no** constituye la falta
    /// de la parte B (`SinFalta`): la transacción se descarta y puede volver a presentarse.
    #[error("ErrEvidenciaSinFalta")]
    ErrEvidenciaSinFalta,
    // ── FV-4b-N3 · revelación obligatoria del sorteo (AV-1) ─────────────────────────────────
    /// El compromiso de ventana no cuadra con la clave BLS registrada o con la tabla `T_n`.
    #[error("ErrCompromisoInstancia")]
    ErrCompromisoInstancia,
    /// El peso de una clave del compromiso no coincide con `fuente_peso_de` del estado.
    #[error("ErrCompromisoPeso")]
    ErrCompromisoPeso,
    /// Ya hay un compromiso de la misma clave y ventana.
    #[error("ErrCompromisoDuplicado")]
    ErrCompromisoDuplicado,
    /// La revelación no tiene compromiso previo (o la tabla de la instancia no está fijada).
    #[error("ErrRevelacionSinCompromiso")]
    ErrRevelacionSinCompromiso,
    /// La revelación llega antes de que venza el plazo de gracia.
    #[error("ErrRevelacionPrematura")]
    ErrRevelacionPrematura,
    /// La revelación llega después del plazo `W_reveal`.
    #[error("ErrRevelacionTardia")]
    ErrRevelacionTardia,
    /// La ventana ya fue revelada por esa clave.
    #[error("ErrRevelacionDuplicada")]
    ErrRevelacionDuplicada,
    /// La prueba VRF revelada no casa con la raíz Merkle comprometida.
    #[error("ErrRevelacionNoCoincide")]
    ErrRevelacionNoCoincide,
    // ── AUS-2a · voto propio (AV-11/AV-12) ──────────────────────────────────────────────────
    /// El voto propio llega fuera de `[apertura(n), cierre(n) + W_reveal]`.
    #[error("ErrVotoPropioPlazo")]
    ErrVotoPropioPlazo,
    /// La clave BLS del voto propio no es la registrada por esa clave Ed25519.
    #[error("ErrVotoPropioClave")]
    ErrVotoPropioClave,
    /// La firma BLS del voto propio no verifica sobre `(n, candidato, h_t_siguiente)`.
    #[error("ErrVotoPropioFirma")]
    ErrVotoPropioFirma,
    /// La clave ya tiene voto admitido en esa ventana (certificado o voto propio previo).
    #[error("ErrVotoPropioDuplicado")]
    ErrVotoPropioDuplicado,
    // ── PD-1b · certificado compacto por peso (0x09) y acta de presencia (0x0A) ────────────────
    /// El certificado/acta compacto por peso no verifica; lleva el motivo del contrato A5/A6.
    #[error("ErrCertificadoPeso({0:?})")]
    ErrCertificadoPesoMotivo(MotivoPeso),
    /// Los bytes del certificado/acta compacto no se pueden deserializar (longitud o forma).
    #[error("ErrCertificadoPesoBytes")]
    ErrCertificadoPesoBytes,
    /// La tabla siguiente del certificado compacto no cuadra o no viene en orden canónico.
    #[error("ErrCertificadoPesoTabla")]
    ErrCertificadoPesoTabla,
    /// La tabla vigente del estado es «desconocida» (C2) y el certificado la exige.
    #[error("ErrCertificadoPesoTablaDesconocida")]
    ErrCertificadoPesoTablaDesconocida,
    /// TB-1a · T9 · el certificado es de una ventana que aún no ha abierto: el slot del bloque que lo
    /// aplica es menor que `apertura_ventana(n)`.
    #[error("ErrCertificadoVentanaFutura")]
    ErrCertificadoVentanaFutura,
    /// CERT-T · el slot de aplicación supera `cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS`
    /// (suma saturada); el techo es inclusivo para todo certificado compacto.
    #[error("ErrCertificadoPlazo")]
    ErrCertificadoPlazo,
    /// TB-1c · T3 · la huella declarada está en la cola `Q` del estado pero falta su contenido
    /// (`tablas_voto_contenido`), que T8 conserva. Es un error **interno**: nunca un `panic` ni una
    /// aceptación.
    #[error("ErrTablaDerivadaSinContenido")]
    ErrTablaDerivadaSinContenido,
    /// El acta llega fuera de `[apertura(n), cierre(n) + W_reveal]`.
    #[error("ErrActaPlazo")]
    ErrActaPlazo,
    /// La tabla de la ventana del acta es desconocida (C5).
    #[error("ErrActaTablaDesconocida")]
    ErrActaTablaDesconocida,
    /// La ventana del acta ya fue liquidada.
    #[error("ErrActaLiquidada")]
    ErrActaLiquidada,
    /// Todos los firmantes del acta ya constan en la ventana.
    #[error("ErrActaRepetida")]
    ErrActaRepetida,
    // ── RA-1 · rearranque por ciclos tras una pausa larga (parte D, mejora 8) ──────────────────
    /// RA-1 · Y3 · la ventana del certificado de rearranque no abre dentro de la fase activa de
    /// ningún ciclo (`[inicio(j), inicio(j) + A)`).
    #[error("ErrRearranqueFueraDeFase")]
    ErrRearranqueFueraDeFase,
    /// RA-1 · Y3 · no existe la instantánea de la tabla del ciclo `j` de la ventana.
    #[error("ErrRearranqueSinTabla")]
    ErrRearranqueSinTabla,
}

impl ErrorTransicion {
    /// Nombre del error tal y como lo escribe el oráculo T01, para el diferencial.
    ///
    /// Aplica las correspondencias de §4 de la orden: `ErrFirma` se lee como `ErrAutorizacion` y
    /// los errores de forma concretos se leen como el nombre que el oráculo escribe en el vector.
    /// Desde SL-4c, los tres defectos de forma de la `EvidenceTx` (`RAT-1`, `EV-01`/`EV-04`) se
    /// escriben con el nombre **completo** `ErrForma(...)`, igual que en T01 v0.5 y T04 v0.6.
    #[must_use]
    pub fn nombre_t01(&self) -> &'static str {
        match self {
            Self::ErrFirma | Self::ErrAutorizacion => "ErrAutorizacion",
            Self::ErrForma(ErrorFormaTx::VersionInactiva { .. }) => "VersionInactiva",
            Self::ErrForma(ErrorFormaTx::ImporteCero) => "ErrSaldo",
            Self::ErrForma(ErrorFormaTx::TransferenciaSinSalidas) => "ErrSaldo",
            // Correspondencia de W02b: el oráculo T01 comprueba la autorización del depósito
            // **antes** de consumir entradas, así que un depósito sin entradas y con firmante
            // distinto de la clave da `ErrAutorizacion`; la forma lo rechaza antes con
            // `DepositoSinEntradas` (F-07). Se traduce al nombre del oráculo para el diferencial
            // (los vectores solo combinan `ent=[]` con firmante ≠ clave, ver `PROGRESO.md` FD-7).
            Self::ErrForma(ErrorFormaTx::DepositoSinEntradas) => "ErrAutorizacion",
            // SL-4c · las tres formas de la v4, con el nombre completo del vector.
            Self::ErrForma(ErrorFormaTx::EvidenciaConEntradasOSalidas) => {
                "ErrForma(EvidenciaConEntradasOSalidas)"
            }
            Self::ErrForma(ErrorFormaTx::EvidenciaCbidAjeno) => "ErrForma(EvidenciaCbidAjeno)",
            Self::ErrForma(ErrorFormaTx::OrdenCanonicoInvalido) => {
                "ErrForma(OrdenCanonicoInvalido)"
            }
            // TX-2b · TXL-01/TXL-02: forma de tamaño, con el nombre completo del vector v0.6.
            Self::ErrForma(ErrorFormaTx::TxExcedeTamano) => "ErrForma(TxExcedeTamano)",
            Self::ErrForma(ErrorFormaTx::CuerpoExcedeTamano) => "ErrForma(CuerpoExcedeTamano)",
            Self::ErrGenesis => "ErrGenesis",
            Self::ErrPow => "ErrPow",
            Self::ErrEmision => "ErrEmision",
            Self::ErrInmaduro => "ErrInmaduro",
            Self::ErrDepositoTemprano => "ErrDepositoTemprano",
            Self::ErrSaldo => "ErrSaldo",
            Self::ErrDobleGasto => "ErrDobleGasto",
            Self::ErrPowTrasCorte => "ErrPowTrasCorte",
            Self::ErrSinTerminal => "ErrSinTerminal",
            Self::ErrTerminalAmbiguo => "ErrTerminalAmbiguo",
            Self::ErrGarantia => "ErrGarantia",
            Self::ErrOperacionFase => "ErrOperacionFase",
            Self::ErrPruebaTardia => "ErrPruebaTardia",
            Self::ErrSectorInactivo => "ErrSectorInactivo",
            Self::ErrSlot => "ErrSlot",
            Self::ErrDesbordamiento => "ErrDesbordamiento",
            Self::ErrFueraDeAlcanceV0 => "ErrFueraDeAlcanceV0",
            Self::ErrRetiroPendiente => "ErrRetiroPendiente",
            Self::ErrNonce => "ErrNonce",
            Self::ErrSinEvidencia => "ErrSinEvidencia",
            Self::ErrEvidenciaTardia => "ErrEvidenciaTardia",
            Self::ErrEvidenciaDuplicada => "ErrEvidenciaDuplicada",
            Self::ErrCasoAbierto => "ErrCasoAbierto",
            Self::ErrVentanaAbierta => "ErrVentanaAbierta",
            Self::ErrPuertaRAT3 => "ErrPuertaRAT3",
            Self::ErrForma(_) => "ErrForma",
            Self::ErrSinPadre => "ErrSinPadre",
            Self::ErrSector(_) => "ErrSector",
            Self::ErrDosPruebasAlmacenamiento => "ErrDosPruebasAlmacenamiento",
            Self::ErrCertificadoInstancia => "ErrCertificadoInstancia",
            Self::ErrCertificadoPeso => "ErrCertificadoPeso",
            Self::ErrCertificadoVrf => "ErrCertificadoVrf",
            Self::ErrCertificadoPlazas => "ErrCertificadoPlazas",
            Self::ErrCertificadoFirma => "ErrCertificadoFirma",
            Self::ErrCertificadoConflictivo => "ErrCertificadoConflictivo",
            Self::ErrFinalidadRetrocede => "ErrFinalidadRetrocede",
            Self::ErrEvidenciaVoto => "ErrEvidenciaVoto",
            Self::ErrEvidenciaInadmisible => "ErrEvidenciaInadmisible",
            Self::ErrEvidenciaSinFalta => "ErrEvidenciaSinFalta",
            Self::ErrCompromisoInstancia => "ErrCompromisoInstancia",
            Self::ErrCompromisoPeso => "ErrCompromisoPeso",
            Self::ErrCompromisoDuplicado => "ErrCompromisoDuplicado",
            Self::ErrRevelacionSinCompromiso => "ErrRevelacionSinCompromiso",
            Self::ErrRevelacionPrematura => "ErrRevelacionPrematura",
            Self::ErrRevelacionTardia => "ErrRevelacionTardia",
            Self::ErrRevelacionDuplicada => "ErrRevelacionDuplicada",
            Self::ErrRevelacionNoCoincide => "ErrRevelacionNoCoincide",
            Self::ErrVotoPropioPlazo => "ErrVotoPropioPlazo",
            Self::ErrVotoPropioClave => "ErrVotoPropioClave",
            Self::ErrVotoPropioFirma => "ErrVotoPropioFirma",
            Self::ErrVotoPropioDuplicado => "ErrVotoPropioDuplicado",
            Self::ErrCertificadoPesoMotivo(_) => "ErrCertificadoPeso",
            Self::ErrCertificadoPesoBytes => "ErrCertificadoPesoBytes",
            Self::ErrCertificadoPesoTabla => "ErrCertificadoPesoTabla",
            Self::ErrCertificadoPesoTablaDesconocida => "ErrCertificadoPesoTablaDesconocida",
            Self::ErrCertificadoVentanaFutura => "ErrCertificadoVentanaFutura",
            Self::ErrCertificadoPlazo => "ErrCertificadoPlazo",
            Self::ErrTablaDerivadaSinContenido => "ErrTablaDerivadaSinContenido",
            Self::ErrActaPlazo => "ErrActaPlazo",
            Self::ErrActaTablaDesconocida => "ErrActaTablaDesconocida",
            Self::ErrActaLiquidada => "ErrActaLiquidada",
            Self::ErrActaRepetida => "ErrActaRepetida",
            Self::ErrRearranqueFueraDeFase => "ErrRearranqueFueraDeFase",
            Self::ErrRearranqueSinTabla => "ErrRearranqueSinTabla",
        }
    }
}
