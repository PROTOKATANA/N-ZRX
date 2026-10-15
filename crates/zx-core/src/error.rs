//! Jerarquía de errores de `zx-core`.
//!
//! Dos capas, por diseño:
//!
//! - **Errores por módulo** ([`EncodingError`]…): un dato inválido llegado de un par no confiable.
//!   Es el caso **esperado**: se rechaza el objeto y la vida sigue.
//! - [`CoreError::InternalInvariant`]: una invariante que este propio crate debía garantizar y no
//!   garantizó. Es un **bug**, no un bloque inválido. Existe porque los lints del workspace
//!   prohíben `panic!`, así que un bug tiene que viajar como valor.
//!
//! La distinción importa operativamente: lo primero se cuenta y se ignora, lo segundo se alerta.
//! En ambos casos se **falla cerrado** — se rechaza —, nunca se continúa.

use thiserror::Error;

/// Fallos al decodificar o codificar la preimagen canónica (SPEC §2).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum EncodingError {
    /// El buffer se acabó antes de leer el campo completo.
    #[error("datos insuficientes: se esperaban {esperados} bytes, quedaban {disponibles}")]
    Truncado {
        /// Bytes que el campo necesitaba.
        esperados: usize,
        /// Bytes que realmente quedaban.
        disponibles: usize,
    },

    /// C-ENC-05: un `CompactSize` codificado de forma no mínima.
    ///
    /// No es pedantería. Sin esta regla un minero puede probar varias codificaciones distintas del
    /// mismo objeto contra el filtro de dificultad, en vez de solo la intencionada.
    #[error(
        "C-ENC-05: CompactSize no mínimo — el valor {valor} se codificó con el prefijo {prefijo:#04x}, \
         pero cabía en una forma más corta"
    )]
    CompactSizeNoMinimo {
        /// Valor decodificado.
        valor: u64,
        /// Byte de prefijo que se usó.
        prefijo: u8,
    },

    /// C-TX-12: un importe negativo o por encima de `ZX_VALUE_SANITY_LIMIT`.
    #[error("C-TX-12: importe fuera de rango: {brek} brek")]
    ImporteFueraDeRango {
        /// Valor rechazado.
        brek: i64,
    },

    /// C-TX-10: byte discriminante de `Lock` desconocido.
    ///
    /// **MUST** rechazarse, nunca tratarse como "gastable por cualquiera".
    #[error("C-TX-10: discriminante de Lock desconocido: {discriminante:#04x}")]
    LockDesconocido {
        /// Byte leído.
        discriminante: u8,
    },

    /// C-TX-11: `MultiSig` con parámetros inválidos.
    #[error("C-TX-11: MultiSig inválido — k={k}, n={n}: {motivo}")]
    MultiSigInvalido {
        /// Umbral de firmas.
        k: u8,
        /// Número de claves.
        n: usize,
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// C-WIRE-04: un contador declarado absurdamente grande.
    ///
    /// **No es una regla de consenso, es una cota del *parser*.** Sin ella, un peer puede declarar
    /// un `CompactSize` de 2⁶⁴−1 elementos con un cuerpo de veinte bytes y provocar una reserva de
    /// memoria enorme **antes** de que nadie lea un solo elemento — y mucho antes de que el
    /// consenso llegue a opinar sobre el peso.
    #[error("C-WIRE-04: se declararon {declarados} elementos y el máximo del lector es {maximo}")]
    DemasiadosElementos {
        /// Cuántos declaró el emisor.
        declarados: u64,
        /// Cota del lector.
        maximo: u64,
    },

    /// C-SIG-03: `hash_type` fuera del conjunto definido.
    #[error("C-SIG-03: hash_type inválido: {valor:#04x}")]
    HashTypeInvalido {
        /// Byte leído.
        valor: u8,
    },

    /// C-SIG-04: `SIGHASH_SINGLE` sin salida correspondiente.
    #[error(
        "C-SIG-04: SIGHASH_SINGLE en la entrada {indice} sin salida en ese índice ({salidas} salidas)"
    )]
    SingleSinSalida {
        /// Índice de la entrada que se firma.
        indice: usize,
        /// Número de salidas de la transacción.
        salidas: usize,
    },

    /// La firma no verifica bajo las reglas de ZIP-215.
    #[error("firma inválida: {motivo}")]
    FirmaInvalida {
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// C-ENC-06/07: dirección bech32m inválida.
    #[error("C-ENC-06: dirección inválida: {motivo}")]
    DireccionInvalida {
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// C-POW-04: `bits` no está en forma canónica.
    #[error("C-POW-04: bits {bits:#010x} no canónico: {motivo}")]
    BitsNoCanonico {
        /// Valor leído.
        bits: u32,
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// C-POW-05: el target decodificado sale de `[MIN_TARGET, POW_LIMIT]`.
    #[error("C-POW-05: {motivo}")]
    TargetFueraDeRango {
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// Índice de entrada fuera del rango de la transacción.
    #[error("índice de entrada {indice} fuera de rango ({entradas} entradas)")]
    IndiceDeEntradaFueraDeRango {
        /// Índice pedido.
        indice: usize,
        /// Entradas que tiene la transacción.
        entradas: usize,
    },

    /// Estrategia A de padres: `1 <= parent_count <= 15` para un bloque no génesis.
    #[error("Estrategia A: {declarados} padres declarados, máximo {maximo}")]
    DemasiadosPadres {
        /// Cuántos padres se declararon (incluido el seleccionado).
        declarados: u64,
        /// `MAX_PADRES` = 15.
        maximo: u64,
    },

    /// El constructor de padres rechaza duplicados; no los elimina en silencio.
    #[error("Estrategia A: padre adicional duplicado")]
    PadreDuplicado,

    /// Un padre adicional repite el `prev_hash` (padre seleccionado).
    #[error("Estrategia A: un padre adicional es igual al padre seleccionado (`prev_hash`)")]
    PadreRepetidoConSeleccionado,

    /// El parser del wire solo acepta el orden canónico estrictamente ascendente.
    #[error(
        "Estrategia A: los padres adicionales no están en orden canónico estrictamente ascendente"
    )]
    PadresNoCanonicos,

    /// El número de listas de testigos no es exactamente el número de transacciones.
    ///
    /// No se sustituyen listas ausentes por listas vacías al calcular el compromiso del cuerpo.
    #[error("cuerpo: {testigos} listas de testigos para {txs} transacciones")]
    CuerpoTestigosDescuadrados {
        /// Número de transacciones.
        txs: usize,
        /// Número de listas de testigos recibidas.
        testigos: usize,
    },

    /// La justificación PoT declara más de `MAX_BUNDLES_POT = 150` portadores.
    #[error("PoT: {declarados} portadores declarados, máximo {maximo}")]
    DemasiadosBundlesPot {
        /// Cuántos se declararon.
        declarados: u64,
        /// `MAX_BUNDLES_POT` = 150.
        maximo: u64,
    },

    /// Una lista de índices de wire no está en orden estrictamente creciente.
    #[error("índices no canónicos: MUST ser estrictamente crecientes y únicos")]
    IndicesNoCanonicos,

    /// F-05: la versión `4` (evidencia) está diseñada pero **inactiva** en v0.
    #[error("F-05: versión inactiva en v0: {version}")]
    VersionInactiva {
        /// Versión leída.
        version: u32,
    },

    /// F-05: versión que no está en la tabla de versiones activas ni es la 4.
    #[error("F-05: versión desconocida: {version}")]
    VersionDesconocida {
        /// Versión leída.
        version: u32,
    },

    /// F-07: discriminante del `tipo` de garantía fuera de `{1, 2, 3}`.
    #[error("F-07: tipo de garantía inválido: {tipo}")]
    TipoGarantiaInvalido {
        /// Byte leído.
        tipo: u8,
    },

    /// SR-1: el wire de una operación de sector no decodifica o excede su tope.
    #[error("SR-1: operación de sector inválida: {0}")]
    OperacionSectorInvalida(#[from] crate::tx::ErrorCodecSector),

    /// PT-3bc: el wire de una operación de prueba de almacenamiento v6 no decodifica o excede su
    /// tope.
    #[error("PT-3: operación de almacenamiento inválida: {0}")]
    OperacionAlmacenamientoInvalida(#[from] crate::tx::ErrorCodecAlmacenamiento),
}

/// Fallos de **forma** de una transacción, sin contexto (F-03, F-05, F-07, F-08, F-10).
///
/// Es lo que [`crate::forma::validar_forma_tx`] y
/// [`crate::forma::validar_forma_cabecera_post`] pueden decidir **sin** UTXO, sin la cabecera que
/// contiene la transacción y sin estado. Las reglas contextuales —posición de la coinbase,
/// `clave == sol.public_key` de F-09, saldos, peso— son de órdenes posteriores y **no** se
/// comprueban aquí.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorFormaTx {
    /// F-05: versión definida pero inactiva en v0 (la `4`).
    #[error("F-05: versión inactiva en v0: {version}")]
    VersionInactiva {
        /// Versión rechazada.
        version: u32,
    },

    /// F-05: versión fuera de la tabla de versiones activas.
    #[error("F-05: versión desconocida: {version}")]
    VersionDesconocida {
        /// Versión rechazada.
        version: u32,
    },

    /// F-05/F-06: `version` y `extension` no son coherentes.
    ///
    /// `1 ⇔ Ninguna`, `2 ⇔ Garantia`, `3 ⇔ CoinbasePost`.
    #[error("F-05: la versión {version} debe llevar extensión {esperada}")]
    ExtensionIncoherente {
        /// Versión de la transacción.
        version: u32,
        /// Extensión esperada para esa versión.
        esperada: &'static str,
    },

    /// F-07: `tipo` de garantía fuera de `{1, 2, 3}`.
    #[error("F-07: tipo de garantía inválido: {tipo}")]
    TipoGarantiaInvalido {
        /// Byte leído.
        tipo: u8,
    },

    /// F-07: un depósito (`tipo = 1`) MUST tener al menos una entrada.
    #[error("F-07: depósito sin entradas")]
    DepositoSinEntradas,

    /// F-07: un retiro (`tipo = 2`) MUST NOT tener entradas.
    #[error("F-07: retiro con {entradas} entradas (MUST ser 0)")]
    RetiroConEntradas {
        /// Entradas presentes.
        entradas: usize,
    },

    /// F-07: un retiro (`tipo = 2`) MUST NOT tener salidas.
    #[error("F-07: retiro con {salidas} salidas (MUST ser 0)")]
    RetiroConSalidas {
        /// Salidas presentes.
        salidas: usize,
    },

    /// F-07: una liberación (`tipo = 3`) MUST NOT tener entradas.
    #[error("F-07: liberación con {entradas} entradas (MUST ser 0)")]
    LiberacionConEntradas {
        /// Entradas presentes.
        entradas: usize,
    },

    /// F-07: una liberación (`tipo = 3`) MUST NOT tener salidas.
    #[error("F-07: liberación con {salidas} salidas (MUST ser 0)")]
    LiberacionConSalidas {
        /// Salidas presentes.
        salidas: usize,
    },

    /// F-05: una v1 con entradas es una transferencia y MUST tener al menos una salida.
    #[error("F-05: transferencia v1 sin salidas")]
    TransferenciaSinSalidas,

    /// TXL-01 (TX-2b, DR-01): `|tx_a_bytes(tx, testigos)| > max_tx_bytes`.
    ///
    /// Es forma del **bloque** (se comprueba antes de aplicar transacciones), no de una tx
    /// aislada: el límite es un parámetro de transición. Dev: `100 000` B.
    #[error("TXL-01: la transacción ocupa más de max_tx_bytes")]
    TxExcedeTamano,

    /// TXL-02 (TX-2b, DR-01): `Σ |tx_a_bytes(tx, testigos)| > max_cuerpo_bloque_bytes`, con la
    /// coinbase incluida. Forma del bloque; dev: `320 000` B.
    #[error("TXL-02: el cuerpo del bloque ocupa más de max_cuerpo_bloque_bytes")]
    CuerpoExcedeTamano,

    /// F-08: `testigos.len()` MUST ser `entradas.len() + 1` en v2.
    #[error("F-08: se esperaban {esperados} testigos y llegaron {obtenidos}")]
    NumeroDeTestigosInvalido {
        /// Número exigido.
        esperados: usize,
        /// Número presente.
        obtenidos: usize,
    },

    /// F-08: el testigo de aceptación (el último de v2) MUST medir 64 B.
    #[error("F-08: testigo de aceptación de {obtenidos} bytes (MUST ser 64)")]
    TestigoAceptacionLongitud {
        /// Longitud presente.
        obtenidos: usize,
    },

    /// F-07: `importe` de la extensión MUST ser `> 0`.
    #[error("F-07: importe de la extensión debe ser > 0")]
    ImporteCero,

    /// F-10: campo dependiente de altura, inactivo en v0.
    #[error("F-10: campo inactivo en v0: {campo}")]
    CampoInactivo {
        /// Campo rechazado.
        campo: &'static str,
    },

    /// F-10: las salidas `Lock::Htlc` nuevas no se admiten en v0.
    #[error("F-10: salida Lock::Htlc inactiva en v0")]
    SalidaHtlc,

    /// F-05: la coinbase PoST (v3) MUST NOT tener entradas.
    #[error("F-05: coinbase PoST con {entradas} entradas (MUST ser 0)")]
    EntradasEnCoinbasePost {
        /// Entradas presentes.
        entradas: usize,
    },

    /// F-05: la coinbase PoST (v3) MUST NOT tener salidas.
    #[error("F-05: coinbase PoST con {salidas} salidas (MUST ser 0)")]
    SalidasEnCoinbasePost {
        /// Salidas presentes.
        salidas: usize,
    },

    /// F-08: la coinbase PoST (v3) MUST NOT llevar testigos.
    #[error("F-08: coinbase PoST con {testigos} testigos (MUST ser 0)")]
    TestigosEnCoinbasePost {
        /// Testigos presentes.
        testigos: usize,
    },

    /// F-03: el campo `height` de una cabecera PoST es reservado y MUST ser 0 en v0.
    #[error("F-03: cabecera PoST con height = {height} (MUST ser 0)")]
    AlturaPostNoCero {
        /// Altura declarada.
        height: u32,
    },

    /// SR-1: una v5 (operación de sector) no lleva entradas ni salidas.
    #[error("SR-1: operación de sector con {entradas} entradas y {salidas} salidas (MUST ser 0)")]
    SectorConEntradasOSalidas {
        /// Entradas presentes.
        entradas: usize,
        /// Salidas presentes.
        salidas: usize,
    },

    /// `EV-04`: una `EvidenceTx` v4 con entradas, salidas o testigos de transacción.
    #[error("EV-04: EvidenceTx con entradas, salidas o testigos (MUST ser 0)")]
    EvidenciaConEntradasOSalidas,

    /// `RAT-1`: alguna de las dos cabeceras de una `EvidenceTx` v4 no lleva el
    /// `consensus_branch_id` de la red local (el que el llamante pasa como `cbid_local`).
    #[error("RAT-1: cabecera de EvidenceTx con consensus_branch_id ajeno a la red local")]
    EvidenciaCbidAjeno,

    /// `EV-01`/`EV-04`: las dos cabeceras de una `EvidenceTx` no están en orden canónico
    /// estrictamente ascendente por `pre_hash`.
    #[error("EV-01: cabeceras de EvidenceTx fuera de orden canónico por pre_hash")]
    OrdenCanonicoInvalido,

    /// Error de codificación al verificar una firma de aceptación.
    #[error(transparent)]
    Codificacion(#[from] EncodingError),
}

/// Fallo al comprobar los compromisos del cuerpo de un bloque DAG.
///
/// Distingue **cuál** de los dos compromisos falla: Merkle cubre efectos, `BodyCommitment` cubre
/// efectos y autorización. Igualarlos no es verificar firmas.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CompromisosError {
    /// `merkle_root` no coincide con la raíz recalculada sobre los `txid`.
    #[error("C-BLK-01: la raíz de Merkle no coincide con las transacciones")]
    MerkleNoCoincide,

    /// `body_commitment` no coincide con el recalculado sobre `(txid, auth_digest)`.
    #[error("compromiso del cuerpo no coincide con (txid, auth_digest)")]
    CuerpoNoCoincide,

    /// El número de listas de testigos no cuadra con el de transacciones.
    #[error(transparent)]
    TestigosDescuadrados(#[from] EncodingError),
}

/// Error agregado de `zx-core`.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Fallo de codificación canónica (SPEC §2).
    #[error(transparent)]
    Encoding(#[from] EncodingError),

    /// Una invariante interna de `zx-core` se rompió.
    ///
    /// **No es un rechazo de dato ajeno: es un bug de este crate.** No debería poder ocurrir con
    /// datos válidos por construcción. Si aparece en producción, quien lo reciba **MUST** tratarlo
    /// como alerta, no como "un bloque inválido más" — y de todas formas rechazar.
    #[error("invariante interna rota (bug de zx-core): {0}")]
    InternalInvariant(&'static str),
}
