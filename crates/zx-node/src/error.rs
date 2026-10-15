//! Error de arranque y de operación del nodo.

use std::path::PathBuf;

use zx_core::Red;

use crate::rechazo::ClasificacionRechazo;

/// Fallo del nodo. Cualquier variante termina el proceso con código ≠ 0 (decisión 2 y 4 de la
/// orden).
#[derive(Debug, thiserror::Error)]
pub enum ErrorNodo {
    /// La red configurada no es `Red::Dev` (decisión 2): se rechaza **antes** de abrir disco o
    /// sockets.
    #[error("red configurada {encontrada:?}: este binario solo arranca en Red::Dev")]
    RedNoEsDev {
        /// Red que se pidió por CLI.
        encontrada: Red,
    },
    /// El perfil dev no se pudo construir.
    #[error("perfil dev: {0}")]
    Perfil(#[from] crate::perfil::ErrorPerfil),
    /// Fallo de E/S (directorio de datos, registro, parcelas).
    #[error("E/S: {0}")]
    Io(#[from] std::io::Error),
    /// Fallo del almacén persistente.
    #[error("almacén: {0}")]
    Almacen(#[from] zx_storage::StorageError),
    /// El génesis reconstruido no coincide con la constante congelada de W04 (defensa, referencia
    /// independiente exigida por `LINEO.md`).
    #[error("el génesis reconstruido ({encontrado}) no coincide con el esperado ({esperado})")]
    GenesisDiscrepante {
        /// Hash reconstruido.
        encontrado: zx_core::BlockHash,
        /// Hash esperado (`HASH_GENESIS_DEV`).
        esperado: zx_core::BlockHash,
    },
    /// El génesis de W04 no se pudo construir.
    #[error("génesis de W04: {0}")]
    Genesis(#[from] zx_consensus::ErrorPow),
    /// Un bloque **propio** fue rechazado por la tubería de admisión.
    ///
    /// `ORDEN-W06d5` decisión 3: ya no es fatal por sí solo. `clasificacion` distingue un rechazo
    /// **legítimo** del protocolo ante un caso de borde real (se registra y se descarta, el nodo
    /// sigue) de una **violación de invariante interna** (fatal, decisión 4 de `ORDEN-W06d1`, sin
    /// cambios). Ver `crate::rechazo` para el criterio completo.
    #[error("bloque propio {hash} rechazado en la admisión: {motivo}")]
    BloquePropioRechazado {
        /// Hash del bloque propio rechazado.
        hash: zx_core::BlockHash,
        /// Motivo exacto.
        motivo: String,
        /// Legítimo (no fatal) o interno (fatal).
        clasificacion: ClasificacionRechazo,
    },
    /// P2 (`ORDEN-MP1`): un bloque **propio** recién minado fue rechazado por su cuerpo. Se cumple
    /// que `Cadena::admitir` devolvió `MotivoBloque::ErrTransicion`, que la clasificación **no** es
    /// legítima y que el bloque lleva **al menos una transacción además de la coinbase**. El fallo
    /// pudo entrar por una transacción de terceros, así que `fase_pow` **no** lo trata como fatal:
    /// escribe `bloque_propio_rechazado_por_tx`, expulsa de la cola esas transacciones (sin
    /// marcarlas como aplicadas) y sigue. En cualquier otro sitio es tan fatal como
    /// [`ErrorNodo::BloquePropioRechazado`] con `Interno`.
    #[error("bloque propio {hash} (altura {altura}) rechazado por su cuerpo: {motivo}")]
    BloquePropioRechazadoPorTx {
        /// Hash del bloque propio rechazado.
        hash: zx_core::BlockHash,
        /// Altura PoW del bloque.
        altura: u32,
        /// Motivo exacto.
        motivo: String,
        /// Número total de transacciones del bloque (incluida la coinbase).
        n_txs: u64,
    },
    /// El almacén no reprodujo un bloque durante la repetición al reiniciar (D-N03′).
    #[error(
        "repetición: el bloque {hash} de la posición {indice} no se pudo reconstruir: {motivo}"
    )]
    RepeticionFallida {
        /// Índice del registro de admisión.
        indice: u64,
        /// Hash del bloque que falló.
        hash: zx_core::BlockHash,
        /// Motivo.
        motivo: String,
    },
    /// El testigo de un bloque PoW ya admitido no reproduce su firma al repetir (defensa contra el
    /// límite declarado por `REVISION-W06b.md`: la integridad del almacén no cubre los testigos
    /// PoW; la repetición del motor sí, porque vuelve a comprobar las firmas).
    #[error("repetición: el testigo de la entrada {indice} (bloque {hash}) no verifica: {motivo}")]
    TestigoPowCorrupto {
        /// Índice del registro.
        indice: u64,
        /// Hash del bloque.
        hash: zx_core::BlockHash,
        /// Motivo del motor de transición.
        motivo: String,
    },
    /// Fallo al construir el contexto de pieza / historia génesis dev de `zx-poas`.
    #[error("historia génesis dev: {0}")]
    Historia(#[from] zx_poas::ErrorHistoriaGenesis),
    /// Fallo del granjero (parcela, auditoría).
    #[error("granjero: {0}")]
    Farmer(#[from] zx_farmer::ErrorFarmer),
    /// Directorio de datos inválido.
    #[error("directorio de datos inválido: {0}")]
    DirectorioInvalido(PathBuf),
    /// `ORDEN-SL4b2` decisión 1: la puerta RAT-3 (`R_slots > Plazo_slots + M_margen_slots`) no se
    /// cumple con el perfil configurado. El nodo se niega a arrancar: sin esta desigualdad, un
    /// infractor podría liberar su garantía antes de que la ventana de admisión de su propia falta
    /// cierre (`CONTRATO-EVIDENCIA-v0.md` EV-15/EV-24(ii)).
    #[error(
        "puerta RAT-3 incumplida: R_slots ({r_slots}) debe ser mayor que Plazo_slots + \
         M_margen_slots ({plazo_mas_margen})"
    )]
    PuertaRat3Incumplida {
        /// `R_slots` configurado.
        r_slots: u64,
        /// `Plazo_slots + M_margen_slots` configurado.
        plazo_mas_margen: u64,
    },
    /// FV-4b-N4 · R-ECL-05: la puerta `R_slots >= V_slots + Plazo_voto + M_margen_voto` no se cumple
    /// con el perfil de votos. El nodo se niega a arrancar: sin esta desigualdad la garantía de una
    /// clave podría liberarse antes de que la ventana de voto que la necesita cierre.
    #[error(
        "puerta R-ECL-05 incumplida: R_slots ({r_slots}) debe ser >= V_slots ({v_slots}) + \
         Plazo_voto + M_margen_voto ({plazos})"
    )]
    PuertaRecl05Incumplida {
        /// `R_slots` configurado.
        r_slots: u64,
        /// `V_slots = LOOKBACK·T_inst` de la ventana de voto.
        v_slots: u64,
        /// `Plazo_voto_slots + M_margen_voto_slots`.
        plazos: u64,
    },
    /// Fallo genérico con mensaje libre (última instancia; se documenta en `PROGRESO.md` cada uso).
    #[error("{0}")]
    Otro(String),
}

/// Alias de resultado del nodo.
pub type ResultadoNodo<T> = Result<T, ErrorNodo>;
