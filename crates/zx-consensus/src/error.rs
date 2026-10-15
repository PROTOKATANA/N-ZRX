//! Errores del motor PoW.
//!
//! Un solo enum, [`ErrorPow`], para que cada rechazo de §6 del encargo tenga **su** variante
//! explícita y para que la distinción **permanente / diferible** de `C-TS-03` sea consultable en el
//! tipo y no una convención de comentario.

use thiserror::Error;
use zx_core::BlockHash;

/// Fallo al aplicar una regla del motor PoW.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorPow {
    /// La ventana del retarget no tiene el tamaño exacto que exige la red.
    ///
    /// **MUST NOT** encogerse dinámicamente: una ventana más corta produce un target distinto y por
    /// tanto un split.
    #[error(
        "ventana de tamaño incorrecto: {timestamps} timestamps y {targets} targets \
         (se esperan {esperados}+1 y {esperados})"
    )]
    VentanaDeTamanoIncorrecto {
        /// Timestamps recibidos.
        timestamps: usize,
        /// Targets recibidos.
        targets: usize,
        /// `N` de la red.
        esperados: usize,
    },

    /// Ventana vacía donde se esperaba al menos un elemento.
    #[error("ventana vacía")]
    VentanaVacia,

    /// `C-TS-02`: la ventana del median-time-past no tiene exactamente `mtp_w` timestamps.
    #[error("C-TS-02: se esperaban {esperados} timestamps para el MTP y llegaron {recibidos}")]
    MtpDeTamanoIncorrecto {
        /// Timestamps recibidos.
        recibidos: usize,
        /// `mtp_w` de la red.
        esperados: usize,
    },

    /// `C-ENC-03`: desbordamiento detectado. **Nunca en silencio.**
    #[error("C-ENC-03: desbordamiento aritmético en una ruta de consenso")]
    DesbordamientoAritmetico,

    /// `C-UPG-02`: ninguna rama de consenso cubre esa altura.
    #[error("C-UPG-02: no hay rama de consenso activa a la altura {altura}")]
    SinRamaActiva {
        /// Altura consultada.
        altura: u32,
    },

    /// `C-HDR-02b`: la cabecera declara una rama que no es la activa (protección *wipe-out*).
    #[error(
        "C-HDR-02b: a la altura {altura} rige la rama {esperado:#010x}, la cabecera dice {encontrado:#010x}"
    )]
    BranchIdIncorrecto {
        /// Altura del bloque.
        altura: u32,
        /// Identificador que debería llevar.
        esperado: u32,
        /// El que lleva.
        encontrado: u32,
    },

    /// La tabla de ramas está mal formada.
    #[error("tabla de ramas inválida: {motivo}")]
    TablaDeRamasInvalida {
        /// Qué invariante se rompe.
        motivo: &'static str,
    },

    /// `C-BLK-05`: `bits` no es el valor exacto que devuelve el retarget.
    #[error("C-BLK-05: bits esperado {esperado:#010x}, encontrado {encontrado:#010x}")]
    BitsIncorrectos {
        /// El que debería llevar.
        esperado: u32,
        /// El que lleva.
        encontrado: u32,
    },

    /// `C-POW-04`: `bits` no está en forma canónica.
    #[error("C-POW-04: bits {bits:#010x} no canónico: {motivo}")]
    BitsNoCanonicos {
        /// Valor leído.
        bits: u32,
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// `C-POW-05`: el target decodificado sale de los límites de la red.
    #[error("C-POW-05: {motivo}")]
    TargetFueraDeRango {
        /// Por qué se rechaza.
        motivo: &'static str,
    },

    /// El `prev_hash` de la cabecera no es el hash del padre.
    #[error("C-HDR-01: prev_hash {encontrado} distinto del padre {esperado}")]
    PrevHashIncorrecto {
        /// Hash del padre que el contexto declara.
        esperado: BlockHash,
        /// Hash declarado en la cabecera.
        encontrado: BlockHash,
    },

    /// La altura de la cabecera no es `altura_padre + 1`.
    #[error("C-HDR-02: altura {encontrada} no es altura_padre + 1 ({esperada})")]
    AlturaIncorrecta {
        /// `altura_padre + 1`.
        esperada: u32,
        /// La declarada.
        encontrada: u32,
    },

    /// `C-BLK-04`: el hash de PoW no satisface el target.
    #[error("C-BLK-04: el PoW no se satisface")]
    PowInsuficiente,

    /// El timestamp de la cabecera no cabe en `i64`.
    #[error("timestamp {ts} fuera del rango representable")]
    TimestampFueraDeRango {
        /// Valor leído.
        ts: u64,
    },

    /// `C-TS-01`: el timestamp no avanza respecto al padre. Rechazo **permanente**.
    #[error("C-TS-01: ts({altura}) = {ts} no supera ts(padre) = {ts_padre}")]
    TimestampNoMonotono {
        /// Altura del bloque.
        altura: u32,
        /// Timestamp del bloque.
        ts: i64,
        /// Timestamp del padre.
        ts_padre: i64,
    },

    /// `C-TS-03`: el timestamp está demasiado en el futuro.
    ///
    /// Rechazo **NO permanente**: el bloque se difiere y se reintenta. **MUST NOT** cachearse como
    /// inválido ni banearse al par — hacerlo produce un split garantizado ante partición temporal.
    #[error("C-TS-03: ts = {ts} excede reloj_local + FTL = {limite} (diferible, NO permanente)")]
    TimestampDemasiadoFuturo {
        /// Timestamp del bloque.
        ts: i64,
        /// Límite admitido.
        limite: i64,
    },

    /// El bloque génesis no cumple alguna invariante (§15, `C-GEN-01…07`).
    #[error("§15: génesis inválido: {motivo}")]
    GenesisInvalido {
        /// Qué invariante se rompe.
        motivo: &'static str,
    },
}

impl ErrorPow {
    /// ¿Es un rechazo **permanente**?
    ///
    /// La distinción es de consenso, no cosmética. Un rechazo diferible **MUST NOT** cachearse como
    /// inválido: si un nodo marca permanentemente un bloque que solo llegó pronto, y luego su reloj
    /// se pone al día, se queda fuera de la cadena buena para siempre. `C-TS-03` lo dice
    /// explícitamente.
    #[must_use]
    pub const fn es_permanente(&self) -> bool {
        !matches!(self, Self::TimestampDemasiadoFuturo { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorPow;

    #[test]
    fn solo_el_timestamp_futuro_es_diferible() {
        let futuro = ErrorPow::TimestampDemasiadoFuturo { ts: 10, limite: 5 };
        assert!(
            !futuro.es_permanente(),
            "C-TS-03: se difiere y se reintenta"
        );
        assert!(ErrorPow::PowInsuficiente.es_permanente());
        assert!(
            ErrorPow::BitsIncorrectos {
                esperado: 1,
                encontrado: 2
            }
            .es_permanente()
        );
        assert!(
            ErrorPow::TimestampNoMonotono {
                altura: 1,
                ts: 0,
                ts_padre: 0
            }
            .es_permanente(),
            "C-TS-01 es permanente"
        );
    }
}
