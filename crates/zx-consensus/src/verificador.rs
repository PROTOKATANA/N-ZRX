//! Verificador de cabecera PoW (`C-HDR-01`, `C-BLK-04`, `C-BLK-05`, `C-TS-01`, `C-TS-03`).
//!
//! Comprueba **solo la cabecera**: rama activa, padre, altura, `bits`, PoW y timestamps. **No**
//! valida el cuerpo, la coinbase ni el fin del PoW (TRN-05 es de W03). Separar la cabecera es lo que
//! permite un sync *headers-first* y una barrera anti-DoS: un par hostil no debe poder obligarnos a
//! verificar firmas antes de descubrir que la cabecera no cumple el PoW.
//!
//! El target esperado lo calcula el llamante, que tiene el estado (ventana del retarget leída sobre
//! **la cadena candidata**, no sobre la activa: `C-REORG-06`). Aquí solo se comprueba que la
//! cabecera declara exactamente el `bits` de ese target.

use primitive_types::U256;
use zx_core::BlockHash;
use zx_core::EncodingError;
use zx_core::Red;
use zx_core::preimage::block::BlockHeader;
use zx_core::target::{codificar_con, decodificar_con};

use crate::activacion::comprobar_branch_id;
use crate::algoritmo::AlgoritmoPow;
use crate::error::ErrorPow;
use crate::parametros::ParametrosPow;
use crate::timestamps::{comprobar_ftl, comprobar_monotonia};

/// Todo lo que la validación de cabecera necesita saber del estado de la cadena.
///
/// Va explícito y no oculto tras un handle para que se vea de un vistazo **qué mira el consenso**.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ContextoPow {
    /// Red, para la tabla de ramas y los límites de target.
    pub red: Red,
    /// Parámetros PoW de esa red.
    pub parametros: ParametrosPow,
    /// Altura del padre.
    pub altura_padre: u32,
    /// Hash de la cabecera del padre.
    pub hash_padre: BlockHash,
    /// Target que exige el retarget a esta altura (`C-BLK-05`).
    pub target_esperado: U256,
    /// Timestamp del padre, para `C-TS-01`.
    pub ts_padre: i64,
    /// Reloj **local** del nodo, para `C-TS-03`. Nunca hora de red (`C-TS-04`).
    pub reloj_local: i64,
}

/// Valida **solo la cabecera PoW**.
///
/// # Orden de comprobaciones
///
/// 1. `branch_id` de la rama activa a esa altura (`C-HDR-02b`),
/// 2. `prev_hash = hash_padre`,
/// 3. `height = altura_padre + 1`,
/// 4. `bits` canónico y dentro de los límites de la red (`C-POW-04`, `C-POW-05`),
/// 5. `bits = codificar_con(target_esperado)` (`C-BLK-05`),
/// 6. `hash_pow < target` estricto, big-endian (`C-BLK-04`, `C-POW-01`),
/// 7. `ts > ts_padre` (`C-TS-01`, permanente) y `ts ≤ reloj_local + ftl` (`C-TS-03`, **diferible**).
///
/// # Errores
/// La variante de [`ErrorPow`] de la primera regla incumplida. Ojo con [`ErrorPow::es_permanente`]:
/// el rechazo por timestamp futuro **MUST NOT** cachearse.
pub fn validar_cabecera_pow(
    c: &BlockHeader,
    ctx: &ContextoPow,
    algo: &impl AlgoritmoPow,
) -> Result<(), ErrorPow> {
    let altura = c.height;

    // C-HDR-02b · rama de consenso correcta. Protección contra wipe-out.
    comprobar_branch_id(ctx.red, altura, c.consensus_branch_id)?;

    // El padre que la cabecera declara MUST ser el que el contexto tiene.
    if c.prev_hash != ctx.hash_padre {
        return Err(ErrorPow::PrevHashIncorrecto {
            esperado: ctx.hash_padre,
            encontrado: c.prev_hash,
        });
    }

    // La cabecera PoW vive exactamente un nivel por encima de su padre.
    let esperada = ctx
        .altura_padre
        .checked_add(1)
        .ok_or(ErrorPow::DesbordamientoAritmetico)?;
    if altura != esperada {
        return Err(ErrorPow::AlturaIncorrecta {
            esperada,
            encontrada: altura,
        });
    }

    // C-POW-04/C-POW-05 · el `bits` de la cabecera MUST ser canónico y admisible en su red. Se
    // comprueba **antes** de comparar con el esperado para que un `bits` no canónico tenga su error
    // propio y no se confunda con "no es el del retarget".
    let target = decodificar_con(c.bits, &ctx.parametros.limites).map_err(invalido)?;

    // C-BLK-05 · `bits` MUST ser exactamente el del retarget, no "uno equivalente".
    let bits_esperados = codificar_con(ctx.target_esperado, &ctx.parametros.limites);
    if c.bits != bits_esperados {
        return Err(ErrorPow::BitsIncorrectos {
            esperado: bits_esperados,
            encontrado: c.bits,
        });
    }

    // C-BLK-04 · PoW. Después de `bits`, porque validar el PoW contra un target que no es el que
    // toca no demostraría nada. Comparación **estricta**: `hash == target` NO cumple.
    let hash_pow = algo.hash_pow(c);
    if U256::from_big_endian(&hash_pow) >= target {
        return Err(ErrorPow::PowInsuficiente);
    }

    // C-BLK-06 · timestamps. El de futuro NO es permanente: ver `es_permanente()`.
    let ts = i64::try_from(c.timestamp)
        .map_err(|_| ErrorPow::TimestampFueraDeRango { ts: c.timestamp })?;
    comprobar_monotonia(altura, ts, ctx.ts_padre)?;
    comprobar_ftl(ts, ctx.reloj_local, ctx.parametros.ftl()?)?;

    Ok(())
}

/// Traduce el error de `zx-core` a la variante propia de [`ErrorPow`].
fn invalido(e: EncodingError) -> ErrorPow {
    match e {
        EncodingError::BitsNoCanonico { bits, motivo } => {
            ErrorPow::BitsNoCanonicos { bits, motivo }
        }
        EncodingError::TargetFueraDeRango { motivo } => ErrorPow::TargetFueraDeRango { motivo },
        // `decodificar_con` solo devuelve las dos variantes anteriores; cualquier otra es un bug,
        // pero se falla cerrado con un mensaje fijo en vez de con un `panic` (prohibido).
        _ => ErrorPow::BitsNoCanonicos {
            bits: 0,
            motivo: "bits inválido (error de codificación inesperado)",
        },
    }
}
