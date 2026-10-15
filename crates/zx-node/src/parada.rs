//! Parada ordenada por señal (`ORDEN-W07d` decisión 2).
//!
//! El bucle de consenso es síncrono; para que un `SIGTERM`/`SIGINT` no mate el proceso con el
//! registro a medias, el manejador solo deja un flag atómico y los bucles de `Nodo` lo consultan en
//! sus esperas (timeouts de canal y `sleep`). Al verlo, `Nodo::ejecutar` escribe el evento crítico
//! `parada` con el estado final y sale con código 0.
//!
//! No se añade ninguna dependencia: el manejador se instala con `signal(2)` de la libc, que Rust ya
//! enlaza en Linux. El `unsafe` queda confinado aquí y acotado a dos llamadas.

use std::sync::atomic::{AtomicU8, Ordering};

/// `SIGINT` en Linux.
const SIGINT: i32 = 2;
/// `SIGTERM` en Linux.
const SIGTERM: i32 = 15;

/// Motivo de parada solicitado: `0` = ninguno, `1` = `SIGTERM`, `2` = `SIGINT`.
static MOTIVO: AtomicU8 = AtomicU8::new(0);

/// Manejador de señal: solo guarda el motivo. Es `async-signal-safe` porque `AtomicU8::store` es una
/// escritura sin cerrojos (el tipo es siempre *lock-free*).
#[expect(
    unsafe_code,
    reason = "manejador de señal: la libc lo invoca desde contexto asíncrono (ORDEN-W07d)"
)]
unsafe extern "C" fn manejador(senal: i32) {
    let motivo = match senal {
        SIGTERM => 1,
        SIGINT => 2,
        _ => 0,
    };
    MOTIVO.store(motivo, Ordering::SeqCst);
}

#[expect(
    unsafe_code,
    reason = "declaración de la libc: no se añade dependencia para dos llamadas (ORDEN-W07d)"
)]
unsafe extern "C" {
    /// `sighandler_t signal(int signum, sighandler_t handler)` de la libc.
    fn signal(signum: i32, handler: unsafe extern "C" fn(i32)) -> usize;
}

/// Instala los manejadores de `SIGTERM` y `SIGINT`.
///
/// # Errores
/// Texto con la señal que no se pudo instalar (`signal` devolvió `SIG_ERR`).
#[expect(
    unsafe_code,
    reason = "instalación de los dos manejadores con `signal` (ORDEN-W07d)"
)]
pub fn instalar() -> Result<(), String> {
    for (senal, nombre) in [(SIGTERM, "SIGTERM"), (SIGINT, "SIGINT")] {
        // `SIG_ERR` es `(void (*)(int))-1`; en un `usize` es `usize::MAX`. El manejador nunca vale
        // eso (es una función real), así que la comparación distingue el fallo.
        // SAFETY: `signal` de la libc con una señal válida y un manejador que solo hace un `store`
        // atómico, que es seguro dentro de un manejador de señal.
        let anterior = unsafe { signal(senal, manejador) };
        if anterior == usize::MAX {
            return Err(format!("signal({nombre}) devolvió SIG_ERR"));
        }
    }
    Ok(())
}

/// `true` si se pidió parada por señal.
#[must_use]
pub fn hay_solicitud() -> bool {
    MOTIVO.load(Ordering::SeqCst) != 0
}

/// El motivo de la parada solicitada, si la hay: `"sigterm"` o `"sigint"`.
#[must_use]
pub fn motivo_solicitado() -> Option<&'static str> {
    match MOTIVO.load(Ordering::SeqCst) {
        1 => Some("sigterm"),
        2 => Some("sigint"),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{MOTIVO, hay_solicitud, motivo_solicitado};
    use std::sync::atomic::Ordering;

    #[test]
    fn sin_solicitud_no_hay_motivo() {
        // El flag es global al proceso; se deja en 0 explícitamente para que el test no dependa del
        // orden con otros tests.
        MOTIVO.store(0, Ordering::SeqCst);
        assert!(!hay_solicitud());
        assert_eq!(motivo_solicitado(), None);
    }

    #[test]
    fn cada_motivo_se_lee_como_su_literal() {
        MOTIVO.store(1, Ordering::SeqCst);
        assert!(hay_solicitud());
        assert_eq!(motivo_solicitado(), Some("sigterm"));

        MOTIVO.store(2, Ordering::SeqCst);
        assert!(hay_solicitud());
        assert_eq!(motivo_solicitado(), Some("sigint"));

        MOTIVO.store(0, Ordering::SeqCst);
    }
}
