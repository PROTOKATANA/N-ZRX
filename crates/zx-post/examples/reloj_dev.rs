//! Instrumento **dev** del reloj por ticks (`C-RLJ-02`…`C-RLJ-07`).
//!
//! Mide el **slot de pared** de [`ServicioPot::avanzar`] con distintos `N(s) = T·n_iter` y muestra
//! el ajuste de `T` con una medida de ventana **inyectada** (RL-2 expone la función; RL-2b la cablea
//! a los timestamps). No decide nada: sólo imprime cifras para el informe.
//!
//! Uso (medida, con candado exclusivo):
//! `flock -x .turno.lock flock -x .maquina.lock target/release/examples/reloj_dev`

use std::error::Error;
use std::hint::black_box;
use std::time::Instant;

use zx_core::BlockHash;
use zx_core::digest::Digest;
use zx_post::reloj::{EstadoReloj, Racional};
use zx_post::servicio_pot::ServicioPot;

/// Terminal de prueba.
fn terminal() -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([0x01_u8; 32]))
}

/// Mediana (en ns) de `reps` avances de un slot.
fn medir_slot(servicio: &mut ServicioPot, reps: usize) -> Result<u128, Box<dyn Error>> {
    let mut muestras = Vec::with_capacity(reps);
    for _ in 0..reps {
        let inicio = Instant::now();
        black_box(servicio.avanzar()?);
        muestras.push(inicio.elapsed().as_nanos());
    }
    muestras.sort_unstable();
    let centro = muestras.len() >> 1;
    Ok(muestras.get(centro).copied().unwrap_or(0))
}

/// Imprime estado y slot de pared.
fn linea(etiqueta: &str, servicio: &mut ServicioPot) -> Result<(), Box<dyn Error>> {
    let reloj = servicio.reloj();
    let ns = medir_slot(servicio, 5)?;
    println!(
        "{etiqueta}: T={} n_iter={} N(s)={} slot_mediana_ns={ns}",
        reloj.t(),
        reloj.n_iter(),
        reloj.iteraciones()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let n_iter = 2_603_792_u64;
    let n_max = 240_000_000_u64;
    let reloj = EstadoReloj::nuevo(50, n_iter, n_max);
    let mut servicio = ServicioPot::nuevo_con_reloj(terminal(), reloj, 4096)?;

    println!("== RL-2 instrumento del reloj por ticks ==");
    println!(
        "n_iter={n_iter} (multiplo de 16) n_max={n_max} T0=50 T_max={}",
        n_max.checked_div(n_iter).unwrap_or(0)
    );
    linea("inicial", &mut servicio)?;

    // Medida de ventana inyectada: `tau_est` muy por debajo de `tau_ref` -> sube T.
    let tau_ref = Racional::entero(1_000);
    let u = Racional::entero(5);
    let tau_subir = Racional::entero(900);
    let ajuste = servicio.ajustar_reloj(tau_subir, tau_ref, u)?;
    println!(
        "ajuste(+1): accion={:?} duplicado={} T={} N(s)={}",
        ajuste.accion,
        ajuste.duplicado,
        ajuste.estado.t(),
        ajuste.estado.iteraciones()
    );
    linea("tras +1", &mut servicio)?;

    // Forzar el techo de PK-08: `+1` repetido debe saturar en `T_max` (RL1-A8).
    let mut ultimo = servicio.reloj();
    for _ in 0..200 {
        let a = servicio.ajustar_reloj(tau_subir, tau_ref, u)?;
        if a.estado == ultimo {
            break;
        }
        ultimo = a.estado;
    }
    println!(
        "techo: T={} n_iter={} N(s)={} (saturado en T_max)",
        ultimo.t(),
        ultimo.n_iter(),
        ultimo.iteraciones()
    );
    linea("en el techo", &mut servicio)?;

    // RL1-A2: un ancla donde la duplicación sí se alcanza (`2000000·101 <= N_max`).
    let reloj_dup = EstadoReloj::nuevo(100, 2_000_000, n_max);
    let mut dup = ServicioPot::nuevo_con_reloj(terminal(), reloj_dup, 4096)?;
    let a = dup.ajustar_reloj(tau_subir, tau_ref, u)?;
    println!(
        "duplicacion: T_exc=101 -> T={} n_iter={} N(s)={} accion={:?} duplicado={}",
        a.estado.t(),
        a.estado.n_iter(),
        a.estado.iteraciones(),
        a.accion,
        a.duplicado
    );
    linea("duplicada", &mut dup)?;

    // Simetría del ajuste: `tau_est` por encima de `tau_ref` -> baja T.
    let mut bajar =
        ServicioPot::nuevo_con_reloj(terminal(), EstadoReloj::nuevo(50, n_iter, n_max), 4096)?;
    let a = bajar.ajustar_reloj(Racional::entero(1_100), tau_ref, u)?;
    println!(
        "ajuste(-1): accion={:?} T={} N(s)={}",
        a.accion,
        a.estado.t(),
        a.estado.iteraciones()
    );
    linea("tras -1", &mut bajar)?;

    Ok(())
}
