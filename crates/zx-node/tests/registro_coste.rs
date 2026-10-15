//! `ORDEN-W07a` V4: coste de escribir un evento del registro estructurado.
//!
//! Mide directamente `Registro::escribir` (con `flush`, la ruta no crítica) sobre `N` eventos
//! reales, tras calentamiento. El informe compara el coste por bloque (los ~3 eventos que un bloque
//! de red deja) con la mediana de `t_admision_ns` de la ejecución V3.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "el test falla con panic por diseño"
)]

use std::time::Instant;

use zx_node::registro::Registro;

#[test]
fn coste_de_escribir_un_evento() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = Registro::abrir(&dir.path().join("registro.jsonl")).expect("registro");

    // Calentamiento (páginas de caché, JIT, etc.).
    for i in 0..1_000u64 {
        r.escribir(r.evento("calentamiento").u64("i", i), false)
            .unwrap();
    }

    const N: u64 = 20_000;
    let hash = "0".repeat(64);
    let t0 = Instant::now();
    for _ in 0..N {
        let ev = r
            .evento("bloque_recibido")
            .str("hash", &hash)
            .str("familia", "post")
            .u64("bytes", 1_234);
        r.escribir(ev, false).unwrap();
    }
    let total = t0.elapsed();
    let ns_evento = total.as_nanos() as f64 / N as f64;
    // Cota conservadora: un bloque de red deja 3 eventos no críticos (recibido, admitido,
    // cambio_punta). Se compara luego con la mediana real de `t_admision_ns` de V3.
    let ns_bloque = ns_evento * 3.0;
    println!(
        "V4: {N} eventos en {total:?} => {ns_evento:.0} ns/evento; 3 eventos/bloque => {ns_bloque:.0} ns/bloque"
    );
    assert!(
        ns_bloque < 10_000_000.0,
        "el registro por bloque no debería pasar de 10 ms: {ns_bloque} ns"
    );
}
