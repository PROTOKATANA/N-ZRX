# Procedencia de `vectores.txt` — formato v0.1 (W02b)

Generado por el **oráculo Julia independiente** en `deepseek/W02b/oraculo-formato-v0.1/` (copia
de `oraculo-formato-v0` actualizada a F-15/F-17) con:

```bash
JULIA_DEPOT_PATH=<zona>/.julia-depot: \
  julia \
  --project=. --threads=1 run.jl --seed 0x5a5a
```

y copiado aquí **sin editar**. No se regenera desde Rust: el test
`crates/zx-core/tests/formato_v0.rs` lo lee y lo compara. Regenerar con `run.jl` si se cambia la
Corrección v0.1 de `FORMATO-v0.md`; nunca a mano.

`sha256` del fichero: ver `vectores.txt.sha256`.

Los casos **v1** (transferencia y coinbase PoW) son byte a byte idénticos a
`testdata/formato-v0/vectores.txt`; el test lo comprueba para los v1 **no-coinbase**, como pide la
decisión 2 de ORDEN-W02b.
