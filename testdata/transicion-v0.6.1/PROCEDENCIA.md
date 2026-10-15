# PROCEDENCIA — testdata/transicion-v0.6.1

Artefacto de la orden **TX-2a-R** (`P-ZRX/P-RELEVO-TX/ORDEN-TX2a-R.md`),
producido en la zona `P-ZRX/P-RELEVO-TX/TX2a-R/` por el ejecutor DeepSeek
(`deepseek-flash`, esfuerzo `high`). Base del repositorio: `776bb21`.

## Contenido

| Fichero | Qué es |
|---|---|
| `vectores-transicion-v0.6.1.txt` | 3 230 casos, 166 242 líneas, 11 273 359 B |
| `vectores-transicion-v0.6.1.sha256` | `sha256sum` relativo a este directorio |
| `cobertura-v0.6.1.txt` | tabla de cobertura (mínimo 3 por fila) |
| `PROCEDENCIA.md` | este documento |

- `sha256` del fichero de vectores:
  `f31488a7493a364174727561f4075e99bedc47e3103ad7d6ffd292afb646658d`.
- Comprobación desde este directorio: `sha256sum -c vectores-transicion-v0.6.1.sha256`.
  La copia de trabajo está en `resultados/vectores-transicion-v0.6.1.{txt,sha256}`
  (el `.sha256` de `resultados/` usa la ruta `resultados/…`).

## De dónde sale

Oráculo de `P-ZRX/P-RELEVO-TX/TX2a/` copiado íntegro a esta zona (sin modificar
los originales) y corregido para:

- **Fusión solo en PoST (ED-1).** Un bloque PoW por la vía de fusión devuelve
  `ErrOperacionFase`, igual que el motor
  (`crates/zx-consensus/src/transicion/fusion.rs:57-60`). Los 6 vectores
  `dep-fee-fusion-*` de v0.6 (bloques PoW) pasan a **negativos** con ese error.
- **Modo fusión por bloque objeto.** `Params.fusion` se aplica solo a la hoja
  del caso (el bloque objeto de la fusión); el prefijo es contexto estricto. Es
  necesario para que existan vectores de fusión sobre PoST: todo PoST necesita un
  prefijo PoW, que nunca se fusiona. Registrado como `FD-TX2a-R-1` en
  `PROGRESO.md` §1.
- **6 vectores nuevos** `dep-fee-fusion-post-*` sobre PoST: la tarifa del
  depósito se acredita si la transacción se aplica
  (`dep-fee-fusion-post-acreditada`) y no se acredita si se descarta
  (`dep-fee-fusion-post-descartada`). Registrado como `FD-TX2a-R-2`.

Las reglas TXL-01, TXL-02 y DEP-FEE son las de TX-2a; no cambian. Los 3 218
vectores de v0.6 ajenos a `dep-fee-fusion-*` dan exactamente lo mismo
(`DIFERENCIAS-v0.6-v0.6.1.md`).

## Reproducción

```bash
cd P-ZRX/P-RELEVO-TX/TX2a-R
export JULIA_DEPOT_PATH=$PWD/.julia-depot JULIA_PKG_OFFLINE=true
env -u LD_LIBRARY_PATH JULIA_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 nice -n 5 \
    julia --project=. exportar.jl \
    --fecha 2026-09-28T15:26:53+02:00 --aleatorios 2000
```

Dos corridas con la misma `--fecha` dan el mismo `sha256`
(`resultados/exportar-v0.6.1.log` y `exportar-v0.6.1-det.log`). Sin fijar la
fecha solo cambia la línea del encabezado.

## Verificación acompañante

- Relectura independiente (`src/lector_vectores.jl`): 3 230 casos, **0
  discrepancias** (`resultados/relectura-v0.6.1.log`).
- Aritmética de tarifas en `Rational{BigInt}` frente a la vía normal
  (`verificar_tarifas.jl`): 12 671 transacciones con tarifa, **0
  discrepancias** (`resultados/tarifas-v0.6.1.log`).
- Diferencias semánticas v0.6→v0.6.1: 6 casos cambiados (todos a
  `ErrOperacionFase`), 6 nuevos y **0** diferencias entre los 3 218 conservados
  (`resultados/diferencias-v0.6-v0.6.1.log`).
