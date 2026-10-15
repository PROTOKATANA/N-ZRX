# `zx-farmer` — parcela persistente y conversión de candidatos PoAS

Crate **nuevo** de la orden W05b1. Porta, sin cambio de lógica, `farmer.rs` y `productor_poas.rs`
de `crates/zx-node` de `9681061`, apuntando a [`zx_poas::HistoriaGenesis`] en vez de
`HistoriaDagDev`.

- **`farmer.rs`** — `plotear_sector_en_disco` (ruta **paralela** de `ab-proof-of-space`; la no
  paralela tiene un SIGSEGV documentado), `ParcelaDisco` (par `<ruta>`+`<ruta>.meta` con checksum
  BLAKE3, lock `<ruta>.lock` y publicación por dos `rename`), `auditar_candidatos` (reto
  `C-POT-03` + `audit_plot_sync` sobre el descriptor verificado) y `auditar_slot`.
- **`productor_poas.rs`** — `convertir_candidatos_locales`: `SolutionCandidates::into_solutions`
  con `ReadSectorRecordChunksMode::ConcurrentChunks` y `ChiaTable`, paso a
  [`zx_core::SolucionPoas`] y verificación con [`zx_poas::verificar_solucion_poas`] (paso 5 de
  `C-POT-08`).

## Frontera

`zx-farmer` depende de `zx-core` y `zx-poas` dentro del workspace (lo vigila
`ci/frontera-crates.sh`), y del plotter/auditor de Autonomys por ruta al clon fijado
`terceros/autonomys` @ `f8842d0`. No depende de `zx-consensus`.

## Lo que NO demuestra

PoT, cabecera, sello, admisión, elección de padres, arranque desde génesis y publicación. La
procedencia causal del lote auditado (slot, salida y rango) no se acredita aquí.
