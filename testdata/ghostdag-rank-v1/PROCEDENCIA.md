# PROCEDENCIA — vectores del oráculo GHOSTDAG (`ghostdag-rank-v1`)

Artefactos **copiados sin cambios** del commit antiguo, para el test
`crates/zx-dag/tests/ghostdag_oraculo.rs`.

## `corpus-rust.txt`

- **Ruta de origen:** `veritas/consenso/ghostdag-rank-v1/resultados/corpus-rust.txt` del
  repositorio de ZEROX.
- **Commit:** `9681061cbae3e6b1038548f206055c984492eaf9` (`9681061`, 2026-09-24).
- **sha256:** `dff05e21ba786bb35be6d264eb30e50e1edc46144c80190ec5e02cfc80e2f0a8`
- **Instrumento Julia que lo generó:** la auditoría independiente GDR-v0.2
  `veritas/consenso/ghostdag-rank-v1/` (`volcar_corpus.jl` + `src/referencia.jl` +
  `src/GhostdagRank.jl`), ejecutada desde la copia del workspace. Ninguna línea la produce Rust.

## `kaspa-rust.txt`

- **Ruta de origen:** `veritas/consenso/ghostdag-rank-v1/resultados/kaspa-rust.txt` del mismo
  repositorio.
- **Commit:** `9681061cbae3e6b1038548f206055c984492eaf9` (`9681061`, 2026-09-24).
- **sha256:** `1ab0a081270861e31de0c71e62a38c542d73b1ef3682571bb4b654f8404e6922`
- **Instrumento:** vectores oficiales de **rusty-kaspa** volcados al formato del corpus
  (modo `SP_KASPA` / `MERGE_KASPA`, U2/U3 desactivados).

## Estado en el árbol nuevo

Los dos ficheros son artefactos históricos **copiados**, **no re-validados en el árbol nuevo**:
no se recomputó el oráculo Julia, no se regeneraron los vectores y no se volvió a comparar Julia
contra ellos. El test `crates/zx-dag/tests/ghostdag_oraculo.rs` los consume desde
`testdata/ghostdag-rank-v1/` y **falla** si faltan: no se degrada a «sin verificar».

Las rutas del test solo cambiaron de segmento (`veritas/consenso/ghostdag-rank-v1/resultados/` →
`testdata/ghostdag-rank-v1/`), como en W01/W02.
