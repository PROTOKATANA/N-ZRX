# PROCEDENCIA — `vectores.txt` (oráculo de cabecera DAG, H-08a)

- **Ruta de origen:** `veritas/consenso/vectores-cabecera-dag/resultados/vectores.txt`
  del repositorio de ZEROX.
- **Commit:** `9681061cbae3e6b1038548f206055c984492eaf9` (`9681061`, 2026-09-24).
- **sha256:** `c12e519687659da61f5f045fb13759372f0245f67e93354a5e60181679a6f2e3`
- **Copia:** byte a byte, sin ninguna modificación.
- **Instrumento Julia que lo generó:** la auditoría
  `veritas/consenso/vectores-cabecera-dag/` (`run.jl` + `src/referencia.jl`; Julia CPU con la
  stdlib `SHA`, SHA3-256 FIPS 202, sin dependencias externas), sobre el escenario determinista
  H-08a. Su `INFORME.md` documenta la validación (ancla NIST `SHA3-256("")`) y la línea de
  reproducción. **Ese instrumento no se ejecutó en esta orden.**
- **Estado en el árbol nuevo:** es un artefacto histórico **copiado**, no un instrumento
  re-validado en el árbol nuevo. No se recomputó en Julia, no se regeneraron los vectores y no se
  comprobó Julia contra ellos. El test `crates/zx-core/tests/oraculo_julia.rs` los consume desde
  `testdata/vectores-cabecera-dag/vectores.txt`.
