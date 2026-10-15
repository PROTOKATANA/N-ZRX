# `zx-dag` — orden DAG de la red dev

Crate **nuevo** (D-P13) que porta el orden DAG del commit `9681061` al workspace nuevo, con las
decisiones D-P07, D-P08 y D-P13 de `P-ZRX/P-DAG/DECISIONES-W05.md`:

- **`ghostdag.rs`** — `sp(B)`, mergeset, coloreo azul/`rojo_k`/`rojo_U3`, `blue_score`, `blue_work`,
  `rank` y orden de aplicación (`C-GD-01`…`C-GD-09`, `C-ORD-01`…`C-ORD-04`). Lógica **idéntica** a la
  antigua; solo cambia el nombre del error (`ConsensusError` → `ErrorDag`) y la derivación de la
  identidad de billete (`Firmante::identidad` → [`identidad_de_cabecera`]).
- **`bloque_dag.rs`** — compromisos del cuerpo DAG, rango contextual validado (C-HDR-06) y
  comprobación contextual de padres (H-04) con **D-P08**: no hay génesis DAG; la raíz es el terminal
  PoW `T`, una cabecera PoST con `0` padres es inválida, el bloque de transición tiene exactamente un
  padre (`T`) y ningún bloque PoST puede llevar `T` como padre adicional ni un PoW ajeno como padre.
- **`dag_causal.rs`** — `RegistroEstructural`, `FuenteRegistrosDag`, `PresupuestoVista`,
  `ErrorVistaCausal` y `VistaPasadoEstructural`. **No** se porta `FuenteIndiceAdmitidos` (depende del
  almacén de admitidos: W06).
- **`identidad.rs`** — `IdentidadTicket` (portado sin cambios de bytes: `huella`,
  `bytes_canonicos`) y `identidad_de_cabecera(&DagBlockHeader)` con el cuerpo de `Firmante::identidad`.

## Raíz GHOSTDAG (D-P07)

La raíz del almacén es el terminal: `AlmacenGhostdag::con_raiz_terminal(params, algoritmo,
hash_terminal, sr_raiz)` = `nuevo(..., slot 0, sr_raiz, identidad 0)`, con `blue_work` 0. El primer
bloque PoST hijo de `T` hereda `w(T)` como azul de la raíz.

## Frontera

`zx-dag` depende **solo** de `zx-core`, `primitive-types` y `thiserror`. No depende de
`zx-consensus` ni de `zx-storage`. La persistencia, la admisión PoST, la procedencia causal del `SR`
y la verificación PoT/PoAS quedan fuera de este crate (W05b/W06).

## Parámetros

`Parametros` conserva como valores por defecto `k = 30`, 15 padres, mergeset 180 y `S_max = 150`:
**valores del consenso antiguo, condicionales; la red dev fijará los suyos.**
