# `zx-cadena`

Gestor del **estado del DAG en memoria** de la red dev (`ORDEN-W06a`, decisión `D-N02`).

Mantiene, sobre el motor de transición de `zx-consensus` (`aplicar` para PoW, `aplicar_fusion`
para PoST) y el orden GHOSTDAG de `zx-dag`:

- la admisión de bloques PoW y PoST, con el motivo de rechazo de bloque;
- `Estado(past(B))` y `Estado(past(B) ∪ {B})` de cada bloque (`ED-1`, `ED-2`);
- el bloque virtual `V`, con `slot(V) = máx slot(puntas)`, y la cadena seleccionada (`ED-3`);
- la historia seleccionada recomputada desde el terminal, con las transacciones descartadas y su
  motivo (`ED-4`…`ED-6`, `C-ORD-04`);
- la garantía del productor como comprobación de admisión (`RD-9`, `RD-10`);
- `merge_depth` dev (`RD-5`), `rojo_U3` inerte (`C-GD-07`) e importe de coinbase por
  `subsidio_post(slot(X))` (`RD-1`);
- la aplicación de una rama con `Undo` por delta y su deshacer exacto (`IE-4`).

Depende solo de `zx-core`, `zx-consensus` y `zx-dag`; no toca red, disco ni relojes.

La verificación de cabeceras (PoW, PoT, PoAS, sello) no es de esta orden: `pow_valido` y
`prueba_valida` llegan ya decididos. La persistencia y la red son W06b/W06c/W06d.
