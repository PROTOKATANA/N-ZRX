# `zx-storage` — almacén de bloques admitidos (D-N03′)

Guarda, con atomicidad y detección de corrupción, los **bloques que el nodo admite** y el **orden
en que los admitió**, para que al reiniciar el nodo los entregue en ese orden a quien los
re-admita sobre `zx-cadena` en memoria.

## Qué persiste y qué no

- **Sí:** los bytes canónicos de cada bloque admitido (PoW o PoST) y el registro de admisión
  (`u64` big-endian creciente → `block_hash`).
- **No:** el estado derivado (UTXO, garantía, GHOSTDAG). Al reiniciar se repiten las admisiones
  sobre `zx-cadena`; las cabeceras **no** se re-verifican (el almacén local es de confianza). La
  integridad de lo guardado se comprueba recalculando el hash del bloque con el código de
  `zx-core` y comparándolo con la clave, **y** recalculando el compromiso del cuerpo (ver abajo).

Este es el coste asumido de D-N03′: el reinicio es lineal en la historia (re-ejecutar
transiciones, no verificar PoT/PoAS). Sirve para la red dev; producción necesitará instantáneas
(IPA E). W07 mide el tiempo de reinicio.

## El compromiso del cuerpo (Corrección A)

`block_hash` cubre **solo la cabecera**. El cuerpo se ata por el compromiso que la cabecera
declara, y ese compromiso se recalcula **al abrir y al leer**:

- **PoW:** `merkle_root(txids)` sobre los `txid` calculados por `zx-core`, contra
  `cabecera.merkle_root`.
- **PoST:** `body_commitment` sobre `(txid, auth_digest)`, contra `cabecera.body_commitment`;
  cubre datos de efecto **y** testigos.

Si no coincide, `StorageError::CuerpoNoCoincide`, sin reparación. Sin este recálculo, un bit
cambiado en el importe o el destino de una transacción dejaría el `block_hash` intacto y el nodo
reconstruiría en silencio un estado distinto.

**Límite honesto del PoW:** los testigos de un bloque PoW **no** están comprometidos, porque el
`txid` los excluye (C-TX-01). Cambiar un testigo PoW no altera `block_hash` ni `merkle_root`, así
que el almacén no puede verlo; lo detecta la **verificación de firmas del motor al re-aplicar** la
transacción en la repetición (D-N03′). En PoST sí queda cubierto por `body_commitment`.

## Esquema (familias de columnas)

| Familia | Clave → valor | Por qué |
|---|---|---|
| `bloques` | `block_hash`(32) → `familia`(1) ‖ bloque canónico | El bloque completo, cabecera y transacciones, con su familia PoW/PoST |
| `registro` | índice(`u64` BE) → `block_hash`(32) | El orden de admisión; contiguo desde `0` |
| `pruebas` | prefijo `prueba:` ‖ huella(32) → `referencia`(8) ‖ estado(1) ‖ [cuerpo] | Cuerpos de pruebas por huella, con retención y poda (`CP-R-27`…`CP-R-31`) |
| `meta` | clave corta → valor | red, hash del génesis y versión del esquema (3) |

La familia `pruebas` es **lógica**: vive en el *column family* `default` bajo el prefijo `prueba:`
(no se añade un *column family* físico para no romper a los abridores que listan solo las tres
familias documentadas). `podar_hasta(punto)` borra el cuerpo de las entradas con
`referencia <= punto` y conserva la huella y el metadato; una entrada podada no se rehidrata y el
nodo responde «no disponible». El tope por cuerpo es `MAX_CUERPO_PRUEBA_BYTES = 400_000` B.

Abrir con otra red u otro génesis devuelve error, nunca reescribe. El bloque PoW se codifica con
`zx_core::wire::cuerpo_a_bytes` y el PoST con `zx_core::wire_dag::bloque_dag_a_bytes`; el
discriminante de familia es lo único que los distingue, porque ambos empiezan por el mismo
`consensus_branch_id` y FORMATO‑v0 F‑04 prohíbe «adivinar» la familia de un buffer.

## Por qué hay una implementación en memoria

No es un juguete: es la implementación de referencia contra la que se contrasta el backend de
RocksDB (test diferencial). Sin una referencia simple y evidentemente correcta, «RocksDB funciona»
no tiene contra qué compararse.

## Feature `rocksdb`

`rocksdb = "=0.25.0"` (la versión de `9681061`) queda detrás de la feature `rocksdb`. Sin ella, el
crate compila y se prueba entero contra el almacén en memoria.

## Repetición

```text
repetir(&self, destino: &mut impl FnMut(BlockHash, &[u8]) -> Result<(), E>)
```

Recorre el registro en orden y entrega `(block_hash, bytes_de_almacén)`, donde
`bytes_de_almacén = familia(1) ‖ bloque canónico`. Se detiene en el primer error del destino y lo
devuelve envuelto en `ErrorRepeticion`.
