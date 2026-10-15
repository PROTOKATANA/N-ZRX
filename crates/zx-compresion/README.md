# zx-compresion — ZRX-C

Crate de la pieza **ZRX-C** de ZEROX: comprime y descomprime **bytes opacos ya
serializados** con **ZSTD**, con un marco versionado que declara la longitud
original y un conjunto de límites que impiden que un marco corrupto, truncado o
preparado como bomba agote la memoria.

Desde **ZC-4** esta crate es la **única implementación** de ZRX-C: el marco, los
topes, el diccionario y la verificación viven aquí, y `zx-p2p` la consume para la
red. Solo hay **un formato de marco**, el descrito abajo.

Reglas (de `P-ZRX/P-COMPRESION/ZC1/ZRX-C.md`, aplicadas tal cual):

- **Nunca se comprime la preimagen de un identificador o de una firma.** El
  llamante comprime *después* de calcular `block_hash`, `txid`, raíces y firmas,
  y descomprime *antes* de volver a verificar. Esta crate no conoce el consenso:
  solo mueve bytes.
- **Integridad de transporte, no de consenso.** El marco lleva la longitud
  original y comprimida y un `checksum` xxHash64 de los bytes originales; la
  igualdad que decide el consenso se calcula siempre sobre los bytes
  descomprimidos y se comprueba con el código de `zx-core`.
- **Nada de bombas.** Antes de descomprimir se rechaza un `len_original` que
  supere el tope del tipo, un ratio declarado imposible y un marco cuya
  estructura no cuadre; la descompresión se hace contra un búfer de capacidad
  exacta acotada por el tope y con `window_log_max` fijado.
- **Umbral mínimo.** Por debajo de [`UMBRAL_MINIMO_BYTES`] (64 B) no se comprime:
  el marco viaja **almacenado** dentro del mismo formato, porque la cabecera
  costaría más que el ahorro.

## Marco ZXC1 (único)

| Campo | Bytes | Valor |
|---|---:|---|
| `magia` | 4 | `ZXC1` |
| `version` | 1 | `1` |
| `algoritmo` | 1 | `0` almacenado, `1` zstd |
| `nivel` | 1 | nivel de compresión zstd (1…22); `0` si almacenado |
| `dict_id` | 4 | id del diccionario, `0` si no hay |
| `len_original` | 8 | bytes originales (big-endian) |
| `len_comprimido` | 8 | bytes del payload tal y como viaja (big-endian) |
| `checksum` | 8 | xxHash64 (semilla 0) de los bytes originales (big-endian) |
| `payload` | variable | frame zstd, o los bytes originales si `algoritmo=0` |

La cabecera mide **35 B** ([`CABECERA`]). Decidir el algoritmo es del emisor:
[`comprimir`] almacena si comprimir no compensa; [`comprimir_red`] hace lo mismo
con el nivel de red y nunca falla. El receptor distingue un marco de un mensaje
crudo por la magia `ZXC1` ([`es_marco`]): ningún mensaje crudo de ZEROX empieza
por `Z` (empiezan por un discriminante `0x00..=0x04`).

## API

- [`comprimir`] / [`comprimir_red`] y [`descomprimir`] / [`descomprimir_por_id`]
  con un [`Limites`] explícito.
- [`Diccionario`] con id, bytes y entrenamiento desde muestras; el diccionario de
  transacciones de la red dev (`DICT_ID_TX`) se resuelve con [`diccionario`] /
  [`diccionario_tx`] por su `dict_id` versionado.
- [`Limites::VALOR_ALMACEN`] es el tope que usa `zx-storage` para el valor de una
  entrada de `bloques`; `zx-p2p` usa sus topes de red por camino.
- [`Metricas`] contabiliza bytes crudos frente a bytes ZRX-C (medida, no decisión).
