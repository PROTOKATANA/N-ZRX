# Procedencia de los vectores v0.2 — transición (W06a-B)

Artefactos **copiados sin cambios** desde el oráculo T01-E
(`P-ZRX/P-TRANSICION/T01/resultados/`; `REVISION-T01-E.md`, corrección F-18: el id de la salida de
una liberación es `ID_LIB(clave, nonce, importe)`, sin `prox_salida`).

| Fichero | sha256 |
|---|---|
| `vectores-transicion-v0.2.txt` | `da3dcc4859da8590c32559ea57cd2342b6a3c54fb7533fa21c66a15d9c91b080` |
| `vectores-transicion-negativos-v0.2.txt` | `3d2dedae145ec67772ed66db2e0601fc82bc87db8c2cdeefe250978e3771c889` |

Ambas huellas coinciden con las fijadas en `P-ZRX/P-NODO/ENTRADA-W06a-B.sha256` y se
reverificaron con `sha256sum` al copiarlas a `testdata/transicion-v0.2/`.

Los consumen `crates/zx-consensus/tests/diferencial_t01.rs`: la base en el test
`diferencial_t01` (2 055 casos) y los negativos en `diferencial_t01_negativos` (3 914 casos).
Sustituyen a los v0.1 **solo en el arnés**; los v0.1 se conservan sin tocar en
`testdata/transicion-v0.1/`. No se regeneran desde Rust.
