# PROCEDENCIA — vectores de `zx-bls` (ORDEN-BLS1 V1)

## Origen

- **Repositorio:** <https://github.com/ethereum/bls12-381-tests>
- **Release:** `v0.1.0`
- **Asset:** `bls_tests_json.tar.gz`
- **URL:** <https://github.com/ethereum/bls12-381-tests/releases/download/v0.1.0/bls_tests_json.tar.gz>
- **sha256 del asset:** `be9f43d5977cc375b02c5699102746eb6efcb428e5ed4d8412d2ae7a3f1882fc`
  (copia de trabajo en `tmp/bls_tests_json.tar.gz` de la zona BLS1, descargada el 2026-09-28).
- **Commit de `master` consultado por la API de GitHub** (para el README y el árbol del repositorio):
  `006855c56cb6491ee19b4aedfddb806aaeacb1db`, autor `2024-06-10T13:41:23Z` (merge del PR #9,
  «Fix some mistakes in the formats»). El asset `v0.1.0` es **anterior** (sus JSON conservan las
  marcas de tiempo originales, `2021-08-12`): se registran release y commit por separado para no
  confundir la versión del asset con el `HEAD` de la rama.
- **Suite:** `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (borrador IRTF de firmas BLS con prueba
  de posesión, draft 4). Los vectores de `hash_to_G2` son los de **RFC 9380**
  (`BLS12381G2_XMD:SHA-256_SSWU_RO_`).
- **DST de firma** que usa `blst` en la capa `crudo`: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
- **DST de la prueba de posesión:** `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
- **DST de `hash_to_G2` de los vectores:** `QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_`.

## Ficheros fijados en `tests/vectores/`

| Fichero | Vectores | sha256 |
|---|---:|---|
| `sign.txt` | 10 | `6a1011129bf814f6f8da097c250541be64ad0fd3dcc8b0f43f109f145c211d85` |
| `verify.txt` | 29 | `04e9fd5df556804e061df65676112785924104de2ce20c02418081f45775e80c` |
| `aggregate.txt` | 6 | `f62d87788542959534b390facc14c5a71b247bd4285ecb7cdb7166f2e46b20d0` |
| `fast_aggregate_verify.txt` | 12 | `b5e1270c873455038f2e6704a36bd5d5fe8c7628469be18797f5cbef33af5c19` |
| `aggregate_verify.txt` | 5 | `ee12bd7b62ec2662fb21c745a219b6ebaa9a44b98967b5b42f5c6ed8a7a907dc` |
| `deserialization_g1.txt` | 13 | `d79d7ab0492c696d3d0715d2a68b0358e65dc8cd5355d743b1c7c48ce27ab5f9` |
| `deserialization_g2.txt` | 15 | `0440202c71b7b4caf9857d21beb9b03e9ded308a23bd74858a2db5893426a35e` |
| `hash_to_g2.txt` | 4 | `00eee685f9ce987085e5f5fd9dd0227c3b8b38b9c797e6fc2d1dfb880a09e31e` |
| **Total** | **94** | |

Los `.txt` son una **proyección a TSV** de los JSON oficiales, sin transformar los valores. La
proyección se regenera y se comprueba como conjunto con `bash tmp/verifica_vectores.sh` (solo `bash`
y `jq`, sin Python); las ocho comprobaciones dan `OK` y reproducen los JSON byte a byte como
conjunto. Las proyecciones son:

```sh
jq -r '[.input.privkey, .input.message, (.output // "null")] | @tsv'                     sign/*.json
jq -r '[.output, .input.pubkey, .input.message, .input.signature] | @tsv'               verify/*.json
jq -r '[(.output // "null"), (.input | join(";"))] | @tsv'                              aggregate/*.json
jq -r '[.output, (.input.pubkeys | join(";")), .input.message, .input.signature] | @tsv' fast_aggregate_verify/*.json
jq -r '[.output, (.input.pubkeys | join(";")), (.input.messages | join(";")), .input.signature] | @tsv' aggregate_verify/*.json
jq -r '[.output, .input.pubkey] | @tsv'                                                 deserialization_G1/*.json
jq -r '[.output, .input.signature] | @tsv'                                              deserialization_G2/*.json
jq -r '[.input.msg, .output.x, .output.y] | @tsv'                                       hash_to_G2/*.json
```

El test `tests/vectores.rs` recorre los 94 vectores. Dos familias **divergen a propósito** de lo que
espera Ethereum, por la decisión 3 de la orden (rechazar el punto del infinito):

- `deserialization_succeeds_infinity_with_true_b_flag` (G1 y G2): Ethereum lo acepta; `zx-bls` lo
  **rechaza**. El test lo cuenta como rechazo correcto.
- `aggregate_infinity_signature`: Ethereum agrega el infinito; `zx-bls` lo rechaza al deserializar.

Estas divergencias no se cuentan como vectores que «pasan»: se ejecutan y se comprueba el rechazo.

## Extracción

```sh
mkdir -p tmp && curl -L -o tmp/bls_tests_json.tar.gz \
  https://github.com/ethereum/bls12-381-tests/releases/download/v0.1.0/bls_tests_json.tar.gz
sha256sum tmp/bls_tests_json.tar.gz   # be9f43d5977cc375b02c5699102746eb6efcb428e5ed4d8412d2ae7a3f1882fc
tar -xzf tmp/bls_tests_json.tar.gz -C tmp/ethvec
```
