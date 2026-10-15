# ZEROX

Implementación en Rust de ZEROX: una cadena de bloques con prueba de espacio y tiempo, bloques en DAG y finalidad
por votos.

**Estado:** en desarrollo (versión 0.0.4). Solo hay una red de desarrollo (`dev`); no la uses con valor real.

## Plataforma soportada

**Linux x86_64.** Es la única plataforma en la que se compila y se prueba. En macOS y Windows no hay garantía.

## Requisitos

- `git` y [rustup](https://rustup.rs). El compilador de Rust está fijado en `rust-toolchain.toml` (un nightly
  concreto); rustup lo instala solo la primera vez que compilas.
- Un compilador de C y C++ y `libclang`, que necesitan RocksDB y los compresores que se compilan desde su código:

  ```sh
  # Debian / Ubuntu
  sudo apt-get install -y git build-essential clang libclang-dev
  # openSUSE
  sudo zypper install git gcc gcc-c++ clang libclang13
  ```

## Compilar

```sh
git clone https://github.com/PROTOKATANA/ZEROX
cd ZEROX
cargo build --release
```

Los binarios quedan en `target/release/`: `zx-node` (el nodo) y `zx-cartera` (la cartera).

## Usar

```sh
target/release/zx-node --help
target/release/zx-node --datos ./datos --registro ./registro.jsonl
```

`--datos` es el directorio del almacén y las parcelas; `--registro`, el archivo donde el nodo escribe sus eventos.

## Pruebas y puerta de calidad

```sh
scripts/check.sh
```

Ejecuta el formato, `clippy` sin avisos, la suite entera de pruebas, el build de release, la auditoría de
dependencias y la revisión de los scripts. La suite tiene más de dos mil pruebas y tarda varias horas. Detalles en
`CONTRIBUTING.md`.

## Licencia

AGPL-3.0-or-later (ver `LICENSE`). Los crates de prueba de espacio de Autonomys que se usan están copiados
en `terceros/autonomys/`, con su licencia 0BSD y una nota de qué se cambió.
