# Crates de Autonomys copiados

Copia de nueve crates de [Autonomys](https://github.com/autonomys/subspace), commit
`f8842d019cdf0f7163421b9644db5a9ff82b2a73`, que ZEROX usa para la prueba de espacio y el granjero:

- `crates/`: `subspace-core-primitives`, `subspace-proof-of-space`, `subspace-verification`,
  `subspace-farmer-components`, `subspace-archiving` y `subspace-erasure-coding`.
- `shared/`: `subspace-kzg`, `ab-proof-of-space` y `subspace-data-retrieval`.

No están publicados en crates.io, y una dependencia git descargaría el repositorio entero de Autonomys (unos
156 MB) para usar estos nueve. Su licencia es 0BSD (ver `LICENSE`): se pueden copiar y modificar sin condiciones.

## Qué cambia respecto al original

- `Cargo.toml` de esta carpeta: el manifiesto raíz de Autonomys recortado a estos nueve crates y a las
  dependencias que heredan. Los perfiles y los `[patch]` del original no se copian: Cargo solo los aplica en el
  espacio de trabajo raíz, que es el de ZEROX, y antes tampoco se aplicaban.
- `shared/subspace-kzg`: los parámetros públicos KZG de la ceremonia de Ethereum se guardan en texto
  (`src/eth-public-parameters.hex`) y un `build.rs` reconstruye el binario al compilar, porque el repositorio no
  versiona archivos binarios. Los bytes reconstruidos son idénticos al original (SHA-256 `f3ead1a6249527aa503d6c56578325c01d19b3365cc59905be2bba64ae322925`).
- Se quitan dos pruebas de Autonomys que nunca se ejecutan aquí y que necesitaban crates no copiados:
  `subspace-farmer-components/tests/plot_read_roundtrip.rs` (GPU, `subspace-proof-of-space-wgpu`) y el módulo de
  pruebas `shared/subspace-data-retrieval/src/object_fetcher/tests.rs` (`subspace-process`), con sus dos
  dependencias de desarrollo.
- `rustfmt.toml` es el de la raíz de Autonomys, para que su código se revise con su propio estilo.
- Nada más: el resto de los archivos es idéntico al del commit indicado.

## Mantenimiento

Este código no pasa por la puerta de calidad de ZEROX (sigue el estilo de Autonomys) y Dependabot no lo
actualiza. Para traer una versión nueva: copiar los mismos crates desde el commit nuevo, repetir los cambios de
arriba y pasar la puerta de calidad entera.
