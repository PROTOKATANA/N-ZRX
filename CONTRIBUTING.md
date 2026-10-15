# Contribuir a ZEROX

## Plataforma

Se desarrolla y se prueba en **Linux x86_64**. Los requisitos del sistema están en `README.md`.

## Preparar el clon

```sh
git clone https://github.com/PROTOKATANA/ZEROX
cd ZEROX
git config core.hooksPath .githooks
```

Los ganchos hacen dos cosas: `pre-commit` rechaza binarios, multimedia, archivos de más de 20 MB y secretos;
`pre-push` ejecuta la puerta de calidad entera. No los saltes (`--no-verify` está prohibido): el CI repite las
mismas comprobaciones.

## Puerta de calidad

```sh
scripts/check.sh        # Linux
pwsh scripts/check.ps1  # el mismo recorrido con PowerShell 7
```

Tiene que pasar entera antes de cada commit. Comprueba:

- **Rust:** `cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings` (cero avisos);
  `cargo test --all-features`; `cargo build --release`; `cargo audit`.
- **Bash:** `shellcheck -x` y `shfmt -d -i 2` sobre todos los `.sh`.
- **PowerShell:** `Invoke-ScriptAnalyzer` sobre los `.ps1`.

Herramientas que necesita, además de rustup: `cargo-audit`, `shellcheck`, `shfmt`, `gitleaks` y, para `check.ps1`,
PowerShell 7 con el módulo `PSScriptAnalyzer`.

La suite tarda varias horas: hay pruebas de nodos completos, de reinicio y de medida.

## Ramas

`main` está siempre en estado de producción y no recibe commits directos. Cada cambio va en su rama:
`feat/<nombre>`, `fix/<nombre>`, `refactor/<nombre>`, `docs/<nombre>`, `test/<nombre>`, `chore/<nombre>` o
`ci/<nombre>`. Antes del merge, `git rebase main`; el merge se hace con `--no-ff` y con el CI en verde.

## Commits

- Un cambio lógico por commit; cada commit compila y pasa las pruebas por sí solo.
- Mensajes con [Conventional Commits](https://www.conventionalcommits.org/es/v1.0.0/), en español y en imperativo:
  `fix(node): no reabrir una ventana de votos ya firmada tras reiniciar`. La primera línea dice qué cambia (máximo
  72 caracteres); el cuerpo, por qué; el pie, el efecto (`BREAKING CHANGE:`, `Closes #12`).
- Tipos: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`, `security`.
- Commits firmados (`git config commit.gpgsign true`, con clave GPG o SSH).

## Estilo de código

### Rust

- El formato lo decide `rustfmt`; los avisos de `clippy` son errores. Las reglas de lint del espacio de trabajo
  están en `Cargo.toml` (`[workspace.lints]`).
- Todo bloque `unsafe` lleva encima un comentario `// SAFETY:` que explica por qué es correcto.
- Nada de `unwrap()` ni `expect()` en rutas que dependen de entrada del usuario, archivos o red.
- Todo código nuevo lleva pruebas; toda corrección de un fallo, una prueba que lo reproduce.
- Las reglas de consenso son funciones puras de sus datos; los errores se distinguen por su tipo, nunca por su
  texto; y cada regla se escribe una sola vez.
- Dependencias con versión exacta en `[workspace.dependencies]` y `Cargo.lock` versionado.

### Bash

- `#!/usr/bin/env bash` y `set -euo pipefail` al principio; variables entre comillas; formato de `shfmt -i 2`.

## Código de terceros

`terceros/autonomys/` es una copia de nueve crates de Autonomys (0BSD). No pasa por la puerta de calidad ni lo
actualiza Dependabot; su `README.md` explica qué se cambió y cómo traer una versión nueva.

## Archivos

Solo texto fuente. Nada de binarios, multimedia, comprimidos ni salidas de compilación, y ningún archivo de más de
20 MB. Los vectores de prueba van en `testdata/`, en texto, con su procedencia.

## Vulnerabilidades

Por el aviso privado de GitHub, nunca en un issue público. Ver `SECURITY.md`.
