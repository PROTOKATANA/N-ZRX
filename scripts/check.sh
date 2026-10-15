#!/usr/bin/env bash
# Puerta de calidad de ZEROX: ejecuta las comprobaciones de cada lenguaje presente en el repo.
# Plataforma soportada: Linux x86_64. Solo mira archivos seguidos por git.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

tiene() { [ -n "$(git ls-files "$@")" ]; }
requiere() { command -v "$1" >/dev/null || {
  echo "ERROR: falta la herramienta '$1'"
  exit 1
}; }
seccion() {
  echo
  echo "== $1 =="
}

if tiene Cargo.toml; then
  seccion "Rust"
  requiere cargo
  requiere cargo-audit
  cargo fmt --all -- --check
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo build --locked --all-features --bins
  cargo test --locked --all-features --no-fail-fast
  cargo build --locked --release
  cargo audit
fi

if tiene 'ci/*.sh'; then
  seccion "Guardianes del proyecto"
  git ls-files -z 'ci/*.sh' | xargs -0 -n 1 bash
fi

if tiene '*.sh' '.githooks/*'; then
  seccion "Bash"
  requiere shellcheck
  requiere shfmt
  git ls-files -z '*.sh' '.githooks/*' | xargs -0 shellcheck -x
  git ls-files -z '*.sh' '.githooks/*' | xargs -0 shfmt -d -i 2
fi

if tiene '*.ps1' '*.psm1' '*.psd1'; then
  seccion "PowerShell"
  requiere pwsh
  git ls-files -z '*.ps1' '*.psm1' '*.psd1' | xargs -0 -I{} \
    pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path '{}' -Severity Warning,Error -EnableExit"
  if tiene '*.Tests.ps1'; then pwsh -NoProfile -Command "Invoke-Pester -CI"; fi
fi

echo
echo "Puerta de calidad superada."
