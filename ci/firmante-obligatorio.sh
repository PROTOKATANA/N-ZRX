#!/usr/bin/env bash
# Firmante obligatorio en el nodo (ORDEN-SL4b2 decisión 2; ORDEN-SL4b3 decisión 2; PROD-3c).
#
# El nodo produce **solo** con las funciones `_con_firmante` de `zx-post`: la variante
# `_sin_firmante` sella sin registrar la oportunidad y no protege contra la doble firma, así que
# solo la usan tests y arneses. Este guardián falla si `crates/zx-node/src/` menciona la ruta sin
# firmante; así una recaída en `producir_bloque_transicion` (el defecto 1 de `REVISION-SL4b2.md`) se
# detecta en CI.
#
# PROD-3c: además vigila la **ruta oficial de firma**, no solo un nombre:
#   (a) en `crates/zx-node/src/regimen.rs` no puede aparecer, fuera de comentarios, el texto
#       `SigningKey`, `Firmante`, `RegistroFirmante`, `registro_firmante`, `_con_firmante`
#       ni un campo `.sk` (el hilo productor no recibe claves privadas);
#   (b) en el código de producto de `crates/zx-node/src/` (no en archivos de pruebas ni en
#       `nodo/firma_contextual.rs`) no se construye un `Firmante` (`Firmante::nuevo`,
#       `Firmante {`) ni se llama a `.firmar(`.
#
# Cómo se distingue producto de pruebas (sin falsos positivos):
#   - **Archivos de pruebas**: (i) cualquier `*.rs` bajo `crates/zx-node/src/` cuyo nombre
#     contiene `test` o `prueba` (p. ej. `dgcand_tests.rs`, `pruebas_prod3b.rs`); (ii) cualquier
#     archivo cuyo módulo se declara en el árbol como `#[cfg(test)] mod X;` (p. ej. `ev1.rs`,
#     `ev2.rs`, que son pruebas aunque el nombre no lo diga). No se inspeccionan para (b).
#   - **Dentro de un archivo de producto**: se omiten los ítems `#[cfg(test)]` (módulos,
#     funciones, `thread_local!`, `use`, `static`). Se detectan con un contador de llaves:
#     al ver `#[cfg(test)]` se saltan las líneas siguientes —incluidos más atributos `#[…]` del
#     mismo ítem— hasta que las llaves del ítem vuelven a la profundidad inicial; si el ítem no
#     abre llaves (`use`, `static`, una sentencia), se salta solo esa línea.
#   - **Comentarios**: se elimina `//…` de cada línea antes de buscar. No se interpretan
#     literales de cadena (un `//` dentro de un string cortaría la línea; no hay tokens
#     prohibidos en strings del producto).
#   - `nodo/firma_contextual.rs` es el único lugar autorizado para (b): se omite por nombre.
#
# Sin Python: solo `bash` + `grep`. Si `grep` falla por un motivo distinto de «sin coincidencias»,
# el script falla cerrado en vez de dar un OK falso.
set -euo pipefail
cd "$(dirname "$0")/.."

objetivo="crates/zx-node/src"
if [[ ! -d "$objetivo" ]]; then
  echo "firmante obligatorio: no existe $objetivo" >&2
  exit 1
fi

# ── (0) Ruta sin firmante: `_sin_firmante` en todo el árbol del nodo ──────────
set +e
coincidencias=$(grep -rn -- "_sin_firmante" "$objetivo")
estado=$?
set -e

case "$estado" in
0)
  echo "firmante obligatorio: $objetivo invoca un productor sin firmante:" >&2
  echo "$coincidencias" >&2
  echo "Usa las funciones _con_firmante de zx-post (C-EVP-06, FIR-01…FIR-15)." >&2
  exit 1
  ;;
1)
  echo "OK — $objetivo no invoca ningún productor _sin_firmante"
  ;;
*)
  echo "firmante obligatorio: grep falló con estado $estado" >&2
  exit 1
  ;;
esac

# ── utilidades ────────────────────────────────────────────────────────────────
# Imprime `num:contenido` de las líneas de **producto** de un archivo .rs:
# sin comentarios de línea y sin ítems `#[cfg(test)]`.
lineas_producto() {
  local archivo="$1"
  local n=0 en_test=0 prof=0 vio_llave=0
  local linea sin c i
  while IFS= read -r linea || [[ -n "$linea" ]]; do
    n=$((n + 1))
    # Quitar comentario de línea (no interpreta literales de cadena).
    sin="${linea%%//*}"
    if [[ "$en_test" -eq 1 ]]; then
      # Otro atributo del mismo ítem: seguir saltando.
      if [[ "$sin" =~ ^[[:space:]]*#\[ ]]; then
        continue
      fi
      for ((i = 0; i < ${#sin}; i++)); do
        c="${sin:i:1}"
        if [[ "$c" == "{" ]]; then
          prof=$((prof + 1))
          vio_llave=1
        elif [[ "$c" == "}" ]]; then
          prof=$((prof - 1))
        fi
      done
      if [[ "$vio_llave" -eq 1 ]]; then
        if [[ "$prof" -le 0 ]]; then
          en_test=0
          prof=0
          vio_llave=0
        fi
      else
        # Ítem sin llaves (`use`, `static`, una sentencia): se salta solo esa línea.
        en_test=0
      fi
      continue
    fi
    if [[ "$sin" =~ \#\[cfg\(test\)\] ]]; then
      en_test=1
      prof=0
      vio_llave=0
      continue
    fi
    printf '%d\t%s\n' "$n" "$sin"
  done <"$archivo"
}

# ── (a) regimen.rs sin material de firma privada, fuera de comentarios ───────
regimen="$objetivo/regimen.rs"
if [[ ! -f "$regimen" ]]; then
  echo "firmante obligatorio: no existe $regimen" >&2
  exit 1
fi
# Patrones prohibidos fuera de comentarios (también se omiten #[cfg(test)] por si acaso).
pat_a='SigningKey|Firmante|RegistroFirmante|registro_firmante|_con_firmante|\.sk([^[:alnum:]_]|$)'
set +e
violaciones_a=$(lineas_producto "$regimen" | grep -E -- "$pat_a")
estado_a=$?
set -e
case "$estado_a" in
0)
  echo "firmante obligatorio: $regimen menciona material de firma privada fuera de comentarios:" >&2
  echo "$violaciones_a" >&2
  echo "El hilo productor solo recibe material público (PROD-3c)." >&2
  exit 1
  ;;
1)
  echo "OK — $regimen sin SigningKey/Firmante/.sk fuera de comentarios"
  ;;
*)
  echo "firmante obligatorio: grep de (a) falló con estado $estado_a" >&2
  exit 1
  ;;
esac

# ── (b) construcción de Firmante / .firmar( solo en la ruta oficial ─────────
# Lugar autorizado de construcción y firma.
permitido="$objetivo/nodo/firma_contextual.rs"
pat_b='Firmante::nuevo|Firmante[[:space:]]*\{|\.firmar\('

# Módulos declarados como `#[cfg(test)] mod X;` en el árbol: sus archivos `X.rs` son pruebas.
modulos_prueba=$(
  grep -rn --include='*.rs' -A2 '#\[cfg(test)\]' "$objetivo" 2>/dev/null |
    grep -oE 'mod [a-z0-9_]+' |
    grep -oE '[a-z0-9_]+' |
    grep -v '^mod$' |
    sort -u
)

es_archivo_pruebas() {
  local base
  base=$(basename "$1" .rs)
  if [[ "$base" == *test* || "$base" == *prueba* ]]; then
    return 0
  fi
  if [[ -n "$modulos_prueba" ]] && echo "$modulos_prueba" | grep -qx "$base"; then
    return 0
  fi
  return 1
}

fallos_b=""
while IFS= read -r -d '' archivo; do
  if es_archivo_pruebas "$archivo"; then
    continue
  fi
  # El módulo de firma contextual es el único lugar autorizado.
  if [[ "$archivo" == "$permitido" ]]; then
    continue
  fi
  set +e
  hits=$(lineas_producto "$archivo" | grep -E -- "$pat_b")
  estado_b=$?
  set -e
  if [[ "$estado_b" -eq 0 ]]; then
    while IFS= read -r h; do
      [[ -z "$h" ]] && continue
      fallos_b+="$archivo:$h"$'\n'
    done <<<"$hits"
  elif [[ "$estado_b" -ne 1 ]]; then
    echo "firmante obligatorio: grep de (b) sobre $archivo falló con estado $estado_b" >&2
    exit 1
  fi
done < <(find "$objetivo" -name '*.rs' -print0)

if [[ -n "${fallos_b// /}" ]]; then
  echo "firmante obligatorio: construcción de Firmante o .firmar( fuera de la ruta oficial:" >&2
  echo "$fallos_b" >&2
  echo "La firma y la construcción del firmante viven solo en $permitido (PROD-3c)." >&2
  exit 1
fi
echo "OK — (b) sin construcción de Firmante ni .firmar( fuera de $permitido"
echo "OK — guardián de la ruta oficial de firma"
