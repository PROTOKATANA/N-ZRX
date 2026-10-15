#!/usr/bin/env bash
# Fronteras de dependencias de los crates de consenso (adaptado de `9681061`; W04 + W05a + W05b1 + W06b + W06c).
#
# Regla: `zx-consensus` y `zx-dag` pueden ver `zx-core` y **solo** `zx-core` dentro del workspace:
# una primitiva de cálculo, no red, estado ni mempool. En particular, `zx-dag` (D-P13) **no** puede
# depender de `zx-consensus` ni de `zx-storage`. `zx-poas` añade `zx-consensus` (génesis dev de W04)
# y `zx-merkle` (PT-2a-2: pertenencia transparente, C-HASH-04), y `zx-farmer` depende de `zx-core`,
# `zx-poas` y `zx-merkle`, nunca de `zx-consensus` (W05b1 §6 V8).
# `zx-p2p` (D-N01, W06c) depende de `zx-core` y, desde ZC-4, de `zx-compresion`: la red no puede ver
# consenso ni almacén, y el ciclo red↔consenso se rompe en `zx-node`. `zx-storage` (D-N03′, W06b)
# depende **solo** de `zx-core`: persistir bloques no es validarlos ni conocer el estado derivado.
# `zx-compresion` (ZRX-C, ZC-2/ZC-4) es un crate de compresión independiente —lo ven `zx-pruebas`
# (CP-C1) y `zx-p2p` (ZC-4)— y no puede depender de ningún otro crate `zx-`: solo zstd y `thiserror`.
#
# `zx-estado` (A1-B1/A1-D2a; `P-ZRX/P-004/ADOPCION-A1-PASO-B.md` §«Dónde vive») es el árbol de estado
# de consenso: puede ver `zx-core` y `zx-consensus` —de donde toma el `Estado`, el `Undo` y sus
# tipos— y **nada más** del workspace. Es regla del votante, no de la cadena: la cadena no calcula la
# raíz. Solo `zx-node` lo consume (A1-D2a), así que `zx-estado` aparece **únicamente** en la lista de
# `zx-node`; por la regla recíproca de este script, cualquier otro crate que lo declarara (en
# particular `zx-consensus`) sería rechazado.
#
# `zx-node` (D-N01, W06d1) puede ver **todos** los crates del workspace: es el único que integra
# red, consenso y almacén. La regla recíproca —que ningún otro crate dependa de `zx-node`— ya la
# impone este mismo script: `zx-node` no aparece en ninguna lista de `permitidos` de abajo, así que
# si alguno lo declarara como dependencia, esa `frontera(...)` lo rechazaría.
#
# `zx-bls` (PK-04, ORDEN-BLS1) es el **único** crate que puede ver `blst`: no depende de ningún
# otro crate `zx-` (solo `blst` y `thiserror`), y la última comprobación de este script falla si
# cualquier otro miembro del workspace declara `blst` como dependencia normal o de build. Así el
# FFI de C/ensamblador de `blst` queda confinado a un crate auditable (PK-04) y no se cuela en la
# ruta de consenso por un atajo.
#
# Se usa `jq` (disponible en la máquina del proyecto y en los runners ubuntu de CI). Si no estuviera,
# el script falla con un mensaje explícito en vez de dar un OK falso.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "jq no está instalado: no se puede comprobar la frontera de crates" >&2
  exit 1
fi

cargo metadata --locked --no-deps --format-version 1 | jq -e '
    def frontera($crate; $permitidos):
        [.packages[] | select(.name == $crate)] as $p |
        if ($p | length) != 1 then
            error($crate + " no aparece en cargo metadata")
        else
            [$p[0].dependencies[]
             | select(.kind != "dev")
             | select(.name | startswith("zx-"))
             | .name as $d
             | select($permitidos | index($d) | not)
             | ($crate + " depende de " + $d)] as $fallos |
            if ($fallos | length) > 0 then
                error($fallos | join("; "))
            else
                "OK — frontera " + $crate + " → {" + ($permitidos | join(",")) + "}"
            end
        end;

    frontera("zx-consensus"; ["zx-core", "zx-bls", "zx-votos"]),
    frontera("zx-dag"; ["zx-core"]),
    frontera("zx-poas"; ["zx-core", "zx-consensus", "zx-merkle"]),
    frontera("zx-farmer"; ["zx-core", "zx-poas", "zx-merkle"]),
    frontera("zx-post"; ["zx-core", "zx-pot", "zx-dag", "zx-poas"]),
    frontera("zx-p2p"; ["zx-core", "zx-compresion"]),
    frontera("zx-cadena"; ["zx-core", "zx-consensus", "zx-dag"]),
    frontera("zx-storage"; ["zx-core"]),
    frontera("zx-compresion"; []),
    frontera("zx-pruebas"; ["zx-compresion"]),
    frontera("zx-bls"; []),
    frontera("zx-votos"; ["zx-bls"]),
    frontera("zx-cartera"; ["zx-core", "zx-consensus", "zx-p2p"]),
    frontera("zx-estado"; ["zx-core", "zx-consensus"]),
    frontera("zx-node"; ["zx-core", "zx-consensus", "zx-dag", "zx-pot", "zx-poas", "zx-farmer", "zx-post", "zx-p2p", "zx-cadena", "zx-storage", "zx-votos", "zx-estado"]),

    ([.packages[]
      | select(.name != "zx-bls")
      | .name as $p
      | .dependencies[]
      | select(.kind != "dev")
      | select(.name == "blst")
      | ($p + " depende de blst")] as $fugas |
     if ($fugas | length) > 0 then
         error($fugas | join("; "))
     else
         "OK — blst confinado en zx-bls"
     end)'
