#!/usr/bin/env bash
# Comprueba también las dependencias del workspace todavía no consumidas por un crate.
# Admite una dependencia por línea: versión directa o tabla inline con version primero,
# seguida sólo de features (lista de nombres simples) y default-features (booleano).
# Los formatos nuevos se rechazan para revisión; no se interpretan parcialmente.
set -euo pipefail
cd "$(dirname "$0")/.."
manifiesto=${1:-Cargo.toml}

awk '
function fallo(mensaje) { print "Dependencias: " mensaje > "/dev/stderr"; errores++ }
/^[[:space:]]*\[workspace\.dependencies\][[:space:]]*$/ { dentro=1; encontrada=1; next }
/^[[:space:]]*\[/ {
    if ($0 !~ /^[[:space:]]*\[[A-Za-z0-9_.-]+\][[:space:]]*$/) fallo("cabecera de tabla no soportada: " $0)
    if ($0 ~ /^[[:space:]]*\[workspace\.dependencies\./) fallo("subtabla no soportada: " $0)
    dentro=0
}
dentro {
    linea=$0
    sub(/[[:space:]]*#.*/, "", linea)
    if (linea ~ /^[[:space:]]*$/) next
    if (linea !~ /^[A-Za-z0-9_-]+[[:space:]]*=/) { fallo("sintaxis no soportada: " $0); next }
    nombre=linea; sub(/[[:space:]]*=.*/, "", nombre)
    valor=linea; sub(/^[^=]*=[[:space:]]*/, "", valor)
    sub(/[[:space:]]*$/, "", valor)
    if (valor ~ /^"[^"\\]*"$/) {
        version=valor; sub(/^"/, "", version); sub(/"$/, "", version)
    } else if (valor ~ /^\{[[:space:]]*version[[:space:]]*=[[:space:]]*"[^"\\]*"([[:space:]]*,[[:space:]]*(default-features[[:space:]]*=[[:space:]]*(true|false)|features[[:space:]]*=[[:space:]]*\[[[:space:]]*("[A-Za-z0-9_+.\/?-]+"[[:space:]]*(,[[:space:]]*"[A-Za-z0-9_+.\/?-]+"[[:space:]]*)*)?\]))*[[:space:]]*\}$/) {
        campos=valor
        if (gsub(/default-features[[:space:]]*=/, "", campos) > 1) fallo("campo default-features repetido: " nombre)
        if (gsub(/features[[:space:]]*=/, "", campos) > 1) fallo("campo features repetido: " nombre)
        version=valor
        sub(/^\{[[:space:]]*version[[:space:]]*=[[:space:]]*"/, "", version)
        sub(/".*$/, "", version)
    } else { fallo("versión ausente o sintaxis no soportada: " nombre); next }
    if (version !~ /^=[0-9]+\.[0-9]+\.[0-9]+$/) fallo(nombre " = " version)
    cantidad++
}
END {
    if (!encontrada || !cantidad) fallo("no se encontró una tabla de dependencias no vacía")
    if (errores) exit 1
    print "OK — " cantidad " dependencias con versión exacta"
}' "$manifiesto"
