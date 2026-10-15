#!/usr/bin/env bash
# v5_sector_4nodos.sh — SR-1-2 V5 · humo de 4 nodos reales con un ALTA DE SECTOR v5.
#
# A arranca sin `--red-marcar`; B, C y D marcan la dirección de A. Los cuatro escuchan en loopback,
# dejan de producir en el slot 260 y se paran con SIGTERM (parada ordenada). Un cliente de prueba
# (`zx-txcliente --modo sector-alta`) conecta con A y publica una `Tx` v5 firmada por la clave 0
# (la del nodo A), que ya tiene garantía madurada de sus coinbases PoST.
#
# Criterio (ORDEN-SR1-2 §3-V5): los cuatro nodos escriben `parada` con `n_sectores >= 1` y el
# **mismo** `resumen_estado`/`punta`; 0 `fallo_productor`, 0 `par_penalizado`, sin pánicos.
#
# Guarda: carga de 1 min <= 2 antes de lanzar. Sin Python. Uso: v5_sector_4nodos.sh
set -uo pipefail

Z="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" # ws/crates/zx-node
BIN="${BIN:-$Z/../../../target/release}"             # SR1-2/target/release
RUN="${RUN:-$Z/../../../run-v5-sector}"              # SR1-2/run-v5-sector

NDEV=138873760
SRDEV=13043817825332783104
SEMILLA=101
SLOT_FIN=260
SLOT_ARRANQUE_CLIENTE=140
ESPERA_SLOT_CLIENTE=40
PA=45301
PB=45302
PC=45303
PD=45304

rm -rf "$RUN"
mkdir -p "$RUN"
: >"$RUN/EJECUCION.txt"
log() { echo "$(date -Is) $*" | tee -a "$RUN/EJECUCION.txt"; }

log "=== SR-1-2 V5 · 4 nodos reales + alta de sector ==="
if [ ! -x "$BIN/zx-node" ] || [ ! -x "$BIN/zx-txcliente" ]; then
  log "FALLO: faltan $BIN/zx-node o $BIN/zx-txcliente"
  echo "NO_SUPERADO" >"$RUN/RESULTADO.txt"
  exit 2
fi

if pgrep -x zx-node >/dev/null 2>&1; then
  log "FALLO: ya hay un zx-node vivo"
  echo "NO_SUPERADO" >"$RUN/RESULTADO.txt"
  exit 3
fi
for p in "$PA" "$PB" "$PC" "$PD"; do
  if ss -ltn 2>/dev/null | grep -q ":$p "; then
    log "FALLO: puerto $p en uso"
    echo "NO_SUPERADO" >"$RUN/RESULTADO.txt"
    exit 3
  fi
done

log "esperando carga de 1 min <= 2 (tope 20 min)..."
fin_espera=$(($(date +%s) + 1200))
while :; do
  l1=$(cut -d' ' -f1 /proc/loadavg)
  if awk "BEGIN{exit !($l1 <= 2)}"; then break; fi
  if [ "$(date +%s)" -ge "$fin_espera" ]; then
    log "FALLO: carga 1 min = $l1 tras 20 min"
    echo "NO_SUPERADO" >"$RUN/RESULTADO.txt"
    exit 4
  fi
  log "carga=$(cat /proc/loadavg) > 2, espero 30 s"
  sleep 30
done
log "carga inicial=$(cat /proc/loadavg) OK"

{
  echo "bin=$BIN"
  echo "sha256_zx-node=$(sha256sum "$BIN/zx-node" 2>/dev/null | awk '{print $1}')"
  echo "sha256_zx-txcliente=$(sha256sum "$BIN/zx-txcliente" 2>/dev/null | awk '{print $1}')"
  echo "n_dev=$NDEV sr_dev=$SRDEV semilla=$SEMILLA"
  echo "puertos: A=$PA B=$PB C=$PC D=$PD"
  echo "slot_fin=$SLOT_FIN alta_cliente_tras=$SLOT_ARRANQUE_CLIENTE espera_slot=$ESPERA_SLOT_CLIENTE"
  echo "uname=$(uname -a)"
  echo "fecha_lanzamiento=$(date -Is)"
} >>"$RUN/EJECUCION.txt"

pids=()
lanzar() {
  local nombre="$1" claves="$2" puerto="$3"
  shift 3
  local marcar=()
  for m in "$@"; do marcar+=(--red-marcar "$m"); done
  mkdir -p "$RUN/$nombre/datos"
  ZX_RED_DATOS="$RUN/$nombre/datos/red" \
    "$BIN/zx-node" \
    --datos "$RUN/$nombre/datos" \
    --registro "$RUN/$nombre/registro.jsonl" \
    --claves "$claves" \
    --n-dev "$NDEV" \
    --semilla "$SEMILLA" \
    --sr-dev "$SRDEV" \
    --red-escuchar "/ip4/127.0.0.1/tcp/$puerto" \
    --dejar-de-producir-en-slot "$SLOT_FIN" \
    "${marcar[@]}" \
    >>"$RUN/$nombre/stdout.log" 2>>"$RUN/$nombre/stderr.log" &
  local pid=$!
  echo "$pid" >"$RUN/$nombre/pid"
  pids+=("$pid")
  log "lanzado $nombre pid=$pid"
}
matar_todo() { for pid in "${pids[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done; }
trap matar_todo EXIT

lanzar A "0" "$PA" "/ip4/127.0.0.1/tcp/$PB" "/ip4/127.0.0.1/tcp/$PC" "/ip4/127.0.0.1/tcp/$PD"
lanzar B "1" "$PB" "/ip4/127.0.0.1/tcp/$PA" "/ip4/127.0.0.1/tcp/$PC" "/ip4/127.0.0.1/tcp/$PD"
lanzar C "2" "$PC" "/ip4/127.0.0.1/tcp/$PA" "/ip4/127.0.0.1/tcp/$PB" "/ip4/127.0.0.1/tcp/$PD"
lanzar D "3" "$PD" "/ip4/127.0.0.1/tcp/$PA" "/ip4/127.0.0.1/tcp/$PB" "/ip4/127.0.0.1/tcp/$PC"

log "esperando a que los 4 puertos escuchen (tope 120 s)..."
fin_puertos=$(($(date +%s) + 120))
while :; do
  listos=0
  for p in "$PA" "$PB" "$PC" "$PD"; do
    ss -ltn 2>/dev/null | grep -q ":$p " && listos=$((listos + 1))
  done
  [ "$listos" -eq 4 ] && {
    log "4/4 puertos escuchando"
    break
  }
  if [ "$(date +%s)" -ge "$fin_puertos" ]; then
    log "AVISO: $listos/4 puertos"
    break
  fi
  sleep 1
done
sleep 2

log "lanzando cliente de alta de sector contra A (semilla $SEMILLA, clave 0)..."
timeout 380 "$BIN/zx-txcliente" \
  --objetivo "/ip4/127.0.0.1/tcp/$PA" \
  --semilla "$SEMILLA" \
  --indices 0 \
  --indice-destino 0 \
  --espera-slot 10 \
  --plazo-s 320 \
  sector-alta --sector-index 0 --history-size 1048576 \
  >"$RUN/cliente.log" 2>&1
cliente_rc=$?
log "cliente rc=$cliente_rc; salida:"
sed 's/^/  /' "$RUN/cliente.log" | tee -a "$RUN/EJECUCION.txt"

log "esperando a que los 4 dejen de producir (slot $SLOT_FIN, tope 400 s)..."
fin_prod=$(($(date +%s) + 400))
while :; do
  nprod=0
  for x in A B C D; do
    grep -q '"tipo":"dejar_de_producir"' "$RUN/$x/registro.jsonl" 2>/dev/null && nprod=$((nprod + 1))
  done
  [ "$nprod" -eq 4 ] && {
    log "4/4 dejaron de producir"
    break
  }
  if [ "$(date +%s)" -ge "$fin_prod" ]; then
    log "AVISO: solo $nprod/4 dejaron de producir"
    break
  fi
  sleep 3
done

log "esperando convergencia de punta en los 4 (tope 180 s)..."
fin_conv=$(($(date +%s) + 180))
estable=0
while :; do
  pA=$(grep '"tipo":"cambio_punta"' "$RUN/A/registro.jsonl" 2>/dev/null | tail -1 | grep -o '"punta":"[^"]*"' | head -1)
  pB=$(grep '"tipo":"cambio_punta"' "$RUN/B/registro.jsonl" 2>/dev/null | tail -1 | grep -o '"punta":"[^"]*"' | head -1)
  pC=$(grep '"tipo":"cambio_punta"' "$RUN/C/registro.jsonl" 2>/dev/null | tail -1 | grep -o '"punta":"[^"]*"' | head -1)
  pD=$(grep '"tipo":"cambio_punta"' "$RUN/D/registro.jsonl" 2>/dev/null | tail -1 | grep -o '"punta":"[^"]*"' | head -1)
  if [ -n "$pA" ] && [ "$pA" = "$pB" ] && [ "$pA" = "$pC" ] && [ "$pA" = "$pD" ]; then
    estable=$((estable + 1))
    if [ "$estable" -ge 2 ]; then
      log "convergidos y estables: $pA"
      break
    fi
  else
    estable=0
  fi
  if [ "$(date +%s)" -ge "$fin_conv" ]; then
    log "AVISO: sin convergencia en 180 s: A=$pA B=$pB C=$pC D=$pD"
    break
  fi
  sleep 3
done
log "SIGTERM a los 4 nodos..."
matar_todo
for _ in $(seq 1 90); do
  vivos=0
  for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null && vivos=$((vivos + 1)); done
  [ "$vivos" -eq 0 ] && break
  sleep 1
done
trap - EXIT

log "=== comparación de parada ==="
fallo_estado=0
fallo_alta=0
fp_total=0
pp_total=0
pan_total=0
pun=""
res=""
ns=""
for n in A B C D; do
  reg="$RUN/$n/registro.jsonl"
  linea=$(grep '"tipo":"parada"' "$reg" 2>/dev/null | tail -1)
  p=$(printf '%s' "$linea" | grep -o '"punta":"[^"]*"' | head -1)
  r=$(printf '%s' "$linea" | grep -o '"resumen_estado":"[^"]*"' | head -1)
  x=$(printf '%s' "$linea" | grep -o '"n_sectores":[0-9]*' | head -1 | sed 's/.*://')
  fp=$(grep -c '"tipo":"fallo_productor"' "$reg" 2>/dev/null)
  fp=${fp:-0}
  pp=$(grep -c '"tipo":"par_penalizado"' "$reg" 2>/dev/null)
  pp=${pp:-0}
  pan=$(grep -c "panicked at" "$RUN/$n/stderr.log" 2>/dev/null || true)
  pan=${pan:-0}
  fp_total=$((fp_total + fp))
  pp_total=$((pp_total + pp))
  pan_total=$((pan_total + pan))
  log "$n: $p n_sectores=${x:-?} $r fallo_productor=$fp par_penalizado=$pp panicos=$pan"
  if [ -z "$p" ] || [ -z "$r" ]; then
    log "FALLO: $n sin parada completa"
    fallo_estado=1
    continue
  fi
  if [ -z "$x" ] || [ "$x" -lt 1 ]; then
    log "FALLO: $n no registró ningún sector"
    fallo_alta=1
  fi
  if [ -z "$pun" ]; then
    pun="$p"
    res="$r"
    ns="$x"
  else
    [ "$p" != "$pun" ] && {
      log "FALLO: $n difiere en punta"
      fallo_estado=1
    }
    [ "$r" != "$res" ] && {
      log "FALLO: $n difiere en resumen_estado"
      fallo_estado=1
    }
    [ "$x" != "$ns" ] && {
      log "FALLO: $n difiere en n_sectores"
      fallo_estado=1
    }
  fi
done

{
  echo "punta=$pun"
  echo "resumen_estado=$res"
  echo "n_sectores=$ns"
  echo "cliente_rc=$cliente_rc"
  echo "fallo_estado=$fallo_estado"
  echo "fallo_alta=$fallo_alta"
  echo "fallo_productor_total=$fp_total"
  echo "par_penalizado_total=$pp_total"
  echo "panicos_total=$pan_total"
  echo "loadavg_fin=$(cat /proc/loadavg)"
  echo "fecha_fin=$(date -Is)"
} >>"$RUN/EJECUCION.txt"

if [ "$fallo_estado" -eq 0 ] && [ "$fallo_alta" -eq 0 ] && [ "$cliente_rc" -eq 0 ] &&
  [ "$fp_total" -eq 0 ] && [ "$pp_total" -eq 0 ] && [ "$pan_total" -eq 0 ]; then
  echo "SUPERADO" >"$RUN/RESULTADO.txt"
else
  echo "NO_SUPERADO" >"$RUN/RESULTADO.txt"
fi
log "RESULTADO=$(cat "$RUN/RESULTADO.txt")"
log "=== V5 SECTOR 4 NODOS TERMINADO ==="
