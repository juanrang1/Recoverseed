#!/usr/bin/env bash
# Lanzador multi-GPU para seed_search. Reparte el espacio entre todas las GPUs,
# muestra el progreso de cada una y detiene todo cuando encuentra la frase.
#
# Uso:
#   ./buscar.sh --phrase "w1 ? w3 ... ?" --addr 0x6c14...6d50 [--gpus N] [--out archivo]
set -u
PHRASE=""; ADDR=""; OUT="hallazgos.txt"; GPUS=""; PERMUTE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --phrase) PHRASE="$2"; shift 2;;
    --addr)   ADDR="$2";   shift 2;;
    --gpus)   GPUS="$2";   shift 2;;
    --out)    OUT="$2";    shift 2;;
    --permute) PERMUTE=1;  shift 1;;
    *) echo "Opcion desconocida: $1"; exit 1;;
  esac
done
if [ -z "$PHRASE" ] || [ -z "$ADDR" ]; then
  echo "Uso: ./buscar.sh --phrase \"w1 ? ... ?\" --addr 0x... [--gpus N] [--out archivo]"
  echo "     (orden desconocido): ./buscar.sh --permute --phrase \"w1 ... w12\" --addr 0x..."; exit 1; fi
if [ ! -x ./seed_search ]; then echo "Falta el binario ./seed_search (compila con nvcc primero)."; exit 1; fi

# nº de GPUs
[ -z "$GPUS" ] && GPUS=$(nvidia-smi -L 2>/dev/null | wc -l)
[ "$GPUS" -lt 1 ] && GPUS=1
# total de combinaciones
if [ "$PERMUTE" -eq 1 ]; then
  total=479001600   # 12!
  echo "Modo PERMUTE: 12 palabras en orden desconocido -> $total permutaciones, en $GPUS GPU(s)."
else
  K=$(echo "$PHRASE" | tr ' ' '\n' | grep -c '^?$')
  if [ "$K" -lt 1 ]; then echo "No hay '?' en la frase (o usa --permute)."; exit 1; fi
  total=1; for ((j=0;j<K;j++)); do total=$((total*2048)); done
  echo "Faltan $K palabra(s) -> $total combinaciones, repartidas en $GPUS GPU(s)."
fi
slice=$((total/GPUS))
echo "Guardando coincidencias en: $OUT"
: > "$OUT"   # limpiar resultados previos

PERMFLAG=""; [ "$PERMUTE" -eq 1 ] && PERMFLAG="--permute"
pids=()
for ((i=0;i<GPUS;i++)); do
  s=$((i*slice))
  if [ $((i+1)) -eq "$GPUS" ]; then e=$total; else e=$(((i+1)*slice)); fi
  CUDA_VISIBLE_DEVICES=$i ./seed_search $PERMFLAG --phrase "$PHRASE" --addr "$ADDR" \
      --start "$s" --end "$e" --gpu "$i" --out "$OUT" > "/tmp/seedgpu_$i.log" 2>&1 &
  pids+=($!)
done

cleanup(){ kill "${pids[@]}" 2>/dev/null; }
trap 'echo; echo "Interrumpido."; cleanup; exit 130' INT TERM

echo "Buscando... (Ctrl-C para detener)"
while true; do
  sleep 8
  prog=""
  for ((i=0;i<GPUS;i++)); do
    p=$(grep -ao '[0-9.]*%' "/tmp/seedgpu_$i.log" 2>/dev/null | tail -1)
    prog="$prog G$i:${p:-0%}"
  done
  printf "\r %s   " "$prog"
  if [ -s "$OUT" ]; then
    echo; echo "===================="; echo " *** ENCONTRADA ***"; cat "$OUT"; echo "===================="
    cleanup; exit 0
  fi
  alive=0
  for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
  [ "$alive" -eq 0 ] && break
done
echo
if [ -s "$OUT" ]; then echo " *** ENCONTRADA ***"; cat "$OUT"
else echo "No encontrada en el espacio completo. Revisa palabras/direccion/ruta."; fi
