# seed_search — Recuperar frases de semilla BIP39 (Ethereum) por GPU

Herramienta CUDA para recuperar una frase de semilla de 12 palabras (BIP39, ruta
MetaMask `m/44'/60'/0'/0/0`) en tres situaciones:

1. **Orden desconocido** — tienes las 12 palabras pero no el orden (`--permute`).
2. **Palabras faltantes** — conoces el orden pero faltan 1-3 palabras (`?`).
3. **Sin dirección** — no sabes la dirección; se busca contra una base de datos
   de direcciones de Ethereum con saldo (`--basedatos`).

Toda la criptografía está validada contra vectores conocidos (Hardhat).

---

## AVISO DE SEGURIDAD (leer primero)

Si corres esto en una **GPU alquilada** (Vast.ai, etc.), el proveedor tiene acceso
root. Cualquier frase o clave recuperada ahí queda **comprometida**.

- Cuando aparezca una coincidencia, **NO** la importes ni uses en el pod.
- Desde **tu propia máquina** (teléfono/PC de confianza): importa la frase, crea
  una wallet **nueva**, y mueve **todos los fondos** ahí de inmediato.

---

## 1. Requisitos y compilación

Necesitas CUDA (probado con 13.0) y una GPU NVIDIA. Para RTX 5090 la arquitectura
es `sm_120`.

```bash
# generar la lista de palabras BIP39 (una sola vez) -> bip39_words.h
python3 gen_wordlist.py

# compilar (ajusta -arch a tu GPU: 5090=sm_120, 4090=sm_89, 3090=sm_86)
nvcc -O3 -arch=sm_120 seed_search.cu -o seed_search

# confirmar que el motor cripto quedo bien
./seed_search --permute --selftest      # debe decir: TODO OK
```

---

## 2. La base de datos de direcciones

Solo necesaria para el modo `--basedatos` (cuando no conoces la dirección). Es una
lista de direcciones de Ethereum con saldo/actividad.

### 2.1 Descargar

```bash
wget https://privatekeyfinder.io/assets/downloads/ethereum.tsv.gz
```

El archivo pesa ~4.6 GB comprimido. Contiene `direccion <TAB> saldo`, una por línea.

### 2.2 Preparar `saldos.txt`

`seed_search` espera **una dirección por línea** (40 hex, con o sin `0x`). El TSV
trae columnas, así que nos quedamos solo con la primera (la dirección). Para no
gastar 15-20 GB descomprimiendo el archivo entero, se hace al vuelo:

```bash
gunzip -c ethereum.tsv.gz | cut -f1 > saldos.txt
```

- `gunzip -c` descomprime a la salida sin guardar el `.tsv` completo.
- `cut -f1` toma la primera columna (la dirección).
- El `saldos.txt` resultante pesa ~1.3 GB.

### 2.3 Verificar

```bash
head saldos.txt        # deben verse direcciones de 40 hex, una por linea
wc -l saldos.txt       # cuantas direcciones tiene (p.ej. ~174 millones)
```

Cada línea debe verse así (sin `0x`, sin columnas extra):
```
c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
```

> Nota: esta base incluye direcciones con saldo por encima de un mínimo. Si tu
> wallet tenía fondos apreciables, estará incluida. Si estaba vacía o por debajo
> del mínimo, podría no aparecer.

---

## 3. Uso

### 3.1 Orden desconocido, contra la base de datos

Tienes las 12 palabras (en cualquier orden), no sabes la dirección:

```bash
./seed_search --permute --basedatos saldos.txt \
  --phrase "palabra1 palabra2 ... palabra12" --accounts 5
```

- `--permute` prueba los 12! ordenamientos.
- `--basedatos` compara cada dirección derivada contra la lista.
- `--accounts 5` revisa las primeras 5 direcciones (cuentas 0-4) por cada orden.

### 3.2 Palabras faltantes, contra la base de datos

Conoces el orden, faltan 1-3 palabras (marca cada hueco con `?`):

```bash
./seed_search --basedatos saldos.txt \
  --phrase "w1 ? w3 w4 ? w6 w7 w8 w9 w10 w11 w12" --accounts 5
```

### 3.3 Si SÍ conoces la dirección (sin base de datos)

Más rápido y directo. Acepta dirección completa o parcial (`0xAbc...123`):

```bash
# orden desconocido
./seed_search --permute --phrase "w1 ... w12" --addr 0x6c14...6d50

# palabras faltantes
./seed_search --phrase "w1 ? w3 ... ?" --addr 0x6c141975f4057cdb7aed9aa16e0d4cbdb46d6d50
```

### 3.4 Volcar todas las candidatas a un archivo (avanzado)

Genera todas las direcciones candidatas (para cruzarlas aparte con `cruzar.py`):

```bash
./seed_search --dump candidatos.bin --phrase "w1 ... w12" --accounts 2
```

---

## 4. Flags

| Flag | Qué hace |
|---|---|
| `--phrase "..."` | Las 12 palabras. Usa `?` para las que faltan. |
| `--permute` | Prueba todos los ordenamientos (orden desconocido). |
| `--addr 0x...` | Dirección objetivo (completa o parcial con `...`). |
| `--basedatos archivo` | Busca contra una lista de direcciones (no necesita `--addr`). |
| `--accounts N` | Revisa las primeras N direcciones por frase (cuentas 0..N-1). |
| `--out archivo` | Dónde guardar las coincidencias (por defecto `hallazgos.txt`). |
| `--dump archivo` | Vuelca todas las candidatas a binario. |
| `--selftest` | Prueba el motor con la frase de Hardhat. |
| `--start / --end / --gpu` | Reparto multi-GPU (ver abajo). |

---

## 5. Resultados

Durante la búsqueda verás una línea de progreso que se actualiza:
```
  21.02%  100663296/479001600  188s  ETA 11.8min  hits=0
```

- `hits=N` cuenta coincidencias **REALES** (verificadas exactamente en la GPU).
  Si sube, es una coincidencia verdadera, no un falso positivo.

Cuando encuentra algo, lo imprime y lo guarda en `hallazgos.txt`:
```
  *** COINCIDENCIA *** cuenta #0  0x<direccion>  frase: <las 12 palabras en orden>
```

Ver el archivo al terminar:
```bash
cat hallazgos.txt
```

**Interpretar varias coincidencias:** si salen varias líneas con la **misma frase**
pero distinta cuenta/dirección, es tu wallet con varias cuentas. Esa es tu frase.

---

## 6. Multi-GPU

Reparte el espacio entre varias GPUs con `--start/--end/--gpu` (una instancia por
GPU), o usa el lanzador `buscar.sh` si lo tienes. Ejemplo manual con 2 GPUs para
el modo permute (total 12! = 479001600):

```bash
CUDA_VISIBLE_DEVICES=0 ./seed_search --permute --basedatos saldos.txt --phrase "..." \
  --accounts 5 --gpu 0 --start 0         --end 239500800 &
CUDA_VISIBLE_DEVICES=1 ./seed_search --permute --basedatos saldos.txt --phrase "..." \
  --accounts 5 --gpu 1 --start 239500800 --end 479001600 &
```

---

## 7. Rendimiento y viabilidad

Velocidad ~0.9M candidatos/seg por RTX 5090 (el cuello es el PBKDF2 de BIP39).

**Orden desconocido (permute):** 12! con checksum → ~9 min (1 GPU), ~1 min (8 GPU).

**Palabras faltantes:**

| Faltan | 1 GPU | 8 GPU |
|---:|---:|---:|
| 1 | instantáneo | instantáneo |
| 2 | ~5 s | instantáneo |
| 3 | ~2.6 h | ~20 min |
| 4 | ~226 días | ~28 días |

El modo `--basedatos` añade un costo mínimo (Bloom + verificación en GPU); la
velocidad se mantiene casi igual. Memoria GPU extra: ~730 MB (Bloom) + ~3.5 GB
(base ordenada) para 174M direcciones — cabe de sobra en una 5090 (32 GB).

---

## 8. Si no encuentra nada (hits=0 al terminar)

Que termine con `hits=0` en modo `--basedatos` significa que ninguna candidata
coincidió con la base. Posibles causas:

1. **Falta o sobra una palabra**, o alguna no es exactamente la correcta (no es
   solo cuestión de orden).
2. **La frase era de 24 palabras**, no 12 (esta herramienta es para 12).
3. **Ruta de derivación distinta** (no la estándar de MetaMask). Otras wallets
   (Ledger, algunas apps) usan rutas diferentes.
4. **La wallet no está en la base** (vacía o por debajo del mínimo del dump).

---

## 9. Notas / problemas conocidos

- **El self-test escribe en `hallazgos.txt`.** Si corriste `--selftest` antes,
  borra el archivo (`rm hallazgos.txt`) antes de una búsqueda real, o usa `--out`
  para separar. Las líneas del self-test dicen `frase: test test ... junk`.
- **No uses la terminal mientras corre**: teclear ensucia la línea de progreso.
  En tmux puedes desconectarte (`Ctrl+b`, soltar, `d`) y el proceso sigue; vuelve
  con `tmux attach`.

---

## Archivos del proyecto

| Archivo | Para qué |
|---|---|
| `seed_search.cu` | Programa principal. |
| `gen_wordlist.py` | Genera `bip39_words.h` (correr una vez). |
| `saldos.txt` | Lista de direcciones (la preparas tú, ver sección 2). |
| `cruzar.py` | Cruce externo de un volcado `--dump` contra `saldos.txt`. |
| `README.md` | Este archivo. |
