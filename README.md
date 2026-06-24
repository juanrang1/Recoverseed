# Recuperación de palabras faltantes de una frase semilla (BIP39 → Ethereum)

Recupera en GPU las **palabras que faltan** de una frase semilla BIP39 de 12 palabras,
cuando conoces el resto de las palabras y la **dirección Ethereum** (completa o parcial).
Ruta de derivación: **MetaMask estándar** `m/44'/60'/0'/0/0`.

Para cada combinación posible de las palabras faltantes: valida el checksum BIP39,
deriva el seed (PBKDF2-HMAC-SHA512, 2048 iteraciones), la clave por BIP32, la clave
pública secp256k1, la dirección (keccak-256), y la compara con la tuya.

> Toda la criptografía fue validada bloque por bloque contra vectores conocidos
> (incluido el vector público de Hardhat: la frase `test test … junk` → `0xf39F…2266`).

---

## Viabilidad (cuánto tarda según las palabras que faltan)

Frase de 12 palabras, peor caso (espacio completo). **En promedio = la mitad.**
Velocidad estimada ~3 millones de candidatos/seg por RTX 5090 (se confirma al correr).

| Faltan | Combinaciones | 1× RTX 5090 | 8× RTX 5090 |
|---:|---:|---:|---:|
| 1 | 2 048 | instantáneo | instantáneo |
| 2 | 4 194 304 | instantáneo | instantáneo |
| 3 | 8 589 934 592 | **~3 min** | **~22 s** |
| 4 | 17 592 186 044 416 | ~4.3 días | ~12.8 h |
| 5 | 36 028 797 018 963 968 | ~24 años ❌ | ~3 años ❌ |

**Techo práctico: 4 palabras.** Cada palabra extra multiplica el tiempo ×2048.
El PBKDF2 de 2048 iteraciones hace que cada candidato sea caro; por eso 5+ es inviable.

---

## Requisitos

- GPU NVIDIA con CUDA (probado en RTX 5090, `sm_120`). Plantilla **cuda-devel** o **PyTorch** de Vast.ai.
- `nvcc` y `g++` funcionando.
- Python con la librería `mnemonic` (solo para generar la wordlist una vez).

## Instalación paso a paso (pod nuevo)

```bash
# 1) Comprobar entorno
nvidia-smi -L
nvcc --version
g++ --version

# 2) Traer el código
git clone https://github.com/juanrang1/Recoverseed.git
cd Recoverseed

# 3) Generar la wordlist (una sola vez) -> crea bip39_words.h
pip install mnemonic
python3 gen_wordlist.py

# 4) Compilar
nvcc -O3 -arch=sm_120 seed_search.cu -o seed_search

# 5) Probar que todo funciona (self-test end-to-end en la GPU)
./seed_search --selftest
```
El self-test esconde 2 palabras de la frase de Hardhat y confirma que las recupera
llegando a `0xf39f…2266`. Debe terminar diciendo **TODO OK**.

> Si cambias de GPU, ajusta `-arch=sm_XXX` (5090 = `sm_120`, 4090 = `sm_89`, 3090 = `sm_86`).

---

## Uso

Pon `?` en cada palabra que falta. Las posiciones pueden ser cualesquiera.

```bash
# Faltan la 1ª, la 5ª y la última (conoces la dirección completa)
./seed_search \
  --phrase "? legal winner thank ? wolf abandon kit absurd net wing ?" \
  --addr 0x6c141975f4057cdb7aed9aa16e0d4cbdb46d6d50

# Faltan las 3 últimas
./seed_search \
  --phrase "legal winner thank year wave sausage worth useful ? ? ?" \
  --addr 0x6c141975f4057cdb7aed9aa16e0d4cbdb46d6d50
```

### Dirección parcial
Si solo recuerdas el inicio y el final (como la muestra la wallet), usa `...`:

```bash
./seed_search --phrase "..." --addr 0x6c14...6d50     # primeros 4 + últimos 4
./seed_search --phrase "..." --addr 0xaaa...aaaa      # primeros 3 + últimos 4
./seed_search --phrase "..." --addr 0xaaaaa...aaaa    # primeros 5 + últimos 4
```
Con dirección parcial pueden salir varios candidatos; se guardan **todos**. Para 3
palabras faltantes: 7 hex conocidos → ~2 candidatos; 8 hex → casi único; 9 hex → único.

### Opciones

| Flag | Significado | Default |
|---|---|---|
| `--phrase "..."` | 12 palabras, `?` donde falte. | — |
| `--addr 0x...` | Dirección completa o patrón `0xpref...suf`. | — |
| `--accounts N` | Escanea las primeras N cuentas (`/0/0`, `/0/1`, …) por si no es la #0. | 1 |
| `--out archivo` | Dónde guardar las coincidencias. | hallazgos.txt |
| `--blocks` / `--threads` | Configuración del grid CUDA. | 4096 / 256 |
| `--selftest` | Prueba end-to-end y termina. | — |

Las coincidencias se imprimen y se guardan al instante en el archivo (frase + nº de cuenta),
así que aunque interrumpas no las pierdes.

---

## Velocidad por GPU (orientativo)

El cuello de botella es el **PBKDF2 de 2048 iteraciones** por candidato.

| GPU | candidatos/seg | Estado |
|---|---|---|
| RTX 5090 | ~3 M (estimado) | medir al correr |
| RTX 4090 | ~2 M | estimado |
| RTX 3090 | ~1 M | estimado |

Solo es estimación: la cifra real la verás en la barra de progreso al lanzar una búsqueda.
Escala casi lineal con el número de GPUs.

---

## ⚠️ Seguridad

Si recuperas la frase en una **GPU alquilada** (Vast.ai, etc.), considérala **expuesta**:
la máquina no es tuya y su dueño tiene acceso de root. En cuanto aparezca la frase, **mueve
los fondos desde un equipo de tu confianza a una billetera nueva (semilla nueva)**, nunca
desde el pod.

## Cómo funciona (resumen)

Por cada candidato: se ordenan las 12 palabras (las fijas + las probadas) en índices BIP39,
se verifica el checksum (descarta ~15/16 antes del cálculo caro), se arma la frase, y se
deriva PBKDF2→seed, BIP32→clave, secp256k1→pubkey, keccak-256→dirección, que se compara
con tu patrón. Cada primitiva (SHA-512, PBKDF2, secp256k1, BIP32, keccak, SHA-256, checksum)
fue validada por separado contra vectores oficiales antes de ensamblar.

## Archivos

| Archivo | Para qué |
|---|---|
| `seed_search.cu` | Programa principal (todas las primitivas + búsqueda). |
| `gen_wordlist.py` | Genera `bip39_words.h` (wordlist oficial). Correr una vez. |
| `seed_recover.py` | Oráculo de referencia en Python (CPU): valida y recupera 2 palabras. |
| `README.md` | Este archivo. |
