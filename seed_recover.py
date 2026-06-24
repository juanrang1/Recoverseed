#!/usr/bin/env python3
# =============================================================================
# seed_recover.py  -  Recuperacion de palabras faltantes de una frase BIP39
#                     conociendo la direccion Ethereum (ruta MetaMask estandar).
#
# Es el ORACULO de referencia: derivacion validada contra el vector Hardhat
# (clave 0xac09..ff80 -> 0xf39f..2266). Sirve para:
#   - --selftest : confirmar que la cadena BIP39->ETH es correcta en tu maquina.
#   - recuperar 2 palabras faltantes al instante.
#   - 3 palabras: funciona pero es LENTO en Python (es la referencia; la
#     busqueda rapida de verdad sera la version CUDA).
#
# Instalacion (en el pod):
#   pip install mnemonic coincurve pycryptodome
#
# Uso:
#   # Auto-prueba
#   python3 seed_recover.py --selftest
#
#   # Recuperar: pon ? en cada palabra que falta. La direccion es la objetivo.
#   python3 seed_recover.py \
#       --phrase "? abandon ability able about above absent absorb abstract ? access junk" \
#       --addr 0x....
#
#   # Direccion PARCIAL (solo conoces el inicio y el final, como la muestra la wallet):
#   python3 seed_recover.py --phrase "..." --addr 0x6c14...6d50
#
#   # Escanear las primeras N cuentas (por si la direccion no es la #0)
#   python3 seed_recover.py --phrase "..." --addr 0x... --accounts 5
# =============================================================================
import sys, argparse, hashlib, hmac, itertools, time

try:
    from mnemonic import Mnemonic
    from coincurve import PrivateKey
    from Crypto.Hash import keccak as _keccak
except ImportError:
    print("Faltan dependencias. Ejecuta:  pip install mnemonic coincurve pycryptodome")
    sys.exit(1)

import re
MNEMO = Mnemonic("english")
WORDLIST = MNEMO.wordlist
WORDSET = set(WORDLIST)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---- patron de direccion dinamico: completa o prefijo...sufijo (0x6c14...6d50) ----
def parse_addr_pattern(s):
    s = s.lower().strip()
    if s.startswith("0x"): s = s[2:]
    if "." in s:
        parts = re.split(r'\.+', s); prefix, suffix = parts[0], parts[-1]
    else:
        prefix, suffix = s, ""
    for h in prefix+suffix:
        if h not in "0123456789abcdef": raise ValueError(f"caracter no hex en la direccion: {h}")
    if len(prefix)+len(suffix) > 40: raise ValueError("prefijo+sufijo suman mas de 40 hex")
    return prefix, suffix

def addr_matches(addr, prefix, suffix):
    a = addr.lower()
    if a.startswith("0x"): a = a[2:]
    return a.startswith(prefix) and (suffix == "" or a.endswith(suffix))

def keccak256(b):
    h = _keccak.new(digest_bits=256); h.update(b); return h.digest()

# ---- BIP39 seed (PBKDF2-HMAC-SHA512, 2048 iteraciones) ----
def bip39_seed(mnemonic, passphrase=""):
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'),
                               ("mnemonic"+passphrase).encode('utf-8'), 2048)

# ---- BIP32: derivar clave privada por una ruta ----
def _ckd(kpar, cpar, i):
    if i >= 0x80000000:                      # endurecida
        data = b'\x00' + kpar.to_bytes(32,'big') + i.to_bytes(4,'big')
    else:                                    # normal: usa pubkey comprimida del padre
        comp = PrivateKey(kpar.to_bytes(32,'big')).public_key.format(compressed=True)
        data = comp + i.to_bytes(4,'big')
    I = hmac.new(cpar, data, hashlib.sha512).digest()
    ki = (int.from_bytes(I[:32],'big') + kpar) % N
    return ki, I[32:]

def derive_privkey(seed, path):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(I[:32],'big'); c = I[32:]
    for i in path:
        k, c = _ckd(k, c, i)
    return k

def eth_path(account=0):
    # m/44'/60'/0'/0/<account>  (MetaMask)
    return [0x8000002C, 0x8000003C, 0x80000000, 0, account]

def address_from_seed(seed, account=0):
    k = derive_privkey(seed, eth_path(account))
    pub = PrivateKey(k.to_bytes(32,'big')).public_key.format(compressed=False)[1:]  # x||y
    return '0x' + keccak256(pub)[-20:].hex()

# ---- self-test contra el vector Hardhat ----
def selftest():
    m = "test test test test test test test test test test test junk"
    addr = address_from_seed(bip39_seed(m), 0)
    exp  = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    print("  vector Hardhat -> ", addr)
    ok = (addr == exp)
    print("  RESULTADO       :  ", "TODO OK" if ok else "FALLO (revisa libreria)")
    return ok

# ---- busqueda de palabras faltantes ----
def recover(template_words, addr_pattern, accounts=1, passphrase="", outfile="hallazgos.txt"):
    prefix, suffix = parse_addr_pattern(addr_pattern)
    known = len(prefix)+len(suffix)
    unknown_pos = [i for i,w in enumerate(template_words) if w == "?"]
    k = len(unknown_pos)
    # validar palabras conocidas
    for i,w in enumerate(template_words):
        if w != "?" and w not in WORDSET:
            print(f"  '{w}' (posicion {i+1}) no es una palabra BIP39 valida."); return None
    combos = 2048**k
    valid_est = combos/16
    fp = valid_est/(16**known) if known<40 else 0
    print(f"  Faltan {k} palabra(s) en las posiciones {[p+1 for p in unknown_pos]}")
    print(f"  Direccion conocida: prefijo '{prefix}' + sufijo '{suffix}' = {known} hex")
    if known < 40:
        print(f"  Direccion PARCIAL -> pueden salir ~{fp:.2g} falsos positivos (recolecto todos).")
    print(f"  Combinaciones brutas: {combos:,}  (el checksum descarta ~15/16)")
    print(f"  Las coincidencias se guardan en: {outfile}")
    if k >= 3:
        print("  AVISO: 3+ palabras en Python es LENTO (referencia). Para velocidad real usa la version CUDA.")
    t0=time.time(); tried=0; checked=0; hits=[]
    cand = list(template_words)
    for combo in itertools.product(WORDLIST, repeat=k):
        for idx,pos in enumerate(unknown_pos):
            cand[pos] = combo[idx]
        phrase = " ".join(cand)
        tried += 1
        if not MNEMO.check(phrase):       # filtro de checksum (barato)
            continue
        checked += 1
        seed = bip39_seed(phrase, passphrase)
        for acc in range(accounts):
            a = address_from_seed(seed, acc)
            if addr_matches(a, prefix, suffix):
                dt=time.time()-t0
                print(f"\n  *** COINCIDENCIA *** cuenta #{acc}  addr {a}")
                print(f"      FRASE: {phrase}   ({dt:.1f}s)")
                hits.append((phrase, acc, a))
                # guardar inmediatamente (por si se interrumpe)
                with open(outfile, "a") as fh:
                    fh.write(f"cuenta #{acc}\taddr {a}\tfrase: {phrase}\n")
        if checked % 5000 == 0:
            dt=time.time()-t0
            print(f"    ...{tried:,} combos, {checked:,} validas, {len(hits)} hits, {dt:.0f}s", flush=True)
    print(f"\n  Terminado. {checked:,} frases validas probadas de {tried:,} combos. {len(hits)} coincidencia(s).")
    if not hits:
        print("  Revisa: palabras conocidas, patron de direccion, y la ruta/cuenta (--accounts).")
    else:
        print(f"  Coincidencia(s) guardada(s) en {outfile}")
        if known < 40 and len(hits) > 1:
            print("  Varias coincidencias (direccion parcial). Carga cada frase en una wallet y mira cual tiene tus fondos.")
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--phrase", help="12 palabras separadas por espacio, ? donde falte")
    ap.add_argument("--addr", help="direccion ETH objetivo: completa o patron parcial '0x6c14...6d50'")
    ap.add_argument("--accounts", type=int, default=1, help="cuantas cuentas escanear (0..N-1)")
    ap.add_argument("--passphrase", default="", help="passphrase BIP39 (normalmente vacia)")
    ap.add_argument("--out", default="hallazgos.txt", help="archivo donde guardar coincidencias")
    a = ap.parse_args()

    print("== Self-test (cadena BIP39->ETH) ==")
    if not selftest():
        print("El self-test fallo; no busco hasta que la derivacion sea correcta."); sys.exit(1)
    if a.selftest: return
    if not a.phrase or not a.addr:
        print("\nFalta --phrase y/o --addr. Ej: --phrase \"? abandon ... junk\" --addr 0x..."); sys.exit(1)

    words = a.phrase.split()
    if len(words) not in (12,15,18,21,24):
        print(f"\nLa frase tiene {len(words)} palabras; debe ser 12/15/18/21/24."); sys.exit(1)
    print("\n== Busqueda ==")
    recover(words, a.addr, accounts=a.accounts, passphrase=a.passphrase, outfile=a.out)

if __name__ == "__main__":
    main()
