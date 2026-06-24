#!/usr/bin/env python3
# Genera bip39_words.h con la wordlist BIP39 oficial (ingles, 2048 palabras)
# desde la libreria 'mnemonic' (fuente autoritativa). Correr UNA vez en el pod.
#   pip install mnemonic
#   python3 gen_wordlist.py
try:
    from mnemonic import Mnemonic
except ImportError:
    raise SystemExit("Falta 'mnemonic'. Ejecuta: pip install mnemonic")
w = Mnemonic("english").wordlist
assert len(w) == 2048, f"wordlist inesperada: {len(w)}"
with open("bip39_words.h","w") as f:
    f.write("// Autogenerado por gen_wordlist.py (wordlist BIP39 ingles, 2048 palabras)\n")
    f.write("static const char* BIP39_WORDS[2048] = {\n")
    for i in range(0,2048,8):
        f.write("  " + ", ".join('"%s"'%x for x in w[i:i+8]) + ",\n")
    f.write("};\n")
print("bip39_words.h generado (2048 palabras)")
