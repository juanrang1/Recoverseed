#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cruzar.py -- cruza el volcado de direcciones candidatas (candidatos.bin, hecho por
seed_search --dump) contra una lista de direcciones de Ethereum con saldo/actividad.
Cuando una candidata aparece en la lista, recupera la FRASE completa (orden correcto).

USO:
  python3 cruzar.py --candidatos candidatos.bin --saldos saldos.txt \
                    --phrase "w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12"

- candidatos.bin: registros de 32 bytes [lin:8 LE][acc:1][pad:3][addr:20].
- saldos.txt: una direccion por linea (con o sin 0x). Se cargan en memoria
  (~2-3 GB de RAM para ~30M direcciones; si te quedas corto, avisa y lo hacemos
  con ordenacion en disco).
- --phrase: las MISMAS 12 palabras, en el MISMO orden que le pasaste a seed_search.
"""
import sys, argparse

FACT12=[1,1,2,6,24,120,720,5040,40320,362880,3628800,39916800]
def lehmer12(lin, base):
    avail=list(base); out=[]
    for i in range(12):
        f=FACT12[11-i]; d=lin//f; lin%=f
        out.append(avail.pop(d))
    return out

def norm_addr(s):
    s=s.strip().lower()
    if s.startswith("0x"): s=s[2:]
    if len(s)!=40: return None
    try: return bytes.fromhex(s)
    except ValueError: return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--candidatos",required=True)
    ap.add_argument("--saldos",required=True)
    ap.add_argument("--phrase",required=True)
    a=ap.parse_args()

    words=a.phrase.split()
    if len(words)!=12:
        print("La frase debe tener 12 palabras."); sys.exit(1)

    # 1) cargar lista de saldos en un set
    print("Cargando lista de saldos...")
    bal=set(); n=0; bad=0
    with open(a.saldos,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            b=norm_addr(line)
            if b is None:
                bad+=1; continue
            bal.add(b); n+=1
            if n%5_000_000==0: print(f"  {n:,} direcciones cargadas...")
    print(f"Cargadas {n:,} direcciones con saldo ({bad} lineas ignoradas).")
    if n==0:
        print("La lista de saldos esta vacia o con formato invalido."); sys.exit(1)

    # 2) recorrer el volcado y cruzar
    print("Cruzando candidatas...")
    hits=[]; total=0
    REC=32; CH=1_000_000*REC
    with open(a.candidatos,"rb") as f:
        while True:
            buf=f.read(CH)
            if not buf: break
            for off in range(0,len(buf),REC):
                rec=buf[off:off+REC]
                if len(rec)<REC: break
                addr=rec[12:32]
                total+=1
                if addr in bal:
                    lin=int.from_bytes(rec[0:8],"little"); acc=rec[8]
                    perm=lehmer12(lin, words)
                    frase=" ".join(perm)
                    hits.append((acc,"0x"+addr.hex(),frase))
                    print("\n  *** COINCIDENCIA ***")
                    print("  direccion:", "0x"+addr.hex())
                    print("  cuenta   :", acc)
                    print("  FRASE    :", frase)
            print(f"\r  {total:,} candidatas revisadas, {len(hits)} hit(s)   ",end="",flush=True)

    print(f"\n\nListo. {total:,} candidatas revisadas, {len(hits)} coincidencia(s).")
    if hits:
        with open("frase_encontrada.txt","w") as o:
            for acc,ad,fr in hits:
                o.write(f"cuenta {acc}\t{ad}\t{fr}\n")
        print("Guardado en frase_encontrada.txt")
        print("\nSEGURIDAD: importa la frase DESDE TU PROPIA MAQUINA (no el pod) y")
        print("mueve los fondos a una wallet nueva de inmediato.")
    else:
        print("Ninguna candidata aparece en la lista de saldos.")
        print("Posibles causas: la wallet ya esta en cero (usa lista de 'con actividad',")
        print("no solo 'saldo>0'); o falta revisar mas cuentas (--accounts en seed_search);")
        print("o la frase tiene una palabra distinta a las que pusiste.")

if __name__=="__main__":
    main()
