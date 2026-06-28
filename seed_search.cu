// =============================================================================
// seed_search.cu  -  Recupera palabras faltantes de una frase BIP39 (12 palabras)
//   conociendo la direccion ETH (ruta MetaMask m/44'/60'/0'/0/0).
//   Toda la criptografia validada por bloques contra vectores conocidos (Hardhat).
//
//   Requiere bip39_words.h (generalo con: python3 gen_wordlist.py)
//   Compilar: nvcc -O3 -arch=sm_120 seed_search.cu -o seed_search
//   Ver README.md para uso completo.
// =============================================================================
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <ctime>
#include "bip39_words.h"
typedef unsigned long long u64; typedef unsigned char u8; typedef unsigned int u32;
typedef unsigned __int128 u128;

// ---------------- SHA-512 ----------------
__device__ __constant__ u64 H0[8]={
  0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
__device__ __constant__ u64 K512[80]={
  0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
  0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
  0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
  0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};
__device__ __forceinline__ u64 ROTR(u64 x,int n){ return (x>>n)|(x<<(64-n)); }
#define BSIG0(x) (ROTR(x,28)^ROTR(x,34)^ROTR(x,39))
#define BSIG1(x) (ROTR(x,14)^ROTR(x,18)^ROTR(x,41))
#define SSIG0(x) (ROTR(x,1)^ROTR(x,8)^((x)>>7))
#define SSIG1(x) (ROTR(x,19)^ROTR(x,61)^((x)>>6))
#define CHf(e,f,g) (((e)&(f))^((~(e))&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
__device__ __forceinline__ u64 ld_be64(const u8* p){ return ((u64)p[0]<<56)|((u64)p[1]<<48)|((u64)p[2]<<40)|((u64)p[3]<<32)|((u64)p[4]<<24)|((u64)p[5]<<16)|((u64)p[6]<<8)|((u64)p[7]); }
__device__ __forceinline__ void st_be64(u8* p,u64 v){ p[0]=v>>56;p[1]=v>>48;p[2]=v>>40;p[3]=v>>32;p[4]=v>>24;p[5]=v>>16;p[6]=v>>8;p[7]=v; }
__device__ void sha512_transform(u64 st[8], const u8* block){
  u64 w[16];
  #pragma unroll
  for(int i=0;i<16;i++) w[i]=ld_be64(block+i*8);
  u64 a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  for(int i=0;i<80;i++){
    u64 wi;
    if(i<16) wi=w[i&15];
    else { u64 w15=w[(i+1)&15], w2=w[(i+14)&15], w7=w[(i+9)&15], w16=w[i&15]; wi=SSIG1(w2)+w7+SSIG0(w15)+w16; w[i&15]=wi; }
    u64 t1=h+BSIG1(e)+CHf(e,f,g)+K512[i]+wi; u64 t2=BSIG0(a)+MAJ(a,b,c); h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}
__device__ void finalize_from_state(u64 st[8], const u8* tail, int taillen, u64 total_len, u8 out[64]){
  u64 s[8];
  #pragma unroll
  for(int i=0;i<8;i++) s[i]=st[i];
  u8 buf[256];
  for(int j=0;j<taillen;j++) buf[j]=tail[j];
  buf[taillen]=0x80; int padlen=taillen+1; int total=(padlen<=112)?128:256;
  for(int j=padlen;j<total-16;j++) buf[j]=0;
  st_be64(buf+total-16,(total_len>>61)); st_be64(buf+total-8,(total_len*8));
  for(int b=0;b<total;b+=128) sha512_transform(s,buf+b);
  #pragma unroll
  for(int k=0;k<8;k++) st_be64(out+k*8,s[k]);
}
__device__ void sha512(const u8* msg,u64 len,u8 out[64]){
  u64 s[8];
  #pragma unroll
  for(int i=0;i<8;i++) s[i]=H0[i];
  u64 i=0; while(len-i>=128){ sha512_transform(s,msg+i); i+=128; }
  finalize_from_state(s,msg+i,(int)(len-i),len,out);
}
// HMAC-SHA512 general (clave variable)
__device__ void hmac_sha512(const u8* key,int keylen,const u8* msg,int msglen,u8 out[64]){
  u8 k0[128];
  if(keylen>128){ u8 hk[64]; sha512(key,keylen,hk); for(int i=0;i<64;i++)k0[i]=hk[i]; for(int i=64;i<128;i++)k0[i]=0; }
  else { for(int i=0;i<keylen;i++)k0[i]=key[i]; for(int i=keylen;i<128;i++)k0[i]=0; }
  u8 ip[128],op[128]; for(int i=0;i<128;i++){ ip[i]=k0[i]^0x36; op[i]=k0[i]^0x5c; }
  u64 s[8];
  #pragma unroll
  for(int i=0;i<8;i++) s[i]=H0[i];
  sha512_transform(s,ip);
  int i=0; while(msglen-i>=128){ sha512_transform(s,msg+i); i+=128; }
  u8 inner[64]; finalize_from_state(s,msg+i,msglen-i,(u64)128+msglen,inner);
  u64 s2[8];
  #pragma unroll
  for(int j=0;j<8;j++) s2[j]=H0[j];
  sha512_transform(s2,op);
  finalize_from_state(s2,inner,64,(u64)128+64,out);
}

// ---------------- secp256k1 ----------------
__device__ __constant__ u64 Pc[4]={0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
__device__ __constant__ u64 Nc[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
__device__ __constant__ u64 Gx[4]={0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL};
__device__ __constant__ u64 Gy[4]={0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
__device__ __constant__ u64 Pm2[4]={0xFFFFFFFEFFFFFC2DULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
#define SECP_C 0x1000003D1ULL

__device__ int ge4(const u64 a[4], const u64 m[4]){ for(int i=3;i>=0;i--){ if(a[i]<m[i])return 0; if(a[i]>m[i])return 1; } return 1; }
__device__ void cond_sub(u64 r[4], const u64 m[4]){
  if(!ge4(r,m)) return;
  u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)r[i]-m[i]-br; r[i]=(u64)t; br=(t>>64)&1; }
}
__device__ void f_add(u64 r[4], const u64 a[4], const u64 b[4]){
  u128 c=0; for(int i=0;i<4;i++){ u128 t=(u128)a[i]+b[i]+c; r[i]=(u64)t; c=t>>64; }
  if(c||ge4(r,Pc)){ u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)r[i]-Pc[i]-br; r[i]=(u64)t; br=(t>>64)&1; } }
}
__device__ void f_sub(u64 r[4], const u64 a[4], const u64 b[4]){
  u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)a[i]-b[i]-br; r[i]=(u64)t; br=(t>>64)&1; }
  if(br){ u128 c=0; for(int i=0;i<4;i++){ u128 t=(u128)r[i]+Pc[i]+c; r[i]=(u64)t; c=t>>64; } }
}
__device__ void f_reduce(u64 p[8], u64 r[4]){
  for(int pass=0;pass<3;pass++){
    u64 hi0=p[4],hi1=p[5],hi2=p[6],hi3=p[7]; p[4]=p[5]=p[6]=p[7]=0;
    u128 carry; u128 c0=(u128)p[0]+(u128)SECP_C*hi0; p[0]=(u64)c0; carry=c0>>64;
    u128 c1=(u128)p[1]+(u128)SECP_C*hi1+carry; p[1]=(u64)c1; carry=c1>>64;
    u128 c2=(u128)p[2]+(u128)SECP_C*hi2+carry; p[2]=(u64)c2; carry=c2>>64;
    u128 c3=(u128)p[3]+(u128)SECP_C*hi3+carry; p[3]=(u64)c3; carry=c3>>64;
    u128 c4=(u128)p[4]+carry; p[4]=(u64)c4; carry=c4>>64;
    u128 c5=(u128)p[5]+carry; p[5]=(u64)c5; carry=c5>>64;
    u128 c6=(u128)p[6]+carry; p[6]=(u64)c6; carry=c6>>64;
    u128 c7=(u128)p[7]+carry; p[7]=(u64)c7; carry=c7>>64;
    p[4]=(u64)(p[4]+(u64)carry);
  }
  r[0]=p[0];r[1]=p[1];r[2]=p[2];r[3]=p[3]; cond_sub(r,Pc); cond_sub(r,Pc);
}
__device__ void f_mul(u64 r[4], const u64 a[4], const u64 b[4]){
  u64 p[8]; for(int i=0;i<8;i++)p[i]=0;
  for(int i=0;i<4;i++){ u128 carry=0;
    for(int j=0;j<4;j++){ u128 t=(u128)a[i]*b[j]+p[i+j]+carry; p[i+j]=(u64)t; carry=t>>64; }
    int k=i+4; while(carry){ u128 t=(u128)p[k]+carry; p[k]=(u64)t; carry=t>>64; k++; }
  }
  f_reduce(p,r);
}
__device__ void f_sqr(u64 r[4], const u64 a[4]){ f_mul(r,a,a); }
__device__ void f_inv(u64 r[4], const u64 a[4]){
  u64 res[4]={1,0,0,0}, base[4]; for(int i=0;i<4;i++)base[i]=a[i];
  for(int i=0;i<4;i++){ u64 e=Pm2[i];
    for(int b=0;b<64;b++){ if(e&1){ f_mul(res,res,base);} f_sqr(base,base); e>>=1; }
  }
  for(int i=0;i<4;i++)r[i]=res[i];
}

// Punto Jacobiano. Infinito = Z==0.
struct PJ { u64 X[4],Y[4],Z[4]; };
__device__ void pj_set_inf(PJ&p){ for(int i=0;i<4;i++){p.X[i]=0;p.Y[i]=0;p.Z[i]=0;} p.X[0]=1; p.Y[0]=1; }
__device__ int is_inf(const PJ&p){ return (p.Z[0]|p.Z[1]|p.Z[2]|p.Z[3])==0; }
__device__ void pj_double(PJ&R, const PJ&Pp){
  if(is_inf(Pp)){ R=Pp; return; }
  u64 A[4],B[4],C[4],D[4],E[4],F[4],t[4],t2[4],X3[4],Y3[4],Z3[4];
  f_sqr(A,Pp.X); f_sqr(B,Pp.Y); f_sqr(C,B);
  f_add(t,Pp.X,B); f_sqr(t,t); f_sub(t,t,A); f_sub(t,t,C); f_add(D,t,t); // D=2*((X+B)^2-A-C)
  f_add(E,A,A); f_add(E,E,A);            // E=3A
  f_sqr(F,E);
  f_add(t,D,D); f_sub(X3,F,t);           // X3=F-2D
  f_sub(t,D,X3); f_mul(t,E,t); f_add(t2,C,C);f_add(t2,t2,t2);f_add(t2,t2,t2); f_sub(Y3,t,t2); // Y3=E*(D-X3)-8C
  f_mul(t,Pp.Y,Pp.Z); f_add(Z3,t,t);     // Z3=2*Y*Z
  for(int i=0;i<4;i++){ R.X[i]=X3[i]; R.Y[i]=Y3[i]; R.Z[i]=Z3[i]; }
}
__device__ void pj_add(PJ&R, const PJ&P1, const PJ&P2){
  if(is_inf(P1)){ R=P2; return; } if(is_inf(P2)){ R=P1; return; }
  u64 Z1Z1[4],Z2Z2[4],U1[4],U2[4],S1[4],S2[4],H[4],I[4],J[4],r[4],V[4],t[4],t2[4],X3[4],Y3[4],Z3[4];
  f_sqr(Z1Z1,P1.Z); f_sqr(Z2Z2,P2.Z);
  f_mul(U1,P1.X,Z2Z2); f_mul(U2,P2.X,Z1Z1);
  f_mul(S1,P1.Y,P2.Z); f_mul(S1,S1,Z2Z2);
  f_mul(S2,P2.Y,P1.Z); f_mul(S2,S2,Z1Z1);
  if(ge4(U1,U2)==1 && ge4(U2,U1)==1){ // U1==U2
    if(!(ge4(S1,S2)==1 && ge4(S2,S1)==1)){ pj_set_inf(R); return; }
    else { pj_double(R,P1); return; }
  }
  f_sub(H,U2,U1); f_add(t,H,H); f_sqr(I,t);
  f_mul(J,H,I);
  f_sub(t,S2,S1); f_add(r,t,t);
  f_mul(V,U1,I);
  f_sqr(t,r); f_sub(t,t,J); f_add(t2,V,V); f_sub(X3,t,t2);          // X3=r^2-J-2V
  f_sub(t,V,X3); f_mul(t,r,t); f_mul(t2,S1,J); f_add(t2,t2,t2); f_sub(Y3,t,t2); // Y3=r*(V-X3)-2*S1*J
  f_add(t,P1.Z,P2.Z); f_sqr(t,t); f_sub(t,t,Z1Z1); f_sub(t,t,Z2Z2); f_mul(Z3,t,H);  // Z3=((Z1+Z2)^2-Z1Z1-Z2Z2)*H
  for(int i=0;i<4;i++){ R.X[i]=X3[i]; R.Y[i]=Y3[i]; R.Z[i]=Z3[i]; }
}
// k*G -> (x,y) afin
__device__ void scalar_mul_G(const u64 k[4], u64 x[4], u64 y[4]){
  PJ R; pj_set_inf(R);
  PJ G; for(int i=0;i<4;i++){G.X[i]=Gx[i];G.Y[i]=Gy[i];} G.Z[0]=1;G.Z[1]=G.Z[2]=G.Z[3]=0;
  for(int i=3;i>=0;i--){ u64 e=k[i];
    for(int b=63;b>=0;b--){ pj_double(R,R); if((e>>b)&1) pj_add(R,R,G); }
  }
  u64 zi[4],zi2[4],zi3[4]; f_inv(zi,R.Z); f_sqr(zi2,zi); f_mul(zi3,zi2,zi);
  f_mul(x,R.X,zi2); f_mul(y,R.Y,zi3);
}
// pubkey comprimida (33 bytes) de k
__device__ void pubkey_compressed(const u64 k[4], u8 out[33]){
  u64 x[4],y[4]; scalar_mul_G(k,x,y);
  out[0]=(y[0]&1)?0x03:0x02;
  for(int i=0;i<4;i++) st_be64(out+1+(3-i)*8, x[i]);  // x big-endian
}

// ---------------- BIP32 ----------------
__device__ void be32_to_fe(const u8* b, u64 r[4]){ for(int i=0;i<4;i++) r[i]=ld_be64(b+(3-i)*8); }
__device__ void fe_to_be32(const u64 r[4], u8* b){ for(int i=0;i<4;i++) st_be64(b+(3-i)*8, r[i]); }
__device__ void add_mod_N(const u64 a[4], const u64 b[4], u64 r[4]){
  u128 c=0; for(int i=0;i<4;i++){ u128 t=(u128)a[i]+b[i]+c; r[i]=(u64)t; c=t>>64; }
  if(c||ge4(r,Nc)){ u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)r[i]-Nc[i]-br; r[i]=(u64)t; br=(t>>64)&1; } }
}
__device__ void bip32_master(const u8 seed[64], u64 k[4], u8 chain[32]){
  u8 I[64]; hmac_sha512((const u8*)"Bitcoin seed",12,seed,64,I);
  be32_to_fe(I,k); for(int i=0;i<32;i++) chain[i]=I[32+i];
}
__device__ void bip32_ckd(const u64 kpar[4], const u8 cpar[32], u32 idx, u64 kchild[4], u8 cchild[32]){
  u8 data[37];
  if(idx>=0x80000000){ data[0]=0; fe_to_be32(kpar,data+1); }
  else { u8 comp[33]; pubkey_compressed(kpar,comp); for(int i=0;i<33;i++)data[i]=comp[i]; }
  data[33]=idx>>24; data[34]=idx>>16; data[35]=idx>>8; data[36]=idx;
  u8 I[64]; hmac_sha512(cpar,32,data,37,I);
  u64 IL[4]; be32_to_fe(I,IL); add_mod_N(IL,kpar,kchild);
  for(int i=0;i<32;i++) cchild[i]=I[32+i];
}
// deriva m/44'/60'/0'/0/account  -> clave privada (32 bytes big-endian)
__device__ void derive_eth(const u8 seed[64], u32 account, u8 priv_be[32]){
  u64 k[4]; u8 c[32]; bip32_master(seed,k,c);
  u32 path[5]={0x8000002C,0x8000003C,0x80000000,0,account};
  for(int s=0;s<5;s++){ u64 kc[4]; u8 cc[32]; bip32_ckd(k,c,path[s],kc,cc); for(int i=0;i<4;i++)k[i]=kc[i]; for(int i=0;i<32;i++)c[i]=cc[i]; }
  fe_to_be32(k,priv_be);
}

__device__ void hmac_midstates(const u8* key, int keylen, u64 ist[8], u64 ost[8]){
  u8 k0[128];
  if(keylen>128){ u8 hk[64]; sha512(key,keylen,hk); for(int i=0;i<64;i++)k0[i]=hk[i]; for(int i=64;i<128;i++)k0[i]=0; }
  else { for(int i=0;i<keylen;i++)k0[i]=key[i]; for(int i=keylen;i<128;i++)k0[i]=0; }
  u8 ip[128], op[128];
  for(int i=0;i<128;i++){ ip[i]=k0[i]^0x36; op[i]=k0[i]^0x5c; }
  #pragma unroll
  for(int i=0;i<8;i++){ ist[i]=H0[i]; ost[i]=H0[i]; }
  sha512_transform(ist, ip);
  sha512_transform(ost, op);
}

__device__ void hmac_msg(const u64 ist[8], const u64 ost[8], const u8* msg, int msglen, u8 out[64]){
  u64 s[8];
  #pragma unroll
  for(int i=0;i<8;i++) s[i]=ist[i];
  int i=0;
  while(msglen-i>=128){ sha512_transform(s, msg+i); i+=128; }
  u8 inner[64];
  finalize_from_state(s, msg+i, msglen-i, (u64)128+msglen, inner);
  u64 s2[8];
  #pragma unroll
  for(int j=0;j<8;j++) s2[j]=ost[j];
  finalize_from_state(s2, inner, 64, (u64)128+64, out);
}

__device__ void pbkdf2_bip39(const u8* pw, int pwlen, const u8* salt, int saltlen, int c, u8 out[64]){
  u64 ist[8], ost[8];
  hmac_midstates(pw, pwlen, ist, ost);
  u8 msg1[140];
  for(int i=0;i<saltlen;i++) msg1[i]=salt[i];
  msg1[saltlen]=0; msg1[saltlen+1]=0; msg1[saltlen+2]=0; msg1[saltlen+3]=1; // INT32BE(1)
  u8 U[64], T[64];
  hmac_msg(ist, ost, msg1, saltlen+4, U);
  #pragma unroll
  for(int j=0;j<64;j++) T[j]=U[j];
  for(int it=1; it<c; it++){
    hmac_msg(ist, ost, U, 64, U);
    #pragma unroll
    for(int j=0;j<64;j++) T[j]^=U[j];
  }
  for(int j=0;j<64;j++) out[j]=T[j];
}

__device__ __constant__ u32 H256[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
__device__ __constant__ u32 K256[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

__device__ __forceinline__ u32 RR32(u32 x,int n){ return (x>>n)|(x<<(32-n)); }
__device__ void sha256(const u8* msg,int len,u8 out[32]){
  u32 h[8]; for(int i=0;i<8;i++) h[i]=H256[i];
  u8 buf[128]; int padlen=len+1,total=(padlen<=56)?64:128;
  for(int i=0;i<len;i++) buf[i]=msg[i]; buf[len]=0x80; for(int i=len+1;i<total-8;i++) buf[i]=0;
  unsigned long long bits=(unsigned long long)len*8; for(int i=0;i<8;i++) buf[total-1-i]=(bits>>(8*i))&0xff;
  for(int off=0;off<total;off+=64){ u32 w[64];
    for(int i=0;i<16;i++) w[i]=(buf[off+i*4]<<24)|(buf[off+i*4+1]<<16)|(buf[off+i*4+2]<<8)|buf[off+i*4+3];
    for(int i=16;i<64;i++){ u32 s0=RR32(w[i-15],7)^RR32(w[i-15],18)^(w[i-15]>>3),s1=RR32(w[i-2],17)^RR32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    u32 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){ u32 S1=RR32(e,6)^RR32(e,11)^RR32(e,25),ch=(e&f)^((~e)&g),t1=hh+S1+ch+K256[i]+w[i],S0=RR32(a,2)^RR32(a,13)^RR32(a,22),maj=(a&b)^(a&c)^(b&c),t2=S0+maj; hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh; }
  for(int i=0;i<8;i++){ out[i*4]=h[i]>>24;out[i*4+1]=h[i]>>16;out[i*4+2]=h[i]>>8;out[i*4+3]=h[i]; }
}
// checksum BIP39 para 12 palabras (en espacio de indices)
__device__ int bip39_ok_12(const int idx[12]){
  u8 bb[17]; for(int i=0;i<17;i++) bb[i]=0; int bp=0;
  for(int w=0;w<12;w++) for(int b=10;b>=0;b--){ bb[bp/8]|=((idx[w]>>b)&1)<<(7-(bp%8)); bp++; }
  u8 ent[16]; for(int i=0;i<16;i++) ent[i]=bb[i];
  int cs_stored=(bb[16]>>4)&0xF;
  u8 hh[32]; sha256(ent,16,hh);
  return cs_stored==((hh[0]>>4)&0xF);
}

__device__ __constant__ int kc_rotc[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
__device__ __constant__ int kc_piln[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
__device__ __constant__ u64 kc_rndc[24]={0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
__device__ __forceinline__ u64 ROTL64(u64 x,int n){ return (x<<n)|(x>>(64-n)); }
__device__ void keccakf(u64 st[25]){ u64 bc[5],t;
  for(int r=0;r<24;r++){ for(int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
    for(int i=0;i<5;i++){ t=bc[(i+4)%5]^ROTL64(bc[(i+1)%5],1); for(int j=0;j<25;j+=5) st[j+i]^=t; }
    t=st[1]; for(int i=0;i<24;i++){ int j=kc_piln[i]; bc[0]=st[j]; st[j]=ROTL64(t,kc_rotc[i]); t=bc[0]; }
    for(int j=0;j<25;j+=5){ for(int i=0;i<5;i++) bc[i]=st[j+i]; for(int i=0;i<5;i++) st[j+i]^=(~bc[(i+1)%5])&bc[(i+2)%5]; }
    st[0]^=kc_rndc[r]; } }
__device__ void keccak256(const u8* in,int len,u8 out[32]){ u64 st[25]; for(int i=0;i<25;i++) st[i]=0; const int rate=136; int i=0; u8 blk[136];
  while(len-i>=rate){ for(int k=0;k<rate/8;k++){ u64 l=0; for(int b=0;b<8;b++) l|=((u64)in[i+k*8+b])<<(8*b); st[k]^=l; } keccakf(st); i+=rate; }
  int rem=len-i; for(int k=0;k<rem;k++) blk[k]=in[i+k]; blk[rem]=0x01; for(int k=rem+1;k<rate;k++) blk[k]=0; blk[rate-1]^=0x80;
  for(int k=0;k<rate/8;k++){ u64 l=0; for(int b=0;b<8;b++) l|=((u64)blk[k*8+b])<<(8*b); st[k]^=l; } keccakf(st);
  for(int k=0;k<4;k++) for(int b=0;b<8;b++) out[k*8+b]=(st[k]>>(8*b))&0xff; }

// ===================== wordlist + resultados en GPU =====================
__device__ char d_words[2048][9];
#define MAX_RESULTS 256
__device__ int  g_result_count;
__device__ unsigned long long g_dump_count;
__device__ int  g_result_acc[MAX_RESULTS];
__device__ char g_results[MAX_RESULTS][120];

// ===================== kernel de busqueda =====================
__global__ void search_kernel(unsigned long long start, unsigned long long end,
                              int K, const int* unknown_pos, const int* fixed_idx,
                              int accounts, int pfx_n, const u8* pfx_nib, int sfx_n, const u8* sfx_nib){
  unsigned long long tid=(unsigned long long)blockIdx.x*blockDim.x+threadIdx.x;
  unsigned long long stride=(unsigned long long)gridDim.x*blockDim.x;
  for(unsigned long long lin=start+tid; lin<end; lin+=stride){
    int idx[12];
    #pragma unroll
    for(int i=0;i<12;i++) idx[i]=fixed_idx[i];
    unsigned long long r=lin;
    for(int j=K-1;j>=0;j--){ idx[unknown_pos[j]]=(int)(r&2047ULL); r>>=11; }
    if(!bip39_ok_12(idx)) continue;                 // filtro checksum (descarta ~15/16)
    // construir la frase
    char m[120]; int mlen=0;
    for(int w=0;w<12;w++){ const char* wp=d_words[idx[w]]; for(int c=0; wp[c]; c++) m[mlen++]=wp[c]; if(w<11) m[mlen++]=' '; }
    u8 seed[64]; pbkdf2_bip39((const u8*)m,mlen,(const u8*)"mnemonic",8,2048,seed);
    for(int acc=0; acc<accounts; acc++){
      u8 priv[32]; derive_eth(seed,acc,priv);
      u64 k[4]; be32_to_fe(priv,k);
      u64 x[4],y[4]; scalar_mul_G(k,x,y);
      u8 pub[64]; fe_to_be32(x,pub); fe_to_be32(y,pub+32);
      u8 hsh[32]; keccak256(pub,64,hsh);
      u8 addr[20]; for(int i=0;i<20;i++) addr[i]=hsh[12+i];
      int ok=1;
      for(int i=0;i<pfx_n && ok;i++){ int nib=(i&1)?(addr[i/2]&0xF):(addr[i/2]>>4); if(nib!=pfx_nib[i]) ok=0; }
      for(int i=0;i<sfx_n && ok;i++){ int p=40-sfx_n+i; int nib=(p&1)?(addr[p/2]&0xF):(addr[p/2]>>4); if(nib!=sfx_nib[i]) ok=0; }
      if(ok){ int slot=atomicAdd(&g_result_count,1);
        if(slot<MAX_RESULTS){ g_result_acc[slot]=acc; for(int i=0;i<mlen;i++) g_results[slot][i]=m[i]; g_results[slot][mlen]=0; } }
    }
  }
}

// ===================== modo permutaciones (orden desconocido) =====================
__device__ __constant__ unsigned long long FACT12[12]={1ULL,1ULL,2ULL,6ULL,24ULL,120ULL,720ULL,5040ULL,40320ULL,362880ULL,3628800ULL,39916800ULL};
__device__ void lehmer12(unsigned long long lin, const int base[12], int out[12]){
  int avail[12];
  #pragma unroll
  for(int i=0;i<12;i++) avail[i]=base[i];
  int m=12;
  for(int i=0;i<12;i++){
    unsigned long long f=FACT12[11-i];
    int d=(int)(lin/f); lin%=f;
    out[i]=avail[d];
    for(int j=d;j<m-1;j++) avail[j]=avail[j+1];
    m--;
  }
}
__global__ void permute_kernel(unsigned long long start, unsigned long long end,
                               const int* base_idx, int accounts,
                               int pfx_n, const u8* pfx_nib, int sfx_n, const u8* sfx_nib,
                               u8* dump, unsigned long long dump_cap, int dump_mode){
  unsigned long long tid=(unsigned long long)blockIdx.x*blockDim.x+threadIdx.x;
  unsigned long long stride=(unsigned long long)gridDim.x*blockDim.x;
  for(unsigned long long lin=start+tid; lin<end; lin+=stride){
    int idx[12]; lehmer12(lin, base_idx, idx);
    if(!bip39_ok_12(idx)) continue;
    char m[120]; int mlen=0;
    for(int w=0;w<12;w++){ const char* wp=d_words[idx[w]]; for(int c=0; wp[c]; c++) m[mlen++]=wp[c]; if(w<11) m[mlen++]=' '; }
    u8 seed[64]; pbkdf2_bip39((const u8*)m,mlen,(const u8*)"mnemonic",8,2048,seed);
    for(int acc=0; acc<accounts; acc++){
      u8 priv[32]; derive_eth(seed,acc,priv);
      u64 k[4]; be32_to_fe(priv,k);
      u64 x[4],y[4]; scalar_mul_G(k,x,y);
      u8 pub[64]; fe_to_be32(x,pub); fe_to_be32(y,pub+32);
      u8 hsh[32]; keccak256(pub,64,hsh);
      u8 addr[20]; for(int i=0;i<20;i++) addr[i]=hsh[12+i];
      if(dump_mode){
        // volcar TODA direccion candidata: registro de 32 bytes [lin:8][acc:1][pad:3][addr:20]
        unsigned long long slot=atomicAdd(&g_dump_count,1ULL);
        if(slot<dump_cap){ u8* rec=dump+slot*32;
          for(int i=0;i<8;i++) rec[i]=(u8)(lin>>(8*i));
          rec[8]=(u8)acc; rec[9]=0; rec[10]=0; rec[11]=0;
          for(int i=0;i<20;i++) rec[12+i]=addr[i]; }
        continue;
      }
      int ok=1;
      for(int i=0;i<pfx_n && ok;i++){ int nib=(i&1)?(addr[i/2]&0xF):(addr[i/2]>>4); if(nib!=pfx_nib[i]) ok=0; }
      for(int i=0;i<sfx_n && ok;i++){ int p=40-sfx_n+i; int nib=(p&1)?(addr[p/2]&0xF):(addr[p/2]>>4); if(nib!=sfx_nib[i]) ok=0; }
      if(ok){ int slot=atomicAdd(&g_result_count,1);
        if(slot<MAX_RESULTS){ g_result_acc[slot]=acc; for(int i=0;i<mlen;i++) g_results[slot][i]=m[i]; g_results[slot][mlen]=0; } }
    }
  }
}

// ===================== host =====================
static int word_to_index(const char* w){ for(int i=0;i<2048;i++) if(!strcmp(w,BIP39_WORDS[i])) return i; return -1; }
static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }

static void upload_wordlist(){
  static char hw[2048][9];
  for(int i=0;i<2048;i++){ strncpy(hw[i],BIP39_WORDS[i],8); hw[i][8]=0; }
  cudaMemcpyToSymbol(d_words,hw,sizeof(hw));
}

// parsea patron de direccion -> nibbles prefijo/sufijo
static int parse_pattern(const char* s,u8* pfx,int* pn,u8* sfx,int* sn){
  const char* p=s; if(p[0]=='0'&&(p[1]=='x'||p[1]=='X')) p+=2;
  char buf[64]; int L=0; for(;p[L]&&L<63;L++) buf[L]=p[L]; buf[L]=0;
  char* dot=strstr(buf,"."); int np=0,ns=0;
  if(dot){ *dot=0; char* q=dot+1; while(*q=='.') q++;
    for(int i=0;buf[i];i++){ int v=hexval(buf[i]); if(v<0)return -1; pfx[np++]=v; }
    for(int i=0;q[i];i++){ int v=hexval(q[i]); if(v<0)return -1; sfx[ns++]=v; }
  } else { for(int i=0;buf[i];i++){ int v=hexval(buf[i]); if(v<0)return -1; pfx[np++]=v; } }
  *pn=np; *sn=ns; return 0;
}

int main(int argc,char**argv){
  const char* phrase=NULL; const char* addr=NULL; const char* outfile="hallazgos.txt";
  const char* dumpfile=NULL; int dump_mode=0;
  int accounts=1, blocks=4096, threads=256, selftest=0, permute=0;
  unsigned long long arg_start=0, arg_end=0; int has_range=0; int gpu_label=-1;
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"--phrase")&&i+1<argc) phrase=argv[++i];
    else if(!strcmp(argv[i],"--addr")&&i+1<argc) addr=argv[++i];
    else if(!strcmp(argv[i],"--out")&&i+1<argc) outfile=argv[++i];
    else if(!strcmp(argv[i],"--dump")&&i+1<argc){ dumpfile=argv[++i]; dump_mode=1; permute=1; }
    else if(!strcmp(argv[i],"--accounts")&&i+1<argc) accounts=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--blocks")&&i+1<argc) blocks=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--threads")&&i+1<argc) threads=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--start")&&i+1<argc){ arg_start=strtoull(argv[++i],0,10); has_range=1; }
    else if(!strcmp(argv[i],"--end")&&i+1<argc){ arg_end=strtoull(argv[++i],0,10); has_range=1; }
    else if(!strcmp(argv[i],"--gpu")&&i+1<argc) gpu_label=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--permute")) permute=1;
    else if(!strcmp(argv[i],"--selftest")) selftest=1;
  }
  upload_wordlist();

  if(selftest){
    if(permute){
      // todas las palabras de Hardhat, orden desconocido -> debe hallar 0xf39f..2266
      phrase="test test test test test test test test test test test junk";
      printf("== SELF-TEST PERMUTE (orden desconocido, frase Hardhat) ==\n");
    } else {
      // esconde 2 palabras de la frase Hardhat y confirma que las recupera -> 0xf39f..2266
      phrase="? test test test test test test test test test test ?";
      printf("== SELF-TEST (esconde 2 palabras de la frase Hardhat) ==\n");
    }
    addr="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"; accounts=1;
  }
  if(!phrase || (!addr && !dump_mode)){ printf("Uso:\n  Buscar (orden desconocido):  --permute --phrase \"w1..w12\" --addr 0x...\n  Volcar TODAS las candidatas: --dump candidatos.bin --phrase \"w1..w12\" [--accounts 2]\n"); return 0; }

  // parsear frase
  char tmp[512]; strncpy(tmp,phrase,511); tmp[511]=0;
  int fixed_idx[12]; int unknown_pos[12]; int K=0; int nwords=0;
  char* tok=strtok(tmp," ");
  while(tok && nwords<12){
    if(!strcmp(tok,"?")){ unknown_pos[K++]=nwords; fixed_idx[nwords]=0; }
    else { int wi=word_to_index(tok); if(wi<0){ printf("Palabra no valida: '%s'\n",tok); return 1; } fixed_idx[nwords]=wi; }
    nwords++; tok=strtok(NULL," ");
  }
  if(nwords!=12){ printf("La frase debe tener 12 palabras (tiene %d).\n",nwords); return 1; }
  if(permute){
    if(K>0){ printf("En modo --permute debes dar las 12 palabras conocidas, sin '?'.\n"); return 1; }
  } else {
    if(K<1){ printf("No hay palabras faltantes (pon ? donde falten, o usa --permute).\n"); return 1; }
  }

  // parsear direccion (en modo dump no hay direccion objetivo)
  u8 pfx[40],sfx[40]; int pn=0,sn=0;
  if(!dump_mode){
    if(parse_pattern(addr,pfx,&pn,sfx,&sn)<0){ printf("Direccion invalida.\n"); return 1; }
  }
  int known=pn+sn;
  unsigned long long total;
  if(permute) total=479001600ULL;                       // 12!
  else { total=1; for(int i=0;i<K;i++) total*=2048ULL; } // 2048^K
  double valid=(double)total/16.0;
  double fp = known<40 ? valid/pow(16.0,known) : 0.0;
  if(permute) printf("Modo PERMUTE: 12 palabras, orden desconocido = %llu permutaciones.\n", total);
  else printf("Faltan %d palabra(s); ", K);
  printf("Direccion conocida = %d hex (%s).\n", known, known>=40?"completa":"parcial");
  if(known<40) printf("Posibles falsos positivos: ~%.2g (se recolectan todos en %s).\n", fp, outfile);
  printf("Combinaciones: %llu  (checksum descarta ~15/16). Guardando en %s\n", total, outfile);

  // subir arrays a GPU
  int *d_unk,*d_fix; u8 *d_pfx,*d_sfx;
  cudaMalloc(&d_unk,K*sizeof(int)); cudaMemcpy(d_unk,unknown_pos,K*sizeof(int),cudaMemcpyHostToDevice);
  cudaMalloc(&d_fix,12*sizeof(int)); cudaMemcpy(d_fix,fixed_idx,12*sizeof(int),cudaMemcpyHostToDevice);
  cudaMalloc(&d_pfx,pn>0?pn:1); if(pn) cudaMemcpy(d_pfx,pfx,pn,cudaMemcpyHostToDevice);
  cudaMalloc(&d_sfx,sn>0?sn:1); if(sn) cudaMemcpy(d_sfx,sfx,sn,cudaMemcpyHostToDevice);
  int zero=0; cudaMemcpyToSymbol(g_result_count,&zero,sizeof(int));

  // buffer de volcado (modo --dump): registros de 32 bytes por candidata
  const unsigned long long DUMP_CAP = (1ULL<<23);   // 8.4M registros por tramo (margen)
  u8* d_dump=NULL; FILE* fdump=NULL; unsigned long long dumped_total=0;
  if(dump_mode){
    if(cudaMalloc(&d_dump, DUMP_CAP*32)!=cudaSuccess){ printf("No hay memoria GPU para el buffer de volcado.\n"); return 1; }
    fdump=fopen(dumpfile,"wb");
    if(!fdump){ printf("No se pudo abrir %s para escribir.\n", dumpfile); return 1; }
    printf("Modo VOLCADO: escribiendo TODAS las direcciones candidatas (cuentas 0..%d) en %s\n", accounts-1, dumpfile);
  }

  // rango asignado a esta instancia (multi-GPU); por defecto todo
  unsigned long long lo = has_range ? arg_start : 0ULL;
  unsigned long long hi = has_range ? arg_end   : total;
  if(hi>total) hi=total;
  unsigned long long span = (hi>lo)?(hi-lo):0;
  char tag[24]; if(gpu_label>=0) snprintf(tag,24,"[GPU%d] ",gpu_label); else tag[0]=0;

  // busqueda por tramos (progreso + guardado parcial)
  unsigned long long CHUNK= (1ULL<<25);
  int last_saved=0; FILE* fh=NULL;
  u8* hostdump=NULL;
  if(dump_mode){ hostdump=(u8*)malloc(DUMP_CAP*32); if(!hostdump){ printf("Sin memoria host para el volcado.\n"); return 1; } }
  time_t t0=time(NULL);
  for(unsigned long long s=lo; s<hi; s+=CHUNK){
    unsigned long long e = s+CHUNK; if(e>hi) e=hi;
    if(dump_mode){ unsigned long long z=0; cudaMemcpyToSymbol(g_dump_count,&z,sizeof(z)); }
    if(permute) permute_kernel<<<blocks,threads>>>(s,e,d_fix,accounts,pn,d_pfx,sn,d_sfx,d_dump,DUMP_CAP,dump_mode);
    else        search_kernel<<<blocks,threads>>>(s,e,K,d_unk,d_fix,accounts,pn,d_pfx,sn,d_sfx);
    cudaError_t err=cudaDeviceSynchronize();
    if(err!=cudaSuccess){ printf("CUDA error: %s\n",cudaGetErrorString(err)); return 1; }
    if(dump_mode){
      unsigned long long dc=0; cudaMemcpyFromSymbol(&dc,g_dump_count,sizeof(dc));
      if(dc>DUMP_CAP){ printf("\nAVISO: tramo lleno (%llu > %llu). Baja CHUNK o sube DUMP_CAP.\n",dc,DUMP_CAP); dc=DUMP_CAP; }
      if(dc>0){
        cudaMemcpy(hostdump, d_dump, dc*32, cudaMemcpyDeviceToHost);
        fwrite(hostdump, 32, dc, fdump); fflush(fdump);
        dumped_total += dc;
      }
      unsigned long long done=e-lo; double prog= span? 100.0*(double)done/(double)span : 100.0;
      double secs=(double)(time(NULL)-t0);
      printf("\r  %s%.2f%%  %llu/%llu  %.0fs  volcadas=%llu   ", tag,prog,done,span,secs,dumped_total); fflush(stdout);
      continue;
    }
    int cnt=0; cudaMemcpyFromSymbol(&cnt,g_result_count,sizeof(int));
    if(cnt>last_saved){
      int n=cnt>MAX_RESULTS?MAX_RESULTS:cnt;
      static char hr[MAX_RESULTS][120]; static int ha[MAX_RESULTS];
      cudaMemcpyFromSymbol(hr,g_results,sizeof(hr)); cudaMemcpyFromSymbol(ha,g_result_acc,sizeof(ha));
      if(!fh) fh=fopen(outfile,"a");
      for(int i=last_saved;i<n;i++){ printf("\n  *** COINCIDENCIA *** cuenta #%d  frase: %s\n",ha[i],hr[i]);
        if(fh){ fprintf(fh,"cuenta #%d\tfrase: %s\n",ha[i],hr[i]); fflush(fh);} }
      last_saved=cnt;
      if(selftest) break;   // en self-test, con un acierto basta
    }
    unsigned long long done=e-lo;
    double prog= span? 100.0*(double)done/(double)span : 100.0;
    double secs=(double)(time(NULL)-t0);
    double eta = (done>0 && secs>0) ? secs*((double)span-done)/(double)done : 0.0;
    char etabuf[32];
    if(eta<60) snprintf(etabuf,32,"%.0fs",eta);
    else if(eta<3600) snprintf(etabuf,32,"%.1fmin",eta/60);
    else if(eta<86400) snprintf(etabuf,32,"%.1fh",eta/3600);
    else snprintf(etabuf,32,"%.1fd",eta/86400);
    printf("\r  %s%.2f%%  %llu/%llu  %.0fs  ETA %s  hits=%d   ", tag,prog,done,span,secs,etabuf,cnt); fflush(stdout);
  }
  if(dump_mode){
    if(fdump) fclose(fdump);
    if(d_dump) cudaFree(d_dump);
    if(hostdump) free(hostdump);
    printf("\n\nVolcado terminado. %llu direcciones candidatas escritas en %s (registros de 32 bytes).\n", dumped_total, dumpfile);
    printf("Ahora cruzalas contra la lista de saldos con cruzar.py.\n");
    return 0;
  }
  if(fh) fclose(fh);
  int cnt=0; cudaMemcpyFromSymbol(&cnt,g_result_count,sizeof(int));
  printf("\n\nTerminado. %d coincidencia(s).\n", cnt);
  if(selftest){
    int ok = (cnt>=1);
    printf("RESULTADO: %s\n", ok?"TODO OK (recupero las palabras de Hardhat)":"FALLO");
    return ok?0:1;
  }
  if(cnt==0) printf("Revisa: palabras conocidas, patron de direccion, y la cuenta (--accounts).\n");
  else if(known<40 && cnt>1) printf("Varias coincidencias (direccion parcial): carga cada frase en una wallet y mira cual tiene fondos.\n");
  return 0;
}
