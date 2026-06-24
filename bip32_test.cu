// =============================================================================
// bip32_test.cu  -  Bloque 3: secp256k1 + BIP32 en CUDA.
//   seed BIP39 (64 bytes) -> clave privada por la ruta MetaMask m/44'/60'/0'/0/0.
//   Incluye SHA-512 + HMAC-SHA512 (general) + secp256k1 (campo, escalar, compresion) + BIP32.
//
// Compilar: nvcc -O3 -arch=sm_120 bip32_test.cu -o bip32_test
// Probar:   ./bip32_test --selftest      (debe decir TODO OK)
// =============================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>
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
  u64 w[80];
  #pragma unroll
  for(int i=0;i<16;i++) w[i]=ld_be64(block+i*8);
  #pragma unroll
  for(int i=16;i<80;i++) w[i]=SSIG1(w[i-2])+w[i-7]+SSIG0(w[i-15])+w[i-16];
  u64 a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  #pragma unroll
  for(int i=0;i<80;i++){ u64 t1=h+BSIG1(e)+CHf(e,f,g)+K512[i]+w[i]; u64 t2=BSIG0(a)+MAJ(a,b,c); h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
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

// ---------------- self-test ----------------
__global__ void selftest_kernel(u8* out){
  // 1) master priv del vector BIP32 (seed 000102..0f)
  u8 seed1[16]; for(int i=0;i<16;i++) seed1[i]=i;
  // pero master usa seed de 64? El vector BIP32 usa el seed tal cual (16 bytes). Adaptamos:
  u8 I[64]; hmac_sha512((const u8*)"Bitcoin seed",12,seed1,16,I);
  for(int i=0;i<32;i++) out[i]=I[i];            // master priv (32 bytes)
  // 2) Hardhat: seed BIP39 conocido -> m/44'/60'/0'/0/0 -> priv
  // seed Hardhat (64 bytes) hardcodeado (= PBKDF2 validado en Bloque 2)
  const u8 seedH[64]={
    0x9d,0xfc,0x3c,0x64,0xc2,0xf8,0xbe,0xde,0x15,0x33,0xb6,0xa7,0x9f,0x85,0x70,0xe5,
    0x94,0x3e,0x0b,0x8f,0xd1,0xcf,0x77,0x10,0x7a,0xdf,0x7b,0x72,0xce,0xf4,0x21,0x85,
    0xd5,0x64,0xa3,0xae,0xe2,0x4c,0xab,0x43,0xf8,0x0e,0x3c,0x45,0x38,0x08,0x7d,0x70,
    0xfc,0x82,0x4e,0xab,0xba,0xd5,0x96,0xa2,0x3c,0x97,0xb6,0xee,0x83,0x22,0xcc,0xc0};
  u8 priv[32]; derive_eth(seedH,0,priv);
  for(int i=0;i<32;i++) out[32+i]=priv[i];
  // 3) scalar_mul(1)=G y scalar_mul(2)
  u64 one[4]={1,0,0,0}, x[4],y[4]; scalar_mul_G(one,x,y); fe_to_be32(x,out+64); fe_to_be32(y,out+96);
  u64 two[4]={2,0,0,0}; scalar_mul_G(two,x,y); fe_to_be32(x,out+128); fe_to_be32(y,out+160);
}
static void hexs(const u8*b,int n,char*s){ for(int i=0;i<n;i++) sprintf(s+i*2,"%02x",b[i]); }
int main(int argc,char**argv){
  bool st=false; for(int i=1;i<argc;i++) if(!strcmp(argv[i],"--selftest")) st=true;
  if(!st){ printf("Uso: ./bip32_test --selftest\n"); return 0; }
  u8* d; cudaMalloc(&d,192);
  selftest_kernel<<<1,1>>>(d);
  cudaError_t e=cudaDeviceSynchronize();
  if(e!=cudaSuccess){ printf("CUDA error: %s\n",cudaGetErrorString(e)); return 1; }
  u8 h[192]; cudaMemcpy(h,d,192,cudaMemcpyDeviceToHost);
  char master[65],priv[65],gx[65],gy[65],g2x[65],g2y[65];
  hexs(h,32,master); hexs(h+32,32,priv); hexs(h+64,32,gx); hexs(h+96,32,gy); hexs(h+128,32,g2x); hexs(h+160,32,g2y);
  const char* EM="e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
  const char* EP="ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
  const char* EGX="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const char* EG2="c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
  bool o1=!strcmp(master,EM),o2=!strcmp(priv,EP),o3=!strcmp(gx,EGX),o4=!strcmp(g2x,EG2);
  printf("== SELF-TEST secp256k1 + BIP32 (GPU) ==\n");
  printf("  scalar*1 == G        : %s\n", o3?"PASS":"FAIL");
  printf("  scalar*2 == 2G       : %s\n", o4?"PASS":"FAIL");
  printf("  BIP32 master vector  : %s\n", o1?"PASS":"FAIL");
  printf("  Hardhat m/44'/60'.. : %s\n", o2?"PASS":"FAIL");
  if(!o2){ printf("    got: %s\n    exp: %s\n", priv, EP); }
  printf("  RESULTADO            : %s\n", (o1&&o2&&o3&&o4)?"TODO OK":"FALLO");
  cudaFree(d);
  return (o1&&o2&&o3&&o4)?0:1;
}
