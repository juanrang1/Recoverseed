// =============================================================================
// pbkdf2_test.cu  -  Bloque 2: HMAC-SHA512 + PBKDF2(2048) en CUDA.
//   Convierte (mnemonic, salt) -> seed BIP39 de 64 bytes. Reusa SHA-512 (Bloque 1).
//   Optimizacion: precalcula los estados ipad/opad (la clave no cambia en 2048 vueltas).
//
// Compilar: nvcc -O3 -arch=sm_120 pbkdf2_test.cu -o pbkdf2_test
// Probar:   ./pbkdf2_test --selftest      (debe decir TODO OK)
// =============================================================================
#include <cstdio>
#include <cstring>
#include <cstdint>
typedef unsigned long long u64; typedef unsigned char u8;

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
__device__ __forceinline__ u64 ld_be64(const u8* p){
  return ((u64)p[0]<<56)|((u64)p[1]<<48)|((u64)p[2]<<40)|((u64)p[3]<<32)
       |((u64)p[4]<<24)|((u64)p[5]<<16)|((u64)p[6]<<8)|((u64)p[7]); }
__device__ __forceinline__ void st_be64(u8* p,u64 v){
  p[0]=v>>56;p[1]=v>>48;p[2]=v>>40;p[3]=v>>32;p[4]=v>>24;p[5]=v>>16;p[6]=v>>8;p[7]=v; }

__device__ void sha512_transform(u64 st[8], const u8* block){
  u64 w[80];
  #pragma unroll
  for(int i=0;i<16;i++) w[i]=ld_be64(block+i*8);
  #pragma unroll
  for(int i=16;i<80;i++) w[i]=SSIG1(w[i-2])+w[i-7]+SSIG0(w[i-15])+w[i-16];
  u64 a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  #pragma unroll
  for(int i=0;i<80;i++){
    u64 t1=h+BSIG1(e)+CHf(e,f,g)+K512[i]+w[i];
    u64 t2=BSIG0(a)+MAJ(a,b,c);
    h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}

// Finaliza desde un estado: procesa 'tail' (<128) + padding; total_len = bytes totales del mensaje
__device__ void finalize_from_state(u64 st[8], const u8* tail, int taillen, u64 total_len, u8 out[64]){
  u64 s[8];
  #pragma unroll
  for(int i=0;i<8;i++) s[i]=st[i];
  u8 buf[256];
  for(int j=0;j<taillen;j++) buf[j]=tail[j];
  buf[taillen]=0x80;
  int padlen=taillen+1;
  int total=(padlen<=112)?128:256;
  for(int j=padlen;j<total-16;j++) buf[j]=0;
  u64 bits=total_len*8;
  st_be64(buf+total-16, (total_len>>61));  // parte alta de 128 bits
  st_be64(buf+total-8,  bits);
  for(int b=0;b<total;b+=128) sha512_transform(s, buf+b);
  #pragma unroll
  for(int k=0;k<8;k++) st_be64(out+k*8, s[k]);
}

// SHA-512 one-shot (solo se usa si la clave > 128 bytes)
__device__ void sha512(const u8* msg, u64 len, u8 out[64]){
  u64 s[8];
  #pragma unroll
  for(int i=0;i<8;i++) s[i]=H0[i];
  u64 i=0;
  while(len-i>=128){ sha512_transform(s,msg+i); i+=128; }
  finalize_from_state(s, msg+i, (int)(len-i), len, out);
}

// HMAC-SHA512: precalcula estados ipad/opad para una clave fija
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
// HMAC de un mensaje (procesa bloques completos del msg + finaliza)
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

// PBKDF2-HMAC-SHA512, dklen=64 (1 bloque), c iteraciones -> seed BIP39
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

// ---------------- self-test en GPU ----------------
__global__ void selftest_kernel(u8* out){
  pbkdf2_bip39((const u8*)"password",8,(const u8*)"salt",4,1, out);       // caso c=1
  pbkdf2_bip39((const u8*)"password",8,(const u8*)"salt",4,2, out+64);     // caso c=2
  const char* m="test test test test test test test test test test test junk";
  pbkdf2_bip39((const u8*)m,59,(const u8*)"mnemonic",8,2048, out+128);     // seed BIP39 real
}
static void hex(const u8* b,int n,char* s){ for(int i=0;i<n;i++) sprintf(s+i*2,"%02x",b[i]); }

int main(int argc,char**argv){
  bool st=false; for(int i=1;i<argc;i++) if(!strcmp(argv[i],"--selftest")) st=true;
  if(!st){ printf("Uso: ./pbkdf2_test --selftest\n"); return 0; }
  u8* dout; cudaMalloc(&dout,192);
  selftest_kernel<<<1,1>>>(dout);
  cudaError_t e=cudaDeviceSynchronize();
  if(e!=cudaSuccess){ printf("CUDA error: %s\n",cudaGetErrorString(e)); return 1; }
  u8 h[192]; cudaMemcpy(h,dout,192,cudaMemcpyDeviceToHost);
  char a[129],b[129],c[129]; hex(h,64,a); hex(h+64,64,b); hex(h+128,64,c);
  const char* E1="867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce";
  const char* E2="e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e";
  const char* E3="9dfc3c64c2f8bede1533b6a79f8570e5943e0b8fd1cf77107adf7b72cef42185d564a3aee24cab43f80e3c4538087d70fc824eabbad596a23c97b6ee8322ccc0";
  bool o1=!strcmp(a,E1),o2=!strcmp(b,E2),o3=!strcmp(c,E3);
  printf("== SELF-TEST PBKDF2-HMAC-SHA512 (GPU) ==\n");
  printf("  PBKDF2 c=1     : %s\n", o1?"PASS":"FAIL");
  printf("  PBKDF2 c=2     : %s\n", o2?"PASS":"FAIL");
  printf("  Seed BIP39 2048: %s\n", o3?"PASS":"FAIL");
  if(!o3){ printf("    got: %s\n    exp: %s\n", c, E3); }
  printf("  RESULTADO      : %s\n", (o1&&o2&&o3)?"TODO OK":"FALLO");
  cudaFree(dout);
  return (o1&&o2&&o3)?0:1;
}
