/* hashbench.c —— 计算文件 SHA-256 并计时（自包含，无外部依赖）
 * 用途：演示「本地源码 -> 云端 NDK 编译 -> 产物拉回手机原生运行」的完整闭环
 * 编译：aarch64-linux-android24-clang -O2 -o hashbench hashbench.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ── 紧凑 SHA-256 实现 ── */
typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; } sha256_t;

static const uint32_t K[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256_block(sha256_t *s, const unsigned char *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void sha256_init(sha256_t *s) {
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
    s->len = 0; s->n = 0;
}

static void sha256_update(sha256_t *s, const unsigned char *p, size_t len) {
    s->len += len;
    while (len) {
        size_t take = 64 - s->n; if (take > len) take = len;
        memcpy(s->buf + s->n, p, take);
        s->n += take; p += take; len -= take;
        if (s->n == 64) { sha256_block(s, s->buf); s->n = 0; }
    }
}

static void sha256_final(sha256_t *s, unsigned char *out) {
    uint64_t bits = s->len * 8;
    unsigned char pad = 0x80;
    sha256_update(s, &pad, 1);
    unsigned char z = 0;
    while (s->n != 56) sha256_update(s, &z, 1);
    unsigned char lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - i*8));
    sha256_update(s, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = s->h[i] >> 24; out[i*4+1] = s->h[i] >> 16;
        out[i*4+2] = s->h[i] >> 8;  out[i*4+3] = s->h[i];
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "用法: %s <文件>\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("打开失败"); return 1; }

    unsigned char *buf = malloc(1 << 20);
    if (!buf) { fprintf(stderr, "内存不足\n"); return 1; }

    sha256_t ctx; sha256_init(&ctx);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    size_t n; long total = 0;
    while ((n = fread(buf, 1, 1 << 20, f)) > 0) { sha256_update(&ctx, buf, n); total += (long)n; }

    unsigned char out[32]; sha256_final(&ctx, out);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fclose(f); free(buf);

    printf("文件:   %s\n", argv[1]);
    printf("大小:   %ld 字节\n", total);
    printf("SHA256: ");
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("耗时:   %.2f ms", ms);
    if (ms > 0 && total > 0)
        printf("  (%.1f MB/s)", total / 1048576.0 / (ms / 1000.0));
    printf("\n");
    return 0;
}
