// cpu_bench.c —— 纯计算基准（不依赖平台特性，x86-64 / aarch64 通用）
// 测四项：整数 ALU、双精度浮点、纯软件 SHA-256、内存带宽
// 编译：clang -O2 -o cpu_bench cpu_bench.c -lpthread
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

/* ── 1. 整数 ALU：依赖链 + 独立乘加 ── */
static volatile uint64_t int_sink;
static double bench_int(void) {
    uint64_t a = 0x123456789abcdefULL, b = 0xfedcba987654321ULL;
    volatile uint64_t c = 1;
    double t0 = now();
    for (uint64_t i = 0; i < 100000000ULL; i++) {
        a = a * 6364136223846793005ULL + 1442695040888963407ULL;  // LCG 依赖链
        b = (b ^ (b >> 17)) + i;
        c ^= (a >> 13) ^ (b << 7);
    }
    int_sink = c;
    return now() - t0;
}

/* ── 2. 双精度浮点：乘法 + 加法，可流水 ── */
static volatile double fp_sink;
static double bench_fp(void) {
    double x[8];
    for (int i = 0; i < 8; i++) x[i] = 1.0 + i * 0.1;
    volatile double s = 0;
    double t0 = now();
    for (uint64_t i = 0; i < 50000000ULL; i++) {
        for (int k = 0; k < 8; k++) x[k] = x[k] * 1.0000001 + 0.0000001;
        s += x[0] + x[1] + x[2] + x[3] + x[4] + x[5] + x[6] + x[7];
    }
    fp_sink = s;
    return now() - t0;
}

/* ── 3. 纯软件 SHA-256（避免硬件加速差异）── */
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
static void sha_block(sha256_t *s, const unsigned char *p) {
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
static void sha_init(sha256_t *s) {
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
    s->len = 0; s->n = 0;
}
static void sha_upd(sha256_t *s, const unsigned char *p, size_t len) {
    s->len += len;
    while (len) {
        size_t take = 64 - s->n; if (take > len) take = len;
        memcpy(s->buf + s->n, p, take);
        s->n += take; p += take; len -= take;
        if (s->n == 64) { sha_block(s, s->buf); s->n = 0; }
    }
}
static void sha_fin(sha256_t *s, unsigned char *out) {
    uint64_t bits = s->len * 8;
    unsigned char pad = 0x80, z = 0, lb[8];
    sha_upd(s, &pad, 1);
    while (s->n != 56) sha_upd(s, &z, 1);
    for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - i*8));
    sha_upd(s, lb, 8);
    for (int i = 0; i < 8; i++) { out[i*4]=s->h[i]>>24; out[i*4+1]=s->h[i]>>16;
                                  out[i*4+2]=s->h[i]>>8;  out[i*4+3]=s->h[i]; }
}

static double bench_sha(size_t bytes) {
    unsigned char *buf = malloc(bytes);
    memset(buf, 0xab, bytes);
    sha256_t s; sha_init(&s);
    double t0 = now();
    sha_upd(&s, buf, bytes);
    unsigned char o[32]; sha_fin(&s, o);
    double dt = now() - t0;
    free(buf);
    int_sink ^= o[0];
    return dt;
}

/* ── 4. 内存带宽：顺序读 + 写 ── */
static double bench_mem(size_t bytes) {
    unsigned char *a = malloc(bytes), *b = malloc(bytes);
    memset(a, 1, bytes); memset(b, 2, bytes);
    uint64_t chk = 0;
    double t0 = now();
    for (int rep = 0; rep < 8; rep++) {
        const uint64_t *pa = (const uint64_t *)a;
        uint64_t *pb = (uint64_t *)b;
        for (size_t i = 0; i < bytes / 8; i += 8) {
            pb[i+0]=pa[i+0]; pb[i+1]=pa[i+1]; pb[i+2]=pa[i+2]; pb[i+3]=pa[i+3];
            pb[i+4]=pa[i+4]; pb[i+5]=pa[i+5]; pb[i+6]=pa[i+6]; pb[i+7]=pa[i+7];
        }
        chk += pb[rep];           /* 让写入不可消除 */
    }
    double dt = now() - t0;
    int_sink ^= chk;
    free(a); free(b);
    return dt;
}

/* ── 多线程：N 个线程各跑整数基准 ── */
#define MT_ITERS 400000000ULL   /* 每线程 4e8 次，单线程约 1.2s，远超线程创建开销 */
static void *worker(void *arg) {
    (void)arg;
    uint64_t a = 0xabcdef1234567890ULL;
    volatile uint64_t c = 1;
    for (uint64_t i = 0; i < MT_ITERS; i++) {
        a = a * 6364136223846793005ULL + 1442695040888963407ULL;
        c ^= a >> 11;
    }
    int_sink ^= c;
    return NULL;
}
static double bench_mt(int nthreads) {
    pthread_t *t = calloc(nthreads, sizeof(pthread_t));
    double t0 = now();
    for (int i = 0; i < nthreads; i++) pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(t[i], NULL);
    double dt = now() - t0;
    free(t);
    return dt;
}

int main(int argc, char **argv) {
    int mt_max = argc > 1 ? atoi(argv[1]) : 1;
    printf("=== cpu_bench ===\n");
    printf("单线程:\n");
    double ti = bench_int();
    printf("  整数 ALU   1e8 迭代   %7.3f s\n", ti);
    double tf = bench_fp();
    printf("  浮点 8x    5e7 迭代   %7.3f s\n", tf);
    size_t sb = 64u << 20;
    double ts = bench_sha(sb);
    printf("  软 SHA256  %zu MB      %7.3f s  -> %8.1f MB/s\n", sb>>20, ts, (sb/1048576.0)/ts);
    size_t mb = 256u << 20;
    double tm = bench_mem(mb);
    printf("  内存 8x%zuMB 拷贝 %7.3f s  -> %8.1f MB/s\n", mb>>20, tm, (mb*8/1048576.0)/tm);
    printf("多线程 (每线程 %llu 次 LCG):\n", (unsigned long long)MT_ITERS);
    double base = 0, dt;
    for (int n = 1; n <= mt_max; n *= 2) {
        dt = bench_mt(n);
        if (n == 1) base = dt;
        printf("  %2d 线程   %7.3f s   加速比 %.2fx   吞吐 %6.1f Mops/s\n",
               n, dt, base / dt, (double)n * MT_ITERS / dt / 1e6);
    }
    return 0;
}
