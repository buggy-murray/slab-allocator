/*
 * bench.c — Benchmark: slab allocator vs malloc vs jemalloc
 *
 * Measures alloc/free throughput under single-threaded and multi-threaded
 * workloads with varying contention levels.
 *
 * Author: G.H. Murray
 * Date:   2026-02-16
 */

#define _GNU_SOURCE
#include "slab.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/*
 * jemalloc — loaded dynamically via dlopen/dlsym.
 * Debian's jemalloc overrides standard malloc/free (no je_ prefix),
 * so we must dlopen the .so and use function pointers to get separate symbols.
 */
#include <dlfcn.h>

static int je_available = 0;
static void *(*je_malloc_fn)(size_t) = NULL;
static void  (*je_free_fn)(void *) = NULL;

static void je_init(void)
{
    void *h = dlopen("libjemalloc.so.2", RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        fprintf(stderr, "bench: jemalloc not found, skipping (%s)\n", dlerror());
        return;
    }
    /* Debian's jemalloc exports standard names */
    je_malloc_fn = dlsym(h, "malloc");
    je_free_fn   = dlsym(h, "free");
    if (je_malloc_fn && je_free_fn) {
        je_available = 1;
        fprintf(stderr, "bench: jemalloc loaded via dlopen\n");
    } else {
        fprintf(stderr, "bench: jemalloc symbols not found\n");
    }
    /* intentionally not dlclose — keep symbols alive */
}

#define OBJ_SIZE    64
#define WARMUP_OPS  10000
#define BENCH_OPS   500000
#define MAX_THREADS 8

/* ── Timing helpers ─────────────────────────────────── */

static inline double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ── Single-threaded benchmarks ────────────────────── */

static void bench_slab_st(int ops)
{
    struct slab_cache *c = slab_cache_create("bench", OBJ_SIZE, 0, 0, NULL, NULL);
    void **ptrs = malloc(ops * sizeof(void *));

    /* Warmup */
    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        ptrs[i] = slab_alloc(c);
    }
    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        slab_free(c, ptrs[i]);
    }

    /* Alloc benchmark */
    double t0 = now_ms();
    for (int i = 0; i < ops; i++)
        ptrs[i] = slab_alloc(c);
    double t1 = now_ms();

    /* Free benchmark */
    double t2 = now_ms();
    for (int i = 0; i < ops; i++)
        slab_free(c, ptrs[i]);
    double t3 = now_ms();

    printf("  slab         alloc: %7.2f ms (%3.0f ns/op)  free: %7.2f ms (%3.0f ns/op)\n",
           t1 - t0, (t1 - t0) * 1e6 / ops,
           t3 - t2, (t3 - t2) * 1e6 / ops);

    free(ptrs);
    slab_cache_destroy(c);
}

static void bench_slab_nomag_st(int ops)
{
    struct slab_cache *c = slab_cache_create("bench_nomag", OBJ_SIZE, 0,
                                              SLAB_NO_MAGAZINES, NULL, NULL);
    void **ptrs = malloc(ops * sizeof(void *));

    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        ptrs[i] = slab_alloc(c); }
    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        slab_free(c, ptrs[i]); }

    double t0 = now_ms();
    for (int i = 0; i < ops; i++)
        ptrs[i] = slab_alloc(c);
    double t1 = now_ms();

    double t2 = now_ms();
    for (int i = 0; i < ops; i++)
        slab_free(c, ptrs[i]);
    double t3 = now_ms();

    printf("  slab(nomag)  alloc: %7.2f ms (%3.0f ns/op)  free: %7.2f ms (%3.0f ns/op)\n",
           t1 - t0, (t1 - t0) * 1e6 / ops,
           t3 - t2, (t3 - t2) * 1e6 / ops);

    free(ptrs);
    slab_cache_destroy(c);
}

static void bench_malloc_st(int ops)
{
    void **ptrs = malloc(ops * sizeof(void *));

    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        ptrs[i] = malloc(OBJ_SIZE); }
    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        free(ptrs[i]); }

    double t0 = now_ms();
    for (int i = 0; i < ops; i++)
        ptrs[i] = malloc(OBJ_SIZE);
    double t1 = now_ms();

    double t2 = now_ms();
    for (int i = 0; i < ops; i++)
        free(ptrs[i]);
    double t3 = now_ms();

    printf("  malloc       alloc: %7.2f ms (%3.0f ns/op)  free: %7.2f ms (%3.0f ns/op)\n",
           t1 - t0, (t1 - t0) * 1e6 / ops,
           t3 - t2, (t3 - t2) * 1e6 / ops);

    free(ptrs);
}

static void bench_jemalloc_st(int ops)
{
    void **ptrs = malloc(ops * sizeof(void *));

    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        ptrs[i] = je_malloc_fn(OBJ_SIZE); }
    for (int i = 0; i < WARMUP_OPS && i < ops; i++) {
        je_free_fn(ptrs[i]); }

    double t0 = now_ms();
    for (int i = 0; i < ops; i++)
        ptrs[i] = je_malloc_fn(OBJ_SIZE);
    double t1 = now_ms();

    double t2 = now_ms();
    for (int i = 0; i < ops; i++)
        je_free_fn(ptrs[i]);
    double t3 = now_ms();

    printf("  jemalloc     alloc: %7.2f ms (%3.0f ns/op)  free: %7.2f ms (%3.0f ns/op)\n",
           t1 - t0, (t1 - t0) * 1e6 / ops,
           t3 - t2, (t3 - t2) * 1e6 / ops);

    free(ptrs);
}

/* ── Multi-threaded churn benchmark ───────────────── */

struct mt_args {
    int ops_per_thread;
    struct slab_cache *cache;
    int use_malloc;   /* 0=slab, 1=malloc, 2=jemalloc */
    double elapsed_ms;
};

static void *mt_churn_worker(void *arg)
{
    struct mt_args *a = (struct mt_args *)arg;
    int ops = a->ops_per_thread;
    void *ptrs[64];

    double t0 = now_ms();
    for (int round = 0; round < ops; round++) {
        /* Allocate a batch */
        for (int i = 0; i < 64; i++) {
            if (a->use_malloc == 1)
                ptrs[i] = malloc(OBJ_SIZE);
            else if (a->use_malloc == 2)
                ptrs[i] = je_malloc_fn(OBJ_SIZE);
            else
                ptrs[i] = slab_alloc(a->cache);
        }
        /* Free them */
        for (int i = 0; i < 64; i++) {
            if (a->use_malloc == 1)
                free(ptrs[i]);
            else if (a->use_malloc == 2)
                je_free_fn(ptrs[i]);
            else
                slab_free(a->cache, ptrs[i]);
        }
    }
    double t1 = now_ms();
    a->elapsed_ms = t1 - t0;
    return NULL;
}

static void bench_mt_churn(int nthreads, int rounds_per_thread, const char *label, int use_malloc)
{
    struct slab_cache *c = NULL;
    if (!use_malloc)
        c = slab_cache_create("mt_bench", OBJ_SIZE, 0, 0, NULL, NULL);

    pthread_t threads[MAX_THREADS];
    struct mt_args args[MAX_THREADS];

    for (int i = 0; i < nthreads; i++) {
        args[i].ops_per_thread = rounds_per_thread;
        args[i].cache = c;
        args[i].use_malloc = use_malloc;
        args[i].elapsed_ms = 0;
    }

    double t0 = now_ms();
    for (int i = 0; i < nthreads; i++)
        pthread_create(&threads[i], NULL, mt_churn_worker, &args[i]);
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);
    double t1 = now_ms();

    long total_ops = (long)nthreads * rounds_per_thread * 128; /* 64 alloc + 64 free */
    printf("  %-12s %2d threads: %8.2f ms  (%3.0f ns/op, %ld total ops)\n",
           label, nthreads, t1 - t0,
           (t1 - t0) * 1e6 / total_ops, total_ops);

    if (c)
        slab_cache_destroy(c);
}

/* ── Steady-state benchmark (realistic workload) ── */

static void bench_steady_state(int ops, int pool_size, const char *label,
                                struct slab_cache *cache, int use_malloc)
{
    void **pool = calloc(pool_size, sizeof(void *));

    /* Fill pool */
    for (int i = 0; i < pool_size; i++) {
        pool[i] = use_malloc ? malloc(OBJ_SIZE) : slab_alloc(cache);
    }

    /* Steady-state: free one, alloc one */
    double t0 = now_ms();
    for (int i = 0; i < ops; i++) {
        int idx = i % pool_size;
        if (use_malloc) {
            free(pool[idx]);
            pool[idx] = malloc(OBJ_SIZE);
        } else {
            slab_free(cache, pool[idx]);
            pool[idx] = slab_alloc(cache);
        }
    }
    double t1 = now_ms();

    printf("  %-12s %7.2f ms (%3.0f ns/roundtrip)\n",
           label, t1 - t0, (t1 - t0) * 1e6 / ops);

    for (int i = 0; i < pool_size; i++) {
        if (use_malloc) free(pool[i]);
        else slab_free(cache, pool[i]);
    }
    free(pool);
}

/* ── Main ─────────────────────────────────────────── */

int main(void)
{
    je_init();

    printf("Slab Allocator Benchmark (obj_size=%d)\n", OBJ_SIZE);
    printf("========================================\n\n");

    printf("Single-threaded (%d ops):\n", BENCH_OPS);
    bench_slab_st(BENCH_OPS);
    bench_slab_nomag_st(BENCH_OPS);
    bench_malloc_st(BENCH_OPS);
    if (je_available)
        bench_jemalloc_st(BENCH_OPS);
    else
        printf("  jemalloc     (not available)\n");

    printf("\nSteady-state (free+alloc, 1000 live objects, %d rounds):\n", BENCH_OPS);
    {
        struct slab_cache *c = slab_cache_create("steady", OBJ_SIZE, 0, 0, NULL, NULL);
        bench_steady_state(BENCH_OPS, 1000, "slab", c, 0);
        slab_cache_destroy(c);
    }
    bench_steady_state(BENCH_OPS, 1000, "malloc", NULL, 1);

    printf("\nMulti-threaded churn (64 alloc + 64 free per round):\n");
    for (int t = 1; t <= MAX_THREADS; t *= 2) {
        int rounds = 50000 / t;
        bench_mt_churn(t, rounds, "slab", 0);
        bench_mt_churn(t, rounds, "malloc", 1);
        if (je_available)
            bench_mt_churn(t, rounds, "jemalloc", 2);
        printf("\n");
    }

    return 0;
}
