/*
 * main.c — Test harness for the slab allocator
 *
 * v0.6: Added multithreaded tests for magazine caching.
 *
 * Author: G.H. Murray
 * Date:   2026-02-16
 */

#define _GNU_SOURCE
#include "slab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>

/* ── Test structures ─────────────────────────────────────────── */

struct task {
    uint32_t pid;
    char     name[28];
};

struct inode {
    uint64_t ino;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    char     padding[32];
};

/* ── Constructor/Destructor examples ─────────────────────────── */

static void task_ctor(void *obj)
{
    struct task *t = obj;
    t->pid = 0;
    memset(t->name, 0, sizeof(t->name));
}

/* ── Tests ───────────────────────────────────────────────────── */

static void test_basic_alloc_free(void)
{
    printf("=== test_basic_alloc_free ===\n");

    struct slab_cache *tc = slab_cache_create("task_cache",
        sizeof(struct task), 0, 0, task_ctor, NULL);
    assert(tc != NULL);

    struct task *t1 = slab_alloc(tc);
    struct task *t2 = slab_alloc(tc);
    struct task *t3 = slab_alloc(tc);

    assert(t1 && t2 && t3);
    assert(t1 != t2 && t2 != t3);
    assert(t1->pid == 0);

    t1->pid = 1;
    snprintf(t1->name, sizeof(t1->name), "init");
    t2->pid = 2;
    snprintf(t2->name, sizeof(t2->name), "kthreadd");

    slab_cache_stats(tc);

    slab_free(tc, t2);
    struct task *t4 = slab_alloc(tc);
    assert(t4 != NULL);
    printf("  t2 was %p, t4 is %p (reuse=%s)\n", (void*)t2, (void*)t4,
           t4 == t2 ? "yes" : "no");

    slab_free(tc, t1);
    slab_free(tc, t3);
    slab_free(tc, t4);

    slab_cache_stats(tc);
    slab_cache_destroy(tc);
    printf("  PASSED\n\n");
}

static void test_slab_growth(void)
{
    printf("=== test_slab_growth ===\n");

    struct slab_cache *ic = slab_cache_create("inode_cache",
        sizeof(struct inode), 0, 0, NULL, NULL);
    assert(ic != NULL);

    printf("  inode size=%zu, objs_per_slab=%u, slab_size=%zu\n",
           ic->obj_size, ic->objs_per_slab, ic->slab_size);

    uint16_t count = ic->objs_per_slab * 3;
    void **ptrs = malloc(sizeof(void *) * count);
    assert(ptrs);

    for (uint16_t i = 0; i < count; i++) {
        ptrs[i] = slab_alloc(ic);
        assert(ptrs[i] != NULL);
        ((struct inode *)ptrs[i])->ino = i + 1;
    }

    printf("  Allocated %u inodes across %u slabs\n", count, ic->nr_slabs);
    slab_cache_stats(ic);

    for (uint16_t i = 0; i < count; i++)
        slab_free(ic, ptrs[i]);

    printf("  After freeing all:\n");
    slab_cache_stats(ic);

    free(ptrs);
    slab_cache_destroy(ic);
    printf("  PASSED\n\n");
}

static void test_performance(void)
{
    printf("=== test_performance (single-threaded, magazines) ===\n");

    struct slab_cache *cache = slab_cache_create("perf_cache", 64, 0, 0, NULL, NULL);
    assert(cache);

    const int N = 100000;
    void **ptrs = malloc(sizeof(void *) * N);
    assert(ptrs);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        ptrs[i] = slab_alloc(cache);
        assert(ptrs[i]);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double alloc_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                      (t1.tv_nsec - t0.tv_nsec) / 1e6;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++)
        slab_free(cache, ptrs[i]);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double free_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                     (t1.tv_nsec - t0.tv_nsec) / 1e6;

    printf("  %d allocs: %.2f ms (%.0f ns/alloc)\n",
           N, alloc_ms, alloc_ms * 1e6 / N);
    printf("  %d frees:  %.2f ms (%.0f ns/free)\n",
           N, free_ms, free_ms * 1e6 / N);

    free(ptrs);
    slab_cache_destroy(cache);
    printf("  PASSED\n\n");
}

static void test_performance_no_mag(void)
{
    printf("=== test_performance (single-threaded, NO magazines) ===\n");

    struct slab_cache *cache = slab_cache_create("perf_nomag", 64, 0,
        SLAB_NO_MAGAZINES, NULL, NULL);
    assert(cache);

    const int N = 100000;
    void **ptrs = malloc(sizeof(void *) * N);
    assert(ptrs);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        ptrs[i] = slab_alloc(cache);
        assert(ptrs[i]);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double alloc_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                      (t1.tv_nsec - t0.tv_nsec) / 1e6;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++)
        slab_free(cache, ptrs[i]);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double free_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                     (t1.tv_nsec - t0.tv_nsec) / 1e6;

    printf("  %d allocs: %.2f ms (%.0f ns/alloc)\n",
           N, alloc_ms, alloc_ms * 1e6 / N);
    printf("  %d frees:  %.2f ms (%.0f ns/free)\n",
           N, free_ms, free_ms * 1e6 / N);

    free(ptrs);
    slab_cache_destroy(cache);
    printf("  PASSED\n\n");
}

static void test_shrink(void)
{
    printf("=== test_shrink ===\n");

    /* Use SLAB_NO_MAGAZINES so objects go directly to slab */
    struct slab_cache *sc = slab_cache_create("shrink_cache",
        64, 0, SLAB_NO_MAGAZINES, NULL, NULL);
    assert(sc != NULL);

    uint16_t count = sc->objs_per_slab * 3;
    void **ptrs = malloc(sizeof(void *) * count);
    assert(ptrs);

    for (uint16_t i = 0; i < count; i++) {
        ptrs[i] = slab_alloc(sc);
        assert(ptrs[i]);
    }
    printf("  Allocated %u objects across %u slabs\n", count, sc->nr_slabs);

    for (uint16_t i = 0; i < count; i++)
        slab_free(sc, ptrs[i]);

    printf("  After free: %u slabs total, %u cached free\n",
           sc->nr_slabs, sc->nr_free);
    assert(sc->nr_free > 0);

    uint32_t released = slab_cache_shrink(sc);
    printf("  Shrink released %u slabs, %u remain\n", released, sc->nr_slabs);
    assert(sc->nr_free == 0);

    free(ptrs);
    slab_cache_destroy(sc);
    printf("  PASSED\n\n");
}

static void test_debug_redzone(void)
{
    printf("=== test_debug_redzone ===\n");

    struct slab_cache *dc = slab_cache_create("debug_cache",
        sizeof(struct task), 0, SLAB_DEBUG | SLAB_NO_MAGAZINES, task_ctor, NULL);
    assert(dc != NULL);

    printf("  obj_size=%zu (raw=%zu, with red zones + poison)\n",
           dc->obj_size, dc->raw_size);

    struct task *t1 = slab_alloc(dc);
    assert(t1 != NULL);
    assert(t1->pid == 0);

    t1->pid = 42;
    snprintf(t1->name, sizeof(t1->name), "debug_test");

    slab_free(dc, t1);

    struct task *t2 = slab_alloc(dc);
    assert(t2 != NULL);

    slab_free(dc, t2);
    slab_cache_destroy(dc);
    printf("  PASSED (no red zone or poison violations)\n\n");
}

static void test_debug_overflow_detect(void)
{
    printf("=== test_debug_overflow_detect ===\n");

    struct slab_cache *dc = slab_cache_create("overflow_cache",
        32, 0, SLAB_RED_ZONE | SLAB_NO_MAGAZINES, NULL, NULL);
    assert(dc != NULL);

    char *obj = slab_alloc(dc);
    assert(obj != NULL);

    memset(obj, 'A', 32);
    obj[32] = 0xFF;  /* Corrupt trailing red zone */

    printf("  (Expect RED ZONE OVERFLOW warning below)\n");
    slab_free(dc, obj);

    slab_cache_destroy(dc);
    printf("  PASSED (overflow detected)\n\n");
}

/* ── Multithreaded tests ─────────────────────────────────────── */

struct mt_args {
    struct slab_cache *cache;
    int ops_per_thread;
    int thread_id;
};

static void *thread_alloc_free(void *arg)
{
    struct mt_args *a = (struct mt_args *)arg;
    void **ptrs = malloc(sizeof(void *) * a->ops_per_thread);
    assert(ptrs);

    /* Allocate all */
    for (int i = 0; i < a->ops_per_thread; i++) {
        ptrs[i] = slab_alloc(a->cache);
        assert(ptrs[i]);
        /* Write thread_id to detect cross-thread corruption */
        *(int *)ptrs[i] = a->thread_id;
    }

    /* Verify no corruption */
    for (int i = 0; i < a->ops_per_thread; i++)
        assert(*(int *)ptrs[i] == a->thread_id);

    /* Free all */
    for (int i = 0; i < a->ops_per_thread; i++)
        slab_free(a->cache, ptrs[i]);

    free(ptrs);
    return NULL;
}

static void *thread_churn(void *arg)
{
    struct mt_args *a = (struct mt_args *)arg;

    /* Rapidly alloc/free in small batches to stress magazines */
    for (int round = 0; round < a->ops_per_thread; round++) {
        void *p1 = slab_alloc(a->cache);
        void *p2 = slab_alloc(a->cache);
        void *p3 = slab_alloc(a->cache);
        assert(p1 && p2 && p3);
        *(int *)p1 = a->thread_id;
        *(int *)p2 = a->thread_id;
        *(int *)p3 = a->thread_id;
        slab_free(a->cache, p2);
        slab_free(a->cache, p1);
        slab_free(a->cache, p3);
    }
    return NULL;
}

static void test_multithreaded_basic(void)
{
    printf("=== test_multithreaded_basic ===\n");

    const int NTHREADS = 4;
    const int OPS = 10000;

    struct slab_cache *cache = slab_cache_create("mt_cache", 64, 0, 0, NULL, NULL);
    assert(cache);

    pthread_t threads[NTHREADS];
    struct mt_args args[NTHREADS];

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < NTHREADS; i++) {
        args[i].cache = cache;
        args[i].ops_per_thread = OPS;
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, thread_alloc_free, &args[i]);
    }

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(threads[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                (t1.tv_nsec - t0.tv_nsec) / 1e6;

    printf("  %d threads × %d ops = %d total ops in %.2f ms\n",
           NTHREADS, OPS, NTHREADS * OPS, ms);
    printf("  %.0f ns/op (alloc+free, %d threads)\n",
           ms * 1e6 / (NTHREADS * OPS * 2), NTHREADS);

    slab_cache_stats(cache);
    slab_cache_destroy(cache);
    printf("  PASSED\n\n");
}

static void test_multithreaded_churn(void)
{
    printf("=== test_multithreaded_churn ===\n");

    const int NTHREADS = 8;
    const int ROUNDS = 50000;

    struct slab_cache *cache = slab_cache_create("churn_cache", 128, 0, 0, NULL, NULL);
    assert(cache);

    pthread_t threads[NTHREADS];
    struct mt_args args[NTHREADS];

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < NTHREADS; i++) {
        args[i].cache = cache;
        args[i].ops_per_thread = ROUNDS;
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, thread_churn, &args[i]);
    }

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(threads[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                (t1.tv_nsec - t0.tv_nsec) / 1e6;

    int total_ops = NTHREADS * ROUNDS * 6;  /* 3 allocs + 3 frees per round */
    printf("  %d threads × %d rounds × 6 ops = %d total ops in %.2f ms\n",
           NTHREADS, ROUNDS, total_ops, ms);
    printf("  %.0f ns/op (%d threads)\n",
           ms * 1e6 / total_ops, NTHREADS);

    slab_cache_stats(cache);
    slab_cache_destroy(cache);
    printf("  PASSED\n\n");
}

static void test_multithreaded_no_mag(void)
{
    printf("=== test_multithreaded_no_mag (contention baseline) ===\n");

    const int NTHREADS = 4;
    const int OPS = 10000;

    struct slab_cache *cache = slab_cache_create("mt_nomag", 64, 0,
        SLAB_NO_MAGAZINES, NULL, NULL);
    assert(cache);

    pthread_t threads[NTHREADS];
    struct mt_args args[NTHREADS];

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < NTHREADS; i++) {
        args[i].cache = cache;
        args[i].ops_per_thread = OPS;
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, thread_alloc_free, &args[i]);
    }

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(threads[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                (t1.tv_nsec - t0.tv_nsec) / 1e6;

    printf("  %d threads × %d ops = %d total ops in %.2f ms\n",
           NTHREADS, OPS, NTHREADS * OPS, ms);
    printf("  %.0f ns/op (alloc+free, %d threads, NO magazines)\n",
           ms * 1e6 / (NTHREADS * OPS * 2), NTHREADS);

    slab_cache_stats(cache);
    slab_cache_destroy(cache);
    printf("  PASSED\n\n");
}

/* ── Main ────────────────────────────────────────────────────── */

int main(void)
{
    printf("Slab Allocator Test Suite v0.6\n");
    printf("==============================\n\n");

    slab_system_init();

    /* Correctness tests */
    test_basic_alloc_free();
    test_slab_growth();
    test_shrink();
    test_debug_redzone();
    test_debug_overflow_detect();

    /* Performance: single-threaded */
    test_performance();
    test_performance_no_mag();

    /* Performance: multithreaded */
    test_multithreaded_basic();
    test_multithreaded_no_mag();
    test_multithreaded_churn();

    slab_system_fini();

    printf("All tests passed.\n");
    return 0;
}
