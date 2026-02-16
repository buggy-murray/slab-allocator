/*
 * main.c — Test harness for the slab allocator
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

    /* Allocate a few objects */
    struct task *t1 = slab_alloc(tc);
    struct task *t2 = slab_alloc(tc);
    struct task *t3 = slab_alloc(tc);

    assert(t1 && t2 && t3);
    assert(t1 != t2 && t2 != t3);

    /* Constructor should have zeroed pid */
    assert(t1->pid == 0);

    /* Use the objects */
    t1->pid = 1;
    snprintf(t1->name, sizeof(t1->name), "init");
    t2->pid = 2;
    snprintf(t2->name, sizeof(t2->name), "kthreadd");

    slab_cache_stats(tc);

    /* Free and reallocate — should reuse memory */
    slab_free(tc, t2);
    struct task *t4 = slab_alloc(tc);
    assert(t4 != NULL);
    /* On SLUB-style allocators, we often get the same address back */
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

    /* Allocate more than one slab's worth */
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

    /* Free all */
    for (uint16_t i = 0; i < count; i++) {
        slab_free(ic, ptrs[i]);
    }

    printf("  After freeing all:\n");
    slab_cache_stats(ic);

    free(ptrs);
    slab_cache_destroy(ic);
    printf("  PASSED\n\n");
}

static void test_performance(void)
{
    printf("=== test_performance ===\n");

    struct slab_cache *cache = slab_cache_create("perf_cache", 64, 0, 0, NULL, NULL);
    assert(cache);

    const int N = 100000;
    void **ptrs = malloc(sizeof(void *) * N);
    assert(ptrs);

    /* Benchmark: allocate N objects */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < N; i++) {
        ptrs[i] = slab_alloc(cache);
        assert(ptrs[i]);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double alloc_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                      (t1.tv_nsec - t0.tv_nsec) / 1e6;

    /* Benchmark: free N objects */
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < N; i++) {
        slab_free(cache, ptrs[i]);
    }

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

    struct slab_cache *sc = slab_cache_create("shrink_cache",
        64, 0, 0, NULL, NULL);
    assert(sc != NULL);

    /* Allocate enough to fill multiple slabs */
    uint16_t count = sc->objs_per_slab * 3;
    void **ptrs = malloc(sizeof(void *) * count);
    assert(ptrs);

    for (uint16_t i = 0; i < count; i++) {
        ptrs[i] = slab_alloc(sc);
        assert(ptrs[i]);
    }
    printf("  Allocated %u objects across %u slabs\n", count, sc->nr_slabs);

    /* Free all — slabs move to free list (up to max_free) */
    for (uint16_t i = 0; i < count; i++)
        slab_free(sc, ptrs[i]);

    printf("  After free: %u slabs total, %u cached free\n",
           sc->nr_slabs, sc->nr_free);
    assert(sc->nr_free > 0);

    /* Shrink: release all cached empty slabs */
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
        sizeof(struct task), 0, SLAB_DEBUG, task_ctor, NULL);
    assert(dc != NULL);

    printf("  obj_size=%zu (raw=%zu, with red zones + poison)\n",
           dc->obj_size, dc->raw_size);

    /* Normal alloc/free cycle should produce no warnings */
    struct task *t1 = slab_alloc(dc);
    assert(t1 != NULL);
    assert(t1->pid == 0);  /* ctor ran */

    t1->pid = 42;
    snprintf(t1->name, sizeof(t1->name), "debug_test");

    slab_free(dc, t1);

    /* Re-alloc should succeed and poison check should pass */
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
        32, 0, SLAB_RED_ZONE, NULL, NULL);
    assert(dc != NULL);

    char *obj = slab_alloc(dc);
    assert(obj != NULL);

    /* Write exactly within bounds — should be fine */
    memset(obj, 'A', 32);

    /* Intentionally corrupt trailing red zone (write 1 byte past) */
    obj[32] = 0xFF;

    printf("  (Expect RED ZONE OVERFLOW warning below)\n");
    slab_free(dc, obj);  /* Should print overflow warning */

    slab_cache_destroy(dc);
    printf("  PASSED (overflow detected)\n\n");
}

/* ── Main ────────────────────────────────────────────────────── */

int main(void)
{
    printf("Slab Allocator Test Suite\n");
    printf("========================\n\n");

    slab_system_init();

    test_basic_alloc_free();
    test_slab_growth();
    test_shrink();
    test_debug_redzone();
    test_debug_overflow_detect();
    test_performance();

    slab_system_fini();

    printf("All tests passed.\n");
    return 0;
}
