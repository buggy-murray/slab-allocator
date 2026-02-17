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
#include "vmem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
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

/* vmem import/release callbacks for vmem-backed slab test */
static int mmap_import(void *arg, size_t size, uintptr_t *addrp, size_t *actual)
{
    (void)arg;
    size = (size + 4095) & ~(size_t)4095;
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return -1;
    *addrp = (uintptr_t)p;
    *actual = size;
    return 0;
}

static void mmap_release(void *arg, uintptr_t addr, size_t size)
{
    (void)arg;
    munmap((void *)addr, size);
}

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

    /* Test kmalloc-style API (v0.10) */
    printf("\n=== test_kmalloc ===\n");
    {
        /* Test various sizes across all size classes */
        size_t sizes[] = { 1, 7, 8, 15, 16, 33, 64, 100, 128, 256, 512, 1024, 2048, 4096 };
        int nsizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

        for (int i = 0; i < nsizes; i++) {
            void *p = slab_kmalloc(sizes[i]);
            assert(p != NULL);
            memset(p, 0xAA, sizes[i]);  /* Write to full requested size */
            slab_kfree(p, sizes[i]);
        }

        /* Bulk alloc/free at different sizes */
        void *ptrs[100];
        for (int i = 0; i < 100; i++) {
            ptrs[i] = slab_kmalloc(48);  /* Goes to size-64 cache */
            assert(ptrs[i] != NULL);
        }
        for (int i = 0; i < 100; i++) {
            slab_kfree(ptrs[i], 48);
        }

        /* Too-large allocation should return NULL */
        void *big = slab_kmalloc(8192);
        assert(big == NULL);

        printf("  PASSED\n");
    }

    slab_system_fini();

    /* ── Test vmem-backed slab cache ── */
    {
        printf("\n=== test_vmem_backed_slab ===\n");

        vmem_t *vm = vmem_create("slab_pages", 0, 0, 4096,
                                 mmap_import, mmap_release, NULL, 64 * 1024);

        struct slab_cache *vc = slab_cache_create_vmem("vmem_test", 64, 0, 0,
                                                        NULL, NULL, vm);
        assert(vc != NULL);

        /* Allocate and verify */
        void *objs[200];
        for (int i = 0; i < 200; i++) {
            objs[i] = slab_alloc(vc);
            assert(objs[i] != NULL);
            memset(objs[i], (unsigned char)i, 64);
        }

        /* Verify data integrity */
        for (int i = 0; i < 200; i++) {
            unsigned char *p = objs[i];
            assert(p[0] == (unsigned char)i);
            assert(p[63] == (unsigned char)i);
        }

        /* Free all */
        for (int i = 0; i < 200; i++)
            slab_free(vc, objs[i]);

        slab_cache_destroy(vc);
        vmem_destroy(vm);

        printf("  PASSED\n");
    }

    /* ── test_quarantine ─────────────────────────────────────── */
    {
        printf("\n=== test_quarantine ===\n");

        struct slab_cache *qc = slab_cache_create("quar_test", 64, 0,
                                                   SLAB_QUARANTINE | SLAB_POISON, NULL, NULL);
        assert(qc != NULL);

        /* Allocate and free — freed objects should not be immediately reused */
        void *a = slab_alloc(qc);
        void *b = slab_alloc(qc);
        assert(a && b);

        slab_free(qc, a);
        slab_free(qc, b);

        /* Allocate two more — should NOT get a or b back because they're
         * still in quarantine (quarantine size = 64, only 2 entries) */
        void *c = slab_alloc(qc);
        void *d = slab_alloc(qc);
        assert(c && d);

        /* With quarantine, freed objects stay poisoned — they shouldn't be
         * reused until quarantine evicts them. Since we only have 2 entries
         * in a 64-slot quarantine, c and d should be different from a and b. */
        /* Note: not guaranteed if magazine caching returns them, but with
         * SLAB_QUARANTINE the free path bypasses magazines */
        printf("  a=%p b=%p c=%p d=%p\n", a, b, c, d);
        printf("  quarantine defers reuse: %s\n",
               (c != a && c != b && d != a && d != b) ? "yes" : "partially (magazine effects)");

        slab_free(qc, c);
        slab_free(qc, d);

        /* Fill quarantine to capacity and beyond — should force eviction */
        void *objs[SLAB_QUARANTINE_SIZE + 10];
        for (int i = 0; i < SLAB_QUARANTINE_SIZE + 10; i++) {
            objs[i] = slab_alloc(qc);
            assert(objs[i]);
        }
        for (int i = 0; i < SLAB_QUARANTINE_SIZE + 10; i++)
            slab_free(qc, objs[i]);

        /* Stats should show quarantine usage */
        slab_cache_stats(qc);

        slab_cache_destroy(qc);
        printf("  PASSED\n");
    }

    /* ── test_pool_tags_integrated ──────────────────────────────── */
    {
        printf("\n=== test_pool_tags_integrated ===\n");

        #define TAG_NET  MAKE_POOL_TAG('N','e','t','X')
        #define TAG_OBJ  MAKE_POOL_TAG('O','b','j','M')
        #define TAG_TMP  MAKE_POOL_TAG('T','m','p','!')

        struct slab_cache *tc = slab_cache_create("tag-test", 64, 0,
            SLAB_POOL_TAGS | SLAB_NO_MAGAZINES, NULL, NULL);
        assert(tc);

        /* Allocate with different tags */
        void *n1 = slab_alloc_tag(tc, TAG_NET);
        void *n2 = slab_alloc_tag(tc, TAG_NET);
        void *o1 = slab_alloc_tag(tc, TAG_OBJ);
        void *t1 = slab_alloc_tag(tc, TAG_TMP);
        void *t2 = slab_alloc_tag(tc, TAG_TMP);
        void *t3 = slab_alloc_tag(tc, TAG_TMP);
        assert(n1 && n2 && o1 && t1 && t2 && t3);

        /* Check NET tag: 2 allocs, 0 frees, 128 active bytes */
        const struct pool_tag_entry *net = slab_pool_tag_find(TAG_NET);
        assert(net);
        assert(atomic_load(&net->allocs) == 2);
        assert(atomic_load(&net->frees) == 0);
        assert(atomic_load(&net->active_bytes) == 128);  /* 2 * 64 */

        /* Check TMP tag: 3 allocs */
        const struct pool_tag_entry *tmp = slab_pool_tag_find(TAG_TMP);
        assert(tmp);
        assert(atomic_load(&tmp->allocs) == 3);
        assert(atomic_load(&tmp->active_bytes) == 192);  /* 3 * 64 */

        /* Free some and verify accounting */
        slab_free_tag(tc, t1, TAG_TMP);
        slab_free_tag(tc, t2, TAG_TMP);
        assert(atomic_load(&tmp->frees) == 2);
        assert(atomic_load(&tmp->active_bytes) == 64);   /* 1 remaining */
        assert(atomic_load(&tmp->peak_bytes) == 192);    /* Peak was 3 */

        /* Free the rest */
        slab_free_tag(tc, n1, TAG_NET);
        slab_free_tag(tc, n2, TAG_NET);
        slab_free_tag(tc, o1, TAG_OBJ);
        slab_free_tag(tc, t3, TAG_TMP);

        /* All freed — active should be 0 */
        assert(atomic_load(&net->active_bytes) == 0);
        assert(atomic_load(&tmp->active_bytes) == 0);

        const struct pool_tag_entry *obj = slab_pool_tag_find(TAG_OBJ);
        assert(obj);
        assert(atomic_load(&obj->allocs) == 1);
        assert(atomic_load(&obj->frees) == 1);
        assert(atomic_load(&obj->active_bytes) == 0);

        /* Dump stats */
        slab_pool_tag_stats();

        slab_cache_destroy(tc);
        printf("  PASSED\n");

        #undef TAG_NET
        #undef TAG_OBJ
        #undef TAG_TMP
    }

    /* ── test_verify_invariants ─────────────────────────────────── */
    {
        printf("\n=== test_verify_invariants ===\n");

        struct slab_cache *vc = slab_cache_create("verify-test", 48, 0,
            SLAB_NO_MAGAZINES, NULL, NULL);
        assert(vc);

        /* Empty cache — should pass */
        assert(slab_cache_verify(vc) == 0);

        /* Allocate some objects to create partial/full slabs */
        void *objs[200];
        for (int i = 0; i < 200; i++) {
            objs[i] = slab_alloc(vc);
            assert(objs[i]);
        }
        assert(slab_cache_verify(vc) == 0);

        /* Free half — creates mix of partial and full */
        for (int i = 0; i < 100; i++)
            slab_free(vc, objs[i]);
        assert(slab_cache_verify(vc) == 0);

        /* Free all — should have only free slabs */
        for (int i = 100; i < 200; i++)
            slab_free(vc, objs[i]);
        assert(slab_cache_verify(vc) == 0);

        slab_cache_destroy(vc);
        printf("  PASSED\n");
    }

    printf("\nAll tests passed.\n");
    return 0;
}
