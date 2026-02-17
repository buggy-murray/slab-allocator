/*
 * slab.c — Userspace slab allocator implementation
 *
 * v0.8: Per-CPU depot partitioning with lock-free C11 atomics.
 *
 * Architecture (3 layers):
 *   Layer 1: Per-thread magazine (TLS, no synchronization needed)
 *   Layer 2: Per-CPU lock-free depot (CAS-based stack of full/empty magazines)
 *   Layer 3: Shared slab lists protected by per-cache mutex
 *
 * Alloc fast path:  pop from magazine (no sync)
 * Alloc medium path: swap empty magazine for full one from depot (CAS)
 * Alloc slow path:  fill magazine from slab lists (mutex)
 *
 * Free fast path:   push to magazine (no sync)
 * Free medium path: swap full magazine for empty one from depot (CAS)
 * Free slow path:   drain magazine to slab lists (mutex)
 *
 * Author: G.H. Murray
 * Date:   2026-02-16
 */

#define _GNU_SOURCE
#include "slab.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>

/* ──────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────── */

static struct slab_cache *global_cache_list = NULL;
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;

static inline size_t align_up(size_t val, size_t align)
{
    return (val + align - 1) & ~(align - 1);
}

static size_t compute_slab_size(size_t obj_size, uint16_t *out_count)
{
    size_t slab_size = SLAB_PAGE_SIZE;
    size_t header    = align_up(sizeof(struct slab), SLAB_ALIGN_DEFAULT);
    uint16_t count;

    for (int order = 0; order < 4; order++) {
        slab_size = SLAB_PAGE_SIZE << order;
        size_t usable = slab_size - header;
        count = (uint16_t)(usable / obj_size);
        if (count >= 8 || count >= SLAB_MAX_OBJECTS)
            break;
    }

    if (count == 0) {
        slab_size = align_up(header + obj_size, SLAB_PAGE_SIZE);
        count = 1;
    }

    if (count > SLAB_MAX_OBJECTS)
        count = SLAB_MAX_OBJECTS;

    *out_count = count;
    return slab_size;
}

static void *pages_alloc_aligned(size_t slab_size, void **out_raw, size_t *out_raw_size)
{
    /* Guard against overflow: slab_size + (slab_size - 1) must not wrap */
    if (slab_size == 0 || slab_size > SIZE_MAX / 2)
        return NULL;
    size_t raw_size = slab_size + (slab_size - 1);
    void *raw = mmap(NULL, raw_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED)
        return NULL;

    uintptr_t raw_addr = (uintptr_t)raw;
    uintptr_t aligned  = (raw_addr + slab_size - 1) & ~(slab_size - 1);

    size_t leading = aligned - raw_addr;
    if (leading > 0)
        munmap(raw, leading);

    size_t trailing = (raw_addr + raw_size) - (aligned + slab_size);
    if (trailing > 0)
        munmap((void *)(aligned + slab_size), trailing);

    *out_raw = (void *)aligned;
    *out_raw_size = slab_size;
    return (void *)aligned;
}

static void pages_free(void *raw_ptr, size_t raw_size)
{
    munmap(raw_ptr, raw_size);
}

static inline struct slab *slab_from_obj(void *obj, size_t slab_size)
{
    return (struct slab *)((uintptr_t)obj & ~(slab_size - 1));
}

/* ──────────────────────────────────────────────────────────────────
 * Debug: red zones and poisoning
 * ────────────────────────────────────────────────────────────────── */

static inline void *obj_to_user(struct slab_cache *cache, void *obj)
{
    if (cache->flags & SLAB_RED_ZONE)
        return (char *)obj + SLAB_RED_ZONE_SIZE;
    return obj;
}

static inline void *user_to_obj(struct slab_cache *cache, void *user)
{
    if (cache->flags & SLAB_RED_ZONE)
        return (char *)user - SLAB_RED_ZONE_SIZE;
    return user;
}

static void red_zone_fill(struct slab_cache *cache, void *obj)
{
    if (!(cache->flags & SLAB_RED_ZONE))
        return;
    memset(obj, SLAB_RED_MAGIC, SLAB_RED_ZONE_SIZE);
    memset((char *)obj + cache->red_offset, SLAB_RED_MAGIC, SLAB_RED_ZONE_SIZE);
}

static bool red_zone_check(struct slab_cache *cache, void *obj)
{
    if (!(cache->flags & SLAB_RED_ZONE))
        return true;

    unsigned char *lead = (unsigned char *)obj;
    unsigned char *trail = (unsigned char *)obj + cache->red_offset;
    bool ok = true;

    for (size_t i = 0; i < SLAB_RED_ZONE_SIZE; i++) {
        if (lead[i] != SLAB_RED_MAGIC) {
            fprintf(stderr,
                "slab: RED ZONE UNDERFLOW in cache '%s' at obj %p (lead[%zu]=0x%02x)\n",
                cache->name, obj_to_user(cache, obj), i, lead[i]);
            ok = false;
            break;
        }
    }
    for (size_t i = 0; i < SLAB_RED_ZONE_SIZE; i++) {
        if (trail[i] != SLAB_RED_MAGIC) {
            fprintf(stderr,
                "slab: RED ZONE OVERFLOW in cache '%s' at obj %p (trail[%zu]=0x%02x)\n",
                cache->name, obj_to_user(cache, obj), i, trail[i]);
            ok = false;
            break;
        }
    }
    return ok;
}

static void poison_free(struct slab_cache *cache, void *obj)
{
    if (!(cache->flags & SLAB_POISON))
        return;
    void *user = obj_to_user(cache, obj);
    memset(user, SLAB_POISON_FREE, cache->raw_size);
}

static bool poison_check_free(struct slab_cache *cache, void *obj)
{
    if (!(cache->flags & SLAB_POISON))
        return true;
    void *user = obj_to_user(cache, obj);
    unsigned char *p = (unsigned char *)user;
    size_t skip = (cache->flags & SLAB_RED_ZONE) ? 0 : sizeof(void *);
    for (size_t i = skip; i < cache->raw_size; i++) {
        if (p[i] != SLAB_POISON_FREE) {
            fprintf(stderr,
                "slab: USE-AFTER-FREE detected in cache '%s' at obj %p (byte[%zu]=0x%02x)\n",
                cache->name, user, i, p[i]);
            return false;
        }
    }
    return true;
}

/* ──────────────────────────────────────────────────────────────────
 * Slab management (caller must hold cache->lock)
 * ────────────────────────────────────────────────────────────────── */

static void slab_init(struct slab *s, struct slab_cache *cache, uint16_t colour_off)
{
    size_t header = align_up(sizeof(struct slab), cache->align);

    s->cache      = cache;
    s->next       = NULL;
    s->inuse      = 0;
    s->total      = cache->objs_per_slab;
    s->colour_off = colour_off;
    s->base       = (char *)s + header + colour_off;

    s->freelist = s->base;
    for (uint16_t i = 0; i < s->total - 1; i++) {
        void *obj  = (char *)s->base + (i * cache->obj_size);
        void *next = (char *)s->base + ((i + 1) * cache->obj_size);
        *(void **)obj = next;
    }
    void *last = (char *)s->base + ((s->total - 1) * cache->obj_size);
    *(void **)last = NULL;
}

static struct slab *slab_new(struct slab_cache *cache)
{
    void *raw;
    size_t raw_size;
    void *mem = pages_alloc_aligned(cache->slab_size, &raw, &raw_size);
    if (!mem)
        return NULL;

    struct slab *s = (struct slab *)mem;
    s->raw_mmap = raw;
    s->raw_size = raw_size;

    /* Assign slab color (v0.9) — rotate through available colors */
    uint16_t colour_off = cache->colour_next * cache->colour_off;
    cache->colour_next++;
    if (cache->colour_next > cache->colour)
        cache->colour_next = 0;

    slab_init(s, cache, colour_off);
    cache->nr_slabs++;
    return s;
}

static void slab_release(struct slab_cache *cache, struct slab *s)
{
    if (s->inuse > 0) {
        fprintf(stderr, "slab: WARNING: releasing slab with %u objects still in use\n",
                s->inuse);
    }
    if (cache->dtor) {
        for (uint16_t i = 0; i < s->total; i++) {
            void *obj = (char *)s->base + (i * cache->obj_size);
            cache->dtor(obj_to_user(cache, obj));
        }
    }
    cache->nr_slabs--;
    pages_free(s->raw_mmap, s->raw_size);
}

static void slab_list_remove(struct slab **head, struct slab *target)
{
    struct slab **pp = head;
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            target->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

static void slab_list_push(struct slab **head, struct slab *s)
{
    s->next = *head;
    *head = s;
}

/* ──────────────────────────────────────────────────────────────────
 * Core alloc/free from shared slab (caller must hold cache->lock)
 * ────────────────────────────────────────────────────────────────── */

/*
 * Allocate one object from shared slab state.
 * Returns internal obj pointer (not user pointer).
 */
static void *slab_alloc_slow(struct slab_cache *cache)
{
    struct slab *s = cache->partial;

    if (!s) {
        if (cache->free) {
            s = cache->free;
            cache->free = s->next;
            cache->nr_free--;
            s->next = NULL;
        } else {
            s = slab_new(cache);
            if (!s)
                return NULL;
        }
        slab_list_push(&cache->partial, s);
        cache->nr_partial++;
    }

    assert(s->freelist != NULL);
    void *obj = s->freelist;
    s->freelist = *(void **)obj;
    s->inuse++;

    if (s->inuse == s->total) {
        slab_list_remove(&cache->partial, s);
        cache->nr_partial--;
        slab_list_push(&cache->full, s);
    }

    return obj;
}

/*
 * Return one internal object to the shared slab state.
 */
static void slab_free_slow(struct slab_cache *cache, void *obj)
{
    struct slab *s = slab_from_obj(obj, cache->slab_size);

    if (s->cache != cache) {
        fprintf(stderr, "slab: ERROR: slab_free called with pointer not belonging to cache '%s'\n",
                cache->name);
        return;
    }

    bool was_full = (s->inuse == s->total);

    *(void **)obj = s->freelist;
    s->freelist = obj;
    s->inuse--;

    if (was_full) {
        slab_list_remove(&cache->full, s);
        slab_list_push(&cache->partial, s);
        cache->nr_partial++;
    }

    if (s->inuse == 0) {
        slab_list_remove(&cache->partial, s);
        cache->nr_partial--;

        if (cache->nr_free < cache->max_free) {
            slab_list_push(&cache->free, s);
            cache->nr_free++;
        } else {
            slab_release(cache, s);
        }
    }
}

/* ──────────────────────────────────────────────────────────────────
 * Per-CPU lock-free depot layer (v0.8)
 *
 * Each CPU has its own depot (full/empty stacks) to eliminate
 * cross-CPU CAS contention. CPU ID obtained via sched_getcpu()
 * (VDSO, ~2ns on Linux). Fallback to CPU 0 if unavailable.
 * ────────────────────────────────────────────────────────────────── */

/*
 * get_cpu_depot — Get the depot for the current CPU.
 *
 * Uses sched_getcpu() for O(1) CPU identification (Linux VDSO).
 * Falls back to CPU 0 if sched_getcpu() fails or returns out-of-range.
 */
static inline struct cpu_depot *get_cpu_depot(struct slab_cache *cache)
{
    int cpu = sched_getcpu();
    if (cpu < 0 || (unsigned)cpu >= cache->nr_cpus)
        cpu = 0;
    return &cache->cpu_depots[cpu];
}

static struct depot_node *depot_pop(_Atomic struct depot_head *head)
{
    struct depot_head old_head, new_head;

    old_head = atomic_load_explicit(head, memory_order_acquire);
    do {
        if (!old_head.node)
            return NULL;
        new_head.node = old_head.node->next;
        new_head.tag  = old_head.tag + 1;
    } while (!atomic_compare_exchange_weak_explicit(
                head, &old_head, new_head,
                memory_order_acq_rel, memory_order_acquire));

    old_head.node->next = NULL;
    return old_head.node;
}

static void depot_push(_Atomic struct depot_head *head, struct depot_node *node)
{
    struct depot_head old_head, new_head;

    old_head = atomic_load_explicit(head, memory_order_relaxed);
    do {
        node->next    = old_head.node;
        new_head.node = node;
        new_head.tag  = old_head.tag + 1;
    } while (!atomic_compare_exchange_weak_explicit(
                head, &old_head, new_head,
                memory_order_release, memory_order_relaxed));
}

/*
 * Allocate a new depot node (malloc, so not lock-free itself,
 * but only called on the slow path during depot replenishment).
 */
static struct depot_node *depot_node_alloc(void)
{
    struct depot_node *n = calloc(1, sizeof(struct depot_node));
    return n;
}

/*
 * Fill a depot node's magazine from the shared slab (under mutex).
 * Returns number of objects placed in the magazine.
 */
static uint16_t depot_fill_magazine(struct slab_cache *cache, struct depot_node *node)
{
    struct slab_magazine *mag = &node->mag;
    mag->count = 0;

    pthread_mutex_lock(&cache->lock);
    for (uint16_t i = 0; i < SLAB_MAG_SIZE; i++) {
        void *obj = slab_alloc_slow(cache);
        if (!obj)
            break;

        if (cache->flags & SLAB_POISON) {
            unsigned char *check = (unsigned char *)obj_to_user(cache, obj);
            size_t skip = (cache->flags & SLAB_RED_ZONE) ? 0 : sizeof(void *);
            if (cache->raw_size > skip && check[skip] == SLAB_POISON_FREE)
                poison_check_free(cache, obj);
        }
        red_zone_fill(cache, obj);

        void *user = obj_to_user(cache, obj);
        if (cache->ctor)
            cache->ctor(user);

        mag->objects[mag->count++] = user;
    }
    pthread_mutex_unlock(&cache->lock);
    return mag->count;
}

/*
 * Drain a depot node's magazine back to shared slab (under mutex).
 */
static void depot_drain_magazine(struct slab_cache *cache, struct depot_node *node)
{
    struct slab_magazine *mag = &node->mag;

    pthread_mutex_lock(&cache->lock);
    for (uint16_t i = 0; i < mag->count; i++) {
        void *user = mag->objects[i];
        void *obj  = user_to_obj(cache, user);
        red_zone_check(cache, obj);
        poison_free(cache, obj);
        slab_free_slow(cache, obj);
    }
    pthread_mutex_unlock(&cache->lock);
    mag->count = 0;
}

/* ──────────────────────────────────────────────────────────────────
 * Per-thread magazine layer
 * ────────────────────────────────────────────────────────────────── */

/*
 * Magazine destructor — called on thread exit.
 * Flushes all cached objects back to shared slab, then returns
 * the magazine to the depot's empty stack for reuse.
 */
struct mag_wrapper {
    struct slab_magazine  mag;
    struct slab_cache    *cache;
};

static void mag_destructor(void *arg)
{
    struct mag_wrapper *w = (struct mag_wrapper *)arg;
    if (!w)
        return;

    struct slab_cache *cache = w->cache;
    struct slab_magazine *mag = &w->mag;

    if (mag->count > 0) {
        pthread_mutex_lock(&cache->lock);
        for (uint16_t i = 0; i < mag->count; i++) {
            void *obj = user_to_obj(cache, mag->objects[i]);
            /* Skip debug on magazine flush — objects were already debug-processed on free */
            slab_free_slow(cache, obj);
        }
        pthread_mutex_unlock(&cache->lock);
    }

    free(w);
}

static struct slab_magazine *mag_get_or_create_wrapped(struct slab_cache *cache)
{
    if (cache->flags & SLAB_NO_MAGAZINES)
        return NULL;

    struct mag_wrapper *w = (struct mag_wrapper *)pthread_getspecific(cache->mag_key);
    if (!w) {
        w = calloc(1, sizeof(struct mag_wrapper));
        if (!w)
            return NULL;
        w->cache = cache;
        pthread_setspecific(cache->mag_key, w);
    }
    return &w->mag;
}

/*
 * Refill magazine — try depot first (lock-free), then slab (mutex).
 *
 * Strategy:
 *  1. Try to pop a full magazine from the depot (CAS — fast)
 *  2. If depot empty, fill a new magazine from slab lists (mutex — slow)
 *
 * Returns number of objects available in magazine after refill.
 */
static uint16_t mag_refill(struct slab_cache *cache, struct slab_magazine *mag)
{
    struct cpu_depot *depot = get_cpu_depot(cache);

    /* Medium path: try per-CPU depot */
    struct depot_node *full = depot_pop(&depot->full);
    if (full) {
        /* Swap: copy full depot magazine into thread magazine */
        memcpy(mag->objects, full->mag.objects,
               full->mag.count * sizeof(void *));
        mag->count = full->mag.count;

        /* Return the now-empty depot node to empty stack */
        full->mag.count = 0;
        depot_push(&depot->empty, full);
        return mag->count;
    }

    /* Slow path: get or create a depot node, fill from slab */
    struct depot_node *node = depot_pop(&depot->empty);
    if (!node) {
        node = depot_node_alloc();
        if (!node) {
            /* Absolute fallback: fill magazine directly (old v0.6 path) */
            uint16_t batch = SLAB_MAG_BATCH;
            uint16_t space = SLAB_MAG_SIZE - mag->count;
            if (batch > space) batch = space;

            pthread_mutex_lock(&cache->lock);
            uint16_t got = 0;
            for (uint16_t i = 0; i < batch; i++) {
                void *obj = slab_alloc_slow(cache);
                if (!obj) break;
                if (cache->flags & SLAB_POISON) {
                    unsigned char *check = (unsigned char *)obj_to_user(cache, obj);
                    size_t skip = (cache->flags & SLAB_RED_ZONE) ? 0 : sizeof(void *);
                    if (cache->raw_size > skip && check[skip] == SLAB_POISON_FREE)
                        poison_check_free(cache, obj);
                }
                red_zone_fill(cache, obj);
                void *user = obj_to_user(cache, obj);
                if (cache->ctor) cache->ctor(user);
                mag->objects[mag->count++] = user;
                got++;
            }
            pthread_mutex_unlock(&cache->lock);
            return got;
        }
        atomic_fetch_add_explicit(&depot->count, 1, memory_order_relaxed);
    }

    /* Fill the depot node from slab, then transfer to thread magazine */
    uint16_t filled = depot_fill_magazine(cache, node);
    if (filled == 0) {
        depot_push(&depot->empty, node);
        return 0;
    }

    memcpy(mag->objects, node->mag.objects, filled * sizeof(void *));
    mag->count = filled;

    node->mag.count = 0;
    depot_push(&depot->empty, node);
    return mag->count;
}

/*
 * Flush magazine — try depot first (lock-free), then slab (mutex).
 *
 * Strategy:
 *  1. Move thread magazine contents into a depot node → push to depot_full (CAS)
 *  2. If no empty depot nodes, drain to slab lists directly (mutex — slow)
 */
static void mag_flush(struct slab_cache *cache, struct slab_magazine *mag)
{
    struct cpu_depot *depot = get_cpu_depot(cache);

    /* Medium path: get an empty depot node, fill it, push to full depot */
    struct depot_node *node = depot_pop(&depot->empty);
    if (!node)
        node = depot_node_alloc();

    if (node) {
        /* Transfer all objects from thread magazine to depot node */
        memcpy(node->mag.objects, mag->objects, mag->count * sizeof(void *));
        node->mag.count = mag->count;
        mag->count = 0;

        depot_push(&depot->full, node);
        return;
    }

    /* Fallback: drain half to slab directly (old v0.6 behavior) */
    uint16_t flush = mag->count / 2;
    if (flush < 1) flush = 1;

    pthread_mutex_lock(&cache->lock);
    for (uint16_t i = 0; i < flush; i++) {
        mag->count--;
        void *user = mag->objects[mag->count];
        void *obj = user_to_obj(cache, user);
        red_zone_check(cache, obj);
        poison_free(cache, obj);
        slab_free_slow(cache, obj);
    }
    pthread_mutex_unlock(&cache->lock);
}

/* ──────────────────────────────────────────────────────────────────
 * Public API
 * ────────────────────────────────────────────────────────────────── */

struct slab_cache *slab_cache_create(const char *name, size_t size,
                                      size_t align, uint32_t flags,
                                      void (*ctor)(void *),
                                      void (*dtor)(void *))
{
    if (size == 0)
        return NULL;

    struct slab_cache *cache = calloc(1, sizeof(struct slab_cache));
    if (!cache)
        return NULL;

    if (align == 0)
        align = SLAB_ALIGN_DEFAULT;

    cache->name      = name;
    cache->raw_size  = size;
    cache->align     = align;
    cache->flags     = flags;
    cache->ctor      = ctor;
    cache->dtor      = dtor;
    cache->max_free  = 3;

    size_t effective = size;
    if (flags & SLAB_RED_ZONE) {
        effective = SLAB_RED_ZONE_SIZE + size + SLAB_RED_ZONE_SIZE;
        cache->red_offset = SLAB_RED_ZONE_SIZE + size;
    }
    if (effective < SLAB_MIN_OBJ_SIZE)
        effective = SLAB_MIN_OBJ_SIZE;

    cache->obj_size  = align_up(effective, align);
    cache->slab_size = compute_slab_size(cache->obj_size, &cache->objs_per_slab);

    /* Compute slab coloring (v0.9) */
    {
        size_t header   = align_up(sizeof(struct slab), align);
        size_t used     = header + (size_t)cache->objs_per_slab * cache->obj_size;
        size_t leftover = (cache->slab_size > used) ? cache->slab_size - used : 0;
        cache->colour_off  = SLAB_CACHE_LINE;
        cache->colour      = (uint16_t)(leftover / SLAB_CACHE_LINE);
        cache->colour_next = 0;
    }

    /* Initialize mutex */
    pthread_mutex_init(&cache->lock, NULL);

    /* Initialize per-CPU depots (v0.8) */
    {
        long ncpus = sysconf(_SC_NPROCESSORS_CONF);
        if (ncpus < 1) ncpus = 1;
        if (ncpus > SLAB_MAX_CPUS) ncpus = SLAB_MAX_CPUS;
        cache->nr_cpus = (uint32_t)ncpus;
        cache->cpu_depots = calloc((size_t)ncpus, sizeof(struct cpu_depot));
        if (!cache->cpu_depots) {
            pthread_mutex_destroy(&cache->lock);
            free(cache);
            return NULL;
        }
        struct depot_head empty_depot = { .node = NULL, .tag = 0 };
        for (uint32_t i = 0; i < cache->nr_cpus; i++) {
            atomic_store(&cache->cpu_depots[i].full, empty_depot);
            atomic_store(&cache->cpu_depots[i].empty, empty_depot);
            atomic_store(&cache->cpu_depots[i].count, 0);
        }
    }

    /* Initialize TLS key for per-thread magazines */
    if (!(flags & SLAB_NO_MAGAZINES)) {
        if (pthread_key_create(&cache->mag_key, mag_destructor) != 0) {
            fprintf(stderr, "slab: WARNING: failed to create TLS key for cache '%s', disabling magazines\n",
                    name);
            cache->flags |= SLAB_NO_MAGAZINES;
        }
    }

    /* Add to global list */
    pthread_mutex_lock(&global_lock);
    cache->next = global_cache_list;
    global_cache_list = cache;
    pthread_mutex_unlock(&global_lock);

    return cache;
}

void slab_cache_destroy(struct slab_cache *cache)
{
    if (!cache)
        return;

    /* Flush the calling thread's magazine before destroying.
     * Must hold cache->lock since slab_free_slow expects it.
     * Clear TLS key first to prevent mag_destructor double-free. */
    if (!(cache->flags & SLAB_NO_MAGAZINES)) {
        struct mag_wrapper *w = (struct mag_wrapper *)pthread_getspecific(cache->mag_key);
        if (w) {
            pthread_setspecific(cache->mag_key, NULL);
            struct slab_magazine *mag = &w->mag;
            pthread_mutex_lock(&cache->lock);
            for (uint16_t i = 0; i < mag->count; i++) {
                void *obj = user_to_obj(cache, mag->objects[i]);
                slab_free_slow(cache, obj);
            }
            pthread_mutex_unlock(&cache->lock);
            mag->count = 0;
            free(w);
        }
    }

    /* Drain all per-CPU depots BEFORE releasing slabs (v0.8) */
    for (uint32_t cpu = 0; cpu < cache->nr_cpus; cpu++) {
        struct depot_node *node;
        while ((node = depot_pop(&cache->cpu_depots[cpu].full)) != NULL) {
            depot_drain_magazine(cache, node);
            free(node);
        }
        while ((node = depot_pop(&cache->cpu_depots[cpu].empty)) != NULL) {
            free(node);
        }
    }
    free(cache->cpu_depots);

    struct slab *s, *next;

    for (s = cache->full; s; s = next) {
        next = s->next;
        fprintf(stderr, "slab: WARNING: destroying cache '%s' with full slab (%u objects leaked)\n",
                cache->name, s->inuse);
        slab_release(cache, s);
    }

    for (s = cache->partial; s; s = next) {
        next = s->next;
        fprintf(stderr, "slab: WARNING: destroying cache '%s' with partial slab (%u objects leaked)\n",
                cache->name, s->inuse);
        slab_release(cache, s);
    }

    for (s = cache->free; s; s = next) {
        next = s->next;
        slab_release(cache, s);
    }

    /* Remove from global list */
    pthread_mutex_lock(&global_lock);
    struct slab_cache **pp = &global_cache_list;
    while (*pp) {
        if (*pp == cache) {
            *pp = cache->next;
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&global_lock);

    /* Destroy TLS key (magazines already flushed by thread exit) */
    if (!(cache->flags & SLAB_NO_MAGAZINES))
        pthread_key_delete(cache->mag_key);

    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

void *slab_alloc(struct slab_cache *cache)
{
    if (!cache)
        return NULL;

    /* Fast path: try per-thread magazine */
    if (!(cache->flags & SLAB_NO_MAGAZINES)) {
        struct slab_magazine *mag = mag_get_or_create_wrapped(cache);
        if (mag) {
            if (mag->count > 0) {
                /* Pop from magazine — no lock needed */
                return mag->objects[--mag->count];
            }
            /* Magazine empty — refill from shared slab */
            if (mag_refill(cache, mag) > 0) {
                return mag->objects[--mag->count];
            }
        }
    }

    /* Slow path: allocate directly from shared slab */
    pthread_mutex_lock(&cache->lock);
    void *obj = slab_alloc_slow(cache);
    pthread_mutex_unlock(&cache->lock);

    if (!obj)
        return NULL;

    /* Debug processing */
    if (cache->flags & SLAB_POISON) {
        unsigned char *check = (unsigned char *)obj_to_user(cache, obj);
        size_t skip = (cache->flags & SLAB_RED_ZONE) ? 0 : sizeof(void *);
        if (cache->raw_size > skip && check[skip] == SLAB_POISON_FREE)
            poison_check_free(cache, obj);
    }
    red_zone_fill(cache, obj);

    void *user = obj_to_user(cache, obj);
    if (cache->ctor)
        cache->ctor(user);

    return user;
}

void slab_free(struct slab_cache *cache, void *ptr)
{
    if (!cache || !ptr)
        return;

    /* Fast path: push to per-thread magazine */
    if (!(cache->flags & SLAB_NO_MAGAZINES)) {
        struct slab_magazine *mag = mag_get_or_create_wrapped(cache);
        if (mag) {
            if (mag->count < SLAB_MAG_SIZE) {
                /* Push to magazine — no lock needed */
                mag->objects[mag->count++] = ptr;
                return;
            }
            /* Magazine full — flush half to shared slab */
            mag_flush(cache, mag);
            /* Now push */
            mag->objects[mag->count++] = ptr;
            return;
        }
    }

    /* Slow path: free directly to shared slab */
    void *obj = user_to_obj(cache, ptr);

    pthread_mutex_lock(&cache->lock);

    red_zone_check(cache, obj);
    poison_free(cache, obj);
    slab_free_slow(cache, obj);

    pthread_mutex_unlock(&cache->lock);
}

uint32_t slab_cache_shrink(struct slab_cache *cache)
{
    if (!cache)
        return 0;

    pthread_mutex_lock(&cache->lock);

    uint32_t released = 0;
    struct slab *s = cache->free;
    while (s) {
        struct slab *next = s->next;
        slab_release(cache, s);
        released++;
        s = next;
    }
    cache->free = NULL;
    cache->nr_free = 0;

    pthread_mutex_unlock(&cache->lock);
    return released;
}

void slab_cache_stats(const struct slab_cache *cache)
{
    if (!cache) return;

    /* Note: not locking here — stats are advisory */
    uint32_t total_objs = 0, used_objs = 0;

    for (const struct slab *s = cache->full; s; s = s->next) {
        total_objs += s->total;
        used_objs  += s->inuse;
    }
    for (const struct slab *s = cache->partial; s; s = s->next) {
        total_objs += s->total;
        used_objs  += s->inuse;
    }
    for (const struct slab *s = cache->free; s; s = s->next) {
        total_objs += s->total;
    }

    fprintf(stderr,
        "slab cache '%s':\n"
        "  obj_size=%zu (raw=%zu, align=%zu), flags=0x%x\n"
        "  slab_size=%zu, objs_per_slab=%u\n"
        "  slabs: total=%u, partial=%u, free=%u\n"
        "  objects: %u/%u used (%.1f%% utilization)\n",
        cache->name,
        cache->obj_size, cache->raw_size, cache->align, cache->flags,
        cache->slab_size, cache->objs_per_slab,
        cache->nr_slabs, cache->nr_partial, cache->nr_free,
        used_objs, total_objs,
        total_objs ? (100.0 * used_objs / total_objs) : 0.0);
}

void slab_system_init(void)
{
    pthread_mutex_lock(&global_lock);
    global_cache_list = NULL;
    pthread_mutex_unlock(&global_lock);
}

void slab_system_fini(void)
{
    /* Take ownership of the entire cache list atomically.
     * slab_cache_destroy removes each cache from global_cache_list
     * under global_lock, so we just snapshot the head here. */
    pthread_mutex_lock(&global_lock);
    struct slab_cache *c = global_cache_list;
    global_cache_list = NULL;  /* Prevent new caches from seeing stale list */
    pthread_mutex_unlock(&global_lock);

    while (c) {
        struct slab_cache *next = c->next;
        fprintf(stderr, "slab: cache '%s' still exists at shutdown (destroying)\n", c->name);
        slab_cache_destroy(c);
        c = next;
    }
}
