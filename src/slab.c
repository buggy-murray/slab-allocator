/*
 * slab.c — Userspace slab allocator implementation
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
#include <assert.h>

/* ──────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────── */

static struct slab_cache *global_cache_list = NULL;

/* Align value up to alignment boundary */
static inline size_t align_up(size_t val, size_t align)
{
    return (val + align - 1) & ~(align - 1);
}

/* Determine slab size: smallest multiple of PAGE_SIZE that fits at least
 * 8 objects (or as many as possible for large objects). */
static size_t compute_slab_size(size_t obj_size, uint16_t *out_count)
{
    size_t slab_size = SLAB_PAGE_SIZE;
    size_t header    = align_up(sizeof(struct slab), SLAB_ALIGN_DEFAULT);
    uint16_t count;

    /* Try to fit at least 8 objects; grow slab if needed */
    for (int order = 0; order < 4; order++) {
        slab_size = SLAB_PAGE_SIZE << order;
        size_t usable = slab_size - header;
        count = (uint16_t)(usable / obj_size);
        if (count >= 8 || count >= SLAB_MAX_OBJECTS)
            break;
    }

    if (count == 0) {
        /* Object larger than max slab size; use single-object slab */
        slab_size = align_up(header + obj_size, SLAB_PAGE_SIZE);
        count = 1;
    }

    if (count > SLAB_MAX_OBJECTS)
        count = SLAB_MAX_OBJECTS;

    *out_count = count;
    return slab_size;
}

/*
 * Allocate pages via mmap, aligned to slab_size boundary.
 * slab_size is always a power of 2, so we overallocate and align manually.
 * This enables O(1) slab lookup: given any object pointer, mask off low bits
 * to find the slab header.
 *
 * out_raw:  receives the original mmap pointer (for munmap)
 * out_raw_size: receives the original mmap size
 * Returns: aligned pointer, or NULL on failure
 */
static void *pages_alloc_aligned(size_t slab_size, void **out_raw, size_t *out_raw_size)
{
    /*
     * We need slab_size bytes at a slab_size-aligned address.
     * Strategy: overallocate by (slab_size - 1) to guarantee alignment,
     * then munmap the leading and trailing waste regions.
     * This reduces memory overhead from 2x to ~1x + a few pages.
     */
    size_t raw_size = slab_size + (slab_size - 1);
    void *raw = mmap(NULL, raw_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED)
        return NULL;

    uintptr_t raw_addr = (uintptr_t)raw;
    uintptr_t aligned  = (raw_addr + slab_size - 1) & ~(slab_size - 1);

    /* Trim leading waste */
    size_t leading = aligned - raw_addr;
    if (leading > 0)
        munmap(raw, leading);

    /* Trim trailing waste */
    size_t trailing = (raw_addr + raw_size) - (aligned + slab_size);
    if (trailing > 0)
        munmap((void *)(aligned + slab_size), trailing);

    /* The slab now owns exactly slab_size bytes at aligned address */
    *out_raw = (void *)aligned;
    *out_raw_size = slab_size;
    return (void *)aligned;
}

/* Free pages via munmap (uses original raw pointer) */
static void pages_free(void *raw_ptr, size_t raw_size)
{
    munmap(raw_ptr, raw_size);
}

/* O(1) slab lookup: mask off low bits to find slab header */
static inline struct slab *slab_from_obj(void *obj, size_t slab_size)
{
    return (struct slab *)((uintptr_t)obj & ~(slab_size - 1));
}

/* ──────────────────────────────────────────────────────────────────
 * Debug: red zones and poisoning
 * ────────────────────────────────────────────────────────────────── */

/* Get the user-visible pointer from the internal object pointer (skip leading red zone) */
static inline void *obj_to_user(struct slab_cache *cache, void *obj)
{
    if (cache->flags & SLAB_RED_ZONE)
        return (char *)obj + SLAB_RED_ZONE_SIZE;
    return obj;
}

/* Get the internal object pointer from the user-visible pointer */
static inline void *user_to_obj(struct slab_cache *cache, void *user)
{
    if (cache->flags & SLAB_RED_ZONE)
        return (char *)user - SLAB_RED_ZONE_SIZE;
    return user;
}

/* Fill red zones around an object */
static void red_zone_fill(struct slab_cache *cache, void *obj)
{
    if (!(cache->flags & SLAB_RED_ZONE))
        return;
    /* Leading red zone */
    memset(obj, SLAB_RED_MAGIC, SLAB_RED_ZONE_SIZE);
    /* Trailing red zone */
    memset((char *)obj + cache->red_offset, SLAB_RED_MAGIC, SLAB_RED_ZONE_SIZE);
}

/* Verify red zones; returns true if intact */
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

/* Poison a free object's user region */
static void poison_free(struct slab_cache *cache, void *obj)
{
    if (!(cache->flags & SLAB_POISON))
        return;
    void *user = obj_to_user(cache, obj);
    memset(user, SLAB_POISON_FREE, cache->raw_size);
}

/* Check that a free object is still poisoned (detect writes to freed memory) */
static bool poison_check_free(struct slab_cache *cache, void *obj)
{
    if (!(cache->flags & SLAB_POISON))
        return true;
    /* Note: we only check user region, freelist pointer at start of obj is expected */
    void *user = obj_to_user(cache, obj);
    unsigned char *p = (unsigned char *)user;
    /* Skip first sizeof(void*) bytes — that's where the freelist pointer lives
     * (only if red zone is off; with red zone, freelist is before user region) */
    size_t skip = (cache->flags & SLAB_RED_ZONE) ? 0 : sizeof(void *);
    for (size_t i = skip; i < cache->raw_size; i++) {
        if (p[i] != SLAB_POISON_FREE) {
            fprintf(stderr,
                "slab: USE-AFTER-FREE detected in cache '%s' at obj %p (byte[%zu]=0x%02x, expected 0x%02x)\n",
                cache->name, user, i, p[i], SLAB_POISON_FREE);
            return false;
        }
    }
    return true;
}

/* ──────────────────────────────────────────────────────────────────
 * Slab management
 * ────────────────────────────────────────────────────────────────── */

/* Initialize a freshly allocated slab: set up freelist through objects */
static void slab_init(struct slab *s, struct slab_cache *cache)
{
    size_t header = align_up(sizeof(struct slab), cache->align);

    s->cache    = cache;
    s->next     = NULL;
    s->inuse    = 0;
    s->total    = cache->objs_per_slab;
    s->base     = (char *)s + header;

    /* Build freelist: each free object stores a pointer to the next free.
     * Constructor is called on alloc (not here) because the freelist pointer
     * at the start of each object would overwrite ctor-initialized data. */
    /* Build freelist only. Red zones are filled on alloc (after popping),
     * because the freelist pointer at obj[0] would overwrite the leading
     * red zone. Poison is also deferred — meaningless before first use. */
    s->freelist = s->base;
    for (uint16_t i = 0; i < s->total - 1; i++) {
        void *obj  = (char *)s->base + (i * cache->obj_size);
        void *next = (char *)s->base + ((i + 1) * cache->obj_size);
        *(void **)obj = next;
    }
    void *last = (char *)s->base + ((s->total - 1) * cache->obj_size);
    *(void **)last = NULL;
}

/* Allocate a new slab for a cache */
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
    slab_init(s, cache);
    cache->nr_slabs++;
    return s;
}

/* Release a slab's memory */
static void slab_release(struct slab_cache *cache, struct slab *s)
{
    if (s->inuse > 0) {
        fprintf(stderr, "slab: WARNING: releasing slab with %u objects still in use\n",
                s->inuse);
    }

    /* Call destructor on all objects if provided */
    if (cache->dtor) {
        for (uint16_t i = 0; i < s->total; i++) {
            void *obj = (char *)s->base + (i * cache->obj_size);
            cache->dtor(obj_to_user(cache, obj));
        }
    }

    cache->nr_slabs--;
    pages_free(s->raw_mmap, s->raw_size);
}

/* Remove a slab from a linked list */
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

/* Prepend a slab to a linked list */
static void slab_list_push(struct slab **head, struct slab *s)
{
    s->next = *head;
    *head = s;
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

    /*
     * With red zones: layout per object is [RED_LEAD | user_data | RED_TRAIL | padding]
     * obj_size must encompass the full layout so freelist pointers don't overlap red zones.
     */
    size_t effective = size;
    if (flags & SLAB_RED_ZONE) {
        effective = SLAB_RED_ZONE_SIZE + size + SLAB_RED_ZONE_SIZE;
        cache->red_offset = SLAB_RED_ZONE_SIZE + size;
    }
    if (effective < SLAB_MIN_OBJ_SIZE)
        effective = SLAB_MIN_OBJ_SIZE;

    cache->obj_size  = align_up(effective, align);
    cache->slab_size = compute_slab_size(cache->obj_size, &cache->objs_per_slab);

    /* Add to global list */
    cache->next = global_cache_list;
    global_cache_list = cache;

    return cache;
}

void slab_cache_destroy(struct slab_cache *cache)
{
    if (!cache)
        return;

    /* Release all slabs */
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
    struct slab_cache **pp = &global_cache_list;
    while (*pp) {
        if (*pp == cache) {
            *pp = cache->next;
            break;
        }
        pp = &(*pp)->next;
    }

    free(cache);
}

void *slab_alloc(struct slab_cache *cache)
{
    if (!cache)
        return NULL;

    struct slab *s = cache->partial;

    /* No partial slabs available */
    if (!s) {
        /* Try to reuse a cached free slab */
        if (cache->free) {
            s = cache->free;
            cache->free = s->next;
            cache->nr_free--;
            s->next = NULL;
        } else {
            /* Allocate a brand new slab */
            s = slab_new(cache);
            if (!s)
                return NULL;
        }
        slab_list_push(&cache->partial, s);
        cache->nr_partial++;
    }

    /* Pop from freelist */
    assert(s->freelist != NULL);
    void *obj = s->freelist;
    s->freelist = *(void **)obj;
    s->inuse++;

    /* Debug: if this object was previously freed and poisoned, verify
     * the poison is intact (detects use-after-free). We check the first
     * user byte — if it's POISON_FREE, the object was recycled. */
    if (cache->flags & SLAB_POISON) {
        unsigned char *check = (unsigned char *)obj_to_user(cache, obj);
        /* Skip freelist-pointer region for non-redzone caches */
        size_t skip = (cache->flags & SLAB_RED_ZONE) ? 0 : sizeof(void *);
        if (cache->raw_size > skip && check[skip] == SLAB_POISON_FREE)
            poison_check_free(cache, obj);
    }

    /* Debug: fill red zones now (freelist pointer no longer needed) */
    red_zone_fill(cache, obj);

    /* Get user-visible pointer (past leading red zone if enabled) */
    void *user = obj_to_user(cache, obj);

    /* Call constructor after removing from freelist (freelist ptr overwrites obj) */
    if (cache->ctor)
        cache->ctor(user);

    /* If slab is now full, move to full list */
    if (s->inuse == s->total) {
        slab_list_remove(&cache->partial, s);
        cache->nr_partial--;
        slab_list_push(&cache->full, s);
    }

    return user;
}

void slab_free(struct slab_cache *cache, void *ptr)
{
    if (!cache || !ptr)
        return;

    /* Convert user pointer back to internal object pointer */
    void *obj = user_to_obj(cache, ptr);

    /*
     * O(1) slab lookup: slabs are aligned to slab_size boundaries,
     * so masking off the low bits gives us the slab header directly.
     */
    struct slab *s = slab_from_obj(obj, cache->slab_size);

    /* Validate: the slab must belong to this cache */
    if (s->cache != cache) {
        fprintf(stderr, "slab: ERROR: slab_free called with pointer %p not belonging to cache '%s'\n",
                ptr, cache->name);
        return;
    }

    /* Debug: check red zones before freeing (detect buffer overflows) */
    red_zone_check(cache, obj);

    bool was_full = (s->inuse == s->total);

    /* Push object back onto freelist, then poison */
    *(void **)obj = s->freelist;
    s->freelist = obj;
    s->inuse--;

    /* Debug: poison the freed object's user region */
    poison_free(cache, obj);

    if (was_full) {
        /* Move from full to partial */
        slab_list_remove(&cache->full, s);
        slab_list_push(&cache->partial, s);
        cache->nr_partial++;
    }

    /* If slab is now completely empty */
    if (s->inuse == 0) {
        slab_list_remove(&cache->partial, s);
        cache->nr_partial--;

        if (cache->nr_free < cache->max_free) {
            /* Cache the empty slab for reuse */
            slab_list_push(&cache->free, s);
            cache->nr_free++;
        } else {
            /* Release back to OS */
            slab_release(cache, s);
        }
    }
}

uint32_t slab_cache_shrink(struct slab_cache *cache)
{
    if (!cache)
        return 0;

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
    return released;
}

void slab_cache_stats(const struct slab_cache *cache)
{
    if (!cache) return;

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
        "  obj_size=%zu (raw=%zu, align=%zu)\n"
        "  slab_size=%zu, objs_per_slab=%u\n"
        "  slabs: total=%u, partial=%u, free=%u\n"
        "  objects: %u/%u used (%.1f%% utilization)\n",
        cache->name,
        cache->obj_size, cache->raw_size, cache->align,
        cache->slab_size, cache->objs_per_slab,
        cache->nr_slabs, cache->nr_partial, cache->nr_free,
        used_objs, total_objs,
        total_objs ? (100.0 * used_objs / total_objs) : 0.0);
}

void slab_system_init(void)
{
    global_cache_list = NULL;
}

void slab_system_fini(void)
{
    struct slab_cache *c = global_cache_list;
    while (c) {
        struct slab_cache *next = c->next;
        fprintf(stderr, "slab: cache '%s' still exists at shutdown (destroying)\n", c->name);
        slab_cache_destroy(c);
        c = next;
    }
    global_cache_list = NULL;
}
