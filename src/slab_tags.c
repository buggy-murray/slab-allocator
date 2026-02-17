/*
 * slab_tags.c — Pool tag tracking implementation
 *
 * Uses a simple open-addressing hash table of tag stats entries.
 * Thread-safe via atomic operations on counters.
 * The hash table itself is fixed-size (no runtime growth).
 *
 * Invariants:
 *   INV-TAG-1: For any tag, alloc_count >= free_count (no double-free)
 *   INV-TAG-2: active_count == alloc_count - free_count
 *   INV-TAG-3: At shutdown, active_count == 0 for all tags (no leaks)
 *   INV-TAG-4: peak_count >= active_count (monotonic high water mark)
 *
 * Author: G.H. Murray
 * Date:   2026-02-17
 */

#define _GNU_SOURCE
#include "slab_tags.h"
#include "slab.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>

/* Hash table size — must be power of 2 */
#define TAG_TABLE_SIZE   256
#define TAG_TABLE_MASK   (TAG_TABLE_SIZE - 1)

/* Global tag table */
static struct slab_tag_stats *g_tag_table[TAG_TABLE_SIZE];
static pthread_mutex_t g_tag_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_tags_initialized = false;

/* Simple hash for 4-byte tag */
static inline uint32_t tag_hash(slab_tag_t tag)
{
    /* FNV-1a inspired mixing */
    uint32_t h = tag;
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;
    return h & TAG_TABLE_MASK;
}

/* Unpack tag to 4-char string (for printing) */
static void tag_to_str(slab_tag_t tag, char out[5])
{
    out[0] = (char)(tag & 0xFF);
    out[1] = (char)((tag >> 8) & 0xFF);
    out[2] = (char)((tag >> 16) & 0xFF);
    out[3] = (char)((tag >> 24) & 0xFF);
    out[4] = '\0';
}

/* Find or create a tag stats entry */
static struct slab_tag_stats *tag_get_or_create(slab_tag_t tag)
{
    uint32_t idx = tag_hash(tag);

    /* Fast path: check existing chain without lock */
    struct slab_tag_stats *s = g_tag_table[idx];
    while (s) {
        if (s->tag == tag)
            return s;
        s = s->next;
    }

    /* Slow path: create under lock */
    pthread_mutex_lock(&g_tag_lock);

    /* Double-check after acquiring lock */
    s = g_tag_table[idx];
    while (s) {
        if (s->tag == tag) {
            pthread_mutex_unlock(&g_tag_lock);
            return s;
        }
        s = s->next;
    }

    /* Allocate new entry */
    s = calloc(1, sizeof(*s));
    if (!s) {
        pthread_mutex_unlock(&g_tag_lock);
        return NULL;
    }

    s->tag = tag;
    atomic_store(&s->alloc_count, 0);
    atomic_store(&s->free_count, 0);
    atomic_store(&s->active_count, 0);
    atomic_store(&s->active_bytes, 0);
    atomic_store(&s->peak_count, 0);
    atomic_store(&s->peak_bytes, 0);
    s->next = g_tag_table[idx];
    g_tag_table[idx] = s;

    pthread_mutex_unlock(&g_tag_lock);
    return s;
}

void slab_tags_init(void)
{
    memset(g_tag_table, 0, sizeof(g_tag_table));
    g_tags_initialized = true;
}

void slab_tags_fini(void)
{
    if (!g_tags_initialized)
        return;

    /* Report leaks */
    bool any_leaks = false;
    for (uint32_t i = 0; i < TAG_TABLE_SIZE; i++) {
        struct slab_tag_stats *s = g_tag_table[i];
        while (s) {
            uint64_t active = atomic_load(&s->active_count);
            if (active > 0) {
                if (!any_leaks) {
                    fprintf(stderr, "\n=== SLAB TAG LEAK REPORT ===\n");
                    any_leaks = true;
                }
                char name[5];
                tag_to_str(s->tag, name);
                fprintf(stderr, "  LEAK: tag='%s' active=%lu objects, %lu bytes\n",
                        name, (unsigned long)active,
                        (unsigned long)atomic_load(&s->active_bytes));
            }
            struct slab_tag_stats *next = s->next;
            free(s);
            s = next;
        }
        g_tag_table[i] = NULL;
    }

    if (!any_leaks)
        fprintf(stderr, "[slab_tags] Shutdown clean — no leaks detected.\n");

    g_tags_initialized = false;
}

void slab_tag_alloc(slab_tag_t tag, size_t obj_size)
{
    if (!g_tags_initialized)
        return;

    struct slab_tag_stats *s = tag_get_or_create(tag);
    if (!s)
        return;

    atomic_fetch_add(&s->alloc_count, 1);
    uint64_t active = atomic_fetch_add(&s->active_count, 1) + 1;
    uint64_t bytes = atomic_fetch_add(&s->active_bytes, obj_size) + obj_size;

    /* Update peak (relaxed — approximate is fine for high water mark) */
    uint64_t peak = atomic_load_explicit(&s->peak_count, memory_order_relaxed);
    while (active > peak) {
        if (atomic_compare_exchange_weak_explicit(&s->peak_count, &peak, active,
                                                   memory_order_relaxed,
                                                   memory_order_relaxed))
            break;
    }

    uint64_t peak_b = atomic_load_explicit(&s->peak_bytes, memory_order_relaxed);
    while (bytes > peak_b) {
        if (atomic_compare_exchange_weak_explicit(&s->peak_bytes, &peak_b, bytes,
                                                   memory_order_relaxed,
                                                   memory_order_relaxed))
            break;
    }
}

void slab_tag_free(slab_tag_t tag, size_t obj_size)
{
    if (!g_tags_initialized)
        return;

    struct slab_tag_stats *s = tag_get_or_create(tag);
    if (!s)
        return;

    atomic_fetch_add(&s->free_count, 1);
    atomic_fetch_sub(&s->active_count, 1);
    atomic_fetch_sub(&s->active_bytes, obj_size);
}

void slab_tag_report(bool show_all)
{
    if (!g_tags_initialized) {
        fprintf(stderr, "[slab_tags] Not initialized.\n");
        return;
    }

    fprintf(stderr, "\n=== SLAB TAG REPORT ===\n");
    fprintf(stderr, "%-6s %10s %10s %10s %10s %10s %10s\n",
            "Tag", "Allocs", "Frees", "Active", "Bytes", "PeakCnt", "PeakBytes");
    fprintf(stderr, "%-6s %10s %10s %10s %10s %10s %10s\n",
            "------", "----------", "----------", "----------",
            "----------", "----------", "----------");

    uint64_t total_active = 0, total_bytes = 0;

    for (uint32_t i = 0; i < TAG_TABLE_SIZE; i++) {
        struct slab_tag_stats *s = g_tag_table[i];
        while (s) {
            uint64_t active = atomic_load(&s->active_count);
            if (active > 0 || show_all) {
                char name[5];
                tag_to_str(s->tag, name);
                fprintf(stderr, "'%s' %10lu %10lu %10lu %10lu %10lu %10lu\n",
                        name,
                        (unsigned long)atomic_load(&s->alloc_count),
                        (unsigned long)atomic_load(&s->free_count),
                        (unsigned long)active,
                        (unsigned long)atomic_load(&s->active_bytes),
                        (unsigned long)atomic_load(&s->peak_count),
                        (unsigned long)atomic_load(&s->peak_bytes));
                total_active += active;
                total_bytes += atomic_load(&s->active_bytes);
            }
            s = s->next;
        }
    }

    fprintf(stderr, "%-6s %10s %10s %10lu %10lu\n",
            "TOTAL", "", "", (unsigned long)total_active, (unsigned long)total_bytes);
}

const struct slab_tag_stats *slab_tag_lookup(slab_tag_t tag)
{
    if (!g_tags_initialized)
        return NULL;

    uint32_t idx = tag_hash(tag);
    struct slab_tag_stats *s = g_tag_table[idx];
    while (s) {
        if (s->tag == tag)
            return s;
        s = s->next;
    }
    return NULL;
}

/* Tagged wrappers */
void *slab_alloc_tagged(struct slab_cache *cache, const char tag[4])
{
    void *obj = slab_alloc(cache);
    if (obj) {
        slab_tag_t t = SLAB_TAG(tag[0], tag[1], tag[2], tag[3]);
        slab_tag_alloc(t, cache->raw_size);
    }
    return obj;
}

void slab_free_tagged(struct slab_cache *cache, void *obj, const char tag[4])
{
    if (obj) {
        slab_tag_t t = SLAB_TAG(tag[0], tag[1], tag[2], tag[3]);
        slab_tag_free(t, cache->raw_size);
    }
    slab_free(cache, obj);
}
