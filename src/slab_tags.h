/*
 * slab_tags.h — Pool tag tracking for the slab allocator
 *
 * Inspired by NT's ExAllocatePoolWithTag and TFS-Successor's Mm spec.
 * Every allocation can be tagged with a 4-character identifier for
 * tracking, leak detection, and per-subsystem accounting.
 *
 * Usage:
 *   void *p = slab_alloc_tagged(cache, "Crea");
 *   slab_free_tagged(cache, p, "Crea");
 *   slab_tag_report();  // prints per-tag stats
 *
 * The tag system is optional — slab_alloc/slab_free still work without tags.
 * Tags add ~16 bytes overhead per allocation in debug mode (stored in a
 * separate hash table, not inline, to preserve cache layout).
 *
 * Author: G.H. Murray
 * Date:   2026-02-17
 */

#ifndef SLAB_TAGS_H
#define SLAB_TAGS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* A tag is 4 ASCII characters packed into a uint32_t */
typedef uint32_t slab_tag_t;

#define SLAB_TAG(a, b, c, d) \
    ((slab_tag_t)(a) | ((slab_tag_t)(b) << 8) | \
     ((slab_tag_t)(c) << 16) | ((slab_tag_t)(d) << 24))

#define SLAB_TAG_NONE  SLAB_TAG('N','o','n','e')

/* Per-tag statistics */
struct slab_tag_stats {
    slab_tag_t tag;
    _Atomic uint64_t alloc_count;      /* Total allocations with this tag    */
    _Atomic uint64_t free_count;       /* Total frees with this tag          */
    _Atomic uint64_t active_count;     /* Currently active (alloc - free)    */
    _Atomic uint64_t active_bytes;     /* Currently active bytes             */
    _Atomic uint64_t peak_count;       /* High water mark of active_count    */
    _Atomic uint64_t peak_bytes;       /* High water mark of active_bytes    */
    struct slab_tag_stats *next;       /* Hash chain                         */
};

/*
 * Initialize/teardown the tag tracking system.
 * Call slab_tags_init() before first tagged allocation.
 * Call slab_tags_fini() at shutdown to report leaks.
 */
void slab_tags_init(void);
void slab_tags_fini(void);

/*
 * Record an allocation or free against a tag.
 * obj_size is the user-visible object size (raw_size).
 */
void slab_tag_alloc(slab_tag_t tag, size_t obj_size);
void slab_tag_free(slab_tag_t tag, size_t obj_size);

/*
 * Print a report of all tags with active allocations.
 * If show_all is true, includes tags with zero active count.
 */
void slab_tag_report(bool show_all);

/*
 * Query stats for a specific tag. Returns NULL if tag not found.
 */
const struct slab_tag_stats *slab_tag_lookup(slab_tag_t tag);

/*
 * Tagged alloc/free wrappers for slab_cache.
 */
struct slab_cache;
void *slab_alloc_tagged(struct slab_cache *cache, const char tag[4]);
void  slab_free_tagged(struct slab_cache *cache, void *obj, const char tag[4]);

#endif /* SLAB_TAGS_H */
