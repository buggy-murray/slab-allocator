/*
 * slab.h — Userspace slab allocator
 *
 * A simplified slab allocator inspired by the Linux kernel's SLUB allocator.
 * Operates in userspace using mmap for page allocation (replacing the buddy
 * allocator).
 *
 * Author: G.H. Murray
 * Date:   2026-02-16
 */

#ifndef SLAB_H
#define SLAB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Page size — matches typical x86-64/ARM64 */
#define SLAB_PAGE_SIZE      4096
#define SLAB_PAGE_SHIFT     12

/* Maximum objects per slab (bounded by page size and minimum object size) */
#define SLAB_MAX_OBJECTS    512

/* Minimum object size (must fit a freelist pointer) */
#define SLAB_MIN_OBJ_SIZE   sizeof(void *)

/* Alignment for objects */
#define SLAB_ALIGN_DEFAULT  sizeof(void *)

/* Debug flags for slab_cache_create */
#define SLAB_RED_ZONE       0x01   /* Guard bytes around objects to detect overflow  */
#define SLAB_POISON         0x02   /* Poison free objects to detect use-after-free   */
#define SLAB_DEBUG          (SLAB_RED_ZONE | SLAB_POISON)

/* Debug magic values */
#define SLAB_RED_MAGIC      0xBB   /* Red zone fill byte                            */
#define SLAB_POISON_FREE    0x6B   /* Free object poison (like Linux's POISON_FREE)  */
#define SLAB_POISON_ALLOC   0x5A   /* Freshly allocated poison (before ctor)         */
#define SLAB_RED_ZONE_SIZE  8      /* Bytes of red zone on each side                 */

/*
 * struct slab — Represents a single slab (one or more pages)
 *
 * In the Linux kernel, this metadata lives inside struct page.
 * Here we keep a separate header at the start of the slab memory.
 */
struct slab {
    struct slab      *next;         /* Next slab in partial/full/free list  */
    struct slab_cache *cache;       /* Back-pointer to owning cache         */
    void             *freelist;     /* Head of free object linked list      */
    uint16_t          inuse;        /* Number of allocated objects          */
    uint16_t          total;        /* Total objects in this slab           */
    void             *base;         /* Base address of object region        */
    void             *raw_mmap;     /* Original mmap pointer (for munmap)   */
    size_t            raw_size;     /* Original mmap size (for munmap)      */
};

/*
 * struct slab_cache — Represents a cache for objects of a fixed size
 *
 * Analogous to struct kmem_cache in the Linux kernel.
 */
struct slab_cache {
    const char       *name;         /* Human-readable name                  */
    size_t            obj_size;     /* Size of each object (after alignment)*/
    size_t            raw_size;     /* Original requested object size       */
    size_t            align;        /* Object alignment                     */
    uint32_t          flags;        /* SLAB_RED_ZONE, SLAB_POISON, etc.    */
    size_t            red_offset;   /* Offset to trailing red zone          */
    size_t            slab_size;    /* Total bytes per slab (pages)         */
    uint16_t          objs_per_slab;/* Objects that fit in one slab         */
    
    struct slab      *partial;      /* Slabs with some free objects         */
    struct slab      *full;         /* Slabs with no free objects           */
    struct slab      *free;         /* Completely empty slabs (cached)      */

    uint32_t          nr_slabs;     /* Total slabs allocated                */
    uint32_t          nr_partial;   /* Number of partial slabs              */
    uint32_t          nr_free;      /* Number of cached free slabs          */
    uint32_t          max_free;     /* Max free slabs to cache before release */

    void (*ctor)(void *obj);        /* Optional object constructor          */
    void (*dtor)(void *obj);        /* Optional object destructor           */

    struct slab_cache *next;        /* Global cache list                    */
};

/*
 * slab_cache_create — Create a new slab cache
 *
 * @name:     Name of the cache (for debugging)
 * @size:     Size of each object in bytes
 * @align:    Alignment requirement (0 for default)
 * @ctor:     Optional constructor called on new objects (NULL if none)
 * @dtor:     Optional destructor called before freeing (NULL if none)
 *
 * Returns a pointer to the new cache, or NULL on failure.
 */
struct slab_cache *slab_cache_create(const char *name, size_t size,
                                      size_t align, uint32_t flags,
                                      void (*ctor)(void *),
                                      void (*dtor)(void *));

/*
 * slab_cache_destroy — Destroy a slab cache and free all memory
 *
 * All objects must be freed before calling this. If objects are still
 * allocated, this will log a warning and leak rather than corrupt.
 */
void slab_cache_destroy(struct slab_cache *cache);

/*
 * slab_alloc — Allocate one object from the cache
 *
 * Returns a pointer to the allocated object, or NULL if allocation fails.
 */
void *slab_alloc(struct slab_cache *cache);

/*
 * slab_free — Free a previously allocated object back to its cache
 *
 * @cache:    The cache the object belongs to
 * @obj:      Pointer to the object to free
 */
void slab_free(struct slab_cache *cache, void *obj);

/*
 * slab_cache_shrink — Release all cached empty slabs back to the OS
 *
 * Returns the number of slabs released. In the Linux kernel, this is
 * triggered by memory pressure via the shrinker subsystem.
 */
uint32_t slab_cache_shrink(struct slab_cache *cache);

/*
 * slab_cache_stats — Print cache statistics to stderr
 */
void slab_cache_stats(const struct slab_cache *cache);

/*
 * slab_system_init — Initialize the slab allocator subsystem
 * slab_system_fini — Tear down and report leaks
 */
void slab_system_init(void);
void slab_system_fini(void);

#endif /* SLAB_H */
