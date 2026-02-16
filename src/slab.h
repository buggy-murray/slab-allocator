/*
 * slab.h — Userspace slab allocator
 *
 * A simplified slab allocator inspired by the Linux kernel's SLUB allocator
 * and Solaris magazine-based caching.
 *
 * v0.7: Lock-free magazine depot layer using C11 atomics.
 *        Per-thread magazines swap with depot (CAS) instead of mutex.
 * v0.8: Per-CPU depot partitioning to eliminate cross-CPU CAS contention.
 *        Each CPU gets its own lock-free depot stacks (full/empty).
 *
 * Author: G.H. Murray
 * Date:   2026-02-16
 */

#ifndef SLAB_H
#define SLAB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

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

/* Per-thread magazine flags */
#define SLAB_NO_MAGAZINES   0x04   /* Disable per-thread caching                    */

/* Debug magic values */
#define SLAB_RED_MAGIC      0xBB   /* Red zone fill byte                            */
#define SLAB_POISON_FREE    0x6B   /* Free object poison (like Linux's POISON_FREE)  */
#define SLAB_POISON_ALLOC   0x5A   /* Freshly allocated poison (before ctor)         */
#define SLAB_RED_ZONE_SIZE  8      /* Bytes of red zone on each side                 */

/* Magazine configuration */
#define SLAB_MAG_SIZE       32     /* Objects per magazine (power of 2 preferred)    */
#define SLAB_MAG_BATCH      16     /* Objects to transfer on refill/flush            */

/* Per-CPU depot configuration (v0.8) */
#define SLAB_MAX_CPUS       256    /* Hard cap on CPU depot array size               */

/*
 * struct slab — Represents a single slab (one or more pages)
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
 * struct slab_magazine — Per-thread object cache
 *
 * Inspired by Solaris magazine layer and NT lookaside lists.
 * Each thread keeps a small stash of recently freed objects to avoid
 * hitting the shared slab lock on every alloc/free.
 */
struct slab_magazine {
    void    *objects[SLAB_MAG_SIZE];
    uint16_t count;                 /* Number of cached objects             */
};

/*
 * struct depot_node — A node in the lock-free depot stack.
 *
 * Each node holds a full magazine. Magazines are swapped between
 * per-thread TLS and the depot using CAS operations.
 */
struct depot_node {
    struct depot_node    *next;
    struct slab_magazine  mag;
};

/*
 * struct depot_head — Tagged pointer for ABA-safe lock-free stack.
 *
 * The tag field increments on every CAS to prevent ABA problems.
 * On 64-bit platforms this struct is 16 bytes, CAS'd atomically
 * via __int128 (x86-64 CMPXCHG16B) or LDXP/STXP (ARM64).
 */
struct depot_head {
    struct depot_node *node;
    uintptr_t          tag;
};

/*
 * struct cpu_depot — Per-CPU lock-free depot (v0.8)
 *
 * Each CPU gets its own pair of lock-free stacks (full/empty magazines)
 * to eliminate cross-CPU CAS contention on the depot layer.
 * Padded to 128 bytes to prevent false sharing between CPU depot slots.
 */
struct cpu_depot {
    _Atomic struct depot_head full;     /* Full magazines ready to use      */
    _Atomic struct depot_head empty;    /* Empty magazines for recycling    */
    _Atomic uint32_t          count;    /* Depot nodes in this CPU's depot  */
    char _pad[128 - 2 * sizeof(struct depot_head) - sizeof(_Atomic uint32_t)];
};

/*
 * struct slab_cache — Represents a cache for objects of a fixed size
 *
 * Analogous to struct kmem_cache in the Linux kernel.
 * Thread-safe: shared state protected by mutex, fast path uses magazines.
 * v0.7: Lock-free depot between per-thread magazines and shared slab lists.
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

    pthread_mutex_t   lock;         /* Protects slab lists and counters     */

    struct slab      *partial;      /* Slabs with some free objects         */
    struct slab      *full;         /* Slabs with no free objects           */
    struct slab      *free;         /* Completely empty slabs (cached)      */

    uint32_t          nr_slabs;     /* Total slabs allocated                */
    uint32_t          nr_partial;   /* Number of partial slabs              */
    uint32_t          nr_free;      /* Number of cached free slabs          */
    uint32_t          max_free;     /* Max free slabs to cache              */

    void (*ctor)(void *obj);        /* Optional object constructor          */
    void (*dtor)(void *obj);        /* Optional object destructor           */

    pthread_key_t     mag_key;      /* TLS key for per-thread magazine      */

    /* Per-CPU lock-free depots (v0.8) */
    struct cpu_depot  *cpu_depots;  /* Array[nr_cpus] of per-CPU depots    */
    uint32_t           nr_cpus;     /* Number of CPU depot slots           */

    struct slab_cache *next;        /* Global cache list                    */
};

/*
 * slab_cache_create — Create a new slab cache
 *
 * @name:     Name of the cache (for debugging)
 * @size:     Size of each object in bytes
 * @align:    Alignment requirement (0 for default)
 * @flags:    SLAB_RED_ZONE, SLAB_POISON, SLAB_NO_MAGAZINES, or 0
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
 * NOT thread-safe with concurrent alloc/free — call after joining threads.
 */
void slab_cache_destroy(struct slab_cache *cache);

/*
 * slab_alloc — Allocate one object from the cache (thread-safe)
 *
 * Fast path: pops from per-thread magazine (no lock).
 * Slow path: locks shared state, refills magazine from slab.
 */
void *slab_alloc(struct slab_cache *cache);

/*
 * slab_free — Free an object back to its cache (thread-safe)
 *
 * Fast path: pushes to per-thread magazine (no lock).
 * Slow path: locks shared state, flushes magazine batch to slab.
 */
void slab_free(struct slab_cache *cache, void *obj);

/*
 * slab_cache_shrink — Release all cached empty slabs back to the OS
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
