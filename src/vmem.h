/*
 * vmem.h — General-purpose resource arena allocator
 *
 * Based on the vmem design by Jeff Bonwick & Jonathan Adams (USENIX 2001).
 * Manages opaque numerical ranges using boundary tags.
 *
 * Phase 1: Basic boundary tag allocator with best-fit.
 *
 * Author: G.H. Murray
 * Date:   2026-02-17
 */

#ifndef VMEM_H
#define VMEM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/* Maximum number of free-list buckets for instant-fit (Phase 2) */
#define VMEM_FREELISTS      32

/* Boundary tag types */
enum vmem_bt_type {
    BT_SPAN,        /* Start marker for an imported span          */
    BT_FREE,        /* Free segment available for allocation       */
    BT_ALLOC,       /* Allocated segment                          */
};

/*
 * struct vmem_bt — Boundary tag
 *
 * Describes a contiguous segment of the arena's resource space.
 * Tags form a doubly-linked ordered list covering the entire arena.
 */
struct vmem_bt {
    struct vmem_bt  *seg_next;  /* Next in segment list (ordered)   */
    struct vmem_bt  *seg_prev;  /* Prev in segment list (ordered)   */
    struct vmem_bt  *fl_next;   /* Next in free list (Phase 2)      */
    struct vmem_bt  *fl_prev;   /* Prev in free list (Phase 2)      */
    uintptr_t        base;      /* Start address of segment         */
    size_t           size;      /* Size of segment                  */
    enum vmem_bt_type type;     /* BT_SPAN, BT_FREE, or BT_ALLOC   */
};

/*
 * struct vmem — Arena descriptor
 */
typedef struct vmem {
    const char      *name;          /* Human-readable name              */
    size_t           quantum;       /* Minimum allocation unit          */

    /* Ordered segment list (circular doubly-linked, sentinel head) */
    struct vmem_bt   seglist;       /* Sentinel node                    */

    /* Free list for best-fit search (Phase 1: single unsorted list) */
    /* Phase 2: segregated free lists with bitmap */
    struct vmem_bt   freelist[VMEM_FREELISTS];
    uint32_t         fl_bitmap;     /* Bitmap of non-empty free lists   */

    /* Statistics */
    size_t           total_size;    /* Total resource under management  */
    size_t           alloc_size;    /* Currently allocated               */
    size_t           free_size;     /* Currently free                    */
    uint32_t         n_spans;       /* Number of spans                   */
    uint32_t         n_allocs;      /* Number of active allocations      */

    pthread_mutex_t  lock;          /* Protects all arena state          */
} vmem_t;

/*
 * vmem_create — Create a new arena
 *
 * @name:    Name for debugging
 * @base:    Start address of initial span (0 if none)
 * @size:    Size of initial span (0 if none)
 * @quantum: Minimum allocation unit (all sizes rounded up to quantum)
 *
 * Returns arena pointer, or NULL on failure.
 */
vmem_t *vmem_create(const char *name, uintptr_t base, size_t size,
                    size_t quantum);

/*
 * vmem_destroy — Destroy an arena and free all boundary tags
 *
 * The arena should have no active allocations (will warn if it does).
 */
void vmem_destroy(vmem_t *vm);

/*
 * vmem_add — Add a span of resource to the arena
 *
 * @addr: Start address of the new span
 * @size: Size of the new span (must be >= quantum)
 *
 * Returns 0 on success, -1 on failure.
 */
int vmem_add(vmem_t *vm, uintptr_t addr, size_t size);

/*
 * vmem_alloc — Allocate a resource from the arena
 *
 * @size:  Size to allocate (rounded up to quantum)
 * @addrp: On success, set to start address of allocation
 *
 * Returns 0 on success, -1 on failure (no space).
 */
int vmem_alloc(vmem_t *vm, size_t size, uintptr_t *addrp);

/*
 * vmem_free — Free a resource back to the arena
 *
 * @addr: Start address (must match a previous vmem_alloc return)
 * @size: Size (must match the size passed to vmem_alloc)
 */
void vmem_free(vmem_t *vm, uintptr_t addr, size_t size);

/*
 * vmem_xalloc — Constrained allocation
 *
 * @size:    Size to allocate
 * @align:   Alignment requirement (0 = don't care)
 * @phase:   Offset from alignment boundary (0 = no phase)
 * @nocross: Don't cross this boundary (0 = don't care)
 * @minaddr: Minimum acceptable address (0 = don't care)
 * @maxaddr: Maximum acceptable address (SIZE_MAX = don't care)
 * @addrp:   On success, set to allocated address
 *
 * Returns 0 on success, -1 on failure.
 */
int vmem_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase,
                size_t nocross, uintptr_t minaddr, uintptr_t maxaddr,
                uintptr_t *addrp);

/*
 * vmem_xfree — Free a constrained allocation
 */
void vmem_xfree(vmem_t *vm, uintptr_t addr, size_t size);

/*
 * vmem_stats — Print arena statistics to stderr
 */
void vmem_stats(const vmem_t *vm);

#endif /* VMEM_H */
