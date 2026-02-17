/*
 * vmem.c — General-purpose resource arena allocator
 *
 * Phase 1: Boundary tags + instant-fit segregated free lists.
 *
 * The arena manages opaque address ranges using a doubly-linked
 * ordered list of boundary tags. Free segments are indexed in
 * power-of-2 segregated free lists for O(1) average allocation.
 *
 * Thread safety: all operations protected by per-arena mutex.
 *
 * Author: G.H. Murray
 * Date:   2026-02-17
 */

#define _GNU_SOURCE
#include "vmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ──────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────── */

static inline size_t roundup(size_t val, size_t quantum)
{
    return (val + quantum - 1) & ~(quantum - 1);
}

/*
 * Free list bucket index for a given size.
 * Uses the position of the highest set bit (floor(log2(size))).
 * Capped to VMEM_FREELISTS - 1.
 */
static inline int freelist_index(size_t size)
{
    if (size == 0) return 0;
    int idx = 0;
    size_t s = size >> 1;
    while (s) { idx++; s >>= 1; }
    if (idx >= VMEM_FREELISTS)
        idx = VMEM_FREELISTS - 1;
    return idx;
}

/* ──────────────────────────────────────────────────────────────────
 * Boundary tag allocation (uses malloc for tag structs)
 * ────────────────────────────────────────────────────────────────── */

static struct vmem_bt *bt_alloc(void)
{
    struct vmem_bt *bt = calloc(1, sizeof(struct vmem_bt));
    return bt;
}

static void bt_free(struct vmem_bt *bt)
{
    free(bt);
}

/* ──────────────────────────────────────────────────────────────────
 * Segment list operations (ordered doubly-linked, circular)
 * ────────────────────────────────────────────────────────────────── */

/* Insert bt after prev in the segment list */
static void seg_insert_after(struct vmem_bt *prev, struct vmem_bt *bt)
{
    bt->seg_next = prev->seg_next;
    bt->seg_prev = prev;
    prev->seg_next->seg_prev = bt;
    prev->seg_next = bt;
}

/* Remove bt from the segment list */
static void seg_remove(struct vmem_bt *bt)
{
    bt->seg_prev->seg_next = bt->seg_next;
    bt->seg_next->seg_prev = bt->seg_prev;
    bt->seg_next = bt->seg_prev = NULL;
}

/* ──────────────────────────────────────────────────────────────────
 * Free list operations (segregated, doubly-linked per bucket)
 * ────────────────────────────────────────────────────────────────── */

/* Add a free BT to its appropriate free list bucket */
static void fl_insert(vmem_t *vm, struct vmem_bt *bt)
{
    assert(bt->type == BT_FREE);
    int idx = freelist_index(bt->size);
    struct vmem_bt *head = &vm->freelist[idx];

    bt->fl_next = head->fl_next;
    bt->fl_prev = head;
    head->fl_next->fl_prev = bt;
    head->fl_next = bt;

    vm->fl_bitmap |= (1U << idx);
}

/* Remove a free BT from its free list */
static void fl_remove(vmem_t *vm, struct vmem_bt *bt)
{
    bt->fl_prev->fl_next = bt->fl_next;
    bt->fl_next->fl_prev = bt->fl_prev;
    bt->fl_next = bt->fl_prev = NULL;

    /* Update bitmap if bucket is now empty */
    int idx = freelist_index(bt->size);
    struct vmem_bt *head = &vm->freelist[idx];
    if (head->fl_next == head)
        vm->fl_bitmap &= ~(1U << idx);
}

/* ──────────────────────────────────────────────────────────────────
 * Coalescing
 * ────────────────────────────────────────────────────────────────── */

/*
 * Try to merge bt with its neighbors in the segment list.
 * bt must be BT_FREE. Merges with adjacent BT_FREE segments.
 * Returns the (possibly merged) surviving tag.
 */
static struct vmem_bt *bt_coalesce(vmem_t *vm, struct vmem_bt *bt)
{
    struct vmem_bt *next = bt->seg_next;
    struct vmem_bt *prev = bt->seg_prev;

    /* Merge with next if it's free */
    if (next != &vm->seglist && next->type == BT_FREE) {
        fl_remove(vm, next);
        bt->size += next->size;
        seg_remove(next);
        bt_free(next);
    }

    /* Merge with prev if it's free */
    if (prev != &vm->seglist && prev->type == BT_FREE) {
        fl_remove(vm, prev);
        prev->size += bt->size;
        fl_remove(vm, bt);
        seg_remove(bt);
        bt_free(bt);
        bt = prev;
        /* Re-insert merged tag into correct free list */
        fl_insert(vm, bt);
    }

    return bt;
}

/* ──────────────────────────────────────────────────────────────────
 * Public API
 * ────────────────────────────────────────────────────────────────── */

vmem_t *vmem_create(const char *name, uintptr_t base, size_t size,
                    size_t quantum, vmem_import_fn import_fn,
                    vmem_release_fn release_fn, void *import_arg,
                    size_t import_quantum)
{
    if (quantum == 0) quantum = 1;

    vmem_t *vm = calloc(1, sizeof(vmem_t));
    if (!vm) return NULL;

    vm->name    = name;
    vm->quantum = quantum;
    vm->import_fn  = import_fn;
    vm->release_fn = release_fn;
    vm->import_arg = import_arg;
    vm->import_quantum = import_quantum > 0 ? import_quantum : quantum;

    /* Initialize segment list sentinel (circular) */
    vm->seglist.seg_next = &vm->seglist;
    vm->seglist.seg_prev = &vm->seglist;

    /* Initialize free list sentinels (each is circular) */
    for (int i = 0; i < VMEM_FREELISTS; i++) {
        vm->freelist[i].fl_next = &vm->freelist[i];
        vm->freelist[i].fl_prev = &vm->freelist[i];
    }
    vm->fl_bitmap = 0;

    pthread_mutex_init(&vm->lock, NULL);

    /* Add initial span if provided */
    if (size > 0) {
        if (vmem_add(vm, base, size) != 0) {
            pthread_mutex_destroy(&vm->lock);
            free(vm);
            return NULL;
        }
    }

    return vm;
}

void vmem_destroy(vmem_t *vm)
{
    if (!vm) return;

    pthread_mutex_lock(&vm->lock);

    if (vm->n_allocs > 0) {
        fprintf(stderr, "vmem: WARNING: destroying arena '%s' with %u active allocations "
                "(%zu bytes leaked)\n", vm->name, vm->n_allocs, vm->alloc_size);
    }

    /* Free all boundary tags */
    struct vmem_bt *bt = vm->seglist.seg_next;
    while (bt != &vm->seglist) {
        struct vmem_bt *next = bt->seg_next;
        bt_free(bt);
        bt = next;
    }

    pthread_mutex_unlock(&vm->lock);
    pthread_mutex_destroy(&vm->lock);
    free(vm);
}

int vmem_add(vmem_t *vm, uintptr_t addr, size_t size)
{
    if (size == 0) return -1;

    size = roundup(size, vm->quantum);

    /* Create span marker */
    struct vmem_bt *span = bt_alloc();
    if (!span) return -1;
    span->base = addr;
    span->size = size;
    span->type = BT_SPAN;

    /* Create free segment for the span */
    struct vmem_bt *free_bt = bt_alloc();
    if (!free_bt) {
        bt_free(span);
        return -1;
    }
    free_bt->base = addr;
    free_bt->size = size;
    free_bt->type = BT_FREE;

    pthread_mutex_lock(&vm->lock);

    /* Insert at end of segment list */
    seg_insert_after(vm->seglist.seg_prev, span);
    seg_insert_after(span, free_bt);

    /* Add to free list */
    fl_insert(vm, free_bt);

    vm->total_size += size;
    vm->free_size  += size;
    vm->n_spans++;

    pthread_mutex_unlock(&vm->lock);
    return 0;
}

int vmem_alloc(vmem_t *vm, size_t size, uintptr_t *addrp)
{
    if (size == 0 || !addrp) return -1;
    size = roundup(size, vm->quantum);

    pthread_mutex_lock(&vm->lock);

    /* Instant-fit: find the smallest bucket that can satisfy */
    int idx = freelist_index(size);
    uint32_t mask = vm->fl_bitmap & ~((1U << idx) - 1);  /* buckets >= idx */

    struct vmem_bt *best = NULL;

    while (mask) {
        int bucket = __builtin_ctz(mask);  /* lowest set bit */
        struct vmem_bt *head = &vm->freelist[bucket];

        /* Search this bucket for best fit */
        for (struct vmem_bt *bt = head->fl_next; bt != head; bt = bt->fl_next) {
            if (bt->size >= size) {
                if (!best || bt->size < best->size) {
                    best = bt;
                    if (bt->size == size) goto found;  /* exact match */
                }
            }
        }

        if (best) goto found;
        mask &= mask - 1;  /* clear lowest bit, try next bucket */
    }

    /* No fit found — try importing more resource */
    if (vm->import_fn) {
        size_t import_size = size;
        if (import_size < vm->import_quantum)
            import_size = vm->import_quantum;
        import_size = roundup(import_size, vm->quantum);

        uintptr_t import_addr;
        size_t actual_size = import_size;

        /* Must unlock before calling import (it may call mmap etc.) */
        pthread_mutex_unlock(&vm->lock);

        if (vm->import_fn(vm->import_arg, import_size, &import_addr, &actual_size) == 0) {
            vmem_add(vm, import_addr, actual_size);
            /* Retry the allocation */
            return vmem_alloc(vm, size, addrp);
        }
    } else {
        pthread_mutex_unlock(&vm->lock);
    }
    return -1;

found:
    fl_remove(vm, best);

    if (best->size > size) {
        /* Split: create a new free BT for the remainder */
        struct vmem_bt *remainder = bt_alloc();
        if (remainder) {
            remainder->base = best->base + size;
            remainder->size = best->size - size;
            remainder->type = BT_FREE;
            seg_insert_after(best, remainder);
            fl_insert(vm, remainder);
            best->size = size;
        }
        /* If bt_alloc fails, just allocate the whole segment (waste, but safe) */
    }

    best->type = BT_ALLOC;
    *addrp = best->base;

    vm->alloc_size += best->size;
    vm->free_size  -= best->size;
    vm->n_allocs++;

    pthread_mutex_unlock(&vm->lock);
    return 0;
}

void vmem_free(vmem_t *vm, uintptr_t addr, size_t size)
{
    if (!vm) return;
    size = roundup(size, vm->quantum);

    pthread_mutex_lock(&vm->lock);

    /* Find the matching BT_ALLOC tag */
    struct vmem_bt *bt = vm->seglist.seg_next;
    while (bt != &vm->seglist) {
        if (bt->type == BT_ALLOC && bt->base == addr) {
            if (bt->size != size) {
                fprintf(stderr, "vmem: WARNING: free size mismatch in '%s': "
                        "addr=%#lx expected=%zu got=%zu\n",
                        vm->name, (unsigned long)addr, bt->size, size);
            }
            break;
        }
        bt = bt->seg_next;
    }

    if (bt == &vm->seglist) {
        fprintf(stderr, "vmem: ERROR: free of unknown addr %#lx in arena '%s'\n",
                (unsigned long)addr, vm->name);
        pthread_mutex_unlock(&vm->lock);
        return;
    }

    bt->type = BT_FREE;
    vm->alloc_size -= bt->size;
    vm->free_size  += bt->size;
    vm->n_allocs--;

    fl_insert(vm, bt);
    bt_coalesce(vm, bt);

    pthread_mutex_unlock(&vm->lock);
}

int vmem_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase,
                size_t nocross, uintptr_t minaddr, uintptr_t maxaddr,
                uintptr_t *addrp)
{
    if (size == 0 || !addrp) return -1;
    size = roundup(size, vm->quantum);
    if (align == 0) align = vm->quantum;

    pthread_mutex_lock(&vm->lock);

    struct vmem_bt *best = NULL;
    uintptr_t best_addr = 0;
    size_t best_waste = SIZE_MAX;

    /* Walk all free segments, find best constrained fit */
    for (int i = 0; i < VMEM_FREELISTS; i++) {
        struct vmem_bt *head = &vm->freelist[i];
        for (struct vmem_bt *bt = head->fl_next; bt != head; bt = bt->fl_next) {
            /* Compute aligned start within this segment */
            uintptr_t start = bt->base;

            /* Apply minimum address constraint */
            if (start < minaddr) start = minaddr;

            /* Align: start = ceil(start - phase, align) + phase */
            if (phase < align) {
                uintptr_t adj = start - phase;
                adj = (adj + align - 1) & ~(align - 1);
                start = adj + phase;
            }

            /* Check if allocation fits */
            if (start < bt->base) continue;
            if (start + size > bt->base + bt->size) continue;

            /* Max address constraint */
            if (maxaddr != 0 && maxaddr != SIZE_MAX) {
                if (start + size - 1 > maxaddr) continue;
            }

            /* No-cross boundary constraint */
            if (nocross > 0) {
                uintptr_t cross_boundary = (start / nocross + 1) * nocross;
                if (start + size > cross_boundary) continue;
            }

            size_t waste = (start - bt->base) + (bt->size - (start - bt->base + size));
            if (waste < best_waste) {
                best = bt;
                best_addr = start;
                best_waste = waste;
                if (waste == 0) break;
            }
        }
        if (best && best_waste == 0) break;
    }

    if (!best) {
        /* Try importing more resource */
        if (vm->import_fn) {
            /* Need at least size + alignment overhead */
            size_t import_size = size + align;
            if (import_size < vm->import_quantum)
                import_size = vm->import_quantum;
            import_size = roundup(import_size, vm->quantum);

            uintptr_t import_addr;
            size_t actual_size = import_size;

            pthread_mutex_unlock(&vm->lock);

            if (vm->import_fn(vm->import_arg, import_size, &import_addr, &actual_size) == 0) {
                vmem_add(vm, import_addr, actual_size);
                return vmem_xalloc(vm, size, align, phase, nocross,
                                   minaddr, maxaddr, addrp);
            }
        } else {
            pthread_mutex_unlock(&vm->lock);
        }
        return -1;
    }

    fl_remove(vm, best);

    /* Split front if aligned start is past segment start */
    if (best_addr > best->base) {
        struct vmem_bt *front = bt_alloc();
        if (front) {
            front->base = best->base;
            front->size = best_addr - best->base;
            front->type = BT_FREE;
            seg_insert_after(best->seg_prev, front);
            fl_insert(vm, front);
            best->base = best_addr;
            best->size -= front->size;
        }
    }

    /* Split tail if there's remainder */
    if (best->size > size) {
        struct vmem_bt *tail = bt_alloc();
        if (tail) {
            tail->base = best->base + size;
            tail->size = best->size - size;
            tail->type = BT_FREE;
            seg_insert_after(best, tail);
            fl_insert(vm, tail);
            best->size = size;
        }
    }

    best->type = BT_ALLOC;
    *addrp = best->base;

    vm->alloc_size += best->size;
    vm->free_size  -= best->size;
    vm->n_allocs++;

    pthread_mutex_unlock(&vm->lock);
    return 0;
}

void vmem_xfree(vmem_t *vm, uintptr_t addr, size_t size)
{
    vmem_free(vm, addr, size);
}

void vmem_stats(const vmem_t *vm)
{
    if (!vm) return;

    fprintf(stderr,
        "vmem arena '%s':\n"
        "  quantum=%zu\n"
        "  spans=%u, allocs=%u\n"
        "  total=%zu, allocated=%zu, free=%zu (%.1f%% used)\n",
        vm->name,
        vm->quantum,
        vm->n_spans, vm->n_allocs,
        vm->total_size, vm->alloc_size, vm->free_size,
        vm->total_size ? (100.0 * vm->alloc_size / vm->total_size) : 0.0);
}
