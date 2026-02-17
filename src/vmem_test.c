/*
 * vmem_test.c — Tests for the vmem arena allocator
 *
 * Author: G.H. Murray
 * Date:   2026-02-17
 */

#define _GNU_SOURCE
#include "vmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

static void test_basic(void)
{
    printf("=== test_basic ===\n");

    vmem_t *vm = vmem_create("test", 0x1000, 0x10000, 64);
    assert(vm != NULL);

    uintptr_t addr;
    int rc = vmem_alloc(vm, 256, &addr);
    assert(rc == 0);
    assert(addr == 0x1000);  /* first allocation at base */
    printf("  alloc 256 → %#lx\n", (unsigned long)addr);

    uintptr_t addr2;
    rc = vmem_alloc(vm, 512, &addr2);
    assert(rc == 0);
    assert(addr2 == 0x1000 + 256);  /* next one after first */
    printf("  alloc 512 → %#lx\n", (unsigned long)addr2);

    vmem_free(vm, addr, 256);
    vmem_free(vm, addr2, 512);

    vmem_stats(vm);
    vmem_destroy(vm);
    printf("  PASSED\n\n");
}

static void test_coalesce(void)
{
    printf("=== test_coalesce ===\n");

    vmem_t *vm = vmem_create("coalesce", 0, 4096, 64);
    assert(vm != NULL);

    /* Allocate 3 adjacent blocks */
    uintptr_t a, b, c;
    assert(vmem_alloc(vm, 64, &a) == 0);
    assert(vmem_alloc(vm, 64, &b) == 0);
    assert(vmem_alloc(vm, 64, &c) == 0);

    printf("  a=%#lx b=%#lx c=%#lx\n",
           (unsigned long)a, (unsigned long)b, (unsigned long)c);

    /* Free middle, then sides — should coalesce */
    vmem_free(vm, b, 64);
    vmem_free(vm, a, 64);
    vmem_free(vm, c, 64);

    /* Now the entire region should be one free segment again.
     * Allocate the full original span minus what's used by tags. */
    uintptr_t big;
    assert(vmem_alloc(vm, 192, &big) == 0);
    assert(big == 0);  /* coalesced back to start */
    printf("  coalesced alloc 192 → %#lx\n", (unsigned long)big);

    vmem_free(vm, big, 192);
    vmem_destroy(vm);
    printf("  PASSED\n\n");
}

static void test_exhaustion(void)
{
    printf("=== test_exhaustion ===\n");

    vmem_t *vm = vmem_create("exhaust", 0, 256, 64);
    assert(vm != NULL);

    /* Fill the arena */
    uintptr_t ptrs[4];
    for (int i = 0; i < 4; i++) {
        assert(vmem_alloc(vm, 64, &ptrs[i]) == 0);
    }

    /* Should fail — full */
    uintptr_t fail;
    assert(vmem_alloc(vm, 64, &fail) == -1);
    printf("  correctly refused allocation from full arena\n");

    /* Free one and retry */
    vmem_free(vm, ptrs[2], 64);
    assert(vmem_alloc(vm, 64, &fail) == 0);
    assert(fail == ptrs[2]);  /* should reuse freed slot */
    printf("  reused freed slot at %#lx\n", (unsigned long)fail);

    vmem_free(vm, ptrs[0], 64);
    vmem_free(vm, ptrs[1], 64);
    vmem_free(vm, fail, 64);
    vmem_free(vm, ptrs[3], 64);
    vmem_destroy(vm);
    printf("  PASSED\n\n");
}

static void test_add_span(void)
{
    printf("=== test_add_span ===\n");

    vmem_t *vm = vmem_create("spans", 0, 128, 64);
    assert(vm != NULL);

    /* Fill initial span */
    uintptr_t a, b;
    assert(vmem_alloc(vm, 64, &a) == 0);
    assert(vmem_alloc(vm, 64, &b) == 0);

    uintptr_t fail;
    assert(vmem_alloc(vm, 64, &fail) == -1);

    /* Add a second span */
    assert(vmem_add(vm, 0x10000, 256) == 0);

    uintptr_t c;
    assert(vmem_alloc(vm, 64, &c) == 0);
    assert(c == 0x10000);
    printf("  allocated from second span: %#lx\n", (unsigned long)c);

    vmem_stats(vm);

    vmem_free(vm, a, 64);
    vmem_free(vm, b, 64);
    vmem_free(vm, c, 64);
    vmem_destroy(vm);
    printf("  PASSED\n\n");
}

static void test_xalloc_align(void)
{
    printf("=== test_xalloc_align ===\n");

    vmem_t *vm = vmem_create("xalloc", 0x100, 0x10000, 1);
    assert(vm != NULL);

    /* Allocate with 4096-byte alignment */
    uintptr_t addr;
    int rc = vmem_xalloc(vm, 256, 4096, 0, 0, 0, SIZE_MAX, &addr);
    assert(rc == 0);
    assert((addr & 0xFFF) == 0);  /* 4K aligned */
    printf("  xalloc align=4096 → %#lx\n", (unsigned long)addr);

    /* Allocate with alignment + phase */
    uintptr_t addr2;
    rc = vmem_xalloc(vm, 64, 256, 8, 0, 0, SIZE_MAX, &addr2);
    assert(rc == 0);
    assert(((addr2 - 8) % 256) == 0);  /* phase 8 from 256 boundary */
    printf("  xalloc align=256 phase=8 → %#lx\n", (unsigned long)addr2);

    vmem_xfree(vm, addr, 256);
    vmem_xfree(vm, addr2, 64);
    vmem_destroy(vm);
    printf("  PASSED\n\n");
}

static void test_best_fit(void)
{
    printf("=== test_best_fit ===\n");

    vmem_t *vm = vmem_create("bestfit", 0, 1024, 64);
    assert(vm != NULL);

    /* Create fragmented layout: [alloc 64][free 128][alloc 64][free 256]... */
    uintptr_t a1, a2, a3, a4;
    assert(vmem_alloc(vm, 64, &a1) == 0);
    assert(vmem_alloc(vm, 128, &a2) == 0);
    assert(vmem_alloc(vm, 64, &a3) == 0);
    assert(vmem_alloc(vm, 256, &a4) == 0);

    /* Free the 128 and 256 blocks, creating two holes */
    vmem_free(vm, a2, 128);
    vmem_free(vm, a4, 256);

    /* Allocate 64 — should pick the 128-byte hole (best fit), not the 256 one */
    uintptr_t best;
    assert(vmem_alloc(vm, 64, &best) == 0);
    assert(best == a2);  /* fits in the 128-byte hole */
    printf("  best-fit picked %#lx (128-byte hole) over 256-byte hole\n",
           (unsigned long)best);

    vmem_free(vm, a1, 64);
    vmem_free(vm, best, 64);
    vmem_free(vm, a3, 64);
    vmem_destroy(vm);
    printf("  PASSED\n\n");
}

int main(void)
{
    printf("Vmem Arena Allocator Test Suite\n");
    printf("================================\n\n");

    test_basic();
    test_coalesce();
    test_exhaustion();
    test_add_span();
    test_xalloc_align();
    test_best_fit();

    printf("All vmem tests passed.\n");
    return 0;
}
