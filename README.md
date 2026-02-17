# Slab Allocator

A userspace slab allocator in C, inspired by the Linux kernel's SLUB allocator
and the Solaris magazine-based caching layer.

**Author:** G.H. Murray

## Features

- **O(1) alloc and free** via page-aligned slab lookup (pointer masking)
- **Per-thread magazine caching** — lock-free fast path for multithreaded workloads
- **Thread-safe** shared slab state with per-cache mutex
- **Debug features:**
  - Red zone detection (buffer overflow/underflow)
  - Poison detection (use-after-free)
- **Memory-efficient:** trimmed overallocation via munmap of leading/trailing waste
- **Slab shrinking:** release empty cached slabs to the OS on demand
- **Constructor/destructor** callbacks per object type

- **Lock-free per-CPU magazine depot** — CAS-based magazine exchange with per-CPU
  partitioning to eliminate cross-CPU contention (v0.7/v0.8)
- **Slab coloring** — rotate object offsets across slabs to reduce L1/L2 cache
  set conflicts (v0.9)
- **Generic kmalloc-style API** — `slab_kmalloc(size)` / `slab_kfree()` with
  power-of-2 size classes from 8 to 4096 bytes (v0.10)
- **Vmem arena allocator** — general-purpose resource manager with boundary tags,
  segregated free lists, and constrained allocation (v1.0)

## Architecture

```
Thread A (CPU 0)       Thread B (CPU 1)       Thread C (CPU 0)
    |                      |                      |
[TLS Magazine]        [TLS Magazine]         [TLS Magazine]    ← Layer 1: no sync
    |                      |                      |
[CPU 0 Depot]         [CPU 1 Depot]          [CPU 0 Depot]     ← Layer 2: per-CPU CAS
  full/empty            full/empty             (same depot)
    |                      |                      |
    +----------------------+----------------------+
                           |
                       [mutex]                                  ← Layer 3: mutex
                           |
                  +--------+--------+
                  | partial | full  |
                  |  slabs  | slabs |
                  +---------+-------+
                      slab_cache
```

**Fast path (no lock):** alloc pops from thread-local magazine; free pushes to it.

**Medium path (CAS):** magazine empty → swap with full magazine from depot; magazine full → swap with empty from depot.

**Slow path (mutex):** depot empty → fill new magazine from slab lists under lock.

**Thread exit:** magazines automatically flushed via `pthread_key` destructor.

## Building

```bash
make        # Build
make run    # Build and run tests
make clean  # Clean build artifacts
```

Requires: GCC (C11), pthreads, libatomic (ARM64), Linux/macOS with mmap support.

### Benchmarks

```bash
# Build and run benchmarks (jemalloc loaded via dlopen if available)
gcc -O2 -std=c11 src/bench.c src/slab.c -o build/bench -lpthread -latomic -ldl
./build/bench
```

### Vmem Tests

```bash
gcc -O2 -std=c11 src/vmem.c src/vmem_test.c -o build/vmem_test -lpthread
./build/vmem_test
```

## API

```c
#include "slab.h"

// Create a cache for 64-byte objects
struct slab_cache *cache = slab_cache_create("my_cache", 64, 0, 0, NULL, NULL);

// Allocate
void *obj = slab_alloc(cache);

// Free
slab_free(cache, obj);

// Release empty cached slabs to OS
slab_cache_shrink(cache);

// Print stats
slab_cache_stats(cache);

// Destroy cache (all objects must be freed first)
slab_cache_destroy(cache);

// --- Generic allocation (kmalloc-style, v0.10) ---
void *buf = slab_kmalloc(100);   // → routes to "size-128" cache
slab_kfree(buf, 100);

// --- Vmem arena (v1.0) ---
#include "vmem.h"

vmem_t *vm = vmem_create("my_arena", 0x10000, 0x100000, 4096);
uintptr_t addr;
vmem_alloc(vm, 8192, &addr);           // simple allocation
vmem_xalloc(vm, 4096, 4096, 0, 0,      // aligned allocation
            0, SIZE_MAX, &addr);
vmem_free(vm, addr, 4096);
vmem_destroy(vm);
```

### Flags

| Flag | Description |
|------|-------------|
| `SLAB_RED_ZONE` | Guard bytes around objects to detect overflow/underflow |
| `SLAB_POISON` | Poison freed objects to detect use-after-free |
| `SLAB_DEBUG` | Both red zones and poisoning |
| `SLAB_NO_MAGAZINES` | Disable per-thread caching (useful for debugging) |

## Performance

Measured on ARM64 (Docker, Linux 6.12, GCC 12, `-O2`). Object size: 64 bytes.

### Steady-State (warm, realistic workload)

| Allocator | ns/roundtrip (free+alloc) |
|-----------|--------------------------|
| **slab**  | **3.4** |
| malloc (glibc 2.36) | 5.5 |
| jemalloc 5.3 | ~6 |

### Bulk Operations (500K sequential, includes cold start)

| Allocator | Alloc (ns/op) | Free (ns/op) |
|-----------|---------------|--------------|
| slab (magazines) | 62 | 4 |
| slab (no magazines) | 46 | 1626 |
| malloc (glibc) | 5 | 6 |
| jemalloc | 8 | 6 |

### Multi-Threaded Churn (64 alloc + 64 free per round, v0.8 per-CPU depots)

| Threads | slab (ns/op) | malloc (ns/op) |
|---------|-------------|----------------|
| 1 | 3 | 5 |
| 2 | 2 | 3 |
| 4 | 1 | 1 |
| 8 | **1** | 1 |

**Key insights:**
- **Steady-state beats malloc:** 5 ns/roundtrip vs 6 ns for glibc malloc
- **Near-perfect MT scaling:** 1 ns/op at 8 threads with per-CPU depots
- Per-CPU depots (v0.8) eliminated the contention bottleneck — **6× improvement** over v0.7's global depot
- Magazine caching reduces free latency by **400×** vs no-magazine mode

## Design References

- Linux SLUB allocator (`mm/slub.c`)
- Bonwick's slab allocator (1994 USENIX paper)
- Bonwick & Adams' magazine layer (2001 USENIX paper)
- Windows NT pool allocator (WRK `ntos/ex/pool.c`)
- NT lookaside lists (per-CPU lock-free LIFO caches)

## Version History

| Version | Feature |
|---------|---------|
| v0.1 | Basic slab allocator with freelist, ctor/dtor |
| v0.2 | O(1) free via page-aligned mmap |
| v0.3 | Memory trim — munmap leading/trailing waste |
| v0.4 | Debug: red zones + poisoning |
| v0.5 | `slab_cache_shrink()` |
| v0.6 | Thread-safe with per-thread magazine caching |
| v0.7 | Lock-free magazine depot (C11 atomics, ABA-safe CAS) |
| v0.8 | Per-CPU depot partitioning (6× MT improvement) |
| v0.9 | Slab coloring for cache line conflict reduction |
| v0.10 | Generic kmalloc-style size-class API |
| v1.0 | Vmem arena allocator (boundary tags, instant-fit, constrained alloc) |

## License

MIT
