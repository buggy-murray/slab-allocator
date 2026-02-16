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

- **Lock-free magazine depot** — CAS-based shared magazine exchange (v0.7)

## Architecture

```
Thread 1                Thread 2                Thread N
    |                       |                       |
[Magazine]             [Magazine]              [Magazine]     ← Layer 1: TLS (no sync)
    |                       |                       |
    +--------+--------------+-----------+-----------+
                            |
                    ┌───────┴───────┐
                    │  Lock-Free    │
                    │    Depot      │                          ← Layer 2: CAS atomics
                    │ (full/empty   │
                    │  mag stacks)  │
                    └───────┬───────┘
                            |
                        [mutex]                               ← Layer 3: mutex
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
# Build and run benchmarks (requires libjemalloc-dev for jemalloc comparison)
gcc -O2 -std=c11 src/bench.c src/slab.c -o build/bench -lpthread -latomic -ljemalloc -ldl
./build/bench
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

### Multi-Threaded Churn (64 alloc + 64 free per round)

| Threads | slab (ns/op) | malloc (ns/op) | jemalloc (ns/op) |
|---------|-------------|----------------|-----------------|
| 1 | 3 | 2 | 3 |
| 4 | 3 | 1 | 1 |
| 8 | 6 | <1 | 1 |

**Key insight:** The slab allocator's warm steady-state performance (3.4 ns) beats
both malloc and jemalloc. The apparent slowness in bulk benchmarks is entirely from
one-time cold start costs (mmap, slab initialization). Magazine caching reduces
free latency by **400×** compared to no-magazine mode.

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

## License

MIT
