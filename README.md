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

## Architecture

```
Thread 1                Thread 2                Thread N
    |                       |                       |
[Magazine]             [Magazine]              [Magazine]
    |                       |                       |
    +--------+--------------+-----------+-----------+
             |                          |
         [mutex]                    [mutex]
             |                          |
    +--------+--------+       +--------+--------+
    | partial | full  |       | partial | full  |
    |  slabs  | slabs |       |  slabs  | slabs |
    +---------+-------+       +---------+-------+
         slab_cache A              slab_cache B
```

**Fast path (no lock):** alloc pops from thread-local magazine; free pushes to it.

**Slow path (locked):** magazine empty → batch-refill from slab; magazine full → batch-flush to slab.

**Thread exit:** magazines automatically flushed via `pthread_key` destructor.

## Building

```bash
make        # Build
make run    # Build and run tests
make clean  # Clean build artifacts
```

Requires: GCC, pthreads, Linux/macOS with mmap support.

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

Measured on ARM64 (Docker, Linux 6.12):

| Benchmark | Alloc | Free |
|-----------|-------|------|
| Single-threaded (magazines) | 59 ns | 137 ns |
| Single-threaded (no magazines) | 43 ns | 128 ns |
| 4 threads (magazines) | 84 ns/op | — |
| 4 threads (no magazines) | 96 ns/op | — |
| 8 threads churn (magazines) | 1 ns/op | — |

Magazine overhead in single-threaded is ~16ns (TLS lookup), but scales much
better under contention.

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

## License

MIT
