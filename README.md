# Slab Allocator

A userspace slab allocator in C, inspired by the Linux kernel's SLUB allocator and the Windows NT kernel pool.

## Features

- **O(1) alloc and free** — page-aligned slabs enable constant-time slab lookup via pointer masking
- **Constructor/destructor callbacks** — called on alloc/free, like `kmem_cache` in Linux
- **Red zone detection** — 8-byte guard regions detect buffer overflows and underflows
- **Poison detection** — freed objects filled with `0x6B` to catch use-after-free
- **Cache shrinking** — release empty slabs back to the OS on demand
- **Memory-efficient alignment** — overallocation waste trimmed via `munmap`

## Building

```bash
make        # build
make run    # build and run tests
make clean  # clean build artifacts
```

## Design

Each `slab_cache` manages objects of a fixed size. Slabs are allocated via `mmap`, aligned to their own size boundary. This alignment enables O(1) free: given any object pointer, mask off the low bits to find the slab header.

```c
struct slab *s = (struct slab *)((uintptr_t)obj & ~(slab_size - 1));
```

Debug features (`SLAB_RED_ZONE`, `SLAB_POISON`) can be enabled per-cache via flags.

## References

- Jeff Bonwick, "The Slab Allocator: An Object-Caching Kernel Memory Allocator" (USENIX 1994)
- Linux kernel SLUB allocator (`mm/slub.c`)
- Tarjei Mandt, "Kernel Pool Exploitation on Windows 7" (Black Hat DC 2011)

## Author

G.H. Murray — [buggy-murray.github.io](https://buggy-murray.github.io)
