# box64_memleak.py

Tracks `customMalloc` / `customFree` / `customCalloc` / `customRealloc` to
detect memory leaks in Box64's custom allocator. Outstanding allocations at
exit are potential leaks.

## Usage

```bash
sudo python3 box64_memleak.py [options]
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-b`, `--binary` | `/usr/local/bin/box64` | Path to the box64 binary |
| `-p`, `--pid` | `0` (all) | Filter by PID; 0 traces all box64 processes |
| `-i`, `--interval` | `15` | Periodic summary interval in seconds |
| `-t`, `--top` | `20` | Number of top outstanding allocations to show in the final report |
| `--mmap` | off | Also track `InternalMmap` / `InternalMunmap` |
| `--stacks` | off | Capture user-space stack traces for each allocation (higher overhead) |
| `--32bit` | off | Also track 32-bit variants (`customMalloc32`, `customFree32`, etc.) |
| `--no-threads` | off | Disable thread/process lifecycle tracking (`pthread_create`, `fork`, `clone`) |
| `--no-cow` | off | Disable copy-on-write page fault tracking (kprobe + `/proc` sampling) |
| `--hash-capacity` | `524288` | BPF hash table size for tracking outstanding allocations; increase if you see "HASH TABLE FULL" warnings |

## Examples

```bash
# Basic leak detection for a specific process
sudo python3 box64_memleak.py -p 12345

# Full tracking: mmap, stacks, 32-bit, top 50
sudo python3 box64_memleak.py --mmap --stacks --32bit -t 50

# Minimal overhead: no thread tracking
sudo python3 box64_memleak.py -b ~/box64/build/box64 --no-threads -i 5

# Minimal overhead: no thread or CoW tracking
sudo python3 box64_memleak.py -b ~/box64/build/box64 --no-threads --no-cow -i 5
```

## Output

**Periodic summaries** (every `--interval` seconds) show:

- malloc / free / calloc / realloc counts for the interval
- Bytes allocated and freed in the interval
- Outstanding allocation count and net bytes
- mmap / munmap counts and outstanding mmaps (if `--mmap`)
- Thread counts: active, created, destroyed, peak, forks, clones (unless `--no-threads`)

**Final report** (on Ctrl+C) includes:

- Cumulative totals for all allocation types
- Total outstanding allocations and bytes
- **Size distribution** -- histogram of outstanding allocation sizes
- **Top N outstanding allocations** by size (pointer, size, age, type, 32-bit flag, PID, TID)
- **Stack traces** for each listed allocation (if `--stacks`)
- **Outstanding mmaps** with addresses, sizes, and PIDs (if `--mmap`)
- **Process/Thread Tree** -- hierarchical view showing which thread created which, with per-thread allocation stats (unless `--no-threads`)
- **Thread summary** -- total created/destroyed, peak concurrent, fork/clone counts (unless `--no-threads`)
- **Top N threads by allocation volume** -- TID, alloc count, bytes, x64 start routine, PID (unless `--no-threads`)
- **Copy-on-Write Analysis** (when fork/clone detected) -- `/proc`-based RSS and Private_Dirty snapshots at fork time vs current, with minor fault deltas. Also shows per-PID CoW page fault counts from kernel kprobe with estimated bytes copied (unless `--no-cow`).

## Required symbols

`customMalloc`, `customFree`, `customCalloc`, `customRealloc`. With `--mmap`:
`InternalMmap`, `InternalMunmap`. With `--32bit`: `customMalloc32`,
`customFree32`, `customCalloc32`, `customRealloc32`. Thread tracking
(enabled by default) requires `my_pthread_create`, `pthread_routine`,
`emuthread_destroy` (auto-disabled if missing). Fork/clone tracking
additionally uses `my_fork`, `my_clone` (skipped if missing). Clone child PID
tracking uses a `my_clone` uretprobe. CoW kprobe tracking (enabled by default) attaches
to `wp_page_copy` (falls back to `do_wp_page`).
