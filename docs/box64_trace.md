# box64_trace.py

Traces Box64's behavior across **all concurrent box64 processes** during a Steam
gaming session. Tracks fork/exec/vfork process lifecycle, per-PID memory usage
(custom allocator, DynaRec JIT with churn/lifetime/protection analysis, mmap),
context creation/destruction, and pressure-vessel container detection. Designed
for understanding memory behavior when Steam spawns 5-10+ concurrent box64
instances.

See also: [`BOX64_FORK_EXEC_MEMORY.md`](BOX64_FORK_EXEC_MEMORY.md) for detailed
documentation on how fork/exec/memory functions work in box64.

## Usage

```bash
sudo python3 box64_trace.py [options]
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-b`, `--binary` | `/usr/local/bin/box64` | Path to the box64 binary |
| `-p`, `--pid` | `0` (all) | Filter by PID; 0 traces all box64 processes |
| `-i`, `--interval` | `15` | Periodic summary interval in seconds |
| `--no-mem` | off | Skip `customMalloc`/`customFree`/`customCalloc`/`customRealloc` tracking |
| `--no-dynarec` | off | Skip `AllocDynarecMap`/`FreeDynarecMap` tracking (also disables churn/histogram/protection) |
| `--no-prot` | off | Skip `protectDB`/`unprotectDB`/`setProtection` tracking (lower overhead; only when dynarec enabled) |
| `--no-block-detail` | off | Skip `FreeDynablock`/`InvalidDynablock`/`MarkDynablock` tracking (requires dynarec enabled) |
| `--churn-threshold` | `1.0` | JIT blocks freed within this many seconds count as "churn" |
| `--no-mmap` | off | Skip `InternalMmap`/`InternalMunmap`/`box_mmap`/`box_munmap` tracking |
| `--no-threads` | off | Disable thread/process lifecycle tracking |
| `--no-cow` | off | Disable copy-on-write page fault tracking |
| `--hash-capacity` | `524288` | BPF hash table size for outstanding allocation tracking |
| `--sample-freq` | `0` (off) | PC sampling frequency in Hz; attaches perf event for JIT code profiling (requires `-p PID`) |

## Examples

```bash
# Trace all box64 processes (typical Steam session)
sudo python3 box64_trace.py

# Trace with custom binary path and 5-second summaries
sudo python3 box64_trace.py -b ~/box64/build/box64 -i 5

# Focus on fork/exec lifecycle only (minimal overhead)
sudo python3 box64_trace.py --no-mem --no-dynarec --no-mmap --no-threads --no-cow

# Trace a specific box64 process with full tracking
sudo python3 box64_trace.py -p 12345

# DynaRec-focused: 2s churn threshold, skip protection overhead
sudo python3 box64_trace.py --no-mem --no-mmap --churn-threshold 2.0 --no-prot
```

## Output

**Periodic summaries** (every `--interval` seconds) show:

- Fork/vfork/exec/posix_spawn/context counts for the interval
- Custom allocator: malloc/free/calloc/realloc counts and bytes (unless `--no-mem`)
- DynaRec JIT: alloc/free/churn counts, bytes allocated/freed/outstanding, hash table capacity (unless `--no-dynarec`)
- Protection: protectDB/unprotectDB/setProtection call counts and cumulative bytes (unless `--no-prot`)
- Mmap: internal/box mmap/munmap counts (unless `--no-mmap`)
- Thread counts: active, created, destroyed, peak, forks, clones (unless `--no-threads`)
- Per-PID `/proc` RSS/PSS snapshot for every tracked box64 process

**Real-time events** printed as they occur:

- `pressure_vessel()` detection with program path
- `x64emu_fork` calls with forktype (fork/vfork/forkpty)

**Final report** (on Ctrl+C) includes:

- **Lifecycle totals** -- fork, vfork, exec, posix_spawn, context new/free, pressure_vessel counts
- **Custom allocator totals** -- malloc/free/calloc/realloc counts and bytes (unless `--no-mem`)
- **DynaRec JIT totals** -- alloc/free/churn counts, bytes, outstanding (unless `--no-dynarec`)
- **Protection overhead** -- protectDB/unprotectDB/setProtection call counts and cumulative bytes (unless `--no-prot`)
- **Allocation size distribution** -- log2 histogram of JIT block sizes (unless `--no-dynarec`)
- **Block lifetime distribution** -- log2 histogram of how long JIT blocks lived before being freed (unless `--no-dynarec`)
- **Top 20 outstanding JIT blocks** by size -- alloc address, x64 address, size, is_new flag, PID (unless `--no-dynarec`)
- **Top 20 churned x64 addresses** -- addresses most frequently re-compiled within the churn threshold (unless `--no-dynarec`)
- **Mmap totals** -- InternalMmap/munmap and box_mmap/munmap counts (unless `--no-mmap`)
- **Process tree** -- Unicode box-drawing tree of parent-child box64 processes with labels and RSS
- **Fork/exec event timeline** -- Chronological table with relative timestamps, PID, event type, target binary
- **Per-PID memory breakdown** -- For each box64 process: custom alloc stats, JIT stats, mmap stats, context lifecycle, latest RSS/PSS/Private_Dirty
- **Memory growth timeline** -- Per-PID RSS snapshots over time showing memory growth patterns
- **Process/thread tree** -- Hierarchical thread view with per-thread allocation stats (unless `--no-threads`)
- **Top 10 threads by allocation volume** -- TID, alloc count, bytes, x64 start routine, PID (unless `--no-threads`)
- **Copy-on-Write analysis** -- `/proc`-based RSS and Private_Dirty snapshots at fork time vs current, with minor fault deltas. Per-PID CoW page fault counts from kernel kprobe (unless `--no-cow`).

## Required symbols

Core (always required): `my_fork`, `my_vfork`, `x64emu_fork`, `my_execve`,
`my_execv`, `my_execvp`, `NewBox64Context`, `FreeBox64Context`, `CalcStackSize`.

Optional (auto-detected): `my_execvpe`, `my_posix_spawn`, `my_posix_spawnp`,
`pressure_vessel` (skipped if missing).

Memory tracking (`--no-mem` to disable): `customMalloc`, `customFree`,
`customCalloc`, `customRealloc` (auto-disabled if missing).

DynaRec tracking (`--no-dynarec` to disable): `AllocDynarecMap`,
`FreeDynarecMap` (auto-disabled if missing). Includes churn detection,
allocation size and lifetime histograms, outstanding block tracking.

Protection tracking (`--no-prot` to disable, requires dynarec enabled):
`protectDB`, `unprotectDB`, `setProtection` (auto-disabled if missing).

Mmap tracking (`--no-mmap` to disable): `InternalMmap`, `InternalMunmap`,
`box_mmap`, `box_munmap` (auto-disabled if missing).

Thread tracking (`--no-threads` to disable): `my_pthread_create`,
`pthread_routine`, `emuthread_destroy` (auto-disabled if missing).
Fork/clone uses `my_fork`, `my_clone` (skipped if missing).
CoW kprobe uses `wp_page_copy` (falls back to `do_wp_page`).

Process tree uses the `sched:sched_process_fork` kernel tracepoint for
parent-child PID mapping.
