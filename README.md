# Box64 eBPF Profiling Tools

eBPF/BCC uprobe-based profiling tools for Box64. These attach to Box64's
internal functions at runtime with minimal overhead and no recompilation.

- **box64_dynarec.py** -- DynaRec JIT block analysis (allocation churn, lifetimes, protection overhead)
- **box64_memleak.py** -- Memory leak detection for Box64's custom allocator
- **box64_steam.py** -- Multi-process Steam tracer (fork/exec lifecycle, per-PID memory, DynaRec JIT analysis with churn/lifetime/protection tracking, mmap, pressure-vessel detection)

## Getting Started

### 1. Install BCC

Install the BCC toolkit using your distribution's package manager (see [Prerequisites](#prerequisites) for full details):

```bash
# Debian/Ubuntu/Raspberry Pi OS
sudo apt install python3-bcc bpfcc-tools
```

### 2. Build Box64 with debug symbols

The tools attach to Box64's internal functions by name, so the binary **must** have debug symbols and must not be stripped:

```bash
git clone https://github.com/ptitSeb/box64.git
cd box64 && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DARM_DYNAREC=ON
make -j$(nproc)
sudo make install
```

### 3. Clone this repository

```bash
git clone https://github.com/devarajabc/box64-ebpf-tools.git
cd box64-ebpf-tools
```

### 4. Pick the right tool

| Goal | Tool | Command |
|------|------|---------|
| Analyze JIT block churn and lifetimes | `box64_dynarec.py` | `sudo python3 box64_dynarec.py -p <PID>` |
| Find memory leaks in Box64's allocator | `box64_memleak.py` | `sudo python3 box64_memleak.py -p <PID>` |
| Profile a full Steam gaming session | `box64_steam.py` | `sudo python3 box64_steam.py` |

### 5. Run and collect data

```bash
# Start your Box64 workload (game, app, etc.) in one terminal,
# then attach the profiler as root in another:
sudo python3 box64_steam.py -p $(pidof box64)

# The tool prints periodic summaries while running.
# Press Ctrl+C when done to get the full report.
```

### 6. Read the report

Each tool prints a comprehensive final report on Ctrl+C. Key things to look for:

- **High churn rates** (dynarec/steam) -- JIT blocks being repeatedly compiled and freed, a sign of code that defeats the JIT cache.
- **Outstanding allocations** (memleak) that grow over time -- potential memory leaks.
- **Process tree** (steam) -- parent-child hierarchy of all box64 processes spawned during a Steam session.
- **Histograms** -- distribution of allocation sizes and block lifetimes.

## How It Works

Each tool follows the same process:

1. **CLI args** -- parsed with `argparse`. Common flags: `-b BINARY`, `-p PID`, `-i INTERVAL`.
2. **Symbol validation** -- runs `nm`/`nm -D` on the Box64 binary to verify required symbols exist. Optional features are auto-disabled if their symbols are missing.
3. **BPF program compilation** -- C source embedded in Python is compiled by BCC at runtime with `#define` flags for conditional feature gating.
4. **Probe attachment** -- uprobes/uretprobes attach to Box64 functions at runtime. No recompilation or restart needed. Optional kprobes attach to kernel functions (e.g., `wp_page_copy` for CoW tracking).
5. **Event loop** -- periodic interval summaries print while the tool runs (+ perf event buffer polling when enabled).
6. **Final report** -- press Ctrl+C to get the comprehensive output: histograms, top-N lists, process trees, timelines.

## Typical Workflows

### Investigating a game that uses too much memory

1. Launch the game through Steam/Box64.
2. Run `sudo python3 box64_steam.py` to get a full session overview -- it tracks all box64 processes automatically.
3. Check the periodic summaries for which PID is growing fastest.
4. If you suspect a leak, run `sudo python3 box64_memleak.py -p <PID> --stacks` on that specific process to get per-allocation stack traces.
5. If you suspect JIT thrashing, run `sudo python3 box64_dynarec.py -p <PID> --churn-threshold 0.5` to identify hot x64 addresses being repeatedly recompiled.

### Quick single-process profiling

```bash
# Start box64 with your app
box64 ./myapp &

# Attach the dynarec profiler
sudo python3 box64_dynarec.py -p $(pidof box64) -i 5

# Let it run, then Ctrl+C for the report
```

### PC sampling profiling (finding hot x64 code)

```bash
# Sample at 99 Hz to find where the JIT spends time
sudo python3 box64_steam.py -p $(pidof box64) --sample-freq 99
```

### Reducing overhead for production use

```bash
# Disable optional tracking to minimize probe count
sudo python3 box64_steam.py --no-prot --no-threads --no-cow --no-block-detail
```

## Documentation

- **[`docs/HOW_BOX64_WORKS.md`](docs/HOW_BOX64_WORKS.md)** -- Complete step-by-step walkthrough of how Box64 executes an x86_64 binary, from ELF loading through DynaRec JIT compilation to syscall translation.
- **[`docs/BOX64_FORK_EXEC_MEMORY.md`](docs/BOX64_FORK_EXEC_MEMORY.md)** -- Technical reference for Box64's fork/exec/clone mechanisms, custom allocator (3-tier: 64B/128B slabs + linked-list), DynaRec JIT block management, and pressure-vessel Steam containers.

## Prerequisites

- **Root access** (eBPF uprobes require `CAP_SYS_ADMIN`)
- **Linux >= 4.9** (BPF uprobe support)
- **python3-bcc** (BCC toolkit):
  ```bash
  # Debian/Ubuntu/Raspberry Pi OS
  sudo apt install python3-bcc bpfcc-tools

  # Fedora
  sudo dnf install python3-bcc bcc-tools

  # Arch Linux / Manjaro ARM
  sudo pacman -S python-bcc bcc-tools

  # openSUSE
  sudo zypper install python3-bcc bcc-tools
  ```
- **Box64 built with debug symbols** (`-DCMAKE_BUILD_TYPE=RelWithDebInfo`).
  The binary must not be stripped -- the tools use `nm` to verify that required
  symbols are present before attaching probes.

## box64_dynarec.py

Tracks `AllocDynarecMap` / `FreeDynarecMap` calls to analyze JIT block churn,
lifetimes, and allocation sizes. Optionally tracks `protectDB` /
`unprotectDB` / `setProtection` call overhead.

### Usage

```bash
sudo python3 box64_dynarec.py [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-b`, `--binary` | `/usr/local/bin/box64` | Path to the box64 binary |
| `-p`, `--pid` | `0` (all) | Filter by PID; 0 traces all box64 processes |
| `-i`, `--interval` | `15` | Periodic summary interval in seconds |
| `--no-prot` | off | Skip `protectDB`/`unprotectDB`/`setProtection` tracking (lower overhead) |
| `--churn-threshold` | `1.0` | Blocks freed within this many seconds count as "churn" |
| `--no-threads` | off | Disable thread/process lifecycle tracking (`pthread_create`, `fork`, `clone`) |
| `--no-cow` | off | Disable copy-on-write page fault tracking (kprobe + `/proc` sampling) |
| `--hash-capacity` | `524288` | BPF hash table size for tracking outstanding blocks; increase if you see "HASH TABLE FULL" warnings |

### Example

```bash
# Trace a specific box64 process, 5-second summaries, 2s churn threshold
sudo python3 box64_dynarec.py -p 12345 -i 5 --churn-threshold 2.0

# Trace all box64 processes, skip protection overhead tracking
sudo python3 box64_dynarec.py --no-prot

# Minimal overhead: no protection tracking, no thread tracking
sudo python3 box64_dynarec.py -b ~/box64/build/box64 --no-prot --no-threads

# Minimal overhead: skip protection, thread, and CoW tracking
sudo python3 box64_dynarec.py -b ~/box64/build/box64 --no-prot --no-threads --no-cow
```

### Output

**Periodic summaries** (every `--interval` seconds) show:

- Alloc / free / churn counts and percentages for the interval
- Bytes allocated, freed, and outstanding
- Number of outstanding JIT blocks
- Protection call counts and cumulative bytes (unless `--no-prot`)
- Thread counts: active, created, destroyed, peak, forks, clones (unless `--no-threads`)

**Final report** (on Ctrl+C) includes:

- Cumulative totals for all counters
- **Allocation size distribution** -- log2 histogram of block sizes
- **Block lifetime distribution** -- log2 histogram of how long blocks lived before being freed
- **Top 20 outstanding JIT blocks** by size (alloc address, x64 address, size, is_new flag, PID)
- **Top 20 churned x64 addresses** -- addresses most frequently re-compiled within the churn threshold
- **Process/Thread Tree** -- hierarchical view showing which thread created which, with per-thread allocation stats (unless `--no-threads`):
  ```
  Process/Thread Tree:
    PID 50679
    └── TID 50679 (main)     403,757 allocs    132.5 MB
        ├── TID 50683 [x64:0x3889dc0] (exited)          18 allocs      7.7 KB
        ├── TID 50684 [x64:0x3889dc0] (exited)          24 allocs     12.3 KB
        ├── TID 50685 [x64:0x3889dc0] (exited)          16 allocs      7.4 KB
        └── TID 50686 [x64:0x3889dc0] (exited)          80 allocs     35.2 KB
  ```
- **Thread summary** -- total created/destroyed, peak concurrent, fork/clone counts (unless `--no-threads`)
- **Top 10 threads by JIT allocation volume** -- TID, alloc count, bytes, x64 start routine, PID (unless `--no-threads`)
- **Copy-on-Write Analysis** (when fork/clone detected) -- `/proc`-based RSS and Private_Dirty snapshots at fork time vs current, with minor fault deltas. Also shows per-PID CoW page fault counts from kernel kprobe with estimated bytes copied (unless `--no-cow`).

### Required symbols

`AllocDynarecMap`, `FreeDynarecMap`. Requires a DynaRec-enabled build
(e.g., `-DARM_DYNAREC=ON`). Protection tracking additionally requires
`protectDB`, `unprotectDB`, `setProtection` (auto-disabled if missing).
Thread tracking (enabled by default) requires `my_pthread_create`, `pthread_routine`,
`emuthread_destroy` (auto-disabled if missing). Fork/clone tracking additionally
uses `my_fork`, `my_clone` (skipped if missing). Clone child PID tracking uses
a `my_clone` uretprobe. CoW kprobe tracking (enabled by default) attaches to `wp_page_copy`
(falls back to `do_wp_page`).

## box64_memleak.py

Tracks `customMalloc` / `customFree` / `customCalloc` / `customRealloc` to
detect memory leaks in Box64's custom allocator. Outstanding allocations at
exit are potential leaks.

### Usage

```bash
sudo python3 box64_memleak.py [options]
```

### Options

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

### Example

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

### Output

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

### Required symbols

`customMalloc`, `customFree`, `customCalloc`, `customRealloc`. With `--mmap`:
`InternalMmap`, `InternalMunmap`. With `--32bit`: `customMalloc32`,
`customFree32`, `customCalloc32`, `customRealloc32`. Thread tracking
(enabled by default) requires `my_pthread_create`, `pthread_routine`,
`emuthread_destroy` (auto-disabled if missing). Fork/clone tracking
additionally uses `my_fork`, `my_clone` (skipped if missing). Clone child PID
tracking uses a `my_clone` uretprobe. CoW kprobe tracking (enabled by default) attaches
to `wp_page_copy` (falls back to `do_wp_page`).

## box64_steam.py

Traces Box64's behavior across **all concurrent box64 processes** during a Steam
gaming session. Tracks fork/exec/vfork process lifecycle, per-PID memory usage
(custom allocator, DynaRec JIT with churn/lifetime/protection analysis, mmap),
context creation/destruction, and pressure-vessel container detection. Designed
for understanding memory behavior when Steam spawns 5-10+ concurrent box64
instances. Subsumes all functionality previously in `box64_dynarec.py`.

See also: `docs/BOX64_FORK_EXEC_MEMORY.md` for detailed documentation on how
fork/exec/memory functions work in box64.

### Usage

```bash
sudo python3 box64_steam.py [options]
```

### Options

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

### Example

```bash
# Trace all box64 processes (typical Steam session)
sudo python3 box64_steam.py

# Trace with custom binary path and 5-second summaries
sudo python3 box64_steam.py -b ~/box64/build/box64 -i 5

# Focus on fork/exec lifecycle only (minimal overhead)
sudo python3 box64_steam.py --no-mem --no-dynarec --no-mmap --no-threads --no-cow

# Trace a specific box64 process with full tracking
sudo python3 box64_steam.py -p 12345

# DynaRec-focused: 2s churn threshold, skip protection overhead
sudo python3 box64_steam.py --no-mem --no-mmap --churn-threshold 2.0 --no-prot
```

### Output

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

### Required symbols

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

## Notes

### Stale uprobe workaround

Both tools run a `_clear_stale_uprobes` step before attaching probes. This
works around a kernel bug where stale `ref_ctr_offset` values persist in the
uprobe inode cache, causing `perf_event_open` to fail with `EINVAL`. The
workaround clears `/sys/kernel/debug/tracing/uprobe_events`, copies the binary
to force a new inode, and drops kernel caches. This is particularly relevant on
**Asahi Linux (16K page size)** kernels.

### Overhead

- The base probes (alloc/free tracking) add minimal overhead per call.
- `--stacks` enables `BPF_STACK_TRACE` collection on every allocation, which
  is noticeably more expensive. Use only when you need call-site attribution.
- `--no-prot` reduces probe count by 3 if you only care about allocation
  patterns and not protection overhead.
- Thread tracking (on by default) adds 4-6 uprobes for thread lifecycle
  tracking plus per-thread stats updates on every alloc/free. The overhead
  is modest since thread creation/destruction is infrequent compared to
  allocations. The process/thread tree is built via timestamp-based
  correlation in Python with no additional BPF overhead.
- CoW tracking (on by default) attaches a kernel kprobe to `wp_page_copy`
  (or `do_wp_page`), which fires on every copy-on-write page fault
  system-wide. Filtering is done in-kernel by PID. The overhead is low for
  typical workloads but can be noticeable under very heavy CoW pressure.
  `/proc`-based CoW analysis (RSS/Private_Dirty snapshots) is always
  available when fork/clone events are detected, with no additional probe
  overhead. Use `--no-cow` to disable both.
- Filtering by PID (`-p`) reduces overhead when multiple box64 processes are
  running.

### Symbol verification

All tools run `nm` and `nm -D` on the binary at startup to verify that all
required symbols are present. If symbols are missing, you will get a clear
error message indicating which symbols are needed and how to rebuild.

## Development

### Running tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --tb=short --ignore=tests/test_upstream_compat.py
```

### Upstream compatibility tests

Verify that upstream Box64's symbols, `dynablock_t` struct layout, and key
function signatures still match what our tools expect:

```bash
BOX64_SRC_DIR=/path/to/box64 pytest tests/test_upstream_compat.py -v
```

### CI

GitHub Actions runs on every push and PR (`.github/workflows/ci.yml`):

- **`test`** — syntax check, ruff lint, unit tests (Python 3.10/3.11/3.12)
- **`upstream-compat`** — shallow-clones upstream Box64 and checks symbol
  existence, `dynablock_t` struct offsets, and key function parameter counts
