# box64_dynarec.py

Tracks `AllocDynarecMap` / `FreeDynarecMap` calls to analyze JIT block churn,
lifetimes, and allocation sizes. Optionally tracks `protectDB` /
`unprotectDB` / `setProtection` call overhead.

## Usage

```bash
sudo python3 box64_dynarec.py [options]
```

## Options

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

## Examples

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

## Output

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

## Required symbols

`AllocDynarecMap`, `FreeDynarecMap`. Requires a DynaRec-enabled build
(e.g., `-DARM_DYNAREC=ON`). Protection tracking additionally requires
`protectDB`, `unprotectDB`, `setProtection` (auto-disabled if missing).
Thread tracking (enabled by default) requires `my_pthread_create`, `pthread_routine`,
`emuthread_destroy` (auto-disabled if missing). Fork/clone tracking additionally
uses `my_fork`, `my_clone` (skipped if missing). Clone child PID tracking uses
a `my_clone` uretprobe. CoW kprobe tracking (enabled by default) attaches to `wp_page_copy`
(falls back to `do_wp_page`).
