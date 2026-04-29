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

## Spawn-and-trace mode

The fastest way to run the tracer: pass your normal box64 invocation
after `--`. The tracer launches it for you, attaches probes before any
guest code runs, and auto-opens the browser dashboard. Stdio passes
through and the tracer exits with the program's return code.

```bash
# All four work — pick whichever matches how you'd normally invoke the
# program. Box64 runs x86_64 Linux ELFs (e.g. Unity Linux builds, native
# Steam binaries), NOT Windows .exe files. Bare names are auto-resolved
# against cwd the same way box64 does internally (BOX64_PATH always
# includes ./), so you don't need to remember `./`.
sudo box64_trace -- box64 ./MyGame.x86_64               # explicit
sudo box64_trace -- ./MyGame.x86_64                     # binfmt_misc → box64
sudo box64_trace -- MyGame.x86_64                       # auto ./ prepended
sudo box64_trace -- box64 MyGame.x86_64                 # also fine
```

### When things go wrong

- **box64 crashes** (SIGSEGV / SIGABRT / SIGILL / etc.) — the tracer
  prints the signal name plus a `BOX64_DYNAREC=0` isolation hint and
  a pointer to any `mono_crash.*.json` files. The dashboard *stays
  open* so you can switch tabs and inspect what was happening at the
  moment of the crash; Ctrl+C tears it down and exits with the
  child's return code.
- **`exec` fails** (typo, missing file, not executable) — the tracer
  bails with rc=127 *before* attaching probes, so you don't waste 10
  seconds on BPF setup for a program that isn't there.
- **Recognised BPF compile errors** — see
  [`troubleshooting.md`](troubleshooting.md) for the fix list.
- **Unknown exception** — `[FATAL]` envelope with a pointer to the
  issues URL; re-run with `BOX64_TRACE_DEBUG=1` for the full traceback.

## Web dashboard

The web dashboard is **on by default** when you run `box64_trace.py`
— it starts a local-only HTTP server (port 8642, or `$BOX64_WEB_PORT`)
and opens the URL in your default browser. Pass `--no-web` to disable
it entirely, or `--web PORT` to pick a different base port (the server
auto-scans up to 20 ports above this if the chosen one is in use).

### What the dashboard shows

| Region | Panel | Information |
|---|---|---|
| Header | Gauges (4) | `allocs/s` (custom-allocator throughput), `JIT MB` (live JIT bytes), `forks`, `threads` — with anomaly coloring when values cross thresholds. |
| Header | Guest / pause | Detected guest binary label; pause polling toggle. |
| Time-series | Allocator | `malloc` / `free` calls, total bytes; trend chart over the last N snapshots. |
| Time-series | JIT Blocks | `AllocDynarecMap` / `FreeDynarecMap` counts, outstanding live blocks. |
| Time-series | Process Lifecycle | `fork` / `vfork` / `execve` events per interval. |
| Time-series | JIT Protection | mprotect RW↔RX flips on JIT regions (overhead signal). |
| Process | Per-Process Breakdown | Live table: PID, label, threads, JIT bytes, JIT allocs, malloc bytes, mmap bytes, contexts. |
| Cache policy | Allocation Size Distribution | log2 histogram of `AllocDynarecMap` sizes — informs slab/arena sizing. |
| Cache policy | Block Lifetime Distribution | log2 histogram of alloc→free deltas — informs TTL-based eviction. |
| Cache policy | Invalidations | KPIs for `InvalidDynablock`, `MarkDynablock`, rapid-free churn count + chart. |
| Cache policy | Top Churned x64 Addresses | Most-recompiled guest PCs — SMC / re-JIT pressure hot spots. |
| Cache policy | Top Outstanding JIT Blocks | Largest live blocks (x64 addr, alloc addr, size, PID) — eviction candidates. |
| Stream | Event Feed | Live fork / exec / vfork / clone / large-alloc events streamed via Server-Sent Events. |

### Browser auto-open

The dashboard tries to open in your default browser when the server
starts. The URL is **always printed prominently** so you can copy-paste
it if auto-open misbehaves (Firefox's "profile is locked" dialog,
headless host, sudo session boundary, etc.).

```bash
sudo box64_trace --browser firefox    # explicit browser
sudo box64_trace --browser none       # skip auto-open, just print URL
BROWSER=chromium sudo -E box64_trace  # honors $BROWSER
```

Resolution order in `auto` mode (the default): `$BROWSER` (colon-list,
like xdg spec) → `xdg-open` → Python's `webbrowser` module. Under
`sudo`, the launcher is wrapped with `sudo -u $SUDO_USER` so the
browser can reach the caller's X / Wayland session.

### HTTP endpoints (served by `box64_web.py`)

| Path | Returns |
|---|---|
| `/` | Dashboard HTML + static assets from `web/`. |
| `/api/snapshot` | Current stats — gauges, per-PID table, histograms, top-N tables. Polled every ~1 s. |
| `/api/history` | Recent snapshots for chart backfill on initial page load. |
| `/api/events` | Server-Sent Events stream of fork / exec / JIT events. |
| `/api/stats-meta` | Field metadata (units, scale hints) consumed by the frontend. |

The frontend in `web/` is a ~770-line vanilla-JS app derived from the
MIT-licensed [kbox](https://github.com/devarajabc/kbox) observatory;
see [`../web/LICENSE-kbox`](../web/LICENSE-kbox) for the upstream
license.
