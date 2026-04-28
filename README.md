# Box64 eBPF Profiling Tools

eBPF/BCC uprobe-based profiling tools for [Box64](https://github.com/ptitSeb/box64).
They attach to Box64's internal functions at runtime — no recompilation, no
LD_PRELOAD, minimal overhead. The tools require root and `python3-bcc`.

| Tool | Purpose | Docs |
|------|---------|------|
| `box64_memleak.py` | Memory leak detection for Box64's custom allocator | [docs/box64_memleak.md](docs/box64_memleak.md) |
| `box64_trace.py` | Multi-process tracer: DynaRec JIT block churn / lifetimes / protection, fork/exec lifecycle, per-PID memory, mmap, CoW page faults, PC sampling, pressure-vessel detection — and a real-time web dashboard | [docs/box64_trace.md](docs/box64_trace.md) |

Both share [`box64_common.py`](box64_common.py) for symbol validation,
`/proc` parsing, BCC/kernel workarounds, CoW delta math, thread-parent
correlation, and output formatting.

## Getting Started

```bash
./install.sh                       # system-wide (uses sudo for /usr/local)
PREFIX=$HOME/.local ./install.sh   # user-local
sudo ./install.sh -y               # unattended (CI)
```

That's it for setup. The installer auto-detects your distro
(`/etc/os-release`) and:

1. **Installs `python3-bcc`** if it's missing — apt / dnf / pacman / zypper,
   covering Debian, Ubuntu, Pop!_OS, Mint, Raspberry Pi OS, Fedora, RHEL,
   Rocky, AlmaLinux, Arch, Manjaro, EndeavourOS, openSUSE, SLES.
2. **Verifies `box64`** is on `$PATH` and was built with debug symbols
   (looks for the `customMalloc` symbol in `nm` output, since uprobes
   attach by name and a stripped binary will silently fail).
3. **Installs the tools** — Python sources + `web/` frontend into
   `$PREFIX/lib/box64-ebpf-tools/` and shell wrappers into `$PREFIX/bin/`,
   so `box64_trace` and `box64_memleak` work from anywhere.

Skip flags: `--no-bcc`, `--no-box64-check`, `--skip-deps` (both). Remove
with `./uninstall.sh` (honors the same `$PREFIX`).

### Don't have Box64 yet?

Build it from source — the tools require debug symbols, so don't strip:

```bash
git clone https://github.com/ptitSeb/box64.git
cd box64 && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DARM_DYNAREC=ON
make -j$(nproc)
sudo make install
```

Then re-run `./install.sh`.

### Run a tool

The fastest path: **spawn-and-trace mode** — pass your normal box64
command after `--` and the tracer launches it for you, attaches probes
before any guest code runs, and auto-opens the browser dashboard. Stdio
passes through and the tracer exits with the program's return code.

```bash
sudo box64_trace -- box64 ./game.exe
sudo box64_trace -- ./game.exe              # binfmt_misc routes through box64
sudo box64_trace --no-web -- box64 ./game.exe
```

Or attach to an already-running session:

```bash
# Find leaks in Box64's customMalloc/customFree allocator.
sudo box64_memleak -p <PID>

# Profile across all running box64 processes — Steam sessions where many
# box64 instances run concurrently.
sudo box64_trace
sudo box64_trace --web                      # with the dashboard
```

You can also run from the repo without installing
(`sudo python3 box64_trace.py …`).

Common flags: `-b BINARY` (default `/usr/local/bin/box64`, falls back to
`which box64`), `-p PID` (`0` = all processes), `-i INTERVAL` (seconds).
Press **Ctrl+C** to stop and print the full report.

## Web dashboard

`box64_trace.py --web [PORT]` (default port 8642) starts a local-only
HTTP server and opens the dashboard in your default browser.

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

### HTTP endpoints (served by `box64_web.py`)

| Path | Returns |
|---|---|
| `/` | Dashboard HTML + static assets from `web/`. |
| `/api/snapshot` | Current stats — gauges, per-PID table, histograms, top-N tables. Polled every ~1 s. |
| `/api/history` | Recent snapshots for chart backfill on initial page load. |
| `/api/events` | Server-Sent Events stream of fork / exec / JIT events. |
| `/api/stats-meta` | Field metadata (units, scale hints) consumed by the frontend. |

The frontend in `web/` is a ~770-line vanilla-JS app derived from the
MIT-licensed [kbox](https://github.com/devarajabc/kbox) observatory; see
[`web/LICENSE-kbox`](web/LICENSE-kbox) for the upstream license.

## Project layout

```
box64_common.py        ~270 lines    shared helpers (table below)
box64_memleak.py      ~1180 lines    custom-allocator leak detector
box64_trace.py        ~3330 lines    multi-process tracer + spawn mode + --web
box64_web.py           ~210 lines    HTTP+SSE backend for the dashboard
web/                                 dashboard frontend (HTML/CSS/JS, MIT — see web/LICENSE-kbox)
install.sh             ~270 lines    distro-aware installer (BCC + box64 + tools)
uninstall.sh            ~30 lines    symmetric removal

tests/                               266 unit tests + 3 upstream-compat tests + live e2e
  conftest.py                        mocks `bcc` so the unit suite runs without it
  test_spawn_mode.py                 fork/SIGSTOP gate + binary-resolver tests
  test_install_sh.py                 installer round-trip + distro mapping
  test_*.py                          fast pure-Python checks (no root, no BCC)
  test_ebpf_integration.py           E2E: runs each tool against live box64 workloads
  test_upstream_compat.py            verifies probed symbols & dynablock_t layout vs. box64 source
  dynarec_stress.c                   stress workload for the JIT probes
  memleak_leaker.c                   deliberately leaks via _exit(0) for memleak E2E
  steam_lifecycle.c                  fork/vfork/pthread workload for the tracer E2E

docs/                                per-tool reference + architecture notes
```

The code-review-graph reports 44 files, 474 nodes, 5117 edges across
Python, C, JavaScript, and bash.

Helpers in `box64_common.py`, grouped:

| Category | Helpers |
|---|---|
| Pure computation | `correlate_thread_parents`, `compute_cow_deltas`, `rank_items` |
| Formatters | `fmt_size`, `fmt_ns` |
| Symbol / binary | `check_binary`, `_read_symbols`, `check_symbols_soft` |
| `/proc` parsing | `read_smaps_rollup`, `read_minflt` |
| BCC / kernel workarounds | `_clear_stale_uprobes`, `_patch_bcc_uretprobe`, `_bcc_has_atomic_increment`, `_rewrite_atomic_increment` |

## Documentation

- **[`docs/box64_memleak.md`](docs/box64_memleak.md)** — options, output format, required symbols for the memory leak detector.
- **[`docs/box64_trace.md`](docs/box64_trace.md)** — options, output format, required symbols for the multi-process tracer.
- **[`docs/HOW_BOX64_WORKS.md`](docs/HOW_BOX64_WORKS.md)** — how Box64 executes an x86_64 binary, from ELF loading through DynaRec to syscall translation.
- **[`docs/BOX64_FORK_EXEC_MEMORY.md`](docs/BOX64_FORK_EXEC_MEMORY.md)** — Box64's fork/exec/clone mechanisms, custom allocator, DynaRec JIT block management, and pressure-vessel containers.
- **[`docs/BOX64_STEAM_INTERNALS.md`](docs/BOX64_STEAM_INTERNALS.md)** — pressure-vessel shim: Steam detection, env-var translation, D-Bus bypass, multi-process re-invocation model.
- **[`docs/CI.md`](docs/CI.md)** — CI workflow details and how to reproduce each job locally.

## Notes

### Overhead

- Base probes (alloc/free) add minimal per-call overhead.
- `--stacks` (memleak) enables `BPF_STACK_TRACE` on every allocation — noticeably more expensive.
- `--no-prot`, `--no-threads`, `--no-cow` reduce probe count for lower overhead.
- Filtering by PID (`-p`) reduces overhead when multiple box64 processes are running.
- `--web` adds an HTTP server thread and per-event SSE fan-out; both are bounded by deque/queue caps in `box64_web.py`.

### Stale uprobe workaround

All tools call `_clear_stale_uprobes` (in `box64_common.py`) before
attaching, working around a kernel bug where stale `ref_ctr_offset`
values persist in the uprobe inode cache. Particularly relevant on
**Asahi Linux (16K page size)** kernels.

### BCC compatibility

`_bcc_has_atomic_increment` probes whether the installed BCC supports
`table.atomic_increment()`; older BCC versions fall back to
`_rewrite_atomic_increment`, which rewrites the BPF C source to use
`lookup_or_init` + `__sync_fetch_and_add`. On aarch64 with BCC 0.29.1,
`_patch_bcc_uretprobe` monkey-patches the ctypes binding for
`bpf_attach_uprobe` to always pass the 7th `ref_ctr_offset` argument.

## Development

```bash
pip install -r requirements-dev.txt

# 266 fast unit tests (no root, no BCC required — conftest.py mocks it).
# Includes test_spawn_mode.py (real fork+SIGSTOP gate) and
# test_install_sh.py (round-trip install/uninstall in a tmpdir).
pytest tests/ --tb=short \
    --ignore=tests/test_upstream_compat.py \
    --ignore=tests/test_ebpf_integration.py

# Upstream-compat tests (need a local box64 source checkout).
BOX64_SRC_DIR=/path/to/box64 pytest tests/test_upstream_compat.py -v

# E2E integration (needs root + real BCC + a built box64).
sudo pytest tests/test_ebpf_integration.py -v
```

CI runs on every push/PR: syntax check, ruff lint, unit tests on Python
3.10/3.11/3.12, upstream compatibility, BCC compile of every embedded BPF
program, and E2E on `ubuntu-24.04-arm` against real x86_64 workloads
running through a freshly built Box64.
