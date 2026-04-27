# Box64 eBPF Profiling Tools

eBPF/BCC uprobe-based profiling tools for Box64. These attach to Box64's
internal functions at runtime with minimal overhead and no recompilation.

| Tool | Purpose | Docs |
|------|---------|------|
| `box64_memleak.py` | Memory leak detection for Box64's custom allocator | [docs/box64_memleak.md](docs/box64_memleak.md) |
| `box64_trace.py` | Multi-process Steam tracer (fork/exec, per-PID memory, JIT, mmap, pressure-vessel, DynaRec JIT block analysis) | [docs/box64_trace.md](docs/box64_trace.md) |

Both tools share [`box64_common.py`](box64_common.py) — 14 helpers for
nm-based symbol validation, `/proc` parsing, BCC/kernel workarounds, CoW
delta math, thread-parent correlation, and output formatting.

## Getting Started

### 1. Install BCC

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

### 2. Build Box64 with debug symbols

The tools attach to Box64's internal functions by name, so the binary **must** have debug symbols and must not be stripped:

```bash
git clone https://github.com/ptitSeb/box64.git
cd box64 && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DARM_DYNAREC=ON
make -j$(nproc)
sudo make install
```

### 3. Pick a tool and run

```bash
# Find memory leaks in Box64's allocator
sudo python3 box64_memleak.py -p <PID>

# Profile a full Steam gaming session (multi-process, includes JIT block
# churn/lifetime analysis, per-PID memory, fork/exec lifecycle, CoW)
sudo python3 box64_trace.py
```

Common flags: `-b BINARY` (default `/usr/local/bin/box64`), `-p PID` (0=all), `-i INTERVAL` (seconds).

Press **Ctrl+C** when done to get the full report.

## Project layout

```
box64_common.py         ~270 lines  shared helpers (see table below)
box64_memleak.py       ~1180 lines  custom-allocator leak detector
box64_trace.py         ~3000 lines  multi-process Steam tracer (also covers JIT block analysis)

tests/                              223 unit tests + 3 upstream-compat tests
  conftest.py                       mocks the `bcc` module so tests run without it
  test_*.py                         fast pure-Python checks (mocks, no root)
  test_ebpf_integration.py          E2E: runs each tool against live box64 workloads
  test_upstream_compat.py           verifies probed symbols & dynablock_t layout vs. box64 source
  dynarec_stress.c                  stress workload for the JIT probes
  memleak_leaker.c                  deliberately leaks via `_exit(0)` for memleak E2E
  steam_lifecycle.c                 fork/vfork/pthread workload for steam E2E

docs/                               per-tool reference + architecture notes
```

`box64_common.py` consolidates every helper that was previously duplicated
across the tools:

| Category | Helpers |
|---|---|
| Pure computation | `correlate_thread_parents`, `compute_cow_deltas`, `rank_items` |
| Formatters | `fmt_size`, `fmt_ns` |
| Symbol / binary | `check_binary`, `_read_symbols`, `check_symbols_soft` |
| `/proc` parsing | `read_smaps_rollup`, `read_minflt` |
| BCC / kernel | `_clear_stale_uprobes`, `_patch_bcc_uretprobe`, `_bcc_has_atomic_increment`, `_rewrite_atomic_increment` |

## Documentation

- **[`docs/box64_memleak.md`](docs/box64_memleak.md)** -- Options, output format, required symbols for the memory leak detector.
- **[`docs/box64_trace.md`](docs/box64_trace.md)** -- Options, output format, required symbols for the multi-process Steam tracer.
- **[`docs/HOW_BOX64_WORKS.md`](docs/HOW_BOX64_WORKS.md)** -- How Box64 executes an x86_64 binary, from ELF loading through DynaRec JIT to syscall translation.
- **[`docs/BOX64_FORK_EXEC_MEMORY.md`](docs/BOX64_FORK_EXEC_MEMORY.md)** -- Box64's fork/exec/clone mechanisms, custom allocator, DynaRec JIT block management, and pressure-vessel Steam containers.
- **[`docs/BOX64_STEAM_INTERNALS.md`](docs/BOX64_STEAM_INTERNALS.md)** -- How Box64's pressure-vessel shim works: Steam detection, environment variable translation, D-Bus bypass, multi-process re-invocation model.

## Notes

### Overhead

- Base probes (alloc/free tracking) add minimal overhead per call.
- `--stacks` (memleak) enables `BPF_STACK_TRACE` on every allocation -- noticeably more expensive.
- `--no-prot`, `--no-threads`, `--no-cow` reduce probe count for lower overhead.
- Filtering by PID (`-p`) reduces overhead when multiple box64 processes are running.

### Stale uprobe workaround

All tools run `_clear_stale_uprobes` (in `box64_common.py`) before attaching
probes, working around a kernel bug where stale `ref_ctr_offset` values
persist in the uprobe inode cache. Particularly relevant on
**Asahi Linux (16K page size)** kernels.

### BCC compatibility

`box64_common.py::_bcc_has_atomic_increment` probes whether the installed
BCC supports `table.atomic_increment()`; older BCC versions fall back to
`_rewrite_atomic_increment`, which rewrites the BPF C source to use
`lookup_or_init` + `__sync_fetch_and_add`. On aarch64 with BCC 0.29.1,
`_patch_bcc_uretprobe` monkey-patches the ctypes binding for
`bpf_attach_uprobe` to always pass the 7th `ref_ctr_offset` argument.

## Development

```bash
pip install -r requirements-dev.txt

# 311 fast unit tests (no root, no BCC required — conftest.py mocks it)
pytest tests/ --tb=short \
    --ignore=tests/test_upstream_compat.py \
    --ignore=tests/test_ebpf_integration.py

# 3 upstream-compat tests (need a local box64 source checkout)
BOX64_SRC_DIR=/path/to/box64 pytest tests/test_upstream_compat.py -v

# E2E integration (needs root + real BCC + built box64)
sudo pytest tests/test_ebpf_integration.py -v
```

CI runs on every push/PR: syntax check, ruff lint, unit tests (Python
3.10/3.11/3.12), upstream compat, BCC fallback compile test, and E2E on
ARM64 against real workloads.
