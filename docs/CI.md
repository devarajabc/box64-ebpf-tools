# CI Pipeline

Two GitHub Actions workflows validate this project. The main CI workflow (`ci.yml`) runs on every push and PR. The E2E workflow (`e2e-arm64.yml`) runs on pushes to `main` and manual dispatch.

## Workflow Overview

```
Push/PR                              Push to main / manual
  │                                        │
  ▼                                        ▼
ci.yml                              e2e-arm64.yml
  ├── test (3.10, 3.11, 3.12)          └── e2e-box64 (ARM64)
  │     ├── Syntax check                     ├── Build Box64 (cached)
  │     ├── Lint (ruff)                      └── eBPF integration tests
  │     └── Unit tests (pytest)
  ├── bpf-compile
  │     └── BPF C compilation (BCC)
  └── upstream-compat
        └── Box64 symbol/struct checks
```

## ci.yml — Main CI

Triggered on every push and pull request. Three parallel jobs:

### test

Runs on `ubuntu-latest` across Python 3.10, 3.11, and 3.12.

| Step | What it does |
|------|-------------|
| Syntax check | `py_compile` on all tool scripts and `box64_common.py` |
| Lint | `ruff check` on tool scripts, shared module, and `tests/` |
| Unit tests | `pytest tests/` (excludes `test_upstream_compat.py` and `test_ebpf_integration.py`) |

Unit tests use a mocked BCC module (via `conftest.py`) so they run without root or eBPF support. They cover:

| Test file | What it validates |
|-----------|-------------------|
| `test_parse_args.py` | CLI argparse defaults and custom values for all three tools |
| `test_cflags.py` | CLI args produce correct `-D` cflags for BPF compilation |
| `test_ifdef_consistency.py` | Bidirectional consistency between `#ifdef` guards in BPF C and `-D` flags in Python |
| `test_bpf_consistency.py` | BPF C function names match Python `attach_uprobe(fn_name=...)` calls |
| `test_fmt_helpers.py` | `fmt_size()` and `fmt_ns()` formatting |
| `test_fmt_edge_cases.py` | Edge cases for formatting functions |
| `test_format_log2_hist.py` | Log2 histogram ASCII rendering |
| `test_proc_parsing.py` | `/proc/[pid]/` RSS/PSS/Private_Dirty parsing |
| `test_symbol_checks.py` | Symbol validation via `nm` output |
| `test_clear_stale_uprobes.py` | Stale uprobe cache workaround |
| `test_bcc_uretprobe_patch.py` | BCC uretprobe patching logic |
| `test_rewrite_atomic.py` | `atomic_increment` rewrite for old BCC |
| `test_block_ranking.py` | JIT block ranking logic |
| `test_read_block.py` | Block reading from BPF maps |
| `test_read_block_metadata.py` | Block metadata extraction |
| `test_size_histogram.py` | Size histogram computation |
| `test_cow_deltas.py` | Copy-on-Write delta computation |
| `test_thread_correlation.py` | Thread/process tree correlation |

### bpf-compile

Runs on `ubuntu-22.04` (needs real BCC/LLVM).

Executes `sudo python3 tests/test_bpf_compile.py`, which:

1. Extracts `BPF_PROGRAM` C source from each tool
2. Compiles it with BCC using each tool's default cflags (and with `FILTER_PID`)
3. Runs each compilation in a subprocess to isolate LLVM crashes
4. Detects `atomic_increment` support and rewrites if needed
5. Required configs must pass; optional configs (e.g. `TRACK_PROFILE`, `CAPTURE_STACKS`) report warnings

### upstream-compat

Runs on `ubuntu-latest` with Python 3.12.

Shallow-clones upstream [Box64](https://github.com/ptitSeb/box64) and runs `pytest tests/test_upstream_compat.py`, which verifies:

- Required symbols (`AllocDynarecMap`, `customMalloc`, etc.) still exist in Box64 source
- `dynablock_t` struct field offsets haven't changed
- Key function parameter counts match expectations

This catches upstream Box64 changes that would break our probes.

## e2e-arm64.yml — E2E eBPF Integration

Triggered on pushes to `main` and `workflow_dispatch` (manual). Not on every PR to conserve ARM64 runner minutes.

Runs on `ubuntu-24.04-arm` (ARM64, kernel 6.8+, full eBPF/uprobe support).

| Step | What it does |
|------|-------------|
| Install dependencies | `python3-bpfcc`, `cmake`, `gcc`, `g++` |
| Cache Box64 build | Caches `/tmp/box64-build`, keyed on workflow file hash |
| Clone Box64 source | Shallow clone of upstream Box64 |
| Build Box64 | `cmake` with `-DARM_DYNAREC=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo` (skipped on cache hit) |
| Cross-compile test binaries | `x86_64-linux-gnu-gcc` compiles `tests/dynarec_stress.c` and `tests/steam_lifecycle.c` to x86_64 ELF |
| Run integration tests | `sudo python3 tests/test_ebpf_integration.py` |

### Test binaries

Three sources of x86_64 test binaries are used:

1. **Custom stress test** (`tests/dynarec_stress.c`) — cross-compiled to x86_64 on the ARM64 runner. Contains hot loops and multiple functions specifically designed to force DynaRec JIT block allocation.
2. **Steam lifecycle test** (`tests/steam_lifecycle.c`) — cross-compiled to x86_64 with `-lpthread`. A multi-process, multi-threaded binary that exercises Box64's wrapped libc (`my_fork`, `my_vfork`, `my_execve`, `my_execvp`, `my_execv`, `my_pthread_create`). Creates this tree:
   ```
   box64 steam_lifecycle                         (parent)
   +-- 10 fork children -> exec -> worker        (rotating execve/execvp/execv)
   +-- 10 vfork children -> execve -> worker
   +-- 4 pthreads (brief hot loops)
   ```
   This generates 10 forks, 10 vforks, 20 execs (3 variants), and 4 pthread_create calls, ensuring broad probe coverage.
3. **Box64's own test suite** (`test01`–`test33`) — pre-compiled x86_64 ELF binaries from the upstream Box64 repo, auto-discovered via `--test-dir`.

All binaries are run in sequence during each tool test. Individual binary failures or timeouts (10s per binary) are tolerated — our eBPF tools still collect probe data from whatever activity occurred.

### Test harness

The integration test harness (`tests/test_ebpf_integration.py`) orchestrates:

1. Starts an eBPF tool (`box64_dynarec.py`, `box64_memleak.py`, or `box64_steam.py`) in the background
2. Polls tool stdout for "probes attached" (BPF compilation takes 4–6s on ARM64)
3. Runs Box64 with each test binary in sequence — exercising DynaRec JIT, `customMalloc`, protection calls, etc.
4. Waits 2s grace period for the final eBPF poll cycle
5. Sends `SIGINT` to the tool, triggering `print_final_report()`
6. Parses stdout and asserts correctness

Assertions for `box64_dynarec.py`:
- Output contains `FINAL REPORT`
- `AllocDynarecMap` count > 0 (Box64 must JIT-compile x86_64 code)
- `Bytes allocated` > 0
- No Python tracebacks

Assertions for `box64_memleak.py`:
- Output contains `FINAL REPORT`
- `Total mallocs` count > 0 (Box64 uses `customMalloc` internally)
- No Python tracebacks

Assertions for `box64_steam.py` (default flags — all features enabled):
- Output contains `FINAL REPORT`
- `fork` count >= 10
- `vfork` count >= 10
- `exec (all)` count >= 10
- `NewBox64Context` count == 20 + number of test binaries (exact check)
- `AllocDynarecMap` count > 0
- `malloc` count > 0
- `Box64 Process Tree` present with >= 10 distinct PIDs
- `Per-PID Memory Breakdown` present with >= 10 PID sections
- No Python tracebacks

Assertions for `box64_steam.py` (PC sampling — `--sample-freq 4999`):
- If BCC doesn't support `TRACK_PROFILE` compilation: **SKIP** (not FAIL) — the tool retries without PC sampling and the test verifies it still produces a `FINAL REPORT`
- Output contains `FINAL REPORT`
- `NewBox64Context` count >= 1
- `PC Sampling Profile` section present
- No Python tracebacks

Assertions for output correctness (baseline vs probed comparison):
- Runs each testNN binary twice: once without probes (baseline), once with `box64_dynarec.py` uprobes attached
- For each binary that exits 0 in both runs: stdout must match exactly
- Detects instrumentation-induced perturbations without relying on upstream refNN.txt files (which may diverge on ARM64 due to known FP-precision differences)

All tools run with **default settings** (all features enabled). The tools auto-disable features if optional symbols are missing in the Box64 build.

Estimated runtime: ~20–25 minutes (Box64 build: 5–8 min on first run, cached thereafter; tests: 8–12 min with all binaries and steam tests).

## Running Tests Locally

```bash
# Unit tests (no root needed, any OS)
pip install -r requirements-dev.txt
pytest tests/ -v --tb=short --ignore=tests/test_upstream_compat.py --ignore=tests/test_ebpf_integration.py

# BPF compilation (root + BCC, Linux only)
sudo python3 tests/test_bpf_compile.py

# Upstream compat (no root needed, any OS)
BOX64_SRC_DIR=/path/to/box64 pytest tests/test_upstream_compat.py -v

# E2E integration (root + BCC + ARM64 Linux + Box64 binary)
# Cross-compile test binaries first:
#   x86_64-linux-gnu-gcc -O1 -o /tmp/dynarec_stress tests/dynarec_stress.c
#   x86_64-linux-gnu-gcc -O1 -o /tmp/steam_lifecycle tests/steam_lifecycle.c
sudo python3 tests/test_ebpf_integration.py \
    --box64 /path/to/box64 \
    --test-bin /tmp/dynarec_stress /tmp/steam_lifecycle \
    --test-dir /path/to/box64-src/tests
```
