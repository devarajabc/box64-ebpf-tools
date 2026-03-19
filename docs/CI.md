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
| Run integration tests | `sudo python3 tests/test_ebpf_integration.py` |

The integration test harness (`tests/test_ebpf_integration.py`) orchestrates:

1. Starts an eBPF tool (`box64_dynarec.py` or `box64_memleak.py`) in the background
2. Waits 3s for probe attachment
3. Runs `box64 test01` — Box64 emulates a pre-compiled x86_64 test binary, exercising DynaRec JIT, `customMalloc`, protection calls, etc.
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

Both tools run with **default settings** (all features enabled). The tools auto-disable features if optional symbols are missing in the Box64 build.

Estimated runtime: ~10–15 minutes (Box64 build: 5–8 min on first run, cached thereafter; tests: 2–3 min).

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
sudo python3 tests/test_ebpf_integration.py \
    --box64 /path/to/box64 \
    --test-bin /path/to/box64-src/tests/test01
```
