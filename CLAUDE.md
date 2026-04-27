# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPF/BCC uprobe-based profiling toolkit for [Box64](https://github.com/ptitSeb/box64) (Linux x86_64 emulator). Three standalone Python scripts attach to Box64's internal functions at runtime via eBPF uprobes — no recompilation needed. All require root and `python3-bcc`.

## Running the Tools

```bash
sudo python3 box64_memleak.py [options]    # Memory leak detection
sudo python3 box64_trace.py [options]      # Multi-process Steam tracer + JIT block analysis
```

Common flags: `-b BINARY` (default `/usr/local/bin/box64`), `-p PID` (0=all), `-i INTERVAL` (seconds).

## Architecture

Each tool follows the same pattern:

1. **CLI args** → parsed with `argparse`
2. **Symbol validation** → runs `nm`/`nm -D` on the Box64 binary to verify required symbols exist; auto-disables features if optional symbols are missing
3. **BPF program compilation** → C source embedded as triple-quoted strings in Python, compiled by BCC with `#define` flags for conditional feature gating. `box64_trace.py` uses the full set (`TRACK_MEM`, `TRACK_DYNAREC`, `TRACK_BLOCK_DETAIL`, `TRACK_MMAP`, `TRACK_THREADS`, `TRACK_COW`, `TRACK_PROFILE`); `box64_memleak.py` uses `CAPTURE_STACKS`, `TRACK_MMAP`, `TRACK_32BIT`, `TRACK_THREADS`, `TRACK_COW`
4. **Probe attachment** → uprobes/uretprobes on Box64 functions + optional kprobe (`wp_page_copy` for CoW)
5. **Event loop** → periodic interval summaries (+ perf event buffer polling when enabled)
6. **Final report** → comprehensive output on Ctrl+C (histograms, top-N lists, process trees, timelines)

### The Two Tools (and the shared module)

- **box64_common.py** (~270 lines): Shared helpers imported by both tools — pure-computation utilities (`correlate_thread_parents`, `compute_cow_deltas`, `rank_items`), formatters (`fmt_size`, `fmt_ns`), binary/symbol validation (`check_binary`, `check_symbols_soft`), `/proc` parsers (`read_smaps_rollup`, `read_minflt`), and BCC/kernel workarounds (`_clear_stale_uprobes`, `_patch_bcc_uretprobe`, `_bcc_has_atomic_increment`, `_rewrite_atomic_increment`). Lazy-imports `bcc` so the module is importable without BCC installed.
- **box64_memleak.py** (~1,180 lines): Tracks `customMalloc`/`customFree`/`customCalloc`/`customRealloc` for leak detection. Optional: mmap, stack traces, 32-bit variants.
- **box64_trace.py** (~3,000 lines): Multi-process tracer for Steam sessions. Also covers JIT block analysis: tracks `AllocDynarecMap`/`FreeDynarecMap` for churn, lifetimes, protection overhead, plus fork/exec/vfork lifecycle, per-PID memory (custom allocator + JIT + mmap + context), pressure-vessel detection, process trees, PC sampling profiling, CoW page faults.

When adding a helper, check whether it already lives in `box64_common.py` — duplicating helpers across tools is what the recent refactor was undoing.

### Shared patterns not in `box64_common.py`

- `format_log2_hist()` — renders BPF log2 histograms as ASCII bar charts (defined in `box64_trace.py`; not used by `box64_memleak.py`)
- Per-PID BPF hash maps with configurable capacity (`--hash-capacity`)
- Thread/process tree construction via timestamp-based correlation (the helper itself, `correlate_thread_parents`, is in `box64_common.py`; the wiring is per-tool)

## Dependencies

Only dependency beyond stdlib is `bcc` — must be installed as a system package:
```bash
sudo apt install python3-bcc bpfcc-tools        # Debian/Ubuntu
sudo dnf install python3-bcc bcc-tools           # Fedora
sudo pacman -S python-bcc bcc-tools              # Arch
```

Box64 must be built with debug symbols (`-DCMAKE_BUILD_TYPE=RelWithDebInfo`) and not stripped.

## Testing and CI

Unit tests live in `tests/` and run with pytest. `tests/conftest.py` mocks the `bcc` module, so the unit suite runs without root or BCC installed:
```bash
pip install -r requirements-dev.txt

# Fast unit tests (no root, no BCC needed)
pytest tests/ -v --tb=short \
    --ignore=tests/test_upstream_compat.py \
    --ignore=tests/test_ebpf_integration.py
```

Upstream compatibility tests verify that Box64's symbols, struct layouts, and function signatures haven't changed:
```bash
BOX64_SRC_DIR=/path/to/box64 pytest tests/test_upstream_compat.py -v
```

End-to-end integration tests run each tool against live Box64 workloads (require root + real BCC + a built Box64):
```bash
sudo pytest tests/test_ebpf_integration.py -v
```

Two CI workflows run on every push/PR:

- **`.github/workflows/ci.yml`** (Linux x86_64):
  - `test` — syntax check, ruff lint, unit tests across Python 3.10/3.11/3.12
  - `bpf-compile` — installs real BCC and compiles every BPF program via `tests/test_bpf_compile.py` (catches real C-level rejections that the mocked unit tests can't)
  - `upstream-compat` — shallow-clones upstream Box64, checks symbol existence, `dynablock_t` struct offsets, and key function parameter counts
- **`.github/workflows/e2e-arm64.yml`** (`ubuntu-24.04-arm`): cross-compiles the C test workloads (`dynarec_stress.c`, `steam_lifecycle.c`, `memleak_leaker.c`) to x86_64, builds Box64 from source (cached by commit hash), then runs `tests/test_ebpf_integration.py` against the live binary. This is the only CI job that exercises real eBPF attachment.

## Technical Reference

The `docs/` directory has per-tool guides plus three architecture notes that are useful when changing probe targets or output:

- `docs/HOW_BOX64_WORKS.md` — end-to-end picture of how Box64 executes an x86_64 binary (ELF loading → DynaRec → syscall translation).
- `docs/BOX64_FORK_EXEC_MEMORY.md` — fork/exec/clone mechanisms, custom allocator (3-tier: 64B/128B slabs + linked-list), DynaRec JIT block management, and pressure-vessel Steam containers.
- `docs/BOX64_STEAM_INTERNALS.md` — pressure-vessel shim, Steam detection, env-var translation, D-Bus bypass, multi-process re-invocation model.
- `docs/CI.md` — CI workflow details and how to reproduce each job locally.

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
