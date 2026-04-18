# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPF/BCC uprobe-based profiling toolkit for [Box64](https://github.com/ptitSeb/box64) (Linux x86_64 emulator). Three standalone Python scripts attach to Box64's internal functions at runtime via eBPF uprobes — no recompilation needed. All require root and `python3-bcc`.

## Running the Tools

```bash
sudo python3 box64_dynarec.py [options]   # JIT block churn/lifetime analysis
sudo python3 box64_memleak.py [options]    # Memory leak detection
sudo python3 box64_steam.py [options]      # Multi-process Steam tracer (superset of dynarec)
```

Common flags: `-b BINARY` (default `/usr/local/bin/box64`), `-p PID` (0=all), `-i INTERVAL` (seconds).

## Architecture

Each tool follows the same pattern:

1. **CLI args** → parsed with `argparse`
2. **Symbol validation** → runs `nm`/`nm -D` on the Box64 binary to verify required symbols exist; auto-disables features if optional symbols are missing
3. **BPF program compilation** → C source embedded as triple-quoted strings in Python, compiled by BCC with `#define` flags for conditional feature gating. `box64_steam.py` uses the full set (`TRACK_MEM`, `TRACK_DYNAREC`, `TRACK_BLOCK_DETAIL`, `TRACK_MMAP`, `TRACK_THREADS`, `TRACK_COW`, `TRACK_PROFILE`); `box64_dynarec.py` uses `TRACK_PROT`, `TRACK_THREADS`, `TRACK_COW`; `box64_memleak.py` uses `CAPTURE_STACKS`, `TRACK_MMAP`, `TRACK_32BIT`, `TRACK_THREADS`, `TRACK_COW`
4. **Probe attachment** → uprobes/uretprobes on Box64 functions + optional kprobe (`wp_page_copy` for CoW)
5. **Event loop** → periodic interval summaries (+ perf event buffer polling when enabled)
6. **Final report** → comprehensive output on Ctrl+C (histograms, top-N lists, process trees, timelines)

### The Three Tools

- **box64_dynarec.py** (~1,170 lines): Tracks `AllocDynarecMap`/`FreeDynarecMap` for JIT block churn, lifetimes, protection overhead (`protectDB`/`unprotectDB`/`setProtection`).
- **box64_memleak.py** (~1,270 lines): Tracks `customMalloc`/`customFree`/`customCalloc`/`customRealloc` for leak detection. Optional: mmap, stack traces, 32-bit variants.
- **box64_steam.py** (~3,000 lines): Multi-process tracer for Steam sessions. Tracks fork/exec/vfork lifecycle, per-PID memory (custom allocator + JIT + mmap + context), pressure-vessel detection, process trees, PC sampling profiling. Subsumes `box64_dynarec.py` functionality.

### Shared Patterns

- `_clear_stale_uprobes()` — workaround for kernel uprobe cache bug (stale `ref_ctr_offset`), especially on Asahi Linux 16K page size kernels
- `fmt_size()` — human-readable size formatting (all three tools)
- `fmt_ns()` — human-readable nanosecond formatting (`box64_dynarec.py`, `box64_steam.py` only)
- `format_log2_hist()` — renders BPF log2 histograms as ASCII bar charts (`box64_dynarec.py`, `box64_steam.py` only)
- `/proc/[pid]/` filesystem reads for RSS/PSS/Private_Dirty memory snapshots
- Thread/process tree construction via timestamp-based correlation in Python
- Per-PID BPF hash maps with configurable capacity (`--hash-capacity`)

## Dependencies

Only dependency beyond stdlib is `bcc` — must be installed as a system package:
```bash
sudo apt install python3-bcc bpfcc-tools        # Debian/Ubuntu
sudo dnf install python3-bcc bcc-tools           # Fedora
sudo pacman -S python-bcc bcc-tools              # Arch
```

Box64 must be built with debug symbols (`-DCMAKE_BUILD_TYPE=RelWithDebInfo`) and not stripped.

## Testing and CI

Unit tests live in `tests/` and run with pytest:
```bash
pip install -r requirements-dev.txt
pytest tests/ -v --tb=short --ignore=tests/test_upstream_compat.py
```

Upstream compatibility tests verify that Box64's symbols, struct layouts, and function signatures haven't changed:
```bash
BOX64_SRC_DIR=/path/to/box64 pytest tests/test_upstream_compat.py -v
```

CI runs on every push/PR via `.github/workflows/ci.yml`:
- **`test` job** — syntax check, ruff lint, unit tests (Python 3.10/3.11/3.12 matrix)
- **`upstream-compat` job** — shallow-clones upstream Box64, checks symbol existence, `dynablock_t` struct offsets, and key function parameter counts

eBPF-level testing is manual — run tools against live Box64 processes.

## Technical Reference

`docs/BOX64_FORK_EXEC_MEMORY.md` documents Box64's fork/exec/clone mechanisms, custom allocator (3-tier: 64B/128B slabs + linked-list), DynaRec JIT block management, and pressure-vessel Steam containers. Useful context when modifying probe targets.

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
