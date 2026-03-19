# Box64 eBPF Profiling Tools

eBPF/BCC uprobe-based profiling tools for Box64. These attach to Box64's
internal functions at runtime with minimal overhead and no recompilation.

| Tool | Purpose | Docs |
|------|---------|------|
| `box64_dynarec.py` | DynaRec JIT block analysis (churn, lifetimes, protection overhead) | [docs/box64_dynarec.md](docs/box64_dynarec.md) |
| `box64_memleak.py` | Memory leak detection for Box64's custom allocator | [docs/box64_memleak.md](docs/box64_memleak.md) |
| `box64_steam.py` | Multi-process Steam tracer (fork/exec, per-PID memory, JIT, mmap, pressure-vessel) | [docs/box64_steam.md](docs/box64_steam.md) |

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
# Analyze JIT block churn and lifetimes
sudo python3 box64_dynarec.py -p <PID>

# Find memory leaks in Box64's allocator
sudo python3 box64_memleak.py -p <PID>

# Profile a full Steam gaming session (all box64 processes)
sudo python3 box64_steam.py
```

Common flags: `-b BINARY` (default `/usr/local/bin/box64`), `-p PID` (0=all), `-i INTERVAL` (seconds).

Press **Ctrl+C** when done to get the full report.

## Documentation

- **[`docs/box64_dynarec.md`](docs/box64_dynarec.md)** -- Options, output format, required symbols for the DynaRec JIT profiler.
- **[`docs/box64_memleak.md`](docs/box64_memleak.md)** -- Options, output format, required symbols for the memory leak detector.
- **[`docs/box64_steam.md`](docs/box64_steam.md)** -- Options, output format, required symbols for the multi-process Steam tracer.
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

All tools run `_clear_stale_uprobes` before attaching probes, working around
a kernel bug where stale `ref_ctr_offset` values persist in the uprobe inode
cache. Particularly relevant on **Asahi Linux (16K page size)** kernels.

## Development

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --tb=short --ignore=tests/test_upstream_compat.py
```

Upstream compatibility tests (verify Box64 symbols/structs still match):

```bash
BOX64_SRC_DIR=/path/to/box64 pytest tests/test_upstream_compat.py -v
```

CI runs on every push/PR: syntax check, ruff lint, unit tests (Python 3.10/3.11/3.12), upstream compat, BCC fallback compile test.
