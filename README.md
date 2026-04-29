# Box64 eBPF Profiling Tools

eBPF/BCC uprobe-based profiling tools for [Box64](https://github.com/ptitSeb/box64).
They attach to Box64's internal functions at runtime — no recompilation, no
LD_PRELOAD, minimal overhead. Linux-only, require root and `python3-bcc`.

## Demo

https://github.com/user-attachments/assets/798e7544-2e6f-4c4e-b96f-7d25e45ddc38

Recorded on **Apple Silicon M1 running Linux (aarch64)**, with Box64
executing the x86_64 build of [*Fallen Ties* by studio-laaya](https://studio-laaya.itch.io/fallen-ties)
under `box64_trace --web`. The dashboard shows live JIT block churn,
allocator throughput, and the pressure-vessel process tree as the game
runs.

## The two tools

| Tool | Purpose | Docs |
|------|---------|------|
| `box64_memleak.py` | Memory leak detection for Box64's custom allocator | [docs/box64_memleak.md](docs/box64_memleak.md) |
| `box64_trace.py` | Multi-process tracer: DynaRec JIT churn / lifetimes / protection, fork/exec lifecycle, per-PID memory, mmap, CoW page faults, PC sampling, pressure-vessel detection — and a real-time web dashboard | [docs/box64_trace.md](docs/box64_trace.md) |

Both share [`box64_common.py`](box64_common.py) for symbol validation,
`/proc` parsing, BCC/kernel workarounds, and output formatting.

## Why not perf or valgrind?

Generic profilers can't see inside Box64: valgrind drowns in JIT false
positives and tracks the *guest* heap rather than `customMalloc`; perf
samples host PCs with no semantic meaning for `AllocDynarecMap` or
`NewBox64Context`; htop / strace can't decompose the pressure-vessel
process tree. Full comparison and design rationale in
[`docs/positioning.md`](docs/positioning.md).

## Quick start

```bash
./install.sh                       # system-wide (uses sudo for /usr/local)
PREFIX=$HOME/.local ./install.sh   # user-local
sudo ./install.sh -y               # unattended (CI)
```

The installer auto-detects your distro (`/etc/os-release`), installs
`python3-bcc` if missing (apt / dnf / pacman / zypper), verifies that
`box64` is on `$PATH` and built with debug symbols, and installs the
tools and `web/` frontend so `box64_trace` and `box64_memleak` work
from anywhere. Skip flags: `--no-bcc`, `--no-box64-check`,
`--skip-deps`. Remove with `./uninstall.sh` (honors the same `$PREFIX`).

**Don't have Box64 yet?** Build from source with debug symbols (don't
strip):

```bash
git clone https://github.com/ptitSeb/box64.git
cd box64 && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DARM_DYNAREC=ON
make -j$(nproc) && sudo make install
```

## Run a tool

The fastest path is **spawn-and-trace mode** — the tracer launches your
program for you, attaches probes before any guest code runs, and opens
the browser dashboard. Stdio passes through and the tracer exits with
the program's return code.

```bash
sudo box64_trace -- ./MyGame.x86_64        # spawn-and-trace
sudo box64_trace                            # attach to all running box64 processes
sudo box64_trace --web                      # with the dashboard
sudo box64_memleak -p <PID>                 # leak detection on a running process
```

Common flags: `-b BINARY` (default `/usr/local/bin/box64`, falls back
to `which box64`), `-p PID` (`0` = all), `-i INTERVAL` (seconds),
`--browser CMD`, `--no-web`. Press **Ctrl+C** to stop and print the
full report.

You can also run from the repo without installing
(`sudo python3 box64_trace.py …`).

Spawn mode, dashboard panels, browser resolution, HTTP endpoints, and
crash behavior are documented in
[`docs/box64_trace.md`](docs/box64_trace.md).

## Documentation

- **[`docs/box64_memleak.md`](docs/box64_memleak.md)** — options, output, required symbols for the leak detector.
- **[`docs/box64_trace.md`](docs/box64_trace.md)** — options, output, dashboard reference, spawn mode, crash behavior.
- **[`docs/positioning.md`](docs/positioning.md)** — why these tools exist instead of perf / valgrind.
- **[`docs/architecture.md`](docs/architecture.md)** — project layout, shared helpers, tool pattern.
- **[`docs/troubleshooting.md`](docs/troubleshooting.md)** — overhead, stale-uprobe and BCC workarounds, common BPF compile failures.
- **[`docs/HOW_BOX64_WORKS.md`](docs/HOW_BOX64_WORKS.md)** — end-to-end picture of how Box64 executes an x86_64 binary.
- **[`docs/BOX64_FORK_EXEC_MEMORY.md`](docs/BOX64_FORK_EXEC_MEMORY.md)** — fork/exec/clone, custom allocator, JIT block management, pressure-vessel.
- **[`docs/BOX64_STEAM_INTERNALS.md`](docs/BOX64_STEAM_INTERNALS.md)** — pressure-vessel shim, Steam detection, env-var translation, D-Bus bypass.
- **[`docs/CI.md`](docs/CI.md)** — CI workflow details and how to reproduce each job locally.

## Development

```bash
pip install -r requirements-dev.txt

# Fast unit tests — no root, no BCC required (conftest.py mocks bcc).
pytest tests/ --tb=short \
    --ignore=tests/test_upstream_compat.py \
    --ignore=tests/test_ebpf_integration.py
```

Upstream compat and live E2E details are in [`docs/CI.md`](docs/CI.md).
