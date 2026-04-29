# Architecture

## Project layout

```
box64_common.py        ~370 lines    shared helpers + diagnose_bpf_error / report_fatal
box64_memleak.py      ~1210 lines    custom-allocator leak detector
box64_trace.py        ~3550 lines    multi-process tracer + spawn mode + --web + crash handling
box64_web.py           ~310 lines    HTTP+SSE backend + browser auto-open + shutdown
web/                                 dashboard frontend (HTML/CSS/JS, MIT — see web/LICENSE-kbox)
install.sh             ~330 lines    distro-aware installer (BCC + box64 + browser + tools)
uninstall.sh            ~40 lines    symmetric removal

tests/                               328 unit tests + 3 upstream-compat tests + live e2e
  conftest.py                        mocks `bcc` so the unit suite runs without it
  test_spawn_mode.py                 fork/SIGSTOP gate + binary-resolver + cmd validation
  test_install_sh.py                 installer round-trip + distro + browser detection
  test_crash_handling.py             child-exit message format + dashboard shutdown
  test_browser_open.py               --browser flag + $BROWSER + xdg-open fallbacks
  test_error_diagnosis.py            BPF/BCC error pattern matching + report_fatal
  test_*.py                          fast pure-Python checks (no root, no BCC)
  test_ebpf_integration.py           E2E: runs each tool against live box64 workloads
  test_upstream_compat.py            verifies probed symbols & dynablock_t layout vs. box64 source
  dynarec_stress.c                   stress workload for the JIT probes
  memleak_leaker.c                   deliberately leaks via _exit(0) for memleak E2E
  steam_lifecycle.c                  fork/vfork/pthread workload for the tracer E2E

docs/                                per-tool reference + architecture notes
```

The code-review-graph reports 44 files across Python, C, JavaScript,
and bash.

## Shared helpers in `box64_common.py`

| Category | Helpers |
|---|---|
| Pure computation | `correlate_thread_parents`, `compute_cow_deltas`, `rank_items` |
| Formatters | `fmt_size`, `fmt_ns` |
| Symbol / binary | `check_binary`, `_read_symbols`, `check_symbols_soft` |
| `/proc` parsing | `read_smaps_rollup`, `read_minflt` |
| BCC / kernel workarounds | `_clear_stale_uprobes`, `_patch_bcc_uretprobe`, `_bcc_has_atomic_increment`, `_rewrite_atomic_increment` |

`box64_common.py` lazy-imports `bcc`, so it stays importable without
BCC installed (which is what lets the unit suite run on macOS / CI).
When adding a helper, check whether it already lives here before
duplicating it across the two tools.

## Tool pattern

Both `box64_memleak.py` and `box64_trace.py` follow the same shape:

1. **CLI args** parsed with `argparse`.
2. **Symbol validation** — `nm` / `nm -D` on the box64 binary; optional
   features auto-disable when their symbols are absent.
3. **BPF program compilation** — C source embedded as triple-quoted
   strings, compiled by BCC with `#define` flags for conditional
   feature gating (`TRACK_MEM`, `TRACK_DYNAREC`, `TRACK_BLOCK_DETAIL`,
   `TRACK_MMAP`, `TRACK_THREADS`, `TRACK_COW`, `TRACK_PROFILE` for
   `box64_trace.py`; `CAPTURE_STACKS`, `TRACK_MMAP`, `TRACK_32BIT`,
   `TRACK_THREADS`, `TRACK_COW` for `box64_memleak.py`).
4. **Probe attachment** — uprobes/uretprobes on box64 functions plus
   optional kprobe (`wp_page_copy` for CoW).
5. **Event loop** — periodic interval summaries (and perf-event buffer
   polling when enabled).
6. **Final report** — comprehensive output on Ctrl+C (histograms,
   top-N lists, process trees, timelines).
