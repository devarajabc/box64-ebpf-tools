# Troubleshooting & operational notes

## Overhead

- Base probes (alloc / free) add minimal per-call overhead.
- `--stacks` (memleak) enables `BPF_STACK_TRACE` on every allocation —
  noticeably more expensive.
- `--no-prot`, `--no-threads`, `--no-cow` reduce probe count for lower
  overhead.
- Filtering by PID (`-p`) reduces overhead when multiple box64
  processes are running.
- The web dashboard (default-on; pass `--no-web` to disable) adds an
  HTTP server thread and per-event SSE fan-out; both are bounded by
  deque/queue caps in `box64_web.py`.

## Stale uprobe workaround

All tools call `_clear_stale_uprobes` (in `box64_common.py`) before
attaching, working around a kernel bug where stale `ref_ctr_offset`
values persist in the uprobe inode cache. Particularly relevant on
**Asahi Linux (16K page size)** kernels.

## BCC compatibility

`_bcc_has_atomic_increment` probes whether the installed BCC supports
`table.atomic_increment()`; older BCC versions fall back to
`_rewrite_atomic_increment`, which rewrites the BPF C source to use
`lookup_or_init` + `__sync_fetch_and_add`. On aarch64 with BCC 0.29.1,
`_patch_bcc_uretprobe` monkey-patches the ctypes binding for
`bpf_attach_uprobe` to always pass the 7th `ref_ctr_offset` argument.

## Common BPF compile failures

The tracer recognises the common cases and prints a one-line diagnosis
with the exact fix command:

- **Permission denied** — usually means you forgot `sudo`.
- **Missing kernel headers** — install `linux-headers-$(uname -r)`
  (apt) or the equivalent on your distro; BCC needs them at runtime to
  JIT-compile BPF programs.
- **Kernel ↔ BCC ABI skew** — your BCC is too old or too new for the
  running kernel; upgrade or downgrade `bpfcc-tools` / `python3-bcc`.
- **Stripped box64** — uprobes attach by symbol name; rebuild box64
  with `-DCMAKE_BUILD_TYPE=RelWithDebInfo` and don't strip.

For unknown exceptions, re-run with `BOX64_TRACE_DEBUG=1` for the full
traceback.
