# Why these tools exist (and not perf / valgrind)

These tools target **box64 developers and power users** debugging the
emulator itself or diagnosing why a specific x86 program misbehaves
under it. For profiling a normal Linux app, perf or valgrind are the
right answer — generic tools work fine for native code.

These exist because *box64* breaks the generic tools' assumptions in
specific ways:

| You'd reach for… | …but on box64 it falls short because |
|---|---|
| **valgrind** | box64 emits aarch64 code at runtime via DynaRec; memcheck either drowns in JIT false positives or breaks. Even when it runs, it tracks the *guest* x86 heap, not box64's own `customMalloc` (the 3-tier slab where DynaRec metadata, ELF mappings, and context structs actually live — i.e. where leaks actually are). Upstream box64 advises against running under valgrind. |
| **perf** | perf samples the host CPU. It doesn't know `AllocDynarecMap` is a JIT block allocation or that `NewBox64Context` opens a new emulated process — you get host PCs with no semantic meaning. perf can't decompose memory by category (custom allocator vs. JIT bytes vs. mmap vs. context structs). |
| **htop / ps aux** | They show "box64 is using 2 GB." They can't tell you which of those bytes are JIT churn vs. leaked guest mallocs vs. mmap-only regions, and Steam's pressure-vessel tree is opaque to them. |
| **strace / ltrace** | They see host syscalls. Almost everything interesting in box64 (DynaRec, register translation, custom allocator, signal trampolines) is intra-process and invisible to them. |

What this repo provides instead, attached by uprobe to the unmodified
release binary (no recompile, no LD_PRELOAD):

- **Symbol-level visibility into box64 internals** — `customMalloc` /
  `customFree`, `AllocDynarecMap` / `FreeDynarecMap`, `NewBox64Context`,
  `protectDB`, fork/exec wrappers.
- **Per-PID memory decomposition across the pressure-vessel process tree**
  — separates custom allocator vs. JIT vs. mmap vs. context structs.
- **JIT block churn / lifetime / protection-flip analysis** — the data
  you need to answer "is this game slow because box64 JIT is thrashing?".
- **CoW page-fault tracking** (`wp_page_copy` kprobe) for fork-heavy
  Steam workloads.
- **Crash attribution** — interpreter-mode comparison + signal capture
  to isolate DynaRec bugs from guest-code bugs (this is how the
  [TheRadioTower SIGABRT report](https://github.com/ptitSeb/box64/issues)
  was narrowed down).

Constraints: Linux-only (eBPF), requires root, `python3-bcc`, and a
box64 built with debug symbols (no strip). Tied to box64's symbol
stability — see `tests/test_upstream_compat.py`.
