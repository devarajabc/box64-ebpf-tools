#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# box64_trace.py — eBPF/BCC uprobe-based multi-process tracer for Box64.
# Tracks fork/exec/vfork process lifecycle, per-PID memory usage (custom allocator,
# DynaRec JIT, mmap), context creation/destruction, and (when present) pressure-vessel
# Steam containers across ALL concurrent box64 instances simultaneously.
#
# Requires: root, linux >=4.9, python3-bcc (BCC toolkit)
#
# Usage:
#   sudo python3 box64_trace.py [-b BINARY] [-p PID] [-i INTERVAL] \
#                               [--no-mem] [--no-dynarec] [--no-mmap] \
#                               [--no-threads] [--no-cow] [--hash-capacity N]

from __future__ import print_function
import argparse
import os
import signal
import struct
import subprocess
import sys
import time

# BCC is imported lazily inside main() so `--help` works on hosts without
# it. Kept as a module-level name (initially None) so tests can monkeypatch
# `box64_trace.BPF` to a mock before calling main().
BPF = None


def _import_bcc():
    """Populate the module-level BPF if not already set; return it."""
    global BPF
    if BPF is not None:
        return BPF
    try:
        from bcc import BPF as _BPF
        BPF = _BPF
        return BPF
    except ImportError:
        print("ERROR: python3-bcc (BCC toolkit) is required. Install it with:")
        print("  sudo apt install python3-bcc bpfcc-tools  # Debian/Ubuntu/Raspberry Pi OS")
        print("  sudo dnf install python3-bcc bcc-tools     # Fedora")
        print("  sudo pacman -S python-bcc bcc-tools        # Arch Linux / Manjaro ARM")
        print("  sudo zypper install python3-bcc bcc-tools  # openSUSE")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def format_log2_hist(hist_map, val_type="value"):
    """Format a BPF log2 histogram from a BPF_HISTOGRAM map."""
    lines = []
    items = []
    for k, v in hist_map.items():
        if v.value > 0:
            items.append((k.value, v.value))
    items.sort()

    if not items:
        lines.append("    (empty)")
        return "\n".join(lines)

    max_count = max(v for _, v in items)
    max_bar = 40

    for bucket, count in items:
        low = 1 << bucket
        high = (1 << (bucket + 1)) - 1
        bar_len = int(count * max_bar / max_count) if max_count > 0 else 0
        bar = "#" * bar_len
        if val_type == "ns":
            lines.append(f"    [{fmt_ns(low):>10s}, {fmt_ns(high):>10s}] : {count:>8} {bar}")
        elif val_type == "bytes":
            lines.append(f"    [{fmt_size(low):>10s}, {fmt_size(high):>10s}] : {count:>8} {bar}")
        else:
            lines.append(f"    [{low:>10}, {high:>10}] : {count:>8} {bar}")

    return "\n".join(lines)


def check_symbols(path, symbols):
    """Verify that required symbols are present in the binary."""
    out = _read_symbols(path)
    if not out:
        print("WARNING: 'nm' failed — cannot verify symbols. Continuing anyway.")
        return
    missing = [s for s in symbols if s not in out]
    if missing:
        print(f"ERROR: required symbols not found in {path}: {', '.join(missing)}")
        print("Make sure box64 is built with debug symbols (RelWithDebInfo) and not stripped.")
        sys.exit(1)


def _read_block_from_fd(f, actual_block_addr):
    """Read dynablock_t metadata using an already-open /proc/PID/mem fd.

    dynablock_t layout (key offsets, post x64_readaddr insertion at 0x38):
      0x00: block (void*)        - pointer to native code start
      0x08: actual_block (void*) - the allocation base
      0x20: x64_addr (uintptr_t) - original x86_64 address
      0x28: x64_size (int)       - x86_64 code size
      0x30: native_size (int)    - JIT native code size
      0x54: isize (int)          - instruction count
    """
    try:
        f.seek(actual_block_addr)
        db_ptr_bytes = f.read(8)
        if len(db_ptr_bytes) < 8:
            return None
        db_ptr = struct.unpack("<Q", db_ptr_bytes)[0]
        if db_ptr == 0:
            return None
        f.seek(db_ptr)
        data = f.read(0x58)
        if len(data) < 0x58:
            return None
        block = struct.unpack_from("<Q", data, 0x00)[0]
        x64_addr = struct.unpack_from("<Q", data, 0x20)[0]
        x64_size = struct.unpack_from("<Q", data, 0x28)[0]
        native_size = struct.unpack_from("<Q", data, 0x30)[0]
        isize = struct.unpack_from("<i", data, 0x54)[0]
        return {
            "block": block,
            "x64_addr": x64_addr,
            "x64_size": x64_size,
            "native_size": native_size,
            "isize": isize,
        }
    except (OSError, struct.error):
        return None


def read_proc_cmdline(pid):
    """Read /proc/PID/cmdline and return argv[0..1] for process labeling."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            data = f.read()
        args = data.split(b'\x00')
        parts = []
        for a in args:
            if not a:
                continue
            decoded = a.decode(errors='replace')
            basename = decoded.split('/')[-1]
            parts.append(basename)
            if len(parts) >= 2:
                break
        if parts:
            # If argv[0] is "box64" and there's a second arg, use that
            if parts[0] == "box64" and len(parts) > 1:
                return parts[1]
            return parts[0]
    except OSError:
        pass
    return f"pid{pid}"


def read_block_metadata(pid, alloc_addr):
    """Read dynablock_t metadata via /proc/PID/mem.

    alloc_addr is the actual_block pointer returned by AllocDynarecMap.
    Layout: *(dynablock_t**)alloc_addr = pointer to dynablock_t struct.
    """
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            # Read dynablock_t* from *(void**)alloc_addr
            f.seek(alloc_addr)
            db_ptr = struct.unpack("Q", f.read(8))[0]
            if db_ptr == 0:
                return None
            # Read a contiguous chunk from offset 0x18 to 0x58 (64 bytes)
            # to minimize seeks
            f.seek(db_ptr + 0x18)
            data = f.read(0x58 - 0x18)  # 64 bytes
            if len(data) < 0x58 - 0x18:
                return None
            in_used = struct.unpack_from("I", data, 0x00)[0]        # 0x18
            tick = struct.unpack_from("I", data, 0x04)[0]           # 0x1c
            x64_addr = struct.unpack_from("Q", data, 0x08)[0]      # 0x20
            x64_size = struct.unpack_from("Q", data, 0x10)[0]      # 0x28
            native_size = struct.unpack_from("Q", data, 0x18)[0]   # 0x30
            # 0x38: x64_readaddr (skip), 0x40: prefixsize (skip), 0x44: size
            total_size = struct.unpack_from("i", data, 0x2c)[0]    # 0x44
            hash_val = struct.unpack_from("I", data, 0x30)[0]      # 0x48
            done, gone, dirty, flags_byte = struct.unpack_from("BBBB", data, 0x34)  # 0x4c-0x4f
            isize = struct.unpack_from("i", data, 0x3c)[0]         # 0x54
            return {
                "tick": tick, "in_used": in_used,
                "x64_addr": x64_addr, "x64_size": x64_size,
                "native_size": native_size, "total_size": total_size,
                "hash": hash_val, "isize": isize,
                "done": done, "gone": gone, "dirty": dirty,
                "always_test": flags_byte & 0x3,
            }
    except (OSError, struct.error):
        return None


# ---------------------------------------------------------------------------
# BPF C program
# ---------------------------------------------------------------------------

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

// ---- Helpers ----

static inline u64 tid_key(void) {
    return bpf_get_current_pid_tgid();
}

static inline u32 get_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

// ---- Per-process memory accounting ----

struct proc_mem_t {
    u64 malloc_count;
    u64 malloc_bytes;
    u64 free_count;
    u64 free_bytes;
    u64 calloc_count;
    u64 realloc_count;
    u64 jit_alloc_count;
    u64 jit_alloc_bytes;
    u64 jit_free_count;
    u64 jit_free_bytes;
    u64 mmap_count;
    u64 mmap_bytes;
    u64 munmap_count;
    u64 box_mmap_count;
    u64 box_mmap_bytes;
    u64 box_munmap_count;
    u64 context_created;
    u64 context_freed;
};

BPF_HASH(proc_mem, u32, struct proc_mem_t, 256);

static inline struct proc_mem_t *get_or_init_proc_mem(u32 pid) {
    struct proc_mem_t *pm = proc_mem.lookup(&pid);
    if (!pm) {
        struct proc_mem_t zero = {};
        proc_mem.update(&pid, &zero);
        pm = proc_mem.lookup(&pid);
    }
    return pm;
}

// ---- Global statistics ----
// [0]=malloc_count  [1]=free_count  [2]=calloc_count  [3]=realloc_count
// [4]=malloc_bytes  [5]=free_bytes
// [6]=jit_alloc     [7]=jit_free    [8]=jit_alloc_bytes  [9]=jit_free_bytes
// [10]=mmap_count   [11]=munmap_count [12]=box_mmap_count [13]=box_munmap_count
// [14]=fork_count   [15]=vfork_count  [16]=exec_count     [17]=posix_spawn_count
// [18]=context_new  [19]=context_free [20]=pressure_vessel_count
// [21]=jit_churn_count  [22]=jit_outstanding_bytes
// [23]=protect_calls  [24]=unprotect_calls  [25]=setprot_calls
// [26]=protect_bytes  [27]=unprotect_bytes  [28]=setprot_bytes
// [29]=invalidation_count  [30]=mark_dirty_count
// [31]=jit_outstanding_blocks
BPF_ARRAY(steam_stats, u64, 32);

static inline void inc_stat(int idx, u64 val) {
    int key = idx;
    u64 *v = steam_stats.lookup(&key);
    if (v) __sync_fetch_and_add(v, val);
}

static inline void dec_stat(int idx, u64 val) {
    int key = idx;
    u64 *v = steam_stats.lookup(&key);
    if (v) __sync_fetch_and_sub(v, val);
}

static inline int log2_u64(u64 v) {
    int r = 0;
    while (v >>= 1) r++;
    return r;
}

// ---- Lifecycle event perf output ----
// Event types:
//  0=fork  1=vfork  2=x64emu_fork  3=fork_child
//  4=execv  5=execve  6=execvp  7=execvpe
//  8=posix_spawn  9=posix_spawnp  10=pressure_vessel
//  11=new_context  12=free_context  13=calc_stack

#define PATHLEN 128

struct lifecycle_event_t {
    u32  pid;
    u32  tid;
    u64  timestamp_ns;
    u8   event_type;
    u32  child_pid;
    int  forktype;
    char path[PATHLEN];
    u64  extra;          // argc for new_context, stack_size for calc_stack
};

BPF_PERF_OUTPUT(lifecycle_events);

// ---- Entry/return handoff maps ----

#ifdef TRACK_MEM
struct alloc_pending_t {
    u64 size;
    u64 old_ptr;
    u8  type;     // 0=malloc, 1=calloc, 2=realloc
};
BPF_HASH(alloc_pending, u64, struct alloc_pending_t);

struct malloc_block_t {
    u64 size;
    u32 pid;
};
BPF_HASH(malloc_blocks, u64, struct malloc_block_t, HASH_CAPACITY);
#endif

#ifdef TRACK_DYNAREC
struct jit_pending_t {
    u64 x64_addr;
    u64 size;
    int is_new;
};
BPF_HASH(jit_pending, u64, struct jit_pending_t);

struct jit_block_t {
    u64 size;
    u64 x64_addr;
    u64 alloc_ns;
    u32 pid;
    u32 tid;
    int is_new;
};
BPF_HASH(jit_blocks, u64, struct jit_block_t, HASH_CAPACITY);

struct churn_event_t {
    u64 x64_addr;
    u64 alloc_addr;
    u64 size;
    u64 lifetime_ns;
    u32 pid;
};
BPF_PERF_OUTPUT(churn_events);
// `alloc_sizes` is fed by BOTH JIT block allocations (AllocDynarecMap)
// AND custom-allocator allocations (customMalloc/Calloc/Realloc).
// Without the customMalloc feed the chart never shows the 64B/128B slab
// tier — i.e. the bulk of small allocations are invisible. The two
// subsystems share a single histogram so the dashboard label
// ("Allocation Size Distribution") matches its content.
BPF_HISTOGRAM(alloc_sizes, int, 64);
BPF_HISTOGRAM(block_lifetimes, int, 64);

#ifdef TRACK_BLOCK_DETAIL
struct block_death_event_t {
    u64  x64_addr;
    u64  alloc_addr;
    u64  x64_size;
    u64  native_size;
    u64  lifetime_ns;
    u32  tick;
    u32  hash;
    u32  isize;
    u32  pid;
    u8   dirty;
    u8   always_test;
    u8   gone;
    u8   is_new;
};
BPF_PERF_OUTPUT(block_death_events);

struct invalidation_event_t {
    u64  x64_addr;
    u64  x64_size;
    u32  hash;
    u32  isize;
    u32  tick;
    u32  pid;
};
BPF_PERF_OUTPUT(invalidation_events);

struct unprot_event_t {
    u64  addr;
    u64  size;
    u32  pid;
    u8   mark;
};
BPF_PERF_OUTPUT(unprot_events);

BPF_HISTOGRAM(death_isizes, int, 64);
BPF_HISTOGRAM(death_native_sizes, int, 64);
#endif /* TRACK_BLOCK_DETAIL */
#endif

#ifdef TRACK_MMAP
// Separate pending maps to avoid TID collision (box_mmap calls InternalMmap)
BPF_HASH(immap_pending, u64, u64);   // tid -> length for InternalMmap
BPF_HASH(bmmap_pending, u64, u64);   // tid -> length for box_mmap

struct mmap_block_t {
    u64 length;
    u32 pid;
};
BPF_HASH(mmap_blocks, u64, struct mmap_block_t, 65536);
#endif

// ---- Thread / process lifecycle tracking ----
#ifdef TRACK_THREADS

struct thread_info_t {
    u64  start_routine;
    u64  create_ns;
    u32  creator_tid;
    u32  pid;
};

struct thread_stats_t {
    u64  alloc_count;
    u64  free_count;
    u64  alloc_bytes;
    u64  freed_bytes;
};

struct thread_event_t {
    u32  tid;
    u32  pid;
    u64  x64_fnc;
    u64  timestamp_ns;
    u32  creator_tid;
    u32  child_pid;
    u8   event_type;      // 0=started, 1=destroyed, 2=fork, 3=clone,
                          // 4=create_request, 5=clone_return
};

BPF_HASH(active_threads, u32, struct thread_info_t, 1024);
BPF_HASH(thread_stats, u32, struct thread_stats_t, 1024);
// [0]=created, [1]=destroyed, [2]=peak, [3]=current, [4]=forks, [5]=clones
BPF_ARRAY(thread_counters, u64, 6);
BPF_PERF_OUTPUT(thread_events);

static inline void inc_thread_ctr(int idx, u64 val) {
    int key = idx;
    u64 *v = thread_counters.lookup(&key);
    if (v) __sync_fetch_and_add(v, val);
}

static inline void update_thread_alloc(u64 size) {
    u32 tid = (u32)tid_key();
    struct thread_stats_t *ts = thread_stats.lookup(&tid);
    if (!ts) {
        struct thread_stats_t zero = {};
        thread_stats.update(&tid, &zero);
        ts = thread_stats.lookup(&tid);
    }
    if (ts) {
        __sync_fetch_and_add(&ts->alloc_count, 1);
        __sync_fetch_and_add(&ts->alloc_bytes, size);
    }
}

static inline void update_thread_free(u64 size) {
    u32 tid = (u32)tid_key();
    struct thread_stats_t *ts = thread_stats.lookup(&tid);
    if (!ts) {
        struct thread_stats_t zero = {};
        thread_stats.update(&tid, &zero);
        ts = thread_stats.lookup(&tid);
    }
    if (ts) {
        __sync_fetch_and_add(&ts->free_count, 1);
        __sync_fetch_and_add(&ts->freed_bytes, size);
    }
}

#endif /* TRACK_THREADS - structs/helpers */


// =========================================================================
// Fork / Exec / Lifecycle Probes (always enabled)
// =========================================================================

// ---- my_fork(x64emu_t* emu) ----
int fork_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(14, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 0;
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));

#ifdef TRACK_THREADS
    inc_thread_ctr(4, 1);
    struct thread_event_t tevt = {};
    tevt.tid = evt.tid;
    tevt.pid = evt.pid;
    tevt.timestamp_ns = evt.timestamp_ns;
    tevt.creator_tid = evt.tid;
    tevt.event_type = 2;
    thread_events.perf_submit(ctx, &tevt, sizeof(tevt));
#endif
    return 0;
}

// ---- my_vfork(x64emu_t* emu) ----
int vfork_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(15, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 1;
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- x64emu_fork(x64emu_t* emu, int forktype) ----
int x64emu_fork_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 2;
    evt.forktype = (int)PT_REGS_PARM2(ctx);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- sched_process_fork tracepoint: capture parent->child PID ----
TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_pid = args->parent_pid;
    // Only track if parent is a known box64 process
    struct proc_mem_t *pm = proc_mem.lookup(&parent_pid);
    if (!pm) return 0;

#ifdef FILTER_PID
    if (parent_pid != FILTER_PID) return 0;
#endif

    u32 child_pid = args->child_pid;

    // Initialize proc_mem for child process
    struct proc_mem_t child_zero = {};
    proc_mem.update(&child_pid, &child_zero);

    struct lifecycle_event_t evt = {};
    evt.pid = parent_pid;
    evt.tid = 0;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 3;   // fork_child
    evt.child_pid = child_pid;
    lifecycle_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// ---- my_execv(x64emu_t* emu, const char* path, ...) ----
int execv_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(16, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 4;
    const char *path = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), path);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- my_execve(x64emu_t* emu, const char* path, ...) ----
int execve_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(16, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 5;
    const char *path = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), path);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- my_execvp(x64emu_t* emu, const char* path, ...) ----
int execvp_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(16, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 6;
    const char *path = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), path);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- my_execvpe(x64emu_t* emu, const char* path, ...) ----
int execvpe_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(16, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 7;
    const char *path = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), path);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- my_posix_spawn(emu, pid_ptr, fullpath, ...) — PARM3=path ----
int posix_spawn_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(17, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 8;
    const char *path = (const char *)PT_REGS_PARM3(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), path);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- my_posix_spawnp(emu, pid_ptr, path, ...) — PARM3=path ----
int posix_spawnp_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(17, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 9;
    const char *path = (const char *)PT_REGS_PARM3(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), path);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- pressure_vessel(argc, argv, nextarg, prog) — PARM4=prog ----
int pressure_vessel_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(20, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 10;
    const char *prog = (const char *)PT_REGS_PARM4(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), prog);
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- NewBox64Context(int argc) ----
int new_context_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u32 pid = get_pid();
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (pm) __sync_fetch_and_add(&pm->context_created, 1);
    inc_stat(18, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = pid;
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 11;
    evt.extra = (u64)PT_REGS_PARM1(ctx);  // argc
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- FreeBox64Context(box64context_t** context) ----
int free_context_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u32 pid = get_pid();
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (pm) __sync_fetch_and_add(&pm->context_freed, 1);
    inc_stat(19, 1);

    struct lifecycle_event_t evt = {};
    evt.pid = pid;
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 12;
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- CalcStackSize(box64context_t *context) return ----
int calc_stack_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct lifecycle_event_t evt = {};
    evt.pid = get_pid();
    evt.tid = (u32)tid_key();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 13;
    evt.extra = (u64)PT_REGS_RC(ctx);  // return value (0 on success)
    lifecycle_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}


// =========================================================================
// Custom Allocator Probes (TRACK_MEM)
// =========================================================================
#ifdef TRACK_MEM

// ---- customMalloc(size_t size) entry ----
int malloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct alloc_pending_t p = {};
    p.size = PT_REGS_PARM1(ctx);
    p.type = 0;
    u64 tid = tid_key();
    alloc_pending.update(&tid, &p);
    return 0;
}

// ---- customMalloc return (also used by customCalloc) ----
int malloc_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    struct alloc_pending_t *p = alloc_pending.lookup(&tid);
    if (!p) return 0;

    u64 ptr = PT_REGS_RC(ctx);
    if (ptr == 0) {
        alloc_pending.delete(&tid);
        return 0;
    }

    u32 pid = get_pid();
    struct malloc_block_t blk = { .size = p->size, .pid = pid };
    malloc_blocks.update(&ptr, &blk);

    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (pm) {
        if (p->type == 1) {
            __sync_fetch_and_add(&pm->calloc_count, 1);
        } else {
            __sync_fetch_and_add(&pm->malloc_count, 1);
        }
        __sync_fetch_and_add(&pm->malloc_bytes, p->size);
    }
    inc_stat(p->type == 1 ? 2 : 0, 1);
    inc_stat(4, p->size);
#ifdef TRACK_THREADS
    update_thread_alloc(p->size);
#endif

    // Feed the unified Allocation Size Distribution. Without this the
    // 64B/128B slab tier is invisible — the chart only ever showed JIT
    // page allocations.
    int mb = log2_u64(p->size);
    alloc_sizes.atomic_increment(mb);

    alloc_pending.delete(&tid);
    return 0;
}

// ---- customFree(void* p) ----
int free_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 ptr = PT_REGS_PARM1(ctx);
    if (ptr == 0) return 0;

    u32 pid = get_pid();
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);

    struct malloc_block_t *blk = malloc_blocks.lookup(&ptr);
    if (blk) {
        if (pm) __sync_fetch_and_add(&pm->free_bytes, blk->size);
        inc_stat(5, blk->size);
#ifdef TRACK_THREADS
        update_thread_free(blk->size);
#endif
        malloc_blocks.delete(&ptr);
    }

    if (pm) __sync_fetch_and_add(&pm->free_count, 1);
    inc_stat(1, 1);
    return 0;
}

// ---- customCalloc(size_t n, size_t size) entry ----
int calloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct alloc_pending_t p = {};
    p.size = PT_REGS_PARM1(ctx) * PT_REGS_PARM2(ctx);
    p.type = 1;
    u64 tid = tid_key();
    alloc_pending.update(&tid, &p);
    return 0;
}

// ---- customRealloc(void* p, size_t size) entry ----
int realloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct alloc_pending_t p = {};
    p.old_ptr = PT_REGS_PARM1(ctx);
    p.size = PT_REGS_PARM2(ctx);
    p.type = 2;
    u64 tid = tid_key();
    alloc_pending.update(&tid, &p);
    return 0;
}

// ---- customRealloc return ----
int realloc_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    struct alloc_pending_t *p = alloc_pending.lookup(&tid);
    if (!p) return 0;

    u64 new_ptr = PT_REGS_RC(ctx);
    u32 pid = get_pid();
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);

    // Remove old allocation
    if (p->old_ptr != 0) {
        struct malloc_block_t *old = malloc_blocks.lookup(&p->old_ptr);
        if (old) {
            if (pm) __sync_fetch_and_add(&pm->free_bytes, old->size);
            inc_stat(5, old->size);
#ifdef TRACK_THREADS
            update_thread_free(old->size);
#endif
        }
        malloc_blocks.delete(&p->old_ptr);
    }

    // Record new allocation
    if (new_ptr != 0) {
        struct malloc_block_t blk = { .size = p->size, .pid = pid };
        malloc_blocks.update(&new_ptr, &blk);
        if (pm) __sync_fetch_and_add(&pm->malloc_bytes, p->size);
        inc_stat(4, p->size);
#ifdef TRACK_THREADS
        update_thread_alloc(p->size);
#endif
        int rb = log2_u64(p->size);
        alloc_sizes.atomic_increment(rb);
    }

    if (pm) __sync_fetch_and_add(&pm->realloc_count, 1);
    inc_stat(3, 1);

    alloc_pending.delete(&tid);
    return 0;
}

#endif /* TRACK_MEM */


// =========================================================================
// DynaRec JIT Probes (TRACK_DYNAREC)
// =========================================================================
#ifdef TRACK_DYNAREC

// ---- AllocDynarecMap(uintptr_t x64_addr, size_t size, int is_new) entry ----
int jit_alloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct jit_pending_t p = {};
    p.x64_addr = PT_REGS_PARM1(ctx);
    p.size     = PT_REGS_PARM2(ctx);
    p.is_new   = (int)PT_REGS_PARM3(ctx);
    u64 tid = tid_key();
    jit_pending.update(&tid, &p);
    return 0;
}

// ---- AllocDynarecMap return ----
int jit_alloc_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    struct jit_pending_t *p = jit_pending.lookup(&tid);
    if (!p) return 0;

    u64 alloc_addr = PT_REGS_RC(ctx);
    if (alloc_addr != 0) {
        u32 pid = get_pid();
        struct jit_block_t blk = {};
        blk.size     = p->size;
        blk.x64_addr = p->x64_addr;
        blk.alloc_ns = bpf_ktime_get_ns();
        blk.pid      = pid;
        blk.tid      = (u32)tid;
        blk.is_new   = p->is_new;
        jit_blocks.update(&alloc_addr, &blk);

        struct proc_mem_t *pm = get_or_init_proc_mem(pid);
        if (pm) {
            __sync_fetch_and_add(&pm->jit_alloc_count, 1);
            __sync_fetch_and_add(&pm->jit_alloc_bytes, p->size);
        }
        inc_stat(6, 1);
        inc_stat(8, p->size);
        inc_stat(22, p->size);  // outstanding_bytes
        inc_stat(31, 1);        // outstanding_blocks

        int bucket = log2_u64(p->size);
        alloc_sizes.atomic_increment(bucket);
#ifdef TRACK_THREADS
        update_thread_alloc(p->size);
#endif
    }

    jit_pending.delete(&tid);
    return 0;
}

// ---- FreeDynarecMap(uintptr_t addr) entry ----
int jit_free_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 addr = PT_REGS_PARM1(ctx);
    if (addr == 0) return 0;

    struct jit_block_t *blk = jit_blocks.lookup(&addr);
    if (blk) {
        u32 pid = get_pid();
        struct proc_mem_t *pm = get_or_init_proc_mem(pid);
        if (pm) {
            __sync_fetch_and_add(&pm->jit_free_count, 1);
            __sync_fetch_and_add(&pm->jit_free_bytes, blk->size);
        }
        inc_stat(7, 1);
        inc_stat(9, blk->size);
        dec_stat(22, blk->size);  // outstanding_bytes
        dec_stat(31, 1);          // outstanding_blocks

        // Lifetime histogram
        u64 now = bpf_ktime_get_ns();
        u64 lifetime = now - blk->alloc_ns;
        int lt_bucket = log2_u64(lifetime);
        block_lifetimes.atomic_increment(lt_bucket);

        // Churn detection
        u64 churn_ns = CHURN_THRESHOLD_NS;
        if (lifetime < churn_ns) {
            inc_stat(21, 1);  // jit_churn_count

            struct churn_event_t evt = {};
            evt.x64_addr    = blk->x64_addr;
            evt.alloc_addr  = addr;
            evt.size        = blk->size;
            evt.lifetime_ns = lifetime;
            evt.pid         = blk->pid;
            churn_events.perf_submit(ctx, &evt, sizeof(evt));
        }

#ifdef TRACK_THREADS
        update_thread_free(blk->size);
#endif
        jit_blocks.delete(&addr);
    }
    return 0;
}

#ifdef TRACK_BLOCK_DETAIL

// ---- FreeDynablock(dynablock_t* db, int need_lock, int need_remove) ----
// dynablock_t offsets:
//   0x08: actual_block (void*)
//   0x1c: tick (u32)
//   0x20: x64_addr (void*)
//   0x28: x64_size (u64)
//   0x30: native_size (u64)
//   0x48: hash (u32)
//   0x4c: done (u8), 0x4d: gone (u8), 0x4e: dirty (u8), 0x4f: always_test (u8 bitfield)
//   0x54: isize (i32)
int freedynablock_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 db_ptr = PT_REGS_PARM1(ctx);
    if (db_ptr == 0) return 0;

    struct block_death_event_t evt = {};
    evt.pid = get_pid();

    // Read fields from dynablock_t
    bpf_probe_read_user(&evt.tick, sizeof(evt.tick), (void*)(db_ptr + 0x1c));
    bpf_probe_read_user(&evt.x64_addr, sizeof(evt.x64_addr), (void*)(db_ptr + 0x20));
    bpf_probe_read_user(&evt.x64_size, sizeof(evt.x64_size), (void*)(db_ptr + 0x28));
    bpf_probe_read_user(&evt.native_size, sizeof(evt.native_size), (void*)(db_ptr + 0x30));
    bpf_probe_read_user(&evt.hash, sizeof(evt.hash), (void*)(db_ptr + 0x48));
    bpf_probe_read_user(&evt.dirty, sizeof(evt.dirty), (void*)(db_ptr + 0x4e));
    u8 flags_byte = 0;
    bpf_probe_read_user(&flags_byte, sizeof(flags_byte), (void*)(db_ptr + 0x4f));
    evt.always_test = flags_byte & 0x3;
    bpf_probe_read_user(&evt.gone, sizeof(evt.gone), (void*)(db_ptr + 0x4d));
    bpf_probe_read_user(&evt.isize, sizeof(evt.isize), (void*)(db_ptr + 0x54));

    // Read actual_block to look up our jit_blocks map
    u64 actual_block = 0;
    bpf_probe_read_user(&actual_block, sizeof(actual_block), (void*)(db_ptr + 0x08));
    evt.alloc_addr = actual_block;

    // Try to get lifetime from our tracking
    struct jit_block_t *blk = jit_blocks.lookup(&actual_block);
    if (blk) {
        u64 now = bpf_ktime_get_ns();
        evt.lifetime_ns = now - blk->alloc_ns;
        evt.is_new = (u8)blk->is_new;
    }

    // Histograms
    if (evt.isize > 0) {
        int is_bucket = log2_u64((u64)evt.isize);
        death_isizes.atomic_increment(is_bucket);
    }
    if (evt.native_size > 0) {
        int ns_bucket = log2_u64(evt.native_size);
        death_native_sizes.atomic_increment(ns_bucket);
    }

    block_death_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- InvalidDynablock(dynablock_t* db, int need_lock) ----
int invaliddynablock_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 db_ptr = PT_REGS_PARM1(ctx);
    if (db_ptr == 0) return 0;

    inc_stat(29, 1);  // invalidation_count

    struct invalidation_event_t evt = {};
    evt.pid = get_pid();
    bpf_probe_read_user(&evt.x64_addr, sizeof(evt.x64_addr), (void*)(db_ptr + 0x20));
    bpf_probe_read_user(&evt.x64_size, sizeof(evt.x64_size), (void*)(db_ptr + 0x28));
    bpf_probe_read_user(&evt.hash, sizeof(evt.hash), (void*)(db_ptr + 0x48));
    bpf_probe_read_user(&evt.isize, sizeof(evt.isize), (void*)(db_ptr + 0x54));
    bpf_probe_read_user(&evt.tick, sizeof(evt.tick), (void*)(db_ptr + 0x1c));

    invalidation_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- MarkDynablock(dynablock_t* db) ----
int markdynablock_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(30, 1);  // mark_dirty_count
    return 0;
}

#endif /* TRACK_BLOCK_DETAIL */

#endif /* TRACK_DYNAREC */


// =========================================================================
// Protection Probes (TRACK_PROT)
// =========================================================================
#ifdef TRACK_PROT

// void protectDB(uintptr_t addr, uintptr_t size)
int protect_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(23, 1);
    u64 size = PT_REGS_PARM2(ctx);
    inc_stat(26, size);
    return 0;
}

// void unprotectDB(uintptr_t addr, size_t size, int mark)
int unprotect_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(24, 1);
    u64 size = PT_REGS_PARM2(ctx);
    inc_stat(27, size);

#ifdef TRACK_BLOCK_DETAIL
    struct unprot_event_t evt = {};
    evt.addr = PT_REGS_PARM1(ctx);
    evt.size = size;
    evt.pid = get_pid();
    evt.mark = (u8)PT_REGS_PARM3(ctx);
    unprot_events.perf_submit(ctx, &evt, sizeof(evt));
#endif
    return 0;
}

// void setProtection(uintptr_t addr, size_t size, uint32_t prot)
int setprot_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(25, 1);
    u64 size = PT_REGS_PARM2(ctx);
    inc_stat(28, size);
    return 0;
}

#endif /* TRACK_PROT */


// =========================================================================
// Mmap Probes (TRACK_MMAP)
// =========================================================================
#ifdef TRACK_MMAP

// ---- InternalMmap entry ----
int immap_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 length = PT_REGS_PARM2(ctx);
    u64 tid = tid_key();
    immap_pending.update(&tid, &length);
    return 0;
}

// ---- InternalMmap return ----
int immap_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    u64 *length = immap_pending.lookup(&tid);
    if (!length) return 0;

    u64 addr = PT_REGS_RC(ctx);
    if ((long)addr < 0) {   // MAP_FAILED == (void*)-1
        immap_pending.delete(&tid);
        return 0;
    }

    u32 pid = get_pid();
    struct mmap_block_t blk = { .length = *length, .pid = pid };
    mmap_blocks.update(&addr, &blk);

    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (pm) {
        __sync_fetch_and_add(&pm->mmap_count, 1);
        __sync_fetch_and_add(&pm->mmap_bytes, *length);
    }
    inc_stat(10, 1);

    immap_pending.delete(&tid);
    return 0;
}

// ---- InternalMunmap entry ----
int imunmap_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 addr = PT_REGS_PARM1(ctx);
    mmap_blocks.delete(&addr);
    u32 pid = get_pid();
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (pm) __sync_fetch_and_add(&pm->munmap_count, 1);
    inc_stat(11, 1);
    return 0;
}

// ---- box_mmap entry ----
int bmmap_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 length = PT_REGS_PARM2(ctx);
    u64 tid = tid_key();
    bmmap_pending.update(&tid, &length);
    return 0;
}

// ---- box_mmap return ----
int bmmap_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    u64 *length = bmmap_pending.lookup(&tid);
    if (!length) return 0;

    u64 addr = PT_REGS_RC(ctx);
    if ((long)addr < 0) {
        bmmap_pending.delete(&tid);
        return 0;
    }

    u32 pid = get_pid();
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (pm) {
        __sync_fetch_and_add(&pm->box_mmap_count, 1);
        __sync_fetch_and_add(&pm->box_mmap_bytes, *length);
    }
    inc_stat(12, 1);

    bmmap_pending.delete(&tid);
    return 0;
}

// ---- box_munmap entry ----
int bmunmap_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u32 pid = get_pid();
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (pm) __sync_fetch_and_add(&pm->box_munmap_count, 1);
    inc_stat(13, 1);
    return 0;
}

#endif /* TRACK_MMAP */


// =========================================================================
// Thread lifecycle probes (TRACK_THREADS)
// =========================================================================
#ifdef TRACK_THREADS

// ---- my_pthread_create entry ----
int thread_create_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_thread_ctr(0, 1);

    struct thread_event_t evt = {};
    evt.tid = (u32)tid_key();
    evt.pid = get_pid();
    evt.x64_fnc = PT_REGS_PARM4(ctx);
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.creator_tid = evt.tid;
    evt.event_type = 4;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- my_pthread_create return ----
int thread_create_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 0) {
        int key = 0;
        u64 *v = thread_counters.lookup(&key);
        if (v && *v > 0) __sync_fetch_and_sub(v, 1);
    }
    return 0;
}

// ---- pthread_routine — fires in the NEW thread ----
int thread_start_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u32 tid = (u32)tid_key();
    void *arg = (void*)PT_REGS_PARM1(ctx);

    struct thread_info_t info = {};
    bpf_probe_read_user(&info.start_routine, sizeof(info.start_routine), arg);
    info.create_ns = bpf_ktime_get_ns();
    info.pid = get_pid();
    info.creator_tid = 0;

    active_threads.update(&tid, &info);
    inc_thread_ctr(3, 1);

    int peak_key = 2, cur_key = 3;
    u64 *peak = thread_counters.lookup(&peak_key);
    u64 *cur = thread_counters.lookup(&cur_key);
    if (peak && cur && *cur > *peak) {
        *peak = *cur;
    }

    struct thread_event_t evt = {};
    evt.tid = tid;
    evt.pid = get_pid();
    evt.x64_fnc = info.start_routine;
    evt.timestamp_ns = info.create_ns;
    evt.event_type = 0;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- emuthread_destroy ----
int thread_destroy_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u32 tid = (u32)tid_key();

    inc_thread_ctr(1, 1);
    int cur_key = 3;
    u64 *cur = thread_counters.lookup(&cur_key);
    if (cur && *cur > 0) __sync_fetch_and_sub(cur, 1);

    struct thread_info_t *info = active_threads.lookup(&tid);
    struct thread_event_t evt = {};
    evt.tid = tid;
    evt.pid = get_pid();
    evt.x64_fnc = info ? info->start_routine : 0;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.event_type = 1;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));

    active_threads.delete(&tid);
    return 0;
}

// ---- my_clone entry ----
int clone_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_thread_ctr(5, 1);

    struct thread_event_t evt = {};
    evt.tid = (u32)tid_key();
    evt.pid = get_pid();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.creator_tid = evt.tid;
    evt.event_type = 3;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ---- my_clone return ----
int clone_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    struct thread_event_t evt = {};
    evt.tid = (u32)tid_key();
    evt.pid = get_pid();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.creator_tid = evt.tid;
    evt.child_pid = (u32)ret;
    evt.event_type = 5;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

#endif /* TRACK_THREADS */


// =========================================================================
// Copy-on-Write page fault tracking (TRACK_COW)
// =========================================================================
#ifdef TRACK_COW

struct cow_stats_t {
    u64 cow_faults;
};

BPF_HASH(cow_per_pid, u32, struct cow_stats_t, 256);

int trace_cow_fault(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct cow_stats_t *cs = cow_per_pid.lookup(&pid);
    if (!cs) {
        struct cow_stats_t zero = {};
        cow_per_pid.update(&pid, &zero);
        cs = cow_per_pid.lookup(&pid);
    }
    if (cs) {
        __sync_fetch_and_add(&cs->cow_faults, 1);
    }
    return 0;
}

#endif /* TRACK_COW */


// =========================================================================
// PC Sampling Profile (TRACK_PROFILE)
// =========================================================================
#ifdef TRACK_PROFILE

// BCC helpers.h only forward-declares bpf_perf_event_data; provide the
// definition so we can access ctx->regs on all architectures.
// Use struct pt_regs (from ptrace.h) since bpf_user_pt_regs_t may not
// be available in all BCC versions.
struct bpf_perf_event_data {
    struct pt_regs regs;
    __u64 sample_period;
    __u64 addr;
};

struct pc_key_t {
    u32 pid;
    u32 bucket;    // ip >> 8 (256-byte granularity)
};

BPF_HASH(pc_samples, struct pc_key_t, u64, PROFILE_CAPACITY);

int on_perf_sample(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct proc_mem_t *pm = get_or_init_proc_mem(pid);
    if (!pm) return 0;

    u64 ip = PT_REGS_IP(&ctx->regs);
    if (ip == 0) return 0;

    struct pc_key_t key = { .pid = pid, .bucket = (u32)(ip >> 8) };
    u64 *v = pc_samples.lookup(&key);
    if (v) {
        __sync_fetch_and_add(v, 1);
    } else {
        u64 one = 1;
        pc_samples.update(&key, &one);
    }
    return 0;
}

#endif /* TRACK_PROFILE */
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    # Split argv on `--` so the spawn-mode COMMAND can contain its own flags
    # without colliding with our argparse options.
    raw = sys.argv[1:]
    if "--" in raw:
        idx = raw.index("--")
        argv, command = raw[:idx], raw[idx + 1:]
    else:
        argv, command = raw, []

    p = argparse.ArgumentParser(
        description="Trace Box64 multi-process behavior: "
                    "fork/exec lifecycle, per-PID memory, DynaRec JIT, "
                    "mmap, and pressure-vessel detection using eBPF uprobes",
        epilog="Spawn-and-trace: append `-- COMMAND ARGS...` to launch an "
               "x86_64 Linux program under tracing — e.g. "
               "`-- box64 MyGame.x86_64`, or just `-- ./MyGame.x86_64` "
               "with binfmt_misc. Bare names are auto-resolved against "
               "cwd like box64 itself does. The browser dashboard auto-"
               "opens; trace exits with COMMAND's rc.")
    p.add_argument("-b", "--binary", default="/usr/local/bin/box64",
                   help="Path to box64 binary (default: /usr/local/bin/box64; "
                        "falls back to `which box64` if missing)")
    p.add_argument("-p", "--pid", type=int, default=0,
                   help="Filter by PID (default: trace all box64 processes; "
                        "ignored in spawn mode)")
    p.add_argument("-i", "--interval", type=int, default=15,
                   help="Summary interval in seconds (default: 15)")
    p.add_argument("--no-mem", action="store_true",
                   help="Skip custom allocator tracking (customMalloc/Free/Calloc/Realloc)")
    p.add_argument("--no-dynarec", action="store_true",
                   help="Skip DynaRec JIT tracking (AllocDynarecMap/FreeDynarecMap)")
    p.add_argument("--no-mmap", action="store_true",
                   help="Skip InternalMmap/box_mmap tracking")
    p.add_argument("--no-threads", action="store_true",
                   help="Disable thread/process lifecycle tracking")
    p.add_argument("--no-cow", action="store_true",
                   help="Disable Copy-on-Write page fault tracking (kprobe + /proc sampling)")
    p.add_argument("--no-prot", action="store_true",
                   help="Skip protectDB/unprotectDB/setProtection tracking (default: on when dynarec enabled)")
    p.add_argument("--no-block-detail", action="store_true",
                   help="Skip FreeDynablock/InvalidDynablock/MarkDynablock probes (reduce overhead)")
    p.add_argument("--churn-threshold", type=float, default=1.0,
                   help="JIT blocks freed within N seconds count as churn (default: 1.0)")
    p.add_argument("--hash-capacity", type=int, default=524288,
                   help="BPF hash table capacity for outstanding alloc tracking (default: 524288)")
    p.add_argument("--sample-freq", type=int, default=0,
                   help="PC sampling frequency in Hz for block profiling (0=off, 4999=recommended, max ~9999)")
    # The default web port is read from $BOX64_WEB_PORT if set, else 8642
    # (the inherited kbox-observatory default). The pre-flight check below
    # auto-scans upward if the chosen port is busy, so this is just a
    # starting point, not a hard requirement.
    _default_web_port = int(os.environ.get("BOX64_WEB_PORT", "8642"))
    p.add_argument("--web-port", type=int, default=_default_web_port,
                   metavar="PORT",
                   help=f"Port for the web dashboard "
                        f"(default {_default_web_port}, override globally "
                        f"with $BOX64_WEB_PORT). Auto-scans upward if the "
                        f"port is busy.")
    p.add_argument("--no-web", action="store_true",
                   help="Disable the web dashboard. By default the dashboard "
                        "starts on http://127.0.0.1:8642 in both spawn and "
                        "attach modes; pass this to skip it entirely.")
    p.add_argument("--browser", default="auto", metavar="CMD",
                   help="Browser to auto-open the dashboard. 'auto' (default) "
                        "respects $BROWSER, then xdg-open, then Python's "
                        "webbrowser module. 'none' skips auto-open. Or pass "
                        "a command name like 'firefox', 'chromium', "
                        "'google-chrome'. The URL is always printed, so you "
                        "can copy-paste it if Firefox's profile-lock dialog "
                        "or any other launcher fails.")
    args = p.parse_args(argv)
    args.command = command
    return args


from box64_common import (
    correlate_thread_parents,
    compute_cow_deltas,
    rank_items,
    fmt_size,
    fmt_ns,
    check_binary,
    _read_symbols,
    check_symbols_soft,
    read_smaps_rollup,
    read_minflt,
    read_tgid,
    _clear_stale_uprobes,
    _patch_bcc_uretprobe,
    _bcc_has_atomic_increment,
    _rewrite_atomic_increment,
    diagnose_bpf_error,
    report_fatal,
)


# ---------------------------------------------------------------------------
# Spawn-and-trace helpers
# ---------------------------------------------------------------------------

# Signals where the standard interpretation is "the program crashed" — as
# opposed to SIGTERM/SIGINT/SIGHUP, which usually mean "the user or another
# process asked it to stop". When box64 dies from one of these under our
# tracer, the user almost always wants a hint.
_CRASH_SIGNALS = frozenset({
    signal.SIGSEGV, signal.SIGABRT, signal.SIGILL, signal.SIGBUS, signal.SIGFPE,
})


def _format_child_exit(status):
    """Translate a waitpid() status into (returncode, human-readable message).

    For crash-class signals we append a short hint pointing at the most
    common Box64 isolation step (`BOX64_DYNAREC=0`) and at where Mono dumps
    crash JSON, since Unity-on-Box64 is the most common failure mode users
    hit.
    """
    if os.WIFEXITED(status):
        rc = os.WEXITSTATUS(status)
        if rc == 0:
            return rc, "exited (rc=0)"
        return rc, f"exited (rc={rc})"
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        rc = 128 + sig
        try:
            name = signal.Signals(sig).name
        except ValueError:
            name = f"signal {sig}"
        msg = f"killed by {name} (rc={rc})"
        if sig in _CRASH_SIGNALS:
            msg += (" — looks like a guest-code or DynaRec crash. "
                    "To isolate, retry with `BOX64_DYNAREC=0` (interpreter "
                    "mode); if that runs, the bug is in Box64's JIT, not "
                    "your build. Mono/Unity games dump mono_crash.*.json "
                    "next to the binary on abort.")
        return rc, msg
    return 1, f"unknown exit status {status:#x}"


def _resolve_box64_binary(binary):
    """If `binary` does not exist, fall back to `which box64`."""
    if os.path.exists(binary):
        return binary
    import shutil
    found = shutil.which("box64")
    return found or binary  # let check_binary fail with a clear message


def _validate_spawn_command(cmd):
    """
    Validate cmd[0] for execvp(). May rewrite cmd[0] in place to handle
    the most common mistake transparently.

    Returns:
      None                       — cmd is fine, proceed.
      ("info", message)          — cmd[0] was auto-rewritten in place;
                                   caller should log `message`. Proceed.
      ("error", (summary, hint)) — cmd is broken; caller should bail.

    Box64 itself adds `./` to its binary search path (BOX64_PATH in
    core.c, see ResolveFileSoft) so `box64 program` finds `program` in
    cwd transparently. Users reasonably expect `box64_trace -- program`
    to work the same way. We provide that by rewriting bare names that
    don't exist on $PATH but do exist in cwd to `./name` before execvp.
    """
    if not cmd:
        return ("error",
                ("no command given after `--`",
                 "pass an x86_64 Linux program to spawn, e.g. "
                 "`-- box64 MyGame.x86_64` or `-- ./MyGame.x86_64` "
                 "(with binfmt_misc)."))
    import shutil
    name = cmd[0]
    # Path-like name (contains a separator): exec resolves it as a path.
    if os.sep in name:
        if not os.path.isfile(name):
            return ("error",
                    (f"'{name}' is not a file",
                     "double-check the path — exec() won't fall back to "
                     "anything else for path-like names."))
        if not os.access(name, os.X_OK):
            return ("error",
                    (f"'{name}' exists but is not executable",
                     f"`chmod +x {name}` if you trust it."))
        return None
    # Bare name: exec() consults $PATH only, NEVER the current directory.
    if shutil.which(name) is not None:
        return None
    if os.path.isfile(name):
        # Auto-fix: rewrite to `./name` so execvp resolves it via cwd
        # like box64 itself does (see core.c:1058 ResolveFileSoft).
        cmd[0] = os.path.join(".", name)
        return ("info",
                f"Resolved '{name}' to '{cmd[0]}' (was not on $PATH; "
                f"using cwd lookup like box64 does internally).")
    return ("error",
            (f"'{name}' not found on $PATH",
             "check the spelling, install it, or use an absolute / "
             "relative path with `./` or `/`."))


def _extract_guest_program(command):
    """Identify the guest x86_64 program in a spawn-mode COMMAND list.

    Returns the basename of what box64 is emulating, or None if we can't
    tell (attach mode with no command, or `box64` with no program after it).

    Cases:
      []                            → None         (attach mode)
      ['box64']                     → None         (no program after the runtime)
      ['box64', 'X.x86_64']         → 'X.x86_64'   (explicit)
      ['box64', '/p/X.x86_64', 'a'] → 'X.x86_64'   (with program args)
      ['./X.x86_64']                → 'X.x86_64'   (binfmt_misc)
      ['X.x86_64']                  → 'X.x86_64'   (auto-./ prepend)
    """
    if not command:
        return None
    head = os.path.basename(command[0])
    if head == "box64":
        if len(command) < 2:
            return None
        return os.path.basename(command[1])
    return head


def _wait_for_user_signal(flag, poll_interval=0.5):
    """Block until `flag[0]` becomes truthy.

    Used by main()'s post-child-exit "keep the dashboard alive" loop.
    We can't use signal.pause() or a single long sleep here: our SIGINT
    handler (sig_handler in main) sets the flag and returns without
    raising, so KeyboardInterrupt never fires. A naive
    `while True: time.sleep(...)` would just restart the sleep on every
    Ctrl+C and the user could never exit.
    """
    try:
        while not flag[0]:
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        pass


def _should_keep_dashboard_alive(web_active, child_exited, user_signalled,
                                 child_returncode):
    """Decide whether to keep the dashboard alive after FINAL REPORT.

    Four cases at end-of-run, by (web on/off) x (program clean/crashed):

      web=on,  crashed → True   (dashboard exists, crash worth inspecting)
      web=on,  clean   → False  (nothing to investigate; don't make user wait)
      web=off, crashed → False  (no dashboard to inspect)
      web=off, clean   → False  (nothing to do)

    "Crashed" here means the child died from a crash-class signal
    (SIGSEGV/SIGABRT/SIGILL/SIGBUS/SIGFPE — `_CRASH_SIGNALS`). SIGTERM
    /SIGINT are user-initiated stops and don't count.

    Also gated:
      - child must have actually exited (we observed it with waitpid),
      - user must not have already Ctrl+C'd (in which case they want out),
      - rc must not be 127 (our exec-failure marker; nothing ever ran).
    """
    if not web_active:
        return False
    if not child_exited:
        return False
    if user_signalled:
        return False
    if child_returncode is None:
        return False
    if child_returncode == 127:
        return False
    return (child_returncode - 128) in _CRASH_SIGNALS


def _spawn_paused(cmd):
    """
    Fork+exec `cmd`, but SIGSTOP the child *before* exec so the parent has
    a window to attach uprobes to the box64 binary before any guest code
    runs. Returns the child PID; caller must SIGCONT to resume.

    With binfmt_misc registered, exec'ing an x86_64 ELF transparently
    routes through the box64 interpreter while keeping the same PID, so
    PID-filtered probes still match.
    """
    pid = os.fork()
    if pid == 0:
        # Child: stop ourselves so the parent can attach probes. The exec
        # only runs after the parent sends SIGCONT.
        os.kill(os.getpid(), signal.SIGSTOP)
        try:
            os.execvp(cmd[0], cmd)
        except OSError as e:
            print(f"box64_trace: exec '{cmd[0]}' failed: {e}", file=sys.stderr)
            os._exit(127)
    # Parent: confirm the child has actually reached the stopped state
    # before continuing. WUNTRACED makes waitpid() return on stop signals.
    _, status = os.waitpid(pid, os.WUNTRACED)
    if not os.WIFSTOPPED(status):
        raise RuntimeError(
            f"spawned child {pid} did not stop as expected (status={status:#x})")
    return pid


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    _import_bcc()  # populates module-level BPF
    binary = _resolve_box64_binary(args.binary)
    args.binary = binary

    # Validate binary
    check_binary(binary)

    # Core lifecycle symbols — always required
    core_syms = ["my_fork", "my_vfork", "x64emu_fork",
                 "my_execve", "my_execv", "my_execvp",
                 "NewBox64Context", "FreeBox64Context", "CalcStackSize"]
    check_symbols(binary, core_syms)

    # Optional exec variants
    exec_extra = check_symbols_soft(binary, ["my_execvpe", "my_posix_spawn", "my_posix_spawnp"])
    has_execvpe = "my_execvpe" not in exec_extra
    has_posix_spawn = "my_posix_spawn" not in exec_extra
    has_posix_spawnp = "my_posix_spawnp" not in exec_extra

    # Optional pressure_vessel
    pv_missing = check_symbols_soft(binary, ["pressure_vessel"])
    has_pv = not pv_missing

    # Memory symbols
    if not args.no_mem:
        mem_syms = ["customMalloc", "customFree", "customCalloc", "customRealloc"]
        missing_mem = check_symbols_soft(binary, mem_syms)
        if missing_mem:
            print(f"WARNING: allocator symbols missing: {', '.join(missing_mem)}; disabling memory tracking.")
            args.no_mem = True

    # DynaRec symbols
    if not args.no_dynarec:
        jit_syms = ["AllocDynarecMap", "FreeDynarecMap"]
        missing_jit = check_symbols_soft(binary, jit_syms)
        if missing_jit:
            print(f"WARNING: DynaRec symbols missing: {', '.join(missing_jit)}; disabling JIT tracking.")
            args.no_dynarec = True

    # Protection symbols (only when dynarec is enabled)
    track_prot = False
    if not args.no_dynarec and not args.no_prot:
        prot_syms = ["protectDB", "unprotectDB", "setProtection"]
        missing_prot = check_symbols_soft(binary, prot_syms)
        if missing_prot:
            print(f"WARNING: protection symbols not found: {', '.join(missing_prot)}; disabling protection tracking.")
        else:
            track_prot = True

    # Block detail symbols (FreeDynablock, InvalidDynablock, MarkDynablock)
    track_block_detail = False
    if not args.no_dynarec and not args.no_block_detail:
        detail_syms = ["FreeDynablock", "InvalidDynablock", "MarkDynablock"]
        missing_detail = check_symbols_soft(binary, detail_syms)
        if missing_detail:
            print(f"WARNING: block detail symbols not found: {', '.join(missing_detail)}; disabling block detail tracking.")
        else:
            track_block_detail = True

    # Mmap symbols
    if not args.no_mmap:
        mmap_syms = ["InternalMmap", "InternalMunmap", "box_mmap", "box_munmap"]
        missing_mmap = check_symbols_soft(binary, mmap_syms)
        if missing_mmap:
            print(f"WARNING: mmap symbols missing: {', '.join(missing_mmap)}; disabling mmap tracking.")
            args.no_mmap = True

    # Thread symbols
    track_threads = not args.no_threads
    has_fork_sym = False
    has_clone_sym = False
    if track_threads:
        thread_syms = ["my_pthread_create", "pthread_routine", "emuthread_destroy"]
        missing_threads = check_symbols_soft(binary, thread_syms)
        if missing_threads:
            print(f"WARNING: thread symbols missing: {', '.join(missing_threads)}; disabling thread tracking.")
            track_threads = False
        else:
            has_clone_sym = not check_symbols_soft(binary, ["my_clone"])

    # ---- Spawn-and-trace mode ----
    # If a `-- COMMAND` was given, fork it now in stopped state, pin our
    # PID filter to its PID. The child is resumed (SIGCONT) only after
    # probes have been attached below. The dashboard is on by default
    # (see --no-web) so spawn mode needs no additional setup here.
    spawned_pid = None
    if args.command:
        # Validate the command will actually exec BEFORE we spend ~10s
        # compiling BPF and attaching 42 probes. May auto-rewrite cmd[0]
        # for bare-name-in-cwd cases the way box64 itself does.
        result = _validate_spawn_command(args.command)
        if result is not None:
            kind, payload = result
            if kind == "info":
                print(f"[*] {payload}")
            else:  # "error"
                summary, hint = payload
                print(f"ERROR: {summary}", file=sys.stderr)
                print(f"       {hint}", file=sys.stderr)
                sys.exit(127)

        # Port resolution happens inside box64_web.start() now —
        # auto-scans preferred → preferred+19 → kernel-ephemeral
        # at the actual bind site, race-free. Doing it here would
        # have a window between probe.close() and the real bind ~10s
        # later (BPF compile) where another process could grab the
        # port we picked.

        cmd_str = " ".join(args.command)
        print(f"[*] Spawning: {cmd_str}")
        try:
            spawned_pid = _spawn_paused(args.command)
        except (OSError, RuntimeError) as e:
            print(f"ERROR: failed to spawn '{cmd_str}': {e}", file=sys.stderr)
            sys.exit(1)
        args.pid = spawned_pid
        print(f"[*] Child PID {spawned_pid} stopped — attaching probes...")

        # Make sure a stopped child never gets orphaned if BPF setup fails
        # before we hit the SIGCONT below.
        import atexit

        def _cleanup_spawned(pid=spawned_pid):
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        atexit.register(_cleanup_spawned)

    # Build cflags
    hash_cap = args.hash_capacity
    churn_ns = int(args.churn_threshold * 1_000_000_000)
    cflags = [f"-DHASH_CAPACITY={hash_cap}", f"-DCHURN_THRESHOLD_NS={churn_ns}ULL"]
    if args.pid:
        cflags.append(f"-DFILTER_PID={args.pid}")
    if not args.no_mem:
        cflags.append("-DTRACK_MEM")
    if not args.no_dynarec:
        cflags.append("-DTRACK_DYNAREC")
    if track_prot:
        cflags.append("-DTRACK_PROT")
    if track_block_detail:
        cflags.append("-DTRACK_BLOCK_DETAIL")
    if not args.no_mmap:
        cflags.append("-DTRACK_MMAP")
    if track_threads:
        cflags.append("-DTRACK_THREADS")
    track_cow = not args.no_cow
    if track_cow:
        cflags.append("-DTRACK_COW")
    track_profile = args.sample_freq > 0
    if track_profile:
        if args.no_dynarec:
            print("ERROR: --sample-freq requires DynaRec tracking (incompatible with --no-dynarec)")
            sys.exit(1)
        cflags.append("-DTRACK_PROFILE")
        cflags.append(f"-DPROFILE_CAPACITY={hash_cap}")
    # Clear stale uprobe events (Asahi Linux workaround)
    _clear_stale_uprobes(binary)
    _patch_bcc_uretprobe()

    bpf_src = BPF_PROGRAM
    if not _bcc_has_atomic_increment():
        print("[*] Old BCC detected: rewriting atomic_increment calls")
        bpf_src = _rewrite_atomic_increment(bpf_src)

    # Markers in BPF compile error text that indicate a genuine
    # TRACK_PROFILE / BCC incompatibility. Only these trigger the PC
    # sampling fallback; unrelated BCC/kernel failures (missing
    # headers, kernel version mismatch, perf_event_paranoid, etc.)
    # are re-raised with their original context intact.
    profile_error_markers = (
        "bpf_perf_event_data",
        "on_perf_sample",
        "pc_samples",
        "TRACK_PROFILE",
        "PROFILE_CAPACITY",
    )

    print(f"[*] Compiling and attaching uprobes to {binary} ...")
    try:
        b = BPF(text=bpf_src, cflags=cflags)
    except Exception as e:
        err_text = str(e)
        looks_like_profile_error = track_profile and any(
            marker in err_text for marker in profile_error_markers
        )
        if looks_like_profile_error:
            print(f"WARNING: BPF compilation failed with TRACK_PROFILE enabled: {e}")
            print("WARNING: Retrying without PC sampling (BCC version incompatibility)")
            cflags = [f for f in cflags if f not in ("-DTRACK_PROFILE", f"-DPROFILE_CAPACITY={hash_cap}")]
            track_profile = False
            try:
                b = BPF(text=bpf_src, cflags=cflags)
            except Exception as retry_err:
                # Surface a clean diagnosis if we recognise the second error.
                diag = diagnose_bpf_error(retry_err)
                if diag:
                    summary, hint = diag
                    print(f"\n[FATAL] BPF compilation failed: {summary}", file=sys.stderr)
                    print(f"        → {hint}", file=sys.stderr)
                raise RuntimeError(
                    f"BPF compilation failed even after disabling TRACK_PROFILE. "
                    f"Original error: {e}"
                ) from retry_err
        else:
            # Not a known-recoverable error. Try to give the user a hint
            # before re-raising for the top-level handler to log.
            diag = diagnose_bpf_error(e)
            if diag:
                summary, hint = diag
                print(f"\n[FATAL] BPF compilation failed: {summary}", file=sys.stderr)
                print(f"        → {hint}", file=sys.stderr)
            raise

    probe_count = 0

    # ---- Core lifecycle probes (always) ----
    b.attach_uprobe(name=binary, sym="my_fork",         fn_name="fork_entry")
    b.attach_uprobe(name=binary, sym="my_vfork",        fn_name="vfork_entry")
    b.attach_uprobe(name=binary, sym="x64emu_fork",     fn_name="x64emu_fork_entry")
    b.attach_uprobe(name=binary, sym="my_execve",       fn_name="execve_entry")
    b.attach_uprobe(name=binary, sym="my_execv",        fn_name="execv_entry")
    b.attach_uprobe(name=binary, sym="my_execvp",       fn_name="execvp_entry")
    b.attach_uprobe(name=binary, sym="NewBox64Context",  fn_name="new_context_entry")
    b.attach_uprobe(name=binary, sym="FreeBox64Context", fn_name="free_context_entry")
    b.attach_uretprobe(name=binary, sym="CalcStackSize", fn_name="calc_stack_return")
    probe_count += 9

    if has_execvpe:
        b.attach_uprobe(name=binary, sym="my_execvpe", fn_name="execvpe_entry")
        probe_count += 1
    if has_posix_spawn:
        b.attach_uprobe(name=binary, sym="my_posix_spawn", fn_name="posix_spawn_entry")
        probe_count += 1
    if has_posix_spawnp:
        b.attach_uprobe(name=binary, sym="my_posix_spawnp", fn_name="posix_spawnp_entry")
        probe_count += 1
    if has_pv:
        b.attach_uprobe(name=binary, sym="pressure_vessel", fn_name="pressure_vessel_entry")
        probe_count += 1

    # sched:sched_process_fork tracepoint (parent->child PID mapping):
    # auto-attached by BCC's TRACEPOINT_PROBE() macro at BPF() construction
    # time, so no explicit attach call is needed.
    probe_count += 1

    # ---- Custom allocator probes ----
    if not args.no_mem:
        b.attach_uprobe(name=binary,    sym="customMalloc",  fn_name="malloc_entry")
        b.attach_uretprobe(name=binary, sym="customMalloc",  fn_name="malloc_return")
        b.attach_uprobe(name=binary,    sym="customFree",    fn_name="free_entry")
        b.attach_uprobe(name=binary,    sym="customCalloc",  fn_name="calloc_entry")
        b.attach_uretprobe(name=binary, sym="customCalloc",  fn_name="malloc_return")
        b.attach_uprobe(name=binary,    sym="customRealloc", fn_name="realloc_entry")
        b.attach_uretprobe(name=binary, sym="customRealloc", fn_name="realloc_return")
        probe_count += 7

    # ---- DynaRec JIT probes ----
    if not args.no_dynarec:
        b.attach_uprobe(name=binary,    sym="AllocDynarecMap", fn_name="jit_alloc_entry")
        b.attach_uretprobe(name=binary, sym="AllocDynarecMap", fn_name="jit_alloc_return")
        b.attach_uprobe(name=binary,    sym="FreeDynarecMap",  fn_name="jit_free_entry")
        probe_count += 3

    # ---- Protection probes ----
    if track_prot:
        b.attach_uprobe(name=binary, sym="protectDB",      fn_name="protect_entry")
        b.attach_uprobe(name=binary, sym="unprotectDB",    fn_name="unprotect_entry")
        b.attach_uprobe(name=binary, sym="setProtection",  fn_name="setprot_entry")
        probe_count += 3

    # ---- Block detail probes ----
    if track_block_detail:
        b.attach_uprobe(name=binary, sym="FreeDynablock",    fn_name="freedynablock_entry")
        b.attach_uprobe(name=binary, sym="InvalidDynablock", fn_name="invaliddynablock_entry")
        b.attach_uprobe(name=binary, sym="MarkDynablock",    fn_name="markdynablock_entry")
        probe_count += 3

    # ---- Mmap probes ----
    if not args.no_mmap:
        b.attach_uprobe(name=binary,    sym="InternalMmap",   fn_name="immap_entry")
        b.attach_uretprobe(name=binary, sym="InternalMmap",   fn_name="immap_return")
        b.attach_uprobe(name=binary,    sym="InternalMunmap", fn_name="imunmap_entry")
        b.attach_uprobe(name=binary,    sym="box_mmap",       fn_name="bmmap_entry")
        b.attach_uretprobe(name=binary, sym="box_mmap",       fn_name="bmmap_return")
        b.attach_uprobe(name=binary,    sym="box_munmap",     fn_name="bmunmap_entry")
        probe_count += 6

    # ---- Thread probes ----
    if track_threads:
        b.attach_uprobe(name=binary,    sym="my_pthread_create",  fn_name="thread_create_entry")
        b.attach_uretprobe(name=binary, sym="my_pthread_create",  fn_name="thread_create_return")
        b.attach_uprobe(name=binary,    sym="pthread_routine",     fn_name="thread_start_entry")
        b.attach_uprobe(name=binary,    sym="emuthread_destroy",   fn_name="thread_destroy_entry")
        probe_count += 4
        if has_clone_sym:
            b.attach_uprobe(name=binary,    sym="my_clone", fn_name="clone_entry")
            b.attach_uretprobe(name=binary, sym="my_clone", fn_name="clone_return")
            probe_count += 2

    # ---- CoW kprobe ----
    track_cow_kprobe = False
    if track_cow:
        for kfunc in ("wp_page_copy", "do_wp_page"):
            try:
                b.attach_kprobe(event=kfunc, fn_name="trace_cow_fault")
                track_cow_kprobe = True
                print(f"[*] CoW kprobe attached to {kfunc}")
                probe_count += 1
                break
            except Exception:
                continue
        if not track_cow_kprobe:
            print("WARNING: CoW kprobe unavailable (wp_page_copy/do_wp_page not found). "
                  "Using /proc sampling only.")

    # ---- PC sampling perf event ----
    if track_profile:
        from bcc import PerfType, PerfSWConfig
        pid_filter = args.pid if getattr(args, "pid", None) else -1
        try:
            b.attach_perf_event(ev_type=PerfType.SOFTWARE,
                                ev_config=PerfSWConfig.CPU_CLOCK,
                                fn_name="on_perf_sample",
                                sample_freq=args.sample_freq,
                                pid=pid_filter)
        except Exception as e:
            print(f"[!] ERROR: Failed to attach PC sampling perf event at "
                  f"{args.sample_freq} Hz (pid={pid_filter}).")
            print(f"    Reason: {e}")
            print("    Hint: Ensure you have sufficient permissions (try running as root), "
                  "check /proc/sys/kernel/perf_event_paranoid, or reduce --sample-freq.")
            sys.exit(1)
        target_desc = f"PID {args.pid}" if getattr(args, "pid", None) else "all PIDs"
        print(f"[*] PC sampling attached at {args.sample_freq} Hz for {target_desc}")

    if args.sample_freq > 0 and not track_profile:
        print("WARNING: PC sampling unavailable (BCC compilation failed)")

    pid_str = f" (PID {args.pid})" if args.pid else " (all PIDs)"
    features = []
    if not args.no_mem:
        features.append("mem")
    if not args.no_dynarec:
        features.append("dynarec")
    if track_prot:
        features.append("prot")
    if track_block_detail:
        features.append("block_detail")
    if not args.no_mmap:
        features.append("mmap")
    if track_threads:
        features.append("threads")
    if track_cow:
        features.append("cow")
    churn_str = f" Churn threshold: {args.churn_threshold}s." if not args.no_dynarec else ""
    print(f"[*] {probe_count} probes attached{pid_str}. Features: {', '.join(features)}.{churn_str} "
          f"Interval: {args.interval}s. Ctrl+C to stop.")

    # ---- Resume spawned child (probes are now live) ----
    if spawned_pid is not None:
        try:
            os.kill(spawned_pid, signal.SIGCONT)
            print(f"[*] Resumed child PID {spawned_pid}.")
        except ProcessLookupError:
            print(f"WARNING: child PID {spawned_pid} disappeared before resume.")
            spawned_pid = None

    # ---- Graceful exit ----
    exiting = [False]
    child_returncode = [0]
    _user_signalled = [False]

    def sig_handler(signum, frame):
        # Mark this as user-initiated so the post-loop "stay alive for the
        # browser" block knows to exit instead of holding open.
        _user_signalled[0] = True
        exiting[0] = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # ---- Python-side state ----
    timeline = []
    proc_children = {}     # parent_pid -> [child_pid, ...]
    pid_labels = {}        # pid -> string
    # Each `tid` we observe via sched_process_fork — could be either a
    # real fork child (its TID happens to equal its new TGID) or a thread
    # clone (CLONE_THREAD: TID under the parent's TGID). proc_mem entries
    # for thread clones never receive any allocations because customMalloc
    # & friends key on TGID — they all fall through to the parent's row.
    # We classify each entry once, immediately after the fork event, while
    # /proc/TID is still live. See _classify_pid below.
    #   "process" → real fork child (TGID == TID)
    #   "thread"  → CLONE_THREAD spawn (TGID != TID), spurious zero row
    #   "unknown" → /proc/TID was already gone when we tried to read
    pid_kind = {}          # pid -> "process" | "thread" | "unknown"
    # Set later by --web; read by handle_lifecycle_event for SSE emission.
    _web_emit = None
    smaps_history = {}     # pid -> [(monotonic_time, smaps_dict), ...]
    pv_events = []         # [(ts_ns, pid, prog_path)]
    context_events = []    # [(ts_ns, pid, event_type)]

    # Thread tracking state
    thread_timeline = {}
    create_requests = []
    thread_parent = {}
    fork_events = []
    clone_children = {}
    process_children = {}
    fork_cow_data = {}

    # PC sampling profile state
    prev_samples = {}               # (pid, bucket) -> count
    block_last_active = {}          # (pid, alloc_addr) -> interval_index
    block_active_intervals = {}     # (pid, alloc_addr) -> number of intervals active
    profile_interval_idx = [0]      # mutable counter
    block_meta_cache = {}           # (pid, alloc_addr) -> metadata dict or None
    proc_mem_fds = {}               # pid -> open file object for /proc/PID/mem

    def _get_proc_mem_fd(pid):
        """Get or open a pooled /proc/PID/mem file descriptor."""
        fd = proc_mem_fds.get(pid)
        if fd is not None:
            try:
                fd.seek(0)  # test if still valid
                return fd
            except OSError:
                proc_mem_fds.pop(pid, None)
        try:
            fd = open(f"/proc/{pid}/mem", "rb")
            proc_mem_fds[pid] = fd
            return fd
        except OSError:
            return None

    def _close_proc_mem_fds():
        """Close all pooled file descriptors."""
        for fd in proc_mem_fds.values():
            try:
                fd.close()
            except OSError:
                pass
        proc_mem_fds.clear()

    def _cached_block_metadata(pid, alloc_addr):
        """Read block metadata with caching and fd pooling."""
        key = (pid, alloc_addr)
        cached = block_meta_cache.get(key)
        if cached is not None:
            return cached if cached else None  # False sentinel = failed read
        fd = _get_proc_mem_fd(pid)
        if fd is None:
            block_meta_cache[key] = False
            return None
        meta = _read_block_from_fd(fd, alloc_addr)
        block_meta_cache[key] = meta if meta else False
        return meta

    def profile_interval():
        """Diff BPF pc_samples hash to find blocks active this interval."""
        if not track_profile:
            return
        profile_interval_idx[0] += 1
        idx = profile_interval_idx[0]

        # 1. Read current BPF hash
        cur = {}
        for k, v in b["pc_samples"].items():
            cur[(k.pid, k.bucket)] = v.value

        # 2. Compute delta (new samples this interval)
        active_buckets = {}  # pid -> set of buckets with new samples
        for key, count in cur.items():
            prev = prev_samples.get(key, 0)
            if count > prev:
                active_buckets.setdefault(key[0], set()).add(key[1])
        prev_samples.update(cur)

        # 3. Map active buckets to blocks (cached metadata + pooled fds)
        for k, v in b["jit_blocks"].items():
            pid = v.pid
            if pid not in active_buckets:
                continue
            alloc_addr = k.value
            meta = _cached_block_metadata(pid, alloc_addr)
            if not meta or meta["native_size"] <= 0:
                continue
            start_b = meta["block"] >> 8
            end_b = (meta["block"] + meta["native_size"] - 1) >> 8
            for bkt in range(start_b, end_b + 1):
                if bkt in active_buckets[pid]:
                    bkey = (pid, alloc_addr)
                    block_last_active[bkey] = idx
                    block_active_intervals[bkey] = block_active_intervals.get(bkey, 0) + 1
                    break

    EVENT_NAMES = {
        0: "fork",         1: "vfork",        2: "x64emu_fork",
        3: "fork_child",   4: "execv",        5: "execve",
        6: "execvp",       7: "execvpe",      8: "posix_spawn",
        9: "posix_spawnp", 10: "pressure_vessel",
        11: "new_context", 12: "free_context", 13: "calc_stack",
    }

    FORKTYPE_NAMES = {1: "fork", 2: "forkpty", 3: "vfork"}

    # ---- Lifecycle event handler ----
    def handle_lifecycle_event(cpu, data, size):
        evt = b["lifecycle_events"].event(data)
        pid = evt.pid
        ts_ns = evt.timestamp_ns
        etype = evt.event_type
        path = evt.path.decode(errors='replace').rstrip('\x00')

        if pid and pid not in pid_labels:
            pid_labels[pid] = read_proc_cmdline(pid)

        entry = {
            "ts_ns": ts_ns,
            "type": etype,
            "name": EVENT_NAMES.get(etype, f"type{etype}"),
            "pid": pid,
            "tid": evt.tid,
            "child_pid": evt.child_pid,
            "forktype": evt.forktype,
            "path": path,
            "extra": evt.extra,
        }
        timeline.append(entry)

        if etype == 3:   # fork_child: parent got child PID
            proc_children.setdefault(pid, []).append(evt.child_pid)
            if evt.child_pid not in pid_labels:
                # Inherit parent label until child does exec
                pid_labels[evt.child_pid] = pid_labels.get(pid, f"pid{evt.child_pid}")
            # Classify the new TID right now while /proc/TID is fresh.
            # If we wait until snapshot/FINAL REPORT time, short-lived
            # threads will be gone and we'd be left with "unknown" rows.
            if evt.child_pid not in pid_kind:
                tgid = read_tgid(evt.child_pid)
                if tgid is None:
                    pid_kind[evt.child_pid] = "unknown"
                elif tgid == evt.child_pid:
                    pid_kind[evt.child_pid] = "process"
                else:
                    pid_kind[evt.child_pid] = "thread"
            if _web_emit:
                _web_emit('process', {
                    "action": "fork", "pid": pid, "child_pid": evt.child_pid,
                    "label": pid_labels.get(pid, ""),
                    "kind": pid_kind.get(evt.child_pid, "unknown"),
                })

        elif etype in (4, 5, 6, 7):  # exec* — update label to target binary
            if path:
                pid_labels[pid] = path.split('/')[-1]
            if _web_emit:
                _web_emit('process', {
                    "action": EVENT_NAMES.get(etype, "exec"),
                    "pid": pid, "cmd": path
                })

        elif etype in (8, 9):  # posix_spawn* — spawns child, parent continues unchanged
            if _web_emit:
                _web_emit('process', {
                    "action": EVENT_NAMES.get(etype, "spawn"),
                    "pid": pid, "cmd": path
                })

        elif etype == 10:  # pressure_vessel
            pv_events.append((ts_ns, pid, path))
            print(f"  [!] pressure_vessel() detected: PID {pid} prog={path!r}")
            if _web_emit:
                _web_emit('process', {"action": "pressure_vessel", "pid": pid, "cmd": path})

        elif etype in (11, 12):
            context_events.append((ts_ns, pid, etype))

        elif etype == 2:  # x64emu_fork
            fname = FORKTYPE_NAMES.get(evt.forktype, f"type{evt.forktype}")
            print(f"  [x64emu_fork] PID {pid} forktype={fname}")

    b["lifecycle_events"].open_perf_buffer(handle_lifecycle_event, page_cnt=64)

    # ---- Thread event handler ----
    if track_threads:
        def handle_thread_event(cpu, data, size):
            evt = b["thread_events"].event(data)
            tid = evt.tid

            if evt.event_type == 0:  # thread started
                thread_timeline[tid] = {
                    "x64_fnc": evt.x64_fnc, "create_ns": evt.timestamp_ns,
                    "destroy_ns": None, "pid": evt.pid
                }

            elif evt.event_type == 1:  # destroyed
                if tid in thread_timeline:
                    thread_timeline[tid]["destroy_ns"] = evt.timestamp_ns
                else:
                    thread_timeline[tid] = {
                        "x64_fnc": evt.x64_fnc, "create_ns": 0,
                        "destroy_ns": evt.timestamp_ns, "pid": evt.pid
                    }

            elif evt.event_type == 2:  # fork
                fork_events.append((evt.timestamp_ns, evt.creator_tid, evt.pid))
                smaps = read_smaps_rollup(evt.pid)
                minflt = read_minflt(evt.pid)
                if smaps:
                    fork_cow_data[evt.pid] = {
                        "snapshot_time": time.monotonic(),
                        "parent_smaps": smaps,
                        "parent_minflt": minflt,
                        "parent_tid": evt.creator_tid,
                        # child_pid -> {first: sample, last: sample, count: int}
                        # Only first+last are kept to bound memory across long runs.
                        "child_samples": {},
                    }

            elif evt.event_type == 4:  # create_request
                create_requests.append((evt.timestamp_ns, evt.creator_tid, evt.pid, evt.x64_fnc))
                cutoff = evt.timestamp_ns - 10_000_000_000
                while create_requests and create_requests[0][0] < cutoff:
                    create_requests.pop(0)

            elif evt.event_type == 5:  # clone_return
                child_pid = evt.child_pid
                parent_tid = evt.creator_tid
                clone_children.setdefault(parent_tid, []).append(child_pid)
                process_children.setdefault(evt.pid, []).append(child_pid)

        b["thread_events"].open_perf_buffer(handle_thread_event, page_cnt=16)

    # ---- Churn event handler ----
    churned_x64_addrs = {}  # x64_addr -> count

    if not args.no_dynarec:
        def handle_churn_event(cpu, data, size):
            evt = b["churn_events"].event(data)
            addr = evt.x64_addr
            churned_x64_addrs[addr] = churned_x64_addrs.get(addr, 0) + 1

        b["churn_events"].open_perf_buffer(handle_churn_event, page_cnt=64)

    # ---- Block detail event handlers ----
    death_stats = {"count": 0, "tick_sum": 0, "isize_sum": 0, "native_size_sum": 0,
                   "dirty_count": 0, "always_test_count": 0}
    invalidation_addrs = {}   # x64_addr -> {"count": N, "isize": I, "last_hash": H}
    unprot_addrs = {}         # addr -> {"count": N, "total_size": S, "mark_count": M}

    if track_block_detail:
        def handle_block_death_event(cpu, data, size):
            evt = b["block_death_events"].event(data)
            death_stats["count"] += 1
            death_stats["tick_sum"] += evt.tick
            death_stats["isize_sum"] += evt.isize
            death_stats["native_size_sum"] += evt.native_size
            if evt.dirty:
                death_stats["dirty_count"] += 1
            if evt.always_test:
                death_stats["always_test_count"] += 1

        b["block_death_events"].open_perf_buffer(handle_block_death_event, page_cnt=64)

        def handle_invalidation_event(cpu, data, size):
            evt = b["invalidation_events"].event(data)
            addr = evt.x64_addr
            entry = invalidation_addrs.get(addr)
            if entry:
                entry["count"] += 1
                entry["last_hash"] = evt.hash
            else:
                invalidation_addrs[addr] = {"count": 1, "isize": evt.isize, "last_hash": evt.hash}

        b["invalidation_events"].open_perf_buffer(handle_invalidation_event, page_cnt=16)

        def handle_unprot_event(cpu, data, size):
            evt = b["unprot_events"].event(data)
            addr = evt.addr
            entry = unprot_addrs.get(addr)
            if entry:
                entry["count"] += 1
                entry["total_size"] += evt.size
                if evt.mark:
                    entry["mark_count"] += 1
            else:
                unprot_addrs[addr] = {"count": 1, "total_size": evt.size,
                                      "mark_count": 1 if evt.mark else 0}

        b["unprot_events"].open_perf_buffer(handle_unprot_event, page_cnt=16)

    # ---- Stats reading ----
    def read_stats():
        st = b["steam_stats"]
        return [st[st.Key(i)].value for i in range(32)]

    # ---- Web dashboard snapshot (only built when the dashboard is enabled) ----
    def _hist_snapshot(map_name):
        """Read a BPF_HISTOGRAM into a list of {bucket, count} dicts."""
        try:
            hm = b[map_name]
        except (KeyError, IndexError):
            return []
        out = []
        for k, v in hm.items():
            cnt = v.value
            if cnt > 0:
                out.append({"bucket": k.value, "count": cnt})
        out.sort(key=lambda r: r["bucket"])
        return out

    def _top_blocks_snapshot(n=20):
        """Top outstanding JIT blocks by size — informs largest-block eviction."""
        try:
            jb = b["jit_blocks"]
        except (KeyError, IndexError):
            return []
        rows = []
        for k, v in jb.items():
            rows.append({
                "alloc_addr": int(k.value),
                "x64_addr": int(v.x64_addr),
                "size": int(v.size),
                "pid": int(v.pid),
            })
        rows.sort(key=lambda r: r["size"], reverse=True)
        return rows[:n]

    def _per_pid_snapshot():
        """Per-PID breakdown read from proc_mem BPF hash + thread_stats.

        Builds a list of {pid, label, malloc_bytes, jit_bytes, mmap_bytes,
        threads_alive} for the dashboard table. Skips entries that
        sched_process_fork created for thread clones (CLONE_THREAD): those
        rows can't ever receive allocations because customMalloc & friends
        key on TGID, not TID — they'd just be perpetual zeros.
        """
        rows = []
        threads_filtered = 0
        # Count threads alive per pid by iterating active_threads (tid -> thread_info)
        threads_per_pid = {}
        if track_threads:
            try:
                for _, info in b["active_threads"].items():
                    threads_per_pid[info.pid] = threads_per_pid.get(info.pid, 0) + 1
            except Exception:
                pass
        try:
            for k, pm in b["proc_mem"].items():
                pid = k.value
                if pid_kind.get(pid) == "thread":
                    threads_filtered += 1
                    continue
                rows.append({
                    "pid": pid,
                    "label": pid_labels.get(pid, ""),
                    "kind": pid_kind.get(pid, "unknown"),
                    "malloc_bytes": pm.malloc_bytes - pm.free_bytes,
                    "malloc_count": pm.malloc_count,
                    "free_count": pm.free_count,
                    "jit_bytes": pm.jit_alloc_bytes - pm.jit_free_bytes,
                    "jit_count": pm.jit_alloc_count,
                    "mmap_bytes": pm.mmap_bytes + pm.box_mmap_bytes,
                    "threads_alive": threads_per_pid.get(pid, 0),
                    "context_created": pm.context_created,
                })
        except Exception:
            pass
        # Sort by JIT bytes desc — heaviest emulator process first
        rows.sort(key=lambda r: r["jit_bytes"], reverse=True)
        # Stash the filter count on the closure so web_snapshot can read
        # it without changing the public list-shape the frontend expects.
        _per_pid_snapshot.last_threads_filtered = threads_filtered
        return rows[:32]   # cap to keep payload small

    _per_pid_snapshot.last_threads_filtered = 0

    def web_snapshot():
        v = read_stats()
        # thread_counters: 0=create_entry,1=create_return,2=start_entry,
        # 3=destroy_entry,4=fork_entry,5=clone_entry
        tc = [0] * 6
        if track_threads:
            tcm = b["thread_counters"]
            tc = [tcm[tcm.Key(i)].value for i in range(6)]
        return {
            "timestamp_ns": time.monotonic_ns(),
            "alloc": {
                "malloc": v[0], "free": v[1], "calloc": v[2], "realloc": v[3],
                "bytes_allocated": v[4], "bytes_freed": v[5],
            },
            "jit": {
                "alloc_count": v[6], "free_count": v[7],
                "bytes_allocated": v[8], "bytes_freed": v[9],
                "outstanding_bytes": v[22], "outstanding_blocks": v[31],
                "churn": v[21],
                "invalidations": v[29], "dirty_marks": v[30],
            },
            "mmap": {
                "internal_mmap": v[10], "internal_munmap": v[11],
                "box_mmap": v[12], "box_munmap": v[13],
            },
            "process": {
                "fork": v[14], "vfork": v[15], "exec": v[16],
                "posix_spawn": v[17],
                "new_context": v[18], "free_context": v[19],
                "pressure_vessel": v[20],
            },
            "protection": {
                "protectDB_calls": v[23], "unprotectDB_calls": v[24],
                "setProtection_calls": v[25],
                "protectDB_bytes": v[26], "unprotectDB_bytes": v[27],
                "setProtection_bytes": v[28],
            },
            "threads": {
                "create_entry": tc[0], "create_return": tc[1],
                "start_entry": tc[2], "destroy_entry": tc[3],
                "fork_entry": tc[4], "clone_entry": tc[5],
            },
            "pids": _per_pid_snapshot(),
            "pids_threads_filtered": _per_pid_snapshot.last_threads_filtered,
            "histograms": {
                "alloc_sizes": _hist_snapshot("alloc_sizes"),
                "block_lifetimes": _hist_snapshot("block_lifetimes"),
            },
            "top_blocks": _top_blocks_snapshot(20),
            # churned_x64_addrs is built by handle_churn_event in main().
            # Take a sorted top-20 snapshot.
            "top_churned": [
                {"x64_addr": addr, "count": cnt}
                for addr, cnt in sorted(
                    churned_x64_addrs.items(), key=lambda kv: kv[1], reverse=True
                )[:20]
            ],
        }

    def web_stats_meta():
        # `guest` is what we display in the dashboard header — prefer the
        # actual x86_64 program name when we can derive it (spawn mode);
        # in attach mode we don't know the program(s), fall back to the
        # box64 binary basename.
        program = _extract_guest_program(args.command)
        return {
            "binary": binary,
            "filter_pid": args.pid if args.pid else 0,
            "interval": args.interval,
            "program": program,
            "guest": program or os.path.basename(binary),
            "track": {
                "mem": not args.no_mem, "dynarec": not args.no_dynarec,
                "mmap": not args.no_mmap, "threads": track_threads,
                "cow": track_cow, "prot": track_prot,
                "block_detail": track_block_detail,
                "profile": track_profile,
            },
        }

    # ---- Periodic summary ----
    def print_periodic(vals, prev_vals):
        d = [vals[i] - prev_vals[i] for i in range(32)]

        print(f"\n--- {time.strftime('%H:%M:%S')} --- Box64 ---")
        print(f"  fork: {d[14]:>6}  vfork: {d[15]:>6}  exec: {d[16]:>6}"
              f"  posix_spawn: {d[17]:>6}  context_new: {d[18]:>4}  context_free: {d[19]:>4}")

        if not args.no_mem:
            print(f"  malloc: {d[0]:>8}  free: {d[1]:>8}  calloc: {d[2]:>8}  realloc: {d[3]:>8}")
            print(f"  bytes_alloc: {fmt_size(d[4]):>10}  bytes_free: {fmt_size(d[5]):>10}")

        if not args.no_dynarec:
            churn_delta = d[21]
            frees_delta = d[7]
            churn_pct = (churn_delta / frees_delta * 100) if frees_delta > 0 else 0.0
            detail_str = ""
            if track_block_detail:
                detail_str = f"  invalidated: {d[29]:>6}  marked_dirty: {d[30]:>6}"
            print(f"  jit_alloc: {d[6]:>8}  jit_free: {frees_delta:>8}  churn: {churn_delta:>8} ({churn_pct:.1f}%){detail_str}")
            print(f"  jit_alloc_bytes: {fmt_size(d[8]):>10}  jit_free_bytes: {fmt_size(d[9]):>10}  "
                  f"outstanding: {fmt_size(vals[22]):>10}")
            outstanding_blocks = vals[31]
            print(f"  outstanding blocks: {outstanding_blocks}", end="")
            if outstanding_blocks >= hash_cap:
                print(f"  *** HASH TABLE FULL (capacity {hash_cap}) — data loss! Use --hash-capacity ***")
            else:
                print()

        if track_prot:
            print(f"  protectDB: {d[23]:>8} ({fmt_size(d[26]):>10})   "
                  f"unprotectDB: {d[24]:>8} ({fmt_size(d[27]):>10})   "
                  f"setProtection: {d[25]:>8} ({fmt_size(d[28]):>10})")

        if not args.no_mmap:
            print(f"  internal_mmap: {d[10]:>6}  internal_munmap: {d[11]:>6}  "
                  f"box_mmap(guest): {d[12]:>6}  box_munmap: {d[13]:>6}")
            if d[12] > 0:
                print(f"    (note: box_mmap calls InternalMmap internally; internal_mmap count includes box_mmap)")

        if track_threads:
            tc = b["thread_counters"]
            created = tc[tc.Key(0)].value
            destroyed = tc[tc.Key(1)].value
            peak = tc[tc.Key(2)].value
            current = tc[tc.Key(3)].value
            forks = tc[tc.Key(4)].value
            clones = tc[tc.Key(5)].value
            print(f"  threads: active {current}, created {created}, destroyed {destroyed}, peak {peak}"
                  f" | forks: {forks}, clones: {clones}")

        # Per-PID /proc RSS snapshot
        tracked_pids = set(pid_labels.keys())
        if tracked_pids:
            print(f"\n  Per-PID /proc RSS snapshot:")
            for pid in sorted(tracked_pids):
                smaps = read_smaps_rollup(pid)
                if smaps:
                    rss = smaps.get('Rss', 0)
                    pss = smaps.get('Pss', 0)
                    label = pid_labels.get(pid, f"pid{pid}")
                    print(f"    PID {pid:>7} [{label:>30}]  "
                          f"RSS={fmt_size(rss):>10}  PSS={fmt_size(pss):>10}")
                    smaps_history.setdefault(pid, []).append(
                        (time.monotonic(), smaps))

        # PC sampling periodic summary
        if track_profile and profile_interval_idx[0] > 0:
            # Count blocks from jit_blocks table
            jit_count = 0
            for _ in b["jit_blocks"].items():
                jit_count += 1
            idx = profile_interval_idx[0]
            active_now = sum(1 for v in block_last_active.values() if v == idx)
            cold_60 = sum(1 for v in block_last_active.values()
                          if (idx - v) * args.interval > 60)
            print(f"  profile: {jit_count:,} blocks | active this interval: {active_now:,} | "
                  f"mapped: {len(block_last_active):,} | cold >60s: {cold_60:,}")

    # ---- Final report ----
    def print_final_report(vals):
        print("\n" + "=" * 76)
        print("FINAL REPORT -- Box64 Multi-Process Analysis")
        print("=" * 76)

        # -- Section 1: Global totals --
        print(f"\n  Lifecycle Totals:")
        print(f"    fork:              {vals[14]:>10}")
        print(f"    vfork:             {vals[15]:>10}")
        print(f"    exec (all):        {vals[16]:>10}")
        print(f"    posix_spawn:       {vals[17]:>10}")
        print(f"    NewBox64Context:   {vals[18]:>10}")
        print(f"    FreeBox64Context:  {vals[19]:>10}")
        print(f"    pressure_vessel:   {vals[20]:>10}")

        if not args.no_mem:
            print(f"\n  Custom Allocator Totals:")
            print(f"    malloc:   {vals[0]:>12}   free:   {vals[1]:>12}")
            print(f"    calloc:   {vals[2]:>12}   realloc:{vals[3]:>12}")
            print(f"    bytes allocated: {fmt_size(vals[4]):>12}   bytes freed: {fmt_size(vals[5]):>12}")

        if not args.no_dynarec:
            churn_pct = (vals[21] / vals[7] * 100) if vals[7] > 0 else 0.0
            print(f"\n  DynaRec JIT Totals:")
            print(f"    AllocDynarecMap:  {vals[6]:>12}")
            print(f"    FreeDynarecMap:   {vals[7]:>12}")
            print(f"    Churn (< {args.churn_threshold}s):   {vals[21]:>12}  ({churn_pct:.1f}%)")
            print(f"    Bytes allocated:  {fmt_size(vals[8]):>12}")
            print(f"    Bytes freed:      {fmt_size(vals[9]):>12}")
            print(f"    Outstanding:      {fmt_size(vals[22]):>12}")

        if track_prot:
            print(f"\n  Protection Overhead:")
            print(f"    protectDB:      {vals[23]:>10} calls, {fmt_size(vals[26]):>10} cumulative bytes")
            print(f"    unprotectDB:    {vals[24]:>10} calls, {fmt_size(vals[27]):>10} cumulative bytes")
            print(f"    setProtection:  {vals[25]:>10} calls, {fmt_size(vals[28]):>10} cumulative bytes")

        # Allocation size histogram. Spans both subsystems (JIT block
        # allocations + customMalloc/Calloc/Realloc), so it shows up
        # whenever EITHER tracker is active. Without the custom-allocator
        # feed the < 256B range was always empty (JIT blocks are
        # page-aligned).
        if not args.no_dynarec or not args.no_mem:
            print(f"\n  Allocation Size Distribution:")
            print(format_log2_hist(b["alloc_sizes"], val_type="bytes"))

        if not args.no_dynarec:
            # Block lifetime histogram (JIT-specific)
            print(f"\n  Block Lifetime Distribution:")
            print(format_log2_hist(b["block_lifetimes"], val_type="ns"))

            # Outstanding JIT blocks
            jit_blocks_map = b["jit_blocks"]
            outstanding = []
            for k, v in jit_blocks_map.items():
                outstanding.append((k.value, v.x64_addr, v.size, v.alloc_ns, v.pid, v.is_new))
            print(f"\n  Outstanding JIT Blocks: {len(outstanding)}")
            if len(outstanding) >= hash_cap:
                print(f"  *** WARNING: Hash table was at capacity ({hash_cap}). Block tracking, lifetime,")
                print(f"  *** and churn data may be incomplete. Re-run with --hash-capacity {hash_cap * 4}")
            if outstanding:
                ranked = rank_items(outstanding, sort_key_idx=2)
                top_n = len(ranked)
                print(f"  Top {top_n} by size:")
                print(f"  {'AllocAddr':>18s}  {'x64Addr':>18s}  {'Size':>10s}  {'is_new':>6s}  {'PID':>7s}")
                print(f"  {'-'*18}  {'-'*18}  {'-'*10}  {'-'*6}  {'-'*7}")
                for i in range(top_n):
                    aaddr, x64, sz, ts, pid, is_new = ranked[i]
                    print(f"  0x{aaddr:016x}  0x{x64:016x}  {fmt_size(sz):>10s}  {is_new:>6}  {pid:>7}")

            # Top churned x64 addresses
            if churned_x64_addrs:
                sorted_churn = sorted(churned_x64_addrs.items(), key=lambda x: x[1], reverse=True)
                top_n = min(20, len(sorted_churn))
                print(f"\n  Top {top_n} Churned x64 Addresses (most frequently re-compiled):")
                print(f"  {'x64 Address':>18s}  {'Churn Count':>12s}")
                print(f"  {'-'*18}  {'-'*12}")
                for i in range(top_n):
                    addr, count = sorted_churn[i]
                    print(f"  0x{addr:016x}  {count:>12}")

        # -- Block detail analysis (FreeDynablock/InvalidDynablock/MarkDynablock) --
        if track_block_detail:
            print(f"\n  Block Detail Analysis:")
            print(f"    Invalidations (InvalidDynablock):  {vals[29]:>10}")
            print(f"    Dirty marks (MarkDynablock):       {vals[30]:>10}")

            # Block death profile
            if death_stats["count"] > 0:
                dc = death_stats["count"]
                avg_isize = death_stats["isize_sum"] / dc
                avg_native = death_stats["native_size_sum"] / dc
                print(f"\n  Freed Block Statistics (from FreeDynablock):")
                print(f"    Total freed:          {dc:>12,}")
                print(f"    Invalidated (hash):   {vals[29]:>12,}  "
                      f"({vals[29]/dc*100:.1f}%)" if dc > 0 else "")
                print(f"    Marked dirty:         {death_stats['dirty_count']:>12,}")
                print(f"    Always_test set:      {death_stats['always_test_count']:>12,}")
                print(f"    Avg isize at death:   {avg_isize:>12.1f} instructions")
                print(f"    Avg native_size:      {fmt_size(int(avg_native)):>12}")

                # Death isize histogram
                print(f"\n  Freed Block Instruction Count Distribution:")
                print(format_log2_hist(b["death_isizes"], val_type="value"))

                # Death native size histogram
                print(f"\n  Freed Block Native Size Distribution:")
                print(format_log2_hist(b["death_native_sizes"], val_type="bytes"))

            # Invalidation hot zones
            if invalidation_addrs:
                sorted_inv = sorted(invalidation_addrs.items(), key=lambda x: x[1]["count"], reverse=True)
                top_n = min(20, len(sorted_inv))
                print(f"\n  Top {top_n} Invalidated x64 Addresses:")
                print(f"  {'x64 Address':>18s}  {'Invalidations':>14s}  {'isize':>6s}  {'Last Hash':>12s}")
                print(f"  {'-'*18}  {'-'*14}  {'-'*6}  {'-'*12}")
                for addr, info in sorted_inv[:top_n]:
                    print(f"  0x{addr:016x}  {info['count']:>14}  {info['isize']:>6}  0x{info['last_hash']:08x}")

            # Unprotect hot zones
            if unprot_addrs:
                sorted_unprot = sorted(unprot_addrs.items(), key=lambda x: x[1]["count"], reverse=True)
                top_n = min(20, len(sorted_unprot))
                print(f"\n  Top {top_n} Unprotected Addresses (unprotectDB hot zones):")
                print(f"  {'Address':>18s}  {'Calls':>8s}  {'Total Size':>12s}  {'Dirty Marks':>11s}")
                print(f"  {'-'*18}  {'-'*8}  {'-'*12}  {'-'*11}")
                for addr, info in sorted_unprot[:top_n]:
                    print(f"  0x{addr:016x}  {info['count']:>8}  "
                          f"{fmt_size(info['total_size']):>12}  {info['mark_count']:>11}")

        # -- Live block snapshot via /proc/PID/mem --
        if not args.no_dynarec:
            jit_blocks_map = b["jit_blocks"]
            # Group blocks by PID for /proc/PID/mem access
            blocks_by_pid = {}
            for k, v in jit_blocks_map.items():
                blocks_by_pid.setdefault(v.pid, []).append((k.value, v.size))

            live_meta = []  # list of (pid, alloc_addr, size, metadata_dict)
            for pid in sorted(blocks_by_pid.keys()):
                mem_path = f"/proc/{pid}/mem"
                try:
                    with open(mem_path, "rb", buffering=0) as mem_f:
                        for alloc_addr, blk_size in blocks_by_pid[pid]:
                            meta = read_block_metadata(pid, alloc_addr, mem_f)
                            if meta:
                                live_meta.append((pid, alloc_addr, blk_size, meta))
                except OSError:
                    # Process may have exited or /proc/<pid>/mem may be unavailable.
                    continue

            if live_meta:
                # Get max tick per process for age computation
                max_tick_per_pid = {}
                for pid, _, _, meta in live_meta:
                    t = meta["tick"]
                    if t > max_tick_per_pid.get(pid, 0):
                        max_tick_per_pid[pid] = t

                # Compute ages and collect stats
                ages = []
                isizes = []
                native_sizes = []
                x64_sizes = []
                expansion_ratios = []
                working_set = {100: {"count": 0, "bytes": 0},
                               1000: {"count": 0, "bytes": 0},
                               4096: {"count": 0, "bytes": 0}}
                cold_count = 0
                cold_bytes = 0
                total_bytes = 0

                for pid, alloc_addr, blk_size, meta in live_meta:
                    max_t = max_tick_per_pid.get(pid, 0)
                    age = max_t - meta["tick"] if max_t > meta["tick"] else 0
                    ages.append(age)
                    isizes.append(meta["isize"])
                    native_sizes.append(meta["native_size"])
                    x64_sizes.append(meta["x64_size"])
                    ns = meta["native_size"]
                    total_bytes += ns

                    if meta["x64_size"] > 0:
                        expansion_ratios.append(meta["native_size"] / meta["x64_size"])

                    if meta["tick"] == 0:
                        cold_count += 1
                        cold_bytes += ns
                    else:
                        for threshold in (100, 1000, 4096):
                            if age <= threshold:
                                working_set[threshold]["count"] += 1
                                working_set[threshold]["bytes"] += ns

                # Block age histogram
                print(f"\n  Live Block Age Distribution (max_tick - block_tick, per-process):")
                age_buckets = {}
                for age in ages:
                    bucket = 0 if age == 0 else max(0, age.bit_length() - 1)
                    age_buckets[bucket] = age_buckets.get(bucket, 0) + 1
                if age_buckets:
                    max_count = max(age_buckets.values())
                    for bucket in sorted(age_buckets.keys()):
                        low = 1 << bucket if bucket > 0 else 0
                        high = (1 << (bucket + 1)) - 1 if bucket > 0 else 0
                        count = age_buckets[bucket]
                        bar_len = int(count * 40 / max_count) if max_count > 0 else 0
                        bar = "#" * bar_len
                        print(f"    [{low:>10}, {high:>10}] : {count:>8} {bar}")

                # isize histogram (live blocks)
                print(f"\n  Live Block Instruction Count Distribution:")
                isize_buckets = {}
                for isize in isizes:
                    if isize > 0:
                        bucket = max(0, isize.bit_length() - 1)
                        isize_buckets[bucket] = isize_buckets.get(bucket, 0) + 1
                if isize_buckets:
                    max_count = max(isize_buckets.values())
                    for bucket in sorted(isize_buckets.keys()):
                        low = 1 << bucket
                        high = (1 << (bucket + 1)) - 1
                        count = isize_buckets[bucket]
                        bar_len = int(count * 40 / max_count) if max_count > 0 else 0
                        bar = "#" * bar_len
                        print(f"    [{low:>10}, {high:>10}] : {count:>8} {bar}")

                # Expansion ratio
                if expansion_ratios:
                    expansion_ratios.sort()
                    avg_exp = sum(expansion_ratios) / len(expansion_ratios)
                    med_exp = expansion_ratios[len(expansion_ratios) // 2]
                    max_exp = expansion_ratios[-1]
                    print(f"\n  Code Expansion Ratio (native_size / x64_size):")
                    print(f"    avg: {avg_exp:.1f}x   median: {med_exp:.1f}x   max: {max_exp:.1f}x")

                # Working set estimate
                total_live = len(live_meta)
                print(f"\n  Working Set Analysis:")
                for threshold in (100, 1000, 4096):
                    ws = working_set[threshold]
                    pct = ws["count"] / total_live * 100 if total_live > 0 else 0
                    print(f"    Blocks active in last {threshold:>5} ticks: "
                          f"{ws['count']:>8,} ({pct:>4.0f}%)  using {fmt_size(ws['bytes']):>10}")
                cold_pct = cold_count / total_live * 100 if total_live > 0 else 0
                print(f"    Cold blocks (never executed):     "
                      f"{cold_count:>8,} ({cold_pct:>4.0f}%)  using {fmt_size(cold_bytes):>10}")
                print(f"    Total live blocks:                "
                      f"{total_live:>8,}         using {fmt_size(total_bytes):>10}")

                # Per-process cache summary
                pid_summaries = {}
                for pid, alloc_addr, blk_size, meta in live_meta:
                    ps = pid_summaries.get(pid)
                    if not ps:
                        ps = {"count": 0, "bytes": 0, "tick_sum": 0, "ws100_count": 0, "ws100_bytes": 0}
                        pid_summaries[pid] = ps
                    ps["count"] += 1
                    ps["bytes"] += meta["native_size"]
                    ps["tick_sum"] += meta["tick"]
                    max_t = max_tick_per_pid.get(pid, 0)
                    age = max_t - meta["tick"] if max_t > meta["tick"] else 0
                    if meta["tick"] > 0 and age <= 100:
                        ps["ws100_count"] += 1
                        ps["ws100_bytes"] += meta["native_size"]

                if len(pid_summaries) > 1:
                    print(f"\n  Per-Process Cache Summary:")
                    print(f"  {'PID':>7s}  {'Label':>25s}  {'Live Blocks':>12s}  {'Cache Size':>10s}  "
                          f"{'Avg Tick':>10s}  {'Working Set (100t)':>20s}")
                    print(f"  {'-'*7}  {'-'*25}  {'-'*12}  {'-'*10}  {'-'*10}  {'-'*20}")
                    for pid in sorted(pid_summaries.keys()):
                        ps = pid_summaries[pid]
                        label = pid_labels.get(pid, f"pid{pid}")[:25]
                        avg_tick = ps["tick_sum"] / ps["count"] if ps["count"] > 0 else 0
                        ws_str = f"{ps['ws100_count']:,} ({fmt_size(ps['ws100_bytes'])})"
                        print(f"  {pid:>7}  {label:>25s}  {ps['count']:>12,}  {fmt_size(ps['bytes']):>10}  "
                              f"{avg_tick:>10.0f}  {ws_str:>20s}")

        if not args.no_mmap:
            print(f"\n  Mmap Totals (box_mmap calls InternalMmap internally; counts overlap):")
            print(f"    InternalMmap:   {vals[10]:>10}   InternalMunmap: {vals[11]:>10}")
            print(f"    box_mmap:       {vals[12]:>10}   box_munmap:     {vals[13]:>10}")

        # -- Section 2: Process tree --
        if proc_children or pid_labels:
            print(f"\n  Box64 Process Tree:")
            all_pids = set(pid_labels.keys())
            child_pids = set()
            for children in proc_children.values():
                child_pids.update(children)
            root_pids = sorted(all_pids - child_pids)
            if not root_pids:
                root_pids = sorted(all_pids)

            def print_proc_tree(pid, prefix, is_last):
                connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
                label = pid_labels.get(pid, f"pid{pid}")
                extra_info = []

                # Check for pressure_vessel detection
                for _, pv_pid, _ in pv_events:
                    if pv_pid == pid:
                        extra_info.append("pressure_vessel()")
                        break

                # Get latest smaps if available
                if pid in smaps_history and smaps_history[pid]:
                    _, latest_smaps = smaps_history[pid][-1]
                    rss = latest_smaps.get('Rss', 0)
                    if rss > 0:
                        extra_info.append(f"RSS={fmt_size(rss)}")

                info_str = f"  ({', '.join(extra_info)})" if extra_info else ""
                print(f"{prefix}{connector}PID {pid:>7}  [{label}]{info_str}")

                child_prefix = prefix + ("    " if is_last else "\u2502   ")
                children = proc_children.get(pid, [])
                for i, child in enumerate(children):
                    print_proc_tree(child, child_prefix, i == len(children) - 1)

            for i, root_pid in enumerate(root_pids):
                label = pid_labels.get(root_pid, f"pid{root_pid}")
                print(f"    PID {root_pid}  [{label}]")
                children = proc_children.get(root_pid, [])
                for j, child in enumerate(children):
                    print_proc_tree(child, "    ", j == len(children) - 1)

        # -- Section 3: Fork/Exec timeline --
        if timeline:
            print(f"\n  Fork/Exec Event Timeline (chronological):")
            print(f"  {'T+':>10s}  {'PID':>7s}  {'Event':>18s}  {'Details'}")
            print(f"  {'-'*10}  {'-'*7}  {'-'*18}  {'-'*40}")

            base_ns = timeline[0]["ts_ns"]
            for entry in timeline:
                rel_s = (entry["ts_ns"] - base_ns) / 1e9
                etype = entry["type"]
                name = entry["name"]
                pid = entry["pid"]
                details = ""

                if etype == 3:  # fork_child
                    details = f"-> child PID {entry['child_pid']}"
                elif etype == 2:  # x64emu_fork
                    fname = FORKTYPE_NAMES.get(entry["forktype"], f"type{entry['forktype']}")
                    details = f"forktype={fname}"
                elif etype in (4, 5, 6, 7, 8, 9):  # exec*
                    details = f"-> {entry['path']}" if entry['path'] else ""
                elif etype == 10:  # pressure_vessel
                    details = f"prog={entry['path']}" if entry['path'] else ""
                elif etype == 11:  # new_context
                    details = f"argc={entry['extra']}"
                elif etype == 13:  # calc_stack
                    details = f"ret={entry['extra']}"

                print(f"  {rel_s:>9.3f}s  {pid:>7}  {name:>18s}  {details}")

        # -- Section 4: Per-PID memory breakdown --
        # sched_process_fork fires for clone(CLONE_THREAD) too, so proc_mem
        # ends up with one entry per thread TID. Those entries can never
        # accumulate any allocations (customMalloc keys on TGID), so they
        # show as perpetual zero rows. Filter them out and show a count.
        proc_mem_table = b["proc_mem"]
        per_pid_data = {}
        threads_filtered = 0
        for k, v in proc_mem_table.items():
            pid = k.value
            if pid_kind.get(pid) == "thread":
                threads_filtered += 1
                continue
            per_pid_data[pid] = v

        if per_pid_data:
            print(f"\n  Per-PID Memory Breakdown:")
            if threads_filtered:
                print(f"  ({threads_filtered} thread TIDs hidden — these are "
                      f"clone(CLONE_THREAD) entries that never receive "
                      f"allocations because customMalloc keys on TGID. Their "
                      f"allocator activity is folded into the parent's row.)")
            for pid in sorted(per_pid_data.keys()):
                v = per_pid_data[pid]
                label = pid_labels.get(pid, f"pid{pid}")
                print(f"\n  {'='*72}")
                print(f"  PID {pid}  [{label}]")
                print(f"  {'-'*72}")

                if not args.no_mem:
                    net_alloc_bytes = v.malloc_bytes - v.free_bytes
                    print(f"    Custom allocator:")
                    print(f"      malloc: {v.malloc_count:>10}  free: {v.free_count:>10}  "
                          f"calloc: {v.calloc_count:>10}  realloc: {v.realloc_count:>10}")
                    print(f"      bytes alloc: {fmt_size(v.malloc_bytes):>12}  "
                          f"bytes freed: {fmt_size(v.free_bytes):>12}  "
                          f"net: {fmt_size(net_alloc_bytes):>12}")

                if not args.no_dynarec:
                    net_jit = v.jit_alloc_bytes - v.jit_free_bytes
                    print(f"    DynaRec JIT:")
                    print(f"      alloc: {v.jit_alloc_count:>10}  free: {v.jit_free_count:>10}")
                    print(f"      bytes alloc: {fmt_size(v.jit_alloc_bytes):>12}  "
                          f"bytes freed: {fmt_size(v.jit_free_bytes):>12}  "
                          f"net: {fmt_size(net_jit):>12}")

                if not args.no_mmap:
                    print(f"    InternalMmap:")
                    print(f"      mmap: {v.mmap_count:>10}  munmap: {v.munmap_count:>10}  "
                          f"total mapped: {fmt_size(v.mmap_bytes):>12}")
                    print(f"    box_mmap (guest):")
                    print(f"      mmap: {v.box_mmap_count:>10}  munmap: {v.box_munmap_count:>10}  "
                          f"total mapped: {fmt_size(v.box_mmap_bytes):>12}")

                print(f"    Context: {v.context_created} created  /  {v.context_freed} freed")

                # Latest smaps
                smaps = read_smaps_rollup(pid)
                if smaps:
                    print(f"    /proc RSS: {fmt_size(smaps.get('Rss', 0)):>10}  "
                          f"PSS: {fmt_size(smaps.get('Pss', 0)):>10}  "
                          f"Private_Dirty: {fmt_size(smaps.get('Private_Dirty', 0)):>10}")

        # -- Section 5: Memory growth timeline --
        if smaps_history:
            print(f"\n  Memory Growth Timeline (RSS over time):")
            for pid in sorted(smaps_history.keys()):
                samples = smaps_history[pid]
                if len(samples) < 2:
                    continue
                label = pid_labels.get(pid, f"pid{pid}")
                print(f"\n    PID {pid} [{label}]:")
                t0 = samples[0][0]
                for ts, smaps in samples:
                    rss = smaps.get('Rss', 0)
                    pss = smaps.get('Pss', 0)
                    print(f"      T+{ts - t0:>8.1f}s  RSS={fmt_size(rss):>10}  PSS={fmt_size(pss):>10}")

        # -- Section 6: Thread summary + tree --
        known_pids = set()
        if track_threads:
            tc = b["thread_counters"]
            created = tc[tc.Key(0)].value
            destroyed = tc[tc.Key(1)].value
            peak = tc[tc.Key(2)].value
            current = tc[tc.Key(3)].value
            forks = tc[tc.Key(4)].value
            clones = tc[tc.Key(5)].value

            print(f"\n  Thread Summary:")
            print(f"    Total created:    {created:>8}")
            print(f"    Total destroyed:  {destroyed:>8}")
            print(f"    Peak concurrent:  {peak:>8}")
            print(f"    Still active:     {current:>8}")
            print(f"    Forks:            {forks:>8}")
            print(f"    Clones:           {clones:>8}")

            ts_table = b["thread_stats"]
            tid_stats = {}
            for k, v in ts_table.items():
                tid_stats[k.value] = (v.alloc_count, v.alloc_bytes)

            # Deferred correlation for thread tree
            correlate_thread_parents(thread_timeline, create_requests,
                                     thread_parent)

            all_tids = set(thread_timeline.keys()) | set(tid_stats.keys())
            for tid in all_tids:
                info = thread_timeline.get(tid, {})
                pid = info.get("pid", 0)
                if pid:
                    known_pids.add(pid)

            for pid in known_pids:
                if pid not in thread_timeline:
                    thread_timeline[pid] = {
                        "x64_fnc": 0, "create_ns": 0,
                        "destroy_ns": None, "pid": pid
                    }
                all_tids.add(pid)

            if all_tids and known_pids:
                children_of = {}
                for tid in all_tids:
                    info = thread_timeline.get(tid, {})
                    pid = info.get("pid", 0)
                    if not pid:
                        continue
                    parent = thread_parent.get(tid)
                    if parent is not None:
                        children_of.setdefault(parent, []).append(tid)
                    elif tid != pid:
                        children_of.setdefault(pid, []).append(tid)

                def fmt_tid_line(tid, is_main=False):
                    info = thread_timeline.get(tid, {})
                    x64_fnc = info.get("x64_fnc", 0)
                    stats = tid_stats.get(tid, (0, 0))
                    ac, ab = stats
                    label = f"TID {tid}"
                    if is_main:
                        label += " (main)"
                    elif x64_fnc:
                        label += f" [x64:0x{x64_fnc:x}]"
                    alive = info.get("destroy_ns") is None if info else True
                    status = "" if alive else " (exited)"
                    return f"{label}{status}  {ac:>10,} allocs  {fmt_size(ab):>10}"

                def print_subtree(tid, prefix, is_last, is_main=False):
                    connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
                    print(f"{prefix}{connector}{fmt_tid_line(tid, is_main)}")
                    child_prefix = prefix + ("    " if is_last else "\u2502   ")
                    kids = sorted(children_of.get(tid, []))
                    clones_list = clone_children.get(tid, [])
                    forks_list = [e for e in fork_events if e[1] == tid]
                    # FIFO match my_fork entry events to sched_process_fork
                    # tracepoint observations on the same parent_pid.
                    fork_kids_by_pid = {}
                    for fe_ts, fe_tid, fe_pid in forks_list:
                        fork_kids_by_pid.setdefault(
                            fe_pid, list(proc_children.get(fe_pid, [])))
                    total = len(kids) + len(clones_list) + len(forks_list)
                    idx = 0
                    for child_tid in kids:
                        idx += 1
                        print_subtree(child_tid, child_prefix, idx == total)
                    for fe_ts, fe_tid, fe_pid in forks_list:
                        idx += 1
                        conn = "\u2514\u2500\u2500 " if idx == total else "\u251c\u2500\u2500 "
                        kids_q = fork_kids_by_pid.get(fe_pid, [])
                        if kids_q:
                            cpid = kids_q.pop(0)
                            print(f"{child_prefix}{conn}fork \u2192 PID {cpid}")
                        else:
                            print(f"{child_prefix}{conn}fork (child PID unknown)")
                    for child_pid in clones_list:
                        idx += 1
                        conn = "\u2514\u2500\u2500 " if idx == total else "\u251c\u2500\u2500 "
                        print(f"{child_prefix}{conn}clone \u2192 PID {child_pid}")

                print(f"\n  Process/Thread Tree:")
                for pid in sorted(known_pids):
                    pid_label = pid_labels.get(pid, "")
                    label_str = f" [{pid_label}]" if pid_label else ""
                    print(f"    PID {pid}{label_str}")
                    print_subtree(pid, "    ", True, is_main=True)

            # Top threads table
            ts_items = sorted(tid_stats.items(), key=lambda x: x[1][1], reverse=True)
            if ts_items:
                top_n = min(10, len(ts_items))
                print(f"\n  Top {top_n} threads by allocation volume:")
                print(f"  {'TID':>7s}  {'Allocs':>10s}  {'AllocBytes':>12s}  {'x64 Start':>18s}  {'PID':>7s}")
                print(f"  {'-'*7}  {'-'*10}  {'-'*12}  {'-'*18}  {'-'*7}")
                for i, (tid, (ac, ab)) in enumerate(ts_items[:top_n]):
                    info = thread_timeline.get(tid, {})
                    fnc = info.get("x64_fnc", 0)
                    pid = info.get("pid", 0)
                    fnc_str = f"0x{fnc:016x}" if fnc else "    (main/unknown)"
                    print(f"  {tid:>7}  {ac:>10}  {fmt_size(ab):>12s}  {fnc_str}  {pid:>7}")

        # -- Section 7: Copy-on-Write analysis --
        # CoW kprobe counts (per-pid) — read once, used both in the per-child
        # summary below and in the system-wide table further down.
        cow_faults_by_pid = {}
        if track_cow_kprobe:
            for k, v in b["cow_per_pid"].items():
                cow_faults_by_pid[k.value] = v.cow_faults

        if fork_cow_data:
            print(f"\n  Copy-on-Write Analysis:")
            for parent_pid, cow_info in fork_cow_data.items():
                ps = cow_info["parent_smaps"]
                print(f"\n    Parent PID {parent_pid} at fork:")
                print(f"      Rss: {fmt_size(ps.get('Rss', 0)):>10}   "
                      f"Private_Dirty: {fmt_size(ps.get('Private_Dirty', 0)):>10}   "
                      f"Minor faults: {cow_info['parent_minflt']}")

                children = cow_info["child_samples"]
                if not children:
                    print("      (no child snapshots collected)")
                    continue

                rows = []
                for cpid, info in children.items():
                    last = info["last"]
                    cur_dirty, cur_minflt = compute_cow_deltas(
                        ps, cow_info["parent_minflt"],
                        last["smaps"], last["minflt"])
                    age = last["time"] - cow_info["snapshot_time"]
                    cow_faults = cow_faults_by_pid.get(cpid, 0)
                    rows.append((cpid, age, info["count"],
                                 last["smaps"].get("Private_Dirty", 0),
                                 cur_dirty, last["minflt"], cur_minflt,
                                 cow_faults))
                sort_idx = 7 if track_cow_kprobe else 6
                rows.sort(key=lambda r: r[sort_idx], reverse=True)

                n = len(rows)
                cow_min, cow_max = min(r[4] for r in rows), max(r[4] for r in rows)
                mf_min, mf_max = min(r[6] for r in rows), max(r[6] for r in rows)
                summary = (f"      {n} children: +CoW {fmt_size(cow_min)}..{fmt_size(cow_max)}, "
                           f"+minflt {mf_min:,}..{mf_max:,}")
                if track_cow_kprobe:
                    cf_min = min(r[7] for r in rows)
                    cf_max = max(r[7] for r in rows)
                    summary += f", CoW faults {cf_min:,}..{cf_max:,}"
                print(summary)

                print()
                if track_cow_kprobe:
                    print(f"      {'PID':>7}  {'Age':>7}  {'N':>3}  "
                          f"{'Priv_Dirty':>10}  {'+CoW':>10}  "
                          f"{'MinFlt':>11}  {'+MinFlt':>11}  {'CoW_Faults':>10}")
                    print(f"      {'-'*7}  {'-'*7}  {'-'*3}  "
                          f"{'-'*10}  {'-'*10}  {'-'*11}  {'-'*11}  {'-'*10}")
                    for cpid, age, count, priv, cow, mflt, dmflt, cf in rows:
                        print(f"      {cpid:>7}  {age:>6.1f}s  {count:>3}  "
                              f"{fmt_size(priv):>10}  {fmt_size(cow):>10}  "
                              f"{mflt:>11,}  {dmflt:>11,}  {cf:>10,}")
                else:
                    print(f"      {'PID':>7}  {'Age':>7}  {'N':>3}  "
                          f"{'Priv_Dirty':>10}  {'+CoW':>10}  "
                          f"{'MinFlt':>11}  {'+MinFlt':>11}")
                    print(f"      {'-'*7}  {'-'*7}  {'-'*3}  "
                          f"{'-'*10}  {'-'*10}  {'-'*11}  {'-'*11}")
                    for cpid, age, count, priv, cow, mflt, dmflt, _cf in rows:
                        print(f"      {cpid:>7}  {age:>6.1f}s  {count:>3}  "
                              f"{fmt_size(priv):>10}  {fmt_size(cow):>10}  "
                              f"{mflt:>11,}  {dmflt:>11,}")

        if track_cow_kprobe:
            cow_items = list(cow_faults_by_pid.items())
            tracked_pids = set(known_pids) | set(pid_labels.keys())
            # Include forked children (from sched_process_fork tracepoint)
            # and clone children (from clone_return) so they aren't filtered
            # out of the system-wide CoW Page Faults table.
            for kids in proc_children.values():
                tracked_pids.update(kids)
            for kids in process_children.values():
                tracked_pids.update(kids)
            if args.pid:
                tracked_pids.add(args.pid)
            if tracked_pids:
                cow_items = [(p, f) for p, f in cow_items if p in tracked_pids]
            cow_items.sort(key=lambda x: x[1], reverse=True)
            if cow_items:
                page_size = os.sysconf("SC_PAGESIZE")
                print(f"\n  CoW Page Faults (kprobe, page size {page_size}):")
                print(f"  {'PID':>7s}  {'CoW Faults':>12s}  {'Est. Copied':>12s}")
                print(f"  {'-'*7}  {'-'*12}  {'-'*12}")
                for pid, faults in cow_items[:20]:
                    label = pid_labels.get(pid, "")
                    label_str = f"  [{label}]" if label else ""
                    print(f"  {pid:>7}  {faults:>12}  {fmt_size(faults * page_size):>12}{label_str}")

        # -- Section 8: PC Sampling Profile --
        if track_profile and block_last_active:
            total_intervals = profile_interval_idx[0]
            interval_sec = args.interval

            # Gather block metadata for all tracked blocks (uses cache)
            block_info = {}  # (pid, alloc) -> metadata dict
            for bkey in block_last_active:
                pid, alloc_addr = bkey
                meta = _cached_block_metadata(pid, alloc_addr)
                if meta:
                    block_info[bkey] = meta

            if block_info:
                print(f"\n  PC Sampling Profile ({args.sample_freq} Hz, "
                      f"{total_intervals} intervals of {interval_sec}s):")

                # 8a. Block Age Distribution (bounds in seconds)
                age_buckets = [
                    ("active now", 0, 0),
                    ("10-30s ago", 10, 30),
                    ("30-60s ago", 30, 60),
                    ("1-2 min ago", 60, 120),
                    ("2-5 min ago", 120, 300),
                    (">5 min ago", 300, total_intervals * interval_sec + 1),
                ]
                # Also count "never seen" blocks (in jit_blocks but not in block_last_active)
                all_jit_keys = set()
                for k, v in b["jit_blocks"].items():
                    all_jit_keys.add((v.pid, k.value))
                never_seen = all_jit_keys - set(block_last_active.keys())

                print(f"\n  Block Age Distribution:")
                print(f"  {'Age':>18s}  {'Blocks':>8s}  {'Native Size':>12s}  {'Cumul. Evictable':>18s}")
                print(f"  {'-'*18}  {'-'*8}  {'-'*12}  {'-'*18}")

                cumulative_size = 0
                for label, lo_s, hi_s in age_buckets:
                    if label == "active now":
                        matching = [bk for bk, la in block_last_active.items()
                                    if la == total_intervals]
                    else:
                        matching = [bk for bk, la in block_last_active.items()
                                    if lo_s <= (total_intervals - la) * interval_sec < hi_s]
                    count = len(matching)
                    size = sum(block_info[bk]["native_size"] for bk in matching if bk in block_info)
                    if label != "active now":
                        cumulative_size += size
                        cum_str = fmt_size(cumulative_size)
                    else:
                        cum_str = "—"
                    print(f"  {label:>18s}  {count:>8,}  {fmt_size(size):>12s}  {cum_str:>18s}")

                # Never-executed blocks
                never_meta = {}
                for bk in never_seen:
                    meta = _cached_block_metadata(bk[0], bk[1])
                    if meta:
                        never_meta[bk] = meta
                never_size = sum(m["native_size"] for m in never_meta.values())
                cumulative_size += never_size
                print(f"  {'never executed':>18s}  {len(never_meta):>8,}  "
                      f"{fmt_size(never_size):>12s}  {fmt_size(cumulative_size):>18s}")

                total_blocks_profiled = len(block_info) + len(never_meta)
                total_native = sum(m["native_size"] for m in block_info.values()) + never_size
                print(f"  {'Total':>18s}  {total_blocks_profiled:>8,}  {fmt_size(total_native):>12s}")

                # 8b. Eviction Threshold Analysis
                thresholds = [10, 30, 60, 120, 300]
                print(f"\n  Eviction Threshold Analysis:")
                print(f"  {'Evict if unused for':>22s}  {'Blocks evicted':>16s}  "
                      f"{'Memory saved':>14s}  {'% of cache':>12s}")
                print(f"  {'-'*22}  {'-'*16}  {'-'*14}  {'-'*12}")

                for thresh_s in thresholds:
                    evictable = [bk for bk, la in block_last_active.items()
                                 if (total_intervals - la) * interval_sec >= thresh_s]
                    evict_size = sum(block_info[bk]["native_size"]
                                     for bk in evictable if bk in block_info)
                    # Add never-seen blocks
                    evict_count = len(evictable) + len(never_meta)
                    evict_size += never_size
                    pct = (evict_size / total_native * 100) if total_native > 0 else 0
                    print(f"  {'> ' + str(thresh_s) + ' seconds':>22s}  {evict_count:>16,}  "
                          f"{fmt_size(evict_size):>14s}  {pct:>11.1f}%")

                # 8c. Top 20 Hottest Blocks (by active intervals)
                sorted_by_activity = sorted(block_active_intervals.items(),
                                            key=lambda x: x[1], reverse=True)
                if sorted_by_activity:
                    top_n = min(20, len(sorted_by_activity))
                    print(f"\n  Top {top_n} Hottest Blocks (by active intervals):")
                    print(f"  {'Intervals':>14s}  {'x64 Address':>18s}  "
                          f"{'isize':>6s}  {'native_size':>12s}  {'PID':>7s}")
                    print(f"  {'-'*14}  {'-'*18}  {'-'*6}  {'-'*12}  {'-'*7}")

                    for bkey, active_count in sorted_by_activity[:top_n]:
                        pid, alloc_addr = bkey
                        meta = block_info.get(bkey)
                        if not meta:
                            continue
                        print(f"  {active_count:>6}/{total_intervals:<6}  "
                              f"0x{meta['x64_addr']:016x}  "
                              f"{meta['isize']:>6}  "
                              f"{fmt_size(meta['native_size']):>12s}  "
                              f"{pid:>7}")

                # 8d. Per-Process Profile Summary
                per_pid_profile = {}  # pid -> {blocks, active, cold, cold_size}
                for bkey in block_info:
                    pid = bkey[0]
                    if pid not in per_pid_profile:
                        per_pid_profile[pid] = {"blocks": 0, "active": 0,
                                                "cold": 0, "cold_size": 0}
                    pp = per_pid_profile[pid]
                    pp["blocks"] += 1
                    la = block_last_active.get(bkey, 0)
                    if la == total_intervals:
                        pp["active"] += 1
                    elif (total_intervals - la) * interval_sec > 60:
                        pp["cold"] += 1
                        pp["cold_size"] += block_info[bkey]["native_size"]

                if per_pid_profile:
                    print(f"\n  Per-Process Profile:")
                    print(f"  {'PID':>7s}  {'Label':>20s}  {'Blocks':>8s}  {'Active':>8s}  "
                          f"{'Cold>60s':>10s}  {'Cold Size':>12s}")
                    print(f"  {'-'*7}  {'-'*20}  {'-'*8}  {'-'*8}  {'-'*10}  {'-'*12}")
                    for pid in sorted(per_pid_profile.keys()):
                        pp = per_pid_profile[pid]
                        label = pid_labels.get(pid, f"pid{pid}")[:20]
                        print(f"  {pid:>7}  {label:>20s}  {pp['blocks']:>8,}  "
                              f"{pp['active']:>8,}  {pp['cold']:>10,}  "
                              f"{fmt_size(pp['cold_size']):>12s}")

        print("\n" + "=" * 76)

    # ---- Optional web dashboard ----
    # If startup fails (port in use, missing assets, etc.) we keep tracing
    # without the dashboard rather than killing the whole run — the CLI
    # report still works and that's the source of truth.
    web_server = None
    web_module = None
    _web_emit = None
    if not args.no_web:
        try:
            import box64_web
            web_server = box64_web.start(
                args.web_port, web_snapshot, web_stats_meta,
                browser_pref=args.browser)
            web_module = box64_web
            _web_emit = box64_web.emit_event
        except OSError as e:
            # box64_web.start() auto-scans 20 ports above args.web_port plus
            # the kernel ephemeral range, so reaching this branch means
            # everything failed — extremely unusual on a sane host.
            import errno
            if e.errno == errno.EACCES:
                print(f"WARNING: permission denied binding ports near "
                      f"{args.web_port} — dashboard disabled.")
                print(f"         Ports < 1024 require CAP_NET_BIND_SERVICE; "
                      f"pick a higher base port with `--web-port NNNN`.")
            else:
                # The OSError raised by start() already lists what was
                # tried; just relay it.
                print(f"WARNING: dashboard could not start ({e}) — "
                      f"continuing without it.")
        except Exception as e:
            print(f"WARNING: failed to start web dashboard: "
                  f"{type(e).__name__}: {e} — continuing without it.")

    # ---- Main loop ----
    prev_vals = read_stats()
    last_print = time.monotonic()

    child_exited = [False]

    def _poll_child_exit():
        """Reap spawned child if it has exited; flip exiting + capture rc.

        We deliberately do NOT shut the dashboard down here — when box64
        crashes, that's exactly when the user most wants to switch to the
        browser tab and inspect live state. The dashboard stays up; the
        user closes it explicitly with Ctrl+C below.
        """
        nonlocal spawned_pid
        if spawned_pid is None:
            return
        try:
            wpid, status = os.waitpid(spawned_pid, os.WNOHANG)
        except ChildProcessError:
            spawned_pid = None
            return
        if wpid == spawned_pid:
            rc, msg = _format_child_exit(status)
            child_returncode[0] = rc
            print(f"[*] Child PID {spawned_pid} {msg}")
            print(f"[*] Finishing report.")
            spawned_pid = None
            child_exited[0] = True
            exiting[0] = True

    while not exiting[0]:
        try:
            deadline = time.monotonic() + args.interval
            while time.monotonic() < deadline and not exiting[0]:
                b.perf_buffer_poll(timeout=1000)
                _poll_child_exit()
        except KeyboardInterrupt:
            exiting[0] = True
            break
        if not exiting[0]:
            vals = read_stats()
            print_periodic(vals, prev_vals)
            prev_vals = vals
            last_print = time.monotonic()
            # PC sampling interval diff
            profile_interval()
            # CoW child sampling — iterate both fork children (from
            # sched_process_fork tracepoint) and clone children (from
            # clone_return uprobe). Only first+last per child are kept.
            for parent_pid, cow_info in fork_cow_data.items():
                child_pids = (set(proc_children.get(parent_pid, []))
                              | set(process_children.get(parent_pid, [])))
                for child_pid in child_pids:
                    smaps = read_smaps_rollup(child_pid)
                    minflt = read_minflt(child_pid)
                    if not smaps:
                        continue
                    sample = {"time": time.monotonic(), "smaps": smaps, "minflt": minflt}
                    cs = cow_info["child_samples"]
                    entry = cs.get(child_pid)
                    if entry is None:
                        cs[child_pid] = {"first": sample, "last": sample, "count": 1}
                    else:
                        entry["last"] = sample
                        entry["count"] += 1

    vals = read_stats()
    print_final_report(vals)
    _close_proc_mem_fds()
    print("[*] Detaching probes.")

    # Spawn mode: forward COMMAND's exit code so the wrapper is transparent
    # to scripts. If the child is still running (Ctrl+C path), terminate it
    # so we don't leak a process.
    if spawned_pid is not None:
        try:
            os.kill(spawned_pid, signal.SIGTERM)
            wpid, status = os.waitpid(spawned_pid, 0)
            rc, _ = _format_child_exit(status)
            child_returncode[0] = rc
        except (ProcessLookupError, ChildProcessError):
            pass

    # Only keep the dashboard alive when there's actually a crash to
    # inspect. Clean exits (and runs where --no-web disabled the dashboard)
    # just exit; making the user Ctrl+C through a successful run is
    # friction with no payoff. See _should_keep_dashboard_alive for the
    # full case matrix.
    if _should_keep_dashboard_alive(
            web_active=(web_module is not None and web_server is not None),
            child_exited=child_exited[0],
            user_signalled=_user_signalled[0],
            child_returncode=child_returncode[0]):
        host_port = f"{web_server.server_address[0]}:{web_server.server_address[1]}"
        print(f"[*] Child crashed — dashboard still serving at "
              f"http://{host_port}/ so you can inspect what was happening "
              f"at the moment of the crash. Ctrl+C to shut down "
              f"(will exit rc={child_returncode[0]}).")
        _wait_for_user_signal(_user_signalled)

    # Tear down the dashboard cleanly. Idempotent — shutdown() on an
    # already-stopped server is a no-op.
    if web_module is not None and web_server is not None:
        web_module.shutdown(web_server)

    if args.command:
        sys.exit(child_returncode[0])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # User Ctrl+C'd before main() installed its own handler, or during
        # final report printing — exit with the conventional 130.
        sys.exit(130)
    except SystemExit:
        # main() and helpers use sys.exit(N) to forward child rc / signal
        # missing-deps. Let those through unchanged.
        raise
    except Exception as e:
        sys.exit(report_fatal(e))
