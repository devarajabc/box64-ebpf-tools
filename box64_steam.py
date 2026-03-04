#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# box64_steam.py — eBPF/BCC uprobe-based multi-process tracer for Box64 + Steam.
# Tracks fork/exec/vfork process lifecycle, per-PID memory usage (custom allocator,
# DynaRec JIT, mmap), context creation/destruction, and pressure-vessel detection
# across ALL concurrent box64 instances simultaneously.
#
# Requires: root, linux >=4.9, python3-bcc (BCC toolkit)
#
# Usage:
#   sudo python3 box64_steam.py [-b BINARY] [-p PID] [-i INTERVAL] \
#                               [--no-mem] [--no-dynarec] [--no-mmap] \
#                               [--no-threads] [--no-cow] [--hash-capacity N]

from __future__ import print_function
import argparse
import os
import signal
import subprocess
import sys
import time

try:
    from bcc import BPF
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

def fmt_size(n):
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def check_binary(path):
    """Verify binary exists and is readable."""
    if not os.path.isfile(path):
        print(f"ERROR: binary not found: {path}")
        sys.exit(1)
    if not os.access(path, os.R_OK):
        print(f"ERROR: cannot read binary: {path}")
        sys.exit(1)


def _read_symbols(path):
    """Read all symbols from binary using nm (local + dynamic)."""
    out = ""
    for nm_args in [["nm", path], ["nm", "-D", path]]:
        try:
            out += subprocess.check_output(nm_args, stderr=subprocess.DEVNULL, text=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    return out


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


def check_symbols_soft(path, symbols):
    """Check if symbols are present; return list of missing ones (non-fatal)."""
    out = _read_symbols(path)
    if not out:
        return []  # can't verify, assume present
    return [s for s in symbols if s not in out]


def read_smaps_rollup(pid):
    """Read /proc/PID/smaps_rollup for CoW-relevant memory stats."""
    result = {}
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    if key in ("Rss", "Private_Dirty", "Private_Clean",
                               "Shared_Dirty", "Shared_Clean", "Pss"):
                        result[key] = int(parts[1]) * 1024  # kB -> bytes
    except (OSError, ValueError):
        pass
    return result


def read_minflt(pid):
    """Read minor page fault count from /proc/PID/stat (field 10)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().split()
            return int(fields[9])
    except (OSError, ValueError, IndexError):
        return 0


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


def _clear_stale_uprobes(binary):
    """Clear stale uprobe events and force a fresh inode for the binary.

    Works around a kernel bug where stale ref_ctr_offset values persist in the
    uprobe inode cache, causing perf_event_open to fail with EINVAL.
    """
    import shutil
    try:
        # Clear all uprobe events
        uprobe_events = "/sys/kernel/debug/tracing/uprobe_events"
        if os.path.exists(uprobe_events):
            with open(uprobe_events, "w") as f:
                f.write("")
    except OSError:
        pass
    try:
        # Force a new inode: copy then atomic rename back.
        # The kernel caches stale ref_ctr_offset per inode; a new inode
        # guarantees a clean slate.
        tmp = binary + ".uprobe_fix"
        shutil.copy2(binary, tmp)
        os.rename(tmp, binary)
        os.sync()
        # Drop kernel caches to release old inode references
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
    except OSError:
        pass  # best-effort; may still work without this


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
BPF_ARRAY(steam_stats, u64, 21);

static inline void inc_stat(int idx, u64 val) {
    int key = idx;
    u64 *v = steam_stats.lookup(&key);
    if (v) __sync_fetch_and_add(v, val);
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
    u32 pid;
};
BPF_HASH(jit_blocks, u64, struct jit_block_t, HASH_CAPACITY);
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
        struct jit_block_t blk = { .size = p->size, .pid = pid };
        jit_blocks.update(&alloc_addr, &blk);

        struct proc_mem_t *pm = get_or_init_proc_mem(pid);
        if (pm) {
            __sync_fetch_and_add(&pm->jit_alloc_count, 1);
            __sync_fetch_and_add(&pm->jit_alloc_bytes, p->size);
        }
        inc_stat(6, 1);
        inc_stat(8, p->size);
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
        jit_blocks.delete(&addr);
    }
    return 0;
}

#endif /* TRACK_DYNAREC */


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
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Trace Box64+Steam multi-process behavior: "
                    "fork/exec lifecycle, per-PID memory, DynaRec JIT, "
                    "mmap, and pressure-vessel detection using eBPF uprobes")
    p.add_argument("-b", "--binary", default="/usr/local/bin/box64",
                   help="Path to box64 binary (default: /usr/local/bin/box64)")
    p.add_argument("-p", "--pid", type=int, default=0,
                   help="Filter by PID (default: trace all box64 processes)")
    p.add_argument("-i", "--interval", type=int, default=10,
                   help="Summary interval in seconds (default: 10)")
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
    p.add_argument("--hash-capacity", type=int, default=524288,
                   help="BPF hash table capacity for outstanding alloc tracking (default: 524288)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    binary = args.binary

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

    # Build cflags
    hash_cap = args.hash_capacity
    cflags = [f"-DHASH_CAPACITY={hash_cap}"]
    if args.pid:
        cflags.append(f"-DFILTER_PID={args.pid}")
    if not args.no_mem:
        cflags.append("-DTRACK_MEM")
    if not args.no_dynarec:
        cflags.append("-DTRACK_DYNAREC")
    if not args.no_mmap:
        cflags.append("-DTRACK_MMAP")
    if track_threads:
        cflags.append("-DTRACK_THREADS")
    track_cow = not args.no_cow
    if track_cow:
        cflags.append("-DTRACK_COW")

    # Clear stale uprobe events (Asahi Linux workaround)
    _clear_stale_uprobes(binary)

    print(f"[*] Compiling and attaching uprobes to {binary} ...")
    b = BPF(text=BPF_PROGRAM, cflags=cflags)

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

    # sched_process_fork tracepoint for parent->child PID mapping
    try:
        b.attach_tracepoint(tp="sched:sched_process_fork", fn_name="trace_fork")
        probe_count += 1
    except Exception as e:
        print(f"WARNING: sched_process_fork tracepoint unavailable: {e}")

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

    pid_str = f" (PID {args.pid})" if args.pid else " (all PIDs)"
    features = []
    if not args.no_mem:
        features.append("mem")
    if not args.no_dynarec:
        features.append("dynarec")
    if not args.no_mmap:
        features.append("mmap")
    if track_threads:
        features.append("threads")
    if track_cow:
        features.append("cow")
    print(f"[*] {probe_count} probes attached{pid_str}. Features: {', '.join(features)}. "
          f"Interval: {args.interval}s. Ctrl+C to stop.")

    # ---- Graceful exit ----
    exiting = [False]

    def sig_handler(signum, frame):
        exiting[0] = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # ---- Python-side state ----
    timeline = []
    proc_children = {}     # parent_pid -> [child_pid, ...]
    pid_labels = {}        # pid -> string
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

        elif etype in (4, 5, 6, 7):  # exec* — update label to target binary
            if path:
                pid_labels[pid] = path.split('/')[-1]

        elif etype in (8, 9):  # posix_spawn* — spawns child, parent continues unchanged
            pass

        elif etype == 10:  # pressure_vessel
            pv_events.append((ts_ns, pid, path))
            print(f"  [!] pressure_vessel() detected: PID {pid} prog={path!r}")

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
                        "child_samples": [],
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

    # ---- Stats reading ----
    def read_stats():
        st = b["steam_stats"]
        return [st[st.Key(i)].value for i in range(21)]

    # ---- Periodic summary ----
    def print_periodic(vals, prev_vals):
        d = [vals[i] - prev_vals[i] for i in range(21)]

        print(f"\n--- {time.strftime('%H:%M:%S')} --- Box64+Steam ---")
        print(f"  fork: {d[14]:>6}  vfork: {d[15]:>6}  exec: {d[16]:>6}"
              f"  posix_spawn: {d[17]:>6}  context_new: {d[18]:>4}  context_free: {d[19]:>4}")

        if not args.no_mem:
            print(f"  malloc: {d[0]:>8}  free: {d[1]:>8}  calloc: {d[2]:>8}  realloc: {d[3]:>8}")
            print(f"  bytes_alloc: {fmt_size(d[4]):>10}  bytes_free: {fmt_size(d[5]):>10}")

        if not args.no_dynarec:
            print(f"  jit_alloc: {d[6]:>8}  jit_free: {d[7]:>8}  "
                  f"jit_alloc_bytes: {fmt_size(d[8]):>10}  jit_free_bytes: {fmt_size(d[9]):>10}")

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

    # ---- Final report ----
    def print_final_report(vals):
        print("\n" + "=" * 76)
        print("FINAL REPORT -- Box64+Steam Multi-Process Analysis")
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
            print(f"\n  DynaRec JIT Totals:")
            print(f"    jit_alloc: {vals[6]:>10}   jit_free: {vals[7]:>10}")
            print(f"    jit_alloc_bytes: {fmt_size(vals[8]):>12}   jit_free_bytes: {fmt_size(vals[9]):>12}")

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
        proc_mem_table = b["proc_mem"]
        per_pid_data = {}
        for k, v in proc_mem_table.items():
            pid = k.value
            per_pid_data[pid] = v

        if per_pid_data:
            print(f"\n  Per-PID Memory Breakdown:")
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
            unmatched = [t for t in thread_timeline if t not in thread_parent]
            remaining_reqs = list(create_requests)
            for tid in unmatched:
                info = thread_timeline[tid]
                pid = info.get("pid", 0)
                create_ns = info.get("create_ns", 0)
                if not pid or not create_ns:
                    continue
                best_idx = None
                best_delta = float('inf')
                for i, (ts, cr_tid, req_pid, req_fnc) in enumerate(remaining_reqs):
                    if req_pid != pid:
                        continue
                    delta = abs(create_ns - ts)
                    if delta < best_delta:
                        best_delta = delta
                        best_idx = i
                if best_idx is not None and best_delta < 5_000_000_000:
                    _, creator_tid, _, _ = remaining_reqs.pop(best_idx)
                    thread_parent[tid] = creator_tid

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
                    total = len(kids) + len(clones_list) + len(forks_list)
                    idx = 0
                    for child_tid in kids:
                        idx += 1
                        print_subtree(child_tid, child_prefix, idx == total)
                    for fe_ts, fe_tid, fe_pid in forks_list:
                        idx += 1
                        conn = "\u2514\u2500\u2500 " if idx == total else "\u251c\u2500\u2500 "
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
        if fork_cow_data:
            print(f"\n  Copy-on-Write Analysis:")
            for parent_pid, cow_info in fork_cow_data.items():
                ps = cow_info["parent_smaps"]
                print(f"\n    Parent PID {parent_pid} at fork:")
                print(f"      Rss: {fmt_size(ps.get('Rss', 0)):>10}   "
                      f"Private_Dirty: {fmt_size(ps.get('Private_Dirty', 0)):>10}   "
                      f"Minor faults: {cow_info['parent_minflt']}")
                for sample in cow_info["child_samples"]:
                    cs = sample["smaps"]
                    elapsed = sample["time"] - cow_info["snapshot_time"]
                    delta_dirty = cs.get("Private_Dirty", 0) - ps.get("Private_Dirty", 0)
                    delta_minflt = sample["minflt"] - cow_info["parent_minflt"]
                    print(f"    Child PID {sample['pid']} (after {elapsed:.1f}s):")
                    print(f"      Private_Dirty: {fmt_size(cs.get('Private_Dirty', 0)):>10}"
                          f"  (+{fmt_size(delta_dirty)} CoW)")
                    print(f"      Minor faults:  {sample['minflt']:>10}"
                          f"  (+{delta_minflt})")

        if track_cow_kprobe:
            cow_table = b["cow_per_pid"]
            cow_items = [(k.value, v.cow_faults) for k, v in cow_table.items()]
            tracked_pids = set(known_pids) | set(pid_labels.keys())
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

        print("\n" + "=" * 76)

    # ---- Main loop ----
    prev_vals = read_stats()
    last_print = time.monotonic()

    while not exiting[0]:
        try:
            deadline = time.monotonic() + args.interval
            while time.monotonic() < deadline and not exiting[0]:
                b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            exiting[0] = True
            break
        if not exiting[0]:
            vals = read_stats()
            print_periodic(vals, prev_vals)
            prev_vals = vals
            last_print = time.monotonic()
            # CoW child sampling
            for parent_pid, cow_info in fork_cow_data.items():
                for child_pid in process_children.get(parent_pid, []):
                    smaps = read_smaps_rollup(child_pid)
                    minflt = read_minflt(child_pid)
                    if smaps:
                        cow_info["child_samples"].append({
                            "time": time.monotonic(), "pid": child_pid,
                            "smaps": smaps, "minflt": minflt,
                        })

    vals = read_stats()
    print_final_report(vals)
    print("[*] Detaching probes.")


if __name__ == "__main__":
    main()
