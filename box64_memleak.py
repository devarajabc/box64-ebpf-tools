#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# box64_memleak.py — eBPF/BCC uprobe-based memory leak detector for Box64's
# custom allocator (customMalloc/customFree/customCalloc/customRealloc).
#
# Requires: root, linux >=4.9, python3-bcc (BCC toolkit)
#
# Usage:
#   sudo python3 box64_memleak.py [-b BINARY] [-p PID] [-i INTERVAL] [-t TOP] \
#                                  [--mmap] [--stacks] [--32bit]

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


def _patch_bcc_uretprobe():
    """Fix BCC 0.29.1 aarch64 bug: lib.bpf_attach_uprobe missing 7th arg.

    On aarch64, the missing ref_ctr_offset parameter picks up garbage from
    register x6, corrupting perf_event_attr.config and causing EINVAL when
    a uprobe and uretprobe target the same symbol. This monkey-patches the
    ctypes binding to always pass ref_ctr_offset=0.
    """
    import platform
    if platform.machine() != "aarch64":
        return
    try:
        import ctypes as ct
        from bcc import libbcc
        lib = libbcc.lib
        original = lib.bpf_attach_uprobe
        # Fix argtypes to include the 7th ref_ctr_offset parameter
        lib.bpf_attach_uprobe.argtypes = [
            ct.c_int,       # prog_fd
            ct.c_int,       # attach_type (uprobe vs uretprobe)
            ct.c_char_p,    # ev_name
            ct.c_char_p,    # binary_path
            ct.c_uint64,    # offset
            ct.c_int,       # pid
            ct.c_uint32,    # ref_ctr_offset
        ]
        lib.bpf_attach_uprobe.restype = ct.c_int

        def _patched_attach_uprobe(*args):
            if len(args) == 6:
                args = args + (ct.c_uint32(0),)
            return original(*args)

        lib.bpf_attach_uprobe = _patched_attach_uprobe
    except Exception as e:
        print(f"WARNING: failed to patch BCC uretprobe binding: {e}")


# ---------------------------------------------------------------------------
# BPF C program
# ---------------------------------------------------------------------------

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
    u64  size;
    u64  timestamp_ns;
    u32  pid;
    u32  tid;
    u8   type;    // 0=malloc, 1=calloc, 2=realloc
    u8   is32;
    int  stack_id;
};

struct pending_t {
    u64 size;
    u64 old_ptr;   // only used by realloc
    u8  type;
    u8  is32;
};

// Outstanding allocations keyed by pointer address
BPF_HASH(allocs, u64, struct alloc_info_t, HASH_CAPACITY);

// TID-keyed pending info (entry probe -> return probe handoff)
BPF_HASH(pending, u64, struct pending_t);

// Statistics: [0]=malloc_count, [1]=free_count, [2]=calloc_count,
//             [3]=realloc_count, [4]=bytes_allocd, [5]=bytes_freed,
//             [6]=mmap_count, [7]=munmap_count
BPF_ARRAY(stats, u64, 8);

#ifdef CAPTURE_STACKS
BPF_STACK_TRACE(stack_traces, 4096);
#endif

#ifdef TRACK_MMAP
struct mmap_info_t {
    u64 length;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
};

BPF_HASH(mmap_pending, u64, u64);   // tid -> length
BPF_HASH(mmap_allocs, u64, struct mmap_info_t, 16384);
#endif

static inline u64 tid_key(void) {
    return bpf_get_current_pid_tgid();
}

static inline u32 get_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

static inline void inc_stat(int idx, u64 val) {
    int key = idx;
    u64 *v = stats.lookup(&key);
    if (v) __sync_fetch_and_add(v, val);
}

// ---- Thread / process lifecycle tracking (structs + helpers) ----
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

// ---- customMalloc entry ----
int malloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct pending_t p = {};
    p.size = PT_REGS_PARM1(ctx);
    p.type = 0;
    p.is32 = 0;
    u64 tid = tid_key();
    pending.update(&tid, &p);
    return 0;
}

// ---- customMalloc return ----
int malloc_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    struct pending_t *p = pending.lookup(&tid);
    if (!p) return 0;

    u64 ptr = PT_REGS_RC(ctx);
    if (ptr == 0) {
        pending.delete(&tid);
        return 0;
    }

    struct alloc_info_t info = {};
    info.size = p->size;
    info.timestamp_ns = bpf_ktime_get_ns();
    info.pid = get_pid();
    info.tid = (u32)tid;
    info.type = p->type;
    info.is32 = p->is32;
#ifdef CAPTURE_STACKS
    info.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
#else
    info.stack_id = -1;
#endif

    allocs.update(&ptr, &info);
    inc_stat(p->type == 1 ? 2 : 0, 1);  // malloc or calloc count
    inc_stat(4, p->size);                 // bytes_allocd
#ifdef TRACK_THREADS
    update_thread_alloc(p->size);
#endif

    pending.delete(&tid);
    return 0;
}

// ---- customFree entry ----
int free_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 ptr = PT_REGS_PARM1(ctx);
    if (ptr == 0) return 0;

    struct alloc_info_t *info = allocs.lookup(&ptr);
    if (info) {
        inc_stat(5, info->size);  // bytes_freed
#ifdef TRACK_THREADS
        update_thread_free(info->size);
#endif
    }
    allocs.delete(&ptr);
    inc_stat(1, 1);  // free_count
    return 0;
}

// ---- customCalloc entry ----
int calloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct pending_t p = {};
    p.size = PT_REGS_PARM1(ctx) * PT_REGS_PARM2(ctx);
    p.type = 1;
    p.is32 = 0;
    u64 tid = tid_key();
    pending.update(&tid, &p);
    return 0;
}

// ---- customRealloc entry ----
int realloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct pending_t p = {};
    p.old_ptr = PT_REGS_PARM1(ctx);
    p.size = PT_REGS_PARM2(ctx);
    p.type = 2;
    p.is32 = 0;
    u64 tid = tid_key();
    pending.update(&tid, &p);
    return 0;
}

// ---- customRealloc return ----
int realloc_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    struct pending_t *p = pending.lookup(&tid);
    if (!p) return 0;

    u64 new_ptr = PT_REGS_RC(ctx);

    // Remove old allocation
    if (p->old_ptr != 0) {
        struct alloc_info_t *old = allocs.lookup(&p->old_ptr);
        if (old) {
            inc_stat(5, old->size);  // bytes_freed (old)
#ifdef TRACK_THREADS
            update_thread_free(old->size);
#endif
        }
        allocs.delete(&p->old_ptr);
    }

    // Record new allocation
    if (new_ptr != 0) {
        struct alloc_info_t info = {};
        info.size = p->size;
        info.timestamp_ns = bpf_ktime_get_ns();
        info.pid = get_pid();
        info.tid = (u32)tid;
        info.type = 2;
        info.is32 = p->is32;
#ifdef CAPTURE_STACKS
        info.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
#else
        info.stack_id = -1;
#endif
        allocs.update(&new_ptr, &info);
        inc_stat(4, p->size);  // bytes_allocd (new)
#ifdef TRACK_THREADS
        update_thread_alloc(p->size);
#endif
    }
    inc_stat(3, 1);  // realloc_count

    pending.delete(&tid);
    return 0;
}

// ---- 32-bit variants ----
#ifdef TRACK_32BIT
int malloc32_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct pending_t p = {};
    p.size = PT_REGS_PARM1(ctx);
    p.type = 0;
    p.is32 = 1;
    u64 tid = tid_key();
    pending.update(&tid, &p);
    return 0;
}

int free32_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 ptr = PT_REGS_PARM1(ctx);
    if (ptr == 0) return 0;
    struct alloc_info_t *info = allocs.lookup(&ptr);
    if (info) inc_stat(5, info->size);
    allocs.delete(&ptr);
    inc_stat(1, 1);
    return 0;
}

int calloc32_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct pending_t p = {};
    p.size = PT_REGS_PARM1(ctx) * PT_REGS_PARM2(ctx);
    p.type = 1;
    p.is32 = 1;
    u64 tid = tid_key();
    pending.update(&tid, &p);
    return 0;
}

int realloc32_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct pending_t p = {};
    p.old_ptr = PT_REGS_PARM1(ctx);
    p.size = PT_REGS_PARM2(ctx);
    p.type = 2;
    p.is32 = 1;
    u64 tid = tid_key();
    pending.update(&tid, &p);
    return 0;
}
#endif /* TRACK_32BIT */

// ---- InternalMmap / InternalMunmap ----
#ifdef TRACK_MMAP
int mmap_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 length = PT_REGS_PARM2(ctx);
    u64 tid = tid_key();
    mmap_pending.update(&tid, &length);
    return 0;
}

int mmap_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    u64 *length = mmap_pending.lookup(&tid);
    if (!length) return 0;

    u64 addr = PT_REGS_RC(ctx);
    if ((long)addr < 0) {   // MAP_FAILED == (void*)-1
        mmap_pending.delete(&tid);
        return 0;
    }

    struct mmap_info_t info = {};
    info.length = *length;
    info.timestamp_ns = bpf_ktime_get_ns();
    info.pid = get_pid();
    info.tid = (u32)tid;
    mmap_allocs.update(&addr, &info);
    inc_stat(6, 1);

    mmap_pending.delete(&tid);
    return 0;
}

int munmap_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 addr = PT_REGS_PARM1(ctx);
    mmap_allocs.delete(&addr);
    inc_stat(7, 1);
    return 0;
}
#endif /* TRACK_MMAP */

// ---- Thread / process lifecycle probes ----
#ifdef TRACK_THREADS

// my_pthread_create entry — fires in creator thread's context
int thread_create_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_thread_ctr(0, 1);  // created

    struct thread_event_t evt = {};
    evt.tid = (u32)tid_key();
    evt.pid = get_pid();
    evt.x64_fnc = PT_REGS_PARM4(ctx);  // start_routine (parm4: emu,t,attr,start_routine,arg)
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.creator_tid = evt.tid;
    evt.event_type = 4;                 // create_request
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// my_pthread_create return — check success
int thread_create_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 0) {
        // pthread_create failed, undo the count
        int key = 0;
        u64 *v = thread_counters.lookup(&key);
        if (v && *v > 0) __sync_fetch_and_sub(v, 1);
    }
    return 0;
}

// pthread_routine — fires in the NEW thread's context
// void* pthread_routine(void* p)  where p is emuthread_t*
// emuthread_t.fnc is at offset 0
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
    info.creator_tid = 0;  // not easily available here

    active_threads.update(&tid, &info);
    inc_thread_ctr(3, 1);  // current++

    // Update peak if needed
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

// emuthread_destroy — fires when thread exits (TLS destructor)
int thread_destroy_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u32 tid = (u32)tid_key();

    inc_thread_ctr(1, 1);  // destroyed
    // current-- (guard against underflow)
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

// my_fork — count fork requests
int fork_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_thread_ctr(4, 1);  // forks

    struct thread_event_t evt = {};
    evt.tid = (u32)tid_key();
    evt.pid = get_pid();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.creator_tid = evt.tid;
    evt.event_type = 2;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// my_clone — count clone calls
int clone_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_thread_ctr(5, 1);  // clones

    struct thread_event_t evt = {};
    evt.tid = (u32)tid_key();
    evt.pid = get_pid();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.creator_tid = evt.tid;
    evt.event_type = 3;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

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
    evt.event_type = 5;       // clone_return
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

#endif /* TRACK_THREADS */

// ---- Copy-on-Write page fault tracking (kprobe) ----
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
        description="Detect memory leaks in Box64's custom allocator using eBPF uprobes")
    p.add_argument("-b", "--binary", default="/usr/local/bin/box64",
                   help="Path to box64 binary (default: /usr/local/bin/box64)")
    p.add_argument("-p", "--pid", type=int, default=0,
                   help="Filter by PID (default: trace all box64 processes)")
    p.add_argument("-i", "--interval", type=int, default=15,
                   help="Summary interval in seconds (default: 15)")
    p.add_argument("-t", "--top", type=int, default=20,
                   help="Top N outstanding allocations to show (default: 20)")
    p.add_argument("--mmap", action="store_true",
                   help="Also track InternalMmap/InternalMunmap")
    p.add_argument("--stacks", action="store_true",
                   help="Capture user-space stack traces (higher overhead)")
    p.add_argument("--32bit", dest="track32", action="store_true",
                   help="Also track customMalloc32/customFree32 variants")
    p.add_argument("--no-threads", action="store_true",
                   help="Disable thread/process lifecycle tracking")
    p.add_argument("--no-cow", action="store_true",
                   help="Disable Copy-on-Write page fault tracking (kprobe + /proc sampling)")
    p.add_argument("--hash-capacity", type=int, default=524288,
                   help="BPF hash table capacity for tracking outstanding allocations (default: 524288)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    binary = args.binary

    # Validate binary
    check_binary(binary)
    required_syms = ["customMalloc", "customFree", "customCalloc", "customRealloc"]
    if args.mmap:
        required_syms += ["InternalMmap", "InternalMunmap"]
    if args.track32:
        required_syms += ["customMalloc32", "customFree32", "customCalloc32", "customRealloc32"]
    check_symbols(binary, required_syms)

    # Thread tracking: on by default, --no-threads to disable
    track_threads = not args.no_threads
    if track_threads:
        thread_syms = ["my_pthread_create", "pthread_routine", "emuthread_destroy"]
        missing = check_symbols_soft(binary, thread_syms)
        if missing:
            print(f"WARNING: thread symbols not found: {', '.join(missing)}; disabling --threads.")
            track_threads = False
        # fork/clone are optional within --threads
        thread_fork_syms = check_symbols_soft(binary, ["my_fork"])
        thread_clone_syms = check_symbols_soft(binary, ["my_clone"])
        has_fork_sym = not thread_fork_syms
        has_clone_sym = not thread_clone_syms

    # Build cflags
    hash_cap = args.hash_capacity
    cflags = [f"-DHASH_CAPACITY={hash_cap}"]
    if args.pid:
        cflags.append(f"-DFILTER_PID={args.pid}")
    if args.stacks:
        cflags.append("-DCAPTURE_STACKS")
    if args.mmap:
        cflags.append("-DTRACK_MMAP")
    if args.track32:
        cflags.append("-DTRACK_32BIT")
    if track_threads:
        cflags.append("-DTRACK_THREADS")
    track_cow = not args.no_cow
    if track_cow:
        cflags.append("-DTRACK_COW")

    # Clear stale uprobe events and kernel caches to avoid ref_ctr_offset
    # mismatch errors on some kernels (e.g. 16K-page Asahi Linux).
    _clear_stale_uprobes(binary)
    _patch_bcc_uretprobe()

    print(f"[*] Attaching uprobes to {binary} ...")
    b = BPF(text=BPF_PROGRAM, cflags=cflags)

    # Attach probes
    b.attach_uprobe(name=binary, sym="customMalloc", fn_name="malloc_entry")
    b.attach_uretprobe(name=binary, sym="customMalloc", fn_name="malloc_return")
    b.attach_uprobe(name=binary, sym="customFree", fn_name="free_entry")
    b.attach_uprobe(name=binary, sym="customCalloc", fn_name="calloc_entry")
    b.attach_uretprobe(name=binary, sym="customCalloc", fn_name="malloc_return")  # same return handler
    b.attach_uprobe(name=binary, sym="customRealloc", fn_name="realloc_entry")
    b.attach_uretprobe(name=binary, sym="customRealloc", fn_name="realloc_return")

    if args.track32:
        b.attach_uprobe(name=binary, sym="customMalloc32", fn_name="malloc32_entry")
        b.attach_uretprobe(name=binary, sym="customMalloc32", fn_name="malloc_return")
        b.attach_uprobe(name=binary, sym="customFree32", fn_name="free32_entry")
        b.attach_uprobe(name=binary, sym="customCalloc32", fn_name="calloc32_entry")
        b.attach_uretprobe(name=binary, sym="customCalloc32", fn_name="malloc_return")
        b.attach_uprobe(name=binary, sym="customRealloc32", fn_name="realloc32_entry")
        b.attach_uretprobe(name=binary, sym="customRealloc32", fn_name="realloc_return")

    if args.mmap:
        b.attach_uprobe(name=binary, sym="InternalMmap", fn_name="mmap_entry")
        b.attach_uretprobe(name=binary, sym="InternalMmap", fn_name="mmap_return")
        b.attach_uprobe(name=binary, sym="InternalMunmap", fn_name="munmap_entry")

    if track_threads:
        b.attach_uprobe(name=binary, sym="my_pthread_create", fn_name="thread_create_entry")
        b.attach_uretprobe(name=binary, sym="my_pthread_create", fn_name="thread_create_return")
        b.attach_uprobe(name=binary, sym="pthread_routine", fn_name="thread_start_entry")
        b.attach_uprobe(name=binary, sym="emuthread_destroy", fn_name="thread_destroy_entry")
        if has_fork_sym:
            b.attach_uprobe(name=binary, sym="my_fork", fn_name="fork_entry")
        if has_clone_sym:
            b.attach_uprobe(name=binary, sym="my_clone", fn_name="clone_entry")
            b.attach_uretprobe(name=binary, sym="my_clone", fn_name="clone_return")

    # CoW kprobe (optional)
    track_cow_kprobe = False
    if track_cow:
        for kfunc in ("wp_page_copy", "do_wp_page"):
            try:
                b.attach_kprobe(event=kfunc, fn_name="trace_cow_fault")
                track_cow_kprobe = True
                print(f"[*] CoW kprobe attached to {kfunc}")
                break
            except Exception:
                continue
        if not track_cow_kprobe:
            print("WARNING: CoW kprobe unavailable (wp_page_copy/do_wp_page not found). "
                  "Using /proc sampling only.")

    probe_count = 7
    if args.track32:
        probe_count += 7
    if args.mmap:
        probe_count += 3
    if track_threads:
        probe_count += 4 + (1 if has_fork_sym else 0) + (2 if has_clone_sym else 0)
    if track_cow_kprobe:
        probe_count += 1
    pid_str = f" (PID {args.pid})" if args.pid else " (all PIDs)"
    print(f"[*] {probe_count} probes attached{pid_str}. Interval: {args.interval}s. Ctrl+C to stop.")

    # Graceful exit
    exiting = [False]

    def sig_handler(signum, frame):
        exiting[0] = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # Thread event tracking + tree building
    thread_timeline = {}
    create_requests = []     # [(timestamp_ns, creator_tid, pid, x64_fnc)]
    thread_parent = {}       # tid -> creator_tid
    fork_events = []         # [(timestamp_ns, parent_tid, parent_pid)]
    clone_children = {}      # parent_tid -> [child_pid, ...]
    process_children = {}    # parent_pid -> [child_pid, ...]
    fork_cow_data = {}       # parent_pid -> {snapshot_time, parent_smaps, ...}

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

    alloc_types = {0: "malloc", 1: "calloc", 2: "realloc"}

    def read_stats():
        st = b["stats"]
        vals = [st[st.Key(i)].value for i in range(8)]
        return vals

    def print_periodic(vals, prev_vals):
        d = [vals[i] - prev_vals[i] for i in range(8)]
        allocs_table = b["allocs"]
        outstanding = len(allocs_table)
        net_bytes = 0
        for _, info in allocs_table.items():
            net_bytes += info.size

        print(f"\n--- {time.strftime('%H:%M:%S')} --- custom allocator ---")
        print(f"  malloc: {d[0]:>8}   free: {d[1]:>8}   calloc: {d[2]:>8}   realloc: {d[3]:>8}")
        print(f"  bytes allocated: {fmt_size(d[4]):>10}   bytes freed: {fmt_size(d[5]):>10}")
        print(f"  outstanding allocs: {outstanding:>8}   net bytes: {fmt_size(net_bytes):>10}", end="")
        if outstanding >= hash_cap:
            print(f"  *** HASH TABLE FULL ({hash_cap}) — use --hash-capacity ***")
        else:
            print()
        if args.mmap:
            print(f"  mmap: {d[6]:>8}   munmap: {d[7]:>8}   outstanding mmaps: {len(b['mmap_allocs'])}")
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

    def print_final_report(vals):
        print("\n" + "=" * 72)
        print("FINAL REPORT — Outstanding Allocations (potential leaks)")
        print("=" * 72)
        print(f"  Total mallocs:  {vals[0]:>12}")
        print(f"  Total frees:    {vals[1]:>12}")
        print(f"  Total callocs:  {vals[2]:>12}")
        print(f"  Total reallocs: {vals[3]:>12}")
        print(f"  Bytes allocated:{fmt_size(vals[4]):>12}")
        print(f"  Bytes freed:    {fmt_size(vals[5]):>12}")
        if args.mmap:
            print(f"  Total mmaps:    {vals[6]:>12}")
            print(f"  Total munmaps:  {vals[7]:>12}")

        # Collect outstanding allocs sorted by size descending
        allocs_table = b["allocs"]
        items = []
        for k, v in allocs_table.items():
            items.append((k.value, v.size, v.timestamp_ns, v.pid, v.tid,
                          v.type, v.is32, v.stack_id))

        items.sort(key=lambda x: x[1], reverse=True)

        total_outstanding = len(items)
        total_bytes = sum(x[1] for x in items)
        print(f"\n  Outstanding allocations: {total_outstanding}")
        print(f"  Outstanding bytes:       {fmt_size(total_bytes)}")
        if total_outstanding >= hash_cap:
            print(f"  *** WARNING: Hash table was at capacity ({hash_cap}). Leak data may be incomplete.")
            print(f"  *** Re-run with --hash-capacity {hash_cap * 4}")

        if total_outstanding == 0:
            print("\n  No outstanding allocations detected. No leaks!")
            return

        # Size distribution histogram
        buckets = {}
        for item in items:
            sz = item[1]
            if sz == 0:
                bucket = "0"
            else:
                # log2 bucket
                bit = sz.bit_length() - 1
                low = 1 << bit
                high = (1 << (bit + 1)) - 1
                bucket = f"{fmt_size(low)}-{fmt_size(high)}"
            buckets[bucket] = buckets.get(bucket, 0) + 1

        print("\n  Size distribution:")
        for bucket, count in sorted(buckets.items()):
            bar = "#" * min(count, 60)
            print(f"    {bucket:>20s} : {count:>6} {bar}")

        # Top N
        top_n = min(args.top, len(items))
        print(f"\n  Top {top_n} outstanding allocations (by size):")
        print(f"  {'Ptr':>18s}  {'Size':>10s}  {'Age(s)':>8s}  {'Type':>8s}  {'32b':>3s}  {'PID':>7s}  {'TID':>7s}")
        print(f"  {'-'*18}  {'-'*10}  {'-'*8}  {'-'*8}  {'-'*3}  {'-'*7}  {'-'*7}")

        now_ns = time.monotonic_ns()  # approximate; BPF uses ktime
        # We can't easily correlate ktime and wall time, so show relative to oldest
        if items:
            max_ts = max(x[2] for x in items)

        for i in range(top_n):
            ptr, size, ts, pid, tid, atype, is32, stack_id = items[i]
            age_s = (max_ts - ts) / 1e9 if max_ts > ts else 0.0
            type_str = alloc_types.get(atype, "?")
            bit32 = "yes" if is32 else " no"
            print(f"  0x{ptr:016x}  {fmt_size(size):>10s}  {age_s:>8.2f}  {type_str:>8s}  {bit32:>3s}  {pid:>7}  {tid:>7}")

            if args.stacks and stack_id >= 0:
                try:
                    stack = b["stack_traces"].walk(stack_id)
                    for addr in stack:
                        sym = b.sym(addr, pid, show_module=True, show_offset=True)
                        print(f"        {sym}")
                except Exception:
                    pass

        # mmap report
        if args.mmap:
            mmap_allocs = b["mmap_allocs"]
            mmap_items = [(k.value, v.length, v.timestamp_ns, v.pid) for k, v in mmap_allocs.items()]
            mmap_items.sort(key=lambda x: x[1], reverse=True)
            total_mmap_bytes = sum(x[1] for x in mmap_items)
            print(f"\n  Outstanding mmaps: {len(mmap_items)}, total: {fmt_size(total_mmap_bytes)}")
            for i, (addr, length, ts, pid) in enumerate(mmap_items[:10]):
                print(f"    0x{addr:016x}  {fmt_size(length):>10s}  PID {pid}")

        # Thread report
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

            # Collect per-thread stats
            ts_table = b["thread_stats"]
            tid_stats = {}
            for k, v in ts_table.items():
                tid_stats[k.value] = (v.alloc_count, v.alloc_bytes)

            # --- Process/Thread Tree ---
            # Deferred correlation: match create_requests with thread_started
            # events using absolute timestamp proximity.  This handles
            # out-of-order perf buffer delivery across CPUs.
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

            # Discover all non-zero PIDs from thread events
            known_pids = set()
            for tid in all_tids:
                info = thread_timeline.get(tid, {})
                pid = info.get("pid", 0)
                if pid:
                    known_pids.add(pid)

            # Synthesize main thread (TID == PID) if missing from timeline
            for pid in known_pids:
                if pid not in thread_timeline:
                    thread_timeline[pid] = {
                        "x64_fnc": 0, "create_ns": 0,
                        "destroy_ns": None, "pid": pid
                    }
                all_tids.add(pid)

            if all_tids and known_pids:
                # Build children map: threads with a matched parent go under
                # their creator; unmatched threads go under TID==PID (main).
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
                        # Unmatched worker thread — attach to main
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
                    print(f"    PID {pid}")
                    print_subtree(pid, "    ", True, is_main=True)

            # --- Top threads table ---
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

        # --- Copy-on-Write Analysis ---
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
            # Filter to only PIDs seen in our uprobe tracking
            tracked_pids = set(known_pids)
            for k, v in b["allocs"].items():
                tracked_pids.add(v.pid)
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
                    print(f"  {pid:>7}  {faults:>12}  {fmt_size(faults * page_size):>12}")

        print("\n" + "=" * 72)

    # Main loop
    prev_vals = read_stats()
    while not exiting[0]:
        try:
            if track_threads:
                # Poll perf buffer at 1s granularity for thread events
                deadline = time.monotonic() + args.interval
                while time.monotonic() < deadline and not exiting[0]:
                    b.perf_buffer_poll(timeout=1000)
            else:
                time.sleep(args.interval)
        except KeyboardInterrupt:
            exiting[0] = True
            break
        if not exiting[0]:
            vals = read_stats()
            print_periodic(vals, prev_vals)
            prev_vals = vals
            # Sample CoW stats for child processes
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
