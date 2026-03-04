#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# box64_dynarec.py — eBPF/BCC uprobe-based DynaRec JIT analysis for Box64.
# Tracks AllocDynarecMap/FreeDynarecMap block churn, lifetimes, sizes,
# and optionally protectDB/unprotectDB/setProtection overhead.
#
# Requires: root, linux >=4.9, python3-bcc (BCC toolkit)
#
# Usage:
#   sudo python3 box64_dynarec.py [-b BINARY] [-p PID] [-i INTERVAL] \
#                                  [--no-prot] [--churn-threshold SECS]

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
    out = _read_symbols(path)
    if not out:
        print("WARNING: 'nm' failed — cannot verify symbols. Continuing anyway.")
        return True
    missing = [s for s in symbols if s not in out]
    if missing:
        return False
    return True


def check_symbols_soft(path, symbols):
    """Check if symbols are present; return list of missing ones (non-fatal)."""
    out = _read_symbols(path)
    if not out:
        return []
    return [s for s in symbols if s not in out]


def check_dynarec_symbols(path):
    """Verify DynaRec symbols exist; fail with clear message if not."""
    required = ["AllocDynarecMap", "FreeDynarecMap"]
    out = _read_symbols(path)
    if not out:
        print("WARNING: 'nm' failed — cannot verify DynaRec symbols.")
        return
    missing = [s for s in required if s not in out]
    if missing:
        print(f"ERROR: DynaRec symbols not found in {path}: {', '.join(missing)}")
        print("Box64 was likely built without DynaRec support.")
        print("Rebuild with a DynaRec option, e.g.: cmake .. -DARM_DYNAREC=ON")
        sys.exit(1)


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


# ---------------------------------------------------------------------------
# BPF C program
# ---------------------------------------------------------------------------

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

// Info stored per outstanding JIT block
struct dynarec_alloc_t {
    u64  x64_addr;      // original x86_64 address
    u64  size;           // allocation size
    u64  alloc_ns;       // timestamp of allocation
    u32  pid;
    u32  tid;
    int  is_new;
};

// Entry probe -> return probe handoff
struct alloc_pending_t {
    u64 x64_addr;
    u64 size;
    int is_new;
};

// Churn event sent to userspace
struct churn_event_t {
    u64 x64_addr;
    u64 alloc_addr;
    u64 size;
    u64 lifetime_ns;
    u32 pid;
};

// Outstanding JIT blocks keyed by alloc address (returned by AllocDynarecMap)
BPF_HASH(jit_blocks, u64, struct dynarec_alloc_t, HASH_CAPACITY);

// TID-keyed pending (entry -> return handoff)
BPF_HASH(alloc_pending, u64, struct alloc_pending_t);

// Histograms
BPF_HISTOGRAM(alloc_sizes, int, 64);
BPF_HISTOGRAM(block_lifetimes, int, 64);

// Stats:
//  [0]=alloc_count, [1]=free_count, [2]=churn_count,
//  [3]=alloc_bytes, [4]=freed_bytes,
//  [5]=protect_count, [6]=unprotect_count, [7]=setprot_count,
//  [8]=protect_bytes, [9]=unprotect_bytes, [10]=setprot_bytes,
//  [11]=outstanding_bytes
BPF_ARRAY(jit_stats, u64, 12);

// Perf output for churn events
BPF_PERF_OUTPUT(churn_events);

static inline u64 tid_key(void) {
    return bpf_get_current_pid_tgid();
}

static inline u32 get_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

static inline void inc_stat(int idx, u64 val) {
    int key = idx;
    u64 *v = jit_stats.lookup(&key);
    if (v) __sync_fetch_and_add(v, val);
}

static inline void dec_stat(int idx, u64 val) {
    int key = idx;
    u64 *v = jit_stats.lookup(&key);
    if (v) __sync_fetch_and_sub(v, val);
}

// log2 for histograms
static inline int log2_u64(u64 v) {
    int r = 0;
    while (v >>= 1) r++;
    return r;
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

// ---- AllocDynarecMap entry ----
// uintptr_t AllocDynarecMap(uintptr_t x64_addr, size_t size, int is_new)
int dynarec_alloc_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    struct alloc_pending_t p = {};
    p.x64_addr = PT_REGS_PARM1(ctx);
    p.size     = PT_REGS_PARM2(ctx);
    p.is_new   = (int)PT_REGS_PARM3(ctx);
    u64 tid = tid_key();
    alloc_pending.update(&tid, &p);
    return 0;
}

// ---- AllocDynarecMap return ----
int dynarec_alloc_return(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 tid = tid_key();
    struct alloc_pending_t *p = alloc_pending.lookup(&tid);
    if (!p) return 0;

    u64 alloc_addr = PT_REGS_RC(ctx);
    if (alloc_addr == 0) {
        alloc_pending.delete(&tid);
        return 0;
    }

    struct dynarec_alloc_t info = {};
    info.x64_addr = p->x64_addr;
    info.size     = p->size;
    info.alloc_ns = bpf_ktime_get_ns();
    info.pid      = get_pid();
    info.tid      = (u32)tid;
    info.is_new   = p->is_new;

    jit_blocks.update(&alloc_addr, &info);

    inc_stat(0, 1);                        // alloc_count
    inc_stat(3, p->size);                  // alloc_bytes
    inc_stat(11, p->size);                 // outstanding_bytes

    // Size histogram
    int bucket = log2_u64(p->size);
    alloc_sizes.atomic_increment(bucket);
#ifdef TRACK_THREADS
    update_thread_alloc(p->size);
#endif

    alloc_pending.delete(&tid);
    return 0;
}

// ---- FreeDynarecMap entry ----
// void FreeDynarecMap(uintptr_t addr)
int dynarec_free_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    u64 addr = PT_REGS_PARM1(ctx);
    if (addr == 0) return 0;

    struct dynarec_alloc_t *info = jit_blocks.lookup(&addr);
    if (!info) {
        inc_stat(1, 1);  // free_count (untracked)
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 lifetime = now - info->alloc_ns;

    inc_stat(1, 1);           // free_count
    inc_stat(4, info->size);  // freed_bytes
    dec_stat(11, info->size); // outstanding_bytes
#ifdef TRACK_THREADS
    update_thread_free(info->size);
#endif

    // Lifetime histogram (log2 of nanoseconds)
    int lt_bucket = log2_u64(lifetime);
    block_lifetimes.atomic_increment(lt_bucket);

    // Churn detection: block freed within threshold
    u64 churn_ns = CHURN_THRESHOLD_NS;
    if (lifetime < churn_ns) {
        inc_stat(2, 1);  // churn_count

        struct churn_event_t evt = {};
        evt.x64_addr    = info->x64_addr;
        evt.alloc_addr  = addr;
        evt.size        = info->size;
        evt.lifetime_ns = lifetime;
        evt.pid         = info->pid;
        churn_events.perf_submit(ctx, &evt, sizeof(evt));
    }

    jit_blocks.delete(&addr);
    return 0;
}

// ---- Protection probes (optional) ----
#ifdef TRACK_PROT

// void protectDB(uintptr_t addr, uintptr_t size)
int protect_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(5, 1);
    u64 size = PT_REGS_PARM2(ctx);
    inc_stat(8, size);
    return 0;
}

// void unprotectDB(uintptr_t addr, size_t size, int mark)
int unprotect_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(6, 1);
    u64 size = PT_REGS_PARM2(ctx);
    inc_stat(9, size);
    return 0;
}

// void setProtection(uintptr_t addr, size_t size, uint32_t prot)
int setprot_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_stat(7, 1);
    u64 size = PT_REGS_PARM2(ctx);
    inc_stat(10, size);
    return 0;
}

#endif /* TRACK_PROT */

// ---- Thread / process lifecycle probes ----
#ifdef TRACK_THREADS

int thread_create_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_thread_ctr(0, 1);

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

    active_threads.update(&tid, &info);
    inc_thread_ctr(3, 1);

    int peak_key = 2, cur_key = 3;
    u64 *peak = thread_counters.lookup(&peak_key);
    u64 *cur = thread_counters.lookup(&cur_key);
    if (peak && cur && *cur > *peak) *peak = *cur;

    struct thread_event_t evt = {};
    evt.tid = tid;
    evt.pid = get_pid();
    evt.x64_fnc = info.start_routine;
    evt.timestamp_ns = info.create_ns;
    evt.event_type = 0;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

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

int fork_entry(struct pt_regs *ctx) {
#ifdef FILTER_PID
    if (get_pid() != FILTER_PID) return 0;
#endif
    inc_thread_ctr(4, 1);
    struct thread_event_t evt = {};
    evt.tid = (u32)tid_key();
    evt.pid = get_pid();
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.creator_tid = evt.tid;
    evt.event_type = 2;
    thread_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

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
        description="Analyze Box64 DynaRec JIT block allocation, churn, and protection overhead using eBPF uprobes")
    p.add_argument("-b", "--binary", default="/usr/local/bin/box64",
                   help="Path to box64 binary (default: /usr/local/bin/box64)")
    p.add_argument("-p", "--pid", type=int, default=0,
                   help="Filter by PID (default: trace all box64 processes)")
    p.add_argument("-i", "--interval", type=int, default=10,
                   help="Summary interval in seconds (default: 10)")
    p.add_argument("--no-prot", action="store_true",
                   help="Skip protection tracking (lower overhead)")
    p.add_argument("--churn-threshold", type=float, default=1.0,
                   help="Blocks freed within N seconds count as churn (default: 1.0)")
    p.add_argument("--no-threads", action="store_true",
                   help="Disable thread/process lifecycle tracking")
    p.add_argument("--no-cow", action="store_true",
                   help="Disable Copy-on-Write page fault tracking (kprobe + /proc sampling)")
    p.add_argument("--hash-capacity", type=int, default=524288,
                   help="BPF hash table capacity for tracking outstanding blocks (default: 524288)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Histogram formatting
# ---------------------------------------------------------------------------

def format_log2_hist(hist_map, val_type="value", section_header=""):
    """Format a BPF log2 histogram from a BPF_HISTOGRAM map."""
    lines = []
    if section_header:
        lines.append(section_header)

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
            # Convert ns bucket boundaries to human-readable
            lines.append(f"    [{fmt_ns(low):>10s}, {fmt_ns(high):>10s}) : {count:>8} {bar}")
        elif val_type == "bytes":
            lines.append(f"    [{fmt_size(low):>10s}, {fmt_size(high):>10s}) : {count:>8} {bar}")
        else:
            lines.append(f"    [{low:>10}, {high:>10}) : {count:>8} {bar}")

    return "\n".join(lines)


def fmt_ns(ns):
    """Human-readable nanosecond duration."""
    if ns < 1000:
        return f"{ns}ns"
    elif ns < 1_000_000:
        return f"{ns/1000:.1f}us"
    elif ns < 1_000_000_000:
        return f"{ns/1_000_000:.1f}ms"
    else:
        return f"{ns/1_000_000_000:.2f}s"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    binary = args.binary

    # Validate
    check_binary(binary)
    check_dynarec_symbols(binary)

    track_prot = not args.no_prot
    if track_prot:
        prot_syms = ["protectDB", "unprotectDB", "setProtection"]
        if not check_symbols(binary, prot_syms):
            print("WARNING: protection symbols not found; disabling --no-prot implicitly.")
            track_prot = False

    # Thread tracking: on by default, --no-threads to disable
    track_threads = not args.no_threads
    if track_threads:
        thread_syms = ["my_pthread_create", "pthread_routine", "emuthread_destroy"]
        missing = check_symbols_soft(binary, thread_syms)
        if missing:
            print(f"WARNING: thread symbols not found: {', '.join(missing)}; disabling --threads.")
            track_threads = False
        thread_fork_syms = check_symbols_soft(binary, ["my_fork"])
        thread_clone_syms = check_symbols_soft(binary, ["my_clone"])
        has_fork_sym = not thread_fork_syms
        has_clone_sym = not thread_clone_syms

    # Build cflags
    hash_cap = args.hash_capacity
    churn_ns = int(args.churn_threshold * 1_000_000_000)
    cflags = [f"-DCHURN_THRESHOLD_NS={churn_ns}ULL", f"-DHASH_CAPACITY={hash_cap}"]
    if args.pid:
        cflags.append(f"-DFILTER_PID={args.pid}")
    if track_prot:
        cflags.append("-DTRACK_PROT")
    if track_threads:
        cflags.append("-DTRACK_THREADS")
    track_cow = not args.no_cow
    if track_cow:
        cflags.append("-DTRACK_COW")

    _clear_stale_uprobes(binary)

    print(f"[*] Attaching uprobes to {binary} ...")
    b = BPF(text=BPF_PROGRAM, cflags=cflags)

    # Core probes
    b.attach_uprobe(name=binary, sym="AllocDynarecMap", fn_name="dynarec_alloc_entry")
    b.attach_uretprobe(name=binary, sym="AllocDynarecMap", fn_name="dynarec_alloc_return")
    b.attach_uprobe(name=binary, sym="FreeDynarecMap", fn_name="dynarec_free_entry")
    probe_count = 3

    # Protection probes
    if track_prot:
        b.attach_uprobe(name=binary, sym="protectDB", fn_name="protect_entry")
        b.attach_uprobe(name=binary, sym="unprotectDB", fn_name="unprotect_entry")
        b.attach_uprobe(name=binary, sym="setProtection", fn_name="setprot_entry")
        probe_count += 3

    # Thread probes
    if track_threads:
        b.attach_uprobe(name=binary, sym="my_pthread_create", fn_name="thread_create_entry")
        b.attach_uretprobe(name=binary, sym="my_pthread_create", fn_name="thread_create_return")
        b.attach_uprobe(name=binary, sym="pthread_routine", fn_name="thread_start_entry")
        b.attach_uprobe(name=binary, sym="emuthread_destroy", fn_name="thread_destroy_entry")
        probe_count += 4
        if has_fork_sym:
            b.attach_uprobe(name=binary, sym="my_fork", fn_name="fork_entry")
            probe_count += 1
        if has_clone_sym:
            b.attach_uprobe(name=binary, sym="my_clone", fn_name="clone_entry")
            b.attach_uretprobe(name=binary, sym="my_clone", fn_name="clone_return")
            probe_count += 2

    # CoW kprobe (optional)
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
    churn_str = f"{args.churn_threshold}s"
    print(f"[*] {probe_count} probes attached{pid_str}. Churn threshold: {churn_str}. Interval: {args.interval}s.")
    print("[*] Ctrl+C to stop and print final report.")

    # Churn event tracking
    churned_x64_addrs = {}  # x64_addr -> count

    def handle_churn_event(cpu, data, size):
        evt = b["churn_events"].event(data)
        addr = evt.x64_addr
        churned_x64_addrs[addr] = churned_x64_addrs.get(addr, 0) + 1

    b["churn_events"].open_perf_buffer(handle_churn_event, page_cnt=64)

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
                # Prune old entries (>10s)
                cutoff = evt.timestamp_ns - 10_000_000_000
                while create_requests and create_requests[0][0] < cutoff:
                    create_requests.pop(0)

            elif evt.event_type == 5:  # clone_return
                child_pid = evt.child_pid
                parent_tid = evt.creator_tid
                clone_children.setdefault(parent_tid, []).append(child_pid)
                process_children.setdefault(evt.pid, []).append(child_pid)

        b["thread_events"].open_perf_buffer(handle_thread_event, page_cnt=16)

    # Graceful exit
    exiting = [False]

    def sig_handler(signum, frame):
        exiting[0] = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    def read_stats():
        st = b["jit_stats"]
        return [st[st.Key(i)].value for i in range(12)]

    def print_periodic(vals, prev_vals):
        d = [vals[i] - prev_vals[i] for i in range(12)]
        outstanding = len(b["jit_blocks"])
        allocs_delta = d[0]
        frees_delta = d[1]
        churn_delta = d[2]
        churn_pct = (churn_delta / frees_delta * 100) if frees_delta > 0 else 0.0

        print(f"\n--- {time.strftime('%H:%M:%S')} --- DynaRec JIT ---")
        print(f"  alloc: {allocs_delta:>8}   free: {frees_delta:>8}   churn: {churn_delta:>8} ({churn_pct:.1f}%)")
        print(f"  bytes allocd: {fmt_size(d[3]):>10}   bytes freed: {fmt_size(d[4]):>10}   outstanding: {fmt_size(vals[11]):>10}")
        print(f"  outstanding blocks: {outstanding}", end="")
        if outstanding >= hash_cap:
            print(f"  *** HASH TABLE FULL (capacity {hash_cap}) — data loss! Use --hash-capacity ***")
        else:
            print()

        if track_prot:
            print(f"  protectDB: {d[5]:>8} ({fmt_size(d[8]):>10})   "
                  f"unprotectDB: {d[6]:>8} ({fmt_size(d[9]):>10})   "
                  f"setProtection: {d[7]:>8} ({fmt_size(d[10]):>10})")
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
        print("\n" + "=" * 76)
        print("FINAL REPORT — DynaRec JIT Analysis")
        print("=" * 76)

        churn_pct = (vals[2] / vals[1] * 100) if vals[1] > 0 else 0.0
        print(f"\n  Totals:")
        print(f"    AllocDynarecMap:  {vals[0]:>12}")
        print(f"    FreeDynarecMap:   {vals[1]:>12}")
        print(f"    Churn (< {args.churn_threshold}s):   {vals[2]:>12}  ({churn_pct:.1f}%)")
        print(f"    Bytes allocated:  {fmt_size(vals[3]):>12}")
        print(f"    Bytes freed:      {fmt_size(vals[4]):>12}")
        print(f"    Outstanding:      {fmt_size(vals[11]):>12}")

        if track_prot:
            print(f"\n  Protection overhead:")
            print(f"    protectDB:      {vals[5]:>10} calls, {fmt_size(vals[8]):>10} cumulative bytes")
            print(f"    unprotectDB:    {vals[6]:>10} calls, {fmt_size(vals[9]):>10} cumulative bytes")
            print(f"    setProtection:  {vals[7]:>10} calls, {fmt_size(vals[10]):>10} cumulative bytes")

        # Allocation size histogram
        print(f"\n  Allocation size distribution:")
        print(format_log2_hist(b["alloc_sizes"], val_type="bytes"))

        # Block lifetime histogram
        print(f"\n  Block lifetime distribution:")
        print(format_log2_hist(b["block_lifetimes"], val_type="ns"))

        # Outstanding blocks
        jit_blocks = b["jit_blocks"]
        outstanding = []
        for k, v in jit_blocks.items():
            outstanding.append((k.value, v.x64_addr, v.size, v.alloc_ns, v.pid, v.is_new))
        outstanding.sort(key=lambda x: x[2], reverse=True)

        print(f"\n  Outstanding JIT blocks: {len(outstanding)}")
        if len(outstanding) >= hash_cap:
            print(f"  *** WARNING: Hash table was at capacity ({hash_cap}). Block tracking, lifetime,")
            print(f"  *** and churn data may be incomplete. Re-run with --hash-capacity {hash_cap * 4}")
        if outstanding:
            top_n = min(20, len(outstanding))
            print(f"  Top {top_n} by size:")
            print(f"  {'AllocAddr':>18s}  {'x64Addr':>18s}  {'Size':>10s}  {'is_new':>6s}  {'PID':>7s}")
            print(f"  {'-'*18}  {'-'*18}  {'-'*10}  {'-'*6}  {'-'*7}")
            for i in range(top_n):
                aaddr, x64, sz, ts, pid, is_new = outstanding[i]
                print(f"  0x{aaddr:016x}  0x{x64:016x}  {fmt_size(sz):>10s}  {is_new:>6}  {pid:>7}")

        # Top churned x64 addresses
        if churned_x64_addrs:
            sorted_churn = sorted(churned_x64_addrs.items(), key=lambda x: x[1], reverse=True)
            top_n = min(20, len(sorted_churn))
            print(f"\n  Top {top_n} churned x64 addresses (most frequently re-compiled):")
            print(f"  {'x64 Address':>18s}  {'Churn Count':>12s}")
            print(f"  {'-'*18}  {'-'*12}")
            for i in range(top_n):
                addr, count = sorted_churn[i]
                print(f"  0x{addr:016x}  {count:>12}")

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

            # --- Top threads table (unchanged) ---
            ts_items = sorted(tid_stats.items(), key=lambda x: x[1][1], reverse=True)
            if ts_items:
                top_n = min(10, len(ts_items))
                print(f"\n  Top {top_n} threads by JIT allocation volume:")
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
            # Also include PIDs from jit_blocks
            for k, v in b["jit_blocks"].items():
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

        print("\n" + "=" * 76)

    # Main loop
    prev_vals = read_stats()
    while not exiting[0]:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            exiting[0] = True
            break

        # Check if interval elapsed (we poll at 1s granularity for churn events)
        if not hasattr(main, '_last_print'):
            main._last_print = time.monotonic()
        now = time.monotonic()
        if now - main._last_print >= args.interval:
            vals = read_stats()
            print_periodic(vals, prev_vals)
            prev_vals = vals
            main._last_print = now
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
