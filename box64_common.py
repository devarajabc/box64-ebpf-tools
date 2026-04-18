"""Shared helpers for box64 eBPF tools.

Pure-computation helpers (correlate_thread_parents, compute_cow_deltas,
rank_items), formatters (fmt_size, fmt_ns), binary/symbol validation
(check_binary, _read_symbols, check_symbols_soft), and /proc parsers
(read_smaps_rollup, read_minflt) have no external deps. BPF/BCC
integration helpers (_clear_stale_uprobes, _patch_bcc_uretprobe,
_bcc_has_atomic_increment, _rewrite_atomic_increment) lazy-import
bcc/ctypes/platform inside their bodies so this module can still be
imported on systems without BCC — the tool scripts handle the
missing-BCC case at their own module load with a friendly error.
"""
import os
import re
import subprocess
import sys

try:
    from bcc import BPF
except ImportError:
    BPF = None


# ---------------------------------------------------------------------------
# Pure computation
# ---------------------------------------------------------------------------

def correlate_thread_parents(thread_timeline, create_requests, thread_parent,
                             threshold_ns=5_000_000_000):
    """Match unparented threads to creators via timestamp proximity.

    Mutates thread_parent dict in-place.  Uses a local copy of
    create_requests; the original list is not modified.

    Greedy match in iteration order; does not globally minimize total
    delta.  This is fine for expected cardinality (dozens of threads).
    """
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
        if best_idx is not None and best_delta < threshold_ns:
            _, creator_tid, _, _ = remaining_reqs.pop(best_idx)
            thread_parent[tid] = creator_tid


def compute_cow_deltas(parent_smaps, parent_minflt, child_smaps, child_minflt):
    """Compute CoW deltas between parent and child snapshots.

    Returns: (delta_dirty_bytes, delta_minflt)
    Both values are clamped to >= 0. A negative Private_Dirty or
    minflt delta does not represent a CoW event — it can only arise
    from out-of-order sampling or a child snapshot that predates the
    parent baseline, in which case zero is the correct display value.
    """
    delta_dirty = child_smaps.get("Private_Dirty", 0) - parent_smaps.get("Private_Dirty", 0)
    delta_minflt = child_minflt - parent_minflt
    return (max(0, delta_dirty), max(0, delta_minflt))


def rank_items(items, top_n=20, sort_key_idx=0):
    """Sort items by field at sort_key_idx descending, return top N."""
    sorted_items = sorted(items, key=lambda x: x[sort_key_idx], reverse=True)
    return sorted_items[:top_n]


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def fmt_size(n):
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


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
# Binary / symbol validation
# ---------------------------------------------------------------------------

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


def check_symbols_soft(path, symbols):
    """Check if symbols are present; return list of missing ones (non-fatal)."""
    out = _read_symbols(path)
    if not out:
        return []  # can't verify, assume present
    return [s for s in symbols if s not in out]


# ---------------------------------------------------------------------------
# /proc parsing
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# BCC / kernel workarounds
# ---------------------------------------------------------------------------

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


def _bcc_has_atomic_increment():
    """Probe whether this BCC version supports table.atomic_increment()."""
    if BPF is None:
        return False
    try:
        BPF(text=r"""
            BPF_HISTOGRAM(t, int, 2);
            int test(void *ctx) { int k = 0; t.atomic_increment(k); return 0; }
        """)
        return True
    except Exception:
        return False


def _rewrite_atomic_increment(bpf_text):
    """Replace table.atomic_increment(key) for old BCC versions.

    Old BCC's rewriter can't process BCC map helpers inside C macros,
    so we do the replacement at the Python string level instead.
    """
    def _replace(m):
        table = m.group(1)
        key = m.group(2)
        return (
            f'{{ u64 _ai_zero = 0, *_ai_val = '
            f'{table}.lookup_or_init(&({key}), &_ai_zero); '
            f'if (_ai_val) __sync_fetch_and_add(_ai_val, 1); }}'
        )

    return re.sub(
        r'(\w+)\.atomic_increment\((\w+)\)',
        _replace,
        bpf_text,
    )
