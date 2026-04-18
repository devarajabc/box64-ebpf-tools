"""Shared pure-computation functions used by box64 eBPF tools.

These are extracted from main() to enable unit testing without BPF/root.
"""


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
