"""Tests for the live JIT block-age histogram helper.

Box64's JIT cache eviction policy (PurgeDynarecMap, custommem.c:1622) is
LRU-with-age-threshold: blocks older than `dynarec_purge_age` ticks AND
not currently in use are eviction candidates. Tuning the threshold needs
to know the AGE DISTRIBUTION of currently-resident blocks — most of them
recent (working set) or stale (cold)?

We already record `alloc_ns` per block in the `jit_blocks` BPF map (set
in jit_alloc_return). `_compute_block_age_histogram(jit_blocks_iter,
now_ns)` walks that map and bucketizes `now_ns - alloc_ns` into log2
nanosecond buckets, returning the same shape as `_hist_snapshot` so the
existing renderHist/_fmtNsRange JS path works without changes.
"""
from types import SimpleNamespace

import box64_trace


def _block(alloc_ns):
    """Build a fake jit_blocks row exposing the one attribute we need."""
    return SimpleNamespace(alloc_ns=alloc_ns)


# ---------------------------------------------------------------------------
# Empty / single-block inputs
# ---------------------------------------------------------------------------

class TestEmpty:
    def test_empty_iter_returns_empty_list(self):
        # No live blocks → no buckets to render. Match the empty-state
        # convention of _hist_snapshot ([], not None).
        assert box64_trace._compute_block_age_histogram([], now_ns=0) == []


class TestSingleBlock:
    def test_one_block_one_bucket(self):
        # Block allocated 1024ns ago: log2(1024) = 10. One entry, count 1.
        hist = box64_trace._compute_block_age_histogram(
            [_block(alloc_ns=0)], now_ns=1024)
        assert hist == [{"bucket": 10, "count": 1}]

    def test_age_zero_lands_in_bucket_zero(self):
        # Block allocated AT now_ns (age = 0): we'd otherwise call
        # log2(0) which is undefined. Helper must clamp age = 0 → bucket 0
        # so a freshly-allocated block doesn't crash the histogram.
        hist = box64_trace._compute_block_age_histogram(
            [_block(alloc_ns=500)], now_ns=500)
        assert hist == [{"bucket": 0, "count": 1}]

    def test_age_one_lands_in_bucket_zero(self):
        # log2(1) = 0. Edge of the bucket-0 range.
        hist = box64_trace._compute_block_age_histogram(
            [_block(alloc_ns=499)], now_ns=500)
        assert hist == [{"bucket": 0, "count": 1}]


# ---------------------------------------------------------------------------
# Bucketing
# ---------------------------------------------------------------------------

class TestBucketing:
    def test_blocks_in_same_log2_bucket_aggregate(self):
        # Ages 100, 150, 200 all fall in log2 bucket 6 (64..127) or 7
        # (128..255). 100 → log2=6, 150 → log2=7, 200 → log2=7. Two
        # blocks in bucket 7, one in bucket 6.
        blocks = [_block(alloc_ns=now - age) for now, age
                  in [(1000, 100), (1000, 150), (1000, 200)]]
        hist = box64_trace._compute_block_age_histogram(blocks, now_ns=1000)
        # Result is sorted by bucket ascending.
        assert hist == [{"bucket": 6, "count": 1},
                        {"bucket": 7, "count": 2}]

    def test_buckets_sorted_ascending(self):
        # Build blocks across 4 distinct buckets, in random order.
        # Output must come back sorted by bucket so the frontend can
        # render bars left-to-right without re-sorting.
        ages = [1, 1024, 16, 1048576]   # buckets 0, 10, 4, 20
        blocks = [_block(alloc_ns=10**9 - a) for a in ages]
        hist = box64_trace._compute_block_age_histogram(blocks, now_ns=10**9)
        buckets = [r["bucket"] for r in hist]
        assert buckets == sorted(buckets)
        assert buckets == [0, 4, 10, 20]


# ---------------------------------------------------------------------------
# Sampling skew — wider edge cases
# ---------------------------------------------------------------------------

class TestSamplingSkew:
    def test_alloc_after_now_clamps_to_zero(self):
        # bpf_ktime_get_ns sampled in user space and BPF can drift; if we
        # ever read alloc_ns > now_ns (e.g. now_ns sampled before the BPF
        # write was visible), the helper must clamp age to 0 rather than
        # producing a negative bucket or crashing.
        hist = box64_trace._compute_block_age_histogram(
            [_block(alloc_ns=10_000)], now_ns=5_000)
        assert hist == [{"bucket": 0, "count": 1}]

    def test_accepts_generator(self):
        # web_snapshot passes a generator (lazy iter over the BPF map);
        # the helper must handle non-list iterables.
        gen = (_block(alloc_ns=i * 1000) for i in range(3))
        hist = box64_trace._compute_block_age_histogram(gen, now_ns=4000)
        # Total count across all buckets equals input length.
        assert sum(r["count"] for r in hist) == 3


# ---------------------------------------------------------------------------
# Realistic distribution
# ---------------------------------------------------------------------------

class TestRealisticDistribution:
    def test_typical_unity_workload_shape(self):
        # Simulate a Unity-shaped distribution: a tail of recently-allocated
        # blocks (working set) plus a long-lived contingent. The histogram
        # should preserve both — that's exactly what an eviction-policy
        # tuner needs to see.
        now = 10**12  # 1000s
        recent = [_block(alloc_ns=now - 1_000_000) for _ in range(50)]   # ~1ms old
        midage = [_block(alloc_ns=now - 100_000_000) for _ in range(20)] # ~100ms
        old    = [_block(alloc_ns=now - 60_000_000_000) for _ in range(5)] # ~60s

        hist = box64_trace._compute_block_age_histogram(
            recent + midage + old, now_ns=now)

        # Three distinct buckets, well separated. Total preserves count.
        assert sum(r["count"] for r in hist) == 75
        assert len(hist) == 3
        # Most populated bucket should be the recent one.
        top_bucket = max(hist, key=lambda r: r["count"])
        assert top_bucket["count"] == 50
