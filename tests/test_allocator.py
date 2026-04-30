"""Tests for allocator-tier helpers added in commit 2fa629f.

The custommem.c 3-tier slab structure (map64 / map128 / LIST) is exposed
via per-PID proc_mem_t fields populated by uprobes on the box64 binary.
The CLI Final Report aggregates across PIDs and renders percentages —
that aggregation lives in `_aggregate_tier_breakdown`, which is what we
unit-test here. Real BPF map values can't be created in unit tests, so
we use plain objects (SimpleNamespace) with the same attribute names.
"""
from types import SimpleNamespace

import box64_trace


def _row(tier64=0, tier128=0, aligned=0, aligned_bytes=0,
         stray=0, slab_grow=0):
    """Build a fake proc_mem row with the 6 attrs the helper reads."""
    return SimpleNamespace(
        tier64_count=tier64,
        tier128_count=tier128,
        aligned_count=aligned,
        aligned_bytes=aligned_bytes,
        stray_free_count=stray,
        slab_grow_count=slab_grow,
    )


# ---------------------------------------------------------------------------
# Empty / degenerate inputs
# ---------------------------------------------------------------------------

class TestEmptyInputs:
    def test_no_pids_no_allocs(self):
        # Most degenerate case: tracer just attached, nothing has run yet.
        # All zeros, no division-by-zero crash.
        agg = box64_trace._aggregate_tier_breakdown([], total_alloc=0)
        assert agg["tier64"] == 0
        assert agg["tier128"] == 0
        assert agg["list"] == 0
        assert agg["tier64_pct"] == 0.0
        assert agg["tier128_pct"] == 0.0
        assert agg["list_pct"] == 0.0
        assert agg["aligned_count"] == 0
        assert agg["aligned_bytes"] == 0
        assert agg["stray_free"] == 0
        assert agg["slab_grow"] == 0

    def test_empty_pids_with_total_alloc(self):
        # tracer attached late: stats counter shows allocations happened
        # before any proc_mem entries existed (pre-attach work). The list
        # tier becomes the full total because tier64/tier128 are 0.
        agg = box64_trace._aggregate_tier_breakdown([], total_alloc=100)
        assert agg["tier64"] == 0
        assert agg["tier128"] == 0
        assert agg["list"] == 100
        assert agg["list_pct"] == 100.0
        assert agg["tier64_pct"] == 0.0


# ---------------------------------------------------------------------------
# Tier classification
# ---------------------------------------------------------------------------

class TestTierClassification:
    def test_all_tier64(self):
        # Every allocation in the smallest slab class.
        agg = box64_trace._aggregate_tier_breakdown(
            [_row(tier64=10)], total_alloc=10)
        assert agg["tier64"] == 10
        assert agg["tier128"] == 0
        assert agg["list"] == 0
        assert agg["tier64_pct"] == 100.0
        assert agg["tier128_pct"] == 0.0
        assert agg["list_pct"] == 0.0

    def test_all_tier128(self):
        agg = box64_trace._aggregate_tier_breakdown(
            [_row(tier128=20)], total_alloc=20)
        assert agg["tier128_pct"] == 100.0
        assert agg["tier64_pct"] == 0.0
        assert agg["list_pct"] == 0.0

    def test_all_list(self):
        # No tier64 or tier128 hits → everything fell through to LIST.
        # (Total comes from the global counter, not from per-row data.)
        agg = box64_trace._aggregate_tier_breakdown(
            [_row()], total_alloc=50)
        assert agg["tier64"] == 0
        assert agg["tier128"] == 0
        assert agg["list"] == 50
        assert agg["list_pct"] == 100.0

    def test_balanced_mix(self):
        # 40% slab 64B, 30% slab 128B, 30% LIST — typical pattern.
        agg = box64_trace._aggregate_tier_breakdown(
            [_row(tier64=40, tier128=30)], total_alloc=100)
        assert agg["tier64_pct"] == 40.0
        assert agg["tier128_pct"] == 30.0
        assert agg["list"] == 30
        assert agg["list_pct"] == 30.0


# ---------------------------------------------------------------------------
# Multi-PID summation
# ---------------------------------------------------------------------------

class TestSummation:
    def test_sums_across_pids(self):
        # Aggregating two real-process rows + the parent process row that
        # most allocations actually happen on.
        rows = [
            _row(tier64=100, tier128=50, aligned=5,
                 aligned_bytes=4096, stray=2, slab_grow=1),
            _row(tier64=200, tier128=80, aligned=3,
                 aligned_bytes=2048, stray=0, slab_grow=4),
            _row(),  # idle child, contributes nothing
        ]
        agg = box64_trace._aggregate_tier_breakdown(rows, total_alloc=500)
        assert agg["tier64"] == 300
        assert agg["tier128"] == 130
        assert agg["list"] == 70
        assert agg["aligned_count"] == 8
        assert agg["aligned_bytes"] == 6144
        assert agg["stray_free"] == 2
        assert agg["slab_grow"] == 5

    def test_accepts_generator(self):
        # The CLI passes a generator (lazy iteration over BPF map). The
        # helper must work with non-list iterables.
        gen = (_row(tier64=i) for i in range(5))
        agg = box64_trace._aggregate_tier_breakdown(gen, total_alloc=10)
        assert agg["tier64"] == 0 + 1 + 2 + 3 + 4   # = 10


# ---------------------------------------------------------------------------
# Edge cases — sampling skew between global stats and per-PID counters
# ---------------------------------------------------------------------------

class TestSamplingSkew:
    def test_total_below_tier_sum_clamps_list_to_zero(self):
        # If we read proc_mem before reading the global stats counter,
        # tier64 + tier128 can transiently exceed total_alloc. Without
        # clamping LIST would go negative — we want it to floor at 0.
        agg = box64_trace._aggregate_tier_breakdown(
            [_row(tier64=80, tier128=40)], total_alloc=100)
        assert agg["list"] == 0   # not -20
        assert agg["list_pct"] == 0.0

    def test_total_zero_with_nonzero_tiers(self):
        # Even more pathological: total reads as 0 but per-PID has hits
        # already. Don't divide by zero; report 0% and let the run keep
        # going.
        agg = box64_trace._aggregate_tier_breakdown(
            [_row(tier64=5, tier128=10)], total_alloc=0)
        assert agg["tier64_pct"] == 0.0
        assert agg["tier128_pct"] == 0.0
        assert agg["list_pct"] == 0.0
        # Raw counts are still preserved — the user can spot the skew.
        assert agg["tier64"] == 5
        assert agg["tier128"] == 10


# ---------------------------------------------------------------------------
# Auxiliary counter aggregation
# ---------------------------------------------------------------------------

class TestAuxCounters:
    def test_aligned_bytes_accumulate(self):
        rows = [
            _row(aligned=1, aligned_bytes=64),
            _row(aligned=1, aligned_bytes=128),
            _row(aligned=1, aligned_bytes=256),
        ]
        agg = box64_trace._aggregate_tier_breakdown(rows, total_alloc=0)
        assert agg["aligned_count"] == 3
        assert agg["aligned_bytes"] == 448

    def test_stray_and_slab_grow_independent(self):
        # These are separate signals — make sure we don't accidentally
        # cross-wire them in the aggregation.
        rows = [_row(stray=10, slab_grow=0),
                _row(stray=0,  slab_grow=7)]
        agg = box64_trace._aggregate_tier_breakdown(rows, total_alloc=0)
        assert agg["stray_free"] == 10
        assert agg["slab_grow"] == 7
