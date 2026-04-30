"""Tests for the dynablock-extras aggregation helper.

Bundle A ("JIT under pressure") + Bundle B ("range invalidation") share a
single aggregation function `_aggregate_dynablock_extras(pm_iter)` that
sums six per-PID counters across the proc_mem map:

  Bundle A — JIT pressure (alloc-side):
    jit_purge       ← PurgeDynarecMap calls (cache evictions; only
                       fires when AllocDynarecMap can't find space)
    jit_cancel      ← CancelBlock64 calls (codegen aborted mid-build)
    box32_grow      ← box32_dynarec_mmap calls (32-bit address-space
                       provider used by ALL slab tiers + JIT mmaplist)

  Bundle B — Range invalidation (free/invalidate-side):
    range_inval     ← MarkRangeDynablock (bulk-invalidate over guest
                       address range, e.g. mprotect / library unload)
    range_free      ← FreeRangeDynablock (bulk-free over a range)
    dbswap_invalid  ← DBSwapInvalid (recompile path: invalid block
                       being rebuilt)

Helper takes any iterable yielding objects with the matching `*_count`
attribute names so unit tests can pass plain SimpleNamespace rows
without needing a live BPF map.
"""
from types import SimpleNamespace

import box64_trace


def _row(jit_purge=0, jit_cancel=0, box32_grow=0,
         range_inval=0, range_free=0, dbswap_invalid=0):
    """Build a fake proc_mem row with the 6 attrs the helper reads.

    Names mirror the proc_mem_t field names exactly so the test mocks
    match the production read-path.
    """
    return SimpleNamespace(
        jit_purge_count=jit_purge,
        jit_cancel_count=jit_cancel,
        box32_dynarec_count=box32_grow,
        range_invalidate_count=range_inval,
        range_free_count=range_free,
        dbswap_invalid_count=dbswap_invalid,
    )


# ---------------------------------------------------------------------------
# Empty / single-PID inputs
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_iter_returns_all_zeros(self):
        # Tracer just attached, nothing has happened yet — every counter
        # is zero, no exceptions, no division anywhere (these aren't
        # percentages, just raw counts).
        agg = box64_trace._aggregate_dynablock_extras([])
        assert agg == {
            "jit_purge": 0,
            "jit_cancel": 0,
            "box32_grow": 0,
            "range_inval": 0,
            "range_free": 0,
            "dbswap_invalid": 0,
        }


class TestSinglePid:
    def test_only_jit_purge(self):
        # Pure Bundle A signal: JIT cache evicting blocks but no
        # codegen aborts and no 32-bit pressure.
        agg = box64_trace._aggregate_dynablock_extras([_row(jit_purge=42)])
        assert agg["jit_purge"] == 42
        assert agg["jit_cancel"] == 0
        assert agg["box32_grow"] == 0
        # Bundle B counters untouched.
        assert agg["range_inval"] == 0
        assert agg["range_free"] == 0
        assert agg["dbswap_invalid"] == 0

    def test_only_jit_cancel(self):
        # Codegen aborts but no eviction — usually means the JIT is
        # bailing on specific block patterns (e.g. instructions it
        # can't translate) rather than running out of cache space.
        agg = box64_trace._aggregate_dynablock_extras([_row(jit_cancel=7)])
        assert agg["jit_cancel"] == 7
        assert agg["jit_purge"] == 0

    def test_only_box32_grow(self):
        # 32-bit guest workload pulling fresh backing regions for slab
        # / JIT — only meaningful when running a 32-bit guest.
        agg = box64_trace._aggregate_dynablock_extras([_row(box32_grow=3)])
        assert agg["box32_grow"] == 3

    def test_only_range_invalidate(self):
        # Pure Bundle B signal: guest mprotected a range or unloaded
        # a library, mass-invalidating blocks.
        agg = box64_trace._aggregate_dynablock_extras(
            [_row(range_inval=15)])
        assert agg["range_inval"] == 15
        assert agg["range_free"] == 0
        assert agg["dbswap_invalid"] == 0

    def test_only_range_free(self):
        agg = box64_trace._aggregate_dynablock_extras(
            [_row(range_free=20)])
        assert agg["range_free"] == 20

    def test_only_dbswap_invalid(self):
        # Recompile path: blocks were invalidated and now being
        # rebuilt. High counts ⇒ heavy self-modifying-code workload.
        agg = box64_trace._aggregate_dynablock_extras(
            [_row(dbswap_invalid=100)])
        assert agg["dbswap_invalid"] == 100


# ---------------------------------------------------------------------------
# Multi-PID summation
# ---------------------------------------------------------------------------

class TestSummation:
    def test_sums_across_pids(self):
        # Three rows all populated. Each counter sums independently —
        # this is the test that catches accidental cross-wiring (e.g.
        # tallying jit_purge into jit_cancel).
        rows = [
            _row(jit_purge=10, jit_cancel=2, box32_grow=1,
                 range_inval=5,  range_free=3, dbswap_invalid=20),
            _row(jit_purge=5,  jit_cancel=1, box32_grow=2,
                 range_inval=10, range_free=6, dbswap_invalid=30),
            _row(jit_purge=0,  jit_cancel=0, box32_grow=4,
                 range_inval=0,  range_free=0, dbswap_invalid=0),
        ]
        agg = box64_trace._aggregate_dynablock_extras(rows)
        assert agg["jit_purge"]      == 15
        assert agg["jit_cancel"]     == 3
        assert agg["box32_grow"]     == 7
        assert agg["range_inval"]    == 15
        assert agg["range_free"]     == 9
        assert agg["dbswap_invalid"] == 50

    def test_accepts_generator(self):
        # web_snapshot passes a generator (lazy iteration over the BPF
        # map) — same pattern as _aggregate_tier_breakdown. Helper must
        # handle non-list iterables.
        gen = (_row(jit_purge=i) for i in range(5))
        agg = box64_trace._aggregate_dynablock_extras(gen)
        assert agg["jit_purge"] == 0 + 1 + 2 + 3 + 4   # = 10

    def test_idle_rows_contribute_zero(self):
        # Mixing real-process rows with idle children (typical Mono/
        # Unity pattern). Idle rows contribute 0 to every counter
        # without affecting the others.
        rows = [_row(jit_purge=50)] + [_row() for _ in range(20)]
        agg = box64_trace._aggregate_dynablock_extras(rows)
        assert agg["jit_purge"] == 50


# ---------------------------------------------------------------------------
# Counter independence — guards against cross-wiring bugs
# ---------------------------------------------------------------------------

class TestCounterIndependence:
    def test_each_field_is_isolated(self):
        # For each of the 6 counters, build a row with ONLY that
        # counter set. The aggregate must show that counter at the
        # expected value and every other counter at zero. Catches
        # off-by-one assignment bugs in the helper.
        for field, expected_key in [
            ("jit_purge",       "jit_purge"),
            ("jit_cancel",      "jit_cancel"),
            ("box32_grow",      "box32_grow"),
            ("range_inval",     "range_inval"),
            ("range_free",      "range_free"),
            ("dbswap_invalid",  "dbswap_invalid"),
        ]:
            row = _row(**{field: 99})
            agg = box64_trace._aggregate_dynablock_extras([row])
            assert agg[expected_key] == 99, (
                f"setting {field}=99 didn't reach agg[{expected_key!r}]")
            for k, v in agg.items():
                if k != expected_key:
                    assert v == 0, (
                        f"setting only {field} leaked into agg[{k!r}]={v}")
