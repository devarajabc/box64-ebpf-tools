"""Dashboard JSON contract tests.

Pins the shape of `/api/snapshot`, `/api/history`, and the SSE event
payloads against what the JS frontend in `web/js/` actually consumes.

These tests are a safety net for refactoring the snapshot pipeline
(currently nested closures inside `box64_trace.py::main()`). They do
NOT verify that the *numbers* are correct — only that the keys, types,
and per-row fields the frontend reads are present and well-typed.
Any regression that would break the rendered dashboard surfaces here.

Source of truth for the contract: grep over `web/js/*.js` for `snap.*`,
`p.*`, `r.x64_addr`, etc. Production code (`web_snapshot()` in
`box64_trace.py`) must produce a value that satisfies these checks;
the test fixture (`_fake_snapshot` in `test_web_dashboard.py`) must
satisfy them too, or it isn't a faithful stand-in.
"""

import http.client
import json
import queue
import re
import socket
import time
from pathlib import Path

import pytest

import box64_web

REPO_ROOT = Path(__file__).resolve().parent.parent
JS_DIR = REPO_ROOT / "web" / "js"


# ---------------------------------------------------------------------------
# Contract derived from web/js/*.js
# ---------------------------------------------------------------------------
TOP_LEVEL_KEYS = {
    "timestamp_ns", "alloc", "jit", "mmap", "process",
    "protection", "threads", "pids", "histograms",
    "top_blocks", "top_churned", "tier_totals",
}

# nested counter buckets — every one of these is read directly by the JS
ALLOC_KEYS = {"malloc", "free", "calloc", "realloc",
              "bytes_allocated", "bytes_freed"}
JIT_KEYS = {"alloc_count", "free_count", "bytes_allocated",
            "bytes_freed", "outstanding_bytes", "outstanding_blocks",
            "churn", "invalidations", "dirty_marks"}
MMAP_KEYS = {"internal_mmap", "internal_munmap",
             "box_mmap", "box_munmap"}
PROCESS_KEYS = {"fork", "vfork", "exec", "posix_spawn",
                "new_context", "free_context", "pressure_vessel"}
PROTECTION_KEYS = {"protectDB_calls", "unprotectDB_calls",
                   "setProtection_calls",
                   "protectDB_bytes", "unprotectDB_bytes",
                   "setProtection_bytes"}
THREADS_KEYS = {"create_entry", "create_return", "start_entry",
                "destroy_entry", "fork_entry", "clone_entry"}

# JS gauges.js::renderPidTable iterates pids[i]; these are the fields it reads
PID_ROW_REQUIRED = {"pid", "label", "jit_bytes", "jit_count",
                    "jit_freed_count", "jit_invalidations",
                    "malloc_bytes", "mmap_bytes",
                    "threads_alive", "context_created",
                    # Allocator tier breakdown (custommem.c 3-tier slab):
                    "tier64_count", "tier128_count",
                    "aligned_count", "aligned_bytes",
                    "stray_free_count", "slab_grow_count"}

# JS gauges.js reads snap.tier_totals.{tier64_pct, tier128_pct, list_pct,
# aligned_count, stray_free, slab_grow}. The backend aggregates across the
# full proc_mem map (not the truncated pids[] list) so percentages don't skew.
TIER_TOTALS_REQUIRED = {"tier64", "tier128", "list",
                        "tier64_pct", "tier128_pct", "list_pct",
                        "aligned_count", "aligned_bytes",
                        "stray_free", "slab_grow"}

# JS gauges.js::renderTopBlocks
TOP_BLOCK_ROW_REQUIRED = {"x64_addr", "alloc_addr", "size", "pid"}

# JS gauges.js::renderChurnTable
TOP_CHURN_ROW_REQUIRED = {"x64_addr", "count"}

HISTOGRAM_KEYS = {"alloc_sizes", "block_lifetimes"}


# ---------------------------------------------------------------------------
# Shape assertions
# ---------------------------------------------------------------------------
def _assert_counter_bucket(snap, name, required):
    assert name in snap, f"missing top-level key {name!r}"
    bucket = snap[name]
    assert isinstance(bucket, dict), \
        f"{name!r} must be a dict, got {type(bucket).__name__}"
    missing = required - set(bucket)
    assert not missing, f"{name!r} missing keys: {sorted(missing)}"
    for k, v in bucket.items():
        assert isinstance(v, (int, float)), \
            f"{name}.{k} must be numeric, got {type(v).__name__}"


def _assert_dashboard_snapshot(snap):
    """Comprehensive shape check matching the JS frontend's expectations."""
    assert isinstance(snap, dict), \
        f"snapshot must be a dict, got {type(snap).__name__}"

    missing = TOP_LEVEL_KEYS - set(snap)
    assert not missing, f"snapshot missing keys: {sorted(missing)}"

    assert isinstance(snap["timestamp_ns"], int)

    _assert_counter_bucket(snap, "alloc", ALLOC_KEYS)
    _assert_counter_bucket(snap, "jit", JIT_KEYS)
    _assert_counter_bucket(snap, "mmap", MMAP_KEYS)
    _assert_counter_bucket(snap, "process", PROCESS_KEYS)
    _assert_counter_bucket(snap, "protection", PROTECTION_KEYS)
    _assert_counter_bucket(snap, "threads", THREADS_KEYS)

    # `pids` is a list — JS does pids[i] / pids.length. A dict here would
    # render an empty table at best and crash some browsers at worst.
    pids = snap["pids"]
    assert isinstance(pids, list), \
        f"pids must be a list (JS uses .length / [i]), got {type(pids).__name__}"
    for i, row in enumerate(pids):
        assert isinstance(row, dict), f"pids[{i}] must be a dict"
        missing = PID_ROW_REQUIRED - set(row)
        assert not missing, f"pids[{i}] missing keys: {sorted(missing)}"
        assert isinstance(row["pid"], int), f"pids[{i}].pid must be int"
        assert isinstance(row["label"], str), f"pids[{i}].label must be str"

    # tier_totals: aggregated across the FULL proc_mem map. The frontend
    # reads percentages from here directly; without it the dashboard's
    # tier-mix panel can't render correctly when there are >32 PIDs.
    tier_totals = snap["tier_totals"]
    assert isinstance(tier_totals, dict), "tier_totals must be a dict"
    missing = TIER_TOTALS_REQUIRED - set(tier_totals)
    assert not missing, f"tier_totals missing keys: {sorted(missing)}"

    # histograms: dict keyed by HISTOGRAM_KEYS, values are dicts of bucket->count
    histograms = snap["histograms"]
    assert isinstance(histograms, dict), "histograms must be a dict"
    missing = HISTOGRAM_KEYS - set(histograms)
    assert not missing, f"histograms missing keys: {sorted(missing)}"
    for hname, hist in histograms.items():
        assert isinstance(hist, dict), \
            f"histograms.{hname} must be a dict, got {type(hist).__name__}"

    # top_blocks: list of {x64_addr, alloc_addr, size, pid}
    tops = snap["top_blocks"]
    assert isinstance(tops, list), "top_blocks must be a list"
    for i, row in enumerate(tops):
        missing = TOP_BLOCK_ROW_REQUIRED - set(row)
        assert not missing, f"top_blocks[{i}] missing keys: {sorted(missing)}"
        # x64_addr is rendered with .toString(16) — must be int-like
        assert isinstance(row["x64_addr"], int)
        assert isinstance(row["alloc_addr"], int)

    # top_churned: list of {x64_addr, count}
    churned = snap["top_churned"]
    assert isinstance(churned, list), "top_churned must be a list"
    for i, row in enumerate(churned):
        missing = TOP_CHURN_ROW_REQUIRED - set(row)
        assert not missing, f"top_churned[{i}] missing keys: {sorted(missing)}"
        assert isinstance(row["x64_addr"], int)
        assert isinstance(row["count"], int)


# ---------------------------------------------------------------------------
# Test fixtures — synthesized contract-compliant data
# ---------------------------------------------------------------------------
def _good_snapshot():
    """A snapshot value that satisfies the contract on the dot."""
    return {
        "timestamp_ns": time.monotonic_ns(),
        "alloc": {"malloc": 1, "free": 1, "calloc": 0, "realloc": 0,
                  "bytes_allocated": 64, "bytes_freed": 32},
        "jit": {"alloc_count": 1, "free_count": 0,
                "bytes_allocated": 4096, "bytes_freed": 0,
                "outstanding_bytes": 4096, "outstanding_blocks": 1,
                "churn": 0, "invalidations": 0, "dirty_marks": 0},
        "mmap": {"internal_mmap": 0, "internal_munmap": 0,
                 "box_mmap": 0, "box_munmap": 0},
        "process": {"fork": 0, "vfork": 0, "exec": 0, "posix_spawn": 0,
                    "new_context": 1, "free_context": 0,
                    "pressure_vessel": 0},
        "protection": {"protectDB_calls": 0, "unprotectDB_calls": 0,
                       "setProtection_calls": 0,
                       "protectDB_bytes": 0, "unprotectDB_bytes": 0,
                       "setProtection_bytes": 0},
        "threads": {"create_entry": 0, "create_return": 0,
                    "start_entry": 0, "destroy_entry": 0,
                    "fork_entry": 0, "clone_entry": 0},
        "pids": [{"pid": 4242, "label": "box64",
                  "jit_bytes": 4096, "jit_count": 1,
                  "jit_freed_count": 0, "jit_invalidations": 0,
                  "malloc_bytes": 32, "mmap_bytes": 0,
                  "threads_alive": 1, "context_created": 1,
                  "tier64_count": 0, "tier128_count": 0,
                  "aligned_count": 0, "aligned_bytes": 0,
                  "stray_free_count": 0, "slab_grow_count": 0}],
        "tier_totals": {"tier64": 0, "tier128": 0, "list": 0,
                        "tier64_pct": 0.0, "tier128_pct": 0.0, "list_pct": 0.0,
                        "aligned_count": 0, "aligned_bytes": 0,
                        "stray_free": 0, "slab_grow": 0},
        "histograms": {"alloc_sizes": {}, "block_lifetimes": {}},
        "top_blocks": [{"x64_addr": 0x401000, "alloc_addr": 0x7f0000000,
                        "size": 4096, "pid": 4242}],
        "top_churned": [{"x64_addr": 0x401000, "count": 3}],
    }


def _good_stats():
    return {"binary": "/usr/local/bin/box64", "guest": "box64",
            "filter_pid": 0, "interval": 1,
            "track": {"mem": True, "dynarec": True, "mmap": True}}


def _free_port():
    # Bind on port 0 so we hand off the bound socket directly — no TOCTOU
    # window between picking and using.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def dashboard():
    port = _free_port()
    server = box64_web.start(port, _good_snapshot, _good_stats,
                             browser_pref="none")
    try:
        yield port
    finally:
        box64_web.shutdown(server)


@pytest.fixture(autouse=True)
def _reset_state():
    """Clear shared state — these tests run alongside other suites that
    mutate _state (history, events, sse_clients, event_seq)."""
    with box64_web._state["lock"]:
        box64_web._state["history"].clear()
        box64_web._state["events"].clear()
        box64_web._state["sse_clients"].clear()
        box64_web._state["event_seq"] = 0
    yield
    with box64_web._state["lock"]:
        box64_web._state["history"].clear()
        box64_web._state["events"].clear()
        box64_web._state["sse_clients"].clear()
        box64_web._state["event_seq"] = 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestSnapshotContract:
    def test_test_web_dashboard_fake_snapshot_is_contract_compliant(self):
        """The _fake_snapshot fixture used by test_web_dashboard.py must
        also satisfy the contract — otherwise those tests verify an
        invalid shape that production never produces. (Earlier the
        fixture had pids={123:{...}}; JS does pids[i] / pids.length.)"""
        from tests.test_web_dashboard import _fake_snapshot
        _assert_dashboard_snapshot(_fake_snapshot())

    def test_api_snapshot_endpoint_returns_contract_compliant_json(
            self, dashboard):
        port = dashboard
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/api/snapshot")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        assert resp.status == 200
        snap = json.loads(body)
        _assert_dashboard_snapshot(snap)

    def test_js_only_reads_known_top_level_snapshot_keys(self):
        """Every `snap.X` access in web/js/*.js must be a key our Python
        contract emits. Catches the case where JS adds a new top-level
        key but Python doesn't produce it (renders blank / undefined in
        the dashboard with no Python-side test failure)."""
        pattern = re.compile(r"\bsnap\.([A-Za-z_][A-Za-z0-9_]*)\b")
        used = set()
        for js in sorted(JS_DIR.glob("*.js")):
            if js.name == "chart.umd.min.js":
                continue   # vendored Chart.js
            for m in pattern.finditer(js.read_text()):
                used.add(m.group(1))

        assert used, "no `snap.X` accesses found in web/js/ — grep regression?"
        unknown = used - TOP_LEVEL_KEYS
        assert not unknown, (
            f"JS reads snap keys not in the Python contract: "
            f"{sorted(unknown)}. Either Python web_snapshot() needs to "
            f"emit them, or JS is reading keys that no longer exist."
        )


class TestHistoryShape:
    def test_history_entries_match_snapshot_contract(self, dashboard):
        port = dashboard
        # Force at least one entry into history regardless of background
        # poll timing — the loop appends once every history_interval.
        with box64_web._state["lock"]:
            box64_web._state["history"].append(_good_snapshot())

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/api/history")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        assert resp.status == 200

        # JS polling.js reads `data.snapshots` and iterates it.
        wrapped = json.loads(body)
        assert isinstance(wrapped, dict), \
            "history must be wrapped in an object with `snapshots` key"
        assert "snapshots" in wrapped, \
            "history response missing `snapshots` key (JS reads data.snapshots)"
        history = wrapped["snapshots"]
        assert isinstance(history, list)
        assert history, "history endpoint returned no entries"
        for i, entry in enumerate(history):
            try:
                _assert_dashboard_snapshot(entry)
            except AssertionError as e:
                pytest.fail(f"history.snapshots[{i}] violates contract: {e}")


class TestEmitEventInvariants:
    def test_event_seq_monotonic_across_emits(self):
        seqs = []
        for i in range(20):
            box64_web.emit_event("process",
                                 {"action": "fork", "pid": 1000 + i})
            with box64_web._state["lock"]:
                seqs.append(box64_web._state["event_seq"])
        assert seqs == sorted(seqs)
        assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))

    def test_emitted_event_has_required_fields(self):
        box64_web.emit_event("process", {"action": "fork", "pid": 7})
        with box64_web._state["lock"]:
            evts = list(box64_web._state["events"])
        assert evts, "emit_event did not record into _state['events']"
        evt = evts[-1]
        assert {"seq", "type", "data", "ts_ns"} <= set(evt)
        assert isinstance(evt["seq"], int)
        assert isinstance(evt["type"], str)
        assert isinstance(evt["data"], dict)
        assert isinstance(evt["ts_ns"], int)

    def test_event_round_trips_to_subscriber_as_sse_block(self):
        """SSE wire format: emit_event must reach a subscriber as a
        parseable `event:` / `data:` block whose data round-trips."""
        event_type = "process"
        data = {"action": "exec", "pid": 7, "path": "/bin/sh"}
        q = queue.Queue(maxsize=8)
        with box64_web._state["lock"]:
            box64_web._state["sse_clients"].append(q)
        try:
            box64_web.emit_event(event_type, data)
            payload = q.get(timeout=1.0).decode("utf-8")
        finally:
            with box64_web._state["lock"]:
                if q in box64_web._state["sse_clients"]:
                    box64_web._state["sse_clients"].remove(q)

        assert payload.startswith(f"event: {event_type}\n")
        for line in payload.splitlines():
            if line.startswith("data: "):
                assert json.loads(line[len("data: "):]) == data
                break
        else:
            pytest.fail(f"no data: line in SSE payload:\n{payload!r}")
