"""Tests for correlate_thread_parents() from box64_common."""
from box64_common import correlate_thread_parents


class TestCorrelateThreadParents:
    def test_empty_timeline(self):
        timeline = {}
        requests = []
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {}

    def test_single_match(self):
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
        }
        # (ts, creator_tid, req_pid, req_fnc)
        requests = [(999_999_000, 50, 1, 0xABC)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {100: 50}

    def test_closest_timestamp_wins(self):
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
        }
        requests = [
            (500_000_000, 50, 1, 0xABC),   # 500ms away
            (999_000_000, 60, 1, 0xDEF),   # 1ms away — closer
        ]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {100: 60}

    def test_cross_pid_not_matched(self):
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
        }
        requests = [(999_999_000, 50, 2, 0xABC)]  # different PID
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {}

    def test_pid_zero_skipped(self):
        timeline = {
            100: {"pid": 0, "create_ns": 1_000_000_000},
        }
        requests = [(999_999_000, 50, 0, 0xABC)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {}

    def test_create_ns_zero_skipped(self):
        timeline = {
            100: {"pid": 1, "create_ns": 0},
        }
        requests = [(100, 50, 1, 0xABC)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {}

    def test_at_threshold_rejected(self):
        timeline = {
            100: {"pid": 1, "create_ns": 10_000_000_000},
        }
        # Delta exactly 5s — should be rejected (strictly <)
        requests = [(5_000_000_000, 50, 1, 0xABC)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {}

    def test_consumed_request_not_reused(self):
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
            200: {"pid": 1, "create_ns": 1_000_000_100},
        }
        # Only one request — first match consumes it
        requests = [(999_999_900, 50, 1, 0xABC)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        # One thread matched, the other has no request left
        assert len(parent) == 1

    def test_preexisting_parents_preserved(self):
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
            200: {"pid": 1, "create_ns": 2_000_000_000},
        }
        requests = [(1_999_999_000, 60, 1, 0xDEF)]
        parent = {100: 42}  # pre-existing
        correlate_thread_parents(timeline, requests, parent)
        assert parent[100] == 42  # unchanged
        assert parent[200] == 60  # new match

    def test_original_requests_not_modified(self):
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
        }
        requests = [(999_999_000, 50, 1, 0xABC)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert len(requests) == 1  # original list unchanged
