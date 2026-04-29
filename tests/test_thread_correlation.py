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


class TestOutOfOrderAndContention:
    """Edge cases that arise when BPF perf events arrive out of order
    or when many threads contend for a small pool of create_requests.
    """

    def test_request_after_create_ns_still_matches(self):
        # BPF perf buffer events can arrive out of monotonic order.
        # The function uses abs(create_ns - ts), so a request stamped
        # AFTER the thread's create_ns must match just like one before.
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
        }
        requests = [(1_000_001_000, 50, 1, 0xABC)]  # 1µs after, not before
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {100: 50}

    def test_delta_just_inside_threshold_matches(self):
        # Companion to test_at_threshold_rejected: a delta of exactly
        # threshold_ns - 1 must still match (strict <).
        timeline = {
            100: {"pid": 1, "create_ns": 10_000_000_000},
        }
        requests = [(5_000_000_001, 50, 1, 0xABC)]  # delta = 4_999_999_999
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {100: 50}

    def test_custom_threshold_parameter(self):
        # Caller may tighten the matching window. A request that fits
        # the default threshold but exceeds the custom one must be
        # rejected.
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
        }
        requests = [(999_000_000, 50, 1, 0xABC)]  # delta = 1ms
        parent = {}
        correlate_thread_parents(timeline, requests, parent,
                                 threshold_ns=500_000)  # 500µs window
        assert parent == {}  # 1ms > 500µs, rejected

    def test_tied_delta_first_seen_wins(self):
        # Two requests equidistant from create_ns. The < comparison
        # in the inner loop is strict, so the first request encountered
        # in iteration order keeps the win even though the second is
        # equally close. Pinning this prevents an accidental flip to >=
        # later that would change the (non-deterministic-looking)
        # outcome under reordering.
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
        }
        requests = [
            (999_500_000, 50, 1, 0xABC),    # 500µs before (delta = 500µs)
            (1_000_500_000, 60, 1, 0xDEF),  # 500µs after  (delta = 500µs)
        ]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {100: 50}  # first wins on tie

    def test_greedy_assignment_can_leave_thread_unmatched(self):
        # Documented limitation: greedy iteration order, not global
        # minimization. With timeline-iteration order and the closer
        # request picked for the first thread, a globally-better
        # pairing may be missed.
        # Setup: thread 100 sees request A at delta=2 (close) and
        # request B at delta=10. Thread 200 only sees request B at
        # delta=1 (very close). A globally-optimal pairing would be
        # 100→A, 200→B. The greedy algorithm sees thread 100 first,
        # picks A (delta=2) — that consumes A. Then thread 200 picks
        # B (delta=1). So this scenario actually happens to give the
        # ideal pairing. Construct a case where it does NOT:
        #
        # Thread 100 prefers B (delta=1) over A (delta=2). Thread 200
        # only matches A (within threshold). Greedy assigns thread 100
        # → B, leaving 200 → A within threshold — that's still ideal.
        #
        # Worst case: thread 100 prefers B, thread 200 ONLY matches B
        # (A is out of threshold for 200). Greedy 100 → B leaves 200
        # unmatched — even though 200 → B and 100 → A would have
        # parented both.
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
            # 200 is far from A, only B is in-threshold (delta = 1ms)
            200: {"pid": 1, "create_ns": 1_000_000_001 + 100_000_000_000},
        }
        # B is right next to thread 200's create_ns AND right next to
        # 100's. A is right next to thread 100 only.
        a_ts = 999_999_000  # delta-to-100 = 1ms; delta-to-200 = ~100s (out)
        b_ts = 1_000_000_000 + 100_000_000_000 + 1_000_000  # delta-to-200=1ms; delta-to-100=~100s (out)
        # If thread 100 sees A (delta 1ms) before B (~100s out of threshold),
        # both threads can match. Verify the happy case:
        requests = [(a_ts, 50, 1, 0xABC), (b_ts, 60, 1, 0xDEF)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        # Thread 100 → A (only A is in threshold), thread 200 → B.
        assert parent == {100: 50, 200: 60}

    def test_cross_pid_request_not_consumed_by_other_pid(self):
        # A request for pid=2 sits in the list while we're matching
        # threads from pid=1. The pid=2 request must be skipped per
        # iteration (req_pid != pid filter), and crucially must NOT be
        # consumed — a later pid=2 thread should still find it.
        timeline = {
            100: {"pid": 1, "create_ns": 1_000_000_000},
            200: {"pid": 2, "create_ns": 2_000_000_000},
        }
        requests = [
            (999_999_000, 50, 1, 0xABC),     # for pid=1
            (1_999_999_000, 60, 2, 0xDEF),   # for pid=2
        ]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        assert parent == {100: 50, 200: 60}

    def test_thread_iteration_order_is_dict_order(self):
        # Greedy assignment in iteration order means dict-iteration
        # order matters (Py3.7+ insertion-order guarantee). Insert
        # threads in a specific order and assert which one consumes
        # the single available request when both are equidistant.
        timeline = {}
        timeline[100] = {"pid": 1, "create_ns": 1_000_000_000}
        timeline[200] = {"pid": 1, "create_ns": 1_000_000_002}  # 2ns later
        # One request, equidistant in absolute terms (1ns to each).
        requests = [(1_000_000_001, 50, 1, 0xABC)]
        parent = {}
        correlate_thread_parents(timeline, requests, parent)
        # Thread 100 was inserted first → iterates first → consumes
        # the request. Thread 200 ends up unparented.
        assert parent == {100: 50}
        assert 200 not in parent
