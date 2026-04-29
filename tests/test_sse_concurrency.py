"""Concurrency tests for box64_web's SSE broadcaster.

The HTTP-level "single subscriber gets the event" path is covered by
test_web_dashboard.py::TestSSE. This file fills the gaps that matter
under real load and that simple HTTP roundtrips don't exercise:

  * `emit_event` must broadcast to *all* registered subscribers,
    not just the first.
  * A slow / dead / disconnected subscriber whose queue is full or
    whose put_nowait raises must NOT block emit, and MUST NOT prevent
    other subscribers from receiving the event.
  * Multiple producers calling `emit_event` from different threads
    must not corrupt `_state` or lose events at the queue layer.
  * `shutdown()` must wake every registered subscriber via the `None`
    sentinel so request threads exit cleanly.

We test against `_state["sse_clients"]` directly with hand-rolled
queues. That keeps the assertions deterministic — no socket timeouts,
no daemon-thread scheduling — while still exercising the real
production code path inside `emit_event` and `shutdown`.
"""
import queue
import threading

import pytest

import box64_web


@pytest.fixture(autouse=True)
def _reset_sse_state():
    """Clear the subscriber list before and after each test.

    The module-level `_state` dict is shared across tests; without
    this, a leaked queue from one test would receive payloads emitted
    in the next one.
    """
    with box64_web._state["lock"]:
        box64_web._state["sse_clients"].clear()
    yield
    with box64_web._state["lock"]:
        box64_web._state["sse_clients"].clear()


def _register(q):
    """Subscribe a queue the same way the SSE handler does."""
    with box64_web._state["lock"]:
        box64_web._state["sse_clients"].append(q)


def _drain(q):
    """Pull every payload currently buffered in q without blocking."""
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            return out


# ---------------------------------------------------------------------------
# Multi-subscriber broadcast
# ---------------------------------------------------------------------------

class TestBroadcast:
    def test_emit_reaches_every_subscriber(self):
        # Three independent SSE clients, each with its own queue. A
        # single emit_event must deliver to all three (not just the
        # first registered, not just the most-recent).
        qs = [queue.Queue(maxsize=8) for _ in range(3)]
        for q in qs:
            _register(q)

        box64_web.emit_event("process", {"action": "fork", "pid": 7})

        for q in qs:
            payloads = _drain(q)
            assert len(payloads) == 1
            assert b"event: process" in payloads[0]
            assert b'"pid": 7' in payloads[0]

    def test_emit_after_unregister_skips_removed_subscriber(self):
        # The handler's `finally` clause removes the queue from
        # sse_clients on disconnect. A subsequent emit must not push
        # to the removed queue (verified by post-condition: queue is
        # still empty).
        kept = queue.Queue(maxsize=8)
        gone = queue.Queue(maxsize=8)
        _register(kept)
        _register(gone)

        with box64_web._state["lock"]:
            box64_web._state["sse_clients"].remove(gone)

        box64_web.emit_event("jit", {"churn": 1})

        assert len(_drain(kept)) == 1
        assert _drain(gone) == []

    def test_event_ring_records_seq_under_lock(self):
        # `event_seq` is incremented inside the lock so concurrent
        # emits never produce duplicate seq values. Sanity-check that
        # sequential emits produce strictly increasing seq.
        with box64_web._state["lock"]:
            start_seq = box64_web._state["event_seq"]

        for i in range(5):
            box64_web.emit_event("process", {"i": i})

        with box64_web._state["lock"]:
            recent = list(box64_web._state["events"])[-5:]
        seqs = [e["seq"] for e in recent]
        assert seqs == [start_seq + 1, start_seq + 2, start_seq + 3,
                        start_seq + 4, start_seq + 5]


# ---------------------------------------------------------------------------
# Failure isolation: one bad subscriber must not break the others
# ---------------------------------------------------------------------------

class TestSubscriberFailureIsolation:
    def test_full_queue_does_not_block_other_subscribers(self):
        # A subscriber that has stopped reading lets its queue fill
        # to maxsize. The next put_nowait raises queue.Full, which
        # emit_event must swallow so a healthy subscriber still gets
        # the event.
        slow = queue.Queue(maxsize=2)
        slow.put_nowait(b"prior-1")
        slow.put_nowait(b"prior-2")  # now full
        healthy = queue.Queue(maxsize=8)

        _register(slow)
        _register(healthy)

        # Must not raise — Full is caught by the bare except in
        # emit_event's broadcast loop.
        box64_web.emit_event("cow", {"delta": 4096})

        # Healthy subscriber received the event despite the slow one
        # being saturated.
        payloads = _drain(healthy)
        assert len(payloads) == 1
        assert b"event: cow" in payloads[0]

        # Slow subscriber's queue stayed at its existing two items —
        # the full-queue put failed silently rather than dropping
        # already-buffered events.
        leftover = _drain(slow)
        assert leftover == [b"prior-1", b"prior-2"]

    def test_subscriber_with_raising_put_does_not_break_others(self):
        # A subscriber object whose put_nowait raises an arbitrary
        # exception (e.g. its underlying socket already closed and a
        # custom queue wrapper now raises) must not propagate.
        class _ExplodingQueue:
            def put_nowait(self, _payload):
                raise RuntimeError("subscriber detached")

        bad = _ExplodingQueue()
        good = queue.Queue(maxsize=8)
        _register(bad)
        _register(good)

        box64_web.emit_event("process", {"action": "exec"})

        assert len(_drain(good)) == 1

    def test_emit_with_no_subscribers_is_noop(self):
        # No subscribers registered. emit_event must still record the
        # event in the ring buffer (so reconnecting clients can replay)
        # and must not raise.
        with box64_web._state["lock"]:
            before_len = len(box64_web._state["events"])

        box64_web.emit_event("process", {"action": "fork"})

        with box64_web._state["lock"]:
            after = list(box64_web._state["events"])
        assert len(after) == before_len + 1
        assert after[-1]["type"] == "process"


# ---------------------------------------------------------------------------
# Multi-producer thread contention
# ---------------------------------------------------------------------------

class TestProducerContention:
    def test_concurrent_emit_does_not_lose_events_or_corrupt_seq(self):
        # N producer threads each emit M events. The receiving queue
        # must contain exactly N*M payloads (no drops, no duplicates),
        # and every seq number stamped into _state["events"] must be
        # unique — proof that the lock around event_seq increment
        # serializes producers.
        producers = 8
        per_producer = 50
        total = producers * per_producer

        # Big enough to hold every event without falling back to the
        # full-queue silent-drop path. We're testing serialization
        # here, not backpressure.
        sink = queue.Queue(maxsize=total + 16)
        _register(sink)

        with box64_web._state["lock"]:
            start_seq = box64_web._state["event_seq"]

        barrier = threading.Barrier(producers)
        errors = []

        def _worker(tid):
            try:
                barrier.wait()
                for i in range(per_producer):
                    box64_web.emit_event("process",
                                         {"tid": tid, "i": i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_worker, args=(t,))
                   for t in range(producers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        assert errors == []
        assert all(not t.is_alive() for t in threads)

        payloads = _drain(sink)
        assert len(payloads) == total

        with box64_web._state["lock"]:
            tail = list(box64_web._state["events"])[-total:]
        seqs = [e["seq"] for e in tail]
        # Every seq is unique and > start_seq.
        assert len(set(seqs)) == total
        assert min(seqs) > start_seq

    def test_subscriber_join_during_emit_storm_does_not_crash(self):
        # While a producer is emitting, subscribers register and
        # unregister. The lock-snapshot pattern in emit_event means
        # a new subscriber may miss in-flight events but must not see
        # partial state, and emit_event must not crash.
        #
        # Bounded iteration count rather than a "while running" loop
        # so the producer cannot leak past the test even if join() is
        # slow — a leaked producer keeps appending to _state["events"]
        # and pollutes other tests in the same process.
        EMIT_COUNT = 500
        errors = []

        def _producer():
            try:
                for _ in range(EMIT_COUNT):
                    box64_web.emit_event("jit", {"churn": 1})
            except Exception as e:
                errors.append(e)

        prod = threading.Thread(target=_producer)
        prod.start()

        try:
            for _ in range(20):
                q = queue.Queue(maxsize=64)
                _register(q)
                with box64_web._state["lock"]:
                    box64_web._state["sse_clients"].remove(q)
        finally:
            prod.join(timeout=10.0)

        assert errors == []
        # Hard fail (not a warning) if the producer is somehow still
        # alive — that would mean it can leak into the next test.
        assert not prod.is_alive(), \
            "producer thread did not exit; would leak into other tests"


# ---------------------------------------------------------------------------
# shutdown() wakes subscribers via None sentinel
# ---------------------------------------------------------------------------

class TestShutdownWakesSubscribers:
    def _fake_server(self):
        """Minimal stand-in for ThreadingHTTPServer that records calls.

        shutdown()'s lock-snapshot + sentinel-broadcast happens before
        it touches the server, so we don't need a live HTTP listener
        for this test — just an object that supports `shutdown` and
        `server_close`.
        """
        calls = []

        class _S:
            def shutdown(self_inner):
                calls.append("shutdown")

            def server_close(self_inner):
                calls.append("server_close")

        return _S(), calls

    def test_shutdown_pushes_none_to_every_subscriber(self):
        qs = [queue.Queue(maxsize=8) for _ in range(3)]
        for q in qs:
            _register(q)

        server, calls = self._fake_server()
        box64_web.shutdown(server)

        # Every subscriber received the shutdown sentinel — this is
        # what their _serve_sse loop interprets as "drop the connection
        # so the client can reconnect or stop".
        for q in qs:
            assert q.get_nowait() is None

        # The server's shutdown() and server_close() were both called.
        assert calls == ["shutdown", "server_close"]

    def test_shutdown_with_no_subscribers_is_safe(self):
        server, calls = self._fake_server()
        # No queues registered.
        box64_web.shutdown(server)
        assert calls == ["shutdown", "server_close"]

    def test_shutdown_swallows_full_subscriber_queue(self):
        # If a subscriber's queue is already full when shutdown fires,
        # the sentinel put fails — but that must not stop shutdown
        # from continuing to other subscribers AND from tearing down
        # the server. Otherwise a single stuck client could prevent
        # port release.
        full = queue.Queue(maxsize=1)
        full.put_nowait(b"prior")  # now full

        ok = queue.Queue(maxsize=8)
        _register(full)
        _register(ok)

        server, calls = self._fake_server()
        box64_web.shutdown(server)

        # Healthy subscriber got the sentinel.
        assert ok.get_nowait() is None
        # Full subscriber kept its prior payload (sentinel put_nowait
        # raised queue.Full and was swallowed).
        assert full.get_nowait() == b"prior"
        # Server still torn down despite the failed sentinel put.
        assert calls == ["shutdown", "server_close"]

    def test_shutdown_with_none_server_is_safe(self):
        # `shutdown(None)` is a documented early-return path used when
        # start() returned None (e.g., an OSError before the server
        # came up). Must not raise even with subscribers registered
        # — though there shouldn't be any in that scenario.
        box64_web.shutdown(None)
