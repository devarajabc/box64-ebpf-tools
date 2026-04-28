"""Tests for crash-handling behaviour: child-exit message formatting and
dashboard shutdown.

`_format_child_exit` is a pure function — easy to test against synthesized
waitpid status values. `box64_web.shutdown` we exercise by mocking out the
HTTP server and asserting the right calls happen.
"""
import os
import signal

import pytest

import box64_trace
import box64_web


# ---------------------------------------------------------------------------
# _format_child_exit: synthesize waitpid statuses and assert the message
# ---------------------------------------------------------------------------

def _exit_status(rc):
    """Build a status word equivalent to a normal exit with code `rc`."""
    return rc << 8


def _signal_status(sig):
    """Build a status word equivalent to death by signal `sig`."""
    return sig & 0x7f


class TestFormatChildExit:
    def test_clean_exit(self):
        rc, msg = box64_trace._format_child_exit(_exit_status(0))
        assert rc == 0
        assert "cleanly" in msg
        assert "rc=0" in msg

    def test_nonzero_exit(self):
        rc, msg = box64_trace._format_child_exit(_exit_status(42))
        assert rc == 42
        assert "rc=42" in msg
        assert "cleanly" not in msg  # only rc=0 gets the "cleanly" wording

    @pytest.mark.parametrize("sig,expected_name", [
        (signal.SIGSEGV, "SIGSEGV"),
        (signal.SIGABRT, "SIGABRT"),
        (signal.SIGILL, "SIGILL"),
        (signal.SIGBUS, "SIGBUS"),
        (signal.SIGFPE, "SIGFPE"),
    ])
    def test_crash_signals_get_box64_hint(self, sig, expected_name):
        rc, msg = box64_trace._format_child_exit(_signal_status(sig))
        assert rc == 128 + sig
        assert expected_name in msg
        assert f"rc={128 + sig}" in msg
        # Crash hint must mention the most useful isolation step.
        assert "BOX64_DYNAREC=0" in msg
        # And the Mono dump pointer for Unity games.
        assert "mono_crash" in msg

    @pytest.mark.parametrize("sig,expected_name", [
        (signal.SIGTERM, "SIGTERM"),
        (signal.SIGINT, "SIGINT"),
        (signal.SIGHUP, "SIGHUP"),
    ])
    def test_user_signals_no_box64_hint(self, sig, expected_name):
        rc, msg = box64_trace._format_child_exit(_signal_status(sig))
        assert rc == 128 + sig
        assert expected_name in msg
        # SIGTERM/SIGINT mean the user (or the system) asked it to stop —
        # not a Box64 crash, so we shouldn't push the BOX64_DYNAREC hint.
        assert "BOX64_DYNAREC" not in msg

    def test_unknown_status_safe_default(self):
        # Some bogus status pattern — make sure we don't crash and return
        # something sensible. (Using the WIFSTOPPED bit pattern.)
        rc, msg = box64_trace._format_child_exit(0x7f)
        assert isinstance(rc, int)
        assert isinstance(msg, str)


# ---------------------------------------------------------------------------
# box64_web.shutdown(): tear-down semantics
# ---------------------------------------------------------------------------

class _FakeServer:
    def __init__(self):
        self.shutdown_called = False
        self.close_called = False

    def shutdown(self):
        self.shutdown_called = True

    def server_close(self):
        self.close_called = True


class TestWebShutdown:
    def test_none_is_noop(self):
        # Don't crash on None — main() may call shutdown unconditionally.
        box64_web.shutdown(None)

    def test_shuts_down_server_and_closes(self):
        srv = _FakeServer()
        box64_web.shutdown(srv)
        assert srv.shutdown_called
        assert srv.close_called

    def test_drains_sse_clients(self):
        # Push a real Queue into the module's client list, call shutdown,
        # and assert we got the None sentinel.
        import queue
        q = queue.Queue(maxsize=4)
        with box64_web._state["lock"]:
            box64_web._state["sse_clients"].append(q)
        try:
            srv = _FakeServer()
            box64_web.shutdown(srv)
            assert q.get_nowait() is None, \
                "shutdown didn't push the None sentinel onto SSE client queue"
        finally:
            with box64_web._state["lock"]:
                if q in box64_web._state["sse_clients"]:
                    box64_web._state["sse_clients"].remove(q)

    def test_tolerates_failing_server(self):
        # Simulating a server that's already half-torn-down: shutdown()
        # raises. We must not propagate.
        class _Broken:
            def shutdown(self):
                raise RuntimeError("already stopped")

            def server_close(self):
                raise RuntimeError("already stopped")

        # Should NOT raise.
        box64_web.shutdown(_Broken())

    def test_tolerates_full_sse_queue(self):
        # If a client queue is full, put_nowait raises queue.Full —
        # shutdown must keep going to the next client.
        import queue
        full_q = queue.Queue(maxsize=1)
        full_q.put(b"already there")  # now full
        ok_q = queue.Queue(maxsize=4)

        with box64_web._state["lock"]:
            box64_web._state["sse_clients"].append(full_q)
            box64_web._state["sse_clients"].append(ok_q)
        try:
            box64_web.shutdown(_FakeServer())
            # full_q didn't get the sentinel (couldn't), but ok_q did.
            assert ok_q.get_nowait() is None
        finally:
            with box64_web._state["lock"]:
                for q in (full_q, ok_q):
                    if q in box64_web._state["sse_clients"]:
                        box64_web._state["sse_clients"].remove(q)
