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
        assert "exited (rc=0)" in msg

    def test_nonzero_exit(self):
        rc, msg = box64_trace._format_child_exit(_exit_status(42))
        assert rc == 42
        assert "exited (rc=42)" in msg

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


# ---------------------------------------------------------------------------
# _wait_for_user_signal: post-child-exit "keep dashboard alive" loop.
# Regression for: after FINAL REPORT printed, the tracer printed
# "Dashboard still serving — Ctrl+C to shut down" but Ctrl+C did not
# actually terminate. The custom sig_handler in main() sets a flag and
# returns without raising KeyboardInterrupt, so a `while True: time.sleep`
# loop just restarted the sleep on every signal and the user had to
# SIGKILL the process.
# ---------------------------------------------------------------------------

class TestWaitForUserSignal:
    def test_returns_when_flag_set_before_call(self):
        # Trivial fast path: flag already set, no wait at all.
        flag = [True]
        import time
        t0 = time.monotonic()
        box64_trace._wait_for_user_signal(flag, poll_interval=0.05)
        assert time.monotonic() - t0 < 0.5

    def test_returns_promptly_after_flag_flips(self):
        # The real bug: under the old `while True: time.sleep(3600)` form,
        # this test would hang for an hour. We assert the function returns
        # within a tight bound after the flag is set externally.
        import threading
        import time
        flag = [False]
        done = threading.Event()

        def _waiter():
            box64_trace._wait_for_user_signal(flag, poll_interval=0.05)
            done.set()

        t = threading.Thread(target=_waiter, daemon=True)
        t.start()

        time.sleep(0.1)
        assert not done.is_set(), (
            "wait returned before flag was set — flag-poll loop is broken")

        # Flip the flag the way sig_handler does in main().
        flag[0] = True
        # Should return well within the poll_interval + a little slack.
        assert done.wait(timeout=1.0), (
            "wait did not return within 1s of the flag being set — "
            "regression: sig_handler-style flag flip is being ignored")

    def test_swallows_keyboardinterrupt_for_belt_and_suspenders(self):
        # In the rare case where SIGINT arrives between the time.sleep
        # call and Python checking signals (e.g. on a build where the
        # default int handler is somehow restored), KeyboardInterrupt
        # might leak out. We catch it and return cleanly so the caller
        # always gets to its shutdown(server) call.
        flag = [False]

        def _raising_sleep(_):
            flag[0] = True  # simulate sig_handler running before raise
            raise KeyboardInterrupt()

        import time
        original = time.sleep
        time.sleep = _raising_sleep
        try:
            box64_trace._wait_for_user_signal(flag, poll_interval=0.01)
        finally:
            time.sleep = original
        # No exception propagated — that's the assertion.


# ---------------------------------------------------------------------------
# _should_keep_dashboard_alive: the four-case decision matrix at end-of-run.
#   web on/off  x  program clean exit / crash signal
# Only (web=on, crashed) keeps the dashboard alive for inspection. Everything
# else exits immediately — making the user Ctrl+C through a clean run is
# friction with no payoff.
# ---------------------------------------------------------------------------

_RC_CLEAN = 0
_RC_NONZERO_CLEAN = 42
_RC_SEGV = 128 + signal.SIGSEGV
_RC_ABRT = 128 + signal.SIGABRT
_RC_TERM = 128 + signal.SIGTERM   # user-initiated, not a crash
_RC_INT = 128 + signal.SIGINT     # ditto


class TestShouldKeepDashboardAlive:
    # The four canonical cases — this is the contract the user asked for.

    def test_web_on_crashed_keeps_dashboard(self):
        # web=on, program crashed: the whole reason the dashboard exists
        # is to inspect this case.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=False,
            child_returncode=_RC_SEGV) is True

    def test_web_on_clean_exits_immediately(self):
        # web=on, clean exit: nothing to investigate; don't make the user
        # Ctrl+C through a successful run.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=False,
            child_returncode=_RC_CLEAN) is False

    def test_web_off_crashed_exits_immediately(self):
        # web=off, program crashed: no dashboard to inspect, just exit.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=False, child_exited=True, user_signalled=False,
            child_returncode=_RC_SEGV) is False

    def test_web_off_clean_exits_immediately(self):
        # web=off, clean exit: trivially nothing to do.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=False, child_exited=True, user_signalled=False,
            child_returncode=_RC_CLEAN) is False

    # ---- additional gates around the matrix ----

    @pytest.mark.parametrize("rc", [_RC_SEGV, _RC_ABRT,
                                    128 + signal.SIGILL,
                                    128 + signal.SIGBUS,
                                    128 + signal.SIGFPE])
    def test_all_crash_class_signals_keep_dashboard(self, rc):
        # SIGSEGV/SIGABRT/SIGILL/SIGBUS/SIGFPE all count as crashes.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=False,
            child_returncode=rc) is True

    @pytest.mark.parametrize("rc", [_RC_TERM, _RC_INT, 128 + signal.SIGHUP])
    def test_user_signals_dont_count_as_crash(self, rc):
        # SIGTERM/SIGINT/SIGHUP are user-initiated stops, not crashes.
        # No reason to keep the dashboard up — the user told it to stop.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=False,
            child_returncode=rc) is False

    def test_nonzero_clean_exit_is_not_a_crash(self):
        # A program that exit(1)s on its own is not a crash — no signal,
        # so no DynaRec-isolation hint applies, and no dashboard wait.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=False,
            child_returncode=_RC_NONZERO_CLEAN) is False

    def test_user_already_signalled_skips_wait(self):
        # If the user already Ctrl+C'd, they want out — don't ask them
        # to Ctrl+C a second time, even on a crash.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=True,
            child_returncode=_RC_SEGV) is False

    def test_child_not_exited_skips_wait(self):
        # We only wait if the child actually exited via waitpid. A stale
        # spawn that we tore down ourselves shouldn't trigger the wait.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=False, user_signalled=False,
            child_returncode=_RC_SEGV) is False

    def test_rc_127_exec_failure_skips_wait(self):
        # rc=127 is our exec-failure marker (_validate_spawn_command).
        # Nothing ever ran, so the dashboard has nothing to show.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=False,
            child_returncode=127) is False

    def test_returncode_none_skips_wait(self):
        # Defensive: caller may pass None if waitpid never resolved.
        assert box64_trace._should_keep_dashboard_alive(
            web_active=True, child_exited=True, user_signalled=False,
            child_returncode=None) is False
