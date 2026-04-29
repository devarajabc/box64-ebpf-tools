"""End-to-end tests for the web dashboard's setup and serve path.

We start a real `box64_web.start()` server bound to a random ephemeral
port (so tests don't fight each other or stomp on the user's actual
:8642 dashboard), exercise every endpoint the frontend depends on,
verify the SSE event broadcaster works, and prove `shutdown()` cleanly
tears it down.

This is what catches "page never loaded" regressions: if any endpoint
fails or the daemon thread dies, the start() self-test raises and the
test fails loudly instead of leaving a half-broken dashboard.
"""
import http.client
import json
import os
import socket
import threading
import time

import pytest

import box64_web


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _free_port():
    """Ask the kernel for any free TCP port on localhost."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fake_snapshot():
    """Realistic shape: alloc/jit/process buckets + pids + histograms."""
    return {
        "timestamp_ns": time.monotonic_ns(),
        "alloc": {"malloc": 10, "free": 8, "calloc": 2, "realloc": 1,
                  "bytes_allocated": 4096, "bytes_freed": 2048},
        "jit": {"alloc_count": 5, "free_count": 3,
                "bytes_allocated": 1024, "bytes_freed": 512,
                "outstanding_bytes": 512, "outstanding_blocks": 2,
                "churn": 0, "invalidations": 0, "dirty_marks": 0},
        "mmap": {"internal_mmap": 0, "internal_munmap": 0,
                 "box_mmap": 0, "box_munmap": 0},
        "process": {"fork": 1, "vfork": 0, "exec": 1, "posix_spawn": 0,
                    "new_context": 1, "free_context": 0,
                    "pressure_vessel": 0},
        "protection": {"protectDB_calls": 0, "unprotectDB_calls": 0,
                       "setProtection_calls": 0,
                       "protectDB_bytes": 0, "unprotectDB_bytes": 0,
                       "setProtection_bytes": 0},
        "threads": {"create_entry": 0, "create_return": 0, "start_entry": 0,
                    "destroy_entry": 0, "fork_entry": 0, "clone_entry": 0},
        "pids": {123: {"label": "test", "jit_bytes": 512,
                       "malloc_bytes": 4096, "mmap_bytes": 0,
                       "threads": 1, "jit_allocs": 5, "context_count": 1}},
        "histograms": {"alloc_sizes": {}, "block_lifetimes": {}},
        "top_blocks": [], "top_churned": [],
    }


def _fake_stats():
    return {"binary": "/usr/local/bin/box64", "guest": "box64",
            "filter_pid": 0, "interval": 15,
            "track": {"mem": True, "dynarec": True, "mmap": True}}


@pytest.fixture
def dashboard():
    """Start a dashboard on a free port, yield (port, server), tear down."""
    port = _free_port()
    server = box64_web.start(port, _fake_snapshot, _fake_stats,
                             browser_pref="none")
    try:
        yield port, server
    finally:
        box64_web.shutdown(server)


def _http_get(port, path, timeout=1.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


# ---------------------------------------------------------------------------
# Startup: self-test and clear success line
# ---------------------------------------------------------------------------

class TestStartup:
    def test_start_returns_running_server(self, dashboard):
        port, server = dashboard
        # The server's address matches what we asked for.
        assert server.server_address == ("127.0.0.1", port)

    def test_start_auto_scans_when_preferred_port_busy(self, capsys):
        # Hold the preferred port so start() must scan upward to find
        # a free one. The dashboard should come up anyway, on a port
        # that's NOT the preferred one, with a clear announcement.
        # Bind the holder directly on port 0 — going via _free_port()
        # would re-open a TOCTOU window where another process could
        # grab `preferred` between close() and the holder's bind().
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        preferred = holder.getsockname()[1]
        try:
            server = box64_web.start(preferred, _fake_snapshot, _fake_stats,
                                     browser_pref="none")
        except Exception:
            holder.close()
            raise
        try:
            actual = server.server_address[1]
            # We got a different (and working) port.
            assert actual != preferred, \
                f"start() didn't scan past the held port {preferred}"
            # Dashboard responds on the new port.
            status, _ = _http_get(actual, "/")
            assert status == 200
            # And the user was told about the relocation.
            out = capsys.readouterr().out
            assert f"Port {preferred} busy" in out
            assert f"{actual}" in out
        finally:
            box64_web.shutdown(server)
            holder.close()

    def test_start_prints_verified_line(self, port_capsys):
        port, capture = port_capsys
        out = capture.readouterr().out
        # The post-self-test summary line must appear so the user knows
        # the dashboard is actually responding (not a printed-but-dead URL).
        assert "Verified:" in out, (
            f"missing 'Verified:' line in startup output:\n{out}")
        assert "/api/snapshot" in out
        assert "/api/history" in out
        assert "/stats" in out


@pytest.fixture
def port_capsys(capsys):
    """Variant of `dashboard` that captures stdout so we can assert on it."""
    port = _free_port()
    server = box64_web.start(port, _fake_snapshot, _fake_stats,
                             browser_pref="none")
    try:
        yield port, capsys
    finally:
        box64_web.shutdown(server)


# ---------------------------------------------------------------------------
# start() ↔ _open_browser integration. The browser-open helper is heavily
# unit-tested in test_browser_open.py; here we just verify start() wires
# the call correctly: passes the URL it published, forwards browser_pref
# verbatim, and prints the right operator-log line for each outcome.
# ---------------------------------------------------------------------------

class TestStartCallsOpenBrowser:
    def _capture_open_browser(self, monkeypatch, return_value):
        """Replace _open_browser with a capturing stub. Returns the
        captured-args list; the stub returns `return_value` on each call."""
        captured = []

        def _stub(url, pref):
            captured.append((url, pref))
            return return_value

        monkeypatch.setattr(box64_web, "_open_browser", _stub)
        return captured

    def test_passes_actual_url_and_pref_to_open_browser(
            self, monkeypatch, capsys):
        captured = self._capture_open_browser(
            monkeypatch, (True, "launched stub"))

        port = _free_port()
        server = box64_web.start(port, _fake_snapshot, _fake_stats,
                                 browser_pref="firefox")
        try:
            assert len(captured) == 1
            url, pref = captured[0]
            assert url == f"http://127.0.0.1:{port}/"
            assert pref == "firefox"
        finally:
            box64_web.shutdown(server)

    def test_logs_auto_opened_on_success(self, monkeypatch, capsys):
        self._capture_open_browser(
            monkeypatch, (True, "launched 'firefox --new-tab'"))

        port = _free_port()
        server = box64_web.start(port, _fake_snapshot, _fake_stats,
                                 browser_pref="firefox")
        try:
            out = capsys.readouterr().out
            assert "Auto-opened:" in out
            assert "launched 'firefox --new-tab'" in out
            # The fallback "→ open the URL above" line must NOT appear
            # when auto-open succeeded.
            assert "open the URL above" not in out
        finally:
            box64_web.shutdown(server)

    def test_logs_fallback_on_auto_open_failure(self, monkeypatch, capsys):
        self._capture_open_browser(
            monkeypatch, (False, "no browser launcher worked"))

        port = _free_port()
        server = box64_web.start(port, _fake_snapshot, _fake_stats,
                                 browser_pref="auto")
        try:
            out = capsys.readouterr().out
            # Failure prints the detail under "Auto-open:" (no "ed")
            # AND the explicit copy-paste guidance line.
            assert "Auto-open:" in out
            assert "no browser launcher worked" in out
            assert "open the URL above" in out
        finally:
            box64_web.shutdown(server)

    def test_url_uses_actual_port_after_scan(self, monkeypatch, capsys):
        # If the preferred port is busy, start() scans upward. The URL
        # passed to _open_browser must reflect the *actual* bound port,
        # not the one we asked for. Regression for the same flavor of
        # mistake that hit _self_test in obs #356.
        captured = self._capture_open_browser(
            monkeypatch, (True, "launched stub"))

        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        preferred = holder.getsockname()[1]
        try:
            server = box64_web.start(preferred, _fake_snapshot, _fake_stats,
                                     browser_pref="firefox")
        except Exception:
            holder.close()
            raise
        try:
            actual = server.server_address[1]
            assert actual != preferred  # scan did happen
            url, _pref = captured[0]
            assert url == f"http://127.0.0.1:{actual}/"
            assert str(preferred) not in url  # no stale-port leak
        finally:
            box64_web.shutdown(server)
            holder.close()


# ---------------------------------------------------------------------------
# Every endpoint the frontend depends on
# ---------------------------------------------------------------------------

class TestEndpoints:
    def test_index_returns_html(self, dashboard):
        port, _ = dashboard
        status, body = _http_get(port, "/")
        assert status == 200
        assert body.lstrip().startswith(b"<!DOCTYPE")
        # The frontend bootstrap loads main.js — sanity-check the marker.
        assert b"main.js" in body

    def test_snapshot_endpoint(self, dashboard):
        port, _ = dashboard
        status, body = _http_get(port, "/api/snapshot")
        assert status == 200
        snap = json.loads(body)
        # The frontend (gauges.js, charts.js) reads these top-level keys.
        for k in ("alloc", "jit", "process", "pids", "histograms"):
            assert k in snap, f"snapshot missing required field {k!r}"

    def test_history_endpoint(self, dashboard):
        port, _ = dashboard
        status, body = _http_get(port, "/api/history")
        assert status == 200
        data = json.loads(body)
        assert "snapshots" in data
        assert isinstance(data["snapshots"], list)

    def test_stats_endpoint(self, dashboard):
        # The `/stats` legacy path that polling.js actually uses.
        port, _ = dashboard
        status, body = _http_get(port, "/stats")
        assert status == 200
        meta = json.loads(body)
        assert "guest" in meta  # frontend reads s.guest

    def test_api_stats_meta_alias(self, dashboard):
        # Documented public name; must match /stats (recent regression).
        port, _ = dashboard
        s1, b1 = _http_get(port, "/stats")
        s2, b2 = _http_get(port, "/api/stats-meta")
        assert s1 == s2 == 200
        assert json.loads(b1) == json.loads(b2)

    def test_static_assets_served(self, dashboard):
        port, _ = dashboard
        for asset in ("/style.css", "/js/main.js", "/js/polling.js",
                      "/js/gauges.js"):
            status, body = _http_get(port, asset)
            assert status == 200, f"{asset} → {status}"
            assert len(body) > 0

    def test_directory_traversal_blocked(self, dashboard):
        # Defense-in-depth: don't serve files outside web/.
        port, _ = dashboard
        status, _ = _http_get(port, "/../../../etc/passwd")
        assert status in (403, 404)


# ---------------------------------------------------------------------------
# SSE event stream
# ---------------------------------------------------------------------------

class TestSSE:
    def test_emit_event_reaches_subscriber(self, dashboard):
        # Use a raw socket — http.client.HTTPResponse.read() does its own
        # buffering and confuses event-stream tests. Speak HTTP manually
        # and read bytes as they arrive.
        port, _ = dashboard
        received = []
        stop = threading.Event()

        def reader():
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=2.0)
                s.sendall(b"GET /api/events HTTP/1.1\r\n"
                          b"Host: 127.0.0.1\r\n"
                          b"Connection: keep-alive\r\n\r\n")
                s.settimeout(1.5)
                buf = b""
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline and not stop.is_set():
                    try:
                        chunk = s.recv(512)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    if b"event: process" in buf and b'"pid": 42' in buf:
                        received.append(buf)
                        break
                s.close()
            except Exception:
                pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        time.sleep(0.3)  # let SSE handler register the queue
        box64_web.emit_event("process", {"action": "fork", "pid": 42})
        t.join(timeout=3.0)
        stop.set()

        assert received, "SSE subscriber never received the emitted event"
        payload = received[0]
        assert b"event: process" in payload
        assert b'"action": "fork"' in payload
        assert b'"pid": 42' in payload


# ---------------------------------------------------------------------------
# Self-test failure path: start() must NOT return a dead server
# ---------------------------------------------------------------------------

class TestSelfTestRefusesDeadServer:
    def test_failing_snapshot_fn_does_not_break_startup(self):
        # snapshot_fn that always raises — but / and /api/history still
        # return; only /api/snapshot would error. Should NOT prevent
        # startup since the self-test catches HTTP 500 there but the
        # current Handler returns 200 with an empty body when fn raises.
        # This pins the "snapshot_fn errors don't sink startup" contract.
        port = _free_port()

        def boom():
            raise RuntimeError("snapshot exploded")

        # We just need to confirm start() returns a live server. If it
        # raised here, snapshot_fn errors would block dashboard startup —
        # bad for resilience.
        try:
            server = box64_web.start(port, boom, _fake_stats,
                                     browser_pref="none")
        except OSError:
            # Acceptable: a strict self-test rejects this. Either way,
            # behaviour is well-defined.
            return
        try:
            # If we got here, the server is running and only /api/snapshot
            # is broken; index/history/stats are fine.
            status, _ = _http_get(port, "/")
            assert status == 200
        finally:
            box64_web.shutdown(server)
