"""HTTP server for box64_trace.py's optional --web dashboard.

Lifts the API contract from kbox (web/js/polling.js):
- GET /api/snapshot — current stats (polled every pollInterval)
- GET /api/history — recent snapshots for chart backfill
- GET /stats — binary path / pid filter info (rarely changes)
- GET /api/events — Server-Sent Events stream for fork/exec/jit events

The frontend assets in web/ are MIT-licensed and partially copied from
kbox (https://github.com/sysprog21/kbox, Copyright 2026 NCKU Taiwan).
See web/LICENSE-kbox for attribution.
"""
import json
import os
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
HISTORY_MAX = 300       # ~15 min at 3s poll interval
EVENT_RING_MAX = 1024   # bounded ring buffer for SSE

_state = {
    "snapshot_fn": None,    # callable returning a dict
    "stats_fn": None,       # callable returning a dict (binary, pid, etc.)
    "history": deque(maxlen=HISTORY_MAX),
    "events": deque(maxlen=EVENT_RING_MAX),
    "event_seq": 0,
    "lock": threading.Lock(),
    "sse_clients": [],
}


def _self_test(host, port, deadline_s=3.0):
    """
    Verify the dashboard's critical endpoints are responding before we
    advertise the URL to the user.

    Returns a list of failure descriptions (empty list = healthy).
    Each endpoint gets up to `deadline_s` seconds total. We start with
    `/` (proves the daemon thread is alive) and only check the API
    routes if `/` works — saves time when the server is dead.
    """
    import http.client
    import json as _json

    def _try(method, path, expect_json=False, expect_starts=None,
             timeout=0.5):
        """Returns None on success, error string on failure."""
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request(method, path)
            resp = conn.getresponse()
            status = resp.status
            body = resp.read()
            conn.close()
            if status != 200:
                return f"{path} → HTTP {status}"
            if expect_starts and not body.lstrip().startswith(expect_starts):
                return f"{path} → unexpected body (got {body[:30]!r})"
            if expect_json:
                try:
                    _json.loads(body)
                except Exception as e:
                    return f"{path} → invalid JSON ({e})"
            return None
        except (OSError, http.client.HTTPException) as e:
            return f"{path} → {type(e).__name__}: {e}"

    # Wait for the daemon thread to finish binding and start serving.
    poll_deadline = time.time() + deadline_s
    while time.time() < poll_deadline:
        err = _try("GET", "/", expect_starts=b"<!DOCTYPE")
        if err is None:
            break
        time.sleep(0.05)
    else:
        return [err or "/ never responded"]

    failures = []
    for path, kwargs in [
        ("/api/snapshot", {"expect_json": True}),
        ("/api/history",  {"expect_json": True}),
        ("/stats",        {"expect_json": True}),
    ]:
        err = _try("GET", path, **kwargs)
        if err is not None:
            failures.append(err)
    return failures


def emit_event(event_type, data):
    """Push an event into the ring + broadcast to SSE clients.

    event_type: 'process' | 'jit' | 'cow' | other.
    data: JSON-serializable dict.
    """
    with _state["lock"]:
        _state["event_seq"] += 1
        seq = _state["event_seq"]
        evt = {"seq": seq, "type": event_type, "data": data, "ts_ns": time.monotonic_ns()}
        _state["events"].append(evt)
        clients = list(_state["sse_clients"])
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n".encode("utf-8")
    for q in clients:
        try:
            q.put_nowait(payload)
        except Exception:
            pass


def _record_history(snap):
    with _state["lock"]:
        _state["history"].append(snap)


_HISTORY_TIMER = {"started": False}


def _history_loop(interval=3.0):
    while True:
        try:
            fn = _state["snapshot_fn"]
            if fn:
                snap = fn()
                if snap:
                    _record_history(snap)
        except Exception:
            pass
        time.sleep(interval)


_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return  # silence default access logging

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, path):
        full = os.path.join(WEB_DIR, path.lstrip("/"))
        # path traversal guard
        if not os.path.abspath(full).startswith(os.path.abspath(WEB_DIR)):
            self.send_error(403)
            return
        if not os.path.isfile(full):
            self.send_error(404)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = _CONTENT_TYPES.get(ext, "application/octet-stream")
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/" or path == "/index.html":
            self._send_static("/index.html")
        elif path == "/api/snapshot":
            fn = _state["snapshot_fn"]
            snap = fn() if fn else {}
            self._send_json(snap or {})
        elif path == "/api/history":
            with _state["lock"]:
                snaps = list(_state["history"])
            self._send_json({"snapshots": snaps})
        elif path in ("/stats", "/api/stats-meta"):
            # `/stats` is the legacy path the frontend's polling.js uses;
            # `/api/stats-meta` is the documented public name. Serve both.
            fn = _state["stats_fn"]
            self._send_json(fn() if fn else {})
        elif path == "/api/events":
            self._serve_sse()
        else:
            self._send_static(path)

    def _serve_sse(self):
        import queue
        q = queue.Queue(maxsize=256)
        with _state["lock"]:
            _state["sse_clients"].append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    payload = q.get(timeout=15)
                    # `None` is the shutdown sentinel — drop the connection
                    # so the client can reconnect (or stop) instead of
                    # hanging on a now-dead server.
                    if payload is None:
                        break
                    self.wfile.write(payload)
                    self.wfile.flush()
                except queue.Empty:
                    # heartbeat to keep the connection alive through proxies
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _state["lock"]:
                if q in _state["sse_clients"]:
                    _state["sse_clients"].remove(q)


def start(port, snapshot_fn, stats_fn, history_interval=3.0, host="127.0.0.1",
          browser_pref="auto"):
    """Start the HTTP server in a daemon thread.

    snapshot_fn: callable returning the current snapshot dict.
    stats_fn:    callable returning binary/pid metadata.
    browser_pref: "auto" (default), "none", or a command name like "firefox".
    """
    _state["snapshot_fn"] = snapshot_fn
    _state["stats_fn"] = stats_fn

    if not _HISTORY_TIMER["started"]:
        _HISTORY_TIMER["started"] = True
        t = threading.Thread(target=_history_loop, args=(history_interval,), daemon=True)
        t.start()

    # Allow reuse — without this, restarting box64_trace within ~60s of a
    # previous run fails with EADDRINUSE because the previous socket is
    # still in TIME_WAIT. Browsers see the resulting bind failure as
    # "page never loaded", which is the worst possible UX.
    ThreadingHTTPServer.allow_reuse_address = True

    # Auto-pick a free port: try the preferred one first, then preferred+1
    # through preferred+19, then ask the kernel for any free port. The
    # bind-on-success approach is race-free — whichever bind succeeds is
    # the socket we'll keep. Replaces the pre-flight probe in
    # box64_trace.py which had a race between probe.close() and the
    # real ThreadingHTTPServer bind 10s later.
    server = None
    last_err = None
    import errno as _errno
    candidates = list(range(port, port + 20)) + [0]  # 0 = kernel ephemeral
    for try_port in candidates:
        try:
            server = ThreadingHTTPServer((host, try_port), Handler)
            break
        except OSError as e:
            last_err = e
            # EACCES on low ports is fatal; scanning won't help.
            if e.errno == _errno.EACCES:
                raise
            continue
    if server is None:
        raise OSError(f"box64_web: could not bind any port from {port} "
                      f"through {port + 19} or kernel-ephemeral "
                      f"({last_err})")
    actual_port = server.server_address[1]
    if actual_port != port:
        if 0 < actual_port - port < 20:
            print(f"[*] Port {port} busy; dashboard will use "
                  f"{actual_port} instead.")
        else:
            print(f"[*] Ports {port}..{port + 19} all busy; kernel "
                  f"assigned {actual_port}.")
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{actual_port}/"

    # Self-test: verify the server actually responds AND that every
    # endpoint the frontend depends on returns a sane status before we
    # hand the URL to the user. If anything's broken (daemon thread
    # died, route mis-wired, snapshot_fn raised), surface it here
    # instead of letting the user discover it via a blank browser tab.
    failures = _self_test(host, actual_port)
    if failures:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass
        raise OSError(
            f"web server bound on {url} but the self-test failed: "
            + "; ".join(failures)
            + ". Re-run with BOX64_TRACE_DEBUG=1 for the daemon-thread "
            "traceback.")

    # Print the URL prominently so the user can always copy-paste it,
    # whatever happens with auto-open below.
    print(f"[*] Web dashboard:  {url}")
    print(f"[*] Verified:       index.html, /api/snapshot, /api/history, "
          f"/stats — server is responding.")

    opened, detail = _open_browser(url, browser_pref)
    if opened:
        print(f"[*] Auto-opened:    {detail}")
    else:
        print(f"[*] Auto-open:      {detail}")
        print(f"[*]                 → open the URL above in your browser.")

    return server


def shutdown(server):
    """Tear down the HTTP server promptly: stop the listener, close any
    open SSE connections, and free the port.

    Called by box64_trace.py once the spawned child exits (or on Ctrl+C)
    so the browser stops showing stale 'live' data while the tracer is
    busy printing its final report.
    """
    if server is None:
        return
    # Wake every connected SSE client by pushing the None sentinel onto
    # its queue. Their handlers will break out of the read loop and let
    # the request thread exit cleanly. Any pending heartbeat-timeout
    # waits stay bounded by the existing 15-second q.get() timeout.
    with _state["lock"]:
        clients = list(_state.get("sse_clients", []))
    for q in clients:
        try:
            q.put_nowait(None)
        except Exception:
            pass
    # `shutdown()` blocks until serve_forever returns. Wrap in try in case
    # the server thread already exited (e.g., parent fork/exec error).
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass


# Command names of the Firefox family. Used by `_browser_argv` to
# decide when to inject `--new-tab` (which delegates to a running
# instance via Firefox's remote-control protocol instead of starting
# a fresh process that would fight the profile lock).
_FIREFOX_CMDS = frozenset({
    "firefox", "firefox-bin", "firefox-esr",
    "firefox-developer-edition", "firefox-nightly",
})


def _browser_argv(cmd, url):
    """Argv for launching `cmd` to open `url`.

    For Firefox-family commands, prepend `--new-tab` so the URL is
    routed to an already-running Firefox over the remote-control
    protocol. This avoids the "Firefox is already running, but is not
    responding" profile-lock dialog and is a no-op when Firefox is
    not running (Firefox just starts and opens the URL in a new tab).
    """
    base = os.path.basename(cmd)
    if base in _FIREFOX_CMDS:
        return [cmd, "--new-tab", url]
    return [cmd, url]


def _firefox_is_running():
    """
    Best-effort: True iff a Firefox-family process is currently alive
    on this system.

    /proc-based scan, no pgrep dependency. Used by the auto-open
    resolver to decide between `firefox --new-tab` (talks to existing
    instance, no profile-lock collision) and `xdg-open` (which would
    spawn a fresh firefox and trigger the "already running but not
    responding" dialog). Catches Snap and Flatpak builds via the
    /proc/<pid>/exe symlink, which other comm-only checks miss.
    """
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/comm") as f:
                    comm = f.read().strip()
            except OSError:
                continue
            looks_firefoxy = (
                comm.startswith("firefox")
                or comm == "MainThread"  # Firefox renames its main thread
            )
            if not looks_firefoxy:
                # Last resort: the exe symlink. Snap and Flatpak runtimes
                # land under /snap/firefox/... or /var/lib/flatpak/... where
                # the comm shows as the wrapper, not "firefox".
                try:
                    exe = os.readlink(f"/proc/{entry}/exe")
                except OSError:
                    continue
                if "/firefox" not in exe:
                    continue
            # Confirm with cmdline so we don't false-positive on an
            # unrelated process literally named "firefox".
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as f:
                    cmd = f.read()
                if b"firefox" in cmd:
                    return True
            except OSError:
                continue
    except OSError:
        pass
    return False


_SESSION_ENV_KEYS = (
    "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR", "XAUTHORITY", "HOME",
)


def _user_session_env(sudo_user):
    """Reconstruct the GUI/session env of `sudo_user` from /proc.

    When the operator runs `sudo box64_trace --web`, sudo strips the
    user's GUI session env (DISPLAY, WAYLAND_DISPLAY, the DBus session
    bus address, XDG_RUNTIME_DIR, XAUTHORITY) before handing control
    to root. If we then re-drop into the user with `sudo -u <user>`
    without those vars, GUI launches like Firefox can't reach the
    running session: `firefox --new-tab URL` can't dispatch over DBus
    or XRemote and falls back to spawning a fresh instance, which
    fights the profile lock and shows the "already running, but is
    not responding" dialog.

    Workaround: read `/proc/<pid>/environ` of any process still owned
    by the user — those processes were started inside the live
    session and carry the right env vars. Return a dict of the first
    non-empty value found per key. Caller is expected to interpolate
    these via `sudo -u <user> env K=V K=V <cmd>`.
    """
    if not sudo_user:
        return {}
    try:
        import pwd
        uid = pwd.getpwnam(sudo_user).pw_uid
    except (ImportError, KeyError):
        return {}

    found = {}
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                if os.stat(f"/proc/{entry}").st_uid != uid:
                    continue
                with open(f"/proc/{entry}/environ", "rb") as f:
                    data = f.read()
            except OSError:
                continue
            for kv in data.split(b"\x00"):
                if b"=" not in kv:
                    continue
                k, _, v = kv.partition(b"=")
                try:
                    key = k.decode("ascii")
                except UnicodeDecodeError:
                    continue
                if key in _SESSION_ENV_KEYS and key not in found:
                    found[key] = v.decode("utf-8", errors="replace")
            if all(k in found for k in _SESSION_ENV_KEYS):
                break  # got everything we wanted
    except OSError:
        pass
    return found


def _open_browser(url, pref="auto"):
    """
    Try to open `url` in a browser.

    `pref`:
      "none"  → skip auto-open entirely (returns (False, reason))
      "auto"  → respect $BROWSER, then xdg-open, then Python's webbrowser
      anything else → treat as a command name (e.g. "firefox", "chromium")

    Returns (opened, detail). `opened` is False on skip/failure; `detail`
    is a short human-readable line for the operator log.

    Why this exists: Firefox prints "already running, but is not responding"
    when launched while another instance holds the profile lock — and that
    error is shown by xdg-open's child rather than as a non-zero exit, so
    we can't reliably detect it. The mitigation is to (a) let the user
    pick a different browser via --browser or $BROWSER, (b) always print
    the URL so copy-paste is one step away.
    """
    import subprocess

    if pref == "none":
        return False, "skipped (--browser=none)"

    sudo_user = os.environ.get("SUDO_USER")
    session_env = _user_session_env(sudo_user) if sudo_user else {}

    def _spawn(argv):
        # Under sudo we have to drop privs so the browser can reach the
        # caller's X/Wayland session — and we must repopulate the session
        # env that sudo stripped (DISPLAY, WAYLAND_DISPLAY, DBus address,
        # XDG_RUNTIME_DIR, XAUTHORITY, HOME). Without those, Firefox's
        # `--new-tab` can't reach the running instance over DBus/XRemote
        # and falls back to "start a fresh process", which is exactly
        # what triggers the profile-lock dialog we're trying to avoid.
        if sudo_user and os.geteuid() == 0:
            if session_env:
                argv = ["sudo", "-u", sudo_user, "env",
                        *(f"{k}={v}" for k, v in session_env.items()),
                        *argv]
            else:
                argv = ["sudo", "-u", sudo_user, *argv]
        try:
            subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True
        except (OSError, FileNotFoundError):
            return False

    if pref != "auto":
        # User specified a browser command directly. Firefox-family
        # commands get `--new-tab` injected so we don't hit the profile
        # lock on a system that already has Firefox open.
        if _spawn(_browser_argv(pref, url)):
            return True, f"launched '{pref}'"
        return False, f"failed to launch '{pref}' (not on PATH?)"

    # auto: $BROWSER env var (colon-separated list, per xdg spec)
    env_browser = os.environ.get("BROWSER", "")
    for cand in (c.strip() for c in env_browser.split(":") if c.strip()):
        if _spawn(_browser_argv(cand, url)):
            return True, f"launched $BROWSER ({cand})"

    import shutil

    # auto: if Firefox is already running AND on PATH, prefer
    # `firefox --new-tab URL` over xdg-open. xdg-open spawns a fresh
    # firefox process that fights the running instance's profile lock,
    # producing the "Firefox is already running, but is not responding"
    # dialog. Firefox's --new-tab uses remote control to deliver the
    # URL to the existing instance instead — no lock contention.
    if (shutil.which("firefox") and _firefox_is_running()
            and _spawn(["firefox", "--new-tab", url])):
        return True, "launched 'firefox --new-tab' (delivered to running instance)"

    # auto: xdg-open
    if shutil.which("xdg-open") and _spawn(["xdg-open", url]):
        return True, "launched via xdg-open"

    # auto: Python's webbrowser (only useful when not under sudo, since the
    # python3 process can't reach the user's session as root). Returns False
    # if no browser was found.
    try:
        import webbrowser
        if webbrowser.open(url, new=2):
            return True, "launched via webbrowser module"
    except Exception:
        pass

    return False, "no browser launcher worked"
