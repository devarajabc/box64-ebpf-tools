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
        elif path == "/stats":
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
                    self.wfile.write(payload)
                    self.wfile.flush()
                except Exception:
                    # heartbeat to keep the connection alive through proxies
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _state["lock"]:
                if q in _state["sse_clients"]:
                    _state["sse_clients"].remove(q)


def start(port, snapshot_fn, stats_fn, history_interval=3.0, host="127.0.0.1"):
    """Start the HTTP server in a daemon thread.

    snapshot_fn: callable returning the current snapshot dict.
    stats_fn:    callable returning binary/pid metadata.
    """
    _state["snapshot_fn"] = snapshot_fn
    _state["stats_fn"] = stats_fn

    if not _HISTORY_TIMER["started"]:
        _HISTORY_TIMER["started"] = True
        t = threading.Thread(target=_history_loop, args=(history_interval,), daemon=True)
        t.start()

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/"
    print(f"[*] Web dashboard: {url}")

    # Best-effort auto-open. Under sudo, browsers can't reach the user's
    # X/Wayland session — try launching as $SUDO_USER first.
    sudo_user = os.environ.get("SUDO_USER")
    try:
        if sudo_user and os.geteuid() == 0:
            import subprocess
            subprocess.Popen(
                ["sudo", "-u", sudo_user, "xdg-open", url],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        else:
            import webbrowser
            webbrowser.open(url, new=2)
    except Exception:
        pass  # silent fallback — URL is printed above

    return server
