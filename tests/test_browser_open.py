"""Tests for box64_web._open_browser browser-selection logic.

Real subprocess.Popen calls would actually launch a browser, so we
monkeypatch subprocess.Popen and webbrowser.open and assert what *would*
have been launched.
"""
import os

import pytest

import box64_web


class _PopenCapture(list):
    """List subclass that also carries a `fail` flag for the fixture."""
    fail = False


@pytest.fixture
def fake_popen(monkeypatch):
    """Capture subprocess.Popen invocations from inside _open_browser.

    Returns a list-like object of argv lists. By default each call
    'succeeds' (returns a stub); set `fake_popen.fail = True` to make
    every subsequent call raise FileNotFoundError.
    """
    calls = _PopenCapture()

    class _Stub:
        pass

    def _fake(argv, **kwargs):
        calls.append(list(argv))
        if calls.fail:
            raise FileNotFoundError(argv[0])
        return _Stub()

    import subprocess
    monkeypatch.setattr(subprocess, "Popen", _fake)
    return calls


@pytest.fixture
def no_env_browser(monkeypatch):
    """Wipe $BROWSER and $SUDO_USER so 'auto' takes the predictable path."""
    monkeypatch.delenv("BROWSER", raising=False)
    monkeypatch.delenv("SUDO_USER", raising=False)


URL = "http://127.0.0.1:8642/"


class TestNoneSkipsLaunch:
    def test_none_returns_skipped(self, fake_popen, no_env_browser):
        opened, detail = box64_web._open_browser(URL, "none")
        assert opened is False
        assert "skip" in detail.lower()
        assert fake_popen == []  # nothing launched


class TestExplicitBrowser:
    def test_specific_firefox_gets_new_tab_flag(self, fake_popen, no_env_browser):
        # `--browser firefox` must inject `--new-tab` so we route the URL
        # to a running Firefox via remote control instead of starting a
        # fresh process that fights the profile lock.
        opened, detail = box64_web._open_browser(URL, "firefox")
        assert opened is True
        assert "firefox" in detail
        assert fake_popen == [["firefox", "--new-tab", URL]]

    def test_specific_chromium_no_new_tab_flag(self, fake_popen, no_env_browser):
        # Non-Firefox browsers must NOT receive --new-tab (Chromium has
        # its own remote-control protocol; the flag would be misparsed).
        opened, detail = box64_web._open_browser(URL, "chromium")
        assert opened is True
        assert fake_popen == [["chromium", URL]]

    def test_specific_command_failure_returns_false(self, fake_popen, no_env_browser):
        fake_popen.fail = True
        opened, detail = box64_web._open_browser(URL, "nosuchbrowser")
        assert opened is False
        assert "nosuchbrowser" in detail


class TestAutoMode:
    def test_browser_env_var_wins(self, fake_popen, monkeypatch):
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setenv("BROWSER", "chromium")
        opened, detail = box64_web._open_browser(URL, "auto")
        assert opened is True
        assert "chromium" in detail
        assert fake_popen[0] == ["chromium", URL]

    def test_browser_env_var_colon_list(self, fake_popen, monkeypatch):
        # First entry fails, second succeeds.
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setenv("BROWSER", "missing-browser:chromium")
        # Pop's fail flag is global, so we need to reject only the first call.
        original_fail = []

        import subprocess as _sp

        def _selective(argv, **kwargs):
            original_fail.append(list(argv))
            if argv[0] == "missing-browser":
                raise FileNotFoundError("missing-browser")
            return type("_Stub", (), {})()

        monkeypatch.setattr(_sp, "Popen", _selective)
        opened, detail = box64_web._open_browser(URL, "auto")
        assert opened is True
        assert "chromium" in detail
        # Both attempts should have been made in order.
        assert original_fail[0][0] == "missing-browser"
        assert original_fail[1][0] == "chromium"

    def test_falls_back_to_xdg_open(self, fake_popen, no_env_browser, monkeypatch):
        # Force shutil.which to claim xdg-open exists, firefox doesn't.
        monkeypatch.setattr("shutil.which",
                            lambda name: "/usr/bin/xdg-open" if name == "xdg-open" else None)
        # No firefox running, so auto skips the firefox --new-tab branch.
        monkeypatch.setattr(box64_web, "_firefox_is_running", lambda: False)
        opened, detail = box64_web._open_browser(URL, "auto")
        assert opened is True
        assert "xdg-open" in detail
        assert fake_popen == [["xdg-open", URL]]

    def test_running_firefox_uses_new_tab_not_xdg_open(
            self, fake_popen, no_env_browser, monkeypatch):
        # If Firefox is already running, prefer `firefox --new-tab URL`
        # over xdg-open to avoid the profile-lock dialog.
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(box64_web, "_firefox_is_running", lambda: True)
        opened, detail = box64_web._open_browser(URL, "auto")
        assert opened is True
        assert "new-tab" in detail or "running instance" in detail
        # Crucially, firefox --new-tab is what was launched, NOT xdg-open.
        assert fake_popen[0] == ["firefox", "--new-tab", URL]
        assert all("xdg-open" not in c for c in fake_popen)

    def test_no_running_firefox_skips_new_tab_branch(
            self, fake_popen, no_env_browser, monkeypatch):
        # Firefox is on PATH but not running → don't try --new-tab; fall
        # through to xdg-open so the user's actual default browser wins.
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(box64_web, "_firefox_is_running", lambda: False)
        opened, detail = box64_web._open_browser(URL, "auto")
        assert opened is True
        assert "xdg-open" in detail
        # We never tried firefox --new-tab.
        assert all(c[0] != "firefox" for c in fake_popen)

    def test_falls_back_to_webbrowser_module(self, fake_popen, no_env_browser, monkeypatch):
        # No xdg-open, but webbrowser.open succeeds.
        monkeypatch.setattr("shutil.which", lambda name: None)
        called = []

        def _fake_open(url, new=0):
            called.append((url, new))
            return True

        import webbrowser
        monkeypatch.setattr(webbrowser, "open", _fake_open)

        opened, detail = box64_web._open_browser(URL, "auto")
        assert opened is True
        assert "webbrowser" in detail
        assert called == [(URL, 2)]

    def test_returns_false_when_nothing_works(self, fake_popen, no_env_browser, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        import webbrowser
        monkeypatch.setattr(webbrowser, "open", lambda url, new=0: False)

        opened, detail = box64_web._open_browser(URL, "auto")
        assert opened is False
        assert "no browser" in detail.lower()


class TestSudoDropsPrivs:
    def test_sudo_user_wraps_command_no_session_env(self, fake_popen, monkeypatch):
        # Simulate running under sudo with a known SUDO_USER, but no
        # discoverable session env. We should still wrap with sudo -u
        # (just without the env shim).
        monkeypatch.setenv("SUDO_USER", "alice")
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.delenv("BROWSER", raising=False)
        monkeypatch.setattr(box64_web, "_user_session_env", lambda u: {})

        box64_web._open_browser(URL, "firefox")
        assert fake_popen == [["sudo", "-u", "alice", "firefox", "--new-tab", URL]]

    def test_sudo_user_wraps_with_session_env(self, fake_popen, monkeypatch):
        # When _user_session_env finds the user's GUI vars, they must be
        # interpolated through `env K=V K=V` so the sudo'd Firefox can
        # reach the existing session via DBus / XRemote.
        monkeypatch.setenv("SUDO_USER", "alice")
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.delenv("BROWSER", raising=False)
        monkeypatch.setattr(box64_web, "_user_session_env", lambda u: {
            "DISPLAY": ":0",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        })

        box64_web._open_browser(URL, "firefox")
        # `env` shim must appear before the firefox command, with the
        # discovered vars in K=V form.
        assert fake_popen[0][:4] == ["sudo", "-u", "alice", "env"]
        rest = fake_popen[0][4:]
        # Both env entries are present (order is dict insertion order
        # in Py3.7+ but we don't want the test to depend on that).
        env_pairs = rest[:2]
        cmd = rest[2:]
        assert sorted(env_pairs) == sorted([
            "DISPLAY=:0",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        ])
        assert cmd == ["firefox", "--new-tab", URL]

    def test_no_sudo_when_sudo_user_unset(self, fake_popen, no_env_browser, monkeypatch):
        # Even if euid is 0, no SUDO_USER means we don't wrap with sudo -u.
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        box64_web._open_browser(URL, "firefox")
        assert fake_popen == [["firefox", "--new-tab", URL]]


class TestUserSessionEnv:
    """Cover env extraction from /proc/<pid>/environ."""

    def test_returns_empty_when_no_sudo_user(self):
        assert box64_web._user_session_env(None) == {}
        assert box64_web._user_session_env("") == {}

    def test_returns_empty_when_user_unknown(self, monkeypatch):
        import pwd
        def _raise(name):
            raise KeyError(name)
        monkeypatch.setattr(pwd, "getpwnam", _raise)
        assert box64_web._user_session_env("nosuchuser") == {}

    def test_extracts_session_vars_from_proc_environ(self, monkeypatch, tmp_path):
        import pwd
        from io import BytesIO

        # Pretend "alice" is uid 1000.
        class _Pw:
            pw_uid = 1000
        monkeypatch.setattr(pwd, "getpwnam", lambda name: _Pw)

        # Fake /proc with two pids — only pid 1234 is owned by uid 1000.
        monkeypatch.setattr(os, "listdir",
                            lambda p: ["1234", "5678"] if p == "/proc" else [])

        class _Stat:
            def __init__(self, uid):
                self.st_uid = uid

        def fake_stat(path):
            if path == "/proc/1234":
                return _Stat(1000)
            if path == "/proc/5678":
                return _Stat(0)  # owned by root, should be skipped
            raise OSError(path)
        monkeypatch.setattr(os, "stat", fake_stat)

        # /proc/1234/environ has DISPLAY + DBUS, /proc/5678/environ has
        # XAUTHORITY but won't be read (not owned by uid).
        environ_data = (
            b"DISPLAY=:0\x00"
            b"WAYLAND_DISPLAY=wayland-0\x00"
            b"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\x00"
            b"XDG_RUNTIME_DIR=/run/user/1000\x00"
            b"HOME=/home/alice\x00"
            b"XAUTHORITY=/home/alice/.Xauthority\x00"
            b"PATH=/usr/bin:/bin\x00"  # not in _SESSION_ENV_KEYS, ignored
        )

        real_open = open

        def fake_open(path, mode="r", *a, **kw):
            if path == "/proc/1234/environ":
                return BytesIO(environ_data)
            if path == "/proc/5678/environ":
                return BytesIO(b"XAUTHORITY=/should/not/be/seen\x00")
            return real_open(path, mode, *a, **kw)

        import builtins
        monkeypatch.setattr(builtins, "open", fake_open)

        env = box64_web._user_session_env("alice")
        assert env == {
            "DISPLAY": ":0",
            "WAYLAND_DISPLAY": "wayland-0",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
            "XDG_RUNTIME_DIR": "/run/user/1000",
            "HOME": "/home/alice",
            "XAUTHORITY": "/home/alice/.Xauthority",
        }


class TestRegressionSudoFirefoxLockDialog:
    """End-to-end regression for the 'Firefox is already running, but is
    not responding' profile-lock dialog.

    The bug had two halves:
      1. Without `--new-tab`, sudo'd Firefox starts a fresh instance
         that fights the user's existing Firefox over the profile lock.
      2. Even with `--new-tab`, sudo strips the operator's GUI session
         env (DISPLAY, WAYLAND_DISPLAY, DBus address, XDG_RUNTIME_DIR,
         XAUTHORITY) — so the new-tab dispatch can't reach the running
         instance over DBus / XRemote and *also* falls back to a fresh
         process.

    Both halves must be correct simultaneously. This test exercises the
    real `_open_browser` → `_user_session_env` pipeline (no mocking of
    `_user_session_env`) and asserts that the spawned argv contains
    BOTH the `--new-tab` flag AND the session env vars repopulated via
    an `env K=V` shim.
    """

    def test_full_pipeline_carries_new_tab_and_session_env(
            self, fake_popen, monkeypatch):
        import pwd
        from io import BytesIO

        # Set up the regression scenario: tool invoked under sudo by
        # alice (uid 1000), who has Firefox already running.
        monkeypatch.setenv("SUDO_USER", "alice")
        monkeypatch.delenv("BROWSER", raising=False)
        monkeypatch.setattr(os, "geteuid", lambda: 0)

        class _Pw:
            pw_uid = 1000
        monkeypatch.setattr(pwd, "getpwnam",
                            lambda name: _Pw if name == "alice" else (_ for _ in ()).throw(KeyError(name)))

        # Fake /proc: alice's running Firefox at pid 4321 carries the
        # full session env; pid 1 is init owned by root and must be
        # ignored even though it has its own environ.
        monkeypatch.setattr(os, "listdir",
                            lambda p: ["1", "4321"] if p == "/proc" else [])

        real_stat = os.stat

        class _Stat:
            def __init__(self, uid):
                self.st_uid = uid

        proc_uids = {"/proc/1": 0, "/proc/4321": 1000}

        def fake_stat(path, *a, **kw):
            # Only intercept /proc/<pid> stats; everything else (pytest
            # internals, real fs paths) must hit the real os.stat or
            # the test fixture spills into unrelated machinery.
            if str(path) in proc_uids:
                return _Stat(proc_uids[str(path)])
            return real_stat(path, *a, **kw)
        monkeypatch.setattr(os, "stat", fake_stat)

        firefox_environ = (
            b"DISPLAY=:0\x00"
            b"WAYLAND_DISPLAY=wayland-0\x00"
            b"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\x00"
            b"XDG_RUNTIME_DIR=/run/user/1000\x00"
            b"HOME=/home/alice\x00"
            b"XAUTHORITY=/home/alice/.Xauthority\x00"
        )

        real_open = open

        def fake_open(path, mode="r", *a, **kw):
            if path == "/proc/4321/environ":
                return BytesIO(firefox_environ)
            if path == "/proc/1/environ":
                # Root-owned process; should never be read because the
                # uid filter rejects it. If we accidentally do read it,
                # blow up loudly so the regression test catches it.
                raise AssertionError("env extraction read a root-owned /proc entry")
            return real_open(path, mode, *a, **kw)

        import builtins
        monkeypatch.setattr(builtins, "open", fake_open)

        # Trigger the real auto-open path with --browser firefox.
        opened, _detail = box64_web._open_browser(URL, "firefox")
        assert opened is True

        argv = fake_popen[0]

        # Must drop privs to alice via sudo -u.
        assert argv[:3] == ["sudo", "-u", "alice"]
        # Must pass through `env` so the K=V pairs survive sudo.
        assert argv[3] == "env"
        # All six discovered session vars must be present (order-independent).
        env_pairs = set()
        for token in argv[4:]:
            if "=" in token and not token.startswith("--") and token != URL:
                env_pairs.add(token)
            else:
                break  # cmd starts here
        assert env_pairs == {
            "DISPLAY=:0",
            "WAYLAND_DISPLAY=wayland-0",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            "XDG_RUNTIME_DIR=/run/user/1000",
            "HOME=/home/alice",
            "XAUTHORITY=/home/alice/.Xauthority",
        }
        # The actual command must be `firefox --new-tab URL` (both halves
        # of the fix at once: lock-safe flag AND session env).
        assert argv[-3:] == ["firefox", "--new-tab", URL]


class TestBrowserArgv:
    def test_firefox_family_gets_new_tab(self):
        for cmd in ("firefox", "firefox-bin", "firefox-esr",
                    "firefox-developer-edition", "firefox-nightly"):
            assert box64_web._browser_argv(cmd, URL) == [cmd, "--new-tab", URL]

    def test_firefox_with_path_prefix_still_recognized(self):
        # User may pass an absolute path (e.g. via $BROWSER); we strip the
        # dirname before matching, so /usr/bin/firefox still gets --new-tab.
        argv = box64_web._browser_argv("/usr/bin/firefox", URL)
        assert argv == ["/usr/bin/firefox", "--new-tab", URL]

    def test_non_firefox_browsers_unchanged(self):
        for cmd in ("chromium", "google-chrome", "brave", "opera",
                    "epiphany", "qutebrowser"):
            assert box64_web._browser_argv(cmd, URL) == [cmd, URL]


class TestEnvBrowserNewTab:
    def test_browser_env_firefox_gets_new_tab(self, fake_popen, monkeypatch):
        # The `$BROWSER=firefox` resolver path must also inject --new-tab.
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setenv("BROWSER", "firefox")
        opened, _ = box64_web._open_browser(URL, "auto")
        assert opened is True
        assert fake_popen[0] == ["firefox", "--new-tab", URL]


class TestFirefoxIsRunning:
    """Cover the /proc scanner, including Snap/Flatpak/dev-edition flavors."""

    def _fake_proc(self, monkeypatch, entries):
        """Install a fake /proc layout via os/builtins monkeypatching.

        `entries` is a dict: pid_str -> {"comm": str, "cmdline": bytes,
                                          "exe": Optional[str]}.
        """
        monkeypatch.setattr(os, "listdir", lambda path: list(entries.keys())
                            if path == "/proc" else os.listdir.__wrapped__(path)
                            if hasattr(os.listdir, "__wrapped__")
                            else [])

        real_open = open

        def fake_open(path, mode="r", *args, **kwargs):
            for pid, info in entries.items():
                if path == f"/proc/{pid}/comm" and "b" not in mode:
                    from io import StringIO
                    return StringIO(info["comm"] + "\n")
                if path == f"/proc/{pid}/cmdline" and "b" in mode:
                    from io import BytesIO
                    return BytesIO(info["cmdline"])
            return real_open(path, mode, *args, **kwargs)

        import builtins
        monkeypatch.setattr(builtins, "open", fake_open)

        def fake_readlink(path):
            for pid, info in entries.items():
                if path == f"/proc/{pid}/exe":
                    if info.get("exe") is None:
                        raise OSError("no exe")
                    return info["exe"]
            raise OSError("not found")

        monkeypatch.setattr(os, "readlink", fake_readlink)

    def test_detects_plain_firefox(self, monkeypatch):
        self._fake_proc(monkeypatch, {
            "1234": {"comm": "firefox", "cmdline": b"/usr/bin/firefox\x00",
                     "exe": "/usr/bin/firefox"},
        })
        assert box64_web._firefox_is_running() is True

    def test_detects_developer_edition(self, monkeypatch):
        # comm "firefox-developer-edition" matches via comm.startswith("firefox").
        self._fake_proc(monkeypatch, {
            "2222": {"comm": "firefox-developer-edition",
                     "cmdline": b"/opt/firefox-developer/firefox\x00",
                     "exe": "/opt/firefox-developer/firefox"},
        })
        assert box64_web._firefox_is_running() is True

    def test_detects_snap_via_exe_symlink(self, monkeypatch):
        # Snap firefox shows comm that may not start with "firefox", but
        # the /proc/<pid>/exe symlink reveals /snap/firefox/.../firefox.
        self._fake_proc(monkeypatch, {
            "3333": {"comm": "MainThread",  # snap launcher comm
                     "cmdline": b"/snap/firefox/current/usr/lib/firefox/firefox\x00",
                     "exe": "/snap/firefox/current/usr/lib/firefox/firefox"},
        })
        assert box64_web._firefox_is_running() is True

    def test_no_firefox_returns_false(self, monkeypatch):
        self._fake_proc(monkeypatch, {
            "4444": {"comm": "chromium", "cmdline": b"/usr/bin/chromium\x00",
                     "exe": "/usr/bin/chromium"},
            "5555": {"comm": "bash", "cmdline": b"/bin/bash\x00",
                     "exe": "/bin/bash"},
        })
        assert box64_web._firefox_is_running() is False

    def test_unrelated_process_named_firefox_in_comm_only(self, monkeypatch):
        # comm starts with "firefox" but cmdline doesn't mention firefox →
        # should NOT count (false-positive guard).
        self._fake_proc(monkeypatch, {
            "6666": {"comm": "firefox-decoy", "cmdline": b"/usr/local/bin/decoy\x00",
                     "exe": "/usr/local/bin/decoy"},
        })
        assert box64_web._firefox_is_running() is False


# ---------------------------------------------------------------------------
# Realistic (pref × sudo × firefox-running × session-env) matrix.
# These exercise the actual command lines `box64_trace` users hit
# under sudo with various browser preferences and firefox availability.
# (The dashboard is on by default, so no flag is needed to enable it.)
# ---------------------------------------------------------------------------


def _split_env_and_cmd(argv, sudo_user):
    """Split a sudo'd argv into (env_pairs, cmd_argv).

    Expected forms (any of):
      [..., 'sudo', '-u', user, cmd, ...]
      [..., 'sudo', '-u', user, 'env', K=V, ..., cmd, ...]
    """
    assert argv[:3] == ["sudo", "-u", sudo_user]
    if len(argv) >= 4 and argv[3] == "env":
        env_pairs = []
        i = 4
        while i < len(argv) and "=" in argv[i] and not argv[i].startswith("--"):
            env_pairs.append(argv[i])
            i += 1
        return env_pairs, argv[i:]
    return [], argv[3:]


class TestSudoMatrix:
    """The realistic (pref × sudo × firefox-running × session-env) matrix
    that real `box64_trace` invocations hit (dashboard on by default)."""

    SESSION_ENV = {
        "DISPLAY": ":0",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "XDG_RUNTIME_DIR": "/run/user/1000",
    }

    @pytest.fixture
    def under_sudo(self, monkeypatch):
        monkeypatch.setenv("SUDO_USER", "alice")
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.delenv("BROWSER", raising=False)
        monkeypatch.setattr(box64_web, "_user_session_env",
                            lambda u: dict(self.SESSION_ENV))

    def test_none_under_sudo_still_skips_no_spawn(
            self, fake_popen, under_sudo):
        opened, detail = box64_web._open_browser(URL, "none")
        assert opened is False
        assert "skip" in detail.lower()
        assert fake_popen == []  # no spawn, even with SUDO_USER set

    def test_chromium_under_sudo_with_session_env(
            self, fake_popen, under_sudo):
        # The env shim must apply to non-Firefox browsers too — they
        # equally need DISPLAY/DBus to reach the user's session.
        opened, _ = box64_web._open_browser(URL, "chromium")
        assert opened is True
        env_pairs, cmd = _split_env_and_cmd(fake_popen[0], "alice")
        assert sorted(env_pairs) == sorted(
            f"{k}={v}" for k, v in self.SESSION_ENV.items())
        # Chromium does NOT receive --new-tab.
        assert cmd == ["chromium", URL]

    def test_auto_sudo_firefox_running_full_pipeline(
            self, fake_popen, under_sudo, monkeypatch):
        # The most common path: user has Firefox open, runs
        # `sudo box64_trace` (dashboard on by default, no --browser),
        # tracer auto-resolves to firefox --new-tab via
        # _firefox_is_running()=True.
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(box64_web, "_firefox_is_running", lambda: True)
        opened, _ = box64_web._open_browser(URL, "auto")
        assert opened is True
        env_pairs, cmd = _split_env_and_cmd(fake_popen[0], "alice")
        assert sorted(env_pairs) == sorted(
            f"{k}={v}" for k, v in self.SESSION_ENV.items())
        assert cmd == ["firefox", "--new-tab", URL]

    def test_auto_sudo_no_firefox_falls_to_xdg_open_with_env_shim(
            self, fake_popen, under_sudo, monkeypatch):
        # No Firefox running, so auto resolves to xdg-open. The env
        # shim still applies — xdg-open also needs DISPLAY/DBus to
        # consult the user's preferred-browser MIME settings.
        monkeypatch.setattr("shutil.which",
                            lambda name: "/usr/bin/xdg-open" if name == "xdg-open" else None)
        monkeypatch.setattr(box64_web, "_firefox_is_running", lambda: False)
        opened, _ = box64_web._open_browser(URL, "auto")
        assert opened is True
        env_pairs, cmd = _split_env_and_cmd(fake_popen[0], "alice")
        assert sorted(env_pairs) == sorted(
            f"{k}={v}" for k, v in self.SESSION_ENV.items())
        assert cmd == ["xdg-open", URL]

    def test_browser_colon_list_under_sudo_first_fails_second_wins(
            self, monkeypatch, under_sudo):
        # $BROWSER='missing-browser:firefox' under sudo: first attempt
        # raises FileNotFoundError, second succeeds with the env shim
        # AND --new-tab injected.
        monkeypatch.setenv("BROWSER", "missing-browser:firefox")
        attempts = []

        import subprocess as _sp

        def _selective(argv, **kwargs):
            attempts.append(list(argv))
            cmd = argv[-1] if not argv[-1].startswith("http") else argv[-2]
            if "missing-browser" in argv:
                raise FileNotFoundError("missing-browser")
            return type("_Stub", (), {})()

        monkeypatch.setattr(_sp, "Popen", _selective)
        opened, _ = box64_web._open_browser(URL, "auto")
        assert opened is True

        # First attempt: tried missing-browser (with sudo+env shim).
        env_pairs1, cmd1 = _split_env_and_cmd(attempts[0], "alice")
        assert sorted(env_pairs1) == sorted(
            f"{k}={v}" for k, v in self.SESSION_ENV.items())
        assert cmd1 == ["missing-browser", URL]

        # Second attempt: firefox with --new-tab (and sudo+env shim).
        env_pairs2, cmd2 = _split_env_and_cmd(attempts[1], "alice")
        assert sorted(env_pairs2) == sorted(
            f"{k}={v}" for k, v in self.SESSION_ENV.items())
        assert cmd2 == ["firefox", "--new-tab", URL]


# ---------------------------------------------------------------------------
# `_user_session_env` robustness — real /proc is messy, so make sure
# the scanner gracefully handles partial data, malformed entries, and
# the special characters that show up in DBus addresses.
# ---------------------------------------------------------------------------


class TestUserSessionEnvRobustness:
    @pytest.fixture(autouse=True)
    def _alice(self, monkeypatch):
        import pwd

        class _Pw:
            pw_uid = 1000
        monkeypatch.setattr(pwd, "getpwnam", lambda name: _Pw)

    def _stub_proc(self, monkeypatch, environs):
        """environs: dict pid_str -> bytes (or Exception subclass to raise).

        All listed pids are owned by uid 1000. Stubs os.listdir + os.stat
        + builtins.open, falling through to the real implementations for
        non-/proc paths.
        """
        from io import BytesIO

        monkeypatch.setattr(os, "listdir",
                            lambda p: list(environs.keys()) if p == "/proc" else [])

        real_stat = os.stat

        class _Stat:
            st_uid = 1000

        def fake_stat(path, *a, **kw):
            if any(str(path) == f"/proc/{pid}" for pid in environs):
                return _Stat()
            return real_stat(path, *a, **kw)
        monkeypatch.setattr(os, "stat", fake_stat)

        real_open = open

        def fake_open(path, mode="r", *a, **kw):
            for pid, val in environs.items():
                if path == f"/proc/{pid}/environ":
                    if isinstance(val, type) and issubclass(val, OSError):
                        raise val("simulated")
                    return BytesIO(val)
            return real_open(path, mode, *a, **kw)

        import builtins
        monkeypatch.setattr(builtins, "open", fake_open)

    def test_skips_process_with_unreadable_environ(self, monkeypatch):
        # Process 1111 vanished mid-scan (environ raises OSError); 2222
        # still has the data. Scanner must skip 1111 and continue.
        self._stub_proc(monkeypatch, {
            "1111": OSError,  # raises on open
            "2222": b"DISPLAY=:0\x00",
        })
        env = box64_web._user_session_env("alice")
        assert env == {"DISPLAY": ":0"}

    def test_ignores_malformed_environ_entries(self, monkeypatch):
        # Mix of valid K=V, bare tokens (no '='), and a binary blob.
        # Only the well-formed entries with keys in _SESSION_ENV_KEYS
        # are picked up.
        self._stub_proc(monkeypatch, {
            "3000": (b"DISPLAY=:0\x00"
                     b"NO_EQUALS_HERE\x00"
                     b"\xff\xfe\xfd\x00"
                     b"HOME=/home/alice\x00"),
        })
        env = box64_web._user_session_env("alice")
        assert env == {"DISPLAY": ":0", "HOME": "/home/alice"}

    def test_preserves_value_containing_equals_sign(self, monkeypatch):
        # The DBus address has multiple '=' characters; we must only
        # split on the FIRST one, so the value is preserved verbatim.
        addr = "unix:path=/run/user/1000/bus,guid=abc123def456"
        self._stub_proc(monkeypatch, {
            "4000": f"DBUS_SESSION_BUS_ADDRESS={addr}\x00".encode(),
        })
        env = box64_web._user_session_env("alice")
        assert env == {"DBUS_SESSION_BUS_ADDRESS": addr}

    def test_walks_multiple_user_processes_to_fill_keys(self, monkeypatch):
        # First process has only DISPLAY; second has WAYLAND_DISPLAY.
        # The scanner must keep going across pids until all desired
        # keys are filled (or we run out of pids).
        self._stub_proc(monkeypatch, {
            "5000": b"DISPLAY=:0\x00",
            "5001": b"WAYLAND_DISPLAY=wayland-0\x00HOME=/home/alice\x00",
        })
        env = box64_web._user_session_env("alice")
        assert env == {
            "DISPLAY": ":0",
            "WAYLAND_DISPLAY": "wayland-0",
            "HOME": "/home/alice",
        }

    def test_accepts_empty_value_after_equals(self, monkeypatch):
        # `WAYLAND_DISPLAY=` with empty value is legal; record it.
        # (Empty here just means the user is purely on X11; we still
        # carry the var through so the sudo'd browser sees the right
        # state rather than inheriting whatever sudo had.)
        self._stub_proc(monkeypatch, {
            "6000": b"DISPLAY=:0\x00WAYLAND_DISPLAY=\x00",
        })
        env = box64_web._user_session_env("alice")
        assert env == {"DISPLAY": ":0", "WAYLAND_DISPLAY": ""}


# ---------------------------------------------------------------------------
# `_firefox_is_running` robustness — sandboxed /proc, missing files,
# readlink failures shouldn't crash or false-positive.
# ---------------------------------------------------------------------------


class TestFirefoxIsRunningRobustness:
    def test_proc_unreadable_returns_false(self, monkeypatch):
        # In a hardened/sandboxed environment, /proc may not be
        # readable at all. The scanner must catch the OSError and
        # return False, not propagate.
        def _raise(_path):
            raise OSError("permission denied")
        monkeypatch.setattr(os, "listdir", _raise)
        assert box64_web._firefox_is_running() is False

    def test_pid_dir_without_comm_is_skipped(self, monkeypatch):
        # PID directory exists but the comm file is missing (TOCTOU
        # — process exited between listdir and open). Skip and
        # continue to the next pid.
        from io import BytesIO

        monkeypatch.setattr(os, "listdir",
                            lambda p: ["7000", "7001"] if p == "/proc" else [])

        real_open = open

        def fake_open(path, mode="r", *a, **kw):
            if path == "/proc/7000/comm":
                raise OSError("vanished")
            if path == "/proc/7001/comm":
                from io import StringIO
                return StringIO("firefox\n")
            if path == "/proc/7001/cmdline":
                return BytesIO(b"/usr/bin/firefox\x00")
            return real_open(path, mode, *a, **kw)

        import builtins
        monkeypatch.setattr(builtins, "open", fake_open)
        # readlink not needed here; comm matches firefox directly.
        monkeypatch.setattr(os, "readlink",
                            lambda p: (_ for _ in ()).throw(OSError("never")))
        assert box64_web._firefox_is_running() is True

    def test_exe_readlink_failure_is_skipped(self, monkeypatch):
        # comm doesn't match firefox-family, so the scanner falls back
        # to /proc/<pid>/exe — but that readlink also fails. Must skip,
        # not return True or crash.
        from io import StringIO

        monkeypatch.setattr(os, "listdir",
                            lambda p: ["8000"] if p == "/proc" else [])

        real_open = open

        def fake_open(path, mode="r", *a, **kw):
            if path == "/proc/8000/comm":
                return StringIO("some-other-process\n")
            return real_open(path, mode, *a, **kw)

        import builtins
        monkeypatch.setattr(builtins, "open", fake_open)
        monkeypatch.setattr(os, "readlink",
                            lambda p: (_ for _ in ()).throw(OSError("vanished")))
        assert box64_web._firefox_is_running() is False
