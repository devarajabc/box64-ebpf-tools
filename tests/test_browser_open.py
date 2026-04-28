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
    def test_specific_command_is_launched(self, fake_popen, no_env_browser):
        opened, detail = box64_web._open_browser(URL, "firefox")
        assert opened is True
        assert "firefox" in detail
        assert fake_popen == [["firefox", URL]]

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
    def test_sudo_user_wraps_command(self, fake_popen, monkeypatch):
        # Simulate running under sudo with a known SUDO_USER.
        monkeypatch.setenv("SUDO_USER", "alice")
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.delenv("BROWSER", raising=False)

        box64_web._open_browser(URL, "firefox")
        assert fake_popen == [["sudo", "-u", "alice", "firefox", URL]]

    def test_no_sudo_when_sudo_user_unset(self, fake_popen, no_env_browser, monkeypatch):
        # Even if euid is 0, no SUDO_USER means we don't wrap with sudo -u.
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        box64_web._open_browser(URL, "firefox")
        assert fake_popen == [["firefox", URL]]
