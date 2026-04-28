"""Tests for spawn-and-trace mode helpers in box64_trace.

`_spawn_paused` does real fork+SIGSTOP+execvp, so these tests fork actual
child processes. No root or BCC needed — the helpers are pure POSIX.
"""
import os
import signal
import sys
import time

import pytest

import box64_trace


# ---------------------------------------------------------------------------
# _resolve_box64_binary
# ---------------------------------------------------------------------------

class TestResolveBox64Binary:
    def test_existing_path_unchanged(self, tmp_path):
        fake = tmp_path / "box64"
        fake.write_text("")  # any existing file passes
        assert box64_trace._resolve_box64_binary(str(fake)) == str(fake)

    def test_missing_falls_back_to_which(self, monkeypatch, tmp_path):
        # Provide a fake `which box64` result.
        fake_which = str(tmp_path / "from_path")
        monkeypatch.setattr("shutil.which",
                            lambda name: fake_which if name == "box64" else None)
        result = box64_trace._resolve_box64_binary("/nonexistent/box64")
        assert result == fake_which

    def test_missing_with_no_which_returns_input(self, monkeypatch):
        # If neither default nor PATH has box64, return the original so
        # check_binary fails downstream with a clear "not found" message.
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert (box64_trace._resolve_box64_binary("/nope/box64")
                == "/nope/box64")

    def test_default_path_when_present(self):
        # Real-world sanity: if the default path exists on this host, we
        # don't reach the fallback.
        if os.path.exists("/usr/local/bin/box64"):
            assert (box64_trace._resolve_box64_binary("/usr/local/bin/box64")
                    == "/usr/local/bin/box64")
        else:
            pytest.skip("no /usr/local/bin/box64 on this host")


# ---------------------------------------------------------------------------
# _spawn_paused
# ---------------------------------------------------------------------------

def _read_proc_state(pid):
    """Return the State field from /proc/<pid>/status, e.g. 'T' for stopped."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("State:"):
                    # 'State:\tT (stopped)' → 'T'
                    return line.split()[1]
    except FileNotFoundError:
        return None
    return None


def _wait_for_state(pid, want, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _read_proc_state(pid) == want:
            return True
        time.sleep(0.01)
    return False


@pytest.mark.skipif(sys.platform != "linux",
                    reason="requires /proc and POSIX fork semantics")
class TestSpawnPaused:
    def test_child_is_stopped_before_exec(self):
        pid = box64_trace._spawn_paused(["/bin/true"])
        try:
            # Child should be in T (stopped) state, *not* yet exec'd.
            # /proc/<pid>/comm reflects the parent's name (python) until exec.
            state = _read_proc_state(pid)
            assert state == "T", f"expected stopped child, got state={state!r}"
        finally:
            # Always resume + reap so we don't leak a process.
            try:
                os.kill(pid, signal.SIGCONT)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass

    def test_sigcont_resumes_and_runs_to_completion(self, tmp_path):
        # Use a shell command that writes a sentinel to a tempfile, so we
        # can prove the *post-SIGCONT* exec actually happened.
        sentinel = tmp_path / "ran"
        pid = box64_trace._spawn_paused(
            ["/bin/sh", "-c", f"echo ran > {sentinel} && exit 42"])

        # Pre-SIGCONT: sentinel must NOT exist (proves the gate held).
        time.sleep(0.05)  # give exec a chance to run if the gate were broken
        assert not sentinel.exists(), \
            "sentinel exists before SIGCONT — gate failed to hold child"

        os.kill(pid, signal.SIGCONT)
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status), f"child did not exit normally: {status:#x}"
        assert os.WEXITSTATUS(status) == 42
        assert sentinel.read_text().strip() == "ran"

    def test_bad_command_exits_127(self):
        # Nonexistent binary → execvp raises OSError → child does os._exit(127).
        pid = box64_trace._spawn_paused(
            ["/this/does/not/exist/box64_trace_test_helper"])
        os.kill(pid, signal.SIGCONT)
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 127

    def test_passes_argv_through(self, tmp_path):
        # Verify all argv elements reach the executed program intact.
        out = tmp_path / "argv"
        pid = box64_trace._spawn_paused([
            "/bin/sh", "-c",
            f'printf "%s\\n" "$@" > {out}',
            "_argv0_", "alpha", "beta gamma", "--flag=x",
        ])
        os.kill(pid, signal.SIGCONT)
        os.waitpid(pid, 0)
        assert out.read_text().splitlines() == [
            "alpha", "beta gamma", "--flag=x",
        ]
