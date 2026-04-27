"""Verify box64_trace BPF compile fallback distinguishes genuine
TRACK_PROFILE / BCC incompatibility from unrelated BCC/kernel errors
(B2). Previously the fallback caught `Exception` unconditionally and
always blamed TRACK_PROFILE when `--sample-freq` was set, masking
missing-header, kernel-version, and permission errors.
"""
import pytest

import box64_trace


class _StopMain(BaseException):
    """Stops main() once the assertions we care about are already
    checkable.  Inherits from BaseException so the production
    ``except Exception`` blocks never swallow it.
    """


def _setup_main_mocks(monkeypatch):
    """Stub the heavy side-effectful helpers main() runs before BPF()."""
    monkeypatch.setattr(box64_trace, "check_binary", lambda *a, **kw: None)
    monkeypatch.setattr(box64_trace, "check_symbols", lambda *a, **kw: True)
    monkeypatch.setattr(box64_trace, "check_symbols_soft", lambda *a, **kw: [])
    monkeypatch.setattr(box64_trace, "_read_symbols", lambda *a, **kw: "")
    monkeypatch.setattr(box64_trace, "_clear_stale_uprobes", lambda *a, **kw: None)
    monkeypatch.setattr(box64_trace, "_patch_bcc_uretprobe", lambda *a, **kw: None)
    monkeypatch.setattr(box64_trace, "_bcc_has_atomic_increment", lambda: True)


def _install_mock_bpf(monkeypatch, side_effects):
    """Install a mock BPF() that consumes `side_effects` in order.

    Each element is either an exception instance (raised on that call)
    or None (simulates success; we raise _StopMain so main() halts).
    Returns the list that will accumulate per-call cflags.
    """
    calls = []

    def mock_bpf(*args, **kwargs):
        calls.append(kwargs.get("cflags", []))
        idx = len(calls) - 1
        if idx < len(side_effects) and side_effects[idx] is not None:
            raise side_effects[idx]
        raise _StopMain()

    monkeypatch.setattr(box64_trace, "BPF", mock_bpf)
    return calls


class TestBpfCompileFallback:
    def test_non_profile_error_with_sample_freq_reraises(self, monkeypatch):
        """A missing-kernel-header failure must propagate even with
        --sample-freq set: it is not a TRACK_PROFILE incompatibility."""
        monkeypatch.setattr("sys.argv", ["prog", "--sample-freq", "99"])
        _setup_main_mocks(monkeypatch)
        err = RuntimeError(
            "failed to load BPF program: missing kernel header asm/types.h"
        )
        calls = _install_mock_bpf(monkeypatch, [err])

        with pytest.raises(RuntimeError, match="missing kernel header"):
            box64_trace.main()

        assert len(calls) == 1, "must not retry on unrelated errors"

    def test_profile_error_triggers_retry_without_track_profile(self, monkeypatch):
        """An error mentioning profile-specific identifiers causes a
        retry with -DTRACK_PROFILE and -DPROFILE_CAPACITY stripped."""
        monkeypatch.setattr("sys.argv", ["prog", "--sample-freq", "99"])
        _setup_main_mocks(monkeypatch)
        err = Exception("error: redefinition of 'struct bpf_perf_event_data'")
        calls = _install_mock_bpf(monkeypatch, [err, None])

        with pytest.raises(_StopMain):
            box64_trace.main()

        assert len(calls) == 2
        assert any("TRACK_PROFILE" in f for f in calls[0])
        assert not any("TRACK_PROFILE" in f for f in calls[1])
        assert not any("PROFILE_CAPACITY" in f for f in calls[1])

    def test_profile_error_on_perf_sample_marker_retries(self, monkeypatch):
        """The 'on_perf_sample' function name is a second profile-specific
        marker; its presence in the error must also trigger retry."""
        monkeypatch.setattr("sys.argv", ["prog", "--sample-freq", "99"])
        _setup_main_mocks(monkeypatch)
        err = Exception("compile error near on_perf_sample")
        calls = _install_mock_bpf(monkeypatch, [err, None])

        with pytest.raises(_StopMain):
            box64_trace.main()

        assert len(calls) == 2

    def test_retry_failure_wraps_both_errors(self, monkeypatch):
        """If retry also fails, raise a RuntimeError that mentions the
        original error and chains the retry error via __cause__."""
        monkeypatch.setattr("sys.argv", ["prog", "--sample-freq", "99"])
        _setup_main_mocks(monkeypatch)
        orig = Exception("error: cannot emit bpf_perf_event_data")
        retry = Exception("error: kernel out of memory")
        calls = _install_mock_bpf(monkeypatch, [orig, retry])

        with pytest.raises(RuntimeError, match="even after disabling TRACK_PROFILE") as exc_info:
            box64_trace.main()

        assert "cannot emit bpf_perf_event_data" in str(exc_info.value)
        assert exc_info.value.__cause__ is retry
        assert len(calls) == 2

    def test_error_without_sample_freq_reraises(self, monkeypatch):
        """Without --sample-freq, any BPF error must propagate without
        retry — track_profile is False so the fallback branch is skipped."""
        monkeypatch.setattr("sys.argv", ["prog"])
        _setup_main_mocks(monkeypatch)
        err = Exception("any random BPF compile error")
        calls = _install_mock_bpf(monkeypatch, [err])

        with pytest.raises(Exception, match="any random BPF compile error"):
            box64_trace.main()

        assert len(calls) == 1
