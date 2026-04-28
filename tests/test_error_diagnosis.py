"""Tests for box64_common.diagnose_bpf_error and report_fatal.

These map common BPF/BCC error strings to actionable hints. The
function is pattern-matching on str(exc), so the tests construct
exceptions with realistic messages and assert the right diagnosis
fires — and that unrecognised messages return None (so the top-level
handler falls back to "unexpected, please file an issue").
"""
import pytest

from box64_common import (
    BCC_INSTALL_URL,
    REPO_ISSUES_URL,
    diagnose_bpf_error,
    report_fatal,
)


# ---------------------------------------------------------------------------
# diagnose_bpf_error
# ---------------------------------------------------------------------------

class TestPermissionDiagnosis:
    @pytest.mark.parametrize("msg", [
        "Operation not permitted",
        "operation not permitted (error -1)",
        "open: Permission denied",
        "PERMISSION DENIED on /sys/kernel/...",
    ])
    def test_perm_messages_caught(self, msg):
        diag = diagnose_bpf_error(Exception(msg))
        assert diag is not None
        summary, hint = diag
        assert "root" in summary.lower() or "CAP" in summary
        assert "sudo" in hint.lower() or "setcap" in hint.lower()


class TestKernelHeadersDiagnosis:
    @pytest.mark.parametrize("msg", [
        "/lib/modules/6.18.15/build: No such file or directory",
        "kernel headers not found at /usr/include/linux",
    ])
    def test_missing_headers_caught(self, msg):
        diag = diagnose_bpf_error(Exception(msg))
        assert diag is not None
        summary, hint = diag
        assert "header" in summary.lower()
        assert "linux-headers" in hint or "kernel-devel" in hint


class TestKernelABIMismatch:
    def test_kallsyms_caught(self):
        diag = diagnose_bpf_error(Exception("failed to read /proc/kallsyms"))
        assert diag is not None
        summary, _ = diag
        assert "version mismatch" in summary.lower() \
               or "abi" in summary.lower() \
               or "mismatch" in summary.lower()

    def test_kprobe_not_exist_caught(self):
        diag = diagnose_bpf_error(
            Exception("kprobe foo does not exist on this kernel"))
        assert diag is not None


class TestSymbolMissing:
    @pytest.mark.parametrize("msg", [
        "could not find symbol customMalloc in shared object box64",
        "unknown symbol AllocDynarecMap in binary /usr/local/bin/box64",
        "could not find sym in libfoo.so",
    ])
    def test_symbol_messages_caught(self, msg):
        diag = diagnose_bpf_error(Exception(msg))
        assert diag is not None
        summary, hint = diag
        assert "symbol" in summary.lower()
        assert "RelWithDebInfo" in hint or "debug" in hint.lower()


class TestUnsupportedKernel:
    def test_btf_not_supported(self):
        diag = diagnose_bpf_error(
            Exception("BTF info not present in kernel"))
        assert diag is not None
        summary, _ = diag
        assert "BTF" in summary or "BPF" in summary

    def test_operation_not_supported(self):
        diag = diagnose_bpf_error(Exception("Operation not supported"))
        assert diag is not None


class TestUnrecognised:
    @pytest.mark.parametrize("msg", [
        "",
        "totally random error message",
        "ConnectionRefusedError",
        "TypeError: 'NoneType' object is not callable",
    ])
    def test_returns_none_for_unrecognised(self, msg):
        # Unrecognised → None, so the top-level handler can fall back to
        # the "unexpected, please report" path.
        assert diagnose_bpf_error(Exception(msg)) is None


# ---------------------------------------------------------------------------
# report_fatal
# ---------------------------------------------------------------------------

class TestReportFatal:
    def test_returns_exit_code_1(self, capsys):
        rc = report_fatal(RuntimeError("boom"))
        assert rc == 1

    def test_recognised_error_gets_hint_no_traceback(self, capsys, monkeypatch):
        monkeypatch.delenv("BOX64_TRACE_DEBUG", raising=False)
        report_fatal(Exception("Operation not permitted"))
        err = capsys.readouterr().err
        assert "FATAL" in err
        assert "root" in err.lower() or "CAP" in err
        assert "Hint:" in err or "→" in err
        # No traceback when we have a clean diagnosis.
        assert "Traceback" not in err

    def test_unrecognised_points_at_issues_url(self, capsys, monkeypatch):
        monkeypatch.delenv("BOX64_TRACE_DEBUG", raising=False)
        report_fatal(RuntimeError("something weird"))
        err = capsys.readouterr().err
        assert REPO_ISSUES_URL in err
        assert "BOX64_TRACE_DEBUG" in err
        # No traceback unless debug is set.
        assert "Traceback" not in err

    def test_debug_flag_includes_traceback(self, capsys):
        try:
            raise RuntimeError("for traceback")
        except RuntimeError as e:
            report_fatal(e, debug=True)
        err = capsys.readouterr().err
        assert "Traceback" in err
        assert "RuntimeError" in err

    def test_env_var_enables_traceback(self, capsys, monkeypatch):
        monkeypatch.setenv("BOX64_TRACE_DEBUG", "1")
        try:
            raise RuntimeError("env-driven traceback")
        except RuntimeError as e:
            report_fatal(e)
        err = capsys.readouterr().err
        assert "Traceback" in err
