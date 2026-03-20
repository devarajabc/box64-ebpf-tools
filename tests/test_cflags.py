"""Verify that CLI args produce the correct BPF cflags.

Tests the real main() code path by mocking out all system dependencies
(binary checks, symbol checks, BCC, etc.) and capturing the cflags
passed to BPF(text=..., cflags=...).
"""
import pytest

import box64_dynarec
import box64_memleak
import box64_steam


class _CflagsCapture(BaseException):
    """Raised by mock BPF to stop main() after capturing cflags.

    Inherits from BaseException (not Exception) so that production
    try/except Exception blocks don't accidentally catch it.
    """
    pass


def _setup_mocks(monkeypatch, module, argv):
    """Monkeypatch all system dependencies so main() can run without root.

    Returns a dict that will contain {'cflags': [...]} after main() is called.
    """
    monkeypatch.setattr("sys.argv", ["prog"] + argv)

    # Stub out binary/symbol checks
    monkeypatch.setattr(module, "check_binary", lambda *a, **kw: None)
    monkeypatch.setattr(module, "check_symbols", lambda *a, **kw: True)
    monkeypatch.setattr(module, "check_symbols_soft", lambda *a, **kw: [])
    monkeypatch.setattr(module, "_read_symbols", lambda *a, **kw: "")
    monkeypatch.setattr(module, "_clear_stale_uprobes", lambda *a, **kw: None)
    monkeypatch.setattr(module, "_patch_bcc_uretprobe", lambda *a, **kw: None)

    # Only dynarec and steam have these
    if hasattr(module, "_bcc_has_atomic_increment"):
        monkeypatch.setattr(module, "_bcc_has_atomic_increment", lambda: True)

    # dynarec-specific
    if hasattr(module, "check_dynarec_symbols"):
        monkeypatch.setattr(module, "check_dynarec_symbols", lambda *a, **kw: None)

    # Mock BPF to capture cflags and stop execution
    captured = {}

    def mock_bpf(*args, **kwargs):
        captured["cflags"] = kwargs.get("cflags", [])
        raise _CflagsCapture()

    monkeypatch.setattr(module, "BPF", mock_bpf)
    return captured


def _run_main(module, monkeypatch, argv):
    """Run module's main() with mocked deps, return captured cflags."""
    captured = _setup_mocks(monkeypatch, module, argv)
    with pytest.raises(_CflagsCapture):
        module.main()
    return captured["cflags"]


def _cflag_names(cflags):
    """Extract just the define names: '-DTRACK_PROT' -> 'TRACK_PROT'."""
    names = set()
    for f in cflags:
        if f.startswith("-D"):
            names.add(f[2:].split("=")[0])
    return names


def _cflag_value(cflags, name):
    """Get the value for a -DNAME=VALUE flag, or None if absent."""
    for f in cflags:
        if f.startswith(f"-D{name}="):
            return f.split("=", 1)[1]
    return None


# ---------------------------------------------------------------------------
# box64_dynarec
# ---------------------------------------------------------------------------

class TestDynarecCflags:
    def test_defaults(self, monkeypatch):
        cflags = _run_main(box64_dynarec, monkeypatch, [])
        names = _cflag_names(cflags)
        assert "CHURN_THRESHOLD_NS" in names
        assert "HASH_CAPACITY" in names
        assert "TRACK_PROT" in names
        assert "TRACK_THREADS" in names
        assert "TRACK_COW" in names
        assert "FILTER_PID" not in names

    def test_no_prot(self, monkeypatch):
        cflags = _run_main(box64_dynarec, monkeypatch, ["--no-prot"])
        assert "TRACK_PROT" not in _cflag_names(cflags)

    def test_no_threads(self, monkeypatch):
        cflags = _run_main(box64_dynarec, monkeypatch, ["--no-threads"])
        assert "TRACK_THREADS" not in _cflag_names(cflags)

    def test_no_cow(self, monkeypatch):
        cflags = _run_main(box64_dynarec, monkeypatch, ["--no-cow"])
        assert "TRACK_COW" not in _cflag_names(cflags)

    def test_pid_filter(self, monkeypatch):
        cflags = _run_main(box64_dynarec, monkeypatch, ["-p", "1234"])
        names = _cflag_names(cflags)
        assert "FILTER_PID" in names
        assert _cflag_value(cflags, "FILTER_PID") == "1234"

    def test_churn_threshold(self, monkeypatch):
        cflags = _run_main(box64_dynarec, monkeypatch, ["--churn-threshold", "2.5"])
        val = _cflag_value(cflags, "CHURN_THRESHOLD_NS")
        assert val == "2500000000ULL"

    def test_hash_capacity(self, monkeypatch):
        cflags = _run_main(box64_dynarec, monkeypatch, ["--hash-capacity", "1000000"])
        assert _cflag_value(cflags, "HASH_CAPACITY") == "1000000"


# ---------------------------------------------------------------------------
# box64_memleak
# ---------------------------------------------------------------------------

class TestMemleakCflags:
    def test_defaults(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, [])
        names = _cflag_names(cflags)
        assert "HASH_CAPACITY" in names
        assert "TRACK_THREADS" in names
        assert "TRACK_COW" in names
        # Optional features off by default
        assert "CAPTURE_STACKS" not in names
        assert "TRACK_MMAP" not in names
        assert "TRACK_32BIT" not in names
        assert "FILTER_PID" not in names

    def test_stacks(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, ["--stacks"])
        assert "CAPTURE_STACKS" in _cflag_names(cflags)

    def test_mmap(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, ["--mmap"])
        assert "TRACK_MMAP" in _cflag_names(cflags)

    def test_32bit(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, ["--32bit"])
        assert "TRACK_32BIT" in _cflag_names(cflags)

    def test_no_threads(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, ["--no-threads"])
        assert "TRACK_THREADS" not in _cflag_names(cflags)

    def test_no_cow(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, ["--no-cow"])
        assert "TRACK_COW" not in _cflag_names(cflags)

    def test_pid_filter(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, ["-p", "5678"])
        names = _cflag_names(cflags)
        assert "FILTER_PID" in names
        assert _cflag_value(cflags, "FILTER_PID") == "5678"

    def test_hash_capacity(self, monkeypatch):
        cflags = _run_main(box64_memleak, monkeypatch, ["--hash-capacity", "262144"])
        assert _cflag_value(cflags, "HASH_CAPACITY") == "262144"


# ---------------------------------------------------------------------------
# box64_steam
# ---------------------------------------------------------------------------

class TestSteamCflags:
    def test_defaults(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, [])
        names = _cflag_names(cflags)
        assert "HASH_CAPACITY" in names
        assert "CHURN_THRESHOLD_NS" in names
        assert "TRACK_MEM" in names
        assert "TRACK_DYNAREC" in names
        assert "TRACK_PROT" in names
        assert "TRACK_BLOCK_DETAIL" in names
        assert "TRACK_MMAP" in names
        assert "TRACK_THREADS" in names
        assert "TRACK_COW" in names
        # Off by default
        assert "FILTER_PID" not in names
        assert "TRACK_PROFILE" not in names

    def test_no_mem(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--no-mem"])
        assert "TRACK_MEM" not in _cflag_names(cflags)

    def test_no_dynarec(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--no-dynarec"])
        names = _cflag_names(cflags)
        assert "TRACK_DYNAREC" not in names
        # prot and block detail depend on dynarec
        assert "TRACK_PROT" not in names
        assert "TRACK_BLOCK_DETAIL" not in names

    def test_no_mmap(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--no-mmap"])
        assert "TRACK_MMAP" not in _cflag_names(cflags)

    def test_no_threads(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--no-threads"])
        assert "TRACK_THREADS" not in _cflag_names(cflags)

    def test_no_cow(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--no-cow"])
        assert "TRACK_COW" not in _cflag_names(cflags)

    def test_no_prot(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--no-prot"])
        assert "TRACK_PROT" not in _cflag_names(cflags)

    def test_no_block_detail(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--no-block-detail"])
        assert "TRACK_BLOCK_DETAIL" not in _cflag_names(cflags)

    def test_pid_filter(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["-p", "9999"])
        names = _cflag_names(cflags)
        assert "FILTER_PID" in names
        assert _cflag_value(cflags, "FILTER_PID") == "9999"

    def test_sample_freq(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--sample-freq", "4999"])
        names = _cflag_names(cflags)
        assert "TRACK_PROFILE" in names
        assert "PROFILE_CAPACITY" in names

    def test_churn_threshold(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--churn-threshold", "0.5"])
        val = _cflag_value(cflags, "CHURN_THRESHOLD_NS")
        assert val == "500000000ULL"

    def test_hash_capacity(self, monkeypatch):
        cflags = _run_main(box64_steam, monkeypatch, ["--hash-capacity", "131072"])
        assert _cflag_value(cflags, "HASH_CAPACITY") == "131072"
