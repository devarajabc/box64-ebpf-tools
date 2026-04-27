"""Tests for symbol-checking functions: check_binary, _read_symbols,
check_symbols, check_symbols_soft."""
import os
import subprocess

import pytest

import box64_common
import box64_memleak
import box64_trace


MODULES = [box64_memleak, box64_trace]


# ---------------------------------------------------------------------------
# check_binary()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", MODULES,
                         ids=["memleak", "steam"])
class TestCheckBinary:
    def test_existing_readable_file(self, module, tmp_path):
        f = tmp_path / "box64"
        f.write_bytes(b"\x7fELF")
        module.check_binary(str(f))  # should not raise

    def test_missing_file_exits(self, module):
        with pytest.raises(SystemExit):
            module.check_binary("/nonexistent/box64")

    def test_unreadable_file_exits(self, module, tmp_path, monkeypatch):
        f = tmp_path / "box64"
        f.write_bytes(b"\x7fELF")
        real_access = os.access
        monkeypatch.setattr("os.access",
                            lambda p, m: False if p == str(f) else real_access(p, m))
        with pytest.raises(SystemExit):
            module.check_binary(str(f))

    def test_directory_is_not_file(self, module, tmp_path):
        with pytest.raises(SystemExit):
            module.check_binary(str(tmp_path))


# ---------------------------------------------------------------------------
# _read_symbols()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", MODULES,
                         ids=["memleak", "steam"])
class TestReadSymbols:
    def test_returns_string(self, module, tmp_path):
        f = tmp_path / "dummy"
        f.write_bytes(b"\x7fELF")
        result = module._read_symbols(str(f))
        assert isinstance(result, str)

    def test_nm_failure_returns_empty(self, module, monkeypatch):
        def mock_check_output(*args, **kwargs):
            raise subprocess.CalledProcessError(1, "nm")
        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        result = module._read_symbols("/nonexistent")
        assert result == ""

    def test_nm_not_found_returns_empty(self, module, monkeypatch):
        def mock_check_output(*args, **kwargs):
            raise FileNotFoundError("nm not found")
        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        result = module._read_symbols("/nonexistent")
        assert result == ""

    def test_combines_nm_and_nm_D(self, module, monkeypatch):
        call_count = 0

        def mock_check_output(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if "-D" in cmd:
                return "DYN_SYMBOL\n"
            return "LOCAL_SYMBOL\n"

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        result = module._read_symbols("/fake/binary")
        assert call_count == 2
        assert "LOCAL_SYMBOL" in result
        assert "DYN_SYMBOL" in result

    def test_partial_failure_returns_other(self, module, monkeypatch):
        """If nm fails but nm -D succeeds, return nm -D output."""
        def mock_check_output(cmd, **kwargs):
            if "-D" not in cmd:
                raise subprocess.CalledProcessError(1, "nm")
            return "DYN_ONLY\n"

        monkeypatch.setattr(subprocess, "check_output", mock_check_output)
        result = module._read_symbols("/fake/binary")
        assert "DYN_ONLY" in result


# ---------------------------------------------------------------------------
# check_symbols()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_memleak, box64_trace],
                         ids=["memleak", "steam"])
class TestCheckSymbolsExitOnMissing:
    """Memleak and steam call sys.exit on missing symbols."""

    def test_all_present_no_exit(self, module, monkeypatch):
        monkeypatch.setattr(module, "_read_symbols",
                            lambda p: "customMalloc\ncustomFree\n")
        # Should not raise
        module.check_symbols("/fake", ["customMalloc", "customFree"])

    def test_missing_exits(self, module, monkeypatch):
        monkeypatch.setattr(module, "_read_symbols",
                            lambda p: "customMalloc\n")
        with pytest.raises(SystemExit):
            module.check_symbols("/fake", ["customMalloc", "customFree"])

    def test_nm_fails_no_exit(self, module, monkeypatch):
        """When nm fails, continue without error."""
        monkeypatch.setattr(module, "_read_symbols", lambda p: "")
        module.check_symbols("/fake", ["customMalloc"])


# ---------------------------------------------------------------------------
# check_symbols_soft()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_common], ids=["common"])
class TestCheckSymbolsSoft:
    def test_all_present(self, module, monkeypatch):
        monkeypatch.setattr(module, "_read_symbols",
                            lambda p: "symA\nsymB\n")
        assert module.check_symbols_soft("/fake", ["symA", "symB"]) == []

    def test_some_missing(self, module, monkeypatch):
        monkeypatch.setattr(module, "_read_symbols", lambda p: "symA\n")
        result = module.check_symbols_soft("/fake", ["symA", "symB"])
        assert result == ["symB"]

    def test_all_missing(self, module, monkeypatch):
        monkeypatch.setattr(module, "_read_symbols", lambda p: "other\n")
        result = module.check_symbols_soft("/fake", ["symA", "symB"])
        assert set(result) == {"symA", "symB"}

    def test_nm_fails_returns_empty(self, module, monkeypatch):
        """When nm fails, assume all symbols present (empty missing list)."""
        monkeypatch.setattr(module, "_read_symbols", lambda p: "")
        assert module.check_symbols_soft("/fake", ["symA"]) == []


