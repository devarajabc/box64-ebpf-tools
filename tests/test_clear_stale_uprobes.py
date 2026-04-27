"""Tests for _clear_stale_uprobes() — must never crash, all steps are best-effort."""
import os
import shutil

import pytest

import box64_memleak
import box64_trace


MODULES = [box64_memleak, box64_trace]


@pytest.mark.parametrize("module", MODULES,
                         ids=["memleak", "steam"])
class TestClearStaleUprobes:
    def test_no_crash_with_nonexistent_binary(self, module):
        """Should not crash even when binary doesn't exist."""
        module._clear_stale_uprobes("/nonexistent/box64")

    def test_no_crash_with_real_file(self, module, tmp_path):
        """Should not crash with a real temporary file."""
        f = tmp_path / "box64"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        module._clear_stale_uprobes(str(f))
        # File should still exist after the operation
        assert f.exists()

    def test_preserves_file_content(self, module, tmp_path):
        """Binary content should be preserved after inode refresh."""
        f = tmp_path / "box64"
        content = b"\x7fELF" + os.urandom(256)
        f.write_bytes(content)
        module._clear_stale_uprobes(str(f))
        assert f.read_bytes() == content

    def test_no_crash_when_copy_fails(self, module, monkeypatch):
        """If shutil.copy2 raises, function should catch and continue."""
        def mock_copy2(*args, **kwargs):
            raise OSError("Permission denied")
        monkeypatch.setattr(shutil, "copy2", mock_copy2)
        module._clear_stale_uprobes("/nonexistent/box64")

    def test_no_crash_when_rename_fails(self, module, tmp_path, monkeypatch):
        """If os.rename raises, function should catch and continue."""
        f = tmp_path / "box64"
        f.write_bytes(b"\x7fELF")
        original_rename = os.rename

        def mock_rename(src, dst):
            raise OSError("Cross-device link")
        monkeypatch.setattr(os, "rename", mock_rename)
        module._clear_stale_uprobes(str(f))

    def test_temp_file_cleaned_up(self, module, tmp_path):
        """The .uprobe_fix temp file should not linger after success."""
        f = tmp_path / "box64"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        module._clear_stale_uprobes(str(f))
        tmp_file = tmp_path / "box64.uprobe_fix"
        assert not tmp_file.exists()
