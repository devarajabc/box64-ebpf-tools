"""Tests for _patch_bcc_uretprobe() aarch64 BCC fix."""
import ctypes as ct
from unittest.mock import MagicMock, patch

import box64_steam
import box64_dynarec
import box64_memleak


def _reset_lib():
    """Return a fresh mock for bcc.libbcc.lib."""
    from bcc import libbcc
    libbcc.lib = MagicMock()
    return libbcc.lib


class TestPatchOnAarch64:
    """When platform.machine() == 'aarch64', the patch should activate."""

    @patch("platform.machine", return_value="aarch64")
    def test_steam_replaces_attach_uprobe(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_steam._patch_bcc_uretprobe()
        # The function should have been replaced
        assert lib.bpf_attach_uprobe is not original

    @patch("platform.machine", return_value="aarch64")
    def test_dynarec_replaces_attach_uprobe(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_dynarec._patch_bcc_uretprobe()
        assert lib.bpf_attach_uprobe is not original

    @patch("platform.machine", return_value="aarch64")
    def test_memleak_replaces_attach_uprobe(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_memleak._patch_bcc_uretprobe()
        assert lib.bpf_attach_uprobe is not original

    @patch("platform.machine", return_value="aarch64")
    def test_wrapper_appends_ref_ctr_offset(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_steam._patch_bcc_uretprobe()
        patched = lib.bpf_attach_uprobe
        # Call with 6 args (what BCC normally passes)
        patched(1, 2, b"name", b"/path", 0x100, -1)
        # Original should receive 7 args with ref_ctr_offset=0
        original.assert_called_once()
        args = original.call_args[0]
        assert len(args) == 7
        assert args[6].value == 0  # ct.c_uint32(0)

    @patch("platform.machine", return_value="aarch64")
    def test_wrapper_passes_through_7_args(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_steam._patch_bcc_uretprobe()
        patched = lib.bpf_attach_uprobe
        # If already 7 args, pass through unchanged
        patched(1, 2, b"name", b"/path", 0x100, -1, ct.c_uint32(42))
        original.assert_called_once()
        args = original.call_args[0]
        assert len(args) == 7


class TestPatchOnNonAarch64:
    """On non-aarch64, the patch should be a no-op."""

    @patch("platform.machine", return_value="x86_64")
    def test_steam_noop_on_x86_64(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_steam._patch_bcc_uretprobe()
        assert lib.bpf_attach_uprobe is original

    @patch("platform.machine", return_value="x86_64")
    def test_dynarec_noop_on_x86_64(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_dynarec._patch_bcc_uretprobe()
        assert lib.bpf_attach_uprobe is original

    @patch("platform.machine", return_value="x86_64")
    def test_memleak_noop_on_x86_64(self, _mock_machine):
        lib = _reset_lib()
        original = lib.bpf_attach_uprobe
        box64_memleak._patch_bcc_uretprobe()
        assert lib.bpf_attach_uprobe is original


class TestPatchImportFailure:
    """If bcc.libbcc access fails, print warning and don't crash."""

    @patch("platform.machine", return_value="aarch64")
    def test_warning_on_import_error(self, _mock_machine, capsys):
        import sys as _sys
        import bcc
        orig_attr = bcc.libbcc
        orig_mod = _sys.modules.get("bcc.libbcc")
        try:
            del bcc.libbcc
            _sys.modules.pop("bcc.libbcc", None)
            # Should not raise
            box64_steam._patch_bcc_uretprobe()
        finally:
            bcc.libbcc = orig_attr
            if orig_mod is not None:
                _sys.modules["bcc.libbcc"] = orig_mod
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
