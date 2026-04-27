"""Test _rewrite_atomic_increment and _bcc_has_atomic_increment against
real BPF_PROGRAM source."""
import re
from unittest.mock import MagicMock, patch

import pytest

import box64_common
import box64_trace


class TestRewriteFunction:
    """Test the rewrite regex on synthetic inputs."""

    def test_single_replacement(self):
        src = "    alloc_sizes.atomic_increment(bucket);\n"
        out = box64_trace._rewrite_atomic_increment(src)
        assert "atomic_increment" not in out
        assert "alloc_sizes.lookup_or_init" in out
        assert "__sync_fetch_and_add" in out
        assert "bucket" in out

    def test_multiple_replacements(self):
        src = (
            "alloc_sizes.atomic_increment(bucket);\n"
            "block_lifetimes.atomic_increment(lt_bucket);\n"
        )
        out = box64_trace._rewrite_atomic_increment(src)
        assert out.count("lookup_or_init") == 2
        assert out.count("__sync_fetch_and_add") == 2

    def test_no_match_untouched(self):
        src = "int x = 42;\n"
        assert box64_trace._rewrite_atomic_increment(src) == src

    def test_preserves_surrounding_code(self):
        src = (
            "    int bucket = log2_u64(p->size);\n"
            "    alloc_sizes.atomic_increment(bucket);\n"
            "#ifdef TRACK_THREADS\n"
        )
        out = box64_trace._rewrite_atomic_increment(src)
        assert "log2_u64" in out
        assert "TRACK_THREADS" in out


class TestRewriteSteamBPF:
    """Test rewrite against real box64_trace.py BPF_PROGRAM."""

    def test_rewrites_exactly_4_calls(self):
        original = box64_trace.BPF_PROGRAM
        count = len(re.findall(r'\w+\.atomic_increment\(\w+\)', original))
        assert count == 4, f"Expected 4 atomic_increment calls, found {count}"

    def test_no_atomic_increment_after_rewrite(self):
        rewritten = box64_trace._rewrite_atomic_increment(
            box64_trace.BPF_PROGRAM
        )
        remaining = re.findall(r'\w+\.atomic_increment\(\w+\)', rewritten)
        assert remaining == [], f"Unrewritten calls: {remaining}"

    def test_rewrite_inserts_lookup_or_init(self):
        rewritten = box64_trace._rewrite_atomic_increment(
            box64_trace.BPF_PROGRAM
        )
        assert rewritten.count("lookup_or_init") == 4

    def test_rewrite_inserts_sync_fetch_and_add(self):
        rewritten = box64_trace._rewrite_atomic_increment(
            box64_trace.BPF_PROGRAM
        )
        orig_count = box64_trace.BPF_PROGRAM.count("__sync_fetch_and_add")
        new_count = rewritten.count("__sync_fetch_and_add")
        assert new_count == orig_count + 4

    def test_non_atomic_increment_lines_unchanged(self):
        original = box64_trace.BPF_PROGRAM
        rewritten = box64_trace._rewrite_atomic_increment(original)
        orig_lines = original.splitlines()
        new_lines = rewritten.splitlines()
        for orig, new in zip(orig_lines, new_lines):
            if "atomic_increment" not in orig:
                assert orig == new


# ---------------------------------------------------------------------------
# _bcc_has_atomic_increment detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_common], ids=["common"])
class TestBccHasAtomicIncrement:
    def test_returns_true_when_bpf_succeeds(self, module, monkeypatch):
        """If BPF() compiles without error, detection returns True."""
        mock_bpf = MagicMock()
        monkeypatch.setattr(module, "BPF", mock_bpf)
        assert module._bcc_has_atomic_increment() is True

    def test_returns_false_when_bpf_raises(self, module, monkeypatch):
        """If BPF() raises (old BCC), detection returns False."""
        mock_bpf = MagicMock(side_effect=Exception("no member named 'atomic_increment'"))
        monkeypatch.setattr(module, "BPF", mock_bpf)
        assert module._bcc_has_atomic_increment() is False

    def test_returns_false_on_any_exception(self, module, monkeypatch):
        """Any exception type should be caught, not just specific ones."""
        mock_bpf = MagicMock(side_effect=RuntimeError("unexpected"))
        monkeypatch.setattr(module, "BPF", mock_bpf)
        assert module._bcc_has_atomic_increment() is False


