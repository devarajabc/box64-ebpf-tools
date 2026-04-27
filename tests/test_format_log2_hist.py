"""Tests for format_log2_hist() — steam uses closed [low, high] brackets."""
import pytest

import box64_trace


class _Val:
    """Mimic BPF map value with .value attribute."""
    def __init__(self, v):
        self.value = v


def _make_hist(pairs):
    """Build a fake BPF histogram {key: val} from (bucket, count) pairs."""
    return {_Val(k): _Val(v) for k, v in pairs}


# ---------------------------------------------------------------------------
# box64_trace.format_log2_hist  (closed brackets, no section_header)
# ---------------------------------------------------------------------------

class TestSteamFormatLog2Hist:
    def test_empty(self):
        result = box64_trace.format_log2_hist(_make_hist([]))
        assert "(empty)" in result

    def test_single_bucket(self):
        result = box64_trace.format_log2_hist(_make_hist([(3, 10)]))
        assert "8" in result
        assert "15" in result
        # Steam uses closed brackets "]" not half-open ")"
        assert "]" in result

    def test_bar_scaling(self):
        hist = _make_hist([(2, 100), (3, 50)])
        result = box64_trace.format_log2_hist(hist)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        bar0 = lines[0].count("#")
        bar1 = lines[1].count("#")
        assert bar0 > bar1

    def test_no_section_header_param(self):
        import inspect
        sig = inspect.signature(box64_trace.format_log2_hist)
        assert "section_header" not in sig.parameters

    def test_val_type_bytes(self):
        result = box64_trace.format_log2_hist(
            _make_hist([(10, 5)]), val_type="bytes")
        assert "KB" in result or "MB" in result or "B" in result

    def test_val_type_ns(self):
        result = box64_trace.format_log2_hist(
            _make_hist([(10, 5)]), val_type="ns")
        assert "us" in result or "ns" in result or "ms" in result
