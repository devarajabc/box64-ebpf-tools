"""Tests for fmt_size() and fmt_ns() helper functions."""
import pytest

import box64_memleak
import box64_trace


# ---------------------------------------------------------------------------
# fmt_size — present in all three tools
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_memleak, box64_trace])
class TestFmtSize:
    def test_zero(self, module):
        assert module.fmt_size(0) == "0.0 B"

    def test_bytes(self, module):
        assert module.fmt_size(512) == "512.0 B"

    def test_kb(self, module):
        assert module.fmt_size(1024) == "1.0 KB"
        assert module.fmt_size(1536) == "1.5 KB"

    def test_mb(self, module):
        assert module.fmt_size(1024 * 1024) == "1.0 MB"

    def test_gb(self, module):
        assert module.fmt_size(1024 ** 3) == "1.0 GB"

    def test_tb(self, module):
        assert module.fmt_size(1024 ** 4) == "1.0 TB"

    def test_negative(self, module):
        assert module.fmt_size(-1024) == "-1.0 KB"

    def test_fractional(self, module):
        assert module.fmt_size(1500) == "1.5 KB"


# ---------------------------------------------------------------------------
# fmt_ns — steam only (memleak has no fmt_ns)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_trace])
class TestFmtNs:
    def test_nanoseconds(self, module):
        assert module.fmt_ns(500) == "500ns"

    def test_microseconds(self, module):
        assert module.fmt_ns(1500) == "1.5us"

    def test_milliseconds(self, module):
        assert module.fmt_ns(1_500_000) == "1.5ms"

    def test_seconds(self, module):
        assert module.fmt_ns(1_500_000_000) == "1.50s"

    def test_boundary_ns_to_us(self, module):
        assert module.fmt_ns(999) == "999ns"
        assert module.fmt_ns(1000) == "1.0us"

    def test_boundary_us_to_ms(self, module):
        assert module.fmt_ns(999_999) == "1000.0us"
        assert module.fmt_ns(1_000_000) == "1.0ms"

    def test_boundary_ms_to_s(self, module):
        assert module.fmt_ns(1_000_000_000) == "1.00s"
