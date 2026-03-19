"""Edge-case tests for fmt_size() and fmt_ns() — boundary values, large
numbers, and rounding behavior not covered by test_fmt_helpers.py."""
import pytest

import box64_dynarec
import box64_memleak
import box64_steam


# ---------------------------------------------------------------------------
# fmt_size boundary and edge cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_dynarec, box64_memleak, box64_steam],
                         ids=["dynarec", "memleak", "steam"])
class TestFmtSizeEdgeCases:
    def test_exactly_1024_is_kb(self, module):
        assert module.fmt_size(1024) == "1.0 KB"

    def test_just_below_1024(self, module):
        assert module.fmt_size(1023) == "1023.0 B"

    def test_exactly_1mb(self, module):
        assert module.fmt_size(1024 ** 2) == "1.0 MB"

    def test_exactly_1gb(self, module):
        assert module.fmt_size(1024 ** 3) == "1.0 GB"

    def test_exactly_1tb(self, module):
        assert module.fmt_size(1024 ** 4) == "1.0 TB"

    def test_multi_tb(self, module):
        assert module.fmt_size(5 * 1024 ** 4) == "5.0 TB"

    def test_one_byte(self, module):
        assert module.fmt_size(1) == "1.0 B"

    def test_negative_one_byte(self, module):
        assert module.fmt_size(-1) == "-1.0 B"

    def test_negative_kb(self, module):
        assert module.fmt_size(-2048) == "-2.0 KB"

    def test_rounding_just_below_kb(self, module):
        """1023.5 bytes should still show as B."""
        result = module.fmt_size(1023)
        assert "B" in result
        assert "KB" not in result

    def test_very_large_value(self, module):
        """100 TB should not crash."""
        result = module.fmt_size(100 * 1024 ** 4)
        assert "TB" in result


# ---------------------------------------------------------------------------
# fmt_ns boundary and edge cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_dynarec, box64_steam],
                         ids=["dynarec", "steam"])
class TestFmtNsEdgeCases:
    def test_zero(self, module):
        assert module.fmt_ns(0) == "0ns"

    def test_one_ns(self, module):
        assert module.fmt_ns(1) == "1ns"

    def test_exactly_1us(self, module):
        assert module.fmt_ns(1000) == "1.0us"

    def test_exactly_1ms(self, module):
        assert module.fmt_ns(1_000_000) == "1.0ms"

    def test_exactly_1s(self, module):
        assert module.fmt_ns(1_000_000_000) == "1.00s"

    def test_large_seconds(self, module):
        """60 seconds should not crash."""
        result = module.fmt_ns(60_000_000_000)
        assert "s" in result

    def test_999ns(self, module):
        assert module.fmt_ns(999) == "999ns"

    def test_999_999us(self, module):
        """Just below 1ms — should still show as us."""
        result = module.fmt_ns(999_999)
        assert "us" in result

    def test_fractional_us(self, module):
        assert module.fmt_ns(1500) == "1.5us"

    def test_fractional_ms(self, module):
        assert module.fmt_ns(1_500_000) == "1.5ms"

    def test_fractional_s(self, module):
        assert module.fmt_ns(1_500_000_000) == "1.50s"


# ---------------------------------------------------------------------------
# format_log2_hist edge cases
# ---------------------------------------------------------------------------

class _Val:
    def __init__(self, v):
        self.value = v


def _make_hist(pairs):
    return {_Val(k): _Val(v) for k, v in pairs}


class TestFormatLog2HistEdgeCases:
    def test_single_count_one(self):
        """Single bucket with count=1 should still produce a bar."""
        result = box64_dynarec.format_log2_hist(_make_hist([(5, 1)]))
        assert "#" in result

    def test_all_zero_counts_is_empty(self):
        """Buckets with count=0 should be filtered out."""
        result = box64_dynarec.format_log2_hist(_make_hist([(1, 0), (2, 0)]))
        assert "(empty)" in result

    def test_bucket_zero(self):
        """Bucket 0 → low=1, high=1."""
        result = box64_dynarec.format_log2_hist(_make_hist([(0, 5)]))
        assert "1" in result

    def test_high_bucket(self):
        """Large bucket numbers should not crash."""
        result = box64_dynarec.format_log2_hist(_make_hist([(30, 5)]))
        assert "#" in result

    def test_val_type_default(self):
        """Default val_type should show raw numbers, not units."""
        result = box64_dynarec.format_log2_hist(_make_hist([(10, 5)]))
        assert "KB" not in result
        assert "ns" not in result

    def test_equal_counts_equal_bars(self):
        """Two buckets with same count should have same bar length."""
        result = box64_dynarec.format_log2_hist(_make_hist([(2, 100), (3, 100)]))
        lines = [line for line in result.strip().split("\n") if "#" in line]
        assert len(lines) == 2
        assert lines[0].count("#") == lines[1].count("#")

    def test_max_bar_length_is_40(self):
        """Longest bar should be exactly 40 characters."""
        result = box64_dynarec.format_log2_hist(_make_hist([(5, 1000)]))
        lines = [line for line in result.strip().split("\n") if "#" in line]
        assert lines[0].count("#") == 40

    def test_many_buckets(self):
        """Many buckets should all appear in output."""
        pairs = [(i, i + 1) for i in range(20)]
        result = box64_dynarec.format_log2_hist(_make_hist(pairs))
        lines = [line for line in result.strip().split("\n") if "#" in line]
        assert len(lines) == 20

    def test_steam_val_type_ns(self):
        result = box64_steam.format_log2_hist(_make_hist([(20, 5)]), val_type="ns")
        assert "ms" in result or "us" in result or "s" in result

    def test_steam_val_type_bytes(self):
        result = box64_steam.format_log2_hist(_make_hist([(20, 5)]), val_type="bytes")
        assert "MB" in result or "KB" in result
