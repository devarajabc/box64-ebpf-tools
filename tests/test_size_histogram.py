"""Tests for compute_size_histogram() in box64_memleak."""
import pytest

import box64_memleak


class TestComputeSizeHistogram:
    def test_empty_list(self):
        assert box64_memleak.compute_size_histogram([]) == {}

    def test_zero_size(self):
        result = box64_memleak.compute_size_histogram([0])
        assert result == {"0": 1}

    def test_power_of_two(self):
        result = box64_memleak.compute_size_histogram([1024])
        # 1024 = 2^10, so bucket is [1024, 2047]
        assert len(result) == 1
        bucket = list(result.keys())[0]
        assert "1.0 KB" in bucket

    def test_same_range_aggregates(self):
        # 100 and 127 are both in [64, 127] (bit_length=7, 2^6=64, 2^7-1=127)
        result = box64_memleak.compute_size_histogram([100, 110, 120])
        assert len(result) == 1
        assert list(result.values())[0] == 3

    def test_different_ranges(self):
        # 1 is in [1,1], 64 is in [64,127], 1024 is in [1024,2047]
        result = box64_memleak.compute_size_histogram([1, 64, 1024])
        assert len(result) == 3

    def test_large_size(self):
        # 1GB+ should produce valid labels
        gb = 1 << 30
        result = box64_memleak.compute_size_histogram([gb])
        assert len(result) == 1
        bucket = list(result.keys())[0]
        assert "GB" in bucket
