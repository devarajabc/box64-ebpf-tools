"""Tests for parse_args() in all three tools."""
import pytest

import box64_memleak
import box64_trace


# ---------------------------------------------------------------------------
# Shared defaults
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [box64_memleak, box64_trace])
class TestSharedDefaults:
    def test_default_binary(self, module, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = module.parse_args()
        assert args.binary == "/usr/local/bin/box64"

    def test_default_pid(self, module, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = module.parse_args()
        assert args.pid == 0

    def test_default_interval(self, module, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = module.parse_args()
        assert args.interval == 15

    def test_custom_binary(self, module, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "-b", "/opt/box64"])
        args = module.parse_args()
        assert args.binary == "/opt/box64"

    def test_custom_pid(self, module, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "-p", "1234"])
        args = module.parse_args()
        assert args.pid == 1234

    def test_custom_interval(self, module, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "-i", "5"])
        args = module.parse_args()
        assert args.interval == 5


# ---------------------------------------------------------------------------
# box64_memleak-specific flags
# ---------------------------------------------------------------------------

class TestMemleakArgs:
    def test_top_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_memleak.parse_args()
        assert args.top == 20

    def test_mmap_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_memleak.parse_args()
        assert args.mmap is False

    def test_mmap_set(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "--mmap"])
        args = box64_memleak.parse_args()
        assert args.mmap is True

    def test_stacks_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_memleak.parse_args()
        assert args.stacks is False

    def test_32bit_flag(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "--32bit"])
        args = box64_memleak.parse_args()
        assert args.track32 is True


# ---------------------------------------------------------------------------
# box64_trace-specific flags
# ---------------------------------------------------------------------------

class TestSteamArgs:
    def test_no_mem_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_trace.parse_args()
        assert args.no_mem is False

    def test_no_dynarec_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_trace.parse_args()
        assert args.no_dynarec is False

    def test_no_mmap_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_trace.parse_args()
        assert args.no_mmap is False

    def test_sample_freq_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_trace.parse_args()
        assert args.sample_freq == 0

    def test_sample_freq_custom(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog", "--sample-freq", "4999"])
        args = box64_trace.parse_args()
        assert args.sample_freq == 4999

    def test_hash_capacity_default(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["prog"])
        args = box64_trace.parse_args()
        assert args.hash_capacity == 524288
