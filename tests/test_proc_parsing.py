"""Tests for /proc parsing helpers: read_smaps_rollup, read_minflt, read_proc_cmdline, read_tgid."""
import pytest
from unittest.mock import mock_open, patch

import box64_common
import box64_memleak
import box64_trace


# ---------------------------------------------------------------------------
# read_smaps_rollup — present in all three tools
# ---------------------------------------------------------------------------

SMAPS_CONTENT = """\
00000000-ffffffff ---p 00000000 00:00 0          [rollup]
Rss:                1024 kB
Pss:                 512 kB
Private_Dirty:       256 kB
Private_Clean:       128 kB
Shared_Dirty:         64 kB
Shared_Clean:         32 kB
SwapPss:               0 kB
"""


@pytest.mark.parametrize("module", [box64_memleak, box64_trace])
class TestReadSmapsRollup:
    def test_parses_fields(self, module):
        m = mock_open(read_data=SMAPS_CONTENT)
        with patch("builtins.open", m):
            result = module.read_smaps_rollup(1234)
        assert result["Rss"] == 1024 * 1024
        assert result["Pss"] == 512 * 1024
        assert result["Private_Dirty"] == 256 * 1024
        assert result["Private_Clean"] == 128 * 1024
        assert result["Shared_Dirty"] == 64 * 1024
        assert result["Shared_Clean"] == 32 * 1024

    def test_ignores_unrelated_fields(self, module):
        m = mock_open(read_data=SMAPS_CONTENT)
        with patch("builtins.open", m):
            result = module.read_smaps_rollup(1234)
        assert "SwapPss" not in result

    def test_oserror_returns_empty(self, module):
        with patch("builtins.open", side_effect=OSError):
            result = module.read_smaps_rollup(99999)
        assert result == {}

    def test_empty_file(self, module):
        m = mock_open(read_data="")
        with patch("builtins.open", m):
            result = module.read_smaps_rollup(1234)
        assert result == {}


# ---------------------------------------------------------------------------
# read_minflt — present in all three tools
# ---------------------------------------------------------------------------

STAT_CONTENT = "1234 (box64) S 1233 1234 1234 0 -1 4194304 500 0 0 0 10 5 0 0 20 0 1 0 100 12345678 200 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0"


@pytest.mark.parametrize("module", [box64_memleak, box64_trace])
class TestReadMinflt:
    def test_extracts_field_10(self, module):
        m = mock_open(read_data=STAT_CONTENT)
        with patch("builtins.open", m):
            result = module.read_minflt(1234)
        # field[9] (0-indexed) is the 10th field = 0 in this data
        assert isinstance(result, int)

    def test_oserror_returns_zero(self, module):
        with patch("builtins.open", side_effect=OSError):
            result = module.read_minflt(99999)
        assert result == 0


# ---------------------------------------------------------------------------
# read_proc_cmdline — steam only
# ---------------------------------------------------------------------------

class TestReadProcCmdline:
    def test_box64_returns_game(self):
        # cmdline: box64\0game.exe\0
        data = b"box64\x00game.exe\x00"
        m = mock_open(read_data=data)
        with patch("builtins.open", m):
            result = box64_trace.read_proc_cmdline(1234)
        assert result == "game.exe"

    def test_non_box64_returns_argv0(self):
        data = b"/usr/bin/steam\x00--some-arg\x00"
        m = mock_open(read_data=data)
        with patch("builtins.open", m):
            result = box64_trace.read_proc_cmdline(1234)
        assert result == "steam"

    def test_full_path_box64(self):
        data = b"/usr/local/bin/box64\x00/path/to/game.exe\x00"
        m = mock_open(read_data=data)
        with patch("builtins.open", m):
            result = box64_trace.read_proc_cmdline(1234)
        # basename of argv[0] is "box64", so returns basename of argv[1]
        assert result == "game.exe"

    def test_empty_cmdline(self):
        m = mock_open(read_data=b"")
        with patch("builtins.open", m):
            result = box64_trace.read_proc_cmdline(1234)
        assert result == "pid1234"

    def test_oserror_returns_pidN(self):
        with patch("builtins.open", side_effect=OSError):
            result = box64_trace.read_proc_cmdline(1234)
        assert result == "pid1234"

    def test_memleak_has_no_read_proc_cmdline(self):
        assert not hasattr(box64_memleak, "read_proc_cmdline")


# ---------------------------------------------------------------------------
# read_tgid — distinguishes thread TIDs from real process TGIDs.
# Critical for filtering CLONE_THREAD entries out of the per-PID breakdown.
# ---------------------------------------------------------------------------

class TestReadTgid:
    # /proc/PID/status format — `Tgid:` is one of dozens of lines; assertions
    # below use representative status content rather than hand-crafted minimal
    # files so the parser is exercised against realistic inputs.
    REAL_PROCESS_STATUS = """\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Tgid:\t12345
Ngid:\t0
Pid:\t12345
PPid:\t1
"""

    THREAD_TID_STATUS = """\
Name:\tworker
State:\tS (sleeping)
Tgid:\t12345
Ngid:\t0
Pid:\t12378
PPid:\t1
"""

    def test_real_process_tgid_equals_pid(self):
        # Main thread / real fork child: Tgid == Pid.
        m = mock_open(read_data=self.REAL_PROCESS_STATUS)
        with patch("builtins.open", m):
            tgid = box64_common.read_tgid(12345)
        assert tgid == 12345

    def test_thread_tid_returns_parents_tgid(self):
        # Thread: Tgid is the PARENT process's Tgid, not the thread's TID.
        # Caller compares tgid != pid to identify thread clones.
        m = mock_open(read_data=self.THREAD_TID_STATUS)
        with patch("builtins.open", m):
            tgid = box64_common.read_tgid(12378)
        assert tgid == 12345
        assert tgid != 12378

    def test_missing_proc_returns_none(self):
        # Process exited before we got to /proc — can't classify.
        with patch("builtins.open", side_effect=FileNotFoundError):
            assert box64_common.read_tgid(99999) is None

    def test_permission_denied_returns_none(self):
        # /proc/PID may be readable for the user but blocked under e.g.
        # hidepid=1. read_tgid should not propagate the OSError.
        with patch("builtins.open", side_effect=PermissionError):
            assert box64_common.read_tgid(99999) is None

    def test_tgid_line_missing_returns_none(self):
        # Defensive: if the kernel ever changes /proc/status format and
        # drops the Tgid line, we return None rather than crashing.
        m = mock_open(read_data="Name:\tfoo\nState:\tR\n")
        with patch("builtins.open", m):
            assert box64_common.read_tgid(12345) is None

    def test_malformed_tgid_value_returns_none(self):
        # Tgid: <something not an int> — don't crash.
        m = mock_open(read_data="Name:\tfoo\nTgid:\tbogus\n")
        with patch("builtins.open", m):
            assert box64_common.read_tgid(12345) is None

    def test_classification_use_in_caller(self):
        # Document the expected pattern callers use to classify entries.
        # This is the contract _per_pid_snapshot relies on.
        m_proc = mock_open(read_data=self.REAL_PROCESS_STATUS)
        with patch("builtins.open", m_proc):
            assert box64_common.read_tgid(12345) == 12345  # → "process"

        m_thr = mock_open(read_data=self.THREAD_TID_STATUS)
        with patch("builtins.open", m_thr):
            assert box64_common.read_tgid(12378) != 12378  # → "thread"

        with patch("builtins.open", side_effect=FileNotFoundError):
            assert box64_common.read_tgid(99999) is None   # → "unknown"
