"""Mock the bcc module so tests can import box64_*.py without BCC installed."""
import sys
import types
from unittest.mock import MagicMock

# Must run before any test imports box64_*.py

_bcc = types.ModuleType("bcc")
_bcc.BPF = MagicMock()
_bcc.PerfType = MagicMock()
_bcc.PerfSWConfig = MagicMock()
sys.modules["bcc"] = _bcc

# Add repo root to sys.path so `import box64_dynarec` etc. work
from pathlib import Path

repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
