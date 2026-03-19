"""Verify bidirectional consistency between #ifdef flags in BPF C and -D flags in Python.

For each tool, extracts:
  - Set A: all #ifdef/#ifndef X tokens from BPF_PROGRAM C source
  - Set B: all -DX tokens from the Python cflags-building code

Then checks:
  - A ⊆ B: every #ifdef flag has a matching -D in Python
  - B ⊆ A: every -D flag has a matching #ifdef in BPF C (except always-on value defines)

Catches flag renames, typos, and forgotten deletions.
"""
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ["box64_dynarec.py", "box64_memleak.py", "box64_steam.py"]

# Value-only defines: always passed in cflags but never #ifdef-guarded.
# HASH_CAPACITY and CHURN_THRESHOLD_NS are used as numeric values in BPF C.
# PROFILE_CAPACITY is similarly a value define (guarded by TRACK_PROFILE).
ALWAYS_ON_VALUE_DEFINES = {"HASH_CAPACITY", "CHURN_THRESHOLD_NS", "PROFILE_CAPACITY"}


def _extract_bpf_source(text):
    """Extract the BPF_PROGRAM = r\"\"\"...\"\"\" string."""
    match = re.search(r'BPF_PROGRAM\s*=\s*r"""(.*?)"""', text, re.DOTALL)
    return match.group(1) if match else ""


def _extract_ifdef_flags(bpf_source):
    """Extract all #ifdef / #ifndef flag names from BPF C source."""
    flags = set()
    for m in re.finditer(r'#\s*ifn?def\s+(\w+)', bpf_source):
        flags.add(m.group(1))
    return flags


def _extract_cflags_defines(python_source):
    """Extract all -DX flag names from Python cflags-building code.

    Only considers lines that reference ``cflags`` (append or list literal),
    to avoid false positives from error messages or comments mentioning -D.

    Matches patterns like:
      cflags.append("-DTRACK_PROT")
      cflags.append(f"-DFILTER_PID={args.pid}")
      cflags = [f"-DHASH_CAPACITY={hash_cap}", ...]
    """
    flags = set()
    for line in python_source.splitlines():
        if "cflags" not in line:
            continue
        for m in re.finditer(r'-D(\w+)', line):
            flags.add(m.group(1))
    return flags


@pytest.mark.parametrize("script", SCRIPTS)
def test_every_ifdef_has_cflag(script):
    """Every #ifdef X in BPF C has a corresponding -DX in Python cflags."""
    text = (REPO_ROOT / script).read_text()
    bpf_source = _extract_bpf_source(text)
    assert bpf_source, f"Could not extract BPF_PROGRAM from {script}"

    ifdef_flags = _extract_ifdef_flags(bpf_source)
    cflag_defines = _extract_cflags_defines(text)

    missing = ifdef_flags - cflag_defines
    assert not missing, (
        f"{script}: #ifdef flags in BPF C with no -D in Python cflags: "
        f"{sorted(missing)}"
    )


@pytest.mark.parametrize("script", SCRIPTS)
def test_every_cflag_has_ifdef(script):
    """Every -DX in Python cflags has a corresponding #ifdef X in BPF C
    (except always-on value defines)."""
    text = (REPO_ROOT / script).read_text()
    bpf_source = _extract_bpf_source(text)
    assert bpf_source, f"Could not extract BPF_PROGRAM from {script}"

    ifdef_flags = _extract_ifdef_flags(bpf_source)
    cflag_defines = _extract_cflags_defines(text)

    # Always-on value defines don't need #ifdef guards
    cflag_defines -= ALWAYS_ON_VALUE_DEFINES

    missing = cflag_defines - ifdef_flags
    assert not missing, (
        f"{script}: -D flags in Python cflags with no #ifdef in BPF C: "
        f"{sorted(missing)}"
    )
