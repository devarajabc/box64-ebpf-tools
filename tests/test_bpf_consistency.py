"""Cross-check BPF C function names against Python attach calls.

Parses each .py file as text (not import) to extract:
  - Function definitions from the BPF C source string
  - fn_name= references from attach_uprobe/uretprobe/kprobe/tracepoint/perf_event calls

For tracepoints: TRACEPOINT_PROBE(cat, event) generates cat__event as the fn_name.
"""
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ["box64_memleak.py", "box64_trace.py"]


def _extract_bpf_source(text):
    """Extract the BPF_PROGRAM = r\"\"\"...\"\"\" string."""
    match = re.search(r'BPF_PROGRAM\s*=\s*r"""(.*?)"""', text, re.DOTALL)
    if not match:
        return ""
    return match.group(1)


def _extract_c_function_names(bpf_source):
    """Find all C function definitions: 'int fn_name(' pattern.

    Also handles TRACEPOINT_PROBE(category, event) which generates
    category__event as the function name.
    """
    names = set()

    # Regular function definitions: int/void fn_name(
    for m in re.finditer(r'\b(?:int|void)\s+(\w+)\s*\(', bpf_source):
        names.add(m.group(1))

    # TRACEPOINT_PROBE(category, event) → category__event
    for m in re.finditer(r'TRACEPOINT_PROBE\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', bpf_source):
        names.add(f"{m.group(1)}__{m.group(2)}")

    return names


def _extract_python_fn_names(text):
    """Find all fn_name="..." in attach_* calls."""
    names = set()
    for m in re.finditer(r'fn_name\s*=\s*"(\w+)"', text):
        names.add(m.group(1))
    return names


@pytest.mark.parametrize("script", SCRIPTS)
def test_all_python_fn_names_exist_in_bpf_c(script):
    """Every fn_name referenced in Python attach calls must have a
    corresponding function definition in the BPF C source."""
    text = (REPO_ROOT / script).read_text()
    bpf_source = _extract_bpf_source(text)
    assert bpf_source, f"Could not extract BPF_PROGRAM from {script}"

    c_functions = _extract_c_function_names(bpf_source)
    py_fn_names = _extract_python_fn_names(text)

    assert py_fn_names, f"No fn_name= found in {script}"

    missing = py_fn_names - c_functions
    assert not missing, (
        f"{script}: Python references fn_name(s) not defined in BPF C source: "
        f"{sorted(missing)}"
    )


@pytest.mark.parametrize("script", SCRIPTS)
def test_bpf_source_is_nonempty(script):
    """Sanity check: BPF_PROGRAM should contain substantial C code."""
    text = (REPO_ROOT / script).read_text()
    bpf_source = _extract_bpf_source(text)
    assert len(bpf_source) > 100, f"BPF_PROGRAM in {script} seems too short"
