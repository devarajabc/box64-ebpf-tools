"""Ensure all atomic_increment usage goes through HIST_INCREMENT macro."""
import re

TOOLS = ["box64_dynarec.py", "box64_memleak.py", "box64_steam.py"]

# Lines that are allowed to contain atomic_increment:
ALLOWED_PATTERNS = [
    r"#define HIST_INCREMENT.*atomic_increment",   # macro definition
    r"t\.atomic_increment",                         # detection probe
    r"table\.atomic_increment",                     # macro definition
    r"_bcc_has_atomic_increment",                   # Python function def/call
    r"// .*atomic_increment",                       # comments
    r"\".*atomic_increment",                        # string checks
]


def test_no_raw_atomic_increment():
    for tool in TOOLS:
        with open(tool) as f:
            for i, line in enumerate(f, 1):
                if "atomic_increment" not in line:
                    continue
                if any(re.search(p, line) for p in ALLOWED_PATTERNS):
                    continue
                raise AssertionError(
                    f"{tool}:{i}: raw atomic_increment outside macro: {line.strip()}"
                )
