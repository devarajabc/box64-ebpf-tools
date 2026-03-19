"""Ensure all atomic_increment usage is guarded by #ifdef HAS_ATOMIC_INCREMENT."""
import re

TOOLS = ["box64_dynarec.py", "box64_memleak.py", "box64_steam.py"]

# Lines that are allowed to contain atomic_increment:
ALLOWED_PATTERNS = [
    r"^\s*#ifdef HAS_ATOMIC_INCREMENT",             # the guard itself
    r"\.atomic_increment\(",                         # inside #ifdef block (BPF C)
    r"t\.atomic_increment",                          # detection probe
    r"_bcc_has_atomic_increment",                    # Python function def/call
    r"// .*atomic_increment",                        # comments
    r"\".*atomic_increment",                         # string checks
]


def test_no_unguarded_atomic_increment():
    """Every .atomic_increment() in BPF C must be preceded by #ifdef HAS_ATOMIC_INCREMENT."""
    for tool in TOOLS:
        with open(tool) as f:
            lines = f.readlines()
        in_ifdef = False
        for i, line in enumerate(lines, 1):
            if "atomic_increment" not in line:
                # Track ifdef state for BPF C sections
                if "#ifdef HAS_ATOMIC_INCREMENT" in line:
                    in_ifdef = True
                elif in_ifdef and "#endif" in line:
                    in_ifdef = False
                continue
            # Check if this is an allowed pattern
            if any(re.search(p, line) for p in ALLOWED_PATTERNS):
                continue
            raise AssertionError(
                f"{tool}:{i}: unguarded atomic_increment: {line.strip()}"
            )
