#!/usr/bin/env python3
"""Compile each tool's BPF_PROGRAM with BCC to verify C correctness.

Requires: root, python3-bcc (or python3-bpfcc).
Run directly (not through pytest, which mocks BCC):
    sudo python3 tests/test_bpf_compile.py
"""
import re
import sys

try:
    from bcc import BPF
except ImportError:
    print("SKIP: BCC not installed")
    sys.exit(0)


def extract_bpf_program(path):
    """Extract BPF_PROGRAM string from a tool without importing it."""
    with open(path) as f:
        content = f.read()
    m = re.search(r'BPF_PROGRAM\s*=\s*r"""(.*?)"""', content, re.DOTALL)
    if not m:
        raise ValueError(f"No BPF_PROGRAM found in {path}")
    return m.group(1)


def rewrite_atomic_increment(bpf_text):
    """Same rewrite logic as the tools use for old BCC."""
    def _replace(m):
        table = m.group(1)
        key = m.group(2)
        return (
            f'{{ u64 _ai_zero = 0, *_ai_val = '
            f'{table}.lookup_or_init(&({key}), &_ai_zero); '
            f'if (_ai_val) __sync_fetch_and_add(_ai_val, 1); }}'
        )
    return re.sub(r'(\w+)\.atomic_increment\((\w+)\)', _replace, bpf_text)


# ---------------------------------------------------------------------------
# Test configurations: (tool, cflags, description)
# ---------------------------------------------------------------------------

CONFIGS = [
    # --- box64_dynarec.py ---
    ("box64_dynarec.py", [
        "-DCHURN_THRESHOLD_NS=1000000000ULL",
        "-DHASH_CAPACITY=524288",
        "-DTRACK_PROT",
        "-DTRACK_THREADS",
        "-DTRACK_COW",
    ], "dynarec all features"),

    ("box64_dynarec.py", [
        "-DCHURN_THRESHOLD_NS=1000000000ULL",
        "-DHASH_CAPACITY=524288",
    ], "dynarec minimal"),

    # --- box64_memleak.py ---
    ("box64_memleak.py", [
        "-DHASH_CAPACITY=524288",
        "-DCAPTURE_STACKS",
        "-DTRACK_MMAP",
        "-DTRACK_32BIT",
        "-DTRACK_THREADS",
        "-DTRACK_COW",
    ], "memleak all features"),

    ("box64_memleak.py", [
        "-DHASH_CAPACITY=524288",
    ], "memleak minimal"),

    # --- box64_steam.py ---
    ("box64_steam.py", [
        "-DCHURN_THRESHOLD_NS=1000000000ULL",
        "-DHASH_CAPACITY=524288",
        "-DTRACK_MEM",
        "-DTRACK_DYNAREC",
        "-DTRACK_PROT",
        "-DTRACK_BLOCK_DETAIL",
        "-DTRACK_MMAP",
        "-DTRACK_THREADS",
        "-DTRACK_COW",
    ], "steam all features"),

    ("box64_steam.py", [
        "-DCHURN_THRESHOLD_NS=1000000000ULL",
        "-DHASH_CAPACITY=524288",
    ], "steam minimal"),
]


def main():
    passed = 0
    failed = 0
    errors = []

    for tool, cflags, desc in CONFIGS:
        bpf_src = extract_bpf_program(tool)

        # Test 1: original source (new BCC with atomic_increment)
        label = f"{desc} [original]"
        try:
            b = BPF(text=bpf_src, cflags=cflags)
            b.cleanup()
            print(f"  PASS  {label}")
            passed += 1
        except Exception as e:
            if "atomic_increment" in str(e):
                print(f"  SKIP  {label} (BCC too old for atomic_increment)")
            else:
                print(f"  FAIL  {label}: {e}")
                errors.append(label)
                failed += 1

        # Test 2: rewritten source (old BCC fallback path)
        label = f"{desc} [rewritten]"
        try:
            rewritten = rewrite_atomic_increment(bpf_src)
            b = BPF(text=rewritten, cflags=cflags)
            b.cleanup()
            print(f"  PASS  {label}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {label}: {e}")
            errors.append(label)
            failed += 1

    print(f"\n{'='*60}")
    print(f"BPF compile: {passed} passed, {failed} failed")
    if errors:
        print("Failures:")
        for e in errors:
            print(f"  - {e}")
    print(f"{'='*60}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
