#!/usr/bin/env python3
"""Compile each tool's BPF_PROGRAM with BCC to verify C correctness.

Requires: root, python3-bcc (or python3-bpfcc).
Run directly (not through pytest, which mocks BCC):
    sudo python3 tests/test_bpf_compile.py

Each compilation runs in a subprocess to isolate BCC/LLVM segfaults
that occur on old BCC versions after failed compilations.
"""
import re
import subprocess
import sys
import textwrap


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


def compile_in_subprocess(bpf_src, cflags):
    """Compile BPF C in a child process. Returns (ok, error_msg)."""
    import json
    import os
    import tempfile

    # Write a temp script that reads BPF source from stdin
    script = textwrap.dedent("""\
        import json, sys
        try:
            from bcc import BPF
        except ImportError:
            print("BCC not installed")
            sys.exit(2)
        try:
            bpf_src = sys.stdin.read()
            cflags = json.loads(sys.argv[1])
            b = BPF(text=bpf_src, cflags=cflags)
            b.cleanup()
        except Exception as e:
            print(str(e))
            sys.exit(1)
    """)

    fd, path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(script)
        result = subprocess.run(
            [sys.executable, path, json.dumps(cflags)],
            input=bpf_src,
            capture_output=True, text=True, timeout=60,
        )
    finally:
        os.unlink(path)

    if result.returncode == 0:
        return True, None
    if result.returncode == 2:
        return None, "BCC not installed"
    msg = result.stdout.strip() or result.stderr.strip() or f"exit code {result.returncode}"
    return False, msg


# ---------------------------------------------------------------------------
# Test configurations: (tool, cflags, description)
# ---------------------------------------------------------------------------

CONFIGS = [
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
    # Detect atomic_increment support in a subprocess (safe from segfaults)
    ok, _ = compile_in_subprocess(
        r"""
        BPF_HISTOGRAM(t, int, 2);
        int test(void *ctx) { int k = 0; t.atomic_increment(k); return 0; }
        """, [])
    if ok is None:
        print("SKIP: BCC not installed")
        return 0

    has_ai = bool(ok)
    if has_ai:
        print("[*] BCC supports atomic_increment — testing original source")
    else:
        print("[*] BCC does not support atomic_increment — testing rewritten source")

    passed = 0
    failed = 0
    errors = []

    for tool, cflags, desc in CONFIGS:
        bpf_src = extract_bpf_program(tool)

        if has_ai:
            label = f"{desc} [original]"
            src = bpf_src
        else:
            label = f"{desc} [rewritten]"
            src = rewrite_atomic_increment(bpf_src)

        ok, err = compile_in_subprocess(src, cflags)
        if ok:
            print(f"  PASS  {label}")
            passed += 1
        else:
            print(f"  FAIL  {label}: {err}")
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
