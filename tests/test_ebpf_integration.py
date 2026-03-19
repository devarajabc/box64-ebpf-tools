#!/usr/bin/env python3
"""End-to-end eBPF integration tests: run our tools against a live Box64 process.

Requires: root, python3-bcc, a Box64 binary (with debug symbols), and one or
more x86_64 test binaries for Box64 to emulate.

Run directly (not through pytest):
    sudo python3 tests/test_ebpf_integration.py \
        --box64 /tmp/box64-build/box64 \
        --test-bin /tmp/dynarec_stress \
        --test-dir /tmp/box64-src/tests
"""
import argparse
import glob
import os
import re
import signal
import subprocess
import sys
import time


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Per-binary timeout — some Box64 tests may hang on missing libs
BOX64_PER_BINARY_TIMEOUT = 10


def discover_test_binaries(test_dir):
    """Find pre-compiled Box64 test binaries (test01..test33) in a directory."""
    pattern = os.path.join(test_dir, "test[0-9][0-9]")
    bins = sorted(glob.glob(pattern))
    # Filter to actual files (not directories or symlinks to directories)
    return [b for b in bins if os.path.isfile(b)]


def run_tool_test(tool_script, tool_args, box64_bin, test_bins,
                  attach_wait=3, grace_period=2, timeout=90):
    """Run an eBPF tool against Box64 processes and return its stdout.

    1. Start the tool in background
    2. Wait for probe attachment
    3. Run Box64 with each test binary in sequence
    4. Wait for completion + grace period
    5. SIGINT the tool to trigger final report
    6. Return (stdout, stderr, returncode)
    """
    tool_path = os.path.join(REPO_ROOT, tool_script)
    cmd = [sys.executable, tool_path, "-b", box64_bin] + tool_args

    print(f"  Starting: {' '.join(cmd)}")
    tool_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Wait for probes to attach
    print(f"  Waiting {attach_wait}s for probe attachment...")
    time.sleep(attach_wait)

    # Check tool didn't crash during startup
    if tool_proc.poll() is not None:
        stdout, stderr = tool_proc.communicate()
        return stdout, stderr, tool_proc.returncode

    # Run Box64 with each test binary
    ran = 0
    for test_bin in test_bins:
        name = os.path.basename(test_bin)
        try:
            result = subprocess.run(
                [box64_bin, test_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=BOX64_PER_BINARY_TIMEOUT,
            )
            status = f"exit {result.returncode}"
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
        except OSError as e:
            status = f"ERROR: {e}"
        print(f"    {name}: {status}")
        ran += 1

    print(f"  Ran {ran} test binaries")

    # Grace period for final eBPF poll cycle
    print(f"  Waiting {grace_period}s for final poll cycle...")
    time.sleep(grace_period)

    # Send SIGINT to trigger print_final_report()
    print("  Sending SIGINT to tool...")
    tool_proc.send_signal(signal.SIGINT)

    try:
        stdout, stderr = tool_proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        tool_proc.kill()
        stdout, stderr = tool_proc.communicate()

    return stdout, stderr, tool_proc.returncode


def check_no_tracebacks(output, label):
    """Check for Python tracebacks in output."""
    if "Traceback (most recent call last)" in output:
        print(f"  FAIL  {label}: Python traceback in output")
        for line in output.splitlines():
            if "Traceback" in line or "Error" in line or "  File " in line:
                print(f"         {line}")
        return False
    return True


def is_zero_size(s):
    """Check if a fmt_size() output string represents zero bytes."""
    return bool(re.match(r'^0(\.0+)?\s*B?$', s.strip()))


def check_dynarec(box64_bin, test_bins):
    """Test box64_dynarec.py against live Box64 processes."""
    print("\n--- box64_dynarec.py ---")

    stdout, stderr, rc = run_tool_test(
        "box64_dynarec.py",
        ["-i", "1"],
        box64_bin, test_bins,
    )

    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "dynarec"):
        errors.append("Python traceback detected")

    if "FINAL REPORT" not in stdout:
        errors.append("FINAL REPORT not found in output")
        print(f"  FAIL  dynarec: FINAL REPORT not found")
        print(f"  stdout ({len(stdout)} chars): {stdout[:500]}")
        print(f"  stderr ({len(stderr)} chars): {stderr[:500]}")
        return False, errors

    # AllocDynarecMap count > 0
    m = re.search(r"AllocDynarecMap:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count > 0:
            print(f"  PASS  AllocDynarecMap: {count}")
        else:
            errors.append("AllocDynarecMap count is 0")
            print(f"  FAIL  AllocDynarecMap count is 0")
    else:
        errors.append("AllocDynarecMap line not found")
        print(f"  FAIL  AllocDynarecMap line not found")

    # Bytes allocated > 0
    m = re.search(r"Bytes allocated:\s+(.+)", stdout)
    if m:
        val = m.group(1).strip()
        if is_zero_size(val):
            errors.append("Bytes allocated is 0")
            print(f"  FAIL  Bytes allocated is 0")
        else:
            print(f"  PASS  Bytes allocated: {val}")
    else:
        errors.append("Bytes allocated line not found")
        print(f"  FAIL  Bytes allocated line not found")

    # FreeDynarecMap count (informational)
    m = re.search(r"FreeDynarecMap:\s+(\d+)", stdout)
    if m:
        print(f"  INFO  FreeDynarecMap: {m.group(1)}")

    # Protection tracking (default-on)
    m = re.search(r"protectDB:\s+(\d+)\s+calls", stdout)
    if m:
        print(f"  INFO  protectDB: {m.group(1)} calls")
    else:
        print(f"  INFO  protectDB not found (symbols may be absent)")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_dynarec.py (all assertions passed)")
    return ok, errors


def check_memleak(box64_bin, test_bins):
    """Test box64_memleak.py against live Box64 processes."""
    print("\n--- box64_memleak.py ---")

    stdout, stderr, rc = run_tool_test(
        "box64_memleak.py",
        ["-i", "1"],
        box64_bin, test_bins,
    )

    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "memleak"):
        errors.append("Python traceback detected")

    if "FINAL REPORT" not in stdout:
        errors.append("FINAL REPORT not found in output")
        print(f"  FAIL  memleak: FINAL REPORT not found")
        print(f"  stdout ({len(stdout)} chars): {stdout[:500]}")
        print(f"  stderr ({len(stderr)} chars): {stderr[:500]}")
        return False, errors

    # Total mallocs > 0
    m = re.search(r"Total mallocs:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count > 0:
            print(f"  PASS  Total mallocs: {count}")
        else:
            errors.append("Total mallocs count is 0")
            print(f"  FAIL  Total mallocs count is 0")
    else:
        errors.append("Total mallocs line not found")
        print(f"  FAIL  Total mallocs line not found")

    # Total frees (informational)
    m = re.search(r"Total frees:\s+(\d+)", stdout)
    if m:
        print(f"  INFO  Total frees: {m.group(1)}")

    # Bytes allocated (informational)
    m = re.search(r"Bytes allocated:\s*(.+)", stdout)
    if m:
        print(f"  INFO  Bytes allocated: {m.group(1).strip()}")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_memleak.py (all assertions passed)")
    return ok, errors


def main():
    parser = argparse.ArgumentParser(
        description="eBPF integration tests against live Box64")
    parser.add_argument("--box64", required=True,
                        help="Path to Box64 binary (with debug symbols)")
    parser.add_argument("--test-bin", nargs="+", default=[],
                        help="Explicit path(s) to x86_64 test binaries")
    parser.add_argument("--test-dir",
                        help="Directory to discover Box64 test binaries "
                             "(test01..test33)")
    args = parser.parse_args()

    # Validate Box64 binary
    if not os.path.isfile(args.box64):
        print(f"ERROR: Box64 binary not found: {args.box64}")
        return 1
    if not os.access(args.box64, os.X_OK):
        print(f"ERROR: Box64 binary not executable: {args.box64}")
        return 1

    # Collect test binaries from both sources
    test_bins = list(args.test_bin)
    if args.test_dir:
        discovered = discover_test_binaries(args.test_dir)
        print(f"Discovered {len(discovered)} test binaries in {args.test_dir}")
        test_bins.extend(discovered)

    if not test_bins:
        print("ERROR: No test binaries specified (use --test-bin and/or --test-dir)")
        return 1

    # Validate explicit test binaries exist
    for tb in args.test_bin:
        if not os.path.isfile(tb):
            print(f"ERROR: Test binary not found: {tb}")
            return 1

    # Check we're root (needed for eBPF)
    if os.geteuid() != 0:
        print("ERROR: Must run as root (eBPF requires CAP_BPF/CAP_SYS_ADMIN)")
        return 1

    # Check BCC is available
    try:
        import bcc  # noqa: F401
    except ImportError:
        print("SKIP: python3-bcc not installed")
        return 0

    print(f"Box64 binary:  {args.box64}")
    print(f"Test binaries: {len(test_bins)} total")
    for tb in test_bins:
        print(f"  {tb}")

    passed = 0
    failed = 0
    errors = []

    ok, errs = check_dynarec(args.box64, test_bins)
    if ok:
        passed += 1
    else:
        failed += 1
        errors.extend(errs)

    ok, errs = check_memleak(args.box64, test_bins)
    if ok:
        passed += 1
    else:
        failed += 1
        errors.extend(errs)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"E2E integration: {passed} passed, {failed} failed")
    if errors:
        print("Failures:")
        for e in errors:
            print(f"  - {e}")
    print(f"{'=' * 60}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
