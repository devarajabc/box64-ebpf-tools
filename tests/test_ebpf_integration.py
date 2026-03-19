#!/usr/bin/env python3
"""End-to-end eBPF integration tests: run our tools against a live Box64 process.

Requires: root, python3-bcc, a Box64 binary (with debug symbols), and a Box64
test binary (e.g. tests/test01 from the Box64 repo).

Run directly (not through pytest):
    sudo python3 tests/test_ebpf_integration.py \
        --box64 /tmp/box64-build/box64 \
        --test-bin /tmp/box64-src/tests/test01
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import time


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_tool_test(tool_script, tool_args, box64_bin, test_bin,
                  attach_wait=3, grace_period=2, timeout=60):
    """Run an eBPF tool against a Box64 process and return its stdout.

    1. Start the tool in background
    2. Wait for probe attachment
    3. Run Box64 with the test binary
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

    # Run Box64 with the test binary
    box64_cmd = [box64_bin, test_bin]
    print(f"  Running: {' '.join(box64_cmd)}")
    try:
        box64_result = subprocess.run(
            box64_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        print(f"  Box64 exited with code {box64_result.returncode}")
    except subprocess.TimeoutExpired:
        print("  WARNING: Box64 timed out after 30s")

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
        # Print the traceback for debugging
        for line in output.splitlines():
            if "Traceback" in line or "Error" in line or "  File " in line:
                print(f"         {line}")
        return False
    return True


def check_dynarec(box64_bin, test_bin):
    """Test box64_dynarec.py against a live Box64 process."""
    print("\n--- box64_dynarec.py ---")

    stdout, stderr, rc = run_tool_test(
        "box64_dynarec.py",
        ["-i", "1"],
        box64_bin, test_bin,
    )

    combined = stdout + "\n" + stderr
    errors = []

    # Check for tracebacks
    if not check_no_tracebacks(combined, "dynarec"):
        errors.append("Python traceback detected")

    # Check for FINAL REPORT
    if "FINAL REPORT" not in stdout:
        errors.append("FINAL REPORT not found in output")
        print(f"  FAIL  dynarec: FINAL REPORT not found")
        print(f"  stdout ({len(stdout)} chars): {stdout[:500]}")
        print(f"  stderr ({len(stderr)} chars): {stderr[:500]}")
        return False, errors

    # Check AllocDynarecMap count > 0
    m = re.search(r"AllocDynarecMap:\s+(\d+)", stdout)
    if m:
        alloc_count = int(m.group(1))
        if alloc_count > 0:
            print(f"  PASS  AllocDynarecMap: {alloc_count}")
        else:
            errors.append("AllocDynarecMap count is 0")
            print(f"  FAIL  AllocDynarecMap count is 0")
    else:
        errors.append("AllocDynarecMap line not found")
        print(f"  FAIL  AllocDynarecMap line not found in output")

    # Check Bytes allocated > 0
    m = re.search(r"Bytes allocated:\s+(\S+)", stdout)
    if m:
        bytes_str = m.group(1)
        # fmt_size returns "0 B" for zero, otherwise something like "1.2 MB"
        if bytes_str == "0" or bytes_str == "0 B":
            errors.append("Bytes allocated is 0")
            print(f"  FAIL  Bytes allocated is 0")
        else:
            print(f"  PASS  Bytes allocated: {bytes_str}")
    else:
        errors.append("Bytes allocated line not found")
        print(f"  FAIL  Bytes allocated line not found in output")

    # Check protection tracking (default-on feature)
    m = re.search(r"protectDB:\s+(\d+)\s+calls", stdout)
    if m:
        prot_count = int(m.group(1))
        print(f"  PASS  protectDB: {prot_count} calls")
    else:
        # Protection section may be absent if symbols were auto-disabled
        print(f"  INFO  protectDB line not found (symbols may be absent)")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_dynarec.py (all assertions passed)")
    return ok, errors


def check_memleak(box64_bin, test_bin):
    """Test box64_memleak.py against a live Box64 process."""
    print("\n--- box64_memleak.py ---")

    stdout, stderr, rc = run_tool_test(
        "box64_memleak.py",
        ["-i", "1"],
        box64_bin, test_bin,
    )

    combined = stdout + "\n" + stderr
    errors = []

    # Check for tracebacks
    if not check_no_tracebacks(combined, "memleak"):
        errors.append("Python traceback detected")

    # Check for FINAL REPORT
    if "FINAL REPORT" not in stdout:
        errors.append("FINAL REPORT not found in output")
        print(f"  FAIL  memleak: FINAL REPORT not found")
        print(f"  stdout ({len(stdout)} chars): {stdout[:500]}")
        print(f"  stderr ({len(stderr)} chars): {stderr[:500]}")
        return False, errors

    # Check Total mallocs > 0
    m = re.search(r"Total mallocs:\s+(\d+)", stdout)
    if m:
        malloc_count = int(m.group(1))
        if malloc_count > 0:
            print(f"  PASS  Total mallocs: {malloc_count}")
        else:
            errors.append("Total mallocs count is 0")
            print(f"  FAIL  Total mallocs count is 0")
    else:
        errors.append("Total mallocs line not found")
        print(f"  FAIL  Total mallocs line not found in output")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_memleak.py (all assertions passed)")
    return ok, errors


def main():
    parser = argparse.ArgumentParser(
        description="eBPF integration tests against live Box64")
    parser.add_argument("--box64", required=True,
                        help="Path to Box64 binary (with debug symbols)")
    parser.add_argument("--test-bin", required=True,
                        help="Path to a Box64 test binary (e.g. test01)")
    args = parser.parse_args()

    # Validate paths
    if not os.path.isfile(args.box64):
        print(f"ERROR: Box64 binary not found: {args.box64}")
        return 1
    if not os.access(args.box64, os.X_OK):
        print(f"ERROR: Box64 binary not executable: {args.box64}")
        return 1
    if not os.path.isfile(args.test_bin):
        print(f"ERROR: Test binary not found: {args.test_bin}")
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

    print(f"Box64 binary: {args.box64}")
    print(f"Test binary:  {args.test_bin}")

    passed = 0
    failed = 0
    errors = []

    # Test dynarec tool
    ok, errs = check_dynarec(args.box64, args.test_bin)
    if ok:
        passed += 1
    else:
        failed += 1
        errors.extend(errs)

    # Test memleak tool
    ok, errs = check_memleak(args.box64, args.test_bin)
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
