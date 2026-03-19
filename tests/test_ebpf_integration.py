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
                  ready_timeout=30, grace_period=2, timeout=90):
    """Run an eBPF tool against Box64 processes and return its stdout.

    1. Start the tool, redirect output to temp files
    2. Poll stdout for "probes attached" (BPF compilation can be slow)
    3. Run Box64 with each test binary in sequence
    4. Wait for completion + grace period
    5. SIGINT the tool to trigger final report
    6. Return (stdout, stderr, returncode)
    """
    import tempfile

    tool_path = os.path.join(REPO_ROOT, tool_script)
    cmd = [sys.executable, "-u", tool_path, "-b", box64_bin] + tool_args

    # Use temp files so we can poll stdout for readiness
    stdout_fd, stdout_path = tempfile.mkstemp(prefix="ebpf_stdout_")
    stderr_fd, stderr_path = tempfile.mkstemp(prefix="ebpf_stderr_")
    stdout_file = os.fdopen(stdout_fd, "w")
    stderr_file = os.fdopen(stderr_fd, "w")

    print(f"  Starting: {' '.join(cmd)}")
    tool_proc = subprocess.Popen(cmd, stdout=stdout_file, stderr=stderr_file)

    # Poll stdout for "probes attached" — this confirms BPF compiled and
    # all uprobes are registered. Much more reliable than a fixed sleep.
    ready = False
    for i in range(ready_timeout):
        if tool_proc.poll() is not None:
            # Tool exited before becoming ready
            break
        try:
            with open(stdout_path) as f:
                content = f.read()
            if "probes attached" in content:
                ready = True
                print(f"  Tool ready after {i + 1}s")
                break
        except OSError:
            pass
        time.sleep(1)

    if not ready:
        if tool_proc.poll() is not None:
            stdout_file.close()
            stderr_file.close()
            with open(stdout_path) as f:
                stdout = f.read()
            with open(stderr_path) as f:
                stderr = f.read()
            os.unlink(stdout_path)
            os.unlink(stderr_path)
            print(f"  Tool exited early (code {tool_proc.returncode})")
            return stdout, stderr, tool_proc.returncode, []
        print(f"  WARNING: Tool not ready after {ready_timeout}s, proceeding anyway")

    # Run Box64 with each test binary
    ran = 0
    bin_results = []
    for test_bin in test_bins:
        name = os.path.basename(test_bin)
        try:
            result = subprocess.run(
                [box64_bin, test_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=BOX64_PER_BINARY_TIMEOUT,
            )
            status = f"exit {result.returncode}"
            bin_results.append((name, result.stdout, result.returncode))
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
            bin_results.append((name, "", -1))
        except OSError as e:
            status = f"ERROR: {e}"
            bin_results.append((name, "", -1))
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
        tool_proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        tool_proc.kill()
        tool_proc.wait()

    stdout_file.close()
    stderr_file.close()

    with open(stdout_path) as f:
        stdout = f.read()
    with open(stderr_path) as f:
        stderr = f.read()
    os.unlink(stdout_path)
    os.unlink(stderr_path)

    return stdout, stderr, tool_proc.returncode, bin_results


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

    stdout, stderr, rc, _bin_results = run_tool_test(
        "box64_dynarec.py",
        ["-i", "1"],
        box64_bin, test_bins,
    )

    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "dynarec"):
        errors.append("Python traceback detected")

    # Print tool startup info for debugging
    for line in stdout.splitlines():
        if line.startswith("[*]") or line.startswith("WARNING"):
            print(f"  TOOL  {line}")

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
    else:
        # Dump stderr for debugging probe attachment issues
        if stderr.strip():
            print(f"  DEBUG stderr ({len(stderr)} chars):")
            for line in stderr.strip().splitlines()[:30]:
                print(f"         {line}")
    return ok, errors


def check_memleak(box64_bin, test_bins):
    """Test box64_memleak.py against live Box64 processes."""
    print("\n--- box64_memleak.py ---")

    stdout, stderr, rc, _bin_results = run_tool_test(
        "box64_memleak.py",
        ["-i", "1"],
        box64_bin, test_bins,
    )

    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "memleak"):
        errors.append("Python traceback detected")

    # Print tool startup info for debugging
    for line in stdout.splitlines():
        if line.startswith("[*]") or line.startswith("WARNING"):
            print(f"  TOOL  {line}")

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


def check_steam(box64_bin, test_bins):
    """Test box64_steam.py against live Box64 processes with multi-process workload."""
    print("\n--- box64_steam.py ---")

    stdout, stderr, rc, _bin_results = run_tool_test(
        "box64_steam.py",
        ["-i", "2"],
        box64_bin, test_bins,
        ready_timeout=40,
    )

    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "steam"):
        errors.append("Python traceback detected")

    # Print tool startup info for debugging
    for line in stdout.splitlines():
        if line.startswith("[*]") or line.startswith("WARNING"):
            print(f"  TOOL  {line}")

    if "FINAL REPORT" not in stdout:
        errors.append("FINAL REPORT not found in output")
        print(f"  FAIL  steam: FINAL REPORT not found")
        print(f"  stdout ({len(stdout)} chars): {stdout[:500]}")
        print(f"  stderr ({len(stderr)} chars): {stderr[:500]}")
        return False, errors

    # fork count >= 1
    m = re.search(r"fork:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 1:
            print(f"  PASS  fork: {count}")
        else:
            errors.append("fork count is 0")
            print(f"  FAIL  fork count is 0")
    else:
        errors.append("fork line not found")
        print(f"  FAIL  fork line not found")

    # vfork count >= 1
    m = re.search(r"vfork:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 1:
            print(f"  PASS  vfork: {count}")
        else:
            errors.append("vfork count is 0")
            print(f"  FAIL  vfork count is 0")
    else:
        errors.append("vfork line not found")
        print(f"  FAIL  vfork line not found")

    # exec (all) count >= 2
    m = re.search(r"exec \(all\):\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 2:
            print(f"  PASS  exec (all): {count}")
        else:
            errors.append(f"exec (all) count is {count}, expected >= 2")
            print(f"  FAIL  exec (all) count is {count}, expected >= 2")
    else:
        errors.append("exec (all) line not found")
        print(f"  FAIL  exec (all) line not found")

    # NewBox64Context count >= 3
    m = re.search(r"NewBox64Context:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 3:
            print(f"  PASS  NewBox64Context: {count}")
        else:
            errors.append(f"NewBox64Context count is {count}, expected >= 3")
            print(f"  FAIL  NewBox64Context count is {count}, expected >= 3")
    else:
        errors.append("NewBox64Context line not found")
        print(f"  FAIL  NewBox64Context line not found")

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

    # malloc count > 0 (from Custom Allocator Totals section)
    m = re.search(r"malloc:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count > 0:
            print(f"  PASS  malloc: {count}")
        else:
            errors.append("malloc count is 0")
            print(f"  FAIL  malloc count is 0")
    else:
        errors.append("malloc line not found")
        print(f"  FAIL  malloc line not found")

    # Box64 Process Tree with >= 2 distinct PIDs
    if "Box64 Process Tree:" in stdout:
        # Extract PIDs from tree lines (format: "  PID NNNNN ...")
        tree_pids = set(re.findall(r"PID\s+(\d+)", stdout))
        if len(tree_pids) >= 2:
            print(f"  PASS  Box64 Process Tree: {len(tree_pids)} PIDs")
        else:
            errors.append(f"Process tree has {len(tree_pids)} PIDs, expected >= 2")
            print(f"  FAIL  Process tree has {len(tree_pids)} PIDs, expected >= 2")
    else:
        errors.append("Box64 Process Tree section not found")
        print(f"  FAIL  Box64 Process Tree section not found")

    # Per-PID Memory Breakdown with >= 2 PID sections
    if "Per-PID Memory Breakdown:" in stdout:
        pid_sections = re.findall(r"PID\s+\d+", stdout)
        if len(pid_sections) >= 2:
            print(f"  PASS  Per-PID Memory Breakdown: {len(pid_sections)} PID sections")
        else:
            errors.append(f"Per-PID Breakdown has {len(pid_sections)} sections, expected >= 2")
            print(f"  FAIL  Per-PID Breakdown has {len(pid_sections)} sections, expected >= 2")
    else:
        errors.append("Per-PID Memory Breakdown section not found")
        print(f"  FAIL  Per-PID Memory Breakdown section not found")

    # Informational checks (no fail)
    if "Memory Growth Timeline" in stdout:
        print(f"  INFO  Memory Growth Timeline present")
    else:
        print(f"  INFO  Memory Growth Timeline not present")

    m = re.search(r"protectDB:\s+(\d+)\s+calls", stdout)
    if m:
        print(f"  INFO  protectDB: {m.group(1)} calls")
    else:
        print(f"  INFO  protectDB not found (symbols may be absent)")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_steam.py (all assertions passed)")
    else:
        if stderr.strip():
            print(f"  DEBUG stderr ({len(stderr)} chars):")
            for line in stderr.strip().splitlines()[:30]:
                print(f"         {line}")
    return ok, errors


def check_steam_sampling(box64_bin, test_bins):
    """Test box64_steam.py with PC sampling (--sample-freq) enabled."""
    print("\n--- box64_steam.py (PC sampling) ---")

    stdout, stderr, rc, _bin_results = run_tool_test(
        "box64_steam.py",
        ["-i", "2", "--sample-freq", "4999"],
        box64_bin, test_bins,
        ready_timeout=40,
        grace_period=4,
    )

    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "steam-sampling"):
        errors.append("Python traceback detected")

    # Print tool startup info for debugging
    for line in stdout.splitlines():
        if line.startswith("[*]") or line.startswith("WARNING"):
            print(f"  TOOL  {line}")

    if "FINAL REPORT" not in stdout:
        errors.append("FINAL REPORT not found in output")
        print(f"  FAIL  steam-sampling: FINAL REPORT not found")
        print(f"  stdout ({len(stdout)} chars): {stdout[:500]}")
        print(f"  stderr ({len(stderr)} chars): {stderr[:500]}")
        return False, errors

    # NewBox64Context count >= 1
    m = re.search(r"NewBox64Context:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 1:
            print(f"  PASS  NewBox64Context: {count}")
        else:
            errors.append("NewBox64Context count is 0")
            print(f"  FAIL  NewBox64Context count is 0")
    else:
        errors.append("NewBox64Context line not found")
        print(f"  FAIL  NewBox64Context line not found")

    # PC Sampling Profile section present
    if "PC Sampling Profile" in stdout:
        print(f"  PASS  PC Sampling Profile section present")
    else:
        errors.append("PC Sampling Profile section not found")
        print(f"  FAIL  PC Sampling Profile section not found")

    # Informational checks (no fail)
    if "Block Age Distribution:" in stdout:
        print(f"  INFO  Block Age Distribution present")
    else:
        print(f"  INFO  Block Age Distribution not present")

    if "Eviction Threshold Analysis:" in stdout:
        print(f"  INFO  Eviction Threshold Analysis present")
    else:
        print(f"  INFO  Eviction Threshold Analysis not present")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_steam.py PC sampling (all assertions passed)")
    else:
        if stderr.strip():
            print(f"  DEBUG stderr ({len(stderr)} chars):")
            for line in stderr.strip().splitlines()[:30]:
                print(f"         {line}")
    return ok, errors


def run_baseline(box64_bin, test_bins):
    """Run Box64 with each test binary (no eBPF) and return per-binary output."""
    baseline = {}
    for test_bin in test_bins:
        name = os.path.basename(test_bin)
        try:
            result = subprocess.run(
                [box64_bin, test_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=BOX64_PER_BINARY_TIMEOUT,
            )
            baseline[name] = (result.stdout, result.returncode)
        except (subprocess.TimeoutExpired, OSError):
            baseline[name] = ("", -1)
    return baseline


def check_output_correctness(box64_bin, test_bins):
    """Verify Box64 output is unchanged while eBPF uprobes are attached.

    Compares a baseline run (no probes) against a probed run to detect
    instrumentation-induced perturbations.  Does NOT compare against upstream
    refNN.txt files, because Box64 on ARM64 has known FP-precision divergences.
    """
    print("\n--- Output correctness (uprobes attached) ---")

    # 1. Baseline: run without any eBPF tool
    print("  Running baseline (no probes)...")
    baseline = run_baseline(box64_bin, test_bins)
    print(f"  Baseline: {len(baseline)} binaries")

    # 2. Probed: run with lightest tool
    stdout, stderr, rc, bin_results = run_tool_test(
        "box64_dynarec.py", ["-i", "1"],
        box64_bin, test_bins,
    )

    errors = []
    checked = 0
    matched = 0

    for name, bin_stdout, bin_rc in bin_results:
        base_stdout, base_rc = baseline.get(name, ("", -1))

        # Skip if either run failed
        if base_rc != 0 or bin_rc != 0:
            print(f"    {name}: skipped (baseline exit {base_rc},"
                  f" probed exit {bin_rc})")
            continue

        checked += 1
        actual_lines = bin_stdout.rstrip().splitlines()
        expected_lines = base_stdout.rstrip().splitlines()

        if actual_lines == expected_lines:
            matched += 1
        else:
            errors.append(f"{name}: output differs with probes attached")
            print(f"  FAIL  {name}: output differs (baseline vs probed)")
            # Show first diff
            for i, (a, e) in enumerate(zip(actual_lines, expected_lines)):
                if a != e:
                    print(f"         line {i+1} baseline: {e[:80]}")
                    print(f"         line {i+1} probed:   {a[:80]}")
                    break

    print(f"  INFO  {matched}/{checked} binaries matched baseline output")

    ok = len(errors) == 0
    if ok and checked > 0:
        print(f"  PASS  Output correctness ({matched}/{checked} matched)")
    elif checked == 0:
        print(f"  SKIP  No binaries produced output in both runs")
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

    # Output correctness: only testNN binaries have deterministic output
    testdir_bins = [tb for tb in test_bins
                    if re.match(r'test\d+', os.path.basename(tb))]
    if testdir_bins:
        ok, errs = check_output_correctness(args.box64, testdir_bins)
        if ok:
            passed += 1
        else:
            failed += 1
            errors.extend(errs)
    else:
        print("\n  SKIP  Output correctness: no testNN binaries found")

    # Steam tests use specific binaries
    steam_bin = next(
        (tb for tb in test_bins if 'steam_lifecycle' in os.path.basename(tb)),
        None,
    )
    stress_bin = next(
        (tb for tb in test_bins if 'dynarec_stress' in os.path.basename(tb)),
        None,
    )

    if steam_bin:
        steam_bins = [steam_bin]
        if stress_bin:
            steam_bins.append(stress_bin)

        ok, errs = check_steam(args.box64, steam_bins)
        if ok:
            passed += 1
        else:
            failed += 1
            errors.extend(errs)

        ok, errs = check_steam_sampling(args.box64, [steam_bin])
        if ok:
            passed += 1
        else:
            failed += 1
            errors.extend(errs)
    else:
        print("\n  SKIP  box64_steam.py: steam_lifecycle binary not found")
        print("  SKIP  box64_steam.py (PC sampling): steam_lifecycle binary not found")

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
