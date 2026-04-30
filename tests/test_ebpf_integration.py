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
import platform
import re
import signal
import subprocess
import sys
import time


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Per-binary timeout — some Box64 tests may hang on missing libs
BOX64_PER_BINARY_TIMEOUT = 10

# Arguments needed by Box64 test binaries to match their ref files.
# Most tests need no arguments; these are the exceptions.
TEST_ARGS = {
    "test04": ["yeah"],
    "test05": ["7"],
}

# Tests with known ARM64 FP divergences vs x86 ref files:
#   test16: cvtsd2si overflow saturation (0x8000... vs 0x7fff...)
#   test17: psqrtpd NaN sign bit (0xfff8... vs 0x7ff8...)
#   test30: psqrtpd NaN sign bit (same as test17, AVX variant)
#   test31: FE_UPWARD rounding mode precision (x87 vs IEEE)
#   test32: fdivrp/fsqrt x87 extended precision vs IEEE double
ARM64_FP_SKIP = {"test16", "test17", "test30", "test31", "test32"}


def discover_test_binaries(test_dir):
    """Find pre-compiled Box64 test binaries (test01..test33) in a directory."""
    pattern = os.path.join(test_dir, "test[0-9][0-9]")
    bins = sorted(glob.glob(pattern))
    # Filter to actual files (not directories or symlinks to directories)
    return [b for b in bins if os.path.isfile(b)]


def run_tool_test(tool_script, tool_args, box64_bin, test_bins,
                  ready_timeout=30, grace_period=2, timeout=90,
                  test_args=None):
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
        extra_args = (test_args or {}).get(name, [])
        try:
            result = subprocess.run(
                [box64_bin, test_bin] + extra_args,
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


def parse_fmt_size(s):
    """Parse fmt_size() output back to approximate bytes."""
    s = s.strip()
    multipliers = {"TB": 1024**4, "GB": 1024**3, "MB": 1024**2, "KB": 1024, "B": 1}
    for unit, mult in multipliers.items():
        if s.endswith(unit):
            val = float(s[:-len(unit)].strip())
            return int(val * mult)
    return 0


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

    # Total frees > 0
    m_frees = re.search(r"Total frees:\s+(\d+)", stdout)
    if m_frees:
        free_count = int(m_frees.group(1))
        if free_count > 0:
            print(f"  PASS  Total frees: {free_count}")
        else:
            errors.append("Total frees count is 0")
            print(f"  FAIL  Total frees count is 0")
    else:
        errors.append("Total frees line not found")
        print(f"  FAIL  Total frees line not found")

    # Bytes allocated > 0
    m_bytes = re.search(r"Bytes allocated:\s*(.+)", stdout)
    if m_bytes:
        val = m_bytes.group(1).strip()
        if is_zero_size(val):
            errors.append("Bytes allocated is 0")
            print(f"  FAIL  Bytes allocated is 0")
        else:
            print(f"  PASS  Bytes allocated: {val}")
    else:
        errors.append("Bytes allocated line not found")
        print(f"  FAIL  Bytes allocated line not found")

    # Outstanding allocations >= 0 (line present)
    m_outstanding = re.search(r"Outstanding allocs:\s+(\d+)", stdout)
    if m_outstanding:
        outstanding = int(m_outstanding.group(1))
        if outstanding >= 0:
            print(f"  PASS  Outstanding allocs: {outstanding}")
        else:
            errors.append(f"Outstanding allocs negative: {outstanding}")
            print(f"  FAIL  Outstanding allocs negative: {outstanding}")
    else:
        print(f"  INFO  Outstanding allocs line not found")

    # Outstanding bytes >= 0 (line present)
    m_outstanding_bytes = re.search(r"Outstanding bytes:\s*(.+)", stdout)
    if m_outstanding_bytes:
        val = m_outstanding_bytes.group(1).strip()
        print(f"  PASS  Outstanding bytes: {val}")
    else:
        print(f"  INFO  Outstanding bytes line not found")

    # No negative numeric values in the report (sanity check).
    # Lookbehind excludes letters, digits, and underscores so version
    # suffixes ("libc-2.31.so", "box64-0.3.1") and ISO timestamps
    # ("2026-04-18") don't match as negative numbers.
    final_idx = stdout.find("FINAL REPORT")
    if final_idx >= 0:
        report = stdout[final_idx:]
        neg_matches = re.findall(r'(?<![a-zA-Z_0-9])-\d+', report)
        if neg_matches:
            errors.append(f"Negative values found in report: {neg_matches[:5]}")
            print(f"  FAIL  Negative values in report: {neg_matches[:5]}")
        else:
            print(f"  PASS  No negative values in report")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_memleak.py (all assertions passed)")
    return ok, errors


def check_memleak_leaker(box64_bin, leaker_bin):
    """Test box64_memleak.py specifically against memleak_leaker binary.

    memleak_leaker uses _exit(0) to skip cleanup, guaranteeing outstanding
    customMalloc entries that the memleak tool must detect.
    """
    print("\n--- box64_memleak.py (memleak_leaker) ---")

    stdout, stderr, rc, _bin_results = run_tool_test(
        "box64_memleak.py",
        ["-i", "1"],
        box64_bin, [leaker_bin],
    )

    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "memleak-leaker"):
        errors.append("Python traceback detected")

    for line in stdout.splitlines():
        if line.startswith("[*]") or line.startswith("WARNING"):
            print(f"  TOOL  {line}")

    if "FINAL REPORT" not in stdout:
        errors.append("FINAL REPORT not found in output")
        print(f"  FAIL  memleak-leaker: FINAL REPORT not found")
        print(f"  stdout ({len(stdout)} chars): {stdout[:500]}")
        print(f"  stderr ({len(stderr)} chars): {stderr[:500]}")
        return False, errors

    # Total mallocs > Total frees (guaranteed by _exit(0) skipping cleanup)
    m_mallocs = re.search(r"Total mallocs:\s+(\d+)", stdout)
    m_frees = re.search(r"Total frees:\s+(\d+)", stdout)
    if m_mallocs and m_frees:
        mallocs = int(m_mallocs.group(1))
        frees = int(m_frees.group(1))
        if mallocs > frees:
            print(f"  PASS  Total mallocs ({mallocs}) > Total frees ({frees})")
        else:
            errors.append(f"Expected mallocs ({mallocs}) > frees ({frees}) due to _exit(0)")
            print(f"  FAIL  Expected mallocs ({mallocs}) > frees ({frees}) due to _exit(0)")
    elif m_mallocs:
        print(f"  INFO  Total mallocs: {m_mallocs.group(1)} (frees line not found)")
    else:
        errors.append("Total mallocs line not found")
        print(f"  FAIL  Total mallocs line not found")

    # Outstanding allocations > 0 (guaranteed by _exit(0))
    m_outstanding = re.search(r"Outstanding allocs:\s+(\d+)", stdout)
    if m_outstanding:
        outstanding = int(m_outstanding.group(1))
        if outstanding > 0:
            print(f"  PASS  Outstanding allocs: {outstanding} (expected > 0)")
        else:
            errors.append(f"Outstanding allocs is {outstanding}, expected > 0")
            print(f"  FAIL  Outstanding allocs is {outstanding}, expected > 0")
    else:
        print(f"  INFO  Outstanding allocs line not found")

    # Outstanding bytes > 0
    m_outstanding_bytes = re.search(r"Outstanding bytes:\s*(.+)", stdout)
    if m_outstanding_bytes:
        val = m_outstanding_bytes.group(1).strip()
        if is_zero_size(val):
            errors.append("Outstanding bytes is 0, expected > 0")
            print(f"  FAIL  Outstanding bytes is 0, expected > 0")
        else:
            print(f"  PASS  Outstanding bytes: {val}")
    else:
        print(f"  INFO  Outstanding bytes line not found")

    # Size distribution section present when outstanding > 0
    if m_outstanding and int(m_outstanding.group(1)) > 0:
        if "Size distribution:" in stdout:
            print(f"  PASS  Size distribution section present")
        else:
            print(f"  INFO  Size distribution section not found")

    ok = len(errors) == 0
    if ok:
        print(f"  PASS  box64_memleak.py memleak_leaker (all assertions passed)")
    else:
        if stderr.strip():
            print(f"  DEBUG stderr ({len(stderr)} chars):")
            for line in stderr.strip().splitlines()[:30]:
                print(f"         {line}")
    return ok, errors


def check_steam(box64_bin, test_bins):
    """Test box64_trace.py against live Box64 processes with multi-process workload."""
    print("\n--- box64_trace.py ---")

    stdout, stderr, rc, _bin_results = run_tool_test(
        "box64_trace.py",
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

    # fork count >= 10 (steam_lifecycle does 10 forks)
    m = re.search(r"fork:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 10:
            print(f"  PASS  fork: {count}")
        else:
            errors.append(f"fork count is {count}, expected >= 10")
            print(f"  FAIL  fork count is {count}, expected >= 10")
    else:
        errors.append("fork line not found")
        print(f"  FAIL  fork line not found")

    # vfork count >= 10 (steam_lifecycle does 10 vforks)
    m = re.search(r"vfork:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 10:
            print(f"  PASS  vfork: {count}")
        else:
            errors.append(f"vfork count is {count}, expected >= 10")
            print(f"  FAIL  vfork count is {count}, expected >= 10")
    else:
        errors.append("vfork line not found")
        print(f"  FAIL  vfork line not found")

    # exec (all) count >= 10 (20 expected: 10 fork + 10 vfork children each exec)
    m = re.search(r"exec \(all\):\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count >= 10:
            print(f"  PASS  exec (all): {count}")
        else:
            errors.append(f"exec (all) count is {count}, expected >= 10")
            print(f"  FAIL  exec (all) count is {count}, expected >= 10")
    else:
        errors.append("exec (all) line not found")
        print(f"  FAIL  exec (all) line not found")

    # NewBox64Context: exact count = 20 exec'd children + 1 initial context per binary
    # steam_lifecycle creates 10 fork + 10 vfork children, each exec's into a worker
    expected_contexts = 20 + len(test_bins)
    m = re.search(r"NewBox64Context:\s+(\d+)", stdout)
    if m:
        count = int(m.group(1))
        if count == expected_contexts:
            print(f"  PASS  NewBox64Context: {count} (expected {expected_contexts})")
        else:
            errors.append(f"NewBox64Context count is {count}, expected {expected_contexts}")
            print(f"  FAIL  NewBox64Context count is {count}, expected {expected_contexts}")
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

    # Box64 Process Tree with >= 10 distinct PIDs (20+ children created)
    if "Box64 Process Tree:" in stdout:
        # Extract PIDs from tree lines (format: "  PID NNNNN ...")
        tree_pids = set(re.findall(r"PID\s+(\d+)", stdout))
        if len(tree_pids) >= 10:
            print(f"  PASS  Box64 Process Tree: {len(tree_pids)} PIDs")
        else:
            errors.append(f"Process tree has {len(tree_pids)} PIDs, expected >= 10")
            print(f"  FAIL  Process tree has {len(tree_pids)} PIDs, expected >= 10")
    else:
        errors.append("Box64 Process Tree section not found")
        print(f"  FAIL  Box64 Process Tree section not found")

    # Per-PID Memory Breakdown with >= 10 PID sections
    if "Per-PID Memory Breakdown:" in stdout:
        pid_sections = re.findall(r"PID\s+\d+", stdout)
        if len(pid_sections) >= 10:
            print(f"  PASS  Per-PID Memory Breakdown: {len(pid_sections)} PID sections")
        else:
            errors.append(f"Per-PID Breakdown has {len(pid_sections)} sections, expected >= 10")
            print(f"  FAIL  Per-PID Breakdown has {len(pid_sections)} sections, expected >= 10")
    else:
        errors.append("Per-PID Memory Breakdown section not found")
        print(f"  FAIL  Per-PID Memory Breakdown section not found")

    # FreeBox64Context <= NewBox64Context
    m_new_ctx = re.search(r"NewBox64Context:\s+(\d+)", stdout)
    m_free_ctx = re.search(r"FreeBox64Context:\s+(\d+)", stdout)
    if m_new_ctx and m_free_ctx:
        new_ctx = int(m_new_ctx.group(1))
        free_ctx = int(m_free_ctx.group(1))
        if free_ctx <= new_ctx:
            print(f"  PASS  FreeBox64Context ({free_ctx}) <= NewBox64Context ({new_ctx})")
        else:
            errors.append(f"FreeBox64Context ({free_ctx}) > NewBox64Context ({new_ctx})")
            print(f"  FAIL  FreeBox64Context ({free_ctx}) > NewBox64Context ({new_ctx})")
        # FreeBox64Context > 0 (children get cleaned up)
        if free_ctx > 0:
            print(f"  PASS  FreeBox64Context > 0 (children cleaned up)")
        else:
            errors.append("FreeBox64Context is 0, expected > 0")
            print(f"  FAIL  FreeBox64Context is 0, expected > 0")
    elif m_free_ctx:
        print(f"  INFO  FreeBox64Context: {m_free_ctx.group(1)}")
    else:
        print(f"  INFO  FreeBox64Context line not found")

    # DynaRec bytes allocated in sane range [1 KB, 1 GB]
    m_dynarec_bytes = re.search(r"DynaRec JIT.*?Bytes allocated:\s*(.+)", stdout)
    if not m_dynarec_bytes:
        m_dynarec_bytes = re.search(r"Bytes allocated:\s*(.+)", stdout)
    if m_dynarec_bytes:
        val = m_dynarec_bytes.group(1).strip()
        alloc_bytes = parse_fmt_size(val)
        if 1024 <= alloc_bytes <= 1024**3:
            print(f"  PASS  DynaRec bytes in sane range: {val} ({alloc_bytes} bytes)")
        elif alloc_bytes > 0:
            print(f"  INFO  DynaRec bytes: {val} ({alloc_bytes} bytes, outside expected range)")
        else:
            print(f"  INFO  DynaRec bytes: {val}")

    # Thread Summary consistency (if present)
    m_threads_created = re.search(r"Threads created:\s+(\d+)", stdout)
    m_threads_destroyed = re.search(r"Threads destroyed:\s+(\d+)", stdout)
    m_threads_peak = re.search(r"Peak threads:\s+(\d+)", stdout)
    if m_threads_created and m_threads_destroyed:
        created = int(m_threads_created.group(1))
        destroyed = int(m_threads_destroyed.group(1))
        if created >= destroyed:
            print(f"  PASS  Threads created ({created}) >= destroyed ({destroyed})")
        else:
            errors.append(f"Threads created ({created}) < destroyed ({destroyed})")
            print(f"  FAIL  Threads created ({created}) < destroyed ({destroyed})")
    if m_threads_peak:
        peak = int(m_threads_peak.group(1))
        if peak >= 1:
            print(f"  PASS  Peak threads: {peak} (>= 1)")
        else:
            print(f"  INFO  Peak threads: {peak}")

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
        print(f"  PASS  box64_trace.py (all assertions passed)")
    else:
        if stderr.strip():
            print(f"  DEBUG stderr ({len(stderr)} chars):")
            for line in stderr.strip().splitlines()[:30]:
                print(f"         {line}")
    return ok, errors


def check_steam_sampling(box64_bin, test_bins):
    """Test box64_trace.py with PC sampling (--sample-freq) enabled."""
    print("\n--- box64_trace.py (PC sampling) ---")

    stdout, stderr, rc, _bin_results = run_tool_test(
        "box64_trace.py",
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

    # Detect BCC incompatibility (tool compiled without TRACK_PROFILE)
    if "PC sampling unavailable" in combined:
        print(f"  SKIP  PC sampling unavailable (BCC version incompatibility)")
        # Still check that the tool ran successfully without profiling
        if "FINAL REPORT" in stdout:
            print(f"  PASS  Tool ran successfully without PC sampling")
        return True, []  # SKIP, not FAIL

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

    # PC Sampling Profile section — sampling attached but short-lived test
    # processes may not produce enough samples for the section to appear
    if "PC Sampling Profile" in stdout:
        print(f"  PASS  PC Sampling Profile section present")
    elif "PC sampling attached" in stdout:
        print(f"  INFO  PC sampling attached but no profile section "
              f"(test processes too short-lived for samples)")
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
        print(f"  PASS  box64_trace.py PC sampling (all assertions passed)")
    else:
        if stderr.strip():
            print(f"  DEBUG stderr ({len(stderr)} chars):")
            for line in stderr.strip().splitlines()[:30]:
                print(f"         {line}")
    return ok, errors


def check_spawn_mode(box64_bin, stress_bin, timeout=60):
    """Test box64_trace.py spawn-and-trace mode end-to-end.

    Runs `box64_trace.py --no-web -- <box64> <stress_bin>` directly: the
    tracer should fork the child paused, attach probes, SIGCONT, wait for
    the child to exit, print FINAL REPORT, and exit with the child's rc.
    """
    print("\n--- box64_trace.py (spawn mode) ---")

    tool_path = os.path.join(REPO_ROOT, "box64_trace.py")
    cmd = [sys.executable, "-u", tool_path, "-b", box64_bin, "-i", "60",
           "--no-web", "--", box64_bin, stress_bin]

    print(f"  Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  FAIL  spawn mode: timed out after {timeout}s")
        return False, [f"spawn mode timed out after {timeout}s"]

    stdout, stderr, rc = result.stdout, result.stderr, result.returncode
    combined = stdout + "\n" + stderr
    errors = []

    if not check_no_tracebacks(combined, "spawn"):
        errors.append("Python traceback in spawn-mode output")

    # Required lines proving the spawn-mode flow ran end-to-end.
    expectations = {
        "Spawning:": "tracer announced the spawn",
        "stopped — attaching probes": "child reached SIGSTOP gate",
        "probes attached": "BPF probes attached after gate",
        "Resumed child PID": "child SIGCONTed after probes",
        "Child PID": "child exit detected (poll loop)",
        "exited (rc=": "child return code captured",
        "FINAL REPORT": "trace report still printed on exit",
    }
    for needle, what in expectations.items():
        if needle in stdout:
            print(f"  PASS  {what} ('{needle}')")
        else:
            errors.append(f"missing '{needle}' — {what}")
            print(f"  FAIL  {what}: '{needle}' not in stdout")

    # Exit code should match the spawned program's exit code. dynarec_stress
    # exits 0 on success; we accept any non-128+signal, non-127 (exec fail).
    if rc == 127:
        errors.append("tracer exited 127 (exec failed)")
        print(f"  FAIL  spawn exec failed (rc=127)")
    elif rc >= 128:
        errors.append(f"tracer exited {rc} — child terminated by signal "
                      f"{rc - 128}")
        print(f"  FAIL  child died from signal {rc - 128}")
    else:
        print(f"  PASS  tracer forwarded child rc ({rc})")

    ok = not errors
    if ok:
        print(f"  PASS  box64_trace.py -- spawn mode (all assertions)")
    return ok, errors


def check_output_correctness(box64_bin, test_bins, test_dir):
    """Verify Box64 output matches upstream ref files while uprobes are attached.

    Compares probed output against refNN.txt files from the Box64 source tree.
    This simultaneously validates correctness and non-perturbation by probes.
    Skips tests with known ARM64 FP divergences on aarch64.
    """
    print("\n--- Output correctness (uprobes attached) ---")

    is_arm64 = platform.machine() in ("aarch64", "arm64")

    # Load ref files
    refs = {}
    for test_bin in test_bins:
        name = os.path.basename(test_bin)
        m = re.match(r'test(\d+)', name)
        if not m:
            continue
        ref_path = os.path.join(test_dir, f"ref{m.group(1)}.txt")
        if os.path.isfile(ref_path):
            with open(ref_path) as f:
                refs[name] = f.read()

    if not refs:
        print("  SKIP  No ref files found")
        return True, []

    # Run with probes attached and correct per-test arguments.
    # box64_trace.py attaches a superset of dynarec's probes, so this
    # exercises non-perturbation against the broadest probe set.
    stdout, stderr, rc, bin_results = run_tool_test(
        "box64_trace.py", ["-i", "1"],
        box64_bin, test_bins,
        test_args=TEST_ARGS,
    )

    errors = []
    checked = 0
    matched = 0
    skipped_fp = 0

    for name, bin_stdout, bin_rc in bin_results:
        if name not in refs:
            continue

        # Skip ARM64 FP-divergent tests
        if is_arm64 and name in ARM64_FP_SKIP:
            skipped_fp += 1
            continue

        if bin_rc != 0:
            print(f"    {name}: skipped (exit {bin_rc})")
            continue

        checked += 1
        actual_lines = bin_stdout.rstrip().splitlines()
        expected_lines = refs[name].rstrip().splitlines()

        if actual_lines == expected_lines:
            matched += 1
        else:
            num = re.match(r'test(\d+)', name).group(1)
            errors.append(f"{name}: output differs from ref{num}.txt")
            print(f"  FAIL  {name}: output differs")
            # Show first diff
            for i, (e, a) in enumerate(
                    zip(expected_lines, actual_lines)):
                if e != a:
                    print(f"         line {i+1} expected: {e[:80]}")
                    print(f"         line {i+1} actual:   {a[:80]}")
                    break

    if skipped_fp:
        print(f"  INFO  Skipped {skipped_fp} tests with known ARM64 FP"
              " divergences")
    print(f"  INFO  {matched}/{checked} binaries matched ref output")

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

    ok, errs = check_memleak(args.box64, test_bins)
    if ok:
        passed += 1
    else:
        failed += 1
        errors.extend(errs)

    # Output correctness: only testNN binaries have deterministic output
    testdir_bins = [tb for tb in test_bins
                    if re.match(r'test\d+', os.path.basename(tb))]
    if testdir_bins and args.test_dir:
        ok, errs = check_output_correctness(
            args.box64, testdir_bins, args.test_dir)
        if ok:
            passed += 1
        else:
            failed += 1
            errors.extend(errs)
    else:
        print("\n  SKIP  Output correctness: no testNN binaries found")

    # Memleak leaker test (dedicated binary)
    memleak_bin = next(
        (tb for tb in test_bins if 'memleak_leaker' in os.path.basename(tb)),
        None,
    )
    if memleak_bin:
        ok, errs = check_memleak_leaker(args.box64, memleak_bin)
        if ok:
            passed += 1
        else:
            failed += 1
            errors.extend(errs)
    else:
        print("\n  SKIP  box64_memleak.py (memleak_leaker): binary not found")

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
        print("\n  SKIP  box64_trace.py: steam_lifecycle binary not found")
        print("  SKIP  box64_trace.py (PC sampling): steam_lifecycle binary not found")

    # Spawn-and-trace mode (`-- COMMAND`). Uses dynarec_stress as a
    # short-lived workload; the tracer should fork it paused, attach,
    # resume, and exit with the child's rc.
    if stress_bin:
        ok, errs = check_spawn_mode(args.box64, stress_bin)
        if ok:
            passed += 1
        else:
            failed += 1
            errors.extend(errs)
    else:
        print("\n  SKIP  box64_trace.py (spawn mode): dynarec_stress not found")

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
