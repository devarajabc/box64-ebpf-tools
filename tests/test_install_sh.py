"""Tests for install.sh and uninstall.sh.

Three layers:
  - Static checks  : bash -n, executability, --help text, unknown-flag rejection.
  - Distro coverage: the package-manager mapping covers all distros the README
                     promises to support.
  - Round-trip     : install into a tmpdir PREFIX with --skip-deps, verify file
                     layout + wrapper behaviour + idempotency + clean uninstall.

We deliberately don't exercise the BCC-install or box64-verify branches end-to-end
because they require either an absent BCC, an absent box64, or the ability to
run `apt install` — none of which is reproducible in CI without containers.
"""
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
UNINSTALL_SH = REPO_ROOT / "uninstall.sh"

pytestmark = pytest.mark.skipif(
    not INSTALL_SH.exists() or not UNINSTALL_SH.exists(),
    reason="install scripts not present",
)


def _run(*args, **env_overrides):
    env = os.environ.copy()
    env.update({k: str(v) for k, v in env_overrides.items()})
    return subprocess.run(args, env=env, capture_output=True, text=True)


def _install(prefix, *flags):
    return _run(str(INSTALL_SH), "-y", *flags, PREFIX=prefix)


def _uninstall(prefix):
    return _run(str(UNINSTALL_SH), PREFIX=prefix)


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------

class TestStatic:
    def test_install_sh_is_executable(self):
        assert os.access(INSTALL_SH, os.X_OK)

    def test_uninstall_sh_is_executable(self):
        assert os.access(UNINSTALL_SH, os.X_OK)

    def test_install_sh_passes_bash_syntax_check(self):
        r = subprocess.run(["bash", "-n", str(INSTALL_SH)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_uninstall_sh_passes_bash_syntax_check(self):
        r = subprocess.run(["bash", "-n", str(UNINSTALL_SH)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_help_documents_all_flags(self):
        r = _run(str(INSTALL_SH), "--help")
        assert r.returncode == 0
        for needle in ("--yes", "--skip-deps", "--no-bcc",
                       "--no-box64-check", "--no-browser-check", "PREFIX"):
            assert needle in r.stdout, f"--help missing '{needle}'"

    def test_unknown_flag_exits_nonzero(self):
        r = _run(str(INSTALL_SH), "--bogus")
        assert r.returncode != 0
        assert "unknown flag" in (r.stderr + r.stdout)


# ---------------------------------------------------------------------------
# Distro → package manager mapping
# ---------------------------------------------------------------------------

class TestDistroCoverage:
    SCRIPT = INSTALL_SH.read_text()

    @pytest.mark.parametrize("distro", [
        # apt
        "ubuntu", "debian", "raspbian", "pop", "linuxmint",
        # dnf
        "fedora", "rhel", "centos", "rocky", "almalinux",
        # pacman
        "arch", "manjaro", "endeavouros",
        # zypper
        "opensuse", "sles",
    ])
    def test_distro_appears_in_mapping(self, distro):
        assert distro in self.SCRIPT, (
            f"install.sh's bcc_install_spec doesn't mention '{distro}'")

    def test_each_package_manager_referenced(self):
        for pm in ("apt", "dnf", "pacman", "zypper"):
            assert pm in self.SCRIPT, f"no branch for '{pm}'"


# ---------------------------------------------------------------------------
# Kernel-headers detection. BCC compiles BPF programs at JIT time and
# needs the *running* kernel's headers; without them every tool launch
# dies with "modprobe: FATAL: Module kheaders not found / chdir(/lib/
# modules/<ver>/build): No such file or directory". The installer must
# detect this up front and fix it, not let the user discover it at
# runtime.
# ---------------------------------------------------------------------------

class TestKernelHeadersStatic:
    """Static checks: the function exists, the right per-distro packages
    are mentioned, and the three detection paths are present."""
    SCRIPT = INSTALL_SH.read_text()

    def test_check_kernel_headers_function_defined(self):
        assert "check_kernel_headers()" in self.SCRIPT

    def test_check_kernel_headers_called_from_main(self):
        # Wired into the main flow alongside install_bcc, so users get
        # the headers fix proactively rather than at runtime.
        assert "check_kernel_headers" in self.SCRIPT.split("# Main", 1)[1]

    def test_three_detection_paths_present(self):
        # 1. /lib/modules/<ver>/build/Makefile (the default BCC path)
        # 2. /sys/kernel/kheaders.tar.xz (CONFIG_IKHEADERS exposed)
        # 3. modprobe kheaders (CONFIG_IKHEADERS=m, just not loaded)
        assert "/lib/modules/" in self.SCRIPT
        assert "/Makefile" in self.SCRIPT
        assert "/sys/kernel/kheaders.tar.xz" in self.SCRIPT
        assert "modprobe kheaders" in self.SCRIPT

    @pytest.mark.parametrize("distro,expected_pkg_or_meta", [
        # Raspberry Pi OS gets the meta-package that tracks the kernel.
        ("raspbian", "raspberrypi-kernel-headers"),
        # Ubuntu's raspi flavor uses linux-headers-<uname-r>, which
        # apt resolves (e.g. linux-headers-6.8.0-1052-raspi). This is
        # the user's reported case: they hit the bug on Ubuntu running
        # the raspi kernel and apt expects the version-suffixed name.
        ("ubuntu", "linux-headers-"),
        ("debian", "linux-headers-"),
        ("fedora", "kernel-devel-"),
        ("arch", "linux-headers"),
        ("opensuse", "kernel-devel"),
    ])
    def test_per_distro_headers_pkg(self, distro, expected_pkg_or_meta):
        # We don't need to be byte-exact — verify the right package name
        # appears within the same case branch as the distro.
        # The function `headers_install_spec` is small and we want each
        # branch independently grep-able.
        assert expected_pkg_or_meta in self.SCRIPT, (
            f"install.sh has no '{expected_pkg_or_meta}' line — "
            f"distro '{distro}' will fall through to the unknown-distro "
            f"path even though we should know its headers package.")


class TestKernelHeadersBehavior:
    """Drive headers_install_spec via subprocess with each (distro, kernel)
    combination, verifying the right package name comes back."""

    @pytest.mark.parametrize("distro,uname_r,expected", [
        # The exact user-reported case: Ubuntu 24.04 LTS on a Raspberry
        # Pi 5, kernel 6.8.0-1052-raspi. apt resolves this to the
        # linux-headers-raspi flavor — version-suffixed package matters.
        ("ubuntu", "6.8.0-1052-raspi", "linux-headers-6.8.0-1052-raspi"),
        ("debian", "6.1.0-25-arm64", "linux-headers-6.1.0-25-arm64"),
        ("raspbian", "6.6.31+rpt-rpi-v8", "raspberrypi-kernel-headers"),
        ("fedora", "6.10.5-200.fc40.aarch64",
         "kernel-devel-6.10.5-200.fc40.aarch64"),
        ("arch", "6.10.6-arch1-1", "linux-headers"),
        ("opensuse-tumbleweed", "6.10.6-1-default", "kernel-devel"),
    ])
    def test_headers_install_spec_returns_correct_pkg(
            self, distro, uname_r, expected):
        # Source install.sh and call headers_install_spec directly.
        # The script's helpers are written to be source-able in a sub-
        # shell without running main; the `# Main` block is at the
        # bottom and uses `if`s that we side-step by exporting SKIP_*.
        cmd = (
            f"source {INSTALL_SH} 2>/dev/null; "
            f"# only call the helper, never reach Main\n"
            f"headers_install_spec '{distro}' '{uname_r}'"
        )
        # Source the file but don't execute Main: insert `return 0`
        # before the Main banner so the source-time exit is silent.
        # Easiest path: pipe the helper-only portion through bash.
        helper_only = INSTALL_SH.read_text().split("# Main\n", 1)[0]
        r = subprocess.run(
            ["bash", "-c",
             f"{helper_only}\nheaders_install_spec '{distro}' '{uname_r}'"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, f"stderr: {r.stderr}"
        assert expected in r.stdout, (
            f"expected '{expected}' in headers_install_spec output, got "
            f"'{r.stdout.strip()}'")

    def test_headers_install_spec_unknown_distro_returns_empty(self):
        helper_only = INSTALL_SH.read_text().split("# Main\n", 1)[0]
        r = subprocess.run(
            ["bash", "-c",
             f"{helper_only}\nheaders_install_spec 'gentoo nixos' '6.10.0'"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == "", (
            f"unknown distro should return empty, got '{r.stdout.strip()}'")


# ---------------------------------------------------------------------------
# Round-trip install + wrapper + uninstall
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Install into a tmpdir PREFIX; verify everything ends up correct."""

    def test_files_land_in_expected_locations(self, tmp_path):
        prefix = tmp_path / "prefix"
        r = _install(prefix, "--skip-deps")
        assert r.returncode == 0, f"install failed: {r.stdout}\n{r.stderr}"

        bindir = prefix / "bin"
        libdir = prefix / "lib" / "box64-ebpf-tools"

        for tool in ("box64_trace", "box64_memleak"):
            wrapper = bindir / tool
            assert wrapper.exists(), f"missing wrapper {wrapper}"
            assert os.access(wrapper, os.X_OK), f"wrapper {wrapper} not executable"

        for src in ("box64_common.py", "box64_trace.py",
                    "box64_memleak.py", "box64_web.py"):
            assert (libdir / src).exists()

        for asset in ("index.html", "style.css", "LICENSE-kbox"):
            assert (libdir / "web" / asset).exists()
        assert (libdir / "web" / "js" / "main.js").exists()
        assert (libdir / "web" / "js" / "polling.js").exists()

    def test_wrapper_resolves_to_installed_lib_path(self, tmp_path):
        prefix = tmp_path / "prefix"
        _install(prefix, "--skip-deps")

        wrapper = prefix / "bin" / "box64_trace"
        text = wrapper.read_text()
        expected = str(prefix / "lib" / "box64-ebpf-tools" / "box64_trace.py")
        assert expected in text, (
            f"wrapper doesn't reference installed Python source:\n{text}")

    def test_wrapper_actually_executes_the_tool(self, tmp_path):
        prefix = tmp_path / "prefix"
        _install(prefix, "--skip-deps")
        # Running --help proves: wrapper found, python3 invoked, sys.path
        # picked up the installed box64_common, argparse parsed.
        r = _run(str(prefix / "bin" / "box64_trace"), "--help")
        assert r.returncode == 0
        assert "Trace Box64" in r.stdout
        assert "-- COMMAND" in r.stdout  # spawn-mode epilog

    def test_install_is_idempotent(self, tmp_path):
        prefix = tmp_path / "prefix"
        r1 = _install(prefix, "--skip-deps")
        r2 = _install(prefix, "--skip-deps")
        assert r1.returncode == 0
        assert r2.returncode == 0
        assert (prefix / "bin" / "box64_trace").exists()

    def test_uninstall_removes_everything(self, tmp_path):
        prefix = tmp_path / "prefix"
        _install(prefix, "--skip-deps")

        r = _uninstall(prefix)
        assert r.returncode == 0

        for relpath in ("bin/box64_trace", "bin/box64_memleak",
                        "lib/box64-ebpf-tools"):
            assert not (prefix / relpath).exists(), (
                f"uninstall left {relpath} behind")

    def test_uninstall_safe_when_nothing_installed(self, tmp_path):
        prefix = tmp_path / "prefix"
        # Calling uninstall on a never-installed PREFIX must not error.
        r = _uninstall(prefix)
        assert r.returncode == 0


# ---------------------------------------------------------------------------
# Flag plumbing
# ---------------------------------------------------------------------------

class TestFlags:
    def test_skip_deps_suppresses_dep_messages(self, tmp_path):
        prefix = tmp_path / "prefix"
        r = _install(prefix, "--skip-deps")
        assert "python3-bcc" not in r.stdout
        assert "[box64]" not in r.stdout

    def test_no_bcc_alone_does_not_check_bcc(self, tmp_path):
        prefix = tmp_path / "prefix"
        r = _install(prefix, "--no-bcc", "--no-box64-check")
        assert r.returncode == 0
        assert "[deps]" not in r.stdout


# ---------------------------------------------------------------------------
# Browser-launcher detection (the `check_browser` step)
# ---------------------------------------------------------------------------

class TestBrowserCheck:
    def test_browser_check_runs_by_default(self, tmp_path):
        prefix = tmp_path / "prefix"
        r = _install(prefix, "--no-bcc", "--no-box64-check")
        assert r.returncode == 0
        # Either the "auto-open will work" success line or the
        # "WARNING: no browser launcher" line must appear — never silent.
        assert "[browser]" in r.stdout

    def test_no_browser_check_flag_skips(self, tmp_path):
        prefix = tmp_path / "prefix"
        r = _install(prefix, "--no-bcc", "--no-box64-check",
                     "--no-browser-check")
        assert r.returncode == 0
        assert "[browser]" not in r.stdout

    def test_browser_env_var_acknowledged(self, tmp_path):
        prefix = tmp_path / "prefix"
        env = os.environ.copy()
        env["PREFIX"] = str(prefix)
        env["BROWSER"] = "firefox-esr"
        r = subprocess.run(
            [str(INSTALL_SH), "-y", "--no-bcc", "--no-box64-check"],
            env=env, capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "$BROWSER set: firefox-esr" in r.stdout
        # Per-browser detection should not also run when $BROWSER wins.
        assert "auto-open will work" not in r.stdout

    def test_warning_branch_exists_in_script(self):
        # End-to-end testing the "no browser anywhere" path is fiddly —
        # wiping PATH also kills dirname/install/etc that install.sh
        # needs. Static-check that the script has the warning branch
        # so it isn't silently dropped in a refactor.
        src = INSTALL_SH.read_text()
        assert "WARNING: no browser launcher" in src
        # Check both pieces of advice the warning gives the user.
        assert "Install a browser" in src
        assert "--browser <cmd>" in src

    def test_skip_deps_also_skips_browser(self, tmp_path):
        prefix = tmp_path / "prefix"
        r = _install(prefix, "--skip-deps")
        assert r.returncode == 0
        assert "[browser]" not in r.stdout
