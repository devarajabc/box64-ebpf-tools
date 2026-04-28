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
                       "--no-box64-check", "PREFIX"):
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
