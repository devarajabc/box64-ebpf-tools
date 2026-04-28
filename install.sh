#!/bin/bash
# Install box64-ebpf-tools so they're callable from $PATH, and (optionally)
# install missing dependencies.
#
# What this script does, in order:
#   1. Detect the distro (--no-bcc skips) and install python3-bcc if
#      `import bcc` doesn't already work.
#   2. Verify `box64` is on $PATH and was built with debug symbols
#      (--no-box64-check skips). Without `customMalloc` exported by
#      RelWithDebInfo, the uprobes have nothing to attach to.
#   3. Detect a browser launcher for the --web dashboard's auto-open
#      (--no-browser-check skips). Surfaces what `auto` mode will
#      pick: $BROWSER, then any of firefox/chromium/google-chrome/
#      brave/edge/vivaldi/opera/epiphany/falkon, then xdg-open. Warns
#      (non-fatal) if nothing is found — --web always prints the URL
#      so copy-paste still works.
#   4. Copy the Python sources + web/ frontend into
#      $PREFIX/lib/box64-ebpf-tools/ and emit thin shell wrappers in
#      $PREFIX/bin/.
#
# Common usage:
#   ./install.sh                          # interactive, system-wide
#   sudo ./install.sh -y                  # unattended, system-wide
#   PREFIX=$HOME/.local ./install.sh      # user-local
#   ./install.sh --skip-deps              # tools only, no checks
#
# Flags:
#   -y, --yes              assume yes to all prompts (for unattended / CI)
#   --skip-deps            skip BCC + box64 + browser checks (tools only)
#   --no-bcc               skip BCC install/check only
#   --no-box64-check       skip box64 binary verification only
#   --no-browser-check     skip browser-launcher detection only

set -eu

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
LIBDIR="$PREFIX/lib/box64-ebpf-tools"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

ASSUME_YES=0
SKIP_BCC=0
SKIP_BOX64=0
SKIP_BROWSER=0
for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=1 ;;
        --skip-deps) SKIP_BCC=1; SKIP_BOX64=1; SKIP_BROWSER=1 ;;
        --no-bcc) SKIP_BCC=1 ;;
        --no-box64-check) SKIP_BOX64=1 ;;
        --no-browser-check) SKIP_BROWSER=1 ;;
        -h|--help)
            sed -n '2,/^set -eu$/p' "$0" | sed 's/^# \{0,1\}//; /^set -eu/d'
            exit 0
            ;;
        *) echo "ERROR: unknown flag '$arg' (try --help)" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Pick sudo only when we actually need it. Used for system package installs
# AND for writing under $PREFIX. The two checks are independent.
need_sudo() {
    [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1
}
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

confirm() {
    # confirm "Prompt text"  →  exits 0 if user said yes (or -y was passed)
    local prompt="$1"
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    # If stdin is not a tty, default to "no" — we shouldn't silently install
    # packages in CI without an explicit -y.
    if [ ! -t 0 ]; then
        echo "$prompt [non-interactive; pass --yes to proceed]" >&2
        return 1
    fi
    read -r -p "$prompt [y/N] " ans
    case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

# Walk up the path to the first existing ancestor; that decides whether
# writing to $PREFIX needs sudo.
writable_ancestor() {
    local p="$1"
    while [ ! -e "$p" ]; do
        p="$(dirname "$p")"
    done
    [ -w "$p" ]
}

# ---------------------------------------------------------------------------
# 1. Detect distro and install BCC if needed
# ---------------------------------------------------------------------------

detect_distro() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${ID:-unknown} ${ID_LIKE:-}"
    else
        echo "unknown"
    fi
}

# Returns "<pkg-mgr>:<packages>" or "" if the distro is unknown.
bcc_install_spec() {
    local ids="$1"
    case " $ids " in
        *" ubuntu "*|*" debian "*|*" raspbian "*|*" pop "*|*" linuxmint "*)
            echo "apt:python3-bpfcc bpfcc-tools" ;;
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*)
            echo "dnf:python3-bcc bcc-tools" ;;
        *" arch "*|*" manjaro "*|*" endeavouros "*|*" arch-arm "*)
            echo "pacman:python-bcc bcc-tools" ;;
        *" opensuse"*|*" sles "*|*" suse "*)
            echo "zypper:python3-bcc bcc-tools" ;;
        *) echo "" ;;
    esac
}

install_bcc() {
    if python3 -c "import bcc" 2>/dev/null; then
        echo "[deps] python3-bcc: already installed"
        return 0
    fi

    local distro spec pm pkgs
    distro="$(detect_distro)"
    spec="$(bcc_install_spec "$distro")"
    if [ -z "$spec" ]; then
        echo "[deps] python3-bcc not found, and I don't recognise this distro"
        echo "       ($distro). Install BCC manually:"
        echo "         https://github.com/iovisor/bcc/blob/master/INSTALL.md"
        if confirm "Continue anyway (the tools will fail at runtime without BCC)?"; then
            return 0
        fi
        exit 1
    fi
    pm="${spec%%:*}"
    pkgs="${spec#*:}"

    echo "[deps] python3-bcc not found. Plan: $SUDO $pm install $pkgs"
    if ! confirm "Install BCC now?"; then
        echo "[deps] skipped — re-run with --no-bcc to silence, or install manually."
        exit 1
    fi

    case "$pm" in
        apt)     $SUDO apt-get update && $SUDO apt-get install -y $pkgs ;;
        dnf)     $SUDO dnf install -y $pkgs ;;
        pacman)  $SUDO pacman -S --needed --noconfirm $pkgs ;;
        zypper)  $SUDO zypper install -y $pkgs ;;
        *)       echo "ERROR: don't know how to drive '$pm'"; exit 1 ;;
    esac

    if ! python3 -c "import bcc" 2>/dev/null; then
        echo "[deps] WARNING: $pm reports BCC installed but 'import bcc' still"
        echo "       fails. You may need to log out and back in, or your distro"
        echo "       may install BCC under a different python3."
    fi
}

# Per-distro kernel-headers package picker. Returns "<pm>:<pkgs>" or "".
# BCC compiles BPF programs at runtime via clang, so it needs *running-
# kernel* headers — generic linux-libc-dev is not enough.
headers_install_spec() {
    local ids="$1"
    local uname_r="$2"
    case " $ids " in
        *" raspbian "*)
            # Raspberry Pi OS (Debian-based): the meta-package tracks the
            # currently-installed kernel automatically.
            echo "apt:raspberrypi-kernel-headers" ;;
        *" ubuntu "*|*" debian "*|*" pop "*|*" linuxmint "*)
            # Generic Debian/Ubuntu (incl. Ubuntu's raspi flavor):
            # linux-headers-$(uname -r) resolves to the matching package
            # — `linux-headers-6.8.0-1052-raspi` for Ubuntu on a Pi,
            # `linux-headers-6.8.0-58-generic` on x86 Ubuntu, etc.
            echo "apt:linux-headers-$uname_r" ;;
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*)
            echo "dnf:kernel-devel-$uname_r" ;;
        *" arch "*|*" manjaro "*|*" endeavouros "*|*" arch-arm "*)
            # Arch family: linux-headers tracks the running kernel
            # package. Pi-Arch users may need linux-rpi-headers — we
            # try the generic one and let the user adjust if needed.
            echo "pacman:linux-headers" ;;
        *" opensuse"*|*" sles "*|*" suse "*)
            echo "zypper:kernel-devel" ;;
        *) echo "" ;;
    esac
}

# BCC needs running-kernel headers to compile BPF programs at JIT time.
# Without them, every box64_trace / box64_memleak invocation dies with
# "modprobe: FATAL: Module kheaders not found / chdir(/lib/modules/.../
# build): No such file or directory". This check makes the installer
# surface and fix that *before* the user hits it at runtime.
check_kernel_headers() {
    local uname_r build_dir
    uname_r="$(uname -r)"
    build_dir="/lib/modules/$uname_r/build"

    # Path 1: real /lib/modules/<ver>/build symlink with a Makefile.
    # This is the path BCC uses by default.
    if [ -d "$build_dir" ] && [ -f "$build_dir/Makefile" ]; then
        echo "[deps] kernel headers: present at $build_dir"
        return 0
    fi

    # Path 2: kheaders.ko already loaded → /sys/kernel/kheaders.tar.xz.
    # BCC will fall back to extracting from this archive when build/
    # is missing. This is what CONFIG_IKHEADERS=y unlocks.
    if [ -f /sys/kernel/kheaders.tar.xz ]; then
        echo "[deps] kernel headers: available via /sys/kernel/kheaders.tar.xz"
        return 0
    fi

    # Path 3: kheaders.ko exists but isn't loaded. Try modprobe.
    if modinfo kheaders >/dev/null 2>&1; then
        if $SUDO modprobe kheaders 2>/dev/null \
           && [ -f /sys/kernel/kheaders.tar.xz ]; then
            echo "[deps] kernel headers: loaded kheaders module, " \
                 "/sys/kernel/kheaders.tar.xz now present"
            return 0
        fi
    fi

    # Nothing on the system; install per-distro.
    local distro spec pm pkgs
    distro="$(detect_distro)"
    spec="$(headers_install_spec "$distro" "$uname_r")"
    if [ -z "$spec" ]; then
        echo "[deps] kernel headers missing for kernel '$uname_r', and I"
        echo "       don't have a package mapping for this distro ($distro)."
        echo "       Install kernel headers (or rebuild with"
        echo "       CONFIG_IKHEADERS=m), then re-run."
        if confirm "Continue anyway (BPF compilation WILL fail at runtime)?"; then
            return 0
        fi
        exit 1
    fi
    pm="${spec%%:*}"
    pkgs="${spec#*:}"

    echo "[deps] kernel headers missing for '$uname_r'."
    echo "       Plan: $SUDO $pm install $pkgs"
    if ! confirm "Install kernel headers now?"; then
        echo "[deps] skipped — BPF compilation will fail at runtime."
        exit 1
    fi

    case "$pm" in
        apt)     $SUDO apt-get install -y $pkgs ;;
        dnf)     $SUDO dnf install -y $pkgs ;;
        pacman)  $SUDO pacman -S --needed --noconfirm $pkgs ;;
        zypper)  $SUDO zypper install -y $pkgs ;;
        *)       echo "ERROR: don't know how to drive '$pm'"; exit 1 ;;
    esac

    if [ ! -d "$build_dir" ] || [ ! -f "$build_dir/Makefile" ]; then
        echo "[deps] WARNING: $pm reports headers installed but $build_dir"
        echo "       still missing. After a kernel update on raspi/Ubuntu, a"
        echo "       reboot is sometimes needed so the running kernel matches"
        echo "       the headers package. Or check 'apt list --installed |"
        echo "       grep linux-headers' to see what landed."
    fi
}

# ---------------------------------------------------------------------------
# 3. Pre-flight: confirm there's a way to auto-open the dashboard
# ---------------------------------------------------------------------------

check_browser() {
    # The --web dashboard *always* prints its URL, so a missing browser
    # launcher is never fatal — it just means the user has to copy-paste
    # instead of having Firefox/Chrome auto-pop. Surface what's available
    # so the user knows what `auto` mode will pick (and what to override
    # with `--browser <cmd>` or $BROWSER if they hit Firefox's "already
    # running" dialog or similar).

    if [ -n "${BROWSER:-}" ]; then
        echo "[browser] \$BROWSER set: $BROWSER (auto-open will use this)"
        return 0
    fi

    local found=()
    for b in firefox chromium google-chrome chrome brave-browser microsoft-edge \
             vivaldi opera epiphany falkon; do
        if command -v "$b" >/dev/null 2>&1; then
            found+=("$b")
        fi
    done

    local has_xdg_open=0
    if command -v xdg-open >/dev/null 2>&1; then
        has_xdg_open=1
    fi

    if [ ${#found[@]} -gt 0 ] || [ "$has_xdg_open" -eq 1 ]; then
        echo "[browser] auto-open will work."
        if [ ${#found[@]} -gt 0 ]; then
            echo "          detected: ${found[*]}"
        fi
        if [ "$has_xdg_open" -eq 1 ]; then
            echo "          xdg-open available (handles \$XDG_CURRENT_DESKTOP default)"
        fi
        echo "          override at runtime with --browser <cmd> or \$BROWSER."
    else
        echo "[browser] WARNING: no browser launcher detected on \$PATH."
        echo "          --web will print the dashboard URL but won't auto-open."
        echo "          Install a browser, set \$BROWSER, or use --browser <cmd>."
    fi
}

# ---------------------------------------------------------------------------
# 2. Verify Box64 is built with debug symbols
# ---------------------------------------------------------------------------

check_box64() {
    local b
    b="$(command -v box64 2>/dev/null || true)"
    if [ -z "$b" ] && [ -x /usr/local/bin/box64 ]; then
        b=/usr/local/bin/box64
    fi
    if [ -z "$b" ]; then
        cat <<EOF
[box64] not found on \$PATH. Build it from source with debug symbols:

    git clone https://github.com/ptitSeb/box64.git
    cd box64 && mkdir build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DARM_DYNAREC=ON
    make -j\$(nproc) && sudo make install

The tracer attaches uprobes by *symbol name*, so a stripped/release build
will silently fail to attach. Re-run this script after installing.
EOF
        if confirm "Continue installing the tools anyway?"; then
            return 0
        fi
        exit 1
    fi

    # 'nm' prints "no symbols" (exit 1) for stripped binaries. The customMalloc
    # symbol in particular is what we need — it's exported in RelWithDebInfo
    # but stripped from Release builds.
    if nm "$b" 2>/dev/null | grep -q ' [tT] customMalloc$'; then
        echo "[box64] $b — debug symbols OK (customMalloc found)"
    else
        echo "[box64] $b — WARNING: customMalloc symbol not found"
        echo "         Rebuild with -DCMAKE_BUILD_TYPE=RelWithDebInfo and"
        echo "         do not strip the binary, or the tools won't attach."
        if ! confirm "Continue anyway?"; then
            exit 1
        fi
    fi
}

# ---------------------------------------------------------------------------
# 4. Copy our Python + web/ assets and emit the wrapper scripts
# ---------------------------------------------------------------------------

install_tools() {
    # We may need sudo for $PREFIX even when we didn't for system packages.
    local PSUDO=""
    if [ "$(id -u)" -ne 0 ] && ! writable_ancestor "$PREFIX"; then
        if command -v sudo >/dev/null 2>&1; then
            PSUDO="sudo"
        else
            echo "ERROR: $PREFIX is not writable and sudo is not available." >&2
            exit 1
        fi
    fi

    echo
    echo "[install] PREFIX=$PREFIX"
    echo "[install] bindir=$BINDIR"
    echo "[install] libdir=$LIBDIR"

    $PSUDO install -d "$BINDIR" "$LIBDIR" "$LIBDIR/web" "$LIBDIR/web/js"

    $PSUDO install -m 0644 \
        "$REPO_DIR/box64_common.py" \
        "$REPO_DIR/box64_trace.py" \
        "$REPO_DIR/box64_memleak.py" \
        "$REPO_DIR/box64_web.py" \
        "$LIBDIR/"

    $PSUDO install -m 0644 \
        "$REPO_DIR/web/index.html" \
        "$REPO_DIR/web/style.css" \
        "$REPO_DIR/web/LICENSE-kbox" \
        "$LIBDIR/web/"
    $PSUDO install -m 0644 "$REPO_DIR/web/js/"*.js "$LIBDIR/web/js/"

    for tool in box64_trace box64_memleak; do
        $PSUDO tee "$BINDIR/$tool" > /dev/null <<EOF
#!/bin/sh
# Auto-generated by box64-ebpf-tools install.sh — DO NOT EDIT.
exec /usr/bin/env python3 "$LIBDIR/$tool.py" "\$@"
EOF
        $PSUDO chmod 0755 "$BINDIR/$tool"
    done

    echo "[install] done."
    echo
    echo "Installed: $BINDIR/box64_trace, $BINDIR/box64_memleak"
    echo
    echo "Quick start (eBPF needs root):"
    echo "  sudo box64_trace -- box64 ./MyGame.x86_64    # explicit"
    echo "  sudo box64_trace -- box64 MyGame.x86_64      # bare name auto-resolves to ./"
    echo "  sudo box64_trace -- ./MyGame.x86_64          # binfmt_misc routes through box64"
    echo "  sudo box64_memleak -p \$(pgrep -n box64)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "box64-ebpf-tools installer"
echo "  detected: $(detect_distro)"
echo

if [ "$SKIP_BCC" -eq 0 ]; then
    install_bcc
    # Kernel headers are a BCC runtime requirement, so gate them on
    # the same flag that controls BCC.
    check_kernel_headers
fi
if [ "$SKIP_BOX64" -eq 0 ]; then check_box64; fi
if [ "$SKIP_BROWSER" -eq 0 ]; then check_browser; fi
install_tools
