#!/bin/bash
# Install box64-ebpf-tools so they're callable from $PATH, and (optionally)
# install missing dependencies.
#
# What this script does, in order:
#   1. Detect the distro and (unless --skip-deps) install python3-bcc if
#      `import bcc` doesn't already work.
#   2. Check that a `box64` binary exists on $PATH and was built with debug
#      symbols (otherwise the uprobes have nothing to attach to).
#   3. Copy the Python sources + web/ frontend into $PREFIX/lib/box64-ebpf-tools/
#      and create thin shell wrappers in $PREFIX/bin/.
#
# Common usage:
#   ./install.sh                    # interactive, system-wide
#   sudo ./install.sh -y            # unattended, system-wide
#   PREFIX=$HOME/.local ./install.sh   # user-local
#   ./install.sh --skip-deps        # tools only, don't touch BCC / box64
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

# ---------------------------------------------------------------------------
# 2a. Pre-flight: confirm there's a way to auto-open the dashboard
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
# 2b. Verify Box64 is built with debug symbols
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
# 3. Copy our Python + web/ assets and emit the wrapper scripts
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
    echo "  sudo box64_trace -- box64 ./game.exe"
    echo "  sudo box64_memleak -p \$(pgrep -n box64)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "box64-ebpf-tools installer"
echo "  detected: $(detect_distro)"
echo

if [ "$SKIP_BCC" -eq 0 ]; then install_bcc; fi
if [ "$SKIP_BOX64" -eq 0 ]; then check_box64; fi
if [ "$SKIP_BROWSER" -eq 0 ]; then check_browser; fi
install_tools
