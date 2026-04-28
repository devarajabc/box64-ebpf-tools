#!/bin/bash
# Remove box64_trace and box64_memleak from $PREFIX (default /usr/local).
# Honors the same PREFIX env var as install.sh.

set -eu

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
LIBDIR="$PREFIX/lib/box64-ebpf-tools"

if [ "$(id -u)" -eq 0 ] || { [ -e "$PREFIX" ] && [ -w "$PREFIX" ]; }; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    echo "ERROR: $PREFIX is not writable and sudo is not available." >&2
    exit 1
fi

$SUDO rm -f "$BINDIR/box64_trace" "$BINDIR/box64_memleak"
$SUDO rm -rf "$LIBDIR"

echo "Removed box64-ebpf-tools from $PREFIX"
