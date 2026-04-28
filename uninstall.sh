#!/bin/bash
# Remove box64_trace and box64_memleak from $PREFIX (default /usr/local).
# Honors the same PREFIX env var as install.sh.

set -eu

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
LIBDIR="$PREFIX/lib/box64-ebpf-tools"

# Nothing to do if we never installed under this PREFIX. Avoids prompting
# for sudo just to `rm -rf` files that don't exist.
if [ ! -e "$LIBDIR" ] && [ ! -e "$BINDIR/box64_trace" ] \
   && [ ! -e "$BINDIR/box64_memleak" ]; then
    echo "Nothing to remove under $PREFIX (no install detected)."
    exit 0
fi

# Sudo only when at least one target file is owned by someone else.
if [ "$(id -u)" -eq 0 ] || { [ -e "$LIBDIR" ] && [ -w "$LIBDIR" ]; }; then
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
