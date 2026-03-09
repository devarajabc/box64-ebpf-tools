"""Check that upstream Box64 still exports the symbols and struct layouts we depend on.

Requires BOX64_SRC_DIR env var pointing to a Box64 source checkout,
or ../box64 as a fallback.  Skips gracefully if unavailable.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Scripts that contain our uprobe attachments
# ---------------------------------------------------------------------------
SCRIPTS = ["box64_dynarec.py", "box64_memleak.py", "box64_steam.py"]
REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Fixture: locate Box64 source
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def box64_src_dir():
    d = os.environ.get("BOX64_SRC_DIR") or str(REPO_ROOT.parent / "box64")
    p = Path(d)
    if not (p / "src").is_dir():
        pytest.skip(f"Box64 source not found at {p} (set BOX64_SRC_DIR)")
    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_probed_symbols():
    """Return {symbol: [script, ...]} for every sym="..." in attach calls."""
    sym_re = re.compile(r'sym="(\w+)"')
    result: dict[str, list[str]] = {}
    for script in SCRIPTS:
        path = REPO_ROOT / script
        text = path.read_text()
        for m in sym_re.finditer(text):
            result.setdefault(m.group(1), []).append(script)
    return result


def _symbol_defined_in_source(src_dir: Path, symbol: str) -> bool:
    """Check if a C function definition or declaration exists in Box64 src/."""
    # Match: return_type symbol(  or  return_type *symbol(
    # Also match: #define symbol(  for macro-based functions
    pattern = rf"\b{re.escape(symbol)}\s*\("
    try:
        result = subprocess.run(
            ["grep", "-rqE", pattern, str(src_dir / "src")],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _count_params_in_declaration(src_dir: Path, symbol: str) -> int | None:
    """Find function declaration/definition and count parameters.

    Searches header files first for the canonical declaration.
    Returns None if not found.  Returns 0 for void param lists.
    """
    pattern = rf"\b{re.escape(symbol)}\s*\([^)]*\)"
    # Search headers first, then all source
    for glob in ["--include=*.h", "--include=*.c"]:
        try:
            result = subprocess.run(
                ["grep", "-rhEo", glob, pattern, str(src_dir / "src")],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if result.returncode != 0 or not result.stdout.strip():
            continue

        # Look for a match that contains type names (declaration, not call site)
        for line in result.stdout.strip().split("\n"):
            paren_match = re.search(r"\(([^)]*)\)", line)
            if not paren_match:
                continue
            params = paren_match.group(1).strip()
            if not params or params == "void":
                return 0
            # A declaration has type keywords; a call site doesn't.
            # Heuristic: contains at least one C type keyword.
            type_keywords = {"int", "void", "char", "size_t", "uintptr_t",
                             "uint32_t", "int32_t", "uint64_t", "int64_t",
                             "unsigned", "long", "const", "struct", "float",
                             "double", "uint8_t", "int8_t", "uint16_t"}
            words = set(re.findall(r"\b\w+\b", params))
            if words & type_keywords:
                return len(params.split(","))

    return None


# ---------------------------------------------------------------------------
# dynablock_t struct offset computation
# ---------------------------------------------------------------------------
# LP64 type sizes
_TYPE_SIZES = {
    "void*": 8,
    "void *": 8,
    "struct dynablock_s*": 8,
    "struct dynablock_s *": 8,
    "instsize_t*": 8,
    "instsize_t *": 8,
    "callret_t*": 8,
    "callret_t *": 8,
    "sep_t*": 8,
    "sep_t *": 8,
    "uintptr_t": 8,
    "size_t": 8,
    "uint64_t": 8,
    "int64_t": 8,
    "uint32_t": 4,
    "int32_t": 4,
    "int": 4,
    "uint8_t": 1,
}

# Alignment = size for natural alignment (LP64)
_TYPE_ALIGN = {k: min(v, 8) for k, v in _TYPE_SIZES.items()}


def _parse_dynablock_fields(header_path: Path):
    """Parse dynablock_t struct fields from dynablock_private.h.

    Returns list of (field_name, type_str, size, alignment) tuples.
    Handles bitfields and strips #ifdef GDBJIT blocks.
    """
    text = header_path.read_text()

    # Find the struct body
    m = re.search(
        r"typedef\s+struct\s+dynablock_s\s*\{(.+?)\}\s*dynablock_t\s*;",
        text,
        re.DOTALL,
    )
    if not m:
        return None
    body = m.group(1)

    # Strip #ifdef GDBJIT ... #endif blocks
    body = re.sub(
        r"#ifdef\s+GDBJIT.*?#endif",
        "",
        body,
        flags=re.DOTALL,
    )

    fields = []
    # Track bitfield accumulation within a single byte
    bitfield_bits = 0
    bitfield_base_type = None

    for line in body.split("\n"):
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue

        # Match: type field;  or  type field:N;  or  type *field;
        fm = re.match(
            r"([\w\s*]+?)\s+(\*?\w+)\s*(?::(\d+))?\s*;",
            line,
        )
        if not fm:
            continue

        type_str = fm.group(1).strip()
        field_name = fm.group(2).strip()
        bitfield_width = int(fm.group(3)) if fm.group(3) else None

        # Handle pointer: "void" + "*field" -> type is "void*"
        if field_name.startswith("*"):
            field_name = field_name[1:]
            type_str = type_str + "*"

        # Normalize pointer spacing
        type_str = re.sub(r"\s*\*\s*", "*", type_str)
        # Struct pointer normalization
        type_str = re.sub(r"(\w+)\*", r"\1 *", type_str)
        type_str = type_str.replace("  ", " ")

        if bitfield_width is not None:
            # Bitfield: accumulate bits
            if bitfield_bits == 0:
                bitfield_base_type = type_str
            bitfield_bits += bitfield_width
            # Check if next line is also a bitfield of same type
            # We'll flush when we hit a non-bitfield or different type
            continue
        else:
            # Flush any pending bitfield
            if bitfield_bits > 0:
                bt = bitfield_base_type or "uint8_t"
                size = _TYPE_SIZES.get(bt, 1)
                align = _TYPE_ALIGN.get(bt, 1)
                fields.append(("__bitfield__", bt, size, align))
                bitfield_bits = 0
                bitfield_base_type = None

            size = _TYPE_SIZES.get(type_str)
            if size is None:
                # Unknown type — skip (shouldn't happen for our struct)
                continue
            align = _TYPE_ALIGN.get(type_str, size)
            fields.append((field_name, type_str, size, align))

    # Flush trailing bitfield
    if bitfield_bits > 0:
        bt = bitfield_base_type or "uint8_t"
        size = _TYPE_SIZES.get(bt, 1)
        align = _TYPE_ALIGN.get(bt, 1)
        fields.append(("__bitfield__", bt, size, align))

    return fields


def _compute_offsets(fields):
    """Compute byte offset for each field using natural LP64 alignment.

    Returns {field_name: offset}.
    """
    offsets = {}
    pos = 0
    for name, _type_str, size, align in fields:
        # Align
        if pos % align != 0:
            pos += align - (pos % align)
        offsets[name] = pos
        pos += size
    return offsets


# ---------------------------------------------------------------------------
# Test A: All probed symbols exist in upstream
# ---------------------------------------------------------------------------
def test_all_probed_symbols_exist_in_upstream(box64_src_dir):
    sym_map = _extract_probed_symbols()
    assert sym_map, "Failed to extract any symbols from scripts"

    missing = {}
    for sym, scripts in sorted(sym_map.items()):
        if not _symbol_defined_in_source(box64_src_dir, sym):
            missing[sym] = scripts

    if missing:
        lines = [f"  {sym} (used by: {', '.join(scripts)})" for sym, scripts in sorted(missing.items())]
        pytest.fail(
            f"{len(missing)} probed symbol(s) not found in upstream Box64 src/:\n"
            + "\n".join(lines)
        )


# ---------------------------------------------------------------------------
# Test B: dynablock_t struct offsets match our hardcoded values
# ---------------------------------------------------------------------------
# Offsets hardcoded in box64_steam.py (BPF reads + Python struct.unpack_from)
EXPECTED_OFFSETS = {
    "block": 0x00,
    "actual_block": 0x08,
    "tick": 0x1C,
    "x64_addr": 0x20,
    "x64_size": 0x28,
    "native_size": 0x30,
    "hash": 0x40,
    "done": 0x44,
    "gone": 0x45,
    "dirty": 0x46,
    "__bitfield__": 0x47,
    "isize": 0x4C,
}


def test_dynablock_struct_offsets(box64_src_dir):
    header = box64_src_dir / "src" / "dynarec" / "dynablock_private.h"
    if not header.exists():
        pytest.skip(f"Header not found: {header}")

    fields = _parse_dynablock_fields(header)
    assert fields, f"Failed to parse dynablock_t from {header}"

    computed = _compute_offsets(fields)

    mismatches = []
    for field, expected in EXPECTED_OFFSETS.items():
        actual = computed.get(field)
        if actual is None:
            mismatches.append(f"  {field}: field not found in struct (expected 0x{expected:02X})")
        elif actual != expected:
            mismatches.append(
                f"  {field}: expected 0x{expected:02X}, got 0x{actual:02X}"
            )

    if mismatches:
        pytest.fail(
            "dynablock_t struct layout has changed — our hardcoded offsets are stale:\n"
            + "\n".join(mismatches)
            + "\n\nUpdate offsets in box64_steam.py (BPF + Python) to match."
        )


# ---------------------------------------------------------------------------
# Test C: Key function parameter counts
# ---------------------------------------------------------------------------
# Functions where our BPF reads specific PT_REGS_PARMn
EXPECTED_PARAM_COUNTS = {
    "AllocDynarecMap": 3,  # (x64_addr, size, is_new)
    "customCalloc": 2,     # (n, size) — BPF computes PARM1*PARM2
    "FreeDynarecMap": 1,   # (addr)
}


def test_key_function_param_counts(box64_src_dir):
    mismatches = []
    for func, expected_count in EXPECTED_PARAM_COUNTS.items():
        actual = _count_params_in_declaration(box64_src_dir, func)
        if actual is None:
            mismatches.append(f"  {func}: declaration not found")
        elif actual != expected_count:
            mismatches.append(
                f"  {func}: expected {expected_count} params, got {actual}"
            )

    if mismatches:
        pytest.fail(
            "Function signature changes detected — BPF PT_REGS_PARMn reads may be wrong:\n"
            + "\n".join(mismatches)
        )
