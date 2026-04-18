"""Tests for _read_block_from_fd() struct decoding (box64_steam only)."""
import io
import struct
import pytest

import box64_steam


def _build_dynablock(block=0x1000, x64_addr=0x400000, x64_size=128,
                     native_size=256, isize=42):
    """Build a fake dynablock_t struct (0x58 bytes).

    Layout (post x64_readaddr insertion at 0x38, shifting +0x8):
      0x00: block (void*)
      0x20: x64_addr (uintptr_t)
      0x28: x64_size (uint64)
      0x30: native_size (uint64)
      0x54: isize (int32)
    """
    data = bytearray(0x58)
    struct.pack_into("<Q", data, 0x00, block)
    struct.pack_into("<Q", data, 0x20, x64_addr)
    struct.pack_into("<Q", data, 0x28, x64_size)
    struct.pack_into("<Q", data, 0x30, native_size)
    struct.pack_into("<i", data, 0x54, isize)
    return bytes(data)


def _build_mem(actual_block_addr, db_ptr, db_data):
    """Build a fake /proc/PID/mem image.

    At actual_block_addr: 8-byte pointer to db_ptr.
    At db_ptr: the dynablock_t struct data.
    """
    # Use a buffer large enough to hold both
    size = max(actual_block_addr + 8, db_ptr + len(db_data))
    buf = bytearray(size)
    struct.pack_into("<Q", buf, actual_block_addr, db_ptr)
    buf[db_ptr:db_ptr + len(db_data)] = db_data
    return io.BytesIO(bytes(buf))


class TestReadBlockFromFd:
    def test_valid_parse(self):
        db_data = _build_dynablock(
            block=0x1000, x64_addr=0x400000,
            x64_size=128, native_size=256, isize=42
        )
        alloc_addr = 0x100
        db_ptr = 0x200
        f = _build_mem(alloc_addr, db_ptr, db_data)

        result = box64_steam._read_block_from_fd(f, alloc_addr)

        assert result is not None
        assert result["block"] == 0x1000
        assert result["x64_addr"] == 0x400000
        assert result["x64_size"] == 128
        assert result["native_size"] == 256
        assert result["isize"] == 42

    def test_null_pointer_returns_none(self):
        # actual_block_addr points to a null pointer (all zeros)
        buf = bytearray(0x100)
        f = io.BytesIO(bytes(buf))
        result = box64_steam._read_block_from_fd(f, 0)
        assert result is None

    def test_truncated_pointer_returns_none(self):
        # Only 4 bytes available when 8 are needed
        f = io.BytesIO(b"\x01\x00\x00\x00")
        result = box64_steam._read_block_from_fd(f, 0)
        assert result is None

    def test_truncated_struct_returns_none(self):
        # Pointer is valid but struct data is too short
        alloc_addr = 0
        db_ptr = 0x100
        buf = bytearray(db_ptr + 0x10)  # only 0x10 bytes of struct (need 0x58)
        struct.pack_into("<Q", buf, alloc_addr, db_ptr)
        f = io.BytesIO(bytes(buf))
        result = box64_steam._read_block_from_fd(f, alloc_addr)
        assert result is None
