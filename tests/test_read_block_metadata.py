"""Tests for read_block_metadata() — box64_steam only."""
import io
import struct

import pytest

import box64_steam


def _build_proc_mem(db_ptr, db_data, alloc_addr=0x1000):
    """Build a fake /proc/PID/mem byte buffer.

    - At alloc_addr: 8-byte pointer to db_ptr
    - At db_ptr + 0x18: db_data (the dynablock_t fields)
    """
    # We need enough space to cover both regions
    size = max(alloc_addr + 8, db_ptr + 0x18 + len(db_data)) + 16
    buf = bytearray(size)
    # Write db_ptr at alloc_addr
    struct.pack_into("Q", buf, alloc_addr, db_ptr)
    # Write dynablock_t fields at db_ptr + 0x18
    struct.pack_into(f"{len(db_data)}s", buf, db_ptr + 0x18, db_data)
    return bytes(buf)


def _build_dynablock_data(in_used=1, tick=42, x64_addr=0xDEAD, x64_size=128,
                          native_size=256, total_size=512, hash_val=0xABCD,
                          done=1, gone=0, dirty=0, flags_byte=0, isize=64):
    """Build 64 bytes of dynablock_t data starting at offset 0x18.

    Post x64_readaddr insertion: everything from size/hash onward is at +0x8.
    """
    data = bytearray(0x58 - 0x18)  # 64 bytes
    struct.pack_into("I", data, 0x00, in_used)      # 0x18
    struct.pack_into("I", data, 0x04, tick)          # 0x1c
    struct.pack_into("Q", data, 0x08, x64_addr)     # 0x20
    struct.pack_into("Q", data, 0x10, x64_size)     # 0x28
    struct.pack_into("Q", data, 0x18, native_size)  # 0x30
    # 0x38: x64_readaddr (skip), 0x40: prefixsize (skip), 0x44: size
    struct.pack_into("i", data, 0x2c, total_size)   # 0x44
    struct.pack_into("I", data, 0x30, hash_val)     # 0x48
    struct.pack_into("BBBB", data, 0x34, done, gone, dirty, flags_byte)  # 0x4c-0x4f
    struct.pack_into("i", data, 0x3c, isize)        # 0x54
    return bytes(data)


class TestReadBlockMetadata:
    def test_valid_parse(self, monkeypatch):
        db_data = _build_dynablock_data(
            in_used=1, tick=42, x64_addr=0xDEAD, x64_size=128,
            native_size=256, total_size=512, hash_val=0xABCD,
            done=1, gone=0, dirty=1, flags_byte=0x03, isize=64)
        alloc_addr = 0x1000
        db_ptr = 0x2000
        mem = _build_proc_mem(db_ptr, db_data, alloc_addr)

        monkeypatch.setattr("builtins.open",
                            lambda *a, **kw: io.BytesIO(mem))
        result = box64_steam.read_block_metadata(1234, alloc_addr)

        assert result is not None
        assert result["tick"] == 42
        assert result["in_used"] == 1
        assert result["x64_addr"] == 0xDEAD
        assert result["x64_size"] == 128
        assert result["native_size"] == 256
        assert result["total_size"] == 512
        assert result["hash"] == 0xABCD
        assert result["done"] == 1
        assert result["gone"] == 0
        assert result["dirty"] == 1
        assert result["always_test"] == 3  # flags_byte & 0x3
        assert result["isize"] == 64

    def test_null_db_ptr_returns_none(self, monkeypatch):
        """If the pointer at alloc_addr is NULL, return None."""
        alloc_addr = 0x1000
        buf = bytearray(alloc_addr + 16)
        struct.pack_into("Q", buf, alloc_addr, 0)  # NULL pointer

        monkeypatch.setattr("builtins.open",
                            lambda *a, **kw: io.BytesIO(bytes(buf)))
        assert box64_steam.read_block_metadata(1, alloc_addr) is None

    def test_truncated_data_returns_none(self, monkeypatch):
        """If struct data is too short, return None."""
        alloc_addr = 0x100
        db_ptr = 0x200
        # Only write the pointer, no dynablock_t data
        buf = bytearray(db_ptr + 0x18 + 10)  # not enough for 64 bytes
        struct.pack_into("Q", buf, alloc_addr, db_ptr)

        monkeypatch.setattr("builtins.open",
                            lambda *a, **kw: io.BytesIO(bytes(buf)))
        assert box64_steam.read_block_metadata(1, alloc_addr) is None

    def test_oserror_returns_none(self, monkeypatch):
        """If /proc/PID/mem can't be opened, return None."""
        def raise_oserror(*a, **kw):
            raise OSError("No such process")
        monkeypatch.setattr("builtins.open", raise_oserror)
        assert box64_steam.read_block_metadata(99999, 0x1000) is None

    def test_always_test_mask(self, monkeypatch):
        """always_test should only use lower 2 bits of flags_byte."""
        db_data = _build_dynablock_data(flags_byte=0xFF)
        alloc_addr = 0x1000
        db_ptr = 0x2000
        mem = _build_proc_mem(db_ptr, db_data, alloc_addr)

        monkeypatch.setattr("builtins.open",
                            lambda *a, **kw: io.BytesIO(mem))
        result = box64_steam.read_block_metadata(1, alloc_addr)
        assert result["always_test"] == 3  # 0xFF & 0x3

    def test_negative_isize(self, monkeypatch):
        """isize is a signed i32 — test negative values."""
        db_data = _build_dynablock_data(isize=-1)
        alloc_addr = 0x1000
        db_ptr = 0x2000
        mem = _build_proc_mem(db_ptr, db_data, alloc_addr)

        monkeypatch.setattr("builtins.open",
                            lambda *a, **kw: io.BytesIO(mem))
        result = box64_steam.read_block_metadata(1, alloc_addr)
        assert result["isize"] == -1

    def test_zero_fields(self, monkeypatch):
        """All zero fields should parse without error."""
        db_data = _build_dynablock_data(
            in_used=0, tick=0, x64_addr=0, x64_size=0,
            native_size=0, total_size=0, hash_val=0,
            done=0, gone=0, dirty=0, flags_byte=0, isize=0)
        alloc_addr = 0x1000
        db_ptr = 0x2000
        mem = _build_proc_mem(db_ptr, db_data, alloc_addr)

        monkeypatch.setattr("builtins.open",
                            lambda *a, **kw: io.BytesIO(mem))
        result = box64_steam.read_block_metadata(1, alloc_addr)
        assert result is not None
        assert all(result[k] == 0 for k in result)
