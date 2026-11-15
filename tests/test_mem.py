"""hookie.mem — in-process read/write/chain helpers.

Cross-platform: everything runs against buffers allocated by MemoryManager, so
these tests exercise the same code on Windows and Linux.
"""
import ctypes

import pytest

from hookie import mem
from hookie.memory import MemoryManager

PTR = ctypes.sizeof(ctypes.c_void_p)


@pytest.fixture
def buf():
    addr = MemoryManager.allocate_rw(256)
    yield addr
    MemoryManager.free_rwx(addr, 256)


def test_write_read_roundtrip(buf):
    mem.write_bytes(buf, b"\xde\xad\xbe\xef", protect=False)
    assert mem.read_bytes(buf, 4) == b"\xde\xad\xbe\xef"


def test_read_bytes_zero_length(buf):
    assert mem.read_bytes(buf, 0) == b""


def test_read_ptr_matches_written_pointer(buf):
    target = buf + 0x40
    mem.write_bytes(buf, target.to_bytes(PTR, "little"), protect=False)
    assert mem.read_ptr(buf) == target


def test_read_chain_follows_pointers(buf):
    # buf -> (buf+16) -> (buf+32); chain [0, 0] dereferences twice-minus-last.
    mem.write_bytes(buf, (buf + 16).to_bytes(PTR, "little"), protect=False)
    mem.write_bytes(buf + 16, (buf + 32).to_bytes(PTR, "little"), protect=False)
    assert mem.read_chain(buf, [0]) == buf            # add last offset, no deref
    assert mem.read_chain(buf, [0, 0]) == buf + 16     # one deref + last offset
    assert mem.read_chain(buf, [0, 0, 0]) == buf + 32  # two derefs + last offset


def test_read_chain_empty_returns_base(buf):
    assert mem.read_chain(buf, []) == buf


def test_read_chain_applies_final_offset(buf):
    mem.write_bytes(buf, (buf + 16).to_bytes(PTR, "little"), protect=False)
    assert mem.read_chain(buf, [0, 0x8]) == buf + 24


def test_protected_read_of_unmapped_raises():
    # protect=True can't make an unmapped address accessible, so it raises.
    with pytest.raises((OSError, ValueError)):
        mem.read_bytes(0x10, 8)


def test_write_bytes_protect_flips_readonly_page():
    code = MemoryManager.allocate_rw(64)
    try:
        MemoryManager.protect_rx(code, 64)  # make it read+execute (not writable)
        # protect=True sees it is not writable, flips it, writes, and restores.
        mem.write_bytes(code, b"\x90\x90\x90\x90")
        assert mem.read_bytes(code, 4) == b"\x90\x90\x90\x90"
    finally:
        MemoryManager.free_rwx(code, 64)


def test_read_flips_unreadable_page_and_restores():
    # The unified protect model also covers reads: a mapped-but-unreadable page
    # is temporarily made readable, read, and restored. (argtypes are set so the
    # 64-bit page address is not truncated.)
    import ctypes as _c
    from hookie.memory import IS_WINDOWS
    page = MemoryManager.allocate_rw(4096)
    try:
        mem.write_bytes(page, b"\x11\x22\x33\x44", protect=False)
        if IS_WINDOWS:
            k32 = _c.WinDLL("kernel32", use_last_error=True)
            k32.VirtualProtect.argtypes = [_c.c_void_p, _c.c_size_t, _c.c_ulong,
                                           _c.POINTER(_c.c_ulong)]
            k32.VirtualProtect.restype = _c.c_int
            old = _c.c_ulong()
            assert k32.VirtualProtect(page, 4096, 0x01, _c.byref(old))  # PAGE_NOACCESS
        else:
            libc = _c.CDLL(None, use_errno=True)
            libc.mprotect.argtypes = [_c.c_void_p, _c.c_size_t, _c.c_int]
            libc.mprotect.restype = _c.c_int
            assert libc.mprotect(page, 4096, 0) == 0  # PROT_NONE
        assert mem.read_bytes(page, 4, protect=True) == b"\x11\x22\x33\x44"
    finally:
        MemoryManager.make_rwx(page, 4096)
        MemoryManager.free_rwx(page, 4096)
