import ctypes

import pytest

from hookie import MemoryManager


def test_prologue_read_clamped_at_page_boundary(engine):
    """A function within 64 bytes of an unmapped page must be hookable without
    faulting: the prologue read is clamped to mapped memory."""
    page = MemoryManager._page_size()
    base = MemoryManager.allocate_rw(page)          # next page is unmapped
    code = b"\xB8\x2A\x00\x00\x00\xC3"               # mov eax,42 ; ret
    off = page - 8
    ctypes.memmove(base + off, code, len(code))
    MemoryManager.flush_instruction_cache(base + off, len(code))
    MemoryManager.protect_rx(base, page)
    try:
        # A blind 64-byte read from here would cross into the unmapped page.
        assert MemoryManager.readable_extent(base + off, 64) == 8
        target = ctypes.CFUNCTYPE(ctypes.c_int)(base + off)
        assert target() == 42
        hook = engine.create_hook(base + off, lambda: 7, [], ctypes.c_int)
        hook.enable()
        assert target() == 7
        hook.disable()
        assert target() == 42
    finally:
        MemoryManager.free_rwx(base, page)


def test_overlapping_hook_is_rejected(engine, native):
    addr, _, _, _ = native(b"\xB8\x2A\x00\x00\x00" + b"\x90" * 16 + b"\xC3")
    engine.create_hook(addr, lambda: 1, [], ctypes.c_int)
    with pytest.raises(ValueError, match="overlap"):
        engine.create_hook(addr, lambda: 2, [], ctypes.c_int)
