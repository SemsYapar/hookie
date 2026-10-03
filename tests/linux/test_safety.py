"""Regression tests for the page-boundary read guard and the overlap guard."""
import ctypes
from _common import BITS, HookEngine, MemoryManager, require_linux


def test_page_boundary_read():
    """A function whose address is within 64 bytes of an unmapped page must be
    hookable without faulting: the prologue read is clamped to mapped memory."""
    page = MemoryManager._page_size()
    base = MemoryManager.allocate_rw(page)          # isolated page; next page unmapped
    # mov eax,42; ret  (6 bytes) placed 8 bytes before the page end.
    code = b"\xB8\x2A\x00\x00\x00\xC3"
    off = page - 8
    ctypes.memmove(base + off, code, len(code))
    MemoryManager.flush_instruction_cache(base + off, len(code))
    MemoryManager.protect_rx(base, page)

    # A blind 64-byte read from here would cross into the unmapped next page.
    assert MemoryManager.readable_extent(base + off, 64) == 8
    engine = HookEngine()
    target = ctypes.CFUNCTYPE(ctypes.c_int)(base + off)
    try:
        assert target() == 42
        hook = engine.create_hook(base + off, lambda: 7, [], ctypes.c_int)
        hook.enable();  assert target() == 7
        hook.disable(); assert target() == 42
        print("PASS safety.page_boundary_read")
    finally:
        engine.destroy_all()
        MemoryManager.free_rwx(base, page)


def test_overlap_guard():
    code = b"\xB8\x2A\x00\x00\x00" + b"\x90" * 16 + b"\xC3"
    base = MemoryManager.allocate_rw(len(code))
    ctypes.memmove(base, code, len(code))
    MemoryManager.flush_instruction_cache(base, len(code))
    MemoryManager.protect_rx(base, len(code))
    engine = HookEngine()
    try:
        engine.create_hook(base, lambda: 1, [], ctypes.c_int)
        try:
            engine.create_hook(base, lambda: 2, [], ctypes.c_int)
        except ValueError as e:
            assert "overlap" in str(e)
            print("PASS safety.overlap_guard")
        else:
            raise AssertionError("overlapping hook was not rejected")
    finally:
        engine.destroy_all()
        MemoryManager.free_rwx(base, len(code))


def main():
    require_linux()
    test_page_boundary_read()
    test_overlap_guard()
    print(f"PASS safety ({BITS}-bit)")


if __name__ == "__main__":
    main()
