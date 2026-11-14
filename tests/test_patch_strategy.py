"""rel32-first patch selection.

A long straight prologue that pre-rel32 would have patched with the 14-byte
absolute jump must now steal <=8 bytes and (on x64) use a 5-byte rel32 core,
which is what keeps the write atomic. The absolute jump is a last resort only.
"""
import ctypes

from helpers import BITS

LONG_PROLOGUE = (b'\x55'                    # push rbp
                 + b'\x48\x89\xE5'          # mov rbp, rsp
                 + b'\x48\x83\xEC\x20'      # sub rsp, 0x20
                 + b'\x48\x89\x7D\xF8'      # mov [rbp-8], rdi
                 + b'\xB8\x07\x00\x00\x00'  # mov eax, 7
                 + b'\xC9\xC3')             # leave ; ret


def test_rel32_preferred_over_absolute(engine, native):
    addr, _, target, _ = native(LONG_PROLOGUE)
    hook = engine.create_hook(addr, lambda: 123, [], ctypes.c_int)

    assert hook.stolen_size <= 8, (
        f"rel32-first should steal <=8 bytes on a long prologue, "
        f"got {hook.stolen_size}")
    if BITS == 64:
        assert hook._core_len == 5, f"x64 rel32 core should be 5, got {hook._core_len}"

    assert target() == 7
    hook.enable()
    assert target() == 123
    hook.disable()
    assert target() == 7
