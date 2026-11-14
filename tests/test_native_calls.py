import ctypes
import struct

from helpers import BITS

NOPPED = b'\xB8\x2A\x00\x00\x00' + b'\x90' * 16 + b'\xC3'  # mov eax,42 ; nops ; ret


def test_basic_detour(engine, native):
    addr, _, target, _ = native(NOPPED)
    assert target() == 42
    hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)
    hook.enable()
    assert target() == 1337
    hook.disable()
    assert target() == 42


def test_original_is_callable_through_trampoline(engine, native):
    addr, _, target, _ = native(NOPPED)
    holder = {}
    hook = engine.create_hook(
        addr, lambda: holder['h'].original() + 100, [], ctypes.c_int)
    holder['h'] = hook
    hook.enable()
    assert target() == 142
    assert hook.original() == 42
    hook.disable()
    assert target() == 42


def _relative_prologue_case():
    if BITS == 64:
        # mov eax,[rip+10] ; nops ; ret ; dd 42  — RIP-relative load in the stolen bytes.
        return b'\x8B\x05' + struct.pack('<i', 10) + b'\x90' * 9 + b'\xC3' + struct.pack('<I', 42)
    # call helper ; nops ; ret ; helper: mov eax,42 ; ret  — rel32 call in the stolen bytes.
    return b'\xE8' + struct.pack('<i', 11) + b'\x90' * 10 + b'\xC3' + b'\xB8\x2A\x00\x00\x00\xC3'


def test_relative_prologue_relocation(engine, native):
    addr, _, target, _ = native(_relative_prologue_case())
    assert target() == 42
    holder = {}
    hook = engine.create_hook(
        addr, lambda: holder['h'].original() + 1, [], ctypes.c_int)
    holder['h'] = hook
    # Trampoline must reproduce the original result even before the target is patched.
    assert hook.original() == 42
    hook.enable()
    assert target() == 43
    hook.disable()
    assert target() == 42
