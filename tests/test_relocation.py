"""x64 relocation correctness.

For each relocation class a tiny native function is hand-assembled so the tricky
instruction lives inside the stolen prologue, then calling the *trampoline*
(hook.original) must reproduce the un-hooked result. If relocation mangled a
displacement the trampoline would return the wrong value or fault, so equality
is a direct proof the stolen instruction's target was preserved.
"""
import ctypes
import struct

import pytest

from helpers import BITS

pytestmark = pytest.mark.skipif(BITS != 64, reason="x64-only relocation cases")

SENTINEL = 0x7C0DE

# (id, machine code, expected un-hooked return value)
CASES = [
    ("call_rel32",
     b"\xE8\x04\x00\x00\x00" + b"\x83\xC0\x02" + b"\xC3" + b"\xB8\x28\x00\x00\x00\xC3", 42),
    ("jmp_rel32",
     b"\xE9\x00\x00\x00\x00" + b"\xB8\x2A\x00\x00\x00\xC3", 42),
    ("jmp_rel8",
     b"\x83\xC0\x00" + b"\xEB\x00" + b"\xB8\x2A\x00\x00\x00\xC3", 42),
    ("jcc_rel8",
     b"\x31\xC0" + b"\x74\x06" + b"\xB8\x63\x00\x00\x00\xC3" + b"\xB8\x2A\x00\x00\x00\xC3", 42),
    ("jcc_rel32",
     b"\x31\xC0" + b"\x0F\x84\x06\x00\x00\x00" + b"\xB8\x63\x00\x00\x00\xC3" + b"\xB8\x2A\x00\x00\x00\xC3", 42),
    ("rip_rel_lea_load",
     b"\x48\x8D\x05\x09\x00\x00\x00" + b"\x8B\x00" + b"\xC3" + b"\x90" * 6 + struct.pack("<I", 42), 42),
    ("rip_rel_mov",
     b"\x8B\x05" + struct.pack("<i", 10) + b"\x90" * 9 + b"\xC3" + struct.pack("<I", 42), 42),
]


@pytest.mark.parametrize("code,expected", [(c, e) for _, c, e in CASES],
                         ids=[n for n, _, _ in CASES])
def test_relocation_class(engine, native, code, expected):
    addr, _, target, _ = native(code)
    assert target() == expected, "un-hooked target wrong (bad test fixture)"

    hook = engine.create_hook(addr, lambda: SENTINEL, [], ctypes.c_int)
    # The trampoline runs the RELOCATED stolen bytes then resumes the original.
    assert hook.original() == expected, "relocation broke the stolen instruction"

    hook.enable()
    assert target() == SENTINEL
    assert hook.original() == expected
    hook.disable()
    assert target() == expected


def test_loop_relocation(engine, native):
    """LOOP uses a rel8 displacement; the stolen-set path must bridge it.
    Prologue padded past 14 bytes so the 14-byte absolute-jmp patch is chosen,
    which drags the LOOP into the stolen set."""
    # xor eax,eax ; mov ecx,3 ; L: add eax,10 ; loop L ; add eax,0 ; ret  => 30
    code = (b"\x31\xC0" + b"\xB9\x03\x00\x00\x00" + b"\x83\xC0\x0A"
            + b"\xE2\xFB" + b"\x83\xC0\x00" + b"\xC3")
    addr, _, target, _ = native(code)
    assert target() == 30
    hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)
    assert hook.original() == 30, "loop relocation broken"
    hook.enable()
    assert target() == 1337
    assert hook.original() == 30
    hook.disable()
    assert target() == 30
