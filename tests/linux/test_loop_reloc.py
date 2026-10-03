"""LOOP / J*CXZ relocation (the rel8->long-jump bridge in _emit_loop).

Prologue is padded past 14 bytes so the engine picks the 14-byte absolute-jmp
patch, which also drags the LOOP into the stolen set and exercises that whole
path end to end.
"""
import ctypes
from _common import BITS, HookEngine, destroy_native, make_native, require_linux


def main():
    require_linux()
    if BITS != 64:
        print("SKIP loop_reloc (x64-only relocation case)")
        return
    # xor eax,eax; mov ecx,3; L: add eax,10; loop L; add eax,0 (pad>=14); ret
    #   loop @0x0A, rel8=-5 -> back to add@0x07 (intra). eax = 10*3 = 30.
    code = (b"\x31\xC0" + b"\xB9\x03\x00\x00\x00" + b"\x83\xC0\x0A"
            + b"\xE2\xFB" + b"\x83\xC0\x00" + b"\xC3")
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(code)
        assert target() == 30, f"un-hooked loop target returned {target()}"
        hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)
        assert hook.original() == 30, f"trampoline loop returned {hook.original()} (reloc broken)"
        hook.enable();  assert target() == 1337
        assert hook.original() == 30
        hook.disable(); assert target() == 30
        print("PASS loop_reloc (64-bit, intra LOOP + 14-byte patch path)")
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


if __name__ == "__main__":
    main()
