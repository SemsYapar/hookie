import ctypes
import struct
from _common import BITS, HookEngine, destroy_native, make_native, require_linux


def make_case():
    if BITS == 64:
        # mov eax,[rip+9] ; NOP*9 ; ret ; dd 42
        # data starts at +16, RIP after MOV is +6 => disp32 = 10.
        code = b'\x8B\x05' + struct.pack('<i', 10) + b'\x90' * 9 + b'\xC3' + struct.pack('<I', 42)
        return code

    # call helper; NOP padding; ret; helper: mov eax,42; ret
    # E8 is at +0, next IP +5, helper starts +16 => rel32=11.
    return b'\xE8' + struct.pack('<i', 11) + b'\x90' * 10 + b'\xC3' + b'\xB8\x2A\x00\x00\x00\xC3'


def main():
    require_linux()
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(make_case())
        assert target() == 42
        holder = {}

        def detour():
            return holder['hook'].original() + 1

        hook = engine.create_hook(addr, detour, [], ctypes.c_int)
        holder['hook'] = hook

        # Test trampoline before target patching too.
        assert hook.original() == 42
        hook.enable()
        assert target() == 43
        hook.disable()
        assert target() == 42
        print(f'PASS native_relative ({BITS}-bit)')
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


if __name__ == '__main__':
    main()
