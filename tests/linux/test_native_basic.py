import ctypes
from _common import BITS, HookEngine, destroy_native, make_native, require_linux


def main():
    require_linux()
    # mov eax, 42; enough NOPs for either x86 or x64 patch strategy; ret
    code = b'\xB8\x2A\x00\x00\x00' + b'\x90' * 16 + b'\xC3'
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(code)
        assert target() == 42

        def detour():
            return 1337

        hook = engine.create_hook(addr, detour, [], ctypes.c_int)
        hook.enable()
        assert target() == 1337
        hook.disable()
        assert target() == 42
        print(f'PASS native_basic ({BITS}-bit)')
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


if __name__ == '__main__':
    main()
