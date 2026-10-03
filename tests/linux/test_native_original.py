import ctypes
from _common import BITS, HookEngine, destroy_native, make_native, require_linux


def main():
    require_linux()
    code = b'\xB8\x2A\x00\x00\x00' + b'\x90' * 16 + b'\xC3'
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(code)
        holder = {}

        def detour():
            return holder['hook'].original() + 100

        hook = engine.create_hook(addr, detour, [], ctypes.c_int)
        holder['hook'] = hook
        hook.enable()
        assert target() == 142
        assert hook.original() == 42
        hook.disable()
        assert target() == 42
        print(f'PASS native_original ({BITS}-bit)')
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


if __name__ == '__main__':
    main()
