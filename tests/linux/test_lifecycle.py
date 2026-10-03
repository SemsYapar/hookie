import ctypes
from _common import BITS, HookEngine, destroy_native, make_native, require_linux


def main():
    require_linux()
    code = b'\xB8\x07\x00\x00\x00' + b'\x90' * 16 + b'\xC3'
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(code)

        def detour():
            return 99

        hook = engine.create_hook(addr, detour, [], ctypes.c_int)
        assert target() == 7
        hook.enable();  assert target() == 99
        hook.enable();  assert target() == 99
        hook.disable(); assert target() == 7
        hook.disable(); assert target() == 7
        hook.enable();  assert target() == 99
        # Direct destroy is part of the public API and must detach ownership.
        hook.destroy()
        assert target() == 7
        assert hook.is_destroyed
        assert hook not in engine.hooks
        print(f'PASS lifecycle ({BITS}-bit)')
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


if __name__ == '__main__':
    main()
