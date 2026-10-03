import ctypes
import os

from hookie import HookEngine


def main():
    if os.name != "nt":
        raise SystemExit("Bu test Windows icindir.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    target = kernel32.GetCurrentProcessId
    target.argtypes = []
    target.restype = ctypes.c_ulong

    target_addr = ctypes.cast(target, ctypes.c_void_p).value
    real_pid = os.getpid()
    fake_pid = 0x12345678

    print(f"target     = 0x{target_addr:X}")
    print(f"before     = {target()}")
    assert target() == real_pid

    engine = HookEngine()

    def detour():
        return fake_pid

    hook = engine.create_hook(target_addr, detour, [], ctypes.c_ulong)
    hook.enable()
    try:
        value = target()
        print(f"hooked     = 0x{value:08X}")
        assert value == fake_pid
    finally:
        hook.disable()

    value = target()
    print(f"restored   = {value}")
    assert value == real_pid

    engine.destroy_all()
    print("PASS")


if __name__ == "__main__":
    main()
