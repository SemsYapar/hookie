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
    engine = HookEngine()
    holder = {}
    calls = 0

    def detour():
        nonlocal calls
        calls += 1
        # target'i tekrar cagirmiyoruz. Trampoline callable'i cagiriyoruz.
        original_value = holder["hook"].original()
        return original_value + 1000

    hook = engine.create_hook(target_addr, detour, [], ctypes.c_ulong)
    holder["hook"] = hook

    expected = os.getpid()
    assert target() == expected

    hook.enable()
    try:
        hooked = target()
        print(f"original() = {expected}")
        print(f"hooked     = {hooked}")
        print(f"calls      = {calls}")
        assert hooked == expected + 1000
        assert calls == 1
    finally:
        hook.disable()

    assert target() == expected
    engine.destroy_all()
    print("PASS")


if __name__ == "__main__":
    main()
