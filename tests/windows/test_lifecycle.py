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

    expected = os.getpid()
    engine = HookEngine()

    def detour():
        return 777

    hook = engine.create_hook(target_addr, detour, [], ctypes.c_ulong)

    # Idempotent enable.
    hook.enable()
    hook.enable()
    assert target() == 777

    # Idempotent disable.
    hook.disable()
    hook.disable()
    assert target() == expected

    # Yeniden enable edilebilmeli.
    hook.enable()
    assert target() == 777
    hook.disable()
    assert target() == expected

    # destroy_hook trampoline'i de serbest birakir ve engine listesinden cikarir.
    engine.destroy_hook(hook)
    assert hook.is_destroyed
    assert hook.original is None
    assert hook not in engine.hooks
    assert target() == expected

    try:
        hook.enable()
    except RuntimeError:
        pass
    else:
        raise AssertionError("destroy edilmis hook enable edilebildi")

    print("PASS")


if __name__ == "__main__":
    main()
