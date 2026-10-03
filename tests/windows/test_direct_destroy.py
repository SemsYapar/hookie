import ctypes
import os

from hookie import HookEngine


def main():
    if os.name != "nt":
        raise SystemExit("This test is Windows-only")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    target = kernel32.GetCurrentProcessId
    target.argtypes = []
    target.restype = ctypes.c_ulong
    target_addr = ctypes.cast(target, ctypes.c_void_p).value

    engine = HookEngine()
    hook = engine.create_hook(target_addr, lambda: 0x1234, [], ctypes.c_ulong)
    hook.enable()
    assert target() == 0x1234

    # Public Hook.destroy() must restore the target and detach ownership too.
    hook.destroy()
    assert hook.is_destroyed
    assert hook not in engine.hooks
    assert target() == os.getpid()
    print("PASS direct destroy ownership")


if __name__ == "__main__":
    main()
