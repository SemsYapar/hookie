import ctypes
import os

from hookie import HookEngine, MemoryManager


def write_code(code: bytes) -> int:
    addr = MemoryManager.allocate_rw(4096)
    ctypes.memmove(addr, code, len(code))
    MemoryManager.flush_instruction_cache(addr, len(code))
    MemoryManager.protect_rx(addr, 4096)
    return addr


def main():
    if os.name != "nt":
        raise SystemExit("Bu test Windows icindir.")

    bits = ctypes.sizeof(ctypes.c_void_p) * 8

    if bits == 64:
        # int f(void)
        #   mov eax, dword ptr [rip+8]   ; loads 41
        #   add eax, 1
        #   nop x5                       ; force stolen region >= 14 bytes
        #   ret
        #   dd 41
        #
        # First instruction is RIP-relative, so this directly tests the exact
        # trampoline-base constraint + displacement relocation path.
        code = bytes.fromhex(
            "8B 05 09 00 00 00 "
            "83 C0 01 "
            "90 90 90 90 90 "
            "C3 "
            "29 00 00 00"
        )
    else:
        exit(1)

    addr = write_code(code)
    FN = ctypes.CFUNCTYPE(ctypes.c_int)
    target = FN(addr)
    engine = HookEngine(bits=bits)
    holder = {}

    try:
        before = target()
        print(f"bits       = {bits}")
        print(f"target     = 0x{addr:X}")
        print(f"before     = {before}")
        assert before == 42

        def detour():
            # Relocated stolen instructions must still produce 42.
            return holder["hook"].original() + 100

        hook = engine.create_hook(addr, detour, [], ctypes.c_int)
        holder["hook"] = hook

        # Test trampoline before patching the original target too.
        tramp_value = hook.original()
        print(f"trampoline = {tramp_value}")
        assert tramp_value == 42

        hook.enable()
        hooked = target()
        print(f"hooked     = {hooked}")
        assert hooked == 142

        hook.disable()
        restored = target()
        print(f"restored   = {restored}")
        assert restored == 42

        engine.destroy_all()
        print("PASS")
    finally:
        engine.destroy_all()
        MemoryManager.free_rwx(addr, 4096)


if __name__ == "__main__":
    main()
