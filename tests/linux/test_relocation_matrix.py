"""x64 relocation correctness matrix (Not E).

For each relocation class we hand-assemble a tiny native function whose tricky
instruction lives inside the stolen prologue, then assert that calling the
*trampoline* (hook.original) reproduces the un-hooked result. If relocation
mangled a displacement the trampoline would return the wrong value or fault,
so equality is a direct proof that the stolen instruction's semantic target
was preserved. enable/disable round-trip is checked too.
"""
import ctypes
import struct
from _common import BITS, HookEngine, destroy_native, make_native, require_linux

SENTINEL = 0x7C0DE


def _run_case(name, code, expected):
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(code)
        got = target()
        assert got == expected, f"{name}: un-hooked target returned {got}, want {expected}"

        hook = engine.create_hook(addr, lambda: SENTINEL, [], ctypes.c_int)

        # The trampoline runs the RELOCATED stolen bytes then resumes the
        # original. This is the actual relocation assertion.
        orig = hook.original()
        assert orig == expected, f"{name}: trampoline returned {orig}, want {expected} (relocation broken)"

        hook.enable()
        assert target() == SENTINEL, f"{name}: detour not reached after enable"
        assert hook.original() == expected, f"{name}: trampoline wrong while enabled"
        hook.disable()
        assert target() == expected, f"{name}: original bytes not restored after disable"
        print(f"  PASS {name}")
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


def cases():
    # --- CALL rel32: steal the call; it must still reach sub40 from the trampoline
    # call +4 -> sub40(@9); add eax,2; ret; sub40: mov eax,40; ret
    yield ("CALL rel32",
           b"\xE8\x04\x00\x00\x00" + b"\x83\xC0\x02" + b"\xC3"
           + b"\xB8\x28\x00\x00\x00\xC3", 42)

    # --- JMP rel32: thunk prologue; relocated jmp must land on body
    # jmp +0 -> body(@5); body: mov eax,42; ret
    yield ("JMP rel32",
           b"\xE9\x00\x00\x00\x00" + b"\xB8\x2A\x00\x00\x00\xC3", 42)

    # --- JMP rel8: add eax,0; jmp +0 -> body(@5); body: mov eax,42; ret
    yield ("JMP rel8",
           b"\x83\xC0\x00" + b"\xEB\x00" + b"\xB8\x2A\x00\x00\x00\xC3", 42)

    # --- Jcc rel8 (taken): xor eax,eax(ZF=1); je +6 -> setok(@10);
    #     mov eax,99; ret; setok: mov eax,42; ret
    yield ("Jcc rel8",
           b"\x31\xC0" + b"\x74\x06" + b"\xB8\x63\x00\x00\x00\xC3"
           + b"\xB8\x2A\x00\x00\x00\xC3", 42)

    # --- Jcc rel32 (taken): xor eax,eax; je rel32=+6 -> setok(@14);
    #     mov eax,99; ret; setok: mov eax,42; ret
    yield ("Jcc rel32",
           b"\x31\xC0" + b"\x0F\x84\x06\x00\x00\x00"
           + b"\xB8\x63\x00\x00\x00\xC3" + b"\xB8\x2A\x00\x00\x00\xC3", 42)

    # --- RIP-relative LEA: lea rax,[rip+9] -> val(@16); mov eax,[rax]; ret; pad; val=42
    yield ("RIP-rel LEA+load",
           b"\x48\x8D\x05\x09\x00\x00\x00" + b"\x8B\x00" + b"\xC3"
           + b"\x90" * 6 + struct.pack("<I", 42), 42)

    # --- RIP-relative MOV: mov eax,[rip+10] -> dword(@16); pad; ret; dd 42
    yield ("RIP-rel MOV",
           b"\x8B\x05" + struct.pack("<i", 10) + b"\x90" * 9 + b"\xC3"
           + struct.pack("<I", 42), 42)


def main():
    require_linux()
    if BITS != 64:
        print("SKIP relocation_matrix (x64-only relocation cases)")
        return
    print("x64 relocation matrix:")
    for name, code, expected in cases():
        _run_case(name, code, expected)
    print("PASS relocation_matrix (64-bit)")


if __name__ == "__main__":
    main()
