"""Stolen-region -> trampoline address mapping.

Platform-agnostic logic, but its real use is on Windows, where a suspended
thread's RIP and stack return addresses are retargeted onto the trampoline copy
of the stolen instructions before the prologue is overwritten (Scenario B).
"""
import ctypes

# endbr64 / push / mov prologue so the stolen region spans a few whole
# instructions, giving the addr_map more than one boundary.
CODE = (b'\xF3\x0F\x1E\xFA'          # endbr64
        + b'\x55'                   # push rbp
        + b'\x48\x89\xE5'           # mov rbp, rsp
        + b'\xB8\x07\x00\x00\x00'   # mov eax, 7
        + b'\xC3')                  # ret


def test_stolen_start_maps_to_trampoline_start(engine, native):
    addr, _, _, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 1, [], ctypes.c_int)
    assert hook.relocate_stolen(addr) == hook.trampoline_addr


def test_outside_stolen_region_maps_to_none(engine, native):
    addr, _, _, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 1, [], ctypes.c_int)
    assert hook.relocate_stolen(addr - 1) is None
    assert hook.relocate_stolen(addr + hook.stolen_size) is None
    assert hook.relocate_stolen(addr + hook.stolen_size + 64) is None


def test_interior_boundary_maps_into_trampoline(engine, native):
    addr, _, _, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 1, [], ctypes.c_int)
    if hook.stolen_size > 4:
        mapped = hook.relocate_stolen(addr + 4)  # push rbp, after 4-byte endbr64
        assert mapped is not None and mapped > hook.trampoline_addr
