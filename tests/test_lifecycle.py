import ctypes

CODE = b'\xB8\x07\x00\x00\x00' + b'\x90' * 16 + b'\xC3'  # mov eax,7 ; nops ; ret


def test_enable_disable_roundtrip(engine, native):
    addr, _, target, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 99, [], ctypes.c_int)
    assert target() == 7
    hook.enable()
    assert target() == 99
    hook.disable()
    assert target() == 7


def test_enable_disable_idempotent(engine, native):
    addr, _, target, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 99, [], ctypes.c_int)
    hook.enable()
    hook.enable()
    assert target() == 99
    hook.disable()
    hook.disable()
    assert target() == 7


def test_direct_destroy_restores_and_detaches(engine, native):
    addr, _, target, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 99, [], ctypes.c_int)
    hook.enable()
    assert target() == 99
    # Public Hook.destroy() restores the target and detaches ownership.
    hook.destroy()
    assert target() == 7
    assert hook.is_destroyed
    assert hook not in engine.hooks
