"""Transaction / rollback safety for enable/disable.

Failures are injected into the memory layer to force the partial-write window,
then the core invariant is asserted: the prologue and is_enabled never disagree,
a failed enable rolls the prologue back to the original bytes, and if both the
patch and its rollback fail the hook fails closed on destroy (no use-after-free).
"""
import ctypes

import pytest

from hookie import MemoryManager

CODE = b"\xB8\x2A\x00\x00\x00" + b"\x90" * 16 + b"\xC3"   # mov eax,42 ; nops ; ret


def _raise(*_a, **_k):
    raise OSError("injected failure")


def test_rollback_on_write_failure(engine, native, monkeypatch):
    """Flush fails on the first store (patch) but succeeds on the rollback store:
    enable must raise, stay disabled, and leave the ORIGINAL prologue intact."""
    addr, _, target, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)

    real_flush = MemoryManager.flush_instruction_cache
    state = {"n": 0}

    def flaky_flush(a, s):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError("injected flush failure")
        return real_flush(a, s)

    monkeypatch.setattr(MemoryManager, "flush_instruction_cache",
                        staticmethod(flaky_flush))
    with pytest.raises(RuntimeError):
        hook.enable()
    assert not hook.is_enabled
    assert not hook._prologue_uncertain
    monkeypatch.undo()

    assert target() == 42, "prologue not rolled back to original"
    hook.enable()
    assert target() == 1337
    hook.disable()
    assert target() == 42


def test_protection_restore_failure_is_nonfatal(engine, native, monkeypatch):
    """restore_protection failing AFTER a good patch is swallowed: the hook is
    live (bytes applied) and is_enabled reflects that."""
    addr, _, target, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)

    monkeypatch.setattr(MemoryManager, "restore_protection", staticmethod(_raise))
    hook.enable()
    assert hook.is_enabled
    assert target() == 1337
    monkeypatch.undo()

    hook.disable()
    assert target() == 42


def test_uncertain_state_fails_closed_on_destroy(native, monkeypatch):
    """If patch+rollback both fail, destroy must fail closed: no trampoline,
    relay, original thunk, or ctypes callback may be released."""
    # Not the `engine` fixture: its destroy_all() teardown would (correctly)
    # raise on the deliberately-uncertain hook. We leak it instead — the test
    # process is disposable.
    from hookie import HookEngine
    engine = HookEngine()
    addr, _, _, _ = native(CODE)
    hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)
    callback = hook._c_detour_ref
    original = hook.original
    tramp = hook.trampoline_addr

    monkeypatch.setattr(MemoryManager, "flush_instruction_cache", staticmethod(_raise))
    with pytest.raises(RuntimeError):
        hook.enable()
    assert hook._prologue_uncertain
    monkeypatch.undo()

    with pytest.raises(RuntimeError, match="uncertain"):
        hook.destroy()

    assert not hook.is_destroyed
    assert hook in engine.hooks
    assert hook.trampoline_addr == tramp and tramp != 0
    assert hook._c_detour_ref is callback
    assert hook.original is original
    # The prologue state is intentionally unknown; do not call the target. The
    # engine fixture's destroy_all() must also tolerate this uncertain hook.
