"""Transaction / rollback safety for enable/disable (Not J).

We inject failures into the memory layer to force the partial-write window and
assert the core invariant: the prologue and is_enabled never disagree, and a
failed enable rolls the prologue back to the original bytes instead of leaving
a half-written patch that would strand the hook (and UAF on destroy).
"""
import ctypes
from _common import BITS, HookEngine, MemoryManager, destroy_native, make_native, require_linux

CODE = b"\xB8\x2A\x00\x00\x00" + b"\x90" * 16 + b"\xC3"   # mov eax,42; nop*16; ret


def test_rollback_on_write_failure():
    """flush fails on the FIRST store (patch) but succeeds on the rollback store:
    enable must raise, stay disabled, and leave the ORIGINAL prologue intact."""
    real_flush = MemoryManager.flush_instruction_cache
    state = {"n": 0}

    def flaky_flush(addr, size):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError("injected flush failure")
        return real_flush(addr, size)

    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(CODE)
        hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)

        MemoryManager.flush_instruction_cache = staticmethod(flaky_flush)
        try:
            raised = False
            try:
                hook.enable()
            except RuntimeError:
                raised = True
            assert raised, "enable did not report failure"
            assert not hook.is_enabled, "is_enabled set despite failed enable"
            assert not hook._prologue_uncertain, "state marked uncertain on clean rollback"
        finally:
            MemoryManager.flush_instruction_cache = staticmethod(real_flush)

        # Prologue must be the ORIGINAL, not a half-written patch.
        assert target() == 42, f"prologue not rolled back (target returned {target()})"
        # And a clean enable afterwards must still work.
        hook.enable();  assert target() == 1337
        hook.disable(); assert target() == 42
        print("  PASS rollback_on_write_failure")
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


def test_protection_restore_failure_is_nonfatal():
    """restore_protection failing AFTER a good patch is swallowed: the hook is
    live (bytes applied) and is_enabled reflects that."""
    real_restore = MemoryManager.restore_protection
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(CODE)
        hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)

        MemoryManager.restore_protection = staticmethod(
            lambda a, s, o: (_ for _ in ()).throw(OSError("injected restore failure")))
        try:
            hook.enable()
            assert hook.is_enabled, "enable should succeed; patch landed"
            assert target() == 1337, "detour not live after enable"
        finally:
            MemoryManager.restore_protection = staticmethod(real_restore)

        hook.disable(); assert target() == 42
        print("  PASS protection_restore_failure_is_nonfatal")
    finally:
        engine.destroy_all()
        destroy_native(addr, size)


def test_uncertain_state_keeps_all_reachable_objects_alive():
    """If patch+rollback both fail, destroy must fail closed: no trampoline,
    relay, original thunk, or ctypes callback may be released."""
    real_flush = MemoryManager.flush_instruction_cache
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(CODE)
        hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)
        callback = hook._c_detour_ref
        original = hook.original
        tramp = hook.trampoline_addr

        MemoryManager.flush_instruction_cache = staticmethod(
            lambda a, s: (_ for _ in ()).throw(OSError("injected flush failure")))
        try:
            try:
                hook.enable()
            except RuntimeError:
                pass
            assert hook._prologue_uncertain, "uncertain flag not set"
        finally:
            MemoryManager.flush_instruction_cache = staticmethod(real_flush)

        try:
            hook.destroy()
        except RuntimeError as exc:
            assert "uncertain" in str(exc)
        else:
            raise AssertionError("unsafe destroy unexpectedly succeeded")

        assert not hook.is_destroyed
        assert hook in engine.hooks
        assert hook.trampoline_addr == tramp and tramp != 0
        assert hook._c_detour_ref is callback
        assert hook.original is original
        print("  PASS uncertain_state_keeps_all_reachable_objects_alive")
    finally:
        # The prologue state is intentionally unknown, so do not pretend normal
        # teardown is safe.  This process exits immediately after the test.
        destroy_native(addr, size)


def test_destroy_does_not_free_when_disable_cannot_make_page_writable():
    real_make_rwx = MemoryManager.make_rwx
    addr = size = 0
    engine = HookEngine()
    try:
        addr, size, target, _ = make_native(CODE)
        hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)
        hook.enable()
        assert target() == 1337
        callback = hook._c_detour_ref
        tramp = hook.trampoline_addr

        MemoryManager.make_rwx = staticmethod(
            lambda a, s: (_ for _ in ()).throw(OSError("injected mprotect failure")))
        try:
            try:
                hook.destroy()
            except OSError:
                pass
            else:
                raise AssertionError("destroy swallowed disable failure")
        finally:
            MemoryManager.make_rwx = staticmethod(real_make_rwx)

        assert hook.is_enabled
        assert not hook.is_destroyed
        assert hook in engine.hooks
        assert hook.trampoline_addr == tramp
        assert hook._c_detour_ref is callback

        # Once protection changes work again, teardown succeeds normally.
        hook.destroy()
        assert hook.is_destroyed and hook not in engine.hooks
        assert target() == 42
        print("  PASS destroy_disable_failure_keeps_resources")
    finally:
        try:
            engine.destroy_all()
        except Exception:
            pass
        destroy_native(addr, size)



def test_destroy_cleanup_failure_never_leaves_dangling_original():
    """Once the prologue is restored, a munmap/VirtualFree-style cleanup error
    must not leave ``hook.original`` callable if another allocation may already
    have been released. The hook is logically destroyed/detached; only the
    failed allocation is leaked for safety/diagnostics."""
    real_free = MemoryManager.free_rwx
    addr = size = 0
    engine = HookEngine()
    leaked_addr = leaked_size = 0
    try:
        addr, size, target, _ = make_native(CODE)
        hook = engine.create_hook(addr, lambda: 1337, [], ctypes.c_int)
        hook.enable()
        leaked_addr = hook.trampoline_addr
        leaked_size = hook.trampoline_size

        calls = {"n": 0}
        def fail_first_free(a, s=4096):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("injected executable free failure")
            return real_free(a, s)

        MemoryManager.free_rwx = staticmethod(fail_first_free)
        try:
            try:
                hook.destroy()
            except RuntimeError as exc:
                assert "detached safely" in str(exc)
            else:
                raise AssertionError("cleanup failure was not reported")
        finally:
            MemoryManager.free_rwx = staticmethod(real_free)

        assert target() == 42
        assert hook.is_destroyed
        assert hook not in engine.hooks
        assert hook.original is None
        assert hook._c_detour_ref is None
        assert hook.trampoline_addr == leaked_addr
        print("  PASS destroy_cleanup_failure_has_no_dangling_original")
    finally:
        if leaked_addr:
            try:
                real_free(leaked_addr, leaked_size)
            except OSError:
                pass
        engine.destroy_all()
        destroy_native(addr, size)

def main():
    require_linux()
    print("transaction/rollback:")
    test_rollback_on_write_failure()
    test_protection_restore_failure_is_nonfatal()
    test_destroy_does_not_free_when_disable_cannot_make_page_writable()
    test_destroy_cleanup_failure_never_leaves_dangling_original()
    test_uncertain_state_keeps_all_reachable_objects_alive()
    print(f"PASS transaction ({BITS}-bit)")


if __name__ == "__main__":
    main()
