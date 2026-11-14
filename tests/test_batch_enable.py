"""enable_all / disable_all drive a single process-wide suspension.

Two things are checked without needing a real multi-threaded race:
  * behaviour — every hook redirects after enable_all and restores after
    disable_all;
  * the contract — the whole group funnels through exactly one
    modify_threads_batch call, instead of one suspend/resume per hook.

The second check is what makes the batching observable on any platform: on
Linux there is no suspension to watch, but the call count still proves the
engine no longer loops enable()/disable() hook by hook.
"""
import ctypes

import hookie.core as core

RET_42 = b'\xB8\x2A\x00\x00\x00' + b'\x90' * 16 + b'\xC3'   # mov eax,42; nops; ret
RET_7 = b'\xB8\x07\x00\x00\x00' + b'\x90' * 16 + b'\xC3'    # mov eax,7;  nops; ret


def test_enable_all_then_disable_all_round_trips(engine, native):
    a_addr, _, a_call, _ = native(RET_42)
    b_addr, _, b_call, _ = native(RET_7)
    engine.create_hook(a_addr, lambda: 1000, [], ctypes.c_int)
    engine.create_hook(b_addr, lambda: 2000, [], ctypes.c_int)

    assert (a_call(), b_call()) == (42, 7)
    engine.enable_all()
    assert (a_call(), b_call()) == (1000, 2000)
    engine.disable_all()
    assert (a_call(), b_call()) == (42, 7)


def test_enable_all_uses_one_batch(engine, native, monkeypatch):
    for code in (RET_42, RET_7):
        addr, _, _, _ = native(code)
        engine.create_hook(addr, lambda: 0, [], ctypes.c_int)

    calls = []
    real_batch = core.modify_threads_batch

    def spy(operations):
        ops = list(operations)
        calls.append(len(ops))
        return real_batch(ops)

    monkeypatch.setattr(core, "modify_threads_batch", spy)

    engine.enable_all()
    assert calls == [2]          # one call, both hooks in it — not two calls

    calls.clear()
    engine.disable_all()
    assert calls == [2]


def test_batch_skips_already_enabled(engine, native, monkeypatch):
    addr, _, call, _ = native(RET_42)
    hook = engine.create_hook(addr, lambda: 99, [], ctypes.c_int)
    hook.enable()

    calls = []
    monkeypatch.setattr(core, "modify_threads_batch",
                        lambda ops: calls.append(list(ops)))
    # Nothing to do: the lone hook is already enabled, so no suspension happens.
    engine.enable_all()
    assert calls == []

    # Restore the real driver so teardown can cleanly unpatch the prologue
    # before the native page is freed.
    monkeypatch.undo()
    hook.disable()
    assert call() == 42
