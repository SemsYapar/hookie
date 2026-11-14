"""Atomic prologue write (closes the entry race / Scenario A).

On Linux, where thread suspension is not available, a rel32 enable()/disable()
must write the critical jmp as a single naturally-aligned 8-byte store so a
thread entering at the first byte never sees a half-written patch.
"""
import ctypes

import pytest

from hookie import memory


def test_write_qword_atomic_roundtrips():
    buf = (ctypes.c_uint8 * 32)()
    aligned = (ctypes.addressof(buf) + 7) & ~7
    memory.MemoryManager.write_qword_atomic(aligned, 0x1122334455667788)
    assert ctypes.c_uint64.from_address(aligned).value == 0x1122334455667788


def test_write_qword_atomic_rejects_misaligned():
    buf = (ctypes.c_uint8 * 16)()
    aligned = (ctypes.addressof(buf) + 7) & ~7
    with pytest.raises(ValueError):
        memory.MemoryManager.write_qword_atomic(aligned + 1, 0)


def test_rel32_enable_uses_atomic_store(engine, native, monkeypatch):
    addr, _, target, _ = native(b'\xB8\x07\x00\x00\x00' + b'\x90' * 16 + b'\xC3')
    hook = engine.create_hook(addr, lambda: 99, [], ctypes.c_int)
    # rel32-first => short stolen region, critical jmp fits one aligned qword.
    assert hook.stolen_size <= 8
    assert hook._core_len <= 8

    real = memory.MemoryManager.write_qword_atomic
    calls = {"n": 0}

    def counting(a, v):
        calls["n"] += 1
        return real(a, v)

    monkeypatch.setattr(memory.MemoryManager, "write_qword_atomic",
                        staticmethod(counting))
    assert target() == 7
    hook.enable()
    assert calls["n"] > 0, "enable() did not use the atomic store path"
    assert target() == 99
    hook.disable()
    assert target() == 7
