"""Thread suspension (Windows) — closes Scenario B.

enable()/disable() suspend every other thread and relocate any thread parked in
the stolen region before patching. Linux has no in-process suspend primitive yet,
so these are Windows-only.
"""
import ctypes
import threading
import time

import pytest

from helpers import BITS, IS_WINDOWS

pytestmark = pytest.mark.skipif(not IS_WINDOWS, reason="thread suspension is Windows-only")


def test_suspend_others_reads_usable_context():
    from hookie import threads
    ip_field = "Rip" if BITS == 64 else "Eip"

    stop = False

    def spin():
        while not stop:
            pass

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    time.sleep(0.1)
    suspended = threads._suspend_others()
    try:
        assert len(suspended) >= 1, "expected at least one suspended thread"
        for _handle, ctx in suspended:
            assert getattr(ctx, ip_field), f"{ip_field} is zero (GetThreadContext failed?)"
    finally:
        threads._resume(suspended)
        stop = True
    t.join(timeout=1.0)


def test_concurrent_enable_disable_does_not_crash(engine, native):
    addr, _, _, _ = native(b"\xB8\x00\x00\x00\x00\xC3")  # mov eax,0 ; ret
    target = ctypes.CFUNCTYPE(None)(addr)
    hook = engine.create_hook(addr, lambda: None, [], None)

    stop = False

    def worker():
        while not stop:
            target()

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(2)]
    for w in workers:
        w.start()
    time.sleep(0.05)
    # A bounded hammer: each enable/disable suspends every thread via a
    # *system-wide* thread snapshot (CreateToolhelp32Snapshot), which is not
    # cheap, so a few dozen cycles under contention is plenty to expose a
    # suspend-the-world deadlock or a torn patch. A wall-clock cap guarantees the
    # test terminates quickly even on a busy machine.
    deadline = time.monotonic() + 2.0
    cycles = 0
    try:
        while cycles < 40 and time.monotonic() < deadline:
            hook.enable()
            hook.disable()
            cycles += 1
    finally:
        stop = True
        time.sleep(0.05)
    for w in workers:
        w.join(timeout=1.0)
    assert cycles > 0
