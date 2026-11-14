"""Hooking a real Windows API (kernel32!GetCurrentProcessId)."""
import ctypes
import os

import pytest

from helpers import IS_WINDOWS

pytestmark = pytest.mark.skipif(not IS_WINDOWS, reason="real WinAPI hooks are Windows-only")


def _get_current_process_id():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = k32.GetCurrentProcessId
    fn.argtypes = []
    fn.restype = ctypes.c_ulong
    return fn, ctypes.cast(fn, ctypes.c_void_p).value


def test_winapi_detour(engine):
    fn, addr = _get_current_process_id()
    assert fn() == os.getpid()
    hook = engine.create_hook(addr, lambda: 0x12345678, [], ctypes.c_ulong)
    hook.enable()
    assert fn() == 0x12345678
    hook.disable()
    assert fn() == os.getpid()


def test_winapi_original_through_trampoline(engine):
    fn, addr = _get_current_process_id()
    # Capture the pid BEFORE hooking: on Windows os.getpid() is itself a call to
    # GetCurrentProcessId, so once the hook is live os.getpid() returns the
    # detour's value too. Using it as the reference while hooked would compare
    # two hooked results and always be off by the detour's +1000.
    real_pid = os.getpid()
    holder = {}
    hook = engine.create_hook(
        addr, lambda: holder['h'].original() + 1000, [], ctypes.c_ulong)
    holder['h'] = hook
    hook.enable()
    assert fn() == real_pid + 1000      # original() (via trampoline) + 1000
    hook.disable()
    assert fn() == real_pid
