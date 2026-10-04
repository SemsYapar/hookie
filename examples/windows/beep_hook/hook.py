"""Intercept kernel32!Beep and rewrite its frequency/duration."""
import ctypes
from ctypes import wintypes
import hookie

_engine = hookie.HookEngine()
_hooks = []

kernel32 = ctypes.windll.kernel32
kernel32.Beep.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Beep.restype = wintypes.BOOL
_target = ctypes.cast(kernel32.Beep, ctypes.c_void_p).value


def _detour(frequency, duration):
    # Keep values in Beep's documented frequency range and shorten long beeps.
    frequency = max(37, min(int(frequency) + 200, 32767))
    duration = min(int(duration), 250)
    return _hook.original(frequency, duration)


_hook = _engine.create_hook(
    _target,
    _detour,
    kernel32.Beep.argtypes,
    kernel32.Beep.restype,
    prototype_factory=(ctypes.WINFUNCTYPE if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.CFUNCTYPE),
)
_hook.enable()
_hooks.append(_hook)
