"""Intercept kernel32!Beep and rewrite its frequency/duration."""
import ctypes
from ctypes import wintypes
import hookie
from hookie import resolve

_engine = hookie.HookEngine()
_hooks = []

_ARGTYPES = [wintypes.DWORD, wintypes.DWORD]
_RESTYPE = wintypes.BOOL
_target = resolve.export("kernel32.dll", "Beep")


def _detour(frequency, duration):
    # Keep values in Beep's documented frequency range and shorten long beeps.
    frequency = max(37, min(int(frequency) + 200, 32767))
    duration = min(int(duration), 250)
    return _hook.original(frequency, duration)


_hook = _engine.create_hook(
    _target,
    _detour,
    _ARGTYPES,
    _RESTYPE,
    prototype_factory=(ctypes.WINFUNCTYPE if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.CFUNCTYPE),
)
_hook.enable()
_hooks.append(_hook)
