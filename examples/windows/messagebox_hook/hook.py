"""Rewrite MessageBoxW text/caption inside the target process."""
import ctypes
from ctypes import wintypes
import hookie
from hookie import resolve

_engine = hookie.HookEngine()
_hooks = []

# Resolve the target by name (resolve.export wraps GetProcAddress) and declare the
# signature explicitly, instead of going through a ctypes.WinDLL handle.
_ARGTYPES = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
_RESTYPE = ctypes.c_int
_target = resolve.export("user32.dll", "MessageBoxW")


def _detour(hwnd, text, caption, utype):
    return _hook.original(hwnd, "hooked by hookie", "hookie", utype)


_hook = _engine.create_hook(
    _target,
    _detour,
    _ARGTYPES,
    _RESTYPE,
    prototype_factory=(ctypes.WINFUNCTYPE if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.CFUNCTYPE),
)
_hook.enable()
_hooks.append(_hook)
