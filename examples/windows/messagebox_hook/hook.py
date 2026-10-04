"""Rewrite MessageBoxW text/caption inside the target process."""
import ctypes
from ctypes import wintypes
import hookie

_engine = hookie.HookEngine()
_hooks = []

user32 = ctypes.windll.user32
user32.MessageBoxW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.UINT,
]
user32.MessageBoxW.restype = ctypes.c_int
_target = ctypes.cast(user32.MessageBoxW, ctypes.c_void_p).value


def _detour(hwnd, text, caption, utype):
    return _hook.original(hwnd, "hooked by hookie", "hookie", utype)


_hook = _engine.create_hook(
    _target,
    _detour,
    user32.MessageBoxW.argtypes,
    user32.MessageBoxW.restype,
    prototype_factory=(ctypes.WINFUNCTYPE if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.CFUNCTYPE),
)
_hook.enable()
_hooks.append(_hook)
