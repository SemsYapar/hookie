"""Prefix strings passed to libc puts()."""
import ctypes
import hookie
from hookie import resolve

_engine = hookie.HookEngine()
_hooks = []

_ARGTYPES = [ctypes.c_char_p]
_RESTYPE = ctypes.c_int
_target = resolve.export(None, "puts")


def _detour(text):
    original = text or b"(null)"
    rewritten = b"[hookie] " + original
    return _hook.original(rewritten)


_hook = _engine.create_hook(
    _target,
    _detour,
    _ARGTYPES,
    _RESTYPE,
)
_hook.enable()
_hooks.append(_hook)
