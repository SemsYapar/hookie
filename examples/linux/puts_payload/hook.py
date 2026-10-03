"""Prefix strings passed to libc puts()."""
import ctypes
import hookie

_engine = hookie.HookEngine()
_hooks = []

libc = ctypes.CDLL(None)
libc.puts.argtypes = [ctypes.c_char_p]
libc.puts.restype = ctypes.c_int
_target = ctypes.cast(libc.puts, ctypes.c_void_p).value


def _detour(text):
    original = text or b"(null)"
    rewritten = b"[hookie] " + original
    return _hook.original(rewritten)


_hook = _engine.create_hook(
    _target,
    _detour,
    libc.puts.argtypes,
    libc.puts.restype,
)
_hook.enable()
_hooks.append(_hook)
