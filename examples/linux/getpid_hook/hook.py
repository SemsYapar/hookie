"""Demonstrate return-value rewriting by intercepting libc getpid()."""
import ctypes
import hookie

_engine = hookie.HookEngine()
_hooks = []

libc = ctypes.CDLL(None)
libc.getpid.argtypes = []
libc.getpid.restype = ctypes.c_int
_target = ctypes.cast(libc.getpid, ctypes.c_void_p).value


def _detour():
    # Deliberately obvious demo value; do not use this payload in software that
    # relies on its real PID for synchronization or file naming.
    return _hook.original() + 100000


_hook = _engine.create_hook(
    _target,
    _detour,
    [],
    ctypes.c_int,
)
_hook.enable()
_hooks.append(_hook)
