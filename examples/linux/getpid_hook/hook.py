"""Demonstrate return-value rewriting by intercepting libc getpid()."""
import ctypes
import hookie
from hookie import resolve

_engine = hookie.HookEngine()
_hooks = []

# resolve.export wraps dlsym; module=None searches the process's global symbols,
# so libc's getpid is found without naming the exact soname.
_target = resolve.export(None, "getpid")


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
