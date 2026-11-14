"""Cross-platform test helpers.

The hook engine and MemoryManager are platform-agnostic, so the mechanical tests
(lifecycle, native calls, relocation, safety, transaction, patch strategy,
atomic write, relocation mapping) run unchanged on Windows and Linux. Only the
truly OS-specific tests (thread suspension, Windows CONTEXT/MBI structs, real
WinAPI hooks, native stub bootstrap) are gated with skip markers.
"""
import ctypes
import sys

from hookie import MemoryManager

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
BITS = ctypes.sizeof(ctypes.c_void_p) * 8


def make_native(code: bytes, restype=ctypes.c_int, argtypes=()):
    """Allocate executable memory, write *code*, and return
    (addr, size, callable, cfunctype). Works on Windows and Linux via
    MemoryManager. Free with free_native (the `native` fixture does this)."""
    size = len(code)
    addr = MemoryManager.allocate_rw(size)
    ctypes.memmove(addr, code, size)
    MemoryManager.flush_instruction_cache(addr, size)
    MemoryManager.protect_rx(addr, size)
    fn_type = ctypes.CFUNCTYPE(restype, *argtypes)
    return addr, size, fn_type(addr), fn_type


def free_native(addr: int, size: int) -> None:
    if addr:
        MemoryManager.free_rwx(addr, size)
