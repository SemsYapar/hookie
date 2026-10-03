import ctypes
import sys

from hookie import HookEngine, MemoryManager

BITS = ctypes.sizeof(ctypes.c_void_p) * 8


def require_linux():
    if not sys.platform.startswith('linux'):
        raise SystemExit('This test is Linux-only')


def make_native(code: bytes, restype=ctypes.c_int, argtypes=()):
    size = len(code)
    addr = MemoryManager.allocate_rw(size)
    ctypes.memmove(addr, code, size)
    MemoryManager.flush_instruction_cache(addr, size)
    MemoryManager.protect_rx(addr, size)
    fn_type = ctypes.CFUNCTYPE(restype, *argtypes)
    return addr, size, fn_type(addr), fn_type


def destroy_native(addr: int, size: int):
    if addr:
        MemoryManager.free_rwx(addr, size)
