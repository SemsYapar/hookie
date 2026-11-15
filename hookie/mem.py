"""In-process memory read/write helpers.

These are thin, cross-platform conveniences over what ctypes already does in the
*current* process — nothing here reaches into another process.

Every helper takes one ``protect`` flag with a single, consistent meaning:

* ``protect=True`` (default) — ensure the page permits the operation. The page's
  current protection is checked; if it already allows the read/write, the
  operation runs as-is. If not, the protection is temporarily changed, the
  operation runs, and the original protection is restored. If the page cannot be
  made to permit the operation (e.g. an unmapped address), an error is raised; if
  the restore fails afterwards, that error is raised too. For writes to code the
  instruction cache is flushed when a change was made.
* ``protect=False`` — do the raw operation with no protection check or change
  (fastest; use it only when you already know the page permits it, e.g. a
  caller-provided buffer inside a hot detour). A wrong address may fault the
  process.

The protection management is implemented by :class:`~hookie.memory.MemoryManager`
(VirtualProtect on Windows, mprotect on Linux). Addresses are plain ints; byte
payloads are ``bytes``.
"""
from __future__ import annotations

import ctypes

from .memory import MemoryManager

__all__ = ["read_bytes", "read_ptr", "write_bytes", "read_chain"]

_PTR_SIZE = ctypes.sizeof(ctypes.c_void_p)


def _permits(address: int, size: int, *, write: bool) -> bool:
    extent = (MemoryManager.writable_extent if write
              else MemoryManager.readable_extent)(address, size)
    return extent >= size


def _with_access(address: int, size: int, *, write: bool, op):
    """Run *op()* with the page permitting the access, flipping protection only if
    needed and restoring it afterwards. Raises if the page can't be made to allow
    the access, or if the flip/restore fails."""
    if _permits(address, size, write=write):
        return op()
    old = MemoryManager.make_rwx(address, size)  # raises if the page can't be changed
    try:
        return op()
    finally:
        MemoryManager.restore_protection(address, size, old)


def read_bytes(address: int, size: int, *, protect: bool = True) -> bytes:
    """Read *size* bytes from *address* and return them as ``bytes`` (no
    NUL-termination assumption). See the module docstring for ``protect``."""
    if size < 0:
        raise ValueError("size must be non-negative")
    if size == 0:
        return b""
    if not protect:
        return ctypes.string_at(address, size)
    return _with_access(address, size, write=False,
                        op=lambda: ctypes.string_at(address, size))


def read_ptr(address: int, *, protect: bool = True) -> int:
    """Read one pointer-sized value at *address* (8 bytes on x64, 4 on x86) and
    return it as an int. Use this to follow a stored pointer; for an arbitrary
    width use :func:`read_bytes`. See the module docstring for ``protect``."""
    def _do():
        return ctypes.c_void_p.from_address(address).value or 0
    if not protect:
        return _do()
    return _with_access(address, _PTR_SIZE, write=False, op=_do)


def write_bytes(address: int, data: bytes, *, protect: bool = True) -> None:
    """Write *data* at *address*. See the module docstring for ``protect``; with
    ``protect=True`` a read-only code page is made writable, written, and
    restored, and the instruction cache is flushed."""
    n = len(data)
    if n == 0:
        return
    buf = (ctypes.c_char * n).from_buffer_copy(data)
    if not protect:
        ctypes.memmove(address, buf, n)
        return
    if _permits(address, n, write=True):
        ctypes.memmove(address, buf, n)
        return
    old = MemoryManager.make_rwx(address, n)
    try:
        ctypes.memmove(address, buf, n)
    finally:
        MemoryManager.restore_protection(address, n, old)
    MemoryManager.flush_instruction_cache(address, n)


def read_chain(base: int, offsets, *, protect: bool = True) -> int:
    """Follow a multi-level pointer and return the final *address*.

    Starting at *base*, for every offset except the last: add the offset and
    dereference (read a pointer). Add the final offset without dereferencing and
    return that address. With offsets ``[0x0, 0x10, 0x8]`` this is
    ``read_ptr(read_ptr(base + 0x0) + 0x10) + 0x8`` — the common game-hacking
    pointer path. An empty offsets list returns *base*. ``protect`` is forwarded
    to each dereferencing :func:`read_ptr`."""
    offsets = list(offsets)
    if not offsets:
        return base
    addr = base
    for off in offsets[:-1]:
        addr = read_ptr(addr + off, protect=protect)
    return addr + offsets[-1]
