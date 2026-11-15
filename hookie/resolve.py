"""In-process target resolution: turn a name, pattern, or reference into an
address you can pass to ``HookEngine.create_hook`` (or to :mod:`hookie.mem`).

Everything here works on the *current* process (the one hookie is running in).
Most of it is a thin, cross-platform wrapper over what ctypes already exposes —
the docstrings say exactly what runs underneath, so there is no magic:

* :func:`module_base` — GetModuleHandleW (Windows) / ``/proc/self/maps`` (Linux)
* :func:`export`      — GetProcAddress (Windows) / dlsym via ctypes (Linux)
* :func:`modules`     — Toolhelp module snapshot (Windows) / ``/proc/self/maps``

The two that add capability ctypes has no equivalent for:

* :func:`scan`        — byte-pattern (AOB) search over a module's executable code
* :func:`rip_target`  — decode an instruction and return the address it references

Addresses are plain ints. Module names are matched by file name
(``"user32.dll"``, ``"libc.so.6"``; on Linux a bare stem like ``"libc"`` also
matches). ``module=None`` means the main executable.
"""
from __future__ import annotations

import ctypes
import os

from .memory import MemoryManager

__all__ = ["module_base", "export", "modules", "scan", "rip_target"]

IS_WINDOWS = os.name == "nt"
_BITS = ctypes.sizeof(ctypes.c_void_p) * 8

if IS_WINDOWS:
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _k32.GetModuleHandleW.restype = wintypes.HMODULE
    _k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    _k32.GetProcAddress.restype = ctypes.c_void_p
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetCurrentProcessId.restype = wintypes.DWORD

    _TH32CS_SNAPMODULE = 0x08
    _TH32CS_SNAPMODULE32 = 0x10
    _INVALID = ctypes.c_void_p(-1).value

    class _MODULEENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD),
            ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", ctypes.c_void_p),
            ("modBaseSize", wintypes.DWORD),
            ("hModule", wintypes.HMODULE),
            ("szModule", ctypes.c_wchar * 256),
            ("szExePath", ctypes.c_wchar * 260),
        ]

    _k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_MODULEENTRY32W)]
    _k32.Module32FirstW.restype = wintypes.BOOL
    _k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_MODULEENTRY32W)]
    _k32.Module32NextW.restype = wintypes.BOOL

    def _iter_modules():
        """Yield (name, base, size) for every module loaded in this process."""
        snap = _k32.CreateToolhelp32Snapshot(
            _TH32CS_SNAPMODULE | _TH32CS_SNAPMODULE32, _k32.GetCurrentProcessId()
        )
        if not snap or snap == _INVALID:
            raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
        try:
            ent = _MODULEENTRY32W()
            ent.dwSize = ctypes.sizeof(_MODULEENTRY32W)
            ok = _k32.Module32FirstW(snap, ctypes.byref(ent))
            while ok:
                yield (ent.szModule, int(ent.modBaseAddr), int(ent.modBaseSize))
                ent.dwSize = ctypes.sizeof(_MODULEENTRY32W)
                ok = _k32.Module32NextW(snap, ctypes.byref(ent))
        finally:
            _k32.CloseHandle(snap)
else:
    _RTLD_NOW = 0x0002
    _RTLD_NOLOAD = 0x0004
    _libdl = ctypes.CDLL(None, use_errno=True)
    _libdl.dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _libdl.dlopen.restype = ctypes.c_void_p
    _libdl.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _libdl.dlsym.restype = ctypes.c_void_p

    def _maps():
        """Parse /proc/self/maps -> list of (start, end, perms, path)."""
        out = []
        with open("/proc/self/maps", "r") as f:
            for line in f:
                parts = line.split(maxsplit=5)
                if len(parts) < 5:
                    continue
                span, perms = parts[0], parts[1]
                path = parts[5].strip() if len(parts) == 6 else ""
                start_s, _, end_s = span.partition("-")
                out.append((int(start_s, 16), int(end_s, 16), perms, path))
        return out

    def _main_exe_path():
        try:
            return os.path.realpath("/proc/self/exe")
        except OSError:
            return ""

    def _module_path(module: str):
        """Full path of a loaded module matching *module* (exact name or stem)."""
        for _s, _e, _p, path in _maps():
            if path and not path.startswith("[") and _name_matches(path, module):
                return path
        return None


def _name_matches(path: str, module: str) -> bool:
    """Does a module file path match the requested name? Exact file name, or a
    bare stem: ``"libc"`` matches ``libc.so.6``, ``"user32"`` matches
    ``user32.dll``. (module=None is handled by the callers, not here.)"""
    base = os.path.basename(path).lower()
    module = module.lower()
    return base == module or base.startswith(module + ".")


def module_base(name=None) -> int:
    """Base (load) address of a module in this process. ``name=None`` -> the main
    executable. Raises ``LookupError`` if the module is not loaded.

    Thin wrapper: Windows ``GetModuleHandleW`` (the HMODULE *is* the base);
    Linux reads the lowest mapping of the module from ``/proc/self/maps``."""
    if IS_WINDOWS:
        h = _k32.GetModuleHandleW(name)
        if not h:
            raise LookupError(f"module not loaded: {name!r}")
        return int(h)
    exe = _main_exe_path()
    best = None
    for start, _end, _perms, path in _maps():
        if not path:
            continue
        hit = (os.path.realpath(path) == exe) if name is None else _name_matches(path, name)
        if hit and (best is None or start < best):
            best = start
    if best is None:
        raise LookupError(f"module not loaded: {name!r}")
    return best


def export(module, name: str) -> int:
    """Address of an exported symbol *name* in *module*. ``module=None`` searches
    every loaded module (like dlsym's ``RTLD_DEFAULT``). Raises ``LookupError`` if
    the symbol is not found.

    Thin wrapper: Windows ``GetProcAddress`` on the module handle (for
    ``module=None``, over each loaded module until one resolves); Linux ``dlsym``
    on a handle from ``dlopen(RTLD_NOLOAD)`` (so the module must already be loaded
    — no new library is pulled in as a side effect)."""
    if IS_WINDOWS:
        enc = name.encode("ascii")
        if module is None:
            for _n, base, _s in _iter_modules():
                addr = _k32.GetProcAddress(base, enc)
                if addr:
                    return int(addr)
            raise LookupError(f"export not found in any loaded module: {name!r}")
        h = _k32.GetModuleHandleW(module)
        if not h:
            raise LookupError(f"module not loaded: {module!r}")
        addr = _k32.GetProcAddress(h, enc)
        if not addr:
            raise LookupError(f"export not found: {name!r} in {module!r}")
        return int(addr)
    if module is None:
        handle = 0  # RTLD_DEFAULT: search the process's global symbols
    else:
        path = _module_path(module) or module
        handle = _libdl.dlopen(path.encode(), _RTLD_NOW | _RTLD_NOLOAD)
        if not handle:
            raise LookupError(f"module not loaded: {module!r}")
    addr = _libdl.dlsym(handle, name.encode("ascii"))
    if not addr:
        raise LookupError(f"export not found: {name!r} in {module!r}")
    return int(addr)


def modules():
    """List modules loaded in this process as ``(name, base, size)`` tuples.

    Wrapper: Windows Toolhelp module snapshot; Linux groups ``/proc/self/maps``
    by file, base = lowest mapping, size = span to the highest."""
    if IS_WINDOWS:
        return list(_iter_modules())
    agg = {}  # path -> [min_start, max_end]
    for start, end, _perms, path in _maps():
        if not path or path.startswith("["):
            continue
        rec = agg.get(path)
        if rec is None:
            agg[path] = [start, end]
        else:
            rec[0] = min(rec[0], start)
            rec[1] = max(rec[1], end)
    return [(os.path.basename(p), lo, hi - lo) for p, (lo, hi) in agg.items()]


def _exec_regions(module):
    """Yield (start, size) of the executable regions of *module* in this process."""
    if IS_WINDOWS:
        base = module_base(module)
        size = next((sz for _n, b, sz in _iter_modules() if b == base), 0)
        _walk_exec_regions_windows(base, size, out := [])
        yield from out
    else:
        exe = _main_exe_path()
        for start, end, perms, path in _maps():
            if "x" not in perms or not path:
                continue
            hit = (os.path.realpath(path) == exe) if module is None else _name_matches(path, module)
            if hit:
                yield (start, end - start)


if IS_WINDOWS:
    from .memory import MEMORY_BASIC_INFORMATION  # type: ignore

    _k32.VirtualQuery.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
    ]
    _k32.VirtualQuery.restype = ctypes.c_size_t
    _MEM_COMMIT = 0x1000
    _EXEC_PROTECT = {0x10, 0x20, 0x40, 0x80}  # EXECUTE / _READ / _READWRITE / _WRITECOPY

    def _walk_exec_regions_windows(base, size, out):
        addr = base
        end = base + size
        mbi = MEMORY_BASIC_INFORMATION()
        while addr < end:
            if _k32.VirtualQuery(addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            region = int(mbi.BaseAddress or addr)
            rsize = int(mbi.RegionSize)
            if rsize == 0:
                break
            if int(mbi.State) == _MEM_COMMIT and (int(mbi.Protect) & 0xFF) in _EXEC_PROTECT:
                lo = max(region, base)
                hi = min(region + rsize, end)
                if hi > lo:
                    out.append((lo, hi - lo))
            addr = region + rsize


def _parse_pattern(pattern: str):
    pat, mask = bytearray(), bytearray()
    for tok in pattern.split():
        if tok in ("??", "?"):
            pat.append(0)
            mask.append(0)
        else:
            pat.append(int(tok, 16))
            mask.append(1)
    if not pat:
        raise ValueError("empty pattern")
    return bytes(pat), bytes(mask)


def _find(data: bytes, pat: bytes, mask: bytes):
    n = len(pat)
    if n > len(data):
        return -1
    anchor = next((j for j in range(n) if mask[j]), None)
    if anchor is None:  # all wildcards: matches at the start
        return 0
    byte = pat[anchor]
    start = 0
    limit = len(data) - n
    while True:
        pos = data.find(byte, start)
        if pos < 0:
            return -1
        i = pos - anchor
        if 0 <= i <= limit and all(mask[j] == 0 or data[i + j] == pat[j] for j in range(n)):
            return i
        start = pos + 1


def scan(pattern: str, module=None):
    """Find a byte pattern (AOB) in a module's executable code and return the
    address of the first match, or ``None`` if not found. ``module=None`` scans
    the main executable.

    *pattern* is hex bytes separated by spaces, with ``??`` (or ``?``) for a
    wildcard byte, e.g. ``"48 8B 05 ?? ?? ?? ?? 48 85 C0"``. This has no ctypes
    equivalent — it reads the module's executable regions and searches them."""
    pat, mask = _parse_pattern(pattern)
    for start, size in _exec_regions(module):
        safe = MemoryManager.readable_extent(start, size)
        if safe <= 0:
            continue
        data = ctypes.string_at(start, safe)
        idx = _find(data, pat, mask)
        if idx >= 0:
            return start + idx
    return None


def rip_target(address: int) -> int:
    """Decode the instruction at *address* and return the absolute address it
    references: the target of a relative ``call``/``jmp`` (the actual function),
    or the address a RIP-relative ``[rip+disp]`` operand points at. Raises
    ``ValueError`` if the instruction references neither.

    Pair it with :func:`scan` when a pattern matches a *call site* rather than the
    function itself: ``rip_target(scan(...))`` turns ``call func`` into ``func``."""
    from .disassembler import Disassembler

    dis = Disassembler(_BITS)
    insns = dis.disassemble(address, size=16)
    if not insns:
        raise ValueError(f"could not decode an instruction at 0x{address:X}")
    target = dis.reference_target(insns[0])
    if target is None:
        raise ValueError(
            f"instruction at 0x{address:X} ({insns[0].mnemonic} {insns[0].op_str}) "
            "has no relative branch or RIP-relative operand"
        )
    return target
