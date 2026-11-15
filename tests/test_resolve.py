"""hookie.resolve — in-process target resolution.

Cross-platform where it can be: name/base/scan tests pick a well-known system
module per OS (libc on Linux, kernel32 on Windows); rip_target runs against
bytes we assemble ourselves, so it needs no platform specifics.
"""
import ctypes
import struct

import pytest

from hookie import resolve, mem
from hookie.memory import MemoryManager
from helpers import IS_WINDOWS, BITS

# (module file name, bare stem, an exported symbol it definitely has)
if IS_WINDOWS:
    MODULE, STEM, SYMBOL = "kernel32.dll", "kernel32", "GetCurrentProcessId"
else:
    MODULE, STEM, SYMBOL = "libc.so.6", "libc", "getpid"


def _ctypes_address(module, symbol):
    lib = ctypes.CDLL(module)
    return ctypes.cast(getattr(lib, symbol), ctypes.c_void_p).value


def test_export_matches_ctypes():
    assert resolve.export(MODULE, SYMBOL) == _ctypes_address(MODULE, SYMBOL)


def test_export_by_stem():
    assert resolve.export(STEM, SYMBOL) == resolve.export(MODULE, SYMBOL)


def test_export_global_search():
    assert resolve.export(None, SYMBOL) == resolve.export(MODULE, SYMBOL)


def test_export_missing_raises():
    with pytest.raises(LookupError):
        resolve.export(MODULE, "there_is_no_such_export_xyz")


def test_module_base_is_below_its_exports():
    base = resolve.module_base(MODULE)
    assert isinstance(base, int) and base > 0
    assert base <= resolve.export(MODULE, SYMBOL)


def test_module_base_missing_raises():
    with pytest.raises(LookupError):
        resolve.module_base("no_such_module_xyz.dll")


def test_modules_lists_the_module():
    names = [n.lower() for n, _b, _s in resolve.modules()]
    assert any(STEM in n for n in names)


def test_scan_finds_a_known_prologue():
    addr = resolve.export(MODULE, SYMBOL)
    first = mem.read_bytes(addr, 12)
    pattern = " ".join(f"{b:02X}" for b in first)
    hit = resolve.scan(pattern, MODULE)
    assert hit is not None
    # The match need not be the symbol itself (an identical run may appear
    # earlier), but the bytes at the hit must equal what we searched for.
    assert mem.read_bytes(hit, len(first)) == first


def test_scan_wildcard():
    addr = resolve.export(MODULE, SYMBOL)
    first = mem.read_bytes(addr, 6)
    pattern = f"{first[0]:02X} ?? {first[2]:02X} ?? {first[4]:02X} ??"
    assert resolve.scan(pattern, MODULE) is not None


def test_scan_miss_returns_none():
    assert resolve.scan("DE AD BE EF CA FE BA BE 11 22 33 44 55 66", MODULE) is None


def test_rip_target_call_rel32():
    code = MemoryManager.allocate_rw(64)
    try:
        disp = 0x40
        mem.write_bytes(code, b"\xE8" + struct.pack("<i", disp), protect=False)
        MemoryManager.protect_rx(code, 64)
        assert resolve.rip_target(code) == code + 5 + disp
    finally:
        MemoryManager.free_rwx(code, 64)


@pytest.mark.skipif(BITS != 64, reason="RIP-relative addressing is x64-only")
def test_rip_target_lea_rip_relative():
    code = MemoryManager.allocate_rw(64)
    try:
        disp = 0x123
        mem.write_bytes(code, b"\x48\x8D\x05" + struct.pack("<i", disp), protect=False)
        MemoryManager.protect_rx(code, 64)
        assert resolve.rip_target(code) == code + 7 + disp
    finally:
        MemoryManager.free_rwx(code, 64)


def test_rip_target_non_reference_raises():
    code = MemoryManager.allocate_rw(64)
    try:
        mem.write_bytes(code, b"\x90\x90\xC3", protect=False)  # nop; nop; ret
        MemoryManager.protect_rx(code, 64)
        with pytest.raises(ValueError):
            resolve.rip_target(code)
    finally:
        MemoryManager.free_rwx(code, 64)
