"""Windows CONTEXT and MEMORY_BASIC_INFORMATION layout per bitness.

Regression guard: a wrong x86 MBI layout (an extra PartitionId) previously
shifted RegionSize/State/Protect by 4 bytes, making readable_extent misread
State and refuse every page on x86.
"""
import ctypes

import pytest

from helpers import BITS, IS_WINDOWS

pytestmark = pytest.mark.skipif(not IS_WINDOWS, reason="Windows structs")


def test_memory_basic_information_layout():
    from hookie import memory
    MBI = memory.MEMORY_BASIC_INFORMATION
    # The fields hookie actually reads must land at the ABI offsets, otherwise
    # VirtualQuery fills the wrong words and readable_extent misjudges the page.
    # (Total sizeof includes trailing alignment padding and is not the invariant
    # that matters — the x86 bug was a 4-byte offset shift of exactly these.)
    if BITS == 64:
        assert MBI.RegionSize.offset == 24
        assert MBI.State.offset == 32
        assert MBI.Protect.offset == 36
    else:
        assert MBI.RegionSize.offset == 12
        assert MBI.State.offset == 16
        assert MBI.Protect.offset == 20
    has_partition_id = any(f[0] == "PartitionId" for f in MBI._fields_)
    assert has_partition_id == (BITS == 64), "PartitionId exists only on x64"


def test_context_layout():
    from hookie import threads
    CTX = threads.CONTEXT
    assert ctypes.sizeof(CTX) == (1232 if BITS == 64 else 716)
    ip_field = "Rip" if BITS == 64 else "Eip"
    assert any(f[0] == ip_field for f in CTX._fields_)


def test_readable_extent_sees_full_page():
    from hookie import memory
    k32 = ctypes.WinDLL("kernel32")
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_ulong, ctypes.c_ulong]
    page = ctypes.cast(k32.VirtualAlloc(None, 4096, 0x1000 | 0x2000, 0x40),
                       ctypes.c_void_p).value
    assert page, "VirtualAlloc failed"
    assert memory.MemoryManager.readable_extent(page, 16) == 16
