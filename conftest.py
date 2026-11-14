"""Pytest configuration: make the in-tree hookie package authoritative and
provide shared fixtures.

Without the sys.path tweak, `import hookie` would resolve to a pip-installed
copy (or fail), so changes in this checkout would silently not be tested.
Prepending the repo root guarantees the local package wins; adding tests/ makes
the shared `helpers` module importable from every test.
"""
import ctypes
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
for _p in (str(_ROOT), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest

from hookie import HookEngine
from helpers import make_native, free_native


@pytest.fixture
def engine():
    """A HookEngine whose hooks are all torn down after the test."""
    eng = HookEngine()
    try:
        yield eng
    finally:
        eng.destroy_all()


@pytest.fixture
def native():
    """Factory for executable native code that is freed after the test:

        addr, size, call, cfunctype = native(b"\\xB8\\x2A\\x00\\x00\\x00\\xC3")
    """
    created = []

    def _factory(code: bytes, restype=ctypes.c_int, argtypes=()):
        addr, size, call, cfunctype = make_native(code, restype, argtypes)
        created.append((addr, size))
        return addr, size, call, cfunctype

    try:
        yield _factory
    finally:
        for addr, size in created:
            free_native(addr, size)
