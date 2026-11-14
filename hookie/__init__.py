__version__ = "0.2.1"

import logging as _logging

from .core import Hook, HookEngine, logger
from .memory import MemoryManager
from .trampoline import TrampolineBuilder
from .disassembler import Disassembler
from .arch.x64 import x64Arch
from .arch.x86 import x86Arch


def log_to_file(path: str | None = None, *, level: int = _logging.INFO,
                mode: str = "a") -> _logging.Handler:
    """Send hookie's hook-installation log to *path*.

    Each hook records the patch strategy (rel32 / rel32+relay / abs14), stolen
    size, whether the write was atomic, whether the stolen region has a call,
    and the thread policy in effect. If a hook later crashes the process, this
    file shows how it was installed. Returns the handler so it can be removed.

    When *path* is None, the file is taken from the HOOKIE_LOG environment
    variable, falling back to <temp>/hookie.log. This is the same file the debug
    stub (`--debug`) appends its bootstrap trace to, so a single log can hold
    both the stub's Python-startup steps and hookie's hook-install choices.
    """
    if path is None:
        import os
        import tempfile
        path = os.environ.get("HOOKIE_LOG") or os.path.join(
            tempfile.gettempdir(), "hookie.log")
    handler = _logging.FileHandler(path, mode=mode, encoding="utf-8")
    handler.setFormatter(_logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    handler.setLevel(level)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.info("hookie %s logging started", __version__)
    return handler


__all__ = [
    "__version__",
    "Hook",
    "HookEngine",
    "MemoryManager",
    "TrampolineBuilder",
    "Disassembler",
    "x64Arch",
    "x86Arch",
    "log_to_file",
    "logger",
]
