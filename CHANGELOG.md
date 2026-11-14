# Changelog

All notable changes to Hookie are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-11-15

A maintenance release: it moves the payload launch logic out of the native stubs
into a single Python file (no user-facing API change) and hardens the
thread-suspension path and the Windows test suite.

### Changed

- **Payload bootstrap extracted to `hookie/bootstrap.py`.** The sys.path setup and
  payload import are now one readable, cross-platform Python file shipped into the
  payload, instead of a C string duplicated across the four native stubs. One file
  serves x86/x64 and Windows/Linux (it branches on `os.name` and reads the version
  from `sys.version_info`). The stub reads it natively — so no `FILE*` crosses the
  CRT boundary into libpython, a real hazard when the stub and the target
  `python3XX.dll` were built by different compilers — compiles it with
  `Py_CompileStringExFlags` under the filename `hookie_bootstrap.py` (clean
  tracebacks), and runs it with `PyEval_EvalCode` in a **fresh** globals dict
  holding only an injected `_hookie_dir`, so its temporaries no longer leak into
  the target process's `__main__`.

### Fixed

- **GIL deadlock while suspending threads.** The suspend/context WinAPI calls now
  run through a stdcall DLL that keeps the GIL held for the call
  (`_FUNCFLAG_PYTHONAPI`). Previously the GIL was released during `SuspendThread`,
  so the thread being suspended could grab the GIL, run Python, and be frozen
  while holding it — deadlocking the suspender when it tried to reacquire. This
  only surfaced under heavy contention (many threads calling the target while
  hooks were installed/removed in a tight loop).
- **Windows-only test corrections.** These tests never ran on the Linux
  development machine, so three latent issues are fixed: `test_struct_layout` now
  asserts `MEMORY_BASIC_INFORMATION` field offsets rather than a wrong total size;
  `test_winapi` captures the pid before hooking, since on Windows `os.getpid()` is
  itself `GetCurrentProcessId` and is intercepted once the hook is live; and the
  native stub-build tests skip (instead of failing) when no C compiler is on PATH.

## [0.2.0] - 2026-11-14

This release makes installing and removing hooks safe while other threads are
running, on both architectures on Windows, and closes the entry race on Linux.
It also replaces the ad-hoc test scripts with a single cross-platform pytest
suite.

### Added

- **Thread-safe hook install/remove on Windows (x64 and x86).** `enable()` /
  `disable()` now suspend every other thread, relocate any thread parked in the
  stolen prologue (by instruction pointer, or by stack return address when the
  stolen bytes contain a `call`) onto the trampoline, write the patch, and
  resume. This closes both the entry race and the in-progress race. See
  `hookie/threads.py`.
- **Atomic prologue write (all platforms).** When the jump fits one
  naturally-aligned 8-byte window, the first qword is stored atomically via
  `MemoryManager.write_qword_atomic`. On Linux, where in-process thread
  suspension is not yet available, this alone closes the entry race — a thread
  sees either the whole old prologue or the whole new jump, never a mix.
- **Batched `enable_all()` / `disable_all()`.** All hooks are now installed or
  removed under a *single* process-wide suspension instead of one suspend/resume
  cycle per hook. This is faster and safer: threads never run free between two
  writes, so a half-installed set of hooks cannot be observed. New
  `modify_threads_batch` driver in `hookie/threads.py`.
- **Install logging.** `hookie.log_to_file()` records, per hook, the patch
  strategy (`rel32` / `rel32+relay` / `abs14`), stolen size, whether the write
  was atomic, whether the stolen region contains a call, and the thread policy
  in effect. The debug stub (`--debug`) appends its bootstrap trace to the same
  file, so one log can hold both the native Python-startup steps and the
  Python-side hook-install choices. Each stub also writes an architecture banner
  (`x64-windows`, `x86-linux`, …) so a crash log is unambiguous about which
  stub ran.

### Changed

- **`rel32`-first patch strategy.** Hookie now prefers the 5-byte `rel32` jump,
  then a `rel32` jump to a nearby relay, and only falls back to the 14-byte
  absolute indirect jump when neither fits. The `rel32` form steals fewer
  prologue bytes and fits the atomic 8-byte window; the 14-byte form cannot be
  written atomically, so it is a last resort.
- **Windows micro-version requirement is now an explicit error.** Packaging a
  Windows payload requires a full `X.Y.Z` Python version; a bare `X.Y` is
  rejected with a clear message instead of silently selecting a runtime.
- **Tests rebuilt as a pytest suite.** The old `tests/linux` / `tests/windows`
  split, `_common.py`, and the hand-rolled runners are gone. Tests now live flat
  under `tests/`, share `engine` / `native` fixtures via a root `conftest.py`,
  and gate OS-specific cases with `@pytest.mark.skipif`. Run with `pytest`.
- Package maturity raised from Alpha to Beta.

### Fixed

- **x86 `MEMORY_BASIC_INFORMATION` layout.** `PartitionId` exists only in the
  64-bit layout; including it on 32-bit shifted every field by four bytes, so
  `VirtualQuery` misreported page state and protection and made valid target
  addresses look unreadable. The field is now 64-bit only.
- **x64 handle truncation in the `terminateprocess` example.** `OpenProcess` /
  `GetModuleBaseNameW` were missing `argtypes` / `restype`, truncating 64-bit
  handles to 32-bit ints.

### Known limitations

- On Linux the in-progress race (a thread already executing inside the stolen
  prologue) is **not** covered yet — only the entry race is, via the atomic
  write. Install hooks at a quiescent point (e.g. at startup). A signal-based
  thread quiesce is the planned Linux backend.

## [0.1.0]

Initial release: Python-native inline hooking with trampolines for x86/x64 on
Windows and Linux, plus `create-dll` / `create-so` payload packaging and
process injection.

[0.2.1]: https://github.com/SemsYapar/hookie/releases/tag/v0.2.1
[0.2.0]: https://github.com/SemsYapar/hookie/releases/tag/v0.2.0
[0.1.0]: https://github.com/SemsYapar/hookie/releases/tag/v0.1.0
