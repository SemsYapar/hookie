# Tests

Pytest suite for the hook engine. `examples/` is for user-facing examples and is
not a test suite.

## Running

No installation of hookie is required — the repo-root `conftest.py` puts the
in-tree package on `sys.path`, so the tests always exercise this checkout, not a
pip-installed copy. You only need pytest:

```bash
pip install pytest
pytest                      # whole suite
pytest -v                   # list every test
pytest tests/test_relocation.py          # one file
pytest -k "atomic or relocate"           # filter by name
```

On Windows, run it under **both** a 32-bit and a 64-bit Python to cover x86 and
x64 — the engine, CONTEXT, and MEMORY_BASIC_INFORMATION all differ by pointer
size:

```powershell
py -3-64 -m pytest
py -3-32 -m pytest
```

## Layout

Tests live flat under `tests/`. The hook engine is platform-agnostic, so the
mechanical tests run on both OSes from one file each; only the truly OS-specific
ones are gated with `@pytest.mark.skipif`. Skipped tests print their reason under
`pytest -rs`.

Shared pieces:

- `conftest.py` (repo root) — `sys.path` setup and the `engine` / `native`
  fixtures. `native(code)` allocates executable memory and frees it after the
  test; `engine` tears down all hooks.
- `helpers.py` — `make_native`, `BITS`, `IS_WINDOWS`, `IS_LINUX`.

## What the suite covers

Cross-platform (run on Windows and Linux):

- `test_lifecycle.py` — enable/disable round-trip, idempotence, direct destroy.
- `test_native_calls.py` — basic detour, `original()` via the trampoline, and a
  RIP-relative / rel32 prologue that must be relocated correctly.
- `test_relocation.py` — x64 relocation matrix (call/jmp/jcc rel8+rel32,
  RIP-relative lea/mov) and the LOOP rel8 bridge. Skipped off x64.
- `test_safety.py` — prologue read clamped at a page boundary; overlapping hooks
  rejected.
- `test_transaction.py` — rollback on a failed patch, non-fatal protection-restore
  failure, and fail-closed destroy when the prologue state is uncertain.
- `test_patch_strategy.py` — rel32 is preferred over the 14-byte absolute jump,
  so the write stays atomically small.
- `test_atomic_write.py` — the atomic 8-byte store and that a rel32 enable uses
  it (closes the entry race on Linux, where there is no thread suspension).
- `test_batch_enable.py` — `enable_all` / `disable_all` round-trip, and the
  contract that the whole group funnels through one `modify_threads_batch` call
  (a single suspend/resume) instead of one per hook.
- `test_mem.py` — `hookie.mem` read/write/chain against allocated buffers, and
  that `write_bytes(protect=True)` can overwrite a read-only page.
- `test_resolve.py` — `hookie.resolve` module_base/export/modules/scan against a
  system module (libc on Linux, kernel32 on Windows), plus `rip_target` against
  assembled call/lea bytes.
- `test_relocate_stolen.py` — stolen-region addresses map to their trampoline
  copies (used when relocating a suspended thread).
- `test_packaging.py` — payload identity, safe-tar extraction, version guards.

Windows-only (skipped on Linux):

- `test_thread_safety.py` — thread suspension + context read, and concurrent
  enable/disable under suspension without a crash.
- `test_struct_layout.py` — CONTEXT and MEMORY_BASIC_INFORMATION sizes/offsets
  per bitness (regression guard for the x86 MBI layout).
- `test_winapi.py` — hooking a real API (`kernel32!GetCurrentProcessId`).

Native-stub bootstrap policy is split by OS because the bootstrap differs:
`test_stub_policy_linux.py` (skipped off Linux) and
`test_stub_policy_windows.py` (skipped off Windows).

## Notes

- The x86 engine must run under a real 32-bit Python process; `HookEngine(bits=32)`
  from a 64-bit process cannot execute 32-bit machine code. Building the x86
  native stub on 64-bit Linux also needs 32-bit multilib (`gcc -m32`).
- Tests that depend on pointer size read `ctypes.sizeof(c_void_p)` and assert the
  matching expected values, so there are no separate x86/x64 files — run each
  suite under both Pythons.
- The relocation and native-call tests execute generated machine code; run them
  in disposable development/test processes.
