# Hookie Architecture

This document describes how Hookie works internally. `README.md` intentionally
stays small; this is the technical reference.

## 1. Mental model

Hookie has two layers:

1. **Hook engine** — patches a native function in the process where Python is
   already running.
2. **Payload bootstrap** — gets Python + Hookie into another process, then runs
   the user's payload entrypoint there.

The hook engine does not know anything about DLL injection. The native bootstrap
does not implement trampoline relocation. They meet only when the bootstrap
executes the packaged Python payload and that code imports `hookie`.

---

## 2. Hook engine

`HookEngine.create_hook()` receives:

- a native target address,
- a Python detour callable,
- the target argument types,
- the target return type,
- optionally a ctypes prototype factory.

Hookie wraps the Python detour with `ctypes`, disassembles whole instructions
from the target prologue, builds a trampoline, and prepares a patch.

The hook starts disabled. `enable()` writes the jump into the target prologue.
`disable()` restores the original bytes.

`hook.original(...)` calls the trampoline, not the patched target entrypoint.

### x64 patch choices

Hookie chooses among:

- a 14-byte absolute indirect jump,
- a 5-byte `rel32` jump when the destination is in range,
- a 5-byte jump to a nearby relay which then performs the absolute jump.

### Relocation

Copied prologue instructions cannot always be copied byte-for-byte. Hookie
relocates:

- relative `call`, `jmp`, and conditional branches,
- branches whose target lies inside the stolen prologue,
- x64 RIP-relative memory operands,
- loop/jcxz-family control flow.

The trampoline ends with a jump back to the first original instruction after the
stolen region.

---

## 3. Memory model

Executable buffers are allocated writable, populated, then changed to executable
permissions. Hookie also supports near/range-constrained allocation where x64
RIP-relative relocation or a `rel32` relay requires it.

Hook installation/removal is not thread-safe: another thread executing the
prologue while its bytes are being replaced can observe a partial patch.

---

## 4. Build identity and directory layout

Every `create-dll` / `create-so` operation generates one random **6-byte id**.
It is rendered as **12 lowercase hex characters**:

```text
6 bytes -> a1b2c3d4e5f6
```

That exact id is the single identity for the build.

Normal/path mode:

```text
deps/
└── a1b2c3d4e5f6/
    ├── Python runtime
    ├── hookie/
    ├── dependencies
    └── hook.py

builds/
└── a1b2c3d4e5f6/
    └── hookie_stub.dll   # or .so
```

Single-file mode extracts to the same relative name:

```text
%TEMP%\a1b2c3d4e5f6\          # Windows
$TMPDIR/a1b2c3d4e5f6/        # Linux
```

The entrypoint filename remains simply:

```text
hook.py
```

There is no separate content id and no `hookie_` prefix on the dependency/temp
directory. `deps/<id>`, `builds/<id>`, and temp extraction all expose the same
build id. The file itself stays `hook.py`; only its in-memory Python module name
uses the id (`hookie_<id>`).

---

## 5. Payload footer

The final DLL/SO carries a 40-byte footer:

```c
struct HookieFooter {
    char     magic[17];
    uint8_t  mode;
    uint8_t  ident_len;
    uint8_t  reserved[5];
    uint64_t raw_size;
    uint64_t data_size;
};
```

`magic` is:

```text
HOOKIE_PAYLOAD_V1
```

There are two modes.

### Path mode

The data before the footer is the absolute path to `deps/<id>`.

```text
[UTF-8 absolute deps path][footer]
```

`ident_len` is zero because the id can be obtained from the basename of the
resolved payload directory.

### Single-file mode

The data is:

```text
[12-byte ASCII id][LZSS-compressed archive][footer]
```

The native bootstrap extracts the archive to the system temporary directory
using exactly that id as the directory name.

---

## 6. Native bootstrap: high-level flow

Windows:

```text
DllMain
  -> create worker thread
  -> resolve payload directory
  -> locate versioned python3XY.dll
  -> reuse matching initialized CPython if present
     OR load bundled python3XY.dll
  -> configure Python paths
  -> execute hook.py as module hookie_<id>
```

Linux:

```text
constructor
  -> create worker thread
  -> resolve payload directory
  -> read bundled libpython/runtime version
  -> reuse matching process CPython when safe
     OR load bundled libpython when no Python is present
  -> configure Python paths
  -> execute hook.py as module hookie_<id>
```

The heavy bootstrap work is deliberately not performed directly under Windows
`DllMain` loader lock.

---

## 7. Single-file extraction

Packaging serializes each payload file as:

```text
uint32 path_length
uint64 file_size
path bytes
file bytes
```

A zero `path_length` terminates the archive.

The archive is compressed with a small LZSS codec and appended to the native
stub. At runtime the stub:

1. reads its own final 40 bytes,
2. validates the footer,
3. reads the id + compressed blob,
4. decompresses it,
5. creates `<temp>/<id>/`,
6. recreates the payload tree there.

The archive extractor rejects absolute/traversal paths.

---

## 8. Python entrypoint execution

The user writes:

```text
hook.py
```

Packaging keeps that filename unchanged. The bootstrap derives the id directly
from the payload directory basename and uses it only for the module name:

```python
_hookie_id = os.path.basename(os.path.normpath(_hookie_dir))
_hookie_name = "hookie_" + _hookie_id
_hookie_file = os.path.join(_hookie_dir, "hook.py")
```

It loads `hook.py` using `importlib.util.spec_from_file_location`, but registers
it in Python under the deterministic module name:

```text
hookie_a1b2c3d4e5f6
```

No path hash or second random identifier is involved.

The module is put in `sys.modules` before execution. This has two useful
properties:

- a second load of the same payload does not blindly execute the same hook setup
  again;
- module globals keep `HookEngine`, `Hook`, and ctypes callback references alive.

The payload top-level is the entrypoint. There is no `install()` callback.

---

## 9. `sys.path` vs `os.add_dll_directory` on Windows

These solve different problems.

### `sys.path`

```python
sys.path.insert(0, payload_dir)
sys.path.insert(0, payload_dir / "Lib" / "site-packages")
```

This tells **Python's importer** where to find Python modules and packages such
as `hookie` and `capstone`.

### `os.add_dll_directory`

```python
handle = os.add_dll_directory(payload_dir)
```

This tells the **Windows native loader** to also search the payload directory
when a `.pyd` or another native component needs dependent DLLs.

Adding a directory to `sys.path` does not change Windows DLL dependency search.
Conversely, `add_dll_directory` does not make Python modules importable.

The returned handle owns that registration. If it is closed or garbage
collected, Windows removes the directory from the DLL search list. Hookie keeps
those handles alive in:

```python
sys._hookie_dll_dirs
```

for the lifetime of the embedded/reused interpreter.

---

## 10. Existing Python runtime policy

Hookie currently avoids subinterpreters.

### Windows

If the payload was built for `python3XY.dll` and that same versioned DLL already
exists and is initialized in the target, Hookie reuses the target main
interpreter and acquires the GIL with `PyGILState_Ensure()`.

If a different Python minor is present but the requested one is not, Hookie may
load its own versioned bundled `python3XY.dll` because Windows symbol lookup is
performed through that explicit module handle.

### Linux

If a matching CPython major/minor is already present, Hookie reuses it.

If a different `libpython` is already mapped, Hookie refuses to load a second
version. ELF symbol interposition makes two independent process-global CPython
runtimes substantially less predictable than the Windows versioned-DLL case.

---

## 11. Bundled runtime lifetime

When Hookie owns a newly initialized runtime, it does not finalize Python after
executing the payload. Native target threads may later enter ctypes callbacks
created by the hooks. Finalizing the interpreter would leave those native jump
targets pointing into a dead Python runtime.

The bootstrap releases the GIL and parks its worker for process lifetime.

---

## 12. Debug mode

Windows `--debug` compiles `HK_DEBUG` traces using `OutputDebugStringW`, visible
in a debugger or DebugView.

Linux `--debug` compiles `HK_DEBUG` traces to stderr.

Debug builds are compiled from source instead of silently reusing release cache
artifacts.

---

## 13. Tests

`examples/` contains user-facing hook payloads.

`tests/` contains regression/native tests. In particular,
`test_stub_runtime_policy` verifies the CPython bootstrap policy rather than
instruction relocation:

- same-version existing Python is reused;
- Linux refuses a mismatched already-loaded Python runtime;
- `hook.py` executes under module name `hookie_<id>`.

x86 native tests require a real 32-bit Python/process and 32-bit toolchain.
