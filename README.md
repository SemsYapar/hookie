# Hookie

Hookie has two useful parts that can be used together **or separately**:

1. **Run Python code inside another process.** `create-dll` / `create-so` package a `hook.py` together with Python and the required dependencies so the native stub can execute that Python code inside the target process. You do not have to hook anything to use Hookie this way.
2. **Hook native functions from Python.** `HookEngine` lets Python detours hook x86/x64 native functions while keeping the original function callable through a trampoline.

Put the two together and you can inject Python into a target process and install native hooks there using Python.

Windows and Linux are supported; x86 and x64 are supported.

## Install

```bash
pip install hookie
```

## Hook a function in the current process

```python
from hookie import HookEngine

engine = HookEngine()
hook = engine.create_hook(target_addr, detour, argtypes, restype)
hook.enable()

# From the detour:
# hook.original(...)

# Many hooks at once, installed/removed under a single thread suspension:
# engine.enable_all()
# engine.disable_all()
```

## Resolving targets

You need an address before you can hook. `hookie.resolve` and `hookie.mem` wrap
that up cross-platform (Windows and Linux), in the current process:

```python
from hookie import resolve, mem

addr = resolve.export("user32.dll", "MessageBoxW")   # exported symbol by name
base = resolve.module_base("game.exe")               # module base; + offset to reach internals
addr = resolve.scan("48 8B 05 ?? ?? ?? ?? 48 85 C0", "game.exe")  # a function with no name
addr = resolve.rip_target(addr)                      # follow a call/reference to the real function

data = mem.read_bytes(addr, 16)                      # read
mem.write_bytes(addr, b"\x90\x90", protect=True)     # write (flips page protection for code)
```

No magic — most of these are thin conveniences over what ctypes already does, and
each docstring says exactly what runs underneath:

| Helper | Under the hood | What hookie adds |
|---|---|---|
| `resolve.module_base` | GetModuleHandleW / `/proc/self/maps` | one call, both OSes |
| `resolve.export` | GetProcAddress / dlsym | one call, both OSes |
| `resolve.modules` | Toolhelp / `/proc/self/maps` | one call, both OSes |
| `resolve.scan` | — (no ctypes equivalent) | AOB search with wildcards |
| `resolve.rip_target` | — (needs disassembly) | resolves a reference to its target |
| `mem.read_bytes` / `read_ptr` | `ctypes.string_at` / `from_address` | `protect=True` checks/ensures access so a bad address raises, not crashes |
| `mem.write_bytes` | `ctypes.memmove` (+ protect flip) | `protect=True` makes a read-only code page writable, then restores |
| `mem.read_chain` | repeated `read_ptr` | one call for a pointer path |

All of `mem` takes one `protect` flag with the same meaning: `True` (default)
checks the page and flips its protection only if the operation needs it, then
restores; `False` does the raw operation with no check (fastest, for a page you
know already allows it).

## Run Python inside another process

Write normal top-level Python code in `hook.py`. It may install hooks, inspect the process, log information, or do any other authorized Python-side work.

Windows:

```bash
hookie create-dll hook.py --arch x64
hookie inject-dll target.exe builds/<id>/hookie_stub.dll
```

Linux:

```bash
hookie create-so hook.py --arch x64
```

Optional build modes:

```bash
--single-file
--debug
```

By default (without `--single-file`), the stub keeps its dependencies next to
it on disk, under `deps/<id>/`, and needs that directory to be present at the
absolute path it was built at in order to run. If you want to hand the built
DLL/SO to someone else, or run it from a different location, build with
`--single-file`: the payload is embedded in the stub itself and extracted to a
temp directory at runtime, so no external `deps/` folder is needed.

## Notepad hooking example

The `examples/windows/notepad_hook/` example hooks Notepad's memory-mapped file read path. Notepad reads the file through `CreateFileMappingW` and `MapViewOfFile`, so the example hooks these APIs, creates a copy-on-write mapping/view, and modifies the mapped data without changing the original file.

Build the payload DLL:

```powershell
hookie create-dll .\examples\windows\notepad_hook\
```

The command prints the generated DLL path, for example:

```text
Done -> C:\Users\sems\Desktop\codepy\hookie\builds\d977ac6719a5\hookie_stub.dll
```

Then inject it into Notepad:

```powershell
hookie inject-dll notepad.exe .\builds\d977ac6719a5\hookie_stub.dll
```

See `examples/` for examples. See `ARCHITECTURE.md` for the trampoline, payload, stub, CPython bootstrap, and runtime-reuse internals.

## Debugging and reporting issues

hookie writes a log that covers both the native stub bootstrap and the
Python-side hook install — exactly the context needed to diagnose a crash. Call
`hookie.log_to_file()` before installing hooks for the install log, and build an
injected payload with `--debug` for the stub trace. Both default to
`%TEMP%\hookie.log` (Windows) / `$TMPDIR/hookie.log` (Linux) and honour the
`HOOKIE_LOG` environment variable, so pointing it at one path gives a single
combined log. When filing an issue, attach that log — the bug-report form asks
for it.

## Current limitations

- Installing/removing inline hooks is thread-safe on Windows (x64/x86): other threads are suspended and, if needed, relocated onto the trampoline while the prologue is patched. On Linux, the entry race is handled by an atomic patch write, but a thread already executing inside the prologue is not covered yet, so install hooks at a quiet point (e.g. at startup). See `ARCHITECTURE.md` for details.
- In an existing Python process, Windows reuses the same CPython minor version and can use Hookie's bundled runtime when a different minor is present.
- On Linux, Hookie reuses the same CPython major/minor. If a different `libpython` is already mapped, Hookie refuses to load a second Python runtime.

Both x86 and x64 are fully supported; a 32-bit process simply needs a 32-bit
Python. The **Windows** stubs ship prebuilt in the wheel, so `create-dll` needs
no C compiler (a compiler is only needed for `--debug` or `--stub-src`). The
**Linux** stub compiles on your machine with one `gcc` call — a prebuilt `.so`
would be tied to a specific glibc, so it is built on the host instead. MIT
licensed.
