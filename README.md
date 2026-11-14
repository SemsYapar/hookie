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

## Current limitations

- Installing/removing inline hooks is thread-safe on Windows (x64/x86): other threads are suspended and, if needed, relocated onto the trampoline while the prologue is patched. On Linux, the entry race is handled by an atomic patch write, but a thread already executing inside the prologue is not covered yet, so install hooks at a quiet point (e.g. at startup). See `ARCHITECTURE.md` for details.
- In an existing Python process, Windows reuses the same CPython minor version and can use Hookie's bundled runtime when a different minor is present.
- On Linux, Hookie reuses the same CPython major/minor. If a different `libpython` is already mapped, Hookie refuses to load a second Python runtime.

Both x86 and x64 are fully supported; a 32-bit process simply needs a 32-bit
Python, and the native stubs ship prebuilt (a C toolchain is only needed to
rebuild a stub from source). MIT licensed.