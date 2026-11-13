# Examples

`examples/` contains user-facing payloads. The entrypoint is always `hook.py`,
and it stays named `hook.py` inside the built payload. The native stub loads it
under the in-memory module name `hookie_<build-id>`. Its module top-level runs
once and installs the hooks; there is no separate `install()` callback.

Keep the `HookEngine`, `Hook`, and Python detour objects alive at module scope for
as long as native code can enter the hook.

## Windows

- `windows/messagebox_hook/hook.py` — rewrites `MessageBoxW` text/caption.
- `windows/beep_hook/hook.py` — rewrites `kernel32!Beep` arguments and shows
  the x86 `WINFUNCTYPE` / x64 calling-convention pattern.
- `windows/notepad_hook/hook.py` — hooks `CreateFileMappingW`/`MapViewOfFile`
  to modify Notepad's view of a file without touching the file on disk. See
  the main `README.md` for the full walkthrough.
- `windows/readfile_hook/hook.py` — hooks `kernelbase!ReadFile`; the first
  read returns injected text, every later read reports zero bytes (simulated
  EOF).
- `windows/terminateprocess_hook/hook.py` — hooks `kernelbase!TerminateProcess`
  and blocks it for a named process (`chrome.exe` in the example) by returning
  success without calling the original.
- `windows/hideprocess_hook/hook.py` — hooks `ntdll!NtQuerySystemInformation`,
  lets the original call fill the real process list, then unlinks a matching
  entry from the returned `SYSTEM_PROCESS_INFORMATION` chain before returning
  it to the caller.

Build one with:

```powershell
hookie create-dll examples\windows\messagebox_hook --arch x64
```

## Linux

- `linux/puts_hook/hook.py` — prefixes strings sent to `libc!puts`.
- `linux/getpid_hook/hook.py` — demonstrates return-value rewriting by
  changing the observed result of `getpid()`.

Build one with:

```bash
hookie create-so examples/linux/puts_hook --arch x64
```

These examples deliberately modify process behavior. Use disposable test
programs while experimenting.