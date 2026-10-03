# Examples

`examples/` contains user-facing payloads. The entrypoint is always `hook.py`,
and it stays named `hook.py` inside the built payload. The native stub loads it
under the in-memory module name `hookie_<build-id>`. Its module top-level runs
once and installs the hooks; there is no separate `install()` callback.

Keep the `HookEngine`, `Hook`, and Python detour objects alive at module scope for
as long as native code can enter the hook.

## Windows

- `windows/messagebox_payload/hook.py` — rewrites `MessageBoxW` text/caption.
- `windows/beep_payload/hook.py` — rewrites `kernel32!Beep` arguments and shows
  the x86 `WINFUNCTYPE` / x64 calling-convention pattern.

Build one with:

```powershell
hookie create-dll examples\windows\messagebox_payload --arch x64
```

## Linux

- `linux/puts_payload/hook.py` — prefixes strings sent to `libc!puts`.
- `linux/getpid_payload/hook.py` — demonstrates return-value rewriting by
  changing the observed result of `getpid()`.

Build one with:

```bash
hookie create-so examples/linux/puts_payload --arch x64
```

These examples deliberately modify process behavior. Use disposable test
programs while experimenting.
