# Tests

`tests/` contains regression tests. `examples/` is reserved for user-facing
examples and is not used as a test suite.

The runners do not depend on the shell's current working directory. They add
the source checkout root to child-process `PYTHONPATH`, so tests import the
`hookie/` package from the checkout being tested. Individual packaging/stub
policy helpers use the fixed repository layout directly.

Install the project first when running the full native suites:

```bash
pip install -e .
```

Linux:

```bash
python tests/run_linux.py
```

Windows:

```powershell
python tests\run_windows.py
```

The runner keeps each native test in its own process. Individual tests can still
be run directly while debugging.

`test_stub_runtime_policy.py` tests the native bootstrap/runtime-selection policy,
not trampoline relocation. On Windows it loads the test DLL in a child Python
process so the DLL is released when the child exits before the parent removes the
temporary directory.

## x86 means a real 32-bit process

The x86 hook engine must be tested from a real 32-bit Python process. A 64-bit
Python process cannot execute 32-bit machine code simply by passing
`HookEngine(bits=32)`.

On 64-bit Linux, building the x86 native stub additionally requires the host's
32-bit multilib libc development files (`gcc -m32` must work). Run the same
Linux suite under a 32-bit Python to cover x86 end-to-end.

The native relocation tests intentionally execute generated machine code and
should be run in disposable development/test processes.

Platform-specific packaging semantics live under `tests/linux/` or `tests/windows/`; the shared `tests/test_packaging.py` contains only cross-platform tests.
