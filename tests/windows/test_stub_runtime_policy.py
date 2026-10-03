"""Windows native-stub same-version interpreter reuse smoke test.

The parent process builds the test DLL and payload.  A child Python process of
that same bitness/version loads the DLL, proves that the stub reuses the already
initialized target interpreter, then exits.  Only after the child exits does the
parent remove the temporary directory, so Windows never has to delete a loaded
DLL.
"""
from __future__ import annotations

import ctypes
import importlib.util
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _load_packaging():
    # This test lives at tests/windows/test_stub_runtime_policy.py.
    # We intentionally load packaging.py directly so the runtime-policy test
    # does not pull in hookie.core/Capstone just to compile and decorate a stub.
    package_dir = Path(__file__).resolve().parents[2] / "hookie"
    path = package_dir / "packaging.py"
    module_spec = importlib.util.spec_from_file_location(
        "hookie_packaging_win_stub_policy_test", path
    )
    module = importlib.util.module_from_spec(module_spec)
    assert module_spec.loader is not None
    module_spec.loader.exec_module(module)
    return module, package_dir


packaging, HOOKIE_PACKAGE_DIR = _load_packaging()
BITS = ctypes.sizeof(ctypes.c_void_p) * 8
ARCH = "x64" if BITS == 64 else "x86"


def _wait(path: Path, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.02)
    return path.exists()


def _child(stub: Path, marker: Path, expected_module: str) -> None:
    # Keep the library object alive until process exit.  Windows keeps loaded DLL
    # files locked; the parent process owns cleanup after this child terminates.
    library = ctypes.WinDLL(str(stub))
    assert library._handle
    assert _wait(marker), "same-version target Python was not reused"
    module_name = marker.read_text(encoding="utf-8")
    assert module_name == expected_module, module_name


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("Windows only")

    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        _child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
        return

    major, minor = sys.version_info[:2]
    pybase = f"python{major}{minor}.dll"
    payload_id = "333333333333"
    expected_module = f"hookie_{payload_id}"

    with tempfile.TemporaryDirectory(prefix="hookie-win-stub-policy-") as td:
        base = Path(td)
        payload = base / payload_id
        payload.mkdir()

        # find_python_dll() only needs the versioned filename to learn which
        # CPython minor the payload expects.  The child process already has the
        # real same-version pythonXY.dll loaded, so this empty file is never
        # LoadLibrary'd.
        (payload / pybase).write_bytes(b"")

        marker = base / "same-ran.txt"
        (payload / "hook.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text(__name__, encoding='utf-8')\n",
            encoding="utf-8",
        )

        src = HOOKIE_PACKAGE_DIR / "stubs" / f"{ARCH}-windows" / "hookie_stub.c"
        stub = base / "hookie_stub.dll"
        packaging._compile_windows_stub(stub, ARCH, src, debug=True)
        packaging._append_resource(stub, payload, False)

        # Test inside another Python process.  When it exits Windows releases
        # hookie_stub.dll, then this parent can safely delete the temp tree.
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child",
                str(stub),
                str(marker),
                expected_module,
            ],
            check=True,
        )

    print(f"PASS windows_stub_runtime_policy ({BITS}-bit, CPython {major}.{minor})")


if __name__ == "__main__":
    main()
