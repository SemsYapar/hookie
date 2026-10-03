"""Linux native-stub runtime policy without requiring Capstone.

This test loads the compiled Hookie stub into the *current* Python process.
It proves that a same-major.minor target interpreter is reused and that a
mismatched payload runtime is refused instead of loading a second libpython.
"""
from __future__ import annotations

import ctypes
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _load_packaging():
    # tests/linux/test_stub_runtime_policy.py -> repo root is parents[2].
    # Load packaging.py directly so the policy test stays independent of
    # hookie.core/Capstone.
    package_dir = Path(__file__).resolve().parents[2] / "hookie"
    path = package_dir / "packaging.py"
    module_spec = importlib.util.spec_from_file_location(
        "hookie_packaging_stub_policy_test", path
    )
    module = importlib.util.module_from_spec(module_spec)
    assert module_spec.loader is not None
    module_spec.loader.exec_module(module)
    return module, package_dir


packaging, HOOKIE_PACKAGE_DIR = _load_packaging()
BITS = ctypes.sizeof(ctypes.c_void_p) * 8


def _compile_stub(out: Path) -> None:
    arch = "x64" if BITS == 64 else "x86"
    src = HOOKIE_PACKAGE_DIR / "stubs" / f"{arch}-linux" / "hookie_stub.c"
    gcc = shutil.which("gcc")
    if not gcc:
        raise RuntimeError("gcc is required for this test")
    subprocess.run(
        [gcc, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra",
         "-o", str(out), str(src), "-ldl", "-pthread"],
        check=True,
    )


def _load_with_payload(stub: Path, payload: Path) -> None:
    packaging._append_resource(stub, payload, False)
    ctypes.CDLL(str(stub))


def _wait(path: Path, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.02)
    return path.exists()


def main() -> None:
    if not sys.platform.startswith("linux"):
        raise SystemExit("Linux only")

    major, minor = sys.version_info[:2]
    same = f"{major}.{minor}"
    other_minor = minor + 1 if minor < 99 else minor - 1
    different = f"{major}.{other_minor}"

    with tempfile.TemporaryDirectory(prefix="hookie-stub-policy-") as td:
        base = Path(td)
        compiled = base / "compiled.so"
        _compile_stub(compiled)

        same_payload = base / "111111111111"
        (same_payload / "lib").mkdir(parents=True)
        (same_payload / ".hookie-libpython").write_text(
            f"lib/libpython{same}.so\n", encoding="utf-8"
        )
        same_marker = base / "same-ran.txt"
        (same_payload / "hook.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(same_marker)!r}).write_text(__name__, encoding='utf-8')\n",
            encoding="utf-8",
        )
        same_stub = base / "same.so"
        shutil.copy2(compiled, same_stub)
        _load_with_payload(same_stub, same_payload)
        assert _wait(same_marker), "same-version existing Python was not reused"
        module_name = same_marker.read_text(encoding="utf-8")
        assert module_name == "hookie_111111111111", module_name

        # The same build id must survive single-file packing/extraction: the
        # temp directory and in-memory Python module both use the deps/build id.
        single_payload = base / "444444444444"
        (single_payload / "lib").mkdir(parents=True)
        (single_payload / ".hookie-libpython").write_text(
            f"lib/libpython{same}.so\n", encoding="utf-8"
        )
        single_marker = base / "single-ran.txt"
        (single_payload / "hook.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(single_marker)!r}).write_text(__name__ + '|' + __file__, encoding='utf-8')\n",
            encoding="utf-8",
        )
        single_stub = base / "single.so"
        shutil.copy2(compiled, single_stub)
        extracted = Path("/tmp") / single_payload.name
        shutil.rmtree(extracted, ignore_errors=True)
        packaging._append_resource(single_stub, single_payload, True)
        ctypes.CDLL(str(single_stub))
        assert _wait(single_marker), "single-file payload was not extracted/executed"
        single_module, single_file = single_marker.read_text(encoding="utf-8").split("|", 1)
        assert single_module == "hookie_444444444444", single_module
        assert Path(single_file).parent == extracted, single_file
        assert Path(single_file).name == "hook.py", single_file
        shutil.rmtree(extracted, ignore_errors=True)

        different_payload = base / "222222222222"
        (different_payload / "lib").mkdir(parents=True)
        (different_payload / ".hookie-libpython").write_text(
            f"lib/libpython{different}.so\n", encoding="utf-8"
        )
        different_marker = base / "different-ran.txt"
        (different_payload / "hook.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(different_marker)!r}).write_text('BAD', encoding='utf-8')\n",
            encoding="utf-8",
        )
        different_stub = base / "different.so"
        shutil.copy2(compiled, different_stub)
        _load_with_payload(different_stub, different_payload)
        time.sleep(0.25)
        assert not different_marker.exists(), "different libpython version was not refused"

    print(f"PASS stub_runtime_policy ({BITS}-bit, CPython {same})")


if __name__ == "__main__":
    main()
