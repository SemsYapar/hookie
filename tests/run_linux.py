"""Run the Linux regression suite in isolated subprocesses."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TESTS = [
    HERE / "test_packaging.py",
    HERE / "linux" / "test_packaging_posix.py",
    HERE / "linux" / "test_stub_runtime_policy.py",
    HERE / "linux" / "test_lifecycle.py",
    HERE / "linux" / "test_transaction.py",
    HERE / "linux" / "test_safety.py",
    HERE / "linux" / "test_native_basic.py",
    HERE / "linux" / "test_native_original.py",
    HERE / "linux" / "test_native_relative.py",
    HERE / "linux" / "test_relocation_matrix.py",
    HERE / "linux" / "test_loop_reloc.py",
]


def _child_env() -> dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(ROOT) if not current else str(ROOT) + os.pathsep + current
    return env


def main() -> None:
    env = _child_env()
    for test in TESTS:
        print(f"\n=== {test.name} ===", flush=True)
        subprocess.run([sys.executable, str(test)], check=True, env=env)
    print("\nPASS Linux suite")


if __name__ == "__main__":
    main()
