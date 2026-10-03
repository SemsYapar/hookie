"""Run the Windows regression suite in isolated subprocesses."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TESTS = [
    HERE / "test_packaging.py",
    HERE / "windows" / "test_stub_runtime_policy.py",
    HERE / "windows" / "test_lifecycle.py",
    HERE / "windows" / "test_direct_destroy.py",
    HERE / "windows" / "test_winapi_basic.py",
    HERE / "windows" / "test_winapi_original.py",
    HERE / "windows" / "test_native_relative.py",
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
    print("\nPASS Windows suite")


if __name__ == "__main__":
    main()
