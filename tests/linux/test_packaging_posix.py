"""Linux/POSIX-specific packaging regression tests."""
from __future__ import annotations

import importlib.util
import io
import os
import tarfile
import tempfile
from pathlib import Path


def _load_packaging():
    package_dir = Path(__file__).resolve().parents[2] / "hookie"
    packaging_path = package_dir / "packaging.py"
    spec = importlib.util.spec_from_file_location("hookie_packaging_posix_test", packaging_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


packaging = _load_packaging()


def _write_tar(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        directory = tarfile.TarInfo("python/bin")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        tf.addfile(directory)

        data = b"#!/bin/sh\n"
        python = tarfile.TarInfo("python/bin/python")
        python.size = len(data)
        python.mode = 0o755
        tf.addfile(python, io.BytesIO(data))

        link = tarfile.TarInfo("python/bin/python3")
        link.type = tarfile.SYMTYPE
        link.linkname = "python"
        tf.addfile(link)


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        archive = base / "ok.tar.gz"
        out = base / "extract"
        _write_tar(archive)
        packaging._safe_extract_tar(archive, out)
        assert (out / "python/bin/python").is_file()
        assert os.access(out / "python/bin/python", os.X_OK)
        assert (out / "python/bin/python3").is_symlink()
        assert os.readlink(out / "python/bin/python3") == "python"
    print("PASS linux_packaging_posix")


if __name__ == "__main__":
    main()
