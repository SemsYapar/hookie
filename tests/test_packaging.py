import importlib.util
import io
import os
import struct
import tarfile
import tempfile
from pathlib import Path
from unittest import mock


def _load_packaging():
    # tests/test_packaging.py -> repo root is one parent up.  Load packaging.py
    # directly so this test does not import hookie.core/Capstone.
    package_dir = Path(__file__).resolve().parents[1] / "hookie"
    packaging_path = package_dir / "packaging.py"
    module_spec = importlib.util.spec_from_file_location(
        "hookie_packaging_test", packaging_path
    )
    module = importlib.util.module_from_spec(module_spec)
    assert module_spec.loader is not None
    module_spec.loader.exec_module(module)
    return module


packaging = _load_packaging()


def test_payload_id_checks_deps_and_builds():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        deps = base / "deps"
        builds = base / "builds"
        builds.mkdir()
        (builds / "abc123abc123").mkdir()
        with mock.patch.object(packaging.secrets, "token_hex", side_effect=["abc123abc123", "def456def456"]):
            payload = packaging._new_payload_dir(deps, builds)
        assert payload.name == "def456def456"
        assert len(payload.name) == 12
        assert payload.is_dir()


def _write_tar(path: Path, members):
    with tarfile.open(path, "w:gz") as tf:
        for kind, name, value in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                data = value
                ti.size = len(data)
                ti.mode = 0o755 if name.endswith("python") else 0o644
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = value
                tf.addfile(ti)
            elif kind == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = value
                tf.addfile(ti)
            else:
                raise AssertionError(kind)


def test_safe_tar_blocks_symlink_escape():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        archive = base / "evil.tar.gz"
        out = base / "extract"
        _write_tar(archive, [
            ("symlink", "link", "../outside"),
            ("file", "link/pwn.txt", b"owned"),
        ])
        try:
            packaging._safe_extract_tar(archive, out)
        except ValueError:
            pass
        else:
            raise AssertionError("symlink traversal archive was accepted")
        assert not (base / "outside" / "pwn.txt").exists()


def test_single_file_uses_build_identity():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        payload = base / "abc123def456"
        payload.mkdir()
        (payload / "hook.py").write_text("x = 1\n", encoding="utf-8")
        stub = payload / "hookie_stub.so"
        stub.write_bytes(b"STUB")
        raw = packaging._archive_payload(payload, stub)
        expected = payload.name.encode("ascii")
        packaging._append_resource(stub, payload, True)
        data = stub.read_bytes()
        footer = data[-packaging._RESOURCE_FOOTER.size:]
        magic, mode, ident_len, raw_size, data_size = packaging._RESOURCE_FOOTER.unpack(footer)
        blob = data[-packaging._RESOURCE_FOOTER.size - data_size:-packaging._RESOURCE_FOOTER.size]
        assert magic == packaging._RESOURCE_MAGIC
        assert mode == packaging._RESOURCE_PACKED
        assert ident_len == 12
        assert blob[:ident_len] == expected
        assert raw_size == len(raw)


def test_place_scripts_keeps_hook_filename():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        src = base / "src"
        out = base / "payload"
        src.mkdir(); out.mkdir()
        (src / "hook.py").write_text("value = 1\n", encoding="utf-8")
        (src / "helper.py").write_text("value = 2\n", encoding="utf-8")
        entry = packaging.place_scripts(src / "hook.py", out)
        assert entry.name == "hook.py"
        assert entry.is_file()
        assert (out / "hook.py").is_file()
        assert (out / "helper.py").is_file()


def test_python_version_guards():
    packaging._validate_payload_python("3.10.0")
    packaging._validate_payload_python("3.14.7", linux=True)
    for version in ("3.9.18", "2.7.18"):
        try:
            packaging._validate_payload_python(version)
        except ValueError:
            pass
        else:
            raise AssertionError(f"old Python accepted: {version}")
    try:
        packaging._validate_payload_python("3.15.0", linux=True)
    except ValueError:
        pass
    else:
        raise AssertionError("Linux CPython 3.15 unexpectedly accepted")


def test_copy_hookie_includes_mit_notice():
    with tempfile.TemporaryDirectory() as td:
        site = Path(td) / "site-packages"
        site.mkdir()
        packaging.copy_hookie(site)
        copied = site / "hookie" / "LICENSE"
        assert copied.is_file()
        text = copied.read_text(encoding="utf-8")
        assert text.startswith("MIT License")
        assert "Copyright (c) 2026 Sems" in text


def test_safe_tar_preserves_internal_hardlink():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        archive = base / "hardlink.tar.gz"
        out = base / "extract"
        _write_tar(archive, [
            ("file", "python/lib/original.txt", b"data"),
            ("hardlink", "python/lib/copy.txt", "python/lib/original.txt"),
        ])
        packaging._safe_extract_tar(archive, out)
        a = out / "python/lib/original.txt"
        b = out / "python/lib/copy.txt"
        assert a.read_bytes() == b"data" and b.read_bytes() == b"data"
        assert os.stat(a).st_ino == os.stat(b).st_ino


def main():
    tests = [obj for name, obj in globals().items() if name.startswith("test_") and callable(obj)]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS packaging ({len(tests)} passed)")


if __name__ == "__main__":
    main()
