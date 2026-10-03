"""
hookie.packaging — build a self-contained, injectable folder from a Python hook script.

`hookie create-dll` lays out everything the stub DLL needs inside one directory:
an embeddable CPython, capstone + hookie installed into it, the user's source script
and the stub DLL itself. On Windows, the optional inject-dll helper can load
the resulting DLL into a target process for simple smoke tests.

Each create gets an isolated ``deps/<id>/`` payload directory. The stub stores
that absolute directory in its Hookie trailer resource. With ``--single-file`` on either platform, the payload tree is archived, LZSS
compressed into that resource, and removed from disk so only the stub remains.

Everything here uses only the standard library plus whatever `pip` can fetch.
"""

from __future__ import annotations

import argparse
import ast
import importlib.metadata
import fnmatch
import hashlib
import json
import os
import posixpath
import pkgutil
import sysconfig
import tarfile
import shutil
import subprocess
import sys
import urllib.request
import zipfile
import struct
import secrets
from pathlib import Path

_CURRENT_PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

# python.org embeddable download; {v}=full version (e.g. 3.12.8), {p}=amd64|win32
_EMBED_URL = "https://www.python.org/ftp/python/{v}/python-{v}-embed-{p}.zip"

# Arch -> (embeddable suffix, pip platform tag, mingw prefix)
_ARCH = {
    "x64": ("amd64", "win_amd64", "x86_64-w64-mingw32"),
    "x86": ("win32", "win32", "i686-w64-mingw32"),
}


def _run(cmd: list[str]) -> None:
    print("  $", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True)


def resolve_embeddable(arch: str, py_version: str, provided: Path | None,
                       work: Path) -> Path:
    """Return a directory holding an extracted embeddable CPython."""
    suffix = _ARCH[arch][0]
    dst = work

    if provided:
        provided = provided.expanduser().resolve()
        if provided.is_dir():
            # Pre-extracted embeddable: copy it into the payload directory.
            shutil.copytree(provided, dst, dirs_exist_ok=True)
            return dst
        zpath = provided                      # kullanıcı zip verdi
    else:
        url = _EMBED_URL.format(v=py_version, p=suffix)
        zpath = work / f"embed-{py_version}-{suffix}.zip"
        print(f"  downloading: {url}")
        urllib.request.urlretrieve(url, zpath)

    with zipfile.ZipFile(zpath) as z:
        z.extractall(dst)
    return dst


def _source_file(src: Path) -> Path:
    """Resolve SOURCE to a hook.py entrypoint.

    SOURCE may be either the hook.py file itself or a directory containing
    hook.py.  The filename stays ``hook.py`` inside the payload as well; the
    native stub gives the loaded Python module a build-specific name.
    """
    src = src.expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"SOURCE does not exist: {src}")

    if src.is_dir():
        hook = src / "hook.py"
        if not hook.is_file():
            raise FileNotFoundError(
                f"SOURCE directory must contain hook.py: {hook}"
            )
        return hook

    if not src.is_file():
        raise ValueError(f"SOURCE must be hook.py or a directory containing hook.py: {src}")
    if src.name != "hook.py":
        raise ValueError(f"SOURCE file must be named hook.py: {src}")
    return src


def _imports_in_file(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise RuntimeError(f"cannot analyze imports in {path}: {exc}") from exc

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".", 1)[0])
    return names



def _stdlib_names() -> set[str]:
    names = set(sys.builtin_module_names)
    known = getattr(sys, "stdlib_module_names", None)
    if known is not None:
        names.update(known)
        return names

    # Fallback for interpreters without sys.stdlib_module_names.
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    names.update(module.name for module in pkgutil.iter_modules([str(stdlib)]))
    return names

def _payload_py_files(source: Path) -> list[Path]:
    """SOURCE, sibling top-level modules, and modules in sibling packages."""
    src_dir = source.parent
    files = list(src_dir.glob("*.py"))
    for pkg in src_dir.iterdir():
        if pkg.is_dir() and (pkg / "__init__.py").is_file():
            files.extend(py for py in pkg.rglob("*.py")
                         if "__pycache__" not in py.parts)
    return files


def discover_dependencies(src: Path) -> list[str]:
    """Infer third-party distributions from the local Python import graph.

    All sibling .py files and sibling Python packages are treated as payload-local and scanned too.
    Standard-library modules and hookie itself are excluded.  Distribution
    metadata from the builder environment resolves import names to the actual
    installed distributions that provide them.  Unresolved third-party imports
    are reported instead of being guessed as PyPI project names.

    Dynamic imports (importlib/__import__ with computed names) cannot be
    discovered statically and should be avoided in payload entry modules.
    """
    source = _source_file(src)
    src_dir = source.parent
    local_modules = {p.stem for p in src_dir.glob("*.py")}
    local_modules.update(p.name for p in src_dir.iterdir()
                         if p.is_dir() and (p / "__init__.py").is_file())

    imported: set[str] = set()
    for py in sorted(_payload_py_files(source)):
        imported.update(_imports_in_file(py))

    stdlib = _stdlib_names()
    third_party = imported - stdlib - local_modules - {"hookie", "__future__"}

    installed_map = importlib.metadata.packages_distributions()
    distributions: set[str] = {"capstone>=5.0.8,<6"}
    unresolved: list[str] = []

    for name in sorted(third_party):
        candidates = installed_map.get(name) or []
        if not candidates:
            unresolved.append(name)
            continue

        # A top-level import can legally be provided by more than one installed
        # distribution (namespace packages are the common case).  Preserve all
        # providers instead of arbitrarily choosing candidates[0].
        distributions.update(candidates)

    if unresolved:
        joined = ", ".join(unresolved)
        raise RuntimeError(
            "cannot resolve distribution metadata for third-party import(s): "
            f"{joined}. Install the package(s) in the Python environment running "
            "hookie, then run the builder again."
        )

    result = sorted(distributions, key=str.lower)
    print("  detected dependencies: " + ", ".join(result))
    return result


def pip_install(site: Path, arch: str, py_version: str,
                packages: list[str]) -> None:
    """Install discovered dependencies into --target as target-platform wheels."""
    xy = ".".join(py_version.split(".")[:2])
    plat = _ARCH[arch][1]
    base = [sys.executable, "-m", "pip", "install",
            "--target", str(site),
            "--platform", plat,
            "--python-version", xy,
            "--implementation", "cp",
            "--only-binary=:all:",
            "--upgrade"]
    if packages:
        _run(base + packages)


def _license_bytes() -> bytes:
    """Return the MIT license bytes from a source checkout or installed wheel."""
    pkg = Path(__file__).resolve().parent
    source_license = pkg.parent / "LICENSE"
    if source_license.is_file():
        return source_license.read_bytes()

    try:
        dist = importlib.metadata.distribution("hookie")
        for entry in dist.files or ():
            parts = tuple(str(entry).replace("\\", "/").split("/"))
            if parts and parts[-1] == "LICENSE" and "licenses" in parts:
                candidate = Path(dist.locate_file(entry))
                if candidate.is_file():
                    return candidate.read_bytes()
    except importlib.metadata.PackageNotFoundError:
        pass
    raise FileNotFoundError("Hookie LICENSE could not be located")


def copy_hookie(site: Path) -> None:
    """Copy the pure-Python package into the payload and retain its MIT notice."""
    pkg = Path(__file__).resolve().parent
    dst = site / "hookie"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(pkg, dst,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc",
                                                  "stubs", "tests"))
    (dst / "LICENSE").write_bytes(_license_bytes())
    print(f"  copied hookie -> {dst}")

def place_scripts(source: Path, out: Path) -> Path:
    """Copy hook.py and sibling local modules/packages into the payload.

    The entrypoint filename is deliberately unchanged: the user's ``hook.py``
    becomes ``<payload>/hook.py``.  The native stub assigns the build-specific
    Python module name (``hookie_<id>``) when it executes this file.
    """
    source = _source_file(source)
    src_dir = source.parent
    entry_name = "hook.py"
    entry = out / entry_name
    shutil.copy2(source, entry)

    modules = 0
    packages = 0
    for py in src_dir.glob("*.py"):
        if py == source or py.name == "hook.py":
            continue
        shutil.copy2(py, out / py.name)
        modules += 1

    for package in src_dir.iterdir():
        if not package.is_dir() or not (package / "__init__.py").is_file():
            continue
        dst = out / package.name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(package, dst,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        packages += 1

    print(f"  placed {source.name} (+{modules} modules, +{packages} packages)")
    return entry


def _stub_variant(arch: str, platform: str) -> Path:
    return Path(__file__).resolve().parent / "stubs" / f"{arch}-{platform}"


def _stub_cache_root() -> Path:
    override = os.environ.get("HOOKIE_CACHE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "hookie" / "cache"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "hookie"


def _stub_cache_path(arch: str, target_platform: str, src: Path,
                     suffix: str, debug: bool) -> Path:
    h = hashlib.sha256()
    h.update(src.read_bytes())
    h.update(f"\0{arch}\0{target_platform}\0debug={int(debug)}".encode("ascii"))
    return (_stub_cache_root() / "stubs" / f"{arch}-{target_platform}" /
            h.hexdigest()[:16] / f"hookie_stub{suffix}")


def _compile_windows_stub(target: Path, arch: str, stub_src: Path,
                          *, debug: bool = False) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("cl"):
        _run(["cl", "/nologo", "/LD", "/O2",
              *(["/DHK_DEBUG"] if debug else []),
              str(stub_src), f"/Fe:{target}"])
    else:
        gcc = f"{_ARCH[arch][2]}-gcc"
        if not shutil.which(gcc):
            raise RuntimeError(
                "no Windows C compiler found; install MSVC cl or MinGW-w64, "
                "or pass --prebuilt-stub")
        _run([gcc, "-shared", "-O2", *(["-DHK_DEBUG"] if debug else []),
              "-o", str(target), str(stub_src)])
    if not target.is_file():
        raise RuntimeError(f"Windows stub compiler did not produce: {target}")


def _compile_linux_stub(target: Path, arch: str, stub_src: Path,
                        *, debug: bool = False) -> None:
    gcc = shutil.which("gcc")
    if not gcc:
        raise RuntimeError("gcc is required to build the Linux stub (or use --prebuilt-stub)")
    target.parent.mkdir(parents=True, exist_ok=True)
    _run([gcc, "-m64" if arch == "x64" else "-m32", "-shared", "-fPIC",
          "-O2", "-Wall", "-Wextra", *(["-DHK_DEBUG"] if debug else []),
          "-o", str(target), str(stub_src), "-ldl", "-pthread"])
    if not target.is_file():
        raise RuntimeError(f"Linux stub compiler did not produce: {target}")


def _ensure_windows_stub(arch: str, stub_src: Path | None,
                         prebuilt: Path | None, *, debug: bool = False) -> tuple[Path, Path]:
    variant = _stub_variant(arch, "windows")
    custom_source = stub_src is not None
    src = (stub_src or (variant / "hookie_stub.c")).expanduser().resolve(strict=True)
    if prebuilt is not None:
        return src, prebuilt.expanduser().resolve(strict=True)

    # Release wheels may ship a known-good Windows prebuilt.  Never let it
    # shadow --stub-src or --debug.
    packaged = variant / "hookie_stub.dll"
    if not custom_source and not debug and packaged.is_file():
        return src, packaged

    cached = _stub_cache_path(arch, "windows", src, ".dll", debug)
    if not cached.is_file():
        _compile_windows_stub(cached, arch, src, debug=debug)
    return src, cached


def _ensure_linux_stub(arch: str, stub_src: Path | None,
                       prebuilt: Path | None, *, debug: bool = False) -> tuple[Path, Path]:
    variant = _stub_variant(arch, "linux")
    src = (stub_src or (variant / "hookie_stub.c")).expanduser().resolve(strict=True)
    if prebuilt is not None:
        return src, prebuilt.expanduser().resolve(strict=True)

    # Linux binaries are intentionally not shipped: glibc symbol versions are
    # tied to the build environment.  Compile once on the user's host and cache
    # by source hash instead.
    cached = _stub_cache_path(arch, "linux", src, ".so", debug)
    if not cached.is_file():
        _compile_linux_stub(cached, arch, src, debug=debug)
    return src, cached


def place_stub(out: Path, arch: str, name: str,
               stub_src: Path, prebuilt: Path | None, *, debug: bool = False) -> None:
    target = out / name
    if prebuilt and prebuilt.is_file():
        shutil.copy2(prebuilt, target)
        print(f"  copied stub -> {target.name}")
        return
    _compile_windows_stub(target, arch, stub_src, debug=debug)


_RESOURCE_MAGIC = b"HOOKIE_PAYLOAD_V1"
# magic[17] mode[1] ident_len[1] reserved[5] raw_size[8] data_size[8] -> 40 bytes.
# ident_len replaces one reserved byte so the native stub never hardcodes the id
# length; the on-disk footer size is unchanged and remains compatible-shaped.
_RESOURCE_FOOTER = struct.Struct("<17sBB5xQQ")
_RESOURCE_PATH = 1
_RESOURCE_PACKED = 2
_PAYLOAD_ID_BYTES = 6  # 6 random bytes -> 12 hex chars (48-bit local build id)


def _new_payload_dir(root: Path, *conflict_roots: Path) -> Path:
    """Create deps/<id>/ with a short unique id.

    The same 12-hex id is used consistently for deps/, builds/, single-file
    extraction, and the generated Python entrypoint name.  Collisions are
    checked across both local roots, so the id is regenerated until it
    is free both under *root* and under every *conflict_roots* entry (typically
    the product/builds root, which reuses the same id for its subdirectory).
    """
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    others = [r.expanduser().resolve() for r in conflict_roots]
    while True:
        ident = secrets.token_hex(_PAYLOAD_ID_BYTES)
        if any((other / ident).exists() for other in others):
            continue
        payload = root / ident
        try:
            payload.mkdir()
        except FileExistsError:
            continue
        return payload


def _archive_payload(root: Path, exclude: Path) -> bytes:
    """Serialize the payload tree. Directories are implicit in file paths."""
    out = bytearray()
    exclude = exclude.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() == exclude:
            continue
        rel = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        out += struct.pack("<IQ", len(rel), len(data))
        out += rel
        out += data
    out += struct.pack("<I", 0)
    return bytes(out)


def _lzss_compress(data: bytes) -> bytes:
    """Small dependency-free LZSS codec used by --single-file."""
    out = bytearray()
    pos = 0
    table: dict[bytes, list[int]] = {}
    n = len(data)
    while pos < n:
        flag_at = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if pos >= n:
                break
            best_len = 0
            best_dist = 0
            if pos + 3 <= n:
                key = data[pos:pos + 3]
                candidates = table.get(key, ())
                for prev in reversed(candidates[-64:]):
                    dist = pos - prev
                    if dist > 4095:
                        break
                    ln = 3
                    limit = min(18, n - pos)
                    while ln < limit and data[prev + ln] == data[pos + ln]:
                        ln += 1
                    if ln > best_len:
                        best_len, best_dist = ln, dist
                        if ln == 18:
                            break
            if best_len >= 3:
                token = ((best_len - 3) << 12) | best_dist
                out += struct.pack("<H", token)
                consume = best_len
            else:
                flags |= 1 << bit
                out.append(data[pos])
                consume = 1
            end = min(pos + consume, n)
            for i in range(pos, end):
                if i + 3 <= n:
                    key = data[i:i + 3]
                    bucket = table.setdefault(key, [])
                    bucket.append(i)
                    if len(bucket) > 128:
                        del bucket[:64]
            pos = end
        out[flag_at] = flags
    return bytes(out)


def _append_resource(stub: Path, payload_dir: Path, single_file: bool) -> None:
    if single_file:
        raw = _archive_payload(payload_dir, stub)
        # Use the same build id everywhere: deps/<id>, builds/<id>, the packed
        # footer identity and the extracted temp directory.
        ident = payload_dir.name.encode("ascii")
        ident_len = len(ident)
        blob = ident + _lzss_compress(raw)
        mode = _RESOURCE_PACKED
        print(f"  packed payload: {len(raw):,} -> {len(blob) - ident_len:,} bytes "
              f"(+ {ident_len}-byte id)")
    else:
        raw = str(payload_dir.resolve()).encode("utf-8")
        blob = raw
        mode = _RESOURCE_PATH
        ident_len = 0
    with stub.open("ab") as f:
        f.write(blob)
        f.write(_RESOURCE_FOOTER.pack(_RESOURCE_MAGIC, mode, ident_len,
                                      len(raw), len(blob)))


def _keep_only_stub(payload_dir: Path, stub: Path) -> None:
    for child in payload_dir.iterdir():
        if child.resolve() == stub.resolve():
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()

def _python_major_minor(py_version: str) -> tuple[int, int]:
    try:
        parts = py_version.split(".")
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError) as exc:
        raise ValueError(f"invalid Python version: {py_version!r}") from exc


def _validate_payload_python(py_version: str, *, linux: bool = False) -> None:
    version = _python_major_minor(py_version)
    if version < (3, 10):
        raise ValueError("Hookie payloads require CPython 3.10 or newer")
    if linux and version >= (3, 15):
        raise ValueError(
            "Linux payloads currently support CPython 3.10-3.14. "
            "The bootstrap intentionally refuses 3.15+ until it is migrated "
            "from removed Py_SetPythonHome to the PyConfig API.")


def create_dll(source: Path, out: Path, *, deps_root: Path, arch: str, py_version: str,
               name: str | None, embeddable: Path | None,
               stub_src: Path, prebuilt: Path | None,
               single_file: bool = False, debug: bool = False) -> Path:
    if arch not in _ARCH:
        raise ValueError(f"arch must be one of {list(_ARCH)}")
    source = _source_file(source)
    _validate_payload_python(py_version)
    if debug and prebuilt is not None:
        raise ValueError("--debug cannot be combined with --prebuilt-stub; debug mode must compile the C stub")
    stub_src, prebuilt = _ensure_windows_stub(arch, stub_src, prebuilt, debug=debug)
    if name is None:
        name = "hookie_stub.dll"
    dependencies = discover_dependencies(source)
    out_root = out.expanduser().resolve()
    payload = _new_payload_dir(deps_root, out_root)
    build = out_root / payload.name
    build.mkdir(parents=True, exist_ok=False)
    site = payload / "Lib" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)

    print(f"  payload id: {payload.name}")
    print(f"[1/7] embeddable CPython {py_version} ({arch})")
    resolve_embeddable(arch, py_version, embeddable, payload)
    print("[2/7] embeddable runtime layout")
    print("[3/7] detected Python dependencies")
    pip_install(site, arch, py_version, dependencies)
    print("[4/7] hookie")
    copy_hookie(site)
    print("[5/7] payload entrypoint")
    place_scripts(source, payload)
    print("[6/7] stub DLL")
    place_stub(payload, arch, name, stub_src, prebuilt, debug=debug)
    stub = payload / name
    if not stub.is_file():
        raise RuntimeError(f"stub was not produced: {stub}")
    print("[7/7] Hookie payload resource")
    _append_resource(stub, payload, single_file)
    product = build / name
    shutil.copy2(stub, product)
    stub.unlink()
    if single_file:
        shutil.rmtree(payload)

    print(f"\nDone -> {product}")
    print(f"Inject '{stub.name}' into a target; it will run hook.py as module hookie_{payload.name}.")
    return product



_PBS_API = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"


def _safe_tar_name(name: str) -> str:
    if not name or "\x00" in name or name.startswith("/"):
        raise ValueError(f"unsafe archive member: {name!r}")
    normalized = posixpath.normpath(name)
    if normalized in ("", ".", "..") or normalized.startswith("../"):
        raise ValueError(f"unsafe archive member: {name!r}")
    return normalized


def _safe_extract_tar(archive: Path, dst: Path) -> None:
    """Extract a gzip tar without traversal through names or link targets.

    Regular files/directories are materialized before links, so a symlink in
    the archive can never redirect a later file write outside the extraction
    root.  Device nodes/FIFOs and other special entries are rejected.
    """
    dst.mkdir(parents=True, exist_ok=True)
    root = dst.resolve()
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        seen: set[str] = set()
        normalized: dict[int, str] = {}
        links = []

        for member in members:
            name = _safe_tar_name(member.name)
            if name in seen:
                raise ValueError(f"duplicate archive member: {member.name!r}")
            seen.add(name)
            normalized[id(member)] = name
            if member.issym() or member.islnk():
                links.append(member)
            elif not (member.isdir() or member.isfile()):
                raise ValueError(f"unsupported archive member type: {member.name!r}")

        # No links exist yet, so parent creation and file writes cannot be
        # redirected by archive-controlled symlinks.
        for member in members:
            if member.issym() or member.islnk():
                continue
            name = normalized[id(member)]
            target = root / Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                try:
                    target.chmod(member.mode & 0o777)
                except OSError:
                    pass
                continue
            src = tf.extractfile(member)
            if src is None:
                raise ValueError(f"cannot read archive member: {member.name!r}")
            with src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            target.chmod(member.mode & 0o777)

        # Create validated links last.
        for member in links:
            name = normalized[id(member)]
            target = root / Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            linkname = member.linkname
            if not linkname or "\x00" in linkname or linkname.startswith("/"):
                raise ValueError(f"unsafe archive link target: {member.name!r} -> {linkname!r}")

            if member.issym():
                resolved_name = posixpath.normpath(posixpath.join(posixpath.dirname(name), linkname))
            else:
                resolved_name = posixpath.normpath(linkname)
            if resolved_name == ".." or resolved_name.startswith("../"):
                raise ValueError(f"unsafe archive link target: {member.name!r} -> {linkname!r}")

            resolved_target = (root / Path(resolved_name)).resolve(strict=False)
            if resolved_target != root and root not in resolved_target.parents:
                raise ValueError(f"unsafe archive link target: {member.name!r} -> {linkname!r}")
            if target.exists() or target.is_symlink():
                raise ValueError(f"archive link collides with existing path: {member.name!r}")

            if member.issym():
                os.symlink(linkname, target)
            else:
                source = root / Path(resolved_name)
                if not source.is_file() or source.is_symlink():
                    raise ValueError(f"unsafe/unresolved hardlink: {member.name!r} -> {linkname!r}")
                os.link(source, target)


def resolve_standalone(arch: str, py_version: str, provided: Path | None, work: Path) -> Path:
    """Return the `python/` directory from python-build-standalone.

    With --standalone this accepts either an extracted `python/` directory or
    an install_only .tar.gz. Without it, the latest GitHub release is queried
    and the matching target-architecture GNU/Linux install_only archive is downloaded.
    """
    extract_root = work / ".hookie-python-extract"
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True)

    if provided:
        provided = provided.expanduser().resolve(strict=True)
        if provided.is_dir():
            candidate = provided / "python" if (provided / "python").is_dir() else provided
            if not (candidate / "bin").is_dir() or not (candidate / "lib").is_dir():
                raise ValueError(f"not a python-build-standalone install tree: {provided}")
            return candidate
        archive = provided
    else:
        print("  resolving latest python-build-standalone release")
        req = urllib.request.Request(_PBS_API, headers={"User-Agent": "hookie-builder"})
        with urllib.request.urlopen(req) as response:
            release = json.load(response)
        version_pattern = py_version if py_version.count(".") >= 2 else py_version + ".*"
        linux_arch = "x86_64" if arch == "x64" else "i686"
        pattern = (f"cpython-{version_pattern}+*-{linux_arch}-unknown-linux-gnu-"
                   "install_only.tar.gz")
        assets = [a for a in release.get("assets", [])
                  if fnmatch.fnmatch(a.get("name", ""), pattern)]
        if not assets:
            raise RuntimeError(f"no python-build-standalone asset matching {pattern!r}")
        asset = assets[0]
        archive = work / asset["name"]
        print(f"  downloading: {asset['browser_download_url']}")
        urllib.request.urlretrieve(asset["browser_download_url"], archive)

    if not archive.name.endswith(".tar.gz"):
        raise ValueError("--standalone archive must be an install_only .tar.gz")
    _safe_extract_tar(archive, extract_root)
    candidate = extract_root / "python"
    if not candidate.is_dir():
        raise ValueError("python-build-standalone archive does not contain python/")
    return candidate


def _linux_python(out: Path) -> Path:
    for name in ("python3", "python"):
        p = out / "bin" / name
        if p.is_file():
            return p
    raise FileNotFoundError("bundled Python executable not found under bin/")


def _find_linux_libpython(out: Path) -> Path:
    matches = []
    for p in (out / "lib").glob("libpython3.*.so*"):
        # Prefer the linker name (libpython3.X.so), then the shortest soname.
        if "t.so" not in p.name:  # exclude free-threaded libpython3.Xt
            matches.append(p)
    if not matches:
        raise FileNotFoundError("libpython3.x.so* not found in standalone runtime")
    matches.sort(key=lambda p: (p.name.count("."), len(p.name), p.name))
    return matches[0]


def _linux_site(out: Path, libpython: Path) -> Path:
    name = libpython.name
    prefix = "libpython"
    version = name[len(prefix):].split(".so", 1)[0]
    if not version or version.endswith("t"):
        raise ValueError(f"unsupported libpython name: {name}")
    site = out / "lib" / f"python{version}" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    return site


def pip_install_linux(out: Path, site: Path, packages: list[str]) -> None:
    """Install Linux payload dependencies with the bundled interpreter itself."""
    py = _linux_python(out)
    base = [str(py), "-m", "pip", "install", "--target", str(site), "--upgrade"]
    if packages:
        _run(base + packages)


def place_stub_linux(out: Path, arch: str, name: str, stub_src: Path,
                     prebuilt: Path | None, *, debug: bool = False) -> None:
    target = out / name
    if prebuilt and prebuilt.is_file():
        shutil.copy2(prebuilt, target)
        print(f"  copied stub -> {target.name}")
        return
    _compile_linux_stub(target, arch, stub_src, debug=debug)


def create_so(source: Path, out: Path, *, deps_root: Path, arch: str, py_version: str, name: str | None,
              standalone: Path | None, stub_src: Path, prebuilt: Path | None,
              single_file: bool = False, debug: bool = False) -> Path:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("create-so must be run on a Linux host")

    source = _source_file(source)
    _validate_payload_python(py_version, linux=True)
    if debug and prebuilt is not None:
        raise ValueError("--debug cannot be combined with --prebuilt-stub; debug mode must compile the C stub")
    stub_src, prebuilt = _ensure_linux_stub(arch, stub_src, prebuilt, debug=debug)
    if name is None:
        name = "hookie_stub.so"
    dependencies = discover_dependencies(source)
    out_root = out.expanduser().resolve()
    payload = _new_payload_dir(deps_root, out_root)
    build = out_root / payload.name
    build.mkdir(parents=True, exist_ok=False)
    print(f"  payload id: {payload.name}")
    print(f"[1/7] python-build-standalone CPython {py_version} (linux-{arch})")
    runtime = resolve_standalone(arch, py_version, standalone, payload)
    shutil.copytree(runtime, payload, dirs_exist_ok=True)
    extract_root = payload / ".hookie-python-extract"
    if extract_root.exists():
        shutil.rmtree(extract_root)

    libpython = _find_linux_libpython(payload)
    site = _linux_site(payload, libpython)
    print("[2/7] detected Python dependencies")
    pip_install_linux(payload, site, dependencies)
    print("[3/7] hookie")
    copy_hookie(site)
    print("[4/7] payload entrypoint")
    place_scripts(source, payload)
    print("[5/7] Linux runtime metadata")
    libpython_rel = libpython.relative_to(payload).as_posix()
    version = libpython.name[len("libpython"):].split(".so", 1)[0]
    if not version or version.endswith("t"):
        raise ValueError(f"unsupported libpython name: {libpython.name}")
    (payload / ".hookie-libpython").write_text(libpython_rel + "\n", encoding="utf-8")
    (payload / ".hookie-python-version").write_text(version + "\n", encoding="utf-8")
    print(f"  libpython: {libpython_rel}")
    print(f"  runtime ABI: CPython {version}")
    print("[6/7] stub shared object")
    place_stub_linux(payload, arch, name, stub_src, prebuilt, debug=debug)
    stub = payload / name
    print("[7/7] Hookie payload resource")
    _append_resource(stub, payload, single_file)
    product = build / name
    shutil.copy2(stub, product)
    stub.unlink()
    if single_file:
        shutil.rmtree(payload)
    print(f"\nDone -> {product}")
    print(f"Load '{product.name}' into a target process; it will run hook.py as module hookie_{payload.name}.")
    return product


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    formatter = argparse.ArgumentDefaultsHelpFormatter
    ap = argparse.ArgumentParser(
        prog="hookie",
        description="Build Hookie payloads for Windows or Linux.",
        epilog=(
            "Windows smoke-test injection:\n"
            "  hookie inject-dll TARGET DLL\n"
            "  TARGET may be a PID or an executable name such as notepad.exe."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(
        dest="cmd",
        required=True,
        title="commands",
        metavar="COMMAND",
    )

    p = sub.add_parser(
        "create-dll",
        help="build a self-contained Windows DLL payload",
        description="Build a self-contained Windows payload from hook.py or a directory containing hook.py.",
        formatter_class=formatter,
    )
    required = p.add_argument_group("required arguments")
    required.add_argument(
        "src", type=Path, metavar="SOURCE",
        help="hook.py file or directory containing hook.py (required; sibling local modules/packages are included)",
    )
    optional = p.add_argument_group("optional arguments")
    optional.add_argument(
        "-o", "--out", type=Path, default=Path("builds"), metavar="DIR",
        help="product root; each create gets a short build-id subdirectory",
    )
    optional.add_argument(
        "--arch", choices=list(_ARCH),
        default="x64" if sys.maxsize > 2**32 else "x86",
        help="target process bitness",
    )
    optional.add_argument(
        "--py-version", default=_CURRENT_PYTHON_VERSION, metavar="VERSION",
        help="embeddable CPython version to bundle",
    )
    optional.add_argument(
        "--name", default=None, metavar="FILE",
        help="stub DLL filename (default: STUB_SRC basename with .dll)",
    )
    optional.add_argument(
        "--embeddable", type=Path, default=None, metavar="PATH",
        help="local embeddable CPython zip/directory instead of downloading it",
    )
    optional.add_argument(
        "--stub-src", type=Path, metavar="FILE",
        default=None,
        help="override Windows stub C source (default: stubs/<arch>-windows/hookie_stub.c)",
    )
    optional.add_argument(
        "--prebuilt-stub", type=Path, default=None, metavar="FILE",
        help="already-compiled stub DLL to copy instead of compiling",
    )
    optional.add_argument(
        "--single-file", dest="single_file", action="store_true",
        help="embed the complete payload in the stub and leave only the DLL",
    )
    optional.add_argument(
        "--debug", action="store_true",
        help="compile the Windows stub with HK_DEBUG tracing via OutputDebugStringW (DebugView/debugger)",
    )

    so = sub.add_parser(
        "create-so",
        help="build a self-contained Linux x86/x64 SO payload",
        description="Build a self-contained Linux x86/x64 payload from hook.py or a directory containing hook.py.",
        formatter_class=formatter,
    )
    required = so.add_argument_group("required arguments")
    required.add_argument(
        "src", type=Path, metavar="SOURCE",
        help="hook.py file or directory containing hook.py (required; sibling local modules/packages are included)",
    )
    optional = so.add_argument_group("optional arguments")
    optional.add_argument(
        "-o", "--out", type=Path, default=Path("builds"), metavar="DIR",
        help="product root; each create gets a short build-id subdirectory",
    )
    optional.add_argument(
        "--arch", choices=list(_ARCH),
        default="x64" if sys.maxsize > 2**32 else "x86",
        help="target process bitness",
    )
    optional.add_argument(
        "--py-version", default=_CURRENT_PYTHON_VERSION, metavar="VERSION",
        help="CPython version to bundle",
    )
    optional.add_argument(
        "--name", default=None, metavar="FILE",
        help="stub shared-object filename (default: STUB_SRC basename with .so)",
    )
    optional.add_argument(
        "--standalone", type=Path, default=None, metavar="PATH",
        help="local python-build-standalone install_only tar.gz/extracted tree instead of downloading it",
    )
    optional.add_argument(
        "--stub-src", type=Path, metavar="FILE",
        default=None,
        help="override Linux stub C source (default: stubs/<arch>-linux/hookie_stub.c)",
    )
    optional.add_argument(
        "--prebuilt-stub", type=Path, default=None, metavar="FILE",
        help="already-compiled .so to copy instead of compiling",
    )
    optional.add_argument(
        "--single-file", dest="single_file", action="store_true",
        help="embed the complete payload in the shared object and leave only the .so",
    )
    optional.add_argument(
        "--debug", action="store_true",
        help="compile the Linux stub with HK_DEBUG tracing to stderr",
    )

    inj = sub.add_parser(
        "inject-dll",
        help="inject a prebuilt stub DLL into a target process (Windows smoke test)",
        description="Load a Hookie stub DLL into a running Windows process via LoadLibraryW.",
        formatter_class=formatter,
    )
    inj_req = inj.add_argument_group("required arguments")
    inj_req.add_argument(
        "target", metavar="TARGET",
        help="target process: a PID or an executable name such as notepad.exe",
    )
    inj_req.add_argument(
        "dll", type=Path, metavar="DLL",
        help="stub DLL to inject into the target",
    )

    args = ap.parse_args(argv)
    if args.cmd == "inject-dll":
        from .injector import inject_dll
        code = inject_dll(args.target, args.dll)
        if code is None:
            print(f"Injection is still pending after 15000 ms for {args.target}. "
                  "The target may be paused in a debugger; the remote LoadLibraryW thread was left intact.")
            return 0
        print(f"Injected {args.dll.resolve()} into {args.target} "
              f"(LoadLibraryW returned nonzero: 0x{code:x})")
        return 0
    if args.cmd == "create-dll":
        create_dll(
            args.src, args.out,
            deps_root=Path("deps"),
            arch=args.arch,
            py_version=args.py_version,
            name=args.name,
            embeddable=args.embeddable,
            stub_src=args.stub_src,
            prebuilt=args.prebuilt_stub,
            single_file=args.single_file,
            debug=args.debug,
        )
    elif args.cmd == "create-so":
        create_so(
            args.src, args.out,
            deps_root=Path("deps"),
            arch=args.arch,
            py_version=args.py_version,
            name=args.name,
            standalone=args.standalone,
            stub_src=args.stub_src,
            prebuilt=args.prebuilt_stub,
            single_file=args.single_file,
            debug=args.debug,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
