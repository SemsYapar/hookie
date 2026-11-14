"""Hookie payload bootstrap — run by the native stub, not imported normally.

The stub compiles this file (filename ``hookie_bootstrap.py`` for clean
tracebacks) and executes it with ``PyEval_EvalCode`` in a *fresh* globals dict
into which it has already injected ``_hookie_dir`` (the absolute payload
directory). Running in its own namespace means the temporaries below never leak
into the target process's ``__main__``.

One file serves every target: it branches on ``os.name`` and takes the
interpreter version from ``sys.version_info`` instead of being told, so x86/x64
and Windows/Linux all share this exact source.

Responsibilities:
  * put the bundled ``site-packages`` (3rd-party deps + the ``hookie`` package)
    and the payload directory on ``sys.path``;
  * on Windows, register the payload directory with ``os.add_dll_directory`` so
    the bundled extension modules and runtime can resolve their dependent DLLs
    (3.8+ no longer searches PATH/cwd), keeping the returned cookie alive;
  * import ``hook.py`` once, under the unique module name ``hookie_<id>``, with
    an idempotency guard so a re-injection does not run the hooks twice.
"""
import sys
import os
import importlib.util

# Injected by the stub into this module's globals before execution.
_dir = _hookie_dir  # noqa: F821
_id = os.path.basename(os.path.normpath(_dir))

if os.name == "nt":
    _site = os.path.join(_dir, "Lib", "site-packages")
else:
    _ver = "%d.%d" % (sys.version_info[0], sys.version_info[1])
    _site = os.path.join(_dir, "lib", "python" + _ver, "site-packages")

if _site not in sys.path:
    sys.path.insert(0, _site)
if _dir not in sys.path:
    sys.path.insert(0, _dir)

# Windows-only: dependent DLLs of the bundled .pyd extension modules and the
# runtime resolve only through add_dll_directory on 3.8+. The returned cookie
# must stay alive or the directory is removed from the search path, so park it
# on a module-level list on `sys`.
if hasattr(os, "add_dll_directory"):
    if not hasattr(sys, "_hookie_dll_dirs"):
        sys._hookie_dll_dirs = []
    sys._hookie_dll_dirs.append(os.add_dll_directory(_dir))

_name = "hookie_" + _id
_file = os.path.join(_dir, "hook.py")
_mod = sys.modules.get(_name)
if _mod is None:
    _spec = importlib.util.spec_from_file_location(_name, _file)
    if _spec is None or _spec.loader is None:
        raise ImportError("cannot load hookie payload")
    _mod = importlib.util.module_from_spec(_spec)
    _mod.__hookie_loaded__ = False
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)
    _mod.__hookie_loaded__ = True
elif not getattr(_mod, "__hookie_loaded__", False):
    raise RuntimeError(
        "previous hookie payload execution failed; refusing to execute it twice"
    )
