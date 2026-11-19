"""Verify reviewed Trainer dependencies without importing them or trusting a local RECORD."""

import hashlib
import os
import stat
import sys
import sysconfig
import types
from collections.abc import Callable
from importlib.util import source_from_cache
from pathlib import Path

from modelaudit_picklescan import call_graph

# SHA-256 over sorted (wheel-relative path NUL, binary file digest) pairs
# under <package>/ and <package>.libs/, excluding __pycache__/*.pyc (checked
# against source below, including NumPy 2.4.4's bundled bytecode).
# Pins are derived from independent PyPI wheels, not the target installation.
_WHEELS: dict[str, dict[int, str]] = {
    "accelerate": {
        84: "5acbc66852c766881671470927d1f23bcce1e2b679d58f52c9f2a36fbd791a49",  # 1.12.0 universal
    },
    "numpy": {
        1017: "ba63b1eca5cfce04411e74df9b56b7696e91d7b6607d13716e6b0cc1b0ab49e9",  # 2.4.4 macOS arm64
        1018: "9c981a943f8db2e62ad4810d0d823a6b756c10021da00cd9731e88f39d3012ba",  # 2.4.6 macOS arm64
        1020: "976d25f64674e2ae6128ab33e0ac4257f042ca7b8fda0edc59c9bda23136affb",  # 2.4.4 Linux x86_64
        1021: "e3c34895f98e7bac06ff315c681629588f5f4a261d6fafb97cf0949a02c60d37",  # 2.4.6 Linux x86_64
    },
    "torch": {
        11678: "cbcdb8d0185e2b3836a05ca30ceb8fdb626f440dbcf2fb8d6ff1126a1482e4e4",  # 2.11.0 Linux x86_64
        12189: "c09bc230ecb7116a1c96b97bba2ee7ada2ac33d3a84a63806c39f9eb9e1fe997",  # 2.15.0 Linux x86_64
        12245: "e0e43645ecad4c07ff49332e40afd3a530188fe9cf0617c894a540713ba1f3c7",  # 2.11.0 macOS arm64
        12836: "44965ff430de38aa0b4a1cb6334946c01539f0ed6a07449279822fdc2779381c",  # 2.15.0 macOS arm64
    },
    "transformers": {
        2240: "2046524703f6828726b596d4decfb0676a85ce9e50edb3c40e08d1afda8284f7",  # 4.57.6 universal
    },
}
_MAX_BYTES = 2 * 1024**3


def _isolated_paths() -> bool:
    # Unloaded framework initializers can import other modules. Don't treat a
    # working directory, PYTHONPATH, editable install or user site as trusted.
    paths = sysconfig.get_paths()
    stdlib = Path(paths["stdlib"])
    trusted = {Path(paths[name]) for name in ("stdlib", "platstdlib", "purelib", "platlib", "scripts")}
    trusted.add(stdlib / "lib-dynload")
    # uv can use a minor-version symlink for the interpreter's extension
    # directory. Accept the interpreter's alias only if it is the same directory.
    if sys.base_exec_prefix != sys.base_prefix:
        alias = Path(sys.base_exec_prefix) / stdlib.relative_to(sys.base_prefix) / "lib-dynload"
        if alias.is_absolute() and alias.samefile(stdlib / "lib-dynload"):
            trusted.add(alias)
    # ModelAudit adds its installed protobuf module root during discovery.
    trusted.add(Path(paths["purelib"]) / "modelaudit" / "protos")
    stdlib_zip = stdlib.parent / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
    return sys.pycache_prefix is None and all(
        p and (Path(p) in trusted or (Path(p) == stdlib_zip and not stdlib_zip.exists())) for p in sys.path
    )


def _wheel_matches(root: Path, pkg: str, check_timeout: Callable[[], bool]) -> bool:
    pins = _WHEELS[pkg]
    remaining = _MAX_BYTES
    files: set[Path] = set()
    caches: list[Path] = []
    pending = [root / pkg]
    libs = root / (pkg + ".libs")
    if libs.exists():
        pending.append(libs)
    visited = 0
    while pending:
        check_timeout()
        directory = pending.pop()
        if directory.is_symlink():
            return False
        with os.scandir(directory) as children:
            for entry in children:
                visited += 1
                if visited > 32768 or entry.is_symlink():
                    return False
                path = Path(entry.path)
                if entry.is_dir():
                    pending.append(path)
                elif entry.is_file():
                    if path.parent.name == "__pycache__" and path.suffix == ".pyc":
                        caches.append(path)
                    else:
                        files.add(path)
                else:
                    return False
    if len(files) not in pins:
        return False
    digest = hashlib.sha256()
    for rel in sorted(p.relative_to(root).as_posix() for p in files):
        check_timeout()
        h = hashlib.sha256()
        with (root / rel).open("rb") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > remaining:
                return False
            while chunk := f.read(1024 * 1024):
                check_timeout()
                remaining -= len(chunk)
                if remaining < 0:
                    return False
                h.update(chunk)
        digest.update(rel.encode() + b"\0" + h.digest())
    if digest.hexdigest() != pins[len(files)]:
        return False
    # A timestamp-valid .pyc can override even an authentic source file.
    for cache in caches:
        check_timeout()
        source = Path(source_from_cache(str(cache)))
        if source not in files or source.suffix != ".py":
            return False
        remaining -= source.stat().st_size + cache.stat().st_size
        if remaining < 0:
            return False
        opt = 1 if ".opt-1." in cache.name else 2 if ".opt-2." in cache.name else 0
        if call_graph._bytecode_cache_can_override_source(cache, source, source.read_text(encoding="utf-8"), opt):
            return False
    return True


def trusted_trainer_runtime(references: set[str], check_timeout: Callable[[], bool]) -> bool:
    """Check the scanner's environment, not an attestation of a remote consumer."""
    try:
        if not _isolated_paths():
            return False
        root = Path(sysconfig.get_path("purelib"))
        packages: set[str] = set()
        for reference in references:
            module, _, name = reference.rpartition(".")
            if reference == "_codecs.encode":
                codec = sys.modules.get("_codecs")
                if type(codec) is not types.ModuleType or call_graph._trusted_module_origin_kind(module) != "stdlib":
                    return False
                encode = vars(codec).get("encode")
                if (
                    type(encode) is not types.BuiltinFunctionType
                    or encode.__self__ is not codec
                    or encode.__name__ != "encode"
                ):
                    return False
                continue
            pkg = module.partition(".")[0]
            if pkg not in _WHEELS or not call_graph.import_only_reference_is_proven_trusted(module, name):
                return False
            source = call_graph._trusted_python_module_source_path(module)
            if source is None or not source.is_relative_to(root / pkg):
                return False
            packages.add(pkg)
        # The CLI loads NumPy. Don't attest live mutable training frameworks
        # solely from their files on disk.
        if any(k.partition(".")[0] in packages - {"numpy"} for k in sys.modules):
            return False
        if "numpy" in packages and not all(
            call_graph.import_only_reference_is_proven_trusted(m, n)
            for m, n in (("numpy", "ndarray"), ("numpy._core.multiarray", "_reconstruct"))
        ):
            return False
        return bool(packages) and all(_wheel_matches(root, pkg, check_timeout) for pkg in sorted(packages))
    except TimeoutError:
        raise
    except (AttributeError, KeyError, ValueError, OSError, RuntimeError, SyntaxError):
        # Unknown import machinery, old picklescan or unreadable installation.
        return False
