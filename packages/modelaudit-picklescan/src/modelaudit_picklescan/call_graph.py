"""Bounded static call-graph checks for importable Python pickle globals."""

from __future__ import annotations

import _imp
import ast
import fnmatch
import hashlib
import marshal
import os
import stat
import sys
import sysconfig
import threading
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.machinery import (
    BYTECODE_SUFFIXES,
    EXTENSION_SUFFIXES,
    SOURCE_SUFFIXES,
    BuiltinImporter,
    ExtensionFileLoader,
    FileFinder,
    FrozenImporter,
    ModuleSpec,
    PathFinder,
    SourceFileLoader,
    SourcelessFileLoader,
)
from importlib.metadata import distribution, packages_distributions
from importlib.util import MAGIC_NUMBER, cache_from_source, source_hash
from pathlib import Path
from types import CodeType, FunctionType, MethodType, ModuleType
from typing import Any, Protocol, TypeVar, cast
from zipimport import zipimporter

# Bound per-pass import/callable fan-out for untrusted inputs. The 32-reference
# cap has kept call-graph enrichment useful while preventing pathological scan
# growth; raising it improves completeness at a runtime cost, lowering it can
# reduce detection coverage.
_MAX_IMPORT_REFERENCES = 32
_MAX_MODULE_NAME_CHARS = 1024
_MAX_MODULE_COMPONENTS = 32
# Limit per-module source reads to 1 MiB so AST parsing remains bounded on large
# inputs. This is an explicit coverage/performance tradeoff and can be tuned if
# scan precision or throughput needs change.
_MAX_SOURCE_BYTES = 1024 * 1024
_CALL_GRAPH_REGULAR_FILE_FINGERPRINT = "regular-file"
_MAX_SOURCE_FINGERPRINT_CANDIDATES = 4096
_MAX_SOURCE_MODULE_NAME_CHARS = 4096
_SOURCE_RESOLUTION_SUFFIXES = tuple(dict.fromkeys((*SOURCE_SUFFIXES, *BYTECODE_SUFFIXES, *EXTENSION_SUFFIXES)))
_MAX_HOOK_IDENTITY_ITEMS = 16
_MAX_HOOK_IDENTITY_DEPTH = 4
_UNREUSABLE_HOOK_STATE_IDENTITY = "<unreusable-hook-state>"
_MAX_BYTECODE_CACHE_BYTES = 4 * _MAX_SOURCE_BYTES
_MAX_BYTECODE_CACHE_DIRECTORY_BYTES = 64 * 1024
_MAX_BYTECODE_CACHE_DIRECTORY_ENTRIES = 256
_BYTECODE_CACHE_OPTIMIZATIONS = (("", 0), ("1", 1), ("2", 2))
_MAX_CALL_GRAPH_DEPTH = 4
_MAX_VISITED_FUNCTIONS = 64
_MAX_CALLS_PER_FUNCTION = 128
_MAX_ASSIGNMENT_ALIASES = 128
_MAX_ASSIGNMENT_ALIAS_PASSES = 256
_MAX_FUNCTION_INSTANCE_ALIASES = 32
_STANDARD_FILE_FINDER_LOADER_DETAILS = (
    (ExtensionFileLoader, list(EXTENSION_SUFFIXES)),
    (SourceFileLoader, list(SOURCE_SUFFIXES)),
    (SourcelessFileLoader, list(BYTECODE_SUFFIXES)),
)
_STANDARD_FILE_FINDER_LOADER_IDENTITY = tuple(
    (loader, tuple(suffixes)) for loader, suffixes in _STANDARD_FILE_FINDER_LOADER_DETAILS
)
_STANDARD_FILE_FINDER_LOADERS = tuple(
    (suffix, loader) for loader, suffixes in _STANDARD_FILE_FINDER_LOADER_IDENTITY for suffix in suffixes
)
_STANDARD_FILE_FINDER_PATH_HOOK_CODE = FileFinder.path_hook(*_STANDARD_FILE_FINDER_LOADER_DETAILS).__code__
_TRUSTED_FILE_FINDER_METHODS = tuple(
    (name, getattr(FileFinder, name)) for name in ("__init__", "find_spec", "_get_spec", "_fill_cache")
)
_TRUSTED_ZIPIMPORTER_METHODS = tuple(
    (name, getattr(zipimporter, name))
    for name in ("__init__", "find_spec", "get_code", "get_data", "get_filename", "get_source", "is_package")
)
_MAX_CLASS_INSTANCE_ALIASES = 128
_MAX_INHERITED_CLASS_METHODS = 128
_MAX_WILDCARD_IMPORTS = 16
_MAX_WILDCARD_REEXPORT_DEPTH = 4
_MAX_SHORT_SINK_DEPTH = 2
_MAX_DISTRIBUTIONS_PER_TOP_LEVEL = 16
_MAX_TRUSTED_PTH_FILES = 64
_MAX_TRUSTED_PTH_BYTES = 64 * 1024
_MAX_TRUSTED_PTH_PATHS = 64
_CONTROLLED_GETATTR_DISPATCH_SINK = "builtins.getattr.__call__"
_IMPORT_EXECUTION_SINK = "builtins.__import__"
_IMPORT_EXECUTION_SAFE_MODULES = frozenset(sys.builtin_module_names)
# Only modules whose import cannot resolve additional shadowable Python modules
# are safe here. pathlib and subprocess transitively import modules such as
# fnmatch and selectors, so a sibling shadow can still execute during unpickling.
_REVIEWED_INERT_STDLIB_IMPORTS = frozenset({"os"})
_TRUSTED_STDLIB_PATHS = tuple(
    Path(path).resolve() for name in ("stdlib", "platstdlib") if (path := sysconfig.get_path(name))
)
_TRUSTED_SITE_PACKAGE_PATHS = tuple(
    Path(path).resolve() for name in ("purelib", "platlib") if (path := sysconfig.get_path(name))
)


def _site_package_root_from_pth_value(value: str, trusted_root: Path) -> Path | None:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = trusted_root / candidate
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved.name not in {"site-packages", "dist-packages"}:
        return None
    try:
        return resolved if resolved.is_dir() else None
    except OSError:
        return None


def _pth_delegated_site_package_paths(pth_path: Path, trusted_root: Path) -> tuple[Path, ...]:
    try:
        if pth_path.stat().st_size > _MAX_TRUSTED_PTH_BYTES:
            return ()
        content = pth_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ()

    paths: list[Path] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        values: list[str] = []
        if line.startswith(("import ", "import\t")):
            try:
                tree = ast.parse(line, filename=str(pth_path))
            except SyntaxError:
                continue
            for statement in tree.body:
                if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
                    continue
                node = statement.value
                if len(node.args) != 1 or node.keywords:
                    continue
                function = node.func
                argument = node.args[0]
                if not (
                    isinstance(function, ast.Attribute)
                    and isinstance(function.value, ast.Name)
                    and function.value.id == "site"
                    and function.attr == "addsitedir"
                    and isinstance(argument, ast.Constant)
                    and isinstance(argument.value, str)
                ):
                    continue
                values.append(argument.value)
        else:
            values.append(line)

        for value in values:
            path = _site_package_root_from_pth_value(value, trusted_root)
            if path is not None and path not in paths:
                paths.append(path)
                if len(paths) >= _MAX_TRUSTED_PTH_PATHS:
                    return tuple(paths)
    return tuple(paths)


def _trusted_delegated_site_package_paths() -> tuple[Path, ...]:
    paths: list[Path] = []
    files_seen = 0
    for trusted_root in _TRUSTED_SITE_PACKAGE_PATHS:
        try:
            pth_paths = trusted_root.glob("*.pth")
            for pth_path in pth_paths:
                if files_seen >= _MAX_TRUSTED_PTH_FILES:
                    return tuple(paths)
                files_seen += 1
                for path in _pth_delegated_site_package_paths(pth_path, trusted_root):
                    if path not in paths:
                        paths.append(path)
                        if len(paths) >= _MAX_TRUSTED_PTH_PATHS:
                            return tuple(paths)
        except OSError:
            continue
    return tuple(paths)


# Active-environment .pth files are trusted startup configuration. They may
# delegate additional installed-package roots without making every venv-shaped
# directory on sys.path trusted.
_TRUSTED_DELEGATED_SITE_PACKAGE_PATHS = _trusted_delegated_site_package_paths()
_IMPORT_AFFECTING_MODULE_NAMES = frozenset({"__loader__", "__package__", "__path__", "__spec__"})
_TRUSTED_IMPORT_ONLY_REFERENCES = frozenset(
    {
        ("_frozen_importlib", "ModuleSpec"),
        ("_sitebuiltins", "_Helper"),
        ("_xxsubinterpreters", "create"),
        ("aiobotocore.credentials", "AioProcessProvider"),
        ("argparse", "Namespace"),
        ("botocore.credentials", "ProcessProvider"),
        ("configparser", "ConfigParser"),
        ("concurrent.futures", "Future"),
        ("concurrent.futures", "Future.add_done_callback"),
        ("dill", "dump"),
        ("ipaddress", "IPv4Address"),
        ("string", "Formatter"),
        ("string", "Formatter._vformat"),
        ("string", "Formatter.vformat"),
        ("string", "Template"),
        ("string", "Template.safe_substitute"),
        ("string", "Template.substitute"),
        ("statistics", "mean"),
        ("tarfile", "TarInfo"),
        ("tempfile", "gettempdir"),
        ("tokenize", "generate_tokens"),
        ("weakref", "WeakMethod"),
        ("weakref", "proxy"),
        ("weakref", "ref"),
        ("zipfile", "ZipInfo"),
    }
)
_LEGACY_BUILTIN_EXCEPTION_NAMES = frozenset(
    {
        "ArithmeticError",
        "AssertionError",
        "AttributeError",
        "BaseException",
        "BufferError",
        "BytesWarning",
        "DeprecationWarning",
        "EOFError",
        "EnvironmentError",
        "Exception",
        "FloatingPointError",
        "FutureWarning",
        "GeneratorExit",
        "IOError",
        "ImportError",
        "ImportWarning",
        "IndentationError",
        "IndexError",
        "KeyError",
        "KeyboardInterrupt",
        "LookupError",
        "MemoryError",
        "NameError",
        "NotImplementedError",
        "OSError",
        "OverflowError",
        "PendingDeprecationWarning",
        "ReferenceError",
        "RuntimeError",
        "RuntimeWarning",
        "StandardError",
        "StopIteration",
        "SyntaxError",
        "SyntaxWarning",
        "SystemError",
        "SystemExit",
        "TabError",
        "TypeError",
        "UnboundLocalError",
        "UnicodeDecodeError",
        "UnicodeEncodeError",
        "UnicodeError",
        "UnicodeTranslateError",
        "UnicodeWarning",
        "UserWarning",
        "ValueError",
        "VMSError",
        "Warning",
        "WindowsError",
        "ZeroDivisionError",
    }
)
_TRUSTED_FRAMEWORK_RECONSTRUCTION_REFERENCES = frozenset(
    {
        ("joblib.numpy_pickle", "NumpyArrayWrapper"),
        ("numpy", "dtype"),
        ("numpy", "ndarray"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "scalar"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy.core.multiarray", "scalar"),
        ("torch", "BFloat16Storage"),
        ("torch", "BoolStorage"),
        ("torch", "ByteStorage"),
        ("torch", "CharStorage"),
        ("torch", "ComplexDoubleStorage"),
        ("torch", "ComplexFloatStorage"),
        ("torch", "DoubleStorage"),
        ("torch", "FloatStorage"),
        ("torch", "HalfStorage"),
        ("torch", "IntStorage"),
        ("torch", "LongStorage"),
        ("torch", "QInt32Storage"),
        ("torch", "QInt8Storage"),
        ("torch", "QUInt2x4Storage"),
        ("torch", "QUInt4x2Storage"),
        ("torch", "QUInt8Storage"),
        ("torch", "ShortStorage"),
        ("torch", "Size"),
        ("torch", "Storage"),
        ("torch", "UntypedStorage"),
        ("torch", "_rebuild_tensor"),
        ("torch", "_rebuild_tensor_v2"),
        ("torch._tensor", "_rebuild_from_type_v2"),
        ("torch._utils", "_rebuild_device_tensor_from_numpy"),
        ("torch._utils", "_rebuild_meta_tensor_no_storage"),
        ("torch._utils", "_rebuild_nested_tensor"),
        ("torch._utils", "_rebuild_parameter"),
        ("torch._utils", "_rebuild_parameter_with_state"),
        ("torch._utils", "_rebuild_qtensor"),
        ("torch._utils", "_rebuild_sparse_tensor"),
        ("torch._utils", "_rebuild_tensor"),
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_tensor_v3"),
        ("torch._utils", "_rebuild_wrapper_subclass"),
        ("torch.serialization", "_get_layout"),
    }
)
_TRUSTED_IMPORT_ONLY_REFERENCES |= _TRUSTED_FRAMEWORK_RECONSTRUCTION_REFERENCES
_TRUSTED_UNRESOLVED_IMPORT_ONLY_REFERENCES = (
    frozenset(
        {
            ("pathlib._local", "PurePath"),
            ("pathlib._local", "PurePosixPath"),
            ("pathlib._local", "PureWindowsPath"),
        }
    )
    | _TRUSTED_FRAMEWORK_RECONSTRUCTION_REFERENCES
)
_PICKLE_CONSTRUCTOR_ENTRYPOINT_METHODS = ("__new__", "__init__")
_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS = ("__setstate__",)
_PICKLE_BUILD_ENTRYPOINT_METHODS = (
    "__getattribute__",
    "__getattr__",
    *_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS,
    "__setattr__",
)
_PICKLE_LIFECYCLE_ENTRYPOINT_METHOD_SET = frozenset(_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS)
_PICKLE_ENTERED_IMPORT_EXECUTION_METHODS = (
    *_PICKLE_CONSTRUCTOR_ENTRYPOINT_METHODS,
    *_PICKLE_BUILD_ENTRYPOINT_METHODS,
)
_INHERITED_CLASS_ENTRYPOINT_METHODS = (
    *_PICKLE_CONSTRUCTOR_ENTRYPOINT_METHODS,
    *_PICKLE_BUILD_ENTRYPOINT_METHODS,
)
_SHARED_SOURCE_SENSITIVE_CACHE_DEPTH: ContextVar[int] = ContextVar(
    "_SHARED_SOURCE_SENSITIVE_CACHE_DEPTH",
    default=0,
)
_SHARED_SOURCE_SENSITIVE_SNAPSHOT: ContextVar[_SharedSourceSnapshot | None] = ContextVar(
    "_SHARED_SOURCE_SENSITIVE_SNAPSHOT",
    default=None,
)
_SHARED_SOURCE_SENSITIVE_CACHE_LOCK = threading.RLock()
_CachedFunctionT = TypeVar("_CachedFunctionT", bound=Callable[..., object])


class _CacheClearable(Protocol):
    def cache_clear(self) -> None:
        pass


_SOURCE_SENSITIVE_CACHED_FUNCTIONS: set[_CacheClearable] = set()


class _CallGraphAnalysisLimitError(RuntimeError):
    """Raised when bounded call-graph enrichment cannot complete safely."""

    def __init__(
        self,
        message: str,
        *,
        partial_findings: tuple[CallGraphFinding, ...] = (),
        partial_startup_hook_write_findings: tuple[StartupHookWriteFinding, ...] = (),
        partial_path: tuple[str, ...] | None = None,
    ) -> None:
        super().__init__(message)
        self.partial_findings = partial_findings
        self.partial_startup_hook_write_findings = partial_startup_hook_write_findings
        self.partial_path = partial_path


class _SourceReadTooLargeError(OSError):
    """Raised when a source-related file exceeds its bounded read budget."""


@dataclass
class _SharedSourceSnapshot:
    search_context: tuple[str, ...]
    resolution_context: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]
    resolution_fingerprints: dict[str, bytes | str | None] = field(default_factory=dict)
    module_sources: dict[str, str] = field(default_factory=dict)
    loaded_module_sources: dict[str, str] = field(default_factory=dict)
    loaded_package_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)
    read_fingerprints: dict[str, tuple[int, bool, bytes | None]] = field(default_factory=dict)
    generation: int = 0
    stable: bool = True
    reusable: bool = True
    lock: Any = field(default_factory=threading.RLock)


def _register_source_sensitive_cache(function: _CachedFunctionT) -> _CachedFunctionT:
    _SOURCE_SENSITIVE_CACHED_FUNCTIONS.add(cast(_CacheClearable, function))
    return function


@_register_source_sensitive_cache
@lru_cache(maxsize=1)
def _installed_package_distributions() -> Mapping[str, list[str]]:
    try:
        return packages_distributions()
    except Exception:
        return {}


@_register_source_sensitive_cache
@lru_cache(maxsize=256)
def _installed_distribution_roots(top_level_name: str) -> tuple[Path, ...]:
    roots: list[Path] = []
    distribution_names = _installed_package_distributions().get(top_level_name, ())
    for distribution_name in distribution_names[:_MAX_DISTRIBUTIONS_PER_TOP_LEVEL]:
        try:
            installed_distribution = distribution(distribution_name)
            metadata_location = getattr(installed_distribution, "_path", None)
            if metadata_location is None:
                continue
            metadata_path = Path(str(metadata_location)).resolve()
            root = Path(str(installed_distribution.locate_file(""))).resolve()
        except Exception:
            continue
        if not _path_is_in_trusted_package_environment(metadata_path):
            continue
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def _path_is_in_trusted_package_environment(path: Path) -> bool:
    trusted_paths = (*_TRUSTED_SITE_PACKAGE_PATHS, *_TRUSTED_DELEGATED_SITE_PACKAGE_PATHS)
    return any(path.is_relative_to(trusted_path) for trusted_path in trusted_paths)


_CLASS_ENTRYPOINT_METHODS = (
    "__getattribute__",
    "__getattr__",
    "__call__",
    "__iter__",
    "__next__",
    "__enter__",
    "__exit__",
    "__new__",
    *_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS,
    "__setattr__",
    "__init__",
)
_CLASS_ENTRYPOINT_METHOD_SET = frozenset(_CLASS_ENTRYPOINT_METHODS)
_RCE_SINK_EXACT = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        _IMPORT_EXECUTION_SINK,
        "builtins.compile",
        "builtins.eval",
        "builtins.exec",
        _CONTROLLED_GETATTR_DISPATCH_SINK,
        "dill.load",
        "dill.loads",
        "importlib.import_module",
        "marshal.load",
        "marshal.loads",
        "pickle.load",
        "pickle.loads",
        "runpy.run_module",
        "runpy.run_path",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
        "yaml.load",
        "yaml.unsafe_load",
    }
)
_RCE_SINK_PREFIXES = ("os.exec", "os.posix_spawn", "os.spawn", "os.system", "os.popen")
_FILE_OPEN_SINK_EXACT = frozenset(
    {
        "builtins.open",
        "codecs.open",
        "io.open",
    }
)
_FILE_WRITE_METHODS = frozenset({"write", "writelines"})
_BUILTIN_CALLS = frozenset({"__import__", "compile", "eval", "exec", "open"})
_TCL_CALL_DISPATCH_SUFFIXES = (".tk.call", "._tk.call")
_TCL_EVAL_DISPATCH_SUFFIXES = (".tk.eval", "._tk.eval")
_SUBPROCESS_DISPATCH_SUFFIXES = (
    ".subprocess.Popen",
    ".subprocess.call",
    ".subprocess.check_call",
    ".subprocess.check_output",
    ".subprocess.run",
)
_STATIC_IMPORT_REFERENCE_ALIAS_SUFFIXES = {
    "six.moves.builtins.__import__": "builtins.__import__",
    "six.moves.builtins.compile": "builtins.compile",
    "six.moves.builtins.eval": "builtins.eval",
    "six.moves.builtins.exec": "builtins.exec",
    "six.moves.cPickle.load": "pickle.load",
    "six.moves.cPickle.loads": "pickle.loads",
    "six.moves.getoutput": "subprocess.getoutput",
}
_SHORT_SINK_PRIORITY_TOKENS = (
    "subprocess",
    "popen",
    "spawn",
    "create_io",
    "fork_exec",
)
_SHORT_SINK_SECONDARY_PRIORITY_TOKENS = ("exec", "system", "run")
_CALLABLE_SINGLETON_ALIASES = {
    ("builtins", "help"): (("_sitebuiltins", "_Helper.__call__"),),
}
_TORCH_EXTENSION_GLOBALS = frozenset(
    {
        "Size",
        "Tensor",
        "bfloat16",
        "bits16",
        "bits1x8",
        "bits2x4",
        "bits4x2",
        "bits8",
        "bool",
        "cdouble",
        "cfloat",
        "chalf",
        "channels_last",
        "channels_last_3d",
        "complex128",
        "complex32",
        "complex64",
        "contiguous_format",
        "device",
        "double",
        "float",
        "float16",
        "float32",
        "float64",
        "float8_e4m3fn",
        "float8_e4m3fnuz",
        "float8_e5m2",
        "float8_e5m2fnuz",
        "half",
        "int",
        "int16",
        "int32",
        "int64",
        "int8",
        "layout",
        "long",
        "memory_format",
        "per_channel_affine",
        "per_channel_affine_float_qparams",
        "per_channel_symmetric",
        "per_tensor_affine",
        "per_tensor_symmetric",
        "preserve_format",
        "qint32",
        "qint8",
        "quint2x4",
        "quint4x2",
        "quint8",
        "short",
        "sparse_bsc",
        "sparse_bsr",
        "sparse_coo",
        "sparse_csc",
        "sparse_csr",
        "strided",
        "uint1",
        "uint16",
        "uint2",
        "uint3",
        "uint32",
        "uint4",
        "uint5",
        "uint6",
        "uint64",
        "uint7",
        "uint8",
    }
)
_NEWOBJ_OPCODES = frozenset({"NEWOBJ", "NEWOBJ_EX"})
_CONSTRUCTOR_OPCODES = frozenset({"INST", "OBJ", "REDUCE"})
_BUILD_OPCODES = frozenset({"BUILD"})


@dataclass(frozen=True)
class CallGraphFinding:
    module: str
    name: str
    import_reference: str
    sink: str
    call_path: tuple[str, ...]


@dataclass(frozen=True)
class StartupHookWriteFinding:
    opener_module: str
    opener_name: str
    writer_module: str
    writer_name: str
    opener_import_reference: str
    writer_import_reference: str
    open_sink: str
    write_sink: str
    opener_call_path: tuple[str, ...]
    writer_call_path: tuple[str, ...]


@dataclass(frozen=True)
class UnanalyzedCallGraphReference:
    module: str
    name: str
    import_reference: str
    reason: str


@dataclass(frozen=True)
class _ModuleAnalysis:
    module: str
    source_path: str
    aliases: dict[str, str]
    direct_names: frozenset[str]
    calls_by_function: dict[str, tuple[str, ...]]
    class_entrypoints: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class _WildcardExportSummary:
    direct_names: frozenset[str]
    wildcard_imports: tuple[str, ...]


@dataclass(frozen=True)
class _ModuleSourceContext:
    source_path: Path
    module_statements: tuple[ast.stmt, ...]
    is_package: bool


@dataclass(frozen=True)
class _ClassSourceContext:
    module_name: str
    class_node: ast.ClassDef
    aliases: dict[str, str]
    local_defs: set[str]
    local_class_nodes: dict[str, ast.ClassDef]


@dataclass(frozen=True)
class _InheritedClassMethod:
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module_name: str
    aliases: dict[str, str]
    local_defs: set[str]


@dataclass(frozen=True)
class _ImportCallPath:
    module: str
    name: str
    import_reference: str
    call_path: tuple[str, ...]


def find_dangerous_call_graphs(
    import_references: object,
    callable_invocations: object | None = None,
) -> tuple[CallGraphFinding, ...]:
    _clear_source_sensitive_caches()
    findings: list[CallGraphFinding] = []
    seen_findings: set[tuple[str, str, tuple[str, ...]]] = set()
    argument_shapes = _callable_invocation_argument_shapes(callable_invocations)
    callable_references = _iter_callable_invocation_references(callable_invocations)
    invoked_references = {
        (str(reference.get("module", "")), str(reference.get("name", "")))
        for reference in callable_references
        if str(reference.get("module", "")) and str(reference.get("name", ""))
    }

    analysis_limit_error: _CallGraphAnalysisLimitError | None = None
    for reference in _iter_call_graph_references(import_references, callable_references, invoked_references):
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        if not module or not name:
            continue

        try:
            entrypoints = _call_graph_entrypoints_for_reference(module, name, reference)
        except _CallGraphAnalysisLimitError as error:
            if analysis_limit_error is None:
                analysis_limit_error = error
            continue
        if not entrypoints:
            continue
        allow_invoked_non_lifecycle_entrypoint = _is_explicit_method_import_reference(name)
        try:
            sink_path = _first_matching_path(entrypoints, _find_sink_path)
        except _CallGraphAnalysisLimitError as error:
            if analysis_limit_error is None:
                analysis_limit_error = error
            sink_path = error.partial_path
        if sink_path is None:
            for entrypoint in entrypoints:
                entrypoint_arg_count = _pickle_entrypoint_positional_arg_count(reference, entrypoint)
                if entrypoint_arg_count is None:
                    continue
                try:
                    sink_path = _find_invoked_import_execution_path(
                        entrypoint,
                        entrypoint_arg_count,
                        allow_non_lifecycle_entrypoint=allow_invoked_non_lifecycle_entrypoint,
                    )
                except _CallGraphAnalysisLimitError as error:
                    if analysis_limit_error is None:
                        analysis_limit_error = error
                    sink_path = error.partial_path
                if sink_path is not None:
                    break
        if sink_path is None:
            for positional_arg_count, keyword_arg_names in argument_shapes.get((module, name), ()):
                try:
                    sink_path = _first_matching_path(
                        entrypoints,
                        _invoked_import_execution_path_callback(
                            positional_arg_count,
                            keyword_arg_names,
                            allow_non_lifecycle_entrypoint=allow_invoked_non_lifecycle_entrypoint,
                        ),
                    )
                except _CallGraphAnalysisLimitError as error:
                    if analysis_limit_error is None:
                        analysis_limit_error = error
                    sink_path = error.partial_path
                if sink_path is not None:
                    break
        if sink_path is None:
            continue

        finding_key = (module, name, sink_path)
        if finding_key in seen_findings:
            continue
        seen_findings.add(finding_key)

        sink = sink_path[-1]
        findings.append(
            CallGraphFinding(
                module=module,
                name=name,
                import_reference=f"{module}.{name}",
                sink=sink,
                call_path=sink_path,
            )
        )
        if len(findings) >= _MAX_IMPORT_REFERENCES:
            break
    if analysis_limit_error is not None:
        raise _CallGraphAnalysisLimitError(
            str(analysis_limit_error),
            partial_findings=tuple(findings),
        ) from analysis_limit_error
    return tuple(findings)


def find_startup_hook_write_call_graphs(
    import_references: object,
    callable_invocations: object | None = None,
    *,
    callable_invocations_complete: bool = True,
) -> tuple[StartupHookWriteFinding, ...]:
    _clear_source_sensitive_caches()
    if callable_invocations is not None and not callable_invocations_complete:
        return ()
    openers: list[_ImportCallPath] = []
    writers: list[_ImportCallPath] = []
    seen: set[tuple[str, str]] = set()
    callable_references = _iter_callable_invocation_references(callable_invocations)
    invocations_by_reference: dict[tuple[str, str], list[dict[str, object]]] = {}
    for reference in callable_references:
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        if module and name:
            invocations_by_reference.setdefault((module, name), []).append(reference)
    require_invocations = callable_invocations is not None
    analysis_limit_error: _CallGraphAnalysisLimitError | None = None
    for reference in _iter_import_references(import_references):
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        if not module or not name or (module, name) in seen:
            continue
        invocation_references = invocations_by_reference.get((module, name), ())
        if require_invocations and not invocation_references:
            continue
        seen.add((module, name))

        try:
            entrypoints = (
                _dedupe_calls(
                    tuple(
                        entrypoint
                        for invocation_reference in invocation_references
                        for entrypoint in _call_graph_entrypoints_for_reference(
                            module,
                            name,
                            invocation_reference,
                        )
                    )
                )
                if require_invocations
                else _safe_call_graph_entrypoints(f"{module}.{name}")
            )
        except _CallGraphAnalysisLimitError as error:
            if analysis_limit_error is None:
                analysis_limit_error = error
            continue
        if not entrypoints:
            continue
        try:
            has_sink_path = _first_matching_path(entrypoints, _find_sink_path) is not None
        except _CallGraphAnalysisLimitError as error:
            if analysis_limit_error is None:
                analysis_limit_error = error
            has_sink_path = error.partial_path is not None
        if has_sink_path:
            continue
        try:
            open_path = _first_matching_path(entrypoints, _find_file_open_path)
        except _CallGraphAnalysisLimitError as error:
            if analysis_limit_error is None:
                analysis_limit_error = error
            open_path = error.partial_path
        if open_path is not None:
            openers.append(
                _ImportCallPath(
                    module=module,
                    name=name,
                    import_reference=f"{module}.{name}",
                    call_path=open_path,
                )
            )
        try:
            write_path = _first_matching_path(entrypoints, _find_file_write_path)
        except _CallGraphAnalysisLimitError as error:
            if analysis_limit_error is None:
                analysis_limit_error = error
            write_path = error.partial_path
        if write_path is not None:
            writers.append(
                _ImportCallPath(
                    module=module,
                    name=name,
                    import_reference=f"{module}.{name}",
                    call_path=write_path,
                )
            )

    findings = _materialize_startup_hook_write_findings(openers, writers)
    if analysis_limit_error is not None:
        raise _CallGraphAnalysisLimitError(
            str(analysis_limit_error),
            partial_startup_hook_write_findings=findings,
        ) from analysis_limit_error
    return findings


def _materialize_startup_hook_write_findings(
    openers: list[_ImportCallPath],
    writers: list[_ImportCallPath],
) -> tuple[StartupHookWriteFinding, ...]:
    if not openers or not writers:
        return ()

    findings: list[StartupHookWriteFinding] = []
    seen_pairs: set[tuple[str, str]] = set()
    for opener in openers:
        for writer in writers:
            pair = (opener.import_reference, writer.import_reference)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            findings.append(
                StartupHookWriteFinding(
                    opener_module=opener.module,
                    opener_name=opener.name,
                    writer_module=writer.module,
                    writer_name=writer.name,
                    opener_import_reference=opener.import_reference,
                    writer_import_reference=writer.import_reference,
                    open_sink=opener.call_path[-1],
                    write_sink=writer.call_path[-1],
                    opener_call_path=opener.call_path,
                    writer_call_path=writer.call_path,
                )
            )
            if len(findings) >= _MAX_IMPORT_REFERENCES:
                return tuple(findings)
    return tuple(findings)


def find_unanalyzed_callable_call_graph_references(
    callable_invocations: object | None,
) -> tuple[UnanalyzedCallGraphReference, ...]:
    _clear_source_sensitive_caches()
    references: list[UnanalyzedCallGraphReference] = []
    seen: set[tuple[str, str]] = set()
    callable_references = _iter_callable_invocation_references(callable_invocations)
    incomplete_newobj_ex_references = {
        (str(reference.get("module", "")), str(reference.get("name", "")))
        for reference in callable_references
        if str(reference.get("opcode", "")) == "NEWOBJ_EX" and _complete_keyword_arg_names(reference) is None
    }

    for reference in callable_references:
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        if not module or not name or (module, name) in seen:
            continue
        seen.add((module, name))
        if _is_skippable_torch_extension_global_reference(module, name) or _unresolved_trusted_import_reference_is_safe(
            module, name
        ):
            continue
        if (module, name) in incomplete_newobj_ex_references:
            references.append(
                UnanalyzedCallGraphReference(
                    module=module,
                    name=name,
                    import_reference=f"{module}.{name}",
                    reason="invocation_metadata_incomplete",
                )
            )
            if len(references) >= _MAX_IMPORT_REFERENCES:
                break
            continue
        if _call_graph_entrypoints_for_reference(module, name, reference):
            continue
        reason = _call_graph_source_unavailable_reason(module)
        if reason is None:
            continue
        references.append(
            UnanalyzedCallGraphReference(
                module=module,
                name=name,
                import_reference=f"{module}.{name}",
                reason=reason,
            )
        )
        if len(references) >= _MAX_IMPORT_REFERENCES:
            break
    return tuple(references)


def find_analyzed_callable_call_graph_global_positions(
    callable_invocations: object | None,
) -> frozenset[int]:
    """Return invoked global positions with source-backed call-graph entrypoints."""
    _clear_source_sensitive_caches()
    positions: set[int] = set()
    for reference in _iter_callable_invocation_references(callable_invocations):
        global_position = reference.get("global_position")
        if type(global_position) is not int:
            continue
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        if module and name and _call_graph_reference_is_analyzed(module, name, reference):
            positions.add(global_position)
    return frozenset(positions)


def module_initialization_is_proven_inert(module_name: str) -> bool:
    """Return whether importing a source-backed module has no executable initialization."""
    parts = _bounded_module_name_parts(module_name)
    if parts is None:
        return False
    for index in range(1, len(parts) + 1):
        context = _module_source_context(".".join(parts[:index]))
        if context is None or (index < len(parts) and not context.is_package):
            return False
        if not _module_source_context_initialization_is_proven_inert(context):
            return False
    return True


def _module_source_context_initialization_is_proven_inert(context: _ModuleSourceContext) -> bool:
    guarded_names = {"__getattr__", *_IMPORT_AFFECTING_MODULE_NAMES}
    return not any(
        _module_statement_binds_name(statement, name)
        for statement in context.module_statements
        for name in guarded_names
    ) and all(_module_initialization_statement_is_inert(statement) for statement in context.module_statements)


def import_only_reference_is_proven_trusted(module_name: str, name: str) -> bool:
    """Return whether a known-safe reference resolves from a trusted installation path."""
    if _legacy_pickle_compat_reference_is_trusted(module_name, name):
        return True
    origin_kind = _trusted_module_origin_kind(module_name)
    reference = (module_name, name)
    return reference in _TRUSTED_IMPORT_ONLY_REFERENCES and (
        origin_kind in {"stdlib", "site_packages"}
        or (origin_kind == "unresolved" and reference in _TRUSTED_UNRESOLVED_IMPORT_ONLY_REFERENCES)
    )


def import_only_module_requires_origin_review(module_name: str, name: str) -> bool:
    """Return whether a module resolves outside trusted install paths."""
    if module_name == "__builtin__" or _legacy_pickle_compat_reference_is_trusted(module_name, name):
        return False
    origin_kind = _trusted_module_origin_kind(module_name)
    return origin_kind not in {"stdlib", "site_packages"} and not (
        origin_kind == "unresolved" and (module_name, name) in _TRUSTED_UNRESOLVED_IMPORT_ONLY_REFERENCES
    )


def _legacy_pickle_compat_reference_is_trusted(module_name: str, name: str) -> bool:
    return (module_name == "copy_reg" and name == "_reconstructor") or (
        module_name == "exceptions" and name in _LEGACY_BUILTIN_EXCEPTION_NAMES
    )


def _unresolved_trusted_import_reference_is_safe(module_name: str, name: str) -> bool:
    return (module_name, name) in _TRUSTED_UNRESOLVED_IMPORT_ONLY_REFERENCES and _trusted_module_origin_kind(
        module_name
    ) == "unresolved"


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _trusted_module_origin_kind(module_name: str) -> str | None:
    parts = _bounded_module_name_parts(module_name)
    if parts is None:
        return None
    _track_shared_source_candidates(parts)
    try:
        standard_spec = BuiltinImporter.find_spec(module_name)
        if standard_spec is None:
            standard_spec = FrozenImporter.find_spec(module_name)
        if standard_spec is None:
            standard_spec = _find_standard_filesystem_spec(module_name)
    except Exception:
        return None
    loaded_module = sys.modules.get(module_name)
    loaded_spec = getattr(loaded_module, "__spec__", None)
    spec: ModuleSpec | None
    if isinstance(loaded_spec, ModuleSpec) and (standard_spec is None or loaded_spec.origin == standard_spec.origin):
        spec = loaded_spec
    else:
        if not isinstance(loaded_spec, ModuleSpec) and (
            _untrusted_meta_path_finder_precedes(BuiltinImporter, module_name)
            or _untrusted_meta_path_finder_precedes(FrozenImporter, module_name)
            or _untrusted_meta_path_finder_precedes(PathFinder, module_name)
            or _has_untrusted_path_hook()
        ):
            return None
        spec = standard_spec
    if spec is None:
        return "unresolved"
    if _module_spec_uses_builtin_or_frozen_loader(spec):
        return "stdlib"
    if spec.origin is None:
        return None
    try:
        origin = Path(spec.origin).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if _path_is_in_trusted_package_environment(origin):
        return "site_packages"
    top_level_name = parts[0]
    if any(origin.is_relative_to(path) for path in _installed_distribution_roots(top_level_name)):
        _mark_shared_source_snapshot_unreusable()
        return "site_packages"
    if any(origin.is_relative_to(path) for path in _TRUSTED_STDLIB_PATHS):
        return "stdlib"
    return None


def _mark_shared_source_snapshot_unreusable() -> None:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is not None:
        with snapshot.lock:
            snapshot.reusable = False


def _bounded_module_name_parts(module_name: str) -> tuple[str, ...] | None:
    if len(module_name) > _MAX_MODULE_NAME_CHARS:
        _mark_shared_source_snapshot_unreusable()
        return None
    parts = tuple(module_name.split("."))
    if (
        not parts
        or len(parts) > _MAX_MODULE_COMPONENTS
        or any(not part or "/" in part or "\\" in part for part in parts)
    ):
        _mark_shared_source_snapshot_unreusable()
        return None
    return parts


@contextmanager
def shared_source_sensitive_caches() -> Iterator[None]:
    """Share source analysis until a bounded source snapshot changes."""
    depth = _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.get()
    if depth > 0:
        snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
        if snapshot is None:
            token = _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.set(depth + 1)
            try:
                yield
            finally:
                _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.reset(token)
        else:
            with snapshot.lock:
                token = _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.set(depth + 1)
                try:
                    yield
                finally:
                    _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.reset(token)
        return

    with _SHARED_SOURCE_SENSITIVE_CACHE_LOCK:
        _clear_source_sensitive_caches_now()
        resolution_context = _source_resolution_context()
        snapshot_token = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.set(
            _SharedSourceSnapshot(
                search_context=_source_search_context(),
                resolution_context=resolution_context,
                reusable=_resolution_context_is_reusable(resolution_context),
            )
        )
        token = _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.set(1)
        try:
            yield
        finally:
            _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.reset(token)
            _SHARED_SOURCE_SENSITIVE_SNAPSHOT.reset(snapshot_token)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _safe_call_graph_entrypoints(function_name: str) -> tuple[str, ...]:
    try:
        return _call_graph_entrypoints(function_name)
    except _CallGraphAnalysisLimitError:
        raise
    except Exception:
        return ()


def _first_matching_path(
    entrypoints: Iterable[str],
    path_for: Callable[[str], tuple[str, ...] | None],
) -> tuple[str, ...] | None:
    analysis_limit_error: _CallGraphAnalysisLimitError | None = None
    for entrypoint in entrypoints:
        try:
            path = path_for(entrypoint)
        except _CallGraphAnalysisLimitError as error:
            if analysis_limit_error is None:
                analysis_limit_error = error
            continue
        except Exception:
            continue
        if path is not None:
            if analysis_limit_error is not None:
                raise _CallGraphAnalysisLimitError(
                    str(analysis_limit_error), partial_path=path
                ) from analysis_limit_error
            return path
    if analysis_limit_error is not None:
        raise analysis_limit_error
    return None


def _invoked_import_execution_path_callback(
    positional_arg_count: int,
    keyword_arg_names: tuple[str, ...] | None = (),
    *,
    allow_non_lifecycle_entrypoint: bool = False,
) -> Callable[[str], tuple[str, ...] | None]:
    def path_for(entrypoint: str) -> tuple[str, ...] | None:
        return _find_invoked_import_execution_path(
            entrypoint,
            positional_arg_count,
            keyword_arg_names,
            allow_non_lifecycle_entrypoint=allow_non_lifecycle_entrypoint,
        )

    return path_for


def _iter_call_graph_references(
    import_references: object,
    callable_references: tuple[dict[str, object], ...],
    invoked_references: set[tuple[str, str]],
) -> tuple[dict[str, object], ...]:
    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    seen_invocations: set[tuple[str, str, str, int | None, bool | None, tuple[str, ...] | None]] = set()
    for item in callable_references:
        module = str(item.get("module", ""))
        name = str(item.get("name", ""))
        if not module or not name or _is_skippable_torch_extension_global_reference(module, name):
            continue
        opcode = str(item.get("opcode", ""))
        positional_arg_count = item.get("positional_arg_count")
        invocation_key = (
            module,
            name,
            opcode,
            positional_arg_count if isinstance(positional_arg_count, int) else None,
            _optional_bool_reference_detail(item.get("build_uses_slot_state")),
            _complete_keyword_arg_names(item),
        )
        if invocation_key in seen_invocations:
            continue
        seen_invocations.add(invocation_key)
        normalized.append(dict(item))

    for item in _iter_import_references(import_references):
        module = str(item.get("module", ""))
        name = str(item.get("name", ""))
        if (
            not module
            or not name
            or (module, name) in seen
            or (module, name) in invoked_references
            or _is_skippable_torch_extension_global_reference(module, name)
        ):
            continue
        seen.add((module, name))
        normalized.append(dict(item))
    return tuple(normalized)


def _iter_import_references(import_references: object) -> tuple[dict[str, object], ...]:
    if not isinstance(import_references, list | tuple):
        return ()
    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for item in import_references:
        if not isinstance(item, Mapping):
            continue
        module = str(item.get("module", ""))
        name = str(item.get("name", ""))
        if not module or not name or (module, name) in seen:
            continue
        if _is_skippable_pytorch_storage_persistent_id_reference(item):
            continue
        seen.add((module, name))
        normalized.append(dict(item))
        if len(normalized) >= _MAX_IMPORT_REFERENCES:
            break
    return tuple(normalized)


def _optional_bool_reference_detail(value: object) -> bool | None:
    return value if type(value) is bool else None


def _complete_keyword_arg_names(reference: Mapping[str, object]) -> tuple[str, ...] | None:
    if str(reference.get("opcode", "")) != "NEWOBJ_EX":
        return ()
    if reference.get("keyword_args_complete") is not True:
        return None
    raw_names = reference.get("keyword_arg_names")
    if not isinstance(raw_names, list | tuple) or any(not isinstance(name, str) for name in raw_names):
        return None
    return tuple(raw_names)


def _iter_callable_invocation_references(callable_invocations: object | None) -> tuple[dict[str, object], ...]:
    if not isinstance(callable_invocations, list | tuple):
        return ()

    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, int | None, bool | None, tuple[str, ...] | None]] = set()
    for item in callable_invocations:
        if not isinstance(item, Mapping):
            continue
        module = str(item.get("module", ""))
        name = str(item.get("name", ""))
        if not module or not name:
            continue
        opcode = str(item.get("opcode", ""))
        positional_arg_count = item.get("positional_arg_count")
        for reference_module, reference_name in (
            (module, name),
            *_callable_singleton_aliases(module, name),
        ):
            reference_key = (
                reference_module,
                reference_name,
                opcode,
                positional_arg_count if isinstance(positional_arg_count, int) else None,
                _optional_bool_reference_detail(item.get("build_uses_slot_state")),
                _complete_keyword_arg_names(item),
            )
            if reference_key in seen:
                continue
            seen.add(reference_key)
            reference = dict(item)
            reference["module"] = reference_module
            reference["name"] = reference_name
            reference["import_reference"] = f"{reference_module}.{reference_name}"
            normalized.append(reference)
    return tuple(normalized)


def _is_explicit_method_import_reference(name: str) -> bool:
    return "." in name


def _call_graph_entrypoints_for_reference(
    module: str,
    name: str,
    reference: Mapping[str, object],
) -> tuple[str, ...]:
    entrypoints = _safe_call_graph_entrypoints(f"{module}.{name}")
    if not entrypoints:
        return ()
    if _is_explicit_method_import_reference(name):
        return entrypoints
    if _resolve_class_target(f"{module}.{name}") is None:
        return entrypoints
    opcode = str(reference.get("opcode", ""))
    if opcode in _NEWOBJ_OPCODES:
        if not isinstance(reference.get("positional_arg_count"), int):
            return _filter_class_entrypoints(entrypoints, (*_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS, "__new__"))
        return _filter_class_entrypoints(entrypoints, ("__new__",))
    if opcode in _BUILD_OPCODES:
        methods: tuple[str, ...] = _PICKLE_BUILD_ENTRYPOINT_METHODS
        if reference.get("build_uses_slot_state") is False:
            methods = tuple(method for method in methods if method != "__setattr__")
        return _filter_class_entrypoints(entrypoints, methods)
    if opcode in _CONSTRUCTOR_OPCODES:
        return _filter_class_entrypoints(entrypoints, _PICKLE_CONSTRUCTOR_ENTRYPOINT_METHODS)
    return entrypoints


def _pickle_entrypoint_positional_arg_count(
    reference: Mapping[str, object],
    entrypoint: str,
) -> int | None:
    if str(reference.get("opcode", "")) not in _BUILD_OPCODES:
        return None
    method_name = entrypoint.rpartition(".")[2]
    if method_name in {"__getattribute__", "__getattr__", "__setstate__"}:
        return 1
    if method_name == "__setattr__":
        return 2
    return None


def _call_graph_reference_is_analyzed(
    module: str,
    name: str,
    reference: Mapping[str, object],
) -> bool:
    if str(reference.get("opcode", "")) == "NEWOBJ_EX" and _complete_keyword_arg_names(reference) is None:
        return False
    return bool(_safe_call_graph_entrypoints(f"{module}.{name}"))


def _filter_class_entrypoints(entrypoints: tuple[str, ...], methods: tuple[str, ...]) -> tuple[str, ...]:
    class_entrypoints = tuple(
        entrypoint
        for entrypoint in entrypoints
        if any(entrypoint.endswith(f".{method}") for method in _CLASS_ENTRYPOINT_METHODS)
    )
    if not class_entrypoints:
        return entrypoints
    return tuple(
        entrypoint for entrypoint in class_entrypoints if any(entrypoint.endswith(f".{method}") for method in methods)
    )


def _callable_invocation_argument_shapes(
    callable_invocations: object | None,
) -> dict[tuple[str, str], tuple[tuple[int, tuple[str, ...] | None], ...]]:
    if not isinstance(callable_invocations, list | tuple):
        return {}

    shapes: dict[tuple[str, str], set[tuple[int, tuple[str, ...] | None]]] = {}
    for item in callable_invocations:
        if not isinstance(item, Mapping):
            continue
        module = str(item.get("module", ""))
        name = str(item.get("name", ""))
        positional_arg_count = item.get("positional_arg_count")
        keyword_arg_names = _complete_keyword_arg_names(item)
        if (
            not module
            or not name
            or isinstance(positional_arg_count, bool)
            or not isinstance(positional_arg_count, int)
            or positional_arg_count < 0
        ):
            continue
        for reference in ((module, name), *_callable_singleton_aliases(module, name)):
            shapes.setdefault(reference, set()).add((positional_arg_count, keyword_arg_names))
            if len(shapes) >= _MAX_IMPORT_REFERENCES:
                return _sorted_callable_invocation_argument_shapes(shapes)
    return _sorted_callable_invocation_argument_shapes(shapes)


def _sorted_callable_invocation_argument_shapes(
    shapes: Mapping[tuple[str, str], set[tuple[int, tuple[str, ...] | None]]],
) -> dict[tuple[str, str], tuple[tuple[int, tuple[str, ...] | None], ...]]:
    return {
        key: tuple(
            sorted(
                value,
                key=lambda shape: (shape[0], shape[1] is not None, shape[1] or ()),
                reverse=True,
            )
        )
        for key, value in shapes.items()
    }


def _callable_singleton_aliases(module: str, name: str) -> tuple[tuple[str, str], ...]:
    return _CALLABLE_SINGLETON_ALIASES.get((module, name), ())


def _is_pytorch_storage_persistent_id_reference(item: Mapping[str, object]) -> bool:
    return (
        item.get("pytorch_storage_persistent_id") is True
        and item.get("module") == "torch"
        and str(item.get("name", "")).endswith("Storage")
    )


def _is_skippable_pytorch_storage_persistent_id_reference(item: Mapping[str, object]) -> bool:
    if not _is_pytorch_storage_persistent_id_reference(item):
        return False
    source_path = _resolve_module_source("torch")
    return source_path is None or _is_library_source_path(str(source_path))


def _is_torch_extension_global_reference(module: str, name: str) -> bool:
    return module == "torch" and name in _TORCH_EXTENSION_GLOBALS


def _is_skippable_torch_extension_global_reference(module: str, name: str) -> bool:
    if not _is_torch_extension_global_reference(module, name):
        return False
    source_path = _resolve_module_source(module)
    if source_path is not None and not _is_library_source_path(str(source_path)):
        return False
    try:
        return not _has_static_torch_extension_global_target(module, name)
    except _CallGraphAnalysisLimitError:
        return False


@_register_source_sensitive_cache
@lru_cache(maxsize=256)
def _has_static_torch_extension_global_target(module: str, name: str) -> bool:
    analysis = _analyze_module(module)
    if analysis is None:
        return False
    full_name = f"{module}.{name}"
    if full_name in analysis.calls_by_function or full_name in analysis.class_entrypoints:
        return True
    if analysis.aliases.get(name) is not None:
        return True
    return _resolve_wildcard_reexport_alias(module, name) is not None


def has_unanalyzed_call_graph_import_references(import_references: object) -> bool:
    if not isinstance(import_references, list | tuple):
        return False
    seen: set[tuple[str, str]] = set()
    for item in import_references:
        if not isinstance(item, Mapping):
            continue
        module = str(item.get("module", ""))
        name = str(item.get("name", ""))
        if not module or not name:
            continue
        if _is_skippable_pytorch_storage_persistent_id_reference(
            item
        ) or _is_skippable_torch_extension_global_reference(module, name):
            continue
        seen.add((module, name))
        if len(seen) > _MAX_IMPORT_REFERENCES:
            return True
    return False


def _clear_source_sensitive_caches() -> None:
    if _SHARED_SOURCE_SENSITIVE_CACHE_DEPTH.get() > 0:
        snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
        if snapshot is None:
            return
        with snapshot.lock:
            if _shared_source_snapshot_is_current(snapshot):
                return
            _clear_source_sensitive_caches_now()
            _reset_shared_source_snapshot(snapshot)
        return

    with _SHARED_SOURCE_SENSITIVE_CACHE_LOCK:
        _clear_source_sensitive_caches_now()


def _clear_source_sensitive_caches_now() -> None:
    for function in _SOURCE_SENSITIVE_CACHED_FUNCTIONS:
        function.cache_clear()


def _source_search_context() -> tuple[str, ...]:
    return tuple(str(Path(entry or os.getcwd()).absolute()) for entry in sys.path)


def _bounded_hook_value_identity(value: object, depth: int = 0) -> str:
    if value is None or isinstance(value, bool | int | float):
        return repr(value)
    if isinstance(value, str):
        return repr(value) if len(value) <= 256 else _UNREUSABLE_HOOK_STATE_IDENTITY
    if isinstance(value, bytes):
        return repr(value) if len(value) <= 256 else _UNREUSABLE_HOOK_STATE_IDENTITY
    if isinstance(value, type):
        return f"{value.__module__}.{value.__qualname__}:{_UNREUSABLE_HOOK_STATE_IDENTITY}"
    if isinstance(value, (CodeType, FunctionType, MethodType, ModuleType)):
        return _UNREUSABLE_HOOK_STATE_IDENTITY
    if depth >= _MAX_HOOK_IDENTITY_DEPTH:
        return _UNREUSABLE_HOOK_STATE_IDENTITY
    if isinstance(value, tuple | list):
        if len(value) > _MAX_HOOK_IDENTITY_ITEMS:
            return _UNREUSABLE_HOOK_STATE_IDENTITY
        sequence_identity = ",".join(_bounded_hook_value_identity(item, depth + 1) for item in value)
        return f"{type(value).__name__}({sequence_identity})"
    if isinstance(value, dict):
        if len(value) > _MAX_HOOK_IDENTITY_ITEMS:
            return _UNREUSABLE_HOOK_STATE_IDENTITY
        mapping_items = sorted(value.items(), key=lambda item: str(item[0]))
        return (
            "dict("
            + ",".join(
                f"{_bounded_hook_value_identity(key, depth + 1)}:{_bounded_hook_value_identity(item, depth + 1)}"
                for key, item in mapping_items
            )
            + ")"
        )
    try:
        instance_state = object.__getattribute__(value, "__dict__")
    except (AttributeError, TypeError):
        return _UNREUSABLE_HOOK_STATE_IDENTITY
    if not isinstance(instance_state, dict):
        return _UNREUSABLE_HOOK_STATE_IDENTITY
    return (
        f"<{type(value).__module__}.{type(value).__qualname__}:"
        f"{_bounded_hook_value_identity(instance_state, depth + 1)}>"
    )


def _function_hook_state(function: FunctionType) -> str:
    closure_values: list[object] = []
    for cell in function.__closure__ or ():
        try:
            closure_values.append(cell.cell_contents)
        except ValueError:
            closure_values.append("<empty>")
    referenced_globals = {
        name: function.__globals__[name]
        for name in sorted(set(function.__code__.co_names))
        if name != "__builtins__" and name in function.__globals__
    }
    return "|".join(
        (
            f"closure={_bounded_hook_value_identity(tuple(closure_values))}",
            f"defaults={_bounded_hook_value_identity(function.__defaults__ or ())}",
            f"kwdefaults={_bounded_hook_value_identity(function.__kwdefaults__ or {})}",
            f"globals={_bounded_hook_value_identity(referenced_globals)}",
        )
    )


def _hook_type_methods(hook_type: type[object]) -> tuple[tuple[str, FunctionType], ...]:
    methods: list[tuple[str, FunctionType]] = []
    for method_name in ("find_spec", "__call__"):
        for candidate_type in hook_type.__mro__:
            method = candidate_type.__dict__.get(method_name)
            if isinstance(method, (classmethod, staticmethod)):
                method = method.__func__
            if isinstance(method, FunctionType):
                methods.append((method_name, method))
                break
    return tuple(methods)


def _hook_type_code(hook_type: type[object]) -> bytes:
    code_parts: list[bytes] = []
    for _method_name, method in _hook_type_methods(hook_type):
        code_parts.append(marshal.dumps(method.__code__))
    return b"".join(code_parts)


def _hook_type_state(hook_type: type[object]) -> str:
    method_states: dict[str, str] = {}
    class_attributes: dict[str, object] = {}
    for method_name, method in _hook_type_methods(hook_type):
        method_states[method_name] = _function_hook_state(method)
        for attribute_name in sorted(set(method.__code__.co_names)):
            for candidate_type in hook_type.__mro__:
                if attribute_name not in candidate_type.__dict__:
                    continue
                class_attributes[f"{candidate_type.__module__}.{candidate_type.__qualname__}.{attribute_name}"] = (
                    candidate_type.__dict__[attribute_name]
                )
                break
    return _bounded_hook_value_identity({"methods": method_states, "class_attributes": class_attributes})


def _import_hook_identity(hook: object) -> str:
    if isinstance(hook, FunctionType):
        module = hook.__module__
        qualname = hook.__qualname__
        code = marshal.dumps(hook.__code__)
        state = _function_hook_state(hook)
    elif isinstance(hook, MethodType):
        function = cast(FunctionType, hook.__func__)
        module = function.__module__
        qualname = function.__qualname__
        code = marshal.dumps(function.__code__)
        bound_type = hook.__self__ if isinstance(hook.__self__, type) else type(hook.__self__)
        state = "|".join(
            (
                f"type={_hook_type_state(bound_type)}",
                f"self={_bounded_hook_value_identity(hook.__self__)}",
                f"function={_function_hook_state(function)}",
            )
        )
    elif isinstance(hook, type):
        module = hook.__module__
        qualname = hook.__qualname__
        code = _hook_type_code(hook)
        known_class_finder = hook in {BuiltinImporter, FrozenImporter, PathFinder}
        state = "" if known_class_finder else f"{_UNREUSABLE_HOOK_STATE_IDENTITY}:{_hook_type_state(hook)}"
    else:
        hook_type = type(hook)
        module = hook_type.__module__
        qualname = hook_type.__qualname__
        code = _hook_type_code(hook_type)
        try:
            instance_state = object.__getattribute__(hook, "__dict__")
        except (AttributeError, TypeError):
            instance_state = _UNREUSABLE_HOOK_STATE_IDENTITY
        instance_identity = _bounded_hook_value_identity(instance_state)
        virtualenv_module = sys.modules.get("_virtualenv")
        virtualenv_finder_type = getattr(virtualenv_module, "_Finder", None) if virtualenv_module is not None else None
        is_virtualenv_finder = isinstance(virtualenv_finder_type, type) and type(hook) is virtualenv_finder_type
        state = (
            f"self={instance_identity}"
            if is_virtualenv_finder
            else f"type={_hook_type_state(hook_type)}|self={instance_identity}"
        )
    digest = hashlib.sha256(code + state.encode()).hexdigest()
    reuse_marker = "unreusable:" if _UNREUSABLE_HOOK_STATE_IDENTITY in state else ""
    return f"{module}.{qualname}:{reuse_marker}{digest}"


def _resolution_context_is_reusable(
    context: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]],
) -> bool:
    return all(":unreusable:" not in identity for identities in context for identity in identities)


def _path_importer_methods_are_trusted(
    importer_type: type[object],
    trusted_methods: tuple[tuple[str, object], ...],
) -> bool:
    return all(getattr(importer_type, name, None) is method for name, method in trusted_methods)


def _is_standard_file_finder_path_hook(hook: object) -> bool:
    if not isinstance(hook, FunctionType) or hook.__code__ is not _STANDARD_FILE_FINDER_PATH_HOOK_CODE:
        return False
    closure = hook.__closure__ or ()
    if len(closure) != len(hook.__code__.co_freevars):
        return False
    closure_values = dict(zip(hook.__code__.co_freevars, (cell.cell_contents for cell in closure), strict=True))
    if closure_values.get("cls") is not FileFinder:
        return False
    loader_details = closure_values.get("loader_details")
    if not isinstance(loader_details, tuple):
        return False
    try:
        normalized_details = tuple((loader, tuple(suffixes)) for loader, suffixes in loader_details)
    except (TypeError, ValueError):
        return False
    return normalized_details == _STANDARD_FILE_FINDER_LOADER_IDENTITY


def _path_hook_resolution_identity(hook: object) -> str:
    """Return a reusable identity only for unmodified standard path hooks."""
    if hook is zipimporter:
        if _path_importer_methods_are_trusted(zipimporter, _TRUSTED_ZIPIMPORTER_METHODS):
            return "trusted:zipimport.zipimporter"
        return "zipimport.zipimporter:unreusable:methods-changed"
    if _is_standard_file_finder_path_hook(hook):
        if _path_importer_methods_are_trusted(FileFinder, _TRUSTED_FILE_FINDER_METHODS):
            return "trusted:importlib.machinery.FileFinder.path_hook"
        return "importlib.machinery.FileFinder.path_hook:unreusable:methods-changed"
    return f"untrusted:unreusable:{_import_hook_identity(hook)}"


def _string_sequence_identity(values: Iterable[str]) -> str:
    digest = hashlib.sha256()
    count = 0
    for value in values:
        encoded = value.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    return f"{count}:{digest.hexdigest()}"


def _pytest_assertion_rewrite_identity(finder: object) -> str | None:
    rewrite_module = sys.modules.get("_pytest.assertion.rewrite")
    finder_type = getattr(rewrite_module, "AssertionRewritingHook", None) if rewrite_module is not None else None
    if not isinstance(finder_type, type) or type(finder) is not finder_type:
        return None

    basenames = {str(value) for value in getattr(finder, "_basenames_to_check_rewrite", ())}
    session = getattr(finder, "session", None)
    for initial_path in getattr(session, "_initialpaths", ()) if session is not None else ():
        basenames.add(Path(str(initial_path)).stem)
    state = "|".join(
        (
            _string_sequence_identity(sorted(str(value) for value in getattr(finder, "_must_rewrite", ()))),
            _string_sequence_identity(str(value) for value in getattr(finder, "fnpats", ())),
            _string_sequence_identity(sorted(basenames)),
            repr(bool(getattr(finder, "_writing_pyc", False))),
        )
    )
    digest = hashlib.sha256(_hook_type_code(finder_type) + state.encode()).hexdigest()
    return f"{finder_type.__module__}.{finder_type.__qualname__}:{digest}"


def _meta_path_finder_resolution_identity(finder: object) -> str:
    return _pytest_assertion_rewrite_identity(finder) or _import_hook_identity(finder)


def _is_trusted_standard_path_importer(finder: object, cache_key: str) -> bool:
    try:
        instance_state = object.__getattribute__(finder, "__dict__")
    except (AttributeError, TypeError):
        return False
    if not isinstance(instance_state, dict):
        return False
    if type(finder) is zipimporter:
        if not _path_importer_methods_are_trusted(zipimporter, _TRUSTED_ZIPIMPORTER_METHODS):
            return False
        try:
            expected_state = object.__getattribute__(zipimporter(cache_key), "__dict__")
        except (AttributeError, ImportError, OSError, TypeError):
            return False
        return (
            isinstance(expected_state, dict)
            and set(instance_state) == set(expected_state)
            and instance_state.get("archive") == expected_state.get("archive")
            and instance_state.get("prefix") == expected_state.get("prefix")
            and instance_state.get("_files") is expected_state.get("_files")
        )
    if type(finder) is not FileFinder:
        return False
    if not _path_importer_methods_are_trusted(FileFinder, _TRUSTED_FILE_FINDER_METHODS):
        return False
    finder_path = instance_state.get("path")
    loaders = instance_state.get("_loaders")
    return (
        set(instance_state) <= {"_loaders", "path", "_path_mtime", "_path_cache", "_relaxed_path_cache"}
        and isinstance(finder_path, str)
        and os.path.abspath(finder_path) == os.path.abspath(cache_key)
        and isinstance(loaders, list)
        and tuple(loaders) == _STANDARD_FILE_FINDER_LOADERS
    )


def _search_path_has_untrusted_importer(search_path: Iterable[str]) -> bool:
    for entry in search_path:
        cache_key = entry or os.getcwd()
        finder = sys.path_importer_cache.get(cache_key)
        if finder is not None and not _is_trusted_standard_path_importer(finder, cache_key):
            return True
    return False


def _source_resolution_context() -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    nonstandard_importers = []
    for entry in sys.path:
        cache_key = entry or os.getcwd()
        finder = sys.path_importer_cache.get(cache_key)
        if finder is None or _is_trusted_standard_path_importer(finder, cache_key):
            continue
        nonstandard_importers.append(f"{Path(cache_key).absolute()}={_import_hook_identity(finder)}")
    return (
        tuple(_meta_path_finder_resolution_identity(finder) for finder in sys.meta_path),
        tuple(_path_hook_resolution_identity(hook) for hook in sys.path_hooks),
        tuple(nonstandard_importers),
    )


def _read_bounded_regular_file(path: Path, max_bytes: int | None) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    file_descriptor = os.open(path, flags)
    try:
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"source candidate is not a regular file: {path}")
        if max_bytes is not None and before.st_size > max_bytes:
            raise _SourceReadTooLargeError(f"source candidate exceeds {max_bytes} bytes: {path}")

        chunks: list[bytes] = []
        remaining = 0 if max_bytes is None else max_bytes + 1
        while remaining > 0:
            chunk = os.read(file_descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(file_descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        try:
            path_stat = path.stat()
        except OSError as error:
            raise OSError(f"source candidate path changed while being read: {path}") from error
        path_identity = (
            path_stat.st_dev,
            path_stat.st_ino,
            path_stat.st_mode,
            path_stat.st_size,
            path_stat.st_mtime_ns,
            path_stat.st_ctime_ns,
        )
        if before_identity != after_identity or after_identity != path_identity:
            raise OSError(f"source candidate changed while being read: {path}")
        if max_bytes is not None and len(content) > max_bytes:
            raise _SourceReadTooLargeError(f"source candidate exceeds {max_bytes} bytes: {path}")
        return content, after
    finally:
        os.close(file_descriptor)


def _read_bounded_source_text(path: Path) -> str:
    source, _ = _read_bounded_regular_file(path, _MAX_SOURCE_BYTES)
    return source.decode("utf-8")


def _resolution_candidate_fingerprint(path: Path) -> tuple[bool, bytes | str | None]:
    try:
        if str(path).endswith(tuple(EXTENSION_SUFFIXES)):
            _read_bounded_regular_file(path, None)
            return True, _CALL_GRAPH_REGULAR_FILE_FINGERPRINT
        max_bytes = _MAX_SOURCE_BYTES * 2 if str(path).endswith(tuple(BYTECODE_SUFFIXES)) else _MAX_SOURCE_BYTES
        source, _ = _read_bounded_regular_file(path, max_bytes)
    except (FileNotFoundError, NotADirectoryError):
        return True, None
    except OSError:
        return False, None
    return True, hashlib.sha256(source).digest()


def _read_candidate_fingerprint(
    path: Path,
    *,
    read_limit: int = _MAX_SOURCE_BYTES,
    require_complete: bool = True,
) -> tuple[bool, bytes | None]:
    try:
        before = path.stat()
    except (FileNotFoundError, NotADirectoryError):
        return True, None
    except OSError:
        return False, None

    if stat.S_ISDIR(before.st_mode):
        try:
            entries: list[bytes] = []
            total_bytes = 0
            for index, entry in enumerate(path.iterdir()):
                if index >= _MAX_BYTECODE_CACHE_DIRECTORY_ENTRIES:
                    return False, None
                entry_name = os.fsencode(entry.name)
                total_bytes += len(entry_name) + 1
                if require_complete and total_bytes > read_limit:
                    return False, None
                entries.append(entry_name)
            after = path.stat()
        except OSError:
            return False, None
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            return False, None
        return True, hashlib.sha256(b"directory\0" + b"\0".join(sorted(entries))).digest()
    if not stat.S_ISREG(before.st_mode):
        return True, None

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        file_descriptor = os.open(path, flags)
    except (FileNotFoundError, NotADirectoryError):
        return False, None
    try:
        opened = os.fstat(file_descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return False, None
        chunks: list[bytes] = []
        remaining = read_limit + int(require_complete)
        while remaining > 0:
            chunk = os.read(file_descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        source = b"".join(chunks)
        after = os.fstat(file_descriptor)
        path_after = path.stat()
    except OSError:
        return False, None
    finally:
        os.close(file_descriptor)

    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    opened_identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    path_identity = (
        path_after.st_dev,
        path_after.st_ino,
        path_after.st_mode,
        path_after.st_size,
        path_after.st_mtime_ns,
        path_after.st_ctime_ns,
    )
    if len({before_identity, opened_identity, after_identity, path_identity}) != 1:
        return False, None
    if require_complete and len(source) > read_limit:
        return False, None
    return True, hashlib.sha256(b"file\0" + source).digest()


def _reset_shared_source_snapshot(snapshot: _SharedSourceSnapshot) -> None:
    snapshot.search_context = _source_search_context()
    snapshot.resolution_context = _source_resolution_context()
    snapshot.resolution_fingerprints.clear()
    snapshot.read_fingerprints.clear()
    snapshot.module_sources.clear()
    snapshot.loaded_module_sources.clear()
    snapshot.loaded_package_paths.clear()
    snapshot.generation += 1
    snapshot.stable = True
    snapshot.reusable = _resolution_context_is_reusable(snapshot.resolution_context)


def _shared_source_snapshot_is_current(snapshot: _SharedSourceSnapshot) -> bool:
    if (
        not snapshot.stable
        or snapshot.search_context != _source_search_context()
        or snapshot.resolution_context != _source_resolution_context()
    ):
        return False
    for path, (read_limit, require_complete, expected_read_fingerprint) in snapshot.read_fingerprints.items():
        reusable, read_fingerprint = _read_candidate_fingerprint(
            Path(path),
            read_limit=read_limit,
            require_complete=require_complete,
        )
        if not reusable or read_fingerprint != expected_read_fingerprint:
            return False
    for path, expected_resolution_fingerprint in snapshot.resolution_fingerprints.items():
        reusable, resolution_fingerprint = _resolution_candidate_fingerprint(Path(path))
        if not reusable or resolution_fingerprint != expected_resolution_fingerprint:
            return False
    for module_name, expected_source in snapshot.module_sources.items():
        if _current_module_source_path(module_name) != expected_source:
            return False
    for module_name, expected_source in snapshot.loaded_module_sources.items():
        if _loaded_module_source_path(module_name) != expected_source:
            return False
    for module_name, expected_search_path in snapshot.loaded_package_paths.items():
        is_loaded, current_search_path = _loaded_package_search_path(module_name)
        if not is_loaded or current_search_path is None or tuple(current_search_path) != expected_search_path:
            return False
    return True


def _begin_shared_source_report() -> int | None:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is None:
        return None
    with snapshot.lock:
        if not _shared_source_snapshot_is_current(snapshot):
            _clear_source_sensitive_caches_now()
            _reset_shared_source_snapshot(snapshot)
        return snapshot.generation


def _ensure_shared_source_snapshot_stable(report_generation: int | None) -> None:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is None or report_generation is None:
        return
    with snapshot.lock:
        if snapshot.generation != report_generation:
            raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")
        if _shared_source_snapshot_is_current(snapshot):
            return
        _clear_source_sensitive_caches_now()
        _reset_shared_source_snapshot(snapshot)
    raise _CallGraphAnalysisLimitError("source changed during shared call-graph analysis")


def shared_source_fingerprint_metadata() -> dict[str, Any] | None:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is None:
        return None
    with snapshot.lock:
        if not snapshot.reusable:
            return {
                "reusable": False,
                "search_context": list(snapshot.search_context),
                "resolution_context": {
                    "meta_path": list(snapshot.resolution_context[0]),
                    "path_hooks": list(snapshot.resolution_context[1]),
                    "path_importers": list(snapshot.resolution_context[2]),
                },
                "module_sources": {},
                "loaded_module_sources": {},
                "loaded_package_paths": {},
                "fingerprints": {},
                "read_fingerprints": {},
            }
        return {
            "reusable": True,
            "search_context": list(snapshot.search_context),
            "resolution_context": {
                "meta_path": list(snapshot.resolution_context[0]),
                "path_hooks": list(snapshot.resolution_context[1]),
                "path_importers": list(snapshot.resolution_context[2]),
            },
            "module_sources": dict(sorted(snapshot.module_sources.items())),
            "loaded_module_sources": dict(sorted(snapshot.loaded_module_sources.items())),
            "loaded_package_paths": {
                module_name: list(search_path)
                for module_name, search_path in sorted(snapshot.loaded_package_paths.items())
            },
            "fingerprints": {
                path: fingerprint.hex() if isinstance(fingerprint, bytes) else fingerprint
                for path, fingerprint in sorted(snapshot.resolution_fingerprints.items())
            },
            "read_fingerprints": {
                path: {
                    "read_limit": read_limit,
                    "require_complete": require_complete,
                    "fingerprint": fingerprint.hex() if isinstance(fingerprint, bytes) else None,
                }
                for path, (read_limit, require_complete, fingerprint) in sorted(snapshot.read_fingerprints.items())
            },
        }


def _track_shared_source_candidates(parts: tuple[str, ...]) -> None:
    candidates: set[Path] = set()
    import_suffixes = (*EXTENSION_SUFFIXES, *SOURCE_SUFFIXES, *BYTECODE_SUFFIXES)
    for entry in sys.path:
        root = Path(entry or os.getcwd())
        archive_path = _zipimport_archive_path(str(root))
        if archive_path is not None:
            candidates.add(archive_path)
        for index in range(1, len(parts) + 1):
            module_path = root.joinpath(*parts[:index])
            for suffix in import_suffixes:
                candidates.add(Path(f"{module_path}{suffix}").absolute())
                candidates.add(module_path.joinpath(f"__init__{suffix}").absolute())
    # Resolution only depends on candidate type and presence. The selected
    # source is content-hashed separately, while native extensions can be large.
    _track_shared_source_paths(candidates, read_limit=0, require_complete=False)
    if not _track_resolution_candidate_paths(candidates):
        return
    _track_resolution_source_candidates(parts)


def _track_resolution_candidate_paths(candidates: Iterable[Path]) -> bool:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is None:
        return True
    candidate_paths = {str(candidate): candidate for candidate in candidates}
    with snapshot.lock:
        if (
            snapshot.search_context != _source_search_context()
            or snapshot.resolution_context != _source_resolution_context()
        ):
            snapshot.stable = False
            snapshot.reusable = False
            return False
        if len(snapshot.resolution_fingerprints.keys() | candidate_paths.keys()) > _MAX_SOURCE_FINGERPRINT_CANDIDATES:
            snapshot.reusable = False
            return False
        for candidate_key, candidate in candidate_paths.items():
            reusable, fingerprint = _resolution_candidate_fingerprint(candidate)
            if not reusable:
                snapshot.reusable = False
                return False
            snapshot.resolution_fingerprints[candidate_key] = fingerprint
    return True


def _track_resolution_source_candidates(parts: tuple[str, ...]) -> None:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is None:
        return
    module_name_length = sum(len(part) for part in parts) + len(parts) - 1
    if module_name_length > _MAX_SOURCE_MODULE_NAME_CHARS:
        with snapshot.lock:
            snapshot.stable = False
            snapshot.reusable = False
        return

    search_path = [str(Path(entry or os.getcwd())) for entry in sys.path]
    for index, part in enumerate(parts):
        qualified_name = ".".join(parts[: index + 1])
        if index < len(parts) - 1:
            is_loaded, loaded_search_path = _loaded_package_search_path(qualified_name)
            if is_loaded:
                if loaded_search_path is None:
                    return
                if _search_path_has_untrusted_importer(loaded_search_path):
                    _mark_shared_source_snapshot_unreusable()
                    return
                with snapshot.lock:
                    expected_search_path = tuple(loaded_search_path)
                    existing_search_path = snapshot.loaded_package_paths.get(qualified_name)
                    if existing_search_path is not None and existing_search_path != expected_search_path:
                        snapshot.stable = False
                        snapshot.reusable = False
                        return
                    snapshot.loaded_package_paths[qualified_name] = expected_search_path
                search_path = loaded_search_path
                continue

        considered_entries: list[str] = []
        namespace_locations: list[str] = []
        resolved_spec: ModuleSpec | None = None
        for entry in search_path:
            considered_entries.append(entry)
            entry_spec = _find_standard_path_spec(qualified_name, [entry])
            if entry_spec is None:
                continue
            if entry_spec.loader is not None:
                resolved_spec = entry_spec
                break
            if entry_spec.submodule_search_locations is not None:
                namespace_locations.extend(entry_spec.submodule_search_locations)
        if resolved_spec is None and namespace_locations:
            resolved_spec = ModuleSpec(qualified_name, loader=None, is_package=True)
            resolved_spec.submodule_search_locations = namespace_locations

        resolution_candidates: set[Path] = set()
        for entry in considered_entries:
            archive_path = _zipimport_archive_path(entry)
            if archive_path is not None:
                resolution_candidates.add(archive_path)
            module_candidate = Path(entry).joinpath(part)
            package_candidate = module_candidate.joinpath("__init__")
            for suffix in _SOURCE_RESOLUTION_SUFFIXES:
                resolution_candidates.add(module_candidate.with_suffix(suffix).absolute())
                resolution_candidates.add(package_candidate.with_suffix(suffix).absolute())
            for source_candidate in (module_candidate.with_suffix(".py"), package_candidate.with_suffix(".py")):
                cache_candidate = _source_cache_path(source_candidate)
                if cache_candidate is not None:
                    resolution_candidates.add(cache_candidate)

        with snapshot.lock:
            if (
                snapshot.search_context != _source_search_context()
                or snapshot.resolution_context != _source_resolution_context()
            ):
                snapshot.stable = False
                snapshot.reusable = False
                return
            if (
                len(snapshot.resolution_fingerprints | {str(candidate): None for candidate in resolution_candidates})
                > _MAX_SOURCE_FINGERPRINT_CANDIDATES
            ):
                snapshot.reusable = False
                return
            for candidate in resolution_candidates:
                reusable, fingerprint = _resolution_candidate_fingerprint(candidate)
                if not reusable:
                    snapshot.reusable = False
                    return
                snapshot.resolution_fingerprints[str(candidate)] = fingerprint

        if index == len(parts) - 1:
            return
        if resolved_spec is None or resolved_spec.submodule_search_locations is None:
            return
        search_path = list(resolved_spec.submodule_search_locations)


def _track_shared_source_paths(
    candidates: Iterable[Path],
    *,
    read_limit: int = _MAX_SOURCE_BYTES,
    require_complete: bool = True,
) -> None:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is None:
        return
    with snapshot.lock:
        if snapshot.search_context != _source_search_context():
            snapshot.reusable = False
            return
        for candidate in candidates:
            candidate_key = str(candidate)
            existing = snapshot.read_fingerprints.get(candidate_key)
            if existing is None and len(snapshot.read_fingerprints) >= _MAX_SOURCE_FINGERPRINT_CANDIDATES:
                snapshot.reusable = False
                return
            if existing is not None:
                existing_read_limit, existing_require_complete, expected_fingerprint = existing
                reusable, current_fingerprint = _read_candidate_fingerprint(
                    candidate,
                    read_limit=existing_read_limit,
                    require_complete=existing_require_complete,
                )
                if not reusable or current_fingerprint != expected_fingerprint:
                    snapshot.reusable = False
                    return
                if existing_require_complete and not require_complete:
                    continue
                if existing_require_complete == require_complete and existing_read_limit >= read_limit:
                    continue
            reusable, fingerprint = _read_candidate_fingerprint(
                candidate,
                read_limit=read_limit,
                require_complete=require_complete,
            )
            if not reusable:
                snapshot.reusable = False
                return
            snapshot.read_fingerprints[candidate_key] = (read_limit, require_complete, fingerprint)


def _track_shared_source_path(module_name: str, path: Path, *, loaded: bool) -> None:
    snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
    if snapshot is None:
        return
    candidate = path.absolute()
    with snapshot.lock:
        if snapshot.search_context != _source_search_context():
            snapshot.stable = False
            snapshot.reusable = False
            return
        if snapshot.resolution_context != _source_resolution_context():
            snapshot.stable = False
            snapshot.reusable = False
            return
        reusable, fingerprint = _resolution_candidate_fingerprint(candidate)
        if not reusable:
            snapshot.stable = False
            snapshot.reusable = False
            return
        existing_source = snapshot.module_sources.get(module_name)
        if existing_source is not None and existing_source != str(candidate):
            snapshot.stable = False
            snapshot.reusable = False
            return
        snapshot.module_sources[module_name] = str(candidate)
        if loaded:
            snapshot.loaded_module_sources[module_name] = str(candidate)
        if (
            str(candidate) not in snapshot.resolution_fingerprints
            and len(snapshot.resolution_fingerprints) >= _MAX_SOURCE_FINGERPRINT_CANDIDATES
        ):
            snapshot.reusable = False
            return
        snapshot.resolution_fingerprints[str(candidate)] = fingerprint


def _call_graph_source_unavailable_reason(module_name: str) -> str | None:
    source_path = _resolve_module_source(module_name)
    if source_path is not None:
        try:
            source = _read_bounded_source_text(source_path)
        except _SourceReadTooLargeError:
            return "source_too_large"
        except OSError:
            return "source_unreadable"
        except UnicodeError:
            return "source_unreadable"
        if _trusted_module_origin_kind(module_name) not in {
            "stdlib",
            "site_packages",
        } and _source_has_importable_untrusted_cache(source_path, source):
            snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
            if snapshot is not None:
                with snapshot.lock:
                    snapshot.reusable = False
            return "untrusted_bytecode_cache"
        try:
            ast.parse(source, filename=str(source_path))
        except SyntaxError:
            return "source_parse_error"
        return None

    try:
        spec = _find_module_spec_without_imports(module_name)
    except Exception:
        return "source_unavailable"
    if spec is None:
        # Module names come from pickle metadata; do not consult executable custom meta-path finders.
        return "source_unavailable"
    if spec.origin in {"built-in", "frozen"}:
        return None
    if spec.origin is not None and any(spec.origin.endswith(suffix) for suffix in EXTENSION_SUFFIXES):
        return None
    return "source_unavailable"


def _find_module_spec_without_imports(module_name: str) -> ModuleSpec | None:
    parts = _bounded_module_name_parts(module_name)
    if parts is None:
        return None

    loaded_module = sys.modules.get(module_name)
    loaded_spec = getattr(loaded_module, "__spec__", None)
    if isinstance(loaded_spec, ModuleSpec):
        return loaded_spec

    if not _untrusted_meta_path_finder_precedes(BuiltinImporter, module_name):
        builtin_spec = BuiltinImporter.find_spec(module_name)
        if builtin_spec is not None:
            return builtin_spec

    if not _untrusted_meta_path_finder_precedes(FrozenImporter, module_name):
        frozen_spec = FrozenImporter.find_spec(module_name)
        if frozen_spec is not None:
            return frozen_spec

    if _untrusted_meta_path_finder_precedes(PathFinder, module_name) or _has_untrusted_path_hook():
        return None

    return _find_standard_filesystem_spec(module_name)


def _find_standard_filesystem_spec(module_name: str) -> ModuleSpec | None:
    if len(module_name) > _MAX_SOURCE_MODULE_NAME_CHARS:
        return None
    parts = module_name.split(".")
    if not parts or any(not part or "/" in part or "\\" in part for part in parts):
        return None

    search_path = [str(Path(entry or os.getcwd())) for entry in sys.path]
    spec: ModuleSpec | None = None
    for index in range(len(parts)):
        qualified_name = ".".join(parts[: index + 1])
        if index < len(parts) - 1:
            is_loaded, loaded_search_path = _loaded_package_search_path(qualified_name)
            if is_loaded:
                if loaded_search_path is None:
                    return None
                search_path = loaded_search_path
                continue
        spec = _find_standard_path_spec(qualified_name, search_path)
        if spec is None:
            return None
        if index == len(parts) - 1:
            return spec
        locations = spec.submodule_search_locations
        if locations is None:
            return None
        search_path = list(locations)
    return spec


def _loaded_package_search_path(module_name: str) -> tuple[bool, list[str] | None]:
    if module_name not in sys.modules:
        return False, None
    loaded_module: Any = sys.modules[module_name]
    if not isinstance(loaded_module, ModuleType):
        return True, None
    raw_search_path = vars(loaded_module).get("__path__")
    if not isinstance(raw_search_path, (list, tuple)) or not all(isinstance(entry, str) for entry in raw_search_path):
        return True, None
    return True, [str(Path(entry or os.getcwd()).absolute()) for entry in raw_search_path]


def _source_cache_path(source_path: Path) -> Path | None:
    optimization = "" if sys.flags.optimize == 0 else str(sys.flags.optimize)
    try:
        return Path(cache_from_source(str(source_path), optimization=optimization)).absolute()
    except (NotImplementedError, ValueError):
        return None


def _effective_bytecode_matches_source(source_path: Path) -> bool:
    cache_path = _source_cache_path(source_path)
    if cache_path is None:
        return True
    try:
        bytecode, _bytecode_stat = _read_bounded_regular_file(cache_path, _MAX_SOURCE_BYTES * 2)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        source, source_stat = _read_bounded_regular_file(source_path, _MAX_SOURCE_BYTES)
    except OSError:
        return False
    if len(bytecode) < 16:
        return False
    if bytecode[:4] != MAGIC_NUMBER:
        return True
    flags = int.from_bytes(bytecode[4:8], "little")
    if flags & ~0b11:
        return True
    if flags & 0b1:
        check_hash_policy = _imp.check_hash_based_pycs
        should_check_hash = check_hash_policy == "always" or (check_hash_policy == "default" and bool(flags & 0b10))
        if should_check_hash and bytecode[8:16] != source_hash(source):
            return True
    elif (
        int.from_bytes(bytecode[8:12], "little") != int(source_stat.st_mtime) & 0xFFFFFFFF
        or int.from_bytes(bytecode[12:16], "little") != source_stat.st_size & 0xFFFFFFFF
    ):
        return True
    try:
        cached_code = marshal.loads(bytecode[16:])
        source_code = compile(source, str(source_path), "exec", dont_inherit=True, optimize=sys.flags.optimize)
    except (EOFError, TypeError, ValueError):
        return False
    return isinstance(cached_code, CodeType) and cached_code == source_code


def _current_module_source_path(module_name: str) -> str | None:
    if len(module_name) > _MAX_SOURCE_MODULE_NAME_CHARS:
        return None
    spec = _find_standard_filesystem_spec(module_name)
    if spec is None or not isinstance(spec.origin, str) or not spec.origin.endswith(tuple(SOURCE_SUFFIXES)):
        return None
    return str(Path(spec.origin).absolute())


def _zipimport_archive_path(entry: str) -> Path | None:
    try:
        archive = zipimporter(entry).archive
    except (ImportError, OSError):
        return None
    return Path(archive).absolute()


def _loaded_module_source_path(module_name: str) -> str | None:
    loaded_module = sys.modules.get(module_name)
    loaded_spec = getattr(loaded_module, "__spec__", None)
    if not isinstance(loaded_spec, ModuleSpec) or not isinstance(loaded_spec.origin, str):
        return None
    if not loaded_spec.origin.endswith(tuple(SOURCE_SUFFIXES)):
        return None
    return str(Path(loaded_spec.origin).absolute())


def _matches_loaded_finder_type(finder: object, module_name: str, type_name: str) -> bool:
    module = sys.modules.get(module_name)
    finder_type = getattr(module, type_name, None) if module is not None else None
    return isinstance(finder_type, type) and type(finder) is finder_type


def _known_meta_path_finder_cannot_handle(finder: object, module_name: str) -> bool:
    root_name = module_name.split(".", maxsplit=1)[0]
    if _matches_loaded_finder_type(finder, "_distutils_hack", "DistutilsMetaFinder"):
        return root_name not in {"distutils", "pip", "test"}

    if _matches_loaded_finder_type(finder, "_virtualenv", "_Finder"):
        virtualenv_module = sys.modules.get("_virtualenv")
        patched_modules = getattr(virtualenv_module, "_DISTUTILS_PATCH", ()) if virtualenv_module is not None else ()
        return module_name not in patched_modules

    if _matches_loaded_finder_type(finder, "_pytest.assertion.rewrite", "AssertionRewritingHook"):
        if module_name == "conftest":
            return False
        must_rewrite = getattr(finder, "_must_rewrite", ())
        if any(module_name == name or module_name.startswith(f"{name}.") for name in must_rewrite):
            return False
        patterns = getattr(finder, "fnpats", ())
        module_filename = f"{module_name.rsplit('.', maxsplit=1)[-1]}.py"
        return all(not fnmatch.fnmatchcase(module_filename, pattern) for pattern in patterns)

    return False


def _untrusted_meta_path_finder_precedes(target: object, module_name: str) -> bool:
    for finder in sys.meta_path:
        if finder is target:
            return False
        if finder is BuiltinImporter or finder is FrozenImporter or finder is PathFinder:
            continue
        if _known_meta_path_finder_cannot_handle(finder, module_name):
            continue
        return True
    return True


def _is_standard_path_hook(hook: object) -> bool:
    return _path_hook_resolution_identity(hook).startswith("trusted:")


def _has_untrusted_path_hook() -> bool:
    if any(not _is_standard_path_hook(hook) for hook in sys.path_hooks):
        return True
    return _search_path_has_untrusted_importer(sys.path)


def _find_standard_path_spec(module_name: str, search_path: list[str]) -> ModuleSpec | None:
    if _search_path_has_untrusted_importer(search_path):
        _mark_shared_source_snapshot_unreusable()
        return None

    namespace_locations: list[str] = []
    loader_details = (
        (ExtensionFileLoader, EXTENSION_SUFFIXES),
        (SourceFileLoader, SOURCE_SUFFIXES),
        (SourcelessFileLoader, BYTECODE_SUFFIXES),
    )
    for entry in search_path:
        try:
            zip_spec = zipimporter(entry).find_spec(module_name)
        except ImportError:
            zip_spec = None
        if zip_spec is not None:
            return zip_spec

        finder = FileFinder(entry, *loader_details)
        spec = finder.find_spec(module_name)
        if spec is None:
            continue
        if spec.loader is not None:
            return spec
        if spec.submodule_search_locations is not None:
            namespace_locations.extend(spec.submodule_search_locations)

    if not namespace_locations:
        return None
    namespace_spec = ModuleSpec(module_name, loader=None, is_package=True)
    namespace_spec.submodule_search_locations = namespace_locations
    return namespace_spec


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _find_sink_path(start: str) -> tuple[str, ...] | None:
    return _find_matching_call_path(
        start,
        _rce_sink,
        import_execution_fallback_allowed=_can_follow_import_execution_fallback(start, 0),
    )


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _find_invoked_import_execution_path(
    start: str,
    positional_arg_count: int,
    keyword_arg_names: tuple[str, ...] | None = (),
    *,
    allow_non_lifecycle_entrypoint: bool = False,
) -> tuple[str, ...] | None:
    resolved = _resolve_function_target(start)
    if resolved is None:
        return None
    context = _source_function_context(resolved)
    if context is None:
        return None
    module_name, is_package, function_node = context
    if not allow_non_lifecycle_entrypoint and not _is_pickle_entered_import_execution_entrypoint(resolved):
        return None
    can_enter = (
        _can_enter_function_with_unknown_keyword_args(function_node, positional_arg_count)
        if keyword_arg_names is None
        else _can_enter_function_with_arguments(function_node, positional_arg_count, keyword_arg_names)
    )
    if not can_enter:
        return None
    if _IMPORT_EXECUTION_SINK in _direct_import_execution_calls(function_node, module_name, is_package):
        return (resolved, _IMPORT_EXECUTION_SINK)
    path = _find_matching_call_path(
        resolved,
        _rce_sink,
        import_execution_fallback_allowed=True,
    )
    if path is None or not _is_import_execution_sink(path[-1]):
        return None
    return path


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _find_file_open_path(start: str) -> tuple[str, ...] | None:
    return _find_matching_call_path(start, _file_open_sink)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _find_file_write_path(start: str) -> tuple[str, ...] | None:
    return _find_matching_call_path(start, _file_write_sink)


def _find_matching_call_path(
    start: str,
    sink_for: Callable[[str], str | None],
    *,
    import_execution_fallback_allowed: bool = False,
) -> tuple[str, ...] | None:
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(start, (start,))])
    visited = {start}
    import_execution_fallback_path: tuple[str, ...] | None = None

    while queue and len(visited) <= _MAX_VISITED_FUNCTIONS:
        function_name, path = queue.popleft()
        sink = sink_for(function_name)
        if sink is not None:
            return path
        resolved_function = _resolve_function_target(function_name)
        if resolved_function is not None and resolved_function != function_name:
            sink = sink_for(resolved_function)
            if sink is not None:
                return (*path, sink)

        calls = _calls_for_function(function_name)
        if calls is None:
            continue

        bounded_calls = calls[:_MAX_CALLS_PER_FUNCTION]
        for call in bounded_calls:
            sink = sink_for(call)
            if sink is not None:
                # Tcl dispatch risk depends on the local call argument shape; do not
                # propagate it through wrappers whose arguments may be fixed safely.
                if _is_tcl_interpreter_dispatch_call(sink) and len(path) > 1:
                    continue
                if _is_import_execution_sink(sink):
                    if import_execution_fallback_allowed and import_execution_fallback_path is None:
                        import_execution_fallback_path = (*path, sink)
                    continue
                return (*path, sink)

        if sink_for is _rce_sink:
            for call in sorted(bounded_calls, key=_short_sink_call_priority):
                short_sink_path = _find_short_matching_call_path(call, sink_for)
                if short_sink_path is not None:
                    sink = short_sink_path[-1]
                    if _is_tcl_interpreter_dispatch_call(sink) or _is_import_execution_sink(sink):
                        continue
                    return (*path, *short_sink_path)

        for call in bounded_calls:
            if len(path) > _MAX_CALL_GRAPH_DEPTH:
                continue
            resolved = _resolve_function_target(call)
            if resolved is None or resolved in visited:
                continue
            visited.add(resolved)
            queue.append((resolved, (*path, resolved)))
    return import_execution_fallback_path


def _short_sink_call_priority(call_name: str) -> int:
    tail = call_name.rpartition(".")[2].lower()
    if any(token in tail for token in _SHORT_SINK_PRIORITY_TOKENS):
        return 0
    if any(token in tail for token in _SHORT_SINK_SECONDARY_PRIORITY_TOKENS):
        return 1
    return 2


def _find_short_matching_call_path(start: str, sink_for: Callable[[str], str | None]) -> tuple[str, ...] | None:
    queue: deque[tuple[str, tuple[str, ...], int]] = deque([(start, (start,), 0)])
    visited = {start}

    while queue and len(visited) <= _MAX_VISITED_FUNCTIONS:
        function_name, path, depth = queue.popleft()
        calls = _calls_for_function(function_name)
        if calls is None:
            continue
        for call in calls[:_MAX_CALLS_PER_FUNCTION]:
            sink = sink_for(call)
            if sink is not None:
                if _is_import_execution_sink(sink):
                    continue
                return (*path, sink)
            if depth >= _MAX_SHORT_SINK_DEPTH:
                continue
            resolved = _resolve_function_target(call)
            if resolved is None or resolved in visited:
                continue
            visited.add(resolved)
            queue.append((resolved, (*path, resolved), depth + 1))
    return None


def _calls_for_function(function_name: str) -> tuple[str, ...] | None:
    resolved = _resolve_function_target(function_name)
    if resolved is None:
        return None
    module_name, qualified_name = _split_function_name(resolved)
    if module_name is None:
        return None
    analysis = _analyze_module(module_name)
    if analysis is None:
        return None
    return analysis.calls_by_function.get(f"{module_name}.{qualified_name}")


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _call_graph_entrypoints(function_name: str) -> tuple[str, ...]:
    resolved = _resolve_function_target(function_name)
    if resolved is not None:
        return (resolved,)

    class_target = _resolve_class_target(function_name)
    if class_target is None:
        return ()
    return _class_entrypoints(class_target)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _resolve_function_target(function_name: str) -> str | None:
    alias_target = _static_import_reference_alias(function_name)
    if alias_target is not None and alias_target != function_name:
        return _resolve_alias_function_target(alias_target)

    module_name, qualified_name = _split_function_name(function_name)
    if module_name is None:
        return None
    analysis = _analyze_module(module_name)
    if analysis is None:
        return None
    full_name = f"{module_name}.{qualified_name}"
    if full_name in analysis.calls_by_function:
        return full_name
    alias_target = analysis.aliases.get(qualified_name)
    if alias_target is not None and alias_target != function_name:
        return _resolve_alias_function_target(alias_target)
    if "." not in qualified_name:
        wildcard_target = _resolve_wildcard_reexport_alias(module_name, qualified_name)
        if wildcard_target is not None and wildcard_target != function_name:
            return _resolve_alias_function_target(wildcard_target)
        module_getattr_target = _resolve_module_getattr_target(module_name, qualified_name, analysis)
        if module_getattr_target is not None:
            return module_getattr_target
    else:
        dotted_alias_target = _resolve_dotted_alias_prefix(module_name, qualified_name, analysis)
        if dotted_alias_target is not None:
            return _resolve_alias_function_target(dotted_alias_target)
        dotted_module_getattr_target = _resolve_dotted_module_getattr_target(module_name, qualified_name, analysis)
        if dotted_module_getattr_target is not None:
            return dotted_module_getattr_target
    return None


def _resolve_dotted_alias_prefix(
    module_name: str,
    qualified_name: str,
    analysis: _ModuleAnalysis,
) -> str | None:
    first_component, _separator, remaining = qualified_name.partition(".")
    if not first_component or not remaining:
        return None
    alias_target = analysis.aliases.get(first_component)
    if alias_target is None:
        return None
    resolved = f"{alias_target}.{remaining}"
    if resolved == f"{module_name}.{qualified_name}":
        return None
    return resolved


def _resolve_dotted_module_getattr_target(
    module_name: str,
    qualified_name: str,
    analysis: _ModuleAnalysis,
) -> str | None:
    first_component, _separator, _remaining = qualified_name.partition(".")
    if not first_component or first_component in analysis.direct_names:
        return None
    if first_component == "__dict__":
        return None
    if analysis.aliases.get(first_component) is not None:
        return None
    if _resolve_wildcard_reexport_alias(module_name, first_component) is not None:
        return None
    return _resolve_module_getattr_target(module_name, first_component, analysis)


def _resolve_module_getattr_target(
    module_name: str,
    qualified_name: str,
    analysis: _ModuleAnalysis,
) -> str | None:
    if qualified_name in analysis.direct_names:
        return None

    module_getattr = f"{module_name}.__getattr__"
    if module_getattr in analysis.calls_by_function:
        return module_getattr

    alias_target = analysis.aliases.get("__getattr__")
    if alias_target is not None and alias_target != module_getattr:
        return _resolve_alias_function_target(alias_target)
    return None


def _resolve_alias_function_target(alias_target: str) -> str | None:
    if (
        _rce_sink(alias_target) is not None
        or _file_open_sink(alias_target) is not None
        or _file_write_sink(alias_target) is not None
    ):
        return alias_target
    return _resolve_function_target(alias_target)


def _static_import_reference_alias(function_name: str) -> str | None:
    for suffix, target in _STATIC_IMPORT_REFERENCE_ALIAS_SUFFIXES.items():
        if function_name == suffix or function_name.endswith(f".{suffix}"):
            return target
    return None


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _resolve_wildcard_reexport_alias(module_name: str, qualified_name: str) -> str | None:
    return _resolve_wildcard_reexport_alias_inner(module_name, qualified_name, set(), 0)


def _resolve_wildcard_reexport_alias_inner(
    module_name: str,
    qualified_name: str,
    visited: set[str],
    depth: int,
) -> str | None:
    if depth >= _MAX_WILDCARD_REEXPORT_DEPTH or module_name in visited:
        return None
    summary = _wildcard_export_summary(module_name)
    if summary is None:
        return None

    next_visited = {*visited, module_name}
    for imported_module in summary.wildcard_imports[:_MAX_WILDCARD_IMPORTS]:
        if imported_module in next_visited:
            continue
        imported_summary = _wildcard_export_summary(imported_module)
        if imported_summary is None:
            continue
        if qualified_name in imported_summary.direct_names:
            return f"{imported_module}.{qualified_name}"
        nested_target = _resolve_wildcard_reexport_alias_inner(
            imported_module,
            qualified_name,
            next_visited,
            depth + 1,
        )
        if nested_target is not None:
            return nested_target
    return None


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _wildcard_export_summary(module_name: str) -> _WildcardExportSummary | None:
    context = _module_source_context(module_name)
    if context is None:
        return None
    return _collect_module_export_summary(context.module_statements, module_name, context.is_package)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _resolve_class_target(function_name: str) -> str | None:
    module_name, qualified_name = _split_function_name(function_name)
    if module_name is None:
        return None
    analysis = _analyze_module(module_name)
    if analysis is None:
        return None
    full_name = f"{module_name}.{qualified_name}"
    if full_name in analysis.class_entrypoints:
        return full_name
    if "." not in qualified_name:
        alias_target = analysis.aliases.get(qualified_name)
        if alias_target is not None and alias_target != function_name:
            return _resolve_class_target(alias_target)
        wildcard_target = _resolve_wildcard_reexport_alias(module_name, qualified_name)
        if wildcard_target is not None and wildcard_target != function_name:
            return _resolve_class_target(wildcard_target)
    else:
        dotted_alias_target = _resolve_dotted_alias_prefix(module_name, qualified_name, analysis)
        if dotted_alias_target is not None:
            return _resolve_class_target(dotted_alias_target)
    return None


def _class_entrypoints(class_name: str) -> tuple[str, ...]:
    module_name, qualified_name = _split_function_name(class_name)
    if module_name is None:
        return ()
    analysis = _analyze_module(module_name)
    if analysis is None:
        return ()
    return analysis.class_entrypoints.get(f"{module_name}.{qualified_name}", ())


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _split_function_name(function_name: str) -> tuple[str | None, str]:
    parts = function_name.split(".")
    for index in range(len(parts) - 1, 0, -1):
        module_name = ".".join(parts[:index])
        qualified_name = ".".join(parts[index:])
        analysis = _analyze_module(module_name)
        if analysis is not None:
            return module_name, qualified_name
    return None, function_name


@_register_source_sensitive_cache
@lru_cache(maxsize=1024)
def _analyze_module(module_name: str) -> _ModuleAnalysis | None:
    context = _module_source_context(module_name)
    if context is None:
        return None

    export_summary = _collect_module_export_summary(context.module_statements, module_name, context.is_package)
    import_aliases = _collect_aliases(context.module_statements, module_name, context.is_package)
    local_defs = _collect_local_defs(context.module_statements)
    local_class_entrypoints = _collect_local_class_entrypoints(
        context.module_statements,
        module_name,
        import_aliases,
        local_defs,
    )
    local_class_targets = set(local_class_entrypoints)
    aliases = {
        **import_aliases,
        **_collect_assignment_aliases(
            context.module_statements,
            module_name,
            import_aliases,
            local_defs,
            local_class_targets,
        ),
    }
    aliases.update(
        _collect_class_instance_default_aliases(
            context.module_statements,
            module_name,
            aliases,
            local_defs,
            local_class_targets,
        )
    )
    calls_by_function, class_entrypoints = _collect_function_calls(
        context.module_statements,
        module_name,
        context.is_package,
        aliases,
        local_defs,
        local_class_targets,
        local_class_entrypoints,
    )
    return _ModuleAnalysis(
        module=module_name,
        source_path=str(context.source_path),
        aliases=aliases,
        direct_names=export_summary.direct_names,
        calls_by_function=calls_by_function,
        class_entrypoints=class_entrypoints,
    )


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _module_source_context(module_name: str) -> _ModuleSourceContext | None:
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return None
    try:
        source = _read_bounded_source_text(source_path)
        if _trusted_module_origin_kind(module_name) not in {
            "stdlib",
            "site_packages",
        } and _source_has_importable_untrusted_cache(source_path, source):
            snapshot = _SHARED_SOURCE_SENSITIVE_SNAPSHOT.get()
            if snapshot is not None:
                with snapshot.lock:
                    snapshot.reusable = False
            return None
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return None

    is_package = source_path.name == "__init__.py"
    module_statements = _module_level_statements(tree)
    return _ModuleSourceContext(source_path=source_path, module_statements=module_statements, is_package=is_package)


def _source_has_importable_untrusted_cache(source_path: Path, source: str) -> bool:
    cache_paths: list[tuple[Path, int]] = []
    for optimization, optimize_level in _BYTECODE_CACHE_OPTIMIZATIONS:
        try:
            cache_path = Path(cache_from_source(str(source_path), optimization=optimization))
        except (NotImplementedError, ValueError):
            return True
        cache_paths.append((cache_path, optimize_level))

    cache_tag = sys.implementation.cache_tag
    source_local_cache_paths = [
        (
            source_path.parent
            / "__pycache__"
            / f"{source_path.stem}.{cache_tag}{f'.opt-{optimization}' if optimization else ''}.pyc",
            optimize_level,
        )
        for optimization, optimize_level in _BYTECODE_CACHE_OPTIMIZATIONS
    ]
    for source_local_cache_path in source_local_cache_paths:
        if source_local_cache_path not in cache_paths:
            cache_paths.append(source_local_cache_path)

    cache_paths_by_directory: dict[Path, list[Path]] = {}
    for cache_path, _ in cache_paths:
        cache_paths_by_directory.setdefault(cache_path.parent, []).append(cache_path)
    for cache_directory, directory_cache_paths in cache_paths_by_directory.items():
        _track_shared_source_paths(
            (cache_directory,),
            read_limit=_MAX_BYTECODE_CACHE_DIRECTORY_BYTES,
        )
        try:
            if cache_directory.is_dir():
                default_cache_name = directory_cache_paths[0].name
                optimized_prefix = f"{default_cache_name[:-4]}.opt-"
                expected_cache_names = {cache_path.name for cache_path in directory_cache_paths}
                for index, candidate in enumerate(cache_directory.iterdir()):
                    if index >= _MAX_BYTECODE_CACHE_DIRECTORY_ENTRIES:
                        return True
                    if not candidate.is_file():
                        continue
                    if _other_cpython_cache_targets_source(
                        candidate.name,
                        source_path,
                        expected_cache_names,
                    ):
                        return True
                    if candidate.name.startswith(optimized_prefix) and candidate.name.endswith(".pyc"):
                        optimization = candidate.name[len(optimized_prefix) : -4]
                        if optimization.isdecimal() and int(optimization) > 2:
                            return True
        except OSError:
            return True
    _track_shared_source_paths(
        (cache_path for cache_path, _ in cache_paths),
        read_limit=_MAX_BYTECODE_CACHE_BYTES,
    )
    return any(
        _bytecode_cache_can_override_source(cache_path, source_path, source, optimize_level)
        for cache_path, optimize_level in cache_paths
    )


def _other_cpython_cache_targets_source(
    candidate_name: str,
    source_path: Path,
    expected_cache_names: set[str],
) -> bool:
    if candidate_name in expected_cache_names:
        return False
    prefix = f"{source_path.stem}.cpython-"
    if not candidate_name.startswith(prefix) or not candidate_name.endswith(".pyc"):
        return False
    tag_and_optimization = candidate_name[len(prefix) : -4]
    version, separator, optimization = tag_and_optimization.partition(".opt-")
    if not version.isdecimal():
        return False
    return not separator or optimization.isdecimal()


def _bytecode_cache_can_override_source(
    cache_path: Path,
    source_path: Path,
    source: str,
    optimize_level: int,
) -> bool:
    if not cache_path.is_file():
        return False
    try:
        if cache_path.stat().st_size > _MAX_BYTECODE_CACHE_BYTES:
            return True
        cache_bytes = cache_path.read_bytes()
    except OSError:
        return True
    header = cache_bytes[:16]
    if len(header) < 8:
        return False
    if header[:4] != MAGIC_NUMBER:
        return False
    flags = int.from_bytes(header[4:8], "little")
    if flags & ~0x03:
        return False
    if not flags & 0x01:
        if len(header) < 16:
            return False
        source_stat = source_path.stat()
        cached_mtime = int.from_bytes(header[8:12], "little")
        cached_size = int.from_bytes(header[12:16], "little")
        if cached_mtime != int(source_stat.st_mtime) & 0xFFFFFFFF or cached_size != source_stat.st_size & 0xFFFFFFFF:
            return False
    source_code = compile(source, str(source_path), "exec", dont_inherit=True, optimize=optimize_level)
    return cache_bytes[16:] != marshal.dumps(source_code)


def _module_level_statements(tree: ast.Module) -> tuple[ast.stmt, ...]:
    return _definition_scope_statements(tree.body)


def _module_initialization_statement_is_inert(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Pass):
        return True
    if isinstance(statement, ast.Expr):
        return isinstance(statement.value, ast.Constant)
    if isinstance(statement, ast.Import):
        return all(_stdlib_import_is_reviewed_inert(alias.name) for alias in statement.names)
    if isinstance(statement, ast.ImportFrom):
        if statement.level == 0 and statement.module == "__future__":
            return all(alias.name != "*" for alias in statement.names)
        return (
            statement.level == 0
            and statement.module is not None
            and all(alias.name != "*" for alias in statement.names)
            and _stdlib_import_is_reviewed_inert(statement.module)
        )
    if isinstance(statement, ast.Assign):
        return all(_inert_assignment_target(target) for target in statement.targets) and _inert_definition_expression(
            statement.value
        )
    if isinstance(statement, ast.AnnAssign):
        return (
            _inert_assignment_target(statement.target)
            and _inert_definition_expression(statement.annotation)
            and (statement.value is None or _inert_definition_expression(statement.value))
        )
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
        return _inert_function_definition(statement)
    if isinstance(statement, ast.ClassDef):
        return (
            not statement.bases
            and not statement.keywords
            and not statement.decorator_list
            and not getattr(statement, "type_params", [])
            and all(_module_initialization_statement_is_inert(item) for item in statement.body)
        )
    return False


def _stdlib_import_is_reviewed_inert(module_name: str) -> bool:
    return module_name in _REVIEWED_INERT_STDLIB_IMPORTS and _trusted_module_origin_kind(module_name) == "stdlib"


def _module_statement_binds_name(statement: ast.stmt, name: str) -> bool:
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return statement.name == name
    if isinstance(statement, ast.Import):
        return any((alias.asname or alias.name.split(".")[0]) == name for alias in statement.names)
    if isinstance(statement, ast.ImportFrom):
        return any((alias.asname or alias.name) == name for alias in statement.names)
    if isinstance(statement, ast.Assign):
        return any(_assignment_target_binds_name(target, name) for target in statement.targets)
    if isinstance(statement, ast.AnnAssign):
        return _assignment_target_binds_name(statement.target, name)
    return False


def _assignment_target_binds_name(target: ast.expr, name: str) -> bool:
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, ast.Tuple | ast.List):
        return any(_assignment_target_binds_name(item, name) for item in target.elts)
    return False


def _inert_assignment_target(target: ast.expr) -> bool:
    if isinstance(target, ast.Name):
        return True
    if isinstance(target, ast.Tuple | ast.List):
        return all(_inert_assignment_target(item) for item in target.elts)
    return False


def _inert_function_definition(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if node.decorator_list or getattr(node, "type_params", []):
        return False
    argument_annotations = (
        *(argument.annotation for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)),
        node.args.vararg.annotation if node.args.vararg is not None else None,
        node.args.kwarg.annotation if node.args.kwarg is not None else None,
        node.returns,
    )
    return all(
        _inert_definition_expression(expression)
        for expression in (
            *node.args.defaults,
            *(default for default in node.args.kw_defaults if default is not None),
            *(annotation for annotation in argument_annotations if annotation is not None),
        )
    )


def _inert_definition_expression(expression: ast.expr) -> bool:
    if isinstance(expression, ast.Constant | ast.Name):
        return True
    if isinstance(expression, ast.Attribute):
        return _inert_definition_expression(expression.value)
    if isinstance(expression, ast.Tuple | ast.List | ast.Set):
        return all(_inert_definition_expression(item) for item in expression.elts)
    if isinstance(expression, ast.Dict):
        return all(
            key is not None and _inert_definition_expression(key) and _inert_definition_expression(value)
            for key, value in zip(expression.keys, expression.values, strict=True)
        )
    if isinstance(expression, ast.UnaryOp):
        return isinstance(expression.op, ast.UAdd | ast.USub | ast.Not | ast.Invert) and _inert_definition_expression(
            expression.operand
        )
    if isinstance(expression, ast.Lambda):
        return all(
            _inert_definition_expression(default)
            for default in (
                *expression.args.defaults,
                *(item for item in expression.args.kw_defaults if item is not None),
            )
        )
    return False


def _definition_scope_statements(nodes: Iterable[ast.stmt]) -> tuple[ast.stmt, ...]:
    statements: list[ast.stmt] = []

    def visit(scope_nodes: Iterable[ast.stmt]) -> None:
        for statement in scope_nodes:
            statements.append(statement)
            for child_body in _definition_scope_child_bodies(statement):
                visit(child_body)

    visit(nodes)
    return tuple(statements)


def _definition_scope_child_bodies(statement: ast.stmt) -> tuple[Iterable[ast.stmt], ...]:
    if isinstance(statement, ast.If):
        return (statement.body, statement.orelse)
    if isinstance(statement, ast.Try):
        return (
            statement.body,
            *(handler.body for handler in statement.handlers),
            statement.orelse,
            statement.finalbody,
        )
    if isinstance(statement, ast.With | ast.AsyncWith):
        return (statement.body,)
    if isinstance(statement, ast.For | ast.AsyncFor | ast.While):
        return (statement.body, statement.orelse)
    if isinstance(statement, ast.Match):
        return tuple(match_case.body for match_case in statement.cases)
    return ()


def _collect_module_export_summary(
    statements: Iterable[ast.stmt],
    module_name: str,
    is_package: bool,
) -> _WildcardExportSummary:
    direct_names: set[str] = set()
    wildcard_imports: list[str] = []
    for statement in statements:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            direct_names.add(statement.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                direct_names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(statement, ast.ImportFrom):
            if statement.module == "__future__":
                continue
            imported_module = _resolve_import_from_module(module_name, is_package, statement.level, statement.module)
            for alias in statement.names:
                if alias.name == "*":
                    if imported_module and len(wildcard_imports) < _MAX_WILDCARD_IMPORTS:
                        wildcard_imports.append(imported_module)
                    continue
                direct_names.add(alias.asname or alias.name)
        elif isinstance(statement, ast.Assign | ast.AnnAssign):
            direct_names.update(_assignment_alias_target_names(statement))
    return _WildcardExportSummary(frozenset(direct_names), tuple(wildcard_imports))


def _collect_aliases(statements: Iterable[ast.stmt], module_name: str, is_package: bool) -> dict[str, str]:
    return _collect_import_aliases(statements, module_name, is_package)


def _collect_import_aliases(nodes: Iterable[ast.AST], module_name: str, is_package: bool) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in nodes:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    local_name = alias.name.split(".")[0]
                    aliases[local_name] = local_name
        elif isinstance(statement, ast.ImportFrom):
            if statement.module == "__future__":
                continue
            imported_module = _resolve_import_from_module(module_name, is_package, statement.level, statement.module)
            for alias in statement.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                aliases[local_name] = f"{imported_module}.{alias.name}" if imported_module else alias.name
    return aliases


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _collect_function_import_aliases(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    is_package: bool,
) -> dict[str, str]:
    aliases: dict[str, str] = {}

    class _FunctionImportAliasVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function_node:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is function_node:
                self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return None

        def visit_Lambda(self, node: ast.Lambda) -> None:
            self.visit(node.args)

        def visit_Import(self, node: ast.Import) -> None:
            aliases.update(_collect_import_aliases((node,), module_name, is_package))

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            aliases.update(_collect_import_aliases((node,), module_name, is_package))

    _FunctionImportAliasVisitor().visit(function_node)
    return aliases


def _collect_local_defs(statements: Iterable[ast.stmt]) -> set[str]:
    local_defs: set[str] = set()
    for statement in statements:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            local_defs.add(statement.name)
    return local_defs


def _collect_local_class_entrypoints(
    statements: Iterable[ast.stmt],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
) -> dict[str, tuple[str, ...]]:
    class_entrypoints: dict[str, tuple[str, ...]] = {}
    statement_tuple = tuple(statements)
    local_class_nodes = _local_class_nodes(statement_tuple)
    for statement in statement_tuple:
        if not isinstance(statement, ast.ClassDef):
            continue
        class_name = f"{module_name}.{statement.name}"
        method_names = set(_class_method_nodes(statement))
        inherited_method_names = set(
            _inherited_class_methods(
                statement,
                module_name,
                aliases,
                local_defs,
                local_class_nodes,
            )
        )
        entrypoints = tuple(
            f"{class_name}.{method_name}"
            for method_name in _CLASS_ENTRYPOINT_METHODS
            if method_name in method_names
            or (method_name in inherited_method_names and method_name in _INHERITED_CLASS_ENTRYPOINT_METHODS)
        )
        existing = class_entrypoints.get(class_name)
        class_entrypoints[class_name] = entrypoints if existing is None else _dedupe_calls((*existing, *entrypoints))
    return class_entrypoints


def _local_class_nodes(statements: Iterable[ast.stmt]) -> dict[str, ast.ClassDef]:
    return {statement.name: statement for statement in statements if isinstance(statement, ast.ClassDef)}


def _class_method_nodes(class_node: ast.ClassDef) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        child.name: child
        for child in _definition_scope_statements(class_node.body)
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def _inherited_class_methods(
    class_node: ast.ClassDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_nodes: dict[str, ast.ClassDef],
) -> dict[str, _InheritedClassMethod]:
    inherited: dict[str, _InheritedClassMethod] = {}
    direct_method_names = set(_class_method_nodes(class_node))
    visited: set[str] = set()

    def visit_base(context: _ClassSourceContext) -> None:
        base_key = f"{context.module_name}.{context.class_node.name}"
        if base_key in visited or len(inherited) >= _MAX_INHERITED_CLASS_METHODS:
            return
        visited.add(base_key)
        for method_name, method_node in _class_method_nodes(context.class_node).items():
            if method_name in direct_method_names or method_name in inherited:
                continue
            inherited[method_name] = _InheritedClassMethod(
                name=method_name,
                node=method_node,
                module_name=context.module_name,
                aliases=context.aliases,
                local_defs=context.local_defs,
            )
            if len(inherited) >= _MAX_INHERITED_CLASS_METHODS:
                return
        for nested_base in _class_base_targets(
            context.class_node,
            context.module_name,
            context.aliases,
            context.local_defs,
        ):
            nested_context = _class_source_context_for_target(
                nested_base,
                context.module_name,
                context.aliases,
                context.local_defs,
                context.local_class_nodes,
            )
            if nested_context is not None:
                visit_base(nested_context)

    for base in _class_base_targets(class_node, module_name, aliases, local_defs):
        base_context = _class_source_context_for_target(
            base,
            module_name,
            aliases,
            local_defs,
            local_class_nodes,
        )
        if base_context is not None:
            visit_base(base_context)
    return inherited


def _class_source_context_for_target(
    class_target: str,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_nodes: dict[str, ast.ClassDef],
) -> _ClassSourceContext | None:
    local_class_node = _local_class_node_from_target(class_target, module_name, local_class_nodes)
    if local_class_node is not None:
        return _ClassSourceContext(
            module_name=module_name,
            class_node=local_class_node,
            aliases=aliases,
            local_defs=local_defs,
            local_class_nodes=local_class_nodes,
        )
    return _source_class_context(class_target)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _source_function_context(
    function_name: str,
) -> tuple[str, bool, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    module_name, qualified_name = _split_source_qualified_name(function_name)
    if module_name is None:
        return None
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return None
    try:
        source = _read_bounded_source_text(source_path)
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return None

    module_statements = _module_level_statements(tree)
    function_node = _find_qualified_function_def(module_statements, qualified_name)
    if function_node is None:
        return _inherited_source_function_context(module_statements, module_name, source_path, qualified_name)
    return module_name, source_path.name == "__init__.py", function_node


def _inherited_source_function_context(
    module_statements: Iterable[ast.stmt],
    module_name: str,
    source_path: Path,
    qualified_name: str,
) -> tuple[str, bool, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    class_qualified_name, _separator, method_name = qualified_name.rpartition(".")
    if not class_qualified_name or not method_name:
        return None
    class_node = _find_qualified_class_def(module_statements, class_qualified_name)
    if class_node is None:
        return None
    is_package = source_path.name == "__init__.py"
    aliases = _collect_aliases(module_statements, module_name, is_package)
    local_defs = _collect_local_defs(module_statements)
    inherited_method = _inherited_class_methods(
        class_node,
        module_name,
        aliases,
        local_defs,
        _local_class_nodes(module_statements),
    ).get(method_name)
    if inherited_method is None:
        return None
    inherited_source_path = _resolve_module_source(inherited_method.module_name)
    inherited_is_package = inherited_source_path is not None and inherited_source_path.name == "__init__.py"
    return inherited_method.module_name, inherited_is_package, inherited_method.node


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _source_class_context(class_name: str) -> _ClassSourceContext | None:
    module_name, qualified_name = _split_source_qualified_name(class_name)
    if module_name is None:
        return None
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return None
    try:
        source = _read_bounded_source_text(source_path)
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return None

    module_statements = _module_level_statements(tree)
    class_node = _find_qualified_class_def(module_statements, qualified_name)
    if class_node is None:
        return None
    is_package = source_path.name == "__init__.py"
    aliases = _collect_aliases(module_statements, module_name, is_package)
    local_defs = _collect_local_defs(module_statements)
    return _ClassSourceContext(
        module_name=module_name,
        class_node=class_node,
        aliases=aliases,
        local_defs=local_defs,
        local_class_nodes=_local_class_nodes(module_statements),
    )


def _local_class_node_from_target(
    class_target: str,
    module_name: str,
    local_class_nodes: dict[str, ast.ClassDef],
) -> ast.ClassDef | None:
    prefix = f"{module_name}."
    if not class_target.startswith(prefix):
        return None
    class_name = class_target[len(prefix) :]
    if "." in class_name:
        return None
    return local_class_nodes.get(class_name)


def _contains_current_loop_break(nodes: Iterable[ast.stmt]) -> bool:
    """Return whether this loop body can break without entering a nested scope or loop."""

    def contains_break(node: ast.AST) -> bool:
        if isinstance(node, ast.Break):
            return True
        if isinstance(
            node,
            ast.For | ast.AsyncFor | ast.While | ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef,
        ):
            return False
        return any(contains_break(child) for child in ast.iter_child_nodes(node))

    return any(contains_break(node) for node in nodes)


def _is_exhaustive_match(node: ast.Match) -> bool:
    return any(
        isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None
        for case in node.cases
    )


_TerminalAssignment = ast.Assign | ast.AnnAssign
_TerminalAssignmentGroup = tuple[str, tuple[_TerminalAssignment | None, ...]]


def _can_complete_normally(branch_body: Iterable[ast.stmt]) -> bool:
    statements = tuple(branch_body)
    return not statements or not isinstance(statements[-1], ast.Raise | ast.Return)


def _assignment_alias_targets(branch_body: Iterable[ast.stmt]) -> set[str]:
    targets: set[str] = set()
    for statement in _definition_scope_statements(branch_body):
        targets.update(_assignment_alias_target_names(statement))
    return targets


def _terminal_assignment_groups(
    branch_bodies: tuple[tuple[ast.stmt, ...], ...],
) -> tuple[_TerminalAssignmentGroup, ...]:
    terminal_assignments: list[dict[str, _TerminalAssignment]] = []
    for branch_body in branch_bodies:
        suffix_assignments: dict[str, _TerminalAssignment] = {}
        for statement in reversed(branch_body):
            if isinstance(statement, ast.Expr | ast.Pass):
                continue
            if not isinstance(statement, ast.Assign | ast.AnnAssign) or statement.value is None:
                break
            for target_name in _assignment_alias_target_names(statement):
                suffix_assignments.setdefault(target_name, statement)
        terminal_assignments.append(suffix_assignments)
    if not terminal_assignments:
        return ()
    terminal_targets = set().union(*(set(assignments) for assignments in terminal_assignments))
    return tuple(
        (target_name, tuple(assignments.get(target_name) for assignments in terminal_assignments))
        for target_name in sorted(terminal_targets)
    )


def _conditionally_rebound_assignment_nodes(
    nodes: Iterable[ast.AST],
) -> tuple[dict[str, set[int]], tuple[tuple[_TerminalAssignmentGroup, ...], ...]]:
    """Return alternate-path assignment nodes grouped by ambiguously rebound name."""
    node_list = tuple(nodes)
    ambiguous_assignment_nodes: dict[str, set[int]] = {}
    terminal_assignment_group_sets: list[tuple[_TerminalAssignmentGroup, ...]] = []
    for node in node_list:
        alternate_bodies: tuple[Iterable[ast.stmt], ...]
        branch_bodies: tuple[Iterable[ast.stmt], ...]
        terminating_bodies: tuple[Iterable[ast.stmt], ...]
        deterministic_terminal_bodies: tuple[Iterable[ast.stmt], ...] | None = None
        if isinstance(node, ast.If):
            alternate_bodies = (node.body, node.orelse)
            terminating_bodies = tuple(
                branch_body for branch_body in alternate_bodies if not _can_complete_normally(branch_body)
            )
            branch_bodies = tuple(
                branch_body for branch_body in alternate_bodies if _can_complete_normally(branch_body)
            )
            continuing_targets = set().union(*(_assignment_alias_targets(branch_body) for branch_body in branch_bodies))
            terminating_targets = set().union(
                *(_assignment_alias_targets(branch_body) for branch_body in terminating_bodies)
            )
            if continuing_targets & terminating_targets:
                branch_bodies = alternate_bodies
            if len(branch_bodies) < 2:
                continue
            deterministic_terminal_bodies = branch_bodies
        elif isinstance(node, ast.Try) and node.handlers:
            alternate_bodies = (
                (*node.body, *node.orelse),
                *(handler.body for handler in node.handlers),
            )
            terminating_bodies = tuple(
                branch_body for branch_body in alternate_bodies if not _can_complete_normally(branch_body)
            )
            branch_bodies = tuple(
                branch_body for branch_body in alternate_bodies if _can_complete_normally(branch_body)
            )
            continuing_targets = set().union(*(_assignment_alias_targets(branch_body) for branch_body in branch_bodies))
            terminating_targets = set().union(
                *(_assignment_alias_targets(branch_body) for branch_body in terminating_bodies)
            )
            if continuing_targets & terminating_targets:
                branch_bodies = alternate_bodies
            if len(branch_bodies) < 2:
                continue
            deterministic_terminal_bodies = branch_bodies
        elif isinstance(node, ast.For | ast.AsyncFor | ast.While) and _contains_current_loop_break(node.body):
            branch_bodies = (node.body, node.orelse)
            if node.body and isinstance(node.body[-1], ast.Break) and not _contains_current_loop_break(node.body[:-1]):
                deterministic_terminal_bodies = (node.body[:-1], node.orelse)
        elif isinstance(node, ast.Match):
            branch_bodies = tuple(case.body for case in node.cases)
            if _is_exhaustive_match(node):
                deterministic_terminal_bodies = branch_bodies
        else:
            continue

        branch_statement_bodies = tuple(tuple(branch_body) for branch_body in branch_bodies)
        for branch_body in branch_statement_bodies:
            for statement in _definition_scope_statements(branch_body):
                for target_name in _assignment_alias_target_names(statement):
                    ambiguous_assignment_nodes.setdefault(target_name, set()).add(id(statement))

        if deterministic_terminal_bodies is not None:
            groups = _terminal_assignment_groups(
                tuple(tuple(branch_body) for branch_body in deterministic_terminal_bodies)
            )
            if groups:
                terminal_assignment_group_sets.append(groups)
    return ambiguous_assignment_nodes, tuple(terminal_assignment_group_sets)


def _resolved_terminal_assignment_nodes(
    nodes: tuple[ast.AST, ...],
    terminal_assignment_group_sets: tuple[tuple[_TerminalAssignmentGroup, ...], ...],
    ambiguous_assignment_nodes: dict[str, set[int]],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None,
) -> dict[str, set[int]]:
    deterministic_node_ids: dict[str, set[int]] = {}

    def incoming_alias_value(
        target_name: str,
        statements: tuple[_TerminalAssignment | None, ...],
        effective_ambiguous_node_ids: dict[str, set[int]],
    ) -> tuple[bool, str | None]:
        statement_ids = {id(statement) for statement in statements if statement is not None}
        first_index = min(index for index, node in enumerate(nodes) if id(node) in statement_ids)
        found_prior_assignment = False
        incoming_value: str | None = None
        for node in nodes[:first_index]:
            if target_name not in _assignment_alias_target_names(node):
                continue
            if id(node) in effective_ambiguous_node_ids.get(target_name, set()):
                continue
            found_prior_assignment = True
            incoming_value = _assignment_alias_value(
                node,
                module_name,
                aliases,
                local_defs,
                local_class_targets,
                class_name=class_name,
            )
        return found_prior_assignment, incoming_value

    while True:
        effective_ambiguous_node_ids = {
            target_name: node_ids - deterministic_node_ids.get(target_name, set())
            for target_name, node_ids in ambiguous_assignment_nodes.items()
            if node_ids - deterministic_node_ids.get(target_name, set())
        }
        active_ambiguous_targets: set[str] = set()
        ambiguous_before_statement: dict[int, set[str]] = {}
        for node in nodes:
            target_names = _assignment_alias_target_names(node)
            if not target_names:
                continue
            ambiguous_before_statement[id(node)] = set(active_ambiguous_targets)
            for target_name in target_names:
                if id(node) in effective_ambiguous_node_ids.get(target_name, set()):
                    active_ambiguous_targets.add(target_name)
                else:
                    active_ambiguous_targets.discard(target_name)

        changed = False
        for terminal_assignment_groups in terminal_assignment_group_sets:
            branch_count = len(terminal_assignment_groups[0][1])
            resolved_by_branch: list[dict[str, str]] = []
            for branch_index in range(branch_count):
                branch_statements: dict[int, _TerminalAssignment] = {}
                for _, statements in terminal_assignment_groups:
                    statement = statements[branch_index]
                    if statement is not None:
                        branch_statements[id(statement)] = statement
                branch_aliases = dict(aliases)
                branch_local_targets: set[str] = set()
                branch_resolved: dict[str, str] = {}
                for statement in sorted(
                    branch_statements.values(),
                    key=lambda statement: (statement.lineno, statement.col_offset),
                ):
                    blocked_dependencies = (
                        _assignment_value_read_names(statement)
                        & ambiguous_before_statement.get(id(statement), set()) - branch_local_targets
                    )
                    if blocked_dependencies:
                        continue
                    resolved = _assignment_alias_value(
                        statement,
                        module_name,
                        branch_aliases,
                        local_defs,
                        local_class_targets,
                        class_name=class_name,
                    )
                    if resolved is None:
                        continue
                    for target_name in _assignment_alias_target_names(statement):
                        branch_aliases[target_name] = resolved
                        branch_local_targets.add(target_name)
                        branch_resolved[target_name] = resolved
                resolved_by_branch.append(branch_resolved)

            for target_name, statements in terminal_assignment_groups:
                present_values = tuple(
                    resolved_by_branch[index].get(target_name)
                    for index, statement in enumerate(statements)
                    if statement is not None
                )
                if None in present_values:
                    continue
                resolved_values = list(present_values)
                if any(statement is None for statement in statements):
                    present_statements = tuple(statement for statement in statements if statement is not None)
                    if any(
                        target_name in ambiguous_before_statement.get(id(statement), set())
                        for statement in present_statements
                    ):
                        continue
                    found_incoming, incoming_value = incoming_alias_value(
                        target_name,
                        statements,
                        effective_ambiguous_node_ids,
                    )
                    if found_incoming:
                        if incoming_value is None:
                            continue
                        resolved_values.append(incoming_value)
                if resolved_values and len(set(resolved_values)) == 1:
                    node_ids = deterministic_node_ids.setdefault(target_name, set())
                    prior_count = len(node_ids)
                    node_ids.update(id(statement) for statement in statements if statement is not None)
                    changed = changed or len(node_ids) != prior_count
        if not changed:
            break
    return deterministic_node_ids


def _propagated_ambiguous_assignment_nodes(
    nodes: tuple[ast.AST, ...],
    ambiguous_assignment_nodes: dict[str, set[int]],
    deterministic_node_ids: dict[str, set[int]],
    *,
    propagate_reads: bool,
) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    effective_ambiguous_node_ids = {
        target_name: node_ids - deterministic_node_ids.get(target_name, set())
        for target_name, node_ids in ambiguous_assignment_nodes.items()
        if node_ids - deterministic_node_ids.get(target_name, set())
    }
    propagated_assignment_nodes: dict[str, set[int]] = {}
    if not propagate_reads:
        return effective_ambiguous_node_ids, propagated_assignment_nodes
    active_ambiguous_targets: set[str] = set()
    for node in nodes:
        target_names = _assignment_alias_target_names(node)
        if not target_names:
            continue
        reads_ambiguous_target = bool(_assignment_alias_read_names(node) & active_ambiguous_targets)
        for target_name in target_names:
            conditional_node_ids = effective_ambiguous_node_ids.get(target_name, set())
            if id(node) in conditional_node_ids or reads_ambiguous_target:
                if reads_ambiguous_target:
                    effective_ambiguous_node_ids.setdefault(target_name, set()).add(id(node))
                    propagated_assignment_nodes.setdefault(target_name, set()).add(id(node))
                active_ambiguous_targets.add(target_name)
            else:
                active_ambiguous_targets.discard(target_name)
    return effective_ambiguous_node_ids, propagated_assignment_nodes


def _collect_assignment_aliases(
    nodes: Iterable[ast.AST],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None = None,
) -> dict[str, str]:
    node_list = tuple(nodes)
    assignment_aliases: dict[str, str] = {}
    source_path = _resolve_module_source(module_name)
    conditionally_rebound_node_ids, terminal_assignment_group_sets = _conditionally_rebound_assignment_nodes(node_list)
    seen_states: set[tuple[tuple[str, str], ...]] = {()}
    passes = 0

    changed = True
    while changed and len(assignment_aliases) < _MAX_ASSIGNMENT_ALIASES:
        if passes >= _MAX_ASSIGNMENT_ALIAS_PASSES:
            raise _CallGraphAnalysisLimitError(
                f"assignment alias analysis exceeded {_MAX_ASSIGNMENT_ALIAS_PASSES} propagation passes"
            )
        passes += 1
        state = tuple(sorted(assignment_aliases.items()))
        changed = False
        last_changed_node_ids: dict[str, int] = {}
        last_resolved_node_ids: dict[str, int] = {}
        scoped_aliases = {**aliases, **assignment_aliases}
        for node in node_list:
            resolved = _assignment_alias_value(
                node,
                module_name,
                scoped_aliases,
                local_defs,
                local_class_targets,
                class_name=class_name,
            )
            if resolved is None:
                continue
            for target_name in _assignment_alias_target_names(node):
                last_resolved_node_ids[target_name] = id(node)
                if assignment_aliases.get(target_name) == resolved:
                    continue
                assignment_aliases[target_name] = resolved
                changed = True
                last_changed_node_ids[target_name] = id(node)
                if len(assignment_aliases) >= _MAX_ASSIGNMENT_ALIASES:
                    break
        next_state = tuple(sorted(assignment_aliases.items()))
        if next_state == state:
            deterministic_node_ids = _resolved_terminal_assignment_nodes(
                node_list,
                terminal_assignment_group_sets,
                conditionally_rebound_node_ids,
                module_name,
                {**aliases, **assignment_aliases},
                local_defs,
                local_class_targets,
                class_name=class_name,
            )
            effective_conditionally_rebound_node_ids, propagated_rebound_node_ids = (
                _propagated_ambiguous_assignment_nodes(
                    node_list,
                    conditionally_rebound_node_ids,
                    deterministic_node_ids,
                    propagate_reads=source_path is None or not _is_stdlib_source_path(str(source_path)),
                )
            )
            changed_conditionally = any(
                node_id in effective_conditionally_rebound_node_ids.get(target_name, set())
                for target_name, node_id in last_changed_node_ids.items()
            )
            resolved_from_conditional_read = any(
                node_id in propagated_rebound_node_ids.get(target_name, set())
                for target_name, node_id in last_resolved_node_ids.items()
            )
            if changed_conditionally or resolved_from_conditional_read:
                raise _CallGraphAnalysisLimitError(
                    "assignment alias analysis encountered ambiguous conditional rebinding"
                )
            break
        if next_state in seen_states:
            raise _CallGraphAnalysisLimitError("assignment alias analysis entered a propagation cycle")
        seen_states.add(next_state)
    return assignment_aliases


def _assignment_alias_value(
    node: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None,
) -> str | None:
    value: ast.AST | None
    if isinstance(node, ast.Assign | ast.AnnAssign):
        value = node.value
    else:
        return None
    if value is None:
        return None

    if isinstance(value, ast.Call):
        call_target = _resolve_expr(value.func, module_name, aliases, local_defs, class_name)
        if call_target in local_class_targets:
            return call_target
        return None

    resolved = _resolve_expr(value, module_name, aliases, local_defs, class_name)
    if resolved is None:
        return None
    if _is_local_class_member_alias(resolved, local_class_targets):
        return resolved
    if (
        _rce_sink(resolved) is not None
        or _file_open_sink(resolved) is not None
        or _file_write_sink(resolved) is not None
    ):
        return resolved
    alias_target = _static_import_reference_alias(resolved) or resolved
    if alias_target.startswith(f"{module_name}."):
        return None
    current_source_path = _resolve_module_source(module_name)
    if current_source_path is None or _is_library_source_path(str(current_source_path)):
        return None
    imported_module, imported_name = _split_source_qualified_name(alias_target)
    source_path = _resolve_module_source(imported_module) if imported_module is not None else None
    if (
        imported_module is not None
        and imported_module != module_name
        and imported_name
        and source_path is not None
        and not _is_stdlib_source_path(str(source_path))
    ):
        return resolved
    return None


def _assignment_alias_target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Assign):
        targets: set[str] = set()
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.add(target.id)
        return targets
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}
    return set()


def _assignment_alias_read_names(node: ast.AST) -> set[str]:
    if not isinstance(node, ast.Assign | ast.AnnAssign) or node.value is None:
        return set()
    value = node.value
    if isinstance(value, ast.Call):
        value = value.func
    while isinstance(value, ast.Attribute):
        value = value.value
    if isinstance(value, ast.Name):
        return {value.id}
    return set()


def _assignment_value_read_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    if node.value is None:
        return set()

    names: set[str] = set()

    def binding_names(target: ast.AST) -> set[str]:
        return {child.id for child in ast.walk(target) if isinstance(child, ast.Name)}

    def visit(value: ast.AST, bound_names: set[str]) -> None:
        if isinstance(value, ast.Name):
            if isinstance(value.ctx, ast.Load) and value.id not in bound_names:
                names.add(value.id)
            return
        if isinstance(value, ast.Lambda):
            for default in (
                *value.args.defaults,
                *(default for default in value.args.kw_defaults if default is not None),
            ):
                visit(default, bound_names)
            lambda_bound_names = {
                argument.arg
                for argument in (
                    *value.args.posonlyargs,
                    *value.args.args,
                    *value.args.kwonlyargs,
                )
            }
            if value.args.vararg is not None:
                lambda_bound_names.add(value.args.vararg.arg)
            if value.args.kwarg is not None:
                lambda_bound_names.add(value.args.kwarg.arg)
            visit(value.body, bound_names | lambda_bound_names)
            return
        if isinstance(value, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            comprehension_bound_names = set(bound_names)
            for generator in value.generators:
                visit(generator.iter, comprehension_bound_names)
                comprehension_bound_names.update(binding_names(generator.target))
                for condition in generator.ifs:
                    visit(condition, comprehension_bound_names)
            if isinstance(value, ast.DictComp):
                visit(value.key, comprehension_bound_names)
                visit(value.value, comprehension_bound_names)
            else:
                visit(value.elt, comprehension_bound_names)
            return
        for child in ast.iter_child_nodes(value):
            visit(child, bound_names)

    visit(node.value, set())
    return names


def _is_local_class_member_alias(resolved: str, local_class_targets: set[str]) -> bool:
    return any(
        resolved == class_target or resolved.startswith(f"{class_target}.") for class_target in local_class_targets
    )


def _looks_like_class_reference(function_name: str) -> bool:
    tail = function_name.rpartition(".")[2]
    return bool(tail and tail[0].isupper())


def _should_expand_imported_class_reference(function_name: str, module_name: str) -> bool:
    if not _looks_like_class_reference(function_name) or function_name.startswith(f"{module_name}."):
        return False
    current_source_path = _resolve_module_source(module_name)
    if current_source_path is None or _is_library_source_path(str(current_source_path)):
        return False
    imported_module, imported_name = _split_source_qualified_name(function_name)
    if imported_module is None or not imported_name:
        return False
    source_path = _resolve_module_source(imported_module)
    return source_path is not None and not _is_stdlib_source_path(str(source_path))


def _is_library_source_path(source_path: str) -> bool:
    return _is_stdlib_source_path(source_path) or _is_installed_package_source_path(source_path)


@lru_cache(maxsize=1024)
def _is_stdlib_source_path(source_path: str) -> bool:
    try:
        resolved = Path(source_path).resolve()
        stdlib = Path(sysconfig.get_paths()["stdlib"]).resolve()
    except Exception:
        return False
    return (
        resolved.is_relative_to(stdlib)
        and "site-packages" not in resolved.parts
        and "dist-packages" not in resolved.parts
    )


def _is_installed_package_source_path(source_path: str) -> bool:
    parts = Path(source_path).parts
    return "site-packages" in parts or "dist-packages" in parts


def _collect_class_instance_default_aliases(
    statements: Iterable[ast.stmt],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
) -> dict[str, str]:
    instance_aliases: dict[str, str] = {}
    for statement in statements:
        if not isinstance(statement, ast.ClassDef):
            continue
        init_node = next(
            (
                child
                for child in statement.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) and child.name == "__init__"
            ),
            None,
        )
        if init_node is None:
            continue
        default_aliases = _parameter_default_sink_aliases(
            init_node,
            module_name,
            aliases,
            local_defs,
            local_class_targets,
        )
        if not default_aliases:
            continue
        for node in ast.walk(init_node):
            if not isinstance(node, ast.Assign | ast.AnnAssign):
                continue
            value = node.value
            if not isinstance(value, ast.Name):
                continue
            resolved = default_aliases.get(value.id)
            if resolved is None:
                continue
            for target_name in sorted(_self_attribute_assignment_target_names(node)):
                instance_aliases[f"{statement.name}.{target_name}"] = resolved
                if len(instance_aliases) >= _MAX_CLASS_INSTANCE_ALIASES:
                    return instance_aliases
        for call_node in _iter_call_nodes(init_node):
            if not _is_super_init_call(call_node.func):
                continue
            forwarded_defaults = _super_init_forwarded_sink_defaults(call_node, default_aliases)
            if not forwarded_defaults:
                continue
            for base_target in _class_base_targets(statement, module_name, aliases, local_defs):
                for parameter_name, resolved in forwarded_defaults.items():
                    for target_name in _constructor_parameter_self_attribute_targets(base_target, parameter_name):
                        instance_aliases[f"{statement.name}.{target_name}"] = resolved
                        if len(instance_aliases) >= _MAX_CLASS_INSTANCE_ALIASES:
                            return instance_aliases
    return instance_aliases


def _parameter_default_sink_aliases(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
) -> dict[str, str]:
    default_aliases: dict[str, str] = {}
    positional_args = (*function_node.args.posonlyargs, *function_node.args.args)
    positional_defaults = function_node.args.defaults
    if positional_defaults:
        for arg, default in zip(positional_args[-len(positional_defaults) :], positional_defaults, strict=True):
            if arg.arg in {"self", "cls"}:
                continue
            resolved = _sink_alias_default_target(default, module_name, aliases, local_defs, local_class_targets)
            if resolved is not None:
                default_aliases[arg.arg] = resolved
    for arg, keyword_default in zip(function_node.args.kwonlyargs, function_node.args.kw_defaults, strict=True):
        if keyword_default is None or arg.arg in {"self", "cls"}:
            continue
        resolved = _sink_alias_default_target(keyword_default, module_name, aliases, local_defs, local_class_targets)
        if resolved is not None:
            default_aliases[arg.arg] = resolved
    return default_aliases


def _sink_alias_default_target(
    default: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
) -> str | None:
    resolved = _resolve_expr(default, module_name, aliases, local_defs)
    if resolved is None or _is_local_class_member_alias(resolved, local_class_targets):
        return None
    alias_target = _static_import_reference_alias(resolved) or resolved
    if (
        _rce_sink(alias_target) is not None
        or _file_open_sink(alias_target) is not None
        or _file_write_sink(alias_target) is not None
    ):
        return alias_target
    return None


def _self_attribute_assignment_target_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    targets: list[ast.AST] = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
    names: set[str] = set()
    for target in targets:
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
            names.add(target.attr)
    return names


def _is_super_init_call(expression: ast.AST) -> bool:
    return (
        isinstance(expression, ast.Attribute)
        and expression.attr == "__init__"
        and isinstance(expression.value, ast.Call)
        and isinstance(expression.value.func, ast.Name)
        and expression.value.func.id == "super"
    )


def _super_init_forwarded_sink_defaults(call_node: ast.Call, default_aliases: dict[str, str]) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    for keyword in call_node.keywords:
        if keyword.arg is None or not isinstance(keyword.value, ast.Name):
            continue
        resolved = default_aliases.get(keyword.value.id)
        if resolved is not None:
            forwarded[keyword.arg] = resolved
    return forwarded


def _class_base_targets(
    class_node: ast.ClassDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
) -> tuple[str, ...]:
    targets: list[str] = []
    for base in class_node.bases:
        resolved = _resolve_expr(base, module_name, aliases, local_defs)
        if resolved is not None:
            targets.append(resolved)
    return tuple(targets)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _constructor_parameter_self_attribute_targets(class_name: str, parameter_name: str) -> tuple[str, ...]:
    module_name, qualified_name = _split_source_qualified_name(class_name)
    if module_name is None:
        return ()
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return ()
    try:
        source = _read_bounded_source_text(source_path)
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return ()

    class_node = _find_qualified_class_def(_module_level_statements(tree), qualified_name)
    if class_node is None:
        return ()
    init_node = next(
        (
            child
            for child in class_node.body
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) and child.name == "__init__"
        ),
        None,
    )
    if init_node is None:
        return ()

    target_names: set[str] = set()
    for node in ast.walk(init_node):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        value = node.value
        if isinstance(value, ast.Name) and value.id == parameter_name:
            target_names.update(_self_attribute_assignment_target_names(node))
    return tuple(sorted(target_names))


def _split_source_qualified_name(function_name: str) -> tuple[str | None, str]:
    parts = function_name.split(".")
    for index in range(len(parts) - 1, 0, -1):
        module_name = ".".join(parts[:index])
        if _resolve_module_source(module_name) is not None:
            return module_name, ".".join(parts[index:])
    return None, function_name


def _find_qualified_class_def(statements: Iterable[ast.stmt], qualified_name: str) -> ast.ClassDef | None:
    nodes: Iterable[ast.stmt] = statements
    current: ast.ClassDef | None = None
    for part in qualified_name.split("."):
        current = next((node for node in nodes if isinstance(node, ast.ClassDef) and node.name == part), None)
        if current is None:
            return None
        nodes = _definition_scope_statements(current.body)
    return current


def _find_qualified_function_def(
    statements: Iterable[ast.stmt],
    qualified_name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    parts = qualified_name.split(".")
    nodes: Iterable[ast.stmt] = statements
    for index, part in enumerate(parts):
        is_leaf = index == len(parts) - 1
        if is_leaf:
            return next(
                (
                    node
                    for node in nodes
                    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == part
                ),
                None,
            )
        parent = next(
            (node for node in nodes if isinstance(node, ast.ClassDef) and node.name == part),
            None,
        )
        if parent is None:
            return None
        nodes = _definition_scope_statements(parent.body)
    return None


def _collect_function_calls(
    statements: Iterable[ast.stmt],
    module_name: str,
    is_package: bool,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    local_class_entrypoints: dict[str, tuple[str, ...]],
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    calls_by_function: dict[str, tuple[str, ...]] = {}
    statement_tuple = tuple(statements)
    local_class_nodes = _local_class_nodes(statement_tuple)
    for statement in statement_tuple:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            function_name = f"{module_name}.{statement.name}"
            _add_function_calls(
                calls_by_function,
                function_name,
                _calls_in_function(
                    statement,
                    module_name,
                    is_package,
                    aliases,
                    local_defs,
                    local_class_targets,
                    local_class_entrypoints,
                ),
            )
        elif isinstance(statement, ast.ClassDef):
            for method_name, child in _class_method_nodes(statement).items():
                function_name = f"{module_name}.{statement.name}.{method_name}"
                _add_function_calls(
                    calls_by_function,
                    function_name,
                    _calls_in_function(
                        child,
                        module_name,
                        is_package,
                        aliases,
                        local_defs,
                        local_class_targets,
                        local_class_entrypoints,
                        class_name=statement.name,
                    ),
                )
            for method_name, method in _inherited_class_methods(
                statement,
                module_name,
                aliases,
                local_defs,
                local_class_nodes,
            ).items():
                function_name = f"{module_name}.{statement.name}.{method_name}"
                if function_name in calls_by_function:
                    continue
                inherited_aliases = {
                    **aliases,
                    **method.aliases,
                    **{local_name: f"{method.module_name}.{local_name}" for local_name in method.local_defs},
                }
                _add_function_calls(
                    calls_by_function,
                    function_name,
                    _calls_in_function(
                        method.node,
                        module_name,
                        is_package,
                        inherited_aliases,
                        local_defs,
                        local_class_targets,
                        local_class_entrypoints,
                        class_name=statement.name,
                    ),
                )
    return calls_by_function, local_class_entrypoints


def _add_function_calls(
    calls_by_function: dict[str, tuple[str, ...]],
    function_name: str,
    calls: tuple[str, ...],
) -> None:
    existing = calls_by_function.get(function_name)
    calls_by_function[function_name] = calls if existing is None else _dedupe_calls((*existing, *calls))


def _dedupe_calls(calls: Iterable[str]) -> tuple[str, ...]:
    deduped: list[str] = []
    seen: set[str] = set()
    for call in calls:
        if call in seen:
            continue
        seen.add(call)
        deduped.append(call)
    return tuple(deduped)


def _calls_in_function(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    is_package: bool,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    local_class_entrypoints: dict[str, tuple[str, ...]],
    *,
    class_name: str | None = None,
) -> tuple[str, ...]:
    calls: list[str] = []
    call_nodes = _iter_call_nodes(function_node)
    function_aliases = {
        **aliases,
        **_collect_function_import_aliases(function_node, module_name, is_package),
    }
    instance_aliases, parameter_controlled_names = _collect_function_instance_aliases(
        function_node,
        call_nodes,
        module_name,
        function_aliases,
        local_defs,
        local_class_targets,
        class_name=class_name,
    )
    function_aliases.update(instance_aliases)
    tcl_command_controlled_names: set[str] | None = None
    dynamic_getattr_callable_names: set[str] | None = None
    getattr_default_callable_names: dict[str, str] | None = None
    assignment_call_candidates: tuple[tuple[set[str], ast.Call], ...] | None = None
    may_use_getattr_dispatch = _may_use_getattr_dispatch(call_nodes, function_aliases)
    for node in call_nodes:
        if may_use_getattr_dispatch:
            if parameter_controlled_names is None:
                parameter_controlled_names = _parameter_controlled_names(function_node)
            if _is_controlled_direct_getattr_dispatch(
                node,
                module_name,
                function_aliases,
                local_defs,
                parameter_controlled_names,
                class_name=class_name,
            ):
                calls.append(_CONTROLLED_GETATTR_DISPATCH_SINK)
                continue
            if isinstance(node.func, ast.Name):
                if dynamic_getattr_callable_names is None:
                    if assignment_call_candidates is None:
                        assignment_call_candidates = _function_assignment_call_candidates(function_node)
                    dynamic_getattr_callable_names = _controlled_getattr_callable_names(
                        assignment_call_candidates,
                        module_name,
                        function_aliases,
                        local_defs,
                        parameter_controlled_names,
                        class_name=class_name,
                    )
                if node.func.id in dynamic_getattr_callable_names and _call_uses_parameter_controlled_argument(
                    node, parameter_controlled_names
                ):
                    calls.append(_CONTROLLED_GETATTR_DISPATCH_SINK)
                    continue
                if getattr_default_callable_names is None:
                    if assignment_call_candidates is None:
                        assignment_call_candidates = _function_assignment_call_candidates(function_node)
                    getattr_default_callable_names = _getattr_default_callable_names(
                        assignment_call_candidates,
                        call_nodes,
                        module_name,
                        function_aliases,
                        local_defs,
                        class_name=class_name,
                    )
                fallback_target = getattr_default_callable_names.get(node.func.id)
                if fallback_target is not None:
                    calls.append(fallback_target)
                    continue
            elif isinstance(node.func, ast.Call):
                fallback_target = _getattr_default_callable_target(
                    node.func,
                    module_name,
                    function_aliases,
                    local_defs,
                    class_name=class_name,
                )
                if fallback_target is not None:
                    calls.append(fallback_target)
                    continue
        resolved = _resolve_expr(node.func, module_name, function_aliases, local_defs, class_name)
        if resolved is not None:
            if _is_tcl_interpreter_dispatch_call(resolved):
                if parameter_controlled_names is None:
                    parameter_controlled_names = _parameter_controlled_names(function_node)
                if tcl_command_controlled_names is None:
                    tcl_command_controlled_names = _parameter_controlled_tcl_command_names(function_node)
                if not _tcl_dispatch_uses_parameter_controlled_command(
                    node,
                    resolved,
                    parameter_controlled_names,
                    tcl_command_controlled_names,
                ):
                    continue
            if _is_file_write_call(resolved):
                if parameter_controlled_names is None:
                    parameter_controlled_names = _parameter_controlled_names(function_node)
                if not _call_uses_parameter_controlled_argument(node, parameter_controlled_names):
                    continue
            if _is_object_subprocess_dispatch_call(resolved):
                if parameter_controlled_names is None:
                    parameter_controlled_names = _parameter_controlled_names(function_node)
                if not _call_uses_parameter_controlled_argument(node, parameter_controlled_names):
                    continue
            class_entrypoints = local_class_entrypoints.get(resolved, ())
            if not class_entrypoints and _should_expand_imported_class_reference(resolved, module_name):
                class_target = _resolve_class_target(resolved)
                class_entrypoints = _class_entrypoints(class_target) if class_target is not None else ()
            if class_entrypoints:
                calls.extend(class_entrypoints)
                continue
            calls.append(resolved)
    calls.extend(_import_execution_calls(function_node, module_name, is_package))
    return tuple(calls)


def _import_execution_calls(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    is_package: bool,
) -> tuple[str, ...]:
    if (
        _has_required_user_arguments(function_node)
        and function_node.name not in _PICKLE_LIFECYCLE_ENTRYPOINT_METHOD_SET
    ):
        return ()
    return _direct_import_execution_calls(function_node, module_name, is_package)


def _direct_import_execution_calls(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    is_package: bool,
) -> tuple[str, ...]:
    imports_user_code = False

    class _ExecutedImportVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function_node:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is function_node:
                self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return None

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return None

        def visit_Import(self, node: ast.Import) -> None:
            nonlocal imports_user_code
            imports_user_code = imports_user_code or any(
                _import_module_can_execute_user_code(alias.name) for alias in node.names
            )

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            nonlocal imports_user_code
            if node.module == "__future__":
                return
            imported_module = _resolve_import_from_module(module_name, is_package, node.level, node.module)
            imports_user_code = imports_user_code or _import_module_can_execute_user_code(imported_module)

    _ExecutedImportVisitor().visit(function_node)
    return (_IMPORT_EXECUTION_SINK,) if imports_user_code else ()


def _has_required_user_arguments(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    required_count, _maximum_count, has_required_keyword_only = _user_positional_argument_range(function_node)
    if required_count:
        return True
    return has_required_keyword_only


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _can_invoke_function_with_positional_args(function_name: str, positional_arg_count: int) -> bool:
    resolved = _resolve_function_target(function_name)
    if resolved is None:
        return False
    context = _source_function_context(resolved)
    if context is None:
        return False
    _module_name, _is_package, function_node = context
    return _can_enter_function_with_arguments(function_node, positional_arg_count, ())


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _can_follow_import_execution_fallback(function_name: str, positional_arg_count: int) -> bool:
    resolved = _resolve_function_target(function_name)
    if resolved is None or not _is_pickle_entered_import_execution_entrypoint(resolved):
        return False
    if _is_pickle_lifecycle_entrypoint(resolved):
        return True
    return _can_invoke_function_with_positional_args(resolved, positional_arg_count)


def _is_pickle_entered_import_execution_entrypoint(function_name: str) -> bool:
    _module_name, qualified_name = _split_source_qualified_name(function_name)
    class_name, _separator, method_name = qualified_name.rpartition(".")
    if not class_name or method_name not in _CLASS_ENTRYPOINT_METHOD_SET:
        return True
    return method_name in _PICKLE_ENTERED_IMPORT_EXECUTION_METHODS


def _is_pickle_lifecycle_entrypoint(function_name: str) -> bool:
    _module_name, qualified_name = _split_source_qualified_name(function_name)
    class_name, _separator, method_name = qualified_name.rpartition(".")
    return bool(class_name and method_name in _PICKLE_LIFECYCLE_ENTRYPOINT_METHOD_SET)


def _can_enter_function_with_positional_args(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    positional_arg_count: int,
) -> bool:
    return _can_enter_function_with_arguments(function_node, positional_arg_count, ())


def _can_enter_function_with_arguments(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    positional_arg_count: int,
    keyword_arg_names: tuple[str, ...],
) -> bool:
    positional_parameters = tuple(
        argument
        for argument in (*function_node.args.posonlyargs, *function_node.args.args)
        if argument.arg not in {"self", "cls"}
    )
    positional_only_names = {
        argument.arg for argument in function_node.args.posonlyargs if argument.arg not in {"self", "cls"}
    }
    positional_or_keyword_names = {
        argument.arg for argument in function_node.args.args if argument.arg not in {"self", "cls"}
    }
    keyword_only_names = {
        argument.arg for argument in function_node.args.kwonlyargs if argument.arg not in {"self", "cls"}
    }
    if function_node.args.vararg is None and positional_arg_count > len(positional_parameters):
        return False
    bound_positionally = {argument.arg for argument in positional_parameters[:positional_arg_count]}
    keyword_names = set(keyword_arg_names)
    if bound_positionally & keyword_names:
        return False
    for keyword_name in keyword_names:
        if keyword_name in positional_only_names:
            if function_node.args.kwarg is None:
                return False
            continue
        if (
            keyword_name not in positional_or_keyword_names
            and keyword_name not in keyword_only_names
            and function_node.args.kwarg is None
        ):
            return False

    all_positional = (*function_node.args.posonlyargs, *function_node.args.args)
    required_positional = all_positional[: max(len(all_positional) - len(function_node.args.defaults), 0)]
    for argument in required_positional:
        if argument.arg in {"self", "cls"}:
            continue
        if argument.arg in positional_only_names:
            if argument.arg not in bound_positionally:
                return False
            continue
        if argument.arg not in bound_positionally and argument.arg not in keyword_names:
            return False
    return all(
        argument.arg in keyword_names
        for argument, default in zip(function_node.args.kwonlyargs, function_node.args.kw_defaults, strict=True)
        if argument.arg not in {"self", "cls"} and default is None
    )


def _can_enter_function_with_unknown_keyword_args(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    positional_arg_count: int,
) -> bool:
    positional_parameters = tuple(
        argument
        for argument in (*function_node.args.posonlyargs, *function_node.args.args)
        if argument.arg not in {"self", "cls"}
    )
    if function_node.args.vararg is None and positional_arg_count > len(positional_parameters):
        return False
    bound_positionally = {argument.arg for argument in positional_parameters[:positional_arg_count]}
    required_count = max(
        len(function_node.args.posonlyargs) + len(function_node.args.args) - len(function_node.args.defaults),
        0,
    )
    return all(
        argument.arg in {"self", "cls"} or argument.arg in bound_positionally
        for argument in function_node.args.posonlyargs[:required_count]
    )


def _user_positional_argument_range(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[int, int | None, bool]:
    positional_args = (*function_node.args.posonlyargs, *function_node.args.args)
    required_positional_args = positional_args[: max(len(positional_args) - len(function_node.args.defaults), 0)]
    required_count = sum(1 for argument in required_positional_args if argument.arg not in {"self", "cls"})
    maximum_count = (
        None
        if function_node.args.vararg is not None
        else sum(1 for argument in positional_args if argument.arg not in {"self", "cls"})
    )
    has_required_keyword_only = any(
        argument.arg not in {"self", "cls"} and default is None
        for argument, default in zip(function_node.args.kwonlyargs, function_node.args.kw_defaults, strict=True)
    )
    return required_count, maximum_count, has_required_keyword_only


def _import_module_can_execute_user_code(module_name: str) -> bool:
    if not module_name or module_name in _IMPORT_EXECUTION_SAFE_MODULES:
        return False
    try:
        standard_spec = FrozenImporter.find_spec(module_name)
    except Exception:
        return True
    if standard_spec is None or not _module_spec_uses_builtin_or_frozen_loader(standard_spec):
        return True
    loaded_module = sys.modules.get(module_name)
    if loaded_module is not None:
        loaded_spec = getattr(loaded_module, "__spec__", None)
        return not (isinstance(loaded_spec, ModuleSpec) and _module_spec_uses_builtin_or_frozen_loader(loaded_spec))
    return _untrusted_meta_path_finder_precedes(FrozenImporter, module_name)


def _may_use_getattr_dispatch(call_nodes: tuple[ast.Call, ...], aliases: Mapping[str, str]) -> bool:
    return any(_call_node_may_be_getattr_call(node, aliases) for node in call_nodes)


def _call_node_may_be_getattr_call(call_node: ast.Call, aliases: Mapping[str, str]) -> bool:
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id == "getattr" or aliases.get(func.id) == "builtins.getattr"
    if isinstance(func, ast.Attribute):
        return func.attr == "getattr"
    return False


def _is_controlled_direct_getattr_dispatch(
    call_node: ast.Call,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    controlled_names: set[str],
    *,
    class_name: str | None,
) -> bool:
    if not isinstance(call_node.func, ast.Call):
        return False
    return _controlled_getattr_call(
        call_node.func,
        module_name,
        aliases,
        local_defs,
        controlled_names,
        class_name=class_name,
    ) and _call_uses_parameter_controlled_argument(call_node, controlled_names)


def _controlled_getattr_callable_names(
    assignment_call_candidates: tuple[tuple[set[str], ast.Call], ...],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    controlled_names: set[str],
    *,
    class_name: str | None,
) -> set[str]:
    callable_names: set[str] = set()
    for targets, value in assignment_call_candidates:
        if _controlled_getattr_call(
            value,
            module_name,
            aliases,
            local_defs,
            controlled_names,
            class_name=class_name,
        ):
            callable_names.update(targets)
    return callable_names


def _controlled_getattr_call(
    call_node: ast.Call,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    controlled_names: set[str],
    *,
    class_name: str | None,
) -> bool:
    resolved = _resolve_expr(call_node.func, module_name, aliases, local_defs, class_name)
    if resolved not in {"getattr", "builtins.getattr"}:
        return False
    if len(call_node.args) < 2:
        return False
    return _expr_uses_names(call_node.args[1], controlled_names)


def _getattr_default_callable_names(
    assignment_call_candidates: tuple[tuple[set[str], ast.Call], ...],
    call_nodes: tuple[ast.Call, ...],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    *,
    class_name: str | None,
) -> dict[str, str]:
    called_names = {node.func.id for node in call_nodes if isinstance(node.func, ast.Name)}
    if not called_names:
        return {}

    callable_names: dict[str, str] = {}
    for targets, value in assignment_call_candidates:
        target_names = targets & called_names
        if not target_names:
            continue
        fallback_target = _getattr_default_callable_target(
            value,
            module_name,
            aliases,
            local_defs,
            class_name=class_name,
        )
        if fallback_target is None:
            continue
        for target_name in sorted(target_names):
            callable_names[target_name] = fallback_target
    return callable_names


def _function_assignment_call_candidates(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[tuple[set[str], ast.Call], ...]:
    candidates: list[tuple[set[str], ast.Call]] = []
    for node in ast.walk(function_node):
        value: ast.AST | None
        if isinstance(node, ast.Assign):
            value = node.value
            targets = set()
            for target in node.targets:
                targets.update(_assignment_target_names(target))
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = _assignment_target_names(node.target)
        else:
            continue
        if isinstance(value, ast.Call):
            candidates.append((targets, value))
    return tuple(candidates)


def _getattr_default_callable_target(
    call_node: ast.Call,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    *,
    class_name: str | None,
) -> str | None:
    resolved = _resolve_expr(call_node.func, module_name, aliases, local_defs, class_name)
    if resolved not in {"getattr", "builtins.getattr"} or len(call_node.args) < 3:
        return None
    return _resolve_expr(call_node.args[2], module_name, aliases, local_defs, class_name)


def _collect_function_instance_aliases(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    call_nodes: tuple[ast.Call, ...],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None,
) -> tuple[dict[str, str], set[str] | None]:
    receiver_names = _method_call_receiver_names(call_nodes)
    if not receiver_names:
        return {}, None

    assignment_candidates = tuple(
        (node, target_names)
        for node in ast.walk(function_node)
        if isinstance(node, ast.Assign | ast.AnnAssign)
        and (target_names := _assignment_alias_target_names(node) & receiver_names)
    )
    if not assignment_candidates:
        return {}, None

    instance_aliases: dict[str, str] = {}
    controlled_names = _parameter_controlled_names(function_node)
    for node, target_names in assignment_candidates:
        if not _function_instance_alias_is_parameter_controlled(node, target_names, call_nodes, controlled_names):
            continue
        resolved = _function_instance_alias_value(
            node,
            module_name,
            {**aliases, **instance_aliases},
            local_defs,
            local_class_targets,
            class_name=class_name,
        )
        if resolved is None:
            continue
        for target_name in sorted(target_names):
            if instance_aliases.get(target_name) == resolved:
                continue
            instance_aliases[target_name] = resolved
            if len(instance_aliases) >= _MAX_FUNCTION_INSTANCE_ALIASES:
                return instance_aliases, controlled_names
    return instance_aliases, controlled_names


def _method_call_receiver_names(call_nodes: tuple[ast.Call, ...]) -> set[str]:
    names: set[str] = set()
    for call_node in call_nodes:
        if isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Name):
            names.add(call_node.func.value.id)
    return names


def _function_instance_alias_is_parameter_controlled(
    node: ast.AST,
    target_names: set[str],
    call_nodes: tuple[ast.Call, ...],
    controlled_names: set[str],
) -> bool:
    value: ast.AST | None
    if isinstance(node, ast.Assign | ast.AnnAssign):
        value = node.value
    else:
        return False
    if isinstance(value, ast.Call) and _call_uses_parameter_controlled_argument(value, controlled_names):
        return True

    return any(
        isinstance(call_node.func, ast.Attribute)
        and isinstance(call_node.func.value, ast.Name)
        and call_node.func.value.id in target_names
        and _call_uses_parameter_controlled_argument(call_node, controlled_names)
        for call_node in call_nodes
    )


def _function_instance_alias_value(
    node: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None,
) -> str | None:
    value: ast.AST | None
    if isinstance(node, ast.Assign | ast.AnnAssign):
        value = node.value
    else:
        return None
    if not isinstance(value, ast.Call):
        return None

    call_target = _resolve_expr(value.func, module_name, aliases, local_defs, class_name)
    if call_target in local_class_targets:
        return call_target
    if call_target is None or call_target.startswith(f"{module_name}."):
        return None
    return _resolve_class_target(call_target)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _iter_call_nodes(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.Call, ...]:
    calls: list[ast.Call] = []

    class _CallVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            calls.append(node)
            if isinstance(node.func, ast.Lambda):
                self.visit(node.func.args)
                self.visit(node.func.body)
                for arg in node.args:
                    self.visit(arg)
                for keyword in node.keywords:
                    self.visit(keyword.value)
                return
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_nested_function_signature(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_nested_function_signature(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            self.visit(node.args)

        def _visit_nested_function_signature(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            self.visit(node.args)
            if node.returns is not None:
                self.visit(node.returns)

    visitor = _CallVisitor()
    for statement in function_node.body:
        visitor.visit(statement)
    return tuple(calls)


@_register_source_sensitive_cache
@lru_cache(maxsize=4096)
def _parameter_controlled_names(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    controlled = _initial_parameter_controlled_names(function_node)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(function_node):
            target_names: set[str]
            if isinstance(node, ast.Assign):
                if not _expr_uses_names(node.value, controlled):
                    continue
                target_names = set()
                for target in node.targets:
                    target_names.update(_assignment_target_names(target))
            elif isinstance(node, ast.AnnAssign):
                if node.value is None or not _expr_uses_names(node.value, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            elif isinstance(node, ast.For | ast.AsyncFor):
                if not _expr_uses_names(node.iter, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            else:
                continue
            before = len(controlled)
            controlled.update(target_names)
            changed = changed or len(controlled) != before
    return controlled


def _initial_parameter_controlled_names(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    controlled = {
        arg.arg
        for arg in (
            *function_node.args.posonlyargs,
            *function_node.args.args,
            *function_node.args.kwonlyargs,
        )
        if arg.arg not in {"self", "cls"}
    }
    if function_node.args.vararg is not None:
        controlled.add(function_node.args.vararg.arg)
    if function_node.args.kwarg is not None:
        controlled.add(function_node.args.kwarg.arg)

    return controlled


def _parameter_controlled_tcl_command_names(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    controlled = _initial_parameter_controlled_names(function_node)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(function_node):
            target_names: set[str]
            if isinstance(node, ast.Assign):
                if not _tcl_call_command_uses_names(node.value, controlled):
                    continue
                target_names = set()
                for target in node.targets:
                    target_names.update(_assignment_target_names(target))
            elif isinstance(node, ast.AnnAssign):
                if node.value is None or not _tcl_call_command_uses_names(node.value, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            elif isinstance(node, ast.For | ast.AsyncFor):
                if not _tcl_call_command_uses_names(node.iter, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            else:
                continue
            before = len(controlled)
            controlled.update(target_names)
            changed = changed or len(controlled) != before
    return controlled


def _assignment_target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in target.elts:
            names.update(_assignment_target_names(element))
        return names
    return set()


def _call_uses_parameter_controlled_argument(call_node: ast.Call, controlled_names: set[str]) -> bool:
    return any(_expr_uses_names(argument, controlled_names) for argument in call_node.args) or any(
        _expr_uses_names(keyword.value, controlled_names) for keyword in call_node.keywords
    )


def _tcl_dispatch_uses_parameter_controlled_command(
    call_node: ast.Call,
    call_name: str,
    controlled_names: set[str],
    command_controlled_names: set[str],
) -> bool:
    if call_name.endswith(_TCL_EVAL_DISPATCH_SUFFIXES):
        return _call_uses_parameter_controlled_argument(call_node, controlled_names)
    if not call_node.args:
        return False
    return _tcl_call_command_uses_names(call_node.args[0], command_controlled_names)


def _tcl_call_command_uses_names(expression: ast.AST, names: set[str]) -> bool:
    if isinstance(expression, ast.Starred):
        return _expr_uses_names(expression.value, names)
    if isinstance(expression, ast.Tuple | ast.List):
        if not expression.elts:
            return False
        return _tcl_call_command_uses_names(expression.elts[0], names)
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        return _tcl_call_command_uses_names(expression.left, names)
    if isinstance(expression, ast.Call) and _is_flatten_call(expression):
        return bool(expression.args) and _tcl_call_command_uses_names(expression.args[0], names)
    return _expr_uses_names(expression, names)


def _is_flatten_call(expression: ast.Call) -> bool:
    if isinstance(expression.func, ast.Name):
        return expression.func.id == "_flatten"
    if isinstance(expression.func, ast.Attribute):
        return expression.func.attr == "_flatten"
    return False


def _expr_uses_names(expression: ast.AST, names: set[str]) -> bool:
    return any(isinstance(node, ast.Name) and node.id in names for node in ast.walk(expression))


def _resolve_expr(
    expression: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    class_name: str | None = None,
) -> str | None:
    if isinstance(expression, ast.Name):
        if class_name is not None and expression.id in {"self", "cls"}:
            return f"{module_name}.{class_name}"
        if expression.id in aliases:
            return aliases[expression.id]
        if expression.id in local_defs:
            return f"{module_name}.{expression.id}"
        if expression.id in _BUILTIN_CALLS:
            return f"builtins.{expression.id}"
        return expression.id
    if isinstance(expression, ast.Attribute):
        base = _resolve_expr(expression.value, module_name, aliases, local_defs, class_name)
        if base is not None:
            return f"{base}.{expression.attr}"
    return None


def _resolve_import_from_module(module_name: str, is_package: bool, level: int, imported_module: str | None) -> str:
    if level == 0:
        return imported_module or ""
    package = module_name if is_package else module_name.rpartition(".")[0]
    package_parts = package.split(".") if package else []
    if level > 1:
        package_parts = package_parts[: max(len(package_parts) - (level - 1), 0)]
    parts = [*package_parts]
    if imported_module:
        parts.extend(imported_module.split("."))
    return ".".join(part for part in parts if part)


@_register_source_sensitive_cache
@lru_cache(maxsize=1024)
def _resolve_module_source(module_name: str) -> Path | None:
    parts = _bounded_module_name_parts(module_name)
    if parts is None or len(module_name) > _MAX_SOURCE_MODULE_NAME_CHARS:
        _mark_shared_source_snapshot_unreusable()
        return None
    _track_shared_source_candidates(parts)
    spec = _find_standard_filesystem_spec(module_name)
    loaded_module = sys.modules.get(module_name)
    loaded_spec = getattr(loaded_module, "__spec__", None)
    if isinstance(loaded_spec, ModuleSpec) and isinstance(loaded_spec.origin, str):
        if loaded_spec.origin.endswith(tuple(SOURCE_SUFFIXES)):
            loaded_source_path = Path(loaded_spec.origin)
            current_origin = spec.origin if spec is not None else None
            try:
                origin_matches = (
                    isinstance(current_origin, str) and loaded_source_path.resolve() == Path(current_origin).resolve()
                )
            except (OSError, RuntimeError, ValueError):
                origin_matches = False
            if origin_matches and loaded_source_path.is_file():
                _track_shared_source_paths((loaded_source_path,))
                _track_shared_source_path(module_name, loaded_source_path, loaded=True)
                return loaded_source_path
        elif loaded_spec.origin not in {"built-in", "frozen"}:
            return None
    elif _untrusted_meta_path_finder_precedes(PathFinder, module_name) or _has_untrusted_path_hook():
        return None

    if spec is not None and isinstance(spec.origin, str) and spec.origin.endswith(tuple(SOURCE_SUFFIXES)):
        source_path = Path(spec.origin)
        _track_shared_source_paths((source_path,))
        if source_path.is_file():
            _track_shared_source_path(module_name, source_path, loaded=False)
            return source_path
    return None


def _module_spec_uses_builtin_or_frozen_loader(spec: ModuleSpec) -> bool:
    loader = cast(Any, spec.loader)
    return (loader is BuiltinImporter or loader is FrozenImporter) and spec.origin in {"built-in", "frozen"}


def _rce_sink(call_name: str) -> str | None:
    if call_name in _RCE_SINK_EXACT:
        return call_name
    if call_name.startswith(_RCE_SINK_PREFIXES):
        return call_name
    if _is_tcl_interpreter_dispatch_call(call_name):
        return call_name
    if _is_object_subprocess_dispatch_call(call_name):
        return call_name
    return None


def _file_open_sink(call_name: str) -> str | None:
    if call_name in _FILE_OPEN_SINK_EXACT:
        return call_name
    return None


def _file_write_sink(call_name: str) -> str | None:
    if _is_file_write_call(call_name):
        return call_name
    return None


def _is_file_write_call(call_name: str) -> bool:
    return call_name.rpartition(".")[2] in _FILE_WRITE_METHODS


def _is_tcl_interpreter_dispatch_call(call_name: str) -> bool:
    return call_name.endswith(_TCL_CALL_DISPATCH_SUFFIXES) or call_name.endswith(_TCL_EVAL_DISPATCH_SUFFIXES)


def _is_object_subprocess_dispatch_call(call_name: str) -> bool:
    return call_name.endswith(_SUBPROCESS_DISPATCH_SUFFIXES)


def _is_import_execution_sink(call_name: str) -> bool:
    return call_name == _IMPORT_EXECUTION_SINK
